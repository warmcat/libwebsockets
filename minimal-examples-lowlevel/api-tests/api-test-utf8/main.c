/*
 * lws-api-test-utf8
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences lws's UTF-8 helpers, and lws_json_purify()'s truncation, which used
 * to cut a multibyte sequence in half when the output buffer filled.  A ws
 * TEXT frame holding the result is invalid UTF-8, which browsers must fail
 * the connection on.
 *
 * Covered behaviours:
 *
 *  - lws_check_utf8() accepts valid UTF-8 whole and split into chunks at
 *    every point, and refuses overlong forms, surrogates, code points past
 *    U+10FFFF, stray continuation bytes and bad lead bytes; a string ending
 *    partway through a sequence leaves a nonzero state
 *  - lws_utf8_trim_partial() turns every prefix of a valid string into the
 *    longest valid prefix, and leaves complete strings alone
 *  - lws_json_purify() truncated into every output size gives valid UTF-8
 *    that is a prefix of the untruncated escaping, with in_used consistent
 *    with what was output; a cut made by the caller's input cap stays put,
 *    and a capped, non-NUL-terminated input is never read past its cap
 */

#include <libwebsockets.h>

#include <stdlib.h>
#include <string.h>

static int fails, oks;

#define CHECK(_c, ...) do { \
	if (_c) oks++; else { fails++; lwsl_err(__VA_ARGS__); } \
} while (0)

static const char * const valid[] = {
	"",
	"plain ascii",
	"\xc2\xa3",				/* U+00A3, 2 bytes */
	"\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac",	/* U+20AC x 3 */
	"\xf0\x9f\x98\x80",			/* U+1F600, 4 bytes */
	"\xf4\x8f\xbf\xbf",			/* U+10FFFF, the last one */
	"\xed\x9f\xbf",				/* U+D7FF, just below surrogates */
	"\xee\x80\x80",				/* U+E000, just above them */
	"a\xc3\xa9\"b\\\xe2\x82\xac\n\xf0\x9f\x98\x80<\t>",
};

static const char * const invalid[] = {
	"\x80",					/* stray continuation */
	"a\xbf" "b",
	"\xc0\x80",				/* overlong NUL */
	"\xc1\xbf",				/* overlong */
	"\xe0\x80\x80",				/* overlong 3-byte */
	"\xe0\x9f\xbf",
	"\xf0\x80\x80\x80",			/* overlong 4-byte */
	"\xf0\x8f\xbf\xbf",
	"\xed\xa0\x80",				/* U+D800, a surrogate */
	"\xed\xbf\xbf",				/* U+DFFF */
	"\xf4\x90\x80\x80",			/* U+110000 */
	"\xf5\x80\x80\x80",			/* bad lead */
	"\xff",
	"\xc3\x28",				/* lead then ASCII */
	"\xe2\x82\x28",
};

static int
is_valid(const char *s, size_t len)
{
	unsigned char st = 0;

	return !lws_check_utf8(&st, (const unsigned char *)s, len) && !st;
}

static void
test_check(void)
{
	size_t n, m;

	for (n = 0; n < LWS_ARRAY_SIZE(valid); n++) {
		size_t len = strlen(valid[n]);

		CHECK(is_valid(valid[n], len), "%s: valid %d refused\n",
		      __func__, (int)n);

		/* split in two at every point, carrying the state */
		for (m = 0; m <= len; m++) {
			unsigned char st = 0;
			int r = lws_check_utf8(&st,
				(const unsigned char *)valid[n], m);

			r |= lws_check_utf8(&st,
				(const unsigned char *)valid[n] + m, len - m);
			CHECK(!r && !st, "%s: valid %d split at %d refused\n",
			      __func__, (int)n, (int)m);
		}
	}

	for (n = 0; n < LWS_ARRAY_SIZE(invalid); n++)
		CHECK(!is_valid(invalid[n], strlen(invalid[n])),
		      "%s: invalid %d accepted\n", __func__, (int)n);

	/* ends partway through a sequence: no error yet, but a state */
	{
		unsigned char st = 0;
		int r = lws_check_utf8(&st, (const unsigned char *)"a\xe2\x82",
				       3);

		CHECK(!r && st, "%s: partial end not flagged\n", __func__);
	}
}

static void
test_trim(void)
{
	char buf[64];
	size_t n, m, t;

	for (n = 0; n < LWS_ARRAY_SIZE(valid); n++) {
		size_t len = strlen(valid[n]);

		for (m = 0; m <= len; m++) {
			memcpy(buf, valid[n], m);
			buf[m] = '\0';

			t = lws_utf8_trim_partial(buf, m);

			CHECK(t <= m && strlen(buf) == t && is_valid(buf, t),
			      "%s: valid %d prefix %d trimmed to %d, bad\n",
			      __func__, (int)n, (int)m, (int)t);

			/* a prefix that was already valid is left alone */
			if (is_valid(valid[n], m))
				CHECK(t == m, "%s: valid %d prefix %d cut to %d\n",
				      __func__, (int)n, (int)m, (int)t);
			else
				/* it only ever removes the one partial sequence */
				CHECK(m - t >= 1 && m - t <= 3,
				      "%s: valid %d prefix %d cut to %d\n",
				      __func__, (int)n, (int)m, (int)t);
		}
	}

	/* it is not a validator: invalid input it did not cut is kept */
	lws_strncpy(buf, "a\x80\x80\x80\x80", sizeof(buf));
	CHECK(lws_utf8_trim_partial(buf, 5) == 5, "%s: stray continuations\n",
	      __func__);
}

static void
test_purify(void)
{
	char full[512], out[512], redo[512], redo_esc[512];
	int n, len, used;
	size_t s;

	for (s = 0; s < LWS_ARRAY_SIZE(valid); s++) {
		lws_json_purify(full, valid[s], sizeof(full), NULL);

		for (len = 1; len <= (int)strlen(full) + 8; len++) {
			used = 0;
			memset(out, 0x55, sizeof(out));
			lws_json_purify(out, valid[s], len, &used);

			n = (int)strlen(out);
			CHECK(n < len, "%s: %d: overran %d\n", __func__,
			      (int)s, len);
			CHECK(is_valid(out, (size_t)n),
			      "%s: %d: len %d gave invalid UTF-8\n", __func__,
			      (int)s, len);
			CHECK(!strncmp(out, full, (size_t)n),
			      "%s: %d: len %d not a prefix\n", __func__,
			      (int)s, len);

			/* what we got is exactly the escaping of what it used */
			lws_strnncpy(redo, valid[s], used, sizeof(redo));
			lws_json_purify(redo_esc, redo, sizeof(redo_esc), NULL);
			CHECK(!strcmp(out, redo_esc),
			      "%s: %d: len %d in_used %d inconsistent\n",
			      __func__, (int)s, len, used);
		}
	}

	/* the caller's own input cap is honoured, even mid-sequence */
	used = 2;
	lws_json_purify(out, "\xe2\x82\xac", sizeof(out), &used);
	CHECK(used == 2 && !strcmp(out, "\xe2\x82"), "%s: input cap moved\n",
	      __func__);

	/*
	 * A capped input is not NUL-terminated: purifying a heap copy of
	 * exactly its length, consumed whole, must not look at the byte past
	 * the cap (ASan reports a heap-buffer-overflow if it does)
	 */
	{
		static const char hello[] = "hello";
		char *h = malloc(sizeof(hello) - 1);

		if (h) {
			memcpy(h, hello, sizeof(hello) - 1);
			used = (int)sizeof(hello) - 1;
			lws_json_purify(out, h, sizeof(out), &used);
			CHECK(used == (int)sizeof(hello) - 1 &&
			      !strcmp(out, hello), "%s: exact cap\n", __func__);
			free(h);
		} else
			CHECK(0, "%s: OOM\n", __func__);
	}

	/*
	 * Under a cap, the output filling partway through a sequence still
	 * backs off to its start: "a" + U+20AC capped at its 4 bytes, into 9
	 * bytes of output (room for three input bytes), gives just "a"
	 */
	{
		char *h = malloc(4);

		if (h) {
			memcpy(h, "a\xe2\x82\xac", 4);
			used = 4;
			lws_json_purify(out, h, 9, &used);
			CHECK(used == 1 && !strcmp(out, "a"),
			      "%s: capped back-off gave %d\n", __func__, used);
			free(h);
		} else
			CHECK(0, "%s: OOM\n", __func__);
	}

	/*
	 * 21 x U+20AC (63 bytes) into 64 bytes: this used to stop one byte
	 * into the 20th character
	 */
	{
		char name[64], esc[64];

		for (n = 0; n < 21; n++)
			memcpy(name + (n * 3), "\xe2\x82\xac", 3);
		name[63] = '\0';
		lws_json_purify(esc, name, sizeof(esc), NULL);
		CHECK(strlen(esc) == 57 && is_valid(esc, strlen(esc)),
		      "%s: euro name gave %d\n", __func__, (int)strlen(esc));
	}
}

int
main(int argc, const char **argv)
{
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: UTF-8 helpers\n");

	test_check();
	test_trim();
	test_purify();

	lwsl_user("Completed: %s (%d ok, %d failed)\n",
		  fails ? "FAIL" : "PASS", oks, fails);

	(void)argc;
	(void)argv;

	return !!fails;
}
