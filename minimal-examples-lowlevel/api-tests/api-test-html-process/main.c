/*
 * lws-api-test-html-process
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_chunked_html_process() substitutes variables in a file being
 * interpreted, one lump of it at a time, in place, and frames each lump
 * as an h1 chunk if asked.  How the file is cut into lumps is not up to
 * the interpreter: on h2 the peer's flow control window decides it.
 *
 * So here a small page is fed through it cut into lumps of every size from
 * one byte to all of it, the way lws_http_file_tx() calls it: the lump at
 * the start of a buffer with 10 bytes in front of it for the chunk size
 * line, and 128 bytes after it to grow into.  Whatever the cut, the output,
 * with the chunk framing taken off, must be the page with its variables
 * replaced, and nothing may be written outside the buffer.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#define HEADROOM	10	/* lws_http_file_tx() leaves this for the size */
#define GROWTH		128	/* ... and this for the content to grow into */
#define GUARD		32
#define GUARD_BYTE	0xa5

#define TEN		"0123456789"
#define HUNDRED		TEN TEN TEN TEN TEN TEN TEN TEN TEN TEN

static const char * const vars[] = {
	"$name", "$v", "$empty", "$longest_var14"
};

static const char * const vals[] = {
	"Alice", HUNDRED, "", "L"
};

static const char page[] =
	"<p>$name, $v; [$empty] $longest_var14 $$name $nam $ "
	"$longest_var14x $name$name$</p>$na";

static const char expected[] =
	"<p>Alice, " HUNDRED "; [] L $Alice $nam $ "
	"Lx AliceAlice$</p>$na";

static const char *
replace(void *data, int index)
{
	(void)data;

	return vals[index];
}

static int
guard_ok(const uint8_t *g, size_t len)
{
	while (len--)
		if (*g++ != GUARD_BYTE)
			return 0;

	return 1;
}

/*
 * Take the chunk framing off one lump's output, checking it as we go
 */

static int
dechunk(const char *p, int len, int final, char *out, size_t *olen,
	size_t omax)
{
	const char *e = p + len;
	char *q;
	long cl;

	if (!len)
		return !final; /* only a lump that is not the last may be empty */

	cl = strtol(p, &q, 16);
	if (cl) {
		if (q + 2 > e || q[0] != '\r' || q[1] != '\n')
			return 0;
		q += 2;
		if (cl < 0 || q + cl + 2 > e || q[cl] != '\r' ||
		    q[cl + 1] != '\n' || *olen + (size_t)cl > omax)
			return 0;
		memcpy(out + *olen, q, (size_t)cl);
		*olen += (size_t)cl;
		q += cl + 2;
	} else
		q = (char *)p;

	if (final) {
		if (e - q != 5 || memcmp(q, "0\r\n\r\n", 5))
			return 0;
		q += 5;
	}

	return q == e;
}

/*
 * Run the page through in lumps of ls bytes.  Returns 0 if the output was
 * right.
 */

static int
run(size_t ls, int chunked)
{
	uint8_t buf[HEADROOM + sizeof(page) + GROWTH + GUARD];
	struct lws_process_html_state s;
	struct lws_process_html_args a;
	size_t done = 0, olen = 0, l;
	char out[512];

	memset(&s, 0, sizeof(s));
	s.vars = vars;
	s.count_vars = (int)LWS_ARRAY_SIZE(vars);
	s.replace = replace;

	while (done < sizeof(page) - 1) {
		l = sizeof(page) - 1 - done;
		if (l > ls)
			l = ls;

		memset(buf, GUARD_BYTE, sizeof(buf));
		memcpy(buf + HEADROOM, page + done, l);
		done += l;

		a.p = (char *)buf + HEADROOM;
		a.len = (int)l;
		a.max_len = (int)(l + GROWTH);
		a.final = done == sizeof(page) - 1;
		a.chunked = chunked;

		if (lws_chunked_html_process(&a, &s)) {
			lwsl_err("%s: lump %d: refused\n", __func__, (int)ls);
			return 1;
		}

		if (!guard_ok(buf + HEADROOM + l + GROWTH, GUARD) ||
		    a.p < (char *)buf ||
		    a.p + a.len > (char *)buf + HEADROOM + l + GROWTH) {
			lwsl_err("%s: lump %d: wrote outside the buffer\n",
				 __func__, (int)ls);
			return 1;
		}

		if (!chunked) {
			if (olen + (size_t)a.len > sizeof(out))
				return 1;
			memcpy(out + olen, a.p, (size_t)a.len);
			olen += (size_t)a.len;
			continue;
		}

		if (!dechunk(a.p, a.len, a.final, out, &olen, sizeof(out))) {
			lwsl_err("%s: lump %d: bad chunk framing\n", __func__,
				 (int)ls);
			return 1;
		}
	}

	if (s.pos) {
		lwsl_err("%s: lump %d: %d bytes left held back\n", __func__,
			 (int)ls, s.pos);
		return 1;
	}

	if (olen != sizeof(expected) - 1 || memcmp(out, expected, olen)) {
		lwsl_err("%s: lump %d, chunked %d: got '%.*s'\n", __func__,
			 (int)ls, chunked, (int)olen, out);
		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_process_html_state s;
	struct lws_process_html_args a;
	uint8_t buf[HEADROOM + 16 + GUARD];
	int e = 0, chunked;
	size_t ls;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: html process\n");

	for (chunked = 0; chunked < 2; chunked++)
		for (ls = 1; ls <= sizeof(page) - 1; ls++)
			e |= run(ls, chunked);

	/*
	 * A substitution with no room to grow into is refused, and writes
	 * nothing past what it was given
	 */

	memset(&s, 0, sizeof(s));
	s.vars = vars;
	s.count_vars = (int)LWS_ARRAY_SIZE(vars);
	s.replace = replace;

	memset(buf, GUARD_BYTE, sizeof(buf));
	memcpy(buf + HEADROOM, "a $v b", 6);
	a.p = (char *)buf + HEADROOM;
	a.len = 6;
	a.max_len = 16;
	a.final = 1;
	a.chunked = 1;
	if (!lws_chunked_html_process(&a, &s)) {
		lwsl_err("an outgrown buffer was not refused\n");
		e = 1;
	}
	if (!guard_ok(buf + HEADROOM + 16, GUARD)) {
		lwsl_err("an outgrown buffer was written past\n");
		e = 1;
	}

	/* a last lump that comes to nothing is just the last-chunk */

	memset(&s, 0, sizeof(s));
	s.vars = vars;
	s.count_vars = (int)LWS_ARRAY_SIZE(vars);
	s.replace = replace;

	memset(buf, GUARD_BYTE, sizeof(buf));
	memcpy(buf + HEADROOM, "$empty", 6);
	a.p = (char *)buf + HEADROOM;
	a.len = 6;
	a.max_len = 16;
	a.final = 1;
	a.chunked = 1;
	if (lws_chunked_html_process(&a, &s) || a.len != 5 ||
	    memcmp(a.p, "0\r\n\r\n", 5)) {
		lwsl_err("an empty last lump is not just the last-chunk\n");
		e = 1;
	}

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return e;
}
