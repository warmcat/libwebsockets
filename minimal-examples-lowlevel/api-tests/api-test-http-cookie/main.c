/*
 * lws-api-test-http-cookie
 *
 * Unit coverage for lws_http_cookie_compose(): the fail-closed Set-Cookie
 * composer the SSO plugins use instead of raw snprintf (F-022 / F-048).
 *
 * In particular this fences the F-048 arithmetic: a clearing cookie with a
 * 127-byte cookie_domain and a 63-byte cookie_name must carry its complete
 * Expires / Max-Age=0 / HttpOnly / SameSite / Secure tail, and a buffer one
 * byte too small must fail closed rather than truncate it.
 *
 * This file is made available under the Creative Commons CC0 1.0 Universal
 * Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * H1 header writer shrink test: each writer is reference-encoded to learn
 * the length it needs, then handed every shorter length on an exact-size
 * heap buffer (must never claim more than it was given, ASan fences any
 * write past it), then the needed length plus headroom (must succeed
 * with identical bytes).  wsi is NULL so only
 * the wsi-independent writers can be covered here; the h2/h3 writers have
 * their own coverage (hpack checks its total up front, api-test-qpack s7).
 */
static int sk_by_name(unsigned char *b, size_t l)
{
	unsigned char *p = b;

	if (lws_add_http_header_by_name(NULL, (const unsigned char *)"x-trigger:",
					(const unsigned char *)"value", 5, &p, b + l))
		return -1;
	return (int)(p - b);
}
static int sk_by_name_nocolon(unsigned char *b, size_t l)
{
	unsigned char *p = b;

	if (lws_add_http_header_by_name(NULL, (const unsigned char *)"x-trigger",
					(const unsigned char *)"value", 5, &p, b + l))
		return -1;
	return (int)(p - b);
}
static int sk_nameless(unsigned char *b, size_t l)
{
	unsigned char *p = b;

	if (lws_add_http_header_by_name(NULL, NULL,
					(const unsigned char *)"HTTP/1.1 200 OK", 15,
					&p, b + l))
		return -1;
	return (int)(p - b);
}
static int sk_by_token(unsigned char *b, size_t l)
{
	unsigned char *p = b;

	if (lws_add_http_header_by_token(NULL, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (const unsigned char *)"text/html", 9,
					 &p, b + l))
		return -1;
	return (int)(p - b);
}
static int sk_finalize(unsigned char *b, size_t l)
{
	unsigned char *p = b;

	if (lws_finalize_http_header(NULL, &p, b + l))
		return -1;
	return (int)(p - b);
}

static const struct {
	const char *name;
	int (*enc)(unsigned char *b, size_t l);
} shrink_cases[] = {
	{ "by_name", sk_by_name }, { "by_name_nocolon", sk_by_name_nocolon },
	{ "nameless", sk_nameless }, { "by_token", sk_by_token },
	{ "finalize", sk_finalize },
};

static int
shrink_test(void)
{
	int fails = 0;
	size_t i, l;

	for (i = 0; i < LWS_ARRAY_SIZE(shrink_cases); i++) {
		unsigned char ref[256], *b;
		int n, m;

		memset(ref, 0, sizeof(ref));
		n = shrink_cases[i].enc(ref, sizeof(ref));
		if (n <= 0 || n > 200) {
			lwsl_err("shrink %s: reference encode %d\n",
				 shrink_cases[i].name, n);
			fails++;
			continue;
		}

		for (l = 0; l < (size_t)n; l++) {
			b = malloc(l ? l : 1);
			if (!b) { fails++; break; }
			memset(b, 0x5a, l ? l : 1);
			m = shrink_cases[i].enc(b, l);
			/*
			 * The H1 writers keep a few bytes of headroom for the
			 * trailing CRLF / NUL, so refusing early is fine: the
			 * class we fence is claiming more than was available
			 * (and ASan catches any write past the allocation)
			 */
			if (m > (int)l) {
				lwsl_err("shrink %s: len %u claimed %d, needs %d\n",
					 shrink_cases[i].name, (unsigned int)l, m, n);
				fails++;
			}
			free(b);
		}

		/* with the headroom available it must succeed identically */
		b = malloc((size_t)n + 8);
		if (!b) { fails++; continue; }
		m = shrink_cases[i].enc(b, (size_t)n + 8);
		if (m != n || memcmp(b, ref, (size_t)n)) {
			lwsl_err("shrink %s: len %d+8 gave %d\n",
				 shrink_cases[i].name, n, m);
			fails++;
		}
		free(b);
	}

	return fails;
}

#define TAIL "; HttpOnly; SameSite=Lax; Secure"

static int
expect_str(int test, const char *label, const char *got, const char *want)
{
	if (strcmp(got, want)) {
		lwsl_err("%s: test %d (%s):\n got  '%s'\n want '%s'\n",
			 __func__, test, label, got, want);
		return 1;
	}

	return 0;
}

int main(void)
{
	/*
	 * F-048 worst case: vhd caps are cookie_name[64] (so <= 63 chars)
	 * and cookie_domain[128] (so <= 127 chars); the composed clearing
	 * cookie must still fit the sizing the auth-server plugin uses
	 */
	char name[64], domain[128], buf[512];
	const char *exp = "Thu, 01 Jan 1970 00:00:00 GMT";
	char want[512];
	int n, fails = 0;

	lwsl_user("LWS API selftest: http-cookie\n");

	memset(name, 'n', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	memset(domain, 'd', sizeof(domain) - 1);
	domain[sizeof(domain) - 1] = '\0';

	/* 1: mint shape with a Domain */

	n = lws_http_cookie_compose(buf, sizeof(buf), "auth_session", "abc",
				    "warmcat.com", 60, NULL);
	if (n < 0) {
		lwsl_err("%s: test 1: compose failed\n", __func__);
		fails++;
	} else
		fails += expect_str(1, "mint", buf,
			"auth_session=abc; Path=/; Domain=warmcat.com; "
			"Max-Age=60" TAIL);

	/* 2: host-only cookie (empty domain omits the Domain attribute) */

	n = lws_http_cookie_compose(buf, sizeof(buf), "auth_session", "abc",
				    "", 60, NULL);
	if (n < 0) {
		lwsl_err("%s: test 2: compose failed\n", __func__);
		fails++;
	} else
		fails += expect_str(2, "host-only", buf,
				"auth_session=abc; Path=/; Max-Age=60" TAIL);

	/* 3: F-048 clearing worst case: 63-byte name, 127-byte domain */

	n = lws_http_cookie_compose(buf, sizeof(buf), name, "", domain, 0, exp);
	if (n < 0) {
		lwsl_err("%s: test 3: clearing worst case failed\n", __func__);
		fails++;
	} else {
		lws_snprintf(want, sizeof(want), "%s=; Path=/; Domain=%s; "
			     "Expires=%s; Max-Age=0" TAIL, name, domain, exp);
		fails += expect_str(3, "clearing worst case", buf, want);
	}

	/*
	 * 4: the same worst case must fit the auth-server plugin's
	 * AUTH_SERVER_CLEAR_COOKIE_SZ sizing (mirrored here: 63 + 1 + 8 + 9 +
	 * 127 + 10 + 29 + 11 + 32 + 1)
	 */
	{
		char clear[63 + 1 + 8 + 9 + 127 + 10 + 29 + 11 + 32 + 1];

		if (lws_http_cookie_compose(clear, sizeof(clear), name, "",
					    domain, 0, exp) < 0) {
			lwsl_err("%s: test 4: does not fit the plugin's "
				 "AUTH_SERVER_CLEAR_COOKIE_SZ\n", __func__);
			fails++;
		}
	}

	/* 5: measuring mode agrees with the composed length */

	n = lws_http_cookie_compose(NULL, 0, name, "", domain, 0, exp);
	if (n < 0 || (size_t)n != strlen(buf)) {
		lwsl_err("%s: test 5: measure mode returned %d, strlen %d\n",
			 __func__, n, (int)strlen(buf));
		fails++;
	}

	/*
	 * 6: fail closed: one byte short of the complete string composes
	 * nothing, rather than a cookie whose attribute tail was truncated
	 */
	{
		char shortbuf[512];

		n = lws_http_cookie_compose(buf, sizeof(buf), "auth_session",
					    "abc", domain, 60, NULL);
		if (n < 0) {
			lwsl_err("%s: test 6: compose failed\n", __func__);
			fails++;
		} else if (lws_http_cookie_compose(shortbuf, (size_t)n,
						   "auth_session", "abc",
						   domain, 60, NULL) >= 0 ||
			   shortbuf[0]) {
			lwsl_err("%s: test 6: truncation not refused\n",
				 __func__);
			fails++;
		}
	}

	/* 7: unusable arguments are refused */

	if (lws_http_cookie_compose(buf, sizeof(buf), NULL, "", NULL, 0,
				    NULL) >= 0 ||
	    lws_http_cookie_compose(buf, sizeof(buf), "x", NULL, NULL, 0,
				    NULL) >= 0) {
		lwsl_err("%s: test 7: NULL name/value accepted\n", __func__);
		fails++;
	}

	/* 8. H1 header writer shrink test */
	fails += shrink_test();

	if (fails) {
		lwsl_err("Failed %d http-cookie tests\n", fails);
		return 1;
	}

	lwsl_user("Completed: ALL OK, 8 tests\n");

	return 0;
}
