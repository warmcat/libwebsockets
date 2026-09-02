/*
 * lws-api-test-dht-msg-parse
 *
 * Coverage for the DHT RPC wire message parser, in particular the F-051
 * fix: the hash token must be 2 - 128 lowercase hex chars, so it can
 * never traverse out of storage paths composed from it.
 *
 * Also covers the F-052 domain-string intake gate: NOTIFY-carried domain
 * names must be presentation-format DNS names, since they too are
 * composed into filesystem paths.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

struct tests {
	const char *msg;
	const char *hash;
	unsigned long long offset;
	unsigned long long len;
};

/* messages that must parse, and the hash they must yield */

static const struct tests ok[] = {
	{ "GET a1b2c3d4 0 1024 payload",		"a1b2c3d4", 0, 1024 },
	{ "PUT 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 100 5 xx",
							"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 100, 5 },
	/* the NONC / CAP placeholder hash */
	{ "NONC_REQ 0000 0 0 ",			"0000", 0, 0 },
};

/* hash tokens that must be rejected at the parser (F-051) */

static const char *bad[] = {
	"GET ../../etc/shadow 0 1000 ",
	"GET ../../../etc/shadow 0 1000 ",
	"GET /etc/passwd 0 1000 ",
	"GET .. 0 1000 x",
	"GET . 0 1000 x",
	"GET a/b 0 1000 x",
	"GET a\\b 0 1000 x",
	"GET A1B2C3D4 0 1000 x",			/* uppercase */
	"GET a1b2c3d4%00 0 1000 x",
	"GET a1b2c3d4;ls 0 1000 x",
	"GET a 0 1000 x",				/* too short */
	"GET  0 1000 x",				/* empty token */
	"GET a1b2c3d4x 0 1000 x",			/* non-hex 'x' */
};

/* domain names that must pass the NOTIFY intake gate (F-052) */

static const char *domains_ok[] = {
	"example.com",
	"example.com.",				/* trailing root dot */
	"a-b.c_d.example.co.uk",
	"localhost",
	"x",
	"4.3.2.1.in-addr.arpa",
};

/* domain names that must be refused before any path composition (F-052) */

static const char *domains_bad[] = {
	"../../x",
	"../x",
	"..",
	".",
	"",						/* empty */
	"example..com",				/* empty label */
	".example.com",				/* leading dot */
	"example.com/",				/* path separator */
	"/etc/passwd",
	"a/b.example.com",
	"a\\b.example.com",
	"example.com;ls",
	"example.com%00",
	"exa mple.com",				/* space */
	"dht-hash-../../x",			/* hash-token shape with junk */
	/*
	 * F-053: quote-bearing names must not reach the monitor's response /
	 * config-file JSON composition, they would break out of the string
	 */
	"x\",\"injected\":\"payload",
	"sub\x01.example.com",			/* control char */
};

static signed char
fence_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	(void)ctx;
	(void)reason;

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_dht_msg m;
	char overlong[512], big[256];
	size_t i;
	int n, fails = 0;

	lwsl_user("LWS API selftest: dht-msg-parse\n");

	for (i = 0; i < LWS_ARRAY_SIZE(ok); i++) {
		n = lws_dht_msg_parse(ok[i].msg, strlen(ok[i].msg), &m);
		if (n || strcmp(m.hash, ok[i].hash) ||
		    m.offset != ok[i].offset || m.len != ok[i].len) {
			lwsl_err("%s: ok test %zu failed (ret %d)\n",
				 __func__, i, n);
			fails++;
		}
	}

	for (i = 0; i < LWS_ARRAY_SIZE(bad); i++) {
		n = lws_dht_msg_parse(bad[i], strlen(bad[i]), &m);
		if (!n) {
			lwsl_err("%s: bad test %zu '%s' accepted as '%s'\n",
				 __func__, i, bad[i], m.hash);
			fails++;
		}
	}

	/* exactly 128 hex chars is the largest acceptable token... */

	for (n = 0; n < 128; n++)
		big[n] = (char)("0123456789abcdef"[n & 15]);
	big[128] = '\0';
	lws_snprintf(overlong, sizeof(overlong), "GET %s 0 10 x", big);
	if (lws_dht_msg_parse(overlong, strlen(overlong), &m) ||
	    strlen(m.hash) != 128) {
		lwsl_err("%s: 128-hex token mishandled\n", __func__);
		fails++;
	}

	/* ...but 129 is over the hash cap and must be rejected */

	big[128] = 'f';
	big[129] = '\0';
	lws_snprintf(overlong, sizeof(overlong), "GET %s 0 10 x", big);
	if (!lws_dht_msg_parse(overlong, strlen(overlong), &m)) {
		lwsl_err("%s: 129-hex token accepted\n", __func__);
		fails++;
	}

	/* roundtrip through the generator must still parse */

	n = lws_dht_msg_gen(overlong, sizeof(overlong), "ACK",
			    "deadbeef", 12, 34);
	if (n <= 0 || lws_dht_msg_parse(overlong, (size_t)n, &m) ||
	    strcmp(m.verb, "ACK") || strcmp(m.hash, "deadbeef") ||
	    m.offset != 12 || m.len != 34) {
		lwsl_err("%s: gen/parse roundtrip failed\n", __func__);
		fails++;
	}

	/*
	 * F-052: domain strings riding NOTIFY datagrams must be
	 * presentation-format DNS names, since they end up composed
	 * into filesystem paths
	 */

	for (i = 0; i < LWS_ARRAY_SIZE(domains_ok); i++) {
		if (!lws_dht_valid_domain_name(domains_ok[i])) {
			lwsl_err("%s: valid domain %zu '%s' refused\n",
				 __func__, i, domains_ok[i]);
			fails++;
		}
	}

	for (i = 0; i < LWS_ARRAY_SIZE(domains_bad); i++) {
		if (lws_dht_valid_domain_name(domains_bad[i])) {
			lwsl_err("%s: invalid domain %zu '%s' accepted\n",
				 __func__, i, domains_bad[i]);
			fails++;
		}
	}

	/* exactly 253 chars (4 max-size labels + dots) is acceptable... */

	memset(big, 'a', 253);
	big[63] = big[127] = big[191] = '.';
	big[253] = '\0';
	if (!lws_dht_valid_domain_name(big)) {
		lwsl_err("%s: 253-char name mishandled\n", __func__);
		fails++;
	}

	/* ...but 254 is over the cap and must be rejected */

	big[253] = 'a';
	big[254] = '\0';
	if (lws_dht_valid_domain_name(big)) {
		lwsl_err("%s: 254-char name accepted\n", __func__);
		fails++;
	}

	/*
	 * F-053: strings that do reach monitor JSON composition (free-text
	 * IPC fields, on-disk names and file snippets) go through
	 * lws_json_purify() first; a quote, backslash or control char must
	 * come out escaped so it cannot inject JSON members.  Fence the
	 * escaper round-trip for the exact payload shape from the finding.
	 */

	{
		static const char * const hostile[] = {
			"x\",\"injected\":\"payload",
			"line1\nline2\ttab\\slash\"quote\x01ctl",
		};
		struct lejp_ctx jctx;

		for (i = 0; i < LWS_ARRAY_SIZE(hostile); i++) {
			char esc[6 * 128 + 8], quoted[6 * 128 + 16];
			int r;

			lws_json_purify(esc, hostile[i], sizeof(esc), NULL);
			lws_snprintf(quoted, sizeof(quoted), "{\"m\":\"%s\"}", esc);

			/* the escaped form must parse back as one JSON string */

			lejp_construct(&jctx, fence_lejp_cb, NULL, NULL, 0);
			r = lejp_parse(&jctx, (const uint8_t *)quoted,
				       (int)strlen(quoted));
			lejp_destruct(&jctx);
			if (r < 0 && r != LEJP_REJECT_UNKNOWN) {
				lwsl_err("%s: escaped payload %zu broke JSON\n",
					 __func__, i);
				fails++;
			}
		}
	}

	if (fails) {
		lwsl_err("Failed %d dht-msg-parse tests\n", fails);
		return 1;
	}

	lwsl_user("Completed: ALL OK, %d tests\n",
		  (int)(LWS_ARRAY_SIZE(ok) + LWS_ARRAY_SIZE(bad) +
			LWS_ARRAY_SIZE(domains_ok) + LWS_ARRAY_SIZE(domains_bad) + 5));

	return 0;
}
