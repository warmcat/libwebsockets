/*
 * lws-api-test-whois-purify
 *
 * Fence for lws_whois_json_purify(): untrusted whois JSON must come out
 * as bounded canonical JSON containing only whitelisted, validated
 * members, or be rejected outright.
 *
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

#include <signal.h>
#include <string.h>

static int fails;

/* canonical output must be a stable, fixed-form serialization */

static const char *valid_input =
	"{\"nameservers\":[\"ns1.example.com\",\"ns2.example.net\"],"
	"\"dnssec\":\"signedDelegation\","
	"\"ds_data\":\"2371 13 2 1f98d0d1c1f3f0c1\","
	"\"expiry_date\":1767225600,"
	"\"creation_date\":1609459200,"
	"\"updated_date\":1735689600}";

static const char *valid_expect =
	"{\"creation_date\":1609459200,\"expiry_date\":1767225600,"
	"\"updated_date\":1735689600,"
	"\"nameservers\":[\"ns1.example.com\",\"ns2.example.net\"],"
	"\"dnssec\":\"signedDelegation\","
	"\"ds_data\":\"2371 13 2 1f98d0d1c1f3f0c1\"}";

/* payloads that are valid JSON but not schema-conformant */

static const char *injected_member =
	"{\"expiry_date\":1,\"injected\":\"payload\",\"dnssec\":\"yes\"}";
static const char *wrong_typed_date =
	"{\"expiry_date\":\"1767225600\"}";
static const char *negative_date =
	"{\"expiry_date\":-5}";
static const char *huge_date =
	"{\"expiry_date\":99999999999999999999}";
static const char *script_ns =
	"{\"nameservers\":[\"ns1.example.com\",\"<script>alert(1)</script>\"]}";
static const char *control_dnssec =
	"{\"dnssec\":\"signed\\u0001\"}";
static const char *numeral_dnssec =
	"{\"dnssec\":123}";
static const char *null_member =
	"{\"expiry_date\":null}";

static signed char
fence_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	(void)ctx;
	(void)reason;

	return 0;
}

/* the canonical output must itself parse cleanly as JSON */

static void
must_parse(const char *json, const char *what)
{
	struct lejp_ctx jctx;
	int r;

	lejp_construct(&jctx, fence_lejp_cb, NULL, NULL, 0);
	r = lejp_parse(&jctx, (const uint8_t *)json, (int)strlen(json));
	lejp_destruct(&jctx);

	if (r < 0 && r != LEJP_REJECT_UNKNOWN) {
		lwsl_err("%s: %s does not parse: %s\n", __func__, what, json);
		fails++;
	}
}

static void
expect(const char *in, const char *want, int want_problems, const char *what)
{
	char out[LWS_WHOIS_CANON_MAX + 1];
	int problems = -1, n;

	n = lws_whois_json_purify(out, sizeof(out), in, strlen(in), &problems);

	if (n < 0) {
		lwsl_err("%s: %s refused\n", __func__, what);
		fails++;
		return;
	}

	must_parse(out, what);

	if (strcmp(out, want)) {
		lwsl_err("%s: %s gave\n  %s\n  want\n  %s\n",
			 __func__, what, out, want);
		fails++;
	}

	if (!problems != !want_problems) {
		lwsl_err("%s: %s problems=%d want %d\n",
			 __func__, what, problems, want_problems);
		fails++;
	}
}

/* payload must be refused outright: nothing written, -1 returned */

static void
expect_reject(const char *in, size_t in_len, const char *what)
{
	char out[LWS_WHOIS_CANON_MAX + 1];
	int problems = 0;

	if (lws_whois_json_purify(out, sizeof(out), in, in_len, &problems) >= 0) {
		lwsl_err("%s: %s not refused\n", __func__, what);
		fails++;
	}
}

int main(int argc, const char **argv)
{
	char out[LWS_WHOIS_CANON_MAX + 1], big[64 * 1024];
	int problems = 0, n, i;

	signal(SIGPIPE, SIG_IGN);
	(void)argc;
	(void)argv;

	lws_set_log_level(LLL_ERR | LLL_USER, NULL);
	lwsl_user("LWS API selftest: whois-purify\n");

	/* conformant payload round-trips to the exact canonical form */

	expect(valid_input, valid_expect, 0, "valid payload");

	/* hostile / malformed payloads are canonicalized with problems */

	expect(injected_member,
	       "{\"expiry_date\":1,\"dnssec\":\"yes\"}", 1, "injected member");
	expect(wrong_typed_date, "{}", 1, "string date");
	expect(negative_date, "{}", 1, "negative date");
	expect(huge_date, "{}", 1, "huge date");
	expect(script_ns, "{\"nameservers\":[\"ns1.example.com\"]}", 1,
	       "markup nameserver");
	expect(control_dnssec, "{}", 1, "control char dnssec");
	expect(numeral_dnssec, "{}", 1, "numeric dnssec");
	expect(null_member, "{}", 1, "null member");

	/* more than 16 nameservers: extras dropped, flagged */

	{
		char in[8192], want[8192];
		size_t o = 0;

		o += (size_t)lws_snprintf(in + o, sizeof(in) - o,
					  "{\"nameservers\":[");
		for (i = 0; i < 20; i++)
			o += (size_t)lws_snprintf(in + o, sizeof(in) - o,
						  "%s\"ns%d.example.com\"",
						  i ? "," : "", i);
		o += (size_t)lws_snprintf(in + o, sizeof(in) - o, "]}");

		o = 0;
		o += (size_t)lws_snprintf(want + o, sizeof(want) - o,
					  "{\"nameservers\":[");
		for (i = 0; i < 16; i++)
			o += (size_t)lws_snprintf(want + o, sizeof(want) - o,
						  "%s\"ns%d.example.com\"",
						  i ? "," : "", i);
		(void)lws_snprintf(want + o, sizeof(want) - o, "]}");

		expect(in, want, 1, "nameserver quota");
	}

	/* non-JSON, empty and truncated payloads are refused outright */

	expect_reject("not json at all", 15, "non-JSON");
	expect_reject("", 0, "empty");
	expect_reject("{\"expiry_date\":123", 18, "truncated object");

	/* valid JSON with no schema-conformant members canonicalizes empty */

	expect("[1,2,3]", "{}", 1, "top-level array");

	/* oversized junk is refused, not allocated into */

	memset(big, 'a', sizeof(big));
	big[0] = '{';
	big[1] = '\"';
	big[sizeof(big) - 2] = '}';
	expect_reject(big, sizeof(big), "64KB junk");

	/* an output buffer that cannot hold the canonical cap is refused */

	if (lws_whois_json_purify(out, 64, "{}", 2, &problems) >= 0) {
		lwsl_err("%s: small out buffer accepted\n", __func__);
		fails++;
	}

	/*
	 * Escaping is still applied on emission even though the charset
	 * checks passed (lws_json_purify uses \uXXXX for quotes)
	 */

	n = lws_whois_json_purify(out, sizeof(out),
				  "{\"ds_data\":\"a\\\"b\"}",
				  strlen("{\"ds_data\":\"a\\\"b\"}"), &problems);
	if (n < 0 || strcmp(out, "{\"ds_data\":\"a\\u0022b\"}") || problems) {
		lwsl_err("%s: escape roundtrip gave '%s' (%d, %d)\n",
			 __func__, out, n, problems);
		fails++;
	}

	if (fails) {
		lwsl_err("Failed %d whois-purify tests\n", fails);
		return 1;
	}

	lwsl_user("Completed: ALL OK, 14 tests\n");

	return 0;
}
