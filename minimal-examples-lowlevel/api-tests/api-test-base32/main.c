/*
 * lws-api-test-base32
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

struct tests {
	const char *plain;
	const char *enc;
};

static const struct tests tests[] = {
	{ "any carnal pleasure.", "MFXHSIDDMFZG4YLMEBYGYZLBON2XEZJO" },
	{ "any carnal pleasure",  "MFXHSIDDMFZG4YLMEBYGYZLBON2XEZI=" },
	{ "any carnal pleasur",   "MFXHSIDDMFZG4YLMEBYGYZLBON2XE===" },
	{ "Surprise!",            "KN2XE4DSNFZWKII=" },
	{ "1",                    "GE======" },
	{ "",                     "" }
};

int main(int argc, const char **argv)
{
	int n, m, fails = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	char enc[64], dec[64];
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: base32\n");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(tests); n++) {
		int e_len = (int)strlen(tests[n].plain);

		/* test encoding */
		memset(enc, 0, sizeof(enc));
		m = lws_b32_encode_string(tests[n].plain, e_len, enc, sizeof(enc));
		if (m != (int)strlen(tests[n].enc) || strcmp(enc, tests[n].enc)) {
			lwsl_err("%s: encode test %d failed (expected '%s', got '%s', len %d)\n",
				__func__, n, tests[n].enc, enc, m);
			fails++;
		}

		/* test decoding */
		memset(dec, 0, sizeof(dec));
		m = lws_b32_decode_string_len(enc, (int)strlen(enc), dec, sizeof(dec));
		if (m != e_len || strcmp(dec, tests[n].plain)) {
			lwsl_err("%s: decode test %d failed (expected '%s', got '%s', len %d)\n",
				__func__, n, tests[n].plain, dec, m);
			fails++;
		}
	}

	if (fails) {
		lwsl_err("Failed %d base32 tests\n", fails);
		return 1;
	}

	lwsl_user("Passed all base32 tests\n");
	return 0;
}
