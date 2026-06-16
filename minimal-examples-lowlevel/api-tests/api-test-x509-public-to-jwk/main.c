/*
 * lws-api-test-x509-public-to-jwk
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests for lws_x509_public_to_jwk() API
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>

struct test_case {
	const char *name;
	const char *cert_path;
	const char *curves;
	int rsa_min_bits;
	enum lws_gencrypto_kty expected_kty;
	int expected_result;
};

static int
load_cert_from_file(const char *path, struct lws_x509_cert **x509)
{
	char pem[8192];
	size_t len;
	FILE *fp;
	int ret;

	fp = fopen(path, "rb");
	if (!fp) {
		lwsl_err("Failed to open %s\n", path);
		return -1;
	}
	len = fread(pem, 1, sizeof(pem) - 1, fp);
	fclose(fp);
	pem[len] = '\0';
	ret = lws_x509_create(x509);
	if (ret) {
		lwsl_err("lws_x509_create failed\n");
		return -1;
	}
	ret = lws_x509_parse_from_pem(*x509, pem, len + 1);
	if (ret) {
		lwsl_err("lws_x509_parse_from_pem failed for %s\n", path);
		lws_x509_destroy(x509);
		return -1;
	}
	return 0;
}

static void
print_jwk_info(struct lws_jwk *jwk)
{
	char hex[24];
	size_t j, hex_len;
	int i;

	switch (jwk->kty) {
	case LWS_GENCRYPTO_KTY_RSA:
		lwsl_user("  Key Type: RSA");
		lwsl_user("  Modulus (n): %u bytes", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len);
		lwsl_user("  Exponent (e): %u bytes", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len);
		break;
	case LWS_GENCRYPTO_KTY_EC:
		lwsl_user("  Key Type: EC");
		lwsl_user("  X coordinate: %u bytes", jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len);
		lwsl_user("  Y coordinate: %u bytes", jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
		break;
	default:
		lwsl_user("  Key Type: Unknown (%d)", jwk->kty);
		break;
	}
	for (i = 0; i < LWS_GENCRYPTO_MAX_KEYEL_COUNT; i++) {
		if (jwk->e[i].buf && jwk->e[i].len > 0) {
			hex_len = jwk->e[i].len < 8 ? jwk->e[i].len : 8;
			for (j = 0; j < hex_len; j++) {
				lws_snprintf(hex + j * 2, 3, "%02x", jwk->e[i].buf[j]);
			}
			hex[hex_len * 2] = '\0';
			lwsl_user("  Element[%d]: %u bytes - %s%s", i, jwk->e[i].len, hex, jwk->e[i].len > 8 ? "..." : "");
		}
	}
}

static int
run_test_case(const struct test_case *tc, const char *cert_dir)
{
	struct lws_x509_cert *cert = NULL;
	struct lws_jwk jwk;
	char cert_full_path[512];
	int ret, result;

	lws_snprintf(cert_full_path, sizeof(cert_full_path), "%s/%s", cert_dir, tc->cert_path);
	lwsl_user("\n=== Test: %s ===", tc->name);
	lwsl_user("Certificate: %s", cert_full_path);
	if (tc->curves) {
		lwsl_user("Allowed curves: %s", tc->curves);
	} else {
		lwsl_user("Allowed curves: (none)");
	}
	lwsl_user("Min RSA bits: %d", tc->rsa_min_bits);
	if (load_cert_from_file(cert_full_path, &cert) < 0) {
		lwsl_user("FAILED: Could not load certificate");
		return -1;
	}
	memset(&jwk, 0, sizeof(jwk));
	ret = lws_x509_public_to_jwk(&jwk, cert, tc->curves, tc->rsa_min_bits);
	if (ret == tc->expected_result) {
		if (ret == 0) {
			if (jwk.kty == (int)tc->expected_kty) {
				result = 0;
				if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
					unsigned int nlen = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
					unsigned int elen = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].len;
					if (!nlen || !elen) {
						lwsl_user("FAILED: RSA n/e length invalid (n=%u, e=%u)", nlen, elen);
						result = -1;
					} else if (tc->rsa_min_bits > 0 && nlen < (unsigned int)(tc->rsa_min_bits / 8)) {
						lwsl_user("FAILED: RSA modulus too short: %u bytes (< %d bytes)", nlen, tc->rsa_min_bits / 8);
						result = -1;
					}
				}
				if (result == 0 && jwk.kty == LWS_GENCRYPTO_KTY_EC) {
					unsigned int xlen = jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
					unsigned int ylen = jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;
					if (!xlen || !ylen) {
						lwsl_user("FAILED: EC x/y length invalid (x=%u, y=%u)", xlen, ylen);
						result = -1;
					} else {
						lwsl_user("EC coordinate lengths: x=%u, y=%u", xlen, ylen);
					}
				}
				if (result == 0) {
					lwsl_user("PASSED");
					print_jwk_info(&jwk);
				}
			} else {
				lwsl_user("FAILED: Expected key type %d, got %d", tc->expected_kty, jwk.kty);
				result = -1;
			}
		} else {
			lwsl_user("PASSED (expected failure)");
			result = 0;
		}
	} else {
		lwsl_user("FAILED: Expected return %d, got %d", tc->expected_result, ret);
		result = -1;
	}
	lws_jwk_destroy(&jwk);
	lws_x509_destroy(&cert);
	return result;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	struct test_case tests[] = {
		{
			.name = "RSA certificate (2048-bit)",
			.cert_path = "rsa-2048-cert.crt",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA certificate (4096-bit)",
			.cert_path = "rsa-4096-cert.crt",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA certificate - insufficient bits (1024-bit rejected)",
			.cert_path = "rsa-1024-cert.crt",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = -1
		},
		{
			.name = "EC certificate (P-256)",
			.cert_path = "ec-p256-cert.crt",
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate (P-384)",
			.cert_path = "ec-p384-cert.crt",
			.curves = "P-384",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate (P-521)",
			.cert_path = "ec-p521-cert.crt",
			.curves = "P-521",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate - curve token mismatch still accepted",
			.cert_path = "ec-p256-cert.crt",
			.curves = "P-384",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC certificate - unsupported curve id (P-224)",
			.cert_path = "ec-p224-cert.crt",
			.curves = "P-224",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "EC certificate - no curves allowed",
			.cert_path = "ec-p256-cert.crt",
			.curves = NULL,
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "RSA certificate with curve list (RSA should work)",
			.cert_path = "rsa-2048-cert.crt",
			.curves = "P-256,P-384",
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "EC certificate with multiple allowed curves",
			.cert_path = "ec-p256-cert.crt",
			.curves = "P-256,P-384,P-521",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
	};
	const char *cert_dir = ".";
	const char *p;
	int total = 0, passed = 0;
	size_t i;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int result = 1;

	if ((p = lws_cmdline_option(argc, argv, "-d"))) {
		logs = atoi(p);
	}
	if ((p = lws_cmdline_option(argc, argv, "-c"))) {
		cert_dir = p;
	}
	lws_set_log_level(logs, NULL);
	lwsl_user("LWS X509 public to JWK api tests");
	lwsl_user("Certificate directory: %s", cert_dir);
	memset(&info, 0, sizeof info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}
	for (i = 0; i < LWS_ARRAY_SIZE(tests); i++) {
		total++;
		if (run_test_case(&tests[i], cert_dir) == 0) {
			passed++;
		}
	}
	lwsl_user("\n---");
	lwsl_user("Results: %d/%d tests passed", passed, total);
	if (passed == total) {
		lwsl_user("Completed: PASS");
		result = 0;
	} else {
		lwsl_user("Completed: FAIL");
	}
	lws_context_destroy(context);
	return result;
}
