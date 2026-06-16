/*
 * lws-api-test-x509-jwk-privkey-pem
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests for lws_x509_jwk_privkey_pem() API
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>

struct test_case {
	const char *name;
	const char *cert_path;
	const char *key_path;
	const char *passphrase;
	const char *curves;
	int rsa_min_bits;
	enum lws_gencrypto_kty expected_kty;
	int expected_result;
};

static int
load_file(const char *path, char *buf, size_t buf_size, size_t *len)
{
	FILE *fp;
	size_t n;

	fp = fopen(path, "rb");
	if (!fp) {
		lwsl_err("Failed to open %s\n", path);
		return -1;
	}
	n = fread(buf, 1, buf_size - 1, fp);
	fclose(fp);
	if (n == 0) {
		lwsl_err("Empty file %s\n", path);
		return -1;
	}
	buf[n] = '\0';
	*len = n + 1;
	return 0;
}

static int
load_cert_and_pubkey(const char *cert_path, struct lws_x509_cert **x509,
		     struct lws_jwk *jwk, const char *curves, int rsa_min_bits)
{
	char pem[8192];
	size_t len;
	int ret;

	if (load_file(cert_path, pem, sizeof(pem), &len)) {
		return -1;
	}
	ret = lws_x509_create(x509);
	if (ret) {
		lwsl_err("lws_x509_create failed\n");
		return -1;
	}
	ret = lws_x509_parse_from_pem(*x509, pem, len);
	if (ret) {
		lwsl_err("lws_x509_parse_from_pem failed for %s\n", cert_path);
		lws_x509_destroy(x509);
		return -1;
	}
	memset(jwk, 0, sizeof(*jwk));
	ret = lws_x509_public_to_jwk(jwk, *x509, curves, rsa_min_bits);
	if (ret) {
		lwsl_err("lws_x509_public_to_jwk failed for %s\n", cert_path);
		lws_x509_destroy(x509);
		return -1;
	}
	return 0;
}

static void
print_jwk_privkey_info(struct lws_jwk *jwk)
{
	char hex[24];
	size_t j, hex_len;
	int i;

	switch (jwk->kty) {
	case LWS_GENCRYPTO_KTY_RSA:
		lwsl_user("  Key Type: RSA");
		lwsl_user("  Modulus (n): %u bytes", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len);
		lwsl_user("  Exponent (e): %u bytes", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len);
		if (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf) {
			lwsl_user("  Private exponent (d): %u bytes", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].len);
		}
		if (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf) {
			lwsl_user("  Prime p: %u bytes", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].len);
		}
		if (jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) {
			lwsl_user("  Prime q: %u bytes", jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].len);
		}
		break;
	case LWS_GENCRYPTO_KTY_EC:
		lwsl_user("  Key Type: EC");
		lwsl_user("  X coordinate: %u bytes", jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len);
		lwsl_user("  Y coordinate: %u bytes", jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
		if (jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf) {
			lwsl_user("  Private key (d): %u bytes", jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len);
		}
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
run_test_case(struct lws_context *context, const struct test_case *tc, const char *cert_dir)
{
	struct lws_x509_cert *cert = NULL;
	struct lws_jwk jwk;
	char cert_full_path[512];
	char key_full_path[512];
	char key_pem[8192];
	size_t key_len;
	int ret;
	int result;

	lws_snprintf(cert_full_path, sizeof(cert_full_path), "%s/%s", cert_dir, tc->cert_path);
	lws_snprintf(key_full_path, sizeof(key_full_path), "%s/%s", cert_dir, tc->key_path);
	lwsl_user("\n=== Test: %s ===", tc->name);
	lwsl_user("Certificate: %s", cert_full_path);
	lwsl_user("Private Key: %s", key_full_path);
	if (tc->passphrase) {
		lwsl_user("Passphrase: (provided)");
	} else {
		lwsl_user("Passphrase: (none)");
	}
	if (load_cert_and_pubkey(cert_full_path, &cert, &jwk, tc->curves, tc->rsa_min_bits) < 0) {
		lwsl_user("FAILED: Could not load certificate or public key");
		return -1;
	}
	if (load_file(key_full_path, key_pem, sizeof(key_pem), &key_len)) {
		lwsl_user("FAILED: Could not load private key file");
		lws_jwk_destroy(&jwk);
		lws_x509_destroy(&cert);
		return -1;
	}
	ret = lws_x509_jwk_privkey_pem(context, &jwk, key_pem, key_len, tc->passphrase);
	if (ret == tc->expected_result) {
		if (ret == 0) {
			if (jwk.kty == (int)tc->expected_kty) {
				result = 0;
				if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
					if (!jwk.e[LWS_GENCRYPTO_RSA_KEYEL_D].buf ||
					    !jwk.e[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
					    !jwk.e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) {
						lwsl_user("FAILED: RSA private key elements missing");
						result = -1;
					}
				}
				if (result == 0 && jwk.kty == LWS_GENCRYPTO_KTY_EC) {
					if (!jwk.e[LWS_GENCRYPTO_EC_KEYEL_D].buf) {
						lwsl_user("FAILED: EC private key element missing");
						result = -1;
					}
				}
				if (result == 0) {
					lwsl_user("PASSED");
					print_jwk_privkey_info(&jwk);
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
			.name = "RSA 2048-bit private key",
			.cert_path = "rsa-2048-cert.crt",
			.key_path = "rsa-2048-key.pem",
			.passphrase = NULL,
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA 4096-bit private key",
			.cert_path = "rsa-4096-cert.crt",
			.key_path = "rsa-4096-key.pem",
			.passphrase = NULL,
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA 2048-bit encrypted private key (correct passphrase)",
			.cert_path = "rsa-2048-cert.crt",
			.key_path = "rsa-2048-key-encrypted.pem",
			.passphrase = "testpass123",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = 0
		},
		{
			.name = "RSA 2048-bit encrypted private key (wrong passphrase)",
			.cert_path = "rsa-2048-cert.crt",
			.key_path = "rsa-2048-key-encrypted.pem",
			.passphrase = "wrongpassword",
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = -1
		},
		{
			.name = "EC P-256 private key",
			.cert_path = "ec-p256-cert.crt",
			.key_path = "ec-p256-key.pem",
			.passphrase = NULL,
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-384 private key",
			.cert_path = "ec-p384-cert.crt",
			.key_path = "ec-p384-key.pem",
			.passphrase = NULL,
			.curves = "P-384",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-521 private key",
			.cert_path = "ec-p521-cert.crt",
			.key_path = "ec-p521-key.pem",
			.passphrase = NULL,
			.curves = "P-521",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-256 encrypted private key (correct passphrase)",
			.cert_path = "ec-p256-cert.crt",
			.key_path = "ec-p256-key-encrypted.pem",
			.passphrase = "testpass123",
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = 0
		},
		{
			.name = "EC P-256 encrypted private key (wrong passphrase)",
			.cert_path = "ec-p256-cert.crt",
			.key_path = "ec-p256-key-encrypted.pem",
			.passphrase = "wrongpassword",
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "Mismatched key type (EC cert with RSA key)",
			.cert_path = "ec-p256-cert.crt",
			.key_path = "rsa-2048-key.pem",
			.passphrase = NULL,
			.curves = "P-256",
			.rsa_min_bits = 0,
			.expected_kty = LWS_GENCRYPTO_KTY_EC,
			.expected_result = -1
		},
		{
			.name = "Mismatched RSA keys (different cert/key)",
			.cert_path = "rsa-2048-cert.crt",
			.key_path = "rsa-4096-key.pem",
			.passphrase = NULL,
			.curves = NULL,
			.rsa_min_bits = 2048,
			.expected_kty = LWS_GENCRYPTO_KTY_RSA,
			.expected_result = -1
		},
		{
			.name = "EC same curve different keypair",
			.cert_path = "ec-p256-cert.crt",
			.key_path = "ec-p256-b-key.pem",
			.passphrase = NULL,
			.curves = "P-256",
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
	lwsl_user("LWS X509 JWK privkey PEM api tests");
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
		if (run_test_case(context, &tests[i], cert_dir) == 0) {
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
