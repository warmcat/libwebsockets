/*
 * lws-api-test-x509-verify
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests for lws_x509_verify() API
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct test_case {
	const char *name;
	const char *cert_path;
	const char *trusted_path;
	const char *common_name;
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

static int
run_test_case(const struct test_case *tc, const char *cert_dir)
{
	struct lws_x509_cert *cert = NULL;
	struct lws_x509_cert *trusted = NULL;
	char cert_full_path[512];
	char trusted_full_path[512];
	int ret, result;

	lws_snprintf(cert_full_path, sizeof(cert_full_path), "%s/%s", cert_dir, tc->cert_path);
	lws_snprintf(trusted_full_path, sizeof(trusted_full_path), "%s/%s", cert_dir, tc->trusted_path);
	lwsl_user("\n=== Test: %s ===", tc->name);
	lwsl_user("Certificate: %s", cert_full_path);
	lwsl_user("Trusted CA: %s", trusted_full_path);
	if (tc->common_name) {
		lwsl_user("Common Name: %s", tc->common_name);
	} else {
		lwsl_user("Common Name: (not checked)");
	}
	if (load_cert_from_file(cert_full_path, &cert) < 0) {
		lwsl_user("FAILED: Could not load certificate");
		return -1;
	}
	if (load_cert_from_file(trusted_full_path, &trusted) < 0) {
		lwsl_user("FAILED: Could not load trusted CA");
		lws_x509_destroy(&cert);
		return -1;
	}
	ret = lws_x509_verify(cert, trusted, tc->common_name);
	if (ret == tc->expected_result) {
		lwsl_user("PASSED");
		result = 0;
	} else {
		lwsl_user("FAILED: Expected return %d, got %d", tc->expected_result, ret);
		result = -1;
	}
	lws_x509_destroy(&cert);
	lws_x509_destroy(&trusted);
	return result;
}

/*
 * lws_x509_create_cert() produces DER, the parse and CA-signing apis take PEM
 */

static char *
der_to_pem(const char *label, const uint8_t *der, size_t der_len)
{
	size_t b64_size = ((der_len + 2) / 3) * 4 + 2, pem_size, n, o;
	char *b64, *pem;
	int m;

	b64 = malloc(b64_size);
	if (!b64)
		return NULL;

	m = lws_b64_encode_string((const char *)der, (int)der_len, b64,
				  (int)b64_size);
	if (m < 0) {
		free(b64);
		return NULL;
	}

	/* 64 chars per line, plus the header and footer lines */
	pem_size = (size_t)m + ((size_t)m / 64) + 2 + (2 * strlen(label)) + 64;
	pem = malloc(pem_size);
	if (!pem) {
		free(b64);
		return NULL;
	}

	o = (size_t)lws_snprintf(pem, pem_size, "-----BEGIN %s-----\n", label);
	for (n = 0; n < (size_t)m; n += 64)
		o += (size_t)lws_snprintf(pem + o, pem_size - o, "%.*s\n",
					  (int)(((size_t)m - n) > 64 ? 64 :
						(size_t)m - n), b64 + n);
	lws_snprintf(pem + o, pem_size - o, "-----END %s-----\n", label);
	free(b64);

	return pem;
}

/*
 * Generate a CA with lws_x509_create_cert(), and a server cert for \p san
 * signed by it, then check lws_x509_verify() accepts the server cert against
 * the generated CA, checking the CN is \p san if \p check_cn.
 */

static int
test_generated_chain(struct lws_context *context, const char *san,
		     int check_cn)
{
	struct lws_x509_cert *ca = NULL, *leaf = NULL;
	struct lws_x509_cert_gen_info gi;
	uint8_t *cert = NULL, *key = NULL;
	char *ca_pem = NULL, *ca_key_pem = NULL, *leaf_pem = NULL;
	size_t cert_len, key_len;
	int ret = -1;

	lwsl_user("\n=== Test: generated CA and server cert for %s ===", san);

	memset(&gi, 0, sizeof(gi));
	gi.san		= "Generated Test CA";
	gi.curve_name	= "P-256";
	gi.is_ca	= 1;
	gi.validity_days = 1;

	if (lws_x509_create_cert(context, &cert, &cert_len, &key, &key_len,
				 &gi)) {
		lwsl_user("FAILED: creating CA");
		goto bail;
	}

	ca_pem = der_to_pem("CERTIFICATE", cert, cert_len);
	ca_key_pem = der_to_pem("EC PRIVATE KEY", key, key_len);
	free(cert);
	free(key);
	cert = key = NULL;
	if (!ca_pem || !ca_key_pem) {
		lwsl_user("FAILED: converting CA to PEM");
		goto bail;
	}

	memset(&gi, 0, sizeof(gi));
	gi.san		= san;
	gi.ca_cert_pem	= ca_pem;
	gi.ca_key_pem	= ca_key_pem;
	gi.curve_name	= "P-256";
	gi.is_server	= 1;
	gi.validity_days = 1;

	if (lws_x509_create_cert(context, &cert, &cert_len, &key, &key_len,
				 &gi)) {
		lwsl_user("FAILED: creating server cert");
		goto bail;
	}

	leaf_pem = der_to_pem("CERTIFICATE", cert, cert_len);
	if (!leaf_pem) {
		lwsl_user("FAILED: converting server cert to PEM");
		goto bail;
	}

	if (lws_x509_create(&ca) || lws_x509_create(&leaf) ||
	    lws_x509_parse_from_pem(ca, ca_pem, strlen(ca_pem) + 1) ||
	    lws_x509_parse_from_pem(leaf, leaf_pem, strlen(leaf_pem) + 1)) {
		lwsl_user("FAILED: parsing the generated certs");
		goto bail;
	}

	if (lws_x509_verify(leaf, ca, check_cn ? san : NULL)) {
		lwsl_user("FAILED: generated server cert did not verify");
		goto bail;
	}

	lwsl_user("PASSED");
	ret = 0;

bail:
	lws_x509_destroy(&leaf);
	lws_x509_destroy(&ca);
	free(cert);
	free(key);
	free(leaf_pem);
	free(ca_key_pem);
	free(ca_pem);

	return ret;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	struct test_case tests[] = {
		{
			.name = "Valid certificate signed by trusted CA (with CN check)",
			.cert_path = "server-cert.crt",
			.trusted_path = "ca-cert.crt",
			.common_name = "test.example.com",
			.expected_result = 0
		},
		{
			.name = "Valid certificate signed by trusted CA (without CN check)",
			.cert_path = "server-cert.crt",
			.trusted_path = "ca-cert.crt",
			.common_name = NULL,
			.expected_result = 0
		},
		{
			.name = "Certificate signed by wrong CA",
			.cert_path = "server-cert.crt",
			.trusted_path = "other-ca-cert.crt",
			.common_name = NULL,
			.expected_result = -1
		},
		{
			.name = "Common name mismatch",
			.cert_path = "server-cert.crt",
			.trusted_path = "ca-cert.crt",
			.common_name = "wrong.com",
			.expected_result = -1
		},
		{
			.name = "Valid intermediate chain (CA -> Intermediate -> Server)",
			.cert_path = "leaf-cert.crt",
			.trusted_path = "ca-cert.crt",
			.common_name = NULL,
			.expected_result = -1
		},
		/*
		 * same-dn-ca-cert.crt is an unrelated CA with its own key that
		 * has the same subject DN as ca-cert.crt, and no key
		 * identifier.  Only checking the signature can tell the two
		 * CAs apart.
		 */
		{
			.name = "Certificate against a different CA with the same DN",
			.cert_path = "server-cert.crt",
			.trusted_path = "same-dn-ca-cert.crt",
			.common_name = NULL,
			.expected_result = -1
		},
		{
			.name = "Valid certificate signed by the same-DN CA",
			.cert_path = "same-dn-leaf-cert.crt",
			.trusted_path = "same-dn-ca-cert.crt",
			.common_name = "other.example.com",
			.expected_result = 0
		},
		{
			.name = "Same-DN CA's certificate against the original CA",
			.cert_path = "same-dn-leaf-cert.crt",
			.trusted_path = "ca-cert.crt",
			.common_name = NULL,
			.expected_result = -1
		},
		{
			.name = "Expired certificate signed by trusted CA",
			.cert_path = "expired-cert.crt",
			.trusted_path = "same-dn-ca-cert.crt",
			.common_name = NULL,
			.expected_result = -1
		},
#if !defined(LWS_WITH_GNUTLS) && !defined(LWS_WITH_BEARSSL) && \
    !defined(LWS_WITH_SCHANNEL) && !defined(LWS_WITH_OPENHITLS)
		/*
		 * Only for the backends whose lws_x509_parse_from_pem() keeps
		 * the further certs of a multi-cert PEM as the chain: the
		 * leaf is followed by its intermediate CA in the PEM
		 */
		{
			.name = "Chain with its intermediate CA in the PEM",
			.cert_path = "same-dn-chain-cert.crt",
			.trusted_path = "same-dn-ca-cert.crt",
			.common_name = "chain.example.com",
			.expected_result = 0
		},
#endif
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
	lwsl_user("LWS X509 verify api tests");
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
	total++;
	if (!test_generated_chain(context, "gen.example.com", 1))
		passed++;
	total++;
	if (!test_generated_chain(context, "127.0.0.1", 0))
		passed++;
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
