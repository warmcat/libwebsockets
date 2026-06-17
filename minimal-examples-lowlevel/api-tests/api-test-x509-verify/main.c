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
