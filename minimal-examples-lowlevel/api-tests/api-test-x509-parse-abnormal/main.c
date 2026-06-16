/*
 * lws-api-test-x509-parse-abnormal
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests for lws_x509_parse_from_pem() API with abnormal parameters
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>

struct test_case {
	const char *name;
	const char *description;
	int expected_result;
};

static int
load_file_to_buffer(const char *path, char *buf, size_t buf_size, size_t *len)
{
	FILE *fp;
	
	fp = fopen(path, "rb");
	if (!fp) {
		lwsl_err("Failed to open %s\n", path);
		return -1;
	}
	*len = fread(buf, 1, buf_size - 1, fp);
	fclose(fp);
	buf[*len] = '\0';
	
	return 0;
}

static int
run_test_with_buffer(struct lws_x509_cert *x509, const char *test_name,
		     const char *description, const char *buf, size_t len,
		     int expected_result)
{
	int ret, result;
	struct lws_x509_cert *test_x509 = NULL;

	lwsl_user("\n=== Test: %s ===", test_name);
	lwsl_user("Description: %s", description);
	
	ret = lws_x509_create(&test_x509);
	if (ret) {
		lwsl_err("lws_x509_create failed\n");
		return -1;
	}
	
	ret = lws_x509_parse_from_pem(test_x509, buf, len);
	
	if (ret == expected_result) {
		lwsl_user("PASSED: Expected return %d, got %d", expected_result, ret);
		result = 0;
	} else {
		lwsl_user("FAILED: Expected return %d, got %d", expected_result, ret);
		result = -1;
	}
	
	lws_x509_destroy(&test_x509);
	return result;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	char pembuf[8192];
	char test_dir[512];
	size_t len;
	const char *p;
	int total = 0, passed = 0;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int result = 1;
	struct lws_x509_cert *x509 = NULL;

	if ((p = lws_cmdline_option(argc, argv, "-d"))) {
		logs = atoi(p);
	}
	if ((p = lws_cmdline_option(argc, argv, "-c"))) {
		lws_strncpy(test_dir, p, sizeof(test_dir));
	} else {
		lws_strncpy(test_dir, ".", sizeof(test_dir));
	}

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS X509 parse from PEM abnormal parameter tests");
	lwsl_user("Test directory: %s", test_dir);

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

	/* Test 1: Parse private key (should fail) */
	{
		char key_path[600];
		lws_snprintf(key_path, sizeof(key_path), "%s/ec-p256-key.pem", test_dir);
		lwsl_user("\n--- Test 1: Parse private key ---");
		lwsl_user("File: %s", key_path);
		
		if (load_file_to_buffer(key_path, pembuf, sizeof(pembuf), &len) == 0) {
			total++;
			if (run_test_with_buffer(x509, 
			    "lws_x509_parse_from_pem with private key",
			    "Calling lws_x509_parse_from_pem with certificate private key, expected return -1",
			    pembuf, len + 1, -1) == 0) {
				passed++;
			}
		} else {
			lwsl_user("SKIPPED: Could not load private key file");
		}
	}

	/* Test 2: Parse DER format certificate (should fail) */
	{
		char der_path[600];
		lws_snprintf(der_path, sizeof(der_path), "%s/cert.der", test_dir);
		lwsl_user("\n--- Test 2: Parse DER format certificate ---");
		lwsl_user("File: %s", der_path);
		
		if (load_file_to_buffer(der_path, pembuf, sizeof(pembuf), &len) == 0) {
			total++;
			if (run_test_with_buffer(x509,
			    "lws_x509_parse_from_pem with DER format",
			    "Calling lws_x509_parse_from_pem with DER format certificate, expected return -1",
			    pembuf, len, -1) == 0) {
				passed++;
			}
		} else {
			lwsl_user("SKIPPED: Could not load DER file");
		}
	}

	/* Test 3: Parse empty certificate (should fail) */
	{
		char empty_path[600];
		lws_snprintf(empty_path, sizeof(empty_path), "%s/empty-cert.pem", test_dir);
		lwsl_user("\n--- Test 3: Parse empty certificate ---");
		lwsl_user("File: %s", empty_path);
		
		if (load_file_to_buffer(empty_path, pembuf, sizeof(pembuf), &len) == 0) {
			total++;
			if (run_test_with_buffer(x509,
			    "lws_x509_parse_from_pem with empty certificate",
			    "Calling lws_x509_parse_from_pem with empty certificate, expected return -1",
			    pembuf, len + 1, -1) == 0) {
				passed++;
			}
		} else {
			total++;
			memset(pembuf, 0, sizeof(pembuf));
			strcpy(pembuf, "");
			len = 1;
			if (run_test_with_buffer(x509,
			    "lws_x509_parse_from_pem with empty certificate",
			    "Calling lws_x509_parse_from_pem with empty certificate, expected return -1",
			    pembuf, len, -1) == 0) {
				passed++;
			}
		}
	}

	/* Test 4: Parse non-existent certificate (should fail) */
	{
		char nonexist_path[600];
		lws_snprintf(nonexist_path, sizeof(nonexist_path), "%s/nonexistent-cert.pem", test_dir);
		lwsl_user("\n--- Test 4: Parse non-existent certificate ---");
		lwsl_user("File: %s", nonexist_path);
		
		if (load_file_to_buffer(nonexist_path, pembuf, sizeof(pembuf), &len) != 0) {
			total++;
			memset(pembuf, 0, sizeof(pembuf));
			strcpy(pembuf, "");
			len = 1;
			if (run_test_with_buffer(x509,
			    "lws_x509_parse_from_pem with non-existent certificate",
			    "Calling lws_x509_parse_from_pem with non-existent certificate, expected return -1",
			    pembuf, len, -1) == 0) {
				passed++;
			}
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
