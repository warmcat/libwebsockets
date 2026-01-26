/*
 * lws-api-test-gencrypto - lws-mbedtls-cipherlist
 *
 * was developed with Claude AI assistance
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests for SSL_CTX_set_cipher_list() public API.
 * Developed with Claude AI assistance.
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_MBEDTLS) && defined(LWS_WITH_TLS)

#include <openssl/ssl.h>

/*
 * Test SSL_CTX_set_cipher_list() with various cipher string formats.
 * This tests the cipher parsing through the public API.
 */
int
test_mbedtls_cipherlist(struct lws_context *context)
{
	SSL_CTX *ctx;
	int result = 0;

	lwsl_user("%s: testing SSL_CTX_set_cipher_list()\n", __func__);

	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		lwsl_err("%s: SSL_CTX_new failed\n", __func__);
		return 1;
	}

	/*
	 * Test 1: mbedTLS format (dash-separated)
	 */
	if (!SSL_CTX_set_cipher_list(ctx,
			"TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256")) {
		lwsl_err("%s: FAIL - mbedTLS format rejected\n", __func__);
		result = 1;
	} else
		lwsl_user("%s: PASS - mbedTLS format accepted\n", __func__);

	/*
	 * Test 2: IANA format (underscore-separated)
	 */
	if (!SSL_CTX_set_cipher_list(ctx,
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")) {
		lwsl_err("%s: FAIL - IANA format rejected\n", __func__);
		result = 1;
	} else
		lwsl_user("%s: PASS - IANA format accepted\n", __func__);

	/*
	 * Test 3: Multiple ciphers (comma-separated)
	 */
	if (!SSL_CTX_set_cipher_list(ctx,
			"TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256,"
			"TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")) {
		lwsl_err("%s: FAIL - multiple ciphers rejected\n", __func__);
		result = 1;
	} else
		lwsl_user("%s: PASS - multiple ciphers accepted\n", __func__);

	/*
	 * Test 4: Invalid cipher should fail
	 */
	if (SSL_CTX_set_cipher_list(ctx, "INVALID-CIPHER-NAME")) {
		lwsl_err("%s: FAIL - invalid cipher should be rejected\n",
			 __func__);
		result = 1;
	} else
		lwsl_user("%s: PASS - invalid cipher rejected\n", __func__);

	/*
	 * Test 5: Empty string should fail
	 */
	if (SSL_CTX_set_cipher_list(ctx, "")) {
		lwsl_err("%s: FAIL - empty string should be rejected\n",
			 __func__);
		result = 1;
	} else
		lwsl_user("%s: PASS - empty string rejected\n", __func__);

	SSL_CTX_free(ctx);

	lwsl_user("%s: %s\n", __func__, result ? "FAILED" : "PASSED");

	return result;
}

#endif
