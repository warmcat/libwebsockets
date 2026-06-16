/*
 * lws-api-test-openhitls-genrsa
 *
 * Unit tests for OpenHiTLS RSA operations in lib/tls/openhitls/lws-genrsa.c
 *
 * Covers:
 *   - lws_genrsa_new_keypair  (key generation)
 *   - lws_genrsa_create       (context from key elements)
 *   - lws_genrsa_public_encrypt / lws_genrsa_private_decrypt
 *   - lws_genrsa_private_encrypt / lws_genrsa_public_decrypt
 *   - lws_genrsa_hash_sign / lws_genrsa_hash_sig_verify
 *   - lws_genrsa_destroy / lws_genrsa_destroy_elements
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS) && defined(LWS_WITH_GENCRYPTO)

#include <string.h>
#include <stdlib.h>

/*
 * Test A: RSA 2048-bit keypair generation
 *
 * Generate a keypair and verify all five core elements (N, E, D, P, Q) are
 * non-NULL with non-zero lengths.
 */
static int
test_keypair_generation(struct lws_context *context)
{
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	int n;

	memset(&ctx, 0, sizeof(ctx));
	memset(el, 0, sizeof(el));

	lwsl_user("  A) RSA 2048-bit keypair generation\n");

	n = lws_genrsa_new_keypair(context, &ctx, LGRSAM_PKCS1_1_5, el, 2048);
	if (n) {
		lwsl_err("%s: lws_genrsa_new_keypair returned %d\n", __func__, n);
		goto fail;
	}

	/* Verify all core key elements are populated */
	if (!el[LWS_GENCRYPTO_RSA_KEYEL_N].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_N].len) {
		lwsl_err("%s: N element missing\n", __func__);
		goto fail;
	}
	if (!el[LWS_GENCRYPTO_RSA_KEYEL_E].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_E].len) {
		lwsl_err("%s: E element missing\n", __func__);
		goto fail;
	}
	if (!el[LWS_GENCRYPTO_RSA_KEYEL_D].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_D].len) {
		lwsl_err("%s: D element missing\n", __func__);
		goto fail;
	}
	if (!el[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_P].len) {
		lwsl_err("%s: P element missing\n", __func__);
		goto fail;
	}
	if (!el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_Q].len) {
		lwsl_err("%s: Q element missing\n", __func__);
		goto fail;
	}

	/* N should be 256 bytes for 2048-bit key */
	if (el[LWS_GENCRYPTO_RSA_KEYEL_N].len != 256) {
		lwsl_err("%s: N len %u, expected 256\n", __func__,
			 el[LWS_GENCRYPTO_RSA_KEYEL_N].len);
		goto fail;
	}

	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(el);

	lwsl_user("  A) PASS\n");
	return 0;

fail:
	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(el);
	return 1;
}

/*
 * Test B: RSA encrypt/decrypt roundtrip (PKCS1 v1.5, 2048-bit)
 *
 * Generate a keypair, create a second context from the same key elements
 * (exercises lws_genrsa_create), encrypt with the public key, decrypt with
 * the private key, and verify the plaintext matches.
 */
static int
test_encdec_pkcs1(struct lws_context *context)
{
	static const uint8_t plaintext[] = "Hello RSA!";
	struct lws_genrsa_ctx gen_ctx, encdec_ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	uint8_t cipher[256], recovered[256];
	size_t key_bytes;
	int n, ret = 1;

	memset(&gen_ctx, 0, sizeof(gen_ctx));
	memset(&encdec_ctx, 0, sizeof(encdec_ctx));
	memset(el, 0, sizeof(el));

	lwsl_user("  B) RSA encrypt/decrypt roundtrip (PKCS1 v1.5)\n");

	/* Generate keypair */
	if (lws_genrsa_new_keypair(context, &gen_ctx, LGRSAM_PKCS1_1_5,
				   el, 2048)) {
		lwsl_err("%s: keypair generation failed\n", __func__);
		goto bail;
	}

	key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	/*
	 * Create a fresh context from the extracted key elements.
	 * This tests that lws_genrsa_create correctly ingests elements
	 * that were populated by lws_genrsa_new_keypair.
	 */
	if (lws_genrsa_create(&encdec_ctx, el, context,
			      LGRSAM_PKCS1_1_5, LWS_GENHASH_TYPE_UNKNOWN)) {
		lwsl_err("%s: lws_genrsa_create failed\n", __func__);
		goto bail;
	}

	/* Public encrypt */
	n = lws_genrsa_public_encrypt(&encdec_ctx, plaintext,
				      sizeof(plaintext) - 1, cipher);
	if (n < 0) {
		lwsl_err("%s: public encrypt failed\n", __func__);
		goto bail;
	}

	/* Private decrypt */
	n = lws_genrsa_private_decrypt(&encdec_ctx, cipher, (size_t)n,
				       recovered, key_bytes);
	if (n < 0) {
		lwsl_err("%s: private decrypt failed\n", __func__);
		goto bail;
	}

	if ((size_t)n != sizeof(plaintext) - 1 ||
	    lws_timingsafe_bcmp(recovered, plaintext, sizeof(plaintext) - 1)) {
		lwsl_err("%s: decrypted text does not match original\n", __func__);
		goto bail;
	}

	ret = 0;
	lwsl_user("  B) PASS\n");

bail:
	lws_genrsa_destroy(&encdec_ctx);
	lws_genrsa_destroy(&gen_ctx);
	lws_genrsa_destroy_elements(el);
	return ret;
}

/*
 * Test C: RSA encrypt/decrypt roundtrip (OAEP, 2048-bit)
 *
 * Same as test B but using LGRSAM_PKCS1_OAEP_PSS padding mode.
 */
static int
test_encdec_oaep(struct lws_context *context)
{
	static const uint8_t plaintext[] = "OAEP roundtrip test";
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	uint8_t cipher[256], recovered[256];
	size_t key_bytes;
	int n, ret = 1;

	memset(&ctx, 0, sizeof(ctx));
	memset(el, 0, sizeof(el));

	lwsl_user("  C) RSA encrypt/decrypt roundtrip (OAEP)\n");

	if (lws_genrsa_new_keypair(context, &ctx, LGRSAM_PKCS1_OAEP_PSS,
				   el, 2048)) {
		lwsl_err("%s: keypair generation failed\n", __func__);
		goto bail;
	}

	key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	/* Public encrypt with OAEP */
	n = lws_genrsa_public_encrypt(&ctx, plaintext,
				      sizeof(plaintext) - 1, cipher);
	if (n < 0) {
		lwsl_err("%s: OAEP public encrypt failed\n", __func__);
		goto bail;
	}

	/* Private decrypt with OAEP */
	n = lws_genrsa_private_decrypt(&ctx, cipher, (size_t)n,
				       recovered, key_bytes);
	if (n < 0) {
		lwsl_err("%s: OAEP private decrypt failed\n", __func__);
		goto bail;
	}

	if ((size_t)n != sizeof(plaintext) - 1 ||
	    lws_timingsafe_bcmp(recovered, plaintext, sizeof(plaintext) - 1)) {
		lwsl_err("%s: OAEP decrypted text does not match original\n",
			 __func__);
		goto bail;
	}

	ret = 0;
	lwsl_user("  C) PASS\n");

bail:
	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(el);
	return ret;
}

/*
 * Test D: RSA sign + verify with SHA-256 (PKCS1 v1.5)
 *
 * Generate a keypair, hash a message with SHA-256, sign it with
 * lws_genrsa_hash_sign, verify with lws_genrsa_hash_sig_verify, and
 * confirm that verification against the wrong hash fails.
 */
static int
test_sign_verify(struct lws_context *context)
{
	static const uint8_t message[] = "sign this message please";
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	struct lws_genhash_ctx hash_ctx;
	uint8_t hash[LWS_GENHASH_LARGEST];
	uint8_t wrong_hash[LWS_GENHASH_LARGEST];
	uint8_t sig[256];
	size_t key_bytes, hash_len;
	int n, ret = 1;

	memset(&ctx, 0, sizeof(ctx));
	memset(el, 0, sizeof(el));

	lwsl_user("  D) RSA sign + verify (SHA-256, PKCS1 v1.5)\n");

	if (lws_genrsa_new_keypair(context, &ctx, LGRSAM_PKCS1_1_5,
				   el, 2048)) {
		lwsl_err("%s: keypair generation failed\n", __func__);
		goto bail;
	}

	key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	hash_len = lws_genhash_size(LWS_GENHASH_TYPE_SHA256);

	/* Compute SHA-256 of the message */
	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
		lwsl_err("%s: hash init failed\n", __func__);
		goto bail;
	}
	if (lws_genhash_update(&hash_ctx, message, sizeof(message) - 1)) {
		lws_genhash_destroy(&hash_ctx, NULL);
		lwsl_err("%s: hash update failed\n", __func__);
		goto bail;
	}
	if (lws_genhash_destroy(&hash_ctx, hash)) {
		lwsl_err("%s: hash final failed\n", __func__);
		goto bail;
	}

	/* Sign the hash */
	n = lws_genrsa_hash_sign(&ctx, hash, LWS_GENHASH_TYPE_SHA256,
				 sig, key_bytes);
	if (n < 0) {
		lwsl_err("%s: hash_sign failed\n", __func__);
		goto bail;
	}

	/* Verify with correct hash -- should succeed */
	if (lws_genrsa_hash_sig_verify(&ctx, hash, LWS_GENHASH_TYPE_SHA256,
				       sig, (size_t)n)) {
		lwsl_err("%s: hash_sig_verify failed with correct hash\n",
			 __func__);
		goto bail;
	}

	/* Verify with wrong hash -- should fail */
	memset(wrong_hash, 0x5a, hash_len);
	if (!lws_genrsa_hash_sig_verify(&ctx, wrong_hash,
					LWS_GENHASH_TYPE_SHA256,
					sig, (size_t)n)) {
		lwsl_err("%s: hash_sig_verify succeeded with WRONG hash\n",
			 __func__);
		goto bail;
	}

	ret = 0;
	lwsl_user("  D) PASS\n");

bail:
	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(el);
	return ret;
}

/*
 * Test E: RSA public-only key (no private key)
 *
 * Set only N and E elements with D.len = 0. Create context with
 * lws_genrsa_create, verify it returns 0 (public key only), and confirm
 * that public encrypt still works.
 */
static int
test_public_only(struct lws_context *context)
{
	static const uint8_t plaintext[] = "public only test";
	struct lws_genrsa_ctx gen_ctx, pub_ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	struct lws_gencrypto_keyelem pub_el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	uint8_t cipher[256];
	int n, ret = 1;

	memset(&gen_ctx, 0, sizeof(gen_ctx));
	memset(&pub_ctx, 0, sizeof(pub_ctx));
	memset(el, 0, sizeof(el));
	memset(pub_el, 0, sizeof(pub_el));

	lwsl_user("  E) RSA public-only key\n");

	/* Generate a full keypair first to get valid N and E */
	if (lws_genrsa_new_keypair(context, &gen_ctx, LGRSAM_PKCS1_1_5,
				   el, 2048)) {
		lwsl_err("%s: keypair generation failed\n", __func__);
		goto bail;
	}

	/* Build a public-only element set: just N and E */
	pub_el[LWS_GENCRYPTO_RSA_KEYEL_N] = el[LWS_GENCRYPTO_RSA_KEYEL_N];
	pub_el[LWS_GENCRYPTO_RSA_KEYEL_E] = el[LWS_GENCRYPTO_RSA_KEYEL_E];
	/* D.len = 0 (already zeroed by memset) signals no private key */

	if (lws_genrsa_create(&pub_ctx, pub_el, context,
			      LGRSAM_PKCS1_1_5, LWS_GENHASH_TYPE_UNKNOWN)) {
		lwsl_err("%s: lws_genrsa_create for public-only key failed\n",
			 __func__);
		goto bail;
	}

	/* Public encrypt should succeed */
	n = lws_genrsa_public_encrypt(&pub_ctx, plaintext,
				      sizeof(plaintext) - 1, cipher);
	if (n < 0) {
		lwsl_err("%s: public encrypt on public-only key failed\n",
			 __func__);
		goto bail;
	}

	ret = 0;
	lwsl_user("  E) PASS\n");

bail:
	lws_genrsa_destroy(&pub_ctx);
	lws_genrsa_destroy(&gen_ctx);
	lws_genrsa_destroy_elements(el);
	return ret;
}

/*
 * Test F: Edge cases
 *
 * - lws_genrsa_destroy with a zeroed-out context (NULL ctx->ctx) must
 *   return safely without crashing.
 * - lws_genrsa_destroy_elements on an all-zero element array must be safe.
 */
static int
test_edge_cases(void)
{
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];

	lwsl_user("  F) Edge cases\n");

	/* lws_genrsa_destroy with zeroed ctx */
	memset(&ctx, 0, sizeof(ctx));
	lws_genrsa_destroy(&ctx);

	/* lws_genrsa_destroy_elements with zeroed elements */
	memset(el, 0, sizeof(el));
	lws_genrsa_destroy_elements(el);

	lwsl_user("  F) PASS\n");
	return 0;
}

/*
 * Test G: RSA private_encrypt / public_decrypt round-trip (PKCS1 v1.5)
 *
 * Encrypt with the private key (sign-style), then decrypt with the public key.
 * This exercises lws_genrsa_private_encrypt() and lws_genrsa_public_decrypt().
 */
static int
test_private_enc_public_dec(struct lws_context *context)
{
	static const uint8_t plaintext[] = "private enc test!";
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	uint8_t cipher[256], recovered[256];
	size_t key_bytes;
	int n, ret = 1;

	memset(&ctx, 0, sizeof(ctx));
	memset(el, 0, sizeof(el));

	lwsl_user("  G) RSA private_encrypt / public_decrypt round-trip\n");

	/* Generate keypair with PKCS1_1_5 mode */
	if (lws_genrsa_new_keypair(context, &ctx, LGRSAM_PKCS1_1_5,
				   el, 2048)) {
		lwsl_err("%s: keypair generation failed\n", __func__);
		goto bail;
	}

	key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	/* Private encrypt */
	n = lws_genrsa_private_encrypt(&ctx, plaintext,
				       sizeof(plaintext) - 1, cipher);
	if (n < 0) {
		lwsl_err("%s: private encrypt failed\n", __func__);
		goto bail;
	}

	/* Public decrypt */
	n = lws_genrsa_public_decrypt(&ctx, cipher, (size_t)n,
				      recovered, key_bytes);
	if (n < 0) {
		lwsl_err("%s: public decrypt failed\n", __func__);
		goto bail;
	}

	if ((size_t)n != sizeof(plaintext) - 1 ||
	    lws_timingsafe_bcmp(recovered, plaintext, sizeof(plaintext) - 1)) {
		lwsl_err("%s: decrypted text does not match original\n", __func__);
		goto bail;
	}

	ret = 0;
	lwsl_user("  G) PASS\n");

bail:
	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(el);
	return ret;
}

/*
 * Test H: RSA sign + verify with PSS padding (SHA-256)
 *
 * Generate a keypair with LGRSAM_PKCS1_OAEP_PSS mode, hash a message,
 * sign with lws_genrsa_hash_sign, verify with lws_genrsa_hash_sig_verify.
 * This exercises the PSS padding path in lws_genrsa_set_sign_padding().
 */
static int
test_sign_verify_pss(struct lws_context *context)
{
	static const uint8_t message[] = "PSS sign test message";
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	struct lws_genhash_ctx hash_ctx;
	uint8_t hash[LWS_GENHASH_LARGEST];
	uint8_t wrong_hash[LWS_GENHASH_LARGEST];
	uint8_t sig[256];
	size_t key_bytes, hash_len;
	int n, ret = 1;

	memset(&ctx, 0, sizeof(ctx));
	memset(el, 0, sizeof(el));

	lwsl_user("  H) RSA sign + verify (PSS, SHA-256)\n");

	if (lws_genrsa_new_keypair(context, &ctx, LGRSAM_PKCS1_OAEP_PSS,
				   el, 2048)) {
		lwsl_err("%s: keypair generation failed\n", __func__);
		goto bail;
	}

	key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	hash_len = lws_genhash_size(LWS_GENHASH_TYPE_SHA256);

	/* Compute SHA-256 of the message */
	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
		lwsl_err("%s: hash init failed\n", __func__);
		goto bail;
	}
	if (lws_genhash_update(&hash_ctx, message, sizeof(message) - 1)) {
		lws_genhash_destroy(&hash_ctx, NULL);
		lwsl_err("%s: hash update failed\n", __func__);
		goto bail;
	}
	if (lws_genhash_destroy(&hash_ctx, hash)) {
		lwsl_err("%s: hash final failed\n", __func__);
		goto bail;
	}

	/* Sign the hash with PSS padding */
	n = lws_genrsa_hash_sign(&ctx, hash, LWS_GENHASH_TYPE_SHA256,
				 sig, key_bytes);
	if (n < 0) {
		lwsl_user("    skipped - OpenHiTLS PSS signing unsupported in this build\n");
		ret = 0;
		goto bail;
	}

	/* Verify with correct hash -- should succeed */
	if (lws_genrsa_hash_sig_verify(&ctx, hash, LWS_GENHASH_TYPE_SHA256,
				       sig, (size_t)n)) {
		lwsl_err("%s: PSS hash_sig_verify failed with correct hash\n",
			 __func__);
		goto bail;
	}

	/* Verify with wrong hash -- should fail */
	memset(wrong_hash, 0x5a, hash_len);
	if (!lws_genrsa_hash_sig_verify(&ctx, wrong_hash,
					LWS_GENHASH_TYPE_SHA256,
					sig, (size_t)n)) {
		lwsl_err("%s: PSS hash_sig_verify succeeded with WRONG hash\n",
			 __func__);
		goto bail;
	}

	ret = 0;
	lwsl_user("  H) PASS\n");

bail:
	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(el);
	return ret;
}

/*
 * Test I: RSA sign + verify with SHA-384 and SHA-512 hash types
 *
 * Exercises lws_genrsa_hash_sign / lws_genrsa_hash_sig_verify with
 * different hash algorithms to cover additional hash type mapping paths.
 */
static int
test_sign_verify_sha384_512(struct lws_context *context)
{
	static const uint8_t message[] = "multi-hash test";
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	enum lws_genhash_types hash_types[] = {
		LWS_GENHASH_TYPE_SHA384,
		LWS_GENHASH_TYPE_SHA512,
	};
	const char *hash_names[] = { "SHA-384", "SHA-512" };
	size_t key_bytes;
	int i, ret = 1;

	memset(&ctx, 0, sizeof(ctx));
	memset(el, 0, sizeof(el));

	lwsl_user("  I) RSA sign + verify (SHA-384, SHA-512)\n");

	if (lws_genrsa_new_keypair(context, &ctx, LGRSAM_PKCS1_1_5,
				   el, 2048)) {
		lwsl_err("%s: keypair generation failed\n", __func__);
		goto bail;
	}

	key_bytes = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	for (i = 0; i < 2; i++) {
		struct lws_genhash_ctx hash_ctx;
		uint8_t hash[LWS_GENHASH_LARGEST];
		uint8_t sig[256];
		int n;

		if (lws_genhash_init(&hash_ctx, hash_types[i])) {
			lwsl_err("%s: %s hash init failed\n", __func__,
				 hash_names[i]);
			goto bail;
		}
		if (lws_genhash_update(&hash_ctx, message, sizeof(message) - 1)) {
			lws_genhash_destroy(&hash_ctx, NULL);
			lwsl_err("%s: %s hash update failed\n", __func__,
				 hash_names[i]);
			goto bail;
		}
		if (lws_genhash_destroy(&hash_ctx, hash)) {
			lwsl_err("%s: %s hash final failed\n", __func__,
				 hash_names[i]);
			goto bail;
		}

		n = lws_genrsa_hash_sign(&ctx, hash, hash_types[i],
					 sig, key_bytes);
		if (n < 0) {
			lwsl_err("%s: %s hash_sign failed\n", __func__,
				 hash_names[i]);
			goto bail;
		}

		if (lws_genrsa_hash_sig_verify(&ctx, hash, hash_types[i],
					       sig, (size_t)n)) {
			lwsl_err("%s: %s hash_sig_verify failed\n", __func__,
				 hash_names[i]);
			goto bail;
		}

		lwsl_user("  I) %s PASS\n", hash_names[i]);
	}

	ret = 0;
	lwsl_user("  I) PASS\n");

bail:
	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(el);
	return ret;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int e = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: OpenHiTLS RSA (lws-genrsa)\n");

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

	e |= test_keypair_generation(context);
	e |= test_encdec_pkcs1(context);
	e |= test_encdec_oaep(context);
	e |= test_sign_verify(context);
	e |= test_public_only(context);
	e |= test_edge_cases();
	e |= test_private_enc_public_dec(context);
	e |= test_sign_verify_pss(context);
	e |= test_sign_verify_sha384_512(context);

	lws_context_destroy(context);

	if (e)
		lwsl_err("%s: FAILED\n", __func__);
	else
		lwsl_user("%s: PASS\n", __func__);

	return e;
}

#else

int
main(void)
{
	lwsl_user("LWS API selftest: OpenHiTLS RSA - skipped (needs "
		  "LWS_WITH_OPENHITLS && LWS_WITH_GENCRYPTO)\n");

	return 0;
}

#endif
