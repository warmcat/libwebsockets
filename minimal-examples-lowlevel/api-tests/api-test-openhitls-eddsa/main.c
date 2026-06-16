/*
 * lws-api-test-openhitls-eddsa
 *
 * Unit tests for OpenHiTLS EdDSA / OKP generic crypto.
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS) && defined(LWS_WITH_GENCRYPTO)

#include <string.h>

static void
destroy_okp(struct lws_gencrypto_keyelem *el)
{
	lws_genec_destroy_elements(el);
	memset(el, 0, sizeof(*el) * LWS_GENCRYPTO_MAX_KEYEL_COUNT);
}

static void
copy_okp_public(struct lws_gencrypto_keyelem *dst,
		const struct lws_gencrypto_keyelem *src)
{
	memset(dst, 0, sizeof(*dst) * LWS_GENCRYPTO_MAX_KEYEL_COUNT);

	dst[LWS_GENCRYPTO_OKP_KEYEL_CRV] =
		src[LWS_GENCRYPTO_OKP_KEYEL_CRV];
	dst[LWS_GENCRYPTO_OKP_KEYEL_X] =
		src[LWS_GENCRYPTO_OKP_KEYEL_X];
}

static int
test_ed25519_roundtrip(void)
{
	static const uint8_t msg[] = "OpenHiTLS Ed25519 generic signing";
	static const uint8_t bad_msg[] = "OpenHiTLS Ed25519 bad payload";
	struct lws_gencrypto_keyelem key[LWS_GENCRYPTO_MAX_KEYEL_COUNT];
	struct lws_gencrypto_keyelem pub[LWS_GENCRYPTO_MAX_KEYEL_COUNT];
	struct lws_genec_ctx signer, verifier, imported;
	uint8_t sig[64], sig2[64];
	int n, n2, ret = 1;

	memset(key, 0, sizeof(key));
	memset(pub, 0, sizeof(pub));
	memset(&signer, 0, sizeof(signer));
	memset(&verifier, 0, sizeof(verifier));
	memset(&imported, 0, sizeof(imported));

	if (lws_geneddsa_create(&signer, NULL, NULL) ||
	    lws_geneddsa_new_keypair(&signer, "Ed25519", key)) {
		lwsl_err("%s: Ed25519 keygen failed\n", __func__);
		goto bail;
	}

	if (key[LWS_GENCRYPTO_OKP_KEYEL_X].len != 32 ||
	    key[LWS_GENCRYPTO_OKP_KEYEL_D].len != 32 ||
	    strcmp((const char *)key[LWS_GENCRYPTO_OKP_KEYEL_CRV].buf,
		   "Ed25519")) {
		lwsl_err("%s: unexpected Ed25519 key element sizes\n",
			 __func__);
		goto bail;
	}

	n = lws_geneddsa_hash_sign_jws(&signer, msg, sizeof(msg) - 1, sig,
				       sizeof(sig));
	if (n != (int)sizeof(sig)) {
		lwsl_err("%s: Ed25519 sign failed: %d\n", __func__, n);
		goto bail;
	}

	copy_okp_public(pub, key);
	if (lws_geneddsa_create(&verifier, NULL, NULL) ||
	    lws_geneddsa_set_key(&verifier, pub)) {
		lwsl_err("%s: Ed25519 public import failed\n", __func__);
		goto bail;
	}

	if (lws_geneddsa_hash_sig_verify_jws(&verifier, msg, sizeof(msg) - 1,
					     sig, sizeof(sig))) {
		lwsl_err("%s: Ed25519 verify failed\n", __func__);
		goto bail;
	}

	if (!lws_geneddsa_hash_sig_verify_jws(&verifier, bad_msg,
					      sizeof(bad_msg) - 1, sig,
					      sizeof(sig))) {
		lwsl_err("%s: Ed25519 accepted wrong payload\n", __func__);
		goto bail;
	}

	if (lws_geneddsa_create(&imported, NULL, NULL) ||
	    lws_geneddsa_set_key(&imported, key)) {
		lwsl_err("%s: Ed25519 private import failed\n", __func__);
		goto bail;
	}

	n2 = lws_geneddsa_hash_sign_jws(&imported, msg, sizeof(msg) - 1,
					sig2, sizeof(sig2));
	if (n2 != (int)sizeof(sig2) ||
	    lws_geneddsa_hash_sig_verify_jws(&verifier, msg, sizeof(msg) - 1,
					     sig2, sizeof(sig2))) {
		lwsl_err("%s: imported Ed25519 sign/verify failed\n",
			 __func__);
		goto bail;
	}

	ret = 0;

bail:
	lws_genec_destroy(&signer);
	lws_genec_destroy(&verifier);
	lws_genec_destroy(&imported);
	destroy_okp(key);

	return ret;
}

static int
test_ed448_explicitly_unsupported(void)
{
	struct lws_gencrypto_keyelem key[LWS_GENCRYPTO_MAX_KEYEL_COUNT];
	struct lws_genec_ctx ctx;
	uint8_t x[57] = {0};
	int ret = 1;

	memset(key, 0, sizeof(key));
	memset(&ctx, 0, sizeof(ctx));

	if (lws_geneddsa_create(&ctx, NULL, NULL)) {
		lwsl_err("%s: create failed\n", __func__);
		return 1;
	}

	if (!lws_geneddsa_new_keypair(&ctx, "Ed448", key)) {
		lwsl_err("%s: Ed448 keygen unexpectedly succeeded\n",
			 __func__);
		goto bail;
	}

	key[LWS_GENCRYPTO_OKP_KEYEL_CRV].buf = (uint8_t *)"Ed448";
	key[LWS_GENCRYPTO_OKP_KEYEL_CRV].len = 6;
	key[LWS_GENCRYPTO_OKP_KEYEL_X].buf = x;
	key[LWS_GENCRYPTO_OKP_KEYEL_X].len = sizeof(x);

	if (!lws_geneddsa_set_key(&ctx, key)) {
		lwsl_err("%s: Ed448 import unexpectedly succeeded\n",
			 __func__);
		goto bail;
	}

	ret = 0;

bail:
	lws_genec_destroy(&ctx);

	return ret;
}

int
main(void)
{
	int ret = 1;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API Test - openhitls eddsa\n");

	if (test_ed25519_roundtrip() || test_ed448_explicitly_unsupported())
		goto bail;

	ret = 0;

bail:
	return lws_cmdline_passfail(0, NULL, ret);
}

#else
int
main(void)
{
	return 0;
}
#endif
