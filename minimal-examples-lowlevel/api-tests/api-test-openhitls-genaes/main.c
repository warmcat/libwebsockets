/*
 * lws-api-test-openhitls-genaes
 *
 * Unit tests for the OpenHiTLS AES abstraction layer in
 * lib/tls/openhitls/lws-genaes.c
 *
 * Tests:
 *   A) AES-256-CBC encrypt + decrypt roundtrip (no padding, 16-byte aligned)
 *   B) AES-128-CBC encrypt + decrypt roundtrip (no padding)
 *   C) AES-256-GCM encrypt + decrypt with AAD
 *   D) AES-128-GCM encrypt + decrypt roundtrip
 *   E) AES-256-CTR encrypt + decrypt roundtrip
 *   F) Edge cases (NULL ctx, destroy without underway)
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS) && defined(LWS_WITH_GENCRYPTO)

#include <string.h>

/* ---------- helpers ---------------------------------------------------- */

static int
hex_eq(const char *label, const uint8_t *a, const uint8_t *b, size_t len)
{
	if (lws_timingsafe_bcmp(a, b, (uint32_t)len)) {
		lwsl_err("%s: %s mismatch\n", __func__, label);
		lwsl_hexdump_notice(a, len);
		lwsl_hexdump_notice(b, len);
		return 1;
	}
	return 0;
}

/* ---------- A) AES-256-CBC encrypt + decrypt roundtrip (NO_PADDING) ---- */

static int
test_aes256_cbc_roundtrip(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key_buf[32], iv[16], ct[32], pt2[32];
	const uint8_t plain[16] = "Hello AES-256!!";
	size_t plain_len = 16;

	lwsl_notice("%s\n", __func__);

	memset(key_buf, 0x00, sizeof(key_buf));
	memset(iv, 0xAA, sizeof(iv));
	memset(ct, 0, sizeof(ct));
	memset(pt2, 0, sizeof(pt2));

	e.buf = key_buf;
	e.len = sizeof(key_buf);

	/* ---- encrypt ---- */
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CBC, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: enc create failed\n", __func__);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, plain, plain_len, ct, iv, NULL, NULL, 0)) {
		lwsl_err("%s: enc crypt failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: enc destroy failed\n", __func__);
		return 1;
	}

	/* ---- decrypt ---- */
	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CBC, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: dec create failed\n", __func__);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, ct, 32, pt2, iv, NULL, NULL, 0)) {
		lwsl_err("%s: dec crypt failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: dec destroy failed\n", __func__);
		return 1;
	}

	if (hex_eq("AES-256-CBC plaintext", plain, pt2, plain_len))
		return 1;

	lwsl_notice("%s: PASS\n", __func__);
	return 0;
}

/* ---------- B) AES-128-CBC encrypt + decrypt roundtrip (NO_PADDING) ---- */

static int
test_aes128_cbc_roundtrip(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key_buf[16], iv[16], ct[32], pt2[32];
	const uint8_t plain[16] = "AES-128 test!!\0\0";
	size_t plain_len = 16;

	lwsl_notice("%s\n", __func__);

	memset(key_buf, 0x42, sizeof(key_buf));
	memset(iv, 0x55, sizeof(iv));
	memset(ct, 0, sizeof(ct));
	memset(pt2, 0, sizeof(pt2));

	e.buf = key_buf;
	e.len = sizeof(key_buf);

	/* encrypt */
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CBC, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: enc create failed\n", __func__);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, plain, plain_len, ct, iv, NULL, NULL, 0)) {
		lwsl_err("%s: enc crypt failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: enc destroy failed\n", __func__);
		return 1;
	}

	/* decrypt */
	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CBC, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: dec create failed\n", __func__);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, ct, 16, pt2, iv, NULL, NULL, 0)) {
		lwsl_err("%s: dec crypt failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: dec destroy failed\n", __func__);
		return 1;
	}

	if (hex_eq("AES-128-CBC plaintext", plain, pt2, plain_len))
		return 1;

	lwsl_notice("%s: PASS\n", __func__);
	return 0;
}

/* ---------- C) AES-256-GCM encrypt + decrypt with AAD ------------------ */

static int
test_aes256_gcm_aad(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key_buf[32], nonce[12];
	const char *plain = "Hello GCM";
	const char *aad_str = "additional data";
	size_t plain_len = 9, aad_len = 15;
	uint8_t ct[64], pt2[64], tag[16], tag2[16];
	size_t iv_off;

	lwsl_notice("%s\n", __func__);

	memset(key_buf, 0x42, sizeof(key_buf));
	memset(nonce, 0xCC, sizeof(nonce));
	memset(ct, 0, sizeof(ct));
	memset(pt2, 0, sizeof(pt2));
	memset(tag, 0, sizeof(tag));

	e.buf = key_buf;
	e.len = sizeof(key_buf);

	/* ---- encrypt ---- */
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_GCM, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: enc create failed\n", __func__);
		return 1;
	}

	/* First crypt: set IV + AAD (out == NULL) */
	iv_off = sizeof(nonce);
	if (lws_genaes_crypt(&ctx, (const uint8_t *)aad_str, aad_len, NULL,
			      nonce, tag, &iv_off, (int)sizeof(tag))) {
		lwsl_err("%s: enc AAD failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}

	/* Second crypt: actual encryption */
	if (lws_genaes_crypt(&ctx, (const uint8_t *)plain, plain_len, ct,
			      NULL, NULL, NULL, 0)) {
		lwsl_err("%s: enc data failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}

	/* destroy to get tag */
	if (lws_genaes_destroy(&ctx, tag, sizeof(tag))) {
		lwsl_err("%s: enc destroy failed\n", __func__);
		return 1;
	}

	/* ---- decrypt ---- */
	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_GCM, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: dec create failed\n", __func__);
		return 1;
	}

	iv_off = sizeof(nonce);
	if (lws_genaes_crypt(&ctx, (const uint8_t *)aad_str, aad_len, NULL,
			      nonce, tag, &iv_off, (int)sizeof(tag))) {
		lwsl_err("%s: dec AAD failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, ct, plain_len, pt2,
			      NULL, NULL, NULL, 0)) {
		lwsl_err("%s: dec data failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}

	/* destroy verifies tag internally */
	if (lws_genaes_destroy(&ctx, tag2, sizeof(tag2))) {
		lwsl_err("%s: dec destroy (tag verify) failed\n", __func__);
		return 1;
	}

	if (hex_eq("AES-256-GCM plaintext", (const uint8_t *)plain, pt2,
		   plain_len))
		return 1;

	lwsl_notice("%s: PASS\n", __func__);
	return 0;
}

/* ---------- D) AES-128-GCM encrypt + decrypt roundtrip ----------------- */

static int
test_aes128_gcm_roundtrip(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key_buf[16], nonce[12];
	const char *plain = "AES-128-GCM test";
	size_t plain_len = 16;
	uint8_t ct[64], pt2[64], tag[16], tag2[16];
	size_t iv_off;

	lwsl_notice("%s\n", __func__);

	memset(key_buf, 0x11, sizeof(key_buf));
	memset(nonce, 0xDD, sizeof(nonce));
	memset(ct, 0, sizeof(ct));
	memset(pt2, 0, sizeof(pt2));
	memset(tag, 0, sizeof(tag));

	e.buf = key_buf;
	e.len = sizeof(key_buf);

	/* encrypt */
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_GCM, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: enc create failed\n", __func__);
		return 1;
	}

	iv_off = sizeof(nonce);
	if (lws_genaes_crypt(&ctx, (const uint8_t *)plain, plain_len, NULL,
			      nonce, tag, &iv_off, (int)sizeof(tag))) {
		lwsl_err("%s: enc AAD (no-AAD) failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, (const uint8_t *)plain, plain_len, ct,
			      NULL, NULL, NULL, 0)) {
		lwsl_err("%s: enc data failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, tag, sizeof(tag))) {
		lwsl_err("%s: enc destroy failed\n", __func__);
		return 1;
	}

	/* decrypt */
	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_GCM, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: dec create failed\n", __func__);
		return 1;
	}

	iv_off = sizeof(nonce);
	if (lws_genaes_crypt(&ctx, (const uint8_t *)plain, plain_len, NULL,
			      nonce, tag, &iv_off, (int)sizeof(tag))) {
		lwsl_err("%s: dec AAD (no-AAD) failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, ct, plain_len, pt2,
			      NULL, NULL, NULL, 0)) {
		lwsl_err("%s: dec data failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, tag2, sizeof(tag2))) {
		lwsl_err("%s: dec destroy failed\n", __func__);
		return 1;
	}

	if (hex_eq("AES-128-GCM plaintext", (const uint8_t *)plain, pt2,
		   plain_len))
		return 1;

	lwsl_notice("%s: PASS\n", __func__);
	return 0;
}

/* ---------- E) AES-256-CTR encrypt + decrypt roundtrip ----------------- */

static int
test_aes256_ctr_roundtrip(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key_buf[32], nonce_counter[16], sb[16];
	const char *plain = "CTR mode roundtrip test!";
	size_t plain_len = 24;
	uint8_t ct[64], pt2[64];
	size_t nc_off;

	lwsl_notice("%s\n", __func__);

	memset(key_buf, 0x42, sizeof(key_buf));
	memset(nonce_counter, 0, sizeof(nonce_counter));
	nonce_counter[15] = 1;
	memset(sb, 0, sizeof(sb));

	e.buf = key_buf;
	e.len = sizeof(key_buf);

	/* encrypt */
	nc_off = 0;
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: enc create failed\n", __func__);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, (const uint8_t *)plain, plain_len, ct,
			      nonce_counter, sb, &nc_off, 0)) {
		lwsl_err("%s: enc crypt failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: enc destroy failed\n", __func__);
		return 1;
	}

	/* verify ciphertext is not the same as plaintext */
	if (!lws_timingsafe_bcmp(plain, ct, (uint32_t)plain_len)) {
		lwsl_err("%s: ciphertext same as plaintext?\n", __func__);
		return 1;
	}

	/* decrypt */
	nc_off = 0;
	memset(nonce_counter, 0, sizeof(nonce_counter));
	nonce_counter[15] = 1;
	memset(sb, 0, sizeof(sb));

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CTR, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: dec create failed\n", __func__);
		return 1;
	}
	if (lws_genaes_crypt(&ctx, ct, plain_len, pt2,
			      nonce_counter, sb, &nc_off, 0)) {
		lwsl_err("%s: dec crypt failed\n", __func__);
		lws_genaes_destroy(&ctx, NULL, 0);
		return 1;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: dec destroy failed\n", __func__);
		return 1;
	}

	if (hex_eq("AES-256-CTR plaintext", (const uint8_t *)plain, pt2,
		   plain_len))
		return 1;

	lwsl_notice("%s: PASS\n", __func__);
	return 0;
}

/* ---------- F) Edge cases ---------------------------------------------- */

static int
test_edge_cases(void)
{
	struct lws_gencrypto_keyelem e;
	struct lws_genaes_ctx ctx;
	uint8_t key_buf[32], iv[16], out[64];

	lwsl_notice("%s\n", __func__);

	memset(key_buf, 0x42, sizeof(key_buf));
	memset(iv, 0, sizeof(iv));
	memset(out, 0, sizeof(out));

	e.buf = key_buf;
	e.len = sizeof(key_buf);

	/*
	 * F.1: lws_genaes_crypt with NULL ctx (ctx->ctx == NULL) must
	 * return -1.  We set ctx.ctx = NULL explicitly.
	 */
	memset(&ctx, 0, sizeof(ctx));
	if (lws_genaes_crypt(&ctx, (const uint8_t *)"data", 4, out,
			      iv, NULL, NULL, 0) != -1) {
		lwsl_err("%s: crypt(NULL ctx) should return -1\n", __func__);
		return 1;
	}

	/*
	 * F.2: lws_genaes_destroy with ctx->ctx == NULL returns 0.
	 */
	memset(&ctx, 0, sizeof(ctx));
	if (lws_genaes_destroy(&ctx, NULL, 0) != 0) {
		lwsl_err("%s: destroy(NULL ctx) should return 0\n", __func__);
		return 1;
	}

	/*
	 * F.3: lws_genaes_destroy without underway (ctx->underway == 0)
	 * should clean up successfully.  We create a context, do not call
	 * crypt (so underway stays 0), then destroy.
	 */
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CBC, &e,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: create for underway test failed\n", __func__);
		return 1;
	}
	/* ctx.underway is still 0 since we never called crypt */
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: destroy without underway failed\n", __func__);
		return 1;
	}

	lwsl_notice("%s: PASS\n", __func__);
	return 0;
}

/* ---------- main ------------------------------------------------------- */

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
	lwsl_user("LWS API selftest: OpenHiTLS genaes\n");

	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws_create_context failed\n", __func__);
		return 1;
	}

	e |= test_aes256_cbc_roundtrip();
	e |= test_aes128_cbc_roundtrip();
	e |= test_aes256_gcm_aad();
	e |= test_aes128_gcm_roundtrip();
	e |= test_aes256_ctr_roundtrip();
	e |= test_edge_cases();

	lws_context_destroy(context);

	if (e)
		lwsl_err("%s: FAILED (%d)\n", __func__, e);
	else
		lwsl_user("%s: pass\n", __func__);

	return e;
}

#else /* !LWS_WITH_OPENHITLS || !LWS_WITH_GENCRYPTO */

int
main(int argc, const char **argv)
{
	lwsl_user("LWS API selftest: OpenHiTLS genaes (SKIP)\n");

	return 0;
}

#endif /* LWS_WITH_OPENHITLS && LWS_WITH_GENCRYPTO */
