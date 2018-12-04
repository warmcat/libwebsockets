/*
 * lws-api-test-gencrypto - lws-genaes
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

static const uint8_t
	/*
	 * produced with (plaintext.txt contains "test plaintext\0\0")
	 *
	 * openssl enc -aes256 \
	 *   -K "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210" \
	 *   -iv "0123456789abcdeffedcba9876543210"
	 *   -in plaintext.txt -out out.enc
	 *
	 */
	*cbc256	= (uint8_t *)"test plaintext\0\0",
	cbc256_enc[] = {
		0x2b, 0x5d, 0xb2, 0xa8, 0x5a, 0x5a, 0xf4, 0x2e,
		0xf7, 0xf9, 0xc5, 0x3c, 0x73, 0xef, 0x40, 0x88,
	}, cbc256_iv[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}, cbc256_key[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
;

static int
test_genaes_cbc(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_jwk_elements e;
	uint8_t res[32], res1[32];

	/*
	 * As part of a jwk, these are allocated.  But here we just use one as
	 * a wrapper on a static binary key.
	 */
	e.buf = (uint8_t *)cbc256_key;
	e.len = sizeof(cbc256_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CBC, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, cbc256, 16, res, (uint8_t *)cbc256_iv,
			     NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (memcmp(cbc256_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CBC, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)cbc256_iv,
			     NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (memcmp(cbc256, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	return 0;

bail:
	lws_genaes_destroy(&ctx);

	return -1;
}

static const uint8_t
/*
 * produced with (plaintext.txt contains "test plaintext\0\0")
 *
 * openssl enc -aes-128-cfb \
 *   -K "0123456789abcdeffedcba9876543210" \
 *   -iv "0123456789abcdeffedcba9876543210"
 *   -in plaintext.txt -out out.enc
 *
 */
*cfb128	= (uint8_t *)"test plaintext\0\0",
cfb128_enc[] = {
	0xd2, 0x11, 0x86, 0xd7, 0xa9, 0x55, 0x59, 0x04,
	0x4f, 0x63, 0x7c, 0xb9, 0xc6, 0xa1, 0xc9, 0x71
}, cfb128_iv[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
}, cfb128_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static int
test_genaes_cfb128(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_jwk_elements e;
	uint8_t res[32], res1[32];
	size_t iv_off = 0;

	e.buf = (uint8_t *)cfb128_key;
	e.len = sizeof(cfb128_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CFB128, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, cfb128, 16, res, (uint8_t *)cfb128_iv,
			     NULL, &iv_off)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (memcmp(cfb128_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	iv_off = 0;

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CFB128, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)cfb128_iv,
			     NULL, &iv_off)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (memcmp(cfb128, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res1, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	return 0;

bail:
	lws_genaes_destroy(&ctx);

	return -1;
}

static const uint8_t
/*
 * produced with (plaintext.txt contains "test plaintext\0\0")
 *
 * openssl enc -aes-128-cfb8 \
 *   -K "0123456789abcdeffedcba9876543210" \
 *   -iv "0123456789abcdeffedcba9876543210"
 *   -in plaintext.txt -out out.enc
 *
 */
*cfb8	= (uint8_t *)"test plaintext\0\0",
cfb8_enc[] = {
	0xd2, 0x91, 0x06, 0x2d, 0x1b, 0x1e, 0x9b, 0x39,
	0xa6, 0x65, 0x8e, 0xbe, 0x68, 0x32, 0x3d, 0xab
}, cfb8_iv[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
}, cfb8_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static int
test_genaes_cfb8(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_jwk_elements e;
	uint8_t res[32], res1[32];

	e.buf = (uint8_t *)cfb8_key;
	e.len = sizeof(cfb8_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CFB8, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, cfb8, 16, res, (uint8_t *)cfb8_iv,
			     NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (memcmp(cfb8_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CFB8, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)cfb8_iv,
			     NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (memcmp(cfb8, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res1, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	return 0;

bail:
	lws_genaes_destroy(&ctx);

	return -1;
}

static const uint8_t
/*
 * produced with (plaintext.txt contains "test plaintext\0\0")
 *
 * openssl enc -aes-128-ctr \
 *   -K "0123456789abcdeffedcba9876543210" \
 *   -iv "0123456789abcdeffedcba9876543210"
 *   -in plaintext.txt -out out.enc
 *
 */
*ctr	= (uint8_t *)"test plaintext\0\0",
ctr_enc[] = {
	0xd2, 0x11, 0x86, 0xd7, 0xa9, 0x55, 0x59, 0x04,
	0x4f, 0x63, 0x7c, 0xb9, 0xc6, 0xa1, 0xc9, 0x71
}, ctr_iv[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
}, ctr_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static int
test_genaes_ctr(void)
{
	uint8_t nonce_counter[16], sb[16];
	struct lws_genaes_ctx ctx;
	struct lws_jwk_elements e;
	uint8_t res[32], res1[32];
	size_t nc_off = 0;

	e.buf = (uint8_t *)ctr_key;
	e.len = sizeof(ctr_key);

	memset(sb, 0, sizeof(nonce_counter));
	memcpy(nonce_counter, ctr_iv, sizeof(ctr_iv));

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, ctr, 16, res, nonce_counter, sb, &nc_off)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (memcmp(ctr_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	nc_off = 0;
	memset(sb , 0, sizeof(nonce_counter));
	memcpy(nonce_counter, ctr_iv, sizeof(ctr_iv));

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CTR, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, nonce_counter, sb, &nc_off)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (memcmp(ctr, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res1, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	lws_explicit_bzero(sb, sizeof(sb));

	return 0;

bail:
	lws_genaes_destroy(&ctx);

	return -1;
}

static const uint8_t
/*
 * produced with (plaintext.txt contains "test plaintext\0\0")
 *
 * openssl enc -aes-128-ecb \
 *   -K "0123456789abcdeffedcba9876543210" \
 *   -in plaintext.txt -out out.enc
 *
 */
*ecb	= (uint8_t *)"test plaintext\0\0",
ecb_enc[] = {
	0xf3, 0xe5, 0x6c, 0x80, 0x3a, 0xf1, 0xc4, 0xa0,
	0x7e, 0xdf, 0x86, 0x0f, 0x6d, 0xca, 0x5d, 0x36,
	0x17, 0x22, 0x37, 0x42, 0x47, 0x41, 0x67, 0x7d,
	0x99, 0x25, 0x02, 0x6b, 0x6b, 0x8f, 0x9c, 0x7f
}, ecb_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static int
test_genaes_ecb(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_jwk_elements e;
	uint8_t res[32], res1[32];

	/*
	 * As part of a jwk, these are allocated.  But here we just use one as
	 * a wrapper on a static binary key.
	 */
	e.buf = (uint8_t *)ecb_key;
	e.len = sizeof(ecb_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_ECB, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, ecb, 16, res, NULL, NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (memcmp(ecb_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_ECB, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, NULL, NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (memcmp(ecb, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	return 0;

bail:
	lws_genaes_destroy(&ctx);

	return -1;
}

static const uint8_t
	/*
	 * produced with (plaintext.txt contains "test plaintext\0\0")
	 *
	 * openssl enc -aes-128-ofb \
	 *   -K "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210" \
	 *   -iv "0123456789abcdeffedcba9876543210"
	 *   -in plaintext.txt -out out.enc
	 *
	 */
	*ofb	= (uint8_t *)"test plaintext\0\0",
	ofb_enc[] = {
		/* !!! ugh... openssl app produces this... */
		// 0xd2, 0x11, 0x86, 0xd7, 0xa9, 0x55, 0x59, 0x04,
		// 0x4f, 0x63, 0x7c, 0xb9, 0xc6, 0xa1, 0xc9, 0x71,
		/* but both OpenSSL and mbedTLS produce this */
		0x11, 0x33, 0x6D, 0xFC, 0x88, 0x4C, 0x28, 0xBA,
		0xD0, 0xF2, 0x6C, 0xBC, 0xDE, 0x4A, 0x56, 0x20
	}, ofb_iv[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}, ofb_key[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
;

static int
test_genaes_ofb(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_jwk_elements e;
	uint8_t res[32], res1[32];
	size_t iv_off = 0;

	e.buf = (uint8_t *)ofb_key;
	e.len = sizeof(ofb_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_OFB, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, ofb, 16, res, (uint8_t *)ofb_iv, NULL,
			     &iv_off)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (memcmp(ofb_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	iv_off = 0;

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_OFB, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)ofb_iv, NULL,
			     &iv_off)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (memcmp(ofb, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	return 0;

bail:
	lws_genaes_destroy(&ctx);

	return -1;
}

static const uint8_t
	/*
	 * Fedora openssl tool doesn't support xts... this data produced
	 * by testing on mbedtls + OpenSSL and getting the same result
	 *
	 * NOTICE that xts requires a double-length key...
	 */
	*xts	= (uint8_t *)"test plaintext\0\0",
	xts_enc[] = {
		0xA9, 0x26, 0xFD, 0x68, 0x1E, 0x6A, 0x80, 0xCA,
		0x18, 0xD5, 0xEB, 0x08, 0x23, 0xF1, 0x90, 0x15
	}, xts_key[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
;

static int
test_genaes_xts(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_jwk_elements e;
	uint8_t res[32], res1[32], data_unit[16];

	memset(data_unit, 0, sizeof(data_unit));

	e.buf = (uint8_t *)xts_key;
	e.len = sizeof(xts_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_XTS, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, xts, 16, res, data_unit, NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (memcmp(xts_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_XTS, &e, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, data_unit, NULL, NULL)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (memcmp(xts, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genaes_destroy(&ctx);

	return 0;

bail:
	lws_genaes_destroy(&ctx);

	return -1;
}


int
test_genaes(struct lws_context *context)
{

	if (test_genaes_cbc())
		goto bail;

	if (test_genaes_cfb128())
		goto bail;

	if (test_genaes_cfb8())
		goto bail;

	if (test_genaes_ctr())
		goto bail;

	if (test_genaes_ecb())
		goto bail;

	if (test_genaes_ofb())
		goto bail;

#if defined(MBEDTLS_CONFIG_H) && !defined(MBEDTLS_CIPHER_MODE_XTS)
#else
	if (test_genaes_xts())
		goto bail;
#endif

	/* end */

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;

bail:
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;
}
