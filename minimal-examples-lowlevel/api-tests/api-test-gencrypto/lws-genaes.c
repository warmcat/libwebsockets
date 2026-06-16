/*
 * lws-api-test-gencrypto - lws-genaes
 *
 * Written in 2010-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>


#if defined(LWS_WITH_SCHANNEL) || \
    (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CBC))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_cbc))

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
	struct lws_gencrypto_keyelem e;
	uint8_t res[32], res1[32];

	/*
	 * As part of a jwk, these are allocated.  But here we just use one as
	 * a wrapper on a static binary key.
	 */
	e.buf = (uint8_t *)cbc256_key;
	e.len = sizeof(cbc256_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CBC, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, cbc256, 16, res, (uint8_t *)cbc256_iv,
			     NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy enc failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(cbc256_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}


	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CBC, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)cbc256_iv,
			     NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy dec failed\n", __func__);
		lwsl_hexdump_notice(res1, 16);
		return -1;
	}

	if (lws_timingsafe_bcmp(cbc256, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}
#endif

#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CFB))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_cfb128))
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
	struct lws_gencrypto_keyelem e;
	uint8_t res[32], res1[32];
	size_t iv_off = 0;

	e.buf = (uint8_t *)cfb128_key;
	e.len = sizeof(cfb128_key);

	int n = lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CFB128, &e, 0, NULL);
	if (n) {
		if (n == -2) {
			lwsl_notice("%s: lws_genaes_create unsupported\n", __func__);
			return 0;
		}
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, cfb128, 16, res, (uint8_t *)cfb128_iv,
			     NULL, &iv_off, 0)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(cfb128_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	iv_off = 0;

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CFB128, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)cfb128_iv,
			     NULL, &iv_off, 0)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(cfb128, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res1, 16);
		return -1;
	}

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}
#endif

#if defined(LWS_WITH_SCHANNEL) || \
    (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CFB))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_cfb8))

#if !defined(LWS_HAVE_MBEDTLS_V4)
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
#endif

#if !defined(LWS_HAVE_MBEDTLS_V4)
static int
test_genaes_cfb8(void)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t res[32], res1[32];

	e.buf = (uint8_t *)cfb8_key;
	e.len = sizeof(cfb8_key);

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CFB8, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, cfb8, 16, res, (uint8_t *)cfb8_iv,
			     NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(cfb8_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CFB8, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)cfb8_iv,
			     NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(cfb8, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res1, 16);
		return -1;
	}

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}
#endif
#endif

#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CTR))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_ctr))
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
	struct lws_gencrypto_keyelem e;
	uint8_t res[32], res1[32];
	size_t nc_off = 0;

	int n;

	e.buf = (uint8_t *)ctr_key;
	e.len = sizeof(ctr_key);

	memset(sb, 0, sizeof(nonce_counter));
	memcpy(nonce_counter, ctr_iv, sizeof(ctr_iv));

	n = lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &e, 0, NULL);
	if (n) {
		if (n == -2) {
			lwsl_notice("%s: lws_genaes_create unsupported\n", __func__);
			return 0;
		}
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, ctr, 16, res, nonce_counter, sb, &nc_off, 0)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(ctr_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	nc_off = 0;
	memset(sb , 0, sizeof(nonce_counter));
	memcpy(nonce_counter, ctr_iv, sizeof(ctr_iv));

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CTR, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, nonce_counter, sb, &nc_off, 0)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(ctr, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res1, 16);
		return -1;
	}

	lws_explicit_bzero(sb, sizeof(sb));

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}
#endif

#if defined(LWS_WITH_SCHANNEL) || \
    (defined(LWS_WITH_MBEDTLS)) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_ecb))
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
	struct lws_gencrypto_keyelem e;
	uint8_t res[32], res1[32];

	/*
	 * As part of a jwk, these are allocated.  But here we just use one as
	 * a wrapper on a static binary key.
	 */
	int n;

	e.buf = (uint8_t *)ecb_key;
	e.len = sizeof(ecb_key);

	n = lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_ECB, &e, 0, NULL);
	if (n) {
		if (n == -2) {
			lwsl_notice("%s: lws_genaes_create unsupported\n", __func__);
			return 0;
		}
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, ecb, 16, res, NULL, NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(ecb_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_ECB, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, NULL, NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(ecb, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}
#endif

#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_OFB))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_ofb))
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
	struct lws_gencrypto_keyelem e;
	uint8_t res[32], res1[32];
	size_t iv_off = 0;

	int n;

	e.buf = (uint8_t *)ofb_key;
	e.len = sizeof(ofb_key);

	n = lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_OFB, &e, 0, NULL);
	if (n) {
		if (n == -2) {
			lwsl_notice("%s: lws_genaes_create unsupported\n", __func__);
			return 0;
		}
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, ofb, 16, res, (uint8_t *)ofb_iv, NULL,
			     &iv_off, 0)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(ofb_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	iv_off = 0;

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_OFB, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, (uint8_t *)ofb_iv, NULL,
			     &iv_off, 0)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(ofb, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}

#endif

#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_XTS))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_xts))

#if !defined(LWS_HAVE_MBEDTLS_V4)
static const uint8_t
	/*
	 * Fedora openssl tool doesn't support xts... this data produced
	 * by testing on mbedtls + OpenSSL and getting the same result
	 *
	 * NOTICE that xts requires a double-length key... OpenSSL now checks
	 * the key for duplication so we use a random key
	 */
	*xts	= (uint8_t *)"test plaintext\0\0",
	xts_enc[] = {
		0x87, 0x83, 0x20, 0x8B, 0x15, 0x89, 0xA1, 0x13,
		0xDC, 0xEA, 0x82, 0xB6, 0xFF, 0x8D, 0x76, 0x3A
	}, xts_key[] = {
		0xa4, 0xd6, 0xa2, 0x1a, 0x3b, 0x34, 0x34, 0x43,
		0x9a, 0xe2, 0x6a, 0x01, 0x1c, 0x73, 0x80, 0x3b,
		0xdd, 0xf6, 0xd4, 0x37, 0x5e, 0x0e, 0x1c, 0x72,
		0x8e, 0xe5, 0x18, 0x69, 0xfd, 0x08, 0x40, 0x2b,
		0x98, 0xf9, 0x75, 0xa8, 0x36, 0xd5, 0x0f, 0xa2,
		0x20, 0x04, 0x43, 0xa7, 0x3a, 0xa6, 0x4a, 0xdc,
		0xe9, 0x54, 0x50, 0xfa, 0x38, 0xad, 0x6d, 0x96,
		0x5f, 0x31, 0x9e, 0xcd, 0x33, 0x08, 0xa0, 0x44
	}
;
#endif
#if !defined(LWS_HAVE_MBEDTLS_V4)
static int
test_genaes_xts(void)
{

	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t res[32], res1[32], data_unit[16];

	memset(data_unit, 0, sizeof(data_unit));

	int n;

	e.buf = (uint8_t *)xts_key;
	e.len = sizeof(xts_key);

	n = lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_XTS, &e, 0, NULL);
	if (n) {
		if (n == -2) {
			lwsl_notice("%s: lws_genaes_create unsupported\n", __func__);
			return 0;
		}
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	if (lws_genaes_crypt(&ctx, xts, 16, res, data_unit, NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(xts_enc, res, 16)) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_XTS, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genaes_crypt(&ctx, res, 16, res1, data_unit, NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: lws_genaes_destroy failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(xts, res1, 16)) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		return -1;
	}

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}
#endif
#endif

//#if !defined(LWS_WITH_SCHANNEL)
static const uint8_t
	/*
	 * https://csrc.nist.gov/CSRC/media/Projects/
	 * Cryptographic-Algorithm-Validation-Program/
	 * documents/mac/gcmtestvectors.zip
	 */

	gcm_ct[] = {
		0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c,
		0xd5, 0x36, 0x86, 0x7e, 0xb9, 0xf2, 0x17, 0x36
	}, gcm_iv[] = {
		0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0,
		0xee, 0xd0, 0x66, 0x84
	}, gcm_key[] = {
		0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92,
		0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1,
		0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
		0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
	}, gcm_pt[] = {
		0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e,
		0xeb, 0x31, 0xb2, 0xea, 0xcc, 0x2b, 0xf2, 0xa5
	}, gcm_aad[] = {
		0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
		0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde
	}, gcm_tag[] = {
		0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87,
		0xd7, 0x37, 0xee, 0x62, 0x98, 0xf7, 0x7e, 0x0c
	};

static int
test_genaes_gcm(void)
{
	uint8_t res[sizeof(gcm_ct)], tag[sizeof(gcm_tag)];
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	size_t iv_off = 0;

	int n;

	e.buf = (uint8_t *)gcm_key;
	e.len = sizeof(gcm_key);

	/* Encrypt */

	n = lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_GCM, &e, 0, NULL);
	if (n) {
		if (n == -2) {
			lwsl_notice("%s: lws_genaes_create unsupported\n", __func__);
			return 0;
		}
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	/* first we set the iv and aad */

	iv_off = sizeof(gcm_iv);
	if (lws_genaes_crypt(&ctx, gcm_aad, sizeof(gcm_aad), NULL,
			     (uint8_t *)gcm_iv, (uint8_t *)gcm_tag,
			     &iv_off, sizeof(gcm_tag))) {
		lwsl_err("%s: lws_genaes_crypt 1a failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_crypt(&ctx, gcm_pt, sizeof(gcm_pt), res,
			     NULL, NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt 2a failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, tag, sizeof(tag))) {
		lwsl_err("%s: lws_genaes_destroy enc failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(gcm_ct, res, sizeof(gcm_ct))) {
		lwsl_err("%s: lws_genaes_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, sizeof(gcm_ct));
		return -1;
	}


	/* Decrypt */

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_GCM, &e, 0, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);
		return 1;
	}

	iv_off = sizeof(gcm_iv); /* initial call sets iv + aad + tag */
	if (lws_genaes_crypt(&ctx, gcm_aad, sizeof(gcm_aad), NULL,
			     (uint8_t *)gcm_iv, (uint8_t *)gcm_tag,
			     &iv_off, sizeof(gcm_tag))) {
		lwsl_err("%s: lws_genaes_crypt 1b failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_crypt(&ctx, gcm_ct, sizeof(gcm_ct), res,
			     NULL, NULL, NULL, 0)) {
		lwsl_err("%s: lws_genaes_crypt 2b failed\n", __func__);
		goto bail;
	}

	if (lws_genaes_destroy(&ctx, tag, sizeof(tag))) {
		lwsl_err("%s: lws_genaes_destroy dec failed\n", __func__);
		return -1;
	}

	if (lws_timingsafe_bcmp(gcm_pt, res, sizeof(gcm_pt))) {
		lwsl_err("%s: lws_genaes_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, sizeof(gcm_ct));
		return -1;
	}

	return 0;

bail:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}
//#endif

struct lws_genaes_hex_case {
	const char *name;
	enum enum_aes_modes mode;
	enum enum_aes_padding padding;
	const char *key_hex;
	const char *iv_hex;
	const char *in_hex;
	const char *out_hex;
};

struct lws_genaes_gcm_hex_case {
	const char *name;
	const char *key_hex;
	const char *iv_hex;
	const char *aad_hex;
	const char *pt_hex;
	const char *ct_hex;
	const char *tag_hex;
};

struct lws_genaes_padding_hex_case {
	const char *name;
	enum enum_aes_modes mode;
	const char *key_hex;
	const char *iv_hex;
	const char *pt_hex;
	const char *ct_hex;
};

static size_t
lws_genaes_hex_to_buf(const char *hex, uint8_t *buf, size_t len)
{
	int n;

	if (!hex || !*hex)
		return 0;

	n = lws_hex_to_byte_array(hex, buf, (int)len);
	if (n < 0)
		return 0;

	return (size_t)n;
}

static void
lws_genaes_reset_state(enum enum_aes_modes mode, const uint8_t *iv_src,
		       size_t iv_len, uint8_t *iv, uint8_t **ivp, uint8_t *sb,
		       uint8_t **sbp, size_t *off, size_t **offp)
{
	*ivp = NULL;
	*sbp = NULL;
	*offp = NULL;
	*off = 0;

	if (iv_src && iv_len)
		memcpy(iv, iv_src, iv_len);

	switch (mode) {
	case LWS_GAESM_ECB:
		break;
	case LWS_GAESM_CTR:
		*ivp = iv;
		memset(sb, 0, 16);
		*sbp = sb;
		*offp = off;
		break;
	case LWS_GAESM_CFB128:
	case LWS_GAESM_OFB:
		*ivp = iv;
		*offp = off;
		break;
	default:
		if (iv_src && iv_len)
			*ivp = iv;
		break;
	}
}

static int
lws_genaes_run_hex_case(const struct lws_genaes_hex_case *tc)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key[64], iv_src[32], iv[32], in[2048], out[2048], res[2048],
		res1[2048], sb[16];
	uint8_t *ivp, *sbp;
	size_t key_len, iv_len, in_len, out_len, off;
	size_t *offp;

	key_len = lws_genaes_hex_to_buf(tc->key_hex, key, sizeof(key));
	iv_len = lws_genaes_hex_to_buf(tc->iv_hex, iv_src, sizeof(iv_src));
	in_len = lws_genaes_hex_to_buf(tc->in_hex, in, sizeof(in));
	out_len = lws_genaes_hex_to_buf(tc->out_hex, out, sizeof(out));
	if (!key_len || in_len != out_len) {
		lwsl_err("%s: bad vector '%s'\n", __func__, tc->name);
		return -1;
	}

	e.buf = key;
	e.len = (uint32_t)key_len;

	lws_genaes_reset_state(tc->mode, iv_src, iv_len, iv, &ivp, sb, &sbp,
			       &off, &offp);
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, tc->mode, &e,
			      tc->padding, NULL)) {
		lwsl_err("%s: %s enc create failed\n", __func__, tc->name);
		return -1;
	}
	if (lws_genaes_crypt(&ctx, in, in_len, res, ivp, sbp, offp, 0)) {
		lwsl_err("%s: %s enc failed\n", __func__, tc->name);
		goto bail_enc;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: %s enc destroy failed\n", __func__, tc->name);
		return -1;
	}
	if (lws_timingsafe_bcmp(out, res, (unsigned int)out_len)) {
		lwsl_err("%s: %s enc mismatch\n", __func__, tc->name);
		lwsl_hexdump_notice(res, out_len);
		return -1;
	}

	lws_genaes_reset_state(tc->mode, iv_src, iv_len, iv, &ivp, sb, &sbp,
			       &off, &offp);
	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, tc->mode, &e,
			      tc->padding, NULL)) {
		lwsl_err("%s: %s dec create failed\n", __func__, tc->name);
		return -1;
	}
	if (lws_genaes_crypt(&ctx, out, out_len, res1, ivp, sbp, offp, 0)) {
		lwsl_err("%s: %s dec failed\n", __func__, tc->name);
		goto bail_dec;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: %s dec destroy failed\n", __func__, tc->name);
		return -1;
	}
	if (lws_timingsafe_bcmp(in, res1, (unsigned int)in_len)) {
		lwsl_err("%s: %s dec mismatch\n", __func__, tc->name);
		lwsl_hexdump_notice(res1, in_len);
		return -1;
	}

	return 0;

bail_dec:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;

bail_enc:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}

static int
lws_genaes_run_padding_hex_case(const struct lws_genaes_padding_hex_case *tc)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key[64], iv_src[32], iv[32], pt[2048], ct[2048], res[2048],
		res1[2048], sb[16];
	uint8_t *ivp, *sbp;
	size_t key_len, iv_len, pt_len, ct_len, off, enc_tail_len;
	size_t *offp;

	key_len = lws_genaes_hex_to_buf(tc->key_hex, key, sizeof(key));
	iv_len = lws_genaes_hex_to_buf(tc->iv_hex, iv_src, sizeof(iv_src));
	pt_len = lws_genaes_hex_to_buf(tc->pt_hex, pt, sizeof(pt));
	ct_len = lws_genaes_hex_to_buf(tc->ct_hex, ct, sizeof(ct));
	if (!key_len || !pt_len || !ct_len) {
		lwsl_err("%s: bad padding vector '%s'\n", __func__, tc->name);
		return -1;
	}
	if (tc->mode != LWS_GAESM_CBC) {
		lwsl_err("%s: unsupported padding mode %d in '%s'\n",
			 __func__, tc->mode, tc->name);
		return -1;
	}

	e.buf = key;
	e.len = (uint32_t)key_len;

	lws_genaes_reset_state(tc->mode, iv_src, iv_len, iv, &ivp, sb, &sbp,
			       &off, &offp);
	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, tc->mode, &e,
			      LWS_GAESP_WITH_PADDING, NULL)) {
		lwsl_err("%s: %s enc create failed\n", __func__, tc->name);
		return -1;
	}
	if (lws_genaes_crypt(&ctx, pt, pt_len, res, ivp, sbp, offp, 0)) {
		lwsl_err("%s: %s enc failed\n", __func__, tc->name);
		goto bail_enc;
	}
	if (ct_len < pt_len) {
		lwsl_err("%s: %s bad CBC padding lengths\n",
			 __func__, tc->name);
		goto bail_enc;
	}

	enc_tail_len = ct_len - pt_len;
	if (lws_genaes_destroy(&ctx, res + pt_len, enc_tail_len)) {
		lwsl_err("%s: %s enc destroy failed\n", __func__,
			 tc->name);
		return -1;
	}

	if (lws_timingsafe_bcmp(ct, res, (unsigned int)ct_len)) {
		lwsl_err("%s: %s enc mismatch\n", __func__, tc->name);
		lwsl_hexdump_notice(res, ct_len);
		return -1;
	}

	lws_genaes_reset_state(tc->mode, iv_src, iv_len, iv, &ivp, sb, &sbp,
			       &off, &offp);
	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, tc->mode, &e,
			      LWS_GAESP_WITH_PADDING, NULL)) {
		lwsl_err("%s: %s dec create failed\n", __func__, tc->name);
		return -1;
	}
	if (lws_genaes_crypt(&ctx, ct, ct_len, res1, ivp, sbp, offp, 0)) {
		lwsl_err("%s: %s dec failed\n", __func__, tc->name);
		goto bail_dec;
	}
	if (lws_genaes_destroy(&ctx, NULL, 0)) {
		lwsl_err("%s: %s dec destroy failed\n", __func__, tc->name);
		return -1;
	}
	if (lws_timingsafe_bcmp(pt, res1, (unsigned int)pt_len)) {
		lwsl_err("%s: %s dec mismatch\n", __func__, tc->name);
		lwsl_hexdump_notice(res1, pt_len);
		return -1;
	}

	return 0;

bail_dec:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;

bail_enc:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}

static int
lws_genaes_run_gcm_hex_case(const struct lws_genaes_gcm_hex_case *tc)
{
	struct lws_genaes_ctx ctx;
	struct lws_gencrypto_keyelem e;
	uint8_t key[64], iv[2048], aad[2048], pt[2048], ct[2048], tag[64],
		res[2048], out_tag[64];
	size_t key_len, iv_len, aad_len, pt_len, ct_len, tag_len, iv_off;

	key_len = lws_genaes_hex_to_buf(tc->key_hex, key, sizeof(key));
	iv_len = lws_genaes_hex_to_buf(tc->iv_hex, iv, sizeof(iv));
	aad_len = lws_genaes_hex_to_buf(tc->aad_hex, aad, sizeof(aad));
	pt_len = lws_genaes_hex_to_buf(tc->pt_hex, pt, sizeof(pt));
	ct_len = lws_genaes_hex_to_buf(tc->ct_hex, ct, sizeof(ct));
	tag_len = lws_genaes_hex_to_buf(tc->tag_hex, tag, sizeof(tag));
	if (!key_len || pt_len != ct_len || !tag_len) {
		lwsl_err("%s: bad GCM vector '%s'\n", __func__, tc->name);
		return -1;
	}

	e.buf = key;
	e.len = (uint32_t)key_len;

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_GCM, &e, 0, NULL)) {
		lwsl_err("%s: %s enc create failed\n", __func__, tc->name);
		return -1;
	}

	iv_off = iv_len;
	if (lws_genaes_crypt(&ctx, aad, aad_len, NULL, iv, tag, &iv_off,
			     (int)tag_len)) {
		lwsl_err("%s: %s enc aad failed\n", __func__, tc->name);
		goto bail_enc;
	}
	if (pt_len &&
	    lws_genaes_crypt(&ctx, pt, pt_len, res, NULL, NULL, NULL, 0)) {
		lwsl_err("%s: %s enc data failed\n", __func__, tc->name);
		goto bail_enc;
	}
	if (lws_genaes_destroy(&ctx, out_tag, tag_len)) {
		lwsl_err("%s: %s enc destroy failed\n", __func__, tc->name);
		return -1;
	}
	if ((pt_len && lws_timingsafe_bcmp(ct, res, (unsigned int)ct_len)) ||
	    lws_timingsafe_bcmp(tag, out_tag, (unsigned int)tag_len)) {
		lwsl_err("%s: %s enc mismatch\n", __func__, tc->name);
		return -1;
	}

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_GCM, &e, 0, NULL)) {
		lwsl_err("%s: %s dec create failed\n", __func__, tc->name);
		return -1;
	}

	iv_off = iv_len;
	if (lws_genaes_crypt(&ctx, aad, aad_len, NULL, iv, tag, &iv_off,
			     (int)tag_len)) {
		lwsl_err("%s: %s dec aad failed\n", __func__, tc->name);
		goto bail_dec;
	}
	if (ct_len &&
	    lws_genaes_crypt(&ctx, ct, ct_len, res, NULL, NULL, NULL, 0)) {
		lwsl_err("%s: %s dec data failed\n", __func__, tc->name);
		goto bail_dec;
	}
	if (lws_genaes_destroy(&ctx, out_tag, tag_len)) {
		lwsl_err("%s: %s dec destroy failed\n", __func__, tc->name);
		return -1;
	}
	if (pt_len && lws_timingsafe_bcmp(pt, res, (unsigned int)pt_len)) {
		lwsl_err("%s: %s dec mismatch\n", __func__, tc->name);
		return -1;
	}

	return 0;

bail_dec:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;

bail_enc:
	lws_genaes_destroy(&ctx, NULL, 0);

	return -1;
}

static int
test_genaes_branch_matrix(void)
{
	static const struct lws_genaes_hex_case basic_cases[] = {
		{ "cbc128-kat", LWS_GAESM_CBC, LWS_GAESP_NO_PADDING,
		  "00000000000000000000000000000000",
		  "00000000000000000000000000000000",
		  "f34481ec3cc627bacd5dc3fb08f273e6",
		  "0336763e966d92595a567cc9ce537f5e" },
		{ "cbc192-kat", LWS_GAESM_CBC, LWS_GAESP_NO_PADDING,
		  "000000000000000000000000000000000000000000000000",
		  "00000000000000000000000000000000",
		  "1b077a6af4b7f98229de786d7516b639",
		  "275cfc0413d8ccb70513c3859b1d0f72" },
		{ "ecb192-kat", LWS_GAESM_ECB, LWS_GAESP_NO_PADDING,
		  "61396c530cc1749a5bab6fbcf906fe672d0c4ab201af4554",
		  "",
		  "60bcdb9416bac08d7fd0d780353740a5",
		  "24f40c4eecd9c49825000fcb4972647a" },
		{ "ecb256-kat", LWS_GAESM_ECB, LWS_GAESP_NO_PADDING,
		  "cc22da787f375711c76302bef0979d8eddf842829c2b99ef3dd04e23e54cc24b",
		  "",
		  "ccc62c6b0a09a671d64456818db29a4d",
		  "df8634ca02b13a125b786e1dce90658b" },
		{ "ctr192-kat", LWS_GAESM_CTR, LWS_GAESP_NO_PADDING,
		  "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		  "6bc1bee22e409f96e93d7e117393172a",
		  "1abc932417521ca24f2b0459fe7e6e0b" },
		{ "ctr256-kat", LWS_GAESM_CTR, LWS_GAESP_NO_PADDING,
		  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		  "6bc1bee22e409f96e93d7e117393172a",
		  "601ec313775789a5b7a7f504bbf3d228" },
		{ "xts128-kat", LWS_GAESM_XTS, LWS_GAESP_NO_PADDING,
		  "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f",
		  "4faef7117cda59c66e4b92013e768ad5",
		  "ebabce95b14d3c8d6fb350390790311c",
		  "778ae8b43cb98d5a825081d5be471c63" },
	};
	static const struct lws_genaes_gcm_hex_case gcm_cases[] = {
		{ "gcm128-kat",
		  "af2904e234458af8ce0d616866c981fc",
		  "ef6381fdeb7877845f46edcd",
		  "41946f4a8304875ab3db0dec08d6c990",
		  "13836338abcfc03b89dd93f1dd691b01",
		  "b13b49e06b9e615a86d4c17ac10da212",
		  "ac8af4dc584da9a6" },
		{ "gcm192-empty",
		  "aa740abfadcda779220d3b406c5d7ec09a77fe9d94104539",
		  "ab2265b4c168955561f04315",
		  "",
		  "",
		  "",
		  "f149e2b5f0adaa9842ca5f45b768a8fc" },
	};
	static const struct lws_genaes_padding_hex_case padding_cases[] = {
		{ "cbc128-pkcs7",
		  LWS_GAESM_CBC,
		  "000102030405060708090a0b0c0d0e0f",
		  "000102030405060708090a0b0c0d0e0f",
		  "000102030405060708090a0b0c0d0e0f",
		  "c6a13b37878f5b826f4f8162a1c8d879b1a29273be2c4207a5ace393398cb6fb" },
	};
	unsigned int n;

	for (n = 0; n < LWS_ARRAY_SIZE(basic_cases); n++) {
#if defined(LWS_WITH_GNUTLS)
		if (basic_cases[n].mode == LWS_GAESM_CTR ||
		    basic_cases[n].mode == LWS_GAESM_XTS)
			continue;
#endif
		if (lws_genaes_run_hex_case(&basic_cases[n])) {
			lwsl_err("%s: basic_cases[%d] failed\n", __func__, n);
			return -1;
		}
	}

	for (n = 0; n < LWS_ARRAY_SIZE(gcm_cases); n++)
		if (lws_genaes_run_gcm_hex_case(&gcm_cases[n])) {
			lwsl_err("%s: gcm_cases[%d] failed\n", __func__, n);
			return -1;
		}

	for (n = 0; n < LWS_ARRAY_SIZE(padding_cases); n++)
		if (lws_genaes_run_padding_hex_case(&padding_cases[n])) {
			lwsl_err("%s: padding_cases[%d] failed\n", __func__, n);
			return -1;
		}

	return 0;
}

int
test_genaes(struct lws_context *context)
{
#if defined(LWS_WITH_SCHANNEL) || \
    (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CBC))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_cbc))
	if (test_genaes_cbc())
		goto bail;
#endif
#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CFB))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_cfb128))
	if (test_genaes_cfb128())
		goto bail;
#endif
#if defined(LWS_WITH_SCHANNEL) || \
    (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CFB))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_cfb8))
#if !defined(LWS_HAVE_MBEDTLS_V4)
	if (test_genaes_cfb8())
		goto bail;
#endif
#endif
#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_CTR))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_ctr))
	if (test_genaes_ctr())
		goto bail;
#endif
#if defined(LWS_WITH_SCHANNEL) || \
    (defined(LWS_WITH_MBEDTLS)) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_ecb))
	if (test_genaes_ecb())
		goto bail;
#endif
#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_OFB))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_ofb))
	if (test_genaes_ofb())
		goto bail;
#endif
#if (defined(LWS_WITH_MBEDTLS) && (!defined(MBEDTLS_CONFIG_H) || defined(MBEDTLS_CIPHER_MODE_XTS))) || \
    (!defined(LWS_WITH_MBEDTLS) && defined(LWS_HAVE_EVP_aes_128_xts))
#if !defined(LWS_HAVE_MBEDTLS_V4)
	if (test_genaes_xts())
		goto bail;
#endif
#endif

//#if !defined(LWS_WITH_SCHANNEL)
	if (test_genaes_gcm())
		goto bail;
	if (test_genaes_branch_matrix())
		goto bail;

	/* end */

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;

bail:
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;
}
