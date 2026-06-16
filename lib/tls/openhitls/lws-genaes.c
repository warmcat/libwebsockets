/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 *  lws_genaes provides an AES abstraction api in lws that works the
 *  same whether you are using openssl or OpenHiTLS cipher functions underneath.
 */
#include "private-lib-core.h"
#include "private.h"
#if defined(LWS_WITH_JOSE)
#include "private-lib-jose.h"
#endif

/*
 * Keep the externally visible lifecycle aligned with the OpenSSL backend:
 *
 * - create(): select the algorithm and allocate the backend context
 * - crypt(): lazily init the backend and feed update / AAD
 * - destroy(): perform any required final step and handle GCM tags
 */

static uint32_t
lws_openhitls_aes_feedback_bits(enum enum_aes_modes mode)
{
	switch (mode) {
	case LWS_GAESM_CFB8:
		return 8;
	case LWS_GAESM_CFB128:
		return 128;
	default:
		return 0;
	}
}

static uint32_t
lws_openhitls_aes_iv_len(enum enum_aes_modes mode)
{
	switch (mode) {
	case LWS_GAESM_ECB:
		return 0;
	case LWS_GAESM_KW:
		return 8;
	default:
		return 16;
	}
}

// Pass in tagLen during encryption, and pass in both the tag and tagLen during decryption.
static int
lws_openhitls_aes_init_gcm(struct lws_genaes_ctx *ctx, uint8_t *tag, int taglen)
{
	uint32_t t = (uint32_t)taglen;
	int32_t ret;

	ret = CRYPT_EAL_CipherCtrl(ctx->ctx, CRYPT_CTRL_SET_TAGLEN,
				   &t, sizeof(t));
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: SET_TAGLEN failed (%d)\n", __func__, (int)ret);
		return -1;
	}

	ctx->taglen = taglen;
	if (tag && taglen > 0)
		memcpy(ctx->tag, tag, (unsigned int)taglen);

	return 0;
}

static int
lws_openhitls_aes_init(struct lws_genaes_ctx *ctx, uint8_t *iv, uint32_t iv_len,
		       uint8_t *tag, int taglen)
{
	uint32_t fb_bits;
	int32_t ret;

	ret = CRYPT_EAL_CipherInit(ctx->ctx, ctx->k->buf,
				   (uint32_t)ctx->k->len, iv, iv_len,
				   ctx->op == LWS_GAESO_ENC);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CipherInit failed (%d)\n", __func__, (int)ret);
		return -1;
	}

	if (ctx->mode == LWS_GAESM_CBC || ctx->mode == LWS_GAESM_ECB) {
		ret = CRYPT_EAL_CipherSetPadding(ctx->ctx,
				ctx->padding == LWS_GAESP_WITH_PADDING ?
					CRYPT_PADDING_PKCS7 :
					CRYPT_PADDING_NONE);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CipherSetPadding failed (%d)\n",
				 __func__, (int)ret);
			return -1;
		}
	}

	fb_bits = lws_openhitls_aes_feedback_bits(ctx->mode);
	if (fb_bits) {
		ret = CRYPT_EAL_CipherCtrl(ctx->ctx, CRYPT_CTRL_SET_FEEDBACKSIZE,
					   &fb_bits, sizeof(fb_bits));
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: SET_FEEDBACKSIZE failed (%d)\n",
				 __func__, (int)ret);
			return -1;
		}
	}

	if (ctx->mode == LWS_GAESM_GCM &&
	    lws_openhitls_aes_init_gcm(ctx, tag, taglen))
		return -1;

	ctx->underway = 1;

	return 0;
}

static int
lws_openhitls_aes_destroy_gcm(struct lws_genaes_ctx *ctx, unsigned char *tag,
			      size_t tlen)
{
	uint32_t tagLen = (uint32_t)ctx->taglen;
	uint8_t calc_tag[16];
	uint8_t *tag_out;
	int32_t ret;

	if (tagLen > sizeof(calc_tag)) {
		lwsl_err("%s: invalid GCM tag length %u\n", __func__,
			 (unsigned int)tagLen);
		return -1;
	}

	if (ctx->op == LWS_GAESO_ENC) {
		if (!tag || tlen < tagLen) {
			lwsl_err("%s: invalid GCM tag output buffer\n", __func__);
			return -1;
		}
		tag_out = tag;
	} else
		tag_out = calc_tag;

	ret = CRYPT_EAL_CipherCtrl(ctx->ctx, CRYPT_CTRL_GET_TAG, tag_out,
		tagLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: GET_TAG failed (%d)\n", __func__, (int)ret);
		return 1;
	}

	if (ctx->op == LWS_GAESO_DEC &&
	    lws_timingsafe_bcmp(ctx->tag, tag_out, tagLen)) {
		lwsl_err("%s: GCM tag mismatch\n", __func__);
		return -1;
	}

	return 0;
}

static int
lws_openhitls_aes_crypt_gcm(struct lws_genaes_ctx *ctx,
			    const uint8_t *in, size_t len, uint8_t *out,
			    uint8_t *iv_or_nonce_ctr_or_data_unit_16,
			    uint8_t *stream_block_16, size_t *nc_or_iv_off,
			    int taglen)
{
	uint32_t outl;
	int32_t ret;

	if (!ctx->underway) {
		if (!nc_or_iv_off) {
			lwsl_err("%s: missing GCM iv length\n", __func__);
			return -1;
		}

		if (taglen < 0 || (unsigned int)taglen > sizeof(ctx->tag)) {
			lwsl_err("%s: invalid GCM tag length %d\n",
				 __func__, taglen);
			return -1;
		}

		if (lws_openhitls_aes_init(ctx,
				iv_or_nonce_ctr_or_data_unit_16,
				(uint32_t)*nc_or_iv_off,
				stream_block_16, taglen))
			return -1;
	}

	if (!out) {
		if (!len)
			return 0;
		// Only when out is empty will aad be set, and this operation will only occur once in the main process.
		ret = CRYPT_EAL_CipherCtrl(ctx->ctx, CRYPT_CTRL_SET_AAD,
					   (void *)in, (uint32_t)len);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: SET_AAD failed (%d)\n",
				 __func__, (int)ret);
			return -1;
		}

		return 0;
	}

	outl = (uint32_t)len;
	ret = CRYPT_EAL_CipherUpdate(ctx->ctx, in, (uint32_t)len, out, &outl);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: GCM update failed (%d)\n", __func__,
			 (int)ret);
		return -1;
	}

	return 0;
}

int lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  enum enum_aes_padding padding, void *engine)
{
	CRYPT_CIPHER_AlgId cipherId;

	ctx->mode = mode;
	ctx->k = el;
	ctx->op = op;
	ctx->padding = padding;
	ctx->underway = 0;
	ctx->taglen = 0;
	memset(ctx->tag, 0, sizeof(ctx->tag));

	/* engine parameter is not used for OpenHiTLS */
	(void)engine;

	cipherId = lws_genaes_mode_to_hitls_cipher_id(mode, el->len);
	if (cipherId == CRYPT_CIPHER_MAX) {
		lwsl_err("%s: unsupported AES mode %d or key size %d bits\n",
			 __func__, mode, (int)el->len * 8);
		return -1;
	}

	ctx->ctx = CRYPT_EAL_CipherNewCtx(cipherId);
	if (!ctx->ctx) {
		lwsl_err("%s: CRYPT_EAL_CipherNewCtx failed\n", __func__);
		return -1;
	}

	return 0;
}

int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	uint8_t buf[256];
	uint32_t outl = sizeof(buf);
	int n = 0;
	int32_t ret;

	if (!ctx->ctx)
		return 0;
	if (!ctx->underway) {
		goto cleanup;
	}

	if (ctx->mode == LWS_GAESM_GCM) {
		n = lws_openhitls_aes_destroy_gcm(ctx, tag, tlen);
		goto cleanup;
	}
	ret = CRYPT_EAL_CipherFinal(ctx->ctx, buf, &outl);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CipherFinal failed (%d)\n", __func__,
				(int)ret);
		n = -1;
		goto cleanup;
	}

	if (ctx->mode == LWS_GAESM_CBC && ctx->op == LWS_GAESO_ENC &&
		outl && tag) {
		if (tlen < outl) {
			lwsl_err("%s: CBC final buffer too small\n",
					__func__);
			n = -1;
			goto cleanup;
		}
		memcpy(tag, buf, outl);
	}


cleanup:
	ctx->k = NULL;
	ctx->underway = 0;
	CRYPT_EAL_CipherFreeCtx(ctx->ctx);
	ctx->ctx = NULL;

	return n;
}

int
lws_genaes_crypt(struct lws_genaes_ctx *ctx,
		 const uint8_t *in, size_t len, uint8_t *out,
		 uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	uint32_t outl;
	uint32_t iv_len;
	int32_t ret;

	if (!ctx->ctx)
		return -1;

	if (ctx->mode == LWS_GAESM_GCM)
		return lws_openhitls_aes_crypt_gcm(ctx, in, len, out,
				iv_or_nonce_ctr_or_data_unit_16,
				stream_block_16, nc_or_iv_off, taglen);

	if (!ctx->underway) {
		iv_len = lws_openhitls_aes_iv_len(ctx->mode);
		if (!iv_or_nonce_ctr_or_data_unit_16)
			iv_len = 0;

		if (lws_openhitls_aes_init(ctx,
				iv_or_nonce_ctr_or_data_unit_16, iv_len,
				NULL, 0))
			return -1;
	}

	if (ctx->mode == LWS_GAESM_KW) {
		/*
		 * RFC3394 AES key wrap grows ciphertext by one 64-bit block on
		 * encryption and removes it on decryption.
		 */
		if (ctx->op == LWS_GAESO_ENC)
			outl = (uint32_t)len + 8;
		else {
			if (len < 8) {
				lwsl_err("%s: invalid AES-KW input length %zu\n",
					 __func__, len);
				return -1;
			}
			outl = (uint32_t)len - 8;
		}
	} else
		outl = (uint32_t)len;

	ret = CRYPT_EAL_CipherUpdate(ctx->ctx, in, (uint32_t)len, out, &outl);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: update failed (%d)\n", __func__, (int)ret);
		return -1;
	}

	return 0;
}
