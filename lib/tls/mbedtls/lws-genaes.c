/*
 * libwebsockets - generic AES api hiding the backend
 *
 * Copyright (C) 2017 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *  lws_genaes provides an abstraction api for AES in lws that works the
 *  same whether you are using openssl or mbedtls hash functions underneath.
 */
#include "core/private.h"
#include "../../jose/private.h"

static int operation_map[] = { MBEDTLS_AES_ENCRYPT, MBEDTLS_AES_DECRYPT };

LWS_VISIBLE int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_jwk_elements *el,
		  void *engine)
{
	int n;

	if (ctx->mode == LWS_GAESM_XTS)
		mbedtls_aes_xts_init(&ctx->xts_ctx);
	else
		mbedtls_aes_init(&ctx->ctx);

	ctx->mode = mode;
	ctx->k = el;
	ctx->op = operation_map[op];

	switch (op) {
	case LWS_GAESO_ENC:
		if (ctx->mode == LWS_GAESM_XTS)
#if defined(MBEDTLS_CIPHER_MODE_XTS)
			n = mbedtls_aes_xts_setkey_enc(&ctx->xts_ctx,
						       ctx->k->buf,
						       ctx->k->len * 8);
#else
			return -1;
#endif
		else
			n = mbedtls_aes_setkey_enc(&ctx->ctx, ctx->k->buf,
						   ctx->k->len * 8);
		break;
	case LWS_GAESO_DEC:
		switch (ctx->mode) {
		case LWS_GAESM_XTS:
#if defined(MBEDTLS_CIPHER_MODE_XTS)
			n = mbedtls_aes_xts_setkey_dec(&ctx->xts_ctx,
						       ctx->k->buf,
						       ctx->k->len * 8);
			break;
#else
			return -1;
#endif

		case LWS_GAESM_CFB128:
		case LWS_GAESM_CFB8:
		case LWS_GAESM_CTR:
		case LWS_GAESM_OFB:
			n = mbedtls_aes_setkey_enc(&ctx->ctx, ctx->k->buf,
						   ctx->k->len * 8);
			break;
		default:
			n = mbedtls_aes_setkey_dec(&ctx->ctx, ctx->k->buf,
						   ctx->k->len * 8);
			break;
		}
		break;
	}

	if (n)
		lwsl_notice("%s: setting key: -0x%x\n", __func__, -n);

	return n;
}

LWS_VISIBLE void
lws_genaes_destroy(struct lws_genaes_ctx *ctx)
{
	if (ctx->mode == LWS_GAESM_XTS)
#if defined(MBEDTLS_CIPHER_MODE_XTS)
		mbedtls_aes_xts_free(&ctx->xts_ctx);
#else
		return -1;
#endif
	else
		mbedtls_aes_free(&ctx->ctx);
}

LWS_VISIBLE int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len,
		 uint8_t *out, uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off)
{
	int n;
	uint8_t iv[16], sb[16];

	switch (ctx->mode) {
	case LWS_GAESM_CBC:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_cbc(&ctx->ctx, ctx->op, len, iv, in, out);
		break;

	case LWS_GAESM_CFB128:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_cfb128(&ctx->ctx, ctx->op, len,
					     nc_or_iv_off, iv, in, out);
		break;

	case LWS_GAESM_CFB8:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_cfb8(&ctx->ctx, ctx->op, len, iv, in, out);
		break;

	case LWS_GAESM_CTR:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		memcpy(sb, stream_block_16, 16);
		n = mbedtls_aes_crypt_ctr(&ctx->ctx, len, nc_or_iv_off,
					  iv, sb, in, out);
		memcpy(iv_or_nonce_ctr_or_data_unit_16, iv, 16);
		memcpy(stream_block_16, sb, 16);
		break;

	case LWS_GAESM_ECB:
		n = mbedtls_aes_crypt_ecb(&ctx->ctx, ctx->op, in, out);
		break;

	case LWS_GAESM_OFB:
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_ofb(&ctx->ctx, len, nc_or_iv_off, iv, in, out);
		break;

	case LWS_GAESM_XTS:
#if defined(MBEDTLS_CIPHER_MODE_XTS)
		memcpy(iv, iv_or_nonce_ctr_or_data_unit_16, 16);
		n = mbedtls_aes_crypt_xts(&ctx->xts_ctx, ctx->op, len, iv, in, out);
		break;
#else
		return -1;
#endif
	}

	if (n) {
		lwsl_notice("%s: enc: -0x%x, len %d\n", __func__, -n, (int)len);

		return -1;
	}

	return 0;
}
