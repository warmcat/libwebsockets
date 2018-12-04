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
 *  lws_genaes provides an AES abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls hash functions underneath.
 */
#include "core/private.h"
#include "../../jose/private.h"

/*
 * Care: many openssl apis return 1 for success.  These are translated to the
 * lws convention of 0 for success.
 */

LWS_VISIBLE int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_jwk_elements *el,
		  void *engine)
{
	int n;

	ctx->ctx = EVP_CIPHER_CTX_new();
	if (!ctx->ctx)
		return -1;

	ctx->mode = mode;
	ctx->k = el;
	ctx->engine = engine;
	ctx->init = 0;
	ctx->op = op;

	switch (ctx->k->len) {
	case 128 / 8:
		switch (mode) {
		case LWS_GAESM_CBC:
			ctx->cipher = EVP_aes_128_cbc();
			break;
		case LWS_GAESM_CFB128:
			ctx->cipher = EVP_aes_128_cfb128();
			break;
		case LWS_GAESM_CFB8:
			ctx->cipher = EVP_aes_128_cfb8();
			break;
		case LWS_GAESM_CTR:
			ctx->cipher = EVP_aes_128_ctr();
			break;
		case LWS_GAESM_ECB:
			ctx->cipher = EVP_aes_128_ecb();
			break;
		case LWS_GAESM_OFB:
			ctx->cipher = EVP_aes_128_ofb();
			break;
		case LWS_GAESM_XTS:
			lwsl_err("%s: AES XTS requires double-length key\n",
				 __func__);
			break;
		default:
			return -1;
		}
		break;

	case 192 / 8:
		switch (mode) {
		case LWS_GAESM_CBC:
			ctx->cipher = EVP_aes_192_cbc();
			break;
		case LWS_GAESM_CFB128:
			ctx->cipher = EVP_aes_192_cfb128();
			break;
		case LWS_GAESM_CFB8:
			ctx->cipher = EVP_aes_192_cfb8();
			break;
		case LWS_GAESM_CTR:
			ctx->cipher = EVP_aes_192_ctr();
			break;
		case LWS_GAESM_ECB:
			ctx->cipher = EVP_aes_192_ecb();
			break;
		case LWS_GAESM_OFB:
			ctx->cipher = EVP_aes_192_ofb();
			break;
		case LWS_GAESM_XTS:
			lwsl_err("%s: AES XTS 192 invalid\n", __func__);
			return -1;

		default:
			return -1;
		}
		break;

	case 256 / 8:
		switch (mode) {
		case LWS_GAESM_CBC:
			ctx->cipher = EVP_aes_256_cbc();
			break;
		case LWS_GAESM_CFB128:
			ctx->cipher = EVP_aes_256_cfb128();
			break;
		case LWS_GAESM_CFB8:
			ctx->cipher = EVP_aes_256_cfb8();
			break;
		case LWS_GAESM_CTR:
			ctx->cipher = EVP_aes_256_ctr();
			break;
		case LWS_GAESM_ECB:
			ctx->cipher = EVP_aes_256_ecb();
			break;
		case LWS_GAESM_OFB:
			ctx->cipher = EVP_aes_256_ofb();
			break;
		case LWS_GAESM_XTS:
			ctx->cipher = EVP_aes_128_xts();
			break;
		default:
			return -1;
		}
		break;

	case 512 / 8:
		switch (mode) {
		case LWS_GAESM_XTS:
			ctx->cipher = EVP_aes_256_xts();
			break;
		default:
			return -1;
		}
	break;

	default:
		lwsl_err("%s: unsupported AES size %d bits\n", __func__,
			 ctx->k->len * 8);
		return -1;
	}

	switch (ctx->op) {
	case LWS_GAESO_ENC:
		n = EVP_EncryptInit_ex(ctx->ctx, ctx->cipher, ctx->engine,
				       NULL, NULL);
		break;
	case LWS_GAESO_DEC:
		n = EVP_DecryptInit_ex(ctx->ctx, ctx->cipher, ctx->engine,
				       NULL, NULL);
		break;
	}
	if (!n) {
		lwsl_err("%s: cipher init failed (cipher %p)\n", __func__,
			 ctx->cipher);

		return -1;
	}

	return 0;
}

LWS_VISIBLE void
lws_genaes_destroy(struct lws_genaes_ctx *ctx)
{
	int outl;
	uint8_t buf[32];

	if (!ctx->ctx)
		return;

	if (ctx->init) {
		switch (ctx->op) {
		case LWS_GAESO_ENC:
			EVP_EncryptFinal_ex(ctx->ctx, buf, &outl);
			break;
		case LWS_GAESO_DEC:
			EVP_DecryptFinal_ex(ctx->ctx, buf, &outl);
			break;
		}
		if (outl)
			lwsl_debug("%s: final len %d\n", __func__, outl);
	}

	ctx->k = NULL;
	EVP_CIPHER_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
}

LWS_VISIBLE int
lws_genaes_crypt(struct lws_genaes_ctx *ctx,
		 const uint8_t *in, size_t len, uint8_t *out,
		 uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off)
{
	int n, outl;

	if (!ctx->init) {
		switch (ctx->op) {
		case LWS_GAESO_ENC:
			EVP_CIPHER_CTX_set_key_length(ctx->ctx, ctx->k->len);
			n = EVP_EncryptInit_ex(ctx->ctx, NULL, NULL,
					       ctx->k->buf,
					       iv_or_nonce_ctr_or_data_unit_16);
			break;
		case LWS_GAESO_DEC:
			EVP_CIPHER_CTX_set_key_length(ctx->ctx, ctx->k->len);
			n = EVP_DecryptInit_ex(ctx->ctx, NULL, NULL,
					       ctx->k->buf,
					       iv_or_nonce_ctr_or_data_unit_16);
			break;
		}

		if (!n) {
			lwsl_err("%s: init failed (cipher %p)\n",
				 __func__, ctx->cipher);

			return -1;
		}
		ctx->init = 1;
	}

	switch (ctx->op) {
	case LWS_GAESO_ENC:
		n = EVP_EncryptUpdate(ctx->ctx, out, &outl, in, len);
		break;
	case LWS_GAESO_DEC:
		n = EVP_DecryptUpdate(ctx->ctx, out, &outl, in, len);
		break;
	}

	// lwsl_notice("discarding outl %d\n", (int)outl);

	if (!n) {
		lwsl_notice("%s: update failed\n", __func__);

		return -1;
	}

	return 0;
}
