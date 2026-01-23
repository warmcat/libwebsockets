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
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include <string.h>

int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  enum enum_aes_padding padding, void *engine)
{
	gnutls_cipher_algorithm_t alg = GNUTLS_CIPHER_UNKNOWN;
	gnutls_datum_t key;

	memset(ctx, 0, sizeof(*ctx));
	ctx->op = op;
	ctx->mode = mode;
	ctx->padding = padding;

	key.data = el[LWS_GENCRYPTO_AES_KEYEL_K].buf;
	key.size = el[LWS_GENCRYPTO_AES_KEYEL_K].len;

	switch (mode) {
	case LWS_GAESM_CBC:
		switch (key.size) {
		case 16: alg = GNUTLS_CIPHER_AES_128_CBC; break;
		case 24: alg = GNUTLS_CIPHER_AES_192_CBC; break;
		case 32: alg = GNUTLS_CIPHER_AES_256_CBC; break;
		}
		break;
	case LWS_GAESM_CFB8:
		if (key.size == 16) alg = GNUTLS_CIPHER_AES_128_CFB8;
		break;
	case LWS_GAESM_GCM:
		switch (key.size) {
		case 16: alg = GNUTLS_CIPHER_AES_128_GCM; break;
		case 24: alg = GNUTLS_CIPHER_AES_192_GCM; break;
		case 32: alg = GNUTLS_CIPHER_AES_256_GCM; break;
		}
		break;
	default:
		lwsl_err("%s: unsupported mode %d\n", __func__, mode);
		return 1;
	}

	if (alg == GNUTLS_CIPHER_UNKNOWN)
		return 1;

	if (gnutls_cipher_init(&ctx->ctx, alg, &key, NULL) < 0)
		return 1;

	return 0;
}

int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len,
		 uint8_t *out, uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	if (iv_or_nonce_ctr_or_data_unit_16) {
		gnutls_cipher_set_iv(ctx->ctx, iv_or_nonce_ctr_or_data_unit_16, 16);
	}

	if (ctx->op == LWS_GAESO_ENC) {
		if (gnutls_cipher_encrypt2(ctx->ctx, in, len, out, len) < 0)
			return 1;
		if (ctx->mode == LWS_GAESM_GCM && stream_block_16) {
			gnutls_cipher_tag(ctx->ctx, stream_block_16, (size_t)taglen);
		}
	} else {
		if (gnutls_cipher_decrypt2(ctx->ctx, in, len, out, len) < 0)
			return 1;
	}

	return 0;
}

int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	if (ctx->ctx) {
		if (tag && tlen && ctx->mode == LWS_GAESM_GCM && ctx->op == LWS_GAESO_ENC)
			gnutls_cipher_tag(ctx->ctx, tag, tlen);
		gnutls_cipher_deinit(ctx->ctx);
	}
	ctx->ctx = NULL;

	return 0;
}
