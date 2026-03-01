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
	ctx->k = el;

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
	case LWS_GAESM_KW:
		switch (key.size) {
		case 16: alg = GNUTLS_CIPHER_AES_128_CBC; break;
		case 24: alg = GNUTLS_CIPHER_AES_192_CBC; break;
		case 32: alg = GNUTLS_CIPHER_AES_256_CBC; break;
		}
		break;
	default:
		lwsl_err("%s: unsupported mode %d\n", __func__, mode);
		return -2;
	}

	if (alg == GNUTLS_CIPHER_UNKNOWN)
		return 1;

	if (gnutls_cipher_init(&ctx->ctx, alg, &key, NULL) < 0)
		return 1;

	return 0;
}

static int
lws_genaes_rfc3394_wrap(int wrap, int cek_bits, const uint8_t *kek,
			int kek_bits, const uint8_t *in, uint8_t *out)
{
	int n, m, ret = -1, c64 = cek_bits / 64;
	gnutls_cipher_hd_t ctx;
	gnutls_cipher_algorithm_t alg;
	gnutls_datum_t key;
	uint8_t a[8], b[16];

	key.data = (uint8_t *)kek;
	key.size = (unsigned int)(kek_bits / 8);

	switch (kek_bits) {
	case 128: alg = GNUTLS_CIPHER_AES_128_CBC; break;
	case 192: alg = GNUTLS_CIPHER_AES_192_CBC; break;
	case 256: alg = GNUTLS_CIPHER_AES_256_CBC; break;
	default: return -1;
	}

	if (wrap) {
		memset(out, 0xa6, 8);
		memcpy(out + 8, in, 8 * (unsigned int)c64);
	} else {
		memcpy(a, in, 8);
		memcpy(out, in + 8, 8 * (unsigned int)c64);
	}

	if (gnutls_cipher_init(&ctx, alg, &key, NULL) < 0) {
		lwsl_err("%s: setkey failed\n", __func__);
		goto bail;
	}

	if (wrap) {
		for (n = 0; n <= 5; n++) {
			uint8_t *r = out + 8;
			for (m = 1; m <= c64; m++) {
				uint8_t zero_iv[16] = {0};
				memcpy(b, out, 8);
				memcpy(b + 8, r, 8);
				gnutls_cipher_set_iv(ctx, zero_iv, 16);
				if (gnutls_cipher_encrypt2(ctx, b, 16, b, 16) < 0)
					goto bail1;

				memcpy(out, b, 8);
				out[7] ^= (uint8_t)(c64 * n + m);
				memcpy(r, b + 8, 8);
				r += 8;
			}
		}
		ret = 0;
	} else {
		for (n = 5; n >= 0; n--) {
			uint8_t *r = out + (c64 - 1) * 8;
			for (m = c64; m >= 1; m--) {
				uint8_t zero_iv[16] = {0};
				memcpy(b, a, 8);
				b[7] ^= (uint8_t)(c64 * n + m);
				memcpy(b + 8, r, 8);
				gnutls_cipher_set_iv(ctx, zero_iv, 16);
				if (gnutls_cipher_decrypt2(ctx, b, 16, b, 16) < 0)
					goto bail1;

				memcpy(a, b, 8);
				memcpy(r, b + 8, 8);
				r -= 8;
			}
		}

		ret = 0;
		for (n = 0; n < 8; n++)
			if (a[n] != 0xa6)
				ret = -1;
	}

bail1:
	gnutls_cipher_deinit(ctx);
bail:
	if (ret)
		lwsl_notice("%s: failed\n", __func__);

	return ret;
}

int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len,
		 uint8_t *out, uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	int n;

	if (ctx->mode == LWS_GAESM_KW) {
		n = lws_genaes_rfc3394_wrap(ctx->op == LWS_GAESO_ENC,
				(ctx->op == LWS_GAESO_ENC ? (int)len * 8 :
						((int)len - 8) * 8), ctx->k->buf,
						(int)ctx->k->len * 8,
				in, out);
		return n;
	}

	if (iv_or_nonce_ctr_or_data_unit_16) {
		if (ctx->mode != LWS_GAESM_GCM || !ctx->gnutls_gcm_initialized) {
			size_t iv_len = (nc_or_iv_off && *nc_or_iv_off) ? *nc_or_iv_off : 16;
			gnutls_cipher_set_iv(ctx->ctx, iv_or_nonce_ctr_or_data_unit_16, iv_len);
			ctx->gnutls_gcm_initialized = 1;
		}
	}

	if (ctx->op == LWS_GAESO_ENC) {
		if (ctx->padding == LWS_GAESP_WITH_PADDING && ctx->mode == LWS_GAESM_CBC) {
			size_t in_pos = 0;
			size_t out_pos = 0;

			if (ctx->buf_len > 0) {
				size_t fill = 16 - (size_t)ctx->buf_len;
				if (len >= fill) {
					memcpy(ctx->buf + ctx->buf_len, in, fill);
					if (gnutls_cipher_encrypt2(ctx->ctx, ctx->buf, 16, out, 16) < 0)
						return 1;
					in_pos += fill;
					out_pos += 16;
					ctx->buf_len = 0;
				}
			}

			size_t left = len - in_pos;
			size_t blocks = (left / 16) * 16;
			if (blocks > 0) {
				if (gnutls_cipher_encrypt2(ctx->ctx, in + in_pos, blocks, out + out_pos, blocks) < 0)
					return 1;
				in_pos += blocks;
				out_pos += blocks;
			}

			left = len - in_pos;
			if (left > 0) {
				memcpy(ctx->buf + ctx->buf_len, in + in_pos, left);
				ctx->buf_len += (int)left;
			}
		} else {
			if (!out && ctx->mode == LWS_GAESM_GCM) {
				if (gnutls_cipher_add_auth(ctx->ctx, in, len) < 0)
					return 1;
			} else {
				if (gnutls_cipher_encrypt2(ctx->ctx, in, len, out, len) < 0)
					return 1;
			}
		}
	} else {
		if (!out && ctx->mode == LWS_GAESM_GCM) {
			if (gnutls_cipher_add_auth(ctx->ctx, in, len) < 0)
				return 1;
		} else {
			if (gnutls_cipher_decrypt2(ctx->ctx, in, len, out, len) < 0)
				return 1;
		}
	}

	return 0;
}

int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	if (ctx->ctx) {
		if (tag && tlen && ctx->mode == LWS_GAESM_GCM && ctx->op == LWS_GAESO_ENC)
			gnutls_cipher_tag(ctx->ctx, tag, tlen);

		if (ctx->op == LWS_GAESO_ENC && ctx->padding == LWS_GAESP_WITH_PADDING &&
		    ctx->mode == LWS_GAESM_CBC && tag) {
			uint8_t pad_val = (uint8_t)(16 - ctx->buf_len);
			memset(ctx->buf + ctx->buf_len, pad_val, (size_t)pad_val);
			if (gnutls_cipher_encrypt2(ctx->ctx, ctx->buf, 16, tag, 16) < 0)
				lwsl_err("%s: final padding block encrypt failed\n", __func__);
		}

		gnutls_cipher_deinit(ctx->ctx);
	}
	ctx->ctx = NULL;

	return 0;
}
