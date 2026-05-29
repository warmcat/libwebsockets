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
#if defined(LWS_WITH_OPENSSL)
#include "private-lib-tls-openssl.h"
#endif
#if defined(LWS_WITH_MBEDTLS)
#if defined(LWS_HAVE_MBEDTLS_PRIVATE_CHACHAPOLY_H)
#include <mbedtls/private/cipher.h>
#include <mbedtls/private/chachapoly.h>
#else
#include <mbedtls/chachapoly.h>
#endif
#endif

int
lws_genchacha_create(struct lws_genchacha_ctx *ctx, enum enum_aes_operation op,
		     struct lws_gencrypto_keyelem *el, void *engine)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->k = el;
	ctx->op = op;
	ctx->engine = engine;

	if (el->len != 32)
		return -1;

#if defined(LWS_WITH_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	ctx->ctx = EVP_CIPHER_CTX_new();
	if (!ctx->ctx)
		return -1;
#elif defined(LWS_WITH_MBEDTLS) && defined(MBEDTLS_CHACHAPOLY_C)
	mbedtls_chachapoly_init(&ctx->u.cp);
	if (mbedtls_chachapoly_setkey(&ctx->u.cp, ctx->k->buf) != 0) {
		mbedtls_chachapoly_free(&ctx->u.cp);
		return -1;
	}
#endif

	/* Always prep the native context as a fallback */
	lws_chacha_keysetup(&ctx->native_ctx, ctx->k->buf, 256);

	return 0;
}

int
lws_genchacha_destroy(struct lws_genchacha_ctx *ctx)
{
#if defined(LWS_WITH_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	if (ctx->ctx)
		EVP_CIPHER_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
#elif defined(LWS_WITH_MBEDTLS) && defined(MBEDTLS_CHACHAPOLY_C)
	mbedtls_chachapoly_free(&ctx->u.cp);
#endif
	return 0;
}

int
lws_genchacha_crypt(struct lws_genchacha_ctx *ctx,
		    const uint8_t *in, size_t len, uint8_t *out,
		    const uint8_t *nonce,
		    const uint8_t *aad, size_t aad_len,
		    uint8_t *tag, size_t tag_len)
{
#if defined(LWS_WITH_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	int outl;

	if (ctx->op == LWS_GAESO_ENC) {
		if (EVP_EncryptInit_ex(ctx->ctx, EVP_chacha20_poly1305(), NULL, ctx->k->buf, nonce) != 1) return -1;
		if (aad && aad_len) {
			if (EVP_EncryptUpdate(ctx->ctx, NULL, &outl, aad, (int)aad_len) != 1) return -1;
		}
		if (in && len) {
			if (EVP_EncryptUpdate(ctx->ctx, out, &outl, in, (int)len) != 1) return -1;
		}
		if (EVP_EncryptFinal_ex(ctx->ctx, out + (len ? len : 0), &outl) != 1) return -1;
		if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_AEAD_GET_TAG, (int)tag_len, tag) != 1) return -1;
		return 0;
	} else {
		if (EVP_DecryptInit_ex(ctx->ctx, EVP_chacha20_poly1305(), NULL, ctx->k->buf, nonce) != 1) return -1;
		if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, tag) != 1) return -1;
		if (aad && aad_len) {
			if (EVP_DecryptUpdate(ctx->ctx, NULL, &outl, aad, (int)aad_len) != 1) return -1;
		}
		if (in && len) {
			if (EVP_DecryptUpdate(ctx->ctx, out, &outl, in, (int)len) != 1) return -1;
		}
		if (EVP_DecryptFinal_ex(ctx->ctx, out + (len ? len : 0), &outl) <= 0) return -1;
		return 0;
	}
#elif defined(LWS_WITH_MBEDTLS) && defined(MBEDTLS_CHACHAPOLY_C)
	if (ctx->op == LWS_GAESO_ENC) {
		if (mbedtls_chachapoly_encrypt_and_tag(&ctx->u.cp, len, nonce, aad, aad_len, in, out, tag) != 0) return -1;
	} else {
		if (mbedtls_chachapoly_auth_decrypt(&ctx->u.cp, len, nonce, aad, aad_len, tag, in, out) != 0) return -1;
	}
	return 0;
#else
	/* Native C fallback using DJB/Moon primitives */
	uint8_t poly_key[32];
	size_t pad_aad = (aad_len + 15) & ~((size_t)15);
	size_t pad_len = (len + 15) & ~((size_t)15);
	size_t total = pad_aad + pad_len + 16;
	uint8_t *mac_buf, *p;
	uint8_t computed_tag[16];
	uint64_t al = (uint64_t)aad_len, ll = (uint64_t)len;

	memset(poly_key, 0, sizeof(poly_key));

	/* 1. Generate Poly1305 key by encrypting 32 zeros with counter 0 */
	lws_chacha_ivsetup_ietf(&ctx->native_ctx, nonce, 0);
	lws_chacha_encrypt_bytes(&ctx->native_ctx, poly_key, poly_key, sizeof(poly_key));

	mac_buf = lws_malloc(total, "poly1305_mac_buf");
	if (!mac_buf)
		return -1;

	memset(mac_buf, 0, total);
	p = mac_buf;
	if (aad && aad_len) {
		memcpy(p, aad, aad_len);
		p += pad_aad;
	}

	if (ctx->op == LWS_GAESO_DEC) {
		if (in && len)
			memcpy(p, in, len);
	} else {
		/* For encryption, stream to out first with counter 1 */
		lws_chacha_ivsetup_ietf(&ctx->native_ctx, nonce, 1);
		if (in && len)
			lws_chacha_encrypt_bytes(&ctx->native_ctx, in, out, (uint32_t)len);
		if (out && len)
			memcpy(p, out, len);
	}
	p += pad_len;

	p[0] = (uint8_t)al; p[1] = (uint8_t)(al >> 8);
	p[2] = (uint8_t)(al >> 16); p[3] = (uint8_t)(al >> 24);
	p[4] = (uint8_t)(al >> 32); p[5] = (uint8_t)(al >> 40);
	p[6] = (uint8_t)(al >> 48); p[7] = (uint8_t)(al >> 56);

	p[8] = (uint8_t)ll; p[9] = (uint8_t)(ll >> 8);
	p[10] = (uint8_t)(ll >> 16); p[11] = (uint8_t)(ll >> 24);
	p[12] = (uint8_t)(ll >> 32); p[13] = (uint8_t)(ll >> 40);
	p[14] = (uint8_t)(ll >> 48); p[15] = (uint8_t)(ll >> 56);

	lws_poly1305_auth(computed_tag, mac_buf, total, poly_key);
	lws_free(mac_buf);

	if (ctx->op == LWS_GAESO_DEC) {
		if (lws_timingsafe_bcmp(computed_tag, tag, 16)) {
			if (out && len)
				memset(out, 0, len);
			return -1;
		}
		lws_chacha_ivsetup_ietf(&ctx->native_ctx, nonce, 1);
		if (in && len)
			lws_chacha_encrypt_bytes(&ctx->native_ctx, in, out, (uint32_t)len);
	} else {
		if (tag)
			memcpy(tag, computed_tag, 16);
	}

	return 0;
#endif
}

int
lws_genchacha_stream(struct lws_genchacha_ctx *ctx,
		     const uint8_t *in, size_t len, uint8_t *out,
		     const uint8_t *nonce, size_t nonce_len)
{
#if defined(LWS_WITH_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	int outl;
	if (EVP_EncryptInit_ex(ctx->ctx, EVP_chacha20(), NULL, ctx->k->buf, nonce) != 1) return -1;
	if (EVP_EncryptUpdate(ctx->ctx, out, &outl, in, (int)len) != 1) return -1;
	if (EVP_EncryptFinal_ex(ctx->ctx, out + outl, &outl) != 1) return -1;
	return 0;
#else
	/* MbedTLS 2 doesn't have a public raw ChaCha20 API, so we and mbedTLS users both use the native fallback! */
	/* QUIC uses a 12-byte (96-bit) nonce and starts counter at 0. But QUIC header protection uses 16 bytes for the sample? */
	/* Wait, QUIC Header Protection generates a 5-byte mask. It samples 16 bytes of ciphertext to use as the nonce/counter! */
	/* No, RFC 9001 5.4.3: ChaCha20 uses the 16-byte sample as the counter+nonce! */
	/* The first 4 bytes are the counter (little endian), the next 12 bytes are the nonce. */

	if (nonce_len == 16) {
		uint32_t counter = (uint32_t)nonce[0] | ((uint32_t)nonce[1] << 8) | ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
		lws_chacha_ivsetup_ietf(&ctx->native_ctx, nonce + 4, counter);
	} else if (nonce_len == 12) {
		lws_chacha_ivsetup_ietf(&ctx->native_ctx, nonce, 0);
	} else {
		return -1;
	}

	lws_chacha_encrypt_bytes(&ctx->native_ctx, in, out, (uint32_t)len);
	return 0;
#endif
}
