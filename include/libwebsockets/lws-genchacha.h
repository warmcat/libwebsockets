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

#ifndef __LWS_GENCHACHA_H__
#define __LWS_GENCHACHA_H__

#include <stdint.h>

/*! \defgroup generic chacha
 * ## Generic ChaCha20 and Poly1305 related functions
 *
 * Lws provides generic ChaCha20 and Poly1305 functions.
 */
///@{

#define LWS_CHACHA_MINKEYLEN 	16
#define LWS_CHACHA_NONCELEN		8
#define LWS_CHACHA_CTRLEN		8
#define LWS_CHACHA_STATELEN		(LWS_CHACHA_NONCELEN+LWS_CHACHA_CTRLEN)
#define LWS_CHACHA_BLOCKLEN		64

struct lws_chacha_ctx {
	uint32_t input[16];
};

/**
 * lws_chacha_keysetup() - Setup ChaCha20 context with key
 *
 * \param x: your struct lws_chacha_ctx
 * \param k: key bytes
 * \param kbits: key size in bits (usually 256)
 */
LWS_VISIBLE LWS_EXTERN void
lws_chacha_keysetup(struct lws_chacha_ctx *x, const uint8_t *k, uint32_t kbits);

/**
 * lws_chacha_ivsetup() - Setup ChaCha20 context with IV and counter (DJB 64-bit style)
 *
 * \param x: your struct lws_chacha_ctx
 * \param iv: 8-byte initialization vector
 * \param counter: optional 8-byte counter (can be NULL)
 */
LWS_VISIBLE LWS_EXTERN void
lws_chacha_ivsetup(struct lws_chacha_ctx *x, const uint8_t *iv, const uint8_t *counter);

/**
 * lws_chacha_ivsetup_ietf() - Setup ChaCha20 context with IV and counter (IETF 96-bit style)
 *
 * \param x: your struct lws_chacha_ctx
 * \param nonce: 12-byte nonce
 * \param counter: 32-bit counter
 */
LWS_VISIBLE LWS_EXTERN void
lws_chacha_ivsetup_ietf(struct lws_chacha_ctx *x, const uint8_t *nonce, uint32_t counter);

/**
 * lws_chacha_encrypt_bytes() - Encrypt/Decrypt bytes using ChaCha20
 *
 * \param x: your struct lws_chacha_ctx
 * \param m: input data
 * \param c: output data
 * \param bytes: number of bytes to process
 */
LWS_VISIBLE LWS_EXTERN void
lws_chacha_encrypt_bytes(struct lws_chacha_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes);


#define LWS_POLY1305_TAGLEN 16
#define LWS_POLY1305_KEYLEN 32

/**
 * lws_poly1305_auth() - Poly1305 one-shot authenticator
 *
 * \param out: 16-byte output tag
 * \param m: input message
 * \param inlen: length of input message
 * \param key: 32-byte key
 */
LWS_VISIBLE LWS_EXTERN void
lws_poly1305_auth(uint8_t out[LWS_POLY1305_TAGLEN], const uint8_t *m, size_t inlen, const uint8_t key[LWS_POLY1305_KEYLEN]);

struct lws_genchacha_ctx {
#if defined(LWS_WITH_MBEDTLS)
	union {
		mbedtls_chachapoly_context cp;
		mbedtls_cipher_context_t cipher;
	} u;
#elif defined(LWS_WITH_OPENSSL)
	EVP_CIPHER_CTX *ctx;
#endif
	/* fallback native ctx */
	struct lws_chacha_ctx native_ctx;
	struct lws_gencrypto_keyelem *k;
	enum enum_aes_operation op;
	void *engine;
};

LWS_VISIBLE LWS_EXTERN int
lws_genchacha_create(struct lws_genchacha_ctx *ctx, enum enum_aes_operation op,
		     struct lws_gencrypto_keyelem *el, void *engine);

LWS_VISIBLE LWS_EXTERN int
lws_genchacha_destroy(struct lws_genchacha_ctx *ctx);

/**
 * lws_genchacha_crypt() - One-shot AEAD encrypt/decrypt
 *
 * \param ctx: your struct lws_genchacha_ctx
 * \param in: input plaintext or ciphertext
 * \param len: length of input
 * \param out: output plaintext or ciphertext
 * \param nonce: 12-byte nonce
 * \param aad: additional authenticated data
 * \param aad_len: length of aad
 * \param tag: tag buffer (written on enc, checked on dec)
 * \param tag_len: usually 16
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genchacha_crypt(struct lws_genchacha_ctx *ctx,
		    const uint8_t *in, size_t len, uint8_t *out,
		    const uint8_t *nonce,
		    const uint8_t *aad, size_t aad_len,
		    uint8_t *tag, size_t tag_len);

/**
 * lws_genchacha_stream() - Raw ChaCha20 keystream
 *
 * \param ctx: your struct lws_genchacha_ctx
 * \param in: input plaintext or ciphertext
 * \param len: length of input
 * \param out: output plaintext or ciphertext
 * \param nonce: 12-byte or 16-byte nonce/counter
 * \param nonce_len: length of nonce
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genchacha_stream(struct lws_genchacha_ctx *ctx,
		     const uint8_t *in, size_t len, uint8_t *out,
		     const uint8_t *nonce, size_t nonce_len);

///@}

#endif
