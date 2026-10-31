/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

/*! \defgroup generic AES
 * ## Generic AES related functions
 *
 * Lws provides generic AES functions that abstract the ones
 * provided by whatever tls library you are linking against.
 *
 * It lets you use the same code if you build against mbedtls or OpenSSL
 * for example.
 */
///@{

#if defined(LWS_WITH_MBEDTLS)
#if !defined(LWS_HAVE_MBEDTLS_V4)
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#else
#include <psa/crypto.h>
#endif
#endif
#if defined(LWS_WITH_OPENHITLS)
#include <crypt_eal_cipher.h>
#endif

enum enum_aes_modes {
	LWS_GAESM_CBC,
	LWS_GAESM_CFB128,
	LWS_GAESM_CFB8,
	LWS_GAESM_CTR,
	LWS_GAESM_ECB,
	LWS_GAESM_OFB,
	LWS_GAESM_XTS,		/* care... requires double-length key */
	LWS_GAESM_GCM,
	LWS_GAESM_KW,
};

enum enum_aes_operation {
	LWS_GAESO_ENC,
	LWS_GAESO_DEC
};

enum enum_aes_padding {
	LWS_GAESP_NO_PADDING,
	LWS_GAESP_WITH_PADDING
};

/* include/libwebsockets/lws-jwk.h must be included before this */

#define LWS_AES_BLOCKSIZE 128
#define LWS_AES_CBC_BLOCKLEN 16

struct lws_genaes_ctx {
#if defined(LWS_WITH_MBEDTLS)
#if !defined(LWS_HAVE_MBEDTLS_V4)
	union {
		mbedtls_aes_context ctx;
#if defined(MBEDTLS_CIPHER_MODE_XTS)
		mbedtls_aes_xts_context ctx_xts;
#endif
		mbedtls_gcm_context ctx_gcm;
	} u;
#else
	psa_key_id_t key_id;
	psa_algorithm_t alg;
	psa_cipher_operation_t cipher_ctx;
	psa_aead_operation_t aead_ctx;
#endif
#elif defined(LWS_WITH_SCHANNEL)
	struct {
		void *hAlg;
		void *hKey;
		void *pbMacContext;
		size_t cbMacContext;
		void *pbNonce;
		size_t cbNonce;
		void *pbTag;
		size_t cbTag;
		void *pbAuthData;
		size_t cbAuthData;
		unsigned char iv[LWS_AES_CBC_BLOCKLEN]; /* Internal IV buffer for chaining */
	} u;
#elif defined(LWS_WITH_GNUTLS)
	gnutls_cipher_hd_t ctx;
	int gnutls_gcm_initialized;
#elif defined(LWS_WITH_BEARSSL)
	union {
		br_aes_ct_cbcenc_keys cbcenc;
		br_aes_ct_cbcdec_keys cbcdec;
		br_aes_ct_ctr_keys ctr;		/* GCM's underlying CTR */
		br_aes_ct_ctrcbc_keys ctrcbc;	/* CTR mode */
	} u;
	br_gcm_context gcm;
#elif defined(LWS_WITH_OPENHITLS)
	CRYPT_EAL_CipherCtx *ctx;
#else
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
	ENGINE *engine;
	char init;
#endif
	unsigned char tag[16];	/* GCM: tag; CBC: iv, or chaining value */
	struct lws_gencrypto_keyelem *k;
	enum enum_aes_operation op;
	enum enum_aes_modes mode;
	enum enum_aes_padding padding;
	int taglen;
	char underway;

	/* CBC state common to all backends, see lws_genaes_final() */
	size_t cbc_total;	/* bytes output so far */
	unsigned char buf[16];	/* enc: partial block; dec: last block */
	int buf_len;		/* bytes in buf */
	char cbc_iv_set;	/* the iv was taken on the first crypt */
	char cbc_final;		/* lws_genaes_final() has been done */
};

/** lws_genaes_create() - Create genaes AES context
 *
 * \param ctx: your struct lws_genaes_ctx
 * \param op: LWS_GAESO_ENC or LWS_GAESO_DEC
 * \param mode: one of LWS_GAESM_
 * \param el: struct prepared with key element data
 * \param padding: LWS_GAESP_NO_PADDING or LWS_GAESP_WITH_PADDING
 * \param engine: if openssl engine used, pass the pointer here
 *
 * Creates an AES context with a key associated with it, formed from
 * the key elements in \p el.
 *
 * \p padding only has a meaning for LWS_GAESM_CBC, where
 * LWS_GAESP_WITH_PADDING means PKCS#7: encrypt adds it, and decrypt checks it
 * and reports the plaintext length without it (see lws_genaes_final()).  It
 * is refused for LWS_GAESM_ECB, and ignored by the stream and AEAD modes.
 *
 * Returns 0 for OK or nonzero for error.
 *
 * This and related APIs operate identically with OpenSSL or mbedTLS backends.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  enum enum_aes_padding padding, void *engine);

/** lws_genaes_destroy() - Destroy genaes AES context
 *
 * \param ctx: your struct lws_genaes_ctx
 * \param tag: NULL, or, GCM-only: buffer to receive tag
 * \param tlen: 0, or, GCM-only: length of tag buffer
 *
 * Destroys any allocations related to \p ctx.
 *
 * For GCM only, up to tlen bytes of tag buffer will be set on exit.
 *
 * For compatibility, a CBC encrypt with LWS_GAESP_WITH_PADDING that was not
 * finished with lws_genaes_final() has its final 16-byte block written to
 * \p tag here, if \p tlen is at least 16.  New code should use
 * lws_genaes_final(), which also reports the length.
 *
 * This and related APIs operate identically with OpenSSL or mbedTLS backends.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen);

/** lws_genaes_crypt() - Encrypt or decrypt
 *
 * \param ctx: your struct lws_genaes_ctx
 * \param in: input plaintext or ciphertext
 * \param len: length of input (and of output, except for CBC, see below)
 * \param out: output plaintext or ciphertext
 * \param iv_or_nonce_ctr_or_data_unit_16: NULL, iv, nonce_ctr16, or data_unit16
 * \param stream_block_16: NULL, or 16-byte stream block (CTR), or tag (GCM)
 * \param nc_or_iv_off: NULL or pointer to nc, or iv_off
 * \param taglen: length of tag
 *
 * Encrypts or decrypts using the AES mode set when the ctx was created.
 * The last three arguments have different meanings depending on the mode:
 *
 * 			      KW   CBC  CFB128 CFB8 CTR    ECB  OFB    XTS
 * iv_or_nonce_ct.._unit_16 : iv   iv   iv     iv   nonce  NULL iv     dataunt
 * stream_block_16	    : NULL NULL NULL   NULL stream NULL NULL   NULL
 * nc_or_iv_off		    : NULL olen iv_off NULL nc_off NULL iv_off NULL
 *
 * For CBC:
 *
 * iv_or_nonce_ctr_or_data_unit_16 : the iv, required on the first call;
 *				   :   later calls continue the chain held in
 *				   :   the ctx and ignore it
 * nc_or_iv_off			   : NULL, or set to the number of bytes
 *				   :   this call wrote to out
 *
 * A CBC operation may be split over any number of calls.  Without padding,
 * and when decrypting with padding, each call's len must be a multiple of 16
 * and that many bytes are written to out.  When encrypting with padding, len
 * may be anything: only whole blocks are written, so out needs room for
 * len + 15 bytes, and the rest is kept in the ctx until the next call or
 * lws_genaes_final(), which pads and writes the last block.  out may be the
 * same buffer as in, except for an encrypt with padding that follows an
 * earlier call that left a partial block in the ctx.
 *
 * Decrypting with padding writes all of the plaintext including the
 * padding bytes: lws_genaes_final() checks the padding and reports the
 * length of the plaintext without it.
 *
 * For CTR, stream_block_16 and nc_or_iv_off may each be NULL.  Then the call
 * starts on a fresh keystream block from the counter in
 * iv_or_nonce_ctr_or_data_unit_16, and the rest of its last keystream block
 * is dropped.  A nonzero *nc_or_iv_off is an offset into stream_block_16, and
 * is refused without it.  One crypt call per CTR ctx is the use that behaves
 * the same on every backend: some carry the keystream on in the ctx between
 * calls, others only through these arguments.
 *
 * For GCM:
 *
 * iv_or_nonce_ctr_or_data_unit_16 : iv
 * stream_block_16		   : decrypt: the tag the peer sent, required
 *				   :   on the first call (taglen bytes);
 *				   :   encrypt: unused, may be NULL, the tag
 *				   :   comes out of lws_genaes_destroy()
 * nc_or_iv_off			   : set pointed-to size_t to iv length
 * in				   : first call: additional data, subsequently
 *				   :   input data
 * len				   : first call: add data length, subsequently
 *				   :   input / output length
 * out				   : first call: NULL, subsequently output data
 *
 * The first GCM call is always the additional data pass, even if there is
 * no additional data (pass in NULL and len 0 then): the payload only goes
 * in from the second call on.  Pass out as NULL on the first call, some
 * backends use that to tell the AAD pass apart from a payload one.
 *
 * The length of the optional arg is always 16 if used, regardless of the mode.
 *
 * Returns 0 for OK or nonzero for error.
 *
 * This and related APIs operate identically with OpenSSL or mbedTLS backends.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len,
		 uint8_t *out,
		 uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16,
		 size_t *nc_or_iv_off, int taglen);

/** lws_genaes_final() - finish a CBC operation
 *
 * \param ctx: your struct lws_genaes_ctx, created for LWS_GAESM_CBC
 * \param out: encrypt with padding: where the final block is written, ie,
 *	       just after the output of the lws_genaes_crypt() calls.
 *	       Otherwise unused, and may be NULL.
 * \param out_max: the space at \p out
 * \param total_len: NULL, or set to the total length of the result: the
 *		     whole ciphertext including the final block when
 *		     encrypting, or the plaintext without its padding when
 *		     decrypting
 *
 * Call it once after the last lws_genaes_crypt() and before
 * lws_genaes_destroy().
 *
 * Encrypting with LWS_GAESP_WITH_PADDING, it adds the PKCS#7 padding to
 * whatever partial block is left and writes that final 16-byte block to
 * \p out, which must have room for it.  A message of 0 bytes still needs one
 * lws_genaes_crypt() call (with len 0) to give it the iv.
 *
 * Decrypting with LWS_GAESP_WITH_PADDING, it checks the padding at the end
 * of the plaintext lws_genaes_crypt() already wrote, and \p total_len is
 * the plaintext length without it.  It fails if there was no ciphertext or
 * the padding is not valid PKCS#7.  The check does not depend on where it
 * fails, but if the ciphertext was not authenticated before decryption,
 * reporting this failure to the peer is still a padding oracle: check a
 * MAC over the ciphertext first, as JWE does.
 *
 * Without padding, nothing is written and \p total_len is the length
 * processed.
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genaes_final(struct lws_genaes_ctx *ctx, uint8_t *out, size_t out_max,
		 size_t *total_len);

///@}
