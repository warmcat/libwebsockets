/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
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
 * included from libwebsockets.h
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
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
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

struct lws_genaes_ctx {
#if defined(LWS_WITH_MBEDTLS)
	union {
		mbedtls_aes_context ctx;
#if defined(MBEDTLS_CIPHER_MODE_XTS)
		mbedtls_aes_xts_context ctx_xts;
#endif
		mbedtls_gcm_context ctx_gcm;
	} u;
#else
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
	ENGINE *engine;
	char init;
#endif
	unsigned char tag[16];
	struct lws_gencrypto_keyelem *k;
	enum enum_aes_operation op;
	enum enum_aes_modes mode;
	enum enum_aes_padding padding;
	int taglen;
	char underway;
};

/** lws_genaes_create() - Create RSA public decrypt context
 *
 * \param ctx: your struct lws_genaes_ctx
 * \param op: LWS_GAESO_ENC or LWS_GAESO_DEC
 * \param mode: one of LWS_GAESM_
 * \param el: struct prepared with key element data
 * \param padding: 0 = no padding, 1 = padding
 * \param engine: if openssl engine used, pass the pointer here
 *
 * Creates an RSA context with a public key associated with it, formed from
 * the key elements in \p el.
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
 * This and related APIs operate identically with OpenSSL or mbedTLS backends.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen);

/** lws_genaes_crypt() - Encrypt or decrypt
 *
 * \param ctx: your struct lws_genaes_ctx
 * \param in: input plaintext or ciphertext
 * \param len: length of input (which is always length of output)
 * \param out: output plaintext or ciphertext
 * \param iv_or_nonce_ctr_or_data_unit_16: NULL, iv, nonce_ctr16, or data_unit16
 * \param stream_block_16: pointer to 16-byte stream block for CTR mode only
 * \param nc_or_iv_off: NULL or pointer to nc, or iv_off
 * \param taglen: length of tag
 *
 * Encrypts or decrypts using the AES mode set when the ctx was created.
 * The last three arguments have different meanings depending on the mode:
 *
 * 			      KW   CBC  CFB128 CFB8 CTR    ECB  OFB    XTS
 * iv_or_nonce_ct.._unit_16 : iv   iv   iv     iv   nonce  NULL iv     dataunt
 * stream_block_16	    : NULL NULL NULL   NULL stream NULL NULL   NULL
 * nc_or_iv_off		    : NULL NULL iv_off NULL nc_off NULL iv_off NULL
 *
 * For GCM:
 *
 * iv_or_nonce_ctr_or_data_unit_16 : iv
 * stream_block_16		   : pointer to tag
 * nc_or_iv_off			   : set pointed-to size_t to iv length
 * in				   : first call: additional data, subsequently
 *				   :   input data
 * len				   : first call: add data length, subsequently
 *				   :   input / output length
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

///@}
