/*
 * libwebsockets - JSON Web Encryption
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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
 *
 * JWE Compact Serialization consists of
 *
 *     BASE64URL(UTF8(JWE Protected Header)) || '.' ||
 *     BASE64URL(JWE Encrypted Key)	     || '.' ||
 *     BASE64URL(JWE Initialization Vector)  || '.' ||
 *     BASE64URL(JWE Ciphertext)	     || '.' ||
 *     BASE64URL(JWE Authentication Tag)
 */

#define LWS_JWE_RFC3394_OVERHEAD_BYTES 8
#define LWS_JWE_AES_IV_BYTES 16

#define LWS_JWE_LIMIT_RSA_KEY_BITS 4096
#define LWS_JWE_LIMIT_AES_KEY_BITS (512 + 64) /* RFC3394 Key Wrap adds 64b */
#define LWS_JWE_LIMIT_EC_KEY_BITS  528 /* 521 rounded to byte boundary */
#define LWS_JWE_LIMIT_HASH_BITS    (LWS_GENHASH_LARGEST * 8)

/* the largest key element for any cipher */
#define LWS_JWE_LIMIT_KEY_ELEMENT_BYTES (LWS_JWE_LIMIT_RSA_KEY_BITS / 8)

/**
 * lws_jwe_create_packet() - add b64 sig to b64 hdr + payload
 *
 * \param jwk: the struct lws_jwk containing the signing key
 * \param algtype: the signing algorithm
 * \param hash_type: the hashing algorithm
 * \param payload: unencoded payload JSON
 * \param len: length of unencoded payload JSON
 * \param nonce: Nonse string to include in protected header
 * \param out: buffer to take signed packet
 * \param out_len: size of \p out buffer
 * \param conext: lws_context to get random from
 *
 * This creates a "flattened" JWS packet from the jwk and the plaintext
 * payload, and signs it.  The packet is written into \p out.
 *
 * This does the whole packet assembly and signing, calling through to
 * lws_jws_sign_from_b64() as part of the process.
 *
 * Returns the length written to \p out, or -1.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwe_create_packet(struct lws_jose *jose, struct lws_jwk *jwk,
		      const char *payload, size_t len, const char *nonce,
		      char *out, size_t out_len, struct lws_context *context);

LWS_VISIBLE LWS_EXTERN void
lws_jwe_be64(uint64_t c, uint8_t *p8);

/*
 * JWE Compact Serialization consists of
 *
 *     BASE64URL(UTF8(JWE Protected Header)) || '.' ||
 *     BASE64URL(JWE Encrypted Key)	     || '.' ||
 *     BASE64URL(JWE Initialization Vector)  || '.' ||
 *     BASE64URL(JWE Ciphertext)	     || '.' ||
 *     BASE64URL(JWE Authentication Tag)
 */

LWS_VISIBLE LWS_EXTERN int
lws_jwe_write_compact(struct lws_jose *jose, struct lws_jws *jws,
		      char *out, size_t out_len);


/**
 * lws_jwe_auth_and_decrypt() - confirm and decrypt JWE
 *
 * \param jose: jose context
 * \param jws: jws / jwe context... .map and .map_b64 must be filled already
 *
 * This is a high level JWE decrypt api that takes a jws with the maps
 * already processed, and if the authentication passes, returns the decrypted
 * plaintext in jws.map.buf[LJWE_CTXT] and its length in jws.map.len[LJWE_CTXT].
 *
 * In the jws, the following fields must have been set by the caller
 *
 * .context
 * .jwk (the key encryption key)
 * .map
 * .map_b64
 *
 * Having the b64 and decoded maps filled externally makes it flexible where
 * the data was picked from, eg, from a Complete JWE JSON serialization, a
 * flattened one, or a Compact Serialization.
 *
 * Returns decrypt length, or -1 for failure.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwe_auth_and_decrypt(struct lws_jose *jose, struct lws_jws *jws);



/* only exposed because we have test vectors that need it */
LWS_VISIBLE LWS_EXTERN int
lws_jwe_auth_and_decrypt_cbc_hs(struct lws_jose *jose,
					struct lws_jws *jws, uint8_t *enc_cek,
					uint8_t *aad, int aad_len);

/* only exposed because we have test vectors that need it */
LWS_VISIBLE LWS_EXTERN int
lws_jwa_concat_kdf(struct lws_jose *jose, struct lws_jws *jws, int direct,
		   uint8_t *out, const uint8_t *shared_secret, int sslen);


/**
 * lws_jwe_encrypt() - perform JWE encryption
 *
 * \param jose: the JOSE header information (encryption types, etc)
 * \param jws: the JWE elements, pointer to jwk etc
 * \param temp: parent-owned buffer to "allocate" elements into
 * \param temp_len: amount of space available in temp
 *
 * returns the amount of temp used, or -1 for error
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwe_encrypt(struct lws_jose *jose, struct lws_jws *jws,
		char *temp, int *temp_len);
