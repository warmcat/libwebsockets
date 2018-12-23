/*
 * libwebsockets - JSON Web Encryption support
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
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
 *
 * JWE code related to aeskw cbc
 *
 */
#include "core/private.h"
#include "jose/jwe/private.h"


/*
 * RFC3394 Key Wrap uses a 128-bit key, and bloats what it is wrapping by
 * one 8-byte block.  So, if you had a 32 byte plaintext CEK to wrap, after
 * wrapping it becomes a 40 byte wrapped, enciphered, key.
 *
 * The CEK comes in from and goes out in LJWE_EKEY.  So LJWE_EKEY length
 * increases by 8 from calling this.
 */

int
lws_jwe_encrypt_aeskw_cbc_hs(struct lws_jwe *jwe, char *temp, int *temp_len)
{
	struct lws_genaes_ctx aesctx;
	/* we are wrapping a key, so size for the worst case after wrap */
	uint8_t enc_cek[LWS_JWE_LIMIT_KEY_ELEMENT_BYTES +
	                LWS_JWE_RFC3394_OVERHEAD_BYTES];
	int n, m, hlen = lws_genhmac_size(jwe->jose.enc_alg->hmac_type),
			 ot = *temp_len;

	if (jwe->jws.jwk->kty != LWS_GENCRYPTO_KTY_OCT) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jwe->jws.jwk->kty);

		return -1;
	}

	/* create a b64 version of the JOSE header, needed for hashing */

	if (lws_jws_encode_b64_element(&jwe->jws.map_b64, LJWE_JOSE,
				       temp + (ot - *temp_len), temp_len,
				       jwe->jws.map.buf[LJWE_JOSE],
				       jwe->jws.map.len[LJWE_JOSE]))
		return -1;

	/* Allocate temp space for ATAG and IV */

	if (lws_jws_alloc_element(&jwe->jws.map, LJWE_ATAG, temp + (ot - *temp_len),
				  temp_len, hlen / 2, 0))
		return -1;

	if (lws_jws_alloc_element(&jwe->jws.map, LJWE_IV, temp + (ot - *temp_len),
				  temp_len, LWS_JWE_AES_IV_BYTES, 0))
		return -1;

	/* 1) Encrypt the payload...  */

	/* the CEK is 256-bit in the example encrypted with a 128-bit key */

	n = lws_jwe_encrypt_cbc_hs(jwe, (uint8_t *)jwe->jws.map.buf[LJWE_EKEY],
				   (uint8_t *)jwe->jws.map_b64.buf[LJWE_JOSE],
				   jwe->jws.map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt_cbc_hs failed\n", __func__);
		return -1;
	}

	/* 2) Encrypt the JWE Encrypted Key: RFC3394 Key Wrap uses 64 bit blocks
	 *    and 128-bit input key*/

	if (lws_genaes_create(&aesctx, LWS_GAESO_ENC, LWS_GAESM_KW,
			      jwe->jws.jwk->e, 1, NULL)) {

		lwsl_notice("%s: lws_genaes_create\n", __func__);
		return -1;
	}

	/* tag size is determined by enc cipher key length */

	n = lws_genaes_crypt(&aesctx, (uint8_t *)jwe->jws.map.buf[LJWE_EKEY],
			     jwe->jws.map.len[LJWE_EKEY], enc_cek, NULL, NULL, NULL,
			     lws_gencrypto_bits_to_bytes(
					     jwe->jose.enc_alg->keybits_fixed));
	m = lws_genaes_destroy(&aesctx, NULL, 0);
	if (n < 0) {
		lwsl_err("%s: encrypt cek fail\n", __func__);
		return -1;
	}
	if (m < 0) {
		lwsl_err("%s: lws_genaes_destroy fail\n", __func__);
		return -1;
	}

	jwe->jws.map.len[LJWE_EKEY] += LWS_JWE_RFC3394_OVERHEAD_BYTES;
	memcpy((uint8_t *)jwe->jws.map.buf[LJWE_EKEY], enc_cek,
	       jwe->jws.map.len[LJWE_EKEY]);

	return jwe->jws.map.len[LJWE_CTXT];
}


int
lws_jwe_auth_and_decrypt_aeskw_cbc_hs(struct lws_jwe *jwe)
{
	struct lws_genaes_ctx aesctx;
	uint8_t enc_cek[LWS_JWE_LIMIT_KEY_ELEMENT_BYTES +
	                LWS_JWE_RFC3394_OVERHEAD_BYTES];
	int n, m;

	if (jwe->jws.jwk->kty != LWS_GENCRYPTO_KTY_OCT) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jwe->jws.jwk->kty);

		return -1;
	}

	/* the CEK is 256-bit in the example encrypted with a 128-bit key */

	if (jwe->jws.map.len[LJWE_EKEY] > sizeof(enc_cek))
		return -1;

	/* 1) Decrypt the JWE Encrypted Key to get the raw MAC / CEK */

	if (lws_genaes_create(&aesctx, LWS_GAESO_DEC, LWS_GAESM_KW,
			      jwe->jws.jwk->e, 1, NULL)) {

		lwsl_notice("%s: lws_genaes_create\n", __func__);
		return -1;
	}

	/*
	 * Decrypt the CEK into enc_cek
	 * tag size is determined by enc cipher key length */

	n = lws_genaes_crypt(&aesctx, (uint8_t *)jwe->jws.map.buf[LJWE_EKEY],
			     jwe->jws.map.len[LJWE_EKEY], enc_cek, NULL, NULL, NULL,
			     lws_gencrypto_bits_to_bytes(
					     jwe->jose.enc_alg->keybits_fixed));
	m = lws_genaes_destroy(&aesctx, NULL, 0);
	if (n < 0) {
		lwsl_err("%s: decrypt CEK fail\n", __func__);
		return -1;
	}
	if (m < 0) {
		lwsl_err("%s: lws_genaes_destroy fail\n", __func__);
		return -1;
	}

	/* 2) Decrypt the payload */

	n = lws_jwe_auth_and_decrypt_cbc_hs(jwe, enc_cek,
			     (uint8_t *)jwe->jws.map_b64.buf[LJWE_JOSE],
			     jwe->jws.map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt_cbc_hs failed\n",
				__func__);
		return -1;
	}

	return jwe->jws.map.len[LJWE_CTXT];
}


