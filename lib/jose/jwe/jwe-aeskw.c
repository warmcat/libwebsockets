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
lws_jwe_encrypt_aeskw_cbc_hs(struct lws_jose *jose, struct lws_jws *jws,
				char *temp, int *temp_len)
{
	struct lws_genaes_ctx aesctx;
	/* we are wrapping a key, so size for the worst case after wrap */
	uint8_t enc_cek[LWS_JWE_LIMIT_KEY_ELEMENT_BYTES +
	                LWS_JWE_RFC3394_OVERHEAD_BYTES];
	int n, m, hlen = lws_genhmac_size(jose->enc_alg->hmac_type);

	if (jws->jwk->kty != LWS_GENCRYPTO_KTY_OCT) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jws->jwk->kty);

		return -1;
	}

	jws->map_b64.len[LJWE_JOSE] = ((jws->map.len[LJWE_JOSE] * 4) / 3) + 10;
	if (*temp_len < jws->map_b64.len[LJWE_JOSE])
		return -1;
	jws->map_b64.buf[LJWE_JOSE] = (char *)temp;
	temp += jws->map_b64.len[LJWE_JOSE];
	*temp_len -= jws->map_b64.len[LJWE_JOSE];

	n = lws_jws_base64_enc(jws->map.buf[LJWE_JOSE], jws->map.len[LJWE_JOSE],
			       (char *)jws->map_b64.buf[LJWE_JOSE],
			       jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_notice("%s: failed to encode JOSE hdr\n", __func__);

		return -1;
	}
	jws->map_b64.len[LJWE_JOSE] = n;

	jws->map.buf[LJWE_ATAG] = (char *)temp;
	jws->map.len[LJWE_ATAG] = hlen / 2;
	if (*temp_len < jws->map.len[LJWE_ATAG])
		return -1;
	temp += hlen / 2;
	*temp_len -= hlen / 2;

	jws->map.buf[LJWE_IV] = (char *)temp;
	jws->map.len[LJWE_IV] = LWS_JWE_AES_IV_BYTES;
	if (*temp_len < jws->map.len[LJWE_IV])
		return -1;
	temp += LWS_JWE_AES_IV_BYTES;
	*temp_len -= LWS_JWE_AES_IV_BYTES;

	/* 1) Encrypt the payload...  */

	/* the CEK is 256-bit in the example encrypted with a 128-bit key */

	n = lws_jwe_encrypt_cbc_hs(jose, jws, (uint8_t *)jws->map.buf[LJWE_EKEY],
			     (uint8_t *)jws->map_b64.buf[LJWE_JOSE],
			     jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt_cbc_hs failed\n", __func__);
		return -1;
	}

	/* 2) Encrypt the JWE Encrypted Key: RFC3394 Key Wrap uses 64 bit blocks
	 *    and 128-bit input key*/

	if (lws_genaes_create(&aesctx, LWS_GAESO_ENC, LWS_GAESM_KW,
			      jws->jwk->e, 1, NULL)) {

		lwsl_notice("%s: lws_genaes_create\n", __func__);
		return -1;
	}

	/* tag size is determined by enc cipher key length */

	n = lws_genaes_crypt(&aesctx, (uint8_t *)jws->map.buf[LJWE_EKEY],
			     jws->map.len[LJWE_EKEY], enc_cek, NULL, NULL, NULL,
			     lws_gencrypto_bits_to_bytes(
					     jose->enc_alg->keybits_fixed));
	m = lws_genaes_destroy(&aesctx, NULL, 0);
	if (n < 0) {
		lwsl_err("%s: encrypt cek fail\n", __func__);
		return -1;
	}
	if (m < 0) {
		lwsl_err("%s: lws_genaes_destroy fail\n", __func__);
		return -1;
	}

	jws->map.len[LJWE_EKEY] += LWS_JWE_RFC3394_OVERHEAD_BYTES;
	memcpy((uint8_t *)jws->map.buf[LJWE_EKEY], enc_cek,
	       jws->map.len[LJWE_EKEY]);

	return jws->map.len[LJWE_CTXT];
}


int
lws_jwe_auth_and_decrypt_aeskw_cbc_hs(struct lws_jose *jose,
					      struct lws_jws *jws)
{
	struct lws_genaes_ctx aesctx;
	uint8_t enc_cek[LWS_JWE_LIMIT_KEY_ELEMENT_BYTES +
	                LWS_JWE_RFC3394_OVERHEAD_BYTES];
	int n, m;

	if (jws->jwk->kty != LWS_GENCRYPTO_KTY_OCT) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jws->jwk->kty);

		return -1;
	}

	/* the CEK is 256-bit in the example encrypted with a 128-bit key */

	if (jws->map.len[LJWE_EKEY] > sizeof(enc_cek))
		return -1;

	/* 1) Decrypt the JWE Encrypted Key to get the raw MAC / CEK */

	if (lws_genaes_create(&aesctx, LWS_GAESO_DEC, LWS_GAESM_KW,
			      jws->jwk->e, 1, NULL)) {

		lwsl_notice("%s: lws_genaes_create\n", __func__);
		return -1;
	}

	/*
	 * Decrypt the CEK into enc_cek
	 * tag size is determined by enc cipher key length */

	n = lws_genaes_crypt(&aesctx, (uint8_t *)jws->map.buf[LJWE_EKEY],
			     jws->map.len[LJWE_EKEY], enc_cek, NULL, NULL, NULL,
			     lws_gencrypto_bits_to_bytes(
					     jose->enc_alg->keybits_fixed));
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

	n = lws_jwe_auth_and_decrypt_cbc_hs(jose, jws, enc_cek,
			     (uint8_t *)jws->map_b64.buf[LJWE_JOSE],
			     jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt_cbc_hs failed\n",
				__func__);
		return -1;
	}

	return jws->map.len[LJWE_CTXT];
}


