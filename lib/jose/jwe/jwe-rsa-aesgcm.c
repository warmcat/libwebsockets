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
 * JWE code related to aes gcm
 *
 */
#include "core/private.h"
#include "jose/jwe/private.h"

#define LWS_AESGCM_IV 12


int
lws_jwe_encrypt_rsa_aes_gcm(struct lws_jwe *jwe, char *temp, int *temp_len)
{
	int ekbytes = jwe->jose.enc_alg->keybits_fixed / 8;
	struct lws_genrsa_ctx rsactx;
	int n, ret = -1, ot = *temp_len;

	if (jwe->jws.jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: wrong kty %d\n", __func__, jwe->jws.jwk->kty);

		return -1;
	}

	/* create the IV + CEK */

	if (lws_jws_randomize_element(jwe->jws.context, &jwe->jws.map, LJWE_IV,
				      temp + (ot - *temp_len), temp_len,
				      LWS_AESGCM_IV, 0))
		return -1;

	if (lws_jws_alloc_element(&jwe->jws.map, LJWE_ATAG,
				  temp + (ot - *temp_len),
				  temp_len, LWS_AESGCM_TAG, 0))
		return -1;

	/* create a b64 version of the JOSE header, needed as aad */

	if (lws_jws_encode_b64_element(&jwe->jws.map_b64, LJWE_JOSE,
				       temp + (ot - *temp_len), temp_len,
				       jwe->jws.map.buf[LJWE_JOSE],
				       jwe->jws.map.len[LJWE_JOSE]))
		return -1;

	/*
	 * If none already, create a new, random CEK in the JWE (so it can be
	 * reused for other recipients on same payload).  If it already exists,
	 * just reuse it.  It will be cleansed in the JWE destroy.
	 */
	if (!jwe->cek_valid) {
		if (lws_get_random(jwe->jws.context, jwe->cek, ekbytes) !=
							       ekbytes) {
			lwsl_err("%s: Problem getting random\n", __func__);
			return -1;
		}
		jwe->cek_valid = 1;
	}

	if (lws_jws_dup_element(&jwe->jws.map, LJWE_EKEY,
			        temp + (ot - *temp_len), temp_len,
			        jwe->cek, ekbytes, 0))
		return -1;

	/* encrypt the payload */

	n = lws_jwe_encrypt_gcm(jwe, (uint8_t *)jwe->jws.map.buf[LJWE_EKEY],
				(uint8_t *)jwe->jws.map_b64.buf[LJWE_JOSE],
				jwe->jws.map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt_gcm failed\n",
			 __func__);
		goto bail;
	}

	/* Encrypt the CEK into EKEY to make the JWE Encrypted Key */

	if (lws_genrsa_create(&rsactx, jwe->jws.jwk->e, jwe->jws.context,
			!strcmp(jwe->jose.alg->alg,   "RSA-OAEP") ?
				LGRSAM_PKCS1_OAEP_PSS : LGRSAM_PKCS1_1_5,
			LWS_GENHASH_TYPE_SHA1 /* !!! */)) {
		lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
			    __func__);
		goto bail;
	}

	n = lws_genrsa_public_encrypt(&rsactx, jwe->cek, ekbytes,
				      (uint8_t *)jwe->jws.map.buf[LJWE_EKEY]);
	lws_genrsa_destroy(&rsactx);
	if (n < 0) {
		lwsl_err("%s: encrypt cek fail: \n", __func__);
		goto bail;
	}

	/* set the EKEY length to the actual enciphered length */
	jwe->jws.map.len[LJWE_EKEY] = n;

	ret = jwe->jws.map.len[LJWE_CTXT];

bail:

	return ret;
}

int
lws_jwe_auth_and_decrypt_rsa_aes_gcm(struct lws_jwe *jwe)
{
	int n;
	struct lws_genrsa_ctx rsactx;
	uint8_t enc_cek[LWS_JWE_LIMIT_KEY_ELEMENT_BYTES];

	if (jwe->jws.jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jwe->jws.jwk->kty);

		return -1;
	}

	if (jwe->jws.map.len[LJWE_EKEY] < 32) {
		lwsl_err("%s: EKEY length too short %d\n", __func__,
				jwe->jws.map.len[LJWE_EKEY]);

		return -1;
	}

	/* Decrypt the JWE Encrypted Key to get the direct CEK */

	if (lws_genrsa_create(&rsactx, jwe->jws.jwk->e, jwe->jws.context,
			!strcmp(jwe->jose.alg->alg,   "RSA-OAEP") ?
				LGRSAM_PKCS1_OAEP_PSS : LGRSAM_PKCS1_1_5,
			LWS_GENHASH_TYPE_SHA1 /* !!! */)) {
		lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
			    __func__);
		return -1;
	}

	n = lws_genrsa_private_decrypt(&rsactx,
				       (uint8_t *)jwe->jws.map.buf[LJWE_EKEY],
				       jwe->jws.map.len[LJWE_EKEY], enc_cek,
				       sizeof(enc_cek));
	lws_genrsa_destroy(&rsactx);
	if (n < 0) {
		lwsl_err("%s: decrypt cek fail: \n", __func__);
		return -1;
	}

	n = lws_jwe_auth_and_decrypt_gcm(jwe, enc_cek,
			(uint8_t *)jwe->jws.map_b64.buf[LJWE_JOSE],
				jwe->jws.map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt_gcm_hs failed\n",
			 __func__);
		return -1;
	}

#if defined(LWS_WITH_MBEDTLS) && defined(LWS_PLAT_OPTEE)
	/* strip padding */

	n = jwe->jws.map.buf[LJWE_CTXT][jwe->jws.map.len[LJWE_CTXT] - 1];
	if (n > 16)
		return -1;
	jwe->jws.map.len[LJWE_CTXT] -= n;
#endif

	return jwe->jws.map.len[LJWE_CTXT];
}
