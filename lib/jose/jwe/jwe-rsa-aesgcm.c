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
#define LWS_AESGCM_TAG 16

/*
 * NOTICE this is AESGCM content encryption, it's not AES GCM key wrapping
 *
 *
 * This section defines the specifics of performing authenticated
 * encryption with AES in Galois/Counter Mode (GCM) ([AES] and
 * [NIST.800-38D]).
 *
 * The CEK is used as the encryption key.
 *
 * Use of an IV of size 96 bits is REQUIRED with this algorithm.
 *
 * The requested size of the Authentication Tag output MUST be 128 bits,
 * regardless of the key size.
 *
 * For decrypt: decrypt the KEK, then decrypt the payload
 *
 * For encrypt: encrypt the payload, then encrypt the KEK
 */

/*
 * encrypting... enc_cek is unencrypted
 */

int
lws_jwe_encrypt_gcm(struct lws_jose *jose, struct lws_jws *jws,
		    uint8_t *enc_cek, uint8_t *aad, int aad_len)
{
	struct lws_gencrypto_keyelem el;
	struct lws_genaes_ctx aesctx;
	size_t ivs = LWS_AESGCM_IV;
	int n;

	/* Some sanity checks on what came in */

	/* MUST be 128-bit for all sizes */
	if (jws->map.len[LJWE_ATAG] != LWS_AESGCM_TAG) {
		lwsl_notice("%s: AESGCM tag size must be 128b, got %d\n",
				__func__, jws->map.len[LJWE_ATAG]);
		return -1;
	}

	if (jws->map.len[LJWE_IV] != LWS_AESGCM_IV) { /* MUST be 96-bit */
		lwsl_notice("%s: AESGCM IV must be 128b, got %d\n", __func__,
				jws->map.len[LJWE_IV]);
		return -1;
	}

	/* EKEY is directly the CEK KEY */
	el.buf = enc_cek;
	el.len = jose->enc_alg->keybits_fixed / 8;

	if (lws_genaes_create(&aesctx, LWS_GAESO_ENC, LWS_GAESM_GCM,
			      &el, LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);

		return -1;
	}

	/* aad */

	n = lws_genaes_crypt(&aesctx, aad, aad_len, NULL,
			     (uint8_t *)jws->map.buf[LJWE_IV],
			     (uint8_t *)jws->map.buf[LJWE_ATAG], &ivs,
			     LWS_AESGCM_TAG);
	if (n) {
		lwsl_err("%s: lws_genaes_crypt aad failed\n", __func__);
		return -1;
	}

	/* payload */
	n = lws_genaes_crypt(&aesctx, (uint8_t *)jws->map.buf[LJWE_CTXT],
			     jws->map.len[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_IV],
			     NULL, &ivs,
			     LWS_AESGCM_TAG);

	n |= lws_genaes_destroy(&aesctx, (uint8_t *)jws->map.buf[LJWE_ATAG],
				LWS_AESGCM_TAG);
	if (n) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		return -1;
	}

	return jws->map.len[LJWE_CTXT];
}



int
lws_jwe_encrypt_rsa_aes_gcm(struct lws_jose *jose, struct lws_jws *jws,
		char *temp, int *temp_len)
{
	int n, ret = -1, used = 0;
	struct lws_genrsa_ctx rsactx;
	uint8_t enc_cek[LWS_JWE_LIMIT_KEY_ELEMENT_BYTES];
	int ekbytes = jose->enc_alg->keybits_fixed / 8;

	if (jws->jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jws->jwk->kty);

		return -1;
	}

	if (jws->map.len[LJWE_EKEY] < 32) {
		lwsl_err("%s: EKEY length too short %d\n", __func__,
				jws->map.len[LJWE_EKEY]);

		return -1;
	}

	/* create the IV + CEK */

	jws->map_b64.len[LJWE_JOSE] = lws_base64_size(jws->map.len[LJWE_JOSE]);

	if (*temp_len < LWS_AESGCM_IV + LWS_AESGCM_TAG + ekbytes +
			jws->map_b64.len[LJWE_JOSE])
		return -1;

	*temp_len -= LWS_AESGCM_IV + LWS_AESGCM_TAG +
		     jws->map_b64.len[LJWE_JOSE] +
		     (jose->enc_alg->keybits_fixed / 8);

	if (lws_get_random(jws->context, temp, LWS_AESGCM_IV) != LWS_AESGCM_IV)
		return -1;
	jws->map.buf[LJWE_IV] = temp;
	jws->map.len[LJWE_IV] = LWS_AESGCM_IV;
	temp += LWS_AESGCM_IV;

	jws->map.buf[LJWE_ATAG] = temp;
	jws->map.len[LJWE_ATAG] = LWS_AESGCM_TAG;
	temp += LWS_AESGCM_TAG;

	/* we create the CEK into EKEY, it'll be cleansed by jws destroy */

	if (lws_get_random(jws->context, temp, ekbytes) != ekbytes)
		return -1;
	jws->map.buf[LJWE_EKEY] = temp;
	jws->map.len[LJWE_EKEY] = ekbytes;
	temp += ekbytes;

	jws->map_b64.buf[LJWE_JOSE] = temp;
	temp += jws->map_b64.len[LJWE_JOSE];
	/* we need a b64u encode of the JOSE header as AAD */

	n = lws_jws_base64_enc(jws->map.buf[LJWE_JOSE], jws->map.len[LJWE_JOSE],
			       (char *)jws->map_b64.buf[LJWE_JOSE],
			       jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_notice("%s: failed to encode JOSE hdr\n", __func__);

		return -1;
	}
	jws->map_b64.len[LJWE_JOSE] = n;

	/* we must cleanse enc_cek */
	used = jws->map.len[LJWE_EKEY];
	memcpy(enc_cek, jws->map.buf[LJWE_EKEY], jws->map.len[LJWE_EKEY]);

	/* encrypt the payload */

	n = lws_jwe_encrypt_gcm(jose, jws, (uint8_t *)jws->map.buf[LJWE_EKEY],
				(uint8_t *)jws->map_b64.buf[LJWE_JOSE],
				jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt_gcm failed\n",
			 __func__);
		goto bail;
	}

	/* Encrypt the CEK to make the JWE Encrypted Key */

	if (lws_genrsa_create(&rsactx, jws->jwk->e, jws->context,
			!strcmp(jose->alg->alg,   "RSA-OAEP") ?
				LGRSAM_PKCS1_OAEP_PSS : LGRSAM_PKCS1_1_5,
			LWS_GENHASH_TYPE_SHA1 /* !!! */)) {
		lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
			    __func__);
		goto bail;
	}

	n = lws_genrsa_public_encrypt(&rsactx,
				       (uint8_t *)jws->map.buf[LJWE_EKEY],
				       jws->map.len[LJWE_EKEY], enc_cek);
	lws_genrsa_destroy(&rsactx);
	if (n < 0) {
		lwsl_err("%s: encrypt cek fail: \n", __func__);
		goto bail;
	}
	jws->map.len[LJWE_EKEY] = n;

	/* overwrite the CEK in EKEY with the encrypted version */

	memcpy((void *)jws->map.buf[LJWE_EKEY], enc_cek,
	       jws->map.len[LJWE_EKEY]);

	ret = jws->map.len[LJWE_CTXT];

bail:
	/* cleanse enc_cek on stack that contained the unencrypted CEK */
	lws_explicit_bzero(enc_cek, used);

	return ret;
}

int
lws_jwe_auth_and_decrypt_gcm(struct lws_jose *jose, struct lws_jws *jws,
			     uint8_t *enc_cek, uint8_t *aad, int aad_len)
{
	struct lws_gencrypto_keyelem el;
	struct lws_genaes_ctx aesctx;
	size_t ivs = LWS_AESGCM_IV;
	uint8_t tag[LWS_AESGCM_TAG];
	int n;

	/* Some sanity checks on what came in */

	/* Tag MUST be 128-bit for all sizes */
	if (jws->map.len[LJWE_ATAG] != LWS_AESGCM_TAG) {
		lwsl_notice("%s: AESGCM tag size must be 128b, got %d\n",
				__func__, jws->map.len[LJWE_ATAG]);
		return -1;
	}

	if (jws->map.len[LJWE_IV] != LWS_AESGCM_IV) { /* MUST be 96-bit */
		lwsl_notice("%s: AESGCM IV must be 128b, got %d\n", __func__,
				jws->map.len[LJWE_IV]);
		return -1;
	}

	/* EKEY is directly the CEK KEY */
	el.buf = enc_cek;
	el.len = jose->enc_alg->keybits_fixed / 8;

	if (lws_genaes_create(&aesctx, LWS_GAESO_DEC, LWS_GAESM_GCM,
			      &el, LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);

		return -1;
	}

	n = lws_genaes_crypt(&aesctx, aad, aad_len,
			     NULL,
			     (uint8_t *)jws->map.buf[LJWE_IV],
			     (uint8_t *)jws->map.buf[LJWE_ATAG], &ivs, 16);
	if (n) {
		lwsl_err("%s: lws_genaes_crypt aad failed\n", __func__);
		return -1;
	}
	n = lws_genaes_crypt(&aesctx, (uint8_t *)jws->map.buf[LJWE_CTXT],
			     jws->map.len[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_IV],
			     (uint8_t *)jws->map.buf[LJWE_ATAG], &ivs, 16);

	n |= lws_genaes_destroy(&aesctx, tag, sizeof(tag));
	if (n) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		return -1;
	}

	return jws->map.len[LJWE_CTXT];
}



int
lws_jwe_auth_and_decrypt_rsa_aes_gcm(struct lws_jose *jose, struct lws_jws *jws)
{
	int n;
	struct lws_genrsa_ctx rsactx;
	uint8_t enc_cek[LWS_JWE_LIMIT_KEY_ELEMENT_BYTES];

	if (jws->jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jws->jwk->kty);

		return -1;
	}

	if (jws->map.len[LJWE_EKEY] < 32) {
		lwsl_err("%s: EKEY length too short %d\n", __func__,
				jws->map.len[LJWE_EKEY]);

		return -1;
	}

	/* Decrypt the JWE Encrypted Key to get the direct CEK */

	if (lws_genrsa_create(&rsactx, jws->jwk->e, jws->context,
			!strcmp(jose->alg->alg,   "RSA-OAEP") ?
				LGRSAM_PKCS1_OAEP_PSS : LGRSAM_PKCS1_1_5,
			LWS_GENHASH_TYPE_SHA1 /* !!! */)) {
		lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
			    __func__);
		return -1;
	}

	n = lws_genrsa_private_decrypt(&rsactx,
				       (uint8_t *)jws->map.buf[LJWE_EKEY],
				       jws->map.len[LJWE_EKEY], enc_cek,
				       sizeof(enc_cek));
	lws_genrsa_destroy(&rsactx);
	if (n < 0) {
		lwsl_err("%s: decrypt cek fail: \n", __func__);
		return -1;
	}

	n = lws_jwe_auth_and_decrypt_gcm(jose, jws, enc_cek,
			(uint8_t *)jws->map_b64.buf[LJWE_JOSE],
				jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt_gcm_hs failed\n",
			 __func__);
		return -1;
	}

	return jws->map.len[LJWE_CTXT];
}
