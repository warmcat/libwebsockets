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
 * JWE code related to rsa + aescbc
 *
 */
#include "core/private.h"
#include "jose/jwe/private.h"

int
lws_jwe_encrypt_cbc_hs(struct lws_jose *jose, struct lws_jws *jws,
			 uint8_t *cek, uint8_t *aad, int aad_len)
{
	int n, hlen = lws_genhmac_size(jose->enc_alg->hmac_type);
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_gencrypto_keyelem el;
	struct lws_genhmac_ctx hmacctx;
	struct lws_genaes_ctx aesctx;
	uint8_t al[8];

	/* Caller must have prepared space for the results */

	if (jws->map.len[LJWE_ATAG] != hlen / 2) {
		lwsl_notice("%s: expected tag len %d, got %d\n", __func__,
			    hlen / 2, jws->map.len[LJWE_ATAG]);
		return -1;
	}

	if (jws->map.len[LJWE_IV] != 16) {
		lwsl_notice("expected iv len %d, got %d\n", 16,
				jws->map.len[LJWE_IV]);
		return -1;
	}

	/* first create the authentication hmac */

	/* JWA Section 5.2.2.1
	 *
	 * 1.  The secondary keys MAC_KEY and ENC_KEY are generated from the
	 *     input key K as follows.  Each of these two keys is an octet
	 *     string.
	 *
	 *       MAC_KEY consists of the initial MAC_KEY_LEN octets of K, in
	 *        order.
	 *       ENC_KEY consists of the final ENC_KEY_LEN octets of K, in
	 *        order.
	 */

	/*
	 *    2.  The IV used is a 128-bit value generated randomly or
	 *        pseudorandomly for use in the cipher.
	 */
	lws_get_random(jws->context, (void *)jws->map.buf[LJWE_IV], 16);

	/*
	 *  3.  The plaintext is CBC encrypted using PKCS #7 padding using
	 *      ENC_KEY as the key and the IV.  We denote the ciphertext output
	 *      from this step as E.
	 */

	/* second half is the AES ENC_KEY */
	el.buf = (uint8_t *)jws->map.buf[LJWE_EKEY] + (hlen / 2);
	el.len = hlen / 2;

	if (lws_genaes_create(&aesctx, LWS_GAESO_ENC, LWS_GAESM_CBC, &el,
			      LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);

		return -1;
	}

	/*
	 * the plaintext gets delivered to us in LJWE_CTXT, this replaces
	 * the plaintext there with the same amount of ciphertext
	 */
	n = lws_genaes_crypt(&aesctx, (uint8_t *)jws->map.buf[LJWE_CTXT],
			     jws->map.len[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_IV], NULL, NULL, 16);
	lws_genaes_destroy(&aesctx, NULL, 0);
	if (n) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		return -1;
	}

	/*
	 * 4.  The octet string AL is equal to the number of bits in the
	 *     Additional Authenticated Data A expressed as a 64-bit unsigned
	 *     big-endian integer.
	 */
	lws_jwe_be64(aad_len * 8, al);

	/* first half of the CEK is the MAC key */
	if (lws_genhmac_init(&hmacctx, jose->enc_alg->hmac_type,
			     (uint8_t *)jws->map.buf[LJWE_EKEY], hlen / 2))
		return -1;

	/*
	 *    5.  A message Authentication Tag T is computed by applying HMAC
	 *    [RFC2104] to the following data, in order:
	 *
	 *     - the Additional Authenticated Data A,
	 *     - the Initialization Vector IV,
	 *     - the ciphertext E computed in the previous step, and
	 *     - the octet string AL defined above.
	 *
	 *    The string MAC_KEY is used as the MAC key.  We denote the output
	 *    of the MAC computed in this step as M.  The first T_LEN octets of
	 *    M are used as T.
	 */

	if (lws_genhmac_update(&hmacctx, aad, aad_len) ||
	    lws_genhmac_update(&hmacctx, jws->map.buf[LJWE_IV],
			       LWS_JWE_AES_IV_BYTES) ||
	    /* since we encrypted it, this is the ciphertext */
	    lws_genhmac_update(&hmacctx, (uint8_t *)jws->map.buf[LJWE_CTXT],
				         jws->map.len[LJWE_CTXT]) ||
	    lws_genhmac_update(&hmacctx, al, 8)) {
		lwsl_err("%s: hmac computation failed\n", __func__);
		lws_genhmac_destroy(&hmacctx, NULL);
		return -1;
	}

	if (lws_genhmac_destroy(&hmacctx, digest)) {
		lwsl_err("%s: problem destroying hmac\n", __func__);
		return -1;
	}

	/* create tag */
	memcpy((void *)jws->map.buf[LJWE_ATAG], digest, hlen / 2);

	return jws->map.len[LJWE_CTXT];
}

/*
 * Requirements on entry:
 *
 *  - jws->map LJWE_JOSE contains the ASCII JOSE header
 *  - jws->map LJWE_EKEY contains cek of enc_alg hmac length
 *  - jws->map LJWE_CTXT contains the plaintext
 *
 * On successful exit:
 *
 *  - jws->map LJWE_ATAG contains the tag
 *  - jws->map LJWE_IV contains the new random IV that was used
 *  - jws->map LJWE_EKEY contains the encrypted CEK
 *  - jws->map LJWE_CTXT contains the ciphertext
 *
 *  Return the amount of temp used, or -1
 */

int
lws_jwe_encrypt_rsa_aes_cbc_hs(struct lws_jose *jose, struct lws_jws *jws,
			       char *temp, int *temp_len)
{
	int n, hlen = lws_genhmac_size(jose->enc_alg->hmac_type), want;
	char ekey[LWS_GENHASH_LARGEST];
	struct lws_genrsa_ctx rsactx;

	if (jws->jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jws->jwk->kty);

		return -1;
	}

	/*
	 * Reserve space in caller temp for extra JWE elements and b64 version
	 * of the JOSE hdr needed for computation... notice that the
	 * unencrypted EKEY coming in is smaller than the RSA-encrypted EKEY
	 * going out, which is going to be the RSA key size
	 */

	want = lws_base64_size(jws->map.len[LJWE_JOSE]) +
		jws->jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len +
		(hlen / 2) + LWS_JWE_AES_IV_BYTES;
	if (*temp_len < want) {
		lwsl_notice("%s: more temp space needed: want %d, got %d\n",
			    __func__, want, *temp_len);
		return -1;
	}

	jws->map_b64.buf[LJWE_JOSE] = (char *)temp;
	jws->map_b64.len[LJWE_JOSE] = lws_base64_size(jws->map.len[LJWE_JOSE]);
	if (*temp_len < jws->map_b64.len[LJWE_JOSE])
		return -1;
	temp += jws->map_b64.len[LJWE_JOSE];
	*temp_len -= jws->map_b64.len[LJWE_JOSE];

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
	temp += jws->map.len[LJWE_IV];
	*temp_len -= jws->map.len[LJWE_IV];

	if (*temp_len < jws->jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len)
		return -1;

	memcpy(temp, jws->map.buf[LJWE_EKEY], jws->map.len[LJWE_EKEY]);
	jws->map.buf[LJWE_EKEY] = (char *)temp;
	/*
	 * don't change jws->map.len[LJWE_EKEY]... it has allocation for up to
	 * jws->jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len bytes now and the length
	 * will be set after the plaintext version is encrypted in-situ
	 */
	temp += jws->jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	*temp_len -= jws->jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	/* we need a b64u encode of the JOSE header as AAD */

	n = lws_jws_base64_enc(jws->map.buf[LJWE_JOSE], jws->map.len[LJWE_JOSE],
			       (char *)jws->map_b64.buf[LJWE_JOSE],
			       jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_notice("%s: failed to encode JOSE hdr\n", __func__);

		return -1;
	}
	jws->map_b64.len[LJWE_JOSE] = n;

	/* Encrypt using the raw CEK (treated as MAC KEY | ENC KEY) */

	n = lws_jwe_encrypt_cbc_hs(jose, jws,
				     (uint8_t *)jws->map.buf[LJWE_EKEY],
				     (uint8_t *)jws->map_b64.buf[LJWE_JOSE],
				     jws->map_b64.len[LJWE_JOSE]);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt_cbc_hs failed\n", __func__);
		return -1;
	}

	if (lws_genrsa_create(&rsactx, jws->jwk->e, jws->context,
			!strcmp(jose->alg->alg,   "RSA-OAEP") ?
					LGRSAM_PKCS1_OAEP_PSS : LGRSAM_PKCS1_1_5,
					LWS_GENHASH_TYPE_UNKNOWN)) {
		lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
			    __func__);
		return -1;
	}

	/* encrypt the CEK using RSA, mbedtls can't handle both in and out are
	 * the EKEY, so copy the unencrypted ekey out temporarily */

	memcpy(ekey, jws->map.buf[LJWE_EKEY], hlen);

	n = lws_genrsa_public_encrypt(&rsactx, (uint8_t *)ekey, hlen,
				      (uint8_t *)jws->map.buf[LJWE_EKEY]);
	lws_genrsa_destroy(&rsactx);
	lws_explicit_bzero(ekey, hlen);
	if (n < 0) {
		lwsl_err("%s: decrypt cek fail\n", __func__);
		return -1;
	}
	jws->map.len[LJWE_EKEY] = n; /* update to encrypted EKEY size */

	/*
	 * We end up with IV, ATAG, set, EKEY encrypted and CTXT is ciphertext,
	 * and b64u version of ATAG in map_b64.
	 */

	return 0;
}

int
lws_jwe_auth_and_decrypt_cbc_hs(struct lws_jose *jose,
					struct lws_jws *jws, uint8_t *enc_cek,
					uint8_t *aad, int aad_len)
{
	int n, hlen = lws_genhmac_size(jose->enc_alg->hmac_type);
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_gencrypto_keyelem el;
	struct lws_genhmac_ctx hmacctx;
	struct lws_genaes_ctx aesctx;
	uint8_t al[8];

	/* Some sanity checks on what came in */

	if (jws->map.len[LJWE_ATAG] != hlen / 2) {
		lwsl_notice("%s: expected tag len %d, got %d\n", __func__,
				hlen / 2, jws->map.len[LJWE_ATAG]);
		return -1;
	}

	if (jws->map.len[LJWE_IV] != 16) {
		lwsl_notice("expected iv len %d, got %d\n", 16,
				jws->map.len[LJWE_IV]);
		return -1;
	}

	/* Prepare to check authentication
	 *
	 * AAD is the b64 JOSE header.
	 *
	 * The octet string AL, which is the number of bits in AAD expressed as
	 * a big-endian 64-bit unsigned integer is:
	 *
	 * [0, 0, 0, 0, 0, 0, 1, 152]
	 *
	 * Concatenate the AAD, the Initialization Vector, the ciphertext, and
	 * the AL value.
	 *
	 */

	lws_jwe_be64(aad_len * 8, al);

	/* first half of enc_cek is the MAC key */
	if (lws_genhmac_init(&hmacctx, jose->enc_alg->hmac_type, enc_cek,
			     hlen / 2))
		return -1;

	if (lws_genhmac_update(&hmacctx, aad, aad_len) ||
	    lws_genhmac_update(&hmacctx, (uint8_t *)jws->map.buf[LJWE_IV],
					 jws->map.len[LJWE_IV]) ||
	    lws_genhmac_update(&hmacctx, (uint8_t *)jws->map.buf[LJWE_CTXT],
				         jws->map.len[LJWE_CTXT]) ||
	    lws_genhmac_update(&hmacctx, al, 8)) {
		lwsl_err("%s: hmac computation failed\n", __func__);
		lws_genhmac_destroy(&hmacctx, NULL);
		return -1;
	}

	if (lws_genhmac_destroy(&hmacctx, digest)) {
		lwsl_err("%s: problem destroying hmac\n", __func__);
		return -1;
	}

	/* first half of digest is the auth tag */

	if (lws_timingsafe_bcmp(digest, jws->map.buf[LJWE_ATAG], hlen / 2)) {
		lwsl_err("%s: auth failed: hmac tag != ATAG\n", __func__);
		lwsl_hexdump_notice(jws->map.buf[LJWE_ATAG], hlen / 2);
		lwsl_hexdump_notice(digest, 16);
		return -1;
	}

	/* second half of enc cek is the CEK KEY */
	el.buf = enc_cek + (hlen / 2);
	el.len = hlen / 2;

	if (lws_genaes_create(&aesctx, LWS_GAESO_DEC, LWS_GAESM_CBC,
			      &el, LWS_GAESP_NO_PADDING, NULL)) {
		lwsl_err("%s: lws_genaes_create failed\n", __func__);

		return -1;
	}

	n = lws_genaes_crypt(&aesctx, (uint8_t *)jws->map.buf[LJWE_CTXT],
			     jws->map.len[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_CTXT],
			     (uint8_t *)jws->map.buf[LJWE_IV], NULL, NULL, 16);
	n |= lws_genaes_destroy(&aesctx, NULL, 0);
	if (n) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		return -1;
	}

	return jws->map.len[LJWE_CTXT];
}

int
lws_jwe_auth_and_decrypt_rsa_aes_cbc_hs(struct lws_jose *jose,
						struct lws_jws *jws)
{
	int n;
	struct lws_genrsa_ctx rsactx;
	uint8_t enc_cek[512];

	if (jws->jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jws->jwk->kty);

		return -1;
	}

	if (jws->map.len[LJWE_EKEY] < 40) {
		lwsl_err("%s: EKEY length too short %d\n", __func__,
				jws->map.len[LJWE_EKEY]);

		return -1;
	}

	/* Decrypt the JWE Encrypted Key to get the raw MAC || CEK */

	if (lws_genrsa_create(&rsactx, jws->jwk->e, jws->context,
			!strcmp(jose->alg->alg,   "RSA-OAEP") ?
				LGRSAM_PKCS1_OAEP_PSS : LGRSAM_PKCS1_1_5,
				LWS_GENHASH_TYPE_UNKNOWN)) {
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
