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
 * JWE code for payload encrypt / decrypt using aescbc
 *
 */
#include "core/private.h"
#include "jose/jwe/private.h"

int
lws_jwe_encrypt_cbc_hs(struct lws_jwe *jwe, uint8_t *cek,
		       uint8_t *aad, int aad_len)
{
	int n, hlen = lws_genhmac_size(jwe->jose.enc_alg->hmac_type);
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_gencrypto_keyelem el;
	struct lws_genhmac_ctx hmacctx;
	struct lws_genaes_ctx aesctx;
	uint8_t al[8];

	/* Caller must have prepared space for the results */

	if (jwe->jws.map.len[LJWE_ATAG] != (unsigned int)hlen / 2) {
		lwsl_notice("%s: expected tag len %d, got %d\n", __func__,
			    hlen / 2, jwe->jws.map.len[LJWE_ATAG]);
		return -1;
	}

	if (jwe->jws.map.len[LJWE_IV] != 16) {
		lwsl_notice("expected iv len %d, got %d\n", 16,
				jwe->jws.map.len[LJWE_IV]);
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
	lws_get_random(jwe->jws.context, (void *)jwe->jws.map.buf[LJWE_IV], 16);

	/*
	 *  3.  The plaintext is CBC encrypted using PKCS #7 padding using
	 *      ENC_KEY as the key and the IV.  We denote the ciphertext output
	 *      from this step as E.
	 */

	/* second half is the AES ENC_KEY */
	el.buf = cek + (hlen / 2);
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
	n = lws_genaes_crypt(&aesctx, (uint8_t *)jwe->jws.map.buf[LJWE_CTXT],
			     jwe->jws.map.len[LJWE_CTXT],
			     (uint8_t *)jwe->jws.map.buf[LJWE_CTXT],
			     (uint8_t *)jwe->jws.map.buf[LJWE_IV],
			     NULL, NULL, 16);
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
	if (lws_genhmac_init(&hmacctx, jwe->jose.enc_alg->hmac_type,
				cek, hlen / 2))
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
	    lws_genhmac_update(&hmacctx, jwe->jws.map.buf[LJWE_IV],
			       LWS_JWE_AES_IV_BYTES) ||
	    /* since we encrypted it, this is the ciphertext */
	    lws_genhmac_update(&hmacctx,
			       (uint8_t *)jwe->jws.map.buf[LJWE_CTXT],
				          jwe->jws.map.len[LJWE_CTXT]) ||
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
	memcpy((void *)jwe->jws.map.buf[LJWE_ATAG], digest, hlen / 2);

	return jwe->jws.map.len[LJWE_CTXT];
}

int
lws_jwe_auth_and_decrypt_cbc_hs(struct lws_jwe *jwe, uint8_t *enc_cek,
				uint8_t *aad, int aad_len)
{
	int n, hlen = lws_genhmac_size(jwe->jose.enc_alg->hmac_type);
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_gencrypto_keyelem el;
	struct lws_genhmac_ctx hmacctx;
	struct lws_genaes_ctx aesctx;
	uint8_t al[8];

	/* Some sanity checks on what came in */

	if (jwe->jws.map.len[LJWE_ATAG] != (unsigned int)hlen / 2) {
		lwsl_notice("%s: expected tag len %d, got %d\n", __func__,
				hlen / 2, jwe->jws.map.len[LJWE_ATAG]);
		return -1;
	}

	if (jwe->jws.map.len[LJWE_IV] != 16) {
		lwsl_notice("expected iv len %d, got %d\n", 16,
				jwe->jws.map.len[LJWE_IV]);
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
	if (lws_genhmac_init(&hmacctx, jwe->jose.enc_alg->hmac_type, enc_cek,
			     hlen / 2)) {
		lwsl_err("%s: lws_genhmac_init fail\n", __func__);
		return -1;
	}

	if (lws_genhmac_update(&hmacctx, aad, aad_len) ||
	    lws_genhmac_update(&hmacctx, (uint8_t *)jwe->jws.map.buf[LJWE_IV],
					 jwe->jws.map.len[LJWE_IV]) ||
	    lws_genhmac_update(&hmacctx, (uint8_t *)jwe->jws.map.buf[LJWE_CTXT],
				         jwe->jws.map.len[LJWE_CTXT]) ||
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

	if (lws_timingsafe_bcmp(digest, jwe->jws.map.buf[LJWE_ATAG], hlen / 2)) {
		lwsl_err("%s: auth failed: hmac tag (%d) != ATAG (%d)\n",
			 __func__, hlen / 2, jwe->jws.map.len[LJWE_ATAG]);
		lwsl_hexdump_notice(jwe->jws.map.buf[LJWE_ATAG], hlen / 2);
		lwsl_hexdump_notice(digest, hlen / 2);
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

	n = lws_genaes_crypt(&aesctx, (uint8_t *)jwe->jws.map.buf[LJWE_CTXT],
			     jwe->jws.map.len[LJWE_CTXT],
			     (uint8_t *)jwe->jws.map.buf[LJWE_CTXT],
			     (uint8_t *)jwe->jws.map.buf[LJWE_IV], NULL, NULL, 16);
	n |= lws_genaes_destroy(&aesctx, NULL, 0);
	if (n) {
		lwsl_err("%s: lws_genaes_crypt failed\n", __func__);
		return -1;
	}

	return jwe->jws.map.len[LJWE_CTXT];
}

