/*
 * libwebsockets - generic EC api hiding the backend - openssl implementation
 *
 * Copyright (C) 2017 - 2018 Andy Green <andy@warmcat.com>
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
 *  lws_genec provides an EC abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls crypto functions underneath.
 */
#include "core/private.h"
#include "tls/openssl/private.h"

const struct lws_ec_curves lws_ec_curves[] = {
	/*
	 * These are the curves we are willing to use by default...
	 *
	 * The 3 recommended+ (P-256) and optional curves in RFC7518 7.6
	 *
	 * Specific keys lengths from RFC8422 p20
	 */
	{ "P-256", NID_X9_62_prime256v1, 32 },
	{ "P-384", NID_secp384r1,	 48 },
	{ "P-521", NID_secp521r1,	 66 },

	{ NULL, 0, 0 }
};

static int
lws_genec_eckey_import(int nid, EVP_PKEY *pkey, struct lws_gencrypto_keyelem *el)
{
	EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
	BIGNUM *bn_d, *bn_x, *bn_y;
	int n;

	if (!ec)
		return -1;

	/*
	 * EC_KEY contains
	 *
	 * EC_GROUP * 	group
	 * EC_POINT * 	pub_key
	 * BIGNUM * 	priv_key  (ie, d)
	 */

	bn_x = BN_bin2bn(el[LWS_GENCRYPTO_EC_KEYEL_X].buf,
			 el[LWS_GENCRYPTO_EC_KEYEL_X].len, NULL);
	if (!bn_x) {
		lwsl_err("%s: BN_bin2bn (x) fail\n", __func__);
		goto bail;
	}
	bn_y = BN_bin2bn(el[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
			 el[LWS_GENCRYPTO_EC_KEYEL_Y].len, NULL);
	if (!bn_y) {
		lwsl_err("%s: BN_bin2bn (y) fail\n", __func__);
		goto bail1;
	}

	n = EC_KEY_set_public_key_affine_coordinates(ec, bn_x, bn_y);
	BN_free(bn_x);
	BN_free(bn_y);
	if (n != 1) {
		lwsl_err("%s: EC_KEY_set_public_key_affine_coordinates fail:\n",
			 __func__);
		lws_tls_err_describe();
		goto bail;
	}

	bn_d = BN_bin2bn(el[LWS_GENCRYPTO_EC_KEYEL_D].buf,
			 el[LWS_GENCRYPTO_EC_KEYEL_D].len, NULL);
	if (!bn_d) {
		lwsl_err("%s: BN_bin2bn (d) fail\n", __func__);
		goto bail;
	}

	n = EC_KEY_set_private_key(ec, bn_d);
	BN_free(bn_d);
	if (n != 1) {
		lwsl_err("%s: EC_KEY_set_private_key fail\n", __func__);
		goto bail;
	}

	if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
		lwsl_err("%s: EVP_PKEY_set1_EC_KEY failed\n", __func__);
		goto bail;
	}

	return 0;

bail1:
	BN_free(bn_x);
bail:
	EC_KEY_free(ec);

	return -1;
}

static int
lws_genec_keypair_import(const struct lws_ec_curves *curve_table,
			 EVP_PKEY_CTX **pctx, struct lws_gencrypto_keyelem *el)
{
	EVP_PKEY *pkey = NULL;
	const struct lws_ec_curves *curve;

	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].len < 4)
		return -2;

	curve = lws_genec_curve(curve_table,
				(char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (!curve)
		return -3;

	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len != curve->key_bytes ||
	    el[LWS_GENCRYPTO_EC_KEYEL_X].len != curve->key_bytes ||
	    el[LWS_GENCRYPTO_EC_KEYEL_Y].len != curve->key_bytes)
		return -4;

	pkey = EVP_PKEY_new();
	if (!pkey)
		return -7;

	if (lws_genec_eckey_import(curve->tls_lib_nid, pkey, el)) {
		lwsl_err("%s: lws_genec_eckey_import fail\n", __func__);
		goto bail;
	}

	*pctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);
	pkey = NULL;
	if (!*pctx)
		goto bail;

	return 0;

bail:
	if (pkey)
		EVP_PKEY_free(pkey);

	if (*pctx) {
		EVP_PKEY_CTX_free(*pctx);
		*pctx = NULL;
	}

	return -9;
}

LWS_VISIBLE int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->ctx = NULL;
	ctx->ctx_peer = NULL;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDH;

	return 0;
}

LWS_VISIBLE int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->ctx = NULL;
	ctx->ctx_peer = NULL;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDSA;

	return 0;
}

LWS_VISIBLE int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	if (ctx->genec_alg != LEGENEC_ECDH)
		return -1;

	return lws_genec_keypair_import(ctx->curve_table,
					side ? &ctx->ctx : &ctx->ctx_peer, el);
}

LWS_VISIBLE int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	return lws_genec_keypair_import(ctx->curve_table, &ctx->ctx, el);
}

static void
lws_genec_keypair_destroy(EVP_PKEY_CTX **pctx)
{
	if (!*pctx)
		return;
	EVP_PKEY_CTX_free(*pctx);
	*pctx = NULL;
}

LWS_VISIBLE void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (ctx->ctx)
		lws_genec_keypair_destroy(&ctx->ctx);
	if (ctx->ctx_peer)
		lws_genec_keypair_destroy(&ctx->ctx_peer);
}

static int
lws_genec_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
		      const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	const EC_POINT *pubkey;
	EVP_PKEY *pkey = NULL;
	int ret = -29, n, m;
	BIGNUM *bn[3];
	EC_KEY *ec;

	if (ctx->genec_alg != LEGENEC_ECDH)
		return -1;

	curve = lws_genec_curve(ctx->curve_table, curve_name);
	if (!curve) {
		lwsl_err("%s: curve '%s' not supported\n",
			 __func__, curve_name);

		return -22;
	}

	ec = EC_KEY_new_by_curve_name(curve->tls_lib_nid);
	if (!ec)
		return -23;

	if (EC_KEY_generate_key(ec) != 1)
		goto bail;

	pkey = EVP_PKEY_new();
	if (!pkey)
		goto bail;

	if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
		lwsl_err("%s: EVP_PKEY_assign_EC_KEY failed\n", __func__);
		goto bail1;
	}

	ctx->ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx->ctx) {
		lwsl_err("%s: EVP_PKEY_CTX_new failed\n", __func__);
		goto bail1;
	}

	/*
	 * we need to capture the individual element BIGNUMs into
	 * lws_gencrypto_keyelem, so they can be serialized, used in jwk etc
	 */

	pubkey = EC_KEY_get0_public_key(ec);
	if (!pubkey)
		goto bail1;

	bn[0] = BN_new();
	bn[1] = (BIGNUM *)EC_KEY_get0_private_key(ec);
	bn[2] = BN_new();

	if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(ec),
		        pubkey, bn[0], bn[2], NULL) != 1) {
		lwsl_err("%s: EC_POINT_get_affine_coordinates_GFp failed\n",
			 __func__);
		goto bail2;
	}

	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = strlen(curve_name) + 1;
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf =
			lws_malloc(el[LWS_GENCRYPTO_EC_KEYEL_CRV].len, "ec");
	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
		goto bail2;

	strcpy((char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name);

	for (n = LWS_GENCRYPTO_EC_KEYEL_X; n < LWS_GENCRYPTO_EC_KEYEL_COUNT;
	     n++) {
		el[n].len = curve->key_bytes;
		el[n].buf = lws_malloc(curve->key_bytes, "ec");
		if (!el[n].buf)
			goto bail2;

		m = BN_bn2bin(bn[n - 1], el[n].buf);
		if (m != el[n].len)
			goto bail2;
	}

	ret = 0;

bail2:
	BN_free(bn[0]);
	BN_free(bn[2]);
bail1:
	EVP_PKEY_free(pkey);
bail:
	EC_KEY_free(ec);

	return ret;
}

LWS_VISIBLE int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
			const char *curve_name,
			struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDH)
		return -1;

	return lws_genec_new_keypair(ctx, side, curve_name, el);
}

LWS_VISIBLE int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	return lws_genec_new_keypair(ctx, LDHS_OURS, curve_name, el);
}

LWS_VISIBLE LWS_EXTERN int
lws_genecdsa_hash_sign(struct lws_genec_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type,
		       uint8_t *sig, size_t sig_len)
{
	const EVP_MD *md = lws_gencrypto_openssl_hash_to_EVP_MD(hash_type);
	EVP_MD_CTX *mdctx = NULL;

	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	if (!md)
		return -1;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto bail;

	if (EVP_DigestSignInit(mdctx, NULL, md, NULL,
			       EVP_PKEY_CTX_get0_pkey(ctx->ctx))) {
		lwsl_err("%s: EVP_DigestSignInit failed\n", __func__);

		goto bail;
	}
	if (EVP_DigestSignUpdate(mdctx, in, EVP_MD_size(md))) {
		lwsl_err("%s: EVP_DigestSignUpdate failed\n", __func__);

		goto bail;
	}
	if (EVP_DigestSignFinal(mdctx, sig, &sig_len)) {
		lwsl_err("%s: EVP_DigestSignFinal failed\n", __func__);

		goto bail;
	}

	EVP_MD_CTX_free(mdctx);

	return (int)sig_len;
bail:
	if (mdctx)
		EVP_MD_CTX_free(mdctx);

	return -1;
}

LWS_VISIBLE LWS_EXTERN int
lws_genecdsa_hash_sig_verify(struct lws_genec_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type,
			   const uint8_t *sig, size_t sig_len)
{
	const EVP_MD *md = lws_gencrypto_openssl_hash_to_EVP_MD(hash_type);
	EVP_MD_CTX *mdctx = NULL;
	int ret = -1;

	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	if (!md)
		return -1;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto bail;

	if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL,
			       EVP_PKEY_CTX_get0_pkey(ctx->ctx))) {
		lwsl_err("%s: EVP_DigestSignInit failed\n", __func__);

		goto bail;
	}
	if (EVP_DigestVerifyUpdate(mdctx, in, EVP_MD_size(md))) {
		lwsl_err("%s: EVP_DigestSignUpdate failed\n", __func__);

		goto bail;
	}
	if (EVP_DigestVerifyFinal(mdctx, sig, sig_len)) {
		lwsl_err("%s: EVP_DigestSignFinal failed\n", __func__);

		goto bail;
	}

	ret = 0;
bail:
	if (mdctx)
		EVP_MD_CTX_free(mdctx);

	return ret;
}
