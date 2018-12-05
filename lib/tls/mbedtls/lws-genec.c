/*
 * libwebsockets - generic EC api hiding the backend - mbedtls implementation
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
#include "tls/mbedtls/private.h"

const struct lws_ec_curves lws_ec_curves[] = {
	/*
	 * These are the curves we are willing to use by default...
	 *
	 * The 3 recommended+ (P-256) and optional curves in RFC7518 7.6
	 *
	 * Specific keys lengths from RFC8422 p20
	 */
	{ "P-256", MBEDTLS_ECP_DP_SECP256R1, 32 },
	{ "P-384", MBEDTLS_ECP_DP_SECP384R1, 48 },
	{ "P-521", MBEDTLS_ECP_DP_SECP521R1, 66 },

	{ NULL, 0, 0 }
};

static int
lws_genec_keypair_import(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
			 struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	mbedtls_ecp_keypair kp;
	int ret = -1;

	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].len < 4) {
		lwsl_notice("%s: crv '%s' (%d)\n", __func__,
			    el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf ?
				    (char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf :
					    "null",
			    el[LWS_GENCRYPTO_EC_KEYEL_CRV].len);
		return -21;
	}

	curve = lws_genec_curve(ctx->curve_table,
				(char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (!curve)
		return -22;

	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len != curve->key_bytes ||
	    el[LWS_GENCRYPTO_EC_KEYEL_X].len != curve->key_bytes ||
	    el[LWS_GENCRYPTO_EC_KEYEL_Y].len != curve->key_bytes)
		return -23;

	mbedtls_ecp_keypair_init(&kp);
	if (mbedtls_ecp_group_load(&kp.grp, curve->tls_lib_nid))
		goto bail1;

	/* d (the private key) is directly an mpi */

	if (mbedtls_mpi_read_binary(&kp.d, el[LWS_GENCRYPTO_EC_KEYEL_D].buf,
				    el[LWS_GENCRYPTO_EC_KEYEL_D].len))
		goto bail1;

	mbedtls_ecp_set_zero(&kp.Q);

	if (mbedtls_mpi_read_binary(&kp.Q.X, el[LWS_GENCRYPTO_EC_KEYEL_X].buf,
				    el[LWS_GENCRYPTO_EC_KEYEL_X].len))
		goto bail1;

	if (mbedtls_mpi_read_binary(&kp.Q.Y, el[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
				    el[LWS_GENCRYPTO_EC_KEYEL_Y].len))
		goto bail1;

	switch (ctx->genec_alg) {
	case LEGENEC_ECDH:
		if (mbedtls_ecdh_get_params(ctx->u.ctx_ecdh, &kp, side))
			goto bail1;
		break;
	case LEGENEC_ECDSA:
		if (mbedtls_ecdsa_from_keypair(ctx->u.ctx_ecdsa, &kp))
			goto bail1;
		break;
	default:
		goto bail1;
	}

	ret = 0;

bail1:
	mbedtls_ecp_keypair_free(&kp);

	return ret;
}

LWS_VISIBLE int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDH;

	ctx->u.ctx_ecdh = lws_zalloc(sizeof(*ctx->u.ctx_ecdh), "genecdh");
	if (!ctx->u.ctx_ecdh)
		return 1;

	mbedtls_ecdh_init(ctx->u.ctx_ecdh);

	return 0;
}

LWS_VISIBLE int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDSA;

	ctx->u.ctx_ecdh = lws_zalloc(sizeof(*ctx->u.ctx_ecdh), "genecdh");
	if (!ctx->u.ctx_ecdh)
		return 1;

	mbedtls_ecdh_init(ctx->u.ctx_ecdh);

	return 0;
}


LWS_VISIBLE int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	if (ctx->genec_alg != LEGENEC_ECDH)
		return -1;

	return lws_genec_keypair_import(ctx, side, el);
}

LWS_VISIBLE int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	return lws_genec_keypair_import(ctx, 0, el);
}

LWS_VISIBLE void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	switch (ctx->genec_alg) {
	case LEGENEC_ECDH:
		if (ctx->u.ctx_ecdh) {
			mbedtls_ecdh_free(ctx->u.ctx_ecdh);
			lws_free(ctx->u.ctx_ecdh);
			ctx->u.ctx_ecdh = NULL;
		}
		break;
	case LEGENEC_ECDSA:
		if (ctx->u.ctx_ecdsa) {
			mbedtls_ecdsa_free(ctx->u.ctx_ecdsa);
			lws_free(ctx->u.ctx_ecdsa);
			ctx->u.ctx_ecdsa = NULL;
		}
		break;
	default:
		break;
	}
}

LWS_VISIBLE int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
			const char *curve_name,
			struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	mbedtls_ecdsa_context ecdsa;
	mbedtls_ecp_keypair *kp;
	mbedtls_mpi *mpi[3];
	int n;

	if (ctx->genec_alg != LEGENEC_ECDH)
		return -1;

	curve = lws_genec_curve(ctx->curve_table, curve_name);
	if (!curve) {
		lwsl_err("%s: curve '%s' not supported\n",
			 __func__, curve_name);

		return -22;
	}

	mbedtls_ecdsa_init(&ecdsa);
	n = mbedtls_ecdsa_genkey(&ecdsa, curve->tls_lib_nid, lws_gencrypto_mbedtls_rngf,
				 ctx->context);
	if (n) {
		lwsl_err("mbedtls_ecdsa_genkey failed 0x%x\n", -n);
		goto bail1;
	}

	kp = (mbedtls_ecp_keypair *)&ecdsa;

	n = mbedtls_ecdh_get_params(ctx->u.ctx_ecdh, kp, side);
	if (n) {
		lwsl_err("mbedtls_ecdh_get_params failed 0x%x\n", -n);
		goto bail1;
	}

	/*
	 * we need to capture the individual element BIGNUMs into
	 * lws_gencrypto_keyelem, so they can be serialized, used in jwk etc
	 */

	mpi[0] = &kp->Q.X;
	mpi[1] = &kp->d;
	mpi[2] = &kp->Q.Y;

	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = strlen(curve_name) + 1;
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf =
			lws_malloc(el[LWS_GENCRYPTO_EC_KEYEL_CRV].len, "ec");
	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
		goto bail1;
	strcpy((char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name);

	for (n = LWS_GENCRYPTO_EC_KEYEL_X; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++) {
		el[n].len = curve->key_bytes;
		el[n].buf = lws_malloc(curve->key_bytes, "ec");
		if (!el[n].buf)
			goto bail2;

		if (mbedtls_mpi_write_binary(mpi[n - 1], el[n].buf,
					     curve->key_bytes))
			goto bail2;
	}

	mbedtls_ecdsa_free(&ecdsa);

	return 0;

bail2:
	for (n = 0; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
bail1:
	mbedtls_ecdsa_free(&ecdsa);

	lws_free_set_NULL(ctx->u.ctx_ecdh);

	return -1;
}

LWS_VISIBLE int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	mbedtls_ecp_keypair *kp;
	mbedtls_mpi *mpi[3];
	int n;

	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	curve = lws_genec_curve(ctx->curve_table, curve_name);
	if (!curve) {
		lwsl_err("%s: curve '%s' not supported\n",
			 __func__, curve_name);

		return -22;
	}

	mbedtls_ecdsa_init(ctx->u.ctx_ecdsa);
	n = mbedtls_ecdsa_genkey(ctx->u.ctx_ecdsa, curve->tls_lib_nid,
				 lws_gencrypto_mbedtls_rngf, ctx->context);
	if (n) {
		lwsl_err("mbedtls_ecdsa_genkey failed 0x%x\n", -n);
		goto bail1;
	}

	/*
	 * we need to capture the individual element BIGNUMs into
	 * lws_gencrypto_keyelems, so they can be serialized, used in jwk etc
	 */

	kp = (mbedtls_ecp_keypair *)&ctx->u.ctx_ecdsa;

	mpi[0] = &kp->Q.X;
	mpi[1] = &kp->d;
	mpi[2] = &kp->Q.Y;

	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = strlen(curve_name) + 1;
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf =
			lws_malloc(el[LWS_GENCRYPTO_EC_KEYEL_CRV].len, "ec");
	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
		goto bail1;
	strcpy((char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name);

	for (n = LWS_GENCRYPTO_EC_KEYEL_X; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++) {
		el[n].len = curve->key_bytes;
		el[n].buf = lws_malloc(curve->key_bytes, "ec");
		if (!el[n].buf)
			goto bail2;

		if (mbedtls_mpi_write_binary(mpi[n - 1], el[n].buf,
					     curve->key_bytes))
			goto bail2;
	}

	return 0;

bail2:
	for (n = 0; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
bail1:

	lws_free_set_NULL(ctx->u.ctx_ecdsa);

	return -1;
}

LWS_VISIBLE LWS_EXTERN int
lws_genecdsa_hash_sign(struct lws_genec_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type,
		       uint8_t *sig, size_t sig_len)
{
	mbedtls_md_type_t md_type =
			lws_gencrypto_mbedtls_hash_to_MD_TYPE(hash_type);
	size_t slen = sig_len;
	int n;

	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	if (md_type < 0)
		return -2;


	n = mbedtls_ecdsa_write_signature(ctx->u.ctx_ecdsa, md_type, in,
					  lws_genhash_size(hash_type), sig,
					  &slen, lws_gencrypto_mbedtls_rngf,
					  ctx->context);
	if (n) {
		lwsl_err("%s: mbedtls_ecdsa_write_signature failed: -0x%x\n",
			 __func__, -n);

		goto bail;
	}

	return (int)slen;
bail:

	return -3;
}

LWS_VISIBLE LWS_EXTERN int
lws_genecdsa_hash_sig_verify(struct lws_genec_ctx *ctx, const uint8_t *in,
			     enum lws_genhash_types hash_type,
			     const uint8_t *sig, size_t sig_len)
{
	mbedtls_md_type_t md_type =
			lws_gencrypto_mbedtls_hash_to_MD_TYPE(hash_type);
	int n;

	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	if (md_type < 0)
		return -2;

	n = mbedtls_ecdsa_read_signature(ctx->u.ctx_ecdsa, in,
					 lws_genhash_size(hash_type), sig,
					 sig_len);
	if (n) {
		lwsl_err("%s: mbedtls_ecdsa_write_signature failed: -0x%x\n",
			 __func__, -n);

		goto bail;
	}

	return 0;
bail:

	return -3;
}

#if 0
LWS_VISIBLE int
lws_genec_public_decrypt(struct lws_genec_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	size_t olen = 0;
	int n;

	ctx->ctx->len = in_len;
	n = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(ctx->ctx, NULL, NULL,
						MBEDTLS_RSA_PUBLIC,
						&olen, in, out, out_max);
	if (n) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return olen;
}

LWS_VISIBLE int
lws_genec_public_encrypt(struct lws_genec_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	int n;

	//ctx->ctx->len = in_len; // ???
	ctx->ctx->padding = MBEDTLS_RSA_PKCS_V15;
	n = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(ctx->ctx, _rngf, ctx->context,
						MBEDTLS_RSA_PRIVATE,
						in_len, in, out);
	if (n) {
		lwsl_notice("%s: -0x%x: in_len: %d\n", __func__, -n,
				(int)in_len);

		return -1;
	}

	return 0;
}


LWS_VISIBLE int
lws_genec_render_pkey_asn1(struct lws_genec_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	uint8_t *p = pkey_asn1, *totlen, *end = pkey_asn1 + pkey_asn1_len - 1;
	mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT] = {
		&ctx->ctx->N, &ctx->ctx->E, &ctx->ctx->D, &ctx->ctx->P,
		&ctx->ctx->Q, &ctx->ctx->DP, &ctx->ctx->DQ,
		&ctx->ctx->QP,
	};
	int n;

	/* 30 82  - sequence
	 *   09 29  <-- length(0x0929) less 4 bytes
	 * 02 01 <- length (1)
	 *  00
	 * 02 82
	 *  02 01 <- length (513)  N
	 *  ...
	 *
	 *  02 03 <- length (3) E
	 *    01 00 01
	 *
	 * 02 82
	 *   02 00 <- length (512) D P Q EXP1 EXP2 COEFF
	 *
	 *  */

	*p++ = 0x30;
	*p++ = 0x82;
	totlen = p;
	p += 2;

	*p++ = 0x02;
	*p++ = 0x01;
	*p++ = 0x00;

	for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++) {
		int m = mbedtls_mpi_size(mpi[n]);
		uint8_t *elen;

		*p++ = 0x02;
		elen = p;
		if (m < 0x7f)
			*p++ = m;
		else {
			*p++ = 0x82;
			*p++ = m >> 8;
			*p++ = m & 0xff;
		}

		if (p + m > end)
			return -1;

		mbedtls_mpi_write_binary(mpi[n], p, m);
		if (p[0] & 0x80) {
			p[0] = 0x00;
			mbedtls_mpi_write_binary(mpi[n], &p[1], m);
			m++;
		}
		if (m < 0x7f)
			*elen = m;
		else {
			*elen++ = 0x82;
			*elen++ = m >> 8;
			*elen = m & 0xff;
		}
		p += m;
	}

	n = lws_ptr_diff(p, pkey_asn1);

	*totlen++ = (n - 4) >> 8;
	*totlen = (n - 4) & 0xff;

	return n;
}
#endif
