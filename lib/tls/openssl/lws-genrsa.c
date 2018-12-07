/*
 * libwebsockets - generic RSA api hiding the backend
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
 *  lws_genrsa provides an RSA abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls hash functions underneath.
 */
#include "core/private.h"

LWS_VISIBLE void
lws_jwk_destroy_genrsa_elements(struct lws_jwk_elements *el)
{
	int n;

	for (n = 0; n < LWS_COUNT_RSA_KEY_ELEMENTS; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
}

static int mode_map_crypt[] = { RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING },
	   mode_map_sig[]   = { RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING };

static int
rsa_pkey_wrap(struct lws_genrsa_ctx *ctx, RSA *rsa)
{
	EVP_PKEY *pkey;

	/* we have the RSA object filled up... wrap in a PKEY */

	pkey = EVP_PKEY_new();
	if (!pkey)
		return 1;

	/* bind the PKEY to the RSA key we just prepared */

	if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
		lwsl_err("%s: EVP_PKEY_assign_RSA_KEY failed\n", __func__);
		goto bail;
	}

	/* pepare our PKEY_CTX with the PKEY */

	ctx->ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);
	pkey = NULL;
	if (!ctx->ctx)
		goto bail;

	return 0;

bail:
	if (pkey)
		EVP_PKEY_free(pkey);

	return 1;
}

LWS_VISIBLE int
lws_genrsa_create(struct lws_genrsa_ctx *ctx, struct lws_jwk_elements *el,
		  struct lws_context *context, enum enum_genrsa_mode mode)
{
	int n;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	/* Step 1:
	 *
	 * convert the MPI for e and n to OpenSSL BIGNUMs
	 */

	for (n = 0; n < 5; n++) {
		ctx->bn[n] = BN_bin2bn(el[n].buf, el[n].len, NULL);
		if (!ctx->bn[n]) {
			lwsl_notice("mpi load failed\n");
			goto bail;
		}
	}

	/* Step 2:
	 *
	 * assemble the OpenSSL RSA from the BIGNUMs
	 */

	ctx->rsa = RSA_new();
	if (!ctx->rsa) {
		lwsl_notice("Failed to create RSA\n");
		goto bail;
	}

#if defined(LWS_HAVE_RSA_SET0_KEY)
	if (RSA_set0_key(ctx->rsa, ctx->bn[JWK_RSA_KEYEL_N],
			 ctx->bn[JWK_RSA_KEYEL_E],
			 ctx->bn[JWK_RSA_KEYEL_D]) != 1) {
		lwsl_notice("RSA_set0_key failed\n");
		goto bail;
	}
	RSA_set0_factors(ctx->rsa, ctx->bn[JWK_RSA_KEYEL_P],
				   ctx->bn[JWK_RSA_KEYEL_Q]);
#else
	ctx->rsa->e = ctx->bn[JWK_RSA_KEYEL_E];
	ctx->rsa->n = ctx->bn[JWK_RSA_KEYEL_N];
	ctx->rsa->d = ctx->bn[JWK_RSA_KEYEL_D];
	ctx->rsa->p = ctx->bn[JWK_RSA_KEYEL_P];
	ctx->rsa->q = ctx->bn[JWK_RSA_KEYEL_Q];
#endif

	if (!rsa_pkey_wrap(ctx, ctx->rsa))
		return 0;

bail:
	for (n = 0; n < 5; n++)
		if (ctx->bn[n]) {
			BN_free(ctx->bn[n]);
			ctx->bn[n] = NULL;
		}

	if (ctx->rsa) {
		RSA_free(ctx->rsa);
		ctx->rsa = NULL;
	}

	return 1;
}

LWS_VISIBLE int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_jwk_elements *el,
		       int bits)
{
	BIGNUM *bn;
	int n;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	ctx->rsa = RSA_new();
	if (!ctx->rsa) {
		lwsl_notice("Failed to create RSA\n");
		return -1;
	}

	bn = BN_new();
	if (!bn)
		goto cleanup_1;
	if (BN_set_word(bn, RSA_F4) != 1) {
		BN_free(bn);
		goto cleanup_1;
	}

	n = RSA_generate_key_ex(ctx->rsa, bits, bn, NULL);
	BN_free(bn);
	if (n != 1)
		goto cleanup_1;

#if defined(LWS_HAVE_RSA_SET0_KEY)
	{
		const BIGNUM *mpi[5];

		RSA_get0_key(ctx->rsa, &mpi[JWK_RSA_KEYEL_N],
			     &mpi[JWK_RSA_KEYEL_E], &mpi[JWK_RSA_KEYEL_D]);
		RSA_get0_factors(ctx->rsa, &mpi[JWK_RSA_KEYEL_P],
				 &mpi[JWK_RSA_KEYEL_Q]);
#else
	{
		BIGNUM *mpi[5] = { ctx->rsa->n, ctx->rsa->e, ctx->rsa->d,
				   ctx->rsa->p, ctx->rsa->q, };
#endif
		for (n = 0; n < 5; n++)
			if (BN_num_bytes(mpi[n])) {
				el[n].buf = lws_malloc(
					BN_num_bytes(mpi[n]), "genrsakey");
				if (!el[n].buf)
					goto cleanup;
				el[n].len = BN_num_bytes(mpi[n]);
				BN_bn2bin(mpi[n], el[n].buf);
			}
	}

	if (!rsa_pkey_wrap(ctx, ctx->rsa))
		return 0;

cleanup:
	for (n = 0; n < LWS_COUNT_RSA_KEY_ELEMENTS; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
cleanup_1:
	RSA_free(ctx->rsa);
	ctx->rsa = NULL;

	return -1;
}

/*
 * in_len must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5
 * based padding modes
 */

LWS_VISIBLE int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	if (RSA_public_encrypt((int)in_len, in, out, ctx->rsa,
			       mode_map_crypt[ctx->mode]) < 0) {
		lwsl_err("%s: RSA_public_encrypt failed\n", __func__);
		lws_tls_err_describe();
		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	if (RSA_public_decrypt((int)in_len, in, out, ctx->rsa,
			       mode_map_crypt[ctx->mode]) < 0) {
		lwsl_err("%s: RSA_public_decrypt failed\n", __func__);
		return -1;
	}

	return 0;
}

static int
lws_genrsa_genrsa_hash_to_NID(enum lws_genhash_types hash_type)
{
	int h = -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1:
		h = NID_sha1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		h = NID_sha256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		h = NID_sha384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		h = NID_sha512;
		break;
	}

	return h;
}

static const EVP_MD *
lws_genrsa_genrsa_hash_to_EVP_MD(enum lws_genhash_types hash_type)
{
	const EVP_MD *h = NULL;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1:
		h = EVP_sha1();
		break;
	case LWS_GENHASH_TYPE_SHA256:
		h = EVP_sha256();
		break;
	case LWS_GENHASH_TYPE_SHA384:
		h = EVP_sha384();
		break;
	case LWS_GENHASH_TYPE_SHA512:
		h = EVP_sha512();
		break;
	}

	return h;
}


LWS_VISIBLE int
lws_genrsa_public_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	int n = lws_genrsa_genrsa_hash_to_NID(hash_type),
	    h = (int)lws_genhash_size(hash_type);
	const EVP_MD *md = NULL;

	if (n < 0)
		return -1;

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		n = RSA_verify(n, in, h, (uint8_t *)sig, (int)sig_len, ctx->rsa);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		md = lws_genrsa_genrsa_hash_to_EVP_MD(hash_type);
		if (!md)
			return -1;

		n = RSA_verify_PKCS1_PSS(ctx->rsa, in, md, (uint8_t *)sig,
					 (int)sig_len);
		break;
	default:
		return -1;
	}

	if (n != 1) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_genrsa_public_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	int n = lws_genrsa_genrsa_hash_to_NID(hash_type),
	    h = (int)lws_genhash_size(hash_type);
	unsigned int used = 0;
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md = NULL;

	if (n < 0)
		return -1;

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		if (RSA_sign(n, in, h, sig, &used, ctx->rsa) != 1) {
			lwsl_err("%s: RSA_sign failed\n", __func__);

			goto bail;
		}
		break;

	case LGRSAM_PKCS1_OAEP_PSS:

		md = lws_genrsa_genrsa_hash_to_EVP_MD(hash_type);
		if (!md)
			return -1;

		if (EVP_PKEY_CTX_set_rsa_padding(ctx->ctx,
						 mode_map_sig[ctx->mode]) != 1) {
			lwsl_err("%s: set_rsa_padding failed\n", __func__);

			goto bail;
		}

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
		break;

	default:
		return -1;
	}

	return used;

bail:
	if (mdctx)
		EVP_MD_CTX_free(mdctx);

	return -1;
}

LWS_VISIBLE void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (!ctx->ctx)
		return;

	EVP_PKEY_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
	ctx->rsa = NULL;
}
