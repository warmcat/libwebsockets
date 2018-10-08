/*
 * libwebsockets - generic RSA api hiding the backend
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
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
 *  lws_genhash provides a hash / hmac abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls hash functions underneath.
 */
#include "core/private.h"

LWS_VISIBLE void
lws_jwk_destroy_genrsa_elements(struct lws_genrsa_elements *el)
{
	int n;

	for (n = 0; n < LWS_COUNT_RSA_ELEMENTS; n++)
		if (el->e[n].buf)
			lws_free_set_NULL(el->e[n].buf);
}

LWS_VISIBLE int
lws_genrsa_create(struct lws_genrsa_ctx *ctx, struct lws_genrsa_elements *el)
{
	int n;

	memset(ctx, 0, sizeof(*ctx));

	/* Step 1:
	 *
	 * convert the MPI for e and n to OpenSSL BIGNUMs
	 */

	for (n = 0; n < 5; n++) {
		ctx->bn[n] = BN_bin2bn(el->e[n].buf, el->e[n].len, NULL);
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
	if (RSA_set0_key(ctx->rsa, ctx->bn[JWK_KEY_N], ctx->bn[JWK_KEY_E],
			 ctx->bn[JWK_KEY_D]) != 1) {
		lwsl_notice("RSA_set0_key failed\n");
		goto bail;
	}
	RSA_set0_factors(ctx->rsa, ctx->bn[JWK_KEY_P], ctx->bn[JWK_KEY_Q]);
#else
	ctx->rsa->e = ctx->bn[JWK_KEY_E];
	ctx->rsa->n = ctx->bn[JWK_KEY_N];
	ctx->rsa->d = ctx->bn[JWK_KEY_D];
	ctx->rsa->p = ctx->bn[JWK_KEY_P];
	ctx->rsa->q = ctx->bn[JWK_KEY_Q];
#endif

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
		       struct lws_genrsa_elements *el, int bits)
{
	BIGNUM *bn;
	int n;

	memset(ctx, 0, sizeof(*ctx));

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

		RSA_get0_key(ctx->rsa, &mpi[JWK_KEY_N], &mpi[JWK_KEY_E],
			     &mpi[JWK_KEY_D]);
		RSA_get0_factors(ctx->rsa, &mpi[JWK_KEY_P], &mpi[JWK_KEY_Q]);
#else
	{
		BIGNUM *mpi[5] = {
			ctx->rsa->n, ctx->rsa->e, ctx->rsa->d,
			ctx->rsa->p, ctx->rsa->q,
		};
#endif
		for (n = 0; n < 5; n++)
			if (BN_num_bytes(mpi[n])) {
				el->e[n].buf = lws_malloc(
					BN_num_bytes(mpi[n]), "genrsakey");
				if (!el->e[n].buf)
					goto cleanup;
				el->e[n].len = BN_num_bytes(mpi[n]);
				BN_bn2bin(mpi[n], el->e[n].buf);
			}
	}

	return 0;

cleanup:
	for (n = 0; n < LWS_COUNT_RSA_ELEMENTS; n++)
		if (el->e[n].buf)
			lws_free_set_NULL(el->e[n].buf);
cleanup_1:
	RSA_free(ctx->rsa);

	return -1;
}

LWS_VISIBLE int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	uint32_t m;

	m = RSA_public_decrypt((int)in_len, in, out, ctx->rsa, RSA_PKCS1_PADDING);

	/* the bignums are also freed by freeing the RSA */
	RSA_free(ctx->rsa);
	ctx->rsa = NULL;

	if (m != (uint32_t)-1)
		return (int)m;

	return -1;
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

LWS_VISIBLE int
lws_genrsa_public_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	int n = lws_genrsa_genrsa_hash_to_NID(hash_type),
	    h = (int)lws_genhash_size(hash_type);

	if (n < 0)
		return -1;

	n = RSA_verify(n, in, h, (uint8_t *)sig, (int)sig_len, ctx->rsa);
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

	if (n < 0)
		return -1;

	n = RSA_sign(n, in, h, sig, &used, ctx->rsa);
	if (n != 1) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return used;
}

LWS_VISIBLE void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (!ctx->rsa)
		return;

#if defined(LWS_HAVE_RSA_SET0_KEY)
	if (RSA_set0_key(ctx->rsa, NULL, NULL, NULL) != 1)
		lwsl_notice("RSA_set0_key failed\n");
	RSA_set0_factors(ctx->rsa, NULL, NULL);

#else
	ctx->rsa->e = NULL;
	ctx->rsa->n = NULL;
	ctx->rsa->d = NULL;
	ctx->rsa->p = NULL;
	ctx->rsa->q = NULL;
#endif

	RSA_free(ctx->rsa);
	ctx->rsa = NULL;
}
