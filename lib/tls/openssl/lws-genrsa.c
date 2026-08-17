 /*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 *  lws_genrsa provides an RSA abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls crypto functions underneath.
 */
#include "private-lib-core.h"
#include "private-lib-tls-openssl.h"
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

/*
 * Care: many openssl apis return 1 for success.  These are translated to the
 * lws convention of 0 for success.
 */

void
lws_genrsa_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
}

static int mode_map_crypt[] = { RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING },
	   mode_map_sig[]   = { RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING };

#if !defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
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
#endif

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	int n;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	/*
	 * OAEP needs a real hash for the OAEP and MGF1 digests... if the
	 * caller has no preference, use the RFC8017 default of SHA-1
	 */

	ctx->oaep_hashid = oaep_hashid;
	if (mode == LGRSAM_PKCS1_OAEP_PSS &&
	    oaep_hashid == LWS_GENHASH_TYPE_UNKNOWN)
		ctx->oaep_hashid = LWS_GENHASH_TYPE_SHA1;

	/* Step 1:
	 *
	 * convert the MPI for e and n to OpenSSL BIGNUMs
	 */

	for (n = 0; n < 5; n++) {
		ctx->bn[n] = BN_bin2bn(el[n].buf, SSL_SIZE_T_CAST(el[n].len), NULL);
		if (!ctx->bn[n]) {
			lwsl_notice("mpi load failed\n");
			goto bail;
		}
	}

	/* Step 2:
	 *
	 * assemble the OpenSSL RSA from the BIGNUMs
	 */
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	{
		OSSL_PARAM params[6];
		int pidx = 0;
		EVP_PKEY_CTX *pctx;
		EVP_PKEY *pkey = NULL;
		
		if (el[LWS_GENCRYPTO_RSA_KEYEL_N].buf)
			params[pidx++] = OSSL_PARAM_construct_BN("n", (unsigned char *)el[LWS_GENCRYPTO_RSA_KEYEL_N].buf, el[LWS_GENCRYPTO_RSA_KEYEL_N].len);
		if (el[LWS_GENCRYPTO_RSA_KEYEL_E].buf)
			params[pidx++] = OSSL_PARAM_construct_BN("e", (unsigned char *)el[LWS_GENCRYPTO_RSA_KEYEL_E].buf, el[LWS_GENCRYPTO_RSA_KEYEL_E].len);
		if (el[LWS_GENCRYPTO_RSA_KEYEL_D].buf)
			params[pidx++] = OSSL_PARAM_construct_BN("d", (unsigned char *)el[LWS_GENCRYPTO_RSA_KEYEL_D].buf, el[LWS_GENCRYPTO_RSA_KEYEL_D].len);
		if (el[LWS_GENCRYPTO_RSA_KEYEL_P].buf)
			params[pidx++] = OSSL_PARAM_construct_BN("rsa-factor1", (unsigned char *)el[LWS_GENCRYPTO_RSA_KEYEL_P].buf, el[LWS_GENCRYPTO_RSA_KEYEL_P].len);
		if (el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf)
			params[pidx++] = OSSL_PARAM_construct_BN("rsa-factor2", (unsigned char *)el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, el[LWS_GENCRYPTO_RSA_KEYEL_Q].len);
		params[pidx] = OSSL_PARAM_construct_end();

		pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
		if (!pctx) goto bail;
		if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
		    EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
			EVP_PKEY_CTX_free(pctx);
			goto bail;
		}
		EVP_PKEY_CTX_free(pctx);
		
		ctx->ctx = EVP_PKEY_CTX_new(pkey, NULL);
		EVP_PKEY_free(pkey);
		if (!ctx->ctx) goto bail;
		return 0;
	}
#else
	ctx->rsa = RSA_new();
	if (!ctx->rsa) {
		lwsl_notice("Failed to create RSA\n");
		goto bail;
	}

#if (defined(LWS_HAVE_RSA_SET0_KEY) || defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)) && !defined(USE_WOLFSSL)
	if (RSA_set0_key(ctx->rsa, ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_N],
			 ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_E],
			 ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_D]) != 1) {
		lwsl_notice("RSA_set0_key failed\n");
		goto bail;
	}
	RSA_set0_factors(ctx->rsa, ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_P],
				   ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_Q]);
#else
	ctx->rsa->e = ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_E];
	ctx->rsa->n = ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_N];
	ctx->rsa->d = ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_D];
	ctx->rsa->p = ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_P];
	ctx->rsa->q = ctx->bn[LWS_GENCRYPTO_RSA_KEYEL_Q];
#endif

	if (!rsa_pkey_wrap(ctx, ctx->rsa))
		return 0;
#endif

bail:
	for (n = 0; n < 5; n++)
		if (ctx->bn[n]) {
			BN_clear_free(ctx->bn[n]);
			ctx->bn[n] = NULL;
		}

	if (ctx->rsa) {
		RSA_free(ctx->rsa);
		ctx->rsa = NULL;
	}

	return 1;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
#if !defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	BIGNUM *bn;
#endif
	int n;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	{
		EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)bits);
		BIGNUM *mpi[5] = { NULL, NULL, NULL, NULL, NULL };

		if (!pkey) return -1;
		
		if (!EVP_PKEY_get_bn_param(pkey, "n", &mpi[LWS_GENCRYPTO_RSA_KEYEL_N]) ||
		    !EVP_PKEY_get_bn_param(pkey, "e", &mpi[LWS_GENCRYPTO_RSA_KEYEL_E]) ||
		    !EVP_PKEY_get_bn_param(pkey, "d", &mpi[LWS_GENCRYPTO_RSA_KEYEL_D]) ||
		    !EVP_PKEY_get_bn_param(pkey, "rsa-factor1", &mpi[LWS_GENCRYPTO_RSA_KEYEL_P]) ||
		    !EVP_PKEY_get_bn_param(pkey, "rsa-factor2", &mpi[LWS_GENCRYPTO_RSA_KEYEL_Q])) {
			goto cleanup_3;
		}

		for (n = 0; n < 5; n++) {
			if (BN_num_bytes(mpi[n])) {
				el[n].buf = lws_malloc(
					(unsigned int)BN_num_bytes(mpi[n]), "genrsakey");
				if (!el[n].buf)
					goto cleanup_3;
				el[n].len = (unsigned int)BN_num_bytes(mpi[n]);
				BN_bn2bin(mpi[n], el[n].buf);
			}
			BN_clear_free(mpi[n]);
			mpi[n] = NULL;
		}
		
		ctx->ctx = EVP_PKEY_CTX_new(pkey, NULL);
		EVP_PKEY_free(pkey);
		if (!ctx->ctx) goto cleanup;
		return 0;
cleanup_3:
		for (n = 0; n < 5; n++)
			if (mpi[n]) BN_clear_free(mpi[n]);
		EVP_PKEY_free(pkey);
		goto cleanup;
	}
#else
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
	BN_clear_free(bn);
	if (n != 1)
		goto cleanup_1;

#if (defined(LWS_HAVE_RSA_SET0_KEY) || defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)) && !defined(USE_WOLFSSL)
	{
		const BIGNUM *mpi[5];

		RSA_get0_key(ctx->rsa, &mpi[LWS_GENCRYPTO_RSA_KEYEL_N],
			     &mpi[LWS_GENCRYPTO_RSA_KEYEL_E], &mpi[LWS_GENCRYPTO_RSA_KEYEL_D]);
		RSA_get0_factors(ctx->rsa, &mpi[LWS_GENCRYPTO_RSA_KEYEL_P],
				 &mpi[LWS_GENCRYPTO_RSA_KEYEL_Q]);
#else
	{
		BIGNUM *mpi[5] = { ctx->rsa->e, ctx->rsa->n, ctx->rsa->d,
				   ctx->rsa->p, ctx->rsa->q, };
#endif
		for (n = 0; n < 5; n++)
			if (BN_num_bytes(mpi[n])) {
				el[n].buf = lws_malloc(
					(unsigned int)BN_num_bytes(mpi[n]), "genrsakey");
				if (!el[n].buf)
					goto cleanup;
				el[n].len = (unsigned int)BN_num_bytes(mpi[n]);
				BN_bn2bin(mpi[n], el[n].buf);
			}
	}

	if (!rsa_pkey_wrap(ctx, ctx->rsa))
		return 0;
#endif

cleanup:
	for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
#if !defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
cleanup_1:
	RSA_free(ctx->rsa);
	ctx->rsa = NULL;
#endif

	return -1;
}

/*
 * in_len must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5
 * based padding modes
 */

#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
/*
 * For OAEP mode, the EVP_PKEY_CTX digest selection is reset by the per-call
 * operation init, so the OAEP and MGF1 digests must be (re)set on it each
 * time after the init and padding selection
 */
static int
rsa_oaep_set_md(EVP_PKEY_CTX *pctx, enum lws_genhash_types oaep_hashid)
{
	const EVP_MD *md = lws_gencrypto_openssl_hash_to_EVP_MD(oaep_hashid);

	if (!md)
		return -1;

	if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, md) != 1 ||
	    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) != 1)
		return -1;

	return 0;
}
#endif

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	size_t out_len = (size_t)EVP_PKEY_size(EVP_PKEY_CTX_get0_pkey(ctx->ctx));
	if (EVP_PKEY_encrypt_init(ctx->ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx->ctx, mode_map_crypt[ctx->mode]) <= 0 ||
	    (ctx->mode == LGRSAM_PKCS1_OAEP_PSS &&
	     rsa_oaep_set_md(ctx->ctx, ctx->oaep_hashid) < 0) ||
	    EVP_PKEY_encrypt(ctx->ctx, out, &out_len, in, in_len) <= 0) {
		lwsl_err("%s: EVP_PKEY_encrypt failed\n", __func__);
		lws_tls_err_describe_clear();
		return -1;
	}
	return (int)out_len;
#else
	int n = RSA_public_encrypt(SSL_SIZE_T_CAST(in_len), in, out, ctx->rsa,
				   mode_map_crypt[ctx->mode]);
	if (n < 0) {
		lwsl_err("%s: RSA_public_encrypt failed\n", __func__);
		lws_tls_err_describe_clear();
		return -1;
	}

	return n;
#endif
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	size_t out_len = (size_t)EVP_PKEY_size(EVP_PKEY_CTX_get0_pkey(ctx->ctx));
	if (EVP_PKEY_sign_init(ctx->ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx->ctx, mode_map_crypt[ctx->mode]) <= 0 ||
	    EVP_PKEY_sign(ctx->ctx, out, &out_len, in, in_len) <= 0) {
		lwsl_err("%s: EVP_PKEY_sign failed\n", __func__);
		lws_tls_err_describe_clear();
		return -1;
	}
	return (int)out_len;
#else
	int n = RSA_private_encrypt(SSL_SIZE_T_CAST(in_len), in, out, ctx->rsa,
			        mode_map_crypt[ctx->mode]);
	if (n < 0) {
		lwsl_err("%s: RSA_private_encrypt failed\n", __func__);
		lws_tls_err_describe_clear();
		return -1;
	}

	return n;
#endif
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	size_t out_len = out_max;
	if (EVP_PKEY_verify_recover_init(ctx->ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx->ctx, mode_map_crypt[ctx->mode]) <= 0 ||
	    EVP_PKEY_verify_recover(ctx->ctx, out, &out_len, in, in_len) <= 0) {
		lwsl_err("%s: EVP_PKEY_verify_recover failed\n", __func__);
		return -1;
	}
	return (int)out_len;
#else
	int n = RSA_public_decrypt(SSL_SIZE_T_CAST(in_len), in, out, ctx->rsa,
			       mode_map_crypt[ctx->mode]);
	if (n < 0) {
		lwsl_err("%s: RSA_public_decrypt failed\n", __func__);
		return -1;
	}

	return n;
#endif
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	size_t out_len = out_max;
	if (EVP_PKEY_decrypt_init(ctx->ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx->ctx, mode_map_crypt[ctx->mode]) <= 0 ||
	    (ctx->mode == LGRSAM_PKCS1_OAEP_PSS &&
	     rsa_oaep_set_md(ctx->ctx, ctx->oaep_hashid) < 0) ||
	    EVP_PKEY_decrypt(ctx->ctx, out, &out_len, in, in_len) <= 0) {
		lwsl_err("%s: EVP_PKEY_decrypt failed\n", __func__);
		lws_tls_err_describe_clear();
		return -1;
	}
	return (int)out_len;
#else
	int n = RSA_private_decrypt(SSL_SIZE_T_CAST(in_len), in, out, ctx->rsa,
			        mode_map_crypt[ctx->mode]);
	if (n < 0) {
		lwsl_err("%s: RSA_private_decrypt failed\n", __func__);
		lws_tls_err_describe_clear();
		return -1;
	}

	return n;
#endif
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	int n = lws_gencrypto_openssl_hash_to_NID(hash_type),
	    h = (int)lws_genhash_size(hash_type);
	const EVP_MD *md = NULL;

	if (n < 0)
		return -1;

	switch(ctx->mode) {
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
	case LGRSAM_PKCS1_1_5:
	case LGRSAM_PKCS1_OAEP_PSS:
		{
			EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(EVP_PKEY_CTX_get0_pkey(ctx->ctx), NULL);
			md = lws_gencrypto_openssl_hash_to_EVP_MD(hash_type);
			if (!pctx || !md) {
				if (pctx) EVP_PKEY_CTX_free(pctx);
				return -1;
			}
			if (EVP_PKEY_verify_init(pctx) <= 0 ||
			    EVP_PKEY_CTX_set_rsa_padding(pctx, mode_map_sig[ctx->mode]) <= 0 ||
			    EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0 ||
			    (ctx->mode == LGRSAM_PKCS1_OAEP_PSS && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0) ||
			    EVP_PKEY_verify(pctx, sig, sig_len, in, (size_t)h) <= 0) {
				n = 0;
			} else {
				n = 1;
			}
			EVP_PKEY_CTX_free(pctx);
		}
		break;
#else
	case LGRSAM_PKCS1_1_5:
		n = RSA_verify(n, in, (unsigned int)h, (uint8_t *)sig,
			       (unsigned int)sig_len, ctx->rsa);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		md = lws_gencrypto_openssl_hash_to_EVP_MD(hash_type);
		if (!md)
			return -1;

#if defined(LWS_HAVE_RSA_verify_pss_mgf1) || defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
		n = RSA_verify_pss_mgf1(ctx->rsa, in, SSL_SIZE_T_CAST(h), md, NULL, -1,
					(uint8_t *)sig, (size_t)sig_len);
#else
		n = RSA_verify_PKCS1_PSS(ctx->rsa, in, md, (uint8_t *)sig,
			(int)sig_len);
#endif
		break;
#endif
	default:
		return -1;
	}

	if (n != 1) {
		lwsl_notice("%s: fail\n", __func__);
		lws_tls_err_describe_clear();

		return -1;
	}

	return 0;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	int n = lws_gencrypto_openssl_hash_to_NID(hash_type),
	    h = (int)lws_genhash_size(hash_type);
	unsigned int used = 0;
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md = NULL;

	if (n < 0)
		return -1;

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
#if defined(LWS_HAVE_EVP_PKEY_GET_BN_PARAM)
		{
			EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(EVP_PKEY_CTX_get0_pkey(ctx->ctx), NULL);
			size_t slen = sig_len;
			md = lws_gencrypto_openssl_hash_to_EVP_MD(hash_type);
			if (!pctx || !md) {
				if (pctx) EVP_PKEY_CTX_free(pctx);
				goto bail;
			}
			if (EVP_PKEY_sign_init(pctx) <= 0 ||
			    EVP_PKEY_CTX_set_rsa_padding(pctx, mode_map_sig[ctx->mode]) <= 0 ||
			    EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0 ||
			    EVP_PKEY_sign(pctx, sig, &slen, in, (size_t)h) <= 0) {
				EVP_PKEY_CTX_free(pctx);
				goto bail;
			}
			used = (unsigned int)slen;
			EVP_PKEY_CTX_free(pctx);
		}
#else
		if (RSA_sign(n, in, (unsigned int)h, sig, &used, ctx->rsa) != 1) {
			lwsl_err("%s: RSA_sign failed\n", __func__);

			goto bail;
		}
#endif
		break;

	case LGRSAM_PKCS1_OAEP_PSS:

		md = lws_gencrypto_openssl_hash_to_EVP_MD(hash_type);
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
#if defined(USE_WOLFSSL)
					ctx->ctx->pkey)) {
#else
				       EVP_PKEY_CTX_get0_pkey(ctx->ctx))) {
#endif
			lwsl_err("%s: EVP_DigestSignInit failed\n", __func__);

			goto bail;
		}
		if (EVP_DigestSignUpdate(mdctx, in, (unsigned int)EVP_MD_size(md))) {
			lwsl_err("%s: EVP_DigestSignUpdate failed\n", __func__);

			goto bail;
		}
		if (EVP_DigestSignFinal(mdctx, sig, &sig_len)) {
			lwsl_err("%s: EVP_DigestSignFinal failed\n", __func__);

			goto bail;
		}
		EVP_MD_CTX_free(mdctx);
		used = (unsigned int)sig_len;
		break;

	default:
		return -1;
	}

	return (int)used;

bail:
	if (mdctx)
		EVP_MD_CTX_free(mdctx);

	return -1;
}

void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (!ctx->ctx)
		return;

	EVP_PKEY_CTX_free(ctx->ctx);
	ctx->ctx = NULL;
	ctx->rsa = NULL;
}
