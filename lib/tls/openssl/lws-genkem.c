/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * lws_genkem binding to OpenSSL 3.5+'s own ML-KEM.
 *
 * The OpenSSL providers in use may not have ML-KEM even though the headers
 * do (eg, a FIPS provider that lacks it), so if OpenSSL won't make an ML-KEM
 * key we return 1, and lws_genkem uses its own implementation instead.
 */

#include "private-lib-core.h"
#include "private-lib-tls-openssl.h"
#include "../private-genkem.h"

/* the probe for LWS_HAVE_OPENSSL_ML_KEM runs after the source list is made */
#if defined(LWS_HAVE_OPENSSL_ML_KEM)

#include <openssl/core_names.h>

int
lws_genkem_backend_set_key(struct lws_genkem_ctx *ctx, const uint8_t *seed,
			   const uint8_t *dk, const uint8_t *ek,
			   uint8_t *ek_out, uint8_t *dk_out)
{
	const struct lws_genkem_info *info = lws_genkem_info(ctx->alg);
	OSSL_PARAM params[2];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx;
	int selection;
	size_t len;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, info->name, NULL);
	if (!pctx) {
		lwsl_info("%s: OpenSSL has no %s, using lws's\n", __func__,
			  info->name);
		return 1;
	}

	/*
	 * OpenSSL makes the whole keypair from a seed or a dk; we checked the
	 * dk's embedded ek hash, and the ek's coefficients, already
	 */

	/*
	 * The params point at our buffers, rather than making copies of the
	 * key material that we would have to wipe.  EVP_PKEY_fromdata() only
	 * reads them, but the OSSL_PARAM data member isn't const.
	 */

	if (seed) {
		params[0] = OSSL_PARAM_construct_octet_string(
				OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed,
				LWS_GENKEM_SEED_LEN);
		selection = EVP_PKEY_KEYPAIR;
	} else if (dk) {
		params[0] = OSSL_PARAM_construct_octet_string(
				OSSL_PKEY_PARAM_PRIV_KEY, (void *)dk,
				info->dk_len);
		selection = EVP_PKEY_KEYPAIR;
	} else {
		params[0] = OSSL_PARAM_construct_octet_string(
				OSSL_PKEY_PARAM_PUB_KEY, (void *)ek,
				info->ek_len);
		selection = EVP_PKEY_PUBLIC_KEY;
	}
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
	    EVP_PKEY_fromdata(pctx, &pkey, selection, params) <= 0) {
		lwsl_err("%s: OpenSSL refused the %s key\n", __func__,
			 info->name);
		goto bail;
	}

	if (ek_out &&
	    (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
					    ek_out, info->ek_len, &len) <= 0 ||
	     len != info->ek_len))
		goto bail;

	if (dk_out && selection == EVP_PKEY_KEYPAIR &&
	    (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
					    dk_out, info->dk_len, &len) <= 0 ||
	     len != info->dk_len))
		goto bail;

	EVP_PKEY_CTX_free(pctx);
	ctx->engine = pkey;

	return 0;

bail:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);

	return -1;
}

int
lws_genkem_backend_encapsulate(struct lws_genkem_ctx *ctx, uint8_t *ct,
			       uint8_t *ss)
{
	const struct lws_genkem_info *info = lws_genkem_info(ctx->alg);
	size_t ct_len = info->ct_len, ss_len = LWS_GENKEM_SS_LEN;
	EVP_PKEY_CTX *pctx;
	int n = -1;

	pctx = EVP_PKEY_CTX_new_from_pkey(NULL, (EVP_PKEY *)ctx->engine, NULL);
	if (!pctx)
		return -1;

	if (EVP_PKEY_encapsulate_init(pctx, NULL) > 0 &&
	    EVP_PKEY_encapsulate(pctx, ct, &ct_len, ss, &ss_len) > 0 &&
	    ct_len == info->ct_len && ss_len == LWS_GENKEM_SS_LEN)
		n = 0;

	EVP_PKEY_CTX_free(pctx);

	if (n)
		lws_explicit_bzero(ss, LWS_GENKEM_SS_LEN);

	return n;
}

int
lws_genkem_backend_decapsulate(struct lws_genkem_ctx *ctx, const uint8_t *ct,
			       uint8_t *ss)
{
	const struct lws_genkem_info *info = lws_genkem_info(ctx->alg);
	size_t ss_len = LWS_GENKEM_SS_LEN;
	EVP_PKEY_CTX *pctx;
	int n = -1;

	pctx = EVP_PKEY_CTX_new_from_pkey(NULL, (EVP_PKEY *)ctx->engine, NULL);
	if (!pctx)
		return -1;

	if (EVP_PKEY_decapsulate_init(pctx, NULL) > 0 &&
	    EVP_PKEY_decapsulate(pctx, ss, &ss_len, ct, info->ct_len) > 0 &&
	    ss_len == LWS_GENKEM_SS_LEN)
		n = 0;

	EVP_PKEY_CTX_free(pctx);

	if (n)
		lws_explicit_bzero(ss, LWS_GENKEM_SS_LEN);

	return n;
}

void
lws_genkem_backend_destroy(struct lws_genkem_ctx *ctx)
{
	/* OpenSSL wipes the key material as it frees it */
	EVP_PKEY_free((EVP_PKEY *)ctx->engine);
	ctx->engine = NULL;
}

#endif
