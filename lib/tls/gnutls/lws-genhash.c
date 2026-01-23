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
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

int
lws_genhash_init(struct lws_genhash_ctx *ctx, enum lws_genhash_types type)
{
	gnutls_digest_algorithm_t alg;

	ctx->type = (uint8_t)type;

	switch (type) {
	case LWS_GENHASH_TYPE_MD5:
		alg = GNUTLS_DIG_MD5;
		break;
	case LWS_GENHASH_TYPE_SHA1:
		alg = GNUTLS_DIG_SHA1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		alg = GNUTLS_DIG_SHA256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		alg = GNUTLS_DIG_SHA384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		alg = GNUTLS_DIG_SHA512;
		break;
	default:
		return 1;
	}

	if (gnutls_hash_init((gnutls_hash_hd_t *)&ctx->u.hash, alg) < 0)
		return 1;

	return 0;
}

int
lws_genhash_update(struct lws_genhash_ctx *ctx, const void *in, size_t len)
{
	if (!len)
		return 0;

	if (gnutls_hash((gnutls_hash_hd_t)ctx->u.hash, in, len) < 0)
		return 1;

	return 0;
}

int
lws_genhash_destroy(struct lws_genhash_ctx *ctx, void *result)
{
	if (ctx->u.hash)
		gnutls_hash_deinit((gnutls_hash_hd_t)ctx->u.hash, result);

	ctx->u.hash = NULL;

	return 0;
}

int
lws_genhmac_init(struct lws_genhmac_ctx *ctx, enum lws_genhmac_types type,
		 const uint8_t *key, size_t key_len)
{
	gnutls_mac_algorithm_t alg;

	ctx->type = (uint8_t)type;

	switch (type) {
	case LWS_GENHMAC_TYPE_SHA256:
		alg = GNUTLS_MAC_SHA256;
		break;
	case LWS_GENHMAC_TYPE_SHA384:
		alg = GNUTLS_MAC_SHA384;
		break;
	case LWS_GENHMAC_TYPE_SHA512:
		alg = GNUTLS_MAC_SHA512;
		break;
	default:
		return -1;
	}

	if (gnutls_hmac_init((gnutls_hmac_hd_t *)&ctx->u.hash, alg, key, key_len) < 0)
		return -1;

	return 0;
}

int
lws_genhmac_update(struct lws_genhmac_ctx *ctx, const void *in, size_t len)
{
	if (!len)
		return 0;

	if (gnutls_hmac((gnutls_hmac_hd_t)ctx->u.hash, in, len) < 0)
		return -1;

	return 0;
}

int
lws_genhmac_destroy(struct lws_genhmac_ctx *ctx, void *result)
{
	if (ctx->u.hash)
		gnutls_hmac_deinit((gnutls_hmac_hd_t)ctx->u.hash, result);

	ctx->u.hash = NULL;

	return 0;
}
