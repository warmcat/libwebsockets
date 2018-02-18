/*
 * libwebsockets - small server side websockets and web server implementation
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
 *  lws_genhash provides a hash abstraction api in lws that works the same
 *  whether you are using openssl or mbedtls hash functions underneath.
 */
#include "libwebsockets.h"

#if defined(LWS_WITH_MBEDTLS)
#include <mbedtls/version.h>

#if (MBEDTLS_VERSION_NUMBER >= 0x02070000)
#define MBA(fn) fn##_ret
#else
#define MBA(fn) fn
#endif
#endif

size_t
lws_genhash_size(int type)
{
	switch(type) {
	case LWS_GENHASH_TYPE_SHA1:
		return 20;
	case LWS_GENHASH_TYPE_SHA256:
		return 32;
	case LWS_GENHASH_TYPE_SHA512:
		return 64;
	}

	return 0;
}

int
lws_genhash_init(struct lws_genhash_ctx *ctx, int type)
{
	ctx->type = type;

#if defined(LWS_WITH_MBEDTLS)
	switch (ctx->type) {
	case LWS_GENHASH_TYPE_SHA1:
		mbedtls_sha1_init(&ctx->u.sha1);
		MBA(mbedtls_sha1_starts)(&ctx->u.sha1);
		break;
	case LWS_GENHASH_TYPE_SHA256:
		mbedtls_sha256_init(&ctx->u.sha256);
		MBA(mbedtls_sha256_starts)(&ctx->u.sha256, 0);
		break;
	case LWS_GENHASH_TYPE_SHA512:
		mbedtls_sha512_init(&ctx->u.sha512);
		MBA(mbedtls_sha512_starts)(&ctx->u.sha512, 0);
		break;
	default:
		return 1;
	}
#else
	ctx->mdctx = EVP_MD_CTX_create();
	if (!ctx->mdctx)
		return 1;

	switch (ctx->type) {
	case LWS_GENHASH_TYPE_SHA1:
		ctx->evp_type = EVP_sha1();
		break;
	case LWS_GENHASH_TYPE_SHA256:
		ctx->evp_type = EVP_sha256();
		break;
	case LWS_GENHASH_TYPE_SHA512:
		ctx->evp_type = EVP_sha512();
		break;
	default:
		return 1;
	}

	if (EVP_DigestInit_ex(ctx->mdctx, ctx->evp_type, NULL) != 1) {
		EVP_MD_CTX_destroy(ctx->mdctx);

		return 1;
	}

#endif
	return 0;
}

int
lws_genhash_update(struct lws_genhash_ctx *ctx, const void *in, size_t len)
{
#if defined(LWS_WITH_MBEDTLS)
	switch (ctx->type) {
	case LWS_GENHASH_TYPE_SHA1:
		MBA(mbedtls_sha1_update)(&ctx->u.sha1, in, len);
		break;
	case LWS_GENHASH_TYPE_SHA256:
		MBA(mbedtls_sha256_update)(&ctx->u.sha256, in, len);
		break;
	case LWS_GENHASH_TYPE_SHA512:
		MBA(mbedtls_sha512_update)(&ctx->u.sha512, in, len);
		break;
	}
#else
	return EVP_DigestUpdate(ctx->mdctx, in, len) != 1;
#endif

	return 0;
}

int
lws_genhash_destroy(struct lws_genhash_ctx *ctx, void *result)
{
#if defined(LWS_WITH_MBEDTLS)
	switch (ctx->type) {
	case LWS_GENHASH_TYPE_SHA1:
		MBA(mbedtls_sha1_finish)(&ctx->u.sha1, result);
		mbedtls_sha1_free(&ctx->u.sha1);
		break;
	case LWS_GENHASH_TYPE_SHA256:
		MBA(mbedtls_sha256_finish)(&ctx->u.sha256, result);
		mbedtls_sha256_free(&ctx->u.sha256);
		break;
	case LWS_GENHASH_TYPE_SHA512:
		MBA(mbedtls_sha512_finish)(&ctx->u.sha512, result);
		mbedtls_sha512_free(&ctx->u.sha512);
		break;
	}

	return 0;
#else
	unsigned int len;
	int ret = 0;

	if (result)
		ret = EVP_DigestFinal_ex(ctx->mdctx, result, &len) != 1;

	(void)len;

	EVP_MD_CTX_destroy(ctx->mdctx);

	return ret;
#endif
}


