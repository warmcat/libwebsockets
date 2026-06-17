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
 *  lws_genhash provides a hash / hmac abstraction api in lws that works the
 *  same whether you are using OpenHITLS or other TLS backends underneath.
 */

#include "private-lib-core.h"

#include <crypt_errno.h>
#include <crypt_eal_md.h>
#include <crypt_eal_mac.h>

static int
openhitls_md_from_lws(enum lws_genhash_types type, CRYPT_MD_AlgId *id)
{
	if (!id)
		return 1;

	switch (type) {
	case LWS_GENHASH_TYPE_MD5:
		*id = CRYPT_MD_MD5;
		break;
	case LWS_GENHASH_TYPE_SHA1:
		*id = CRYPT_MD_SHA1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		*id = CRYPT_MD_SHA256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		*id = CRYPT_MD_SHA384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		*id = CRYPT_MD_SHA512;
		break;
	default:
		return 1;
	}

	return 0;
}

static int
openhitls_hmac_from_lws(enum lws_genhmac_types type, CRYPT_MAC_AlgId *id)
{
	if (!id)
		return 1;

	switch (type) {
	case LWS_GENHMAC_TYPE_SHA256:
		*id = CRYPT_MAC_HMAC_SHA256;
		break;
	case LWS_GENHMAC_TYPE_SHA384:
		*id = CRYPT_MAC_HMAC_SHA384;
		break;
	case LWS_GENHMAC_TYPE_SHA512:
		*id = CRYPT_MAC_HMAC_SHA512;
		break;
	default:
		return 1;
	}

	return 0;
}

int
lws_genhash_init(struct lws_genhash_ctx *ctx, enum lws_genhash_types type)
{
	CRYPT_MD_AlgId id;

	ctx->type = (uint8_t)type;
	if (openhitls_md_from_lws(type, &id))
		return 1;

	ctx->ctx = CRYPT_EAL_MdNewCtx(id);
	if (!ctx->ctx)
		return 1;

	if (CRYPT_EAL_MdInit(ctx->ctx) != CRYPT_SUCCESS) {
		CRYPT_EAL_MdFreeCtx(ctx->ctx);
		ctx->ctx = NULL;
		return 1;
	}

	return 0;
}

int
lws_genhash_update(struct lws_genhash_ctx *ctx, const void *in, size_t len)
{
	if (!len)
		return 0;

	return CRYPT_EAL_MdUpdate(ctx->ctx, in, (uint32_t)len) != CRYPT_SUCCESS;
}

int
lws_genhash_destroy(struct lws_genhash_ctx *ctx, void *result)
{
	uint32_t len;
	int ret = 0;

	if (!ctx->ctx)
		return 0;

	if (result) {
		len = (uint32_t)lws_genhash_size((enum lws_genhash_types)ctx->type);
		if (CRYPT_EAL_MdFinal(ctx->ctx, result, &len) != CRYPT_SUCCESS)
			ret = 1;
	}

	CRYPT_EAL_MdFreeCtx(ctx->ctx);
	ctx->ctx = NULL;

	return ret;
}

int
lws_genhmac_init(struct lws_genhmac_ctx *ctx, enum lws_genhmac_types type,
		 const uint8_t *key, size_t key_len)
{
	CRYPT_MAC_AlgId id;

	ctx->type = (uint8_t)type;
	if (openhitls_hmac_from_lws(type, &id))
		return -1;

	ctx->ctx = CRYPT_EAL_MacNewCtx(id);
	if (!ctx->ctx)
		return -1;

	if (CRYPT_EAL_MacInit(ctx->ctx, key, (uint32_t)key_len) != CRYPT_SUCCESS) {
		CRYPT_EAL_MacFreeCtx(ctx->ctx);
		ctx->ctx = NULL;
		return -1;
	}

	return 0;
}

int
lws_genhmac_update(struct lws_genhmac_ctx *ctx, const void *in, size_t len)
{
	return CRYPT_EAL_MacUpdate(ctx->ctx, in, (uint32_t)len) != CRYPT_SUCCESS;
}

int
lws_genhmac_destroy(struct lws_genhmac_ctx *ctx, void *result)
{
	uint32_t len;
	int ret = 0;

	if (!ctx->ctx)
		return 0;

	if (result) {
		len = (uint32_t)lws_genhmac_size((enum lws_genhmac_types)ctx->type);
		if (CRYPT_EAL_MacFinal(ctx->ctx, result, &len) != CRYPT_SUCCESS)
			ret = -1;
	} else {
		CRYPT_EAL_MacDeinit(ctx->ctx);
	}

	CRYPT_EAL_MacFreeCtx(ctx->ctx);
	ctx->ctx = NULL;

	return ret;
}
