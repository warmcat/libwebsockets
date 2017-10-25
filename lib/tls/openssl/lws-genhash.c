/*
 * libwebsockets - generic hash and HMAC api hiding the backend
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
#include "libwebsockets.h"

size_t
lws_genhash_size(enum lws_genhash_types type)
{
	switch(type) {
	case LWS_GENHASH_TYPE_SHA1:
		return 20;
	case LWS_GENHASH_TYPE_SHA256:
		return 32;
	case LWS_GENHASH_TYPE_SHA384:
		return 48;
	case LWS_GENHASH_TYPE_SHA512:
		return 64;
	}

	return 0;
}

int
lws_genhash_init(struct lws_genhash_ctx *ctx, enum lws_genhash_types type)
{
	ctx->type = type;
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
	case LWS_GENHASH_TYPE_SHA384:
		ctx->evp_type = EVP_sha384();
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

	return 0;
}

int
lws_genhash_update(struct lws_genhash_ctx *ctx, const void *in, size_t len)
{
	return EVP_DigestUpdate(ctx->mdctx, in, len) != 1;
}

int
lws_genhash_destroy(struct lws_genhash_ctx *ctx, void *result)
{
	unsigned int len;
	int ret = 0;

	if (result)
		ret = EVP_DigestFinal_ex(ctx->mdctx, result, &len) != 1;

	(void)len;

	EVP_MD_CTX_destroy(ctx->mdctx);

	return ret;
}

size_t
lws_genhmac_size(enum lws_genhmac_types type)
{
	switch(type) {
	case LWS_GENHMAC_TYPE_SHA256:
		return 32;
	case LWS_GENHMAC_TYPE_SHA384:
		return 48;
	case LWS_GENHMAC_TYPE_SHA512:
		return 64;
	}

	return 0;
}

int
lws_genhmac_init(struct lws_genhmac_ctx *ctx, enum lws_genhmac_types type,
		 const uint8_t *key, size_t key_len)
{
	const char *ts;
	const EVP_MD *md;
	EVP_PKEY *pkey;

	ctx->type = type;

	switch (type) {
	case LWS_GENHMAC_TYPE_SHA256:
		ts = "SHA256";
		break;
	case LWS_GENHMAC_TYPE_SHA384:
		ts = "SHA384";
		break;
	case LWS_GENHMAC_TYPE_SHA512:
		ts = "SHA512";
		break;
	default:
		return -1;
	}

        ctx->ctx = EVP_MD_CTX_create();
        if (!ctx->ctx)
		return -1;

        md = EVP_get_digestbyname(ts);
        if (!md)
		return -1;

        if (EVP_DigestInit_ex(ctx->ctx, md, NULL) != 1)
		return -1;

        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int)key_len);

        if (EVP_DigestSignInit(ctx->ctx, NULL, md, NULL, pkey) != 1)
		return -1;

        EVP_PKEY_free(pkey);

	return 0;
}

int
lws_genhmac_update(struct lws_genhmac_ctx *ctx, const void *in, size_t len)
{
	 if (EVP_DigestSignUpdate(ctx->ctx, in, len) != 1)
		return -1;

	return 0;
}

int
lws_genhmac_destroy(struct lws_genhmac_ctx *ctx, void *result)
{
	size_t size = lws_genhmac_size(ctx->type);
	int n = EVP_DigestSignFinal(ctx->ctx, result, &size);

	EVP_MD_CTX_destroy(ctx->ctx);
	if (n != 1)
		return -1;

	return 0;
}
