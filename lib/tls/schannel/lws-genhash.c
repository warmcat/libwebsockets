/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

/*
 * This implementation uses Windows CNG (Cryptography API: Next Generation)
 */

int
lws_genhash_init(struct lws_genhash_ctx *ctx, enum lws_genhash_types type)
{
	LPCWSTR alg_id = NULL;
	NTSTATUS status;

	ctx->type = (uint8_t)type;
	ctx->u.hHash = NULL;

	switch (ctx->type) {
	case LWS_GENHASH_TYPE_MD5:
		alg_id = BCRYPT_MD5_ALGORITHM;
		break;
	case LWS_GENHASH_TYPE_SHA1:
		alg_id = BCRYPT_SHA1_ALGORITHM;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		alg_id = BCRYPT_SHA256_ALGORITHM;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		alg_id = BCRYPT_SHA384_ALGORITHM;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		alg_id = BCRYPT_SHA512_ALGORITHM;
		break;
	default:
		return 1;
	}

	status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, alg_id, NULL, 0);
	if (!BCRYPT_SUCCESS(status)) {
		lwsl_err("%s: BCryptOpenAlgorithmProvider failed 0x%x\n", __func__, (int)status);
		return 1;
	}

	status = BCryptCreateHash(ctx->u.hAlg, &ctx->u.hHash, NULL, 0, NULL, 0, 0);
	if (!BCRYPT_SUCCESS(status)) {
		lwsl_err("%s: BCryptCreateHash failed 0x%x\n", __func__, (int)status);
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
		ctx->u.hAlg = NULL;
		return 1;
	}

	return 0;
}

int
lws_genhash_update(struct lws_genhash_ctx *ctx, const void *in, size_t len)
{
	NTSTATUS status;

	if (!len)
		return 0;

	status = BCryptHashData(ctx->u.hHash, (PUCHAR)in, (ULONG)len, 0);
	if (!BCRYPT_SUCCESS(status)) {
		lwsl_err("%s: BCryptHashData failed 0x%x\n", __func__, (int)status);
		return 1;
	}

	return 0;
}

int
lws_genhash_destroy(struct lws_genhash_ctx *ctx, void *result)
{
	NTSTATUS status = 0;
	int ret = 0;

	if (result) {
		status = BCryptFinishHash(ctx->u.hHash, (PUCHAR)result, (ULONG)lws_genhash_size((enum lws_genhash_types)ctx->type), 0);
		if (!BCRYPT_SUCCESS(status)) {
			lwsl_err("%s: BCryptFinishHash failed 0x%x\n", __func__, (int)status);
			ret = 1;
		}
	}

	if (ctx->u.hHash)
		BCryptDestroyHash(ctx->u.hHash);
	if (ctx->u.hAlg)
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);

	ctx->u.hHash = NULL;
	ctx->u.hAlg = NULL;

	return ret;
}


int
lws_genhmac_init(struct lws_genhmac_ctx *ctx, enum lws_genhmac_types type,
		 const uint8_t *key, size_t key_len)
{
	LPCWSTR alg_id = NULL;
	NTSTATUS status;

	ctx->type = (uint8_t)type;
	ctx->u.hHash = NULL;

	switch (ctx->type) {
	case LWS_GENHMAC_TYPE_SHA256:
		alg_id = BCRYPT_SHA256_ALGORITHM;
		break;
	case LWS_GENHMAC_TYPE_SHA384:
		alg_id = BCRYPT_SHA384_ALGORITHM;
		break;
	case LWS_GENHMAC_TYPE_SHA512:
		alg_id = BCRYPT_SHA512_ALGORITHM;
		break;
	default:
		return -1;
	}

	status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, alg_id, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (!BCRYPT_SUCCESS(status)) {
		lwsl_err("%s: BCryptOpenAlgorithmProvider failed 0x%x\n", __func__, (int)status);
		return -1;
	}

	status = BCryptCreateHash(ctx->u.hAlg, &ctx->u.hHash, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
	if (!BCRYPT_SUCCESS(status)) {
		lwsl_err("%s: BCryptCreateHash failed 0x%x\n", __func__, (int)status);
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
		ctx->u.hAlg = NULL;
		return -1;
	}

	return 0;
}

int
lws_genhmac_update(struct lws_genhmac_ctx *ctx, const void *in, size_t len)
{
	NTSTATUS status;

	if (!len)
		return 0;

	status = BCryptHashData(ctx->u.hHash, (PUCHAR)in, (ULONG)len, 0);
	if (!BCRYPT_SUCCESS(status)) {
		lwsl_err("%s: BCryptHashData failed 0x%x\n", __func__, (int)status);
		return -1;
	}

	return 0;
}

int
lws_genhmac_destroy(struct lws_genhmac_ctx *ctx, void *result)
{
	NTSTATUS status = 0;
	int ret = 0;

	if (result) {
		status = BCryptFinishHash(ctx->u.hHash, (PUCHAR)result, (ULONG)lws_genhmac_size((enum lws_genhmac_types)ctx->type), 0);
		if (!BCRYPT_SUCCESS(status)) {
			lwsl_err("%s: BCryptFinishHash failed 0x%x\n", __func__, (int)status);
			ret = -1;
		}
	}

	if (ctx->u.hHash)
		BCryptDestroyHash(ctx->u.hHash);
	if (ctx->u.hAlg)
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);

	ctx->u.hHash = NULL;
	ctx->u.hAlg = NULL;

	return ret;
}
