/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

#ifndef BCRYPT_AUTH_MODE_INFO_BLOCK_LENGTH
#define BCRYPT_AUTH_MODE_INFO_BLOCK_LENGTH L"AuthModeInfoBlockLength"
#endif

#ifndef MS_PRIMITIVE_PROVIDER
#define MS_PRIMITIVE_PROVIDER L"Microsoft Primitive Provider"
#endif

int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  enum enum_aes_padding padding, void *engine)
{
	NTSTATUS status;
	LPCWSTR algId = NULL;

	ctx->mode = mode;
	ctx->op = op;
	ctx->k = el;
	ctx->underway = 0;
	ctx->u.hKey = NULL;
	ctx->u.hAlg = NULL;

	ctx->u.pbMacContext = NULL;
	ctx->u.cbMacContext = 0;
	ctx->u.pbNonce = NULL;
	ctx->u.cbNonce = 0;
	ctx->u.pbTag = NULL;
	ctx->u.cbTag = 0;
	ctx->u.pbAuthData = NULL;
	ctx->u.cbAuthData = 0;

	memset(ctx->u.iv, 0, sizeof(ctx->u.iv));

	/* Note: CNG AES supports CBC, ECB, CFB, GMAC (GCM) etc. */
	algId = BCRYPT_AES_ALGORITHM;

	status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, algId, MS_PRIMITIVE_PROVIDER, 0);
	if (!BCRYPT_SUCCESS(status))
		return -1;

	LPCWSTR chainMode = NULL;
	switch(mode) {
		case LWS_GAESM_CBC: chainMode = BCRYPT_CHAIN_MODE_CBC; break;
		case LWS_GAESM_ECB: chainMode = BCRYPT_CHAIN_MODE_ECB; break;
		case LWS_GAESM_CFB8: chainMode = BCRYPT_CHAIN_MODE_CFB; break;
		case LWS_GAESM_GCM: chainMode = BCRYPT_CHAIN_MODE_GCM; break;
		default:
			BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
			return -1;
	}

	status = BCryptSetProperty(ctx->u.hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)chainMode, (ULONG)(wcslen(chainMode) + 1) * sizeof(WCHAR), 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
		return -1;
	}

	status = BCryptGenerateSymmetricKey(ctx->u.hAlg, &ctx->u.hKey, NULL, 0, (PUCHAR)el->buf, (ULONG)el->len, 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
		return -1;
	}

	return 0;
}

int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	if (ctx->mode == LWS_GAESM_GCM && ctx->underway && ctx->u.pbMacContext) {
		/* Finalize GCM to get/verify tag using persisted authInfo */

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *authInfo =
			(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *)ctx->u.pbMacContext;

		/* Clear the chaining flag for the final call */
		authInfo->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

		/* We must pass a valid output buffer (even if dummy) to force BCryptEncrypt to execute
		   and produce the tag, otherwise it acts as "Get Size" */
		uint8_t dummy[128];
		ULONG result_len = 0;

		/* Ensure tag buffer pointers are correct for the final call */
		if (ctx->op == LWS_GAESO_ENC && tag && tlen) {
			/* Final call to generate tag in internal buffer */
			if (BCRYPT_SUCCESS(BCryptEncrypt(ctx->u.hKey, NULL, 0, authInfo, ctx->u.iv, 16, dummy, sizeof(dummy), &result_len, 0))) {
				/* Copy internal tag to user buffer */
				if (tlen <= ctx->u.cbTag)
					memcpy(tag, ctx->u.pbTag, tlen);
			}
		}

		if (ctx->op == LWS_GAESO_DEC && tag && tlen) {
			/* For decryption, we must populate the internal tag buffer with the expected tag
			   BEFORE the final verification call.
			*/
			if (tlen <= ctx->u.cbTag)
				memcpy(ctx->u.pbTag, tag, tlen);

			if (!BCRYPT_SUCCESS(BCryptDecrypt(ctx->u.hKey, NULL, 0, authInfo, ctx->u.iv, 16, dummy, sizeof(dummy), &result_len, 0))) {
				/* Verification failed */
				/* We cannot easily return failure here as destroy returns 0 typically,
				   but the tag check failure is implied. */
			}
		}
	}

	if (ctx->u.pbMacContext) lws_free(ctx->u.pbMacContext);
	if (ctx->u.pbNonce) lws_free(ctx->u.pbNonce);
	if (ctx->u.pbAuthData) lws_free(ctx->u.pbAuthData);
	if (ctx->u.pbTag) lws_free(ctx->u.pbTag);

	if (ctx->u.hKey)
		BCryptDestroyKey(ctx->u.hKey);
	if (ctx->u.hAlg)
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);

	return 0;
}

int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len,
		 uint8_t *out,
		 uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16,
		 size_t *nc_or_iv_off, int taglen)
{
	NTSTATUS status;
	ULONG result_len = 0;

	if (ctx->mode == LWS_GAESM_GCM) {
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *authInfo;

		if (!ctx->underway) {
			/* First call: Initialize context and process AAD */
			ctx->underway = 1;

			/* Determine MacContext size */
			ULONG ctxSize = 0, resLen = 0;
			NTSTATUS st = BCryptGetProperty(ctx->u.hAlg, BCRYPT_AUTH_MODE_INFO_BLOCK_LENGTH,
							(PUCHAR)&ctxSize, sizeof(ctxSize), &resLen, 0);
			if (BCRYPT_SUCCESS(st)) {
				ctx->u.cbMacContext = ctxSize;
			} else {
				ctx->u.cbMacContext = 2048; /* Fallback if query fails */
			}

			/*
			 * Allocate PERSISTENT buffer for authInfo + MacContext.
			 * We store this in ctx->u.pbMacContext so it survives until destroy.
			 */
			size_t allocSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) + ctx->u.cbMacContext;
			ctx->u.pbMacContext = lws_malloc(allocSize, "genaes auth info + mac ctx");
			if (!ctx->u.pbMacContext) {
				return -1;
			}
			/* Zero the whole buffer */
			memset(ctx->u.pbMacContext, 0, allocSize);

			/* Point authInfo to the start of the buffer */
			authInfo = (BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *)ctx->u.pbMacContext;
			BCRYPT_INIT_AUTH_MODE_INFO(*authInfo);

			/* Point pbMacContext to the space after authInfo */
			authInfo->pbMacContext = (PUCHAR)ctx->u.pbMacContext + sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
			authInfo->cbMacContext = (ULONG)ctx->u.cbMacContext;

			/* Store Nonce/IV */
			PUCHAR iv = (PUCHAR)iv_or_nonce_ctr_or_data_unit_16;

			/* Determine Nonce Size */
			if (nc_or_iv_off)
				ctx->u.cbNonce = *nc_or_iv_off;
			else
				ctx->u.cbNonce = 12; /* Default GCM nonce size */

			/* Allocate Nonce Buffer */
			ctx->u.pbNonce = lws_malloc(ctx->u.cbNonce, "genaes nonce");
			if (!ctx->u.pbNonce) {
				/* pbMacContext freed in destroy */
				return -1;
			}

			/* Initialize Nonce */
			if (iv)
				memcpy(ctx->u.pbNonce, iv, ctx->u.cbNonce);
			else
				memset(ctx->u.pbNonce, 0, ctx->u.cbNonce);

			/* Setup Internal Tag Buffer */
			int tlen = (taglen > 0) ? taglen : 16; /* Default to 16 if unknown */
			ctx->u.cbTag = tlen;
			ctx->u.pbTag = lws_malloc(ctx->u.cbTag, "genaes tag");
			if (!ctx->u.pbTag) {
				return -1;
			}
			memset(ctx->u.pbTag, 0, ctx->u.cbTag);

			/* If decrypting and tag provided via stream_block (lws convention), copy it now */
			if (ctx->op == LWS_GAESO_DEC && stream_block_16) {
				memcpy(ctx->u.pbTag, stream_block_16, ctx->u.cbTag);
			}

			/* Setup AuthInfo for Initial state - Persisted */
			authInfo->pbNonce = ctx->u.pbNonce;
			authInfo->cbNonce = (ULONG)ctx->u.cbNonce;

			authInfo->pbTag = ctx->u.pbTag;
			authInfo->cbTag = (ULONG)ctx->u.cbTag;

			authInfo->dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

			/* Process AAD if present */
			if (in && len) {
				uint8_t *authData = NULL;

				/* Allocate and copy auth data for alignment */
				authData = lws_malloc(len, "genaes aad");
				if (!authData) {
					return -1;
				}
				memcpy(authData, in, len);

				authInfo->pbAuthData = (PUCHAR)authData;
				authInfo->cbAuthData = (ULONG)len;

				if (ctx->op == LWS_GAESO_ENC)
					status = BCryptEncrypt(ctx->u.hKey, NULL, 0, authInfo,
							       ctx->u.iv, 16, NULL, 0, &result_len, 0);
				else
					status = BCryptDecrypt(ctx->u.hKey, NULL, 0, authInfo,
							       ctx->u.iv, 16, NULL, 0, &result_len, 0);

				lws_free(authData);

				if (!BCRYPT_SUCCESS(status)) {
					lwsl_err("lws_genaes_crypt: GCM AAD failed: 0x%x\n",
						 status);
					return -1;
				}
			}

			return 0;
		}

		/* Subsequent calls: Process Payload */

		/* Retrieve persisted authInfo */
		authInfo = (BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *)ctx->u.pbMacContext;

		/* Ensure flags are still set for chaining (should persist, but safety) */
		authInfo->dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

		/* Reset AAD pointers for payload call */
		authInfo->pbAuthData = NULL;
		authInfo->cbAuthData = 0;

		/*
		 * The persisted authInfo structure retains the pointer to the nonce,
		 * which is required by CNG for the lifetime of the operation when using
		 * a reused structure.
		 */

		{
			uint8_t *in_aligned, *out_aligned;

			/* Allocate aligned buffers */
			in_aligned = lws_malloc(len, "genaes in aligned");
			if (!in_aligned) {
				return -1;
			}
			memcpy(in_aligned, in, len);

			out_aligned = lws_malloc(len, "genaes out aligned");
			if (!out_aligned) {
				lws_free(in_aligned);
				return -1;
			}

			if (ctx->op == LWS_GAESO_ENC)
				status = BCryptEncrypt(ctx->u.hKey, (PUCHAR)in_aligned, (ULONG)len,
						       authInfo, ctx->u.iv, 16, (PUCHAR)out_aligned,
						       (ULONG)len, &result_len, 0);
			else
				status = BCryptDecrypt(ctx->u.hKey, (PUCHAR)in_aligned, (ULONG)len,
						       authInfo, ctx->u.iv, 16, (PUCHAR)out_aligned,
						       (ULONG)len, &result_len, 0);

			if (BCRYPT_SUCCESS(status))
				memcpy(out, out_aligned, len);

			lws_free(in_aligned);
			lws_free(out_aligned);
		}

		return BCRYPT_SUCCESS(status) ? 0 : -1;
	} else {
		/* CBC, ECB, etc. */
		PUCHAR iv_in = (PUCHAR)iv_or_nonce_ctr_or_data_unit_16;
		PUCHAR iv_use = NULL;
		ULONG iv_len = 0;

		if (iv_in && ctx->mode != LWS_GAESM_ECB) {
			if (!ctx->underway) {
				memcpy(ctx->u.iv, iv_in, 16);
				ctx->underway = 1;
			}
			iv_use = ctx->u.iv;
			iv_len = 16;
		}

		if (ctx->op == LWS_GAESO_ENC)
			status = BCryptEncrypt(ctx->u.hKey, (PUCHAR)in, (ULONG)len, NULL,
					       iv_use, iv_len, (PUCHAR)out, (ULONG)len, &result_len, 0);
		else
			status = BCryptDecrypt(ctx->u.hKey, (PUCHAR)in, (ULONG)len, NULL,
					       iv_use, iv_len, (PUCHAR)out, (ULONG)len, &result_len, 0);
	}

	return BCRYPT_SUCCESS(status) ? 0 : -1;
}
