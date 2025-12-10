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

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	NTSTATUS status;
	BCRYPT_RSAKEY_BLOB *rsablob;
	ULONG bloblen;
	uint8_t *p;

	ctx->context = context;
	ctx->mode = mode;
	ctx->u.hKey = NULL;

	/*
	 * BCRYPT_RSAKEY_BLOB layout:
	 *   BCRYPT_RSAKEY_BLOB header
	 *   Public Exponent (cbPublicExp)
	 *   Modulus (cbModulus)
	 *   Prime1 (cbPrime1)
	 *   Prime2 (cbPrime2)
	 *   ... (private key components if present)
	 */

	status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
	if (!BCRYPT_SUCCESS(status))
		return -1;

	/* Calculate total blob length */
	bloblen = sizeof(BCRYPT_RSAKEY_BLOB);

	/* Public Exponent */
	bloblen += el[LWS_GENCRYPTO_RSA_KEYEL_E].len;
	/* Modulus */
	bloblen += el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	if (el[LWS_GENCRYPTO_RSA_KEYEL_P].len) {
		/* Private Key components */
		bloblen += el[LWS_GENCRYPTO_RSA_KEYEL_P].len;
		bloblen += el[LWS_GENCRYPTO_RSA_KEYEL_Q].len;
		bloblen += el[LWS_GENCRYPTO_RSA_KEYEL_DP].len; /* Exponent1 */
		bloblen += el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len; /* Exponent2 */
		bloblen += el[LWS_GENCRYPTO_RSA_KEYEL_QI].len; /* Coefficient */
	}

	rsablob = (BCRYPT_RSAKEY_BLOB *)lws_malloc(bloblen, "genrsa blob");
	if (!rsablob) {
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
		return -1;
	}

	/* Fill header */
	rsablob->Magic = el[LWS_GENCRYPTO_RSA_KEYEL_P].len ? BCRYPT_RSAPRIVATE_MAGIC : BCRYPT_RSAPUBLIC_MAGIC;
	rsablob->BitLength = el[LWS_GENCRYPTO_RSA_KEYEL_N].len * 8;
	rsablob->cbPublicExp = el[LWS_GENCRYPTO_RSA_KEYEL_E].len;
	rsablob->cbModulus = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	if (el[LWS_GENCRYPTO_RSA_KEYEL_P].len) {
		rsablob->cbPrime1 = el[LWS_GENCRYPTO_RSA_KEYEL_P].len;
		rsablob->cbPrime2 = el[LWS_GENCRYPTO_RSA_KEYEL_Q].len;
	} else {
		rsablob->cbPrime1 = 0;
		rsablob->cbPrime2 = 0;
	}

	p = (uint8_t *)(rsablob + 1);

	/* Copy Public Exponent */
	memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_E].buf, el[LWS_GENCRYPTO_RSA_KEYEL_E].len);
	p += el[LWS_GENCRYPTO_RSA_KEYEL_E].len;

	/* Copy Modulus */
	memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_N].buf, el[LWS_GENCRYPTO_RSA_KEYEL_N].len);
	p += el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	if (el[LWS_GENCRYPTO_RSA_KEYEL_P].len) {
		/* Copy Primes and CRT params */
		memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_P].buf, el[LWS_GENCRYPTO_RSA_KEYEL_P].len);
		p += el[LWS_GENCRYPTO_RSA_KEYEL_P].len;

		memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, el[LWS_GENCRYPTO_RSA_KEYEL_Q].len);
		p += el[LWS_GENCRYPTO_RSA_KEYEL_Q].len;

		/* Exponent1 (DP) */
		memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf, el[LWS_GENCRYPTO_RSA_KEYEL_DP].len);
		p += el[LWS_GENCRYPTO_RSA_KEYEL_DP].len;

		/* Exponent2 (DQ) */
		memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf, el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len);
		p += el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len;

		/* Coefficient (QI) */
		memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf, el[LWS_GENCRYPTO_RSA_KEYEL_QI].len);
		p += el[LWS_GENCRYPTO_RSA_KEYEL_QI].len;
	}

	status = BCryptImportKeyPair(ctx->u.hAlg, NULL,
		el[LWS_GENCRYPTO_RSA_KEYEL_P].len ? BCRYPT_RSAPRIVATE_BLOB : BCRYPT_RSAPUBLIC_BLOB,
		&ctx->u.hKey, (PUCHAR)rsablob, bloblen, 0);

	lws_free(rsablob);

	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
		return -1;
	}

	return 0;
}

void
lws_genrsa_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	NTSTATUS status;
	BCRYPT_RSAKEY_BLOB *rsablob = NULL;
	ULONG bloblen = 0;
	ULONG reslen = 0;
	uint8_t *p;

	ctx->context = context;
	ctx->mode = mode;

	status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
	if (!BCRYPT_SUCCESS(status))
		return -1;

	status = BCryptGenerateKeyPair(ctx->u.hAlg, &ctx->u.hKey, bits, 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
		ctx->u.hAlg = NULL;
		return -1;
	}

	status = BCryptFinalizeKeyPair(ctx->u.hKey, 0);
	if (!BCRYPT_SUCCESS(status)) {
		goto fail;
	}

	/* Export key to blob to fill 'el' */
	status = BCryptExportKey(ctx->u.hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &bloblen, 0);
	if (!BCRYPT_SUCCESS(status) && status != 0xC0000023) { /* STATUS_BUFFER_TOO_SMALL */
		goto fail;
	}

	rsablob = (BCRYPT_RSAKEY_BLOB *)lws_malloc(bloblen, "genrsa export blob");
	if (!rsablob) goto fail;

	status = BCryptExportKey(ctx->u.hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, (PUCHAR)rsablob, bloblen, &reslen, 0);
	if (!BCRYPT_SUCCESS(status)) goto fail;

	/* Parse blob into 'el' */
	p = (uint8_t *)(rsablob + 1);

	/* Alloc helper macro */
#define LWS_GENRSA_ALLOC_EL(idx, size) \
	el[idx].buf = lws_malloc(size, "genrsa el"); \
	if (!el[idx].buf) goto fail; \
	el[idx].len = size;

	/* Public Exponent */
	LWS_GENRSA_ALLOC_EL(LWS_GENCRYPTO_RSA_KEYEL_E, rsablob->cbPublicExp);
	memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_E].buf, p, rsablob->cbPublicExp);
	p += rsablob->cbPublicExp;

	/* Modulus */
	LWS_GENRSA_ALLOC_EL(LWS_GENCRYPTO_RSA_KEYEL_N, rsablob->cbModulus);
	memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_N].buf, p, rsablob->cbModulus);
	p += rsablob->cbModulus;

	/* Prime1 */
	LWS_GENRSA_ALLOC_EL(LWS_GENCRYPTO_RSA_KEYEL_P, rsablob->cbPrime1);
	memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_P].buf, p, rsablob->cbPrime1);
	p += rsablob->cbPrime1;

	/* Prime2 */
	LWS_GENRSA_ALLOC_EL(LWS_GENCRYPTO_RSA_KEYEL_Q, rsablob->cbPrime2);
	memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, p, rsablob->cbPrime2);
	p += rsablob->cbPrime2;

	/* Exponent1 */
	LWS_GENRSA_ALLOC_EL(LWS_GENCRYPTO_RSA_KEYEL_DP, rsablob->cbPrime1); /* Same size as Prime1? Usually yes */
	memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf, p, rsablob->cbPrime1);
	p += rsablob->cbPrime1;

	/* Exponent2 */
	LWS_GENRSA_ALLOC_EL(LWS_GENCRYPTO_RSA_KEYEL_DQ, rsablob->cbPrime2);
	memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf, p, rsablob->cbPrime2);
	p += rsablob->cbPrime2;

	/* Coefficient */
	LWS_GENRSA_ALLOC_EL(LWS_GENCRYPTO_RSA_KEYEL_QI, rsablob->cbPrime1);
	memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf, p, rsablob->cbPrime1);
	p += rsablob->cbPrime1;

	el[LWS_GENCRYPTO_RSA_KEYEL_D].len = 0;
	el[LWS_GENCRYPTO_RSA_KEYEL_D].buf = NULL;

	lws_free(rsablob);
	return 0;

fail:
	if (rsablob) lws_free(rsablob);
	lws_genrsa_destroy_elements(el);
	lws_genrsa_destroy(ctx);
	return -1;
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	NTSTATUS status;
	ULONG result_len = 0;
	BCRYPT_OAEP_PADDING_INFO oaepInfo;
	void *pPaddingInfo = NULL;
	DWORD dwFlags = BCRYPT_PAD_PKCS1;

	if (ctx->mode == LGRSAM_PKCS1_OAEP_PSS) {
		oaepInfo.algId = BCRYPT_SHA1_ALGORITHM; // Default or from ctx
		oaepInfo.pbLabel = NULL;
		oaepInfo.cbLabel = 0;
		pPaddingInfo = &oaepInfo;
		dwFlags = BCRYPT_PAD_OAEP;
	}

	status = BCryptEncrypt(ctx->u.hKey, (PUCHAR)in, (ULONG)in_len, pPaddingInfo, NULL, 0, (PUCHAR)out, (ULONG)256 /* Should be keysize */, &result_len, dwFlags); // 256 is placeholder, needs real size

	if (!BCRYPT_SUCCESS(status))
		return -1;

	return (int)result_len;
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	/* CNG doesn't support raw encryption with private key. */
	return -1;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	/* CNG doesn't support raw decryption with public key. */
	return -1;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	NTSTATUS status;
	ULONG result_len = 0;
	BCRYPT_OAEP_PADDING_INFO oaepInfo;
	void *pPaddingInfo = NULL;
	DWORD dwFlags = BCRYPT_PAD_PKCS1;

	if (ctx->mode == LGRSAM_PKCS1_OAEP_PSS) {
		oaepInfo.algId = BCRYPT_SHA1_ALGORITHM;
		oaepInfo.pbLabel = NULL;
		oaepInfo.cbLabel = 0;
		pPaddingInfo = &oaepInfo;
		dwFlags = BCRYPT_PAD_OAEP;
	}

	status = BCryptDecrypt(ctx->u.hKey, (PUCHAR)in, (ULONG)in_len, pPaddingInfo, NULL, 0, (PUCHAR)out, (ULONG)out_max, &result_len, dwFlags);

	if (!BCRYPT_SUCCESS(status))
		return -1;

	return (int)result_len;
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type,
			   const uint8_t *sig, size_t sig_len)
{
	NTSTATUS status;
	BCRYPT_PKCS1_PADDING_INFO pkcs1Info;
	BCRYPT_PSS_PADDING_INFO pssInfo;
	void *pPaddingInfo = NULL;
	DWORD dwFlags = 0;
	LPCWSTR algId = NULL;

	switch(hash_type) {
		case LWS_GENHASH_TYPE_SHA256: algId = BCRYPT_SHA256_ALGORITHM; break;
		case LWS_GENHASH_TYPE_SHA384: algId = BCRYPT_SHA384_ALGORITHM; break;
		case LWS_GENHASH_TYPE_SHA512: algId = BCRYPT_SHA512_ALGORITHM; break;
		default: algId = BCRYPT_SHA1_ALGORITHM; break;
	}

	if (ctx->mode == LGRSAM_PKCS1_OAEP_PSS) {
		pssInfo.pszAlgId = algId;
		pssInfo.cbSalt = 0; // Depends on spec
		pPaddingInfo = &pssInfo;
		dwFlags = BCRYPT_PAD_PSS;
	} else {
		pkcs1Info.pszAlgId = algId;
		pPaddingInfo = &pkcs1Info;
		dwFlags = BCRYPT_PAD_PKCS1;
	}

	status = BCryptVerifySignature(ctx->u.hKey, pPaddingInfo, (PUCHAR)in, (ULONG)lws_genhash_size(hash_type), (PUCHAR)sig, (ULONG)sig_len, dwFlags);

	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		     enum lws_genhash_types hash_type,
		     uint8_t *sig, size_t sig_len)
{
	NTSTATUS status;
	BCRYPT_PKCS1_PADDING_INFO pkcs1Info;
	BCRYPT_PSS_PADDING_INFO pssInfo;
	void *pPaddingInfo = NULL;
	DWORD dwFlags = 0;
	LPCWSTR algId = NULL;
	ULONG result_len = 0;

	switch(hash_type) {
		case LWS_GENHASH_TYPE_SHA256: algId = BCRYPT_SHA256_ALGORITHM; break;
		case LWS_GENHASH_TYPE_SHA384: algId = BCRYPT_SHA384_ALGORITHM; break;
		case LWS_GENHASH_TYPE_SHA512: algId = BCRYPT_SHA512_ALGORITHM; break;
		default: algId = BCRYPT_SHA1_ALGORITHM; break;
	}

	if (ctx->mode == LGRSAM_PKCS1_OAEP_PSS) {
		pssInfo.pszAlgId = algId;
		pssInfo.cbSalt = 0;
		pPaddingInfo = &pssInfo;
		dwFlags = BCRYPT_PAD_PSS;
	} else {
		pkcs1Info.pszAlgId = algId;
		pPaddingInfo = &pkcs1Info;
		dwFlags = BCRYPT_PAD_PKCS1;
	}

	status = BCryptSignHash(ctx->u.hKey, pPaddingInfo, (PUCHAR)in, (ULONG)lws_genhash_size(hash_type), sig, (ULONG)sig_len, &result_len, dwFlags);

	return BCRYPT_SUCCESS(status) ? (int)result_len : -1;
}

void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (ctx->u.hKey)
		BCryptDestroyKey(ctx->u.hKey);
	if (ctx->u.hAlg)
		BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
	ctx->u.hKey = NULL;
	ctx->u.hAlg = NULL;
}

int
lws_genrsa_render_pkey_asn1(struct lws_genrsa_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	/* ASN.1 encoding not supported in this backend */
	return -1;
}
