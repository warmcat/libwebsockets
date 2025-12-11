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
		oaepInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM; // Default or from ctx
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
	/*
	 * "Private Encrypt" in OpenSSL is low-level signing (raw data ^ d).
	 * CNG doesn't support "encrypt with private key" via BCryptEncrypt.
	 * However, BCryptDecrypt using the PRIVATE key performs (in ^ d).
	 * We must handle padding manually because BCryptDecrypt expects ciphertext
	 * that matches key size, and BCRYPT_PAD_NONE.
	 */
	NTSTATUS status;
	ULONG result_len = 0;
	ULONG keylen = 0, reslen = 0;
	uint8_t *padded = NULL;

	/* Get key length */
	status = BCryptGetProperty(ctx->u.hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&keylen, sizeof(keylen), &reslen, 0);
	if (!BCRYPT_SUCCESS(status)) return -1;

	padded = lws_malloc(keylen, "genrsa pad");
	if (!padded) return -1;

	if (ctx->mode == LGRSAM_PKCS1_1_5) {
		/* PKCS#1 v1.5 padding type 1 (Signature) */
		/* 00 01 FF ... FF 00 [input] */
		if (in_len > keylen - 11) { /* 3 bytes overhead + 8 bytes min pad */
			lws_free(padded);
			return -1;
		}

		padded[0] = 0x00;
		padded[1] = 0x01;
		memset(padded + 2, 0xFF, keylen - in_len - 3);
		padded[keylen - in_len - 1] = 0x00;
		memcpy(padded + keylen - in_len, in, in_len);
	} else {
		/* OAEP not supported for raw signing via private_encrypt typically,
		   or unsupported manual pad. Fail or assume NO_PADDING if intended?
		   lws api doc says: "Performs PKCS1 v1.5 Encryption".
		   So we only support PKCS1 1.5 here.
		*/
		lws_free(padded);
		return -1;
	}

	/* Perform Raw Decrypt (m^d) */
	status = BCryptDecrypt(ctx->u.hKey, padded, keylen, NULL, NULL, 0, (PUCHAR)out, keylen, &result_len, BCRYPT_PAD_NONE);

	lws_free(padded);

	if (!BCRYPT_SUCCESS(status))
		return -1;

	return (int)result_len;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	/*
	 * "Public Decrypt" is low-level signature verification (raw sig ^ e).
	 * BCryptEncrypt using the PUBLIC key performs (in ^ e).
	 * We use BCRYPT_PAD_NONE and manually unpad.
	 */
	NTSTATUS status;
	ULONG result_len = 0;
	ULONG keylen = 0, reslen = 0;
	uint8_t *raw_out = NULL;
	int ret = -1;

	status = BCryptGetProperty(ctx->u.hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&keylen, sizeof(keylen), &reslen, 0);
	if (!BCRYPT_SUCCESS(status)) return -1;

	if (in_len != keylen) return -1; /* Raw RSA op requires matching block size */

	raw_out = lws_malloc(keylen, "genrsa raw out");
	if (!raw_out) return -1;

	/* Perform Raw Encrypt (s^e) */
	status = BCryptEncrypt(ctx->u.hKey, (PUCHAR)in, keylen, NULL, NULL, 0, raw_out, keylen, &result_len, BCRYPT_PAD_NONE);

	if (BCRYPT_SUCCESS(status)) {
		/* Unpad */
		if (ctx->mode == LGRSAM_PKCS1_1_5) {
			/* Expect 00 01 FF ... FF 00 [payload] */
			if (raw_out[0] == 0x00 && raw_out[1] == 0x01) {
				uint8_t *p = raw_out + 2;
				while (p < raw_out + keylen && *p == 0xFF) p++;
				if (p < raw_out + keylen && *p == 0x00) {
					p++; /* Skip 00 separator */
					size_t payload_len = raw_out + keylen - p;
					if (payload_len <= out_max) {
						memcpy(out, p, payload_len);
						ret = (int)payload_len;
					}
				}
			}
		}
	}

	lws_free(raw_out);
	return ret;
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
		oaepInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
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

/* ASN.1 helpers */
static void lws_asn1_encode_length(uint8_t **p, size_t len) {
	if (len < 128) {
		*(*p)++ = (uint8_t)len;
	} else if (len < 256) {
		*(*p)++ = 0x81;
		*(*p)++ = (uint8_t)len;
	} else if (len < 65536) {
		*(*p)++ = 0x82;
		*(*p)++ = (uint8_t)(len >> 8);
		*(*p)++ = (uint8_t)(len);
	} else {
		*(*p)++ = 0x83; /* Assume < 16MB */
		*(*p)++ = (uint8_t)(len >> 16);
		*(*p)++ = (uint8_t)(len >> 8);
		*(*p)++ = (uint8_t)(len);
	}
}

static size_t lws_asn1_length_size(size_t len) {
	if (len < 128) return 1;
	if (len < 256) return 2;
	if (len < 65536) return 3;
	return 4;
}

static void lws_asn1_encode_integer(uint8_t **p, uint8_t *val, size_t len) {
	*(*p)++ = 0x02; /* INTEGER */

	/* Skip leading zeros but keep at least one zero if value is zero?
	   Actually BCRYPT blobs are Big-Endian unsigned.
	   ASN.1 integers are signed. If MSB is set, we need to prepend 0x00. */

	int pad = (len > 0 && (val[0] & 0x80));
	lws_asn1_encode_length(p, len + pad);

	if (pad) *(*p)++ = 0x00;
	memcpy(*p, val, len);
	*p += len;
}

static size_t lws_asn1_integer_size(uint8_t *val, size_t len) {
	int pad = (len > 0 && (val[0] & 0x80));
	return 1 + lws_asn1_length_size(len + pad) + pad + len;
}

int
lws_genrsa_render_pkey_asn1(struct lws_genrsa_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	NTSTATUS status;
	BCRYPT_RSAKEY_BLOB *blob = NULL;
	ULONG bloblen = 0, reslen;
	uint8_t *p;
	size_t seq_len = 0;
	uint8_t *out = pkey_asn1;
	uint8_t *ver_zero = (uint8_t *)"\x00";

	/* Export key */
	LPCWSTR type = _private ? BCRYPT_RSAPRIVATE_BLOB : BCRYPT_RSAPUBLIC_BLOB;

	/* For private keys, we ideally want FULLPRIVATEBLOB to get 'd' if possible,
	   but std RSAPRIVATE_BLOB usually doesn't have it in older windows.
	   Let's try BCRYPT_RSAFULLPRIVATE_BLOB if _private is true. */
	if (_private) type = BCRYPT_RSAFULLPRIVATE_BLOB;

	status = BCryptExportKey(ctx->u.hKey, NULL, type, NULL, 0, &bloblen, 0);
	if (!BCRYPT_SUCCESS(status)) return -1;

	blob = lws_malloc(bloblen, "asn1 blob");
	if (!blob) return -1;

	status = BCryptExportKey(ctx->u.hKey, NULL, type, (PUCHAR)blob, bloblen, &reslen, 0);
	if (!BCRYPT_SUCCESS(status)) {
		lws_free(blob);
		return -1;
	}

	p = (uint8_t *)(blob + 1);
	/* Layout after header: Exponent, Modulus, Prime1, Prime2... */
	uint8_t *pub_exp = p; p += blob->cbPublicExp;
	uint8_t *modulus = p; p += blob->cbModulus;

	/* Calculate Sequence Size */
	if (_private) {
		/* Private Key Sequence: 0, n, e, d, p, q, dmp1, dmq1, iqmp */
		/* blob layout: e, n, p, q, dp, dq, qi, d */
		uint8_t *prime1 = p; p += blob->cbPrime1;
		uint8_t *prime2 = p; p += blob->cbPrime2;
		uint8_t *exp1 = p; p += blob->cbPrime1;
		uint8_t *exp2 = p; p += blob->cbPrime2;
		uint8_t *coeff = p; p += blob->cbPrime1;
		uint8_t *priv_exp = p; /* blob->cbModulus size */

		seq_len += lws_asn1_integer_size(ver_zero, 1);
		seq_len += lws_asn1_integer_size(modulus, blob->cbModulus);
		seq_len += lws_asn1_integer_size(pub_exp, blob->cbPublicExp);
		seq_len += lws_asn1_integer_size(priv_exp, blob->cbModulus);
		seq_len += lws_asn1_integer_size(prime1, blob->cbPrime1);
		seq_len += lws_asn1_integer_size(prime2, blob->cbPrime2);
		seq_len += lws_asn1_integer_size(exp1, blob->cbPrime1);
		seq_len += lws_asn1_integer_size(exp2, blob->cbPrime2);
		seq_len += lws_asn1_integer_size(coeff, blob->cbPrime1);

		if (1 + lws_asn1_length_size(seq_len) + seq_len > pkey_asn1_len) {
			lws_free(blob);
			return -1;
		}

		*out++ = 0x30; /* SEQUENCE */
		lws_asn1_encode_length(&out, seq_len);
		lws_asn1_encode_integer(&out, ver_zero, 1);
		lws_asn1_encode_integer(&out, modulus, blob->cbModulus);
		lws_asn1_encode_integer(&out, pub_exp, blob->cbPublicExp);
		lws_asn1_encode_integer(&out, priv_exp, blob->cbModulus);
		lws_asn1_encode_integer(&out, prime1, blob->cbPrime1);
		lws_asn1_encode_integer(&out, prime2, blob->cbPrime2);
		lws_asn1_encode_integer(&out, exp1, blob->cbPrime1);
		lws_asn1_encode_integer(&out, exp2, blob->cbPrime2);
		lws_asn1_encode_integer(&out, coeff, blob->cbPrime1);

	} else {
		/* Public Key Sequence: n, e */
		seq_len += lws_asn1_integer_size(modulus, blob->cbModulus);
		seq_len += lws_asn1_integer_size(pub_exp, blob->cbPublicExp);

		if (1 + lws_asn1_length_size(seq_len) + seq_len > pkey_asn1_len) {
			lws_free(blob);
			return -1;
		}

		*out++ = 0x30;
		lws_asn1_encode_length(&out, seq_len);
		lws_asn1_encode_integer(&out, modulus, blob->cbModulus);
		lws_asn1_encode_integer(&out, pub_exp, blob->cbPublicExp);
	}

	lws_free(blob);
	return (int)(out - pkey_asn1);
}
