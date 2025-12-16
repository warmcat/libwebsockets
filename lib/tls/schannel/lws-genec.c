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
 * We need to map integer IDs to BCRYPT string constants.
 * SChannel/CNG doesn't use NIDs like OpenSSL.
 */
enum {
	LWS_SCHANNEL_CURVE_P256 = 1,
	LWS_SCHANNEL_CURVE_P384,
	LWS_SCHANNEL_CURVE_P521,
};

const struct lws_ec_curves lws_ec_curves[4] = {
	/*
	 * These are the curves we are willing to use by default...
	 *
	 * The 3 recommended+ (P-256) and optional curves in RFC7518 7.6
	 *
	 * Specific keys lengths from RFC8422 p20
	 */
	{ "P-256", LWS_SCHANNEL_CURVE_P256, 32 },
	{ "P-384", LWS_SCHANNEL_CURVE_P384, 48 },
	{ "P-521", LWS_SCHANNEL_CURVE_P521, 66 },

	{ NULL, 0, 0 }
};

static LPCWSTR
lws_schannel_get_curve_alg(int nid, int is_ecdsa)
{
	switch (nid) {
	case LWS_SCHANNEL_CURVE_P256:
		return is_ecdsa ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_ECDH_P256_ALGORITHM;
	case LWS_SCHANNEL_CURVE_P384:
		return is_ecdsa ? BCRYPT_ECDSA_P384_ALGORITHM : BCRYPT_ECDH_P384_ALGORITHM;
	case LWS_SCHANNEL_CURVE_P521:
		return is_ecdsa ? BCRYPT_ECDSA_P521_ALGORITHM : BCRYPT_ECDH_P521_ALGORITHM;
	default:
		/* Default to P-256 if unknown or 0 */
		return is_ecdsa ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_ECDH_P256_ALGORITHM;
	}
}

int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	int nid = 0;

	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDH;
	ctx->u.hAlg = NULL;
	ctx->u.hKey = NULL;
	ctx->u.hKeyPeer = NULL;

	if (curve_table && curve_table->name)
		nid = curve_table->tls_lib_nid;

	/* Open specific algorithm provider based on curve if known */
	NTSTATUS status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, lws_schannel_get_curve_alg(nid, 0), NULL, 0);
	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	NTSTATUS status;
	BCRYPT_ECCKEY_BLOB *eccblob;
	ULONG bloblen;
	uint8_t *p;
	ULONG magic;
	ULONG keylen = el[LWS_GENCRYPTO_EC_KEYEL_X].len; /* Bytes in X coordinate */
	BCRYPT_KEY_HANDLE *target_key_handle;

	/* Determine target handle based on side */
	if (side == LDHS_OURS) {
		target_key_handle = &ctx->u.hKey;
	} else if (side == LDHS_THEIRS) {
		target_key_handle = &ctx->u.hKeyPeer;
	} else {
		return -1;
	}

	/* Determine Magic */
	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len) {
		/* Private Key */
		if (keylen == 32) magic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
		else if (keylen == 48) magic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
		else if (keylen == 66) magic = BCRYPT_ECDH_PRIVATE_P521_MAGIC; /* 521 bits = 66 bytes */
		else return -1;
	} else {
		/* Public Key */
		if (keylen == 32) magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
		else if (keylen == 48) magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
		else if (keylen == 66) magic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
		else return -1;
	}

	bloblen = sizeof(BCRYPT_ECCKEY_BLOB) + el[LWS_GENCRYPTO_EC_KEYEL_X].len + el[LWS_GENCRYPTO_EC_KEYEL_Y].len;
	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len)
		bloblen += el[LWS_GENCRYPTO_EC_KEYEL_D].len;

	eccblob = (BCRYPT_ECCKEY_BLOB *)lws_malloc(bloblen, "genecdh blob");
	if (!eccblob) return -1;

	eccblob->dwMagic = magic;
	eccblob->cbKey = keylen;

	p = (uint8_t *)(eccblob + 1);

	/* X */
	memcpy(p, el[LWS_GENCRYPTO_EC_KEYEL_X].buf, el[LWS_GENCRYPTO_EC_KEYEL_X].len);
	p += el[LWS_GENCRYPTO_EC_KEYEL_X].len;

	/* Y */
	memcpy(p, el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, el[LWS_GENCRYPTO_EC_KEYEL_Y].len);
	p += el[LWS_GENCRYPTO_EC_KEYEL_Y].len;

	/* D */
	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len) {
		memcpy(p, el[LWS_GENCRYPTO_EC_KEYEL_D].buf, el[LWS_GENCRYPTO_EC_KEYEL_D].len);
		p += el[LWS_GENCRYPTO_EC_KEYEL_D].len;
	}

	/* Close previous key if any */
	if (*target_key_handle) BCryptDestroyKey(*target_key_handle);

	status = BCryptImportKeyPair(ctx->u.hAlg, NULL,
		el[LWS_GENCRYPTO_EC_KEYEL_D].len ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_ECCPUBLIC_BLOB,
		target_key_handle, (PUCHAR)eccblob, bloblen, 0);

	lws_free(eccblob);

	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
		        const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	NTSTATUS status;
	ULONG bits = 256;
	BCRYPT_ECCKEY_BLOB *eccblob = NULL;
	ULONG bloblen = 0, reslen = 0;
	uint8_t *p;

	if (curve_name) {
		if (strstr(curve_name, "256")) bits = 256;
		else if (strstr(curve_name, "384")) bits = 384;
		else if (strstr(curve_name, "521")) bits = 521;
	}

	status = BCryptGenerateKeyPair(ctx->u.hAlg, &ctx->u.hKey, bits, 0);
	if (!BCRYPT_SUCCESS(status)) return -1;

	status = BCryptFinalizeKeyPair(ctx->u.hKey, 0);
	if (!BCRYPT_SUCCESS(status)) goto fail;

	/* Export to el */
	status = BCryptExportKey(ctx->u.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &bloblen, 0);
	if (!BCRYPT_SUCCESS(status) && status != 0xC0000023) goto fail;

	eccblob = (BCRYPT_ECCKEY_BLOB *)lws_malloc(bloblen, "genec export");
	if (!eccblob) goto fail;

	status = BCryptExportKey(ctx->u.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, (PUCHAR)eccblob, bloblen, &reslen, 0);
	if (!BCRYPT_SUCCESS(status)) goto fail;

	p = (uint8_t *)(eccblob + 1);

#define LWS_GENEC_ALLOC_EL(idx, size) \
	el[idx].buf = lws_malloc(size, "genec el"); \
	if (!el[idx].buf) goto fail; \
	el[idx].len = size;

	/* X */
	LWS_GENEC_ALLOC_EL(LWS_GENCRYPTO_EC_KEYEL_X, eccblob->cbKey);
	memcpy(el[LWS_GENCRYPTO_EC_KEYEL_X].buf, p, eccblob->cbKey);
	p += eccblob->cbKey;

	/* Y */
	LWS_GENEC_ALLOC_EL(LWS_GENCRYPTO_EC_KEYEL_Y, eccblob->cbKey);
	memcpy(el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, p, eccblob->cbKey);
	p += eccblob->cbKey;

	/* D */
	LWS_GENEC_ALLOC_EL(LWS_GENCRYPTO_EC_KEYEL_D, eccblob->cbKey);
	memcpy(el[LWS_GENCRYPTO_EC_KEYEL_D].buf, p, eccblob->cbKey);

	lws_free(eccblob);
	return 0;

fail:
	if (eccblob) lws_free(eccblob);
	lws_genec_destroy_elements(el);
	return -1;
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
		  int *ss_len)
{
	NTSTATUS status;
	BCRYPT_SECRET_HANDLE hSecret = NULL;
	ULONG reslen = 0;

	if (!ctx->u.hKey || !ctx->u.hKeyPeer)
		return -1;

	status = BCryptSecretAgreement(ctx->u.hKey, ctx->u.hKeyPeer, &hSecret, 0);
	if (!BCRYPT_SUCCESS(status)) return -1;

	/* Derive the raw secret */
	status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &reslen, 0);
	if (BCRYPT_SUCCESS(status) && reslen <= (ULONG)*ss_len) {
		status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, ss, reslen, &reslen, 0);
		*ss_len = (int)reslen;
	} else {
		status = -1;
	}

	if (hSecret) BCryptDestroySecret(hSecret);

	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	int nid = 0;

	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDSA;
	ctx->u.hKey = NULL;
	ctx->u.hKeyPeer = NULL;

	if (curve_table && curve_table->name)
		nid = curve_table->tls_lib_nid;

	/* Default to P256 alg provider or specific if known */
	NTSTATUS status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, lws_schannel_get_curve_alg(nid, 1), NULL, 0);
	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	/* Same as ECDH new keypair basically, just different alg provider potentially */
	return lws_genecdh_new_keypair(ctx, LDHS_OURS, curve_name, el);
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	/* Same as ECDH set key */
	return lws_genecdh_set_key(ctx, el, LDHS_OURS);
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 enum lws_genhash_types hash_type, int keybits,
				 const uint8_t *sig, size_t sig_len)
{
	NTSTATUS status;
	status = BCryptVerifySignature(ctx->u.hKey, NULL, (PUCHAR)in, (ULONG)lws_genhash_size(hash_type), (PUCHAR)sig, (ULONG)sig_len, 0);
	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type, int keybits,
			   uint8_t *sig, size_t sig_len)
{
	NTSTATUS status;
	ULONG res = 0;
	status = BCryptSignHash(ctx->u.hKey, NULL, (PUCHAR)in, (ULONG)lws_genhash_size(hash_type), sig, (ULONG)sig_len, &res, 0);
	return BCRYPT_SUCCESS(status) ? (int)res : -1;
}

void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (ctx->u.hKey) BCryptDestroyKey(ctx->u.hKey);
	if (ctx->u.hKeyPeer) BCryptDestroyKey(ctx->u.hKeyPeer);
	if (ctx->u.hAlg) BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
}
/*
void
lws_genec_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_EC_KEYEL_COUNT);
}
*/
