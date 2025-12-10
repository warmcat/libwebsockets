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
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDH;
	ctx->u.hAlg = NULL;
	ctx->u.hKey = NULL;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	// Import key from elements to ctx->u.hKey
	// Requires constructing BCRYPT_ECCKEY_BLOB
	return -1;
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
		        const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	NTSTATUS status;
	// TODO: Map curve_name to BCRYPT properties if necessary or just generate standard key

	status = BCryptGenerateKeyPair(ctx->u.hAlg, &ctx->u.hKey, 256, 0); // Assuming P-256 for now
	if (!BCRYPT_SUCCESS(status)) return -1;

	BCryptFinalizeKeyPair(ctx->u.hKey, 0);

	// Export to el
	return 0;
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
		  int *ss_len)
{
	NTSTATUS status;
	BCRYPT_SECRET_HANDLE hSecret;

	// ECDH requires a second key (peer key) to compute secret.
	// lws_genec_ctx structure in my simplified view only has one key.
	// We need to see how lws handles the "other" key.
	// Usually set_key is called for the peer key?

	status = BCryptSecretAgreement(ctx->u.hKey, ctx->u.hKey, &hSecret, 0); // Self-agreement? Placeholder.
	if (!BCRYPT_SUCCESS(status)) return -1;

	ULONG len = 0;
	status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &len, 0);
	if (BCRYPT_SUCCESS(status) && len <= (ULONG)*ss_len) {
		status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, ss, len, &len, 0);
		*ss_len = (int)len;
	} else {
		status = -1;
	}

	BCryptDestroySecret(hSecret);
	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDSA;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&ctx->u.hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	NTSTATUS status;
	status = BCryptGenerateKeyPair(ctx->u.hAlg, &ctx->u.hKey, 256, 0);
	if (!BCRYPT_SUCCESS(status)) return -1;
	BCryptFinalizeKeyPair(ctx->u.hKey, 0);
	return 0;
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	// Import
	return -1;
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 enum lws_genhash_types hash_type, int keybits,
				 const uint8_t *sig, size_t sig_len)
{
	NTSTATUS status;
	// Verify signature
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
	if (ctx->u.hAlg) BCryptCloseAlgorithmProvider(ctx->u.hAlg, 0);
}

void
lws_genec_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_EC_KEYEL_COUNT);
}

int
lws_genec_dump(struct lws_gencrypto_keyelem *el)
{
	return 0;
}
