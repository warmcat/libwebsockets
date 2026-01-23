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
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

static gnutls_ecc_curve_t
lws_genec_curve_to_gnutls(const char *name)
{
	if (!strcmp(name, "P-256") || !strcmp(name, "secp256r1"))
		return GNUTLS_ECC_CURVE_SECP256R1;
	if (!strcmp(name, "P-384") || !strcmp(name, "secp384r1"))
		return GNUTLS_ECC_CURVE_SECP384R1;
	if (!strcmp(name, "P-521") || !strcmp(name, "secp521r1"))
		return GNUTLS_ECC_CURVE_SECP521R1;

	return GNUTLS_ECC_CURVE_INVALID;
}

int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDH;

	return 0;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	gnutls_datum_t x, y, d;
	gnutls_ecc_curve_t curve;

	curve = lws_genec_curve_to_gnutls((const char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (curve == GNUTLS_ECC_CURVE_INVALID)
		return 1;

	x.data = el[LWS_GENCRYPTO_EC_KEYEL_X].buf;
	x.size = el[LWS_GENCRYPTO_EC_KEYEL_X].len;
	y.data = el[LWS_GENCRYPTO_EC_KEYEL_Y].buf;
	y.size = el[LWS_GENCRYPTO_EC_KEYEL_Y].len;
	d.data = el[LWS_GENCRYPTO_EC_KEYEL_D].buf;
	d.size = el[LWS_GENCRYPTO_EC_KEYEL_D].len;

	if (side == LDHS_OURS) {
		if (d.data) {
			if (gnutls_privkey_init(&ctx->priv) < 0)
				return 1;
			if (gnutls_privkey_import_ecc_raw(ctx->priv, curve, &x, &y, &d) < 0) {
				gnutls_privkey_deinit(ctx->priv);
				return 1;
			}
			ctx->has_private = 1;
		}
		if (x.data && y.data) {
			if (gnutls_pubkey_init(&ctx->pub) < 0)
				return 1;
			if (gnutls_pubkey_import_ecc_raw(ctx->pub, curve, &x, &y) < 0) {
				gnutls_pubkey_deinit(ctx->pub);
				return 1;
			}
		}
	} else {
		/* LDHS_THEIRS - for ECDH we need the peer public key */
		if (x.data && y.data) {
			/* LWS generic EC doesn't have a separate peer pubkey handle usually,
			 * but we might need one for ECDH.
			 * Actually we can just store it in ctx->pub if it's the peer's.
			 */
			if (gnutls_pubkey_init(&ctx->pub) < 0)
				return 1;
			if (gnutls_pubkey_import_ecc_raw(ctx->pub, curve, &x, &y) < 0) {
				gnutls_pubkey_deinit(ctx->pub);
				return 1;
			}
		}
	}

	return 0;
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
		        const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	/* TODO: Implement EC key generation */
	return 1;
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
		  int *ss_len)
{
	/* TODO: Implement ECDH shared secret computation */
	/* GnuTLS uses gnutls_privkey_derive for this */
	return 1;
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDSA;

	return 0;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	/* TODO: Implement EC key generation */
	return 1;
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	return lws_genecdh_set_key(ctx, el, LDHS_OURS);
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 enum lws_genhash_types hash_type, int keybits,
				 const uint8_t *sig, size_t sig_len)
{
	gnutls_datum_t v_hash, v_sig;
	gnutls_sign_algorithm_t alg;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA256: alg = GNUTLS_SIGN_ECDSA_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: alg = GNUTLS_SIGN_ECDSA_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: alg = GNUTLS_SIGN_ECDSA_SHA512; break;
	default: return -1;
	}

	v_hash.data = (uint8_t *)in;
	v_hash.size = (unsigned int)lws_genhash_size(hash_type);
	v_sig.data = (uint8_t *)sig;
	v_sig.size = (unsigned int)sig_len;

	if (gnutls_pubkey_verify_hash2(ctx->pub, alg, 0, &v_hash, &v_sig) < 0)
		return -1;

	return 0;
}

int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type, int keybits,
			   uint8_t *sig, size_t sig_len)
{
	gnutls_datum_t v_hash, v_sig;
	gnutls_sign_algorithm_t alg;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA256: alg = GNUTLS_SIGN_ECDSA_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: alg = GNUTLS_SIGN_ECDSA_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: alg = GNUTLS_SIGN_ECDSA_SHA512; break;
	default: return -1;
	}

	v_hash.data = (uint8_t *)in;
	v_hash.size = (unsigned int)lws_genhash_size(hash_type);

	if (gnutls_privkey_sign_hash2(ctx->priv, alg, 0, &v_hash, &v_sig) < 0)
		return -1;

	if (v_sig.size > sig_len) {
		gnutls_free(v_sig.data);
		return -1;
	}

	memcpy(sig, v_sig.data, v_sig.size);
	gnutls_free(v_sig.data);

	return (int)v_sig.size;
}

void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (ctx->priv)
		gnutls_privkey_deinit(ctx->priv);
	if (ctx->pub)
		gnutls_pubkey_deinit(ctx->pub);

	ctx->priv = NULL;
	ctx->pub = NULL;
}
