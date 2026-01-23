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

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types hash_type)
{
	gnutls_datum_t m, e, d, p, q, u, e1, e2;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	m.data = el[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
	m.size = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	e.data = el[LWS_GENCRYPTO_RSA_KEYEL_E].buf;
	e.size = el[LWS_GENCRYPTO_RSA_KEYEL_E].len;
	d.data = el[LWS_GENCRYPTO_RSA_KEYEL_D].buf;
	d.size = el[LWS_GENCRYPTO_RSA_KEYEL_D].len;
	p.data = el[LWS_GENCRYPTO_RSA_KEYEL_P].buf;
	p.size = el[LWS_GENCRYPTO_RSA_KEYEL_P].len;
	q.data = el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf;
	q.size = el[LWS_GENCRYPTO_RSA_KEYEL_Q].len;
	e1.data = el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf;
	e1.size = el[LWS_GENCRYPTO_RSA_KEYEL_DP].len;
	e2.data = el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf;
	e2.size = el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len;
	u.data = el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf;
	u.size = el[LWS_GENCRYPTO_RSA_KEYEL_QI].len;

	if (d.data) {
		if (gnutls_privkey_init(&ctx->priv) < 0)
			return 1;

		if (gnutls_privkey_import_rsa_raw(ctx->priv, &m, &e, &d, &p, &q, &u, &e1, &e2) < 0) {
			gnutls_privkey_deinit(ctx->priv);
			return 1;
		}
	}

	if (m.data && e.data) {
		if (gnutls_pubkey_init(&ctx->pub) < 0)
			return 1;

		if (gnutls_pubkey_import_rsa_raw(ctx->pub, &m, &e) < 0) {
			gnutls_pubkey_deinit(ctx->pub);
			return 1;
		}
	}

	return 0;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	/* TODO: Implement RSA key generation via gnutls_x509_privkey_generate */
	return 1;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	/* GnuTLS doesn't have a direct equivalent for RSA public decrypt
	 * that returns the decrypted data in its abstract API.
	 * This is typically used for signature verification.
	 */
	lwsl_err("%s: GnuTLS doesn't support public decrypt\n", __func__);
	return -1;
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	gnutls_datum_t v_in, v_out;
	int n;

	v_in.data = (uint8_t *)in;
	v_in.size = (unsigned int)in_len;

	n = gnutls_pubkey_encrypt_data(ctx->pub, 0, &v_in, &v_out);
	if (n < 0)
		return -1;

	memcpy(out, v_out.data, v_out.size);
	n = (int)v_out.size;
	gnutls_free(v_out.data);

	return n;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	gnutls_datum_t v_in, v_out;
	int n;

	v_in.data = (uint8_t *)in;
	v_in.size = (unsigned int)in_len;

	n = gnutls_privkey_decrypt_data(ctx->priv, 0, &v_in, &v_out);
	if (n < 0)
		return -1;

	if (v_out.size > out_max) {
		gnutls_free(v_out.data);
		return -1;
	}

	memcpy(out, v_out.data, v_out.size);
	n = (int)v_out.size;
	gnutls_free(v_out.data);

	return n;
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	/* Private encrypt is usually signing without hashing or with raw data */
	return -1;
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type,
			   const uint8_t *sig, size_t sig_len)
{
	gnutls_datum_t v_hash, v_sig;
	gnutls_sign_algorithm_t alg;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: alg = GNUTLS_SIGN_RSA_SHA1; break;
	case LWS_GENHASH_TYPE_SHA256: alg = GNUTLS_SIGN_RSA_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: alg = GNUTLS_SIGN_RSA_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: alg = GNUTLS_SIGN_RSA_SHA512; break;
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
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		     enum lws_genhash_types hash_type,
		     uint8_t *sig, size_t sig_len)
{
	gnutls_datum_t v_hash, v_sig;
	gnutls_sign_algorithm_t alg;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: alg = GNUTLS_SIGN_RSA_SHA1; break;
	case LWS_GENHASH_TYPE_SHA256: alg = GNUTLS_SIGN_RSA_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: alg = GNUTLS_SIGN_RSA_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: alg = GNUTLS_SIGN_RSA_SHA512; break;
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
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (ctx->priv)
		gnutls_privkey_deinit(ctx->priv);
	if (ctx->pub)
		gnutls_pubkey_deinit(ctx->pub);

	ctx->priv = NULL;
	ctx->pub = NULL;
}

int
lws_genrsa_render_pkey_asn1(struct lws_genrsa_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	return -1;
}
