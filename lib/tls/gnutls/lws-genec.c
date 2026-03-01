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

const struct lws_ec_curves lws_ec_curves[4] = {
	{ "P-256", GNUTLS_ECC_CURVE_SECP256R1, 32 },
	{ "P-384", GNUTLS_ECC_CURVE_SECP384R1, 48 },
	{ "P-521", GNUTLS_ECC_CURVE_SECP521R1, 66 },
	{ NULL, 0, 0 }
};

static gnutls_ecc_curve_t
lws_genec_curve_to_gnutls(const char *name)
{
	int n = 0;

	while (lws_ec_curves[n].name) {
		if (!strcmp(name, lws_ec_curves[n].name))
			return (gnutls_ecc_curve_t)lws_ec_curves[n].tls_lib_nid;
		n++;
	}

	return GNUTLS_ECC_CURVE_INVALID;
}

static int
lws_gnutls_export_bignum_to_keyelem(gnutls_datum_t *in,
				    struct lws_gencrypto_keyelem *el,
				    int keybytes)
{
	el->len = (uint32_t)keybytes;
	el->buf = lws_zalloc((size_t)keybytes, "ec");
	if (!el->buf)
		return 1;

	if (in->size <= (unsigned int)keybytes) {
		memcpy(el->buf + keybytes - in->size, in->data, in->size);
	} else if (in->size == (unsigned int)keybytes + 1 && in->data[0] == 0) {
		memcpy(el->buf, in->data + 1, (size_t)keybytes);
	} else {
		/* It's too big and not just a leading zero... */
		lws_free_set_NULL(el->buf);
		return 1;
	}
	return 0;
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
	gnutls_datum_t x = {0, 0}, y = {0, 0}, d = {0, 0};
	gnutls_ecc_curve_t curve;
	const struct lws_ec_curves *c;
	int keybytes;
	uint8_t *x_pad = NULL, *y_pad = NULL, *d_pad = NULL;
	int ret = 1;

	curve = lws_genec_curve_to_gnutls((const char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (curve == GNUTLS_ECC_CURVE_INVALID)
		return 1;

	c = lws_genec_curve(ctx->curve_table,
			    (const char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (!c)
		return 1;

	keybytes = c->key_bytes;

	if (el[LWS_GENCRYPTO_EC_KEYEL_X].len) {
		x_pad = lws_zalloc((size_t)keybytes, "x_pad");
		if (!x_pad) goto bail;
		if (el[LWS_GENCRYPTO_EC_KEYEL_X].len <= (uint32_t)keybytes) {
			memcpy(x_pad + keybytes - el[LWS_GENCRYPTO_EC_KEYEL_X].len,
			       el[LWS_GENCRYPTO_EC_KEYEL_X].buf,
			       el[LWS_GENCRYPTO_EC_KEYEL_X].len);
		} else if (el[LWS_GENCRYPTO_EC_KEYEL_X].len == (uint32_t)keybytes + 1 && el[LWS_GENCRYPTO_EC_KEYEL_X].buf[0] == 0) {
			memcpy(x_pad, el[LWS_GENCRYPTO_EC_KEYEL_X].buf + 1, (size_t)keybytes);
		} else {
			goto bail;
		}
		x.data = x_pad;
		x.size = (unsigned int)keybytes;
	}

	if (el[LWS_GENCRYPTO_EC_KEYEL_Y].len) {
		y_pad = lws_zalloc((size_t)keybytes, "y_pad");
		if (!y_pad) goto bail;
		if (el[LWS_GENCRYPTO_EC_KEYEL_Y].len <= (uint32_t)keybytes) {
			memcpy(y_pad + keybytes - el[LWS_GENCRYPTO_EC_KEYEL_Y].len,
			       el[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
			       el[LWS_GENCRYPTO_EC_KEYEL_Y].len);
		} else if (el[LWS_GENCRYPTO_EC_KEYEL_Y].len == (uint32_t)keybytes + 1 && el[LWS_GENCRYPTO_EC_KEYEL_Y].buf[0] == 0) {
			memcpy(y_pad, el[LWS_GENCRYPTO_EC_KEYEL_Y].buf + 1, (size_t)keybytes);
		} else {
			goto bail;
		}
		y.data = y_pad;
		y.size = (unsigned int)keybytes;
	}

	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len) {
		d_pad = lws_zalloc((size_t)keybytes, "d_pad");
		if (!d_pad) goto bail;
		if (el[LWS_GENCRYPTO_EC_KEYEL_D].len <= (uint32_t)keybytes) {
			memcpy(d_pad + keybytes - el[LWS_GENCRYPTO_EC_KEYEL_D].len,
			       el[LWS_GENCRYPTO_EC_KEYEL_D].buf,
			       el[LWS_GENCRYPTO_EC_KEYEL_D].len);
		} else if (el[LWS_GENCRYPTO_EC_KEYEL_D].len == (uint32_t)keybytes + 1 && el[LWS_GENCRYPTO_EC_KEYEL_D].buf[0] == 0) {
			memcpy(d_pad, el[LWS_GENCRYPTO_EC_KEYEL_D].buf + 1, (size_t)keybytes);
		} else {
			goto bail;
		}
		d.data = d_pad;
		d.size = (unsigned int)keybytes;
	}

	if (side == LDHS_OURS) {
		if (d.size) {
			if (gnutls_privkey_init(&ctx->priv) < 0)
				goto bail;
			if (gnutls_privkey_import_ecc_raw(ctx->priv, curve, &x, &y, &d) < 0) {
				gnutls_privkey_deinit(ctx->priv);
				goto bail;
			}
			ctx->has_private = 1;
		}
		if (x.size && y.size) {
			if (gnutls_pubkey_init(&ctx->pub) < 0)
				goto bail;
			if (gnutls_pubkey_import_ecc_raw(ctx->pub, curve, &x, &y) < 0) {
				gnutls_pubkey_deinit(ctx->pub);
				goto bail;
			}
		}
	} else {
		/* LDHS_THEIRS - for ECDH we need the peer public key */
		if (x.size && y.size) {
			/* LWS generic EC doesn't have a separate peer pubkey handle usually,
			 * but we might need one for ECDH.
			 * Actually we can just store it in ctx->pub if it's the peer's.
			 */
			if (gnutls_pubkey_init(&ctx->pub) < 0)
				goto bail;
			if (gnutls_pubkey_import_ecc_raw(ctx->pub, curve, &x, &y) < 0) {
				gnutls_pubkey_deinit(ctx->pub);
				goto bail;
			}
		}
	}

	ret = 0;
bail:
	lws_free(x_pad);
	lws_free(y_pad);
	lws_free(d_pad);

	return ret;

	return 0;
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
		        const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	gnutls_ecc_curve_t curve;
	gnutls_datum_t x, y, d;
	int ret = 1;

	const struct lws_ec_curves *c;

	unsigned int bits;

	curve = lws_genec_curve_to_gnutls(curve_name);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		lwsl_err("%s: unknown curve %s\n", __func__, curve_name);
		return -1;
	}

	c = lws_genec_curve(ctx->curve_table, curve_name);
	if (!c)
		return -1;

	if (gnutls_privkey_init(&ctx->priv) < 0)
		return -1;

	if (!strcmp(curve_name, "P-256"))
		bits = 256;
	else if (!strcmp(curve_name, "P-384"))
		bits = 384;
	else if (!strcmp(curve_name, "P-521"))
		bits = 521;
	else
		bits = c->key_bytes * 8;

	if (gnutls_privkey_generate(ctx->priv, GNUTLS_PK_EC, bits, 0) < 0) {
		lwsl_err("%s: gnutls_privkey_generate failed\n", __func__);
		goto bail;
	}

	if (gnutls_privkey_export_ecc_raw(ctx->priv, &curve, &x, &y, &d) < 0) {
		lwsl_err("%s: export failed\n", __func__);
		goto bail;
	}

	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(curve_name) + 1;
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = lws_malloc(
				el[LWS_GENCRYPTO_EC_KEYEL_CRV].len, "ec");
	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
		goto bail_datum;
	strcpy((char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name);

	if (lws_gnutls_export_bignum_to_keyelem(&x, &el[LWS_GENCRYPTO_EC_KEYEL_X], c->key_bytes))
		goto bail_datum;
	if (lws_gnutls_export_bignum_to_keyelem(&y, &el[LWS_GENCRYPTO_EC_KEYEL_Y], c->key_bytes))
		goto bail_datum;
	if (lws_gnutls_export_bignum_to_keyelem(&d, &el[LWS_GENCRYPTO_EC_KEYEL_D], c->key_bytes))
		goto bail_datum;

	ctx->has_private = 1;
	ret = 0;

bail_datum:
	gnutls_free(x.data);
	gnutls_free(y.data);
	gnutls_free(d.data);
bail:
	if (ret)
		gnutls_privkey_deinit(ctx->priv);

	return ret;
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
		  int *ss_len)
{
	gnutls_datum_t secret;
	int ret;

	if (!ctx->has_private)
		return -1;

	ret = gnutls_privkey_derive_secret(ctx->priv, ctx->pub, NULL, &secret, 0);
	if (ret < 0) {
		lwsl_err("%s: gnutls_privkey_derive_secret failed: %s\n",
			 __func__, gnutls_strerror(ret));
		return -1;
	}

	if ((int)secret.size > *ss_len) {
		if ((int)secret.size == *ss_len + 1 && secret.data[0] == 0) {
			memcpy(ss, secret.data + 1, (size_t)*ss_len);
		} else {
			gnutls_free(secret.data);
			return -1;
		}
	} else if ((int)secret.size < *ss_len) {
		int pad_len = *ss_len - (int)secret.size;
		memset(ss, 0, (size_t)pad_len);
		memcpy(ss + pad_len, secret.data, secret.size);
	} else {
		memcpy(ss, secret.data, secret.size);
	}

	/* keep *ss_len as the requested derivation size (keybytes of the curve), which is the padded length */

	gnutls_free(secret.data);

	return 0;
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

	int ret;
	gnutls_datum_t r, s;
	int keybytes = lws_gencrypto_bits_to_bytes(keybits);

	if ((int)sig_len != keybytes * 2) {
		lwsl_err("%s: sig buf size %d vs %d\n", __func__,
			 (int)sig_len, keybytes * 2);
		return -1;
	}

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA256: alg = GNUTLS_SIGN_ECDSA_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: alg = GNUTLS_SIGN_ECDSA_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: alg = GNUTLS_SIGN_ECDSA_SHA512; break;
	default: return -1;
	}

	v_hash.data = (uint8_t *)in;
	v_hash.size = (unsigned int)lws_genhash_size(hash_type);

	r.data = (uint8_t *)sig;
	r.size = (unsigned int)keybytes;
	s.data = (uint8_t *)sig + keybytes;
	s.size = (unsigned int)keybytes;

	if (gnutls_encode_rs_value(&v_sig, &r, &s) < 0)
		return -1;

	ret = gnutls_pubkey_verify_hash2(ctx->pub, alg, 0, &v_hash, &v_sig);
	gnutls_free(v_sig.data);

	if (ret < 0)
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

	gnutls_datum_t r, s;
	int keybytes = lws_gencrypto_bits_to_bytes(keybits);

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA256: alg = GNUTLS_SIGN_ECDSA_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: alg = GNUTLS_SIGN_ECDSA_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: alg = GNUTLS_SIGN_ECDSA_SHA512; break;
	default: return -1;
	}

	if ((int)sig_len != keybytes * 2) {
		lwsl_err("%s: sig buf size %d vs %d\n", __func__,
			 (int)sig_len, keybytes * 2);
		return -1;
	}

	v_hash.data = (uint8_t *)in;
	v_hash.size = (unsigned int)lws_genhash_size(hash_type);

	if (gnutls_privkey_sign_hash2(ctx->priv, alg, 0, &v_hash, &v_sig) < 0)
		return -1;

	if (gnutls_decode_rs_value(&v_sig, &r, &s) < 0) {
		gnutls_free(v_sig.data);
		return -1;
	}

	gnutls_free(v_sig.data);

	memset(sig, 0, sig_len);

	/* copy r */
	if (r.size <= (unsigned int)keybytes) {
		memcpy(sig + keybytes - r.size, r.data, r.size);
	} else if (r.size == (unsigned int)keybytes + 1 && r.data[0] == 0) {
		/* skip leading zero byte */
		memcpy(sig, r.data + 1, (size_t)keybytes);
	} else {
		gnutls_free(r.data);
		gnutls_free(s.data);
		return -1;
	}

	/* copy s */
	if (s.size <= (unsigned int)keybytes) {
		memcpy(sig + 2 * keybytes - s.size, s.data, s.size);
	} else if (s.size == (unsigned int)keybytes + 1 && s.data[0] == 0) {
		/* skip leading zero byte */
		memcpy(sig + keybytes, s.data + 1, (size_t)keybytes);
	} else {
		gnutls_free(r.data);
		gnutls_free(s.data);
		return -1;
	}

	gnutls_free(r.data);
	gnutls_free(s.data);

	return keybytes * 2;
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
