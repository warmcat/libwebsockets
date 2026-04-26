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
#include "private-lib-tls-bearssl.h"

struct lws_br_prng_ctx {
	const br_prng_class *vtable;
	struct lws_context *context;
};

static void
lws_br_prng_init(const br_prng_class **ctx, const void *params, const void *seed, size_t seed_len)
{
	/* lws entropy pool doesn't need init here */
}

static void
lws_br_prng_generate(const br_prng_class **ctx, void *out, size_t len)
{
	struct lws_br_prng_ctx *lctx = (struct lws_br_prng_ctx *)ctx;
	lws_get_random(lctx->context, out, len);
}

static void
lws_br_prng_update(const br_prng_class **ctx, const void *seed, size_t seed_len)
{
	/* no-op */
}

static const br_prng_class lws_br_prng_vtable = {
	sizeof(struct lws_br_prng_ctx),
	lws_br_prng_init,
	lws_br_prng_generate,
	lws_br_prng_update
};

const struct lws_ec_curves lws_ec_curves[4] = {
	{ "P-256", BR_EC_secp256r1, 32 },
	{ "P-384", BR_EC_secp384r1, 48 },
	{ "P-521", BR_EC_secp521r1, 66 },
	{ NULL, 0, 0 }
};

static int lws_genec_curve_name_to_bearssl_curve(const char *curve_name)
{
	int i = 0;
	while (lws_ec_curves[i].name) {
		if (!strcmp(lws_ec_curves[i].name, curve_name))
			return lws_ec_curves[i].tls_lib_nid;
		i++;
	}
	return 0;
}

int
lws_genhash_init(struct lws_genhash_ctx *ctx, enum lws_genhash_types type)
{
	ctx->type = type;
	switch (type) {
	case LWS_GENHASH_TYPE_MD5:
		br_md5_init(&ctx->u.md5);
		break;
	case LWS_GENHASH_TYPE_SHA1:
		br_sha1_init(&ctx->u.sha1);
		break;
	case LWS_GENHASH_TYPE_SHA256:
		br_sha256_init(&ctx->u.sha256);
		break;
	case LWS_GENHASH_TYPE_SHA384:
		br_sha384_init(&ctx->u.sha384);
		break;
	case LWS_GENHASH_TYPE_SHA512:
		br_sha512_init(&ctx->u.sha512);
		break;
	default:
		return -1;
	}
	return 0;
}

int
lws_genhash_update(struct lws_genhash_ctx *ctx, const void *in, size_t len)
{
	if (!len)
		return 0;

	switch (ctx->type) {
	case LWS_GENHASH_TYPE_MD5:
		br_md5_update(&ctx->u.md5, in, len);
		break;
	case LWS_GENHASH_TYPE_SHA1:
		br_sha1_update(&ctx->u.sha1, in, len);
		break;
	case LWS_GENHASH_TYPE_SHA256:
		br_sha256_update(&ctx->u.sha256, in, len);
		break;
	case LWS_GENHASH_TYPE_SHA384:
		br_sha384_update(&ctx->u.sha384, in, len);
		break;
	case LWS_GENHASH_TYPE_SHA512:
		br_sha512_update(&ctx->u.sha512, in, len);
		break;
	default:
		return -1;
	}
	return 0;
}

int
lws_genhash_destroy(struct lws_genhash_ctx *ctx, void *result)
{
	if (!result)
		return 0;

	switch (ctx->type) {
	case LWS_GENHASH_TYPE_MD5:
		br_md5_out(&ctx->u.md5, result);
		break;
	case LWS_GENHASH_TYPE_SHA1:
		br_sha1_out(&ctx->u.sha1, result);
		break;
	case LWS_GENHASH_TYPE_SHA256:
		br_sha256_out(&ctx->u.sha256, result);
		break;
	case LWS_GENHASH_TYPE_SHA384:
		br_sha384_out(&ctx->u.sha384, result);
		break;
	case LWS_GENHASH_TYPE_SHA512:
		br_sha512_out(&ctx->u.sha512, result);
		break;
	default:
		return -1;
	}
	return 0;
}

int
lws_genhmac_init(struct lws_genhmac_ctx *ctx, enum lws_genhmac_types type, const uint8_t *key, size_t key_len)
{
	const br_hash_class *vtable;

	ctx->type = type;
	switch (type) {
	case LWS_GENHMAC_TYPE_SHA1:
		vtable = &br_sha1_vtable;
		break;
	case LWS_GENHMAC_TYPE_SHA256:
		vtable = &br_sha256_vtable;
		break;
	case LWS_GENHMAC_TYPE_SHA384:
		vtable = &br_sha384_vtable;
		break;
	case LWS_GENHMAC_TYPE_SHA512:
		vtable = &br_sha512_vtable;
		break;
	default:
		return -1;
	}

	br_hmac_key_init(&ctx->hmac_key, vtable, key, key_len);
	br_hmac_init(&ctx->ctx, &ctx->hmac_key, 0);

	return 0;
}

int
lws_genhmac_update(struct lws_genhmac_ctx *ctx, const void *in, size_t len)
{
	if (!len)
		return 0;

	br_hmac_update(&ctx->ctx, in, len);
	return 0;
}

int
lws_genhmac_destroy(struct lws_genhmac_ctx *ctx, void *result)
{
	if (!result)
		return 0;

	br_hmac_out(&ctx->ctx, result);
	return 0;
}

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx, const struct lws_gencrypto_keyelem *el, struct lws_context *context, enum enum_genrsa_mode mode, enum lws_genhash_types hash_type)
{
	ctx->context = context;
	ctx->mode = mode;

	if (el[LWS_GENCRYPTO_RSA_KEYEL_E].len && el[LWS_GENCRYPTO_RSA_KEYEL_N].len) {
		ctx->pub.e = el[LWS_GENCRYPTO_RSA_KEYEL_E].buf;
		ctx->pub.elen = el[LWS_GENCRYPTO_RSA_KEYEL_E].len;
		ctx->pub.n = el[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
		ctx->pub.nlen = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	} else {
		ctx->pub.e = NULL;
	}

	if (el[LWS_GENCRYPTO_RSA_KEYEL_D].len && el[LWS_GENCRYPTO_RSA_KEYEL_P].len) {
		ctx->priv.p = el[LWS_GENCRYPTO_RSA_KEYEL_P].buf;
		ctx->priv.plen = el[LWS_GENCRYPTO_RSA_KEYEL_P].len;
		ctx->priv.q = el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf;
		ctx->priv.qlen = el[LWS_GENCRYPTO_RSA_KEYEL_Q].len;
		ctx->priv.dp = el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf;
		ctx->priv.dplen = el[LWS_GENCRYPTO_RSA_KEYEL_DP].len;
		ctx->priv.dq = el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf;
		ctx->priv.dqlen = el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len;
		ctx->priv.iq = el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf;
		ctx->priv.iqlen = el[LWS_GENCRYPTO_RSA_KEYEL_QI].len;
		ctx->priv.n_bitlen = (uint32_t)(el[LWS_GENCRYPTO_RSA_KEYEL_N].len * 8);
	} else {
		ctx->priv.p = NULL;
	}

	return 0;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx, enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el, int bits)
{
	br_rsa_keygen kg;
	br_rsa_compute_privexp cp;
	struct lws_br_prng_ctx prng;
	const br_prng_class *prng_ptr;
	uint8_t *dbuf = NULL;
	size_t dlen;
	uint32_t pubexp = 65537;
	int ret = -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	kg = br_rsa_keygen_get_default();
	cp = br_rsa_compute_privexp_get_default();
	if (!kg || !cp)
		return -1;

	prng.vtable = &lws_br_prng_vtable;
	prng.context = context;
	prng_ptr = prng.vtable;

	ctx->kbuf_priv = lws_malloc(BR_RSA_KBUF_PRIV_SIZE((size_t)bits), "rsapriv");
	ctx->kbuf_pub = lws_malloc(BR_RSA_KBUF_PUB_SIZE((size_t)bits), "rsapub");
	dbuf = lws_malloc((size_t)(bits + 7) / 8, "rsad");
	if (!ctx->kbuf_priv || !ctx->kbuf_pub || !dbuf)
		goto bail;

	if (!kg(&prng_ptr, &ctx->priv, ctx->kbuf_priv, &ctx->pub, ctx->kbuf_pub, (unsigned)bits, pubexp))
		goto bail;

	dlen = cp(dbuf, &ctx->priv, pubexp);
	if (!dlen)
		goto bail;

	/* copy elements to el */
	el[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc(ctx->pub.elen, "rsae");
	el[LWS_GENCRYPTO_RSA_KEYEL_E].len = (uint32_t)ctx->pub.elen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_E].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_E].buf, ctx->pub.e, ctx->pub.elen);

	el[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc(ctx->pub.nlen, "rsan");
	el[LWS_GENCRYPTO_RSA_KEYEL_N].len = (uint32_t)ctx->pub.nlen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_N].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_N].buf, ctx->pub.n, ctx->pub.nlen);

	el[LWS_GENCRYPTO_RSA_KEYEL_D].buf = lws_malloc(dlen, "rsad");
	el[LWS_GENCRYPTO_RSA_KEYEL_D].len = (uint32_t)dlen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_D].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_D].buf, dbuf, dlen);

	el[LWS_GENCRYPTO_RSA_KEYEL_P].buf = lws_malloc(ctx->priv.plen, "rsap");
	el[LWS_GENCRYPTO_RSA_KEYEL_P].len = (uint32_t)ctx->priv.plen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_P].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_P].buf, ctx->priv.p, ctx->priv.plen);

	el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = lws_malloc(ctx->priv.qlen, "rsaq");
	el[LWS_GENCRYPTO_RSA_KEYEL_Q].len = (uint32_t)ctx->priv.qlen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, ctx->priv.q, ctx->priv.qlen);

	el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf = lws_malloc(ctx->priv.dplen, "rsadp");
	el[LWS_GENCRYPTO_RSA_KEYEL_DP].len = (uint32_t)ctx->priv.dplen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf, ctx->priv.dp, ctx->priv.dplen);

	el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf = lws_malloc(ctx->priv.dqlen, "rsadq");
	el[LWS_GENCRYPTO_RSA_KEYEL_DQ].len = (uint32_t)ctx->priv.dqlen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf, ctx->priv.dq, ctx->priv.dqlen);

	el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf = lws_malloc(ctx->priv.iqlen, "rsaiq");
	el[LWS_GENCRYPTO_RSA_KEYEL_QI].len = (uint32_t)ctx->priv.iqlen;
	if (el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf) memcpy(el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf, ctx->priv.iq, ctx->priv.iqlen);

	if (!el[LWS_GENCRYPTO_RSA_KEYEL_E].buf || !el[LWS_GENCRYPTO_RSA_KEYEL_N].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_D].buf || !el[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf || !el[LWS_GENCRYPTO_RSA_KEYEL_DP].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf || !el[LWS_GENCRYPTO_RSA_KEYEL_QI].buf)
		goto bail;

	ret = 0;

bail:
	if (dbuf)
		lws_free(dbuf);

	if (ret) {
		lws_free_set_NULL(ctx->kbuf_priv);
		lws_free_set_NULL(ctx->kbuf_pub);
	}
	return ret;
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out)
{
	br_rsa_public pub = br_rsa_public_get_default();

	if (!ctx->pub.e)
		return -1;

	if (in_len > ctx->pub.nlen)
		return -1;

	memset(out, 0, ctx->pub.nlen);
	memcpy(out + (ctx->pub.nlen - in_len), in, in_len);

	if (!pub(out, ctx->pub.nlen, &ctx->pub))
		return -1;

	return (int)ctx->pub.nlen;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
	br_rsa_private priv = br_rsa_private_get_default();
	unsigned char buf[512];
	uint32_t r;

	if (!ctx->priv.p || in_len > sizeof(buf) || ctx->pub.nlen > sizeof(buf))
		return -1;

	memcpy(buf, in, in_len);

	/* BearSSL's private core decrypts in place */
	r = priv(buf, &ctx->priv);
	if (!r)
		return -1;

	if (in_len > out_max)
		return -1;

	memcpy(out, buf, in_len);
	return (int)in_len;
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, const uint8_t *sig, size_t sig_len)
{
	br_rsa_pkcs1_vrfy vrfy = br_rsa_pkcs1_vrfy_get_default();
	const br_hash_class *hc;
	const unsigned char *oid;
	unsigned char hash[64];
	br_hash_compat_context hctx;

	if (!ctx->pub.e)
		return -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: hc = &br_sha1_vtable; oid = BR_HASH_OID_SHA1; break;
	case LWS_GENHASH_TYPE_SHA256: hc = &br_sha256_vtable; oid = BR_HASH_OID_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: hc = &br_sha384_vtable; oid = BR_HASH_OID_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: hc = &br_sha512_vtable; oid = BR_HASH_OID_SHA512; break;
	default: return -1;
	}

	hc->init(&hctx.vtable);
	hc->update(&hctx.vtable, in, sig_len);
	hc->out(&hctx.vtable, hash);

	if (!vrfy(sig, sig_len, oid, lws_genhash_size(hash_type), &ctx->pub, hash))
		return -1;

	return 0;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, uint8_t *sig, size_t sig_len)
{
	br_rsa_pkcs1_sign sign = br_rsa_pkcs1_sign_get_default();
	const br_hash_class *hc;
	const unsigned char *oid;
	unsigned char hash[64];
	br_hash_compat_context hctx;

	if (!ctx->priv.p)
		return -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: hc = &br_sha1_vtable; oid = BR_HASH_OID_SHA1; break;
	case LWS_GENHASH_TYPE_SHA256: hc = &br_sha256_vtable; oid = BR_HASH_OID_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: hc = &br_sha384_vtable; oid = BR_HASH_OID_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: hc = &br_sha512_vtable; oid = BR_HASH_OID_SHA512; break;
	default: return -1;
	}

	hc->init(&hctx.vtable);
	hc->update(&hctx.vtable, in, sig_len);
	hc->out(&hctx.vtable, hash);

	if (!sign(oid, hash, lws_genhash_size(hash_type), &ctx->priv, sig))
		return -1;

	return (int)ctx->pub.nlen;
}

void lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	lws_free_set_NULL(ctx->kbuf_priv);
	lws_free_set_NULL(ctx->kbuf_pub);
}

void lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (ctx->pub.q) {
		lws_free((void *)ctx->pub.q);
		ctx->pub.q = NULL;
	}
	lws_free_set_NULL(ctx->kbuf_priv);
	lws_free_set_NULL(ctx->kbuf_pub);
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context, const struct lws_ec_curves *el)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = el;
	ctx->genec_alg = LEGENEC_ECDSA;
	return 0;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	const br_ec_impl *impl;
	struct lws_br_prng_ctx prng;
	const br_prng_class *prng_ptr;
	int curve;
	size_t len;

	curve = lws_genec_curve_name_to_bearssl_curve(curve_name);
	if (!curve)
		return -1;

	impl = br_ec_get_default();
	if (!impl)
		return -1;

	prng.vtable = &lws_br_prng_vtable;
	prng.context = ctx->context;
	prng_ptr = prng.vtable;

	ctx->kbuf_priv = lws_malloc(BR_EC_KBUF_PRIV_MAX_SIZE, "ecpriv");
	ctx->kbuf_pub = lws_malloc(BR_EC_KBUF_PUB_MAX_SIZE, "ecpub");
	if (!ctx->kbuf_priv || !ctx->kbuf_pub)
		goto bail;

	len = br_ec_keygen(&prng_ptr, impl, &ctx->priv, ctx->kbuf_priv, curve);
	if (!len)
		goto bail;

	ctx->pub.curve = curve;
	ctx->pub.q = lws_malloc(BR_EC_KBUF_PUB_MAX_SIZE, "ecpubq");
	if (!ctx->pub.q)
		goto bail;

	ctx->pub.qlen = br_ec_compute_pub(impl, &ctx->pub, (void *)ctx->pub.q, &ctx->priv);
	if (!ctx->pub.qlen)
		goto bail;

	/* copy to el */
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = lws_malloc(strlen(curve_name) + 1, "eccrv");
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(curve_name);
	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) memcpy(el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name, strlen(curve_name));

	el[LWS_GENCRYPTO_EC_KEYEL_D].buf = lws_malloc(ctx->priv.xlen, "ecd");
	el[LWS_GENCRYPTO_EC_KEYEL_D].len = (uint32_t)ctx->priv.xlen;
	if (el[LWS_GENCRYPTO_EC_KEYEL_D].buf) memcpy(el[LWS_GENCRYPTO_EC_KEYEL_D].buf, ctx->priv.x, ctx->priv.xlen);

	/* BearSSL public key point is uncompressed 0x04 || X || Y. */
	/* JWK expects X and Y separately */
	if (ctx->pub.qlen > 1 && ctx->pub.q[0] == 0x04) {
		size_t coord_len = (ctx->pub.qlen - 1) / 2;
		el[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(coord_len, "ecx");
		el[LWS_GENCRYPTO_EC_KEYEL_X].len = (uint32_t)coord_len;
		if (el[LWS_GENCRYPTO_EC_KEYEL_X].buf) memcpy(el[LWS_GENCRYPTO_EC_KEYEL_X].buf, ctx->pub.q + 1, coord_len);

		el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(coord_len, "ecy");
		el[LWS_GENCRYPTO_EC_KEYEL_Y].len = (uint32_t)coord_len;
		if (el[LWS_GENCRYPTO_EC_KEYEL_Y].buf) memcpy(el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, ctx->pub.q + 1 + coord_len, coord_len);
	}

	if (!el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf || !el[LWS_GENCRYPTO_EC_KEYEL_D].buf ||
	    !el[LWS_GENCRYPTO_EC_KEYEL_X].buf || !el[LWS_GENCRYPTO_EC_KEYEL_Y].buf)
		goto bail;

	return 0;

bail:
	lws_free_set_NULL(ctx->kbuf_priv);
	lws_free_set_NULL(ctx->kbuf_pub);
	return -1;
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el)
{
	if (!ctx->curve_table)
		return -1;

	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len) {
		ctx->priv.curve = ctx->curve_table->tls_lib_nid;
		ctx->priv.x = el[LWS_GENCRYPTO_EC_KEYEL_D].buf;
		ctx->priv.xlen = el[LWS_GENCRYPTO_EC_KEYEL_D].len;
		ctx->has_private = 1;
	}

	if (el[LWS_GENCRYPTO_EC_KEYEL_X].len && el[LWS_GENCRYPTO_EC_KEYEL_Y].len) {
		size_t qlen = 1 + el[LWS_GENCRYPTO_EC_KEYEL_X].len + el[LWS_GENCRYPTO_EC_KEYEL_Y].len;
		unsigned char *q = lws_malloc(qlen, "genec pub");
		if (!q)
			return -1;

		q[0] = 0x04; /* Uncompressed format */
		memcpy(q + 1, el[LWS_GENCRYPTO_EC_KEYEL_X].buf, el[LWS_GENCRYPTO_EC_KEYEL_X].len);
		memcpy(q + 1 + el[LWS_GENCRYPTO_EC_KEYEL_X].len, el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, el[LWS_GENCRYPTO_EC_KEYEL_Y].len);

		ctx->pub.curve = ctx->curve_table->tls_lib_nid;
		ctx->pub.q = q;
		ctx->pub.qlen = qlen;
	}

	return 0;
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, int keybits, const uint8_t *sig, size_t sig_len)
{
	br_ecdsa_vrfy vrfy = br_ecdsa_vrfy_raw_get_default();
	const br_hash_class *hc;
	unsigned char hash[64];
	br_hash_compat_context hctx;

	if (!ctx->pub.q)
		return -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: hc = &br_sha1_vtable; break;
	case LWS_GENHASH_TYPE_SHA256: hc = &br_sha256_vtable; break;
	case LWS_GENHASH_TYPE_SHA384: hc = &br_sha384_vtable; break;
	case LWS_GENHASH_TYPE_SHA512: hc = &br_sha512_vtable; break;
	default: return -1;
	}

	hc->init(&hctx.vtable);
	hc->update(&hctx.vtable, in, sig_len);
	hc->out(&hctx.vtable, hash);

	if (!vrfy(br_ec_get_default(), hash, lws_genhash_size(hash_type), &ctx->pub, sig, sig_len))
		return -1;

	return 0;
}

int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, int keybits, uint8_t *sig, size_t sig_len)
{
	br_ecdsa_sign sign = br_ecdsa_sign_raw_get_default();
	const br_hash_class *hc;
	unsigned char hash[64];
	br_hash_compat_context hctx;
	size_t r;

	if (!ctx->has_private)
		return -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: hc = &br_sha1_vtable; break;
	case LWS_GENHASH_TYPE_SHA256: hc = &br_sha256_vtable; break;
	case LWS_GENHASH_TYPE_SHA384: hc = &br_sha384_vtable; break;
	case LWS_GENHASH_TYPE_SHA512: hc = &br_sha512_vtable; break;
	default: return -1;
	}

	hc->init(&hctx.vtable);
	hc->update(&hctx.vtable, in, sig_len);
	hc->out(&hctx.vtable, hash);

	r = sign(br_ec_get_default(), hc, hash, &ctx->priv, sig);
	if (!r)
		return -1;

	return (int)r;
}

int lws_geneddsa_create(struct lws_genec_ctx *ctx, struct lws_context *context, const struct lws_ec_curves *el) { return -1; }
int lws_geneddsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name, struct lws_gencrypto_keyelem *el) { return -1; }
int lws_geneddsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *sig, size_t sig_len) { return -1; }

int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op, enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el, enum enum_aes_padding padding, void *engine)
{
	ctx->op = op;
	ctx->mode = mode;
	ctx->padding = padding;
	ctx->k = el;
	ctx->underway = 0;

	switch (mode) {
	case LWS_GAESM_CBC:
		if (op == LWS_GAESO_ENC) {
			br_aes_ct_cbcenc_init(&ctx->u.cbcenc, el->buf, el->len);
			ctx->cbcenc_vtable = &br_aes_ct_cbcenc_vtable;
		} else {
			br_aes_ct_cbcdec_init(&ctx->u.cbcdec, el->buf, el->len);
			ctx->cbcdec_vtable = &br_aes_ct_cbcdec_vtable;
		}
		break;

	case LWS_GAESM_CTR:
		br_aes_ct_ctr_init(&ctx->u.ctr, el->buf, el->len);
		ctx->ctr_vtable = &br_aes_ct_ctr_vtable;
		break;

	case LWS_GAESM_GCM:
		br_aes_ct_ctr_init(&ctx->u.ctr, el->buf, el->len);
		ctx->ctr_vtable = &br_aes_ct_ctr_vtable;
		br_gcm_init(&ctx->gcm, &ctx->ctr_vtable, br_ghash_ctmul);
		break;

	default:
		return -1;
	}

	return 0;
}

int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	if (ctx->mode == LWS_GAESM_GCM && tag && tlen) {
		br_gcm_get_tag(&ctx->gcm, ctx->tag);
		if (ctx->op == LWS_GAESO_ENC)
			memcpy(tag, ctx->tag, tlen);
		else if (memcmp(tag, ctx->tag, tlen))
			return -1;
	}
	return 0;
}

int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out, uint8_t *iv_or_nonce_ctr_or_data_unit_16, uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	if (in && len)
		memcpy(out, in, len);

	switch (ctx->mode) {
	case LWS_GAESM_CBC:
		if (len % 16)
			return -1;
		if (ctx->op == LWS_GAESO_ENC)
			br_aes_ct_cbcenc_run(&ctx->u.cbcenc, iv_or_nonce_ctr_or_data_unit_16, out, len);
		else
			br_aes_ct_cbcdec_run(&ctx->u.cbcdec, iv_or_nonce_ctr_or_data_unit_16, out, len);
		break;

	case LWS_GAESM_CTR:
		/* nc_or_iv_off is the counter cc */
		*nc_or_iv_off = br_aes_ct_ctr_run(&ctx->u.ctr, iv_or_nonce_ctr_or_data_unit_16, (uint32_t)*nc_or_iv_off, out, len);
		break;

	case LWS_GAESM_GCM:
		if (!ctx->underway) {
			br_gcm_reset(&ctx->gcm, iv_or_nonce_ctr_or_data_unit_16, 12);
			if (stream_block_16 && nc_or_iv_off && *nc_or_iv_off)
				br_gcm_aad_inject(&ctx->gcm, stream_block_16, *nc_or_iv_off);
			br_gcm_flip(&ctx->gcm);
			ctx->underway = 1;
		}
		br_gcm_run(&ctx->gcm, ctx->op == LWS_GAESO_ENC, out, len);
		break;

	default:
		return -1;
	}

	return 0;
}

int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context, const struct lws_ec_curves *curve_table)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDH;
	return 0;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el, enum enum_lws_dh_side side)
{
	return lws_genecdsa_set_key(ctx, el);
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side, const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	return lws_genecdsa_new_keypair(ctx, curve_name, el);
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss, int *ss_len)
{
	const br_ec_impl *ec;
	uint32_t r;

	if (!ctx->has_private || !ctx->pub.q)
		return -1;

	ec = br_ec_get_default();

	if (ctx->pub.qlen > 512)
		return -1;

	memcpy(ss, ctx->pub.q, ctx->pub.qlen);

	r = ec->mul(ss, ctx->pub.qlen, ctx->priv.x, ctx->priv.xlen, ctx->priv.curve);
	if (!r)
		return -1;

	/* BearSSL mul returns the uncompressed point. Shared secret is the X coordinate */
	size_t xoff, xlen = 0;
	xoff = ec->xoff(ctx->priv.curve, &xlen);

	memmove(ss, ss + xoff, xlen);
	*ss_len = (int)xlen;

	return 0;
}


int lws_geneddsa_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el) { return -1; }
int lws_geneddsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in, size_t in_len, const uint8_t *sig, size_t sig_len) { return -1; }
