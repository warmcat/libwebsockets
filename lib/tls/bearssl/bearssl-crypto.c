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

/* MGF1 hash for OAEP, chosen by the oaep_hashid given to create() */

static const br_hash_class *
lws_genrsa_oaep_hash_vtable(enum lws_genhash_types type)
{
	switch (type) {
	case LWS_GENHASH_TYPE_SHA1:		return &br_sha1_vtable;
	case LWS_GENHASH_TYPE_SHA256:		return &br_sha256_vtable;
	case LWS_GENHASH_TYPE_SHA384:		return &br_sha384_vtable;
	case LWS_GENHASH_TYPE_SHA512:		return &br_sha512_vtable;
	default:				return NULL;
	}
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
	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENRSA_CTX_CREATED_MARK)
		return -1;

	if (mode < 0 || mode >= LGRSAM_COUNT)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;
	ctx->oaep_hashid = hash_type;

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

	ctx->created_mark = LWS_GENRSA_CTX_CREATED_MARK;

	return 0;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx, enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el, int bits)
{
	br_rsa_keygen kg;
	br_rsa_compute_privexp cp;
	struct lws_br_prng_ctx prng;
	uint8_t *dbuf = NULL;
	size_t dlen;
	uint32_t pubexp = 65537;
	int ret = -1;

	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENRSA_CTX_CREATED_MARK)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;
	/* the documented default OAEP hash when nothing else is known */
	ctx->oaep_hashid = LWS_GENHASH_TYPE_SHA1;

	kg = br_rsa_keygen_get_default();
	cp = br_rsa_compute_privexp_get_default();
	if (!kg || !cp)
		return -1;

	prng.vtable = &lws_br_prng_vtable;
	prng.context = context;

	ctx->kbuf_priv = lws_malloc(BR_RSA_KBUF_PRIV_SIZE((size_t)bits), "rsapriv");
	ctx->kbuf_pub = lws_malloc(BR_RSA_KBUF_PUB_SIZE((size_t)bits), "rsapub");
	dbuf = lws_malloc((size_t)(bits + 7) / 8, "rsad");
	if (!ctx->kbuf_priv || !ctx->kbuf_pub || !dbuf)
		goto bail;

	if (!kg(&prng.vtable, &ctx->priv, ctx->kbuf_priv, &ctx->pub, ctx->kbuf_pub, (unsigned)bits, pubexp))
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
	ctx->created_mark = LWS_GENRSA_CTX_CREATED_MARK;

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
	br_rsa_oaep_encrypt enc = br_rsa_oaep_encrypt_get_default();
	struct lws_br_prng_ctx prng;
	const br_hash_class *dig;
	size_t n;

	if (!ctx->pub.e)
		return -1;

	/*
	 * BearSSL provides OAEP pieces but no PKCS#1 v1.5 data encryption;
	 * rather than silently substitute something else, fail loudly
	 */
	if (ctx->mode != LGRSAM_PKCS1_OAEP_PSS) {
		lwsl_err("%s: BearSSL has no PKCS#1 v1.5 public encrypt pieces\n", __func__);
		return -1;
	}

	dig = lws_genrsa_oaep_hash_vtable(ctx->oaep_hashid);
	if (!dig)
		return -1;

	prng.vtable = &lws_br_prng_vtable;
	prng.context = ctx->context;

	n = enc(&prng.vtable, dig, NULL, 0, &ctx->pub, out, ctx->pub.nlen,
		in, in_len);
	if (!n)
		return -1;

	return (int)n;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
	br_rsa_oaep_decrypt dec = br_rsa_oaep_decrypt_get_default();
	const br_hash_class *dig;
	unsigned char buf[512];
	size_t nlen, len;

	if (!ctx->priv.p)
		return -1;

	if (ctx->mode != LGRSAM_PKCS1_OAEP_PSS) {
		lwsl_err("%s: BearSSL has no PKCS#1 v1.5 private decrypt pieces\n", __func__);
		return -1;
	}

	dig = lws_genrsa_oaep_hash_vtable(ctx->oaep_hashid);
	if (!dig)
		return -1;

	nlen = ((size_t)ctx->priv.n_bitlen + 7) / 8;
	if (nlen > sizeof(buf) || in_len != nlen)
		return -1;

	/* BearSSL's OAEP decrypt works in place and sets len on success */
	memcpy(buf, in, in_len);
	len = in_len;

	if (!dec(dig, NULL, 0, &ctx->priv, buf, &len))
		return -1;

	if (len > out_max)
		return -1;

	memcpy(out, buf, len);

	return (int)len;
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out)
{
	lwsl_err("%s: BearSSL has no PKCS#1 v1.5 private encrypt pieces\n", __func__);

	return -1;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
	lwsl_err("%s: BearSSL has no PKCS#1 v1.5 public decrypt pieces\n", __func__);

	return -1;
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, const uint8_t *sig, size_t sig_len)
{
	br_rsa_pkcs1_vrfy vrfy = br_rsa_pkcs1_vrfy_get_default();
	const unsigned char *oid;
	unsigned char hash[64];
	size_t hlen;

	if (!ctx->pub.e)
		return -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: oid = BR_HASH_OID_SHA1; break;
	case LWS_GENHASH_TYPE_SHA256: oid = BR_HASH_OID_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: oid = BR_HASH_OID_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: oid = BR_HASH_OID_SHA512; break;
	default: return -1;
	}

	hlen = lws_genhash_size(hash_type);

	/*
	 * bearssl decodes the hash that was signed into hash[]; it only
	 * validates the padding structure, so the caller's hash in must be
	 * compared against what the signature actually signed
	 */
	if (!vrfy(sig, sig_len, oid, hlen, &ctx->pub, hash) ||
	    lws_timingsafe_bcmp(hash, in, (unsigned int)hlen))
		return -1;

	return 0;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, uint8_t *sig, size_t sig_len)
{
	br_rsa_pkcs1_sign sign = br_rsa_pkcs1_sign_get_default();
	const unsigned char *oid;
	size_t nlen;

	if (!ctx->priv.p)
		return -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1: oid = BR_HASH_OID_SHA1; break;
	case LWS_GENHASH_TYPE_SHA256: oid = BR_HASH_OID_SHA256; break;
	case LWS_GENHASH_TYPE_SHA384: oid = BR_HASH_OID_SHA384; break;
	case LWS_GENHASH_TYPE_SHA512: oid = BR_HASH_OID_SHA512; break;
	default: return -1;
	}

	/* in is the caller's precomputed hash of hash_type bytes; the
	 * signature is the size of the key modulus */
	nlen = ((size_t)ctx->priv.n_bitlen + 7) / 8;
	if (sig_len < nlen)
		return -1;

	if (!sign(oid, in, lws_genhash_size(hash_type), &ctx->priv, sig))
		return -1;

	return (int)nlen;
}

void lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	lws_free_set_NULL(ctx->kbuf_priv);
	lws_free_set_NULL(ctx->kbuf_pub);
	ctx->created_mark = 0;
}

int
lws_genrsa_render_pkey_asn1(struct lws_genrsa_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	lwsl_err("%s: BearSSL backend does not implement pkey ASN.1 export\n",
		 __func__);

	return -1;
}

void lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (ctx->pub.q) {
		lws_free((void *)ctx->pub.q);
		ctx->pub.q = NULL;
	}
	lws_free_set_NULL(ctx->kbuf_priv);
	lws_free_set_NULL(ctx->kbuf_pub);
	ctx->has_private = 0;
	ctx->created_mark = 0;
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context, const struct lws_ec_curves *el)
{
	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENEC_CTX_CREATED_MARK)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = el;
	ctx->genec_alg = LEGENEC_ECDSA;
	ctx->created_mark = LWS_GENEC_CTX_CREATED_MARK;
	return 0;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name, struct lws_gencrypto_keyelem *el)
{
	const br_ec_impl *impl;
	struct lws_br_prng_ctx prng;
	int curve;
	size_t len;

	curve = lws_genec_curve_name_to_bearssl_curve(curve_name);
	if (!curve)
		return -1;

	impl = br_ec_get_default();
	if (!impl)
		return -1;

	/*
	 * last-set-wins: release any key already in the ctx, without
	 * disturbing its created state
	 */
	lws_free_set_NULL(ctx->kbuf_priv);
	lws_free_set_NULL(ctx->kbuf_pub);
	if (ctx->pub.q) {
		lws_free((void *)ctx->pub.q);
		ctx->pub.q = NULL;
	}
	ctx->has_private = 0;

	prng.vtable = &lws_br_prng_vtable;
	prng.context = ctx->context;

	ctx->kbuf_priv = lws_malloc(BR_EC_KBUF_PRIV_MAX_SIZE, "ecpriv");
	ctx->kbuf_pub = lws_malloc(BR_EC_KBUF_PUB_MAX_SIZE, "ecpub");
	if (!ctx->kbuf_priv || !ctx->kbuf_pub)
		goto bail;

	len = br_ec_keygen(&prng.vtable, impl, &ctx->priv, ctx->kbuf_priv, curve);
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
	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) memcpy(el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name, strlen(curve_name) + 1);

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
	lws_free_set_NULL(ctx->pub.q);
	lws_free_set_NULL(ctx->kbuf_priv);
	lws_free_set_NULL(ctx->kbuf_pub);
	return -1;
}

/*
 * Validate the curve element against the ctx's curve table (a NULL table
 * means the lws default one) and check the coordinate lengths match the
 * curve exactly.  Returns the matched curve, or NULL
 */
static const struct lws_ec_curves *
lws_genec_validate_elements(struct lws_genec_ctx *ctx,
			    const struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;

	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].len < 4)
		return NULL;

	curve = lws_genec_curve(ctx->curve_table,
				(char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (!curve)
		return NULL;

	if ((el[LWS_GENCRYPTO_EC_KEYEL_D].len &&
	     el[LWS_GENCRYPTO_EC_KEYEL_D].len != curve->key_bytes) ||
	    el[LWS_GENCRYPTO_EC_KEYEL_X].len != curve->key_bytes ||
	    el[LWS_GENCRYPTO_EC_KEYEL_Y].len != curve->key_bytes)
		return NULL;

	return curve;
}

/* install the X / Y elements as the ctx's uncompressed public point */

static int
lws_genec_set_pub(struct lws_genec_ctx *ctx,
		  const struct lws_ec_curves *curve,
		  const struct lws_gencrypto_keyelem *el)
{
	size_t qlen = 1 + el[LWS_GENCRYPTO_EC_KEYEL_X].len +
		     el[LWS_GENCRYPTO_EC_KEYEL_Y].len;
	unsigned char *q = lws_malloc(qlen, "genec pub");
	if (!q)
		return -1;

	q[0] = 0x04; /* uncompressed */
	memcpy(q + 1, el[LWS_GENCRYPTO_EC_KEYEL_X].buf,
	       el[LWS_GENCRYPTO_EC_KEYEL_X].len);
	memcpy(q + 1 + el[LWS_GENCRYPTO_EC_KEYEL_X].len,
	       el[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
	       el[LWS_GENCRYPTO_EC_KEYEL_Y].len);

	/* last-set-wins: replace any existing pub allocation */
	lws_free((void *)ctx->pub.q);

	ctx->pub.curve = curve->tls_lib_nid;
	ctx->pub.q = q;
	ctx->pub.qlen = qlen;

	return 0;
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;

	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].len < 4)
		return -2;

	curve = lws_genec_validate_elements(ctx, el);
	if (!curve)
		return -3;

	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len) {
		ctx->priv.curve = curve->tls_lib_nid;
		ctx->priv.x = el[LWS_GENCRYPTO_EC_KEYEL_D].buf;
		ctx->priv.xlen = el[LWS_GENCRYPTO_EC_KEYEL_D].len;
		ctx->has_private = 1;
	} else
		ctx->has_private = 0;

	return lws_genec_set_pub(ctx, curve, el);
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, int keybits, const uint8_t *sig, size_t sig_len)
{
	br_ecdsa_vrfy vrfy = br_ecdsa_vrfy_raw_get_default();

	if (!ctx->pub.q)
		return -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1:
	case LWS_GENHASH_TYPE_SHA256:
	case LWS_GENHASH_TYPE_SHA384:
	case LWS_GENHASH_TYPE_SHA512:
		break;
	default:
		return -1;
	}

	/* in is the caller's precomputed hash of hash_type bytes */
	if (!vrfy(br_ec_get_default(), in, lws_genhash_size(hash_type),
		  &ctx->pub, sig, sig_len))
		return -1;

	return 0;
}

int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in, enum lws_genhash_types hash_type, int keybits, uint8_t *sig, size_t sig_len)
{
	br_ecdsa_sign sign = br_ecdsa_sign_raw_get_default();
	const br_hash_class *hc;
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

	/*
	 * in is the caller's precomputed hash of hash_type bytes; the hash
	 * class only tells bearssl how long it is
	 */
	r = sign(br_ec_get_default(), hc, in, &ctx->priv, sig);
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
		if (op == LWS_GAESO_ENC)
			br_aes_ct_cbcenc_init(&ctx->u.cbcenc, el->buf, el->len);
		else
			br_aes_ct_cbcdec_init(&ctx->u.cbcdec, el->buf, el->len);
		break;

	case LWS_GAESM_CTR:
		br_aes_ct_ctrcbc_init(&ctx->u.ctrcbc, el->buf, el->len);
		break;

	case LWS_GAESM_GCM:
		br_aes_ct_ctr_init(&ctx->u.ctr, el->buf, el->len);
		br_gcm_init(&ctx->gcm, &ctx->u.ctr.vtable, br_ghash_ctmul);
		break;

	default:
		/* BearSSL provides CBC / CTR / GCM pieces only */
		lwsl_notice("%s: BearSSL provides no AES mode %d pieces\n",
			    __func__, mode);
		return -2;
	}

	return 0;
}

int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	if (ctx->mode == LWS_GAESM_GCM && tag && tlen) {
		unsigned char computed[16];

		if (ctx->underway == 1) {
			/* AAD-only: no data phase ever happened */
			br_gcm_flip(&ctx->gcm);
			ctx->underway = 2;
		}
		if (ctx->underway != 2)
			return -1;
		br_gcm_get_tag(&ctx->gcm, computed);
		if (ctx->op == LWS_GAESO_ENC)
			memcpy(tag, computed, tlen);
		/*
		 * for decryption the expected tag was stashed with the
		 * first crypt call, like the other backends
		 */
		else if (!ctx->taglen ||
			 tlen != (size_t)ctx->taglen ||
			 memcmp(computed, ctx->tag, tlen))
			return -1;

		return 0;
	}

	if (ctx->mode == LWS_GAESM_CBC &&
	    ctx->padding == LWS_GAESP_WITH_PADDING && ctx->buf_len == 16) {
		if (ctx->op == LWS_GAESO_ENC) {
			if (!tag || tlen < 16)
				return -1;

			/* emit a full block of pad, chained from ctx->tag */
			memset(tag, 16, 16);
			br_aes_ct_cbcenc_run(&ctx->u.cbcenc, ctx->tag,
					     tag, 16);
		} else {
			unsigned int i, b;

			/*
			 * decrypt the held-back block and check its pad;
			 * like the other backends, the caller takes the
			 * plaintext from crypt()
			 */
			br_aes_ct_cbcdec_run(&ctx->u.cbcdec, ctx->tag,
					     ctx->buf, 16);
			b = ctx->buf[15];
			if (b < 1 || b > 16)
				return -1;
			for (i = 16 - b; i < 16; i++)
				if (ctx->buf[i] != (uint8_t)b)
					return -1;
		}
		ctx->buf_len = 0;
	}

	return 0;
}

int
lws_genaes_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out, uint8_t *iv_or_nonce_ctr_or_data_unit_16, uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	switch (ctx->mode) {
	case LWS_GAESM_CBC: {
			size_t proc = len;
			uint8_t iv_work[16];

			if (!out || !iv_or_nonce_ctr_or_data_unit_16 ||
			    (len % 16))
				return -1;

			if (ctx->padding == LWS_GAESP_WITH_PADDING) {
				if (ctx->op == LWS_GAESO_DEC) {
					/*
					 * hold the last block back for
					 * destroy() to unpad and check
					 */
					if (!len)
						return -1;
					proc = len - 16;
					memcpy(ctx->buf, in + proc, 16);
				}
				/* enc: destroy() appends a pad block chained
				 * from where this leaves the cbc chain */
			}

			if (proc) {
				memcpy(out, in, proc);

				/*
				 * bearssl's cbc runners update the iv in
				 * place with the chaining value; the lws
				 * api leaves the caller's iv untouched
				 */
				memcpy(iv_work,
				       iv_or_nonce_ctr_or_data_unit_16, 16);
				if (ctx->op == LWS_GAESO_ENC)
					br_aes_ct_cbcenc_run(&ctx->u.cbcenc,
							     iv_work, out,
							     proc);
				else
					br_aes_ct_cbcdec_run(&ctx->u.cbcdec,
							     iv_work, out,
							     proc);
			} else
				memcpy(iv_work,
				       iv_or_nonce_ctr_or_data_unit_16, 16);

			if (ctx->padding == LWS_GAESP_WITH_PADDING) {
				/* keep the chaining value destroy() needs */
				memcpy(ctx->tag, iv_work, 16);
				ctx->buf_len = 16;
			}
			break;
		}

	case LWS_GAESM_CTR: {
			size_t o = 0;

			if (!out || !iv_or_nonce_ctr_or_data_unit_16 ||
			    !stream_block_16 || !nc_or_iv_off)
				return -1;
			if (*nc_or_iv_off > 15)
				return -1;

			memcpy(out, in, len);

			/*
			 * stream_block_16 holds the keystream for the
			 * current counter block, *nc_or_iv_off is the offset
			 * into it; a fresh keystream block is generated (and
			 * the 128-bit counter incremented) when it wraps
			 */
			while (len) {
				size_t chunk, i;

				if (*nc_or_iv_off == 0) {
					memset(stream_block_16, 0, 16);
					br_aes_ct_ctrcbc_ctr(&ctx->u.ctrcbc,
						iv_or_nonce_ctr_or_data_unit_16,
						stream_block_16, 16);
				}

				chunk = 16 - *nc_or_iv_off;
				if (chunk > len)
					chunk = len;

				for (i = 0; i < chunk; i++)
					out[o + i] ^=
						stream_block_16[*nc_or_iv_off + i];
				o += chunk;
				*nc_or_iv_off += chunk;
				if (*nc_or_iv_off == 16)
					*nc_or_iv_off = 0;
				len -= chunk;
			}
			break;
		}

	case LWS_GAESM_GCM:
		if (!ctx->underway) {
			/*
			 * first call: the IV (length in *nc_or_iv_off) and,
			 * for later decryption checking, the expected tag
			 * arrive with it, like the other backends
			 */
			if (!iv_or_nonce_ctr_or_data_unit_16 || !nc_or_iv_off)
				return -1;
			br_gcm_reset(&ctx->gcm,
				     iv_or_nonce_ctr_or_data_unit_16,
				     *nc_or_iv_off);
			ctx->underway = 1;

			if (stream_block_16 && taglen > 0 &&
			    taglen <= (int)sizeof(ctx->tag)) {
				memcpy(ctx->tag, stream_block_16, (size_t)taglen);
				ctx->taglen = taglen;
			}
		}

		if (!out) {
			/* AAD pass: in/len is the additional data */
			if (ctx->underway == 2)
				return -1;
			br_gcm_aad_inject(&ctx->gcm, in, len);
			break;
		}

		if (ctx->underway == 1) {
			/* all AAD seen, move to the data phase */
			br_gcm_flip(&ctx->gcm);
			ctx->underway = 2;
		}

		if (len) {
			memcpy(out, in, len);
			br_gcm_run(&ctx->gcm, ctx->op == LWS_GAESO_ENC,
				   out, len);
		}
		break;

	default:
		return -1;
	}

	return 0;
}

int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context, const struct lws_ec_curves *curve_table)
{
	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENEC_CTX_CREATED_MARK)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_ECDH;
	ctx->created_mark = LWS_GENEC_CTX_CREATED_MARK;
	return 0;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el, enum enum_lws_dh_side side)
{
	const struct lws_ec_curves *curve = lws_genec_validate_elements(ctx, el);

	if (!curve)
		return -1;

	if (side == LDHS_THEIRS)
		/*
		 * the peer side contributes its public part only; our
		 * private state is left as it is
		 */
		return lws_genec_set_pub(ctx, curve, el);

	/* our side: the private part, when present, comes with the pub */
	if (el[LWS_GENCRYPTO_EC_KEYEL_D].len) {
		ctx->priv.curve = curve->tls_lib_nid;
		ctx->priv.x = el[LWS_GENCRYPTO_EC_KEYEL_D].buf;
		ctx->priv.xlen = el[LWS_GENCRYPTO_EC_KEYEL_D].len;
		ctx->has_private = 1;
	} else
		ctx->has_private = 0;

	return lws_genec_set_pub(ctx, curve, el);
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
	unsigned char buf[BR_EC_KBUF_PUB_MAX_SIZE];
	size_t xoff, xlen = 0;
	uint32_t r;

	if (!ctx->has_private || !ctx->pub.q)
		return -1;

	if (ctx->pub.qlen > sizeof(buf))
		return -1;

	ec = br_ec_get_default();

	memcpy(buf, ctx->pub.q, ctx->pub.qlen);

	r = ec->mul(buf, ctx->pub.qlen, ctx->priv.x, ctx->priv.xlen, ctx->priv.curve);
	if (!r)
		return -1;

	/*
	 * BearSSL mul returns the uncompressed point. Shared secret is
	 * the X coordinate
	 */
	xoff = ec->xoff(ctx->priv.curve, &xlen);

	if (xlen > (size_t)*ss_len)
		return -1;

	memmove(ss, buf + xoff, xlen);
	*ss_len = (int)xlen;

	return 0;
}


int lws_geneddsa_set_key(struct lws_genec_ctx *ctx, const struct lws_gencrypto_keyelem *el) { return -1; }
int lws_geneddsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in, size_t in_len, const uint8_t *sig, size_t sig_len) { return -1; }
