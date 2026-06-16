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
 *
 *  lws_genec provides an EC abstraction api in lws that works the
 *  same whether you are using openssl or OpenHiTLS crypto functions underneath.
 */
#include "private-lib-core.h"
#include "private.h"
#include "bsl_asn1.h"
#include "bsl_sal.h"
#include "crypt_eal_rand.h"

/* Random number generator initialization state */
static int rand_initialized = 0;

static BSL_ASN1_TemplateItem lws_ecdsa_sig_templ_items[] = {
	{ BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0 },
	{ BSL_ASN1_TAG_INTEGER, 0, 1 },
	{ BSL_ASN1_TAG_INTEGER, 0, 1 },
};

static BSL_ASN1_Template lws_ecdsa_sig_templ = {
	lws_ecdsa_sig_templ_items,
	(uint32_t)(sizeof(lws_ecdsa_sig_templ_items) /
		   sizeof(lws_ecdsa_sig_templ_items[0]))
};

/*
 * Convert ECDSA signature from JWS format (raw concatenated r || s) to DER format.
 * JWS format: r (keybytes) + s (keybytes)
 * DER format: SEQUENCE { INTEGER r, INTEGER s }
 *
 * Returns the length of DER signature, or -1 on error.
 */
static int
lws_ecdsa_sig_jws_to_der(const uint8_t *jws_sig, int keybytes, uint8_t *der_sig, int der_len)
{
	uint8_t *encoded = NULL;
	uint32_t encoded_len = 0;
	BSL_ASN1_Buffer asn_arr[2];
	int ret = -1;

	if (!jws_sig || !der_sig || keybytes <= 0 || der_len <= 0)
		return -1;

	asn_arr[0].tag = BSL_ASN1_TAG_INTEGER;
	asn_arr[0].len = (uint32_t)keybytes;
	asn_arr[0].buff = (uint8_t *)(uintptr_t)jws_sig;
	asn_arr[1].tag = BSL_ASN1_TAG_INTEGER;
	asn_arr[1].len = (uint32_t)keybytes;
	asn_arr[1].buff = (uint8_t *)(uintptr_t)(jws_sig + keybytes);

	ret = BSL_ASN1_EncodeTemplate(&lws_ecdsa_sig_templ, asn_arr,
				      (uint32_t)(sizeof(asn_arr) / sizeof(asn_arr[0])),
				      &encoded, &encoded_len);
	if (ret != BSL_SUCCESS)
		return -1;

	if (encoded_len > (uint32_t)der_len)
		goto err;

	memcpy(der_sig, encoded, encoded_len);
	ret = (int)encoded_len;

err:
	BSL_SAL_Free(encoded);

	return ret;
}

static int
lws_ecdsa_sig_der_to_jws(const uint8_t *der_sig, uint32_t der_len, int keybytes,
			 uint8_t *jws_sig, size_t jws_sig_len)
{
	BSL_ASN1_Buffer asn_arr[2] = { { 0 } };
	uint8_t *p = (uint8_t *)(uintptr_t)der_sig;
	uint32_t rem = der_len;

	if (!der_sig || !jws_sig || keybytes <= 0 ||
	    jws_sig_len != (size_t)(keybytes * 2))
		return -1;

	if (BSL_ASN1_DecodeTemplate(&lws_ecdsa_sig_templ, NULL, &p, &rem, asn_arr,
				    (uint32_t)(sizeof(asn_arr) / sizeof(asn_arr[0]))) !=
	    BSL_SUCCESS)
		return -1;

	if (asn_arr[0].len > (uint32_t)keybytes ||
	    asn_arr[1].len > (uint32_t)keybytes)
		return -1;

	memset(jws_sig, 0, jws_sig_len);
	memcpy(jws_sig + (keybytes - (int)asn_arr[0].len), asn_arr[0].buff,
	       asn_arr[0].len);
	memcpy(jws_sig + keybytes + (keybytes - (int)asn_arr[1].len),
	       asn_arr[1].buff, asn_arr[1].len);

	return 0;
}

/* Initialize OpenHiTLS random number generator if not already done
 * This is exported for use by lws-genrsa.c as well */
int lws_hitls_init_rand(void)
{
	if (rand_initialized)
		return 0;

	/*
	 * Prefer OpenHiTLS CTR-DRBG path and tolerate repeat init from
	 * other callsites.
	 */
	int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL,
					 NULL, 0);
	if (ret == CRYPT_SUCCESS || ret == CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
		rand_initialized = 1;
		return 0;
	}

	lwsl_err("%s: CRYPT_EAL_RandInit failed: %d\n", __func__, ret);
	return -1;
}

const struct lws_ec_curves lws_ec_curves[4] = {
	{ "P-256", CRYPT_ECC_NISTP256, 32 },
	{ "P-384", CRYPT_ECC_NISTP384,  48 },
	{ "P-521", CRYPT_ECC_NISTP521,  66 },
	{ NULL, 0, 0 }
};

int
lws_genecdh_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->ctx[0] = NULL;
	ctx->ctx[1] = NULL;
	/* Use OpenHiTLS curve table if NULL is passed */
	ctx->curve_table = curve_table ? curve_table : lws_ec_curves;
	ctx->genec_alg = LEGENEC_ECDH;

	return 0;
}

int
lws_genecdsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->ctx[0] = NULL;
	ctx->ctx[1] = NULL;
	/* Use OpenHiTLS curve table if NULL is passed */
	ctx->curve_table = curve_table ? curve_table : lws_ec_curves;
	ctx->genec_alg = LEGENEC_ECDSA;

	return 0;
}

static int
lws_genec_import_key_material(CRYPT_EAL_PkeyCtx *pctx, CRYPT_PKEY_AlgId pkeyAlg,
			      const struct lws_ec_curves *curve,
			      const struct lws_gencrypto_keyelem *el,
			      int have_private_key)
{
	uint8_t *pubKeyBuf = NULL;
	int ret;

	/* Build uncompressed public key point: 0x04 || X || Y */
	pubKeyBuf = lws_malloc((uint32_t)curve->key_bytes * 2 + 1, "ec-pub-import");
	if (pubKeyBuf == NULL) {
		lwsl_err("%s: OOM allocating public key buffer\n", __func__);
		return -1;
	}
	pubKeyBuf[0] = 0x04; /* Uncompressed point indicator */
	memcpy(pubKeyBuf + 1, el[LWS_GENCRYPTO_EC_KEYEL_X].buf,
	       (size_t)curve->key_bytes);
	memcpy(pubKeyBuf + 1 + curve->key_bytes,
	       el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, (size_t)curve->key_bytes);

	CRYPT_EAL_PkeyPub pubKey = {
		.id = pkeyAlg,
		.key.eccPub = {
			.data = pubKeyBuf,
			.len = (uint32_t)curve->key_bytes * 2 + 1,
		},
	};

	ret = CRYPT_EAL_PkeySetPub(pctx, &pubKey);
	lws_free(pubKeyBuf);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPub failed: %d\n", __func__, ret);
		return -1;
	}

	/* For verification, we only need the public key */
	if (!have_private_key)
		return 0;

	CRYPT_EAL_PkeyPrv prvKey = {
		.id = pkeyAlg,
		.key.eccPrv = {
			.data = (uint8_t *)el[LWS_GENCRYPTO_EC_KEYEL_D].buf,
			.len = (uint32_t)el[LWS_GENCRYPTO_EC_KEYEL_D].len,
		},
	};

		ret = CRYPT_EAL_PkeySetPrv(pctx, &prvKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPrv failed: %d\n", __func__, ret);
		return -1;
	}

	return 0;
}

static int
lws_genec_keypair_import(struct lws_genec_ctx *ctx,
		         const struct lws_ec_curves *curve_table,
		         CRYPT_EAL_PkeyCtx **pctx,
		         const struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	CRYPT_PKEY_ParaId curveId;
	CRYPT_PKEY_AlgId pkeyAlg;
	int ret;
	int have_private_key = (el[LWS_GENCRYPTO_EC_KEYEL_D].len == 0) ? 0 : 1;

	/* Validate curve name */
	if (el[LWS_GENCRYPTO_EC_KEYEL_CRV].len < 4)
		return -2;

	curve = lws_genec_curve(curve_table,
				(char *)el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (curve == NULL)
		return -3;

	/* Validate key element lengths */
	if ((el[LWS_GENCRYPTO_EC_KEYEL_D].len &&
	     el[LWS_GENCRYPTO_EC_KEYEL_D].len != curve->key_bytes) ||
	    el[LWS_GENCRYPTO_EC_KEYEL_X].len != curve->key_bytes ||
	    el[LWS_GENCRYPTO_EC_KEYEL_Y].len != curve->key_bytes) {
		lwsl_notice("%s: key length mismatch: curve=%s key_bytes=%d, D.len=%d, X.len=%d, Y.len=%d\n",
			    __func__, curve->name, curve->key_bytes,
			    (int)el[LWS_GENCRYPTO_EC_KEYEL_D].len,
			    (int)el[LWS_GENCRYPTO_EC_KEYEL_X].len,
			    (int)el[LWS_GENCRYPTO_EC_KEYEL_Y].len);
		return -4;
	}

	ctx->has_private = (char)have_private_key;

	/* Determine algorithm based on context */
	pkeyAlg = (ctx->genec_alg == LEGENEC_ECDSA) ?
		  CRYPT_PKEY_ECDSA : CRYPT_PKEY_ECDH;

	*pctx = CRYPT_EAL_PkeyNewCtx(pkeyAlg);
	if (*pctx == NULL) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed for alg %d\n", __func__, (int)pkeyAlg);
		return -5;
	}

	/* Set the curve */
	curveId = (CRYPT_PKEY_ParaId)curve->tls_lib_nid;
	ret = CRYPT_EAL_PkeySetParaById(*pctx, curveId);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetParaById failed: %d\n", __func__, ret);
		goto err;
	}

	ret = lws_genec_import_key_material(*pctx, pkeyAlg, curve, el,
					    have_private_key);
	if (ret) {
		goto err;
	}

	return 0;

err:
	CRYPT_EAL_PkeyFreeCtx(*pctx);
	*pctx = NULL;
	return -9;
}

int
lws_genecdh_set_key(struct lws_genec_ctx *ctx,
		    const struct lws_gencrypto_keyelem *el,
		    enum enum_lws_dh_side side)
{
	if (ctx->genec_alg != LEGENEC_ECDH)
		return -1;

	return lws_genec_keypair_import(ctx, ctx->curve_table, &ctx->ctx[side], el);
}

int
lws_genecdsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	return lws_genec_keypair_import(ctx, ctx->curve_table, &ctx->ctx[0], el);
}

void
lws_genec_destroy(struct lws_genec_ctx *ctx)
{
	if (ctx->ctx[0])
		CRYPT_EAL_PkeyFreeCtx(ctx->ctx[0]);
	if (ctx->ctx[1])
		CRYPT_EAL_PkeyFreeCtx(ctx->ctx[1]);
	ctx->ctx[0] = NULL;
	ctx->ctx[1] = NULL;
}

static int
lws_genec_fill_keyel_from_generated(const char *curve_name,
				    struct lws_gencrypto_keyelem *el,
				    const CRYPT_EAL_PkeyPub *pubKey,
				    uint8_t *prvKeyBuf, uint32_t prvKeyLen)
{
	uint32_t crvLen = (uint32_t)strlen(curve_name) + 1;
	uint32_t pubKeyLen = pubKey->key.eccPub.len;
	uint32_t coordLen;
	uint8_t *crv;
	uint8_t *x;
	uint8_t *y;

	/* Generated keys must provide an uncompressed point: 0x04 || X || Y */
	if (pubKeyLen <= 1 || pubKey->key.eccPub.data[0] != 0x04 ||
	    ((pubKeyLen - 1) & 1u)) {
		lwsl_err("%s: unexpected EC public key format\n", __func__);
		return -1;
	}

	coordLen = (pubKeyLen - 1) / 2;
	crv = lws_malloc(crvLen, "ec");
	x = lws_malloc(coordLen, "ec-x");
	y = lws_malloc(coordLen, "ec-y");
	if (!crv || !x || !y) {
		lwsl_err("%s: OOM allocating EC key elements\n", __func__);
		lws_free(crv);
		lws_free(x);
		lws_free(y);
		return -1;
	}

	/* Copy curve name */
	strcpy((char *)crv, curve_name);
	memcpy(x, pubKey->key.eccPub.data + 1, coordLen);
	memcpy(y, pubKey->key.eccPub.data + 1 + coordLen, coordLen);

	el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = crvLen;
	el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = crv;
	el[LWS_GENCRYPTO_EC_KEYEL_X].len = coordLen;
	el[LWS_GENCRYPTO_EC_KEYEL_X].buf = x;
	el[LWS_GENCRYPTO_EC_KEYEL_Y].len = coordLen;
	el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = y;

	/* Private key buffer ownership is transferred only after success */
	el[LWS_GENCRYPTO_EC_KEYEL_D].len = prvKeyLen;
	el[LWS_GENCRYPTO_EC_KEYEL_D].buf = prvKeyBuf;

	return 0;
}

int
lws_genecdh_new_keypair(struct lws_genec_ctx *ctx, enum enum_lws_dh_side side,
			const char *curve_name,
			struct lws_gencrypto_keyelem *el)
{
	const struct lws_ec_curves *curve;
	CRYPT_PKEY_ParaId curveId;
	CRYPT_PKEY_AlgId pkeyAlg;
	uint8_t *pubKeyBuf = NULL;
	uint8_t *prvKeyBuf = NULL;
	int ret;

	if (ctx->genec_alg != LEGENEC_ECDH && ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	/* Initialize random number generator if needed */
	if (lws_hitls_init_rand() < 0)
		return -1;

	curve = lws_genec_curve(ctx->curve_table, curve_name);
	if (!curve) {
		lwsl_err("%s: curve '%s' not supported\n",
			 __func__, curve_name);
		return -22;
	}

	/* Create appropriate pkey context based on algorithm type */
	pkeyAlg = (ctx->genec_alg == LEGENEC_ECDSA) ?
		  CRYPT_PKEY_ECDSA : CRYPT_PKEY_ECDH;
	ctx->ctx[side] = CRYPT_EAL_PkeyNewCtx(pkeyAlg);
	if (!ctx->ctx[side]) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -23;
	}

	/* Set the curve using the simpler API */
	curveId = (CRYPT_PKEY_ParaId)curve->tls_lib_nid;
	ret = CRYPT_EAL_PkeySetParaById(ctx->ctx[side], curveId);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetParaById failed: %d\n", __func__, ret);
		goto err;
	}

	/* Generate the key */
	ret = CRYPT_EAL_PkeyGen(ctx->ctx[side]);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGen failed: %d\n", __func__, ret);
		goto err;
	}

	/* Extract the key elements
	 * Need to allocate buffers for the output */
	/* Allocate buffer for public key (uncompressed point is 65 bytes for P-256) */
	pubKeyBuf = lws_malloc(((uint32_t)curve->key_bytes * 2 + 1), "ec-pub");
	if (pubKeyBuf == NULL) {
		lwsl_err("%s: OOM allocating public key buffer\n", __func__);
		goto err;
	}
	CRYPT_EAL_PkeyPub pubKey = {
		.id = pkeyAlg,
		.key.eccPub = {
			.data = pubKeyBuf,
			.len = (uint32_t)curve->key_bytes * 2 + 1,
		},
	};

	/* Allocate buffer for private key */
	prvKeyBuf = lws_malloc((uint32_t)curve->key_bytes, "ec-prv");
	if (prvKeyBuf == NULL) {
		lwsl_err("%s: OOM allocating private key buffer\n", __func__);
		goto err;
	}

	CRYPT_EAL_PkeyPrv prvKey = {
		.id = pkeyAlg,
		.key.eccPrv = {
			.data = prvKeyBuf,
			.len = (uint32_t)curve->key_bytes,
		},
	};

	ret = CRYPT_EAL_PkeyGetPub(ctx->ctx[side], &pubKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed: %d\n", __func__, ret);
		goto err;
	}

	ret = CRYPT_EAL_PkeyGetPrv(ctx->ctx[side], &prvKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPrv failed: %d\n", __func__, ret);
		goto err;
	}

	if (lws_genec_fill_keyel_from_generated(curve_name, el, &pubKey,
						prvKeyBuf, prvKey.key.eccPrv.len)) {
		lwsl_err("%s: failed to fill output key elements\n", __func__);
		goto err;
	}
	lws_free(pubKeyBuf);  /* temp public key buffer is no longer needed, The private key can be taken out without needing to be released. */
	ctx->has_private = 1;

	return 0;

err:
	if (pubKeyBuf)
		lws_free(pubKeyBuf);
	if (prvKeyBuf)
		lws_free(prvKeyBuf);

	for (int n = LWS_GENCRYPTO_EC_KEYEL_CRV; n < LWS_GENCRYPTO_EC_KEYEL_COUNT; n++)
		if (el[n].buf) {
			lws_free_set_NULL(el[n].buf);
			el[n].len = 0;
		}
	CRYPT_EAL_PkeyFreeCtx(ctx->ctx[side]);
	ctx->ctx[side] = NULL;

	return -1;
}

int
lws_genecdsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	return lws_genecdh_new_keypair(ctx, LDHS_OURS, curve_name, el);
}

int
lws_genecdsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
			   enum lws_genhash_types hash_type, int keybits,
			   uint8_t *sig, size_t sig_len)
{
	uint32_t outLen;
	int ret;
	int keybytes = lws_gencrypto_bits_to_bytes(keybits);
	uint8_t der_buf[256]; /* Buffer for DER-encoded signature - increased for P-521 */

	if (ctx->genec_alg != LEGENEC_ECDSA) {
		lwsl_notice("%s: ctx alg %d\n", __func__, ctx->genec_alg);
		return -1;
	}

	if (!ctx->has_private)
		return -1;

	/* Initialize random number generator for ECDSA signing */
	if (lws_hitls_init_rand() < 0) {
		lwsl_err("%s: failed to init random number generator\n", __func__);
		return -1;
	}

	if ((int)sig_len != keybytes * 2) {
		lwsl_notice("%s: sig buff %d < expected\n", __func__, (int)sig_len);
		return -1;
	}

	/* Sign into temporary buffer - OpenHiTLS returns DER-encoded signature */
	outLen = sizeof(der_buf);

	/* OpenHiTLS native ECDSA sign */
	ret = CRYPT_EAL_PkeySignData(ctx->ctx[0], in,
				     (uint32_t)lws_genhash_size(hash_type),
				     der_buf, &outLen);

	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: ECDSA signing failed (error %d)\n", __func__, ret);
		return -1;
	}

	if (lws_ecdsa_sig_der_to_jws(der_buf, outLen, keybytes, sig, sig_len)) {
		lwsl_err("%s: failed to convert DER signature to JWS\n",
			 __func__);
		return -1;
	}

	return 0;
}

int
lws_genecdsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 enum lws_genhash_types hash_type, int keybits,
				 const uint8_t *sig, size_t sig_len)
{
	int ret;
	int keybytes = lws_gencrypto_bits_to_bytes(keybits);

	if (ctx->genec_alg != LEGENEC_ECDSA)
		return -1;

	if ((int)sig_len != keybytes * 2) {
		lwsl_err("%s: sig buf size %d vs expected\n", __func__,
			 (int)sig_len);
		return -1;
	}

	/* OpenHiTLS native ECDSA verify */
	uint8_t der_sig[256];
	int der_len = lws_ecdsa_sig_jws_to_der(sig, keybytes, der_sig, sizeof(der_sig));
	if (der_len < 0) {
		lwsl_err("%s: failed to convert signature to DER format\n", __func__);
		return -1;
	}

	ret = CRYPT_EAL_PkeyVerifyData(ctx->ctx[0], in,
				       (uint32_t)lws_genhash_size(hash_type),
				       der_sig, (uint32_t)der_len);

	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyVerifyData fail: %d\n", __func__, ret);
		return -1;
	}

	return 0;
}

int
lws_genecdh_compute_shared_secret(struct lws_genec_ctx *ctx, uint8_t *ss,
				  int *ss_len)
{
	int32_t ret;
	uint32_t shareLen = (uint32_t)*ss_len;

	if (!ctx->ctx[LDHS_OURS] || !ctx->ctx[LDHS_THEIRS]) {
		lwsl_err("%s: both sides must be set up\n", __func__);
		return -1;
	}

	ret = CRYPT_EAL_PkeyComputeShareKey(ctx->ctx[LDHS_OURS],
					    ctx->ctx[LDHS_THEIRS],
					    ss, &shareLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyComputeShareKey failed: %d\n",
			 __func__, ret);
		return -1;
	}

	*ss_len = (int)shareLen;

	return 0;
}

/*
 * OpenHiTLS currently exposes CRYPT_PKEY_ED25519 but not CRYPT_PKEY_ED448 in
 * the public EAL pkey API.  Keep Ed448 as an explicit unsupported boundary.
 */
#define LWS_OPENHITLS_ED25519_KEYLEN		32
#define LWS_OPENHITLS_ED25519_SIGLEN		64

static int
lws_openhitls_eddsa_alg_from_curve(const struct lws_gencrypto_keyelem *el,
				   CRYPT_PKEY_AlgId *alg, uint32_t *key_len,
				   uint32_t *sig_len)
{
	const struct lws_gencrypto_keyelem *crv =
			&el[LWS_GENCRYPTO_OKP_KEYEL_CRV];

	if ((crv->len == 7 || crv->len == 8) &&
	    !strncmp((const char *)crv->buf, "Ed25519", 7)) {
		*alg = CRYPT_PKEY_ED25519;
		*key_len = LWS_OPENHITLS_ED25519_KEYLEN;
		*sig_len = LWS_OPENHITLS_ED25519_SIGLEN;
		return 0;
	}

	if ((crv->len == 5 || crv->len == 6) &&
	    !strncmp((const char *)crv->buf, "Ed448", 5))
		lwsl_notice("%s: OpenHiTLS Ed448 is not supported\n", __func__);

	return -1;
}

static int
lws_openhitls_eddsa_curve_name_to_alg(const char *curve_name,
				      CRYPT_PKEY_AlgId *alg,
				      uint32_t *key_len, uint32_t *sig_len)
{
	if (!strcmp(curve_name, "Ed25519")) {
		*alg = CRYPT_PKEY_ED25519;
		*key_len = LWS_OPENHITLS_ED25519_KEYLEN;
		*sig_len = LWS_OPENHITLS_ED25519_SIGLEN;
		return 0;
	}

	if (!strcmp(curve_name, "Ed448"))
		lwsl_notice("%s: OpenHiTLS Ed448 is not supported\n", __func__);

	return -1;
}

static int
lws_openhitls_eddsa_alloc_keyel(uint32_t len,
				struct lws_gencrypto_keyelem *el,
				int keyel, const char *reason)
{
	el[keyel].buf = lws_malloc(len, reason);
	if (!el[keyel].buf)
		return -1;
	el[keyel].len = len;

	return 0;
}

int
lws_geneddsa_create(struct lws_genec_ctx *ctx, struct lws_context *context,
		    const struct lws_ec_curves *curve_table)
{
	ctx->context = context;
	ctx->ctx[0] = NULL;
	ctx->ctx[1] = NULL;
	ctx->curve_table = curve_table;
	ctx->genec_alg = LEGENEC_EDDSA;

	return 0;
}

int
lws_geneddsa_set_key(struct lws_genec_ctx *ctx,
		     const struct lws_gencrypto_keyelem *el)
{
	CRYPT_EAL_PkeyPub pub = {0};
	CRYPT_EAL_PkeyPrv prv = {0};
	CRYPT_PKEY_AlgId alg;
	uint32_t key_len, sig_len;
	int ret;

	if (ctx->genec_alg != LEGENEC_EDDSA)
		return -1;

	if (lws_openhitls_eddsa_alg_from_curve(el, &alg, &key_len, &sig_len))
		return -1;

	(void)sig_len;

	if ((el[LWS_GENCRYPTO_OKP_KEYEL_D].len &&
	     el[LWS_GENCRYPTO_OKP_KEYEL_D].len != key_len) ||
	    (el[LWS_GENCRYPTO_OKP_KEYEL_X].len &&
	     el[LWS_GENCRYPTO_OKP_KEYEL_X].len != key_len))
		return -1;

	if (!el[LWS_GENCRYPTO_OKP_KEYEL_D].len &&
	    !el[LWS_GENCRYPTO_OKP_KEYEL_X].len)
		return -1;

	if (ctx->ctx[0])
		CRYPT_EAL_PkeyFreeCtx(ctx->ctx[0]);

	ctx->ctx[0] = CRYPT_EAL_PkeyNewCtx(alg);
	if (!ctx->ctx[0]) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	if (el[LWS_GENCRYPTO_OKP_KEYEL_D].len) {
		prv.id = alg;
		prv.key.curve25519Prv.data =
			(uint8_t *)el[LWS_GENCRYPTO_OKP_KEYEL_D].buf;
		prv.key.curve25519Prv.len =
			(uint32_t)el[LWS_GENCRYPTO_OKP_KEYEL_D].len;
		ret = CRYPT_EAL_PkeySetPrv(ctx->ctx[0], &prv);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeySetPrv failed: %d\n",
				 __func__, ret);
			return -1;
		}
		ctx->has_private = 1;
	} else
		ctx->has_private = 0;

	if (el[LWS_GENCRYPTO_OKP_KEYEL_X].len) {
		pub.id = alg;
		pub.key.curve25519Pub.data =
			(uint8_t *)el[LWS_GENCRYPTO_OKP_KEYEL_X].buf;
		pub.key.curve25519Pub.len =
			(uint32_t)el[LWS_GENCRYPTO_OKP_KEYEL_X].len;
		ret = CRYPT_EAL_PkeySetPub(ctx->ctx[0], &pub);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeySetPub failed: %d\n",
				 __func__, ret);
			return -1;
		}
	}

	return 0;
}

int
lws_geneddsa_new_keypair(struct lws_genec_ctx *ctx, const char *curve_name,
			 struct lws_gencrypto_keyelem *el)
{
	CRYPT_EAL_PkeyPub pub = {0};
	CRYPT_EAL_PkeyPrv prv = {0};
	CRYPT_PKEY_AlgId alg;
	uint32_t key_len, sig_len;
	uint32_t crv_len;
	int ret;

	if (ctx->genec_alg != LEGENEC_EDDSA)
		return -1;

	if (lws_openhitls_eddsa_curve_name_to_alg(curve_name, &alg, &key_len,
						  &sig_len))
		return -1;

	(void)sig_len;

	if (lws_hitls_init_rand() < 0)
		return -1;

	if (ctx->ctx[0])
		CRYPT_EAL_PkeyFreeCtx(ctx->ctx[0]);
	ctx->ctx[0] = CRYPT_EAL_PkeyNewCtx(alg);
	if (!ctx->ctx[0]) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	ret = CRYPT_EAL_PkeyGen(ctx->ctx[0]);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGen failed: %d\n", __func__, ret);
		goto bail;
	}

	crv_len = (uint32_t)strlen(curve_name) + 1;
	if (lws_openhitls_eddsa_alloc_keyel(crv_len, el,
					    LWS_GENCRYPTO_OKP_KEYEL_CRV,
					    "okp-crv") ||
	    lws_openhitls_eddsa_alloc_keyel(key_len, el,
					    LWS_GENCRYPTO_OKP_KEYEL_X,
					    "okp-x") ||
	    lws_openhitls_eddsa_alloc_keyel(key_len, el,
					    LWS_GENCRYPTO_OKP_KEYEL_D,
					    "okp-d")) {
		lwsl_err("%s: OOM allocating OKP key elements\n", __func__);
		goto bail;
	}

	memcpy(el[LWS_GENCRYPTO_OKP_KEYEL_CRV].buf, curve_name, crv_len);

	pub.id = alg;
	pub.key.curve25519Pub.data = el[LWS_GENCRYPTO_OKP_KEYEL_X].buf;
	pub.key.curve25519Pub.len = key_len;
	ret = CRYPT_EAL_PkeyGetPub(ctx->ctx[0], &pub);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed: %d\n", __func__,
			 ret);
		goto bail;
	}
	el[LWS_GENCRYPTO_OKP_KEYEL_X].len = pub.key.curve25519Pub.len;

	prv.id = alg;
	prv.key.curve25519Prv.data = el[LWS_GENCRYPTO_OKP_KEYEL_D].buf;
	prv.key.curve25519Prv.len = key_len;
	ret = CRYPT_EAL_PkeyGetPrv(ctx->ctx[0], &prv);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPrv failed: %d\n", __func__,
			 ret);
		goto bail;
	}
	el[LWS_GENCRYPTO_OKP_KEYEL_D].len = prv.key.curve25519Prv.len;
	ctx->has_private = 1;

	return 0;

bail:
	for (int n = LWS_GENCRYPTO_OKP_KEYEL_CRV;
	     n < LWS_GENCRYPTO_OKP_KEYEL_COUNT; n++)
		if (el[n].buf) {
			lws_free_set_NULL(el[n].buf);
			el[n].len = 0;
		}
	if (ctx->ctx[0]) {
		CRYPT_EAL_PkeyFreeCtx(ctx->ctx[0]);
		ctx->ctx[0] = NULL;
	}

	return -1;
}

int
lws_geneddsa_hash_sig_verify_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
				 size_t in_len, const uint8_t *sig,
				 size_t sig_len)
{
	int ret;

	if (ctx->genec_alg != LEGENEC_EDDSA || !ctx->ctx[0] ||
	    in_len > UINT32_MAX || sig_len > UINT32_MAX)
		return -1;

	ret = CRYPT_EAL_PkeyVerify(ctx->ctx[0], CRYPT_MD_SHA512, in,
				   (uint32_t)in_len, sig, (uint32_t)sig_len);
	if (ret != CRYPT_SUCCESS)
		return -1;

	return 0;
}

int
lws_geneddsa_hash_sign_jws(struct lws_genec_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *sig, size_t sig_len)
{
	uint32_t out_len = (uint32_t)sig_len;
	int ret;

	if (ctx->genec_alg != LEGENEC_EDDSA || !ctx->ctx[0] ||
	    in_len > UINT32_MAX || sig_len > UINT32_MAX)
		return -1;

	if (!ctx->has_private)
		return -1;

	ret = CRYPT_EAL_PkeySign(ctx->ctx[0], CRYPT_MD_SHA512, in,
				 (uint32_t)in_len, sig, &out_len);
	if (ret != CRYPT_SUCCESS)
		return -1;

	return (int)out_len;
}
