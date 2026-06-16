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
 *  lws_genrsa provides an RSA abstraction api in lws that works the
 *  same whether you are using openssl or OpenHiTLS crypto functions underneath.
 */
#include "private-lib-core.h"
#include "private.h"
/* Random number generator initialization state (shared with EC) */
extern int lws_hitls_init_rand(void);

static int
lws_genrsa_set_crypt_padding(struct lws_genrsa_ctx *ctx)
{
	CRYPT_RsaPadType pad;
	CRYPT_MD_AlgId mdId;
	int32_t ret;

	if (ctx->mode == LGRSAM_PKCS1_1_5)
		pad = CRYPT_RSAES_PKCSV15;
	else
		pad = CRYPT_RSAES_OAEP;

	ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_PADDING,
				 &pad, (uint32_t)sizeof(pad));
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_PADDING) failed: %d\n",
			 __func__, ret);
		return -1;
	}
	if (ctx->mode == LGRSAM_PKCS1_OAEP_PSS) {
		mdId = lws_genhash_type_to_hitls_md_id(ctx->oaep_hashid);
		if (mdId == CRYPT_MD_MAX) {
			lwsl_err("%s: unsupported OAEP hash %d\n", __func__,
				 (int)ctx->oaep_hashid);
			return -1;
		}
		BSL_Param oaep_param[] = {
			{ CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0 },
			{ CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0 },
			BSL_PARAM_END
		};

		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_RSAES_OAEP,
					 oaep_param, 0);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_RSAES_OAEP) failed: %d\n",
				 __func__, ret);
			return -1;
		}

		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_OAEP_LABEL,
					 NULL, 0);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_OAEP_LABEL) failed: %d\n",
				 __func__, ret);
			return -1;
		}
	}

	return 0;
}

static int
lws_genrsa_set_sign_padding(struct lws_genrsa_ctx *ctx, CRYPT_MD_AlgId mdId)
{
	int32_t ret;

	if (ctx->mode == LGRSAM_PKCS1_1_5) {
		CRYPT_RsaPadType pad = CRYPT_EMSA_PKCSV15;
		int32_t pkcs15 = (int32_t)mdId;

		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_PADDING,
					 &pad, (uint32_t)sizeof(pad));
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_PADDING) failed: %d\n",
				 __func__, ret);
			return -1;
		}
		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15,
					 &pkcs15, (uint32_t)sizeof(pkcs15));
	} else {
		CRYPT_RSA_PssPara pss;

		pss.saltLen = CRYPT_RSA_SALTLEN_TYPE_HASHLEN;
		pss.mdId = mdId;
		pss.mgfId = mdId;
		ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS,
					 &pss, 0);
	}

	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_RSA_EMSA_*) failed: %d\n",
			 __func__, ret);
		return -1;
	}

	return 0;
}

static int
lws_genrsa_private_encrypt_prepare(struct lws_genrsa_ctx *ctx,
				   const uint8_t *in, size_t in_len,
				   uint8_t **padded, uint32_t *padded_len)
{
	const uint32_t pkcs1_type1_overhead = 11;
	uint32_t len, pad_len;
	uint8_t *buf;

	if (in_len > UINT32_MAX)
		return -1;

	len = CRYPT_EAL_PkeyGetKeyLen(ctx->ctx);
	if (!len) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetKeyLen failed\n", __func__);
		return -1;
	}

	buf = lws_malloc(len, "rsa-prvenc-pad");
	if (!buf)
		return -1;

	switch (ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		if (len <= pkcs1_type1_overhead ||
		    in_len > len - pkcs1_type1_overhead) {
			lwsl_err("%s: input too large for key size\n", __func__);
			goto bail;
		}
		buf[0] = 0x00;
		buf[1] = 0x01;
		pad_len = len - 3 - (uint32_t)in_len;
		memset(&buf[2], 0xff, pad_len);
		buf[2 + pad_len] = 0x00;
		memcpy(&buf[3 + pad_len], in, in_len);
		break;
	default:
		lwsl_err("%s: unsupported mode %d\n", __func__, (int)ctx->mode);
		goto bail;
	}

	*padded = buf;
	*padded_len = len;

	return 0;

bail:
	lws_free(buf);

	return -1;
}

void
lws_genrsa_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	lws_gencrypto_destroy_elements(el, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
}

struct lws_genrsa_keypair_bufs {
	uint8_t *n;
	uint8_t *e;
	uint8_t *d;
	uint8_t *p;
	uint8_t *q;
};

static void
lws_genrsa_keypair_bufs_destroy(struct lws_genrsa_keypair_bufs *bufs)
{
	if (bufs->n)
		lws_free(bufs->n);
	if (bufs->e)
		lws_free(bufs->e);
	if (bufs->d)
		lws_free(bufs->d);
	if (bufs->p)
		lws_free(bufs->p);
	if (bufs->q)
		lws_free(bufs->q);

	memset(bufs, 0, sizeof(*bufs));
}

static int
lws_genrsa_keypair_bufs_alloc(struct lws_genrsa_keypair_bufs *bufs, uint32_t bytes)
{
	bufs->n = lws_malloc(bytes, "rsa-n");
	bufs->e = lws_malloc(3, "rsa-e");
	bufs->d = lws_malloc(bytes, "rsa-d");
	bufs->p = lws_malloc(bytes / 2, "rsa-p");
	bufs->q = lws_malloc(bytes / 2, "rsa-q");
	if (!bufs->n || !bufs->e || !bufs->d || !bufs->p || !bufs->q) {
		lws_genrsa_keypair_bufs_destroy(bufs);
		return -1;
	}

	return 0;
}

static void
lws_genrsa_keypair_bufs_to_elements(struct lws_gencrypto_keyelem *el,
				    const CRYPT_EAL_PkeyPub *pubKey,
				    const CRYPT_EAL_PkeyPrv *prvKey,
				    struct lws_genrsa_keypair_bufs *bufs)
{
	el[LWS_GENCRYPTO_RSA_KEYEL_N].len = pubKey->key.rsaPub.nLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_N].buf = bufs->n;

	el[LWS_GENCRYPTO_RSA_KEYEL_E].len = pubKey->key.rsaPub.eLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_E].buf = bufs->e;

	el[LWS_GENCRYPTO_RSA_KEYEL_D].len = prvKey->key.rsaPrv.dLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_D].buf = bufs->d;

	el[LWS_GENCRYPTO_RSA_KEYEL_P].len = prvKey->key.rsaPrv.pLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_P].buf = bufs->p;

	el[LWS_GENCRYPTO_RSA_KEYEL_Q].len = prvKey->key.rsaPrv.qLen;
	el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = bufs->q;

	memset(bufs, 0, sizeof(*bufs));
}

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;
	ctx->oaep_hashid = oaep_hashid;

	/* Initialize random number generator if needed */
	if (lws_hitls_init_rand() < 0)
		return -1;

	ctx->ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!ctx->ctx) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return 1;
	}

	/* Set public key elements (n and e) */
	CRYPT_EAL_PkeyPub pubKey = {
		.id = CRYPT_PKEY_RSA,
		.key.rsaPub = {
			.n = el[LWS_GENCRYPTO_RSA_KEYEL_N].buf,
			.nLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_N].len,
			.e = el[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
			.eLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_E].len,
		},
	};

	ret = CRYPT_EAL_PkeySetPub(ctx->ctx, &pubKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPub failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Set private key elements if present */
	if (el[LWS_GENCRYPTO_RSA_KEYEL_D].len == 0)
		return 0;

	CRYPT_EAL_PkeyPrv prvKey = {
		.id = CRYPT_PKEY_RSA,
		.key.rsaPrv = {
			.d = el[LWS_GENCRYPTO_RSA_KEYEL_D].buf,
			.dLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_D].len,
			.n = el[LWS_GENCRYPTO_RSA_KEYEL_N].buf,
			.nLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_N].len,
			.e = el[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
			.eLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_E].len,
			.p = el[LWS_GENCRYPTO_RSA_KEYEL_P].len > 0 ?
					el[LWS_GENCRYPTO_RSA_KEYEL_P].buf : NULL,
			.pLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_P].len,
			.q = el[LWS_GENCRYPTO_RSA_KEYEL_Q].len > 0 ?
					el[LWS_GENCRYPTO_RSA_KEYEL_Q].buf : NULL,
			.qLen = (uint32_t)el[LWS_GENCRYPTO_RSA_KEYEL_Q].len,
		},
	};

	ret = CRYPT_EAL_PkeySetPrv(ctx->ctx, &prvKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPrv failed: %d\n", __func__, ret);
		goto bail;
	}

	return 0;

bail:
	CRYPT_EAL_PkeyFreeCtx(ctx->ctx);
	ctx->ctx = NULL;
	return 1;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	CRYPT_EAL_PkeyPara para = {0};
	CRYPT_RsaPara *rsaPara = &para.para.rsaPara;
	struct lws_genrsa_keypair_bufs bufs;
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;
	ctx->oaep_hashid = LWS_GENHASH_TYPE_SHA1;
	memset(&bufs, 0, sizeof(bufs));

	/* Initialize random number generator if needed */
	if (lws_hitls_init_rand() < 0)
		return -1;

	ctx->ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!ctx->ctx) {
		lwsl_err("%s: CRYPT_EAL_PkeyNewCtx failed\n", __func__);
		return -1;
	}

	/* Set RSA parameters for key generation
	 * Use the standard public exponent 65537 (0x010001) */
	static const uint8_t default_pub_exp[] = {0x01, 0x00, 0x01};
	para.id = CRYPT_PKEY_RSA;
	rsaPara->e = (uint8_t *)default_pub_exp;
	rsaPara->eLen = sizeof(default_pub_exp);
	rsaPara->bits = (uint32_t)bits;

	ret = CRYPT_EAL_PkeySetPara(ctx->ctx, &para);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySetPara failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Generate the key */
	ret = CRYPT_EAL_PkeyGen(ctx->ctx);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGen failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Extract the key elements
	 * Need to allocate buffers for the output first */
	uint32_t bytes = (uint32_t)bits / 8;
	if (lws_genrsa_keypair_bufs_alloc(&bufs, bytes))
		goto bail;

	CRYPT_EAL_PkeyPub pubKey = {
		.id = CRYPT_PKEY_RSA,
		.key.rsaPub = {
			.n = bufs.n,
			.nLen = bytes,
			.e = bufs.e,
			.eLen = 3,
		},
	};
	CRYPT_EAL_PkeyPrv prvKey = {
		.id = CRYPT_PKEY_RSA,
		.key.rsaPrv = {
			.n = bufs.n,
			.nLen = bytes,
			.d = bufs.d,
			.dLen = bytes,
			.p = bufs.p,
			.pLen = (uint32_t)bytes / 2,
			.q = bufs.q,
			.qLen = (uint32_t)bytes / 2,
			.e = NULL,
			.eLen = 0,
		},
	};

	ret = CRYPT_EAL_PkeyGetPub(ctx->ctx, &pubKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed: %d\n", __func__, ret);
		goto bail;
	}

	ret = CRYPT_EAL_PkeyGetPrv(ctx->ctx, &prvKey);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPrv failed: %d\n", __func__, ret);
		goto bail;
	}

	/* Now copy the data to the output elements
	 * Take ownership of the allocated buffers */
	lws_genrsa_keypair_bufs_to_elements(el, &pubKey, &prvKey, &bufs);

	/* Note: Padding mode is set separately during encrypt/decrypt operations,
	 * not during key generation */

	return 0;

bail:
	lws_genrsa_keypair_bufs_destroy(&bufs);
	lws_genrsa_destroy_elements(el);

	CRYPT_EAL_PkeyFreeCtx(ctx->ctx);
	ctx->ctx = NULL;

	return -1;
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	uint32_t outLen = CRYPT_EAL_PkeyGetKeyLen(ctx->ctx);
	int32_t ret;

	if (!outLen) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetKeyLen failed\n", __func__);
		return -1;
	}

	if (lws_genrsa_set_crypt_padding(ctx))
		return -1;

	ret = CRYPT_EAL_PkeyEncrypt(ctx->ctx, in, (uint32_t)in_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyEncrypt failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)outLen;
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	uint8_t *padded = NULL;
	uint32_t outLen, padded_len;
	int32_t ret;

	if (lws_genrsa_private_encrypt_prepare(ctx, in, in_len,
					       &padded, &padded_len))
		return -1;
	outLen = padded_len;

	ret = CRYPT_EAL_PkeyCtrl(ctx->ctx, CRYPT_CTRL_SET_NO_PADDING, NULL, 0);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyCtrl(SET_NO_PADDING) failed: %d\n",
			 __func__, ret);
		goto bail;
	}

	ret = CRYPT_EAL_PkeyDecrypt(ctx->ctx, padded, padded_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyDecrypt failed: %d\n", __func__, ret);
		goto bail;
	}

	lws_free(padded);

	return (int)outLen;

bail:
	if (padded)
		lws_free(padded);

	return -1;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	uint32_t outLen;
	int32_t ret;

	if (out_max > UINT32_MAX)
		return -1;

	if (lws_genrsa_set_crypt_padding(ctx))
		return -1;

	outLen = (uint32_t)out_max;
	ret = CRYPT_EAL_PkeyVerifyRecover(ctx->ctx, in, (uint32_t)in_len,
					  out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyVerifyRecover failed: %d\n",
			 __func__, ret);
		return -1;
	}

	return (int)outLen;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	uint32_t outLen = (uint32_t)out_max;
	int32_t ret;

	if (lws_genrsa_set_crypt_padding(ctx))
		return -1;

	ret = CRYPT_EAL_PkeyDecrypt(ctx->ctx, in, (uint32_t)in_len, out, &outLen);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyDecrypt failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)outLen;
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	CRYPT_MD_AlgId mdId;
	uint32_t hash_len;
	int32_t ret;

	mdId = lws_genhash_type_to_hitls_md_id(hash_type);
	if (mdId == CRYPT_MD_MAX)
		return -1;
	hash_len = (uint32_t)lws_genhash_size(hash_type);

	if (lws_genrsa_set_sign_padding(ctx, mdId))
		return -1;

	ret = CRYPT_EAL_PkeyVerifyData(ctx->ctx, in, hash_len,
				       sig, (uint32_t)sig_len);
	if (ret != CRYPT_SUCCESS) {
		lwsl_notice("%s: CRYPT_EAL_PkeyVerifyData failed: %d\n", __func__, ret);
		return -1;
	}

	return 0;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	CRYPT_MD_AlgId mdId;
	uint32_t hash_len;
	uint32_t used = (uint32_t)sig_len;
	int32_t ret;

	mdId = lws_genhash_type_to_hitls_md_id(hash_type);
	if (mdId == CRYPT_MD_MAX)
		return -1;
	hash_len = (uint32_t)lws_genhash_size(hash_type);

	if (lws_genrsa_set_sign_padding(ctx, mdId))
		return -1;

	ret = CRYPT_EAL_PkeySignData(ctx->ctx, in, hash_len, sig, &used);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeySignData failed: %d\n", __func__, ret);
		return -1;
	}

	return (int)used;
}

void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (!ctx->ctx)
		return;

	CRYPT_EAL_PkeyFreeCtx(ctx->ctx);
	ctx->ctx = NULL;
}
