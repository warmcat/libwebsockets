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
#include <hitls_pki_utils.h>
#include <crypt_eal_codecs.h>

extern int32_t
HITLS_X509_GetDistinguishNameStrFromList(BslList *list, BSL_Buffer *buff);

static time_t
lws_tls_openhitls_bsltime_to_unix(BSL_TIME *bsl_time)
{
#if !defined(LWS_PLAT_OPTEE)
	struct tm t;
	memset(&t, 0, sizeof(t));
	t.tm_year = bsl_time->year - 1900;
	t.tm_mon = bsl_time->month - 1;
	t.tm_mday = bsl_time->day - 1;
	t.tm_hour = bsl_time->hour;
	t.tm_min = bsl_time->minute;
	t.tm_sec = bsl_time->second;
	t.tm_isdst = 0;
	return mktime(&t);
#else
	return (time_t)-1;
#endif
}

static int
lws_openhitls_append_aki_issuer(union lws_tls_cert_info_results *buf,
				size_t len, const uint8_t *data,
				size_t data_len)
{
	size_t used = (size_t)buf->ns.len;

	buf->ns.len = (int)(used + data_len);
	if (buf->ns.len < 0 || len <= used || data_len >= len - used)
		return -1;

	memcpy(buf->ns.name + used, data, data_len);
	buf->ns.name[used + data_len] = '\0';

	return 0;
}

static int
lws_openhitls_aki_issuer_name(union lws_tls_cert_info_results *buf,
			      size_t len, HITLS_X509_ExtAki *aki)
{
	HITLS_X509_GeneralName *gn;
	int ret = 1;

	if (!aki->issuerName || !BSL_LIST_COUNT(aki->issuerName))
		return 1;

	buf->ns.len = 0;
	gn = BSL_LIST_GET_FIRST(aki->issuerName);
	while (gn) {
		if (gn->type == HITLS_X509_GN_DNNAME) {
			BSL_Buffer dn = { 0 };

			/* Return the AKI issuer as a NUL-terminated certinfo
			 * string; too-small buffers fail before truncating.
			 */
			if (HITLS_X509_GetDistinguishNameStrFromList(
				    (BslList *)(uintptr_t)gn->value.data,
				    &dn) != HITLS_PKI_SUCCESS)
				return -1;
			ret = lws_openhitls_append_aki_issuer(buf, len,
							     dn.data,
							     dn.dataLen);
			BSL_SAL_Free(dn.data);
		} else {
			ret = lws_openhitls_append_aki_issuer(buf, len,
							     gn->value.data,
							     gn->value.dataLen);
		}

		if (ret)
			return ret;

		gn = BSL_LIST_GET_NEXT(aki->issuerName);
	}

	return buf->ns.len ? 0 : 1;
}

int
lws_tls_openhitls_cert_info(HITLS_X509_Cert *x509, enum lws_tls_cert_info type,
			     union lws_tls_cert_info_results *buf, size_t len)
{
	CRYPT_EAL_PkeyCtx *pubkey = NULL;
	HITLS_X509_ExtAki aki = {0};
	HITLS_X509_ExtSki ski = {0};
	BSL_Buffer encode = {0};
	BSL_TIME bsl_time = {0};
	uint32_t usage;
	int32_t ret;
	if (!buf || !x509) {
		return -1;
	}
	buf->ns.len = 0;
	if (!len) {
		len = sizeof(buf->ns.name);
	}

	switch (type) {
	case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_BEFORE_TIME, &bsl_time, sizeof(BSL_TIME));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_BEFORE_TIME failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->time = lws_tls_openhitls_bsltime_to_unix(&bsl_time);
		if (buf->time == (time_t)-1) {
			return -1;
		}
		return 0;

	case LWS_TLS_CERT_INFO_VALIDITY_TO:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_AFTER_TIME, &bsl_time, sizeof(BSL_TIME));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_AFTER_TIME failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->time = lws_tls_openhitls_bsltime_to_unix(&bsl_time);
		if (buf->time == (time_t)-1) {
			return -1;
		}
		return 0;

	case LWS_TLS_CERT_INFO_COMMON_NAME:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_SUBJECT_CN_STR, &encode, sizeof(BSL_Buffer));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_SUBJECT_CN_STR failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		if (encode.dataLen + 1 > len) {
			BSL_SAL_Free(encode.data);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		buf->ns.name[encode.dataLen] = '\0';
		BSL_SAL_Free(encode.data);
		return 0;

	case LWS_TLS_CERT_INFO_ISSUER_NAME:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_ISSUER_DN_STR, &encode, sizeof(BSL_Buffer));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_ISSUER_DN_STR failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		if (encode.dataLen + 1 > len) {
			BSL_SAL_Free(encode.data);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		buf->ns.name[encode.dataLen] = '\0';
		BSL_SAL_Free(encode.data);
		return 0;

	case LWS_TLS_CERT_INFO_USAGE:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_KUSAGE, &usage, sizeof(usage));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_KUSAGE failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->usage = usage;
		return 0;

	case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_PUBKEY, &pubkey, sizeof(CRYPT_EAL_PkeyCtx *));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_PUBKEY failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		ret = CRYPT_EAL_EncodeBuffKey(pubkey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encode);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_EncodeBuffKey failed, ret=0x%x\n", __func__, ret);
			CRYPT_EAL_PkeyFreeCtx(pubkey);
			return -1;
		}
		if (encode.dataLen > len) {
			lwsl_err("%s: output buffer too small, need=%u, have=%zu\n", __func__, encode.dataLen, len);
			BSL_SAL_Free(encode.data);
			CRYPT_EAL_PkeyFreeCtx(pubkey);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		BSL_SAL_Free(encode.data);
		CRYPT_EAL_PkeyFreeCtx(pubkey);
		return 0;

	case LWS_TLS_CERT_INFO_DER_SPKI:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_PUBKEY, &pubkey,
					  sizeof(CRYPT_EAL_PkeyCtx *));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_PUBKEY failed, ret=0x%x\n",
				 __func__, ret);
			return -1;
		}
		ret = CRYPT_EAL_EncodeBuffKey(pubkey, NULL, BSL_FORMAT_ASN1,
					      CRYPT_PUBKEY_SUBKEY, &encode);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_EncodeBuffKey failed, ret=0x%x\n",
				 __func__, ret);
			CRYPT_EAL_PkeyFreeCtx(pubkey);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		if (encode.dataLen > len) {
			BSL_SAL_Free(encode.data);
			CRYPT_EAL_PkeyFreeCtx(pubkey);
			return -1;
		}
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		BSL_SAL_Free(encode.data);
		CRYPT_EAL_PkeyFreeCtx(pubkey);
		return 0;

	case LWS_TLS_CERT_INFO_DER_RAW:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_ENCODELEN, &encode.dataLen, sizeof(encode.dataLen));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_ENCODELEN failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		buf->ns.len = (int)encode.dataLen;
		if (encode.dataLen > len) {
			lwsl_err("%s: output buffer too small, need=%u, have=%zu\n", __func__, encode.dataLen, len);
			return -1;
		}
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_GET_ENCODE, &encode.data, 0);
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_ENCODE failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		memcpy(buf->ns.name, encode.data, encode.dataLen);
		return 0;

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_AKI failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		if (!aki.kid.data || aki.kid.dataLen == 0) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return 1;
		}
		if (len < aki.kid.dataLen) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		buf->ns.len = (int)aki.kid.dataLen;
		memcpy(buf->ns.name, aki.kid.data, (size_t)buf->ns.len);
		HITLS_X509_ClearAuthorityKeyId(&aki);
		return 0;

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_AKI failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		ret = lws_openhitls_aki_issuer_name(buf, len, &aki);
		HITLS_X509_ClearAuthorityKeyId(&aki);
		return ret;

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_AKI failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		if (!aki.serialNum.data || aki.serialNum.dataLen == 0) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return 1;
		}
		if (len < aki.serialNum.dataLen) {
			HITLS_X509_ClearAuthorityKeyId(&aki);
			return -1;
		}
		buf->ns.len = (int)aki.serialNum.dataLen;
		memcpy(buf->ns.name, aki.serialNum.data, (size_t)buf->ns.len);
		HITLS_X509_ClearAuthorityKeyId(&aki);
		return 0;

	case LWS_TLS_CERT_INFO_SUBJECT_KEY_ID:
		ret = HITLS_X509_CertCtrl(x509, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_EXT_GET_SKI failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		if (!ski.kid.data || ski.kid.dataLen == 0) {
			return 1;
		}
		if (len < ski.kid.dataLen) {
			return -1;
		}
		buf->ns.len = (int)ski.kid.dataLen;
		memcpy(buf->ns.name, ski.kid.data, (size_t)buf->ns.len);
		return 0;

	default:
		return -1;
	}

	return 0;
}

int
lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type,
	      union lws_tls_cert_info_results *buf, size_t len)
{
	return lws_tls_openhitls_cert_info(x509->cert, type, buf, len);
}

#if defined(LWS_WITH_NETWORK)
int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	HITLS_X509_Cert *cert;
	HITLS_Ctx *ssl;
	int ret;

	wsi = lws_get_network_wsi(wsi);
	if (!wsi || !wsi->tls.ssl || !buf) {
		return -1;
	}
	ssl = (HITLS_Ctx *)wsi->tls.ssl;
	cert = HITLS_GetPeerCertificate(ssl);
	if (!cert) {
		lwsl_debug("%s: no peer certificate\n", __func__);
		return -1;
	}
	if (type == LWS_TLS_CERT_INFO_VERIFIED) {
		HITLS_ERROR verify_result = HITLS_X509_V_OK;
		ret = HITLS_GetVerifyResult((const HITLS_Ctx *)ssl, &verify_result);
		if (ret != HITLS_SUCCESS) {
			HITLS_X509_CertFree(cert);
			return -1;
		}
		buf->verified = verify_result == HITLS_X509_V_OK;
		HITLS_X509_CertFree(cert);
		return 0;
	}
	ret = lws_tls_openhitls_cert_info(cert, type, buf, len);
	HITLS_X509_CertFree(cert);
	return ret;
}

int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
			       union lws_tls_cert_info_results *buf, size_t len)
{
	lws_tls_ctx *ctx;
	HITLS_X509_Cert *cert;

	if (!vhost || !vhost->tls.ssl_ctx) {
		return -1;
	}
	ctx = vhost->tls.ssl_ctx;
	cert = HITLS_CFG_GetCertificate(ctx);
	if (!cert) {
		lwsl_debug("%s: no vhost certificate configured\n", __func__);
		return -1;
	}
	return lws_tls_openhitls_cert_info(cert, type, buf, len);
}
#endif

int
lws_x509_create(struct lws_x509_cert **x509)
{
	*x509 = lws_malloc(sizeof(**x509), __func__);
	if (*x509)
		(*x509)->cert = NULL;
	return !(*x509);
}

int
lws_x509_parse_from_pem(struct lws_x509_cert *x509, const void *pem, size_t len)
{
	BSL_Buffer buf;
	int32_t ret;
	uint8_t *pem_copy = NULL;

	if (!x509 || !pem || !len) {
		return -1;
	}
	if (((const char *)pem)[len - 1] != '\0') {
		pem_copy = lws_malloc(len + 1, __func__);
		if (!pem_copy)
			return -1;
		memcpy(pem_copy, pem, len);
		pem_copy[len] = '\0';
		buf.data = pem_copy;
		buf.dataLen = (uint32_t)len;
	} else {
		buf.data = (uint8_t *)(lws_intptr_t)pem;
		buf.dataLen = (uint32_t)len - 1;
	}

	ret = HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &buf, &x509->cert);
	lws_free(pem_copy);
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertParseBuff failed, ret=0x%x\n", __func__, ret);
		return -1;
	}
	return 0;
}

void
lws_x509_destroy(struct lws_x509_cert **x509)
{
	if (!x509 || !*x509) {
		return;
	}
	if ((*x509)->cert) {
		HITLS_X509_CertFree((*x509)->cert);
		(*x509)->cert = NULL;
	}
	lws_free_set_NULL(*x509);
}

static int
X509_AddCertToChain(HITLS_X509_List *chain, HITLS_X509_Cert *cert)
{
    int ref;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(chain, cert, BSL_LIST_POS_END);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_CertFree(cert);
    }
    return ret;
}

int
lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted, const char *common_name)
{
	HITLS_X509_StoreCtx *store_ctx = NULL;
	HITLS_X509_List *chain = NULL;
	BSL_Buffer encode = {0};
	int result = -1;
	int32_t ret;

	if (!x509 || !x509->cert || !trusted || !trusted->cert) {
		return -1;
	}
	if (common_name) {
		ret = HITLS_X509_CertCtrl(x509->cert, HITLS_X509_GET_SUBJECT_CN_STR, &encode, sizeof(BSL_Buffer));
		if (ret != HITLS_PKI_SUCCESS) {
			lwsl_err("%s: HITLS_X509_GET_SUBJECT_CN_STR failed, ret=0x%x\n", __func__, ret);
			return -1;
		}
		if (encode.dataLen != strlen(common_name) || memcmp(encode.data, common_name, encode.dataLen)) {
			lwsl_err("%s: common name mismatch: got '%.*s' (len %zu), expected '%s' (len %zu)\n", __func__, (int)encode.dataLen, encode.data, (size_t)encode.dataLen, common_name, strlen(common_name));
			BSL_SAL_Free(encode.data);
			return -1;
		}
		BSL_SAL_Free(encode.data);
	}
	store_ctx = HITLS_X509_StoreCtxNew();
	if (!store_ctx) {
		lwsl_err("%s: failed to create store context\n", __func__);
		return -1;
	}
	ret = HITLS_X509_StoreCtxCtrl(store_ctx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, trusted->cert, sizeof(HITLS_X509_Cert *));
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_StoreCtxCtrl(SET_CA) failed, ret=0x%x\n", __func__, ret);
		goto bail;
	}
	chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
	if (chain == NULL) {
		lwsl_err("%s: BSL_LIST_New failed\n", __func__);
		goto bail;
	}
	ret = X509_AddCertToChain(chain, x509->cert);
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: X509_AddCertToChain failed, ret=0x%x\n", __func__, ret);
		goto bail;
	}
	ret = HITLS_X509_CertVerify(store_ctx, chain);
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_CertVerify failed, ret=0x%x\n", __func__, ret);
		goto bail;
	}
	result = 0;
bail:
	HITLS_X509_StoreCtxFree(store_ctx);
	BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
	return result;
}

#if defined(LWS_WITH_JOSE)
static int
lws_x509_public_to_jwk_rsa(struct lws_jwk *jwk, CRYPT_EAL_PkeyCtx *pubkey, int rsa_min_bits)
{
	CRYPT_EAL_PkeyPub rsa_pub = {0};
	uint8_t *n_buf = NULL, *e_buf = NULL;
	uint32_t key_bytes;
	int result = -1;
	int32_t ret;

	key_bytes = CRYPT_EAL_PkeyGetKeyLen(pubkey);
	if ((int)(key_bytes * 8) < rsa_min_bits) {
		lwsl_err("%s: RSA key too small (%u < %d)\n", __func__, key_bytes * 8, rsa_min_bits);
		return -1;
	}
	n_buf = lws_malloc(key_bytes, "jwk-rsa-n");
	e_buf = lws_malloc(key_bytes, "jwk-rsa-e");
	if (!n_buf || !e_buf) {
		goto bail;
	}
	rsa_pub.id = CRYPT_PKEY_RSA;
	rsa_pub.key.rsaPub.n = n_buf;
	rsa_pub.key.rsaPub.nLen = key_bytes;
	rsa_pub.key.rsaPub.e = e_buf;
	rsa_pub.key.rsaPub.eLen = key_bytes;
	/* CRYPT_EAL_PkeyGetPub will fill in the actual lengths of n and e, which may be less than key_bytes */
	ret = CRYPT_EAL_PkeyGetPub(pubkey, &rsa_pub);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed for RSA, ret=0x%x\n", __func__, ret);
		goto bail;
	}
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc(rsa_pub.key.rsaPub.nLen, "certkeyimp");
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc(rsa_pub.key.rsaPub.eLen, "certkeyimp");
	if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf || !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf) {
		lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf);
		lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf);
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = NULL;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = NULL;
		goto bail;
	}
	jwk->kty = LWS_GENCRYPTO_KTY_RSA;
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len = rsa_pub.key.rsaPub.nLen;
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len = rsa_pub.key.rsaPub.eLen;
	memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, rsa_pub.key.rsaPub.n, rsa_pub.key.rsaPub.nLen);
	memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, rsa_pub.key.rsaPub.e, rsa_pub.key.rsaPub.eLen);
	result = 0;
bail:
	lws_free(n_buf);
	lws_free(e_buf);
	return result;
}

static int
lws_x509_public_to_jwk_ec(struct lws_jwk *jwk, CRYPT_EAL_PkeyCtx *pubkey, const char *curves)
{
	CRYPT_EAL_PkeyPub ecc_pub = {0};
	CRYPT_PKEY_ParaId curve_id;
	const struct lws_ec_curves *curve;
	uint8_t *tmp_buf = NULL;
	uint32_t coord_len, pub_len;
	int32_t result = -1;
	int32_t ret;

	if (!curves) {
		lwsl_err("%s: ec curves not allowed\n", __func__);
		return -1;
	}
	curve_id = CRYPT_EAL_PkeyGetParaId(pubkey);
	if (lws_genec_confirm_curve_allowed_by_tls_id(curves, (int)curve_id, jwk)) {
		return -1;
	}
	curve = lws_genec_curve(lws_ec_curves, (char *)jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
	if (!curve) {
		lwsl_err("%s: curve not found\n", __func__);
		return -1;
	}
	coord_len = curve->key_bytes;
	pub_len = 1 + 2 * coord_len;
	tmp_buf = lws_malloc(pub_len, "jwk-ecc-pub");
	if (!tmp_buf) {
		return -1;
	}
	ecc_pub.id = CRYPT_PKEY_ECDSA;
	ecc_pub.key.eccPub.data = tmp_buf;
	ecc_pub.key.eccPub.len = pub_len;
	ret = CRYPT_EAL_PkeyGetPub(pubkey, &ecc_pub);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed for EC, ret=0x%x\n", __func__, ret);
		goto bail;
	}
	if (ecc_pub.key.eccPub.len != pub_len || ecc_pub.key.eccPub.data[0] != 0x04) {
		lwsl_err("%s: invalid EC public key format\n", __func__);
		goto bail;
	}
	jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(coord_len, "certkeyimp");
	jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(coord_len, "certkeyimp");
	if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf || !jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf) {
		lws_free(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf);
		lws_free(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf);
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = NULL;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = NULL;
		goto bail;
	}
	jwk->kty = LWS_GENCRYPTO_KTY_EC;
	jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len = coord_len;
	jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len = coord_len;
	memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, ecc_pub.key.eccPub.data + 1, coord_len);
	memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, ecc_pub.key.eccPub.data + 1 + coord_len, coord_len);
	result = 0;
bail:
	lws_free(tmp_buf);
	return result;
}

int
lws_x509_public_to_jwk(struct lws_jwk *jwk, struct lws_x509_cert *x509, const char *curves, int rsa_min_bits)
{
	CRYPT_EAL_PkeyCtx *pubkey = NULL;
	int result = -1;
	int32_t ret;

	if (!jwk || !x509 || !x509->cert) {
		return -1;
	}
	memset(jwk, 0, sizeof(*jwk));
	ret = HITLS_X509_CertCtrl(x509->cert, HITLS_X509_GET_PUBKEY, &pubkey, sizeof(CRYPT_EAL_PkeyCtx *));
	if (ret != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: HITLS_X509_GET_PUBKEY failed, ret=0x%x\n", __func__, ret);
		return -1;
	}

	CRYPT_PKEY_AlgId alg_id = CRYPT_EAL_PkeyGetId(pubkey);
	if (alg_id == CRYPT_PKEY_RSA) {
		result = lws_x509_public_to_jwk_rsa(jwk, pubkey, rsa_min_bits);
	}
	else if (alg_id == CRYPT_PKEY_ECDSA) {
		result = lws_x509_public_to_jwk_ec(jwk, pubkey, curves);
	}
	else {
		lwsl_err("%s: unsupported key type %d\n", __func__, alg_id);
	}

	CRYPT_EAL_PkeyFreeCtx(pubkey);
	return result;
}

static int
lws_x509_jwk_privkey_pem_ec(struct lws_jwk *jwk, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId alg_id)
{
	CRYPT_EAL_PkeyPrv prv = {0};
	uint8_t *tmp_ec_d = NULL;
	uint32_t coord_len;
	int32_t ret;

	if (alg_id != CRYPT_PKEY_ECDSA) {
		lwsl_err("%s: jwk is EC but privkey is %d\n", __func__, alg_id);
		return -1;
	}
	coord_len = jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len;
	if (coord_len == 0) {
		lwsl_err("%s: JWK EC Y coordinate length is 0\n", __func__);
		return -1;
	}
	tmp_ec_d = lws_malloc(coord_len, "jwk-ec-d");
	if (!tmp_ec_d) {
		return -1;
	}
	prv.id = CRYPT_PKEY_ECDSA;
	prv.key.eccPrv.data = tmp_ec_d;
	prv.key.eccPrv.len = coord_len;
	ret = CRYPT_EAL_PkeyGetPrv(pkey, &prv);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to extract EC private key, ret=0x%x\n", __func__, ret);
		lws_free(tmp_ec_d);
		return -1;
	}
	if (prv.key.eccPrv.len < coord_len) {
		uint32_t pad_len = coord_len - prv.key.eccPrv.len;
		memmove(tmp_ec_d + pad_len, tmp_ec_d, prv.key.eccPrv.len);
		memset(tmp_ec_d, 0, pad_len);
	}
	jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf = tmp_ec_d;
	jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len = coord_len;
	return 0;
}

static int
lws_x509_jwk_privkey_pem_rsa(struct lws_jwk *jwk, CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_AlgId alg_id)
{
	CRYPT_EAL_PkeyPrv prv = {0};
	uint8_t *tmp_n = NULL, *tmp_e = NULL, *tmp_d = NULL;
	uint8_t *tmp_p = NULL, *tmp_q = NULL;
	uint32_t key_bytes;
	int32_t result = -1;
	int32_t ret;

	if (alg_id != CRYPT_PKEY_RSA) {
		lwsl_err("%s: RSA jwk, non-RSA privkey %d\n", __func__, alg_id);
		return -1;
	}
	key_bytes = CRYPT_EAL_PkeyGetKeyLen(pkey);
	if (key_bytes == 0) {
		lwsl_err("%s: failed to get RSA key length\n", __func__);
		return -1;
	}
	tmp_n = lws_malloc(key_bytes, "jwk-rsa-n");
	tmp_e = lws_malloc(key_bytes, "jwk-rsa-e");
	tmp_d = lws_malloc(key_bytes, "jwk-rsa-d");
	tmp_p = lws_malloc(key_bytes, "jwk-rsa-p");
	tmp_q = lws_malloc(key_bytes, "jwk-rsa-q");
	if (!tmp_n || !tmp_e || !tmp_d || !tmp_p || !tmp_q) {
		goto bail;
	}
	prv.id = CRYPT_PKEY_RSA;
	prv.key.rsaPrv.n = tmp_n;
	prv.key.rsaPrv.nLen = key_bytes;
	prv.key.rsaPrv.e = tmp_e;
	prv.key.rsaPrv.eLen = key_bytes;
	prv.key.rsaPrv.d = tmp_d;
	prv.key.rsaPrv.dLen = key_bytes;
	prv.key.rsaPrv.p = tmp_p;
	prv.key.rsaPrv.pLen = key_bytes;
	prv.key.rsaPrv.q = tmp_q;
	prv.key.rsaPrv.qLen = key_bytes;

	ret = CRYPT_EAL_PkeyGetPrv(pkey, &prv);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to extract RSA private key, ret=0x%x\n", __func__, ret);
		goto bail;
	}
	if (prv.key.rsaPrv.nLen != jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len ||
	    memcmp(prv.key.rsaPrv.n, jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf,
		   prv.key.rsaPrv.nLen)) {
		lwsl_err("%s: RSA privkey n doesn't match jwk pubkey\n", __func__);
		goto bail;
	}
	if (prv.key.rsaPrv.eLen != jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len ||
	    memcmp(prv.key.rsaPrv.e, jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
		   prv.key.rsaPrv.eLen)) {
		lwsl_err("%s: RSA privkey e doesn't match jwk pubkey\n", __func__);
		goto bail;
	}
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf = lws_malloc(prv.key.rsaPrv.dLen, "jwk-d");
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf = lws_malloc(prv.key.rsaPrv.pLen, "jwk-p");
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = lws_malloc(prv.key.rsaPrv.qLen, "jwk-q");
	if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf ||
	    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
	    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) {
		lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf);
		lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf);
		lws_free(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf);
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf = NULL;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf = NULL;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = NULL;
		goto bail;
	}

	memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf, prv.key.rsaPrv.d, prv.key.rsaPrv.dLen);
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].len = prv.key.rsaPrv.dLen;
	memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf, prv.key.rsaPrv.p, prv.key.rsaPrv.pLen);
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].len = prv.key.rsaPrv.pLen;
	memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, prv.key.rsaPrv.q, prv.key.rsaPrv.qLen);
	jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].len = prv.key.rsaPrv.qLen;
	result = 0;
bail:
	lws_free(tmp_n);
	lws_free(tmp_e);
	lws_free(tmp_d);
	lws_free(tmp_p);
	lws_free(tmp_q);
	return result;
}

int
lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk, void *pem, size_t len, const char *passphrase)
{
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	BSL_Buffer pem_buf, pwd_buf = {0};
	uint8_t *pem_copy = NULL;
	int result = -1;
	int32_t ret;

	if (!jwk || !pem || !len) {
		return -1;
	}

	if (((const char *)pem)[len - 1] != '\0') {
		pem_copy = lws_malloc(len + 1, __func__);
		if (!pem_copy) {
			return -1;
		}
		memcpy(pem_copy, pem, len);
		pem_copy[len] = '\0';
		pem_buf.data = pem_copy;
		pem_buf.dataLen = (uint32_t)len;
	} else {
		pem_buf.data = (uint8_t *)pem;
		pem_buf.dataLen = (uint32_t)len - 1;
	}

	if (passphrase) {
		pwd_buf.data = (uint8_t *)(lws_intptr_t)passphrase;
		pwd_buf.dataLen = (uint32_t)strlen(passphrase);
	}
	ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_ENCDEC_UNKNOW, &pem_buf, pwd_buf.data, pwd_buf.dataLen, &pkey);
	if (pem_copy) {
		lws_explicit_bzero(pem_copy, len + 1);
		lws_free(pem_copy);
	} else {
		lws_explicit_bzero(pem, len);
	}
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: failed to parse PEM private key, ret=0x%x\n", __func__, ret);
		return -1;
	}

	CRYPT_PKEY_AlgId alg_id = CRYPT_EAL_PkeyGetId(pkey);
	if (jwk->kty == LWS_GENCRYPTO_KTY_EC) {
		result = lws_x509_jwk_privkey_pem_ec(jwk, pkey, alg_id);
	}
	else if (jwk->kty == LWS_GENCRYPTO_KTY_RSA) {
		result = lws_x509_jwk_privkey_pem_rsa(jwk, pkey, alg_id);
	}
	else {
		lwsl_err("%s: unknown JWK kty %d\n", __func__, jwk->kty);
	}

	CRYPT_EAL_PkeyFreeCtx(pkey);
	return result;
}
#endif
