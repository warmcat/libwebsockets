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
#include <crypt_eal_pkey.h>
#include <crypt_eal_rand.h>
#include <bsl_list.h>
#include <bsl_obj.h>

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
	/* tm_mon is 0-based, but tm_mday is 1-based like the cert field */
	t.tm_mday = bsl_time->day;
	t.tm_hour = bsl_time->hour;
	t.tm_min = bsl_time->minute;
	t.tm_sec = bsl_time->second;
	t.tm_isdst = 0;

	/*
	 * X.509 times are UTC, so they must not be reinterpreted in the local
	 * timezone... mktime() is only a fallback for platforms lacking a UTC
	 * conversion, and skews the result by the local UTC offset.
	 */

#if defined(WIN32)
	return _mkgmtime(&t);
#else
#if defined(LWS_HAVE_TIMEGM) && !defined(OPTEE_DEV_KIT)
	return timegm(&t);
#else
	return mktime(&t);
#endif
#endif
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

/*
 * openHiTLS gives us a name's raw value bytes, whatever its string type.  We
 * hand it out as a C string, so it has to be all of it: with an embedded NUL,
 * every string consumer would act on just the part before it, eg, a cert-dist
 * client cert with CN "victim.example.com\0.x" would be taken for
 * "victim.example.com".  Other control characters (and so UCS-2 / UCS-4
 * string types) have no place in a name either: refuse the name, as the
 * openssl backend does.
 */

static int
lws_openhitls_name_unsafe(const uint8_t *p, uint32_t len)
{
	uint32_t n;

	for (n = 0; n < len; n++)
		if (p[n] < 0x20 || p[n] == 0x7f)
			return 1;

	return 0;
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
		if (!encode.dataLen ||
		    lws_openhitls_name_unsafe(encode.data, encode.dataLen)) {
			lwsl_notice("%s: CN is empty or has control characters\n",
				    __func__);
			BSL_SAL_Free(encode.data);
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
		if (lws_openhitls_name_unsafe(encode.data, encode.dataLen)) {
			lwsl_notice("%s: issuer DN has control characters\n",
				    __func__);
			BSL_SAL_Free(encode.data);
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
	if (!wsi || !wsi->io->tls.ssl || !buf) {
		return -1;
	}
	ssl = (HITLS_Ctx *)wsi->io->tls.ssl;
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

	/*
	 * Confirm the private key belongs to the cert... without comparing the
	 * public point, any other key on the same curve is accepted, since
	 * every P-256 x is 32 bytes
	 */

	{
		CRYPT_EAL_PkeyPub ecc_pub = {0};
		uint32_t pub_len = 1 + 2 * coord_len;
		uint8_t *pub_buf;
		int mismatch;

		if (coord_len != jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len ||
		    !jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf ||
		    !jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf) {
			lwsl_err("%s: jwk has no usable EC pubkey\n", __func__);
			return -1;
		}

		pub_buf = lws_malloc(pub_len, "jwk-ecc-pub");
		if (!pub_buf) {
			return -1;
		}
		ecc_pub.id = CRYPT_PKEY_ECDSA;
		ecc_pub.key.eccPub.data = pub_buf;
		ecc_pub.key.eccPub.len = pub_len;
		ret = CRYPT_EAL_PkeyGetPub(pkey, &ecc_pub);
		if (ret != CRYPT_SUCCESS) {
			lwsl_err("%s: CRYPT_EAL_PkeyGetPub failed for EC, ret=0x%x\n", __func__, ret);
			lws_free(pub_buf);
			return -1;
		}
		mismatch = ecc_pub.key.eccPub.len != pub_len ||
			   pub_buf[0] != 0x04 ||
			   !!memcmp(pub_buf + 1,
				    jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf,
				    coord_len) ||
			   !!memcmp(pub_buf + 1 + coord_len,
				    jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
				    coord_len);
		lws_free(pub_buf);
		if (mismatch) {
			lwsl_err("%s: EC privkey doesn't match jwk pubkey\n", __func__);
			return -1;
		}
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

	/* d, p and q are private key material, wipe our copies of it */

	if (tmp_d) {
		lws_explicit_bzero(tmp_d, key_bytes);
		lws_free(tmp_d);
	}
	if (tmp_p) {
		lws_explicit_bzero(tmp_p, key_bytes);
		lws_free(tmp_p);
	}
	if (tmp_q) {
		lws_explicit_bzero(tmp_q, key_bytes);
		lws_free(tmp_q);
	}

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

/*
 * Cert creation: the key is SEC1 (EC) or PKCS#1 (RSA) DER, as the other
 * backends hand it back
 */

static CRYPT_EAL_PkeyCtx *
lws_x509_openhitls_gen_key(const struct lws_x509_cert_gen_info *info)
{
	static const uint8_t e[] = { 1, 0, 1 };
	CRYPT_EAL_PkeyCtx *pkey;
	CRYPT_EAL_PkeyPara para;
	CRYPT_PKEY_ParaId curve;

	if (lws_hitls_init_rand())
		return NULL;

	if (info->curve_name) {
		if (!strcmp(info->curve_name, "P-256"))
			curve = CRYPT_ECC_NISTP256;
		else if (!strcmp(info->curve_name, "P-384"))
			curve = CRYPT_ECC_NISTP384;
		else if (!strcmp(info->curve_name, "P-521"))
			curve = CRYPT_ECC_NISTP521;
		else {
			lwsl_err("%s: unknown curve %s\n", __func__,
				 info->curve_name);
			return NULL;
		}

		pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
		if (!pkey)
			return NULL;
		if (CRYPT_EAL_PkeySetParaById(pkey, curve) != CRYPT_SUCCESS)
			goto bail;
	} else {
		pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
		if (!pkey)
			return NULL;

		memset(&para, 0, sizeof(para));
		para.id = CRYPT_PKEY_RSA;
		para.para.rsaPara.e = (uint8_t *)(lws_intptr_t)e;
		para.para.rsaPara.eLen = sizeof(e);
		para.para.rsaPara.bits = (uint32_t)(info->key_bits ?
						    info->key_bits : 2048);
		if (CRYPT_EAL_PkeySetPara(pkey, &para) != CRYPT_SUCCESS)
			goto bail;
	}

	if (CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS)
		return pkey;

bail:
	CRYPT_EAL_PkeyFreeCtx(pkey);

	return NULL;
}

static int
lws_x509_openhitls_set_time(HITLS_X509_Cert *cert, int cmd, int64_t t)
{
	BSL_TIME bt;

	memset(&bt, 0, sizeof(bt));
	if (BSL_SAL_UtcTimeToDateConvert(t, &bt) != BSL_SUCCESS)
		return 1;

	return HITLS_X509_CertCtrl(cert, cmd, &bt, sizeof(bt)) !=
							HITLS_PKI_SUCCESS;
}

/* the SAN is a single DNS name or IP address literal */

static int
lws_x509_openhitls_set_san(HITLS_X509_Cert *cert, const char *san)
{
	HITLS_X509_ExtSan es = { false, NULL };
	HITLS_X509_GeneralName *gn;
	size_t len = strlen(san);
	uint8_t ip[16];
	int n, ret = 1;

	/* 253 is the longest a DNS name can be */
	if (!len || len > 253)
		return 1;

	es.names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName *));
	gn = BSL_SAL_Calloc(1, sizeof(*gn));
	if (!es.names || !gn)
		goto bail;

#if defined(LWS_WITH_NETWORK)
	n = lws_parse_numeric_address(san, ip, sizeof(ip));
#else
	n = -1;
#endif
	if (n == 4 || n == 16) {
		gn->type = HITLS_X509_GN_IP;
		gn->value.dataLen = (uint32_t)n;
	} else {
		gn->type = HITLS_X509_GN_DNS;
		gn->value.dataLen = (uint32_t)len;
	}
	gn->value.data = BSL_SAL_Malloc(gn->value.dataLen);
	if (!gn->value.data)
		goto bail;
	memcpy(gn->value.data, gn->type == HITLS_X509_GN_IP ? ip :
			(const uint8_t *)san, gn->value.dataLen);

	if (BSL_LIST_AddElement(es.names, gn, BSL_LIST_POS_END) != BSL_SUCCESS)
		goto bail;
	gn = NULL; /* the list owns it now */

	if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &es,
				sizeof(es)) == HITLS_PKI_SUCCESS)
		ret = 0;

bail:
	if (gn)
		HITLS_X509_FreeGeneralName(gn);
	BSL_LIST_FREE(es.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);

	return ret;
}

static int
lws_x509_openhitls_set_eku(HITLS_X509_Cert *cert, int is_server)
{
	static const BslCid cids[] = { BSL_CID_KP_CLIENTAUTH,
				       BSL_CID_KP_SERVERAUTH };
	HITLS_X509_ExtExKeyUsage eku = { false, NULL };
	BslOidString *oid;
	BSL_Buffer *b;
	int n, ret = 1;

	eku.oidList = BSL_LIST_New(sizeof(BSL_Buffer));
	if (!eku.oidList)
		return 1;

	/* a server cert is also usable as a client cert, as on openssl */
	for (n = 0; n < (is_server ? 2 : 1); n++) {
		oid = BSL_OBJ_GetOID(cids[n]);
		if (!oid)
			goto bail;
		b = BSL_SAL_Malloc(sizeof(*b));
		if (!b)
			goto bail;
		b->data = (uint8_t *)oid->octs; /* static, not owned */
		b->dataLen = oid->octetLen;
		if (BSL_LIST_AddElement(eku.oidList, b, BSL_LIST_POS_END) !=
								BSL_SUCCESS) {
			BSL_SAL_Free(b);
			goto bail;
		}
	}

	if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &eku,
				sizeof(eku)) == HITLS_PKI_SUCCESS)
		ret = 0;

bail:
	/* frees just the BSL_Buffer wrappers */
	BSL_LIST_FREE(eku.oidList, NULL);

	return ret;
}

static int
lws_x509_openhitls_pem_buf(const char *pem, BSL_Buffer *b)
{
	size_t len = strlen(pem);

	/* PEM decode wants the NUL there but not counted */
	if (!len || len > 0x7fffffff)
		return 1;

	b->data = (uint8_t *)(lws_intptr_t)pem;
	b->dataLen = (uint32_t)len;

	return 0;
}

static int
lws_x509_openhitls_copy_out(BSL_Buffer *b, uint8_t **out, size_t *out_len)
{
	*out = malloc(b->dataLen);
	if (!*out)
		return 1;

	memcpy(*out, b->data, b->dataLen);
	*out_len = b->dataLen;

	return 0;
}

int
lws_x509_create_cert(struct lws_context *context,
		     uint8_t **cert_buf, size_t *cert_len,
		     uint8_t **key_buf, size_t *key_len,
		     const struct lws_x509_cert_gen_info *info)
{
	HITLS_X509_ExtBCons bcons = { true, false, -1 };
	HITLS_X509_ExtKeyUsage ku = { true, 0 };
	CRYPT_EAL_PkeyCtx *pkey = NULL, *issuer_key = NULL;
	HITLS_X509_Cert *cert = NULL, *issuer = NULL;
	BSL_Buffer der = { NULL, 0 }, key_der = { NULL, 0 }, pb;
	BslList *subject = NULL, *issuer_dn;
	int32_t version = HITLS_X509_VERSION_3;
	uint8_t serial[8];
	HITLS_X509_DN dn;
	int64_t now;
	int ret = 1;

	(void)context;

	if (!info || !info->san || !*info->san ||
	    (info->ca_cert_pem && !info->ca_key_pem) ||
	    (!info->ca_cert_pem && info->ca_key_pem))
		return 1;

	pkey = lws_x509_openhitls_gen_key(info);
	if (!pkey) {
		lwsl_err("%s: key generation failed\n", __func__);
		return 1;
	}

	cert = HITLS_X509_CertNew();
	subject = HITLS_X509_DnListNew();
	if (!cert || !subject)
		goto bail;

	if (HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version,
				sizeof(version)) != HITLS_PKI_SUCCESS)
		goto bail;

	/* positive, and the top byte nonzero so it stays minimal DER */
	if (CRYPT_EAL_Randbytes(serial, sizeof(serial)) !=
								CRYPT_SUCCESS)
		goto bail;
	serial[0] = (uint8_t)((serial[0] & 0x7f) | 0x40);
	if (HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serial,
				sizeof(serial)) != HITLS_PKI_SUCCESS)
		goto bail;

	/* valid from a day ago, so a peer's clock skew doesn't refuse it */
	now = (int64_t)time(NULL);
	if (lws_x509_openhitls_set_time(cert, HITLS_X509_SET_BEFORE_TIME,
					now - 86400) ||
	    lws_x509_openhitls_set_time(cert, HITLS_X509_SET_AFTER_TIME,
				now + (int64_t)(info->validity_days ?
					info->validity_days : 365) * 86400))
		goto bail;

	if (HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0) !=
							HITLS_PKI_SUCCESS)
		goto bail;

	dn.cid = BSL_CID_AT_COMMONNAME;
	dn.data = (uint8_t *)(lws_intptr_t)info->san;
	dn.dataLen = (uint32_t)strlen(info->san);
	if (HITLS_X509_AddDnName(subject, &dn, 1) != HITLS_PKI_SUCCESS ||
	    HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, subject,
				sizeof(BslList)) != HITLS_PKI_SUCCESS)
		goto bail;

	issuer_dn = subject;
	if (info->ca_cert_pem) {
		if (lws_x509_openhitls_pem_buf(info->ca_cert_pem, &pb) ||
		    HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &pb, &issuer) !=
							HITLS_PKI_SUCCESS) {
			lwsl_err("%s: unable to parse CA cert\n", __func__);
			goto bail;
		}
		if (lws_x509_openhitls_pem_buf(info->ca_key_pem, &pb) ||
		    CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_ENCDEC_UNKNOW,
					    &pb, NULL, 0, &issuer_key) !=
								CRYPT_SUCCESS) {
			lwsl_err("%s: unable to parse CA key\n", __func__);
			goto bail;
		}
		/* a reference into the issuer cert, not ours to free */
		if (HITLS_X509_CertCtrl(issuer, HITLS_X509_GET_SUBJECT_DN,
					&issuer_dn, sizeof(BslList *)) !=
							HITLS_PKI_SUCCESS)
			goto bail;
	}
	if (HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, issuer_dn,
				sizeof(BslList)) != HITLS_PKI_SUCCESS)
		goto bail;

	bcons.isCa = !!info->is_ca;
	if (info->is_ca)
		ku.keyUsage = HITLS_X509_EXT_KU_KEY_CERT_SIGN |
			      HITLS_X509_EXT_KU_CRL_SIGN;
	else
		ku.keyUsage = HITLS_X509_EXT_KU_DIGITAL_SIGN |
			      HITLS_X509_EXT_KU_KEY_ENCIPHERMENT;
	if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bcons,
				sizeof(bcons)) != HITLS_PKI_SUCCESS ||
	    HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku,
				sizeof(ku)) != HITLS_PKI_SUCCESS)
		goto bail;

	if (!info->is_ca && lws_x509_openhitls_set_eku(cert, info->is_server))
		goto bail;

	if (info->is_server && lws_x509_openhitls_set_san(cert, info->san)) {
		lwsl_err("%s: unable to add SAN\n", __func__);
		goto bail;
	}

	if (HITLS_X509_CertSign(CRYPT_MD_SHA256, issuer_key ? issuer_key : pkey,
				NULL, cert) != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: signing failed\n", __func__);
		goto bail;
	}

	if (HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &der) !=
							HITLS_PKI_SUCCESS ||
	    CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_ASN1,
				    info->curve_name ? CRYPT_PRIKEY_ECC :
						       CRYPT_PRIKEY_RSA,
				    &key_der) != CRYPT_SUCCESS)
		goto bail;

	if (lws_x509_openhitls_copy_out(&der, cert_buf, cert_len))
		goto bail;
	if (lws_x509_openhitls_copy_out(&key_der, key_buf, key_len)) {
		free(*cert_buf);
		*cert_buf = NULL;
		goto bail;
	}

	ret = 0;

bail:
	if (key_der.data) {
		lws_explicit_bzero(key_der.data, key_der.dataLen);
		BSL_SAL_Free(key_der.data);
	}
	BSL_SAL_Free(der.data);
	HITLS_X509_DnListFree(subject);
	HITLS_X509_CertFree(issuer);
	HITLS_X509_CertFree(cert);
	CRYPT_EAL_PkeyFreeCtx(issuer_key);
	CRYPT_EAL_PkeyFreeCtx(pkey);

	return ret;
}

int
lws_x509_create_self_signed(struct lws_context *context,
			    uint8_t **cert_buf, size_t *cert_len,
			    uint8_t **key_buf, size_t *key_len,
			    const char *san, int key_bits)
{
	struct lws_x509_cert_gen_info info;

	memset(&info, 0, sizeof(info));
	info.san = san ? san : "localhost";
	info.key_bits = key_bits;
	info.is_server = 1;

	return lws_x509_create_cert(context, cert_buf, cert_len, key_buf,
				    key_len, &info);
}
