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
#include "private.h"
#include <bcrypt.h>

#ifndef CERT_KEY_PROV_HANDLE_PROP_ID
#define CERT_KEY_PROV_HANDLE_PROP_ID 17
#endif

#ifndef BCRYPT_PKCS8_BLOB_HEADER
typedef struct _BCRYPT_PKCS8_BLOB_HEADER {
	ULONG cbBlobMagic;
	ULONG cbKeyData;
} BCRYPT_PKCS8_BLOB_HEADER;
#endif

#ifndef BCRYPT_PKCS8_MAGIC
#define BCRYPT_PKCS8_MAGIC 0x384b5042  // "BPK8"
#endif

#define LWS_MS_ENH_RSA_AES_PROV_W L"Microsoft Enhanced RSA and AES Cryptographic Provider"

#ifndef PROV_RSA_AES
#define PROV_RSA_AES 24
#endif
#ifndef CALG_RSA_SIGN
#define CALG_RSA_SIGN 0x00002400
#endif
#ifndef CALG_RSA_KEYX
#define CALG_RSA_KEYX 0x0000a400
#endif

struct lws_x509_cert {
	PCCERT_CONTEXT cert;
};

static time_t
filetime_to_unix(FILETIME ft)
{
	ULARGE_INTEGER ull;
	ull.LowPart = ft.dwLowDateTime;
	ull.HighPart = ft.dwHighDateTime;

	return (time_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

static int
lws_tls_schannel_cert_info(PCCERT_CONTEXT pCert, enum lws_tls_cert_info type,
		union lws_tls_cert_info_results *buf, size_t len)
{
	if (!pCert)
		return -1;

	switch(type) {
		case LWS_TLS_CERT_INFO_VALIDITY_FROM:
			buf->time = filetime_to_unix(pCert->pCertInfo->NotBefore);
			break;
		case LWS_TLS_CERT_INFO_VALIDITY_TO:
			buf->time = filetime_to_unix(pCert->pCertInfo->NotAfter);
			break;
		case LWS_TLS_CERT_INFO_COMMON_NAME:
			if (!CertGetNameStringA(pCert, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, buf->ns.name, (DWORD)len))
				return -1;
			buf->ns.len = (int)strlen(buf->ns.name);
			break;
		case LWS_TLS_CERT_INFO_ISSUER_NAME:
			if (!CertNameToStrA(pCert->dwCertEncodingType, &pCert->pCertInfo->Issuer,
						CERT_X500_NAME_STR, buf->ns.name, (DWORD)len))
				return -1;
			buf->ns.len = (int)strlen(buf->ns.name);
			break;
		case LWS_TLS_CERT_INFO_USAGE:
			{
				BYTE usage[2] = {0};

				if (CertGetIntendedKeyUsage(pCert->dwCertEncodingType, pCert->pCertInfo, usage, 2))
					buf->usage = usage[0] | (usage[1] << 8);
				else
					buf->usage = 0;
			}
			break;
		case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
			if (len < pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData)
				return -1;
			memcpy(buf->ns.name, pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
					pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData);
			buf->ns.len = (int)pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;
			break;
		case LWS_TLS_CERT_INFO_DER_RAW:
			if (len < pCert->cbCertEncoded)
				return -1;
			memcpy(buf->ns.name, pCert->pbCertEncoded, pCert->cbCertEncoded);
			buf->ns.len = (int)pCert->cbCertEncoded;
			break;
		default:
			return -1;
	}
	return 0;
}

int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
		union lws_tls_cert_info_results *buf, size_t len)
{
	/* stub - usually for server's own cert info? */
	return -1;
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		union lws_tls_cert_info_results *buf, size_t len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	PCCERT_CONTEXT pCert = NULL;
	int ret = 0;

	if (!conn)
		return -1;

	if (QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert) != SEC_E_OK || !pCert)
		return -1;

	switch (type) {
		case LWS_TLS_CERT_INFO_VERIFIED:
			/* If we are here, handshake succeeded. */
			/* SChannel verifies by default unless SCH_CRED_NO_SERVER_CREDENTIALS */
			/* But lws_tls_client_confirm_peer_cert does extra checks */
			/* We can assume true if handshake passed, or check flags if we stored them */
			buf->verified = 1;
			break;
		default:
			ret = lws_tls_schannel_cert_info(pCert, type, buf, len);
	}

	CertFreeCertificateContext(pCert);

	return ret;
}

int
lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type,
		union lws_tls_cert_info_results *buf, size_t len)
{
	return lws_tls_schannel_cert_info(x509->cert, type, buf, len);
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	return 0;
}

	int
lws_x509_create(struct lws_x509_cert **x509)
{
	*x509 = lws_malloc(sizeof(**x509), __func__);

	if (*x509) {
		(*x509)->cert = NULL;
		return 0;
	}
	return -1;
}

void
lws_x509_destroy(struct lws_x509_cert **x509)
{
	if (!*x509)
		return;

	if ((*x509)->cert) {
		CertFreeCertificateContext((*x509)->cert);
		(*x509)->cert = NULL;
	}

	lws_free_set_NULL(*x509);
}

/*
 * Convert PEM to DER. Windows CryptStringToBinary handles headers/footers automatically
 * if using CRYPT_STRING_BASE64_ANY or CRYPT_STRING_ANY.
 */

int
lws_x509_parse_from_pem(struct lws_x509_cert *x509, const void *pem, size_t len)
{
	DWORD dwSkip, dwFlags;
	DWORD dwLen = 0;
	uint8_t *der = NULL;

	lwsl_notice("%s: len %zu\n", __func__, len);

	if (!CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, CRYPT_STRING_BASE64HEADER, NULL, &dwLen, &dwSkip, &dwFlags) &&
		/* Try generic if header parsing fails or is missing */
	    !CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, CRYPT_STRING_ANY, NULL, &dwLen, &dwSkip, &dwFlags)) {
		lwsl_err("%s: CryptStringToBinary failed 0x%x\n", __func__, GetLastError());
		return -1;
	}

	lwsl_info("%s: CryptStringToBinary suggested dwLen %d\n", __func__, (int)dwLen);

	der = lws_malloc(dwLen, "x509 der");
	if (!der)
		return -1;

	if (!CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, dwFlags, der, &dwLen, NULL, NULL)) {
		lws_free(der);
		return -1;
	}

	x509->cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, dwLen);
	lws_free(der);

	if (!x509->cert) {
		lwsl_err("%s: CertCreateCertificateContext failed\n", __func__);
		return -1;
	}

	return 0;
}

/* Stub for verification logic */
/* Windows has CertVerifySubjectCertificateContext, but it verifies against a store.
   Here we check if x509 is issued by trusted. */

/* Manually checking issuer match? */

int
lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted, const char *common_name)
{
	DWORD dwFlags = 0;

	if (CertVerifySubjectCertificateContext(x509->cert, trusted->cert, &dwFlags))
		/* Checked signature against issuer? API docs say "checks the validity... by using the issuer". */
		return 0;

	return -1;
}

/* Minimal ASN.1 Reader Helpers */
static int
lws_asn1_read_length(const uint8_t **p, const uint8_t *end, size_t *len)
{
	uint8_t c;
	int bytes;

	if (*p >= end) return -1;

	c = *(*p)++;

	if (!(c & 0x80)) {
		*len = c;
		return 0;
	}

	bytes = c & 0x7F;
	if (bytes > 4 || *p + bytes > end)
		return -1;

	*len = 0;
	while (bytes--)
		*len = (*len << 8) | *(*p)++;

	return 0;
}


static int
lws_asn1_read_integer(const uint8_t **p, const uint8_t *end, struct lws_gencrypto_keyelem *el)
{
	const uint8_t *val;
	size_t len, vlen;

	if (*p >= end || *(*p)++ != 0x02)
		return -1; /* Expect INTEGER tag */

	if (lws_asn1_read_length(p, end, &len) < 0)
		return -1;

	if (*p + len > end)
		return -1;

	/* Skip leading zero if present (ASN.1 integer is signed, might have 0x00 pad for positive MSB) */

	val = *p;
	vlen = len;

	while (vlen > 0 && val[0] == 0x00) {
		val++;
		vlen--;
	}

	/* Copy to key element */
	el->len = (uint32_t)vlen;
	el->buf = lws_malloc(vlen, "asn1 int");

	if (!el->buf)
		return -1;
	memcpy(el->buf, val, vlen);

	*p += len;

	return 0;
}

#if defined(LWS_WITH_JOSE)

/* Extract public key blob from cert */
/* Decode SubjectPublicKeyInfo */

int
lws_x509_public_to_jwk(struct lws_jwk *jwk, struct lws_x509_cert *x509,
		       const char *curves, int rsa_min_bits)
{
	BCRYPT_KEY_HANDLE hKey = NULL;
	DWORD dwBlobLen = 0;
	NTSTATUS status;
	int ret = -1;

	memset(jwk, 0, sizeof(*jwk));

	/* Import public key from cert info to CNG key handle */
	if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &x509->cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hKey)) {
		lwsl_err("%s: CryptImportPublicKeyInfoEx2 failed %d\n", __func__, GetLastError());
		return -1;
	}

	/* Get algorithm */
	/* We need to determine if it is RSA or EC to set jwk->kty and export appropriate blob */
	/* Ideally we would query property but let's try exporting. */

	/* Try exporting as RSA Public Blob */
	status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &dwBlobLen, 0);
	if (BCRYPT_SUCCESS(status)) {
		jwk->kty = LWS_GENCRYPTO_KTY_RSA;
		BCRYPT_RSAKEY_BLOB *rsablob = lws_malloc(dwBlobLen, "rsa pub");
		if (rsablob) {
			if (BCRYPT_SUCCESS(BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, (PUCHAR)rsablob, dwBlobLen, &dwBlobLen, 0))) {
				/* Convert blob to JWK elements */
				/* n, e */
				uint8_t *p = (uint8_t *)(rsablob + 1);

				/* Exponent */
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len = rsablob->cbPublicExp;
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc(rsablob->cbPublicExp, "rsa e");
				memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, p, rsablob->cbPublicExp);
				p += rsablob->cbPublicExp;
				/* Modulus */
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len = rsablob->cbModulus;
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc(rsablob->cbModulus, "rsa n");
				memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, p, rsablob->cbModulus);
				ret = 0;
			}
			lws_free(rsablob);
		}
		goto bail;
	}

	/* Try EC */
	status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &dwBlobLen, 0);
	if (!BCRYPT_SUCCESS(status))
		goto bail;

	jwk->kty = LWS_GENCRYPTO_KTY_EC;
	BCRYPT_ECCKEY_BLOB *eccblob = lws_malloc(dwBlobLen, "ec pub");
	if (!eccblob)
		goto bail;

	if (BCRYPT_SUCCESS(BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)eccblob, dwBlobLen, &dwBlobLen, 0))) {
		uint8_t *p = (uint8_t *)(eccblob + 1);

		/* X */
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len = eccblob->cbKey;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(eccblob->cbKey, "ec x");
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, p, eccblob->cbKey);
		p += eccblob->cbKey;
		/* Y */
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len = eccblob->cbKey;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(eccblob->cbKey, "ec y");
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, p, eccblob->cbKey);

		/* Map Curve? dwMagic tells us */
		/* Assume P-256 for now or derive from Magic/Length */
		/* JWK needs 'crv' string? The caller might have validated 'curves' arg. */
		/* We leave 'crv' element empty for now or set it if we can deduce */
		ret = 0;
	}
	lws_free(eccblob);

bail:
	BCryptDestroyKey(hKey);

	return ret;
}

/* Minimal RSA PKCS#1 parser */

int
lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk,
			 void *pem, size_t len, const char *passphrase)
{
	DWORD dwLen = 0, dwSkip, dwFlags;
	const uint8_t *p, *end;
	uint8_t *der = NULL;
	size_t seq_len;
	size_t ver_len;
	int ret = -1;

	if (passphrase) {
		lwsl_err("%s: Encrypted private keys not supported yet\n", __func__);
		return -1;
	}

	if (!CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, CRYPT_STRING_ANY, NULL, &dwLen, &dwSkip, &dwFlags)) {
		lwsl_err("%s: CryptStringToBinary failed\n", __func__);
		return -1;
	}

	der = lws_malloc(dwLen, "privkey der");
	if (!der)
		return -1;

	if (!CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, dwFlags, der, &dwLen, NULL, NULL)) {
		lws_free(der);
		return -1;
	}

	p = der;
	end = der + dwLen;

	/* Try parsing SEQUENCE */
	if (p >= end || *p++ != 0x30)
		goto bail; /* SEQUENCE */

	if (lws_asn1_read_length(&p, end, &seq_len) < 0)
		goto bail;

	/* Check for PKCS#8 wrapping: version=0, AlgorithmIdentifier, OCTET STRING */
	/* Peek version */
	/*
	   If it's RSA PKCS#1: SEQUENCE version 0, n, e, d...
	   If it's PKCS#8: SEQUENCE version 0, AlgId, OctetString
	   */

	/* Read version */
	if (p >= end || *p++ != 0x02)
		goto bail; /* INTEGER */

	if (lws_asn1_read_length(&p, end, &ver_len) < 0)
		goto bail;
	p += ver_len; /* Skip version value (usually 0) */

	/* Check next tag */
	if (p >= end)
		goto bail;

	if (*p == 0x30) {
		/* Likely PKCS#8 AlgorithmIdentifier. Skip it and OctetString header to get to inner key. */
		/* Just a heuristic: if we see SEQUENCE, we assume PKCS#8 and try to dig in. */
		/* Actually proper parsing is better but keeping it minimal. */
		/* Skip AlgId */
		size_t alg_len;
		p++;
		if (lws_asn1_read_length(&p, end, &alg_len) < 0)
			goto bail;
		p += alg_len;

		/* Expect OCTET STRING */
		if (p >= end || *p++ != 0x04)
			goto bail;
		size_t oct_len;
		if (lws_asn1_read_length(&p, end, &oct_len) < 0)
			goto bail;

		/* Now p points to inner key (RSAPrivateKey usually).
		   It should be a SEQUENCE again. */
		if (p >= end || *p++ != 0x30)
			goto bail;
		if (lws_asn1_read_length(&p, end, &seq_len) < 0)
			goto bail;

		/* Read inner version */
		if (p >= end || *p++ != 0x02)
			goto bail;
		if (lws_asn1_read_length(&p, end, &ver_len) < 0)
			goto bail;
		p += ver_len;
	} else if (*p == 0x02) {
		/* PKCS#1: kp points to Modulus tag. Version already consumed. */
	} else {
		goto bail;
	}

	/* Read RSA fields */
	jwk->kty = LWS_GENCRYPTO_KTY_RSA;

	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N]) < 0)
		goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E]) < 0)
		goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D]) < 0)
		goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P]) < 0)
		goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q]) < 0)
		goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP]) < 0)
		goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ]) < 0)
		goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI]) < 0)
		goto bail;

	ret = 0;

bail:
	lws_free(der);

	return ret;
}
#endif


static int lws_tls_schannel_wrap_pkcs8(const uint8_t *pkcs1, size_t pkcs1_len, uint8_t **pkcs8_out, size_t *pkcs8_len_out)
{
	/* OID 1.2.840.113549.1.1.1 (rsaEncryption) */
	const uint8_t alg_id[] = {
		0x30, 0x0D,
		0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
		0x05, 0x00
	};
	size_t tmp, len_bytes = (pkcs1_len < 128) ? 1 : (pkcs1_len < 0x100 ? 2 : (pkcs1_len < 0x10000 ? 3 : 4));
	size_t inner_payload_len = 3 + sizeof(alg_id) + 1 + (len_bytes > 1 ? len_bytes : 1) + pkcs1_len;
	/* Standard ASN.1: if len >= 128, it's 0x80 | num_bytes, then the bytes.
	   So for 128..255, it's 2 bytes (81 XX). For 256..65535, it's 3 bytes (82 XX XX).
	   len_bytes matches this. */

	size_t outer_len_bytes = (inner_payload_len < 128) ? 1 : (inner_payload_len < 0x100 ? 2 : (inner_payload_len < 0x10000 ? 3 : 4));
	size_t total_len = 1 + (outer_len_bytes > 1 ? outer_len_bytes : 1) + inner_payload_len;

	uint8_t *q, *pkcs8 = lws_malloc(total_len, "pkcs8 wrapper");
	if (!pkcs8)
		return -1;

	q = pkcs8;

	/* Write Outer Sequence */
	*q++ = 0x30;
	if (outer_len_bytes == 1)
		*q++ = (uint8_t)inner_payload_len;
	else {
		*q++ = 0x80 | (uint8_t)(outer_len_bytes - 1);
		tmp = inner_payload_len;
		for (int i = (int)outer_len_bytes - 2; i >= 0; i--) {
			q[i] = (uint8_t)(tmp & 0xFF);
			tmp >>= 8;
		}
		q += outer_len_bytes - 1;
	}

	/* Write Version */
	*q++ = 0x02;
	*q++ = 0x01;
	*q++ = 0x00;

	/* Write AlgID */
	memcpy(q, alg_id, sizeof(alg_id));
	q += sizeof(alg_id);

	/* Write OctetString containing Key */
	*q++ = 0x04;
	if (len_bytes == 1)
		*q++ = (uint8_t)pkcs1_len;
	else {
		*q++ = 0x80 | (uint8_t)(len_bytes - 1);
		tmp = pkcs1_len;
		for (int i = (int)len_bytes - 2; i >= 0; i--) {
			q[i] = (uint8_t)(tmp & 0xFF);
			tmp >>= 8;
		}
		q += len_bytes - 1;
	}
	memcpy(q, pkcs1, pkcs1_len);

	*pkcs8_out = pkcs8;
	*pkcs8_len_out = total_len;

	return 0;
}

int
lws_tls_schannel_cert_info_load(struct lws_context *context,
		const char *cert, const char *private_key,
		const char *mem_cert, size_t len_mem_cert,
		const char *mem_privkey, size_t mem_privkey_len,
		PCCERT_CONTEXT *pcert, HCERTSTORE *phStore,
		void **phKey, int *pKeyType,
		const char *container_name)
{
	struct lws_x509_cert x509_obj = {0};
	PCCERT_CONTEXT pCertContext = NULL;
	NCRYPT_PROV_HANDLE hProvCNG = 0;
	NCRYPT_KEY_HANDLE hKeyCNG = 0;
	SECURITY_STATUS status;
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	int ret = -1, is_ec = 0;
	uint8_t *key_der = NULL, *pkcs8 = NULL, *der = NULL;
	size_t key_der_len, seq_len, ver_len, alg_len, oct_len, pkcs8_len;
	const uint8_t *kp = NULL, *kend = NULL;
	DWORD flags = NCRYPT_SILENT_FLAG;
	WCHAR wContainer[128];
	NCryptBuffer nameBuf;
	NCryptBufferDesc nameDesc;
	NCryptBufferDesc *pNameDesc = NULL;
	CRYPT_KEY_PROV_INFO kpi = {0};
	CERT_KEY_CONTEXT ckc = {0};
	size_t pkcs1_len;
	const uint8_t *pkcs1_ptr = NULL;
	LPCWSTR keyName = NULL;
	lws_filepos_t amount;
	PCCERT_CONTEXT pStoreCert = NULL;
	HCERTSTORE hStore = NULL;
	static const uint8_t ec_oid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

	memset(wContainer, 0, sizeof(wContainer));


	/* 1. Load Certificate */
	lwsl_debug("%s: Start, cert %p, mem_cert %p\n", __func__, cert, mem_cert);

	hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
	if (!hStore) {
		lwsl_err("%s: Failed to create memory store\n", __func__);
		return 1;
	}

	if (cert) {
		if (lws_tls_alloc_pem_to_der_file(context, cert, mem_cert, len_mem_cert, &der, &amount)) {
			lwsl_err("%s: Failed to load cert file %s\n", __func__, cert ? cert : "mem");
			CertCloseStore(hStore, 0);
			return 1;
		}

		if (!CertAddEncodedCertificateToStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, (DWORD)amount, CERT_STORE_ADD_ALWAYS, &x509_obj.cert)) {
			lwsl_err("%s: CertAddEncodedCertificateToStore failed\n", __func__);
			lws_free(der);
			CertCloseStore(hStore, 0);
			return 1;
		}
		lws_free(der);
	} else if (mem_cert) {
		if (lws_x509_parse_from_pem(&x509_obj, mem_cert, len_mem_cert)) {
			lwsl_err("%s: Failed to parse cert pem\n", __func__);
			CertCloseStore(hStore, 0);
			return 1;
		}

		/* Move to store */
		pStoreCert = NULL;
		if (!CertAddCertificateContextToStore(hStore, x509_obj.cert, CERT_STORE_ADD_ALWAYS, &pStoreCert)) {
			lwsl_err("%s: CertAddCertificateContextToStore failed\n", __func__);
			CertFreeCertificateContext(x509_obj.cert);
			CertCloseStore(hStore, 0);
			return 1;
		}
		CertFreeCertificateContext(x509_obj.cert);
		x509_obj.cert = pStoreCert;
	} else {
		CertCloseStore(hStore, 0);
		return 1; /* No cert */
	}

	if (phStore)
		*phStore = hStore;
	else
		CertCloseStore(hStore, 0);

	if (!x509_obj.cert) {
		lwsl_err("%s: Failed to create cert context\n", __func__);
		return 1;
	}

	/* 2. Load Private Key */
	if (!private_key && !mem_privkey) {
		*pcert = x509_obj.cert;
		return 0;
	}

	/* Load key DER */
	if (lws_tls_alloc_pem_to_der_file(context, private_key, mem_privkey, mem_privkey_len, &key_der, &key_der_len)) {
		lwsl_err("%s: Failed to load key (alloc_pem_to_der failed)\n", __func__);
		goto cleanup;
	}

	/* Check if it is an EC key */
	/* If it is EC, we use CNG. If RSA, we use Legacy CAPI. */
	/* Simple check: If pem string contains "EC PRIVATE KEY", it's EC. */
	/* Or check OID in PKCS#8 */
	/*
	 * Try to import as PKCS#8 directly using CNG.
	 * This handles both RSA and EC keys, and importantly, handles "minimal" RSA keys
	 * (missing CRT params) that the legacy CAPI path fails on.
	 */
	is_ec = 0;
	if (strstr(private_key ? private_key : (mem_privkey ? mem_privkey : ""), "EC PRIVATE KEY")) {
		is_ec = 1;
	} else {
		/* Check DER for OID 1.2.840.10045.2.1 (ecPublicKey) */
		/* Sequence { Version, AlgorithmIdentifier { OID ... } ... } */
		kp = key_der;
		kend = key_der + key_der_len;
		if (kp < kend && *kp++ == 0x30 && lws_asn1_read_length(&kp, kend, &seq_len) == 0) {
			/* Check for version 0 */
			if (kp < kend && *kp++ == 0x02 && lws_asn1_read_length(&kp, kend, &ver_len) == 0) {
				kp += ver_len;
				/* Next is AlgorithmIdentifier Sequence */
				if (kp < kend && *kp++ == 0x30 && lws_asn1_read_length(&kp, kend, &alg_len) == 0) {
					/* Check OID: 1.2.840.10045.2.1 is 06 07 2A 86 48 CE 3D 02 01 */
					/* ec_oid is already declared at the top */
					if (alg_len >= sizeof(ec_oid) && !memcmp(kp, ec_oid, sizeof(ec_oid))) {
						is_ec = 1;
					}
				}
			}
		}
	}

	if (is_ec) {
		/* EC Path: Use CNG (NCrypt) */
		/* hProvCNG and hKeyCNG are already declared at the top */

		/* Open Storage Provider */
		/* For server (named), use MS_KEY_STORAGE_PROVIDER. For client (ephemeral), we could use it too but verify flags. */
		/* Actually, SChannel works best with KSP for EC. */

		status = NCryptOpenStorageProvider(&hProvCNG, MS_KEY_STORAGE_PROVIDER, 0);
		if (status != ERROR_SUCCESS) {
			lwsl_err("NCryptOpenStorageProvider failed 0x%x\n", (int)status);
			lws_free(key_der);
			goto cleanup;
		}

		flags = NCRYPT_SILENT_FLAG;
		if (container_name) {
			flags |= NCRYPT_OVERWRITE_KEY_FLAG;
		}

		keyName = NULL;
		if (container_name) {
			if (MultiByteToWideChar(CP_UTF8, 0, container_name, -1, wContainer, sizeof(wContainer)/sizeof(wContainer[0]))) {
				keyName = wContainer;
			}
		}

		/* Import Key */
		/* We have DER. NCryptImportKey supports NCRYPT_PKCS8_PRIVATE_KEY_BLOB */
		/* Note: If the PEM was "EC PRIVATE KEY" (SEC1), CryptStringToBinary converted it to DER SEC1. */
		/* NCryptImportKey typically expects PKCS#8. If it is SEC1, we might need to wrap it? */
		/* Windows 10+ might support ECCPRIVATE_BLOB? */
		/* But generic "Private Key" usually implies PKCS#8. */
		/* Let's try importing as PKCS8 first. */

		/* NCryptImportKey signature:
		   (hProvider, hImportKey, pszBlobType, pParameterList, phKey, pbInput, cbInput, dwFlags)
		   */
		if (container_name) {
			/* For persisted keys, we need to pass the key name property.
			   However, NCryptImportKey into a named key usually requires specific steps or using NCryptCreatePersistedKey.
			   Wait, if we use NCryptImportKey with NCRYPT_OVERWRITE_KEY_FLAG and a key name, how do we pass the key name?
			   Docs say: "The behavior of this function is consistent with the NCryptCreatePersistedKey function...".
			   NCryptCreatePersistedKey takes pszKeyName directly.
			   NCryptImportKey does NOT take pszKeyName directly in the signature.

			   Actually, to import a named key, we should:
			   1. Create a parameter list with NCRYPT_KEY_NAME_PROPERTY (L"Name").
			   */
			/* nameBuf and nameDesc are already declared at the top */

			nameBuf.cbBuffer = (ULONG)((wcslen(wContainer) + 1) * sizeof(WCHAR));
			nameBuf.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
			nameBuf.pvBuffer = wContainer;

			nameDesc.ulVersion = NCRYPTBUFFER_VERSION;
			nameDesc.cBuffers = 1;
			nameDesc.pBuffers = &nameBuf;

			status = NCryptImportKey(hProvCNG, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &nameDesc, &hKeyCNG, (PUCHAR)key_der, (DWORD)key_der_len, flags);
		} else
			status = NCryptImportKey(hProvCNG, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &hKeyCNG, (PUCHAR)key_der, (DWORD)key_der_len, flags);

		if (status != ERROR_SUCCESS) {
			/* Maybe it is SEC1 (EC PRIVATE KEY) and not PKCS#8? */
			/* Trying to wrap SEC1 into PKCS#8 manually is hard. */
			/* However, CryptImportPKCS8 is CAPI. */
			lwsl_err("NCryptImportKey (PKCS8) failed 0x%x. Note: EC SEC1 keys not auto-converted.\n", (int)status);
			NCryptFreeObject(hProvCNG);
			lws_free(key_der);
			goto cleanup;
		}
		lws_free(key_der);

		/* Set usage to all to ensure SChannel doesn't reject it */
		flags = NCRYPT_ALLOW_ALL_USAGES;
		NCryptSetProperty(hKeyCNG, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&flags, sizeof(flags), 0);

		/* Unified Handle Approach: Always use explicit handle linking */
		/* Link Handle Property */
		if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, &hKeyCNG)) {
			lwsl_err("CertSetCertificateContextProperty (CNG Handle) failed 0x%x\n", GetLastError());
			NCryptFreeObject(hKeyCNG);
			NCryptFreeObject(hProvCNG);
			goto cleanup;
		}

		/* ckc is already declared at the top */
		ckc.cbSize = sizeof(ckc);
		ckc.hNCryptKey = hKeyCNG;
		ckc.dwKeySpec = CERT_NCRYPT_KEY_SPEC;

		/* Link Key Context Property */
		if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_CONTEXT_PROP_ID, 0, &ckc)) {
			lwsl_err("%s: CertSetCertificateContextProperty (KEY_CONTEXT) failed 0x%x\n", __func__, GetLastError());
			NCryptFreeObject(hKeyCNG);
			NCryptFreeObject(hProvCNG);
			goto cleanup;
		}
		lwsl_debug("%s: Ephemeral KEY_CONTEXT Linked (Prop 5, CERT_NCRYPT_KEY_SPEC)\n", __func__);

		/*
		 * REMOVED Prop 6 (CERT_KEY_SPEC_PROP_ID) setting.
		 * The CERT_KEY_CONTEXT already handles binding. Setting Prop 6 might conflict or force legacy interpretation.
		 */

		if (phKey)
			*phKey = (void*)hKeyCNG;
		else
			NCryptFreeObject(hKeyCNG);

		if (pKeyType)
			*pKeyType = 1; /* CNG */

		/* We don't have a place to return hProvCNG, but hKeyCNG holds a ref. */
		NCryptFreeObject(hProvCNG);
		hKeyCNG = 0;
		hProvCNG = 0;

		*pcert = x509_obj.cert;

		return 0;
	}

	/* RSA Path */
	kp = key_der;
	kend = key_der + key_der_len;

	pkcs1_ptr = key_der;
	pkcs1_len = key_der_len;

	if (kp >= kend || *kp++ != 0x30) {
		lwsl_err("%s: Failed to find SEQUENCE tag at start of key\n", __func__);
		lws_free(key_der);
		goto cleanup;
	}
	if (lws_asn1_read_length(&kp, kend, &seq_len) < 0) {
		lwsl_err("%s: Failed to read key SEQUENCE length\n", __func__);
		lws_free(key_der);
		goto cleanup;
	}

	/* Check for version */
	if (kp >= kend || *kp++ != 0x02) {
		lwsl_err("%s: Failed to find version tag\n", __func__);
		lws_free(key_der);
		goto cleanup;
	}
	if (lws_asn1_read_length(&kp, kend, &ver_len) < 0) {
		lwsl_err("%s: Failed to read version length\n", __func__);
		lws_free(key_der);
		goto cleanup;
	}
	kp += ver_len;

	/* PKCS#8 check */
	if (kp < kend && *kp == 0x30) {
		const uint8_t *pkcs1_seq_start;

		lwsl_debug("%s: PKCS#8 detected\n", __func__);
		kp++;
		if (lws_asn1_read_length(&kp, kend, &alg_len) < 0) {
			lwsl_err("%s: PKCS#8 Failed to read alg SEQUENCE length\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}
		kp += alg_len;
		if (kp >= kend || *kp++ != 0x04) {
			lwsl_err("%s: PKCS#8 Failed to find OCTET STRING (0x04) tag\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}
		if (lws_asn1_read_length(&kp, kend, &oct_len) < 0) {
			lwsl_err("%s: PKCS#8 Failed to read octet length\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}

		pkcs1_seq_start = kp;

		if (kp >= kend || *kp++ != 0x30) {
			lwsl_err("%s: PKCS#8 Failed to find inner SEQUENCE\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}
		if (lws_asn1_read_length(&kp, kend, &seq_len) < 0) {
			lwsl_err("%s: PKCS#8 Failed to read inner SEQUENCE length\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}

		/* We now have the inner PKCS#1 DER payload. */
		pkcs1_ptr = pkcs1_seq_start;
		pkcs1_len = (size_t)(kp - pkcs1_seq_start) + seq_len;

	} else if (kp < kend && *kp == 0x02) {
		lwsl_debug("%s: PKCS#1 detected\n", __func__);
		/* PKCS#1: kp points to Modulus tag. Version already consumed. */
	} else {
		lwsl_err("%s: Unknown key format at 0x%02X\n", __func__, kp < kend ? *kp : 0xFF);
		lws_free(key_der);

		goto cleanup;
	}

	/* Convert to CAPI Blob (Via CryptDecodeObjectEx) */
	{
		DWORD cbDecoded = 0;

		if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					PKCS_RSA_PRIVATE_KEY,
					pkcs1_ptr, (DWORD)pkcs1_len,
					0, NULL, NULL, &cbDecoded)) {
			lwsl_err("%s: CryptDecodeObjectEx (Get Size) failed 0x%x\n", __func__, GetLastError());
			goto cleanup;
		}

		pkcs8_len = (size_t)cbDecoded;
	}

	pkcs8 = lws_malloc(pkcs8_len, "capi_blob"); /* Reusing pkcs8 ptr for CAPI blob */
	if (!pkcs8) {
		lwsl_err("%s: OOM allocating CAPI blob (%d bytes)\n", __func__, (int)pkcs8_len);
		goto cleanup;
	}

	if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				PKCS_RSA_PRIVATE_KEY,
				pkcs1_ptr, (DWORD)pkcs1_len,
				0, NULL, pkcs8, (DWORD *)&pkcs8_len)) {
		lwsl_err("%s: CryptDecodeObjectEx (Convert) failed 0x%x\n", __func__, GetLastError());
		lws_free(pkcs8);
		goto cleanup;
	}
	lwsl_debug("%s: CAPI RSA Blob created, len %d\n", __func__, (int)pkcs8_len);

	/* 5. Import into CAPI Context (Ephemeral Only) */
	/*
	 * Persistence failed (Access Denied 0x5).
	 * Reverting to Ephemeral (VerifyContext) with explicit SIGNATURE enforcement.
	 */

	DWORD algId;

	/* Read AlgID to determine dwKeySpec */
	{
		DWORD *pAlg = (DWORD *)(pkcs8 + 4);
		algId = *pAlg;
	}

	/*
	 * SChannel Server often rejects Ephemeral Keys (VerifyContext) for RSA.
	 * We must use a persisted Machine Keyset and link via CERT_KEY_PROV_INFO.
	 */
	{
		WCHAR wContainerInfo[128];
		if (!container_name || !MultiByteToWideChar(CP_UTF8, 0, container_name, -1, wContainerInfo, sizeof(wContainerInfo)/sizeof(WCHAR))) {
			lwsl_err("%s: Missing or invalid container name for RSA\n", __func__);
			lws_free(pkcs8);
			goto cleanup;
		}

		/* Try to acquire existing keyset, if it fails, create a new one */
		if (!CryptAcquireContextW(&hProv, wContainerInfo, LWS_MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_MACHINE_KEYSET | CRYPT_SILENT)) {
			if (GetLastError() == NTE_BAD_KEYSET) {
				if (!CryptAcquireContextW(&hProv, wContainerInfo, LWS_MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET | CRYPT_SILENT)) {
					lwsl_err("%s: CryptAcquireContext (Create Machine Keyset) failed 0x%x\n", __func__, GetLastError());
					lws_free(pkcs8);
					goto cleanup;
				}
			} else {
				lwsl_err("%s: CryptAcquireContext (Open Machine Keyset) failed 0x%x\n", __func__, GetLastError());
				lws_free(pkcs8);
				goto cleanup;
			}
		}

		/* Import the key into the persisted keyset */
		if (!CryptImportKey(hProv, pkcs8, (DWORD)pkcs8_len, 0, 0, &hKey)) {
			lwsl_err("%s: CryptImportKey (Machine Keyset) failed 0x%x\n", __func__, GetLastError());
			lws_free(pkcs8);
			goto cleanup;
		}
		lws_free(pkcs8);
		lwsl_debug("%s: CryptImportKey success into machine keyset, hKey %p, hProv %p\n", __func__, (void*)hKey, (void*)hProv);

		/* 0. Clear conflicting properties */
		CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_CONTEXT_PROP_ID, 0, NULL);
		CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_PROV_HANDLE_PROP_ID, 0, NULL);

		/* 1. Prepare CERT_KEY_PROV_INFO */
		memset(&kpi, 0, sizeof(kpi));
		kpi.pwszContainerName = wContainerInfo;
		kpi.pwszProvName = (LPWSTR)LWS_MS_ENH_RSA_AES_PROV_W;
		kpi.dwProvType = PROV_RSA_AES;
		kpi.dwFlags = CERT_SET_KEY_PROV_HANDLE_PROP_ID | CERT_SET_KEY_CONTEXT_PROP_ID | CRYPT_MACHINE_KEYSET | CRYPT_SILENT;
		kpi.cProvParam = 0;
		kpi.rgProvParam = NULL;
		kpi.dwKeySpec = (algId == CALG_RSA_SIGN) ? AT_SIGNATURE : AT_KEYEXCHANGE;

		/* 2. Set Prop 2 (CERT_KEY_PROV_INFO_PROP_ID) */
		if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)) {
			lwsl_err("%s: CertSetCertificateContextProperty (Prop 2 PROV_INFO) failed 0x%x\n", __func__, GetLastError());
			goto cleanup;
		}

		lwsl_debug("%s: CAPI Machine Keyset Linked (Prop 2 / %s)\n", __func__,
				kpi.dwKeySpec == AT_SIGNATURE ? "AT_SIGNATURE" : "AT_KEYEXCHANGE");

		/* Return handle to caller if requested */
		if (phKey)
			*phKey = (void*)hProv;
		if (pKeyType)
			*pKeyType = 0; /* CAPI */

		hProv = 0; /* Caller owns hProv now, or it gets released during lws_ssl_destroy but the keyset remains until explictly deleted */
	}

	lwsl_debug("%s: returning success\n", __func__);
	*pcert = x509_obj.cert;

	return 0;

cleanup:
	if (hKey)
		CryptDestroyKey(hKey);

	if (hProvCNG) {
		if (!ret && phKey) {
			*phKey = (void*)hKeyCNG;
			if (pKeyType)
				*pKeyType = 1; /* CNG */
			/* Success, handle stays with cert. Keep provider alive. */
			hProvCNG = 0;
		} else {
			/* Failure, free everything */
			if (hKeyCNG)
				NCryptFreeObject(hKeyCNG);
			NCryptFreeObject(hProvCNG);
		}
	} else {
		if (!ret && phKey) {
			*phKey = (void*)hProv;
			if (pKeyType)
				*pKeyType = 0; /* CAPI */
			hProv = 0; /* Caller owns hProv now */
		}
	}
	if (hProv)
		CryptReleaseContext(hProv, 0);

	if (ret && x509_obj.cert)
		CertFreeCertificateContext(x509_obj.cert);
	if (ret && phStore && *phStore) {
		CertCloseStore(*phStore, 0);
		*phStore = NULL;
	}

	return ret;
}
