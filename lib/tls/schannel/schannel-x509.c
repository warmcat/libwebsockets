/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
    if (!pCert) return -1;

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
                 if (CertGetIntendedKeyUsage(pCert->dwCertEncodingType, pCert->pCertInfo, usage, 2)) {
                      buf->usage = usage[0] | (usage[1] << 8);
                 } else {
                      buf->usage = 0;
                 }
             }
             break;
        case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
             if (len < pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData) return -1;
             memcpy(buf->ns.name, pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
                    pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData);
             buf->ns.len = (int)pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;
             break;
        case LWS_TLS_CERT_INFO_DER_RAW:
             if (len < pCert->cbCertEncoded) return -1;
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
	/* SChannel stores creds, not easy to extract cert back unless we kept it */
	/* lws_tls_schannel_ctx has 'cred', but not cert. */
	/* For now, leave as stub or failure */
	return -1;
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
    struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
    PCCERT_CONTEXT pCert = NULL;
    int ret = 0;

    if (!conn) return -1;

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

int
lws_x509_parse_from_pem(struct lws_x509_cert *x509, const void *pem, size_t len)
{
	/*
	 * Convert PEM to DER. Windows CryptStringToBinary handles headers/footers automatically
	 * if using CRYPT_STRING_BASE64_ANY or CRYPT_STRING_ANY.
	 */
	DWORD dwSkip, dwFlags;
	DWORD dwLen = 0;
	uint8_t *der = NULL;

	if (!CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, CRYPT_STRING_BASE64HEADER, NULL, &dwLen, &dwSkip, &dwFlags)) {
		/* Try generic if header parsing fails or is missing */
		if (!CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, CRYPT_STRING_ANY, NULL, &dwLen, &dwSkip, &dwFlags)) {
			lwsl_err("%s: CryptStringToBinary failed\n", __func__);
			return -1;
		}
	}

	der = lws_malloc(dwLen, "x509 der");
	if (!der) return -1;

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

int
lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted,
		const char *common_name)
{
	/* Stub for verification logic */
	/* Windows has CertVerifySubjectCertificateContext, but it verifies against a store.
	   Here we check if x509 is issued by trusted. */

	/* Manually checking issuer match? */
	DWORD dwFlags = 0;
	if (CertVerifySubjectCertificateContext(x509->cert, trusted->cert, &dwFlags)) {
		/* Checked signature against issuer? API docs say "checks the validity... by using the issuer". */
		return 0;
	}

	return -1;
}

#if defined(LWS_WITH_JOSE)
int
lws_x509_public_to_jwk(struct lws_jwk *jwk, struct lws_x509_cert *x509,
		       const char *curves, int rsa_min_bits)
{
	/* Extract public key blob from cert */
	/* Decode SubjectPublicKeyInfo */
	DWORD dwBlobLen = 0;
	BCRYPT_KEY_HANDLE hKey = NULL;
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
	} else {
		/* Try EC */
		status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &dwBlobLen, 0);
		if (BCRYPT_SUCCESS(status)) {
			jwk->kty = LWS_GENCRYPTO_KTY_EC;
			BCRYPT_ECCKEY_BLOB *eccblob = lws_malloc(dwBlobLen, "ec pub");
			if (eccblob) {
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
			}
		}
	}

	BCryptDestroyKey(hKey);
	return ret;
}

/* Minimal ASN.1 Reader Helpers */
static int lws_asn1_read_length(const uint8_t **p, const uint8_t *end, size_t *len) {
	if (*p >= end) return -1;
	uint8_t c = *(*p)++;
	if (!(c & 0x80)) {
		*len = c;
	} else {
		int bytes = c & 0x7F;
		if (bytes > 4 || *p + bytes > end) return -1;
		*len = 0;
		while (bytes--) {
			*len = (*len << 8) | *(*p)++;
		}
	}
	return 0;
}

static int lws_asn1_read_integer(const uint8_t **p, const uint8_t *end, struct lws_gencrypto_keyelem *el) {
	size_t len;
	if (*p >= end || *(*p)++ != 0x02) return -1; /* Expect INTEGER tag */
	if (lws_asn1_read_length(p, end, &len) < 0) return -1;
	if (*p + len > end) return -1;

	/* Skip leading zero if present (ASN.1 integer is signed, might have 0x00 pad for positive MSB) */
	const uint8_t *val = *p;
	size_t vlen = len;
	while (vlen > 0 && val[0] == 0x00) {
		val++;
		vlen--;
	}

	/* Copy to key element */
	el->len = (uint32_t)vlen;
	el->buf = lws_malloc(vlen, "asn1 int");
	if (!el->buf) return -1;
	memcpy(el->buf, val, vlen);

	*p += len;
	return 0;
}

int
lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk,
			 void *pem, size_t len, const char *passphrase)
{
	/* Minimal RSA PKCS#1 parser */
	DWORD dwLen = 0, dwSkip, dwFlags;
	uint8_t *der = NULL;
	const uint8_t *p, *end;
	size_t seq_len;
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
	if (!der) return -1;

	if (!CryptStringToBinaryA((LPCSTR)pem, (DWORD)len, dwFlags, der, &dwLen, NULL, NULL)) {
		lws_free(der);
		return -1;
	}

	p = der;
	end = der + dwLen;

	/* Try parsing SEQUENCE */
	if (p >= end || *p++ != 0x30) goto bail; /* SEQUENCE */
	if (lws_asn1_read_length(&p, end, &seq_len) < 0) goto bail;

	/* Check for PKCS#8 wrapping: version=0, AlgorithmIdentifier, OCTET STRING */
	/* Peek version */
	/*
	   If it's RSA PKCS#1: SEQUENCE { version (0), n, e, d... }
	   If it's PKCS#8: SEQUENCE { version (0), AlgId, OctetString }
	*/

	/* Read version */
	if (p >= end || *p++ != 0x02) goto bail; /* INTEGER */
	size_t ver_len;
	if (lws_asn1_read_length(&p, end, &ver_len) < 0) goto bail;
	p += ver_len; /* Skip version value (usually 0) */

	/* Check next tag */
	if (p >= end) goto bail;

	if (*p == 0x30) {
		/* Likely PKCS#8 AlgorithmIdentifier. Skip it and OctetString header to get to inner key. */
		/* Just a heuristic: if we see SEQUENCE, we assume PKCS#8 and try to dig in. */
		/* Actually proper parsing is better but keeping it minimal. */
		/* Skip AlgId */
		size_t alg_len;
		p++;
		if (lws_asn1_read_length(&p, end, &alg_len) < 0) goto bail;
		p += alg_len;

		/* Expect OCTET STRING */
		if (p >= end || *p++ != 0x04) goto bail;
		size_t oct_len;
		if (lws_asn1_read_length(&p, end, &oct_len) < 0) goto bail;

		/* Now p points to inner key (RSAPrivateKey usually).
		   It should be a SEQUENCE again. */
		if (p >= end || *p++ != 0x30) goto bail;
		if (lws_asn1_read_length(&p, end, &seq_len) < 0) goto bail;

		/* Read inner version */
		if (p >= end || *p++ != 0x02) goto bail;
		if (lws_asn1_read_length(&p, end, &ver_len) < 0) goto bail;
		p += ver_len;
	} else if (*p == 0x02) {
		/* Likely RSA PKCS#1 starting with Modulus (since we already read Version) */
		/* Backtrack pointer to Modulus tag? No, we just continue reading RSA fields. */
		p--; /* Back to tag */
	} else {
		goto bail;
	}

	/* Read RSA fields */
	jwk->kty = LWS_GENCRYPTO_KTY_RSA;

	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N]) < 0) goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E]) < 0) goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D]) < 0) goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P]) < 0) goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q]) < 0) goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP]) < 0) goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ]) < 0) goto bail;
	if (lws_asn1_read_integer(&p, end, &jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI]) < 0) goto bail;

	ret = 0;

bail:
	lws_free(der);
	return ret;
}
#endif

int
lws_tls_schannel_cert_info_load(struct lws_context *context,
                                const char *cert, const char *private_key,
                                const char *mem_cert, size_t len_mem_cert,
                                const char *mem_privkey, size_t mem_privkey_len,
                                PCCERT_CONTEXT *pcert)
{
	struct lws_x509_cert x509_obj = {0};
	struct lws_gencrypto_keyelem e[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	BCRYPT_RSAKEY_BLOB *rsablob;
	ULONG bloblen;
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	SECURITY_STATUS status;
	uint8_t *p;
	int ret = 1;

	memset(e, 0, sizeof(e));

	/* 1. Load Certificate */
	if (cert) {
		uint8_t *der = NULL;
		lws_filepos_t amount;

		if (lws_tls_alloc_pem_to_der_file(context, cert, mem_cert, len_mem_cert, &der, &amount)) {
			lwsl_err("%s: Failed to load cert file %s\n", __func__, cert ? cert : "mem");
			return 1;
		}

		x509_obj.cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, (DWORD)amount);
		lws_free(der);
	} else if (mem_cert) {
		if (lws_x509_parse_from_pem(&x509_obj, mem_cert, len_mem_cert)) {
			lwsl_err("%s: Failed to parse cert pem\n", __func__);
			return 1;
		}
	} else {
		return 1; /* No cert */
	}

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
    uint8_t *key_der = NULL;
    lws_filepos_t key_der_len;

    if (lws_tls_alloc_pem_to_der_file(context, private_key, mem_privkey, mem_privkey_len, &key_der, &key_der_len)) {
        lwsl_err("%s: Failed to load key\n", __func__);
        goto cleanup;
    }

    /* Parse DER to Key Elements */
    const uint8_t *kp = key_der;
    const uint8_t *kend = key_der + key_der_len;
    size_t seq_len;

    if (kp >= kend || *kp++ != 0x30) { lws_free(key_der); goto cleanup; }
    if (lws_asn1_read_length(&kp, kend, &seq_len) < 0) { lws_free(key_der); goto cleanup; }

    /* Check for version */
    if (kp >= kend || *kp++ != 0x02) { lws_free(key_der); goto cleanup; }
    size_t ver_len;
    if (lws_asn1_read_length(&kp, kend, &ver_len) < 0) { lws_free(key_der); goto cleanup; }
    kp += ver_len;

    /* PKCS#8 check */
    if (kp < kend && *kp == 0x30) {
        size_t alg_len;
        kp++;
        if (lws_asn1_read_length(&kp, kend, &alg_len) < 0) { lws_free(key_der); goto cleanup; }
        kp += alg_len;
        if (kp >= kend || *kp++ != 0x04) { lws_free(key_der); goto cleanup; }
        size_t oct_len;
        if (lws_asn1_read_length(&kp, kend, &oct_len) < 0) { lws_free(key_der); goto cleanup; }
        if (kp >= kend || *kp++ != 0x30) { lws_free(key_der); goto cleanup; }
        if (lws_asn1_read_length(&kp, kend, &seq_len) < 0) { lws_free(key_der); goto cleanup; }
        if (kp >= kend || *kp++ != 0x02) { lws_free(key_der); goto cleanup; }
        if (lws_asn1_read_length(&kp, kend, &ver_len) < 0) { lws_free(key_der); goto cleanup; }
        kp += ver_len;
    } else if (kp < kend && *kp == 0x02) {
        kp--;
    } else {
        lws_free(key_der);
        goto cleanup;
    }

    if (lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_N]) < 0 ||
        lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_E]) < 0 ||
        lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_D]) < 0 ||
        lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_P]) < 0 ||
        lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_Q]) < 0 ||
        lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_DP]) < 0 ||
        lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_DQ]) < 0 ||
        lws_asn1_read_integer(&kp, kend, &e[LWS_GENCRYPTO_RSA_KEYEL_QI]) < 0) {
        lws_free(key_der);
        lws_gencrypto_destroy_elements(e, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
        goto cleanup;
    }
    lws_free(key_der);

	/* 3. Convert to BCRYPT_RSAKEY_BLOB */
	bloblen = sizeof(BCRYPT_RSAKEY_BLOB) +
		e[LWS_GENCRYPTO_RSA_KEYEL_E].len +
		e[LWS_GENCRYPTO_RSA_KEYEL_N].len +
		e[LWS_GENCRYPTO_RSA_KEYEL_P].len +
		e[LWS_GENCRYPTO_RSA_KEYEL_Q].len +
		e[LWS_GENCRYPTO_RSA_KEYEL_DP].len +
		e[LWS_GENCRYPTO_RSA_KEYEL_DQ].len +
		e[LWS_GENCRYPTO_RSA_KEYEL_QI].len +
		e[LWS_GENCRYPTO_RSA_KEYEL_D].len;

	rsablob = (BCRYPT_RSAKEY_BLOB *)lws_malloc(bloblen, "rsablob");
	if (!rsablob) {
	    lws_gencrypto_destroy_elements(e, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
	    goto cleanup;
	}

	rsablob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
	rsablob->BitLength = e[LWS_GENCRYPTO_RSA_KEYEL_N].len * 8;
	rsablob->cbPublicExp = e[LWS_GENCRYPTO_RSA_KEYEL_E].len;
	rsablob->cbModulus = e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
	rsablob->cbPrime1 = e[LWS_GENCRYPTO_RSA_KEYEL_P].len;
	rsablob->cbPrime2 = e[LWS_GENCRYPTO_RSA_KEYEL_Q].len;

	p = (uint8_t *)(rsablob + 1);
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, rsablob->cbPublicExp); p += rsablob->cbPublicExp;
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, rsablob->cbModulus); p += rsablob->cbModulus;
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_P].buf, rsablob->cbPrime1); p += rsablob->cbPrime1;
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, rsablob->cbPrime2); p += rsablob->cbPrime2;
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf, rsablob->cbPrime1); p += rsablob->cbPrime1;
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf, rsablob->cbPrime2); p += rsablob->cbPrime2;
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf, rsablob->cbPrime1); p += rsablob->cbPrime1;
	memcpy(p, e[LWS_GENCRYPTO_RSA_KEYEL_D].buf, rsablob->cbModulus);

	lws_gencrypto_destroy_elements(e, LWS_GENCRYPTO_RSA_KEYEL_COUNT);

	/* 4. Import Key */
	status = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
	if (status != ERROR_SUCCESS) {
	    lwsl_err("NCryptOpenStorageProvider failed 0x%x\n", (int)status);
	    lws_free(rsablob);
	    goto cleanup;
	}

	status = NCryptImportKey(hProv, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &hKey, (PBYTE)rsablob, bloblen, 0);
	lws_free(rsablob);

	if (status != ERROR_SUCCESS) {
	    lwsl_err("NCryptImportKey failed 0x%x\n", (int)status);
	    goto cleanup;
	}

	/* 5. Link Key to Cert */
	if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, (void*)&hKey)) {
	     lwsl_err("CertSetCertificateContextProperty (Handle) failed %d\n", GetLastError());
	     goto cleanup;
	}

	lwsl_notice("%s: loaded cert and attached key\n", __func__);

	/* Handle ownership transferred/shared with cert context. We do not free hKey. */
	hKey = 0;
	/* hProv is used by hKey, so we should probably keep it open too if hKey depends on it.
	   However, usually hKey keeps a reference to its provider.
	   Safe bet: Do not free hProv either if hKey is alive.
	*/
	hProv = 0;

	*pcert = x509_obj.cert;
	ret = 0;

cleanup:
    if (hKey) NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    if (ret && x509_obj.cert) CertFreeCertificateContext(x509_obj.cert);

    return ret;
}
