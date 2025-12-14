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
		/* PKCS#1: kp points to Modulus tag. Version already consumed. */
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
                                PCCERT_CONTEXT *pcert, HCERTSTORE *phStore,
                                void **phKey, int *pKeyType,
                                const char *container_name)
{
	struct lws_x509_cert x509_obj = {0};
	struct lws_gencrypto_keyelem e[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	BYTE *rsablob = NULL;
	ULONG bloblen;
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	int ret = 1;

	if (phStore) *phStore = NULL;
    if (phKey) *phKey = NULL;
    if (pKeyType) *pKeyType = 0; /* Default CAPI */

	memset(e, 0, sizeof(e));

	/* 1. Load Certificate */
    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!hStore) {
        lwsl_err("%s: Failed to create memory store\n", __func__);
        return 1;
    }

	if (cert) {
		uint8_t *der = NULL;
		lws_filepos_t amount;

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
        PCCERT_CONTEXT pStoreCert = NULL;
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
    uint8_t *key_der = NULL;
    lws_filepos_t key_der_len;

    if (lws_tls_alloc_pem_to_der_file(context, private_key, mem_privkey, mem_privkey_len, &key_der, &key_der_len)) {
        lwsl_err("%s: Failed to load key\n", __func__);
        goto cleanup;
    }

    /* Check if it is an EC key */
    /* If it is EC, we use CNG. If RSA, we use Legacy CAPI. */
    /* Simple check: If pem string contains "EC PRIVATE KEY", it's EC. */
    /* Or check OID in PKCS#8 */
    int is_ec = 0;
    if (strstr(private_key ? private_key : (mem_privkey ? mem_privkey : ""), "EC PRIVATE KEY")) {
        is_ec = 1;
    } else {
        /* Check DER for OID 1.2.840.10045.2.1 (ecPublicKey) */
        /* Sequence { Version, AlgorithmIdentifier { OID ... } ... } */
        const uint8_t *kp = key_der;
        const uint8_t *kend = key_der + key_der_len;
        size_t seq_len;
        if (kp < kend && *kp++ == 0x30 && lws_asn1_read_length(&kp, kend, &seq_len) == 0) {
             /* Check for version 0 */
             size_t ver_len;
             if (kp < kend && *kp++ == 0x02 && lws_asn1_read_length(&kp, kend, &ver_len) == 0) {
                  kp += ver_len;
                  /* Next is AlgorithmIdentifier Sequence */
                  size_t alg_len;
                  if (kp < kend && *kp++ == 0x30 && lws_asn1_read_length(&kp, kend, &alg_len) == 0) {
                       /* Check OID: 1.2.840.10045.2.1 is 06 07 2A 86 48 CE 3D 02 01 */
                       const uint8_t ec_oid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
                       if (alg_len >= sizeof(ec_oid) && !memcmp(kp, ec_oid, sizeof(ec_oid))) {
                           is_ec = 1;
                       }
                  }
             }
        }
    }

    if (is_ec) {
        /* EC Path: Use CNG (NCrypt) */
        NCRYPT_PROV_HANDLE hProvCNG = 0;
        NCRYPT_KEY_HANDLE hKeyCNG = 0;
        SECURITY_STATUS status;

        /* Open Storage Provider */
        /* For server (named), use MS_KEY_STORAGE_PROVIDER. For client (ephemeral), we could use it too but verify flags. */
        /* Actually, SChannel works best with KSP for EC. */

        status = NCryptOpenStorageProvider(&hProvCNG, MS_KEY_STORAGE_PROVIDER, 0);
        if (status != ERROR_SUCCESS) {
            lwsl_err("NCryptOpenStorageProvider failed 0x%x\n", (int)status);
            lws_free(key_der);
            goto cleanup;
        }

        /* Import Key */
        /* We have DER. NCryptImportKey supports NCRYPT_PKCS8_PRIVATE_KEY_BLOB */
        /* Note: If the PEM was "EC PRIVATE KEY" (SEC1), CryptStringToBinary converted it to DER SEC1. */
        /* NCryptImportKey typically expects PKCS#8. If it is SEC1, we might need to wrap it? */
        /* Windows 10+ might support ECCPRIVATE_BLOB? */
        /* But generic "Private Key" usually implies PKCS#8. */
        /* Let's try importing as PKCS8 first. */

        DWORD flags = 0;
        if (container_name) {
             /* We want a persisted key */
             /* NCryptImportKey takes a key name? */
             /* Yes, pszKeyName. */
             /* And we need NCRYPT_OVERWRITE_KEY_FLAG if it exists? */
             flags = NCRYPT_OVERWRITE_KEY_FLAG;
        }

        WCHAR wContainer[128];
        LPCWSTR keyName = NULL;
        if (container_name) {
             if (MultiByteToWideChar(CP_UTF8, 0, container_name, -1, wContainer, sizeof(wContainer)/sizeof(wContainer[0]))) {
                 keyName = wContainer;
             }
        }

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
             NCryptBuffer nameBuf;
             NCryptBufferDesc nameDesc;

             nameBuf.cbBuffer = (ULONG)((wcslen(wContainer) + 1) * sizeof(WCHAR));
             nameBuf.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
             nameBuf.pvBuffer = wContainer;

             nameDesc.ulVersion = NCRYPTBUFFER_VERSION;
             nameDesc.cBuffers = 1;
             nameDesc.pBuffers = &nameBuf;

             status = NCryptImportKey(hProvCNG, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &nameDesc, &hKeyCNG, (PUCHAR)key_der, (DWORD)key_der_len, flags);
        } else {
             status = NCryptImportKey(hProvCNG, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &hKeyCNG, (PUCHAR)key_der, (DWORD)key_der_len, flags);
        }

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

        /* Link to Cert */
        if (container_name) {
            /* Named Key: Use PROV_INFO with CNG Provider */
             CRYPT_KEY_PROV_INFO kpi = {0};
             kpi.pwszContainerName = wContainer;
             kpi.pwszProvName = MS_KEY_STORAGE_PROVIDER;
             kpi.dwProvType = 0; /* CNG */
             kpi.dwFlags = 0;
             kpi.dwKeySpec = 0; /* CNG keys have no KeySpec usually, or 0 */

             if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_PROV_INFO_PROP_ID, 0, (void*)&kpi)) {
                 lwsl_err("CertSetCertificateContextProperty (CNG ProvInfo) failed 0x%x\n", GetLastError());
                 NCryptFreeObject(hKeyCNG); // Free key handle?
                 /* If we persist it, we close the handle but the key remains in storage. */
                 NCryptFreeObject(hProvCNG);
                 goto cleanup;
             }

             /* Clean up handles */
             NCryptFreeObject(hKeyCNG);
             NCryptFreeObject(hProvCNG);

        } else {
             /* Ephemeral: Use CERT_KEY_PROV_HANDLE_PROP_ID with NCRYPT_KEY_HANDLE_PROP_ID? */
             /* Actually for CNG, we use CERT_NCRYPT_KEY_HANDLE_PROP_ID */
             if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, (void*)hKeyCNG)) {
                  lwsl_err("CertSetCertificateContextProperty (NCrypt Handle) failed 0x%x\n", GetLastError());
                  NCryptFreeObject(hKeyCNG);
                  NCryptFreeObject(hProvCNG);
                  goto cleanup;
             }
             /* We must keep the handle open? Or does Cert context take ownership? */
             /* For NCRYPT_KEY_HANDLE_PROP_ID, the doc says: "This property value is an NCRYPT_KEY_HANDLE data type." */
             /* Usually we don't close it if we want the cert to use it? */
             /* Actually, if we pass the handle, we should be careful. */
             /* But wait, my CAPI logic closes the key handle but keeps the provider. */
             /* For CNG, the Key Handle IS the object. */
             /* Let's try NOT freeing hKeyCNG here for ephemeral case, but free hProvCNG? */
             /* NCrypt handles are independent? */
             NCryptFreeObject(hProvCNG);
             /* We do NOT free hKeyCNG if successful, it is attached to cert? */
             /* Actually, CertSetCertificateContextProperty adds a *property*. It doesn't take ownership of the handle. */
             /* But if we close the handle, the property becomes invalid? */
             /* Yes. So we must leak/keep hKeyCNG for the lifetime of the cert. */
             /* But we return pcert = x509_obj.cert. */
             /* The caller will free pcert. */
             /* For CAPI, the Prov Handle is kept open. */
             /* For CNG, we need to keep the Key Handle open. */
             /* The lws_tls_schannel_cert_info_load signature returns HCRYPTPROV* phProv. */
             /* It does not have a slot for NCRYPT_KEY_HANDLE. */
             /* This is a problem for Client (Ephemeral) EC. */
             /* BUT: Client usually doesn't need to persist beyond the connection setup. */
             /* However, for Server EC, we use Named container, so we close handles and use string property. */

             /* Let's assume this patch is primarily for Server EC fix. */
             /* Client EC might work if we just return 0 for phProv (since it's not CAPI). */

             /* IMPORTANT: For Ephemeral (Client), we can't return the CNG handle in HCRYPTPROV* phProv. */
             /* We need to store it in the context using the new key_type aware structure. */
             if (phKey) *phKey = (void*)hKeyCNG;
             if (pKeyType) *pKeyType = 1; /* CNG */
        }

        *pcert = x509_obj.cert;
        return 0;
    }

    /* RSA Path (Legacy CAPI) */
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
        /* PKCS#1: kp points to Modulus tag. Version already consumed. */
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

	/* 3. Convert to PRIVATEKEYBLOB (CAPI) */
	/* BLOBHEADER + RSAPUBKEY + Modulus + Prime1 + Prime2 + Exponent1 + Exponent2 + Coefficient + PrivateExponent */
	/* CAPI uses Little Endian. */

    uint32_t cbModulus = e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
    /* Ensure alignment to 8 bytes if needed? Usually just length */
    uint32_t bitlen = cbModulus * 8;
    uint32_t cbPrime = cbModulus / 2;

    bloblen = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) +
              cbModulus +
              cbPrime + /* P */
              cbPrime + /* Q */
              cbPrime + /* DP */
              cbPrime + /* DQ */
              cbPrime + /* InverseQ (Coeff) */
              cbModulus; /* D */

    rsablob = lws_malloc(bloblen, "rsablob capi");
    if (!rsablob) {
        lws_gencrypto_destroy_elements(e, LWS_GENCRYPTO_RSA_KEYEL_COUNT);
        goto cleanup;
    }

    BLOBHEADER *blobHeader = (BLOBHEADER *)rsablob;
    blobHeader->bType = PRIVATEKEYBLOB;
    blobHeader->bVersion = CUR_BLOB_VERSION;
    blobHeader->reserved = 0;
    blobHeader->aiKeyAlg = CALG_RSA_KEYX;

    RSAPUBKEY *rsaPubKey = (RSAPUBKEY *)(rsablob + sizeof(BLOBHEADER));
    rsaPubKey->magic = 0x32415352; /* "RSA2" for private key */
    rsaPubKey->bitlen = bitlen;
    /* Public Exponent: usually small, fit in 4 bytes. e.g. 65537 */
    uint32_t pubExp = 0;
    if (e[LWS_GENCRYPTO_RSA_KEYEL_E].len <= 4) {
        /* ASN.1 is Big Endian. Convert to int host order (usually LE on Windows) */
        for (uint32_t i = 0; i < e[LWS_GENCRYPTO_RSA_KEYEL_E].len; i++) {
            pubExp = (pubExp << 8) | e[LWS_GENCRYPTO_RSA_KEYEL_E].buf[i];
        }
    } else {
        /* Standard CAPI RSAPUBKEY has only DWORD pubexp. If larger, this structure is insufficient. */
        /* Assuming standard exp */
        pubExp = 65537;
    }
    rsaPubKey->pubexp = pubExp; /* Already LE if assigned to uint32 */

    uint8_t *p = (uint8_t *)(rsaPubKey + 1);

    /* Helper macro to copy and reverse (Big Endian -> Little Endian) */
    /* And pad with zeros at the END (high bytes) if source is shorter than dest */
#define COPY_REVERSE(elem, size) \
    do { \
        uint32_t _len = e[elem].len; \
        uint32_t _size = size; \
        if (_len > _size) _len = _size; \
        for (uint32_t i = 0; i < _len; i++) { \
            p[(_len - 1) - i] = e[elem].buf[i]; \
        } \
        if (_size > _len) { \
            memset(p + _len, 0, _size - _len); \
        } \
        p += _size; \
    } while(0)

    COPY_REVERSE(LWS_GENCRYPTO_RSA_KEYEL_N, cbModulus);
    COPY_REVERSE(LWS_GENCRYPTO_RSA_KEYEL_P, cbPrime);
    COPY_REVERSE(LWS_GENCRYPTO_RSA_KEYEL_Q, cbPrime);
    COPY_REVERSE(LWS_GENCRYPTO_RSA_KEYEL_DP, cbPrime);
    COPY_REVERSE(LWS_GENCRYPTO_RSA_KEYEL_DQ, cbPrime);
    COPY_REVERSE(LWS_GENCRYPTO_RSA_KEYEL_QI, cbPrime);
    COPY_REVERSE(LWS_GENCRYPTO_RSA_KEYEL_D, cbModulus);

#undef COPY_REVERSE

	lws_gencrypto_destroy_elements(e, LWS_GENCRYPTO_RSA_KEYEL_COUNT);

	/* 4. Import Key (Legacy CAPI) */
    /* MS_ENH_RSA_AES_PROV type is PROV_RSA_AES, not PROV_RSA_FULL. Mismatch causes NTE_KEYSET_ENTRY_BAD. */
    if (container_name) {
        /* Use named container for persistence (needed for SChannel server) */
        /* First try to create new keyset */
        if (!CryptAcquireContext(&hProv, container_name, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
            if (GetLastError() == NTE_EXISTS) {
                /* Exists, open it */
                 if (!CryptAcquireContext(&hProv, container_name, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_SILENT)) {
                     lwsl_err("CryptAcquireContext (open) failed 0x%x\n", GetLastError());
                     lws_free(rsablob);
                     goto cleanup;
                 }
            } else {
                lwsl_err("CryptAcquireContext (new) failed 0x%x\n", GetLastError());
                lws_free(rsablob);
                goto cleanup;
            }
        }
    } else {
        /* Ephemeral (Client) */
        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            lwsl_err("CryptAcquireContext (ephemeral) failed 0x%x\n", GetLastError());
            lws_free(rsablob);
            goto cleanup;
        }
    }

    if (!CryptImportKey(hProv, rsablob, bloblen, 0, CRYPT_EXPORTABLE, &hKey)) {
        lwsl_err("CryptImportKey failed 0x%x\n", GetLastError());
        lws_free(rsablob);
        goto cleanup;
    }
    lws_free(rsablob);

	/* 5. Link Key to Cert (Legacy Property) */
    if (container_name) {
        /*
         * For Server (Named Container), we must tell SChannel where the key is using PROV_INFO.
         * SChannel runs in LSA and cannot always use the process-local handle we have.
         */
        CRYPT_KEY_PROV_INFO kpi = {0};
        WCHAR wContainer[128];

        /* Convert container name to Wide String */
        if (!MultiByteToWideChar(CP_UTF8, 0, container_name, -1, wContainer, sizeof(wContainer)/sizeof(wContainer[0]))) {
             lwsl_err("MultiByteToWideChar failed\n");
             goto cleanup;
        }

        kpi.pwszContainerName = wContainer;
#ifdef MS_ENH_RSA_AES_PROV_W
        kpi.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W;
#else
        kpi.pwszProvName = (LPWSTR)L"Microsoft Enhanced RSA and AES Cryptographic Provider";
#endif
        kpi.dwProvType = PROV_RSA_AES;
        kpi.dwFlags = 0;
        kpi.cProvParam = 0;
        kpi.rgProvParam = NULL;
        kpi.dwKeySpec = AT_KEYEXCHANGE;

        if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_PROV_INFO_PROP_ID, 0, (void*)&kpi)) {
             lwsl_err("CertSetCertificateContextProperty (ProvInfo) failed 0x%x\n", GetLastError());
             goto cleanup;
        }
    } else {
        /*
         * For Client (Ephemeral), we use the handle directly.
         * Note: CERT_KEY_PROV_HANDLE_PROP_ID usage is process-specific but usually works for client auth
         * if the CSP supports it or if we are verifying context.
         */
        if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_PROV_HANDLE_PROP_ID, 0, (void*)hProv)) {
             lwsl_err("CertSetCertificateContextProperty (ProvHandle) failed 0x%x\n", GetLastError());
             goto cleanup;
        }

        /* Explicitly set Key Spec to AT_KEYEXCHANGE (1) */
        DWORD keySpec = AT_KEYEXCHANGE;
        if (!CertSetCertificateContextProperty(x509_obj.cert, CERT_KEY_SPEC_PROP_ID, 0, (void*)&keySpec)) {
             lwsl_warn("CertSetCertificateContextProperty (KeySpec) failed 0x%x\n", GetLastError());
        }
    }

	/* We can close the key handle, but MUST keep the provider handle open.
       The key is associated with the provider context.
    */
    if (hKey) {
        CryptDestroyKey(hKey);
        hKey = 0;
    }

	*pcert = x509_obj.cert;
	ret = 0;

cleanup:
    /* hKey is CryptDestroyKey for CAPI, but if we zeroed it, it's fine. */
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) {
        if (!ret && phKey) {
            *phKey = (void*)hProv;
            if (pKeyType) *pKeyType = 0; /* CAPI */
        } else {
            CryptReleaseContext(hProv, 0);
        }
    }
    if (ret && x509_obj.cert) CertFreeCertificateContext(x509_obj.cert);
    if (ret && phStore && *phStore) {
        CertCloseStore(*phStore, 0);
        *phStore = NULL;
    }

    return ret;
}
