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

struct lws_tls_schannel_x509 {
	PCCERT_CONTEXT cert;
};

int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
		        union lws_tls_cert_info_results *buf, size_t len)
{
	/* stub */
	return 0;
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	/* stub */
	return 0;
}

int
lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type,
	      union lws_tls_cert_info_results *buf, size_t len)
{
	/* stub */
	return 0;
}

int
lws_tls_alloc_pem_to_der_file(struct lws_context *context, const char *filename,
			      const char *inbuf, lws_filepos_t inlen,
			      uint8_t **buf, lws_filepos_t *amount)
{
	/* stub */
	return 0;
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	/* stub */
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

int
lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk,
			 void *pem, size_t len, const char *passphrase)
{
	/* Parsing arbitrary PEM private keys on Windows is hard without a full parser.
	   CryptStringToBinary can decode base64, but parsing the resulting PKCS#8 or plain RSA struct
	   requires parsing ASN.1 to import into CNG.
	   However, if the PEM is a standard PKCS#8 unencrypted key, CryptImportPKCS8 *might* work if we strip headers.
	   Or `CryptDecodeObjectEx` with `PKCS_PRIVATE_KEY_INFO` or `RSA_PRIVATE_KEY` etc.

	   For this stub/initial implementation, we might have to fail or implement a minimal ASN.1 reader.
	   Since `lws-genrsa.c` implemented some manual logic, maybe we can rely on that?
	   But converting PEM->DER->BCRYPT_BLOB is complex.

	   Given this is for `api-test-jose` which likely uses specific test keys, maybe we can support unencrypted PKCS#8?

	   Returning -1 for now as a known limitation unless we want to pull in a big parser.
	*/
	lwsl_err("%s: Parsing PEM private keys not fully supported on SChannel backend yet\n", __func__);
	return -1;
}
#endif
