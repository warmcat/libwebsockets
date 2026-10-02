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

#define LWS_FT_UNIX_EPOCH 116444736000000000ULL

static time_t
filetime_to_unix(FILETIME ft)
{
	ULARGE_INTEGER ull;
	ull.LowPart = ft.dwLowDateTime;
	ull.HighPart = ft.dwHighDateTime;

	/*
	 * QuadPart is unsigned: a certificate date before 1970 (or a garbage
	 * NotAfter) would wrap the subtraction and come back out as a time
	 * ~56000 years in the future, ie, "never expires"
	 */

	if (ull.QuadPart < LWS_FT_UNIX_EPOCH)
		return (time_t)0;

	ull.QuadPart = (ull.QuadPart - LWS_FT_UNIX_EPOCH) / 10000000ULL;

	if (sizeof(time_t) < 8 && ull.QuadPart > 0x7fffffffULL)
		return (time_t)0x7fffffff;

	return (time_t)ull.QuadPart;
}

static int
lws_tls_schannel_cert_info(PCCERT_CONTEXT pCert, enum lws_tls_cert_info type,
		union lws_tls_cert_info_results *buf, size_t len)
{
	if (!pCert)
		return -1;

	/*
	 * A zero len means "the union's own ns.name[]", which is the contract
	 * the other backends implement.  Without this, CertNameToStrA() /
	 * CertGetNameStringA() are asked for a zero-sized buffer, write
	 * nothing, return the size they would have needed (ie, nonzero, so
	 * "success"), and we hand the caller a strlen() of uninitialised
	 * stack as a certificate name.
	 */

	if (!len)
		len = sizeof(buf->ns.name);

	switch(type) {
		case LWS_TLS_CERT_INFO_VALIDITY_FROM:
			buf->time = filetime_to_unix(pCert->pCertInfo->NotBefore);
			break;
		case LWS_TLS_CERT_INFO_VALIDITY_TO:
			buf->time = filetime_to_unix(pCert->pCertInfo->NotAfter);
			break;
		case LWS_TLS_CERT_INFO_COMMON_NAME:
			/* a return of 1 is just the NUL, ie, there is no CN */
			if (CertGetNameStringA(pCert, CERT_NAME_ATTR_TYPE, 0,
					       szOID_COMMON_NAME, buf->ns.name,
					       (DWORD)len) < 2)
				return -1;
			buf->ns.name[len - 1] = '\0';
			buf->ns.len = (int)strlen(buf->ns.name);
			break;
		case LWS_TLS_CERT_INFO_ISSUER_NAME:
			if (CertNameToStrA(pCert->dwCertEncodingType,
					   &pCert->pCertInfo->Issuer,
					   CERT_X500_NAME_STR, buf->ns.name,
					   (DWORD)len) < 2)
				return -1;
			buf->ns.name[len - 1] = '\0';
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
		case LWS_TLS_CERT_INFO_DER_SPKI:
		{
			DWORD cbSize = 0;
			/* First, get the size of the DER encoded SPKI */
			if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						 X509_PUBLIC_KEY_INFO,
						 &pCert->pCertInfo->SubjectPublicKeyInfo,
						 0, NULL, NULL, &cbSize)) {
				return -1;
			}
			buf->ns.len = (int)cbSize;
			if (len < cbSize)
				return -1;

			if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						 X509_PUBLIC_KEY_INFO,
						 &pCert->pCertInfo->SubjectPublicKeyInfo,
						 0, NULL, buf->ns.name, &cbSize)) {
				return -1;
			}
			break;
		}
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
	struct lws_tls_schannel_conn *conn;
	PCCERT_CONTEXT pCert = NULL;
	int ret = 0;

	/*
	 * the tls session lives on the network wsi: an h2 / mux stream asking
	 * about its peer has none of its own
	 */
	wsi = lws_get_network_wsi(wsi);
	conn = wsi->io->tls.ssl;

	if (!conn)
		return -1;

	if (QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert) != SEC_E_OK || !pCert)
		return -1;

	switch (type) {
		case LWS_TLS_CERT_INFO_VERIFIED:
			/*
			 * The real result recorded by
			 * lws_tls_schannel_confirm_cert(), ie, did the chain
			 * verify with nothing forgiven.  This used to be
			 * hardcoded to 1, which made it a constant-true
			 * authorisation predicate: a peer accepted only
			 * because LCCSCF_ALLOW_SELFSIGNED was set reported
			 * itself verified.  If nothing checked the peer at
			 * all, we have no answer and must fail closed.
			 */
			if (!conn->f_peer_cert_checked) {
				ret = -1;
				break;
			}
			buf->verified = (unsigned int)conn->f_peer_cert_verified;
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
	/*
	 * The vhost may legitimately have no ctx, eg, it was created with
	 * LWS_SERVER_OPTION_IGNORE_MISSING_CERT and the cert has not arrived
	 * yet... there is nothing to configure on then.
	 */

	if (!vh->tls.ssl_ctx)
		return 0;

	if (!lws_check_opt(vh->options,
			   LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) &&
	    !lws_check_opt(vh->options,
		LWS_SERVER_OPTION_MBEDTLS_VERIFY_CLIENT_CERT_POST_HANDSHAKE))
		return 0;

	/*
	 * The handshake asks for the client cert (ASC_REQ_MUTUAL_AUTH) and
	 * lws_tls_schannel_server_client_cert() checks it against
	 * ssl_ctx->ca_store.  With no CA there is nothing to check it
	 * against, so refuse to bring the vhost up rather than come up
	 * accepting anonymous peers on an endpoint whose only authentication
	 * is mTLS.
	 */

	if (!vh->tls.ssl_ctx->ca_store &&
	    lws_check_opt(vh->options,
			  LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) &&
	    !lws_check_opt(vh->options,
			   LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED)) {
		lwsl_vhost_err(vh, "requires a valid client cert but no CA "
			       "was configured (ssl_ca_filepath / "
			       "server_ssl_ca_mem)");

		return 1;
	}

	lwsl_vhost_notice(vh, "will request and check client certificates");

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
lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted,
		const char *common_name)
{
	HCERTCHAINENGINE engine = NULL;
	PCCERT_CHAIN_CONTEXT chain = NULL;
	LWS_CERT_CHAIN_ENGINE_CONFIG cfg;
	CERT_CHAIN_PARA cp;
	HCERTSTORE store;
	char cn[256];
	int ret = -1;

	if (!x509 || !x509->cert || !trusted || !trusted->cert)
		return -1;

	if (common_name) {
		if (CertGetNameStringA(x509->cert, CERT_NAME_ATTR_TYPE, 0,
				       szOID_COMMON_NAME, cn, sizeof(cn)) < 2) {
			lwsl_err("%s: CertGetNameStringA failed\n", __func__);

			return -1;
		}
		cn[sizeof(cn) - 1] = '\0';
		if (strcmp(cn, common_name)) {
			lwsl_err("%s: common name mismatch (expected %s, got %s)\n",
				 __func__, common_name, cn);

			return -1;
		}
	}

	/*
	 * Build and validate a real chain with `trusted` as the exclusive
	 * root, rather than only asking "did this key sign that cert".  A
	 * bare signature check accepts an expired CA, and accepts a leaf
	 * certificate with no basicConstraints CA:TRUE acting as an issuer,
	 * ie, it lets anyone holding a certificate we know mint further
	 * "verified" certificates.
	 */

	store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
	if (!store)
		return -1;

	if (!CertAddCertificateContextToStore(store, trusted->cert,
					      CERT_STORE_ADD_ALWAYS, NULL))
		goto bail;

	memset(&cfg, 0, sizeof(cfg));
	cfg.hExclusiveRoot = store;
	cfg.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
	cfg.cbSize = sizeof(cfg);

	if (!CertCreateCertificateChainEngine(
			(PCERT_CHAIN_ENGINE_CONFIG)&cfg, &engine)) {
		cfg.dwExclusiveFlags = 0;
		cfg.cbSize = (DWORD)offsetof(LWS_CERT_CHAIN_ENGINE_CONFIG,
					     dwExclusiveFlags);
		if (!CertCreateCertificateChainEngine(
				(PCERT_CHAIN_ENGINE_CONFIG)&cfg, &engine))
			goto bail;
	}

	memset(&cp, 0, sizeof(cp));
	cp.cbSize = sizeof(cp);

	if (!CertGetCertificateChain(engine, x509->cert, NULL, store, &cp, 0,
				     NULL, &chain) || !chain)
		goto bail;

	/*
	 * We do no revocation lookups, so "unknown" is the expected answer
	 * for those and is not a reason to refuse; everything else (expiry,
	 * basic constraints, name constraints, untrusted root) is.
	 */

	if (!(chain->TrustStatus.dwErrorStatus &
	      ~(DWORD)(CERT_TRUST_REVOCATION_STATUS_UNKNOWN |
		       CERT_TRUST_IS_OFFLINE_REVOCATION)))
		ret = 0;
	else
		lwsl_err("%s: chain error 0x%x\n", __func__,
			 (unsigned int)chain->TrustStatus.dwErrorStatus);

bail:
	if (chain)
		CertFreeCertificateChain(chain);
	if (engine)
		CertFreeCertificateChainEngine(engine);
	CertCloseStore(store, 0);

	return ret;
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

	/*
	 * The length *bytes* were in bounds, but the length *value* has to be
	 * too: every caller then either advances by it or reads through it,
	 * and on 32-bit an unvalidated value up to 0xffffffff also wraps the
	 * `p >= end` tests that follow those advances
	 */

	if (*len > (size_t)(end - *p))
		return -1;

	return 0;
}


static int
lws_asn1_read_integer(const uint8_t **p, const uint8_t *end, struct lws_gencrypto_keyelem *el)
{
	const uint8_t *val;
	size_t len, vlen;

	if (*p >= end || **p != 0x02)
		return -1; /* Expect INTEGER tag */
	(*p)++;

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
				if (rsa_min_bits && (uint64_t)rsablob->cbModulus * 8 <
							(uint64_t)rsa_min_bits) {
					lwsl_err("%s: key bits %d less than minimum %d\n", __func__,
						 (int)(rsablob->cbModulus * 8), rsa_min_bits);
					lws_free(rsablob);
					goto bail;
				}
				/* Convert blob to JWK elements */
				/* n, e */
				uint8_t *p = (uint8_t *)(rsablob + 1);

				/* Exponent */
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc(rsablob->cbPublicExp, "rsa e");
				if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf) {
					lws_free(rsablob);
					goto bail;
				}
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len = rsablob->cbPublicExp;
				memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, p, rsablob->cbPublicExp);
				p += rsablob->cbPublicExp;
				/* Modulus */
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc(rsablob->cbModulus, "rsa n");
				if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf) {
					lws_free(rsablob);
					goto bail;
				}
				jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len = rsablob->cbModulus;
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

	if (!curves) {
		lwsl_err("%s: ec curves not allowed\n", __func__);
		goto bail;
	}

	jwk->kty = LWS_GENCRYPTO_KTY_EC;
	BCRYPT_ECCKEY_BLOB *eccblob = lws_malloc(dwBlobLen, "ec pub");
	if (!eccblob)
		goto bail;

	if (BCRYPT_SUCCESS(BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)eccblob, dwBlobLen, &dwBlobLen, 0))) {
		uint8_t *p = (uint8_t *)(eccblob + 1);
		const char *crv;

		/*
		 * The curve is implied by the coordinate size.  Leaving 'crv'
		 * unset (as this did) hands downstream JOSE code a JWK it
		 * cannot identify the curve of, and made the 'curves'
		 * allowlist argument unenforceable.
		 */

		switch (eccblob->cbKey) {
		case 32:
			crv = "P-256";
			break;
		case 48:
			crv = "P-384";
			break;
		case 66:
			crv = "P-521";
			break;
		default:
			lwsl_err("%s: unsupported EC key size %d\n", __func__,
				 (int)eccblob->cbKey);
			goto bail_ec;
		}

		if (!strstr(curves, crv)) {
			lwsl_err("%s: curve %s not in allowed list %s\n",
				 __func__, crv, curves);
			goto bail_ec;
		}

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf =
				(uint8_t *)lws_strdup(crv);
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
			goto bail_ec;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].len =
				(uint32_t)strlen(crv);

		/* X */
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(eccblob->cbKey, "ec x");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf)
			goto bail_ec;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len = eccblob->cbKey;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, p, eccblob->cbKey);
		p += eccblob->cbKey;
		/* Y */
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(eccblob->cbKey, "ec y");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf)
			goto bail_ec;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len = eccblob->cbKey;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, p, eccblob->cbKey);

		ret = 0;
	}

bail_ec:
	lws_free(eccblob);

bail:
	BCryptDestroyKey(hKey);

	if (ret)
		/* do not leave half-populated key material behind */
		lws_jwk_destroy(jwk);

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

	/*
	 * This arm only understands RSA, and it overwrites jwk->kty below.  An
	 * EC jwk that came from the cert must not be silently turned into an
	 * RSA one and then compared against RSA element indices that alias the
	 * EC crv / x elements: refuse it up front, the way the other backends
	 * refuse a private key whose public point does not match (C-343).
	 */

	if (jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: only RSA private keys are supported on this "
			 "backend (jwk kty %d)\n", __func__, jwk->kty);

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
	if (p >= end || *p != 0x30)
		goto bail; /* SEQUENCE */
	p++;

	if (lws_asn1_read_length(&p, end, &seq_len) < 0)
		goto bail;

	/* Check for PKCS#8 wrapping: version=0, AlgorithmIdentifier, OCTET STRING */
	/* Peek version */
	/*
	   If it's RSA PKCS#1: SEQUENCE version 0, n, e, d...
	   If it's PKCS#8: SEQUENCE version 0, AlgId, OctetString
	   */

	/* Read version */
	if (p >= end || *p != 0x02)
		goto bail; /* INTEGER */
	p++;

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
		if (p >= end || *p != 0x04)
			goto bail;
		p++;
		size_t oct_len;
		if (lws_asn1_read_length(&p, end, &oct_len) < 0)
			goto bail;

		/* Now p points to inner key (RSAPrivateKey usually).
		   It should be a SEQUENCE again. */
		if (p >= end || *p != 0x30)
			goto bail;
		p++;
		if (lws_asn1_read_length(&p, end, &seq_len) < 0)
			goto bail;

		/* Read inner version */
		if (p >= end || *p != 0x02)
			goto bail;
		p++;
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

	{
		struct lws_gencrypto_keyelem tmp_n = {0}, tmp_e = {0};

		if (lws_asn1_read_integer(&p, end, &tmp_n) < 0)
			goto bail;
		if (lws_asn1_read_integer(&p, end, &tmp_e) < 0) {
			lws_free(tmp_n.buf);
			goto bail;
		}

		if (tmp_n.len != jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len ||
		    memcmp(tmp_n.buf, jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, tmp_n.len) ||
		    tmp_e.len != jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len ||
		    memcmp(tmp_e.buf, jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, tmp_e.len)) {
			lwsl_err("%s: privkey doesn't match jwk pubkey\n", __func__);
			lws_free(tmp_n.buf);
			lws_free(tmp_e.buf);
			goto bail;
		}

		lws_free(tmp_n.buf);
		lws_free(tmp_e.buf);
	}

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

	if (phStore) {
		/* do not leak a store the caller already had installed */
		if (*phStore)
			CertCloseStore(*phStore, 0);
		*phStore = hStore;
	} else
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
	/*
	 * Tell an EC key from the DER itself: the PEM label is gone by now,
	 * and the bytes we were handed in memory need not be NUL-terminated,
	 * so they cannot be searched as a string.  This used to strstr() the
	 * memory key (reading past its end) or, for a key file, its *path*.
	 */
	is_ec = 0;
	{
		kp = key_der;
		kend = key_der + key_der_len;
		if (kp < kend && *kp == 0x30) {
			kp++;
			if (lws_asn1_read_length(&kp, kend, &seq_len) == 0) {
				if (kp < kend && *kp == 0x02) {
					kp++;
					if (lws_asn1_read_length(&kp, kend, &ver_len) == 0) {
						/*
						 * SEC1 (RFC 5915): version 1
						 * then the key as an OCTET
						 * STRING
						 */
						if (ver_len == 1 && kp + 1 < kend &&
						    kp[0] == 1 && kp[1] == 0x04)
							is_ec = 1;
						kp += ver_len;
						/*
						 * PKCS#8: version 0 then the
						 * AlgorithmIdentifier, whose
						 * OID is 1.2.840.10045.2.1
						 * (ecPublicKey) for EC
						 */
						if (kp < kend && *kp == 0x30) {
							kp++;
							if (lws_asn1_read_length(&kp, kend, &alg_len) == 0) {
								/* Check OID: 1.2.840.10045.2.1 is 06 07 2A 86 48 CE 3D 02 01 */
								/* ec_oid is already declared at the top */
								if (alg_len >= sizeof(ec_oid) &&
								    kp + sizeof(ec_oid) <= kend &&
								    !memcmp(kp, ec_oid, sizeof(ec_oid))) {
									is_ec = 1;
								}
							}
						}
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

	if (kp >= kend || *kp != 0x30) {
		lwsl_err("%s: Failed to find SEQUENCE tag at start of key\n", __func__);
		lws_free(key_der);
		goto cleanup;
	}
	kp++;
	if (lws_asn1_read_length(&kp, kend, &seq_len) < 0) {
		lwsl_err("%s: Failed to read key SEQUENCE length\n", __func__);
		lws_free(key_der);
		goto cleanup;
	}

	/* Check for version */
	if (kp >= kend || *kp != 0x02) {
		lwsl_err("%s: Failed to find version tag\n", __func__);
		lws_free(key_der);
		goto cleanup;
	}
	kp++;
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
		if (kp >= kend || *kp != 0x04) {
			lwsl_err("%s: PKCS#8 Failed to find OCTET STRING (0x04) tag\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}
		kp++;
		if (lws_asn1_read_length(&kp, kend, &oct_len) < 0) {
			lwsl_err("%s: PKCS#8 Failed to read octet length\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}

		pkcs1_seq_start = kp;

		if (kp >= kend || *kp != 0x30) {
			lwsl_err("%s: PKCS#8 Failed to find inner SEQUENCE\n", __func__);
			lws_free(key_der);

			goto cleanup;
		}
		kp++;
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

	/*
	 * Every success path returns directly above, so we are always here on
	 * failure and ret is always -1
	 */

cleanup:
	if (hKey)
		CryptDestroyKey(hKey);

	if (hKeyCNG)
		NCryptFreeObject(hKeyCNG);
	if (hProvCNG)
		NCryptFreeObject(hProvCNG);
	if (hProv)
		CryptReleaseContext(hProv, 0);

	if (x509_obj.cert)
		CertFreeCertificateContext(x509_obj.cert);
	if (phStore && *phStore) {
		CertCloseStore(*phStore, 0);
		*phStore = NULL;
	}

	return ret;
}

#if defined(LWS_WITH_ACME)
static int
_lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			     uint8_t *csr, size_t csr_len, char **privkey_pem,
			     size_t *privkey_len, int is_ecdsa)
{
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
	DWORD cbPubKeyInfo = 0;
	CERT_REQUEST_INFO reqInfo = {0};
	CERT_NAME_BLOB subjectName = {0};
	CERT_ALT_NAME_ENTRY sanEntry[2] = {0};
	CERT_ALT_NAME_INFO sanInfo = {0};
	BYTE *pbSanEncoded = NULL, *pbExtsEncoded = NULL;
	DWORD cbSanEncoded = 0, cbExtsEncoded = 0;
	CERT_EXTENSION ext = {0};
	CERT_EXTENSIONS exts = {0};
	CRYPT_ATTRIBUTE attr = {0};
	CRYPT_ATTR_BLOB attrBlob = {0};
	CRYPT_ALGORITHM_IDENTIFIER algId = {0};
	BYTE *pbCsr = NULL;
	DWORD cbCsr = 0;
	char dnStr[512] = "";
	WCHAR wCN[256] = {0}, wSAN[256] = {0};
	char *p;
	int ret = -1;
	DWORD cbPriv = 0;
	BYTE *pbPriv = NULL;
	int csr_b64_len = -1;

	/*
	 * The caller reads and eventually frees *privkey_pem on our success
	 * return, so it must be defined on every path
	 */

	*privkey_pem = NULL;
	*privkey_len = 0;

	if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
		return -1;

	if (is_ecdsa) {
		if (NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0) != ERROR_SUCCESS)
			goto bail;
	} else {
		DWORD bits = 4096;
		if (NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_RSA_ALGORITHM, NULL, 0, 0) != ERROR_SUCCESS)
			goto bail;
		NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PUCHAR)&bits, sizeof(bits), 0);
	}

	if (NCryptFinalizeKey(hKey, 0) != ERROR_SUCCESS)
		goto bail;

	/* Get Public Key Info */
	if (!CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING, NULL, &cbPubKeyInfo))
		goto bail;
	pPubKeyInfo = lws_malloc(cbPubKeyInfo, "pubkeyinfo");
	if (!pPubKeyInfo || !CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING, pPubKeyInfo, &cbPubKeyInfo))
		goto bail;

	/* Build Subject DN */
	p = dnStr;
	if (elements[LWS_TLS_REQ_ELEMENT_COUNTRY])
		p += lws_snprintf(p, sizeof(dnStr) - (p - dnStr), "C=%s,", elements[LWS_TLS_REQ_ELEMENT_COUNTRY]);
	if (elements[LWS_TLS_REQ_ELEMENT_STATE])
		p += lws_snprintf(p, sizeof(dnStr) - (p - dnStr), "S=%s,", elements[LWS_TLS_REQ_ELEMENT_STATE]);
	if (elements[LWS_TLS_REQ_ELEMENT_LOCALITY])
		p += lws_snprintf(p, sizeof(dnStr) - (p - dnStr), "L=%s,", elements[LWS_TLS_REQ_ELEMENT_LOCALITY]);
	if (elements[LWS_TLS_REQ_ELEMENT_ORGANIZATION])
		p += lws_snprintf(p, sizeof(dnStr) - (p - dnStr), "O=%s,", elements[LWS_TLS_REQ_ELEMENT_ORGANIZATION]);
	if (elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME])
		p += lws_snprintf(p, sizeof(dnStr) - (p - dnStr), "CN=%s,", elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME]);
	if (p > dnStr) *(p - 1) = '\0'; /* Remove trailing comma */

	if (!CertStrToNameA(X509_ASN_ENCODING, dnStr, CERT_X500_NAME_STR, NULL, NULL, &subjectName.cbData, NULL))
		goto bail;
	subjectName.pbData = lws_malloc(subjectName.cbData, "subjname");
	if (!subjectName.pbData || !CertStrToNameA(X509_ASN_ENCODING, dnStr, CERT_X500_NAME_STR, NULL, subjectName.pbData, &subjectName.cbData, NULL))
		goto bail;

	/* Build SAN Extensions */
	sanInfo.rgAltEntry = sanEntry;
	if (elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME]) {
		MultiByteToWideChar(CP_UTF8, 0, elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME], -1, wCN, sizeof(wCN)/sizeof(wCN[0]));
		sanEntry[sanInfo.cAltEntry].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
		sanEntry[sanInfo.cAltEntry].pwszDNSName = wCN;
		sanInfo.cAltEntry++;
	}
	if (elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME]) {
		MultiByteToWideChar(CP_UTF8, 0, elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME], -1, wSAN, sizeof(wSAN)/sizeof(wSAN[0]));
		sanEntry[sanInfo.cAltEntry].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
		sanEntry[sanInfo.cAltEntry].pwszDNSName = wSAN;
		sanInfo.cAltEntry++;
	}

	if (sanInfo.cAltEntry > 0) {
		if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &sanInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbSanEncoded, &cbSanEncoded)) {
			ext.pszObjId = szOID_SUBJECT_ALT_NAME2;
			ext.fCritical = FALSE;
			ext.Value.cbData = cbSanEncoded;
			ext.Value.pbData = pbSanEncoded;

			exts.cExtension = 1;
			exts.rgExtension = &ext;

			if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_EXTENSIONS, &exts, CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbExtsEncoded, &cbExtsEncoded)) {
				attr.pszObjId = szOID_RSA_certExtensions;
				attr.cValue = 1;
				attr.rgValue = &attrBlob;
				attrBlob.cbData = cbExtsEncoded;
				attrBlob.pbData = pbExtsEncoded;
			}
		}
	}

	/* Build Request Info */
	reqInfo.dwVersion = CERT_REQUEST_V1;
	reqInfo.Subject = subjectName;
	reqInfo.SubjectPublicKeyInfo = *pPubKeyInfo;
	reqInfo.cAttribute = (attr.cValue > 0) ? 1 : 0;
	reqInfo.rgAttribute = &attr;

	/* Set Signature Algorithm */
	algId.pszObjId = is_ecdsa ? szOID_ECDSA_SHA256 : szOID_RSA_SHA256RSA;

	/* Encode & Sign */
	if (!CryptSignAndEncodeCertificate(hKey, 0, X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
					   &reqInfo, &algId, NULL, NULL, &cbCsr))
		goto bail;

	pbCsr = lws_malloc(cbCsr, "csr_raw");
	if (!pbCsr || !CryptSignAndEncodeCertificate(hKey, 0, X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
						     &reqInfo, &algId, NULL, pbCsr, &cbCsr))
		goto bail;

	/*
	 * Convert CSR to base64url.  Keep the length in its own variable:
	 * assigning it to `ret` made every subsequent `goto bail` return a
	 * non-negative value, ie, success, with *privkey_pem never assigned.
	 */

	csr_b64_len = lws_jws_base64_enc((char *)pbCsr, (size_t)cbCsr,
					 (char *)csr, csr_len);
	if (csr_b64_len < 0)
		goto bail;

	/* Export Private Key as PEM */
	/* Windows 10+ CNG supports NCRYPT_PKCS8_PRIVATE_KEY_BLOB directly */
#ifndef NCRYPT_PKCS8_PRIVATE_KEY_BLOB
#define NCRYPT_PKCS8_PRIVATE_KEY_BLOB L"PKCS8_PRIVATEKEY"
#endif

	if (NCryptExportKey(hKey, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, NULL, 0, &cbPriv, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
		goto bail;
	pbPriv = lws_malloc(cbPriv, "privkey_raw");
	if (!pbPriv || NCryptExportKey(hKey, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, pbPriv, cbPriv, &cbPriv, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
		goto bail;

	{
		DWORD cchPem = 0, alloc;

		if (!CryptBinaryToStringA(pbPriv, cbPriv,
					  CRYPT_STRING_BASE64HEADER, NULL,
					  &cchPem))
			goto bail;

		/* the size query counts the NUL, the conversion does not */
		alloc = cchPem;
		*privkey_pem = lws_malloc(alloc, "privkey_pem");
		if (!*privkey_pem)
			goto bail;

		if (!CryptBinaryToStringA(pbPriv, cbPriv,
					  CRYPT_STRING_BASE64HEADER,
					  *privkey_pem, &cchPem)) {
			lws_free_set_NULL(*privkey_pem);
			goto bail;
		}

		(*privkey_pem)[alloc - 1] = '\0';
		*privkey_len = strlen(*privkey_pem);
	}

	ret = csr_b64_len;

bail:
	if (pbPriv) lws_free(pbPriv);
	if (pbCsr) lws_free(pbCsr);
	if (pbExtsEncoded) LocalFree(pbExtsEncoded);
	if (pbSanEncoded) LocalFree(pbSanEncoded);
	if (subjectName.pbData) lws_free(subjectName.pbData);
	if (pPubKeyInfo) lws_free(pPubKeyInfo);
	if (hKey) NCryptFreeObject(hKey);
	if (hProv) NCryptFreeObject(hProv);

	return ret < 0 ? -1 : ret;
}

int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *csr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
	return _lws_tls_acme_sni_csr_create(context, elements, csr, csr_len, privkey_pem, privkey_len, 0);
}

int
lws_tls_acme_sni_csr_create_ecdsa(struct lws_context *context, const char *elements[],
				  uint8_t *csr, size_t csr_len, char **privkey_pem,
				  size_t *privkey_len)
{
	return _lws_tls_acme_sni_csr_create(context, elements, csr, csr_len, privkey_pem, privkey_len, 1);
}
#endif

/*
 * Cert creation
 *
 * Keys are made ephemeral in the CNG software KSP and handed back as SEC1
 * (EC) or PKCS#1 (RSA) DER, the same as the other backends.  A CA key may come
 * as SEC1, PKCS#1 or PKCS#8 PEM.
 */

static const struct lws_schannel_curve {
	const char	*name;
	LPCWSTR		alg;
	LPCSTR		oid;
	ULONG		magic;
	DWORD		cb;
} lws_schannel_curves[] = {
	{ "P-256", NCRYPT_ECDSA_P256_ALGORITHM, szOID_ECC_CURVE_P256,
	  BCRYPT_ECDSA_PRIVATE_P256_MAGIC, 32 },
	{ "P-384", NCRYPT_ECDSA_P384_ALGORITHM, szOID_ECC_CURVE_P384,
	  BCRYPT_ECDSA_PRIVATE_P384_MAGIC, 48 },
	{ "P-521", NCRYPT_ECDSA_P521_ALGORITHM, szOID_ECC_CURVE_P521,
	  BCRYPT_ECDSA_PRIVATE_P521_MAGIC, 66 },
};

static const struct lws_schannel_curve *
lws_schannel_curve_by_name(const char *name)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(lws_schannel_curves); n++)
		if (!strcmp(lws_schannel_curves[n].name, name))
			return &lws_schannel_curves[n];

	return NULL;
}

static const struct lws_schannel_curve *
lws_schannel_curve_by_oid(const char *oid)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(lws_schannel_curves); n++)
		if (!strcmp(lws_schannel_curves[n].oid, oid))
			return &lws_schannel_curves[n];

	return NULL;
}

static NCRYPT_KEY_HANDLE
lws_schannel_gen_key(NCRYPT_PROV_HANDLE hProv,
		     const struct lws_schannel_curve *curve, int key_bits)
{
	DWORD pol = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
	      bits = (DWORD)(key_bits ? key_bits : 2048);
	NCRYPT_KEY_HANDLE hKey = 0;

	/* no name: an ephemeral key, nothing is left in the key store */
	if (NCryptCreatePersistedKey(hProv, &hKey, curve ? curve->alg :
				     NCRYPT_RSA_ALGORITHM, NULL, 0, 0) !=
							ERROR_SUCCESS)
		return 0;

	/* we hand the private key back, so it must be exportable */
	if (NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol,
			      sizeof(pol), 0) != ERROR_SUCCESS ||
	    (!curve && NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY,
					 (PBYTE)&bits, sizeof(bits), 0) !=
							ERROR_SUCCESS) ||
	    NCryptFinalizeKey(hKey, 0) != ERROR_SUCCESS) {
		NCryptFreeObject(hKey);
		return 0;
	}

	return hKey;
}

/* SEC1 ECPrivateKey DER -> BCRYPT_ECCPRIVATE_BLOB -> CNG key */

static NCRYPT_KEY_HANDLE
lws_schannel_import_sec1(NCRYPT_PROV_HANDLE hProv, const BYTE *der, DWORD len)
{
	const struct lws_schannel_curve *curve;
	CRYPT_ECC_PRIVATE_KEY_INFO *eki = NULL;
	BCRYPT_ECCKEY_BLOB *b = NULL;
	NCRYPT_KEY_HANDLE hKey = 0;
	DWORD cb = 0, blen = 0;
	BYTE *p;

	if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ECC_PRIVATE_KEY, der,
				 len, CRYPT_DECODE_ALLOC_FLAG, NULL, &eki, &cb))
		return 0;

	/*
	 * Standalone SEC1 has to name its curve, and CNG wants the public
	 * point too, which SEC1 makes optional
	 */

	if (!eki->szCurveOid ||
	    !(curve = lws_schannel_curve_by_oid(eki->szCurveOid)) ||
	    eki->PrivateKey.cbData > curve->cb ||
	    eki->PublicKey.cbData != 1 + 2 * curve->cb ||
	    eki->PublicKey.pbData[0] != 4) {
		lwsl_err("%s: unsupported EC key\n", __func__);
		goto bail;
	}

	blen = (DWORD)sizeof(*b) + 3 * curve->cb;
	b = lws_zalloc(blen, __func__);
	if (!b)
		goto bail;

	b->dwMagic = curve->magic;
	b->cbKey = curve->cb;
	p = (BYTE *)(b + 1);
	memcpy(p, eki->PublicKey.pbData + 1, 2 * curve->cb); /* X, Y */
	/* d left-padded to the coordinate size */
	memcpy(p + 3 * curve->cb - eki->PrivateKey.cbData,
	       eki->PrivateKey.pbData, eki->PrivateKey.cbData);

	if (NCryptImportKey(hProv, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, &hKey,
			    (PBYTE)b, blen, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
		hKey = 0;

bail:
	if (b) {
		lws_explicit_bzero(b, blen);
		lws_free(b);
	}
	if (eki) {
		lws_explicit_bzero(eki->PrivateKey.pbData,
				   eki->PrivateKey.cbData);
		LocalFree(eki);
	}

	return hKey;
}

/* PKCS#1 RSAPrivateKey DER -> CAPI private key blob -> CNG key */

static NCRYPT_KEY_HANDLE
lws_schannel_import_pkcs1(NCRYPT_PROV_HANDLE hProv, const BYTE *der, DWORD len)
{
	NCRYPT_KEY_HANDLE hKey = 0;
	BYTE *blob = NULL;
	DWORD cb = 0;

	if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, der,
				 len, CRYPT_DECODE_ALLOC_FLAG, NULL, &blob, &cb))
		return 0;

	if (NCryptImportKey(hProv, 0, LEGACY_RSAPRIVATE_BLOB, NULL, &hKey,
			    blob, cb, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
		hKey = 0;

	lws_explicit_bzero(blob, cb);
	LocalFree(blob);

	return hKey;
}

static NCRYPT_KEY_HANDLE
lws_schannel_import_key_pem(NCRYPT_PROV_HANDLE hProv, const char *pem)
{
	NCRYPT_KEY_HANDLE hKey = 0;
	CRYPT_PRIVATE_KEY_INFO *pki;
	DWORD len = 0, cb;
	size_t plen = strlen(pem);
	BYTE *der;

	if (!plen || plen > 65536 ||
	    !CryptStringToBinaryA(pem, (DWORD)plen, CRYPT_STRING_BASE64HEADER,
				  NULL, &len, NULL, NULL))
		return 0;

	der = lws_malloc(len, __func__);
	if (!der)
		return 0;

	if (!CryptStringToBinaryA(pem, (DWORD)plen, CRYPT_STRING_BASE64HEADER,
				  der, &len, NULL, NULL))
		goto bail;

	/* the three layouts are distinct, only the right decoder accepts it */

	if (CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, der,
				len, CRYPT_DECODE_ALLOC_FLAG, NULL, &pki, &cb)) {
		lws_explicit_bzero(pki, cb);
		LocalFree(pki);
		if (NCryptImportKey(hProv, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
				    NULL, &hKey, der, len, NCRYPT_SILENT_FLAG) !=
								ERROR_SUCCESS)
			hKey = 0;
	} else {
		hKey = lws_schannel_import_sec1(hProv, der, len);
		if (!hKey)
			hKey = lws_schannel_import_pkcs1(hProv, der, len);
	}

bail:
	lws_explicit_bzero(der, len);
	lws_free(der);

	return hKey;
}

static int
lws_schannel_export_key_der(NCRYPT_KEY_HANDLE hKey,
			    const struct lws_schannel_curve *curve,
			    uint8_t **out, size_t *out_len)
{
	CRYPT_ECC_PRIVATE_KEY_INFO eki;
	BYTE *blob = NULL, *pub = NULL;
	DWORD blen = 0, len = 0;
	BCRYPT_ECCKEY_BLOB *b;
	const void *what;
	LPCSTR type;
	int ret = 1;

	if (NCryptExportKey(hKey, 0, curve ? BCRYPT_ECCPRIVATE_BLOB :
						LEGACY_RSAPRIVATE_BLOB,
			    NULL, NULL, 0, &blen, NCRYPT_SILENT_FLAG) !=
								ERROR_SUCCESS)
		return 1;

	blob = lws_malloc(blen, __func__);
	if (!blob)
		return 1;

	if (NCryptExportKey(hKey, 0, curve ? BCRYPT_ECCPRIVATE_BLOB :
						LEGACY_RSAPRIVATE_BLOB,
			    NULL, blob, blen, &blen, NCRYPT_SILENT_FLAG) !=
								ERROR_SUCCESS)
		goto bail;

	if (curve) {
		/* the blob is the header, then X, Y and d */
		b = (BCRYPT_ECCKEY_BLOB *)blob;
		if (blen < sizeof(*b) || b->cbKey != curve->cb ||
		    blen < sizeof(*b) + 3 * curve->cb)
			goto bail;

		pub = lws_malloc(1 + 2 * curve->cb, __func__);
		if (!pub)
			goto bail;
		pub[0] = 4; /* uncompressed point */
		memcpy(pub + 1, b + 1, 2 * curve->cb);

		memset(&eki, 0, sizeof(eki));
		eki.dwVersion = CRYPT_ECC_PRIVATE_KEY_INFO_v1;
		eki.PrivateKey.cbData = curve->cb;
		eki.PrivateKey.pbData = (BYTE *)(b + 1) + 2 * curve->cb;
		eki.szCurveOid = (LPSTR)curve->oid;
		eki.PublicKey.cbData = 1 + 2 * curve->cb;
		eki.PublicKey.pbData = pub;

		type = X509_ECC_PRIVATE_KEY;
		what = &eki;
	} else {
		type = PKCS_RSA_PRIVATE_KEY;
		what = blob;
	}

	if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, what, 0, NULL, NULL,
				 &len))
		goto bail;

	/* the caller frees it with free(), as on the other backends */
	*out = malloc(len);
	if (!*out)
		goto bail;

	if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, what, 0, NULL, *out,
				 &len)) {
		free(*out);
		*out = NULL;
		goto bail;
	}

	*out_len = len;
	ret = 0;

bail:
	lws_free(pub);
	lws_explicit_bzero(blob, blen);
	lws_free(blob);

	return ret;
}

static int
lws_schannel_add_ext(CERT_EXTENSION *ext, LPCSTR oid, BOOL critical,
		     LPCSTR type, const void *what)
{
	ext->pszObjId = (LPSTR)oid;
	ext->fCritical = critical;

	return !CryptEncodeObjectEx(X509_ASN_ENCODING, type, what,
				    CRYPT_ENCODE_ALLOC_FLAG, NULL,
				    &ext->Value.pbData, &ext->Value.cbData);
}

int
lws_x509_create_cert(struct lws_context *context,
		     uint8_t **cert_buf, size_t *cert_len,
		     uint8_t **key_buf, size_t *key_len,
		     const struct lws_x509_cert_gen_info *info)
{
	LPSTR eku_oids[] = { szOID_PKIX_KP_SERVER_AUTH,
			     szOID_PKIX_KP_CLIENT_AUTH };
	NCRYPT_KEY_HANDLE hKey = 0, hCaKey = 0, hSign;
	const struct lws_schannel_curve *curve = NULL;
	CERT_BASIC_CONSTRAINTS2_INFO bc;
	struct lws_x509_cert *ca = NULL;
	CERT_PUBLIC_KEY_INFO *spki = NULL;
	CRYPT_ALGORITHM_IDENTIFIER sig;
	NCRYPT_PROV_HANDLE hProv = 0;
	CERT_EXTENSION ext[4];
	CERT_ALT_NAME_ENTRY ane;
	CERT_ALT_NAME_INFO ani;
	CERT_ENHKEY_USAGE eku;
	CERT_NAME_BLOB subject = { 0, NULL };
	CERT_NAME_INFO ni;
	CERT_RDN_ATTR attr;
	CRYPT_BIT_BLOB ku;
	WCHAR wsan[256], grp[32];
	DWORD cb = 0, n, ne = 0;
	ULARGE_INTEGER t;
	BYTE kub, serial[8];
	CERT_INFO ci;
	CERT_RDN rdn;
	uint8_t ip[16];
	int ipl = -1, ret = 1;
	size_t sl;

	(void)context;

	memset(ext, 0, sizeof(ext));

	if (!info || !info->san ||
	    (!info->ca_cert_pem != !info->ca_key_pem) ||
	    info->validity_days < 0 ||
	    info->validity_days > 100 * 366) /* keeps FILETIME math sane */
		return 1;

	/* 253 is the longest a DNS name can be */
	sl = strlen(info->san);
	if (!sl || sl > 253 ||
	    !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, info->san, -1,
				 wsan, (int)LWS_ARRAY_SIZE(wsan)))
		return 1;

	if (info->curve_name) {
		curve = lws_schannel_curve_by_name(info->curve_name);
		if (!curve) {
			lwsl_err("%s: unknown curve %s\n", __func__,
				 info->curve_name);
			return 1;
		}
	}

	if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0) !=
							ERROR_SUCCESS)
		return 1;

	hKey = lws_schannel_gen_key(hProv, curve, info->key_bits);
	if (!hKey) {
		lwsl_err("%s: key generation failed\n", __func__);
		goto bail;
	}
	hSign = hKey;

	if (info->ca_cert_pem) {
		if (lws_x509_create(&ca) ||
		    lws_x509_parse_from_pem(ca, info->ca_cert_pem,
					    strlen(info->ca_cert_pem) + 1)) {
			lwsl_err("%s: unable to parse CA cert\n", __func__);
			goto bail;
		}
		hCaKey = lws_schannel_import_key_pem(hProv, info->ca_key_pem);
		if (!hCaKey) {
			lwsl_err("%s: unable to import CA key\n", __func__);
			goto bail;
		}
		hSign = hCaKey;
	}

	/* the signature algorithm follows the signing key, not ours */
	if (NCryptGetProperty(hSign, NCRYPT_ALGORITHM_GROUP_PROPERTY,
			      (PBYTE)grp, (DWORD)(sizeof(grp) - sizeof(WCHAR)),
			      &cb, 0) != ERROR_SUCCESS)
		goto bail;
	grp[cb / sizeof(WCHAR)] = L'\0';
	memset(&sig, 0, sizeof(sig));
	if (!wcscmp(grp, NCRYPT_RSA_ALGORITHM_GROUP))
		sig.pszObjId = szOID_RSA_SHA256RSA;
	else if (!wcscmp(grp, NCRYPT_ECDSA_ALGORITHM_GROUP) ||
		 /* a PKCS#8 EC key may import as ECDH, it still signs */
		 !wcscmp(grp, NCRYPT_ECDH_ALGORITHM_GROUP))
		sig.pszObjId = szOID_ECDSA_SHA256;
	else
		goto bail;

	cb = 0;
	if (!CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING, NULL, &cb))
		goto bail;
	spki = lws_malloc(cb, __func__);
	if (!spki ||
	    !CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING, spki, &cb))
		goto bail;

	/* CN=san, as a UTF8String */
	attr.pszObjId = szOID_COMMON_NAME;
	attr.dwValueType = CERT_RDN_UTF8_STRING;
	attr.Value.cbData = 0; /* NUL-terminated wide string */
	attr.Value.pbData = (BYTE *)wsan;
	rdn.cRDNAttr = 1;
	rdn.rgRDNAttr = &attr;
	ni.cRDN = 1;
	ni.rgRDN = &rdn;
	if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_UNICODE_NAME, &ni,
				 CRYPT_ENCODE_ALLOC_FLAG, NULL, &subject.pbData,
				 &subject.cbData))
		goto bail;

	/* Extensions */

	memset(&bc, 0, sizeof(bc));
	bc.fCA = !!info->is_ca;
	if (lws_schannel_add_ext(&ext[ne++], szOID_BASIC_CONSTRAINTS2, TRUE,
				 X509_BASIC_CONSTRAINTS2, &bc))
		goto bail;

	kub = info->is_ca ? CERT_KEY_CERT_SIGN_KEY_USAGE |
			    CERT_CRL_SIGN_KEY_USAGE :
			    CERT_DIGITAL_SIGNATURE_KEY_USAGE |
			    CERT_KEY_ENCIPHERMENT_KEY_USAGE;
	ku.cbData = 1;
	ku.pbData = &kub;
	ku.cUnusedBits = 0;
	if (lws_schannel_add_ext(&ext[ne++], szOID_KEY_USAGE, TRUE,
				 X509_KEY_USAGE, &ku))
		goto bail;

	if (!info->is_ca) {
		/* a server cert is also usable as a client cert, as on openssl */
		eku.cUsageIdentifier = info->is_server ? 2 : 1;
		eku.rgpszUsageIdentifier = info->is_server ? eku_oids :
							     eku_oids + 1;
		if (lws_schannel_add_ext(&ext[ne++], szOID_ENHANCED_KEY_USAGE,
					 FALSE, X509_ENHANCED_KEY_USAGE, &eku))
			goto bail;
	}

	if (info->is_server) {
		memset(&ane, 0, sizeof(ane));
#if defined(LWS_WITH_NETWORK)
		ipl = lws_parse_numeric_address(info->san, ip, sizeof(ip));
#endif
		if (ipl == 4 || ipl == 16) {
			ane.dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
			ane.IPAddress.cbData = (DWORD)ipl;
			ane.IPAddress.pbData = ip;
		} else {
			ane.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
			ane.pwszDNSName = wsan;
		}
		ani.cAltEntry = 1;
		ani.rgAltEntry = &ane;
		if (lws_schannel_add_ext(&ext[ne++], szOID_SUBJECT_ALT_NAME2,
					 FALSE, X509_ALTERNATE_NAME, &ani)) {
			lwsl_err("%s: unable to add SAN\n", __func__);
			goto bail;
		}
	}

	memset(&ci, 0, sizeof(ci));
	ci.dwVersion = CERT_V3;

	/*
	 * CERT_INFO serials are little-endian: keep the last, most significant,
	 * byte positive and nonzero so it stays minimal DER
	 */
	if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, serial, sizeof(serial),
					    BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
		goto bail;
	serial[sizeof(serial) - 1] = (BYTE)((serial[sizeof(serial) - 1] &
					     0x7f) | 0x40);
	ci.SerialNumber.cbData = sizeof(serial);
	ci.SerialNumber.pbData = serial;

	ci.SignatureAlgorithm = sig;
	ci.Subject = subject;
	ci.Issuer = ca ? ca->cert->pCertInfo->Subject : subject;
	ci.SubjectPublicKeyInfo = *spki;

	/* valid from a day ago, so a peer's clock skew doesn't refuse it */
	GetSystemTimeAsFileTime(&ci.NotBefore);
	t.LowPart = ci.NotBefore.dwLowDateTime;
	t.HighPart = ci.NotBefore.dwHighDateTime;
	t.QuadPart -= 864000000000ull; /* one day in 100ns units */
	ci.NotBefore.dwLowDateTime = t.LowPart;
	ci.NotBefore.dwHighDateTime = t.HighPart;
	t.QuadPart += 864000000000ull * (ULONGLONG)(1 +
			(info->validity_days ? info->validity_days : 365));
	ci.NotAfter.dwLowDateTime = t.LowPart;
	ci.NotAfter.dwHighDateTime = t.HighPart;

	ci.cExtension = ne;
	ci.rgExtension = ext;

	cb = 0;
	if (!CryptSignAndEncodeCertificate(hSign, 0, X509_ASN_ENCODING,
					   X509_CERT_TO_BE_SIGNED, &ci, &sig,
					   NULL, NULL, &cb))
		goto bail;
	*cert_buf = malloc(cb);
	if (!*cert_buf)
		goto bail;
	if (!CryptSignAndEncodeCertificate(hSign, 0, X509_ASN_ENCODING,
					   X509_CERT_TO_BE_SIGNED, &ci, &sig,
					   NULL, *cert_buf, &cb) ||
	    lws_schannel_export_key_der(hKey, curve, key_buf, key_len)) {
		lwsl_err("%s: signing or key export failed 0x%x\n", __func__,
			 (unsigned int)GetLastError());
		free(*cert_buf);
		*cert_buf = NULL;
		goto bail;
	}
	*cert_len = cb;

	ret = 0;

bail:
	for (n = 0; n < LWS_ARRAY_SIZE(ext); n++)
		if (ext[n].Value.pbData)
			LocalFree(ext[n].Value.pbData);
	if (subject.pbData)
		LocalFree(subject.pbData);
	lws_free(spki);
	lws_x509_destroy(&ca);
	if (hCaKey)
		NCryptFreeObject(hCaKey);
	if (hKey)
		NCryptFreeObject(hKey);
	if (hProv)
		NCryptFreeObject(hProv);

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
