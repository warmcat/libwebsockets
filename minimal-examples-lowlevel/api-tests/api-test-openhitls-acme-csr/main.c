/*
 * lws-api-test-openhitls-acme-csr
 *
 * Focused OpenHiTLS ACME temporary certificate and CSR tests.
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS) && defined(LWS_WITH_ACME)

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

#include <crypt_eal_codecs.h>
#include <crypt_eal_init.h>
#include <hitls_cert_init.h>
#include <hitls_crypt_init.h>
#include <hitls_pki_csr.h>
#include <hitls_pki_utils.h>

static int
init_openhitls(void)
{
	int32_t ret;

	ret = BSL_ERR_Init();
	if (ret != BSL_SUCCESS) {
		lwsl_err("%s: BSL_ERR_Init failed: 0x%x\n", __func__, ret);
		return 1;
	}

	ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
	if (ret != CRYPT_SUCCESS) {
		lwsl_err("%s: CRYPT_EAL_Init failed: 0x%x\n", __func__, ret);
		return 1;
	}

	ret = HITLS_CertMethodInit();
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CertMethodInit failed: 0x%x\n", __func__,
			 ret);
		return 1;
	}
	HITLS_CryptMethodInit();

	return 0;
}

static int
contains_mem(const char *haystack, size_t haystack_len, const char *needle)
{
	size_t needle_len = strlen(needle), n;

	if (needle_len > haystack_len)
		return 0;

	for (n = 0; n <= haystack_len - needle_len; n++)
		if (!memcmp(haystack + n, needle, needle_len))
			return 1;

	return 0;
}

static int
b64url_to_der(const uint8_t *in, int in_len, uint8_t *out, int out_len)
{
	char b64[4096];
	int n, pad, i;

	if (in_len < 0 || (size_t)in_len + 4 > sizeof(b64))
		return -1;

	for (i = 0; i < in_len; i++) {
		if (in[i] == '-')
			b64[i] = '+';
		else
			if (in[i] == '_')
				b64[i] = '/';
			else
				b64[i] = (char)in[i];
	}

	pad = (4 - (in_len & 3)) & 3;
	for (n = 0; n < pad; n++)
		b64[i++] = '=';
	b64[i] = '\0';

	return lws_b64_decode_string_len(b64, i, (char *)out, out_len);
}

static int
test_temp_cert(void)
{
	struct lws_context context;
	struct lws_vhost vhost;
	union lws_tls_cert_info_results ir;
	int ret = 1;

	memset(&context, 0, sizeof(context));
	memset(&vhost, 0, sizeof(vhost));
	memset(&ir, 0, sizeof(ir));

	vhost.context = &context;
	vhost.tls.ssl_ctx = HITLS_CFG_NewTLSConfig();
	if (!vhost.tls.ssl_ctx) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);
		return 1;
	}

	if (lws_tls_acme_sni_cert_create(&vhost, "example.com",
					 "www.example.com")) {
		lwsl_err("%s: temp cert create failed\n", __func__);
		goto bail;
	}

	if (lws_tls_vhost_cert_info(&vhost, LWS_TLS_CERT_INFO_COMMON_NAME,
				    &ir, sizeof(ir.ns.name)) ||
	    strcmp(ir.ns.name, "temp.acme.invalid")) {
		lwsl_err("%s: unexpected temp cert CN '%s'\n", __func__,
			 ir.ns.name);
		goto bail;
	}

	/*
	 * The destroy helper is internal to the library; calling create again
	 * exercises the public path that first destroys any existing temp cert.
	 */
	if (lws_tls_acme_sni_cert_create(&vhost, "alt.example.com",
					 "alt2.example.com") ||
	    lws_tls_vhost_cert_info(&vhost, LWS_TLS_CERT_INFO_COMMON_NAME,
				    &ir, sizeof(ir.ns.name)) ||
	    strcmp(ir.ns.name, "temp.acme.invalid")) {
		lwsl_err("%s: temp cert recreate failed\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	HITLS_CFG_FreeConfig((HITLS_Config *)vhost.tls.ssl_ctx);

	return ret;
}

static int
test_csr(void)
{
	const char *elements[LWS_TLS_REQ_ELEMENT_COUNT];
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	HITLS_X509_Csr *parsed = NULL;
	HITLS_X509_Attrs *attrs = NULL;
	HITLS_X509_Ext *ext = NULL;
	HITLS_X509_ExtSan san;
	BslList *subject_dn = NULL;
	BSL_Buffer der, pem;
	uint8_t csr[4096], csr_der[4096];
	char *privkey_pem = NULL;
	size_t privkey_len = 0;
	int n, der_len, ret = 1;

	memset(elements, 0, sizeof(elements));
	memset(&san, 0, sizeof(san));
	memset(&der, 0, sizeof(der));
	memset(&pem, 0, sizeof(pem));

	elements[LWS_TLS_REQ_ELEMENT_COUNTRY] = "GB";
	elements[LWS_TLS_REQ_ELEMENT_STATE] = "State";
	elements[LWS_TLS_REQ_ELEMENT_LOCALITY] = "London";
	elements[LWS_TLS_REQ_ELEMENT_ORGANIZATION] = "Warmcat";
	elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME] = "example.com";
	elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME] = "www.example.com";
	elements[LWS_TLS_REQ_ELEMENT_EMAIL] = "admin@example.com";

	n = lws_tls_acme_sni_csr_create(NULL, elements, csr, sizeof(csr),
					&privkey_pem, &privkey_len);
	if (n <= 0 || !privkey_pem || !privkey_len) {
		lwsl_err("%s: csr create failed\n", __func__);
		goto bail;
	}

	pem.data = (uint8_t *)privkey_pem;
	pem.dataLen = (uint32_t)privkey_len;
	if (!contains_mem(privkey_pem, privkey_len, "BEGIN PRIVATE KEY") ||
	    CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM,
				    CRYPT_PRIKEY_PKCS8_UNENCRYPT, &pem,
				    NULL, 0, &pkey) != CRYPT_SUCCESS) {
		lwsl_err("%s: private key PEM did not parse\n", __func__);
		goto bail;
	}

	der_len = b64url_to_der(csr, n, csr_der, sizeof(csr_der));
	if (der_len <= 0) {
		lwsl_err("%s: CSR b64url decode failed\n", __func__);
		goto bail;
	}

	der.data = csr_der;
	der.dataLen = (uint32_t)der_len;
	if (HITLS_X509_CsrParseBuff(BSL_FORMAT_ASN1, &der, &parsed) !=
								HITLS_PKI_SUCCESS) {
		lwsl_err("%s: CSR parse failed\n", __func__);
		goto bail;
	}

	if (HITLS_X509_CsrVerify(parsed) != HITLS_PKI_SUCCESS) {
		lwsl_err("%s: CSR verify failed\n", __func__);
		goto bail;
	}

	if (HITLS_X509_CsrCtrl(parsed, HITLS_X509_GET_SUBJECT_DN,
			       &subject_dn, sizeof(subject_dn)) !=
								HITLS_PKI_SUCCESS) {
		lwsl_err("%s: CSR subject DN read failed\n", __func__);
		goto bail;
	}

	if (BSL_LIST_COUNT(subject_dn) < 5) {
		lwsl_err("%s: CSR subject DN count too small\n", __func__);
		goto bail;
	}

	if (HITLS_X509_CsrCtrl(parsed, HITLS_X509_CSR_GET_ATTRIBUTES,
			       &attrs, sizeof(attrs)) != HITLS_PKI_SUCCESS ||
	    HITLS_X509_AttrCtrl(attrs,
				HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS,
				&ext, sizeof(ext)) != HITLS_PKI_SUCCESS ||
	    HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_GET_SAN, &san,
			       sizeof(san)) != HITLS_PKI_SUCCESS ||
	    BSL_LIST_COUNT(san.names) != 2) {
		lwsl_err("%s: CSR SAN extension missing\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	BSL_LIST_FREE(san.names, NULL);
	HITLS_X509_ExtFree(ext);
	HITLS_X509_CsrFree(parsed);
	CRYPT_EAL_PkeyFreeCtx(pkey);
	free(privkey_pem);

	return ret;
}

static int
test_failure_paths(void)
{
	const char *elements[LWS_TLS_REQ_ELEMENT_COUNT];
	uint8_t csr[8];
	char *privkey_pem = (char *)1;
	size_t privkey_len = 123;

	memset(elements, 0, sizeof(elements));
	elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME] = "example.com";

	if (lws_tls_acme_sni_csr_create(NULL, elements, csr, sizeof(csr),
					&privkey_pem, &privkey_len) >= 0) {
		lwsl_err("%s: tiny CSR buffer unexpectedly succeeded\n",
			 __func__);
		return 1;
	}

	if (privkey_pem || privkey_len) {
		lwsl_err("%s: failure path left private key output set\n",
			 __func__);
		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int e = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: OpenHiTLS ACME CSR\n");

	if (init_openhitls())
		e = 1;
	else {
		e |= test_temp_cert();
		e |= test_csr();
		e |= test_failure_paths();
	}

	if (e)
		lwsl_err("%s: failed\n", __func__);
	else
		lwsl_user("%s: pass\n", __func__);

	return e;
}

#else

int
main(void)
{
	return 0;
}

#endif
