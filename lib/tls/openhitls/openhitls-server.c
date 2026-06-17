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
 * openHiTLS TLS server implementation
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"
#include <hitls_cert.h>
#include <hitls_pki_cert.h>
#include <hitls_pki_csr.h>
#include <hitls_pki_utils.h>
#include <crypt_eal_codecs.h>
#include <crypt_eal_rand.h>
#include <crypt_params_key.h>
#include <bsl_sal.h>
#include <time.h>

static void
lws_openhitls_log_error_string(const char *prefix, const char *subject,
			       int32_t ret)
{
	const char *file = NULL;
	const char *s;
	uint32_t line = 0;
	int32_t err;

	err = BSL_ERR_PeekErrorFileLine(&file, &line);
	if (!err) {
		err = ret;
	}

	s = BSL_ERR_GetString(err);
	lwsl_err("%s '%s' 0x%x: %s\n", prefix, subject ? subject : "?",
		 (unsigned int)err, (s && *s) ? s : "unknown");
}

/*
 * openHiTLS verify callback return convention:
 *   return 0 = OK / accept
 *   return non-zero = reject / propagate error
 *
 * The first argument behaves like the client-side callback: it is a verify
 * code where 0 means verification passed.  Normalize it to the OpenSSL-style
 * boolean expected by LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION.
 */
static int
OpenHiTLS_verify_callback(int32_t verify_code, HITLS_CERT_StoreCtx *store_ctx)
{
	void *userdata = NULL;
	struct lws *wsi;
	lws_tls_conn *ssl;
	const struct lws_protocols *lp;
	HITLS_X509_Cert *topcert = NULL;
	union lws_tls_cert_info_results ir;
	int internal_allow = !verify_code;
	int n;

	HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
					HITLS_X509_STORECTX_GET_USR_DATA,
					&userdata,
					(uint32_t)sizeof(userdata));

	ssl = (lws_tls_conn *)userdata;
	wsi = ssl ? (struct lws *)HITLS_GetUserData((HITLS_Ctx *)ssl) : NULL;
	ssl = wsi ? wsi->tls.ssl : NULL;

	if (!wsi) {
		return 1;
	}

	if (!HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
				     HITLS_X509_STORECTX_GET_CUR_CERT,
				     &topcert, sizeof(topcert)) &&
	    topcert &&
	    !lws_tls_openhitls_cert_info(topcert, LWS_TLS_CERT_INFO_COMMON_NAME,
					 &ir, sizeof(ir.ns.name))) {
		lwsl_info("%s: client cert CN '%s'\n", __func__, ir.ns.name);
	}
	else
		lwsl_info("%s: couldn't get client cert CN\n", __func__);

	lp = &wsi->a.vhost->protocols[0];
	n = lp->callback(wsi,
			 LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
			 store_ctx, ssl, (unsigned int)internal_allow);

	return n;
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	lws_tls_ctx *ctx;

	if (!vh || !vh->tls.ssl_ctx) {
		return -1;
	}

	ctx = (lws_tls_ctx *)vh->tls.ssl_ctx;

	if (!lws_check_opt(vh->options,
			   LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT)) {
		return 0;
	}

	if (HITLS_CFG_SetClientVerifySupport(ctx, true) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetClientVerifySupport failed\n",
			 __func__);
		return -1;
	}

	if (HITLS_CFG_SetNoClientCertSupport(ctx,
			lws_check_opt(vh->options,
				      LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetNoClientCertSupport failed\n",
			 __func__);
		return -1;
	}

	if (HITLS_CFG_SetSessionIdCtx(ctx,
				      (const uint8_t *)vh->context,
				      sizeof(void *)) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetSessionIdCtx failed\n", __func__);
		return -1;
	}

	if (HITLS_CFG_SetVerifyCb(ctx, OpenHiTLS_verify_callback)
			!= HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_SetVerifyCb failed\n", __func__);
		return -1;
	}

	return 0;
}

static int32_t
lws_ssl_server_name_cb(HITLS_Ctx *ssl, int *alert, void *arg)
{
	struct lws_context *context = (struct lws_context *)arg;
	struct lws_vhost *vhost, *vh;
	lws_tls_ctx *target_ctx;
	const char *servername;

	(void)alert;

	if (!ssl) {
		return HITLS_ACCEPT_SNI_ERR_NOACK;
	}

	vh = context->vhost_list;
	while (vh) {
		lws_tls_ctx *ctx = (lws_tls_ctx *)vh->tls.ssl_ctx;

		if (!vh->being_destroyed && ctx && ctx == HITLS_GetGlobalConfig(ssl)) {
			break;
		}
		vh = vh->vhost_next;
	}

	if (!vh) {
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

	servername = HITLS_GetServerName(ssl, HITLS_SNI_HOSTNAME_TYPE);
	if (!servername) {
		lwsl_info("SNI: Unknown ServerName\n");
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

	vhost = lws_select_vhost(context, vh->listen_port, servername);
	if (!vhost) {
		lwsl_info("SNI: none: %s:%d\n", servername, vh->listen_port);
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

	target_ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	if (!target_ctx) {
		return HITLS_ACCEPT_SNI_ERR_OK;
	}

	if (!HITLS_SetNewConfig(ssl, target_ctx)) {
		return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
	}

	lwsl_info("SNI: Found: %s:%d\n", servername, vh->listen_port);

	return HITLS_ACCEPT_SNI_ERR_OK;
}

/*
 * this may now get called after the vhost creation, when certs become
 * available.
 */
int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t mem_cert_len,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	lws_tls_ctx *ctx;
	HITLS_Config *config;
	lws_filepos_t flen;
	uint8_t *der_buf = NULL;
	int n, ret;

	(void)wsi;

	n = (int)lws_tls_generic_cert_checks(vhost, cert, private_key);

	if (!cert && !private_key) {
		n = LWS_TLS_EXTANT_ALTERNATIVE;
	}

	if (n == LWS_TLS_EXTANT_NO && (!mem_cert || !mem_privkey)) {
		return 0;
	}
	if (n == LWS_TLS_EXTANT_NO) {
		n = LWS_TLS_EXTANT_ALTERNATIVE;
	}

	if (n == LWS_TLS_EXTANT_ALTERNATIVE && (!mem_cert || !mem_privkey)) {
		return 1;
	} /* no alternative */

	if (n == LWS_TLS_EXTANT_ALTERNATIVE) {
		/*
		 * Although we have prepared update certs, we no longer have
		 * the rights to read our own cert + key we saved.
		 *
		 * If we were passed copies in memory buffers, use those
		 * in favour of the filepaths we normally want.
		 */
		cert = NULL;
		private_key = NULL;
	}

	/*
	 * use the multi-cert interface for backwards compatibility in the
	 * both simple files case
	 */

	if (n != LWS_TLS_EXTANT_ALTERNATIVE && cert) {
		int m;

		if (!vhost->tls.ssl_ctx) {
			return 1;
		}

		ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
		config = ctx;
		if (!config) {
			return 1;
		}

		/* Prefer chain-file semantics to match the OpenSSL server path. */
		m = HITLS_CFG_UseCertificateChainFile(config, cert);
		if (m != HITLS_SUCCESS) {
			lws_openhitls_log_error_string("problem getting cert",
						       cert, m);

			return 1;
		}

		if (!private_key) {
			lwsl_err("ssl private key not set\n");
			return 1;
		} else {
			/* set the private key from KeyFile */
			ret = HITLS_CFG_LoadKeyFile(config, private_key,
						    TLS_PARSE_FORMAT_PEM);
			if (ret != HITLS_SUCCESS) {
				lws_openhitls_log_error_string("ssl problem getting key",
						       private_key, ret);
				return 1;
			}
		}

		return 0;
	}

	/* Match the client path: normalize memory PEM/DER into DER, then load ASN.1. */

	if (!vhost->tls.ssl_ctx) {
		return 1;
	}

	ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;
	config = ctx;
	if (!config) {
		return 1;
	}

	if (lws_tls_alloc_pem_to_der_file(vhost->context, NULL, mem_cert,
					  (lws_filepos_t)mem_cert_len, &der_buf,
					  &flen)) {
		lwsl_err("%s: couldn't read cert file\n", __func__);

		return 1;
	}
	ret = HITLS_CFG_LoadCertBuffer(config, der_buf, (uint32_t)flen,
				       TLS_PARSE_FORMAT_ASN1);
	if (ret != HITLS_SUCCESS) {
		lws_free_set_NULL(der_buf);
		lws_openhitls_log_error_string("couldn't read cert file",
					       "memory", ret);
		lws_tls_err_describe_clear();

		return 1;
	}
	lws_free_set_NULL(der_buf);

	if (lws_tls_alloc_pem_to_der_file(vhost->context, NULL, mem_privkey,
					  (lws_filepos_t)mem_privkey_len,
					  &der_buf, &flen)) {
		lwsl_notice("unable to convert memory privkey\n");

		return 1;
	}
	ret = HITLS_CFG_LoadKeyBuffer(config, der_buf, (uint32_t)flen,
				      TLS_PARSE_FORMAT_ASN1);
	if (ret != HITLS_SUCCESS) {
		lws_free_set_NULL(der_buf);
		lws_openhitls_log_error_string("unable to convert memory privkey",
					       "memory", ret);

		return 1;
	}
	lws_free_set_NULL(der_buf);

	/* verify private key */
	ret = HITLS_CFG_CheckPrivateKey(config);
	if (ret != HITLS_SUCCESS) {
		lws_openhitls_log_error_string("Private SSL key doesn't match cert",
					       "memory", ret);

		return 1;
	}

	vhost->tls.skipped_certs = 0;

	return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	lws_tls_ctx *ctx;
	HITLS_Config *config;
	int ret;

	(void)wsi;

	config = HITLS_CFG_NewTLSConfig();
	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);
		return 1;
	}

	if (lws_openhitls_apply_tls_version_by_ssl_options(
			config, info->ssl_options_set,
			info->ssl_options_clear, __func__)) {
		lwsl_err("%s: unable to apply server TLS version options\n",
			 __func__);
		HITLS_CFG_FreeConfig(config);
		return 1;
	}

	ctx = config;
	/* Assign ctx to vhost immediately, so vhost destruction handles cleanup */
	vhost->tls.ssl_ctx = ctx;

#if defined(LWS_WITH_TLS_KEYLOG) && defined(LWS_WITH_TLS) && \
		(!defined(LWS_WITHOUT_CLIENT) || !defined(LWS_WITHOUT_SERVER))
	if (vhost->context->keylog_file[0])
		HITLS_CFG_SetKeyLogCb(config, lws_openhitls_klog_dump);
#endif

	HITLS_CFG_SetConfigUserData(config, vhost->context);

	if (lws_check_opt(info->options,
			  LWS_SERVER_OPTION_OPENSSL_AUTO_DH_PARAMETERS))
		HITLS_CFG_SetDhAutoSupport(config, true);

	HITLS_CFG_SetCipherServerPreference(config, true);

	HITLS_CFG_SetModeSupport(config,
				       HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				       HITLS_MODE_RELEASE_BUFFERS);

	if (info->tls_ciphers_iana && info->tls_ciphers_iana[0]) {
		ret = lws_openhitls_apply_cipher_suites(
			config, info->tls_ciphers_iana, __func__);
		if (ret) {
			lwsl_err("%s: no valid IANA cipher from '%s'\n",
				 __func__, info->tls_ciphers_iana);
			return 1;
		}
	} else if (info->ssl_cipher_list || info->tls1_3_plus_cipher_list) {
		lwsl_info("%s: openHiTLS ignores OpenSSL cipher-list fields; "
			  "use tls_ciphers_iana\n", __func__);
	}

	HITLS_CFG_SetServerNameCb(config, lws_ssl_server_name_cb);
	HITLS_CFG_SetServerNameArg(config, vhost->context);

	if (info->ssl_ca_filepath &&
	    HITLS_CFG_LoadVerifyFile(config, info->ssl_ca_filepath) !=
			    HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_LoadVerifyFile unhappy\n",
			 __func__);
	}

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem)) {
		return 0;
	}

	lws_ssl_bind_passphrase(ctx, 0, info);

	return lws_tls_server_certs_load(vhost, wsi, info->ssl_cert_filepath,
					 info->ssl_private_key_filepath,
					 info->server_ssl_cert_mem,
					 info->server_ssl_cert_mem_len,
					 info->server_ssl_private_key_mem,
					 info->server_ssl_private_key_mem_len);
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	lws_tls_ctx *vhost_ctx;
	HITLS_Ctx *ssl;
	BSL_UIO *uio;

	if (!wsi->a.vhost || !wsi->a.vhost->tls.ssl_ctx) {
		lwsl_err("%s: no vhost or ssl_ctx\n", __func__);
		return 1;
	}

	vhost_ctx = (lws_tls_ctx *)wsi->a.vhost->tls.ssl_ctx;

	/* Create new SSL connection from vhost's config */
	ssl = HITLS_New(vhost_ctx);
	if (!ssl) {
		lwsl_err("%s: HITLS_New failed\n", __func__);
		return 1;
	}

	HITLS_SetUserData(ssl, wsi);

	/* Create and attach BSL_UIO for I/O (TCP socket) */
	uio = BSL_UIO_New(BSL_UIO_TcpMethod());
	if (!uio) {
		lwsl_err("%s: BSL_UIO_New failed\n", __func__);
		HITLS_Free(ssl);
		return 1;
	}

	BSL_UIO_SetFD(uio, (int)wsi->desc.sockfd);

	/* Set non-blocking mode */
	BSL_UIO_Ctrl(uio, BSL_UIO_SET_NOBLOCK, 1, NULL);

	HITLS_SetUio(ssl, uio);

	HITLS_SetModeSupport(ssl,
			     HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			     HITLS_MODE_RELEASE_BUFFERS);

	wsi->tls.ssl = ssl;
	if (wsi->a.vhost->tls.ssl_info_event_mask)
		HITLS_SetInfoCb(ssl, lws_ssl_info_callback);
	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	BSL_UIO *uio = NULL;

	/*
	 * HITLS_Close() (called from __lws_tls_shutdown) has been observed to
	 * corrupt heap metadata.  Skip it; HITLS_Free() handles full cleanup.
	 */
	uio = HITLS_GetUio(wsi->tls.ssl);
	if (uio) {
		BSL_UIO_SetFD(uio, -1);
	}
	HITLS_Free(wsi->tls.ssl);
	wsi->tls.ssl = NULL;

	return LWS_SSL_CAPABLE_DONE;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	union lws_tls_cert_info_results ir;
	int ret;

	ret = HITLS_Accept(wsi->tls.ssl);

	wsi->skip_fallback = 1;

	if (ret == HITLS_SUCCESS) {

		if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, &ir,
						   sizeof(ir.ns.name))) {
			lwsl_notice("%s: client cert CN '%s'\n", __func__,
							    ir.ns.name);
		}
		else
			lwsl_info("%s: no client cert CN\n", __func__);

		lws_openhitls_describe_cipher(wsi);

		if (HITLS_GetReadPendingBytes(wsi->tls.ssl) &&
		    lws_dll2_is_detached(&wsi->tls.dll_pending_tls)) {
			lws_dll2_add_head(&wsi->tls.dll_pending_tls,
								  &pt->tls.dll_pending_tls_owner);
		}

		return LWS_SSL_CAPABLE_DONE;
	}

	lwsl_debug("%s: HITLS_Accept returned 0x%x\n", __func__, ret);
	ret = lws_ssl_get_error(wsi, ret);

	if (ret == HITLS_ERR_TLS || ret == HITLS_ERR_SYSCALL) {
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (ret == HITLS_WANT_READ) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		lwsl_info("SSL_ERROR_WANT_READ: ret %d\n", ret);
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
	if (ret == HITLS_WANT_WRITE) {
		lwsl_debug("%s: WANT_WRITE\n", __func__);

		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

#if defined(LWS_WITH_ACME)

struct lws_tls_ss_pieces {
	HITLS_X509_Cert *cert;
	CRYPT_EAL_PkeyCtx *pkey;
};

static int
lws_openhitls_rand_init(void)
{
	int32_t ret;

	ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
	if (ret == CRYPT_SUCCESS || ret == CRYPT_EAL_ERR_DRBG_REPEAT_INIT)
		return 0;

	lwsl_notice("%s: CRYPT_EAL_RandInit failed: 0x%x\n", __func__, ret);

	return 1;
}

static CRYPT_EAL_PkeyCtx *
lws_openhitls_rsa_new_key(void)
{
	uint8_t e[] = { 1, 0, 1 };
	CRYPT_EAL_PkeyPara para;
	CRYPT_EAL_PkeyCtx *pkey;
	int bits = lws_plat_recommended_rsa_bits();

	if (lws_openhitls_rand_init())
		return NULL;

	memset(&para, 0, sizeof(para));
	para.id = CRYPT_PKEY_RSA;
	para.para.rsaPara.e = e;
	para.para.rsaPara.eLen = sizeof(e);
	para.para.rsaPara.bits = (uint32_t)bits;

	pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
	if (!pkey)
		return NULL;

	if (CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS &&
	    CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS)
		return pkey;

	CRYPT_EAL_PkeyFreeCtx(pkey);

	return NULL;
}

static int
lws_openhitls_add_dn(BslList *dn, BslCid cid, const char *value)
{
	HITLS_X509_DN name;

	if (!value || !value[0])
		value = "none";

	memset(&name, 0, sizeof(name));
	name.cid = cid;
	name.data = (uint8_t *)value;
	name.dataLen = (uint32_t)strlen(value);

	return HITLS_X509_AddDnName(dn, &name, 1) != HITLS_PKI_SUCCESS;
}

static BslList *
lws_openhitls_new_acme_dn(void)
{
	BslList *dn;

	dn = HITLS_X509_DnListNew();
	if (!dn)
		return NULL;

	if (lws_openhitls_add_dn(dn, BSL_CID_AT_COUNTRYNAME, "GB") ||
	    lws_openhitls_add_dn(dn, BSL_CID_AT_ORGANIZATIONNAME,
				 "somecompany") ||
	    lws_openhitls_add_dn(dn, BSL_CID_AT_COMMONNAME,
				 "temp.acme.invalid")) {
		HITLS_X509_DnListFree(dn);
		return NULL;
	}

	return dn;
}

static void
lws_openhitls_free_san(HITLS_X509_ExtSan *san)
{
	if (san->names)
		BSL_LIST_FREE(san->names,
			      (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
	memset(san, 0, sizeof(*san));
}

static int
lws_openhitls_add_san_name(HITLS_X509_ExtSan *san, const char *name)
{
	HITLS_X509_GeneralName *gn;
	uint32_t len;

	if (!name || !name[0])
		return 0;

	len = (uint32_t)strlen(name);
	gn = BSL_SAL_Calloc(1, sizeof(*gn));
	if (!gn)
		return 1;

	gn->type = HITLS_X509_GN_DNS;
	gn->value.data = BSL_SAL_Dump(name, len);
	gn->value.dataLen = len;
	if (!gn->value.data ||
	    BSL_LIST_AddElement(san->names, gn, BSL_LIST_POS_END) !=
								BSL_SUCCESS) {
		HITLS_X509_FreeGeneralName(gn);
		return 1;
	}

	return 0;
}

static int
lws_openhitls_prepare_san(HITLS_X509_ExtSan *san, const char *san_a,
			  const char *san_b)
{
	memset(san, 0, sizeof(*san));
	san->names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
	if (!san->names)
		return 1;

	if (lws_openhitls_add_san_name(san, san_a) ||
	    lws_openhitls_add_san_name(san, san_b)) {
		lws_openhitls_free_san(san);
		return 1;
	}

	if (!BSL_LIST_COUNT(san->names)) {
		lws_openhitls_free_san(san);
		return 1;
	}

	return 0;
}

static int
lws_openhitls_b64url(const uint8_t *in, size_t in_len, uint8_t *out,
		     size_t out_len)
{
	int n;

	if (!out_len)
		return -1;

	n = lws_b64_encode_string_url((const char *)in, (int)in_len,
				      (char *)out, (int)out_len);
	if (n < 0)
		return -1;

	while (n && out[n - 1] == '=')
		n--;

	out[n] = '\0';

	return n;
}

int
lws_tls_acme_sni_cert_create(struct lws_vhost *vhost, const char *san_a,
			     const char *san_b)
{
	BSL_Buffer cert_der = { 0 }, key_der = { 0 };
	HITLS_X509_ExtSan san;
	HITLS_Config *config;
	BslList *dn = NULL;
	BSL_TIME before, after;
	uint8_t serial[] = { 1 };
	int32_t ret, version = HITLS_X509_VERSION_3;
	time_t now;

	if (!vhost || !vhost->tls.ssl_ctx || !san_a || !san_a[0])
		return 1;

	lws_tls_acme_sni_cert_destroy(vhost);

	vhost->tls.ss = lws_zalloc(sizeof(*vhost->tls.ss), "sni cert");
	if (!vhost->tls.ss)
		return 1;

	vhost->tls.ss->pkey = lws_openhitls_rsa_new_key();
	vhost->tls.ss->cert = HITLS_X509_CertNew();
	if (!vhost->tls.ss->pkey || !vhost->tls.ss->cert)
		goto bail;

	dn = lws_openhitls_new_acme_dn();
	if (!dn)
		goto bail;

	now = time(NULL);
	if (now == (time_t)-1 ||
	    BSL_SAL_UtcTimeToDateConvert((int64_t)now, &before) !=
								BSL_SUCCESS ||
	    BSL_SAL_UtcTimeToDateConvert((int64_t)now + 3600, &after) !=
								BSL_SUCCESS)
		goto bail;

	ret = HITLS_X509_CertCtrl(vhost->tls.ss->cert, HITLS_X509_SET_VERSION,
				  &version, sizeof(version));
	ret |= HITLS_X509_CertCtrl(vhost->tls.ss->cert,
				   HITLS_X509_SET_SERIALNUM, serial,
				   sizeof(serial));
	ret |= HITLS_X509_CertCtrl(vhost->tls.ss->cert,
				   HITLS_X509_SET_BEFORE_TIME, &before,
				   sizeof(before));
	ret |= HITLS_X509_CertCtrl(vhost->tls.ss->cert,
				   HITLS_X509_SET_AFTER_TIME, &after,
				   sizeof(after));
	ret |= HITLS_X509_CertCtrl(vhost->tls.ss->cert, HITLS_X509_SET_PUBKEY,
				   vhost->tls.ss->pkey, 0);
	ret |= HITLS_X509_CertCtrl(vhost->tls.ss->cert,
				   HITLS_X509_SET_SUBJECT_DN, dn,
				   sizeof(*dn));
	ret |= HITLS_X509_CertCtrl(vhost->tls.ss->cert,
				   HITLS_X509_SET_ISSUER_DN, dn,
				   sizeof(*dn));
	if (ret)
		goto bail;

	/*
	 * openHiTLS PKI copies ctrl payloads into the cert; the temporary DN
	 * and SAN lists remain caller-owned and must be freed after ctrl.
	 */
	if (lws_openhitls_prepare_san(&san, san_a, san_b))
		goto bail;
	ret = HITLS_X509_CertCtrl(vhost->tls.ss->cert, HITLS_X509_EXT_SET_SAN,
				  &san, sizeof(san));
	lws_openhitls_free_san(&san);
	if (ret != HITLS_PKI_SUCCESS)
		goto bail;

	if (HITLS_X509_CertSign(CRYPT_MD_SHA256, vhost->tls.ss->pkey, NULL,
				vhost->tls.ss->cert) != HITLS_PKI_SUCCESS ||
	    HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, vhost->tls.ss->cert,
				   &cert_der) != HITLS_PKI_SUCCESS ||
	    CRYPT_EAL_EncodeBuffKey(vhost->tls.ss->pkey, NULL,
				    BSL_FORMAT_ASN1,
				    CRYPT_PRIKEY_PKCS8_UNENCRYPT,
				    &key_der) != CRYPT_SUCCESS)
		goto bail;

	config = (HITLS_Config *)vhost->tls.ssl_ctx;
	ret = HITLS_CFG_LoadCertBuffer(config, cert_der.data,
				       cert_der.dataLen,
				       TLS_PARSE_FORMAT_ASN1);
	if (ret == HITLS_SUCCESS)
		ret = HITLS_CFG_LoadKeyBuffer(config, key_der.data,
					      key_der.dataLen,
					      TLS_PARSE_FORMAT_ASN1);
	if (ret == HITLS_SUCCESS)
		ret = HITLS_CFG_CheckPrivateKey(config);

	BSL_SAL_FREE(cert_der.data);
	BSL_SAL_FREE(key_der.data);
	HITLS_X509_DnListFree(dn);
	if (ret != HITLS_SUCCESS)
		lws_tls_acme_sni_cert_destroy(vhost);

	return ret != HITLS_SUCCESS;

bail:
	BSL_SAL_FREE(cert_der.data);
	BSL_SAL_FREE(key_der.data);
	if (dn)
		HITLS_X509_DnListFree(dn);
	lws_tls_acme_sni_cert_destroy(vhost);
	return 1;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
	if (!vhost || !vhost->tls.ss)
		return;

	HITLS_X509_CertFree(vhost->tls.ss->cert);
	CRYPT_EAL_PkeyFreeCtx(vhost->tls.ss->pkey);
	lws_free_set_NULL(vhost->tls.ss);
}

static int
lws_openhitls_csr_add_subject(const char *elements[], HITLS_X509_Csr *csr)
{
	static const BslCid dn_cid[LWS_TLS_REQ_ELEMENT_COUNT] = {
		BSL_CID_AT_COUNTRYNAME,
		BSL_CID_AT_STATEORPROVINCENAME,
		BSL_CID_AT_LOCALITYNAME,
		BSL_CID_AT_ORGANIZATIONNAME,
		BSL_CID_AT_COMMONNAME,
		BSL_CID_UNKNOWN,
		BSL_CID_UNKNOWN
	};
	HITLS_X509_DN dn;
	int n;

	memset(&dn, 0, sizeof(dn));

	for (n = 0; n < LWS_TLS_REQ_ELEMENT_COUNT; n++) {
		if (dn_cid[n] == BSL_CID_UNKNOWN || !elements[n]) {
			if (n == LWS_TLS_REQ_ELEMENT_EMAIL && elements[n])
				lwsl_debug("%s: openHiTLS PKI omits email DN\n",
					   __func__);
			continue;
		}

		dn.cid = dn_cid[n];
		dn.data = (uint8_t *)(elements[n][0] ? elements[n] : "none");
		dn.dataLen = (uint32_t)strlen((const char *)dn.data);
		if (HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME,
				       &dn, 1) != HITLS_PKI_SUCCESS) {
			lwsl_notice("%s: failed to add CSR subject element %d\n",
				    __func__, n);
			return 1;
		}
	}

	return 0;
}

static int
lws_openhitls_csr_add_san(const char *elements[], HITLS_X509_Csr *csr)
{
	HITLS_X509_Attrs *attrs = NULL;
	HITLS_X509_Ext *ext = NULL;
	HITLS_X509_ExtSan san;
	int ret = 1;

	if (!elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME])
		return 0;

	if (lws_openhitls_prepare_san(&san,
			elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME],
			elements[LWS_TLS_REQ_ELEMENT_SUBJECT_ALT_NAME]))
		return 1;

	ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
	if (!ext)
		goto bail;

	if (HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san,
			       sizeof(san)) != HITLS_PKI_SUCCESS ||
	    HITLS_X509_CsrCtrl(csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs,
			       sizeof(attrs)) != HITLS_PKI_SUCCESS ||
	    HITLS_X509_AttrCtrl(attrs,
				HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS,
				ext, 0) != HITLS_PKI_SUCCESS)
		goto bail;

	ret = 0;

bail:
	HITLS_X509_ExtFree(ext);
	lws_openhitls_free_san(&san);

	return ret;
}

int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *csr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
	BSL_Buffer csr_der = { 0 }, key_pem = { 0 };
	CRYPT_EAL_PkeyCtx *pkey = NULL;
	HITLS_X509_Csr *req = NULL;
	int n, ret = -1;

	(void)context;

	if (!elements || !csr || !csr_len || !privkey_pem || !privkey_len)
		return -1;

	*privkey_pem = NULL;
	*privkey_len = 0;

	pkey = lws_openhitls_rsa_new_key();
	req = HITLS_X509_CsrNew();
	if (!pkey || !req) {
		lwsl_notice("%s: unable to allocate key or CSR\n", __func__);
		goto bail;
	}

	if (HITLS_X509_CsrCtrl(req, HITLS_X509_SET_PUBKEY, pkey, 0) !=
								HITLS_PKI_SUCCESS) {
		lws_openhitls_log_error_string("unable to set CSR public key",
					       __func__, HITLS_PKI_SUCCESS);
		goto bail;
	}
	if (lws_openhitls_csr_add_subject(elements, req)) {
		lws_openhitls_log_error_string("unable to set CSR subject",
					       __func__, HITLS_PKI_SUCCESS);
		goto bail;
	}
	if (lws_openhitls_csr_add_san(elements, req)) {
		lws_openhitls_log_error_string("unable to set CSR SAN",
					       __func__, HITLS_PKI_SUCCESS);
		goto bail;
	}
	if (HITLS_X509_CsrSign(CRYPT_MD_SHA256, pkey, NULL, req) !=
							HITLS_PKI_SUCCESS) {
		lws_openhitls_log_error_string("unable to sign CSR", __func__,
					       HITLS_PKI_SUCCESS);
		goto bail;
	}
	if (HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1, req, &csr_der) !=
								HITLS_PKI_SUCCESS) {
		lws_openhitls_log_error_string("unable to encode CSR", __func__,
					       HITLS_PKI_SUCCESS);
		goto bail;
	}

	n = lws_openhitls_b64url(csr_der.data, csr_der.dataLen, csr, csr_len);
	if (n < 0)
		goto bail;

	if (CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM,
				    CRYPT_PRIKEY_PKCS8_UNENCRYPT,
				    &key_pem) != CRYPT_SUCCESS) {
		lws_openhitls_log_error_string("unable to encode CSR private key",
					       __func__, CRYPT_SUCCESS);
		goto bail;
	}

	*privkey_pem = malloc(key_pem.dataLen); /* malloc so caller can free */
	if (!*privkey_pem)
		goto bail;

	memcpy(*privkey_pem, key_pem.data, key_pem.dataLen);
	*privkey_len = key_pem.dataLen;
	ret = n;

bail:
	if (ret < 0) {
		free(*privkey_pem);
		*privkey_pem = NULL;
		*privkey_len = 0;
	}
	BSL_SAL_FREE(csr_der.data);
	BSL_SAL_FREE(key_pem.data);
	HITLS_X509_CsrFree(req);
	CRYPT_EAL_PkeyFreeCtx(pkey);

	return ret;
}

#endif

int
lws_tls_vhost_backend_create_ctx(struct lws_vhost *vhost)
{
        return 0; /* no action */
}

void
lws_tls_vhost_backend_free_ctx(lws_tls_ctx *ctx)
{
        /* no action */
}
