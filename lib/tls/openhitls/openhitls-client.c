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
 * openHiTLS TLS client implementation
 */

#include <hitls_pki_errno.h>
#include <hitls_pki_x509.h>

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"
static void
lws_openhitls_verify_result_to_policy(int vr, HITLS_X509_Cert *peer_cert,
				      const char **type, unsigned int *avoid)
{
	const char *lt = "tls=verify";
	unsigned int la = 0;

	switch (vr) {
	case HITLS_X509_ERR_VFY_HOSTNAME_FAIL:
		lt = "tls=hostname";
		la = LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
	case HITLS_X509_ERR_VFY_INVALID_CA:
	case HITLS_X509_ERR_VFY_INTERCA_INVALID_BCONS:
	case HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND:
	case HITLS_X509_ERR_ROOT_CERT_NOT_FOUND:
		lt = "tls=invalidca";
		la = LCCSCF_ALLOW_SELFSIGNED;
		break;
	case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
	case HITLS_X509_ERR_TIME_FUTURE:
		lt = "tls=notyetvalid";
		la = LCCSCF_ALLOW_EXPIRED;
		break;
	case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
	case HITLS_X509_ERR_TIME_EXPIRED:
		lt = "tls=expired";
		la = LCCSCF_ALLOW_EXPIRED;
		break;
	default:
		break;
	}

	if (type)
		*type = lt;
	if (avoid)
		*avoid = la;
}

static int lws_openhitls_client_ctx_fingerprint(
    struct lws_vhost *vh,
    const struct lws_context_creation_info *info,
    const char *ca_filepath,
    const void *ca_mem,
    unsigned int ca_mem_len,
    const char *cert_filepath,
    const void *cert_mem,
    unsigned int cert_mem_len,
    const char *private_key_filepath,
    uint8_t hash[32])
{
	struct lws_genhash_ctx hash_ctx;
	char c = 1;

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
			return -1;
	}

	if (info->client_tls_ciphers_iana &&
	    lws_genhash_update(&hash_ctx, info->client_tls_ciphers_iana,
			       strlen(info->client_tls_ciphers_iana))) {
		goto bail_hash;
	}

	if (info->ssl_client_options_set &&
	    lws_genhash_update(&hash_ctx, &info->ssl_client_options_set,
			       sizeof(info->ssl_client_options_set))) {
		goto bail_hash;
	}

	if (info->ssl_client_options_clear &&
	    lws_genhash_update(&hash_ctx, &info->ssl_client_options_clear,
			       sizeof(info->ssl_client_options_clear))) {
		goto bail_hash;
	}

	if (!lws_check_opt(vh->options,
			   LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS) &&
	    (!ca_mem || !ca_mem_len) && lws_genhash_update(&hash_ctx, &c, 1)) {
		goto bail_hash;
	}

	if (ca_filepath &&
	    lws_genhash_update(&hash_ctx, ca_filepath, strlen(ca_filepath))) {
		goto bail_hash;
	}

	if (cert_filepath && lws_genhash_update(&hash_ctx, cert_filepath,
						strlen(cert_filepath))) {
		goto bail_hash;
	}

	if (private_key_filepath &&
	    lws_genhash_update(&hash_ctx, private_key_filepath,
			       strlen(private_key_filepath))) {
		goto bail_hash;
	}

	if (ca_mem && ca_mem_len &&
	    lws_genhash_update(&hash_ctx, ca_mem, ca_mem_len)) {
		goto bail_hash;
	}

	if (cert_mem && cert_mem_len &&
	    lws_genhash_update(&hash_ctx, cert_mem, cert_mem_len)) {
		goto bail_hash;
	}

	if (lws_genhash_destroy(&hash_ctx, hash)) {
		return -1;
	}

	return 0;

bail_hash:
	lws_genhash_destroy(&hash_ctx, NULL);

	return -1;
}

#if defined(LWS_WITH_TLS_JIT_TRUST)
static void lws_openhitls_kid_from_bsl(const BSL_Buffer *b, lws_tls_kid_t *kid)
{
	size_t n;

	memset(kid, 0, sizeof(*kid));

	n = b->dataLen;
	if (n > sizeof(kid->kid)) {
		n = sizeof(kid->kid);
	}

	memcpy(kid->kid, b->data, n);
	kid->kid_len = (uint8_t)n;
}

static void lws_openhitls_collect_peer_kids(struct lws *wsi,
					    HITLS_CERT_StoreCtx *store_ctx)
{
	HITLS_X509_List *chain = NULL;
	BslList *list;
	BslListNode *node;

	if (HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
				    HITLS_X509_STORECTX_GET_CERT_CHAIN, &chain,
				    (uint32_t)sizeof(chain)) !=
	    HITLS_PKI_SUCCESS) {
		return;
	}

	list = (BslList *)chain;
	if (!list || BSL_LIST_EMPTY(list)) {
		return;
	}

	wsi->tls.kid_chain.count = 0;

	for (node = list->first;
	     node &&
	     wsi->tls.kid_chain.count < LWS_ARRAY_SIZE(wsi->tls.kid_chain.akid);
	     node = BSL_LIST_GetNextNode(list, node)) {
		HITLS_X509_ExtSki ski = {0};
		HITLS_X509_ExtAki aki = {0};
		HITLS_X509_Cert *cert =
		    (HITLS_X509_Cert *)BSL_LIST_GetData(node);
		uint8_t idx = wsi->tls.kid_chain.count;

		if (!cert) {
			continue;
		}

		memset(&wsi->tls.kid_chain.skid[idx], 0,
		       sizeof(wsi->tls.kid_chain.skid[idx]));
		memset(&wsi->tls.kid_chain.akid[idx], 0,
		       sizeof(wsi->tls.kid_chain.akid[idx]));

		if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski,
					sizeof(ski)) == HITLS_SUCCESS) {
			lws_openhitls_kid_from_bsl(
			    &ski.kid, &wsi->tls.kid_chain.skid[idx]);
		}

		if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_AKI, &aki,
					sizeof(aki)) == HITLS_SUCCESS) {
			lws_openhitls_kid_from_bsl(
			    &aki.kid, &wsi->tls.kid_chain.akid[idx]);
		}

		wsi->tls.kid_chain.count++;
	}
}
#endif

static int lws_openhitls_store_ctx_set_error(HITLS_CERT_StoreCtx *store_ctx,
					     int32_t e)
{
	return HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
				       HITLS_X509_STORECTX_SET_ERROR, &e,
				       (uint32_t)sizeof(e)) == HITLS_PKI_SUCCESS
		   ? 0
		   : -1;
}

/*
 * openHiTLS verify callback return convention:
 *   return 0 (HITLS_PKI_SUCCESS) = OK / override and accept
 *   return non-zero              = reject / propagate error
 * Note: the first argument is errCode (0 = cert passed, non-zero = cert failed),
 * NOT a boolean isPreverifyOk like OpenSSL.
 */

static int32_t OpenHiTLS_client_verify_callback(int32_t verify_code,
						HITLS_CERT_StoreCtx *store_ctx)
{
	void *userdata = NULL;
	lws_tls_conn *ssl = NULL;
	struct lws *wsi = NULL;
	const struct lws_protocols *lp;
	const char *type = "tls=verify";
	int internal_allow = !verify_code;
	int n;
	int32_t vr = 0;

	if (HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
				    HITLS_X509_STORECTX_GET_USR_DATA, &userdata,
				    (uint32_t)sizeof(userdata)) ==
	    HITLS_PKI_SUCCESS) {
		ssl = (lws_tls_conn *)userdata;
	}
	wsi = ssl ? (struct lws *)HITLS_GetUserData((HITLS_Ctx *)ssl) : NULL;

	/* keep old behaviour accepting self-signed server certs */
	if (!internal_allow) {
		if (!wsi) {
			lwsl_err("%s: can't get wsi from store ctx\n",
				 __func__);

			return -1;
		}
		HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
					HITLS_X509_STORECTX_GET_ERROR, &vr,
					sizeof(int32_t));
		if (vr != HITLS_X509_V_OK) {
			/* openHiTLS uses ROOT_CERT_NOT_FOUND for self-signed
			 * certs */
			if (vr == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND &&
			    wsi->tls.use_ssl & LCCSCF_ALLOW_SELFSIGNED) {
				lwsl_notice("accepting self-signed "
					    "certificate (verify_callback)\n");
				(void)lws_openhitls_store_ctx_set_error(
				    store_ctx, (int32_t)HITLS_X509_V_OK);
				return 0; /* ok: override */
			} else if ((vr == HITLS_X509_ERR_VFY_INVALID_CA ||
				    vr == HITLS_X509_ERR_VFY_INTERCA_INVALID_BCONS ||
				    vr == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
				    vr == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND) &&
				   wsi->tls.use_ssl & LCCSCF_ALLOW_INSECURE) {
				lwsl_notice(
				    "accepting non-trusted certificate\n");
				(void)lws_openhitls_store_ctx_set_error(
				    store_ctx, (int32_t)HITLS_X509_V_OK);
				return 0; /* ok: override */
			} else if (
			    (vr == HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE ||
			     vr == HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED) &&
			    wsi->tls.use_ssl & LCCSCF_ALLOW_EXPIRED) {
				if (vr ==
				    HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE) {
					lwsl_notice("accepting not yet valid "
						    "certificate (verify_"
						    "callback)\n");
				} else if (
				    vr == HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED) {
					lwsl_notice("accepting expired "
						    "certificate (verify_"
						    "callback)\n");
				}
				(void)lws_openhitls_store_ctx_set_error(
				    store_ctx, (int32_t)HITLS_X509_V_OK);
				return 0; /* ok: override */
			}
		}
	}

	if (!wsi) {
		lwsl_err("%s: can't get wsi from store ctx\n", __func__);
		return 0;
	}

#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (vr == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
		if (!wsi->tls.kid_chain.count) {
			lws_openhitls_collect_peer_kids(wsi, store_ctx);
		}
		if (wsi->tls.kid_chain.count) {
			(void)lws_tls_jit_trust_sort_kids(wsi,
							  &wsi->tls.kid_chain);
		}
	}
#endif

	lp = &(lws_get_context_protocol(wsi->a.context, 0));
	if (wsi->a.protocol) {
		lp = wsi->a.protocol;
	}

	n = lp->callback(wsi,
			 LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION,
			 store_ctx, ssl, (unsigned int)internal_allow);

	/* keep old behaviour if something wrong with server certs */
	/* if ssl error is overruled in callback and cert is ok,
	 * HITLS_X509_STORECTX_SET_ERROR must be set to HITLS_X509_V_OK and
	 * return value is 0 from callback */
	if (!internal_allow) {
		HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
					HITLS_X509_STORECTX_GET_ERROR, &vr,
					sizeof(int32_t));
		if (vr != HITLS_X509_V_OK) {
			/* cert validation error was not handled in callback */
			lws_strncpy(wsi->tls.err_helper, type,
				    sizeof(wsi->tls.err_helper));

			lwsl_err("SSL error: %s (preverify_ok=%d;err=%d)\n",
				 type, internal_allow, vr);

#if defined(LWS_WITH_SYS_METRICS)
			{
				char buckname[64];

				lws_snprintf(buckname, sizeof(buckname),
					     "tls=\"%s\"", type);
				lws_metrics_hist_bump_describe_wsi(
				    wsi,
				    lws_metrics_priv_to_pub(
					wsi->a.context->mth_conn_failures),
				    buckname);
			}
#endif

			return vr ? vr : -1; /* not ok */
		}
	}
	/*
	 * Both lws user callback and openHiTLS verify callback use
	 * 0 = OK, so pass through directly.
	 *
	 */
	return n;
}

int lws_ssl_client_bio_create(struct lws *wsi)
{
	char hostname[128];
	char alpn_buf[128];
	const char *alpn_comma = wsi->a.context->tls.alpn_default;
	HITLS_Ctx *ssl;
	lws_system_blob_t *b;
	BSL_UIO *uio;
	const uint8_t *data;
	size_t size;
	char *p;
	int ret;
	int n;

	if (wsi->stash) {
		lws_strncpy(hostname, wsi->stash->cis[CIS_HOST],
			    sizeof(hostname));
		alpn_comma = wsi->stash->cis[CIS_ALPN];
	} else {
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		if (lws_hdr_copy(wsi, hostname, sizeof(hostname),
				 _WSI_TOKEN_CLIENT_HOST) <= 0)
#endif
		{
			lwsl_err("%s: Unable to get hostname\n", __func__);

			return -1;
		}
	}

	/*
	 * remove any :port part on the hostname... necessary for network
	 * connection but typical certificates do not contain it
	 */
	p = hostname;
	while (*p) {
		if (*p == ':') {
			*p = '\0';
			break;
		}
		p++;
	}

	/* Create new SSL connection */
	ssl = HITLS_New((lws_tls_ctx *)wsi->a.vhost->tls.ssl_client_ctx);
	if (!ssl) {
		lwsl_err("SSL_new failed\n");
		lws_tls_err_describe_clear();
		return -1;
	}

#if defined(LWS_WITH_TLS_SESSIONS)
	if (!(wsi->a.vhost->options &
	      LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)) {
		wsi->tls.ssl = ssl;
		lws_tls_reuse_session(wsi);
		wsi->tls.ssl = NULL;
	}
#endif

	if (wsi->a.vhost->tls.ssl_info_event_mask) {
		HITLS_SetInfoCb(ssl, lws_ssl_info_callback);
	}

	if (!(wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)) {
		/* HiTLS support NO_PARTIAL_WILDCARDS by default */
		HITLS_SetHost(ssl, hostname);
	}

	HITLS_SetVerifyCb(ssl, OpenHiTLS_client_verify_callback);

	/*
	 * openHiTLS may abort the handshake with
	 * HITLS_CERT_ERR_VERIFY_CERT_CHAIN before the verify callback is
	 * ever called (e.g. when the server cert chain cannot be built to a
	 * trusted root).  Set VerifyNoneSupport so the handshake is allowed
	 * to complete; the verify result is still recorded and checked
	 * afterwards in lws_tls_client_confirm_peer_cert() against the
	 * per-connection LCCSCF_ALLOW_SELFSIGNED / LCCSCF_ALLOW_INSECURE
	 * policy flags.
	 */
	if (wsi->tls.use_ssl &
	    (LCCSCF_ALLOW_INSECURE | LCCSCF_ALLOW_SELFSIGNED)) {
		HITLS_SetVerifyNoneSupport(ssl, true);
	}
	HITLS_SetModeSupport(ssl, HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	/* use server name indication (SNI), if supported */
	HITLS_SetServerName(ssl, (uint8_t *)hostname,
			    (uint32_t)strlen(hostname));

	/* Create and attach BSL_UIO (TCP socket) */
	uio = BSL_UIO_New(BSL_UIO_TcpMethod());
	if (!uio) {
		lwsl_err("%s: BSL_UIO_New failed\n", __func__);
		HITLS_Free(ssl);
		return -1;
	}

	/* BSL_UIO_SetFD returns void */
	BSL_UIO_SetFD(uio, (int)wsi->desc.sockfd);

	/* Set non-blocking mode */
	BSL_UIO_Ctrl(uio, BSL_UIO_SET_NOBLOCK, 1, NULL);

	ret = HITLS_SetUio(ssl, uio);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUio failed: 0x%x\n", __func__, ret);
		BSL_UIO_Free(uio);
		HITLS_Free(ssl);
		return -1;
	}

	/*
	 * ALPN precedence: context default -> vhost default -> stash override
	 * -> request header.
	 */
	if (wsi->a.vhost->tls.alpn) {
		alpn_comma = wsi->a.vhost->tls.alpn;
	}
	if (wsi->stash) {
		alpn_comma = wsi->stash->cis[CIS_ALPN];
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	} else {
		if (lws_hdr_copy(wsi, alpn_buf, sizeof(alpn_buf),
				 _WSI_TOKEN_CLIENT_ALPN) > 0) {
			alpn_comma = alpn_buf;
		}
#endif
	}

	lwsl_info("%s client conn using alpn list '%s'\n", wsi->role_ops->name,
		  alpn_comma);

    n = lws_alpn_comma_to_openssl(alpn_comma, (uint8_t *)alpn_buf,
                        sizeof(alpn_buf) - 1);
    ret = HITLS_SetAlpnProtos(ssl, (uint8_t *)alpn_buf, (uint32_t)n);

	/* OpenHiTLS_client_verify_callback will be called @ HITLS_Connect(). */
	HITLS_SetUserData(ssl, wsi);

	wsi->tls.ssl = ssl;

	if (wsi->sys_tls_client_cert) {
		b = lws_system_get_blob(wsi->a.context,
					LWS_SYSBLOB_TYPE_CLIENT_CERT_DER,
					wsi->sys_tls_client_cert - 1);
		if (!b) {
			goto no_client_cert;
		}

		/*
		 * Set up the per-connection client cert
		 */

		size = lws_system_blob_get_size(b);
		if (!size) {
			goto no_client_cert;
		}

		if (lws_system_blob_get_single_ptr(b, &data)) {
			goto no_client_cert;
		}

		ret = HITLS_LoadCertBuffer(ssl, data, (uint32_t)size,
					   TLS_PARSE_FORMAT_ASN1);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: use_certificate failed\n", __func__);
			lws_tls_err_describe_clear();
			goto no_client_cert;
		}

		b = lws_system_get_blob(wsi->a.context,
					LWS_SYSBLOB_TYPE_CLIENT_KEY_DER,
					wsi->sys_tls_client_cert - 1);
		if (!b) {
			goto no_client_cert;
		}

		size = lws_system_blob_get_size(b);
		if (!size) {
			goto no_client_cert;
		}

		if (lws_system_blob_get_single_ptr(b, &data)) {
			goto no_client_cert;
		}

		ret = HITLS_LoadKeyBuffer(ssl, data, (uint32_t)size,
					  TLS_PARSE_FORMAT_ASN1);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: use_privkey failed\n", __func__);
			lws_tls_err_describe_clear();
			goto no_client_cert;
		}

		if (HITLS_CheckPrivateKey(ssl) != HITLS_SUCCESS) {
			lwsl_err("Private SSL key doesn't match cert\n");
			lws_tls_err_describe_clear();
			goto no_client_cert;
		}

		lwsl_notice("%s: set system client cert %u\n", __func__,
			    wsi->sys_tls_client_cert - 1);
	}

	return 0;

no_client_cert:
	lwsl_err("%s: unable to set up system client cert %d\n", __func__,
		 wsi->sys_tls_client_cert - 1);

	return 1;
}

enum lws_ssl_capable_status lws_tls_client_connect(struct lws *wsi,
						   char *errbuf,
						   size_t len)
{
	int m, ret, en;

	errno = 0;
	wsi->tls.err_helper[0] = '\0';
	ret = HITLS_Connect(wsi->tls.ssl);
	en = errno;

	m = lws_ssl_get_error(wsi, ret);

	if (m == HITLS_ERR_SYSCALL
#if defined(WIN32)
	    && en
#endif
	) {
#if defined(WIN32) || (_LWS_ENABLED_LOGS & LLL_INFO)
		lwsl_info("%s: ret %d, m %d, errno %d\n", __func__, ret, m, en);
#endif
		lws_snprintf(errbuf, len, "connect SYSCALL %d", en);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (m == HITLS_ERR_TLS) {
		int n =
		    lws_snprintf(errbuf, len, "tls: %s", wsi->tls.err_helper);
		if (!wsi->tls.err_helper[0]) {
			const char *desc = BSL_ERR_GetString(m);
			if (desc && desc[0]) {
				lws_snprintf(errbuf + n, len - (unsigned int)n,
					     "%s", desc);
			}
		}
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (m == HITLS_WANT_READ) {
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	if (m == HITLS_WANT_WRITE) {
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}
	if (ret == HITLS_SUCCESS || m == HITLS_ERR_SYSCALL) {
		uint8_t *proto = NULL;
		uint32_t proto_len = 0;

		if (HITLS_GetSelectedAlpnProto(wsi->tls.ssl, &proto,
					       &proto_len) == HITLS_SUCCESS &&
		    proto && proto_len) {
			char a[32];

			if (proto_len >= sizeof(a)) {
				proto_len = sizeof(a) - 1;
			}
			memcpy(a, proto, proto_len);
			a[proto_len] = '\0';
			lws_role_call_alpn_negotiated(wsi, a);
		}

#if defined(LWS_TLS_SYNTHESIZE_CB)
		lws_sul_schedule(wsi->a.context, wsi->tsi,
				 &wsi->tls.sul_cb_synth,
				 lws_sess_cache_synth_cb, 500 * LWS_US_PER_MS);
#endif

		lwsl_info("client connect OK\n");
		lws_openhitls_describe_cipher(wsi);
		return LWS_SSL_CAPABLE_DONE;
	}

	if (!ret) /* we don't know what he wants, but he says to retry */
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	lws_snprintf(errbuf, len, "connect unk %d", m);

	return LWS_SSL_CAPABLE_ERROR;
}

int lws_tls_client_confirm_peer_cert(struct lws *wsi,
				     char *ebuf,
				     size_t ebuf_len)
{
	HITLS_ERROR verify_result = HITLS_X509_V_OK;
	HITLS_X509_Cert *tls_cert;
	const char *type = "";
	unsigned int avoid = 0;
	int vr;

	HITLS_GetVerifyResult((const HITLS_Ctx *)wsi->tls.ssl, &verify_result);

	if (verify_result == HITLS_X509_V_OK) {
		return 0;
	}

	vr = (int)verify_result;
	tls_cert = HITLS_GetPeerCertificate(wsi->tls.ssl);

	lws_openhitls_verify_result_to_policy(vr, tls_cert, &type, &avoid);

	lwsl_info("%s: cert problem: %s (0x%x)\n", __func__, type,
		  verify_result);

#if defined(LWS_WITH_SYS_METRICS)
	lws_metrics_hist_bump_describe_wsi(
	    wsi, lws_metrics_priv_to_pub(wsi->a.context->mth_conn_failures),
	    type);
#endif

	if (wsi->tls.use_ssl & avoid) {
		lwsl_info("%s: allowing verify error 0x%x due to policy\n",
			  __func__, verify_result);
		return 0;
	}

	lws_snprintf(
	    ebuf, ebuf_len,
	    "server cert didn't look good, %s (use_ssl 0x%x) verify = 0x%x",
	    type, (unsigned int)wsi->tls.use_ssl, verify_result);
	lwsl_info("%s: server cert verify failed: 0x%x\n", __func__,
		  verify_result);
	lws_tls_err_describe_clear();

	return -1;
}

int lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh,
					const uint8_t *der,
					size_t der_len)
{
	lws_tls_ctx *ctx;
	int ret;

	ctx = (lws_tls_ctx *)vh->tls.ssl_client_ctx;

	ret = HITLS_CFG_LoadVerifyBuffer(ctx, der, (uint32_t)der_len,
					 TLS_PARSE_FORMAT_ASN1);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CFG_LoadVerifyBuffer failed: 0x%x\n",
			 __func__, ret);
		return 1;
	}
	return 0;
}

int lws_tls_client_create_vhost_context(
    struct lws_vhost *vh,
    const struct lws_context_creation_info *info,
    const char *cipher_list,
    const char *ca_filepath,
    const void *ca_mem,
    unsigned int ca_mem_len,
    const char *cert_filepath,
    const void *cert_mem,
    unsigned int cert_mem_len,
    const char *private_key_filepath,
    const void *key_mem,
    unsigned int key_mem_len)
{
	struct lws_tls_client_reuse *tcr = NULL;
	lws_tls_ctx *ctx;
	uint8_t hash[32];
	HITLS_Config *config;
	lws_filepos_t flen;
	uint8_t *der_buf;
	int cert_set = 0;
	int ret;

	(void)cipher_list;

	if (lws_openhitls_client_ctx_fingerprint(
		vh, info, ca_filepath, ca_mem, ca_mem_len,
		cert_filepath, cert_mem, cert_mem_len, private_key_filepath,
		hash)) {
		return -1;
	}

	lws_start_foreach_dll_safe(
	    struct lws_dll2 *, p, tp,
	    lws_dll2_get_head(&vh->context->tls.cc_owner))
	{
		tcr = lws_container_of(p, struct lws_tls_client_reuse, cc_list);

		if (!memcmp(hash, tcr->hash, sizeof(hash))) {
			tcr->refcount++;
			vh->tls.ssl_client_ctx = tcr->ssl_client_ctx;
			vh->tls.tcr = tcr;

			lwsl_info("%s: vh %s: reusing client ctx %d: use %d\n",
				  __func__, vh->name, tcr->index, tcr->refcount);

			return 0;
		}
	}lws_end_foreach_dll_safe(p, tp);

	config = HITLS_CFG_NewTLSConfig();
	if (!config) {
		lwsl_err("%s: HITLS_CFG_NewTLSConfig failed\n", __func__);
		return -1;
	}

	if (lws_openhitls_apply_tls_version_by_ssl_options(
			config, info->ssl_client_options_set,
			info->ssl_client_options_clear, __func__)) {
		lwsl_err("%s: unable to apply client TLS version options\n",
			 __func__);
		HITLS_CFG_FreeConfig(config);
		return -1;
	}
	HITLS_CFG_SetConfigUserData(config, vh->context);

	lws_plat_vhost_tls_client_ctx_init(vh);

	ctx = config;
	vh->tls.ssl_client_ctx = ctx;

	tcr = lws_zalloc(sizeof(*tcr), "client ctx tcr");
	if (!tcr)
		goto bail_cfg;

	tcr->ssl_client_ctx = ctx;
	tcr->refcount = 1;
	memcpy(tcr->hash, hash, sizeof(hash));
	tcr->index = vh->context->tls.count_client_contexts++;
	lws_dll2_add_head(&tcr->cc_list, &vh->context->tls.cc_owner);
	vh->tls.tcr = tcr;

	lwsl_info("%s: vh %s: created new client ctx %d\n", __func__, vh->name,
		  tcr->index);


#if defined(LWS_WITH_TLS_KEYLOG) && defined(LWS_WITH_TLS) && \
		!defined(LWS_WITHOUT_CLIENT)
	if (vh->context->keylog_file[0]) {
		ret = HITLS_CFG_SetKeyLogCb(config, lws_openhitls_klog_dump);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_SetKeyLogCb failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	}
#endif

#if defined(LWS_WITH_TLS_SESSIONS)
	lws_tls_session_cache(vh, info->tls_session_timeout);
#endif

	HITLS_CFG_SetModeSupport(config,
				       HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER |
					   HITLS_MODE_RELEASE_BUFFERS);

	HITLS_CFG_SetCipherServerPreference(config, true);

	if (info->client_tls_ciphers_iana &&
	    info->client_tls_ciphers_iana[0]) {
		ret = lws_openhitls_apply_cipher_suites(
			config, info->client_tls_ciphers_iana, __func__);
		if (ret) {
			lwsl_err("%s: no valid IANA cipher from '%s'\n",
				 __func__, info->client_tls_ciphers_iana);
			goto bail_cfg;
		}
	} else if (cipher_list || info->client_tls_1_3_plus_cipher_list) {
		lwsl_info("%s: openHiTLS ignores OpenSSL cipher-list fields; "
			  "use client_tls_ciphers_iana\n", __func__);
	}

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
	if (!lws_check_opt(vh->options,
			   LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS)) {
		ret = HITLS_CFG_LoadDefaultCAPath(config);
		if (ret != HITLS_SUCCESS) {
			lwsl_warn(
			    "%s: unable to load system default CA path: 0x%x\n",
			    __func__, ret);
		}
	}
#endif

	/* Load CA certificates for verification (OpenSSL-equivalent flow). */
	if (!ca_filepath && (!ca_mem || !ca_mem_len)) {
		ret = HITLS_CFG_LoadVerifyDir(config, LWS_OPENSSL_CLIENT_CERTS);		
        if (ret != HITLS_SUCCESS) {
			lwsl_err("Unable to load SSL Client certs from %s "
				 "-- client ssl isn't going to work\n",
				 LWS_OPENSSL_CLIENT_CERTS);
		}
	} else if (ca_filepath) {
		lwsl_notice("%s: loading CA from %s\n", __func__, ca_filepath);
		ret = HITLS_CFG_LoadVerifyFile(config, ca_filepath);
		if (ret != HITLS_SUCCESS) {
			lwsl_notice("%s: LoadVerifyFile failed, trying PEM->DER "
				    "fallback for %s\n", __func__, ca_filepath);
		} else
			lwsl_info("loaded ssl_ca_filepath\n");
	} else {
		lwsl_notice("%s: loading CA from memory (%u bytes)\n", __func__,
			    ca_mem_len);
		if (lws_tls_client_vhost_ca_mem_parse(vh, ca_mem, ca_mem_len)) {
			lwsl_err("%s: Unable to load x.509 ca_mem\n", __func__);
			goto bail_cfg;
		}
	}

	/* Load client certificate if provided (OpenSSL order: filepath first).
	 */
	if (cert_filepath) {
		if (lws_tls_use_any_upgrade_check_extant(cert_filepath) !=
			LWS_TLS_EXTANT_YES &&
		    (info->options & LWS_SERVER_OPTION_IGNORE_MISSING_CERT)) {
			lwsl_notice("%s: ignoring missing client cert %s\n",
				    __func__, cert_filepath);
			return 0;
		}

		lwsl_notice("%s: loading client cert from %s\n", __func__,
			    cert_filepath);
		ret = HITLS_CFG_UseCertificateChainFile(config, cert_filepath);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_UseCertificateChainFile "
				 "failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
		cert_set = 1;
	} else if (cert_mem && cert_mem_len) {
		lwsl_notice("%s: loading client cert from memory (%u bytes)\n",
			    __func__, cert_mem_len);
		if (lws_tls_alloc_pem_to_der_file(vh->context, NULL, cert_mem,
						  cert_mem_len, &der_buf,
						  &flen)) {
			lwsl_err("%s: couldn't read cert file\n", __func__);
			goto bail_cfg;
		}
		ret = HITLS_CFG_LoadCertBuffer(config, der_buf, (uint32_t)flen,
					       TLS_PARSE_FORMAT_ASN1);
		lws_free_set_NULL(der_buf);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadCertBuffer failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
		cert_set = 1;
	}

	/* Load client private key if provided (OpenSSL order: filepath first).
	 */
	if (private_key_filepath) {
		lws_ssl_bind_passphrase(ctx, 1, info);
		lwsl_notice("%s: loading client key from %s\n", __func__,
			    private_key_filepath);
		ret = HITLS_CFG_LoadKeyFile(config, private_key_filepath,
					    TLS_PARSE_FORMAT_PEM);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyFile failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	} else if (key_mem && key_mem_len) {
		lwsl_notice("%s: loading client key from memory (%u bytes)\n",
			    __func__, key_mem_len);
		if (lws_tls_alloc_pem_to_der_file(vh->context, NULL, key_mem,
						  key_mem_len, &der_buf,
						  &flen)) {
			lwsl_err("%s: couldn't use mem cert\n", __func__);
			goto bail_cfg;
		}
		ret = HITLS_CFG_LoadKeyBuffer(config, der_buf, (uint32_t)flen,
					      TLS_PARSE_FORMAT_ASN1);
		lws_free_set_NULL(der_buf);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("%s: HITLS_CFG_LoadKeyBuffer failed: 0x%x\n",
				 __func__, ret);
			goto bail_cfg;
		}
	}

	if ((private_key_filepath || (key_mem && key_mem_len)) && cert_set) {
		ret = HITLS_CFG_CheckPrivateKey(config);
		if (ret != HITLS_SUCCESS) {
			lwsl_err("Private SSL key doesn't match cert\n");
			goto bail_cfg;
		}
	}

	return 0;

bail_cfg:
	if (tcr) {
		lws_dll2_remove(&tcr->cc_list);
		lws_free(tcr);
		vh->tls.tcr = NULL;
	}
	HITLS_CFG_FreeConfig(config);
	vh->tls.ssl_client_ctx = NULL;
	return 1;
}
