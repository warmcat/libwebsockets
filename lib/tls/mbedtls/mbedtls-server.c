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
#include "private-lib-tls-mbedtls.h"
#include <mbedtls/x509_csr.h>
#include <errno.h>

extern int lws_plat_mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len);
extern int lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len);

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	int verify_options = MBEDTLS_SSL_VERIFY_OPTIONAL, post_handshake, require;

	/*
	 * The vhost may legitimately have no ctx, eg, it was created with
	 * LWS_SERVER_OPTION_IGNORE_MISSING_CERT and the cert has not arrived
	 * yet... there is nothing to configure on then.
	 */

	if (!vh->tls.ssl_ctx)
		return 0;

	post_handshake = !!lws_check_opt(vh->options,
		LWS_SERVER_OPTION_MBEDTLS_VERIFY_CLIENT_CERT_POST_HANDSHAKE);
	require = !!lws_check_opt(vh->options,
		LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT);

	if (!post_handshake && !require) {
		lwsl_notice("no client cert required\n");

		return 0;
	}

	if (post_handshake) {
		/*
		 * He wants the client cert collected and kept so he can decide
		 * about it himself after the handshake.  mbedtls only sends a
		 * CertificateRequest, and only parses and keeps what comes
		 * back, if the authmode is not VERIFY_NONE... and VERIFY_NONE
		 * is what mbedtls_ssl_config_defaults() leaves a server at.
		 * So VERIFY_OPTIONAL is precisely what this option means: ask
		 * for the cert and keep it, but don't fail the handshake on
		 * it.  Leaving it at the default made the option a silent
		 * no-op, ie, there was never any client cert to inspect.
		 */
		lwsl_notice("%s: vh %s can verify client cert post-handshake\n",
				__func__, vh->name);

#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
		lwsl_warn("%s: mbedtls lacks MBEDTLS_SSL_KEEP_PEER_CERTIFICATE:"
			  " the peer cert will not be readable after the "
			  "handshake\n", __func__);
#endif
	}

	/*
	 * The two options are orthogonal: asking to inspect the cert after the
	 * handshake must not quietly cancel an explicit "require a valid
	 * client cert".  VERIFY_REQUIRED keeps the peer cert around for
	 * inspection just the same, it only additionally refuses the ones that
	 * do not verify.
	 */

	if (require &&
	    !lws_check_opt(vh->options, LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
		verify_options = MBEDTLS_SSL_VERIFY_REQUIRED;

	lwsl_notice("%s: vh %s client cert authmode %d\n", __func__, vh->name,
		    verify_options);

	mbedtls_ssl_conf_authmode(&vh->tls.ssl_ctx->conf, verify_options);

	return 0;
}

/*
 * mbedtls has no SSL_get_SSL_CTX(), so identify the listening vhost this
 * handshake belongs to by its config.  A vhost whose cert was hot-reloaded
 * keeps the retired ctx alive for the connections still using it, so those
 * have to be searched too... otherwise the caller cannot tell which listener
 * the connection arrived on.
 */

static struct lws_vhost *
lws_mbedtls_vhost_from_conf(struct lws_context *context,
			    const mbedtls_ssl_config *conf)
{
	struct lws_vhost *vh = lws_vhost_first(context);

	while (vh) {
		if (vh->being_destroyed) {
			vh = lws_vhost_next(vh);
			continue;
		}

		if (vh->tls.ssl_ctx && &vh->tls.ssl_ctx->conf == conf)
			return vh;

		lws_start_foreach_dll(struct lws_dll2 *, d,
				lws_dll2_get_head(&vh->tls.retired_ctx_list)) {
			struct lws_tls_ctx_ref *r = lws_container_of(d,
						struct lws_tls_ctx_ref, list);

			if (r->ctx && &r->ctx->conf == conf)
				return vh;
		} lws_end_foreach_dll(d);

		vh = lws_vhost_next(vh);
	}

	return NULL;
}

static int
lws_mbedtls_sni_cb(void *arg, mbedtls_ssl_context *mbedtls_ctx,
		   const unsigned char *servername, size_t len)
{
	struct lws_context *context = (struct lws_context *)arg;
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	LWS_RATELIMIT_DEFINE_STATIC(rl);
#endif
	struct lws_vhost *vhost, *vh;
	char sn_str[128];

	/*
	 * mbedtls documents this as "not '\0'-terminated, use len"... it
	 * points into the received ClientHello, so it must be copied out
	 * bounded before it can go anywhere near a "%s".
	 */

	lws_strnncpy(sn_str, (const char *)servername, len, sizeof(sn_str));

	lwsl_info("%s: SNI '%s'\n", __func__, sn_str);

	/*
	 * Find out which listening vhost took us, so we only match vhosts on
	 * the same port.
	 */

	vh = lws_mbedtls_vhost_from_conf(context,
					 mbedtls_ctx->MBEDTLS_PRIVATE(conf));
	if (!vh) {
		/*
		 * We can't tell which listener this is... we must not borrow
		 * an arbitrary TLS vhost's listen_port to search with, that
		 * would let SNI select a vhost belonging to a different
		 * listener.  Leave him on the vhost he arrived on.
		 */
		lwsl_info("%s: no vhost owns this tls conf\n", __func__);

		return 0;
	}

	vhost = lws_select_vhost_sni(context, vh->listen_port, sn_str);
	if (!vhost) {
		lwsl_info("SNI: none: %s:%d\n", sn_str, vh->listen_port);

		/*
		 * He named something that is not served on this listener, and
		 * no vhost there is the nominated sni-fallback.  Refuse him
		 * rather than let him pick an arbitrary vhost's certificate
		 * and client-certificate policy with an unknown name...
		 * mbedtls turns a nonzero return from the SNI callback into a
		 * fatal unrecognized_name alert and aborts the handshake.
		 *
		 * The name is his to choose, so it stays out of the notice
		 * level line; it is logged just above at info level.
		 */

		lwsl_ratelimit_notice(&rl, 10 * LWS_US_PER_SEC, "%s: refused "
				      "tls connection on port %d, its SNI name "
				      "matches no vhost there and none is the "
				      "sni-fallback\n", __func__,
				      vh->listen_port);

		return -1;
	}

	lwsl_info("SNI: Found: %s:%d at vhost '%s'\n", sn_str,
					vh->listen_port, vhost->name);

	if (!vhost->tls.ssl_ctx) {
		lwsl_err("%s: vhost %s matches SNI but no valid cert\n",
				__func__, vh->name);
		return -1;
	}

	mbedtls_ssl_set_hs_own_cert(mbedtls_ctx, vhost->tls.ssl_ctx->chain, vhost->tls.ssl_ctx->key);

	/*
	 * Unlike openssl's SSL_set_SSL_CTX(), ssl->conf still points at the
	 * *listening* vhost's config for the rest of the handshake; these
	 * per-handshake overrides are the only things that change.  So the CA
	 * chain has to be set unconditionally, including to NULL: a vhost
	 * that requires a client cert but configures no CA of its own would
	 * otherwise raise the authmode to REQUIRED while still validating
	 * against the listening vhost's trust store, ie, accept a client cert
	 * issued by somebody else's CA.  (lws configures no CRL for mbedtls
	 * anywhere, so NULL is what the non-SNI path uses too.)
	 */

	mbedtls_ssl_set_hs_ca_chain(mbedtls_ctx, vhost->tls.ssl_ctx->ca_chain,
				    NULL);
	mbedtls_ssl_set_hs_authmode(mbedtls_ctx, vhost->tls.ssl_ctx->conf.MBEDTLS_PRIVATE(authmode));

#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03020000
	{
		struct lws *wsi = (struct lws *)
				mbedtls_ssl_get_user_data_p(mbedtls_ctx);

		/*
		 * Bind the wsi to the vhost that will actually serve him, so
		 * mounts, protocols and the mTLS rebind refusals see the right
		 * one (gnutls and openhitls do this in their SNI callbacks;
		 * here conn->ctx stays the listening vhost's, so the
		 * post-accept ctx-to-vhost adaptation cannot do it).
		 * lws_vhost_bind_wsi() gives back the count held on the
		 * listening vhost and refuses a move onto a dying vhost.
		 */
		if (wsi && wsi->a.vhost != vhost)
			lws_vhost_bind_wsi(vhost, wsi);
	}
#endif

	return 0;
}

int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t mem_cert_len,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	lws_filepos_t flen;
	uint8_t *p = NULL;
	int n;

	char resolved_cert[256];
	char resolved_key[256];

	if (cert && private_key) {
		if (lws_tls_resolve_grace_period_certs(vhost->context, cert, private_key,
						       resolved_cert, sizeof(resolved_cert),
						       resolved_key, sizeof(resolved_key)) == 0) {
			cert = resolved_cert;
			private_key = resolved_key;
		}
	}

	n = (int)lws_tls_generic_cert_checks(vhost, cert, private_key);

	if (n == LWS_TLS_EXTANT_NO && (!mem_cert || !mem_privkey))
		return 0;

	if (n == LWS_TLS_EXTANT_NO)
		n = LWS_TLS_EXTANT_ALTERNATIVE;

	if (n == LWS_TLS_EXTANT_ALTERNATIVE && (!mem_cert || !mem_privkey))
		return 1;

	if (n == LWS_TLS_EXTANT_ALTERNATIVE) {
		cert = NULL;
		private_key = NULL;
	}

	vhost->tls.ssl_ctx->chain = lws_zalloc(sizeof(*vhost->tls.ssl_ctx->chain), "chain");
	vhost->tls.ssl_ctx->key = lws_zalloc(sizeof(*vhost->tls.ssl_ctx->key), "key");
	if (!vhost->tls.ssl_ctx->chain || !vhost->tls.ssl_ctx->key)
		return 1;

	mbedtls_x509_crt_init(vhost->tls.ssl_ctx->chain);
	mbedtls_pk_init(vhost->tls.ssl_ctx->key);

	if (cert) {
#if !defined(LWS_PLAT_OPTEE)
		n = mbedtls_x509_crt_parse_file(vhost->tls.ssl_ctx->chain, cert);
		if (n != 0) {
			lwsl_err("problem loading cert %s: %d\n", cert, n);
			return 1;
		}
#endif
	} else {
		if (lws_tls_alloc_pem_to_der_file(vhost->context, cert, mem_cert,
						  mem_cert_len, &p, &flen)) {
			lwsl_err("couldn't load mem cert\n");
			return 1;
		}
		n = mbedtls_x509_crt_parse(vhost->tls.ssl_ctx->chain, p, (size_t)flen);
		lws_free(p);
		if (n != 0) {
			lwsl_err("problem interpreting cert: %d\n", n);
			return 1;
		}
	}

	if (private_key) {
#if !defined(LWS_PLAT_OPTEE)
#if defined(MBEDTLS_VERSION_MAJOR) && (MBEDTLS_VERSION_MAJOR >= 3)
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && !defined(LWS_HAVE_MBEDTLS_V4)
		n = mbedtls_pk_parse_keyfile(vhost->tls.ssl_ctx->key, private_key, NULL, lws_gencrypto_mbedtls_rngf, vhost->context);
#else
		n = mbedtls_pk_parse_keyfile(vhost->tls.ssl_ctx->key, private_key, NULL);
#endif
#else
		n = mbedtls_pk_parse_keyfile(vhost->tls.ssl_ctx->key, private_key, NULL);
#endif
		if (n != 0) {
			lwsl_err("problem loading key %s: %d\n", private_key, n);
			return 1;
		}
#endif
	} else {
		if (lws_tls_alloc_pem_to_der_file(vhost->context, private_key,
						  (char *)mem_privkey, mem_privkey_len,
						  &p, &flen)) {
			lwsl_err("couldn't find private key\n");
			return 1;
		}
#if defined(MBEDTLS_VERSION_MAJOR) && (MBEDTLS_VERSION_MAJOR >= 3)
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && !defined(LWS_HAVE_MBEDTLS_V4)
		n = mbedtls_pk_parse_key(vhost->tls.ssl_ctx->key, p, (size_t)flen, NULL, 0, lws_gencrypto_mbedtls_rngf, vhost->context);
#else
		n = mbedtls_pk_parse_key(vhost->tls.ssl_ctx->key, p, (size_t)flen, NULL, 0);
#endif
#else
		n = mbedtls_pk_parse_key(vhost->tls.ssl_ctx->key, p, (size_t)flen, NULL, 0);
#endif
		lws_free(p);
		if (n != 0) {
			lwsl_err("Problem loading mem key: %d\n", n);
			return 1;
		}
	}

	mbedtls_ssl_conf_own_cert(&vhost->tls.ssl_ctx->conf, vhost->tls.ssl_ctx->chain, vhost->tls.ssl_ctx->key);

	vhost->tls.skipped_certs = 0;

	return 0;
}

int
lws_tls_vhost_backend_create_ctx(struct lws_vhost *vhost)
{
	struct lws_tls_ctx *ctx;
	int n;


	ctx = lws_zalloc(sizeof(*ctx), "mbedtls server ctx");
	if (!ctx)
		return 1;

	vhost->tls.ssl_ctx = ctx;

	mbedtls_ssl_config_init(&ctx->conf);

	if (mbedtls_ssl_config_defaults(&ctx->conf,
					MBEDTLS_SSL_IS_SERVER,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT)) {
		lwsl_err("mbedtls_ssl_config_defaults failed\n");
		return 1;
	}

	/* TLS 1.2 floor + no peer-initiated renegotiation, see C-406.  The
	 * override is vhost->tls.ssl_options_clear (info.ssl_options_clear) */
	lws_mbedtls_conf_floor(&ctx->conf, vhost->tls.ssl_options_clear);

	/*
	 * Applied here rather than in lws_tls_server_vhost_backend_init(), so
	 * a ctx recreated later (eg, on a cert update) also gets it
	 */

	if (lws_mbedtls_conf_ciphers(ctx, vhost->name,
				     vhost->tls.cfg_tls_ciphers_iana,
				     vhost->tls.cfg_ssl_cipher_list,
				     vhost->tls.cfg_tls1_3_plus_cipher_list))
		return 1;

#if !defined(LWS_HAVE_MBEDTLS_V4)
	mbedtls_ssl_conf_rng(&ctx->conf, lws_gencrypto_mbedtls_rngf, vhost->context);
#endif

	if (vhost->tls.cfg_ssl_ca_filepath) {
		ctx->ca_chain = lws_zalloc(sizeof(*ctx->ca_chain), "ca_chain");
		if (!ctx->ca_chain)
			return 1;
		mbedtls_x509_crt_init(ctx->ca_chain);
#if !defined(LWS_PLAT_OPTEE)
		n = mbedtls_x509_crt_parse_file(ctx->ca_chain, vhost->tls.cfg_ssl_ca_filepath);
		if (n != 0) {
			lwsl_err("couldn't load CA file %s: %d\n", vhost->tls.cfg_ssl_ca_filepath, n);
			return 1;
		}
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->ca_chain, NULL);
#endif
	} else if (vhost->tls.cfg_server_ssl_ca_mem && vhost->tls.cfg_server_ssl_ca_mem_len) {
		ctx->ca_chain = lws_zalloc(sizeof(*ctx->ca_chain), "ca_chain");
		if (!ctx->ca_chain)
			return 1;
		mbedtls_x509_crt_init(ctx->ca_chain);
		n = lws_mbedtls_x509_crt_parse_mem(ctx->ca_chain,
					vhost->tls.cfg_server_ssl_ca_mem,
					vhost->tls.cfg_server_ssl_ca_mem_len);
		if (n != 0) {
			lwsl_err("%s: mem CA parse unhappy: %d\n", __func__, n);
			return 1;
		}
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->ca_chain, NULL);
	}

	return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	int n;

	if (lws_tls_vhost_backend_create_ctx(vhost))
		return 1;

	mbedtls_ssl_conf_sni(&vhost->tls.ssl_ctx->conf, lws_mbedtls_sni_cb, vhost->context);

	/*
	 * The configured cipher lists were mapped to mbedtls ciphersuite ids
	 * and applied in lws_tls_vhost_backend_create_ctx() above, which
	 * fails if any entry could not be mapped
	 */

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem))
		return 0;

	n = (int)lws_tls_generic_cert_checks(vhost, info->ssl_cert_filepath,
					     info->ssl_private_key_filepath);

	if (n == LWS_TLS_EXTANT_NO &&
	    (vhost->options & LWS_SERVER_OPTION_IGNORE_MISSING_CERT)) {
		lwsl_notice("No certs found, continuing without SSL_CTX\n");
		lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_ctx);
		vhost->tls.ssl_ctx = NULL;
		return 0;
	}

	n = lws_tls_server_certs_load(vhost, wsi, info->ssl_cert_filepath,
				      info->ssl_private_key_filepath,
				      info->server_ssl_cert_mem,
				      info->server_ssl_cert_mem_len,
				      info->server_ssl_private_key_mem,
				      info->server_ssl_private_key_mem_len);
	if (n)
		return n;

	return 0;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_tls_conn *conn;

	errno = 0;
	wsi->tls.ctx_ref = lws_tls_ctx_ref_get(wsi->a.vhost);
	if (!wsi->tls.ctx_ref && !wsi->a.vhost->tls.ssl_ctx) {
		lwsl_err("No TLS context\n");
		return 1;
	}

	conn = lws_zalloc(sizeof(*conn), "mbedtls server conn");
	if (!conn)
		return 1;

	wsi->tls.ssl = (lws_tls_conn *)conn;
	conn->ctx = wsi->tls.ctx_ref ? wsi->tls.ctx_ref->ctx : wsi->a.vhost->tls.ssl_ctx;

	mbedtls_ssl_init(&conn->ssl);
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03020000
	/* so the SNI callback can find the wsi to rebind */
	mbedtls_ssl_set_user_data_p(&conn->ssl, wsi);
#endif
	mbedtls_net_init(&conn->net);

	if (mbedtls_ssl_setup(&conn->ssl, &conn->ctx->conf)) {
		mbedtls_ssl_free(&conn->ssl);
		lws_free(conn);
		wsi->tls.ssl = NULL;
		return 1;
	}

	conn->net.MBEDTLS_PRIVATE_V30_ONLY(fd) = (int)accept_fd;
	mbedtls_ssl_set_bio(&conn->ssl, &conn->net, lws_plat_mbedtls_net_send, lws_plat_mbedtls_net_recv, NULL);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	if (wsi->tls.use_ssl)
		__lws_tls_shutdown(wsi);
	
#if defined(LWS_ROLE_QUIC)
	mbedtls_quic_bio_free(wsi);
#endif

	if (wsi->tls.ssl) {
		mbedtls_ssl_free(&wsi->tls.ssl->ssl);
		lws_free(wsi->tls.ssl);
		wsi->tls.ssl = NULL;
	}

	return 0;
}

#if defined(LWS_WITH_TCP_TLS)
enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	union lws_tls_cert_info_results ir;
	int n, en;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _o_mbed_ssl_acc_start = lws_now_usecs();
#endif

	n = mbedtls_ssl_handshake(&wsi->tls.ssl->ssl);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _o_mbed_ssl_acc_start) / 1000);
		if (ms > 2 && !wsi->tls.ssl_accept_in_bg)
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _o_mbed_ssl_acc_start, 2000, "ssl_accept:%dms", ms);
	}
#endif

	wsi->skip_fallback = 1;
	if (n == 0) {
		if ((char *)strstr(wsi->a.vhost->name, ".invalid")) {
			lwsl_notice("%s: vhost has .invalid, rejecting accept\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		if (lws_check_opt(wsi->a.vhost->options,
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT)) {
			uint32_t f = mbedtls_ssl_get_verify_result(
							&wsi->tls.ssl->ssl);

			/*
			 * With LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED the
			 * authmode had to stay VERIFY_OPTIONAL, and mbedtls
			 * completes the handshake under that whatever the cert
			 * turned out to be, just recording the result here.
			 *
			 * openssl's SSL_VERIFY_PEER (which is what lws asks
			 * for there) means "no cert is OK, a bad cert is not".
			 * So tolerate only the absence of a cert: anything
			 * that was presented and failed must fail the accept,
			 * otherwise an app reading the CN or SAN afterwards to
			 * authorize is reading an unvalidated identity.
			 */

			f &= ~((uint32_t)MBEDTLS_X509_BADCERT_MISSING |
			       (uint32_t)MBEDTLS_X509_BADCERT_SKIP_VERIFY);

			if (f) {
				char vi[256];

				mbedtls_x509_crt_verify_info(vi, sizeof(vi),
							     "  ! ", f);
				lwsl_notice("%s: %s: client cert rejected: %s\n",
					    __func__, lws_wsi_tag(wsi), vi);

				return LWS_SSL_CAPABLE_ERROR;
			}
		}

		n = lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
					   &ir, sizeof(ir.ns.name));
		if (!n)
			lwsl_notice("%s: client cert CN '%s'\n", __func__, ir.ns.name);
		else
			lwsl_info("%s: couldn't get client cert CN\n", __func__);

		return LWS_SSL_CAPABLE_DONE;
	}

	en = errno;
	lwsl_debug("%s: %s: accept mbedtls_ssl_handshake %d errno %d\n", __func__,
		    lws_wsi_tag(wsi), n, en);

	if (n == MBEDTLS_ERR_SSL_WANT_READ) {
		if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

#if defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
	if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
		if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
#endif

	if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
		if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}
#endif

#if defined(LWS_WITH_ACME)
int
lws_tls_acme_sni_cert_create(struct lws_vhost *vhost, const char *san_a,
			     const char *san_b)
{
	/* The previous OpenSSL ASN1 wrapper based generation is removed.
	 * Native mbedTLS ACME integration should be done via mbedtls_x509write_crt.
	 */
	return -1;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
}
#endif

#if defined(LWS_WITH_JOSE)
int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *dcsr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
	/* This will be updated if JOSE is used */
	return -1;
}
#endif
