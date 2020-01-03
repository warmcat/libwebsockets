/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#if defined(LWS_WITH_SERVER)

static void
lws_sul_tls_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = lws_container_of(sul,
			struct lws_context_per_thread, sul_tls);

	lws_tls_check_all_cert_lifetimes(pt->context);

	__lws_sul_insert(&pt->pt_sul_owner, &pt->sul_tls,
			 (lws_usec_t)24 * 3600 * LWS_US_PER_SEC);
}

int
lws_context_init_server_ssl(const struct lws_context_creation_info *info,
			    struct lws_vhost *vhost)
{
	struct lws_context *context = vhost->context;
	struct lws *wsi = context->pt[0].fake_wsi;

	if (!lws_check_opt(info->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		vhost->tls.use_ssl = 0;

		return 0;
	}

	/*
	 * If he is giving a server cert, take it as a sign he wants to use
	 * it on this vhost.  User code can leave the cert filepath NULL and
	 * set the LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX option itself, in
	 * which case he's expected to set up the cert himself at
	 * LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, which
	 * provides the vhost SSL_CTX * in the user parameter.
	 */
	if (info->ssl_cert_filepath || info->server_ssl_cert_mem)
		vhost->options |= LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX;

	if (info->port != CONTEXT_PORT_NO_LISTEN) {

		vhost->tls.use_ssl = lws_check_opt(vhost->options,
					LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX);

		if (vhost->tls.use_ssl && info->ssl_cipher_list)
			lwsl_notice(" SSL ciphers: '%s'\n",
						info->ssl_cipher_list);

		if (vhost->tls.use_ssl)
			lwsl_notice(" Using SSL mode\n");
		else
			lwsl_notice(" Using non-SSL mode\n");
	}

	/*
	 * give him a fake wsi with context + vhost set, so he can use
	 * lws_get_context() in the callback
	 */
	wsi->vhost = vhost; /* not a real bound wsi */
	wsi->context = context;
	wsi->protocol = NULL;

	/*
	 * as a server, if we are requiring clients to identify themselves
	 * then set the backend up for it
	 */
	if (lws_check_opt(info->options,
			  LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT))
		/* Normally SSL listener rejects non-ssl, optionally allow */
		vhost->tls.allow_non_ssl_on_ssl_port = 1;

	/*
	 * give user code a chance to load certs into the server
	 * allowing it to verify incoming client certs
	 */
	if (vhost->tls.use_ssl) {
		if (lws_tls_server_vhost_backend_init(info, vhost, wsi))
			return -1;

		lws_tls_server_client_cert_verify_config(vhost);

		if (vhost->protocols[0].callback(wsi,
			    LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
			    vhost->tls.ssl_ctx, vhost, 0))
			return -1;
	}

	if (vhost->tls.use_ssl)
		lws_context_init_alpn(vhost);

	/* check certs once a day */

	context->pt[0].sul_tls.cb = lws_sul_tls_cb;
	__lws_sul_insert(&context->pt[0].pt_sul_owner, &context->pt[0].sul_tls,
			 (lws_usec_t)24 * 3600 * LWS_US_PER_SEC);

	return 0;
}
#endif

int
lws_server_socket_service_ssl(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_vhost *vh;
        char buf[256];
	int n;

        (void)buf;

	if (!LWS_SSL_ENABLED(wsi->vhost))
		return 0;

	switch (lwsi_state(wsi)) {
	case LRS_SSL_INIT:

		if (wsi->tls.ssl)
			lwsl_err("%s: leaking ssl\n", __func__);
		if (accept_fd == LWS_SOCK_INVALID)
			assert(0);
		if (context->simultaneous_ssl_restriction &&
		    context->simultaneous_ssl >=
		    	    context->simultaneous_ssl_restriction) {
			lwsl_notice("unable to deal with SSL connection\n");
			return 1;
		}

		if (lws_tls_server_new_nonblocking(wsi, accept_fd)) {
			if (accept_fd != LWS_SOCK_INVALID)
				compatible_close(accept_fd);
			goto fail;
		}

		if (context->simultaneous_ssl_restriction &&
		    ++context->simultaneous_ssl ==
				    context->simultaneous_ssl_restriction)
			/* that was the last allowed SSL connection */
			lws_gate_accepts(context, 0);

#if defined(LWS_WITH_STATS)
		context->updated = 1;
#endif
		/*
		 * we are not accepted yet, but we need to enter ourselves
		 * as a live connection.  That way we can retry when more
		 * pieces come if we're not sorted yet
		 */
		lwsi_set_state(wsi, LRS_SSL_ACK_PENDING);

		lws_pt_lock(pt, __func__);
		if (__insert_wsi_socket_into_fds(context, wsi)) {
			lwsl_err("%s: failed to insert into fds\n", __func__);
			goto fail;
		}
		lws_pt_unlock(pt);

		lws_set_timeout(wsi, PENDING_TIMEOUT_SSL_ACCEPT,
				context->timeout_secs);

		lwsl_debug("inserted SSL accept into fds, trying SSL_accept\n");

		/* fallthru */

	case LRS_SSL_ACK_PENDING:

		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_err("%s: lws_change_pollfd failed\n", __func__);
			goto fail;
		}

		if (wsi->vhost->tls.allow_non_ssl_on_ssl_port) {

			n = recv(wsi->desc.sockfd, (char *)pt->serv_buf,
				 context->pt_serv_buf_size, MSG_PEEK);

			/*
			 * We have LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT..
			 * this just means don't hang up on him because of no
			 * tls hello... what happens next is driven by
			 * additional option flags:
			 *
			 * none: fail the connection
			 *
			 * LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS:
			 *     Destroy the TLS, issue a redirect using plaintext
			 *     http (this may not be accepted by a client that
			 *     has visited the site before and received an STS
			 *     header).
			 *
			 * LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER:
			 *     Destroy the TLS, continue and serve normally
			 *     using http
			 *
			 * LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG:
			 *     Destroy the TLS, apply whatever role and protocol
			 *     were told in the vhost info struct
			 *     .listen_accept_role / .listen_accept_protocol and
			 *     continue with that
			 */

			if (n >= 1 && pt->serv_buf[0] >= ' ') {
				/*
				* TLS content-type for Handshake is 0x16, and
				* for ChangeCipherSpec Record, it's 0x14
				*
				* A non-ssl session will start with the HTTP
				* method in ASCII.  If we see it's not a legit
				* SSL handshake kill the SSL for this
				* connection and try to handle as a HTTP
				* connection upgrade directly.
				*/
				wsi->tls.use_ssl = 0;

				lws_tls_server_abort_connection(wsi);
				/*
				 * care... this creates wsi with no ssl when ssl
				 * is enabled and normally mandatory
				 */
				wsi->tls.ssl = NULL;

				if (lws_check_opt(wsi->vhost->options,
				    LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS)) {
					lwsl_info("%s: redirecting from http "
						  "to https\n", __func__);
					wsi->tls.redirect_to_https = 1;
					goto notls_accepted;
				}

				if (lws_check_opt(wsi->vhost->options,
				LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER)) {
					lwsl_info("%s: allowing unencrypted "
						  "http service on tls port\n",
						  __func__);
					goto notls_accepted;
				}

				if (lws_check_opt(wsi->vhost->options,
		    LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG)) {
					if (lws_http_to_fallback(wsi, NULL, 0))
						goto fail;
					lwsl_info("%s: allowing non-tls "
						  "fallback\n", __func__);
					goto notls_accepted;
				}

				lwsl_notice("%s: client did not send a valid "
					    "tls hello (default vhost %s)\n",
					    __func__, wsi->vhost->name);
				goto fail;
			}
			if (!n) {
				/*
				 * connection is gone, fail out
				 */
				lwsl_debug("PEEKed 0\n");
				goto fail;
			}
			if (n < 0 && (LWS_ERRNO == LWS_EAGAIN ||
				      LWS_ERRNO == LWS_EWOULDBLOCK)) {
				/*
				 * well, we get no way to know ssl or not
				 * so go around again waiting for something
				 * to come and give us a hint, or timeout the
				 * connection.
				 */
				if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
					lwsl_info("%s: change_pollfd failed\n",
						  __func__);
					return -1;
				}

				lwsl_info("SSL_ERROR_WANT_READ\n");
				return 0;
			}
		}

		/* normal SSL connection processing path */

#if defined(LWS_WITH_STATS)
		/* only set this the first time around */
		if (!wsi->accept_start_us)
			wsi->accept_start_us = lws_now_usecs();
#endif
		errno = 0;
		lws_stats_bump(pt, LWSSTATS_C_SSL_ACCEPT_SPIN, 1);
		n = lws_tls_server_accept(wsi);
		lwsl_info("SSL_accept says %d\n", n);
		switch (n) {
		case LWS_SSL_CAPABLE_DONE:
			break;
		case LWS_SSL_CAPABLE_ERROR:
			lws_stats_bump(pt, LWSSTATS_C_SSL_CONNECTIONS_FAILED, 1);
	                lwsl_info("SSL_accept failed socket %u: %d\n",
	                		wsi->desc.sockfd, n);
			wsi->socket_is_permanently_unusable = 1;
			goto fail;

		default: /* MORE_SERVICE */
			return 0;
		}

		lws_stats_bump(pt, LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED, 1);
#if defined(LWS_WITH_STATS)
		if (wsi->accept_start_us)
			lws_stats_bump(pt,
				      LWSSTATS_US_SSL_ACCEPT_LATENCY_AVG,
				      lws_now_usecs() -
					      wsi->accept_start_us);
		wsi->accept_start_us = lws_now_usecs();
#endif
#if defined(LWS_WITH_DETAILED_LATENCY)
		if (context->detailed_latency_cb) {
			wsi->detlat.type = LDLT_TLS_NEG_SERVER;
			wsi->detlat.latencies[LAT_DUR_PROXY_RX_TO_ONWARD_TX] =
				lws_now_usecs() -
				wsi->detlat.earliest_write_req_pre_write;
			wsi->detlat.latencies[LAT_DUR_USERCB] = 0;
			lws_det_lat_cb(wsi->context, &wsi->detlat);
		}
#endif

		/* adapt our vhost to match the SNI SSL_CTX that was chosen */
		vh = context->vhost_list;
		while (vh) {
			if (!vh->being_destroyed && wsi->tls.ssl &&
			    vh->tls.ssl_ctx == lws_tls_ctx_from_wsi(wsi)) {
				lwsl_info("setting wsi to vh %s\n", vh->name);
				lws_vhost_bind_wsi(vh, wsi);
				break;
			}
			vh = vh->vhost_next;
		}

		/* OK, we are accepted... give him some time to negotiate */
		lws_set_timeout(wsi, PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
				context->timeout_secs);

		lwsi_set_state(wsi, LRS_ESTABLISHED);
		if (lws_tls_server_conn_alpn(wsi))
			goto fail;
		lwsl_debug("accepted new SSL conn\n");
		break;

	default:
		break;
	}

	return 0;

notls_accepted:
	lwsi_set_state(wsi, LRS_ESTABLISHED);

	return 0;

fail:
	return 1;
}

