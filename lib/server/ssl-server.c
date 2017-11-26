/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "private-libwebsockets.h"

LWS_VISIBLE int
lws_context_init_server_ssl(struct lws_context_creation_info *info,
			    struct lws_vhost *vhost)
{
	struct lws_context *context = vhost->context;
	struct lws wsi;

	if (!lws_check_opt(info->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		vhost->use_ssl = 0;

		return 0;
	}

	/*
	 * If he is giving a cert filepath, take it as a sign he wants to use
	 * it on this vhost.  User code can leave the cert filepath NULL and
	 * set the LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX option itself, in
	 * which case he's expected to set up the cert himself at
	 * LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, which
	 * provides the vhost SSL_CTX * in the user parameter.
	 */
	if (info->ssl_cert_filepath)
		info->options |= LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX;

	if (info->port != CONTEXT_PORT_NO_LISTEN) {

		vhost->use_ssl = lws_check_opt(info->options,
					LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX);

		if (vhost->use_ssl && info->ssl_cipher_list)
			lwsl_notice(" SSL ciphers: '%s'\n",
						info->ssl_cipher_list);

		if (vhost->use_ssl)
			lwsl_notice(" Using SSL mode\n");
		else
			lwsl_notice(" Using non-SSL mode\n");
	}

	/*
	 * give him a fake wsi with context + vhost set, so he can use
	 * lws_get_context() in the callback
	 */
	memset(&wsi, 0, sizeof(wsi));
	wsi.vhost = vhost;
	wsi.context = context;

	/*
	 * as a server, if we are requiring clients to identify themselves
	 * then set the backend up for it
	 */
	if (lws_check_opt(info->options,
			  LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT))
		/* Normally SSL listener rejects non-ssl, optionally allow */
		vhost->allow_non_ssl_on_ssl_port = 1;

	/*
	 * give user code a chance to load certs into the server
	 * allowing it to verify incoming client certs
	 */
	if (vhost->use_ssl) {
		if (lws_tls_server_vhost_backend_init(info, vhost, &wsi))
			return -1;

		lws_tls_server_client_cert_verify_config(vhost);

		if (vhost->protocols[0].callback(&wsi,
			    LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
			    vhost->ssl_ctx, vhost, 0))
			return -1;
	}

	if (vhost->use_ssl)
		/*
		 * SSL is happy and has a cert it's content with
		 * If we're supporting HTTP2, initialize that
		 */
		lws_context_init_http2_ssl(vhost);

	return 0;
}

LWS_VISIBLE int
lws_server_socket_service_ssl(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_context *context = wsi->context;
	struct lws_vhost *vh;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n;
        char buf[256];

        (void)buf;

	if (!LWS_SSL_ENABLED(wsi->vhost))
		return 0;

	switch (wsi->mode) {
	case LWSCM_SSL_INIT:
	case LWSCM_SSL_INIT_RAW:
		if (wsi->ssl)
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

		//lwsl_notice("%s: ssl restr %d, simul %d\n", __func__,
		//		context->simultaneous_ssl_restriction,
		//		context->simultaneous_ssl);

#if defined(LWS_WITH_STATS)
	context->updated = 1;
#endif
		/*
		 * we are not accepted yet, but we need to enter ourselves
		 * as a live connection.  That way we can retry when more
		 * pieces come if we're not sorted yet
		 */
		if (wsi->mode == LWSCM_SSL_INIT)
			wsi->mode = LWSCM_SSL_ACK_PENDING;
		else
			wsi->mode = LWSCM_SSL_ACK_PENDING_RAW;

		if (insert_wsi_socket_into_fds(context, wsi)) {
			lwsl_err("%s: failed to insert into fds\n", __func__);
			goto fail;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_SSL_ACCEPT,
				context->timeout_secs);

		lwsl_debug("inserted SSL accept into fds, trying SSL_accept\n");

		/* fallthru */

	case LWSCM_SSL_ACK_PENDING:
	case LWSCM_SSL_ACK_PENDING_RAW:
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_err("%s: lws_change_pollfd failed\n", __func__);
			goto fail;
		}

		lws_latency_pre(context, wsi);

		if (wsi->vhost->allow_non_ssl_on_ssl_port) {

			n = recv(wsi->desc.sockfd, (char *)pt->serv_buf,
				 context->pt_serv_buf_size, MSG_PEEK);

		/*
		 * optionally allow non-SSL connect on SSL listening socket
		 * This is disabled by default, if enabled it goes around any
		 * SSL-level access control (eg, client-side certs) so leave
		 * it disabled unless you know it's not a problem for you
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
				wsi->use_ssl = 0;

				lws_tls_server_abort_connection(wsi);
				wsi->ssl = NULL;
				if (lws_check_opt(context->options,
				    LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS))
					wsi->redirect_to_https = 1;
				goto accepted;
			}
			if (!n) /*
				 * connection is gone, or nothing to read
				 * if it's gone, we will timeout on
				 * PENDING_TIMEOUT_SSL_ACCEPT
				 */
				break;
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
		if (!wsi->accept_start_us)
			wsi->accept_start_us = time_in_microseconds();
#endif
		errno = 0;
		lws_stats_atomic_bump(wsi->context, pt,
				      LWSSTATS_C_SSL_CONNECTIONS_ACCEPT_SPIN, 1);
		n = lws_tls_server_accept(wsi);
		lws_latency(context, wsi,
			"SSL_accept LWSCM_SSL_ACK_PENDING\n", n, n == 1);
		lwsl_info("SSL_accept says %d\n", n);
		switch (n) {
		case LWS_SSL_CAPABLE_DONE:
			break;
		case LWS_SSL_CAPABLE_ERROR:
			lws_stats_atomic_bump(wsi->context, pt,
					      LWSSTATS_C_SSL_CONNECTIONS_FAILED, 1);
	                lwsl_info("SSL_accept failed socket %u: %d\n",
	                		wsi->desc.sockfd, n);
			goto fail;

		default: /* MORE_SERVICE */
			return 0;
		}

		lws_stats_atomic_bump(wsi->context, pt,
				      LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED, 1);
#if defined(LWS_WITH_STATS)
		lws_stats_atomic_bump(wsi->context, pt,
				      LWSSTATS_MS_SSL_CONNECTIONS_ACCEPTED_DELAY,
				      time_in_microseconds() - wsi->accept_start_us);
		wsi->accept_start_us = time_in_microseconds();
#endif

accepted:

		/* adapt our vhost to match the SNI SSL_CTX that was chosen */
		vh = context->vhost_list;
		while (vh) {
			if (!vh->being_destroyed &&
			    vh->ssl_ctx == lws_tls_ctx_from_wsi(wsi)) {
				lwsl_info("setting wsi to vh %s\n", vh->name);
				wsi->vhost = vh;
				break;
			}
			vh = vh->vhost_next;
		}

		/* OK, we are accepted... give him some time to negotiate */
		lws_set_timeout(wsi, PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
				context->timeout_secs);

		if (wsi->mode == LWSCM_SSL_ACK_PENDING_RAW)
			wsi->mode = LWSCM_RAW;
		else
			wsi->mode = LWSCM_HTTP_SERVING;
#if defined(LWS_WITH_HTTP2)
		if (lws_h2_configure_if_upgraded(wsi))
			goto fail;
#endif
		lwsl_debug("accepted new SSL conn\n");
		break;
	}

	return 0;

fail:
	return 1;
}

