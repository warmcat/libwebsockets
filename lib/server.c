/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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

int
lws_context_init_server(struct lws_context_creation_info *info,
			struct lws_context *context)
{
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 serv_addr6;
#endif
#if LWS_POSIX
	struct sockaddr_in serv_addr4;
	socklen_t len = sizeof(struct sockaddr);
	int n, opt = 1, limit = 1;
	struct sockaddr_in sin;
	struct sockaddr *v;
#endif
	lws_sockfd_type sockfd;
	struct lws *wsi;
	int m = 0;

	/* set up our external listening socket we serve on */

	if (info->port == CONTEXT_PORT_NO_LISTEN)
		return 0;

#if LWS_POSIX
#if defined(__linux__)
	limit = context->count_threads;
#endif

	for (m = 0; m < limit; m++) {
#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context))
		sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	else
#endif
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == -1) {
#else
	sockfd = mbed3_create_tcp_stream_socket();
	if (!lws_sockfd_valid(sockfd)) {
#endif
		lwsl_err("ERROR opening socket\n");
		return 1;
	}

#if LWS_POSIX
	/*
	 * allow us to restart even if old sockets in TIME_WAIT
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&opt, sizeof(opt)) < 0) {
		compatible_close(sockfd);
		return 1;
	}
#if defined(__linux__) && defined(SO_REUSEPORT) && LWS_MAX_SMP > 1
	if (context->count_threads > 1)
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
				(const void *)&opt, sizeof(opt)) < 0) {
			compatible_close(sockfd);
			return 1;
		}
#endif
#endif
	lws_plat_set_socket_options(context, sockfd);

#if LWS_POSIX
#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context)) {
		v = (struct sockaddr *)&serv_addr6;
		n = sizeof(struct sockaddr_in6);
		bzero((char *) &serv_addr6, sizeof(serv_addr6));
		serv_addr6.sin6_addr = in6addr_any;
		serv_addr6.sin6_family = AF_INET6;
		serv_addr6.sin6_port = htons(info->port);
	} else
#endif
	{
		v = (struct sockaddr *)&serv_addr4;
		n = sizeof(serv_addr4);
		bzero((char *) &serv_addr4, sizeof(serv_addr4));
		serv_addr4.sin_addr.s_addr = INADDR_ANY;
		serv_addr4.sin_family = AF_INET;

		if (info->iface && interface_to_sa(context, info->iface,
				   (struct sockaddr_in *)v, n) < 0) {
			lwsl_err("Unable to find interface %s\n", info->iface);
			goto bail;
		}

		serv_addr4.sin_port = htons(info->port);
	} /* ipv4 */

	n = bind(sockfd, v, n);
	if (n < 0) {
		lwsl_err("ERROR on binding to port %d (%d %d)\n",
					      info->port, n, LWS_ERRNO);
		goto bail;
	}

	if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
		lwsl_warn("getsockname: %s\n", strerror(LWS_ERRNO));
	else
		info->port = ntohs(sin.sin_port);
#endif
	context->listen_port = info->port;

	wsi = lws_zalloc(sizeof(struct lws));
	if (wsi == NULL) {
		lwsl_err("Out of mem\n");
		goto bail;
	}
	wsi->context = context;
	wsi->sock = sockfd;
	wsi->mode = LWSCM_SERVER_LISTENER;
	wsi->protocol = context->protocols;
	wsi->tsi = m;

	context->pt[m].wsi_listening = wsi;
	if (insert_wsi_socket_into_fds(context, wsi))
		goto bail;

	context->pt[m].lserv_fd = sockfd;

#if LWS_POSIX
	listen(wsi->sock, LWS_SOMAXCONN);
	} /* for each thread able to independently lister */
#else
	mbed3_tcp_stream_bind(wsi->sock, info->port, wsi);
#endif
	lwsl_notice(" Listening on port %d\n", info->port);

	return 0;

bail:
	compatible_close(sockfd);

	return 1;
}

int
_lws_server_listen_accept_flow_control(struct lws *twsi, int on)
{
	struct lws_context_per_thread *pt = &twsi->context->pt[(int)twsi->tsi];
	struct lws *wsi = pt->wsi_listening;
	int n;

	if (!wsi || twsi->context->being_destroyed)
		return 0;

	lwsl_debug("%s: Thr %d: LISTEN wsi %p: state %d\n",
		   __func__, twsi->tsi, (void *)wsi, on);

	if (on)
		n = lws_change_pollfd(wsi, 0, LWS_POLLIN);
	else
		n = lws_change_pollfd(wsi, LWS_POLLIN, 0);

	return n;
}

int
lws_http_action(struct lws *wsi)
{
	enum http_connection_type connection_type;
	enum http_version request_version;
	char content_length_str[32];
	unsigned int n, count = 0;
	char http_version_str[10];
	char http_conn_str[20];
	int http_version_len;
	char *uri_ptr = NULL;
	int uri_len = 0;

	static const unsigned char methods[] = {
		WSI_TOKEN_GET_URI,
		WSI_TOKEN_POST_URI,
		WSI_TOKEN_OPTIONS_URI,
		WSI_TOKEN_PUT_URI,
		WSI_TOKEN_PATCH_URI,
		WSI_TOKEN_DELETE_URI,
#ifdef LWS_USE_HTTP2
		WSI_TOKEN_HTTP_COLON_PATH,
#endif
	};
#ifdef _DEBUG
	static const char * const method_names[] = {
		"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE",
#ifdef LWS_USE_HTTP2
		":path",
#endif
	};
#endif

	/* it's not websocket.... shall we accept it as http? */

	for (n = 0; n < ARRAY_SIZE(methods); n++)
		if (lws_hdr_total_length(wsi, methods[n]))
			count++;
	if (!count) {
		lwsl_warn("Missing URI in HTTP request\n");
		goto bail_nuke_ah;
	}

	if (count != 1) {
		lwsl_warn("multiple methods?\n");
		goto bail_nuke_ah;
	}

	if (lws_ensure_user_space(wsi))
		goto bail_nuke_ah;

	for (n = 0; n < ARRAY_SIZE(methods); n++)
		if (lws_hdr_total_length(wsi, methods[n])) {
			uri_ptr = lws_hdr_simple_ptr(wsi, methods[n]);
			uri_len = lws_hdr_total_length(wsi, methods[n]);
			lwsl_info("Method: %s request for '%s'\n",
				  	method_names[n], uri_ptr);
			break;
		}

	/* HTTP header had a content length? */

	wsi->u.http.content_length = 0;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) ||
		lws_hdr_total_length(wsi, WSI_TOKEN_PATCH_URI) ||
		lws_hdr_total_length(wsi, WSI_TOKEN_PUT_URI))
		wsi->u.http.content_length = 100 * 1024 * 1024;

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		lws_hdr_copy(wsi, content_length_str,
			     sizeof(content_length_str) - 1,
			     WSI_TOKEN_HTTP_CONTENT_LENGTH);
		wsi->u.http.content_length = atoi(content_length_str);
	}

	/* http_version? Default to 1.0, override with token: */
	request_version = HTTP_VERSION_1_0;

	/* Works for single digit HTTP versions. : */
	http_version_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP);
	if (http_version_len > 7) {
		lws_hdr_copy(wsi, http_version_str,
				sizeof(http_version_str) - 1, WSI_TOKEN_HTTP);
		if (http_version_str[5] == '1' && http_version_str[7] == '1')
			request_version = HTTP_VERSION_1_1;
	}
	wsi->u.http.request_version = request_version;

	/* HTTP/1.1 defaults to "keep-alive", 1.0 to "close" */
	if (request_version == HTTP_VERSION_1_1)
		connection_type = HTTP_CONNECTION_KEEP_ALIVE;
	else
		connection_type = HTTP_CONNECTION_CLOSE;

	/* Override default if http "Connection:" header: */
	if (lws_hdr_total_length(wsi, WSI_TOKEN_CONNECTION)) {
		lws_hdr_copy(wsi, http_conn_str, sizeof(http_conn_str) - 1,
			     WSI_TOKEN_CONNECTION);
		http_conn_str[sizeof(http_conn_str) - 1] = '\0';
		if (!strcasecmp(http_conn_str, "keep-alive"))
			connection_type = HTTP_CONNECTION_KEEP_ALIVE;
		else
			if (!strcasecmp(http_conn_str, "close"))
				connection_type = HTTP_CONNECTION_CLOSE;
	}
	wsi->u.http.connection_type = connection_type;

	n = wsi->protocol->callback(wsi, LWS_CALLBACK_FILTER_HTTP_CONNECTION,
				    wsi->user_space, uri_ptr, uri_len);

	if (!n) {
		/*
		 * if there is content supposed to be coming,
		 * put a timeout on it having arrived
		 */
		lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
				AWAITING_TIMEOUT);

		n = wsi->protocol->callback(wsi, LWS_CALLBACK_HTTP,
					    wsi->user_space, uri_ptr, uri_len);
	}

	/*
	 * If we are in keepalive, we may already have the next header set
	 * pipelined in the lws_read buffer above us... if so, we must hold
	 * the ah so it's still bound when we want to process the next headers.
	 *
	 */
	if (connection_type == HTTP_CONNECTION_CLOSE ||
	    !wsi->u.hdr.more_rx_waiting)
		/* now drop the header info we kept a pointer to */
		lws_free_header_table(wsi);

	if (n) {
		lwsl_info("LWS_CALLBACK_HTTP closing\n");
		return 1; /* struct ah ptr already nuked */		}

	/*
	 * If we're not issuing a file, check for content_length or
	 * HTTP keep-alive. No keep-alive header allocation for
	 * ISSUING_FILE, as this uses HTTP/1.0.
	 *
	 * In any case, return 0 and let lws_read decide how to
	 * proceed based on state
	 */
	if (wsi->state != LWSS_HTTP_ISSUING_FILE)
		/* Prepare to read body if we have a content length: */
		if (wsi->u.http.content_length > 0)
			wsi->state = LWSS_HTTP_BODY;

	return 0;

bail_nuke_ah:
	lws_free_header_table(wsi);

	return 1;
}


int
lws_handshake_server(struct lws *wsi, unsigned char **buf, size_t len)
{
	struct lws_context *context = lws_get_context(wsi);
	struct allocated_headers *ah;
	int protocol_len, n, hit;
	char protocol_list[128];
	char protocol_name[32];
	char *p;

	assert(wsi->u.hdr.ah);

	while (len--) {
		wsi->u.hdr.more_rx_waiting = !!len;

		assert(wsi->mode == LWSCM_HTTP_SERVING);

		if (lws_parse(wsi, *(*buf)++)) {
			lwsl_info("lws_parse failed\n");
			goto bail_nuke_ah;
		}

		if (wsi->u.hdr.parser_state != WSI_PARSING_COMPLETE)
			continue;

		lwsl_parser("lws_parse sees parsing complete\n");

		wsi->mode = LWSCM_PRE_WS_SERVING_ACCEPT;
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* is this websocket protocol or normal http 1.0? */

		if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
			if (!strcasecmp(lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE),
					"websocket")) {
				lwsl_info("Upgrade to ws\n");
				goto upgrade_ws;
			}
#ifdef LWS_USE_HTTP2
			if (!strcasecmp(lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE),
					"h2c-14")) {
				lwsl_info("Upgrade to h2c-14\n");
				goto upgrade_h2c;
			}
#endif
			lwsl_err("Unknown upgrade\n");
			/* dunno what he wanted to upgrade to */
			goto bail_nuke_ah;
		}

		/* no upgrade ack... he remained as HTTP */

		lwsl_info("No upgrade\n");
		ah = wsi->u.hdr.ah;

		lws_union_transition(wsi, LWSCM_HTTP_SERVING_ACCEPTED);
		wsi->state = LWSS_HTTP;
		wsi->u.http.fd = LWS_INVALID_FILE;

		/* expose it at the same offset as u.hdr */
		wsi->u.http.ah = ah;
		lwsl_debug("%s: wsi %p: ah %p\n", __func__, (void *)wsi, (void *)wsi->u.hdr.ah);

		n = lws_http_action(wsi);

		return n;

#ifdef LWS_USE_HTTP2
upgrade_h2c:
		if (!lws_hdr_total_length(wsi, WSI_TOKEN_HTTP2_SETTINGS)) {
			lwsl_err("missing http2_settings\n");
			goto bail_nuke_ah;
		}

		lwsl_err("h2c upgrade...\n");

		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP2_SETTINGS);
		/* convert the peer's HTTP-Settings */
		n = lws_b64_decode_string(p, protocol_list,
					  sizeof(protocol_list));
		if (n < 0) {
			lwsl_parser("HTTP2_SETTINGS too long\n");
			return 1;
		}

		/* adopt the header info */

		ah = wsi->u.hdr.ah;

		lws_union_transition(wsi, LWSCM_HTTP2_SERVING);

		/* http2 union member has http union struct at start */
		wsi->u.http.ah = ah;

		lws_http2_init(&wsi->u.http2.peer_settings);
		lws_http2_init(&wsi->u.http2.my_settings);

		/* HTTP2 union */

		lws_http2_interpret_settings_payload(&wsi->u.http2.peer_settings,
				(unsigned char *)protocol_list, n);

		strcpy(protocol_list,
		       "HTTP/1.1 101 Switching Protocols\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Upgrade: h2c\x0d\x0a\x0d\x0a");
		n = lws_issue_raw(wsi, (unsigned char *)protocol_list,
					strlen(protocol_list));
		if (n != strlen(protocol_list)) {
			lwsl_debug("http2 switch: ERROR writing to socket\n");
			return 1;
		}

		wsi->state = LWSS_HTTP2_AWAIT_CLIENT_PREFACE;

		return 0;
#endif

upgrade_ws:
		if (!wsi->protocol)
			lwsl_err("NULL protocol at lws_read\n");

		/*
		 * It's websocket
		 *
		 * Select the first protocol we support from the list
		 * the client sent us.
		 *
		 * Copy it to remove header fragmentation
		 */

		if (lws_hdr_copy(wsi, protocol_list, sizeof(protocol_list) - 1,
				 WSI_TOKEN_PROTOCOL) < 0) {
			lwsl_err("protocol list too long");
			goto bail_nuke_ah;
		}

		protocol_len = lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL);
		protocol_list[protocol_len] = '\0';
		p = protocol_list;
		hit = 0;

		while (*p && !hit) {
			unsigned int n = 0;
			while (n < sizeof(protocol_name) - 1 && *p && *p !=',')
				protocol_name[n++] = *p++;
			protocol_name[n] = '\0';
			if (*p)
				p++;

			lwsl_info("checking %s\n", protocol_name);

			n = 0;
			while (context->protocols[n].callback) {
				if (context->protocols[n].name &&
				    !strcmp(context->protocols[n].name,
					    protocol_name)) {
					lwsl_info("prot match %d\n", n);
					wsi->protocol = &context->protocols[n];
					hit = 1;
					break;
				}

				n++;
			}
		}

		/* we didn't find a protocol he wanted? */

		if (!hit) {
			if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL)) {
				lwsl_err("No protocol from \"%s\" supported\n",
					 protocol_list);
				goto bail_nuke_ah;
			}
			/*
			 * some clients only have one protocol and
			 * do not sent the protocol list header...
			 * allow it and match to protocol 0
			 */
			lwsl_info("defaulting to prot 0 handler\n");
			wsi->protocol = &context->protocols[0];
		}

		/* allocate wsi->user storage */
		if (lws_ensure_user_space(wsi))
			goto bail_nuke_ah;

		/*
		 * Give the user code a chance to study the request and
		 * have the opportunity to deny it
		 */

		if ((wsi->protocol->callback)(wsi,
				LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
				wsi->user_space,
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL), 0)) {
			lwsl_warn("User code denied connection\n");
			goto bail_nuke_ah;
		}

		/*
		 * Perform the handshake according to the protocol version the
		 * client announced
		 */

		switch (wsi->ietf_spec_revision) {
		case 13:
			lwsl_parser("lws_parse calling handshake_04\n");
			if (handshake_0405(context, wsi)) {
				lwsl_info("hs0405 has failed the connection\n");
				goto bail_nuke_ah;
			}
			break;

		default:
			lwsl_warn("Unknown client spec version %d\n",
						       wsi->ietf_spec_revision);
			goto bail_nuke_ah;
		}

		/* drop the header info -- no bail_nuke_ah after this */
		lws_free_header_table(wsi);

		lws_union_transition(wsi, LWSCM_WS_SERVING);

		/*
		 * create the frame buffer for this connection according to the
		 * size mentioned in the protocol definition.  If 0 there, use
		 * a big default for compatibility
		 */

		n = wsi->protocol->rx_buffer_size;
		if (!n)
			n = LWS_MAX_SOCKET_IO_BUF;
		n += LWS_PRE;
		wsi->u.ws.rx_ubuf = lws_malloc(n + 4 /* 0x0000ffff zlib */);
		if (!wsi->u.ws.rx_ubuf) {
			lwsl_err("Out of Mem allocating rx buffer %d\n", n);
			return 1;
		}
		wsi->u.ws.rx_ubuf_alloc = n;
		lwsl_info("Allocating RX buffer %d\n", n);
#if LWS_POSIX
		if (setsockopt(wsi->sock, SOL_SOCKET, SO_SNDBUF,
			       (const char *)&n, sizeof n)) {
			lwsl_warn("Failed to set SNDBUF to %d", n);
			return 1;
		}
#endif
		lwsl_parser("accepted v%02d connection\n", wsi->ietf_spec_revision);

		return 0;
	} /* while all chars are handled */

	return 0;

bail_nuke_ah:
	/* drop the header info */
	lws_free_header_table(wsi);
	return 1;
}

static int
lws_get_idlest_tsi(struct lws_context *context)
{
	unsigned int lowest = ~0;
	int n = 0, hit = -1;

	for (; n < context->count_threads; n++) {
		if ((unsigned int)context->pt[n].fds_count != context->fd_limit_per_thread - 1 &&
		    (unsigned int)context->pt[n].fds_count < lowest) {
			lowest = context->pt[n].fds_count;
			hit = n;
		}
	}

	return hit;
}

struct lws *
lws_create_new_server_wsi(struct lws_context *context)
{
	struct lws *new_wsi;
	int n = lws_get_idlest_tsi(context);

	if (n < 0) {
		lwsl_err("no space for new conn\n");
		return NULL;
	}

	new_wsi = lws_zalloc(sizeof(struct lws));
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->tsi = n;
	lwsl_info("Accepted %p to tsi %d\n", new_wsi, new_wsi->tsi);

	new_wsi->context = context;
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;
	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/* intialize the instance struct */

	new_wsi->state = LWSS_HTTP;
	new_wsi->mode = LWSCM_HTTP_SERVING;
	new_wsi->hdr_parsing_completed = 0;

#ifdef LWS_OPENSSL_SUPPORT
	new_wsi->use_ssl = LWS_SSL_ENABLED(context);
#endif

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = context->protocols;
	new_wsi->user_space = NULL;
	new_wsi->ietf_spec_revision = 0;
	new_wsi->sock = LWS_SOCK_INVALID;


	/*
	 * outermost create notification for wsi
	 * no user_space because no protocol selection
	 */
	context->protocols[0].callback(new_wsi, LWS_CALLBACK_WSI_CREATE,
				       NULL, NULL, 0);

	return new_wsi;
}

/**
 * lws_http_transaction_completed() - wait for new http transaction or close
 * @wsi:	websocket connection
 *
 *	Returns 1 if the HTTP connection must close now
 *	Returns 0 and resets connection to wait for new HTTP header /
 *	  transaction if possible
 */

LWS_VISIBLE int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed(struct lws *wsi)
{
	lwsl_debug("%s: wsi %p\n", __func__, wsi);
	/* if we can't go back to accept new headers, drop the connection */
	if (wsi->u.http.connection_type != HTTP_CONNECTION_KEEP_ALIVE) {
		lwsl_info("%s: %p: close connection\n", __func__, wsi);
		return 1;
	}

	/* otherwise set ourselves up ready to go again */
	wsi->state = LWSS_HTTP;
	wsi->mode = LWSCM_HTTP_SERVING;
	wsi->u.http.content_length = 0;
	wsi->hdr_parsing_completed = 0;

	/* He asked for it to stay alive indefinitely */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	/*
	 * We already know we are on http1.1 / keepalive and the next thing
	 * coming will be another header set.
	 *
	 * If there is no pending rx and we still have the ah, drop it and
	 * reacquire a new ah when the new headers start to arrive.  (Otherwise
	 * we needlessly hog an ah indefinitely.)
	 *
	 * However if there is pending rx and we know from the keepalive state
	 * that is already at least the start of another header set, simply
	 * reset the existing header table and keep it.
	 */
	if (!wsi->u.hdr.more_rx_waiting)
		lws_free_header_table(wsi);
	else
		lws_reset_header_table(wsi);

	/* If we're (re)starting on headers, need other implied init */
	wsi->u.hdr.ues = URIES_IDLE;

	lwsl_info("%s: %p: keep-alive await new transaction\n", __func__, wsi);

	return 0;
}

/**
 * lws_adopt_socket() - adopt foreign socket as if listen socket accepted it
 * @context: lws context
 * @accept_fd: fd of already-accepted socket to adopt
 *
 * Either returns new wsi bound to accept_fd, or closes accept_fd and
 * returns NULL, having cleaned up any new wsi pieces.
 *
 * LWS adopts the socket in http serving mode, it's ready to accept an upgrade
 * to ws or just serve http.
 */

LWS_VISIBLE struct lws *
lws_adopt_socket(struct lws_context *context, lws_sockfd_type accept_fd)
{
	struct lws *new_wsi = lws_create_new_server_wsi(context);

	if (!new_wsi) {
		compatible_close(accept_fd);
		return NULL;
	}

	new_wsi->sock = accept_fd;

	/* the transport is accepted... give him time to negotiate */
	lws_set_timeout(new_wsi, PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
			AWAITING_TIMEOUT);

#if LWS_POSIX == 0
	mbed3_tcp_stream_accept(accept_fd, new_wsi);
#endif

	/*
	 * A new connection was accepted. Give the user a chance to
	 * set properties of the newly created wsi. There's no protocol
	 * selected yet so we issue this to protocols[0]
	 */
	if ((context->protocols[0].callback)(new_wsi,
	     LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, NULL, NULL, 0)) {
		compatible_close(new_wsi->sock);
		lws_free(new_wsi);
		return NULL;
	}

	lws_libev_accept(new_wsi, new_wsi->sock);

	if (!LWS_SSL_ENABLED(context)) {
		if (insert_wsi_socket_into_fds(context, new_wsi))
			goto fail;
	} else {
		new_wsi->mode = LWSCM_SSL_INIT;
		if (lws_server_socket_service_ssl(new_wsi, accept_fd))
			goto fail;
	}

	return new_wsi;

fail:
	lwsl_err("%s: fail\n", __func__);
	lws_close_free_wsi(new_wsi, LWS_CLOSE_STATUS_NOSTATUS);

	return NULL;
}

LWS_VISIBLE int
lws_server_socket_service(struct lws_context *context, struct lws *wsi,
			  struct lws_pollfd *pollfd)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	lws_sockfd_type accept_fd = LWS_SOCK_INVALID;
#if LWS_POSIX
	struct sockaddr_in cli_addr;
	socklen_t clilen;
#endif

	int n, len;

	switch (wsi->mode) {

	case LWSCM_HTTP_SERVING:
	case LWSCM_HTTP_SERVING_ACCEPTED:
	case LWSCM_HTTP2_SERVING:

		/* handle http headers coming in */

		/* pending truncated sends have uber priority */

		if (wsi->trunc_len) {
			if (!(pollfd->revents & LWS_POLLOUT))
				break;

			if (lws_issue_raw(wsi, wsi->trunc_alloc + wsi->trunc_offset,
					  wsi->trunc_len) < 0)
				goto fail;
			/*
			 * we can't afford to allow input processing send
			 * something new, so spin around he event loop until
			 * he doesn't have any partials
			 */
			break;
		}

		/* any incoming data ready? */

		if (!(pollfd->revents & pollfd->events & LWS_POLLIN))
			goto try_pollout;

		if ((wsi->state == LWSS_HTTP ||
		     wsi->state == LWSS_HTTP_ISSUING_FILE ||
		     wsi->state == LWSS_HTTP_HEADERS) && !wsi->u.hdr.ah)
			if (lws_allocate_header_table(wsi))
				goto try_pollout;

		/*
		 * This is a good situation, the ah allocated and we know there
		 * is header data pending.  However, in http1.1 / keepalive
		 * case, back-to-back header sets pipelined into one packet
		 * is common.
		 *
		 * Ah is defined to be required to stay attached to the wsi
		 * until the current set of header data completes, which may
		 * involve network roundtrips if fragmented.  Typically the
		 * header set is not fragmented and gets done atomically.
		 *
		 * When we complete processing for the first header set, we
		 * normally drop the ah in lws_http_transaction_completed()
		 * since we do not know how long it would be held waiting for
		 * the start of the next header set to arrive.
		 *
		 * However if there is pending data, http1.1 / keepalive mode
		 * is active, we need to retain (just reset) the ah after
		 * dealing with each header set instead of dropping it.
		 *
		 * Otherwise the remaining header data has nowhere to be stored.
		 */

		len = lws_ssl_capable_read(wsi, pt->serv_buf,
					   LWS_MAX_SOCKET_IO_BUF);
		lwsl_debug("%s: wsi %p read %d\r\n", __func__, wsi, len);
		switch (len) {
		case 0:
			lwsl_info("%s: read 0 len\n", __func__);
			/* lwsl_info("   state=%d\n", wsi->state); */
			if (!wsi->hdr_parsing_completed)
				lws_free_header_table(wsi);
			/* fallthru */
		case LWS_SSL_CAPABLE_ERROR:
			goto fail;
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			goto try_pollout;
		}

		/* just ignore incoming if waiting for close */
		if (wsi->state != LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
			/*
			 * hm this may want to send
			 * (via HTTP callback for example)
			 */
			n = lws_read(wsi, pt->serv_buf, len);
			if (n < 0) /* we closed wsi */
				return 1;
			/* hum he may have used up the
			 * writability above */
			break;
		}

try_pollout:
		/* this handles POLLOUT for http serving fragments */

		if (!(pollfd->revents & LWS_POLLOUT))
			break;

		/* one shot */
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_notice("%s a\n", __func__);
			goto fail;
		}

		lws_libev_io(wsi, LWS_EV_STOP | LWS_EV_WRITE);

		if (wsi->state != LWSS_HTTP_ISSUING_FILE) {
			n = user_callback_handle_rxflow(wsi->protocol->callback,
					wsi, LWS_CALLBACK_HTTP_WRITEABLE,
					wsi->user_space, NULL, 0);
			if (n < 0) {
				lwsl_info("writeable_fail\n");
				goto fail;
			}
			break;
		}

		/* >0 == completion, <0 == error */
		n = lws_serve_http_file_fragment(wsi);
		if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi))) {
			lwsl_info("completed\n");
			goto fail;
		}
		break;

	case LWSCM_SERVER_LISTENER:

#if LWS_POSIX
		/* pollin means a client has connected to us then */

		do {
			if (!(pollfd->revents & LWS_POLLIN) || !(pollfd->events & LWS_POLLIN))
				break;

			/* listen socket got an unencrypted connection... */

			clilen = sizeof(cli_addr);
			lws_latency_pre(context, wsi);
			accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
					    &clilen);
			lws_latency(context, wsi, "listener accept", accept_fd,
				    accept_fd >= 0);
			if (accept_fd < 0) {
				if (LWS_ERRNO == LWS_EAGAIN ||
				    LWS_ERRNO == LWS_EWOULDBLOCK) {
					lwsl_err("accept asks to try again\n");
					break;
				}
				lwsl_err("ERROR on accept: %s\n", strerror(LWS_ERRNO));
				break;
			}

			lws_plat_set_socket_options(context, accept_fd);

			lwsl_debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), accept_fd);

#else
			/* not very beautiful... */
			accept_fd = (lws_sockfd_type)pollfd;
#endif
			/*
			 * look at who we connected to and give user code a chance
			 * to reject based on client IP.  There's no protocol selected
			 * yet so we issue this to protocols[0]
			 */
			if ((context->protocols[0].callback)(wsi,
					LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
					NULL, (void *)(long)accept_fd, 0)) {
				lwsl_debug("Callback denied network connection\n");
				compatible_close(accept_fd);
				break;
			}

			if (!lws_adopt_socket(context, accept_fd))
				/* already closed cleanly as necessary */
				return 1;

#if LWS_POSIX
		} while (pt->fds_count < context->fd_limit_per_thread - 1 &&
			 lws_poll_listen_fd(&pt->fds[wsi->position_in_fds_table]) > 0);
#endif
		return 0;

	default:
		break;
	}

	if (!lws_server_socket_service_ssl(wsi, accept_fd))
		return 0;

fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);

	return 1;
}

/**
 * lws_serve_http_file() - Send a file back to the client using http
 * @wsi:		Websocket instance (available from user callback)
 * @file:		The file to issue over http
 * @content_type:	The http content type, eg, text/html
 * @other_headers:	NULL or pointer to header string
 * @other_headers_len:	length of the other headers if non-NULL
 *
 *	This function is intended to be called from the callback in response
 *	to http requests from the client.  It allows the callback to issue
 *	local files down the http link in a single step.
 *
 *	Returning <0 indicates error and the wsi should be closed.  Returning
 *	>0 indicates the file was completely sent and
 *	lws_http_transaction_completed() called on the wsi (and close if != 0)
 *	==0 indicates the file transfer is started and needs more service later,
 *	the wsi should be left alone.
 */

LWS_VISIBLE int
lws_serve_http_file(struct lws *wsi, const char *file, const char *content_type,
		    const char *other_headers, int other_headers_len)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	unsigned char *response = pt->serv_buf + LWS_PRE;
	unsigned char *p = response;
	unsigned char *end = p + LWS_MAX_SOCKET_IO_BUF - LWS_PRE;
	int ret = 0;

	wsi->u.http.fd = lws_plat_file_open(wsi, file, &wsi->u.http.filelen,
					    O_RDONLY);

	if (wsi->u.http.fd == LWS_INVALID_FILE) {
		lwsl_err("Unable to open '%s'\n", file);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);

		return -1;
	}

	if (lws_add_http_header_status(wsi, 200, &p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER,
					 (unsigned char *)"libwebsockets", 13,
					 &p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (unsigned char *)content_type,
					 strlen(content_type), &p, end))
		return -1;
	if (lws_add_http_header_content_length(wsi, wsi->u.http.filelen, &p, end))
		return -1;

	if (other_headers) {
		if ((end - p) < other_headers_len)
			return -1;
		memcpy(p, other_headers, other_headers_len);
		p += other_headers_len;
	}

	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	ret = lws_write(wsi, response, p - response, LWS_WRITE_HTTP_HEADERS);
	if (ret != (p - response)) {
		lwsl_err("_write returned %d from %d\n", ret, (p - response));
		return -1;
	}

	wsi->u.http.filepos = 0;
	wsi->state = LWSS_HTTP_ISSUING_FILE;

	return lws_serve_http_file_fragment(wsi);
}

int
lws_interpret_incoming_packet(struct lws *wsi, unsigned char **buf, size_t len)
{
	int m;

	lwsl_parser("%s: received %d byte packet\n", __func__, (int)len);
#if 0
	lwsl_hexdump(*buf, len);
#endif

	/* let the rx protocol state machine have as much as it needs */

	while (len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (!(wsi->rxflow_change_to & LWS_RXFLOW_ALLOW)) {
			lws_rxflow_cache(wsi, *buf, 0, len);
			lwsl_parser("%s: cached %d\n", __func__, len);
			return 1;
		}

		if (wsi->u.ws.rx_draining_ext) {
			m = lws_rx_sm(wsi, 0);
			if (m < 0)
				return -1;
			continue;
		}

		/* account for what we're using in rxflow buffer */
		if (wsi->rxflow_buffer)
			wsi->rxflow_pos++;

		/* process the byte */
		m = lws_rx_sm(wsi, *(*buf)++);
		if (m < 0)
			return -1;
		len--;
	}

	lwsl_parser("%s: exit with %d unused\n", __func__, (int)len);

	return 0;
}

LWS_VISIBLE void
lws_server_get_canonical_hostname(struct lws_context *context,
				  struct lws_context_creation_info *info)
{
	if (info->options & LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME)
		return;
#if LWS_POSIX
	/* find canonical hostname */
	gethostname((char *)context->canonical_hostname,
		    sizeof(context->canonical_hostname) - 1);

	lwsl_notice(" canonical_hostname = %s\n", context->canonical_hostname);
#else
	(void)context;
#endif
}
