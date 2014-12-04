/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
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

int lws_context_init_server(struct lws_context_creation_info *info,
			    struct libwebsocket_context *context)
{
	int n;
	int sockfd;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	int opt = 1;
	struct libwebsocket *wsi;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 serv_addr6;
#endif
	struct sockaddr_in serv_addr4;
	struct sockaddr *v;

	/* set up our external listening socket we serve on */

	if (info->port == CONTEXT_PORT_NO_LISTEN)
		return 0;

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context))
		sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	else
#endif
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		lwsl_err("ERROR opening socket\n");
		return 1;
	}

	/*
	 * allow us to restart even if old sockets in TIME_WAIT
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
				      (const void *)&opt, sizeof(opt)) < 0) {
		compatible_close(sockfd);
		return 1;
	}

	lws_plat_set_socket_options(context, sockfd);

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

		if (info->iface) {
			if (interface_to_sa(context, info->iface,
				   (struct sockaddr_in *)v, n) < 0) {
				lwsl_err("Unable to find interface %s\n",
							info->iface);
				compatible_close(sockfd);
				return 1;
			}
		}

		serv_addr4.sin_port = htons(info->port);
	} /* ipv4 */

	n = bind(sockfd, v, n);
	if (n < 0) {
		lwsl_err("ERROR on binding to port %d (%d %d)\n",
					      info->port, n, LWS_ERRNO);
		compatible_close(sockfd);
		return 1;
	}

	if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
		lwsl_warn("getsockname: %s\n", strerror(LWS_ERRNO));
	else
		info->port = ntohs(sin.sin_port);

	context->listen_port = info->port;

	wsi = lws_zalloc(sizeof(struct libwebsocket));
	if (wsi == NULL) {
		lwsl_err("Out of mem\n");
		compatible_close(sockfd);
		return 1;
	}
	wsi->sock = sockfd;
	wsi->mode = LWS_CONNMODE_SERVER_LISTENER;

	insert_wsi_socket_into_fds(context, wsi);

	context->listen_service_modulo = LWS_LISTEN_SERVICE_MODULO;
	context->listen_service_count = 0;
	context->listen_service_fd = sockfd;

	listen(sockfd, LWS_SOMAXCONN);
	lwsl_notice(" Listening on port %d\n", info->port);

	return 0;
}

int
_libwebsocket_rx_flow_control(struct libwebsocket *wsi)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;

	/* there is no pending change */
	if (!(wsi->rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE))
		return 0;

	/* stuff is still buffered, not ready to really accept new input */
	if (wsi->rxflow_buffer) {
		/* get ourselves called back to deal with stashed buffer */
		libwebsocket_callback_on_writable(context, wsi);
		return 0;
	}

	/* pending is cleared, we can change rxflow state */

	wsi->rxflow_change_to &= ~LWS_RXFLOW_PENDING_CHANGE;

	lwsl_info("rxflow: wsi %p change_to %d\n", wsi,
			      wsi->rxflow_change_to & LWS_RXFLOW_ALLOW);

	/* adjust the pollfd for this wsi */

	if (wsi->rxflow_change_to & LWS_RXFLOW_ALLOW) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: fail\n", __func__);
			return -1;
		}
	} else
		if (lws_change_pollfd(wsi, LWS_POLLIN, 0))
			return -1;

	return 0;
}

int lws_http_action(struct libwebsocket_context *context,
		    struct libwebsocket *wsi)
{
	char *uri_ptr = NULL;
	int uri_len = 0;
	enum http_version request_version;
	enum http_connection_type connection_type;
	int http_version_len;
	char content_length_str[32];
	char http_version_str[10];
	char http_conn_str[20];
	int n;

	/* it's not websocket.... shall we accept it as http? */

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) &&
		!lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) &&
#ifdef LWS_USE_HTTP2
		!lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_PATH) &&
#endif
		!lws_hdr_total_length(wsi, WSI_TOKEN_OPTIONS_URI)) {
		lwsl_warn("Missing URI in HTTP request\n");
		goto bail_nuke_ah;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) &&
		lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
		lwsl_warn("GET and POST methods?\n");
		goto bail_nuke_ah;
	}

	if (libwebsocket_ensure_user_space(wsi))
		goto bail_nuke_ah;

#ifdef LWS_USE_HTTP2
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_PATH)) {
		uri_ptr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_PATH);
		uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_PATH);
		lwsl_info("HTTP2 request for '%s'\n", uri_ptr);
		goto got_uri;
	}
#endif
	if (lws_hdr_total_length(wsi, WSI_TOKEN_OPTIONS_URI)) {
		uri_ptr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_OPTIONS_URI);
		uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_OPTIONS_URI);
		lwsl_info("HTTP OPTIONS request for '%s'\n", uri_ptr);
		goto got_uri;
	}
	if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
		uri_ptr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_POST_URI);
		uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI);
		lwsl_info("HTTP POST request for '%s'\n", uri_ptr);
		goto got_uri;
	}
	if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI)) {
		uri_ptr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI);
		uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
		lwsl_info("HTTP GET request for '%s'\n", uri_ptr);
	}

got_uri:
	/* HTTP header had a content length? */

	wsi->u.http.content_length = 0;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
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
			if (strcasecmp(http_conn_str, "close"))
				connection_type = HTTP_CONNECTION_CLOSE;
	}
	wsi->u.http.connection_type = connection_type;

	n = 0;
	if (wsi->protocol->callback)
		n = wsi->protocol->callback(context, wsi,
					LWS_CALLBACK_FILTER_HTTP_CONNECTION,
					     wsi->user_space, uri_ptr, uri_len);

	if (!n) {
		/*
		 * if there is content supposed to be coming,
		 * put a timeout on it having arrived
		 */
		libwebsocket_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
							      AWAITING_TIMEOUT);

		if (wsi->protocol->callback)
			n = wsi->protocol->callback(context, wsi,
			    LWS_CALLBACK_HTTP,
			    wsi->user_space, uri_ptr, uri_len);
	}

	/* now drop the header info we kept a pointer to */
	lws_free2(wsi->u.http.ah);

	if (n) {
		lwsl_info("LWS_CALLBACK_HTTP closing\n");
		return 1; /* struct ah ptr already nuked */		}

	/* 
	 * If we're not issuing a file, check for content_length or
	 * HTTP keep-alive. No keep-alive header allocation for
	 * ISSUING_FILE, as this uses HTTP/1.0. 
	 * 
	 * In any case, return 0 and let libwebsocket_read decide how to
	 * proceed based on state
	 */
	if (wsi->state != WSI_STATE_HTTP_ISSUING_FILE)
		/* Prepare to read body if we have a content length: */
		if (wsi->u.http.content_length > 0)
			wsi->state = WSI_STATE_HTTP_BODY;

	return 0;

bail_nuke_ah:
	/* drop the header info */
	lws_free2(wsi->u.hdr.ah);

	return 1;
}


int lws_handshake_server(struct libwebsocket_context *context,
		struct libwebsocket *wsi, unsigned char **buf, size_t len)
{
	struct allocated_headers *ah;
	int protocol_len;
	char protocol_list[128];
	char protocol_name[32];
	char *p;
	int n, hit;

	/* LWS_CONNMODE_WS_SERVING */

	while (len--) {
		if (libwebsocket_parse(context, wsi, *(*buf)++)) {
			lwsl_info("libwebsocket_parse failed\n");
			goto bail_nuke_ah;
		}

		if (wsi->u.hdr.parser_state != WSI_PARSING_COMPLETE)
			continue;

		lwsl_parser("libwebsocket_parse sees parsing complete\n");

		wsi->mode = LWS_CONNMODE_PRE_WS_SERVING_ACCEPT;
		libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* is this websocket protocol or normal http 1.0? */

		if (!lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE) ||
			     !lws_hdr_total_length(wsi, WSI_TOKEN_CONNECTION)) {
			
			ah = wsi->u.hdr.ah;
			
			lws_union_transition(wsi, LWS_CONNMODE_HTTP_SERVING_ACCEPTED);
			wsi->state = WSI_STATE_HTTP;
			wsi->u.http.fd = LWS_INVALID_FILE;

			/* expose it at the same offset as u.hdr */
			wsi->u.http.ah = ah;
			
			n = lws_http_action(context, wsi);

			return n;
		}

		if (!strcasecmp(lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE),
								"websocket"))
			goto upgrade_ws;
#ifdef LWS_USE_HTTP2
		if (!strcasecmp(lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE),
								"h2c-14"))
			goto upgrade_h2c;
#endif
		/* dunno what he wanted to upgrade to */
		goto bail_nuke_ah;

#ifdef LWS_USE_HTTP2
upgrade_h2c:
		if (!lws_hdr_total_length(wsi, WSI_TOKEN_HTTP2_SETTINGS)) {
			lwsl_err("missing http2_settings\n");
			goto bail_nuke_ah;
		}

		lwsl_err("h2c upgrade...\n");

		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP2_SETTINGS);
		/* convert the peer's HTTP-Settings */
		n = lws_b64_decode_string(p, protocol_list, sizeof(protocol_list));
		if (n < 0) {
			lwsl_parser("HTTP2_SETTINGS too long\n");
			return 1;
		}

		/* adopt the header info */

		ah = wsi->u.hdr.ah;

		lws_union_transition(wsi, LWS_CONNMODE_HTTP2_SERVING);
		
		/* http2 union member has http union struct at start */
		wsi->u.http.ah = ah;
		
		lws_http2_init(&wsi->u.http2.peer_settings);
		lws_http2_init(&wsi->u.http2.my_settings);
		
		/* HTTP2 union */
		
		lws_http2_interpret_settings_payload(&wsi->u.http2.peer_settings, (unsigned char *)protocol_list, n);

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
		
		wsi->state = WSI_STATE_HTTP2_AWAIT_CLIENT_PREFACE;
		
		return 0;
#endif

upgrade_ws:
		if (!wsi->protocol)
			lwsl_err("NULL protocol at libwebsocket_read\n");

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
			n = 0;
			while (n < sizeof(protocol_name) - 1 && *p && *p !=',')
				protocol_name[n++] = *p++;
			protocol_name[n] = '\0';
			if (*p)
				p++;

			lwsl_info("checking %s\n", protocol_name);

			n = 0;
			while (wsi->protocol && context->protocols[n].callback) {
				if (!wsi->protocol->name) {
					n++;
					continue;
				}
				if (!strcmp(context->protocols[n].name,
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
			if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL) ==
									 NULL) {
				/*
				 * some clients only have one protocol and
				 * do not sent the protocol list header...
				 * allow it and match to protocol 0
				 */
				lwsl_info("defaulting to prot 0 handler\n");
				wsi->protocol = &context->protocols[0];
			} else {
				lwsl_err("No protocol from list \"%s\" supported\n",
					 protocol_list);
				goto bail_nuke_ah;
			}
		}

		/* allocate wsi->user storage */
		if (libwebsocket_ensure_user_space(wsi))
			goto bail_nuke_ah;

		/*
		 * Give the user code a chance to study the request and
		 * have the opportunity to deny it
		 */

		if ((wsi->protocol->callback)(wsi->protocol->owning_server, wsi,
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

		lws_union_transition(wsi, LWS_CONNMODE_WS_SERVING);

		/*
		 * create the frame buffer for this connection according to the
		 * size mentioned in the protocol definition.  If 0 there, use
		 * a big default for compatibility
		 */

		n = wsi->protocol->rx_buffer_size;
		if (!n)
			n = LWS_MAX_SOCKET_IO_BUF;
		n += LWS_SEND_BUFFER_PRE_PADDING + LWS_SEND_BUFFER_POST_PADDING;
		wsi->u.ws.rx_user_buffer = lws_malloc(n);
		if (!wsi->u.ws.rx_user_buffer) {
			lwsl_err("Out of Mem allocating rx buffer %d\n", n);
			return 1;
		}
		lwsl_info("Allocating RX buffer %d\n", n);

		if (setsockopt(wsi->sock, SOL_SOCKET, SO_SNDBUF, (const char *)&n, sizeof n)) {
			lwsl_warn("Failed to set SNDBUF to %d", n);
			return 1;
		}

		lwsl_parser("accepted v%02d connection\n",
						       wsi->ietf_spec_revision);
	} /* while all chars are handled */

	return 0;

bail_nuke_ah:
	/* drop the header info */
	lws_free_header_table(wsi);
	return 1;
}

struct libwebsocket *
libwebsocket_create_new_server_wsi(struct libwebsocket_context *context)
{
	struct libwebsocket *new_wsi;

	new_wsi = lws_zalloc(sizeof(struct libwebsocket));
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;
	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/* intialize the instance struct */

	new_wsi->state = WSI_STATE_HTTP;
	new_wsi->mode = LWS_CONNMODE_HTTP_SERVING;
	new_wsi->hdr_parsing_completed = 0;

	if (lws_allocate_header_table(new_wsi)) {
		lws_free(new_wsi);
		return NULL;
	}

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = context->protocols;
	new_wsi->user_space = NULL;
	new_wsi->ietf_spec_revision = 0;

	/*
	 * outermost create notification for wsi
	 * no user_space because no protocol selection
	 */
	context->protocols[0].callback(context, new_wsi,
			LWS_CALLBACK_WSI_CREATE, NULL, NULL, 0);

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

LWS_VISIBLE
int lws_http_transaction_completed(struct libwebsocket *wsi)
{
	/* if we can't go back to accept new headers, drop the connection */
	if (wsi->u.http.connection_type != HTTP_CONNECTION_KEEP_ALIVE) {
		lwsl_info("%s: close connection\n", __func__);
		return 1;
	}

	/* otherwise set ourselves up ready to go again */
	wsi->state = WSI_STATE_HTTP;
	
	lwsl_info("%s: await new transaction\n", __func__);
	
	return 0;
}

int lws_server_socket_service(struct libwebsocket_context *context,
			struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd)
{
	struct libwebsocket *new_wsi = NULL;
	int accept_fd = 0;
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	int n;
	int len;

	switch (wsi->mode) {

	case LWS_CONNMODE_HTTP_SERVING:
	case LWS_CONNMODE_HTTP_SERVING_ACCEPTED:
	case LWS_CONNMODE_HTTP2_SERVING:

		/* handle http headers coming in */

		/* pending truncated sends have uber priority */

		if (wsi->truncated_send_len) {
			if (pollfd->revents & LWS_POLLOUT)
				if (lws_issue_raw(wsi, wsi->truncated_send_malloc +
					wsi->truncated_send_offset,
							wsi->truncated_send_len) < 0) {
					lwsl_info("closing from socket service\n");
					return -1;
				}
			/*
			 * we can't afford to allow input processing send
			 * something new, so spin around he event loop until
			 * he doesn't have any partials
			 */
			break;
		}

		/* any incoming data ready? */

		if (pollfd->revents & LWS_POLLIN) {
			len = lws_ssl_capable_read(context, wsi,
					context->service_buffer,
						       sizeof(context->service_buffer));
			switch (len) {
			case 0:
				lwsl_info("lws_server_skt_srv: read 0 len\n");
				/* lwsl_info("   state=%d\n", wsi->state); */
				if (!wsi->hdr_parsing_completed)
					lws_free_header_table(wsi);
				/* fallthru */
			case LWS_SSL_CAPABLE_ERROR:
				libwebsocket_close_and_free_session(
						context, wsi,
						LWS_CLOSE_STATUS_NOSTATUS);
				return 0;
			case LWS_SSL_CAPABLE_MORE_SERVICE:
				goto try_pollout;
			}

			/* just ignore incoming if waiting for close */
			if (wsi->state != WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
			
				/* hm this may want to send (via HTTP callback for example) */
				n = libwebsocket_read(context, wsi,
							context->service_buffer, len);
				if (n < 0)
					/* we closed wsi */
					return 0;

				/* hum he may have used up the writability above */
				break;
			}
		}

try_pollout:
		/* this handles POLLOUT for http serving fragments */

		if (!(pollfd->revents & LWS_POLLOUT))
			break;

		/* one shot */
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0))
			goto fail;
		
		lws_libev_io(context, wsi, LWS_EV_STOP | LWS_EV_WRITE);

		if (wsi->state != WSI_STATE_HTTP_ISSUING_FILE) {
			n = user_callback_handle_rxflow(
					wsi->protocol->callback,
					wsi->protocol->owning_server,
					wsi, LWS_CALLBACK_HTTP_WRITEABLE,
					wsi->user_space,
					NULL,
					0);
			if (n < 0)
				goto fail;
			break;
		}

		/* >0 == completion, <0 == error */
		n = libwebsockets_serve_http_file_fragment(context, wsi);
		if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi)))
			goto fail;
		break;

	case LWS_CONNMODE_SERVER_LISTENER:

		/* pollin means a client has connected to us then */

		if (!(pollfd->revents & LWS_POLLIN))
			break;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		lws_latency_pre(context, wsi);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		lws_latency(context, wsi,
			"unencrypted accept LWS_CONNMODE_SERVER_LISTENER",
						     accept_fd, accept_fd >= 0);
		if (accept_fd < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK) {
				lwsl_debug("accept asks to try again\n");
				break;
			}
			lwsl_warn("ERROR on accept: %s\n", strerror(LWS_ERRNO));
			break;
		}

		lws_plat_set_socket_options(context, accept_fd);

		/*
		 * look at who we connected to and give user code a chance
		 * to reject based on client IP.  There's no protocol selected
		 * yet so we issue this to protocols[0]
		 */

		if ((context->protocols[0].callback)(context, wsi,
				LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
					   NULL, (void *)(long)accept_fd, 0)) {
			lwsl_debug("Callback denied network connection\n");
			compatible_close(accept_fd);
			break;
		}

		new_wsi = libwebsocket_create_new_server_wsi(context);
		if (new_wsi == NULL) {
			compatible_close(accept_fd);
			break;
		}

		new_wsi->sock = accept_fd;

		/* the transport is accepted... give him time to negotiate */
		libwebsocket_set_timeout(new_wsi,
			PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
							AWAITING_TIMEOUT);

		/*
		 * A new connection was accepted. Give the user a chance to
		 * set properties of the newly created wsi. There's no protocol
		 * selected yet so we issue this to protocols[0]
		 */

		(context->protocols[0].callback)(context, new_wsi,
			LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, NULL, NULL, 0);

		lws_libev_accept(context, new_wsi, accept_fd);

		if (!LWS_SSL_ENABLED(context)) {
			lwsl_debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), accept_fd);

			insert_wsi_socket_into_fds(context, new_wsi);
		}
		break;

	default:
		break;
	}

	if (lws_server_socket_service_ssl(context, &wsi, new_wsi,
							  accept_fd, pollfd))
		goto fail;

	return 0;
	
fail:
	libwebsocket_close_and_free_session(context, wsi,
						 LWS_CLOSE_STATUS_NOSTATUS);
	return 1;
}

#include "lextable-strings.h"

const unsigned char *lws_token_to_string(enum lws_token_indexes token)
{
	if ((unsigned int)token >= ARRAY_SIZE(set))
		return NULL;
	
	return (unsigned char *)set[token];
}

int lws_add_http_header_by_name(struct libwebsocket_context *context,
			    struct libwebsocket *wsi,
			    const unsigned char *name,
			    const unsigned char *value,
			    int length,
			    unsigned char **p,
			    unsigned char *end)
{
#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWS_CONNMODE_HTTP2_SERVING)
		return lws_add_http2_header_by_name(context, wsi, name, value, length, p, end);
#endif
	if (name) {
		while (*p < end && *name)
			*((*p)++) = *name++;
	
		if (*p == end)
			return 1;
	
		*((*p)++) = ' ';
	}
	if (*p + length + 3 >= end)
		return 1;

	memcpy(*p, value, length);
	*p += length;
	
	*((*p)++) = '\x0d';
	*((*p)++) = '\x0a';
		
	return 0;
}

int lws_finalize_http_header(struct libwebsocket_context *context,
			    struct libwebsocket *wsi,
			    unsigned char **p,
			    unsigned char *end)
{
#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWS_CONNMODE_HTTP2_SERVING)
		return 0;
#endif
	
	if ((long)(end - *p) < 3)
		return 1;
	
	*((*p)++) = '\x0d';
	*((*p)++) = '\x0a';
		
	return 0;
}

int lws_add_http_header_by_token(struct libwebsocket_context *context,
			    struct libwebsocket *wsi,
			    enum lws_token_indexes token,
			    const unsigned char *value,
			    int length,
			    unsigned char **p,
			    unsigned char *end)
{
	const unsigned char *name;
#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWS_CONNMODE_HTTP2_SERVING)
		return lws_add_http2_header_by_token(context, wsi, token, value, length, p, end);
#endif
	name = lws_token_to_string(token);
	if (!name)
		return 1;
	
	return lws_add_http_header_by_name(context, wsi, name, value, length, p, end);
}

int lws_add_http_header_content_length(struct libwebsocket_context *context,
			    struct libwebsocket *wsi,
			    unsigned long content_length,
			    unsigned char **p,
			    unsigned char *end)
{
	char b[24];
	int n;

	n = sprintf(b, "%lu", content_length);
	if (lws_add_http_header_by_token(context, wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH, (unsigned char *)b, n, p, end))
		return 1;
	wsi->u.http.content_length = content_length;
	wsi->u.http.content_remain = content_length;

	return 0;
}

static const char *err400[] = {
	"Bad Request",
	"Unauthorized",
	"Payment Required",
	"Forbidden",
	"Not Found",
	"Method Not Allowed",
	"Not Acceptable",
	"Proxy Auth Required",
	"Request Timeout",
	"Conflict",
	"Gone",
	"Length Required",
	"Precondition Failed",
	"Request Entity Too Large",
	"Request URI too Long",
	"Unsupported Media Type",
	"Requested Range Not Satisfiable",
	"Expectation Failed"
};

static const char *err500[] = {
	"Internal Server Error",
	"Not Implemented",
	"Bad Gateway",
	"Service Unavailable",
	"Gateway Timeout",
	"HTTP Version Not Supported"
};

int lws_add_http_header_status(struct libwebsocket_context *context,
			    struct libwebsocket *wsi,
			    unsigned int code,
			    unsigned char **p,
			    unsigned char *end)
{
	unsigned char code_and_desc[60];
	const char *description = "";
	int n;

#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWS_CONNMODE_HTTP2_SERVING)
		return lws_add_http2_header_status(context, wsi, code, p, end);
#endif
	if (code >= 400 && code < (400 + ARRAY_SIZE(err400)))
		description = err400[code - 400];
	if (code >= 500 && code < (500 + ARRAY_SIZE(err500)))
		description = err500[code - 500];

	n = sprintf((char *)code_and_desc, "HTTP/1.0 %u %s", code, description);
	
	return lws_add_http_header_by_name(context, wsi, NULL, code_and_desc, n, p, end);
}

/**
 * libwebsockets_return_http_status() - Return simple http status
 * @context:		libwebsockets context
 * @wsi:		Websocket instance (available from user callback)
 * @code:		Status index, eg, 404
 * @html_body:		User-readable HTML description < 1KB, or NULL
 *
 *	Helper to report HTTP errors back to the client cleanly and
 *	consistently
 */
LWS_VISIBLE int libwebsockets_return_http_status(
		struct libwebsocket_context *context, struct libwebsocket *wsi,
				       unsigned int code, const char *html_body)
{
	int n, m;

	unsigned char *p = context->service_buffer + LWS_SEND_BUFFER_PRE_PADDING;
	unsigned char *start = p;
	unsigned char *end = p + sizeof(context->service_buffer) -
					LWS_SEND_BUFFER_PRE_PADDING;

	if (!html_body)
		html_body = "";

	if (lws_add_http_header_status(context, wsi, code, &p, end))
		return 1;
	if (lws_add_http_header_by_token(context, wsi, WSI_TOKEN_HTTP_SERVER, (unsigned char *)"libwebsockets", 13, &p, end))
		return 1;
	if (lws_add_http_header_by_token(context, wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (unsigned char *)"text/html", 9, &p, end))
		return 1;
	if (lws_finalize_http_header(context, wsi, &p, end))
		return 1;

	m = libwebsocket_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
	if (m != (int)(p - start))
		return 1;

	n = sprintf((char *)start, "<html><body><h1>%u</h1>%s</body></html>", code, html_body);
	m = libwebsocket_write(wsi, start, n, LWS_WRITE_HTTP);

	return m != n;
}

/**
 * libwebsockets_serve_http_file() - Send a file back to the client using http
 * @context:		libwebsockets context
 * @wsi:		Websocket instance (available from user callback)
 * @file:		The file to issue over http
 * @content_type:	The http content type, eg, text/html
 * @other_headers:	NULL or pointer to \0-terminated other header string
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

LWS_VISIBLE int libwebsockets_serve_http_file(
		struct libwebsocket_context *context,
			struct libwebsocket *wsi, const char *file,
			   const char *content_type, const char *other_headers,
			   int other_headers_len)
{
	unsigned char *response = context->service_buffer + LWS_SEND_BUFFER_PRE_PADDING;
	unsigned char *p = response;
	unsigned char *end = p + sizeof(context->service_buffer) -
					LWS_SEND_BUFFER_PRE_PADDING;
	int ret = 0;

	wsi->u.http.fd = lws_plat_open_file(file, &wsi->u.http.filelen);

	if (wsi->u.http.fd == LWS_INVALID_FILE) {
		lwsl_err("Unable to open '%s'\n", file);
		libwebsockets_return_http_status(context, wsi,
						HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	if (lws_add_http_header_status(context, wsi, 200, &p, end))
		return -1;
	if (lws_add_http_header_by_token(context, wsi, WSI_TOKEN_HTTP_SERVER, (unsigned char *)"libwebsockets", 13, &p, end))
		return -1;
	if (lws_add_http_header_by_token(context, wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (unsigned char *)content_type, strlen(content_type), &p, end))
		return -1;
	if (lws_add_http_header_content_length(context, wsi, wsi->u.http.filelen, &p, end))
		return -1;

	if (other_headers) {
		if ((end - p) < other_headers_len)
			return -1;
		memcpy(p, other_headers, other_headers_len);
		p += other_headers_len;
	}

	if (lws_finalize_http_header(context, wsi, &p, end))
		return -1;
	
	ret = libwebsocket_write(wsi, response,
				   p - response, LWS_WRITE_HTTP_HEADERS);
	if (ret != (p - response)) {
		lwsl_err("_write returned %d from %d\n", ret, (p - response));
		return -1;
	}

	wsi->u.http.filepos = 0;
	wsi->state = WSI_STATE_HTTP_ISSUING_FILE;

	return libwebsockets_serve_http_file_fragment(context, wsi);
}


int libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						 unsigned char *buf, size_t len)
{
	size_t n = 0;
	int m;

#if 0
	lwsl_parser("received %d byte packet\n", (int)len);
	lwsl_hexdump(buf, len);
#endif

	/* let the rx protocol state machine have as much as it needs */

	while (n < len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (!(wsi->rxflow_change_to & LWS_RXFLOW_ALLOW)) {
			lws_rxflow_cache(wsi, buf, n, len);

			return 1;
		}

		/* account for what we're using in rxflow buffer */
		if (wsi->rxflow_buffer)
			wsi->rxflow_pos++;

		/* process the byte */
		m = libwebsocket_rx_sm(wsi, buf[n++]);
		if (m < 0)
			return -1;
	}

	return 0;
}

LWS_VISIBLE void
lws_server_get_canonical_hostname(struct libwebsocket_context *context,
				struct lws_context_creation_info *info)
{
	if (info->options & LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME)
		return;

	/* find canonical hostname */
	gethostname((char *)context->canonical_hostname,
				       sizeof(context->canonical_hostname) - 1);

	lwsl_notice(" canonical_hostname = %s\n", context->canonical_hostname);
}
