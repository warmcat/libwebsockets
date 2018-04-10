/*
 * libwebsockets - lib/client/client.c
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

int
lws_handshake_client(struct lws *wsi, unsigned char **buf, size_t len)
{
	int m;

	if ((lwsi_state(wsi) != LRS_WAITING_PROXY_REPLY) &&
	    (lwsi_state(wsi) != LRS_H1C_ISSUE_HANDSHAKE) &&
	    (lwsi_state(wsi) != LRS_WAITING_SERVER_REPLY) &&
	    !lwsi_role_client(wsi))
		return 0;

	while (len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (lws_is_flowcontrolled(wsi)) {
			lwsl_debug("%s: caching %ld\n", __func__, (long)len);
			lws_rxflow_cache(wsi, *buf, 0, (int)len);
			return 0;
		}
		if (wsi->ws->rx_draining_ext) {
#if !defined(LWS_NO_CLIENT)
			if (lwsi_role_client(wsi))
				m = lws_client_rx_sm(wsi, 0);
			else
#endif
				m = lws_rx_sm(wsi, 0);
			if (m < 0)
				return -1;
			continue;
		}
		/* account for what we're using in rxflow buffer */
		if (wsi->rxflow_buffer)
			wsi->rxflow_pos++;

		if (lws_client_rx_sm(wsi, *(*buf)++)) {
			lwsl_debug("client_rx_sm exited\n");
			return -1;
		}
		len--;
	}
	lwsl_debug("%s: finished with %ld\n", __func__, (long)len);

	return 0;
}

LWS_VISIBLE LWS_EXTERN void
lws_client_http_body_pending(struct lws *wsi, int something_left_to_send)
{
	wsi->client_http_body_pending = !!something_left_to_send;
}

/*
 * return self, or queued client wsi we are acting on behalf of
 */

struct lws *
lws_client_wsi_effective(struct lws *wsi)
{
	struct lws *wsi_eff = wsi;

	if (!wsi->transaction_from_pipeline_queue ||
	    !wsi->dll_client_transaction_queue_head.next)
		return wsi;

	/*
	 * The head is the last queued transaction... so
	 * the guy we are fulfilling here is the tail
	 */

	lws_vhost_lock(wsi->vhost);
	lws_start_foreach_dll_safe(struct lws_dll_lws *, d, d1,
				   wsi->dll_client_transaction_queue_head.next) {
		if (d->next == NULL)
			wsi_eff = lws_container_of(d, struct lws,
					dll_client_transaction_queue);
	} lws_end_foreach_dll_safe(d, d1);
	lws_vhost_unlock(wsi->vhost);

	return wsi_eff;
}

/*
 * return self or the guy we are queued under
 */

struct lws *
lws_client_wsi_master(struct lws *wsi)
{
	struct lws *wsi_eff = wsi;
	struct lws_dll_lws *d;

	lws_vhost_lock(wsi->vhost);
	d = wsi->dll_client_transaction_queue.prev;
	while (d) {
		wsi_eff = lws_container_of(d, struct lws,
					dll_client_transaction_queue_head);

		d = d->prev;
	}
	lws_vhost_unlock(wsi->vhost);

	return wsi_eff;
}

int
lws_client_socket_service(struct lws *wsi, struct lws_pollfd *pollfd,
			  struct lws *wsi_conn)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char *p = (char *)&pt->serv_buf[0];
	struct lws *w;
#if defined(LWS_OPENSSL_SUPPORT)
	char ebuf[128];
#endif
	const char *cce = NULL;
	unsigned char c;
	char *sb = p;
	int n = 0;
	ssize_t len = 0;
#if defined(LWS_WITH_SOCKS5)
	char conn_mode = 0, pending_timeout = 0;
#endif

	if ((pollfd->revents & LWS_POLLOUT) &&
	     wsi->keepalive_active &&
	     wsi->dll_client_transaction_queue_head.next) {

		lwsl_debug("%s: pollout HANDSHAKE2\n", __func__);

		/* we have a transaction queue that wants to pipeline */
		lws_vhost_lock(wsi->vhost);
		lws_start_foreach_dll_safe(struct lws_dll_lws *, d, d1,
					   wsi->dll_client_transaction_queue_head.next) {
			struct lws *w = lws_container_of(d, struct lws,
						  dll_client_transaction_queue);

			if (lwsi_state(w) == LRS_H1C_ISSUE_HANDSHAKE2) {
				/*
				 * pollfd has the master sockfd in it... we
				 * need to use that in HANDSHAKE2 to understand
				 * which wsi to actually write on
				 */
				lws_client_socket_service(w, pollfd, wsi);
				lws_callback_on_writable(wsi);
				break;
			}
		} lws_end_foreach_dll_safe(d, d1);
		lws_vhost_unlock(wsi->vhost);

		return 0;
	}

	switch (lwsi_state(wsi)) {

	case LRS_WAITING_CONNECT:

		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 */

		if (!lws_client_connect_2(wsi)) {
			/* closed */
			lwsl_client("closed\n");
			return -1;
		}

		/* either still pending connection, or changed mode */
		return 0;

#if defined(LWS_WITH_SOCKS5)
	/* SOCKS Greeting Reply */
	case LRS_WAITING_SOCKS_GREETING_REPLY:
	case LRS_WAITING_SOCKS_AUTH_REPLY:
	case LRS_WAITING_SOCKS_CONNECT_REPLY:

		/* handle proxy hung up on us */

		if (pollfd->revents & LWS_POLLHUP) {
			lwsl_warn("SOCKS connection %p (fd=%d) dead\n",
				  (void *)wsi, pollfd->fd);
			goto bail3;
		}

		n = recv(wsi->desc.sockfd, sb, context->pt_serv_buf_size, 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN) {
				lwsl_debug("SOCKS read EAGAIN, retrying\n");
				return 0;
			}
			lwsl_err("ERROR reading from SOCKS socket\n");
			goto bail3;
		}

		switch (lwsi_state(wsi)) {

		case LRS_WAITING_SOCKS_GREETING_REPLY:
			if (pt->serv_buf[0] != SOCKS_VERSION_5)
				goto socks_reply_fail;

			if (pt->serv_buf[1] == SOCKS_AUTH_NO_AUTH) {
				lwsl_client("SOCKS GR: No Auth Method\n");
				socks_generate_msg(wsi, SOCKS_MSG_CONNECT, &len);
				conn_mode = LRS_WAITING_SOCKS_CONNECT_REPLY;
				pending_timeout =
				   PENDING_TIMEOUT_AWAITING_SOCKS_CONNECT_REPLY;
				goto socks_send;
			}

			if (pt->serv_buf[1] == SOCKS_AUTH_USERNAME_PASSWORD) {
				lwsl_client("SOCKS GR: User/Pw Method\n");
				socks_generate_msg(wsi,
						   SOCKS_MSG_USERNAME_PASSWORD,
						   &len);
				conn_mode = LRS_WAITING_SOCKS_AUTH_REPLY;
				pending_timeout =
				      PENDING_TIMEOUT_AWAITING_SOCKS_AUTH_REPLY;
				goto socks_send;
			}
			goto socks_reply_fail;

		case LRS_WAITING_SOCKS_AUTH_REPLY:
			if (pt->serv_buf[0] != SOCKS_SUBNEGOTIATION_VERSION_1 ||
			    pt->serv_buf[1] != SOCKS_SUBNEGOTIATION_STATUS_SUCCESS)
				goto socks_reply_fail;

			lwsl_client("SOCKS password OK, sending connect\n");
			socks_generate_msg(wsi, SOCKS_MSG_CONNECT, &len);
			conn_mode = LRS_WAITING_SOCKS_CONNECT_REPLY;
			pending_timeout =
				   PENDING_TIMEOUT_AWAITING_SOCKS_CONNECT_REPLY;
socks_send:
			n = send(wsi->desc.sockfd, (char *)pt->serv_buf, len,
				 MSG_NOSIGNAL);
			if (n < 0) {
				lwsl_debug("ERROR writing to socks proxy\n");
				goto bail3;
			}

			lws_set_timeout(wsi, pending_timeout, AWAITING_TIMEOUT);
			lwsi_set_state(wsi, conn_mode);
			break;

socks_reply_fail:
			lwsl_notice("socks reply: v%d, err %d\n",
				    pt->serv_buf[0], pt->serv_buf[1]);
			goto bail3;

		case LRS_WAITING_SOCKS_CONNECT_REPLY:
			if (pt->serv_buf[0] != SOCKS_VERSION_5 ||
			    pt->serv_buf[1] != SOCKS_REQUEST_REPLY_SUCCESS)
				goto socks_reply_fail;

			lwsl_client("socks connect OK\n");

			/* free stash since we are done with it */
			lws_client_stash_destroy(wsi);
			if (lws_hdr_simple_create(wsi,
						  _WSI_TOKEN_CLIENT_PEER_ADDRESS,
						  wsi->vhost->socks_proxy_address))
				goto bail3;

			wsi->c_port = wsi->vhost->socks_proxy_port;

			/* clear his proxy connection timeout */
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
			goto start_ws_handshake;
		}
		break;
#endif

	case LRS_WAITING_PROXY_REPLY:

		/* handle proxy hung up on us */

		if (pollfd->revents & LWS_POLLHUP) {

			lwsl_warn("Proxy connection %p (fd=%d) dead\n",
				  (void *)wsi, pollfd->fd);

			goto bail3;
		}

		n = recv(wsi->desc.sockfd, sb, context->pt_serv_buf_size, 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN) {
				lwsl_debug("Proxy read EAGAIN... retrying\n");
				return 0;
			}
			lwsl_err("ERROR reading from proxy socket\n");
			goto bail3;
		}

		pt->serv_buf[13] = '\0';
		if (strcmp(sb, "HTTP/1.0 200 ") &&
		    strcmp(sb, "HTTP/1.1 200 ")) {
			lwsl_err("ERROR proxy: %s\n", sb);
			goto bail3;
		}

		/* clear his proxy connection timeout */

		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* fallthru */

	case LRS_H1C_ISSUE_HANDSHAKE:

		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 *
		 * take care of our lws_callback_on_writable
		 * happening at a time when there's no real connection yet
		 */
#if defined(LWS_WITH_SOCKS5)
start_ws_handshake:
#endif
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0))
			return -1;

#ifdef LWS_OPENSSL_SUPPORT
		/* we can retry this... just cook the SSL BIO the first time */

		if ((wsi->use_ssl & LCCSCF_USE_SSL) && !wsi->ssl &&
		    lws_ssl_client_bio_create(wsi) < 0) {
			cce = "bio_create failed";
			goto bail3;
		}

		if (wsi->use_ssl & LCCSCF_USE_SSL) {
			n = lws_ssl_client_connect1(wsi);
			if (!n)
				return 0;
			if (n < 0) {
				cce = "lws_ssl_client_connect1 failed";
				goto bail3;
			}
		} else
			wsi->ssl = NULL;

		/* fallthru */

	case LRS_WAITING_SSL:

		if (wsi->use_ssl & LCCSCF_USE_SSL) {
			n = lws_ssl_client_connect2(wsi, ebuf, sizeof(ebuf));
			if (!n)
				return 0;
			if (n < 0) {
				cce = ebuf;
				goto bail3;
			}
		} else
			wsi->ssl = NULL;
#endif
#if defined (LWS_WITH_HTTP2)
		if (wsi->client_h2_alpn) {
			/*
			 * We connected to the server and set up tls, and
			 * negotiated "h2".
			 *
			 * So this is it, we are an h2 master client connection
			 * now, not an h1 client connection.
			 */
			lwsl_info("client connection upgraded to h2\n");
			lws_h2_configure_if_upgraded(wsi);

			lws_role_transition(wsi, LWSI_ROLE_H2_CLIENT,
					    LRS_H2_CLIENT_SEND_SETTINGS,
					    &wire_ops_h2);

			/* send the H2 preface to legitimize the connection */
			if (lws_h2_issue_preface(wsi)) {
				cce = "error sending h2 preface";
				goto bail3;
			}

			break;
		}
#endif
		lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);
		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND,
				context->timeout_secs);

		/* fallthru */

	case LRS_H1C_ISSUE_HANDSHAKE2:
		p = lws_generate_client_handshake(wsi, p);
		if (p == NULL) {
			if (lwsi_role_raw(wsi))
				return 0;

			lwsl_err("Failed to generate handshake for client\n");
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "chs");
			return 0;
		}

		/* send our request to the server */
		lws_latency_pre(context, wsi);

		w = lws_client_wsi_master(wsi);
		lwsl_debug("%s: HANDSHAKE2: %p: sending headers on %p (wsistate 0x%x 0x%x)\n",
				__func__, wsi, w, wsi->wsistate, w->wsistate);

		n = lws_ssl_capable_write(w, (unsigned char *)sb, (int)(p - sb));
		lws_latency(context, wsi, "send lws_issue_raw", n,
			    n == p - sb);
		switch (n) {
		case LWS_SSL_CAPABLE_ERROR:
			lwsl_debug("ERROR writing to client socket\n");
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "cws");
			return 0;
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			lws_callback_on_writable(wsi);
			break;
		}

		if (wsi->client_http_body_pending) {
			lwsi_set_state(wsi, LRS_ISSUE_HTTP_BODY);
			lws_set_timeout(wsi,
					PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD,
					context->timeout_secs);
			/* user code must ask for writable callback */
			break;
		}

		lwsi_set_state(wsi, LRS_WAITING_SERVER_REPLY);
		wsi->hdr_parsing_completed = 0;

		if (lwsi_state(w) == LRS_IDLING) {
			lwsi_set_state(w, LRS_WAITING_SERVER_REPLY);
			w->hdr_parsing_completed = 0;

			w->ah->parser_state = WSI_TOKEN_NAME_PART;
			w->ah->lextable_pos = 0;
			/* If we're (re)starting on headers, need other implied init */
			wsi->ah->ues = URIES_IDLE;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				wsi->context->timeout_secs);

		lws_callback_on_writable(w);

		goto client_http_body_sent;

	case LRS_ISSUE_HTTP_BODY:
		if (wsi->client_http_body_pending) {
			lws_set_timeout(wsi,
					PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD,
					context->timeout_secs);
			/* user code must ask for writable callback */
			break;
		}
client_http_body_sent:
		/* prepare ourselves to do the parsing */
		wsi->ah->parser_state = WSI_TOKEN_NAME_PART;
		wsi->ah->lextable_pos = 0;
		lwsi_set_state(wsi, LRS_WAITING_SERVER_REPLY);
		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				context->timeout_secs);
		break;

	case LRS_WAITING_SERVER_REPLY:
		/*
		 * handle server hanging up on us...
		 * but if there is POLLIN waiting, handle that first
		 */
		if ((pollfd->revents & (LWS_POLLIN | LWS_POLLHUP)) ==
								LWS_POLLHUP) {

			lwsl_debug("Server connection %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);
			cce = "Peer hung up";
			goto bail3;
		}
		lwsl_notice("eeee\n");
		if (!(pollfd->revents & LWS_POLLIN))
			break;

		/* interpret the server response
		 *
		 *  HTTP/1.1 101 Switching Protocols
		 *  Upgrade: websocket
		 *  Connection: Upgrade
		 *  Sec-WebSocket-Accept: me89jWimTRKTWwrS3aRrL53YZSo=
		 *  Sec-WebSocket-Nonce: AQIDBAUGBwgJCgsMDQ4PEC==
		 *  Sec-WebSocket-Protocol: chat
		 *
		 * we have to take some care here to only take from the
		 * socket bytewise.  The browser may (and has been seen to
		 * in the case that onopen() performs websocket traffic)
		 * coalesce both handshake response and websocket traffic
		 * in one packet, since at that point the connection is
		 * definitively ready from browser pov.
		 */
		len = 1;
		while (wsi->ah->parser_state != WSI_PARSING_COMPLETE &&
		       len > 0) {
			int plen = 1;

			n = lws_ssl_capable_read(wsi, &c, 1);
			lws_latency(context, wsi, "send lws_issue_raw", n,
				    n == 1);
			switch (n) {
			case 0:
			case LWS_SSL_CAPABLE_ERROR:
				cce = "read failed";
				goto bail3;
			case LWS_SSL_CAPABLE_MORE_SERVICE:
				return 0;
			}

			if (lws_parse(wsi, &c, &plen)) {
				lwsl_warn("problems parsing header\n");
				goto bail3;
			}
		}

		/*
		 * hs may also be coming in multiple packets, there is a 5-sec
		 * libwebsocket timeout still active here too, so if parsing did
		 * not complete just wait for next packet coming in this state
		 */
		if (wsi->ah->parser_state != WSI_PARSING_COMPLETE)
			break;



		/*
		 * otherwise deal with the handshake.  If there's any
		 * packet traffic already arrived we'll trigger poll() again
		 * right away and deal with it that way
		 */
		return lws_client_interpret_server_handshake(wsi);

bail3:
		lwsl_info("closing conn at LWS_CONNMODE...SERVER_REPLY\n");
		if (cce)
			lwsl_info("reason: %s\n", cce);
		wsi->protocol->callback(wsi,
			LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
			wsi->user_space, (void *)cce, cce ? strlen(cce) : 0);
		wsi->already_did_cce = 1;
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "cbail3");
		return -1;

	default:
		break;
	}

	return 0;
}

/*
 * In-place str to lower case
 */

static void
strtolower(char *s)
{
	while (*s) {
#ifdef LWS_PLAT_OPTEE
		int tolower_optee(int c);
		*s = tolower_optee((int)*s);
#else
		*s = tolower((int)*s);
#endif
		s++;
	}
}

int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed_client(struct lws *wsi)
{
	struct lws *wsi_eff = lws_client_wsi_effective(wsi);

	lwsl_info("%s: wsi: %p, wsi_eff: %p\n", __func__, wsi, wsi_eff);

	if (user_callback_handle_rxflow(wsi_eff->protocol->callback,
			wsi_eff, LWS_CALLBACK_COMPLETED_CLIENT_HTTP,
			wsi_eff->user_space, NULL, 0)) {
		lwsl_debug("%s: Completed call returned nonzero (role 0x%x)\n",
						__func__, lwsi_role(wsi_eff));
		return -1;
	}

	/*
	 * Are we constitutionally capable of having a queue, ie, we are on
	 * the "active client connections" list?
	 *
	 * If not, that's it for us.
	 */

	if (lws_dll_is_null(&wsi->dll_active_client_conns))
		return -1;

	/* if this was a queued guy, close him and remove from queue */

	if (wsi->transaction_from_pipeline_queue) {
		lwsl_debug("closing queued wsi %p\n", wsi_eff);
		/* so the close doesn't trigger a CCE */
		wsi_eff->already_did_cce = 1;
		__lws_close_free_wsi(wsi_eff,
			LWS_CLOSE_STATUS_CLIENT_TRANSACTION_DONE,
			"queued client done");
	}

	/* after the first one, they can only be coming from the queue */
	wsi->transaction_from_pipeline_queue = 1;

	wsi->http.rx_content_length = 0;
	wsi->hdr_parsing_completed = 0;

	/* is there a new tail after removing that one? */
	wsi_eff = lws_client_wsi_effective(wsi);

	/*
	 * Do we have something pipelined waiting?
	 * it's OK if he hasn't managed to send his headers yet... he's next
	 * in line to do that...
	 */
	if (wsi_eff == wsi) {
		/*
		 * Nothing pipelined... we should hang around a bit
		 * in case something turns up...
		 */
		lwsl_info("%s: nothing pipelined waiting\n", __func__);
		lwsi_set_state(wsi, LRS_IDLING);

		lws_set_timeout(wsi, PENDING_TIMEOUT_CLIENT_CONN_IDLE, 5);

		return 0;
	}

	/*
	 * H1: we can serialize the queued guys into the same ah
	 * H2: everybody needs their own ah until their own STREAM_END
	 */

	/* otherwise set ourselves up ready to go again */
	lwsi_set_state(wsi, LRS_WAITING_SERVER_REPLY);

	wsi->ah->parser_state = WSI_TOKEN_NAME_PART;
	wsi->ah->lextable_pos = 0;

	lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
			wsi->context->timeout_secs);

	/* If we're (re)starting on headers, need other implied init */
	wsi->ah->ues = URIES_IDLE;

	lwsl_info("%s: %p: new queued transaction as %p\n", __func__, wsi, wsi_eff);
	lws_callback_on_writable(wsi);

	return 0;
}

LWS_VISIBLE LWS_EXTERN unsigned int
lws_http_client_http_response(struct lws *wsi)
{
	if (!wsi->ah)
		return 0;

	return wsi->ah->http_response;
}
#if defined(LWS_PLAT_OPTEE)
char *
strrchr(const char *s, int c)
{
	char *hit = NULL;

	while (*s)
		if (*(s++) == (char)c)
		       hit = (char *)s - 1;

	return hit;
}

#define atoll atoi
#endif

int
lws_client_interpret_server_handshake(struct lws *wsi)
{
	int n, len, okay = 0, port = 0, ssl = 0;
	int close_reason = LWS_CLOSE_STATUS_PROTOCOL_ERR;
	struct lws_context *context = wsi->context;
	const char *pc, *prot, *ads = NULL, *path, *cce = NULL;
	struct allocated_headers *ah = NULL;
	struct lws *w = lws_client_wsi_effective(wsi);
	char *p, *q;
	char new_path[300];
#if !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char *sb = (char *)&pt->serv_buf[0];
	const struct lws_ext_options *opts;
	const struct lws_extension *ext;
	char ext_name[128];
	const char *c, *a;
	char ignore;
	int more = 1;
	void *v;
#endif
	lws_client_stash_destroy(wsi);

	ah = wsi->ah;
	if (!wsi->do_ws) {
		/* we are being an http client...
		 */
		if (wsi->client_h2_alpn)
			lws_role_transition(wsi, LWSI_ROLE_H2_CLIENT,
					    LRS_ESTABLISHED, &wire_ops_h2);
		else
			lws_role_transition(wsi, LWSI_ROLE_H1_CLIENT,
					    LRS_ESTABLISHED, &wire_ops_h1);

		wsi->ah = ah;
		ah->http_response = 0;
	}

	/*
	 * well, what the server sent looked reasonable for syntax.
	 * Now let's confirm it sent all the necessary headers
	 *
	 * http (non-ws) client will expect something like this
	 *
	 * HTTP/1.0.200
	 * server:.libwebsockets
	 * content-type:.text/html
	 * content-length:.17703
	 * set-cookie:.test=LWS_1456736240_336776_COOKIE;Max-Age=360000
	 */

	wsi->http.connection_type = HTTP_CONNECTION_KEEP_ALIVE;
	if (!wsi->client_h2_substream) {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP);
		if (wsi->do_ws && !p) {
			lwsl_info("no URI\n");
			cce = "HS: URI missing";
			goto bail3;
		}
		if (!p) {
			p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP1_0);
			wsi->http.connection_type = HTTP_CONNECTION_CLOSE;
		}
		if (!p) {
			cce = "HS: URI missing";
			lwsl_info("no URI\n");
			goto bail3;
		}
	} else {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_STATUS);
		if (!p) {
			cce = "HS: :status missing";
			lwsl_info("no status\n");
			goto bail3;
		}
	}
	n = atoi(p);
	if (ah)
		ah->http_response = n;

	if (n == 301 || n == 302 || n == 303 || n == 307 || n == 308) {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_LOCATION);
		if (!p) {
			cce = "HS: Redirect code but no Location";
			goto bail3;
		}

		/* Relative reference absolute path */
		if (p[0] == '/') {
#ifdef LWS_OPENSSL_SUPPORT
			ssl = wsi->use_ssl & LCCSCF_USE_SSL;
#endif
			ads = lws_hdr_simple_ptr(wsi,
						 _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			port = wsi->c_port;
			/* +1 as lws_client_reset expects leading / omitted */
			path = p + 1;
		}
		/* Absolute (Full) URI */
		else if (strchr(p, ':')) {
			if (lws_parse_uri(p, &prot, &ads, &port, &path)) {
				cce = "HS: URI did not parse";
				goto bail3;
			}

			if (!strcmp(prot, "wss") || !strcmp(prot, "https"))
				ssl = 1;
		}
		/* Relative reference relative path */
		else {
			/* This doesn't try to calculate an absolute path,
			 * that will be left to the server */
#ifdef LWS_OPENSSL_SUPPORT
			ssl = wsi->use_ssl & LCCSCF_USE_SSL;
#endif
			ads = lws_hdr_simple_ptr(wsi,
						 _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			port = wsi->c_port;
			/* +1 as lws_client_reset expects leading / omitted */
			path = new_path + 1;
			lws_strncpy(new_path, lws_hdr_simple_ptr(wsi,
				   _WSI_TOKEN_CLIENT_URI), sizeof(new_path));
			q = strrchr(new_path, '/');
			if (q)
				lws_strncpy(q + 1, p, sizeof(new_path) -
							(q - new_path));
			else
				path = p;
		}

#ifdef LWS_OPENSSL_SUPPORT
		if ((wsi->use_ssl & LCCSCF_USE_SSL) && !ssl) {
			cce = "HS: Redirect attempted SSL downgrade";
			goto bail3;
		}
#endif

		if (!lws_client_reset(&wsi, ssl, ads, port, path, ads)) {
			/* there are two ways to fail out with NULL return...
			 * simple, early problem where the wsi is intact, or
			 * we went through with the reconnect attempt and the
			 * wsi is already closed.  In the latter case, the wsi
			 * has beet set to NULL additionally.
			 */
			lwsl_err("Redirect failed\n");
			cce = "HS: Redirect failed";
			if (wsi)
				goto bail3;

			return 1;
		}
		return 0;
	}

	if (!wsi->do_ws) {

		/* if h1 KA is allowed, enable the queued pipeline guys */

		if (!wsi->client_h2_alpn && !wsi->client_h2_substream && w == wsi) { /* ie, coming to this for the first time */
			if (wsi->http.connection_type == HTTP_CONNECTION_KEEP_ALIVE)
				wsi->keepalive_active = 1;
			else {
				/*
				 * Ugh... now the main http connection has seen
				 * both sides, we learn the server doesn't
				 * support keepalive.
				 *
				 * That means any guys queued on us are going
				 * to have to be restarted from connect2 with
				 * their own connections.
				 */

				/*
				 * stick around telling any new guys they can't
				 * pipeline to this server
				 */
				wsi->keepalive_rejected = 1;

				lws_vhost_lock(wsi->vhost);
				lws_start_foreach_dll_safe(struct lws_dll_lws *, d, d1,
							   wsi->dll_client_transaction_queue_head.next) {
					struct lws *ww = lws_container_of(d, struct lws,
								  dll_client_transaction_queue);

					/* remove him from our queue */
					lws_dll_lws_remove(&ww->dll_client_transaction_queue);
					/* give up on pipelining */
					ww->client_pipeline = 0;

					/* go back to "trying to connect" state */
					lws_role_transition(ww,
							LWSI_ROLE_H1_CLIENT,
							LRS_UNCONNECTED,
							&wire_ops_h1);
					ww->user_space = NULL;
				} lws_end_foreach_dll_safe(d, d1);
				lws_vhost_unlock(wsi->vhost);
			}
		}

#ifdef LWS_WITH_HTTP_PROXY
		wsi->perform_rewrite = 0;
		if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE)) {
			if (!strncmp(lws_hdr_simple_ptr(wsi,
						WSI_TOKEN_HTTP_CONTENT_TYPE),
						"text/html", 9))
				wsi->perform_rewrite = 1;
		}
#endif

		/* allocate the per-connection user memory (if any) */
		if (lws_ensure_user_space(wsi)) {
			lwsl_err("Problem allocating wsi user mem\n");
			cce = "HS: OOM";
			goto bail2;
		}

		/* he may choose to send us stuff in chunked transfer-coding */
		wsi->chunked = 0;
		wsi->chunk_remaining = 0; /* ie, next thing is chunk size */
		if (lws_hdr_total_length(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING)) {
			wsi->chunked = !strcmp(lws_hdr_simple_ptr(wsi,
					       WSI_TOKEN_HTTP_TRANSFER_ENCODING),
						"chunked");
			/* first thing is hex, after payload there is crlf */
			wsi->chunk_parser = ELCP_HEX;
		}

		if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
			wsi->http.rx_content_length =
					atoll(lws_hdr_simple_ptr(wsi,
						WSI_TOKEN_HTTP_CONTENT_LENGTH));
			lwsl_info("%s: incoming content length %llu\n",
				    __func__, (unsigned long long)
					    wsi->http.rx_content_length);
			wsi->http.rx_content_remain =
					wsi->http.rx_content_length;
		} else /* can't do 1.1 without a content length or chunked */
			if (!wsi->chunked)
				wsi->http.connection_type =
							HTTP_CONNECTION_CLOSE;

		/*
		 * we seem to be good to go, give client last chance to check
		 * headers and OK it
		 */
		if (wsi->protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
					    wsi->user_space, NULL, 0)) {

			cce = "HS: disallowed by client filter";
			goto bail2;
		}

		/* clear his proxy connection timeout */
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

		/* call him back to inform him he is up */
		if (wsi->protocol->callback(wsi,
					    LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					    wsi->user_space, NULL, 0)) {
			cce = "HS: disallowed at ESTABLISHED";
			goto bail3;
		}

		/*
		 * for pipelining, master needs to keep his ah... guys who
		 * queued on him can drop it now though.
		 */

		if (w != wsi) {
			/* free up parsing allocations for queued guy */
			lws_header_table_force_to_detachable_state(w);
			lws_header_table_detach(w, 0);
		}

		lwsl_info("%s: client connection up\n", __func__);

		return 0;
	}

	if (wsi->client_h2_substream) {/* !!! client ws-over-h2 not there yet */
		lwsl_warn("%s: client ws-over-h2 upgrade not supported yet\n",
			  __func__);
		cce = "HS: h2 / ws upgrade unsupported";
		goto bail3;
	}

	if (p && !strncmp(p, "401", 3)) {
		lwsl_warn(
		       "lws_client_handshake: got bad HTTP response '%s'\n", p);
		cce = "HS: ws upgrade unauthorized";
		goto bail3;
	}

	if (p && strncmp(p, "101", 3)) {
		lwsl_warn(
		       "lws_client_handshake: got bad HTTP response '%s'\n", p);
		cce = "HS: ws upgrade response not 101";
		goto bail3;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_ACCEPT) == 0) {
		lwsl_info("no ACCEPT\n");
		cce = "HS: ACCEPT missing";
		goto bail3;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE);
	if (!p) {
		lwsl_info("no UPGRADE\n");
		cce = "HS: UPGRADE missing";
		goto bail3;
	}
	strtolower(p);
	if (strcmp(p, "websocket")) {
		lwsl_warn(
		      "lws_client_handshake: got bad Upgrade header '%s'\n", p);
		cce = "HS: Upgrade to something other than websocket";
		goto bail3;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_CONNECTION);
	if (!p) {
		lwsl_info("no Connection hdr\n");
		cce = "HS: CONNECTION missing";
		goto bail3;
	}
	strtolower(p);
	if (strcmp(p, "upgrade")) {
		lwsl_warn("lws_client_int_s_hs: bad header %s\n", p);
		cce = "HS: UPGRADE malformed";
		goto bail3;
	}

	pc = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS);
	if (!pc) {
		lwsl_parser("lws_client_int_s_hs: no protocol list\n");
	} else
		lwsl_parser("lws_client_int_s_hs: protocol list '%s'\n", pc);

	/*
	 * confirm the protocol the server wants to talk was in the list
	 * of protocols we offered
	 */

	len = lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL);
	if (!len) {
		lwsl_info("%s: WSI_TOKEN_PROTOCOL is null\n", __func__);
		/*
		 * no protocol name to work from,
		 * default to first protocol
		 */
		n = 0;
		wsi->protocol = &wsi->vhost->protocols[0];
		goto check_extensions;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL);
	len = (int)strlen(p);

	while (pc && *pc && !okay) {
		if (!strncmp(pc, p, len) &&
		    (pc[len] == ',' || pc[len] == '\0')) {
			okay = 1;
			continue;
		}
		while (*pc && *pc++ != ',')
			;
		while (*pc && *pc == ' ')
			pc++;
	}

	if (!okay) {
		lwsl_info("%s: got bad protocol %s\n", __func__, p);
		cce = "HS: PROTOCOL malformed";
		goto bail2;
	}

	/*
	 * identify the selected protocol struct and set it
	 */
	n = 0;
	/* keep client connection pre-bound protocol */
	if (!lwsi_role_client(wsi))
		wsi->protocol = NULL;

	while (wsi->vhost->protocols[n].callback) {
		if (!wsi->protocol &&
		    strcmp(p, wsi->vhost->protocols[n].name) == 0) {
			wsi->protocol = &wsi->vhost->protocols[n];
			break;
		}
		n++;
	}

	if (!wsi->vhost->protocols[n].callback) { /* no match */
		/* if server, that's already fatal */
		if (!lwsi_role_client(wsi)) {
			lwsl_info("%s: fail protocol %s\n", __func__, p);
			cce = "HS: Cannot match protocol";
			goto bail2;
		}

		/* for client, find the index of our pre-bound protocol */

		n = 0;
		while (wsi->vhost->protocols[n].callback) {
			if (wsi->protocol && strcmp(wsi->protocol->name,
				   wsi->vhost->protocols[n].name) == 0) {
				wsi->protocol = &wsi->vhost->protocols[n];
				break;
			}
			n++;
		}

		if (!wsi->vhost->protocols[n].callback) {
			if (wsi->protocol)
				lwsl_err("Failed to match protocol %s\n",
						wsi->protocol->name);
			else
				lwsl_err("No protocol on client\n");
			goto bail2;
		}
	}

	lwsl_debug("Selected protocol %s\n", wsi->protocol->name);

check_extensions:
	/*
	 * stitch protocol choice into the vh protocol linked list
	 * We always insert ourselves at the start of the list
	 *
	 * X <-> B
	 * X <-> pAn <-> pB
	 */

	lws_vhost_lock(wsi->vhost);

	wsi->same_vh_protocol_prev = /* guy who points to us */
		&wsi->vhost->same_vh_protocol_list[n];
	wsi->same_vh_protocol_next = /* old first guy is our next */
			wsi->vhost->same_vh_protocol_list[n];
	/* we become the new first guy */
	wsi->vhost->same_vh_protocol_list[n] = wsi;

	if (wsi->same_vh_protocol_next)
		/* old first guy points back to us now */
		wsi->same_vh_protocol_next->same_vh_protocol_prev =
				&wsi->same_vh_protocol_next;
	wsi->on_same_vh_list = 1;

	lws_vhost_unlock(wsi->vhost);

#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* instantiate the accepted extensions */

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_EXTENSIONS)) {
		lwsl_ext("no client extensions allowed by server\n");
		goto check_accept;
	}

	/*
	 * break down the list of server accepted extensions
	 * and go through matching them or identifying bogons
	 */

	if (lws_hdr_copy(wsi, sb, context->pt_serv_buf_size,
			 WSI_TOKEN_EXTENSIONS) < 0) {
		lwsl_warn("ext list from server failed to copy\n");
		cce = "HS: EXT: list too big";
		goto bail2;
	}

	c = sb;
	n = 0;
	ignore = 0;
	a = NULL;
	while (more) {

		if (*c && (*c != ',' && *c != '\t')) {
			if (*c == ';') {
				ignore = 1;
				if (!a)
					a = c + 1;
			}
			if (ignore || *c == ' ') {
				c++;
				continue;
			}

			ext_name[n] = *c++;
			if (n < (int)sizeof(ext_name) - 1)
				n++;
			continue;
		}
		ext_name[n] = '\0';
		ignore = 0;
		if (!*c)
			more = 0;
		else {
			c++;
			if (!n)
				continue;
		}

		/* check we actually support it */

		lwsl_notice("checking client ext %s\n", ext_name);

		n = 0;
		ext = wsi->vhost->extensions;
		while (ext && ext->callback) {
			if (strcmp(ext_name, ext->name)) {
				ext++;
				continue;
			}

			n = 1;
			lwsl_notice("instantiating client ext %s\n", ext_name);

			/* instantiate the extension on this conn */

			wsi->active_extensions[wsi->count_act_ext] = ext;

			/* allow him to construct his ext instance */

			if (ext->callback(lws_get_context(wsi), ext, wsi,
				   LWS_EXT_CB_CLIENT_CONSTRUCT,
				   (void *)&wsi->act_ext_user[wsi->count_act_ext],
				   (void *)&opts, 0)) {
				lwsl_info(" ext %s failed construction\n",
					  ext_name);
				ext++;
				continue;
			}

			/*
			 * allow the user code to override ext defaults if it
			 * wants to
			 */
			ext_name[0] = '\0';
			if (user_callback_handle_rxflow(wsi->protocol->callback,
					wsi, LWS_CALLBACK_WS_EXT_DEFAULTS,
					(char *)ext->name, ext_name,
					sizeof(ext_name))) {
				cce = "HS: EXT: failed setting defaults";
				goto bail2;
			}

			if (ext_name[0] &&
			    lws_ext_parse_options(ext, wsi, wsi->act_ext_user[
						  wsi->count_act_ext], opts, ext_name,
						  (int)strlen(ext_name))) {
				lwsl_err("%s: unable to parse user defaults '%s'",
					 __func__, ext_name);
				cce = "HS: EXT: failed parsing defaults";
				goto bail2;
			}

			/*
			 * give the extension the server options
			 */
			if (a && lws_ext_parse_options(ext, wsi,
					wsi->act_ext_user[wsi->count_act_ext],
					opts, a, lws_ptr_diff(c, a))) {
				lwsl_err("%s: unable to parse remote def '%s'",
					 __func__, a);
				cce = "HS: EXT: failed parsing options";
				goto bail2;
			}

			if (ext->callback(lws_get_context(wsi), ext, wsi,
					LWS_EXT_CB_OPTION_CONFIRM,
				      wsi->act_ext_user[wsi->count_act_ext],
				      NULL, 0)) {
				lwsl_err("%s: ext %s rejects server options %s",
					 __func__, ext->name, a);
				cce = "HS: EXT: Rejects server options";
				goto bail2;
			}

			wsi->count_act_ext++;

			ext++;
		}

		if (n == 0) {
			lwsl_warn("Unknown ext '%s'!\n", ext_name);
			cce = "HS: EXT: unknown ext";
			goto bail2;
		}

		a = NULL;
		n = 0;
	}

check_accept:
#endif

	/*
	 * Confirm his accept token is the one we precomputed
	 */

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_ACCEPT);
	if (strcmp(p, wsi->ah->initial_handshake_hash_base64)) {
		lwsl_warn("lws_client_int_s_hs: accept '%s' wrong vs '%s'\n", p,
				  wsi->ah->initial_handshake_hash_base64);
		cce = "HS: Accept hash wrong";
		goto bail2;
	}

	/* allocate the per-connection user memory (if any) */
	if (lws_ensure_user_space(wsi)) {
		lwsl_err("Problem allocating wsi user mem\n");
		cce = "HS: OOM";
		goto bail2;
	}

	/*
	 * we seem to be good to go, give client last chance to check
	 * headers and OK it
	 */
	if (wsi->protocol->callback(wsi,
				    LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
				    wsi->user_space, NULL, 0)) {
		cce = "HS: Rejected by filter cb";
		goto bail2;
	}

	/* clear his proxy connection timeout */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	/* free up his parsing allocations */
	lws_header_table_detach(wsi, 0);

	lws_role_transition(wsi, LWSI_ROLE_WS1_CLIENT, LRS_ESTABLISHED,
			    &wire_ops_ws);
	lws_restart_ws_ping_pong_timer(wsi);

	wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/*
	 * create the frame buffer for this connection according to the
	 * size mentioned in the protocol definition.  If 0 there, then
	 * use a big default for compatibility
	 */
	n = (int)wsi->protocol->rx_buffer_size;
	if (!n)
		n = context->pt_serv_buf_size;
	n += LWS_PRE;
	wsi->ws->rx_ubuf = lws_malloc(n + 4 /* 0x0000ffff zlib */,
				"client frame buffer");
	if (!wsi->ws->rx_ubuf) {
		lwsl_err("Out of Mem allocating rx buffer %d\n", n);
		cce = "HS: OOM";
		goto bail2;
	}
       wsi->ws->rx_ubuf_alloc = n;
	lwsl_info("Allocating client RX buffer %d\n", n);

#if !defined(LWS_WITH_ESP32)
	if (setsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_SNDBUF,
		       (const char *)&n, sizeof n)) {
		lwsl_warn("Failed to set SNDBUF to %d", n);
		cce = "HS: SO_SNDBUF failed";
		goto bail3;
	}
#endif

	lwsl_debug("handshake OK for protocol %s\n", wsi->protocol->name);

	/* call him back to inform him he is up */

	if (wsi->protocol->callback(wsi, LWS_CALLBACK_CLIENT_ESTABLISHED,
				    wsi->user_space, NULL, 0)) {
		cce = "HS: Rejected at CLIENT_ESTABLISHED";
		goto bail3;
	}
#if !defined(LWS_WITHOUT_EXTENSIONS)
	/*
	 * inform all extensions, not just active ones since they
	 * already know
	 */
	ext = wsi->vhost->extensions;

	while (ext && ext->callback) {
		v = NULL;
		for (n = 0; n < wsi->count_act_ext; n++)
			if (wsi->active_extensions[n] == ext)
				v = wsi->act_ext_user[n];

		ext->callback(context, ext, wsi,
			  LWS_EXT_CB_ANY_WSI_ESTABLISHED, v, NULL, 0);
		ext++;
	}
#endif

	return 0;

bail3:
	close_reason = LWS_CLOSE_STATUS_NOSTATUS;

bail2:
	if (wsi->protocol) {
		n = 0;
		if (cce)
			n = strlen(cce);
		wsi->protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
				wsi->user_space, (void *)cce,
				(unsigned int)n);
	}
	wsi->already_did_cce = 1;

	lwsl_info("closing connection due to bail2 connection error\n");

	/* closing will free up his parsing allocations */
	lws_close_free_wsi(wsi, close_reason, "c hs interp");

	return 1;
}


char *
lws_generate_client_handshake(struct lws *wsi, char *pkt)
{
	char buf[128], hash[20], key_b64[40], *p = pkt;
	struct lws_context *context = wsi->context;
	const char *meth;
	int n;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	const struct lws_extension *ext;
	int ext_count = 0;
#endif
	const char *pp = lws_hdr_simple_ptr(wsi,
				_WSI_TOKEN_CLIENT_SENT_PROTOCOLS);

	meth = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
	if (!meth) {
		meth = "GET";
		wsi->do_ws = 1;
	} else {
		wsi->do_ws = 0;
	}

	if (!strcmp(meth, "RAW")) {
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
		lwsl_notice("client transition to raw\n");

		if (pp) {
			const struct lws_protocols *pr;

			pr = lws_vhost_name_to_protocol(wsi->vhost, pp);

			if (!pr) {
				lwsl_err("protocol %s not enabled on vhost\n",
					 pp);
				return NULL;
			}

			lws_bind_protocol(wsi, pr);
		}

		if ((wsi->protocol->callback)(wsi,
				LWS_CALLBACK_RAW_ADOPT,
				wsi->user_space, NULL, 0))
			return NULL;

		lws_header_table_force_to_detachable_state(wsi);
		lws_role_transition(wsi, LWSI_ROLE_RAW_SOCKET, LRS_ESTABLISHED,
				    &wire_ops_raw);
		lws_header_table_detach(wsi, 1);

		return NULL;
	}

	if (wsi->do_ws) {
		/*
		 * create the random key
		 */
		n = lws_get_random(context, hash, 16);
		if (n != 16) {
			lwsl_err("Unable to read from random dev %s\n",
				 SYSTEM_RANDOM_FILEPATH);
			return NULL;
		}

		lws_b64_encode_string(hash, 16, key_b64, sizeof(key_b64));
	}

	/*
	 * 04 example client handshake
	 *
	 * GET /chat HTTP/1.1
	 * Host: server.example.com
	 * Upgrade: websocket
	 * Connection: Upgrade
	 * Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
	 * Sec-WebSocket-Origin: http://example.com
	 * Sec-WebSocket-Protocol: chat, superchat
	 * Sec-WebSocket-Version: 4
	 */

	p += sprintf(p, "%s %s HTTP/1.1\x0d\x0a", meth,
		     lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI));

	p += sprintf(p, "Pragma: no-cache\x0d\x0a"
			"Cache-Control: no-cache\x0d\x0a");

	p += sprintf(p, "Host: %s\x0d\x0a",
		     lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_HOST));

	if (lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_ORIGIN)) {
		if (lws_check_opt(context->options,
				  LWS_SERVER_OPTION_JUST_USE_RAW_ORIGIN))
			p += sprintf(p, "Origin: %s\x0d\x0a",
				     lws_hdr_simple_ptr(wsi,
						     _WSI_TOKEN_CLIENT_ORIGIN));
		else
			p += sprintf(p, "Origin: http://%s\x0d\x0a",
				     lws_hdr_simple_ptr(wsi,
						     _WSI_TOKEN_CLIENT_ORIGIN));
	}

	if (wsi->do_ws) {
		p += sprintf(p, "Upgrade: websocket\x0d\x0a"
				"Connection: Upgrade\x0d\x0a"
				"Sec-WebSocket-Key: ");
		strcpy(p, key_b64);
		p += strlen(key_b64);
		p += sprintf(p, "\x0d\x0a");
		if (lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS))
			p += sprintf(p, "Sec-WebSocket-Protocol: %s\x0d\x0a",
			     lws_hdr_simple_ptr(wsi,
					     _WSI_TOKEN_CLIENT_SENT_PROTOCOLS));

		/* tell the server what extensions we could support */

#if !defined(LWS_WITHOUT_EXTENSIONS)
		ext = wsi->vhost->extensions;
		while (ext && ext->callback) {
			n = lws_ext_cb_all_exts(context, wsi,
				   LWS_EXT_CB_CHECK_OK_TO_PROPOSE_EXTENSION,
				   (char *)ext->name, 0);
			if (n) { /* an extension vetos us */
				lwsl_ext("ext %s vetoed\n", (char *)ext->name);
				ext++;
				continue;
			}
			n = wsi->vhost->protocols[0].callback(wsi,
				LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED,
					wsi->user_space, (char *)ext->name, 0);

			/*
			 * zero return from callback means go ahead and allow
			 * the extension, it's what we get if the callback is
			 * unhandled
			 */

			if (n) {
				ext++;
				continue;
			}

			/* apply it */

			if (ext_count)
				*p++ = ',';
			else
				p += sprintf(p, "Sec-WebSocket-Extensions: ");
			p += sprintf(p, "%s", ext->client_offer);
			ext_count++;

			ext++;
		}
		if (ext_count)
			p += sprintf(p, "\x0d\x0a");
#endif

		if (wsi->ws->ietf_spec_revision)
			p += sprintf(p, "Sec-WebSocket-Version: %d\x0d\x0a",
				     wsi->ws->ietf_spec_revision);

		/* prepare the expected server accept response */

		key_b64[39] = '\0'; /* enforce composed length below buf sizeof */
		n = sprintf(buf, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
				  key_b64);

		lws_SHA1((unsigned char *)buf, n, (unsigned char *)hash);

		lws_b64_encode_string(hash, 20,
			  wsi->ah->initial_handshake_hash_base64,
			  sizeof(wsi->ah->initial_handshake_hash_base64));
	}

	/* give userland a chance to append, eg, cookies */

	if (wsi->protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
				wsi->user_space, &p,
				(pkt + context->pt_serv_buf_size) - p - 12))
		return NULL;

	p += sprintf(p, "\x0d\x0a");

	return p;
}

LWS_VISIBLE int
lws_http_client_read(struct lws *wsi, char **buf, int *len)
{
	int rlen, n;

	rlen = lws_ssl_capable_read(wsi, (unsigned char *)*buf, *len);
	*len = 0;

	// lwsl_notice("%s: rlen %d\n", __func__, rlen);

	/* allow the source to signal he has data again next time */
	lws_change_pollfd(wsi, 0, LWS_POLLIN);

	if (rlen == LWS_SSL_CAPABLE_ERROR) {
		lwsl_notice("%s: SSL capable error\n", __func__);
		return -1;
	}

	if (rlen == 0)
		return -1;

	if (rlen < 0)
		return 0;

	*len = rlen;
	wsi->client_rx_avail = 0;

	/*
	 * server may insist on transfer-encoding: chunked,
	 * so http client must deal with it
	 */
spin_chunks:
	while (wsi->chunked && (wsi->chunk_parser != ELCP_CONTENT) && *len) {
		switch (wsi->chunk_parser) {
		case ELCP_HEX:
			if ((*buf)[0] == '\x0d') {
				wsi->chunk_parser = ELCP_CR;
				break;
			}
			n = char_to_hex((*buf)[0]);
			if (n < 0) {
				lwsl_debug("chunking failure\n");
				return -1;
			}
			wsi->chunk_remaining <<= 4;
			wsi->chunk_remaining |= n;
			break;
		case ELCP_CR:
			if ((*buf)[0] != '\x0a') {
				lwsl_debug("chunking failure\n");
				return -1;
			}
			wsi->chunk_parser = ELCP_CONTENT;
			lwsl_info("chunk %d\n", wsi->chunk_remaining);
			if (wsi->chunk_remaining)
				break;
			lwsl_info("final chunk\n");
			goto completed;

		case ELCP_CONTENT:
			break;

		case ELCP_POST_CR:
			if ((*buf)[0] != '\x0d') {
				lwsl_debug("chunking failure\n");

				return -1;
			}

			wsi->chunk_parser = ELCP_POST_LF;
			break;

		case ELCP_POST_LF:
			if ((*buf)[0] != '\x0a')
				return -1;

			wsi->chunk_parser = ELCP_HEX;
			wsi->chunk_remaining = 0;
			break;
		}
		(*buf)++;
		(*len)--;
	}

	if (wsi->chunked && !wsi->chunk_remaining)
		return 0;

	if (wsi->http.rx_content_remain &&
	    wsi->http.rx_content_remain < (unsigned int)*len)
		n = (int)wsi->http.rx_content_remain;
	else
		n = *len;

	if (wsi->chunked && wsi->chunk_remaining &&
	    wsi->chunk_remaining < n)
		n = wsi->chunk_remaining;

#ifdef LWS_WITH_HTTP_PROXY
	/* hubbub */
	if (wsi->perform_rewrite)
		lws_rewrite_parse(wsi->rw, (unsigned char *)*buf, n);
	else
#endif
	{
		struct lws *wsi_eff = lws_client_wsi_effective(wsi);

		if (user_callback_handle_rxflow(wsi_eff->protocol->callback,
				wsi_eff, LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
				wsi_eff->user_space, *buf, n)) {
			lwsl_debug("%s: RECEIVE_CLIENT_HTTP_READ returned -1\n",
				   __func__);

			return -1;
		}
	}

	if (wsi->chunked && wsi->chunk_remaining) {
		(*buf) += n;
		wsi->chunk_remaining -= n;
		*len -= n;
	}

	if (wsi->chunked && !wsi->chunk_remaining)
		wsi->chunk_parser = ELCP_POST_CR;

	if (wsi->chunked && *len)
		goto spin_chunks;

	if (wsi->chunked)
		return 0;

	/* if we know the content length, decrement the content remaining */
	if (wsi->http.rx_content_length > 0)
		wsi->http.rx_content_remain -= n;

	// lwsl_notice("rx_content_remain %lld, rx_content_length %lld\n",
	//	wsi->http.rx_content_remain, wsi->http.rx_content_length);

	if (wsi->http.rx_content_remain || !wsi->http.rx_content_length)
		return 0;

completed:

	if (lws_http_transaction_completed_client(wsi)) {
		lwsl_notice("%s: transaction completed says -1\n", __func__);
		return -1;
	}

	return 0;
}
