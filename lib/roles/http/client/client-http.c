/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

void
lws_client_http_body_pending(struct lws *wsi, int something_left_to_send)
{
	wsi->client_http_body_pending = !!something_left_to_send;
}

/*
 * Returns 0 for wsi survived OK, or LWS_HPI_RET_WSI_ALREADY_DIED
 * meaning the wsi was destroyed by us before return.
 */
	
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
/*
 * sansIO rx for an h1 client until it is established: the socks and http
 * CONNECT legs of its transport, the wait for its response headers, and the
 * idle wait between transactions of a connection kept warm.
 *
 * While it waits for its response headers it is the header parser's.  The
 * parser takes bytes one at a time and stops at the end of the block, so
 * whatever the peer coalesced after it (a browser's first ws frames, say)
 * is left for the next phase, which interprets the completed block once
 * the remainder has been parked.  A parse failure, or the peer closing
 * before responding, is a connection failure for the user.
 */
int
lws_h1_client_rx(struct lws *wsi, const uint8_t *buf, size_t len,
		 int from_transport)
{
	const char *cce;
	int n, m;
#if defined(LWS_CLIENT_HTTP_PROXYING)
	char pbuf[24];
#endif

	(void)from_transport;

#if defined(LWS_CLIENT_HTTP_PROXYING)
	if (lwsi_state(wsi) == LRS_WAITING_PROXY_REPLY) {
		/*
		 * The http proxy's reply to our CONNECT.  Its status line
		 * decides it; whatever the proxy sent with it is discarded,
		 * as before (the peer speaks only after we do, in every
		 * protocol this tunnel carries).
		 */
		if (!len) {
			cce = "proxy conn dead";
			goto fail;
		}

		if (len < 13 || strncmp((const char *)buf, "HTTP/1.", 7) ||
		    (buf[7] != '0' && buf[7] != '1') || buf[8] != ' ') {
			cce = "http_proxy fail";
			goto fail;
		}

		memcpy(pbuf, &buf[9], 3);
		pbuf[3] = '\0';
		n = atoi(pbuf);
		if (n != 200) {
			lws_snprintf(pbuf, sizeof(pbuf), "http_proxy -> %u",
				     (unsigned int)n);
			cce = pbuf;
			goto fail;
		}

		lwsl_wsi_info(wsi, "proxy connection established");

		/* clear his proxy connection timeout */
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/*
		 * The tunnel is up: for the protocol this is the socket
		 * connecting, and it goes on from here as a direct
		 * connection does
		 */
		lws_wsi_event(wsi, LWS_WSIEV_SOCKET_CONNECTED);

		return (int)len;
	}
#endif

#if defined(LWS_WITH_SOCKS5)
	if (lwsi_in_socks5_leg(wsi)) {
		size_t used;

		switch (lws_socks5c_rx(wsi, buf, len, &cce, &used)) {
		case LW5CHS_RET_BAIL3:
			goto fail;
		case LW5CHS_RET_STARTHS:
			/*
			 * The tunnel is up: for the protocol this is the
			 * socket connecting, and it goes on from here as a
			 * direct connection does
			 */
			lws_wsi_event(wsi, LWS_WSIEV_SOCKET_CONNECTED);
			break;
		default:
			break;
		}

		/* what followed the reply is the peer's, left for the protocol */
		return (int)used;
	}
#endif

	if (lwsi_state(wsi) == LRS_IDLING) {
		/*
		 * Kept warm between transactions: the peer has nothing to
		 * say to us.  It closing, or sending anyway, ends the
		 * connection; the 1-byte probe read this replaces silently
		 * ate whatever arrived.
		 */
		lwsl_wsi_info(wsi, "peer %s while idle",
			      len ? "sent" : "closed");

		return LWS_RX_CLOSE;
	}

	if (lwsi_state(wsi) != LRS_WAITING_SERVER_REPLY || !wsi->stream.ah) {
		lwsl_wsi_err(wsi, "%s: rx in state 0x%x", __func__,
			     lwsi_state(wsi));

		return LWS_RX_CLOSE;
	}

	if (!len) {
		cce = "server closed before responding";
		goto fail;
	}

	n = (int)len;
	m = lws_parse(wsi, (unsigned char *)buf, &n);
	if (m) {
		lwsl_wsi_warn(wsi, "problems parsing header");
		if (m == LPR_FAIL)
			lws_parse_fail_diag(wsi, buf, (int)len - n, (int)len);
		cce = "problems parsing header";
		goto fail;
	}
	m = (int)len - n;

#if defined(LWS_WITH_SECURE_STREAMS_BUFFER_DUMP)
	do {
		lws_ss_handle_t *h;

		/* the opaque user data is only an ss handle on
		 * a wsi that belongs to a secure stream */
		if (!wsi->for_ss)
			break;

		h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
		if (!h)
			break;

		if (h->info.dump)
			h->info.dump(ss_to_userobj(h), buf, (size_t)m,
				     (wsi->stream.ah->parser_state ==
					WSI_PARSING_COMPLETE) ? 1 : 0);
	} while (0);
#endif

	return m;

fail:
	lwsl_info("%s: closing conn at LWS_CONNMODE...SERVER_REPLY, %s, state 0x%x\n",
		  __func__, lws_wsi_tag(wsi), lwsi_state(wsi));
	lwsl_info("reason: %s\n", cce);
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "cbail3");

	return LWS_RX_DIED;
}
#endif

int
lws_http_client_socket_service(struct lws *wsi, struct lws_pollfd *pollfd)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char *p = (char *)&pt->serv_buf[0], *end = p + wsi->a.context->pt_serv_buf_size;
#if defined(LWS_WITH_TLS)
	char ebuf[128];
#endif
	const char *cce = NULL;
	char *sb = p;
	int n = 0;

	switch (lwsi_state(wsi)) {

	case LRS_WAITING_DNS:
		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 */
		lwsl_err("%s: %s: WAITING_DNS\n", __func__, lws_wsi_tag(wsi));
		if (!lws_client_connect_2_dnsreq_MAY_CLOSE_WSI(wsi)) {
			/* closed */
			lwsl_client("closed\n");
			return LWS_HPI_RET_WSI_ALREADY_DIED;
		}

		/* either still pending connection, or changed mode */
		return 0;

	case LRS_WAITING_CONNECT:

		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 */
		/*
		 * A hangup or error here means this fd's attempt failed;
		 * disposition it via connect_3 so any parallel racing
		 * attempt on the same wsi can still be promoted instead of
		 * being lost when the wsi is killed
		 */
		if (pollfd->revents & (LWS_POLLOUT | LWS_POLLHUP))
			if (lws_client_connect_3_connect(wsi, NULL, NULL, 0, pollfd) == NULL) {
				lwsl_client("closed\\n");
				return LWS_HPI_RET_WSI_ALREADY_DIED;
			}
		break;

#if defined(LWS_WITH_SOCKS5)
	/* SOCKS Greeting Reply */
	case LRS_WAITING_SOCKS_GREETING_REPLY:
	case LRS_WAITING_SOCKS_AUTH_REPLY:
	case LRS_WAITING_SOCKS_CONNECT_REPLY:
		/*
		 * IO's rx stage read the proxy's reply; if the tunnel came up
		 * we issue the handshake as a direct connection does
		 */
		if (lwsi_state(wsi) == LRS_H1C_ISSUE_HANDSHAKE)
			goto start_ws_handshake_l;

		return 0;
#endif

#if defined(LWS_CLIENT_HTTP_PROXYING) && (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3))

	case LRS_WAITING_PROXY_REPLY:
		/* IO's rx stage read the proxy's reply */
		if (lwsi_state(wsi) != LRS_H1C_ISSUE_HANDSHAKE)
			return 0;

		/* the tunnel came up: issue the handshake as a direct connection does */
               /* fallthru */

#endif

               /* dummy fallthru to satisfy compiler */
               /* fallthru */
	case LRS_H1C_ISSUE_HANDSHAKE:

		// lwsl_debug("%s: LRS_H1C_ISSUE_HANDSHAKE\n", __func__);

		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 *
		 * take care of our lws_callback_on_writable
		 * happening at a time when there's no real connection yet
		 */
#if defined(LWS_WITH_SOCKS5)
start_ws_handshake_l:
#endif
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			cce = "unable to clear POLLOUT";
			/* turn whatever went wrong into a clean close */
			goto bail3_l;
		}

#if defined(LWS_ROLE_H2) || defined(LWS_WITH_TLS)
		if (
#if defined(LWS_WITH_TLS)
		    !(wsi->tls.use_ssl & LCCSCF_USE_SSL)
#endif
#if defined(LWS_ROLE_H2) && defined(LWS_WITH_TLS)
		    &&
#endif
#if defined(LWS_ROLE_H2)
		    !(wsi->flags & LCCSCF_H2_PRIOR_KNOWLEDGE)
#endif
		    )
			goto hs2;
#endif

#if defined(LWS_WITH_TLS)
		n = lws_client_create_tls(wsi, &cce, 1);
		if (n == CCTLS_RETURN_ERROR)
			goto bail3_l;
		if (n == CCTLS_RETURN_RETRY)
			return 0;

		/*
		 * lws_client_create_tls() can already have done the
		 * whole tls setup and preface send... if so he set our state
		 * to LRS_H1C_ISSUE_HANDSHAKE2... let's proceed but be prepared
		 * to notice our state and not resend the preface...
		 */

		// lwsl_debug("%s: LRS_H1C_ISSUE_HANDSHAKE fallthru\n", __func__);

		/* fallthru */

	case LRS_WAITING_SSL:

		if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
			n = lws_ssl_client_connect2(wsi, ebuf, sizeof(ebuf));
			if (!n)
				return 0;
			if (n < 0) {
				cce = ebuf;
				goto bail3_l;
			}
		} else {
			wsi->tls.ssl = NULL;
			if (wsi->flags & LCCSCF_H2_PRIOR_KNOWLEDGE) {
				lwsl_info("h2 prior knowledge\n");
				lws_role_call_alpn_negotiated(wsi, "h2");
			}
		}
#endif
#if !defined(LWS_WITH_TLS) && defined(LWS_ROLE_H2)
		/*
		 * No TLS in this build, so no LRS_WAITING_SSL case above to
		 * do it: cleartext h2 prior knowledge still has to move us to
		 * the h2 role before the preface goes out below.
		 */
		if (wsi->flags & LCCSCF_H2_PRIOR_KNOWLEDGE) {
			lwsl_info("h2 prior knowledge\n");
			lws_role_call_alpn_negotiated(wsi, "h2");
		}
#endif

#if defined (LWS_WITH_HTTP2)
		if (lwsi_role_h2(wsi)) {
			/*
			 * We connected to the server and set up tls and
			 * negotiated "h2" or connected as clear text
			 * with http/2 prior knowledge.
			 *
			 * So this is it, we are an h2 nwsi client connection
			 * now, not an h1 client connection.
			 */

			lwsl_info("%s: doing h2 hello path\n", __func__);

			/*
			 * send the H2 preface to legitimize the connection
			 *
			 * transitions us to LRS_H2_WAITING_TO_SEND_HEADERS
			 */
			if (lwsi_role_h2(wsi))
				if (lws_h2_issue_preface(wsi)) {
					cce = "error sending h2 preface";
					goto bail3_l;
				}

			lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND,
					(int)context->timeout_secs);

			break;
		}
#endif

		/* fallthru */

	case LRS_H1C_ISSUE_HANDSHAKE2:

#if defined(LWS_ROLE_H2) || defined(LWS_WITH_TLS)
hs2:
#endif

		p = lws_generate_client_handshake(wsi, p,
						  lws_ptr_diff_size_t(end, p));
		if (p == NULL) {
			if (wsi->role_ops == &role_ops_raw_skt
#if defined(LWS_ROLE_RAW_FILE)
				|| wsi->role_ops == &role_ops_raw_file
#endif
			    )
				return 0;

			lwsl_err("Failed to generate handshake for client\n");
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "chs");
			return -1;
		}

		/* send our request to the server */

		lwsl_wsi_info(wsi, "HANDSHAKE2: sending headers (wsistate 0x%lx)",
			      (unsigned long)wsi->wsistate);

		n = lws_ssl_capable_write(wsi, (unsigned char *)sb, lws_ptr_diff_size_t(p, sb));
		switch (n) {
		case LWS_SSL_CAPABLE_ERROR:
			lwsl_debug("ERROR writing to client socket\n");
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "cws");
			return LWS_HPI_RET_WSI_ALREADY_DIED;
		case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
		case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
			lws_callback_on_writable(wsi);
			break;
		}

		if (wsi->client_http_body_pending || lws_has_buffered_out(wsi)) {
			lwsl_debug("body pending\n");
			lws_wsi_event(wsi, LWS_WSIEV_REQ_HDRS_SENT_BODY);
			lws_set_timeout(wsi,
					PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD,
					(int)context->timeout_secs);

			if (wsi->flags & LCCSCF_HTTP_X_WWW_FORM_URLENCODED)
				lws_callback_on_writable(wsi);
#if defined(LWS_WITH_HTTP_PROXY)
			if (wsi->http.proxy_clientside && wsi->parent &&
			    wsi->parent->http.buflist_post_body)
				lws_callback_on_writable(wsi);
#endif
			/* user code must ask for writable callback */
			break;
		}

		lws_wsi_event(wsi, LWS_WSIEV_REQ_HDRS_SENT);

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				(int)wsi->a.context->timeout_secs);

		lws_callback_on_writable(wsi);

		goto client_http_body_sent;

	case LRS_ISSUE_HTTP_BODY:
#if defined(LWS_WITH_HTTP_PROXY)
			if (wsi->http.proxy_clientside && wsi->parent &&
			    wsi->parent->http.buflist_post_body)
				lws_callback_on_writable(wsi);
#endif
		if (wsi->client_http_body_pending || lws_has_buffered_out(wsi)) {
			//lws_set_timeout(wsi,
			//		PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD,
			//		context->timeout_secs);
			/* user code must ask for writable callback */
			break;
		}
client_http_body_sent:
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
		/* prepare ourselves to do the parsing */
		wsi->stream.ah->parser_state = WSI_TOKEN_NAME_PART;
		wsi->stream.ah->lextable_pos = 0;
		wsi->stream.ah->unk_pos = 0;
		lws_header_table_rx_snapshot(wsi);
#endif
		if (lwsi_state(wsi) == LRS_ISSUE_HTTP_BODY)
			lws_wsi_event(wsi, LWS_WSIEV_REQ_BODY_SENT);
		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				(int)context->timeout_secs);
		break;

	case LRS_WAITING_SERVER_REPLY:
		/*
		 * IO's rx stage reads the response header block; the server
		 * hanging up reaches the rx op as an empty rx and is reported
		 * from there.
		 */
		if (pollfd->revents & LWS_POLLOUT)
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				cce = "Unable to clear POLLOUT";
				goto bail3_l;
			}

		if (!wsi->stream.ah ||
		    wsi->stream.ah->parser_state != WSI_PARSING_COMPLETE)
			/* the block is not complete yet; the timeout guards */
			break;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
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
		/*
		 * The block may come in several packets, and the peer may
		 * coalesce what follows it: the parser stops at its end and
		 * the pump parks the rest for the next phase.  A 5-sec
		 * timeout is active here, so if the block is not complete yet
		 * just wait for the next packet in this state.
		 */
#endif

		/*
		 * otherwise deal with the handshake.  If there's any
		 * packet traffic already arrived we'll trigger poll() again
		 * right away and deal with it that way
		 */
		return lws_client_interpret_server_handshake(wsi);

bail3_l:
		lwsl_info("%s: closing conn at LWS_CONNMODE...SERVER_REPLY, %s, state 0x%x\n",
				__func__, lws_wsi_tag(wsi), lwsi_state(wsi));
		if (cce)
			lwsl_info("reason: %s\n", cce);
		else
			cce = "unknown";
		lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "cbail3");
		return LWS_HPI_RET_WSI_ALREADY_DIED;

	default:
		break;
	}

	return 0;
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)

int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed_client(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int n;

	lwsl_info("%s: %s (%s)\n", __func__, lws_wsi_tag(wsi),
			wsi->a.protocol->name);

	// if (wsi->stream.ah && wsi->stream.ah->http_response)
	/* we're only judging if any (200, or 500 etc) http txn completed */
	lws_metrics_caliper_report(wsi->cal_conn, METRES_GO);

	if (user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
					LWS_CALLBACK_COMPLETED_CLIENT_HTTP,
					wsi->user_space, NULL, 0)) {
		lwsl_debug("%s: Completed call returned nonzero (role 0x%lx)\n",
			   __func__, (unsigned long)lwsi_role(wsi));
		return -1;
	}

	wsi->http.rx_content_length = 0;

	/*
	 * For h1, wsi may pass some assets on to a queued child and be
	 * destroyed during this.
	 */
	lws_pt_lock(pt, __func__);
	n = _lws_generic_transaction_completed_active_conn(&wsi, 1);
	lws_pt_unlock(pt);

	if (wsi->stream.ah) {
		if (wsi->client_mux_substream)
			/*
			 * As an h2 client, once we did our transaction, that is
			 * it for us.  Further transactions will happen as new
			 * SIDs on the connection.
			 */
			__lws_header_table_detach(wsi, 0);
		else
			if (!n)
				_lws_header_table_reset(wsi->stream.ah);
	}

	if (!n || !wsi->stream.ah)
		return 0;

	/*
	 * H1: we can serialize the queued guys into the same ah
	 * H2: everybody needs their own ah until their own STREAM_END
	 */

	/* otherwise set ourselves up ready to go again */

	wsi->stream.ah->parser_state = WSI_TOKEN_NAME_PART;
	wsi->stream.ah->lextable_pos = 0;
	wsi->stream.ah->unk_pos = 0;
	lws_header_table_rx_snapshot(wsi);

	lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
			(int)wsi->a.context->timeout_secs);

	/* If we're (re)starting on headers, need other implied init */
	wsi->stream.ah->ues = URIES_IDLE;
	lws_wsi_event(wsi, LWS_WSIEV_REQ_ISSUE);

	lwsl_info("%s: %s: new queued transaction\n", __func__, lws_wsi_tag(wsi));
	lws_callback_on_writable(wsi);

	return 0;
}

unsigned int
lws_http_client_http_response(struct lws *wsi)
{
	if (wsi->stream.ah && wsi->stream.ah->http_response)
		return wsi->stream.ah->http_response;

	return 0;
}
#endif


#if defined(LWS_WITH_HTTP_DIGEST_AUTH) && defined(LWS_WITH_TLS)

static const char *digest_toks[] = {
	"Digest",	// 1 <<  0
	"username",	// 1 <<  1
	"realm",	// 1 <<  2
	"nonce",	// 1 <<  3
	"uri",		// 1 <<  4 optional
	"response",	// 1 <<  5
	"opaque",	// 1 <<  6
	"qop",		// 1 <<  7
	"algorithm",	// 1 <<  8
	"nc",		// 1 <<  9
	"cnonce",	// 1 << 10
	"domain",	// 1 << 11
};

#define PEND_NAME_EQ -1
#define PEND_DELIM -2

enum lws_check_basic_auth_results
lws_http_digest_auth(struct lws* wsi)
{
	uint8_t nonce[256], response[LWS_GENHASH_LARGEST * 2 + 1], qop[32];
	int seen = 0, n, pend = -1;
	char *tmp_digest = NULL;
	struct lws_tokenize ts;
	char resp_username[32];
	lws_tokenize_elem e;
	char realm[64];
	char b64[512];
	int m, ml, fi;
	char algo[16];
	enum lws_genhash_types hash_type = LWS_GENHASH_TYPE_MD5;

	qop[0] = '\0';
	lws_strncpy(algo, "MD5", sizeof(algo));

	/* Did he send auth? */
	ml = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE);
	if (!ml)
		return LCBA_FAILED_AUTH;

	/* Disallow fragmentation monkey business */

	fi = wsi->stream.ah->frag_index[WSI_TOKEN_HTTP_WWW_AUTHENTICATE];
	if (wsi->stream.ah->frags[fi].nfrag) {
		lwsl_wsi_err(wsi, "fragmented http auth header not allowed\n");
		return LCBA_FAILED_AUTH;
	}

	m = lws_hdr_copy(wsi, b64, sizeof(b64), WSI_TOKEN_HTTP_WWW_AUTHENTICATE);
	if (m < 7) {
		lwsl_wsi_err(wsi, "HTTP auth length bad\n");
		return LCBA_END_TRANSACTION;
	}

	/*
	 * We are expecting AUTHORIZATION to have something like this
	 *
	 * Authorization: Digest
	 *   username="Mufasa",
	 *   realm="testrealm@host.com",
	 *   nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
	 *   uri="/dir/index.html",
	 *   response="e966c932a9242554e42c8ee200cec7f6",
	 *   opaque="5ccc069c403ebaf9f0171e9517f40e41"
	 *
	 * but the order, whitespace etc is quite open.  uri is optional
	 */
	lws_tokenize_init(&ts,b64, LWS_TOKENIZE_F_MINUS_NONTERM |
				   LWS_TOKENIZE_F_NO_INTEGERS |
				   LWS_TOKENIZE_F_RFC7230_DELIMS);

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			if (pend >= 0)
				goto str_val;

			if (!strncasecmp(ts.token, "Digest", ts.token_len)) {
				seen |= 1 << 0;
				break;
			}
			if (seen) /* we must be first and one time */
				return LCBA_END_TRANSACTION;

			seen |= 1 << 15;
			pend = PEND_NAME_EQ;
			break;

		case LWS_TOKZE_TOKEN_NAME_EQUALS:
			if ((seen & (1 << 15)) == (1 << 15) || pend != -1)
				/* no auth type token or disordered */
				return LCBA_END_TRANSACTION;

			for (n = 0; n < (int)LWS_ARRAY_SIZE(digest_toks); n++)
				if (!strncmp(ts.token, digest_toks[n], ts.token_len))
					break;

			if (n == LWS_ARRAY_SIZE(digest_toks)) {
				lwsl_wsi_notice(wsi, "c: '%.*s'\n",
						(int)ts.token_len,
						ts.token);

				return LCBA_END_TRANSACTION;
			}

			if (seen & (1 << n) || (seen & (1 << 15)) == (1 << 15))
				/* dup or no auth type token */
				return LCBA_END_TRANSACTION;

			seen |= 1 << n;
			pend = n;
			break;

		case LWS_TOKZE_QUOTED_STRING:
str_val:
			if (pend < 0)
				return LCBA_END_TRANSACTION;

			switch (pend) {
			case 1: /* username */
				if (ts.token_len >= (int)sizeof(resp_username))
					return LCBA_END_TRANSACTION;

				strncpy(resp_username, ts.token, ts.token_len);
				break;
			case 2: /* realm */
				if (ts.token_len >= (int)sizeof(realm))
					return LCBA_END_TRANSACTION;

				strncpy(realm, ts.token, ts.token_len);
				realm[ts.token_len] = 0;
				break;
			case 3: /* nonce */
				if (ts.token_len >= (int)sizeof(nonce))
					return LCBA_END_TRANSACTION;

				strncpy((char *)nonce, ts.token, ts.token_len);
				nonce[ts.token_len] = 0;
				break;
			case 4: /* uri */
				break;
			case 5: /* response */
				if (ts.token_len !=
					lws_genhash_size(hash_type) * 2)
					return LCBA_END_TRANSACTION;

				if (lws_hex_len_to_byte_array(ts.token, ts.token_len,
							  response,
							  sizeof(response)) < 0)
					return LCBA_END_TRANSACTION;
				break;
			case 6: /* opaque */
				break;
			case 7: /* qop */
				if (ts.token_len >= (int)sizeof(qop))
					return LCBA_END_TRANSACTION;

				strncpy((char *)qop, ts.token, ts.token_len);
				qop[ts.token_len] = '\0';
				{
					char *p = (char *)qop;
					while (p) {
						if (!strncmp(p, "auth", 4) && (p[4] == '\0' || p[4] == ',' || p[4] == ' ')) {
							strcpy((char *)qop, "auth");
							break;
						}
						p = (char *)strchr(p, ',');
						if (p) {
							p++;
							while (*p == ' ') p++;
						}
					}
					if (!p)
						return LCBA_END_TRANSACTION;
				}
				break;
			case 8: /* algorithm */
				if (ts.token_len == 3 && !strncasecmp(ts.token, "MD5", 3)) {
					hash_type = LWS_GENHASH_TYPE_MD5;
					lws_strncpy(algo, "MD5", sizeof(algo));
				} else if (ts.token_len == 7 && !strncasecmp(ts.token, "SHA-256", 7)) {
					hash_type = LWS_GENHASH_TYPE_SHA256;
					lws_strncpy(algo, "SHA-256", sizeof(algo));
				} else if (ts.token_len == 7 && !strncasecmp(ts.token, "SHA-384", 7)) {
					hash_type = LWS_GENHASH_TYPE_SHA384;
					lws_strncpy(algo, "SHA-384", sizeof(algo));
				} else if (ts.token_len == 7 && !strncasecmp(ts.token, "SHA-512", 7)) {
					hash_type = LWS_GENHASH_TYPE_SHA512;
					lws_strncpy(algo, "SHA-512", sizeof(algo));
				} else {
					lwsl_wsi_err(wsi, "wrong alg %.*s\n", (int)ts.token_len, ts.token);
					return LCBA_END_TRANSACTION;
				}
				break;
			}
			pend = PEND_DELIM;
			break;

			case LWS_TOKZE_DELIMITER:
				if (*ts.token == ',') {
					if (pend != PEND_DELIM)
						return LCBA_END_TRANSACTION;

					pend = PEND_NAME_EQ;
					break;
				}
				if (*ts.token == ';') {
					/* it's the end */
					e = LWS_TOKZE_ENDED;
					break;
				}
				break;

			case LWS_TOKZE_ENDED:
				break;

			default:
				lwsl_wsi_notice(wsi, "unexpected token %d\n", e);
				return LCBA_END_TRANSACTION;
		}

	} while (e > 0);

	/* we got all the parts we care about? Realm + Nonce... */

	if ((seen & 0xc) != 0xc) {
		lwsl_wsi_err(wsi,
				"%s: Not all digest auth tokens found! "
				"m: 0x%x\nServer sent: %s",
				__func__, seen & 0x81ef, b64);

		return LCBA_END_TRANSACTION;
	}

	lwsl_wsi_info(wsi, "HTTP digest auth realm %s nonce %s\n", realm, nonce);

	if (wsi->stash &&
	    wsi->stash->cis[CIS_PATH]) {
		char *username =  wsi->stash->cis[CIS_USERNAME];
		char *password = wsi->stash->cis[CIS_PASSWORD];
		uint8_t digest[LWS_GENHASH_LARGEST * 2 + 1];
		char *uri = wsi->stash->cis[CIS_PATH];
		char a1[LWS_GENHASH_LARGEST * 2 + 1];
		char a2[LWS_GENHASH_LARGEST * 2 + 1];
		char nc[sizeof(int) * 2 + 1];
		struct lws_genhash_ctx hc;
		int ncount = 1, ssl;
		const char *a, *p;
		struct lws *nwsi;
		char cnonce[256];
		size_t l;

		l = sizeof(a1) + sizeof(a2) + sizeof(nonce) +
			(sizeof(ncount) *2) + sizeof(response) +
			sizeof(cnonce) + sizeof(qop) + strlen(uri) +
			strlen(username) + strlen(password) +
			strlen(realm) + 111;

		tmp_digest = lws_malloc(l, __func__);
		if (!tmp_digest)
			return LCBA_FAILED_AUTH;

		n = lws_snprintf(tmp_digest, l, "%s:%s:%s",
				 username, realm, password);

		if (lws_genhash_init(&hc, hash_type) ||
				lws_genhash_update(&hc,
						   tmp_digest,
							(size_t)n) ||
				lws_genhash_destroy(&hc, digest)) {
			lws_genhash_destroy(&hc, NULL);

			goto bail;
		}

		lws_hex_from_byte_array(digest,
					lws_genhash_size(hash_type),
					a1, sizeof(a1));
		lwsl_debug("A1: %s:%s:%s = %s\n", username, realm, password, a1);

		/*
		 * In case of Websocket upgrade, method is NULL
		 * we assume it is a GET
		*/

		n = lws_snprintf(tmp_digest, l, "%s:%s",
				   wsi->stash->cis[CIS_METHOD] ?
				   wsi->stash->cis[CIS_METHOD] : "GET", uri);

		if (lws_genhash_init(&hc, hash_type) ||
				     lws_genhash_update(&hc,
						    tmp_digest,
						    (size_t)n) ||
				     lws_genhash_destroy(&hc, digest)) {
			lws_genhash_destroy(&hc, NULL);
			lwsl_err("%s: hash failed\n", __func__);

			goto bail;
		}
		lws_hex_from_byte_array(digest,
					lws_genhash_size(hash_type),
					a2, sizeof(a2));
		lwsl_debug("A2: %s:%s = %s\n", wsi->stash->cis[CIS_METHOD],
				uri, a2);

		lws_hex_random(lws_get_context(wsi), cnonce, sizeof(cnonce));
		lws_hex_from_byte_array((const uint8_t *)&ncount,
					sizeof(ncount), nc, sizeof(nc));

		if (qop[0])
			n = lws_snprintf(tmp_digest, l, "%s:%s:%08x:%s:%s:%s", a1,
					nonce, ncount, cnonce, qop, a2);
		else
			n = lws_snprintf(tmp_digest, l, "%s:%s:%s", a1,
					nonce, a2);

		lwsl_wsi_debug(wsi, "digest response: %s\n", tmp_digest);


		if (lws_genhash_init(&hc, hash_type) ||
				lws_genhash_update(&hc, tmp_digest, (size_t)n) ||
				lws_genhash_destroy(&hc, digest)) {
			lws_genhash_destroy(&hc, NULL);
			lwsl_wsi_err(wsi, "hash failed\n");

			goto bail;
		}
		lws_hex_from_byte_array(digest,
					lws_genhash_size(hash_type),
					(char *)response,
					lws_genhash_size(hash_type) * 2 + 1);

		if (qop[0]) {
			n = lws_snprintf(tmp_digest, l,
					 "Digest username=\"%s\", realm=\"%s\", "
					 "nonce=\"%s\", uri=\"%s\", qop=%s, nc=%08x, "
					 "cnonce=\"%s\", response=\"%s\", "
					 "algorithm=\"%s\"",
					 username, realm, nonce, uri, qop, ncount,
					 cnonce, response, algo);
		} else {
			n = lws_snprintf(tmp_digest, l,
					 "Digest username=\"%s\", realm=\"%s\", "
					 "nonce=\"%s\", uri=\"%s\", "
					 "response=\"%s\", "
					 "algorithm=\"%s\"",
					 username, realm, nonce, uri,
					 response, algo);
		}
		(void)n;

		lwsl_hexdump(tmp_digest, l);

		if (lws_hdr_simple_create(wsi, WSI_TOKEN_HTTP_AUTHORIZATION,
								tmp_digest)) {
			lwsl_wsi_err(wsi, "Failed to add Digest auth header");
			goto bail;
		}

		nwsi = lws_get_network_wsi(wsi);
		ssl = nwsi->tls.use_ssl & LCCSCF_USE_SSL;

		a = wsi->stash->cis[CIS_ADDRESS];
		p = &wsi->stash->cis[CIS_PATH][1];

		wsi->client_pipeline = 0;

		/*
		 * If the server kept the TCP/TLS connection alive on the 401
		 * and sent an explicitly empty body, reuse the existing
		 * session instead of tearing down and recreating it.
		 * Fall back to the close/reconnect path if any doubt exists.
		 */
		{
			const char *cl401 = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH);
			const char *te401 = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING);
			const char *conn = lws_hdr_simple_ptr(wsi, WSI_TOKEN_CONNECTION);
			int keep_alive = 1;

			if (conn) {
				struct lws_tokenize ts;
				lws_tokenize_init(&ts, conn, LWS_TOKENIZE_F_COMMA_SEP_LIST | LWS_TOKENIZE_F_MINUS_NONTERM);
				do {
					ts.e = (int8_t)lws_tokenize(&ts);
					if (ts.e == LWS_TOKZE_TOKEN &&
					    ts.token_len == 5 &&
					    !strncasecmp(ts.token, "close", 5)) {
						keep_alive = 0;
						break;
					}
				} while (ts.e > 0);
			}

			if (wsi->http.conn_type == HTTP_CONNECTION_KEEP_ALIVE &&
			    keep_alive &&
			    (!te401 || strncasecmp(te401, "chunked", 7)) &&
			    cl401 && atoi(cl401) == 0) {
				wsi->http.digest_auth_hdr = tmp_digest;
				return LCBA_AUTH_RETRY_KEEPALIVE;
			}
		}

		/*
		 * This prevents connection pipelining when two
		 * HTTP connection use the same tcp socket.
		 */
		wsi->keepalive_rejected = 1;

		if (!lws_client_reset(&wsi, ssl, a, wsi->c_port, p, a, 1)) {
			lwsl_wsi_err(wsi, "Failed to reset WSI for Digest auth");

			goto bail;
		}

		/*
		 * Keep track of digest auth to send it at next attempt, lws_client_reset will free it
		*/

		wsi->http.digest_auth_hdr = tmp_digest;
	} else {
		/*
		 * We have no stashed path to compute the digest response
		 * against (the client connect info left .path NULL)...
		 *
		 * We must not return LCBA_CONTINUE here: the caller takes that
		 * to mean we went through lws_client_reset(), ie, that the wsi
		 * is in LTS_RESTARTING and so survives the
		 * lws_close_free_wsi() it does next.  Without the reset the
		 * wsi is really freed there and touching it afterwards is a
		 * use-after-free.
		 */

		lwsl_wsi_err(wsi, "digest auth: no path stashed");

		return LCBA_FAILED_AUTH;
	}

	/*
	 * We only get here having successfully done lws_client_reset(), so
	 * the wsi is in LTS_RESTARTING and the caller's close leaves it
	 * extant for the retry
	 */

	return LCBA_CONTINUE;

bail:
	lws_free(tmp_digest);

	return LCBA_FAILED_AUTH;
}
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)

int
lws_http_is_redirected_to_get(struct lws *wsi)
{
	return wsi->redirected_to_get;
}

/*
 * Is the response head in the ah a 1xx interim (not 101 Switching Protocols,
 * which is the final response to an Upgrade)?  Only h1 has them: an h2 / h3
 * stream gets :status in its own HEADERS.
 */
static int
lws_http_client_response_is_interim(struct lws *wsi)
{
	const char *st;
	int n;

	if (wsi->client_mux_substream)
		return 0;

	st = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP);
	if (!st)
		return 0;

	n = atoi(st);

	return n >= 100 && n < 200 && n != 101;
}

int
lws_client_interpret_server_handshake(struct lws *wsi)
{
	int n, port = 0, ssl = 0;
	int close_reason = LWS_CLOSE_STATUS_PROTOCOL_ERR;
	const char *prot, *ads = NULL, *path, *cce = NULL;
	struct allocated_headers *ah, *ah1;
	struct lws *nwsi = lws_get_network_wsi(wsi);
	char *p = NULL, *q, *simp;
	char new_path[300];
#if defined(LWS_ROLE_WT)
	char wt_cce[40];
#endif
	lws_parse_uri_t *puri = NULL;

	// lws_free_set_NULL(wsi->stash);

#if defined(LWS_WITH_CONMON)
	wsi->conmon.ciu_txn_resp = (lws_conmon_interval_us_t)
					(lws_now_usecs() - wsi->conmon_datum);
#endif
	// lws_free_set_NULL(wsi->stash);

	ah = wsi->stream.ah;
	if (!wsi->do_ws) {
		/* we are being an http client...
		 */

		/*
		 * Learn any h3 alternative the server advertises on this
		 * authenticated response, so later connections to this origin
		 * can race QUIC to the right endpoint... but not from a 1xx
		 * interim, which is swallowed further down and would otherwise
		 * buy the server a cache write per interim
		 */

		if (!lws_http_client_response_is_interim(wsi))
			lws_client_alt_svc_learn(wsi);

#if defined(LWS_ROLE_WT)
		if (wsi->a.protocol && !strcmp(wsi->a.protocol->name, "webtransport")) {
			const char *st = lws_hdr_simple_ptr(wsi,
						WSI_TOKEN_HTTP_COLON_STATUS);

			/*
			 * The server may refuse the WebTransport CONNECT, eg,
			 * 403 from LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION.
			 * Anything other than 2xx means there is no session:
			 * fail the client connection rather than entering the
			 * wt role and waiting for a FIN.
			 */
			n = st ? atoi(st) : 0;
			if (n < 200 || n > 299) {
				if (ah)
					ah->http_response = (unsigned int)n;
				lws_snprintf(wt_cce, sizeof(wt_cce),
					     "HS: WT CONNECT refused %d", n);
				lwsl_wsi_notice(wsi, "%s", wt_cce);
				cce = wt_cce;
				goto bail3_l;
			}

			lwsl_debug("%s: %s: transitioning to WebTransport client\n",
				   __func__, lws_wsi_tag(wsi));
			lws_wsi_event(wsi, LWS_WSIEV_WT_SESSION);
			wsi->wt.is_session = 1;
		} else
#endif
		{
			/* the response headers are in: h1, or a mux stream */
			lws_wsi_event(wsi, LWS_WSIEV_RESP_HDRS);
		}

		wsi->stream.ah = ah;
		ah->http_response = 0;
	}

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)

	if ((wsi->flags & LCCSCF_CACHE_COOKIES) &&
	    !lws_http_client_response_is_interim(wsi) &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_SET_COOKIE))
		lws_parse_set_cookie(wsi);

#endif
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

	wsi->http.conn_type = HTTP_CONNECTION_KEEP_ALIVE;
	if (!wsi->client_mux_substream) {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP);
		/*
		if (wsi->do_ws && !p) {
			lwsl_info("no URI\n");
			cce = "HS: URI missing";
			goto bail3_l;
		}
		*/
		if (!p) {
			p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP1_0);
			wsi->http.conn_type = HTTP_CONNECTION_CLOSE;
		}
		if (!p) {
			cce = "HS: URI missing";
			lwsl_info("no URI\n");
			goto bail3_l;
		}
#if defined(LWS_ROLE_H2)
	} else {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_STATUS);
		if (!p) {
			cce = "HS: :status missing";
			lwsl_info("no status\n");
			goto bail3_l;
		}
#endif
	}
#if !defined(LWS_ROLE_H2)
	if (!p) {
		cce = "HS: :status missing";
		lwsl_info("no status\n");
		goto bail3_l;
	}
#endif
	n = atoi(p);

#if defined(LWS_WITH_HTTP_DIGEST_AUTH) && defined(LWS_WITH_TLS)
	if (n == 401 && lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE)) {
		if (!(wsi->stash && wsi->stash->cis[CIS_USERNAME] &&
                		    wsi->stash->cis[CIS_PASSWORD])) {
			/*
			 * Our contract with our caller is 0, or
			 * LWS_HPI_RET_WSI_ALREADY_DIED meaning we closed the
			 * wsi ourselves... an LCBA_xxx result here would be
			 * taken as "already died" while leaving the wsi alive
			 * and still in the fds table
			 */

			cce = "HS: digest auth wanted but no credentials";
			lwsl_wsi_err(wsi, "%s", cce);

			goto bail3_l;
		}

		enum lws_check_basic_auth_results auth_res = lws_http_digest_auth(wsi);

		if (auth_res == LCBA_AUTH_RETRY_KEEPALIVE) {
			/*
			 * Server kept the TCP/TLS connection alive:
			 * reuse it for the authenticated retry without
			 * any close/reconnect.  Reset the AH parser and
			 * re-populate client request headers from stash,
			 * then schedule a new HTTP handshake send.
			 */
			static const uint8_t hnames_cis[] = {
				_WSI_TOKEN_CLIENT_PEER_ADDRESS,
				_WSI_TOKEN_CLIENT_URI,
				_WSI_TOKEN_CLIENT_HOST,
				_WSI_TOKEN_CLIENT_ORIGIN,
				_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
				_WSI_TOKEN_CLIENT_METHOD,
				_WSI_TOKEN_CLIENT_IFACE,
				_WSI_TOKEN_CLIENT_ALPN
			};
			int m;

			lwsl_wsi_info(wsi, "digest auth: reusing TCP/TLS connection\n");

			_lws_header_table_reset(wsi->stream.ah);

			if (wsi->stash)
				for (m = 0; m < (int)LWS_ARRAY_SIZE(hnames_cis); m++)
					if (hnames_cis[m] &&
					    wsi->stash->cis[m] &&
					    lws_hdr_simple_create(wsi, hnames_cis[m], wsi->stash->cis[m]))
						goto bail3_l;

			wsi->stream.ah->ues = URIES_IDLE;
			lws_wsi_event(wsi, LWS_WSIEV_REQ_ISSUE);
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (auth_res)
			goto bail3_l;

		/*
		 * The close either restarts this wsi, keeping its opaque
		 * (close.c leaves the ss binding alone for a restart), or
		 * fails and frees it: nothing may be written to it after
		 */
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "digest_auth_step2");

		return -1;
	}

    ah = wsi->stream.ah;
#endif
	if (ah)
		ah->http_response = (unsigned int)n;

	if (n >= 100 && n < 200 && n != 101 && !wsi->client_mux_substream) {
		/*
		 * A 1xx interim response (100 Continue, 103 Early Hints...).
		 * RFC 9110 15.2: a client MUST be able to parse one or more of
		 * these before the final response, whether or not it asked for
		 * one with Expect.  101 Switching Protocols is not one of them:
		 * it is the final response to our Upgrade (ws, h2c), handled
		 * below.  An interim carries nothing for the user: rewind the
		 * header table to where the response section began, so our own
		 * request tokens survive, and go back to waiting for the real
		 * one.  It is the server talking to us, so the connection
		 * validity and the response timeout start again from here.
		 *
		 * But not for ever: each interim re-arms the response timeout,
		 * so a server sending one every few seconds would hold this
		 * wsi, its fd and its ah indefinitely for a few bytes each.
		 */
		if (!ah || ++ah->rx_interims > LWS_HTTP_INTERIM_RESPONSE_LIMIT) {
			cce = "HS: too many interim responses";
			goto bail3_l;
		}

		lwsl_wsi_info(wsi, "%d interim response, awaiting the final one",
			      n);
		lws_header_table_rx_rewind(wsi);
		/* the role transition above already moved us to ESTABLISHED */
		lws_wsi_event(wsi, LWS_WSIEV_RESP_INTERIM);
		lws_validity_confirmed(wsi);
		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				(int)wsi->a.context->timeout_secs);

		return 0;
	}

	if (!wsi->client_no_follow_redirect &&
#if defined(LWS_WITH_HTTP_PROXY)
	    !wsi->http.proxy_clientside &&
#endif
	    (n == 301 || n == 302 || n == 303 || n == 307 || n == 308)) {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_LOCATION);
		if (!p) {
			cce = "HS: Redirect code but no Location";
			goto bail3_l;
		}

#if defined(LWS_WITH_CONMON)
		if (wsi->conmon.pcol == LWSCONMON_PCOL_NONE) {
			wsi->conmon.pcol = LWSCONMON_PCOL_HTTP;
			wsi->conmon.protocol_specific.http.response = n;
		}

#if defined(LWS_WITH_SECURE_STREAMS)
		if (wsi->for_ss
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
		    && !wsi->client_bound_sspc
#endif
		   ) {
	
			lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);

			if (h)
				lws_conmon_ss_json(h);
		}
#endif
#endif

		/* let's let the user code know, if he cares */

		if (wsi->a.protocol->callback(wsi,
					LWS_CALLBACK_CLIENT_HTTP_REDIRECT,
					wsi->user_space, p, (unsigned int)n)) {
			cce = "HS: user code rejected redirect";
			goto bail3_l;
		}

		/* Relative reference absolute path */
		if (p[0] == '/' || !(char *)strchr(p, ':')) {
#if defined(LWS_WITH_TLS)
			ssl = nwsi->tls.use_ssl & LCCSCF_USE_SSL;
#endif
			ads = lws_hdr_simple_ptr(wsi,
						 _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			port = nwsi->c_port;
			path = p;
			/* lws_client_reset expects leading / omitted */
			if (*path == '/')
				path++;
		}
		/* Absolute (Full) URI */
		else if ((char *)strchr(p, ':')) {
			puri = lws_parse_uri_create(p);
			if (!puri) {
				cce = "HS: URI did not parse";
				goto bail3_l;
			}
			prot = puri->scheme;
			ads = puri->host;
			port = puri->port;
			path = puri->path;

			if (!strcmp(prot, "wss") || !strcmp(prot, "https"))
				ssl = LCCSCF_USE_SSL;
		}
		/* Relative reference relative path */
		else {
			/* This doesn't try to calculate an absolute path,
			 * that will be left to the server */
#if defined(LWS_WITH_TLS)
			ssl = nwsi->tls.use_ssl & LCCSCF_USE_SSL;
#endif
			ads = lws_hdr_simple_ptr(wsi,
						 _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			port = wsi->c_port;
			/* +1 as lws_client_reset expects leading / omitted */
			path = new_path + 1;
			if (lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI))
				lws_strncpy(new_path, lws_hdr_simple_ptr(wsi,
				   _WSI_TOKEN_CLIENT_URI), sizeof(new_path));
			else {
				new_path[0] = '/';
				new_path[1] = '\0';
			}
			q = (char *)strrchr(new_path, '/');
			if (q)
				lws_strncpy(q + 1, p, sizeof(new_path) -
							(unsigned int)(q - new_path) - 1);
			else
				path = p;
		}

		/*
		 * Some redirect codes imply we have to change the method
		 * used for the subsequent transaction.
		 *
		 * ugh... https://peterdaugaardrasmussen.com/2020/05/09/how-to-redirect-http-put-or-post-requests/
		 * says only 307 or 308 mean keep POST or other method
		 */

		if (n != 307 && n != 308) {
			char *mp = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
			int ml = lws_hdr_total_length(wsi, _WSI_TOKEN_CLIENT_METHOD);
			uint16_t pl = (uint16_t)strlen(path);

			if (ml >= 3 && mp) {
				lwsl_info("%s: 303 switching to GET\n", __func__);
				memcpy(mp, "GET", 4);
				wsi->redirected_to_get = 1;
				wsi->stream.ah->frags[wsi->stream.ah->frag_index[
					_WSI_TOKEN_CLIENT_METHOD]].len = 3;
			}
        		if (wsi->stash)
                		wsi->stash->cis[CIS_METHOD] = "GET";

			mp = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI);
			ml = lws_hdr_total_length(wsi, _WSI_TOKEN_CLIENT_URI);
			(void)mp;
			(void)ml;

			if (wsi->stream.ah->pos + pl + 1 >= wsi->stream.ah->data_length) {
				lwsl_warn("%s: redirect path exceeds ah size\n", __func__);
				goto bail3_l;
			}
			memcpy(wsi->stream.ah->data + wsi->stream.ah->pos + 1, path, pl + 1u);
			wsi->stream.ah->data[wsi->stream.ah->pos] = '/';
			wsi->stream.ah->frags[wsi->stream.ah->frag_index[_WSI_TOKEN_CLIENT_URI]].offset = wsi->stream.ah->pos;
			wsi->stream.ah->frags[wsi->stream.ah->frag_index[_WSI_TOKEN_CLIENT_URI]].len = (uint16_t)(pl + 1u);

			if (wsi->stash) {
				struct client_info_stash *ostash = wsi->stash;
				const char *cisin[CIS_COUNT];
				int m;

				wsi->stash = NULL;
				for (m = 0; m < CIS_COUNT; m++)
					cisin[m] = ostash->cis[m];
				cisin[CIS_PATH] = wsi->stream.ah->data + wsi->stream.ah->pos;

				if (lws_client_stash_create(wsi, cisin)) {
					lwsl_err("%s: failed to realloc stash for redirect\n", __func__);
					lws_free(ostash);
					cce = "HS: stash realloc failed";
					goto bail3_l;
				}
				lws_free(ostash);
			}

			wsi->stream.ah->pos += pl + 1u;
		}


#if defined(LWS_WITH_TLS)
		if ((wsi->tls.use_ssl & LCCSCF_USE_SSL) && !ssl &&
		     !(wsi->flags & LCCSCF_ACCEPT_TLS_DOWNGRADE_REDIRECTS)) {
			cce = "HS: Redirect attempted SSL downgrade";
			goto bail3_l;
		}
#endif

		if (!ads) /* make coverity happy */ {
			cce = "no ads";
			goto bail3_l;
		}

		if (!lws_client_reset(&wsi, ssl, ads, port, path, ads, 1)) {
			lwsl_err("Redirect failed\n");
			cce = "HS: Redirect failed";
			goto bail3_l;
		}

		/*
		 * We are redirecting, let's close in order to extricate
		 * ourselves from the current wsi usage, eg, h2 mux cleanly.
		 *
		 * We will notice LTS_RESTARTING and switch to redirect
		 * flow late in the close action.
		 */

		/* restarts the wsi, or fails and frees it: no write after */
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "redir");

		if (puri)
			lws_parse_uri_destroy(&puri);

		return LWS_HPI_RET_WSI_ALREADY_DIED;
	}

	/* if h1 KA is allowed, enable the queued pipeline guys */

	if (lwsi_role_h1(wsi)) {
		/* ie, coming to this for the first time */
		if (wsi->http.conn_type != HTTP_CONNECTION_KEEP_ALIVE) {
			/*
			 * The role the restarted guys go back to... this has
			 * to be computed outside the event macro's argument
			 * list, MSVC rejects #if inside one (C5101)
			 */
			const struct lws_role_ops *rops =
#if defined(LWS_ROLE_H1)
						   &role_ops_h1;
#elif defined(LWS_ROLE_H2)
						   &role_ops_h2;
#elif defined(LWS_ROLE_H3)
						   &role_ops_h3;
#else
						   NULL;
#endif

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

			lws_vhost_lock(wsi->a.vhost);
			lws_start_foreach_dll_safe(struct lws_dll2 *,
						   d, d1,
			  lws_dll2_get_head(&wsi->dll2_cli_txn_queue_owner)) {
				struct lws *ww = lws_container_of(d,
					struct lws,
					dll2_cli_txn_queue);

				/* remove him from our queue */
				lws_dll2_remove(&ww->dll2_cli_txn_queue);
				/* give up on pipelining */
				ww->client_pipeline = 0;

				/* go back to "trying to connect" state */
				lws_wsi_event_role(ww, LWS_WSIEV_RESTART, rops);
				ww->user_space = NULL;
			} lws_end_foreach_dll_safe(d, d1);
			lws_vhost_unlock(wsi->a.vhost);
		}
	}

#ifdef LWS_WITH_HTTP_PROXY
	wsi->http.perform_rewrite = 0;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE)) {
		if (!strncmp(lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE),
					"text/html", 9))
			wsi->http.perform_rewrite = 0;
	}
#endif

	/* he may choose to send us stuff in chunked transfer-coding */
	wsi->http.rx_chunked = 0;
	wsi->http.chunk_remaining = 0; /* ie, next thing is chunk size */
	wsi->http.chunk_skip = 0;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING)) {
		simp = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING);

		/* cannot be NULL, since it has nonzero length... coverity */
		if (!simp)
			goto bail2;
		if (!strcasecmp(simp, "chunked")) {
			wsi->http.rx_chunked = 1;
		} else {
			lwsl_err("%s: unsupported TE %s\n", __func__, simp);
			cce = "HS: unsupported TE";
			goto bail2;
		}
		/* first thing is hex, after payload there is crlf */
		wsi->http.chunk_parser = ELCP_HEX;
	}

	wsi->http.content_length_given = 0;
	if (wsi->http.rx_chunked &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		/*
		 * RFC 9112 6.3: with both, Transfer-Encoding overrides
		 * Content-Length.  Taking the Content-Length as well left
		 * rx_content_remain clamping every body slice, and chunked
		 * delivery never decrements it, so a "Content-Length: 1"
		 * made us deliver (and a proxy forward) the body a byte at
		 * a time.
		 */
		lwsl_wsi_notice(wsi, "ignoring Content-Length with chunked");
		wsi->http.rx_content_length = 0;
		wsi->http.rx_content_remain = 0;
	} else if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		simp = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH);

		/* cannot be NULL, since it has nonzero length... coverity */
		if (!simp)
			goto bail2;

		{
			long long cl_val = atoll(simp);
			if (cl_val < 0)
				goto bail2;
			wsi->http.rx_content_length = (lws_filepos_t)cl_val;
		}
		lwsl_info("%s: incoming content length %llu\n",
			    __func__, (unsigned long long)
				    wsi->http.rx_content_length);
		wsi->http.rx_content_remain =
				wsi->http.rx_content_length;
		wsi->http.content_length_given = 1;
	} else { /* can't do 1.1 without a content length or chunked */
		if (!wsi->http.rx_chunked)
			wsi->http.conn_type = HTTP_CONNECTION_CLOSE;
		lwsl_debug("%s: no content length\n", __func__);
	}

	if (wsi->do_ws) {
		/*
		 * Give one last opportunity to ws protocols to inspect server reply
		 * before the ws upgrade code discard it. ie: download reply body in case
		 * of any other response code than 101.
		 */
		if (wsi->a.protocol->callback(wsi,
					  LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					  wsi->user_space, NULL, 0)) {

			cce = "HS: disallowed by client filter";
			goto bail2;
		}
	} else {
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
		ah1 = wsi->stream.ah;
		wsi->stream.ah = ah;
		if (wsi->a.protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
					    wsi->user_space, NULL, 0)) {
			wsi->stream.ah = ah1;
			cce = "HS: disallowed by client filter";
			goto bail2;
		}

		/* clear his proxy connection timeout */
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

		/* call him back to inform him he is up */
		if (wsi->a.protocol->callback(wsi,
					    LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					    wsi->user_space, NULL, 0)) {
			wsi->stream.ah = ah1;
			cce = "HS: disallowed at ESTABLISHED";
			goto bail3_l;
		}

		wsi->stream.ah = ah1;

		lwsl_info("%s: %s: client conn up\n", __func__, lws_wsi_tag(wsi));

		/*
		 * Did we get a response from the server with an explicit
		 * content-length of zero?  If so, and it's not H2 which will
		 * notice it via END_STREAM, this transaction is already
		 * completed at the end of the header processing...
		 * We also completed it if the request method is HEAD which as
		 * no content leftover.
		 * Or if the response status code is 204 : No Content
		 */
		simp = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
		if (!wsi->mux_substream &&
		    !wsi->client_mux_substream &&
			(204 == lws_http_client_http_response(wsi) ||
			 (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
				(!wsi->http.rx_content_length ||
				(simp && !strcmp(simp,"HEAD")))))) {
			if (!lws_http_transaction_completed_client(wsi))
				return 0;

			/*
			 * The user callback asked us to close from
			 * LWS_CALLBACK_COMPLETED_CLIENT_HTTP... nothing did the
			 * close for us, and our caller only understands 0 or
			 * LWS_HPI_RET_WSI_ALREADY_DIED, so do it here
			 */

			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "client txn completed close");

			return LWS_HPI_RET_WSI_ALREADY_DIED;
		}

		/*
		 * We can also get a case where it's http/1 and there's no
		 * content-length at all, so anything that comes is the body
		 * until it hangs up on us.  With that situation, hanging up
		 * on us past this point should generate a valid
		 * LWS_CALLBACK_COMPLETED_CLIENT_HTTP.
		 *
		 * In that situation, he can't pipeline because in h1 there's
		 * no post-header in-band way to signal the end of the
		 * transaction except hangup.
		 *
		 * lws_http_transaction_completed_client() is the right guy to
		 * issue it when we see the peer has hung up on us.
		 */

		return 0;
	}

#if defined(LWS_ROLE_WS)
	switch (lws_client_ws_upgrade(wsi, &cce)) {
	case 2:
		goto bail2;
	case 3:
		goto bail3_l;
	}

	return 0;
#endif

bail3_l:
	close_reason = LWS_CLOSE_STATUS_NOSTATUS;

bail2:
	if (wsi->a.protocol) {
		n = 0;
		if (cce)
			n = (int)strlen(cce);

		lws_inform_client_conn_fail(wsi, (void *)cce, (unsigned int)n);
	}

	lwsl_info("closing connection (prot %s) "
		  "due to bail2 connection error: %s\n", wsi->a.protocol ?
				  wsi->a.protocol->name : "unknown", cce);

	/* closing will free up his parsing allocations */
	lws_close_free_wsi(wsi, (enum lws_close_status)close_reason, "c hs interp");

	if (puri)
		lws_parse_uri_destroy(&puri);

	return LWS_HPI_RET_WSI_ALREADY_DIED;
}
#endif

/*
 * set the boundary string and the content-type for client multipart mime
 *
 * \p end is one past the last byte we may write at \p p
 */

uint8_t *
lws_http_multipart_headers(struct lws *wsi, uint8_t *p, uint8_t *end)
{
	char buf[10], arg[48];
	int n;

	if (lws_get_random(wsi->a.context, (uint8_t *)buf, sizeof(buf)) !=
			sizeof(buf))
		return NULL;

	lws_b64_encode_string(buf, sizeof(buf),
			       wsi->http.multipart_boundary,
			       sizeof(wsi->http.multipart_boundary));

	n = lws_snprintf(arg, sizeof(arg), "multipart/form-data; boundary=\"%s\"",
			 wsi->http.multipart_boundary);

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (uint8_t *)arg, n, &p, end))
		return NULL;

	wsi->http.multipart = wsi->http.multipart_issue_boundary = 1;
	lws_client_http_body_pending(wsi, 1);

	return p;
}

int
lws_client_http_multipart(struct lws *wsi, const char *name,
			  const char *filename, const char *content_type,
			  char **p, char *end)
{
	/*
	 * Client conn must have been created with LCCSCF_HTTP_MULTIPART_MIME
	 * flag to use this api
	 */
	assert(wsi->http.multipart);

	if (!name) {
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p),
					"\xd\xa--%s--\xd\xa",
					wsi->http.multipart_boundary);

		return 0;
	}

	if (wsi->client_subsequent_mime_part)
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "\xd\xa");
	wsi->client_subsequent_mime_part = 1;

	*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "--%s\xd\xa"
				    "Content-Disposition: form-data; "
				      "name=\"%s\"",
				      wsi->http.multipart_boundary, name);
	if (filename)
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p),
				   "; filename=\"%s\"", filename);

	if (content_type)
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "\xd\xa"
				"Content-Type: %s", content_type);

	*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "\xd\xa\xd\xa");

	return *p == end;
}

/*
 * replacement multipart state machine
 *
 * We want it to emit this kind of thing:
 *
 * POST /builds?project=warmcat%2Flibwebsockets HTTP/1.1
 * Host: 127.0.0.1
 * User-Agent: lws
 * Accept: * / *
 * Content-Length: 698
 * Content-Type: multipart/form-data; boundary=------------------------dbe229171d826cc3
 *
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="file"; filename="xxx.bin"
 * Content-Type: application/octet-stream
 *
 * #!/bin/bash -x
 * xxx
 * exit $?
 *
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="version"
 *
 * f2dcc4ea
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="description"
 * 
 * lws qa
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="token"
 *
 * mytoken
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="email"
 *
 * my@email.com
 * --------------------------dbe229171d826cc3--
 *
 */

typedef enum {
	LWS_POST_STATE__NEXT,
	LWS_POST_STATE__FILE,
	LWS_POST_STATE__DATA,
} post_state;

typedef struct lws_http_mp_sm {
	struct lws_context	*cx;
	lws_http_mp_sm_cb_t	cb;
	char			boundary[24 + 16 + 1];
	char			ft[4096];
	char			*eq;
	int			fd;
	lws_filepos_t		pos;
	lws_filepos_t		total;
	const char		*a; /* last hit */
	post_state		ps;
} lws_http_mp_sm_t;

struct lws_http_mp_sm *
lws_http_mp_sm_init(struct lws *wsi, lws_http_mp_sm_cb_t cb, uint8_t **p, uint8_t *end)
{
	struct lws_http_mp_sm *phms;
	char cla[512 + sizeof(phms->boundary)], ft[256], *eq;
	uint64_t cl = 0;
	struct stat s;
	int n;

	phms = lws_malloc(sizeof(*phms), __func__);
	if (!phms)
		return NULL;
	phms->cb = cb;
	phms->cx = lws_get_context(wsi);

	for (n = 0; n < 24; n++)
		phms->boundary[n] = '-';
	lws_hex_random(phms->cx, phms->boundary + 24, 16);
	phms->boundary[24 + 16] = '\0';

	n = lws_snprintf(cla, sizeof(cla), "multipart/form-data; boundary=%s", phms->boundary);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
		     (const uint8_t *)cla, n, p, end)) {
		lwsl_warn("%s: failed to set content_type\n", __func__);
		goto bail;
	}

	/*
	 * We have to now add together the length of everything we will put in
	 * the body, in order to know the content-length now at header-time.
	 *
	 * That includes the multipart boundaries, headers, and CRLF delimiters.
	 */

	phms->a = NULL;
	do {
		/* The cb will a) use cla / len as a scratchpad and
		 * b) provide a string formelem=@name or formelem=name */

		n = phms->cb(lws_get_context(wsi), ft, sizeof(ft), &phms->a);
		if (n < 0)
			goto bail;
		if (n)
			break;
		eq = (char *)strchr(ft, '=');
		if (eq) {
			*eq = '\0';
			eq++;
		} /* ft contains the lhs of the = (now NUL) and eq the rhs sz */

		cl += 2 /* -- */ + strlen(phms->boundary) + 2 /* CRLF */;
		if (eq && *eq == '@') { /* ie, form file contents */
			cl += (unsigned int)lws_snprintf(cla, sizeof(cla),
					   "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\x0d\x0a"
					   "Content-Type: application/octet-stream\x0d\x0a\x0d\x0a",
					   ft, eq + 1);
			if (stat(eq + 1, &s)) {
				lwsl_warn("%s: failed to stat %s\n", __func__, eq + 1);
				goto bail;
			}

			cl += (uint64_t)s.st_size + 2 /* ending CRLF */;
			continue;
		}

		/* form data */

		cl += (unsigned int)lws_snprintf(cla, sizeof(cla),
				   "Content-Disposition: form-data; name=\"%s\"\x0d\x0a\x0d\x0a", ft);
		if (eq)
			cl += strlen(eq) + 2 /* CRLF */;

	} while (1);

	cl += 2 /* -- */ + strlen(phms->boundary) + 2 /* -- */ + 2 /* CRLF */;

	// lwsl_warn("%s: going with content length 0x%x\n", __func__, (unsigned int)cl);

	if (lws_add_http_header_content_length(wsi, cl, p, end))
		goto bail;

	phms->a		= NULL;
	phms->pos	= 0;
	phms->total	= 0;
	phms->ps	= LWS_POST_STATE__NEXT;

	/*
	 * Tell lws we are going to send the body next...
	 */

	return phms;

bail:
	free(phms);

	return NULL;
}

void
lws_http_mp_sm_destroy(struct lws_http_mp_sm **pphms)
{
	if (*pphms) {
		lws_free(*pphms);
		*pphms = NULL;
	}
}

int
lws_http_mp_sm_fill(struct lws_http_mp_sm *phms, uint8_t **p, uint8_t *end)
{
	int n;

	assert(phms);

	do {
		switch (phms->ps) {
		case LWS_POST_STATE__NEXT:

			if (lws_ptr_diff(end, *p) < 300)
				return 1;

			n = phms->cb(phms->cx, phms->ft, sizeof(phms->ft), &phms->a);
			if (n < 0) { /* error */
				return -1;
			}
			if (n) { /* no more form elements */
				*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "--%s--\x0d\x0a", phms->boundary);

				return 0; /* finished then */
			}

			phms->eq = (char *)strchr(phms->ft, '=');
			if (phms->eq) {
				*phms->eq = '\0';
				phms->eq++;
			} /* phms->ft contains the lhs of the = (now NUL) and eq the rhs sz */

			*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "--%s\x0d\x0a", phms->boundary);

			if (phms->eq && *phms->eq == '@') { /* ie, form file contents */
				struct stat s;

				*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p),
						   "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\x0d\x0a"
						   "Content-Type: application/octet-stream\x0d\x0a\x0d\x0a",
						   phms->ft, phms->eq + 1);
				phms->fd = open(phms->eq + 1, O_RDONLY);
				if (phms->fd == -1) {
					lwsl_warn("%s: unable to open '%s'\n", __func__, phms->eq + 1);
					return -1; /* failed */
				}
				if (fstat(phms->fd, &s)) {
					lwsl_warn("%s: failed to stat %s\n", __func__, phms->eq + 1);
					return -1; /* failed */
				}
				phms->pos = 0;
				phms->total = (lws_filepos_t)s.st_size;
				phms->ps = LWS_POST_STATE__FILE;
				continue;
			}

			/* form data */

			*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p),
				   "Content-Disposition: form-data; name=\"%s\"\x0d\x0a\x0d\x0a", phms->ft);
			phms->ps = LWS_POST_STATE__DATA;
			break;

		case LWS_POST_STATE__FILE: {
			size_t chunk = lws_ptr_diff_size_t(end, *p) - 2;
			ssize_t r;

			if (lws_ptr_diff(end, *p) < 100)
                                return 1;

			r = read(phms->fd, *p, LWS_POSIX_LENGTH_CAST(chunk));
			if (r < 0) {
				close(phms->fd);
				lwsl_warn("%s: unable to read\n", __func__);
				return -1; /* failed */
			}

			*p += r;
			phms->pos += (uint64_t)r;
			if (phms->pos == phms->total) {
				**p = '\x0d';
				*p += 1;
				**p = '\x0a';
				*p += 1;
				close(phms->fd);
				phms->ps = LWS_POST_STATE__NEXT;
			}
			break;
		}
		case LWS_POST_STATE__DATA:
			if (lws_ptr_diff(end, *p) < 300)
				return 1;

			*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "%s\x0d\x0a", phms->eq);
			phms->ps = LWS_POST_STATE__NEXT;
			break;

		} /* switch */
	} while (lws_ptr_diff(end, *p) > 100);

	return 1; /* more to do */
}


char *
lws_generate_client_handshake(struct lws *wsi, char *pkt, size_t pkt_len)
{
	const char *meth, *pp = lws_hdr_simple_ptr(wsi,
				_WSI_TOKEN_CLIENT_SENT_PROTOCOLS), *path;
	char *p = pkt, *p1, *end = p + pkt_len;

	meth = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
	if (!meth) {
		meth = "GET";
#if defined(LWS_ROLE_WS)
		wsi->do_ws = wsi->ws ? 1 : 0;
#else
		wsi->do_ws = 0;
#endif
	} else {
		wsi->do_ws = 0;
	}

	if (!strcmp(meth, "RAW")) {
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
		lwsl_notice("client transition to raw\n");

		if (pp) {
			const struct lws_protocols *pr;

			pr = lws_vhost_name_to_protocol(wsi->a.vhost, pp);

			if (!pr) {
				lwsl_err("protocol %s not enabled on vhost\n",
					 pp);
				return NULL;
			}

			lws_bind_protocol(wsi, pr, __func__);
		}

		if ((wsi->a.protocol->callback)(wsi, LWS_CALLBACK_RAW_ADOPT,
					      wsi->user_space, NULL, 0))
			return NULL;

		lws_wsi_event(wsi, LWS_WSIEV_RAW_UPGRADED);
		lws_header_table_detach(wsi, 1);

		return NULL;
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

	path = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI);
	if (!path) {
		if (wsi->stash && wsi->stash->cis[CIS_PATH] &&
			wsi->stash->cis[CIS_PATH][0])
			path = wsi->stash->cis[CIS_PATH];
		else
			path = "/";
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "%s %s HTTP/1.1\x0d\x0a", meth, path);

	if (!(wsi->flags & LCCSCF_HTTP_NO_CACHE_CONTROL))
		p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
				  "Pragma: no-cache\x0d\x0a"
				  "Cache-Control: no-cache\x0d\x0a");

	const char *host = lws_wsi_client_stash_item(wsi, CIS_HOST, _WSI_TOKEN_CLIENT_HOST);
	if (host)
		p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
				  "Host: %s\x0d\x0a", host);

	const char *origin = lws_wsi_client_stash_item(wsi, CIS_ORIGIN, _WSI_TOKEN_CLIENT_ORIGIN);
	if (origin) {
		if (lws_check_opt(wsi->a.context->options,
				  LWS_SERVER_OPTION_JUST_USE_RAW_ORIGIN))
			p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
					  "Origin: %s\x0d\x0a", origin);
		else
			p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
					  "Origin: %s://%s\x0d\x0a",
					  wsi->flags & LCCSCF_USE_SSL ?
							 "https" : "http",
					  origin);
	}

	if (wsi->flags & LCCSCF_HTTP_MULTIPART_MIME) {
		p1 = (char *)lws_http_multipart_headers(wsi, (uint8_t *)p,
							(uint8_t *)end);
		if (!p1)
			return NULL;
		p = p1;
	}

	/*
	 * A proxied onward leg used to copy Content-Length, Authorization and
	 * Content-Type from the parent's ah here, and splice the parent's
	 * extra onward headers in verbatim.  Both now happen in the proxy's
	 * LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER handler, from the
	 * snapshot lws_http_proxy_start() took while the ah was attached, so
	 * the composer has no dependency on the parent's ah (C-460), and the
	 * same replay serves an h2 onward leg, which never saw them before.
	 */

#if defined(LWS_WITH_HTTP_DIGEST_AUTH)
    if (wsi->http.digest_auth_hdr) {
        p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "Authorization: %s\x0d\x0a",
                          wsi->http.digest_auth_hdr);
        lws_free(wsi->http.digest_auth_hdr);
        wsi->http.digest_auth_hdr = NULL;
    }
#endif

#if defined(LWS_ROLE_WS)
	if (wsi->do_ws) {
		const char *conn1 = "";
	//	if (!wsi->client_pipeline)
	//		conn1 = "close, ";
		p = lws_generate_client_ws_handshake(wsi, p, conn1,
						     lws_ptr_diff_size_t(end, p));
                if (!p)
                    return NULL;
	} else
#endif
	{
		if (!wsi->client_pipeline)
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "connection: close\x0d\x0a");
	}

	/* give userland a chance to append, eg, cookies */

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)
	if ((wsi->flags & LCCSCF_CACHE_COOKIES) &&
	    lws_cookie_send_cookies(wsi, &p, end)) {
		/* better no request than one carrying scratch as cookies */
		lwsl_wsi_err(wsi, "cookie jar attach failed");

		return NULL;
	}
#endif

	/*
	 * lws_snprintf() returns size on truncation, so if any emit above did
	 * not fit, p is sitting exactly on end and everything after it was
	 * silently dropped.  We must not go on to tell the user callback how
	 * much room is left by subtracting from that, since the result
	 * underflows to ~4GB and any bound the callback derives from it is
	 * then meaningless.  A truncated request head is not something we can
	 * send anyway, so fail the connection.
	 */

	if (lws_ptr_diff(end, p) <= 12) {
		lwsl_wsi_err(wsi, "request head too long for pt_serv_buf");

		return NULL;
	}

	if (wsi->a.protocol->callback(wsi,
			LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
			wsi->user_space, &p,
			lws_ptr_diff_size_t(end, p) - 12))
		return NULL;

	if (wsi->flags & LCCSCF_HTTP_X_WWW_FORM_URLENCODED) {
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "Content-Type: application/x-www-form-urlencoded\x0d\x0a");
		p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p), "Content-Length: %lu\x0d\x0a", wsi->http.writeable_len);
		lws_client_http_body_pending(wsi, 1);
	}

	p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p), "\x0d\x0a");

	/*
	 * Same again for anything the user callback and the tail emitted...
	 * if p ended up on end, the head is truncated (it may not even have
	 * its terminating CRLF) and must not be sent
	 */

	if (p >= end) {
		lwsl_wsi_err(wsi, "request head truncated");

		return NULL;
	}

	if (wsi->client_http_body_pending || lws_has_buffered_out(wsi))
		lws_callback_on_writable(wsi);

	lws_metrics_caliper_bind(wsi->cal_conn, wsi->a.context->mt_http_txn);
#if defined(LWS_WITH_CONMON)
	wsi->conmon_datum = lws_now_usecs();
#endif

	// puts(pkt);

	return p;
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
#if defined(LWS_WITH_HTTP_BASIC_AUTH)

int
lws_http_basic_auth_gen2(const char *user, const void *pw, size_t pwd_len,
			 char *buf, size_t len)
{
	size_t n = strlen(user), m = pwd_len;
	char b[128];

	if (len < 6 + ((4 * (n + m + 1)) / 3) + 1)
		return 1;

	memcpy(buf, "Basic ", 6);

	n = (unsigned int)lws_snprintf(b, sizeof(b), "%s:", user);
	if ((n + pwd_len) >= sizeof(b) - 2)
		return 2;

	memcpy(&b[n], pw, pwd_len);
	n += pwd_len;

	lws_b64_encode_string(b, (int)n, buf + 6, (int)len - 6);
	buf[len - 1] = '\0';

	return 0;
}

int lws_http_basic_auth_gen(const char *user, const char *pw, char *buf, size_t len)
{
	return lws_http_basic_auth_gen2(user, pw, strlen(pw), buf, len);
}

#endif

/*
 * sansIO body rx for an http client: the bytes the app pulled with
 * lws_http_client_read(), or none when the transport ended.  Strips any
 * chunked framing, delivers the payload to the app in
 * LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ (a callback per chunk block), keeps
 * the content accounting and completes the transaction when the body is
 * done.  Returns the bytes taken, or LWS_RX_CLOSE.
 */
int
lws_h1_client_body_rx(struct lws *wsi, uint8_t *buf, size_t len)
{
	unsigned char *p = buf;
	int rem = (int)len, consumed = 0, n;

	if (!len) {
		if (!lwsi_hdrs_pending(wsi) &&
		    !wsi->http.content_length_given && !wsi->http.rx_chunked) {
			/*
			 * We had the headers from this stream, but as there
			 * was no content-length: we had to wait until the
			 * stream ended to inform the user code the transaction
			 * has completed to the best of our knowledge
			 */
			lwsl_wsi_info(wsi, "body ended with the stream");
			if (lws_http_transaction_completed_client(wsi))
				/* closing anyway, the api has warn_unused_result */
				return LWS_RX_CLOSE;
		}

		return LWS_RX_CLOSE;
	}

	wsi->client_rx_avail = 0;

	/*
	 * server may insist on transfer-encoding: chunked,
	 * so http client must deal with it
	 */
spin_chunks:
	if (wsi->http.rx_chunked) {
		unsigned char *b = p;
		size_t l = (size_t)rem;

		/* consume any chunk framing before the next payload bytes */

		n = lws_http_dechunk_framing(wsi, &b, &l);
		consumed += rem - (int)l;
		p = b;
		rem = (int)l;

		if (n < 0)
			return LWS_RX_CLOSE;

		if (n > 0)
			/* that was the terminating chunk */
			goto completed;

		if (!rem)
			/* need more to get to the next payload bytes */
			return consumed;
	}

	if (wsi->http.rx_content_remain &&
	    wsi->http.rx_content_remain < (unsigned int)rem)
		n = (int)wsi->http.rx_content_remain;
	else
		n = rem;

	if (wsi->http.rx_chunked && wsi->http.chunk_remaining &&
	    wsi->http.chunk_remaining < n)
		n = wsi->http.chunk_remaining;

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_WITH_HUBBUB)
	/* hubbub */
	if (wsi->http.perform_rewrite)
		lws_rewrite_parse(wsi->http.rw, p, n);
	else
#endif
	{
		if (
#if defined(LWS_WITH_HTTP_PROXY)
		    !wsi->protocol_bind_balance ==
		    !!wsi->http.proxy_clientside
#else
		    !!wsi->protocol_bind_balance
#endif
		  ) {
			if (user_callback_handle_rxflow(wsi->a.protocol->callback,
					wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
					wsi->user_space, p, (unsigned int)n)) {
				lwsl_wsi_info(wsi, "RECEIVE_CLIENT_HTTP_READ refused");

				return LWS_RX_CLOSE;
			}
		} else
			lwsl_wsi_notice(wsi, "swallowed read (%d)", n);
	}

	p += n;
	rem -= n;
	if (wsi->http.rx_chunked && wsi->http.chunk_remaining)
		wsi->http.chunk_remaining -= n;

	consumed += n;

	if (wsi->http.rx_chunked && !wsi->http.chunk_remaining)
		wsi->http.chunk_parser = ELCP_POST_CR;

	if (wsi->http.rx_chunked && rem)
		goto spin_chunks;

	if (wsi->http.rx_chunked)
		return consumed;

	/* if we know the content length, decrement the content remaining */
	if (wsi->http.rx_content_length > 0)
		wsi->http.rx_content_remain -= (unsigned int)n;

	if (wsi->http.rx_content_remain || !wsi->http.content_length_given)
		return consumed;

completed:
	if (lws_http_transaction_completed_client(wsi)) {
		lwsl_wsi_info(wsi, "transaction completed says -1");

		return LWS_RX_CLOSE;
	}

	return consumed;
}

#endif

static uint8_t hnames2[] = {
	_WSI_TOKEN_CLIENT_ORIGIN,
	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	_WSI_TOKEN_CLIENT_METHOD,
	_WSI_TOKEN_CLIENT_IFACE
};

/**
 * lws_client_reset() - retarget a connected wsi to start over with a new
 * 			connection (ie, redirect)
 *			this only works if still in HTTP, ie, not upgraded yet
 * wsi:		connection to reset
 * address:	network address of the new server
 * port:	port to connect to
 * path:	uri path to connect to on the new server
 * host:	host header to send to the new server
 */
struct lws *
lws_client_reset(struct lws **pwsi, int ssl, const char *address, int port,
		const char *path, const char *host, char weak)
{
#if defined(LWS_ROLE_WS)
	struct _lws_websocket_related *ws;
#endif
	const char *cisin[CIS_COUNT];
	struct lws *wsi;
	size_t o;
	int n, r;

	if (!pwsi)
		return NULL;

	wsi = *pwsi;

	lwsl_debug("%s: %s: redir %d: %s\n", __func__, lws_wsi_tag(wsi),
			wsi->redirects, address);

	if (wsi->redirects == 4) {
		lwsl_err("%s: Too many redirects\n", __func__);
		return NULL;
	}
	wsi->redirects++;

	/*
	 * goal is to close our role part, close the sockfd, detach the ah
	 * but leave our wsi extant and still bound to whatever vhost it was
	 */

	o = path[0] == '/' && path[1] == '/';

	memset((char *)cisin, 0, sizeof(cisin));

	cisin[CIS_ADDRESS]	= address;
	cisin[CIS_PATH]		= path + o;
	cisin[CIS_HOST]		= host;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(hnames2); n++) {
		cisin[n + 3] = lws_hdr_simple_ptr(wsi, hnames2[n]);
#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
		if (!cisin[n + 3] && hnames2[n] == _WSI_TOKEN_CLIENT_METHOD)
			cisin[n + 3] = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD);
#endif
	}

	r = wsi->stream.ah ? (int)wsi->stream.ah->http_response : 0;

#if defined(LWS_WITH_TLS)
	cisin[CIS_ALPN]		= wsi->alpn;
#endif

	if (!port) {
		lwsl_info("%s: forcing port 443\n", __func__);

		port = 443;
		ssl = 1;
	}

	wsi->c_port = (uint16_t)port;

	wsi->flags = (wsi->flags & (~LCCSCF_USE_SSL)) |
		(ssl ? LCCSCF_USE_SSL : 0);

	if (!cisin[CIS_ALPN] || !cisin[CIS_ALPN][0])
#if defined(LWS_ROLE_H2)
		cisin[CIS_ALPN] = "h2,http/1.1";
#else
	cisin[CIS_ALPN] = "http/1.1";
#endif

	lwsl_notice("%s: REDIRECT %d: %s %s:%d, path='%s', ssl = %d, alpn='%s'\n",
		    __func__, r, cisin[CIS_METHOD], address,
		    port, path, ssl, cisin[CIS_ALPN]);

	{
		/*
		 * The wsi's own binding is the live one: a stash that
		 * survived the first connect may carry none (the redirect
		 * case: it was what the post-close restore in the redirect
		 * path used to put back), and when we are reset from inside
		 * the close flow (the h3 grace timer, a failed QUIC attempt
		 * falling back to tcp) the stash is already gone.  Fall back
		 * to the stash only if the wsi has no binding.
		 */
		void *opaque = wsi->a.opaque_user_data;

		if (!opaque && wsi->stash)
			opaque = wsi->stash->opaque_user_data;

		if (lws_client_stash_create(wsi, cisin))
			return NULL;

		wsi->stash->opaque_user_data = opaque;
	}

#if defined(LWS_ROLE_H3) || defined(LWS_ROLE_QUIC)
	lws_sul_cancel(&wsi->sul_h3_grace);
#endif
	/* the old transport is no longer watched; the close releases it */
	lws_io_unwatch(wsi);

#if defined(LWS_ROLE_WS)
	if (weak) {
		ws = wsi->ws;
		wsi->ws = NULL;
	}
#endif

	/*
	 * After this point we can't trust the incoming strings like address,
	 * path any more, since they may have been pointing into the old ah.
	 *
	 * We must use the copies in the wsi->stash instead if we want them.
	 */

	__lws_reset_wsi(wsi); /* detaches ah here */
#if defined(LWS_ROLE_WS)
	if (weak)
		wsi->ws = ws;
#endif
	wsi->client_pipeline = 1;

	/*
	 * We could be a redirect before, or after the POST was done.
	 * Http's hack around this is 307 / 308 keep the method, ie,
	 * it's pre and they have to repeat the body.  Other 3xx
	 * turn it into a GET.
	 */

	if ((r / 100) == 3 && r != 307 && r != 308)
		wsi->redirected_to_get = 1;

	/*
	 * Will complete at close flow: the close sees the restarting phase and
	 * hands the wsi back to the connect path instead of freeing it
	 */

	lws_wsi_event(wsi, LWS_WSIEV_RETARGET);

	return *pwsi;
}
