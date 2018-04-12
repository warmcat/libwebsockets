/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#include <private-libwebsockets.h>

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif


/*
 * We have to take care about parsing because the headers may be split
 * into multiple fragments.  They may contain unknown headers with arbitrary
 * argument lengths.  So, we parse using a single-character at a time state
 * machine that is completely independent of packet size.
 *
 * Returns <0 for error or length of chars consumed from buf (up to len)
 */

int
lws_read_h1(struct lws *wsi, unsigned char *buf, lws_filepos_t len)
{
	unsigned char *last_char, *oldbuf = buf;
	lws_filepos_t body_chunk_len;
	size_t n;

	// lwsl_notice("%s: h1 path: wsi state 0x%x\n", __func__, lwsi_state(wsi));

	switch (lwsi_state(wsi)) {

	case LRS_ISSUING_FILE:
		return 0;

	case LRS_ESTABLISHED:

		if (lwsi_role_ws(wsi))
			goto ws_mode;

		if (lwsi_role_client(wsi))
			break;

		wsi->hdr_parsing_completed = 0;

		/* fallthru */

	case LRS_HEADERS:
		if (!wsi->ah) {
			lwsl_err("%s: LRS_HEADERS: NULL ah\n", __func__);
			assert(0);
		}
		lwsl_parser("issuing %d bytes to parser\n", (int)len);

		if (lws_handshake_client(wsi, &buf, (size_t)len))
			goto bail;

		last_char = buf;
		if (lws_handshake_server(wsi, &buf, (size_t)len))
			/* Handshake indicates this session is done. */
			goto bail;

		/* we might have transitioned to RAW */
		if (wsi->role_ops == &role_ops_raw_skt ||
		    wsi->role_ops == &role_ops_raw_file)
			 /* we gave the read buffer to RAW handler already */
			goto read_ok;

		/*
		 * It's possible that we've exhausted our data already, or
		 * rx flow control has stopped us dealing with this early,
		 * but lws_handshake_server doesn't update len for us.
		 * Figure out how much was read, so that we can proceed
		 * appropriately:
		 */
		len -= (buf - last_char);
//		lwsl_debug("%s: thinks we have used %ld\n", __func__, (long)len);

		if (!wsi->hdr_parsing_completed)
			/* More header content on the way */
			goto read_ok;

		switch (lwsi_state(wsi)) {
			case LRS_ESTABLISHED:
			case LRS_HEADERS:
				goto read_ok;
			case LRS_ISSUING_FILE:
				goto read_ok;
			case LRS_BODY:
				wsi->http.rx_content_remain =
						wsi->http.rx_content_length;
				if (wsi->http.rx_content_remain)
					goto http_postbody;

				/* there is no POST content */
				goto postbody_completion;
			default:
				break;
		}
		break;

	case LRS_BODY:
http_postbody:
		//lwsl_notice("http post body\n");
		while (len && wsi->http.rx_content_remain) {
			/* Copy as much as possible, up to the limit of:
			 * what we have in the read buffer (len)
			 * remaining portion of the POST body (content_remain)
			 */
			body_chunk_len = min(wsi->http.rx_content_remain, len);
			wsi->http.rx_content_remain -= body_chunk_len;
			len -= body_chunk_len;
#ifdef LWS_WITH_CGI
			if (wsi->cgi) {
				struct lws_cgi_args args;

				args.ch = LWS_STDIN;
				args.stdwsi = &wsi->cgi->stdwsi[0];
				args.data = buf;
				args.len = body_chunk_len;

				/* returns how much used */
				n = user_callback_handle_rxflow(
					wsi->protocol->callback,
					wsi, LWS_CALLBACK_CGI_STDIN_DATA,
					wsi->user_space,
					(void *)&args, 0);
				if ((int)n < 0)
					goto bail;
			} else {
#endif
				n = wsi->protocol->callback(wsi,
					LWS_CALLBACK_HTTP_BODY, wsi->user_space,
					buf, (size_t)body_chunk_len);
				if (n)
					goto bail;
				n = (size_t)body_chunk_len;
#ifdef LWS_WITH_CGI
			}
#endif
			buf += n;

			if (wsi->http.rx_content_remain)  {
				lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
						wsi->context->timeout_secs);
				break;
			}
			/* he sent all the content in time */
postbody_completion:
#ifdef LWS_WITH_CGI
			/*
			 * If we're running a cgi, we can't let him off the
			 * hook just because he sent his POST data
			 */
			if (wsi->cgi)
				lws_set_timeout(wsi, PENDING_TIMEOUT_CGI,
						wsi->context->timeout_secs);
			else
#endif
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
#ifdef LWS_WITH_CGI
			if (!wsi->cgi)
#endif
			{
				lwsl_info("HTTP_BODY_COMPLETION\n");
				n = wsi->protocol->callback(wsi,
					LWS_CALLBACK_HTTP_BODY_COMPLETION,
					wsi->user_space, NULL, 0);
				if (n)
					goto bail;

				if (wsi->http2_substream)
					lwsi_set_state(wsi, LRS_ESTABLISHED);
			}

			break;
		}
		break;

	case LRS_AWAITING_CLOSE_ACK:
	case LRS_WAITING_TO_SEND_CLOSE:
	case LRS_SHUTDOWN:

ws_mode:

		if (lws_handshake_client(wsi, &buf, (size_t)len))
			goto bail;
#if defined(LWS_ROLE_WS)
		if (lwsi_role_ws(wsi) && lwsi_role_server(wsi) &&
			/*
			 * for h2 we are on the swsi
			 */
		    lws_interpret_incoming_packet(wsi, &buf, (size_t)len) < 0) {
			lwsl_info("interpret_incoming_packet bailed\n");
			goto bail;
		}
#endif
		break;

	case LRS_DEFERRING_ACTION:
		lwsl_debug("%s: LRS_DEFERRING_ACTION\n", __func__);
		break;

	case LRS_SSL_ACK_PENDING:
		break;

	case LRS_DEAD_SOCKET:
		lwsl_err("%s: Unhandled state LRS_DEAD_SOCKET\n", __func__);
		assert(0);
		/* fallthru */

	default:
		lwsl_err("%s: Unhandled state %d\n", __func__, lwsi_state(wsi));
		assert(0);
		goto bail;
	}

read_ok:
	/* Nothing more to do for now */
//	lwsl_info("%s: %p: read_ok, used %ld (len %d, state %d)\n", __func__,
//		  wsi, (long)(buf - oldbuf), (int)len, wsi->state);

	return lws_ptr_diff(buf, oldbuf);

bail:
	/*
	 * h2 / h2-ws calls us recursively in lws_read()->lws_h2_parser()->
	 * lws_read() pattern, having stripped the h2 framing in the middle.
	 *
	 * When taking down the whole connection, make sure that only the
	 * outer lws_read() does the wsi close.
	 */
	if (!wsi->outer_will_close)
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "lws_read bail");

	return -1;
}

int
lws_h1_server_socket_service(struct lws *wsi, struct lws_pollfd *pollfd)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct allocated_headers *ah;
	int n, len;

	if (lwsi_state(wsi) == LRS_DEFERRING_ACTION)
		goto try_pollout;

	/* any incoming data ready? */

	if (!(pollfd->revents & pollfd->events & LWS_POLLIN))
		goto try_pollout;

	/*
	 * If we previously just did POLLIN when IN and OUT were
	 * signalled (because POLLIN processing may have used up
	 * the POLLOUT), don't let that happen twice in a row...
	 * next time we see the situation favour POLLOUT
	 */
	if (wsi->favoured_pollin &&
	    (pollfd->revents & pollfd->events & LWS_POLLOUT)) {
		// lwsl_notice("favouring pollout\n");
		wsi->favoured_pollin = 0;
		goto try_pollout;
	}

	/*
	 * We haven't processed that the tunnel is set up yet, so
	 * defer reading
	 */
	if (lwsi_state(wsi) == LRS_SSL_ACK_PENDING)
		return LWS_HPI_RET_HANDLED;

	/* these states imply we MUST have an ah attached */

	if ((lwsi_state(wsi) == LRS_ESTABLISHED ||
	     lwsi_state(wsi) == LRS_ISSUING_FILE ||
	     lwsi_state(wsi) == LRS_HEADERS)) {
		if (!wsi->ah) {
			/* no autoservice beacuse we will do it next */
			if (lws_header_table_attach(wsi, 0)) {
				lwsl_info("wsi %p: ah get fail\n", wsi);
				goto try_pollout;
			}
		}
		ah = wsi->ah;

		assert(ah->rxpos <= ah->rxlen);
		/* if nothing in ah rx buffer, get some fresh rx */
		if (ah->rxpos == ah->rxlen) {

			if (wsi->preamble_rx) {
				memcpy(ah->rx, wsi->preamble_rx, wsi->preamble_rx_len);
				lws_free_set_NULL(wsi->preamble_rx);
				ah->rxlen = wsi->preamble_rx_len;
				wsi->preamble_rx_len = 0;
			} else {
				ah->rxlen = lws_ssl_capable_read(wsi, ah->rx,
					   sizeof(ah->rx));
			}

			ah->rxpos = 0;
			switch (ah->rxlen) {
			case 0:
				lwsl_info("%s: read 0 len a\n",
					   __func__);
				wsi->seen_zero_length_recv = 1;
				lws_change_pollfd(wsi, LWS_POLLIN, 0);
				 goto try_pollout;
				//goto fail;

			case LWS_SSL_CAPABLE_ERROR:
				goto fail;
			case LWS_SSL_CAPABLE_MORE_SERVICE:
				ah->rxlen = ah->rxpos = 0;
				goto try_pollout;
			}
		}

		if (!(ah->rxpos != ah->rxlen && ah->rxlen)) {
			lwsl_err("%s: assert: rxpos %d, rxlen %d\n",
				 __func__, ah->rxpos, ah->rxlen);

			assert(0);
		}

		/* just ignore incoming if waiting for close */
		if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE ||
		    lwsi_state(wsi) == LRS_ISSUING_FILE)
			goto try_pollout;

		/*
		 * otherwise give it to whoever wants it
		 * according to the connection state
		 */
#if defined(LWS_ROLE_H2)
		if (lwsi_role_h2(wsi) && lwsi_state(wsi) != LRS_BODY)
			n = lws_read_h2(wsi, ah->rx + ah->rxpos,
					ah->rxlen - ah->rxpos);
		else
#endif
			n = lws_read_h1(wsi, ah->rx + ah->rxpos,
					ah->rxlen - ah->rxpos);
		if (n < 0) /* we closed wsi */
			return LWS_HPI_RET_DIE;

		if (!wsi->ah)
			return LWS_HPI_RET_HANDLED;
		if (wsi->ah->rxlen)
			 wsi->ah->rxpos += n;

		lwsl_debug("%s: wsi %p: ah read rxpos %d, rxlen %d\n",
			   __func__, wsi, wsi->ah->rxpos,
			   wsi->ah->rxlen);

		if (lws_header_table_is_in_detachable_state(wsi) &&
		    (wsi->role_ops == &role_ops_raw_skt ||
		     wsi->role_ops == &role_ops_raw_file)) // ???
			lws_header_table_detach(wsi, 1);

		/* during the parsing we upgraded to ws */

		if (wsi->ah && wsi->ah->rxpos == wsi->ah->rxlen &&
		    lwsi_role_ws(wsi)) {
			lwsl_info("%s: %p: dropping ah on ws post-upgrade\n",
				  __func__, wsi);
			lws_header_table_force_to_detachable_state(wsi);
			lws_header_table_detach(wsi, 0);
		}

		return LWS_HPI_RET_HANDLED;
	}

	len = lws_read_or_use_preamble(pt, wsi);
	if (len < 0)
		goto fail;

	if (!len)
		goto try_pollout;

	/* just ignore incoming if waiting for close */
	if (lwsi_state(wsi) != LRS_FLUSHING_BEFORE_CLOSE &&
	    lwsi_state(wsi) != LRS_ISSUING_FILE) {
		/*
		 * this may want to send
		 * (via HTTP callback for example)
		 *
		 * returns number of bytes used
		 */
#if defined(LWS_ROLE_H2)
		if (lwsi_role_h2(wsi) && lwsi_state(wsi) != LRS_BODY)
			n = lws_read_h2(wsi, pt->serv_buf, len);
		else
#endif
			n = lws_read_h1(wsi, pt->serv_buf, len);
		if (n < 0) /* we closed wsi */
			return LWS_HPI_RET_DIE;

		if (n != len) {
			if (wsi->preamble_rx) {
				lwsl_err("DISCARDING %d (ah %p)\n", len - n, wsi->ah);

				goto fail;
			}
			assert(n < len);
			wsi->preamble_rx = lws_malloc(len - n, "preamble_rx");
			if (!wsi->preamble_rx) {
				lwsl_err("OOM\n");
				goto fail;
			}
			memcpy(wsi->preamble_rx, pt->serv_buf + n, len - n);
			wsi->preamble_rx_len = (int)len - n;
			lwsl_debug("stashed %d\n", (int)wsi->preamble_rx_len);
		}

		/*
		 *  he may have used up the
		 * writability above, if we will defer POLLOUT
		 * processing in favour of POLLIN, note it
		 */
		if (pollfd->revents & LWS_POLLOUT)
			wsi->favoured_pollin = 1;
		return LWS_HPI_RET_HANDLED;
	}
	/*
	 *  he may have used up the
	 * writability above, if we will defer POLLOUT
	 * processing in favour of POLLIN, note it
	 */
	if (pollfd->revents & LWS_POLLOUT)
		wsi->favoured_pollin = 1;

try_pollout:

	/* this handles POLLOUT for http serving fragments */

	if (!(pollfd->revents & LWS_POLLOUT))
		return LWS_HPI_RET_HANDLED;

	/* one shot */
	if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
		lwsl_notice("%s a\n", __func__);
		goto fail;
	}

	/* clear back-to-back write detection */
	wsi->could_have_pending = 0;

	if (lwsi_state(wsi) == LRS_DEFERRING_ACTION) {
		lwsl_debug("%s: LRS_DEFERRING_ACTION now writable\n",
			   __func__);

		if (wsi->ah)
			lwsl_debug("     existing ah rxpos %d / rxlen %d\n",
			   wsi->ah->rxpos, wsi->ah->rxlen);
		lwsi_set_state(wsi, LRS_ESTABLISHED);
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_info("failed at set pollfd\n");
			goto fail;
		}
	}

	if (!wsi->hdr_parsing_completed)
		return LWS_HPI_RET_HANDLED;

	if (lwsi_state(wsi) != LRS_ISSUING_FILE) {

		lws_stats_atomic_bump(wsi->context, pt,
					LWSSTATS_C_WRITEABLE_CB, 1);
#if defined(LWS_WITH_STATS)
		if (wsi->active_writable_req_us) {
			uint64_t ul = time_in_microseconds() -
					wsi->active_writable_req_us;

			lws_stats_atomic_bump(wsi->context, pt,
					LWSSTATS_MS_WRITABLE_DELAY, ul);
			lws_stats_atomic_max(wsi->context, pt,
				  LWSSTATS_MS_WORST_WRITABLE_DELAY, ul);
			wsi->active_writable_req_us = 0;
		}
#endif

		n = user_callback_handle_rxflow(wsi->protocol->callback,
				wsi, LWS_CALLBACK_HTTP_WRITEABLE,
				wsi->user_space, NULL, 0);
		if (n < 0) {
			lwsl_info("writeable_fail\n");
			goto fail;
		}

		return LWS_HPI_RET_HANDLED;
	}

	/* >0 == completion, <0 == error
	 *
	 * We'll get a LWS_CALLBACK_HTTP_FILE_COMPLETION callback when
	 * it's done.  That's the case even if we just completed the
	 * send, so wait for that.
	 */
	n = lws_serve_http_file_fragment(wsi);
	if (n < 0)
		goto fail;

	return LWS_HPI_RET_HANDLED;


fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "server socket svc fail");

	return LWS_HPI_RET_DIE;
}

static int
rops_handle_POLLIN_h1(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_pollfd *pollfd)
{

//	lwsl_notice("%s: %p: wsistate 0x%x %s, revents 0x%x\n", __func__, wsi,
//			wsi->wsistate, wsi->role_ops->name, pollfd->revents);

#ifdef LWS_WITH_CGI
	if (wsi->cgi && (pollfd->revents & LWS_POLLOUT)) {
		if (lws_handle_POLLOUT_event(wsi, pollfd))
			return LWS_HPI_RET_CLOSE_HANDLED;

		return LWS_HPI_RET_HANDLED;
	}
#endif

        if (lwsi_state(wsi) == LRS_RETURNED_CLOSE ||
            lwsi_state(wsi) == LRS_WAITING_TO_SEND_CLOSE ||
            lwsi_state(wsi) == LRS_AWAITING_CLOSE_ACK) {
                /*
                 * we stopped caring about anything except control
                 * packets.  Force flow control off, defeat tx
                 * draining.
                 */
                lws_rx_flow_control(wsi, 1);
                if (wsi->ws)
                        wsi->ws->tx_draining_ext = 0;
        }

        if (lws_is_flowcontrolled(wsi))
                /* We cannot deal with any kind of new RX because we are
                 * RX-flowcontrolled.
                 */
		return LWS_HPI_RET_HANDLED;

#if !defined(LWS_NO_SERVER)
	if (!lwsi_role_client(wsi)) {
		int n;

		lwsl_debug("%s: %p: wsistate 0x%x\n", __func__, wsi, wsi->wsistate);
		n = lws_h1_server_socket_service(wsi, pollfd);
		if (n != LWS_HPI_RET_HANDLED)
			return n;
		if (lwsi_state(wsi) != LRS_SSL_INIT)
			if (lws_server_socket_service_ssl(wsi, LWS_SOCK_INVALID))
				return LWS_HPI_RET_CLOSE_HANDLED;

		return LWS_HPI_RET_HANDLED;
	}
#endif

#ifndef LWS_NO_CLIENT
	if ((pollfd->revents & LWS_POLLIN) &&
	     wsi->hdr_parsing_completed && !wsi->told_user_closed) {

		/*
		 * In SSL mode we get POLLIN notification about
		 * encrypted data in.
		 *
		 * But that is not necessarily related to decrypted
		 * data out becoming available; in may need to perform
		 * other in or out before that happens.
		 *
		 * simply mark ourselves as having readable data
		 * and turn off our POLLIN
		 */
		wsi->client_rx_avail = 1;
		lws_change_pollfd(wsi, LWS_POLLIN, 0);

		//lwsl_notice("calling back %s\n", wsi->protocol->name);

		/* let user code know, he'll usually ask for writeable
		 * callback and drain / re-enable it there
		 */
		if (user_callback_handle_rxflow(
				wsi->protocol->callback,
				wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP,
				wsi->user_space, NULL, 0)) {
			lwsl_info("RECEIVE_CLIENT_HTTP closed it\n");
			return LWS_HPI_RET_CLOSE_HANDLED;
		}

		return LWS_HPI_RET_HANDLED;
	}
#endif

//	if (lwsi_state(wsi) == LRS_ESTABLISHED)
//		return LWS_HPI_RET_HANDLED;

#if !defined(LWS_NO_CLIENT)
	if ((pollfd->revents & LWS_POLLOUT) &&
	    lws_handle_POLLOUT_event(wsi, pollfd)) {
		lwsl_debug("POLLOUT event closed it\n");
		return LWS_HPI_RET_CLOSE_HANDLED;
	}

	if (lws_client_socket_service(wsi, pollfd, NULL))
		return LWS_HPI_RET_DIE;
#endif

	return LWS_HPI_RET_HANDLED;
}

int rops_handle_POLLOUT_h1(struct lws *wsi)
{
	if (lwsi_state(wsi) == LRS_ISSUE_HTTP_BODY)
		return LWS_HP_RET_USER_SERVICE;

	if (lwsi_role_client(wsi))
		return LWS_HP_RET_USER_SERVICE;

	return LWS_HP_RET_BAIL_OK;
}

static int
rops_service_flag_pending_h1(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct allocated_headers *ah;
	int forced = 0;

	/* POLLIN faking (the pt lock is taken by the parent) */

	/*
	 * 3) For any wsi who have an ah with pending RX who did not
	 * complete their current headers, and are not flowcontrolled,
	 * fake their POLLIN status so they will be able to drain the
	 * rx buffered in the ah
	 */
	ah = pt->ah_list;
	while (ah) {
		if ((ah->rxpos != ah->rxlen &&
		    !ah->wsi->hdr_parsing_completed) || ah->wsi->preamble_rx) {
			pt->fds[ah->wsi->position_in_fds_table].revents |=
				pt->fds[ah->wsi->position_in_fds_table].events &
					LWS_POLLIN;
			if (pt->fds[ah->wsi->position_in_fds_table].revents &
			    LWS_POLLIN) {
				forced = 1;
				break;
			}
		}
		ah = ah->next;
	}

	return forced;
}

static int
rops_write_role_protocol_h1(struct lws *wsi, unsigned char *buf, size_t len,
			    enum lws_write_protocol *wp)
{
#if 0
	/* if not in a state to send stuff, then just send nothing */

	if ((lwsi_state(wsi) != LRS_RETURNED_CLOSE &&
	     lwsi_state(wsi) != LRS_WAITING_TO_SEND_CLOSE &&
	     lwsi_state(wsi) != LRS_AWAITING_CLOSE_ACK)) {
		//assert(0);
		lwsl_debug("binning %d %d\n", lwsi_state(wsi), *wp);
		return 0;
	}
#endif

	return lws_issue_raw(wsi, (unsigned char *)buf, len);
}

static int
rops_alpn_negotiated_h1(struct lws *wsi, const char *alpn)
{
	lwsl_debug("%s: client %d\n", __func__, lwsi_role_client(wsi));
#if !defined(LWS_NO_CLIENT)
	if (lwsi_role_client(wsi)) {
		/*
		 * If alpn asserts it is http/1.1, server support for KA is
		 * mandatory.
		 *
		 * Knowing this lets us proceed with sending pipelined headers
		 * before we received the first response headers.
		 */
		wsi->keepalive_active = 1;
	}
#endif

	return 0;
}

struct lws_role_ops role_ops_h1 = {
	/* role name */			"h1",
	/* alpn id */			"http/1.1",
	/* check_upgrades */		NULL,
	/* init_context */		NULL,
	/* init_vhost */		NULL,
	/* periodic_checks */		NULL,
	/* service_flag_pending */	rops_service_flag_pending_h1,
	/* handle_POLLIN */		rops_handle_POLLIN_h1,
	/* handle_POLLOUT */		rops_handle_POLLOUT_h1,
	/* perform_user_POLLOUT */	NULL,
	/* callback_on_writable */	NULL,
	/* tx_credit */			NULL,
	/* write_role_protocol */	rops_write_role_protocol_h1,
	/* rxflow_cache */		NULL,
	/* encapsulation_parent */	NULL,
	/* alpn_negotiated */		rops_alpn_negotiated_h1,
	/* close_via_role_protocol */	NULL,
	/* close_role */		NULL,
	/* close_kill_connection */	NULL,
	/* destroy_role */		NULL,
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_CLIENT_HTTP_WRITEABLE,
					  LWS_CALLBACK_HTTP_WRITEABLE },
	/* close cb clnt, srv */	{ LWS_CALLBACK_CLOSED_CLIENT_HTTP,
					  LWS_CALLBACK_CLOSED_HTTP },
};
