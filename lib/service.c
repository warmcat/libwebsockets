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

int
lws_calllback_as_writeable(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int n, m;

	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_WRITEABLE_CB, 1);
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

	switch (lwsi_role(wsi)) {
	case LWSI_ROLE_RAW_SOCKET:
		n = LWS_CALLBACK_RAW_WRITEABLE;
		break;
	case LWSI_ROLE_RAW_FILE:
		n = LWS_CALLBACK_RAW_WRITEABLE_FILE;
		break;
	case LWSI_ROLE_WS1_CLIENT:
	case LWSI_ROLE_WS2_CLIENT:
		n = LWS_CALLBACK_CLIENT_WRITEABLE;
		break;
	case LWSI_ROLE_H1_CLIENT:
	case LWSI_ROLE_H2_CLIENT:
		n = LWS_CALLBACK_CLIENT_HTTP_WRITEABLE;
		break;
	case LWSI_ROLE_WS1_SERVER:
	case LWSI_ROLE_WS2_SERVER:
		n = LWS_CALLBACK_SERVER_WRITEABLE;
		break;
	default:
		n = LWS_CALLBACK_HTTP_WRITEABLE;
		break;
	}

	m = user_callback_handle_rxflow(wsi->protocol->callback,
					   wsi, (enum lws_callback_reasons) n,
					   wsi->user_space, NULL, 0);

	return m;
}

LWS_VISIBLE int
lws_handle_POLLOUT_event(struct lws *wsi, struct lws_pollfd *pollfd)
{
	int write_type = LWS_WRITE_PONG;
	int n;
	volatile struct lws *vwsi = (volatile struct lws *)wsi;

#if !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_tokens eff_buf;
	int ret, m;
#endif

	lwsl_info("%s: %p\n", __func__, wsi);

	vwsi->leave_pollout_active = 0;
	vwsi->handling_pollout = 1;
	/*
	 * if another thread wants POLLOUT on us, from here on while
	 * handling_pollout is set, he will only set leave_pollout_active.
	 * If we are going to disable POLLOUT, we will check that first.
	 */

	/*
	 * user callback is lowest priority to get these notifications
	 * actually, since other pending things cannot be disordered
	 */

	/* Priority 1: pending truncated sends are incomplete ws fragments
	 *	       If anything else sent first the protocol would be
	 *	       corrupted.
	 */
	wsi->could_have_pending = 0; /* clear back-to-back write detection */
	if (wsi->trunc_len) {
		//lwsl_notice("%s: completing partial\n", __func__);
		if (lws_issue_raw(wsi, wsi->trunc_alloc + wsi->trunc_offset,
				  wsi->trunc_len) < 0) {
			lwsl_info("%s signalling to close\n", __func__);
			goto bail_die;
		}
		/* leave POLLOUT active either way */
		goto bail_ok;
	} else
		if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE) {
			wsi->socket_is_permanently_unusable = 1;
			goto bail_die; /* retry closing now */
		}

	if (lwsi_state(wsi) == LRS_ISSUE_HTTP_BODY)
		goto user_service;

#ifdef LWS_WITH_HTTP2
	/*
	 * Priority 2: H2 protocol packets
	 */
	if ((wsi->upgraded_to_http2
#if !defined(LWS_NO_CLIENT)
			|| wsi->client_h2_alpn
#endif
			) && wsi->h2.h2n->pps) {
		lwsl_info("servicing pps\n");
		if (lws_h2_do_pps_send(wsi)) {
			wsi->socket_is_permanently_unusable = 1;
			goto bail_die;
		}
		if (wsi->h2.h2n->pps)
			goto bail_ok;

		/* we can resume whatever we were doing */
		lws_rx_flow_control(wsi, LWS_RXFLOW_REASON_APPLIES_ENABLE |
					 LWS_RXFLOW_REASON_H2_PPS_PENDING);

		goto bail_ok; /* leave POLLOUT active */
	}
#endif

#ifdef LWS_WITH_CGI
	if (wsi->cgi) {
		/* also one shot */
		if (pollfd)
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				lwsl_info("failed at set pollfd\n");
				return 1;
			}
		goto user_service_go_again;
	}
#endif

	/* Priority 3: pending control packets (pong or close)
	 *
	 * 3a: close notification packet requested from close api
	 */

	if (lwsi_state(wsi) == LRS_WAITING_TO_SEND_CLOSE) {
		lwsl_debug("sending close packet\n");
		wsi->waiting_to_send_close_frame = 0;
		n = lws_write(wsi, &wsi->ws->ping_payload_buf[LWS_PRE],
			      wsi->ws->close_in_ping_buffer_len,
			      LWS_WRITE_CLOSE);
		if (n >= 0) {
			lwsi_set_state(wsi, LRS_AWAITING_CLOSE_ACK);
			lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_ACK, 5);
			lwsl_debug("sent close indication, awaiting ack\n");

			goto bail_ok;
		}

		goto bail_die;
	}

	/* else, the send failed and we should just hang up */

	if ((lwsi_role_ws(wsi) && wsi->ws->ping_pending_flag) ||
	    (lwsi_state(wsi) == LRS_RETURNED_CLOSE &&
	     wsi->ws->payload_is_close)) {

		if (wsi->ws->payload_is_close)
			write_type = LWS_WRITE_CLOSE;

		n = lws_write(wsi, &wsi->ws->ping_payload_buf[LWS_PRE],
			      wsi->ws->ping_payload_len, write_type);
		if (n < 0)
			goto bail_die;

		/* well he is sent, mark him done */
		wsi->ws->ping_pending_flag = 0;
		if (wsi->ws->payload_is_close) {
			// assert(0);
			/* oh... a close frame was it... then we are done */
			goto bail_die;
		}

		/* otherwise for PING, leave POLLOUT active either way */
		goto bail_ok;
	}

	if (lwsi_role_ws_client(wsi) && !wsi->socket_is_permanently_unusable &&
	    wsi->ws->send_check_ping) {

		lwsl_info("issuing ping on wsi %p\n", wsi);
		wsi->ws->send_check_ping = 0;
		n = lws_write(wsi, &wsi->ws->ping_payload_buf[LWS_PRE],
			      0, LWS_WRITE_PING);
		if (n < 0)
			goto bail_die;

		/*
		 * we apparently were able to send the PING in a reasonable time
		 * now reset the clock on our peer to be able to send the
		 * PONG in a reasonable time.
		 */

		lws_set_timeout(wsi, PENDING_TIMEOUT_WS_PONG_CHECK_GET_PONG,
				wsi->context->timeout_secs);

		goto bail_ok;
	}

	/* Priority 4: if we are closing, not allowed to send more data frags
	 *	       which means user callback or tx ext flush banned now
	 */
	if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
		goto user_service;

	/* Priority 5: Tx path extension with more to send
	 *
	 *	       These are handled as new fragments each time around
	 *	       So while we must block new writeable callback to enforce
	 *	       payload ordering, but since they are always complete
	 *	       fragments control packets can interleave OK.
	 */
	if (lwsi_role_ws_client(wsi) && wsi->ws->tx_draining_ext) {
		lwsl_ext("SERVICING TX EXT DRAINING\n");
		if (lws_write(wsi, NULL, 0, LWS_WRITE_CONTINUATION) < 0)
			goto bail_die;
		/* leave POLLOUT active */
		goto bail_ok;
	}

	/* Priority 6: extensions
	 */
#if !defined(LWS_WITHOUT_EXTENSIONS)
	m = lws_ext_cb_active(wsi, LWS_EXT_CB_IS_WRITEABLE, NULL, 0);
	if (m)
		goto bail_die;

	if (!wsi->extension_data_pending)
		goto user_service;

	/*
	 * check in on the active extensions, see if they
	 * had pending stuff to spill... they need to get the
	 * first look-in otherwise sequence will be disordered
	 *
	 * NULL, zero-length eff_buf means just spill pending
	 */

	ret = 1;
	if (lwsi_role_raw(wsi))
		ret = 0;

	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* give every extension a chance to spill */

		m = lws_ext_cb_active(wsi, LWS_EXT_CB_PACKET_TX_PRESEND,
				      &eff_buf, 0);
		if (m < 0) {
			lwsl_err("ext reports fatal error\n");
			goto bail_die;
		}
		if (m)
			/*
			 * at least one extension told us he has more
			 * to spill, so we will go around again after
			 */
			ret = 1;

		/* assuming they gave us something to send, send it */

		if (eff_buf.token_len) {
			n = lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
					  eff_buf.token_len);
			if (n < 0) {
				lwsl_info("closing from POLLOUT spill\n");
				goto bail_die;
			}
			/*
			 * Keep amount spilled small to minimize chance of this
			 */
			if (n != eff_buf.token_len) {
				lwsl_err("Unable to spill ext %d vs %d\n",
							  eff_buf.token_len, n);
				goto bail_die;
			}
		} else
			continue;

		/* no extension has more to spill */

		if (!ret)
			continue;

		/*
		 * There's more to spill from an extension, but we just sent
		 * something... did that leave the pipe choked?
		 */

		if (!lws_send_pipe_choked(wsi))
			/* no we could add more */
			continue;

		lwsl_info("choked in POLLOUT service\n");

		/*
		 * Yes, he's choked.  Leave the POLLOUT masked on so we will
		 * come back here when he is unchoked.  Don't call the user
		 * callback to enforce ordering of spilling, he'll get called
		 * when we come back here and there's nothing more to spill.
		 */

		goto bail_ok;
	}

	wsi->extension_data_pending = 0;
#endif

user_service:
	/* one shot */

	if (wsi->parent_carries_io) {
		vwsi->handling_pollout = 0;
		vwsi->leave_pollout_active = 0;

		return lws_calllback_as_writeable(wsi);
	}

	if (pollfd) {
		int eff = vwsi->leave_pollout_active;

		if (!eff)
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				lwsl_info("failed at set pollfd\n");
				goto bail_die;
			}

		vwsi->handling_pollout = 0;

		/* cannot get leave_pollout_active set after the above */
		if (!eff && wsi->leave_pollout_active) {
			/*
			 * got set inbetween sampling eff and clearing
			 * handling_pollout, force POLLOUT on
			 */
			lwsl_debug("leave_pollout_active\n");
			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
				lwsl_info("failed at set pollfd\n");
				goto bail_die;
			}
		}

		vwsi->leave_pollout_active = 0;
	}

	if (lwsi_role_client(wsi) && !wsi->hdr_parsing_completed &&
			lwsi_state(wsi) != LRS_H2_WAITING_TO_SEND_HEADERS)
		goto bail_ok;


#ifdef LWS_WITH_CGI
user_service_go_again:
#endif

#if defined(LWS_WITH_HTTP2)
	/* this is the network wsi */
	if (lwsi_role_h2(wsi)) {
		if (lws_handle_POLLOUT_event_h2(wsi) == -1)
			goto bail_die;

		goto bail_ok;
	}
#endif
	
	lwsl_info("%s: non http2\n", __func__);

	vwsi = (volatile struct lws *)wsi;
	vwsi->leave_pollout_active = 0;

	n = lws_calllback_as_writeable(wsi);
	vwsi->handling_pollout = 0;

	if (vwsi->leave_pollout_active)
		lws_change_pollfd(wsi, 0, LWS_POLLOUT);

	return n;

	/*
	 * since these don't disable the POLLOUT, they are always doing the
	 * right thing for leave_pollout_active whether it was set or not.
	 */

bail_ok:
	vwsi->handling_pollout = 0;
	vwsi->leave_pollout_active = 0;

	return 0;

bail_die:
	vwsi->handling_pollout = 0;
	vwsi->leave_pollout_active = 0;

	return -1;
}

static int
__lws_service_timeout_check(struct lws *wsi, time_t sec)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int n = 0;

	(void)n;

	/*
	 * if extensions want in on it (eg, we are a mux parent)
	 * give them a chance to service child timeouts
	 */
	if (lws_ext_cb_active(wsi, LWS_EXT_CB_1HZ, NULL, sec) < 0)
		return 0;

	/*
	 * if we went beyond the allowed time, kill the
	 * connection
	 */
	if (wsi->dll_timeout.prev &&
	    lws_compare_time_t(wsi->context, sec, wsi->pending_timeout_set) >
			       wsi->pending_timeout_limit) {

		if (wsi->desc.sockfd != LWS_SOCK_INVALID &&
		    wsi->position_in_fds_table >= 0)
			n = pt->fds[wsi->position_in_fds_table].events;

		lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_TIMEOUTS, 1);

		/* no need to log normal idle keepalive timeout */
		if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
			lwsl_info("wsi %p: TIMEDOUT WAITING on %d "
				  "(did hdr %d, ah %p, wl %d, pfd "
				  "events %d) %llu vs %llu\n",
				  (void *)wsi, wsi->pending_timeout,
				  wsi->hdr_parsing_completed, wsi->ah,
				  pt->ah_wait_list_length, n,
				  (unsigned long long)sec,
				  (unsigned long long)wsi->pending_timeout_limit);
#if defined(LWS_WITH_CGI)
		if (wsi->cgi)
			lwsl_notice("CGI timeout: %s\n", wsi->cgi->summary);
#endif

		/*
		 * Since he failed a timeout, he already had a chance to do
		 * something and was unable to... that includes situations like
		 * half closed connections.  So process this "failed timeout"
		 * close as a violent death and don't try to do protocol
		 * cleanup like flush partials.
		 */
		wsi->socket_is_permanently_unusable = 1;
		if (lwsi_state(wsi) == LRS_WAITING_SSL && wsi->protocol)
			wsi->protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
				wsi->user_space,
				(void *)"Timed out waiting SSL", 21);

		__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "timeout");

		return 1;
	}

	return 0;
}

int lws_rxflow_cache(struct lws *wsi, unsigned char *buf, int n, int len)
{
#if defined(LWS_WITH_HTTP2)
	if (wsi->upgraded_to_http2) {
		struct lws_h2_netconn *h2n = wsi->h2.h2n;

		assert(h2n->rx_scratch);
		buf += n;
		len -= n;
		assert ((char *)buf >= (char *)h2n->rx_scratch &&
			(char *)&buf[len] <=
			    (char *)&h2n->rx_scratch[wsi->vhost->h2_rx_scratch_size]);

		h2n->rx_scratch_pos = lws_ptr_diff(buf, h2n->rx_scratch);
		h2n->rx_scratch_len = len;

		lwsl_info("%s: %p: pausing h2 rx_scratch\n", __func__, wsi);

		return 0;
	}
#endif
	/* his RX is flowcontrolled, don't send remaining now */
	if (wsi->rxflow_buffer) {
		if (buf >= wsi->rxflow_buffer &&
		    &buf[len - 1] < &wsi->rxflow_buffer[wsi->rxflow_len]) {
			/* rxflow while we were spilling prev rxflow */
			lwsl_info("%s: staying in rxflow buf\n", __func__);
			return 1;
		} else {
			lwsl_err("%s: conflicting rxflow buf, "
				 "current %p len %d, new %p len %d\n", __func__,
				 wsi->rxflow_buffer, wsi->rxflow_len, buf, len);
			assert(0);
			return 1;
		}
	}

	/* a new rxflow, buffer it and warn caller */
	lwsl_info("%s: new rxflow input buffer len %d\n", __func__, len - n);
	wsi->rxflow_buffer = lws_malloc(len - n, "rxflow buf");
	if (!wsi->rxflow_buffer)
		return -1;

	wsi->rxflow_len = len - n;
	wsi->rxflow_pos = 0;
	memcpy(wsi->rxflow_buffer, buf + n, len - n);

	return 0;
}

/* this is used by the platform service code to stop us waiting for network
 * activity in poll() when we have something that already needs service
 */

LWS_VISIBLE LWS_EXTERN int
lws_service_adjust_timeout(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct allocated_headers *ah;

	/* Figure out if we really want to wait in poll()
	 * We only need to wait if really nothing already to do and we have
	 * to wait for something from network
	 */

	/* 1) if we know we are draining rx ext, do not wait in poll */
	if (pt->rx_draining_ext_list)
		return 0;

#ifdef LWS_OPENSSL_SUPPORT
	/* 2) if we know we have non-network pending data, do not wait in poll */
	if (lws_ssl_anybody_has_buffered_read_tsi(context, tsi)) {
		lwsl_info("ssl buffered read\n");
		return 0;
	}
#endif

	/* 3) if any ah has pending rx, do not wait in poll */
	ah = pt->ah_list;
	while (ah) {
		if (ah->rxpos != ah->rxlen || (ah->wsi && ah->wsi->preamble_rx)) {
			if (!ah->wsi) {
				assert(0);
			}
			// lwsl_debug("ah pending force\n");
			return 0;
		}
		ah = ah->next;
	}

	return timeout_ms;
}

/*
 * guys that need POLLIN service again without waiting for network action
 * can force POLLIN here if not flowcontrolled, so they will get service.
 *
 * Return nonzero if anybody got their POLLIN faked
 */
int
lws_service_flag_pending(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct allocated_headers *ah;
#ifdef LWS_OPENSSL_SUPPORT
	struct lws *wsi_next;
#endif
	struct lws *wsi;
	int forced = 0;

	lws_pt_lock(pt, __func__);

	/* POLLIN faking */

	/*
	 * 1) For all guys with already-available ext data to drain, if they are
	 * not flowcontrolled, fake their POLLIN status
	 */
	wsi = pt->rx_draining_ext_list;
	while (wsi) {
		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & LWS_POLLIN;
		if (pt->fds[wsi->position_in_fds_table].revents & LWS_POLLIN) {
			forced = 1;
			break;
		}
		wsi = wsi->ws->rx_draining_ext_list;
	}

#ifdef LWS_OPENSSL_SUPPORT
	/*
	 * 2) For all guys with buffered SSL read data already saved up, if they
	 * are not flowcontrolled, fake their POLLIN status so they'll get
	 * service to use up the buffered incoming data, even though their
	 * network socket may have nothing
	 */
	wsi = pt->pending_read_list;
	while (wsi) {
		wsi_next = wsi->pending_read_list_next;
		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & LWS_POLLIN;
		if (pt->fds[wsi->position_in_fds_table].revents & LWS_POLLIN) {
			forced = 1;
			/*
			 * he's going to get serviced now, take him off the
			 * list of guys with buffered SSL.  If he still has some
			 * at the end of the service, he'll get put back on the
			 * list then.
			 */
			__lws_ssl_remove_wsi_from_buffered_list(wsi);
		}

		wsi = wsi_next;
	}
#endif
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

	lws_pt_unlock(pt);

	return forced;
}

#ifndef LWS_NO_CLIENT

LWS_VISIBLE int
lws_http_client_read(struct lws *wsi, char **buf, int *len)
{
	int rlen, n;

	rlen = lws_ssl_capable_read(wsi, (unsigned char *)*buf, *len);
	*len = 0;

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

	if (wsi->http.rx_content_remain || !wsi->http.rx_content_length)
		return 0;

completed:

	if (lws_http_transaction_completed_client(wsi)) {
		lwsl_notice("%s: transaction completed says -1\n", __func__);
		return -1;
	}

	return 0;
}
#endif

static int
lws_is_ws_with_ext(struct lws *wsi)
{
#if defined(LWS_WITHOUT_EXTENSIONS)
	return 0;
#else
	return lwsi_role_ws(wsi) && !!wsi->count_act_ext;
#endif
}

static int
lws_service_periodic_checks(struct lws_context *context,
			    struct lws_pollfd *pollfd, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	lws_sockfd_type our_fd = 0, tmp_fd;
	struct allocated_headers *ah;
	struct lws *wsi;
	int timed_out = 0;
	time_t now;
	int n = 0, m;

	if (!context->protocol_init_done)
		if (lws_protocol_init(context))
			return -1;

	time(&now);

	/*
	 * handle case that system time was uninitialized when lws started
	 * at boot, and got initialized a little later
	 */
	if (context->time_up < 1464083026 && now > 1464083026)
		context->time_up = now;

	if (context->last_timeout_check_s &&
	    now - context->last_timeout_check_s > 100) {
		/*
		 * There has been a discontiguity.  Any stored time that is
		 * less than context->time_discontiguity should have context->
		 * time_fixup added to it.
		 *
		 * Some platforms with no RTC will experience this as a normal
		 * event when ntp sets their clock, but we can have started
		 * long before that with a 0-based unix time.
		 */

		context->time_discontiguity = now;
		context->time_fixup = now - context->last_timeout_check_s;

		lwsl_notice("time discontiguity: at old time %llus, "
			    "new time %llus: +%llus\n",
			    (unsigned long long)context->last_timeout_check_s,
			    (unsigned long long)context->time_discontiguity,
			    (unsigned long long)context->time_fixup);

		context->last_timeout_check_s = now - 1;
	}

	if (!lws_compare_time_t(context, context->last_timeout_check_s, now))
		return 0;

	context->last_timeout_check_s = now;

#if defined(LWS_WITH_STATS)
	if (!tsi && now - context->last_dump > 10) {
		lws_stats_log_dump(context);
		context->last_dump = now;
	}
#endif

	lws_plat_service_periodic(context);
	lws_check_deferred_free(context, 0);

#if defined(LWS_WITH_PEER_LIMITS)
	lws_peer_cull_peer_wait_list(context);
#endif

	/* retire unused deprecated context */
#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_ESP32)
#if LWS_POSIX && !defined(_WIN32)
	if (context->deprecated && !context->count_wsi_allocated) {
		lwsl_notice("%s: ending deprecated context\n", __func__);
		kill(getpid(), SIGINT);
		return 0;
	}
#endif
#endif
	/* global timeout check once per second */

	if (pollfd)
		our_fd = pollfd->fd;

	/*
	 * Phase 1: check every wsi on the timeout check list
	 */

	lws_pt_lock(pt, __func__);

	lws_start_foreach_dll_safe(struct lws_dll_lws *, d, d1,
				   context->pt[tsi].dll_head_timeout.next) {
		wsi = lws_container_of(d, struct lws, dll_timeout);
		tmp_fd = wsi->desc.sockfd;
		if (__lws_service_timeout_check(wsi, now)) {
			/* he did time out... */
			if (tmp_fd == our_fd)
				/* it was the guy we came to service! */
				timed_out = 1;
			/* he's gone, no need to mark as handled */
		}
	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * Phase 2: double-check active ah timeouts independent of wsi
	 *	    timeout status
	 */

	ah = pt->ah_list;
	while (ah) {
		int len;
		char buf[256];
		const unsigned char *c;

		if (!ah->in_use || !ah->wsi || !ah->assigned ||
		    (ah->wsi->vhost &&
		     lws_compare_time_t(context, now, ah->assigned) <
		     ah->wsi->vhost->timeout_secs_ah_idle + 360)) {
			ah = ah->next;
			continue;
		}

		/*
		 * a single ah session somehow got held for
		 * an unreasonable amount of time.
		 *
		 * Dump info on the connection...
		 */
		wsi = ah->wsi;
		buf[0] = '\0';
#if !defined(LWS_PLAT_OPTEE)
		lws_get_peer_simple(wsi, buf, sizeof(buf));
#else
		buf[0] = '\0';
#endif
		lwsl_notice("ah excessive hold: wsi %p\n"
			    "  peer address: %s\n"
			    "  ah rxpos %u, rxlen %u, pos %u\n",
			    wsi, buf, ah->rxpos, ah->rxlen,
			    ah->pos);
		buf[0] = '\0';
		m = 0;
		do {
			c = lws_token_to_string(m);
			if (!c)
				break;
			if (!(*c))
				break;

			len = lws_hdr_total_length(wsi, m);
			if (!len || len > (int)sizeof(buf) - 1) {
				m++;
				continue;
			}

			if (lws_hdr_copy(wsi, buf,
					 sizeof buf, m) > 0) {
				buf[sizeof(buf) - 1] = '\0';

				lwsl_notice("   %s = %s\n",
					    (const char *)c, buf);
			}
			m++;
		} while (1);

		/* explicitly detach the ah */

		lws_header_table_force_to_detachable_state(wsi);
		lws_header_table_detach(wsi, 0);

		/* ... and then drop the connection */

		m = 0;
		if (wsi->desc.sockfd == our_fd) {
			m = timed_out;

			/* it was the guy we came to service! */
			timed_out = 1;
		}

		if (!m) /* if he didn't already timeout */
			__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					     "excessive ah");

		ah = pt->ah_list;
	}

	lws_pt_unlock(pt);

#ifdef LWS_WITH_CGI
	/*
	 * Phase 3: handle cgi timeouts
	 */
	lws_cgi_kill_terminated(pt);
#endif
#if 0
	{
		char s[300], *p = s;

		for (n = 0; n < context->count_threads; n++)
			p += sprintf(p, " %7lu (%5d), ",
				     context->pt[n].count_conns,
				     context->pt[n].fds_count);

		lwsl_notice("load: %s\n", s);
	}
#endif
	/*
	 * Phase 4: vhost / protocol timer callbacks
	 */

	wsi = NULL;
	lws_start_foreach_ll(struct lws_vhost *, v, context->vhost_list) {
		struct lws_timed_vh_protocol *nx;
		if (v->timed_vh_protocol_list) {
			lws_start_foreach_ll(struct lws_timed_vh_protocol *,
					q, v->timed_vh_protocol_list) {
				if (now >= q->time) {
					if (!wsi)
						wsi = lws_zalloc(sizeof(*wsi), "cbwsi");
					wsi->context = context;
					wsi->vhost = v;
					wsi->protocol = q->protocol;
					lwsl_debug("timed cb: vh %s, protocol %s, reason %d\n", v->name, q->protocol->name, q->reason);
					q->protocol->callback(wsi, q->reason, NULL, NULL, 0);
					nx = q->next;
					lws_timed_callback_remove(v, q);
					q = nx;
					continue; /* we pointed ourselves to the next from the now-deleted guy */
				}
			} lws_end_foreach_ll(q, next);
		}
	} lws_end_foreach_ll(v, vhost_next);
	if (wsi)
		lws_free(wsi);

	/*
	 * Phase 5: check for unconfigured vhosts due to required
	 *	    interface missing before
	 */

	lws_context_lock(context);
	lws_start_foreach_llp(struct lws_vhost **, pv,
			      context->no_listener_vhost_list) {
		struct lws_vhost *v = *pv;
		lwsl_debug("deferred iface: checking if on vh %s\n", (*pv)->name);
		if (lws_context_init_server(NULL, *pv) == 0) {
			/* became happy */
			lwsl_notice("vh %s: became connected\n", v->name);
			*pv = v->no_listener_vhost_list;
			v->no_listener_vhost_list = NULL;
			break;
		}
	} lws_end_foreach_llp(pv, no_listener_vhost_list);
	lws_context_unlock(context);

	/*
	 * at intervals, check for ws connections needing ping-pong checks
	 */

	if (context->ws_ping_pong_interval &&
	    context->last_ws_ping_pong_check_s < now + 10) {
		struct lws_vhost *vh = context->vhost_list;
		context->last_ws_ping_pong_check_s = now;

		while (vh) {

			lws_vhost_lock(vh);

			for (n = 0; n < vh->count_protocols; n++) {
				wsi = vh->same_vh_protocol_list[n];

				while (wsi) {
					if (lwsi_role_ws(wsi) &&
					    !wsi->socket_is_permanently_unusable &&
					    !wsi->ws->send_check_ping &&
					    wsi->ws->time_next_ping_check &&
					    lws_compare_time_t(context, now,
						wsi->ws->time_next_ping_check) >
					       context->ws_ping_pong_interval) {

						lwsl_info("req pp on wsi %p\n",
							  wsi);
						wsi->ws->send_check_ping = 1;
						lws_set_timeout(wsi,
					PENDING_TIMEOUT_WS_PONG_CHECK_SEND_PING,
							context->timeout_secs);
						lws_callback_on_writable(wsi);
						wsi->ws->time_next_ping_check =
							now;
					}
					wsi = wsi->same_vh_protocol_next;
				}
			}

			lws_vhost_unlock(vh);
			vh = vh->vhost_next;
		}
	}

#ifdef LWS_OPENSSL_SUPPORT
	/*
	 * check the remaining cert lifetime daily
	 */
	n = lws_compare_time_t(context, now, context->last_cert_check_s);
	if ((!context->last_cert_check_s || n > (24 * 60 * 60)) &&
	    !lws_tls_check_all_cert_lifetimes(context))
		context->last_cert_check_s = now;
#endif

	return timed_out;
}

LWS_VISIBLE int
lws_service_fd_tsi(struct lws_context *context, struct lws_pollfd *pollfd,
		   int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_tokens eff_buf;
	unsigned int pending = 0;
	struct lws *wsi;
	char draining_flow = 0;
	int n = 0, m;

#if defined(LWS_WITH_HTTP2)
	struct lws *wsi1;
#endif

	/* the socket we came to service timed out, nothing to do */
	if (lws_service_periodic_checks(context, pollfd, tsi) || !pollfd)
		return 0;

	/* no, here to service a socket descriptor */
	wsi = wsi_from_fd(context, pollfd->fd);
	if (!wsi)
		/* not lws connection ... leave revents alone and return */
		return 0;

	/*
	 * so that caller can tell we handled, past here we need to
	 * zero down pollfd->revents after handling
	 */

#if LWS_POSIX
	/* handle session socket closed */

	if ((!(pollfd->revents & pollfd->events & LWS_POLLIN)) &&
	    (pollfd->revents & LWS_POLLHUP)) {
		wsi->socket_is_permanently_unusable = 1;
		lwsl_debug("Session Socket %p (fd=%d) dead\n",
						       (void *)wsi, pollfd->fd);

		goto close_and_handled;
	}

#ifdef _WIN32
	if (pollfd->revents & LWS_POLLOUT)
		wsi->sock_send_blocking = FALSE;
#endif

#endif

	if ((!(pollfd->revents & pollfd->events & LWS_POLLIN)) &&
	    (pollfd->revents & LWS_POLLHUP)) {
		lwsl_debug("pollhup\n");
		wsi->socket_is_permanently_unusable = 1;
		goto close_and_handled;
	}

#ifdef LWS_OPENSSL_SUPPORT
	if (lwsi_state(wsi) == LRS_SHUTDOWN && lws_is_ssl(wsi) && wsi->ssl) {
		n = 0;
		switch (__lws_tls_shutdown(wsi)) {
		case LWS_SSL_CAPABLE_DONE:
		case LWS_SSL_CAPABLE_ERROR:
			goto close_and_handled;

		case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
		case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			goto handled;
		}
	}
#endif
	wsi->could_have_pending = 0; /* clear back-to-back write detection */

	/* okay, what we came here to do... */

	switch (lwsi_role(wsi)) {
	case LWSI_ROLE_EVENT_PIPE:
	{
#if !defined(WIN32) && !defined(_WIN32)
		char s[10];

		/*
		 * discard the byte(s) that signaled us
		 * We really don't care about the number of bytes, but coverity
		 * thinks we should.
		 */
		n = read(wsi->desc.sockfd, s, sizeof(s));
		(void)n;
		if (n < 0)
			goto close_and_handled;
#endif
		/*
		 * the poll() wait, or the event loop for libuv etc is a
		 * process-wide resource that we interrupted.  So let every
		 * protocol that may be interested in the pipe event know that
		 * it happened.
		 */
		if (lws_broadcast(context, LWS_CALLBACK_EVENT_WAIT_CANCELLED,
				  NULL, 0)) {
			lwsl_info("closed in event cancel\n");
			goto close_and_handled;
		}

		goto handled;
	}

#ifdef LWS_WITH_CGI
	case LWSI_ROLE_CGI: /* we exist to handle a cgi's stdin/out/err data...
			 * do the callback on our master wsi
			 */
		{
			struct lws_cgi_args args;

			if (wsi->cgi_channel >= LWS_STDOUT &&
			    !(pollfd->revents & pollfd->events & LWS_POLLIN))
				break;
			if (wsi->cgi_channel == LWS_STDIN &&
			    !(pollfd->revents & pollfd->events & LWS_POLLOUT))
				break;

			if (wsi->cgi_channel == LWS_STDIN)
				if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
					lwsl_info("failed at set pollfd\n");
					return 1;
				}

			args.ch = wsi->cgi_channel;
			args.stdwsi = &wsi->parent->cgi->stdwsi[0];
			args.hdr_state = wsi->hdr_state;

			lwsl_debug("CGI LWS_STDOUT %p role 0x%x state 0x%x\n",
				   wsi->parent, lwsi_role(wsi->parent),
				   lwsi_state(wsi->parent));

			if (user_callback_handle_rxflow(
					wsi->parent->protocol->callback,
					wsi->parent, LWS_CALLBACK_CGI,
					wsi->parent->user_space,
					(void *)&args, 0))
				return 1;

			break;
		}
#endif

	case LWSI_ROLE_H1_SERVER:

#ifdef LWS_WITH_CGI
		if (wsi->cgi && (pollfd->revents & LWS_POLLOUT)) {
			n = lws_handle_POLLOUT_event(wsi, pollfd);
			if (n)
				goto close_and_handled;
			goto handled;
		}
#endif
		/* fallthru */

	case LWSI_ROLE_LISTEN_SOCKET:
	case LWSI_ROLE_RAW_SOCKET:
		n = lws_server_socket_service(context, wsi, pollfd);
		if (n) /* closed by above */
			return 1;

		goto handled;

	case LWSI_ROLE_RAW_FILE:

		if (pollfd->revents & LWS_POLLOUT) {
			n = lws_calllback_as_writeable(wsi);
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				lwsl_info("failed at set pollfd\n");
				return 1;
			}
			if (n)
				goto close_and_handled;
		}
		n = LWS_CALLBACK_RAW_RX;
		if (lwsi_role(wsi) == LWSI_ROLE_RAW_FILE)
			n = LWS_CALLBACK_RAW_RX_FILE;

		if (pollfd->revents & LWS_POLLIN) {
			if (user_callback_handle_rxflow(
					wsi->protocol->callback,
					wsi, n, wsi->user_space, NULL, 0)) {
				lwsl_debug("raw rx callback closed it\n");
				goto close_and_handled;
			}
		}

		if (pollfd->revents & LWS_POLLHUP)
			goto close_and_handled;
		n = 0;
		goto handled;

	case LWSI_ROLE_H1_CLIENT:

		if (lwsi_state(wsi) == LRS_ESTABLISHED)
			goto handled;

do_client:
#if !defined(LWS_NO_CLIENT)
		if ((pollfd->revents & LWS_POLLOUT) &&
		    lws_handle_POLLOUT_event(wsi, pollfd)) {
			lwsl_debug("POLLOUT event closed it\n");
			goto close_and_handled;
		}

		n = lws_client_socket_service(wsi, pollfd, NULL);
		if (n)
			return 1;
#endif
		goto handled;

	case LWSI_ROLE_WS1_SERVER:
	case LWSI_ROLE_WS1_CLIENT:
	case LWSI_ROLE_H2_SERVER:
	case LWSI_ROLE_WS2_SERVER:
	case LWSI_ROLE_H2_CLIENT:
	case LWSI_ROLE_WS2_CLIENT:

		 lwsl_info("%s: wsistate 0x%x, pollout %d\n", __func__,
			   wsi->wsistate, pollfd->revents & LWS_POLLOUT);

		/*
		 * something went wrong with parsing the handshake, and
		 * we ended up back in the event loop without completing it
		 */
		if (lwsi_state(wsi) == LRS_PRE_WS_SERVING_ACCEPT) {
			wsi->socket_is_permanently_unusable = 1;
			goto close_and_handled;
		}

		if (lwsi_state(wsi) == LRS_WAITING_CONNECT)
			goto do_client;

		/* 1: something requested a callback when it was OK to write */

		if ((pollfd->revents & LWS_POLLOUT) &&
		    lwsi_state_can_handle_POLLOUT(wsi) &&
		    lws_handle_POLLOUT_event(wsi, pollfd)) {
			if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
				lwsi_set_state(wsi, LRS_FLUSHING_BEFORE_CLOSE);
			/* the write failed... it's had it */
			wsi->socket_is_permanently_unusable = 1;
			goto close_and_handled;
		}

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

		if (wsi->ws && wsi->ws->tx_draining_ext)
			/*
			 * We cannot deal with new RX until the TX ext path has
			 * been drained.  It's because new rx will, eg, crap on
			 * the wsi rx buf that may be needed to retain state.
			 *
			 * TX ext drain path MUST go through event loop to avoid
			 * blocking.
			 */
			break;

		if (lws_is_flowcontrolled(wsi))
			/* We cannot deal with any kind of new RX because we are
			 * RX-flowcontrolled.
			 */
			break;

#if defined(LWS_WITH_HTTP2)
		if (wsi->http2_substream || wsi->upgraded_to_http2) {
			wsi1 = lws_get_network_wsi(wsi);
			if (wsi1 && wsi1->trunc_len)
				/* We cannot deal with any kind of new RX
				 * because we are dealing with a partial send
				 * (new RX may trigger new http_action() that
				 * expect to be able to send)
				 */
				break;
		}
#endif

		/* 2: RX Extension needs to be drained
		 */

		if (lwsi_role_ws(wsi) && wsi->ws && wsi->ws->rx_draining_ext) {

			lwsl_ext("%s: RX EXT DRAINING: Service\n", __func__);
#ifndef LWS_NO_CLIENT
			if (lwsi_role_ws_client(wsi)) {
				n = lws_client_rx_sm(wsi, 0);
				if (n < 0)
					/* we closed wsi */
					n = 0;
			} else
#endif
				n = lws_rx_sm(wsi, 0);

			goto handled;
		}

		if (wsi->ws && wsi->ws->rx_draining_ext)
			/*
			 * We have RX EXT content to drain, but can't do it
			 * right now.  That means we cannot do anything lower
			 * priority either.
			 */
			break;

		/* 3: RX Flowcontrol buffer / h2 rx scratch needs to be drained
		 */

		if (wsi->rxflow_buffer) {
			lwsl_info("draining rxflow (len %d)\n",
				wsi->rxflow_len - wsi->rxflow_pos);
			assert(wsi->rxflow_pos < wsi->rxflow_len);
			/* well, drain it */
			eff_buf.token = (char *)wsi->rxflow_buffer +
						wsi->rxflow_pos;
			eff_buf.token_len = wsi->rxflow_len - wsi->rxflow_pos;
			draining_flow = 1;
			goto drain;
		}

#if defined(LWS_WITH_HTTP2)
		if (wsi->upgraded_to_http2) {
			struct lws_h2_netconn *h2n = wsi->h2.h2n;

			if (h2n->rx_scratch_len) {
				lwsl_info("%s: %p: h2 rx pos = %d len = %d\n",
					  __func__, wsi, h2n->rx_scratch_pos,
					  h2n->rx_scratch_len);
				eff_buf.token = (char *)h2n->rx_scratch +
						h2n->rx_scratch_pos;
				eff_buf.token_len = h2n->rx_scratch_len;

				h2n->rx_scratch_len = 0;
				goto drain;
			}
		}
#endif

		/* 4: any incoming (or ah-stashed incoming rx) data ready?
		 * notice if rx flow going off raced poll(), rx flow wins
		 */

		if (!(pollfd->revents & pollfd->events & LWS_POLLIN))
			break;

read:
		if (lws_is_flowcontrolled(wsi)) {
			lwsl_info("%s: %p should be rxflow (bm 0x%x)..\n",
				    __func__, wsi, wsi->rxflow_bitmap);
			break;
		}

		if (wsi->ah && wsi->ah->rxlen - wsi->ah->rxpos) {
			lwsl_info("%s: %p: inherited ah rx %d\n", __func__,
					wsi, wsi->ah->rxlen - wsi->ah->rxpos);
			eff_buf.token_len = wsi->ah->rxlen -
					    wsi->ah->rxpos;
			eff_buf.token = (char *)wsi->ah->rx +
					wsi->ah->rxpos;
		} else {
			if (!(lwsi_role_client(wsi) &&
			      (lwsi_state(wsi) != LRS_ESTABLISHED &&
			       lwsi_state(wsi) != LRS_H2_WAITING_TO_SEND_HEADERS))) {
				/*
				 * extension may not consume everything
				 * (eg, pmd may be constrained
				 * as to what it can output...) has to go in
				 * per-wsi rx buf area.
				 * Otherwise in large temp serv_buf area.
				 */

#if defined(LWS_WITH_HTTP2)
				if (wsi->upgraded_to_http2) {
					if (!wsi->h2.h2n->rx_scratch) {
						wsi->h2.h2n->rx_scratch =
							lws_malloc(
							wsi->vhost->h2_rx_scratch_size,
							 "h2 rx scratch");
						if (!wsi->h2.h2n->rx_scratch)
							goto close_and_handled;
					}
					eff_buf.token = wsi->h2.h2n->rx_scratch;
					eff_buf.token_len = wsi->vhost->h2_rx_scratch_size;
				} else
#endif
				{
					eff_buf.token = (char *)pt->serv_buf;
					if (lws_is_ws_with_ext(wsi)) {
						eff_buf.token_len =
							wsi->ws->rx_ubuf_alloc;
					} else {
						eff_buf.token_len =
						      context->pt_serv_buf_size;
					}

					if ((unsigned int)eff_buf.token_len >
						     context->pt_serv_buf_size)
						eff_buf.token_len =
						      context->pt_serv_buf_size;
				}

				if ((int)pending > eff_buf.token_len)
					pending = eff_buf.token_len;

				eff_buf.token_len = lws_ssl_capable_read(wsi,
					(unsigned char *)eff_buf.token,
					pending ? (int)pending :
					eff_buf.token_len);
				switch (eff_buf.token_len) {
				case 0:
					lwsl_info("%s: zero length read\n",
						  __func__);
					goto close_and_handled;
				case LWS_SSL_CAPABLE_MORE_SERVICE:
					lwsl_info("SSL Capable more service\n");
					n = 0;
					goto handled;
				case LWS_SSL_CAPABLE_ERROR:
					lwsl_info("%s: LWS_SSL_CAPABLE_ERROR\n",
							__func__);
					goto close_and_handled;
				}
				// lwsl_notice("Actual RX %d\n", eff_buf.token_len);
			}
		}

drain:
#ifndef LWS_NO_CLIENT
		if (lwsi_role_http_client(wsi) && wsi->hdr_parsing_completed &&
		    !wsi->told_user_closed) {

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

			/* let user code know, he'll usually ask for writeable
			 * callback and drain / re-enable it there
			 */
			if (user_callback_handle_rxflow(
					wsi->protocol->callback,
					wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP,
					wsi->user_space, NULL, 0)) {
				lwsl_info("RECEIVE_CLIENT_HTTP closed it\n");
				goto close_and_handled;
			}

			n = 0;
			goto handled;
		}
#endif
		/*
		 * give any active extensions a chance to munge the buffer
		 * before parse.  We pass in a pointer to an lws_tokens struct
		 * prepared with the default buffer and content length that's in
		 * there.  Rather than rewrite the default buffer, extensions
		 * that expect to grow the buffer can adapt .token to
		 * point to their own per-connection buffer in the extension
		 * user allocation.  By default with no extensions or no
		 * extension callback handling, just the normal input buffer is
		 * used then so it is efficient.
		 */
		m = 0;
		do {
#if !defined(LWS_WITHOUT_EXTENSIONS)
			m = lws_ext_cb_active(wsi, LWS_EXT_CB_PACKET_RX_PREPARSE,
					      &eff_buf, 0);
			if (m < 0)
				goto close_and_handled;
#endif

			/* service incoming data */

			if (eff_buf.token_len) {
				/*
				 * if draining from rxflow buffer, not
				 * critical to track what was used since at the
				 * use it bumps wsi->rxflow_pos.  If we come
				 * around again it will pick up from where it
				 * left off.
				 */

				if (lwsi_role_h2(wsi) && lwsi_state(wsi) != LRS_BODY)
					n = lws_read_h2(wsi, (unsigned char *)eff_buf.token,
						     eff_buf.token_len);
				else
					n = lws_read_h1(wsi, (unsigned char *)eff_buf.token,
						     eff_buf.token_len);

				if (n < 0) {
					/* we closed wsi */
					n = 0;
					goto handled;
				}
			}

			eff_buf.token = NULL;
			eff_buf.token_len = 0;
		} while (m);

		if (wsi->ah
#if !defined(LWS_NO_CLIENT)
				&& !wsi->client_h2_alpn
#endif
				) {
			lwsl_info("%s: %p: detaching ah\n", __func__, wsi);
			lws_header_table_force_to_detachable_state(wsi);
			lws_header_table_detach(wsi, 0);
		}

		pending = lws_ssl_pending(wsi);
		if (pending) {
			if (lws_is_ws_with_ext(wsi))
				pending = pending > wsi->ws->rx_ubuf_alloc ?
					wsi->ws->rx_ubuf_alloc : pending;
			else
				pending = pending > context->pt_serv_buf_size ?
					context->pt_serv_buf_size : pending;
			goto read;
		}

		if (draining_flow && wsi->rxflow_buffer &&
		    wsi->rxflow_pos == wsi->rxflow_len) {
			lwsl_info("%s: %p flow buf: drained\n", __func__, wsi);
			lws_free_set_NULL(wsi->rxflow_buffer);
			/* having drained the rxflow buffer, can rearm POLLIN */
#ifdef LWS_NO_SERVER
			n =
#endif
			__lws_rx_flow_control(wsi);
			/* n ignored, needed for NO_SERVER case */
		}

		break;

	}

	n = 0;
	goto handled;

close_and_handled:
	lwsl_debug("%p: Close and handled\n", wsi);
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "close_and_handled");
	/*
	 * pollfd may point to something else after the close
	 * due to pollfd swapping scheme on delete on some platforms
	 * we can't clear revents now because it'd be the wrong guy's revents
	 */
	return 1;

handled:
	pollfd->revents = 0;

	return n;
}

LWS_VISIBLE int
lws_service_fd(struct lws_context *context, struct lws_pollfd *pollfd)
{
	return lws_service_fd_tsi(context, pollfd, 0);
}

LWS_VISIBLE int
lws_service(struct lws_context *context, int timeout_ms)
{
	return lws_plat_service(context, timeout_ms);
}

LWS_VISIBLE int
lws_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	return _lws_plat_service_tsi(context, timeout_ms, tsi);
}

