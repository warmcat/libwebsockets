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
wops_handle_POLLIN_ws(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_pollfd *pollfd)
{
	struct lws_tokens eff_buf;
	unsigned int pending = 0;
	char draining_flow = 0;
	int n = 0, m;
#if defined(LWS_WITH_HTTP2)
	struct lws *wsi1;
#endif

	// lwsl_notice("%s: %s\n", __func__, wsi->protocol->name);

	lwsl_info("%s: wsistate 0x%x, pollout %d\n", __func__,
		   wsi->wsistate, pollfd->revents & LWS_POLLOUT);

	/*
	 * something went wrong with parsing the handshake, and
	 * we ended up back in the event loop without completing it
	 */
	if (lwsi_state(wsi) == LRS_PRE_WS_SERVING_ACCEPT) {
		wsi->socket_is_permanently_unusable = 1;
		return LWS_HPI_RET_CLOSE_HANDLED;
	}

	if (lwsi_state(wsi) == LRS_WAITING_CONNECT) {
#if !defined(LWS_NO_CLIENT)
		if ((pollfd->revents & LWS_POLLOUT) &&
		    lws_handle_POLLOUT_event(wsi, pollfd)) {
			lwsl_debug("POLLOUT event closed it\n");
			return LWS_HPI_RET_CLOSE_HANDLED;
		}

		n = lws_client_socket_service(wsi, pollfd, NULL);
		if (n)
			return LWS_HPI_RET_DIE;
#endif
		return LWS_HPI_RET_HANDLED;
	}

	/* 1: something requested a callback when it was OK to write */

	if ((pollfd->revents & LWS_POLLOUT) &&
	    lwsi_state_can_handle_POLLOUT(wsi) &&
	    lws_handle_POLLOUT_event(wsi, pollfd)) {
		if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
			lwsi_set_state(wsi, LRS_FLUSHING_BEFORE_CLOSE);
		/* the write failed... it's had it */
		wsi->socket_is_permanently_unusable = 1;
		return LWS_HPI_RET_CLOSE_HANDLED;
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
		return LWS_HPI_RET_HANDLED;

	if (lws_is_flowcontrolled(wsi))
		/* We cannot deal with any kind of new RX because we are
		 * RX-flowcontrolled.
		 */
		return LWS_HPI_RET_HANDLED;

#if defined(LWS_WITH_HTTP2)
	if (wsi->http2_substream || wsi->upgraded_to_http2) {
		wsi1 = lws_get_network_wsi(wsi);
		if (wsi1 && wsi1->trunc_len)
			/* We cannot deal with any kind of new RX
			 * because we are dealing with a partial send
			 * (new RX may trigger new http_action() that
			 * expect to be able to send)
			 */
			return LWS_HPI_RET_HANDLED;
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

		return LWS_HPI_RET_HANDLED;
	}

	if (wsi->ws && wsi->ws->rx_draining_ext)
		/*
		 * We have RX EXT content to drain, but can't do it
		 * right now.  That means we cannot do anything lower
		 * priority either.
		 */
		return LWS_HPI_RET_HANDLED;

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

	if (!(pollfd->revents & pollfd->events & LWS_POLLIN) && !wsi->ah)
		return LWS_HPI_RET_HANDLED;

read:
	if (lws_is_flowcontrolled(wsi)) {
		lwsl_info("%s: %p should be rxflow (bm 0x%x)..\n",
			    __func__, wsi, wsi->rxflow_bitmap);
		return LWS_HPI_RET_HANDLED;
	}

	if (wsi->ah && wsi->ah->rxlen == wsi->ah->rxpos) {
		/* we drained the excess data in the ah */
		lwsl_info("%s: %p: dropping ah on ws post-upgrade\n", __func__, wsi);
		lws_header_table_force_to_detachable_state(wsi);
		lws_header_table_detach(wsi, 0);
	} else
		if (wsi->ah)
			lwsl_info("%s: %p: unable to drop yet %d vs %d\n",
				    __func__, wsi, wsi->ah->rxpos, wsi->ah->rxlen);

	if (wsi->ah && wsi->ah->rxlen - wsi->ah->rxpos) {
		lwsl_info("%s: %p: inherited ah rx %d\n", __func__,
				wsi, wsi->ah->rxlen - wsi->ah->rxpos);
		eff_buf.token_len = wsi->ah->rxlen - wsi->ah->rxpos;
		eff_buf.token = (char *)wsi->ah->rx + wsi->ah->rxpos;
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
						return LWS_HPI_RET_CLOSE_HANDLED;
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
					      wsi->context->pt_serv_buf_size;
				}

				if ((unsigned int)eff_buf.token_len >
		 	 	 	 	 wsi->context->pt_serv_buf_size)
					eff_buf.token_len =
						wsi->context->pt_serv_buf_size;
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
				return LWS_HPI_RET_CLOSE_HANDLED;
			case LWS_SSL_CAPABLE_MORE_SERVICE:
				lwsl_info("SSL Capable more service\n");
				return LWS_HPI_RET_HANDLED;
			case LWS_SSL_CAPABLE_ERROR:
				lwsl_info("%s: LWS_SSL_CAPABLE_ERROR\n",
						__func__);
				return LWS_HPI_RET_CLOSE_HANDLED;
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
			return LWS_HPI_RET_CLOSE_HANDLED;
		}

		return LWS_HPI_RET_HANDLED;
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
			return LWS_HPI_RET_CLOSE_HANDLED;
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
				return LWS_HPI_RET_HANDLED;
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
			pending = pending > wsi->context->pt_serv_buf_size ?
				wsi->context->pt_serv_buf_size : pending;
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

	/* n = 0 */
	return LWS_HPI_RET_HANDLED;
}


int wops_handle_POLLOUT_ws(struct lws *wsi)
{
	int write_type = LWS_WRITE_PONG;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_tokens eff_buf;
	int ret, m;
#endif
	int n;

	// lwsl_notice("%s: %s\n", __func__, wsi->protocol->name);

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

			return LWS_HP_RET_BAIL_OK;
		}

		return LWS_HP_RET_BAIL_DIE;
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
			return LWS_HP_RET_BAIL_DIE;

		/* well he is sent, mark him done */
		wsi->ws->ping_pending_flag = 0;
		if (wsi->ws->payload_is_close) {
			// assert(0);
			/* oh... a close frame was it... then we are done */
			return LWS_HP_RET_BAIL_DIE;
		}

		/* otherwise for PING, leave POLLOUT active either way */
		return LWS_HP_RET_BAIL_OK;
	}

	if (lwsi_role_ws_client(wsi) && !wsi->socket_is_permanently_unusable &&
	    wsi->ws->send_check_ping) {

		lwsl_info("issuing ping on wsi %p\n", wsi);
		wsi->ws->send_check_ping = 0;
		n = lws_write(wsi, &wsi->ws->ping_payload_buf[LWS_PRE],
			      0, LWS_WRITE_PING);
		if (n < 0)
			return LWS_HP_RET_BAIL_DIE;

		/*
		 * we apparently were able to send the PING in a reasonable time
		 * now reset the clock on our peer to be able to send the
		 * PONG in a reasonable time.
		 */

		lws_set_timeout(wsi, PENDING_TIMEOUT_WS_PONG_CHECK_GET_PONG,
				wsi->context->timeout_secs);

		return LWS_HP_RET_BAIL_OK;
	}

	/* Priority 4: if we are closing, not allowed to send more data frags
	 *	       which means user callback or tx ext flush banned now
	 */
	if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
		return LWS_HP_RET_USER_SERVICE;

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
			return LWS_HP_RET_BAIL_DIE;
		/* leave POLLOUT active */
		return LWS_HP_RET_BAIL_OK;
	}

	/* Priority 6: extensions
	 */
#if !defined(LWS_WITHOUT_EXTENSIONS)
	m = lws_ext_cb_active(wsi, LWS_EXT_CB_IS_WRITEABLE, NULL, 0);
	if (m)
		return LWS_HP_RET_BAIL_DIE;

	if (!wsi->extension_data_pending)
		return LWS_HP_RET_USER_SERVICE;

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
			return LWS_HP_RET_BAIL_DIE;
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
				return LWS_HP_RET_BAIL_DIE;
			}
			/*
			 * Keep amount spilled small to minimize chance of this
			 */
			if (n != eff_buf.token_len) {
				lwsl_err("Unable to spill ext %d vs %d\n",
							  eff_buf.token_len, n);
				return LWS_HP_RET_BAIL_DIE;
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

		return LWS_HP_RET_BAIL_OK;
	}

	wsi->extension_data_pending = 0;
#endif

	return LWS_HP_RET_USER_SERVICE;
}

static int
wops_periodic_checks_ws(struct lws_context *context, int tsi, time_t now)
{
	struct lws_vhost *vh;

	if (!context->ws_ping_pong_interval ||
	    context->last_ws_ping_pong_check_s >= now + 10)
		return 0;

	vh = context->vhost_list;
	context->last_ws_ping_pong_check_s = now;

	while (vh) {
		int n;

		lws_vhost_lock(vh);

		for (n = 0; n < vh->count_protocols; n++) {
			struct lws *wsi = vh->same_vh_protocol_list[n];

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

	return 0;
}

struct lws_protocol_ops wire_ops_ws = {
	"ws",
	wops_handle_POLLIN_ws,
	wops_handle_POLLOUT_ws,
	wops_periodic_checks_ws
};
