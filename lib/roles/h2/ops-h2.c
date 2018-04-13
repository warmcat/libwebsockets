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

/*
 * These are the standardized defaults.
 * Override what actually goes in the vhost settings in platform or user code.
 * Leave these alone because they are used to determine "what is different
 * from the protocol defaults".
 */
const struct http2_settings lws_h2_defaults = { {
	1,
	/* H2SET_HEADER_TABLE_SIZE */			4096,
	/* *** This controls how many entries in the dynamic table ***
	 * Allows the sender to inform the remote endpoint of the maximum
	 * size of the header compression table used to decode header
	 * blocks, in octets.  The encoder can select any size equal to or
	 * less than this value by using signaling specific to the header
	 * compression format inside a header block (see [COMPRESSION]).
	 * The initial value is 4,096 octets.
	 */
	/* H2SET_ENABLE_PUSH */				   1,
	/* H2SET_MAX_CONCURRENT_STREAMS */	  0x7fffffff,
	/* H2SET_INITIAL_WINDOW_SIZE */		       65535,
	/* H2SET_MAX_FRAME_SIZE */		       16384,
	/* H2SET_MAX_HEADER_LIST_SIZE */	  0x7fffffff,
	/*< This advisory setting informs a peer of the maximum size of
	 * header list that the sender is prepared to accept, in octets.
	 * The value is based on the uncompressed size of header fields,
	 * including the length of the name and value in octets plus an
	 * overhead of 32 octets for each header field.
	 */
	/* H2SET_RESERVED7 */				   0,
	/* H2SET_ENABLE_CONNECT_PROTOCOL */		   0,
}};

/* these are the "lws defaults"... they can be overridden in plat */

const struct http2_settings lws_h2_stock_settings = { {
	1,
	/* H2SET_HEADER_TABLE_SIZE */			65536, /* ffox */
	/* *** This controls how many entries in the dynamic table ***
	 * Allows the sender to inform the remote endpoint of the maximum
	 * size of the header compression table used to decode header
	 * blocks, in octets.  The encoder can select any size equal to or
	 * less than this value by using signaling specific to the header
	 * compression format inside a header block (see [COMPRESSION]).
	 * The initial value is 4,096 octets.
	 *
	 * Can't pass h2spec with less than 4096 here...
	 */
	/* H2SET_ENABLE_PUSH */				   1,
	/* H2SET_MAX_CONCURRENT_STREAMS */		  24,
	/* H2SET_INITIAL_WINDOW_SIZE */		       65535,
	/* H2SET_MAX_FRAME_SIZE */		       16384,
	/* H2SET_MAX_HEADER_LIST_SIZE */	        4096,
	/*< This advisory setting informs a peer of the maximum size of
	 * header list that the sender is prepared to accept, in octets.
	 * The value is based on the uncompressed size of header fields,
	 * including the length of the name and value in octets plus an
	 * overhead of 32 octets for each header field.
	 */
	/* H2SET_RESERVED7 */				   0,
	/* H2SET_ENABLE_CONNECT_PROTOCOL */		   1,
}};

static int
rops_handle_POLLIN_h2(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_pollfd *pollfd)
{
	struct lws_tokens eff_buf;
	unsigned int pending = 0;
	char draining_flow = 0;
	struct lws *wsi1;
	int n;

#ifdef LWS_WITH_CGI
	if (wsi->cgi && (pollfd->revents & LWS_POLLOUT)) {
		if (lws_handle_POLLOUT_event(wsi, pollfd))
			return LWS_HPI_RET_CLOSE_HANDLED;

		return LWS_HPI_RET_HANDLED;
	}
#endif

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

	if (lws_is_flowcontrolled(wsi))
		/* We cannot deal with any kind of new RX because we are
		 * RX-flowcontrolled.
		 */
		return LWS_HPI_RET_HANDLED;

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

	/* 3: RX Flowcontrol buffer / h2 rx scratch needs to be drained
	 */

	eff_buf.token_len = lws_buflist_next_segment_len(&wsi->buflist_rxflow,
						(uint8_t **)&eff_buf.token);
	if (eff_buf.token_len) {
		lwsl_info("draining rxflow (len %d)\n", eff_buf.token_len);
		draining_flow = 1;
		goto drain;
	}

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

	/* 4: any incoming (or ah-stashed incoming rx) data ready?
	 * notice if rx flow going off raced poll(), rx flow wins
	 */

	if (!(pollfd->revents & pollfd->events & LWS_POLLIN))
		return LWS_HPI_RET_HANDLED;

read:
	if (lws_is_flowcontrolled(wsi)) {
		lwsl_info("%s: %p should be rxflow (bm 0x%x)..\n",
			    __func__, wsi, wsi->rxflow_bitmap);
		return LWS_HPI_RET_HANDLED;
	}

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
			} else {
				eff_buf.token = (char *)pt->serv_buf;
				eff_buf.token_len =
					     wsi->context->pt_serv_buf_size;

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
	if (lwsi_role_http(wsi) && lwsi_role_client(wsi) &&
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
			return LWS_HPI_RET_DIE;
		}
	}

	eff_buf.token = NULL;
	eff_buf.token_len = 0;

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
		pending = pending > wsi->context->pt_serv_buf_size ?
				wsi->context->pt_serv_buf_size : pending;
		goto read;
	}

	if (draining_flow && /* were draining, now nothing left */
	    !lws_buflist_next_segment_len(&wsi->buflist_rxflow, NULL)) {
		lwsl_info("%s: %p flow buf: drained\n", __func__, wsi);
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

int rops_handle_POLLOUT_h2(struct lws *wsi)
{
	// lwsl_notice("%s\n", __func__);

	if (lwsi_state(wsi) == LRS_ISSUE_HTTP_BODY)
		return LWS_HP_RET_USER_SERVICE;

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
			return LWS_HP_RET_BAIL_DIE;
		}
		if (wsi->h2.h2n->pps)
			return LWS_HP_RET_BAIL_OK;

		/* we can resume whatever we were doing */
		lws_rx_flow_control(wsi, LWS_RXFLOW_REASON_APPLIES_ENABLE |
					 LWS_RXFLOW_REASON_H2_PPS_PENDING);

		return LWS_HP_RET_BAIL_OK; /* leave POLLOUT active */
	}

	/* Priority 4: if we are closing, not allowed to send more data frags
	 *	       which means user callback or tx ext flush banned now
	 */
	if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
		return LWS_HP_RET_USER_SERVICE;

	return LWS_HP_RET_USER_SERVICE;
}

static int
rops_service_flag_pending_h2(struct lws_context *context, int tsi)
{
	/* h1 will deal with this if both h1 and h2 enabled */

#if !defined(LWS_ROLE_H1)
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
#else
	return 0;
#endif
}

static int
rops_write_role_protocol_h2(struct lws *wsi, unsigned char *buf, size_t len,
			    enum lws_write_protocol *wp)
{
	unsigned char flags = 0;
	int n;

	/* if not in a state to send stuff, then just send nothing */

	if (!lwsi_role_ws(wsi) &&
	    ((*wp) & 0x1f) != LWS_WRITE_HTTP &&
	    ((*wp) & 0x1f) != LWS_WRITE_HTTP_FINAL &&
	    ((*wp) & 0x1f) != LWS_WRITE_HTTP_HEADERS_CONTINUATION &&
	    ((*wp) & 0x1f) != LWS_WRITE_HTTP_HEADERS &&
	    ((lwsi_state(wsi) != LRS_RETURNED_CLOSE &&
	      lwsi_state(wsi) != LRS_WAITING_TO_SEND_CLOSE &&
	      lwsi_state(wsi) != LRS_AWAITING_CLOSE_ACK) ||
	     ((*wp) & 0x1f) != LWS_WRITE_CLOSE)) {
		//assert(0);
		lwsl_notice("binning wsistate 0x%x %d\n", wsi->wsistate, *wp);
		return 0;
	}

	/*
	 * ws-over-h2 also ends up here after the ws framing applied
	 */

	n = LWS_H2_FRAME_TYPE_DATA;
	if ((*wp & 0x1f) == LWS_WRITE_HTTP_HEADERS) {
		n = LWS_H2_FRAME_TYPE_HEADERS;
		if (!((*wp) & LWS_WRITE_NO_FIN))
			flags = LWS_H2_FLAG_END_HEADERS;
		if (wsi->h2.send_END_STREAM ||
		    ((*wp) & LWS_WRITE_H2_STREAM_END)) {
			flags |= LWS_H2_FLAG_END_STREAM;
			wsi->h2.send_END_STREAM = 1;
		}
	}

	if ((*wp & 0x1f) == LWS_WRITE_HTTP_HEADERS_CONTINUATION) {
		n = LWS_H2_FRAME_TYPE_CONTINUATION;
		if (!((*wp) & LWS_WRITE_NO_FIN))
			flags = LWS_H2_FLAG_END_HEADERS;
		if (wsi->h2.send_END_STREAM ||
		    ((*wp) & LWS_WRITE_H2_STREAM_END)) {
			flags |= LWS_H2_FLAG_END_STREAM;
			wsi->h2.send_END_STREAM = 1;
		}
	}

	if (((*wp & 0x1f) == LWS_WRITE_HTTP ||
	     (*wp & 0x1f) == LWS_WRITE_HTTP_FINAL) &&
	    wsi->http.tx_content_length) {
		wsi->http.tx_content_remain -= len;
		lwsl_info("%s: wsi %p: tx_content_remain = %llu\n",
			  __func__, wsi,
			  (unsigned long long)wsi->http.tx_content_remain);
		if (!wsi->http.tx_content_remain) {
			lwsl_info("%s: selecting final write mode\n",
				  __func__);
			*wp = LWS_WRITE_HTTP_FINAL;
		}
	}

	if ((*wp & 0x1f) == LWS_WRITE_HTTP_FINAL ||
	    ((*wp) & LWS_WRITE_H2_STREAM_END)) {
	    //lws_get_network_wsi(wsi)->h2.END_STREAM) {
		lwsl_info("%s: setting END_STREAM\n", __func__);
		flags |= LWS_H2_FLAG_END_STREAM;
		wsi->h2.send_END_STREAM = 1;
	}

	return lws_h2_frame_write(wsi, n, flags, wsi->h2.my_sid,
				  (int)len, buf);
}

static int
rops_check_upgrades_h2(struct lws *wsi)
{
#if defined(LWS_ROLE_WS)
	struct lws *nwsi;
	char *p;

	/*
	 * with H2 there's also a way to upgrade a stream to something
	 * else... :method is CONNECT and :protocol says the name of
	 * the new protocol we want to carry.  We have to have sent a
	 * SETTINGS saying that we support it though.
	 */
	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD);
	if (!wsi->vhost->set.s[H2SET_ENABLE_CONNECT_PROTOCOL] ||
	    !wsi->http2_substream || !p || strcmp(p, "CONNECT"))
		return LWS_UPG_RET_CONTINUE;

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_COLON_PROTOCOL);
	if (!p || strcmp(p, "websocket"))
		return LWS_UPG_RET_CONTINUE;

	nwsi = lws_get_network_wsi(wsi);

	wsi->vhost->conn_stats.ws_upg++;
	lwsl_info("Upgrade h2 to ws\n");
	wsi->h2_stream_carries_ws = 1;
	nwsi->ws_over_h2_count++;
	if (lws_process_ws_upgrade(wsi))
		return LWS_UPG_RET_BAIL;

	if (nwsi->ws_over_h2_count == 1)
		lws_set_timeout(nwsi, NO_PENDING_TIMEOUT, 0);

	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
	lwsl_info("Upgraded h2 to ws OK\n");

	return LWS_UPG_RET_DONE;
#else
	return LWS_UPG_RET_CONTINUE;
#endif
}

static int
rops_init_vhost_h2(struct lws_vhost *vh,
		   struct lws_context_creation_info *info)
{
	if (!info->h2_rx_scratch_size)
		vh->h2_rx_scratch_size = LWS_H2_RX_SCRATCH_SIZE;
	else
		vh->h2_rx_scratch_size = info->h2_rx_scratch_size;

	return 0;
}

static int
rops_init_context_h2(struct lws_context *context,
		     struct lws_context_creation_info *info)
{
	context->set = lws_h2_stock_settings;

	return 0;
}

static lws_filepos_t
rops_tx_credit_h2(struct lws *wsi)
{
	return lws_h2_tx_cr_get(wsi);
}

static int
rops_destroy_role_h2(struct lws *wsi)
{
	if (wsi->upgraded_to_http2 || wsi->http2_substream) {
		lws_hpack_destroy_dynamic_header(wsi);

		if (wsi->h2.h2n)
			lws_free_set_NULL(wsi->h2.h2n);
	}

	return 0;
}

static int
rops_close_kill_connection_h2(struct lws *wsi, enum lws_close_status reason)
{
	struct lws *wsi2;

	if (wsi->http2_substream && wsi->h2_stream_carries_ws)
		lws_h2_rst_stream(wsi, 0, "none");

	if (wsi->h2.parent_wsi) {
		lwsl_info(" wsi: %p, his parent %p: siblings:\n", wsi,
			  wsi->h2.parent_wsi);
		lws_start_foreach_llp(struct lws **, w,
				      wsi->h2.parent_wsi->h2.child_list) {
			lwsl_info("   \\---- child %p\n", *w);
		} lws_end_foreach_llp(w, h2.sibling_list);
	}

	if (wsi->upgraded_to_http2 || wsi->http2_substream || wsi->client_h2_substream) {
		lwsl_info("closing %p: parent %p\n", wsi, wsi->h2.parent_wsi);

		if (wsi->h2.child_list) {
			lwsl_info(" parent %p: closing children: list:\n", wsi);
			lws_start_foreach_llp(struct lws **, w,
					      wsi->h2.child_list) {
				lwsl_info("   \\---- child %p\n", *w);
			} lws_end_foreach_llp(w, h2.sibling_list);
			/* trigger closing of all of our http2 children first */
			lws_start_foreach_llp(struct lws **, w,
					      wsi->h2.child_list) {
				lwsl_info("   closing child %p\n", *w);
				/* disconnect from siblings */
				wsi2 = (*w)->h2.sibling_list;
				(*w)->h2.sibling_list = NULL;
				(*w)->socket_is_permanently_unusable = 1;
				__lws_close_free_wsi(*w, reason, "h2 child recurse");
				*w = wsi2;
				continue;
			} lws_end_foreach_llp(w, h2.sibling_list);
		}
	}

	if (wsi->upgraded_to_http2) {
		/* remove pps */
		struct lws_h2_protocol_send *w = wsi->h2.h2n->pps, *w1;
		while (w) {
			w1 = w->next;
			free(w);
			w = w1;
		}
		wsi->h2.h2n->pps = NULL;
	}

	if ((wsi->client_h2_substream || wsi->http2_substream) &&
	     wsi->h2.parent_wsi) {
		lwsl_info("  %p: disentangling from siblings\n", wsi);
		lws_start_foreach_llp(struct lws **, w,
				wsi->h2.parent_wsi->h2.child_list) {
			/* disconnect from siblings */
			if (*w == wsi) {
				wsi2 = (*w)->h2.sibling_list;
				(*w)->h2.sibling_list = NULL;
				*w = wsi2;
				lwsl_info("  %p disentangled from sibling %p\n",
					  wsi, wsi2);
				break;
			}
		} lws_end_foreach_llp(w, h2.sibling_list);
		wsi->h2.parent_wsi->h2.child_count--;
		wsi->h2.parent_wsi = NULL;
		if (wsi->h2.pending_status_body)
			lws_free_set_NULL(wsi->h2.pending_status_body);
	}

	if (wsi->h2_stream_carries_ws) {
		struct lws *nwsi = lws_get_network_wsi(wsi);

		nwsi->ws_over_h2_count++;
		/* if no ws, then put a timeout on the parent wsi */
		if (!nwsi->ws_over_h2_count)
			__lws_set_timeout(nwsi,
				PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE, 31);
	}

	if (wsi->upgraded_to_http2 && wsi->h2.h2n &&
	    wsi->h2.h2n->rx_scratch)
		lws_free_set_NULL(wsi->h2.h2n->rx_scratch);

	return 0;
}

static int
rops_callback_on_writable_h2(struct lws *wsi)
{
	struct lws *network_wsi, *wsi2;
	int already;

	//lwsl_notice("%s: %p (wsistate 0x%x)\n", __func__, wsi, wsi->wsistate);

//	if (!lwsi_role_h2(wsi) && !lwsi_role_h2_ENCAPSULATION(wsi))
//		return 0;

	if (wsi->h2.requested_POLLOUT
#if !defined(LWS_NO_CLIENT)
			&& !wsi->client_h2_alpn
#endif
	) {
		lwsl_debug("already pending writable\n");
		return 1;
	}

	/* is this for DATA or for control messages? */
	if (wsi->upgraded_to_http2 && !wsi->h2.h2n->pps &&
	    !lws_h2_tx_cr_get(wsi)) {
		/*
		 * other side is not able to cope with us sending DATA
		 * anything so no matter if we have POLLOUT on our side if it's
		 * DATA we want to send.
		 *
		 * Delay waiting for our POLLOUT until peer indicates he has
		 * space for more using tx window command in http2 layer
		 */
		lwsl_notice("%s: %p: skint (%d)\n", __func__, wsi,
			    wsi->h2.tx_cr);
		wsi->h2.skint = 1;
		return 0;
	}

	wsi->h2.skint = 0;
	network_wsi = lws_get_network_wsi(wsi);
	already = network_wsi->h2.requested_POLLOUT;

	/* mark everybody above him as requesting pollout */

	wsi2 = wsi;
	while (wsi2) {
		wsi2->h2.requested_POLLOUT = 1;
		lwsl_info("mark %p pending writable\n", wsi2);
		wsi2 = wsi2->h2.parent_wsi;
	}

	/* for network action, act only on the network wsi */

	wsi = network_wsi;
	if (already && !wsi->client_h2_alpn
#if !defined(LWS_NO_CLIENT)
			&& !wsi->client_h2_substream
#endif
			)
		return 1;

	return 0;
}

static void
lws_h2_dump_waiting_children(struct lws *wsi)
{
#if defined(_DEBUG)
	lwsl_info("%s: %p: children waiting for POLLOUT service:\n",
		  __func__, wsi);

	wsi = wsi->h2.child_list;
	while (wsi) {
		if (wsi->h2.requested_POLLOUT)
			lwsl_info("  * %p %s\n", wsi, wsi->protocol->name);
		else
			lwsl_info("    %p %s\n", wsi, wsi->protocol->name);

		wsi = wsi->h2.sibling_list;
	}
#endif
}

/*
 * we are the 'network wsi' for potentially many muxed child wsi with
 * no network connection of their own, who have to use us for all their
 * network actions.  So we use a round-robin scheme to share out the
 * POLLOUT notifications to our children.
 *
 * But because any child could exhaust the socket's ability to take
 * writes, we can only let one child get notified each time.
 *
 * In addition children may be closed / deleted / added between POLLOUT
 * notifications, so we can't hold pointers
 */

static int
rops_perform_user_POLLOUT_h2(struct lws *wsi)
{
	struct lws **wsi2, *wsi2a;
	int write_type = LWS_WRITE_PONG, n;

	wsi = lws_get_network_wsi(wsi);

	wsi->h2.requested_POLLOUT = 0;
	if (!wsi->h2.initialized) {
		lwsl_info("pollout on uninitialized http2 conn\n");
		return 0;
	}

	lws_h2_dump_waiting_children(wsi);

	wsi2 = &wsi->h2.child_list;
	if (!*wsi2)
		return 0;

	do {
		struct lws *w, **wa;

		wa = &(*wsi2)->h2.sibling_list;
		if (!(*wsi2)->h2.requested_POLLOUT)
			goto next_child;

		/*
		 * we're going to do writable callback for this child.
		 * move him to be the last child
		 */

		lwsl_debug("servicing child %p\n", *wsi2);

		w = *wsi2;
		while (w) {
			if (!w->h2.sibling_list) { /* w is the current last */
				lwsl_debug("w=%p, *wsi2 = %p\n", w, *wsi2);
				if (w == *wsi2) /* we are already last */
					break;
				/* last points to us as new last */
				w->h2.sibling_list = *wsi2;
				/* guy pointing to us until now points to
				 * our old next */
				*wsi2 = (*wsi2)->h2.sibling_list;
				/* we point to nothing because we are last */
				w->h2.sibling_list->h2.sibling_list = NULL;
				/* w becomes us */
				w = w->h2.sibling_list;
				break;
			}
			w = w->h2.sibling_list;
		}

		w->h2.requested_POLLOUT = 0;
		lwsl_info("%s: child %p (wsistate 0x%x)\n", __func__, w,
			  w->wsistate);

		/* if we arrived here, even by looping, we checked choked */
		w->could_have_pending = 0;
		wsi->could_have_pending = 0;

		if (w->h2.pending_status_body) {
			w->h2.send_END_STREAM = 1;
			n = lws_write(w, (uint8_t *)w->h2.pending_status_body +
					 LWS_PRE,
				         strlen(w->h2.pending_status_body +
					        LWS_PRE), LWS_WRITE_HTTP_FINAL);
			lws_free_set_NULL(w->h2.pending_status_body);
			lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
					   "h2 end stream 1");
			wa = &wsi->h2.child_list;
			goto next_child;
		}

		if (lwsi_state(w) == LRS_H2_WAITING_TO_SEND_HEADERS) {
			if (lws_h2_client_handshake(w))
				return -1;

			goto next_child;
		}

		if (lwsi_state(w) == LRS_DEFERRING_ACTION) {

			/*
			 * we had to defer the http_action to the POLLOUT
			 * handler, because we know it will send something and
			 * only in the POLLOUT handler do we know for sure
			 * that there is no partial pending on the network wsi.
			 */

			lwsi_set_state(w, LRS_ESTABLISHED);

			lwsl_info("  h2 action start...\n");
			n = lws_http_action(w);
			lwsl_info("  h2 action result %d "
				  "(wsi->http.rx_content_remain %lld)\n",
				  n, w->http.rx_content_remain);

			/*
			 * Commonly we only managed to start a larger transfer
			 * that will complete asynchronously under its own wsi
			 * states.  In those cases we will hear about
			 * END_STREAM going out in the POLLOUT handler.
			 */
			if (n || w->h2.send_END_STREAM) {
				lwsl_info("closing stream after h2 action\n");
				lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
						   "h2 end stream");
				wa = &wsi->h2.child_list;
			}

			goto next_child;
		}

		if (lwsi_state(w) == LRS_ISSUING_FILE) {

			((volatile struct lws *)w)->leave_pollout_active = 0;

			/* >0 == completion, <0 == error
			 *
			 * We'll get a LWS_CALLBACK_HTTP_FILE_COMPLETION
			 * callback when it's done.  That's the case even if we
			 * just completed the send, so wait for that.
			 */
			n = lws_serve_http_file_fragment(w);
			lwsl_debug("lws_serve_http_file_fragment says %d\n", n);

			/*
			 * We will often hear about out having sent the final
			 * DATA here... if so close the actual wsi
			 */
			if (n < 0 || w->h2.send_END_STREAM) {
				lwsl_debug("Closing POLLOUT child %p\n", w);
				lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
						   "h2 end stream file");
				wa = &wsi->h2.child_list;
				goto next_child;
			}
			if (n > 0)
				if (lws_http_transaction_completed(w))
					return -1;
			if (!n) {
				lws_callback_on_writable(w);
				(w)->h2.requested_POLLOUT = 1;
			}

			goto next_child;
		}

		/* Notify peer that we decided to close */

		if (lwsi_state(w) == LRS_WAITING_TO_SEND_CLOSE) {
			lwsl_debug("sending close packet\n");
			w->waiting_to_send_close_frame = 0;
			n = lws_write(w, &w->ws->ping_payload_buf[LWS_PRE],
				      w->ws->close_in_ping_buffer_len,
				      LWS_WRITE_CLOSE);
			if (n >= 0) {
				lwsi_set_state(w, LRS_AWAITING_CLOSE_ACK);
				lws_set_timeout(w, PENDING_TIMEOUT_CLOSE_ACK, 5);
				lwsl_debug("sent close frame, awaiting ack\n");
			}

			goto next_child;
		}

		/*
		 * Acknowledge receipt of peer's notification he closed,
		 * then logically close ourself
		 */

		if ((lwsi_role_ws(w) && w->ws->ping_pending_flag) ||
		    (lwsi_state(w) == LRS_RETURNED_CLOSE &&
		     w->ws->payload_is_close)) {

			if (w->ws->payload_is_close)
				write_type = LWS_WRITE_CLOSE |
					     LWS_WRITE_H2_STREAM_END;

			n = lws_write(w, &w->ws->ping_payload_buf[LWS_PRE],
				      w->ws->ping_payload_len, write_type);
			if (n < 0)
				return -1;

			/* well he is sent, mark him done */
			w->ws->ping_pending_flag = 0;
			if (w->ws->payload_is_close) {
				/* oh... a close frame... then we are done */
				lwsl_debug("Acknowledged peer's close packet\n");
				w->ws->payload_is_close = 0;
				lwsi_set_state(w, LRS_RETURNED_CLOSE);
				lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
						   "returned close packet");
				wa = &wsi->h2.child_list;
				goto next_child;
			}

			lws_callback_on_writable(w);
			(w)->h2.requested_POLLOUT = 1;

			/* otherwise for PING, leave POLLOUT active either way */
			goto next_child;
		}

		if (lws_callback_as_writeable(w)) {
			lwsl_info("Closing POLLOUT child (end stream %d)\n",
				  w->h2.send_END_STREAM);
			lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
					   "h2 pollout handle");
			wa = &wsi->h2.child_list;
		} else
			 if (w->h2.send_END_STREAM)
				lws_h2_state(w, LWS_H2_STATE_HALF_CLOSED_LOCAL);

next_child:
		wsi2 = wa;
	} while (wsi2 && *wsi2 && !lws_send_pipe_choked(wsi));

	// lws_h2_dump_waiting_children(wsi);

	wsi2a = wsi->h2.child_list;
	while (wsi2a) {
		if (wsi2a->h2.requested_POLLOUT) {
			lws_change_pollfd(wsi, 0, LWS_POLLOUT);
			break;
		}
		wsi2a = wsi2a->h2.sibling_list;
	}

	return 0;
}

static int
rops_rxflow_cache_h2(struct lws *wsi, unsigned char *buf, int n, int len)
{
	struct lws_h2_netconn *h2n;

	if (!wsi->upgraded_to_http2)
		return 0; /* parent interprets as continue */

	h2n = wsi->h2.h2n;

	assert(h2n->rx_scratch);
	buf += n;
	len -= n;
	assert ((char *)buf >= (char *)h2n->rx_scratch &&
		(char *)&buf[len] <=
		    (char *)&h2n->rx_scratch[wsi->vhost->h2_rx_scratch_size]);

	h2n->rx_scratch_pos = lws_ptr_diff(buf, h2n->rx_scratch);
	h2n->rx_scratch_len = len;

	lwsl_info("%s: %p: pausing h2 rx_scratch\n", __func__, wsi);

	return 1; /* parent interprets as return 0 */
}

static struct lws *
rops_encapsulation_parent_h2(struct lws *wsi)
{
	if (wsi->h2.parent_wsi)
		return wsi->h2.parent_wsi;

	return NULL;
}

static int
rops_alpn_negotiated_h2(struct lws *wsi, const char *alpn)
{
	struct allocated_headers *ah;

	lwsl_debug("%s: client %d\n", __func__, lwsi_role_client(wsi));
#if !defined(LWS_NO_CLIENT)
	if (lwsi_role_client(wsi)) {
		lwsl_info("%s: upgraded to H2\n", __func__);
		wsi->client_h2_alpn = 1;
	}
#endif

		wsi->upgraded_to_http2 = 1;
		wsi->vhost->conn_stats.h2_alpn++;

		/* adopt the header info */

		ah = wsi->ah;

		lws_role_transition(wsi, LWSIFR_SERVER, LRS_H2_AWAIT_PREFACE,
				    &role_ops_h2);

		/* http2 union member has http union struct at start */
		wsi->ah = ah;

		if (!wsi->h2.h2n)
			wsi->h2.h2n = lws_zalloc(sizeof(*wsi->h2.h2n), "h2n");
		if (!wsi->h2.h2n)
			return 1;

		lws_h2_init(wsi);

		/* HTTP2 union */

		lws_hpack_dynamic_size(wsi,
				       wsi->h2.h2n->set.s[H2SET_HEADER_TABLE_SIZE]);
		wsi->h2.tx_cr = 65535;

		lwsl_info("%s: wsi %p: configured for h2\n", __func__, wsi);


	return 0;
}

struct lws_role_ops role_ops_h2 = {
	/* role name */			"h2",
	/* alpn id */			"h2",
	/* check_upgrades */		rops_check_upgrades_h2,
	/* init_context */		rops_init_context_h2,
	/* init_vhost */		rops_init_vhost_h2,
	/* periodic_checks */		NULL,
	/* service_flag_pending */	rops_service_flag_pending_h2,
	/* handle_POLLIN */		rops_handle_POLLIN_h2,
	/* handle_POLLOUT */		rops_handle_POLLOUT_h2,
	/* perform_user_POLLOUT */	rops_perform_user_POLLOUT_h2,
	/* callback_on_writable */	rops_callback_on_writable_h2,
	/* tx_credit */			rops_tx_credit_h2,
	/* write_role_protocol */	rops_write_role_protocol_h2,
	/* rxflow_cache */		rops_rxflow_cache_h2,
	/* encapsulation_parent */	rops_encapsulation_parent_h2,
	/* alpn_negotiated */		rops_alpn_negotiated_h2,
	/* close_via_role_protocol */	NULL,
	/* close_role */		NULL,
	/* close_kill_connection */	rops_close_kill_connection_h2,
	/* destroy_role */		rops_destroy_role_h2,
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_CLIENT_HTTP_WRITEABLE,
					  LWS_CALLBACK_HTTP_WRITEABLE },
	/* close cb clnt, srv */	{ LWS_CALLBACK_CLOSED_CLIENT_HTTP,
					  LWS_CALLBACK_CLOSED_HTTP },
};
