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
wops_handle_POLLIN_h2(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_pollfd *pollfd)
{
	struct lws_tokens eff_buf;
	unsigned int pending = 0;
	char draining_flow = 0;
	int n;

#if defined(LWS_WITH_HTTP2)
	struct lws *wsi1;
#endif

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

int wops_handle_POLLOUT_h2(struct lws *wsi)
{
	lwsl_notice("%s\n", __func__);

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

struct lws_protocol_ops wire_ops_h2 = {
	"h2",
	wops_handle_POLLIN_h2,
	wops_handle_POLLOUT_h2
};
