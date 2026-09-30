/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

#include <private-lib-core.h>

#if defined(LWS_WITH_CLIENT)
/*
 * The client's transport is up (IO's connect and tls are done): the user
 * hears the connection exists.  The client_transport_up op.
 */
static lws_handling_result_t
rops_client_transport_up_raw_skt(struct lws *wsi, const lws_sockaddr46 *peer)
{
	/*
	 * whether the user has already been told: TRANSPORT_UP below tells.
	 * A STARTTLS upgrade is told again: that is how the user hears the
	 * tls it asked for with lws_tls_client_upgrade() is up
	 */
	int told = lwsi_carrier(wsi) == LCR_ESTABLISHED &&
		   !lwsi_tls_upgrading(wsi), n;

	/*
	 * Nothing reads the connection while its STARTTLS handshake goes on,
	 * so whatever is parked now was read before the tls, unprotected: it
	 * must not be given to the user as though it came over it.  An
	 * upgrade started from RAW_RX was already checked after that rx (by
	 * lws_rx_pump()), this is for one started from anywhere else.
	 */
	if (lwsi_tls_upgrading(wsi) &&
	    lws_buflist_next_segment_len(&wsi->buflist, NULL)) {
		lwsl_wsi_warn(wsi, "plaintext parked behind the start of tls");

		return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

	/*
	 * The transport is up before the user hears of it: a callback that
	 * completes the raw transaction, or closes, leaves the wsi in a close
	 * phase, from which TRANSPORT_UP raised afterwards had no row
	 */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
	lws_wsi_event(wsi, LWS_WSIEV_TRANSPORT_UP);

	if (told)
		return LWS_HPI_RET_HANDLED;

	n = user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
			wsi->role_ops->adoption_cb[lwsi_role_server(wsi)],
			wsi->user_space, NULL, 0);
	if (n)
		return LWS_HPI_RET_PLEASE_CLOSE_ME;

	return LWS_HPI_RET_HANDLED;
}
#endif

/*
 * sansIO rx for a raw socket: every byte goes to the user as RAW_RX, so
 * everything is consumed.  len 0 is the peer closing.
 */
static lws_handling_result_t
rops_rx_raw_skt(struct lws *wsi, const uint8_t *buf, size_t len,
		int from_transport, size_t *used)
{
	int n;

	(void)from_transport;
	*used = 0;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SOCKS5)
	if (lwsi_in_socks5_leg(wsi)) {
		const char *cce = NULL;
		lws_handling_result_t hr;

		switch (lws_socks5c_rx(wsi, buf, len, &cce, used)) {
		case LW5CHS_RET_BAIL3:
			lws_inform_client_conn_fail(wsi, (void *)cce,
						    strlen(cce));

			return LWS_HPI_RET_PLEASE_CLOSE_ME;
		case LW5CHS_RET_STARTHS:
			/*
			 * The socks leg is done: IO finishes the connection
			 * the way a direct one finishes, tls first if that was
			 * asked for
			 */
			hr = lws_client_transport_connected(wsi);
			if (hr != LWS_HPI_RET_HANDLED)
				return hr;
			break;
		default:
			break;
		}

		/* what followed the reply is the peer's: left for us as raw */
		return LWS_HPI_RET_HANDLED;
	}
#endif

	if (!len)
		return LWS_HPI_RET_PLEASE_CLOSE_ME;

#if defined(LWS_WITH_UDP)
	if (lws_fi(&wsi->fic, "udp_rx_loss")) {
		*used = len;

		return LWS_HPI_RET_HANDLED;
	}
#endif

	n = user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
					LWS_CALLBACK_RAW_RX, wsi->user_space,
					(void *)buf, len);
	if (n < 0) {
		lwsl_wsi_info(wsi, "LWS_CALLBACK_RAW_RX_fail");

		return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

	*used = len;

	return LWS_HPI_RET_HANDLED;
}

/*
 * How a raw socket is read: not while a partial send is pending (nothing
 * must be generated behind it), not during the transport phases, else
 * forced even with rx parked (a plain socket, nothing to block behind),
 * bounded by the protocol's rx_buffer_size.  Pre-established server
 * sockets are in their tls accept, the handler's.
 */
static int
rops_rx_policy_raw_skt(struct lws *wsi, int *flags, size_t *max)
{
	if (lws_has_buffered_out(wsi)) {
		/*
		 * Nothing is read until the partial send drains, so a
		 * level-armed POLLIN would spin: drop it, the drain restores it
		 * (rops_tx_drained_raw_skt())
		 */
		if (lws_io_want_read(wsi, 0))
			return LWS_RXPOL_CLOSE;

		return LWS_RXPOL_HOLD;
	}

#if defined(LWS_WITH_SERVER)
	if (!lwsi_role_client(wsi) && lwsi_state(wsi) != LRS_ESTABLISHED)
		return LWS_RXPOL_ROLE;
#endif
	switch (lwsi_state(wsi)) {
	case LRS_SSL_ACK_PENDING:
	case LRS_WAITING_CONNECT:
	case LRS_WAITING_SSL:
		return LWS_RXPOL_ROLE;
	default:
		break;
	}

	*flags = LWS_RXP_FORCE_READ;
	*max = wsi->a.protocol->rx_buffer_size;

	return LWS_RXPOL_PUMP;
}

/* established: the user hears it is writeable; the dispatcher does the rest */
static lws_handling_result_t
rops_handle_POLLOUT_raw_skt(struct lws *wsi)
{
	(void)wsi;

	return LWS_HP_RET_USER_SERVICE;
}


static int
rops_adoption_bind_raw_skt(struct lws *wsi, int type, const char *vh_prot_name)
{

	// lwsl_notice("%s: bind type %d\n", __func__, type);

	/* no http but socket... must be raw skt */
	if ((type & LWS_ADOPT_HTTP) || !(type & LWS_ADOPT_SOCKET) ||
	    ((type & _LWS_ADOPT_FINISH) && (!(type & LWS_ADOPT_FLAG_UDP))))
		return 0; /* no match */

	/* the udp FINISH pass only binds the protocol: no second adoption */
	if (!(type & _LWS_ADOPT_FINISH))
		lws_wsi_event_role(wsi, (type & LWS_ADOPT_ALLOW_SSL) ?
					LWS_WSIEV_ADOPTED_TLS : LWS_WSIEV_ADOPTED,
				   &role_ops_raw_skt);

	if (vh_prot_name)
		lws_bind_protocol(wsi, wsi->a.protocol, __func__);
	else
		/* this is the only time he will transition */
		lws_bind_protocol(wsi,
			&wsi->a.vhost->protocols[wsi->a.vhost->raw_protocol_index],
			__func__);

	return 1; /* bound */
}

#if defined(LWS_WITH_CLIENT)
static int
rops_client_bind_raw_skt(struct lws *wsi,
			 const struct lws_client_connect_info *i)
{
	if (!i) {

		/* finalize */

		if (!wsi->user_space && wsi->stash->cis[CIS_METHOD])
			if (lws_ensure_user_space(wsi))
				return 1;

		return 0;
	}

	/* we are a fallback if nothing else matched */

	if (!i->local_protocol_name ||
	    strcmp(i->local_protocol_name, "raw-proxy"))
		lws_wsi_event_role(wsi, LWS_WSIEV_CLIENT_BIND, &role_ops_raw_skt);

	return 1; /* matched */
}
#endif

/* the partial send our rx policy held reading behind has gone */
static int
rops_tx_drained_raw_skt(struct lws *wsi)
{
	return lws_io_read_after_drain(wsi) ? -1 : 0;
}

static const lws_rops_t rops_table_raw_skt[] = {
	/*  1 */ { .handle_POLLIN	  = NULL }, /* a sansIO role has none */
	/*  2 */ { .adoption_bind	  = rops_adoption_bind_raw_skt },
	/*  3 */ { .handle_POLLOUT	  = rops_handle_POLLOUT_raw_skt },
#if defined(LWS_WITH_CLIENT)
	/*  4 */ { .client_bind		  = rops_client_bind_raw_skt },
#endif
	/*  5, or 4 with no client */
	{ .rx				  = rops_rx_raw_skt },
	/*  6, or 5 with no client */
	{ .rx_policy			  = rops_rx_policy_raw_skt },
#if defined(LWS_WITH_CLIENT)
	/*  7 */ { .client_transport_up	  = rops_client_transport_up_raw_skt },
#endif
	/*  8, or 6 with no client */
	{ .tx_drained			  = rops_tx_drained_raw_skt },
};
const struct lws_role_ops role_ops_raw_skt = {
	/* role name */			"raw-skt",
	/* alpn id */			NULL,

	/* rops_table */		rops_table_raw_skt,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00, 0x00,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00, 0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x00, 0x00,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x03, 0x00,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x00, 0x00,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x00, 0x00,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x00, 0x00,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x00, 0x00,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x00, 0x02,
#if defined(LWS_WITH_CLIENT)
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x04, 0x00,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x07, 0x05,
	  /* LWS_ROPS_rx_dgram */
	  /* LWS_ROPS_rx_policy */			0x00, 0x06,
	  /* LWS_ROPS_rx_done */			0x00,
	  /* LWS_ROPS_tx */
	  /* LWS_ROPS_tx_sent */			0x00, 0x00,
	  /* LWS_ROPS_tx_drained */			0x08,
#else
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x00, 0x00,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x00, 0x04,
	  /* LWS_ROPS_rx_dgram */
	  /* LWS_ROPS_rx_policy */			0x00, 0x05,
	  /* LWS_ROPS_rx_done */			0x00,
	  /* LWS_ROPS_tx */
	  /* LWS_ROPS_tx_sent */			0x00, 0x00,
	  /* LWS_ROPS_tx_drained */			0x06,
#endif
					},

	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_RAW_CONNECTED,
					  LWS_CALLBACK_RAW_ADOPT },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_RAW_RX,
					  LWS_CALLBACK_RAW_RX },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_RAW_WRITEABLE,
					  LWS_CALLBACK_RAW_WRITEABLE},
	/* close cb clnt, srv */	{ LWS_CALLBACK_RAW_CLOSE,
					  LWS_CALLBACK_RAW_CLOSE },
	/* protocol_bind cb c, srv */	{ LWS_CALLBACK_RAW_SKT_BIND_PROTOCOL,
					  LWS_CALLBACK_RAW_SKT_BIND_PROTOCOL },
	/* protocol_unbind cb c, srv */	{ LWS_CALLBACK_RAW_SKT_DROP_PROTOCOL,
					  LWS_CALLBACK_RAW_SKT_DROP_PROTOCOL },
	/* file_handle */		0,
	/* child_stdio */		0,
};
