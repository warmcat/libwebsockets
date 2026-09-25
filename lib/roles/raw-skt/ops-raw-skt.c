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
static int
lws_raw_skt_connect(struct lws *wsi)
{
	int n;
#if defined(LWS_WITH_TLS)
	const char *cce = NULL;
	char ccebuf[128];

#if !defined(LWS_WITH_SYS_ASYNC_DNS)
	switch (lws_client_create_tls(wsi, &cce, 1)) {
#else
	switch (lws_client_create_tls(wsi, &cce, 0)) {
#endif
	case CCTLS_RETURN_ERROR:
		lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));
		return -1;
	case CCTLS_RETURN_RETRY:
		return 0;
	case CCTLS_RETURN_DONE:
		break;
	}

	if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
		/*
		 * Arriving here from the socks5 leg the transport is still in
		 * the socks phase, and the tls connect only runs its handshake
		 * from WAITING_SSL: without this it reported the tls link up
		 * with no handshake ever made
		 */
		if (lwsi_transport(wsi) != LTS_WAITING_SSL)
			lws_wsi_event(wsi, LWS_WSIEV_TLS_START);
		n = lws_ssl_client_connect2(wsi, ccebuf, sizeof(ccebuf));
		if (n < 0) {
			lws_inform_client_conn_fail(wsi, (void *)ccebuf,
						    strlen(ccebuf));

			return -1;
		}
		if (n != 1)
			return 0; /* wait */
	}
#endif

	/*
	 * The POLLOUT path runs the generic connect completion first, which
	 * already delivered the adoption callback and set ESTABLISHED, so the
	 * carrier being established is "the user has already been told"
	 */
	n = lwsi_carrier(wsi) != LCR_ESTABLISHED;

	/*
	 * The transport is up before the user hears of it: a callback that
	 * completes the raw transaction, or closes, leaves the wsi in a close
	 * phase, from which TRANSPORT_UP raised afterwards had no row
	 */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
	lws_wsi_event(wsi, LWS_WSIEV_TRANSPORT_UP);

	if (n) {
		n = user_callback_handle_rxflow(wsi->a.protocol->callback,
				wsi, wsi->role_ops->adoption_cb[lwsi_role_server(wsi)],
				wsi->user_space, NULL, 0);
		if (n) {
			lws_inform_client_conn_fail(wsi, (void *)"user", 4);
			return 1;
		}
	}

	return 1; /* success */
}
#endif

/*
 * sansIO rx for a raw socket: every byte goes to the user as RAW_RX, so
 * everything is consumed.  len 0 is the peer closing.
 */
static int
rops_rx_raw_skt(struct lws *wsi, const uint8_t *buf, size_t len,
		int from_transport)
{
	int n;

	(void)from_transport;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SOCKS5)
	if (lwsi_in_socks5_leg(wsi)) {
		const char *cce = NULL;

		switch (lws_socks5c_rx(wsi, buf, len, &cce)) {
		case LW5CHS_RET_BAIL3:
			lws_inform_client_conn_fail(wsi, (void *)cce,
						    strlen(cce));
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "raw skt socks fail");

			return LWS_RX_DIED;
		case LW5CHS_RET_STARTHS:
			/*
			 * The socks leg is done: finish the connection the
			 * way a direct one finishes, tls first if that was
			 * asked for.  Going back through the generic
			 * completion would only send the socks greeting
			 * again.
			 */
			if (lws_raw_skt_connect(wsi) < 0) {
				lws_close_free_wsi(wsi,
						   LWS_CLOSE_STATUS_NOSTATUS,
						   "raw svc fail");

				return LWS_RX_DIED;
			}
			break;
		default:
			break;
		}

		return (int)len;
	}
#endif

	if (!len)
		return LWS_RX_CLOSE;

#if defined(LWS_WITH_UDP)
	if (lws_fi(&wsi->fic, "udp_rx_loss"))
		return (int)len;
#endif

	n = user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
					LWS_CALLBACK_RAW_RX, wsi->user_space,
					(void *)buf, len);
	if (n < 0) {
		lwsl_wsi_info(wsi, "LWS_CALLBACK_RAW_RX_fail");

		return LWS_RX_CLOSE;
	}

	return (int)len;
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
	if (lws_has_buffered_out(wsi))
		return LWS_RXPOL_HOLD;

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

static lws_handling_result_t
rops_handle_POLLIN_raw_skt(struct lws_context_per_thread *pt, struct lws *wsi,
			   struct lws_pollfd *pollfd)
{
	int n = 0;
#if defined(LWS_WITH_LATENCY)
	lws_usec_t _raw_skt_start = lws_now_usecs();
#endif

	/* pending truncated sends have uber priority */

	if (lws_has_buffered_out(wsi)) {
		if (!(pollfd->revents & LWS_POLLOUT))
			return LWS_HPI_RET_HANDLED;

		/* drain the output buflist */
		if (lws_issue_raw(wsi, NULL, 0) < 0)
			goto fail;
		/*
		 * we can't afford to allow input processing to send
		 * something new, so spin around he event loop until
		 * he doesn't have any partials
		 */
		return LWS_HPI_RET_HANDLED;
	}


#if defined(LWS_WITH_SERVER)
	if (!lwsi_role_client(wsi) &&  lwsi_state(wsi) != LRS_ESTABLISHED) {

		lwsl_wsi_debug(wsi, "wsistate 0x%x\n", (int)wsi->wsistate);

		if (lwsi_transport(wsi) != LTS_SSL_INIT)
			if (lws_server_socket_service_ssl(wsi,
							  LWS_SOCK_INVALID,
				!!(pollfd->revents & pollfd->events & LWS_POLLIN)))
				return LWS_HPI_RET_PLEASE_CLOSE_ME;

		return LWS_HPI_RET_HANDLED;
	}
#endif

	if ((pollfd->revents & pollfd->events & LWS_POLLIN) &&
	    !(wsi->favoured_pollin &&
	      (pollfd->revents & pollfd->events & LWS_POLLOUT))) {

		lwsl_wsi_debug(wsi, "POLLIN: state 0x%x", lwsi_state(wsi));

		switch (lwsi_state(wsi)) {

		    /* any tunnel has to have been established... */
		case LRS_SSL_ACK_PENDING:
			goto nope;
		    /* we are actually connected */
		case LRS_WAITING_CONNECT:
			goto nope;

		case LRS_WAITING_SSL:
#if defined(LWS_WITH_CLIENT)
			n = lws_raw_skt_connect(wsi);
			if (n < 0)
				goto fail;
#endif
			break;

		default:
			/* the reading was done by IO's rx stage */
			break;
		}
	}
nope:
	if (!(pollfd->revents & LWS_POLLOUT))
		return LWS_HPI_RET_HANDLED;

#if defined(LWS_WITH_CLIENT)
	if (lwsi_transport(wsi) == LTS_WAITING_CONNECT) {
	    if (!lws_client_connect_3_connect(wsi, NULL, NULL, 0, pollfd))
		return LWS_HPI_RET_WSI_ALREADY_DIED;

	    /*
	     * The generic completion either finished a plain connection
	     * (ESTABLISHED already), started tls (WAITING_SSL, which we
	     * carry on with here), or only started a proxy or socks leg
	     * whose replies arrive on POLLIN in their own states.  It may
	     * also still be connecting.  Only the tls case is ours to
	     * finish now.
	     */
	    if (lwsi_transport(wsi) == LTS_WAITING_SSL &&
		lws_raw_skt_connect(wsi) < 0)
		    goto fail;
	}
#endif

	/*
	 * Established, the pass's POLLOUT was served by IO's rx stage.  In a
	 * transport phase it was not, and nothing else clears it: one shot
	 */
	if (!lwsi_state_can_handle_POLLOUT(wsi) &&
	    lws_change_pollfd(wsi, LWS_POLLOUT, 0))
		goto fail;

#if defined(LWS_WITH_LATENCY)
		{
			unsigned int ms = (unsigned int)((lws_now_usecs() - _raw_skt_start) / 1000);
			if (ms > 2)
				lws_latency_note(pt, _raw_skt_start, 2000, "rawskt:%dms", ms);
		}
#endif

	return LWS_HPI_RET_HANDLED;

fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "raw svc fail");

	return LWS_HPI_RET_WSI_ALREADY_DIED;
}

static int
rops_adoption_bind_raw_skt(struct lws *wsi, int type, const char *vh_prot_name)
{

	// lwsl_notice("%s: bind type %d\n", __func__, type);

	/* no http but socket... must be raw skt */
	if ((type & LWS_ADOPT_HTTP) || !(type & LWS_ADOPT_SOCKET) ||
	    ((type & _LWS_ADOPT_FINISH) && (!(type & LWS_ADOPT_FLAG_UDP))))
		return 0; /* no match */

#if defined(LWS_WITH_UDP)
	if ((type & LWS_ADOPT_FLAG_UDP) && !wsi->udp) {
		/*
		 * these can be >128 bytes, so just alloc for UDP
		 */
		wsi->udp = lws_malloc(sizeof(*wsi->udp), "udp struct");
		if (!wsi->udp)
			return 0;
		memset(wsi->udp, 0, sizeof(*wsi->udp));
	}
#endif

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

static const lws_rops_t rops_table_raw_skt[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_raw_skt },
	/*  2 */ { .adoption_bind	  = rops_adoption_bind_raw_skt },
	/*  3 */ { .handle_POLLOUT	  = rops_handle_POLLOUT_raw_skt },
#if defined(LWS_WITH_CLIENT)
	/*  4 */ { .client_bind		  = rops_client_bind_raw_skt },
#endif
	/*  5, or 4 with no client */
	{ .rx				  = rops_rx_raw_skt },
	/*  6, or 5 with no client */
	{ .rx_policy			  = rops_rx_policy_raw_skt },
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
	  /* LWS_ROPS_handle_POLLIN */			0x00, 0x01,
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
	  /* LWS_ROPS_rx */				0x00, 0x05,
	  /* LWS_ROPS_rx_dgram */
	  /* LWS_ROPS_rx_policy */			0x00, 0x06,
#else
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x00, 0x00,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x00, 0x04,
	  /* LWS_ROPS_rx_dgram */
	  /* LWS_ROPS_rx_policy */			0x00, 0x05,
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
};
