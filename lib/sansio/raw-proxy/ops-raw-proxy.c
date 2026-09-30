/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

/*
 * sansIO rx for a proxied raw socket: every byte goes to the user as the
 * side's RAW_PROXY_*_RX, so everything is consumed.  len 0 is the peer
 * closing.
 */
static lws_handling_result_t
rops_rx_raw_proxy(struct lws *wsi, const uint8_t *buf, size_t len,
		  int from_transport, size_t *used)
{
	int n;

	(void)from_transport;
	*used = 0;

#if defined(LWS_WITH_CLIENT)
	/* the proxy's reply to our CONNECT: not CLI_RX, the tunnel rx's */
	if (lwsi_in_tunnel_leg(wsi))
		return lws_client_tunnel_rx(wsi, buf, len, used);
#endif

	if (!len)
		return LWS_HPI_RET_PLEASE_CLOSE_ME;

	n = user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
					lwsi_role_client(wsi) ?
						LWS_CALLBACK_RAW_PROXY_CLI_RX :
						LWS_CALLBACK_RAW_PROXY_SRV_RX,
					wsi->user_space, (void *)buf, len);
	if (n < 0) {
		lwsl_info("LWS_CALLBACK_RAW_PROXY_*_RX fail\n");

		return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

	*used = len;

	return LWS_HPI_RET_HANDLED;
}

/*
 * As raw-skt: hold behind a partial, not during the transport phases, except
 * a client's tunnel legs, read whole for the tunnel rx
 */
static int
rops_rx_policy_raw_proxy(struct lws *wsi, int *flags, size_t *max)
{
	if (lws_has_buffered_out(wsi)) {
		/*
		 * Nothing is read until the partial send drains, so a
		 * level-armed POLLIN would spin: drop it, the drain restores it
		 * (rops_tx_drained_raw_proxy())
		 */
		if (lws_io_want_read(wsi, 0))
			return LWS_RXPOL_CLOSE;

		return LWS_RXPOL_HOLD;
	}

#if defined(LWS_WITH_CLIENT)
	if (lwsi_role_client(wsi) && lwsi_transport(wsi) != LTS_NONE) {
		if (!lwsi_in_tunnel_leg(wsi))
			/* dns, connect, tls: IO's transport stage */
			return LWS_RXPOL_ROLE;

		*flags = 0;
		*max = 0;

		return LWS_RXPOL_PUMP;
	}
#endif

	if (lwsi_transport(wsi) == LTS_SSL_ACK_PENDING)
		return LWS_RXPOL_ROLE;

	*flags = LWS_RXP_FORCE_READ;
	*max = 0;

	return LWS_RXPOL_PUMP;
}


static int
rops_adoption_bind_raw_proxy(struct lws *wsi, int type,
			     const char *vh_prot_name)
{
	/* no http but socket... must be raw skt */
	if ((type & LWS_ADOPT_HTTP) || !(type & LWS_ADOPT_SOCKET) ||
	    (!(type & LWS_ADOPT_FLAG_RAW_PROXY)) || (type & _LWS_ADOPT_FINISH))
		return 0; /* no match */


	lws_wsi_event_role(wsi, (type & LWS_ADOPT_ALLOW_SSL) ?
				LWS_WSIEV_ADOPTED_TLS : LWS_WSIEV_ADOPTED,
			   &role_ops_raw_proxy);

	if (vh_prot_name)
		lws_bind_protocol(wsi, wsi->a.protocol, __func__);
	else
		/* this is the only time he will transition */
		lws_bind_protocol(wsi,
			&wsi->a.vhost->protocols[wsi->a.vhost->raw_protocol_index],
			__func__);

	return 1; /* bound */
}

static int
rops_client_bind_raw_proxy(struct lws *wsi,
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

	if (i->local_protocol_name && !strcmp(i->local_protocol_name, "raw-proxy"))
		lws_wsi_event_role(wsi, LWS_WSIEV_CLIENT_BIND, &role_ops_raw_proxy);

	return 0;
}

static lws_handling_result_t
rops_handle_POLLOUT_raw_proxy(struct lws *wsi)
{
	if (lwsi_state(wsi) == LRS_ESTABLISHED)
		return LWS_HP_RET_USER_SERVICE;

	if (lwsi_role_client(wsi))
		return LWS_HP_RET_USER_SERVICE;

	return LWS_HP_RET_BAIL_OK;
}

/* the partial send our rx policy held reading behind has gone */
static int
rops_tx_drained_raw_proxy(struct lws *wsi)
{
	return lws_io_read_after_drain(wsi) ? -1 : 0;
}

static const lws_rops_t rops_table_raw_proxy[] = {
	/*  1 */ { .handle_POLLIN	= NULL }, /* a sansIO role has none */
	/*  2 */ { .handle_POLLOUT	= rops_handle_POLLOUT_raw_proxy },
	/*  3 */ { .adoption_bind	= rops_adoption_bind_raw_proxy },
	/*  4 */ { .client_bind		= rops_client_bind_raw_proxy },
	/*  5 */ { .rx			= rops_rx_raw_proxy },
	/*  6 */ { .rx_policy		= rops_rx_policy_raw_proxy },
	/*  7 */ { .tx_drained		= rops_tx_drained_raw_proxy },
};


const struct lws_role_ops role_ops_raw_proxy = {
	/* role name */			"raw-proxy",
	/* alpn id */			NULL,

	/* rops_table */		rops_table_raw_proxy,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00, 0x00,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00, 0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x00, 0x00,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x02, 0x00,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x00, 0x00,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x00, 0x00,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x00, 0x00,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x00, 0x00,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x00, 0x03,
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x04, 0x00,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x00, 0x05,
	  /* LWS_ROPS_rx_dgram */
	  /* LWS_ROPS_rx_policy */			0x00, 0x06,
	  /* LWS_ROPS_rx_done */			0x00,
	  /* LWS_ROPS_tx */
	  /* LWS_ROPS_tx_sent */			0x00, 0x00,
	  /* LWS_ROPS_tx_drained */			0x07,
					},

	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_RAW_PROXY_CLI_ADOPT,
					  LWS_CALLBACK_RAW_PROXY_SRV_ADOPT },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_RAW_PROXY_CLI_RX,
					  LWS_CALLBACK_RAW_PROXY_SRV_RX },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_RAW_PROXY_CLI_WRITEABLE,
					  LWS_CALLBACK_RAW_PROXY_SRV_WRITEABLE, },
	/* close cb clnt, srv */	{ LWS_CALLBACK_RAW_PROXY_CLI_CLOSE,
					  LWS_CALLBACK_RAW_PROXY_SRV_CLOSE },
	/* protocol_bind cb c, srv */	{ LWS_CALLBACK_RAW_PROXY_CLI_BIND_PROTOCOL,
					  LWS_CALLBACK_RAW_PROXY_SRV_BIND_PROTOCOL },
	/* protocol_unbind cb c, srv */	{ LWS_CALLBACK_RAW_PROXY_CLI_DROP_PROTOCOL,
					  LWS_CALLBACK_RAW_PROXY_SRV_DROP_PROTOCOL },
	/* file_handle */		0,
	/* child_stdio */		0,
};
