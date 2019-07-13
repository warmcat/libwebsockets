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

#include <core/private.h>

static int
rops_handle_POLLIN_raw_proxy(struct lws_context_per_thread *pt, struct lws *wsi,
			     struct lws_pollfd *pollfd)
{
	struct lws_tokens ebuf;
	int n, buffered;

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

	if ((pollfd->revents & pollfd->events & LWS_POLLIN) &&
	    /* any tunnel has to have been established... */
	    lwsi_state(wsi) != LRS_SSL_ACK_PENDING &&
	    !(wsi->favoured_pollin &&
	      (pollfd->revents & pollfd->events & LWS_POLLOUT))) {

		buffered = lws_buflist_aware_read(pt, wsi, &ebuf);
		switch (ebuf.len) {
		case 0:
			lwsl_info("%s: read 0 len\n", __func__);
			wsi->seen_zero_length_recv = 1;
			if (lws_change_pollfd(wsi, LWS_POLLIN, 0))
				goto fail;

			/*
			 * we need to go to fail here, since it's the only
			 * chance we get to understand that the socket has
			 * closed
			 */
			// goto try_pollout;
			goto fail;

		case LWS_SSL_CAPABLE_ERROR:
			goto fail;
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			goto try_pollout;
		}
		n = user_callback_handle_rxflow(wsi->protocol->callback,
						wsi, lwsi_role_client(wsi) ?
						 LWS_CALLBACK_RAW_PROXY_CLI_RX :
						 LWS_CALLBACK_RAW_PROXY_SRV_RX,
						wsi->user_space, ebuf.token,
						ebuf.len);
		if (n < 0) {
			lwsl_info("LWS_CALLBACK_RAW_PROXY_*_RX fail\n");
			goto fail;
		}

		if (lws_buflist_aware_consume(wsi, &ebuf, ebuf.len, buffered))
			return LWS_HPI_RET_PLEASE_CLOSE_ME;
	} else
		if (wsi->favoured_pollin &&
		    (pollfd->revents & pollfd->events & LWS_POLLOUT))
			/* we balanced the last favouring of pollin */
			wsi->favoured_pollin = 0;

try_pollout:

	if (!(pollfd->revents & LWS_POLLOUT))
		return LWS_HPI_RET_HANDLED;

	if (lws_handle_POLLOUT_event(wsi, pollfd)) {
		lwsl_debug("POLLOUT event closed it\n");
		return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

#if !defined(LWS_NO_CLIENT)
	if (lws_client_socket_service(wsi, pollfd, NULL))
		return LWS_HPI_RET_WSI_ALREADY_DIED;
#endif

	return LWS_HPI_RET_HANDLED;

fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "raw svc fail");

	return LWS_HPI_RET_WSI_ALREADY_DIED;
}

static int
rops_adoption_bind_raw_proxy(struct lws *wsi, int type,
			     const char *vh_prot_name)
{
	/* no http but socket... must be raw skt */
	if ((type & LWS_ADOPT_HTTP) || !(type & LWS_ADOPT_SOCKET) ||
	    (!(type & LWS_ADOPT_FLAG_RAW_PROXY)) || (type & _LWS_ADOPT_FINISH))
		return 0; /* no match */

	if (type & LWS_ADOPT_FLAG_UDP)
		/*
		 * these can be >128 bytes, so just alloc for UDP
		 */
		wsi->udp = lws_malloc(sizeof(*wsi->udp), "udp struct");

	lws_role_transition(wsi, LWSIFR_SERVER, (type & LWS_ADOPT_ALLOW_SSL) ?
				    LRS_SSL_INIT : LRS_ESTABLISHED,
			    &role_ops_raw_proxy);

	if (vh_prot_name)
		lws_bind_protocol(wsi, wsi->protocol, __func__);
	else
		/* this is the only time he will transition */
		lws_bind_protocol(wsi,
			&wsi->vhost->protocols[wsi->vhost->raw_protocol_index],
			__func__);

	return 1; /* bound */
}

static int
rops_client_bind_raw_proxy(struct lws *wsi,
			   const struct lws_client_connect_info *i)
{
	if (!i) {

		/* finalize */

		if (!wsi->user_space && wsi->stash->method)
			if (lws_ensure_user_space(wsi))
				return 1;

		return 0;
	}

	/* we are a fallback if nothing else matched */

//	lws_role_transition(wsi, LWSIFR_CLIENT, LRS_UNCONNECTED,
//			    &role_ops_raw_proxy);

	return 0;
}

static int
rops_handle_POLLOUT_raw_proxy(struct lws *wsi)
{
	if (lwsi_state(wsi) == LRS_ESTABLISHED)
		return LWS_HP_RET_USER_SERVICE;

	if (lwsi_role_client(wsi))
		return LWS_HP_RET_USER_SERVICE;

	return LWS_HP_RET_BAIL_OK;
}

struct lws_role_ops role_ops_raw_proxy = {
	/* role name */			"raw-proxy",
	/* alpn id */			NULL,
	/* check_upgrades */		NULL,
	/* init_context */		NULL,
	/* init_vhost */		NULL,
	/* destroy_vhost */		NULL,
	/* periodic_checks */		NULL,
	/* service_flag_pending */	NULL,
	/* handle_POLLIN */		rops_handle_POLLIN_raw_proxy,
	/* handle_POLLOUT */		rops_handle_POLLOUT_raw_proxy,
	/* perform_user_POLLOUT */	NULL,
	/* callback_on_writable */	NULL,
	/* tx_credit */			NULL,
	/* write_role_protocol */	NULL,
	/* encapsulation_parent */	NULL,
	/* alpn_negotiated */		NULL,
	/* close_via_role_protocol */	NULL,
	/* close_role */		NULL,
	/* close_kill_connection */	NULL,
	/* destroy_role */		NULL,
	/* adoption_bind */		rops_adoption_bind_raw_proxy,
	/* client_bind */		rops_client_bind_raw_proxy,
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
};
