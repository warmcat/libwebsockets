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
rops_handle_POLLIN_raw_skt(struct lws_context_per_thread *pt, struct lws *wsi,
			   struct lws_pollfd *pollfd)
{
	int len, n;

	/* pending truncated sends have uber priority */

	if (wsi->trunc_len) {
		if (!(pollfd->revents & LWS_POLLOUT))
			return LWS_HPI_RET_HANDLED;

		if (lws_issue_raw(wsi, wsi->trunc_alloc + wsi->trunc_offset,
				  wsi->trunc_len) < 0)
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

		len = lws_read_or_use_preamble(pt, wsi);
		if (len < 0)
			goto fail;

		if (!len)
			goto try_pollout;

		n = user_callback_handle_rxflow(wsi->protocol->callback,
						wsi, LWS_CALLBACK_RAW_RX,
						wsi->user_space, pt->serv_buf,
						len);
		if (n < 0) {
			lwsl_info("LWS_CALLBACK_RAW_RX_fail\n");
			goto fail;
		}
	} else
		if (wsi->favoured_pollin &&
		    (pollfd->revents & pollfd->events & LWS_POLLOUT))
			/* we balanced the last favouring of pollin */
			wsi->favoured_pollin = 0;

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
			wsi, LWS_CALLBACK_RAW_WRITEABLE,
			wsi->user_space, NULL, 0);
	if (n < 0) {
		lwsl_info("writeable_fail\n");
		goto fail;
	}

	return LWS_HPI_RET_HANDLED;

fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "raw svc fail");

	return LWS_HPI_RET_CLOSE_HANDLED;
}


static int
rops_handle_POLLIN_raw_file(struct lws_context_per_thread *pt, struct lws *wsi,
			    struct lws_pollfd *pollfd)
{
	int n;

	if (pollfd->revents & LWS_POLLOUT) {
		n = lws_callback_as_writeable(wsi);
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_info("failed at set pollfd\n");
			return LWS_HPI_RET_DIE;
		}
		if (n)
			return LWS_HPI_RET_CLOSE_HANDLED;
	}

	if (pollfd->revents & LWS_POLLIN) {
		if (user_callback_handle_rxflow(wsi->protocol->callback,
						wsi, LWS_CALLBACK_RAW_RX_FILE,
						wsi->user_space, NULL, 0)) {
			lwsl_debug("raw rx callback closed it\n");
			return LWS_HPI_RET_CLOSE_HANDLED;
		}
	}

	if (pollfd->revents & LWS_POLLHUP)
		return LWS_HPI_RET_CLOSE_HANDLED;

	return LWS_HPI_RET_HANDLED;
}


struct lws_role_ops role_ops_raw_skt = {
	/* role name */			"raw-skt",
	/* alpn id */			NULL,
	/* check_upgrades */		NULL,
	/* init_context */		NULL,
	/* init_vhost */		NULL,
	/* periodic_checks */		NULL,
	/* service_flag_pending */	NULL,
	/* handle_POLLIN */		rops_handle_POLLIN_raw_skt,
	/* handle_POLLOUT */		NULL,
	/* perform_user_POLLOUT */	NULL,
	/* callback_on_writable */	NULL,
	/* tx_credit */			NULL,
	/* write_role_protocol */	NULL,
	/* rxflow_cache */		NULL,
	/* encapsulation_parent */	NULL,
	/* alpn_negotiated */		NULL,
	/* close_via_role_protocol */	NULL,
	/* close_role */		NULL,
	/* close_kill_connection */	NULL,
	/* destroy_role */		NULL,
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_RAW_WRITEABLE, 0 },
	/* close cb clnt, srv */	{ LWS_CALLBACK_RAW_CLOSE, 0 },
};



struct lws_role_ops role_ops_raw_file = {
	/* role name */			"raw-file",
	/* alpn id */			NULL,
	/* check_upgrades */		NULL,
	/* init_context */		NULL,
	/* init_vhost */		NULL,
	/* periodic_checks */		NULL,
	/* service_flag_pending */	NULL,
	/* handle_POLLIN */		rops_handle_POLLIN_raw_file,
	/* handle_POLLOUT */		NULL,
	/* perform_user_POLLOUT */	NULL,
	/* callback_on_writable */	NULL,
	/* tx_credit */			NULL,
	/* write_role_protocol */	NULL,
	/* rxflow_cache */		NULL,
	/* encapsulation_parent */	NULL,
	/* alpn_negotiated */		NULL,
	/* close_via_role_protocol */	NULL,
	/* close_role */		NULL,
	/* close_kill_connection */	NULL,
	/* destroy_role */		NULL,
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_RAW_WRITEABLE_FILE, 0 },
	/* close cb clnt, srv */	{ LWS_CALLBACK_RAW_CLOSE_FILE, 0 },
};
