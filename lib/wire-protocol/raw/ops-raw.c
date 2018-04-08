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
wops_handle_POLLIN_raw(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_pollfd *pollfd)
{
	int len, n;

	switch (lwsi_role(wsi)) {
	case LWSI_ROLE_RAW_SOCKET:
		/* pending truncated sends have uber priority */

		if (wsi->trunc_len) {
			if (!(pollfd->revents & LWS_POLLOUT))
				break;

			if (lws_issue_raw(wsi, wsi->trunc_alloc +
					       wsi->trunc_offset,
					  wsi->trunc_len) < 0)
				goto fail;
			/*
			 * we can't afford to allow input processing to send
			 * something new, so spin around he event loop until
			 * he doesn't have any partials
			 */
			break;
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
							wsi->user_space,
							pt->serv_buf, len);
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

	case LWSI_ROLE_RAW_FILE:

		if (pollfd->revents & LWS_POLLOUT) {
			n = lws_calllback_as_writeable(wsi);
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				lwsl_info("failed at set pollfd\n");
				return LWS_HPI_RET_DIE;
			}
			if (n)
				return LWS_HPI_RET_CLOSE_HANDLED;
		}
		n = LWS_CALLBACK_RAW_RX;
		if (lwsi_role(wsi) == LWSI_ROLE_RAW_FILE)
			n = LWS_CALLBACK_RAW_RX_FILE;

		if (pollfd->revents & LWS_POLLIN) {
			if (user_callback_handle_rxflow(
					wsi->protocol->callback,
					wsi, n, wsi->user_space, NULL, 0)) {
				lwsl_debug("raw rx callback closed it\n");
				return LWS_HPI_RET_CLOSE_HANDLED;
			}
		}

		if (pollfd->revents & LWS_POLLHUP)
			return LWS_HPI_RET_CLOSE_HANDLED;

		break;

	default:
		assert(0);
	}

	return LWS_HPI_RET_HANDLED;

fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "raw svc fail");

	return LWS_HPI_RET_CLOSE_HANDLED;
}

int wops_handle_POLLOUT_raw(struct lws *wsi)
{
	return LWS_HP_RET_USER_SERVICE;
}

struct lws_protocol_ops wire_ops_raw = {
	"raw",
	wops_handle_POLLIN_raw,
	wops_handle_POLLOUT_raw
};
