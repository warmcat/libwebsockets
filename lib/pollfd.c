/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2015 Andy Green <andy@warmcat.com>
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
_lws_change_pollfd(struct lws *wsi, int _and, int _or, struct lws_pollargs *pa)
{
	struct lws_context_per_thread *pt;
	struct lws_context *context;
	int ret = 0, pa_events = 1;
	struct lws_pollfd *pfd;
	int sampled_tid, tid;

	if (!wsi || wsi->position_in_fds_table < 0)
		return 0;

	context = wsi->context;
	pt = &context->pt[(int)wsi->tsi];
	assert(wsi->position_in_fds_table >= 0 &&
	       wsi->position_in_fds_table < pt->fds_count);

	pfd = &pt->fds[wsi->position_in_fds_table];
	pa->fd = wsi->sock;
	pa->prev_events = pfd->events;
	pa->events = pfd->events = (pfd->events & ~_and) | _or;

	if (context->protocols[0].callback(wsi, LWS_CALLBACK_CHANGE_MODE_POLL_FD,
					   wsi->user_space, (void *)pa, 0)) {
		ret = -1;
		goto bail;
	}

	/*
	 * if we changed something in this pollfd...
	 *   ... and we're running in a different thread context
	 *     than the service thread...
	 *       ... and the service thread is waiting ...
	 *         then cancel it to force a restart with our changed events
	 */
#if LWS_POSIX
	pa_events = pa->prev_events != pa->events;
#endif
	if (pa_events) {

		if (lws_plat_change_pollfd(context, wsi, pfd)) {
			lwsl_info("%s failed\n", __func__);
			ret = -1;
			goto bail;
		}

		sampled_tid = context->service_tid;
		if (sampled_tid) {
			tid = context->protocols[0].callback(wsi,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
			if (tid == -1) {
				ret = -1;
				goto bail;
			}
			if (tid != sampled_tid)
				lws_cancel_service_pt(wsi);
		}
	}
bail:
	return ret;
}

int
insert_wsi_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_pollargs pa = { wsi->sock, LWS_POLLIN, 0 };
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int ret = 0;
#ifndef LWS_NO_SERVER
	struct lws_pollargs pa1;
#endif

	lwsl_debug("%s: %p: tsi=%d, sock=%d, pos-in-fds=%d\n",
		  __func__, wsi, wsi->tsi, wsi->sock, pt->fds_count);

	if ((unsigned int)pt->fds_count >= context->fd_limit_per_thread) {
		lwsl_err("Too many fds (%d)\n", context->max_fds);
		return 1;
	}

#if !defined(_WIN32) && !defined(MBED_OPERATORS)
	if (wsi->sock >= context->max_fds) {
		lwsl_err("Socket fd %d is too high (%d)\n",
			 wsi->sock, context->max_fds);
		return 1;
	}
#endif

	assert(wsi);
	assert(lws_socket_is_valid(wsi->sock));

	if (context->protocols[0].callback(wsi, LWS_CALLBACK_LOCK_POLL,
					   wsi->user_space, (void *) &pa, 1))
		return -1;

	lws_pt_lock(pt);
	pt->count_conns++;
	insert_wsi(context, wsi);
	wsi->position_in_fds_table = pt->fds_count;
	pt->fds[pt->fds_count].fd = wsi->sock;
	pt->fds[pt->fds_count].events = LWS_POLLIN;
	pa.events = pt->fds[pt->fds_count].events;

	lws_plat_insert_socket_into_fds(context, wsi);

	/* external POLL support via protocol 0 */
	if (context->protocols[0].callback(wsi, LWS_CALLBACK_ADD_POLL_FD,
					   wsi->user_space, (void *) &pa, 0))
		ret =  -1;
#ifndef LWS_NO_SERVER
	/* if no more room, defeat accepts on this thread */
	if ((unsigned int)pt->fds_count == context->fd_limit_per_thread - 1)
		_lws_change_pollfd(pt->wsi_listening, LWS_POLLIN, 0, &pa1);
#endif
	lws_pt_unlock(pt);

	if (context->protocols[0].callback(wsi, LWS_CALLBACK_UNLOCK_POLL,
					   wsi->user_space, (void *)&pa, 1))
		ret = -1;

	return ret;
}

int
remove_wsi_socket_from_fds(struct lws *wsi)
{
	struct lws_pollargs pa = { wsi->sock, 0, 0 };
#ifndef LWS_NO_SERVER
	struct lws_pollargs pa1;
#endif
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws *end_wsi;
	int m, ret = 0;

#if !defined(_WIN32) && !defined(MBED_OPERATORS)
	if (wsi->sock > context->max_fds) {
		lwsl_err("fd %d too high (%d)\n", wsi->sock, context->max_fds);
		return 1;
	}
#endif

	if (context->protocols[0].callback(wsi, LWS_CALLBACK_LOCK_POLL,
					   wsi->user_space, (void *)&pa, 1))
		return -1;

	lws_libev_io(wsi, LWS_EV_STOP | LWS_EV_READ | LWS_EV_WRITE);

	lws_pt_lock(pt);

	lwsl_info("%s: wsi=%p, sock=%d, fds pos=%d, end guy pos=%d, endfd=%d\n",
		  __func__, wsi, wsi->sock, wsi->position_in_fds_table,
		  pt->fds_count, pt->fds[pt->fds_count].fd);

	/* the guy who is to be deleted's slot index in pt->fds */
	m = wsi->position_in_fds_table;

	/* have the last guy take up the now vacant slot */
	pt->fds[m] = pt->fds[pt->fds_count - 1];

	lws_plat_delete_socket_from_fds(context, wsi, m);

	/* end guy's "position in fds table" is now the deletion guy's old one */
	end_wsi = wsi_from_fd(context, pt->fds[pt->fds_count].fd);
	assert(end_wsi);
	end_wsi->position_in_fds_table = m;

	/* deletion guy's lws_lookup entry needs nuking */
	delete_from_fd(context, wsi->sock);
	/* removed wsi has no position any more */
	wsi->position_in_fds_table = -1;

	/* remove also from external POLL support via protocol 0 */
	if (lws_socket_is_valid(wsi->sock))
		if (context->protocols[0].callback(wsi, LWS_CALLBACK_DEL_POLL_FD,
						   wsi->user_space, (void *) &pa, 0))
			ret = -1;
#ifndef LWS_NO_SERVER
	/* if this made some room, accept connects on this thread */
	if ((unsigned int)pt->fds_count < context->fd_limit_per_thread - 1)
		_lws_change_pollfd(pt->wsi_listening, 0, LWS_POLLIN, &pa1);
#endif
	lws_pt_unlock(pt);

	if (context->protocols[0].callback(wsi, LWS_CALLBACK_UNLOCK_POLL,
					   wsi->user_space, (void *) &pa, 1))
		ret = -1;

	return ret;
}

int
lws_change_pollfd(struct lws *wsi, int _and, int _or)
{
	struct lws_context_per_thread *pt;
	struct lws_context *context;
	struct lws_pollargs pa;
	int ret = 0;

	if (!wsi || !wsi->protocol || wsi->position_in_fds_table < 0)
		return 1;

	context = lws_get_context(wsi);
	if (!context)
		return 1;

	if (context->protocols[0].callback(wsi, LWS_CALLBACK_LOCK_POLL,
					   wsi->user_space,  (void *) &pa, 0))
		return -1;

	pt = &context->pt[(int)wsi->tsi];

	lws_pt_lock(pt);
	ret = _lws_change_pollfd(wsi, _and, _or, &pa);
	lws_pt_unlock(pt);
	if (context->protocols[0].callback(wsi, LWS_CALLBACK_UNLOCK_POLL,
					   wsi->user_space, (void *) &pa, 0))
		ret = -1;

	return ret;
}


/**
 * lws_callback_on_writable() - Request a callback when this socket
 *					 becomes able to be written to without
 *					 blocking
 *
 * @wsi:	Websocket connection instance to get callback for
 */

LWS_VISIBLE int
lws_callback_on_writable(struct lws *wsi)
{
#ifdef LWS_USE_HTTP2
	struct lws *network_wsi, *wsi2;
	int already;

	lwsl_info("%s: %p\n", __func__, wsi);

	if (wsi->mode != LWSCM_HTTP2_SERVING)
		goto network_sock;

	if (wsi->u.http2.requested_POLLOUT) {
		lwsl_info("already pending writable\n");
		return 1;
	}

	if (wsi->u.http2.tx_credit <= 0) {
		/*
		 * other side is not able to cope with us sending
		 * anything so no matter if we have POLLOUT on our side.
		 *
		 * Delay waiting for our POLLOUT until peer indicates he has
		 * space for more using tx window command in http2 layer
		 */
		lwsl_info("%s: %p: waiting_tx_credit (%d)\n", __func__, wsi,
			  wsi->u.http2.tx_credit);
		wsi->u.http2.waiting_tx_credit = 1;
		return 0;
	}

	network_wsi = lws_http2_get_network_wsi(wsi);
	already = network_wsi->u.http2.requested_POLLOUT;

	/* mark everybody above him as requesting pollout */

	wsi2 = wsi;
	while (wsi2) {
		wsi2->u.http2.requested_POLLOUT = 1;
		lwsl_info("mark %p pending writable\n", wsi2);
		wsi2 = wsi2->u.http2.parent_wsi;
	}

	/* for network action, act only on the network wsi */

	wsi = network_wsi;
	if (already)
		return 1;
network_sock:
#endif

	if (lws_ext_cb_active(wsi, LWS_EXT_CB_REQUEST_ON_WRITEABLE, NULL, 0))
		return 1;

	if (wsi->position_in_fds_table < 0) {
		lwsl_err("%s: failed to find socket %d\n", __func__, wsi->sock);
		return -1;
	}

	if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
		return -1;

	lws_libev_io(wsi, LWS_EV_START | LWS_EV_WRITE);

	return 1;
}

/**
 * lws_callback_on_writable_all_protocol() - Request a callback for
 *			all connections using the given protocol when it
 *			becomes possible to write to each socket without
 *			blocking in turn.
 *
 * @context:	lws_context
 * @protocol:	Protocol whose connections will get callbacks
 */

LWS_VISIBLE int
lws_callback_on_writable_all_protocol(const struct lws_context *context,
				      const struct lws_protocols *protocol)
{
	const struct lws_context_per_thread *pt = &context->pt[0];
	unsigned int n, m = context->count_threads;
	struct lws *wsi;

	while (m--) {
		for (n = 0; n < pt->fds_count; n++) {
			wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->protocol == protocol)
				lws_callback_on_writable(wsi);
		}
		pt++;
	}

	return 0;
}
