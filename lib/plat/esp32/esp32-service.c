/*
 * libwebsockets - lib/plat/lws-plat-esp32.c
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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

#include "core/private.h"

int
lws_plat_service(struct lws_context *context, int timeout_ms)
{
	int n = _lws_plat_service_tsi(context, timeout_ms, 0);

	lws_service_fd_tsi(context, NULL, 0);
	esp_task_wdt_reset();

	return n;
}


LWS_EXTERN int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt;
	int n = -1, m, c;

	/* stay dead once we are dead */

	if (!context || !context->vhost_list)
		return 1;

	pt = &context->pt[tsi];
	lws_stats_atomic_bump(context, pt, LWSSTATS_C_SERVICE_ENTRY, 1);

	{
		unsigned long m = lws_now_secs();

		if (m > context->time_last_state_dump) {
			context->time_last_state_dump = m;
			n = esp_get_free_heap_size();
			if (n != context->last_free_heap) {
				if (n > context->last_free_heap)
					lwsl_notice(" heap :%d (+%d)\n", n,
						    n - context->last_free_heap);
				else
					lwsl_notice(" heap :%d (-%d)\n", n,
						    context->last_free_heap - n);
				context->last_free_heap = n;
			}
		}
	}

	if (timeout_ms < 0)
		goto faked_service;

	if (!pt->service_tid_detected) {
		struct lws *_lws = lws_zalloc(sizeof(*_lws), "tid probe");

		_lws->context = context;

		pt->service_tid = context->vhost_list->protocols[0].callback(
			_lws, LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
		pt->service_tid_detected = 1;
		lws_free(_lws);
	}

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!lws_service_adjust_timeout(context, 1, tsi)) {
		/* -1 timeout means just do forced service */
		_lws_plat_service_tsi(context, -1, pt->tid);
		/* still somebody left who wants forced service? */
		if (!lws_service_adjust_timeout(context, 1, pt->tid))
			/* yes... come back again quickly */
			timeout_ms = 0;
	}

	if (timeout_ms) {
		lws_pt_lock(pt, __func__);
		/* don't stay in poll wait longer than next hr timeout */
		lws_usec_t t =  __lws_hrtimer_service(pt);

		if ((lws_usec_t)timeout_ms * 1000 > t)
			timeout_ms = t / 1000;
		lws_pt_unlock(pt);
	}

//	n = poll(pt->fds, pt->fds_count, timeout_ms);
	{
		fd_set readfds, writefds, errfds;
		struct timeval tv = { timeout_ms / 1000,
				      (timeout_ms % 1000) * 1000 }, *ptv = &tv;
		int max_fd = 0;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&errfds);

		for (n = 0; n < pt->fds_count; n++) {
			pt->fds[n].revents = 0;
			if (pt->fds[n].fd >= max_fd)
				max_fd = pt->fds[n].fd;
			if (pt->fds[n].events & LWS_POLLIN)
				FD_SET(pt->fds[n].fd, &readfds);
			if (pt->fds[n].events & LWS_POLLOUT)
				FD_SET(pt->fds[n].fd, &writefds);
			FD_SET(pt->fds[n].fd, &errfds);
		}

		n = select(max_fd + 1, &readfds, &writefds, &errfds, ptv);
		n = 0;
		for (m = 0; m < pt->fds_count; m++) {
			c = 0;
			if (FD_ISSET(pt->fds[m].fd, &readfds)) {
				pt->fds[m].revents |= LWS_POLLIN;
				c = 1;
			}
			if (FD_ISSET(pt->fds[m].fd, &writefds)) {
				pt->fds[m].revents |= LWS_POLLOUT;
				c = 1;
			}
			if (FD_ISSET(pt->fds[m].fd, &errfds)) {
				// lwsl_notice("errfds %d\n", pt->fds[m].fd);
				pt->fds[m].revents |= LWS_POLLHUP;
				c = 1;
			}

			if (c)
				n++;
		}
	}

	m = 0;

#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	m |= !!pt->ws.rx_draining_ext_list;
#endif

	if (pt->context->tls_ops &&
	    pt->context->tls_ops->fake_POLLIN_for_buffered)
		m |= pt->context->tls_ops->fake_POLLIN_for_buffered(pt);

	if (!m && !n) {
		lws_service_fd_tsi(context, NULL, tsi);
		return 0;
	}


faked_service:
	m = lws_service_flag_pending(context, tsi);
	if (m)
		c = -1; /* unknown limit */
	else
		if (n < 0) {
			if (LWS_ERRNO != LWS_EINTR)
				return -1;
			return 0;
		} else
			c = n;

	/* any socket with events to service? */
	for (n = 0; n < pt->fds_count && c; n++) {
		if (!pt->fds[n].revents)
			continue;

		c--;

		m = lws_service_fd_tsi(context, &pt->fds[n], tsi);
		if (m < 0)
			return -1;
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

	return 0;
}


void
lws_plat_service_periodic(struct lws_context *context)
{
}

