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

#if !defined(LWS_AMAZON_RTOS)
	esp_task_wdt_reset();
#endif

	return n;
}


LWS_EXTERN int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt;
	lws_usec_t timeout_us;
	int n = -1, m, c, a = 0;

	/* stay dead once we are dead */

	if (!context || !context->vhost_list)
		return 1;

	pt = &context->pt[tsi];
	lws_stats_bump(pt, LWSSTATS_C_SERVICE_ENTRY, 1);

	{
		unsigned long m = lws_now_secs();

		if (m > context->time_last_state_dump) {
			context->time_last_state_dump = m;
#if defined(LWS_AMAZON_RTOS)
			n = xPortGetFreeHeapSize();
#else
			n = esp_get_free_heap_size();
#endif
			if ((unsigned int)n != context->last_free_heap) {
				if ((unsigned int)n > context->last_free_heap)
					lwsl_notice(" heap :%ld (+%ld)\n",
						    (unsigned long)n,
						    (unsigned long)(n -
						      context->last_free_heap));
				else
					lwsl_notice(" heap :%ld (-%ld)\n",
						    (unsigned long)n,
						    (unsigned long)(
						      context->last_free_heap -
						      n));
				context->last_free_heap = n;
			}
		}
	}

	if (timeout_ms < 0)
		timeout_ms = 0;
	else
		/* force a default timeout of 23 days */
		timeout_ms = 2000000000;
	timeout_us = ((lws_usec_t)timeout_ms) * LWS_US_PER_MS;

	if (!pt->service_tid_detected) {
		struct lws *_lws = lws_zalloc(sizeof(*_lws), "tid probe");

		if (!_lws)
			return 1;
		_lws->context = context;

		pt->service_tid = context->vhost_list->protocols[0].callback(
			_lws, LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
		pt->service_tid_detected = 1;
		lws_free(_lws);
	}

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (lws_service_adjust_timeout(context, 1, tsi)) {

again:
		a = 0;
		if (timeout_us) {
			lws_usec_t us;

			lws_pt_lock(pt, __func__);
			/* don't stay in poll wait longer than next hr timeout */
			us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
			if (us && us < timeout_us)
				timeout_us = us;

			lws_pt_unlock(pt);
		}

	//	n = poll(pt->fds, pt->fds_count, timeout_ms);
		{
			fd_set readfds, writefds, errfds;
			struct timeval tv = { timeout_us / LWS_US_PER_SEC,
					      timeout_us % LWS_US_PER_SEC }, *ptv = &tv;
			int max_fd = 0;
			FD_ZERO(&readfds);
			FD_ZERO(&writefds);
			FD_ZERO(&errfds);

			for (n = 0; n < (int)pt->fds_count; n++) {
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

	#if defined(LWS_WITH_DETAILED_LATENCY)
			/*
			 * so we can track how long it took before we actually read a POLLIN
			 * that was signalled when we last exited poll()
			 */
			if (context->detailed_latency_cb)
				pt->ust_left_poll = lws_now_usecs();
	#endif

			for (m = 0; m < (int)pt->fds_count; m++) {
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

		if (!m && !n)
			return 0;
	} else
		a = 1;

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
	for (n = 0; n < (int)pt->fds_count && c; n++) {
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

	if (a)
		goto again;

	return 0;
}
