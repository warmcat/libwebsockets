/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
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

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "core/private.h"


LWS_EXTERN int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	lws_usec_t timeout_us = timeout_ms * LWS_US_PER_MS;
	struct lws_context_per_thread *pt;
	WSANETWORKEVENTS networkevents;
	struct lws_pollfd *pfd;
	struct lws *wsi;
	unsigned int i;
	DWORD ev;
	int n;
	unsigned int eIdx;
	int interrupt_requested;

	/* stay dead once we are dead */
	if (context == NULL || !context->vhost_list)
		return 1;

	pt = &context->pt[tsi];

	if (!pt->service_tid_detected) {
		struct lws _lws;

		memset(&_lws, 0, sizeof(_lws));
		_lws.context = context;

		pt->service_tid = context->vhost_list->
			protocols[0].callback(&_lws, LWS_CALLBACK_GET_THREAD_ID,
						  NULL, NULL, 0);
		pt->service_tid_detected = 1;
	}

	if (timeout_ms < 0) {
		if (lws_service_flag_pending(context, tsi)) {
			/* any socket with events to service? */
			for (n = 0; n < (int)pt->fds_count; n++) {
				int m;
				if (!pt->fds[n].revents)
					continue;

				m = lws_service_fd_tsi(context, &pt->fds[n], tsi);
				if (m < 0)
					return -1;
				/* if something closed, retry this slot */
				if (m)
					n--;
			}
		}
		return 0;
	}

	if (context->event_loop_ops->run_pt)
		context->event_loop_ops->run_pt(context, tsi);

	for (i = 0; i < pt->fds_count; ++i) {
		pfd = &pt->fds[i];

		if (!(pfd->events & LWS_POLLOUT))
			continue;

		wsi = wsi_from_fd(context, pfd->fd);
		if (!wsi || wsi->listener)
			continue;
		if (wsi->sock_send_blocking)
			continue;
		pfd->revents = LWS_POLLOUT;
		n = lws_service_fd(context, pfd);
		if (n < 0)
			return -1;

		/*
		 * Force WSAWaitForMultipleEvents() to check events
		 * and then return immediately.
		 */
		timeout_ms = 0;

		/* if something closed, retry this slot */
		if (n)
			i--;
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
			timeout_us = 0;
	}

	if (timeout_us) {
		lws_usec_t us;

		lws_pt_lock(pt, __func__);
		/* don't stay in poll wait longer than next hr timeout */
		us = __lws_sul_check(&pt->pt_sul_owner, lws_now_usecs());
		if (us && us < timeout_us)
			timeout_us = us;

		lws_pt_unlock(pt);
	}

	for (n = 0; n < (int)pt->fds_count; n++)
		WSAEventSelect(pt->fds[n].fd, pt->events,
		       FD_READ | (!!(pt->fds[n].events & LWS_POLLOUT) * FD_WRITE) |
		       FD_OOB | FD_ACCEPT |
		       FD_CONNECT | FD_CLOSE | FD_QOS |
		       FD_ROUTING_INTERFACE_CHANGE |
		       FD_ADDRESS_LIST_CHANGE);

	ev = WSAWaitForMultipleEvents(1, &pt->events, FALSE,
				      (DWORD)(timeout_us / LWS_US_PER_MS), FALSE);
	if (ev == WSA_WAIT_EVENT_0) {
		EnterCriticalSection(&pt->interrupt_lock);
		interrupt_requested = pt->interrupt_requested;
		pt->interrupt_requested = 0;
		LeaveCriticalSection(&pt->interrupt_lock);
		if (interrupt_requested) {
			lws_broadcast(pt, LWS_CALLBACK_EVENT_WAIT_CANCELLED,
				      NULL, 0);
			return 0;
		}

#if defined(LWS_WITH_TLS)
		if (pt->context->tls_ops &&
		    pt->context->tls_ops->fake_POLLIN_for_buffered)
			pt->context->tls_ops->fake_POLLIN_for_buffered(pt);
#endif

		for (eIdx = 0; eIdx < pt->fds_count; ++eIdx) {
			unsigned int err;

			if (WSAEnumNetworkEvents(pt->fds[eIdx].fd, pt->events,
					&networkevents) == SOCKET_ERROR) {
				lwsl_err("WSAEnumNetworkEvents() failed "
					 "with error %d\n", LWS_ERRNO);
				return -1;
			}

			if (!networkevents.lNetworkEvents)
				networkevents.lNetworkEvents = LWS_POLLOUT;

			pfd = &pt->fds[eIdx];
			pfd->revents = (short)networkevents.lNetworkEvents;

			err = networkevents.iErrorCode[FD_CONNECT_BIT];

			if ((networkevents.lNetworkEvents & FD_CONNECT) &&
			     err && err != LWS_EALREADY &&
			     err != LWS_EINPROGRESS && err != LWS_EWOULDBLOCK &&
			     err != WSAEINVAL) {
				lwsl_debug("Unable to connect errno=%d\n", err);
				pfd->revents |= LWS_POLLHUP;
			}

			if (pfd->revents & LWS_POLLOUT) {
				wsi = wsi_from_fd(context, pfd->fd);
				if (wsi)
					wsi->sock_send_blocking = 0;
			}
			 /* if something closed, retry this slot */
			if (pfd->revents & LWS_POLLHUP)
				--eIdx;

			if (pfd->revents) {
				recv(pfd->fd, NULL, 0, 0);
				lws_service_fd_tsi(context, pfd, tsi);
			}
		}
	} else if (ev == WSA_WAIT_TIMEOUT) {
		lws_service_fd(context, NULL);
	} else if (ev == WSA_WAIT_FAILED)
		return 0;

	return 0;
}

int
lws_plat_service(struct lws_context *context, int timeout_ms)
{
	return _lws_plat_service_tsi(context, timeout_ms, 0);
}
