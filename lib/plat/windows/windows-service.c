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

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "private-lib-core.h"


int
_lws_plat_service_forced_tsi(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	int m, n, r;

	r = lws_service_flag_pending(context, tsi);

	/* any socket with events to service? */
	for (n = 0; n < (int)pt->fds_count; n++) {
		if (!pt->fds[n].revents)
			continue;

		m = lws_service_fd_tsi(context, &pt->fds[n], tsi);
		if (m < 0)
			return -1;
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

	lws_service_do_ripe_rxflow(pt);

	return r;
}

extern void lws_client_conn_wait_timeout(lws_sorted_usec_list_t *sul);

int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt;
	WSANETWORKEVENTS networkevents;
	struct lws_pollfd *pfd;
	lws_usec_t timeout_us;
	struct lws *wsi;
	unsigned int i;
	DWORD ev;
	int n;

	/* stay dead once we are dead */
	if (context == NULL)
		return 1;

	pt = &context->pt[tsi];

	if (!pt->service_tid_detected && context->vhost_list) {
		lws_fakewsi_def_plwsa(pt);

		lws_fakewsi_prep_plwsa_ctx(context);

		pt->service_tid = context->vhost_list->
			protocols[0].callback((struct lws *)plwsa,
					LWS_CALLBACK_GET_THREAD_ID,
						  NULL, NULL, 0);
		pt->service_tid_detected = 1;
	}

	if (timeout_ms < 0)
		timeout_ms = 0;
	else
		/* force a default timeout of 23 days */
		timeout_ms = 2000000000;
	timeout_us = ((lws_usec_t)timeout_ms) * LWS_US_PER_MS;

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
		timeout_us = 0;

		/* if something closed, retry this slot */
		if (n)
			i--;
	}

	/*
	 * service pending callbacks and get maximum wait time
	 */
	{
		lws_usec_t us;

		lws_pt_lock(pt, __func__);
		/* don't stay in poll wait longer than next hr timeout */
		us = __lws_sul_service_ripe(pt->pt_sul_owner,
					    LWS_COUNT_PT_SUL_OWNERS,
					    lws_now_usecs());
		if (us && us < timeout_us)
			timeout_us = us;

		lws_pt_unlock(pt);
	}

	if (_lws_plat_service_forced_tsi(context, tsi))
		timeout_us = 0;

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */

	if (!lws_service_adjust_timeout(context, 1, tsi))
		timeout_us = 0;

	/*
	 * WSA cannot actually tell us this from the wait... if anyone wants
	 * POLLOUT and is not blocked for it, no need to wait since we will want
	 * to service at least those.   Still enter the wait so we can pick up
	 * other pending things...
	 */

	for (n = 0; n < (int)pt->fds_count; n++)
		if (pt->fds[n].fd != LWS_SOCK_INVALID &&
		    pt->fds[n].events & LWS_POLLOUT &&
		    !pt->fds[n].write_blocked) {
			timeout_us = 0;
			break;
		}

	// lwsl_notice("%s: to %dms\n", __func__, (int)(timeout_us / 1000));
	ev = WSAWaitForMultipleEvents(pt->fds_count + 1, pt->events, FALSE,
				      (DWORD)(timeout_us / LWS_US_PER_MS),
				      FALSE);
	//lwsl_notice("%s: ev 0x%x\n", __func__, ev);

	/*
	 * The wait returns indicating the one event that had something, or
	 * that we timed out, or something broken.
	 *
	 * Amazingly WSA can only handle 64 events, because the errors start
	 * at ordinal 64.
	 */

	if (ev >= WSA_MAXIMUM_WAIT_EVENTS &&
	    ev != WSA_WAIT_TIMEOUT)
		/* some kind of error */
		return 0;

       if (!ev) {
	       /*
	        * The zero'th event is the cancel event specifically.  Lock
	        * the event reset so we are definitely clearing it while we
	        * try to clear it.
	        */
		EnterCriticalSection(&pt->interrupt_lock);
		WSAResetEvent(pt->events[0]);
		LeaveCriticalSection(&pt->interrupt_lock);
		lws_broadcast(pt, LWS_CALLBACK_EVENT_WAIT_CANCELLED, NULL, 0);

		return 0;
	}

       /*
        * Otherwise at least fds[ev - 1] has something to do...
        */

#if defined(LWS_WITH_TLS)
	if (pt->context->tls_ops &&
	    pt->context->tls_ops->fake_POLLIN_for_buffered)
		pt->context->tls_ops->fake_POLLIN_for_buffered(pt);
#endif

	/*
	 * POLLOUT for any fds that can
	 */

	for (n = 0; n < (int)pt->fds_count; n++)
		if (pt->fds[n].fd != LWS_SOCK_INVALID &&
		    pt->fds[n].events & LWS_POLLOUT &&
		    !pt->fds[n].write_blocked) {
			struct timeval tv;
			fd_set se;

			/*
			 * We have to check if it is blocked...
			 * if not, do the POLLOUT handling
			 */

			FD_ZERO(&se);
			FD_SET(pt->fds[n].fd, &se);
			tv.tv_sec = tv.tv_usec = 0;
			if (select(1, NULL, &se, NULL, &tv) != 1)
				pt->fds[n].write_blocked = 1;
			else {
				pt->fds[n].revents |= LWS_POLLOUT;
				lws_service_fd_tsi(context, &pt->fds[n], tsi);
			}
		}

       if (ev && ev < WSA_MAXIMUM_WAIT_EVENTS) {
		unsigned int err;

		/* handle fds[ev - 1] */

               if (WSAEnumNetworkEvents(pt->fds[ev - 1].fd, pt->events[ev],
				&networkevents) == SOCKET_ERROR) {
			lwsl_err("WSAEnumNetworkEvents() failed "
				 "with error %d\n", LWS_ERRNO);
			return -1;
		}

		pfd = &pt->fds[ev - 1];
		pfd->revents = (short)networkevents.lNetworkEvents;

	        if (!pfd->write_blocked && pfd->revents & FD_WRITE)
	        	 pfd->write_blocked = 0;

		err = networkevents.iErrorCode[FD_CONNECT_BIT];
		if ((networkevents.lNetworkEvents & FD_CONNECT) &&
		    wsi_from_fd(context, pfd->fd) &&
		    !wsi_from_fd(context, pfd->fd)->udp) {
                       lwsl_debug("%s: FD_CONNECT: %p\n", __func__,
                		  wsi_from_fd(context, pfd->fd));
			pfd->revents &= ~LWS_POLLOUT;
			if (err && err != LWS_EALREADY &&
			    err != LWS_EINPROGRESS &&
			    err != LWS_EWOULDBLOCK &&
			    err != WSAEINVAL) {
				lwsl_debug("Unable to connect errno=%d\n", err);

				/*
				 * the connection has definitively failed... but
				 * do we have more DNS entries to try?
				 */
				if (wsi_from_fd(context, pfd->fd)->dns_results_next) {
					lws_sul_schedule(context, 0,
						&wsi_from_fd(context, pfd->fd)->
							sul_connect_timeout,
						lws_client_conn_wait_timeout, 1);
                                       return 0;
                               } else
					pfd->revents |= LWS_POLLHUP;
			} else
                               if (wsi_from_fd(context, pfd->fd)) {
                                       if (wsi_from_fd(context, pfd->fd)->udp)
                                               pfd->revents |= LWS_POLLHUP;
                                       else
                                               lws_client_connect_3_connect(
                                        	  wsi_from_fd(context, pfd->fd),
						  NULL, NULL,
						  LWS_CONNECT_COMPLETION_GOOD,
						  NULL);
                               }
		}

		if (pfd->revents & LWS_POLLOUT) {
			wsi = wsi_from_fd(context, pfd->fd);
			if (wsi)
				wsi->sock_send_blocking = 0;
		}

		if (pfd->revents) {
			/*
			 * On windows is somehow necessary to "acknowledge" the
			 * POLLIN event, otherwise we never receive another one
			 * on the TCP connection.  But it breaks UDP, so only
			 * do it on non-UDP.
			 */
			wsi = wsi_from_fd(context, pfd->fd);
			if (wsi && !wsi->udp)
				recv(pfd->fd, NULL, 0, 0);

			lws_service_fd_tsi(context, pfd, tsi);
		}
	}

	return 0;
}

int
lws_plat_service(struct lws_context *context, int timeout_ms)
{
	return _lws_plat_service_tsi(context, timeout_ms, 0);
}
