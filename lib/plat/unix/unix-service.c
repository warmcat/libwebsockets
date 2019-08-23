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

#define _GNU_SOURCE
#include "private-lib-core.h"

int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
	return poll(fd, 1, 0);
}

LWS_EXTERN int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	volatile struct lws_foreign_thread_pollfd *ftp, *next;
	volatile struct lws_context_per_thread *vpt;
	struct lws_context_per_thread *pt;
	lws_usec_t timeout_us;
	int n = -1, m, c;

	/* stay dead once we are dead */

	if (!context || !context->vhost_list)
		return 1;

	pt = &context->pt[tsi];
	vpt = (volatile struct lws_context_per_thread *)pt;

	lws_stats_bump(pt, LWSSTATS_C_SERVICE_ENTRY, 1);

	if (timeout_ms < 0)
		goto faked_service;

	/* force a default timeout of 23 days */
	timeout_ms = 2000000000;
	timeout_us = ((lws_usec_t)timeout_ms) * LWS_US_PER_MS;

	if (context->event_loop_ops->run_pt)
		context->event_loop_ops->run_pt(context, tsi);

	if (!pt->service_tid_detected) {
		struct lws _lws;

		memset(&_lws, 0, sizeof(_lws));
		_lws.context = context;

		pt->service_tid = context->vhost_list->protocols[0].callback(
					&_lws, LWS_CALLBACK_GET_THREAD_ID,
					NULL, NULL, 0);
		pt->service_tid_detected = 1;
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

	vpt->inside_poll = 1;
	lws_memory_barrier();
	n = poll(pt->fds, pt->fds_count, timeout_us / LWS_US_PER_MS);
	vpt->inside_poll = 0;
	lws_memory_barrier();

#if defined(LWS_WITH_DETAILED_LATENCY)
	/*
	 * so we can track how long it took before we actually read a POLLIN
	 * that was signalled when we last exited poll()
	 */
	if (context->detailed_latency_cb)
		pt->ust_left_poll = lws_now_usecs();
#endif

	/* Collision will be rare and brief.  Just spin until it completes */
	while (vpt->foreign_spinlock)
		;

	/*
	 * At this point we are not inside a foreign thread pollfd change,
	 * and we have marked ourselves as outside the poll() wait.  So we
	 * are the only guys that can modify the lws_foreign_thread_pollfd
	 * list on the pt.  Drain the list and apply the changes to the
	 * affected pollfds in the correct order.
	 */

	lws_pt_lock(pt, __func__);

	ftp = vpt->foreign_pfd_list;
	//lwsl_notice("cleared list %p\n", ftp);
	while (ftp) {
		struct lws *wsi;
		struct lws_pollfd *pfd;

		next = ftp->next;
		pfd = &vpt->fds[ftp->fd_index];
		if (lws_socket_is_valid(pfd->fd)) {
			wsi = wsi_from_fd(context, pfd->fd);
			if (wsi)
				__lws_change_pollfd(wsi, ftp->_and, ftp->_or);
		}
		lws_free((void *)ftp);
		ftp = next;
	}
	vpt->foreign_pfd_list = NULL;
	lws_memory_barrier();

	lws_pt_unlock(pt);

	m = 0;
#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	m |= !!pt->ws.rx_draining_ext_list;
#endif

#if defined(LWS_WITH_TLS)
	if (pt->context->tls_ops &&
	    pt->context->tls_ops->fake_POLLIN_for_buffered)
		m |= pt->context->tls_ops->fake_POLLIN_for_buffered(pt);
#endif

	if (
#if (defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)) || defined(LWS_WITH_TLS)
		!m &&
#endif
		!n) { /* nothing to do */
		lws_service_do_ripe_rxflow(pt);

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
	for (n = 0; n < (int)pt->fds_count && c; n++) {
		if (!pt->fds[n].revents)
			continue;

		c--;

		m = lws_service_fd_tsi(context, &pt->fds[n], tsi);
		if (m < 0) {
			lwsl_err("%s: lws_service_fd_tsi returned %d\n",
				 __func__, m);
			return -1;
		}
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

	lws_service_do_ripe_rxflow(pt);

	return 0;
}

int
lws_plat_check_connection_error(struct lws *wsi)
{
	return 0;
}

int
lws_plat_service(struct lws_context *context, int timeout_ms)
{
	return _lws_plat_service_tsi(context, timeout_ms, 0);
}
