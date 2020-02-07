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

#include "private-lib-core.h"

static void
lws_event_hrtimer_cb(int fd, short event, void *p)
{
	struct lws_context_per_thread *pt = (struct lws_context_per_thread *)p;
	struct timeval tv;
	lws_usec_t us;

	lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
	if (us) {
		tv.tv_sec = us / LWS_US_PER_SEC;
		tv.tv_usec = us - (tv.tv_sec * LWS_US_PER_SEC);
		evtimer_add(pt->event.hrtimer, &tv);
	}
	lws_pt_unlock(pt);
}

static void
lws_event_idle_timer_cb(int fd, short event, void *p)
{
	struct lws_context_per_thread *pt = (struct lws_context_per_thread *)p;
	struct timeval tv;
	lws_usec_t us;

	if (pt->is_destroyed)
		return;

	lws_service_do_ripe_rxflow(pt);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
		/* -1 timeout means just do forced service */
		_lws_plat_service_forced_tsi(pt->context, pt->tid);
		/* still somebody left who wants forced service? */
		if (!lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
			/* yes... come back again later */

			tv.tv_sec = 0;
			tv.tv_usec = 1000;
			evtimer_add(pt->event.idle_timer, &tv);

			return;
		}
	}

	lwsl_debug("%s: wait\n", __func__);

	/* account for hrtimer */

	lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
	if (us) {
		tv.tv_sec = us / LWS_US_PER_SEC;
		tv.tv_usec = us - (tv.tv_sec * LWS_US_PER_SEC);
		evtimer_add(pt->event.hrtimer, &tv);
	}
	lws_pt_unlock(pt);


	if (pt->destroy_self)
		lws_context_destroy(pt->context);
}

static void
lws_event_cb(evutil_socket_t sock_fd, short revents, void *ctx)
{
	struct lws_io_watcher *lws_io = (struct lws_io_watcher *)ctx;
	struct lws_context *context = lws_io->context;
	struct lws_context_per_thread *pt;
	struct lws_pollfd eventfd;
	struct timeval tv;
	struct lws *wsi;

	if (revents & EV_TIMEOUT)
		return;

	/* !!! EV_CLOSED doesn't exist in libevent2 */
#if LIBEVENT_VERSION_NUMBER < 0x02000000
	if (revents & EV_CLOSED) {
		event_del(lws_io->event.watcher);
		event_free(lws_io->event.watcher);
		return;
	}
#endif

	eventfd.fd = sock_fd;
	eventfd.events = 0;
	eventfd.revents = 0;
	if (revents & EV_READ) {
		eventfd.events |= LWS_POLLIN;
		eventfd.revents |= LWS_POLLIN;
	}
	if (revents & EV_WRITE) {
		eventfd.events |= LWS_POLLOUT;
		eventfd.revents |= LWS_POLLOUT;
	}

	wsi = wsi_from_fd(context, sock_fd);
	if (!wsi)
		return;

	pt = &context->pt[(int)wsi->tsi];
	if (pt->is_destroyed)
		return;

	lws_service_fd_tsi(context, &eventfd, wsi->tsi);

	if (pt->destroy_self) {
		lws_context_destroy(pt->context);
		return;
	}

	/* set the idle timer for 1ms ahead */

	tv.tv_sec = 0;
	tv.tv_usec = 1000;
	evtimer_add(pt->event.idle_timer, &tv);
}

void
lws_event_sigint_cb(evutil_socket_t sock_fd, short revents, void *ctx)
{
	struct lws_context_per_thread *pt = ctx;
	struct event *signal = (struct event *)ctx;

	if (pt->context->eventlib_signal_cb) {
		pt->context->eventlib_signal_cb((void *)(lws_intptr_t)sock_fd,
						event_get_signal(signal));

		return;
	}
	if (!pt->event_loop_foreign)
		event_base_loopbreak(pt->event.io_loop);
}


static int
elops_init_pt_event(struct lws_context *context, void *_loop, int tsi)
{
	struct lws_vhost *vh = context->vhost_list;
	struct event_base *loop = (struct event_base *)_loop;
	struct lws_context_per_thread *pt = &context->pt[tsi];

	lwsl_info("%s: loop %p\n", __func__, _loop);

	if (!loop)
		loop = event_base_new();
	else
		context->pt[tsi].event_loop_foreign = 1;

	if (!loop) {
		lwsl_err("%s: creating event base failed\n", __func__);

		return -1;
	}

	pt->event.io_loop = loop;

	/*
	* Initialize all events with the listening sockets
	* and register a callback for read operations
	*/

	while (vh) {
		if (vh->lserv_wsi) {
			vh->lserv_wsi->w_read.context = context;
			vh->lserv_wsi->w_read.event.watcher = event_new(
					loop, vh->lserv_wsi->desc.sockfd,
					(EV_READ | EV_PERSIST), lws_event_cb,
					&vh->lserv_wsi->w_read);
			event_add(vh->lserv_wsi->w_read.event.watcher, NULL);
		}
		vh = vh->vhost_next;
	}

	/* static event loop objects */

	pt->event.hrtimer = event_new(loop, -1, EV_PERSIST,
				      lws_event_hrtimer_cb, pt);

	pt->event.idle_timer = event_new(loop, -1, 0,
					 lws_event_idle_timer_cb, pt);

	/* Register the signal watcher unless it's a foreign loop */

	if (pt->event_loop_foreign)
		return 0;

	pt->w_sigint.event.watcher = evsignal_new(loop, SIGINT,
						  lws_event_sigint_cb, pt);
	event_add(pt->w_sigint.event.watcher, NULL);

	return 0;
}

static int
elops_init_context_event(struct lws_context *context,
			 const struct lws_context_creation_info *info)
{
	int n;

	context->eventlib_signal_cb = info->signal_cb;

	for (n = 0; n < context->count_threads; n++)
		context->pt[n].w_sigint.context = context;

	return 0;
}

static int
elops_accept_event(struct lws *wsi)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt;
	int fd;

	wsi->w_read.context = context;
	wsi->w_write.context = context;

	// Initialize the event
	pt = &context->pt[(int)wsi->tsi];

	if (wsi->role_ops->file_handle)
		fd = wsi->desc.filefd;
	else
		fd = wsi->desc.sockfd;

	wsi->w_read.event.watcher = event_new(pt->event.io_loop, fd,
			(EV_READ | EV_PERSIST), lws_event_cb, &wsi->w_read);
	wsi->w_write.event.watcher = event_new(pt->event.io_loop, fd,
			(EV_WRITE | EV_PERSIST), lws_event_cb, &wsi->w_write);

	return 0;
}

static void
elops_io_event(struct lws *wsi, int flags)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!pt->event.io_loop || wsi->context->being_destroyed ||
	    pt->is_destroyed)
		return;

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	if (flags & LWS_EV_START) {
		if (flags & LWS_EV_WRITE)
			event_add(wsi->w_write.event.watcher, NULL);

		if (flags & LWS_EV_READ)
			event_add(wsi->w_read.event.watcher, NULL);
	} else {
		if (flags & LWS_EV_WRITE)
			event_del(wsi->w_write.event.watcher);

		if (flags & LWS_EV_READ)
			event_del(wsi->w_read.event.watcher);
	}
}

static void
elops_run_pt_event(struct lws_context *context, int tsi)
{
	/* Run / Dispatch the event_base loop */
	if (context->pt[tsi].event.io_loop)
		event_base_dispatch(context->pt[tsi].event.io_loop);
}

static void
elops_destroy_pt_event(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;

	lwsl_info("%s\n", __func__);

	if (!pt->event.io_loop)
		return;

	/*
	 * Free all events with the listening sockets
	 */
	while (vh) {
		if (vh->lserv_wsi) {
			event_free(vh->lserv_wsi->w_read.event.watcher);
			vh->lserv_wsi->w_read.event.watcher = NULL;
			event_free(vh->lserv_wsi->w_write.event.watcher);
			vh->lserv_wsi->w_write.event.watcher = NULL;
		}
		vh = vh->vhost_next;
	}

	event_free(pt->event.hrtimer);
	event_free(pt->event.idle_timer);

	if (!pt->event_loop_foreign) {
		event_del(pt->w_sigint.event.watcher);
		event_free(pt->w_sigint.event.watcher);

		event_base_free(pt->event.io_loop);
	}
}

static void
elops_destroy_wsi_event(struct lws *wsi)
{
	struct lws_context_per_thread *pt;

	if (!wsi)
		return;

	pt = &wsi->context->pt[(int)wsi->tsi];
	if (pt->is_destroyed)
		return;

	if (wsi->w_read.event.watcher) {
		event_free(wsi->w_read.event.watcher);
		wsi->w_read.event.watcher = NULL;
	}

	if (wsi->w_write.event.watcher) {
		event_free(wsi->w_write.event.watcher);
		wsi->w_write.event.watcher = NULL;
	}
}

static int
elops_wsi_logical_close_event(struct lws *wsi)
{
	elops_destroy_wsi_event(wsi);

	return 0;
}

static int
elops_init_vhost_listen_wsi_event(struct lws *wsi)
{
	struct lws_context_per_thread *pt;
	int fd;

	if (!wsi) {
		assert(0);
		return 0;
	}

	wsi->w_read.context = wsi->context;
	wsi->w_write.context = wsi->context;

	pt = &wsi->context->pt[(int)wsi->tsi];

	if (wsi->role_ops->file_handle)
		fd = wsi->desc.filefd;
	else
		fd = wsi->desc.sockfd;

	wsi->w_read.event.watcher = event_new(pt->event.io_loop, fd,
					      (EV_READ | EV_PERSIST),
					      lws_event_cb, &wsi->w_read);
	wsi->w_write.event.watcher = event_new(pt->event.io_loop, fd,
					       (EV_WRITE | EV_PERSIST),
					       lws_event_cb, &wsi->w_write);

	elops_io_event(wsi, LWS_EV_START | LWS_EV_READ);

	return 0;
}

static int
elops_destroy_context2_event(struct lws_context *context)
{
	struct lws_context_per_thread *pt;
	int n, m;

	lwsl_debug("%s: in\n", __func__);

	for (n = 0; n < context->count_threads; n++) {
		int budget = 1000;

		pt = &context->pt[n];

		/* only for internal loops... */

		if (pt->event_loop_foreign || !pt->event.io_loop)
			continue;

		if (!context->finalize_destroy_after_internal_loops_stopped) {
			event_base_loopexit(pt->event.io_loop, NULL);
			continue;
		}
		while (budget-- &&
		       (m = event_base_loop(pt->event.io_loop, EVLOOP_NONBLOCK)))
			;
#if 0
		if (m) {
			lwsl_err("%s: tsi %d: NOT everything closed\n",
				 __func__, n);
			event_base_dump_events(pt->event.io_loop, stderr);
		} else
			lwsl_debug("%s: %d: everything closed OK\n", __func__, n);
#endif
		event_base_free(pt->event.io_loop);

	}

	lwsl_debug("%s: out\n", __func__);

	return 0;
}

struct lws_event_loop_ops event_loop_ops_event = {
	/* name */			"libevent",
	/* init_context */		elops_init_context_event,
	/* destroy_context1 */		NULL,
	/* destroy_context2 */		elops_destroy_context2_event,
	/* init_vhost_listen_wsi */	elops_init_vhost_listen_wsi_event,
	/* init_pt */			elops_init_pt_event,
	/* wsi_logical_close */		elops_wsi_logical_close_event,
	/* check_client_connect_ok */	NULL,
	/* close_handle_manually */	NULL,
	/* accept */			elops_accept_event,
	/* io */			elops_io_event,
	/* run_pt */			elops_run_pt_event,
	/* destroy_pt */		elops_destroy_pt_event,
	/* destroy wsi */		elops_destroy_wsi_event,

	/* flags */			0,
};
