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
lws_ev_hrtimer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	struct lws_context_per_thread *pt =
			(struct lws_context_per_thread *)watcher->data;
	lws_usec_t us;

	lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
	if (us) {
		ev_timer_set(&pt->ev.hrtimer, ((float)us) / 1000000.0, 0);
		ev_timer_start(pt->ev.io_loop, &pt->ev.hrtimer);
	}
	lws_pt_unlock(pt);
}

static void
lws_ev_idle_cb(struct ev_loop *loop, struct ev_idle *handle, int revents)
{
	struct lws_context_per_thread *pt = lws_container_of(handle,
					struct lws_context_per_thread, ev.idle);
	lws_usec_t us;
	int reschedule = 0;

	lws_service_do_ripe_rxflow(pt);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!lws_service_adjust_timeout(pt->context, 1, pt->tid))
		/* -1 timeout means just do forced service */
		reschedule = _lws_plat_service_forced_tsi(pt->context, pt->tid);

	/* account for hrtimer */

	lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
	if (us) {
		ev_timer_set(&pt->ev.hrtimer, ((float)us) / 1000000.0, 0);
		ev_timer_start(pt->ev.io_loop, &pt->ev.hrtimer);
	}
	lws_pt_unlock(pt);

	/* there is nobody who needs service forcing, shut down idle */
	if (!reschedule)
		ev_idle_stop(loop, handle);

	if (pt->destroy_self)
		lws_context_destroy(pt->context);
}

static void
lws_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct lws_io_watcher *lws_io = lws_container_of(watcher,
					struct lws_io_watcher, ev.watcher);
	struct lws_context *context = lws_io->context;
	struct lws_context_per_thread *pt;
	struct lws_pollfd eventfd;
	struct lws *wsi;

	if (revents & EV_ERROR)
		return;

	eventfd.fd = watcher->fd;
	eventfd.events = 0;
	eventfd.revents = EV_NONE;

	if (revents & EV_READ) {
		eventfd.events |= LWS_POLLIN;
		eventfd.revents |= LWS_POLLIN;
	}
	if (revents & EV_WRITE) {
		eventfd.events |= LWS_POLLOUT;
		eventfd.revents |= LWS_POLLOUT;
	}

	wsi = wsi_from_fd(context, watcher->fd);
	pt = &context->pt[(int)wsi->tsi];

	lws_service_fd_tsi(context, &eventfd, (int)wsi->tsi);

	ev_idle_start(pt->ev.io_loop, &pt->ev.idle);
}

void
lws_ev_sigint_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	struct lws_context *context = watcher->data;

	if (context->eventlib_signal_cb) {
		context->eventlib_signal_cb((void *)watcher, watcher->signum);

		return;
	}
	ev_break(loop, EVBREAK_ALL);
}

static int
elops_init_pt_ev(struct lws_context *context, void *_loop, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct ev_signal *w_sigint = &context->pt[tsi].w_sigint.ev.watcher;
	struct ev_loop *loop = (struct ev_loop *)_loop;
	struct lws_vhost *vh = context->vhost_list;
	const char *backend_name;
	int status = 0;
	int backend;

	lwsl_info("%s: loop %p\n", __func__, _loop);

	if (!loop)
		loop = ev_loop_new(0);
	else
		context->pt[tsi].event_loop_foreign = 1;

	if (!loop) {
		lwsl_err("%s: creating event base failed\n", __func__);

		return -1;
	}

	pt->ev.io_loop = loop;

	/*
	 * Initialize the accept w_accept with all the listening sockets
	 * and register a callback for read operations
	 */
	while (vh) {
		if (vh->lserv_wsi) {
			vh->lserv_wsi->w_read.context = context;
			vh->w_accept.context = context;

			ev_io_init(&vh->w_accept.ev.watcher, lws_accept_cb,
				   vh->lserv_wsi->desc.sockfd, EV_READ);
			ev_io_start(loop, &vh->w_accept.ev.watcher);

		}
		vh = vh->vhost_next;
	}

	/* Register the signal watcher unless it's a foreign loop */
	if (!context->pt[tsi].event_loop_foreign) {
		ev_signal_init(w_sigint, lws_ev_sigint_cb, SIGINT);
		w_sigint->data = context;
		ev_signal_start(loop, w_sigint);
	}

	backend = ev_backend(loop);
	switch (backend) {
	case EVBACKEND_SELECT:
		backend_name = "select";
		break;
	case EVBACKEND_POLL:
		backend_name = "poll";
		break;
	case EVBACKEND_EPOLL:
		backend_name = "epoll";
		break;
#if defined(LWS_HAVE_EVBACKEND_LINUXAIO)
       case EVBACKEND_LINUXAIO:
               backend_name = "Linux AIO";
               break;
#endif
#if defined(LWS_HAVE_EVBACKEND_IOURING)
       case EVBACKEND_IOURING:
               backend_name = "Linux io_uring";
               break;
#endif
       case EVBACKEND_KQUEUE:
		backend_name = "kqueue";
		break;
	case EVBACKEND_DEVPOLL:
		backend_name = "/dev/poll";
		break;
	case EVBACKEND_PORT:
		backend_name = "Solaris 10 \"port\"";
		break;
	default:
		backend_name = "Unknown libev backend";
		break;
	}

	lwsl_info(" libev backend: %s\n", backend_name);
	(void)backend_name;

	ev_timer_init(&pt->ev.hrtimer, lws_ev_hrtimer_cb, 0, 0);
	pt->ev.hrtimer.data = pt;

	ev_idle_init(&pt->ev.idle, lws_ev_idle_cb);

	return status;
}

static void
elops_destroy_pt_ev(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;

	while (vh) {
		if (vh->lserv_wsi)
			ev_io_stop(pt->ev.io_loop, &vh->w_accept.ev.watcher);
		vh = vh->vhost_next;
	}

	/* static assets */

	ev_timer_stop(pt->ev.io_loop, &pt->ev.hrtimer);
	ev_idle_stop(pt->ev.io_loop, &pt->ev.idle);

	if (!pt->event_loop_foreign) {
		ev_signal_stop(pt->ev.io_loop, &pt->w_sigint.ev.watcher);

		ev_loop_destroy(pt->ev.io_loop);
	}
}

static int
elops_init_context_ev(struct lws_context *context,
		      const struct lws_context_creation_info *info)
{
	int n;

	context->eventlib_signal_cb = info->signal_cb;

	for (n = 0; n < context->count_threads; n++)
		context->pt[n].w_sigint.context = context;

	return 0;
}

static int
elops_accept_ev(struct lws *wsi)
{
	int fd;

	if (wsi->role_ops->file_handle)
		fd = wsi->desc.filefd;
	else
		fd = wsi->desc.sockfd;

	wsi->w_read.context = wsi->context;
	wsi->w_write.context = wsi->context;

	ev_io_init(&wsi->w_read.ev.watcher, lws_accept_cb, fd, EV_READ);
	ev_io_init(&wsi->w_write.ev.watcher, lws_accept_cb, fd, EV_WRITE);

	return 0;
}

static void
elops_io_ev(struct lws *wsi, int flags)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!pt->ev.io_loop || pt->is_destroyed)
		return;

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	if (flags & LWS_EV_START) {
		if (flags & LWS_EV_WRITE)
			ev_io_start(pt->ev.io_loop, &wsi->w_write.ev.watcher);
		if (flags & LWS_EV_READ)
			ev_io_start(pt->ev.io_loop, &wsi->w_read.ev.watcher);
	} else {
		if (flags & LWS_EV_WRITE)
			ev_io_stop(pt->ev.io_loop, &wsi->w_write.ev.watcher);
		if (flags & LWS_EV_READ)
			ev_io_stop(pt->ev.io_loop, &wsi->w_read.ev.watcher);
	}

	if (pt->destroy_self)
		lws_context_destroy(pt->context);
}

static void
elops_run_pt_ev(struct lws_context *context, int tsi)
{
	if (context->pt[tsi].ev.io_loop)
		ev_run(context->pt[tsi].ev.io_loop, 0);
}

static int
elops_destroy_context2_ev(struct lws_context *context)
{
	struct lws_context_per_thread *pt;
	int n, m;

	lwsl_debug("%s\n", __func__);

	for (n = 0; n < context->count_threads; n++) {
		int budget = 1000;

		pt = &context->pt[n];

		/* only for internal loops... */

		if (pt->event_loop_foreign || !pt->ev.io_loop)
			continue;

		if (!context->finalize_destroy_after_internal_loops_stopped) {
			ev_break(pt->ev.io_loop, EVBREAK_ONE);
			continue;
		}
		while (budget-- &&
		       (m = ev_run(pt->ev.io_loop, 0)))
			;

		ev_loop_destroy(pt->ev.io_loop);
	}

	return 0;
}

static int
elops_init_vhost_listen_wsi_ev(struct lws *wsi)
{
	int fd;

	if (!wsi) {
		assert(0);
		return 0;
	}

	wsi->w_read.context = wsi->context;
	wsi->w_write.context = wsi->context;

	if (wsi->role_ops->file_handle)
		fd = wsi->desc.filefd;
	else
		fd = wsi->desc.sockfd;

	ev_io_init(&wsi->w_read.ev.watcher, lws_accept_cb, fd, EV_READ);
	ev_io_init(&wsi->w_write.ev.watcher, lws_accept_cb, fd, EV_WRITE);

	elops_io_ev(wsi, LWS_EV_START | LWS_EV_READ);

	return 0;
}

static void
elops_destroy_wsi_ev(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	ev_io_stop(pt->ev.io_loop, &wsi->w_read.ev.watcher);
	ev_io_stop(pt->ev.io_loop, &wsi->w_write.ev.watcher);
}

struct lws_event_loop_ops event_loop_ops_ev = {
	/* name */			"libev",
	/* init_context */		elops_init_context_ev,
	/* destroy_context1 */		NULL,
	/* destroy_context2 */		elops_destroy_context2_ev,
	/* init_vhost_listen_wsi */	elops_init_vhost_listen_wsi_ev,
	/* init_pt */			elops_init_pt_ev,
	/* wsi_logical_close */		NULL,
	/* check_client_connect_ok */	NULL,
	/* close_handle_manually */	NULL,
	/* accept */			elops_accept_ev,
	/* io */			elops_io_ev,
	/* run_pt */			elops_run_pt_ev,
	/* destroy_pt */		elops_destroy_pt_ev,
	/* destroy wsi */		elops_destroy_wsi_ev,

	/* flags */			0,
};
