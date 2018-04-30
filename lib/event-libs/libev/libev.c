/*
 * libwebsockets - small server side websockets and web server implementation
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

#include "private-libwebsockets.h"

static void
lws_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct lws_io_watcher *lws_io = lws_container_of(watcher,
					struct lws_io_watcher, ev.watcher);
	struct lws_context *context = lws_io->context;
	struct lws_pollfd eventfd;

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

	lws_service_fd(context, &eventfd);
}

LWS_VISIBLE void
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
	struct ev_signal *w_sigint = &context->pt[tsi].w_sigint.ev.watcher;
	struct lws_vhost *vh = context->vhost_list;
	const char *backend_name;
	struct ev_loop *loop = (struct ev_loop *)_loop;
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

	context->pt[tsi].ev.io_loop = loop;

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

	return status;
}

static void
elops_destroy_pt_ev(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;

	if (!pt->ev.io_loop)
		return;

	while (vh) {
		if (vh->lserv_wsi)
			ev_io_stop(pt->ev.io_loop, &vh->w_accept.ev.watcher);
		vh = vh->vhost_next;
	}
	if (!pt->event_loop_foreign)
		ev_signal_stop(pt->ev.io_loop, &pt->w_sigint.ev.watcher);

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

static void
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
}

static void
elops_io_ev(struct lws *wsi, int flags)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!pt->ev.io_loop)
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
	int n, m, internal = 0;

	lwsl_debug("%s\n", __func__);

	for (n = 0; n < context->count_threads; n++) {
		int budget = 1000;

		pt = &context->pt[n];

		/* only for internal loops... */

		if (pt->event_loop_foreign || !pt->ev.io_loop)
			continue;

		internal = 1;
		if (!context->finalize_destroy_after_internal_loops_stopped) {
			ev_break(pt->ev.io_loop, EVBREAK_ONE);
			continue;
		}
		while (budget-- &&
		       (m = ev_run(pt->ev.io_loop, 0)))
			;

		ev_loop_destroy(pt->ev.io_loop);
	}

	return internal;
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
	/* destroy wsi */		NULL,

	/* periodic_events_available */	0,
};
