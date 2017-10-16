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

void lws_feature_status_libev(struct lws_context_creation_info *info)
{
	if (lws_check_opt(info->options, LWS_SERVER_OPTION_LIBEV))
		lwsl_info("libev support compiled in and enabled\n");
	else
		lwsl_info("libev support compiled in but disabled\n");
}

static void
lws_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct lws_io_watcher *lws_io = lws_container_of(watcher,
					struct lws_io_watcher, ev_watcher);
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
	ev_break(loop, EVBREAK_ALL);
}

LWS_VISIBLE int
lws_ev_sigint_cfg(struct lws_context *context, int use_ev_sigint,
		  lws_ev_signal_cb_t *cb)
{
	context->use_ev_sigint = use_ev_sigint;
	if (cb)
		context->lws_ev_sigint_cb = cb;
	else
		context->lws_ev_sigint_cb = &lws_ev_sigint_cb;

	return 0;
}

LWS_VISIBLE int
lws_ev_initloop(struct lws_context *context, struct ev_loop *loop, int tsi)
{
	struct ev_signal *w_sigint = &context->pt[tsi].w_sigint.ev_watcher;
	struct ev_io *w_accept = &context->pt[tsi].w_accept.ev_watcher;
	struct lws_vhost *vh = context->vhost_list;
	const char *backend_name;
	int status = 0;
	int backend;

	if (!loop)
		loop = ev_loop_new(0);
	else
		context->pt[tsi].ev_loop_foreign = 1;

	context->pt[tsi].io_loop_ev = loop;

	/*
	 * Initialize the accept w_accept with all the listening sockets
	 * and register a callback for read operations
	 */
	while (vh) {
		if (vh->lserv_wsi) {
			vh->lserv_wsi->w_read.context = context;
			ev_io_init(w_accept, lws_accept_cb,
				   vh->lserv_wsi->desc.sockfd, EV_READ);
		}
		vh = vh->vhost_next;
	}
	ev_io_start(context->pt[tsi].io_loop_ev, w_accept);

	/* Register the signal watcher unless the user says not to */
	if (context->use_ev_sigint) {
		ev_signal_init(w_sigint, context->lws_ev_sigint_cb, SIGINT);
		ev_signal_start(context->pt[tsi].io_loop_ev, w_sigint);
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

void
lws_libev_destroyloop(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];

	if (!lws_check_opt(context->options, LWS_SERVER_OPTION_LIBEV))
		return;

	if (!pt->io_loop_ev)
		return;

	ev_io_stop(pt->io_loop_ev, &pt->w_accept.ev_watcher);
	if (context->use_ev_sigint)
		ev_signal_stop(pt->io_loop_ev,
		       &pt->w_sigint.ev_watcher);
	if (!pt->ev_loop_foreign)
		ev_loop_destroy(pt->io_loop_ev);
}

LWS_VISIBLE void
lws_libev_accept(struct lws *new_wsi, lws_sock_file_fd_type desc)
{
	struct lws_context *context = lws_get_context(new_wsi);
	struct ev_io *r = &new_wsi->w_read.ev_watcher;
	struct ev_io *w = &new_wsi->w_write.ev_watcher;
	int fd;

	if (!LWS_LIBEV_ENABLED(context))
		return;

	if (new_wsi->mode == LWSCM_RAW_FILEDESC)
		fd = desc.filefd;
	else
		fd = desc.sockfd;

	new_wsi->w_read.context = context;
	new_wsi->w_write.context = context;
	ev_io_init(r, lws_accept_cb, fd, EV_READ);
	ev_io_init(w, lws_accept_cb, fd, EV_WRITE);
}

LWS_VISIBLE void
lws_libev_io(struct lws *wsi, int flags)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!LWS_LIBEV_ENABLED(context))
		return;

	if (!pt->io_loop_ev)
		return;

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	if (flags & LWS_EV_START) {
		if (flags & LWS_EV_WRITE)
			ev_io_start(pt->io_loop_ev, &wsi->w_write.ev_watcher);
		if (flags & LWS_EV_READ)
			ev_io_start(pt->io_loop_ev, &wsi->w_read.ev_watcher);
	} else {
		if (flags & LWS_EV_WRITE)
			ev_io_stop(pt->io_loop_ev, &wsi->w_write.ev_watcher);
		if (flags & LWS_EV_READ)
			ev_io_stop(pt->io_loop_ev, &wsi->w_read.ev_watcher);
	}
}

LWS_VISIBLE int
lws_libev_init_fd_table(struct lws_context *context)
{
	int n;

	if (!LWS_LIBEV_ENABLED(context))
		return 0;

	for (n = 0; n < context->count_threads; n++) {
		context->pt[n].w_accept.context = context;
		context->pt[n].w_sigint.context = context;
	}

	return 1;
}

LWS_VISIBLE void
lws_libev_run(const struct lws_context *context, int tsi)
{
	if (context->pt[tsi].io_loop_ev && LWS_LIBEV_ENABLED(context))
		ev_run(context->pt[tsi].io_loop_ev, 0);
}
