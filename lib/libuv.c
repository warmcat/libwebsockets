/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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

void
lws_feature_status_libuv(struct lws_context_creation_info *info)
{
	if (info->options & LWS_SERVER_OPTION_LIBUV)
		lwsl_notice("libuv support compiled in and enabled\n");
	else
		lwsl_notice("libuv support compiled in but disabled\n");
}

static void
lws_accept_cb(uv_poll_t *watcher, int status, int revents)
{
	struct lws_io_watcher *lws_io = container_of(watcher,
					struct lws_io_watcher, uv_watcher);
	struct lws_context *context = lws_io->context;
	struct lws_pollfd eventfd;

	if (status < 0)
		return;

	eventfd.fd = watcher->io_watcher.fd;
	eventfd.events = 0;
	eventfd.revents = 0;//EV_NONE;
	if (revents & UV_READABLE) {
		eventfd.events |= LWS_POLLIN;
		eventfd.revents |= LWS_POLLIN;
	}
	if (revents & UV_WRITABLE) {
		eventfd.events |= LWS_POLLOUT;
		eventfd.revents |= LWS_POLLOUT;
	}
	lws_service_fd(context, &eventfd);
}

LWS_VISIBLE void
lws_uv_sigint_cb(uv_loop_t *loop, uv_signal_t *watcher, int revents)
{
    //ev_break(loop, EVBREAK_ALL);
}

LWS_VISIBLE int
lws_uv_sigint_cfg(struct lws_context *context, int use_uv_sigint,
		  lws_uv_signal_cb_t *cb)
{
	context->use_ev_sigint = use_uv_sigint;
	if (cb)
		context->lws_uv_sigint_cb = cb;
	else
		context->lws_uv_sigint_cb = &lws_uv_sigint_cb;

	return 0;
}

LWS_VISIBLE int
lws_uv_initloop(struct lws_context *context, uv_loop_t *loop, int tsi)
{
	uv_poll_t *w_accept = &context->pt[tsi].w_accept.uv_watcher;
	int status = 0;

	if (!loop)
		loop = uv_loop_new();

	context->pt[tsi].io_loop_uv = loop;

	/*
	 * Initialize the accept w_accept with the listening socket
	 * and register a callback for read operations
	 */
	uv_poll_init(context->pt[tsi].io_loop_uv, w_accept,
			context->pt[tsi].lserv_fd);
	uv_poll_start(w_accept, UV_READABLE, lws_accept_cb);

	return status;
}

LWS_VISIBLE void
lws_libuv_accept(struct lws *new_wsi, int accept_fd)
{
	struct lws_context *context = lws_get_context(new_wsi);
	uv_poll_t *r = &new_wsi->w_read.uv_watcher;

	if (!LWS_LIBUV_ENABLED(context))
		return;

	new_wsi->w_read.context = context;
	new_wsi->w_write.context = context;

	uv_poll_init(context->pt[(int)new_wsi->tsi].io_loop_uv, r, accept_fd);
}

LWS_VISIBLE void
lws_libuv_io(struct lws *wsi, int flags)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int current_events = wsi->w_read.uv_watcher.io_watcher.pevents &
			     (UV_READABLE | UV_WRITABLE);

	if (!LWS_LIBUV_ENABLED(context))
		return;

	if (!pt->io_loop_uv)
		return;

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	if (flags & LWS_EV_START) {
		if (flags & LWS_EV_WRITE)
			current_events |= UV_WRITABLE;

		if (flags & LWS_EV_READ)
			current_events |= UV_READABLE;

		uv_poll_start(&wsi->w_read.uv_watcher, current_events,
			      lws_accept_cb);
	} else {
		if (flags & LWS_EV_WRITE)
			current_events &= ~UV_WRITABLE;

		if (flags & LWS_EV_READ)
			current_events &= ~UV_READABLE;

		if (!(current_events & (UV_READABLE | UV_WRITABLE)))
			uv_poll_stop(&wsi->w_read.uv_watcher);
		else
			uv_poll_start(&wsi->w_read.uv_watcher, current_events,
				      lws_accept_cb);
	}
}

LWS_VISIBLE int
lws_libuv_init_fd_table(struct lws_context *context)
{
	int n;

	if (!LWS_LIBUV_ENABLED(context))
		return 0;

	for (n = 0; n < context->count_threads; n++) {
		context->pt[n].w_accept.context = context;
		context->pt[n].w_sigint.context = context;
	}

	return 1;
}

LWS_VISIBLE void
lws_libuv_run(const struct lws_context *context, int tsi)
{
	if (context->pt[tsi].io_loop_uv && LWS_LIBUV_ENABLED(context))
		uv_run(context->pt[tsi].io_loop_uv, 0);
}
