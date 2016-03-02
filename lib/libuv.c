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
lws_io_cb(uv_poll_t *watcher, int status, int revents)
{
	struct lws_io_watcher *lws_io = container_of(watcher,
					struct lws_io_watcher, uv_watcher);
	struct lws_context *context = lws_io->context;
	struct lws_pollfd eventfd;

	eventfd.fd = watcher->io_watcher.fd;
	eventfd.events = 0;
	eventfd.revents = 0;

	if (status < 0) {
		/* at this point status will be an UV error, like UV_EBADF,
		we treat all errors as LWS_POLLHUP */

		/* you might want to return; instead of servicing the fd in some cases */
		if (status == UV_EAGAIN)
			return;

		eventfd.events |= LWS_POLLHUP;
		eventfd.revents |= LWS_POLLHUP;
	} else {
		if (revents & UV_READABLE) {
			eventfd.events |= LWS_POLLIN;
			eventfd.revents |= LWS_POLLIN;
		}
		if (revents & UV_WRITABLE) {
			eventfd.events |= LWS_POLLOUT;
			eventfd.revents |= LWS_POLLOUT;
		}
	}
	lws_service_fd(context, &eventfd);
}

LWS_VISIBLE void
lws_uv_sigint_cb(uv_loop_t *loop, uv_signal_t *watcher, int revents)
{
	uv_stop(loop);
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

static void
lws_uv_timeout_cb(uv_timer_t *timer)
{
	struct lws_context_per_thread *pt = container_of(timer,
			struct lws_context_per_thread, uv_timeout_watcher);

	lwsl_info("%s\n", __func__);
	/* do timeout check only */
	lws_service_fd_tsi(pt->context, NULL, pt->tid);
}

static const int sigs[] = { SIGINT, SIGTERM, SIGSEGV, SIGFPE };

LWS_VISIBLE int
lws_uv_initloop(struct lws_context *context, uv_loop_t *loop, uv_signal_cb cb,
		int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws *wsi = wsi_from_fd(context, pt->lserv_fd);
	int status = 0, n;

	if (!loop) {
		loop = lws_malloc(sizeof(*loop));
		uv_loop_init(loop);
		pt->ev_loop_foreign = 0;
	} else
		pt->ev_loop_foreign = 1;

	pt->io_loop_uv = loop;

	assert(ARRAY_SIZE(sigs) <= ARRAY_SIZE(pt->signals));
	for (n = 0; n < ARRAY_SIZE(sigs); n++) {
		uv_signal_init(loop, &pt->signals[n]);
		uv_signal_start(&pt->signals[n], cb, sigs[n]);
	}

	/*
	 * Initialize the accept wsi read watcher with the listening socket
	 * and register a callback for read operations
	 *
	 * We have to do it here because the uv loop(s) are not
	 * initialized until after context creation.
	 */
	if (wsi) {
		wsi->w_read.context = context;
		uv_poll_init(pt->io_loop_uv, &wsi->w_read.uv_watcher,
			     pt->lserv_fd);
		uv_poll_start(&wsi->w_read.uv_watcher, UV_READABLE,
			      lws_io_cb);
	}

	uv_timer_init(pt->io_loop_uv, &pt->uv_timeout_watcher);
	uv_timer_start(&pt->uv_timeout_watcher, lws_uv_timeout_cb, 1000, 1000);

	return status;
}

void lws_uv_close_cb(uv_handle_t *handle)
{

}

void lws_uv_walk_cb(uv_handle_t *handle, void *arg)
{
	uv_close(handle, lws_uv_close_cb);
}

void
lws_libuv_destroyloop(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	int m;

	if (!(context->options & LWS_SERVER_OPTION_LIBUV))
		return;

	if (!pt->io_loop_uv)
		return;

	if (context->use_ev_sigint)
		uv_signal_stop(&pt->w_sigint.uv_watcher);
	for (m = 0; m < ARRAY_SIZE(sigs); m++)
		uv_signal_stop(&pt->signals[m]);
	if (!pt->ev_loop_foreign) {
		uv_stop(pt->io_loop_uv);
		uv_walk(pt->io_loop_uv, lws_uv_walk_cb, NULL);
		while (uv_run(pt->io_loop_uv, UV_RUN_NOWAIT));
		m = uv_loop_close(pt->io_loop_uv);
		if (m == UV_EBUSY)
			lwsl_debug("%s: uv_loop_close: UV_EBUSY\n", __func__);
		lws_free(pt->io_loop_uv);
	}
}

void
lws_libuv_accept(struct lws *wsi, int accept_fd)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (!LWS_LIBUV_ENABLED(context))
		return;

	lwsl_debug("%s: new wsi %p\n", __func__, wsi);

	wsi->w_read.context = context;

	uv_poll_init(pt->io_loop_uv, &wsi->w_read.uv_watcher, accept_fd);
}

void
lws_libuv_io(struct lws *wsi, int flags)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int current_events = wsi->w_read.uv_watcher.io_watcher.pevents &
			     (UV_READABLE | UV_WRITABLE);
	struct lws_io_watcher *w = &wsi->w_read;

	if (!LWS_LIBUV_ENABLED(context))
		return;

	lwsl_debug("%s: wsi: %p, flags:%d\n", __func__, wsi, flags);

	if (!pt->io_loop_uv) {
		lwsl_info("%s: no io loop yet\n", __func__);
		return;
	}

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	if (flags & LWS_EV_START) {
		if (flags & LWS_EV_WRITE)
			current_events |= UV_WRITABLE;

		if (flags & LWS_EV_READ)
			current_events |= UV_READABLE;

		uv_poll_start(&w->uv_watcher, current_events, lws_io_cb);
	} else {
		if (flags & LWS_EV_WRITE)
			current_events &= ~UV_WRITABLE;

		if (flags & LWS_EV_READ)
			current_events &= ~UV_READABLE;

		if (!(current_events & (UV_READABLE | UV_WRITABLE)))
			uv_poll_stop(&w->uv_watcher);
		else
			uv_poll_start(&w->uv_watcher, current_events,
				      lws_io_cb);
	}
}

int
lws_libuv_init_fd_table(struct lws_context *context)
{
	int n;

	if (!LWS_LIBUV_ENABLED(context))
		return 0;

	for (n = 0; n < context->count_threads; n++) {
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

static void
lws_libuv_kill(const struct lws_context *context)
{
	int n;

	for (n = 0; n < context->count_threads; n++)
		if (context->pt[n].io_loop_uv && LWS_LIBUV_ENABLED(context))
			uv_stop(context->pt[n].io_loop_uv);
}

/*
 * This does not actually stop the event loop.  The reason is we have to pass
 * libuv handle closures through its event loop.  So this tries to close all
 * wsi, and set a flag; when all the wsi closures are finalized then we
 * actually stop the libuv event loops.
 */

LWS_VISIBLE void
lws_libuv_stop(struct lws_context *context)
{
	struct lws_context_per_thread *pt;
	int n, m;

	context->requested_kill = 1;

	m = context->count_threads;
	context->being_destroyed = 1;

	while (m--) {
		pt = &context->pt[m];

		for (n = 0; (unsigned int)n < context->pt[m].fds_count; n++) {
			struct lws *wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;

			lws_close_free_wsi(wsi,
				LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY
				/* no protocol close */);
			n--;
		}
	}

	if (context->count_wsi_allocated == 0)
		lws_libuv_kill(context);
}

LWS_VISIBLE uv_loop_t *
lws_uv_getloop(struct lws_context *context, int tsi)
{
	if (context->pt[tsi].io_loop_uv && LWS_LIBUV_ENABLED(context))
		return context->pt[tsi].io_loop_uv;

	return NULL;
}

static void
lws_libuv_closewsi(uv_handle_t* handle)
{
	struct lws *n = NULL, *wsi = (struct lws *)(((void *)handle) -
			  (void *)(&n->w_read.uv_watcher));
	struct lws_context *context = lws_get_context(wsi);

	lws_close_free_wsi_final(wsi);

	if (context->requested_kill && context->count_wsi_allocated == 0)
		lws_libuv_kill(context);
}

void
lws_libuv_closehandle(struct lws *wsi)
{
	struct lws_context *context = lws_get_context(wsi);

	/* required to defer actual deletion until libuv has processed it */

	uv_close((uv_handle_t*)&wsi->w_read.uv_watcher, lws_libuv_closewsi);

	if (context->requested_kill && context->count_wsi_allocated == 0)
		lws_libuv_kill(context);
}
