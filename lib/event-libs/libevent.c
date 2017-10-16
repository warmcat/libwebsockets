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

void lws_feature_status_libevent(struct lws_context_creation_info *info)
{
	if (lws_check_opt(info->options, LWS_SERVER_OPTION_LIBEVENT))
		lwsl_info("libevent support compiled in and enabled\n");
	else
		lwsl_info("libevent support compiled in but disabled\n");
}

static void
lws_event_cb(evutil_socket_t sock_fd, short revents, void *ctx)
{
	struct lws_io_watcher *lws_io = (struct lws_io_watcher *)ctx;
	struct lws_context *context = lws_io->context;
	struct lws_pollfd eventfd;

	if (revents & EV_TIMEOUT)
		return;

	/* !!! EV_CLOSED doesn't exist in libevent2 */
	#if LIBEVENT_VERSION_NUMBER < 0x02000000
	if (revents & EV_CLOSED) {
		event_del(lws_io->event_watcher);
		event_free(lws_io->event_watcher);
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

	lws_service_fd(context, &eventfd);
}

LWS_VISIBLE void
lws_event_sigint_cb(evutil_socket_t sock_fd, short revents, void *ctx)
{
	struct lws_context_per_thread *pt = ctx;

	if (!pt->ev_loop_foreign)
		event_base_loopbreak(pt->io_loop_event_base);
}

LWS_VISIBLE int
lws_event_sigint_cfg(struct lws_context *context, int use_event_sigint,
lws_event_signal_cb_t *cb)
{
	context->use_ev_sigint = use_event_sigint;
	if (cb)
		context->lws_event_sigint_cb = cb;
	else
		context->lws_event_sigint_cb = &lws_event_sigint_cb;

	return 0;
}

LWS_VISIBLE int
lws_event_initloop(struct lws_context *context, struct event_base *loop,
int tsi)
{
	struct lws_vhost *vh = context->vhost_list;

	if (!loop)
		context->pt[tsi].io_loop_event_base = event_base_new();
	else {
		context->pt[tsi].ev_loop_foreign = 1;
		context->pt[tsi].io_loop_event_base = loop;
	}

	/*
	* Initialize all events with the listening sockets
	* and register a callback for read operations
	*/

	while (vh) {
		if (vh->lserv_wsi) {
			vh->lserv_wsi->w_read.context = context;
			vh->lserv_wsi->w_read.event_watcher = event_new(
					loop, vh->lserv_wsi->desc.sockfd,
					(EV_READ | EV_PERSIST), lws_event_cb,
					&vh->lserv_wsi->w_read);
			event_add(vh->lserv_wsi->w_read.event_watcher, NULL);
		}
		vh = vh->vhost_next;
	}

	/* Register the signal watcher unless the user says not to */
	if (!context->use_ev_sigint)
		return 0;

	context->pt[tsi].w_sigint.event_watcher = evsignal_new(loop, SIGINT,
			context->lws_event_sigint_cb, &context->pt[tsi]);
	event_add(context->pt[tsi].w_sigint.event_watcher, NULL);

	return 0;
}

void
lws_libevent_destroyloop(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;

	if (!lws_check_opt(context->options, LWS_SERVER_OPTION_LIBEVENT))
		return;

	if (!pt->io_loop_event_base)
		return;

	/*
	 * Free all events with the listening sockets
	 */
	while (vh) {
		if (vh->lserv_wsi) {
			event_free(vh->lserv_wsi->w_read.event_watcher);
			vh->lserv_wsi->w_read.event_watcher = NULL;
		}
		vh = vh->vhost_next;
	}

	if (context->use_ev_sigint)
		event_free(pt->w_sigint.event_watcher);
	if (!pt->ev_loop_foreign)
		event_base_free(pt->io_loop_event_base);
}

LWS_VISIBLE void
lws_libevent_accept(struct lws *new_wsi, lws_sock_file_fd_type desc)
{
	struct lws_context *context = lws_get_context(new_wsi);
	struct lws_context_per_thread *pt;
	int fd;

	if (!LWS_LIBEVENT_ENABLED(context))
		return;

	new_wsi->w_read.context = context;
	new_wsi->w_write.context = context;

	// Initialize the event
	pt = &context->pt[(int)new_wsi->tsi];

	if (new_wsi->mode == LWSCM_RAW_FILEDESC)
		fd = desc.filefd;
	else
		fd = desc.sockfd;

	new_wsi->w_read.event_watcher = event_new(pt->io_loop_event_base, fd,
		(EV_READ | EV_PERSIST), lws_event_cb, &new_wsi->w_read);
	new_wsi->w_write.event_watcher = event_new(pt->io_loop_event_base, fd,
		(EV_WRITE | EV_PERSIST), lws_event_cb, &new_wsi->w_write);
}

LWS_VISIBLE void
lws_libevent_io(struct lws *wsi, int flags)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!LWS_LIBEVENT_ENABLED(context))
		return;

	if (!pt->io_loop_event_base || context->being_destroyed)
		return;

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	if (flags & LWS_EV_START) {
		if (flags & LWS_EV_WRITE)
			event_add(wsi->w_write.event_watcher, NULL);
		if (flags & LWS_EV_READ)
			event_add(wsi->w_read.event_watcher, NULL);
	} else {
		if (flags & LWS_EV_WRITE)
			event_del(wsi->w_write.event_watcher);

		if (flags & LWS_EV_READ)
			event_del(wsi->w_read.event_watcher);
	}
}

LWS_VISIBLE int
lws_libevent_init_fd_table(struct lws_context *context)
{
	int n;

	if (!LWS_LIBEVENT_ENABLED(context))
		return 0;

	for (n = 0; n < context->count_threads; n++)
		context->pt[n].w_sigint.context = context;

	return 1;
}

LWS_VISIBLE void
lws_libevent_run(const struct lws_context *context, int tsi)
{
	/* Run / Dispatch the event_base loop */
	if (context->pt[tsi].io_loop_event_base &&
	    LWS_LIBEVENT_ENABLED(context))
		event_base_dispatch(context->pt[tsi].io_loop_event_base);
}
