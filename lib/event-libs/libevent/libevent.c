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

void lws_feature_status_libevent(const struct lws_context_creation_info *info)
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

	lws_service_fd(context, &eventfd);
}

LWS_VISIBLE void
lws_event_sigint_cb(evutil_socket_t sock_fd, short revents, void *ctx)
{
	struct lws_context_per_thread *pt = ctx;

	if (pt->context->eventlib_signal_cb) {
		pt->context->eventlib_signal_cb(
				(void *)(lws_intptr_t)sock_fd, revents);

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

	if (!loop)
		context->pt[tsi].event.io_loop = event_base_new();
	else {
		context->pt[tsi].event_loop_foreign = 1;
		context->pt[tsi].event.io_loop = loop;
	}

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

	/* Register the signal watcher unless it's a foreign loop */
	if (context->pt[tsi].event_loop_foreign)
		return 0;

	context->pt[tsi].w_sigint.event.watcher = evsignal_new(loop, SIGINT,
			lws_event_sigint_cb, &context->pt[tsi]);
	event_add(context->pt[tsi].w_sigint.event.watcher, NULL);

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

static void
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
}

static void
elops_io_event(struct lws *wsi, int flags)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!pt->event.io_loop || context->being_destroyed)
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
	if (context->pt[tsi].event.io_loop &&
	    LWS_LIBEVENT_ENABLED(context))
		event_base_dispatch(context->pt[tsi].event.io_loop);
}

static void
elops_destroy_pt_event(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;

	if (!lws_check_opt(context->options, LWS_SERVER_OPTION_LIBEVENT))
		return;

	if (!pt->event.io_loop)
		return;

	/*
	 * Free all events with the listening sockets
	 */
	while (vh) {
		if (vh->lserv_wsi) {
			event_free(vh->lserv_wsi->w_read.event.watcher);
			vh->lserv_wsi->w_read.event.watcher = NULL;
		}
		vh = vh->vhost_next;
	}

	if (!pt->event_loop_foreign)
		event_free(pt->w_sigint.event.watcher);
	if (!pt->event_loop_foreign)
		event_base_free(pt->event.io_loop);
}

static void
elops_destroy_wsi_event(struct lws *wsi)
{
	if (!wsi)
		return;

	if(wsi->w_read.event.watcher)
		event_free(wsi->w_read.event.watcher);

	if(wsi->w_write.event.watcher)
		event_free(wsi->w_write.event.watcher);
}


struct lws_event_loop_ops event_loop_ops_event = {
	/* name */			"libevent",
	/* init_context */		elops_init_context_event,
	/* destroy_context1 */		NULL,
	/* destroy_context2 */		NULL,
	/* init_vhost_listen_wsi */	NULL,
	/* init_pt */			elops_init_pt_event,
	/* wsi_logical_close */		NULL,
	/* check_client_connect_ok */	NULL,
	/* close_handle_manually */	NULL,
	/* accept */			elops_accept_event,
	/* io */			elops_io_event,
	/* run_pt */			elops_run_pt_event,
	/* destroy_pt */		elops_destroy_pt_event,
	/* destroy wsi */		elops_destroy_wsi_event,

	/* periodic_events_available */	0,
};
