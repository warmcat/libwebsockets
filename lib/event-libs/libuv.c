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

void
lws_feature_status_libuv(struct lws_context_creation_info *info)
{
	if (lws_check_opt(info->options, LWS_SERVER_OPTION_LIBUV))
		lwsl_info("libuv support compiled in and enabled\n");
	else
		lwsl_info("libuv support compiled in but disabled\n");
}

static void
lws_uv_idle(uv_idle_t *handle
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	struct lws_context_per_thread *pt = lws_container_of(handle,
					struct lws_context_per_thread, uv_idle);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
		/* -1 timeout means just do forced service */
		_lws_plat_service_tsi(pt->context, -1, pt->tid);
		/* still somebody left who wants forced service? */
		if (!lws_service_adjust_timeout(pt->context, 1, pt->tid))
			/* yes... come back again later */
		return;
	}

	/* there is nobody who needs service forcing, shut down idle */
	uv_idle_stop(handle);
}

static void
lws_io_cb(uv_poll_t *watcher, int status, int revents)
{
	struct lws_io_watcher *lws_io = lws_container_of(watcher,
					struct lws_io_watcher, uv_watcher);
	struct lws *wsi = lws_container_of(lws_io, struct lws, w_read);
	struct lws_context *context = wsi->context;
	struct lws_pollfd eventfd;

#if defined(WIN32) || defined(_WIN32)
	eventfd.fd = watcher->socket;
#else
	eventfd.fd = watcher->io_watcher.fd;
#endif
	eventfd.events = 0;
	eventfd.revents = 0;

	if (status < 0) {
		/*
		 * At this point status will be an UV error, like UV_EBADF,
		 * we treat all errors as LWS_POLLHUP
		 *
		 * You might want to return; instead of servicing the fd in
		 * some cases */
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

	uv_idle_start(&context->pt[(int)wsi->tsi].uv_idle, lws_uv_idle);
}

LWS_VISIBLE void
lws_uv_sigint_cb(uv_signal_t *watcher, int signum)
{
	lwsl_err("internal signal handler caught signal %d\n", signum);
	lws_libuv_stop(watcher->data);
}

LWS_VISIBLE int
lws_uv_sigint_cfg(struct lws_context *context, int use_uv_sigint,
		  uv_signal_cb cb)
{
	context->use_ev_sigint = use_uv_sigint;
	if (cb)
		context->lws_uv_sigint_cb = cb;
	else
		context->lws_uv_sigint_cb = &lws_uv_sigint_cb;

	return 0;
}

static void
lws_uv_timeout_cb(uv_timer_t *timer
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	struct lws_context_per_thread *pt = lws_container_of(timer,
			struct lws_context_per_thread, uv_timeout_watcher);

	if (pt->context->requested_kill)
		return;

	lwsl_debug("%s\n", __func__);

	lws_service_fd_tsi(pt->context, NULL, pt->tid);
}

static const int sigs[] = { SIGINT, SIGTERM, SIGSEGV, SIGFPE, SIGHUP };

int
lws_uv_initvhost(struct lws_vhost* vh, struct lws* wsi)
{
	struct lws_context_per_thread *pt;
	int n;

	if (!LWS_LIBUV_ENABLED(vh->context))
		return 0;
	if (!wsi)
		wsi = vh->lserv_wsi;
	if (!wsi)
		return 0;
	if (wsi->w_read.context)
		return 0;

	pt = &vh->context->pt[(int)wsi->tsi];
	if (!pt->io_loop_uv)
		return 0;

	wsi->w_read.context = vh->context;
	n = uv_poll_init_socket(pt->io_loop_uv,
				&wsi->w_read.uv_watcher, wsi->desc.sockfd);
	if (n) {
		lwsl_err("uv_poll_init failed %d, sockfd=%p\n",
				 n, (void *)(lws_intptr_t)wsi->desc.sockfd);

		return -1;
	}
	lws_libuv_io(wsi, LWS_EV_START | LWS_EV_READ);

	return 0;
}

/*
 * This needs to be called after vhosts have been defined.
 *
 * If later, after server start, another vhost is added, this must be
 * called again to bind the vhost
 */

LWS_VISIBLE int
lws_uv_initloop(struct lws_context *context, uv_loop_t *loop, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;
	int status = 0, n, ns, first = 1;

	if (!pt->io_loop_uv) {
		if (!loop) {
			loop = lws_malloc(sizeof(*loop), "libuv loop");
			if (!loop) {
				lwsl_err("OOM\n");
				return -1;
			}
	#if UV_VERSION_MAJOR > 0
			uv_loop_init(loop);
	#else
			lwsl_err("This libuv is too old to work...\n");
			return 1;
	#endif
			pt->ev_loop_foreign = 0;
		} else {
			lwsl_notice(" Using foreign event loop...\n");
			pt->ev_loop_foreign = 1;
		}

		pt->io_loop_uv = loop;
		uv_idle_init(loop, &pt->uv_idle);

		ns = ARRAY_SIZE(sigs);
		if (lws_check_opt(context->options,
				  LWS_SERVER_OPTION_UV_NO_SIGSEGV_SIGFPE_SPIN))
			ns = 2;

		if (pt->context->use_ev_sigint) {
			assert(ns <= (int)ARRAY_SIZE(pt->signals));
			for (n = 0; n < ns; n++) {
				uv_signal_init(loop, &pt->signals[n]);
				pt->signals[n].data = pt->context;
				uv_signal_start(&pt->signals[n],
						context->lws_uv_sigint_cb,
						sigs[n]);
			}
		}
	} else
		first = 0;

	if (lws_create_event_pipes(context))
		goto bail;

	/*
	 * Initialize the accept wsi read watcher with all the listening sockets
	 * and register a callback for read operations
	 *
	 * We have to do it here because the uv loop(s) are not
	 * initialized until after context creation.
	 */
	while (vh) {
		if (lws_uv_initvhost(vh, vh->lserv_wsi) == -1)
			return -1;
		vh = vh->vhost_next;
	}

	if (first) {
		uv_timer_init(pt->io_loop_uv, &pt->uv_timeout_watcher);
		uv_timer_start(&pt->uv_timeout_watcher, lws_uv_timeout_cb,
			       10, 1000);
	}

	return status;

bail:
	return -1;
}

static void lws_uv_close_cb(uv_handle_t *handle)
{
}

static void lws_uv_walk_cb(uv_handle_t *handle, void *arg)
{
	if (!uv_is_closing(handle))
		uv_close(handle, lws_uv_close_cb);
}

LWS_VISIBLE void
lws_close_all_handles_in_loop(uv_loop_t *loop)
{
	uv_walk(loop, lws_uv_walk_cb, NULL);
}

void
lws_libuv_destroyloop(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	int m, budget = 100, ns;

	if (!lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV))
		return;

	if (!pt->io_loop_uv)
		return;

	if (context->use_ev_sigint) {
		uv_signal_stop(&pt->w_sigint.uv_watcher);

		ns = ARRAY_SIZE(sigs);
		if (lws_check_opt(context->options,
				  LWS_SERVER_OPTION_UV_NO_SIGSEGV_SIGFPE_SPIN))
			ns = 2;

		for (m = 0; m < ns; m++) {
			uv_signal_stop(&pt->signals[m]);
			uv_close((uv_handle_t *)&pt->signals[m], lws_uv_close_cb);
		}
	}

	uv_timer_stop(&pt->uv_timeout_watcher);
	uv_close((uv_handle_t *)&pt->uv_timeout_watcher, lws_uv_close_cb);

	uv_idle_stop(&pt->uv_idle);
	uv_close((uv_handle_t *)&pt->uv_idle, lws_uv_close_cb);

	if (pt->ev_loop_foreign)
		return;

	while (budget-- && uv_run(pt->io_loop_uv, UV_RUN_NOWAIT))
		;

	uv_stop(pt->io_loop_uv);
	uv_walk(pt->io_loop_uv, lws_uv_walk_cb, NULL);
	while (uv_run(pt->io_loop_uv, UV_RUN_NOWAIT))
		;
#if UV_VERSION_MAJOR > 0
	m = uv_loop_close(pt->io_loop_uv);
	if (m == UV_EBUSY)
		lwsl_err("%s: uv_loop_close: UV_EBUSY\n", __func__);
#endif
	lws_free(pt->io_loop_uv);
}

void
lws_libuv_accept(struct lws *wsi, lws_sock_file_fd_type desc)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (!LWS_LIBUV_ENABLED(context))
		return;

	wsi->w_read.context = context;
	if (wsi->mode == LWSCM_RAW_FILEDESC || wsi->event_pipe)
		uv_poll_init(pt->io_loop_uv, &wsi->w_read.uv_watcher,
			     (int)(long long)desc.filefd);
	else
		uv_poll_init_socket(pt->io_loop_uv, &wsi->w_read.uv_watcher,
				    desc.sockfd);
}

void
lws_libuv_io(struct lws *wsi, int flags)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws_io_watcher *w = &wsi->w_read;
//#if defined(WIN32) || defined(_WIN32)
//	int current_events = w->uv_watcher.events &
//			     (UV_READABLE | UV_WRITABLE);
//#else
	int current_events = w->actual_events & (UV_READABLE | UV_WRITABLE);
//#endif

	if (!LWS_LIBUV_ENABLED(context))
		return;

	// w->context is set after the loop is initialized

	if (!pt->io_loop_uv || !w->context) {
		lwsl_info("%s: no io loop yet\n", __func__);
		return;
	}

	if (!((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	      (flags & (LWS_EV_READ | LWS_EV_WRITE)))) {
		lwsl_err("%s: assert: flags %d", __func__, flags);
		assert(0);
	}

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

	w->actual_events = current_events;
}

int
lws_libuv_init_fd_table(struct lws_context *context)
{
	int n;

	if (!LWS_LIBUV_ENABLED(context))
		return 0;

	for (n = 0; n < context->count_threads; n++)
		context->pt[n].w_sigint.context = context;

	return 1;
}

LWS_VISIBLE void
lws_libuv_run(const struct lws_context *context, int tsi)
{
	if (context->pt[tsi].io_loop_uv && LWS_LIBUV_ENABLED(context))
		uv_run(context->pt[tsi].io_loop_uv, 0);
}

LWS_VISIBLE void
lws_libuv_stop_without_kill(const struct lws_context *context, int tsi)
{
	if (context->pt[tsi].io_loop_uv && LWS_LIBUV_ENABLED(context))
		uv_stop(context->pt[tsi].io_loop_uv);
}

static void
lws_libuv_kill(const struct lws_context *context)
{
	int n;

	for (n = 0; n < context->count_threads; n++)
		if (context->pt[n].io_loop_uv &&
		    LWS_LIBUV_ENABLED(context))
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

	if (context->requested_kill)
		return;

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

	lwsl_info("%s: feels everything closed\n", __func__);
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
	struct lws *n = NULL, *wsi = (struct lws *)(((char *)handle) -
			  (char *)(&n->w_read.uv_watcher));
	struct lws_context *context = lws_get_context(wsi);
	int lspd = 0;

	if (wsi->mode == LWSCM_SERVER_LISTENER &&
	    wsi->context->deprecated) {
		lspd = 1;
		context->deprecation_pending_listen_close_count--;
		if (!context->deprecation_pending_listen_close_count)
			lspd = 2;
	}

	lws_close_free_wsi_final(wsi);

	if (lspd == 2 && context->deprecation_cb) {
		lwsl_notice("calling deprecation callback\n");
		context->deprecation_cb();
	}

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

static void
lws_libuv_closewsi_m(uv_handle_t* handle)
{
	lws_sockfd_type sockfd = (lws_sockfd_type)(lws_intptr_t)handle->data;

	compatible_close(sockfd);
}

void
lws_libuv_closehandle_manually(struct lws *wsi)
{
	uv_handle_t *h = (void *)&wsi->w_read.uv_watcher;

	h->data = (void *)(lws_intptr_t)wsi->desc.sockfd;
	/* required to defer actual deletion until libuv has processed it */
	uv_close((uv_handle_t*)&wsi->w_read.uv_watcher, lws_libuv_closewsi_m);
}

int
lws_libuv_check_watcher_active(struct lws *wsi)
{
	uv_handle_t *h = (void *)&wsi->w_read.uv_watcher;

	return uv_is_active(h);
}


#if defined(LWS_WITH_PLUGINS) && (UV_VERSION_MAJOR > 0)

LWS_VISIBLE int
lws_plat_plugins_init(struct lws_context *context, const char * const *d)
{
	struct lws_plugin_capability lcaps;
	struct lws_plugin *plugin;
	lws_plugin_init_func initfunc;
	int m, ret = 0;
	void *v;
	uv_dirent_t dent;
	uv_fs_t req;
	char path[256];
	uv_lib_t lib;
	int pofs = 0;

#if  defined(__MINGW32__) || !defined(WIN32)
	pofs = 3;
#endif

	lib.errmsg = NULL;
	lib.handle = NULL;

	uv_loop_init(&context->pu_loop);

	lwsl_notice("  Plugins:\n");

	while (d && *d) {

		lwsl_notice("  Scanning %s\n", *d);
		m =uv_fs_scandir(&context->pu_loop, &req, *d, 0, NULL);
		if (m < 1) {
			lwsl_err("Scandir on %s failed\n", *d);
			return 1;
		}

		while (uv_fs_scandir_next(&req, &dent) != UV_EOF) {
			if (strlen(dent.name) < 7)
				continue;

			lwsl_notice("   %s\n", dent.name);

			lws_snprintf(path, sizeof(path) - 1, "%s/%s", *d,
				     dent.name);
			if (uv_dlopen(path, &lib)) {
				uv_dlerror(&lib);
				lwsl_err("Error loading DSO: %s\n", lib.errmsg);
				uv_dlclose(&lib);
				goto bail;
			}

			/* we could open it, can we get his init function? */

#if !defined(WIN32) && !defined(__MINGW32__)
			m = lws_snprintf(path, sizeof(path) - 1, "init_%s",
				     dent.name + pofs /* snip lib... */);
			path[m - 3] = '\0'; /* snip the .so */
#else
			m = lws_snprintf(path, sizeof(path) - 1, "init_%s",
				     dent.name + pofs);
			path[m - 4] = '\0'; /* snip the .dll */
#endif
			if (uv_dlsym(&lib, path, &v)) {
				uv_dlerror(&lib);
				lwsl_err("Failed to get %s on %s: %s", path,
						dent.name, lib.errmsg);
				uv_dlclose(&lib);
				goto bail;
			}
			initfunc = (lws_plugin_init_func)v;
			lcaps.api_magic = LWS_PLUGIN_API_MAGIC;
			m = initfunc(context, &lcaps);
			if (m) {
				lwsl_err("Init %s failed %d\n", dent.name, m);
				goto skip;
			}

			plugin = lws_malloc(sizeof(*plugin), "plugin");
			if (!plugin) {
				uv_dlclose(&lib);
				lwsl_err("OOM\n");
				goto bail;
			}
			plugin->list = context->plugin_list;
			context->plugin_list = plugin;
			strncpy(plugin->name, dent.name, sizeof(plugin->name) - 1);
			plugin->name[sizeof(plugin->name) - 1] = '\0';
			plugin->lib = lib;
			plugin->caps = lcaps;
			context->plugin_protocol_count += lcaps.count_protocols;
			context->plugin_extension_count += lcaps.count_extensions;

			continue;

skip:
			uv_dlclose(&lib);
		}
bail:
		uv_fs_req_cleanup(&req);
		d++;
	}

	return ret;
}

LWS_VISIBLE int
lws_plat_plugins_destroy(struct lws_context *context)
{
	struct lws_plugin *plugin = context->plugin_list, *p;
	lws_plugin_destroy_func func;
	char path[256];
	int pofs = 0;
	void *v;
	int m;

#if  defined(__MINGW32__) || !defined(WIN32)
	pofs = 3;
#endif

	if (!plugin)
		return 0;

	while (plugin) {
		p = plugin;

#if !defined(WIN32) && !defined(__MINGW32__)
		m = lws_snprintf(path, sizeof(path) - 1, "destroy_%s",
				 plugin->name + pofs);
		path[m - 3] = '\0';
#else
		m = lws_snprintf(path, sizeof(path) - 1, "destroy_%s",
				 plugin->name + pofs);
		path[m - 4] = '\0';
#endif

		if (uv_dlsym(&plugin->lib, path, &v)) {
			uv_dlerror(&plugin->lib);
			lwsl_err("Failed to get %s on %s: %s", path,
					plugin->name, plugin->lib.errmsg);
		} else {
			func = (lws_plugin_destroy_func)v;
			m = func(context);
			if (m)
				lwsl_err("Destroying %s failed %d\n",
						plugin->name, m);
		}

		uv_dlclose(&p->lib);
		plugin = p->list;
		p->list = NULL;
		free(p);
	}

	context->plugin_list = NULL;

	while (uv_loop_close(&context->pu_loop))
		;

	return 0;
}

#endif

