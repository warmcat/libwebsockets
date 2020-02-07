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
lws_uv_sultimer_cb(uv_timer_t *timer
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	struct lws_context_per_thread *pt = lws_container_of(timer,
				struct lws_context_per_thread, uv.sultimer);
	lws_usec_t us;

	lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
	if (us)
		uv_timer_start(&pt->uv.sultimer, lws_uv_sultimer_cb,
			       LWS_US_TO_MS(us), 0);
	lws_pt_unlock(pt);
}

static void
lws_uv_idle(uv_idle_t *handle
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	struct lws_context_per_thread *pt = lws_container_of(handle,
					struct lws_context_per_thread, uv.idle);
	lws_usec_t us;

	lws_service_do_ripe_rxflow(pt);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!lws_service_adjust_timeout(pt->context, 1, pt->tid))
		/* -1 timeout means just do forced service */
		_lws_plat_service_forced_tsi(pt->context, pt->tid);

	/* account for sultimer */

	lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
	if (us)
		uv_timer_start(&pt->uv.sultimer, lws_uv_sultimer_cb,
			       LWS_US_TO_MS(us), 0);
	lws_pt_unlock(pt);

	/* there is nobody who needs service forcing, shut down idle */
	uv_idle_stop(handle);
}

static void
lws_io_cb(uv_poll_t *watcher, int status, int revents)
{
	struct lws *wsi = (struct lws *)((uv_handle_t *)watcher)->data;
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_pollfd eventfd;

	if (pt->is_destroyed)
		return;

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
	lws_service_fd_tsi(context, &eventfd, wsi->tsi);

	if (pt->destroy_self) {
		lws_context_destroy(pt->context);
		return;
	}

	uv_idle_start(&pt->uv.idle, lws_uv_idle);
}

/*
 * This does not actually stop the event loop.  The reason is we have to pass
 * libuv handle closures through its event loop.  So this tries to close all
 * wsi, and set a flag; when all the wsi closures are finalized then we
 * actually stop the libuv event loops.
 */
static void
lws_libuv_stop(struct lws_context *context)
{
	struct lws_context_per_thread *pt;
	int n, m;

	lwsl_err("%s\n", __func__);

	if (context->requested_kill) {
		lwsl_err("%s: ignoring\n", __func__);
		return;
	}

	context->requested_kill = 1;

	m = context->count_threads;
	context->being_destroyed = 1;

	/*
	 * Phase 1: start the close of every dynamic uv handle
	 */

	while (m--) {
		pt = &context->pt[m];

		if (pt->pipe_wsi) {
			uv_poll_stop(pt->pipe_wsi->w_read.uv.pwatcher);
			lws_destroy_event_pipe(pt->pipe_wsi);
			pt->pipe_wsi = NULL;
		}

		for (n = 0; (unsigned int)n < context->pt[m].fds_count; n++) {
			struct lws *wsi = wsi_from_fd(context, pt->fds[n].fd);

			if (!wsi)
				continue;
			lws_close_free_wsi(wsi,
				LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY,
				__func__ /* no protocol close */);
			n--;
		}
	}

	lwsl_info("%s: started closing all wsi\n", __func__);

	/* we cannot have completed... there are at least the cancel pipes */
}

static void
lws_uv_signal_handler(uv_signal_t *watcher, int signum)
{
	struct lws_context *context = watcher->data;

	if (context->eventlib_signal_cb) {
		context->eventlib_signal_cb((void *)watcher, signum);

		return;
	}

	lwsl_err("internal signal handler caught signal %d\n", signum);
	lws_libuv_stop(watcher->data);
}

static const int sigs[] = { SIGINT, SIGTERM, SIGSEGV, SIGFPE, SIGHUP };

/*
 * Closing Phase 2: Close callback for a static UV asset
 */

static void
lws_uv_close_cb_sa(uv_handle_t *handle)
{
	struct lws_context *context =
			LWS_UV_REFCOUNT_STATIC_HANDLE_TO_CONTEXT(handle);
	int n;

	lwsl_info("%s: sa left %d: dyn left: %d\n", __func__,
		    context->count_event_loop_static_asset_handles,
		    context->count_wsi_allocated);

	/* any static assets left? */

	if (LWS_UV_REFCOUNT_STATIC_HANDLE_DESTROYED(handle) ||
	    context->count_wsi_allocated)
		return;

	/*
	 * That's it... all wsi were down, and now every
	 * static asset lws had a UV handle for is down.
	 *
	 * Stop the loop so we can get out of here.
	 */

	for (n = 0; n < context->count_threads; n++) {
		struct lws_context_per_thread *pt = &context->pt[n];

		if (pt->uv.io_loop && !pt->event_loop_foreign)
			uv_stop(pt->uv.io_loop);
	}

	if (!context->pt[0].event_loop_foreign) {
		lwsl_info("%s: calling lws_context_destroy2\n", __func__);
		lws_context_destroy2(context);
	}

	lwsl_info("%s: all done\n", __func__);
}

/*
 * These must be called by protocols that want to use libuv objects directly...
 *
 * .... when the libuv object is created...
 */

void
lws_libuv_static_refcount_add(uv_handle_t *h, struct lws_context *context)
{
	LWS_UV_REFCOUNT_STATIC_HANDLE_NEW(h, context);
}

/*
 * ... and in the close callback when the object is closed.
 */

void
lws_libuv_static_refcount_del(uv_handle_t *h)
{
	lws_uv_close_cb_sa(h);
}


static void lws_uv_close_cb(uv_handle_t *handle)
{
}

static void lws_uv_walk_cb(uv_handle_t *handle, void *arg)
{
	if (!uv_is_closing(handle))
		uv_close(handle, lws_uv_close_cb);
}

void
lws_close_all_handles_in_loop(uv_loop_t *loop)
{
	uv_walk(loop, lws_uv_walk_cb, NULL);
}


void
lws_libuv_stop_without_kill(const struct lws_context *context, int tsi)
{
	if (context->pt[tsi].uv.io_loop)
		uv_stop(context->pt[tsi].uv.io_loop);
}



uv_loop_t *
lws_uv_getloop(struct lws_context *context, int tsi)
{
	if (context->pt[tsi].uv.io_loop)
		return context->pt[tsi].uv.io_loop;

	return NULL;
}

int
lws_libuv_check_watcher_active(struct lws *wsi)
{
	uv_handle_t *h = (uv_handle_t *)wsi->w_read.uv.pwatcher;

	if (!h)
		return 0;

	return uv_is_active(h);
}


#if defined(LWS_WITH_PLUGINS) && (UV_VERSION_MAJOR > 0)

int
lws_uv_plugins_init(struct lws_context *context, const char * const *d)
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

	uv_loop_init(&context->uv.loop);

	lwsl_notice("  Plugins:\n");

	while (d && *d) {

		lwsl_notice("  Scanning %s\n", *d);
		m =uv_fs_scandir(&context->uv.loop, &req, *d, 0, NULL);
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
				lwsl_err("%s: Failed to get '%s' on %s: %s\n",
					 __func__, path, dent.name, lib.errmsg);
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
			lws_strncpy(plugin->name, dent.name, sizeof(plugin->name));
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

int
lws_uv_plugins_destroy(struct lws_context *context)
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

	while (uv_loop_close(&context->uv.loop))
		;

	return 0;
}

#endif

static int
elops_init_context_uv(struct lws_context *context,
		      const struct lws_context_creation_info *info)
{
	int n;

	context->eventlib_signal_cb = info->signal_cb;

	for (n = 0; n < context->count_threads; n++)
		context->pt[n].w_sigint.context = context;

	return 0;
}

static int
elops_destroy_context1_uv(struct lws_context *context)
{
	struct lws_context_per_thread *pt;
	int n, m = 0;

	for (n = 0; n < context->count_threads; n++) {
		int budget = 10000;
		pt = &context->pt[n];

		/* only for internal loops... */

		if (!pt->event_loop_foreign) {

			while (budget-- && (m = uv_run(pt->uv.io_loop,
						  UV_RUN_NOWAIT)))
					;
			if (m)
				lwsl_info("%s: tsi %d: not all closed\n",
					 __func__, n);

		}
	}

	/* call destroy2 if internal loop */
	return !context->pt[0].event_loop_foreign;
}

static int
elops_destroy_context2_uv(struct lws_context *context)
{
	struct lws_context_per_thread *pt;
	int n, internal = 0;

	for (n = 0; n < context->count_threads; n++) {
		pt = &context->pt[n];

		/* only for internal loops... */

		if (!pt->event_loop_foreign && pt->uv.io_loop) {
			internal = 1;
			if (!context->finalize_destroy_after_internal_loops_stopped)
				uv_stop(pt->uv.io_loop);
			else {
#if UV_VERSION_MAJOR > 0
				uv_loop_close(pt->uv.io_loop);
#endif
				lws_free_set_NULL(pt->uv.io_loop);
			}
		}
	}

	return internal;
}

static int
elops_wsi_logical_close_uv(struct lws *wsi)
{
	if (!lws_socket_is_valid(wsi->desc.sockfd))
		return 0;

	if (wsi->listener || wsi->event_pipe) {
		lwsl_debug("%s: %p: %d %d stop listener / pipe poll\n",
			   __func__, wsi, wsi->listener, wsi->event_pipe);
		if (wsi->w_read.uv.pwatcher)
			uv_poll_stop(wsi->w_read.uv.pwatcher);
	}
	lwsl_debug("%s: lws_libuv_closehandle: wsi %p\n", __func__, wsi);
	/*
	 * libuv has to do his own close handle processing asynchronously
	 */
	lws_libuv_closehandle(wsi);

	return 1; /* do not complete the wsi close, uv close cb will do it */
}

static int
elops_check_client_connect_ok_uv(struct lws *wsi)
{
	if (lws_libuv_check_watcher_active(wsi)) {
		lwsl_warn("Waiting for libuv watcher to close\n");
		return 1;
	}

	return 0;
}

static void
lws_libuv_closewsi_m(uv_handle_t* handle)
{
	lws_sockfd_type sockfd = (lws_sockfd_type)(lws_intptr_t)handle->data;
	lwsl_debug("%s: sockfd %d\n", __func__, sockfd);
	compatible_close(sockfd);
	lws_free(handle);
}

static void
elops_close_handle_manually_uv(struct lws *wsi)
{
	uv_handle_t *h = (uv_handle_t *)wsi->w_read.uv.pwatcher;

	lwsl_debug("%s: lws_libuv_closehandle: wsi %p\n", __func__, wsi);

	/*
	 * the "manual" variant only closes the handle itself and the
	 * related fd.  handle->data is the fd.
	 */
	h->data = (void *)(lws_intptr_t)wsi->desc.sockfd;

	/*
	 * We take responsibility to close / destroy these now.
	 * Remove any trace from the wsi.
	 */

	wsi->desc.sockfd = LWS_SOCK_INVALID;
	wsi->w_read.uv.pwatcher = NULL;
	wsi->told_event_loop_closed = 1;

	uv_close(h, lws_libuv_closewsi_m);
}

static int
elops_accept_uv(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	wsi->w_read.context = wsi->context;

	wsi->w_read.uv.pwatcher =
		lws_malloc(sizeof(*wsi->w_read.uv.pwatcher), "uvh");
	if (!wsi->w_read.uv.pwatcher)
		return -1;

	if (wsi->role_ops->file_handle)
		uv_poll_init(pt->uv.io_loop, wsi->w_read.uv.pwatcher,
			     (int)(long long)wsi->desc.filefd);
	else
		uv_poll_init_socket(pt->uv.io_loop,
				    wsi->w_read.uv.pwatcher,
				    wsi->desc.sockfd);

	((uv_handle_t *)wsi->w_read.uv.pwatcher)->data = (void *)wsi;

	return 0;
}

static void
elops_io_uv(struct lws *wsi, int flags)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws_io_watcher *w = &wsi->w_read;
	int current_events = w->actual_events & (UV_READABLE | UV_WRITABLE);

	lwsl_debug("%s: %p: %d\n", __func__, wsi, flags);

	/* w->context is set after the loop is initialized */

	if (!pt->uv.io_loop || !w->context) {
		lwsl_info("%s: no io loop yet\n", __func__);
		return;
	}

	if (!((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	      (flags & (LWS_EV_READ | LWS_EV_WRITE)))) {
		lwsl_err("%s: assert: flags %d", __func__, flags);
		assert(0);
	}

	if (!w->uv.pwatcher || wsi->told_event_loop_closed) {
		lwsl_err("%s: no watcher\n", __func__);

		return;
	}

	if (flags & LWS_EV_START) {
		if (flags & LWS_EV_WRITE)
			current_events |= UV_WRITABLE;

		if (flags & LWS_EV_READ)
			current_events |= UV_READABLE;

		uv_poll_start(w->uv.pwatcher, current_events, lws_io_cb);
	} else {
		if (flags & LWS_EV_WRITE)
			current_events &= ~UV_WRITABLE;

		if (flags & LWS_EV_READ)
			current_events &= ~UV_READABLE;

		if (!(current_events & (UV_READABLE | UV_WRITABLE)))
			uv_poll_stop(w->uv.pwatcher);
		else
			uv_poll_start(w->uv.pwatcher, current_events,
				      lws_io_cb);
	}

	w->actual_events = current_events;
}

static int
elops_init_vhost_listen_wsi_uv(struct lws *wsi)
{
	struct lws_context_per_thread *pt;
	int n;

	if (!wsi)
		return 0;
	if (wsi->w_read.context)
		return 0;

	pt = &wsi->context->pt[(int)wsi->tsi];
	if (!pt->uv.io_loop)
		return 0;

	wsi->w_read.context = wsi->context;

	wsi->w_read.uv.pwatcher =
		lws_malloc(sizeof(*wsi->w_read.uv.pwatcher), "uvh");
	if (!wsi->w_read.uv.pwatcher)
		return -1;

	n = uv_poll_init_socket(pt->uv.io_loop, wsi->w_read.uv.pwatcher,
				   wsi->desc.sockfd);
	if (n) {
		lwsl_err("uv_poll_init failed %d, sockfd=%p\n", n,
				(void *)(lws_intptr_t)wsi->desc.sockfd);

		return -1;
	}

	((uv_handle_t *)wsi->w_read.uv.pwatcher)->data = (void *)wsi;

	elops_io_uv(wsi, LWS_EV_START | LWS_EV_READ);

	return 0;
}

static void
elops_run_pt_uv(struct lws_context *context, int tsi)
{
	if (context->pt[tsi].uv.io_loop)
		uv_run(context->pt[tsi].uv.io_loop, 0);
}

static void
elops_destroy_pt_uv(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	int m, ns;

	lwsl_info("%s: %d\n", __func__, tsi);

	if (!lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV))
		return;

	if (!pt->uv.io_loop)
		return;

	if (pt->event_loop_destroy_processing_done)
		return;

	pt->event_loop_destroy_processing_done = 1;

	if (!pt->event_loop_foreign) {
		uv_signal_stop(&pt->w_sigint.uv.watcher);

		ns = LWS_ARRAY_SIZE(sigs);
		if (lws_check_opt(context->options,
				  LWS_SERVER_OPTION_UV_NO_SIGSEGV_SIGFPE_SPIN))
			ns = 2;

		for (m = 0; m < ns; m++) {
			uv_signal_stop(&pt->uv.signals[m]);
			uv_close((uv_handle_t *)&pt->uv.signals[m],
				 lws_uv_close_cb_sa);
		}
	} else
		lwsl_debug("%s: not closing pt signals\n", __func__);

	uv_timer_stop(&pt->uv.sultimer);
	uv_close((uv_handle_t *)&pt->uv.sultimer, lws_uv_close_cb_sa);

	uv_idle_stop(&pt->uv.idle);
	uv_close((uv_handle_t *)&pt->uv.idle, lws_uv_close_cb_sa);
}

/*
 * This needs to be called after vhosts have been defined.
 *
 * If later, after server start, another vhost is added, this must be
 * called again to bind the vhost
 */

int
elops_init_pt_uv(struct lws_context *context, void *_loop, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;
	int status = 0, n, ns, first = 1;
	uv_loop_t *loop = (uv_loop_t *)_loop;

	if (!pt->uv.io_loop) {
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
			pt->event_loop_foreign = 0;
		} else {
			lwsl_notice(" Using foreign event loop...\n");
			pt->event_loop_foreign = 1;
		}

		pt->uv.io_loop = loop;
		uv_idle_init(loop, &pt->uv.idle);
		LWS_UV_REFCOUNT_STATIC_HANDLE_NEW(&pt->uv.idle, context);


		ns = LWS_ARRAY_SIZE(sigs);
		if (lws_check_opt(context->options,
				  LWS_SERVER_OPTION_UV_NO_SIGSEGV_SIGFPE_SPIN))
			ns = 2;

		if (!pt->event_loop_foreign) {
			assert(ns <= (int)LWS_ARRAY_SIZE(pt->uv.signals));
			for (n = 0; n < ns; n++) {
				uv_signal_init(loop, &pt->uv.signals[n]);
				LWS_UV_REFCOUNT_STATIC_HANDLE_NEW(&pt->uv.signals[n],
								  context);
				pt->uv.signals[n].data = pt->context;
				uv_signal_start(&pt->uv.signals[n],
						lws_uv_signal_handler, sigs[n]);
			}
		}
	} else
		first = 0;

	/*
	 * Initialize the accept wsi read watcher with all the listening sockets
	 * and register a callback for read operations
	 *
	 * We have to do it here because the uv loop(s) are not
	 * initialized until after context creation.
	 */
	while (vh) {
		if (elops_init_vhost_listen_wsi_uv(vh->lserv_wsi) == -1)
			return -1;
		vh = vh->vhost_next;
	}

	if (!first)
		return status;

	uv_timer_init(pt->uv.io_loop, &pt->uv.sultimer);
	LWS_UV_REFCOUNT_STATIC_HANDLE_NEW(&pt->uv.sultimer, context);

	return status;
}

static void
lws_libuv_closewsi(uv_handle_t* handle)
{
	struct lws *wsi = (struct lws *)handle->data;
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
#if defined(LWS_WITH_SERVER)
	int lspd = 0;
#endif

	lwsl_info("%s: %p\n", __func__, wsi);

	/*
	 * We get called back here for every wsi that closes
	 */

#if defined(LWS_WITH_SERVER)
	if (wsi->role_ops == &role_ops_listen && wsi->context->deprecated) {
		lspd = 1;
		context->deprecation_pending_listen_close_count--;
		if (!context->deprecation_pending_listen_close_count)
			lspd = 2;
	}
#endif

	lws_pt_lock(pt, __func__);
	__lws_close_free_wsi_final(wsi);
	lws_pt_unlock(pt);

	/* it's our job to close the handle finally */
	lws_free(handle);

#if defined(LWS_WITH_SERVER)
	if (lspd == 2 && context->deprecation_cb) {
		lwsl_notice("calling deprecation callback\n");
		context->deprecation_cb();
	}
#endif

	lwsl_info("%s: sa left %d: dyn left: %d (rk %d)\n", __func__,
		    context->count_event_loop_static_asset_handles,
		    context->count_wsi_allocated, context->requested_kill);

	/*
	 * eventually, we closed all the wsi...
	 */

	if (context->requested_kill && !context->count_wsi_allocated) {
		struct lws_vhost *vh = context->vhost_list;
		int m;

		/*
		 * Start Closing Phase 2: close of static handles
		 */

		lwsl_info("%s: all lws dynamic handles down, closing static\n",
			    __func__);

		for (m = 0; m < context->count_threads; m++)
			elops_destroy_pt_uv(context, m);

		/* protocols may have initialized libuv objects */

		while (vh) {
			lws_vhost_destroy1(vh);
			vh = vh->vhost_next;
		}

		if (!context->count_event_loop_static_asset_handles &&
		    context->pt[0].event_loop_foreign) {
			lwsl_info("%s: call lws_context_destroy2\n", __func__);
			lws_context_destroy2(context);
		}
	}
}

void
lws_libuv_closehandle(struct lws *wsi)
{
	uv_handle_t* handle;

	if (!wsi->w_read.uv.pwatcher)
		return;

	if (wsi->told_event_loop_closed) {
	//	assert(0);
		return;
	}

	lwsl_debug("%s: %p\n", __func__, wsi);

	wsi->told_event_loop_closed = 1;

	/*
	 * The normal close path attaches the related wsi as the
	 * handle->data.
	 */

	handle = (uv_handle_t *)wsi->w_read.uv.pwatcher;

	/* ensure we can only do this once */

	wsi->w_read.uv.pwatcher = NULL;

	uv_close(handle, lws_libuv_closewsi);
}

struct lws_event_loop_ops event_loop_ops_uv = {
	/* name */			"libuv",
	/* init_context */		elops_init_context_uv,
	/* destroy_context1 */		elops_destroy_context1_uv,
	/* destroy_context2 */		elops_destroy_context2_uv,
	/* init_vhost_listen_wsi */	elops_init_vhost_listen_wsi_uv,
	/* init_pt */			elops_init_pt_uv,
	/* wsi_logical_close */		elops_wsi_logical_close_uv,
	/* check_client_connect_ok */	elops_check_client_connect_ok_uv,
	/* close_handle_manually */	elops_close_handle_manually_uv,
	/* accept */			elops_accept_uv,
	/* io */			elops_io_uv,
	/* run_pt */			elops_run_pt_uv,
	/* destroy_pt */		elops_destroy_pt_uv,
	/* destroy wsi */		NULL,

	/* flags */			0,
};
