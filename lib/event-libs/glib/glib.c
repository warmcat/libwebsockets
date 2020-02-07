/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

#include <glib-unix.h>

#define wsi_to_subclass(_w)	  ((_w)->w_read.glib.source)
#define wsi_to_gsource(_w)	  ((GSource *)wsi_to_subclass(_w))
#define pt_to_loop(_pt)		  ((_pt)->glib.loop)
#define pt_to_g_main_context(_pt) g_main_loop_get_context(pt_to_loop(_pt))

static gboolean
lws_glib_idle_timer_cb(void *p);

static gboolean
lws_glib_hrtimer_cb(void *p);

static gboolean
lws_glib_check(GSource *src)
{
	struct lws_io_watcher_glib_subclass *sub =
			(struct lws_io_watcher_glib_subclass *)src;

	return !!g_source_query_unix_fd(src, sub->tag);
}

/*
 * These helpers attach only to the main_context that belongs to the pt's glib
 * mainloop.  The simpler g_timeout_add() and g_idle_add() are forbidden
 * because they implicitly choose the default main context to attach to
 * instead of specifically the loop bound to the pt.
 *
 * https://developer.gnome.org/programming-guidelines/unstable/main-contexts.html.en#what-is-gmaincontext
 */

static int
lws_glib_set_idle(struct lws_context_per_thread *pt)
{
	GSource *gis;

	if (pt->glib.idle_tag)
		return 0;

	gis = g_idle_source_new();
	if (!gis)
		return 1;

	g_source_set_callback(gis, lws_glib_idle_timer_cb, pt, NULL);
	pt->glib.idle_tag = g_source_attach(gis, pt_to_g_main_context(pt));

	return 0;
}

static int
lws_glib_set_timeout(struct lws_context_per_thread *pt, unsigned int ms)
{
	GSource *gts;

	gts = g_timeout_source_new(ms);
	if (!gts)
		return 1;

	g_source_set_callback(gts, lws_glib_hrtimer_cb, pt, NULL);
	pt->glib.hrtimer_tag = g_source_attach(gts, pt_to_g_main_context(pt));

	return 0;
}

static gboolean
lws_glib_dispatch(GSource *src, GSourceFunc x, gpointer userData)
{
	struct lws_io_watcher_glib_subclass *sub =
			(struct lws_io_watcher_glib_subclass *)src;
	struct lws_context_per_thread *pt;
	struct lws_pollfd eventfd;
	GIOCondition cond;

	cond = g_source_query_unix_fd(src, sub->tag);
	eventfd.revents = cond;

	/* translate from glib event namespace to platform */

	if (cond & G_IO_IN)
		eventfd.revents |= LWS_POLLIN;
	if (cond & G_IO_OUT)
		eventfd.revents |= LWS_POLLOUT;
	if (cond & G_IO_ERR)
		eventfd.revents |= LWS_POLLHUP;
	if (cond & G_IO_HUP)
		eventfd.revents |= LWS_POLLHUP;

	eventfd.events = eventfd.revents;
	eventfd.fd = sub->wsi->desc.sockfd;

	lwsl_debug("%s: wsi %p: fd %d, events %d\n", __func__, sub->wsi,
			eventfd.fd, eventfd.revents);

	pt = &sub->wsi->context->pt[(int)sub->wsi->tsi];
	if (pt->is_destroyed)
		return G_SOURCE_CONTINUE;

	lws_service_fd_tsi(sub->wsi->context, &eventfd, sub->wsi->tsi);

	if (!pt->glib.idle_tag)
		lws_glib_set_idle(pt);

	if (pt->destroy_self)
		lws_context_destroy(pt->context);

	return G_SOURCE_CONTINUE;
}

static const GSourceFuncs lws_glib_source_ops = {
    .prepare	= NULL,
    .check	= lws_glib_check,
    .dispatch	= lws_glib_dispatch,
    .finalize	= NULL,
};

/*
 * This is the callback for a timer object that is set to the earliest scheduled
 * lws event... it services any lws scheduled events that are ready, and then
 * resets the event loop timer to the earliest remaining event, if any.
 */

static gboolean
lws_glib_hrtimer_cb(void *p)
{
	struct lws_context_per_thread *pt = (struct lws_context_per_thread *)p;
	unsigned int ms;
	lws_usec_t us;

	lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(&pt->pt_sul_owner, lws_now_usecs());
	if (us) {
		ms = us / LWS_US_PER_MS;
		if (!ms)
			ms = 1;

		lws_glib_set_timeout(pt, ms);
	}

	lws_pt_unlock(pt);

	lws_glib_set_idle(pt);

	return FALSE; /* stop it repeating */
}

static gboolean
lws_glib_idle_timer_cb(void *p)
{
	struct lws_context_per_thread *pt = (struct lws_context_per_thread *)p;

	if (pt->is_destroyed)
		return FALSE;

	lws_service_do_ripe_rxflow(pt);
	lws_glib_hrtimer_cb(pt);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
		/* -1 timeout means just do forced service */
		_lws_plat_service_forced_tsi(pt->context, pt->tid);
		/* still somebody left who wants forced service? */
		if (!lws_service_adjust_timeout(pt->context, 1, pt->tid))
			return TRUE;
	}

	if (pt->destroy_self)
		lws_context_destroy(pt->context);

	/*
	 * For glib, this disables the idle callback.  Otherwise we keep
	 * coming back here immediately endlessly.
	 *
	 * We reenable the idle callback on the next network or scheduled event
	 */

	pt->glib.idle_tag = 0;

	return FALSE;
}

void
lws_glib_sigint_cb(void *ctx)
{
	struct lws_context_per_thread *pt = ctx;

	pt->inside_service = 1;

	if (pt->context->eventlib_signal_cb) {
		pt->context->eventlib_signal_cb(NULL, 0);

		return;
	}
	if (!pt->event_loop_foreign)
		g_main_loop_quit(pt_to_loop(pt));
}

static int
elops_init_context_glib(struct lws_context *context,
			 const struct lws_context_creation_info *info)
{
	int n;

	context->eventlib_signal_cb = info->signal_cb;

	for (n = 0; n < context->count_threads; n++)
		context->pt[n].w_sigint.context = context;

	return 0;
}

static int
elops_accept_glib(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int fd;

	assert(!wsi_to_subclass(wsi));

	wsi_to_subclass(wsi) = (struct lws_io_watcher_glib_subclass *)
			g_source_new((GSourceFuncs *)&lws_glib_source_ops,
						sizeof(*wsi_to_subclass(wsi)));
	if (!wsi_to_subclass(wsi))
		return 1;

	wsi->w_read.context = wsi->context;
	wsi_to_subclass(wsi)->wsi = wsi;

	if (wsi->role_ops->file_handle)
		fd = wsi->desc.filefd;
	else
		fd = wsi->desc.sockfd;

	wsi_to_subclass(wsi)->tag = g_source_add_unix_fd(wsi_to_gsource(wsi),
						fd, (GIOCondition)LWS_POLLIN);
	wsi->w_read.actual_events = LWS_POLLIN;

	g_source_set_callback(wsi_to_gsource(wsi),
			G_SOURCE_FUNC(lws_service_fd), wsi->context, NULL);

	g_source_attach(wsi_to_gsource(wsi), pt_to_g_main_context(pt));

	return 0;
}

static int
elops_init_pt_glib(struct lws_context *context, void *_loop, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;
	GMainLoop *loop = (GMainLoop *)_loop;

	if (!loop)
		loop = g_main_loop_new(NULL, 0);
	else
		context->pt[tsi].event_loop_foreign = 1;

	if (!loop) {
		lwsl_err("%s: creating glib loop failed\n", __func__);

		return -1;
	}

	pt->glib.loop = loop;

	/*
	* Initialize all events with the listening sockets
	* and register a callback for read operations
	*/

	while (vh) {
		if (vh->lserv_wsi)
			elops_accept_glib(vh->lserv_wsi);

		vh = vh->vhost_next;
	}

	lws_glib_set_idle(pt);

	/* Register the signal watcher unless it's a foreign loop */

	if (pt->event_loop_foreign)
		return 0;

	pt->glib.sigint_tag = g_unix_signal_add(SIGINT,
					G_SOURCE_FUNC(lws_glib_sigint_cb), pt);

	return 0;
}

/*
 * We are changing the event wait for this guy
 */

static void
elops_io_glib(struct lws *wsi, int flags)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	GIOCondition cond = wsi->w_read.actual_events | G_IO_ERR;

	if (!pt_to_loop(pt) || wsi->context->being_destroyed || pt->is_destroyed)
		return;

	/*
	 * We are being given individual set / clear operations using
	 * LWS_EV_ common namespace, convert them to glib namespace bitfield
	 */

	if (flags & LWS_EV_READ) {
		if (flags & LWS_EV_STOP)
			cond &= ~(G_IO_IN | G_IO_HUP);
		else
			cond |= G_IO_IN | G_IO_HUP;
	}

	if (flags & LWS_EV_WRITE) {
		if (flags & LWS_EV_STOP)
			cond &= ~G_IO_OUT;
		else
			cond |= G_IO_OUT;
	}

	wsi->w_read.actual_events = cond;

	lwsl_debug("%s: wsi %p, fd %d, 0x%x/0x%x\n", __func__, wsi,
			wsi->desc.sockfd, flags, (int)cond);

	g_source_modify_unix_fd(wsi_to_gsource(wsi), wsi_to_subclass(wsi)->tag,
				cond);
}

static void
elops_run_pt_glib(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];

	if (pt_to_loop(pt))
		g_main_loop_run(pt_to_loop(pt));
}

static void
elops_destroy_wsi_glib(struct lws *wsi)
{
	struct lws_context_per_thread *pt;

	if (!wsi)
		return;

	pt = &wsi->context->pt[(int)wsi->tsi];
	if (pt->is_destroyed)
		return;

	if (!wsi_to_gsource(wsi))
		return;

	if (wsi_to_subclass(wsi)->tag) {
		g_source_remove_unix_fd(wsi_to_gsource(wsi),
					wsi_to_subclass(wsi)->tag);
		wsi_to_subclass(wsi)->tag = NULL;
	}

	g_source_destroy(wsi_to_gsource(wsi));
	wsi_to_subclass(wsi) = NULL;
}

static void
elops_destroy_pt_glib(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_vhost *vh = context->vhost_list;

	if (!pt_to_loop(pt))
		return;

	/*
	 * Free all events with the listening sockets
	 */
	while (vh) {
		if (vh->lserv_wsi)
			elops_destroy_wsi_glib(vh->lserv_wsi);

		vh = vh->vhost_next;
	}

	if (pt->glib.hrtimer_tag)
		g_source_remove(pt->glib.hrtimer_tag);

	if (!pt->event_loop_foreign) {
		g_main_loop_quit(pt_to_loop(pt));
		g_source_remove(pt->glib.sigint_tag);
		g_main_loop_unref(pt_to_loop(pt));
	}

	pt_to_loop(pt) = NULL;
}

static int
elops_destroy_context2_glib(struct lws_context *context)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	int n;

	for (n = 0; n < (int)context->count_threads; n++) {
		if (!pt->event_loop_foreign)
			g_main_loop_quit(pt_to_loop(pt));
		pt++;
	}

	return 0;
}

static int
elops_wsi_logical_close_glib(struct lws *wsi)
{
	elops_destroy_wsi_glib(wsi);

	return 0;
}

struct lws_event_loop_ops event_loop_ops_glib = {
	/* name */			"glib",
	/* init_context */		elops_init_context_glib,
	/* destroy_context1 */		NULL,
	/* destroy_context2 */		elops_destroy_context2_glib,
	/* init_vhost_listen_wsi */	elops_accept_glib,
	/* init_pt */			elops_init_pt_glib,
	/* wsi_logical_close */		elops_wsi_logical_close_glib,
	/* check_client_connect_ok */	NULL,
	/* close_handle_manually */	NULL,
	/* accept */			elops_accept_glib,
	/* io */			elops_io_glib,
	/* run_pt */			elops_run_pt_glib,
	/* destroy_pt */		elops_destroy_pt_glib,
	/* destroy wsi */		elops_destroy_wsi_glib,

	/* flags */			LELOF_DESTROY_FINAL,
};
