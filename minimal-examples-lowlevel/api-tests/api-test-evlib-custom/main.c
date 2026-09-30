/*
 * lws-api-test-evlib-custom
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An app that brings its own event library (info->event_lib_custom) and its
 * own loop object (info->foreign_loops) gets exactly that: lws binds the pt to
 * the custom lib with the app's loop object, registers its fds with it, and
 * unregisters them all again at context destroy.
 *
 * ctest also runs this with LWS_EVLIB=uv in the environment.  LWS_EVLIB only
 * picks an event lib for apps that did not choose one; the app's loop object
 * here is its own struct, not a uv_loop_t, so the custom lib must still be the
 * one in use.
 */

#include <libwebsockets.h>
#include <string.h>

#define EVC_MAGIC 0x45564c43u /* "EVLC" */

/* the app's own "event loop" object, handed to lws as the foreign loop */

struct app_loop {
	uint32_t		magic;
	int			fds;		/* currently registered */
	int			fds_peak;
	int			init_pt;	/* init_pt calls for this loop */
};

/* our part of each pt */

struct evc_pt {
	struct app_loop		*loop;
};

static struct app_loop app_loop;

static int
evc_init_pt(struct lws_context *cx, void *_loop, int tsi)
{
	struct evc_pt *priv = (struct evc_pt *)lws_evlib_tsi_to_evlib_pt(cx, tsi);
	struct app_loop *al = (struct app_loop *)_loop;

	if (!al || al->magic != EVC_MAGIC || tsi) {
		lwsl_err("%s: bound to unexpected loop %p, tsi %d\n",
			 __func__, _loop, tsi);
		return 1;
	}

	priv->loop = al;
	al->init_pt++;

	return 0;
}

static int
evc_sock_accept(struct lws *wsi)
{
	struct evc_pt *priv = (struct evc_pt *)lws_evlib_wsi_to_evlib_pt(wsi);

	if (++priv->loop->fds > priv->loop->fds_peak)
		priv->loop->fds_peak = priv->loop->fds;

	return 0;
}

static void
evc_io(struct lws *wsi, unsigned int flags)
{
	/* nothing runs the loop in this test */
	(void)wsi;
	(void)flags;
}

static int
evc_wsi_logical_close(struct lws *wsi)
{
	struct evc_pt *priv = (struct evc_pt *)lws_evlib_wsi_to_evlib_pt(wsi);

	priv->loop->fds--;

	return 0;
}

static const struct lws_event_loop_ops evc_ops = {
	.name			= "api-test-custom",
	.init_pt		= evc_init_pt,
	.init_vhost_listen_wsi	= evc_sock_accept,
	.sock_accept		= evc_sock_accept,
	.io			= evc_io,
	.wsi_logical_close	= evc_wsi_logical_close,
	.evlib_size_pt		= sizeof(struct evc_pt),
};

static const lws_plugin_evlib_t evlib_custom = {
	.hdr = {
		.name		= "api-test custom event loop",
		._class		= "lws_evlib_plugin",
		.lws_build_hash	= LWS_BUILD_HASH,
		.api_magic	= LWS_PLUGIN_API_MAGIC
	},
	.ops	= &evc_ops
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	void *foreign_loops[1];
	const char *e;
	int fail = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	e = getenv("LWS_EVLIB");
	lwsl_user("LWS API selftest: custom event lib (LWS_EVLIB '%s')\n",
		  e ? e : "");

	app_loop.magic		= EVC_MAGIC;
	foreign_loops[0]	= &app_loop;

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.event_lib_custom	= &evlib_custom;
	info.foreign_loops	= foreign_loops;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		fail = 1;
		goto done;
	}

	if (app_loop.init_pt != 1) {
		lwsl_err("%s: custom init_pt ran %d times, expected once\n",
			 __func__, app_loop.init_pt);
		fail = 1;
	}

	/* the event pipe at least has been registered with the custom lib */

	if (app_loop.fds < 1) {
		lwsl_err("%s: no fds registered with the custom lib\n",
			 __func__);
		fail = 1;
	}

	lws_context_destroy(cx);

	if (app_loop.fds) {
		lwsl_err("%s: %d fds still registered after destroy\n",
			 __func__, app_loop.fds);
		fail = 1;
	}

done:
	lwsl_user("Completed: %s (peak fds %d)\n", fail ? "FAIL" : "PASS",
		  app_loop.fds_peak);

	return fail;
}
