/*
 * lws-minimal-http-server-libuv-foreign
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the most minimal http server you can make with lws that
 * uses a libuv event loop created outside lws.  It shows how lws can
 * participate in someone else's event loop and clean up after itself.
 *
 * To keep it simple, it serves stuff from the subdirectory 
 * "./mount-origin" of the directory it was started in.
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static struct lws_context *context;

static const struct lws_http_mount mount = {
	/* .mount_next */		NULL,		/* linked-list "next" */
	/* .mountpoint */		"/",		/* mountpoint URL */
	/* .origin */			"./mount-origin", /* serve from dir */
	/* .def */			"index.html",	/* default filename */
	/* .protocol */			NULL,
	/* .cgienv */			NULL,
	/* .extra_mimetypes */		NULL,
	/* .interpret */		NULL,
	/* .cgi_timeout */		0,
	/* .cache_max_age */		0,
	/* .auth_mask */		0,
	/* .cache_reusable */		0,
	/* .cache_revalidate */		0,
	/* .cache_intermediaries */	0,
	/* .origin_protocol */		LWSMPRO_FILE,	/* files in a dir */
	/* .mountpoint_len */		1,		/* char count */
	/* .basic_auth_login_file */	NULL,
};

void signal_cb(uv_signal_t *watcher, int signum)
{
	lwsl_notice("Signal %d caught, exiting...\n", watcher->signum);

	switch (watcher->signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:
		signal(SIGABRT, SIG_DFL);
		abort();
		break;
	}
	lws_libuv_stop(context);
}

/* this logs once a second to show that the foreign loop assets are working */

static void timer_cb(uv_timer_t *t)
{
	lwsl_user("Foreign 1Hz timer\n");
}

static void lws_uv_close_cb(uv_handle_t *handle)
{
}

static void lws_uv_walk_cb(uv_handle_t *handle, void *arg)
{
	lwsl_info("%s: closing foreign loop asset: %p (type %d)\n",
		    __func__, handle, handle->type);
	uv_close(handle, lws_uv_close_cb);
}

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	uv_timer_t timer_outer;
	uv_loop_t loop;

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.error_document_404 = "/404.html";
	info.options = LWS_SERVER_OPTION_LIBUV;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */, NULL);

	lwsl_user("LWS minimal http server libuv + foreign loop |"
		  " visit http://localhost:7681\n");

	uv_loop_init(&loop);

	uv_timer_init(&loop, &timer_outer);
	uv_timer_start(&timer_outer, timer_cb, 0, 1000);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_uv_sigint_cfg(context, 1, signal_cb);

	if (lws_uv_initloop(context, &loop, 0)) {
		lwsl_err("lws_uv_initloop failed\n");

		goto bail;
	}

	lws_libuv_run(context, 0);

bail:
	lwsl_user("%s: starting exit cleanup...\n", __func__);

	/* cleanup the lws part */

	lws_context_destroy(context);
	lws_context_destroy2(context);

	/* cleanup the foreign loop part */

	lwsl_user("%s: lws context destroyed: cleaning the foreign loop\n",
		    __func__);

	/*
	 * Instead of walking to close all the foreign assets, it's also
	 * fine to close them individually instead as below
	 */
	// uv_timer_stop(&timer_outer);
	// uv_close((uv_handle_t*)&timer_outer, NULL);

	/* close every foreign loop asset unconditionally */
	uv_walk(&loop, lws_uv_walk_cb, NULL);

	/* let it run until everything completed close */
	uv_run(&loop, UV_RUN_DEFAULT);

	/* nothing left in the foreign loop, destroy it */

	uv_loop_close(&loop);

	lwsl_user("%s: exiting...\n", __func__);

	return 0;
}
