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
static uv_loop_t loop;
static int lifetime = 5, reported;
struct lws_context_creation_info info;

enum {
	TEST_STATE_CREATE_LWS_CONTEXT,
	TEST_STATE_DESTROY_LWS_CONTEXT,
	TEST_STATE_EXIT
};

static int sequence = TEST_STATE_CREATE_LWS_CONTEXT;

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

	if (context)
		lws_context_destroy(context);
}

/* this logs once a second to show that the foreign loop assets are working */

static void
timer_cb(uv_timer_t *t)
{
	void *foreign_loops[1];

	foreign_loops[0] = &loop;
	info.foreign_loops = foreign_loops;

	lwsl_user("Foreign 1Hz timer\n");

	if (sequence == TEST_STATE_EXIT && !context && !reported) {
		/*
		 * at this point the lws_context_destroy() we did earlier
		 * has completed and the entire context is wholly destroyed
		 */
		lwsl_user("lws_destroy_context() completed, continuing for 5s\n");
		reported = 1;
	}

	if (--lifetime)
		return;

	switch (sequence++) {
	case TEST_STATE_CREATE_LWS_CONTEXT:
		context = lws_create_context(&info);
		if (!context) {
			lwsl_err("lws init failed\n");
			return;
		}
		lwsl_user("LWS Context created and active for 10s\n");
		lifetime = 11;
		break;
	case TEST_STATE_DESTROY_LWS_CONTEXT:
		/* cleanup the lws part */
		lwsl_user("Destroying lws context and continuing loop for 5s\n");
		lws_context_destroy(context);
		lifetime = 6;
		break;

	case TEST_STATE_EXIT:
		lwsl_user("Deciding to exit foreign loop too\n");
		uv_stop(&loop);
		break;
	default:
		break;
	}
}


int main(int argc, const char **argv)
{
	uv_timer_t timer_outer;
	uv_signal_t sighandler;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http server libuv + foreign loop |"
		  " visit http://localhost:7681\n");

	/*
	 * We prepare the info here, but don't use it until later in the
	 * timer callback, to demonstrate the independence of the foreign loop
	 * and lws.
	 */

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.error_document_404 = "/404.html";
	info.options = LWS_SERVER_OPTION_LIBUV;
	info.pcontext = &context;
	if (lws_cmdline_option(argc, argv, "-s")) {
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		info.ssl_cert_filepath = "localhost-100y.cert";
		info.ssl_private_key_filepath = "localhost-100y.key";
	}
	info.pcontext = &context;

	lwsl_user("  This app creates a uv loop with a timer + signalhandler, and\n");
	lwsl_user("  performs a test in three phases:\n");
	lwsl_user("\n");
	lwsl_user("  1) 5s: Runs the loop with just the timer\n");
	lwsl_user("  2) 10s: create an lws context serving on localhost:7681\n");
	lwsl_user("     using the same uv loop.  Destroy it after 10s.\n");
	lwsl_user("  3) 5s: Run the loop again with just the timer\n");
	lwsl_user("\n");
	lwsl_user("  Finally close only the timer and signalhandler and\n");
	lwsl_user("   exit the loop cleanly\n");

	/* we create and start our "foreign loop" */

	uv_loop_init(&loop);
	uv_signal_init(&loop, &sighandler);
	uv_signal_start(&sighandler, signal_cb, SIGINT);

	uv_timer_init(&loop, &timer_outer);
	uv_timer_start(&timer_outer, timer_cb, 0, 1000);

	uv_run(&loop, UV_RUN_DEFAULT);

	/* in the case we hit ^C while lws still exists */
	lws_context_destroy(context);

	/* cleanup the foreign loop assets */

	uv_timer_stop(&timer_outer);
	uv_close((uv_handle_t*)&timer_outer, NULL);
	uv_signal_stop(&sighandler);
	uv_close((uv_handle_t *)&sighandler, NULL);

	uv_run(&loop, UV_RUN_DEFAULT);
	uv_loop_close(&loop);

	lwsl_user("%s: exiting...\n", __func__);

	return 0;
}
