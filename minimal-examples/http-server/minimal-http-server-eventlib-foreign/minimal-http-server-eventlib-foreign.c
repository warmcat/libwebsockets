/*
 * lws-minimal-http-server-eventlib-foreign
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the most minimal http server you can make with lws that
 * uses a libuv event loop created outside lws.  It shows how lws can
 * participate in someone else's event loop and clean up after itself.
 *
 * You choose the event loop to work with at runtime, by giving the
 * --uv, --event or --ev switch.  Lws has to have been configured to build the
 * selected event lib support.
 *
 * To keep it simple, it serves stuff from the subdirectory 
 * "./mount-origin" of the directory it was started in.
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

struct lws_context_creation_info info;
static struct lws_context *context;
static int lifetime = 5, reported;

static void foreign_timer_service(void *foreign_loop);

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

static void
signal_cb(int signum)
{
	lwsl_notice("Signal %d caught, exiting...\n", signum);

	switch (signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:
		break;
	}

	lws_context_destroy(context);
}

/*
 * The event-loop specific foreign loop code, one set for each event loop lib
 *
 * Only the code in this section is specific to the event library used.
 */

#if defined(LWS_WITH_LIBUV)

static uv_loop_t loop_uv;
static uv_timer_t timer_outer_uv;
static uv_signal_t sighandler_uv;

static void
timer_cb_uv(uv_timer_t *t)
{
	foreign_timer_service(&loop_uv);
}

static void
signal_cb_uv(uv_signal_t *watcher, int signum)
{
	signal_cb(signum);
}

static void
foreign_event_loop_init_and_run_libuv(void)
{
	/* we create and start our "foreign loop" */

#if (UV_VERSION_MAJOR > 0) // Travis...
	uv_loop_init(&loop_uv);
#endif
	uv_signal_init(&loop_uv, &sighandler_uv);
	uv_signal_start(&sighandler_uv, signal_cb_uv, SIGINT);

	uv_timer_init(&loop_uv, &timer_outer_uv);
#if (UV_VERSION_MAJOR > 0) // Travis...
	uv_timer_start(&timer_outer_uv, timer_cb_uv, 0, 1000);
#else
	(void)timer_cb_uv;
#endif

	uv_run(&loop_uv, UV_RUN_DEFAULT);
}

static void
foreign_event_loop_stop_libuv(void)
{
	uv_stop(&loop_uv);
}

static void
foreign_event_loop_cleanup_libuv(void)
{
	/* cleanup the foreign loop assets */

	uv_timer_stop(&timer_outer_uv);
	uv_close((uv_handle_t*)&timer_outer_uv, NULL);
	uv_signal_stop(&sighandler_uv);
	uv_close((uv_handle_t *)&sighandler_uv, NULL);

	uv_run(&loop_uv, UV_RUN_DEFAULT);
#if (UV_VERSION_MAJOR > 0) // Travis...
	uv_loop_close(&loop_uv);
#endif
}

#endif

#if defined(LWS_WITH_LIBEVENT)

static struct event_base *loop_event;
static struct event *timer_outer_event;
static struct event *sighandler_event;

static void
timer_cb_event(int fd, short event, void *arg)
{
	foreign_timer_service(loop_event);
}

static void
signal_cb_event(int fd, short event, void *arg)
{
	signal_cb((int)(lws_intptr_t)arg);
}

static void
foreign_event_loop_init_and_run_libevent(void)
{
	struct timeval tv;

	/* we create and start our "foreign loop" */

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	loop_event = event_base_new();

	sighandler_event = evsignal_new(loop_event, SIGINT, signal_cb_event,
					(void*)SIGINT);

	timer_outer_event = event_new(loop_event, -1, EV_PERSIST,
				      timer_cb_event, NULL);
	//evtimer_new(loop_event, timer_cb_event, NULL);
	evtimer_add(timer_outer_event, &tv);

	event_base_loop(loop_event, 0);
}

static void
foreign_event_loop_stop_libevent(void)
{
	event_base_loopexit(loop_event, NULL);
}

static void
foreign_event_loop_cleanup_libevent(void)
{
	/* cleanup the foreign loop assets */

	evtimer_del(timer_outer_event);
	event_free(timer_outer_event);
	evsignal_del(sighandler_event);
	event_free(sighandler_event);

	event_base_loop(loop_event, 0);
	event_base_free(loop_event);
}

#endif

#if defined(LWS_WITH_GLIB)

#include <glib-2.0/glib.h>
#include <glib-unix.h>

static GMainLoop *loop_glib;
static guint timer_outer_glib;
static guint sighandler_glib;

static int
timer_cb_glib(void *p)
{
	foreign_timer_service(loop_glib);
	return 1;
}

static void
signal_cb_glib(void *p)
{
	signal_cb(SIGINT);
}

static void
foreign_event_loop_init_and_run_glib(void)
{
	/* we create and start our "foreign loop" */

	loop_glib = g_main_loop_new(NULL, 0);

	sighandler_glib = g_unix_signal_add(SIGINT,
					G_SOURCE_FUNC(signal_cb_glib), NULL);

	timer_outer_glib = g_timeout_add(1000, timer_cb_glib, NULL);

	g_main_loop_run(loop_glib);
}

static void
foreign_event_loop_stop_glib(void)
{
	g_main_loop_quit(loop_glib);
}

static void
foreign_event_loop_cleanup_glib(void)
{
	/* cleanup the foreign loop assets */
	g_source_remove(sighandler_glib);
	g_main_loop_unref(loop_glib);
}

#endif

#if defined(LWS_WITH_LIBEV)

static struct ev_loop *loop_ev;
static struct ev_timer timer_outer_ev;
static struct ev_signal sighandler_ev;

static void
timer_cb_ev(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	foreign_timer_service(loop_ev);
}

static void
signal_cb_ev(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	signal_cb(watcher->signum);
}

static void
foreign_event_loop_init_and_run_libev(void)
{
	/* we create and start our "foreign loop" */

	loop_ev = ev_loop_new(0);

	ev_signal_init(&sighandler_ev, signal_cb_ev, SIGINT);
	ev_signal_start(loop_ev, &sighandler_ev);

	ev_timer_init(&timer_outer_ev, timer_cb_ev, 0, 1);
	ev_timer_start(loop_ev, &timer_outer_ev);

	ev_run(loop_ev, 0);
}

static void
foreign_event_loop_stop_libev(void)
{
	ev_break(loop_ev, EVBREAK_ALL);
}

static void
foreign_event_loop_cleanup_libev(void)
{
	/* cleanup the foreign loop assets */

	ev_timer_stop(loop_ev, &timer_outer_ev);
	ev_signal_stop(loop_ev, &sighandler_ev);

	ev_run(loop_ev, UV_RUN_DEFAULT);
	ev_loop_destroy(loop_ev);
}

#endif

/* this is called at 1Hz using a foreign loop timer */

static void
foreign_timer_service(void *foreign_loop)
{
	void *foreign_loops[1];

	lwsl_user("Foreign 1Hz timer\n");

	if (sequence == TEST_STATE_EXIT && !context && !reported) {
		/*
		 * at this point the lws_context_destroy() we did earlier
		 * has completed and the entire context is wholly destroyed
		 */
		lwsl_user("lws_destroy_context() done, continuing for 5s\n");
		reported = 1;
	}

	if (--lifetime)
		return;

	switch (sequence++) {
	case TEST_STATE_CREATE_LWS_CONTEXT:
		/* this only has to exist for the duration of create context */
		foreign_loops[0] = foreign_loop;
		info.foreign_loops = foreign_loops;

		context = lws_create_context(&info);
		if (!context) {
			lwsl_err("lws init failed\n");
			return;
		}
		lwsl_user("LWS Context created and will be active for 10s\n");
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
#if defined(LWS_WITH_LIBUV)
		if (info.options & LWS_SERVER_OPTION_LIBUV)
			foreign_event_loop_stop_libuv();
#endif
#if defined(LWS_WITH_LIBEVENT)
		if (info.options & LWS_SERVER_OPTION_LIBEVENT)
			foreign_event_loop_stop_libevent();
#endif
#if defined(LWS_WITH_LIBEV)
		if (info.options & LWS_SERVER_OPTION_LIBEV)
			foreign_event_loop_stop_libev();
#endif
#if defined(LWS_WITH_GLIB)
		if (info.options & LWS_SERVER_OPTION_GLIB)
			foreign_event_loop_stop_glib();
#endif
		break;
	default:
		break;
	}
}

int main(int argc, const char **argv)
{
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
	lwsl_user("LWS minimal http server eventlib + foreign loop |"
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
	info.pcontext = &context;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	if (lws_cmdline_option(argc, argv, "-s")) {
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		info.ssl_cert_filepath = "localhost-100y.cert";
		info.ssl_private_key_filepath = "localhost-100y.key";
	}

	if (lws_cmdline_option(argc, argv, "--uv"))
		info.options |= LWS_SERVER_OPTION_LIBUV;
	else
		if (lws_cmdline_option(argc, argv, "--event"))
			info.options |= LWS_SERVER_OPTION_LIBEVENT;
		else
			if (lws_cmdline_option(argc, argv, "--ev"))
				info.options |= LWS_SERVER_OPTION_LIBEV;
			else
				if (lws_cmdline_option(argc, argv, "--glib"))
					info.options |= LWS_SERVER_OPTION_GLIB;
				else {
				lwsl_err("This app only makes sense when used\n");
				lwsl_err(" with a foreign loop, --uv, --event, --glib, or --ev\n");

				return 1;
			}

	lwsl_user("  This app creates a foreign event loop with a timer +\n");
	lwsl_user("  signalhandler, and performs a test in three phases:\n");
	lwsl_user("\n");
	lwsl_user("  1) 5s: Runs the loop with just the timer\n");
	lwsl_user("  2) 10s: create an lws context serving on localhost:7681\n");
	lwsl_user("     using the same foreign loop.  Destroy it after 10s.\n");
	lwsl_user("  3) 5s: Run the loop again with just the timer\n");
	lwsl_user("\n");
	lwsl_user("  Finally close only the timer and signalhandler and\n");
	lwsl_user("   exit the loop cleanly\n");
	lwsl_user("\n");

	/* foreign loop specific startup and run */

#if defined(LWS_WITH_LIBUV)
	if (info.options & LWS_SERVER_OPTION_LIBUV)
		foreign_event_loop_init_and_run_libuv();
#endif
#if defined(LWS_WITH_LIBEVENT)
	if (info.options & LWS_SERVER_OPTION_LIBEVENT)
		foreign_event_loop_init_and_run_libevent();
#endif
#if defined(LWS_WITH_LIBEV)
	if (info.options & LWS_SERVER_OPTION_LIBEV)
		foreign_event_loop_init_and_run_libev();
#endif
#if defined(LWS_WITH_GLIB)
	if (info.options & LWS_SERVER_OPTION_GLIB)
		foreign_event_loop_init_and_run_glib();
#endif

	lws_context_destroy(context);

	/* foreign loop specific cleanup and exit */

#if defined(LWS_WITH_LIBUV)
	if (info.options & LWS_SERVER_OPTION_LIBUV)
		foreign_event_loop_cleanup_libuv();
#endif
#if defined(LWS_WITH_LIBEVENT)
	if (info.options & LWS_SERVER_OPTION_LIBEVENT)
		foreign_event_loop_cleanup_libevent();
#endif
#if defined(LWS_WITH_LIBEV)
	if (info.options & LWS_SERVER_OPTION_LIBEV)
		foreign_event_loop_cleanup_libev();
#endif
#if defined(LWS_WITH_GLIB)
	if (info.options & LWS_SERVER_OPTION_GLIB)
		foreign_event_loop_cleanup_glib();
#endif

	lwsl_user("%s: exiting...\n", __func__);

	return 0;
}
