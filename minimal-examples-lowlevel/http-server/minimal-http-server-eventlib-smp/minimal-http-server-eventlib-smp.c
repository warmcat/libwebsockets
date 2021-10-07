/*
 * lws-minimal-http-server-eventlib-smp
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http[s] server that can work with any of the
 * supported event loop backends, or the default poll() one.
 *
 * To keep it simple, it serves stuff from the subdirectory 
 * "./mount-origin" of the directory it was started in.
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#if defined(WIN32)
#define HAVE_STRUCT_TIMESPEC
#if defined(pid_t)
#undef pid_t
#endif
#endif

#include <pthread.h>

#define COUNT_THREADS 8

static struct lws_context *context;
static volatile int interrupted;

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

void *thread_service(void *threadid)
{
	while (lws_service_tsi(context, 10000,
			       (int)(lws_intptr_t)threadid) >= 0 &&
	       !interrupted)
		;

	pthread_exit(NULL);

	return NULL;
}

void signal_cb(void *handle, int signum)
{
	interrupted = 1;

	switch (signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:
		lwsl_err("%s: signal %d\n", __func__, signum);
		break;
	}
	lws_context_destroy(context);
}

void sigint_handler(int sig)
{
	signal_cb(NULL, sig);
}

int main(int argc, const char **argv)
{
	pthread_t pthread_service[COUNT_THREADS];
	struct lws_context_creation_info info;
	const char *p;
	void *retval;
	int n, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http server eventlib SMP | visit http://localhost:7681\n");
	lwsl_user(" [-s (ssl)] [--uv (libuv)] [--ev (libev)] [--event (libevent)]\n");
	lwsl_user("WARNING: Not stable, under development!\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.error_document_404 = "/404.html";
	info.pcontext = &context;
	info.signal_cb = signal_cb;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	if ((p = lws_cmdline_option(argc, argv, "-t"))) {
		info.count_threads = (unsigned int)atoi(p);
		if (info.count_threads < 1 || info.count_threads > LWS_MAX_SMP)
			return 1;
	} else
		info.count_threads = COUNT_THREADS;

#if defined(LWS_WITH_TLS)
	if (lws_cmdline_option(argc, argv, "-s")) {
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		info.ssl_cert_filepath = "localhost-100y.cert";
		info.ssl_private_key_filepath = "localhost-100y.key";
	}
#endif

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
				else
					signal(SIGINT, sigint_handler);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lwsl_notice("  Service threads: %d\n", lws_get_count_threads(context));

	/* start all the service threads */

	for (n = 0; n < lws_get_count_threads(context); n++)
		if (pthread_create(&pthread_service[n], NULL, thread_service,
				   (void *)(lws_intptr_t)n))
			lwsl_err("Failed to start service thread\n");

	/* wait for all the service threads to exit */

	while ((--n) >= 0)
		pthread_join(pthread_service[n], &retval);

	lwsl_notice("%s: calling external context destroy\n", __func__);
	lws_context_destroy(context);

	return 0;
}
