/*
 * lws-minimal-ws-server
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal ws server that can cooperate with
 * other threads cleanly.  Two other threads are started, which fill
 * a ringbuffer with strings at 10Hz.
 *
 * The actual work and thread spawning etc are done in the protocol
 * implementation in protocol_lws_minimal.c.
 *
 * To keep it simple, it serves stuff in the subdirectory "./mount-origin" of
 * the directory it was started in.
 * You can change that by changing mount.origin.
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
#include <uv.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_minimal.c"

#define COUNT_THREADS 5

static struct lws_protocols protocols[] = {
	{ "http", lws_callback_http_dummy, 0, 0 },
	LWS_PLUGIN_PROTOCOL_MINIMAL,
	{ NULL, NULL, 0, 0 } /* terminator */
};

static struct lws_context *context;
static int interrupted;

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

/*
 * This demonstrates how to pass a pointer into a specific protocol handler
 * running on a specific vhost.  In this case, it's our default vhost and
 * we pass the pvo named "config" with the value a const char * "myconfig".
 *
 * This is the preferred way to pass configuration into a specific vhost +
 * protocol instance.
 */

static const struct lws_protocol_vhost_options pvo_ops = {
	NULL,
	NULL,
	"config",		/* pvo name */
	(void *)"myconfig"	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo = {
	NULL,		/* "next" pvo linked-list */
	&pvo_ops,	/* "child" pvo linked-list */
	"lws-minimal",	/* protocol name we belong to on this vhost */
	""		/* ignored */
};

void *thread_service(void *threadid)
{
	while (lws_service_tsi(context, 1000,
			       (int)(lws_intptr_t)threadid) >= 0 &&
	       !interrupted)
		;

	pthread_exit(NULL);

	return NULL;
}

void sigint_handler(int sig)
{
	interrupted = 1;
}

void signal_cb(uv_signal_t *watcher, int signum)
{
	uv_loop_t *loop = watcher->loop;
	lwsl_notice("signal_cb: signal %d caught\n", watcher->signum);
	interrupted = 1;
	uv_signal_stop(watcher);
	lws_context_destroy(context);
	uv_stop(loop);
}

int main(int argc, const char **argv)
{
	int n, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	uv_signal_t *s, signal_outer[COUNT_THREADS];
	pthread_t pthread_service[COUNT_THREADS];
	struct lws_context_creation_info info;
	void *foreign_loops[COUNT_THREADS];
	uv_loop_t loop[COUNT_THREADS];
	const char *p;
	void *retval;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal ws server + threads + smp | visit http://localhost:7681\n");

	for(n = 0; n < COUNT_THREADS; n++)
	{
		uv_loop_init(&loop[n]);
		s = &signal_outer[n*3 + 0]; uv_signal_init(&loop[n], s); uv_signal_start(s, signal_cb, SIGHUP);
		s = &signal_outer[n*3 + 1]; uv_signal_init(&loop[n], s); uv_signal_start(s, signal_cb, SIGHUP);
		s = &signal_outer[n*3 + 2]; uv_signal_init(&loop[n], s); uv_signal_start(s, signal_cb, SIGHUP);
		foreign_loops[n] = &loop[n];
	}

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.pcontext = &context;
	info.protocols = protocols;
	info.pvo = &pvo; /* per-vhost options */
	info.foreign_loops = foreign_loops;
	info.count_threads = COUNT_THREADS;
	info.options = LWS_SERVER_OPTION_LIBUV |
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

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

	lws_context_destroy(context);

	return 0;
}
