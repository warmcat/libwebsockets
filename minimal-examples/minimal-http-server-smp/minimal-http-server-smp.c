/*
 * lws-minimal-http-server-smp
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal multithreaded http server you can make with lws.
 *
 * To keep it simple, it serves stuff in the directory it was started in.
 * You can change that by changing mount.origin.
 *
 * Also for simplicity the number of threads is set in the code... note that
 * the real number of threads possible is decided by the LWS_MAX_SMP that lws
 * was configured with, by default that is 1.  Lws will limit the number of
 * requested threads to the number possible.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define COUNT_THREADS 10

static struct lws_context *context;
static int interrupted;

static const struct lws_http_mount mount = {
	/* .mount_next */		NULL,		/* linked-list "next" */
	/* .mountpoint */		"/",		/* mountpoint URL */
	/* .origin */			".",		/* serve from dir */
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
	while (lws_service_tsi(context, 50, (int)(lws_intptr_t)threadid) >= 0 &&
	       !interrupted)
		;

	pthread_exit(NULL);
}

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, char **argv)
{
	pthread_t pthread_service[COUNT_THREADS];
	struct lws_context_creation_info info;
	void *retval;
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.count_threads = COUNT_THREADS;

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER
			/* | LLL_INFO */ /* | LLL_DEBUG */, NULL);

	lwsl_user("LWS minimal http server SMP | visit http://localhost:7681\n");

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
