/*
 * libwebsockets-test-server for libev - libwebsockets test implementation
 *
 * Copyright (C) 2010-2015 Andy Green <andy@warmcat.com>
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

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <uv.h>

int close_testing;
int max_poll_elements;
int debug_level = 7;
struct lws_context *context;
struct lws_plat_file_ops fops_plat;

/* http server gets files from this path */
#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"
char *resource_path = LOCAL_RESOURCE_PATH;

#if defined(LWS_WITH_TLS) && defined(LWS_HAVE_SSL_CTX_set1_param)
char crl_path[1024] = "";
#endif

/* singlethreaded version --> no locks */

void test_server_lock(int care)
{
}
void test_server_unlock(int care)
{
}

#define LWS_PLUGIN_STATIC
#if defined(LWS_ROLE_WS)
#include "../plugins/protocol_dumb_increment.c"
#include "../plugins/protocol_lws_mirror.c"
#include "../plugins/protocol_lws_status.c"
#include "../plugins/protocol_post_demo.c"
#endif


/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
	/* first protocol must always be HTTP handler */

	{ "http-only", lws_callback_http_dummy, 0, 0, },
#if defined(LWS_ROLE_WS)
	LWS_PLUGIN_PROTOCOL_DUMB_INCREMENT,
	LWS_PLUGIN_PROTOCOL_MIRROR,
	LWS_PLUGIN_PROTOCOL_LWS_STATUS,
	LWS_PLUGIN_PROTOCOL_POST_DEMO,
#endif
	{ NULL, NULL, 0, 0 } /* terminator */
};


static const struct lws_extension exts[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate; client_no_context_takeover; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};

void signal_cb(void *handle, int signum)
{
	uv_signal_t *watcher = (uv_signal_t *)handle;

	lwsl_err("Signal %d caught, exiting...\n", watcher->signum);
	switch (watcher->signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:
		signal(SIGABRT, SIG_DFL);
		abort();
		break;
	}
	lws_context_destroy(context);
}

/*
 * mount handlers for sections of the URL space
 */

static const struct lws_http_mount mount_ziptest = {
	NULL,			/* linked-list pointer to next*/
	"/ziptest",		/* mountpoint in URL namespace on this vhost */
	LOCAL_RESOURCE_PATH"/candide.zip",	/* handler */
	NULL,	/* default filename if none given */
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,
	0,
	0,
	LWSMPRO_FILE,	/* origin points to a callback */
	8,			/* strlen("/ziptest"), ie length of the mountpoint */
	NULL,

	{ NULL, NULL } // sentinel
};

static const struct lws_http_mount mount_post = {
	(struct lws_http_mount *)&mount_ziptest, /* linked-list pointer to next*/
	"/formtest",		/* mountpoint in URL namespace on this vhost */
	"protocol-post-demo",	/* handler */
	NULL,	/* default filename if none given */
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,
	0,
	0,
	LWSMPRO_CALLBACK,	/* origin points to a callback */
	9,			/* strlen("/formtest"), ie length of the mountpoint */
	NULL,

	{ NULL, NULL } // sentinel
};

/*
 * mount a filesystem directory into the URL space at /
 * point it to our /usr/share directory with our assets in
 * stuff from here is autoserved by the library
 */

static const struct lws_http_mount mount = {
	(struct lws_http_mount *)&mount_post,	/* linked-list pointer to next*/
	"/",		/* mountpoint in URL namespace on this vhost */
	LOCAL_RESOURCE_PATH, /* where to go on the filesystem for that */
	"test.html",	/* default filename if none given */
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,
	0,
	0,
	LWSMPRO_FILE,	/* mount type is a directory in a filesystem */
	1,		/* strlen("/"), ie length of the mountpoint */
	NULL,

	{ NULL, NULL } // sentinel
};

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "allow-non-ssl",	no_argument,	NULL, 'a' },
	{ "interface",  required_argument,	NULL, 'i' },
	{ "closetest",  no_argument,		NULL, 'c' },
	{ "libev",  no_argument,		NULL, 'e' },
	{ "foreign",  no_argument,		NULL, 'f' },
#ifndef LWS_NO_DAEMONIZE
	{ "daemonize", 	no_argument,		NULL, 'D' },
#endif
	{ "resource_path", required_argument,	NULL, 'r' },
	{ NULL, 0, 0, 0 }
};

#if UV_VERSION_MAJOR > 0
/* ----- this code is only needed for foreign / external libuv tests -----*/
struct counter
{
	int cur, lim;
	int stop_loop;
};

static void timer_cb(uv_timer_t *t)
{
	struct counter *c = t->data;

	lwsl_notice("  timer %p cb, count %d, loop has %d handles\n",
		    t, c->cur, t->loop->active_handles);

	if (c->cur++ == c->lim) {
		lwsl_debug("stop loop from timer\n");
		uv_timer_stop(t);
		if (c->stop_loop)
			uv_stop(t->loop);
	}
}

static void timer_test_cancel_cb(uv_timer_t *h)
{
	if (context) {
		lwsl_notice("(doing cancel test)\n");
		lws_cancel_service(context);
	}
}


static void timer_close_cb(uv_handle_t *h)
{
	lwsl_notice("timer close cb %p, loop has %d handles\n",
		    h, h->loop->active_handles);
}

static void walk_cb(uv_handle_t *h, void *arg)
{
	lwsl_err("%s: handle %p: type %d\n", __func__, h, h->type);
}

void outer_signal_cb(uv_signal_t *s, int signum)
{
	lwsl_notice("Foreign loop got signal %d\n", signum);
	uv_signal_stop(s);
	uv_stop(s->loop);
}

/* --- end of foreign test code ---- */
#endif

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	char interface_name[128] = "";
#if UV_VERSION_MAJOR > 0
/* --- only needed for foreign loop test ---> */
	uv_loop_t loop;
	uv_signal_t signal_outer;
	uv_timer_t timer_outer;
	struct counter ctr;
	int foreign_libuv_loop = 0;
	uv_timer_t timer_test_cancel;
/* <--- only needed for foreign loop test --- */
#endif
	const char *iface = NULL;
	char cert_path[1024];
	char key_path[1024];
	void *foreign_loops[1];
	int use_ssl = 0;
	int opts = 0;
	int n = 0;
#ifndef LWS_NO_DAEMONIZE
	int daemonize = 0;
#endif

	/*
	 * take care to zero down the info struct, he contains random garbaage
	 * from the stack otherwise
	 */
	memset(&info, 0, sizeof info);
	info.port = 7681;

	while (n >= 0) {
		n = getopt_long(argc, argv, "feci:hsap:d:Dr:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'f':
#if UV_VERSION_MAJOR > 0
			foreign_libuv_loop = 1;
#endif
			break;
		case 'e':
			opts |= LWS_SERVER_OPTION_LIBEV;
			break;
#ifndef LWS_NO_DAEMONIZE
		case 'D':
			daemonize = 1;
			#ifndef _WIN32
			syslog_options &= ~LOG_PERROR;
			#endif
			break;
#endif
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 's':
			use_ssl = 1;
			break;
		case 'a':
			opts |= LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT;
			break;
		case 'p':
			info.port = atoi(optarg);
			break;
		case 'i':
			lws_strncpy(interface_name, optarg, sizeof interface_name);
			iface = interface_name;
			break;
		case 'c':
			close_testing = 1;
			fprintf(stderr, " Close testing mode -- closes on "
					   "client after 50 dumb increments"
					   "and suppresses lws_mirror spam\n");
			break;
		case 'r':
			resource_path = optarg;
			printf("Setting resource path to \"%s\"\n", resource_path);
			break;
		case 'h':
			fprintf(stderr, "Usage: test-server "
					"[--port=<p>] [--ssl] "
					"[-d <log bitfield>] "
					"[--resource_path <path>]\n");
			exit(1);
		}
	}

#if !defined(WIN32)
#if !defined(LWS_NO_DAEMONIZE)
	/*
	 * normally lock path would be /var/lock/lwsts or similar, to
	 * simplify getting started without having to take care about
	 * permissions or running as root, set to /tmp/.lwsts-lock
	 */
	if (daemonize && lws_daemonize("/tmp/.lwsts-lock")) {
		fprintf(stderr, "Failed to daemonize\n");
		return 1;
	}
#endif
#endif

	/* tell the library what debug level to emit and to send it to stderr */
	lws_set_log_level(debug_level, NULL);

	lwsl_notice("libwebsockets test server libuv - license LGPL2.1+SLE\n");
	lwsl_notice("(C) Copyright 2010-2018 Andy Green <andy@warmcat.com>\n");

	lwsl_info("Using resource path \"%s\"\n", resource_path);

	info.iface = iface;
	info.protocols = protocols;
	info.extensions = exts;
	info.mounts = &mount;
	info.pcontext = &context;

	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;

	if (use_ssl) {
		if (strlen(resource_path) > sizeof(cert_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		sprintf(cert_path, "%s/libwebsockets-test-server.pem",
			resource_path);
		if (strlen(resource_path) > sizeof(key_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		sprintf(key_path, "%s/libwebsockets-test-server.key.pem",
			resource_path);

		info.ssl_cert_filepath = cert_path;
		info.ssl_private_key_filepath = key_path;
		opts |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	}
	info.gid = -1;
	info.uid = -1;
	info.timeout_secs = 5;
	info.options = opts | LWS_SERVER_OPTION_LIBUV;

#if UV_VERSION_MAJOR > 0
	if (foreign_libuv_loop) {
		/* create the foreign loop */
		uv_loop_init(&loop);

		/* run some timer on that loop just so loop is not 'clean' */

		uv_signal_init(&loop, &signal_outer);
		uv_signal_start(&signal_outer, outer_signal_cb, SIGINT);

		uv_timer_init(&loop, &timer_test_cancel);
		uv_timer_start(&timer_test_cancel, timer_test_cancel_cb, 2000, 2000);

		uv_timer_init(&loop, &timer_outer);
		timer_outer.data = &ctr;
		ctr.cur = 0;
		ctr.lim = ctr.cur + 5;
		ctr.stop_loop = 1;
		uv_timer_start(&timer_outer, timer_cb, 0, 1000);
		lwsl_notice("running loop without libwebsockets for %d s\n", ctr.lim);

		uv_run(&loop, UV_RUN_DEFAULT);

		/* timer will stop loop and we will get here */

		foreign_loops[0] = &loop;
		info.foreign_loops = foreign_loops;
	} else
		info.signal_cb = signal_cb;
#endif

	context = lws_create_context(&info);
	if (context == NULL) {
		lwsl_err("libwebsocket init failed\n");
		return -1;
	}

#if UV_VERSION_MAJOR > 0
	if (foreign_libuv_loop) {
		/*
		 * prepare inner timer on loop, to run along with lws.
		 * Will exit after 5s while lws keeps running
		 */
		struct counter ctr_inner = { 0, 3, 0 };
		int e;
		uv_timer_t timer_inner;
		uv_timer_init(&loop, &timer_inner);
		timer_inner.data = &ctr_inner;
		uv_timer_start(&timer_inner, timer_cb, 200, 1000);

		/* make this timer long-lived, should keep
		 * firing after lws exits */
		ctr.cur = 0;
		ctr.lim = ctr.cur + 1000;
		uv_timer_start(&timer_outer, timer_cb, 0, 1000);

		uv_run(&loop, UV_RUN_DEFAULT);

		/* we are here either because signal stopped us,
		 * or outer timer expired */

		/* stop short timer */
		uv_timer_stop(&timer_inner);

		lwsl_notice("Destroying lws context\n");

		/* detach lws */
		lws_context_destroy(context);

		lwsl_notice("Please wait while the outer libuv test continues for 10s\n");

		ctr.lim = ctr.cur + 10;

		/* try and run outer timer for 10 more seconds,
		 * (or sigint outer handler) after lws has left the loop */
		uv_run(&loop, UV_RUN_DEFAULT);

		/* Clean up the foreign loop now */

		/* PHASE 1: stop and close things we created
		 *          outside of lws */

		uv_timer_stop(&timer_outer);
		uv_close((uv_handle_t*)&timer_outer, timer_close_cb);
		uv_timer_stop(&timer_test_cancel);
		uv_close((uv_handle_t*)&timer_test_cancel, timer_close_cb);
		uv_timer_stop(&timer_inner);
		uv_close((uv_handle_t*)&timer_inner, timer_close_cb);
		uv_signal_stop(&signal_outer);
		uv_close((uv_handle_t*)&signal_outer, NULL);

		e = 100;
		while (e--)
			uv_run(&loop, UV_RUN_NOWAIT);

		/* PHASE 2: close the UV loop itself */

		e = uv_loop_close(&loop);
		if (e) {
			lwsl_notice("uv loop close rc %s\n", e ? uv_strerror(e) : "ok");

			uv_walk(&loop, walk_cb, NULL);
		}

	} else
#endif
	{
		lws_service(context, 0);

		/*
		 * we can't destroy the internal loops while they are running
		 */
		lws_context_destroy(context);
	}

	lwsl_notice("libwebsockets-test-server exited cleanly\n");

	context = NULL;

	return 0;
}
