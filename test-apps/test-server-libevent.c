/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2011-2017 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */
#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

int close_testing;
int max_poll_elements;
int debug_level = 7;
volatile int force_exit = 0;
struct lws_context *context;
struct lws_plat_file_ops fops_plat;

/* http server gets files from this path */
#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"
char *resource_path = LOCAL_RESOURCE_PATH;

#if defined(LWS_WITH_TLS) && defined(LWS_HAVE_SSL_CTX_set1_param)
char crl_path[1024] = "";
#endif

#define LWS_PLUGIN_STATIC
#include "../plugins/protocol_dumb_increment.c"
#include "../plugins/protocol_lws_mirror.c"
#include "../plugins/protocol_lws_status.c"
#include "../plugins/protocol_post_demo.c"

/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
	/* first protocol must always be HTTP handler */
	{ "http-only", lws_callback_http_dummy, 0, 0, },
	LWS_PLUGIN_PROTOCOL_DUMB_INCREMENT,
	LWS_PLUGIN_PROTOCOL_MIRROR,
	LWS_PLUGIN_PROTOCOL_LWS_STATUS,
	LWS_PLUGIN_PROTOCOL_POST_DEMO,
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

/* this shows how to override the lws file operations.  You don't need
 * to do any of this unless you have a reason (eg, want to serve
 * compressed files without decompressing the whole archive)
 */
static lws_fop_fd_t
test_server_fops_open(const struct lws_plat_file_ops *fops,
		const char *vfs_path, const char *vpath,
		lws_fop_flags_t *flags)
{
	lws_fop_fd_t n;

	/* call through to original platform implementation */
	n = fops_plat.open(fops, vfs_path, vpath, flags);

	lwsl_notice("%s: opening %s, ret %p\n", __func__, vfs_path, n);

	return n;
}

void signal_cb(evutil_socket_t sock_fd, short events, void *ctx)
{
	struct event_base *event_base_loop = ctx;

	lwsl_notice("Signal caught, exiting...\n");
	force_exit = 1;
	if (events & EV_SIGNAL)
		event_base_loopbreak(event_base_loop);
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
		{ "help",  no_argument,    NULL, 'h' },
		{ "debug",  required_argument,  NULL, 'd' },
		{ "port",  required_argument,  NULL, 'p' },
		{ "ssl",  no_argument,    NULL, 's' },
		{ "allow-non-ssl",  no_argument,  NULL, 'a' },
		{ "interface",  required_argument,  NULL, 'i' },
		{ "closetest",  no_argument,    NULL, 'c' },
		{ "libevent",  no_argument,    NULL, 'e' },
#ifndef LWS_NO_DAEMONIZE
		{ "daemonize",   no_argument,    NULL, 'D' },
#endif
		{ "resource_path", required_argument,  NULL, 'r' },
		{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	int sigs[] = { SIGINT, SIGKILL, SIGTERM, SIGSEGV, SIGFPE };
	struct event *signals[ARRAY_SIZE(sigs)];
	struct event_base *event_base_loop = event_base_new();
	struct lws_context_creation_info info;
	char interface_name[128] = "";
	const char *iface = NULL;
	char cert_path[1024];
	char key_path[1024];
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
		n = getopt_long(argc, argv, "eci:hsap:d:Dr:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'e':
			opts |= LWS_SERVER_OPTION_LIBEVENT;
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

#if !defined(LWS_NO_DAEMONIZE) && !defined(WIN32)
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

	for (n = 0; n < (int)ARRAY_SIZE(sigs); n++) {
		signals[n] = evsignal_new(event_base_loop, sigs[n], signal_cb, event_base_loop);

		evsignal_add(signals[n], NULL);
	}

	/* tell the library what debug level to emit and to send it to stderr */
	lws_set_log_level(debug_level, NULL);

	lwsl_notice("libwebsockets test server libevent - license LGPL2.1+SLE\n");
	lwsl_notice("(C) Copyright 2010-2018 Andy Green <andy@warmcat.com>\n");

	printf("Using resource path \"%s\"\n", resource_path);

	info.iface = iface;
	info.protocols = protocols;
	info.extensions = exts;
	info.mounts = &mount;

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
	info.max_http_header_pool = 1;
	info.options = opts | LWS_SERVER_OPTION_LIBEVENT;

	context = lws_create_context(&info);
	if (context == NULL) {
		lwsl_err("libwebsocket init failed\n");
		return -1;
	}

	/*
	 * this shows how to override the lws file operations.  You don't need
	 * to do any of this unless you have a reason (eg, want to serve
	 * compressed files without decompressing the whole archive)
	 */
	/* stash original platform fops */
	fops_plat = *(lws_get_fops(context));
	/* override the active fops */
	lws_get_fops(context)->open = test_server_fops_open;

	// Don't use the default Signal Event Watcher & Handler
	lws_event_sigint_cfg(context, 0, NULL);
	// Initialize the LWS with libevent loop
	lws_event_initloop(context, event_base_loop, 0);

	event_base_dispatch(event_base_loop);

	lws_context_destroy(context);

	lwsl_notice("libwebsockets-test-server exited cleanly\n");

	return 0;
}
