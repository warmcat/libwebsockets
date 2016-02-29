/*
 * libwebsockets-test-client - libwebsockets test implementation
 *
 * Copyright (C) 2011-2016 Andy Green <andy@warmcat.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#define random rand
#include "gettimeofday.h"
#else
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include "../lib/libwebsockets.h"

static int deny_deflate, deny_mux, longlived, mirror_lifetime;
static struct lws *wsi_dumb, *wsi_mirror;
static volatile int force_exit;
static unsigned int opts;

/*
 * This demo shows how to connect multiple websockets simultaneously to a
 * websocket server (there is no restriction on their having to be the same
 * server just it simplifies the demo).
 *
 *  dumb-increment-protocol:  we connect to the server and print the number
 *				we are given
 *
 *  lws-mirror-protocol: draws random circles, which are mirrored on to every
 *				client (see them being drawn in every browser
 *				session also using the test server)
 */

enum demo_protocols {

	PROTOCOL_DUMB_INCREMENT,
	PROTOCOL_LWS_MIRROR,

	/* always last */
	DEMO_PROTOCOL_COUNT
};


/*
 * dumb_increment protocol
 *
 * since this also happens to be protocols[0], some callbacks that are not
 * bound to a specific protocol also turn up here.
 */

static int
callback_dumb_increment(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	char *buf = (char *)in;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_info("dumb: LWS_CALLBACK_CLIENT_ESTABLISHED\n");
		break;

	case LWS_CALLBACK_CLOSED:
		lwsl_notice("dumb: LWS_CALLBACK_CLOSED\n");
		wsi_dumb = NULL;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		((char *)in)[len] = '\0';
		lwsl_info("rx %d '%s'\n", (int)len, (char *)in);
		break;

	/* because we are protocols[0] ... */

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (wsi == wsi_dumb) {
			lwsl_err("dumb: LWS_CALLBACK_CLIENT_CONNECTION_ERROR\n");
			wsi_dumb = NULL;
		}
		if (wsi == wsi_mirror) {
			lwsl_err("mirror: LWS_CALLBACK_CLIENT_CONNECTION_ERROR\n");
			wsi_mirror = NULL;
		}
		break;

	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		if ((strcmp(in, "deflate-stream") == 0) && deny_deflate) {
			lwsl_notice("denied deflate-stream extension\n");
			return 1;
		}
		if ((strcmp(in, "x-webkit-deflate-frame") == 0))
			return 1;
		if ((strcmp(in, "deflate-frame") == 0))
			return 1;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		while (len--)
			putchar(*buf++);
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		wsi_dumb = NULL;
		force_exit = 1;
		break;

	default:
		break;
	}

	return 0;
}


/* lws-mirror_protocol */


static int
callback_lws_mirror(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	unsigned char buf[LWS_PRE + 4096];
	unsigned int rands[4];
	int l = 0;
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:

		lwsl_notice("mirror: LWS_CALLBACK_CLIENT_ESTABLISHED\n");

		lws_get_random(lws_get_context(wsi), rands, sizeof(rands[0]));
		mirror_lifetime = 16384 + (rands[0] & 65535);
		/* useful to test single connection stability */
		if (longlived)
			mirror_lifetime += 500000;

		lwsl_info("opened mirror connection with "
			  "%d lifetime\n", mirror_lifetime);

		/*
		 * mirror_lifetime is decremented each send, when it reaches
		 * zero the connection is closed in the send callback.
		 * When the close callback comes, wsi_mirror is set to NULL
		 * so a new connection will be opened
		 *
		 * start the ball rolling,
		 * LWS_CALLBACK_CLIENT_WRITEABLE will come next service
		 */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLOSED:
		lwsl_notice("mirror: LWS_CALLBACK_CLOSED mirror_lifetime=%d\n", mirror_lifetime);
		wsi_mirror = NULL;
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		for (n = 0; n < 1; n++) {
			lws_get_random(lws_get_context(wsi), rands, sizeof(rands));
			l += sprintf((char *)&buf[LWS_PRE + l],
					"c #%06X %u %u %u;",
					rands[0] & 0xffffff,	/* colour */
					rands[1] & 511,		/* x */
					rands[2] & 255,		/* y */
					(rands[3] & 31) + 1);	/* radius */
		}

		n = lws_write(wsi, &buf[LWS_PRE], l,
			      opts | LWS_WRITE_TEXT);
		if (n < 0)
			return -1;
		if (n < l) {
			lwsl_err("Partial write LWS_CALLBACK_CLIENT_WRITEABLE\n");
			return -1;
		}

		mirror_lifetime--;
		if (!mirror_lifetime) {
			lwsl_info("closing mirror session\n");
			return -1;
		}
		/* get notified as soon as we can write again */
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
	{
		"dumb-increment-protocol,fake-nonexistant-protocol",
		callback_dumb_increment,
		0,
		20,
	},
	{
		"fake-nonexistant-protocol,lws-mirror-protocol",
		callback_lws_mirror,
		0,
		128,
	},
	{ NULL, NULL, 0, 0 } /* end */
};

static const struct lws_extension exts[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate; client_max_window_bits"
	},
	{
		"deflate-frame",
		lws_extension_callback_pm_deflate,
		"deflate_frame"
	},
	{ NULL, NULL, NULL /* terminator */ }
};



void sighandler(int sig)
{
	force_exit = 1;
}

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",      required_argument,      NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "version",	required_argument,	NULL, 'v' },
	{ "undeflated",	no_argument,		NULL, 'u' },
	{ "nomux",	no_argument,		NULL, 'n' },
	{ "longlived",	no_argument,		NULL, 'l' },
	{ NULL, 0, 0, 0 }
};

static int ratelimit_connects(unsigned int *last, unsigned int secs)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if (tv.tv_sec - (*last) < secs)
		return 0;

	*last = tv.tv_sec;

	return 1;
}

int main(int argc, char **argv)
{
	int n = 0, ret = 0, port = 7681, use_ssl = 0, ietf_version = -1;
	unsigned int rl_dumb = 0, rl_mirror = 0, do_ws = 1;
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_context *context;
	const char *prot, *p;
	char path[300];

	memset(&info, 0, sizeof info);

	lwsl_notice("libwebsockets test client - license LGPL2.1+SLE\n");
	lwsl_notice("(C) Copyright 2010-2016 Andy Green <andy@warmcat.com>\n");

	if (argc < 2)
		goto usage;

	while (n >= 0) {
		n = getopt_long(argc, argv, "nuv:hsp:d:l", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'd':
			lws_set_log_level(atoi(optarg), NULL);
			break;
		case 's':
			use_ssl = 2; /* 2 = allow selfsigned */
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'l':
			longlived = 1;
			break;
		case 'v':
			ietf_version = atoi(optarg);
			break;
		case 'u':
			deny_deflate = 1;
			break;
		case 'n':
			deny_mux = 1;
			break;
		case 'h':
			goto usage;
		}
	}

	if (optind >= argc)
		goto usage;

	signal(SIGINT, sighandler);

	memset(&i, 0, sizeof(i));

	i.port = port;
	if (lws_parse_uri(argv[optind], &prot, &i.address, &i.port, &p))
		goto usage;

	/* add back the leading / on path */
	path[0] = '/';
	strncpy(path + 1, p, sizeof(path) - 2);
	path[sizeof(path) - 1] = '\0';
	i.path = path;

	if (!strcmp(prot, "http") || !strcmp(prot, "ws"))
		use_ssl = 0;
	if (!strcmp(prot, "https") || !strcmp(prot, "wss"))
		use_ssl = 1;

	/*
	 * create the websockets context.  This tracks open connections and
	 * knows how to route any traffic and which protocol version to use,
	 * and if each connection is client or server side.
	 *
	 * For this client-only demo, we tell it to not listen on any port.
	 */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.gid = -1;
	info.uid = -1;

	context = lws_create_context(&info);
	if (context == NULL) {
		fprintf(stderr, "Creating libwebsocket context failed\n");
		return 1;
	}

	i.context = context;
	i.ssl_connection = use_ssl;
	i.host = i.address;
	i.origin = i.address;
	i.ietf_version_or_minus_one = ietf_version;
	i.client_exts = exts;

	if (!strcmp(prot, "http") || !strcmp(prot, "https")) {
		lwsl_notice("using %s mode (non-ws)\n", prot);
		i.method = "GET";
		do_ws = 0;
	} else
		lwsl_notice("using %s mode (ws)\n", prot);

	/*
	 * sit there servicing the websocket context to handle incoming
	 * packets, and drawing random circles on the mirror protocol websocket
	 *
	 * nothing happens until the client websocket connection is
	 * asynchronously established... calling lws_client_connect() only
	 * instantiates the connection logically, lws_service() progresses it
	 * asynchronously.
	 */

	while (!force_exit) {

		if (do_ws) {
			if (!wsi_dumb && ratelimit_connects(&rl_dumb, 2u)) {
				lwsl_notice("dumb: connecting\n");
				i.protocol = protocols[PROTOCOL_DUMB_INCREMENT].name;
				wsi_dumb = lws_client_connect_via_info(&i);
			}

			if (!wsi_mirror && ratelimit_connects(&rl_mirror, 2u)) {
				lwsl_notice("mirror: connecting\n");
				i.protocol = protocols[PROTOCOL_LWS_MIRROR].name;
				wsi_mirror = lws_client_connect_via_info(&i);
			}
		} else
			if (!wsi_dumb && ratelimit_connects(&rl_dumb, 2u)) {
				lwsl_notice("http: connecting\n");
				wsi_dumb = lws_client_connect_via_info(&i);
			}

		lws_service(context, 500);
	}

	lwsl_err("Exiting\n");
	lws_context_destroy(context);

	return ret;

usage:
	fprintf(stderr, "Usage: libwebsockets-test-client "
				"<server address> [--port=<p>] "
				"[--ssl] [-k] [-v <ver>] "
				"[-d <log bitfield>] [-l]\n");
	return 1;
}
