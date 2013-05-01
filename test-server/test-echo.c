/*
 * libwebsockets-test-echo - libwebsockets echo test implementation
 *
 * This implements both the client and server sides.  It defaults to
 * serving, use --client <remote address> to connect as client.
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#ifdef WIN32
#else
#include <syslog.h>
#endif
#include <signal.h>

#ifdef CMAKE_BUILD
#include "lws_config.h"
#endif

#include "../lib/libwebsockets.h"

int force_exit = 0;

#define MAX_ECHO_PAYLOAD 1400
#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"

struct per_session_data__echo {
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_ECHO_PAYLOAD + LWS_SEND_BUFFER_POST_PADDING];
	unsigned int len;
	unsigned int index;
};

static int
callback_echo(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
							   void *in, size_t len)
{
	struct per_session_data__echo *pss = (struct per_session_data__echo *)user;
	int n;

	switch (reason) {

#ifndef LWS_NO_SERVER
	/* when the callback is used for server operations --> */

	case LWS_CALLBACK_SERVER_WRITEABLE:
		n = libwebsocket_write(wsi, &pss->buf[LWS_SEND_BUFFER_PRE_PADDING], pss->len, LWS_WRITE_TEXT);
		if (n < 0) {
			lwsl_err("ERROR %d writing to socket, hanging up\n", n);
			return 1;
		}
		if (n < (int)pss->len) {
			lwsl_err("Partial write\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (len > MAX_ECHO_PAYLOAD) {
			lwsl_err("Server received packet bigger than %u, hanging up\n", MAX_ECHO_PAYLOAD);
			return 1;
		}
		memcpy(&pss->buf[LWS_SEND_BUFFER_PRE_PADDING], in, len);
		pss->len = (unsigned int)len;
		libwebsocket_callback_on_writable(context, wsi);
		break;
#endif

#ifndef LWS_NO_CLIENT
	/* when the callback is used for client operations --> */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("Client has connected\n");
		pss->index = 0;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		lwsl_notice("Client RX: %s", (char *)in);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		/* we will send our packet... */
		pss->len = sprintf((char *)&pss->buf[LWS_SEND_BUFFER_PRE_PADDING], "hello from libwebsockets-test-echo client pid %d index %d\n", getpid(), pss->index++);
		lwsl_notice("Client TX: %s", &pss->buf[LWS_SEND_BUFFER_PRE_PADDING]);
		n = libwebsocket_write(wsi, &pss->buf[LWS_SEND_BUFFER_PRE_PADDING], pss->len, LWS_WRITE_TEXT);
		if (n < 0) {
			lwsl_err("ERROR %d writing to socket, hanging up\n", n);
			return -1;
		}
		if (n < (int)pss->len) {
			lwsl_err("Partial write\n");
			return -1;
		}
		break;
#endif
	default:
		break;
	}

	return 0;
}



static struct libwebsocket_protocols protocols[] = {
	/* first protocol must always be HTTP handler */

	{
		"default",		/* name */
		callback_echo,		/* callback */
		sizeof(struct per_session_data__echo)	/* per_session_data_size */
	},
	{
		NULL, NULL, 0		/* End of list */
	}
};

void sighandler(int sig)
{
	force_exit = 1;
}

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
#ifndef LWS_NO_CLIENT
	{ "client",	required_argument,	NULL, 'c' },
	{ "ratems",	required_argument,	NULL, 'r' },
#endif
	{ "ssl",	no_argument,		NULL, 's' },
	{ "interface",  required_argument,	NULL, 'i' },
#ifndef LWS_NO_DAEMONIZE
	{ "daemonize", 	no_argument,		NULL, 'D' },
#endif
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	int n = 0;
	int port = 7681;
	int use_ssl = 0;
	struct libwebsocket_context *context;
	int opts = 0;
	char interface_name[128] = "";
	const char *interface = NULL;
#ifndef WIN32
	int syslog_options = LOG_PID | LOG_PERROR;
#endif
	int client = 0;
	int listen_port;
	struct lws_context_creation_info info;
#ifndef LWS_NO_CLIENT
	char address[256];
	int rate_us = 250000;
	unsigned int oldus = 0;
	struct libwebsocket *wsi;
#endif

	int debug_level = 7;
#ifndef LWS_NO_DAEMONIZE
	int daemonize = 0;
#endif

	memset(&info, 0, sizeof info);

#ifndef LWS_NO_CLIENT
	lwsl_notice("Built to support client operations\n");
#endif
#ifndef LWS_NO_SERVER
	lwsl_notice("Built to support server operations\n");
#endif

	while (n >= 0) {
		n = getopt_long(argc, argv, "i:hsp:d:D"
#ifndef LWS_NO_CLIENT
			"c:r:"
#endif
				, options, NULL);
		if (n < 0)
			continue;
		switch (n) {
#ifndef LWS_NO_DAEMONIZE
		case 'D':
			daemonize = 1;
#ifndef WIN32
			syslog_options &= ~LOG_PERROR;
#endif
			break;
#endif
#ifndef LWS_NO_CLIENT
		case 'c':
			client = 1;
			strcpy(address, optarg);
			port = 80;
			break;
		case 'r':
			rate_us = atoi(optarg) * 1000;
			break;
#endif
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 's':
			use_ssl = 1; /* 1 = take care about cert verification, 2 = allow anything */
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'i':
			strncpy(interface_name, optarg, sizeof interface_name);
			interface_name[(sizeof interface_name) - 1] = '\0';
			interface = interface_name;
			break;
		case '?':
		case 'h':
			fprintf(stderr, "Usage: libwebsockets-test-echo "
					"[--ssl] "
#ifndef LWS_NO_CLIENT
					"[--client <remote ads>] "
					"[--ratems <ms>] "
#endif
					"[--port=<p>] "
					"[-d <log bitfield>]\n");
			exit(1);
		}
	}

#ifndef LWS_NO_DAEMONIZE
	/*
	 * normally lock path would be /var/lock/lwsts or similar, to
	 * simplify getting started without having to take care about
	 * permissions or running as root, set to /tmp/.lwsts-lock
	 */
	if (!client && daemonize && lws_daemonize("/tmp/.lwstecho-lock")) {
		fprintf(stderr, "Failed to daemonize\n");
		return 1;
	}
#endif

#ifdef WIN32
#else
	/* we will only try to log things according to our debug_level */
	setlogmask(LOG_UPTO (LOG_DEBUG));
	openlog("lwsts", syslog_options, LOG_DAEMON);

	/* tell the library what debug level to emit and to send it to syslog */
	lws_set_log_level(debug_level, lwsl_emit_syslog);
#endif
	lwsl_notice("libwebsockets echo test - "
			"(C) Copyright 2010-2013 Andy Green <andy@warmcat.com> - "
						    "licensed under LGPL2.1\n");
#ifndef LWS_NO_CLIENT
	if (client) {
		lwsl_notice("Running in client mode\n");
		listen_port = CONTEXT_PORT_NO_LISTEN;
		if (use_ssl)
			use_ssl = 2;
	} else {
#endif
#ifndef LWS_NO_SERVER
		lwsl_notice("Running in server mode\n");
		listen_port = port;
#endif
#ifndef LWS_NO_CLIENT
	}
#endif

	info.port = listen_port;
	info.iface = interface;
	info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
	info.extensions = libwebsocket_get_internal_extensions();
#endif
	if (use_ssl && !client) {
		info.ssl_cert_filepath = LOCAL_RESOURCE_PATH"/libwebsockets-test-server.pem";
		info.ssl_private_key_filepath = LOCAL_RESOURCE_PATH"/libwebsockets-test-server.key.pem";
	}
	info.gid = -1;
	info.uid = -1;
	info.options = opts;

	context = libwebsocket_create_context(&info);

	if (context == NULL) {
		lwsl_err("libwebsocket init failed\n");
		return -1;
	}

#ifndef LWS_NO_CLIENT
	if (client) {
		lwsl_notice("Client connecting to %s:%u....\n", address, port);
		/* we are in client mode */
		wsi = libwebsocket_client_connect(context, address,
				port, use_ssl, "/", address,
				 "origin", NULL, -1);
		if (!wsi) {
			lwsl_err("Client failed to connect to %s:%u\n", address, port);
			goto bail;
		}
		lwsl_notice("Client connected to %s:%u\n", address, port);
	}
#endif
	signal(SIGINT, sighandler);

	n = 0;
	while (n >= 0 && !force_exit) {
#ifndef LWS_NO_CLIENT
		struct timeval tv;

		if (client) {
			gettimeofday(&tv, NULL);

			if (((unsigned int)tv.tv_usec - oldus) > (unsigned int)rate_us) {
				libwebsocket_callback_on_writable_all_protocol(&protocols[0]);
				oldus = tv.tv_usec;
			}
		}
#endif
		n = libwebsocket_service(context, 10);
	}
#ifndef LWS_NO_CLIENT
bail:
#endif
	libwebsocket_context_destroy(context);

	lwsl_notice("libwebsockets-test-echo exited cleanly\n");
#ifdef WIN32
#else
	closelog();
#endif

	return 0;
}
