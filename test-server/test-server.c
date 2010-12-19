/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010 Andy Green <andy@warmcat.com>
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

#include "../lib/libwebsockets.h"

/*
 * This demo server shows how to use libwebsockets for one or more
 * websocket protocols in the same server
 *
 * It defines the following websocket protocols:
 *
 *  dumb-increment-protocol:  once the socket is opened, an incrementing
 *				ascii string is sent down it every 50ms.
 * 				If you send "reset\n" on the websocket, then
 * 				the incrementing number is reset to 0.
 *
 *  lws-mirror-protocol: copies any received packet to every connection also
 * 				using this protocol, including the sender
 */


#define LOCAL_RESOURCE_PATH "/usr/share/libwebsockets-test-server"

/* this protocol server (always the first one) just knows how to do HTTP */

static int callback_http(struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
							   void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_HTTP:
		fprintf(stderr, "serving HTTP URI %s\n", in);

		if (in && strcmp(in, "/favicon.ico") == 0) {
			if (libwebsockets_serve_http_file(wsi,
			     LOCAL_RESOURCE_PATH"/favicon.ico", "image/x-icon"))
				fprintf(stderr, "Failed to send favicon\n");
			break;
		}

		/* send the script... when it runs it'll start websockets */

		if (libwebsockets_serve_http_file(wsi,
				  LOCAL_RESOURCE_PATH"/test.html", "text/html"))
			fprintf(stderr, "Failed to send HTTP file\n");
		break;

	default:
		break;
	}

	return 0;
}

/* dumb_increment protocol */

/*
 * one of these is auto-created for each connection and a pointer to the
 * appropriate instance is passed to the callback in the user parameter
 *
 * for this example protocol we use it to individualize the count for each
 * connection.
 */

struct per_session_data__dumb_increment {
	int number;
};

static int
callback_dumb_increment(struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	int n;
	char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +
						  LWS_SEND_BUFFER_POST_PADDING];
	char *p = (char *)&buf[LWS_SEND_BUFFER_PRE_PADDING];
	struct per_session_data__dumb_increment *pss = user;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		pss->number = 0;
		break;

	/*
	 * in this protocol, we just use the broadcast action as the chance to
	 * send our own connection-specific data and ignore the broadcast info
	 * that is available in the 'in' parameter
	 */

	case LWS_CALLBACK_BROADCAST:
		n = sprintf(p, "%d", pss->number++);
		n = libwebsocket_write(wsi, p, n, LWS_WRITE_TEXT);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			return 1;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		fprintf(stderr, "rx %d\n", len);
		if (len < 6)
			break;
		if (strcmp(in, "reset\n") == 0)
			pss->number = 0;
		break;

	default:
		break;
	}

	return 0;
}


/* lws-mirror_protocol */

static int
callback_lws_mirror(struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	int n;

	switch (reason) {

	case LWS_CALLBACK_BROADCAST:
		n = libwebsocket_write(wsi, in, len, LWS_WRITE_TEXT);
		break;

	case LWS_CALLBACK_RECEIVE:
		/*
		 * copy the incoming packet to all other protocol users
		 *
		 * This demonstrates how easy it is to broadcast from inside
		 * a callback.
		 * 
		 * How this works is it calls back to the callback for all
		 * connected sockets using this protocol with
		 * LWS_CALLBACK_BROADCAST reason.  Our handler for that above
		 * writes the data down the socket.
		 */
		libwebsockets_broadcast(libwebsockets_get_protocol(wsi),
								       in, len);
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {
	/* first protocol must always be HTTP handler */
	[0] = {
		.name = "http-only",
		.callback = callback_http,
	},
	[1] = {
		.name = "dumb-increment-protocol",
		.callback = callback_dumb_increment,
		.per_session_data_size =
				sizeof(struct per_session_data__dumb_increment),
	},
	[2] = {
		.name = "lws-mirror-protocol",
		.callback = callback_lws_mirror,
	},
	[3] = {  /* end of list */
		.callback = NULL
	}
};

static struct option options[] = {
	{ "help", 	no_argument, NULL, 'h' },
	{ "port", 	required_argument, NULL, 'p' },
	{ "ssl", 	no_argument, NULL, 's' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	int n = 0;
	const char *cert_path =
			    LOCAL_RESOURCE_PATH"/libwebsockets-test-server.pem";
	const char *key_path =
			LOCAL_RESOURCE_PATH"/libwebsockets-test-server.key.pem";
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1024 +
						  LWS_SEND_BUFFER_POST_PADDING];
	int port = 7681;
	int use_ssl = 0;

	fprintf(stderr, "libwebsockets test server\n"
			"(C) Copyright 2010 Andy Green <andy@warmcat.com> "
						    "licensed under LGPL2.1\n");

	while (n >= 0) {
		n = getopt_long(argc, argv, "hsp:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 's':
			use_ssl = 1;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			fprintf(stderr, "Usage: test-server "
					     "[--port=<p>] [--ssl]\n");
			exit(1);
		}
	}

	if (!use_ssl)
		cert_path = key_path = NULL;

	if (libwebsocket_create_server(port, protocols, cert_path, key_path,
								  -1, -1) < 0) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}

	/*
	 * After initializing and creating the websocket server in its own fork
	 * we return to the main process here
	 */

	buf[LWS_SEND_BUFFER_PRE_PADDING] = 'x';

	while (1) {
		
		usleep(50000);

		/*
		 * This broadcasts to all dumb-increment-protocol connections
		 * at 20Hz.
		 * 
		 * We're just sending a character 'x', in these examples the
		 * callbacks send their own per-connection content.
		 *
		 * You have to send something with nonzero length to get the
		 * callback actions delivered.
		 *
		 * We take care of pre-and-post padding allocation.
		 */

		/* protocols[1] == dumb-increment-protocol */
		libwebsockets_broadcast(&protocols[1],
					&buf[LWS_SEND_BUFFER_PRE_PADDING], 1);
	}

	return 0;
}
