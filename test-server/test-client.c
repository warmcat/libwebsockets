/*
 * libwebsockets-test-client - libwebsockets test implementation
 *
 * Copyright (C) 2011 Andy Green <andy@warmcat.com>
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
#include <poll.h>

/*
 * This demo shows how to connect multiple websockets simultaneously to a
 * websocket server (there is no restriction on their having to be the same
 * server just it simplifies the demo).
 *
 *  dumb-increment-protocol:  we connect to the server and print the number
 * 				we are given
 *
 *  lws-mirror-protocol: draws random circles, which are mirrored on to every
 * 				client (see them being drawn in every browser
 * 				session also using the test server)
 */

enum demo_protocols {

	PROTOCOL_DUMB_INCREMENT,
	PROTOCOL_LWS_MIRROR,

	/* always last */
	DEMO_PROTOCOL_COUNT
};


/* dumb_increment protocol */

static int
callback_dumb_increment(struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_RECEIVE:
		fprintf(stderr, "rx %d '%s'\n", len, in);
		break;

	default:
		break;
	}

	return 0;
}


/* lws-mirror_protocol */

/* "how to draw a circle" */

struct coord {
	int x;
	int y;
};

static struct coord circle[] = {

{ 0, 240 },
{ 12, 239 },
{ 25, 238 },
{ 37, 237 },
{ 49, 234 },
{ 62, 231 },
{ 74, 228 },
{ 86, 224 },
{ 97, 219 },
{ 108, 213 },
{ 120, 207 },
{ 130, 201 },
{ 141, 194 },
{ 151, 186 },
{ 160, 178 },
{ 169, 169 },
{ 178, 160 },
{ 186, 151 },
{ 194, 141 },
{ 201, 130 },
{ 207, 120 },
{ 213, 108 },
{ 219, 97 },
{ 224, 86 },
{ 228, 74 },
{ 231, 62 },
{ 234, 49 },
{ 237, 37 },
{ 238, 25 },
{ 239, 12 },
{ 240, 0 },
{ 239, -12 },
{ 238, -25 },
{ 237, -37 },
{ 234, -49 },
{ 231, -62 },
{ 228, -74 },
{ 224, -86 },
{ 219, -97 },
{ 213, -108 },
{ 207, -120 },
{ 201, -130 },
{ 194, -141 },
{ 186, -151 },
{ 178, -160 },
{ 169, -169 },
{ 160, -178 },
{ 151, -186 },
{ 141, -194 },
{ 130, -201 },
{ 120, -207 },
{ 108, -213 },
{ 97, -219 },
{ 86, -224 },
{ 74, -228 },
{ 62, -231 },
{ 49, -234 },
{ 37, -237 },
{ 25, -238 },
{ 12, -239 },
{ 0, -240 },
{ -12, -239 },
{ -25, -238 },
{ -37, -237 },
{ -49, -234 },
{ -62, -231 },
{ -74, -228 },
{ -86, -224 },
{ -97, -219 },
{ -108, -213 },
{ -119, -207 },
{ -130, -201 },
{ -141, -194 },
{ -151, -186 },
{ -160, -178 },
{ -169, -169 },
{ -178, -160 },
{ -186, -151 },
{ -194, -141 },
{ -201, -130 },
{ -207, -120 },
{ -213, -108 },
{ -219, -97 },
{ -224, -86 },
{ -228, -74 },
{ -231, -62 },
{ -234, -49 },
{ -237, -37 },
{ -238, -25 },
{ -239, -12 },
{ -240, 0 },
{ -239, 12 },
{ -238, 25 },
{ -237, 37 },
{ -234, 49 },
{ -231, 62 },
{ -228, 74 },
{ -224, 86 },
{ -219, 97 },
{ -213, 108 },
{ -207, 120 },
{ -201, 130 },
{ -194, 141 },
{ -186, 151 },
{ -178, 160 },
{ -169, 169 },
{ -160, 178 },
{ -151, 186 },
{ -141, 194 },
{ -130, 201 },
{ -119, 207 },
{ -108, 213 },
{ -97, 219 },
{ -86, 224 },
{ -74, 228 },
{ -62, 231 },
{ -49, 234 },
{ -37, 237 },
{ -25, 238 },
{ -12, 239 },
{ 0, 240 },
	
};

static int
callback_lws_mirror(struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_RECEIVE:
//		fprintf(stderr, "rx %d '%s'\n", len, in);
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {

	[PROTOCOL_DUMB_INCREMENT] = {
		.name = "dumb-increment-protocol",
		.callback = callback_dumb_increment,
	},
	[PROTOCOL_LWS_MIRROR] = {
		.name = "lws-mirror-protocol",
		.callback = callback_lws_mirror,
	},
	[DEMO_PROTOCOL_COUNT] = {  /* end of list */
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
	int port = 7681;
	int use_ssl = 0;
	struct libwebsocket_context *context;
	const char * address = argv[1];
	struct libwebsocket *wsi_dumb;
	struct libwebsocket *wsi_mirror;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1024 +
						  LWS_SEND_BUFFER_POST_PADDING];
	int len;
	int i = 0;
	int xofs;
	int yofs;
	int oldx;
	int oldy;
	int scale;
	int colour;

	fprintf(stderr, "libwebsockets test client\n"
			"(C) Copyright 2010 Andy Green <andy@warmcat.com> "
						    "licensed under LGPL2.1\n");

	if (argc < 2)
		goto usage;

	optind++;

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
			goto usage;
		}
	}

	/*
	 * create the websockets context.  This tracks open connections and
	 * knows how to route any traffic and which protocol version to use,
	 * and if each connection is client or server side.
	 *
	 * For this client-only demo, we tell it to not listen on any port.
	 */

	context = libwebsocket_create_context(CONTEXT_PORT_NO_LISTEN,
						 protocols, NULL, NULL, -1, -1);
	if (context == NULL) {
		fprintf(stderr, "Creating libwebsocket context failed\n");
		return 1;
	}


	/* create a client websocket using dumb increment protocol */

	wsi_dumb = libwebsocket_client_connect(context, address, port, "/",
				       "http://host", "origin",
				       protocols[PROTOCOL_DUMB_INCREMENT].name);

	if (wsi_dumb == NULL) {
		fprintf(stderr, "libwebsocket dumb connect failed\n");
		return -1;
	}

	/* create a client websocket using mirror protocol */

	wsi_mirror = libwebsocket_client_connect(context, address, port, "/",
				       "http://host", "origin",
				       protocols[PROTOCOL_LWS_MIRROR].name);

	if (wsi_mirror == NULL) {
		fprintf(stderr, "libwebsocket dumb connect failed\n");
		return -1;
	}

	fprintf(stderr, "Websocket connections opened\n");

	/*
	 * sit there servicing the websocket context to handle incoming
	 * packets, and drawing random circles on the mirror protocol websocket
	 */

	n = 0;
	while (n >= 0) {

		usleep(10000);

		if (i == sizeof circle / sizeof circle[0])
			i = 0;

		if (i == 0) {
			xofs = random() % 500;
			yofs = random() % 250;
			scale = random() % 24;
			if (!scale)
				scale = 1;

			oldx = xofs + (circle[i].x / scale);
			oldy = yofs + (circle[i].y / scale);
			colour = random() & 0xffffff;
		}

		len = sprintf(&buf[LWS_SEND_BUFFER_PRE_PADDING],
			"d #%06X %d %d %d %d", colour, oldx, oldy,
				xofs + (circle[i].x / scale),
				yofs + (circle[i].y / scale));
		oldx = xofs + (circle[i].x / scale);
		oldy = yofs + (circle[i].y / scale);
		i++;

		libwebsocket_write(wsi_mirror,
			&buf[LWS_SEND_BUFFER_PRE_PADDING], len, LWS_WRITE_TEXT);


		n = libwebsocket_service(context, 0);
	}

	libwebsocket_client_close(wsi_dumb);
	libwebsocket_client_close(wsi_mirror);

	return 0;

usage:
	fprintf(stderr, "Usage: libwebsockets-test-client "
					     "<server address> [--port=<p>] "
					     "[--ssl]\n");
	return 1;
}
