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
static int port = 7681;
static int use_ssl = 0;

/* this protocol server (always the first one) just knows how to do HTTP */

static int callback_http(struct libwebsocket * wsi,
		enum libwebsocket_callback_reasons reason, void * user,
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

struct per_session_data__dumb_increment {
	int number;
};

static int
callback_dumb_increment(struct libwebsocket * wsi,
			enum libwebsocket_callback_reasons reason,
			void * user, void *in, size_t len)
{
	int n;
	char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +
						  LWS_SEND_BUFFER_POST_PADDING];
	unsigned char *p = (unsigned char *)&buf[LWS_SEND_BUFFER_PRE_PADDING];
	struct per_session_data__dumb_increment * pss = user;
	
	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		pss->number = 0;
		break;

	case LWS_CALLBACK_SEND:	
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

#define MAX_MESSAGE_QUEUE 64

struct per_session_data__lws_mirror {
	struct libwebsocket * wsi;
	int ringbuffer_tail;
};

struct a_message {
	void * payload;
	size_t len;
};

static struct a_message ringbuffer[MAX_MESSAGE_QUEUE];
static int ringbuffer_head;


static int
callback_lws_mirror(struct libwebsocket * wsi,
			enum libwebsocket_callback_reasons reason,
			void * user, void *in, size_t len)
{
	int n;
	char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +
						  LWS_SEND_BUFFER_POST_PADDING];
	unsigned char *p = (unsigned char *)&buf[LWS_SEND_BUFFER_PRE_PADDING];
	struct per_session_data__lws_mirror * pss = user;
	
	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		pss->wsi = wsi;
		pss->ringbuffer_tail = ringbuffer_head;
		break;

	case LWS_CALLBACK_SEND:	
		/* send everything that's pending */
		while (pss->ringbuffer_tail != ringbuffer_head) {

			n = libwebsocket_write(wsi,
				(unsigned char *)ringbuffer[pss->ringbuffer_tail].payload +
					LWS_SEND_BUFFER_PRE_PADDING,
				   ringbuffer[pss->ringbuffer_tail].len,
							LWS_WRITE_TEXT);
			if (n < 0) {
				fprintf(stderr, "ERROR writing to socket");
				exit(1);
			}

			if (pss->ringbuffer_tail == (MAX_MESSAGE_QUEUE - 1))
				pss->ringbuffer_tail = 0;
			else
				pss->ringbuffer_tail++;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (ringbuffer[ringbuffer_head].payload)
			free(ringbuffer[ringbuffer_head].payload );

		ringbuffer[ringbuffer_head].payload =
				malloc(LWS_SEND_BUFFER_PRE_PADDING + len +
						  LWS_SEND_BUFFER_POST_PADDING);
		ringbuffer[ringbuffer_head].len = len;
		memcpy(ringbuffer[ringbuffer_head].payload +
					  LWS_SEND_BUFFER_PRE_PADDING, in, len);
		if (ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
			ringbuffer_head = 0;
		else
			ringbuffer_head++;
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static const struct libwebsocket_protocols protocols[] = {
	{
		.name = "http-only",
		.callback = callback_http,
		.per_session_data_size = 0,
	},
	{
		.name = "dumb-increment-protocol",
		.callback = callback_dumb_increment,
		.per_session_data_size =
				sizeof(struct per_session_data__dumb_increment),
	},
	{
		.name = "lws-mirror-protocol",
		.callback = callback_lws_mirror,
		.per_session_data_size =
				sizeof(struct per_session_data__lws_mirror),
	},
	{  /* end of list */
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
	const char * cert_path =
			    LOCAL_RESOURCE_PATH"/libwebsockets-test-server.pem";
	const char * key_path =
			LOCAL_RESOURCE_PATH"/libwebsockets-test-server.key.pem";

	fprintf(stderr, "libwebsockets test server\n"
			"(C) Copyright 2010 Andy Green <andy@warmcat.com> "
						    "licensed under LGPL2.1\n");
	
	while (n >= 0) {
		n = getopt_long(argc, argv, "hp:", options, NULL);
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
	
	if (libwebsocket_create_server(port, protocols,
				       cert_path, key_path, -1, -1) < 0) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}

	return 0;
}
