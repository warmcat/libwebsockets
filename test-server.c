#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "libwebsockets.h"

/*
 * libwebsocket Example server  Copyright 2010 Andy Green <andy@warmcat.com>
 * 
 * Shows how to use libwebsocket 
 */

static int port = 7681;
static int ws_protocol = 76;

/*
 * libwebsockets needs this one callback in your server application, it's
 * called for a handful of different reasons during the connection lifecycle.
 * 
 * All the serving actions occur in the callback but the websocket protocol
 * stuff is already handled by the library.
 */

static int websocket_callback(struct libwebsocket * wsi,
		enum libwebsocket_callback_reasons reason, void *in, size_t len)
{
	int n;
	char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +
						  LWS_SEND_BUFFER_POST_PADDING];
	static int bump;
	char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];
	const char *uri;
	
	switch (reason) {
	/*
	 * Websockets session handshake completed and is established
	 */
	case LWS_CALLBACK_ESTABLISHED:
		fprintf(stderr, "Websocket connection established\n");
		break;

	/*
	 * Websockets session is closed
	 */
	case LWS_CALLBACK_CLOSED:
		fprintf(stderr, "Websocket connection closed\n");
		break;

	/*
	 * Opportunity for us to send something on the connection
	 */
	case LWS_CALLBACK_SEND:	
		n = sprintf(p, "%d", bump++);
		n = libwebsocket_write(wsi, (unsigned char *)p, n, 0);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			exit(1);
		}
		break;
	/*
	 * Something has arrived for us on the connection, it's len bytes long
	 * and is available at *in
	 */
	case LWS_CALLBACK_RECEIVE:
		fprintf(stderr, "Received %d bytes payload\n", (int)len);
		break;

	/*
	 * The client has asked us for something in normal HTTP mode,
	 * not websockets mode.  Normally it means we want to send
	 * our script / html to the client, and when that script runs
	 * it will start up separate websocket connections.
	 * 
	 * Interpret the URI string to figure out what is needed to send
	 */
		 
	case LWS_CALLBACK_HTTP:

		uri = libwebsocket_get_uri(wsi);
		if (uri && strcmp(uri, "/favicon.ico") == 0) {
			if (libwebsockets_serve_http_file(wsi, "./favicon.ico",
								"image/x-icon"))
				fprintf(stderr, "Failed to send favicon\n");
			break;
		}
		
		/* send the script... when it runs it'll start websockets */

		if (libwebsockets_serve_http_file(wsi, "./test.html",
								   "text/html"))
			fprintf(stderr, "Failed to send HTTP file\n");

		break;
	}

	return 0;
}

static struct option options[] = {
	{ "help", 	no_argument, NULL, 'h' },
	{ "port", 	required_argument, NULL, 'p' },
	{ "protocol", 	required_argument, NULL, 'r' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	int n = 0;

	fprintf(stderr, "libwebsockets test server\n"
			"Copyright 2010 Andy Green <andy@warmcat.com> "
						       "licensed under GPL2\n");
	
	while (n >= 0) {
		n = getopt_long(argc, argv, "hp:r:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			ws_protocol = atoi(optarg);
			break;
		case 'h':
			fprintf(stderr, "Usage: test-server "
					     "[--port=<p>] [--protocol=<v>]\n");
			exit(1);
		}
	}
	
	if (libwebsocket_create_server(port, websocket_callback, ws_protocol) <
									    0) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}
	
	/* just sit there until killed */
		
	while (1)
		sleep(10);

	return 0;
}
