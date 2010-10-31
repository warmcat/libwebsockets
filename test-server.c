#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "libwebsockets.h"

/*
 * libwebsocket Example server  Copyright 2010 Andy Green <andy@warmcat.com>
 * 
 * Shows how to use libwebsocket 
 */


static int port = 7681;
static int ws_protocol = 76;

static int websocket_callback(struct libwebsocket * wsi,
	       enum libwebsocket_callback_reasons reason, void *in, size_t len)
{
	int n;
	char buf[LWS_SEND_BUFFER_PRE_PADDING + 256 + LWS_SEND_BUFFER_POST_PADDING];
	static int bump;
	static int slow;
	
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		fprintf(stderr, "Websocket connection established\n");
		slow = 500;
		break;

	case LWS_CALLBACK_CLOSED:
		fprintf(stderr, "Websocket connection closed\n");
		break;

	case LWS_CALLBACK_SEND:	
		slow--;
		if (slow) {
			usleep(10000);
			break;
		}
		slow = 100;
		n = sprintf(&buf[LWS_SEND_BUFFER_PRE_PADDING], "%d", bump++);
		n = libwebsocket_write(wsi, (unsigned char *)&buf[LWS_SEND_BUFFER_PRE_PADDING], n, 0);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			exit(1);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		fprintf(stderr, "Received %d bytes payload\n", (int)len);
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

	fprintf(stderr, "libwebsockets test server\nCopyright 2010 Andy Green <andy@warmcat.com> licensed under GPL2\n");
	
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
			fprintf(stderr, "Usage: test-server [--port=<p>] [--protocol=<v>]\n");
			exit(1);
		}
		
	}
	
	if (libwebsocket_create_server(port, websocket_callback, ws_protocol) < 0) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}
		
	while (1)
		sleep(1);

	return 0;
}
