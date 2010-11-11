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

#define LOCAL_RESOURCE_PATH "/usr/share/libwebsockets-test-server"
static int port = 7681;
static int ws_protocol = 76;
static int use_ssl = 0;

struct per_session_data {
	int number;
};

 /**
 * libwebsocket_callback() - User server actions
 * @wsi:	Opaque websocket instance pointer
 * @reason:	The reason for the call
 * @user:	Pointer to per-session user data allocated by library
 * @in:		Pointer used for some callback reasons
 * @len:	Length set for some callback reasons
 * 
 * 	This callback is the way the user controls what is served.  All the
 * 	protocol detail is hidden and handled by the library.
 * 
 * 	For each connection / session there is user data allocated that is
 * 	pointed to by "user".  You set the size of this user data area when
 * 	the library is initialized with libwebsocket_create_server.
 * 
 * 	You get an opportunity to initialize user data when called back with
 * 	LWS_CALLBACK_ESTABLISHED reason.
 * 
 * 	LWS_CALLBACK_ESTABLISHED:  after successful websocket handshake
 * 
 * 	LWS_CALLBACK_CLOSED: when the websocket session ends
 *
 * 	LWS_CALLBACK_SEND: opportunity to send to client (you would use
 * 				libwebsocket_write() taking care about the
 * 				special buffer requirements
 * 	LWS_CALLBACK_RECEIVE: data has appeared for the server, it can be
 *				found at *in and is len bytes long
 *
 *  	LWS_CALLBACK_HTTP: an http request has come from a client that is not
 * 				asking to upgrade the connection to a websocket
 * 				one.  This is a chance to serve http content,
 * 				for example, to send a script to the client
 * 				which will then open the websockets connection.
 * 				@in points to the URI path requested and 
 * 				libwebsockets_serve_http_file() makes it very
 * 				simple to send back a file to the client.
 *
 * 	LWS_CALLBACK_PROTOCOL_FILTER: before the confirmation handshake is sent
 * 				the user callback is given a chance to confirm
 * 				it's OK with the protocol that was requested
 * 				from the client.  The protocol string (which
 * 				may be NULL if no protocol header was sent)
 * 				can be found at parameter @in.  Return 0 from
 * 				the callback to allow the connection or nonzero
 * 				to abort the connection.
 */

static int websocket_callback(struct libwebsocket * wsi,
		enum libwebsocket_callback_reasons reason, void * user,
							   void *in, size_t len)
{
	int n;
	char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +
						  LWS_SEND_BUFFER_POST_PADDING];
	char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];
	struct per_session_data * pss = user;
	
	switch (reason) {
	/*
	 * Websockets session handshake completed and is established
	 */
	case LWS_CALLBACK_ESTABLISHED:
		fprintf(stderr, "Websocket connection established\n");
		pss->number = 0;
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
		n = sprintf(p, "%d", pss->number++);
		n = libwebsocket_write(wsi, (unsigned char *)p, n,
								LWS_WRITE_TEXT);
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

	/*
	 * This is our chance to choose if we support one of the requested
	 * protocols or not.  in points to the protocol string.  Nonzero return
	 * aborts the connection handshake
	 */

	case LWS_CALLBACK_PROTOCOL_FILTER:
		if (in == NULL) {
			fprintf(stderr, "Client did not request protocol\n");
			/* accept it */
			return 0;
		}
		fprintf(stderr, "Client requested protocol '%s'\n", in);
		/* accept it */
		return 0;
	}

	return 0;
}

static struct option options[] = {
	{ "help", 	no_argument, NULL, 'h' },
	{ "port", 	required_argument, NULL, 'p' },
	{ "protocol", 	required_argument, NULL, 'r' },
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
		n = getopt_long(argc, argv, "hp:r:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 's':
			use_ssl = 1;
			break;
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

	if (!use_ssl)
		cert_path = key_path = NULL;
	
	if (libwebsocket_create_server(port, websocket_callback, ws_protocol,
					 sizeof(struct per_session_data),
					     cert_path, key_path, -1, -1) < 0) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}
	
	/* just sit there until killed */
		
	while (1)
		sleep(10);

	return 0;
}
