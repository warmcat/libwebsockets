/*
 * libwebsockets-test-server-extpoll - libwebsockets external poll loop sample
 *
 * This acts the same as libwebsockets-test-server but works with the poll
 * loop taken out of libwebsockets and into this app.  It's an example of how
 * you can integrate libwebsockets polling into an app that already has its
 * own poll loop.
 *
 * Copyright (C) 2010-2011 Andy Green <andy@warmcat.com>
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
#ifdef __MINGW32__
#include "../win32port/win32helpers/websock-w32.h"
#else
#ifdef __MINGW64__
#include "../win32port/win32helpers/websock-w32.h"
#else
#include <poll.h>
#endif
#endif

#include "../lib/libwebsockets.h"


/*
 * This demo server shows how to use libwebsockets for one or more
 * websocket protocols in the same server
 *
 * It defines the following websocket protocols:
 *
 *  dumb-increment-protocol:  once the socket is opened, an incrementing
 *				ascii string is sent down it every 50ms.
 *				If you send "reset\n" on the websocket, then
 *				the incrementing number is reset to 0.
 *
 *  lws-mirror-protocol: copies any received packet to every connection also
 *				using this protocol, including the sender
 */

#define MAX_POLL_ELEMENTS 100
struct pollfd pollfds[100];
int count_pollfds = 0;

 

enum demo_protocols {
	/* always first */
	PROTOCOL_HTTP = 0,

	PROTOCOL_DUMB_INCREMENT,
	PROTOCOL_LWS_MIRROR,

	/* always last */
	DEMO_PROTOCOL_COUNT
};


#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"

/* this protocol server (always the first one) just knows how to do HTTP */

static int callback_http(struct libwebsocket_context * this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
							   void *in, size_t len)
{
	int n;
	char client_name[128];
	char client_ip[128];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		fprintf(stderr, "serving HTTP URI %s\n", (char *)in);

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
	 * callback for confirming to continue with client IP appear in
	 * protocol 0 callback since no websocket protocol has been agreed
	 * yet.  You can just ignore this if you won't filter on client IP
	 * since the default uhandled callback return is 0 meaning let the
	 * connection continue.
	 */

	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:

		libwebsockets_get_peer_addresses((int)(long)user, client_name,
			     sizeof(client_name), client_ip, sizeof(client_ip));

		fprintf(stderr, "Received network connect from %s (%s)\n",
							client_name, client_ip);

		/* if we returned non-zero from here, we kill the connection */
		break;

	/*
	 * callbacks for managing the external poll() array appear in
	 * protocol 0 callback
	 */

	case LWS_CALLBACK_ADD_POLL_FD:
		pollfds[count_pollfds].fd = (int)(long)user;
		pollfds[count_pollfds].events = (int)len;
		pollfds[count_pollfds++].revents = 0;
		break;

	case LWS_CALLBACK_DEL_POLL_FD:
		for (n = 0; n < count_pollfds; n++)
			if (pollfds[n].fd == (int)(long)user)
				while (n < count_pollfds) {
					pollfds[n] = pollfds[n + 1];
					n++;
				}
		count_pollfds--;
		break;

	case LWS_CALLBACK_SET_MODE_POLL_FD:
		for (n = 0; n < count_pollfds; n++)
			if (pollfds[n].fd == (int)(long)user)
				pollfds[n].events |= (int)(long)len;
		break;

	case LWS_CALLBACK_CLEAR_MODE_POLL_FD:
		for (n = 0; n < count_pollfds; n++)
			if (pollfds[n].fd == (int)(long)user)
				pollfds[n].events &= ~(int)(long)len;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * this is just an example of parsing handshake headers, you don't need this
 * in your code unless you will filter allowing connections by the header
 * content
 */

static void
dump_handshake_info(struct lws_tokens *lwst)
{
	int n;
	static const char *token_names[] = {
		[WSI_TOKEN_GET_URI] = "GET URI",
		[WSI_TOKEN_HOST] = "Host",
		[WSI_TOKEN_CONNECTION] = "Connection",
		[WSI_TOKEN_KEY1] = "key 1",
		[WSI_TOKEN_KEY2] = "key 2",
		[WSI_TOKEN_PROTOCOL] = "Protocol",
		[WSI_TOKEN_UPGRADE] = "Upgrade",
		[WSI_TOKEN_ORIGIN] = "Origin",
		[WSI_TOKEN_DRAFT] = "Draft",
		[WSI_TOKEN_CHALLENGE] = "Challenge",

		/* new for 04 */
		[WSI_TOKEN_KEY] = "Key",
		[WSI_TOKEN_VERSION] = "Version",
		[WSI_TOKEN_SWORIGIN] = "Sworigin",

		/* new for 05 */
		[WSI_TOKEN_EXTENSIONS] = "Extensions",

		/* client receives these */
		[WSI_TOKEN_ACCEPT] = "Accept",
		[WSI_TOKEN_NONCE] = "Nonce",
		[WSI_TOKEN_HTTP] = "Http",
		[WSI_TOKEN_MUXURL]	= "MuxURL",
	};
	
	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		if (lwst[n].token == NULL)
			continue;

		fprintf(stderr, "    %s = %s\n", token_names[n], lwst[n].token);
	}
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
callback_dumb_increment(struct libwebsocket_context * this,
			struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	int n;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +
						  LWS_SEND_BUFFER_POST_PADDING];
	unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];
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
		n = sprintf((char *)p, "%d", pss->number++);
		n = libwebsocket_write(wsi, p, n, LWS_WRITE_TEXT);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			return 1;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		fprintf(stderr, "rx %d\n", (int)len);
		if (len < 6)
			break;
		if (strcmp(in, "reset\n") == 0)
			pss->number = 0;
		break;

	/*
	 * this just demonstrates how to use the protocol filter. If you won't
	 * study and reject connections based on header content, you don't need
	 * to handle this callback
	 */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		dump_handshake_info((struct lws_tokens *)(long)user);
		/* you could return non-zero here and kill the connection */
		break;

	default:
		break;
	}

	return 0;
}


/* lws-mirror_protocol */

#define MAX_MESSAGE_QUEUE 64

struct per_session_data__lws_mirror {
	struct libwebsocket *wsi;
	int ringbuffer_tail;
};

struct a_message {
	void *payload;
	size_t len;
};

static struct a_message ringbuffer[MAX_MESSAGE_QUEUE];
static int ringbuffer_head;


static int
callback_lws_mirror(struct libwebsocket_context * this,
			struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	int n;
	struct per_session_data__lws_mirror *pss = user;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		pss->ringbuffer_tail = ringbuffer_head;
		pss->wsi = wsi;
		libwebsocket_callback_on_writable(this, wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:

		if (pss->ringbuffer_tail != ringbuffer_head) {

			n = libwebsocket_write(wsi, (unsigned char *)
				   ringbuffer[pss->ringbuffer_tail].payload +
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

			if (((ringbuffer_head - pss->ringbuffer_tail) %
				  MAX_MESSAGE_QUEUE) < (MAX_MESSAGE_QUEUE - 15))
				libwebsocket_rx_flow_control(wsi, 1);

			libwebsocket_callback_on_writable(this, wsi);

		}
		break;

	case LWS_CALLBACK_BROADCAST:
		n = libwebsocket_write(wsi, in, len, LWS_WRITE_TEXT);
		if (n < 0)
			fprintf(stderr, "mirror write failed\n");
		break;

	case LWS_CALLBACK_RECEIVE:

		if (ringbuffer[ringbuffer_head].payload)
			free(ringbuffer[ringbuffer_head].payload);

		ringbuffer[ringbuffer_head].payload =
				malloc(LWS_SEND_BUFFER_PRE_PADDING + len +
						  LWS_SEND_BUFFER_POST_PADDING);
		ringbuffer[ringbuffer_head].len = len;
		memcpy((char *)ringbuffer[ringbuffer_head].payload +
					  LWS_SEND_BUFFER_PRE_PADDING, in, len);
		if (ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
			ringbuffer_head = 0;
		else
			ringbuffer_head++;

		if (((ringbuffer_head - pss->ringbuffer_tail) %
				  MAX_MESSAGE_QUEUE) > (MAX_MESSAGE_QUEUE - 10))
			libwebsocket_rx_flow_control(wsi, 0);

		libwebsocket_callback_on_writable_all_protocol(
					       libwebsockets_get_protocol(wsi));
		break;

	/*
	 * this just demonstrates how to use the protocol filter. If you won't
	 * study and reject connections based on header content, you don't need
	 * to handle this callback
	 */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		dump_handshake_info((struct lws_tokens *)(long)user);
		/* you could return non-zero here and kill the connection */
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {
	/* first protocol must always be HTTP handler */

	{
		"http-only",		/* name */
		callback_http,		/* callback */
		0			/* per_session_data_size */
	},
	{
		"dumb-increment-protocol",
		callback_dumb_increment,
		sizeof(struct per_session_data__dumb_increment),
	},
	{
		"lws-mirror-protocol",
		callback_lws_mirror,
		sizeof(struct per_session_data__lws_mirror)
	},
	{
		NULL, NULL, 0		/* End of list */
	}
};

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "killmask",	no_argument,		NULL, 'k' },
	{ "interface",  required_argument, 	NULL, 'i' },
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
	struct libwebsocket_context *context;
	int opts = 0;
	unsigned int oldus = 0;
	char interface_name[128] = "";
	const char *interface_ptr = NULL;

	fprintf(stderr, "libwebsockets test server with external poll()\n"
			"(C) Copyright 2010-2011 Andy Green <andy@warmcat.com> "
						    "licensed under LGPL2.1\n");

	while (n >= 0) {
		n = getopt_long(argc, argv, "i:khsp:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 's':
			use_ssl = 1;
			break;
		case 'k':
			opts = LWS_SERVER_OPTION_DEFEAT_CLIENT_MASK;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'i':
			strncpy(interface_name, optarg, sizeof interface_name);
			interface_name[(sizeof interface_name) - 1] = '\0';
			interface_ptr = interface_name;
			break;
		case 'h':
			fprintf(stderr, "Usage: test-server "
					     "[--port=<p>] [--ssl]\n");
			exit(1);
		}
	}

	if (!use_ssl)
		cert_path = key_path = NULL;

	context = libwebsocket_create_context(port, interface_ptr, protocols,
					libwebsocket_internal_extensions,
					cert_path, key_path, -1, -1, opts);
	if (context == NULL) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}

	buf[LWS_SEND_BUFFER_PRE_PADDING] = 'x';

	/*
	 * This is an example of an existing application's explicit poll()
	 * loop that libwebsockets can integrate with.
	 */

	while (1) {
		struct timeval tv;

		/*
		 * this represents an existing server's single poll action
		 * which also includes libwebsocket sockets
		 */

		n = poll(pollfds, count_pollfds, 25);
		if (n < 0)
			goto done;

		if (n)
			for (n = 0; n < count_pollfds; n++)
				if (pollfds[n].revents)
					/*
					* returns immediately if the fd does not
					* match anything under libwebsockets
					* control
					*/
					if (libwebsocket_service_fd(context,
								  &pollfds[n]))
						goto done;

		/* do our broadcast periodically */

		gettimeofday(&tv, NULL);

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

		if (((unsigned int)tv.tv_usec - oldus) > 50000) {
			libwebsockets_broadcast(
					&protocols[PROTOCOL_DUMB_INCREMENT],
					&buf[LWS_SEND_BUFFER_PRE_PADDING], 1);
			oldus = tv.tv_usec;
		}
	}

done:
	libwebsocket_context_destroy(context);

	return 0;
}
