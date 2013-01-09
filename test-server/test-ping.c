/*
 * libwebsockets-test-ping - libwebsockets floodping
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
#include <signal.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/ioctl.h>

#include "../lib/libwebsockets.h"
#include <poll.h>

/*
 * this is specified in the 04 standard, control frames can only have small
 * payload length styles
 */
#define MAX_PING_PAYLOAD 125
#define MAX_MIRROR_PAYLOAD 4096
#define MAX_PING_CLIENTS 256
#define PING_RINGBUFFER_SIZE 256

static struct libwebsocket *ping_wsi[MAX_PING_CLIENTS];
static unsigned int interval_us = 1000000;
static unsigned int size = 64;
static int flood;
static const char *address;
static unsigned char pingbuf[LWS_SEND_BUFFER_PRE_PADDING + MAX_MIRROR_PAYLOAD +
						  LWS_SEND_BUFFER_POST_PADDING];
static char peer_name[128];
static unsigned long started;
static int screen_width = 80;
static int use_mirror;
static unsigned int write_options;

static unsigned long rtt_min = 100000000;
static unsigned long rtt_max;
static unsigned long rtt_avg;
static unsigned long global_rx_count;
static unsigned long global_tx_count;
static int clients = 1;
static unsigned long interrupted_time;

struct ping {
	unsigned long issue_timestamp;
	unsigned long index;
	unsigned int seen;
};

struct per_session_data__ping {
	unsigned long ping_index;

	struct ping ringbuffer[PING_RINGBUFFER_SIZE];
	int ringbuffer_head;
	int ringbuffer_tail;

	unsigned long rx_count;
};

/*
 * uses the ping pong protocol features to provide an equivalent for the
 * ping utility for 04+ websockets
 */

enum demo_protocols {

	PROTOCOL_LWS_MIRROR,

	/* always last */
	DEMO_PROTOCOL_COUNT
};


static int
callback_lws_mirror(struct libwebsocket_context * this,
			struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	struct timeval tv;
	unsigned char *p;
	int shift;
	unsigned long l;
	unsigned long iv;
	int n;
	int match = 0;
	struct per_session_data__ping *psd = user;

	switch (reason) {
	case LWS_CALLBACK_CLOSED:

		fprintf(stderr, "LWS_CALLBACK_CLOSED on %p\n", (void *)wsi);

		/* remove closed guy */
	
		for (n = 0; n < clients; n++)
			if (ping_wsi[n] == wsi) {				
				clients--;
				while (n < clients) {
					ping_wsi[n] = ping_wsi[n + 1];
					n++;
				}
			}

		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:

		psd->rx_count = 0;
		psd->ping_index = 1;
		psd->ringbuffer_head = 0;
		psd->ringbuffer_tail = 0;

		/*
		 * start the ball rolling,
		 * LWS_CALLBACK_CLIENT_WRITEABLE will come next service
		 */

		libwebsocket_callback_on_writable(this, wsi);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		gettimeofday(&tv, NULL);
		iv = (tv.tv_sec * 1000000) + tv.tv_usec;

		psd->rx_count++;

		shift = 56;
		p = in;
		l = 0;

		while (shift >= 0) {
			l |= (*p++) << shift;
			shift -= 8;
		}

		/* find it in the ringbuffer, look backwards from head */
		n = psd->ringbuffer_head;
		while (!match) {

			if (psd->ringbuffer[n].index == l) {
				psd->ringbuffer[n].seen++;
				match = 1;
				continue;
			}

			if (n == psd->ringbuffer_tail) {
				match = -1;
				continue;
			}

			if (n == 0)
				n = PING_RINGBUFFER_SIZE - 1;
			else
				n--;
		}

		if (match < 1) {

			if (!flood)
				fprintf(stderr, "%d bytes from %s: req=%ld "
				      "time=(unknown)\n", (int)len, address, l);
			else
				fprintf(stderr, "\b \b");

			break;
		}

		if (psd->ringbuffer[n].seen > 1)
			fprintf(stderr, "DUP! ");

		if ((iv - psd->ringbuffer[n].issue_timestamp) < rtt_min)
			rtt_min = iv - psd->ringbuffer[n].issue_timestamp;

		if ((iv - psd->ringbuffer[n].issue_timestamp) > rtt_max)
			rtt_max = iv - psd->ringbuffer[n].issue_timestamp;

		rtt_avg += iv - psd->ringbuffer[n].issue_timestamp;
		global_rx_count++;

		if (!flood)
			fprintf(stderr, "%d bytes from %s: req=%ld "
				"time=%lu.%lums\n", (int)len, address, l,
			       (iv - psd->ringbuffer[n].issue_timestamp) / 1000,
			((iv - psd->ringbuffer[n].issue_timestamp) / 100) % 10);
		else
			fprintf(stderr, "\b \b");
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:

		shift = 56;
		p = &pingbuf[LWS_SEND_BUFFER_PRE_PADDING];

		/* 64-bit ping index in network byte order */

		while (shift >= 0) {
			*p++ = psd->ping_index >> shift;
			shift -= 8;
		}

		gettimeofday(&tv, NULL);

		psd->ringbuffer[psd->ringbuffer_head].issue_timestamp =
					     (tv.tv_sec * 1000000) + tv.tv_usec;
		psd->ringbuffer[psd->ringbuffer_head].index = psd->ping_index++;
		psd->ringbuffer[psd->ringbuffer_head].seen = 0;

		if (psd->ringbuffer_head == PING_RINGBUFFER_SIZE - 1)
			psd->ringbuffer_head = 0;
		else
			psd->ringbuffer_head++;

		/* snip any re-used tail so we keep to the ring length */

		if (psd->ringbuffer_tail == psd->ringbuffer_head) {
			if (psd->ringbuffer_tail == PING_RINGBUFFER_SIZE - 1)
				psd->ringbuffer_tail = 0;
			else
				psd->ringbuffer_tail++;
		}

		global_tx_count++;

		if (use_mirror)
			libwebsocket_write(wsi,
				&pingbuf[LWS_SEND_BUFFER_PRE_PADDING],
					size, write_options | LWS_WRITE_BINARY);
		else
			libwebsocket_write(wsi,
				&pingbuf[LWS_SEND_BUFFER_PRE_PADDING],
					size, write_options | LWS_WRITE_PING);

		if (flood &&
			 (psd->ping_index - psd->rx_count) < (screen_width - 1))
			fprintf(stderr, ".");
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {

	[PROTOCOL_LWS_MIRROR] = {
		.name = "lws-mirror-protocol",
		.callback = callback_lws_mirror,
		.per_session_data_size = sizeof (struct per_session_data__ping),
	},
	[DEMO_PROTOCOL_COUNT] = {  /* end of list */
		.callback = NULL
	}
};

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 't' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "size",	required_argument,	NULL, 's' },
	{ "protocol",	required_argument,	NULL, 'n' },
	{ "flood",	no_argument,		NULL, 'f' },
	{ "mirror",	no_argument,		NULL, 'm' },
	{ "replicate",	required_argument,	NULL, 'r' },
	{ "killmask",	no_argument,		NULL, 'k' },
	{ "version",	required_argument,	NULL, 'v' },
	{ NULL, 0, 0, 0 }
};


static void
signal_handler(int sig, siginfo_t *si, void *v)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	interrupted_time = (tv.tv_sec * 1000000) + tv.tv_usec;
}


int main(int argc, char **argv)
{
	int n = 0;
	int port = 7681;
	int use_ssl = 0;
	struct libwebsocket_context *context;
	char protocol_name[256];
	char ip[30];
	struct sigaction sa;
	struct timeval tv;
	struct winsize w;
	unsigned long oldus = 0;
	unsigned long l;
	int ietf_version = -1;

	if (argc < 2)
		goto usage;

	address = argv[1];
	optind++;

	while (n >= 0) {
		n = getopt_long(argc, argv, "v:kr:hmfts:n:i:p:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'm':
			use_mirror = 1;
			break;
		case 't':
			use_ssl = 2; /* 2 = allow selfsigned */
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			strncpy(protocol_name, optarg, sizeof protocol_name);
			protocol_name[(sizeof protocol_name) - 1] = '\0';
			protocols[PROTOCOL_LWS_MIRROR].name = protocol_name;
			break;
		case 'i':
			interval_us = 1000000.0 * atof(optarg);
			break;
		case 's':
			size = atoi(optarg);
			break;
		case 'f':
			flood = 1;
			break;
		case 'r':
			clients = atoi(optarg);
			if (clients > MAX_PING_CLIENTS || clients < 1) {
				fprintf(stderr, "Max clients supportd = %d\n",
							      MAX_PING_CLIENTS);
				return 1;
			}
			break;
		case 'k':
			write_options = LWS_WRITE_CLIENT_IGNORE_XOR_MASK;
			break;
		case 'v':
			ietf_version = atoi(optarg);
			break;

		case 'h':
			goto usage;
		}
	}

	if (!use_mirror) {
		if (size > MAX_PING_PAYLOAD) {
			fprintf(stderr, "Max ping opcode payload size %d\n",
							      MAX_PING_PAYLOAD);
			return 1;
		}
	} else {
		if (size > MAX_MIRROR_PAYLOAD) {
			fprintf(stderr, "Max mirror payload size %d\n",
							    MAX_MIRROR_PAYLOAD);
			return 1;
		}
	}


	if (isatty(STDOUT_FILENO))
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1)
			if (w.ws_col > 0)
				screen_width = w.ws_col;

	context = libwebsocket_create_context(CONTEXT_PORT_NO_LISTEN, NULL,
					      protocols,
					      libwebsocket_internal_extensions,
					      NULL, NULL, NULL, -1, -1, 0, NULL);
	if (context == NULL) {
		fprintf(stderr, "Creating libwebsocket context failed\n");
		return 1;
	}

	/* create client websockets using dumb increment protocol */

	for (n = 0; n < clients; n++) {
		ping_wsi[n] = libwebsocket_client_connect(context, address,
						   port, use_ssl, "/", address,
				 "origin", protocols[PROTOCOL_LWS_MIRROR].name,
								  ietf_version);
		if (ping_wsi[n] == NULL) {
			fprintf(stderr, "client connnection %d failed to "
								"connect\n", n);
			return 1;
		}
	}

	libwebsockets_get_peer_addresses(
			libwebsocket_get_socket_fd(ping_wsi[0]),
				    peer_name, sizeof peer_name, ip, sizeof ip);

	fprintf(stderr, "Websocket PING %s (%s) %d bytes of data.\n",
							   peer_name, ip, size);

	/* set the ^C handler */

	sa.sa_sigaction = signal_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

	gettimeofday(&tv, NULL);
	started = (tv.tv_sec * 1000000) + tv.tv_usec;

	/* service loop */

	n = 0;
	while (n >= 0) {

		gettimeofday(&tv, NULL);
		l = (tv.tv_sec * 1000000) + tv.tv_usec;

		/* servers can hang up on us */

		if (clients == 0) {
			n = -1;
			continue;
		}

		if (!interrupted_time) {
			if ((l - oldus) > interval_us) {
				for (n = 0; n < clients; n++)
					libwebsocket_callback_on_writable(
							  context, ping_wsi[n]);
				oldus = l;
			}
		} else

			/* allow time for in-flight pongs to come */
		
			if ((l - interrupted_time) > 250000) {
				n = -1;
				continue;
			}

		if (!interval_us)
			n = libwebsocket_service(context, 0);
		else
			n = libwebsocket_service(context, 1);
	}

	/* stats */

	fprintf(stderr, "\n--- %s websocket ping statistics "
		"using %d connections ---\n"
		"%lu packets transmitted, %lu received, "
		"%lu%% packet loss, time %ldms\n"
		"rtt min/avg/max = %0.3f/%0.3f/%0.3f ms\n"
		"payload bandwidth average %0.3f KiBytes/sec\n",
		peer_name, clients, global_tx_count, global_rx_count,
		((global_tx_count - global_rx_count) * 100) / global_tx_count,
		(l - started) / 1000,
		((double)rtt_min) / 1000.0,
		((double)rtt_avg / global_rx_count) / 1000.0,
		((double)rtt_max) / 1000.0,
		((double)global_rx_count * (double)size) /
				  ((double)(l - started) / 1000000.0) / 1024.0);

	libwebsocket_context_destroy(context);

	return 0;

usage:
	fprintf(stderr, "Usage: libwebsockets-test-ping "
					     "<server address> [--port=<p>] "
					     "[--ssl] [--interval=<float sec>] "
					     "[--size=<bytes>] "
					     "[--protocol=<protocolname>] "
					     "[--mirror] "
					     "[--replicate=clients>]"
					     "[--version <version>]"
					     "\n");
	return 1;
}
