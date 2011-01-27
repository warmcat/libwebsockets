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

static unsigned int interval_us = 1000000;
static unsigned int size = 64;
static int flood = 0;
static const char *address;
static unsigned char pingbuf[LWS_SEND_BUFFER_PRE_PADDING + MAX_MIRROR_PAYLOAD +
						  LWS_SEND_BUFFER_POST_PADDING];
static unsigned long oldus = 0;
static unsigned long ping_index = 1;
static char *hname = "(unknown)";
static unsigned long rx_count = 0;
static unsigned long started;

static unsigned long rtt_min = 100000000;
static unsigned long rtt_max = 0;
static unsigned long rtt_avg = 0;
static int screen_width = 80;
static int use_mirror = 0;

struct ping {
	unsigned long issue_timestamp;
	unsigned long index;
	unsigned int seen;
};

#define PING_RINGBUFFER_SIZE 256

struct ping ringbuffer[PING_RINGBUFFER_SIZE];
int ringbuffer_head;
int ringbuffer_tail;

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
callback_lws_mirror(struct libwebsocket *wsi,
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

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:

		/*
		 * start the ball rolling,
		 * LWS_CALLBACK_CLIENT_WRITEABLE will come next service
		 */

		libwebsocket_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		gettimeofday(&tv, NULL);
		iv = (tv.tv_sec * 1000000) + tv.tv_usec;

		rx_count++;

		shift = 56;
		p = in;
		l = 0;

		while (shift >= 0) {
			l |= (*p++) << shift;
			shift -= 8;
		}

		/* find it in the ringbuffer, look backwards from head */
		n = ringbuffer_head;
		while (!match) {

			if (ringbuffer[n].index == l) {
				ringbuffer[n].seen++;
				match = 1;
				continue;
			}

			if (n == ringbuffer_tail) {
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

		if (ringbuffer[n].seen > 1)
			fprintf(stderr, "DUP! ");

		if ((iv - ringbuffer[n].issue_timestamp) < rtt_min)
			rtt_min = iv - ringbuffer[n].issue_timestamp;

		if ((iv - ringbuffer[n].issue_timestamp) > rtt_max)
			rtt_max = iv - ringbuffer[n].issue_timestamp;

		rtt_avg += iv - ringbuffer[n].issue_timestamp;

	
		if (!flood)
			fprintf(stderr, "%d bytes from %s: req=%ld "
					"time=%lu.%lums\n", (int)len, address, l,
					(iv - ringbuffer[n].issue_timestamp) / 1000,
					((iv - ringbuffer[n].issue_timestamp) / 100) % 10
					);
		else
			fprintf(stderr, "\b \b");
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:

		shift = 56;
		p = &pingbuf[LWS_SEND_BUFFER_PRE_PADDING];

		while (shift >= 0) {
			*p++ = ping_index >> shift;
			shift -= 8;
		}
	
		gettimeofday(&tv, NULL);
		
		ringbuffer[ringbuffer_head].issue_timestamp =
					     (tv.tv_sec * 1000000) + tv.tv_usec;
		ringbuffer[ringbuffer_head].index = ping_index++;
		ringbuffer[ringbuffer_head].seen = 0;

		if (ringbuffer_head == PING_RINGBUFFER_SIZE - 1)
			ringbuffer_head = 0;
		else
			ringbuffer_head++;

		/* snip any re-used tail so we keep the whole buffer length */

		if (ringbuffer_tail == ringbuffer_head) {
			if (ringbuffer_tail == PING_RINGBUFFER_SIZE - 1)
				ringbuffer_tail = 0;
			else
				ringbuffer_tail++;
		}

		if (use_mirror)
			libwebsocket_write(wsi,
				&pingbuf[LWS_SEND_BUFFER_PRE_PADDING],
							size, LWS_WRITE_BINARY);
		else
			libwebsocket_write(wsi,
				&pingbuf[LWS_SEND_BUFFER_PRE_PADDING],
							  size, LWS_WRITE_PING);

		if (flood && (ping_index - rx_count) < (screen_width - 1))
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
	{ NULL, 0, 0, 0 }
};


static void
signal_handler(int sig, siginfo_t *si, void *v)
{
	struct timeval tv;
	unsigned long l;

	gettimeofday(&tv, NULL);
	l = (tv.tv_sec * 1000000) + tv.tv_usec;

	fprintf(stderr, "\n--- %s websocket ping statistics ---\n"
		"%lu packets transmitted, %lu received, %lu%% packet loss, time %ldms\n"
		"rtt min/avg/max = %0.3f/%0.3f/%0.3f ms\n",
		hname, ping_index - 1, rx_count,
		(((ping_index - 1) - rx_count) * 100) / (ping_index - 1),
		(l - started) / 1000,
		((double)rtt_min) / 1000.0,
		((double)rtt_avg / rx_count) / 1000.0,
		((double)rtt_max) / 1000.0
	);

	exit(0);
}


int main(int argc, char **argv)
{
	int n = 0;
	int port = 7681;
	int use_ssl = 0;
	struct libwebsocket_context *context;
	struct libwebsocket *wsi_mirror;
	char protocol_name[256];
	unsigned int len;
	struct sockaddr_in sin;
	struct hostent *host;
	struct hostent *host1;
	char ip[30];
	char *p;
	struct sigaction sa;
	struct timeval tv;
	struct winsize w;
                
	if (argc < 2)
		goto usage;

	address = argv[1];
	optind++;

	while (n >= 0) {
		n = getopt_long(argc, argv, "hmfts:n:i:p:", options, NULL);
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
			protocol_name[(sizeof protocol_name) -1] = '\0';
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

	context = libwebsocket_create_context(CONTEXT_PORT_NO_LISTEN,
						 protocols, NULL, NULL, -1, -1);
	if (context == NULL) {
		fprintf(stderr, "Creating libwebsocket context failed\n");
		return 1;
	}

	/* create a client websocket using dumb increment protocol */

	wsi_mirror = libwebsocket_client_connect(context, address, port, use_ssl,
					"/", "http://host", "origin",
				       protocols[PROTOCOL_LWS_MIRROR].name);

	if (wsi_mirror == NULL) {
		fprintf(stderr, "libwebsocket connect failed\n");
		return -1;
	}

	strcpy(ip, "(unknown)");
	len = sizeof sin;
	if (getpeername(libwebsocket_get_socket_fd(wsi_mirror),
					    (struct sockaddr *) &sin, &len) < 0)
		perror("getpeername");
	else {
		host = gethostbyaddr((char *) &sin.sin_addr,
				    sizeof sin.sin_addr,
				    AF_INET);
		if (host == NULL)
			perror("gethostbyaddr");
		else {
			hname = host->h_name;

			host1 = gethostbyname(hname);
			if (host1 != NULL) {
				p = (char *)host1;
				n = 0;
				while (p != NULL) {
					p = host1->h_addr_list[n++];
					if (p == NULL)
						continue;
					if (host1->h_addrtype != AF_INET)
						continue;

					sprintf(ip, "%d.%d.%d.%d",
							p[0], p[1], p[2], p[3]);
					p = NULL;
				}
			}
		}
	}

	fprintf(stderr, "Websocket PING %s (%s) %d bytes of data.\n",
							       hname, ip, size);

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
		unsigned long l;

		gettimeofday(&tv, NULL);

		l = (tv.tv_sec * 1000000) + tv.tv_usec;
		if ((l - oldus) > interval_us) {
			libwebsocket_callback_on_writable(wsi_mirror);
			oldus = l;
		}

		if (!interval_us)
			n = libwebsocket_service(context, 0);
		else
			n = libwebsocket_service(context, 1);
	}

	libwebsocket_client_close(wsi_mirror);
	libwebsocket_context_destroy(context);

	return 0;

usage:
	fprintf(stderr, "Usage: libwebsockets-test-ping "
					     "<server address> [--port=<p>] "
					     "[--ssl] [--interval=<float sec>] "
					     "[--size=<bytes>] "
					     "[--protocol=<protocolname>] "
					     "[--mirror] "
					     "\n");
	return 1;
}
