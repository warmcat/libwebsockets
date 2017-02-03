/*
 * libwebsockets-test-fraggle - random fragmentation test
 *
 * Copyright (C) 2011-2016 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "../lib/libwebsockets.h"

#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"

static int client;
static int terminate;

enum demo_protocols {
	PROTOCOL_FRAGGLE,

	/* always last */
	DEMO_PROTOCOL_COUNT
};

/* fraggle protocol */

enum fraggle_states {
	FRAGSTATE_START_MESSAGE,
	FRAGSTATE_RANDOM_PAYLOAD,
	FRAGSTATE_POST_PAYLOAD_SUM,
};

struct per_session_data__fraggle {
	int packets_left;
	int total_message;
	unsigned long sum;
	enum fraggle_states state;
};

static int
callback_fraggle(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	int n;
	unsigned char buf[LWS_PRE + 8000];
	struct per_session_data__fraggle *psf = user;
	int chunk;
	int write_mode = LWS_WRITE_CONTINUATION;
	unsigned long sum;
	unsigned char *p = (unsigned char *)in;
	unsigned char *bp = &buf[LWS_PRE];
	int ran;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:

		fprintf(stderr, "server sees client connect\n");
		psf->state = FRAGSTATE_START_MESSAGE;
		/* start the ball rolling */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:

		fprintf(stderr, "client connects to server\n");
		psf->state = FRAGSTATE_START_MESSAGE;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:

		switch (psf->state) {

		case FRAGSTATE_START_MESSAGE:

			psf->state = FRAGSTATE_RANDOM_PAYLOAD;
			psf->sum = 0;
			psf->total_message = 0;
			psf->packets_left = 0;

			/* fallthru */

		case FRAGSTATE_RANDOM_PAYLOAD:

			for (n = 0; (unsigned int)n < len; n++)
				psf->sum += p[n];

			psf->total_message += len;
			psf->packets_left++;

			if (lws_is_final_fragment(wsi))
				psf->state = FRAGSTATE_POST_PAYLOAD_SUM;
			break;

		case FRAGSTATE_POST_PAYLOAD_SUM:

			sum = ((unsigned int)p[0]) << 24;
			sum |= p[1] << 16;
			sum |= p[2] << 8;
			sum |= p[3];
			if (sum == psf->sum)
				fprintf(stderr, "EOM received %d correctly "
						"from %d fragments\n",
					psf->total_message, psf->packets_left);
			else
				fprintf(stderr, "**** ERROR at EOM: "
						"length %d, rx sum = 0x%lX, "
						"server says it sent 0x%lX\n",
					     psf->total_message, psf->sum, sum);

			psf->state = FRAGSTATE_START_MESSAGE;
			break;
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:

		switch (psf->state) {

		case FRAGSTATE_START_MESSAGE:
			lws_get_random(lws_get_context(wsi), &ran, sizeof(ran));
			psf->packets_left = (ran & 1023) + 1;
			fprintf(stderr, "Spamming %d random fragments\n",
							     psf->packets_left);
			psf->sum = 0;
			psf->total_message = 0;
			write_mode = LWS_WRITE_BINARY;
			psf->state = FRAGSTATE_RANDOM_PAYLOAD;

			/* fallthru */

		case FRAGSTATE_RANDOM_PAYLOAD:

			/*
			 * note how one chunk can be 8000, but we use the
			 * default rx buffer size of 4096, so we exercise the
			 * code for rx spill because the rx buffer is full
			 */

			lws_get_random(lws_get_context(wsi), &ran, sizeof(ran));
			chunk = (ran & 511) + 1;
			psf->total_message += chunk;

			lws_get_random(lws_get_context(wsi), bp, chunk);
			for (n = 0; n < chunk; n++)
				psf->sum += bp[n];

			psf->packets_left--;
			if (psf->packets_left)
				write_mode |= LWS_WRITE_NO_FIN;
			else
				psf->state = FRAGSTATE_POST_PAYLOAD_SUM;

			n = lws_write(wsi, bp, chunk, write_mode);
			if (n < 0)
				return -1;
			if (n < chunk) {
				lwsl_err("Partial write\n");
				return -1;
			}

			lws_callback_on_writable(wsi);
			break;

		case FRAGSTATE_POST_PAYLOAD_SUM:

			fprintf(stderr, "Spamming session over, "
					"len = %d. sum = 0x%lX\n",
						  psf->total_message, psf->sum);

			bp[0] = psf->sum >> 24;
			bp[1] = (unsigned char)(psf->sum >> 16);
			bp[2] = (unsigned char)(psf->sum >> 8);
			bp[3] = (unsigned char)psf->sum;

			n = lws_write(wsi, (unsigned char *)bp,
							   4, LWS_WRITE_BINARY);
			if (n < 0)
				return -1;
			if (n < 4) {
				lwsl_err("Partial write\n");
				return -1;
			}

			psf->state = FRAGSTATE_START_MESSAGE;

			lws_callback_on_writable(wsi);
			break;
		}
		break;

	case LWS_CALLBACK_CLOSED:

		terminate = 1;
		break;

	/* because we are protocols[0] ... */

	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		if (strcmp(in, "deflate-stream") == 0) {
			fprintf(stderr, "denied deflate-stream extension\n");
			return 1;
		}
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
	{
		"fraggle-protocol",
		callback_fraggle,
		sizeof(struct per_session_data__fraggle),
	},
	{
		NULL, NULL, 0		/* End of list */
	}
};

static const struct lws_extension exts[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate; client_no_context_takeover; client_max_window_bits"
	},
	{
		"deflate-frame",
		lws_extension_callback_pm_deflate,
		"deflate_frame"
	},
	{ NULL, NULL, NULL /* terminator */ }
};

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "interface",  required_argument,	NULL, 'i' },
	{ "client",	no_argument,		NULL, 'c' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	int n = 0;
	int port = 7681;
	int use_ssl = 0;
	struct lws_context *context;
	int opts = 0;
	char interface_name[128] = "", ads_port[300];
	const char *iface = NULL;
	struct lws *wsi;
	const char *address = NULL;
	int server_port = port;
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof info);
	lwsl_notice("libwebsockets test server fraggle - license LGPL2.1+SLE\n");
	lwsl_notice("(C) Copyright 2010-2016 Andy Green <andy@warmcat.com>\n");

	while (n >= 0) {
		n = getopt_long(argc, argv, "ci:hsp:d:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'd':
			lws_set_log_level(atoi(optarg), NULL);
			break;
		case 's':
			use_ssl = 1;
			break;
		case 'p':
			port = atoi(optarg);
			server_port = port;
			break;
		case 'i':
			strncpy(interface_name, optarg, sizeof interface_name);
			interface_name[(sizeof interface_name) - 1] = '\0';
			iface = interface_name;
			break;
		case 'c':
			client = 1;
			fprintf(stderr, " Client mode\n");
			break;
		case 'h':
			fprintf(stderr, "Usage: libwebsockets-test-fraggle "
					"[--port=<p>] [--ssl] "
					"[-d <log bitfield>] "
					"[--client]\n");
			exit(1);
		}
	}

	if (client) {
		server_port = CONTEXT_PORT_NO_LISTEN;
		if (optind >= argc) {
			fprintf(stderr, "Must give address of server\n");
			return 1;
		}
	}

	info.port = server_port;
	info.iface = iface;
	info.protocols = protocols;
	info.extensions = exts;

	if (use_ssl) {
		info.ssl_cert_filepath = LOCAL_RESOURCE_PATH
				"/libwebsockets-test-server.pem";
		info.ssl_private_key_filepath = LOCAL_RESOURCE_PATH
				"/libwebsockets-test-server.key.pem";
	}
	info.gid = -1;
	info.uid = -1;
	info.options = opts;
	info.extensions = exts;

	if (use_ssl)
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (context == NULL) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}

	if (client) {
		struct lws_client_connect_info i;

		address = argv[optind];
		lws_snprintf(ads_port, sizeof(ads_port), "%s:%u",
			 address, port & 65535);
		memset(&i, 0, sizeof(i));
		i.context = context;
		i.address = address;
		i.port = port;
		i.ssl_connection = use_ssl;
		i.path = "/";
		i.host = ads_port;
		i.origin = ads_port;
		i.protocol = protocols[PROTOCOL_FRAGGLE].name;

		lwsl_notice("Connecting to %s:%u\n", address, port);
		wsi = lws_client_connect_via_info(&i);
		if (wsi == NULL) {
			fprintf(stderr, "Client connect to server failed\n");
			goto bail;
		}
	}

	n = 0;
	while (!n && !terminate)
		n = lws_service(context, 50);

	fprintf(stderr, "Terminating...\n");

bail:
	lws_context_destroy(context);

	return 0;
}
