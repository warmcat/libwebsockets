/*
 * libwebsockets-test-server - libwebsockets plugin for quic server
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>

#define TOTAL_DATA (128 * 1024)

struct per_session_data__quic_server {
	size_t server_sent;
	size_t server_rx;
	uint32_t server_hash;
	int server_done;
};

static uint32_t
simple_hash(uint32_t hash, const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		hash = (hash << 5) + hash + data[i]; /* hash * 33 + c */
	return hash;
}

static int
callback_quic_server(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct per_session_data__quic_server *pss = (struct per_session_data__quic_server *)user;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
	{
		struct lws_vhost *vh = lws_get_vhost(wsi);
		const struct lws_protocol_vhost_options *pvo;

		int port = 7681;

		pvo = (const struct lws_protocol_vhost_options *)in;
		if (!pvo)
			return 0;

		pvo = lws_pvo_search(pvo, "status");
		if (!pvo || strcmp(pvo->value, "on"))
			return 0;

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in,
			"port");
		if (pvo)
			port = atoi(pvo->value);

		if (!lws_create_adopt_udp(vh, "127.0.0.1", port, LWS_CAUDP_BIND,
					"lws-quic-server", NULL, NULL, NULL,
					NULL, "quic_listen")) {
			lwsl_vhost_err(vh, "Failed to bind QUIC UDP listener on port %d", port);
			return 1;
		}

		lwsl_vhost_notice(vh, "QUIC server protocol initialized on UDP port %d", port);
		break;
	}

	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		lwsl_notice("Server received new QUIC client connection!\n");
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		pss->server_hash = 5381;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
	{
		uint8_t buf[LWS_PRE + 1024];
		size_t to_send;
		int n;

		if (pss->server_sent >= TOTAL_DATA)
			break;

		to_send = TOTAL_DATA - pss->server_sent;
		if (to_send > 1024)
			to_send = 1024;
		memset(&buf[LWS_PRE], (pss->server_sent & 0xff), to_send);
		n = lws_write(wsi, &buf[LWS_PRE], to_send, LWS_WRITE_BINARY);
		if (n > 0) {
			pss->server_sent += (size_t)n;
			if (pss->server_sent < TOTAL_DATA)
				lws_callback_on_writable(wsi);
		}
		break;
	}

	case LWS_CALLBACK_QT_SERVER_RECEIVE:
	{
		pss->server_rx += len;
		pss->server_hash = simple_hash(pss->server_hash, in, len);
		if (pss->server_rx >= TOTAL_DATA && !pss->server_done) {
			lwsl_notice("Server received all %lu bytes, hash %u\n",
				    (unsigned long)pss->server_rx, pss->server_hash);
			pss->server_done = 1;
		}
		break;
	}

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name                   = "lws-quic-server",
		.callback               = callback_quic_server,
		.per_session_data_size  = sizeof(struct per_session_data__quic_server),
		.rx_buffer_size         = 2048,
	}
};

LWS_VISIBLE const lws_plugin_protocol_t lws_quic_server = {
	.hdr = {
		.name = "lws quic server",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
};
