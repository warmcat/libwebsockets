/*
 * ws protocol handler plugin for "lws-minimal-client-echo"
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The protocol shows how to send and receive bulk messages over a ws connection
 * that optionally may have the permessage-deflate extension negotiated on it.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

#define RING_DEPTH 1024

/* one of these created for each message */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
	char binary;
	char first;
	char final;
};

struct per_session_data__minimal_client_echo {
	struct lws_ring *ring;
	uint32_t tail;
	uint8_t completed:1;
};

struct vhd_minimal_client_echo {
	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws *client_wsi;

	int *interrupted;
	int *options;
	const char **url;
	const char **ads;
	int *port;
};

static int
connect_client(struct vhd_minimal_client_echo *vhd)
{
	struct lws_client_connect_info i;
	char host[128];

	lws_snprintf(host, sizeof(host), "%s:%u", *vhd->ads, *vhd->port);

	memset(&i, 0, sizeof(i));

	i.context = vhd->context;
	i.port = *vhd->port;
	i.address = *vhd->ads;
	i.path = *vhd->url;
	i.host = host;
	i.origin = host;
	i.ssl_connection = 0;
	i.vhost = vhd->vhost;
	//i.protocol = ;
	i.pwsi = &vhd->client_wsi;

	lwsl_user("connecting to %s:%d/%s\n", i.address, i.port, i.path);

	return !lws_client_connect_via_info(&i);
}

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

static void
schedule_callback(struct lws *wsi, int reason, int secs)
{
	lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
		lws_get_protocol(wsi), reason, secs);
}

static int
callback_minimal_client_echo(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct per_session_data__minimal_client_echo *pss =
			(struct per_session_data__minimal_client_echo *)user;
	struct vhd_minimal_client_echo *vhd = (struct vhd_minimal_client_echo *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
				lws_get_protocol(wsi));
	const struct msg *pmsg;
	struct msg amsg;
	int n, m, flags;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct vhd_minimal_client_echo));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		/* get the pointer to "interrupted" we were passed in pvo */
		vhd->interrupted = (int *)lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in,
			"interrupted")->value;
		vhd->port = (int *)lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in,
			"port")->value;
		vhd->options = (int *)lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in,
			"options")->value;
		vhd->ads = (const char **)lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in,
			"ads")->value;
		vhd->url = (const char **)lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in,
			"url")->value;

		if (connect_client(vhd))
			schedule_callback(wsi, LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("LWS_CALLBACK_CLIENT_ESTABLISHED\n");
		pss->ring = lws_ring_create(sizeof(struct msg), RING_DEPTH,
					    __minimal_destroy_message);
		if (!pss->ring)
			return 1;
		pss->tail = 0;
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:

		lwsl_user("LWS_CALLBACK_CLIENT_WRITEABLE\n");
		do {
			pmsg = lws_ring_get_element(pss->ring, &pss->tail);
			if (!pmsg) {
				lwsl_user(" (nothing in ring)\n");
				break;
			}

			flags = lws_write_ws_flags(
				    pmsg->binary ? LWS_WRITE_BINARY : LWS_WRITE_TEXT,
				    pmsg->first, pmsg->final);

			/* notice we allowed for LWS_PRE in the payload already */
			m = lws_write(wsi, pmsg->payload + LWS_PRE, pmsg->len, flags);
			if (m < (int)pmsg->len) {
				lwsl_err("ERROR %d writing to ws socket\n", m);
				return -1;
			}

			lwsl_user(" wrote %d: flags: 0x%x first: %d final %d\n",
					m, flags, pmsg->first, pmsg->final);

			lws_ring_consume_single_tail(pss->ring, &pss->tail, 1);

		} while (lws_ring_get_element(pss->ring, &pss->tail) &&
			 !lws_send_pipe_choked(wsi));

		/* more to do for us? */
		if (lws_ring_get_element(pss->ring, &pss->tail))
			/* come back as soon as we can write more */
			lws_callback_on_writable(wsi);

		if ((int)lws_ring_get_count_free_elements(pss->ring) > RING_DEPTH - 5)
			lws_rx_flow_control(wsi, 1);

		if ((*vhd->options & 1) && pmsg && pmsg->final)
			pss->completed = 1;

		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:

		lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE: %4d (rpp %5d, first %d, last %d, bin %d)\n",
			(int)len, (int)lws_remaining_packet_payload(wsi),
			lws_is_first_fragment(wsi),
			lws_is_final_fragment(wsi),
			lws_frame_is_binary(wsi));

		// lwsl_hexdump_notice(in, len);

		amsg.first = lws_is_first_fragment(wsi);
		amsg.final = lws_is_final_fragment(wsi);
		amsg.binary = lws_frame_is_binary(wsi);
		n = (int)lws_ring_get_count_free_elements(pss->ring);
		if (!n) {
			lwsl_user("dropping!\n");
			break;
		}

		amsg.len = len;
		/* notice we over-allocate by LWS_PRE */
		amsg.payload = malloc(LWS_PRE + len);
		if (!amsg.payload) {
			lwsl_user("OOM: dropping\n");
			break;
		}

		memcpy((char *)amsg.payload + LWS_PRE, in, len);
		if (!lws_ring_insert(pss->ring, &amsg, 1)) {
			__minimal_destroy_message(&amsg);
			lwsl_user("dropping!\n");
			break;
		}
		lws_callback_on_writable(wsi);

		if (n < 3)
			lws_rx_flow_control(wsi, 0);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		vhd->client_wsi = NULL;
		schedule_callback(wsi, LWS_CALLBACK_USER, 1);
		if (*vhd->options & 1) {
			if (!*vhd->interrupted)
				*vhd->interrupted = 1;
			lws_cancel_service(lws_get_context(wsi));
		}
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		lwsl_user("LWS_CALLBACK_CLIENT_CLOSED\n");
		lws_ring_destroy(pss->ring);
		vhd->client_wsi = NULL;
		// schedule_callback(wsi, LWS_CALLBACK_USER, 1);
		//if (*vhd->options & 1) {
			if (!*vhd->interrupted)
				*vhd->interrupted = 1 + pss->completed;
			lws_cancel_service(lws_get_context(wsi));
	//	}
		break;

	/* rate-limited client connect retries */

	case LWS_CALLBACK_USER:
		lwsl_notice("%s: LWS_CALLBACK_USER\n", __func__);
		if (connect_client(vhd))
			schedule_callback(wsi, LWS_CALLBACK_USER, 1);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_MINIMAL_CLIENT_ECHO \
	{ \
		"lws-minimal-client-echo", \
		callback_minimal_client_echo, \
		sizeof(struct per_session_data__minimal_client_echo), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

/* boilerplate needed if we are built as a dynamic plugin */

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_MINIMAL_client_echo
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_minimal_client_echo(struct lws_context *context,
			       struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_minimal_client_echo(struct lws_context *context)
{
	return 0;
}
#endif
