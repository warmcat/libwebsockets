/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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
#include "../lib/libwebsockets.h"
#include <string.h>
#include <stdlib.h>

/* lws-mirror_protocol */

#define MAX_MESSAGE_QUEUE 512

struct per_session_data__lws_mirror {
	struct lws *wsi;
	int ringbuffer_tail;
};

struct a_message {
	void *payload;
	size_t len;
};

struct per_vhost_data__lws_mirror {
	struct a_message ringbuffer[MAX_MESSAGE_QUEUE];
	int ringbuffer_head;
};

static int
callback_lws_mirror(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_mirror *pss =
			(struct per_session_data__lws_mirror *)user;
	struct per_vhost_data__lws_mirror *v =
			(struct per_vhost_data__lws_mirror *)
			lws_protocol_vh_priv_get(lws_vhost_get(wsi),
					lws_protocol_get(wsi));
	int n, m;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);
		pss->ringbuffer_tail = v->ringbuffer_head;
		pss->wsi = wsi;
		break;

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		lws_protocol_vh_priv_zalloc(lws_vhost_get(wsi),
				lws_protocol_get(wsi),
				sizeof(struct per_vhost_data__lws_mirror));
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY: /* per vhost */
		if (!v)
			break;
		lwsl_info("%s: mirror protocol cleaning up %p\n", __func__, v);
		for (n = 0; n < ARRAY_SIZE(v->ringbuffer); n++)
			if (v->ringbuffer[n].payload) {
				free(v->ringbuffer[n].payload);
				v->ringbuffer[n].payload = NULL;
			}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		while (pss->ringbuffer_tail != v->ringbuffer_head) {
			m = v->ringbuffer[pss->ringbuffer_tail].len;
			n = lws_write(wsi, (unsigned char *)
				   v->ringbuffer[pss->ringbuffer_tail].payload +
				   LWS_PRE, m, LWS_WRITE_TEXT);
			if (n < 0) {
				lwsl_err("ERROR %d writing to mirror socket\n", n);
				return -1;
			}
			if (n < m)
				lwsl_err("mirror partial write %d vs %d\n", n, m);

			if (pss->ringbuffer_tail == (MAX_MESSAGE_QUEUE - 1))
				pss->ringbuffer_tail = 0;
			else
				pss->ringbuffer_tail++;

			if (((v->ringbuffer_head - pss->ringbuffer_tail) &
			    (MAX_MESSAGE_QUEUE - 1)) == (MAX_MESSAGE_QUEUE - 15))
				lws_rx_flow_allow_all_protocol(lws_get_context(wsi),
					       lws_get_protocol(wsi));

			if (lws_send_pipe_choked(wsi)) {
				lws_callback_on_writable(wsi);
				break;
			}
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (((v->ringbuffer_head - pss->ringbuffer_tail) &
		    (MAX_MESSAGE_QUEUE - 1)) == (MAX_MESSAGE_QUEUE - 1)) {
			lwsl_err("dropping!\n");
			goto choke;
		}

		if (v->ringbuffer[v->ringbuffer_head].payload)
			free(v->ringbuffer[v->ringbuffer_head].payload);

		v->ringbuffer[v->ringbuffer_head].payload = malloc(LWS_PRE + len);
		v->ringbuffer[v->ringbuffer_head].len = len;
		memcpy((char *)v->ringbuffer[v->ringbuffer_head].payload +
		       LWS_PRE, in, len);
		if (v->ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
			v->ringbuffer_head = 0;
		else
			v->ringbuffer_head++;

		if (((v->ringbuffer_head - pss->ringbuffer_tail) &
		    (MAX_MESSAGE_QUEUE - 1)) != (MAX_MESSAGE_QUEUE - 2))
			goto done;

choke:
		lwsl_debug("LWS_CALLBACK_RECEIVE: throttling %p\n", wsi);
		lws_rx_flow_control(wsi, 0);

done:
		lws_callback_on_writable_all_protocol(lws_get_context(wsi),
						      lws_get_protocol(wsi));
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws-mirror-protocol",
		callback_lws_mirror,
		sizeof(struct per_session_data__lws_mirror),
		128, /* rx buf size must be >= permessage-deflate rx size */
	},
};

LWS_VISIBLE int
init_protocol_lws_mirror(struct lws_context *context,
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

LWS_VISIBLE int
destroy_protocol_lws_mirror(struct lws_context *context)
{
	return 0;
}

