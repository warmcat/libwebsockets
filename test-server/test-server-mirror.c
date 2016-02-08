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
#include "test-server.h"

/* lws-mirror_protocol */

#define MAX_MESSAGE_QUEUE 512

struct a_message {
	void *payload;
	size_t len;
};

static struct a_message ringbuffer[MAX_MESSAGE_QUEUE];
static int ringbuffer_head;

int
callback_lws_mirror(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_mirror *pss =
			(struct per_session_data__lws_mirror *)user;
	int n, m;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);
		pss->ringbuffer_tail = ringbuffer_head;
		pss->wsi = wsi;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lwsl_notice("%s: mirror protocol cleaning up\n", __func__);
		for (n = 0; n < sizeof ringbuffer / sizeof ringbuffer[0]; n++)
			if (ringbuffer[n].payload)
				free(ringbuffer[n].payload);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (close_testing)
			break;
		while (pss->ringbuffer_tail != ringbuffer_head) {
			m = ringbuffer[pss->ringbuffer_tail].len;
			n = lws_write(wsi, (unsigned char *)
				   ringbuffer[pss->ringbuffer_tail].payload +
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

			if (((ringbuffer_head - pss->ringbuffer_tail) &
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
		if (((ringbuffer_head - pss->ringbuffer_tail) &
		    (MAX_MESSAGE_QUEUE - 1)) == (MAX_MESSAGE_QUEUE - 1)) {
			lwsl_err("dropping!\n");
			goto choke;
		}

		if (ringbuffer[ringbuffer_head].payload)
			free(ringbuffer[ringbuffer_head].payload);

		ringbuffer[ringbuffer_head].payload = malloc(LWS_PRE + len);
		ringbuffer[ringbuffer_head].len = len;
		memcpy((char *)ringbuffer[ringbuffer_head].payload +
		       LWS_PRE, in, len);
		if (ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
			ringbuffer_head = 0;
		else
			ringbuffer_head++;

		if (((ringbuffer_head - pss->ringbuffer_tail) &
		    (MAX_MESSAGE_QUEUE - 1)) != (MAX_MESSAGE_QUEUE - 2))
			goto done;

choke:
		lwsl_debug("LWS_CALLBACK_RECEIVE: throttling %p\n", wsi);
		lws_rx_flow_control(wsi, 0);

done:
		lws_callback_on_writable_all_protocol(lws_get_context(wsi),
						      lws_get_protocol(wsi));
		break;

	/*
	 * this just demonstrates how to use the protocol filter. If you won't
	 * study and reject connections based on header content, you don't need
	 * to handle this callback
	 */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		dump_handshake_info(wsi);
		/* you could return non-zero here and kill the connection */
		break;

	default:
		break;
	}

	return 0;
}
