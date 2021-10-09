/*
 * lws-minimal-ss-sink-hello_world
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Simple SS sink
 */

#include <libwebsockets.h>

LWS_SS_USER_TYPEDEF
	char			payload[200];
	size_t			size;
	size_t			pos;
} myss_sink_t;

static lws_ss_state_return_t
myss_sink_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	    int *flags)
{
	myss_sink_t *g = (myss_sink_t *)userobj;
	lws_ss_state_return_t r = LWSSSSRET_OK;

	if (g->size == g->pos)
		return LWSSSSRET_TX_DONT_SEND;

	if (*len > g->size - g->pos)
		*len = g->size - g->pos;

	if (!g->pos)
		*flags |= LWSSS_FLAG_SOM;

	memcpy(buf, g->payload + g->pos, *len);
	g->pos += *len;

	if (g->pos != g->size) /* more to do */
		r = lws_ss_request_tx(lws_ss_from_user(g));
	else
		*flags |= LWSSS_FLAG_EOM;

	lwsl_ss_user(lws_ss_from_user(g), "TX %zu, flags 0x%x, r %d", *len,
					  (unsigned int)*flags, (int)r);

	return r;
}

static lws_ss_state_return_t
myss_sink_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	myss_sink_t *g = (myss_sink_t *)userobj;

	lwsl_ss_notice(lws_ss_from_user(g), "len %u, flags 0x%x",
					    (unsigned int)len,
					    (unsigned int)flags);
	lwsl_hexdump_notice(buf, len);

	if (flags & LWSSS_FLAG_EOM) {
		/* we're going to respond to it */

		g->size	= (size_t)lws_snprintf(g->payload, sizeof(g->payload),
					       "From Sink: Hello World: %lu",
					       (unsigned long)lws_now_usecs());
		g->pos = 0;

		return lws_ss_request_tx_len(lws_ss_from_user(g),
					     (unsigned long)g->size);
	}

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
myss_sink_state(void *userobj, void *sh, lws_ss_constate_t state,
	       lws_ss_tx_ordinal_t ack)
{
	myss_sink_t *g = (myss_sink_t *)userobj;

	switch ((int)state) {
	case LWSSSCS_CREATING:
		return lws_ss_request_tx(lws_ss_from_user(g));

	case LWSSSCS_SERVER_TXN:
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sink_hello_world", myss_sink_t)
	.tx				= myss_sink_tx,
	.rx				= myss_sink_rx,
	.state				= myss_sink_state,
	.flags				= LWSSSINFLAGS_REGISTER_SINK
};
