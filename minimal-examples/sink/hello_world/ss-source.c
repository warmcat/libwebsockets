/*
 * lws-minimal-ss-sink-hello_world
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Simple SS source... it's just a normal SS user implementation, it does not
 * have any dependency on the policy routing it to a sink instead of, eg,
 * wss to a cloud endpoint.
 */

#include <libwebsockets.h>

extern int test_result;

LWS_SS_USER_TYPEDEF
	char			payload[200];
	size_t			size;
	size_t			pos;
} myss_src_t;

static lws_ss_state_return_t
myss_src_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	    int *flags)
{
	myss_src_t *g = (myss_src_t *)userobj;
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
myss_src_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	myss_src_t *g = (myss_src_t *)userobj;

	lwsl_ss_notice(lws_ss_from_user(g), "len %u, flags 0x%x",
					    (unsigned int)len,
					    (unsigned int)flags);
	lwsl_hexdump_notice(buf, len);

	/*
	 * In this example, we take getting the sink's ack of our message
	 * as meaning "success".
	 */

	test_result = 0;
	lws_default_loop_exit(lws_ss_cx_from_user(g));

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
myss_src_state(void *userobj, void *sh, lws_ss_constate_t state,
	       lws_ss_tx_ordinal_t ack)
{
	myss_src_t *g = (myss_src_t *)userobj;

	switch ((int)state) {
	case LWSSSCS_CREATING:
		lwsl_notice("%s: CREATING\n", __func__);
		return lws_ss_request_tx(lws_ss_from_user(g));

	case LWSSSCS_CONNECTED:
		g->size	= (size_t)lws_snprintf(g->payload, sizeof(g->payload),
					       "From Source: Hello World: %lu",
					       (unsigned long)lws_now_usecs());
		g->pos = 0;

		return lws_ss_request_tx_len(lws_ss_from_user(g),
					     (unsigned long)g->size);
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sink_hello_world", myss_src_t)
	.tx				= myss_src_tx,
	.rx				= myss_src_rx,
	.state				= myss_src_state,
};
