/*
 * lws-minimal-ss-server-hello_world
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Simple SS server that just serves one thing.
 */

#include <libwebsockets.h>

LWS_SS_USER_TYPEDEF
	char			payload[200];
	size_t			size;
	size_t			pos;
} myss_srv_t;

static lws_ss_state_return_t
myss_srv_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	    int *flags)
{
	myss_srv_t *g = (myss_srv_t *)userobj;
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
myss_srv_state(void *userobj, void *sh, lws_ss_constate_t state,
	       lws_ss_tx_ordinal_t ack)
{
	myss_srv_t *g = (myss_srv_t *)userobj;

	switch ((int)state) {
	case LWSSSCS_CREATING:
		return lws_ss_request_tx(lws_ss_from_user(g));

	case LWSSSCS_SERVER_TXN:
		/*
		 * A transaction is starting on an accepted connection.  Say
		 * that we're OK with the transaction, prepare the user
		 * object with the response, and request tx to start sending it.
		 */
		lws_ss_server_ack(lws_ss_from_user(g), 0);

		if (lws_ss_set_metadata(lws_ss_from_user(g), "mime",
					"text/html", 9))
			return LWSSSSRET_DISCONNECT_ME;

		g->size	= (size_t)lws_snprintf(g->payload, sizeof(g->payload),
					       "Hello World: %lu",
					       (unsigned long)lws_now_usecs());
		g->pos = 0;

		return lws_ss_request_tx_len(lws_ss_from_user(g),
					     (unsigned long)g->size);
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("myserver", myss_srv_t)
	.tx				= myss_srv_tx,
	.state				= myss_srv_state,
};
