/*
 * SS ws-echo example
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Demonstrates http post using the LWS high-level SS apis.
 *
 *  - main.c:              boilerplate to create the lws_context and event loop
 *  - ws-echo-ss.c:       (this file) the secure stream user code
 *  - example-policy.json: the example policy
 */

#include <libwebsockets.h>
#include <signal.h>

extern int test_result;

LWS_SS_USER_TYPEDEF
	lws_sorted_usec_list_t	sul;
	char			msg[64];
	const char		*payload;
	size_t			size;
	size_t			pos;

	int			count;
} ws_echo_t;

static lws_ss_state_return_t
ws_echo_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	     int *flags)
{
	ws_echo_t *g = (ws_echo_t *)userobj;
	lws_ss_state_return_t r = LWSSSSRET_OK;

	if (g->size == g->pos)
		return LWSSSSRET_TX_DONT_SEND;

	if (*len > g->size - g->pos)
		*len = g->size - g->pos;

	if (!g->pos)
		*flags |= LWSSS_FLAG_SOM;

	memcpy(buf, g->payload + g->pos, *len);
	g->pos += *len;

	if (g->pos != g->size)
		/* more to do */
		r = lws_ss_request_tx(lws_ss_from_user(g));
	else
		*flags |= LWSSS_FLAG_EOM;

	lwsl_ss_user(lws_ss_from_user(g), "TX %zu, flags 0x%x, r %d", *len,
					  (unsigned int)*flags, (int)r);

	return r;
}

static lws_ss_state_return_t
ws_echo_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	ws_echo_t *g = (ws_echo_t *)userobj;

	lwsl_ss_user(lws_ss_from_user(g), "RX %zu, flags 0x%x", len,
					  (unsigned int)flags);

	lwsl_hexdump_notice(in, len);

	if ((flags & LWSSS_FLAG_EOM) == LWSSS_FLAG_EOM)
		/* We received the whole response */
		test_result &= ~2;

	return LWSSSSRET_OK;
}

static void
sul_cb(lws_sorted_usec_list_t *sul)
{
	ws_echo_t *g = (ws_echo_t *)lws_container_of(sul, ws_echo_t, sul);

	/* provide a hint about the payload size */
	g->pos = 0;
	g->payload = g->msg;
	g->size = (size_t)lws_snprintf(g->msg, sizeof(g->msg),
					"hello %d", g->count++);

	if (lws_ss_request_tx_len(lws_ss_from_user(g), (unsigned long)g->size))
		lwsl_notice("%s: req failed\n", __func__);

	lws_sul_schedule(lws_ss_cx_from_user(g), 0, &g->sul, sul_cb,
			 LWS_US_PER_SEC / 2);
}

static lws_ss_state_return_t
ws_echo_state(void *userobj, void *h_src, lws_ss_constate_t state,
		lws_ss_tx_ordinal_t ack)
{
	ws_echo_t *g = (ws_echo_t *)userobj;

	switch ((int)state) {
	case LWSSSCS_CREATING:
		/* run for 5s then exit */
		lws_ss_start_timeout(lws_ss_from_user(g), 5000);
		break;

	case LWSSSCS_CONNECTED:
		test_result &= ~1;
		lws_sul_schedule(lws_ss_cx_from_user(g), 0, &g->sul, sul_cb,
				 LWS_US_PER_SEC / 2);
		break;

	case LWSSSCS_TIMEOUT:
		/* for this test, when our 5s are up, we exit the process */
		lws_sul_cancel(&g->sul);
		lws_default_loop_exit(lws_ss_cx_from_user(g));
		break;

	case LWSSSCS_DISCONNECTED: /* for our example, disconnect = done */
		lws_sul_cancel(&g->sul);
		lws_default_loop_exit(lws_ss_cx_from_user(g));
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sx_ws_echo", ws_echo_t)
	.tx		= ws_echo_tx,
	.rx		= ws_echo_rx,
	.state		= ws_echo_state,
};
