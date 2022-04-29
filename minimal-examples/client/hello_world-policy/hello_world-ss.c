/*
 * hello_world example
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Demonstrates the simplest example using the LWS high-level SS apis.
 *
 *  - main.c:              boilerplate to create the lws_context and event loop
 *  - hello_world-ss.c:    (this file) the secure stream user code
 *  - example-policy.json: the example policy
 */

#include <libwebsockets.h>
#include <signal.h>

extern int test_result;

LWS_SS_USER_TYPEDEF
	/* Your per-stream instantiation members go here */
} hello_world_t;

static lws_ss_state_return_t
hello_world_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	hello_world_t *g = (hello_world_t *)userobj;
	struct lws_ss_handle *h = lws_ss_from_user(g);

	lwsl_ss_user(h, "RX %zu, flags 0x%x", len, (unsigned int)flags);

	if (len) { /* log the first 16 and last 16 bytes of the chunk */
		lwsl_hexdump_ss_info(h, in, len >= 16 ? 16 : len);
		if (len >= 16)
			lwsl_hexdump_ss_info(h, in + len - 16, 16);
	}

	if ((flags & LWSSS_FLAG_EOM) == LWSSS_FLAG_EOM) /* had whole message */
		test_result &= ~2;

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
hello_world_state(void *userobj, void *h_src, lws_ss_constate_t state,
		  lws_ss_tx_ordinal_t ack)
{
	hello_world_t *g = (hello_world_t *)userobj;
	const char *ct;
	size_t ctl;

	switch ((int)state) {
	case LWSSSCS_CREATING: /* start the transaction as soon as we exist */
		return lws_ss_request_tx(lws_ss_from_user(g));

	case LWSSSCS_QOS_ACK_REMOTE: /* server liked our request */

		if (!lws_ss_get_metadata(g->ss, "ctype", (const void **)&ct, &ctl))
			lwsl_ss_user(g->ss, "get_metadata ctype '%.*s'", (int)ctl, ct);
		else
			lwsl_ss_user(g->ss, "get_metadata ctype missing");

		test_result &= ~1;
		break;

	case LWSSSCS_DISCONNECTED: /* for our example, disconnect = done */
		lws_default_loop_exit(lws_ss_cx_from_user(g));
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sx-hello_world", hello_world_t)
	.rx		= hello_world_rx,
	.state		= hello_world_state,
};
