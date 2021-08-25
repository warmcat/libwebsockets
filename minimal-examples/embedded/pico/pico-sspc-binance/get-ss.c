/*
 * pico-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The SS user struct for the "GET" stream... it reads from
 * https://libwebsockets.org/index.html every 5s
 */

#include "private.h"

typedef struct {
	struct lws_ss_handle 	*ss;
	void			*opaque_data;

	lws_sorted_usec_list_t	sul5;
} get_t;

static void
sul_start_get(lws_sorted_usec_list_t *sul)
{
	get_t *g = lws_container_of(sul, get_t, sul5);

	lwsl_ss_notice(g->ss, "conn");
	lws_ss_request_tx(g->ss);
	lws_sul_schedule(lws_ss_get_context(g->ss), 0, sul, sul_start_get,
			 5 * LWS_US_PER_SEC);
}

static lws_ss_state_return_t
get_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	get_t *g = (get_t *)userobj;

	lwsl_ss_notice(g->ss, "RX %u, flags 0x%x",
		       (unsigned int)len, (unsigned int)flags);

	if (len) {
		lwsl_hexdump_notice(in, 16);
		if (len >= 16)
			lwsl_hexdump_notice(in + len - 16, 16);
	}

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
get_state(void *userobj, void *h_src, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	get_t *g = (get_t *)userobj;

	lwsl_ss_notice(g->ss, "%s (%d), ord 0x%x",
		       lws_ss_state_name((int)state), state, (unsigned int)ack);

	switch (state) {
	case LWSSSCS_CREATING:
		/*
		 * ... also let's start a sul that creates a second stream to
		 * GET from libwebsockets.org every 5s, showing we are running
		 * multiple SS on the transport successfully.
		 */

		lws_sul_schedule(lws_ss_get_context(g->ss), 0, &g->sul5,
				 sul_start_get, 5 * LWS_US_PER_SEC);
		break;
	case LWSSSCS_DESTROYING:
		lws_sul_cancel(&g->sul5);
		break;
	}

	return LWSSSSRET_OK;
}

const lws_ss_info_t ssi_get = {
	.handle_offset		  = offsetof(get_t, ss),
	.opaque_user_data_offset  = offsetof(get_t, opaque_data),
	.rx			  = get_rx,
	.state			  = get_state,
	.user_alloc		  = sizeof(get_t),
	.streamtype		  = "mintest-lws", /* bind to this policy */
};
