/*
 * lws-minimal-secure-streams-custom-client-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 */

#include "private.h"

lws_dll2_owner_t scheduler;
lws_transport_mux_t *tm;

static struct lws_context_standalone cx = {
	.txp_cpath.ops_onw		= &lws_transport_mux_client_ops,
};

/*
 * Describes how the transport goes through the transport_mux
 */

lws_transport_info_t info_serial = {
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.flags				= 0,
}, info_mux = { /* onward transport for mux is serial */
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.txp_cpath = {
		.ops_onw		= &lws_sss_ops_client_serial,
		.ops_in			= &lws_transport_mux_client_ops,
	},
	.onward_txp_info		= &info_serial,
	.flags				= 0,
};


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
	lws_sul_schedule(&cx, 0, sul, sul_start_get, 5 * LWS_US_PER_SEC);
}

static lws_ss_state_return_t
get_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	get_t *g = (get_t *)userobj;

	lwsl_ss_notice(g->ss, "RX %u, flags 0x%x",
		       (unsigned int)len, (unsigned int)flags);

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
		 * ... also let's start a sul that creates a second stream to GET from
		 * libwebsockets.org every 5s, showing we are running multiple SS on the
		 * transport successfully.
		 */

		lws_sul_schedule(&cx, 0, &g->sul5, sul_start_get, 5 * LWS_US_PER_SEC);
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
	.streamtype		  = "mintest-lws", /* bind to corresponding policy */
};

int
main(void)
{
	/*
	 * Set up pico for ttyACM USB cnsole and UART0 at 2Mbps
	 */

	stdio_init_all();
#if 0
	{ volatile int n = 0; while (n < 10000000) n++; }
#endif

	lwsl_user("\npico-sspc-binance demo\n");

	open_serial_port(uart0);

	/* create the mux object itself... only one of these */

	tm = lws_transport_mux_create(&cx, &info_mux, NULL);
	if (!tm) {
		lwsl_err("%s: unable to create client mux\n", __func__);
		return 1;
	}
	tm->info.txp_cpath.priv_in = tm;
	cx.txp_cpath.mux = tm;

	/*
	 * Now that's done, create the SS and it will try to connect over the
	 * mux -> transport -> proxy -> binance wss
	 */

	if (lws_ss_create(&cx, 0, &ssi_binance, NULL, NULL, NULL, NULL)) {
		printf("failed to create binance secure stream\n");
		return 1;
	}

	if (lws_ss_create(&cx, 0, &ssi_get, NULL, NULL, NULL, NULL)) {
		printf("failed to create get secure stream\n");
		return 1;
	}

	/*
	 * this represents our application event loop.
	 * Your event loop is hopefully better than this
	 * one, but either way this shows how to handle
	 * everything needed for LWS_ONLY_SSPC
	 */

	while (true) {

		serial_handle_events(tm);

		/* check the scheduler */

		while (scheduler.head) {
			lws_sorted_usec_list_t *sul = lws_container_of(
					scheduler.head, lws_sorted_usec_list_t, list);

			if (sul->us > lws_now_usecs())
				break;
			lws_dll2_remove(&sul->list);

			sul->cb(sul);
		}
	}

	return 0;
}

