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
lws_sorted_usec_list_t sul;
lws_transport_mux_t *tm;

static struct lws_context_standalone cx = {
	.txp_cpath.ops_onw		= &lws_transport_mux_client_ops,
};

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

int
main(void)
{
	struct lws_ss_handle *h;
	/*
	 * Set up pico for ttyACM USB cnsole and
	 * UART0 at 921600bps
	 */

	stdio_init_all();

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
	 * mux -> transport -> proxy
	 */

	if (lws_ss_create(&cx, 0, &ssi_binance, NULL, &h, NULL, NULL)) {
		printf("failed to create secure stream\n");
		return 1;
	}

	/*
	 * this represents our application event loop.
	 * Your event loop is hopefully better than this
	 * one, but either way this shows how to handle
	 * everything needed for liblws-sspc
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

