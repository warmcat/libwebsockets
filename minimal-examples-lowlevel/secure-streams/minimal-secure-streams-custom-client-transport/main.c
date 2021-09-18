/*
 * lws-minimal-secure-streams-custom-client-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *                         Kutoga <kutoga@user.github.invalid>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This is a version of minimal-secure-streams-binance that uses a custom
 * SS Serialization transport.
 *
 * Lws provides a wsi-based SS serialization transport, so you can connect to
 * SS proxy over tcp or Unix Domain Sockets.  This example shows how to create
 * SS proxy clients with no dependency on libwebsockets library.
 *
 * libwebsockets header is used, but the application does not have an
 * lws_context and does not link against libwebsockets, instead using a much
 * smaller SSPC-only library liblws-sspc (built during lws build).
 */

#include "private.h"

int interrupted;
int transport_fd;

/*
 * Apps that bind to liblws-sspc have a fake lws_context with a couple of
 * members in it, there is no lws_create_context, it's so trivial you can
 * make your own like below.
 *
 * The is to retain the same SS apis that expect an lws_context, and also the
 * place where we bind to the transport to be used
 */

static struct lws_context_standalone cx = {
	.txp_cpath.ops_onw		= &lws_transport_mux_client_ops,
};



static void
sigint_handler(int sig)
{
	interrupted = 1;
}

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
main(int argc, const char **argv)
{
	struct lws_ss_handle *h = NULL;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal Secure Streams binance client / custom SS proxy transport\n");

	/* open the transport itself... only one of these */

	transport_fd = open_transport_file(&a_cpcx, "/dev/ttyUSB1", NULL);
	if (transport_fd < 0) {
		lwsl_err("%s: failed to open custom transport tty\n", __func__);
		return 1;
	}

	/* create the mux object itself... only one of these */

	a_cpcx.tm = lws_transport_mux_create(&cx, &info_mux, NULL);
	if (!a_cpcx.tm) {
		lwsl_err("%s: unable to create client mux\n", __func__);
		return 1;
	}
	a_cpcx.tm->info.txp_cpath.priv_in = a_cpcx.tm;
	cx.txp_cpath.mux = a_cpcx.tm;

	/*
	 * Now that's done, create the SS and it will try to connect over the
	 * mux -> transport -> proxy
	 */

	if (lws_ss_create(&cx, 0, &ssi_binance, NULL, &h, NULL, NULL)) {
		printf("failed to create secure stream\n");
		interrupted = 1;
	}


	custom_poll_run(&a_cpcx);

	if (h)
		lws_ss_destroy(&h);

	lws_transport_mux_destroy(&a_cpcx.tm);

	printf("Completed\n");

	close(transport_fd);

	return 0;
}
