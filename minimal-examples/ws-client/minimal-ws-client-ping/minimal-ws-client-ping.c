/*
 * lws-minimal-ws-client-ping
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a ws client that sends pings from time to time and
 * shows when it receives the PONG
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

static struct lws_context *context;
static struct lws *client_wsi;
static int interrupted, zero_length_ping, port = 443, quick_pings, no_user_ping,
	   ssl_connection = LCCSCF_USE_SSL;
static const char *server_address = "libwebsockets.org", *pro = "lws-mirror-protocol";

struct pss {
	int send_a_ping;
};

static const lws_retry_bo_t retry = {
	.secs_since_valid_ping = 3,
	.secs_since_valid_hangup = 10,
};

static int
connect_client(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));

	i.context = context;
	i.port = port;
	i.address = server_address;
	i.path = "/";
	i.host = i.address;
	i.origin = i.address;
	i.ssl_connection = ssl_connection;
	i.protocol = pro;
	i.local_protocol_name = "lws-ping-test";
	i.pwsi = &client_wsi;
	if (quick_pings)
		i.retry_and_idle_policy = &retry;

	return !lws_client_connect_via_info(&i);
}

static int
callback_minimal_broker(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	int n;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		goto try;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		client_wsi = NULL;
		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
				lws_get_protocol(wsi), LWS_CALLBACK_USER, 1);
		break;

	/* --- client callbacks --- */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("%s: established\n", __func__);
		lws_set_timer_usecs(wsi, 5 * LWS_USEC_PER_SEC);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (pss->send_a_ping) {
			uint8_t ping[LWS_PRE + 125];
			int m;

			pss->send_a_ping = 0;
			n = 0;
			if (!zero_length_ping)
				n = lws_snprintf((char *)ping + LWS_PRE, 125,
					"ping body!");

			lwsl_user("Sending PING %d...\n", n);

			m = lws_write(wsi, ping + LWS_PRE, n, LWS_WRITE_PING);
			if (m < n) {
				lwsl_err("sending ping failed: %d\n", m);

				return -1;
			}
			
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_WS_CLIENT_DROP_PROTOCOL:
		client_wsi = NULL;
		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
					       lws_get_protocol(wsi),
					       LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE_PONG\n");
		lwsl_hexdump_notice(in, len);
		break;

	case LWS_CALLBACK_TIMER:
		if (no_user_ping)
			break;
		/* we want to send a ws PING every few seconds */
		pss->send_a_ping = 1;
		lws_callback_on_writable(wsi);
		lws_set_timer_usecs(wsi, 10 * LWS_USEC_PER_SEC);
		break;

	/* rate-limited client connect retries */

	case LWS_CALLBACK_USER:
		lwsl_notice("%s: LWS_CALLBACK_USER\n", __func__);
try:
		if (connect_client())
			lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
						       lws_get_protocol(wsi),
						       LWS_CALLBACK_USER, 1);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"lws-ping-test",
		callback_minimal_broker,
		sizeof(struct pss),
		0,
	},
	{ NULL, NULL, 0, 0 }
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal ws client PING\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;
#if defined(LWS_WITH_MBEDTLS)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	info.client_ssl_ca_filepath = "./libwebsockets.org.cer";
#endif

	if (lws_cmdline_option(argc, argv, "-z"))
		zero_length_ping = 1;

	if (lws_cmdline_option(argc, argv, "-n"))
		no_user_ping = 1;

	if ((p = lws_cmdline_option(argc, argv, "--protocol")))
		pro = p;

	if ((p = lws_cmdline_option(argc, argv, "--server"))) {
		server_address = p;
		pro = "lws-minimal";
		ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
	}

	if ((p = lws_cmdline_option(argc, argv, "--port")))
		port = atoi(p);

	/* the default validity check is 5m / 5m10s... -v = 5s / 10s */

	if (lws_cmdline_option(argc, argv, "-v"))
		quick_pings = 1;

	/*
	 * since we know this lws context is only ever going to be used with
	 * one client wsis / fds / sockets at a time, let lws know it doesn't
	 * have to use the default allocations for fd tables up to ulimit -n.
	 * It will just allocate for 1 internal and 1 (+ 1 http2 nwsi) that we
	 * will use.
	 */
	info.fd_limit_per_thread = 1 + 1 + 1;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);
	lwsl_user("Completed\n");

	return 0;
}
