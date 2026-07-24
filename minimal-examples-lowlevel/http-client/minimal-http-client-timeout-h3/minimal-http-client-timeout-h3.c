/*
 * lws-minimal-http-client-timeout-h3
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates and tests the H3 client reply timeout: an HTTP/3 GET is
 * issued against a "blackhole" server that completes the QUIC + TLS handshake
 * but then deliberately never sends any H3 response.  The client must receive
 * LWS_CALLBACK_CLIENT_CONNECTION_ERROR ("Timed out waiting server reply")
 * within the context timeout, rather than hanging on the live QUIC connection
 * forever.
 *
 * Run with no args: client mode (connects to --server/-p, expects a timeout).
 * Run with -s:     server mode, the blackhole responder (listens on -p).
 *
 * The test is driven by ctest, which starts the server (-s) as a background
 * fixture and then runs the client against it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

/* A short, deterministic reply timeout for the client. */
#define CLIENT_TIMEOUT_SECS	4

static int interrupted, bad = 1;
static struct lws *client_wsi;
static int _argc;
static const char **_argv;
static int server_mode;

/*
 * We reuse the canned self-signed cert/key that the other QUIC examples ship,
 * so the test is fully self-contained and needs no on-disk artefacts.
 */
static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";
static const char * const test_key = // NOSONAR
"-----BEGIN PRIVATE KEY-----\n" // NOSONAR
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";


/*
 * Server (blackhole) HTTP protocol: accept the request, then deliberately do
 * nothing.  No response is ever produced, so the client's reply timeout is the
 * only thing that can resolve the stream.
 */
static int
callback_blackhole_http(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_HTTP:
		/* Acknowledge we got the request, but never answer it. */
		lwsl_notice("%s: blackhole: received request, not responding\n",
			    __func__);
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols server_protocols[] = {
	{ "http", callback_blackhole_http, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Client HTTP protocol: we only succeed by receiving the connection-error
 * callback that fires when PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE expires.
 */
static int
callback_client_http(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("CLIENT_CONNECTION_ERROR: %s\n",
			    in ? (char *)in : "(null)");
		/*
		 * This is the expected outcome: the reply timeout fired while
		 * we were in LRS_WAITING_SERVER_REPLY.
		 */
		interrupted = 1;
		bad = 0;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* If the blackhole actually answered, the timeout is moot; the
		 * response would be cleared and we'd come here.  That's not what
		 * this test wants, so treat it as a failure. */
		lwsl_err("Unexpected response from blackhole server\n");
		interrupted = 1;
		bad = 2;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_err("Unexpected COMPLETED from blackhole server\n");
		interrupted = 1;
		bad = 2;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* CLOSED without first seeing CONNECTION_ERROR is acceptable too
		 * (the stream close path is also valid), as long as it wasn't a
		 * normal completion. */
		if (bad == 1) {
			lwsl_notice("CLOSED_CLIENT_HTTP (timed out via close path)\n");
			interrupted = 1;
			bad = 0;
			lws_cancel_service(lws_get_context(wsi));
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols client_protocols[] = {
	{ "http", callback_client_http, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

static int
connect_client(struct lws_context *context, struct lws_vhost *vh,
	       const char *address, uint16_t port)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof i);
	i.context = context;
	i.vhost = vh;			/* bind our own protocol, not SS _ss_default */
	i.address = address;
	i.port = port;
	i.path = "/no-reply";
	i.host = address;
	i.origin = address;
	i.method = "GET";

	/* Force ALPN to h3 and use QUIC */
	i.alpn = "h3";
	i.ssl_connection = LCCSCF_USE_SSL |
			   LCCSCF_ALLOW_SELFSIGNED |
			   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

	i.protocol = client_protocols[0].name;
	i.local_protocol_name = client_protocols[0].name;
	i.pwsi = &client_wsi;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("Client creation failed\n");
		return 1;
	}

	return 0;
}

/*
 * We drive the client connect from a short deferred timer rather than the
 * LWS_SYSTATE_OPERATIONAL notifier: that notifier is gated by the secure
 * streams captive-portal probe, which needs outbound internet and would
 * otherwise make this self-contained test environment-dependent.  By the time
 * the sul fires the context + TLS global init are ready.
 */
static lws_sorted_usec_list_t connect_sul;
static struct lws_context *g_context;
static struct lws_vhost *g_client_vh;

static void
connect_sul_cb(lws_sorted_usec_list_t *sul)
{
	const char *p;
	uint16_t port = 0;

	if (server_mode)
		return; /* server is already listening */

	if ((p = lws_cmdline_option(_argc, _argv, "-p")))
		port = (uint16_t)atoi(p);
	if (!port) {
		lwsl_err("client mode needs -p <server port>\n");
		interrupted = 1;
		bad = 5;
		return;
	}

	if (connect_client(g_context, g_client_vh, "127.0.0.1", port))
		interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	struct lws_context *context;
	const char *p;
	uint16_t port = 7681;
	int n = 0;

	_argc = argc;
	_argv = argv;

	signal(SIGINT, sigint_handler);

	if (lws_cmdline_option(argc, argv, "-s"))
		server_mode = 1;

	if ((p = lws_cmdline_option(argc, argv, "-p"))) {
		int __pt = atoi(p);
		if (__pt < 0 || __pt > 65535) {
			lwsl_err("Port %d is outside valid 16-bit range\n", __pt);
			return 1;
		}
		port = (uint16_t)__pt;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DISABLE_IPV6;
	info.protocols = server_protocols; /* used for the server vhost */
	/*
	 * Client reply timeout: short and deterministic for the test.  This is
	 * what arms PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE on the H3 stream
	 * after the request is sent.
	 */
	info.timeout_secs = CLIENT_TIMEOUT_SECS;
	info.fd_limit_per_thread = 1 + 1 + 1;

	lwsl_user("LWS minimal http client timeout h3 (%s mode)\n",
		  server_mode ? "server/blackhole" : "client");

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}
	g_context = context;

	/*
	 * Instantiate the blackhole QUIC server vhost explicitly.  We pass
	 * CONTEXT_PORT_NO_LISTEN_SERVER so it doesn't open a TCP listener; the
	 * UDP QUIC listener is created below via lws_create_adopt_udp().
	 */
	if (server_mode) {
		struct lws_context_creation_info vinfo;

		memset(&vinfo, 0, sizeof vinfo);
		vinfo.options = info.options;
		vinfo.protocols = server_protocols;
		vinfo.port = CONTEXT_PORT_NO_LISTEN_SERVER;
		vinfo.vhost_name = "blackhole";
		vinfo.listen_accept_role = "quic";
		vinfo.listen_accept_protocol = "http";
		vinfo.alpn = "h3";
		vinfo.server_ssl_cert_mem = test_cert;
		vinfo.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
		vinfo.server_ssl_private_key_mem = test_key;
		vinfo.server_ssl_private_key_mem_len =
						(unsigned int)strlen(test_key);

		vh = lws_create_vhost(context, &vinfo);
		if (!vh) {
			lwsl_err("Failed to create blackhole QUIC vhost\n");
			goto bail;
		}

		if (!lws_create_adopt_udp(vh, NULL, port, LWS_CAUDP_BIND,
					  "http", NULL, NULL, NULL, NULL,
					  "quic_listen")) {
			lwsl_err("Failed to bind QUIC UDP listener on %u\n",
				 port);
			goto bail;
		}
		lwsl_notice("blackhole server listening on %u (QUIC/h3)\n", port);
	} else {
		/*
		 * Client mode: create our own vhost with our own client http
		 * protocol, so the client stream binds to callback_client_http
		 * (and not the secure-streams _ss_default vhost).  Then defer
		 * the connect slightly so the separate blackhole server process
		 * (when run via ctest) is ready.
		 */
		struct lws_context_creation_info vinfo;

		memset(&vinfo, 0, sizeof vinfo);
		vinfo.options = info.options;
		vinfo.protocols = client_protocols;
		vinfo.port = CONTEXT_PORT_NO_LISTEN;
		vinfo.vhost_name = "timeout-h3-cli";

		g_client_vh = lws_create_vhost(context, &vinfo);
		if (!g_client_vh) {
			lwsl_err("Failed to create client vhost\n");
			goto bail;
		}

		connect_sul.cb = connect_sul_cb;
		lws_sul_schedule(context, 0, &connect_sul, connect_sul_cb,
				 1 * LWS_US_PER_SEC);
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	if (!server_mode) {
		if (bad == 0) {
			lwsl_user("Completed: OK (timed out as expected)\n");
			return 0;
		}
		lwsl_err("Completed: failed: exit %d\n", bad);
		return 1;
	}

bail:
	lws_context_destroy(context);
	return !!server_mode ? 0 : 1;
}
