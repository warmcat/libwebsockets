/*
 * lws-minimal-http-client-openhitls-certfail
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Verifies OpenHiTLS correctly rejects TLS handshakes when certificate
 * verification fails:
 *   R6: Self-signed cert rejected without LCCSCF_ALLOW_SELFSIGNED
 *   R7: Hostname mismatch (CN/SAN != connected hostname)
 *   R8: mTLS client cert required but not provided
 *
 * Gated to compile only under OpenHiTLS builds.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#ifndef LWS_TEST_SERVER_CERT_PEM
#define LWS_TEST_SERVER_CERT_PEM "libwebsockets-test-server.pem"
#endif

#ifndef LWS_TEST_SERVER_KEY_PEM
#define LWS_TEST_SERVER_KEY_PEM "libwebsockets-test-server.key.pem"
#endif

static int interrupted, bad, completed, server_only;
static lws_state_notify_link_t nl;
static struct lws_context *context;
static struct lws *client_wsi;

/*
 * Test mode: "selfsigned", "hostname", "mtls"
 */
static const char *test_mode;
static int test_port = 443;

/* ------------------------------------------------------------------ */
/* Embedded TLS server for hostname and mTLS tests                     */
/* ------------------------------------------------------------------ */

static const struct lws_http_mount mount = {
	.mountpoint		= "/",
	.origin			= "./mount-origin",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

/* ------------------------------------------------------------------ */
/* HTTP client callback                                               */
/* ------------------------------------------------------------------ */

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("CLIENT_CONNECTION_ERROR: %s\n",
			  in ? (char *)in : "(null)");
		/*
		 * Expected failure: handshake rejected is a "success" for
		 * our test. The program will exit with bad=0 (no error),
		 * and CTest WILL_FAIL TRUE inverts PASS.
		 */
		completed++;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/*
		 * Unexpected success: handshake completed when it should
		 * have been rejected. This is a real failure.
		 */
		lwsl_err("Unexpected: connection established (should have failed)\n");
		bad = 1;
		completed++;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		completed++;
		lws_cancel_service(lws_get_context(wsi));
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		0,
		0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

/* ------------------------------------------------------------------ */
/* System state notification                                          */
/* ------------------------------------------------------------------ */

static int
app_system_state_nf(lws_state_manager_t *mgr,
		    lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *cx =
		lws_system_context_from_system_mgr(mgr);
	struct lws_client_connect_info i;

	if (target != LWS_SYSTATE_OPERATIONAL ||
	    current != LWS_SYSTATE_OPERATIONAL)
		return 0;

	memset(&i, 0, sizeof(i));
	i.context	= cx;
	i.port		= test_port;
	i.address	= "localhost";
	i.host		= i.address;
	i.origin	= i.address;
	i.path		= "/";
	i.protocol	= protocols[0].name;
	i.pwsi		= &client_wsi;

	if (!strcmp(test_mode, "selfsigned")) {
		/*
		 * R6: Connect to self-signed cert server WITHOUT
		 * LCCSCF_ALLOW_SELFSIGNED. Handshake should fail.
		 */
		i.ssl_connection = LCCSCF_USE_SSL;
		lwsl_user("%s: selfsigned test - expect rejection\n", __func__);
	} else if (!strcmp(test_mode, "hostname")) {
		/*
		 * R7: Trust the wronghost cert explicitly so the rejection is
		 * caused by hostname mismatch, not by the cert being self-signed.
		 * No LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK, and "localhost" !=
		 * CN/SAN "wronghost.example.com".
		 */
		i.ssl_connection = LCCSCF_USE_SSL;
		lwsl_user("%s: hostname mismatch test - expect rejection\n",
			  __func__);
	} else if (!strcmp(test_mode, "mtls")) {
		/*
		 * R8: Connect to mTLS server without client cert.
		 * Server requires valid client cert, client doesn't provide one.
		 */
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED;
		lwsl_user("%s: mTLS test - expect rejection\n", __func__);
	} else {
		lwsl_err("Unknown test mode: %s\n", test_mode);
		bad = 1;
		completed++;
		return 0;
	}

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed immediately\n", __func__);
		/* Immediate connect failure counts as expected rejection */
		completed++;
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sigint_handler(int sig)
{
	(void)sig;

	interrupted = 1;

	if (context) {
		lws_cancel_service(context);
	}
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	p = lws_cmdline_option(argc, argv, "--server-only");
	if (p) {
		server_only = 1;
		test_mode = p;
	} else {
		p = lws_cmdline_option(argc, argv, "--test");
		if (p)
			test_mode = p;
	}

	if (!test_mode) {
		lwsl_err("Usage: %s [--server-only hostname|mtls | --test selfsigned|hostname|mtls] [--port <port>]\n",
			 argv[0]);
		return 1;
	}

	lwsl_user("LWS minimal http client openhitls certfail %s %s\n",
		  server_only ? "--server-only" : "--test", test_mode);

	info.options	= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols	= protocols;

	p = lws_cmdline_option(argc, argv, "--port");

	if (server_only && !strcmp(test_mode, "hostname")) {
		/*
		 * R7: Embed a TLS server using wronghost cert.
		 * Server listens on the specified port.
		 */
		info.port = 7750;
		if (p)
			info.port = atoi(p);
		info.ssl_cert_filepath =
			"wronghost.example.com.cert";
		info.ssl_private_key_filepath =
			"wronghost.example.com.key";
		info.mounts = &mount;
		lwsl_user("  Embedded wronghost server on port %d\n",
			  info.port);
	} else if (server_only && !strcmp(test_mode, "mtls")) {
		/*
		 * R8: Embed a TLS server requiring client certs (mTLS).
		 */
		info.port = 7760;
		if (p)
			info.port = atoi(p);
		info.ssl_cert_filepath =
			LWS_TEST_SERVER_CERT_PEM;
		info.ssl_private_key_filepath =
			LWS_TEST_SERVER_KEY_PEM;
		info.options |=
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
		/*
		 * The CA cert used to verify client certs must be the one
		 * that signed the repo's self-signed cert.
		 */
		info.ssl_ca_filepath =
			LWS_TEST_SERVER_CERT_PEM;
		info.mounts = &mount;
		lwsl_user("  Embedded mTLS server on port %d\n", info.port);
	} else if (server_only) {
		lwsl_err("Unsupported --server-only mode: %s\n", test_mode);
		return 1;
	} else {
		/* Client-only mode: all test servers are external fixtures. */
		info.port = CONTEXT_PORT_NO_LISTEN;
		if (p)
			test_port = atoi(p);
		if (!strcmp(test_mode, "hostname")) {
			info.client_ssl_ca_filepath =
				"./wronghost.example.com.cert";
		}
	}

	if (!server_only) {
		nl.name				= "app";
		nl.notify_cb			= app_system_state_nf;
		info.register_notifier_list	= app_notifier_list;
		info.fd_limit_per_thread	= 1 + 1 + 1;
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (server_only) {
		while (!interrupted) {
			/*
			 * Server-only fixture mode is a disposable helper
			 * process.  Keep servicing until SIGTERM from the
			 * cleanup fixture and then let process exit reclaim
			 * resources instead of exercising normal teardown.
			 */
			(void)lws_service(context, 0);
		}
		return 0;
	}

	while (n >= 0 && !interrupted && !completed)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	/*
	 * For cert verification tests, we expect the connection to FAIL.
	 * - If it failed: bad=0, completed=1 → exit 0
	 * - If it succeeded: bad=1, completed=1 → exit 1
	 *
	 * CTest uses WILL_FAIL TRUE, so:
	 * - exit 0 (expected failure happened) → WILL_FAIL inverts to FAIL
	 * - exit 1 (unexpected success) → WILL_FAIL inverts to PASS
	 *
	 * Wait... that's backwards. Let me reconsider.
	 *
	 * With WILL_FAIL TRUE:
	 * - Test exits 0 → CTest reports FAIL (inverted)
	 * - Test exits non-0 → CTest reports PASS (inverted)
	 *
	 * So we want:
	 * - Expected failure happened → exit 1 (so CTest sees PASS)
	 * - Unexpected success → exit 0 (so CTest sees FAIL)
	 *
	 * Therefore: if bad==0 (connection failed as expected), exit 1.
	 *            if bad==1 (connection succeeded unexpectedly), exit 0.
	 */
	if (bad) {
		lwsl_user("Completed: unexpected success (BUG)\n");
		return 0; /* CTest WILL_FAIL → FAIL = correct */
	}

	lwsl_user("Completed: cert verification rejected as expected\n");
	return 1; /* CTest WILL_FAIL → PASS = correct */
}
