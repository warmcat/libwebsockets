/*
 * lws-minimal-http-client-h3
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http client using lws, restricted to H3/QUIC.
 *
 * It visits https://libwebsockets.org/index.html and receives the html page there.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int bad = 1, status, refuse_body, refused;
static const char *refuse_path = "/leaf.jpg";
static struct lws_client_connect_info ci;

static int
do_connect(const char *path);
static struct lws_context *context;
static struct lws *client_wsi;
static int _argc;
static const char **_argv;

static const lws_retry_bo_t retry = {
	.secs_since_valid_ping = 3,
	.secs_since_valid_hangup = 10,
};

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		lws_default_loop_exit(context);
		bad = 3; /* connection failed before we could make connection */
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		{
			char buf[128];

			lws_get_peer_simple(wsi, buf, sizeof(buf));
			status = (int)lws_http_client_http_response(wsi);

			lwsl_user("Connected to %s, http response: %d\n",
					buf, status);
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
		if (refuse_body && refused < refuse_body) {
			/*
			 * --refuse-body N: reject the first body chunk of the
			 * first N transactions, the way an SS returning
			 * DISCONNECT_ME does.  Each h3 stream must then
			 * actually close (CLOSED, not COMPLETED, and not after
			 * a timeout), and a final /index.html on the same QUIC
			 * connection must still complete: the abandoned
			 * streams' unread bytes must not have eaten the
			 * connection flow control window
			 */
			refused++;
			lwsl_user("refusing body %d of %d: expecting CLOSED\n",
				  refused, refuse_body);
			return -1;
		}
		return 0; /* don't passthru */

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char buffer[1024 + LWS_PRE];
			char *px = buffer + LWS_PRE;
			int lenx = sizeof(buffer) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
		lws_default_loop_exit(context);
		bad = status != 200;
		if (refuse_body && refused <= refuse_body) {
			lwsl_err("refused body but transaction completed\n");
			bad = 4;
		}
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_CLOSED_CLIENT_HTTP\n");
		if (refuse_body && refused <= refuse_body &&
		    wsi == client_wsi) {
			/*
			 * closed after we refused the body: next transaction
			 * on the same connection (it joins the existing QUIC
			 * connection via the active conns list)
			 */
			client_wsi = NULL;
			if (do_connect(refused < refuse_body ? refuse_path :
							     "/index.html"))
				bad = 3;
			else
				refused += refused == refuse_body;
			break;
		}
		lws_default_loop_exit(context);
		if (bad == 1)
			bad = status != 200;
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
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
		0, 0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		   int current, int target)
{
	struct lws_context *context = mgr->parent;

	const char *p;

	if (current != LWS_SYSTATE_OPERATIONAL || target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	lwsl_info("%s: operational\n", __func__);

	memset(&ci, 0, sizeof ci);
	ci.context = context;
	ci.port = 443;
	ci.address = "libwebsockets.org";
	if ((p = lws_cmdline_option(_argc, _argv, "--server")))
		ci.address = p;
	if ((p = lws_cmdline_option(_argc, _argv, "-p")))
		{
			int __pt = atoi(p);
			if (__pt < 0 || __pt > 65535) {
				lwsl_err("Port %d is outside valid 16-bit range\n", __pt);
				return 1;
			}
			ci.port = (uint16_t)__pt;
		}
	ci.host = ci.address;
	ci.origin = ci.address;
	ci.method = "GET";

	/* Force ALPN to h3 and use QUIC */
	ci.alpn = "h3";
	ci.ssl_connection = LCCSCF_USE_SSL | LCCSCF_PIPELINE;
	if (lws_cmdline_option(_argc, _argv, "-l"))
		ci.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	
	ci.protocol = protocols[0].name;
	ci.pwsi = &client_wsi;
	ci.retry_and_idle_policy = &retry;

	if (do_connect(refuse_body ? refuse_path : "/index.html"))
		return 1;

	return 0;
}

static int
do_connect(const char *path)
{
	struct lws_client_connect_info i = ci;

	i.path = path;
	lwsl_user("%s: GET %s\n", __func__, path);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("Client creation failed\n");
		lws_default_loop_exit(context);
		if (bad != 3)
			bad = 3; /* synchronous connection/creation failure */
		lws_cancel_service(context);

		return 1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
					     system_notify_cb, "app" };
	lws_state_notify_link_t *na[] = { &notifier, NULL };
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	_argc = argc;
	_argv = argv;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS minimal http client h3\n");

	if ((p = lws_cmdline_option(argc, argv, "--refuse-body")))
		refuse_body = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--refuse-path")))
		refuse_path = p;

	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;
	info.register_notifier_list = na;
	info.connect_timeout_secs = 30;
	info.fd_limit_per_thread = 1 + 1 + 1;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		bad = 5;
		goto bail;
	}

	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);

bail:
	if (bad == 0) {
		lwsl_user("Completed: OK\n");
		return 0;
	} else {
		lwsl_err("Completed: failed: exit %d\n", bad);
		return 1;
	}
}
