/*
 * lws-minimal-http-client-openhitls-https
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal https client that connects to a local TLS server,
 * performs a GET, and verifies it receives an HTTP 200 response.  Gated to
 * compile only under OpenHiTLS builds.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad, status, completed;
static lws_state_notify_link_t nl;
static struct lws *client_wsi;

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 1024], *p = &buf[LWS_PRE];
	int n;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		bad = 1;
		completed++;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		bad |= status != 200;
		completed++;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		lwsl_user("Connected with server response: %d\n", status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
		return 0; /* don't passthru */

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		n = sizeof(buf) - LWS_PRE;
		if (lws_http_client_read(wsi, (char **)&p, &n) < 0)
			return -1;
		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
		bad |= status != 200;
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

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *cx = lws_system_context_from_system_mgr(mgr);
	struct lws_client_connect_info i;
	const char *p;

	if (target != LWS_SYSTATE_OPERATIONAL ||
	    current != LWS_SYSTATE_OPERATIONAL)
		return 0;

	memset(&i, 0, sizeof i);
	i.context		= cx;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED;
	i.port			= 443;

	p = lws_cmdline_option_cx(cx, "--port");
	if (p)
		i.port = atoi(p);

	i.address		= "localhost";
	i.path			= "/";
	i.method		= "GET";
	i.host			= i.address;
	i.origin		= i.address;
	i.protocol		= protocols[0].name;
	i.pwsi			= &client_wsi;

	lwsl_user("%s: connecting to https://%s:%d%s\n", __func__,
		  i.address, i.port, i.path);
	if (!lws_client_connect_via_info(&i))
		completed++;

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS minimal http client openhitls https\n");

	info.options			= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols;

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;
	info.register_notifier_list	= app_notifier_list;
	info.fd_limit_per_thread	= 1 + 1 + 1;

#if defined(LWS_WITH_OPENHITLS)
	{
		const char *ca = lws_cmdline_option(argc, argv, "--ca");
		if (ca)
			info.client_ssl_ca_filepath = ca;
	}
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !completed && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
