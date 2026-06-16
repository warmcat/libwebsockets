/*
 * lws-minimal-http-client-openhitls-session
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates TLS session reuse with OpenHiTLS.  The program performs
 * two sequential HTTPS (or WSS) connections to the same TLS server within a
 * single lws_context, and verifies that the second connection reuses the
 * cached TLS session via lws_tls_session_is_reused().
 *
 * Gated to compile only under OpenHiTLS + TLS sessions builds.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad, completed;
static lws_state_notify_link_t nl;
static struct lws_context *context;
static struct lws *client_wsi;

static int conn_count;	     /* which connection: 0 or 1 */
static int session_reused[2]; /* per-connection reuse status */
static int use_ws;	     /* if set, do WSS instead of HTTPS */

static lws_sorted_usec_list_t sul_reconnect;
static lws_sorted_usec_list_t sul_exit;

static const char *server_address = "localhost";
static int server_port = 443;

static void
exit_event_loop(lws_sorted_usec_list_t *sul)
{
	completed++;
	lws_cancel_service(context);
}

/* Forward declarations */
static void connect_client(lws_sorted_usec_list_t *sul);
static void schedule_reconnect_cb(lws_sorted_usec_list_t *sul);

/* ------------------------------------------------------------------ */
/* WS echo server (for WSS mode)                                      */
/* ------------------------------------------------------------------ */

struct pss_echo {
	char buf[128];
	size_t len;
};

static int
callback_ws_echo_server(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss_echo *pss = (struct pss_echo *)user;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		memset(pss, 0, sizeof(*pss));
		break;
	case LWS_CALLBACK_RECEIVE:
		if (len > sizeof(pss->buf))
			len = sizeof(pss->buf);
		memcpy(pss->buf, in, len);
		pss->len = len;
		lws_callback_on_writable(wsi);
		break;
	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (pss->len) {
			unsigned char sbuf[LWS_PRE + 128];
			memcpy(&sbuf[LWS_PRE], pss->buf, pss->len);
			lws_write(wsi, &sbuf[LWS_PRE], pss->len,
				  LWS_WRITE_TEXT);
			pss->len = 0;
		}
		break;
	default:
		break;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* WS client callbacks (for WSS mode)                                 */
/* ------------------------------------------------------------------ */

static int ws_echo_verified;

static int
callback_ws_client(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	unsigned char buf[LWS_PRE + 128];

	switch (reason) {

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
	{
		int idx = conn_count;
#if defined(LWS_WITH_TLS_SESSIONS)
		session_reused[idx] = lws_tls_session_is_reused(wsi);
		lwsl_user("WS connection %d: session_reused=%d\n",
			  idx, session_reused[idx]);
#endif
		/* send test message */
		memcpy(&buf[LWS_PRE], "hello", 5);
		if (lws_write(wsi, &buf[LWS_PRE], 5, LWS_WRITE_TEXT) < 5) {
			lwsl_err("%s: ws write failed\n", __func__);
			bad = 1;
			lws_sul_schedule(lws_get_context(wsi), 0,
					 &sul_exit, exit_event_loop, 1);
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (lws_is_final_fragment(wsi)) {
			if (len == 5 && memcmp(in, "hello", 5) == 0)
				ws_echo_verified = 1;
			/* close to trigger reconnect or completion */
			return -1;
		}
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		client_wsi = NULL;
		if (conn_count == 0) {
			conn_count = 1;
			lws_sul_schedule(context, 0, &sul_reconnect,
					 schedule_reconnect_cb,
					 LWS_US_PER_SEC);
		} else {
			lws_sul_schedule(context, 0, &sul_exit,
					 exit_event_loop, 1);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------------ */
/* HTTP client callbacks                                              */
/* ------------------------------------------------------------------ */

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
		lws_sul_schedule(lws_get_context(wsi), 0,
				 &sul_exit, exit_event_loop, 1);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	{
		int idx = conn_count;
#if defined(LWS_WITH_TLS_SESSIONS)
		session_reused[idx] = lws_tls_session_is_reused(wsi);
		lwsl_user("HTTP connection %d: session_reused=%d, status=%u\n",
			  idx, session_reused[idx],
			  lws_http_client_http_response(wsi));
#endif
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		n = sizeof(buf) - LWS_PRE;
		if (lws_http_client_read(wsi, (char **)&p, &n) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		client_wsi = NULL;
		if (conn_count == 0) {
			/* schedule reconnect after 1s delay */
			conn_count = 1;
			lws_sul_schedule(context, 0, &sul_reconnect,
					 schedule_reconnect_cb,
					 LWS_US_PER_SEC);
		} else {
			lws_sul_schedule(lws_get_context(wsi), 0,
					 &sul_exit, exit_event_loop, 1);
		}
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/*
		 * COMPLETED_CLIENT_HTTP already scheduled the next step for a
		 * clean transaction.  CLOSED_CLIENT_HTTP is only actionable if
		 * the connection ended before completion.
		 */
		if (!client_wsi)
			break;
		client_wsi = NULL;
		bad = 1;
		lws_sul_schedule(lws_get_context(wsi), 0,
				 &sul_exit, exit_event_loop, 1);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------------ */
/* Protocols                                                         */
/* ------------------------------------------------------------------ */

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	{ "lws-echo", callback_ws_echo_server,
	  sizeof(struct pss_echo), 128, 0, NULL, 0 },
	{ "lws-openhitls-session-ws", callback_ws_client,
	  0, 128, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* ------------------------------------------------------------------ */
/* Connection initiation                                              */
/* ------------------------------------------------------------------ */

static void
schedule_reconnect_cb(lws_sorted_usec_list_t *sul)
{
	connect_client(sul);
}

static void
connect_client(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.port			= server_port;
	i.address		= server_address;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED;
	i.host			= i.address;
	i.origin		= i.address;
	i.path			= "/";

	if (use_ws) {
		i.protocol		= "lws-echo";
		i.local_protocol_name = "lws-openhitls-session-ws";
	} else {
		i.method		= "GET";
		i.protocol		= protocols[0].name;
	}

	i.pwsi			= &client_wsi;

	lwsl_user("%s: connection %d to %s://%s:%d%s\n", __func__,
		  conn_count, use_ws ? "wss" : "https",
		  i.address, i.port, i.path);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		bad = 1;
		lws_sul_schedule(context, 0, &sul_exit,
				 exit_event_loop, 1);
	}
}

/* ------------------------------------------------------------------ */
/* System state notification                                          */
/* ------------------------------------------------------------------ */

static int
app_system_state_nf(lws_state_manager_t *mgr,
		    lws_state_notify_link_t *link,
		    int current, int target)
{
	if (target != LWS_SYSTATE_OPERATIONAL ||
	    current != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/* start first connection */
	connect_client(NULL);
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
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS minimal http client openhitls session\n");

	/* check for WSS mode */
	if (lws_cmdline_option(argc, argv, "--ws"))
		use_ws = 1;

	info.options			= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols			= protocols;

	if (use_ws) {
		/* embed WS echo server */
		info.port = 7730;
		p = lws_cmdline_option(argc, argv, "--port");
		if (p)
			info.port = atoi(p);
		server_port = info.port;
		info.ssl_cert_filepath =
			"libwebsockets-test-server.pem";
		info.ssl_private_key_filepath =
			"libwebsockets-test-server.key.pem";
	} else {
		info.port = CONTEXT_PORT_NO_LISTEN;
		p = lws_cmdline_option(argc, argv, "--port");
		if (p)
			server_port = atoi(p);
	}

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;
	info.register_notifier_list	= app_notifier_list;
	info.fd_limit_per_thread	= 1 + 1 + 4;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !completed && !interrupted)
		n = lws_service(context, 0);

	/*
	 * OpenHiTLS currently traps in context teardown when a WSS client and
	 * embedded TLS server share the same context.  The test outcome is
	 * already determined once the event loop exits, so let process exit
	 * reclaim the context in this specific mode.
	 */
	if (!use_ws)
		lws_context_destroy(context);

	/* Report results */
	if (bad) {
		lwsl_user("Completed: failed\n");
		return 1;
	}

#if defined(LWS_WITH_TLS_SESSIONS)
	lwsl_user("Connection 0: session_reused=%d\n", session_reused[0]);
	lwsl_user("Connection 1: session_reused=%d\n", session_reused[1]);

	if (session_reused[0] != 0) {
		lwsl_err("First connection should NOT reuse session\n");
		return 1;
	}
	if (session_reused[1] != 1) {
		lwsl_err("Second connection SHOULD reuse session but did not\n");
		return 1;
	}
	lwsl_user("Completed: OK (session reuse verified)\n");
	return 0;
#else
	lwsl_user("Completed: OK (no TLS sessions support)\n");
	return 0;
#endif
}
