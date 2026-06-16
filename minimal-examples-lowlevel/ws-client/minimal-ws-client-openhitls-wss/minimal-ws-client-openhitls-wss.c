/*
 * lws-minimal-ws-client-openhitls-wss
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a WSS client connecting to an embedded WS echo server
 * within the same lws_context, sending a test message, and verifying the
 * echoed response matches.  Gated to compile only under OpenHiTLS + WS builds.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad, completed;
static struct lws_context *context;

static const char *test_msg = "hello";
static const size_t test_msg_len = 5;

static lws_sorted_usec_list_t sul_exit;

static void
exit_event_loop(lws_sorted_usec_list_t *sul)
{
	completed++;
	lws_cancel_service(context);
}

/*
 * WS client state
 */
static struct {
	struct lws *wsi;
	lws_sorted_usec_list_t sul;
	uint16_t retry_count;
	char rxbuf[128];
	size_t rxlen;
	int got_echo;
	int sent;
	int done;
} client;

/*
 * WS echo server: per-session data
 */
struct pss_echo {
	char buf[128];
	size_t len;
};

/* ------------------------------------------------------------------ */
/* WS echo server callbacks                                           */
/* ------------------------------------------------------------------ */

static int
callback_ws_echo_server(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss_echo *pss = (struct pss_echo *)user;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_user("%s: server: client connected\n", __func__);
		memset(pss, 0, sizeof(*pss));
		break;

	case LWS_CALLBACK_RECEIVE:
		/* store received message and request writable */
		if (len > sizeof(pss->buf))
			len = sizeof(pss->buf);
		memcpy(pss->buf, in, len);
		pss->len = len;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (pss->len) {
			unsigned char buf[LWS_PRE + 128];
			memcpy(&buf[LWS_PRE], pss->buf, pss->len);
			if (lws_write(wsi, &buf[LWS_PRE], pss->len,
				      LWS_WRITE_TEXT) < (int)pss->len) {
				lwsl_err("%s: echo write failed\n", __func__);
				return -1;
			}
			pss->len = 0;
		}
		break;

	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* WS client callbacks                                                */
/* ------------------------------------------------------------------ */

static void
connect_client(lws_sorted_usec_list_t *sul);

static const uint32_t backoff_ms[] = { 1000, 2000, 3000 };
static const lws_retry_bo_t retry = {
	.retry_ms_table			= backoff_ms,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(backoff_ms),
	.conceal_count			= LWS_ARRAY_SIZE(backoff_ms),
	.secs_since_valid_ping		= 3,
	.secs_since_valid_hangup	= 10,
	.jitter_percent			= 20,
};

static int
callback_ws_client(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	unsigned char buf[LWS_PRE + 128];

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		goto do_retry;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("%s: client: WS established\n", __func__);
		/* send test message */
		memcpy(&buf[LWS_PRE], test_msg, test_msg_len);
		if (lws_write(wsi, &buf[LWS_PRE], test_msg_len,
			      LWS_WRITE_TEXT) < (int)test_msg_len) {
			lwsl_err("%s: client write failed\n", __func__);
			bad = 1;
			completed++;
			lws_cancel_service(lws_get_context(wsi));
		}
		client.sent = 1;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		lwsl_user("%s: client received %d bytes\n", __func__, (int)len);
		if (len <= sizeof(client.rxbuf) - client.rxlen) {
			memcpy(client.rxbuf + client.rxlen, in, len);
			client.rxlen += len;
		}
		if (lws_is_final_fragment(wsi)) {
			/* verify echo matches */
			if (client.rxlen == test_msg_len &&
			    memcmp(client.rxbuf, test_msg, test_msg_len) == 0) {
				lwsl_user("%s: echo verified OK\n", __func__);
				client.got_echo = 1;
			} else {
				lwsl_err("%s: echo mismatch (got %d, expected %d)\n",
					 __func__, (int)client.rxlen,
					 (int)test_msg_len);
				bad = 1;
			}
			client.done = 1;
			/* close the connection by returning -1 */
			return -1;
		}
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		if (client.done) {
			/* defer exit to next event loop iteration */
			lws_sul_schedule(lws_get_context(wsi), 0,
					 &sul_exit, exit_event_loop, 1);
		} else
			goto do_retry;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

do_retry:
	if (lws_retry_sul_schedule_retry_wsi(wsi, &client.sul,
					      connect_client,
					      &client.retry_count)) {
		lwsl_err("%s: connection attempts exhausted\n", __func__);
		bad = 1;
		completed++;
	}
	return 0;
}

static void
connect_client(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));

	i.context	= context;
	i.port		= 7681;
	{
		const char *p = lws_cmdline_option_cx(context, "--port");
		if (p)
			i.port = atoi(p);
	}
	i.address	= "localhost";
	i.path		= "/";
	i.host		= i.address;
	i.origin	= i.address;
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED;
	i.protocol	= "lws-echo";
	i.local_protocol_name = "lws-openhitls-wss-client";
	i.pwsi		= &client.wsi;
	i.retry_and_idle_policy = &retry;

	lwsl_user("%s: connecting to wss://localhost:%d/\n", __func__, i.port);
	if (!lws_client_connect_via_info(&i))
		if (lws_retry_sul_schedule(context, 0, sul, &retry,
					   connect_client,
					   &client.retry_count)) {
			bad = 1;
			completed++;
		}
}

/* ------------------------------------------------------------------ */
/* Protocols                                                         */
/* ------------------------------------------------------------------ */

static const struct lws_protocols protocols[] = {
	/* 0: must be first, http handler */
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	/* WS echo server protocol */
	{ "lws-echo", callback_ws_echo_server,
	  sizeof(struct pss_echo), 128, 0, NULL, 0 },
	/* WS client protocol */
	{ "lws-openhitls-wss-client", callback_ws_client,
	  0, 128, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* ------------------------------------------------------------------ */
/* System state notification                                          */
/* ------------------------------------------------------------------ */

static lws_state_notify_link_t nl;

static int
app_system_state_nf(lws_state_manager_t *mgr,
		    lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *cx =
		lws_system_context_from_system_mgr(mgr);

	if (target != LWS_SYSTATE_OPERATIONAL ||
	    current != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/* schedule the client connection attempt */
	lws_sul_schedule(cx, 0, &client.sul, connect_client, 1);

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
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS minimal ws client openhitls wss\n");

	/* server vhost: listen on port with TLS using repo certs */
	info.port			= 7681;
	{
		const char *p = lws_cmdline_option(argc, argv, "--port");
		if (p)
			info.port = atoi(p);
	}
	info.protocols			= protocols;
	info.options			= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.ssl_cert_filepath		= "libwebsockets-test-server.pem";
	info.ssl_private_key_filepath	= "libwebsockets-test-server.key.pem";
	info.fd_limit_per_thread	= 1 + 1 + 4;

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;
	info.register_notifier_list	= app_notifier_list;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !completed && !interrupted)
		n = lws_service(context, 0);

	/*
	 * OpenHiTLS currently traps in context teardown when a WSS client and
	 * embedded TLS server share the same context.  The test verdict is
	 * known when the loop exits, so allow process exit to reclaim it.
	 */
	lwsl_user("Completed: %s (echo %s)\n",
		  bad ? "failed" : "OK",
		  client.got_echo ? "verified" : "missing");

	return bad;
}
