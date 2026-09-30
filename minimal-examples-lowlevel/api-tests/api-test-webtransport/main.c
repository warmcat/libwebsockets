/*
 * lws-api-test-webtransport
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws WebTransport client and two lws h3 servers in one process confirm
 * the client only opens a WebTransport session with a peer whose SETTINGS
 * enabled it, and that either end closing its session wsi ends the session
 * on both (draft-ietf-webtrans-http3).
 *
 *  - the "wt" server advertises SETTINGS_ENABLE_WEBTRANSPORT and
 *    SETTINGS_H3_DATAGRAM, and the client's session is established.  The
 *    server then ends the session, and the client must see its own end of
 *    the session close.
 *
 *  - the client opens a session with the "wt" server and a bidi stream on
 *    it, and sends a message on the stream.  When the server has received
 *    it, the client ends the session.  The server must see both its session
 *    and its end of the stream close.
 *
 *  - the "nowt" server is a vhost with the h3_settings_no_wt fault, so its
 *    SETTINGS enable neither.  The client must fail the attempt with a
 *    CLIENT_CONNECTION_ERROR saying so, without ever sending the CONNECT:
 *    the server's protocol must not see a WebTransport request at all.
 *
 * The second case needs LWS_WITH_SYS_FAULT_INJECTION, without it only the
 * first case runs.
 */

#include <libwebsockets.h>
#include <libwebsockets/lws-webtransport.h>
#include <string.h>
#include <signal.h>

#define CASE_TIMEOUT_S 10
/*
 * The peer must see a session end promptly: it is told on the wire.  Some
 * timeout closing it seconds later instead means it was not told.
 */
#define PEER_CLOSE_BOUND_US (1 * LWS_US_PER_SEC)

#define STREAM_MSG "wt-stream-msg"

enum {
	WTAT_SERVER_ENDS,	/* the server closes the session */
	WTAT_CLIENT_ENDS,	/* the client opens a stream, then closes */
	WTAT_NOWT,		/* connect to the server without wt */
};

struct xcase {
	const char	*name;
	int		type;
};

static const struct xcase cases[] = {
	{ "server ends the session: client sees it close", WTAT_SERVER_ENDS },
	{ "client ends the session: server sees it and its stream close",
							WTAT_CLIENT_ENDS },
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	{ "peer SETTINGS without WebTransport: refused before CONNECT",
							WTAT_NOWT },
#endif
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static const char *server_addr = "127.0.0.1";
static int port_wt = 7681, port_nowt = 7682, cur = -1, failures, ran,
	   case_done;
static lws_usec_t us_close;	/* when one end closed its session wsi */

/* what the servers' protocol saw during the case */
static struct {
	struct lws	*session;	/* the server's end of the session */
	struct lws	*stream;	/* the server's end of the stream */
	int		wt_requests;	/* CONNECTs offered to the protocol */
	int		sessions_closed;
	int		stream_msgs;	/* STREAM_MSG received on a stream */
	int		streams_closed;
} srv;

/* what the client saw during the case */
static struct {
	struct lws	*session;	/* the client's end of the session */
	int		established;
	int		stream_msg_sent;
	int		sessions_closed;
	int		conn_error;
	char		conn_error_reason[128];
} cli;

/* a self-signed test cert does for the client's alpn */

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_finish(int pass, const char *why)
{
	if (case_done)
		return;
	case_done = 1;

	lws_sul_cancel(&sul_watchdog);

	if (pass)
		lwsl_user("case %d: PASS\n", cur);
	else {
		lwsl_err("case %d: FAIL: %s\n", cur, why);
		failures++;
	}

	lws_sul_schedule(context, 0, &sul_next, next_case,
			 100 * LWS_US_PER_MS);
}

static void
case_evaluate(void)
{
	const struct xcase *c;

	/* closes during context destroy, after the last case */
	if (cur < 0 || cur >= (int)LWS_ARRAY_SIZE(cases) || case_done)
		return;

	c = &cases[cur];

	switch (c->type) {
	case WTAT_SERVER_ENDS:
	case WTAT_CLIENT_ENDS:
		if (!cli.established) {
			case_finish(0, "session not established");
			return;
		}
		if (srv.wt_requests != 1) {
			case_finish(0, "server did not see exactly one CONNECT");
			return;
		}
		if (c->type == WTAT_CLIENT_ENDS && srv.stream_msgs != 1) {
			case_finish(0, "server did not get the stream message");
			return;
		}

		/*
		 * Done when both ends of the session have closed, and for the
		 * client closing, when the server's end of the stream has too.
		 * Whichever end did not close its session wsi itself only
		 * learns of it from the wire.
		 */
		if (!srv.sessions_closed || !cli.sessions_closed ||
		    (c->type == WTAT_CLIENT_ENDS && !srv.streams_closed))
			return;

		if (lws_now_usecs() - us_close > PEER_CLOSE_BOUND_US) {
			case_finish(0, "peer saw the session end too late");
			return;
		}

		case_finish(1, NULL);
		return;

	default:
		break;
	}

	if (cli.established) {
		case_finish(0, "session established with a peer without wt");
		return;
	}
	if (!cli.conn_error) {
		case_finish(0, "no CLIENT_CONNECTION_ERROR");
		return;
	}
	if (!strstr(cli.conn_error_reason, "did not enable WebTransport")) {
		case_finish(0, "CLIENT_CONNECTION_ERROR for the wrong reason");
		return;
	}
	if (srv.wt_requests) {
		case_finish(0, "the CONNECT was sent to a peer without wt");
		return;
	}

	case_finish(1, NULL);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		/* issued on the CONNECT stream before the 200 */
		lwsl_user("%s: server: WebTransport CONNECT on %s\n", __func__,
			  lws_get_vhost_name(lws_get_vhost(wsi)));
		srv.wt_requests++;
		break;

	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		if (lws_wt_is_session(wsi))
			srv.session = wsi;
		break;

	case LWS_CALLBACK_RECEIVE:
		/* session rx is a datagram, we only expect the stream's */
		if (lws_wt_is_session(wsi))
			break;
		if (len != strlen(STREAM_MSG) || memcmp(in, STREAM_MSG, len)) {
			case_finish(0, "server got unexpected stream data");
			break;
		}
		lwsl_user("%s: server: stream message received\n", __func__);
		srv.stream = wsi;
		srv.stream_msgs++;

		/* the client may end the session now */
		if (cli.session) {
			us_close = lws_now_usecs();
			lws_set_timeout(cli.session, PENDING_TIMEOUT_USER_OK,
					LWS_TO_KILL_ASYNC);
		} else
			case_finish(0, "client has no session");
		break;

	case LWS_CALLBACK_CLOSED:
		if (!lws_wt_is_session(wsi)) {
			/*
			 * The quic connection and listener wsi are bound to
			 * the first protocol too, only count our stream
			 */
			if (wsi != srv.stream)
				break;
			lwsl_user("%s: server: stream closed\n", __func__);
			srv.stream = NULL;
			srv.streams_closed++;
			case_evaluate();
			break;
		}
		lwsl_user("%s: server: session closed\n", __func__);
		if (wsi == srv.session)
			srv.session = NULL;
		srv.sessions_closed++;
		case_evaluate();
		break;

	default:
		break;
	}

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + sizeof(STREAM_MSG)];
	struct lws *cwsi;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: CONNECTION_ERROR: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli.conn_error++;
		if (in)
			lws_strnncpy(cli.conn_error_reason, (const char *)in,
				     len, sizeof(cli.conn_error_reason));
		case_evaluate();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* the 200 to the CONNECT: the wsi is now the session */
		if (!lws_wt_is_session(wsi))
			break;
		lwsl_user("%s: client: session established\n", __func__);
		cli.established++;
		cli.session = wsi;

		if (cases[cur].type == WTAT_SERVER_ENDS) {
			/* that is all we wanted from it: the server ends it */
			if (srv.session) {
				us_close = lws_now_usecs();
				lws_set_timeout(srv.session,
						PENDING_TIMEOUT_USER_OK,
						LWS_TO_KILL_ASYNC);
			} else
				case_finish(0, "server has no session");
			break;
		}

		/* the client ends it after the server has seen a stream */
		cwsi = lws_wt_create_stream(wsi, 0);
		if (!cwsi) {
			case_finish(0, "client could not create a stream");
			break;
		}
		lws_callback_on_writable(cwsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		/* WRITEABLE may come again unasked, there is one message */
		if (lws_wt_is_session(wsi) || cli.stream_msg_sent)
			break;
		cli.stream_msg_sent = 1;

		/*
		 * The stream stays open after the message, so it is still
		 * open on both sides when the session ends
		 */
		memcpy(&buf[LWS_PRE], STREAM_MSG, strlen(STREAM_MSG));
		if (lws_write(wsi, &buf[LWS_PRE], strlen(STREAM_MSG),
			      LWS_WRITE_BINARY) != (int)strlen(STREAM_MSG))
			case_finish(0, "client stream write failed");
		else
			lwsl_user("%s: client: stream message sent\n", __func__);
		break;

	case LWS_CALLBACK_CLOSED:
		if (!lws_wt_is_session(wsi))
			break;
		lwsl_user("%s: client: session closed\n", __func__);
		if (wsi == cli.session)
			cli.session = NULL;
		cli.sessions_closed++;
		case_evaluate();
		break;

	default:
		break;
	}

	return 0;
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_finish(0, "watchdog: case did not complete");
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	const struct xcase *c;
	struct lws_client_connect_info i;

	if (++cur >= (int)LWS_ARRAY_SIZE(cases)) {
		lws_default_loop_exit(context);
		return;
	}

	c = &cases[cur];
	lwsl_user("=== case %d: %s ===\n", cur, c->name);
	ran++;

	memset(&srv, 0, sizeof(srv));
	memset(&cli, 0, sizeof(cli));
	case_done = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = c->type == WTAT_NOWT ? port_nowt : port_wt;
	i.path = "/";
	i.protocol = "webtransport";
	i.alpn = "h3";
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
			   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

	if (!lws_client_connect_via_info(&i))
		case_finish(0, "client connect failed");
}

static const struct lws_protocols protocols_srv[] = {
	{ "webtransport", callback_srv, 0, 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "webtransport", callback_cli, 0, 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static struct lws_vhost *
create_srv_vhost(struct lws_context_creation_info *info, const char *name,
		 int port)
{
	struct lws_vhost *vh;

	/* a tls vhost opens its quic listener on the same port, beside tcp */

	info->port = port;
	info->vhost_name = name;

	vh = lws_create_vhost(context, info);
	if (!vh)
		lwsl_err("Failed to create server vhost %s\n", name);

	return vh;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	lws_fi_t fi;
#endif
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* two tcp + two quic listeners and both ends of each connection */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_wt = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--nowt-port")))
		port_nowt = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: WebTransport session setup and close\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* both server vhosts share the test cert */

	info.protocols = protocols_srv;
	info.server_ssl_cert_mem = test_cert;
	info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
	info.server_ssl_private_key_mem = test_key;
	info.server_ssl_private_key_mem_len = (unsigned int)strlen(test_key);

	if (!create_srv_vhost(&info, "srv-wt", port_wt))
		goto bail;

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	/* this one's SETTINGS enable neither WebTransport nor datagrams */
	memset(&fi, 0, sizeof(fi));
	fi.name = "h3_settings_no_wt";
	fi.type = LWSFI_ALWAYS;
	if (lws_fi_add(&info.fic, &fi))
		goto bail;

	if (!create_srv_vhost(&info, "srv-nowt", port_nowt))
		goto bail;
#else
	lwsl_user("No fault injection in this build: skipping the "
		  "peer without WebTransport\n");
#endif

	info.server_ssl_cert_mem = NULL;
	info.server_ssl_cert_mem_len = 0;
	info.server_ssl_private_key_mem = NULL;
	info.server_ssl_private_key_mem_len = 0;

	/* client vhost, no listener */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	n = failures || ran != (int)LWS_ARRAY_SIZE(cases);
	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  n ? "FAIL" : "PASS", failures, ran);

	return n;
}
