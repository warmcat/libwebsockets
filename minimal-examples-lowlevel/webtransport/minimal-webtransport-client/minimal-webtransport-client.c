/*
 * lws-minimal-webtransport-client
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a WebTransport client.
 *
 * It opens a session to lws-minimal-webtransport-server, opens a bidi stream
 * on it and sends one message, then ends the session and exits.
 */

#include <libwebsockets.h>
#include <libwebsockets/lws-webtransport.h>
#include <string.h>
#include <signal.h>

struct pss {
	int		sent;	/* our message went out on this stream */
};

static struct lws_context *context;
static struct lws *session;
static int interrupted;

static int
callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 64];
	struct lws *cwsi;
	int n;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		interrupted = 1;
		lws_default_loop_exit(context);
		break;

	/*
	 * The server's 200 to our extended CONNECT: like any other h3 client
	 * stream, it is announced with ESTABLISHED_CLIENT_HTTP (not the ws
	 * CLIENT_ESTABLISHED), and the wsi is now the WebTransport session.
	 */
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!lws_wt_is_session(wsi))
			break;

		lwsl_user("WebTransport session established\n");
		session = wsi;

		cwsi = lws_wt_create_stream(wsi, 0);
		if (!cwsi) {
			lwsl_err("Failed to create bidi stream\n");
			return -1;
		}

		/* a stream we created is not announced, ask to write on it */
		lws_callback_on_writable(cwsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (lws_wt_is_session(wsi))
			/* a write on the session wsi goes out as a datagram */
			break;

		/* WRITEABLE can come again without being asked for */
		if (!pss || pss->sent)
			break;
		pss->sent = 1;

		n = lws_snprintf((char *)&buf[LWS_PRE], sizeof(buf) - LWS_PRE,
				 "Hello from WebTransport Stream!");

		/*
		 * Finish our side of the stream with the message: ending the
		 * session resets any stream still open, discarding whatever it
		 * had not sent yet
		 */
		if (lws_write(wsi, &buf[LWS_PRE], (unsigned int)n,
			      LWS_WRITE_BINARY | LWS_WRITE_H2_STREAM_END) < n)
			return -1;

		lwsl_user("Sent message on stream, ending the session\n");

		/*
		 * Closing the session wsi ends the WebTransport session: the
		 * server sees it close, and every stream of the session goes
		 * with it on both sides
		 */
		if (session)
			lws_set_timeout(session, PENDING_TIMEOUT_USER_OK,
					LWS_TO_KILL_ASYNC);
		break;

	case LWS_CALLBACK_RECEIVE:
		/* datagrams arrive on the session wsi, stream data on the stream */
		lwsl_user("RECEIVE on %s (len: %zu)\n",
			  lws_wt_is_session(wsi) ? "session" : "stream", len);
		lwsl_hexdump_notice(in, len);
		break;

	case LWS_CALLBACK_CLOSED:
		if (!lws_wt_is_session(wsi))
			break;

		lwsl_user("WebTransport session closed\n");
		session = NULL;
		lws_default_loop_exit(context);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "webtransport", callback_minimal, sizeof(struct pss), 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	int n = 0;

	signal(SIGINT, sigint_handler);
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS minimal WebTransport client\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.port = 7681;
	i.address = "localhost";
	i.path = "/";
	i.host = i.address;
	i.origin = i.address;
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_INSECURE;
	i.protocol = "webtransport";
	i.alpn = "h3"; /* Force HTTP/3 */

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("Client connect failed\n");
		interrupted = 1;
		lws_default_loop_exit(context);
	}

	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", interrupted ? "FAIL" : "OK");

	return interrupted;
}
