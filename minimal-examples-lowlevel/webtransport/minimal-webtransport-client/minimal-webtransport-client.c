/*
 * lws-minimal-webtransport-client
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a WebTransport client.
 */

#include <libwebsockets.h>
#include <libwebsockets/lws-webtransport.h>
#include <string.h>
#include <signal.h>

static struct lws_context *context;
static int interrupted;

static int
callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		interrupted = 1;
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("LWS_CALLBACK_CLIENT_ESTABLISHED (wsi: %p)\n", wsi);
		if (lws_wt_is_session(wsi)) {
			lwsl_user("  WebTransport Session Established. Spawning bidi stream.\n");
			struct lws *cwsi = lws_wt_create_stream(wsi, 0);
			if (cwsi) {
				lwsl_user("  Created Bidi Stream: %p\n", cwsi);
				/* request to write some data */
				lws_callback_on_writable(cwsi);
			}
		} else {
			lwsl_user("  WebTransport Stream Established\n");
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (!lws_wt_is_session(wsi)) {
			uint8_t buf[LWS_PRE + 32];
			uint8_t *p = &buf[LWS_PRE];
			int n = lws_snprintf((char *)p, 32, "Hello from WebTransport Stream!");
			lws_write(wsi, p, (unsigned int)n, LWS_WRITE_BINARY);
			lwsl_user("  Sent message on stream %p\n", wsi);
		} else {
			/* We could write datagrams here */
		}
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE (wsi: %p, len: %zu)\n", wsi, len);
		lwsl_hexdump_notice(in, len);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		lwsl_user("LWS_CALLBACK_CLIENT_CLOSED\n");
		if (lws_wt_is_session(wsi)) {
			interrupted = 1;
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "webtransport", callback_minimal, 0, 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
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
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);
	lwsl_user("Completed\n");

	return 0;
}
