/*
 * lws-minimal-webtransport-server
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal WebTransport server.
 */

#include <libwebsockets.h>
#include <libwebsockets/lws-webtransport.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

static int interrupted;

static int
callback_webtransport(struct lws *wsi, enum lws_callback_reasons reason,
		      void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_user("LWS_CALLBACK_ESTABLISHED (wsi: %p)\n", wsi);
		/* If it's a session WSI, we can create streams */
		if (lws_wt_is_session(wsi)) {
			lwsl_user("  WebTransport Session Established\n");
			/* Example: create a bidi stream */
			struct lws *cwsi = lws_wt_create_stream(wsi, 0);
			if (cwsi) {
				lwsl_user("  Created Bidi Stream: %p\n", cwsi);
			}
		} else {
			lwsl_user("  WebTransport Stream Established\n");
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		lwsl_user("LWS_CALLBACK_RECEIVE (wsi: %p, len: %zu)\n", wsi, len);
		lwsl_hexdump_notice(in, len);
		/* We can bounce it back if we want, or just print it */
		break;

	case LWS_CALLBACK_CLOSED:
		lwsl_user("LWS_CALLBACK_CLOSED (wsi: %p)\n", wsi);
		break;

	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{ "webtransport", callback_webtransport, 0, 1024, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 } /* terminator */
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
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	signal(SIGINT, sigint_handler);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal WebTransport server\n");

	memset(&info, 0, sizeof info);
	info.port = 7681;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT;

	info.ssl_cert_filepath = "localhost-100y.cert";
	info.ssl_private_key_filepath = "localhost-100y.key";
	info.alpn = "h3"; /* We only support HTTP/3 for WebTransport */

	/* generate localhost-100y.cert and key if missing using lws provided script */
	
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);
	return 0;
}
