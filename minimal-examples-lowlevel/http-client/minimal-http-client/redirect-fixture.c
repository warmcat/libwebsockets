/*
 * lws-minimal-http-client-redirect-fixture
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The server end of the http client examples' redirect ctests: it is not an
 * example itself.
 *
 * Both of its listeners redirect every request to another host: the address
 * given by --to, on the plain http listener, path /landing.  The client
 * examples dial the fixture by a different name than --to, so the redirect is
 * cross-host, and from the tls listener it is also https -> http.
 *
 * /landing on the plain http listener answers 200, unless the request carries
 * an Authorization header: then the credential leaked to a host it was not
 * meant for, and it answers 403, so the client does not see success.
 *
 *  --port-tls <port>	the tls listener, which redirects everything
 *  --port <port>	the plain http listener, redirecting all but /landing
 *  --to <host>		the host the redirects name
 *  --cert <file>	the tls listener's certificate
 *  --key <file>	... and its key
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static struct lws_context *context;
static char location[128];
static int interrupted;

static int
callback_fixture(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	if (reason != LWS_CALLBACK_HTTP)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	/* an h2 stream is not itself tls, its network connection is */
	if (lws_is_ssl(lws_get_network_wsi(wsi)) ||
	    strcmp((const char *)in, "/landing")) {
		lwsl_user("%s: redirecting %s to %s\n", __func__,
			  (const char *)in, location);

		if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
				      (unsigned char *)location,
				      (int)strlen(location), &p, end) < 0)
			return -1;

		return 0;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION)) {
		lwsl_err("%s: /landing: credentials leaked to here\n", __func__);

		if (lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL) ||
		    lws_http_transaction_completed(wsi))
			return -1;

		return 0;
	}

	lwsl_user("%s: /landing: no credentials\n", __func__);

	if (lws_return_http_status(wsi, HTTP_STATUS_OK, "ok") ||
	    lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_fixture, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
	lws_cancel_service(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *to = "127.0.0.1", *cert = NULL, *key = NULL;
	int port = 0, port_tls = 0, n = 0;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS http client redirect fixture\n");

	if ((p = lws_cmdline_option(argc, argv, "--port")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-tls")))
		port_tls = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--to")))
		to = p;
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	if (port <= 0 || port > 65535 || port_tls <= 0 || port_tls > 65535 ||
	    !cert || !key) {
		lwsl_err("Usage: %s --port <port> --port-tls <port> "
			 "--cert <file> --key <file> [--to <host>]\n", argv[0]);
		return 1;
	}

	lws_snprintf(location, sizeof(location), "http://%s:%d/landing",
		     to, port);

	info.protocols = protocols;
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "plain";
	info.port = port;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create plain vhost\n");
		goto bail;
	}

	info.vhost_name = "tls";
	info.port = port_tls;
	info.ssl_cert_filepath = cert;
	info.ssl_private_key_filepath = key;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create tls vhost\n");
		goto bail;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;

bail:
	lws_context_destroy(context);

	return 1;
}
