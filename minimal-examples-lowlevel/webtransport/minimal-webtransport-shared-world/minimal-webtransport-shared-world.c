/*
 * lws-minimal-webtransport-shared-world
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This server mounts the assets for the WebTransport shared world UI and loads the
 * `protocol_webtransport_shared_world` plugin.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;

static const struct lws_http_mount mount = {
	.mount_next		= NULL,
	.mountpoint		= "/",
	.origin			= "../../../../plugins/protocol_webtransport_shared_world/assets",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

extern const lws_plugin_protocol_t webtransport_shared_world;

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal webtransport shared world | visit https://localhost:7681\n");

	memset(&info, 0, sizeof info);
	info.port = 7681;
	info.mounts = &mount;
	info.error_document_404 = "/404.html";
	info.options =
		LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	info.pvo = NULL;
	info.protocols = webtransport_shared_world.protocols;

	info.ssl_cert_filepath = "localhost-100y.cert";
	info.ssl_private_key_filepath = "localhost-100y.key";
	info.alpn = "h3,h2,http/1.1";

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
