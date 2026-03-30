/*
 * lws-minimal-http-server-eventlib
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http[s] server that can work with any of the
 * supported event loop backends, or the default poll() one.
 *
 * To keep it simple, it serves stuff from the subdirectory
 * "./mount-origin" of the directory it was started in.
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_EV,
	LWS_SW_EVENT,
	LWS_SW_GLIB,
	LWS_SW_UV,
	LWS_SW_D,
	LWS_SW_S,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_EV]	= { "--ev",            "Enable --ev feature" },
	[LWS_SW_EVENT]	= { "--event",         "Enable --event feature" },
	[LWS_SW_GLIB]	= { "--glib",          "Enable --glib feature" },
	[LWS_SW_UV]	= { "--uv",            "Enable --uv feature" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_S]	= { "-s",              "Use TLS / https" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <string.h>
#include <signal.h>

#if defined(LWS_WITH_PLUGINS)
static const char * const plugin_dirs[] = {
	LWS_PLUGIN_DIR "/",
	NULL
};
#endif

static struct lws_context *context;

static struct lws_protocols protocols[] = {
	/* first protocol must always be HTTP handler */

	{ "http-only", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * mount handlers for sections of the URL space
 */

static const struct lws_http_mount mount_ziptest_uncomm = {
	.mountpoint		= "/uncommziptest",		/* mountpoint in URL namespace on this vhost */
	.origin			= "./mount-origin/candide-uncompressed.zip",	/* handler */
	.origin_protocol	= LWSMPRO_FILE,	/* origin points to a file */
	.mountpoint_len		= 14,			/* strlen("/ziptest"), ie length of the mountpoint */
}, mount_ziptest = {
	.mount_next		= (struct lws_http_mount *)&mount_ziptest_uncomm,			/* linked-list pointer to next*/
	.mountpoint		= "/ziptest",		/* mountpoint in URL namespace on this vhost */
	.origin			= "./mount-origin/candide.zip",	/* handler */
	.origin_protocol	= LWSMPRO_FILE,	/* origin points to a file */
	.mountpoint_len		= 8,			/* strlen("/ziptest"), ie length of the mountpoint */

}, mount_post = {
	.mount_next		= (struct lws_http_mount *)&mount_ziptest, /* linked-list pointer to next*/
	.mountpoint		= "/formtest",		/* mountpoint in URL namespace on this vhost */
	.origin			= "protocol-post-demo",	/* handler */
	.origin_protocol	= LWSMPRO_CALLBACK,	/* origin points to a callback */
	.mountpoint_len		= 9,			/* strlen("/formtest"), ie length of the mountpoint */

}, mount = {
	.mount_next		= &mount_post,		/* linked-list "next" */
	.mountpoint		= "/",			/* mountpoint URL */
	.origin			= "./mount-origin",	/* serve from dir */
	.def			= "test.html",		/* default filename */
	.origin_protocol	= LWSMPRO_FILE,		/* files in a dir */
	.mountpoint_len		= 1,			/* char count */
};

void signal_cb(void *handle, int signum)
{
	lwsl_err("%s: signal %d\n", __func__, signum);

	switch (signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:

		break;
	}
	lws_context_destroy(context);
}

void sigint_handler(int sig)
{
	signal_cb(NULL, sig);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http server eventlib | visit http://localhost:7681\n");
	lwsl_user(" [-s (ssl)] [--uv (libuv)] [--ev (libev)] [--event (libevent)]\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.error_document_404 = "/404.html";
	info.pcontext = &context;
	info.protocols = protocols;
#if defined(LWS_WITH_PLUGINS)
	info.plugin_dirs = plugin_dirs;
#endif
	info.signal_cb = signal_cb;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_S].sw)) {
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#if defined(LWS_WITH_TLS)
		info.ssl_cert_filepath = "localhost-100y.cert";
		info.ssl_private_key_filepath = "localhost-100y.key";
#endif
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_UV].sw))
		info.options |= LWS_SERVER_OPTION_LIBUV;
	else
		if (lws_cmdline_option(argc, argv, switches[LWS_SW_EVENT].sw))
			info.options |= LWS_SERVER_OPTION_LIBEVENT;
		else
			if (lws_cmdline_option(argc, argv, switches[LWS_SW_EV].sw))
				info.options |= LWS_SERVER_OPTION_LIBEV;
			else
				if (lws_cmdline_option(argc, argv, switches[LWS_SW_GLIB].sw))
					info.options |= LWS_SERVER_OPTION_GLIB;
				else
					signal(SIGINT, sigint_handler);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (!lws_vhost_name_to_protocol(lws_get_vhost_by_name(context, "default"), "protocol-post-demo")) {
		lwsl_err("protocol-post-demo plugin required\n");
		return 1;
	}

	while (!lws_service(context, 0))
		;

	lwsl_info("calling external context destroy\n");
	lws_context_destroy(context);

	return 0;
}
