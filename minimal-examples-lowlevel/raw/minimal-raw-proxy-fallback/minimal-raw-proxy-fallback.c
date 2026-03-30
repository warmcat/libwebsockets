/*
 * lws-minimal-raw-proxy-fallback
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a normal http / https server which if it receives something
 * it can't make sense of at the start, falls back to becoming a raw tcp proxy
 * to a specified address and port.
 *
 * Incoming connections cause an outgoing connection to be initiated, and if
 * successfully established then traffic coming in one side is placed on a
 * ringbuffer and sent out the opposite side as soon as possible.
 *
 * If it receives expected packets for an http(s) connection, it acts like a
 * normal h1 / h2 webserver.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_D,
	LWS_SW_H,
	LWS_SW_R,
	LWS_SW_S,
	LWS_SW_U,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_H]	= { "-h",              "Strict Host Check / Help" },
	[LWS_SW_R]	= { "-r",              "Enable -r feature" },
	[LWS_SW_S]	= { "-s",              "Use TLS / https" },
	[LWS_SW_U]	= { "-u",              "URL to connect to" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <string.h>
#include <signal.h>
#include <sys/types.h>

#if defined(LWS_WITH_PLUGINS)
static const char * const plugin_dirs[] = {
	LWS_PLUGIN_DIR "/",
	NULL
};
#endif

static const struct lws_http_mount mount = {
	.mountpoint		= "/",			/* mountpoint URL */
	.origin			= "./mount-origin",	/* serve from dir */
	.def			= "index.html",		/* default filename */
	.origin_protocol	= LWSMPRO_FILE,		/* files in a dir */
	.mountpoint_len		= 1,			/* char count */
};

static int interrupted;

void sigint_handler(int sig)
{
	interrupted = 1;
}

static struct lws_protocol_vhost_options pvo1 = {
        NULL,
        NULL,
        "onward",		/* pvo name */
        "ipv4:127.0.0.1:22"	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo = {
        NULL,           	/* "next" pvo linked-list */
        &pvo1,			/* "child" pvo linked-list */
        "raw-proxy",		/* protocol name we belong to on this vhost */
        ""              	/* ignored */
};


int main(int argc, const char **argv)
{
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	char outward[256];
	const char *p;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal raw proxy fallback | visit http://localhost:7681\n");

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_R].sw))) {
		lws_strncpy(outward, p, sizeof(outward));
		pvo1.value = outward;
	}

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.pvo = &pvo;
	info.mounts = &mount;
#if defined(LWS_WITH_PLUGINS)
	info.plugin_dirs = plugin_dirs;
#endif
	info.error_document_404 = "/404.html";
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE |
		LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-proxy";
	info.listen_accept_protocol = "raw-proxy";

#if defined(LWS_WITH_TLS)
	if (lws_cmdline_option(argc, argv, switches[LWS_SW_S].sw)) {
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
				LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT;
		info.ssl_cert_filepath = "localhost-100y.cert";
		info.ssl_private_key_filepath = "localhost-100y.key";

		if (lws_cmdline_option(argc, argv, switches[LWS_SW_U].sw))
			info.options |= LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS;

		if (lws_cmdline_option(argc, argv, switches[LWS_SW_H].sw))
			info.options |= LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER;
	}
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (!lws_vhost_name_to_protocol(lws_get_vhost_by_name(context, "default"), "raw-proxy")) {
		lwsl_err("raw-proxy plugin required\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
