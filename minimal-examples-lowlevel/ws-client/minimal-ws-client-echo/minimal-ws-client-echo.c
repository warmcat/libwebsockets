/*
 * lws-minimal-ws-client-echo
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a ws client that echoes back what it was sent, in a
 * way compatible with autobahn -m fuzzingserver
 */

#include <libwebsockets.h>

enum {
	LWS_SW_LIBUV,
	LWS_SW_SSL,
	LWS_SW_D,
	LWS_SW_I,
	LWS_SW_N,
	LWS_SW_O,
	LWS_SW_P,
	LWS_SW_S,
	LWS_SW_U,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_LIBUV]	= { "--libuv",         "Enable --libuv feature" },
	[LWS_SW_SSL]	= { "--ssl",           "Enable SSL" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_I]	= { "-i",              "Interface to bind to" },
	[LWS_SW_N]	= { "-n",              "Enable -n feature" },
	[LWS_SW_O]	= { "-o",              "Enable -o feature" },
	[LWS_SW_P]	= { "-p",              "Port number to listen or connect on" },
	[LWS_SW_S]	= { "-s",              "Use TLS / https" },
	[LWS_SW_U]	= { "-u",              "URL to connect to" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <string.h>
#include <signal.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_minimal_client_echo.c"

static struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_MINIMAL_CLIENT_ECHO,
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_context *context;
static int interrupted, port = 7681, options = 0;
static const char *url = "/", *ads = "localhost", *iface = NULL;

/* pass pointers to shared vars to the protocol */

static const struct lws_protocol_vhost_options pvo_iface = {
	NULL,
	NULL,
	"iface",		/* pvo name */
	(void *)&iface	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_ads = {
	&pvo_iface,
	NULL,
	"ads",		/* pvo name */
	(void *)&ads	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_url = {
	&pvo_ads,
	NULL,
	"url",		/* pvo name */
	(void *)&url	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_options = {
	&pvo_url,
	NULL,
	"options",		/* pvo name */
	(void *)&options	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_port = {
	&pvo_options,
	NULL,
	"port",		/* pvo name */
	(void *)&port	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo_interrupted = {
	&pvo_port,
	NULL,
	"interrupted",		/* pvo name */
	(void *)&interrupted	/* pvo value */
};

static const struct lws_protocol_vhost_options pvo = {
	NULL,		/* "next" pvo linked-list */
	&pvo_interrupted,	/* "child" pvo linked-list */
	"lws-minimal-client-echo",	/* protocol name we belong to on this vhost */
	""		/* ignored */
};
static const struct lws_extension extensions[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
		 "; client_no_context_takeover"
		 "; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
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
	lwsl_user("LWS minimal ws client echo + permessage-deflate + multifragment bulk message\n");
	lwsl_user("   lws-minimal-ws-client-echo [-n (no exts)] [-u url] [-p port] [-o (once)]\n");

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_U].sw)))
		url = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_P].sw)))
		port = atoi(p);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_O].sw))
		options |= 1;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_SSL].sw))
		options |= 2;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_S].sw)))
		ads = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_I].sw)))
		iface = p;

	lwsl_user("options %d, ads %s\n", options, ads);

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.pvo = &pvo;
	if (!lws_cmdline_option(argc, argv, switches[LWS_SW_N].sw))
		info.extensions = extensions;
	info.pt_serv_buf_size = 32 * 1024;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_VALIDATE_UTF8;
	/*
	 * since we know this lws context is only ever going to be used with
	 * one client wsis / fds / sockets at a time, let lws know it doesn't
	 * have to use the default allocations for fd tables up to ulimit -n.
	 * It will just allocate for 1 internal and 1 (+ 1 http2 nwsi) that we
	 * will use.
	 */
	info.fd_limit_per_thread = 1 + 1 + 1;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_LIBUV].sw))
		info.options |= LWS_SERVER_OPTION_LIBUV;
	else
		signal(SIGINT, sigint_handler);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (!lws_service(context, 0) && !interrupted)
		;

	lws_context_destroy(context);

	n = (options & 1) ? interrupted != 2 : interrupted == 3;
	lwsl_user("Completed %d %s\n", interrupted, !n ? "OK" : "failed");

	return n;
}
