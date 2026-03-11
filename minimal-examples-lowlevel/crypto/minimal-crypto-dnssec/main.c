/*
 * lws-crypto-dnssec
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Natively integrated DNSSEC cryptography utility using lws_gencrypto.
 * Defers execution dynamically through the lws-dht-dnssec protocol.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

enum {
	LWS_SW_CURVE,
	LWS_SW_DURATION,
	LWS_SW_HASH,
	LWS_SW_KSK,
	LWS_SW_ZSK,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_CURVE]	= { "--curve",         "Enable --curve feature" },
	[LWS_SW_DURATION]	= { "--duration",      "Enable --duration feature" },
	[LWS_SW_HASH]	= { "--hash",          "Enable --hash feature" },
	[LWS_SW_KSK]	= { "--ksk",           "Enable --ksk feature" },
	[LWS_SW_ZSK]	= { "--zsk",           "Enable --zsk feature" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

int main(int argc, const char **argv)
{
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	const struct lws_protocols *prot;
	const struct lws_dht_dnssec_ops *ops;
	struct lws_vhost *vh;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS DNSSEC Crypto Utility (DHT Plugin Wrapper)\n");

	if (argc < 2) {
		lwsl_err("Usage: lws-crypto-dnssec <keygen|dsfromkey|signzone> [args...]\n");
		return 1;
	}

	static const char * const pdirs[] = {
		"./lib",
		"../lib",
		"./build/lib",
		"../build/lib",
		"../../lib",
		NULL
	};

	memset(&info, 0, sizeof info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;
	info.plugin_dirs = pdirs;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	vh = lws_get_vhost_by_name(context, "default");
	if (!vh) {
		lwsl_err("default vhost failed\n");
		lws_context_destroy(context);
		return 1;
	}

	prot = lws_vhost_name_to_protocol(vh, "lws-dht-dnssec");
	if (!prot) {
		lwsl_err("lws-dht-dnssec plugin not found. Please ensure it is built and loaded.\n");
		lws_context_destroy(context);
		return 1;
	}

	ops = (const struct lws_dht_dnssec_ops *)prot->user;
	if (!ops) {
		lwsl_err("lws-dht-dnssec plugin loaded but has no ops struct exposed\n");
		lws_context_destroy(context);
		return 1;
	}

	const char *mode = argv[1];

	if (!strcmp(mode, "keygen")) {
		if (ops->keygen) result = ops->keygen(context, argc, argv);
	} else if (!strcmp(mode, "dsfromkey")) {
		if (ops->dsfromkey) result = ops->dsfromkey(context, argc, argv);
	} else if (!strcmp(mode, "signzone")) {
		if (ops->signzone) result = ops->signzone(context, argc, argv);
	} else {
		lwsl_err("Unknown mode: %s. Use keygen, dsfromkey, or signzone.\n", mode);
		result = 1;
	}

	lws_context_destroy(context);
	return result;
}
