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
	LWS_SW_TYPE,
	LWS_SW_BITS,
	LWS_SW_DURATION,
	LWS_SW_HASH,
	LWS_SW_D,
	LWS_SW_P,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_CURVE]	= { "--curve",         "Set crypto curve for EC keygen (e.g. P-256)" },
	[LWS_SW_TYPE]	= { "--type",          "Set key type (EC or RSA, default EC)" },
	[LWS_SW_BITS]	= { "--bits",          "Set key size for RSA keygen (e.g. 2048)" },
	[LWS_SW_DURATION]	= { "--duration",      "Set signature validity duration in hours" },
	[LWS_SW_HASH]	= { "--hash",          "Set hash type for DS record (e.g. SHA256)" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_P]	= { "-p",              "Extra plugin dir" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information (-h, --help)" },
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

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	if ((argc == 1) || lws_cmdline_option(argc, argv, "-h") || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lwsl_user("Usage: %s <keygen|importnsd|dsfromkey|signzone> [args...]\n\n", argv[0]);
		lwsl_user("  keygen    [--type <RSA|EC>] [--bits <size>] [--curve <curve>] <domain>\n");
		lwsl_user("            Outputs: <domain>.[ksk|zsk].key & <domain>.[ksk|zsk].private.jwk\n");
		lwsl_user("  importnsd <domain> <key1-prefix> [key2-prefix]\n");
		lwsl_user("            Inputs : <prefix>.private, <prefix>.key\n");
		lwsl_user("            Outputs: <domain>.[ksk|zsk].key, <domain>.[ksk|zsk].private.jwk, <domain>.dnssec.txt\n");
		lwsl_user("  dsfromkey [--hash <hash>] <domain>\n");
		lwsl_user("            Inputs : <domain>.ksk.key  Outputs: Base64 DS Record to stdout\n");
		lwsl_user("  signzone  [--duration <hours>] <domain>\n");
		lwsl_user("            Inputs : <domain>.zone, <domain>.ksk.private.jwk, <domain>.zsk.private.jwk\n");
		lwsl_user("            Outputs: <domain>.zone.signed and <domain>.zone.signed.jws (auto-bumps SOA serial)\n\n");
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lwsl_user("LWS DNSSEC Crypto Utility (DHT Plugin Wrapper)\n");

	if (argc < 2) {
		lwsl_err("Usage: lws-crypto-dnssec <keygen|importnsd|dsfromkey|signzone> [args...]\n");
		return 1;
	}

#if 0
	static const char * const pdirs[] = {
		"./lib",
		"../lib",
		"./plugins",
		"../plugins",
		"./build/lib",
		"../build/lib",
		"../../lib",
		NULL
	};
	static const char * dynamic_pdirs[3];
#endif

	memset(&info, 0, sizeof info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

#if 0
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_P].sw))) {
		dynamic_pdirs[0] = p;
		dynamic_pdirs[1] = NULL;
		info.plugin_dirs = dynamic_pdirs;
	} else {
		info.plugin_dirs = pdirs;
	}
#endif

	info.argc = (int)argc;
	info.argv = argv;

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
	int n = argc - 1;

	/* move back 1 arg each time the candidate begins with '-' */
	while (n > 1 && argv[n][0] == '-')
		n--;

	if (n < 2) {
		lwsl_err("Missing domain argument\n");
		lws_context_destroy(context);
		return 1;
	}

	if (!strcmp(mode, "keygen")) {
		struct lws_dht_dnssec_keygen_args kg_args;
		memset(&kg_args, 0, sizeof(kg_args));

		if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_CURVE].sw)))
			kg_args.curve = p;
		if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_TYPE].sw)))
			kg_args.type = p;
		if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_BITS].sw)))
			kg_args.bits = atoi(p);

		kg_args.domain = argv[n];

		if (ops->keygen) result = ops->keygen(context, &kg_args);
	} else if (!strcmp(mode, "dsfromkey")) {
		struct lws_dht_dnssec_dsfromkey_args ds_args;
		memset(&ds_args, 0, sizeof(ds_args));

		ds_args.domain = argv[n];
		if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_HASH].sw)))
			ds_args.hash = p;

		if (ops->dsfromkey) result = ops->dsfromkey(context, &ds_args);
	} else if (!strcmp(mode, "signzone")) {
		struct lws_dht_dnssec_signzone_args sz_args;
		memset(&sz_args, 0, sizeof(sz_args));

		if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_DURATION].sw)))
			sz_args.sign_validity_duration = (uint32_t)atoi(p) * 3600;

		sz_args.domain = argv[n];

		if (ops->signzone) result = ops->signzone(context, &sz_args);
	} else if (!strcmp(mode, "importnsd")) {
		struct lws_dht_dnssec_importnsd_args i_args;
		memset(&i_args, 0, sizeof(i_args));

		if (n < 3) {
			lwsl_err("importnsd requires at least <domain> <key1-prefix>\n");
			result = 1;
		} else {
			i_args.domain = argv[n - 1];
			int p_idx = 2;
			while (p_idx < argc && argv[p_idx][0] == '-') { p_idx += 2; }
			i_args.domain = argv[p_idx++];
			if (p_idx < argc) i_args.key1_prefix = argv[p_idx++];
			if (p_idx < argc) i_args.key2_prefix = argv[p_idx++];

			if (!i_args.key1_prefix) {
				lwsl_err("importnsd requires <domain> and at least 1 key prefix.\n");
				result = 1;
			} else {
				if (ops->importnsd) result = ops->importnsd(context, &i_args);
			}
		}
	} else {
		lwsl_err("Unknown mode: %s. Use keygen, importnsd, dsfromkey, or signzone.\n", mode);
		result = 1;
	}

	lws_context_destroy(context);
	return result;
}
