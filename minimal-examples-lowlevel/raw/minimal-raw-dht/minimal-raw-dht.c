/*
 * lws-minimal-raw-dht
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal DHT node that can store and retrieve data/files
 * using the lws-dht UDP data transport, by instantiating the
 * lws-dht-object-store plugin.
 */

#include <libwebsockets.h>


enum {
	LWS_SW_BULK,
	LWS_SW_DOMAIN,
	LWS_SW_GEN_MANIFEST,
	LWS_SW_GET,
	LWS_SW_JWK,
	LWS_SW_POLICY_ALLOW,
	LWS_SW_POLICY_DENY,
	LWS_SW_PUT,
	LWS_SW_RECEIVER,
	LWS_SW_TARGET_IP,
	LWS_SW_TARGET_PORT,
	LWS_SW_TEST_HANDSHAKE,
	LWS_SW_P,
	LWS_SW_S,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_BULK]	= { "--bulk",          "Enable --bulk feature" },
	[LWS_SW_DOMAIN]	= { "--domain",        "Specify the DNS target domain" },
	[LWS_SW_GEN_MANIFEST]	= { "--gen-manifest",  "Enable --gen-manifest feature" },
	[LWS_SW_GET]	= { "--get",           "Enable --get feature" },
	[LWS_SW_JWK]	= { "--jwk",           "Enable --jwk feature" },
	[LWS_SW_POLICY_ALLOW]	= { "--policy-allow",  "Enable --policy-allow feature" },
	[LWS_SW_POLICY_DENY]	= { "--policy-deny",   "Enable --policy-deny feature" },
	[LWS_SW_PUT]	= { "--put",           "Chunk, wrap, and distribute a payload object to the network" },
	[LWS_SW_RECEIVER]	= { "--receiver",      "Enable --receiver feature" },
	[LWS_SW_TARGET_IP]	= { "--target-ip",     "Bootstrapping UDP network node target IP" },
	[LWS_SW_TARGET_PORT]	= { "--target-port",   "Bootstrapping UDP network node target port" },
	[LWS_SW_TEST_HANDSHAKE]	= { "--test-handshake", "Enable --test-handshake feature" },
	[LWS_SW_P]	= { "-p",              "Port number to listen or connect on" },
	[LWS_SW_S]	= { "-s",              "Use TLS / https" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <sys/stat.h>
#if defined(WIN32)
#include <direct.h>
#define mkdir(a, b) _mkdir(a)
#endif

static lws_state_notify_link_t nl;
int retcode = 1;
int interrupted;
int use_stdin;
char port_buf[16];
const char *storage_path = "./dht-store";
static struct lws_context *cx;

static lws_state_notify_link_t *const app_notifier_list[] = {&nl, NULL};
extern const struct lws_protocols lws_dht_object_store_protocols[];
extern const struct lws_protocols lws_dht_stats_protocols[];
extern const struct lws_protocols lws_dht_dnssec_protocols[];

static void
dht_completion_cb(void *closure, int result)
{
	int *p_interrupted = (int *)closure;

	*p_interrupted = 1;

	// lwsl_user("dht_completion_cb called! result: %d\n", result);

	if (!result)
		retcode = 0;

	lws_cancel_service(cx);
}

struct lws_protocol_vhost_options pvos[] = {
	{
		.options	= &pvos[1],
		.next		= &pvos[17],
		.name		= "lws-dht-object-store",
		.value		= "ok"
	},
	{
		.options	= NULL,
		.next		= &pvos[2],
		.name		= "dht-storage-path",
		.value		= "./dht-store"
	},
	{
		.options	= NULL,
		.next		= &pvos[3],
		.name		= "dht-port",
		.value		= port_buf
	},
	{
		.options	= NULL,
		.next		= &pvos[4],
		.name		= "completion-cb",
		.value		= (const char *)dht_completion_cb
	},
	{
		.options	= NULL,
		.next		= &pvos[5],
		.name		= "completion-cb-arg",
		.value		= (const char *)&interrupted
	},
	{
		.options	= NULL,
		.next		= &pvos[6],
		.name		= "target-ip",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[7],
		.name		= "target-port",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[8],
		.name		= "put-file",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[9],
		.name		= "get-hash",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[10],
		.name		= "bulk",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[11],
		.name		= "gen-manifest",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[12],
		.name		= "receiver",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[13],
		.name		= "dht-iface",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[14],
		.name		= "dht-jwk",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[15],
		.name		= "dht-policy-allow",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[16],
		.name		= "dht-policy-deny",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= &pvos[18],
		.name		= "dht-test-handshake",
		.value		= ""
	},
	{
		.options	= &pvos[1],
		.next		= NULL,
		.name		= "lws-dht-dnssec",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= NULL,
		.name		= "domain",
		.value		= ""
	},
};

static const struct lws_http_mount mount_stats = {
	.mountpoint		= "/",
	.origin			= "../../../plugins/protocol_lws_dht_stats/assets",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

static struct lws_protocols app_protocols[5];

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
                    int current, int target)
{
        struct lws_context *cx = lws_system_context_from_system_mgr(mgr);
        struct lws_context_creation_info info;
        struct lws_vhost *vh;

        switch (target) {
        case LWS_SYSTATE_OPERATIONAL:
                if (current == LWS_SYSTATE_OPERATIONAL)
                        break;

		lwsl_user("%s: OPERATIONAL->creating vhost\n", __func__);

		static const struct lws_protocol_vhost_options pvo_stats = {
			NULL, NULL, "lws-dht-stats", ""
		};

		memset(&info, 0, sizeof(info));
                info.vhost_name		= "http";
                info.port		= atoi(port_buf) + 100;
                info.protocols		= app_protocols;
                info.mounts		= &mount_stats;
                info.pvo		= &pvo_stats;
                info.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
                vh = lws_create_vhost(cx, &info);
                if (!vh) {
			lwsl_err("http vhost creation failed\n");
			return 0;
		}

		if (!lws_vhost_name_to_protocol(vh, "lws-dht-stats")) {
			lwsl_err("dht-stats protocol plugin not found\n");
			return 0;
		}

		memset(&info, 0, sizeof(info));
                info.vhost_name		= "dht";
                info.pvo		= pvos;
		info.port		= atoi(port_buf);
		info.protocols		= app_protocols;
                info.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
                vh = lws_create_vhost(cx, &info);
                if (!vh) {
			lwsl_err("vhost creation failed\n");
			return 0;
		}

		if (!lws_vhost_name_to_protocol(vh, "lws-dht-dnssec")) {
			lwsl_err("dht-dnssec protocol plugin not found\n");
			return 0;
		}
		if (!lws_vhost_name_to_protocol(vh, "lws-dht-object-store")) {
			lwsl_err("dht-object-store protocol plugin not found\n");
			return 0;
		}

                lws_finalize_startup(cx, __func__);
		break;
        }
	return 0;
}

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int dht_port = 5000;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal raw DHT | DHT protocol plugin refactor\n");

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_S].sw)))
		storage_path = p;

	mkdir(storage_path, 0700);
	pvos[1].value = storage_path;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_P].sw)))
		dht_port = atoi(p);

	lws_snprintf(port_buf, sizeof(port_buf), "%d", dht_port);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_TARGET_IP].sw)))
		pvos[5].value = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_TARGET_PORT].sw)))
		pvos[6].value = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PUT].sw))) {
		pvos[7].value = p;
		use_stdin = 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_GET].sw))) {
		pvos[8].value = p;
		use_stdin = 1;
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_BULK].sw)) {
		pvos[9].value = "1";
		use_stdin = 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_DOMAIN].sw)))
		pvos[18].value = p;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_GEN_MANIFEST].sw))
		pvos[10].value = "1";

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_RECEIVER].sw))
		pvos[11].value = "1";

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_JWK].sw)))
		pvos[13].value = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_POLICY_ALLOW].sw)))
		pvos[14].value = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_POLICY_DENY].sw)))
		pvos[15].value = p;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_TEST_HANDSHAKE].sw))
		pvos[16].value = "1";


#if defined(LWS_WITH_PLUGINS)
	static const char * const d_plugin_dirs[] = { NULL };
#endif

	app_protocols[0].name = "http";
	app_protocols[0].callback = lws_callback_http_dummy;
	app_protocols[1].name = NULL;
	app_protocols[1].callback = NULL;

	info.port				= CONTEXT_PORT_NO_LISTEN;
	info.options				= LWS_SERVER_OPTION_EXPLICIT_VHOSTS | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.pvo				= pvos;
	info.protocols				= app_protocols;
#if defined(LWS_WITH_PLUGINS)
	info.plugin_dirs			= d_plugin_dirs;
#endif
	info.fd_limit_per_thread		= 100;

        nl.name					= "app";
        nl.notify_cb				= app_system_state_nf;
        info.register_notifier_list		= app_notifier_list;

        cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(cx, 0);

	lws_context_destroy(cx);

        return lws_cmdline_passfail(argc, argv, retcode);
}
