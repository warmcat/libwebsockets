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
 * lws-dht-dnssec plugin.
 */

#include <libwebsockets.h>

#include <signal.h>
#include <fcntl.h>

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
extern const struct lws_protocols lws_dht_dnssec_protocols[];
static struct lws_protocols app_protocols[3] = { {0} };

enum {
	LWS_SW_S,
	LWS_SW_P,
	LWS_SW_TARGET_IP,
	LWS_SW_TARGET_PORT,
	LWS_SW_PUT,
	LWS_SW_DOMAIN,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_S]		= { "-s",		"Storage path (defaults to ./dht-store)" },
	[LWS_SW_P]		= { "-p",		"UDP socket port to bind to (defaults to 49100)" },
	[LWS_SW_TARGET_IP]	= { "--target-ip",	"Bootstrapping UDP network node target IP" },
	[LWS_SW_TARGET_PORT]	= { "--target-port",	"Bootstrapping UDP network node target port" },
	[LWS_SW_PUT]		= { "--put",		"Chunk, wrap, and distribute a payload object to the network" },
	[LWS_SW_DOMAIN]		= { "--domain",		"Download and validate a registered Domain" },
	[LWS_SW_HELP]		= { "--help",		"Show this help information" },
};

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
		.next		= NULL,
		.name		= "lws-dht-dnssec",
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
		.name		= "get-domain",
		.value		= ""
	},
	{
		.options	= NULL,
		.next		= NULL,
		.name		= "domain",
		.value		= ""
	},
};

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

		memset(&info, 0, sizeof(info));
                info.vhost_name		= "dht-client";
                info.pvo		= pvos;
		info.port		= atoi(port_buf);
		info.protocols		= app_protocols;
                info.options		= LWS_SERVER_OPTION_EXPLICIT_VHOSTS | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

		vh = lws_create_vhost(cx, &info);
                if (!vh) {
			lwsl_err("vhost creation failed\n");
			return 0;
		}

		if (!lws_vhost_name_to_protocol(vh, "lws-dht-dnssec")) {
			lwsl_err("dht-dnssec protocol plugin not found\n");
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
	int dht_port = 0;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal raw DHT DNSSEC client\n");

	if (argc == 1 || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw) ||
	    lws_cmdline_option(argc, argv, "-h")) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));

		return 0;
	}

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

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_DOMAIN].sw))) {
		pvos[9].value = p;  /* "domain" PVO */
		if (!use_stdin)
			pvos[8].value = p; /* implicitly feed it to "get-domain" if no "--put" was supplied */
	}

	app_protocols[0].name			= "http";
	app_protocols[0].callback		= lws_callback_http_dummy;
	app_protocols[1].name			= NULL;
	app_protocols[1].callback		= NULL;

	static const char * const pdirs[] = {
		"./lib",
		"../lib",
		"./build/lib",
		"../build/lib",
		"../../lib",
		NULL
	};

	info.port				= CONTEXT_PORT_NO_LISTEN;
	info.options				= LWS_SERVER_OPTION_EXPLICIT_VHOSTS | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols				= app_protocols;
	info.fd_limit_per_thread		= 100;
	info.pvo 				= NULL;
	info.plugin_dirs			= pdirs;

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
