/*
 * lws-api-test-extip
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This api test confirms the extip plugin works as a client.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_EXPECTED_EXIT,
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_EXPECTED_EXIT]	= { "--expected-exit", "Enable --expected-exit feature" },
	[LWS_SW_SERVER]		= { "-s",              "IP reporting server address optionally with :port" },
	[LWS_SW_HELP]		= { "--help",		"Show this help information" },
};

static int interrupted, bad = 1;
static struct lws_context *context;

/* 
 * We conditionally `#include` the plugin source directly into the executable
 * if dynamic plugins are completely disabled system-wide.
 */
#if !defined(LWS_WITH_PLUGINS)
#include "../../../plugins/protocol_lws_extip/protocol_lws_extip.c"
#endif

static int
smd_cb(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	if (!(c & LWSSMDCL_NETWORK))
		return 0;

	if (!buf)
		return 0;

	if (!strstr((const char *)buf, "\"ext-ips\""))
		return 0;

	lwsl_user("Extip SMD: %s\n", (const char *)buf);

	/* Check if we got at least one valid IP. */
	if (strstr((const char *)buf, ".") || strstr((const char *)buf, ":")) {
		bad = 0;
	}

	return 0;
}

void sigint_handler(int sig)
{
	interrupted = 1;
}

static lws_sorted_usec_list_t sul_timeout;

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_user("%s: Test timed out (5s)..\n", __func__);
	if (!bad) {
		lwsl_user("At least one af obtained successfully.\n");
	} else {
		lwsl_err("Failed to obtain any external IP!\n");
	}
	interrupted = 1;
	lws_cancel_service(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_system_ops_t ops;
	const char *p;
	char server_addr[64] = "127.0.0.1:49200";
	
	signal(SIGINT, sigint_handler);
	
	memset(&info, 0, sizeof info);
	memset(&ops, 0, sizeof ops);

	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_cmdline_option_handle_builtin(0, NULL, &info);
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lwsl_user("LWS API selftest: extip client\n");

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw))) {
		const char *colon = strchr(p, ':');
		if (colon)
			lws_strncpy(server_addr, p, sizeof(server_addr));
		else
			lws_snprintf(server_addr, sizeof(server_addr), "%s:49200", p);
	}

	info.early_smd_cb = smd_cb;
	info.early_smd_class_filter = LWSSMDCL_NETWORK;
	
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	struct lws_protocol_vhost_options pvo_debug = {
		.next = NULL,
		.options = NULL,
		.name = "debug",
		.value = "1"
	};

	struct lws_protocol_vhost_options pvo_extip = {
		.next = &pvo_debug,
		.options = NULL,
		.name = "connect",
		.value = server_addr
	};

	struct lws_protocol_vhost_options pvo = {
		.next = NULL,
		.options = &pvo_extip,
		.name = "protocol-lws-extip",
		.value = ""
	};

#if !defined(LWS_WITH_PLUGINS)
	static const struct lws_protocols my_protocols[] = {
		LWS_PLUGIN_PROTOCOL_EXTIP,
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	};
#endif

	info.pvo = &pvo;
#if !defined(LWS_WITH_PLUGINS)
	info.protocols = my_protocols;
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		bad = 2;
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb, 5 * LWS_USEC_PER_SEC);

	while (!interrupted)
		lws_service(context, 0);

	lws_context_destroy(context);

bail:
	return lws_cmdline_passfail(argc, argv, bad);
}
