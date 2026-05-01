/*
 * lws-minimal-secure-streams-proxy
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This shows how to instantiate an SS Proxy... when clients are built with
 * LWS_SS_USE_SSPC defined as a compiler preprocessor symbol, instead of doing
 * their own SS networking, they connect out to an SS Proxy, by default at a
 * Unix Domain Socket address @proxy.ss.lws, although you can also listen on
 * TCP.
 *
 * The central networking management can then optimize connections, eg, sharing
 * an h2 bundle to the same endpoint even though streams inside are from
 * different processes.
 *
 * The proxy's policy can be a literal string, a local file, or brought in at
 * init from over the network.  In this example, there's a small literal policy
 * that tells the proxy to download
 * https://warmcat.com/policy/minimal-proxy-v4.2-v2.json and use that, for
 * convenience that includes all the minimal example streamtypes.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_I,
	LWS_SW_P,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_I]	= { "-i",              "Interface to bind to" },
	[LWS_SW_P]	= { "-p",              "Port number to listen or connect on" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <string.h>
#include <signal.h>

static int test_result = 1, port = 0 /* unix domain socket */;
static const char *ibind = NULL; /* default to unix domain skt "proxy.ss.lws" */
static lws_state_notify_link_t nl;
static struct lws_context *cx;

/*
 * We just define enough policy so it can fetch the latest one from warmcat.com
 * securely.  You'd probably want to provide a JSON file
 */

static const char * const default_ss_policy =
	"{"
	  "\"release\":"			"\"01234567\","
	  "\"product\":"			"\"myproduct\","
	  "\"schema-version\":"			"1,"
	  "\"retry\": ["	/* named backoff / retry strategies */
		"{\"default\": {"
			"\"backoff\": ["	 "1000,"
						 "2000,"
						 "3000,"
						 "5000,"
						"10000"
				"],"
			"\"conceal\":"		"5,"
			"\"jitterpc\":"		"20,"
			"\"svalidping\":"	"30,"
			"\"svalidhup\":"	"35"
		"}}"
	  "],"
	  "\"certs\": [" /* named individual certificates in BASE64 DER */
		/*
		 * Let's Encrypt certs for warmcat.com / libwebsockets.org
		 *
		 * We fetch the real policy from there using SS and switch to
		 * using that.
		 */
		"{\"isrg_root_x2\": \""
	"MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw"
	"CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg"
	"R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00"
	"MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT"
	"ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw"
	"EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW"
	"+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9"
	"ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T"
	"AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI"
	"zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW"
	"tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1"
	"/q4AaOeMSQ+2b1tbFfLn"
		"\"}"
	  "],"
	  "\"trust_stores\": [" /* named cert chains */
		"{"
			"\"name\": \"le_via_isrg\","
			"\"stack\": ["
				"\"isrg_root_x2\""
			"]"
		"}"
	  "],"
	  "\"s\": [{"
		"\"captive_portal_detect\": {"
			"\"endpoint\": \"connectivitycheck.android.com\","
			"\"http_url\": \"generate_204\","
			"\"port\": 80,"
			"\"protocol\": \"h1\","
			"\"http_method\": \"GET\","
			"\"opportunistic\": true,"
			"\"http_expect\": 204,"
			"\"http_fail_redirect\": true"
		"},"
		"\"fetch_policy\": {"
			"\"endpoint\":"		"\"warmcat.com\","
			"\"port\":"		"443,"
			"\"protocol\":"		"\"h1\","
			"\"http_method\":"	"\"GET\","
			"\"http_url\":"		"\"policy/minimal-proxy-v4.2-v2.json\","
			"\"tls\":"		"true,"
			"\"opportunistic\":"	"true,"
			"\"retry\":"		"\"default\","
			"\"tls_trust_store\":"	"\"le_via_isrg\""
		"}}"
	"}"
;

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *context = lws_system_context_from_system_mgr(mgr);

	switch (target) {
	case LWS_SYSTATE_OPERATIONAL:
		if (current == LWS_SYSTATE_OPERATIONAL) {
			/*
			 * At this point we have DHCP, ntp, system auth token
			 * and we can reasonably create the proxy
			 */
			if (lws_ss_proxy_create(context, ibind, port)) {
				lwsl_err("%s: failed to create ss proxy\n",
						__func__);
				return -1;
			}
			test_result = 0; /* we passed if we started proxy */
		}
		break;
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, default_ss_policy);
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	/* connect to ssproxy via UDS by default, else via tcp with this port */
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_P].sw)))
		port = atoi(p);

	/* UDS "proxy.ss.lws" in abstract namespace, else this socket path;
	 * when -p given this can specify the network interface to bind to */
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_I].sw)))
		ibind = p;

	lwsl_user("LWS secure streams Proxy [-d<verb>]\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 1 + 26 + 1;

	info.connect_timeout_secs = 15; /* httpbin.org seems to need this depending on time of day */
	info.timeout_secs = 10;

	nl.name = "app";
	nl.notify_cb = app_system_state_nf;
	info.register_notifier_list = app_notifier_list;

	info.pt_serv_buf_size = (unsigned int)((6144 * 2) + 2048);
	info.max_http_header_data = (unsigned short)(6144 + 2048);

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_context_default_loop_run_destroy(cx);

	return lws_cmdline_passfail(argc, argv, test_result);
}
