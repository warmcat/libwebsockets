/*
 * lws-api-test-ss-proxy-tcp
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An SS proxy listening on tcp has no client authentication: anybody who
 * can connect to it can use the proxy's policy and credentials.  So lws
 * listens on loopback when it isn't told where to bind, and refuses a bind
 * that is not loopback unless .ss_proxy_tcp_allow_remote is set.  Each case
 * runs in a context of its own:
 *
 *  - "default": the proxy is created with a port and no bind.  Its listener
 *    must be bound to a loopback address, and a client must be able to
 *    connect to it there.
 *
 *  - "refused": the proxy is created with a port and the wildcard address.
 *    It must fail.
 *
 *  - "allowed": as "refused", but with .ss_proxy_tcp_allow_remote set.  It
 *    must listen on the wildcard address.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

enum {
	LWS_SW_PORT,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "--port",	"tcp port for the proxy to listen on" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

#if defined(LWS_WITH_IPV4)
#define WILDCARD "0.0.0.0"
#else
#define WILDCARD "::"
#endif

static const char * const policy =
	"{"
		"\"release\":\"01234567\","
		"\"product\":\"myproduct\","
		"\"schema-version\":1,"
		"\"retry\":[{\"default\":{"
			"\"backoff\":[1000,2000,3000],"
			"\"conceal\":3,"
			"\"jitterpc\":20,"
			"\"svalidping\":30,"
			"\"svalidhup\":35"
		"}}],"
		"\"s\":["
			"{\"sink\":{"
				"\"local_sink\":true,"
				"\"protocol\":\"raw\""
			"}}"
		"]"
	"}";

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_timeout;
static int connected, timed_out;

static int
ads_is_loopback(const char *ads)
{
	static const uint8_t lo6[] = { 0, 0, 0, 0, 0, 0, 0, 0,
				       0, 0, 0, 0, 0, 0, 0, 1 };
	uint8_t a[16];

	switch (lws_parse_numeric_address(ads, a, sizeof(a))) {
	case 4:
		return a[0] == 127;
	case 16:
		return !memcmp(a, lo6, sizeof(lo6));
	default:
		return 0;
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection to proxy failed: %s\n", __func__,
			 in ? (const char *)in : "?");
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_user("%s: connected to proxy\n", __func__);
		connected = 1;
		lws_cancel_service(lws_get_context(wsi));
		/* the connection goes when the context is destroyed */
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "sspxt-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_cancel_service(cx);
}

/*
 * Create a context, and in it the proxy listening on port, bound to bind.
 * Returns the proxy's vhost, or NULL if the proxy could not be created.
 */

static struct lws_vhost *
proxy_start(int port, const char *bind, uint8_t allow_remote)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;

	lws_context_info_defaults(&info, policy);
	info.fd_limit_per_thread	= 0;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.ss_proxy_tcp_allow_remote	= allow_remote;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: lws init failed\n", __func__);
		return NULL;
	}

	if (lws_ss_proxy_create(cx, bind, port))
		return NULL;

	vh = lws_get_vhost_by_name(cx, "ssproxy");
	if (!vh)
		lwsl_err("%s: no proxy vhost\n", __func__);

	return vh;
}

static void
proxy_stop(void)
{
	lws_context_destroy(cx);
	cx = NULL;
}

/* the proxy must be listening on loopback, and reachable there */

static int
case_default(int port)
{
	struct lws_client_connect_info i;
	struct lws_context_creation_info info;
	struct lws_vhost *vh = proxy_start(port, NULL, 0), *vh_cli;
	const char *iface;
	int ret = 1;

	if (!vh)
		goto bail;

	iface = lws_get_vhost_iface(vh);
	lwsl_user("%s: proxy listening on %s, port %d\n", __func__,
		  iface ? iface : "(all interfaces)", port);
	if (!iface || !ads_is_loopback(iface)) {
		lwsl_err("%s: proxy listener is not loopback-only\n", __func__);
		goto bail;
	}

	memset(&info, 0, sizeof(info));
	info.vhost_name	= "sspxt-cli";
	info.port	= CONTEXT_PORT_NO_LISTEN;
	info.protocols	= protocols_cli;
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli) {
		lwsl_err("%s: client vhost creation failed\n", __func__);
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= iface;
	i.port			= port;
	i.host			= i.address;
	i.origin		= i.address;
	i.method		= "RAW";
	i.local_protocol_name	= "sspxt-cli";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: client connect failed\n", __func__);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, sul_timeout_cb,
			 5 * LWS_US_PER_SEC);

	while (!connected && !timed_out)
		if (lws_service(cx, 0) < 0)
			break;

	lws_sul_cancel(&sul_timeout);

	if (connected)
		ret = 0;
	else
		lwsl_err("%s: client did not reach the proxy\n", __func__);

bail:
	proxy_stop();

	return ret;
}

/* a wildcard bind must fail without the opt-in */

static int
case_refused(int port)
{
	struct lws_vhost *vh = proxy_start(port, WILDCARD, 0);

	proxy_stop();

	if (vh) {
		lwsl_err("%s: proxy listening on %s without opt-in\n", __func__,
			 WILDCARD);
		return 1;
	}

	return 0;
}

/* ... and work with it */

static int
case_allowed(int port)
{
	struct lws_vhost *vh = proxy_start(port, WILDCARD, 1);
	const char *iface = vh ? lws_get_vhost_iface(vh) : NULL;
	int ret = !iface || strcmp(iface, WILDCARD);

	if (ret)
		lwsl_err("%s: proxy not listening on %s with opt-in\n",
			 __func__, WILDCARD);

	proxy_stop();

	return ret;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int port, fails = 0;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	/* only for the builtin switches, eg, -d */
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API Test - SS proxy tcp\n");

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw);
	port = p ? atoi(p) : 0;
	if (port <= 0 || port > 65535) {
		lwsl_err("%s: --port <1..65535> is required\n", __func__);
		return 1;
	}

	if (case_default(port)) {
		lwsl_err("case default: FAIL\n");
		fails++;
	}
	if (case_refused(port)) {
		lwsl_err("case refused: FAIL\n");
		fails++;
	}
	if (case_allowed(port)) {
		lwsl_err("case allowed: FAIL\n");
		fails++;
	}

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "OK");

	return !!fails;
}
