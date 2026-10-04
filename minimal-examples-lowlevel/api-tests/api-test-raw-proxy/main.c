/*
 * lws-api-test-raw-proxy
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The raw-proxy role's client side, in one process:
 *
 *  - protocol_lws_raw_proxy on a vhost accepting into the raw-proxy role,
 *    its "onward" a raw echo origin: a raw client connects to the proxy,
 *    the proxy's onward connection comes up, and what the client sends
 *    comes back to it from the origin through the proxy
 *
 *  - an app's own raw-proxy client, over tls (which the plugin never asks
 *    for), straight to the origin's tls vhost: its transport comes up after
 *    its tls handshake, and the origin echoes it
 *
 *  - a raw client sending plain text to a tls listener that allows it and
 *    falls back to its listen accept role and protocol: the connection
 *    leaves tls behind for raw, and the origin's protocol echoes it
 *
 * Each leg is done when its echo has come back.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_raw_proxy.c"

#define WATCHDOG_S		20

static int port_origin = 7681, port_origin_tls = 7682, port_proxy = 7683,
	   port_fallback = 7684, fails, done, leg = -1;
static struct lws_context *cx;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static const char *cert, *key;

static const char * const leg_names[] = {
	"raw client through the raw proxy",
	"an app's raw-proxy client over tls",
	"plain text to a tls listener falling back to raw",
};

static const char * const leg_msg[] = { "hello", "tls-hello", "plain-hello" };

/*
 * The origin: echoes what it is sent
 */

struct echo_pss {
	uint8_t		buf[LWS_PRE + 64];
	size_t		len;
};

static int
callback_raw_echo(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct echo_pss *pss = (struct echo_pss *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->len + len > sizeof(pss->buf) - LWS_PRE)
			return -1;
		memcpy(pss->buf + LWS_PRE + pss->len, in, len);
		pss->len += len;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->len &&
		    lws_write(wsi, pss->buf + LWS_PRE, pss->len,
			      LWS_WRITE_RAW) != (int)pss->len)
			return -1;
		pss->len = 0;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * The clients: send the leg's message once up, done when it comes back
 */

struct cli_pss {
	char		rx[64];
	size_t		rx_len;
};

static void
finish(void)
{
	if (done)
		return;
	done = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_default_loop_exit(cx);
}

static void
next_leg(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++leg == (int)LWS_ARRAY_SIZE(leg_names) || (leg && !(cert && key))) {
		finish();
		return;
	}

	lwsl_user("%s: leg %d: %s\n", __func__, leg, leg_names[leg]);

	memset(&i, 0, sizeof i);
	i.context		= cx;
	i.vhost			= vh_cli;
	i.method		= "RAW";
	i.address		= "127.0.0.1";
	i.host			= "127.0.0.1";
	i.origin		= "127.0.0.1";
	i.path			= "/";
	if (leg != 1) {
		/* a raw client, through the proxy, or plain to tls */
		i.port			= leg ? port_fallback : port_proxy;
		i.protocol		= "raw-cli";
		i.local_protocol_name	= "raw-cli";
	} else {
		/* our own raw-proxy client, over tls, to the origin */
		i.port			= port_origin_tls;
		i.protocol		= "raw-proxy";
		i.local_protocol_name	= "raw-proxy";
		i.ssl_connection	= LCCSCF_USE_SSL |
					  LCCSCF_ALLOW_SELFSIGNED |
					  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	}

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: leg %d: connect failed\n", __func__, leg);
		fails++;
		finish();
	}
}

static int
cli_rx(struct lws *wsi, struct cli_pss *pss, const void *in, size_t len)
{
	size_t want = strlen(leg_msg[leg]);

	if (pss->rx_len + len > sizeof(pss->rx))
		return -1;
	memcpy(pss->rx + pss->rx_len, in, len);
	pss->rx_len += len;

	if (pss->rx_len < want)
		return 0;

	if (pss->rx_len != want || memcmp(pss->rx, leg_msg[leg], want)) {
		lwsl_err("%s: leg %d: wrong echo\n", __func__, leg);
		lwsl_hexdump_err(pss->rx, pss->rx_len);
		fails++;
		finish();

		return -1;
	}

	lwsl_user("%s: leg %d: echoed\n", __func__, leg);
	/* the next leg once this one has closed */
	pss->rx_len = 0;

	return -1;
}

static int
cli_send(struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 64];
	size_t n = strlen(leg_msg[leg]);

	memcpy(buf + LWS_PRE, leg_msg[leg], n);

	return lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) != (int)n;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct cli_pss *pss = (struct cli_pss *)user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: leg %d: connection error: %s\n", __func__, leg,
			 in ? (const char *)in : "(null)");
		fails++;
		finish();
		break;

	/* the raw client of leg 0 */
	case LWS_CALLBACK_RAW_ADOPT:
		lws_callback_on_writable(wsi);
		break;
	case LWS_CALLBACK_RAW_WRITEABLE:
		return cli_send(wsi);
	case LWS_CALLBACK_RAW_RX:
		return cli_rx(wsi, pss, in, len);
	case LWS_CALLBACK_RAW_CLOSE:
		if (!done)
			lws_sul_schedule(cx, 0, &sul_next, next_leg, 1);
		break;

	/* our own raw-proxy client of leg 1 */
	case LWS_CALLBACK_RAW_PROXY_CLI_ADOPT:
		lws_callback_on_writable(wsi);
		break;
	case LWS_CALLBACK_RAW_PROXY_CLI_WRITEABLE:
		return cli_send(wsi);
	case LWS_CALLBACK_RAW_PROXY_CLI_RX:
		return cli_rx(wsi, pss, in, len);
	case LWS_CALLBACK_RAW_PROXY_CLI_CLOSE:
		if (!done)
			lws_sul_schedule(cx, 0, &sul_next, next_leg, 1);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_origin[] = {
	{ "raw-echo", callback_raw_echo, sizeof(struct echo_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_proxy[] = {
	LWS_PLUGIN_PROTOCOL_RAW_PROXY,
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "raw-cli", callback_cli, sizeof(struct cli_pss), 0, 0, NULL, 0 },
	{ "raw-proxy", callback_cli, sizeof(struct cli_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: leg %d timed out\n", __func__, leg);
	fails++;
	finish();
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_protocol_vhost_options pvo_onward = {
		NULL, NULL, "onward", NULL
	}, pvo = {
		NULL, &pvo_onward, "raw-proxy", ""
	};
	struct lws_context_creation_info info;
	char onward[64];
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have every end */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_origin = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-tls")))
		port_origin_tls = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-proxy")))
		port_proxy = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-fallback")))
		port_fallback = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	lwsl_user("LWS API selftest: raw proxy client side\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* the echo origin, in the clear and over tls */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "raw-echo";
	info.protocols = protocols_origin;
	info.vhost_name = "origin";
	info.port = port_origin;
	if (!lws_create_vhost(cx, &info))
		goto bail;
	if (cert && key) {
		info.vhost_name = "origin-tls";
		info.port = port_origin_tls;
		info.ssl_cert_filepath = cert;
		info.ssl_private_key_filepath = key;
		if (!lws_create_vhost(cx, &info))
			goto bail;

		/*
		 * a tls listener taking plain text too, which goes to its
		 * listen accept role and protocol
		 */
		info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT |
			LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG;
		info.vhost_name = "fallback-tls";
		info.port = port_fallback;
		if (!lws_create_vhost(cx, &info))
			goto bail;
		info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			       LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
		info.ssl_cert_filepath = NULL;
		info.ssl_private_key_filepath = NULL;
	}

	/* the proxy, accepting into the raw-proxy role, onward the origin */
	lws_snprintf(onward, sizeof(onward), "ipv4:127.0.0.1:%d", port_origin);
	pvo_onward.value = onward;
	info.listen_accept_role = "raw-proxy";
	info.listen_accept_protocol = "raw-proxy";
	info.protocols = protocols_proxy;
	info.pvo = &pvo;
	info.vhost_name = "proxy";
	info.port = port_proxy;
	if (!lws_create_vhost(cx, &info))
		goto bail;
	info.pvo = NULL;

	/* the clients */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.protocols = protocols_cli;
	info.vhost_name = "cli";
	info.port = CONTEXT_PORT_NO_LISTEN;
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 WATCHDOG_S * LWS_USEC_PER_SEC);
	lws_sul_schedule(cx, 0, &sul_next, next_leg, 1);

	while (n >= 0 && !done)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(cx);

	if (fails || !done) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
