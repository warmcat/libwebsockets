/*
 * lws-api-test-client-proxy-redirect
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws http client going through an http CONNECT proxy, or a SOCKS5
 * proxy, follows its origin's redirects to the origin, never to the proxy:
 *
 *  - a relative Location ("/echo") is on the origin the client asked for,
 *    by the name it asked for it by, on the origin's port
 *
 *  - an absolute Location naming the origin on another port goes to that
 *    port, through the proxy
 *
 * The origin is two lws server vhosts in this process, on two ports.  Each
 * answers /echo with the port it listens on and the Host: it was asked
 * for, which the client checks.  The client names the origin "localhost"
 * while the proxy is "127.0.0.1", so a request that was retargeted at the
 * proxy's address shows up with the wrong Host:, and one retargeted at the
 * proxy's port does not reach the origin at all.  The proxies are
 * api-test-ws-close's proxy-fixture.py, which speaks both http CONNECT and
 * SOCKS5 on one port.
 *
 * Raw clients go through the same proxies to a raw origin that speaks
 * first (a banner, as smtp does), on its own port, and with tls on another:
 * the raw-skt client must hear RAW_CONNECTED before any RAW_RX, over tls
 * when it asked for it, and every byte it (or a raw-proxy role client) is
 * given must be the origin's, never the proxy's reply.  It answers the
 * banner and must get the origin's answer back.
 *
 * The test fails if any case does not end with the right echo inside the
 * watchdog period.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define CASE_TIMEOUT_S	10

/* what the raw origin says first, and how it answers our reply to that */
#define RAW_BANNER	"220 raw origin\n"
#define RAW_PING	"ping\n"
#define RAW_PONG	"pong\n"

enum {
	K_HTTP,			/* an http client following redirects */
	K_RAW,			/* a raw-skt client */
	K_RAW_TLS,		/* a raw-skt client over tls */
	K_RAW_PROXY,		/* a raw-proxy role client */
};

static const struct pcase {
	const char	*name;
	const char	*vhost;		/* the client vhost: its proxy */
	const char	*path;
	char		port2;		/* the echo comes from the second port */
	char		kind;
} cases[] = {
	{ "http CONNECT proxy: relative redirect",
			"cli-hp",	"/redir-rel",	0, K_HTTP },
	{ "http CONNECT proxy: redirect to another port",
			"cli-hp",	"/redir-port",	1, K_HTTP },
	{ "http CONNECT proxy: raw-skt client",
			"cli-hp",	NULL,		0, K_RAW },
#if defined(LWS_WITH_TLS)
	{ "http CONNECT proxy: raw-skt client over tls",
			"cli-hp",	NULL,		0, K_RAW_TLS },
#endif
#if defined(LWS_ROLE_RAW_PROXY)
	{ "http CONNECT proxy: raw-proxy client",
			"cli-hp",	NULL,		0, K_RAW_PROXY },
#endif
#if defined(LWS_WITH_SOCKS5)
	{ "socks5: relative redirect",
			"cli-s5",	"/redir-rel",	0, K_HTTP },
	{ "socks5: redirect to another port",
			"cli-s5",	"/redir-port",	1, K_HTTP },
	{ "socks5: raw-skt client",
			"cli-s5",	NULL,		0, K_RAW },
#if defined(LWS_WITH_TLS)
	{ "socks5: raw-skt client over tls",
			"cli-s5",	NULL,		0, K_RAW_TLS },
#endif
#if defined(LWS_ROLE_RAW_PROXY)
	{ "socks5: raw-proxy client",
			"cli-s5",	NULL,		0, K_RAW_PROXY },
#endif
#endif
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int cur = -1, failures, port1 = 7690, port2 = 7691, port_raw = 7693,
	   port_raw_tls = 7694, status, done, raw_connected, raw_pinged;
static char redir_port[64], rx[128];
static size_t rx_len;

struct pss_srv {
	char			body[128];
	int			len;
};

struct pss_raw {
	char			rx[16];
	size_t			rx_len;
	char			answer;	/* the banner went, the pong is due */
};

/* ---- the origin ---- */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	const char *path = (const char *)in;
	char host[64];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (!strcmp(path, "/redir-rel")) {
			if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
					      (const unsigned char *)"/echo", 5,
					      &p, end) < 0)
				return -1;
			return lws_http_transaction_completed(wsi);
		}
		if (!strcmp(path, "/redir-port")) {
			if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
					      (const unsigned char *)redir_port,
					      (int)strlen(redir_port),
					      &p, end) < 0)
				return -1;
			return lws_http_transaction_completed(wsi);
		}
		if (strcmp(path, "/echo")) {
			lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
			return lws_http_transaction_completed(wsi);
		}

		if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) < 0)
			host[0] = '\0';
		pss->len = lws_snprintf(pss->body, sizeof(pss->body),
					"port=%d host=%s", lws_get_vhost_listen_port(
					lws_get_vhost(wsi)), host);
		lwsl_user("%s: origin: %s\n", __func__, pss->body);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						(lws_filepos_t)pss->len,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->len)
			break;
		memcpy(start, pss->body, (size_t)pss->len);
		if (lws_write(wsi, start, (size_t)pss->len,
			      LWS_WRITE_HTTP_FINAL) != pss->len)
			return 1;
		pss->len = 0;

		return lws_http_transaction_completed(wsi);

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The raw origin speaks first, with its banner, and answers RAW_PING with
 * RAW_PONG
 */

static int
callback_raw_origin(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct pss_raw *pss = (struct pss_raw *)user;
	uint8_t buf[LWS_PRE + 32];
	const char *say;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_RX:
		n = len;
		if (n > sizeof(pss->rx) - pss->rx_len)
			n = sizeof(pss->rx) - pss->rx_len;
		memcpy(pss->rx + pss->rx_len, in, n);
		pss->rx_len += n;
		if (pss->rx_len == strlen(RAW_PING) &&
		    !memcmp(pss->rx, RAW_PING, pss->rx_len))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		say = pss->answer ? RAW_PONG : RAW_BANNER;
		n = strlen(say);
		memcpy(buf + LWS_PRE, say, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) != (int)n)
			return -1;
		pss->answer = 1;
		break;

	default:
		break;
	}

	return 0;
}

/* ---- the client ---- */

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_end(const char *why)
{
	if (done)
		return;
	done = 1;
	lws_sul_cancel(&sul_watchdog);

	lwsl_user("--- case %d: %s: %s%s%s ---\n", cur, cases[cur].name,
		  why ? "FAIL" : "PASS", why ? ": " : "", why ? why : "");
	if (why)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
case_check(void)
{
	char want[64];

	if (status != HTTP_STATUS_OK) {
		case_end("no 200 from the origin");
		return;
	}

	/* the origin, asked by the name the client used, on the right port */
	lws_snprintf(want, sizeof(want), "port=%d host=localhost",
		     cases[cur].port2 ? port2 : port1);

	rx[rx_len] = '\0';
	lwsl_user("%s: client: got \"%s\", want \"%s\"\n", __func__, rx, want);

	if (strncmp(rx, want, strlen(want)) ||
	    (rx[strlen(want)] && rx[strlen(want)] != ':'))
		case_end("the redirect was not followed to the origin");
	else
		case_end(NULL);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = &buf[LWS_PRE];
	int lenx = sizeof(buf) - LWS_PRE;

	/* a connection from an earlier case going away is not this case's */
	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(cur + 1))
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		case_end("connection error");
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len > sizeof(rx) - 1 - rx_len)
			len = sizeof(rx) - 1 - rx_len;
		memcpy(rx + rx_len, in, len);
		rx_len += len;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		case_check();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		case_end("closed before completing");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * A raw client, of the raw-skt role or the raw-proxy one: the first bytes it
 * is given must be the origin's banner, never anything of the proxy's, and a
 * raw-skt one must have been told it is connected (over tls, when it asked
 * for that) before it is given any.  It answers the banner, and passes when
 * the origin's answer comes back.
 */
static int
callback_cli_raw(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 16];
	size_t n;

	/* a connection from an earlier case going away is not this case's */
	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(cur + 1))
		return 0;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		case_end("connection error");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		if (rx_len) {
			case_end("RAW_RX before RAW_CONNECTED");
			return -1;
		}
		if (cases[cur].kind == K_RAW_TLS && !lws_is_ssl(wsi)) {
			case_end("connected without the tls it asked for");
			return -1;
		}
		raw_connected = 1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!raw_connected) {
			case_end("RAW_RX before RAW_CONNECTED");
			return -1;
		}
		/* fallthru */
	case LWS_CALLBACK_RAW_PROXY_CLI_RX:
		n = len;
		if (n > sizeof(rx) - 1 - rx_len)
			n = sizeof(rx) - 1 - rx_len;
		memcpy(rx + rx_len, in, n);
		rx_len += n;
		rx[rx_len] = '\0';

		/* all of it the origin's, never the proxy's reply */
		if (strncmp(rx, RAW_BANNER RAW_PONG, rx_len)) {
			lwsl_user("%s: client: got \"%s\"\n", __func__, rx);
			case_end("the client was given bytes not the origin's");
			return -1;
		}
		if (rx_len == strlen(RAW_BANNER) && !raw_pinged) {
			raw_pinged = 1;
			lws_callback_on_writable(wsi);
		}
		if (rx_len == strlen(RAW_BANNER RAW_PONG)) {
			case_end(NULL);
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
	case LWS_CALLBACK_RAW_PROXY_CLI_WRITEABLE:
		if (!raw_pinged)
			break;
		n = strlen(RAW_PING);
		memcpy(buf + LWS_PRE, RAW_PING, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) != (int)n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
	case LWS_CALLBACK_RAW_PROXY_CLI_CLOSE:
		case_end("closed before completing");
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_raw_origin[] = {
	{ "raw-origin", callback_raw_origin, sizeof(struct pss_raw),
	  0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	{ "cli-raw", callback_cli_raw, 0, 0, 0, NULL, 0 },
#if defined(LWS_ROLE_RAW_PROXY)
	/* a client of the raw-proxy role is bound to the one of this name */
	{ "raw-proxy", callback_cli_raw, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_end("watchdog: case did not complete");
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("=== case %d: %s ===\n", cur, cases[cur].name);
	done = 0;
	status = 0;
	rx_len = 0;
	raw_connected = 0;
	raw_pinged = 0;

	memset(&i, 0, sizeof(i));
	i.context	= context;
	i.vhost		= lws_get_vhost_by_name(context, cases[cur].vhost);
	i.address	= "localhost";
	i.host		= i.address;
	i.origin	= i.address;
	i.port		= port1;
	i.path		= cases[cur].path;
	i.method	= "GET";
	i.protocol	= protocols_cli[0].name;
	i.opaque_user_data = (void *)(intptr_t)(cur + 1);

	switch (cases[cur].kind) {
	case K_RAW_TLS:
		i.port		= port_raw_tls;
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		/* fallthru */
	case K_RAW:
		if (cases[cur].kind == K_RAW)
			i.port	= port_raw;
		i.method	= "RAW";
		i.path		= "/";
		i.local_protocol_name = "cli-raw";
		i.protocol	= i.local_protocol_name;
		break;
	case K_RAW_PROXY:
		i.port		= port_raw;
		i.method	= "RAW";
		i.path		= "/";
		i.local_protocol_name = "raw-proxy";
		i.protocol	= i.local_protocol_name;
		break;
	default:
		break;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	if (!i.vhost || !lws_client_connect_via_info(&i))
		case_end("connect failed");
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char proxy_host[64], socks[80];
	unsigned int proxy_port = 0;
	const char *p, *c;
#if defined(LWS_WITH_TLS)
	const char *cert = "localhost-100y.cert", *key = "localhost-100y.key";
#endif
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread = 0;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port2")))
		port2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-raw")))
		port_raw = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-raw-tls")))
		port_raw_tls = atoi(p);
#if defined(LWS_WITH_TLS)
	if ((p = lws_cmdline_option(argc, argv, "--cert")))
		cert = p;
	if ((p = lws_cmdline_option(argc, argv, "--key")))
		key = p;
#endif

	p = lws_cmdline_option(argc, argv, "--proxy");
	c = p ? strchr(p, ':') : NULL;
	if (!c || (size_t)(c - p) >= sizeof(proxy_host)) {
		lwsl_err("--proxy host:port is required\n");
		return 1;
	}
	lws_strnncpy(proxy_host, p, (size_t)(c - p), sizeof(proxy_host));
	proxy_port = (unsigned int)atoi(c + 1);
	lws_strncpy(socks, p, sizeof(socks));

	lws_snprintf(redir_port, sizeof(redir_port),
		     "http://localhost:%d/echo", port2);

	lwsl_user("LWS API selftest: client redirects through a proxy\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
#if defined(LWS_WITH_TLS)
	/* the raw client over tls needs its vhost's client tls */
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the origin, on two ports */

	info.protocols = protocols_srv;
	info.port = port1;
	info.vhost_name = "origin";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.port = port2;
	info.vhost_name = "origin2";
	if (!lws_create_vhost(context, &info))
		goto bail;

	/* the raw origin, plaintext and over tls */

	info.protocols = protocols_raw_origin;
	info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "raw-origin";
	info.port = port_raw;
	info.vhost_name = "raw-origin";
	if (!lws_create_vhost(context, &info))
		goto bail;
#if defined(LWS_WITH_TLS)
	info.port = port_raw_tls;
	info.vhost_name = "raw-origin-tls";
	info.ssl_cert_filepath = cert;
	info.ssl_private_key_filepath = key;
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
#endif
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;

	/* the clients, one through each kind of proxy */

	info.protocols = protocols_cli;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli-hp";
	info.http_proxy_address = proxy_host;
	info.http_proxy_port = proxy_port;
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.http_proxy_address = NULL;
	info.http_proxy_port = 0;

#if defined(LWS_WITH_SOCKS5)
	info.vhost_name = "cli-s5";
	info.socks_proxy_address = socks;
	if (!lws_create_vhost(context, &info))
		goto bail;
#endif

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0 && cur < (int)LWS_ARRAY_SIZE(cases))
		n = lws_service(context, 0);

	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  failures ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(cases));

	return !!failures;

bail:
	lwsl_err("vhost creation failed\n");
	lws_context_destroy(context);

	return 1;
}
