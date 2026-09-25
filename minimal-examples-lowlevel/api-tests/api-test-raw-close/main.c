/*
 * lws-api-test-raw-close
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises lws_raw_transaction_completed() on a raw socket server, with an
 * lws raw client on the other end in the same context.
 *
 * The server answers each accepted connection with a single write and then
 * says the transaction is completed.  When the write went out whole, that
 * closes the connection at once.  When it could only go out as a partial
 * (the accepted socket's send buffer is shrunk to make sure of it), the
 * close has to wait until the buffered remainder has drained, and the
 * client must still see every byte before the close arrives.
 *
 * The test fails if a case does not complete inside the watchdog period.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#if !defined(WIN32)
#include <sys/socket.h>
#endif

#define CASE_TIMEOUT_S	20
#define SMALL_SNDBUF	16384

struct xcase {
	const char	*name;
	size_t		len;		/* bytes the server writes at once */
	int		shrink;		/* shrink the accepted socket's sndbuf */
};

static const struct xcase cases[] = {
	{ "write fits, close at once",			100,	0 },
	{ "write goes partial, close after the drain",	600000,	1 },
};

/* client side view of the current case */

static struct {
	size_t		rx_len;
	uint32_t	rx_sum;
	int		connected;
	int		closed;
	int		error;
} cli;

/* server side, per connection */

struct pss_srv {
	int		wrote;
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result, cur = -1, failures, port = 7690, case_done, ncases;

/* with --socks host:port, the cases run again through a socks5 proxy */
static struct lws_vhost *vh_socks;

#define CASE(n) (&cases[(n) % (int)LWS_ARRAY_SIZE(cases)])
#define CASE_VIA_SOCKS(n) ((n) >= (int)LWS_ARRAY_SIZE(cases))

static uint8_t
pat(size_t i)
{
	return (uint8_t)(0x30 + ((i * 7) % 61));
}

static uint32_t
sum_pat(size_t len)
{
	uint32_t s = 0;
	size_t i;

	for (i = 0; i < len; i++)
		s = (s * 31u) + pat(i);

	return s;
}

static void next_case(lws_sorted_usec_list_t *sul);

static void
case_finish(int pass, const char *why)
{
	if (case_done)
		return;
	case_done = 1;
	lws_sul_cancel(&sul_watchdog);

	lwsl_user("--- case %d: %s: %s%s%s ---\n", cur, CASE(cur)->name,
		  pass ? "PASS" : "FAIL", why ? ": " : "", why ? why : "");
	if (!pass)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_case,
			 100 * LWS_US_PER_MS);
}

static void
case_evaluate(void)
{
	const struct xcase *c = CASE(cur);

	if (cli.error) {
		case_finish(0, "client connection error");
		return;
	}

	if (cli.rx_len != c->len || cli.rx_sum != sum_pat(c->len)) {
		lwsl_err("received %u bytes sum %08x, expected %u sum %08x\n",
			 (unsigned int)cli.rx_len, cli.rx_sum,
			 (unsigned int)c->len, sum_pat(c->len));
		case_finish(0, "client did not receive the whole write");
		return;
	}

	case_finish(1, NULL);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("case %d: watchdog: connected %d, closed %d, %u bytes\n",
		 cur, cli.connected, cli.closed, (unsigned int)cli.rx_len);
	case_finish(0, "timed out");
}

/* ---- server side ---- */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	static uint8_t wbuf[LWS_PRE + 600000];
	const struct xcase *c;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		if (cur < 0 || cur >= ncases)
			return -1;
		c = CASE(cur);
		lwsl_user("%s: server: adopted\n", __func__);
#if !defined(WIN32)
		if (c->shrink) {
			int sfd = lws_get_socket_fd(wsi);
			int sb = SMALL_SNDBUF;

			/* make the single write partial, deterministically */
			if (sfd >= 0 &&
			    setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &sb,
				       sizeof(sb)))
				lwsl_warn("%s: SO_SNDBUF failed\n", __func__);
		}
#endif
		memset(pss, 0, sizeof(*pss));
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->wrote || cur < 0 || cur >= ncases)
			break;
		c = CASE(cur);
		pss->wrote = 1;

		for (n = 0; n < c->len; n++)
			wbuf[LWS_PRE + n] = pat(n);

		if (lws_write(wsi, &wbuf[LWS_PRE], c->len, LWS_WRITE_RAW) !=
								(int)c->len) {
			lwsl_err("%s: server: write failed\n", __func__);
			return -1;
		}
		lwsl_user("%s: server: wrote %u, buffered %d\n", __func__,
			  (unsigned int)c->len,
			  lws_partial_buffered(wsi));

		/*
		 * We are done with him: close now, or once the partial that
		 * the write left behind has drained
		 */
		return lws_raw_transaction_completed(wsi);

	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_user("%s: server: closed\n", __func__);
		break;

	default:
		break;
	}

	return 0;
}

/* ---- client side ---- */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli.error = 1;
		case_evaluate();
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		cli.connected = 1;
		break;

	case LWS_CALLBACK_RAW_RX:
		for (n = 0; n < len; n++)
			cli.rx_sum = (cli.rx_sum * 31u) + ((const uint8_t *)in)[n];
		cli.rx_len += len;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_user("%s: client: closed after %u bytes\n", __func__,
			  (unsigned int)cli.rx_len);
		cli.closed = 1;
		case_evaluate();
		break;

	default:
		break;
	}

	return 0;
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;

	cur++;
	if (cur >= ncases) {
		result = !!failures;
		lwsl_user("Completed: %s (%d of %d cases failed)\n",
			  failures ? "FAIL" : "PASS", failures, ncases);
		lws_default_loop_exit(context);
		return;
	}

	c = CASE(cur);
	case_done = 0;
	memset(&cli, 0, sizeof(cli));

	lwsl_user("=== case %d: %s%s ===\n", cur, c->name,
		  CASE_VIA_SOCKS(cur) ? " (via socks5)" : "");

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.method		= "RAW";
	i.address		= "127.0.0.1";
	i.host			= i.address;
	i.port			= port;
	i.local_protocol_name	= "raw-drain-cli";
	if (CASE_VIA_SOCKS(cur))
		i.vhost		= vh_socks;

	if (!lws_client_connect_via_info(&i)) {
		case_finish(0, "could not start connection");
		return;
	}
}

static const struct lws_protocols protocols[] = {
	{ "raw-drain", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	{ "raw-drain-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	ncases = (int)LWS_ARRAY_SIZE(cases);

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: raw socket close after drain\n");

	info.port = port;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "raw-drain";

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

#if defined(LWS_WITH_SOCKS5)
	/*
	 * A raw client through socks5: the raw role's own path out of the
	 * socks handshake, which no other test reaches.  The proxy fixture
	 * is api-test-ws-close's proxy-fixture.py.
	 */
	if ((p = lws_cmdline_option(argc, argv, "--socks"))) {
		info.port = CONTEXT_PORT_NO_LISTEN;
		info.vhost_name = "cli-socks";
		info.socks_proxy_address = p;
		vh_socks = lws_create_vhost(context, &info);
		if (!vh_socks) {
			lwsl_err("Failed to create socks client vhost\n");
			return 1;
		}
		ncases *= 2;
	}
#endif

	result = 1;
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	lws_context_default_loop_run_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
