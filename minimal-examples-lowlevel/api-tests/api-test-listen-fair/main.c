/*
 * lws-api-test-listen-fair
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A listen socket with a backlog of connections must not keep the event
 * loop to itself while it adopts them, when adopting each one is costly:
 * the connections it already has must be served meanwhile.
 *
 * Adopting a tls connection is costly on a slow cpu: the server's first
 * step of the handshake, done as it is adopted, signs for it, which took
 * ~1.5s on a riscv64 board with mbedtls 2.28.  With 8 connections in the
 * backlog, adopting them one after another held the loop for 12s, while
 * the first one's next handshake message sat unread and its deadline for
 * its request (the vhost's timeout_secs_ah_idle, 10s) ran out.
 *
 * Here the cost is LWS_CALLBACK_FILTER_NETWORK_CONNECTION, which lws calls
 * for every connection it accepts, before adopting it, keeping the cpu
 * busy for LF_ADOPT_MS, so no tls is needed.  A raw client opens LF_CONNS
 * connections at once and sends a GET on each, to a vhost allowing
 * LF_AH_IDLE_S for each request: much less than adopting them all takes.
 * Every GET must be answered.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LF_CONNS		12
#define LF_ADOPT_MS		250	/* LF_CONNS of these is 3s */
#define LF_AH_IDLE_S		1
#define LF_DEADLINE_S		20

static struct lws_context *cx;
static struct lws_vhost *vh_cli, *vh_srv;
static lws_sorted_usec_list_t sul_start, sul_deadline;
static const char *server = "localhost";
static int fails, finished, answered, ended, adopted;

static void
lf_end(void)
{
	if (++ended == LF_CONNS) {
		finished = 1;
		lws_cancel_service(cx);
	}
}

static int
lf_srv_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	uint8_t hb[LWS_PRE + 256], *start = &hb[LWS_PRE], *p = start,
		*end = &hb[sizeof(hb) - 1];
	lws_usec_t t;

	switch (reason) {
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		/* what a costly adoption costs the loop */
		t = lws_now_usecs();
		while (lws_now_usecs() - t < LF_ADOPT_MS * LWS_US_PER_MS)
			;
		adopted++;
		return 0;

	case LWS_CALLBACK_HTTP:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 0, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the client: raw connections each sending one GET */

static int
lf_cli_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	static const char get[] = "GET / HTTP/1.1\x0d\x0aHost: lf\x0d\x0a"
				  "\x0d\x0a";
	int idx = (int)(intptr_t)lws_get_opaque_user_data(wsi);
	uint8_t tx[LWS_PRE + sizeof(get)];

	(void)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		memcpy(tx + LWS_PRE, get, sizeof(get) - 1);
		if (lws_write(wsi, tx + LWS_PRE, sizeof(get) - 1,
			      LWS_WRITE_RAW) != (int)sizeof(get) - 1)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len >= 12 && !strncmp((const char *)in, "HTTP/1.1 200", 12))
			answered++;
		else {
			lwsl_err("  FAIL: connection %d: not answered 200\n",
				 idx);
			fails++;
		}
		/* it ends at the close */
		return -1;

	case LWS_CALLBACK_RAW_CLOSE:
		lf_end();
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("  FAIL: connection %d: %s\n", idx,
			 in ? (const char *)in : "connection error");
		fails++;
		lf_end();
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols lf_srv_protocols[] = {
	{ "http", lf_srv_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols lf_cli_protocols[] = {
	{ "lf-cli", lf_cli_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
lf_start(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	int n;

	(void)sul;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= server;
	i.host			= server;
	i.port			= lws_get_vhost_listen_port(vh_srv);
	i.method		= "RAW";
	i.protocol		= lf_cli_protocols[0].name;
	i.local_protocol_name	= lf_cli_protocols[0].name;

	for (n = 0; n < LF_CONNS; n++) {
		i.opaque_user_data = (void *)(intptr_t)n;
		if (!lws_client_connect_via_info(&i)) {
			lwsl_err("  FAIL: connection %d: connect failed\n", n);
			fails++;
			lf_end();
		}
	}
}

static void
lf_deadline(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	lwsl_err("  FAIL: not finished in %ds: %d adopted, %d ended\n",
		 LF_DEADLINE_S, adopted, ended);
	fails++;
	finished = 1;
}

static void
sigint_handler(int sig)
{
	(void)sig;
	finished = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_usec_t t0;
	const char *p;
	int m = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: listen socket fair to other connections\n");

	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port			= 0;
	info.protocols			= lf_srv_protocols;
	info.vhost_name			= "lf-srv";
	info.timeout_secs_ah_idle	= LF_AH_IDLE_S;
	vh_srv = lws_create_vhost(cx, &info);

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= lf_cli_protocols;
	info.vhost_name			= "lf-cli";
	info.timeout_secs_ah_idle	= 0;
	vh_cli = lws_create_vhost(cx, &info);

	t0 = lws_now_usecs();

	if (!vh_srv || !vh_cli) {
		lwsl_err("vhost creation failed\n");
		fails++;
	} else {
		lws_sul_schedule(cx, 0, &sul_start, lf_start, 1);
		lws_sul_schedule(cx, 0, &sul_deadline, lf_deadline,
				 LF_DEADLINE_S * LWS_US_PER_SEC);

		while (m >= 0 && !finished)
			m = lws_service(cx, 0);
	}

	lws_sul_cancel(&sul_start);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	if (answered != LF_CONNS) {
		lwsl_err("  FAIL: %d of %d requests answered\n", answered,
			 LF_CONNS);
		fails++;
	}

	lwsl_user("Completed: %s (%d answered, %d adopted, %dms)\n",
		  fails ? "FAIL" : "PASS", answered, adopted,
		  (int)((lws_now_usecs() - t0) / LWS_US_PER_MS));

	return !!fails;
}
