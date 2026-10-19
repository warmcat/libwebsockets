/*
 * lws-api-test-client-final-callback
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Every client connection gets one last callback on its own protocol, and
 * only one: LWS_CALLBACK_CLIENT_CONNECTION_ERROR if it never connected,
 * else its CLOSED.  That is true when the context is destroyed under it as
 * well, which is what this checks.  A protocol keeping a client's wsi
 * pointer (eg, through i.pwsi) learns from it that the wsi is gone, so it
 * cannot touch the freed wsi later, eg, in its PROTOCOL_DESTROY.
 *
 * In one context, a "silent" raw server takes connections and never
 * answers, and a ws server accepts ws connections.  The client protocol,
 * which is not the client vhost's protocols[0], starts:
 *
 *  - ws-unanswered:   a ws client of the silent server, waiting for the
 *                     upgrade's answer: it never connected
 *  - http-unanswered: an http GET to the silent server, waiting for the
 *                     response: it connected
 *  - tls-handshake:   a tls client of the silent server, in its handshake:
 *                     it never connected
 *  - ws-established:  a ws client of the ws server, established
 *  - unroutable:      a client of 192.0.2.1 (TEST-NET-1): still connecting
 *                     at the destroy where that address is routed, else
 *                     refused before it
 *
 * Once they are all in those states, the context is destroyed.  Each must
 * have had exactly one final callback, of the kind it should, by the time
 * the client protocol's PROTOCOL_DESTROY comes, and none may still be held
 * there.  The first final callback during the destroy also tries to connect
 * again, as a naive retry would: lws must refuse it, since a connection
 * made there could restart the destroy's close loop forever.
 *
 * ctest runs it on the default event loop and on libuv, which finishes the
 * closes later, from its own close callbacks.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	FCB_SW_PORT_SILENT,
	FCB_SW_PORT_WS,
	FCB_SW_SERVER,
	FCB_SW_HELP,
};

static const struct lws_switches switches[] = {
	[FCB_SW_PORT_SILENT]	= { "--port-silent", "Port of the silent server "
						     "(default 7681)" },
	[FCB_SW_PORT_WS]	= { "--port-ws", "Port of the ws server "
						 "(default 7682)" },
	[FCB_SW_SERVER]		= { "--server", "Address the clients connect "
						"to (default localhost)" },
	[FCB_SW_HELP]		= { "--help", "Show this help information" },
};

/* how long the clients have to reach their states before the destroy */
#define FCB_DEADLINE_US		(10 * LWS_US_PER_SEC)

enum fcb_final {
	FCB_FINAL_CCE,
	FCB_FINAL_CLOSED,
};

enum fcb_target {
	FCB_TGT_SILENT,
	FCB_TGT_WS,
	FCB_TGT_UNROUTABLE,
};

typedef struct fcb_client {
	const char		*name;
	char			target;		/* FCB_TGT_ */
	char			ws;		/* a ws upgrade, else a GET */
	char			tls;
	char			expect;		/* FCB_FINAL_ */

	/* results */
	struct lws		*wsi;		/* held until its final cb */
	int			cce;
	int			closed;
} fcb_client_t;

static fcb_client_t clients[] = {
	{ .name = "ws-unanswered", .target = FCB_TGT_SILENT, .ws = 1,
	  .expect = FCB_FINAL_CCE },
	{ .name = "http-unanswered", .target = FCB_TGT_SILENT,
	  .expect = FCB_FINAL_CLOSED },
#if defined(LWS_WITH_TLS)
	{ .name = "tls-handshake", .target = FCB_TGT_SILENT, .tls = 1,
	  .expect = FCB_FINAL_CCE },
#endif
	{ .name = "ws-established", .target = FCB_TGT_WS, .ws = 1,
	  .expect = FCB_FINAL_CLOSED },
	{ .name = "unroutable", .target = FCB_TGT_UNROUTABLE,
	  .expect = FCB_FINAL_CCE },
};

static struct lws_context *cx;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_start, sul_check;
static const char *server_ads = "localhost";
static int port_silent = 7681, port_ws = 7682;
static int failed, silent_heard, ws_established, retry_tried, retry_refused,
	   protocol_destroyed;
static lws_usec_t deadline;

/*
 * The silent server: it takes the connection, reads what it is sent, and
 * never answers.  It counts connections that sent it something.
 */

struct pss_silent {
	char			heard;
};

static int
callback_silent(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct pss_silent *pss = (struct pss_silent *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss && !pss->heard) {
			pss->heard = 1;
			silent_heard++;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int
callback_ws_srv(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	return 0;
}

/* the clients */

static int
fcb_connect(fcb_client_t *c)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= server_ads;
	i.port			= c->target == FCB_TGT_WS ? port_ws : port_silent;
	if (c->target == FCB_TGT_UNROUTABLE) {
		i.address	= "192.0.2.1";
		i.port		= 7;
	}
	i.host			= i.address;
	i.origin		= i.address;
	i.path			= "/";
	i.local_protocol_name	= "fcb-cli";
	i.opaque_user_data	= c;
	i.pwsi			= &c->wsi;

	if (c->ws)
		i.protocol	= "fcb-ws";
	else
		i.method	= "GET";

	if (c->tls) {
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		i.alpn		= "http/1.1";
	}

	return !lws_client_connect_via_info(&i);
}

static void
fcb_final(struct lws *wsi, int is_cce)
{
	fcb_client_t *c = (fcb_client_t *)lws_get_opaque_user_data(wsi);

	if (!c)
		return;

	if (c->wsi && c->wsi != wsi) {
		lwsl_err("%s: %s: final cb on another wsi\n", __func__,
			 c->name);
		failed = 1;
	}

	lwsl_user("%s: %s: %s%s\n", __func__, c->name,
		  is_cce ? "CLIENT_CONNECTION_ERROR" : "CLOSED",
		  lws_context_is_being_destroyed(cx) ? " (context destroy)" :
						       "");
	if (is_cce)
		c->cce++;
	else
		c->closed++;

	/* it's gone, forget it */
	c->wsi = NULL;
	lws_set_opaque_user_data(wsi, NULL);

	if (lws_context_is_being_destroyed(cx) && !retry_tried) {
		/*
		 * A naive retry.  There is nothing to retry for, and a
		 * connection made now could keep the destroy's close loop
		 * going forever: lws must refuse it
		 */
		retry_tried = 1;
		retry_refused = fcb_connect(c);
		c->wsi = NULL;
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	fcb_client_t *c = (fcb_client_t *)lws_get_opaque_user_data(wsi);
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		fcb_final(wsi, 1);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		if (c && c->target == FCB_TGT_WS)
			ws_established = 1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* a ws upgrade's answer comes here too */
		if (c && c->target == FCB_TGT_SILENT) {
			lwsl_err("%s: %s: the silent server answered\n",
				 __func__, c->name);
			failed = 1;
		}
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		fcb_final(wsi, 0);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		/*
		 * A protocol holding a client wsi here would touch it, eg, to
		 * clear its opaque or set a timeout: it must not be holding
		 * any by now
		 */
		protocol_destroyed = 1;
		for (n = 0; n < LWS_ARRAY_SIZE(clients); n++)
			if (clients[n].wsi) {
				lwsl_err("%s: %s: still held at "
					 "PROTOCOL_DESTROY\n", __func__,
					 clients[n].name);
				failed = 1;
			}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_silent[] = {
	{ "fcb-silent", callback_silent, sizeof(struct pss_silent), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_ws[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "fcb-ws", callback_ws_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* the client protocol is deliberately not the client vhost's protocols[0] */
static const struct lws_protocols protocols_cli[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "fcb-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
check_cb(lws_sorted_usec_list_t *sul)
{
	int silent = 0;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(clients); n++)
		if (clients[n].target == FCB_TGT_SILENT)
			silent++;

	if (silent_heard == silent && ws_established) {
		lwsl_user("%s: all clients in place, destroying the context\n",
			  __func__);
		lws_default_loop_exit(cx);
		return;
	}

	if (lws_now_usecs() > deadline) {
		lwsl_err("%s: clients not in place: silent server heard %d of "
			 "%d, ws %sestablished\n", __func__, silent_heard,
			 silent, ws_established ? "" : "not ");
		failed = 1;
		lws_default_loop_exit(cx);
		return;
	}

	lws_sul_schedule(cx, 0, &sul_check, check_cb, 50 * LWS_US_PER_MS);
}

static void
start_cb(lws_sorted_usec_list_t *sul)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(clients); n++)
		if (fcb_connect(&clients[n]) && !clients[n].cce) {
			lwsl_err("%s: %s: connect failed\n", __func__,
				 clients[n].name);
			failed = 1;
		}

	deadline = lws_now_usecs() + FCB_DEADLINE_US;
	lws_sul_schedule(cx, 0, &sul_check, check_cb, 50 * LWS_US_PER_MS);
}

static void
sigint_handler(int sig)
{
	failed = 1;
	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	size_t n;
	int result;

	if (lws_cmdline_option(argc, argv, switches[FCB_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv,
				    switches[FCB_SW_PORT_SILENT].sw)))
		port_silent = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[FCB_SW_PORT_WS].sw)))
		port_ws = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[FCB_SW_SERVER].sw)))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: client final callback at context "
		  "destroy\n");

	/* keep an event library chosen on the commandline, eg, --uv */
	info.options		|= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
				   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port		= CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * The client protocol must see PROTOCOL_DESTROY, which only comes
	 * for protocols the vhost instantiated: in a plugins build, that is
	 * not all of them by default
	 */
	info.options		|= LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS;

	/* the silent server: raw, it never answers */

	info.options			|=
			LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.vhost_name			= "silent";
	info.port			= port_silent;
	info.protocols			= protocols_silent;
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "fcb-silent";
	if (!lws_create_vhost(cx, &info))
		goto bail;

	/* the ws server */

	info.vhost_name			= "ws";
	info.port			= port_ws;
	info.protocols			= protocols_ws;
	info.options			&= ~(uint64_t)
			LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role		= NULL;
	info.listen_accept_protocol	= NULL;
	if (!lws_create_vhost(cx, &info))
		goto bail;

	/* the clients' vhost */

	info.vhost_name			= "cli";
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols_cli;
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(cx, 0, &sul_start, start_cb, 1);

	lws_context_default_loop_run_destroy(cx);

	result = failed;

	for (n = 0; n < LWS_ARRAY_SIZE(clients); n++) {
		fcb_client_t *c = &clients[n];
		int ok = c->cce + c->closed == 1 &&
			 (c->expect == FCB_FINAL_CCE) == !!c->cce;

		lwsl_user("%s: %s: CLIENT_CONNECTION_ERROR %d, CLOSED %d: %s\n",
			  __func__, c->name, c->cce, c->closed,
			  ok ? "ok" : "FAIL");
		if (!ok)
			result = 1;
	}

	if (!protocol_destroyed) {
		lwsl_err("%s: no PROTOCOL_DESTROY\n", __func__);
		result = 1;
	}
	if (!retry_tried || !retry_refused) {
		lwsl_err("%s: a connect during the destroy was %s\n", __func__,
			 retry_tried ? "allowed" : "not tried");
		result = 1;
	}

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;

bail:
	lwsl_err("%s: vhost creation failed\n", __func__);
	lws_context_destroy(cx);

	return 1;
}
