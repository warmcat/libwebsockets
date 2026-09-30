/*
 * lws-api-test-ss-server-txn
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms what the metadata of a Secure Streams http server stream holds
 * when the user code hears LWSSSCS_SERVER_TXN, for several requests arriving
 * one after the other on the same keep-alive h1 connection (and so on the same
 * accepted stream).
 *
 *  - "path", "method" and "auth" come from the request itself, a URL argument
 *    with the same name can't replace them
 *
 *  - a URL argument fills metadata with no header association ("my_arg"),
 *    but not metadata the server emits as a response header ("mime")
 *
 *  - nothing a request provided survives into the next request's view
 *
 *  - a ws upgrade on the same connection after those transactions is
 *    accepted, and the accepted stream hears LWSSSCS_SERVER_UPGRADE
 *
 * The client is a raw socket in the same process, so we control exactly what
 * is sent on the connection.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_PORT,
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "-p",	"Port for the test server "
					"(default 7681)" },
	[LWS_SW_SERVER]	= { "--server",	"Address the client connects to "
					"(default localhost)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

/* what the server stream's metadata must hold at SERVER_TXN, NULL = unset */

typedef struct txn {
	const char		*name;
	const char		*request;

	const char		*path;
	const char		*method;
	const char		*auth;
	const char		*my_arg;
	char			upgrade;	/* ws upgrade, not an http txn */

	/* results */
	char			checked;
	char			responded;
} txn_t;

static txn_t txns[] = {
	{
		/* URL args named like the request-derived metadata */
		"urlargs",
		"GET /txn/one?path=/admin&method=POST&auth=Bearer%20fake"
			"&mime=text/evil&my_arg=hello HTTP/1.1\r\n"
		"Host: localhost\r\n"
		"Authorization: Bearer real\r\n"
		"\r\n",
		"/txn/one", "GET", "Bearer real", "hello", 0, 0, 0
	}, {
		/* nothing from the last request on this connection remains */
		"plain",
		"GET /txn/two HTTP/1.1\r\n"
		"Host: localhost\r\n"
		"\r\n",
		"/txn/two", "GET", NULL, NULL, 0, 0, 0
	}, {
		/* a ws upgrade after completed transactions */
		"upgrade",
		"GET /ws HTTP/1.1\r\n"
		"Host: localhost\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Protocol: txn-ws\r\n"
		"\r\n",
		NULL, NULL, NULL, NULL, 1, 0, 0
	},
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static struct lws_ss_handle *srv_template;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_timeout, sul_start;
static const char *server_ads = "localhost";
static unsigned int cur_txn;
static int port = 7681, failed;

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_default_loop_exit(context);
}

/*
 * The server side, one Secure Stream object per template or accepted stream
 */

typedef struct srv {
	struct lws_ss_handle	*ss;
	void			*opaque_data;

	char			sent;
} srv_t;

static int
srv_md_check(srv_t *m, const txn_t *t, const char *name, const char *want)
{
	const void *v;
	size_t len;

	if (lws_ss_get_metadata(m->ss, name, &v, &len)) {
		lwsl_err("%s: %s: no metadata %s\n", __func__, t->name, name);
		return 1;
	}

	if (!want) {
		if (!len)
			return 0;
	} else
		if (len == strlen(want) && !memcmp(v, want, len))
			return 0;

	lwsl_err("%s: %s: metadata %s: '%.*s', expected '%s'\n", __func__,
		 t->name, name, (int)len, len ? (const char *)v : "",
		 want ? want : "(unset)");

	return 1;
}

static lws_ss_state_return_t
srv_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
       int *flags)
{
	srv_t *m = (srv_t *)userobj;

	if (m->sent || *len < 2)
		return LWSSSSRET_TX_DONT_SEND;

	memcpy(buf, "ok", 2);
	*len = 2;
	*flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;
	m->sent = 1;

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
srv_state(void *userobj, void *sh, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	srv_t *m = (srv_t *)userobj;
	txn_t *t = &txns[cur_txn];
	const void *v;
	size_t len;

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	if (state == LWSSSCS_SERVER_UPGRADE) {
		if (cur_txn >= LWS_ARRAY_SIZE(txns) || !t->upgrade ||
		    t->checked) {
			lwsl_err("%s: unexpected upgrade\n", __func__);
			finish(1);

			return LWSSSSRET_DISCONNECT_ME;
		}
		t->checked = 1;

		return LWSSSSRET_OK;
	}

	if (state != LWSSSCS_SERVER_TXN)
		return LWSSSSRET_OK;

	if (cur_txn >= LWS_ARRAY_SIZE(txns) || t->upgrade || t->checked) {
		lwsl_err("%s: unexpected transaction\n", __func__);
		finish(1);

		return LWSSSSRET_DISCONNECT_ME;
	}

	t->checked = 1;

	if (srv_md_check(m, t, "path", t->path) ||
	    srv_md_check(m, t, "method", t->method) ||
	    srv_md_check(m, t, "auth", t->auth) ||
	    srv_md_check(m, t, "my_arg", t->my_arg))
		finish(1);

	/* the response header value is ours to choose, not the client's */

	if (!lws_ss_get_metadata(m->ss, "mime", &v, &len) && len &&
	    (len != 10 || memcmp(v, "text/plain", 10))) {
		lwsl_err("%s: %s: mime '%.*s' came from the request\n",
			 __func__, t->name, (int)len, (const char *)v);
		finish(1);
	}

	lws_ss_server_ack(m->ss, 0);
	if (lws_ss_set_metadata(m->ss, "mime", "text/plain", 10))
		return LWSSSSRET_DISCONNECT_ME;

	m->sent = 0;

	return lws_ss_request_tx_len(m->ss, 2);
}

static const lws_ss_info_t ssi_server = {
	.handle_offset			= offsetof(srv_t, ss),
	.opaque_user_data_offset	= offsetof(srv_t, opaque_data),
	.streamtype			= "txnsrv",
	.tx				= srv_tx,
	.state				= srv_state,
	.user_alloc			= sizeof(srv_t),
};

/*
 * The client side, a raw socket sending one request at a time on one
 * connection, the next when the previous one's response is complete
 */

typedef struct cli_pss {
	char			rx[2048];
	size_t			rx_len;
	char			sent;
} cli_pss_t;

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	cli_pss_t *pss = (cli_pss_t *)user;
	uint8_t buf[LWS_PRE + 512];
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		finish(1);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->sent || cur_txn >= LWS_ARRAY_SIZE(txns))
			break;

		lwsl_user("--- txn %s ---\n", txns[cur_txn].name);
		n = strlen(txns[cur_txn].request);
		if (n > sizeof(buf) - LWS_PRE)
			return -1;
		memcpy(buf + LWS_PRE, txns[cur_txn].request, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) != (int)n)
			return -1;
		pss->sent = 1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len > sizeof(pss->rx) - 1 - pss->rx_len) {
			lwsl_err("%s: response too large\n", __func__);
			finish(1);
			return -1;
		}
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;
		pss->rx[pss->rx_len] = '\0';

		/*
		 * The server's http response body is "ok", the upgrade
		 * response has no body
		 */

		if (!strstr(pss->rx, txns[cur_txn].upgrade ? "\r\n\r\n" :
							     "\r\n\r\nok"))
			break;

		if (strncmp(pss->rx, txns[cur_txn].upgrade ? "HTTP/1.1 101" :
							     "HTTP/1.1 200", 12)) {
			lwsl_err("%s: %s: unexpected response\n", __func__,
				 txns[cur_txn].name);
			finish(1);
			return -1;
		}

		txns[cur_txn].responded = 1;
		pss->rx_len = 0;
		pss->sent = 0;

		if (++cur_txn == LWS_ARRAY_SIZE(txns)) {
			finish(0);
			return -1;
		}

		/* the next request on the same connection */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (cur_txn < LWS_ARRAY_SIZE(txns)) {
			lwsl_err("%s: connection closed in txn %s\n", __func__,
				 txns[cur_txn].name);
			finish(1);
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_cli[] = {
	{ "txn-cli", callback_cli, sizeof(cli_pss_t), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
start_client(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.method		= "RAW";
	i.address		= server_ads;
	i.host			= server_ads;
	i.port			= port;
	i.local_protocol_name	= "txn-cli";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: client connect failed\n", __func__);
		finish(1);
	}
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	if (lws_ss_create(context, 0, &ssi_server, NULL, &srv_template,
			  NULL, NULL)) {
		lwsl_err("%s: failed to create server stream\n", __func__);
		finish(1);

		return -1;
	}

	/* start from the event loop, when the client vhost exists */
	lws_sul_schedule(context, 0, &sul_start, start_client, 1);

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout in txn %s ---\n",
		 cur_txn < LWS_ARRAY_SIZE(txns) ? txns[cur_txn].name : "(end)");
	finish(1);
}

static void
sigint_handler(int sig)
{
	finish(1);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char policy[1024];
	unsigned int n;
	const char *p;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: SS server transaction metadata\n");

	lws_snprintf(policy, sizeof(policy),
		"{\"release\":\"01234567\",\"product\":\"myproduct\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"default\":{\"backoff\":[1000,2000,3000],"
			"\"conceal\":3,\"jitterpc\":20,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"s\":[{\"txnsrv\":{"
			"\"server\":true,\"port\":%d,\"protocol\":\"h1\","
			"\"metadata\":[{\"mime\":\"Content-Type:\","
				"\"path\":\"\",\"method\":\"\",\"auth\":\"\","
				"\"my_arg\":\"\"}],"
			"\"ws_subprotocol\":\"txn-ws\","
			"\"tls\":false}}]}", port);

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;

	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.register_notifier_list	= app_notifier_list;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the raw client vhost; the server vhost comes from the policy */

	info.vhost_name	= "cli";
	info.protocols	= protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		lws_context_destroy(context);
		return 1;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	for (n = 0; n < LWS_ARRAY_SIZE(txns); n++) {
		lwsl_user("%s: checked %d, responded %d\n", txns[n].name,
			  txns[n].checked, txns[n].responded);
		if (!txns[n].checked || !txns[n].responded)
			failed = 1;
	}

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;
}
