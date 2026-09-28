/*
 * lws-api-test-ss-server-upgrade
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms which Secure Streams server stream hears LWSSSCS_SERVER_UPGRADE
 * when a peer upgrades to ws, over h1 and over h2 (RFC 8441).
 *
 * The policy describes a tls server streamtype "ssupg" that also serves the
 * ws subprotocol "ssupg-ws".  Creating it makes the listening vhost and a
 * "template" server stream; each incoming connection (or h2 stream) gets its
 * own accepted stream, bound to the connection's wsi, and it is the accepted
 * stream that carries the ws rx and tx after the upgrade.
 *
 * An lws ws client in the same process connects first with ALPN http/1.1 and
 * then with h2.  In each phase the server's accepted stream must hear
 * LWSSSCS_SERVER_UPGRADE exactly once, and then sends one ws message that the
 * client checks.  The template stream must never hear the upgrade.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_POLICY,
	LWS_SW_PORT,
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_POLICY]	= { "-c",	"Path to the JSON policy to use" },
	[LWS_SW_PORT]	= { "-p",	"Port the client connects to, must be the "
					"policy's server port (default 7681)" },
	[LWS_SW_SERVER]	= { "--server",	"Address the client connects to "
					"(default 127.0.0.1)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

typedef struct phase {
	const char		*name;
	const char		*alpn;
	char			mux;		/* expect ws inside a mux (h2) */

	/* results */
	int			accepted_upgrades;
	char			rx_ok;
} phase_t;

static phase_t phases[] = {
	{ "h1", "http/1.1", 0, 0, 0 },
	{ "h2", "h2",       1, 0, 0 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static struct lws_ss_handle *srv_template;
static lws_sorted_usec_list_t sul_timeout, sul_next;
static const char *server_ads = "127.0.0.1";
static unsigned int cur_phase;
static int template_upgrades, port = 7681, failed;

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

	char			upgraded;
	char			sent;
} srv_t;

static lws_ss_state_return_t
srv_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
srv_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
       int *flags)
{
	srv_t *m = (srv_t *)userobj;

	if (!m->upgraded || m->sent)
		return LWSSSSRET_TX_DONT_SEND;

	*len = (size_t)lws_snprintf((char *)buf, *len, "ssupg %s",
				    phases[cur_phase].name);
	*flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;
	m->sent = 1;

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
srv_state(void *userobj, void *sh, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	srv_t *m = (srv_t *)userobj;

	lwsl_ss_user(m->ss, "%s%s", lws_ss_state_name(state),
		     m->ss == srv_template ? " (template)" : "");

	if (state != LWSSSCS_SERVER_UPGRADE)
		return LWSSSSRET_OK;

	if (m->ss == srv_template) {
		/*
		 * The template stream has no connection, it can't do anything
		 * useful with the upgrade, and the accepted stream that should
		 * have heard it is left treating ws as http
		 */
		lwsl_err("--- %s: template stream got SERVER_UPGRADE ---\n",
			 phases[cur_phase].name);
		template_upgrades++;
		finish(1);

		return LWSSSSRET_OK;
	}

	phases[cur_phase].accepted_upgrades++;
	m->upgraded = 1;

	/* send the client the one ws message it is waiting for */

	return lws_ss_request_tx(m->ss);
}

static const lws_ss_info_t ssi_server = {
	.handle_offset			= offsetof(srv_t, ss),
	.opaque_user_data_offset	= offsetof(srv_t, opaque_data),
	.streamtype			= "ssupg",
	.rx				= srv_rx,
	.tx				= srv_tx,
	.state				= srv_state,
	.user_alloc			= sizeof(srv_t),
};

/*
 * The client side, a plain lws ws client per phase
 */

static void
start_phase(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	phase_t *ph = &phases[cur_phase];

	lwsl_user("--- phase %s ---\n", ph->name);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_ads;
	i.port			= port;
	i.path			= "/";
	i.host			= server_ads;
	i.origin		= server_ads;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.alpn			= ph->alpn;
	i.protocol		= "ssupg-ws";
	i.local_protocol_name	= "ssupg-ws";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("--- %s: client connect failed ---\n", ph->name);
		finish(1);
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	phase_t *ph = &phases[cur_phase];
	char want[32];

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("%s: %s: established\n", __func__, ph->name);
		if ((lws_get_network_wsi(wsi) != wsi) != ph->mux) {
			lwsl_err("--- %s: ws %s encapsulated ---\n", ph->name,
				 ph->mux ? "not" : "unexpectedly");
			finish(1);
			return -1;
		}
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		lws_snprintf(want, sizeof(want), "ssupg %s", ph->name);
		if (len != strlen(want) || memcmp(in, want, len)) {
			lwsl_err("--- %s: unexpected ws message ---\n",
				 ph->name);
			lwsl_hexdump_err(in, len);
			finish(1);
			return -1;
		}
		ph->rx_ok = 1;

		return -1; /* this phase is done, close the ws */

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("--- %s: client connection error: %s ---\n", ph->name,
			 in ? (char *)in : "(null)");
		finish(1);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		lwsl_user("%s: %s: closed\n", __func__, ph->name);
		if (!ph->rx_ok) {
			finish(1);
			break;
		}
		if (++cur_phase == LWS_ARRAY_SIZE(phases)) {
			finish(0);
			break;
		}
		/* start the next phase from outside this wsi's callback */
		lws_sul_schedule(context, 0, &sul_next, start_phase, 1);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "ssupg-ws", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
smd_cb(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	if (!(c & LWSSMDCL_SYSTEM_STATE) ||
	    lws_json_simple_strcmp(buf, len, "\"state\":", "OPERATIONAL"))
		return 0;

	if (lws_ss_create(context, 0, &ssi_server, NULL, &srv_template,
			  NULL, NULL)) {
		lwsl_err("%s: failed to create server stream\n", __func__);
		finish(1);
		return -1;
	}

	lws_sul_schedule(context, 0, &sul_next, start_phase, 1);

	return 0;
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout in phase %s ---\n",
		 cur_phase < LWS_ARRAY_SIZE(phases) ?
				phases[cur_phase].name : "(end)");
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
	const char *p, *policy;
	unsigned int n;
	int result = 0;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	policy = lws_cmdline_option(argc, argv, switches[LWS_SW_POLICY].sw);
	if (!policy) {
		lwsl_err("-c <policy JSON path> is required\n");
		return 1;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: SS server ws upgrade over h1 and h2\n");

	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.early_smd_cb		= smd_cb;
	info.early_smd_class_filter	= LWSSMDCL_SYSTEM_STATE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the ws client vhost; the server vhost comes from the policy */

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

	if (template_upgrades)
		result = 1;

	for (n = 0; n < LWS_ARRAY_SIZE(phases); n++) {
		lwsl_user("%s: accepted stream upgrades %d, ws rx %s\n",
			  phases[n].name, phases[n].accepted_upgrades,
			  phases[n].rx_ok ? "ok" : "missing");
		if (phases[n].accepted_upgrades != 1 || !phases[n].rx_ok)
			result = 1;
	}

	if (failed)
		result = 1;

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
