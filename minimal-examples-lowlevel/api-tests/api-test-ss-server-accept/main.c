/*
 * lws-api-test-ss-server-accept
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms the lifetime of the streams a Secure Streams server accepts.
 *
 * Every connection (and every h2 stream) that arrives at the server gets its
 * own accepted stream, created from the server "template" stream.  Whatever
 * the peer does, the accepted stream must be destroyed when its connection
 * goes: a server that keeps them leaks one stream object per connection, for
 * as long as the context lives.
 *
 * The user code here sees each accepted stream's LWSSSCS_CREATING and
 * LWSSSCS_DESTROYING, so it can count how many are alive.  A client in the
 * same process runs each phase a few times, and after each run all the
 * accepted streams must be gone again.
 *
 *  - tcp:        connect and close, without starting tls
 *  - h1-partial: tls with ALPN http/1.1, part of a request, close
 *  - h1-txn:     a complete http/1.1 transaction the server answers
 *  - h2-txn:     a complete h2 transaction the server answers: the h2
 *                network connection has an accepted stream of its own
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

#define CYCLES 3

static const char h1_partial[] = "GET / HTTP/1.1\r\nHost: localhost\r\n";

typedef struct phase {
	const char		*name;
	const char		*alpn;		/* NULL = no tls */
	const char		*send;		/* raw: sent before closing */
	size_t			send_len;
	char			http;		/* a whole GET, answered */

	/* results */
	int			cycles_ok;
} phase_t;

static phase_t phases[] = {
	{ "tcp",	NULL,		NULL,		0,		0, 0 },
	{ "h1-partial",	"http/1.1",	h1_partial,	sizeof(h1_partial) - 1,
								0, 0 },
	{ "h1-txn",	"http/1.1",	NULL,		0,		1, 0 },
	{ "h2-txn",	"h2",		NULL,		0,		1, 0 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static struct lws_ss_handle *srv_template;
static lws_sorted_usec_list_t sul_timeout, sul_next, sul_check;
static const char *server_ads = "127.0.0.1";
static unsigned int cur_phase, cycle;
static int port = 7681, failed;

/*
 * accepted streams: created, destroyed, how many had been created when the
 * cycle started, and how many earlier failed cycles left behind
 */
static int acc_created, acc_destroyed, acc_created_at_start, acc_left;
static lws_usec_t cycle_deadline;
static char client_done, client_rx_ok;

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
is_template(srv_t *m)
{
	return srv_template && m == lws_ss_to_user_object(srv_template);
}

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

	/* srv_template is not set yet when the template hears CREATING */
	if (!srv_template || is_template(m)) {
		lwsl_ss_user(m->ss, "%s (template)", lws_ss_state_name(state));
		return LWSSSSRET_OK;
	}

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_CREATING:
		acc_created++;
		break;

	case LWSSSCS_DESTROYING:
		acc_destroyed++;
		break;

	case LWSSSCS_SERVER_TXN:
		lws_ss_server_ack(m->ss, 0);
		m->sent = 0;

		return lws_ss_request_tx_len(m->ss, 2);

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_server = {
	.handle_offset			= offsetof(srv_t, ss),
	.opaque_user_data_offset	= offsetof(srv_t, opaque_data),
	.streamtype			= "accsrv",
	.rx				= srv_rx,
	.tx				= srv_tx,
	.state				= srv_state,
	.user_alloc			= sizeof(srv_t),
};

/*
 * The client side: a raw socket for the phases that stop short of a request,
 * an http client for the ones with a whole transaction
 */

static void
check_cycle(lws_sorted_usec_list_t *sul);

static void
start_cycle(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	phase_t *ph;

	if (cycle == CYCLES) {
		cycle = 0;
		if (++cur_phase == LWS_ARRAY_SIZE(phases)) {
			finish(0);
			return;
		}
	}

	ph = &phases[cur_phase];
	if (!cycle)
		lwsl_user("--- phase %s ---\n", ph->name);

	acc_created_at_start = acc_created;
	client_done = 0;
	client_rx_ok = 0;
	cycle_deadline = lws_now_usecs() + (5 * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_ads;
	i.port			= port;
	i.host			= server_ads;
	i.origin		= server_ads;
	i.local_protocol_name	= "acc-cli";

	if (ph->http) {
		i.method	= "GET";
		i.path		= "/";
		/*
		 * An idle h2 client connection is kept for reuse for a while
		 * after its last stream, don't wait for the default 5s
		 */
		i.keep_warm_secs = 1;
	} else
		i.method	= "RAW";

	if (ph->alpn) {
		i.ssl_connection	= LCCSCF_USE_SSL |
					  LCCSCF_ALLOW_SELFSIGNED |
					  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		i.alpn			= ph->alpn;
	}

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("--- %s: client connect failed ---\n", ph->name);
		finish(1);
		return;
	}

	lws_sul_schedule(context, 0, &sul_check, check_cycle,
			 50 * LWS_US_PER_MS);
}

/*
 * The cycle is over when the client is gone and every accepted stream the
 * server made for it has been destroyed
 */

static void
check_cycle(lws_sorted_usec_list_t *sul)
{
	phase_t *ph = &phases[cur_phase];
	int live = acc_created - acc_destroyed - acc_left;

	if (client_done && acc_created > acc_created_at_start && !live) {
		if (ph->http && !client_rx_ok) {
			lwsl_err("--- %s: no response ---\n", ph->name);
			finish(1);
			return;
		}
		ph->cycles_ok++;
		cycle++;
		lws_sul_schedule(context, 0, &sul_next, start_cycle, 1);
		return;
	}

	if (lws_now_usecs() > cycle_deadline) {
		lwsl_err("--- %s: cycle %u: client %s, %d accepted streams "
			 "made, %d still alive ---\n", ph->name, cycle,
			 client_done ? "gone" : "still there",
			 acc_created - acc_created_at_start, live);
		lws_ss_dump_extant(context, 0);
		failed = 1;

		/* go on with the next phase, so we see how each one does */
		acc_left += live;
		cycle = CYCLES;
		lws_sul_schedule(context, 0, &sul_next, start_cycle, 1);
		return;
	}

	lws_sul_schedule(context, 0, &sul_check, check_cycle,
			 50 * LWS_US_PER_MS);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	phase_t *ph = &phases[cur_phase];
	uint8_t buf[LWS_PRE + 256];
	char *px = (char *)buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("--- %s: client connection error: %s ---\n", ph->name,
			 in ? (char *)in : "(null)");
		finish(1);
		break;

	/* the raw phases */

	case LWS_CALLBACK_RAW_CONNECTED:
		/* hang up from outside the connection's own setup */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!ph->send || ph->send_len > sizeof(buf) - LWS_PRE)
			return -1;
		memcpy(buf + LWS_PRE, ph->send, ph->send_len);
		if (lws_write(wsi, buf + LWS_PRE, ph->send_len,
			      LWS_WRITE_RAW) != (int)ph->send_len)
			return -1;

		return -1; /* and hang up */

	case LWS_CALLBACK_RAW_RX:
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		client_done = 1;
		break;

	/* the http phases */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (lws_http_client_http_response(wsi) != 200) {
			lwsl_err("--- %s: response %u ---\n", ph->name,
				 lws_http_client_http_response(wsi));
			finish(1);
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len == 2 && !memcmp(in, "ok", 2))
			client_rx_ok = 1;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		return -1;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_done = 1;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "acc-cli", callback_cli, 0, 0, 0, NULL, 0 },
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

	lws_sul_schedule(context, 0, &sul_next, start_cycle, 1);

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

	lwsl_user("LWS API selftest: SS server accepted stream lifetime\n");

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

	/* the client vhost; the server vhost comes from the policy */

	info.vhost_name	= "cli";
	info.protocols	= protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		lws_context_destroy(context);
		return 1;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 60 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	for (n = 0; n < LWS_ARRAY_SIZE(phases); n++) {
		lwsl_user("%s: %d / %d cycles left no accepted stream\n",
			  phases[n].name, phases[n].cycles_ok, CYCLES);
		if (phases[n].cycles_ok != CYCLES)
			result = 1;
	}

	if (failed)
		result = 1;

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
