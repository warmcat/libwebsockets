/*
 * lws-api-test-ss-redirect
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A Secure Streams client whose policy allows redirects, and that sends
 * identity in its headers (here the device serial, as "x-dsn:"), follows a
 * redirect only on the authority its policy named.  The headers would go
 * again to wherever the redirect took it, so a Location naming another
 * authority must be refused, however it is spelled:
 *
 *  - a relative path, an absolute URI naming our authority, and a
 *    network-path reference ("//host:port/path") naming our authority are
 *    followed
 *
 *  - an absolute URI, or a network-path reference, naming another host is
 *    refused: the second is not a path, it names another authority as much
 *    as the first does
 *
 * A small raw socket server in the same process answers "/start/<phase>"
 * with that phase's redirect, and anything else with a 200, noting what it
 * was asked for.  Each phase is a stream of its own, with no retries.  The
 * "other" host is another name for the same server ("127.0.0.1" when the
 * policy says "localhost"), so a redirect to it that was followed would
 * reach the server, and be seen.
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

typedef struct phase {
	const char		*name;
	const char		*loc;		/* a format taking a host and
						 * the server's port */
	char			other;		/* the host is not ours */
	const char		*target;	/* followed: what the server
						 * must be asked for after, or
						 * NULL: refused */
} phase_t;

static const phase_t phases[] = {
	{ "relative path",		"/same",		0, "/same" },
	{ "absolute URI, our authority", "http://%s:%d/abs",	0, "/abs" },
	{ "//host:port/path, our authority", "//%s:%d/np",	0, "/np" },
	{ "absolute URI, another host",	"http://%s:%d/x",	1, NULL },
	{ "//host:port/path, another host", "//%s:%d/x",	1, NULL },
};

static const char * const phase_md[] = { "0", "1", "2", "3", "4" };

static struct lws_context *context;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_timeout, sul_next;
static const char *server_ads = "localhost", *other_ads;
static unsigned int cur_phase;
static int failed, port = 7681, phase_ok;
static char asked[64];			/* the last thing the server was asked */

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_default_loop_exit(context);
}

/*
 * The raw socket server side
 */

typedef struct srv_pss {
	char			req[1024];
	char			resp[256];
	size_t			req_len;
	int			resp_len;
} srv_pss_t;

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	srv_pss_t *pss = (srv_pss_t *)user;
	uint8_t buf[LWS_PRE + sizeof(pss->resp)];
	const char *sp1, *sp2, *ads;
	char loc[128], host[64];
	int n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->resp_len)
			break;

		if (len > sizeof(pss->req) - 1 - pss->req_len) {
			lwsl_err("%s: request too large\n", __func__);
			return -1;
		}
		memcpy(pss->req + pss->req_len, in, len);
		pss->req_len += len;
		pss->req[pss->req_len] = '\0';

		if (!strstr(pss->req, "\r\n\r\n"))
			break; /* wait for the rest of the request headers */

		/* the request line is "GET <target> HTTP/1.1" */

		sp1 = strchr(pss->req, ' ');
		sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
		if (!sp2) {
			lwsl_err("%s: bad request line\n", __func__);
			return -1;
		}
		lws_strnncpy(asked, sp1 + 1, lws_ptr_diff_size_t(sp2, sp1 + 1),
			     sizeof(asked));
		lwsl_user("%s: server was asked for %s\n", __func__, asked);

		if (!strncmp(asked, "/start/", 7)) {
			n = atoi(asked + 7);
			if (n < 0 || n >= (int)LWS_ARRAY_SIZE(phases))
				return -1;
			ads = phases[n].other ? other_ads : server_ads;
			/* an IPv6 literal goes in a URI in brackets */
			lws_snprintf(host, sizeof(host),
				     strchr(ads, ':') ? "[%s]" : "%s", ads);
			lws_snprintf(loc, sizeof(loc), phases[n].loc, host, /* NOSONAR: const test table */
				     port);
			pss->resp_len = lws_snprintf(pss->resp,
					sizeof(pss->resp),
					"HTTP/1.1 302 Found\r\n"
					"Location: %s\r\n"
					"Content-Length: 0\r\n"
					"Connection: close\r\n\r\n", loc);
		} else
			pss->resp_len = lws_snprintf(pss->resp,
					sizeof(pss->resp),
					"HTTP/1.1 200 OK\r\n"
					"Content-Length: 2\r\n"
					"Connection: close\r\n\r\nok");

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!pss->resp_len)
			break;
		if (pss->resp_len < 0)
			/* the response has gone out, it said we close */
			return -1;

		memcpy(buf + LWS_PRE, pss->resp, (size_t)pss->resp_len);
		if (lws_write(wsi, buf + LWS_PRE, (size_t)pss->resp_len,
			      LWS_WRITE_RAW) != pss->resp_len)
			return -1;

		pss->resp_len = -1;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "redir-srv", callback_srv, sizeof(srv_pss_t), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The Secure Streams client side
 */

typedef struct cli {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} cli_t;

static void
start_phase(lws_sorted_usec_list_t *sul);

/* the phase ended one way or the other: judge it, and go on to the next */

static lws_ss_state_return_t
phase_end(int completed)
{
	const phase_t *ph = &phases[cur_phase];
	int ok;

	if (phase_ok)
		return LWSSSSRET_OK;
	phase_ok = 1;

	if (ph->target)
		ok = completed && !strcmp(asked, ph->target);
	else
		ok = !completed && !strncmp(asked, "/start/", 7);

	lwsl_user("--- phase %s: %s (completed %d, server last asked %s) ---\n",
		  ph->name, ok ? "PASS" : "FAIL", completed, asked);
	if (!ok)
		failed = 1;

	if (++cur_phase == LWS_ARRAY_SIZE(phases))
		finish(0);
	else
		lws_sul_schedule(context, 0, &sul_next, start_phase, 1);

	return LWSSSSRET_DESTROY_ME;
}

static lws_ss_state_return_t
cli_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
cli_state(void *userobj, void *sh, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	cli_t *m = (cli_t *)userobj;

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_QOS_ACK_REMOTE:
		return phase_end(1);

	case LWSSSCS_QOS_NACK_REMOTE:
	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_ALL_RETRIES_FAILED:
		return phase_end(0);

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_cli = {
	.handle_offset			= offsetof(cli_t, ss),
	.opaque_user_data_offset	= offsetof(cli_t, opaque_data),
	.streamtype			= "redir",
	.rx				= cli_rx,
	.state				= cli_state,
	.user_alloc			= sizeof(cli_t),
};

static void
start_phase(lws_sorted_usec_list_t *sul)
{
	struct lws_ss_handle *ss;

	lwsl_user("=== phase %s ===\n", phases[cur_phase].name);
	phase_ok = 0;
	asked[0] = '\0';

	if (lws_ss_create(context, 0, &ssi_cli, NULL, &ss, NULL, NULL) ||
	    lws_ss_set_metadata(ss, "phase", phase_md[cur_phase], 1) ||
	    lws_ss_client_connect(ss)) {
		lwsl_err("%s: unable to start phase\n", __func__);
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

	/*
	 * Start from the event loop, so the server vhost is certainly
	 * listening by then
	 */
	lws_sul_schedule(context, 0, &sul_next, start_phase, 1);

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

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
	char policy[1024];
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
	other_ads = strcmp(server_ads, "localhost") ? "localhost" : "127.0.0.1";

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: SS redirects stay on the authority\n");

	/* no retries: a refused redirect ends the phase at once */

	lws_snprintf(policy, sizeof(policy),
		"{\"release\":\"01234567\",\"product\":\"myproduct\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"none\":{\"backoff\":[],"
			"\"conceal\":0,\"jitterpc\":0,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"s\":[{\"redir\":{"
			"\"endpoint\":\"%s\",\"port\":%d,\"protocol\":\"h1\","
			"\"http_method\":\"GET\",\"http_url\":\"start/${phase}\","
			"\"metadata\":[{\"phase\":\"\"}],"
			"\"http_dsn_header\":\"x-dsn:\","
			"\"allow_redirects\":true,"
			"\"retry\":\"none\",\"tls\":false}}]}",
		server_ads, port);

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

	/* the identity the stream's headers carry */

	lws_system_blob_direct_set(lws_system_get_blob(context,
				   LWS_SYSBLOB_TYPE_DEVICE_SERIAL, 0),
				   (const uint8_t *)"serial-1234", 11);

	/* the raw socket server vhost */

	info.vhost_name	= "redir-srv";
	info.port	= port;
	info.protocols	= protocols_srv;
	info.options	= LWS_SERVER_OPTION_ONLY_RAW;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 30 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	if (cur_phase != LWS_ARRAY_SIZE(phases))
		failed = 1;

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;

bail:
	lws_context_destroy(context);

	return 1;
}
