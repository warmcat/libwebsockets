/*
 * lws-api-test-ss-retry-on-route
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A Secure Stream that failed to connect waits out its policy's backoff
 * before it tries again.  If it failed because the network wasn't there yet,
 * eg, a VM whose DHCP hadn't finished, the network may well appear early in
 * a long backoff, and the stream sits idle for the rest of it.  sai-builders
 * in fresh VMs waited up to 10s like that, every time.
 *
 * When lws hears the network got better, a route was added or an address
 * acquired, a stream waiting to retry tries again at once.
 *
 * The stream here has a 10s backoff, and nothing is listening where it
 * connects.  Once it has failed, the test starts listening there, and says a
 * route was added, the way lws' netlink support does.  The stream must then
 * complete within 3s: without being told to retry, it would wait out the 10s.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define RR_BACKOFF_MS		10000
#define RR_MUST_RETRY_US	(3 * LWS_US_PER_SEC)
#define RR_GIVE_UP_US		(8 * LWS_US_PER_SEC)

static struct lws_context *context;
static lws_sorted_usec_list_t sul_listen, sul_timeout;
static lws_state_notify_link_t nl;
static const char *server_ads = "127.0.0.1";
static lws_usec_t us_route;
static int failed = 1, port = 7681, saw_failure, done;

static void
finish(int fail)
{
	if (done)
		return;
	done = 1;
	failed = fail;
	lws_default_loop_exit(context);
}

/*
 * The server, once it's there: answers any request with an empty 200
 */

typedef struct srv_pss {
	char			req[1024];
	size_t			req_len;
	char			answered;
} srv_pss_t;

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	static const char resp[] = "HTTP/1.1 200 OK\r\n"
				   "content-length: 0\r\n\r\n";
	srv_pss_t *pss = (srv_pss_t *)user;
	uint8_t buf[LWS_PRE + sizeof(resp)];

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->answered)
			break;
		if (len > sizeof(pss->req) - 1 - pss->req_len)
			return -1;
		memcpy(pss->req + pss->req_len, in, len);
		pss->req_len += len;
		pss->req[pss->req_len] = '\0';
		if (strstr(pss->req, "\r\n\r\n"))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->answered)
			break;
		pss->answered = 1;
		memcpy(buf + LWS_PRE, resp, sizeof(resp) - 1);
		if (lws_write(wsi, buf + LWS_PRE, sizeof(resp) - 1,
			      LWS_WRITE_RAW) != (int)sizeof(resp) - 1)
			return -1;
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "rr-srv", callback_srv, sizeof(srv_pss_t), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The network gets better: something listens where the stream connects,
 * and a route is announced the way the netlink support announces one
 */

static void
sul_listen_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	info.vhost_name	= "rr-srv";
	info.port	= port;
	info.protocols	= protocols_srv;
	info.options	= LWS_SERVER_OPTION_ONLY_RAW;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("%s: unable to create the server vhost\n", __func__);
		finish(1);
		return;
	}

	lwsl_user("%s: listening now, announcing a route\n", __func__);
	us_route = lws_now_usecs();

	if (lws_smd_msg_printf(context, LWSSMDCL_NETWORK, "{\"rt\":\"add\"}"))
		lwsl_err("%s: unable to send smd\n", __func__);
}

/*
 * The client stream
 */

typedef struct cli {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} cli_t;

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
	lws_usec_t took;

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_DISCONNECTED:
		if (saw_failure || us_route)
			break;
		saw_failure = 1;
		/* it's waiting out its backoff by the time this fires */
		lws_sul_schedule(context, 0, &sul_listen, sul_listen_cb,
				 500 * LWS_US_PER_MS);
		break;

	case LWSSSCS_QOS_ACK_REMOTE:
		if (!us_route) {
			lwsl_err("--- completed before it ever failed ---\n");
			finish(1);
			break;
		}
		took = lws_now_usecs() - us_route;
		lwsl_user("--- completed %dms after the route appeared, "
			  "backoff %dms: %s ---\n",
			  (int)(took / LWS_US_PER_MS), RR_BACKOFF_MS,
			  took < RR_MUST_RETRY_US ? "PASS" : "FAIL");
		finish(took >= RR_MUST_RETRY_US);
		return LWSSSSRET_DESTROY_ME;

	case LWSSSCS_ALL_RETRIES_FAILED:
		lwsl_err("--- gave up retrying ---\n");
		finish(1);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_cli = {
	.handle_offset			= offsetof(cli_t, ss),
	.opaque_user_data_offset	= offsetof(cli_t, opaque_data),
	.streamtype			= "rr",
	.rx				= cli_rx,
	.state				= cli_state,
	.user_alloc			= sizeof(cli_t),
};

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_ss_handle *ss;

	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	if (lws_ss_create(context, 0, &ssi_cli, NULL, &ss, NULL, NULL)) {
		lwsl_err("%s: unable to create the stream\n", __func__);
		finish(1);
		return 0;
	}

	/*
	 * Where connecting to a port nothing listens on is refused before
	 * the connect call returns, eg, loopback on FreeBSD, the stream has
	 * already reported UNREACHABLE and started its backoff by the time
	 * this returns, and says so with LWSSSSRET_TX_DONT_SEND.  That is
	 * the failure we are waiting for, not a reason to give up.
	 */

	switch (lws_ss_client_connect(ss)) {
	case LWSSSSRET_OK:
	case LWSSSSRET_TX_DONT_SEND:
		break;
	default:
		lwsl_err("%s: unable to start the stream\n", __func__);
		lws_ss_destroy(&ss);
		finish(1);
		break;
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- %s ---\n", us_route ? "still waiting out the backoff" :
					    "never failed to connect");
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

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: a stream backing off retries when a "
		  "route appears\n");

	lws_snprintf(policy, sizeof(policy),
		"{\"release\":\"01234567\",\"product\":\"myproduct\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"slow\":{\"backoff\":[%d,%d,%d],"
			"\"conceal\":10,\"jitterpc\":0,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"s\":[{\"rr\":{"
			"\"endpoint\":\"%s\",\"port\":%d,\"protocol\":\"h1\","
			"\"http_method\":\"GET\",\"http_url\":\"\","
			"\"retry\":\"slow\",\"tls\":false}}]}",
		RR_BACKOFF_MS, RR_BACKOFF_MS, RR_BACKOFF_MS, server_ads, port);

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

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 RR_GIVE_UP_US);

	lws_context_default_loop_run_destroy(context);

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;
}
