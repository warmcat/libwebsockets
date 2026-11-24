/*
 * lws-api-test-ss-rx-header-metadata
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A Secure Streams policy can capture a response header into metadata,
 * either a header lws knows ("cache-control:") or a custom one ("x-cust:").
 * The metadata must hold exactly the header's value:
 *
 *  - a well-known header the server sent more than once, with another
 *    header between them, has its values joined with ", ", the way
 *    lws_hdr_copy() gives them, and nothing else that was in the headers
 *
 *  - a custom header has its value
 *
 *  - a second response on the same stream replaces both values
 *
 * With LWS_WITH_SS_DIRECT_PROTOCOL_STR, a second stream does the same with a
 * "direct_proto_str" policy, where the app asks lws_ss_get_metadata() for
 * the headers by name, without the policy naming them.
 *
 * A raw socket server in the same process answers each request on a stream
 * with the next of the responses below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_SERVER]	= { "--server",	"Address of the test server "
					"(default localhost)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

typedef struct rxmd_resp {
	const char		*headers;	/* what the server sends */
	const char		*cc;		/* what "cc" must be then */
	const char		*cust;		/* what "cust" must be then */
} rxmd_resp_t;

static const rxmd_resp_t resps[] = {
	{
		"cache-control: max-age=1\r\n"
		"x-between: not part of cache-control\r\n"
		"cache-control: no-transform\r\n"
		"x-cust: first\r\n",
		"max-age=1, no-transform", "first"
	},
	{
		"cache-control: no-store\r\n"
		"x-cust: second\r\n",
		"no-store", "second"
	},
};

static struct lws_context *context;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_timeout, sul_again;
static struct lws_ss_handle *cur_ss;
static const char *server_ads = "localhost";
static char endpoint[128];
static unsigned int server_asked, checked;
static int failed = 1, direct;

#if defined(LWS_WITH_SS_DIRECT_PROTOCOL_STR)
#define RXMD_DIRECT \
	",{\"rxmd-direct\":{" \
		"\"endpoint\":\"${ep}\",\"port\":80,\"protocol\":\"h1\"," \
		"\"http_method\":\"GET\",\"http_url\":\"x\"," \
		"\"retry\":\"none\",\"direct_proto_str\":true," \
		"\"metadata\":[{\"ep\":\"\"}]}}"
#define RXMD_STREAMS 2
#else
#define RXMD_DIRECT ""
#define RXMD_STREAMS 1
#endif

/* the streamtypes, and the names their app asks for the headers by */

static const char * const st_names[] = { "rxmd", "rxmd-direct" };
static const char * const cc_names[] = { "cc", "cache-control:" };
static const char * const cust_names[] = { "cust", "x-cust:" };

/*
 * The raw socket server side
 */

typedef struct srv_pss {
	char			req[1024];
	size_t			req_len;
	unsigned int		resp;		/* which of resps[] we send */
	char			answered;	/* 1: to send, 2: sent */
} srv_pss_t;

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	srv_pss_t *pss = (srv_pss_t *)user;
	uint8_t buf[LWS_PRE + 512];
	char *start;
	int n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->answered)
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

		if (server_asked >= LWS_ARRAY_SIZE(resps)) {
			lwsl_err("%s: asked too many times\n", __func__);
			return -1;
		}
		pss->resp = server_asked++;
		pss->answered = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!pss->answered)
			break;
		if (pss->answered == 2)
			/* the response has gone out, it said we close */
			return -1;

		start = (char *)buf + LWS_PRE;
		n = lws_snprintf(start, sizeof(buf) - LWS_PRE,
				 "HTTP/1.1 200 OK\r\n"
				 "%s"
				 "Content-Length: 2\r\n"
				 "Connection: close\r\n\r\nok",
				 resps[pss->resp].headers);
		if (lws_write(wsi, (uint8_t *)start, (size_t)n,
			      LWS_WRITE_RAW) != n)
			return -1;

		pss->answered = 2;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "rxmd-srv", callback_srv, sizeof(srv_pss_t), 0, 0, NULL, 0 },
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
done(int pass)
{
	failed = !pass;
	lws_default_loop_exit(context);
}

/* the metadata must be exactly the value, not a byte more or less */

static int
md_is(const char *name, const char *want)
{
	size_t len, wlen = strlen(want);
	const void *v;

	if (lws_ss_get_metadata(cur_ss, name, &v, &len)) {
		lwsl_err("%s: no metadata %s\n", __func__, name);
		return 0;
	}

	if (len != wlen || memcmp(v, want, wlen)) {
		lwsl_err("%s: %s is len %d, wanted \"%s\"\n", __func__, name,
			 (int)len, want);
		lwsl_hexdump_err(v, len);
		return 0;
	}

	return 1;
}

static const lws_ss_info_t ssi_cli;

static void
start_stream(void)
{
	lws_ss_info_t ssi = ssi_cli;

	lwsl_user("=== stream %s ===\n", st_names[direct]);
	checked = server_asked = 0;
	ssi.streamtype = st_names[direct];

	/* the endpoint is bound by reference, so it lives in a static */
	if (lws_ss_create(context, 0, &ssi, NULL, &cur_ss, NULL, NULL) ||
	    lws_ss_set_metadata(cur_ss, "ep", endpoint, strlen(endpoint)) ||
	    lws_ss_client_connect(cur_ss) < 0) {
		lwsl_err("%s: unable to start the stream\n", __func__);
		done(0);
	}
}

static void
connect_again(lws_sorted_usec_list_t *sul)
{
	if (checked == LWS_ARRAY_SIZE(resps)) {
		/* this stream saw all the responses: the next stream */
		lws_ss_destroy(&cur_ss);
		direct++;
		start_stream();
		return;
	}

	if (lws_ss_client_connect(cur_ss) < 0) {
		lwsl_err("%s: connect failed\n", __func__);
		done(0);
	}
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
	const rxmd_resp_t *r;

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_QOS_ACK_REMOTE:
		if (checked != server_asked - 1) {
			lwsl_err("%s: response %u unexpected\n", __func__,
				 server_asked);
			done(0);
			break;
		}

		r = &resps[checked];
		if (!md_is(cc_names[direct], r->cc) ||
		    !md_is(cust_names[direct], r->cust)) {
			done(0);
			break;
		}
		lwsl_user("response %u: cc \"%s\", cust \"%s\": as expected\n",
			  checked, r->cc, r->cust);
		checked++;
		break;

	case LWSSSCS_DISCONNECTED:
		if (checked == LWS_ARRAY_SIZE(resps) &&
		    direct + 1 == RXMD_STREAMS) {
			done(1);
			break;
		}
		if (checked == server_asked)
			/* the next response, or the next stream */
			lws_sul_schedule(context, 0, &sul_again, connect_again,
					 1);
		break;

	case LWSSSCS_QOS_NACK_REMOTE:
	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_ALL_RETRIES_FAILED:
		done(0);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_cli = {
	.handle_offset			= offsetof(cli_t, ss),
	.opaque_user_data_offset	= offsetof(cli_t, opaque_data),
	.rx				= cli_rx,
	.state				= cli_state,
	.user_alloc			= sizeof(cli_t),
};

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	start_stream();

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout after %u responses ---\n", checked);
	done(0);
}

static void
sigint_handler(int sig)
{
	done(0);
}

/*
 * In "rxmd", "cc" captures a header lws knows, "cust" a custom one.
 * "rxmd-direct" leaves the app to ask for the headers by name
 */

static const char * const policy =
	"{\"release\":\"01234567\",\"product\":\"myproduct\","
	 "\"schema-version\":1,"
	 "\"retry\":[{\"none\":{\"backoff\":[],"
		"\"conceal\":0,\"jitterpc\":0,"
		"\"svalidping\":30,\"svalidhup\":35}}],"
	 "\"s\":[{\"rxmd\":{"
		"\"endpoint\":\"${ep}\",\"port\":80,\"protocol\":\"h1\","
		"\"http_method\":\"GET\",\"http_url\":\"x\","
		"\"retry\":\"none\","
		"\"metadata\":[{\"ep\":\"\"},"
			      "{\"cc\":\"cache-control:\"},"
			      "{\"cust\":\"x-cust:\"}]}}"
	 RXMD_DIRECT
	 "]}";

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: SS metadata from response headers\n");

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;

	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_CPD_BYPASS;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.register_notifier_list	= app_notifier_list;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the raw socket server, on any free port */

	info.protocols		= protocols_srv;
	info.options		= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role	= "raw-skt";
	info.listen_accept_protocol = "rxmd-srv";
	info.vhost_name		= "rxmd-srv";
	info.port		= 0;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create the server vhost\n");
		lws_context_destroy(context);
		return 1;
	}

	/* an IPv6 literal goes in a url in brackets */
	lws_snprintf(endpoint, sizeof(endpoint),
		     strchr(server_ads, ':') ? "http://[%s]:%d/x" :
					       "http://%s:%d/x",
		     server_ads, lws_get_vhost_listen_port(vh));

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;
}
