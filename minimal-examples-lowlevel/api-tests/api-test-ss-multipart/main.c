/*
 * lws-api-test-ss-multipart
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms how a Secure Streams client with "http_multipart_ss_in" deframes
 * a multipart response body into one SOM .. EOM message per part, however the
 * server's chunked encoding happens to split the body.
 *
 * A small raw socket server in the same process answers each GET with a
 * canned HTTP/1.1 response whose body is sent as a fixed list of chunks, so we
 * control exactly where each piece the client's parser sees begins and ends:
 * at the CRLF before a delimiter, exactly around a delimiter line, in the
 * middle of something that only looks like the start of a delimiter, and so
 * on.  Every response is fetched by the same client stream, one after the
 * other, so the multipart state must also start clean for each response.
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

/* BND_HEAD is used alone to show an incomplete delimiter */
#define BND_HEAD "lws-mp-7f"
#define BND BND_HEAD "3a"
#define MP_CT "multipart/related; boundary=" BND

typedef struct phase {
	const char		*name;
	const char		*content_type;
	const char		*chunks[6];	/* the body, a chunk each */
	const char		*parts[3];	/* what the client must see */
	char			multipart;

	/* results */
	int			parts_seen;
	int			related_start;
	int			related_end;
	char			completed;
} phase_t;

static phase_t phases[] = {
	{
		/*
		 * A part's content chunk ends in the CRLF that begins the
		 * next delimiter, and the next chunk is exactly the rest of
		 * the delimiter line; the last part's chunk ends in the CR
		 * alone.  The preamble is not part of any part.
		 */
		"crlf-split", MP_CT, {
			"This is the preamble\r\n"
			"--" BND "\r\n"
			"Content-Type: text/plain\r\n\r\npart one\r\n",
			"--" BND "\r\n",
			"Content-Type: text/plain\r\n\r\npart two\r",
			"\n--" BND "--\r\n",
		}, {
			"Content-Type: text/plain\r\n\r\npart one",
			"Content-Type: text/plain\r\n\r\npart two",
		}, 1, 0, 0, 0, 0
	}, {
		/*
		 * The body starts with a chunk that is exactly the first
		 * delimiter line.  Then an empty part, a delimiter line with
		 * transport padding, a part containing the start of the
		 * delimiter at the end of one chunk that the next chunk shows
		 * was content, the close delimiter split from its CRLF, and an
		 * epilogue.
		 */
		"boundary-chunks", MP_CT, {
			"--" BND "\r\n",
			"\r\n--" BND " \t\r\nx\r\n--" BND_HEAD,
			"3b y\r",
			"\n--" BND "--",
			"\r\nThis is the epilogue\r\n",
		}, {
			"",
			"x\r\n--" BND_HEAD "3b y",
		}, 1, 0, 0, 0, 0
	}, {
		/*
		 * Not multipart: the body is passed through untouched, even
		 * though the earlier responses on this stream were multipart
		 * with this boundary
		 */
		"not-multipart", "text/plain", {
			"a\r\n--" BND "\r\n",
			"b",
		}, {
			"a\r\n--" BND "\r\nb",
		}, 0, 0, 0, 0, 0
	}, {
		/* the whole multipart body in one chunk */
		"one-chunk", MP_CT, {
			"--" BND "\r\nA: 1\r\n\r\none\r\n"
			"--" BND "\r\nA: 2\r\n\r\ntwo\r\n"
			"--" BND "--\r\n",
		}, {
			"A: 1\r\n\r\none",
			"A: 2\r\n\r\ntwo",
		}, 1, 0, 0, 0, 0
	},
};

static const char * const phase_md[] = { "0", "1", "2", "3" };

static struct lws_context *context;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_timeout, sul_next;
static struct lws_ss_handle *ss_mp;
static unsigned int cur_phase;
static int failed;

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
	size_t			req_len;
	unsigned int		phase;
	char			responded;
} srv_pss_t;

static int
srv_compose_response(const phase_t *ph, char *p, char *end)
{
	char *start = p;
	unsigned int n;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "HTTP/1.1 200 OK\r\n"
			  "Content-Type: %s\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "Connection: close\r\n\r\n", ph->content_type);

	for (n = 0; n < LWS_ARRAY_SIZE(ph->chunks) && ph->chunks[n]; n++)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%x\r\n%s\r\n",
				  (unsigned int)strlen(ph->chunks[n]),
				  ph->chunks[n]);

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "0\r\n\r\n");

	if (lws_ptr_diff_size_t(end, p) < 2)
		return -1; /* lws_snprintf() truncated it */

	return lws_ptr_diff(p, start);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	srv_pss_t *pss = (srv_pss_t *)user;
	uint8_t buf[LWS_PRE + 2048];
	const char *u;
	int n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->responded)
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

		/* the request is "GET /mp/<phase index> HTTP/1.1" */

		u = strstr(pss->req, " /mp/");
		if (!u || u[5] < '0' ||
		    u[5] >= '0' + (int)LWS_ARRAY_SIZE(phases)) {
			lwsl_err("%s: unexpected request\n", __func__);
			return -1;
		}
		pss->phase = (unsigned int)(u[5] - '0');
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->responded)
			/* the response has gone out, it said we close */
			return -1;

		n = srv_compose_response(&phases[pss->phase],
					 (char *)buf + LWS_PRE,
					 (char *)buf + sizeof(buf));
		if (n < 0) {
			lwsl_err("%s: response too large\n", __func__);
			return -1;
		}
		if (lws_write(wsi, buf + LWS_PRE, (size_t)n,
			      LWS_WRITE_RAW) != n)
			return -1;

		pss->responded = 1;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "mp-srv", callback_srv, sizeof(srv_pss_t), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The Secure Streams client side
 */

typedef struct cli {
	struct lws_ss_handle	*ss;
	void			*opaque_data;

	char			part[256];
	size_t			part_len;
	char			in_part;
} cli_t;

static lws_ss_state_return_t
cli_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	phase_t *ph = &phases[cur_phase];
	cli_t *m = (cli_t *)userobj;
	const char *want;

	if (flags & (LWSSS_FLAG_RELATED_START | LWSSS_FLAG_RELATED_END)) {
		if (len || m->in_part) {
			lwsl_err("%s: %s: bad RELATED_ message\n", __func__,
				 ph->name);
			goto fail;
		}
		if (flags & LWSSS_FLAG_RELATED_START)
			ph->related_start++;
		else
			ph->related_end++;

		return LWSSSSRET_OK;
	}

	if (!!(flags & LWSSS_FLAG_SOM) == !!m->in_part) {
		lwsl_err("%s: %s: SOM %s a part\n", __func__, ph->name,
			 m->in_part ? "inside" : "missing at start of");
		goto fail;
	}

	if (flags & LWSSS_FLAG_SOM) {
		m->in_part = 1;
		m->part_len = 0;
	}

	if (len > sizeof(m->part) - m->part_len) {
		lwsl_err("%s: %s: part rx len %llu too large\n", __func__,
			 ph->name, (unsigned long long)len);
		goto fail;
	}
	if (len)
		memcpy(m->part + m->part_len, buf, len);
	m->part_len += len;

	if (!(flags & LWSSS_FLAG_EOM))
		return LWSSSSRET_OK;

	m->in_part = 0;

	if (ph->parts_seen == (int)LWS_ARRAY_SIZE(ph->parts) ||
	    !(want = ph->parts[ph->parts_seen])) {
		lwsl_err("%s: %s: unexpected extra part\n", __func__, ph->name);
		lwsl_hexdump_err(m->part, m->part_len);
		goto fail;
	}

	if (m->part_len != strlen(want) || memcmp(m->part, want, m->part_len)) {
		lwsl_err("%s: %s: part %d differs\n", __func__, ph->name,
			 ph->parts_seen);
		lwsl_hexdump_err(m->part, m->part_len);
		goto fail;
	}

	ph->parts_seen++;

	return LWSSSSRET_OK;

fail:
	finish(1);

	return LWSSSSRET_DISCONNECT_ME;
}

static void
start_phase(lws_sorted_usec_list_t *sul)
{
	lwsl_user("--- phase %s ---\n", phases[cur_phase].name);

	if (lws_ss_set_metadata(ss_mp, "phase", phase_md[cur_phase], 1) ||
	    lws_ss_client_connect(ss_mp)) {
		lwsl_err("%s: unable to start phase\n", __func__);
		finish(1);
	}
}

static int
phase_check(const phase_t *ph)
{
	int n = 0;

	while (n < (int)LWS_ARRAY_SIZE(ph->parts) && ph->parts[n])
		n++;

	if (ph->parts_seen != n) {
		lwsl_err("%s: %s: saw %d parts, expected %d\n", __func__,
			 ph->name, ph->parts_seen, n);
		return 1;
	}

	if (ph->related_start != ph->multipart ||
	    ph->related_end != ph->multipart) {
		lwsl_err("%s: %s: RELATED_START %d, RELATED_END %d\n",
			 __func__, ph->name, ph->related_start,
			 ph->related_end);
		return 1;
	}

	return 0;
}

static lws_ss_state_return_t
cli_state(void *userobj, void *sh, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	phase_t *ph = &phases[cur_phase];
	cli_t *m = (cli_t *)userobj;

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_QOS_ACK_REMOTE:
		if (m->in_part || phase_check(ph)) {
			finish(1);
			break;
		}
		ph->completed = 1;
		lwsl_user("%s: phase %s: ok\n", __func__, ph->name);
		break;

	case LWSSSCS_QOS_NACK_REMOTE:
	case LWSSSCS_ALL_RETRIES_FAILED:
		finish(1);
		break;

	case LWSSSCS_DISCONNECTED:
		/*
		 * The server closes after each response, the next phase is
		 * another transaction on the same stream
		 */
		if (!ph->completed)
			break;
		if (++cur_phase == LWS_ARRAY_SIZE(phases)) {
			finish(0);
			break;
		}
		lws_sul_schedule(context, 0, &sul_next, start_phase, 1);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_cli = {
	.handle_offset			= offsetof(cli_t, ss),
	.opaque_user_data_offset	= offsetof(cli_t, opaque_data),
	.streamtype			= "mp",
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

	if (lws_ss_create(context, 0, &ssi_cli, NULL, &ss_mp, NULL, NULL)) {
		lwsl_err("%s: failed to create client stream\n", __func__);
		finish(1);

		return -1;
	}

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
	const char *p, *server_ads = "localhost";
	struct lws_context_creation_info info;
	char policy[1024];
	int port = 7681;
	unsigned int n;

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

	lwsl_user("LWS API selftest: SS multipart rx deframing\n");

	lws_snprintf(policy, sizeof(policy),
		"{\"release\":\"01234567\",\"product\":\"myproduct\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"default\":{\"backoff\":[1000,2000,3000],"
			"\"conceal\":3,\"jitterpc\":20,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"s\":[{\"mp\":{"
			"\"endpoint\":\"%s\",\"port\":%d,\"protocol\":\"h1\","
			"\"http_method\":\"GET\",\"http_url\":\"mp/${phase}\","
			"\"metadata\":[{\"phase\":\"\"}],"
			"\"http_multipart_ss_in\":true,"
			"\"retry\":\"default\",\"tls\":false}}]}",
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

	/* the raw socket server vhost */

	info.vhost_name	= "mp-srv";
	info.port	= port;
	info.protocols	= protocols_srv;
	info.options	= LWS_SERVER_OPTION_ONLY_RAW;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	for (n = 0; n < LWS_ARRAY_SIZE(phases); n++)
		if (!phases[n].completed)
			failed = 1;

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;

bail:
	lws_context_destroy(context);

	return 1;
}
