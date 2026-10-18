/*
 * lws-api-test-proxy-v2-peer-limits
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Per-client peer limits behind a trusted PROXY v2 sender (G-196).
 *
 * A server trusts loopback, where all our connections come from, to send a
 * PROXY v2 header first.  Each connection sends a header naming a client,
 * then all or part of a GET.  Since every one of them comes through one
 * "proxy", the limits only mean anything if they apply to the client each
 * header names, not to the proxy.
 *
 * With ip_limit_wsi 2, each connection sends a whole GET and is either
 * answered, which it stays open after, holding its place against the limit,
 * or dropped unanswered:
 *
 *  - two connections naming client A are served;
 *
 *  - one naming client B is served too: A having spent its budget must not
 *    spend B's;
 *
 *  - a third naming A is dropped, and pl_notify_cb is told it was A, not the
 *    proxy;
 *
 *  - a LOCAL header, the proxy's own connection, counts against the proxy,
 *    which has used none of its budget, and is served;
 *
 *  - a second naming B is served, a third dropped.
 *
 * With ip_limit_ah 1, and nothing else limited:
 *
 *  - a connection naming A sends only the start of its GET, so it holds its
 *    ah, and is neither answered nor dropped;
 *
 *  - a second naming A sends a whole GET, but must wait for an ah, so it is
 *    not answered either;
 *
 *  - one naming B sends a whole GET and is served at once: A holding its
 *    one ah must not hold B's.
 *
 * While a connection is held, the server must wait for something to happen,
 * not spin on it: a connection left waiting for an ah with POLLIN on is
 * reported readable on every poll, and turned away unread every time
 * (G-209).  The event loop's turns that did not sleep are counted by how
 * long they took: a loop that waits properly spends at most the last
 * millisecond before each timer that way, polling without waiting because
 * the wait is truncated to whole ms, while a spinning one spends the whole
 * held window.
 */

#include <libwebsockets.h>
#include <string.h>

#define PVL_CLIENT_A	"192.0.2.10"
#define PVL_CLIENT_B	"192.0.2.20"
#define PVL_LOCAL	NULL		/* a LOCAL header, the proxy itself */
#define PVL_STEP_US	(3 * LWS_US_PER_SEC)
/* how long a connection that should be left waiting is watched for */
#define PVL_HELD_US	(500 * LWS_US_PER_MS)
/* an event loop turn shorter than this did not sleep */
#define PVL_SLEPT_US	LWS_US_PER_MS
/* how long of a held window the loop may spend not sleeping */
#define PVL_BUSY_MAX_US	(100 * LWS_US_PER_MS)

enum pvl_outcome {
	PVL_SERVED,	/* answered, and left open */
	PVL_DROPPED,	/* closed unanswered */
	PVL_HELD,	/* neither, for PVL_HELD_US */
};

struct pvl_step {
	const char		*name;
	const char		*client;	/* who the header names */
	enum pvl_outcome	expect;
	char			partial;	/* only the start of a GET */
};

static const struct pvl_step pvl_steps_wsi[] = {
	{ "first connection naming A is served",	PVL_CLIENT_A,
	  PVL_SERVED, 0 },
	{ "second connection naming A is served",	PVL_CLIENT_A,
	  PVL_SERVED, 0 },
	{ "B is served although A is at its limit",	PVL_CLIENT_B,
	  PVL_SERVED, 0 },
	{ "third connection naming A is dropped",	PVL_CLIENT_A,
	  PVL_DROPPED, 0 },
	{ "the proxy's own LOCAL connection is served",	PVL_LOCAL,
	  PVL_SERVED, 0 },
	{ "second connection naming B is served",	PVL_CLIENT_B,
	  PVL_SERVED, 0 },
	{ "third connection naming B is dropped",	PVL_CLIENT_B,
	  PVL_DROPPED, 0 },
};

static const struct pvl_step pvl_steps_ah[] = {
	{ "A holding an ah with a partial request",	PVL_CLIENT_A,
	  PVL_HELD, 1 },
	{ "A's second request waits for an ah",		PVL_CLIENT_A,
	  PVL_HELD, 0 },
	{ "B is served although A holds its ah",	PVL_CLIENT_B,
	  PVL_SERVED, 0 },
};

static const char * const outcome_names[] = { "served", "dropped", "held" };

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_step;
static const char *server = "localhost";
static const struct pvl_step *steps;
static int nsteps, port, step, fails, finished, judged, answered, closed;
static int notifies, check_notify;
static lws_usec_t busy_us;	/* this step's event loop turns not sleeping */
static char notified[64];

static void
pvl_next(lws_sorted_usec_list_t *sul);

static void
pvl_judge(const char *why)
{
	const struct pvl_step *s = &steps[step];
	enum pvl_outcome got;

	if (judged)
		return;
	judged = 1;
	lws_sul_cancel(&sul_step);

	got = answered ? PVL_SERVED : (closed ? PVL_DROPPED : PVL_HELD);

	if (why) {
		lwsl_err("  FAIL: %s: %s\n", s->name, why);
		fails++;
	} else
		if (got != s->expect) {
			lwsl_err("  FAIL: %s: %s\n", s->name,
				 outcome_names[got]);
			fails++;
		} else
			lwsl_user("  PASS: %s\n", s->name);

	if (s->expect == PVL_HELD) {
		lwsl_user("  the event loop did not sleep for %dms of it\n",
			  (int)(busy_us / LWS_US_PER_MS));
		if (busy_us > PVL_BUSY_MAX_US) {
			lwsl_err("  FAIL: %s: the server spun meanwhile\n",
				 s->name);
			fails++;
		}
	}

	lws_sul_schedule(context, 0, &sul_step, pvl_next, 1);
}

static void
pvl_deadline(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	/* for a step that should be held, that is the answer */
	pvl_judge(steps[step].expect == PVL_HELD ? NULL :
						  "neither served nor dropped");
}

/* the server: anything that gets as far as a whole request is answered */

static int
pvl_srv_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	uint8_t hb[LWS_PRE + 256], *start = &hb[LWS_PRE], *p = start,
		*end = &hb[sizeof(hb) - 1];

	if (reason == LWS_CALLBACK_HTTP) {
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 0, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
pvl_notify_cb(struct lws_context *ctx, lws_sockfd_type sockfd,
	      lws_sockaddr46 *sa46)
{
	(void)ctx;
	(void)sockfd;

	notifies++;
	lws_sa46_write_numeric_address(sa46, notified, sizeof(notified));

	return 0;
}

/* the "proxy": a raw client sending a PROXY v2 header, then (part of) a GET */

static int
pvl_cli_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	uint8_t tx[LWS_PRE + LWS_PROXY_V2_MAX + 64];
	const struct pvl_step *s;
	lws_proxy_v2_t pv;
	int n;

	(void)user;

	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(step + 1))
		/* an earlier step's connection, still open to hold its place */
		return 0;
	s = &steps[step];

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		memset(&pv, 0, sizeof(pv));
		if (s->client) {
			if (lws_sa46_parse_numeric_address(s->client,
							   &pv.src) ||
			    lws_sa46_parse_numeric_address("192.0.2.1",
							   &pv.dst))
				return -1;
			sa46_sockport(&pv.src, htons(40000));
			sa46_sockport(&pv.dst, htons(443));
		} else
			pv.local = 1;

		n = lws_proxy_v2_render(&pv, tx + LWS_PRE, LWS_PROXY_V2_MAX);
		if (n <= 0)
			return -1;
		n += lws_snprintf((char *)tx + LWS_PRE + n,
				  sizeof(tx) - LWS_PRE - (size_t)n,
				  "GET / HTTP/1.1\x0d\x0aHost: pvl\x0d\x0a%s",
				  s->partial ? "" : "\x0d\x0a");
		if (lws_write(wsi, tx + LWS_PRE, (size_t)n, LWS_WRITE_RAW) != n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len >= 12 && !strncmp((const char *)in, "HTTP/1.1 200", 12))
			answered = 1;
		pvl_judge(answered ? NULL : "unexpected answer");
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		closed = 1;
		pvl_judge(NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		pvl_judge(in ? (const char *)in : "connection error");
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols pvl_srv_protocols[] = {
	{ "pvl-srv", pvl_srv_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols pvl_cli_protocols[] = {
	{ "pvl-cli", pvl_cli_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
pvl_next(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	(void)sul;

	if (check_notify && step >= 0 && steps[step].expect == PVL_DROPPED) {
		/* the connection dropped must be reported as its client's */
		if (strcmp(notified, steps[step].client)) {
			lwsl_err("  FAIL: pl_notify_cb was told '%s', not "
				 "'%s'\n", notified, steps[step].client);
			fails++;
		} else
			lwsl_user("  PASS: pl_notify_cb was told it was %s\n",
				  notified);
		notified[0] = '\0';
	}

	if (++step == nsteps) {
		finished = 1;
		lws_cancel_service(context);
		return;
	}

	judged		= 0;
	answered	= 0;
	closed		= 0;
	busy_us		= 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server;
	i.host			= server;
	i.port			= port;
	i.method		= "RAW";
	i.protocol		= pvl_cli_protocols[0].name;
	i.local_protocol_name	= pvl_cli_protocols[0].name;
	i.opaque_user_data	= (void *)(intptr_t)(step + 1);

	lws_sul_schedule(context, 0, &sul_step, pvl_deadline,
			 steps[step].expect == PVL_HELD ? PVL_HELD_US :
							  PVL_STEP_US);

	if (!lws_client_connect_via_info(&i))
		pvl_judge("connect failed");
}

/* one phase: its own context, with the limits given */

static int
pvl_phase(const char *what, const struct pvl_step *s, int n,
	  unsigned short limit_wsi, unsigned short limit_ah)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	lws_usec_t t;
	int m = 0;

	lwsl_user("%s\n", what);

	steps		= s;
	nsteps		= n;
	step		= -1;
	finished	= 0;
	notifies	= 0;
	notified[0]	= '\0';
	check_notify	= !!limit_wsi;

	lws_context_info_defaults(&info, NULL);
	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.ip_limit_wsi		= limit_wsi;
	info.ip_limit_ah		= limit_ah;
	info.pl_notify_cb		= pvl_notify_cb;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port		= 0;
	info.protocols		= pvl_srv_protocols;
	info.vhost_name		= "pvl-srv";
	/* every connection of ours comes from loopback, our "proxy" */
#if defined(LWS_WITH_IPV6)
	info.proxy_v2_trusted	= "127.0.0.1, ::1";
#else
	info.proxy_v2_trusted	= "127.0.0.1";
#endif
	vh = lws_create_vhost(context, &info);
	if (!vh)
		goto bail;
	port = lws_get_vhost_listen_port(vh);

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.protocols		= pvl_cli_protocols;
	info.vhost_name		= "pvl-cli";
	info.proxy_v2_trusted	= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_step, pvl_next, 1);

	while (m >= 0 && !finished) {
		t = lws_now_usecs();
		m = lws_service(context, 0);
		t = lws_now_usecs() - t;
		if (t < PVL_SLEPT_US)
			busy_us += t;
	}

	lws_sul_cancel(&sul_step);
	lws_context_destroy(context);

	if (!finished) {
		lwsl_err("service loop ended early\n");
		return 1;
	}

	return 0;

bail:
	lwsl_err("setup failed\n");
	lws_context_destroy(context);

	return 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	/* only for the builtin cmdline options, eg, -d */
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	lwsl_user("LWS API selftest: PROXY v2 peer limits\n");

	if (pvl_phase("ip_limit_wsi 2:", pvl_steps_wsi,
		      (int)LWS_ARRAY_SIZE(pvl_steps_wsi), 2, 0) ||
	    pvl_phase("ip_limit_ah 1:", pvl_steps_ah,
		      (int)LWS_ARRAY_SIZE(pvl_steps_ah), 0, 1))
		fails++;

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
