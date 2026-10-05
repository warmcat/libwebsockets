/*
 * lws-api-test-h2-client-queue
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An h2 client pipelining requests on to one connection (LCCSCF_PIPELINE)
 * queues the ones the peer's SETTINGS_MAX_CONCURRENT_STREAMS does not let
 * it open yet, and sends them as streams close.  This exercises what becomes
 * of the queue when the peer never lets a stream close to admit them.
 *
 * The "server" is a raw tcp fixture speaking just enough h2 to advertise a
 * stream limit of 0, refuse the first stream with RST_STREAM, answer the
 * client's SETTINGS and PINGs, and keep the connection alive with PINGs of
 * its own (which the client must answer, and which re-arm its connection
 * timeout).  A real h2 server would not stay like that, an errant or hostile
 * one may.  Two requests are started back to back so the second queues on
 * the first's connection.
 *
 *  - leg 0: the limit stays 0 for ever.  The queued request must fail to the
 *    app with CLIENT_CONNECTION_ERROR inside the context's timeout_secs,
 *    while the fixture still holds the connection open (so it is the queued
 *    request's own deadline that failed it, not the connection going away),
 *    and the connection, left with nothing to do, must then idle out and
 *    close inside keep_warm_secs.
 *
 *  - leg 1: a later SETTINGS raises the limit to 1.  The queued request must
 *    then be sent, and is answered 200.
 *
 * A leg that does not reach its expected end inside LEG_WATCHDOG_S fails.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define TIMEOUT_S		3	/* context timeout_secs */
#define KEEP_WARM_S		2	/* the client's keep_warm_secs */
#define PING_INTERVAL_MS	300	/* the fixture's PINGs, < TIMEOUT_S */
#define RAISE_AFTER_MS		500	/* leg 1: SETTINGS raising the limit */
#define LEG_WATCHDOG_S		20
#define MAX_REQ			2

/* h2 frame types and flags the fixture deals in */
#define H2_HEADERS		1
#define H2_RST_STREAM		3
#define H2_SETTINGS		4
#define H2_PING			6
#define H2_GOAWAY		7
#define H2F_ACK			1
#define H2F_END_STREAM		1
#define H2F_END_HEADERS		4
#define H2SET_MAX_CONCURRENT	3
#define H2_ERR_REFUSED_STREAM	7
#define H2_PREFACE_LEN		24

struct leg {
	const char	*name;
	uint8_t		raise;		/* SETTINGS raises the limit later */
};

static const struct leg legs[] = {
	{ "the peer's stream limit stays 0: the queued request fails in time "
	  "and the connection idles out", 0 },
	{ "the peer raises its stream limit: the queued request goes", 1 },
};

/* one fixture connection */
struct fx_pss {
	struct lws		*wsi;
	lws_sorted_usec_list_t	sul_ping;
	lws_sorted_usec_list_t	sul_raise;
	uint8_t			rx[1024];
	uint8_t			tx[LWS_PRE + 512];
	size_t			rxlen;
	size_t			txlen;
	uint8_t			preface_done;
	uint8_t			raised;		/* the limit is 1 now */
};

struct req {
	uint8_t		error;		/* CLIENT_CONNECTION_ERROR */
	uint8_t		closed;		/* CLOSED_CLIENT_HTTP */
	uint8_t		completed;	/* COMPLETED_CLIENT_HTTP */
	uint8_t		conn_open_at_error; /* the fixture still had the
					     * connection when we failed */
	int		status;
};

static struct {
	int		accepted;	/* fixture connections adopted */
	int		closed;		/* ... and closed */
	int		refused;	/* streams RST_STREAMed */
	int		answered;	/* streams answered 200 */
	int		goaway;		/* GOAWAYs from the client */
} srv;

static struct req reqs[MAX_REQ];
static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result, cur = -1, failures, port = 7681, leg_done;
static const char *server_addr = "127.0.0.1";

static void
leg_evaluate(void);

/*
 * the fixture
 */

static void
fx_tx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	    const void *pl, size_t len)
{
	size_t room = sizeof(p->tx) - LWS_PRE;
	uint8_t *h;

	if (p->txlen > room || len > room - p->txlen ||
	    9 > room - p->txlen - len) {
		lwsl_err("%s: fixture tx overflow\n", __func__);
		return;
	}

	h = p->tx + LWS_PRE + p->txlen;

	h[0] = (uint8_t)(len >> 16);
	h[1] = (uint8_t)(len >> 8);
	h[2] = (uint8_t)len;
	h[3] = type;
	h[4] = flags;
	lws_ser_wu32be(&h[5], sid);
	if (len)
		memcpy(h + 9, pl, len);
	p->txlen += 9 + len;

	lws_callback_on_writable(p->wsi);
}

static void
fx_tx_settings_max_streams(struct fx_pss *p, uint32_t max)
{
	uint8_t s[6];

	lws_ser_wu16be(&s[0], H2SET_MAX_CONCURRENT);
	lws_ser_wu32be(&s[2], max);
	fx_tx_frame(p, H2_SETTINGS, 0, 0, s, sizeof(s));
}

static void
fx_ping_cb(lws_sorted_usec_list_t *sul)
{
	struct fx_pss *p = lws_container_of(sul, struct fx_pss, sul_ping);
	uint8_t pl[8];

	memset(pl, 0x5a, sizeof(pl));
	fx_tx_frame(p, H2_PING, 0, 0, pl, sizeof(pl));

	lws_sul_schedule(context, 0, &p->sul_ping, fx_ping_cb,
			 PING_INTERVAL_MS * LWS_US_PER_MS);
}

static void
fx_raise_cb(lws_sorted_usec_list_t *sul)
{
	struct fx_pss *p = lws_container_of(sul, struct fx_pss, sul_raise);

	lwsl_user("%s: fixture: raising the stream limit to 1\n", __func__);
	p->raised = 1;
	fx_tx_settings_max_streams(p, 1);
}

/* a whole frame from the client */
static void
fx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	 const uint8_t *pl, size_t len)
{
	uint8_t rst[4], st200 = 0x88; /* hpack: indexed :status 200 */

	switch (type) {
	case H2_SETTINGS:
		if (!(flags & H2F_ACK))
			fx_tx_frame(p, H2_SETTINGS, H2F_ACK, 0, NULL, 0);
		break;

	case H2_PING:
		if (!(flags & H2F_ACK) && len == 8)
			fx_tx_frame(p, H2_PING, H2F_ACK, 0, pl, len);
		break;

	case H2_HEADERS:
		if (p->raised) {
			lwsl_user("%s: fixture: answering sid %u 200\n",
				  __func__, (unsigned int)sid);
			srv.answered++;
			fx_tx_frame(p, H2_HEADERS,
				    H2F_END_STREAM | H2F_END_HEADERS, sid,
				    &st200, 1);
			break;
		}

		lwsl_user("%s: fixture: refusing sid %u\n", __func__,
			  (unsigned int)sid);
		lws_ser_wu32be(rst, H2_ERR_REFUSED_STREAM);
		fx_tx_frame(p, H2_RST_STREAM, 0, sid, rst, sizeof(rst));
		if (!srv.refused++ && legs[cur].raise)
			lws_sul_schedule(context, 0, &p->sul_raise,
					 fx_raise_cb,
					 RAISE_AFTER_MS * LWS_US_PER_MS);
		break;

	case H2_GOAWAY:
		srv.goaway++;
		break;

	default:
		break;
	}
}

static int
fx_rx(struct fx_pss *p, const uint8_t *in, size_t len)
{
	if (p->rxlen + len > sizeof(p->rx)) {
		lwsl_err("%s: fixture rx overflow\n", __func__);
		return -1;
	}
	memcpy(p->rx + p->rxlen, in, len);
	p->rxlen += len;

	if (!p->preface_done) {
		if (p->rxlen < H2_PREFACE_LEN)
			return 0;
		if (memcmp(p->rx, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
			   H2_PREFACE_LEN)) {
			lwsl_err("%s: fixture: not an h2 preface\n", __func__);
			return -1;
		}
		p->rxlen -= H2_PREFACE_LEN;
		memmove(p->rx, p->rx + H2_PREFACE_LEN, p->rxlen);
		p->preface_done = 1;
	}

	while (p->rxlen >= 9) {
		size_t fl = ((size_t)p->rx[0] << 16) |
			    ((size_t)p->rx[1] << 8) | p->rx[2], o, rest;

		if (fl > sizeof(p->rx) - 9) {
			lwsl_err("%s: fixture: frame too big\n", __func__);
			return -1;
		}
		if (p->rxlen < 9 + fl)
			break;

		fx_frame(p, p->rx[3], p->rx[4],
			 lws_ser_ru32be(&p->rx[5]) & 0x7fffffff,
			 p->rx + 9, fl);

		/*
		 * what follows the frame, bounded itself before it's moved,
		 * from where it starts inside the buffer: a frame filling the
		 * buffer leaves o one past its end, with nothing to move
		 */
		o = 9 + fl;
		rest = p->rxlen - o;
		if (rest) {
			if (o >= sizeof(p->rx) || rest > sizeof(p->rx) - o) {
				lwsl_err("%s: fixture: rx accounting\n",
					 __func__);
				return -1;
			}
			memmove(p->rx, p->rx + o, rest);
		}
		p->rxlen = rest;
	}

	return 0;
}

static int
callback_fx(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct fx_pss *p = (struct fx_pss *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		srv.accepted++;
		lwsl_user("%s: fixture: connection %d adopted\n", __func__,
			  srv.accepted);
		p->wsi = wsi;
		/* the server preface: our SETTINGS, with a stream limit of 0 */
		fx_tx_settings_max_streams(p, 0);
		lws_sul_schedule(context, 0, &p->sul_ping, fx_ping_cb,
				 PING_INTERVAL_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (fx_rx(p, (const uint8_t *)in, len))
			return -1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!p->txlen)
			break;
		if (lws_write(wsi, p->tx + LWS_PRE, p->txlen,
			      LWS_WRITE_RAW) != (int)p->txlen) {
			lwsl_err("%s: fixture write failed\n", __func__);
			return -1;
		}
		p->txlen = 0;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		srv.closed++;
		lwsl_user("%s: fixture: connection closed (%d of %d)\n",
			  __func__, srv.closed, srv.accepted);
		lws_sul_cancel(&p->sul_ping);
		lws_sul_cancel(&p->sul_raise);
		/* a leg ends with the connection given up */
		leg_evaluate();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * the client
 */

static void
next_leg(lws_sorted_usec_list_t *sul);

static void
leg_evaluate(void)
{
	const struct leg *l = &legs[cur];
	int fail = 0;

	if (leg_done)
		return;

	/* the first request must have ended, however */
	if (!reqs[0].error && !reqs[0].closed && !reqs[0].completed)
		return;

	if (l->raise) {
		if (!reqs[1].completed && !reqs[1].error)
			return;
		if (!reqs[1].completed || reqs[1].status != 200) {
			lwsl_err("%s: queued request not answered 200 after "
				 "the limit was raised (completed %d, status "
				 "%d, error %d)\n", __func__, reqs[1].completed,
				 reqs[1].status, reqs[1].error);
			fail = 1;
		}
		if (!srv.answered) {
			lwsl_err("%s: fixture answered no stream\n", __func__);
			fail = 1;
		}
	} else {
		if (!reqs[1].error && !reqs[1].completed)
			return;
		if (reqs[1].completed) {
			lwsl_err("%s: queued request completed on a limit of "
				 "0\n", __func__);
			fail = 1;
		}
		if (!reqs[1].conn_open_at_error) {
			lwsl_err("%s: queued request failed only because the "
				 "connection went away\n", __func__);
			fail = 1;
		}
	}

	/* either way the connection must then be given up */
	if (!fail && srv.closed < srv.accepted)
		return;

	if (!srv.refused) {
		lwsl_err("%s: fixture refused no stream\n", __func__);
		fail = 1;
	}

	leg_done = 1;
	lws_sul_cancel(&sul_watchdog);

	lwsl_user("leg %d: %s: %s\n", cur, fail ? "FAIL" : "PASS", l->name);
	if (fail)
		failures++;

	/* let the close callbacks finish before the next leg */
	lws_sul_schedule(context, 0, &sul_next, next_leg, 0);
}

static void
leg_watchdog(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: leg %d did not finish: req0 err %d closed %d compl %d, "
		 "req1 err %d closed %d compl %d, fixture %d/%d conns, %d "
		 "refused, %d answered\n", __func__, cur, reqs[0].error,
		 reqs[0].closed, reqs[0].completed, reqs[1].error,
		 reqs[1].closed, reqs[1].completed, srv.closed, srv.accepted,
		 srv.refused, srv.answered);
	failures++;
	leg_done = 1;
	lws_sul_schedule(context, 0, &sul_next, next_leg, 0);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct req *r = (struct req *)lws_get_opaque_user_data(wsi);
	char rbuf[LWS_PRE + 256], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE, n;

	if (!r)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	n = (int)(r - &reqs[0]);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: request %d: connection error: %s\n", __func__,
			  n, in ? (const char *)in : "(null)");
		r->error = 1;
		r->conn_open_at_error = srv.closed < srv.accepted;
		leg_evaluate();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		r->status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: request %d: status %d\n", __func__, n,
			  r->status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("%s: request %d: completed\n", __func__, n);
		r->completed = 1;
		leg_evaluate();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_user("%s: request %d: closed\n", __func__, n);
		r->closed = 1;
		leg_evaluate();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
req_start(int n)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = port;
	i.path = n ? "/queued" : "/first";
	i.method = "GET";
	i.protocol = "h2-queue";
	i.opaque_user_data = &reqs[n];
	i.keep_warm_secs = KEEP_WARM_S;
	i.ssl_connection = LCCSCF_PIPELINE | LCCSCF_H2_PRIOR_KNOWLEDGE;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: request %d: connect failed\n", __func__, n);
		return 1;
	}

	return 0;
}

static void
next_leg(lws_sorted_usec_list_t *sul)
{
	cur++;
	if (cur == (int)LWS_ARRAY_SIZE(legs)) {
		result = !!failures;
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("leg %d: %s\n", cur, legs[cur].name);

	memset(&srv, 0, sizeof(srv));
	memset(reqs, 0, sizeof(reqs));
	leg_done = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, leg_watchdog,
			 LEG_WATCHDOG_S * LWS_US_PER_SEC);

	/*
	 * Back to back: the second finds the first on the vhost's active
	 * connections and queues on it
	 */
	if (req_start(0) || req_start(1)) {
		failures++;
		leg_done = 1;
		lws_sul_cancel(&sul_watchdog);
		lws_sul_schedule(context, 0, &sul_next, next_leg, 0);
	}
}

static const struct lws_protocols protocols_srv[] = {
	{ "fake-h2", callback_fx, sizeof(struct fx_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "h2-queue", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;
	info.timeout_secs = TIMEOUT_S;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: h2 client queue against the peer's "
		  "stream limit\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the raw fixture "server" */

	info.port = port;
	info.vhost_name = "fx";
	info.protocols = protocols_srv;
	info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "fake-h2";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create fixture vhost\n");
		goto bail;
	}

	/* client vhost, no listener */

	info.options &= ~(uint64_t)
			LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	result = 1;
	lws_sul_schedule(context, 0, &sul_next, next_leg, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d legs failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(legs));

	return result;
}
