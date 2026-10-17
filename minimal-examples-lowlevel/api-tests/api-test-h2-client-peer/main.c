/*
 * lws-api-test-h2-client-peer
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * What an h2 client keeps of its own request, and what it takes from the
 * peer, when the peer's response is decoded into the same header table the
 * request was composed from.
 *
 * The "server" is a raw tcp fixture speaking just enough h2, in the same
 * process, so it can answer exactly as each case needs and see exactly the
 * :method, :scheme and :path of every request the client sent, on which of
 * the case's connections.  lws sends each field as a literal with a literal
 * name and no huffman coding, which is all the fixture decodes.
 *
 * Every request, in every case, must say :scheme "http": the fixture is h2
 * in the clear, where lws once claimed "https" whatever the connection.
 *
 * Each case starts one request with LCCSCF_H2_PRIOR_KNOWLEDGE:
 *
 *  - a GET, and a HEAD, answered 307 to another path: the redirected request
 *    must go with the method it was made with.  The response decoded into
 *    the request's header table used to take over the last of its request
 *    items, so the request was followed with ":method: 307"
 *
 *  - a GET answered 307 by a response carrying a ":method" of its own: a
 *    response has no request pseudo-headers (RFC 9113 8.3.2), so the client
 *    must GOAWAY PROTOCOL_ERROR rather than follow it, which once took the
 *    response's ":method" for the redirect's
 *
 *  - a GET answered with DATA before any HEADERS: a response starts with its
 *    HEADERS (RFC 9113 8.1), so the client must GOAWAY PROTOCOL_ERROR, and
 *    the app must never see the DATA as body
 *
 *  - a GET answered 200 on a connection kept warm, which the fixture PINGs
 *    once the stream has gone: an idle connection is still live, and must
 *    ACK it, where it once dropped everything that came, unparsed
 *
 *  - a GET whose response HEADERS has no END_HEADERS, its CONTINUATION
 *    coming only after the request timed out and its stream closed: the
 *    rest of the block must still be decoded, for the connection's hpack
 *    table, and not fail the connection, as an unexpected CONTINUATION did
 *
 * A case that does not reach its expected end inside CASE_WATCHDOG_S fails.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define CASE_WATCHDOG_S		10
#define TIMEOUT_S		2	/* context timeout_secs */
#define IDLE_MS			300	/* the stream gone, before the PING */
#define STALL_MS		3000	/* > TIMEOUT_S: the CONTINUATION's wait */
#define SETTLE_MS		500	/* then, for the client to answer */
#define MAX_SEEN		4

/* h2 frame types and flags the fixture deals in */
#define H2_DATA			0
#define H2_HEADERS		1
#define H2_SETTINGS		4
#define H2_PING			6
#define H2_GOAWAY		7
#define H2_CONTINUATION		9
#define H2F_ACK			1
#define H2F_END_STREAM		1
#define H2F_END_HEADERS		4
#define H2F_PADDED		8
#define H2F_PRIORITY		0x20
#define H2_PREFACE_LEN		24
#define H2_ERR_PROTOCOL_ERROR	1
#define FX_PING_DATA		"fxping01"

/* hpack static table indexes the fixture's responses use */
#define HP_METHOD		2
#define HP_STATUS		8
#define HP_CONTENT_LENGTH	28
#define HP_LOCATION		46

enum {
	HCP_REDIR_307,		/* 307 to /two, then 200 */
	HCP_REDIR_307_METHOD,	/* ... the 307 also saying :method: PUT */
	HCP_DATA_FIRST,		/* DATA, then the HEADERS */
	HCP_IDLE_PING,		/* 200, then a PING after IDLE_MS */
	HCP_HDRS_STALL,		/* HEADERS, the CONTINUATION after STALL_MS */
};

static const struct hcp_case {
	const char	*name;
	const char	*method;
	int		action;
	int		requests;	/* the fixture must see this many */
	const char	*want_method;	/* ... the last one with this :method */
	const char	*want_path;	/* ... and this :path */
	int		want_status;	/* the client's final status, or 0 */
	int		want_goaway;	/* the client must GOAWAY so, -1 not at
					 * all, or 0 for either */
} cases[] = {
	{ "GET answered 307 is followed with GET", "GET", HCP_REDIR_307,
	  2, "GET", "/two", 200, 0 },
	{ "HEAD answered 307 is followed with HEAD", "HEAD", HCP_REDIR_307,
	  2, "HEAD", "/two", 200, 0 },
	{ "a 307 with a :method of its own is refused",
	  "GET", HCP_REDIR_307_METHOD, 1, "GET", "/one", 0,
	  H2_ERR_PROTOCOL_ERROR },
	{ "DATA before the response HEADERS is refused", "GET",
	  HCP_DATA_FIRST, 1, "GET", "/one", 0, H2_ERR_PROTOCOL_ERROR },
	{ "a connection kept warm answers a PING", "GET", HCP_IDLE_PING,
	  1, "GET", "/one", 200, -1 },
	{ "a CONTINUATION after its stream timed out keeps the connection",
	  "GET", HCP_HDRS_STALL, 1, "GET", "/one", 0, -1 },
};

/* a request the fixture saw */
struct seen {
	char		method[16];
	char		path[64];
	char		scheme[8];
	int		conn;
};

/* one fixture connection */
struct fx_pss {
	struct lws	*wsi;
	uint8_t		rx[2048];
	uint8_t		tx[LWS_PRE + 1024];
	size_t		rxlen;
	size_t		txlen;
	int		conn;		/* 1-based, in this case */
	uint32_t	stall_sid;	/* HCP_HDRS_STALL: its CONTINUATION's */
	lws_sorted_usec_list_t	sul_later;	/* the case's next frame */
	lws_sorted_usec_list_t	sul_settle;
	uint8_t		preface_done;
	uint8_t		settling;	/* waiting on the client's answer */
};

static struct {
	struct seen	seen[MAX_SEEN];
	int		requests;
	int		accepted;
	int		closed;		/* fixture connections closed */
	int		bad;		/* a request the fixture couldn't read,
					 * or refused */
	int		goaway;		/* GOAWAYs from the client */
	uint32_t	goaway_err;	/* ... the last one's error code */
	uint8_t		ping_acked;	/* the client ACKed the fixture's PING */
	uint8_t		settled;	/* the client had its chance to answer
					 * the case's last frame */
} srv;

static struct {
	int		status;
	size_t		body;		/* response body bytes the app got */
	uint8_t		error;
	uint8_t		completed;
	uint8_t		closed;
} cli;

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result, cur = -1, failures, port = 7681, case_done;
static const char *server_addr = "127.0.0.1";

static void
case_evaluate(void);

/*
 * the fixture
 */

static void
fx_tx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	    const void *pl, size_t len)
{
	size_t room = sizeof(p->tx) - LWS_PRE;
	uint8_t *h;

	if (len > room - 9 || p->txlen > room - 9 - len) {
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

/* hpack: a literal field without indexing, its name a static table index */
static size_t
fx_hp_field(uint8_t *b, size_t room, unsigned int name_idx, const char *v)
{
	size_t vl = strlen(v);

	/* 4-bit name index prefix, 7-bit value length, both one byte here */
	if (name_idx < 15 || name_idx > 15 + 127 || vl > 126 || room < vl + 3)
		return 0;

	b[0] = 0x0f;
	b[1] = (uint8_t)(name_idx - 15);
	b[2] = (uint8_t)vl;
	memcpy(b + 3, v, vl);

	return vl + 3;
}

/* ... and one whose name index fits under its 4-bit prefix */
static size_t
fx_hp_field_short(uint8_t *b, size_t room, unsigned int name_idx,
		  const char *v)
{
	size_t vl = strlen(v);

	if (!name_idx || name_idx >= 15 || vl > 126 || room < vl + 2)
		return 0;

	b[0] = (uint8_t)name_idx;
	b[1] = (uint8_t)vl;
	memcpy(b + 2, v, vl);

	return vl + 2;
}

static void
fx_respond(struct fx_pss *p, uint32_t sid, const char *status,
	   const char *location, const char *method)
{
	uint8_t b[256];
	size_t n = 0, m;

	n += fx_hp_field_short(b + n, sizeof(b) - n, HP_STATUS, status);
	if (method)
		n += fx_hp_field_short(b + n, sizeof(b) - n, HP_METHOD, method);

	if (location) {
		m = fx_hp_field(b + n, sizeof(b) - n, HP_LOCATION, location);
		if (!m) {
			lwsl_err("%s: fixture: location too big\n", __func__);
			return;
		}
		n += m;
	}

	n += fx_hp_field(b + n, sizeof(b) - n, HP_CONTENT_LENGTH, "0");

	fx_tx_frame(p, H2_HEADERS, H2F_END_STREAM | H2F_END_HEADERS, sid, b, n);
}

static void
fx_settle_cb(lws_sorted_usec_list_t *sul)
{
	struct fx_pss *p = lws_container_of(sul, struct fx_pss, sul_settle);

	p->settling = 0;
	srv.settled = 1;
	case_evaluate();
}

/* the case's last frame, then time for the client to answer it */
static void
fx_last_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	      const void *pl, size_t len)
{
	fx_tx_frame(p, type, flags, sid, pl, len);
	p->settling = 1;
	lws_sul_schedule(context, 0, &p->sul_settle, fx_settle_cb,
			 SETTLE_MS * LWS_US_PER_MS);
}

static void
fx_idle_ping_cb(lws_sorted_usec_list_t *sul)
{
	struct fx_pss *p = lws_container_of(sul, struct fx_pss, sul_later);

	lwsl_user("%s: fixture: PING to the idle connection\n", __func__);
	fx_last_frame(p, H2_PING, 0, 0, FX_PING_DATA, 8);
}

static void
fx_cont_cb(lws_sorted_usec_list_t *sul)
{
	struct fx_pss *p = lws_container_of(sul, struct fx_pss, sul_later);
	uint8_t b[16];
	size_t n = fx_hp_field(b, sizeof(b), HP_CONTENT_LENGTH, "0");

	lwsl_user("%s: fixture: the CONTINUATION, after the stall\n",
		  __func__);
	fx_last_frame(p, H2_CONTINUATION, H2F_END_HEADERS, p->stall_sid, b, n);
}

/*
 * The request's :method, :scheme and :path, from a block of literal fields with
 * literal names and no huffman, which is how lws sends them
 */
static int
fx_read_request(const uint8_t *pl, size_t len, struct seen *s)
{
	size_t i = 0, nl, vl;

	while (i < len) {
		if (pl[i] != 0x00 || i + 2 > len)
			return 1;
		nl = pl[i + 1];
		if (nl & 0x80 || nl == 0x7f || i + 2 + nl + 1 > len)
			return 1;
		vl = pl[i + 2 + nl];
		if (vl & 0x80 || vl == 0x7f || i + 3 + nl + vl > len)
			return 1;

		if (nl == 7 && !memcmp(pl + i + 2, ":method", 7))
			lws_strnncpy(s->method, (const char *)pl + i + 3 + nl,
				     vl, sizeof(s->method));
		if (nl == 5 && !memcmp(pl + i + 2, ":path", 5))
			lws_strnncpy(s->path, (const char *)pl + i + 3 + nl,
				     vl, sizeof(s->path));
		if (nl == 7 && !memcmp(pl + i + 2, ":scheme", 7))
			lws_strnncpy(s->scheme, (const char *)pl + i + 3 + nl,
				     vl, sizeof(s->scheme));

		i += 3 + nl + vl;
	}

	return !s->method[0] || !s->path[0] || !s->scheme[0];
}

static void
fx_request(struct fx_pss *p, uint8_t flags, uint32_t sid, const uint8_t *pl,
	   size_t len)
{
	const struct hcp_case *c = &cases[cur];
	struct seen *s;
	char loc[64];

	if (!(flags & H2F_END_HEADERS)) {
		lwsl_err("%s: fixture: request in more than one frame\n",
			 __func__);
		srv.bad++;
		return;
	}

	if (flags & H2F_PADDED) {
		if (!len || pl[0] >= len) {
			srv.bad++;
			return;
		}
		len -= 1u + pl[0];
		pl++;
	}
	if (flags & H2F_PRIORITY) {
		if (len < 5) {
			srv.bad++;
			return;
		}
		pl += 5;
		len -= 5;
	}

	if (srv.requests == MAX_SEEN) {
		srv.bad++;
		return;
	}
	s = &srv.seen[srv.requests++];
	memset(s, 0, sizeof(*s));
	s->conn = p->conn;

	if (fx_read_request(pl, len, s)) {
		lwsl_err("%s: fixture: can't read the request\n", __func__);
		srv.bad++;
		return;
	}

	lwsl_user("%s: fixture: conn %d sid %u: %s %s (:scheme %s)\n",
		  __func__, p->conn, (unsigned int)sid, s->method, s->path,
		  s->scheme);

	/* the fixture is h2 in the clear: an "https" request is a lie */
	if (strcmp(s->scheme, "http")) {
		lwsl_err("%s: fixture: :scheme %s, on a cleartext connection\n",
			 __func__, s->scheme);
		srv.bad++;
	}

	switch (c->action) {
	case HCP_REDIR_307:
	case HCP_REDIR_307_METHOD:
		if (srv.requests == 1) {
			lws_snprintf(loc, sizeof(loc), "http://%s:%d/two",
				     server_addr, port);
			fx_respond(p, sid, "307", loc,
				   c->action == HCP_REDIR_307_METHOD ?
							"PUT" : NULL);
			break;
		}
		fx_respond(p, sid, "200", NULL, NULL);
		break;

	case HCP_DATA_FIRST:
		fx_tx_frame(p, H2_DATA, 0, sid, "hello", 5);
		fx_respond(p, sid, "200", NULL, NULL);
		break;

	case HCP_IDLE_PING:
		fx_respond(p, sid, "200", NULL, NULL);
		lws_sul_schedule(context, 0, &p->sul_later, fx_idle_ping_cb,
				 IDLE_MS * LWS_US_PER_MS);
		break;

	case HCP_HDRS_STALL: {
		uint8_t b[8];
		size_t n = fx_hp_field_short(b, sizeof(b), HP_STATUS, "200");

		/* the block, END_STREAM and all, but not END_HEADERS */
		fx_tx_frame(p, H2_HEADERS, H2F_END_STREAM, sid, b, n);
		p->stall_sid = sid;
		lws_sul_schedule(context, 0, &p->sul_later, fx_cont_cb,
				 STALL_MS * LWS_US_PER_MS);
		break;
	}
	}
}

/* a whole frame from the client */
static void
fx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	 const uint8_t *pl, size_t len)
{
	switch (type) {
	case H2_SETTINGS:
		if (!(flags & H2F_ACK))
			fx_tx_frame(p, H2_SETTINGS, H2F_ACK, 0, NULL, 0);
		break;

	case H2_PING:
		if (!(flags & H2F_ACK) && len == 8)
			fx_tx_frame(p, H2_PING, H2F_ACK, 0, pl, len);
		if ((flags & H2F_ACK) && len == 8 &&
		    !memcmp(pl, FX_PING_DATA, 8))
			srv.ping_acked = 1;
		break;

	case H2_HEADERS:
		fx_request(p, flags, sid, pl, len);
		break;

	case H2_GOAWAY:
		srv.goaway++;
		if (len >= 8)
			srv.goaway_err = lws_ser_ru32be(&pl[4]);
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
		p->wsi = wsi;
		p->conn = ++srv.accepted;
		/* the server preface: an empty SETTINGS */
		fx_tx_frame(p, H2_SETTINGS, 0, 0, NULL, 0);
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
		lws_sul_cancel(&p->sul_later);
		lws_sul_cancel(&p->sul_settle);
		/* nothing more can come on it than came */
		if (p->settling)
			srv.settled = 1;
		case_evaluate();
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
next_case(lws_sorted_usec_list_t *sul);

static void
case_end(int fail)
{
	case_done = 1;
	lws_sul_cancel(&sul_watchdog);

	lwsl_user("case %d: %s: %s\n", cur, fail ? "FAIL" : "PASS",
		  cases[cur].name);
	if (fail)
		failures++;

	/* let the close callbacks finish before the next case */
	lws_sul_schedule(context, 0, &sul_next, next_case, 0);
}

static void
case_evaluate(void)
{
	const struct hcp_case *c = &cases[cur];
	const struct seen *s;
	int fail = 0;

	if (case_done || (!cli.error && !cli.completed && !cli.closed))
		return;

	/* a GOAWAY is only all in once the connection has gone */
	if (c->want_goaway > 0 && srv.closed < srv.accepted)
		return;
	/* ...or, for none, once the client had every chance to send one */
	if (c->want_goaway < 0 && !srv.settled)
		return;

	if (srv.bad) {
		lwsl_err("%s: the fixture couldn't read, or refused, %d "
			 "requests\n", __func__, srv.bad);
		fail = 1;
	}

	if (srv.requests != c->requests) {
		lwsl_err("%s: fixture saw %d requests, wanted %d\n", __func__,
			 srv.requests, c->requests);
		fail = 1;
	}

	if (srv.requests) {
		s = &srv.seen[srv.requests - 1];
		if (strcmp(s->method, c->want_method) ||
		    strcmp(s->path, c->want_path)) {
			lwsl_err("%s: last request was '%s %s', wanted "
				 "'%s %s'\n", __func__, s->method, s->path,
				 c->want_method, c->want_path);
			fail = 1;
		}
	}

	if (c->want_goaway < 0 && srv.goaway) {
		lwsl_err("%s: client sent GOAWAY %u\n", __func__,
			 (unsigned int)srv.goaway_err);
		fail = 1;
	}

	if (c->action == HCP_IDLE_PING && !srv.ping_acked) {
		lwsl_err("%s: the idle connection didn't ACK the PING\n",
			 __func__);
		fail = 1;
	}

	if (c->want_goaway > 0 &&
	    (!srv.goaway || srv.goaway_err != (uint32_t)c->want_goaway)) {
		lwsl_err("%s: no GOAWAY %d from the client (%d, err %u)\n",
			 __func__, c->want_goaway, srv.goaway,
			 (unsigned int)srv.goaway_err);
		fail = 1;
	}

	if (!c->want_status && (cli.completed || cli.body)) {
		lwsl_err("%s: client completed %d, with %u body bytes, from a "
			 "response it must refuse\n", __func__, cli.completed,
			 (unsigned int)cli.body);
		fail = 1;
	}

	if (c->want_status &&
	    (!cli.completed || cli.status != c->want_status)) {
		lwsl_err("%s: client ended with status %d (completed %d, "
			 "error %d), wanted %d\n", __func__, cli.status,
			 cli.completed, cli.error, c->want_status);
		fail = 1;
	}

	case_end(fail);
}

static void
case_watchdog(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: case %d did not finish: client status %d err %d "
		 "completed %d closed %d, fixture %d requests %d conns\n",
		 __func__, cur, cli.status, cli.error, cli.completed,
		 cli.closed, srv.requests, srv.accepted);
	case_end(1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	char rbuf[LWS_PRE + 256], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE;

	/* only the current case's request: an earlier one may still close */
	if (cur < 0 || cur >= (int)LWS_ARRAY_SIZE(cases) ||
	    lws_get_opaque_user_data(wsi) != &cases[cur])
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli.error = 1;
		case_evaluate();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: status %d\n", __func__, cli.status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		cli.body += len;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("%s: completed\n", __func__);
		cli.completed = 1;
		case_evaluate();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		cli.closed = 1;
		case_evaluate();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	cur++;
	if (cur == (int)LWS_ARRAY_SIZE(cases)) {
		result = !!failures;
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("case %d: %s\n", cur, cases[cur].name);

	memset(&srv, 0, sizeof(srv));
	memset(&cli, 0, sizeof(cli));
	case_done = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, case_watchdog,
			 CASE_WATCHDOG_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = port;
	i.path = "/one";
	i.method = cases[cur].method;
	i.protocol = "h2-peer";
	i.opaque_user_data = (void *)&cases[cur];
	/* the connection is to outlive the case's stream */
	if (cases[cur].action == HCP_IDLE_PING ||
	    cases[cur].action == HCP_HDRS_STALL)
		i.keep_warm_secs = 5;
	i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		case_end(1);
	}
}

static const struct lws_protocols protocols_srv[] = {
	{ "fake-h2", callback_fx, sizeof(struct fx_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "h2-peer", callback_cli, 0, 0, 0, NULL, 0 },
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
	/* HCP_HDRS_STALL's stream is to time out before its CONTINUATION */
	info.timeout_secs = TIMEOUT_S;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: h2 client against a scripted peer\n");

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
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(cases));

	return result;
}
