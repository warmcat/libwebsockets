/*
 * lws-api-test-h2-server-slow-response
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An h2 server connection whose client is waiting on responses the server
 * has not finished preparing is not idle, however long the preparation
 * takes.  The vhost's keepalive_timeout is how long a server waits on a
 * client with nothing outstanding; it must not close a connection out from
 * under streams still being answered, eg, by a reverse proxy whose onward
 * server is slow, or by a plugin building the response on a thread.  Closing
 * the network connection fails every stream on it.
 *
 * The server is an lws h2 server (cleartext, prior knowledge) with a 1s
 * keepalive_timeout, whose callback answers each request 3s after it
 * arrives.  The client is a raw tcp fixture speaking just enough h2 to send
 * two requests on one connection and then nothing at all, so nothing it
 * does renews the server's timeouts.  Both responses must arrive complete,
 * and once they have, the server must still close the now idle connection
 * after its keepalive_timeout.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define SR_TIMEOUT_S		10	/* context timeout_secs */
#define SR_KEEPALIVE_S		1	/* server vhost keepalive_timeout */
#define SR_DELAY_MS		3000	/* > keepalive, < timeout_secs */
#define SR_IDLE_CLOSE_MAX_MS	((SR_KEEPALIVE_S * 2 + 2) * 1000)
#define SR_WATCHDOG_S		20
#define SR_STREAMS		2

/* h2 frame types and flags the fixture deals in */
#define SR_H2_DATA		0
#define SR_H2_HEADERS		1
#define SR_H2_RST_STREAM	3
#define SR_H2_SETTINGS		4
#define SR_H2_PING		6
#define SR_H2_GOAWAY		7
#define SR_H2F_ACK		1
#define SR_H2F_END_STREAM	1
#define SR_H2F_END_HEADERS	4

static const char body[] = "the answer, after a while\n";

/* the server */

struct srv_pss {
	struct lws		*wsi;
	lws_sorted_usec_list_t	sul_delay;
	uint8_t			due;
};

/* one fixture client stream */
struct fx_stream {
	lws_usec_t		end;
	size_t			rx;
	uint8_t			status_200;
	uint8_t			ended;
};

/* the fixture client connection */
struct fx_pss {
	struct lws		*wsi;
	uint8_t			rx[4096];
	uint8_t			tx[LWS_PRE + 512];
	size_t			rxlen;
	size_t			txlen;
};

static struct {
	struct fx_stream	s[SR_STREAMS];
	lws_usec_t		sent;
	lws_usec_t		closed;
	uint8_t			failed;
} fx;

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog;
static int result = 1, port = 7681, done;
static const char *server_addr = "127.0.0.1";

static void
finish(int fail)
{
	if (done)
		return;
	done = 1;
	result = fail;
	lws_sul_cancel(&sul_watchdog);
	lws_default_loop_exit(context);
}

static void
srv_delay_cb(lws_sorted_usec_list_t *sul)
{
	struct srv_pss *pss = lws_container_of(sul, struct srv_pss, sul_delay);

	pss->due = 1;
	lws_callback_on_writable(pss->wsi);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct srv_pss *pss = (struct srv_pss *)user;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		lwsl_user("%s: request, answering in %dms\n", __func__,
			  SR_DELAY_MS);
		pss->wsi = wsi;
		lws_sul_schedule(lws_get_context(wsi), 0, &pss->sul_delay,
				 srv_delay_cb, SR_DELAY_MS * LWS_US_PER_MS);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* WRITEABLE can come unasked on h2: only answer when due */
		if (!pss || !pss->due)
			return 0;
		pss->due = 0;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", sizeof(body) - 1,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		memcpy(start, body, sizeof(body) - 1);
		if (lws_write(wsi, start, sizeof(body) - 1,
			      LWS_WRITE_HTTP_FINAL) != (int)sizeof(body) - 1)
			return 1;

		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss)
			lws_sul_cancel(&pss->sul_delay);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * the fixture client
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

static void
fx_send_requests(struct fx_pss *p)
{
	/*
	 * hpack: indexed :method GET, :scheme http, :path /, and :authority
	 * as a literal without indexing, name index 1
	 */
	static const uint8_t req[] = {
		0x82, 0x86, 0x84, 0x01, 9,
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'
	};
	size_t n;

	memcpy(p->tx + LWS_PRE, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
	p->txlen = 24;
	fx_tx_frame(p, SR_H2_SETTINGS, 0, 0, NULL, 0);

	for (n = 0; n < SR_STREAMS; n++)
		fx_tx_frame(p, SR_H2_HEADERS,
			    SR_H2F_END_HEADERS | SR_H2F_END_STREAM,
			    (uint32_t)(1 + (n * 2)), req, sizeof(req));

	fx.sent = lws_now_usecs();
}

static struct fx_stream *
fx_stream(uint32_t sid)
{
	if (!(sid & 1) || sid > SR_STREAMS * 2)
		return NULL;

	return &fx.s[sid / 2];
}

/* a whole frame from the server */
static void
fx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	 const uint8_t *pl, size_t len)
{
	struct fx_stream *s;

	switch (type) {
	case SR_H2_SETTINGS:
		if (!(flags & SR_H2F_ACK))
			fx_tx_frame(p, SR_H2_SETTINGS, SR_H2F_ACK, 0, NULL, 0);
		return;

	case SR_H2_PING:
		if (!(flags & SR_H2F_ACK) && len == 8)
			fx_tx_frame(p, SR_H2_PING, SR_H2F_ACK, 0, pl, len);
		return;

	case SR_H2_GOAWAY:
		lwsl_user("%s: GOAWAY\n", __func__);
		return;

	case SR_H2_RST_STREAM:
		lwsl_err("%s: stream %u reset\n", __func__, (unsigned int)sid);
		fx.failed = 1;
		return;

	case SR_H2_HEADERS:
		s = fx_stream(sid);
		if (!s)
			break;
		/*
		 * hpack: :status comes first, either indexed (static index 8
		 * is :status 200) or, as lws sends it, a literal without
		 * indexing with a new name
		 */
		if ((len && pl[0] == 0x88) ||
		    (len >= 13 && !memcmp(pl, "\x00\x07:status\x03" "200", 13)))
			s->status_200 = 1;
		break;

	case SR_H2_DATA:
		s = fx_stream(sid);
		if (!s)
			break;
		s->rx += len;
		break;

	default:
		return;
	}

	s = fx_stream(sid);
	if (!s) {
		lwsl_err("%s: frame type %u on unexpected stream %u\n",
			 __func__, type, (unsigned int)sid);
		fx.failed = 1;
		return;
	}

	if ((flags & SR_H2F_END_STREAM) && !s->ended) {
		s->ended = 1;
		s->end = lws_now_usecs();
		lwsl_user("%s: stream %u complete after %dms\n", __func__,
			  (unsigned int)sid, (int)((s->end - fx.sent) /
						   LWS_US_PER_MS));
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

static void
evaluate(void)
{
	lws_usec_t last = 0;
	int fail = fx.failed, n;

	for (n = 0; n < SR_STREAMS; n++) {
		struct fx_stream *s = &fx.s[n];

		if (!s->ended || !s->status_200 || s->rx != sizeof(body) - 1) {
			lwsl_err("%s: stream %d: ended %d, 200 %d, %u body "
				 "bytes\n", __func__, 1 + (n * 2), s->ended,
				 s->status_200, (unsigned int)s->rx);
			fail = 1;
			continue;
		}
		/* the delay must really have been before the answer */
		if (s->end - fx.sent < (SR_DELAY_MS * LWS_US_PER_MS * 9) / 10) {
			lwsl_err("%s: stream %d answered without the delay\n",
				 __func__, 1 + (n * 2));
			fail = 1;
		}
		if (s->end > last)
			last = s->end;
	}

	/* ... and the idle connection must still have been reaped after */
	if (!fail && fx.closed - last > SR_IDLE_CLOSE_MAX_MS * LWS_US_PER_MS) {
		lwsl_err("%s: idle connection closed %dms after the last "
			 "response\n", __func__,
			 (int)((fx.closed - last) / LWS_US_PER_MS));
		fail = 1;
	}

	lwsl_user("%s: %s: %d h2 responses taking %dms, keepalive_timeout "
		  "%ds, timeout_secs %ds\n", __func__, fail ? "FAIL" : "PASS",
		  SR_STREAMS, SR_DELAY_MS, SR_KEEPALIVE_S, SR_TIMEOUT_S);

	finish(fail);
}

static int
callback_fx(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct fx_pss *p = (struct fx_pss *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		p->wsi = wsi;
		fx_send_requests(p);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		fx.failed = 1;
		fx.closed = lws_now_usecs();
		evaluate();
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
		fx.closed = lws_now_usecs();
		lwsl_user("%s: server closed the connection after %dms\n",
			  __func__, (int)((fx.closed - fx.sent) /
					  LWS_US_PER_MS));
		evaluate();
		break;

	default:
		break;
	}

	return 0;
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: the server never closed the connection\n", __func__);
	finish(1);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, sizeof(struct srv_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "fake-h2-client", callback_fx, sizeof(struct fx_pss), 0, 0, NULL, 0 },
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
	struct lws_client_connect_info i;
	struct lws_vhost *vh_cli;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;
	info.timeout_secs = SR_TIMEOUT_S;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: h2 server answering slower than its "
		  "keepalive\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the h2 server, cleartext with prior knowledge, short keepalive */

	info.port = port;
	info.vhost_name = "srv";
	info.protocols = protocols_srv;
	info.keepalive_timeout = SR_KEEPALIVE_S;
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	/* the fixture's vhost, no listener */

	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.keepalive_timeout = 0;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 SR_WATCHDOG_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = port;
	i.method = "RAW";
	i.local_protocol_name = "fake-h2-client";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		goto bail;
	}

	while (!lws_service(context, 0))
		;

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
