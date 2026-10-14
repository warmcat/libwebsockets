/*
 * lws-api-test-h2-server-write-after-end
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Once an h2 stream has ended both ways, the peer ending its request and us
 * our answer, it's gone: nothing can be sent or received on it again.  A user
 * that writes to it after that, eg, from a timer, must be told the write
 * failed, so it closes the stream.  If the write is thrown away and reported
 * as done, the user goes on writing into it for as long as the connection
 * lasts.
 *
 * The server is an lws h2 server (cleartext, prior knowledge) whose callback
 * answers a request with a FINAL write, but leaves the stream open rather
 * than completing the transaction, and a little later writes to it again.
 * The client is a raw tcp fixture speaking just enough h2 to make the request
 * and watch the answer.
 *
 * The late write must fail, the server's stream must close, and the fixture
 * must see the whole answer and nothing after it, with the connection
 * staying up.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define SR_LATE_MS		100	/* the late write, after the answer */
#define SR_SETTLE_MS		300	/* then judge, after this */
#define SR_WATCHDOG_S		10

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

static const char answer[] = "the answer\n", late[] = "too late\n";

/* the server */

struct srv_pss {
	struct lws		*wsi;
	lws_sorted_usec_list_t	sul_late;
	uint8_t			answered;
	uint8_t			due;
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
	size_t			rx;		/* DATA the fixture got */
	uint8_t			ended;		/* ... and its END_STREAM */
	uint8_t			late_write;	/* 0 not yet, 1 failed, 2 ok */
	uint8_t			srv_closed;
	uint8_t			goaway;
	uint8_t			failed;
} fx;

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog, sul_evaluate;
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
	lws_sul_cancel(&sul_evaluate);
	lws_default_loop_exit(context);
}

static void
evaluate_cb(lws_sorted_usec_list_t *sul)
{
	int fail = fx.failed;

	if (!fx.ended || fx.rx != sizeof(answer) - 1) {
		lwsl_err("%s: answer: %u bytes, ended %d\n", __func__,
			 (unsigned int)fx.rx, fx.ended);
		fail = 1;
	}

	if (fx.late_write != 1) {
		lwsl_err("%s: the late write %s\n", __func__,
			 fx.late_write ? "did not fail" : "never happened");
		fail = 1;
	}

	if (!fx.srv_closed) {
		lwsl_err("%s: the server's stream is still open\n", __func__);
		fail = 1;
	}

	if (fx.goaway) {
		lwsl_err("%s: the connection went down\n", __func__);
		fail = 1;
	}

	lwsl_user("%s: %s\n", __func__, fail ? "FAIL" : "PASS");

	finish(fail);
}

static void
srv_late_cb(lws_sorted_usec_list_t *sul)
{
	struct srv_pss *pss = lws_container_of(sul, struct srv_pss, sul_late);

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
		pss->wsi = wsi;
		pss->due = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* WRITEABLE can come unasked on h2: only write when due */
		if (!pss || !pss->due)
			return 0;
		pss->due = 0;

		if (!pss->answered) {
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"text/plain", sizeof(answer) - 1,
					&p, end) ||
			    lws_finalize_write_http_header(wsi, start, &p, end))
				return 1;

			memcpy(start, answer, sizeof(answer) - 1);
			if (lws_write(wsi, start, sizeof(answer) - 1,
				      LWS_WRITE_HTTP_FINAL) !=
						(int)sizeof(answer) - 1)
				return 1;
			pss->answered = 1;

			/*
			 * We deliberately don't complete the transaction,
			 * leaving the stream wsi there to write to again
			 */
			lws_sul_schedule(lws_get_context(wsi), 0,
					 &pss->sul_late, srv_late_cb,
					 SR_LATE_MS * LWS_US_PER_MS);
			return 0;
		}

		memcpy(start, late, sizeof(late) - 1);
		if (lws_write(wsi, start, sizeof(late) - 1,
			      LWS_WRITE_HTTP) < 0) {
			lwsl_user("%s: the late write failed, closing\n",
				  __func__);
			fx.late_write = 1;
			return -1;
		}

		lwsl_err("%s: the late write went through\n", __func__);
		fx.late_write = 2;
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (!pss || !pss->wsi)
			break;
		lws_sul_cancel(&pss->sul_late);
		fx.srv_closed = 1;
		lwsl_user("%s: server stream closed\n", __func__);
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
fx_send_request(struct fx_pss *p)
{
	/*
	 * hpack: indexed :method GET, :scheme http, :path /, and :authority
	 * as a literal without indexing, name index 1
	 */
	static const uint8_t req[] = {
		0x82, 0x86, 0x84, 0x01, 9,
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'
	};

	memcpy(p->tx + LWS_PRE, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
	p->txlen = 24;
	fx_tx_frame(p, SR_H2_SETTINGS, 0, 0, NULL, 0);
	fx_tx_frame(p, SR_H2_HEADERS, SR_H2F_END_HEADERS | SR_H2F_END_STREAM,
		    1, req, sizeof(req));
}

/* a whole frame from the server */
static void
fx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	 const uint8_t *pl, size_t len)
{
	switch (type) {
	case SR_H2_SETTINGS:
		if (!(flags & SR_H2F_ACK))
			fx_tx_frame(p, SR_H2_SETTINGS, SR_H2F_ACK, 0, NULL, 0);
		break;

	case SR_H2_PING:
		if (!(flags & SR_H2F_ACK) && len == 8)
			fx_tx_frame(p, SR_H2_PING, SR_H2F_ACK, 0, pl, len);
		break;

	case SR_H2_GOAWAY:
		lwsl_err("%s: GOAWAY\n", __func__);
		fx.goaway = 1;
		break;

	case SR_H2_RST_STREAM:
		lwsl_err("%s: stream %u reset\n", __func__, (unsigned int)sid);
		fx.failed = 1;
		break;

	case SR_H2_DATA:
		if (sid != 1)
			break;
		if (fx.ended) {
			lwsl_err("%s: DATA after END_STREAM\n", __func__);
			fx.failed = 1;
			break;
		}
		fx.rx += len;
		if (!(flags & SR_H2F_END_STREAM))
			break;
		fx.ended = 1;
		/* the late write comes after SR_LATE_MS; judge after that */
		lws_sul_schedule(context, 0, &sul_evaluate, evaluate_cb,
				 (SR_LATE_MS + SR_SETTLE_MS) * LWS_US_PER_MS);
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
	case LWS_CALLBACK_RAW_CONNECTED:
		p->wsi = wsi;
		fx_send_request(p);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		finish(1);
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
		if (!done) {
			lwsl_err("%s: the server closed the connection\n",
				 __func__);
			finish(1);
		}
		break;

	default:
		break;
	}

	return 0;
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out, %u bytes of answer\n", __func__,
		 (unsigned int)fx.rx);
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

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: h2 server writing after the stream "
		  "ended\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the h2 server, cleartext with prior knowledge */

	info.port = port;
	info.vhost_name = "srv";
	info.protocols = protocols_srv;
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
