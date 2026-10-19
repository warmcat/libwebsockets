/*
 * lws-api-test-h2-parked-rx
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Rx a wsi could not consume yet is parked on its buflist, and the wsi is
 * listed on its pt; the service loop offers it the parked rx again each pass
 * it can take it.  On an h2 server, both the network connection and its
 * streams may be listed.  The pass servicing the connection's parked rx can
 * free a stream that is listed after it, eg, when the parked rx resets that
 * stream: the walk of the list must survive a member other than the one it
 * is servicing going away.
 *
 * Here an lws h2 server (cleartext, prior knowledge) and a raw tcp fixture
 * client speaking just enough h2 run in one event loop.  The server parks
 * the rest of a read when a stream's body handler fails part way through
 * it.  Afterwards the server must still answer a PING on the connection.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define PR_WATCHDOG_S		20
#define PR_SETTLE_MS		300	/* for the server's deferred actions */

/* h2 frame types and flags the fixture deals in */
#define PR_H2_DATA		0
#define PR_H2_HEADERS		1
#define PR_H2_RST_STREAM	3
#define PR_H2_SETTINGS		4
#define PR_H2_PING		6
#define PR_H2_GOAWAY		7
#define PR_H2F_ACK		1
#define PR_H2F_END_HEADERS	4

static const uint8_t ping_payload[8] = { 'p', 'a', 'r', 'k', 'e', 'd', 'r', 'x' };

/* the server */

enum {
	PR_REQ_HOLD = 1,	/* never answered */
	PR_REQ_FAIL,		/* its body handler fails */
};

struct srv_pss {
	uint8_t			kind;
};

static struct {
	int			fail_bodies;
	int			hold_closed;
} srv;

/* the fixture client connection */

struct fx_pss {
	struct lws		*wsi;
	uint8_t			rx[4096];
	uint8_t			tx[LWS_PRE + 512];
	size_t			rxlen;
	size_t			txlen;
};

static struct {
	struct lws		*wsi;
	uint8_t			ping_acked;
	uint8_t			goaway;
	uint8_t			failed;
} fx;

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog, sul_step;
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
	lws_sul_cancel(&sul_step);
	lws_default_loop_exit(context);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct srv_pss *pss = (struct srv_pss *)user;
	char path[32];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_hdr_copy(wsi, path, sizeof(path),
				 WSI_TOKEN_HTTP_COLON_PATH) < 0)
			return -1;
		if (!strcmp(path, "/hold")) {
			pss->kind = PR_REQ_HOLD;
			return 0;
		}
		if (!strcmp(path, "/fail")) {
			pss->kind = PR_REQ_FAIL;
			return 0;
		}
		return -1;

	case LWS_CALLBACK_HTTP_BODY:
		if (pss->kind != PR_REQ_FAIL)
			return 0;
		srv.fail_bodies++;
		return -1;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss && pss->kind == PR_REQ_HOLD)
			srv.hold_closed++;
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
		fx.failed = 1;
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

/*
 * hpack, all literals without indexing using static table names: :method
 * GET (2) or POST (3), :scheme http (6), :path (4) and :authority (1), and
 * for a POST content-length (28) 4
 */

static void
fx_tx_request(struct fx_pss *p, uint32_t sid, const char *path, int post)
{
	uint8_t hb[64], *h = hb;
	size_t pl = strlen(path);

	*h++ = post ? 0x83 : 0x82;
	*h++ = 0x86;
	*h++ = 0x04;
	*h++ = (uint8_t)pl;
	memcpy(h, path, pl);
	h += pl;
	*h++ = 0x01;
	*h++ = 9;
	memcpy(h, "localhost", 9);
	h += 9;
	if (post) {
		*h++ = 0x0f;
		*h++ = 28 - 15;
		*h++ = 1;
		*h++ = '4';
	}

	fx_tx_frame(p, PR_H2_HEADERS, PR_H2F_END_HEADERS, sid, hb,
		    lws_ptr_diff_size_t(h, hb));
}

/*
 * The first write: stream 1 sends body while its action is deferred, so it
 * is stashed and, once the action ran, listed with its parked rx; never
 * answered, it keeps it.  Stream 3's body handler is going to fail.
 */

static void
fx_open(struct fx_pss *p)
{
	static const uint8_t one = 'x';

	memcpy(p->tx + LWS_PRE, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
	p->txlen = 24;
	fx_tx_frame(p, PR_H2_SETTINGS, 0, 0, NULL, 0);
	fx_tx_request(p, 1, "/hold", 0);
	fx_tx_frame(p, PR_H2_DATA, 0, 1, &one, 1);
	fx_tx_frame(p, PR_H2_DATA, 0, 1, &one, 1);
	fx_tx_request(p, 3, "/fail", 1);
}

/*
 * The second write: stream 3's body fails, which parks the rest of this read
 * on the connection, listed ahead of stream 1.  The rest resets stream 1,
 * then asks for a PING ACK to show the server is still there afterwards.
 */

static void
step_cb(lws_sorted_usec_list_t *sul)
{
	static const uint8_t one = 'x', cancel[4] = { 0, 0, 0, 8 };
	struct fx_pss *p;

	if (!fx.wsi) {
		lwsl_err("%s: no fixture connection\n", __func__);
		finish(1);
		return;
	}
	p = (struct fx_pss *)lws_wsi_user(fx.wsi);

	fx_tx_frame(p, PR_H2_DATA, 0, 3, &one, 1);
	fx_tx_frame(p, PR_H2_RST_STREAM, 0, 1, cancel, sizeof(cancel));
	fx_tx_frame(p, PR_H2_PING, 0, 0, ping_payload, sizeof(ping_payload));
}

/* a whole frame from the server */
static void
fx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, const uint8_t *pl,
	 size_t len)
{
	switch (type) {
	case PR_H2_SETTINGS:
		if (!(flags & PR_H2F_ACK))
			fx_tx_frame(p, PR_H2_SETTINGS, PR_H2F_ACK, 0, NULL, 0);
		return;

	case PR_H2_PING:
		if (!(flags & PR_H2F_ACK)) {
			if (len == 8)
				fx_tx_frame(p, PR_H2_PING, PR_H2F_ACK, 0, pl,
					    len);
			return;
		}
		if (len == sizeof(ping_payload) &&
		    !memcmp(pl, ping_payload, len))
			fx.ping_acked = 1;
		return;

	case PR_H2_GOAWAY:
		lwsl_err("%s: GOAWAY\n", __func__);
		fx.goaway = 1;
		return;

	default:
		return;
	}
}

static int
fx_rx(struct fx_pss *p, const uint8_t *in, size_t len)
{
	if (len > sizeof(p->rx) - p->rxlen) {
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

		fx_frame(p, p->rx[3], p->rx[4], p->rx + 9, fl);

		o = 9 + fl;
		rest = p->rxlen - o;
		if (rest)
			memmove(p->rx, p->rx + o, rest);
		p->rxlen = rest;
	}

	return 0;
}

static void
evaluate(void)
{
	int fail = fx.failed || fx.goaway || !fx.ping_acked ||
		   srv.fail_bodies != 1 || srv.hold_closed != 1;

	lwsl_user("%s: %s: failing bodies %d, held stream closed %d, ping "
		  "acked %d, goaway %d\n", __func__, fail ? "FAIL" : "PASS",
		  srv.fail_bodies, srv.hold_closed, fx.ping_acked, fx.goaway);

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
		fx.wsi = wsi;
		fx_open(p);
		lws_sul_schedule(context, 0, &sul_step, step_cb,
				 PR_SETTLE_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		finish(1);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (fx_rx(p, (const uint8_t *)in, len))
			return -1;
		if (fx.ping_acked && srv.hold_closed)
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
		fx.wsi = NULL;
		lws_sul_cancel(&sul_step);
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
	lwsl_err("%s: did not complete\n", __func__);
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

	lwsl_user("LWS API selftest: h2 rx parked on the service loop\n");

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
			 PR_WATCHDOG_S * LWS_US_PER_SEC);

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

	while (!done && !lws_service(context, 0))
		;

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
