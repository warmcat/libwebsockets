/*
 * lws-api-test-sansio
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The sansIO half driven with no socket under it (README.sans-io-split.md,
 * "Staging" 9): connections whose transport is this test's buffers
 * (lws_set_transport() for a server connection, the transport of
 * lws_client_connect_info for a client one).  The socketpair end each is
 * adopted on is only its place in the poll set; no byte ever goes through
 * it, and the test never calls poll() or lws_service(): it is the event
 * loop, and it hears what lws wants of the transport the way an embedder
 * of the sansIO half does, through the io_ops seam.
 *
 * Server half: we feed the bytes a client would send and check the bytes
 * the server answers with: an h1 GET answered by the http callback, then a
 * ws upgrade and an echo through the ws role.
 *
 * Client half: we check the bytes the client sends and feed the bytes a
 * server would answer with: an h1 GET and its response body, then a ws
 * upgrade, the client's first frame, and a frame to it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * A transport: the bytes the peer sent, waiting to be read, and the bytes
 * the connection wrote.  fd is the connection's place in lws's poll set;
 * want_read and want_write are what lws asked of the transport, as the
 * test heard them through the io_ops.
 */
struct transport {
	const uint8_t	*rx;
	size_t		rx_len, rx_pos;
	uint8_t		tx[65536];
	size_t		tx_len;
	int		fd;
	int		want_read;
	int		want_write;
};

static struct transport *transports[4];
static int ntransports;

static int
tp_read(struct lws *wsi, void *opaque, uint8_t *buf, size_t len)
{
	struct transport *t = (struct transport *)opaque;
	size_t n = t->rx_len - t->rx_pos;

	if (!n)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	if (n > len)
		n = len;
	memcpy(buf, t->rx + t->rx_pos, n);
	t->rx_pos += n;

	return (int)n;
}

static int
tp_write(struct lws *wsi, void *opaque, const uint8_t *buf, size_t len)
{
	struct transport *t = (struct transport *)opaque;

	if (t->tx_len + len > sizeof(t->tx))
		return LWS_SSL_CAPABLE_ERROR;
	memcpy(t->tx + t->tx_len, buf, len);
	t->tx_len += len;

	return (int)len;
}

static const lws_transport_ops_t tops = {
	.read		= tp_read,
	.write		= tp_write,
};

/*
 * The io_ops seam: lws's requests of its transport reach IO through these.
 * We note the ones about our connections, then let IO do what it does.
 */

static struct transport *
tp_of(struct lws *wsi)
{
	int fd = (int)lws_get_socket_fd(wsi), n;

	for (n = 0; n < ntransports; n++)
		if (transports[n]->fd == fd)
			return transports[n];

	return NULL;
}

static int
tp_want_write(struct lws *wsi)
{
	struct transport *t = tp_of(wsi);

	if (t)
		t->want_write = 1;

	return lws_io_ops_default.want_write(wsi);
}

static int
tp_want_read(struct lws *wsi, int on)
{
	struct transport *t = tp_of(wsi);

	if (t)
		t->want_read = on;

	return lws_io_ops_default.want_read(wsi, on);
}

static lws_io_ops_t io_ops;

/* a transport starts, or starts again, under a connection at fd */
static int
tp_register(struct transport *t, int fd)
{
	int n;

	memset(t, 0, sizeof(*t));
	t->fd = fd;
	t->want_read = 1;

	for (n = 0; n < ntransports; n++)
		if (transports[n] == t)
			return 0;
	if (ntransports == (int)LWS_ARRAY_SIZE(transports))
		return 1;
	transports[ntransports++] = t;

	return 0;
}

/*
 * Offer the connection what happened at its transport: the bytes waiting,
 * while lws will read them, and a turn to write for each time it asked.
 * lws may have parked bytes it read but has not acted on yet (the body
 * that came with a response's headers): a real loop gives those a pass
 * without the socket saying anything, and so do we, while it says it holds
 * some.  There is no poll(): the test says what happened, until nothing
 * more can.
 */
static void
pump(struct lws_context *cx, struct transport *t)
{
	int n;

	for (n = 0; n < 64; n++) {
		struct lws_pollfd pfd;
		size_t rpos = t->rx_pos, tlen = t->tx_len;
		int held = !lws_service_adjust_timeout(cx, 1, 0);
		int in = t->want_read && (t->rx_pos < t->rx_len || held);

		pfd.fd = t->fd;
		pfd.events = (short)(LWS_POLLIN |
				     (t->want_write ? LWS_POLLOUT : 0));
		pfd.revents = (short)((in ? LWS_POLLIN : 0) |
				      (t->want_write ? LWS_POLLOUT : 0));
		if (!pfd.revents)
			return;
		t->want_write = 0;

		if (lws_service_fd(cx, &pfd))
			return;

		/* the pass changed nothing we can see: it is waiting on us */
		if (t->rx_pos == rpos && t->tx_len == tlen && !t->want_write &&
		    held == !lws_service_adjust_timeout(cx, 1, 0))
			return;
	}
}

/* what the peer sent arrives; returns nonzero if it was not all taken */
static int
feed(struct lws_context *cx, struct transport *t, const void *s, size_t len)
{
	t->rx = (const uint8_t *)s;
	t->rx_len = len;
	t->rx_pos = 0;
	t->tx_len = 0;
	pump(cx, t);

	return t->rx_pos != t->rx_len;
}

static const uint8_t *
find_bytes(const uint8_t *hay, size_t hlen, const char *needle)
{
	size_t nlen = strlen(needle), n;

	for (n = 0; n + nlen <= hlen; n++)
		if (!memcmp(hay + n, needle, nlen))
			return hay + n;

	return NULL;
}

/* the server half's protocols */

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *p = buf + LWS_PRE, *end = buf + sizeof(buf);
	static const char body[] = "sansio ok\n";

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
						sizeof(body) - 1, &p, end) ||
		    lws_finalize_write_http_header(wsi, buf + LWS_PRE, &p, end))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		memcpy(p, body, sizeof(body) - 1);
		if (lws_write(wsi, p, sizeof(body) - 1, LWS_WRITE_HTTP_FINAL) !=
							(int)sizeof(body) - 1)
			return 1;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_echo(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 128];

	switch (reason) {
	case LWS_CALLBACK_RECEIVE:
		if (len > sizeof(buf) - LWS_PRE)
			return -1;
		memcpy(buf + LWS_PRE, in, len);
		if (lws_write(wsi, buf + LWS_PRE, len, LWS_WRITE_TEXT) != (int)len)
			return -1;
		return 0;
	default:
		break;
	}

	return 0;
}

#if defined(LWS_WITH_CLIENT)

/* the client half's protocol: what it heard */

static struct {
	char		rx[64];
	size_t		rx_len;
	int		established;
	int		completed;
	int		sent;
	int		error;
} cli;

static int
callback_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 64];
	char *px;
	int lenx;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("client connection error: %s\n",
			 in ? (const char *)in : "");
		cli.error = 1;
		break;

	/* h1 */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.established = 1;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		/* the body is ours to pull, at our pace, into our buffer */
		px = (char *)buf + LWS_PRE;
		lenx = (int)sizeof(buf) - LWS_PRE;
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (cli.rx_len + len > sizeof(cli.rx))
			return -1;
		memcpy(cli.rx + cli.rx_len, in, len);
		cli.rx_len += len;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		cli.completed = 1;
		break;

	/* ws */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		cli.established = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (cli.sent)
			break;
		memcpy(buf + LWS_PRE, "Hello", 5);
		if (lws_write(wsi, buf + LWS_PRE, 5, LWS_WRITE_TEXT) != 5)
			return -1;
		cli.sent = 1;
		break;

	default:
		break;
	}

	return 0;
}
#endif

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	{ "echo", callback_echo, 0, 128, 0, NULL, 0 },
#if defined(LWS_WITH_CLIENT)
	{ "client", callback_client, 0, 128, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static int
server_half(struct lws_context *cx)
{
	static const char req_get[] =
		"GET /x HTTP/1.1\r\nHost: sansio\r\n\r\n";
	static const char req_ws[] =
		"GET /echo HTTP/1.1\r\nHost: sansio\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Protocol: echo\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
	/* the masked text frame "Hello" of RFC 6455 5.7 */
	static const char frame[] = "\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58";
	static const char echo[] = "\x81\x05Hello";
	static struct transport tp;
	struct lws *wsi;
	int sv[2];

	/* the connection's place in the poll set; no byte goes through it */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket(cx, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);

	/* 1: an h1 GET, answered by the http callback */
	if (feed(cx, &tp, req_get, sizeof(req_get) - 1)) {
		lwsl_err("case 1: request not consumed\n");
		return 1;
	}
	if (tp.tx_len < 20 || memcmp(tp.tx, "HTTP/1.1 200 ", 13) ||
	    !find_bytes(tp.tx, tp.tx_len, "\r\n\r\nsansio ok\n")) {
		lwsl_err("case 1: bad response\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 1: h1 GET over the test transport: PASS\n");

	/* 2: the ws upgrade on the kept-alive connection */
	if (feed(cx, &tp, req_ws, sizeof(req_ws) - 1)) {
		lwsl_err("case 2: upgrade not consumed\n");
		return 1;
	}
	if (tp.tx_len < 20 || memcmp(tp.tx, "HTTP/1.1 101 ", 13) ||
	    !find_bytes(tp.tx, tp.tx_len,
		    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")) {
		lwsl_err("case 2: bad upgrade response\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 2: ws upgrade over the test transport: PASS\n");

	/* 3: a masked frame in, the echo out */
	if (feed(cx, &tp, frame, sizeof(frame) - 1)) {
		lwsl_err("case 3: frame not consumed\n");
		return 1;
	}
	if (tp.tx_len != sizeof(echo) - 1 ||
	    memcmp(tp.tx, echo, sizeof(echo) - 1)) {
		lwsl_err("case 3: bad echo\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 3: ws echo over the test transport: PASS\n");

	return 0;
}

#if defined(LWS_WITH_CLIENT)

static struct lws *
client_connect(struct lws_context *cx, struct lws_vhost *vh,
	       struct transport *tp, const char *path, const char *method,
	       const char *ws_protocol)
{
	struct lws_client_connect_info ci;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return NULL;
	}
	close(sv[1]);
	if (tp_register(tp, sv[0]))
		return NULL;
	memset(&cli, 0, sizeof(cli));

	memset(&ci, 0, sizeof(ci));
	ci.context		= cx;
	ci.vhost		= vh;
	ci.address		= "sansio";
	ci.port			= 80;
	ci.host			= ci.address;
	ci.origin		= ci.address;
	ci.path			= path;
	ci.method		= method;
	ci.protocol		= ws_protocol;
	ci.local_protocol_name	= "client";
	ci.transport		= &tops;
	ci.transport_opaque	= tp;
	ci.transport_fd		= sv[0];

	return lws_client_connect_via_info(&ci);
}

static int
client_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char resp_get[] =
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
		"Content-Length: 10\r\n\r\nsansio ok\n";
	static const char resp_ws[] =
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Protocol: echo\r\n"
		"Sec-WebSocket-Accept: ";
	static const char frame[] = "\x81\x05Hello";
	static struct transport tp;
	char key[24 + 36 + 1], accept[32], resp[256];
	uint8_t sha[20];
	const uint8_t *k;
	int n;

	/* 4: an h1 GET: the client's request, then its response body */
	if (!client_connect(cx, vh, &tp, "/x", "GET", NULL)) {
		lwsl_err("case 4: connect failed\n");
		return 1;
	}
	pump(cx, &tp);
	if (tp.tx_len < 20 || memcmp(tp.tx, "GET /x HTTP/1.1\r\n", 17) ||
	    !find_bytes(tp.tx, tp.tx_len, "\r\nHost: sansio") ||
	    memcmp(tp.tx + tp.tx_len - 4, "\r\n\r\n", 4)) {
		lwsl_err("case 4: bad request\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	if (feed(cx, &tp, resp_get, sizeof(resp_get) - 1)) {
		lwsl_err("case 4: response not consumed\n");
		return 1;
	}
	if (cli.error || !cli.established || !cli.completed ||
	    cli.rx_len != 10 || memcmp(cli.rx, "sansio ok\n", 10)) {
		lwsl_err("case 4: bad response handling: est %d comp %d rx %d\n",
			 cli.established, cli.completed, (int)cli.rx_len);
		return 1;
	}
	lwsl_user("case 4: h1 client GET over the test transport: PASS\n");

	/* 5: the ws upgrade: its key answered, the client's first frame */
	if (!client_connect(cx, vh, &tp, "/echo", NULL, "echo")) {
		lwsl_err("case 5: connect failed\n");
		return 1;
	}
	pump(cx, &tp);
	k = find_bytes(tp.tx, tp.tx_len, "\r\nSec-WebSocket-Key: ");
	if (tp.tx_len < 20 || memcmp(tp.tx, "GET /echo HTTP/1.1\r\n", 20) ||
	    !find_bytes(tp.tx, tp.tx_len, "\r\nUpgrade: websocket\r\n") ||
	    !find_bytes(tp.tx, tp.tx_len, "\r\nSec-WebSocket-Protocol: echo\r\n") ||
	    !k || k + 21 + 24 + 2 > tp.tx + tp.tx_len ||
	    memcmp(k + 21 + 24, "\r\n", 2)) {
		lwsl_err("case 5: bad upgrade request\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	memcpy(key, k + 21, 24);
	memcpy(key + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 37);
	lws_SHA1((const uint8_t *)key, 24 + 36, sha);
	lws_b64_encode_string((const char *)sha, 20, accept, sizeof(accept));
	n = lws_snprintf(resp, sizeof(resp), "%s%s\r\n\r\n", resp_ws, accept);

	if (feed(cx, &tp, resp, (size_t)n)) {
		lwsl_err("case 5: upgrade response not consumed\n");
		return 1;
	}
	if (cli.error || !cli.established || !cli.sent) {
		lwsl_err("case 5: not established: est %d sent %d\n",
			 cli.established, cli.sent);
		return 1;
	}
	/* the masked text frame "Hello" it sent on establishing */
	if (tp.tx_len != 11 || tp.tx[0] != 0x81 || tp.tx[1] != 0x85) {
		lwsl_err("case 5: bad client frame\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	for (n = 0; n < 5; n++)
		if ((tp.tx[6 + n] ^ tp.tx[2 + (n & 3)]) != "Hello"[n]) {
			lwsl_err("case 5: bad client frame payload\n");
			lwsl_hexdump_err(tp.tx, tp.tx_len);
			return 1;
		}
	lwsl_user("case 5: ws client upgrade over the test transport: PASS\n");

	/* 6: a frame to the client */
	if (feed(cx, &tp, frame, sizeof(frame) - 1)) {
		lwsl_err("case 6: frame not consumed\n");
		return 1;
	}
	if (cli.rx_len != 5 || memcmp(cli.rx, "Hello", 5)) {
		lwsl_err("case 6: bad rx: %d\n", (int)cli.rx_len);
		return 1;
	}
	lwsl_user("case 6: ws client rx over the test transport: PASS\n");

	return 0;
}
#endif

int
main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, result = 1;
	struct lws_context_creation_info info;
	struct lws_context *cx;
	struct lws_vhost *vh;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: the sansIO half over a test transport\n");

	/* IO's requests of the transport, with us listening */
	io_ops = lws_io_ops_default;
	io_ops.want_write = tp_want_write;
	io_ops.want_read = tp_want_read;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.io_ops = &io_ops;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}
	info.vhost_name = "sansio";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost failed\n");
		goto bail;
	}

	if (server_half(cx))
		goto bail;
#if defined(LWS_WITH_CLIENT)
	if (client_half(cx, vh))
		goto bail;
#else
	(void)vh;
#endif

	result = 0;

bail:
	lws_context_destroy(cx);
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
