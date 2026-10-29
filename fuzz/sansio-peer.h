/*
 * lws fuzzing: a peer on lws' sansIO transport, with the fuzzer as the
 * network and the clock
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * peer.h gives the protocol parsers their bytes over a socketpair, always
 * in two halves, with the clock running on its own and a transport that
 * takes every write.  So nothing the fuzzer does can choose where a frame
 * is split, make lws hold a partial write, or bring a timeout due.  Here
 * the connection's transport is our own buffers (lws_set_transport(), as
 * api-test-sansio uses it, see READMEs/README.sans-io-split.md), the time is
 * what we say (lws_service_set_now()), and the input is a little program
 * of what happens at the transport, in order:
 *
 *   op byte: bits 0-2 the op, bits 3-7 its argument a (0 .. 31)
 *
 *   0, 5, 6  RX: the peer sends the next a + 1 bytes of the input, or,
 *	       if a is 31, the next u16 + 32 of them
 *   1  BULK:   the peer sends (a + 1) * 2KiB at once, of a pattern made of
 *	       the next byte + 1 bytes of the input, repeated: what it takes
 *	       to spend a flow control window or pass a size limit, without
 *	       an input that big
 *   2  TIME:   the time moves on by 2^(a + 8)us, 256us .. 6 days, running
 *	       whatever falls due: timeouts, validity pings, deferred closes
 *   3  TX:     what the transport takes of lws' writes: a 0, all of it;
 *	       1 .. 15, at most a * a bytes a write; 16, nothing (lws must
 *	       hold what it has); 17 .. 31, (a - 16) * 64 more bytes, then
 *	       nothing
 *   4  EVENT:  a 0, the peer finishes sending (FIN); a 1, it resets the
 *	       connection; others are given to the harness' event hook, eg,
 *	       for its application to do something
 *   7  the harness' own op, if it has one, eg, to frame what follows of the
 *	       input in its protocol, with the lengths right; else RX
 *
 * Lengths past what the input has left are cut to it, so any input is a
 * valid program and a mutation reshapes rather than invalidates it.  After
 * the program, the peer finishes sending, and the time runs on until lws
 * has closed the connection; if it still hasn't, it is killed, so no
 * connection outlives its input.
 *
 * A harness defines FZP_SERVER or FZP_CLIENT before including this, for the
 * side lws is on.
 *
 * POSIX only: each connection's place in lws' poll set is one end of a
 * socketpair, though no byte goes through it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define FZP_ROUNDS		64	/* service passes per thing happening */
#define FZP_TX_KEEP		4096	/* how much of what lws wrote we keep */
#define FZP_BULK_MAX		(32 * 2048)
#define FZP_END_STEPS		12	/* time steps to let a close finish */

enum {
	FZP_OP_RX,
	FZP_OP_BULK,
	FZP_OP_TIME,
	FZP_OP_TX,
	FZP_OP_EVENT,
	FZP_OP_HARNESS = 7
};

enum {
	FZP_EV_FIN,
	FZP_EV_RST,
	/* 2 .. 31 go to the harness' hook */
};

struct fzp_transport {
	const uint8_t	*rx;
	size_t		rx_len, rx_pos;

	/* the start of what lws wrote, eg, for a client's key */
	uint8_t		tx[FZP_TX_KEEP];
	size_t		tx_len;		/* kept */
	size_t		tx_total;	/* all of it */

	size_t		tx_limit;	/* the most one write takes, 0: all */
	long		tx_budget;	/* bytes it takes before it takes no
					 * more, -1: no end */
	struct lws	*wsi;		/* until lws releases the transport */
	int		fd;
	int		want_read;
	int		want_write;
	int		closed;
	int		fin;
	int		reset;
};

static struct lws_context *fzp_cx;
static struct fzp_transport fzp_tp;
static lws_io_ops_t fzp_io_ops;
static lws_usec_t fzp_now = (lws_usec_t)1000 * LWS_US_PER_SEC;

/* given what the harness doesn't handle itself: EVENT ops 2 .. 31 */
static void (*fzp_event_hook)(struct fzp_transport *t, int ev);

/*
 * The harness' op 7, given its argument and what's left of the input:
 * returns how much of the input it used
 */
static size_t (*fzp_op_hook)(struct fzp_transport *t, int a,
			     const uint8_t *in, size_t len);

static void
fzp_set_now(void)
{
	lws_service_set_now(fzp_cx, 0, fzp_now,
			    (time_t)1767225600 + (time_t)(fzp_now /
							  LWS_US_PER_SEC));
}

static int
fzp_read(struct lws *wsi, void *opaque, uint8_t *buf, size_t len)
{
	struct fzp_transport *t = (struct fzp_transport *)opaque;
	size_t n = t->rx_len - t->rx_pos;

	(void)wsi;

	if (!n)
		return t->reset ? LWS_SSL_CAPABLE_ERROR :
			t->fin ? 0 : LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	if (n > len)
		n = len;
	memcpy(buf, t->rx + t->rx_pos, n);
	t->rx_pos += n;

	return (int)n;
}

static int
fzp_write(struct lws *wsi, void *opaque, const uint8_t *buf, size_t len)
{
	struct fzp_transport *t = (struct fzp_transport *)opaque;

	(void)wsi;

	if (t->reset)
		return LWS_SSL_CAPABLE_ERROR;

	/* a transport that takes only some of it: lws keeps the rest */
	if (t->tx_limit && len > t->tx_limit)
		len = t->tx_limit;
	if (t->tx_budget >= 0) {
		if (!t->tx_budget)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		if (len > (size_t)t->tx_budget)
			len = (size_t)t->tx_budget;
		t->tx_budget -= (long)len;
	}

	if (t->tx_len < sizeof(t->tx)) {
		size_t k = sizeof(t->tx) - t->tx_len;

		if (k > len)
			k = len;
		memcpy(t->tx + t->tx_len, buf, k);
		t->tx_len += k;
	}
	t->tx_total += len;

	return (int)len;
}

static const lws_transport_ops_t fzp_tops = {
	.read		= fzp_read,
	.write		= fzp_write,
};

/*
 * The io_ops seam: what lws asks of its transport.  We note the asks about
 * ours, and let IO do the rest of what it does
 */

static struct fzp_transport *
fzp_of(struct lws *wsi)
{
	/* a mux stream has no socket of its own, nor a transport */
	if (fzp_tp.fd < 0 || (int)lws_get_socket_fd(wsi) != fzp_tp.fd)
		return NULL;

	return &fzp_tp;
}

static int
fzp_want_write(struct lws *wsi)
{
	struct fzp_transport *t = fzp_of(wsi);

	if (t)
		t->want_write = 1;

	return lws_io_ops_default.want_write(wsi);
}

static int
fzp_want_read(struct lws *wsi, int on)
{
	struct fzp_transport *t = fzp_of(wsi);

	if (t)
		t->want_read = on;

	return lws_io_ops_default.want_read(wsi, on);
}

static int
fzp_close(struct lws *wsi, int phase)
{
	struct fzp_transport *t = fzp_of(wsi);

	if (phase == LWS_IOCLOSE_RELEASE && t) {
		t->closed = 1;
		t->wsi = NULL;
	}

	return lws_io_ops_default.close(wsi, phase);
}

/*
 * A connection waiting on a worker (a file read handed to a thread) has
 * nothing to say until the worker's result is back: wait for lws' wake, and
 * have lws pick the result up
 */
static int
fzp_await_workers(void)
{
	struct lws_pollfd pfd;
	int budget = 100; /* 50ms each */

	if (!lws_service_work_outstanding(fzp_cx))
		return 0;

	pfd.fd = lws_service_wake_fd(fzp_cx, 0);
	if (pfd.fd == LWS_SOCK_INVALID)
		return 0;

	while (budget--) {
		pfd.events = LWS_POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 50) > 0 && (pfd.revents & LWS_POLLIN)) {
			lws_service_fd(fzp_cx, &pfd);
			return 1;
		}
		if (!lws_service_work_outstanding(fzp_cx))
			return 0;
	}

	return 0;
}

/*
 * Offer the connection what happened at its transport: the bytes waiting
 * while lws will read them, and a turn to write while it asks for one and
 * the transport can take some, until nothing more moves.  There is no
 * poll(): we say what the transport reports.
 */
static void
fzp_pump(struct fzp_transport *t)
{
	int n;

	for (n = 0; n < FZP_ROUNDS && !t->closed; n++) {
		size_t rpos = t->rx_pos, ttot = t->tx_total;
		/* lws holding read bytes it hasn't acted on yet */
		int held = !lws_service_adjust_timeout(fzp_cx, 1, 0),
		    reading = t->want_read, in, out;
		struct lws_pollfd pfd;

		in = t->want_read &&
		     (t->rx_pos < t->rx_len || held || t->fin || t->reset);
		out = t->want_write && ((t->tx_budget && !t->fin) || t->reset);

		pfd.fd = t->fd;
		pfd.events = (short)((t->want_read ? LWS_POLLIN : 0) |
				     (t->want_write ? LWS_POLLOUT : 0));
		pfd.revents = (short)((in ? LWS_POLLIN : 0) |
				      (out ? LWS_POLLOUT : 0) |
				      (t->fin ? POLLHUP : 0) |
				      (t->reset ? POLLHUP | POLLERR : 0));
		if (!pfd.revents) {
			if (fzp_await_workers())
				continue;
			return;
		}

		/* offered, lws asks again if it still wants it */
		if (out && !in)
			t->want_write = 0;

		if (lws_service_fd(fzp_cx, &pfd) && t->closed)
			return;

		if (t->rx_pos == rpos && t->tx_total == ttot &&
		    !t->want_write && t->want_read == reading &&
		    held == !lws_service_adjust_timeout(fzp_cx, 1, 0) &&
		    !fzp_await_workers())
			return;
	}
}

/* the time moves on, lws runs what fell due, and the transport is offered */
static void
fzp_advance(struct fzp_transport *t, lws_usec_t us)
{
	fzp_now += us;
	fzp_set_now();
	fzp_pump(t);
}

static void
fzp_rx(struct fzp_transport *t, const uint8_t *p, size_t len)
{
	/* each thing that happens at the transport is a little later */
	fzp_now += LWS_US_PER_MS;
	fzp_set_now();

	t->rx = p;
	t->rx_len = len;
	t->rx_pos = 0;
	fzp_pump(t);

	/* what lws didn't take now, it never will: its rx is stopped */
	t->rx = NULL;
	t->rx_len = t->rx_pos = 0;
}

/* runs the program in the input against the connection on t */
static void
fzp_run(struct fzp_transport *t, const uint8_t *in, size_t len)
{
	static uint8_t bulk[FZP_BULK_MAX];
	size_t pos = 0, n, k, i;
	int op, a;

	while (pos < len && !t->closed) {
		op = in[pos] & 7;
		a = in[pos++] >> 3;

		switch (op) {
		case FZP_OP_BULK:
			k = pos < len ? (size_t)in[pos++] + 1 : 1;
			if (k > len - pos)
				k = len - pos;
			n = ((size_t)a + 1) * 2048;
			if (!k)
				memset(bulk, 0, n);
			else
				for (i = 0; i < n; i++)
					bulk[i] = in[pos + (i % k)];
			pos += k;
			fzp_rx(t, bulk, n);
			break;

		case FZP_OP_TIME:
			fzp_advance(t, (lws_usec_t)1 << (a + 8));
			break;

		case FZP_OP_TX:
			if (!a) {
				t->tx_limit = 0;
				t->tx_budget = -1;
			} else if (a < 16)
				t->tx_limit = (size_t)(a * a);
			else if (a == 16)
				t->tx_budget = 0;
			else
				t->tx_budget = (t->tx_budget < 0 ? 0 :
						t->tx_budget) + (a - 16) * 64;
			fzp_pump(t);
			break;

		case FZP_OP_EVENT:
			if (a == FZP_EV_FIN)
				t->fin = 1;
			else if (a == FZP_EV_RST)
				t->reset = 1;
			else if (fzp_event_hook)
				fzp_event_hook(t, a);
			fzp_pump(t);
			break;

		case FZP_OP_HARNESS:
			if (fzp_op_hook) {
				pos += fzp_op_hook(t, a, in + pos, len - pos);
				break;
			}
			/* fallthru */
		default: /* RX */
			n = (size_t)a + 1;
			if (a == 31) {
				n = 32;
				if (len - pos >= 2) {
					n += ((size_t)in[pos] << 8) | in[pos + 1];
					pos += 2;
				}
			}
			if (n > len - pos)
				n = len - pos;
			fzp_rx(t, in + pos, n);
			pos += n;
			break;
		}
	}

	/*
	 * The peer is done: it finishes sending, the transport takes all,
	 * and the time runs on far enough for any close lws is in the middle
	 * of to finish
	 */
	t->fin = 1;
	t->tx_limit = 0;
	t->tx_budget = -1;
	fzp_pump(t);
	for (i = 0; i < FZP_END_STEPS && !t->closed; i++)
		fzp_advance(t, (lws_usec_t)1 << (i + 18));

	/* one that would still live on, eg, an idle ws, is killed */
	if (!t->closed && t->wsi)
		lws_set_timeout(t->wsi, PENDING_TIMEOUT_CLOSE_SEND,
				LWS_TO_KILL_SYNC);

	/* and anything the close left due runs */
	fzp_advance(t, LWS_US_PER_SEC);

	/* for triage with LWS_FUZZ_VERBOSE=1: what lws said to the peer */
	lwsl_notice("%s: lws wrote %zu bytes, the start:\n", __func__,
		    t->tx_total);
	lwsl_hexdump_notice(t->tx, t->tx_len < 512 ? t->tx_len : 512);
}

/* a new transport, whose place in the poll set is fd */
static struct fzp_transport *
fzp_transport_start(int fd)
{
	memset(&fzp_tp, 0, sizeof(fzp_tp));
	fzp_tp.fd = fd;
	fzp_tp.want_read = 1;
	fzp_tp.tx_budget = -1;

	return &fzp_tp;
}

/* the fd a connection's place in the poll set is, or -1 */
static int
fzp_placeholder_fd(void)
{
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
		return -1;
	close(sv[1]);

	return sv[0];
}

#if defined(FZP_SERVER)
/*
 * One server connection's life on vh: the peer sends prelude, if any, eg, a
 * protocol's fixed preface, then the input is its program
 */
static void
fzp_server_session(struct lws_vhost *vh, const uint8_t *prelude,
		   size_t prelude_len, const uint8_t *in, size_t len)
{
	struct fzp_transport *t;
	int fd = fzp_placeholder_fd();

	if (fd < 0)
		return;

	t = fzp_transport_start(fd);
	t->wsi = lws_adopt_socket_vhost(vh, fd);
	if (!t->wsi) {
		/* adopt closes the fd itself when it fails */
		t->fd = -1;
		return;
	}
	lws_set_transport(t->wsi, &fzp_tops, t);

	if (prelude_len)
		fzp_rx(t, prelude, prelude_len);
	fzp_run(t, in, len);
	t->fd = -1;
}
#endif

#if defined(FZP_CLIENT)
/*
 * A client connection made over our transport from ci, which is completed
 * with the transport: returns the transport with its request offered the
 * chance to go, or NULL if the connection didn't start
 */
static struct fzp_transport *
fzp_client_start(struct lws_client_connect_info *ci)
{
	struct fzp_transport *t;
	int fd = fzp_placeholder_fd();

	if (fd < 0)
		return NULL;

	t = fzp_transport_start(fd);
	ci->context		= fzp_cx;
	ci->transport		= &fzp_tops;
	ci->transport_opaque	= t;
	ci->transport_fd	= fd;

	fzp_now += LWS_US_PER_MS;
	fzp_set_now();

	t->wsi = lws_client_connect_via_info(ci);
	if (!t->wsi || t->closed) {
		t->fd = -1;
		return NULL;
	}
	fzp_pump(t);
	if (t->closed) {
		t->fd = -1;
		return NULL;
	}

	return t;
}

static void
fzp_client_end(struct fzp_transport *t, const uint8_t *in, size_t len)
{
	fzp_run(t, in, len);
	t->fd = -1;
}
#endif

/*
 * Fuzzing means feeding the parsers garbage, so their rejection logs are
 * expected noise that dominates the runtime: LWS_FUZZ_VERBOSE=1 gets them
 * back, eg, to replay a finding.  info is the harness' context creation
 * info; we add the io_ops.
 */
static int
fzp_init(struct lws_context_creation_info *info)
{
	signal(SIGPIPE, SIG_IGN);

	if (getenv("LWS_FUZZ_VERBOSE"))
		/*
		 * The parser's logs are too many to follow a connection by,
		 * and one input's logs are a burst that the spew handling
		 * would otherwise keep back until after the process exits
		 */
		lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO |
				  LLL_USER | LLLF_LOG_SPEW_OFF, NULL);
	else
		lws_set_log_level(0, NULL);

	lws_io_ops_init(&fzp_io_ops);
	fzp_io_ops.want_write	= fzp_want_write;
	fzp_io_ops.want_read	= fzp_want_read;
	fzp_io_ops.close	= fzp_close;
	info->io_ops		= &fzp_io_ops;

	fzp_tp.fd = -1;

	fzp_cx = lws_create_context(info);
	if (!fzp_cx)
		return 1;

	fzp_set_now();

	return 0;
}
