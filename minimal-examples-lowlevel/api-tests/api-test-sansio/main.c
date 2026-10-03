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
 * it, and the test never polls it or calls lws_service(): it is the event
 * loop, and it hears what lws wants of the transport the way an embedder
 * of the sansIO half does, through the io_ops seam.  The one fd it does
 * poll is lws' wake fd, for a file read lws handed to a worker thread
 * (LWS_WITH_ASYNC_QUEUE), as any embedder's loop must.
 *
 * Server half: we feed the bytes a client would send and check the bytes
 * the server answers with: an h1 GET answered by the http callback, then a
 * ws upgrade and an echo through the ws role.
 *
 * Client half: we check the bytes the client sends and feed the bytes a
 * server would answer with: an h1 GET and its response body, then a ws
 * upgrade, the client's first frame, and a frame to it.
 *
 * Then what either side must refuse, and how it says so: ws upgrades lws
 * will not do, frames with RSV bits nothing negotiated gives a meaning,
 * with and without permessage-deflate, and one longer than lws takes; and
 * what the h1 server makes of a request line (dot segments, '+', token
 * limits, no version, no request line at all, versions it does and does
 * not speak, methods it does not know, empty lines before it), and what the h1 client makes of a response's body framing
 * (a Content-Length that is not only digits, or given twice, and a
 * Transfer-Encoding that is more than "chunked").
 *
 * Then a ws close the peer starts, in either role: a pong it is owed for a
 * ping sent before its close still goes, ahead of the answer to the close,
 * and a close that comes while a frame of ours is still partly unsent is
 * answered once the frame has gone; but one that comes when the server is
 * to close once its last frame has gone is not answered.
 *
 * Then state that belongs to one transaction and not to the connection it
 * came on: serving the vhost's 404 document is one request's business, the
 * next request on the kept-alive connection gets its own 404 redirect.
 *
 * Then transactions completed while their answer is still queued, the
 * transport taking only a few bytes a write: an h2 POST the app answers and
 * completes at once has the rest of its body discarded as it comes, and its
 * stream ended once the answer has gone; and one the app answers with a
 * file likewise, the file all going.  Last, since it moves the time on, a
 * file stalled on the stream's window is still closed by its timeout,
 * though the body arrived and completed meanwhile; but an answer
 * the app writes a piece at a time that is only slow, each piece going
 * before the watchdog expires, all goes.  And an answer the app starts
 * from the body's first piece, then cannot finish for want of window, is
 * closed by the response's watchdog too, though the body went on arriving
 * after the answer started, and completed; on an h1 connection as on an h2
 * stream.
 *
 * And an h1 POST answered with a file the app abandons, by completing the
 * transaction from its timer, while a read of the file is out on a worker:
 * the answer is short of its Content-Length, and the connection is closed,
 * as it is for an answer the app completes short of it itself, though not
 * for a HEAD.  On an h2 stream the same abandoned file leaves the connection
 * alone: its body is discarded, and the stream ends.  And an h1 POST
 * answered and completed before its body, which then comes
 * slowly: the body being discarded has its own timeout, renewed as it comes,
 * not the watchdog of the answer that has already gone.
 *
 * And a request the mount redirects before any app sees it, likewise only
 * partly written: the transaction completes when it has gone, answered in
 * the request's own version, and the kept-alive connection goes on to the
 * next request.
 *
 * And ws over h2: the peer's close is answered, nothing it sends after it is
 * acted on, and the stream, which was processed, is not refused; and when
 * the stream has no window for the answer yet, it goes once it has.
 *
 * And a CONNECT from a user agent the context turns away: it is refused as
 * any other request of its would be, not given to the fallback role first.
 *
 * And an h1 POST with neither Content-Length nor Transfer-Encoding: it has
 * no body (RFC 9112 6.3), and the request pipelined behind its head is the
 * next one served, not read as its body until the close.
 *
 * And a peer that finishes while the connection holds its reading behind a
 * partial send, reported the OSX way, a bare POLLHUP in place of the POLLOUT:
 * what it sent before finishing is still read.
 *
 * And a peer that resets the connection while rx it sent is parked and cannot
 * be taken yet, reported the Linux way, POLLHUP and POLLERR on every poll
 * until the close: an h1 request pipelined behind a file being served goes
 * with the connection at once, and a ws message held by rx flow control
 * gets the close timeout's grace, counted from the first time the reset is
 * seen, not from the last.  And a connection asking for nothing, its rx held
 * by flow control and nothing to send, hears the peer's close as a bare
 * POLLHUP, the way BSD and OSX report it: it ends at once, or when the grace
 * is up if it still holds rx.
 *
 * And an h1 server answering a request on a connection the peer asked to
 * close, with a request pipelined behind it parked while the answer went:
 * its close is staged, waiting for the peer's FIN, and the loop waits with
 * it rather than offering the parked request every turn to a connection
 * whose protocol is gone.
 *
 * And an h1 client whose server answers while its request body is still
 * going: it reads nothing until the body has gone, and does not ask to hear
 * of what it is not reading meanwhile, then it reads the answer.
 *
 * And a ws client told "100 Continue" ahead of its 101: it waits on for the
 * 101, and is established by it.  And an h1 client given a response with no
 * body (to a HEAD, or a 304) whose headers speak of one: it completes the
 * transaction at the end of the headers.
 *
 * Then whether the transport would take a write: a connection on the test's
 * transport is asked of the transport, never of the fd that is its place in
 * the poll set, even when that fd could not take a byte.
 *
 * Before any of it, the io_ops table is checked at context creation: one
 * not stamped with the ABI version the test was built with, or missing a
 * member lws calls without checking, is refused.
 *
 * Time is ours too: the test says what the time is (lws_service_set_now())
 * and lws takes it instead of the clock, so the bytes depend only on what
 * the test feeds.  Last, lws' timers run by the test's clock.
 *
 * Each connection's life is a transcript (transcripts/README.md): with
 * --transcripts <dir> what this run produces must be what is recorded
 * there, and --record <dir> writes them.
 */

#include <libwebsockets.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* the test's clock: a fixed start, so a run is the same whenever it is */
#define T0_US		((lws_usec_t)1000 * LWS_US_PER_SEC)
#define T0_WALL		((time_t)1767225600) /* 2026-01-01 00:00:00 UTC */
/* each thing that happens at a transport happens 1ms after the last */
#define TICK_US		((lws_usec_t)LWS_US_PER_MS)
/* the seed of lws' random, in a build that can seed it */
#define SEED		1

static lws_usec_t now_us = T0_US;

/* the time moves on a tick, and lws is told, running what fell due */
static void
tick(struct lws_context *cx)
{
	now_us += TICK_US;
	lws_service_set_now(cx, 0, now_us,
			    T0_WALL + (time_t)((now_us - T0_US) / LWS_US_PER_SEC));
}

/* the time moves on to ms after the start, and lws is told */
static void
at(struct lws_context *cx, int ms)
{
	now_us = T0_US + (lws_usec_t)ms * LWS_US_PER_MS;
	lws_service_set_now(cx, 0, now_us,
			    T0_WALL + (time_t)((now_us - T0_US) / LWS_US_PER_SEC));
}

/*
 * The transcripts (transcripts/README.md): each connection's life as data,
 * the times, the bytes its peer sent, the bytes lws wrote, what lws gave
 * the app and its close, for a port to replay and for this test to check
 * lws against.  With --record <dir> they are written there; with
 * --transcripts <dir> what this run produces must be what is there.
 */
static struct {
	char		*js;
	size_t		len, size;
	const char	*name;
	int		open;
	lws_usec_t	last_t;		/* the time and kind of the last step */
	const char	*last_kind;
	struct lws_context *cx;	/* whose random a seeded transcript reseeds */
	int		random;	/* its bytes depend on lws' random */
	int		steps;
	int		fails;
} tr;

static const char *record_dir, *check_dir;

/* append to the transcript, growing it as needed */
static void
tr_append(const char *fmt, ...)
{
	va_list ap;
	size_t n;
	char *p;
	int m;

	if (tr.fails)
		return;

	for (n = 0; n < 2; n++) {
		va_start(ap, fmt);
		m = vsnprintf(tr.js ? tr.js + tr.len : NULL,
			      tr.js ? tr.size - tr.len : 0, fmt, ap);
		va_end(ap);
		if (m < 0)
			goto oom;
		if (tr.js && tr.len + (size_t)m < tr.size) {
			tr.len += (size_t)m;
			return;
		}
		p = realloc(tr.js, tr.size + (size_t)m + 4096);
		if (!p)
			goto oom;
		tr.js = p;
		tr.size += (size_t)m + 4096;
	}

oom:
	lwsl_err("transcript: OOM\n");
	tr.fails++;
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
#define RANDOM_SEEDED 1 /* lws_fi_random_seed() exists */
#else
#define RANDOM_SEEDED 0
#endif

/*
 * A connection's transcript starts; side is "server" or "client".  One whose
 * bytes depend on lws' random starts the seeded stream afresh, so what it
 * draws does not depend on what the cases before it drew, or on which of
 * them this build has.
 */
static void
tr_begin(const char *name, const char *side, int random)
{
#if RANDOM_SEEDED
	if (random)
		lws_fi_random_seed(tr.cx, SEED);
#endif
	tr.len = 0;
	tr.name = name;
	tr.random = random;
	tr.open = 1;
	tr.steps = 0;
	tr.last_kind = NULL;

	tr_append("{\n \"format\": \"lws-transcript/1\",\n"
		  " \"case\": \"%s\",\n \"side\": \"%s\",\n"
		  " \"t0_us\": %lld,\n \"t0_wall\": %lld,\n"
		  " \"seed\": %d,\n \"steps\": [", name, side,
		  (long long)T0_US, (long long)T0_WALL, random ? SEED : 0);
}

/*
 * One thing that happened: kind is rx, tx, app_rx or close.  Bytes lws
 * wrote in several writes at the same time are one tx step: how many writes
 * it takes is lws' business, not the transcript's.
 */
static void
tr_step(const char *kind, const uint8_t *buf, size_t len)
{
	size_t n;

	if (!tr.open)
		return;

	if (tr.last_kind && !strcmp(kind, "tx") &&
	    !strcmp(tr.last_kind, "tx") && tr.last_t == now_us)
		tr.len -= 2; /* reopen the last step's hex, before its "} */
	else
		tr_append("%s\n  {\"t\": %lld, \"%s\": \"",
			  tr.steps++ ? "," : "", (long long)(now_us - T0_US),
			  kind);
	for (n = 0; n < len; n++)
		tr_append("%02x", buf[n]);
	tr_append("\"}");

	tr.last_kind = kind;
	tr.last_t = now_us;
}

/* how much at p to show: up to the end of its line, at most 100 */
static int
line_len(const char *p, size_t max)
{
	size_t n = 0;

	while (n < max && n < 100 && p[n] != '\n')
		n++;

	return (int)n;
}

/*
 * The connection's transcript ends: written to record_dir, or compared with
 * the one in check_dir.  A transcript whose bytes depend on lws' random can
 * only be reproduced in a build that seeds it.  Returns nonzero on failure.
 */
static int
tr_end(void)
{
	char path[256], *exp = NULL;
	size_t elen = 0, esize = 0, n, line = 1, ls = 0;
	ssize_t r;
	int fd, e = 1;

	tr_append("\n ]\n}\n");
	tr.open = 0;
	if (tr.fails)
		return 1;

	if (!record_dir && !check_dir)
		return 0;

	if (tr.random && !RANDOM_SEEDED) {
		if (record_dir) {
			lwsl_err("%s: not recorded: its bytes depend on lws' "
				 "random, which only a build with fault "
				 "injection seeds\n", tr.name);
			return 1;
		}
		lwsl_user("transcript %s: not checked, it needs lws' random "
			  "seeded (fault injection)\n", tr.name);
		return 0;
	}

	lws_snprintf(path, sizeof(path), "%s/%s.json",
		     record_dir ? record_dir : check_dir, tr.name);

	if (record_dir) {
		fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
		if (fd < 0 || write(fd, tr.js, tr.len) != (ssize_t)tr.len) {
			lwsl_err("%s: unable to write\n", path);
			if (fd >= 0)
				close(fd);
			return 1;
		}
		close(fd);
		lwsl_user("transcript %s: recorded\n", path);

		return 0;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: missing\n", path);
		return 1;
	}
	do {
		if (elen + 4096 > esize) {
			char *p = realloc(exp, esize + 16384);

			if (!p)
				goto bail;
			exp = p;
			esize += 16384;
		}
		r = read(fd, exp + elen, esize - elen);
		if (r > 0)
			elen += (size_t)r;
	} while (r > 0);
	if (r < 0)
		goto bail;

	if (elen == tr.len && !memcmp(exp, tr.js, elen)) {
		lwsl_user("transcript %s: matches\n", tr.name);
		e = 0;
		goto bail;
	}

	/* say where it went different, by line */
	for (n = 0; n < elen && n < tr.len && exp[n] == tr.js[n]; n++)
		if (exp[n] == '\n') {
			line++;
			ls = n + 1;
		}
	lwsl_err("transcript %s: differs from %s at line %d, column %d:\n",
		 tr.name, path, (int)line, (int)(n - ls + 1));

	/* show from a little before where they part, within the line */
	if (n - ls > 40)
		ls = n - 40;
	lwsl_err("  expected: ...%.*s\n", line_len(exp + ls, elen - ls),
		 exp + ls);
	lwsl_err("  got:      ...%.*s\n", line_len(tr.js + ls, tr.len - ls),
		 tr.js + ls);

bail:
	close(fd);
	free(exp);

	return e;
}

/*
 * A transport: the bytes the peer sent, waiting to be read, and the bytes
 * the connection wrote.  fd is the connection's place in lws's poll set;
 * want_read and want_write are what lws asked of the transport, as the
 * test heard them through the io_ops; read_resumed counts the times lws
 * asked to read again after it had stopped.  fin is the peer having finished
 * sending: past what it sent, reads find the end, and the poll reports it
 * the way OSX does, a bare POLLHUP, never together with POLLOUT.  reset is
 * the peer having reset the connection: past what it sent, reads and writes
 * fail, and the poll reports it the way Linux does, POLLHUP and POLLERR on
 * every poll, whatever was asked for, with POLLIN and POLLOUT if they were.
 */
struct transport {
	const uint8_t	*rx;
	size_t		rx_len, rx_pos;
	uint8_t		tx[65536];
	size_t		tx_len;
	size_t		tx_limit;	/* the most one write takes, 0: all */
	long		tx_budget;	/* bytes it takes before it takes no
					 * more, -1: no end */
	int		fd;
	int		want_read;
	int		read_resumed;
	int		want_write;
	int		shutdown;
	int		closed;
	int		fin;
	int		reset;
};

static struct transport *transports[32];
static int ntransports;

static int
tp_read(struct lws *wsi, void *opaque, uint8_t *buf, size_t len)
{
	struct transport *t = (struct transport *)opaque;
	size_t n = t->rx_len - t->rx_pos;

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
tp_write(struct lws *wsi, void *opaque, const uint8_t *buf, size_t len)
{
	struct transport *t = (struct transport *)opaque;

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
	if (t->tx_len + len > sizeof(t->tx))
		return LWS_SSL_CAPABLE_ERROR;
	memcpy(t->tx + t->tx_len, buf, len);
	t->tx_len += len;
	tr_step("tx", buf, len);

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

	/*
	 * A mux stream has no socket of its own, nor a transport: it must not
	 * be taken for a transport that has lost its fd
	 */
	if (fd < 0)
		return NULL;

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

	if (t) {
		if (on && !t->want_read)
			t->read_resumed++;
		t->want_read = on;
	}

	return lws_io_ops_default.want_read(wsi, on);
}

/* lws releasing a transport of ours is the connection's close */
static int
tp_close(struct lws *wsi, int phase)
{
	struct transport *t = tp_of(wsi);

	/* lws stopped sending, eg, waiting for the peer to close too */
	if (phase == LWS_IOCLOSE_SHUTDOWN && t)
		t->shutdown = 1;
	if (phase == LWS_IOCLOSE_RELEASE && t) {
		t->closed = 1;
		tr_step("close", NULL, 0);
	}

	return lws_io_ops_default.close(wsi, phase);
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
	t->tx_budget = -1;

	/* an earlier transport's fd was closed and is reused now: not his */
	for (n = 0; n < ntransports; n++)
		if (transports[n] != t && transports[n]->fd == fd)
			transports[n]->fd = -1;

	for (n = 0; n < ntransports; n++)
		if (transports[n] == t)
			return 0;
	if (ntransports == (int)LWS_ARRAY_SIZE(transports)) {
		lwsl_err("%s: more transports than transports[]\n", __func__);
		return 1;
	}
	transports[ntransports++] = t;

	return 0;
}

/*
 * Offer the connection what happened at its transport: the bytes waiting,
 * while lws will read them, and a turn to write for each time it asked.
 * lws may have parked bytes it read but has not acted on yet (the body
 * that came with a response's headers): a real loop gives those a pass
 * without the socket saying anything, and so do we, while it says it holds
 * some.  There is no poll() of the transport: the test says what happened,
 * until nothing more can... except that a connection waiting on a worker
 * has nothing to say until the worker's result is back, so then we wait
 * for lws' wake, have lws pick the result up, and go on.
 */
/*
 * A case that wants a worker's result left out, for something to happen
 * meanwhile, holds them: the worker still does the work, but its result is
 * not picked up until the hold is let go
 */
static int workers_held;

static int
await_workers(struct lws_context *cx)
{
	struct lws_pollfd pfd;
	int budget = 100; /* 50ms each: 5s */

	if (workers_held || !lws_service_work_outstanding(cx))
		return 0;

	pfd.fd = lws_service_wake_fd(cx, 0);
	if (pfd.fd == LWS_SOCK_INVALID) {
		lwsl_err("%s: work outstanding and no wake fd\n", __func__);
		return 0;
	}

	while (budget--) {
		pfd.events = LWS_POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 50) > 0 && (pfd.revents & LWS_POLLIN)) {
			lws_service_fd(cx, &pfd);
			return 1;
		}
		if (!lws_service_work_outstanding(cx))
			/* what was out went without needing the wake */
			return 0;
	}

	lwsl_err("%s: a worker did not come back\n", __func__);

	return 0;
}

static void
pump(struct lws_context *cx, struct transport *t)
{
	int n;

	for (n = 0; n < 64; n++) {
		struct lws_pollfd pfd;
		size_t rpos = t->rx_pos, tlen = t->tx_len;
		int held = !lws_service_adjust_timeout(cx, 1, 0),
		    reading = t->want_read;
		int in = t->want_read &&
			 (t->rx_pos < t->rx_len || held || t->fin || t->reset),
		    /* can take some, and never reported with a bare hangup */
		    out = t->want_write &&
			  ((t->tx_budget && !t->fin) || t->reset);

		pfd.fd = t->fd;
		/* what lws asked of the transport is what it polls for */
		pfd.events = (short)((t->want_read ? LWS_POLLIN : 0) |
				     (t->want_write ? LWS_POLLOUT : 0));
		pfd.revents = (short)((in ? LWS_POLLIN : 0) |
				      (out ? LWS_POLLOUT : 0) |
				      (t->fin ? POLLHUP : 0) |
				      (t->reset ? POLLHUP | POLLERR : 0));
		if (!pfd.revents) {
			if (await_workers(cx))
				continue;
			return;
		}
		/*
		 * Offered, lws asks again if it still wants it... but a pass
		 * that also reads leaves POLLOUT for the next one (IO's
		 * fairness), and a real poll, level-triggered, would report it
		 * again then
		 */
		if (out && !in)
			t->want_write = 0;

		/*
		 * a nonzero return is not the connection gone: failing it,
		 * a ws connection still has its close to send, and a real
		 * loop's next poll() gives it the POLLOUT for it
		 */
		if (lws_service_fd(cx, &pfd) && t->closed)
			return;

		/*
		 * the pass changed nothing we can see (asking to read again is
		 * a change: a real poll() reports what is waiting next time):
		 * it is waiting on us
		 */
		if (t->rx_pos == rpos && t->tx_len == tlen && !t->want_write &&
		    t->want_read == reading &&
		    held == !lws_service_adjust_timeout(cx, 1, 0) &&
		    !await_workers(cx))
			return;
	}
}

/*
 * what the peer sent arrives, a tick after the last thing; returns nonzero
 * if it was not all taken
 */
static int
feed(struct lws_context *cx, struct transport *t, const void *s, size_t len)
{
	tick(cx);
	tr_step("rx", (const uint8_t *)s, len);

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

/*
 * The uri vhost's http protocol: answers 200 with what lws made of the
 * request line, the path, a newline, then the args
 */

struct pss_uri {
	char		body[256];
	int		len;
	int		completed;
	int		slow;	/* /slow: pieces still to write */
	int		in_body; /* /in-body: 1 body awaited, 2 answer started */
	int		abandon; /* /abandon: the timer completes the file */
};

/* /slow's answer: SLOW_PIECES of 100 bytes, one every SLOW_GAP_US */
#define SLOW_PIECES	5
#define SLOW_GAP_US	(8 * LWS_US_PER_SEC)

/* what the uri vhost's app saw of transactions it completed */
static int uri_late_writeable, uri_closed;
/* a transport that is to take only a little of the /early response */
static struct transport *early_tp;
/* what /file answers with, relative to where ctest runs us */
#define EARLY_FILE "transcripts/README.md"
/* when /abandon's app gives up on the file it is serving */
#define ABANDON_US	(5 * LWS_US_PER_MS)

static int
callback_uri(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 512], *p = buf + LWS_PRE, *end = buf + sizeof(buf);
	struct pss_uri *pss = (struct pss_uri *)user;
	size_t o;
	int n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (in && !strcmp((const char *)in, "/early")) {
			/*
			 * Answered, whole, before any body, and completed
			 * at once, the way a naive app does
			 */
			if (early_tp)
				/* the transport takes 4 bytes of it */
				early_tp->tx_budget = 4;
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 3, &p, end) ||
			    lws_finalize_write_http_header(wsi, buf + LWS_PRE,
							   &p, end))
				return 1;
			p = buf + LWS_PRE;
			memcpy(p, "ok\n", 3);
			if (lws_write(wsi, p, 3, LWS_WRITE_HTTP_FINAL) != 3)
				return 1;
			pss->completed = 1;
			if (lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}
#if defined(LWS_WITH_FILE_OPS)
		if (in && !strcmp((const char *)in, "/file")) {
			/* a file is the answer, before any body */
			if (early_tp)
				early_tp->tx_budget = 4;
			pss->completed = 1;
			n = lws_serve_http_file(wsi, EARLY_FILE, "text/plain",
						NULL, 0);
			if (n < 0 ||
			    (n > 0 && lws_http_transaction_completed(wsi)))
				return -1;
			return 0;
		}
		if (in && !strcmp((const char *)in, "/abandon")) {
			/*
			 * a file is the answer, before any body, but the app
			 * gives up on it shortly, see LWS_CALLBACK_TIMER
			 */
			n = lws_serve_http_file(wsi, EARLY_FILE, "text/plain",
						NULL, 0);
			if (n)
				/* we want it still being served for the timer */
				return -1;
			pss->abandon = 1;
			lws_set_timer_usecs(wsi, ABANDON_US);
			return 0;
		}
#endif
		if (in && !strcmp((const char *)in, "/short")) {
			/* says 10 bytes, sends 3 (none to a HEAD), completes */
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 10, &p, end) ||
			    lws_finalize_write_http_header(wsi, buf + LWS_PRE,
							   &p, end))
				return 1;
			if (!lws_hdr_total_length(wsi, WSI_TOKEN_HEAD_URI)) {
				p = buf + LWS_PRE;
				memcpy(p, "abc", 3);
				if (lws_write(wsi, p, 3, LWS_WRITE_HTTP_FINAL) != 3)
					return 1;
			}
			if (lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}
		if (in && !strcmp((const char *)in, "/in-body")) {
			/* answered from the body's first piece, see below */
			pss->in_body = 1;
			return 0;
		}
		if (in && !strcmp((const char *)in, "/slow")) {
			/* answered a piece at a time, as the app has them */
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", SLOW_PIECES * 100,
						&p, end) ||
			    lws_finalize_write_http_header(wsi, buf + LWS_PRE,
							   &p, end))
				return 1;
			pss->slow = SLOW_PIECES;
			lws_set_timer_usecs(wsi, SLOW_GAP_US);
			return 0;
		}
		n = lws_hdr_copy(wsi, pss->body, (int)sizeof(pss->body) - 1,
				 WSI_TOKEN_GET_URI);
		if (!n)
			n = lws_hdr_copy(wsi, pss->body,
					 (int)sizeof(pss->body) - 1,
					 WSI_TOKEN_POST_URI);
		if (n < 0)
			return 1;
		/*
		 * The copy is NUL-terminated, so measure what's in the buffer
		 * rather than trusting the returned length as an index.  We
		 * keep room for the '\n' and the args' NUL after it.
		 */
		o = strlen(pss->body);
		if (o > sizeof(pss->body) - 2)
			return 1;
		pss->body[o++] = '\n';
		if (lws_hdr_copy(wsi, pss->body + o, (int)(sizeof(pss->body) - o),
				 WSI_TOKEN_HTTP_URI_ARGS) < 0)
			return 1;
		pss->len = (int)strlen(pss->body);
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
						(lws_filepos_t)pss->len, &p, end) ||
		    lws_finalize_write_http_header(wsi, buf + LWS_PRE, &p, end))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_TIMER:
		if (pss->abandon) {
			/*
			 * /abandon: the app completes the transaction from
			 * under the file it is serving, the request's body
			 * still to come
			 */
			pss->abandon = 0;
			pss->completed = 1;
			if (lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}
		/* /slow has its next piece */
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		if (pss->in_body == 1) {
			/*
			 * /in-body: the answer starts now, while the rest of
			 * the body is still to come, as an app relaying a
			 * request would start it
			 */
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
							"text/plain", 200,
							&p, end) ||
			    lws_finalize_write_http_header(wsi, buf + LWS_PRE,
							   &p, end))
				return 1;
			pss->in_body = 2;
			return 0;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		/*
		 * The answer is under way, from LWS_CALLBACK_HTTP or from the
		 * body's first piece: the body's end changes nothing, the
		 * answer goes on from the writeable (the dummy would answer
		 * again here, or complete the transaction from under it)
		 */
		if (pss->in_body)
			lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (pss->completed) {
			/* nothing is ours to write after we completed it */
			uri_late_writeable++;
			return 0;
		}
		if (pss->in_body) {
			/*
			 * /in-body: as much of the answer as the peer's
			 * window takes, up to half of it; the rest waits
			 * for a window that never comes
			 */
			n = (int)lws_get_peer_write_allowance(wsi);
			if (n < 0 || n > 100)
				n = 100;
			if (n) {
				memset(p, 'b', (size_t)n);
				if (lws_write(wsi, p, (size_t)n,
					      LWS_WRITE_HTTP) != n)
					return 1;
			}
			lws_callback_on_writable(wsi);
			return 0;
		}
		if (pss->slow) {
			memset(p, 's', 100);
			if (lws_write(wsi, p, 100, --pss->slow ?
				      LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL) !=
									100)
				return 1;
			if (pss->slow) {
				lws_set_timer_usecs(wsi, SLOW_GAP_US);
				return 0;
			}
			pss->completed = 1;
			if (lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}
		memcpy(p, pss->body, (size_t)pss->len);
		if (lws_write(wsi, p, (size_t)pss->len, LWS_WRITE_HTTP_FINAL) !=
								pss->len)
			return 1;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss && (pss->completed || pss->in_body))
			uri_closed++;
		break;

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
		tr_step("app_rx", in, len);
		/* "Hold" stops its rx, and is not echoed: case 28 */
		if (len == 4 && !memcmp(in, "Hold", 4)) {
			lws_rx_flow_control(wsi, 0);
			return 0;
		}
		/* it echoes whole messages */
		if (!lws_is_first_fragment(wsi) || !lws_is_final_fragment(wsi))
			return 0;
		if (len > sizeof(buf) - LWS_PRE)
			return -1;
		memcpy(buf + LWS_PRE, in, len);
		if (lws_write(wsi, buf + LWS_PRE, len, LWS_WRITE_TEXT) != (int)len)
			return -1;
		/* "Bye" is the last: close once its echo has gone */
		if (len == 3 && !memcmp(in, "Bye", 3))
			return lws_raw_transaction_completed(wsi);
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
	int		quiet; /* the ws client sends nothing */
	int		sent;
	int		error;
} cli;

/* a POST body of this many 16-byte pieces, which go while post_go is set */
static int post_pieces, post_go;

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
		tr_step("app_rx", in, len);
		if (cli.rx_len + len > sizeof(cli.rx))
			return -1;
		memcpy(cli.rx + cli.rx_len, in, len);
		cli.rx_len += len;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		cli.completed = 1;
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		/* a POST: say how much body, and that it follows */
		if (post_pieces) {
			unsigned char **pp = (unsigned char **)in, *end = *pp + len;
			char cl[16];

			lenx = lws_snprintf(cl, sizeof(cl), "%d",
					    post_pieces * 16);
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(unsigned char *)cl, lenx, pp, end))
				return -1;
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		/* a piece of the body a turn, while the test lets it go */
		if (!post_pieces || !post_go)
			break;
		memset(buf + LWS_PRE, 'b', 16);
		if (lws_write(wsi, buf + LWS_PRE, 16, --post_pieces ?
			      LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL) != 16)
			return -1;
		if (post_pieces)
			lws_callback_on_writable(wsi);
		else
			lws_client_http_body_pending(wsi, 0);
		break;

	/* ws */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		cli.established = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (cli.sent || cli.quiet)
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

#if !defined(LWS_WITHOUT_EXTENSIONS)
static const struct lws_extension extensions[] = {
	{ "permessage-deflate", lws_extension_callback_pm_deflate,
	  "permessage-deflate" },
	{ NULL, NULL, NULL }
};
#endif

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	{ "echo", callback_echo, 0, 128, 0, NULL, 0 },
#if defined(LWS_WITH_CLIENT)
	{ "client", callback_client, 0, 128, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_uri[] = {
	{ "http", callback_uri, sizeof(struct pss_uri), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#if defined(LWS_WITH_FILE_OPS)

/*
 * The 404 vhost's http protocol: whatever reaches it is not found, and
 * lws_return_http_status() decides how to say so: a redirect to the vhost's
 * 404 document, or, for the 404 document itself, the status page
 */
static int
callback_404(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL) ||
		    lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_404[] = {
	{ "http", callback_404, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* /cb goes to the protocol directly */
static const struct lws_http_mount mount_404_cb = {
	.mountpoint		= "/cb",
	.origin			= "http",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 3,
};

/* a directory mount: a request for /d itself is redirected to /d/ */
static const struct lws_http_mount mount_404_dir = {
	.mount_next		= &mount_404_cb,
	.mountpoint		= "/d",
	.origin			= "/nonexistent-lws-sansio",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 2,
};

/* the rest are files in a dir that is not there, falling back to it */
static const struct lws_http_mount mount_404_files = {
	.mount_next		= &mount_404_dir,
	.mountpoint		= "/",
	.origin			= "/nonexistent-lws-sansio",
	.protocol		= "http",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};
#endif

/*
 * The context's header limits: only two of them, for the h1 cases that
 * go past them.  Nothing else any other case sends comes near them.
 */
static struct lws_token_limits token_limits;

#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
/* a user agent the context turns away, whatever it asks for */
static const struct lws_protocol_vhost_options reject_badbot = {
	NULL, NULL, "badbot", "403 Go away"
};
#endif

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
	tr_begin("h1-ws-server", "server", 0);

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

	return tr_end();
}

/*
 * 9: a ws upgrade lws will not do is answered with why, before the
 * connection is shut down: a version other than 13, the only one there is,
 * gets 426 saying 13 (RFC 6455 4.2.2); no version, a Connection header
 * without the upgrade token, only subprotocols lws does not have, or a
 * method other than GET (RFC 6455 4.1), 400
 */
static int
upgrade_refusals_half(struct lws_context *cx)
{
#define UPG_REQ(conn, ver, pcol) \
	"GET /echo HTTP/1.1\r\nHost: sansio\r\nUpgrade: websocket\r\n" \
	"Connection: " conn "\r\n" ver \
	"Sec-WebSocket-Protocol: " pcol "\r\n" \
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	static const struct {
		const char	*name;
		const char	*req;
		const char	*status;
		const char	*hdr;	/* a header the refusal must have */
	} c[] = {
		{ "ws-server-version-8",
		  UPG_REQ("Upgrade", "Sec-WebSocket-Version: 8\r\n", "echo"),
		  "HTTP/1.1 426 ", "\r\nsec-websocket-version: 13\r\n" },
		{ "ws-server-no-version",
		  UPG_REQ("Upgrade", "", "echo"), "HTTP/1.1 400 ", NULL },
		{ "ws-server-conn-no-upgrade",
		  UPG_REQ("up", "Sec-WebSocket-Version: 13\r\n", "echo"),
		  "HTTP/1.1 400 ", NULL },
		{ "ws-server-no-subprotocol",
		  UPG_REQ("Upgrade", "Sec-WebSocket-Version: 13\r\n", "chat"),
		  "HTTP/1.1 400 ", NULL },
		{ "ws-server-not-get",
		  "POST /echo HTTP/1.1\r\nHost: sansio\r\n"
		  "Upgrade: websocket\r\nConnection: Upgrade\r\n"
		  "Sec-WebSocket-Version: 13\r\n"
		  "Sec-WebSocket-Protocol: echo\r\n"
		  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		  "HTTP/1.1 400 ", NULL },
	};
#undef UPG_REQ
	static struct transport tp;
	struct lws *wsi;
	size_t n;
	int sv[2];

	for (n = 0; n < LWS_ARRAY_SIZE(c); n++) {
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
		tr_begin(c[n].name, "server", 0);

		feed(cx, &tp, c[n].req, strlen(c[n].req));
		if (!tp.shutdown || tp.tx_len < 13 ||
		    memcmp(tp.tx, c[n].status, 13) ||
		    (c[n].hdr && !find_bytes(tp.tx, tp.tx_len, c[n].hdr))) {
			lwsl_err("case 9: %s: not refused as expected\n",
				 c[n].name);
			lwsl_hexdump_err(tp.tx, tp.tx_len);
			return 1;
		}
		if (tr_end())
			return 1;
	}
	lwsl_user("case 9: refused ws upgrades say why: PASS\n");

	return 0;
}

/*
 * 13: what lws makes of an h1 request line and headers, on a vhost whose
 * app answers with the path and args lws gave it.  The path's dot segments
 * go, even just before the args; '+' is a space in the args, but itself in
 * the path; and a request line or a header past its token limit fails the
 * request with 414 or 431, rather than being cut short and served.  A
 * request line without a version (HTTP/0.9), a head without a request line,
 * or a version that is not "HTTP/" digit "." digit is refused with 400, and
 * a major version other than 1 with 505; HTTP/1.2 is served as 1.1.  A
 * method lws does not know is refused with 501, a head starting with a
 * header rather than a request line with 400; up to eight empty lines
 * before the request line are ignored, more are 400.
 */
static int
uri_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct {
		const char	*name;
		const char	*req;
		const char	*body; /* NULL: refused with status */
		const char	*status;
	} c[] = {
		{ "h1-uri-dotdot-args", "GET /x/..?a=b HTTP/1.1\r\n"
			"Host: sansio-uri\r\n\r\n", "/\na=b", NULL },
		{ "h1-uri-dot-args", "GET /x/.?a=b HTTP/1.1\r\n"
			"Host: sansio-uri\r\n\r\n", "/x/\na=b", NULL },
		{ "h1-uri-plus", "GET /a+b?c+d=e+f HTTP/1.1\r\n"
			"Host: sansio-uri\r\n\r\n", "/a+b\nc d=e f", NULL },
		{ "h1-uri-at-limit", "GET /23456789012345678901234567890123 "
			"HTTP/1.1\r\nHost: sansio-uri\r\n\r\n",
			"/23456789012345678901234567890123\n", NULL },
		{ "h1-uri-past-limit", "GET /234567890123456789012345678901234 "
			"HTTP/1.1\r\nHost: sansio-uri\r\n\r\n", NULL,
			"HTTP/1.1 414 " },
		{ "h1-header-past-limit", "GET / HTTP/1.1\r\n"
			"Host: sansio-uri\r\n"
			"User-Agent: 12345678901234567\r\n\r\n", NULL,
			"HTTP/1.1 431 " },
		/* the request line is method, target and HTTP version */
		{ "h1-reqline-http09", "GET /x\r\n", NULL, "HTTP/1.1 400 " },
		{ "h1-reqline-no-method", "Host: sansio-uri\r\n\r\n", NULL,
			"HTTP/1.1 400 " },
		{ "h1-reqline-version-2", "GET /x HTTP/2.0\r\n"
			"Host: sansio-uri\r\n\r\n", NULL, "HTTP/1.1 505 " },
		{ "h1-reqline-version-junk", "GET /x HTTP/1.x\r\n"
			"Host: sansio-uri\r\n\r\n", NULL, "HTTP/1.1 400 " },
		{ "h1-reqline-version-long", "GET /x HTTP/1.10\r\n"
			"Host: sansio-uri\r\n\r\n", NULL, "HTTP/1.1 400 " },
		{ "h1-reqline-version-1-2", "GET /x HTTP/1.2\r\n"
			"Host: sansio-uri\r\n\r\n", "/x\n", NULL },
		{ "h1-reqline-unknown-method", "FOO /x HTTP/1.1\r\n"
			"Host: sansio-uri\r\n\r\n", NULL, "HTTP/1.1 501 " },
		{ "h1-reqline-unknown-header-first", "X-Foo: bar\r\n"
			"Host: sansio-uri\r\n\r\n", NULL, "HTTP/1.1 400 " },
		/* a few empty lines before the request line are ignored */
		{ "h1-reqline-leading-empty", "\r\n\r\nGET /x HTTP/1.1\r\n"
			"Host: sansio-uri\r\n\r\n", "/x\n", NULL },
		{ "h1-reqline-leading-empty-many", "\r\n\r\n\r\n\r\n\r\n\r\n"
			"\r\n\r\n\r\nGET /x HTTP/1.1\r\n"
			"Host: sansio-uri\r\n\r\n", NULL, "HTTP/1.1 400 " },
	};
	static struct transport tp;
	const uint8_t *b;
	struct lws *wsi;
	size_t n;
	int sv[2];

	for (n = 0; n < LWS_ARRAY_SIZE(c); n++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
			lwsl_err("socketpair failed\n");
			return 1;
		}
		close(sv[1]);
		if (tp_register(&tp, sv[0]))
			return 1;
		wsi = lws_adopt_socket_vhost(vh, sv[0]);
		if (!wsi) {
			lwsl_err("adopt failed\n");
			return 1;
		}
		lws_set_transport(wsi, &tops, &tp);
		tr_begin(c[n].name, "server", 0);

		feed(cx, &tp, c[n].req, strlen(c[n].req));
		if (!c[n].body) {
			if ((!tp.shutdown && !tp.closed) || tp.tx_len < 13 ||
			    memcmp(tp.tx, c[n].status, 13)) {
				lwsl_err("case 13: %s: not refused\n",
					 c[n].name);
				lwsl_hexdump_err(tp.tx, tp.tx_len);
				return 1;
			}
		} else {
			b = find_bytes(tp.tx, tp.tx_len, "\r\n\r\n");
			if (tp.tx_len < 13 || memcmp(tp.tx, "HTTP/1.1 200 ", 13) ||
			    !b || (size_t)(tp.tx + tp.tx_len - (b + 4)) !=
							strlen(c[n].body) ||
			    memcmp(b + 4, c[n].body, strlen(c[n].body))) {
				lwsl_err("case 13: %s: wrong\n", c[n].name);
				lwsl_hexdump_err(tp.tx, tp.tx_len);
				return 1;
			}
		}
		if (tr_end())
			return 1;
	}
	lwsl_user("case 13: h1 request line and header handling: PASS\n");

	return 0;
}

/*
 * Is there a ws frame at *pos in tx, FIN and opcode op with payload pl, and
 * masked or not?  If so, moves *pos past it.
 */
static int
ws_frame_at(const struct transport *tp, size_t *pos, uint8_t op, int masked,
	    const char *pl, size_t plen)
{
	const uint8_t *f = tp->tx + *pos, *m = f + 2;
	size_t n, hl = 2 + (masked ? 4u : 0u);

	if (*pos + hl + plen > tp->tx_len || f[0] != (0x80 | op) ||
	    f[1] != ((masked ? 0x80 : 0) | plen))
		return 0;
	for (n = 0; n < plen; n++)
		if ((f[hl + n] ^ (masked ? m[n & 3] : 0)) != (uint8_t)pl[n])
			return 0;
	*pos += hl + plen;

	return 1;
}

/*
 * 18: the ws peer starts the close.  A ping it sent first still gets its
 * pong, ahead of the answer to the close, which carries its own status
 * back; and a close that comes while the echo of a frame just before it
 * is only partly written is answered once the echo has all gone, rather
 * than the connection dropped.  Then the connection is shut down, or
 * released.
 *
 * But a close that comes while the server is already closing, once its
 * last echo has gone (lws_raw_transaction_completed() with the echo partly
 * written), is not answered: the echo still all goes, and then the
 * connection ends.
 *
 * Having had the peer's close, the server reads nothing more, even when an
 * echo still partly written drains after it.
 */
static int
ws_server_peer_close_half(struct lws_context *cx)
{
	static const char req_ws[] =
		"GET /echo HTTP/1.1\r\nHost: sansio\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Protocol: echo\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
	/* masked, zero key: PING "p", then CLOSE 1000 */
	static const char ping_close[] = "\x89\x81\x00\x00\x00\x00p"
					 "\x88\x82\x00\x00\x00\x00\x03\xe8";
	/* masked, zero key: TEXT "Hello", then CLOSE 1000 */
	static const char text_close[] = "\x81\x85\x00\x00\x00\x00Hello"
					 "\x88\x82\x00\x00\x00\x00\x03\xe8";
	/* masked, zero key: TEXT "Bye", the last, then CLOSE 1000 */
	static const char bye_close[] = "\x81\x83\x00\x00\x00\x00" "Bye"
					"\x88\x82\x00\x00\x00\x00\x03\xe8";
	static const struct {
		const char	*name;
		const char	*frames;
		size_t		len;
		size_t		tx_limit;
		uint8_t		op;	/* what goes before the close */
		const char	*pl;
		int		answered; /* the close is answered */
	} c[] = {
		{ "ws-server-ping-close", ping_close, sizeof(ping_close) - 1,
		  0, 0xa, "p", 1 },
		{ "ws-server-close-partial", text_close, sizeof(text_close) - 1,
		  4, 0x1, "Hello", 1 },
		{ "ws-server-close-when-flushed", bye_close,
		  sizeof(bye_close) - 1, 4, 0x1, "Bye", 0 },
	};
	static struct transport tp;
	struct lws *wsi;
	size_t n, pos;
	int sv[2];

	for (n = 0; n < LWS_ARRAY_SIZE(c); n++) {
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
		tr_begin(c[n].name, "server", 0);

		if (feed(cx, &tp, req_ws, sizeof(req_ws) - 1) ||
		    tp.tx_len < 13 || memcmp(tp.tx, "HTTP/1.1 101 ", 13)) {
			lwsl_err("case 18: %s: no upgrade\n", c[n].name);
			return 1;
		}

		tp.tx_limit = c[n].tx_limit;
		tp.read_resumed = 0;
		feed(cx, &tp, c[n].frames, c[n].len);
		if (tp.read_resumed) {
			lwsl_err("case 18: %s: read again after the close\n",
				 c[n].name);
			return 1;
		}
		pos = 0;
		if (!ws_frame_at(&tp, &pos, c[n].op, 0, c[n].pl,
				 strlen(c[n].pl)) ||
		    (c[n].answered &&
		     !ws_frame_at(&tp, &pos, 0x8, 0, "\x03\xe8", 2)) ||
		    pos != tp.tx_len || (!tp.closed && !tp.shutdown)) {
			lwsl_err("case 18: %s: closed %d\n", c[n].name,
				 tp.closed);
			lwsl_hexdump_err(tp.tx, tp.tx_len);
			return 1;
		}
		if (tr_end())
			return 1;
	}
	lwsl_user("case 18: ws server answers the peer's close: PASS\n");

	return 0;
}

/*
 * An h1 server connection as a series of requests, each answered with the
 * status (the first 13 bytes of the response) and, if has is set, carrying
 * those bytes too.  Unless the step says the connection ends, it must still
 * be open for the next request.
 */
struct h1_step {
	const char	*req;
	const char	*status;
	const char	*has;
	int		ends;
};

static int
h1_steps(struct lws_context *cx, struct lws_vhost *vh, const char *name,
	 const char *label, const struct h1_step *st, size_t count)
{
	static struct transport tp;
	struct lws *wsi;
	size_t n;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	tr_begin(name, "server", 0);

	for (n = 0; n < count; n++) {
		feed(cx, &tp, st[n].req, strlen(st[n].req));
		if (tp.tx_len < 13 || memcmp(tp.tx, st[n].status, 13) ||
		    (st[n].has && !find_bytes(tp.tx, tp.tx_len, st[n].has)) ||
		    (!st[n].ends && (tp.shutdown || tp.closed)) ||
		    (st[n].ends && !tp.shutdown && !tp.closed)) {
			lwsl_err("%s: %s: request %d: wanted '%.13s'%s%s\n",
				 label, name, (int)n, st[n].status,
				 st[n].ends ? ", then the end" : "",
				 (tp.shutdown || tp.closed) ? ", ended" : "");
			lwsl_hexdump_err(tp.tx, tp.tx_len);
			return 1;
		}
	}

	return tr_end();
}

/*
 * 34: an h1 POST with neither Content-Length nor Transfer-Encoding, and a
 * GET pipelined behind its head in the same read.  The POST has no body
 * (RFC 9112 6.3): it is answered, and the GET is the next request, served
 * after it on the kept-alive connection, rather than taken as the POST's
 * body and read until the close.
 */
static int
h1_post_no_length_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct h1_step st[] = {
		{ "POST /x?a=1 HTTP/1.1\r\nHost: sansio-uri\r\n\r\n"
		  "GET /y?b=2 HTTP/1.1\r\nHost: sansio-uri\r\n\r\n",
		  "HTTP/1.1 200 ", "/y\nb=2", 0 },
	};

	if (h1_steps(cx, vh, "h1-post-no-length", "case 34", st,
		     LWS_ARRAY_SIZE(st)))
		return 1;
	lwsl_user("case 34: an h1 POST with no length has no body, and the "
		  "request behind it is served: PASS\n");

	return 0;
}

/*
 * 39: an answer whose head gives a Content-Length of 10, completed by the
 * app after only 3 bytes of it: kept alive, the peer would read the next
 * answer as the rest of this one, so the connection is closed.  The same
 * answer to a HEAD is whole without its body, and the connection goes on.
 */
static int
h1_short_answer_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct h1_step st[] = {
		{ "HEAD /short HTTP/1.1\r\nHost: sansio-uri\r\n\r\n",
		  "HTTP/1.1 200 ", "content-length: 10\x0d\x0a", 0 },
		{ "GET /short HTTP/1.1\r\nHost: sansio-uri\r\n\r\n",
		  "HTTP/1.1 200 ", "\x0d\x0a\x0d\x0a" "abc", 1 },
	};

	if (h1_steps(cx, vh, "h1-short-answer", "case 39", st,
		     LWS_ARRAY_SIZE(st)))
		return 1;
	lwsl_user("case 39: an h1 answer completed short of its "
		  "Content-Length ends the connection: PASS\n");

	return 0;
}

#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
/*
 * 23: a CONNECT from a user agent the context rejects is refused with the
 * rejection's status, as any other request from it is, rather than taken
 * to the fallback role first
 */
static int
h1_connect_rejected_ua_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct h1_step st[] = {
		{ "CONNECT example.com:443 HTTP/1.1\r\n"
		  "Host: example.com:443\r\nUser-Agent: badbot/1\r\n\r\n",
		  "HTTP/1.1 403 ", NULL, 1 },
	};

	if (h1_steps(cx, vh, "h1-connect-rejected-ua", "case 23", st,
		     LWS_ARRAY_SIZE(st)))
		return 1;
	lwsl_user("case 23: a rejected user agent's CONNECT is refused: "
		  "PASS\n");

	return 0;
}
#endif

#if defined(LWS_WITH_FILE_OPS)
/*
 * 16: one keep-alive connection to a vhost whose 404 document is
 * /404.html.  A request nothing serves is redirected there; the 404
 * document, not being there either, is the status page; and the next
 * request nothing serves is redirected again, as the first was
 */
static int
h1_404_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct h1_step st[] = {
		{ "GET /x HTTP/1.1\r\nHost: sansio-404\r\n\r\n",
		  "HTTP/1.1 302 ", "/404.html\r\n", 0 },
		{ "GET /404.html HTTP/1.1\r\nHost: sansio-404\r\n\r\n",
		  "HTTP/1.1 404 ", NULL, 0 },
		{ "GET /cb/y HTTP/1.1\r\nHost: sansio-404\r\n\r\n",
		  "HTTP/1.1 302 ", "/404.html\r\n", 0 },
	};

	if (h1_steps(cx, vh, "h1-404-keepalive", "case 16", st,
		     LWS_ARRAY_SIZE(st)))
		return 1;
	lwsl_user("case 16: the 404 redirect is per transaction: PASS\n");

	return 0;
}

/*
 * 21: the mount's own redirect, for a directory asked for without its
 * trailing '/', while the transport takes only a few bytes: the transaction
 * completes once the redirect has all gone, and the kept-alive connection
 * takes its next request.  What the transport takes and when is not part of
 * a transcript, so this case has none.
 */
static int
h1_redirect_queued_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char req_d[] =
		"GET /d HTTP/1.1\r\nHost: sansio-404\r\n\r\n",
			  req_cb[] =
		"GET /cb/y HTTP/1.1\r\nHost: sansio-404\r\n\r\n";
	static uint8_t out[1024];
	static struct transport tp;
	struct lws *wsi;
	size_t outl;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);

	/* the transport takes 8 bytes of the redirect, then no more */
	tp.tx_budget = 8;
	feed(cx, &tp, req_d, sizeof(req_d) - 1);
	outl = tp.tx_len;
	memcpy(out, tp.tx, outl);

	/* ...and then the rest */
	tp.tx_budget = -1;
	tp.tx_len = 0;
	tick(cx);
	pump(cx, &tp);
	if (outl + tp.tx_len > sizeof(out) - 1) {
		lwsl_err("case 21: too much output\n");
		return 1;
	}
	memcpy(out + outl, tp.tx, tp.tx_len);
	outl += tp.tx_len;

	if (tp.closed || tp.shutdown || outl < 13 ||
	    memcmp(out, "HTTP/1.1 301 ", 13) ||
	    !find_bytes(out, outl, "http://sansio-404/d/\r\n")) {
		lwsl_err("case 21: redirect not whole, or connection ended\n");
		lwsl_hexdump_err(out, outl);
		return 1;
	}

	/* the connection goes on to the next request */
	feed(cx, &tp, req_cb, sizeof(req_cb) - 1);
	if (tp.closed || tp.shutdown || tp.tx_len < 13 ||
	    memcmp(tp.tx, "HTTP/1.1 302 ", 13)) {
		lwsl_err("case 21: next request not served\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 21: a queued mount redirect completes: PASS\n");

	return 0;
}
#endif

/*
 * 14: a ws server given a frame longer than lws takes (256MiB) closes with
 * 1009 saying so, the same as a client does
 */
static int
server_refused_frames_half(struct lws_context *cx)
{
	static const char req_ws[] =
		"GET /echo HTTP/1.1\r\nHost: sansio\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Protocol: echo\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
	/* FIN, BINARY, masked, 64-bit length 256MiB + 1 */
	static const char frame[] =
		"\x82\xff\x00\x00\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00";
	static const char refusal[] = "\x88\x0c\x03\xf1huge frame";
	static struct transport tp;
	struct lws *wsi;
	int sv[2];

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
	tr_begin("ws-server-huge-frame", "server", 0);

	if (feed(cx, &tp, req_ws, sizeof(req_ws) - 1) ||
	    tp.tx_len < 13 || memcmp(tp.tx, "HTTP/1.1 101 ", 13)) {
		lwsl_err("case 14: no upgrade\n");
		return 1;
	}
	feed(cx, &tp, frame, sizeof(frame) - 1);
	if (tp.tx_len != sizeof(refusal) - 1 ||
	    memcmp(tp.tx, refusal, sizeof(refusal) - 1)) {
		lwsl_err("case 14: huge frame not refused\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 14: ws server refuses a huge frame with 1009: PASS\n");

	return tr_end();
}

#if defined(LWS_WITH_HTTP2)

/* just enough HPACK (RFC 7541) and h2 framing to say what case 15 needs */

static uint8_t *
hp_int(uint8_t *p, uint8_t flags, int bits, uint32_t v)
{
	uint32_t max = (1u << bits) - 1;

	if (v < max) {
		*p++ = (uint8_t)(flags | v);
		return p;
	}
	*p++ = (uint8_t)(flags | max);
	v -= max;
	while (v >= 0x80) {
		*p++ = (uint8_t)(0x80 | (v & 0x7f));
		v >>= 7;
	}
	*p++ = (uint8_t)v;

	return p;
}

/* a string literal, not huffman coded: len copies of c, or s */
static uint8_t *
hp_str(uint8_t *p, const char *s, size_t len, char c)
{
	p = hp_int(p, 0, 7, (uint32_t)len);
	if (s)
		memcpy(p, s, len);
	else
		memset(p, c, len);

	return p + len;
}

static uint8_t *
h2_frame_hdr(uint8_t *p, size_t len, uint8_t type, uint8_t flags,
	     uint32_t sid)
{
	*p++ = (uint8_t)(len >> 16);
	*p++ = (uint8_t)(len >> 8);
	*p++ = (uint8_t)len;
	*p++ = type;
	*p++ = flags;
	lws_ser_wu32be(p, sid);

	return p + 4;
}

/* a HEADERS frame with END_STREAM | END_HEADERS, block from b to e */
static size_t
h2_headers(uint8_t *out, uint32_t sid, const uint8_t *b, const uint8_t *e)
{
	uint8_t *p = h2_frame_hdr(out, (size_t)(e - b), 1, 0x05, sid);

	memcpy(p, b, (size_t)(e - b));

	return (size_t)(p - out) + (size_t)(e - b);
}

/*
 * 15: an h2 request whose header block does not fit the ah is answered 431
 * "Oversized headers", and the connection goes on.  The rest of the block
 * is still decoded, which keeps the connection's hpack state in step: a
 * field it put in the dynamic table before the ah filled is still there for
 * later requests, but one it put there afterwards could not be kept, so a
 * later request that refers to it is answered 431 too, rather than served
 * as if the peer had not sent it.
 */
static int
h2_oversized_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		/* SETTINGS, then the ack of the server's */
		"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	static uint8_t blk[6000], fr[6100];
	static struct transport tp;
	struct lws *wsi;
	uint8_t *p;
	size_t n;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	tr_begin("h2-oversized-headers", "server", 0);

	feed(cx, &tp, preface, sizeof(preface) - 1);

	/*
	 * sid 1: GET / with :authority entered in the dynamic table, then
	 * 5000 bytes of user-agent and referer, not indexed, that the 4096
	 * byte ah cannot hold, then accept, entered in the dynamic table
	 * after the ah filled.  The table is then accept (62), :authority (63)
	 */
	p = blk;
	*p++ = 0x82; /* :method GET */
	*p++ = 0x86; /* :scheme http */
	*p++ = 0x84; /* :path / */
	p = hp_int(p, 0x40, 6, 1); /* :authority, incremental */
	p = hp_str(p, "sansio-h2", 9, 0);
	p = hp_int(p, 0x00, 4, 58); /* user-agent, not indexed */
	p = hp_str(p, NULL, 3000, 'u');
	p = hp_int(p, 0x00, 4, 51); /* referer, not indexed */
	p = hp_str(p, NULL, 2000, 'r');
	p = hp_int(p, 0x40, 6, 19); /* accept, incremental */
	p = hp_str(p, "x", 1, 0);
	n = h2_headers(fr, 1, blk, p);
	feed(cx, &tp, fr, n);
	if (!find_bytes(tp.tx, tp.tx_len, "Oversized headers")) {
		lwsl_err("case 15: oversized block not answered\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}

	/* sid 3: GET / referring to accept, which could not be kept */
	p = blk;
	*p++ = 0x82;
	*p++ = 0x86;
	*p++ = 0x84;
	*p++ = 0x80 | 63; /* :authority */
	*p++ = 0x80 | 62; /* accept */
	n = h2_headers(fr, 3, blk, p);
	feed(cx, &tp, fr, n);
	if (!find_bytes(tp.tx, tp.tx_len, "Oversized headers")) {
		lwsl_err("case 15: lost entry not refused\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}

	/* sid 5: GET / with only :authority from the table, served */
	p = blk;
	*p++ = 0x82;
	*p++ = 0x86;
	*p++ = 0x84;
	*p++ = 0x80 | 63; /* :authority */
	n = h2_headers(fr, 5, blk, p);
	feed(cx, &tp, fr, n);
	if (tp.closed || tp.shutdown ||
	    find_bytes(tp.tx, tp.tx_len, "Oversized headers") ||
	    !find_bytes(tp.tx, tp.tx_len, "/\n")) {
		lwsl_err("case 15: connection did not go on\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 15: h2 oversized headers answered 431: PASS\n");

	return tr_end();
}

/*
 * 22: ws over h2 (RFC 8441), the peer's CLOSE and then a PING in one DATA
 * frame: the close is answered, with the peer's own status and END_STREAM,
 * and nothing after it is acted on, the PING getting no pong (RFC 6455
 * 5.5.2).  The stream was processed, so it is not reset as REFUSED_STREAM,
 * as a refused upgrade is: at most NO_ERROR, to stop the peer sending.
 *
 * With skint, the peer gives streams no window to start with, and ends its
 * side of the stream with its CLOSE, so the answer waits for its
 * WINDOW_UPDATE: nothing of it, and no reset, goes before, and then the
 * same as without.
 */
static int
h2_ws_peer_close_half(struct lws_context *cx, struct lws_vhost *vh,
		      int skint)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00",
			  preface_skint[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		/* SETTINGS: INITIAL_WINDOW_SIZE 0 */
		"\x00\x00\x06\x04\x00\x00\x00\x00\x00"
		"\x00\x04\x00\x00\x00\x00"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	/* WINDOW_UPDATE, sid 1: 100 */
	static const char wu[] = "\x00\x00\x04\x08\x00\x00\x00\x00\x01"
				 "\x00\x00\x00\x64";
	/* DATA, sid 1: masked, zero key, CLOSE 1000 then PING "p" */
	static const char data[] = "\x00\x00\x0f\x00\x00\x00\x00\x00\x01"
				   "\x88\x82\x00\x00\x00\x00\x03\xe8"
				   "\x89\x81\x00\x00\x00\x00p",
	/* the same, with END_STREAM: the peer is done with the stream too */
			  data_es[] = "\x00\x00\x0f\x00\x01\x00\x00\x00\x01"
				   "\x88\x82\x00\x00\x00\x00\x03\xe8"
				   "\x89\x81\x00\x00\x00\x00p";
	static uint8_t blk[256], fr[300];
	static struct transport tp;
	int sv[2], closed = 0, pong = 0, rst = 0;
	struct lws *wsi;
	uint8_t *p;
	size_t n, o, f;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	tr_begin(skint ? "h2-ws-peer-close-skint" : "h2-ws-peer-close",
		 "server", 0);

	if (skint)
		feed(cx, &tp, preface_skint, sizeof(preface_skint) - 1);
	else
		feed(cx, &tp, preface, sizeof(preface) - 1);

	/* the extended CONNECT for a ws stream to echo */
	p = blk;
	p = hp_int(p, 0x00, 4, 2); /* :method, not indexed */
	p = hp_str(p, "CONNECT", 7, 0);
	*p++ = 0x00; /* :protocol, a new name, not indexed */
	p = hp_str(p, ":protocol", 9, 0);
	p = hp_str(p, "websocket", 9, 0);
	*p++ = 0x86; /* :scheme http */
	p = hp_int(p, 0x00, 4, 4); /* :path, not indexed */
	p = hp_str(p, "/echo", 5, 0);
	p = hp_int(p, 0x00, 4, 1); /* :authority, not indexed */
	p = hp_str(p, "sansio-h2ws", 11, 0);
	*p++ = 0x00;
	p = hp_str(p, "sec-websocket-version", 21, 0);
	p = hp_str(p, "13", 2, 0);
	*p++ = 0x00;
	p = hp_str(p, "sec-websocket-protocol", 22, 0);
	p = hp_str(p, "echo", 4, 0);
	n = h2_headers(fr, 1, blk, p);
	fr[4] = 0x04; /* END_HEADERS alone: the stream carries the ws */
	feed(cx, &tp, fr, n);

	if (skint)
		feed(cx, &tp, data_es, sizeof(data_es) - 1);
	else
		feed(cx, &tp, data, sizeof(data) - 1);

	if (skint) {
		/* nothing on sid 1 can go yet, and it is not given up */
		for (o = 0; o + 9 <= tp.tx_len; o += 9 + f) {
			f = ((size_t)tp.tx[o] << 16) |
			    ((size_t)tp.tx[o + 1] << 8) | tp.tx[o + 2];
			if ((lws_ser_ru32be(&tp.tx[o + 5]) & 0x7fffffff) == 1 &&
			    (!tp.tx[o + 3] || tp.tx[o + 3] == 3)) {
				lwsl_err("case 22: skint: frame type %d on "
					 "sid 1 before the window\n",
					 tp.tx[o + 3]);
				lwsl_hexdump_err(tp.tx, tp.tx_len);
				return 1;
			}
		}
		feed(cx, &tp, wu, sizeof(wu) - 1);
	}

	/* sid 1's DATA: the answer to the close, ending it, and no pong */
	for (o = 0; o + 9 <= tp.tx_len; o += 9 + f) {
		f = ((size_t)tp.tx[o] << 16) | ((size_t)tp.tx[o + 1] << 8) |
		    tp.tx[o + 2];
		if (o + 9 + f > tp.tx_len)
			break;
		if ((lws_ser_ru32be(&tp.tx[o + 5]) & 0x7fffffff) != 1)
			continue;
		/* RST_STREAM: the stream was processed, only NO_ERROR */
		if (tp.tx[o + 3] == 3 && f == 4 &&
		    lws_ser_ru32be(&tp.tx[o + 9]))
			rst = (int)lws_ser_ru32be(&tp.tx[o + 9]);
		if (tp.tx[o + 3])
			continue;
		if (f >= 4 && !memcmp(&tp.tx[o + 9], "\x88\x02\x03\xe8", 4) &&
		    (tp.tx[o + 4] & 1))
			closed = 1;
		if (f && tp.tx[o + 9] == 0x8a)
			pong = 1;
	}
	if (!closed || pong || rst) {
		lwsl_err("case 22: %sclose answered %d, pong %d, rst %d\n",
			 skint ? "skint: " : "", closed, pong, rst);
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 22: ws over h2 answers the close%s, then nothing: "
		  "PASS\n", skint ? " once it has the window" : "");

	return tr_end();
}

/*
 * 20: an h2 POST the app answers and completes as soon as it arrives, while
 * the transport is taking only a few bytes: the completion waits for the
 * queued response.  The request's body arriving meanwhile is discarded, not
 * a reason to reset the stream, and once the transport has taken the rest
 * the stream completes and ends, without the app being given a writeable
 * for a transaction it had completed.  What the transport takes and when
 * is not part of a transcript, so this case has none.
 *
 * The same when the app answers the POST by serving a file: the body that
 * arrives while the file is going is discarded, and the file all goes.
 */
static int
h2_early_answer_half(struct lws_context *cx, struct lws_vhost *vh,
		     const char *path)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	/* DATA, sid 1, END_STREAM: the 3 byte body */
	static const char data[] = "\x00\x00\x03\x00\x01\x00\x00\x00\x01"
				   "abc";
	static uint8_t blk[128], fr[256], out[32768];
	static struct transport tp;
	int sv[2], ended = 0, rst = 0, m;
	size_t n, o, outl, body = 0, want = 3; /* "ok\n" */
	struct lws *wsi;
	uint8_t *p;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	if (!strcmp(path, "/file")) {
		/* the answer is all of the file */
		m = open(EARLY_FILE, O_RDONLY);
		if (m < 0) {
			lwsl_err("case 20: no %s\n", EARLY_FILE);
			return 1;
		}
		want = (size_t)lseek(m, 0, SEEK_END);
		close(m);
	}

	feed(cx, &tp, preface, sizeof(preface) - 1);

	/* POST to path, content-length 3, the body to follow */
	p = blk;
	*p++ = 0x83; /* :method POST */
	*p++ = 0x86; /* :scheme http */
	p = hp_int(p, 0x00, 4, 4); /* :path, not indexed */
	p = hp_str(p, path, strlen(path), 0);
	p = hp_int(p, 0x00, 4, 1); /* :authority, not indexed */
	p = hp_str(p, "sansio-h2", 9, 0);
	p = hp_int(p, 0x00, 4, 28); /* content-length, not indexed */
	p = hp_str(p, "3", 1, 0);
	n = h2_headers(fr, 1, blk, p);
	fr[4] = 0x04; /* END_HEADERS alone: the body follows */

	/* the app has the transport take 4 bytes of its response */
	early_tp = &tp;
	feed(cx, &tp, fr, n);
	early_tp = NULL;
	/* what went, from here, is frames whole as far as they went */
	outl = tp.tx_len;
	memcpy(out, tp.tx, outl);
	feed(cx, &tp, data, sizeof(data) - 1);
	if (tp.closed || tp.shutdown) {
		lwsl_err("case 20: %s: connection ended\n", path);
		return 1;
	}

	/* the transport takes everything again, until nothing more goes */
	tp.tx_budget = -1;
	for (m = 0; m < 16; m++) {
		tp.tx_len = 0;
		tick(cx);
		pump(cx, &tp);
		if (!tp.tx_len)
			break;
		if (outl + tp.tx_len > sizeof(out)) {
			lwsl_err("case 20: %s: too much output\n", path);
			return 1;
		}
		memcpy(out + outl, tp.tx, tp.tx_len);
		outl += tp.tx_len;
	}

	/* frames: the response ends sid 1, which is not reset */
	for (o = 0; o + 9 <= outl; o += 9 + n) {
		n = ((size_t)out[o] << 16) | ((size_t)out[o + 1] << 8) |
		    out[o + 2];
		if ((lws_ser_ru32be(&out[o + 5]) & 0x7fffffff) != 1)
			continue;
		if (out[o + 3] == 3)
			rst = 1;
		if (!out[o + 3]) {
			body += n;
			if (out[o + 4] & 1)
				ended = 1;
		}
	}
	if (rst || !ended || uri_closed != 1 || uri_late_writeable ||
	    tp.closed || tp.shutdown ||
	    body != want) {
		lwsl_err("case 20: %s: rst %d, ended %d, closed %d, late wr %d, "
			 "body %d / %d, rx %d / %d, want read %d\n", path, rst,
			 ended, uri_closed, uri_late_writeable, (int)body,
			 (int)want,
			 (int)tp.rx_pos, (int)tp.rx_len, tp.want_read);
		lwsl_hexdump_err(out, outl);
		return 1;
	}
	lwsl_user("case 20: %s: h2 answer goes whole, the body meanwhile "
		  "discarded: PASS\n", path);

	return 0;
}

/*
 * 26: the h2 POST of case 20 answered at once, the transport taking only 4
 * bytes of the answer, so the connection holds its reading behind the rest.
 * Then the peer sends its body and finishes, which OSX reports only as a
 * bare POLLHUP in place of the POLLOUT asked for.  The answer can never go
 * now, but what the peer sent before it finished is still read, before the
 * connection ends.
 */
static int
h2_fin_behind_partial_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	/* DATA, sid 1, END_STREAM: the 3 byte body */
	static const char data[] = "\x00\x00\x03\x00\x01\x00\x00\x00\x01"
				   "abc";
	static uint8_t blk[128], fr[256];
	static struct transport tp;
	struct lws *wsi;
	uint8_t *p;
	size_t n;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);

	feed(cx, &tp, preface, sizeof(preface) - 1);

	/* POST /early, content-length 3, the body to follow */
	p = blk;
	*p++ = 0x83; /* :method POST */
	*p++ = 0x86; /* :scheme http */
	p = hp_int(p, 0x00, 4, 4); /* :path, not indexed */
	p = hp_str(p, "/early", 6, 0);
	p = hp_int(p, 0x00, 4, 1); /* :authority, not indexed */
	p = hp_str(p, "sansio-h2", 9, 0);
	p = hp_int(p, 0x00, 4, 28); /* content-length, not indexed */
	p = hp_str(p, "3", 1, 0);
	n = h2_headers(fr, 1, blk, p);
	fr[4] = 0x04; /* END_HEADERS alone: the body follows */

	/* the app has the transport take 4 bytes of its answer */
	early_tp = &tp;
	feed(cx, &tp, fr, n);
	early_tp = NULL;
	if (!tp.want_write) {
		lwsl_err("case 26: nothing of the answer waiting to go\n");
		return 1;
	}

	/* the body, and the peer is done */
	tp.fin = 1;
	feed(cx, &tp, data, sizeof(data) - 1);
	if (!tp.closed || tp.rx_pos != tp.rx_len) {
		lwsl_err("case 26: closed %d, read %d / %d\n", tp.closed,
			 (int)tp.rx_pos, (int)tp.rx_len);
		return 1;
	}
	lwsl_user("case 26: what came before a bare POLLHUP is read before "
		  "the connection ends: PASS\n");

	return 0;
}

#endif /* LWS_WITH_HTTP2 */

#if defined(LWS_WITH_FILE_OPS)
/*
 * 27: an h1 GET answered with a file, the transport taking only 4 bytes of
 * it, and a byte pipelined behind the request, parked while the file is
 * served.  Then the peer resets the connection.  The file can never go now,
 * and the parked byte waits on it: the connection goes at once, rather than
 * waiting on the next poll's report of the reset, and the next, and so on.
 */
static int
h1_reset_behind_file_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char req[] =
		"GET /file HTTP/1.1\r\nHost: sansio-uri\r\n\r\nX";
	static struct transport tp;
	struct lws *wsi;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);

	/* the app has the transport take 4 bytes of the file's answer */
	early_tp = &tp;
	feed(cx, &tp, req, sizeof(req) - 1);
	early_tp = NULL;
	if (tp.closed || !tp.want_write) {
		lwsl_err("case 27: closed %d, nothing waiting to go\n",
			 tp.closed);
		return 1;
	}

	tp.reset = 1;
	tick(cx);
	pump(cx, &tp);
	if (!tp.closed) {
		lwsl_err("case 27: the reset connection lives on\n");
		return 1;
	}
	lwsl_user("case 27: a reset behind a file being served ends the "
		  "connection: PASS\n");

	return 0;
}

/*
 * 40: an h1 GET answered with a file on a connection the peer asked to
 * close, a byte pipelined behind the request and parked while the file is
 * served; the transport takes 4 bytes of the answer, then the rest.  The
 * transaction completing closes the connection: the close is staged, our
 * FIN sent, waiting for the peer's.  The protocol is gone, so the parked
 * byte is for nobody: the loop must wait for the peer's FIN, not go round
 * offering the parked byte to a connection that cannot take it (the
 * staged close's whole timeout_secs at 100% cpu).  Then the peer's FIN
 * ends it.
 */
static int
h1_shutdown_behind_parked_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char req[] =
		"GET /file HTTP/1.1\r\nHost: sansio-uri\r\n"
		"Connection: close\r\n\r\nX";
	static struct transport tp;
	struct lws *wsi;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);

	/* the transport takes 4 bytes of the file's answer for now */
	early_tp = &tp;
	feed(cx, &tp, req, sizeof(req) - 1);
	early_tp = NULL;
	if (tp.closed || tp.shutdown || !tp.want_write) {
		lwsl_err("case 40: closed %d, shutdown %d, nothing waiting "
			 "to go\n", tp.closed, tp.shutdown);
		return 1;
	}

	/* ...then the rest: the answer completes and the close is staged */
	tp.tx_budget = -1;
	tick(cx);
	pump(cx, &tp);
	if (tp.closed || !tp.shutdown || !tp.want_read ||
	    !find_bytes(tp.tx, tp.tx_len, "\r\n\r\n")) {
		lwsl_err("case 40: closed %d, shutdown %d, reading %d, "
			 "tx %d\n", tp.closed, tp.shutdown, tp.want_read,
			 (int)tp.tx_len);
		return 1;
	}

	/*
	 * Only the peer's FIN is awaited now: a loop that would not wait in
	 * poll is spinning on the parked byte
	 */
	if (!lws_service_adjust_timeout(cx, 1000, 0)) {
		lwsl_err("case 40: the loop would not wait for the FIN\n");
		return 1;
	}

	tp.fin = 1;
	tick(cx);
	pump(cx, &tp);
	if (!tp.closed) {
		lwsl_err("case 40: the peer's FIN did not end it\n");
		return 1;
	}
	lwsl_user("case 40: a close staged behind a parked request waits for "
		  "the FIN: PASS\n");

	return 0;
}
#endif

/*
 * 28: a ws message the app holds with rx flow control, the one after it
 * parked unread behind it.  Then the peer resets the connection.  What it
 * sent before may still be wanted, if the app lets its rx go again soon,
 * but the reset is reported on every poll until the connection is closed:
 * the grace is counted from the first poll that saw it, and the connection
 * goes when that is up however often the reset was seen meanwhile.
 *
 * 29: the same connection asks for nothing now, neither to read nor to
 * write, and the peer's close is reported to it as a bare POLLHUP, the way
 * BSD and OSX do (OSX for a FIN too), with no POLLERR: it is taken as the
 * hangup it is, the connection going at once when nothing is parked, and
 * when the grace is up when something is.
 */
static int
ws_hangup_behind_flowcontrol_half(struct lws_context *cx, int ms)
{
	static const char req_ws[] =
		"GET /echo HTTP/1.1\r\nHost: sansio\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Protocol: echo\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
	/* masked, zero key: TEXT "Hold", then TEXT "Hello" */
	static const char hold_hello[] = "\x81\x84\x00\x00\x00\x00Hold"
					 "\x81\x85\x00\x00\x00\x00Hello";
	static const struct {
		int		cn;
		const char	*name;
		size_t		len;	/* of hold_hello: "Hold" alone, or both */
		int		bare;	/* a bare POLLHUP, else a Linux reset */
		int		grace;	/* rx parked: it goes when that is up */
	} c[] = {
		{ 28, "reset, rx parked", sizeof(hold_hello) - 1, 0, 1 },
		{ 28, "reset, nothing parked", 10, 0, 0 },
		{ 29, "bare POLLHUP, rx parked", sizeof(hold_hello) - 1, 1, 1 },
		{ 29, "bare POLLHUP, nothing parked", 10, 1, 0 },
	};
	static struct transport tp;
	struct lws *wsi;
	size_t n;
	int sv[2], s, t;

	for (n = 0; n < LWS_ARRAY_SIZE(c); n++) {
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

		if (feed(cx, &tp, req_ws, sizeof(req_ws) - 1) ||
		    tp.tx_len < 13 || memcmp(tp.tx, "HTTP/1.1 101 ", 13)) {
			lwsl_err("case %d: %s: no upgrade\n", c[n].cn,
				 c[n].name);
			return 1;
		}
		feed(cx, &tp, hold_hello, c[n].len);
		if (tp.want_read || tp.want_write || tp.tx_len) {
			lwsl_err("case %d: %s: rx not held, or tx: read %d, "
				 "write %d, tx %d\n", c[n].cn, c[n].name,
				 tp.want_read, tp.want_write, (int)tp.tx_len);
			return 1;
		}

		/* the hangup is seen at t, and every 900ms after it */
		t = ms + (int)n * 10000;
		at(cx, t);
		if (c[n].bare)
			tp.fin = 1;
		else
			tp.reset = 1;
		for (s = 0; s <= 4; s++) {
			at(cx, t + (s * 900));
			pump(cx, &tp);
			if (tp.closed != (!c[n].grace || s * 900 >= 3000)) {
				lwsl_err("case %d: %s: closed %d at %dms\n",
					 c[n].cn, c[n].name, tp.closed, s * 900);
				return 1;
			}
		}
	}
	lwsl_user("case 28: a reset behind rx flow control ends the "
		  "connection when its grace is up: PASS\n");
	lwsl_user("case 29: a bare POLLHUP to a connection asking for nothing "
		  "ends it: PASS\n");

	return 0;
}

#if defined(LWS_WITH_HTTP2)
#if defined(LWS_WITH_FILE_OPS)
/*
 * 24: an h2 POST the app answers with a file, where the peer gave the
 * stream a window of only 100 bytes and never opens it further, while it
 * sends the request's body and keeps the connection alive with PINGs.  The
 * body, discarded as it comes, completing does not take the file's timeout
 * (the file sender renews it as it sends) with it: that closes the stream
 * once it expires, and the connection goes on.  It moves the time on past
 * it, so it goes last, and it has no transcript.
 */
static int
h2_file_stalled_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		/* SETTINGS: INITIAL_WINDOW_SIZE 100, then the server's ack */
		"\x00\x00\x06\x04\x00\x00\x00\x00\x00"
		"\x00\x04\x00\x00\x00\x64"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	/* DATA, sid 1, END_STREAM: the 3 byte body */
	static const char data[] = "\x00\x00\x03\x00\x01\x00\x00\x00\x01"
				   "abc";
	static const char ping[] = "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
				   "12345678";
	static uint8_t blk[128], fr[256];
	static struct transport tp;
	struct lws *wsi;
	uint8_t *p;
	int sv[2], s;
	size_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	feed(cx, &tp, preface, sizeof(preface) - 1);

	/* POST /file, content-length 3, the body to follow */
	p = blk;
	*p++ = 0x83; /* :method POST */
	*p++ = 0x86; /* :scheme http */
	p = hp_int(p, 0x00, 4, 4); /* :path, not indexed */
	p = hp_str(p, "/file", 5, 0);
	p = hp_int(p, 0x00, 4, 1); /* :authority, not indexed */
	p = hp_str(p, "sansio-h2", 9, 0);
	p = hp_int(p, 0x00, 4, 28); /* content-length, not indexed */
	p = hp_str(p, "3", 1, 0);
	n = h2_headers(fr, 1, blk, p);
	fr[4] = 0x04; /* END_HEADERS alone: the body follows */
	feed(cx, &tp, fr, n);

	/* the first 100 bytes of the file went; the body comes */
	feed(cx, &tp, data, sizeof(data) - 1);

	/* a PING every 4s keeps the connection from being idle */
	for (s = 4; s <= 32; s += 4) {
		at(cx, 4200 + s * 1000);
		feed(cx, &tp, ping, sizeof(ping) - 1);
		if (tp.closed || tp.shutdown) {
			lwsl_err("case 24: connection ended at %ds\n", s);
			return 1;
		}
	}

	if (uri_closed != 1) {
		lwsl_err("case 24: the stalled stream was not closed\n");
		return 1;
	}
	lwsl_user("case 24: a file stalled on its window, the body complete, "
		  "is closed by its timeout: PASS\n");

	return 0;
}

/*
 * What one exchange's tx, whole h2 frames, did on sid 1: the DATA it sent,
 * whether it ended the stream, and whether it reset it
 */
static void
h2_sid1_tally(const struct transport *tp, size_t *body, int *ended, int *rst)
{
	size_t o, f;

	for (o = 0; o + 9 <= tp->tx_len; o += 9 + f) {
		f = ((size_t)tp->tx[o] << 16) | ((size_t)tp->tx[o + 1] << 8) |
		    tp->tx[o + 2];
		if ((lws_ser_ru32be(&tp->tx[o + 5]) & 0x7fffffff) != 1)
			continue;
		if (tp->tx[o + 3] == 3)
			*rst = 1;
		if (!tp->tx[o + 3]) {
			*body += f;
			if (tp->tx[o + 4] & 1)
				*ended = 1;
		}
	}
}

/*
 * 25: an h2 GET the app answers a piece at a time, 100 bytes every 8s, while
 * PINGs keep the connection from being idle: it takes longer than the
 * response's watchdog, but is never stalled for that long, since each piece
 * that goes renews it.  The whole answer goes, ending the stream.  It moves
 * the time on too, so it goes last, and it has no transcript.
 */
static int
h2_slow_answer_half(struct lws_context *cx, struct lws_vhost *vh, int start_ms)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	static const char ping[] = "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
				   "12345678";
	static uint8_t blk[128], fr[256];
	static struct transport tp;
	int sv[2], s, ended = 0, rst = 0;
	size_t n, body = 0;
	struct lws *wsi;
	uint8_t *p;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	feed(cx, &tp, preface, sizeof(preface) - 1);

	/* GET /slow */
	p = blk;
	*p++ = 0x82; /* :method GET */
	*p++ = 0x86; /* :scheme http */
	p = hp_int(p, 0x00, 4, 4); /* :path, not indexed */
	p = hp_str(p, "/slow", 5, 0);
	p = hp_int(p, 0x00, 4, 1); /* :authority, not indexed */
	p = hp_str(p, "sansio-h2", 9, 0);
	n = h2_headers(fr, 1, blk, p);
	feed(cx, &tp, fr, n);
	h2_sid1_tally(&tp, &body, &ended, &rst);

	/* a PING every 4s, until the answer is done or it is much too late */
	for (s = 4; !uri_closed && s <= 8 * (SLOW_PIECES + 2); s += 4) {
		at(cx, start_ms + s * 1000);
		feed(cx, &tp, ping, sizeof(ping) - 1);
		h2_sid1_tally(&tp, &body, &ended, &rst);
		if (tp.closed || tp.shutdown) {
			lwsl_err("case 25: connection ended at %ds\n", s);
			return 1;
		}
	}

	/* sid 1: the whole answer in DATA, ending the stream, and no reset */
	if (rst || !ended || body != SLOW_PIECES * 100 || uri_closed != 1) {
		lwsl_err("case 25: rst %d, ended %d, body %d, closed %d\n",
			 rst, ended, (int)body, uri_closed);
		return 1;
	}
	lwsl_user("case 25: an answer slower than the response watchdog, but "
		  "never stalled, all goes: PASS\n");

	return 0;
}

/*
 * 33: an h2 POST the app starts answering from the first piece of its body,
 * where the peer gave the stream a window of only 100 bytes and never opens
 * it further, then sends the rest of the body, which completes, and keeps
 * the connection alive with PINGs.  The body's own timeout, renewed by each
 * piece and cleared once it is all here, must not take the response's
 * watchdog with it: the answer, stalled on the window after its first 100
 * bytes, is closed by the watchdog.  It moves the time on past it, so it
 * goes last, and it has no transcript.
 */
static int
h2_answer_in_body_half(struct lws_context *cx, struct lws_vhost *vh,
		       int start_ms)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		/* SETTINGS: INITIAL_WINDOW_SIZE 100, then the server's ack */
		"\x00\x00\x06\x04\x00\x00\x00\x00\x00"
		"\x00\x04\x00\x00\x00\x64"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	/* DATA, sid 1: the body's first 3 bytes; then its last 3, END_STREAM */
	static const char data1[] = "\x00\x00\x03\x00\x00\x00\x00\x00\x01"
				    "abc";
	static const char data2[] = "\x00\x00\x03\x00\x01\x00\x00\x00\x01"
				    "def";
	static const char ping[] = "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
				   "12345678";
	static uint8_t blk[128], fr[256];
	static struct transport tp;
	int sv[2], s, ended = 0, rst = 0;
	size_t n, f, body = 0;
	struct lws *wsi;
	uint8_t *p;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	feed(cx, &tp, preface, sizeof(preface) - 1);

	/* POST /in-body, content-length 6, the body to follow */
	p = blk;
	*p++ = 0x83; /* :method POST */
	*p++ = 0x86; /* :scheme http */
	p = hp_int(p, 0x00, 4, 4); /* :path, not indexed */
	p = hp_str(p, "/in-body", 8, 0);
	p = hp_int(p, 0x00, 4, 1); /* :authority, not indexed */
	p = hp_str(p, "sansio-h2", 9, 0);
	p = hp_int(p, 0x00, 4, 28); /* content-length, not indexed */
	p = hp_str(p, "6", 1, 0);
	n = h2_headers(fr, 1, blk, p);
	fr[4] = 0x04; /* END_HEADERS alone: the body follows */
	feed(cx, &tp, fr, n);

	/* the body's first piece: the answer's HEADERS go, from the callback */
	feed(cx, &tp, data1, sizeof(data1) - 1);
	for (n = 0; n + 9 <= tp.tx_len; n += 9 + f) {
		f = ((size_t)tp.tx[n] << 16) | ((size_t)tp.tx[n + 1] << 8) |
		    tp.tx[n + 2];
		if (tp.tx[n + 3] == 1 &&
		    (lws_ser_ru32be(&tp.tx[n + 5]) & 0x7fffffff) == 1)
			break;
	}
	if (n + 9 > tp.tx_len) {
		lwsl_err("case 33: the answer did not start with the body\n");
		return 1;
	}

	/*
	 * the rest of the body: it completes, and the answer's first 100
	 * bytes go, all the window takes
	 */
	feed(cx, &tp, data2, sizeof(data2) - 1);
	h2_sid1_tally(&tp, &body, &ended, &rst);
	if (body != 100 || ended || rst) {
		lwsl_err("case 33: %d of the answer went, ended %d, rst %d\n",
			 (int)body, ended, rst);
		return 1;
	}

	/* a PING every 4s keeps the connection from being idle */
	for (s = 4; s <= 36; s += 4) {
		at(cx, start_ms + s * 1000);
		feed(cx, &tp, ping, sizeof(ping) - 1);
		h2_sid1_tally(&tp, &body, &ended, &rst);
		if (tp.closed || tp.shutdown) {
			lwsl_err("case 33: connection ended at %ds\n", s);
			return 1;
		}
		/* the watchdog is 30s from the last piece that went */
		if (s <= 28 && uri_closed) {
			lwsl_err("case 33: the stream was closed at %ds\n", s);
			return 1;
		}
	}

	if (uri_closed != 1 || body != 100 || uri_late_writeable) {
		lwsl_err("case 33: closed %d, body %d, late wr %d\n",
			 uri_closed, (int)body, uri_late_writeable);
		return 1;
	}
	lwsl_user("case 33: an answer started during the body, then stalled, "
		  "is closed by the response's watchdog: PASS\n");

	return 0;
}
#endif
#endif

/*
 * 35: the app answering an h1 POST with a file, the body still to come,
 * abandons the file from its timer by completing the transaction, while a
 * read of the file is out on a worker.  The completion reaps the read, but
 * the answer is short of the Content-Length its head gave: kept alive, the
 * peer would read whatever came next as the rest of it, so the connection
 * is closed.  The worker's timing is not part of a transcript, so this case
 * has none.
 *
 * 38: the same on an h2 stream, where the stream's end ends the answer,
 * whatever it was: the connection lives on, the body arriving is
 * discarded, and the stream ends.
 */
#if defined(LWS_WITH_FILE_OPS) && defined(LWS_WITH_ASYNC_QUEUE)
static int
h1_file_abandoned_half(struct lws_context *cx, struct lws_vhost *vh,
		       int start_ms)
{
	static const char req[] =
		"POST /abandon HTTP/1.1\r\nHost: sansio-uri\r\n"
		"Content-Length: 6\r\n\r\n";
	static struct transport tp;
	struct lws *wsi;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	/* the file's headers go, and its first read is handed to a worker */
	workers_held = 1;
	feed(cx, &tp, req, sizeof(req) - 1);
	if (!find_bytes(tp.tx, tp.tx_len, "HTTP/1.1 200 ") ||
	    !lws_service_work_outstanding(cx)) {
		lwsl_err("case 35: no file answer with a read out\n");
		workers_held = 0;
		return 1;
	}

	/* the app's timer: it completes the transaction from under the read */
	at(cx, start_ms + 10);
	workers_held = 0;
	if (!(tp.closed || tp.shutdown) || lws_service_work_outstanding(cx) ||
	    uri_late_writeable) {
		lwsl_err("case 35: ended %d, the read still out %d, late wr %d\n",
			 tp.closed || tp.shutdown,
			 lws_service_work_outstanding(cx), uri_late_writeable);
		return 1;
	}
	lwsl_user("case 35: an h1 file abandoned with a read out ends the "
		  "connection: PASS\n");

	return 0;
}

#if defined(LWS_WITH_HTTP2)
static int
h2_file_abandoned_half(struct lws_context *cx, struct lws_vhost *vh,
		       int start_ms)
{
	static const char preface[] =
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	/* DATA, sid 1, END_STREAM: the 3 byte body */
	static const char data[] = "\x00\x00\x03\x00\x01\x00\x00\x00\x01"
				   "abc";
	static const char ping[] = "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
				   "12345678";
	static uint8_t blk[128], fr[256];
	static struct transport tp;
	struct lws *wsi;
	int sv[2];
	uint8_t *p;
	size_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	feed(cx, &tp, preface, sizeof(preface) - 1);

	/* POST /abandon, content-length 3, the body to follow */
	p = blk;
	*p++ = 0x83; /* :method POST */
	*p++ = 0x86; /* :scheme http */
	p = hp_int(p, 0x00, 4, 4); /* :path, not indexed */
	p = hp_str(p, "/abandon", 8, 0);
	p = hp_int(p, 0x00, 4, 1); /* :authority, not indexed */
	p = hp_str(p, "sansio-h2", 9, 0);
	p = hp_int(p, 0x00, 4, 28); /* content-length, not indexed */
	p = hp_str(p, "3", 1, 0);
	n = h2_headers(fr, 1, blk, p);
	fr[4] = 0x04; /* END_HEADERS alone: the body follows */

	/* the file's HEADERS go, and its first read is handed to a worker */
	workers_held = 1;
	feed(cx, &tp, fr, n);
	if (!lws_service_work_outstanding(cx)) {
		lwsl_err("case 38: no read out\n");
		workers_held = 0;
		return 1;
	}

	/* the app's timer: it completes the transaction from under the read */
	at(cx, start_ms + 10);
	workers_held = 0;
	if (tp.closed || tp.shutdown || lws_service_work_outstanding(cx)) {
		lwsl_err("case 38: ended %d, the read still out %d\n",
			 tp.closed || tp.shutdown,
			 lws_service_work_outstanding(cx));
		return 1;
	}

	/* the body, discarded; then the connection still answers a PING */
	feed(cx, &tp, data, sizeof(data) - 1);
	feed(cx, &tp, ping, sizeof(ping) - 1);
	if (tp.closed || tp.shutdown || uri_closed != 1 ||
	    uri_late_writeable || tp.tx_len < 17 || tp.tx[3] != 6 ||
	    !(tp.tx[4] & 1)) {
		lwsl_err("case 38: ended %d, stream closed %d, late wr %d\n",
			 tp.closed || tp.shutdown, uri_closed,
			 uri_late_writeable);
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 38: an h2 file abandoned with a read out ends its "
		  "stream, the body discarded: PASS\n");

	return 0;
}
#endif
#endif

/*
 * 37: an h1 POST the app answers whole and completes before any of its body
 * has come, the body then coming a byte every 10s, slower than the response
 * watchdog would allow an answer to stall for, but each byte inside the
 * body's own timeout.  The answer has all gone: what bounds the connection
 * while the body is discarded is the body's timeout, renewed by each byte,
 * and once it is all here the request after it is served.  It moves the
 * time on, so it goes late, and it has no transcript.
 */
static int
h1_discard_slow_body_half(struct lws_context *cx, struct lws_vhost *vh,
			  int start_ms)
{
	static const char req[] =
		"POST /early HTTP/1.1\r\nHost: sansio-uri\r\n"
		"Content-Length: 5\r\n\r\n";
	static const char body[] = "abcd", last[] =
		"e"
		"GET /after?d=4 HTTP/1.1\r\nHost: sansio-uri\r\n\r\n";
	static struct transport tp;
	struct lws *wsi;
	int sv[2], s;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	/* answered whole and completed, with the body still to come */
	feed(cx, &tp, req, sizeof(req) - 1);
	if (!find_bytes(tp.tx, tp.tx_len, "ok\n")) {
		lwsl_err("case 37: no answer\n");
		return 1;
	}

	/* the body, a byte every 10s */
	for (s = 10; s <= 40; s += 10) {
		at(cx, start_ms + s * 1000);
		if (feed(cx, &tp, &body[s / 10 - 1], 1) || tp.closed) {
			lwsl_err("case 37: closed %d at %ds\n", tp.closed, s);
			return 1;
		}
	}

	/* its last byte, then the next request, answered */
	at(cx, start_ms + 50000);
	if (feed(cx, &tp, last, sizeof(last) - 1) ||
	    !find_bytes(tp.tx, tp.tx_len, "/after\nd=4") || tp.closed ||
	    uri_late_writeable) {
		lwsl_err("case 37: rest not taken, or next request not "
			 "served: closed %d, late wr %d\n", tp.closed,
			 uri_late_writeable);
		return 1;
	}
	lwsl_user("case 37: a body discarded after its answer went has its "
		  "own timeout: PASS\n");

	return 0;
}

/*
 * 36: case 33 on an h1 connection.  The app starts its answer from the first
 * piece of the POST's body, the rest of the body completes, and the answer
 * goes on from the writeable, until the transport stops taking it.  The
 * body's own timeout, renewed by each piece and cleared once it is all here,
 * must not take the response's watchdog with it: the answer, stalled, is
 * closed by the watchdog.  It moves the time on past it, so it goes late, and
 * it has no transcript.
 */
static int
h1_answer_in_body_half(struct lws_context *cx, struct lws_vhost *vh,
		       int start_ms)
{
	static const char req[] =
		"POST /in-body HTTP/1.1\r\nHost: sansio-uri\r\n"
		"Content-Length: 6\r\n\r\nabc";
	static struct transport tp;
	struct lws *wsi;
	int sv[2], s;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	uri_late_writeable = uri_closed = 0;

	/* the head and the body's first piece: the answer's headers go */
	feed(cx, &tp, req, sizeof(req) - 1);
	if (!find_bytes(tp.tx, tp.tx_len, "HTTP/1.1 200 ")) {
		lwsl_err("case 36: the answer did not start with the body\n");
		return 1;
	}

	/*
	 * the rest of the body: it completes, and the answer goes on, the
	 * transport taking 150 bytes of it, then no more
	 */
	tp.tx_budget = 150;
	feed(cx, &tp, "def", 3);
	if (tp.tx_len != 150 || tp.closed || tp.shutdown) {
		lwsl_err("case 36: %d of the answer went, closed %d\n",
			 (int)tp.tx_len, tp.closed);
		return 1;
	}

	for (s = 4; s <= 36; s += 4) {
		at(cx, start_ms + s * 1000);
		/* the watchdog is 30s from the last piece that went */
		if (s <= 28 && (uri_closed || tp.closed)) {
			lwsl_err("case 36: closed at %ds\n", s);
			return 1;
		}
	}

	if (uri_closed != 1 || !tp.closed || uri_late_writeable) {
		lwsl_err("case 36: closed %d / %d, late wr %d\n",
			 uri_closed, tp.closed, uri_late_writeable);
		return 1;
	}
	lwsl_user("case 36: an h1 answer started during the body, then "
		  "stalled, is closed by the response's watchdog: PASS\n");

	return 0;
}

static int timer_fired;

static void
timer_cb(lws_sorted_usec_list_t *sul)
{
	timer_fired++;
}

/*
 * 8: timers run by the time the test gives.  Scheduled while the time is
 * T0 + 1s for 250ms, one is not due at T0 + 1.249s, which says 1ms is left,
 * and fires once at T0 + 1.25s.  Time does not go back: a time before the
 * last is taken as the last.
 */
static int
time_half(struct lws_context *cx)
{
	lws_sorted_usec_list_t sul;
	lws_usec_t left;

	memset(&sul, 0, sizeof(sul));
	lws_service_set_now(cx, 0, T0_US + LWS_US_PER_SEC, T0_WALL + 1);
	lws_sul_schedule(cx, 0, &sul, timer_cb, 250 * LWS_US_PER_MS);

	left = lws_service_set_now(cx, 0, T0_US + 1249 * LWS_US_PER_MS,
				   T0_WALL + 1);
	if (timer_fired || left <= 0 || left > LWS_US_PER_MS) {
		lwsl_err("case 8: early: fired %d, %lld us left\n", timer_fired,
			 (long long)left);
		lws_sul_cancel(&sul);
		return 1;
	}

	/* going back is ignored, so the timer is still 1ms away, not later */
	left = lws_service_set_now(cx, 0, T0_US, T0_WALL);
	if (timer_fired || left <= 0 || left > LWS_US_PER_MS) {
		lwsl_err("case 8: time went back: %lld us left\n",
			 (long long)left);
		lws_sul_cancel(&sul);
		return 1;
	}

	lws_service_set_now(cx, 0, T0_US + 1250 * LWS_US_PER_MS, T0_WALL + 1);
	lws_service_set_now(cx, 0, T0_US + 2 * LWS_US_PER_SEC, T0_WALL + 2);
	if (timer_fired != 1) {
		lwsl_err("case 8: fired %d times\n", timer_fired);
		lws_sul_cancel(&sul);
		return 1;
	}
	lwsl_user("case 8: timers run by the test's clock: PASS\n");

	return 0;
}

/*
 * 7: lws_send_pipe_choked() on a connection over the test transport.  Its
 * fd is only its place in the poll set, so an fd that could not take a
 * write must not make the connection choked: the transport takes the bytes.
 */
static int
choked_half(struct lws_context *cx)
{
	static const uint8_t fill[4096];
	struct lws *wsi;
	int sv[2], e = 1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}

	/* nobody reads sv[1]: sv[0] takes writes until its buffer is full */
	if (fcntl(sv[0], F_SETFL, O_NONBLOCK) < 0) {
		lwsl_err("case 7: nonblocking failed\n");
		close(sv[0]);
		goto bail;
	}
	while (write(sv[0], fill, sizeof(fill)) > 0)
		;

	wsi = lws_adopt_socket(cx, sv[0]);
	if (!wsi) {
		lwsl_err("case 7: adopt failed\n");
		goto bail;
	}

	/* on its socket, the full fd is the connection's: it is choked */
	if (!lws_send_pipe_choked(wsi)) {
		lwsl_err("case 7: full socket not choked\n");
		goto bail;
	}

	lws_set_transport(wsi, &tops, NULL);
	if (lws_send_pipe_choked(wsi)) {
		lwsl_err("case 7: transport choked by its poll fd\n");
		goto bail;
	}
	lwsl_user("case 7: a transport is not choked by its poll fd: PASS\n");
	e = 0;

bail:
	close(sv[1]);

	return e;
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

	tick(cx);

	return lws_client_connect_via_info(&ci);
}

/*
 * A ws client connection over tp, its upgrade request checked and answered
 * with pre (interim responses ahead of the 101, or ""), then the 101 with the
 * accept value of the key it chose, and resp_hdrs.  Unless quiet, the client
 * sends "Hello" once it is established.  Returns nonzero unless it is
 * established (and, unless quiet, sent it).
 */
static int
ws_client_up_pre(struct lws_context *cx, struct lws_vhost *vh,
		 struct transport *tp, const char *pre, const char *resp_hdrs,
		 int quiet)
{
	static const char resp_ws[] =
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Protocol: echo\r\n"
		"Sec-WebSocket-Accept: ";
	char key[24 + 36 + 1], accept[32], resp[384];
	uint8_t sha[20];
	const uint8_t *k;
	int n;

	if (!client_connect(cx, vh, tp, "/echo", NULL, "echo")) {
		lwsl_err("ws connect failed\n");
		return 1;
	}
	cli.quiet = quiet;
	pump(cx, tp);
	k = find_bytes(tp->tx, tp->tx_len, "\r\nSec-WebSocket-Key: ");
	if (tp->tx_len < 20 || memcmp(tp->tx, "GET /echo HTTP/1.1\r\n", 20) ||
	    !find_bytes(tp->tx, tp->tx_len, "\r\nUpgrade: websocket\r\n") ||
	    !find_bytes(tp->tx, tp->tx_len,
			"\r\nSec-WebSocket-Protocol: echo\r\n") ||
	    !k || k + 21 + 24 + 2 > tp->tx + tp->tx_len ||
	    memcmp(k + 21 + 24, "\r\n", 2)) {
		lwsl_err("bad ws upgrade request\n");
		lwsl_hexdump_err(tp->tx, tp->tx_len);
		return 1;
	}
	memcpy(key, k + 21, 24);
	memcpy(key + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 37);
	lws_SHA1((const uint8_t *)key, 24 + 36, sha);
	lws_b64_encode_string((const char *)sha, 20, accept, sizeof(accept));
	n = lws_snprintf(resp, sizeof(resp), "%s%s%s\r\n%s\r\n", pre, resp_ws,
			 accept, resp_hdrs);

	if (feed(cx, tp, resp, (size_t)n)) {
		lwsl_err("ws upgrade response not consumed\n");
		return 1;
	}
	if (cli.error || !cli.established || cli.sent == quiet) {
		lwsl_err("ws not established: est %d sent %d\n",
			 cli.established, cli.sent);
		return 1;
	}

	return 0;
}

static int
ws_client_up(struct lws_context *cx, struct lws_vhost *vh,
	     struct transport *tp, const char *resp_hdrs, int quiet)
{
	return ws_client_up_pre(cx, vh, tp, "", resp_hdrs, quiet);
}

/*
 * 31: a ws client the server tells "100 Continue" ahead of its 101.  An
 * interim response is none of its business: it waits on for the 101, and is
 * established by that as usual.
 */
static int
ws_client_interim_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static struct transport tp;

	tr_begin("ws-client-interim", "client", 1);
	if (ws_client_up_pre(cx, vh, &tp, "HTTP/1.1 100 Continue\r\n\r\n",
			     "", 0)) {
		lwsl_err("case 31: failed\n");
		return 1;
	}
	lwsl_user("case 31: a ws client waits on past an interim response "
		  "for its 101: PASS\n");

	return tr_end();
}

static int
client_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char resp_get[] =
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
		"Content-Length: 10\r\n\r\nsansio ok\n";
	static const char frame[] = "\x81\x05Hello";
	static struct transport tp;
	int n;

	/* 4: an h1 GET: the client's request, then its response body */
	tr_begin("h1-client-get", "client", 0);
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
	if (tr_end())
		return 1;

	/* 5: the ws upgrade: its key answered, the client's first frame */
	tr_begin("ws-client", "client", 1);
	if (ws_client_up(cx, vh, &tp, "", 0)) {
		lwsl_err("case 5: failed\n");
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

	return tr_end();
}

/*
 * 30: an h1 client POST whose body goes a piece at a time, and a server that
 * answers before any of it has arrived.  The client reads nothing until its
 * body has gone, so it must not ask to hear of what it is not reading
 * meanwhile: a real poll() would report the answer on every call, a busy
 * loop for as long as the body takes.  Once the body has gone, the answer
 * is read, without anything else waking the connection.
 */
static int
h1_client_early_answer_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
		"Content-Length: 10\r\n\r\nsansio ok\n";
	static struct transport tp;
	struct lws *wsi;

	post_pieces = 4;
	post_go = 0;
	wsi = client_connect(cx, vh, &tp, "/up", "POST", NULL);
	if (!wsi) {
		lwsl_err("case 30: connect failed\n");
		return 1;
	}
	pump(cx, &tp);
	if (tp.tx_len < 20 || memcmp(tp.tx, "POST /up HTTP/1.1\r\n", 19) ||
	    !find_bytes(tp.tx, tp.tx_len, "\r\ncontent-length: 64\r\n") ||
	    memcmp(tp.tx + tp.tx_len - 4, "\r\n\r\n", 4)) {
		lwsl_err("case 30: bad request head\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}

	/* the server answers before any of the body */
	feed(cx, &tp, resp, sizeof(resp) - 1);
	if (tp.closed || tp.rx_pos || tp.want_read || cli.completed) {
		lwsl_err("case 30: closed %d, read %d, reading asked %d, "
			 "completed %d\n", tp.closed, (int)tp.rx_pos,
			 tp.want_read, cli.completed);
		return 1;
	}

	/* the body goes, and then the answer is read */
	post_go = 1;
	tp.tx_len = 0;
	lws_callback_on_writable(wsi);
	tick(cx);
	pump(cx, &tp);
	post_pieces = post_go = 0;
	if (tp.tx_len != 64 || tp.rx_pos != tp.rx_len || cli.error ||
	    !cli.completed || cli.rx_len != 10 ||
	    memcmp(cli.rx, "sansio ok\n", 10)) {
		lwsl_err("case 30: body %d, read %d / %d, completed %d, rx %d\n",
			 (int)tp.tx_len, (int)tp.rx_pos, (int)tp.rx_len,
			 cli.completed, (int)cli.rx_len);
		return 1;
	}
	lwsl_user("case 30: an h1 client answered early reads the answer once "
		  "its body has gone, not before: PASS\n");

	return 0;
}

/*
 * A ws connection the server sends a frame it must not take: the client
 * fails the connection, with a masked close and nothing of the bad frame
 * given to the app (what came before it, rx, is), and lets it go once the
 * server answers the close.
 */
struct refused_frame {
	const char	*name;
	const char	*frames;
	size_t		len;
	const char	*rx; /* what the app gets before the bad frame */
	unsigned int	status; /* the close status it fails it with */
};

static int
client_refuses(struct lws_context *cx, struct lws_vhost *vh, int cn,
	       const char *resp_hdrs, int quiet, const struct refused_frame *c,
	       size_t count)
{
	static const char close_ack[] = "\x88\x02\x03\xe8";
	static struct transport tp;
	unsigned int st;
	size_t n, rxl;

	for (n = 0; n < count; n++) {
		rxl = strlen(c[n].rx);
		tr_begin(c[n].name, "client", 1);
		if (ws_client_up(cx, vh, &tp, resp_hdrs, quiet)) {
			lwsl_err("case %d: %s: failed\n", cn, c[n].name);
			return 1;
		}
		feed(cx, &tp, c[n].frames, c[n].len);
		/* one masked close, its payload the status and a reason */
		st = tp.tx_len >= 8 && tp.tx[0] == 0x88 &&
		     (tp.tx[1] & 0x80) && (tp.tx[1] & 0x7f) >= 2 &&
		     tp.tx_len == 6u + (tp.tx[1] & 0x7fu) ?
			(unsigned int)(((tp.tx[6] ^ tp.tx[2]) << 8) |
				       (tp.tx[7] ^ tp.tx[3])) : 0;
		if (st != c[n].status || cli.rx_len != rxl ||
		    memcmp(cli.rx, c[n].rx, rxl)) {
			lwsl_err("case %d: %s: close %u, rx %d\n", cn,
				 c[n].name, st, (int)cli.rx_len);
			lwsl_hexdump_err(tp.tx, tp.tx_len);
			return 1;
		}
		feed(cx, &tp, close_ack, sizeof(close_ack) - 1);
		if (!tp.closed) {
			lwsl_err("case %d: %s: not closed\n", cn, c[n].name);
			return 1;
		}
		if (tr_end())
			return 1;
	}

	return 0;
}

/*
 * 10: frame headers a ws client must not take from the server: RSV bits
 * with no extension negotiated to give them a meaning, and a frame longer
 * than lws will sit in one frame for (256MiB), the same as a server does
 */
/*
 * 17: an h1 response whose body the client cannot frame is not read: a
 * Content-Length that is not only digits, two of them, or a second
 * Transfer-Encoding after "chunked", which makes it a list of codings.  The
 * client fails the connection, the app told of it and given none of the
 * body.
 */
static int
client_refused_heads_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct {
		const char	*name;
		const char	*resp;
	} c[] = {
		{ "h1-client-cl-junk", "HTTP/1.1 200 OK\r\n"
			"Content-Length: 10abc\r\n\r\nsansio ok\n" },
		{ "h1-client-cl-twice", "HTTP/1.1 200 OK\r\n"
			"Content-Length: 10\r\nContent-Length: 5\r\n\r\n"
			"sansio ok\n" },
		{ "h1-client-te-list", "HTTP/1.1 200 OK\r\n"
			"Transfer-Encoding: chunked\r\n"
			"Transfer-Encoding: gzip\r\n\r\n"
			"a\r\nsansio ok\n\r\n0\r\n\r\n" },
	};
	static struct transport tp;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(c); n++) {
		tr_begin(c[n].name, "client", 0);
		if (!client_connect(cx, vh, &tp, "/x", "GET", NULL)) {
			lwsl_err("case 17: %s: connect failed\n", c[n].name);
			return 1;
		}
		pump(cx, &tp);
		feed(cx, &tp, c[n].resp, strlen(c[n].resp));
		if (!cli.error || cli.completed || cli.rx_len || !tp.closed) {
			lwsl_err("case 17: %s: err %d comp %d rx %d closed %d\n",
				 c[n].name, cli.error, cli.completed,
				 (int)cli.rx_len, tp.closed);
			return 1;
		}
		if (tr_end())
			return 1;
	}
	lwsl_user("case 17: h1 client refuses bad body framing: PASS\n");

	return 0;
}

/*
 * 32: h1 responses with no body, whatever their framing headers say (RFC
 * 9112 6.3): the answer to a HEAD, with Transfer-Encoding: chunked or with a
 * Content-Length, and a 304 with a Content-Length.  The client completes the
 * transaction at the end of the headers, with nothing for the app.
 */
static int
client_bodyless_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct {
		const char	*name;
		const char	*method;
		const char	*resp;
	} c[] = {
		{ "h1-client-head-chunked", "HEAD", "HTTP/1.1 200 OK\r\n"
			"Transfer-Encoding: chunked\r\n\r\n" },
		{ "h1-client-head-cl", "HEAD", "HTTP/1.1 200 OK\r\n"
			"Content-Length: 10\r\n\r\n" },
		{ "h1-client-304-cl", "GET", "HTTP/1.1 304 Not Modified\r\n"
			"Content-Length: 10\r\n\r\n" },
	};
	static struct transport tp;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(c); n++) {
		tr_begin(c[n].name, "client", 0);
		if (!client_connect(cx, vh, &tp, "/x", c[n].method, NULL)) {
			lwsl_err("case 32: %s: connect failed\n", c[n].name);
			return 1;
		}
		pump(cx, &tp);
		feed(cx, &tp, c[n].resp, strlen(c[n].resp));
		if (cli.error || !cli.completed || cli.rx_len) {
			lwsl_err("case 32: %s: err %d comp %d rx %d\n",
				 c[n].name, cli.error, cli.completed,
				 (int)cli.rx_len);
			return 1;
		}
		if (tr_end())
			return 1;
	}
	lwsl_user("case 32: h1 client completes bodyless responses at their "
		  "headers: PASS\n");

	return 0;
}

/*
 * 19: as 18, the ws client: the server's ping, then its close, in one read,
 * get the masked pong and then the masked answer to the close
 */
static int
ws_client_peer_close_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char ping_close[] = "\x89\x01p\x88\x02\x03\xe8";
	static struct transport tp;
	size_t pos = 0;

	tr_begin("ws-client-ping-close", "client", 1);
	if (ws_client_up(cx, vh, &tp, "", 1)) {
		lwsl_err("case 19: failed\n");
		return 1;
	}
	feed(cx, &tp, ping_close, sizeof(ping_close) - 1);
	if (!ws_frame_at(&tp, &pos, 0xa, 1, "p", 1) ||
	    !ws_frame_at(&tp, &pos, 0x8, 1, "\x03\xe8", 2) ||
	    pos != tp.tx_len || (!tp.closed && !tp.shutdown)) {
		lwsl_err("case 19: closed %d\n", tp.closed);
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	lwsl_user("case 19: ws client answers the peer's close: PASS\n");

	return tr_end();
}

static int
client_refused_frames_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct refused_frame c[] = {
		/* FIN, RSV1, TEXT: RSV1 without permessage-deflate */
		{ "ws-client-rsv1-no-ext", "\xc1\x05Hello", 7, "", 1002 },
		/* FIN, RSV2, TEXT */
		{ "ws-client-rsv2", "\xa1\x05Hello", 7, "", 1002 },
		/* FIN, BINARY, 64-bit length 256MiB + 1 */
		{ "ws-client-huge-frame",
		  "\x82\x7f\x00\x00\x00\x00\x10\x00\x00\x01Hello", 15, "",
		  1009 },
	};

	if (client_refuses(cx, vh, 10, "", 0, c, LWS_ARRAY_SIZE(c)))
		return 1;
	lwsl_user("case 10: ws client refuses bad frame headers: PASS\n");

	return 0;
}

#if !defined(LWS_WITHOUT_EXTENSIONS)
/*
 * 11: with permessage-deflate negotiated, RSV1 is still only for the first
 * frame of a data message (RFC 7692 6.1), and RSV2 / RSV3 still mean
 * nothing: an extension being active is not a licence for any RSV bits
 */
static int
client_pmd_refused_frames_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const struct refused_frame c[] = {
		/* FIN, RSV2, TEXT */
		{ "ws-client-pmd-rsv2", "\xa1\x05Hello", 7, "", 1002 },
		/* TEXT "He" uncompressed, then FIN, RSV1, CONTINUATION */
		{ "ws-client-pmd-rsv1-continuation",
		  "\x01\x02He\xc0\x03llo", 9, "He", 1002 },
		/* FIN, RSV1, PING */
		{ "ws-client-pmd-rsv1-ping", "\xc9\x00", 2, "", 1002 },
	};

	/*
	 * quiet: what the client would send is deflated, and deflate's bytes
	 * are the zlib implementation's business, not lws'
	 */
	if (client_refuses(cx, vh, 11,
			   "Sec-WebSocket-Extensions: permessage-deflate\r\n",
			   1, c, LWS_ARRAY_SIZE(c)))
		return 1;
	lwsl_user("case 11: ws client with pmd refuses bad RSV bits: PASS\n");

	return 0;
}
#endif
#endif

#if !defined(LWS_WITHOUT_EXTENSIONS)
/*
 * 12: the same for a ws server with permessage-deflate negotiated: RSV1 on
 * a continuation fails the connection, with a close saying why (1002)
 */
static int
server_pmd_refused_frames_half(struct lws_context *cx, struct lws_vhost *vh)
{
	static const char req_ws[] =
		"GET /echo HTTP/1.1\r\nHost: sansio-pmd\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Protocol: echo\r\n"
		"Sec-WebSocket-Extensions: permessage-deflate\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
	/* masked (with a zero key) TEXT "He", then FIN, RSV1, CONTINUATION */
	static const char frames[] =
		"\x01\x82\x00\x00\x00\x00He\xc0\x83\x00\x00\x00\x00llo";
	static const char refusal[] = "\x88\x0a\x03\xearsv bits";
	static const char close_ack[] = "\x88\x82\x00\x00\x00\x00\x03\xea";
	static struct transport tp;
	struct lws *wsi;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		lwsl_err("socketpair failed\n");
		return 1;
	}
	close(sv[1]);
	if (tp_register(&tp, sv[0]))
		return 1;
	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		lwsl_err("adopt failed\n");
		return 1;
	}
	lws_set_transport(wsi, &tops, &tp);
	tr_begin("ws-server-pmd-rsv1-continuation", "server", 0);

	if (feed(cx, &tp, req_ws, sizeof(req_ws) - 1) ||
	    tp.tx_len < 20 || memcmp(tp.tx, "HTTP/1.1 101 ", 13) ||
	    !find_bytes(tp.tx, tp.tx_len,
			"\r\nsec-websocket-extensions: permessage-deflate")) {
		lwsl_err("case 12: pmd not negotiated\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}

	/*
	 * echo only answers whole messages, so what it writes is only its
	 * close: status 1002 and why
	 */
	feed(cx, &tp, frames, sizeof(frames) - 1);
	if (tp.tx_len != sizeof(refusal) - 1 ||
	    memcmp(tp.tx, refusal, sizeof(refusal) - 1)) {
		lwsl_err("case 12: RSV1 continuation not refused\n");
		lwsl_hexdump_err(tp.tx, tp.tx_len);
		return 1;
	}
	/* once the client answers the close, it shuts the connection down */
	feed(cx, &tp, close_ack, sizeof(close_ack) - 1);
	if (!tp.shutdown) {
		lwsl_err("case 12: not shut down\n");
		return 1;
	}
	lwsl_user("case 12: ws server with pmd refuses RSV1 continuation: "
		  "PASS\n");

	return tr_end();
}
#endif

/*
 * 0: context creation refuses an io_ops table it cannot use: a plain copy
 * of IO's, not stamped with our ABI version, and a stamped one missing a
 * member lws calls without checking.  Returns nonzero if one was taken.
 */
static int
refused_tables(struct lws_context_creation_info *info)
{
	lws_io_ops_t bad;
	struct lws_context *cx;

	bad = lws_io_ops_default;
	info->io_ops = &bad;
	cx = lws_create_context(info);
	if (cx) {
		lwsl_err("case 0: unstamped io_ops taken\n");
		lws_context_destroy(cx);
		return 1;
	}

	lws_io_ops_init(&bad);
	bad.tx_push = NULL;
	cx = lws_create_context(info);
	if (cx) {
		lwsl_err("case 0: io_ops without tx_push taken\n");
		lws_context_destroy(cx);
		return 1;
	}
	lwsl_user("case 0: unusable io_ops tables refused: PASS\n");

	return 0;
}

int
main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, result = 1;
	struct lws_context_creation_info info;
	struct lws_vhost *vh, *vh_uri;
#if defined(LWS_WITH_FILE_OPS)
	struct lws_vhost *vh_404;
#endif
#if defined(LWS_WITH_HTTP2)
	struct lws_vhost *vh_h2, *vh_h2ws;
#endif
#if !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_vhost *vh_pmd;
#endif
	struct lws_context *cx;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	/* how much of a burst of logs to keep, rather than a small tail */
	if ((p = lws_cmdline_option(argc, argv, "--log-spew-tail")))
		lws_log_spew_tail_lines((unsigned int)atoi(p));
	/* write the transcripts to this dir, or check them against these */
	record_dir = lws_cmdline_option(argc, argv, "--record");
	check_dir = lws_cmdline_option(argc, argv, "--transcripts");
	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: the sansIO half over a test transport\n");

	/* IO's requests of the transport, with us listening */
	lws_io_ops_init(&io_ops);
	io_ops.want_write = tp_want_write;
	io_ops.want_read = tp_want_read;
	io_ops.close = tp_close;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	if (refused_tables(&info))
		return 1;

	info.io_ops = &io_ops;
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
	info.reject_service_keywords = &reject_badbot;
#endif
	token_limits.token_limit[WSI_TOKEN_GET_URI] = 33;
	token_limits.token_limit[WSI_TOKEN_HTTP_USER_AGENT] = 16;
	info.token_limits = &token_limits;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}
	/* from here, the time is what we say */
	lws_service_set_now(cx, 0, T0_US, T0_WALL);
	/* and each seeded transcript reseeds lws' random, see tr_begin() */
	tr.cx = cx;

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
#endif
	if (choked_half(cx))
		goto bail;
	if (time_half(cx))
		goto bail;

	/*
	 * The rest start at their own times, so that their transcripts are
	 * the same in a build without the cases before them
	 */

	at(cx, 3000);
	if (upgrade_refusals_half(cx))
		goto bail;

	info.vhost_name = "sansio-uri";
	info.protocols = protocols_uri;
	vh_uri = lws_create_vhost(cx, &info);
	if (!vh_uri) {
		lwsl_err("uri vhost failed\n");
		goto bail;
	}
	at(cx, 3100);
	if (uri_half(cx, vh_uri))
		goto bail;

	at(cx, 3150);
	if (server_refused_frames_half(cx))
		goto bail;

#if defined(LWS_WITH_HTTP2)
	info.vhost_name = "sansio-h2";
	info.protocols = protocols_uri;
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	vh_h2 = lws_create_vhost(cx, &info);
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	if (!vh_h2) {
		lwsl_err("h2 vhost failed\n");
		goto bail;
	}
	at(cx, 3500);
	if (h2_oversized_half(cx, vh_h2))
		goto bail;
	if (h2_early_answer_half(cx, vh_h2, "/early"))
		goto bail;
#if defined(LWS_WITH_FILE_OPS)
	if (h2_early_answer_half(cx, vh_h2, "/file"))
		goto bail;
#endif
#endif

#if defined(LWS_WITH_CLIENT)
	at(cx, 3200);
	if (client_refused_frames_half(cx, vh))
		goto bail;
#endif

#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* a vhost with permessage-deflate, for the cases that want it */
	info.vhost_name = "sansio-pmd";
	info.protocols = protocols;
	info.extensions = extensions;
	vh_pmd = lws_create_vhost(cx, &info);
	if (!vh_pmd) {
		lwsl_err("pmd vhost failed\n");
		goto bail;
	}
	at(cx, 3300);
	if (server_pmd_refused_frames_half(cx, vh_pmd))
		goto bail;
#if defined(LWS_WITH_CLIENT)
	at(cx, 3400);
	if (client_pmd_refused_frames_half(cx, vh_pmd))
		goto bail;
#endif
#endif

#if defined(LWS_WITH_FILE_OPS)
	info.vhost_name = "sansio-404";
	info.protocols = protocols_404;
	info.extensions = NULL;
	info.mounts = &mount_404_files;
	info.error_document_404 = "/404.html";
	vh_404 = lws_create_vhost(cx, &info);
	info.mounts = NULL;
	info.error_document_404 = NULL;
	if (!vh_404) {
		lwsl_err("404 vhost failed\n");
		goto bail;
	}
	at(cx, 3600);
	if (h1_404_half(cx, vh_404))
		goto bail;
	if (h1_redirect_queued_half(cx, vh_404))
		goto bail;
#endif

#if defined(LWS_WITH_CLIENT)
	at(cx, 3700);
	if (client_refused_heads_half(cx, vh))
		goto bail;
#endif

	at(cx, 3800);
	if (ws_server_peer_close_half(cx))
		goto bail;
#if defined(LWS_WITH_CLIENT)
	at(cx, 3900);
	if (ws_client_peer_close_half(cx, vh))
		goto bail;
#endif

#if defined(LWS_WITH_HTTP2)
	/* ws over h2 needs a vhost with the ws protocol */
	info.vhost_name = "sansio-h2ws";
	info.protocols = protocols;
	info.extensions = NULL;
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	vh_h2ws = lws_create_vhost(cx, &info);
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	if (!vh_h2ws) {
		lwsl_err("h2 ws vhost failed\n");
		goto bail;
	}
	at(cx, 4000);
	if (h2_ws_peer_close_half(cx, vh_h2ws, 0))
		goto bail;
	at(cx, 4050);
	if (h2_ws_peer_close_half(cx, vh_h2ws, 1))
		goto bail;
#endif

#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
	at(cx, 4100);
	if (h1_connect_rejected_ua_half(cx, vh_uri))
		goto bail;
#endif

#if defined(LWS_WITH_HTTP2)
	at(cx, 4150);
	if (h2_fin_behind_partial_half(cx, vh_h2))
		goto bail;
#endif

#if defined(LWS_WITH_FILE_OPS)
	at(cx, 4160);
	if (h1_reset_behind_file_half(cx, vh_uri))
		goto bail;
	at(cx, 4165);
	if (h1_shutdown_behind_parked_half(cx, vh_uri))
		goto bail;
#endif

#if defined(LWS_WITH_CLIENT)
	at(cx, 4170);
	if (h1_client_early_answer_half(cx, vh))
		goto bail;
	at(cx, 4180);
	if (ws_client_interim_half(cx, vh))
		goto bail;
	at(cx, 4190);
	if (client_bodyless_half(cx, vh))
		goto bail;
#endif

#if defined(LWS_WITH_HTTP2) && defined(LWS_WITH_FILE_OPS)
	/* last, since they move the time on past the answers' timeouts */
	at(cx, 4200);
	if (h2_file_stalled_half(cx, vh_h2))
		goto bail;
	at(cx, 40000);
	if (h2_slow_answer_half(cx, vh_h2, 40000))
		goto bail;
#endif

	/* last, since it moves the time on past the close timeout */
	if (ws_hangup_behind_flowcontrol_half(cx, 100000))
		goto bail;

#if defined(LWS_WITH_HTTP2) && defined(LWS_WITH_FILE_OPS)
	/* and this moves it on past the response watchdog */
	at(cx, 150000);
	if (h2_answer_in_body_half(cx, vh_h2, 150000))
		goto bail;
#endif

	/* after those, at its own time, so that its transcript is the same */
	at(cx, 200000);
	if (h1_post_no_length_half(cx, vh_uri))
		goto bail;
	at(cx, 205000);
	if (h1_short_answer_half(cx, vh_uri))
		goto bail;

#if defined(LWS_WITH_FILE_OPS) && defined(LWS_WITH_ASYNC_QUEUE)
	at(cx, 210000);
	if (h1_file_abandoned_half(cx, vh_uri, 210000))
		goto bail;
#if defined(LWS_WITH_HTTP2)
	at(cx, 220000);
	if (h2_file_abandoned_half(cx, vh_h2, 220000))
		goto bail;
#endif
#endif

	/* this moves the time on past the response watchdog */
	at(cx, 250000);
	if (h1_answer_in_body_half(cx, vh_uri, 250000))
		goto bail;
	at(cx, 300000);
	if (h1_discard_slow_body_half(cx, vh_uri, 300000))
		goto bail;

	result = 0;

bail:
	lws_context_destroy(cx);
	free(tr.js);
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
