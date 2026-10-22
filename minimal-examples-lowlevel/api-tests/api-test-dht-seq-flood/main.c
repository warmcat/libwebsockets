/*
 * lws-api-test-dht-seq-flood
 *
 * The DHT keeps at most 64 transport sequencers, and a forged first data
 * chunk from an address it has none for is enough to make one.  Making room
 * must never cost a transfer in flight, and whatever ends a sequencer holding
 * a consumer's message must tell the consumer (G-496):
 *
 *  - B queues a message to a raw UDP peer P.  Before P acks it, 70 first
 *    chunks arrive at B from 70 sources at 127.0.0.2 and 127.0.0.3, as a
 *    spoofer would send them.  None of them is a node B knows, so they only
 *    get the strangers' share of B's table, half of it, and make room for
 *    each other there (G-525), and P's sequencer survives: when P then acks,
 *    B's message to P completes
 *
 *  - B queues a second message to P, and one message to each of 63
 *    addresses where nothing listens.  Each takes a free sequencer or one
 *    that nothing is using any more, until all 64 hold a message no one has
 *    acked: then a message to a 65th peer is refused, rather than one of
 *    them being destroyed for it
 *
 *  - P acks its second message.  B's handler for its WRITE_COMPLETED sends
 *    to a new peer: P's sequencer is the only one with nothing outstanding,
 *    but it is the one calling back, so it must not be recycled under its
 *    own callback (G-181), and the send is refused.  This is the case where
 *    only `in_cb` keeps the sequencer from being recycled (G-519)
 *
 *  - each of the 63 later fails visibly, with LWS_DHT_EVENT_WRITE_FAILED,
 *    and once they are gone, a message to P is taken again.  B's handler
 *    resends the first failed message: it is taken, on a new session, not
 *    lost in the one that failed, and fails in its turn
 *
 *  - 32 raw peers on 127.0.0.4 - .7 each prove a session with B, answering
 *    its challenge, and then keep resending that chunk.  They fill the
 *    strangers' share, so 32 more on 127.0.0.8 - .11 then get no slot: their
 *    first chunks are dropped unanswered, while the sessions have just
 *    brought data.  But B's message to a new peer is taken: the rest of the
 *    table is not theirs to fill (G-525)
 *
 *  - duplicates are not progress: a few seconds later, the peers stop
 *    resending, and a newcomer's first chunk takes the slot of one of the
 *    idle sessions and is challenged (G-518)
 *
 *  - the sessions then each bring a new byte four times a second, which is
 *    progress, and keeps them in use.  A second newcomer's first chunk is
 *    dropped while they are young, but once the oldest is ten seconds old it
 *    gives way to the newcomer, whatever it brings; the strangers never hold
 *    more than their share, the first newcomer, younger, keeps its session,
 *    and B can still send to a new peer (G-525)
 *
 * Loopback addresses count as separate hosts, so the 4 sessions per host
 * limit doesn't apply here.  Nothing listens on the fan port, at 127.0.1.1
 * and up.  The UDP ports are allocated uniquely at build time and passed in
 * on the command line, so parallel ctest instances do not collide.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define FL_POLL_US	(50 * LWS_US_PER_MS)
#define FL_DEADLINE_US	(30 * LWS_US_PER_SEC)

#define FL_MAX_TS	64	/* LWS_DHT_MAX_TS */
#define FL_STRANGERS	32	/* LWS_DHT_TS_STRANGERS_MAX */
/* LWS_DHT_TS_STRANGER_MIN_AGE_US, and some */
#define FL_MIN_AGE_US	(10500 * LWS_US_PER_MS)
#define FL_SPOOFERS	70	/* first chunks, from two hosts */
#define FL_SETTLE_US	(150 * LWS_US_PER_MS)
#define FL_HOLDERS	FL_STRANGERS	/* peers holding proven sessions */
/* the holders, as many again who come late, and two newcomers */
#define FL_LATE		FL_HOLDERS
#define FL_NC0		(FL_HOLDERS * 2)
#define FL_NC1		(FL_NC0 + 1)
#define FL_PEERS	(FL_NC1 + 1)
#define FL_DUP_US	(250 * LWS_US_PER_MS)	/* how often they send */
#define FL_PROTECT_US	(400 * LWS_US_PER_MS)
/* LWS_DHT_TS_RX_GRACE_US, and some */
#define FL_GRACE_US	(3500 * LWS_US_PER_MS)
#define FL_CH_LEN	8	/* B's session challenge */

enum {
	FL_SEND,	/* B queues a message to P */
	FL_FLOOD,	/* when P has had its chunk, the forged chunks come */
	FL_SETTLE,	/* B has taken them: P's sequencer must be there */
	FL_COMPLETE,	/* P acked: B's message to it must complete */
	FL_FENCE,	/* P acks a second, and B sends from its handler */
	FL_FAIL_ALL,	/* the silent peers' sessions all fail, visibly */
	FL_P_DONE,	/* P has acked a third message: nothing outstanding */
	FL_HOLD,	/* the holders prove their sessions, then the late come */
	FL_SHARE,	/* the late get nothing, but B's send is taken */
	FL_GRACE,	/* the holders only resend, then stop, and newcomer 0... */
	FL_NEWCOMER,	/* ... must be challenged */
	FL_TRICKLE,	/* the sessions bring data, then newcomer 1 comes... */
	FL_YOUNG,	/* ... and is refused while they are young */
	FL_AGE,		/* until the oldest is old enough: it must give way */
};

static struct lws_context *cx;
static struct lws_dht_ctx *dht;
static struct lws *wsi_p, *wsi_spoof[FL_SPOOFERS], *wsi_peer[FL_PEERS];
static struct sockaddr_in sa_dht, sa_p, sa_fan, sa_spoof[FL_SPOOFERS],
			  sa_peer[FL_PEERS];
static lws_sorted_usec_list_t sul_poll, sul_deadline, sul_dup;
static int state, retcode = 1, port_fan;
static lws_usec_t flood_time, hold_time, phase_time;
static uint8_t msg[512];

static struct {
	uint8_t		tid[16];	/* B's tid for its chunks to P */
	size_t		tid_len;
	int		silent_failed;
	int		p_completed;	/* B's messages to P that completed */
	int		fence_r;	/* B's send from P's WRITE_COMPLETED */
	int		resend_r;	/* ...and from a WRITE_FAILED */
	unsigned int	resent:1;
	unsigned int	fence_done:1;
	unsigned int	p_failed:1;
	unsigned int	sending:1;	/* the proven peers send */
	unsigned int	trickle:1;	/* ...a new byte each time */
	int		held;		/* peers proven */
	struct {
		uint64_t	off;	/* where the peer's next byte goes */
		uint64_t	acked;	/* what B acked of its session */
		uint8_t		proven;	/* B acked its first chunk */
		uint8_t		gone;	/* B lost its session: quiet */
		uint8_t		ch;	/* B challenged it */
	} p[FL_PEERS];
} fl;

static void fl_silent(int i, struct sockaddr_in *sin);

static int
fl_is(const struct sockaddr *sa, const struct sockaddr_in *sin)
{
	return sa && sa->sa_family == AF_INET &&
	       ((const struct sockaddr_in *)sa)->sin_addr.s_addr ==
						sin->sin_addr.s_addr &&
	       ((const struct sockaddr_in *)sa)->sin_port == sin->sin_port;
}

/* one of the silent peers, at 127.0.1.x on the fan port */

static int
fl_is_silent(const struct sockaddr *sa)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;

	return sa && sa->sa_family == AF_INET &&
	       sin->sin_port == sa_fan.sin_port &&
	       (ntohl(sin->sin_addr.s_addr) & 0xffffff00) == 0x7f000100;
}

static void
cb_dht(void *closure, int event, const lws_dht_hash_t *info_hash,
       const void *data, size_t data_len, const struct sockaddr *from,
       size_t fromlen)
{
	switch (event) {
	case LWS_DHT_EVENT_WRITE_FAILED:
		if (fl_is(from, &sa_p))
			fl.p_failed = 1;
		if (!fl_is_silent(from))
			break;
		fl.silent_failed++;
		if (!fl.resent) {
			/* the consumer tries its failed message again */
			fl.resent = 1;
			fl.resend_r = lws_dht_send_data(dht, from, msg,
							sizeof(msg));
		}
		break;
	case LWS_DHT_EVENT_WRITE_COMPLETED:
		if (!fl_is(from, &sa_p))
			break;
		fl.p_completed++;
		if (state == FL_FENCE && !fl.fence_done) {
			struct sockaddr_in sin;

			/* every other sequencer holds an unacked message */
			fl_silent(FL_MAX_TS - 1, &sin);
			fl.fence_r = lws_dht_send_data(dht,
					(struct sockaddr *)&sin, msg,
					sizeof(msg));
			fl.fence_done = 1;
		}
		break;
	}
}

static ssize_t
fl_find(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle), n;

	for (n = 0; n + nl <= len; n++)
		if (!memcmp(buf + n, needle, nl))
			return (ssize_t)n;

	return -1;
}

/*
 * A chunk of B's to P: ...e1:q4:data1:t<len>:<tid>1:y1:qe.  Keep its tid,
 * which P's ack has to echo.
 */

static void
fl_p_rx(const uint8_t *buf, size_t len)
{
	ssize_t at = fl_find(buf, len, "1:q4:data1:t");
	size_t n, l = 0;

	if (at < 0 || fl.tid_len)
		return;

	for (n = (size_t)at + 12; n < len && buf[n] >= '0' && buf[n] <= '9'; n++)
		l = (l * 10) + (size_t)(buf[n] - '0');

	if (n >= len || buf[n] != ':' || !l || l > sizeof(fl.tid) ||
	    n + 1 + l > len)
		return;

	memcpy(fl.tid, buf + n + 1, l);
	fl.tid_len = l;
}

static int
fl_sendto(struct lws *wsi, const char *q, size_t l)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi);
	ssize_t r;

	if (fd == LWS_SOCK_INVALID)
		return 1;

	r = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   q,
#if defined(WIN32)
		   (int)
#endif
		   l, 0, (const struct sockaddr *)&sa_dht, sizeof(sa_dht));
	if (r != (ssize_t)l) {
		lwsl_err("%s: sendto returned %d\n", __func__, (int)r);
		return 1;
	}

	return 0;
}

/* P's ack of B's chunks below offset: d1:rd2:id..3:len..6:offset..e1:t..e */

static int
fl_p_send_ack(uint64_t offset)
{
	char q[160];
	int n;

	n = lws_snprintf(q, sizeof(q), "d1:rd2:id20:66666666666666666666"
			 "3:leni0e6:offseti%llue" "e1:t%u:",
			 (unsigned long long)offset, (unsigned int)fl.tid_len);
	if (n <= 0 || (size_t)n + fl.tid_len + 7 > sizeof(q))
		return 1;

	memcpy(q + n, fl.tid, fl.tid_len);
	memcpy(q + (size_t)n + fl.tid_len, "1:y1:re", 7);

	return fl_sendto(wsi_p, q, (size_t)n + fl.tid_len + 7);
}

/*
 * The first chunk of a session from a source B has never heard from: all it
 * takes to make B create a sequencer for that source and challenge it.  The
 * tid is "sq" + 8 bytes and the id is the source's own, as a forger would
 * make them.
 */

static int
fl_spoof(int i)
{
	char q[160];
	int n;

	n = lws_snprintf(q, sizeof(q), "d1:ad4:data4:junk2:id20:"
			 "spoofer-%012d3:leni4e6:offseti0ee"
			 "1:q4:data1:t10:sq%08d1:y1:qe", i, i);
	if (n <= 0 || (size_t)n >= sizeof(q))
		return 1;

	return fl_sendto(wsi_spoof[i], q, (size_t)n);
}

/*
 * A chunk of peer i's session: its first, four bytes at offset 0, carrying
 * B's challenge ch when it has one to answer, or once it is trickling, one
 * new byte at the next offset
 */

static int
fl_chunk(int i, const uint8_t *ch, int more)
{
	char q[192];
	size_t l;
	int n;

	memcpy(q, "d1:ad", 5);
	l = 5;
	if (ch) {
		memcpy(q + l, "2:ch8:", 6);
		memcpy(q + l + 6, ch, FL_CH_LEN);
		l += 6 + FL_CH_LEN;
	}
	if (more)
		n = lws_snprintf(q + l, sizeof(q) - l, "4:data1:x2:id20:"
				 "holder-%013d3:leni1e6:offseti%llue"
				 "e1:q4:data1:t10:sq%08d1:y1:qe", i,
				 (unsigned long long)fl.p[i].off++, i);
	else
		n = lws_snprintf(q + l, sizeof(q) - l, "4:data4:hold2:id20:"
				 "holder-%013d3:leni4e6:offseti0ee"
				 "1:q4:data1:t10:sq%08d1:y1:qe", i, i);
	if (n <= 0 || (size_t)n >= sizeof(q) - l)
		return 1;

	return fl_sendto(wsi_peer[i], q, l + (size_t)n);
}

/*
 * B's reply to peer i: a challenge, which it answers if it never had a
 * session, or an ack.  A challenge to a peer that had a session means B
 * gave the session up: the peer goes quiet.
 */

static void
fl_peer_rx(int i, const uint8_t *buf, size_t len)
{
	uint64_t v = 0;
	ssize_t at;
	size_t n;

	if (fl_find(buf, len, "d1:rd2:ch8:") == 0 &&
	    len >= 11 + FL_CH_LEN) {
		fl.p[i].ch = 1;
		if (fl.p[i].proven)
			fl.p[i].gone = 1;
		else if (i < FL_LATE || i >= FL_NC0)
			fl_chunk(i, buf + 11, 0);
		return;
	}

	at = fl_find(buf, len, "6:offseti");
	if (at < 0)
		return;
	for (n = (size_t)at + 9; n < len && buf[n] >= '0' && buf[n] <= '9'; n++)
		v = (v * 10) + (uint64_t)(buf[n] - '0');
	if (n == len || buf[n] != 'e')
		return;
	if (v > fl.p[i].acked)
		fl.p[i].acked = v;

	if (v == 4 && !fl.p[i].proven) {
		fl.p[i].proven = 1;
		fl.p[i].off = 4;
		fl.held++;
	}
}

/* the proven peers resend the chunk B has already taken, or bring more */

static void
dup_cb(lws_sorted_usec_list_t *sul)
{
	int i;

	for (i = 0; i < FL_PEERS; i++)
		if (fl.sending && fl.p[i].proven && !fl.p[i].gone)
			fl_chunk(i, NULL, fl.trickle);

	lws_sul_schedule(cx, 0, &sul_dup, dup_cb, FL_DUP_US);
}

static int
cb_peer(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	void *in, size_t len)
{
	const struct lws_udp *udp;
	int i;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	udp = lws_get_udp(wsi);
	if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
	    udp->sa46.sa4.sin_port != sa_dht.sin_port)
		return 0;

	if (wsi == wsi_p) {
		fl_p_rx(in, len);
		return 0;
	}

	for (i = 0; i < FL_PEERS; i++)
		if (wsi == wsi_peer[i]) {
			fl_peer_rx(i, in, len);
			break;
		}

	return 0;
}

static int
has_ts(struct sockaddr_in *sin)
{
	return !!lws_dht_get_ts(dht, (struct sockaddr *)sin, sizeof(*sin), 0);
}

/* how many of peers from .. to - 1 B has a sequencer for */

static int
peers_ts(int from, int to)
{
	int n = 0;

	while (from < to)
		n += has_ts(&sa_peer[from++]);

	return n;
}

static void
fl_silent(int i, struct sockaddr_in *sin)
{
	*sin = sa_fan;
	sin->sin_addr.s_addr = htonl(0x7f000101u + (uint32_t)i);
}

/* B's message to a new silent peer must be taken */

static int
fl_send_new(int i)
{
	struct sockaddr_in sin;

	fl_silent(i, &sin);
	if (lws_dht_send_data(dht, (struct sockaddr *)&sin, msg, sizeof(msg)) !=
							LWS_DHT_SEND_QUEUED) {
		lwsl_err("send to a new peer refused\n");
		return 1;
	}

	return 0;
}

/* 0 = keep polling, 1 = passed, -1 = failed */

static int
step(void)
{
	struct sockaddr_in sin;
	int n, count;

	/* whatever else happens, strangers never hold more than their share */
	if (state >= FL_HOLD) {
		count = peers_ts(0, FL_PEERS);
		if (count > FL_STRANGERS) {
			lwsl_err("%d strangers hold sequencers\n", count);
			return -1;
		}
	}

	switch (state) {
	case FL_SEND:
		if (lws_dht_send_data(dht, (struct sockaddr *)&sa_p, msg,
				      sizeof(msg)) != LWS_DHT_SEND_QUEUED) {
			lwsl_err("message to P not taken\n");
			return -1;
		}
		state++;
		return 0;

	case FL_FLOOD:
		if (!fl.tid_len)
			return 0;
		for (n = 0; n < FL_SPOOFERS; n++)
			if (fl_spoof(n))
				return -1;
		lwsl_user("%d forged first chunks sent\n", FL_SPOOFERS);
		flood_time = lws_now_usecs();
		state++;
		return 0;

	case FL_SETTLE:
		if (lws_now_usecs() - flood_time < FL_SETTLE_US)
			return 0;
		count = 0;
		for (n = 0; n < FL_SPOOFERS; n++)
			count += has_ts(&sa_spoof[n]);
		lwsl_user("%d forged sources have sequencers\n", count);
		if (count != FL_STRANGERS) {
			lwsl_err("the forged sources did not fill exactly the "
				 "strangers' share\n");
			return -1;
		}
		if (fl.p_failed || !has_ts(&sa_p)) {
			lwsl_err("P's transfer was destroyed for the flood\n");
			return -1;
		}
		if (fl_p_send_ack(sizeof(msg)))
			return -1;
		state++;
		return 0;

	case FL_COMPLETE:
		if (fl.p_failed) {
			lwsl_err("P's session failed\n");
			return -1;
		}
		if (!fl.p_completed)
			return 0;
		lwsl_user("P's message completed after the flood\n");

		/*
		 * Every sequencer is now one nothing is using: the forged
		 * sources never answered their challenges, and P's is done.
		 * P's takes a second message, and each of these takes a free
		 * one or one of the others...
		 */
		if (lws_dht_send_data(dht, (struct sockaddr *)&sa_p, msg,
				      sizeof(msg)) != LWS_DHT_SEND_QUEUED) {
			lwsl_err("second message to P not taken\n");
			return -1;
		}
		for (n = 0; n < FL_MAX_TS - 1; n++) {
			fl_silent(n, &sin);
			if (lws_dht_send_data(dht, (struct sockaddr *)&sin,
					      msg, sizeof(msg)) !=
							LWS_DHT_SEND_QUEUED) {
				lwsl_err("silent peer %d refused\n", n);
				return -1;
			}
		}

		/* ... and now each holds a message nobody has acked */
		fl_silent(n, &sin);
		if (lws_dht_send_data(dht, (struct sockaddr *)&sin, msg,
				      sizeof(msg)) != LWS_DHT_SEND_REFUSED) {
			lwsl_err("65th peer not refused\n");
			return -1;
		}
		for (n = 0; n < FL_MAX_TS - 1; n++) {
			fl_silent(n, &sin);
			if (!has_ts(&sin)) {
				lwsl_err("silent peer %d lost its message\n", n);
				return -1;
			}
		}
		if (fl_p_send_ack(2 * sizeof(msg)))
			return -1;
		state++;
		return 0;

	case FL_FENCE:
		if (fl.p_failed) {
			lwsl_err("P's session failed\n");
			return -1;
		}
		if (!fl.fence_done)
			return 0;
		if (fl.p_completed != 2 || fl.fence_r != LWS_DHT_SEND_REFUSED) {
			lwsl_err("send from P's WRITE_COMPLETED: %d, P's "
				 "sequencer recycled under its callback\n",
				 fl.fence_r);
			return -1;
		}
		lwsl_user("send from P's WRITE_COMPLETED refused, P's "
			  "sequencer kept\n");
		state++;
		return 0;

	case FL_FAIL_ALL:
		if (fl.resent && fl.resend_r != LWS_DHT_SEND_QUEUED) {
			lwsl_err("message resent from WRITE_FAILED: %d\n",
				 fl.resend_r);
			return -1;
		}
		/* the 63, and the one resent */
		if (fl.silent_failed < FL_MAX_TS)
			return 0;
		if (fl.silent_failed != FL_MAX_TS) {
			lwsl_err("%d failures for %d sessions\n",
				 fl.silent_failed, FL_MAX_TS);
			return -1;
		}
		lwsl_user("all %d silent peers' messages, and the one resent, "
			  "reported failed\n", FL_MAX_TS - 1);
		if (lws_dht_send_data(dht, (struct sockaddr *)&sa_p, msg,
				      sizeof(msg)) != LWS_DHT_SEND_QUEUED) {
			lwsl_err("P refused once the table emptied\n");
			return -1;
		}
		if (fl_p_send_ack(3 * sizeof(msg)))
			return -1;
		state++;
		return 0;

	case FL_P_DONE:
		if (fl.p_failed) {
			lwsl_err("P's session failed\n");
			return -1;
		}
		if (fl.p_completed != 3)
			return 0;
		for (n = 0; n < FL_HOLDERS; n++)
			if (fl_chunk(n, NULL, 0))
				return -1;
		fl.sending = 1;
		lws_sul_schedule(cx, 0, &sul_dup, dup_cb, FL_DUP_US);
		state++;
		return 0;

	case FL_HOLD:
		if (fl.held != FL_HOLDERS)
			return 0;
		lwsl_user("%d peers hold proven sessions\n", fl.held);
		hold_time = lws_now_usecs();
		for (n = FL_LATE; n < FL_LATE + FL_HOLDERS; n++)
			if (fl_chunk(n, NULL, 0))
				return -1;
		state++;
		return 0;

	case FL_SHARE:
		if (lws_now_usecs() - hold_time < FL_PROTECT_US)
			return 0;
		for (n = FL_LATE; n < FL_LATE + FL_HOLDERS; n++)
			if (fl.p[n].ch || has_ts(&sa_peer[n])) {
				lwsl_err("a late peer got a slot beyond the "
					 "strangers' share\n");
				return -1;
			}
		lwsl_user("late peers refused while the sessions had data\n");
		/* the rest of the table is for us */
		if (fl_send_new(FL_MAX_TS))
			return -1;
		lwsl_user("B's message to a new peer is taken\n");
		state++;
		return 0;

	case FL_GRACE:
		if (lws_now_usecs() - hold_time < FL_GRACE_US)
			return 0;
		/* duplicates were never progress: now they stop */
		fl.sending = 0;
		if (fl_chunk(FL_NC0, NULL, 0))
			return -1;
		phase_time = lws_now_usecs();
		state++;
		return 0;

	case FL_NEWCOMER:
		if (!fl.p[FL_NC0].proven) {
			if (lws_now_usecs() - phase_time < LWS_US_PER_SEC)
				return 0;
			lwsl_err("sessions only resending still hold every "
				 "slot\n");
			return -1;
		}
		lwsl_user("newcomer took the place of a session that only "
			  "resent\n");
		/* the one it replaced is quiet from now */
		for (n = 0; n < FL_HOLDERS; n++)
			if (!has_ts(&sa_peer[n]))
				fl.p[n].gone = 1;
		fl.sending = 1;
		fl.trickle = 1;
		phase_time = lws_now_usecs();
		state++;
		return 0;

	case FL_TRICKLE:
		/* every session has brought something new */
		for (n = 0; n < FL_PEERS; n++)
			if (fl.p[n].proven && !fl.p[n].gone &&
			    fl.p[n].acked < 5) {
				if (lws_now_usecs() - phase_time <
							2 * LWS_US_PER_SEC)
					return 0;
				lwsl_err("peer %d's new data not acked\n", n);
				return -1;
			}
		if (fl_chunk(FL_NC1, NULL, 0))
			return -1;
		phase_time = lws_now_usecs();
		state++;
		return 0;

	case FL_YOUNG:
		if (lws_now_usecs() - phase_time < FL_PROTECT_US)
			return 0;
		if (fl.p[FL_NC1].ch) {
			lwsl_err("a newcomer took the slot of a young session "
				 "bringing data\n");
			return -1;
		}
		lwsl_user("newcomer refused while the sessions are young\n");
		state++;
		return 0;

	case FL_AGE:
		if (!fl.p[FL_NC1].ch) {
			if (lws_now_usecs() - hold_time < FL_MIN_AGE_US)
				return 0;
			if (lws_now_usecs() - hold_time >
					FL_MIN_AGE_US + LWS_US_PER_SEC) {
				lwsl_err("sessions bringing data hold the "
					 "strangers' share for ever\n");
				return -1;
			}
			/* it tries again, as a sender would */
			return fl_chunk(FL_NC1, NULL, 0) ? -1 : 0;
		}
		if (!fl.p[FL_NC1].proven)
			return 0;
		lwsl_user("the oldest session gave way to a newcomer\n");
		if (!has_ts(&sa_peer[FL_NC0]) || fl.p[FL_NC0].gone) {
			lwsl_err("the younger newcomer lost its session\n");
			return -1;
		}
		count = peers_ts(0, FL_HOLDERS);
		if (count >= FL_HOLDERS - 1) {
			lwsl_err("no holder gave way (%d have sessions)\n",
				 count);
			return -1;
		}
		if (fl_send_new(FL_MAX_TS + 1))
			return -1;

		return 1;
	}

	return -1;
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	int n = step();

	if (n) {
		retcode = n < 0;
		lws_default_loop_exit(cx);
		return;
	}

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, FL_POLL_US);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out in state %d\n", __func__, state);
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

/* a raw UDP socket bound to ads, and the address it got */

static struct lws *
fl_socket(struct lws_vhost *vh, const char *ads, const char *name,
	  struct sockaddr_in *sin)
{
	struct lws *w;
#if defined(WIN32)
	int slen;
#else
	socklen_t slen;
#endif

	w = lws_create_adopt_udp(vh, ads, 0, LWS_CAUDP_BIND, "fl-peer", NULL,
				 NULL, NULL, NULL, name);
	slen = sizeof(*sin);
	if (!w || getsockname(lws_get_socket_fd(w), (struct sockaddr *)sin,
			      &slen) || sin->sin_family != AF_INET ||
	    !sin->sin_port) {
		lwsl_err("raw udp socket on %s creation failed\n", ads);
		return NULL;
	}

	return w;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	static const struct lws_protocols protocols[] = {
		{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
		{ "fl-peer", cb_peer, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	int port_dht = 0, port_p = 0, n = 0;
	struct lws_vhost *vh;
	lws_dht_info_t di;
	uint8_t idb[20];
	const char *p;

	lws_context_info_defaults(&info, NULL);
	/* the forging and holding sockets need more fds than a client's */
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-dht")))
		port_dht = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-fan")))
		port_fan = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-p")))
		port_p = atoi(p);

	if (port_dht < 1 || port_dht > 65535 || port_fan < 1 ||
	    port_fan > 65535 || port_p < 1 || port_p > 65535 ||
	    port_dht == port_fan || port_dht == port_p || port_fan == port_p) {
		lwsl_err("usage: --port-dht <udp port> --port-p <udp port> "
			 "--port-fan <unused udp port>\n");
		return 1;
	}

	lwsl_user("LWS API selftest: dht sequencer table flood\n");

	signal(SIGINT, sigint_handler);

	memset(msg, 'x', sizeof(msg));

	memset(&sa_dht, 0, sizeof(sa_dht));
	sa_dht.sin_family = AF_INET;
	sa_dht.sin_port = htons((uint16_t)port_dht);
	sa_dht.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa_p = sa_dht;
	sa_p.sin_port = htons((uint16_t)port_p);
	sa_fan = sa_dht;
	sa_fan.sin_port = htons((uint16_t)port_fan);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "dht-fl";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	memset(idb, 0x33, sizeof(idb));
	memset(&di, 0, sizeof(di));
	di.allow_private_ads	= 1; /* everything is on loopback */
	di.vhost		= vh;
	di.cb			= cb_dht;
	di.name			= "fl";
	di.port			= port_dht;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}
	if (!dht) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	wsi_p = lws_create_adopt_udp(vh, "127.0.0.1", port_p, LWS_CAUDP_BIND,
				     protocols[1].name, NULL, NULL, NULL, NULL,
				     "fl-p");
	if (!wsi_p) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	/* each forged chunk comes from its own address, on two hosts */
	for (n = 0; n < FL_SPOOFERS; n++) {
		wsi_spoof[n] = fl_socket(vh, n & 1 ? "127.0.0.3" : "127.0.0.2",
					 "fl-spoof", &sa_spoof[n]);
		if (!wsi_spoof[n])
			goto bail;
	}

	/*
	 * the holders, 8 to a loopback address, the late ones after them, and
	 * the newcomers
	 */
	for (n = 0; n < FL_PEERS; n++) {
		char ads[16];

		lws_snprintf(ads, sizeof(ads), "127.0.0.%d",
			     n < FL_NC0 ? 4 + (n / 8) : 12 + n - FL_NC0);
		wsi_peer[n] = fl_socket(vh, ads, "fl-hold", &sa_peer[n]);
		if (!wsi_peer[n])
			goto bail;
	}
	n = 0;

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, FL_DEADLINE_US);
	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, FL_POLL_US);

	while (n >= 0)
		n = lws_service(cx, 0);

	lwsl_user("Completed: %s\n", retcode ? "FAIL" : "PASS");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_sul_cancel(&sul_dup);
	lws_context_destroy(cx);

	return retcode;
}
