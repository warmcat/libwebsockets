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
 *    spoofer would send them.  B's table fills with their sequencers, and
 *    they make room for each other, but P's survives: when P then acks, B's
 *    message to P completes
 *
 *  - B queues a second message to P, and one message to each of 63
 *    addresses where nothing listens.  Each takes a sequencer that nothing
 *    is using any more, until all 64 hold a message no one has acked: then
 *    a message to a 65th peer is refused, rather than one of them being
 *    destroyed for it
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
 *  - 64 raw peers on 127.0.0.4 - .7 each prove a session with B, answering
 *    its challenge, and then keep resending that chunk.  A newcomer's first
 *    chunk right after is dropped unanswered: the sessions have just brought
 *    data.  But the duplicates are not progress: a few seconds later, a
 *    second newcomer's first chunk takes the slot of one of the idle
 *    sessions and is challenged, and B's message to a new peer is taken
 *    (G-518)
 *
 * Loopback addresses count as separate hosts, so the 4 sessions per host
 * limit doesn't apply here.  Nothing listens on the fan port, at 127.0.1.1
 * and up.  The UDP ports are
 * allocated uniquely at build time and passed in on the command line, so
 * parallel ctest instances do not collide.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define FL_POLL_US	(50 * LWS_US_PER_MS)
#define FL_DEADLINE_US	(20 * LWS_US_PER_SEC)

#define FL_MAX_TS	64	/* LWS_DHT_MAX_TS */
#define FL_SPOOFERS	70	/* first chunks, from two hosts */
#define FL_SETTLE_US	(150 * LWS_US_PER_MS)
#define FL_HOLDERS	64	/* peers holding proven sessions */
#define FL_DUP_US	(250 * LWS_US_PER_MS)	/* how often they resend */
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
	FL_HOLD,	/* the holders prove their sessions */
	FL_PROTECT,	/* a newcomer is refused: the sessions just had data */
	FL_GRACE,	/* the holders only resend, then another newcomer... */
	FL_NEWCOMER,	/* ... must be challenged */
};

static struct lws_context *cx;
static struct lws_dht_ctx *dht;
static struct lws *wsi_p, *wsi_spoof[FL_SPOOFERS], *wsi_hold[FL_HOLDERS],
		  *wsi_new[2];
static struct sockaddr_in sa_dht, sa_p, sa_fan, sa_spoof[FL_SPOOFERS];
static lws_sorted_usec_list_t sul_poll, sul_deadline, sul_dup;
static int state, retcode = 1, port_fan;
static lws_usec_t flood_time, hold_time;
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
	uint8_t		proven[FL_HOLDERS];	/* B acked its chunk */
	int		held;			/* holders proven */
	uint8_t		new_ch[2];		/* B challenged newcomer */
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
 * The first chunk of holder or newcomer i's session, carrying B's challenge
 * ch when it has one to answer
 */

static int
fl_chunk(struct lws *wsi, int i, const uint8_t *ch)
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
	n = lws_snprintf(q + l, sizeof(q) - l, "4:data4:hold2:id20:"
			 "holder-%013d3:leni4e6:offseti0ee"
			 "1:q4:data1:t10:sq%08d1:y1:qe", i, i);
	if (n <= 0 || (size_t)n >= sizeof(q) - l)
		return 1;

	return fl_sendto(wsi, q, l + (size_t)n);
}

/* B's reply to a holder or newcomer: a challenge, or an ack */

static void
fl_hold_rx(struct lws *wsi, const uint8_t *buf, size_t len)
{
	int i;

	for (i = 0; i < 2; i++)
		if (wsi == wsi_new[i]) {
			if (fl_find(buf, len, "d1:rd2:ch8:") == 0)
				fl.new_ch[i] = 1;
			return;
		}

	for (i = 0; i < FL_HOLDERS; i++)
		if (wsi == wsi_hold[i])
			break;
	if (i == FL_HOLDERS)
		return;

	if (fl_find(buf, len, "d1:rd2:ch8:") == 0 &&
	    len >= 11 + FL_CH_LEN) {
		if (!fl.proven[i])
			fl_chunk(wsi, i, buf + 11);
		return;
	}

	if (fl_find(buf, len, "6:offseti4e") >= 0 && !fl.proven[i]) {
		fl.proven[i] = 1;
		fl.held++;
	}
}

/* the holders resend the chunk B has already taken from each */

static void
dup_cb(lws_sorted_usec_list_t *sul)
{
	int i;

	for (i = 0; i < FL_HOLDERS; i++)
		if (fl.proven[i])
			fl_chunk(wsi_hold[i], i, NULL);

	lws_sul_schedule(cx, 0, &sul_dup, dup_cb, FL_DUP_US);
}

static int
cb_peer(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	void *in, size_t len)
{
	const struct lws_udp *udp;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	udp = lws_get_udp(wsi);
	if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
	    udp->sa46.sa4.sin_port != sa_dht.sin_port)
		return 0;

	if (wsi == wsi_p)
		fl_p_rx(in, len);
	else
		fl_hold_rx(wsi, in, len);

	return 0;
}

static int
has_ts(struct sockaddr_in *sin)
{
	return !!lws_dht_get_ts(dht, (struct sockaddr *)sin, sizeof(*sin), 0);
}

static void
fl_silent(int i, struct sockaddr_in *sin)
{
	*sin = sa_fan;
	sin->sin_addr.s_addr = htonl(0x7f000101u + (uint32_t)i);
}

/* 0 = keep polling, 1 = passed, -1 = failed */

static int
step(void)
{
	struct sockaddr_in sin;
	int n, count;

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
		count = has_ts(&sa_p);
		for (n = 0; n < FL_SPOOFERS; n++)
			count += has_ts(&sa_spoof[n]);
		lwsl_user("%d sequencers after the flood\n", count);
		if (count < FL_MAX_TS) {
			lwsl_err("the flood did not fill the table\n");
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
		 * P's takes a second message, and each of these takes one of
		 * the others...
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
			if (fl_chunk(wsi_hold[n], n, NULL))
				return -1;
		lws_sul_schedule(cx, 0, &sul_dup, dup_cb, FL_DUP_US);
		state++;
		return 0;

	case FL_HOLD:
		if (fl.held != FL_HOLDERS)
			return 0;
		lwsl_user("%d peers hold proven sessions\n", fl.held);
		hold_time = lws_now_usecs();
		if (fl_chunk(wsi_new[0], FL_HOLDERS, NULL))
			return -1;
		state++;
		return 0;

	case FL_PROTECT:
		if (lws_now_usecs() - hold_time < FL_PROTECT_US)
			return 0;
		if (fl.new_ch[0]) {
			lwsl_err("a newcomer took the slot of a session that "
				 "just had data\n");
			return -1;
		}
		lwsl_user("newcomer refused while the sessions had data\n");
		state++;
		return 0;

	case FL_GRACE:
		if (lws_now_usecs() - hold_time < FL_GRACE_US)
			return 0;
		if (fl_chunk(wsi_new[1], FL_HOLDERS + 1, NULL))
			return -1;
		flood_time = lws_now_usecs();
		state++;
		return 0;

	case FL_NEWCOMER:
		if (!fl.new_ch[1]) {
			if (lws_now_usecs() - flood_time < LWS_US_PER_SEC)
				return 0;
			lwsl_err("sessions only resending still hold every "
				 "slot\n");
			return -1;
		}
		lwsl_user("newcomer challenged after the sessions went "
			  "idle\n");
		fl_silent(FL_MAX_TS, &sin);
		if (lws_dht_send_data(dht, (struct sockaddr *)&sin, msg,
				      sizeof(msg)) != LWS_DHT_SEND_QUEUED) {
			lwsl_err("send to a new peer refused\n");
			return -1;
		}
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

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	static const struct lws_protocols protocols[] = {
		{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
		{ "fl-peer", cb_peer, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	int port_dht = 0, port_p = 0, n = 0;
#if defined(WIN32)
	int slen;
#else
	socklen_t slen;
#endif
	struct lws_vhost *vh;
	lws_dht_info_t di;
	uint8_t idb[20];
	const char *p;

	lws_context_info_defaults(&info, NULL);
	/* the 70 forging sockets need more fds than a client's default */
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
		wsi_spoof[n] = lws_create_adopt_udp(vh, n & 1 ? "127.0.0.3" :
							       "127.0.0.2", 0,
						    LWS_CAUDP_BIND,
						    protocols[1].name, NULL,
						    NULL, NULL, NULL,
						    "fl-spoof");
		slen = sizeof(sa_spoof[n]);
		if (!wsi_spoof[n] ||
		    getsockname(lws_get_socket_fd(wsi_spoof[n]),
				(struct sockaddr *)&sa_spoof[n], &slen) ||
		    sa_spoof[n].sin_family != AF_INET ||
		    !sa_spoof[n].sin_port) {
			lwsl_err("raw udp socket %d creation failed\n", n);
			goto bail;
		}
	}

	/* the holders, 16 to a loopback address, and the newcomers */
	for (n = 0; n < FL_HOLDERS + 2; n++) {
		char ads[16];
		struct lws *w;

		lws_snprintf(ads, sizeof(ads), "127.0.0.%d",
			     n < FL_HOLDERS ? 4 + (n & 3) : 8 + n - FL_HOLDERS);
		w = lws_create_adopt_udp(vh, ads, 0, LWS_CAUDP_BIND,
					 protocols[1].name, NULL, NULL, NULL,
					 NULL, "fl-hold");
		if (!w) {
			lwsl_err("raw udp socket creation failed\n");
			goto bail;
		}
		if (n < FL_HOLDERS)
			wsi_hold[n] = w;
		else
			wsi_new[n - FL_HOLDERS] = w;
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
