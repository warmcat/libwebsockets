/*
 * lws-api-test-dht-seq-reentry
 *
 * The DHT's reliable transport calls back into its consumer, and what the
 * consumer does there can make the DHT recycle sequencers: it keeps at most
 * 64 (LWS_DHT_MAX_TS), and making one more destroys the least recently used.
 * This checks the sequencer calling back is never the one destroyed, and
 * nothing uses it after the callback if it could have been (G-181):
 *
 *  - a plain UDP socket Q sends DHT B a chunk with the verb "FAN".  B's
 *    handler for it sends to 64 endpoints B has no sequencer for, so B
 *    makes 64, which is enough to recycle every sequencer it had, including
 *    the one delivering Q's chunk.  B must not free that one under its own
 *    delivery: Q's chunk is acked with Q's tid and its full length
 *
 *  - none of those 64 endpoints answer, so B's sends to them fail.  When
 *    the first one is reported failed, B's event callback sends to 64 more
 *    new endpoints.  The sequencer reporting its failure must survive that,
 *    to be destroyed once, by the DHT, after the callback
 *
 * Run under ASan, the old behaviour shows as a heap use-after-free (or a
 * double free) inside the DHT.
 *
 * It also checks what a peer that has not proven its address can make B
 * send (G-182):
 *
 *  - a second socket R, a stranger to B, sends B 16 small chunks with the
 *    verb "BIG", each of which B's handler answers with a 1KB reply.  R's
 *    source address could be forged, so until R acks something B must not
 *    send it more than its first reply and a small allowance beyond what R
 *    sent.  Once R acks that reply, B sends the rest, and R's acks of all of
 *    it complete B's transfer
 *
 * and that a receive session must be proven before B takes anything from it
 * (G-204):
 *
 *  - B challenges the first chunk of every new session, Q's and R's
 *    included: they send their chunks again carrying B's challenge, which
 *    only reaches the real sender's address
 *
 *  - B sends a third socket V a message, so B's sequencer for V is one it
 *    made to send, and starts out proven, and V acks it.  Then chunks
 *    claiming to be from V, with a session tid of their own and no answer to
 *    B's challenge, as a blind spoofer of V's address would send, ask for
 *    BIG replies.  B must not take them: its handler is never called for
 *    them, and V gets nothing from B but challenges
 *
 * The UDP ports are allocated uniquely at build time and passed in on the
 * command line, so parallel ctest instances do not collide.  Nothing
 * listens on the fan-out port, at 127.0.0.2.. and 127.0.1.2..
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define SR_POLL_US	(50 * LWS_US_PER_MS)
#define SR_DEADLINE_US	(15 * LWS_US_PER_SEC)

/* LWS_DHT_MAX_TS: enough new sequencers to recycle every one B has */
#define SR_FANOUT	64
/* polls to let the second fan-out's sequencers fail and be destroyed */
#define SR_SETTLE_POLLS	40

#define SR_Q_TID	"sqQQQQQQQQ"
#define SR_R_TID	"sqRRRRRRRR"
#define SR_V_TID	"sqVVVVVVVV"	/* a spoofer's, from V's address */

/* B's session challenge ("ch"), as its reply to a chunk carries it */
#define SR_CH_LEN	8
/* the forged requests from V's address */
#define SR_V_COUNT	4

/* R's requests, and the size of B's answer to each */
#define SR_BIG_COUNT	16
#define SR_BIG_PAYLOAD	1000
/* what B may send unproven R beyond one reply and what R sent: 2KB */
#define SR_R_ALLOWANCE	2048

static struct lws_context *cx;
static struct lws_dht_ctx *dht_b;
static struct lws *wsi_q, *wsi_r, *wsi_v;
static struct sockaddr_in sa_b, sa_r, sa_v;
static lws_sorted_usec_list_t sul_poll, sul_deadline;
static int port_fan, retcode = 1;

static const char *fan_msg = "FAN 0102030405 0 0 ";
static const char *big_msg = "BIG 0102030405 0 0 ";
static const char *nop_msg = "NOP 0102030405 0 0 ";
static const char *sr_verbs[] = { "FAN", "BIG" };

static struct {
	int		fanned;		/* B's FAN handler sent to this many */
	int		fanned2;	/* ...and its WRITE_FAILED handler */
	int		settle;
	unsigned int	q_sent:1;	/* Q sent B its FAN chunk */
	unsigned int	q_acked:1;	/* ...B acked it, whole, with Q's tid */
	unsigned int	q_bad:1;	/* ...or acked something else */
	unsigned int	q_ch_set:1;	/* B challenged Q's chunk */
	uint8_t		q_ch[SR_CH_LEN];
	unsigned int	failed:1;	/* a fan-out send was reported failed */

	int		r_state;
	lws_usec_t	r_t;
	size_t		r_sent;		/* bytes of requests R sent B */
	size_t		r_got;		/* bytes of B's replies R got */
	size_t		r_got_unproven;	/* ...before R acked anything */
	size_t		reply_len;	/* each of B's replies */
	uint32_t	r_offsets;	/* bitmap of B's replies R got */
	uint8_t		b_tid[16];	/* the tid of B's chunks to R */
	size_t		b_tid_len;
	unsigned int	r_bad:1;	/* B's chunks to R were not as expected */
	unsigned int	r_completed:1;	/* R's acks completed B's transfer */
	unsigned int	r_ch_set:1;	/* B challenged R's chunks */
	uint8_t		r_ch[SR_CH_LEN];

	int		v_state;
	lws_usec_t	v_t;
	uint8_t		v_b_tid[16];	/* the tid of B's chunks to V */
	size_t		v_b_tid_len;
	int		v_big;		/* B's handler took a BIG from V */
	int		v_challenged;	/* B challenged the forged chunks */
	size_t		v_got;		/* bytes B sent V beyond its message */
} sr;

/* the endpoint of the i-th fan-out target of set s, nobody listens there */

static void
sr_fan_target(struct sockaddr_in *sin, int set, int i)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_port = htons((uint16_t)port_fan);
	sin->sin_addr.s_addr = htonl((uint32_t)((127u << 24) | ((unsigned int)set << 8) |
				     (2u + (unsigned int)i)));
}

static int
sr_fanout(struct lws_dht_ctx *ctx, int set)
{
	static const char msg[] = "NOP 0102030405 0 0 ";
	struct sockaddr_in sin;
	int i, n = 0;

	for (i = 0; i < SR_FANOUT; i++) {
		sr_fan_target(&sin, set, i);
		if (!lws_dht_send_data(ctx, (const struct sockaddr *)&sin,
				       msg, sizeof(msg) - 1))
			n++;
	}

	return n;
}

/* B's handler for the verbs it registered */

static int
cb_sr_verbs(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct lws_dht_verb_dispatch_args *args =
				(struct lws_dht_verb_dispatch_args *)in;

	if (reason != LWS_CALLBACK_DHT_VERB_DISPATCH || !args)
		return 0;

	args->out_precedence = LWS_DHT_VERB_RESULT_PROCEED;

	if (!strcmp(args->msg->verb, "FAN"))
		sr.fanned = sr_fanout(args->ctx, 0);

	if (!strcmp(args->msg->verb, "BIG")) {
		/* a reply much bigger than the request */
		char rsp[64 + SR_BIG_PAYLOAD];
		int n;

		/* nowhere to send the reply */
		if (!args->from)
			return 0;

		if (args->from->sa_family == AF_INET &&
		    ((const struct sockaddr_in *)args->from)->sin_port ==
								sa_v.sin_port)
			sr.v_big++;

		n = lws_dht_msg_gen(rsp, sizeof(rsp) - SR_BIG_PAYLOAD, "RSP",
				    args->msg->hash, 0, SR_BIG_PAYLOAD);
		if (n <= 0)
			return 0;
		memset(rsp + n, 'x', SR_BIG_PAYLOAD);
		sr.reply_len = (size_t)n + SR_BIG_PAYLOAD;
		lws_dht_send_data(args->ctx, args->from, rsp, sr.reply_len);
	}

	return 0;
}

/* B's DHT events */

static void
cb_b(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	if (event == LWS_DHT_EVENT_WRITE_COMPLETED && from &&
	    from->sa_family == AF_INET &&
	    ((const struct sockaddr_in *)from)->sin_port == sa_r.sin_port) {
		sr.r_completed = 1;
		return;
	}

	if (event != LWS_DHT_EVENT_WRITE_FAILED || sr.failed)
		return;

	/* the first fan-out send has failed: fan out again from here */
	sr.failed = 1;
	sr.fanned2 = sr_fanout(dht_b, 1);
}

static ssize_t
sr_find(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle), n;

	for (n = 0; n + nl <= len; n++)
		if (!memcmp(buf + n, needle, nl))
			return (ssize_t)n;

	return -1;
}

/* the bencode integer following key, eg "6:offseti", or -1 */

static int64_t
sr_int(const uint8_t *buf, size_t len, const char *key)
{
	ssize_t at = sr_find(buf, len, key);
	int64_t v = 0;
	size_t n;

	if (at < 0)
		return -1;

	for (n = (size_t)at + strlen(key); n < len && buf[n] != 'e'; n++) {
		if (buf[n] < '0' || buf[n] > '9' || v > 0x7fffffffffffll / 10)
			return -1;
		v = (v * 10) + (buf[n] - '0');
	}

	return n < len ? v : -1;
}

static void
sr_sendto(struct lws *wsi, const void *buf, size_t len)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi);
	ssize_t n;

	if (fd == LWS_SOCK_INVALID)
		return;

	n = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   buf,
#if defined(WIN32)
		   (int)
#endif
		   len, 0, (const struct sockaddr *)&sa_b, sizeof(sa_b));
	if (n != (ssize_t)len)
		lwsl_err("%s: sendto returned %d\n", __func__, (int)n);
}

/*
 * a data chunk to B: d1:ad[2:ch..]4:data..2:id..3:len..6:offset..e1:q4:data
 * 1:t.., carrying B's challenge ch once B asked for it
 */

static size_t
sr_send_chunk(struct lws *wsi, const char *id, const char *tid,
	      uint64_t offset, const char *msg, const uint8_t *ch)
{
	char q[256];
	size_t o = 5;
	int n;

	memcpy(q, "d1:ad", 5);
	if (ch) {
		memcpy(q + o, "2:ch8:", 6);
		memcpy(q + o + 6, ch, SR_CH_LEN);
		o += 6 + SR_CH_LEN;
	}

	n = lws_snprintf(q + o, sizeof(q) - o, "4:data%u:%s2:id20:%s"
			 "3:leni%ue6:offseti%lluee1:q4:data1:t%u:%s1:y1:qe",
			 (unsigned int)strlen(msg), msg, id,
			 (unsigned int)strlen(msg), (unsigned long long)offset,
			 (unsigned int)strlen(tid), tid);
	if (n <= 0 || (size_t)n >= sizeof(q) - o - 1)
		return 0;

	sr_sendto(wsi, q, o + (size_t)n);

	return strlen(msg);
}

/* a raw peer's ack of B's chunks below offset, echoing their tid */

static void
sr_send_ack(struct lws *wsi, const uint8_t *tid, size_t tid_len,
	    uint64_t offset)
{
	char q[160];
	int n;

	n = lws_snprintf(q, sizeof(q), "d1:rd2:id20:55555555555555555555"
			 "3:leni0e6:offseti%llue" "e1:t%u:",
			 (unsigned long long)offset, (unsigned int)tid_len);
	if (n <= 0 || (size_t)n + tid_len + 7 > sizeof(q))
		return;

	memcpy(q + n, tid, tid_len);
	memcpy(q + (size_t)n + tid_len, "1:y1:re", 7);

	sr_sendto(wsi, q, (size_t)n + tid_len + 7);
}

static void
sr_r_send_ack(uint64_t offset)
{
	sr_send_ack(wsi_r, sr.b_tid, sr.b_tid_len, offset);
}

/*
 * B's challenge to a chunk with tid: d1:rd2:ch8:<ch>2:id..e1:t<tid>1:y1:re.
 * Copies the challenge out, or returns -1 if this is not one.
 */

static int
sr_challenge(const uint8_t *buf, size_t len, const char *tid, uint8_t *ch)
{
	char t[32];

	if (sr_find(buf, len, "d1:rd2:ch8:") != 0 || len < 11 + SR_CH_LEN)
		return -1;

	lws_snprintf(t, sizeof(t), "e1:t%u:%s1:y1:re",
		     (unsigned int)strlen(tid), tid);
	if (sr_find(buf, len, t) < 0)
		return -1;

	memcpy(ch, buf + 11, SR_CH_LEN);

	return 0;
}

/* R's requests from offset 0 to what it sent, carrying ch if set */

static void
sr_r_send_requests(const uint8_t *ch)
{
	size_t sent = 0;
	int n;

	for (n = 0; n < SR_BIG_COUNT; n++)
		sent += sr_send_chunk(wsi_r, "55555555555555555555", SR_R_TID,
				      sent, big_msg, ch);
	sr.r_sent = sent;
}

/*
 * A chunk of B's to R: ...e1:q4:data1:t<len>:<tid>1:y1:qe.  Copies the tid
 * out, or returns -1 if this is not a chunk.
 */

static int
sr_chunk_tid(const uint8_t *buf, size_t len, uint8_t *tid, size_t *tid_len)
{
	ssize_t at = sr_find(buf, len, "1:q4:data1:t");
	size_t n, l = 0;

	if (at < 0)
		return -1;

	for (n = (size_t)at + 12; n < len && buf[n] >= '0' && buf[n] <= '9'; n++)
		l = (l * 10) + (size_t)(buf[n] - '0');

	if (n >= len || buf[n] != ':' || !l || l > 16 || n + 1 + l > len)
		return -1;

	memcpy(tid, buf + n + 1, l);
	*tid_len = l;

	return 0;
}

static void
sr_r_rx(const uint8_t *in, size_t len)
{
	int64_t off = sr_int(in, len, "6:offseti"),
		clen = sr_int(in, len, "3:leni");
	uint8_t tid[16];
	size_t tid_len;
	uint32_t bit;

	if (!sr_challenge(in, len, SR_R_TID, sr.r_ch)) {
		/* the first time, R sends its requests again, answering it */
		if (!sr.r_ch_set) {
			sr.r_ch_set = 1;
			sr_r_send_requests(sr.r_ch);
		}
		return;
	}

	if (sr_chunk_tid(in, len, tid, &tid_len))
		return; /* B's acks of R's chunks */

	if (!sr.reply_len || off < 0 || clen != (int64_t)sr.reply_len ||
	    off % (int64_t)sr.reply_len ||
	    off / (int64_t)sr.reply_len >= SR_BIG_COUNT ||
	    (sr.b_tid_len && (tid_len != sr.b_tid_len ||
			      memcmp(tid, sr.b_tid, tid_len)))) {
		lwsl_err("%s: unexpected chunk from B\n", __func__);
		sr.r_bad = 1;
		return;
	}

	if (!sr.b_tid_len) {
		memcpy(sr.b_tid, tid, tid_len);
		sr.b_tid_len = tid_len;
	}

	bit = 1u << (off / (int64_t)sr.reply_len);
	if (sr.r_offsets & bit)
		return; /* a retransmit */

	sr.r_offsets |= bit;
	sr.r_got += (size_t)clen;
	if (sr.r_state < 2)
		sr.r_got_unproven += (size_t)clen;
}

/*
 * What B sends V: its message, which V acks, and challenges to the forged
 * chunks.  Anything else is B answering the forgeries.
 */

static void
sr_v_rx(const uint8_t *in, size_t len)
{
	int64_t off = sr_int(in, len, "6:offseti"),
		clen = sr_int(in, len, "3:leni");
	uint8_t tid[16], ch[SR_CH_LEN];
	size_t tid_len;

	if (!sr_challenge(in, len, SR_V_TID, ch)) {
		sr.v_challenged++;
		return;
	}

	if (sr_chunk_tid(in, len, tid, &tid_len))
		return; /* B's acks: there are none, it took nothing */

	if (!off && clen == (int64_t)strlen(nop_msg)) {
		/* B's message: V acks it, as its own sequencer would */
		memcpy(sr.v_b_tid, tid, tid_len);
		sr.v_b_tid_len = tid_len;
		sr_send_ack(wsi_v, tid, tid_len, (uint64_t)clen);
		return;
	}

	sr.v_got += clen > 0 ? (size_t)clen : 0;
}

/* B sends V something, then V's address is used to ask B for more */

static int
sr_v_step(void)
{
	lws_usec_t now = lws_now_usecs();
	size_t sent = 0;
	int n;

	switch (sr.v_state) {
	case 0:
		if (lws_dht_send_data(dht_b, (const struct sockaddr *)&sa_v,
				      nop_msg, strlen(nop_msg))) {
			lwsl_err("%s: B could not send to V\n", __func__);
			return -1;
		}
		sr.v_t = now;
		sr.v_state++;
		break;

	case 1:
		if (!sr.v_b_tid_len) {
			if (now - sr.v_t > 2 * LWS_US_PER_SEC) {
				lwsl_err("%s: B's message never reached V\n",
					 __func__);
				return -1;
			}
			break;
		}

		/* a blind spoofer's requests, with V's address */
		for (n = 0; n < SR_V_COUNT; n++)
			sent += sr_send_chunk(wsi_v, "66666666666666666666",
					      SR_V_TID, sent, big_msg, NULL);
		sr.v_t = now;
		sr.v_state++;
		break;

	case 2:
		/* give B time to have answered all it is going to */
		if (now - sr.v_t < 300 * LWS_US_PER_MS)
			break;

		return 1;
	}

	return 0;
}

static int
cb_peer(struct lws *wsi, enum lws_callback_reasons reason, void *user,
     void *in, size_t len)
{
	const struct lws_udp *udp;
	char t[32];

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	udp = lws_get_udp(wsi);
	if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
	    udp->sa46.sa4.sin_port != sa_b.sin_port)
		return 0;

	if (wsi == wsi_r) {
		sr_r_rx(in, len);
		return 0;
	}

	if (wsi == wsi_v) {
		sr_v_rx(in, len);
		return 0;
	}

	/* B's challenge to Q's chunk: Q sends it again, answering it */

	if (!sr_challenge(in, len, SR_Q_TID, sr.q_ch)) {
		if (!sr.q_ch_set) {
			sr.q_ch_set = 1;
			sr_send_chunk(wsi_q, "44444444444444444444", SR_Q_TID,
				      0, fan_msg, sr.q_ch);
		}
		return 0;
	}

	/* an ack: d1:rd2:id..3:len..6:offset..e1:t<tid>1:y1:re */

	if (sr_find(in, len, "d1:rd") != 0 || sr_find(in, len, "6:offseti") < 0)
		return 0;

	lws_snprintf(t, sizeof(t), "e1:t%u:%s1:y1:re",
		     (unsigned int)strlen(SR_Q_TID), SR_Q_TID);

	if (sr_find(in, len, t) < 0 ||
	    sr_int(in, len, "6:offseti") != (int64_t)strlen(fan_msg)) {
		lwsl_err("%s: B's ack of Q's chunk is wrong\n", __func__);
		lwsl_hexdump_err(in, len);
		sr.q_bad = 1;
		return 0;
	}

	sr.q_acked = 1;

	return 0;
}

/* R asks B for more than it sends, then proves itself */

static int
sr_r_step(void)
{
	lws_usec_t now = lws_now_usecs();

	switch (sr.r_state) {
	case 0:
		sr_r_send_requests(NULL);
		sr.r_t = now;
		sr.r_state++;
		break;

	case 1:
		/* give B time to have answered all it is going to */
		if (now - sr.r_t < 300 * LWS_US_PER_MS)
			break;

		if (!sr.b_tid_len) {
			lwsl_err("%s: B never answered R\n", __func__);
			return -1;
		}

		/* prove R, by acking B's first reply */
		sr_r_send_ack(sr.reply_len);
		sr.r_t = now;
		sr.r_state++;
		break;

	case 2:
		if (sr.r_offsets != (1u << SR_BIG_COUNT) - 1) {
			if (now - sr.r_t > 2 * LWS_US_PER_SEC) {
				lwsl_err("%s: B did not send R the rest\n",
					 __func__);
				return -1;
			}
			break;
		}

		sr_r_send_ack((uint64_t)SR_BIG_COUNT * sr.reply_len);
		sr.r_t = now;
		sr.r_state++;
		break;

	case 3:
		if (sr.r_completed) {
			sr.r_state++;
			break;
		}
		if (now - sr.r_t > 2 * LWS_US_PER_SEC) {
			lwsl_err("%s: R's acks did not complete B's transfer\n",
				 __func__);
			return -1;
		}
		break;

	case 4:
		return sr_v_step();
	}

	return 0;
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	int n;

	if (!sr.q_sent) {
		sr_send_chunk(wsi_q, "44444444444444444444", SR_Q_TID, 0,
			      fan_msg, NULL);
		sr.q_sent = 1;
	}

	if (sr.q_acked && sr.fanned2 && sr.settle < SR_SETTLE_POLLS)
		sr.settle++;

	if (sr.settle >= SR_SETTLE_POLLS) {
		n = sr_r_step();
		if (n) {
			retcode = n < 0;
			lws_default_loop_exit(cx);
			return;
		}
	}

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SR_POLL_US);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out\n", __func__);
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
		{ "sr-peer", cb_peer, 0, 0, 0, NULL, 0 },
		{ "sr-verbs", cb_sr_verbs, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	struct lws_vhost *vh;
	lws_dht_info_t di;
	uint8_t idb[20];
	int port_b = 0, port_q = 0, port_r = 0, port_v = 0, n = 0;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-b")))
		port_b = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-q")))
		port_q = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-r")))
		port_r = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-v")))
		port_v = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-fan")))
		port_fan = atoi(p);

	if (port_b < 1 || port_b > 65535 || port_q < 1 || port_q > 65535 ||
	    port_r < 1 || port_r > 65535 || port_v < 1 || port_v > 65535 ||
	    port_fan < 1 || port_fan > 65535 || port_b == port_q ||
	    port_r == port_b || port_r == port_q ||
	    port_v == port_b || port_v == port_q || port_v == port_r ||
	    port_fan == port_b || port_fan == port_q || port_fan == port_r ||
	    port_fan == port_v) {
		lwsl_err("usage: --port-b <udp port> --port-q <udp port> "
			 "--port-r <udp port> --port-v <udp port> "
			 "--port-fan <unused udp port>\n");
		return 1;
	}

	lwsl_user("LWS API selftest: dht sequencer reentry\n");

	signal(SIGINT, sigint_handler);

	memset(&sa_b, 0, sizeof(sa_b));
	sa_b.sin_family = AF_INET;
	sa_b.sin_port = htons((uint16_t)port_b);
	sa_b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa_r = sa_b;
	sa_r.sin_port = htons((uint16_t)port_r);
	sa_v = sa_b;
	sa_v.sin_port = htons((uint16_t)port_v);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "dht-sr-b";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	memset(idb, 0x22, sizeof(idb));
	memset(&di, 0, sizeof(di));
	di.allow_private_ads	= 1; /* everything is on loopback */
	di.vhost		= vh;
	di.cb			= cb_b;
	di.name			= "sr-b";
	di.port			= port_b;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_b = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}
	if (!dht_b ||
	    lws_dht_register_verbs(dht_b, sr_verbs,
				   (int)LWS_ARRAY_SIZE(sr_verbs),
				   &protocols[2])) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	wsi_q = lws_create_adopt_udp(vh, "127.0.0.1", port_q, LWS_CAUDP_BIND,
				     protocols[1].name, NULL, NULL, NULL, NULL,
				     "sr-q");
	wsi_r = lws_create_adopt_udp(vh, "127.0.0.1", port_r, LWS_CAUDP_BIND,
				     protocols[1].name, NULL, NULL, NULL, NULL,
				     "sr-r");
	wsi_v = lws_create_adopt_udp(vh, "127.0.0.1", port_v, LWS_CAUDP_BIND,
				     protocols[1].name, NULL, NULL, NULL, NULL,
				     "sr-v");
	if (!wsi_q || !wsi_r || !wsi_v) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, SR_DEADLINE_US);
	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SR_POLL_US);

	while (n >= 0)
		n = lws_service(cx, 0);

	if (sr.fanned != SR_FANOUT) {
		lwsl_err("B's FAN handler sent to %d of %d\n", sr.fanned,
			 SR_FANOUT);
		retcode = 1;
	}
	if (!sr.q_acked || sr.q_bad) {
		lwsl_err("B did not ack Q's FAN chunk properly\n");
		retcode = 1;
	}
	if (sr.fanned2 != SR_FANOUT) {
		lwsl_err("B's WRITE_FAILED handler sent to %d of %d\n",
			 sr.fanned2, SR_FANOUT);
		retcode = 1;
	}
	lwsl_user("R sent B %u, got %u before acking, %u in all\n",
		  (unsigned int)sr.r_sent, (unsigned int)sr.r_got_unproven,
		  (unsigned int)sr.r_got);
	if (sr.r_got_unproven > sr.reply_len + sr.r_sent + SR_R_ALLOWANCE) {
		lwsl_err("B sent unproven R %u bytes for its %u\n",
			 (unsigned int)sr.r_got_unproven,
			 (unsigned int)sr.r_sent);
		retcode = 1;
	}
	if (sr.r_bad || !sr.r_completed ||
	    sr.r_got != SR_BIG_COUNT * sr.reply_len) {
		lwsl_err("B's transfer to R did not complete once R was "
			 "proven\n");
		retcode = 1;
	}

	lwsl_user("V: B's handler took %d forged requests, B challenged %d, "
		  "sent V %u bytes beyond its message\n", sr.v_big,
		  sr.v_challenged, (unsigned int)sr.v_got);
	if (sr.v_state != 2 || sr.v_big || sr.v_got || !sr.v_challenged) {
		lwsl_err("B took requests from an unproven session of V's\n");
		retcode = 1;
	}

	lwsl_user("Completed: %s\n", retcode ? "FAIL" : "PASS");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	return retcode;
}
