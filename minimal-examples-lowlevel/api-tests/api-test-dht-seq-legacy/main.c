/*
 * lws-api-test-dht-seq-legacy
 *
 * Released lws v5.0.0 sends its reliable-transport chunks with the fixed tid
 * "sqnc", and takes any reply whose tid is 4 bytes long and starts "sq" (or
 * "da") as an ack of its sequencer to that endpoint: one with no offset as an
 * ack of everything.  It then frees its data and reports the transfer as
 * delivered.  An updated node takes nothing of a receive session until a
 * chunk answers its challenge (G-204), which v5.0.0 cannot do; if it
 * answered v5.0.0's chunk with a challenge echoing "sqnc", v5.0.0 would read
 * that as an ack of all it sent while nothing was received (G-213).
 *
 * A plain UDP socket L plays a v5.0.0 node sending DHT B a message, and runs
 * everything B sends it through v5.0.0's reply parsing, reproduced here
 * (parse_message() and the DHT_REPLY dispatch of lws_dht_process_packet() in
 * lib/misc/dht/dht-bencode.c of v5.0.0):
 *
 *  - L sends B a v5.0.0 chunk, as v5.0.0 lays it out, three times, as its
 *    retransmits would, and v5.0.0-shaped chunks with other 4-byte tids a
 *    spoofer might use ("sqAB", "daXY").  B must take none of them, and
 *    must send nothing that v5.0.0 would read as an ack
 *
 *  - then L sends B the same message as an updated node does, with a
 *    session tid "sq" + nonce: B challenges it, L answers, and B delivers
 *    the message and acks it.  This shows B was listening all along, and
 *    those replies too must be nothing v5.0.0 would take as an ack
 *
 * The UDP ports are allocated uniquely at build time and passed in on the
 * command line, so parallel ctest instances do not collide.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define SL_POLL_US		(100 * LWS_US_PER_MS)
#define SL_DEADLINE_US		(10 * LWS_US_PER_SEC)
/* polls between v5.0.0's retransmits, and to let B answer the last */
#define SL_GAP_POLLS		3

#define SL_CH_LEN		8
#define SL_SESSION_TID		"sqLLLLLLLL"
#define SL_ID_L			"77777777777777777777"

static struct lws_context *cx;
static struct lws_dht_ctx *dht_b;
static struct lws *wsi_l;
static struct sockaddr_in sa_b;
static lws_sorted_usec_list_t sul_poll, sul_deadline;
static int retcode = 1;

static const char *leg_msg = "LEG 0102030405 0 0 ";
static const char *sl_verbs[] = { "LEG" };

/* the 4-byte tids of the v5.0.0-shaped chunks: v5.0.0's own, then forgeries */
static const char *legacy_tids[] = { "sqnc", "sqnc", "sqnc", "sqAB", "daXY" };

static struct {
	int		state;
	int		polls;
	int		next_legacy;
	int		delivered_legacy;	/* B's handler, legacy phase */
	int		delivered;		/* ...and for the session */
	int		replies_legacy;		/* datagrams B sent L, legacy */
	int		replies;		/* ...and for the session */
	int		v5_acks;		/* v5.0.0 would take as an ack */
	int		v5_ack_all;		/* ...of everything */
	unsigned int	ch_set:1;
	unsigned int	session_acked:1;
	uint8_t		ch[SL_CH_LEN];
} sl;

/*
 * v5.0.0's bencode walking, enough to judge what it makes of a reply:
 * dht_bencode_skip(), dht_bencode_find_key(), dht_bencode_get_string() and
 * dht_bencode_get_int() at v5.0.0
 */

static int
v5_uint(const uint8_t *p, const uint8_t *end, uint64_t *v, const uint8_t **pq)
{
	*v = 0;
	if (p >= end || *p < '0' || *p > '9')
		return -1;
	while (p < end && *p >= '0' && *p <= '9') {
		if (*v > (UINT64_MAX - 9) / 10)
			return -1;
		*v = (*v * 10) + (uint64_t)(*p++ - '0');
	}
	*pq = p;

	return 0;
}

static int
v5_skip(const uint8_t **pp, const uint8_t *end, int depth)
{
	const uint8_t *p = *pp, *q;
	uint64_t l;

	if (p >= end || depth > 32)
		return -1;

	switch (*p) {
	case 'i':
		while (p < end && *p != 'e')
			p++;
		if (p >= end)
			return -1;
		*pp = p + 1;
		return 0;
	case 'l':
	case 'd':
		p++;
		while (p < end && *p != 'e')
			if (v5_skip(&p, end, depth + 1))
				return -1;
		if (p >= end)
			return -1;
		*pp = p + 1;
		return 0;
	}

	if (v5_uint(p, end, &l, &q) || q >= end || *q != ':' ||
	    l > (uint64_t)(end - q - 1))
		return -1;
	*pp = q + 1 + l;

	return 0;
}

static const uint8_t *
v5_find_key(const uint8_t *p, const uint8_t *end, const char *key,
	    size_t *vlen)
{
	size_t klen = strlen(key);
	const uint8_t *q, *v;
	uint64_t l;

	if (p >= end || *p != 'd')
		return NULL;
	p++;

	while (p < end && *p != 'e') {
		if (v5_uint(p, end, &l, &q) || q >= end || *q != ':' ||
		    l > (uint64_t)(end - q - 1))
			return NULL;
		p = q + 1;
		v = p + l;
		if (v5_skip(&v, end, 0))
			return NULL;
		if (l == klen && !memcmp(p, key, klen)) {
			*vlen = (size_t)(v - (p + l));
			return p + l;
		}
		p = v;
	}

	return NULL;
}

static const uint8_t *
v5_get_string(const uint8_t *dict, const uint8_t *end, const char *key,
	      size_t *len)
{
	const uint8_t *p, *q;
	size_t vlen;
	uint64_t l;

	p = v5_find_key(dict, end, key, &vlen);
	if (!p || v5_uint(p, p + vlen, &l, &q) || q >= p + vlen || *q != ':')
		return NULL;
	*len = (size_t)l;

	return q + 1;
}

static int
v5_get_int(const uint8_t *dict, const uint8_t *end, const char *key,
	   uint64_t *v)
{
	const uint8_t *p, *q;
	size_t vlen;

	p = v5_find_key(dict, end, key, &vlen);
	if (!p || *p != 'i')
		return -1;

	return v5_uint(p + 1, p + vlen, v, &q);
}

/*
 * What v5.0.0 does with a datagram from B, the endpoint it has a sequencer
 * for: 1 and the offset it would take as acked if it is a sequencer ack,
 * else 0.  v5.0.0 keeps tids shorter than 16 bytes; drops a reply whose tid
 * is not 4 or 16 bytes long (16 is a notify ack), or that names no id; and
 * takes a 4-byte tid starting "sq" or "da" that is none of its request
 * replies' as an ack of offset + len, the offset ~0 if absent.
 */

static int
v5_is_seq_ack(const uint8_t *buf, size_t len, uint64_t *acked)
{
	static const char *not_acks[] = { "pn", "nt", "ip", "fn", "gp", "ap" };
	const uint8_t *end = buf + len, *t, *y, *r, *id;
	uint64_t offset = UINT64_MAX, l = 0;
	size_t tl = 0, yl, rl, il;
	unsigned int n;

	if (len < 2 || buf[0] != 'd')
		return 0;

	t = v5_get_string(buf, end, "t", &tl);
	if (!t || !tl || tl >= 16)
		tl = 0;

	y = v5_get_string(buf, end, "y", &yl);
	if (!y || yl != 1 || *y != 'r')
		return 0;

	r = v5_find_key(buf, end, "r", &rl);
	if (!r || *r != 'd')
		return 0;

	id = v5_get_string(r, r + rl, "id", &il);
	if (!id || !il)
		return 0;

	/* v5.0.0 leaves a missing offset at ~0, and a missing len at 0 */
	if (v5_find_key(r, r + rl, "offset", &il) &&
	    v5_get_int(r, r + rl, "offset", &offset))
		offset = 0;
	if (v5_get_int(r, r + rl, "len", &l))
		l = 0;

	if (tl != 4)
		return 0;

	for (n = 0; n < LWS_ARRAY_SIZE(not_acks); n++)
		if (t[0] == not_acks[n][0] && t[1] == not_acks[n][1])
			return 0;

	if (!(t[0] == 's' && t[1] == 'q') && !(t[0] == 'd' && t[1] == 'a'))
		return 0;

	*acked = offset + l; /* v5.0.0's own sum, which wraps */

	return 1;
}

/* B's handler for its verb: delivery of L's message */

static int
cb_sl_verbs(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	if (reason != LWS_CALLBACK_DHT_VERB_DISPATCH || !in)
		return 0;

	((struct lws_dht_verb_dispatch_args *)in)->out_precedence =
						LWS_DHT_VERB_RESULT_PROCEED;
	if (sl.state < 2)
		sl.delivered_legacy++;
	else
		sl.delivered++;

	return 0;
}

static void
cb_b(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	/* B's part is in its verb handler, its other dht events don't matter */
}

static ssize_t
sl_find(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle), n;

	for (n = 0; n + nl <= len; n++)
		if (!memcmp(buf + n, needle, nl))
			return (ssize_t)n;

	return -1;
}

static void
sl_sendto(const void *buf, size_t len)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi_l);
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
 * A chunk of L's message at offset 0: with a v5.0.0 tid, laid out as
 * v5.0.0's dht_tx_chunk() does, or with the session tid as an updated node
 * does, carrying B's challenge once B asked for it
 */

static void
sl_send_chunk(const char *tid, const uint8_t *ch)
{
	char q[256];
	size_t o = 5;
	int n;

	memcpy(q, "d1:ad", 5);
	if (ch) {
		memcpy(q + o, "2:ch8:", 6);
		memcpy(q + o + 6, ch, SL_CH_LEN);
		o += 6 + SL_CH_LEN;
	}

	n = lws_snprintf(q + o, sizeof(q) - o, "4:data%u:%s2:id20:%s"
			 "3:leni%ue6:offseti0ee1:q4:data1:t%u:%s1:y1:qe",
			 (unsigned int)strlen(leg_msg), leg_msg, SL_ID_L,
			 (unsigned int)strlen(leg_msg),
			 (unsigned int)strlen(tid), tid);
	if (n <= 0 || (size_t)n >= sizeof(q) - o - 1)
		return;

	sl_sendto(q, o + (size_t)n);
}

static int
cb_peer(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	void *in, size_t len)
{
	const struct lws_udp *udp;
	const uint8_t *buf = (const uint8_t *)in;
	uint64_t acked;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	udp = lws_get_udp(wsi);
	if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
	    udp->sa46.sa4.sin_port != sa_b.sin_port)
		return 0;

	if (sl.state < 2)
		sl.replies_legacy++;
	else
		sl.replies++;

	if (v5_is_seq_ack(buf, len, &acked)) {
		lwsl_err("%s: v5.0.0 would take this as an ack to %llu\n",
			 __func__, (unsigned long long)acked);
		lwsl_hexdump_err(buf, len);
		sl.v5_acks++;
		if (acked >= strlen(leg_msg))
			sl.v5_ack_all++;
	}

	if (sl.state < 2)
		return 0;

	/* B's challenge to the session chunk: L answers it, once */

	if (!sl_find(buf, len, "d1:rd2:ch8:") && len >= 11 + SL_CH_LEN &&
	    sl_find(buf, len, "e1:t10:" SL_SESSION_TID "1:y1:re") > 0) {
		if (!sl.ch_set) {
			memcpy(sl.ch, buf + 11, SL_CH_LEN);
			sl.ch_set = 1;
			sl_send_chunk(SL_SESSION_TID, sl.ch);
		}
		return 0;
	}

	/* B's ack of the session's chunk */

	if (!sl_find(buf, len, "d1:rd") &&
	    sl_find(buf, len, "e1:t10:" SL_SESSION_TID "1:y1:re") > 0)
		sl.session_acked = 1;

	return 0;
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	switch (sl.state) {
	case 0: /* L's v5.0.0 chunk and its retransmits, then the forgeries */
		if (sl.polls++ % SL_GAP_POLLS)
			break;
		if (sl.next_legacy < (int)LWS_ARRAY_SIZE(legacy_tids)) {
			sl_send_chunk(legacy_tids[sl.next_legacy++], NULL);
			break;
		}
		sl.state++;
		sl.polls = 0;
		break;

	case 1: /* let B answer whatever it is going to */
		if (sl.polls++ < SL_GAP_POLLS)
			break;
		sl.state++;
		sl.polls = 0;
		sl_send_chunk(SL_SESSION_TID, NULL);
		break;

	case 2: /* the session: challenge, answer, delivery and ack */
		if (sl.delivered && sl.session_acked) {
			retcode = 0;
			lws_default_loop_exit(cx);
			return;
		}
		break;
	}

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SL_POLL_US);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out\n", __func__);
	retcode = 1;
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
		{ "sl-peer", cb_peer, 0, 0, 0, NULL, 0 },
		{ "sl-verbs", cb_sl_verbs, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	struct lws_vhost *vh;
	lws_dht_info_t di;
	uint8_t idb[20];
	int port_b = 0, port_l = 0, n = 0;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-b")))
		port_b = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-l")))
		port_l = atoi(p);

	if (port_b < 1 || port_b > 65535 || port_l < 1 || port_l > 65535 ||
	    port_b == port_l) {
		lwsl_err("usage: --port-b <udp port> --port-l <udp port>\n");
		return 1;
	}

	lwsl_user("LWS API selftest: dht sequencer vs v5.0.0 senders\n");

	signal(SIGINT, sigint_handler);

	memset(&sa_b, 0, sizeof(sa_b));
	sa_b.sin_family = AF_INET;
	sa_b.sin_port = htons((uint16_t)port_b);
	sa_b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "dht-sl-b";
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
	di.name			= "sl-b";
	di.port			= port_b;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_b = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}
	if (!dht_b ||
	    lws_dht_register_verbs(dht_b, sl_verbs,
				   (int)LWS_ARRAY_SIZE(sl_verbs),
				   &protocols[2])) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	wsi_l = lws_create_adopt_udp(vh, "127.0.0.1", port_l, LWS_CAUDP_BIND,
				     protocols[1].name, NULL, NULL, NULL, NULL,
				     "sl-l");
	if (!wsi_l) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, SL_DEADLINE_US);
	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SL_POLL_US);

	while (n >= 0)
		n = lws_service(cx, 0);

	lwsl_user("v5.0.0 chunks: B delivered %d, sent %d datagrams; "
		  "session: delivered %d, sent %d, acked %d; v5.0.0 would "
		  "take %d as acks, %d of everything\n", sl.delivered_legacy,
		  sl.replies_legacy, sl.delivered, sl.replies,
		  sl.session_acked, sl.v5_acks, sl.v5_ack_all);

	if (sl.delivered_legacy || sl.replies_legacy) {
		lwsl_err("B answered or took v5.0.0-shaped chunks\n");
		retcode = 1;
	}
	if (sl.v5_acks) {
		lwsl_err("B sent what v5.0.0 reads as an ack of data B never "
			 "took\n");
		retcode = 1;
	}
	if (sl.delivered != 1 || !sl.session_acked) {
		lwsl_err("B did not take the session's chunk\n");
		retcode = 1;
	}

	lwsl_user("Completed: %s\n", retcode ? "FAIL" : "PASS");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	return retcode;
}
