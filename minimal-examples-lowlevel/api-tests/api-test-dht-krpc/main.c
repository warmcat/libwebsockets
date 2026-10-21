/*
 * lws-api-test-dht-krpc
 *
 * Wire-level round-trip coverage for the DHT KRPC packet builders and
 * the bencode parser: DHT contexts on separate vhosts in this one
 * process exchange real datagrams over loopback UDP.
 *
 *  - a ping from A is answered by B's pong, so A's routing table gains B
 *    as a known-good node (rx_pong observed on A, rx_ping on B)
 *  - a subscribe request from A is answered by B through the same
 *    closest-nodes + token reply path a get_peers reply uses; A parses
 *    the cursor-built reply and the token surfaces as the
 *    LWS_DHT_EVENT_TOKEN callback, naming the hash A subscribed to
 *  - A returns that token in a subscribe_confirm with a 16-byte tid, so B
 *    registers A as a subscriber; B's notify reaches A, and A's ack (which
 *    echoes the 16-byte tid) clears B's pending notification, so notifying
 *    the same content again finds nothing to send.  A confirms twice, with
 *    different tids: that renews its one subscription, so B notifies once
 *  - lws_dht_foreach_node() shows B in A's table as good, at B's port,
 *    having answered A
 *  - A's neighbourhood maintenance issues a find_node to its only node
 *    within a few seconds (tx_find_node on A, rx_find_node on B)
 *  - a reliable-transport data datagram from A is reassembled by B's
 *    sequencer and delivered verbatim to B's event callback
 *  - a CAP_REQ from A over the same transport is answered by B's CAP_RSP,
 *    sent back over the sequencer B made for A when A spoke first
 *  - data A sends to a port nobody listens on is retransmitted until the
 *    retry policy runs out, and then reported as LWS_DHT_EVENT_WRITE_FAILED
 *  - once B is a good node for A, A probes it for A's external address:
 *    the probe's nonce survives the round trip, and in a two-node network
 *    the one other node is the quorum, so A learns 127.0.0.1:port-a from B
 *  - a third context C that uses B's node id pings A from its own port once
 *    B is good for A: A answers it, but B's entry keeps B's endpoint, so the
 *    good node A hands out for that id is still B, and A warns that the id
 *    is claimed from two places
 *  - a plain UDP socket R asks B a find_node with no target; B refuses it
 *    with a BEP 5 error reply, which must be exactly the bencode
 *    d1:eli203e<len>:<message>e1:t<tid>1:y1:ee.  R then relays B's refusal
 *    verbatim to A, as a peer refusing A would, and A's parser reports it as
 *    LWS_DHT_EVENT_ERROR with the code, message and tid, not as a drop
 *  - R then sends A replies to requests A never sent: a find_node reply
 *    whose nodes list names three made-up nodes, and a pong, both with the
 *    tids A's own maintenance uses.  Neither the nodes named nor R itself
 *    may enter A's routing table: only an answer to a request A sent to
 *    that endpoint may change it (G-119)
 *  - A sends R reliable data, and R answers its chunk with acks that claim
 *    it all: one with the fixed tid acks used to carry, and one with the
 *    wrong nonce.  Neither may complete the transfer, so A keeps
 *    retransmitting; only an ack echoing the chunk's tid for what was sent
 *    completes it (G-096).  (One echoing the tid but acking bytes A never
 *    sent gets R blacklisted: api-test-dht-seq-refuse checks that.)
 *  - R asks B for its capabilities, as a stranger B must not repeat itself
 *    to (answering B's challenge to its first chunk, see Q below), and acks
 *    B's answer with the fixed tid, as a spoofer naming R could.  That must
 *    not prove R to B: B's answer to R's second request goes out once, not
 *    once per retry (G-096, C-599)
 *  - A pings R, passing R's address in a sockaddr_storage with that
 *    struct's size as its length, as the announce in a search does.  The
 *    request must still be recorded, so R's pong is taken as the answer to
 *    it and R enters A's table (G-128).  It must also go out at all: BSD and
 *    macOS refuse to send to an address whose length isn't its family's.
 *  - A probes its good nodes, B and R, for its external address again, and
 *    R answers that A is at a multicast address.  That must not be counted:
 *    no vote may decide we are somewhere unroutable (G-095)
 *  - A searches for a target, and R answers A's get_peers with a nodes list
 *    naming 5 ids next to the target, all at one public address, three
 *    unusable endpoints (multicast, address 0, port 0) closer still, and B's
 *    id at another address.  At most two of the one host's ids may enter the
 *    search, none of the unusable endpoints, and B's candidate must stay at
 *    B: otherwise one host owns the lookup (G-123)
 *  - a third plain UDP socket R2, the attacker's second endpoint, pings A
 *    with an id next to a second target, and A searches for that target.
 *    Once B has answered, R and R2 answer too, each listing 9 made-up ids
 *    closer to the target than B, each at a public address of its own, so
 *    the per-host cap never applies.  Together they would push every other
 *    candidate out of the search's 14 slots, B included, though B replied,
 *    and once they time out the search would complete on R and R2 alone.
 *    B must still be a candidate, and each of R and R2 may have put in no
 *    more than the few unverified candidates one introducer may (G-158)
 *  - once A's subscription works, A confirms another hash with the token B
 *    gave it for the first: B must refuse it, since a token only buys the
 *    hash it was asked for.  Then A subscribes to six more hashes, each with
 *    its own token: B, made with a share of KRPC_SHARE hashes per source
 *    host, starts storage for only as many as are left of A's share
 *    (G-121)
 *  - a second plain UDP socket Q sends B a reliable stream whose chunks
 *    carry Q's session tid.  B takes nothing of a session until it is
 *    proven: Q's first chunk is challenged, and taken when Q sends it again
 *    carrying B's challenge (G-204).  A chunk at Q's next offset with
 *    another tid, as a blind spoofer would have to send, is not taken: B
 *    challenges it, and Q's own chunk at that offset is still delivered and
 *    acked with Q's tid (G-141).  B then sends Q more than Q sent B.  Q challenges B's chunk,
 *    and B, which repeats nothing to Q unproven, sends it again at once
 *    carrying Q's challenge, since answering B's session proves Q; Q acks
 *    it.  A repeat of Q's chunk is still acked at Q's offset, not at B's
 *    send progress (G-140).  Q restarts with a new tid from offset 0: B
 *    challenges it, refuses a wrong answer, and takes the right one as a new
 *    session from 0, after which the old tid is a stranger's (G-133).  A
 *    chunk Q sends past a gap in that session is delivered, and B's ack
 *    reports it as a SACK block, closing the block, the list and both
 *    dicts once each, so the ack is still one whole message.  B delivers
 *    each of Q's chunks exactly once and none of the others
 *
 * The UDP ports (six to listen on, one left unused) are allocated uniquely
 * at build time and passed in on the command line, so parallel ctest
 * instances do not collide.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define POLL_US		(100 * LWS_US_PER_MS)
#define DEADLINE_US	(15 * LWS_US_PER_SEC)

static struct lws_context *cx;
static struct lws_vhost *vh_a, *vh_b, *vh_c;
static struct lws_dht_ctx *dht_a, *dht_b, *dht_c;
static lws_sorted_usec_list_t sul_poll, sul_deadline;

static struct sockaddr_in sa_a, sa_b, sa_c, sa_r, sa_q, sa_dead;

static const char *data_msg = "PUT 0102030405 0 5 hello";
static const char *cap_req = "CAP_REQ 0102030405 0 0 ";
static size_t data_msg_len;

static uint8_t token[40];
static size_t token_len;

/*
 * R's raw KRPC: the query it asks B, the message B refuses it with, and the
 * one datagram R has waiting to go out and where to
 */
static const char raw_query_head[] = "d1:ad2:id20:";
static const char raw_query_tail[] = "e1:q9:find_node1:t2:aa1:y1:qe";
static const char err_msg[] = "find_node with no target";

/* a hand-driven KRPC peer: its socket and the one datagram it has queued */
struct raw_peer {
	struct lws		*wsi;
	uint8_t			tx[1024];
	size_t			tx_len;
	struct sockaddr_in	to;
};

/*
 * R, Q, the sender of a reliable stream to B, and R2, R's second endpoint in
 * the second search
 */
static struct raw_peer peer_r, peer_q, peer_r2;

struct seen {
	unsigned char token_ok:1;	/* A got B's get_peers token */
	unsigned char token_ih_bad:1;	/* ... for some other hash */
	unsigned char table_ok:1;	/* foreach shows B good in A's table */
	unsigned char confirmed:1;	/* A sent B its subscribe_confirm */
	unsigned char notified:1;	/* B sent A a notify */
	unsigned char notify_ok:1;	/* A got B's notify */
	unsigned char acked:1;		/* A's ack cleared B's pending notify */
	unsigned char dup_sub:1;	/* B notified A more than once */
	unsigned char data_ok:1;	/* B got A's data payload verbatim */
	unsigned char ping_sent:1;
	unsigned char searched:1;
	unsigned char data_sent:1;
	unsigned char cap_ok:1;		/* A got B's CAP_RSP */
	unsigned char dead_sent:1;	/* A sent data to the unused port */
	unsigned char dead_failed:1;	/* ...and was told it failed */
	unsigned char probed:1;		/* A asked B for its external address */
	unsigned char extip_ok:1;	/* ...and learnt it */
	unsigned char extip_bad:1;	/* ...or learnt something else */
	unsigned char samid_sent:1;	/* C pinged A using B's id */
	unsigned char samid_ok:1;	/* ...and A still has B at B */
	unsigned char samid_bad:1;	/* ...or A moved B's entry */
	unsigned char raw_up:1;		/* R's socket is bound */
	unsigned char err_asked:1;	/* R asked B a find_node with no target */
	unsigned char err_wire_ok:1;	/* B's refusal is well-formed bencode */
	unsigned char err_wire_bad:1;	/* ...or it is not */
	unsigned char err_decoded_ok:1;	/* A decoded the relayed refusal */
	unsigned char err_decoded_bad:1;/* ...or decoded something else */
	unsigned char unsol_ok:1;	/* R's unasked-for replies changed
					 * nothing in A's table */
	unsigned char unsol_bad:1;	/* ...or they did */
	unsigned char seq_ok:1;		/* only A's real ack completed */
	unsigned char seq_bad:1;	/* ...or a forged one did */
	unsigned char unproven_ok:1;	/* B sent R each answer once */
	unsigned char unproven_bad:1;	/* ...or repeated one */
	unsigned char ss_sent:1;	/* A pinged R with a storage salen */
	unsigned char ss_ponged:1;	/* ...R answered it */
	unsigned char ss_ok:1;		/* ...and A took the answer */
	unsigned char ss_bad:1;		/* ...or dropped it */
	unsigned char mart_sent:1;	/* A probed B and R again */
	unsigned char mart_answered:1;	/* ...R said A is at 224.0.0.1 */
	unsigned char mart_ok:1;	/* ...and A did not believe it */
	unsigned char srch_started:1;	/* A searched for KRPC_SRCH_TARGET */
	unsigned char srch_answered:1;	/* ...R answered its get_peers */
	unsigned char srch_ok:1;	/* ...and the search took little of it */
	unsigned char srch_bad:1;	/* ...or it took too much */
	unsigned char ecl_pinged:1;	/* R2 pinged A */
	unsigned char ecl_ponged:1;	/* ...and A answered */
	unsigned char ecl_started:1;	/* A searched for KRPC_ECL_TARGET */
	unsigned char ecl_asked:1;	/* ...R saw its get_peers */
	unsigned char ecl_asked2:1;	/* ...R2 saw its get_peers */
	unsigned char ecl_sent:1;	/* ...R and R2 sent their decoys */
	unsigned char ecl_ok:1;		/* ...and B kept its place */
	unsigned char ecl_bad:1;	/* ...or the decoys took the search */
	unsigned char share_ok:1;	/* B kept to the token and the share */
	unsigned char share_bad:1;	/* ...or it did not */
	unsigned char q_up:1;		/* Q's socket is bound */
	unsigned char q_b_sent:1;	/* B's send to Q completed */
	unsigned char q_ok:1;		/* B kept to Q's session */
	unsigned char q_bad:1;		/* ...or it did not */
};

/* the id R answers A's ping with, and the polls since it did */
#define KRPC_SS_ID_R		0x77
static int ss_polls, mart_polls;

/* R's unasked-for replies to A: how far along, and the polls since */
static int unsol_state, unsol_polls;

/*
 * R as the far end of reliable transfers: A's data to R, answered with forged
 * acks, then R's capability requests to B, whose answers R counts
 */
enum {
	KRPC_SEQ_IDLE,
	KRPC_SEQ_A_SENT,	/* A sent R data, waiting for its chunk */
	KRPC_SEQ_ACKED_SQNC,	/* R acked it with the old fixed tid */
	KRPC_SEQ_ACKED_NONCE,	/* ... with the wrong nonce */
	KRPC_SEQ_ACKED_REAL,	/* ... properly: now it may complete */
	KRPC_SEQ_CAP1,		/* R asked B for its capabilities */
	KRPC_SEQ_CAP1_ACKED,	/* R acked B's answer with the fixed tid */
	KRPC_SEQ_CAP2,		/* R asked again, counting B's answers */
	KRPC_SEQ_DONE
};

static const char *seq_msg = "PUT 0102030405 0 5 ahoy!";
static int seq_state, seq_polls, cap_rsps;
static uint8_t seq_tid[16];
static size_t seq_tid_len;
static uint64_t cap_rsp_len;
static uint8_t cap_ch[8];	/* B's challenge to R's first request */

/*
 * Q sends B a reliable stream by hand, as a peer of B's with session tid T.
 * On one host, a blind spoofer forging Q's address is Q's own socket: a
 * "forged" chunk is one with a tid that is not Q's session's, as a spoofer
 * who cannot see Q's traffic would have to send.  Each state is waiting for
 * B's answer to the chunk Q sent in it.
 */
enum {
	KRPC_QS_IDLE,
	KRPC_QS_T0_FIRST,	/* Q's first chunk, tid T at 0, unproven */
	KRPC_QS_T0,		/* ...again, answering B's challenge */
	KRPC_QS_FORGED,		/* a forged chunk at Q's next offset */
	KRPC_QS_T1,		/* Q's own chunk at that offset */
	KRPC_QS_B_SENDS,	/* B sends Q more than Q sent B: Q challenges
				 * it, and acks it once it is proven */
	KRPC_QS_DUP,		/* Q repeats its chunk at T1's offset */
	KRPC_QS_RESTART,	/* Q restarted: a new tid U, from offset 0 */
	KRPC_QS_BAD_CH,		/* ...with the wrong answer to B's challenge */
	KRPC_QS_PROVEN,		/* ...with the right one */
	KRPC_QS_GAP,		/* a chunk of U's past a gap: acked with a SACK */
	KRPC_QS_OLD,		/* Q's old session's tid T again */
	KRPC_QS_DONE
};

#define KRPC_Q_TID_T		"sqTTTTTTTT"
#define KRPC_Q_TID_FORGED	"sqFFFFFFFF"
#define KRPC_Q_TID_U		"sqUUUUUUUU"
#define KRPC_Q_CH_LEN		8
#define KRPC_Q_CH_TO_B		"QCHALNGE"
#define KRPC_Q_GAP		7	/* bytes U's chunk past the gap skips */

/*
 * What Q sends B, in order: Q's three messages, one sent on the old session
 * after the restart (which must never arrive), one sent on the new session
 * past a gap, and the forged one,
 * at least as long as T1's message so that taking it would cover T1's
 * bytes.  B's message to Q is longer than everything Q sends B on T.
 */
static const char * const q_msg[] = {
	"Q session T chunk 0.",
	"Q session T chunk 1.",
	"Q session U chunk 0.",
	"Q session T, too late",
	"Q session U, past a gap",
};
static const char *q_forged = "forged by a spoofer!!",
		  *q_b_msg = "B to Q: longer than all Q sent B on T so far";
static int q_state, q_seen[LWS_ARRAY_SIZE(q_msg)], q_forged_seen;
static uint8_t q_ch[KRPC_Q_CH_LEN];
static int q_b_challenged;

/*
 * The search A makes once the transport cases are done, and what R's answer
 * names: one public host (TEST-NET-3, never routed) with many ids next to the
 * target, unusable endpoints, and B's id somewhere else
 */
#define KRPC_SRCH_TARGET	0x5a
/* (a nodes list holds at most 9 entries: the rest of it is below) */
#define KRPC_SRCH_HOST_IDS	5
#define KRPC_SRCH_PER_HOST	2	/* what the library lets one host have */
static const uint8_t srch_host[] = { 203, 0, 113, 7 },
		     srch_host_b[] = { 203, 0, 113, 8 },
		     srch_host_port0[] = { 203, 0, 113, 9 },
		     srch_mcast[] = { 224, 0, 0, 1 },
		     srch_zero[] = { 0, 0, 0, 1 };
static int srch_polls;

/*
 * The second search, that R and R2 try to eclipse: decoy ids KRPC_ECL_TARGET
 * but for the last byte, 9 from each (all a nodes list holds), each at its
 * own TEST-NET-3 address from KRPC_ECL_ADS_BASE up.  R2's own id is the
 * target but for its last byte, KRPC_ECL_ID_R2.
 */
#define KRPC_ECL_TARGET		0x3c
#define KRPC_ECL_ID_R2		0x01
#define KRPC_ECL_PER_PEER	9
#define KRPC_ECL_DECOYS		(2 * KRPC_ECL_PER_PEER)
#define KRPC_ECL_ADS_BASE	30
#define KRPC_ECL_INTRO_CAP	3	/* what one introducer may have pending */
static uint8_t ecl_tid[4], ecl_tid2[4];
static int ecl_polls;

/*
 * How many hashes one source host may have each DHT start storing, and the
 * hashes A subscribes to on B to use up its share: 0x46... with the last byte
 * the index.  A's first subscription (sub_hash()) already holds one.
 */
#define KRPC_SHARE		4
#define KRPC_SHARE_FILL		0x46
#define KRPC_SHARE_HASHES	6
static uint8_t share_token[KRPC_SHARE_HASHES][8];
static unsigned int share_tokens;	/* bitmap of the ones that came */
static int share_state, share_polls;

/* the ids R's unasked-for replies name: R's own, and the nodes it lists */
#define KRPC_UNSOL_ID_R		0x66
#define KRPC_UNSOL_ID_LISTED	0x55

static struct seen sv;
static int samid_warned;

/* A's warning that B's id was claimed from C's endpoint too */

static void
emit_cb(int level, const char *line)
{
	if ((level & LLL_WARN) && strstr(line, "claimed from"))
		samid_warned = 1;

	lwsl_emit_stderr(level, line);
}
static int retcode = 1;

static lws_dht_hash_t *
sub_hash(void);

static int
table_b_cb(void *user, const lws_dht_node_info_t *ni)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)ni->sa;

	if (ni->sa->sa_family == AF_INET && sin->sin_port == sa_b.sin_port &&
	    ni->good && ni->replied >= 0 && ni->heard >= 0 &&
	    ni->id->len == 20 && ni->id->id[0] == 0x22)
		*(int *)user = 1;

	return 0;
}

static void
cb_a(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	lws_dht_hash_t *ih;

	(void)closure;
	(void)from;
	(void)fromlen;

	switch (event) {
	case LWS_DHT_EVENT_TOKEN:
		if (info_hash && info_hash->len == 20 &&
		    info_hash->id[0] == KRPC_SHARE_FILL) {
			uint8_t k = info_hash->id[19];

			if (data_len == 8 && k < KRPC_SHARE_HASHES) {
				memcpy(share_token[k], data, 8);
				share_tokens |= 1u << k;
			}
			break;
		}
		/*
		 * B's subscribe reply carries the anti-spoof token, reported
		 * with the hash we subscribed to: that is what we must
		 * confirm with it
		 */
		if (data_len == 8 && !sv.token_ok) {
			ih = sub_hash();
			if (!ih || !info_hash || info_hash->len != ih->len ||
			    info_hash->type != ih->type ||
			    memcmp(info_hash->id, ih->id, ih->len))
				sv.token_ih_bad = 1;
			if (ih)
				lws_dht_hash_destroy(&ih);
			memcpy(token, data, data_len);
			token_len = data_len;
			sv.token_ok = 1;
		}
		break;
	case LWS_DHT_EVENT_NOTIFY:
		sv.notify_ok = 1;
		break;

	case LWS_DHT_EVENT_WRITE_COMPLETED:
		if (!from || fromlen < sizeof(sa_r) ||
		    ((const struct sockaddr_in *)from)->sin_port !=
							sa_r.sin_port)
			break;
		/* R's only real ack goes out after the forged ones */
		if (seq_state != KRPC_SEQ_ACKED_REAL) {
			lwsl_err("%s: a forged ack completed A's transfer to "
				 "R (state %d)\n", __func__, seq_state);
			sv.seq_bad = 1;
			seq_state = KRPC_SEQ_ACKED_REAL;
		} else
			sv.seq_ok = 1;
		break;
	case LWS_DHT_EVENT_WRITE_FAILED:
		if (from && fromlen >= sizeof(sa_r) &&
		    ((const struct sockaddr_in *)from)->sin_port ==
							sa_r.sin_port) {
			lwsl_err("%s: A's transfer to R failed (state %d)\n",
				 __func__, seq_state);
			sv.seq_bad = 1;
			seq_state = KRPC_SEQ_ACKED_REAL;
			break;
		}

		if (from && fromlen >= sizeof(sa_dead) &&
		    ((const struct sockaddr_in *)from)->sin_port ==
							sa_dead.sin_port)
			sv.dead_failed = 1;
		break;
	case LWS_DHT_EVENT_DATA:
		/* A registered no verbs, so B's CAP_RSP comes to us whole */
		if (data_len > 8 && !memcmp(data, "CAP_RSP ", 8))
			sv.cap_ok = 1;
		break;
	case LWS_DHT_EVENT_EXTERNAL_ADDR: {
		const struct lws_dht_consensus_info *ci =
				(const struct lws_dht_consensus_info *)data;
		const struct sockaddr_in *sin;

		/* B sees us at our loopback address and port, and says so */
		if (!ci || data_len != sizeof(*ci)) {
			sv.extip_bad = 1;
			break;
		}
		sin = (const struct sockaddr_in *)&ci->ss;
		if (sin->sin_family == AF_INET &&
		    sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
		    sin->sin_port == sa_a.sin_port && ci->num_peers == 1)
			sv.extip_ok = 1;
		else {
			lwsl_err("%s: unexpected external address report\n",
				 __func__);
			sv.extip_bad = 1;
		}
		break;
	}
	case LWS_DHT_EVENT_ERROR: {
		const struct lws_dht_error_info *ei =
				(const struct lws_dht_error_info *)data;

		/* B's refusal, relayed by R: code, message and tid intact */
		if (data_len == sizeof(*ei) && ei->code == 203 &&
		    ei->message_len == strlen(err_msg) &&
		    !memcmp(ei->message, err_msg, ei->message_len) &&
		    ei->tid_len == 2 && !memcmp(ei->tid, "aa", 2))
			sv.err_decoded_ok = 1;
		else {
			lwsl_err("%s: unexpected error reply report\n",
				 __func__);
			sv.err_decoded_bad = 1;
		}
		break;
	}
	default:
		break;
	}
}

/* where needle starts in buf, or -1 (memmem() is not portable) */

static ssize_t
krpc_find(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle), n;

	for (n = 0; n + nl <= len; n++)
		if (!memcmp(buf + n, needle, nl))
			return (ssize_t)n;

	return -1;
}

/* the bencode integer following key, eg "6:offseti", or -1 */

static int64_t
krpc_int(const uint8_t *buf, size_t len, const char *key)
{
	ssize_t at = krpc_find(buf, len, key);
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

/*
 * A reliable-transport chunk is a "data" query whose tid follows the verb:
 * ...1:q4:data1:t<len>:<tid>1:y1:qe.  Copies the tid out, or returns -1 if
 * this is not a chunk.
 */

static int
krpc_chunk_tid(const uint8_t *buf, size_t len, uint8_t *tid, size_t *tid_len)
{
	ssize_t at = krpc_find(buf, len, "1:q4:data1:t");
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
peer_queue(struct raw_peer *p, const void *buf, size_t len,
	   const struct sockaddr_in *to);
static void
raw_queue(const void *buf, size_t len, const struct sockaddr_in *to);
static void
ss_rx(const uint8_t *in, size_t len);
static int
eclipse_rx(const uint8_t *in, size_t len, uint8_t *tid);
static void
search_rx(const uint8_t *in, size_t len);

/* a raw peer's ack, from R's id, claiming everything below offset */

static void
krpc_queue_ack(struct raw_peer *p, const uint8_t *tid, size_t tid_len,
	       uint64_t offset, const struct sockaddr_in *to)
{
	uint8_t q[128];
	int n;

	n = lws_snprintf((char *)q, sizeof(q), "d1:rd2:id20:"
			 "33333333333333333333"
			 "3:leni0e6:offseti%llue" "e1:t%u:",
			 (unsigned long long)offset, (unsigned int)tid_len);
	if (n < 0 || (size_t)n + tid_len + 7 > sizeof(q))
		return;

	memcpy(q + n, tid, tid_len);
	memcpy(q + (size_t)n + tid_len, "1:y1:re", 7);

	peer_queue(p, q, (size_t)n + tid_len + 7, to);
}

/*
 * R's data chunk to B, carrying a capability request, and the answer to B's
 * challenge if it has one
 */

static void
krpc_queue_cap_req(uint64_t offset, const uint8_t *ch)
{
	uint8_t q[160];
	size_t o = 5;
	int n;

	memcpy(q, "d1:ad", 5);
	if (ch) {
		memcpy(q + o, "2:ch8:", 6);
		memcpy(q + o + 6, ch, sizeof(cap_ch));
		o += 6 + sizeof(cap_ch);
	}

	n = lws_snprintf((char *)q + o, sizeof(q) - o, "4:data%u:%s2:id20:"
			 "33333333333333333333"
			 "3:leni%ue6:offseti%lluee1:q4:data1:t10:sqRRRRRRRR"
			 "1:y1:qe", (unsigned int)strlen(cap_req), cap_req,
			 (unsigned int)strlen(cap_req),
			 (unsigned long long)offset);
	if (n < 0 || o + (size_t)n >= sizeof(q) - 1)
		return;

	raw_queue(q, o + (size_t)n, &sa_b);
}

/*
 * A datagram for R while the transport cases run: from A, chunks of the data
 * A is sending R; from B, its answers to R's capability requests (and its
 * acks of R's requests, which R ignores)
 */

static void
seq_rx(const struct sockaddr_in *from, const uint8_t *in, size_t len)
{
	uint8_t tid[16];
	size_t tid_len;

	if (from->sin_port == sa_b.sin_port && seq_state == KRPC_SEQ_CAP1 &&
	    !peer_r.tx_len && krpc_find(in, len, "d1:rd2:ch8:") == 0 &&
	    len >= 11 + sizeof(cap_ch) &&
	    krpc_find(in, len, "e1:t10:sqRRRRRRRR") >= 0) {
		/* B challenged R's first request: R asks again, answering */
		memcpy(cap_ch, in + 11, sizeof(cap_ch));
		krpc_queue_cap_req(0, cap_ch);
		return;
	}

	if (krpc_chunk_tid(in, len, tid, &tid_len))
		return;

	if (from->sin_port == sa_b.sin_port) {
		if (krpc_find(in, len, "CAP_RSP ") < 0)
			return;

		cap_rsps++;

		if (seq_state == KRPC_SEQ_CAP1 && !peer_r.tx_len) {
			/*
			 * Acked with the tid acks used to have, which anyone
			 * naming R as the source could send
			 */
			cap_rsp_len = (uint64_t)krpc_int(in, len, "3:leni");
			krpc_queue_ack(&peer_r, (const uint8_t *)"sqnc", 4,
				       cap_rsp_len, &sa_b);
			seq_state = KRPC_SEQ_CAP1_ACKED;
		}
		return;
	}

	if (from->sin_port != sa_a.sin_port || peer_r.tx_len)
		return;

	/*
	 * Each chunk from A after the first is a retransmit, so the ack R
	 * sent before it did not retire A's data: R tries the next one.
	 */

	switch (seq_state) {
	case KRPC_SEQ_A_SENT:
		memcpy(seq_tid, tid, tid_len);
		seq_tid_len = tid_len;
		krpc_queue_ack(&peer_r, (const uint8_t *)"sqnc", 4,
			       (uint64_t)-1, &sa_a);
		seq_state = KRPC_SEQ_ACKED_SQNC;
		break;
	case KRPC_SEQ_ACKED_SQNC:
		if (tid_len != seq_tid_len || memcmp(tid, seq_tid, tid_len)) {
			lwsl_err("%s: A's retransmit has another tid\n",
				 __func__);
			sv.seq_bad = 1;
			break;
		}
		tid[tid_len - 1] ^= 1;
		krpc_queue_ack(&peer_r, tid, tid_len, strlen(seq_msg), &sa_a);
		seq_state = KRPC_SEQ_ACKED_NONCE;
		break;
	case KRPC_SEQ_ACKED_NONCE:
		krpc_queue_ack(&peer_r, tid, tid_len, strlen(seq_msg), &sa_a);
		seq_state = KRPC_SEQ_ACKED_REAL;
		break;
	default:
		break;
	}
}

/*
 * R and Q: plain UDP sockets speaking KRPC by hand, the peers the DHT
 * contexts cannot be made to be.  Each sends whatever was queued in its tx
 * when the event loop lets it, and inspects what the contexts answer.
 */

static void
peer_queue(struct raw_peer *p, const void *buf, size_t len,
	   const struct sockaddr_in *to)
{
	if (len > sizeof(p->tx)) {
		lwsl_err("%s: %u bytes too long to queue\n", __func__,
			 (unsigned int)len);
		return;
	}

	memcpy(p->tx, buf, len);
	p->tx_len = len;
	p->to = *to;
	lws_callback_on_writable(p->wsi);
}

static void
raw_queue(const void *buf, size_t len, const struct sockaddr_in *to)
{
	peer_queue(&peer_r, buf, len, to);
}

static void
peer_send(struct raw_peer *p)
{
	lws_sockfd_type fd;
	ssize_t n;

	if (!p->tx_len)
		return;

	fd = lws_get_socket_fd(p->wsi);
	if (fd == LWS_SOCK_INVALID) {
		lwsl_err("%s: no socket to send on\n", __func__);
		p->tx_len = 0;
		return;
	}
	n = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   p->tx,
#if defined(WIN32)
		   (int)
#endif
		   p->tx_len, 0, (const struct sockaddr *)&p->to,
		   sizeof(p->to));
	if (n != (ssize_t)p->tx_len)
		lwsl_err("%s: sendto returned %d\n", __func__, (int)n);
	p->tx_len = 0;
}

static int
cb_raw(struct lws *wsi, enum lws_callback_reasons reason, void *user,
       void *in, size_t len)
{
	const struct lws_udp *udp;
	char exp[96];
	ssize_t n;

	(void)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		sv.raw_up = 1;
		break;

	case LWS_CALLBACK_RAW_RX:
		udp = lws_get_udp(wsi);
		if (!udp || udp->sa46.sa4.sin_family != AF_INET)
			break;

		if (sv.srch_started && !sv.srch_answered &&
		    udp->sa46.sa4.sin_port == sa_a.sin_port) {
			search_rx(in, len);
			break;
		}

		if (sv.ecl_started && !sv.ecl_asked &&
		    udp->sa46.sa4.sin_port == sa_a.sin_port &&
		    eclipse_rx(in, len, ecl_tid)) {
			sv.ecl_asked = 1;
			break;
		}

		if (seq_state != KRPC_SEQ_IDLE) {
			seq_rx(&udp->sa46.sa4, in, len);
			break;
		}

		if (sv.ss_sent && udp->sa46.sa4.sin_port == sa_a.sin_port) {
			ss_rx(in, len);
			break;
		}

		if (udp->sa46.sa4.sin_port != sa_b.sin_port)
			break;

		/*
		 * B's refusal of our target-less find_node: BEP 5 wants the
		 * "e" member to be a list of the code and the message, and the
		 * tid we chose echoed back.  B has no "v" to add.
		 */
		n = lws_snprintf(exp, sizeof(exp),
				 "d1:eli203e%u:%se1:t2:aa1:y1:ee",
				 (unsigned int)strlen(err_msg), err_msg);
		if (len == (size_t)n && !memcmp(in, exp, len))
			sv.err_wire_ok = 1;
		else {
			lwsl_err("%s: B's error reply is not the expected "
				 "bencode\n", __func__);
			lwsl_hexdump_err(in, len);
			sv.err_wire_bad = 1;
		}

		/* relay it to A as it stands, as a peer refusing A would */
		raw_queue(in, len, &sa_a);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		peer_send(&peer_r);
		break;

	default:
		break;
	}

	return 0;
}

/*
 * Once B is known to be answering, R asks it a find_node that has no target;
 * B must refuse that with a 203 rather than walk its table against nothing.
 */

static void
error_reply_step(const struct lws_dht_stats *sb)
{
	uint8_t q[sizeof(raw_query_head) - 1 + 20 + sizeof(raw_query_tail) - 1];
	uint8_t *p = q;

	if (!sv.raw_up || !sb->rx_ping || sv.err_asked)
		return;

	sv.err_asked = 1;

	memcpy(p, raw_query_head, sizeof(raw_query_head) - 1);
	p += sizeof(raw_query_head) - 1;
	memset(p, 0x33, 20); /* R's node id */
	p += 20;
	memcpy(p, raw_query_tail, sizeof(raw_query_tail) - 1);

	raw_queue(q, sizeof(q), &sa_b);
}

/*
 * Once A holds B as good, R sends A replies to requests A never made, with
 * the tids A's maintenance find_node and pings use: first a find_node reply
 * listing three made-up nodes (on loopback, which A admits), then a pong.
 * Anyone can send those, from any address, so after a while A's table must
 * still not hold R or any node R named.
 */

static int
unsol_table_cb(void *user, const lws_dht_node_info_t *ni)
{
	if (ni->id->len == 20 && (ni->id->id[0] == KRPC_UNSOL_ID_R ||
				  ni->id->id[0] == KRPC_UNSOL_ID_LISTED))
		(*(int *)user)++;

	return 0;
}

static void
unsolicited_reply_step(void)
{
	uint8_t q[256], *p = q;
	int n, seen = 0;

	/* after R's relay of B's refusal, which also goes out from R */
	if (!sv.raw_up || !sv.table_ok || !sv.err_decoded_ok || sv.unsol_ok ||
	    sv.unsol_bad || peer_r.tx_len)
		return;

	switch (unsol_state) {
	case 0:
		/* d1:rd2:id20:<R>5:nodes84:<3 x node info>e1:t4:fn..1:y1:re */
		memcpy(p, "d1:rd2:id20:", 12);
		p += 12;
		memset(p, KRPC_UNSOL_ID_R, 20);
		p += 20;
		memcpy(p, "5:nodes84:", 10);
		p += 10;
		for (n = 0; n < 3; n++) {
			*p++ = LWS_DHT_HASH_TYPE_SHA1;
			*p++ = 20;
			memset(p, KRPC_UNSOL_ID_LISTED, 20);
			p[19] = (uint8_t)n;
			p += 20;
			memcpy(p, &sa_dead.sin_addr, 4);
			p += 4;
			/* ports nobody uses, next to the unused one */
			*p++ = (uint8_t)((ntohs(sa_dead.sin_port) + n) >> 8);
			*p++ = (uint8_t)(ntohs(sa_dead.sin_port) + n);
		}
		memcpy(p, "e1:t4:fn\0\0" "1:y1:re", 17);
		p += 17;
		raw_queue(q, lws_ptr_diff_size_t(p, q), &sa_a);
		unsol_state++;
		break;

	case 1:
		/* d1:rd2:id20:<R>e1:t4:pn..1:y1:re */
		memcpy(p, "d1:rd2:id20:", 12);
		p += 12;
		memset(p, KRPC_UNSOL_ID_R, 20);
		p += 20;
		memcpy(p, "e1:t4:pn\0\0" "1:y1:re", 17);
		p += 17;
		raw_queue(q, lws_ptr_diff_size_t(p, q), &sa_a);
		unsol_state++;
		break;

	default:
		/* give A a few polls to have processed both */
		if (++unsol_polls < 5)
			break;

		lws_dht_foreach_node(dht_a, AF_INET, unsol_table_cb, &seen);
		if (seen) {
			lwsl_err("%s: unasked-for replies put %d nodes in A's "
				 "table\n", __func__, seen);
			sv.unsol_bad = 1;
		} else
			sv.unsol_ok = 1;
		break;
	}
}

/*
 * After R's unasked-for replies, R is the far end of reliable transfers: see
 * seq_rx() for what R answers A's chunks with
 */

static void
seq_step(void)
{
	if (!sv.mart_ok || sv.unproven_ok || sv.unproven_bad || peer_r.tx_len)
		return;

	switch (seq_state) {
	case KRPC_SEQ_IDLE:
		seq_state = KRPC_SEQ_A_SENT;
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_r,
				  seq_msg, strlen(seq_msg));
		break;

	case KRPC_SEQ_ACKED_REAL:
		/* (the two cases are independent: go on even if it failed) */
		if (!sv.seq_ok && !sv.seq_bad)
			break;

		/* R is a stranger to B, which answers it once, unrepeated */
		seq_state = KRPC_SEQ_CAP1;
		krpc_queue_cap_req(0, NULL);
		break;

	case KRPC_SEQ_CAP1_ACKED:
		/* the forged ack has gone: ask again */
		seq_state = KRPC_SEQ_CAP2;
		seq_polls = 0;
		krpc_queue_cap_req(strlen(cap_req), NULL);
		break;

	case KRPC_SEQ_CAP2:
		/* B retransmits every 100ms by now: give it 1.5s to */
		if (++seq_polls < 15)
			break;

		if (cap_rsps == 2)
			sv.unproven_ok = 1;
		else {
			lwsl_err("%s: R got %d answers to its 2 requests\n",
				 __func__, cap_rsps);
			sv.unproven_bad = 1;
		}
		seq_state = KRPC_SEQ_DONE;
		break;

	default:
		break;
	}
}

/*
 * Q's chunk to B: "d1:ad[2:ch8:<ch>]4:data<msg>2:id20:<Q>3:len..6:offset..e
 * 1:q4:data1:t10:<tid>1:y1:qe", with the answer to B's challenge if it has one
 */

static void
q_queue_chunk(const char *tid, uint64_t offset, const char *msg,
	      const uint8_t *ch)
{
	uint8_t q[256];
	size_t m = strlen(msg), o = 0;
	int n;

	memcpy(q, "d1:ad", 5);
	o = 5;
	if (ch) {
		memcpy(q + o, "2:ch8:", 6);
		memcpy(q + o + 6, ch, KRPC_Q_CH_LEN);
		o += 6 + KRPC_Q_CH_LEN;
	}

	n = lws_snprintf((char *)q + o, sizeof(q) - o, "4:data%u:%s2:id20:"
			 "44444444444444444444"
			 "3:leni%ue6:offseti%lluee1:q4:data1:t10:%s1:y1:qe",
			 (unsigned int)m, msg, (unsigned int)m,
			 (unsigned long long)offset, tid);
	if (n < 0 || o + (size_t)n >= sizeof(q) - 1)
		return;

	peer_queue(&peer_q, q, o + (size_t)n, &sa_b);
}

/* Q's challenge to a chunk of B's: "d1:rd2:ch8:<ch>2:id20:<Q>e1:t<tid>1:y1:re" */

static void
q_queue_challenge(const uint8_t *tid, size_t tid_len)
{
	uint8_t q[128];
	int n;

	n = lws_snprintf((char *)q, sizeof(q), "d1:rd2:ch8:" KRPC_Q_CH_TO_B
			 "2:id20:44444444444444444444e1:t%u:",
			 (unsigned int)tid_len);
	if (n < 0 || (size_t)n + tid_len + 7 > sizeof(q))
		return;

	memcpy(q + n, tid, tid_len);
	memcpy(q + (size_t)n + tid_len, "1:y1:re", 7);

	peer_queue(&peer_q, q, (size_t)n + tid_len + 7, &sa_b);
}

static void
q_expect(int ok, const char *what)
{
	if (ok)
		return;

	lwsl_err("%s: Q: %s\n", __func__, what);
	sv.q_bad = 1;
}

/*
 * B's answer to Q's chunk is an ack, "d1:rd2:id..3:len..6:offset..[4:sack..]
 * e1:t<tid>1:y1:re", or a challenge, "d1:rd2:ch8:<ch>2:id..e1:t<tid>1:y1:re",
 * asking whoever sent a chunk with a tid it does not know to prove itself.
 * Either echoes the tid of the chunk it answers.
 */

static int
q_answers(const uint8_t *in, size_t len, const char *tid)
{
	char t[16];

	lws_snprintf(t, sizeof(t), "e1:t10:%s", tid);

	return krpc_find(in, len, t) >= 0;
}

/*
 * B's ack to Q's chunk past the gap ends exactly "4:sackld1:li<len>e1:oi<start>
 * eee1:t10:<tid>1:y1:re": the block, the list and the reply dict closed once
 * each, then the rest of the message, then its own end
 */

static int
q_is_sack(const uint8_t *in, size_t len, size_t blen, uint64_t start,
	  const char *tid)
{
	ssize_t at = krpc_find(in, len, "4:sackl");
	char exp[96];
	int n;

	n = lws_snprintf(exp, sizeof(exp),
			 "4:sackld1:li%ue1:oi%llueee" "e1:t10:%s1:y1:re",
			 (unsigned int)blen, (unsigned long long)start, tid);

	return at >= 0 && len - (size_t)at == (size_t)n &&
	       !memcmp(in + at, exp, (size_t)n);
}

static int
q_is_challenge(const uint8_t *in, size_t len)
{
	ssize_t at = krpc_find(in, len, "d1:rd2:ch8:");

	if (at < 0 || (size_t)at + 11 + KRPC_Q_CH_LEN > len ||
	    krpc_find(in, len, "6:offseti") >= 0)
		return 0;

	memcpy(q_ch, in + at + 11, KRPC_Q_CH_LEN);

	return 1;
}

static void
q_rx(const uint8_t *in, size_t len)
{
	size_t l0 = strlen(q_msg[0]), l1 = strlen(q_msg[1]),
	       l2 = strlen(q_msg[2]), l4 = strlen(q_msg[4]);
	uint8_t tid[16], ch[KRPC_Q_CH_LEN];
	size_t tid_len;
	int64_t off;

	if (!krpc_chunk_tid(in, len, tid, &tid_len)) {
		if (q_state != KRPC_QS_B_SENDS)
			return;

		/*
		 * B's own data to Q.  Q challenges it, as a receiver that did
		 * not know B's session would: B must send it again at once
		 * with Q's challenge, although B never repeats itself to Q
		 * unproven, since the challenge proves Q hears B.  Then Q acks
		 * it truly, so it completes.
		 */
		if (krpc_find(in, len, "d1:ad2:ch8:" KRPC_Q_CH_TO_B) == 0) {
			krpc_queue_ack(&peer_q, tid, tid_len,
				       (uint64_t)krpc_int(in, len, "3:leni"),
				       &sa_b);
			return;
		}

		if (q_b_challenged) {
			q_expect(0, "B sent its chunk again without the "
				    "answer to Q's challenge");
			return;
		}
		q_b_challenged = 1;
		q_queue_challenge(tid, tid_len);
		return;
	}

	off = krpc_int(in, len, "6:offseti");

	switch (q_state) {
	case KRPC_QS_T0_FIRST:
		q_expect(q_answers(in, len, KRPC_Q_TID_T) &&
			 q_is_challenge(in, len),
			 "B took the first chunk of a session unchallenged");
		q_queue_chunk(KRPC_Q_TID_T, 0, q_msg[0], q_ch);
		q_state = KRPC_QS_T0;
		break;

	case KRPC_QS_T0:
		q_expect(q_answers(in, len, KRPC_Q_TID_T) &&
			 off == (int64_t)l0, "first chunk not acked");
		/* a spoofer's chunk where Q's next one will be */
		q_queue_chunk(KRPC_Q_TID_FORGED, l0, q_forged, NULL);
		q_state = KRPC_QS_FORGED;
		break;

	case KRPC_QS_FORGED:
		q_expect(q_answers(in, len, KRPC_Q_TID_FORGED) &&
			 q_is_challenge(in, len),
			 "B took a chunk with a tid not of Q's session");
		q_queue_chunk(KRPC_Q_TID_T, l0, q_msg[1], NULL);
		q_state = KRPC_QS_T1;
		break;

	case KRPC_QS_T1:
		q_expect(q_answers(in, len, KRPC_Q_TID_T) &&
			 off == (int64_t)(l0 + l1),
			 "Q's own chunk after the forged one not acked on T");
		/* B answers Q with more than Q has sent it */
		q_state = KRPC_QS_B_SENDS;
		lws_dht_send_data(dht_b, (struct sockaddr *)&sa_q, q_b_msg,
				  strlen(q_b_msg));
		break;

	case KRPC_QS_DUP:
		q_expect(q_answers(in, len, KRPC_Q_TID_T) &&
			 off == (int64_t)(l0 + l1),
			 "repeated chunk acked with other than Q's offset");
		/* Q restarts: a new session, from offset 0 */
		q_queue_chunk(KRPC_Q_TID_U, 0, q_msg[2], NULL);
		q_state = KRPC_QS_RESTART;
		break;

	case KRPC_QS_RESTART:
		q_expect(q_answers(in, len, KRPC_Q_TID_U) &&
			 q_is_challenge(in, len),
			 "B took a new session's chunk unchallenged");
		memcpy(ch, q_ch, sizeof(ch));
		ch[0] ^= 1;
		q_queue_chunk(KRPC_Q_TID_U, 0, q_msg[2], ch);
		q_state = KRPC_QS_BAD_CH;
		break;

	case KRPC_QS_BAD_CH:
		memcpy(ch, q_ch, sizeof(ch));
		q_expect(q_answers(in, len, KRPC_Q_TID_U) &&
			 q_is_challenge(in, len) && !memcmp(ch, q_ch, sizeof(ch)),
			 "B took a wrong answer to its challenge");
		q_queue_chunk(KRPC_Q_TID_U, 0, q_msg[2], q_ch);
		q_state = KRPC_QS_PROVEN;
		break;

	case KRPC_QS_PROVEN:
		q_expect(q_answers(in, len, KRPC_Q_TID_U) &&
			 off == (int64_t)l2,
			 "Q's proven new session not acked from 0");
		/* leave a gap: B acks what it holds, and SACKs the chunk */
		q_queue_chunk(KRPC_Q_TID_U, l2 + KRPC_Q_GAP, q_msg[4], NULL);
		q_state = KRPC_QS_GAP;
		break;

	case KRPC_QS_GAP:
		q_expect(q_answers(in, len, KRPC_Q_TID_U) &&
			 off == (int64_t)l2 &&
			 q_is_sack(in, len, l4, l2 + KRPC_Q_GAP, KRPC_Q_TID_U),
			 "chunk past a gap not acked with a well-formed SACK");
		if (sv.q_bad)
			lwsl_hexdump_err(in, len);
		/* the old session is over: its tid is a stranger's now */
		q_queue_chunk(KRPC_Q_TID_T, l0 + l1, q_msg[3], NULL);
		q_state = KRPC_QS_OLD;
		break;

	case KRPC_QS_OLD:
		q_expect(q_answers(in, len, KRPC_Q_TID_T) &&
			 q_is_challenge(in, len),
			 "B took a chunk of Q's replaced session");
		q_expect(q_seen[0] == 1 && q_seen[1] == 1 && q_seen[2] == 1 &&
			 !q_seen[3] && q_seen[4] == 1 && !q_forged_seen,
			 "B did not deliver exactly Q's own chunks once each");
		q_state = KRPC_QS_DONE;
		if (!sv.q_bad)
			sv.q_ok = 1;
		break;

	default:
		break;
	}
}

/* Q starts once B is up, and repeats itself once B's send to it is done */

static void
q_step(void)
{
	switch (q_state) {
	case KRPC_QS_IDLE:
		if (!sv.q_up || !sv.data_ok)
			break;
		q_queue_chunk(KRPC_Q_TID_T, 0, q_msg[0], NULL);
		q_state = KRPC_QS_T0_FIRST;
		break;

	case KRPC_QS_B_SENDS:
		if (!sv.q_b_sent)
			break;
		q_queue_chunk(KRPC_Q_TID_T, strlen(q_msg[0]), q_msg[1], NULL);
		q_state = KRPC_QS_DUP;
		break;

	default:
		break;
	}
}

static int
cb_q(struct lws *wsi, enum lws_callback_reasons reason, void *user,
     void *in, size_t len)
{
	const struct lws_udp *udp;

	(void)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		sv.q_up = 1;
		break;

	case LWS_CALLBACK_RAW_RX:
		udp = lws_get_udp(wsi);
		if (udp && udp->sa46.sa4.sin_family == AF_INET &&
		    udp->sa46.sa4.sin_port == sa_b.sin_port)
			q_rx(in, len);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		peer_send(&peer_q);
		break;

	default:
		break;
	}

	return 0;
}

/*
 * After R's unasked-for replies, A pings R with R's address in a
 * sockaddr_storage, passing the storage's size: that request has to be
 * sent with its family's length, or BSD and macOS refuse it (EINVAL), and
 * recorded like any other, or R's pong to it is dropped as unasked-for.
 */

static int
ss_table_cb(void *user, const lws_dht_node_info_t *ni)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)ni->sa;

	if (ni->id->len == 20 && ni->id->id[0] == KRPC_SS_ID_R &&
	    ni->sa->sa_family == AF_INET && sin->sin_port == sa_r.sin_port)
		*(int *)user = 1;

	return 0;
}

static void
storage_ping_step(void)
{
	struct sockaddr_storage ss;
	int seen = 0;

	if (!sv.unsol_ok || sv.ss_ok || sv.ss_bad || peer_r.tx_len)
		return;

	if (!sv.ss_sent) {
		sv.ss_sent = 1;
		memset(&ss, 0, sizeof(ss));
		memcpy(&ss, &sa_r, sizeof(sa_r));
		lws_dht_ping_node(dht_a, (struct sockaddr *)&ss, sizeof(ss));
		return;
	}

	/* give A a few polls to have processed R's pong */
	if (!sv.ss_ponged || ++ss_polls < 3)
		return;

	lws_dht_foreach_node(dht_a, AF_INET, ss_table_cb, &seen);
	if (seen)
		sv.ss_ok = 1;
	else {
		lwsl_err("%s: R's pong to A's ping was dropped\n", __func__);
		sv.ss_bad = 1;
	}
}

/*
 * R's answer to A's pings: the pong, from R's id, echoing A's tid.  To A's
 * external-address probe (tid "ip" + nonce), R says A is at a multicast
 * address.
 */

static void
ss_rx(const uint8_t *in, size_t len)
{
	uint8_t q[96], *p = q;
	ssize_t at = krpc_find(in, len, "1:q4:ping1:t10:ip");

	if (at >= 0 && (size_t)at + 25 <= len && sv.mart_sent &&
	    !sv.mart_answered) {
		sv.mart_answered = 1;

		memcpy(p, "d2:ip6:", 7);
		p += 7;
		*p++ = 224;
		*p++ = 0;
		*p++ = 0;
		*p++ = 1;
		*p++ = (uint8_t)(ntohs(sa_a.sin_port) >> 8);
		*p++ = (uint8_t)ntohs(sa_a.sin_port);
		memcpy(p, "1:rd2:id20:", 11);
		p += 11;
		memset(p, KRPC_SS_ID_R, 20);
		p += 20;
		memcpy(p, "e1:t10:", 7);
		p += 7;
		memcpy(p, in + at + 15, 10);
		p += 10;
		memcpy(p, "1:y1:re", 7);
		p += 7;

		raw_queue(q, lws_ptr_diff_size_t(p, q), &sa_a);
		return;
	}

	at = krpc_find(in, len, "1:q4:ping1:t4:");
	if (at < 0 || (size_t)at + 18 > len || sv.ss_ponged)
		return;

	sv.ss_ponged = 1;

	memcpy(p, "d1:rd2:id20:", 12);
	p += 12;
	memset(p, KRPC_SS_ID_R, 20);
	p += 20;
	memcpy(p, "e1:t4:", 6);
	p += 6;
	memcpy(p, in + at + 14, 4);
	p += 4;
	memcpy(p, "1:y1:re", 7);
	p += 7;

	raw_queue(q, lws_ptr_diff_size_t(p, q), &sa_a);
}

/*
 * Once R is a good node of A's, A probes B and R for its external address;
 * R's answer names a multicast address, which A must ignore: cb_a() flags any
 * address report but A's own as extip_bad
 */

static void
martian_step(void)
{
	if (!sv.ss_ok || sv.mart_ok || peer_r.tx_len)
		return;

	if (!sv.mart_sent) {
		sv.mart_sent = 1;
		lws_dht_test_external_ips(dht_a);
		return;
	}

	if (sv.mart_answered && ++mart_polls >= 5 && !sv.extip_bad)
		sv.mart_ok = 1;
}

/*
 * After the transport cases, A searches for KRPC_SRCH_TARGET.  R is one of the
 * nodes A asks, and answers with a nodes list that tries to take the search
 * over (see the top of the file); then the search's candidates are checked.
 */

static lws_dht_hash_t *
search_target(void)
{
	uint8_t idata[20];

	memset(idata, KRPC_SRCH_TARGET, sizeof(idata));

	return lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
}

/* one nodes list entry: SHA1 id of fill bytes ending in last, at ads:port */

static uint8_t *
search_node_info(uint8_t *p, uint8_t fill, uint8_t last, const uint8_t *ads,
		 uint16_t port)
{
	*p++ = LWS_DHT_HASH_TYPE_SHA1;
	*p++ = 20;
	memset(p, fill, 20);
	p[19] = last;
	p += 20;
	memcpy(p, ads, 4);
	p += 4;
	*p++ = (uint8_t)(port >> 8);
	*p++ = (uint8_t)port;

	return p;
}

static void
search_rx(const uint8_t *in, size_t len)
{
	ssize_t at = krpc_find(in, len, "1:q9:get_peers1:t4:");
	uint8_t q[400], *p = q, *nodes;
	int n;

	if (at < 0 || (size_t)at + 23 > len)
		return;

	sv.srch_answered = 1;

	memcpy(p, "d1:rd2:id20:", 12);
	p += 12;
	memset(p, KRPC_SS_ID_R, 20);
	p += 20;
	n = lws_snprintf((char *)p, 16, "5:nodes%u:",
			 (KRPC_SRCH_HOST_IDS + 4) * 28);
	p += n;
	nodes = p;

	for (n = 0; n < KRPC_SRCH_HOST_IDS; n++)
		p = search_node_info(p, KRPC_SRCH_TARGET, (uint8_t)(0x80 + n),
				     srch_host, (uint16_t)(20000 + n));
	/* unusable endpoints, with ids closer to the target than any */
	p = search_node_info(p, KRPC_SRCH_TARGET, 1, srch_mcast, 20100);
	p = search_node_info(p, KRPC_SRCH_TARGET, 2, srch_zero, 20101);
	p = search_node_info(p, KRPC_SRCH_TARGET, 3, srch_host_port0, 0);
	/* B's id, somewhere B is not */
	p = search_node_info(p, 0x22, 0x22, srch_host_b, 20200);

	if (lws_ptr_diff_size_t(p, nodes) != (KRPC_SRCH_HOST_IDS + 4) * 28) {
		lwsl_err("%s: nodes list size mismatch\n", __func__);
		sv.srch_bad = 1;
		return;
	}

	memcpy(p, "5:token8:RRRRRRRRe1:t4:", 23);
	p += 23;
	memcpy(p, in + at + 19, 4);
	p += 4;
	memcpy(p, "1:y1:re", 7);
	p += 7;

	raw_queue(q, lws_ptr_diff_size_t(p, q), &sa_a);
}

struct srch_tally {
	int		host, unusable, b_at_b, b_moved, total;
};

static int
search_node_cb(void *user, const lws_dht_node_info_t *ni)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)ni->sa;
	struct srch_tally *t = (struct srch_tally *)user;

	t->total++;
	if (ni->sa->sa_family != AF_INET)
		return 0;

	if (!memcmp(&sin->sin_addr, srch_host, 4))
		t->host++;
	if (!memcmp(&sin->sin_addr, srch_mcast, 4) ||
	    !memcmp(&sin->sin_addr, srch_zero, 4) || !sin->sin_port)
		t->unusable++;
	if (ni->id->len == 20 && ni->id->id[0] == 0x22 &&
	    ni->id->id[19] == 0x22) {
		if (sin->sin_port == sa_b.sin_port &&
		    sin->sin_addr.s_addr == sa_b.sin_addr.s_addr)
			t->b_at_b++;
		else
			t->b_moved++;
	}

	return 0;
}

static void
search_step_check(void)
{
	struct srch_tally t;
	lws_dht_hash_t *target;

	if (seq_state != KRPC_SEQ_DONE || sv.srch_ok || sv.srch_bad ||
	    peer_r.tx_len)
		return;

	target = search_target();
	if (!target) {
		sv.srch_bad = 1;
		return;
	}

	if (!sv.srch_started) {
		sv.srch_started = 1;
		if (lws_dht_search(dht_a, target, 0, AF_INET, NULL, NULL) < 0) {
			lwsl_err("%s: lws_dht_search failed\n", __func__);
			sv.srch_bad = 1;
		}
		goto bail;
	}

	/* give A a few polls to have processed R's answer */
	if (!sv.srch_answered || ++srch_polls < 3)
		goto bail;

	memset(&t, 0, sizeof(t));
	if (lws_dht_foreach_search_node(dht_a, target, AF_INET,
					search_node_cb, &t) < 0) {
		lwsl_err("%s: A has no search for the target\n", __func__);
		sv.srch_bad = 1;
		goto bail;
	}

	if (t.host > KRPC_SRCH_PER_HOST || !t.host || t.unusable ||
	    t.b_moved || !t.b_at_b) {
		lwsl_err("%s: search took %d candidates from one host, %d "
			 "unusable, B at B %d, B moved %d (of %d)\n", __func__,
			 t.host, t.unusable, t.b_at_b, t.b_moved, t.total);
		sv.srch_bad = 1;
	} else
		sv.srch_ok = 1;

bail:
	lws_dht_hash_destroy(&target);
}

/*
 * Once the first search is checked, R2 pings A so A knows it, and A searches
 * for KRPC_ECL_TARGET.  R and R2 note the tid of A's get_peers for it, and
 * answer only after B has, with their decoys; then the search's candidates
 * are checked.
 */

static int
eclipse_rx(const uint8_t *in, size_t len, uint8_t *tid)
{
	char needle[21];
	ssize_t at;

	/* the target, however the hash is framed */
	memset(needle, KRPC_ECL_TARGET, 20);
	needle[20] = '\0';

	at = krpc_find(in, len, "1:q9:get_peers1:t4:");
	if (at < 0 || (size_t)at + 23 > len || krpc_find(in, len, needle) < 0)
		return 0;

	memcpy(tid, in + at + 19, 4);

	return 1;
}

/* the id R2 uses, next to the target */

static void
eclipse_id_r2(uint8_t *id20)
{
	memset(id20, KRPC_ECL_TARGET, 20);
	id20[19] = KRPC_ECL_ID_R2;
}

/* a get_peers answer from p, with id id20, listing decoys from first on */

static void
eclipse_queue(struct raw_peer *p, const uint8_t *id20, const uint8_t *tid,
	      int first)
{
	uint8_t q[400], *o = q, ads[4] = { 203, 0, 113, 0 };
	int n;

	memcpy(o, "d1:rd2:id20:", 12);
	o += 12;
	memcpy(o, id20, 20);
	o += 20;
	o += lws_snprintf((char *)o, 16, "5:nodes%u:",
			  (unsigned int)KRPC_ECL_PER_PEER * 28);

	for (n = first; n < first + KRPC_ECL_PER_PEER; n++) {
		ads[3] = (uint8_t)(KRPC_ECL_ADS_BASE + n);
		o = search_node_info(o, KRPC_ECL_TARGET, (uint8_t)(0x40 + n),
				     ads, (uint16_t)(21000 + n));
	}

	memcpy(o, "5:token8:RRRRRRRRe1:t4:", 23);
	o += 23;
	memcpy(o, tid, 4);
	o += 4;
	memcpy(o, "1:y1:re", 7);
	o += 7;

	peer_queue(p, q, lws_ptr_diff_size_t(o, q), &sa_a);
}

static int
cb_r2(struct lws *wsi, enum lws_callback_reasons reason, void *user,
      void *in, size_t len)
{
	const struct lws_udp *udp;

	(void)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		udp = lws_get_udp(wsi);
		if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
		    udp->sa46.sa4.sin_port != sa_a.sin_port)
			break;
		if (krpc_find(in, len, "1:t2:e2") >= 0 &&
		    krpc_find(in, len, "1:y1:r") >= 0) {
			sv.ecl_ponged = 1;
			break;
		}
		if (sv.ecl_started && !sv.ecl_asked2 &&
		    eclipse_rx(in, len, ecl_tid2))
			sv.ecl_asked2 = 1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		peer_send(&peer_r2);
		break;

	default:
		break;
	}

	return 0;
}

struct ecl_tally {
	int		decoys, b_replied, b_present, total;
};

static int
eclipse_node_cb(void *user, const lws_dht_node_info_t *ni)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)ni->sa;
	struct ecl_tally *t = (struct ecl_tally *)user;
	const uint8_t *a;

	t->total++;
	if (ni->sa->sa_family != AF_INET)
		return 0;

	a = (const uint8_t *)&sin->sin_addr;
	if (a[0] == 203 && a[1] == 0 && a[2] == 113 &&
	    a[3] >= KRPC_ECL_ADS_BASE &&
	    a[3] < KRPC_ECL_ADS_BASE + KRPC_ECL_DECOYS)
		t->decoys++;

	if (sin->sin_port == sa_b.sin_port &&
	    sin->sin_addr.s_addr == sa_b.sin_addr.s_addr) {
		t->b_present++;
		if (ni->replied >= 0)
			t->b_replied++;
	}

	return 0;
}

static void
eclipse_step(void)
{
	lws_dht_hash_t *target;
	struct ecl_tally t;
	uint8_t idata[20];

	if (!sv.srch_ok || sv.ecl_ok || sv.ecl_bad || peer_r.tx_len ||
	    peer_r2.tx_len)
		return;

	if (!sv.ecl_pinged) {
		static const char ping_head[] = "d1:ad2:id20:",
				  ping_tail[] = "e1:q4:ping1:t2:e21:y1:qe";
		uint8_t q[64];

		/* R2 makes itself known to A, as any node can */
		sv.ecl_pinged = 1;
		memcpy(q, ping_head, sizeof(ping_head) - 1);
		eclipse_id_r2(q + sizeof(ping_head) - 1);
		memcpy(q + sizeof(ping_head) - 1 + 20, ping_tail,
		       sizeof(ping_tail) - 1);
		peer_queue(&peer_r2, q, sizeof(ping_head) - 1 + 20 +
					sizeof(ping_tail) - 1, &sa_a);
		return;
	}

	if (!sv.ecl_ponged)
		return;

	memset(idata, KRPC_ECL_TARGET, sizeof(idata));
	target = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
	if (!target) {
		sv.ecl_bad = 1;
		return;
	}

	if (!sv.ecl_started) {
		sv.ecl_started = 1;
		if (lws_dht_search(dht_a, target, 0, AF_INET, NULL, NULL) < 0) {
			lwsl_err("%s: lws_dht_search failed\n", __func__);
			sv.ecl_bad = 1;
		}
		goto bail;
	}

	memset(&t, 0, sizeof(t));
	if (lws_dht_foreach_search_node(dht_a, target, AF_INET,
					eclipse_node_cb, &t) < 0) {
		lwsl_err("%s: A has no search for the target\n", __func__);
		sv.ecl_bad = 1;
		goto bail;
	}

	if (!sv.ecl_sent) {
		uint8_t id20[20];

		/* R and R2 answer once A asked them, and B has answered A */
		if (!sv.ecl_asked || !sv.ecl_asked2 || !t.b_replied)
			goto bail;

		memset(id20, KRPC_SS_ID_R, sizeof(id20));
		eclipse_queue(&peer_r, id20, ecl_tid, 0);
		eclipse_id_r2(id20);
		eclipse_queue(&peer_r2, id20, ecl_tid2, KRPC_ECL_PER_PEER);
		sv.ecl_sent = 1;
		goto bail;
	}

	/* give A a few polls to have processed the answers */
	if (++ecl_polls < 3)
		goto bail;

	if (!t.b_replied || !t.decoys || t.decoys > 2 * KRPC_ECL_INTRO_CAP) {
		lwsl_err("%s: B present %d (replied %d), %d of R and R2's "
			 "decoys (of %d)\n", __func__, t.b_present,
			 t.b_replied, t.decoys, t.total);
		sv.ecl_bad = 1;
	} else {
		lwsl_user("%s: B kept, %d decoys taken (of %d)\n", __func__,
			  t.decoys, t.total);
		sv.ecl_ok = 1;
	}

bail:
	lws_dht_hash_destroy(&target);
}

static void
cb_b(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	size_t n;
	int from_q = from && fromlen >= sizeof(sa_q) &&
		     ((const struct sockaddr_in *)from)->sin_port ==
							sa_q.sin_port;

	(void)closure;
	(void)info_hash;

	switch (event) {
	case LWS_DHT_EVENT_DATA:
		if (from_q) {
			/* count what B delivers of Q's stream */
			for (n = 0; n < LWS_ARRAY_SIZE(q_msg); n++)
				if (data_len == strlen(q_msg[n]) &&
				    !memcmp(data, q_msg[n], data_len))
					q_seen[n]++;
			if (data_len == strlen(q_forged) &&
			    !memcmp(data, q_forged, data_len))
				q_forged_seen++;
			break;
		}
		if (data_len == data_msg_len &&
		    !memcmp(data, data_msg, data_len))
			sv.data_ok = 1;
		break;
	case LWS_DHT_EVENT_WRITE_COMPLETED:
		if (from_q)
			sv.q_b_sent = 1;
		break;
	default:
		break;
	}
}

static int
stats_of(struct lws_vhost *vh, struct lws_dht_stats *s)
{
	return lws_dht_get_stats(vh, s, NULL, NULL);
}

/*
 * C shares B's node id but not its endpoint.  Once A has answered C's ping
 * it has seen C's claim to that id; the one good node A knows must still be
 * B at B's port.
 */

static void
same_id_step(void)
{
	struct sockaddr_in sin[4];
	struct sockaddr_in6 sin6[1];
	struct lws_dht_stats sc;
	int num = (int)LWS_ARRAY_SIZE(sin), num6 = 0;

	if (!sv.extip_ok || sv.samid_ok || sv.samid_bad)
		return;

	if (!sv.samid_sent) {
		sv.samid_sent = 1;
		lws_dht_ping_node(dht_c, (struct sockaddr *)&sa_a,
				  sizeof(sa_a));
		return;
	}

	if (stats_of(vh_c, &sc) || !sc.rx_pong)
		return;

	lws_dht_get_nodes(dht_a, sin, &num, sin6, &num6);
	if (num != 1 || sin[0].sin_port != sa_b.sin_port) {
		lwsl_err("%s: A's node for B's id moved (%d good)\n",
			 __func__, num);
		sv.samid_bad = 1;
		return;
	}
#if (_LWS_ENABLED_LOGS & LLL_WARN)
	if (!samid_warned) {
		lwsl_err("%s: A didn't warn of B's id from C\n", __func__);
		sv.samid_bad = 1;
		return;
	}
#endif
	sv.samid_ok = 1;
}

static lws_dht_hash_t *
sub_hash(void)
{
	uint8_t idata[20];

	memset(idata, 0x44, sizeof(idata));

	return lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
}

/*
 * Subscribe, notify, ack: A confirms the subscription with the token B
 * gave it, B notifies A of new content, and A's ack must find the pending
 * notification by its 16-byte tid so B commits the content as delivered.
 *
 * A confirms twice with different tids, as a subscriber renewing does: B
 * must hold one subscription for A's endpoint, under the latest tid, not
 * one per tid.
 */

static void
subscription_step(void)
{
	uint8_t tid[16], sha_old[32], sha_new[32];
	lws_dht_hash_t *ih;
	int n;

	if (!sv.token_ok || sv.acked)
		return;

	ih = sub_hash();
	if (!ih)
		return;

	memset(sha_old, 0, sizeof(sha_old));
	memset(sha_new, 0x77, sizeof(sha_new));

	if (!sv.confirmed) {
		sv.confirmed = 1;
		for (n = 0; n < 2; n++) {
			lws_get_random(cx, tid, sizeof(tid));
			lws_dht_send_subscribe_confirm(dht_a,
					(struct sockaddr *)&sa_b, sizeof(sa_b),
					tid, sizeof(tid), ih, token, token_len,
					sha_old, 1);
		}
		goto bail;
	}

	/*
	 * Until B has registered A this finds no subscriber; once it has, it
	 * sends the notify.  After A's ack has been processed, B holds the
	 * new content as A's current one and there is nothing left to send.
	 */

	n = lws_dht_notify_subscribers(dht_b, ih, sha_new, NULL, 0);
	if (n > 1) {
		lwsl_err("%s: B holds %d subscriptions for A\n", __func__, n);
		sv.dup_sub = 1;
	}
	if (n > 0)
		sv.notified = 1;
	else if (!n && sv.notified && sv.notify_ok)
		sv.acked = 1;

bail:
	lws_dht_hash_destroy(&ih);
}

/*
 * Once A's subscription to sub_hash() works, A confirms a hash it has no
 * token for using that one's token, and then uses up its share of hashes on B
 */

static lws_dht_hash_t *
share_hash(uint8_t fill, uint8_t k)
{
	uint8_t idata[20];

	memset(idata, fill, sizeof(idata));
	idata[19] = k;

	return lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
}

static void
share_confirm(lws_dht_hash_t *ih, uint8_t *tok)
{
	uint8_t tid[16], sha[32];

	lws_get_random(cx, tid, sizeof(tid));
	memset(sha, 0, sizeof(sha));
	lws_dht_send_subscribe_confirm(dht_a, (struct sockaddr *)&sa_b,
				       sizeof(sa_b), tid, sizeof(tid), ih,
				       tok, 8, sha, 1);
}

static void
share_step(void)
{
	uint8_t sha[32];
	lws_dht_hash_t *ih;
	int k, stored = 0;

	if (!sv.acked || sv.share_ok || sv.share_bad)
		return;

	switch (share_state) {
	case 0:
		/* another hash, with sub_hash()'s token */
		ih = share_hash(0x45, 0);
		if (!ih)
			goto bad;
		share_confirm(ih, token);
		lws_dht_hash_destroy(&ih);

		for (k = 0; k < KRPC_SHARE_HASHES; k++) {
			ih = share_hash(KRPC_SHARE_FILL, (uint8_t)k);
			if (!ih)
				goto bad;
			lws_dht_send_subscribe(dht_a, (struct sockaddr *)&sa_b,
					       sizeof(sa_b), ih, 0, 0);
			lws_dht_hash_destroy(&ih);
		}
		share_state++;
		break;

	case 1:
		if (share_tokens != (1u << KRPC_SHARE_HASHES) - 1)
			break;

		for (k = 0; k < KRPC_SHARE_HASHES; k++) {
			ih = share_hash(KRPC_SHARE_FILL, (uint8_t)k);
			if (!ih)
				goto bad;
			share_confirm(ih, share_token[k]);
			lws_dht_hash_destroy(&ih);
		}
		share_state++;
		break;

	case 2:
		/* give B a few polls to have processed the confirms */
		if (++share_polls < 5)
			break;

		memset(sha, 0x99, sizeof(sha));

		ih = share_hash(0x45, 0);
		if (!ih)
			goto bad;
		k = lws_dht_notify_subscribers(dht_b, ih, sha, NULL, 0);
		lws_dht_hash_destroy(&ih);
		if (k) {
			lwsl_err("%s: B took a token for one hash as good for "
				 "another\n", __func__);
			goto bad;
		}

		for (k = 0; k < KRPC_SHARE_HASHES; k++) {
			ih = share_hash(KRPC_SHARE_FILL, (uint8_t)k);
			if (!ih)
				goto bad;
			if (lws_dht_notify_subscribers(dht_b, ih, sha,
						       NULL, 0) > 0)
				stored++;
			lws_dht_hash_destroy(&ih);
		}

		/* sub_hash() is one of A's share already */
		if (stored != KRPC_SHARE - 1) {
			lwsl_err("%s: B started %d of A's %d hashes, its share "
				 "left is %d\n", __func__, stored,
				 KRPC_SHARE_HASHES, KRPC_SHARE - 1);
			goto bad;
		}

		sv.share_ok = 1;
		break;
	}

	return;

bad:
	sv.share_bad = 1;
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_dht_stats sa, sb;

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, POLL_US);

	if (!sv.ping_sent) {
		sv.ping_sent = 1;
		lws_dht_ping_node(dht_a, (struct sockaddr *)&sa_b,
				  sizeof(sa_b));
	}

	if (stats_of(vh_a, &sa) || stats_of(vh_b, &sb))
		return;

	/* once the pong made A's table good, exercise the rest */

	if (sa.rx_pong && !sv.searched) {
		lws_dht_hash_t *ih;

		sv.searched = 1;

		/*
		 * Ask B to subscribe to a hash: the reply is built by the
		 * same closest-nodes + token path a get_peers reply uses,
		 * and the library's own tid must route it back so the
		 * token surfaces as the LWS_DHT_EVENT_TOKEN callback.
		 */

		ih = sub_hash();
		if (!ih) {
			lwsl_err("%s: hash create failed\n", __func__);
			lws_default_loop_exit(cx);
			return;
		}

		lws_dht_send_subscribe(dht_a, (struct sockaddr *)&sa_b,
				       sizeof(sa_b), ih, 0, 0);
		lws_dht_hash_destroy(&ih);

		sv.data_sent = 1;
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_b,
				  data_msg, data_msg_len);
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_b,
				  cap_req, strlen(cap_req));
	}

	subscription_step();
	share_step();
	same_id_step();
	error_reply_step(&sb);
	unsolicited_reply_step();
	storage_ping_step();
	martian_step();
	seq_step();
	q_step();
	search_step_check();
	eclipse_step();

	if (sv.data_ok && !sv.dead_sent) {
		sv.dead_sent = 1;
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_dead,
				  data_msg, data_msg_len);
	}

	/*
	 * A only probes nodes it holds as good, and B becomes good by
	 * answering A's maintenance find_node
	 */

	if (!sv.probed) {
		int good = 0, seen = 0;

		lws_dht_nodes(dht_a, AF_INET, &good, NULL, NULL, NULL);
		if (good) {
			lws_dht_foreach_node(dht_a, AF_INET, table_b_cb, &seen);
			sv.table_ok = !!seen;
			sv.probed = 1;
			lws_dht_test_external_ips(dht_a);
		}
	}


	/*
	 * Everything observable has been seen: B answered the ping, the
	 * subscribe round trip produced a token, the notify was acked, the
	 * data payload arrived verbatim, A's maintenance find_node probe
	 * reached B, B told A its external address, C's use of B's id did
	 * not move B's entry in A's table, B's refusal of R's broken
	 * find_node was well-formed on the wire and understood by A,
	 * R's replies to nothing A asked left A's table alone, only R's real
	 * ack completed A's transfer to it, B did not repeat itself to R
	 * on the word of an ack anyone could have sent, and R's answer to
	 * A's search did not take it over, nor did its decoys at many
	 * addresses take the second search over, and B kept A to the hash each
	 * token was for and to its share of hashes.
	 */

	if (sv.token_ok && !sv.token_ih_bad && sv.table_ok && sv.acked &&
	    !sv.dup_sub &&
	    sv.data_ok && sv.cap_ok &&
	    sv.dead_failed &&
	    sv.extip_ok && !sv.extip_bad &&
	    sv.samid_ok && !sv.samid_bad &&
	    sv.err_wire_ok && !sv.err_wire_bad &&
	    sv.err_decoded_ok && !sv.err_decoded_bad &&
	    sv.unsol_ok && !sv.unsol_bad &&
	    sv.seq_ok && !sv.seq_bad &&
	    sv.unproven_ok && !sv.unproven_bad &&
	    sv.ss_ok && !sv.ss_bad && sv.mart_ok &&
	    sv.srch_ok && !sv.srch_bad &&
	    sv.ecl_ok && !sv.ecl_bad &&
	    sv.share_ok && !sv.share_bad &&
	    sv.q_ok && !sv.q_bad &&
	    sa.tx_find_node && sb.rx_find_node &&
	    sb.rx_ping && !sa.rx_drops && !sb.rx_drops) {
		retcode = 0;
		lws_default_loop_exit(cx);
	}
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
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
	lws_dht_info_t di;
	static const struct lws_protocols protocols[] = {
		{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
		{ "krpc-raw", cb_raw, 0, 0, 0, NULL, 0 },
		{ "krpc-q", cb_q, 0, 0, 0, NULL, 0 },
		{ "krpc-r2", cb_r2, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	uint8_t ida[20], idb[20];
	const char *p;
	int port_a = 0, port_b = 0, port_c = 0, port_r = 0, port_q = 0,
	    port_r2 = 0, port_dead = 0, n = 0;

	lws_context_info_defaults(&info, NULL);
	/* the builtin options keep the emit function we set here */
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, emit_cb);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-a")))
		port_a = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-b")))
		port_b = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-c")))
		port_c = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-r")))
		port_r = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-q")))
		port_q = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-r2")))
		port_r2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-dead")))
		port_dead = atoi(p);

	if (port_a < 1 || port_a > 65535 || port_b < 1 || port_b > 65535 ||
	    port_c < 1 || port_c > 65535 || port_r < 1 || port_r > 65535 ||
	    port_q < 1 || port_q > 65535 ||
	    port_r2 < 1 || port_r2 > 65535 ||
	    port_dead < 1 || port_dead > 65535 ||
	    port_a == port_b || port_a == port_c || port_b == port_c ||
	    port_r == port_a || port_r == port_b || port_r == port_c ||
	    port_q == port_a || port_q == port_b || port_q == port_c ||
	    port_q == port_r ||
	    port_r2 == port_a || port_r2 == port_b || port_r2 == port_c ||
	    port_r2 == port_r || port_r2 == port_q ||
	    port_dead == port_a || port_dead == port_b || port_dead == port_c ||
	    port_dead == port_r || port_dead == port_q ||
	    port_dead == port_r2) {
		lwsl_err("usage: --port-a <udp port> --port-b <udp port> "
			 "--port-c <udp port> --port-r <udp port> "
			 "--port-q <udp port> --port-r2 <udp port> "
			 "--port-dead <unused udp port>\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	data_msg_len = strlen(data_msg);

	memset(&sa_a, 0, sizeof(sa_a));
	sa_a.sin_family = AF_INET;
	sa_a.sin_port = htons((uint16_t)port_a);
	sa_a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sa_b = sa_a;
	sa_b.sin_port = htons((uint16_t)port_b);
	sa_c = sa_a;
	sa_c.sin_port = htons((uint16_t)port_c);
	sa_r = sa_a;
	sa_r.sin_port = htons((uint16_t)port_r);
	sa_q = sa_a;
	sa_q.sin_port = htons((uint16_t)port_q);
	sa_dead = sa_a;
	sa_dead.sin_port = htons((uint16_t)port_dead);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "dht-krpc-a";
	vh_a = lws_create_vhost(cx, &info);
	info.vhost_name = "dht-krpc-b";
	vh_b = lws_create_vhost(cx, &info);
	info.vhost_name = "dht-krpc-c";
	vh_c = lws_create_vhost(cx, &info);
	if (!vh_a || !vh_b || !vh_c) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	memset(ida, 0x11, sizeof(ida));
	memset(idb, 0x22, sizeof(idb));

	memset(&di, 0, sizeof(di));
	di.allow_private_ads = 1; /* the nodes are all on loopback */
	di.max_hashes_per_source = KRPC_SHARE;
	di.vhost	= vh_a;
	di.cb		= cb_a;
	di.name		= "krpc-a";
	di.port		= port_a;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, ida);
		di.id = id;
		dht_a = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	di.vhost	= vh_b;
	di.cb		= cb_b;
	di.name		= "krpc-b";
	di.port		= port_b;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_b = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	/* C claims B's id from another endpoint */

	di.vhost	= vh_c;
	di.cb		= NULL;
	di.name		= "krpc-c";
	di.port		= port_c;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_c = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	if (!dht_a || !dht_b || !dht_c) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	/* R: the hand-driven KRPC peer */

	peer_r.wsi = lws_create_adopt_udp(vh_c, "127.0.0.1", port_r,
				       LWS_CAUDP_BIND, protocols[1].name, NULL,
				       NULL, NULL, NULL, "krpc-r");
	if (!peer_r.wsi) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	/* Q: the hand-driven sender of a reliable stream to B */

	peer_q.wsi = lws_create_adopt_udp(vh_c, "127.0.0.1", port_q,
				       LWS_CAUDP_BIND, protocols[2].name, NULL,
				       NULL, NULL, NULL, "krpc-q");
	if (!peer_q.wsi) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	/* R2: R's second endpoint in the second search */

	peer_r2.wsi = lws_create_adopt_udp(vh_c, "127.0.0.1", port_r2,
				       LWS_CAUDP_BIND, protocols[3].name, NULL,
				       NULL, NULL, NULL, "krpc-r2");
	if (!peer_r2.wsi) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, DEADLINE_US);
	poll_cb(&sul_poll);

	while (n >= 0)
		n = lws_service(cx, 0);

	{
		struct lws_dht_stats sa, sb;
		int fails = 0;

		if (stats_of(vh_a, &sa) || stats_of(vh_b, &sb)) {
			lwsl_err("stats unavailable\n");
			fails++;
		} else {
			if (!sa.rx_pong) {
				lwsl_err("A never saw B's pong\n");
				fails++;
			}
			if (!sb.rx_ping) {
				lwsl_err("B never saw A's ping\n");
				fails++;
			}
			if (!sv.token_ok) {
				lwsl_err("A never received B's subscription token\n");
				fails++;
			}
			if (!sv.table_ok) {
				lwsl_err("A's table didn't show B as a good "
					 "node that answered it\n");
				fails++;
			}
			if (sv.token_ih_bad) {
				lwsl_err("A's subscription token was not reported "
					 "with the hash it subscribed to\n");
				fails++;
			}
			if (sv.dup_sub) {
				lwsl_err("A's renewed subscription took a second "
					 "slot on B\n");
				fails++;
			}
			if (!sv.notified || !sv.notify_ok) {
				lwsl_err("B's notify never reached subscriber A\n");
				fails++;
			} else if (!sv.acked) {
				lwsl_err("A's notify ack never cleared B's pending "
					 "notification\n");
				fails++;
			}
			if (sa.rx_drops || sb.rx_drops) {
				lwsl_err("datagrams were dropped as unparseable "
					 "(A %u, B %u)\n",
					 sa.rx_drops, sb.rx_drops);
				fails++;
			}
			if (!sv.data_ok) {
				lwsl_err("B never received the data payload verbatim\n");
				fails++;
			}
			if (!sv.cap_ok) {
				lwsl_err("B never answered A's CAP_REQ\n");
				fails++;
			}
			if (!sv.dead_failed) {
				lwsl_err("data to a dead port never failed\n");
				fails++;
			}
			if (!sa.tx_find_node || !sb.rx_find_node) {
				lwsl_err("A's find_node maintenance probe never reached B\n");
				fails++;
			}
			if (!sv.extip_ok || sv.extip_bad) {
				lwsl_err("A did not learn its external address "
					 "from B\n");
				fails++;
			}
			if (!sv.samid_ok || sv.samid_bad) {
				lwsl_err("C's use of B's id moved or hid B's "
					 "entry in A\n");
				fails++;
			}
			if (!sv.err_wire_ok || sv.err_wire_bad) {
				lwsl_err("B's error reply was not well-formed "
					 "bencode\n");
				fails++;
			}
			if (!sv.err_decoded_ok || sv.err_decoded_bad) {
				lwsl_err("A did not decode the relayed error "
					 "reply\n");
				fails++;
			}
			if (!sv.unsol_ok || sv.unsol_bad) {
				lwsl_err("replies A never asked for changed its "
					 "routing table\n");
				fails++;
			}
			if (!sv.seq_ok || sv.seq_bad) {
				lwsl_err("A's transfer to R did not complete on "
					 "R's real ack alone\n");
				fails++;
			}
			if (!sv.mart_ok) {
				lwsl_err("A was not probed again, or believed "
					 "R's multicast address for it\n");
				fails++;
			}
			if (!sv.ss_ok || sv.ss_bad) {
				lwsl_err("a request sent with a sockaddr_storage "
					 "length had its reply dropped\n");
				fails++;
			}
			if (!sv.unproven_ok || sv.unproven_bad) {
				lwsl_err("a forged ack made B repeat itself to "
					 "R\n");
				fails++;
			}
			if (!sv.share_ok || sv.share_bad) {
				lwsl_err("B did not keep A to its tokens' hashes "
					 "and its share of hashes\n");
				fails++;
			}
			if (!sv.q_ok || sv.q_bad) {
				lwsl_err("B's receive half did not keep to Q's "
					 "session (state %d)\n", q_state);
				fails++;
			}
			if (!sv.srch_ok || sv.srch_bad) {
				lwsl_err("one host's get_peers answer took A's "
					 "search over\n");
				fails++;
			}
			if (!sv.ecl_ok || sv.ecl_bad) {
				lwsl_err("decoys at many addresses pushed B "
					 "out of A's search\n");
				fails++;
			}
		}

		if (retcode)
			retcode = fails ? 1 : 0;
	}

	lwsl_user("Completed: LWS api selftest: dht-krpc\n");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	return retcode;
}
