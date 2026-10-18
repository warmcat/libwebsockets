/*
 * Copyright (c) 2009-2011 by Juliusz Chroboczek
 * Minor changes (c) 2018 Gwiz <gwiz2009@gmail.com>
 *   Added handler for implied port & hook for dhtdigg
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *   Adaptation for lws, cleaning, modernization
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "../core/private-lib-core.h"
#include "../core-net/private-lib-core-net.h"
#include "dht-extvote.h"
#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <errno.h>

// #define DHT_VERBOSE
#define lwsl_dht_err			lwsl_err
#define lwsl_dht_warn			lwsl_warn
#define lwsl_dht_rx_warn		lwsl_notice
#define lwsl_dht_rx			lwsl_info
#define lwsl_dht_info			lwsl_info
#define lwsl_hexdump_dht		lwsl_hexdump_notice

/*
 * The maximum number of nodes that we snub.  There is probably little
 * reason to increase this value.
 */
#define DHT_MAX_BLACKLISTED		10
#define TOKEN_SIZE			8

/*
 * Request admission (see lws_dht_admit_request()): each pool admits
 * LWS_DHT_RL_POOL_RATE requests/s with bursts of LWS_DHT_RL_POOL_BURST, and
 * each source address, tracked in a table of LWS_DHT_RL_SOURCES, gets
 * LWS_DHT_RL_SRC_RATE/s with bursts of LWS_DHT_RL_SRC_BURST of that.
 */
#define LWS_DHT_RL_POOL_RATE		100
#define LWS_DHT_RL_POOL_BURST		400
#define LWS_DHT_RL_SRC_RATE		10
#define LWS_DHT_RL_SRC_BURST		40
#define LWS_DHT_RL_SOURCES		64
/*
 * When performing a search, we search for up to SEARCH_NODES closest nodes
 * to the destination, and use the additional ones to backtrack if any of
 * the target 8 turn out to be dead.
 */
#define SEARCH_NODES 			14

/* DHT Constants */
#define LWS_DHT_MAX_PING_FAILURES	3
#define LWS_DHT_NODE_DROP_FAILURES	4
#define LWS_DHT_PING_TIMEOUT_SECS	15
#define LWS_DHT_NODE_MAX_IDLE_SECS	(15 * 60)
#define LWS_DHT_NODE_EXPIRE_SECS	7200
#define LWS_DHT_IDLE_EXPIRE_SECS	120
#define LWS_DHT_PACKET_SANITY_LIMIT	1500
/*
 * Cap on concurrent transport sequencers (one per peer address).  Each one
 * allocates its dsh up front, and an unauthenticated inbound 'data' datagram
 * can create one, so this is what bounds that memory.
 */
#define LWS_DHT_MAX_TS			64
/*
 * per storage object: cap subscribers, the subscribers from one source (see
 * dht_source_key()), and peers announced by one source ip
 */
#define LWS_DHT_MAX_SUBSCRIBERS		32
#define LWS_DHT_MAX_SUBSCRIBERS_PER_SRC	4
#define LWS_DHT_MAX_PEERS_PER_SRC	8
/*
 * An external-address probe's tid is "ip" followed by a random nonce of its
 * own, so a probed node learns nothing that would let it answer for another
 * one, and the nonce is too wide to guess.  The length also keeps these
 * replies apart from the 4-byte request tids and the 16-byte notify tids.
 */
#define LWS_DHT_IP_PROBE_NONCE_LEN	8
#define LWS_DHT_IP_PROBE_TID_LEN	(2 + LWS_DHT_IP_PROBE_NONCE_LEN)
/*
 * A reliable-transport sequencer's data chunks carry the tid "sq" followed by
 * a random nonce the sequencer chose when it was made, and the receiver's acks
 * echo the tid of the chunk they answer.  Acks are replies, and replies can be
 * sent from any source address: only one carrying the nonce our sequencer for
 * that endpoint sends with comes from someone who saw our data.
 */
#define LWS_DHT_SEQ_NONCE_LEN		8
#define LWS_DHT_SEQ_TID_LEN		(2 + LWS_DHT_SEQ_NONCE_LEN)
/*
 * The tid of the peer's chunks is its session: our receive half binds to the
 * first one it sees, and takes chunks only with that tid.  A chunk with
 * another tid is a restarted peer or a forgery: it is answered with a reply
 * carrying a random challenge ("ch"), which goes to the real peer's address.
 * Only a chunk carrying the challenge back can start a new receive session,
 * so a blind spoofer can neither feed the session nor replace it.  The
 * challenge reply has no offset, so peers predating it drop it as a broken
 * ack.
 */
#define LWS_DHT_SEQ_CH_LEN		8
/* subscribes we sent whose reply we are still waiting for */
#define LWS_DHT_MAX_PENDING_SUBSCRIBES	8
/*
 * requests we sent whose reply we are still waiting for: searches, bucket
 * maintenance, pings and an external-address probe round all in flight at
 * once fit, the oldest is given up if not
 */
#define LWS_DHT_MAX_PENDING_REQUESTS	128

/* Serialization Field Sizes */
#define LWS_DHT_IPV4_VLEN                  4
#define LWS_DHT_IPV6_VLEN                  16
#define LWS_DHT_PORT_VLEN                  2
#define LWS_DHT_NODE_INFO_IP4_VLEN         (LWS_DHT_IPV4_VLEN + LWS_DHT_PORT_VLEN) /* 6 */
#define LWS_DHT_NODE_INFO_IP6_VLEN         (LWS_DHT_IPV6_VLEN + LWS_DHT_PORT_VLEN) /* 18 */

/* Legacy encoding uses a fixed 20-byte SHA1 hash */
#define LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN  (LWS_DHT_SHA1_HASH_LEN + LWS_DHT_NODE_INFO_IP4_VLEN) /* 26 */
#define LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN  (LWS_DHT_SHA1_HASH_LEN + LWS_DHT_NODE_INFO_IP6_VLEN) /* 38 */

/* Extended encoding prepends a 2-byte header (hash_type + hash_len) */
#define LWS_DHT_NODE_INFO_HASH_HDR_VLEN    2


#ifdef _WIN32
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT			WSAEAFNOSUPPORT
#endif
#endif

#define DHT_FIND_NODE	1
#define DHT_GET_PEERS	2
#define DHT_ANNOUNCE_PEER 3
#define DHT_SUBSCRIBE	 4
#define DHT_SUBSCRIBE_CONFIRM 5
#define DHT_NOTIFY       6
#define DHT_DATA         7
#define DHT_REPLY        8
#define DHT_ERROR        9
#define DHT_PING        10
#define DHT_PEER_ANNOUNCED 11

#define DHT_MSG_TYPE_MASK	0x0f
#define WANT4				1
#define WANT6				2

/* We set sin_family to 0 to mark unused slots. */
#if AF_INET == 0 || AF_INET6 == 0
#error Platform seems to lack both AF_INET and AF_INET6
#endif

#if !defined(MAX)
#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#endif
#if !defined(MIN)
#define MIN(x, y) ((x) <= (y) ? (x) : (y))
#endif

/* a token bucket, refilled lazily when found empty */
typedef struct lws_dht_tb {
	time_t			time;		/* last refill */
	int			tokens;
} lws_dht_tb_t;

#if defined(LWS_WITH_DHT_BACKEND)

struct node {
	lws_dht_hash_t          *id;
	struct sockaddr_storage ss;
	size_t                  sslen;
	time_t                  time;                /* time of last message received */
	time_t                  reply_time;          /* time of last correct reply received */
	time_t                  pinged_time;         /* time of last request */
	int                     pinged;              /* how many requests we sent since last reply */
	uint8_t                 bep42_ok;            /* id conforms to BEP42 for its address (or private) */
	lws_dll2_t              list;                /* bucket ->nodes membership */
};

/* how many routing table entries one address (IPv4, or IPv6 /64) may hold in a bucket */
#define LWS_DHT_MAX_SAME_ADS_PER_BUCKET	2
/* ... and how many candidates it may hold in one search's node list */
#define LWS_DHT_MAX_SAME_ADS_PER_SEARCH	2
/*
 * how many unverified candidates (not yet replied) one search may hold, in its
 * node list and backlog together, that were introduced by the nodes list of
 * one host's replies
 */
#define LWS_DHT_MAX_INTRODUCED_PER_SEARCH	(SEARCH_NODES / 4)
/* candidates a search keeps back, to fall back on when ones it asks fail */
#define LWS_DHT_SEARCH_BACKLOG		8

struct bucket {
	int                     af;
	lws_dht_hash_t          *first;
	time_t                  time;                   /* time of last reply in this bucket */
	lws_dll2_owner_t        nodes;                   /* node list, nodes.count is node count */
	struct sockaddr_storage cached;			/* the address of a likely candidate */
	size_t                  cachedlen;
	lws_dll2_t              list;                /* ctx ->buckets / ->buckets6 membership */
};

struct search_node {
	lws_dht_hash_t          *id;
	struct sockaddr_storage ss;
	size_t                  sslen;
	time_t                  request_time;        /* the time of the last unanswered request */
	time_t                  reply_time;          /* the time of the last reply */
	int                     pinged;
	uint8_t                 token[40];
	size_t                  token_len;
	int                     replied;             /* whether we have received a reply */
	int                     acked;               /* whether they acked our announcement */
	lws_sockaddr46          intro;               /* who listed it, family 0: our table */
};

/* a candidate held back in a search's backlog */
struct search_cand {
	lws_dht_hash_t          *id;
	struct sockaddr_storage ss;
	size_t                  sslen;
	lws_sockaddr46          intro;               /* as search_node.intro */
};

struct search {
	unsigned short          tid;
	int                     af;
	time_t                  step_time;           /* the time of the last search_step */
	lws_dht_hash_t          *id;
	unsigned short          port;                /* 0 for pure searches */
	int                     done;
	struct search_node      nodes[SEARCH_NODES];
	int                     numnodes;
	/* sorted by distance like nodes[]; never asked until moved into it */
	struct search_cand      backlog[LWS_DHT_SEARCH_BACKLOG];
	int                     numbacklog;
	lws_dll2_t              list;                /* ctx ->searches membership */
};

struct peer {
	time_t                  time;
	uint8_t                 ip[16];
	unsigned short          len;
	unsigned short          port;
};

struct subscriber {
	lws_dll2_t              list;                /* storage ->subscribers membership */
	struct sockaddr_storage ss;
	size_t                  sslen;
	uint8_t                 tid[16];
	size_t                  tid_len;
	time_t                  expire;
	uint8_t                 current_sha256[32];
	int                     pending_notify;
	int                     notify_retries;
	time_t                  last_notify;
	uint8_t                 pending_sha256[32];
};

struct storage {
	lws_dht_hash_t          *id;
	int                     numpeers, maxpeers;
	struct peer             *peers;
	lws_dll2_owner_t        subscribers;
	lws_dll2_t              list;                /* ctx ->storage membership */
	/* the dht_source_key() of the host it was started for, if not us */
	uint8_t                 src[LWS_DHT_EXTVOTE_KEY_LEN];
	uint8_t                 src_af;              /* 0: started by us */
};

#endif

struct lws_dht_verb {
	const char *name;
	const struct lws_protocols *protocol;
};

struct lws_dht_verb_list {
	lws_dll2_t		list;
	struct lws_dht_verb	v;
};

struct lws_dht_ctx {
	struct lws_vhost	*vhost;
	struct lws		*wsi_v4;
	struct lws		*wsi_v6;
	lws_dll2_t		list;
	char			*name;
	lws_sorted_usec_list_t	sul;
	lws_dht_callback_t	*cb;
	void			*closure;

	lws_dht_hash_t		*myid;

#if defined(LWS_WITH_DHT_BACKEND)
	lws_dll2_owner_t	buckets;
	lws_dll2_owner_t	buckets6;
	lws_dll2_owner_t	storage;

	lws_dll2_owner_t	searches;
	unsigned short		search_id;
#endif

	struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED];
	int			next_blacklisted;

	/* the vote on our external address: [0] IPv4, [1] IPv6 */
	lws_dht_extvote_t	extvote[2];

	/*
	 * The nodes the current external-address probe round was sent to: a
	 * reply about our address counts only from one of these, once each,
	 * and only carrying the random nonce that was sent to that node.
	 */
	struct {
		struct sockaddr_storage ss;
		size_t			sslen;
		uint8_t			nonce[LWS_DHT_IP_PROBE_NONCE_LEN];
		uint8_t			answered;
	} ip_probes[16];
	int			ip_probe_count;

	/*
	 * The subscribes we sent and have had no reply to: a reply surfaces
	 * its token only if it answers one of these, from the node it went
	 * to, so nobody can make us react to a token we never asked for.
	 */
	struct {
		struct sockaddr_storage ss;
		size_t			sslen;	/* 0 = free */
		time_t			sent;
		unsigned short		seq;
		/* the hash subscribed to, reported with the token */
		uint8_t			ih_type;
		uint8_t			ih_len;
		uint8_t			ih[LWS_GENHASH_LARGEST];
	} sb_pending[LWS_DHT_MAX_PENDING_SUBSCRIBES];

	/*
	 * Every request we sent and have had no reply to, with the endpoint
	 * it went to.  Anyone can send y=r from any address naming any tid,
	 * so a reply is taken only if it answers one of these, from where
	 * that went, once: only that proves anything about the endpoint, and
	 * only that may change our routing table (G-119).
	 */
	struct {
		lws_sockaddr46		sa46;
		time_t			sent;	/* 0 = free */
		uint8_t			tid[LWS_DHT_IP_PROBE_TID_LEN];
		uint8_t			tid_len;
	} req_pending[LWS_DHT_MAX_PENDING_REQUESTS];

#if defined(LWS_WITH_DHT_BACKEND)
	time_t			search_time;
	time_t			confirm_nodes_time;
	time_t			rotate_secrets_time;
	time_t			mybucket_grow_time;
	time_t			mybucket6_grow_time;
	time_t			expire_stuff_time;
#endif

	/*
	 * Request admission: a bucket per recent source address (IPv4
	 * address, IPv6 /64), then one pool for the good nodes of our
	 * routing table at their known endpoint and one for everybody else
	 */
	struct {
		lws_dht_tb_t		tb;
		time_t			last;	/* last request, for LRU */
		uint8_t			key[16];
		uint8_t			af;	/* 0 = free */
	} rl_src[LWS_DHT_RL_SOURCES];
	lws_dht_tb_t		rl_known;
	lws_dht_tb_t		rl_general;

	struct lws_dht_stats	stats_history[LWS_DHT_STAT_BUCKETS];
	struct lws_dht_stats	stats_current;
	int			stats_history_head;
	lws_sorted_usec_list_t	sul_stats;
	lws_sorted_usec_list_t	sul_ip_monitor;

	time_t			now;

	uint8_t			secret[16]; /* token key, rotated */
	uint8_t			oldsecret[16];
	uint8_t			my_v[9];
	uint8_t			aux;

	uint8_t			have_v:1;
	uint8_t			legacy:1;
	uint8_t			allow_private_ads:1;
	uint8_t			id_random:1; /* myid was not given: BEP42 may replace it */

	unsigned int		max_hashes_per_source;

	const char		*fallback_nodes_path;
	const char		*iface;
	lws_dht_blacklist_cb_t	*blacklist_cb;
	lws_dht_hash_cb_t	*hash_cb;
	lws_dht_capture_announce_cb_t *capture_announce_cb;

	lws_dll2_owner_t	ts_owner;
	lws_dll2_owner_t	verb_owner;
};

#if defined(LWS_WITH_DHT_BACKEND)
/*
 * The bucket chains are dll2 owners, but the code needs to walk them in
 * id order by struct bucket *.  These helpers hide the container_of dance.
 */

static LWS_INLINE struct bucket *
bucket_head(struct lws_dht_ctx *ctx, int af)
{
	lws_dll2_t *d = lws_dll2_get_head(af == AF_INET ? &ctx->buckets :
							  &ctx->buckets6);

	return d ? lws_container_of(d, struct bucket, list) : NULL;
}

static LWS_INLINE struct bucket *
bucket_next(struct bucket *b)
{
	return lws_dll2_get_next(
		&b->list) ? lws_container_of(lws_dll2_get_next(&b->list), struct bucket, list)
			    : NULL;
}
#endif


typedef struct lws_dht_ts {
	lws_dll2_t			list;
	struct lws_transport_sequencer	*ts;
	struct sockaddr_storage		sa;
	size_t				salen;
	struct lws_dht_ctx		*ctx;
	lws_sorted_usec_list_t		sul_idle;
	/* "sq" + our nonce, sent with each chunk; an ack must echo it */
	uint8_t				tx_tid[LWS_DHT_SEQ_TID_LEN];
	/* the challenge the peer asked us to prove our session with */
	uint8_t				tx_ch[LWS_DHT_SEQ_CH_LEN];
	/* the peer's session: the tid of its chunks, echoed in our acks */
	uint8_t				rx_tid[16];
	size_t				rx_tid_len;
	/* what a chunk with another tid must carry to start a new session */
	uint8_t				rx_ch[LWS_DHT_SEQ_CH_LEN];
	/*
	 * nonzero while the sequencer is calling back into the consumer, ie,
	 * delivering data or reporting the session's end: whatever the
	 * callback sends, it must not recycle this sequencer from under the
	 * call (G-181), see dht_ts_create()
	 */
	uint8_t				in_cb;
	uint8_t				tx_ch_set:1;
} lws_dht_ts_t;

struct lws_dht_mparams {
	uint8_t			tid[16];
	uint8_t			nodes[256];
	uint8_t			nodes6[1024];
	uint8_t			token[128];
	uint8_t			values[2048];
	uint8_t			values6[2048];
	size_t			tid_len;
	size_t			nodes_len;
	size_t			nodes6_len;
	size_t			token_len;
	size_t			values_len;
	size_t			values6_len;
	uint8_t			sha256[32];
	lws_dht_hash_t		*id;
	lws_dht_hash_t		*info_hash;
	lws_dht_hash_t		*target;
	unsigned short		port;
	int			want;

	uint8_t			sender_ip[16];
	int			sender_ip_len;
	unsigned short		sender_port;

	const uint8_t		*data;
	size_t			data_len;

	uint64_t		offset;
	uint64_t		len;
	int			status;

	lws_transport_sequencer_sack_block_t sack[4];
	uint8_t			num_sack;

	/* sequencer session challenge, or answer to one, if ch_len */
	uint8_t			ch[LWS_DHT_SEQ_CH_LEN];
	uint8_t			ch_len;

	/* DHT_ERROR only: the "e" list, message pointing into the datagram */
	const uint8_t		*error_msg;
	size_t			error_msg_len;
	int			error_code;
};

int lws_dht_hash_validate(int type, int len);
int lws_dht_hash_copy(lws_dht_hash_t *dest, const lws_dht_hash_t *src);
int lws_dht_hash_is_zero(const lws_dht_hash_t *h);
lws_dht_hash_t * lws_dht_hash_dup(const lws_dht_hash_t *src);
int lws_dht_hash_cmp(const lws_dht_hash_t *a, const lws_dht_hash_t *b);
void lws_dht_hash(struct lws_dht_ctx *ctx, void *hash_return, int hash_size, const void *v1, int len1, const void *v2, int len2, const void *v3, int len3);
int id_cmp(const lws_dht_hash_t *restrict id1, const lws_dht_hash_t *restrict id2);
int xorcmp(const lws_dht_hash_t *id1, const lws_dht_hash_t *id2, const lws_dht_hash_t *ref);
int lowbit(const lws_dht_hash_t *id);
int common_bits(const lws_dht_hash_t *id1, const lws_dht_hash_t *id2);
#if defined(LWS_WITH_DHT_BACKEND)
struct bucket * find_bucket(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int af);
struct bucket * previous_bucket(struct bucket *b);
struct node * find_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int af);
int node_good(struct lws_dht_ctx *ctx, struct node *node);
void blacklist_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen);
struct node * maybe_new_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen, int confirm);
int dht_endpoint_refused(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen);
int expire_buckets(struct lws_dht_ctx *ctx, lws_dll2_owner_t *bo);
void lws_dht_dump_tables(struct lws_dht_ctx *ctx);
int bucket_maintenance(struct lws_dht_ctx *ctx, int af);
int neighbourhood_maintenance(struct lws_dht_ctx *ctx, int af);
struct search * find_search(struct lws_dht_ctx *ctx, unsigned short tid, int af);
struct search_node *search_awaiting_reply_from(struct lws_dht_ctx *ctx, struct search *sr, const struct sockaddr *sa);
int insert_search_node(struct lws_dht_ctx *ctx, lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen, struct search *sr, int replied, const uint8_t *token, size_t token_len, const struct sockaddr *intro);
void search_free_nodes(struct search *sr);
void expire_searches(struct lws_dht_ctx *ctx);
int search_send_get_peers(struct lws_dht_ctx *ctx, struct search *sr, struct search_node *n);
void search_step(struct lws_dht_ctx *ctx, struct search *sr, lws_dht_callback_t *callback, void *closure);
struct storage * find_storage(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id);
struct storage * storage_get(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *src);
int storage_store(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, unsigned short port, int ours);
int expire_storage(struct lws_dht_ctx *ctx);
void lws_dht_periodic_cb(lws_sorted_usec_list_t *sul);
#endif
int lws_dht_process_packet(struct lws_dht_ctx *ctx, const void *buf, size_t buflen, const struct sockaddr *from, size_t fromlen);

/*
 * Compare two socket addresses by family, address and port; 1 if they are
 * the same peer endpoint.  Uses the lws sa46 address comparison (which
 * normalizes v4 to v4-in-v6) plus the port: the sequencer table and the
 * search reply matching key on the full endpoint, so they must not alias
 * two peers behind one NAT address, or accept a reply from the same
 * address on a different port.
 */

static LWS_INLINE int
dht_sa_same_peer(const struct sockaddr *a, const struct sockaddr *b)
{
	const lws_sockaddr46 *x = (const lws_sockaddr46 *)a,
			      *y = (const lws_sockaddr46 *)b;

	if (lws_sa46_compare_ads(x, y))
		return 0;

#if defined(LWS_WITH_IPV6)
	if (x->sa4.sin_family == AF_INET6)
		return x->sa6.sin6_port == y->sa6.sin6_port;
#endif

	return x->sa4.sin_port == y->sa4.sin_port;
}

/* the port of a v4 or v6 socket address, in network order */

static LWS_INLINE uint16_t
dht_sa_port(const struct sockaddr *a)
{
#if defined(LWS_WITH_IPV6)
	if (a->sa_family == AF_INET6)
		return ((const struct sockaddr_in6 *)a)->sin6_port;
#endif

	return ((const struct sockaddr_in *)a)->sin_port;
}
/*
 * Bencode emission cursor.  All TX builders compose into a fixed buffer
 * through these bounds-checked appends; a failed append refuses the whole
 * datagram.
 */

typedef struct dht_txbuf {
	char	*buf;	/**< packet buffer being composed into */
	size_t	 len;	/**< bytes composed so far */
	size_t	 size;	/**< bytes available at buf */
} dht_txbuf_t;

int dht_tx_raw(dht_txbuf_t *t, const void *v, size_t vl);
int dht_tx_lit(dht_txbuf_t *t, const char *lit);
int dht_tx_str(dht_txbuf_t *t, const void *v, size_t vl);
int dht_tx_int(dht_txbuf_t *t, uint64_t n);
int dht_tx_id_len(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id);
int dht_tx_id_raw(struct lws_dht_ctx *ctx, dht_txbuf_t *t, const lws_dht_hash_t *id);
int dht_tx_id(struct lws_dht_ctx *ctx, dht_txbuf_t *t, const lws_dht_hash_t *id);
int dht_tx_v(struct lws_dht_ctx *ctx, dht_txbuf_t *t);
int dht_tx_ip(dht_txbuf_t *t, const struct sockaddr *sa);
int dht_tx_want(dht_txbuf_t *t, int want);
void make_tid(uint8_t *tid_return, const char *prefix, unsigned short seqno);
void make_tid_random(struct lws_dht_ctx *ctx, uint8_t *tid_return,
		     const char *prefix);
int dht_req_pending_take(struct lws_dht_ctx *ctx, const uint8_t *tid,
			 size_t tid_len, const struct sockaddr *from);
int tid_match(const uint8_t *tid, const char *prefix, unsigned short *seqno_return);
int node_blacklisted(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen);
int dht_send(struct lws_dht_ctx *ctx, const void *buf, size_t len, const struct sockaddr *sa, size_t salen);
int send_ping(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, const uint8_t *tid, size_t tid_len);
int send_pong(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, const uint8_t *tid, size_t tid_len);
#if defined(LWS_WITH_DHT_BACKEND)
int send_cached_ping(struct lws_dht_ctx *ctx, struct bucket *b);
void mark_as_pinged(struct lws_dht_ctx *ctx, struct node *n, struct bucket *b);
void flush_search_node(struct search_node *n, struct search *sr);
int send_get_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash, int want, int confirm);
int send_announce_peer(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash, unsigned short port, uint8_t *token, size_t token_len, int confirm);
int rotate_secrets(struct lws_dht_ctx *ctx);
void make_token(struct lws_dht_ctx *ctx, const struct sockaddr *sa, const lws_dht_hash_t *ih, int old, uint8_t *token_return);
int token_match(struct lws_dht_ctx *ctx, const uint8_t *token, size_t token_len, const struct sockaddr *sa, const lws_dht_hash_t *ih);
int send_find_node(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, const uint8_t *tid, size_t tid_len, const lws_dht_hash_t *target, int want, int confirm);
int send_closest_nodes(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, struct lws_dht_mparams *mp, const lws_dht_hash_t *id, int af, struct storage *st);
int send_error(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, const uint8_t *tid, size_t tid_len, int code, const char *message);
void lws_dht_clear_pending_notify(struct lws_dht_ctx *ctx, const uint8_t *tid, size_t tid_len, const struct sockaddr *from);
void lws_dht_capture_announce(struct lws_dht_ctx *ctx, lws_dht_hash_t *hash, const struct sockaddr *fromaddr, unsigned short prt);
#endif
int is_martian(const struct lws_dht_ctx *ctx, const struct sockaddr *sa);
int lws_dht_ads_is_private(const struct sockaddr *sa);
void lws_dht_bep42_own_id(struct lws_dht_ctx *ctx, const struct sockaddr *sa);
int lws_dht_peer_known(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *from);
int lws_dht_admit_request(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *from);
void lws_dht_ip_vote(struct lws_dht_ctx *ctx, const struct sockaddr *from, size_t fromlen, const lws_sockaddr46 *reported);
struct lws_transport_sequencer * lws_dht_ts_rx(struct lws_dht_ctx *ctx, const struct sockaddr *from, size_t fromlen, const lws_dht_hash_t *id);
lws_dht_ts_t * lws_dht_ts_find(struct lws_dht_ctx *ctx, const struct sockaddr *sa);
void lws_dht_ts_touch(lws_dht_ts_t *dts);
int dht_tx_challenge(lws_dht_ts_t *dts, const uint8_t *tid, size_t tid_len);
int lws_dht_get_external_addr(struct lws_dht_ctx *ctx, struct sockaddr_storage *ss, size_t *sslen);
struct lws_dht_ctx * lws_dht_create(const lws_dht_info_t *info);
void * lws_dht_get_closure(struct lws_dht_ctx *ctx);
void lws_dht_destroy(struct lws_dht_ctx **pctx);
int lws_dht_get_nodes(struct lws_dht_ctx *ctx, struct sockaddr_in *sin, int *num, struct sockaddr_in6 *sin6, int *num6);
int lws_dht_insert_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, struct sockaddr *sa, size_t salen);
int lws_dht_ping_node(struct lws_dht_ctx *ctx, struct sockaddr *sa, size_t salen);
int lws_dht_send_data_at(struct lws_dht_ctx *ctx, const struct sockaddr *dest, uint64_t offset, const void *data, size_t len);
int lws_dht_msg_gen(char *out, size_t len, const char *verb, const char *hash, unsigned long long offset, unsigned long long len_val);
int lws_dht_msg_parse(const char *in, size_t len, struct lws_dht_msg *out);
int
lws_dht_register_verbs(struct lws_dht_ctx *ctx, const char **verbs, int count, const struct lws_protocols *protocol);
struct lws_dht_ctx * lws_dht_get_by_name(struct lws_vhost *vhost, const char *name);
