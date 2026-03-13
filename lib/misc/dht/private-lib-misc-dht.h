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
#define MAX_TOKEN_BUCKET_TOKENS		400
#define TOKEN_SIZE			8
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

#if defined(LWS_WITH_DHT_BACKEND)

struct node {
	lws_dht_hash_t          *id;
	struct sockaddr_storage ss;
	size_t                  sslen;
	time_t                  time;                /* time of last message received */
	time_t                  reply_time;          /* time of last correct reply received */
	time_t                  pinged_time;         /* time of last request */
	int                     pinged;              /* how many requests we sent since last reply */
	struct node *next;
};

struct bucket {
	int                     af;
	lws_dht_hash_t          *first;
	int                     count;                  /* number of nodes */
	int                     time;                   /* time of last reply in this bucket */
	struct node *           nodes;
	struct sockaddr_storage cached;			/* the address of a likely candidate */
	size_t                  cachedlen;
	struct bucket *         next;
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
	struct search           *next;
};

struct peer {
	time_t                  time;
	uint8_t                 ip[16];
	unsigned short          len;
	unsigned short          port;
};

struct subscriber {
	struct subscriber       *next;
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
	struct subscriber       *subscribers;
	struct storage          *next;
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
	struct bucket		*buckets;
	struct bucket		*buckets6;
	struct storage		*storage;
	int			numstorage;

	struct search		*searches;
	int			numsearches;
	unsigned short		search_id;
#endif

	struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED];
	int			next_blacklisted;

	struct {
		struct sockaddr_storage ss;
		size_t			sslen;
		int			count;
	} reported_ads[8];

	int			num_reported_ads;
	int			external_ads_set;

#if defined(LWS_WITH_DHT_BACKEND)
	time_t			search_time;
	time_t			confirm_nodes_time;
	time_t			rotate_secrets_time;
	time_t			mybucket_grow_time;
	time_t			mybucket6_grow_time;
	time_t			expire_stuff_time;

	time_t			token_bucket_time;
	int			token_bucket_tokens;
#endif

	struct lws_dht_stats	stats_history[LWS_DHT_STAT_BUCKETS];
	struct lws_dht_stats	stats_current;
	int			stats_history_head;
	lws_sorted_usec_list_t	sul_stats;

	struct timeval		now;

	uint8_t			secret[8];
	uint8_t			oldsecret[8];
	uint8_t			my_v[9];
	uint8_t			aux;

	uint8_t			have_v:1;
	uint8_t			legacy:1;

	const char		*fallback_nodes_path;
	const char		*iface;
	lws_dht_blacklist_cb_t	*blacklist_cb;
	lws_dht_hash_cb_t	*hash_cb;
	lws_dht_capture_announce_cb_t *capture_announce_cb;

	lws_dll2_owner_t	ts_owner;
	lws_dll2_owner_t	verb_owner;
};


typedef struct lws_dht_ts {
	lws_dll2_t			list;
	struct lws_transport_sequencer	*ts;
	struct sockaddr_storage		sa;
	size_t				salen;
	struct lws_dht_ctx		*ctx;
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
struct bucket * previous_bucket(struct lws_dht_ctx *ctx, struct bucket *b);
struct node * find_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int af);
int node_good(struct lws_dht_ctx *ctx, struct node *node);
void blacklist_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen);
struct node * maybe_new_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen, int confirm);
int expire_buckets(struct lws_dht_ctx *ctx, struct bucket *b);
void lws_dht_dump_tables(struct lws_dht_ctx *ctx);
int bucket_maintenance(struct lws_dht_ctx *ctx, int af);
int neighbourhood_maintenance(struct lws_dht_ctx *ctx, int af);
struct search * find_search(struct lws_dht_ctx *ctx, unsigned short tid, int af);
int insert_search_node(struct lws_dht_ctx *ctx, lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen, struct search *sr, int replied, const uint8_t *token, size_t token_len);
void expire_searches(struct lws_dht_ctx *ctx);
int search_send_get_peers(struct lws_dht_ctx *ctx, struct search *sr, struct search_node *n);
void search_step(struct lws_dht_ctx *ctx, struct search *sr, lws_dht_callback_t *callback, void *closure);
struct storage * find_storage(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id);
int storage_store(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, unsigned short port);
int expire_storage(struct lws_dht_ctx *ctx);
void lws_dht_periodic_cb(lws_sorted_usec_list_t *sul);
#endif
int lws_dht_process_packet(struct lws_dht_ctx *ctx, const void *buf, size_t buflen, const struct sockaddr *from, size_t fromlen);
int dht_tx_check(size_t size, size_t offset, size_t delta);
int dht_tx_skip(size_t *offset, size_t size, size_t delta);
int dht_tx_id_len(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id);
void * dht_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
int dht_tx_copy__advance_offset(char *buf, size_t *offset, size_t size, const void *src, size_t delta);
int dht_tx_add_v(char *buf, size_t *offset, size_t size, struct lws_dht_ctx *ctx);
int dht_tx_add_ip(char *buf, size_t *offset, size_t size, const struct sockaddr *sa);
int dht_put_id__advance_offset(struct lws_dht_ctx *ctx, char *buf, size_t *offset, size_t size, const lws_dht_hash_t *id);
void make_tid(uint8_t *tid_return, const char *prefix, unsigned short seqno);
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
int send_notify(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, const uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash, const uint8_t *sha256);
int send_announce_peer(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash, unsigned short port, uint8_t *token, size_t token_len, int confirm);
int rotate_secrets(struct lws_dht_ctx *ctx);
void make_token(struct lws_dht_ctx *ctx, const struct sockaddr *sa, int old, uint8_t *token_return);
int token_match(struct lws_dht_ctx *ctx, const uint8_t *token, size_t token_len, const struct sockaddr *sa);
int send_find_node(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, const uint8_t *tid, size_t tid_len, const lws_dht_hash_t *target, int want, int confirm);
int send_closest_nodes(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, struct lws_dht_mparams *mp, const lws_dht_hash_t *id, int af, struct storage *st);
int send_error(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen, const uint8_t *tid, size_t tid_len, int code, const char *message);
void lws_dht_clear_pending_notify(struct lws_dht_ctx *ctx, const uint8_t *tid, size_t tid_len);
int token_bucket(struct lws_dht_ctx *ctx);
void lws_dht_capture_announce(struct lws_dht_ctx *ctx, lws_dht_hash_t *hash, const struct sockaddr *fromaddr, unsigned short prt);
#endif
int is_martian(const struct sockaddr *sa);
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
