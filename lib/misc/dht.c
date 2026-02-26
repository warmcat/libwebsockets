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
#include <arpa/inet.h>
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

#if !defined(MSG_CONFIRM)
#define MSG_CONFIRM			0
#endif

#ifdef _WIN32
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT			WSAEAFNOSUPPORT
#endif
#endif

typedef enum {
	DHT_ERROR,
	DHT_REPLY,
	DHT_PING,
	DHT_FIND_NODE,
	DHT_GET_PEERS,
	DHT_ANNOUNCE_PEER,
	DHT_PEER_ANNOUNCED,
	DHT_DATA,
} lws_dht_message_type_t;

#define WANT4 1
#define WANT6 2

/* We set sin_family to 0 to mark unused slots. */
#if AF_INET == 0 || AF_INET6 == 0
#error Platform seems to lack AF_INET or AF_INET6
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
/* nothing */
#elif defined(__GNUC__)
#define inline __inline
#if  (__GNUC__ >= 3)
#define restrict __restrict
#else
#define restrict /**/
#endif
#else
#define inline /**/
#define restrict /**/
#endif

#if !defined(MAX)
#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#endif
#if !defined(MIN)
#define MIN(x, y) ((x) <= (y) ? (x) : (y))
#endif

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

struct storage {
	lws_dht_hash_t          *id;
	int                     numpeers, maxpeers;
	struct peer             *peers;
	struct storage          *next;
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

	struct bucket		*buckets;
	struct bucket		*buckets6;
	struct storage		*storage;
	int			numstorage;

	struct search		*searches;
	int			numsearches;
	unsigned short		search_id;

	struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED];
	int			next_blacklisted;

	struct {
		struct sockaddr_storage ss;
		size_t			sslen;
		int			count;
	} reported_ads[8];

	int			num_reported_ads;
	int			external_ads_set;

	time_t			search_time;
	time_t			confirm_nodes_time;
	time_t			rotate_secrets_time;
	time_t			mybucket_grow_time;
	time_t			mybucket6_grow_time;
	time_t			expire_stuff_time;

	time_t			token_bucket_time;
	int			token_bucket_tokens;

	struct timeval		now;

	uint8_t			secret[8];
	uint8_t			oldsecret[8];
	uint8_t			my_v[9];
	uint8_t			aux;

	uint8_t			have_v:1;
	uint8_t			legacy:1;

	const char		*iface;
	lws_dht_blacklist_cb_t	*blacklist_cb;
	lws_dht_hash_cb_t	*hash_cb;
	lws_dht_capture_announce_cb_t *capture_announce_cb;

	lws_dll2_owner_t	ts_owner;
	lws_dll2_owner_t	verb_owner;
};

#define CHECK(offset, delta, size)								\
	do { if ((int)(delta) < 0 || (size_t)(offset) + (size_t)(delta) > (size_t)(size))	\
		goto fail; } while(0)

#define INC(offset, delta, size)								\
	do { CHECK(offset, delta, size); 							\
	     offset = (size_t)(offset) + (size_t)(delta); } while(0)

static void *
dht_memmem(const void *haystack, size_t haystacklen,
	   const void *needle, size_t needlelen)
{
	const uint8_t *h = (const uint8_t *)haystack;
	const uint8_t *n = (const uint8_t *)needle;
	size_t i;

	if (needlelen > haystacklen)
		return NULL;

	for (i = 0; i <= haystacklen - needlelen; i++) {
		if (memcmp(h + i, n, needlelen) == 0)
			return (void *)(h + i);
	}

	return NULL;
}

#define COPY(buf, offset, src, delta, size)							\
	do { CHECK(offset, delta, size); 							\
	     memcpy((char *)buf + (size_t)(offset), src, (size_t)(delta));			\
	     offset = (size_t)(offset) + (size_t)(delta); } while(0)

#define ADD_V(buf, offset, ctx, size)								\
	do { if (ctx->have_v) {                                   				\
	     COPY(buf, offset, ctx->my_v, (unsigned int)sizeof(ctx->my_v), size); 		\
	} } while (0)

#define ADD_IP(buf, offset, sa, size)								\
	do { 											\
		char _tmp[32]; 									\
		int _rc; 									\
		if (sa->sa_family == AF_INET) { 						\
			struct sockaddr_in *_sin = (struct sockaddr_in *)sa;			\
			_rc = lws_snprintf(_tmp, sizeof(_tmp), "2:ip6:"); 			\
			COPY(buf, offset, _tmp, _rc, size); 					\
			COPY(buf, offset, &_sin->sin_addr, 4, size); 				\
			COPY(buf, offset, &_sin->sin_port, 2, size); 				\
		} else if (sa->sa_family == AF_INET6) {						\
			struct sockaddr_in6 *_sin6 = (struct sockaddr_in6 *)sa;			\
			_rc = lws_snprintf(_tmp, sizeof(_tmp), "2:ip18:");			\
			COPY(buf, offset, _tmp, _rc, size);					\
			COPY(buf, offset, &_sin6->sin6_addr, 16, size);				\
			COPY(buf, offset, &_sin6->sin6_port, 2, size);				\
		}										\
	} while (0)

static const uint8_t zeroes[20] = {0};
static const uint8_t v4prefix[16] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

static int
lws_dht_hash_validate(int type, int len)
{
	switch (type) {
	case LWS_DHT_HASH_TYPE_SHA1:
		return len == 20;
	case LWS_DHT_HASH_TYPE_SHA256:
		return len == 32;
	case LWS_DHT_HASH_TYPE_SHA512:
		return len == 64;
	case LWS_DHT_HASH_TYPE_BLAKE3:
		return len == 32;
	}

	return 0;
}

LWS_VISIBLE lws_dht_hash_t *
lws_dht_hash_create(int type, int len, const uint8_t *data)
{
	lws_dht_hash_t *h;

	if (!lws_dht_hash_validate(type, len)) {
		lwsl_dht_warn("%s: invalid hash type %d len %d\n", __func__, type, len);

		return NULL;
	}

	h = lws_malloc(sizeof(*h) + (size_t)len, __func__);
	if (!h)
		return NULL;

	h->type = (uint8_t)type;
	h->len = (uint8_t)len;
	if (data)
		memcpy(h->id, data, (size_t)len);
	else
		memset(h->id, 0, (size_t)len);

	return h;
}

static int
lws_dht_hash_copy(lws_dht_hash_t *dest, const lws_dht_hash_t *src)
{
	if (dest->len < src->len)
		return -1;
	dest->type = src->type;
	memcpy(dest->id, src->id, (size_t)src->len);

	return 0;
}

LWS_VISIBLE void
lws_dht_hash_destroy(lws_dht_hash_t **p)
{
	if (!*p)
		return;
	lws_free(*p);
	*p = NULL;
}

int
lws_dht_hash_is_zero(const lws_dht_hash_t *h)
{
	int i;

	if (!h)
		return 1;

	for (i = 0; i < h->len; i++)
		if (h->id[i])
			return 0;

	return 1;
}

static lws_dht_hash_t *
lws_dht_hash_dup(const lws_dht_hash_t *src)
{
	return lws_dht_hash_create(src->type, src->len, src->id);
}

static int
lws_dht_hash_cmp(const lws_dht_hash_t *a, const lws_dht_hash_t *b)
{
	if (a->type != b->type)
		return a->type - b->type;
	if (a->len != b->len)
		return a->len - b->len;
	return memcmp(a->id, b->id, a->len);
}

static void
dht_default_hash(void *hash_return, int hash_size,
		 const void *v1, int len1,
		 const void *v2, int len2,
		 const void *v3, int len3)
{
	uint8_t *h = hash_return;
	const uint8_t *p;
	int i;

	memset(h, 0, (size_t)hash_size);

	p = v1;
	for (i = 0; i < len1; i++)
		h[i % hash_size] ^= p[i];
	p = v2;
	for (i = 0; i < len2; i++)
		h[i % hash_size] ^= p[i];
	p = v3;
	for (i = 0; i < len3; i++)
		h[i % hash_size] ^= p[i];
}

static void
lws_dht_hash(struct lws_dht_ctx *ctx, void *hash_return, int hash_size,
	     const void *v1, int len1,
	     const void *v2, int len2,
	     const void *v3, int len3)
{
	if (ctx->hash_cb) {
		ctx->hash_cb(hash_return, hash_size, v1, len1, v2, len2, v3, len3);
		return;
	}

	dht_default_hash(hash_return, hash_size, v1, len1, v2, len2, v3, len3);
}

static void
lws_dht_capture_announce(struct lws_dht_ctx *ctx, lws_dht_hash_t *hash,
			 const struct sockaddr *fromaddr, unsigned short prt)
{
	if (ctx->capture_announce_cb)
		ctx->capture_announce_cb(ctx, hash, fromaddr, prt);
}

static int
is_martian(const struct sockaddr *sa)
{
	switch(sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in*)sa;
			const uint8_t *address = (const uint8_t*)&sin->sin_addr;

			return sin->sin_port == 0 ||
				(address[0] == 0) ||
				/* (address[0] == 127) || local loopback is okay for testing */
				((address[0] & 0xE0) == 0xE0);
			}
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
			const uint8_t *address = (const uint8_t*)&sin6->sin6_addr;

			return sin6->sin6_port == 0 ||
				(address[0] == 0xFF) ||
				(address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
				(memcmp(address, zeroes, 15) == 0 &&
				(address[15] == 0 || address[15] == 1)) ||
				(memcmp(address, v4prefix, 12) == 0);
		}

		default:
			       return 0;
	}
}

/*
 * Forget about the ``XOR-metric''.  An id is just a path from the
 * root of the tree, so bits are numbered from the start.
 */

static int
id_cmp(const lws_dht_hash_t *restrict id1, const lws_dht_hash_t *restrict id2)
{
	/* Memcmp is guaranteed to perform an unsigned comparison. */
	return lws_dht_hash_cmp(id1, id2);
}

static int
xorcmp(const lws_dht_hash_t *id1, const lws_dht_hash_t *id2,
		const lws_dht_hash_t *ref)
{
	int i;
	int len = ref->len;

	for (i = 0; i < len; i++) {
		uint8_t v1 = (i < id1->len) ? id1->id[i] : 0;
		uint8_t v2 = (i < id2->len) ? id2->id[i] : 0;
		uint8_t vr = (i < ref->len) ? ref->id[i] : 0;
		uint8_t x1 = v1 ^ vr;
		uint8_t x2 = v2 ^ vr;

		if (x1 != x2)
			return x1 < x2 ? -1 : 1;
	}
	return 0;
}

static int
lowbit(const lws_dht_hash_t *id)
{
	int i, j;
	for (i = (int)id->len - 1; i >= 0; i--)
		if (id->id[i] != 0)
			break;

	if (i < 0)
		return -1;

	for (j = 7; j >= 0; j--)
		if ((id->id[i] & (0x80 >> j)) != 0)
			break;

	return 8 * i + j;
}

/* Find how many bits two ids have in common. */
static int
common_bits(const lws_dht_hash_t *id1, const lws_dht_hash_t *id2)
{
	int i, j;
	uint8_t xor;
    int len = MIN(id1->len, id2->len);

	for (i = 0; i < len; i++) {
		if (id1->id[i] != id2->id[i])
			break;
	}

	if (i == len)
		return len * 8;

	xor = id1->id[i] ^ id2->id[i];

	j = 0;
	while ((xor & 0x80) == 0) {
		xor = (uint8_t)(xor << 1);
		j++;
	}

	return 8 * i + j;
}

static struct bucket *
find_bucket(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int af)
{
	struct bucket *b = af == AF_INET ? ctx->buckets : ctx->buckets6;

	if (b == NULL)
		return NULL;

	while (1) {
		if (b->next == NULL)
			return b;
		if (id_cmp(id, b->next->first) < 0)
			return b;
		b = b->next;
	}
}

static struct bucket *
previous_bucket(struct lws_dht_ctx *ctx, struct bucket *b)
{
	struct bucket *p = b->af == AF_INET ? ctx->buckets : ctx->buckets6;

	if (b == p)
		return NULL;

	while (1) {
		if (p->next == NULL)
			return NULL;
		if (p->next == b)
			return p;
		p = p->next;
	}
}

/* Every bucket contains an unordered list of nodes. */
static struct node *
find_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int af)
{
	struct bucket *b = find_bucket(ctx, id, af);
	struct node *n;

	if (b == NULL)
		return NULL;

	n = b->nodes;
	while (n) {
		if (id_cmp(n->id, id) == 0)
			return n;
		n = n->next;
	}
	return NULL;
}

/* Return a random node in a bucket. */
static struct node *
random_node(struct lws_dht_ctx *ctx, struct bucket *b)
{
	struct node *n;
	int nn;

	if (b->count == 0)
		return NULL;

	nn = (int)(lws_get_random(ctx->vhost->context, &nn, sizeof(nn)) % (unsigned int)b->count);
	n = b->nodes;
	while (nn > 0 && n) {
		n = n->next;
		nn--;
	}
	return n;
}


/* Return the middle id of a bucket. */
static int
bucket_middle(struct bucket *b, lws_dht_hash_t *id_return)
{
	int bit1 = lowbit(b->first);
	int bit2 = b->next ? lowbit(b->next->first) : -1;
	int bit = MAX(bit1, bit2) + 1;
	if (bit >= id_return->len * 8)
		return -1;

	memcpy(id_return->id, b->first->id, b->first->len);
	id_return->id[bit / 8] = (uint8_t)(id_return->id[bit / 8] | (0x80 >> (bit % 8)));

	return 1;
}

/* Return a random id within a bucket. */
static int
bucket_random(struct lws_dht_ctx *ctx, struct bucket *b, lws_dht_hash_t *id_return)
{
	int bit1 = lowbit(b->first);
	int bit2 = b->next ? lowbit(b->next->first) : -1;
	int bit = MAX(bit1, bit2) + 1;
	int i;

	if (bit >= id_return->len * 8) {
		memcpy(id_return->id, b->first->id, b->first->len);
		return 1;
	}

	int r;
	memcpy(id_return->id, b->first->id, (size_t)(bit / 8));
	lws_get_random(ctx->vhost->context, &r, sizeof(r));
	id_return->id[bit / 8] = (uint8_t)(b->first->id[bit / 8] & (0xFF00 >> (bit % 8)));
	id_return->id[bit / 8] |= (uint8_t)(r & (0xFF >> (bit % 8)));
	for (i = bit / 8 + 1; i < id_return->len; i++) {
		lws_get_random(ctx->vhost->context, &r, sizeof(r));
		id_return->id[i] = (uint8_t)(r & 0xff);
	}
	return 1;
}

/* Insert a new node into a bucket. */
static struct node *
insert_node(struct lws_dht_ctx *ctx, struct node *node)
{
	struct bucket *b = find_bucket(ctx, node->id, node->ss.ss_family);

	if (b == NULL)
		return NULL;

	node->next = b->nodes;
	b->nodes = node;
	b->count++;

	return node;
}

/* This is our definition of a known-good node. */
static int
node_good(struct lws_dht_ctx *ctx, struct node *node)
{
	return node->pinged <= 2 &&
		node->reply_time >= ctx->now.tv_sec - 7200 &&
		node->time >= ctx->now.tv_sec - 900;
}

/*
 * Our transaction-ids are 4-bytes long, with the first two bytes identifying
 * the kind of request, and the remaining two a sequence number in host order.
 */

static void
make_tid(uint8_t *tid_return, const char *prefix, unsigned short seqno)
{
	tid_return[0] = (uint8_t)(prefix[0] & 0xFF);
	tid_return[1] = (uint8_t)(prefix[1] & 0xFF);
	memcpy(tid_return + 2, &seqno, 2);
}

int
tid_match(const uint8_t *tid, const char *prefix,
		unsigned short *seqno_return)
{
	if (tid[0] == (prefix[0] & 0xFF) && tid[1] == (prefix[1] & 0xFF)) {
		if (seqno_return)
			memcpy(seqno_return, tid + 2, 2);
		return 1;
	}

	return 0;
}


static int
node_blacklisted(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen)
{
	int i;

	if (salen > sizeof(struct sockaddr_storage))
		abort();

	if (ctx->blacklist_cb && ctx->blacklist_cb(sa, salen))
		return 1;

	for (i = 0; i < DHT_MAX_BLACKLISTED; i++) {
		if (memcmp(&ctx->blacklist[i], sa, (size_t)salen) == 0)
			return 1;
	}

	return 0;
}

static int
dht_send(struct lws_dht_ctx *ctx, const void *buf, size_t len,
		const struct sockaddr *sa, size_t salen)
{
	struct lws *wsi;
#if defined(HDT_VERBOSE)
	char buf_ip[64];

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)sa;

		inet_ntop(AF_INET, &s->sin_addr, buf_ip, sizeof(buf_ip));
		lwsl_dht_info("%s: sending to %s:%d\n", __func__, buf_ip, ntohs(s->sin_port));
	}
#endif

	if (!salen)
		abort();

	if (node_blacklisted(ctx, sa, salen)) {
		lwsl_dht_warn("Attempting to send to blacklisted node.\n");
		errno = EPERM;

		return -1;
	}

	if (sa->sa_family == AF_INET)
		wsi = ctx->wsi_v4;
	else if (sa->sa_family == AF_INET6)
		wsi = ctx->wsi_v6;
	else
		wsi = NULL;

	if (!wsi) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (len > 1500)
		return -1;

#if defined(HDT_VERBOSE)
	{
		size_t k;
		fprintf(stderr, "DHT_SEND: ");
		for (k=0; k<len; k++) fprintf(stderr, "%02X ", ((uint8_t *)buf)[k]);
		fprintf(stderr, "\n");
	}
#endif

	int n;

#ifdef _WIN32
	n = (int)sendto(wsi->desc.sockfd, (const char *)buf, (int)len, 0, sa, (socklen_t)salen);
#else
	n = (int)sendto(wsi->desc.sockfd, (const void *)buf, len, 0, sa, (socklen_t)salen);
#endif

	if (n < 0) {
		lwsl_dht_warn("%s: sendto failed: errno %d\n", __func__, errno);
	}
	return n;
}

/* ... */


static int
send_ping(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", ctx->legacy ? 20 : (2 + ctx->myid->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		/* Strip prefix, ensure valid length? SHA1 assumed */
		if (ctx->myid->len >= 20)
			COPY(buf, i, ctx->myid->id, 20, sizeof(buf));
		else { /* Too short? Pad? */
			memset(buf + i, 0, 20);
			memcpy(buf + i, ctx->myid->id, ctx->myid->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)ctx->myid->type;
		buf[i++] = (char)ctx->myid->len;
		CHECK(i, ctx->myid->len, sizeof(buf));
		memcpy(buf + i, ctx->myid->id, ctx->myid->len);
		i += ctx->myid->len;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q4:ping1:t%d:", (int)tid_len);
	INC(i, rc, sizeof(buf));
	COPY(buf, i, tid, tid_len, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe");
	INC(i, rc, sizeof(buf));

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_pong(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:rd2:id%d:", ctx->legacy ? 20 : (2 + ctx->myid->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (ctx->myid->len >= 20)
			COPY(buf, i, ctx->myid->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, ctx->myid->id, ctx->myid->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)ctx->myid->type;
		buf[i++] = (char)ctx->myid->len;
		CHECK(i, ctx->myid->len, sizeof(buf));
		memcpy(buf + i, ctx->myid->id, ctx->myid->len);
		i += ctx->myid->len;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)tid_len);
	INC(i, rc, sizeof(buf));
	COPY(buf, i, tid, tid_len, sizeof(buf));
	ADD_IP(buf, i, sa, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:re");
	INC(i, rc, sizeof(buf));

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

/* Every bucket caches the address of a likely node.  Ping it. */
static int
send_cached_ping(struct lws_dht_ctx *ctx, struct bucket *b)
{
	uint8_t tid[4];
	int rc;

	/* We set family to 0 when there's no cached node. */
	if (b->cached.ss_family == 0)
		return 0;

	lwsl_dht_info("Sending ping to cached node.\n");
	make_tid(tid, "pn", 0);
	rc = send_ping(ctx, (struct sockaddr*)&b->cached, b->cachedlen, tid, 4);
	b->cached.ss_family = 0;
	b->cachedlen = 0;
	return rc;
}

/*
 * Called whenever we send a request to a node, increases the ping count
 * and, if that reaches 3, sends a ping to a new candidate.
 */
static void
pinged(struct lws_dht_ctx *ctx, struct node *n, struct bucket *b)
{
	n->pinged++;
	n->pinged_time = ctx->now.tv_sec;
	if (n->pinged >= 3)
		send_cached_ping(ctx, b ? b : find_bucket(ctx, n->id, n->ss.ss_family));
}

static void
flush_search_node(struct search_node *n, struct search *sr)
{
	int i = (int)(n - sr->nodes), j;

	lws_dht_hash_destroy(&n->id);
	for (j = i; j < sr->numnodes - 1; j++)
		sr->nodes[j] = sr->nodes[j + 1];
	sr->numnodes--;
}

/*
 * The internal blacklist is an LRU cache of nodes that have sent
 * incorrect messages.
 */
void
blacklist_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen)
{
	int i;

	lwsl_dht_warn("Blacklisting broken node.\n");

	if (id) {
		struct node *n;
		struct search *sr;

		/* Make the node easy to discard. */
		n = find_node(ctx, id, sa->sa_family);
		if (n) {
			n->pinged = 3;
			pinged(ctx, n, NULL);
		}
		/* Discard it from any searches in progress. */
		sr = ctx->searches;
		while (sr) {
			for (i = 0; i < sr->numnodes; i++)
				if (id_cmp(sr->nodes[i].id, id) == 0)
					flush_search_node(&sr->nodes[i], sr);
			sr = sr->next;
		}
	}
	/* And make sure we don't hear from it again. */
	if (ctx->next_blacklisted >= DHT_MAX_BLACKLISTED)
		ctx->next_blacklisted = 0;

	if (salen > sizeof(ctx->blacklist[0]))
		salen = sizeof(ctx->blacklist[0]);

	memcpy(&ctx->blacklist[ctx->next_blacklisted], sa, salen);
	ctx->next_blacklisted++;
}

/* Split a bucket into two equal parts. */
static struct bucket *
split_bucket(struct lws_dht_ctx *ctx, struct bucket *b)
{
	lws_dht_hash_t *new_id;
	struct bucket *new;
	struct node *nodes;
	int rc;

	new_id = lws_dht_hash_dup(b->first);
	if (!new_id)
		return NULL;

	rc = bucket_middle(b, new_id);
	if (rc < 0) {
		lws_dht_hash_destroy(&new_id);
		return NULL;
	}

	new = lws_zalloc(sizeof(struct bucket), __func__);
	if (new == NULL) {
		lws_dht_hash_destroy(&new_id);
		return NULL;
	}

	new->af = b->af;

	send_cached_ping(ctx, b);

	new->first = new_id;
	new->time = b->time;

	nodes = b->nodes;
	b->nodes = NULL;
	b->count = 0;
	new->next = b->next;
	b->next = new;

	while (nodes) {
		struct node *n = nodes;

		nodes = nodes->next;
		insert_node(ctx, n);
	}
	return b;
}

/*
 * We just learnt about a node, not necessarily a new one.  Confirm is 1 if
 * the node sent a message, 2 if it sent us a reply.
 */
struct node *
new_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen,
		int confirm)
{
	struct bucket *b = find_bucket(ctx, id, sa->sa_family);
	struct node *n;
	int mybucket, split;

	lwsl_dht_info("%s: id %02x, confirm %d\n", __func__, id->id[0], confirm);

	if (b == NULL) {
		lwsl_dht_warn("%s: bucket not found\n", __func__);
		return NULL;
	}

	if (id_cmp(id, ctx->myid) == 0) {
		lwsl_dht_warn("%s: same id\n", __func__);
		return NULL;
	}

	if (is_martian(sa) || node_blacklisted(ctx, sa, salen)) {
		lwsl_dht_warn("%s: martian or blacklisted\n", __func__);
		return NULL;
	}

	mybucket = id_cmp(b->first, ctx->myid) <= 0 &&
		(b->next == NULL || id_cmp(ctx->myid, b->next->first) < 0);

	if (confirm == 2)
		b->time = (int)ctx->now.tv_sec;

	n = b->nodes;
	while (n) {
		if (id_cmp(n->id, id) == 0) {
			if (confirm || n->time < ctx->now.tv_sec - 15 * 60) {
				/* Known node.  Update stuff. */
				memcpy((struct sockaddr*)&n->ss, sa, salen);
				if (confirm)
					n->time = ctx->now.tv_sec;
				if (confirm >= 2) {
					n->reply_time = ctx->now.tv_sec;
					n->pinged = 0;
					n->pinged_time = 0;
				}
			}
			return n;
		}
		n = n->next;
	}

	/* New node. */

	if (mybucket) {
		if (sa->sa_family == AF_INET)
			ctx->mybucket_grow_time = ctx->now.tv_sec;
		else
			ctx->mybucket6_grow_time = ctx->now.tv_sec;
	}

	/* First, try to get rid of a known-bad node. */
	n = b->nodes;
	while (n) {
		if (n->pinged >= 3 && n->pinged_time < ctx->now.tv_sec - 15) {
			lws_dht_hash_destroy(&n->id);
			n->id = lws_dht_hash_dup(id);
			if (!n->id) {
				// Should we remove node from bucket? For now keep but it's broken
				return NULL;
			}
			memcpy((struct sockaddr*)&n->ss, sa, salen);
			n->time = confirm ? ctx->now.tv_sec : 0;
			n->reply_time = confirm >= 2 ? ctx->now.tv_sec : 0;
			n->pinged_time = 0;
			n->pinged = 0;
			return n;
		}
		n = n->next;
	}

	if (b->count >= 8) {
		/* Bucket full.  Ping a dubious node */
		int dubious = 0;
		n = b->nodes;
		while (n) {
			/*
			 * Pick the first dubious node that we haven't pinged in the
			 * last 15 seconds.  This gives nodes the time to reply, but
			 * tends to concentrate on the same nodes, so that we get rid
			 * of bad nodes fast.
			 */
			if (!node_good(ctx, n)) {
				dubious = 1;
				if (n->pinged_time < ctx->now.tv_sec - 15) {
					uint8_t tid[4];
					lwsl_dht_info("Sending ping to dubious node.\n");
					make_tid(tid, "pn", 0);
					send_ping(ctx, (struct sockaddr*)&n->ss, n->sslen,
							tid, 4);
					pinged(ctx, n, b);
					break;
				}
			}
			n = n->next;
		}

		split = 0;
		if (mybucket) {
			if (!dubious)
				split = 1;
			/*
			 * If there's only one bucket, split eagerly.  This is
			 * incorrect unless there's more than 8 nodes in the DHT.
			 */
			else if (b->af == AF_INET && ctx->buckets->next == NULL)
				split = 1;
			else if (b->af == AF_INET6 && ctx->buckets6->next == NULL)
				split = 1;
		}

		if (split) {
			lwsl_dht_info("Splitting.\n");
			b = split_bucket(ctx, b);
			return new_node(ctx, id, sa, salen, confirm);
		}

		/* No space for this node.  Cache it away for later. */
		if (confirm || b->cached.ss_family == 0) {
			memcpy(&b->cached, sa, salen);
			b->cachedlen = salen;
		}

		return NULL;
	}

	/* Create a new node. */
	n = lws_zalloc(sizeof(struct node), __func__);
	if (n == NULL)
		return NULL;
	n->id = lws_dht_hash_dup(id);
	if (!n->id) {
		lws_free(n);
		return NULL;
	}
	memcpy(&n->ss, sa, (size_t)salen);
	n->sslen = salen;
	n->time = confirm ? ctx->now.tv_sec : 0;
	n->reply_time = confirm >= 2 ? ctx->now.tv_sec : 0;
	n->pinged_time = 0;
	n->pinged = 0;
	insert_node(ctx, n);
	return n;
}

/*
 * Called periodically to purge known-bad nodes.  Note that we're very
 * conservative here: broken nodes in the table don't do much harm, we'll
 * recover as soon as we find better ones.
 */
static int
expire_buckets(struct lws_dht_ctx *ctx, struct bucket *b)
{
	while (b) {
		struct node *n, *p;
		int changed = 0;

		while (b->nodes && b->nodes->pinged >= 4) {
			n = b->nodes;
			b->nodes = n->next;
			b->count--;
			changed = 1;
			lws_dht_hash_destroy(&n->id);
			lws_free(n);
		}

		p = b->nodes;
		while (p) {
			while (p->next && p->next->pinged >= 4) {
				n = p->next;
				p->next = n->next;
				b->count--;
				changed = 1;
				lws_dht_hash_destroy(&n->id);
				lws_free(n);
			}
			p = p->next;
		}

		if (changed)
			send_cached_ping(ctx, b);

		b = b->next;
	}
	ctx->expire_stuff_time = ctx->now.tv_sec + 120 + ((lws_get_random(ctx->vhost->context, &ctx->expire_stuff_time, sizeof(ctx->expire_stuff_time)), ctx->expire_stuff_time) % 240);
	return 1;
}

/*
 * While a search is in progress, we don't necessarily keep the nodes being
 * walked in the main bucket table.  A search in progress is identified by
 * a unique transaction id, a short (and hence small enough to fit in the
 * transaction id of the protocol packets).
 */

struct search *
find_search(struct lws_dht_ctx *ctx, unsigned short tid, int af)
{
	struct search *sr = ctx->searches;
	while (sr) {
		if (sr->tid == tid && sr->af == af)
			return sr;
		sr = sr->next;
	}
	return NULL;
}

/*
 * A search contains a list of nodes, sorted by decreasing distance to the
 * target.  We just got a new candidate, insert it at the right spot or
 * discard it.
 */
static int
insert_search_node(struct lws_dht_ctx *ctx, lws_dht_hash_t *id,
		const struct sockaddr *sa, size_t salen,
		struct search *sr, int replied,
		const uint8_t *token, size_t token_len)
{
	struct search_node *n;
	int i, j;

	if (sa->sa_family != sr->af) {
		lwsl_dht_warn("Attempted to insert node in the wrong family.\n");
		return 0;
	}

	for (i = 0; i < sr->numnodes; i++) {
		if (id_cmp(id, sr->nodes[i].id) == 0) {
			n = &sr->nodes[i];
			goto found;
		}
		if (xorcmp(id, sr->nodes[i].id, sr->id) < 0)
			break;
	}

	if (i == SEARCH_NODES)
		return 0;

	if (sr->numnodes < SEARCH_NODES)
		sr->numnodes++;

	for (j = sr->numnodes - 1; j > i; j--) {
		sr->nodes[j] = sr->nodes[j - 1];
	}

	n = &sr->nodes[i];

	memset(n, 0, sizeof(struct search_node));
	n->id = lws_dht_hash_dup(id);
	if (!n->id)
		return 0;

found:
	memcpy(&n->ss, sa, (size_t)salen);
	n->sslen = salen;

	if (replied) {
		n->replied = 1;
		n->reply_time = ctx->now.tv_sec;
		n->request_time = 0;
		n->pinged = 0;
	}
	if (token) {
		if (token_len >= 40) {
			lwsl_dht_warn("Eek!  Overlong token.\n");
		} else {
			memcpy(n->token, token, (size_t)token_len);
			n->token_len = token_len;
		}
	}

	return 1;
}

static void
expire_searches(struct lws_dht_ctx *ctx)
{
	struct search *sr = ctx->searches, *previous = NULL;

	while (sr) {
		struct search *next = sr->next;
		if (sr->step_time < ctx->now.tv_sec - DHT_SEARCH_EXPIRE_TIME) {
			if (previous)
				previous->next = next;
			else
				ctx->searches = next;
			lws_dht_hash_destroy(&sr->id);
			for (int i = 0; i < sr->numnodes; i++)
				lws_dht_hash_destroy(&sr->nodes[i].id);
			lws_free(sr);
			ctx->numsearches--;
		} else {
			previous = sr;
		}
		sr = next;
	}
}

static int
send_get_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		int want, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", ctx->legacy ? 20 : (2 + ctx->myid->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (ctx->myid->len >= 20)
			COPY(buf, i, ctx->myid->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, ctx->myid->id, ctx->myid->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)ctx->myid->type;
		buf[i++] = (char)ctx->myid->len;
		CHECK(i, ctx->myid->len, sizeof(buf));
		memcpy(buf + i, ctx->myid->id, ctx->myid->len);
		i += ctx->myid->len;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "9:info_hash%d:", ctx->legacy ? 20 : (2 + infohash->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (infohash->len >= 20)
			COPY(buf, i, infohash->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, infohash->id, infohash->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)infohash->type;
		buf[i++] = (char)infohash->len;
		CHECK(i, infohash->len, sizeof(buf));
		memcpy(buf + i, infohash->id, infohash->len);
		i += infohash->len;
	}

	if (want > 0) {
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "4:wantl%s%se",
				(want & WANT4) ? "2:n4" : "",
				(want & WANT6) ? "2:n6" : "");
		INC(i, rc, sizeof(buf));
	}
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q9:get_peers1:t%d:", (int)tid_len);
	INC(i, rc, sizeof(buf));
	COPY(buf, i, tid, tid_len, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe");
	INC(i, rc, sizeof(buf));

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

/* This must always return 0 or 1, never -1, not even on failure (see below). */
static int
search_send_get_peers(struct lws_dht_ctx *ctx, struct search *sr, struct search_node *n)
{
	struct node *node;
	uint8_t tid[4];

	if (n == NULL) {
		int i;
		for (i = 0; i < sr->numnodes; i++) {
			if (sr->nodes[i].pinged < 3 && !sr->nodes[i].replied &&
					sr->nodes[i].request_time < ctx->now.tv_sec - 15)
				n = &sr->nodes[i];
		}
	}

	if (!n || n->pinged >= 3 || n->replied ||
			n->request_time >= ctx->now.tv_sec - 15)
		return 0;

	lwsl_dht_info("Sending get_peers.\n");
	make_tid(tid, "gp", sr->tid);
	send_get_peers(ctx, (struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1,
			n->reply_time >= ctx->now.tv_sec - 15);
	n->pinged++;
	n->request_time = ctx->now.tv_sec;
	/* If the node happens to be in our main routing table, mark it
	   as pinged. */
	node = find_node(ctx, n->id, n->ss.ss_family);
	if (node) pinged(ctx, node, NULL);
	return 1;
}

static int
send_announce_peer(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		   uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		   unsigned short port, uint8_t *token, size_t token_len, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", ctx->legacy ? 20 : (2 + ctx->myid->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (ctx->myid->len >= 20)
			COPY(buf, i, ctx->myid->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, ctx->myid->id, ctx->myid->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)ctx->myid->type;
		buf[i++] = (char)ctx->myid->len;
		CHECK(i, ctx->myid->len, sizeof(buf));
		memcpy(buf + i, ctx->myid->id, ctx->myid->len);
		i += ctx->myid->len;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "9:info_hash%d:", ctx->legacy ? 20 : (2 + infohash->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (infohash->len >= 20)
			COPY(buf, i, infohash->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, infohash->id, infohash->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)infohash->type;
		buf[i++] = (char)infohash->len;
		CHECK(i, infohash->len, sizeof(buf));
		memcpy(buf + i, infohash->id, infohash->len);
		i += infohash->len;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "4:porti%ue5:token%d:", (unsigned)port,
			(int)token_len);
	INC(i, rc, sizeof(buf));
	COPY(buf, i, token, token_len, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q13:announce_peer1:t%d:", (int)tid_len);
	INC(i, rc, sizeof(buf));
	COPY(buf, i, tid, tid_len, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe");
	INC(i, rc, sizeof(buf));

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

/*
 * When a search is in progress, we periodically call search_step to send
 * further requests.
 */
static void
search_step(struct lws_dht_ctx *ctx, struct search *sr, lws_dht_callback_t *callback, void *closure)
{
	int i, j;
	int all_done = 1;

	/* Check if the first 8 live nodes have replied. */
	j = 0;
	for (i = 0; i < sr->numnodes && j < 8; i++) {
		struct search_node *n = &sr->nodes[i];
		if (n->pinged >= 3)
			continue;
		if (!n->replied) {
			all_done = 0;
			break;
		}
		j++;
	}

	if (all_done) {
		if (sr->port == 0) {
			goto done;
		} else {
			int all_acked = 1;

			j = 0;
			for (i = 0; i < sr->numnodes && j < 8; i++) {
				struct search_node *n = &sr->nodes[i];
				struct node *node;
				uint8_t tid[4];
				if (n->pinged >= 3)
					continue;
				/*
				 * A proposed extension to the protocol consists in
				 * omitting the token when storage tables are full.  While
				 * I don't think this makes a lot of sense -- just sending
				 * a positive reply is just as good --, let's deal with it.
				 */
				if (!n->token_len)
					n->acked = 1;

				if (!n->acked) {
					all_acked = 0;
					lwsl_dht_info("Sending announce_peer.\n");
					make_tid(tid, "ap", sr->tid);
					send_announce_peer(ctx, (struct sockaddr*)&n->ss,
							sizeof(struct sockaddr_storage),
							tid, 4, sr->id, sr->port,
							n->token, n->token_len,
							n->reply_time >= ctx->now.tv_sec - 15);
					n->pinged++;
					n->request_time = ctx->now.tv_sec;
					node = find_node(ctx, n->id, n->ss.ss_family);
					if (node) pinged(ctx, node, NULL);
				}
				j++;
			}
			if (all_acked)
				goto done;
		}
		sr->step_time = ctx->now.tv_sec;
		return;
	}

	if (sr->step_time + 15 >= ctx->now.tv_sec)
		return;

	j = 0;
	for (i = 0; i < sr->numnodes; i++) {
		j += search_send_get_peers(ctx, sr, &sr->nodes[i]);
		if (j >= 3)
			break;
	}
	sr->step_time = ctx->now.tv_sec;
	return;

done:
	sr->done = 1;
	if (callback)
		(*callback)(closure, sr->af == AF_INET ?
				LWS_DHT_EVENT_SEARCH_DONE : LWS_DHT_EVENT_SEARCH_DONE6,
				sr->id, NULL, 0, NULL, 0);

	sr->step_time = ctx->now.tv_sec;
}

static struct search *
new_search(struct lws_dht_ctx *ctx)
{
	struct search *sr, *oldest = NULL;

	/* Find the oldest done search */
	sr = ctx->searches;
	while (sr) {
		if (sr->done &&
		    (oldest == NULL || oldest->step_time > sr->step_time))
			oldest = sr;
		sr = sr->next;
	}

	/* The oldest slot is expired. */
	if (oldest && oldest->step_time < ctx->now.tv_sec - DHT_SEARCH_EXPIRE_TIME) {
		lws_dht_hash_destroy(&oldest->id);
		for (int i = 0; i < oldest->numnodes; i++)
			lws_dht_hash_destroy(&oldest->nodes[i].id);
		lws_free(oldest);
		ctx->numsearches--;

		return NULL; /* Indicate that the slot was freed, caller should allocate new */
	}

	/* Allocate a new slot. */
	if (ctx->numsearches < DHT_MAX_SEARCHES) {
		sr = lws_zalloc(sizeof(struct search), __func__);
		if (sr != NULL) {
			sr->next = ctx->searches;
			ctx->searches = sr;
			ctx->numsearches++;
			return sr;
		}
	}

	/* Oh, well, never mind.  Re-use the oldest slot. */
	if (oldest) {
		lws_dht_hash_destroy(&oldest->id);
		for (int i = 0; i < oldest->numnodes; i++)
			lws_dht_hash_destroy(&oldest->nodes[i].id);
		memset(oldest, 0, sizeof(struct search)); // Clear old data
	}
	return oldest;
}

/* Insert the contents of a bucket into a search structure. */
static void
insert_search_bucket(struct lws_dht_ctx *ctx, struct bucket *b, struct search *sr)
{
	struct node *n;
	n = b->nodes;
	while (n) {
		insert_search_node(ctx, n->id, (struct sockaddr*)&n->ss, n->sslen,
				sr, 0, NULL, 0);
		n = n->next;
	}
}

/* A struct storage stores all the stored peer addresses for a given info hash. */
static struct storage *
find_storage(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id)
{
	struct storage *st = ctx->storage;

	while (st) {
		if (id_cmp(id, st->id) == 0)
			break;
		st = st->next;
	}
	return st;
}

static int
storage_store(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		const struct sockaddr *sa, unsigned short port)
{
	int i, len;
	struct storage *st;
	uint8_t *ip;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		ip = (uint8_t*)&sin->sin_addr;
		len = 4;
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		ip = (uint8_t*)&sin6->sin6_addr;
		len = 16;
	} else
		return -1;

	st = find_storage(ctx, id);

	if (st == NULL) {
		if (ctx->numstorage >= DHT_MAX_HASHES)
			return -1;
		st = lws_zalloc(sizeof(struct storage), __func__);
		if (st == NULL)
			return -1;
		st->id = lws_dht_hash_dup(id);
		if (!st->id) {
			lws_free(st);
			return -1;
		}
		st->next = ctx->storage;
		ctx->storage = st;
		ctx->numstorage++;
	}

	for (i = 0; i < st->numpeers; i++) {
		if (st->peers[i].port == port && st->peers[i].len == len &&
				memcmp(st->peers[i].ip, ip, (size_t)len) == 0)
			break;
	}

	if (i < st->numpeers) {
		/* Already there, only need to refresh */
		st->peers[i].time = ctx->now.tv_sec;
		return 0;
	} else {
		struct peer *p;
		if (i >= st->maxpeers) {
			/* Need to expand the array. */
			struct peer *new_peers;
			int n;
			if (st->maxpeers >= DHT_MAX_PEERS)
				return 0;
			n = st->maxpeers == 0 ? 2 : 2 * st->maxpeers;
			n = MIN(n, DHT_MAX_PEERS);
			new_peers = lws_realloc(st->peers, (size_t)n * sizeof(struct peer), __func__);
			if (new_peers == NULL)
				return -1;
			st->peers = new_peers;
			st->maxpeers = n;
		}
		p = &st->peers[st->numpeers++];
		p->time = ctx->now.tv_sec;
		p->len = (unsigned short)len;
		memcpy(p->ip, ip, (size_t)len);
		p->port = port;

		return 1;
	}
}

/*
 * Start a search.  If port is non-zero, perform an announce when the
 * search is complete.
 */
LWS_VISIBLE int
lws_dht_search(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int port, int af,
		lws_dht_callback_t *callback, void *closure)
{
	struct search *sr;
	struct storage *st;
	struct bucket *b = find_bucket(ctx, id, af);

	if (port) {
		/* We are announcing.  Store ourselves. */
		struct sockaddr_in sin;

		if (af == AF_INET) {
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			/*
			 * In the test case, we are on loopback.
			 * Generally determining our own public IP is hard.
			 * But here we want to store what we are listening on so others can find us.
			 * For the test, Node A is on 10001.
			 */
			sin.sin_port = 0; /* Unused by storage_store, it uses the port arg */
			sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			/* If we have a bound wsi, maybe use its address? */
			/* But effectively we just want to put "us" in the storage. */

			storage_store(ctx, id, (struct sockaddr *)&sin, (unsigned short)port);
		}
	}

	if (b == NULL) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	/*
	 * Try to answer this search locally.  In a fully grown DHT this
	 * is very unlikely, but people are running modified versions of
	 * this code in private DHTs with very few nodes.  What's wrong
	 * with flooding?
	 */
	if (callback) {
		st = find_storage(ctx, id);
		if (st) {
			unsigned short swapped;
			uint8_t buf[18];
			int i;

			lwsl_dht_info("Found local data (%d peers).\n", st->numpeers);

			for (i = 0; i < st->numpeers; i++) {
				swapped = htons(st->peers[i].port);
				if (st->peers[i].len == 4) {
					memcpy(buf, st->peers[i].ip, 4);
					memcpy(buf + 4, &swapped, 2);
					if (callback)
						(*callback)(closure, LWS_DHT_EVENT_VALUES, id,
								(void*)buf, 6, NULL, 0);
				} else if (st->peers[i].len == 16) {
					memcpy(buf, st->peers[i].ip, 16);
					memcpy(buf + 16, &swapped, 2);
					if (callback)
						(*callback)(closure, LWS_DHT_EVENT_VALUES6, id,
								(void*)buf, 18, NULL, 0);
				}
			}
		}
	}

	sr = ctx->searches;
	while (sr) {
		if (sr->af == af && id_cmp(sr->id, id) == 0)
			break;
		sr = sr->next;
	}

	if (sr) {
		/*
		 * We're reusing data from an old search.  Reusing the same tid
		 * means that we can merge replies for both searches.
		 */
		int i;
		sr->done = 0;
again:
		for (i = 0; i < sr->numnodes; i++) {
			struct search_node *n;

			n = &sr->nodes[i];
			/* Discard any doubtful nodes. */
			if (n->pinged >= 3 || n->reply_time < ctx->now.tv_sec - 7200) {
				flush_search_node(n, sr);
				goto again;
			}
			n->pinged	= 0;
			n->token_len	= 0;
			n->replied	= 0;
			n->acked	= 0;
		}
	} else {
		sr = new_search(ctx);
		if (sr == NULL) {
			errno = ENOSPC;
			return -1;
		}
		sr->af		= af;
		sr->tid		= ctx->search_id++;
		sr->step_time	= 0;
		sr->id		= lws_dht_hash_dup(id);
		if (!sr->id) {
			/*
			 * If we fail to dup the ID, we should free the search struct
			 * and decrement numsearches if it was incremented.
			 * For now, just return NULL and let the caller handle it.
			 * This is a memory allocation failure, so returning -1 is appropriate.
			 */
			if (sr == ctx->searches)
				ctx->searches = sr->next;
			else {
				struct search *temp_sr = ctx->searches;
				while (temp_sr && temp_sr->next != sr)
					temp_sr = temp_sr->next;
				if (temp_sr)
					temp_sr->next = sr->next;
			}
			lws_free(sr);
			ctx->numsearches--;
			errno = ENOMEM;
			return -1;
		}
		sr->done = 0;
		sr->numnodes = 0;
	}

	sr->port = (unsigned short)port;

	insert_search_bucket(ctx, b, sr);

	if (sr->numnodes < SEARCH_NODES) {
		struct bucket *p = previous_bucket(ctx, b);
		if (b->next)
			insert_search_bucket(ctx, b->next, sr);
		if (p)
			insert_search_bucket(ctx, p, sr);
	}
	if (sr->numnodes < SEARCH_NODES)
		insert_search_bucket(ctx, find_bucket(ctx, ctx->myid, af), sr);

	search_step(ctx, sr, callback, closure);
	ctx->search_time = ctx->now.tv_sec;
	return 1;
}

static int
expire_storage(struct lws_dht_ctx *ctx)
{
	struct storage *st = ctx->storage, *previous = NULL;
	while (st) {
		int i = 0;
		while (i < st->numpeers) {
			if (st->peers[i].time < ctx->now.tv_sec - 32 * 60) {
				if (i != st->numpeers - 1)
					st->peers[i] = st->peers[st->numpeers - 1];
				st->numpeers--;
				continue;
			}
			i++;
		}

		if (st->numpeers == 0) {
			lws_free(st->peers);
			if (previous)
				previous->next = st->next;
			else
				ctx->storage = st->next;
			lws_dht_hash_destroy(&st->id);
			lws_free(st->peers);
			lws_free(st);
			if (previous)
				st = previous->next;
			else
				st = ctx->storage;
			ctx->numstorage--;
			if (ctx->numstorage < 0) {
				lwsl_dht_err("Eek... numstorage became negative.\n");
				ctx->numstorage = 0;
			}
		} else {
			previous = st;
			st = st->next;
		}
	}
	return 1;
}

static int
rotate_secrets(struct lws_dht_ctx *ctx)
{
	size_t rc;

	ctx->rotate_secrets_time = ctx->now.tv_sec + 900 + ((lws_get_random(ctx->vhost->context, &ctx->rotate_secrets_time, sizeof(ctx->rotate_secrets_time)), ctx->rotate_secrets_time) % 1800);

	memcpy(ctx->oldsecret, ctx->secret, sizeof(ctx->secret));
	rc = lws_get_random(ctx->vhost->context, ctx->secret, sizeof(ctx->secret));
	if (rc != sizeof(ctx->secret)) {
		lwsl_dht_err("Failed to get random bytes for secret rotation\n");
		return -1;
	}

	return 1;
}

static void
make_token(struct lws_dht_ctx *ctx, const struct sockaddr *sa, int old, uint8_t *token_return)
{
	unsigned short port;
	int iplen;
	void *ip;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		ip = &sin->sin_addr;
		iplen = 4;
		port = htons(sin->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		ip = &sin6->sin6_addr;
		iplen = 16;
		port = htons(sin6->sin6_port);
	} else
		abort();

	lws_dht_hash(ctx, token_return, TOKEN_SIZE,
			old ? ctx->oldsecret : ctx->secret, sizeof(ctx->secret),
			ip, iplen, (uint8_t*)&port, 2);
}
int
token_match(struct lws_dht_ctx *ctx, const uint8_t *token, size_t token_len,
		const struct sockaddr *sa)
{
	uint8_t t[TOKEN_SIZE];

	if (token_len != TOKEN_SIZE)
		return 0;
	make_token(ctx, sa, 0, t);
	if (memcmp(t, token, TOKEN_SIZE) == 0)
		return 1;
	make_token(ctx, sa, 1, t);
	if (memcmp(t, token, TOKEN_SIZE) == 0)
		return 1;

	return 0;
}

LWS_VISIBLE int
lws_dht_nodes(struct lws_dht_ctx *ctx, int af, int *good_return, int *dubious_return, int *cached_return,
		int *incoming_return)
{
	int good = 0, dubious = 0, cached = 0, incoming = 0;
	struct bucket *b = af == AF_INET ? ctx->buckets : ctx->buckets6;

	while (b) {
		struct node *n = b->nodes;
		while (n) {
			if (node_good(ctx, n)) {
				good++;
				if (n->time > n->reply_time)
					incoming++;
			} else
				dubious++;

			n = n->next;
		}
		if (b->cached.ss_family > 0)
			cached++;
		b = b->next;
	}
	if (good_return)
		*good_return = good;
	if (dubious_return)
		*dubious_return = dubious;
	if (cached_return)
		*cached_return = cached;
	if (incoming_return)
		*incoming_return = incoming;

	return good + dubious;
}

static void
dump_bucket(struct lws_dht_ctx *ctx, struct bucket *b)
{
	struct node *n = b->nodes;

	lwsl_dht_info("Bucket ");
	lwsl_hexdump_dht(b->first->id, b->first->len);
	lwsl_dht_info(" count %d age %d%s%s:\n",
			b->count, (int)(ctx->now.tv_sec - b->time),
			(id_cmp(b->first, ctx->myid) <= 0 &&
			 (b->next == NULL || id_cmp(ctx->myid, b->next->first) < 0)) ?
			" (my bucket)" : "",
			b->cached.ss_family ? " (has cached)" : "");

	while (n) {
		char buf[64];
		unsigned short port;

		lwsl_dht_info("    Node ");
		lwsl_hexdump_dht(n->id->id, n->id->len);
		if (n->ss.ss_family == AF_INET) {
			lws_sa46_write_numeric_address((lws_sockaddr46 *)&n->ss, buf, sizeof(buf));
			port = ntohs(((struct sockaddr_in*)&n->ss)->sin_port);
			lwsl_dht_info(" %s:%d ", buf, port);
		} else {
			lws_sa46_write_numeric_address((lws_sockaddr46 *)&n->ss, buf, sizeof(buf));
			port = ntohs(((struct sockaddr_in6*)&n->ss)->sin6_port);
			lwsl_dht_info(" [%s]:%d ", buf, port);
		}
		if (n->reply_time)
			lwsl_dht_info("age %ld, %ld",
					(long)(ctx->now.tv_sec - n->time),
					(long)(ctx->now.tv_sec - n->reply_time));
		else
			lwsl_dht_info("age %ld", (long)(ctx->now.tv_sec - n->time));
		if (n->pinged)
			lwsl_dht_info(" (%d)", n->pinged);
		if (node_good(ctx, n))
			lwsl_dht_info(" (good)");
		lwsl_dht_info("\n");
		n = n->next;
	}

}

void
lws_dht_dump_tables(struct lws_dht_ctx *ctx)
{
	int i;
	struct bucket *b;
	struct storage *st;
	struct search *sr = ctx->searches;

	(void)st;

	lwsl_dht_info("My id ");
	lwsl_hexdump_dht(ctx->myid->id, ctx->myid->len);
	lwsl_dht_info("\n");

	b = ctx->buckets;
	while (b) {
		dump_bucket(ctx, b);
		b = b->next;
	}

	lwsl_dht_info("\n");

	b = ctx->buckets6;
	while (b) {
		dump_bucket(ctx, b);
		b = b->next;
	}

	while (sr) {
		lwsl_dht_info("\nSearch%s id ", sr->af == AF_INET6 ? " (IPv6)" : "");
		lwsl_hexdump_dht(sr->id->id, sr->id->len);
		lwsl_dht_info(" age %d%s\n", (int)(ctx->now.tv_sec - sr->step_time),
				sr->done ? " (done)" : "");
		for (i = 0; i < sr->numnodes; i++) {
			struct search_node *n = &sr->nodes[i];
			lwsl_dht_info("Node %d id ", i);
			lwsl_hexdump_dht(n->id->id, n->id->len);
			lwsl_dht_info(" bits %d age ", common_bits(sr->id, n->id));
			if (n->request_time)
				lwsl_dht_info("%d, ", (int)(ctx->now.tv_sec - n->request_time));
			lwsl_dht_info("%d", (int)(ctx->now.tv_sec - n->reply_time));
			if (n->pinged)
				lwsl_dht_info(" (%d)", n->pinged);
			lwsl_dht_info("%s%s.\n",
					find_node(ctx, n->id, AF_INET) ? " (known)" : "",
					n->replied ? " (replied)" : "");
		}
		sr = sr->next;
	}

	st = ctx->storage;
	while (st) {
		lwsl_dht_info("\nStorage ");
		lwsl_hexdump_dht(st->id->id, st->id->len);
		lwsl_dht_info(" %d/%d nodes:", st->numpeers, st->maxpeers);
		for (i = 0; i < st->numpeers; i++) {
			char buf[64];
			if (st->peers[i].len == 4 || st->peers[i].len == 16) {
				lws_write_numeric_address(st->peers[i].ip, (int)st->peers[i].len, buf, 64);
			} else {
				strcpy(buf, "???");
			}
			lwsl_dht_info(" %s:%u (%ld)",
					buf, st->peers[i].port,
					(long)(ctx->now.tv_sec - st->peers[i].time));
		}
		st = st->next;
	}

	lwsl_dht_info("\n\n");
}

static int
send_find_node(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len,
		const lws_dht_hash_t *target, int want, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", ctx->legacy ? 20 : (2 + ctx->myid->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (ctx->myid->len >= 20)
			COPY(buf, i, ctx->myid->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, ctx->myid->id, ctx->myid->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)ctx->myid->type;
		buf[i++] = (char)ctx->myid->len;
		CHECK(i, ctx->myid->len, sizeof(buf));
		memcpy(buf + i, ctx->myid->id, ctx->myid->len);
		i += ctx->myid->len;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "6:target%d:", ctx->legacy ? 20 : (2 + target->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (target->len >= 20)
			COPY(buf, i, target->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, target->id, target->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)target->type;
		buf[i++] = (char)target->len;
		CHECK(i, target->len, sizeof(buf));
		memcpy(buf + i, target->id, target->len);
		i += target->len;
	}

    if (want > 0) {
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "4:wantl%s%se",
				(want & WANT4) ? "2:n4" : "",
				(want & WANT6) ? "2:n6" : "");
		INC(i, rc, sizeof(buf));
	}

    rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q9:find_node1:t%d:", (int)tid_len);
	INC(i, rc, sizeof(buf));
	COPY(buf, i, tid, tid_len, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe"); INC(i, rc, sizeof(buf));

    return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

static int
bucket_maintenance(struct lws_dht_ctx *ctx, int af)
{
	struct bucket *b;

	b = af == AF_INET ? ctx->buckets : ctx->buckets6;

	while (b) {
		struct bucket *q;
		if (b->time < ctx->now.tv_sec - 600) {
			/*
			 * This bucket hasn't seen any positive confirmation for a long
			 * time.  Pick a random id in this bucket's range, and send
			 * a request to a random node.
			 */
			lws_dht_hash_t *id;
			struct node *n;
			int rc;

			id = lws_dht_hash_create(b->first->type, b->first->len, NULL);
			if (!id)
				return 0;

			rc = bucket_random(ctx, b, id);
			if (rc < 0)
				lws_dht_hash_copy(id, b->first);

			q = b;
			/*
			 * If the bucket is empty, we try to fill it from a neighbour.
			 * We also sometimes do it gratuitiously to recover from
			 * buckets full of broken nodes.
			 */
			if (q->next && (q->count == 0 || ((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) & 7) == 0))
				q = b->next;
			if (q->count == 0 || ((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) & 7) == 0) {
				struct bucket *r;
				r = previous_bucket(ctx, b);
				if (r && r->count > 0)
					q = r;
			}

			if (q) {
				n = random_node(ctx, q);
				if (n) {
					uint8_t tid[4];
					int want = -1;

					if (ctx->wsi_v4 && ctx->wsi_v6) {
						struct bucket *otherbucket;
						otherbucket =
							find_bucket(ctx, id, af == AF_INET ? AF_INET6 : AF_INET);
						if (otherbucket && otherbucket->count < 8)
							/*
							 * The corresponding bucket in the other family
							 * is emptyish -- querying both is useful.
							 */
								want = WANT4 | WANT6;
						else if ((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) % 37 == 0)
							/*
							 * Most of the time, this just adds overhead.
							 * However, it might help stitch back one of
							 * the DHTs after a network collapse, so query
							 * both, but only very occasionally.
							 */
							want = WANT4 | WANT6;
					}

					lwsl_dht_info("Sending find_node for%s bucket maintenance.\n",
							af == AF_INET6 ? " IPv6" : "");
					make_tid(tid, "fn", 0);
					send_find_node(ctx, (struct sockaddr*)&n->ss, n->sslen,
							tid, 4, id, want,
							n->reply_time >= ctx->now.tv_sec - 15);
					pinged(ctx, n, q);
					/*
					 * In order to avoid sending queries back-to-back,
					 * give up for now and reschedule us soon.
					 */
					lws_dht_hash_destroy(&id);
					return 1;
				}
			}
			lws_dht_hash_destroy(&id);
		}
		b = b->next;
	}
	return 0;
}

static int
neighbourhood_maintenance(struct lws_dht_ctx *ctx, int af)
{
	lws_dht_hash_t *id;
	struct bucket *b = find_bucket(ctx, ctx->myid, af);
	struct bucket *q;
	struct node *n;

	if (b == NULL)
		return 0;

	id = lws_dht_hash_dup(ctx->myid);
	if (!id) return 0;
	id->id[id->len - 1] = (uint8_t)((lws_get_random(ctx->vhost->context, &id->id[id->len - 1], 1), id->id[id->len - 1]) & 0xFF);
	q = b;
	if (q->next && (q->count == 0 || ((lws_get_random(ctx->vhost->context, &id->id[0], 1), id->id[0]) & 7) == 0))
		q = b->next;
	if (q->count == 0 || ((lws_get_random(ctx->vhost->context, &id->id[0], 1), id->id[0]) & 7) == 0) {
		struct bucket *r;
		r = previous_bucket(ctx, b);
		if (r && r->count > 0)
			q = r;
	}

	if (q) {
		/*
		 * Since our node-id is the same in both DHTs, it's probably
		 * profitable to query both families.
		 */
		int want = ctx->wsi_v4 && ctx->wsi_v6 ? (WANT4 | WANT6) : -1;
		n = random_node(ctx, q);
		if (n) {
			uint8_t tid[4];

			lwsl_dht_info("Sending find_node for%s neighborhood maintenance.\n",
					af == AF_INET6 ? " IPv6" : "");
			make_tid(tid, "fn", 0);
			send_find_node(ctx, (struct sockaddr*)&n->ss, n->sslen,
					tid, 4, id, want,
					n->reply_time >= ctx->now.tv_sec - 15);
			pinged(ctx, n, q);
		}
		lws_dht_hash_destroy(&id);
		return 1;
	}
	lws_dht_hash_destroy(&id);
	return 0;
}

static void
lws_dht_periodic_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_dht_ctx *ctx = lws_container_of(sul, struct lws_dht_ctx, sul);
	time_t tosleep = 10;

	ctx->now.tv_sec = (time_t)lws_now_secs();

	if (ctx->now.tv_sec >= ctx->rotate_secrets_time)
		rotate_secrets(ctx);

	if (ctx->now.tv_sec >= ctx->expire_stuff_time) {
		int soon = 0;

		expire_buckets(ctx, ctx->buckets);
		expire_buckets(ctx, ctx->buckets6);
		expire_storage(ctx);
		expire_searches(ctx);
		soon |= bucket_maintenance(ctx, AF_INET);
		soon |= bucket_maintenance(ctx, AF_INET6);
		ctx->expire_stuff_time = ctx->now.tv_sec + 120;
		if (soon) {
			if (ctx->confirm_nodes_time == 0 ||
			    ctx->confirm_nodes_time > ctx->now.tv_sec + 2)
				ctx->confirm_nodes_time = ctx->now.tv_sec + 2;
		}
	}

	if (ctx->search_time > 0 && ctx->now.tv_sec >= ctx->search_time) {
		struct search *sr;

		sr = ctx->searches;
		while (sr) {
			if (!sr->done && sr->step_time + 5 <= ctx->now.tv_sec) {
				search_step(ctx, sr, ctx->cb, ctx->closure);
			}
			sr = sr->next;
		}

		ctx->search_time = 0;

		sr = ctx->searches;
		while (sr) {
			if (!sr->done) {
				time_t tm = sr->step_time + 15 + ((lws_get_random(ctx->vhost->context, &tm, sizeof(tm)), tm) % 10);
				if (ctx->search_time == 0 || ctx->search_time > tm)
					ctx->search_time = tm;
			}
			sr = sr->next;
		}
	}

	if (ctx->confirm_nodes_time > 0 && ctx->now.tv_sec >= ctx->confirm_nodes_time) {
		int soon = 0;
		soon |= neighbourhood_maintenance(ctx, AF_INET);
		soon |= neighbourhood_maintenance(ctx, AF_INET6);

		if (!soon) {
			if (ctx->mybucket_grow_time >= ctx->now.tv_sec - 150)
				soon |= neighbourhood_maintenance(ctx, AF_INET);
			if (ctx->mybucket6_grow_time >= ctx->now.tv_sec - 150)
				soon |= neighbourhood_maintenance(ctx, AF_INET6);
		}

		if (soon)
			ctx->confirm_nodes_time = ctx->now.tv_sec + 5 + ((lws_get_random(ctx->vhost->context, &soon, sizeof(soon)), soon) % 20);
		else
			ctx->confirm_nodes_time = ctx->now.tv_sec + 60 + ((lws_get_random(ctx->vhost->context, &soon, sizeof(soon)), soon) % 120);
	}

	if (ctx->confirm_nodes_time > ctx->now.tv_sec)
		tosleep = ctx->confirm_nodes_time - ctx->now.tv_sec;
	else
		tosleep = 0;

	if (ctx->search_time > 0) {
		if (ctx->search_time <= ctx->now.tv_sec)
			tosleep = 0;
		else if (tosleep > ctx->search_time - ctx->now.tv_sec)
			tosleep = ctx->search_time - ctx->now.tv_sec;
	}

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul,
			 lws_dht_periodic_cb, tosleep * LWS_US_PER_SEC);
}

static int
insert_closest_node(struct node **nodes, int numnodes,
		const lws_dht_hash_t *id, struct node *n)
{
	int i;

	for (i = 0; i < numnodes; i++) {
		if (id_cmp(n->id, nodes[i]->id) == 0)
			return numnodes;
		if (xorcmp(n->id, nodes[i]->id, id) < 0)
			break;
	}

	if (i == 8)
		return numnodes;

	if (numnodes < 8)
		numnodes++;

	if (i < numnodes - 1)
		memmove(nodes + i + 1, nodes + i,
			(size_t)(numnodes - i - 1) * sizeof(struct node *));

	nodes[i] = n;

	return numnodes;
}

static int
buffer_closest_nodes(struct lws_dht_ctx *ctx, struct node **nodes, int numnodes,
		const lws_dht_hash_t *id, struct bucket *b)
{
	struct node *n = b->nodes;
	while (n) {
		if (node_good(ctx, n))
			numnodes = insert_closest_node(nodes, numnodes, id, n);
		n = n->next;
	}
	return numnodes;
}

typedef struct lws_dht_ts {
	lws_dll2_t			list;
	struct lws_transport_sequencer	*ts;
	struct sockaddr_storage		sa;
	size_t				salen;
	struct lws_dht_ctx		*ctx;
} lws_dht_ts_t;

static int
dht_tx_chunk(struct lws_transport_sequencer *ts, uint64_t offset,
	     const uint8_t *buf, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	char pkt[2048];
	size_t i = 0;
	int rc;

	/* d1:ad4:data%d:<payload>6:offseti%llue3:leni%llue2:id%d:<id>e1:q4:data1:t2:da1:y1:qe */

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "d1:ad4:data%d:", (int)len);
	INC(i, rc, sizeof(pkt));
	COPY(pkt, i, buf, len, sizeof(pkt));

	/* Correct alphabetical order: data (done), id, len, offset */
	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "2:id%d:", dts->ctx->legacy ? 20 : (2 + dts->ctx->myid->len));
	INC(i, rc, sizeof(pkt));

	if (dts->ctx->legacy) {
		if (dts->ctx->myid->len >= 20)
			COPY(pkt, i, dts->ctx->myid->id, 20, sizeof(pkt));
		else {
			memset(pkt + i, 0, 20);
			memcpy(pkt + i, dts->ctx->myid->id, dts->ctx->myid->len);
			i += 20;
		}
	} else {
		pkt[i++] = (char)dts->ctx->myid->type;
		pkt[i++] = (char)dts->ctx->myid->len;
		CHECK(i, dts->ctx->myid->len, sizeof(pkt));
		memcpy(pkt + i, dts->ctx->myid->id, dts->ctx->myid->len);
		i += dts->ctx->myid->len;
	}

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "3:leni%llue6:offseti%llue",
			 (unsigned long long)len, (unsigned long long)offset);
	INC(i, rc, sizeof(pkt));

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "e1:q4:data1:t4:sqnc1:y1:qe");
	INC(i, rc, sizeof(pkt));

	return dht_send(dts->ctx, pkt, i, (struct sockaddr *)&dts->sa, dts->salen);

fail:
	return -1;
}

static int
dht_tx_ack(struct lws_transport_sequencer *ts, uint64_t offset, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	const lws_transport_sequencer_stats_t *stats = lws_transport_sequencer_get_stats(ts);
	char pkt[512];
	size_t i = 0;
	int rc;

	/* d1:rd2:id%d:<id>3:leni%llue6:offseti%lluee1:t4:sqnc1:y1:re */

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "d1:rd2:id%d:", dts->ctx->legacy ? 20 : (2 + dts->ctx->myid->len));
	INC(i, rc, sizeof(pkt));

	if (dts->ctx->legacy) {
		if (dts->ctx->myid->len >= 20)
			COPY(pkt, i, dts->ctx->myid->id, 20, sizeof(pkt));
		else {
			memset(pkt + i, 0, 20);
			memcpy(pkt + i, dts->ctx->myid->id, dts->ctx->myid->len);
			i += 20;
		}
	} else {
		pkt[i++] = (char)dts->ctx->myid->type;
		pkt[i++] = (char)dts->ctx->myid->len;
		CHECK(i, dts->ctx->myid->len, sizeof(pkt));
		memcpy(pkt + i, dts->ctx->myid->id, dts->ctx->myid->len);
		i += dts->ctx->myid->len;
	}

	/* Correct alphabetical order: id, len, offset, sack.  Need an extra 'e' to close rd dict. */
	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "3:leni0e6:offseti%llue",
			 (unsigned long long)stats->ack_offset);
	INC(i, rc, sizeof(pkt));

	{
		lws_transport_sequencer_sack_block_t blocks[4];
		size_t num_blocks, j;

		num_blocks = lws_transport_sequencer_get_sack_blocks(ts, blocks, 4);
		if (num_blocks) {
			rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "4:sackl");
			INC(i, rc, sizeof(pkt));
			for (j = 0; j < num_blocks; j++) {
				/* d1:li...e1:oi...ee */
				rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "d1:li%llue1:oi%lluee",
						  (unsigned long long)blocks[j].len,
						  (unsigned long long)blocks[j].start);
				INC(i, rc, sizeof(pkt));
			}
			rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "e");
			INC(i, rc, sizeof(pkt));
		}
	}

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "e1:t4:sqnc1:y1:re");
	INC(i, rc, sizeof(pkt));

	return dht_send(dts->ctx, pkt, i, (struct sockaddr *)&dts->sa, dts->salen);

fail:
	return -1;
}

static int
dht_on_rx_data(struct lws_transport_sequencer *ts, uint64_t offset,
	       const uint8_t *buf, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	struct lws_dht_msg msg;

	if (!lws_dht_msg_parse((const char *)buf, len, &msg)) {
		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&dts->ctx->verb_owner)) {
			struct lws_dht_verb_list *vl = lws_container_of(d, struct lws_dht_verb_list, list);
			if (!strcmp(vl->v.name, msg.verb)) {
				struct lws_dht_verb_dispatch_args args;
				struct lws *wsi;
				int n;

				args.ctx = dts->ctx;
				args.msg = &msg;
				args.from = (const struct sockaddr *)&dts->sa;
				args.fromlen = dts->salen;

				/* prepare a temporary wsi to associate the callback with this vhost and protocol */
				wsi = lws_zalloc(sizeof(*wsi), "dht verb");
				if (!wsi)
					return -1;

				wsi->a.context = dts->ctx->vhost->context;
				wsi->a.vhost = dts->ctx->vhost;
				wsi->a.protocol = vl->v.protocol;

				n = vl->v.protocol->callback(wsi, LWS_CALLBACK_DHT_VERB_DISPATCH,
							lws_protocol_vh_priv_get(dts->ctx->vhost, vl->v.protocol),
							&args, 0);
				lws_free(wsi);
				return n;
			}
		} lws_end_foreach_dll(d);
	}

	if (dts->ctx->cb)
		dts->ctx->cb(dts->ctx->closure, LWS_DHT_EVENT_DATA,
			     NULL, buf, len, (struct sockaddr *)&dts->sa, dts->salen);

	return 0;
}

static void
dht_on_state_change(struct lws_transport_sequencer *ts, int state, int status)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;

	if (!dts->ctx->cb)
		return;

	dts->ctx->cb(dts->ctx->closure,
		     state == 0 ? LWS_DHT_EVENT_WRITE_COMPLETED :
				  LWS_DHT_EVENT_WRITE_FAILED,
		     NULL, (void *)(intptr_t)status, 0,
		     (struct sockaddr *)&dts->sa, dts->salen);
}

static const lws_transport_sequencer_ops_t dht_seq_ops = {
	.name		= "dht-seq",
	.tx_chunk	= dht_tx_chunk,
	.tx_ack		= dht_tx_ack,
	.on_rx_data	= dht_on_rx_data,
	.on_state_change = dht_on_state_change,
};

static const lws_retry_bo_t dht_retry_policy = {
	.retry_ms_table		= (uint32_t[]){ 25, 50, 100 },
	.retry_ms_table_count	= 3,
	.conceal_count		= 10, /* Increased from 5 to 10 */
};

LWS_VISIBLE struct lws_transport_sequencer *
lws_dht_get_ts(struct lws_dht_ctx *ctx, const struct sockaddr *dest, size_t salen, int create)
{
	lws_dll2_t *d = lws_dll2_get_head(&ctx->ts_owner);
	while (d) {
		lws_dht_ts_t *dts = lws_container_of(d, lws_dht_ts_t, list);
		int match = 0;

		if (dts->sa.ss_family == dest->sa_family) {
			if (dest->sa_family == AF_INET) {
				struct sockaddr_in *sin1 = (struct sockaddr_in *)&dts->sa;
				struct sockaddr_in *sin2 = (struct sockaddr_in *)dest;
				if (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr &&
				    sin1->sin_port == sin2->sin_port)
					match = 1;
			} else if (dest->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin1 = (struct sockaddr_in6 *)&dts->sa;
				struct sockaddr_in6 *sin2 = (struct sockaddr_in6 *)dest;
				if (memcmp(&sin1->sin6_addr, &sin2->sin6_addr, 16) == 0 &&
				    sin1->sin6_port == sin2->sin6_port)
					match = 1;
			}
		}

		if (match)
			return dts->ts;
		d = d->next;
	}

	if (!create)
		return NULL;

	lws_dht_ts_t *dts = lws_zalloc(sizeof(*dts), "dht ts");
	if (!dts)
		return NULL;

	lws_transport_sequencer_info_t tsi = {
		.cx		= ctx->vhost->context,
		.ops		= &dht_seq_ops,
		.retry_policy	= &dht_retry_policy,
		.user_data	= dts,
		.window_size	= 65536, /* 64KB - safe for broadside uploader */
	};

	dts->ctx = ctx;
	dts->salen = salen;
	memcpy(&dts->sa, dest, salen);
	dts->ts = lws_transport_sequencer_create(&tsi);
	if (!dts->ts) {
		lws_free(dts);
		return NULL;
	}

	lws_dll2_add_tail(&dts->list, &ctx->ts_owner);

	return dts->ts;
}

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

static int
send_nodes_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		 struct lws_dht_mparams *mp,
		 struct node **nodes, int numnodes,
		 struct node **nodes6, int numnodes6,
		 int af, struct storage *st)
{
	char buf[2048];
	size_t i = 0;
	int rc, j0, j, k, len, n_idx;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:rd2:id%d:", ctx->legacy ? 20 : (2 + ctx->myid->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (ctx->myid->len >= 20)
			COPY(buf, i, ctx->myid->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, ctx->myid->id, ctx->myid->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)ctx->myid->type;
		buf[i++] = (char)ctx->myid->len;
		CHECK(i, ctx->myid->len, sizeof(buf));
		memcpy(buf + i, ctx->myid->id, ctx->myid->len);
		i += ctx->myid->len;
	}

	if (numnodes > 0) {
		/* Calculate total length */
		size_t nodes_len = 0;
		for (n_idx = 0; n_idx < numnodes; n_idx++) {
			if (ctx->legacy) nodes_len += 26;
			else nodes_len += (size_t)(2 + nodes[n_idx]->id->len + 6);
		}

		rc = lws_snprintf(buf + i, sizeof(buf) - i, "5:nodes%d:", (int)nodes_len);
		INC(i, rc, sizeof(buf));

		for (n_idx = 0; n_idx < numnodes; n_idx++) {
			struct node *n = nodes[n_idx];
			struct sockaddr_in *sin = (struct sockaddr_in*)&n->ss;

			if (ctx->legacy) {
				CHECK(i, 26, sizeof(buf));
				if (n->id->len >= 20) memcpy(buf + i, n->id->id, 20);
				else { memset(buf + i, 0, 20); memcpy(buf + i, n->id->id, n->id->len); }
				i += 20;
			} else {
				CHECK(i, 2 + n->id->len + 6, sizeof(buf));
				buf[i++] = (char)n->id->type;
				buf[i++] = (char)n->id->len;
				memcpy(buf + i, n->id->id, n->id->len);
				i += n->id->len;
			}
			memcpy(buf + i, &sin->sin_addr, 4);
			i += 4;
			memcpy(buf + i, &sin->sin_port, 2);
			i += 2;
		}
	}

	if (numnodes6 > 0) {
		size_t nodes6_len = 0;

		for (n_idx = 0; n_idx < numnodes6; n_idx++) {
			if (ctx->legacy)
				nodes6_len += 38;
			else
				nodes6_len += (size_t)(2 + nodes6[n_idx]->id->len + 18);
		}

		rc = lws_snprintf(buf + i, sizeof(buf) - i, "6:nodes6%d:", (int)nodes6_len);
		INC(i, rc, sizeof(buf));

		for (n_idx = 0; n_idx < numnodes6; n_idx++) {
			struct node *n = nodes6[n_idx];
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
			if (ctx->legacy) {
				CHECK(i, 38, sizeof(buf));
				if (n->id->len >= 20)
					memcpy(buf + i, n->id->id, 20);
				else {
					memset(buf + i, 0, 20);
					memcpy(buf + i, n->id->id, n->id->len);
				}
				i += 20;
			} else {
				CHECK(i, 2 + n->id->len + 18, sizeof(buf));

				buf[i++] = (char)n->id->type;
				buf[i++] = (char)n->id->len;

				memcpy(buf + i, n->id->id, n->id->len);
				i += n->id->len;
			}
			memcpy(buf + i, &sin6->sin6_addr, 16);
			i += 16;
			memcpy(buf + i, &sin6->sin6_port, 2);
			i += 2;
		}
	}

	/* ... rest of function ... */
	if (mp->token_len > 0) {
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "5:token%d:", (int)mp->token_len);
		INC(i, rc, sizeof(buf));
		COPY(buf, i, mp->token, mp->token_len, sizeof(buf));
	}

	if (st && st->numpeers > 0) {
		/* ... existing implementation ... */
		len = af == AF_INET ? 4 : 16;
		j0 = (int)(random() % (unsigned int)st->numpeers);
		j = j0;
		k = 0;

		rc = lws_snprintf(buf + i, sizeof(buf) - i, "6:valuesl"); INC(i, rc, sizeof(buf));
		do {
			if (st->peers[j].len == len) {
				unsigned short swapped;
				swapped = htons(st->peers[j].port);
				rc = lws_snprintf(buf + i, sizeof(buf) - i, "%d:", len + 2);
				INC(i, rc, sizeof(buf));
				COPY(buf, i, st->peers[j].ip, len, sizeof(buf));
				COPY(buf, i, &swapped, 2, sizeof(buf));
				k++;
			}
			j = (int)(((unsigned int)j + 1) % (unsigned int)st->numpeers);
		} while (j != j0 && k < 50);
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "e"); INC(i, rc, sizeof(buf));
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)mp->tid_len); INC(i, rc, sizeof(buf));
	COPY(buf, i, mp->tid, mp->tid_len, sizeof(buf));
	ADD_IP(buf, i, sa, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:re"); INC(i, rc, sizeof(buf));

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_closest_nodes(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		   struct lws_dht_mparams *mp, const lws_dht_hash_t *id,
		   int af, struct storage *st)
{
	struct node *nodes[8];
	struct node *nodes6[8];
	int numnodes = 0, numnodes6 = 0;
	struct bucket *b;
	int want = mp->want;

	if (want < 0)
		want = sa->sa_family == AF_INET ? WANT4 : WANT6;

	if ((want & WANT4)) {
		b = find_bucket(ctx, id, AF_INET);
		if (b) {
			numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b);
			if (b->next)
				numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b->next);
			b = previous_bucket(ctx, b);
			if (b)
				numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b);
		}
	}

	if ((want & WANT6)) {
		b = find_bucket(ctx, id, AF_INET6);
		if (b) {
			numnodes6 = buffer_closest_nodes(ctx, nodes6, numnodes6, id, b);
			if (b->next)
				numnodes6 =
					buffer_closest_nodes(ctx, nodes6, numnodes6, id, b->next);
			b = previous_bucket(ctx, b);
			if (b)
				numnodes6 = buffer_closest_nodes(ctx, nodes6, numnodes6, id, b);
		}
	}
	lwsl_dht_info("  (%d+%d nodes.)\n", numnodes, numnodes6);

	return send_nodes_peers(ctx, sa, salen, mp, nodes, numnodes,
				nodes6, numnodes6, af, st);
}

static unsigned long long
dht_strtoull(const char *p, size_t max_len, char **endptr);

static const uint8_t *
dht_bencode_get_string(const uint8_t *dict, const uint8_t *end, const char *key, size_t *len_ret);

static const uint8_t *
dht_bencode_find_key(const uint8_t *dict, const uint8_t *end, const char *key, size_t *len_ret);

static unsigned long long
dht_bencode_get_int(const uint8_t *dict, const uint8_t *end, const char *key);

static void
parse_hash(const uint8_t *dict, const uint8_t *end, const char *key,
	   lws_dht_hash_t **h_ret);

static unsigned long long
dht_strtoull(const char *p, size_t max_len, char **endptr)
{
	unsigned long long n = 0;
	size_t i = 0;

	while (i < max_len && p[i] >= '0' && p[i] <= '9') {
		n = n * 10 + (unsigned int)(p[i] - '0');
		i++;
	}

	if (endptr)
		*endptr = (char *)p + i;

	return n;
}

static void
parse_hash(const uint8_t *dict, const uint8_t *end, const char *key,
	   lws_dht_hash_t **h_ret)
{
	size_t l;
	const uint8_t *data = dht_bencode_get_string(dict, end, key, &l);

	*h_ret = NULL;
	if (data) {
		int type = 0, len = 0;
		const uint8_t *hash_data = NULL;

		if (l == 20) {
			type = LWS_DHT_HASH_TYPE_SHA1;
			len = 20;
			hash_data = data;
		} else if (l > 2 && data[1] == l - 2) {
			type = data[0];
			len = data[1];
			hash_data = data + 2;
		}

		if (hash_data && lws_dht_hash_validate(type, len)) {
			*h_ret = lws_dht_hash_create(type, len, hash_data);
		} else {
			lwsl_notice("%s: rejecting invalid/unsupported hash type %d len %d\n",
					__func__, type, len);
		}
	}
}

static int
send_error(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len,
		int code, const char *message)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:eli%de%d:",
			code, (int)strlen(message));
	INC(i, rc, sizeof(buf));
	COPY(buf, i, message, (int)strlen(message), sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)tid_len); INC(i, rc, sizeof(buf));
	COPY(buf, i, tid, tid_len, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:ee"); INC(i, rc, sizeof(buf));
	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}



static int
dht_bencode_skip(const uint8_t **pp, const uint8_t *end)
{
	const uint8_t *p = *pp;
	char *q;

	if (p >= end)
		return -1;

	switch (*p) {
	case 'd':
		p++;
		while (p < end && *p != 'e') {
			if (dht_bencode_skip(&p, end)) /* key */
				return -1;
			if (dht_bencode_skip(&p, end)) /* value */
				return -1;
		}
		if (p >= end || *p != 'e')
			return -1;
		p++;
		break;
	case 'l':
		p++;
		while (p < end && *p != 'e') {
			if (dht_bencode_skip(&p, end))
				return -1;
		}
		if (p >= end || *p != 'e')
			return -1;
		p++;
		break;
	case 'i':
		p++;
		while (p < end && *p != 'e')
			p++;
		if (p >= end || *p != 'e')
			return -1;
		p++;
		break;
	default: /* string N:data */
		if (*p < '0' || *p > '9')
			return -1;
		{
			unsigned long long l = dht_strtoull((const char *)p, (size_t)(end - p), &q);
			if (!q || *q != ':')
				return -1;
			p = (uint8_t *)q + 1;
			if (p + l > end)
				return -1;
			p += (size_t)l;
		}
		break;
	}
	*pp = p;
	return 0;
}

static const uint8_t *
dht_bencode_find_key(const uint8_t *buf, const uint8_t *end, const char *key, size_t *vlen)
{
	const uint8_t *p = buf;
	size_t klen = strlen(key);
	char *q;

	if (p >= end || *p != 'd')
		return NULL;
	p++;

	while (p < end && *p != 'e') {
		unsigned long long l = dht_strtoull((const char *)p, (size_t)(end - p), &q);
		if (!q || *q != ':')
			return NULL;
		p = (uint8_t *)q + 1;
		if (p + l > end)
			return NULL;

		if ((size_t)l == klen && !memcmp(p, key, klen)) {
			const uint8_t *vstart = p + (size_t)l;
			const uint8_t *vend = vstart;

			if (dht_bencode_skip(&vend, end))
				return NULL;

			if (vlen)
				*vlen = (size_t)(vend - vstart);
			return vstart;
		}

		p += (size_t)l;
		if (dht_bencode_skip(&p, end))
			return NULL;
	}

	return NULL;
}

static const uint8_t *
dht_bencode_get_string(const uint8_t *dict, const uint8_t *end, const char *key, size_t *len_ret)
{
	size_t vlen;
	const uint8_t *p = dht_bencode_find_key(dict, end, key, &vlen);
	char *q;

	if (!p)
		return NULL;

	*len_ret = (size_t)dht_strtoull((const char *)p, vlen, &q);
	if (!q || *q != ':')
		return NULL;

	if ((const uint8_t *)q + 1 + *len_ret > end)
		return NULL;

	return (const uint8_t *)q + 1;
}

static unsigned long long
dht_bencode_get_int(const uint8_t *dict, const uint8_t *end, const char *key)
{
	size_t vlen;
	const uint8_t *p = dht_bencode_find_key(dict, end, key, &vlen);
	char *q;

	if (!p || *p != 'i')
		return 0;

	return dht_strtoull((const char *)p + 1, vlen - 1, &q);
}

int
parse_message(const uint8_t *buf, size_t buflen, struct lws_dht_mparams *mp)
{
#define CHECK_BUF(p, l) \
	do { if ((const uint8_t *)(p) + (l) > end) goto fail; } while(0)
	const uint8_t *p, *end = buf + buflen, *meta = NULL, *meta_end = NULL;
	size_t l;
	int message = -1;
	const uint8_t *q_ptr;

	memset(mp, 0, sizeof(*mp));
	mp->tid_len = sizeof(mp->tid);
	mp->token_len = sizeof(mp->token);
	mp->nodes_len = sizeof(mp->nodes);
	mp->nodes6_len = sizeof(mp->nodes6);
	mp->values_len = sizeof(mp->values);
	mp->values6_len = sizeof(mp->values6);
	mp->want = -1;

	if (buflen < 2 || buf[0] != 'd')
		return -1;

	p = dht_bencode_get_string(buf, end, "t", &l);
	if (p && l > 0 && l < sizeof(mp->tid)) {
		memcpy(mp->tid, p, l);
		mp->tid_len = l;
	} else
		mp->tid_len = 0;

	p = dht_bencode_get_string(buf, end, "y", &l);
	if (!p || l != 1)
		return -1;

	switch (*p) {
	case 'r':
		message = DHT_REPLY;
		meta = dht_bencode_find_key(buf, end, "r", &l);
		break;
	case 'q':
		q_ptr = dht_bencode_get_string(buf, end, "q", &l);
		if (!q_ptr)
			return -1;
		if (l == 4 && !memcmp(q_ptr, "ping", 4))
			message = DHT_PING;
		else if (l == 9 && !memcmp(q_ptr, "find_node", 9))
			message = DHT_FIND_NODE;
		else if (l == 9 && !memcmp(q_ptr, "get_peers", 9))
			message = DHT_GET_PEERS;
		else if (l == 13 && !memcmp(q_ptr, "announce_peer", 13))
			message = DHT_ANNOUNCE_PEER;
		else if (l == 4 && !memcmp(q_ptr, "data", 4))
			message = DHT_DATA;
		else
			return -1;

		meta = dht_bencode_find_key(buf, end, "a", &l);
		break;
	case 'e':
		return DHT_ERROR;
	default:
		return -1;
	}

	p = dht_memmem(buf, buflen, "5:token", 7);
	if (p) {
		size_t l;
		char *q;

		l = dht_strtoull((char*)p + 7,
			buflen - lws_ptr_diff_size_t(p + 7, buf), &q);
		if (q && (uint8_t *)q < buf + buflen && *q == ':' && l > 0 && l < mp->token_len) {
			CHECK_BUF(q + 1, l);
			memcpy(mp->token, q + 1, l);
			mp->token_len = l;
		} else
			mp->token_len = 0;
	}

	if (!meta || *meta != 'd')
		return message;

	meta_end = meta + l;

	parse_hash(meta, meta_end, "id", &mp->id);
	parse_hash(meta, meta_end, "info_hash", &mp->info_hash);
	parse_hash(meta, meta_end, "target", &mp->target);

	if (dht_bencode_find_key(meta, meta_end, "implied_port", &l))
		mp->port = 1;
	else
		mp->port = (unsigned short)dht_bencode_get_int(meta, meta_end, "port");

	p = dht_bencode_get_string(meta, meta_end, "token", &l);
	if (p && l > 0 && l < sizeof(mp->token)) {
		memcpy(mp->token, p, l);
		mp->token_len = l;
	} else
		mp->token_len = 0;

	p = dht_bencode_get_string(meta, meta_end, "nodes", &l);
	if (p && l > 0 && l < sizeof(mp->nodes)) {
		memcpy(mp->nodes, p, l);
		mp->nodes_len = l;
	} else
		mp->nodes_len = 0;

	p = dht_bencode_get_string(meta, meta_end, "nodes6", &l);
	if (p && l > 0 && l < sizeof(mp->nodes6)) {
		memcpy(mp->nodes6, p, l);
		mp->nodes6_len = l;
	} else
		mp->nodes6_len = 0;

	if (message == DHT_DATA) {
		p = dht_bencode_get_string(meta, meta_end, "data", &l);
		if (p) {
			mp->data = p;
			mp->data_len = l;
		}
	}

	if (dht_bencode_find_key(meta, meta_end, "offset", NULL)) {
		mp->offset = dht_bencode_get_int(meta, meta_end, "offset");
		lwsl_debug("%s: Parsed offset %llu\n", __func__, (unsigned long long)mp->offset);
	} else
		lwsl_notice("%s: offset key NOT FOUND in reply\n", __func__);

	if (dht_bencode_find_key(meta, meta_end, "len", NULL))
		mp->len = dht_bencode_get_int(meta, meta_end, "len");

	p = dht_bencode_find_key(meta, meta_end, "sack", &l);
	if (p && *p == 'l') {
		const uint8_t *v = p + 1, *vend = p + l;
		while (v < vend && *v != 'e' && mp->num_sack < 4) {
			if (*v == 'd') {
				const uint8_t *vstart = v, *v_dict_end = v;
				if (dht_bencode_skip(&v_dict_end, vend))
					break;
				mp->sack[mp->num_sack].len = (uint32_t)dht_bencode_get_int(vstart, v_dict_end, "l");
				mp->sack[mp->num_sack].start = dht_bencode_get_int(vstart, v_dict_end, "o");
				mp->num_sack++;
				v = v_dict_end;
			} else break;
		}
	}

	p = dht_bencode_find_key(meta, meta_end, "values", &l);
	if (p && *p == 'l') {
		const uint8_t *v = p + 1, *vend = p + l;
		size_t j = 0, j6 = 0;
		while (v < vend && *v != 'e') {
			size_t slen;
			char *q_ptr;
			unsigned long long sl = dht_strtoull((const char *)v, (size_t)(vend - v), &q_ptr);
			if (!q_ptr || *q_ptr != ':')
				break;
			slen = (size_t)sl;
			v = (const uint8_t *)q_ptr + 1;
			if (v + slen > vend)
				break;
			if (slen == 6 && j + 6 <= sizeof(mp->values)) {
				memcpy(mp->values + j, v, 6);
				j += 6;
			} else if (slen == 18 && j6 + 18 <= sizeof(mp->values6)) {
				memcpy(mp->values6 + j6, v, 18);
				j6 += 18;
			}
			v += slen;
		}
		mp->values_len = j;
		mp->values6_len = j6;
	}

	p = dht_bencode_find_key(buf, end, "ip", &l);
	if (!p)
		p = dht_bencode_find_key(buf, end, "you", &l);
	if (p) {
		size_t slen;
		char *q_ptr;
		unsigned long long sl = dht_strtoull((const char *)p, (size_t)(end - p), &q_ptr);
		if (q_ptr && *q_ptr == ':' && (sl == 6 || sl == 18)) {
			slen = (size_t)sl;
			p = (const uint8_t *)q_ptr + 1;
			mp->sender_ip_len = (int)slen - 2;
			memcpy(mp->sender_ip, p, (size_t)mp->sender_ip_len);
			memcpy(&mp->sender_port, p + mp->sender_ip_len, 2);
			mp->sender_port = ntohs(mp->sender_port);
		} else
			mp->sender_ip_len = 0;
	} else
		mp->sender_ip_len = 0;

#undef CHECK_BUF

	if (dht_memmem(buf, buflen, "1:y1:r", 6))
		return DHT_REPLY;
	if (dht_memmem(buf, buflen, "1:y1:e", 6))
		return DHT_ERROR;
	if (!dht_memmem(buf, buflen, "1:y1:q", 6))
		return -1;
	/* Parse query type robustly */
	{
		uint8_t *p = dht_memmem(buf, buflen, "1:q", 3);
		if (p) {
			char *endptr;
			long qlen;
			/* Value should be string: "N:value" */
			qlen = (long)dht_strtoull((char*)p + 3,
				buflen - lws_ptr_diff_size_t(p + 3, buf), &endptr);

			if (endptr && (uint8_t *)endptr < buf + buflen && *endptr == ':') {
				p = (uint8_t *)endptr + 1;
				/*
				 * Check bounds? buflen unknown relative to p here easily without math.
				 * Assuming dht_memmem ensures it's within buf.
				 */
				if (qlen == 4 && memcmp(p, "ping", 4) == 0)
					return DHT_PING;
				if (qlen == 9 && memcmp(p, "find_node", 9) == 0)
					return DHT_FIND_NODE;
				if (qlen == 9 && memcmp(p, "get_peers", 9) == 0)
					return DHT_GET_PEERS;
				if (qlen == 13 && memcmp(p, "announce_peer", 13) == 0)
					return DHT_ANNOUNCE_PEER;
				if (qlen == 4 && memcmp(p, "data", 4) == 0)
					return DHT_DATA;

				lwsl_dht_rx_warn("Unknown q: %.*s\n", (int)qlen, p);
			}
		}
	}

	return message;

fail:
	return -1;
}


static int
send_peer_announced(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:rd2:id%d:", ctx->legacy ? 20 : (2 + ctx->myid->len));
	INC(i, rc, sizeof(buf));

	if (ctx->legacy) {
		if (ctx->myid->len >= 20)
			COPY(buf, i, ctx->myid->id, 20, sizeof(buf));
		else {
			memset(buf + i, 0, 20);
			memcpy(buf + i, ctx->myid->id, ctx->myid->len);
			i += 20;
		}
	} else {
		buf[i++] = (char)ctx->myid->type;
		buf[i++] = (char)ctx->myid->len;
		CHECK(i, ctx->myid->len, sizeof(buf));
		memcpy(buf + i, ctx->myid->id, ctx->myid->len);
		i += ctx->myid->len;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)tid_len);
	INC(i, rc, sizeof(buf));
	COPY(buf, i, tid, tid_len, sizeof(buf));
	ADD_IP(buf, i, sa, sizeof(buf));
	ADD_V(buf, i, ctx, sizeof(buf));
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:re"); INC(i, rc, sizeof(buf));
	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

/* Rate control for requests we receive. */

static int
token_bucket(struct lws_dht_ctx *ctx)
{
	if (ctx->token_bucket_tokens == 0) {
		ctx->token_bucket_tokens = (int)MIN((long)MAX_TOKEN_BUCKET_TOKENS,
				100 * (long)(ctx->now.tv_sec - ctx->token_bucket_time));
		ctx->token_bucket_time = ctx->now.tv_sec;
	}

	if (ctx->token_bucket_tokens == 0)
		return 0;

	ctx->token_bucket_tokens--;
	return 1;
}

static void
lws_dht_reply_pong(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		   const struct sockaddr *from, size_t fromlen)
{
	lwsl_dht_rx("Pong!\n");
	new_node(ctx, mp->id, from, fromlen, 2);
}

static void
lws_dht_reply_nodes(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		    const struct sockaddr *from, size_t fromlen)
{
	int gp = 0;
	struct search *sr = NULL;
	unsigned short ttid;
	size_t offset;

	if (tid_match(mp->tid, "gp", &ttid)) {
		gp = 1;
		sr = find_search(ctx, ttid, from->sa_family);
	}

	lwsl_dht_rx("Nodes found (%d+%d)%s!\n", (int)(mp->nodes_len / 26),
			(int)(mp->nodes6_len / 38),
			gp ? " for get_peers" : "");

	if (ctx->legacy && (mp->nodes_len % 26 != 0 || mp->nodes6_len % 38 != 0)) {
		lwsl_dht_rx_warn("Unexpected length for node info!\n");
		blacklist_node(ctx, mp->id, from, fromlen);
		return;
	}

	offset = 0;
	while (offset < mp->nodes_len) {
		uint8_t *ni = (uint8_t *)mp->nodes + offset;
		lws_dht_hash_t *node_id = NULL;
		size_t step = 0;
		uint8_t hash_type;
		uint8_t hash_len;
		const uint8_t *hash_data;

		if (ctx->legacy) {
			if (offset + 26 > mp->nodes_len) break;
			hash_type = LWS_DHT_HASH_TYPE_SHA1;
			hash_len = 20;
			hash_data = ni;
			step = 26;
		} else {
			if (offset + 2 > mp->nodes_len) break;
			hash_type = ni[0];
			hash_len = ni[1];
			if (offset + 2 + hash_len + 6 > mp->nodes_len) break;
			hash_data = ni + 2;
			step = (size_t)(2 + hash_len + 6);
		}

		node_id = lws_dht_hash_create(hash_type, hash_len, hash_data);
		if (node_id) {
			if (lws_dht_hash_cmp(node_id, ctx->myid) != 0) {
				struct sockaddr_in sin;

				memset(&sin, 0, sizeof(sin));
				sin.sin_family = AF_INET;
				if (ctx->legacy) {
					memcpy(&sin.sin_addr, ni + 20, 4);
					memcpy(&sin.sin_port, ni + 24, 2);
				} else {
					memcpy(&sin.sin_addr, ni + 2 + hash_len, 4);
					memcpy(&sin.sin_port, ni + 2 + hash_len + 4, 2);
				}
				new_node(ctx, node_id, (struct sockaddr*)&sin, sizeof(sin), 0);
				if (sr && sr->af == AF_INET)
					insert_search_node(ctx, node_id, (struct sockaddr*)&sin, sizeof(sin), sr, 0, NULL, 0);

			}
			lws_dht_hash_destroy(&node_id);
		}
		offset += step;
	}

	offset = 0;
	while (offset < mp->nodes6_len) {
		uint8_t *ni = (uint8_t *)mp->nodes6 + offset;
		lws_dht_hash_t *node_id = NULL;
		size_t step = 0;
		uint8_t hash_type;
		uint8_t hash_len;
		const uint8_t *hash_data;

		if (ctx->legacy) {
			if (offset + 38 > mp->nodes6_len) break;
			hash_type = LWS_DHT_HASH_TYPE_SHA1;
			hash_len = 20;
			hash_data = ni;
			step = 38;
		} else {
			if (offset + 2 > mp->nodes6_len) break;
			hash_type = ni[0];
			hash_len = ni[1];
			if (offset + 2 + hash_len + 18 > mp->nodes6_len) break;
			hash_data = ni + 2;
			step = (size_t)(2 + hash_len + 18);
		}

		node_id = lws_dht_hash_create(hash_type, hash_len, hash_data);
		if (node_id) {
			if (lws_dht_hash_cmp(node_id, ctx->myid) != 0) {
				struct sockaddr_in6 sin6;
				memset(&sin6, 0, sizeof(sin6));
				sin6.sin6_family = AF_INET6;
				if (ctx->legacy) {
					memcpy(&sin6.sin6_addr, ni + 20, 16);
					memcpy(&sin6.sin6_port, ni + 36, 2);
				} else {
					memcpy(&sin6.sin6_addr, ni + 2 + hash_len, 16);
					memcpy(&sin6.sin6_port, ni + 2 + hash_len + 16, 2);
				}
				new_node(ctx, node_id, (struct sockaddr*)&sin6, sizeof(sin6), 0);
				if (sr && sr->af == AF_INET6)
					insert_search_node(ctx, node_id, (struct sockaddr*)&sin6,
							sizeof(sin6), sr, 0, NULL, 0);
			}
			lws_dht_hash_destroy(&node_id);
		}
		offset += step;
	}

	if (sr) {
		insert_search_node(ctx, mp->id, from, fromlen, sr, 1, mp->token, mp->token_len);
		if (mp->values_len > 0 || mp->values6_len > 0) {
			lwsl_dht_rx("Got values (%d+%d)!\n", (int)(mp->values_len / 6), (int)(mp->values6_len / 18));
			if (ctx->cb) {
				int j;

				for (j = 0; j < (int)mp->values_len; j += 6)
					(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES, sr->id, mp->values + j, 6, from, fromlen);
				for (j = 0; j < (int)mp->values6_len; j += 18)
					(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES6, sr->id, mp->values6 + j, 18, from, fromlen);
			}
		}
		search_send_get_peers(ctx, sr, NULL);
	}
}

static void
lws_dht_reply_announce(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		       const struct sockaddr *from, size_t fromlen)
{
	unsigned short ttid;
	struct search *sr;

	lwsl_dht_rx("Got reply to announce_peer.\n");
	if (!tid_match(mp->tid, "ap", &ttid))
		return;

	sr = find_search(ctx, ttid, from->sa_family);
	if (!sr) {
		lwsl_dht_warn("Unknown search!\n");
		new_node(ctx, mp->id, from, fromlen, 1);
	} else {
		size_t i;
		new_node(ctx, mp->id, from, fromlen, 2);
		for (i = 0; i < (size_t)sr->numnodes; i++)
			if (id_cmp(sr->nodes[i].id, mp->id) == 0) {
				sr->nodes[i].request_time = 0;
				sr->nodes[i].reply_time = (time_t)lws_now_secs();
				sr->nodes[i].acked = 1;
				sr->nodes[i].pinged = 0;
				break;
			}
		/* See comment for gp above. */
		search_send_get_peers(ctx, sr, NULL);
	}
}

static int
lws_dht_process_packet(struct lws_dht_ctx *ctx, const void *buf, size_t buflen,
			const struct sockaddr *from, size_t fromlen)
{
	struct lws_dht_mparams mp;
	int message;

	memset(&mp, 0, sizeof(mp));
	mp.offset = (uint64_t)-1;

	mp.tid_len = sizeof(mp.tid);
	mp.token_len = sizeof(mp.token);
	mp.nodes_len = sizeof(mp.nodes);
	mp.nodes6_len = sizeof(mp.nodes6);
	mp.values_len = sizeof(mp.values);
	mp.values6_len = sizeof(mp.values6);

	ctx->now.tv_sec = (time_t)lws_now_secs();

	if (is_martian(from))
		return 0;

	if (node_blacklisted(ctx, from, fromlen)) {
		lwsl_dht_rx("Received packet from blacklisted node.\n");
		return 0;
	}

	message = parse_message(buf, buflen, &mp);

	if (message < 0 || message == DHT_ERROR || lws_dht_hash_is_zero(mp.id)) {
		lwsl_dht_rx_warn("Unparseable message. msg=%d id_ptr=%p\n", message, mp.id);
		goto done;
	}

	if (id_cmp(mp.id, ctx->myid) == 0) {
		lwsl_dht_warn("Received message from self. id %02x ctx->myid %02x, ctx %p\n", mp.id->id[0], ctx->myid->id[0], ctx);
		goto done;
	}

	if (message > DHT_REPLY && message != DHT_DATA) {
		/* Rate limit requests. */
		if (!token_bucket(ctx)) {
			lwsl_dht_warn("Dropping request due to rate limiting.\n");
			goto done;
		}
	} else if (message == DHT_REPLY && mp.sender_ip_len) {
		/* Track reported external address */
		struct sockaddr_storage ss;
		size_t sslen;
		int found = 0, j;

		memset(&ss, 0, sizeof(ss));
		if (mp.sender_ip_len == 4) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, mp.sender_ip, 4);
			sin->sin_port = htons(mp.sender_port);
			sslen = sizeof(*sin);
		} else {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			memcpy(&sin6->sin6_addr, mp.sender_ip, 16);
			sin6->sin6_port = htons(mp.sender_port);
			sslen = sizeof(*sin6);
		}

		for (j = 0; j < ctx->num_reported_ads; j++) {
			if (ctx->reported_ads[j].sslen == sslen &&
			    !memcmp(&ctx->reported_ads[j].ss, &ss, sslen)) {
				ctx->reported_ads[j].count++;
				found = 1;
				if (ctx->reported_ads[j].count >= 3 && !ctx->external_ads_set) {
					lwsl_notice("%s: reached consensus on external address\n", __func__);
					ctx->external_ads_set = 1;
					if (ctx->cb)
						ctx->cb(ctx->closure,
							ss.ss_family == AF_INET ?
								LWS_DHT_EVENT_EXTERNAL_ADDR :
								LWS_DHT_EVENT_EXTERNAL_ADDR6,
							NULL, &ss, sslen, from, fromlen);
				}
				break;
			}
		}
		if (!found && ctx->num_reported_ads < (int)LWS_ARRAY_SIZE(ctx->reported_ads)) {
			ctx->reported_ads[ctx->num_reported_ads].ss = ss;
			ctx->reported_ads[ctx->num_reported_ads].sslen = sslen;
			ctx->reported_ads[ctx->num_reported_ads].count = 1;
			ctx->num_reported_ads++;
		}
	}

	switch(message) {
	case DHT_REPLY:
		if (mp.tid_len != 4) {
			lwsl_dht_rx_warn("Broken node truncates transaction ids.\n");
			blacklist_node(ctx, mp.id, from, fromlen);
			break;
		}
		if (tid_match(mp.tid, "pn", NULL)) {
			lws_dht_reply_pong(ctx, &mp, from, fromlen);
			break;
		}
		if (tid_match(mp.tid, "fn", NULL) || tid_match(mp.tid, "gp", NULL)) {
			lws_dht_reply_nodes(ctx, &mp, from, fromlen);
			break;
		}
		if (tid_match(mp.tid, "ap", NULL)) {
			lws_dht_reply_announce(ctx, &mp, from, fromlen);
			break;
		}

		if (tid_match(mp.tid, "da", NULL) || tid_match(mp.tid, "sqnc", NULL)) {
			struct lws_transport_sequencer *ts;

			ts = lws_dht_get_ts(ctx, from, fromlen, 0);
			if (ts) {
				lws_transport_sequencer_acknowledge_sack(ts, mp.offset + mp.len,
									 mp.sack, mp.num_sack, mp.status);
			} else {
				char ads[64];
				lws_sa46_write_numeric_address((lws_sockaddr46 *)from, ads, sizeof(ads));
				lwsl_warn("dht_cb: ACK received from %s (len %d) but no sequencer found!\n", ads, (int)fromlen);
			}
			break;
		}


		lwsl_dht_rx_warn("Unexpected reply.\n");
		blacklist_node(ctx, mp.id, from, fromlen);
		break;

	case DHT_PING:
		lwsl_dht_rx("Ping (%d)!\n", (int)mp.tid_len);
		new_node(ctx, mp.id, from, fromlen, 1);
		lwsl_dht_rx("Sending pong.\n");
		send_pong(ctx, from, fromlen, mp.tid, mp.tid_len);
		break;

	case DHT_FIND_NODE:
		lwsl_dht_rx("Find node!\n");
		new_node(ctx, mp.id, from, fromlen, 1);
		lwsl_dht_rx("Sending closest nodes (%d).\n", mp.want);
		send_closest_nodes(ctx, from, fromlen, &mp, mp.target, 0, NULL);
		break;

	case DHT_GET_PEERS:
		lwsl_dht_rx("Get_peers!\n");
		new_node(ctx, mp.id, from, fromlen, 1);
		if (lws_dht_hash_is_zero(mp.info_hash)) {
			lwsl_dht_rx_warn("Eek!  Got get_peers with no info_hash.\n");
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
					203, "Get_peers with no info_hash");
			break;
		} else {
			struct storage *st = find_storage(ctx, mp.info_hash);

			make_token(ctx, from, 0, mp.token);
			mp.token_len = TOKEN_SIZE;

			if (st && st->numpeers > 0) {
				lwsl_dht_rx("Sending found%s peers.\n",
						from->sa_family == AF_INET6 ? " IPv6" : "");
				send_closest_nodes(ctx, from, fromlen, &mp,
						   mp.info_hash, from->sa_family, st);
				break;
			}
			lwsl_dht_rx("Sending nodes for get_peers.\n");
			send_closest_nodes(ctx, from, fromlen, &mp,
					   mp.info_hash, 0, NULL);
			break;
		}
		break;

	case DHT_DATA:
		if (mp.data) {
			struct lws_transport_sequencer *ts;
			lwsl_dht_rx("Received reliable data payload (%d bytes, offset %llu)\n",
				    (int)mp.data_len, (unsigned long long)mp.offset);
			ts = lws_dht_get_ts(ctx, from, fromlen, 1);
			if (ts)
				lws_transport_sequencer_rx(ts, mp.offset, mp.data, mp.data_len);
		}
		break;
	case DHT_ANNOUNCE_PEER:
		lwsl_dht_rx("Announce peer!\n");
		new_node(ctx, mp.id, from, fromlen, 1);
		{
			int is_zero = 1;
			int i;
			for (i = 0; i < mp.info_hash->len; i++)
				if (mp.info_hash->id[i]) {
					is_zero = 0;
					break;
				}
			if (is_zero) {
				lwsl_dht_rx_warn("Announce_peer with no info_hash.\n");
				send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
						203, "Announce_peer with no info_hash");
				break;
			}
		}
		if (!token_match(ctx, mp.token, mp.token_len, from)) {
			lwsl_dht_rx_warn("Incorrect token for announce_peer.\n");
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
					   203, "Announce_peer with bad token");
			break;
		}



		lws_dht_capture_announce(ctx, mp.info_hash, from, mp.port ? mp.port : mp.sender_port);
		lws_dht_reply_announce(ctx, &mp, from, fromlen);

		if (mp.port == 0) {
			lwsl_dht_rx_warn("Announce with forbidden port %d.\n", mp.port);
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
					203, "Announce_peer with forbidden port number");
			break;
		}
		if (mp.port == 1) {
			lwsl_dht_rx("Announce with implied port. Using from port.\n");
			if (from->sa_family == AF_INET) {
				struct sockaddr_in *temp_sin = (struct sockaddr_in*)from;
				mp.port = ntohs(temp_sin->sin_port);
			}
			else {
				struct sockaddr_in6 *temp_sin6 = (struct sockaddr_in6*)from;
				mp.port = ntohs(temp_sin6->sin6_port);
			}
		}

		storage_store(ctx, mp.info_hash, from, mp.port);

		/*
		* Note that if storage_store failed, we lie to the requestor.
		* This is to prevent them from backtracking, and hence
		* polluting the DHT.
		*/

		lws_dht_capture_announce(ctx, mp.info_hash, from, mp.port);

		lwsl_dht_rx("Sending peer announced.\n");
		send_peer_announced(ctx, from, fromlen, mp.tid, mp.tid_len);
		break;
	}
done:
	lws_dht_hash_destroy(&mp.id);
	lws_dht_hash_destroy(&mp.info_hash);
	lws_dht_hash_destroy(&mp.target);

	return 0;
}



int
lws_callback_dht(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct lws_dht_ctx *ctx;

	switch (reason) {

	case LWS_CALLBACK_RAW_RX: {
		if (!user)
			break;
		ctx = *((struct lws_dht_ctx **)user);
		if (!ctx)
			break;

		lws_dht_process_packet(ctx, in, len,
				       sa46_sockaddr(&wsi->udp->sa46),
				       sa46_socklen(&wsi->udp->sa46));
		break;
	}

	case LWS_CALLBACK_RAW_ADOPT:
		break;

	default:
		break;
	}

	return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_protocol =
	{ "lws-dht", lws_callback_dht, sizeof(struct lws_dht_ctx *), 0, 0, NULL, 0 };

int
lws_dht_get_external_addr(struct lws_dht_ctx *ctx, struct sockaddr_storage *ss,
			  size_t *sslen)
{
	int j;

	if (!ctx->external_ads_set)
		return -1;

	for (j = 0; j < ctx->num_reported_ads; j++) {
		if (ctx->reported_ads[j].count >= 3) {
			*ss = ctx->reported_ads[j].ss;
			*sslen = ctx->reported_ads[j].sslen;

			return 0;
		}
	}

	return -1;
}

struct lws_dht_ctx *
lws_dht_create(const lws_dht_info_t *info)
{
	struct lws_dht_ctx *ctx = lws_zalloc(sizeof(*ctx), "dht ctx");
	int rc;

	if (!ctx)
		return NULL;

	ctx->vhost		= info->vhost;
	ctx->cb			= info->cb;
	ctx->closure		= info->closure;
	ctx->legacy = info->legacy;
	ctx->iface = info->iface;
	if (info->name) {
		ctx->name = lws_strdup(info->name);
		if (!ctx->name)
			goto fail;
	}
	ctx->blacklist_cb = info->blacklist_cb;
	ctx->hash_cb = info->hash_cb;
	ctx->capture_announce_cb = info->capture_announce_cb;
	lws_dll2_owner_clear(&ctx->ts_owner);
	lws_dll2_owner_clear(&ctx->verb_owner);

	if (info->id)
		ctx->myid = lws_dht_hash_dup(info->id);
	else {
		uint8_t temp_id[20];
		lws_get_random(ctx->vhost->context, temp_id, 20);
		ctx->myid = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, temp_id);
	}

	if (!ctx->myid) {
		lws_free(ctx);
		return NULL;
	}

	if (info->v) {
		memcpy(ctx->my_v, "1:v4:", 5);
		memcpy(ctx->my_v + 5, info->v, 4);
		ctx->have_v = 1;
	}

	ctx->now.tv_sec			= (time_t)lws_now_secs();

	ctx->mybucket_grow_time		= ctx->now.tv_sec;
	ctx->mybucket6_grow_time	= ctx->now.tv_sec;
	ctx->confirm_nodes_time		= ctx->now.tv_sec + ((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) % 3);

	ctx->search_id			= (unsigned short)((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) & 0xFFFF);
	ctx->search_time		= 0;

	ctx->next_blacklisted		= 0;

	ctx->token_bucket_time		= ctx->now.tv_sec;
	ctx->token_bucket_tokens	= MAX_TOKEN_BUCKET_TOKENS;

	ctx->iface = info->iface;

	memset(ctx->secret, 0, sizeof(ctx->secret));
	rc = rotate_secrets(ctx);
	if (rc < 0)
		goto fail;

	if (info->port) {
		ctx->wsi_v4 = lws_create_adopt_udp(ctx->vhost, ctx->iface, info->port, LWS_CAUDP_BIND,
						   lws_dht_protocol.name, NULL, NULL, ctx, NULL, "dht-v4");
		if (!ctx->wsi_v4)
			goto fail;
		*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v4)) = ctx;

		if (info->ipv6) {
			const char *v6ads = ctx->iface;
			if (!v6ads)
				v6ads = "::";
			ctx->wsi_v6 = lws_create_adopt_udp(ctx->vhost, v6ads, info->port, LWS_CAUDP_BIND,
							   lws_dht_protocol.name, NULL, NULL, ctx, NULL, "dht-v6");
			if (ctx->wsi_v6)
				*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v6)) = ctx;
			/* It's OK if IPv6 fails if not supported */
		}
	}

	ctx->buckets = lws_zalloc(sizeof(struct bucket), __func__);
	if (ctx->buckets) {
		ctx->buckets->af = AF_INET;
		ctx->buckets->first = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, zeroes);
		if (!ctx->buckets->first) goto fail;
	} else goto fail;

	if (info->ipv6) {
		ctx->buckets6 = lws_zalloc(sizeof(struct bucket), __func__);
		if (ctx->buckets6) {
			ctx->buckets6->af = AF_INET6;
			ctx->buckets6->first = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, zeroes);
			if (!ctx->buckets6->first)
				goto fail;
		} else
			goto fail;
	}

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul,
			 lws_dht_periodic_cb, 100 * LWS_US_PER_MS);

	expire_buckets(ctx, ctx->buckets);
	expire_buckets(ctx, ctx->buckets6);

	lws_dll2_add_tail(&ctx->list, &ctx->vhost->dht_owner);

	return ctx;

fail:
	lws_dht_destroy(&ctx);
	return NULL;
}

void *
lws_dht_get_closure(struct lws_dht_ctx *ctx)
{
	return ctx->closure;
}

void
lws_dht_destroy(struct lws_dht_ctx **pctx)
{
	struct lws_dht_ctx *ctx = *pctx;

	if (!ctx)
		return;

	lws_dll2_remove(&ctx->list);

	if (ctx->name)
		lws_free(ctx->name);

	lws_sul_cancel(&ctx->sul);

	lws_dht_hash_destroy(&ctx->myid);

	while (ctx->buckets) {
		struct bucket *b = ctx->buckets;
		ctx->buckets = b->next;
		while (b->nodes) {
			struct node *n = b->nodes;
			b->nodes = n->next;
			lws_dht_hash_destroy(&n->id);
			lws_free(n);
		}
		lws_dht_hash_destroy(&b->first);
		lws_free(b);
	}

	while (ctx->buckets6) {
		struct bucket *b = ctx->buckets6;

		ctx->buckets6 = b->next;
		while (b->nodes) {
			struct node *n = b->nodes;
			b->nodes = n->next;
			lws_dht_hash_destroy(&n->id);
			lws_free(n);
		}
		lws_dht_hash_destroy(&b->first);
		lws_free(b);
	}

	while (ctx->storage) {
		struct storage *st = ctx->storage;

		ctx->storage = ctx->storage->next;
		lws_free(st->peers);
		lws_dht_hash_destroy(&st->id);
		lws_free(st);
	}

	while (ctx->searches) {
		struct search *sr = ctx->searches;

		ctx->searches = ctx->searches->next;
		lws_dht_hash_destroy(&sr->id);
		for (int i = 0; i < sr->numnodes; i++)
			lws_dht_hash_destroy(&sr->nodes[i].id);
		lws_free(sr);
	}

	lws_dll2_t *d = lws_dll2_get_head(&ctx->ts_owner);
	while (d) {
		lws_dll2_t *d1 = d->next;
		lws_dht_ts_t *dts = lws_container_of(d, lws_dht_ts_t, list);

		lws_transport_sequencer_destroy(&dts->ts);
		lws_dll2_remove(&dts->list);
		lws_free(dts);
		d = d1;
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d_verb, d1_verb, lws_dll2_get_head(&ctx->verb_owner)) {
		struct lws_dht_verb_list *vl = lws_container_of(d_verb, struct lws_dht_verb_list, list);
		lws_dll2_remove(d_verb);
		lws_free(vl);
	} lws_end_foreach_dll_safe(d_verb, d1_verb);

	lws_free(ctx);
	*pctx = NULL;
}

/* dht_periodic is no longer used, logic moved to SUL and process_packet */

int
lws_dht_get_nodes(struct lws_dht_ctx *ctx, struct sockaddr_in *sin, int *num,
		  struct sockaddr_in6 *sin6, int *num6)
{
	int i, j;
	struct bucket *b;
	struct node *n;

	i = 0;

	/*
	 * For restoring to work without discarding too many nodes, the list
	 * must start with the contents of our bucket.
	 */
	b = find_bucket(ctx, ctx->myid, AF_INET);
	if (b == NULL)
		goto no_ipv4;

	n = b->nodes;
	while (n && i < *num) {
		if (node_good(ctx, n)) {
			sin[i] = *(struct sockaddr_in*)&n->ss;
			i++;
		}
		n = n->next;
	}

	b = ctx->buckets;
	while (b && i < *num) {
		if (id_cmp(b->first, ctx->myid) <= 0 &&
				(b->next == NULL || id_cmp(ctx->myid, b->next->first) < 0))
		{
			/* skip, handled above */
		} else {
			n = b->nodes;
			while (n && i < *num) {
				if (node_good(ctx, n)) {
					sin[i] = *(struct sockaddr_in*)&n->ss;
					i++;
				}
				n = n->next;
			}
		}
		b = b->next;
	}

no_ipv4:

	j = 0;

	b = find_bucket(ctx, ctx->myid, AF_INET6);
	if (b == NULL)
		goto no_ipv6;

	n = b->nodes;
	while (n && j < *num6) {
		if (node_good(ctx, n)) {
			sin6[j] = *(struct sockaddr_in6*)&n->ss;
			j++;
		}
		n = n->next;
	}

	b = ctx->buckets6;
	while (b && j < *num6) {
		if (id_cmp(b->first, ctx->myid) <= 0 &&
				(b->next == NULL || id_cmp(ctx->myid, b->next->first) < 0))
		{
			/* skip */
		} else {
			n = b->nodes;
			while (n && j < *num6) {
				if (node_good(ctx, n)) {
					sin6[j] = *(struct sockaddr_in6*)&n->ss;
					j++;
				}
				n = n->next;
			}
		}
		b = b->next;
	}

no_ipv6:

	*num = i;
	*num6 = j;
	return i + j;
}

int
lws_dht_insert_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		    struct sockaddr *sa, size_t salen)
{
	struct node *node;

	if ((sa->sa_family == AF_INET) || (sa->sa_family == AF_INET6)) {
		/*
		 * confirm=1 means we treat it as if we just heard from it, so it
		 * gets a timestamp and isn't immediately expired.
		 */
		node = new_node(ctx, id, sa, salen, 1);

		return !!node;
	}

	errno = EAFNOSUPPORT;

	return -1;
}

int
lws_dht_ping_node(struct lws_dht_ctx *ctx, struct sockaddr *sa, size_t salen)
{
	uint8_t tid[4];

	lwsl_dht_info("Sending ping.\n");
	make_tid(tid, "pn", 0);

	return send_ping(ctx, sa, salen, tid, 4);
}


LWS_VISIBLE LWS_EXTERN int
lws_dht_send_data(struct lws_dht_ctx *ctx, const struct sockaddr *dest, const void *data, size_t len)
{
	struct lws_transport_sequencer *ts = lws_dht_get_ts(ctx, dest, (size_t)(dest->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)), 1);

	if (!ts)
		return 1;

	return lws_transport_sequencer_write(ts, data, len);
}

int
lws_dht_send_data_at(struct lws_dht_ctx *ctx, const struct sockaddr *dest, uint64_t offset, const void *data, size_t len)
{
	struct lws_transport_sequencer *ts = lws_dht_get_ts(ctx, dest, (size_t)(dest->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)), 1);

	if (!ts)
		return 1;

	return lws_transport_sequencer_write_at(ts, offset, data, len);
}
struct lws_dll2_owner *
lws_dht_get_ts_owner(struct lws_dht_ctx *ctx)
{
	return &ctx->ts_owner;
}

int
lws_dht_msg_gen(char *out, size_t len, const char *verb, const char *hash, unsigned long long offset, unsigned long long len_val)
{
	if (!verb)
		return -1;

	return lws_snprintf(out, len, "%s %s %llu %llu ", verb, hash, offset, len_val);
}

int
lws_dht_msg_parse(const char *in, size_t len, struct lws_dht_msg *out)
{
	const char *p = in, *sp;
	size_t l;

	if (!in || !out || len < 10)
		return -1;

	memset(out, 0, sizeof(*out));

	/* Parse VERB */
	sp = strchr(p, ' ');
	if (!sp) return -1;
	l = (size_t)(sp - p);
	if (l >= sizeof(out->verb)) l = sizeof(out->verb) - 1;
	memcpy(out->verb, p, l);
	out->verb[l] = '\0';

	/* Parse HASH */
	p = sp + 1;
	sp = strchr(p, ' ');
	if (!sp) return -1;
	l = (size_t)(sp - p);
	if (l >= sizeof(out->hash)) l = sizeof(out->hash) - 1;
	memcpy(out->hash, p, l);
	out->hash[l] = '\0';

	/* Parse OFFSET */
	p = sp + 1;
	sp = strchr(p, ' ');
	if (!sp) return -1;
	out->offset = (unsigned long long)strtoull(p, NULL, 10);

	/* Parse LEN */
	p = sp + 1;
	sp = strchr(p, ' ');
	out->len = (unsigned long long)strtoull(p, NULL, 10);

	/* Payload */
	if (sp) {
		out->payload = sp + 1;
		out->payload_len = len - (size_t)((const char *)out->payload - in);
	}

	return 0;
}

int
lws_dht_register_verbs(struct lws_dht_ctx *ctx, const struct lws_dht_verb *verbs, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		struct lws_dht_verb_list *vl = lws_zalloc(sizeof(*vl), "dht verb");
		if (!vl) return -1;
		vl->v = verbs[i];
		lws_dll2_add_tail(&vl->list, &ctx->verb_owner);
	}

	return 0;
}

struct lws_dht_ctx *
lws_dht_get_by_name(struct lws_vhost *vhost, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, vhost->dht_owner.head) {
		struct lws_dht_ctx *ctx = lws_container_of(d, struct lws_dht_ctx, list);

		if (ctx->name && !strcmp(ctx->name, name))
			return ctx;
	} lws_end_foreach_dll(d);

	return NULL;
}

void
lws_dht_destroy_all_on_vhost(struct lws_vhost *vh)
{
	while (vh->dht_owner.head) {
		struct lws_dht_ctx *ctx = lws_container_of(vh->dht_owner.head,
							   struct lws_dht_ctx,
							   list);

		lws_dht_destroy(&ctx);
	}
}
