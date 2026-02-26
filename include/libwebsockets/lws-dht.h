/*
 * Copyright (c) 2009-2011 by Juliusz Chroboczek
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *  Adaptation for lws, cleaning, modernization
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

#if !defined(__LWS_DHT_H__)
#define __LWS_DHT_H__

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*! \defgroup dht Distributed Hash Table
 * ## Distributed Hash Table (DHT) API
 *
 * Lws provides a Mainline DHT implementation that can be used to track
 * external IP addresses and find nodes/peers in a P2P network.
 */
///@{

struct lws_dht_ctx;

extern const struct lws_protocols lws_dht_protocol;

/**
 * struct lws_dht_hash - DHT hash/ID structure
 *
 * \param type: LWS_DHT_HASH_TYPE_...
 * \param len: length of the ID in bytes
 * \param id: the ID bytes
 */
typedef struct lws_dht_hash {
	uint8_t			type; /* LWS_DHT_HASH_TYPE_... */
	uint8_t			len;
	uint8_t			id[];
} lws_dht_hash_t;

enum {
	LWS_DHT_HASH_TYPE_UNKNOWN	= 0,
	LWS_DHT_HASH_TYPE_SHA1		= 0x11, /* 20 bytes */
	LWS_DHT_HASH_TYPE_SHA256	= 0x12, /* 32 bytes */
	LWS_DHT_HASH_TYPE_SHA512	= 0x13, /* 64 bytes */
	LWS_DHT_HASH_TYPE_BLAKE3	= 0x1e, /* 32 bytes */
};

/**
 * lws_dht_hash_create() - Create a DHT hash from data
 *
 * \param type: LWS_DHT_HASH_TYPE_...
 * \param len: length of data
 * \param data: the data to hash or use as ID
 *
 * This creates a new lws_dht_hash_t object on the heap.
 *
 * \return pointer to the new hash, or NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN lws_dht_hash_t *
lws_dht_hash_create(int type, int len, const uint8_t *data);

/**
 * lws_dht_hash_destroy() - Destroy a DHT hash
 *
 * \param p: pointer to the hash pointer to destroy
 *
 * Frees the hash and sets the pointer to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dht_hash_destroy(lws_dht_hash_t **p);

/**
 * lws_dht_callback_t() - DHT event callback
 *
 * \param closure: user-defined closure pointer
 * \param event: LWS_DHT_EVENT_...
 * \param info_hash: the hash related to the event
 * \param data: event-specific data
 * \param data_len: length of event-specific data
 */
typedef void
lws_dht_callback_t(void *closure, int event, const lws_dht_hash_t *info_hash, const void *data, size_t data_len, const struct sockaddr *from, size_t fromlen);

struct lws_dht_msg {
	char verb[16];
	char hash[LWS_GENHASH_LARGEST * 2 + 1];
	unsigned long long offset;
	unsigned long long len;
	const void *payload;
	size_t payload_len;
};

struct lws_dht_verb_dispatch_args {
	struct lws_dht_ctx *ctx;
	const struct lws_dht_msg *msg;
	const struct sockaddr *from;
	size_t fromlen;
};

struct lws_dht_verb {
	const char *name;
	const struct lws_protocols *protocol;
};

/**
 * lws_dht_msg_parse() - Parse a raw DHT message
 *
 * \param in: raw message buffer
 * \param len: length of raw message
 * \param out: struct to populate with parsed data
 *
 * Safe parsing of DHT command messages.
 *
 * \return 0 on success, non-zero on error
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_msg_parse(const char *in, size_t len, struct lws_dht_msg *out);

/**
 * lws_dht_msg_gen() - Generate a raw DHT message
 *
 * \param out: buffer to write message to
 * \param verb: e.g. "PUT", "GET", "REPLICATE"
 * \param hash: the hex SHA1 associated
 * \param offset: the byte offset
 * \param len_val: the length val
 *
 * Generate a complete DHT payload with a space separated verb schema.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_msg_gen(char *out, size_t len, const char *verb, const char *hash, unsigned long long offset, unsigned long long len_val);

/**
 * lws_dht_register_verbs() - Register custom verb handlers
 *
 * \param ctx: DHT context
 * \param verbs: array of lws_dht_verb_t
 * \param count: number of verbs in array
 *
 * \return 0 on success, non-zero on error
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_register_verbs(struct lws_dht_ctx *ctx, const struct lws_dht_verb *verbs, int count);

/**
 * lws_dht_blacklist_cb_t() - DHT blacklist check callback
 *
 * \param sa: sockaddr to check
 * \param salen: length of sockaddr
 *
 * \return 0 if the address is allowed, non-zero if it is blacklisted.
 */
typedef int
lws_dht_blacklist_cb_t(const struct sockaddr *sa, size_t salen);

/**
 * lws_dht_hash_cb_t() - Custom hash function for DHT
 *
 * \param hash_return: where to store the hash result
 * \param hash_size: size of the hash result buffer
 * \param v1: first data chunk
 * \param len1: length of first chunk
 * \param v2: second data chunk (optional)
 * \param len2: length of second chunk
 * \param v3: third data chunk (optional)
 * \param len3: length of third chunk
 */
typedef void
lws_dht_hash_cb_t(void *hash_return, int hash_size,
		  const void *v1, int len1,
		  const void *v2, int len2,
		  const void *v3, int len3);

/**
 * lws_dht_capture_announce_cb_t() - Captured announce callback
 *
 * \param ctx: DHT context
 * \param hash: the announced hash
 * \param fromaddr: where the announce came from
 * \param prt: the port announced
 */
typedef void
lws_dht_capture_announce_cb_t(struct lws_dht_ctx *ctx, lws_dht_hash_t *hash,
			      const struct sockaddr *fromaddr,
			      unsigned short prt);

/* The maximum number of peers we store for a given hash. */
#define DHT_MAX_PEERS 2048

/* The maximum number of hashes we're willing to track. */
#define DHT_MAX_HASHES 16384

/* The maximum number of searches we keep data about. */
#define DHT_MAX_SEARCHES 1024

/* The time after which we consider a search to be expirable. */
#define DHT_SEARCH_EXPIRE_TIME (62 * 60)

/**
 * enum lws_dht_event_t - DHT events reported via callback
 */
typedef enum {
	LWS_DHT_EVENT_NONE,
	LWS_DHT_EVENT_VALUES,		/**< Peers for requested hash found */
	LWS_DHT_EVENT_VALUES6,		/**< IPv6 peers for requested hash found */
	LWS_DHT_EVENT_SEARCH_DONE,	/**< Search operation completed */
	LWS_DHT_EVENT_SEARCH_DONE6,	/**< IPv6 search operation completed */
	LWS_DHT_EVENT_EXTERNAL_ADDR,	/**< External IPv4 address determined */
	LWS_DHT_EVENT_EXTERNAL_ADDR6,	/**< External IPv6 address determined */
	LWS_DHT_EVENT_DATA,		/**< Arbitrary data payload received */
	LWS_DHT_EVENT_WRITE_COMPLETED,	/**< Reliable write successful */
	LWS_DHT_EVENT_WRITE_FAILED,	/**< Reliable write failed */
} lws_dht_event_t;


/**
 * struct lws_dht_info - Initialization parameters for DHT
 *
 * \param vhost: vhost to attach UDP wsi to
 * \param cb: callback for DHT events
 * \param closure: user-defined closure for cb
 * \param id: DHT ID (optional, NULL = random)
 * \param v: version string (optional, NULL = default)
 * \param port: UDP port to listen on
 * \param ipv6: enable IPv6
 * \param legacy: if set, on wire: no multihash, 20-byte assumed
 * \param aux: 0 (sha1), or MULTIHASH_TYPE_...
 * \param iface: interface to bind to
 * \param blacklist_cb: (optional) user blacklist cb
 * \param hash_cb: (optional) user hash cb
 * \param capture_announce_cb: (optional) user capture announce cb
 */
typedef struct lws_dht_info {
	struct lws_vhost		*vhost;
	lws_dht_callback_t		*cb;
	void				*closure;
	const lws_dht_hash_t		*id;
	const char			*v;
	const char			*name;
	int				port;
	uint8_t				ipv6:1;
	uint8_t				legacy:1;
	uint8_t				aux;
	const char			*iface;
	lws_dht_blacklist_cb_t		*blacklist_cb;
	lws_dht_hash_cb_t		*hash_cb;
	lws_dht_capture_announce_cb_t	*capture_announce_cb;
} lws_dht_info_t;

/**
 * lws_dht_create() - Create a DHT context
 *
 * \param info: initialization parameters
 *
 * \return pointer to DHT context or NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN struct lws_dht_ctx *
lws_dht_create(const lws_dht_info_t *info);

/**
 * lws_dht_get_closure() - Get the user closure pointer
 *
 * \param ctx: DHT context
 *
 * \return the closure pointer
 */
LWS_VISIBLE LWS_EXTERN void *
lws_dht_get_closure(struct lws_dht_ctx *ctx);

/**
 * lws_dht_destroy() - Destroy a DHT context
 *
 * \param pctx: pointer to the DHT context pointer to destroy
 */
LWS_VISIBLE LWS_EXTERN void
lws_dht_destroy(struct lws_dht_ctx **pctx);

/**
 * lws_dht_get_by_name() - Get a specific DHT context by name
 *
 * \param vhost: vhost the DHT is bound to
 * \param name: name to match against
 *
 * \return pointer to DHT context or NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN struct lws_dht_ctx *
lws_dht_get_by_name(struct lws_vhost *vhost, const char *name);

/**
 * lws_dht_insert_node() - Manually insert a node into the DHT
 *
 * \param ctx: DHT context
 * \param id: ID of the node
 * \param sa: sockaddr of the node
 * \param salen: length of sockaddr
 *
 * \return 1 if successful, 0 if it already exists, or -1 on error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_insert_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		    struct sockaddr *sa, size_t salen);

/**
 * lws_dht_ping_node() - Ping a node to verify it is alive
 *
 * \param ctx: DHT context
 * \param sa: sockaddr of the node
 * \param salen: length of sockaddr
 *
 * \return number of bytes sent on success, or -1 on error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_ping_node(struct lws_dht_ctx *ctx, struct sockaddr *sa, size_t salen);

LWS_VISIBLE LWS_EXTERN int
lws_dht_send_data(struct lws_dht_ctx *ctx, const struct sockaddr *dest, const void *data, size_t len);

LWS_VISIBLE LWS_EXTERN int
lws_dht_send_data_at(struct lws_dht_ctx *ctx, const struct sockaddr *dest, uint64_t offset, const void *data, size_t len);

LWS_VISIBLE LWS_EXTERN struct lws_transport_sequencer *
lws_dht_get_ts(struct lws_dht_ctx *ctx, const struct sockaddr *dest, size_t salen, int create);

/**
 * lws_dht_search() - Perform an asynchronous search for a hash
 *
 * \param ctx: DHT context
 * \param id: hash to search for
 * \param port: port to search on
 * \param af: address family (AF_INET, AF_INET6, or 0 for both)
 * \param callback: search completion/result callback
 * \param closure: closure for \p callback
 *
 * This performs an iterative, asynchronous search for the requested hash. If
 * \p port is non-zero, it also announces our availability for this hash.
 *
 * Results (peers/values) are delivered to the \p callback as they are found via
 * `LWS_DHT_EVENT_VALUES` or `LWS_DHT_EVENT_VALUES6` events.
 *
 * The \p callback is also called with event `LWS_DHT_EVENT_SEARCH_DONE` (or
 * `LWS_DHT_EVENT_SEARCH_DONE6`) when the search operation has exhausted all
 * potential nodes or reached a timeout.
 *
 * \return 1 if search started successfully, 0 if answered locally (callback still called), or -1 on error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_search(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int port, int af,
	       lws_dht_callback_t *callback, void *closure);

/**
 * lws_dht_nodes() - Get statistics about DHT nodes
 *
 * \param ctx: DHT context
 * \param af: address family (AF_INET, AF_INET6)
 * \param good_return: count of known good nodes
 * \param dubious_return: count of dubious nodes
 * \param cached_return: count of cached nodes
 * \param incoming_return: count of incoming nodes
 *
 * \return total number of good + dubious nodes.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_nodes(struct lws_dht_ctx *ctx, int af, int *good_return, int *dubious_return,
	      int *cached_return, int *incoming_return);

/**
 * lws_dht_dump_tables() - Log the state of DHT routing tables
 *
 * \param ctx: DHT context
 */
LWS_VISIBLE LWS_EXTERN void
lws_dht_dump_tables(struct lws_dht_ctx *ctx);

/**
 * lws_dht_get_nodes() - Get a list of known nodes
 *
 * \param ctx: DHT context
 * \param sin: buffer for IPv4 nodes
 * \param num: in/out count for IPv4 nodes
 * \param sin6: buffer for IPv6 nodes
 * \param num6: in/out count for IPv6 nodes
 *
 * \return total number of nodes filled (v4 + v6).
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_get_nodes(struct lws_dht_ctx *ctx, struct sockaddr_in *sin, int *num,
		  struct sockaddr_in6 *sin6, int *num6);

/**
 * lws_dht_get_external_addr() - Get our external IP and port as determined by STUN
 *
 * \param ctx: DHT context
 * \param ss: buffer for external address and port
 * \param sslen: length of buffer/written address
 *
 * \return 0 on success, or -1 if the address and port are not yet determined.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dht_get_external_addr(struct lws_dht_ctx *ctx, struct sockaddr_storage *ss, size_t *sslen);

#endif /* __LWS_DHT_H__ */

///@}
