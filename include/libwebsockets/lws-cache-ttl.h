/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/** \defgroup lws_cache_ttl Cache supporting expiry
 * ##Cache supporting expiry
 *
 * These apis let you quickly and reliably implement caches of named objects,
 * that have a "destroy-by date" and cache limits that will be observed.
 *
 * You can instantiate as many caches as you need.
 *
 * Allocated object memory is entirely for the use of user code, up to the
 * requested size.
 *
 * The key name for the listed objects may be any string chosen by the user,
 * there is no special length limit as it is also allocated.
 *
 * Both expiry and LRU orderings are kept so it is easy to find out usage
 * ordering and when the next object that will expire.
 *
 * Cached objects may be destroyed any time you go around the event loop, when
 * you allocate new objects (to keep the whole cache under the specified limit),
 * or when their expiry time arrives.  So you shouldn't keep copies of pointers
 * to cached objects after returning to the event loop.
 *
 * Caches may be layered...
 */
///@{


struct lws_cache_ttl_lru;

/**
 * lws_cache_item_alloc() - allocate a new cache item object and bind to a cache
 *
 * \param cache: the existing cache to allocate the object in
 * \param key: a key string that identifies the item in the cache
 * \param size: the size of the object to allocate
 * \param expiry: the usec time that the object will autodestroy
 *
 * If an item with the key already exists, it is destroyed before allocating a
 * new one.
 *
 * The allocated user space is not zeroed down, just malloc'd.
 *
 * Returns NULL if unable to allocate, or a pointer to \p size bytes dedicated
 * to this cache item, available for any use until it is destroyed.  It will be
 * scheduled to be auto-destroyed when \p expiry occurs.  And it can be
 * destroyed at any time we return to the event loop, so this pointer cannot
 * be stored.
 */
void * /* only valid until return to event loop */
lws_cache_item_alloc(struct lws_cache_ttl_lru *cache, const char *key,
		     size_t size, lws_usec_t expiry);

/**
 * lws_cache_item_find() - get a pointer by key string to existing item, if any
 *
 * \param cache: the cache to search for the key
 * \param key: the item key string
 * \param size: the size of the user area pointed to by the returned pointer
 *
 * If the cache still has an item matching the key string, a pointer to the
 * user allocation is returned and *len is set to its length.  If not, then
 * NULL is returned.
 *
 * The LRU ordering is updated when calling this if an item matches, it is
 * moved to the head of the recently used list.
 */
void * /* only valid until return to event loop */
lws_cache_item_find(struct lws_cache_ttl_lru *cache, const char *key, size_t *size);

/**
 * lws_cache_item_destroy_by_key() - destroy a cache item allocated by lws_cache_item_alloc()
 *
 * \param cache: the cache to search for the key
 * \param key: the item key string
 *
 * If the cache still has an item matching the key string, it will be destroyed.
 */
void
lws_cache_item_destroy_by_key(struct lws_cache_ttl_lru *cache, const char *key);

struct lws_cache_ops {
	void (*item_alloc)(struct lws_cache_ttl_lru *cache, const char *key,
			   size_t size, lws_usec_t expiry);
};

typedef void (*lws_cache_item_destroy_cb)(void *item, size_t size);
struct lws_cache_creation_info {
	struct lws_context		*cx;
	/**< Mandatory: the lws_context */
	lws_cache_item_destroy_cb	cb;
	/**< NULL, or a callback that can hook cache item destory */
	struct lws_cache_ttl_lru	*parent;
	/**< NULL, or next cache level */
	const struct lws_cache_ops	*ops;
	/**< NULL for default, heap-based ops, else custom cache storage and
	 * query implementation */

	size_t				max_footprint;
	/**< 0, or the max heap allocation allowed before destroying
	 *   lru items to keep it under the limit */
	size_t				max_items;
	/**< 0, or the max number of items allowed in the cache before
	 *   destroying lru items to keep it under the limit */
	int				tsi;
	/**< 0 unless using SMP, then tsi to bind sul to */
};

/**
 * lws_cache_create() - create an empty cache you can allocate items in
 *
 * \param info: a struct describing the cache to create
 *
 * Create an empty cache you can allocate items in.  The cache will be kept
 * below the max_footprint and max_items limits if they are nonzero, by destroying
 * least-recently-used items until it remains below the limits.
 *
 * Items will auto-destroy when their expiry time is reached.
 *
 * When items are destroyed from the cache, if \p cb is non-NULL, it will be
 * called back with the item pointer after it has been removed from the cache,
 * but before it is deallocated and destroyed.
 *
 * context and tsi are used when scheduling expiry callbacks
 */
struct lws_cache_ttl_lru *
lws_cache_create(const struct lws_cache_creation_info *info);

/**
 * lws_cache_destroy() - destroy a previously created cache
 *
 * \param cache: pointer to the cache
 *
 * Everything in the cache is destroyed, then the cache itself is destroyed,
 * and *cache set to NULL.
 */
void
lws_cache_destroy(struct lws_cache_ttl_lru **cache);

///@}

