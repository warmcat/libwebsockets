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

#include <private-lib-core.h>

typedef struct lws_cache_ttl_item {
	lws_dll2_t			list_expiry;
	lws_dll2_t			list_lru;

	lws_usec_t			expiry;
	size_t				key_len;
	size_t				size;

	/*
	 * len + key_len + 1 bytes of data overcommitted, user object first
	 * so it is well-aligned, then the NUL-terminated key name
	 */
} lws_cache_ttl_item_t;

typedef struct lws_cache_ttl_lru {
	lws_dll2_owner_t		items_expiry;
	lws_dll2_owner_t		items_lru;

	struct lws_cache_creation_info	info;

	lws_sorted_usec_list_t		sul;

	size_t				current_footprint;

} lws_cache_ttl_lru_t;

static void
expiry_cb(lws_sorted_usec_list_t *sul);


//static const struct lws_cache_ops lws_cache_ops_heap = {
	// .item_alloc			= lws_cache_heap_item_alloc,
//};

static int
earliest_expiry(struct lws_cache_ttl_lru *cache, lws_usec_t *pearliest)
{
	lws_cache_ttl_item_t *item;

	if (!cache->items_expiry.head)
		return 1;

	item = lws_container_of(cache->items_expiry.head,
				lws_cache_ttl_item_t, list_expiry);

	*pearliest = item->expiry;

	return 0;
}

static void
update_sul(struct lws_cache_ttl_lru *cache)
{
	lws_usec_t earliest;

	if (earliest_expiry(cache, &earliest)) {
		lws_sul_cancel(&cache->sul);
		return;
	}

	lwsl_debug("%s: setting exp %llu\n", __func__,
			(unsigned long long)earliest);

	lws_sul_schedule(cache->info.cx, cache->info.tsi, &cache->sul,
			 expiry_cb, earliest - lws_now_usecs());
}


static void
lws_cache_item_destroy_by_item(struct lws_cache_ttl_lru *cache,
			       lws_cache_ttl_item_t *item, int parent_too)
{
	lws_dll2_remove(&item->list_expiry);
	lws_dll2_remove(&item->list_lru);

	cache->current_footprint -= item->size;

	update_sul(cache);

	//if (parent_too && cache->parent)
	//	cache->parent->

	if (cache->info.cb)
		cache->info.cb((void *)((uint8_t *)&item[1]), item->size);

	lws_free(item);
}

static void
lws_cache_item_evict_lru(lws_cache_ttl_lru_t *cache)
{
	lws_cache_ttl_item_t *ei;

	if (!cache->items_lru.head)
		return;

	ei = lws_container_of(cache->items_lru.head,
			      lws_cache_ttl_item_t, list_lru);
	lws_cache_item_destroy_by_item(cache, ei, 0);
}

static void
expiry_cb(lws_sorted_usec_list_t *sul)
{
	lws_cache_ttl_lru_t *cache = lws_container_of(sul, lws_cache_ttl_lru_t, sul);

	while (cache->items_expiry.head) {
		lws_cache_ttl_item_t *item;

		item = lws_container_of(cache->items_expiry.head,
					lws_cache_ttl_item_t, list_expiry);

		if (lws_now_usecs() < item->expiry)
			return;

		lws_cache_item_destroy_by_item(cache, item, 1);
	}
}

static int
lws_sort_expiry(const lws_dll2_t *a, const lws_dll2_t *b)
{
	const lws_cache_ttl_item_t
		*c = lws_container_of(a, lws_cache_ttl_item_t, list_expiry),
		*d = lws_container_of(b, lws_cache_ttl_item_t, list_expiry);

	if (c->expiry > d->expiry)
		return 1;
	if (c->expiry < d->expiry)
		return -1;

	return 0;
}

void *
lws_cache_item_alloc(struct lws_cache_ttl_lru *cache, const char *key,
		     size_t size, lws_usec_t expiry)
{
	lws_cache_ttl_item_t *item, *ei;
	size_t kl = strlen(key);
	char *p;

	/*
	 * Make space if space is limited
	 */

	if (cache->info.max_footprint)
		while (cache->current_footprint + size > cache->info.max_footprint)
			lws_cache_item_evict_lru(cache);

	if (cache->info.max_items)
		while (cache->items_lru.count + 1 > cache->info.max_items)
			lws_cache_item_evict_lru(cache);

	/* remove any existing entry of the same key */

	lws_cache_item_destroy_by_key(cache, key);

	item = lws_malloc(sizeof(*item) + kl + 1u + size, __func__);
	if (!item)
		return NULL;

	cache->current_footprint += item->size;

	/* only need to zero down our item object */
	memset(item, 0, sizeof(*item));

	p = ((char *)&item[1]);
	/* copy the key string into place, with terminating NUL */
	memcpy(p + size, key, kl + 1);

	item->expiry = expiry;
	item->key_len = kl;
	item->size = size;

	if (expiry) {
		/* adding to expiry is optional, on nonzero expiry */
		lws_dll2_add_sorted(&item->list_expiry, &cache->items_expiry,
				    lws_sort_expiry);
		ei = lws_container_of(cache->items_expiry.head,
				      lws_cache_ttl_item_t, list_expiry);
		lwsl_debug("%s: setting exp %llu\n", __func__,
				(unsigned long long)ei->expiry);
		lws_sul_schedule(cache->info.cx, cache->info.tsi, &cache->sul,
				 expiry_cb, ei->expiry - lws_now_usecs());
	}

	/* always add outselves to head of lru list */
	lws_dll2_add_head(&item->list_lru, &cache->items_lru);

	return (void *)p;
}

void *
lws_cache_item_find(struct lws_cache_ttl_lru *cache, const char *key, size_t *size)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, cache->items_lru.head) {
		lws_cache_ttl_item_t *item =
			lws_container_of(d, lws_cache_ttl_item_t, list_lru);

		if (!strcmp(key, ((char *)&item[1]) + item->size)) {
			*size = item->size;

			return (void *)&item[1];
		}

	} lws_end_foreach_dll(d);

	// if (cache->parent)


	return NULL;
}

void
lws_cache_item_destroy_by_key(struct lws_cache_ttl_lru *cache, const char *key)
{
	lws_cache_ttl_item_t *item;
	size_t size;
	void *user;

	user = lws_cache_item_find(cache, key, &size);

	if (!user)
		return;

	item = (lws_cache_ttl_item_t *)(((uint8_t *)user) - sizeof(*item));

	lws_cache_item_destroy_by_item(cache, item, 1);
}

struct lws_cache_ttl_lru *
lws_cache_create(const struct lws_cache_creation_info *info)
{
	lws_cache_ttl_lru_t *cache = lws_zalloc(sizeof(*cache), __func__);

	if (!cache)
		return NULL;

	cache->info		= *info;
//	if (!cache->info.ops)
//		cache->info.ops = &lws_cache_ops_heap;

	return cache;
}

static int
destroy_dll(struct lws_dll2 *d, void *user)
{
	lws_cache_ttl_lru_t *cache = (struct lws_cache_ttl_lru *)user;
	lws_cache_ttl_item_t *item = lws_container_of(d, lws_cache_ttl_item_t,
						      list_lru);

	lws_cache_item_destroy_by_item(cache, item, 0);

	return 0;
}

void
lws_cache_destroy(struct lws_cache_ttl_lru **_cache)
{
	lws_cache_ttl_lru_t *cache = *_cache;

	if (!cache)
		return;

	lws_dll2_foreach_safe(&cache->items_lru, cache, destroy_dll);

	lws_sul_cancel(&cache->sul);

	lws_free_set_NULL(*_cache);
}
