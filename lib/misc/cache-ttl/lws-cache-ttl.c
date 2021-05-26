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
#include "private-lib-misc-cache-ttl.h"

#include <assert.h>

#if defined(write)
#undef write
#endif

void
lws_cache_clear_matches(lws_dll2_owner_t *results_owner)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, results_owner->head) {
		lws_cache_match_t *item = lws_container_of(d, lws_cache_match_t,
							   list);
		lws_dll2_remove(d);
		lws_free(item);
	} lws_end_foreach_dll(d);
}

void
lws_cache_schedule(struct lws_cache_ttl_lru *cache, sul_cb_t cb, lws_usec_t e)
{
	lwsl_cache("%s: %s schedule %llu\n", __func__, cache->info.name,
			(unsigned long long)e);

	lws_sul_schedule(cache->info.cx, cache->info.tsi, &cache->sul, cb,
			 e - lws_now_usecs());
}

int
lws_cache_write_through(struct lws_cache_ttl_lru *cache,
			const char *specific_key, const uint8_t *source,
			size_t size, lws_usec_t expiry, void **ppay)
{
	struct lws_cache_ttl_lru *levels[LWS_CACHE_MAX_LEVELS], *c = cache;
	int n = 0, r = 0;

	lws_cache_item_remove(cache, specific_key);

	/* starting from L1 */

	do {
		levels[n++] = c;
		c = c->info.parent;
	} while (c && n < (int)LWS_ARRAY_SIZE(levels));

	/* starting from outermost cache level */

	while (n) {
		n--;
		r = levels[n]->info.ops->write(levels[n], specific_key,
						source, size, expiry, ppay);
	}

	return r;
}

/*
 * We want to make a list of unique keys that exist at any cache level
 * matching a wildcard search key.
 *
 * If L1 has a cached version though, we will just use that.
 */

int
lws_cache_lookup(struct lws_cache_ttl_lru *cache, const char *wildcard_key,
		 const void **pdata, size_t *psize)
{
	struct lws_cache_ttl_lru *l1 = cache;
	lws_dll2_owner_t results_owner;
	lws_usec_t expiry = 0;
	char meta_key[128];
	size_t sum = 0;
	uint8_t *p;

	memset(&results_owner, 0, sizeof(results_owner));
	meta_key[0] = META_ITEM_LEADING;
	lws_strncpy(&meta_key[1], wildcard_key, sizeof(meta_key) - 2);

	/*
	 * If we have a cached result set in L1 already, return that
	 */

	if (l1->info.ops->get(l1, meta_key, pdata, psize))
		return 0;

	/*
	 * No, we have to do the actual lookup work in the backing store layer
	 * to get results for this...
	 */

	while (cache->info.parent)
		cache = cache->info.parent;

	if (cache->info.ops->lookup(cache, wildcard_key, &results_owner)) {
		/* eg, OOM */

		lws_cache_clear_matches(&results_owner);
		return 1;
	}

	/*
	 * Scan the results, we want to know how big a payload it needs in
	 * the cache, and we want to know the earliest expiry of any of the
	 * component parts, so the meta cache entry for these results can be
	 * expired when any of the results would expire.
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d, results_owner.head) {
		lws_cache_match_t *m = lws_container_of(d, lws_cache_match_t,
							list);
		sum += 8; /* payload size, name length */
		sum += m->tag_size;

		if (m->expiry && (!expiry || expiry < m->expiry))
			expiry = m->expiry;

	} lws_end_foreach_dll(d);

	/*
	 * create the right amount of space for an L1 record of these results,
	 * with its expiry set to the earliest of the results
	 */

	if (l1->info.ops->write(l1, meta_key, NULL, sum, expiry, (void **)&p)) {
		lws_cache_clear_matches(&results_owner);
		return 1;
	}

	*pdata = p;
	*psize = sum;

	/*
	 * Fill in the serialized results
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d, results_owner.head) {
		lws_cache_match_t *m = lws_container_of(d, lws_cache_match_t,
							list);

		lws_ser_wu32be(p, (uint32_t)m->payload_size);
		p += 4;
		lws_ser_wu32be(p, (uint32_t)m->tag_size);
		p += 4;

		memcpy(p, &m[1], m->tag_size + 1);

	} lws_end_foreach_dll(d);

	lws_cache_clear_matches(&results_owner);

	return 0;
}

int
lws_cache_item_get(struct lws_cache_ttl_lru *cache, const char *specific_key,
		   const void **pdata, size_t *psize)
{
	while (cache) {
		if (!cache->info.ops->get(cache, specific_key, pdata, psize))
			return 0;

		cache = cache->info.parent;
	}

	return 1;
}

int
lws_cache_item_remove(struct lws_cache_ttl_lru *cache, const char *wildcard_key)
{
	while (cache) {
		if (cache->info.ops->invalidate(cache, wildcard_key))
			return 1;

		cache = cache->info.parent;
	}

	return 0;
}

uint64_t
lws_cache_footprint(struct lws_cache_ttl_lru *cache)
{
	return cache->current_footprint;
}

struct lws_cache_ttl_lru *
lws_cache_create(const struct lws_cache_creation_info *info)
{
	assert(info);
	assert(info->ops);
	assert(info->name);
	assert(info->ops->create);

	return info->ops->create(info);
}

void
lws_cache_destroy(struct lws_cache_ttl_lru **_cache)
{
	lws_cache_ttl_lru_t *cache = *_cache;

	if (!cache)
		return;

	assert(cache->info.ops->destroy);

	lws_sul_cancel(&cache->sul);

	cache->info.ops->destroy(_cache);
}
