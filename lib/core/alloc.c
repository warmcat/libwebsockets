/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"

#if defined(LWS_PLAT_ALLOC_SIZE)

/* the heap is processwide */
static size_t allocated, heap_limit;
#endif

#if defined(LWS_WITH_ALLOC_SITES)
/*
 * Every allocation has a header in front of it saying who asked for it, and
 * is listed on sites_live until it's freed, so the heap no footprint
 * participant accounts for can be told apart by who holds it
 */

#define LWS_ALLOC_SITE_MAGIC	0x6c777361u
/* the dump ranks this many sites, and lists the biggest few of them */
#define LWS_ALLOC_SITE_RANKED	128
#define LWS_ALLOC_SITE_LISTED	24

typedef struct lws_alloc_site_hdr {
	lws_dll2_t		list;	/* on sites_live */
	const char		*reason;
	size_t			size;	/* what the caller asked for */
	uint32_t		magic;
#if defined(LWS_PLAT_CALLERS)
	uintptr_t		pcs[LWS_ALLOC_SITE_CALLERS];
#endif
} lws_alloc_site_hdr_t;

/* what follows is as aligned as malloc() gives, two pointers' worth */
#define LWS_ALLOC_SITE_ALIGN	(2 * sizeof(void *))
#define LWS_ALLOC_SITE_HDR_LEN	((sizeof(lws_alloc_site_hdr_t) + \
				  LWS_ALLOC_SITE_ALIGN - 1) & \
				 ~(LWS_ALLOC_SITE_ALIGN - 1))

static lws_dll2_owner_t sites_live;
static char sites_foreign; /* the app set its own allocator */

/* lws allocates from any thread or task that uses it */
#if defined(LWS_PLAT_FREERTOS)
static portMUX_TYPE sites_mux = portMUX_INITIALIZER_UNLOCKED;
#define sites_lock()	portENTER_CRITICAL(&sites_mux)
#define sites_unlock()	portEXIT_CRITICAL(&sites_mux)
#elif defined(LWS_HAVE_PTHREAD_H)
static pthread_mutex_t sites_mtx = PTHREAD_MUTEX_INITIALIZER;
#define sites_lock()	pthread_mutex_lock(&sites_mtx)
#define sites_unlock()	pthread_mutex_unlock(&sites_mtx)
#else
#define sites_lock()
#define sites_unlock()
#endif

/* from the pointer the caller has, to the header, taking it off the list */
static void *
lws_alloc_site_take(void *ptr)
{
	lws_alloc_site_hdr_t *h = (lws_alloc_site_hdr_t *)
			((uint8_t *)ptr - LWS_ALLOC_SITE_HDR_LEN);

	assert(h->magic == LWS_ALLOC_SITE_MAGIC);

	sites_lock();
	lws_dll2_remove(&h->list);
	sites_unlock();

	return h;
}

/* list the block as the caller's, returning the pointer the caller gets */
static void *
lws_alloc_site_give(void *v, size_t size, const char *reason,
		    const uintptr_t *pcs)
{
	lws_alloc_site_hdr_t *h = (lws_alloc_site_hdr_t *)v;

	/* realloc() moved our old list node along with the block */
	memset(&h->list, 0, sizeof(h->list));
	h->reason	= reason ? reason : "-";
	h->size		= size;
	h->magic	= LWS_ALLOC_SITE_MAGIC;
#if defined(LWS_PLAT_CALLERS)
	memcpy(h->pcs, pcs, sizeof(h->pcs));
#else
	(void)pcs;
#endif

	sites_lock();
	lws_dll2_add_tail(&h->list, &sites_live);
	sites_unlock();

	return (uint8_t *)v + LWS_ALLOC_SITE_HDR_LEN;
}

#if defined(LWS_PLAT_ALLOC_SIZE)
size_t
lws_alloc_site_block_size(void *p)
{
	lws_alloc_site_hdr_t *h = (lws_alloc_site_hdr_t *)
			((uint8_t *)p - LWS_ALLOC_SITE_HDR_LEN);

	/* the app's allocator made it, without our header */
	if (sites_foreign)
		return lws_plat_alloc_size(p);

	assert(h->magic == LWS_ALLOC_SITE_MAGIC);

	return lws_plat_alloc_size(h);
}
#endif

static int
lws_alloc_site_same(const lws_alloc_site_t *s, const lws_alloc_site_hdr_t *h)
{
#if defined(LWS_PLAT_CALLERS)
	if (memcmp(s->pcs, h->pcs, sizeof(h->pcs)))
		return 0;
#endif
	return s->reason == h->reason || !strcmp(s->reason, h->reason);
}

int
lws_alloc_sites(lws_alloc_site_t *sites, int max, lws_alloc_site_t *rest)
{
	int ns = 0, n, m;

	if (rest)
		memset(rest, 0, sizeof(*rest));

	sites_lock();
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&sites_live)) {
		lws_alloc_site_hdr_t *h = lws_container_of(d,
					lws_alloc_site_hdr_t, list);

		for (n = 0; n < ns; n++)
			if (lws_alloc_site_same(&sites[n], h))
				break;

		if (n == ns) {
			if (ns == max) {
				if (rest) {
					rest->bytes += h->size;
					rest->count++;
				}
				continue;
			}
			memset(&sites[ns], 0, sizeof(sites[ns]));
			sites[ns].reason = h->reason;
#if defined(LWS_PLAT_CALLERS)
			memcpy(sites[ns].pcs, h->pcs, sizeof(h->pcs));
#endif
			ns++;
		}
		sites[n].bytes += h->size;
		sites[n].count++;
	} lws_end_foreach_dll(d);
	sites_unlock();

	/* biggest first */
	for (n = 0; n + 1 < ns; n++)
		for (m = n + 1; m < ns; m++)
			if (sites[m].bytes > sites[n].bytes) {
				lws_alloc_site_t t = sites[n];

				sites[n] = sites[m];
				sites[m] = t;
			}

	return ns;
}

void
lws_alloc_sites_dump(struct lws_context *cx)
{
	/*
	 * Too big for the stack of whatever ran out of heap, and only in
	 * builds that are for looking at the heap
	 */
	static lws_alloc_site_t s[LWS_ALLOC_SITE_RANKED];
	lws_alloc_site_t rest;
	unsigned int count;
	int ns, n;

	/*
	 * Gathered under the lock first, so nothing is logged holding it.  The
	 * sites must all be ranked before the biggest can be told, so the
	 * ones past what we list are only added to the rest after
	 */
	ns = lws_alloc_sites(s, (int)LWS_ARRAY_SIZE(s), &rest);
	for (n = LWS_ALLOC_SITE_LISTED; n < ns; n++) {
		rest.bytes += s[n].bytes;
		rest.count += s[n].count;
	}
	if (ns > LWS_ALLOC_SITE_LISTED)
		ns = LWS_ALLOC_SITE_LISTED;

	sites_lock();
	count = sites_live.count;
	sites_unlock();

	for (n = 0; n < ns; n++)
#if defined(LWS_PLAT_CALLERS)
		lwsl_cx_notice(cx, "fp:   %7llu B %4u x %-28.28s 0x%08llx "
				   "0x%08llx 0x%08llx",
				   (unsigned long long)s[n].bytes,
				   s[n].count, s[n].reason,
				   (unsigned long long)s[n].pcs[0],
				   (unsigned long long)s[n].pcs[1],
				   (unsigned long long)s[n].pcs[2]);
#else
		lwsl_cx_notice(cx, "fp:   %7llu B %4u x %s",
			       (unsigned long long)s[n].bytes, s[n].count,
			       s[n].reason);
#endif
	if (rest.count)
		lwsl_cx_notice(cx, "fp:   %7llu B %4u x from elsewhere",
			       (unsigned long long)rest.bytes, rest.count);

	lwsl_cx_notice(cx, "fp:   %7llu B for the %u headers listing them",
		       (unsigned long long)(count * LWS_ALLOC_SITE_HDR_LEN),
		       count);
}
#endif

/*
 * Reclaimable heap occupants, processwide like the heap.  LRU order: the
 * head is the least recently used.
 */

static lws_dll2_owner_t reclaimables;
static char in_reclaim;
/*
 * lws_zalloc_try() is asking: an allocation with a fallback.  Processwide
 * like in_reclaim, since it only lasts for the one allocation.
 */
static char alloc_trying;
/* lws_alloc_arena_set(): processwide too, see there */
static lws_alloc_arena_t alloc_arena;

lws_alloc_arena_t
lws_alloc_arena_set(lws_alloc_arena_t arena)
{
	lws_alloc_arena_t was = alloc_arena;

	alloc_arena = arena;

	return was;
}

void
lws_reclaimable_add(lws_reclaimable_t *r)
{
	lws_dll2_add_tail(&r->list, &reclaimables);
}

void
lws_reclaimable_remove(lws_reclaimable_t *r)
{
	lws_dll2_remove(&r->list);
}

void
lws_reclaimable_touch(lws_reclaimable_t *r)
{
	if (!lws_dll2_is_detached(&r->list)) {
		lws_dll2_remove(&r->list);
		lws_dll2_add_tail(&r->list, &reclaimables);
	}
}

void
lws_reclaimable_pin(lws_reclaimable_t *r)
{
	r->pins++;
}

void
lws_reclaimable_unpin(lws_reclaimable_t *r)
{
	if (r->pins)
		r->pins--;
}

size_t
lws_reclaim(size_t want)
{
	size_t freed = 0;

	/*
	 * A tenant's evict() must not allocate; if one does and that fails,
	 * it gets a plain NULL rather than a nested reclaim
	 */
	if (in_reclaim)
		return 0;
	in_reclaim = 1;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&reclaimables)) {
		lws_reclaimable_t *r = lws_container_of(d, lws_reclaimable_t,
							list);

		if (freed >= want)
			break;

		if (r->pins || !r->resident || !r->evict)
			continue;

		freed += r->evict(r);
	} lws_end_foreach_dll_safe(d, d1);

	in_reclaim = 0;

	return freed;
}

void
lws_heap_limit_set(size_t bytes)
{
#if defined(LWS_PLAT_ALLOC_SIZE)
	heap_limit = bytes;
#else
	(void)bytes;
#endif
}

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
static lws_dll2_owner_t active;
#endif

#if defined(LWS_PLAT_OPTEE)

#define TEE_USER_MEM_HINT_NO_FILL_ZERO       0x80000000
#if defined (LWS_WITH_NETWORK)

/* normal TA apis */

void *__attribute__((weak))
	TEE_Malloc(uint32_t size, uint32_t hint)
{
	return NULL;
}
void *__attribute__((weak))
	TEE_Realloc(void *buffer, uint32_t newSize)
{
	return NULL;
}
void __attribute__((weak))
	TEE_Free(void *buffer)
{
}
#else

/* in-OP-TEE core apis */

void *
	TEE_Malloc(uint32_t size, uint32_t hint)
{
	return malloc(size);
}
void *
	TEE_Realloc(void *buffer, uint32_t newSize)
{
	return realloc(buffer, newSize);
}
void
	TEE_Free(void *buffer)
{
	free(buffer);
}

#endif

void *lws_realloc(void *ptr, size_t size, const char *reason)
{
	return TEE_Realloc(ptr, size);
}

void *lws_malloc(size_t size, const char *reason)
{
	return TEE_Malloc(size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
}

void lws_free(void *p)
{
	TEE_Free(p);
}

void *lws_zalloc(size_t size, const char *reason)
{
	void *ptr = TEE_Malloc(size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

void lws_set_allocator(void *(*cb)(void *ptr, size_t size, const char *reason))
{
	(void)cb;
}
#else

static void *
_realloc(void *ptr, size_t size, const char *reason)
{
#if defined(LWS_WITH_ALLOC_METADATA_LWS)
	uint8_t comp[16 * LWS_ARRAY_SIZE(((lws_backtrace_info_t *)NULL)->st)];
	size_t complen, user_size = size;
	size_t adj = 0, old_adj = 0;
#endif
#if defined(LWS_WITH_ALLOC_SITES)
	uintptr_t pcs[LWS_ALLOC_SITE_CALLERS];
	size_t site_size = size;
#endif
	void *v;

	if (size) {
#if defined(LWS_WITH_ALLOC_SITES)
		if (size > (size_t)-1 - LWS_ALLOC_SITE_HDR_LEN)
			return NULL;

		memset(pcs, 0, sizeof(pcs));
#if defined(LWS_PLAT_CALLERS)
		/*
		 * How many frames stand between us and the code that wanted
		 * the memory depends on the wrapper it called, the platform's
		 * walk and what the compiler inlined or tail called, so keep
		 * the nearest few: the first is usually lws_realloc() or
		 * lws_zalloc(), and the reason says the rest of the time
		 */
		lws_plat_callers(pcs, LWS_ALLOC_SITE_CALLERS, 0);
#endif

		/* realloc() must see the true base, and the room for our header */
		if (ptr)
			ptr = lws_alloc_site_take(ptr);
		size += LWS_ALLOC_SITE_HDR_LEN;
#endif
#if defined(LWS_WITH_ALLOC_METADATA_LWS)
		/*
		 * Any metadata, old or new, is at most a dll2 and a comp
		 * buffer's worth: a size so close to the top of size_t that
		 * adding that wraps must fail like the plain allocation would,
		 * not wrap into a tiny block the caller then overruns
		 */
		if (size > (size_t)-1 - sizeof(lws_dll2_t) - sizeof(comp))
			return NULL;

		lws_alloc_metadata_gen(size, comp, sizeof(comp), &adj, &complen);

		/*
		 * The pointer we handed the caller last time points into the
		 * middle of the real allocation, behind our metadata... we
		 * have to recover the true base (which also unlinks the old
		 * metadata node from "active") before realloc() may see it
		 */

		if (ptr) {
			uint8_t *u = (uint8_t *)ptr;

			_lws_alloc_metadata_trim(&ptr, NULL, NULL);
			old_adj = lws_ptr_diff_size_t(u, ptr);
		}

		/*
		 * The metadata size depends on this call's backtrace and size,
		 * so it generally differs from the old one: realloc() keeps the
		 * caller's data at old_adj, but it must end up at adj.  Get
		 * room for it at whichever offset is further in, and move it
		 * across once we have the new block.
		 */

		size += adj > old_adj ? adj : old_adj;
#endif

#if defined(LWS_PLAT_FREERTOS)
		lwsl_debug("%s: size %lu: %s (free heap %d)\n", __func__,
#if defined(LWS_AMAZON_RTOS)
			    (unsigned long)size, reason, (unsigned int)xPortGetFreeHeapSize() - (int)size);
#else
			    (unsigned long)size, reason, (unsigned int)esp_get_free_heap_size() - (int)size);
#endif
#else
		lwsl_debug("%s: size %lu: %s\n", __func__,
			   (unsigned long)size, reason);
#endif

#if defined(LWS_PLAT_ALLOC_SIZE)
		if (ptr)
			allocated -= lws_plat_alloc_size(ptr);
#endif

		/*
		 * If the platform can't give us the memory, ask the
		 * reclaimable heap occupants to give some back and try
		 * again, until it works or nothing more can be reclaimed.
		 * The caller then sees only a successful allocation.
		 */

		for (;;) {
#if defined(LWS_PLAT_ALLOC_SIZE)
			if (heap_limit && allocated + size > heap_limit)
				v = NULL;
			else
#endif
#if defined(LWS_PLAT_OPTEE)
				v = (void *)TEE_Realloc(ptr, size);
#elif defined(LWS_PLAT_REALLOC_ARENA)
				v = lws_plat_realloc_arena(ptr, size,
							   (int)alloc_arena);
#else
				v = (void *)realloc(ptr, size);
#endif
			if (v)
				break;

			/*
			 * An allocation with a fallback just fails: nobody is
			 * asked to give anything back for it, and the heap
			 * didn't run out for anybody
			 */
			if (alloc_trying || !lws_reclaim(size)) {
#if defined(LWS_WITH_FOOTPRINT)
				if (!alloc_trying)
					lws_footprint_alloc_failed(size, reason);
#endif
#if defined(LWS_PLAT_ALLOC_SIZE)
				/* the old block is still ours */
				if (ptr)
					allocated += lws_plat_alloc_size(ptr);
#endif
#if defined(LWS_WITH_ALLOC_METADATA_LWS)
				/* ... and still live: list it again */
				if (ptr)
					lws_dll2_add_tail((lws_dll2_t *)
						((uint8_t *)ptr + old_adj -
						 sizeof(lws_dll2_t)), &active);
#endif
#if defined(LWS_WITH_ALLOC_SITES)
				/* ... and still live: list it again */
				if (ptr) {
					sites_lock();
					lws_dll2_add_tail(&((lws_alloc_site_hdr_t *)
						ptr)->list, &sites_live);
					sites_unlock();
				}
#endif
				return NULL;
			}
		}

#if defined(LWS_PLAT_ALLOC_SIZE)
		allocated += lws_plat_alloc_size(v);
#endif

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
		/*
		 * Before the new metadata goes in, since with adj > old_adj it
		 * overlaps where the data was.  user_size is in bounds at both
		 * offsets; on a grow the part past the old data is garbage
		 * either way.
		 */
		if (old_adj && old_adj != adj)
			memmove((uint8_t *)v + adj, (uint8_t *)v + old_adj,
				user_size);

		_lws_alloc_metadata_adjust(&active, &v, adj, comp, (unsigned int)complen);
#endif
#if defined(LWS_WITH_ALLOC_SITES)
		v = lws_alloc_site_give(v, site_size, reason, pcs);
#endif

		return v;
	}

	/*
	 * We are freeing it then...
	 */

	if (ptr) {
#if defined(LWS_WITH_ALLOC_METADATA_LWS)
		_lws_alloc_metadata_trim(&ptr, NULL, NULL);
#endif
#if defined(LWS_WITH_ALLOC_SITES)
		ptr = lws_alloc_site_take(ptr);
		((lws_alloc_site_hdr_t *)ptr)->magic = 0;
#endif

#if defined(LWS_PLAT_ALLOC_SIZE)
		allocated -= lws_plat_alloc_size(ptr);
#endif
		free(ptr);
#if defined(LWS_PLAT_FREERTOS)
		lwsl_debug("%s: free heap %d\n", __func__,
#if defined(LWS_AMAZON_RTOS)
			    (unsigned int)xPortGetFreeHeapSize() - (int)size);
#else
			    (unsigned int)esp_get_free_heap_size() - (int)size);
#endif
#endif
	}

	return NULL;
}

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
void
_lws_alloc_metadata_dump_lws(lws_dll2_foreach_cb_t cb, void *arg)
{
	lwsl_err("%s\n", __func__);
	_lws_alloc_metadata_dump(&active, cb, arg);
}
#endif

void *(*_lws_realloc)(void *ptr, size_t size, const char *reason) = _realloc;

void *lws_realloc(void *ptr, size_t size, const char *reason)
{
	return _lws_realloc(ptr, size, reason);
}

void *lws_zalloc(size_t size, const char *reason)
{
	void *ptr = _lws_realloc(NULL, size, reason);

	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

void lws_set_allocator(void *(*cb)(void *ptr, size_t size, const char *reason))
{
#if defined(LWS_WITH_ALLOC_SITES)
	sites_foreign = cb != _realloc;
#endif
	_lws_realloc = cb;
}

size_t lws_get_allocated_heap(void)
{
#if defined(LWS_PLAT_ALLOC_SIZE)
	return allocated;
#else
	return 0;
#endif
}
#endif

void *
lws_zalloc_try(size_t size, const char *reason)
{
	void *v;

	alloc_trying = 1;
	v = lws_zalloc(size, reason);
	alloc_trying = 0;

	return v;
}
