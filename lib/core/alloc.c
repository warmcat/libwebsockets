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

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)

#include <malloc.h>

/* the heap is processwide */
static size_t allocated, heap_limit;
#endif

/*
 * Reclaimable heap occupants, processwide like the heap.  LRU order: the
 * head is the least recently used.
 */

static lws_dll2_owner_t reclaimables;
static char in_reclaim;

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
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
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
	size_t complen;
	size_t adj = 0;
#endif
	void *v;

	if (size) {
#if defined(LWS_WITH_ALLOC_METADATA_LWS)
		lws_alloc_metadata_gen(size, comp, sizeof(comp), &adj, &complen);
		size += adj;

		/*
		 * The pointer we handed the caller last time points into the
		 * middle of the real allocation, behind our metadata... we
		 * have to recover the true base (which also unlinks the old
		 * metadata node from "active") before realloc() may see it
		 */

		if (ptr)
			_lws_alloc_metadata_trim(&ptr, NULL, NULL);
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

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
		if (ptr)
			allocated -= malloc_usable_size(ptr);
#endif

		/*
		 * If the platform can't give us the memory, ask the
		 * reclaimable heap occupants to give some back and try
		 * again, until it works or nothing more can be reclaimed.
		 * The caller then sees only a successful allocation.
		 */

		for (;;) {
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
			if (heap_limit && allocated + size > heap_limit)
				v = NULL;
			else
#endif
#if defined(LWS_PLAT_OPTEE)
				v = (void *)TEE_Realloc(ptr, size);
#else
				v = (void *)realloc(ptr, size);
#endif
			if (v)
				break;

			if (!lws_reclaim(size)) {
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
				/* the old block is still ours */
				if (ptr)
					allocated += malloc_usable_size(ptr);
#endif
				return NULL;
			}
		}

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
		allocated += malloc_usable_size(v);
#endif

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
		_lws_alloc_metadata_adjust(&active, &v, adj, comp, (unsigned int)complen);
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

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
		allocated -= malloc_usable_size(ptr);
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
	_lws_realloc = cb;
}

size_t lws_get_allocated_heap(void)
{
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
	return allocated;
#else
	return 0;
#endif
}
#endif
