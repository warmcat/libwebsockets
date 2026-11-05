/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 *
 * lws_footprint: caches, pools and lists account for the heap they hold.  See
 * READMEs/README.lws_footprint.md
 */

#include "private-lib-core.h"

static struct lws_context *
fp_cx(lws_footprint_t *fp)
{
	return lws_container_of(fp->list.owner, struct lws_context, footprints);
}

static void
fp_report(lws_footprint_t *fp, lws_footprint_report_t *r)
{
	memset(r, 0, sizeof(*r));
	r->count	= fp->count;
	r->bytes	= fp->bytes;
	r->bytes_hwm	= fp->bytes_hwm;

	if (fp->ops && fp->ops->report)
		fp->ops->report(fp, r);
}

/*
 * The free heap, if the platform can say.  The context keeps what it was when
 * the context was created, so the dump can say how much has gone since.
 */
static int
fp_heap_free(size_t *heap_free)
{
#if defined(LWS_PLAT_FREERTOS)
#if defined(LWS_AMAZON_RTOS)
	*heap_free = (size_t)xPortGetFreeHeapSize();
#else
	*heap_free = (size_t)esp_get_free_heap_size();
#endif
	return 0;
#else
	(void)heap_free;

	return 1;
#endif
}

/*
 * The allocator has no context, so when an allocation fails it dumps the first
 * context's participants
 */
static struct lws_context *fp_oom_cx;

void
lws_footprint_context_init(struct lws_context *cx)
{
	if (fp_heap_free(&cx->fp_baseline_free))
		cx->fp_baseline_free = 0;

	if (!fp_oom_cx)
		fp_oom_cx = cx;
}

void
lws_footprint_context_destroy(struct lws_context *cx)
{
	/*
	 * Participants should all have unregistered as their owners went.  Any
	 * still here outlive the context, say who they are and detach them, so
	 * their later unregister doesn't touch the freed context
	 */

	if (fp_oom_cx == cx)
		fp_oom_cx = NULL;

	while (cx->footprints.head) {
		lws_footprint_t *fp = lws_container_of(cx->footprints.head,
						       lws_footprint_t, list);

		lwsl_cx_warn(cx, "%s %s still registered, %u items, %llu bytes",
			     fp->source, fp->ident ? fp->ident : "",
			     (unsigned int)fp->count,
			     (unsigned long long)fp->bytes);
		lws_dll2_remove(&fp->list);
	}
}

void
lws_footprint_register(struct lws_context *cx, lws_footprint_t *fp,
		       const char *source, const lws_footprint_ops_t *ops)
{
	fp->source	= source;
	fp->ops		= ops;

	lws_context_lock(cx, __func__); /* ------------------------- cx { */
	lws_dll2_add_tail(&fp->list, &cx->footprints);
	lws_context_unlock(cx); /* ----------------------------------- } cx */
}

void
lws_footprint_unregister(lws_footprint_t *fp)
{
	struct lws_context *cx;

	if (!fp->list.owner)
		return;

	cx = fp_cx(fp);

	lws_context_lock(cx, __func__); /* ------------------------- cx { */
	lws_dll2_remove(&fp->list);
	lws_context_unlock(cx); /* ----------------------------------- } cx */
}

int
lws_footprint_total(struct lws_context *cx, lws_footprint_report_t *r)
{
	lws_footprint_report_t pr;
	int n = 0;

	memset(r, 0, sizeof(*r));

	lws_context_lock(cx, __func__); /* ------------------------- cx { */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->footprints)) {
		fp_report(lws_container_of(d, lws_footprint_t, list), &pr);

		r->count	+= pr.count;
		r->bytes	+= pr.bytes;
		r->bytes_hwm	+= pr.bytes_hwm;
		r->sheddable	+= pr.sheddable;
		n++;
	} lws_end_foreach_dll(d);

	lws_context_unlock(cx); /* ----------------------------------- } cx */

	return n;
}

void
lws_footprint_dump(struct lws_context *cx, int items)
{
	lws_footprint_report_t r, t;
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	size_t heap_free;
#endif

	memset(&t, 0, sizeof(t));

	lws_context_lock(cx, __func__); /* ------------------------- cx { */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->footprints)) {
		lws_footprint_t *fp = lws_container_of(d, lws_footprint_t,
						       list);

		fp_report(fp, &r);

		lwsl_cx_notice(cx, "fp: %-16s %-24s %5u items %7llu B "
				   "(hwm %7llu, shed %7llu)", fp->source,
				   fp->ident ? fp->ident : "-",
				   (unsigned int)r.count,
				   (unsigned long long)r.bytes,
				   (unsigned long long)r.bytes_hwm,
				   (unsigned long long)r.sheddable);

		if (items && fp->ops && fp->ops->dump)
			fp->ops->dump(fp);

		t.count		+= r.count;
		t.bytes		+= r.bytes;
		t.sheddable	+= r.sheddable;
	} lws_end_foreach_dll(d);

	lws_context_unlock(cx); /* ----------------------------------- } cx */

	lwsl_cx_notice(cx, "fp: total %u participants, %u items, %llu B "
			   "(shed %llu)", (unsigned int)cx->footprints.count,
			   (unsigned int)t.count, (unsigned long long)t.bytes,
			   (unsigned long long)t.sheddable);

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	if (!fp_heap_free(&heap_free) && cx->fp_baseline_free) {
		long long used = (long long)cx->fp_baseline_free -
				 (long long)heap_free;

		lwsl_cx_notice(cx, "fp: heap free %llu, %lld used since context "
				   "creation, %lld of it not accounted for",
				   (unsigned long long)heap_free, used,
				   used - (long long)t.bytes);
	}
#if defined(LWS_ESP_PLATFORM)
	{
		/*
		 * The free heap is spread over several regions and the holes
		 * between allocations: a big allocation needs one hole that
		 * size, however much is free in all
		 */
		multi_heap_info_t mhi;

		heap_caps_get_info(&mhi, MALLOC_CAP_8BIT);
		lwsl_cx_notice(cx, "fp: largest free block %u, in %u free blocks",
			       (unsigned int)mhi.largest_free_block,
			       (unsigned int)mhi.free_blocks);
#if defined(LWS_PLAT_HEAP_INTERNAL)
		/* ... and of it, the internal RAM only some things can use */
		heap_caps_get_info(&mhi, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
		lwsl_cx_notice(cx, "fp: internal free %u, largest block %u, "
			       "in %u free blocks",
			       (unsigned int)mhi.total_free_bytes,
			       (unsigned int)mhi.largest_free_block,
			       (unsigned int)mhi.free_blocks);
#endif
	}
#endif
#endif
#if defined(LWS_PLAT_ALLOC_SIZE)
	/*
	 * What lws_malloc() and friends hold, which is most of what lws
	 * participants count, but not the tls library's own
	 */
	lwsl_cx_notice(cx, "fp: lws_malloc() holds %llu",
		       (unsigned long long)lws_get_allocated_heap());
#endif
#if defined(LWS_WITH_ALLOC_SITES)
	/* ... and who asked for it, including what participants count */
	if (items)
		lws_alloc_sites_dump(cx);
#endif
}

void
lws_footprint_alloc_failed(size_t size, const char *reason)
{
#if !defined(LWS_WITH_NETWORK) || LWS_MAX_SMP == 1
	static lws_usec_t last;
	static char in_dump;
	lws_usec_t now;

	/*
	 * With one service thread there are no real locks to get in the order
	 * of; with more, the failing thread may hold a pt lock, which must
	 * never be held taking the context lock, so it's left to the dumps
	 * the application asks for.
	 *
	 * A burst of failures is usually one shortage, so say it once.
	 */

	if (!fp_oom_cx || in_dump)
		return;

	now = lws_now_usecs();
	if (last && now - last < 5 * LWS_US_PER_SEC)
		return;
	last = now;

	in_dump = 1;
#if defined(LWS_ESP_PLATFORM)
	lwsl_cx_warn(fp_oom_cx, "fp: no heap for %llu bytes for %s (largest "
		     "free block %u)", (unsigned long long)size,
		     reason ? reason : "-", (unsigned int)
		     heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
#else
	lwsl_cx_warn(fp_oom_cx, "fp: no heap for %llu bytes for %s",
		     (unsigned long long)size, reason ? reason : "-");
#endif
	lws_footprint_dump(fp_oom_cx, 1);
	in_dump = 0;
#else
	(void)size;
	(void)reason;
#endif
}

/*
 * Shedding may destroy objects that unregister other participants, or the one
 * being asked, so we can't keep a place in the list across a .shed.  Instead
 * each call has a pass number, a participant asked on this pass is marked with
 * it, and after each .shed we look again from the head for the next one of
 * the class not yet asked.
 */

static lws_footprint_t *
fp_next_to_shed(struct lws_context *cx, lws_fp_shed_t c, unsigned int pass)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->footprints)) {
		lws_footprint_t *fp = lws_container_of(d, lws_footprint_t,
						       list);

		if (fp->ops && fp->ops->shed && fp->ops->shed_class == c &&
		    fp->shed_pass != pass)
			return fp;
	} lws_end_foreach_dll(d);

	return NULL;
}

size_t
lws_footprint_shed(struct lws_context *cx, size_t want, lws_fp_shed_t most)
{
	lws_footprint_t *fp;
	unsigned int pass;
	size_t freed = 0;
	int c;

	lws_context_lock(cx, __func__); /* ------------------------- cx { */

	pass = ++cx->fp_shed_pass;

	for (c = LWSFP_SHED_IDLE; c <= (int)most && freed < want; c++)
		while (freed < want &&
		       (fp = fp_next_to_shed(cx, (lws_fp_shed_t)c, pass))) {
			const char *source = fp->source;
			size_t f;

			fp->shed_pass = pass;
			f = fp->ops->shed(fp, want - freed);
			/* fp may be gone now */
			if (f)
				lwsl_cx_info(cx, "%s gave back %llu", source,
					     (unsigned long long)f);
			(void)source; /* without info logs */
			freed += f;
		}

	lws_context_unlock(cx); /* ----------------------------------- } cx */

	return freed;
}
