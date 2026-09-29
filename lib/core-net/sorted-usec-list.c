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
 * sorted-usec-list.c: the timer lists both halves schedule into: a sorted
 * list of deadlines per service thread.  Neither half's (see
 * READMEs/README.sans-io-split.md): sansIO sets its deadlines here, and an IO
 * that wants to hear of a new earliest one is told through the deadline op
 * (lws-io-ops.h); IO's service runs what is due (lib/io/sorted-usec-list.c).
 */

#include "private-lib-core.h"

static int
sul_compare(const lws_dll2_t *d, const lws_dll2_t *i)
{
	lws_usec_t a = ((lws_sorted_usec_list_t *)d)->us;
	lws_usec_t b = ((lws_sorted_usec_list_t *)i)->us;

	/*
	 * Simply returning (a - b) in an int
	 * may lead to an integer overflow bug
	 */

	if (a > b)
		return 1;
	if (a < b)
		return -1;

	return 0;
}

/*
 * notice owner was chosen already, and sul->us was already computed
 */

int
__lws_sul_insert(lws_dll2_owner_t *own, lws_sorted_usec_list_t *sul)
{
	lws_dll2_remove(&sul->list);

	assert(sul->cb);

	/*
	 * we sort the pt's list of sequencers with pending timeouts, so it's
	 * cheap to check it every poll wait
	 */

	lws_dll2_add_sorted(&sul->list, own, sul_compare);

	return 0;
}

void
lws_sul_cancel(lws_sorted_usec_list_t *sul)
{
	lws_dll2_remove(&sul->list);

	/* we are clearing the timeout and leaving ourselves detached */
	sul->us = 0;
}

void
__lws_sul_insert_pt(struct lws_context_per_thread *pt, int idx,
		    lws_sorted_usec_list_t *sul)
{
	struct lws_context *cx = pt->context;

	__lws_sul_insert(&pt->pt_sul_owner[idx], sul);

	/*
	 * If this became the earliest deadline on the pt, an IO that wants
	 * to be told (lws-io-ops.h) hears it now; the built-in loops ask
	 * what is due each time round instead
	 */
	if (cx->io_ops && cx->io_ops->deadline &&
	    lws_dll2_get_head(&pt->pt_sul_owner[idx]) == &sul->list)
		cx->io_ops->deadline(cx, (int)pt->tid, sul->us);
}

void
lws_sul2_schedule(struct lws_context *context, int tsi, int flags,
	          lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];

	lws_pt_assert_lock_held(pt);

	assert(sul->cb);

	__lws_sul_insert_pt(pt, !!(flags & LWSSULLI_WAKE_IF_SUSPENDED), sul);
}

void
lws_sul_schedule(struct lws_context *ctx, int tsi, lws_sorted_usec_list_t *sul,
		 sul_cb_t _cb, lws_usec_t _us)
{
	struct lws_context_per_thread *_pt = &ctx->pt[tsi];

	assert(_cb);

	lws_pt_lock(_pt, __func__);

	if (_us == (lws_usec_t)LWS_SET_TIMER_USEC_CANCEL)
		lws_sul_cancel(sul);
	else {
		sul->cb = _cb;
		sul->us = lws_pt_now(_pt) + _us;
		lws_sul2_schedule(ctx, tsi, LWSSULLI_MISS_IF_SUSPENDED, sul);
	}

	lws_pt_unlock(_pt);
}

void
lws_sul_schedule_wakesuspend(struct lws_context *ctx, int tsi,
			     lws_sorted_usec_list_t *sul, sul_cb_t _cb,
			     lws_usec_t _us)
{
	struct lws_context_per_thread *_pt = &ctx->pt[tsi];

	assert(_cb);

	lws_pt_lock(_pt, __func__);

	if (_us == (lws_usec_t)LWS_SET_TIMER_USEC_CANCEL)
		lws_sul_cancel(sul);
	else {
		sul->cb = _cb;
		sul->us = lws_pt_now(_pt) + _us;
		lws_sul2_schedule(ctx, tsi, LWSSULLI_WAKE_IF_SUSPENDED, sul);
	}

	lws_pt_unlock(_pt);
}

#if defined(LWS_WITH_SUL_DEBUGGING)

/*
 * Sanity checker for any sul left scheduled when its containing object is
 * freed... code scheduling suls must take care to cancel them when destroying
 * their object.  This optional debugging helper checks that when an object is
 * being destroyed, there is no live sul scheduled from inside the object.
 */

void
lws_sul_debug_zombies(struct lws_context *ctx, void *po, size_t len,
		      const char *destroy_description)
{
	struct lws_context_per_thread *pt;
	int n, m;

	for (n = 0; n < ctx->count_threads; n++) {
		pt = &ctx->pt[n];

		lws_pt_lock(pt, __func__);

		for (m = 0; m < LWS_COUNT_PT_SUL_OWNERS; m++) {

			lws_start_foreach_dll(struct lws_dll2 *, p,
				      lws_dll2_get_head(&pt->pt_sul_owner[m])) {
				lws_sorted_usec_list_t *sul =
					lws_container_of(p,
						lws_sorted_usec_list_t, list);

				if (!po) {
					lwsl_cx_err(ctx, "%s",
							 destroy_description);
					/* just sanity check the list */
					assert(sul->cb);
				}

				/*
				 * Is the sul resident inside the object that is
				 * indicated as being deleted?
				 */

				if (po &&
				    (void *)sul >= po &&
				    (size_t)lws_ptr_diff(sul, po) < len) {
					lwsl_cx_err(ctx, "ERROR: Zombie Sul "
						 "(on list %d) %s, cb %p\n", m,
						 destroy_description, sul->cb);
					/*
					 * This assert fires if you have left
					 * a sul scheduled to fire later, but
					 * are about to destroy the object the
					 * sul lives in.  You must take care to
					 * do lws_sul_cancel(&sul) on any suls
					 * that may be scheduled before
					 * destroying the object the sul lives
					 * inside.
					 *
					 * You can look up the cb pointer in
					 * your mapfile to find out which
					 * callback function the sul was using
					 * which usually tells you which sul
					 * it is.
					 */
					assert(0);
				}

			} lws_end_foreach_dll(p);
		}

		lws_pt_unlock(pt);
	}
}

#endif
