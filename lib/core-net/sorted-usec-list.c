/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
lws_sul2_schedule(struct lws_context *context, int tsi, int flags,
	          lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];

	__lws_sul_insert(
		&pt->pt_sul_owner[!!(flags & LWSSULLI_WAKE_IF_SUSPENDED)], sul);
}

/*
 * own points to the first in an array of length own_len
 *
 * While any sul list owner has a "ripe", ie, ready to handle sul we do them
 * strictly in order of sul time.  When nobody has a ripe sul we return 0, if
 * actually nobody has any sul, or the interval between usnow and the next
 * earliest scheduled event on any list.
 */

lws_usec_t
__lws_sul_service_ripe(lws_dll2_owner_t *own, int own_len, lws_usec_t usnow)
{
	struct lws_context_per_thread *pt = (struct lws_context_per_thread *)
			lws_container_of(own, struct lws_context_per_thread,
					 pt_sul_owner);

	if (pt->attach_owner.count)
		lws_system_do_attach(pt);

	/* must be at least 1 */
	assert(own_len);

	/*
	 * Of the own_len sul owning lists, the earliest next sul could be on
	 * any of them.  We have to find it and handle each in turn until no
	 * ripe sul left on any owning list, and we can exit.
	 *
	 * This ensures the ripe sul are handled strictly in the right order no
	 * matter which owning list they are on.
	 */

	do {
		lws_sorted_usec_list_t *hit = NULL;
		lws_usec_t lowest;
		int n = 0;

		for (n = 0; n < own_len; n++) {
			lws_sorted_usec_list_t *sul;
			if (!own[n].count)
				continue;
			 sul = (lws_sorted_usec_list_t *)
						     lws_dll2_get_head(&own[n]);

			if (!hit || sul->us <= lowest) {
				hit = sul;
				lowest = sul->us;
			}
		}

		if (!hit)
			return 0;

		if (lowest > usnow)
			return lowest - usnow;

		/* his moment has come... remove him from his owning list */

		lws_dll2_remove(&hit->list);
		hit->us = 0;

		pt->inside_lws_service = 1;
		hit->cb(hit);
		pt->inside_lws_service = 0;

	} while (1);

	/* unreachable */

	return 0;
}

/*
 * Earliest wakeable event on any pt
 */

int
lws_sul_earliest_wakeable_event(struct lws_context *ctx, lws_usec_t *pearliest)
{
	struct lws_context_per_thread *pt;
	int n = 0, hit = -1;
	lws_usec_t lowest;

	for (n = 0; n < ctx->count_threads; n++) {
		pt = &ctx->pt[n];

		lws_pt_lock(pt, __func__);

		if (pt->pt_sul_owner[LWSSULLI_WAKE_IF_SUSPENDED].count) {
			lws_sorted_usec_list_t *sul = (lws_sorted_usec_list_t *)
					lws_dll2_get_head(&pt->pt_sul_owner[
					           LWSSULLI_WAKE_IF_SUSPENDED]);

			if (hit == -1 || sul->us < lowest) {
				hit = n;
				lowest = sul->us;
			}
		}

		lws_pt_unlock(pt);
	}


	if (hit == -1)
		/* there is no pending event */
		return 1;

	*pearliest = lowest;

	return 0;
}
