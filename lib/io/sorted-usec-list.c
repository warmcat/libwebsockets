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

/*
 * IO's side of the timer lists (the lists themselves, and scheduling into
 * them, are neither half's: lib/core-net/sorted-usec-list.c): the service
 * running the deadlines that are due, and the clock's own adjustments.
 */

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

	if (lws_dll2_count(&pt->attach_owner))
		lws_system_do_attach(pt);

	lws_pt_assert_lock_held(pt);

	/* must be at least 1 */
	assert(own_len > 0);

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
		lws_usec_t lowest = 0;
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

		if (!hit->cb) {
			/*
			 * Removed before bailing on purpose: it is ripe and
			 * cannot be serviced, if we left it on the list it
			 * would be found again on every service and no sul on
			 * this pt would ever fire again
			 */
			lwsl_err("%s: sul with NULL callback (did not cancel on destory?)\n", __func__);

			continue;
		}

		// lwsl_notice("%s: sul: %p\n", __func__, hit->cb);

		pt->inside_lws_service = 1;

#if defined(LWS_WITH_LATENCY)
		lws_latency_cb_start(pt);
#endif

		hit->cb(hit);

#if defined(LWS_WITH_LATENCY)
		lws_latency_cb_end(pt, "timer");
#endif

		pt->inside_lws_service = 0;

	} while (1);

	/* unreachable */

	return 0;
}

/*
 * Normally we use the OS monotonic time, which does not step when the
 * gettimeofday() time is adjusted after, eg, ntpclient.  But on some OSes,
 * high resolution monotonic time doesn't exist; sul time is computed from and
 * compared against gettimeofday() time and breaks when that steps.
 *
 * For those cases, this allows us to retrospectively adjust existing suls on
 * all owning lists by the step amount, at the same time we adjust the
 * nonmonotonic clock.  Then nothing breaks so long as we do this when the
 * gettimeofday() clock is stepped.
 *
 * Linux and so on offer Posix MONOTONIC, which lws uses.  FreeRTOS doesn't
 * have a high-resolution monotonic clock and has to use gettimeofday(), which
 * requires this adjustment when it is stepped.
 */

lws_usec_t
lws_sul_nonmonotonic_adjust(struct lws_context *ctx, int64_t step_us)
{
	struct lws_context_per_thread *pt = &ctx->pt[0];
	int n, m;

	/*
	 * for each pt
	 */

	for (m = 0; m < ctx->count_threads; m++) {

		/*
		 * For each owning list...
		 */

		lws_pt_lock(pt, __func__);

		for (n = 0; n < LWS_COUNT_PT_SUL_OWNERS; n++) {

			if (!pt->pt_sul_owner[n].count)
				continue;

			/* ... and for every existing sul on a list... */

			lws_start_foreach_dll(struct lws_dll2 *, p,
					      lws_dll2_get_head(
							&pt->pt_sul_owner[n])) {
				lws_sorted_usec_list_t *sul = lws_container_of(
					       p, lws_sorted_usec_list_t, list);

				/*
				 * ... retrospectively step its ripe time by the
				 * step we will adjust the gettimeofday() clock
				 * with
				 */

				sul->us += step_us;

			} lws_end_foreach_dll(p);
		}

		lws_pt_unlock(pt);

		pt++;
	}

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
	lws_usec_t lowest = 0;

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
