/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"

int
__lws_sul_insert(lws_dll2_owner_t *own, lws_sorted_usec_list_t *sul,
		 lws_usec_t us)
{
	lws_dll2_remove(&sul->list);

	if (us == LWS_SET_TIMER_USEC_CANCEL) {
		/* we are clearing the timeout */
		sul->us = 0;

		return 0;
	}

	sul->us = lws_now_usecs() + us;
	assert(sul->cb);

	/*
	 * we sort the pt's list of sequencers with pending timeouts, so it's
	 * cheap to check it every second
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   lws_dll2_get_head(own)) {
		/* .list is always first member in lws_sorted_usec_list_t */
		lws_sorted_usec_list_t *sul1 = (lws_sorted_usec_list_t *)p;

		assert(sul1->us); /* shouldn't be on the list otherwise */
		assert(sul != sul1);
		if (sul1->us >= sul->us) {
			/* drop us in before this guy */
			lws_dll2_add_before(&sul->list, &sul1->list);

			// lws_dll2_describe(own, "post-insert");

			return 0;
		}
	} lws_end_foreach_dll_safe(p, tp);

	/*
	 * Either nobody on the list yet to compare him to, or he's the
	 * furthest away timeout... stick him at the tail end
	 */

	lws_dll2_add_tail(&sul->list, own);

	// lws_dll2_describe(own, "post-tail-insert");

	return 0;
}

void
lws_sul_schedule(struct lws_context *context, int tsi,
	         lws_sorted_usec_list_t *sul, sul_cb_t cb, lws_usec_t us)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];

	sul->cb = cb;

	__lws_sul_insert(&pt->pt_sul_owner, sul, us);
}

lws_usec_t
__lws_sul_check(lws_dll2_owner_t *own, lws_usec_t usnow)
{
	lws_usec_t future_us = 0;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   lws_dll2_get_head(own)) {
		/* .list is always first member in lws_sorted_usec_list_t */
		lws_sorted_usec_list_t *sul = (lws_sorted_usec_list_t *)p;

		assert(sul->us); /* shouldn't be on the list otherwise */
		if (sul->us <= usnow) {
			/* seq has timed out... remove him from timeout list */
			lws_dll2_remove(&sul->list);
			sul->us = 0;
			sul->cb(sul);
		} else {
			/*
			 * No need to look further if we met one later than now:
			 * the list is sorted in ascending time order
			 */
			future_us = sul->us - usnow;

			break;
		}

	} lws_end_foreach_dll_safe(p, tp);

	return future_us;
}
