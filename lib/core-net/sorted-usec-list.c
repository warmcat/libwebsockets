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

int
__lws_sul_insert(lws_dll2_owner_t *own, lws_sorted_usec_list_t *sul,
		 lws_usec_t us)
{
	lws_usec_t now = lws_now_usecs();
	lws_dll2_remove(&sul->list);

	if (us == LWS_SET_TIMER_USEC_CANCEL) {
		/* we are clearing the timeout */
		sul->us = 0;

		return 0;
	}

	sul->us = now + us;
	assert(sul->cb);

	/*
	 * we sort the pt's list of sequencers with pending timeouts, so it's
	 * cheap to check it every second
	 */

	lws_dll2_add_sorted(&sul->list, own, sul_compare);

#if 0 // defined(_DEBUG)
	{
		lws_usec_t worst = 0;
		int n = 1;

		lwsl_info("%s: own %p: count %d\n", __func__, own, own->count);

		lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
					   lws_dll2_get_head(own)) {
			lws_sorted_usec_list_t *sul = (lws_sorted_usec_list_t *)p;
			lwsl_info("%s:    %d: %llu (+%lld)\n", __func__, n++,
					(unsigned long long)sul->us,
					(long long)(sul->us - now));
			if (sul->us < worst) {
				lwsl_err("%s: wrongly sorted sul entry!\n",
						__func__);
				assert(0);
			}
			worst = sul->us;
		} lws_end_foreach_dll_safe(p, tp);
	}
#endif

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
__lws_sul_service_ripe(lws_dll2_owner_t *own, lws_usec_t usnow)
{
	struct lws_context_per_thread *pt = (struct lws_context_per_thread *)
			lws_container_of(own, struct lws_context_per_thread,
					 pt_sul_owner);

	if (pt->attach_owner.count)
		lws_system_do_attach(pt);

	while (lws_dll2_get_head(own)) {

		/* .list is always first member in lws_sorted_usec_list_t */
		lws_sorted_usec_list_t *sul = (lws_sorted_usec_list_t *)
							lws_dll2_get_head(own);

		assert(sul->us); /* shouldn't be on the list otherwise */

		if (sul->us > usnow)
			return sul->us - usnow;

		/* his moment has come... remove him from timeout list */
		lws_dll2_remove(&sul->list);
		sul->us = 0;
		pt->inside_lws_service = 1;
		sul->cb(sul);
		pt->inside_lws_service = 0;

		/*
		 * The callback may have done any mixture of delete
		 * and add sul entries... eg, close a wsi may pull out
		 * multiple entries making iterating it statefully
		 * unsafe.  Always restart at the current head of list.
		 */
	}

	/*
	 * Nothing left to take care of in the list (cannot return 0 otherwise
	 * because we will service anything equal to usnow rather than return)
	 */

	return 0;
}
