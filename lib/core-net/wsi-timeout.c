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

void
__lws_remove_from_timeout_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	lws_dll_remove_track_tail(&wsi->dll_timeout, &pt->dll_timeout_head);
}

void
lws_remove_from_timeout_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);
	__lws_remove_from_timeout_list(wsi);
	lws_pt_unlock(pt);
}


void
__lws_set_timer_usecs(struct lws *wsi, lws_usec_t usecs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws_dll *target = NULL;
	struct timeval now;
	struct lws *wsi1;
	int bef = 0;

	lws_dll_remove_track_tail(&wsi->dll_hrtimer, &pt->dll_hrtimer_head);

	if (usecs == LWS_SET_TIMER_USEC_CANCEL)
		return;

	gettimeofday(&now, NULL);
	wsi->pending_timer = ((now.tv_sec * 1000000ll) + now.tv_usec) + usecs;

	/*
	 * we sort the hrtimer list with the earliest timeout first
	 */

	lws_start_foreach_dll_safe(struct lws_dll *, d, d1,
				   pt->dll_hrtimer_head.next) {
		target = d;
		wsi1 = lws_container_of(d, struct lws, dll_hrtimer);

		if (wsi1->pending_timer >= wsi->pending_timer) {
			/* d, dprev's next, is >= our time */
			bef = 1;
			break;
		}
	} lws_end_foreach_dll_safe(d, d1);

	lws_dll_insert(&wsi->dll_hrtimer, target, &pt->dll_hrtimer_head, bef);
}

LWS_VISIBLE void
lws_set_timer_usecs(struct lws *wsi, lws_usec_t usecs)
{
	__lws_set_timer_usecs(wsi, usecs);
}


lws_usec_t
__lws_hrtimer_service(struct lws_context_per_thread *pt)
{
	struct timeval now;
	struct lws *wsi;
	lws_usec_t t;

	gettimeofday(&now, NULL);
	t = (now.tv_sec * 1000000ll) + now.tv_usec;

	lws_start_foreach_dll_safe(struct lws_dll *, d, d1,
				   pt->dll_hrtimer_head.next) {
		wsi = lws_container_of(d, struct lws, dll_hrtimer);

		/*
		 * if we met one in the future, we are done, because the list
		 * is sorted by time in the future.
		 */
		if (wsi->pending_timer > t)
			break;

		lws_set_timer_usecs(wsi, LWS_SET_TIMER_USEC_CANCEL);

		/* it's time for the timer to be serviced */

		if (wsi->protocol &&
		    wsi->protocol->callback(wsi, LWS_CALLBACK_TIMER,
					    wsi->user_space, NULL, 0))
			__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					     "timer cb errored");
	} lws_end_foreach_dll_safe(d, d1);

	/* return an estimate how many us until next timer hit */

	if (!pt->dll_hrtimer_head.next)
		return LWS_HRTIMER_NOWAIT;

	wsi = lws_container_of(pt->dll_hrtimer_head.next, struct lws,
			       dll_hrtimer);

	gettimeofday(&now, NULL);
	t = (now.tv_sec * 1000000ll) + now.tv_usec;

	if (wsi->pending_timer < t)
		return 0;

	return wsi->pending_timer - t;
}

void
__lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	time_t now;

	time(&now);

	lwsl_debug("%s: %p: %d secs (reason %d)\n", __func__, wsi, secs, reason);
	wsi->pending_timeout_limit = secs;
	wsi->pending_timeout_set = now;
	wsi->pending_timeout = reason;

	lws_dll_remove_track_tail(&wsi->dll_timeout, &pt->dll_timeout_head);
	if (reason)
		lws_dll_add_head(&wsi->dll_timeout, &pt->dll_timeout_head);
}

LWS_VISIBLE void
lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	// lwsl_info("%s: %p: %d %d\n", __func__, wsi, reason, secs);

	if (secs == LWS_TO_KILL_SYNC) {
		lws_remove_from_timeout_list(wsi);
		lwsl_debug("synchronously killing %p\n", wsi);
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "to sync kill");
		return;
	}

	if (secs == LWS_TO_KILL_ASYNC)
		secs = 0;

	lws_pt_lock(pt, __func__);
	__lws_set_timeout(wsi, reason, secs);
	lws_pt_unlock(pt);
}

/* requires context + vh lock */

int
__lws_timed_callback_remove(struct lws_vhost *vh, struct lws_timed_vh_protocol *p)
{
	lws_start_foreach_llp(struct lws_timed_vh_protocol **, pt,
			      vh->timed_vh_protocol_list) {
		if (*pt == p) {
			*pt = p->next;
			lws_free(p);

			return 0;
		}
	} lws_end_foreach_llp(pt, next);

	return 1;
}


LWS_VISIBLE LWS_EXTERN int
lws_timed_callback_vh_protocol(struct lws_vhost *vh,
			       const struct lws_protocols *prot, int reason,
			       int secs)
{
	struct lws_timed_vh_protocol *p = (struct lws_timed_vh_protocol *)
			lws_malloc(sizeof(*p), "timed_vh");

	if (!p)
		return 1;

	p->tsi_req = lws_pthread_self_to_tsi(vh->context);
	if (p->tsi_req < 0) /* not called from a service thread --> tsi 0 */
		p->tsi_req = 0;

	lws_context_lock(vh->context, __func__); /* context ----------------- */

	p->protocol = prot;
	p->reason = reason;
	p->time = lws_now_secs() + secs;

	lws_vhost_lock(vh); /* vhost ---------------------------------------- */
	p->next = vh->timed_vh_protocol_list;
	vh->timed_vh_protocol_list = p;
	lws_vhost_unlock(vh); /* -------------------------------------- vhost */

	lws_context_unlock(vh->context); /* ------------------------- context */

	return 0;
}
