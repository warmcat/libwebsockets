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
	lws_dll2_remove(&wsi->sul_timeout.list);
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
__lws_set_timer_usecs(struct lws *wsi, lws_usec_t us)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	__lws_sul_insert(&pt->dll_hrtimer_owner, &wsi->sul_hrtimer, us);
}

LWS_VISIBLE void
lws_set_timer_usecs(struct lws *wsi, lws_usec_t usecs)
{
	__lws_set_timer_usecs(wsi, usecs);
}

static void
lws_hrtimer_sul_check_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_hrtimer);

	if (wsi->protocol &&
	    wsi->protocol->callback(wsi, LWS_CALLBACK_TIMER,
				    wsi->user_space, NULL, 0))
		__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				     "hrtimer cb errored");
}

/* return 0 if nothing pending, or the number of us before the next event */

lws_usec_t
__lws_hrtimer_service(struct lws_context_per_thread *pt, lws_usec_t t)
{
	return __lws_sul_check(&pt->dll_hrtimer_owner,
			       lws_hrtimer_sul_check_cb, t);
}

void
__lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	__lws_sul_insert(&pt->dll_timeout_owner, &wsi->sul_timeout,
			 ((lws_usec_t)secs) * LWS_US_PER_SEC);

	lwsl_debug("%s: %p: %d secs, reason %d\n", __func__, wsi, secs, reason);

	wsi->pending_timeout = reason;
}

void
lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!secs) {
		lws_remove_from_timeout_list(wsi);

		return;
	}

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

void
lws_set_timeout_us(struct lws *wsi, enum pending_timeout reason, lws_usec_t us)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!us) {
		lws_remove_from_timeout_list(wsi);

		return;
	}

	lws_pt_lock(pt, __func__);
	__lws_sul_insert(&pt->dll_timeout_owner, &wsi->sul_timeout, us);

	lwsl_debug("%s: %p: %llu us, reason %d\n", __func__, wsi,
		   (unsigned long long)us, reason);

	wsi->pending_timeout = reason;
	lws_pt_unlock(pt);
}

static void
lws_wsitimeout_sul_check_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_timeout);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_TIMEOUTS, 1);

	/* no need to log normal idle keepalive timeout */
//		if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		lwsl_info("wsi %p: TIMEDOUT WAITING on %d "
			  "(did hdr %d, ah %p, wl %d\n",
			  (void *)wsi, wsi->pending_timeout,
			  wsi->hdr_parsing_completed, wsi->http.ah,
			  pt->http.ah_wait_list_length);
#if defined(LWS_WITH_CGI)
	if (wsi->http.cgi)
		lwsl_notice("CGI timeout: %s\n", wsi->http.cgi->summary);
#endif
#else
	lwsl_info("wsi %p: TIMEDOUT WAITING on %d ", (void *)wsi,
		  wsi->pending_timeout);
#endif
	/* cgi timeout */
	if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
		/*
		 * Since he failed a timeout, he already had a chance to
		 * do something and was unable to... that includes
		 * situations like half closed connections.  So process
		 * this "failed timeout" close as a violent death and
		 * don't try to do protocol cleanup like flush partials.
		 */
		wsi->socket_is_permanently_unusable = 1;
	if (lwsi_state(wsi) == LRS_WAITING_SSL && wsi->protocol)
		wsi->protocol->callback(wsi,
			LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
			wsi->user_space,
			(void *)"Timed out waiting SSL", 21);

	__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "timeout");
}

/* return 0 if nothing pending, or the number of us before the next event */

lws_usec_t
__lws_wsitimeout_service(struct lws_context_per_thread *pt, lws_usec_t t)
{
	return __lws_sul_check(&pt->dll_timeout_owner,
			       lws_wsitimeout_sul_check_cb, t);
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
	p->time = (lws_now_usecs() / LWS_US_PER_SEC) + secs;

	// lwsl_notice("%s: %s.%s %d\n", __func__, vh->name, prot->name, secs);

	lws_vhost_lock(vh); /* vhost ---------------------------------------- */
	p->next = vh->timed_vh_protocol_list;
	vh->timed_vh_protocol_list = p;
	lws_vhost_unlock(vh); /* -------------------------------------- vhost */

	lws_context_unlock(vh->context); /* ------------------------- context */

	return 0;
}
