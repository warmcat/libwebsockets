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
__lws_wsi_remove_from_sul(struct lws *wsi)
{
	//struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	//lwsl_notice("%s: wsi %p, to %p, hr %p\n", __func__, wsi,
	//		&wsi->sul_timeout.list, &wsi->sul_hrtimer.list);

	// lws_dll2_describe(&pt->pt_sul_owner, "pre-remove");
	lws_dll2_remove(&wsi->sul_timeout.list);
	lws_dll2_remove(&wsi->sul_hrtimer.list);
	// lws_dll2_describe(&pt->pt_sul_owner, "post-remove");
}

/*
 * hrtimer
 */

static void
lws_sul_hrtimer_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_hrtimer);

	if (wsi->protocol &&
	    wsi->protocol->callback(wsi, LWS_CALLBACK_TIMER,
				    wsi->user_space, NULL, 0))
		__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				     "hrtimer cb errored");
}

void
__lws_set_timer_usecs(struct lws *wsi, lws_usec_t us)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	wsi->sul_hrtimer.cb = lws_sul_hrtimer_cb;
	__lws_sul_insert(&pt->pt_sul_owner, &wsi->sul_hrtimer, us);
}

LWS_VISIBLE void
lws_set_timer_usecs(struct lws *wsi, lws_usec_t usecs)
{
	__lws_set_timer_usecs(wsi, usecs);
}

/*
 * wsi timeout
 */

static void
lws_sul_wsitimeout_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_timeout);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (wsi->pending_timeout != PENDING_TIMEOUT_USER_OK)
		lws_stats_bump(pt, LWSSTATS_C_TIMEOUTS, 1);

	/* no need to log normal idle keepalive timeout */
//		if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (wsi->pending_timeout != PENDING_TIMEOUT_USER_OK)
		lwsl_info("wsi %p: TIMEDOUT WAITING on %d "
			  "(did hdr %d, ah %p, wl %d)\n",
			  (void *)wsi, wsi->pending_timeout,
			  wsi->hdr_parsing_completed, wsi->http.ah,
			  pt->http.ah_wait_list_length);
#if defined(LWS_WITH_CGI)
	if (wsi->http.cgi)
		lwsl_notice("CGI timeout: %s\n", wsi->http.cgi->summary);
#endif
#else
	if (wsi->pending_timeout != PENDING_TIMEOUT_USER_OK)
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
#if !defined(LWS_NO_CLIENT)
	if (lwsi_state(wsi) == LRS_WAITING_SSL)
		lws_inform_client_conn_fail(wsi,
			(void *)"Timed out waiting SSL", 21);
#endif

	__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "timeout");
}

void
__lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	wsi->sul_timeout.cb = lws_sul_wsitimeout_cb;
	__lws_sul_insert(&pt->pt_sul_owner, &wsi->sul_timeout,
			 ((lws_usec_t)secs) * LWS_US_PER_SEC);

	lwsl_debug("%s: %p: %d secs, reason %d\n", __func__, wsi, secs, reason);

	wsi->pending_timeout = reason;
}

void
lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);
	lws_dll2_remove(&wsi->sul_timeout.list);
	lws_pt_unlock(pt);

	if (!secs)
		return;

	if (secs == LWS_TO_KILL_SYNC) {
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

	lws_pt_lock(pt, __func__);
	lws_dll2_remove(&wsi->sul_timeout.list);
	lws_pt_unlock(pt);

	if (!us)
		return;

	lws_pt_lock(pt, __func__);
	__lws_sul_insert(&pt->pt_sul_owner, &wsi->sul_timeout, us);

	lwsl_notice("%s: %p: %llu us, reason %d\n", __func__, wsi,
		   (unsigned long long)us, reason);

	wsi->pending_timeout = reason;
	lws_pt_unlock(pt);
}

/* requires context + vh lock */

int
__lws_timed_callback_remove(struct lws_vhost *vh, struct lws_timed_vh_protocol *p)
{
	lws_start_foreach_llp_safe(struct lws_timed_vh_protocol **, pt,
			      vh->timed_vh_protocol_list, next) {
		if (*pt == p) {
			*pt = p->next;
			lws_dll2_remove(&p->sul.list);
			lws_free(p);

			return 0;
		}
	} lws_end_foreach_llp_safe(pt);

	return 1;
}

void
lws_sul_timed_callback_vh_protocol_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_timed_vh_protocol *tvp = lws_container_of(sul,
					struct lws_timed_vh_protocol, sul);
	struct lws_context_per_thread *pt =
				&tvp->vhost->context->pt[tvp->tsi_req];

	pt->fake_wsi->context = tvp->vhost->context;

	pt->fake_wsi->vhost = tvp->vhost; /* not a real bound wsi */
	pt->fake_wsi->protocol = tvp->protocol;

	lwsl_debug("%s: timed cb: vh %s, protocol %s, reason %d\n", __func__,
		   tvp->vhost->name, tvp->protocol->name, tvp->reason);

	tvp->protocol->callback(pt->fake_wsi, tvp->reason, NULL, NULL, 0);

	__lws_timed_callback_remove(tvp->vhost, tvp);
}

LWS_VISIBLE LWS_EXTERN int
lws_timed_callback_vh_protocol_us(struct lws_vhost *vh,
				  const struct lws_protocols *prot, int reason,
				  lws_usec_t us)
{
	struct lws_timed_vh_protocol *p = (struct lws_timed_vh_protocol *)
			lws_malloc(sizeof(*p), "timed_vh");

	if (!p)
		return 1;

	memset(p, 0, sizeof(*p));

	p->tsi_req = lws_pthread_self_to_tsi(vh->context);
	if (p->tsi_req < 0) /* not called from a service thread --> tsi 0 */
		p->tsi_req = 0;

	lws_context_lock(vh->context, __func__); /* context ----------------- */

	p->protocol = prot;
	p->reason = reason;
	p->vhost = vh;

	p->sul.cb = lws_sul_timed_callback_vh_protocol_cb;
	/* list is always at the very top of the sul */
	__lws_sul_insert(&vh->context->pt[p->tsi_req].pt_sul_owner,
			 (lws_sorted_usec_list_t *)&p->sul.list, us);

	// lwsl_notice("%s: %s.%s %d\n", __func__, vh->name, prot->name, secs);

	lws_vhost_lock(vh); /* vhost ---------------------------------------- */
	p->next = vh->timed_vh_protocol_list;
	vh->timed_vh_protocol_list = p;
	lws_vhost_unlock(vh); /* -------------------------------------- vhost */

	lws_context_unlock(vh->context); /* ------------------------- context */

	return 0;
}

LWS_VISIBLE LWS_EXTERN int
lws_timed_callback_vh_protocol(struct lws_vhost *vh,
			       const struct lws_protocols *prot, int reason,
			       int secs)
{
	return lws_timed_callback_vh_protocol_us(vh, prot, reason,
					((lws_usec_t)secs) * LWS_US_PER_SEC);
}
