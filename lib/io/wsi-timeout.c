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
 * hrtimer
 */

static void
lws_sul_hrtimer_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_hrtimer);

	if (wsi->a.protocol &&
	    wsi->a.protocol->callback(wsi, LWS_CALLBACK_TIMER,
				    wsi->user_space, NULL, 0))
		__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				     "hrtimer cb errored");
}

void
__lws_set_timer_usecs(struct lws *wsi, lws_usec_t us)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	wsi->sul_hrtimer.cb = lws_sul_hrtimer_cb;
	__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &wsi->sul_hrtimer, us);
}

void
lws_set_timer_usecs(struct lws *wsi, lws_usec_t usecs)
{
	if ((int64_t)usecs == (int64_t)LWS_SET_TIMER_USEC_CANCEL)
		lws_sul_cancel(&wsi->sul_hrtimer);
	else
		__lws_set_timer_usecs(wsi, usecs);
}

/*
 * wsi timeout
 */

static void
lws_sul_wsitimeout_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_timeout);
	struct lws_context *cx = wsi->a.context;
	struct lws_context_per_thread *pt = &cx->pt[(int)wsi->tsi];

	/* no need to log normal idle keepalive timeout */
//		if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
	if (wsi->pending_timeout == PENDING_TIMEOUT_HTTP_RESPONSE)
		/*
		 * We started sending the response (response headers went out)
		 * but never completed it: under h2 / h3 no END_STREAM was sent
		 * on a HEADERS frame, or the response body was never finished.
		 * The usual cause is a headers-only response written without
		 * LWS_WRITE_H2_STREAM_END -- the stream then hangs open with no
		 * further write ever closing it.  Call out the reason explicitly
		 * since this is a user-code bug, not a network condition.
		 */
		lwsl_wsi_warn(wsi, "HTTP response started but never completed "
			      "(no END_STREAM); user code likely wrote a "
			      "headers-only response without "
			      "LWS_WRITE_H2_STREAM_END, protocol=%s, uri=\"%s\"",
			      wsi->a.protocol ? wsi->a.protocol->name : "none",
			      lws_wsi_request_uri(wsi) ?
			      lws_wsi_request_uri(wsi) : "");
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	else if (wsi->pending_timeout != PENDING_TIMEOUT_USER_OK)
		lwsl_wsi_info(wsi, "TIMEDOUT WAITING %d, dhdr %d, ah %p, wl %d",
				   wsi->pending_timeout,
				   lwsi_hdrs_pending(wsi), wsi->stream.ah,
				   pt->http.ah_wait_list_length);
#if defined(LWS_WITH_CGI)
	if (wsi->http.cgi)
		lwsl_wsi_notice(wsi, "CGI timeout: %s", wsi->http.cgi->summary);
#endif
#else
	if (wsi->pending_timeout != PENDING_TIMEOUT_USER_OK)
		lwsl_wsi_info(wsi, "TIMEDOUT WAITING on %d ",
				   wsi->pending_timeout);
#endif
	/* cgi timeout */
	if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE &&
	    wsi->pending_timeout != PENDING_TIMEOUT_CLIENT_CONN_IDLE)
		/*
		 * Since he failed a timeout, he already had a chance to
		 * do something and was unable to... that includes
		 * situations like half closed connections.  So process
		 * this "failed timeout" close as a violent death and
		 * don't try to do protocol cleanup like flush partials.
		 *
		 * The two idle timeouts are the exception: a keep-alive or
		 * kept-warm connection that nothing used is closed in good
		 * order, it did nothing wrong.
		 */
		lwsi_set_skt_unusable(wsi, 1);
#if defined(LWS_WITH_CLIENT)
	/*
	 * lwsi_transport() sees the phase under a close in progress, where
	 * the lwsi_state() read this replaced did not: a connection already
	 * closing is not told it failed to connect on top of that
	 */
	if (lwsi_transport(wsi) == LTS_WAITING_SSL &&
	    lwsi_close(wsi) == LCS_NONE)
		lws_inform_client_conn_fail(wsi,
			(void *)"Timed out waiting SSL", 21);
	if (lwsi_state(wsi) == LRS_WAITING_SERVER_REPLY)
		lws_inform_client_conn_fail(wsi,
			(void *)"Timed out waiting server reply", 30);
#endif

	lws_context_lock(cx, __func__);
	lws_pt_lock(pt, __func__);
	__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "timeout");
	lws_pt_unlock(pt);
	lws_context_unlock(cx);
}

void
__lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	if (reason == PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE && secs > 0) {
		if (wsi->immortal_substream_count > 0) {
			lwsl_wsi_info(wsi, "Refusing to set idle keepalive timeout because it has %d immortal substreams", wsi->immortal_substream_count);
			return;
		}
	}
	wsi->sul_timeout.cb = lws_sul_wsitimeout_cb;
	__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &wsi->sul_timeout,
			    ((lws_usec_t)secs) * LWS_US_PER_SEC);

	lwsl_wsi_debug(wsi, "%d secs, reason %d\n", secs, reason);

	wsi->pending_timeout = (char)reason;
}

void
lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	lws_context_lock(pt->context, __func__);
	lws_pt_lock(pt, __func__);
	lws_dll2_remove(&wsi->sul_timeout.list);
	lws_pt_unlock(pt);

	if (!secs)
		goto bail;

	if (secs == LWS_TO_KILL_SYNC) {
		lwsl_wsi_debug(wsi, "TO_KILL_SYNC");
		lws_context_unlock(pt->context);
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "to sync kill");
		return;
	}

	if (secs == LWS_TO_KILL_ASYNC)
		secs = 0;

	if (reason == PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE && secs > 0) {
		if (wsi->immortal_substream_count > 0) {
			lwsl_wsi_info(wsi, "Refusing to set idle keepalive timeout because it has %d immortal substreams", wsi->immortal_substream_count);
			lws_context_unlock(pt->context);
			return;
		}
	}
	if (secs && wsi->mux_stream_immortal)
		lwsl_wsi_err(wsi, "on immortal stream %d %d", reason, secs);

	lws_pt_lock(pt, __func__);
	__lws_set_timeout(wsi, reason, secs);
	lws_pt_unlock(pt);

bail:
	lws_context_unlock(pt->context);
}

void
lws_set_timeout_us(struct lws *wsi, enum pending_timeout reason, lws_usec_t us)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);
	lws_dll2_remove(&wsi->sul_timeout.list);
	lws_pt_unlock(pt);

	if (!us)
		return;

	lws_pt_lock(pt, __func__);
	/*
	 * Arm the callback like __lws_set_timeout() does... a wsi that never
	 * went through lws_set_timeout() still has a NULL cb here, and a sul
	 * on the pt list with a NULL cb stalls that pt's whole timer wheel
	 */
	wsi->sul_timeout.cb = lws_sul_wsitimeout_cb;
	__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &wsi->sul_timeout, us);

	lwsl_wsi_info(wsi, "%llu us, reason %d",
			     (unsigned long long)us, reason);

	wsi->pending_timeout = (char)reason;
	lws_pt_unlock(pt);
}



