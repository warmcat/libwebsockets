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

static const unsigned char lextable_h1[] = {
	#include "lextable.h"
};

#define FAIL_CHAR 0x08



static struct allocated_headers *
_lws_create_ah(struct lws_context_per_thread *pt, ah_data_idx_t data_size)
{
	struct allocated_headers *ah = lws_zalloc(sizeof(*ah), "ah struct");

	if (!ah)
		return NULL;

	ah->data = lws_malloc(data_size, "ah data");
	if (!ah->data) {
		lws_free(ah);

		return NULL;
	}
	lws_dll2_add_head(&ah->list, &pt->http.ah_owner);
	ah->data_length = data_size;

	lwsl_info("%s: created ah %p (size %d): pool length %u\n", __func__,
		    ah, (int)data_size,
		    (unsigned int)lws_dll2_count(&pt->http.ah_owner));

	return ah;
}

int
_lws_destroy_ah(struct lws_context_per_thread *pt, struct allocated_headers *ah)
{
	if (!lws_dll2_is_detached(&ah->list)) {
			lws_dll2_remove(&ah->list);
			lwsl_info("%s: freed ah %p : pool length %u\n",
				    __func__, ah,
				    (unsigned int)lws_dll2_count(&pt->http.ah_owner));
			/* Remove any dangling wsi references to the ah we are about to free */
			if (ah->wsi) {
				ah->wsi->stream.ah = NULL;
				ah->wsi = NULL;
			}
			if (ah->data)
				lws_free(ah->data);
			lws_free(ah);

			return 0;
	}

	return 1;
}

void
_lws_header_table_reset(struct allocated_headers *ah)
{
	/* init the ah to reflect no headers or data have appeared yet */
	memset(ah->frag_index, 0, sizeof(ah->frag_index));
	memset(ah->frags, 0, sizeof(ah->frags));
	ah->nfrag = 0;
	ah->rx_snap_pos = 0;
	ah->rx_snap_nfrag = 0;
	ah->rx_interims = 0;
	ah->leading_empty_lines = 0;
	ah->pos = 0;
	ah->http_response = 0;
	ah->parser_state = WSI_TOKEN_NAME_PART;
	ah->lextable_pos = 0;
	/*
	 * nor URI decode state: a request that ended partway through a %XX
	 * or a /../ must not make the ah's next user decode its URI from
	 * there
	 */
	ah->ues = URIES_IDLE;
	ah->ups = URIPS_IDLE;
	ah->esc_stash = 0;
	ah->post_literal_equal = 0;
	/* no stale limit from the ah's last user for h2 / h3 :path */
	ah->current_token_limit = 0;
	ah->unk_pos = 0;
#if defined(LWS_WITH_CUSTOM_HEADERS)
	ah->unk_value_pos = 0;
	ah->unk_ll_head = 0;
	ah->unk_ll_tail = 0;
	ah->rx_snap_unk_ll_head = 0;
	ah->rx_snap_unk_ll_tail = 0;
#endif
}

// doesn't scrub the ah rxbuffer by default, parent must do if needed

int
__lws_header_table_reset(struct lws *wsi, int autoservice)
{
	struct allocated_headers *ah = wsi->stream.ah;
	struct lws_context_per_thread *pt;
	int gone = 0;

	/* if we have the idea we're resetting 'our' ah, must be bound to one */
	assert(ah);
	/* ah also concurs with ownership */
	assert(ah->wsi == wsi);

	_lws_header_table_reset(ah);

	/* while we hold the ah, keep a timeout on the wsi */
	__lws_set_timeout(wsi, PENDING_TIMEOUT_HOLDING_AH,
			  wsi->a.vhost->timeout_secs_ah_idle);

	ah->assigned = lws_wsi_now_wall(wsi);

	if (lws_buflist_next_segment_len(&wsi->buflist, NULL) && autoservice) {
		lwsl_debug("%s: service on readbuf ah\n", __func__);

		pt = &wsi->a.context->pt[(int)wsi->tsi];

		/*
		 * Unlike a normal connect, we have the headers already
		 * (or the first part of them anyway).
		 *
		 * We are usually here from the previous owner's detach.  If
		 * the recipient's pipelined request is served synchronously,
		 * its completion detaches and hands the ah to the next
		 * waiter, and we would recurse from here once per waiter,
		 * with the pt lock held and as deep as the wait list: past
		 * the first level, leave him to the forced-service pass that
		 * runs at the top of the next event loop turn for any wsi
		 * holding buffered rx, and make sure that turn comes.
		 */
		if (pt->http.ah_autoservice_depth) {
			lwsl_info("%s: deferring nested service\n", __func__);
			lws_io_wake(wsi);

			return 0;
		}

		lwsl_info("%s: calling service\n", __func__);
		pt->http.ah_autoservice_depth++;
		gone = lws_io_service_now(wsi) > 0;
		pt->http.ah_autoservice_depth--;
	}

	return gone;
}

void
lws_header_table_reset(struct lws *wsi, int autoservice)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);

	__lws_header_table_reset(wsi, autoservice);

	lws_pt_unlock(pt);
}

static void
_lws_header_ensure_we_are_on_waiting_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	struct lws **pwsi = &pt->http.ah_wait_list;

	while (*pwsi) {
		if (*pwsi == wsi)
			return;
		pwsi = &(*pwsi)->http.ah_wait_list;
	}

	lwsl_info("%s: wsi: %s\n", __func__, lws_wsi_tag(wsi));
	wsi->http.ah_wait_list = pt->http.ah_wait_list;
	pt->http.ah_wait_list = wsi;
	pt->http.ah_wait_list_length++;

	/* we cannot accept input then */

	__lws_io_want_read(wsi, 0);
}

static int
__lws_remove_from_ah_waiting_list(struct lws *wsi)
{
        struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	struct lws **pwsi =&pt->http.ah_wait_list;

	while (*pwsi) {
		if (*pwsi == wsi) {
			lwsl_info("%s: wsi %s\n", __func__, lws_wsi_tag(wsi));
			/* point prev guy to our next */
			*pwsi = wsi->http.ah_wait_list;
			/* we shouldn't point anywhere now */
			wsi->http.ah_wait_list = NULL;
			pt->http.ah_wait_list_length--;

			return 1;
		}
		pwsi = &(*pwsi)->http.ah_wait_list;
	}

	return 0;
}

lws_ah_attach_result_t LWS_WARN_UNUSED_RESULT
lws_header_table_attach(struct lws *wsi, int autoservice)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n;

#if defined(LWS_ROLE_MQTT) && defined(LWS_WITH_CLIENT)
	if (lwsi_role_mqtt(wsi))
		goto connect_via_info2;
#endif

	lwsl_info("%s: %s: ah %p (tsi %d, count = %d) in\n", __func__,
		  lws_wsi_tag(wsi), (void *)wsi->stream.ah, wsi->tsi,
		  pt->http.ah_count_in_use);

	if (!lwsi_role_http(wsi)) {
		/*
		 * A caller asking for an ah on a non-http role is a bug on
		 * its side, but the input that got it there can be remote
		 * (C-016 was exactly that), so refuse rather than abort.
		 */
		lwsl_err("%s: bad role %s\n", __func__, wsi->role_ops->name);
		return LWS_AH_ATTACH_FAIL;
	}

	lws_pt_lock(pt, __func__);

	/* if we are already bound to one, just clear it down */
	if (wsi->stream.ah) {
		lwsl_info("%s: cleardown\n", __func__);
		goto reset;
	}

	n = pt->http.ah_count_in_use == (int)context->max_http_header_pool;
#if defined(LWS_WITH_PEER_LIMITS)
	if (!n)
		n = lws_peer_confirm_ah_attach_ok(context, wsi->peer);
#endif
	if (n) {
		/*
		 * Pool is either all busy, or we don't want to give this
		 * particular guy an ah right now...
		 *
		 * Make sure we are on the waiting list, and return that we
		 * weren't able to provide the ah
		 */
		_lws_header_ensure_we_are_on_waiting_list(wsi);

		goto bail;
	}

	__lws_remove_from_ah_waiting_list(wsi);

	wsi->stream.ah = _lws_create_ah(pt, context->max_http_header_data);
	if (!wsi->stream.ah) { /* we could not create an ah */
		_lws_header_ensure_we_are_on_waiting_list(wsi);

		goto bail;
	}

	wsi->stream.ah->in_use = 1;
	wsi->stream.ah->wsi = wsi; /* mark our owner */
	pt->http.ah_count_in_use++;

#if defined(LWS_WITH_PEER_LIMITS) && (defined(LWS_ROLE_H1) || \
    defined(LWS_ROLE_H2))
	lws_context_lock(context, "ah attach"); /* <========================= */
	if (wsi->peer) {
		wsi->peer->http.count_ah++;
		wsi->peer->http.total_ah++;
	}
	lws_context_unlock(context); /* ====================================> */
#endif

	__lws_io_want_read(wsi, 1);

	lwsl_info("%s: did attach wsi %s: ah %p: count %d (on exit)\n", __func__,
		  lws_wsi_tag(wsi), (void *)wsi->stream.ah, pt->http.ah_count_in_use);

reset:
	/*
	 * __lws_header_table_reset() with autoservice set services the wsi's
	 * fd inline; that can complete his transaction, close him and free
	 * him before we get control back.  There is then nothing left of the
	 * wsi to ask about it, so take an identity for him now that we can
	 * check afterwards without dereferencing him: his fd.  The context's
	 * fd -> wsi lookup owns that mapping and clears it on close, so if
	 * the fd no longer maps to this same wsi, our guy went away.
	 *
	 * (The pointer comparison below never dereferences wsi.)
	 */

	if (__lws_header_table_reset(wsi, autoservice)) {
		lws_pt_unlock(pt);

		lwsl_info("%s: wsi closed inside the reset\n", __func__);

		return LWS_AH_ATTACH_WSI_GONE;
	}

	lws_pt_unlock(pt);

#if defined(LWS_WITH_CLIENT)
#if defined(LWS_ROLE_MQTT)
connect_via_info2:
#endif
	if (lwsi_role_client(wsi) && lwsi_state(wsi) == LRS_UNCONNECTED)
		if (!lws_client_transport_start(wsi))
			/*
			 * Our client connect has failed; by that api's
			 * contract the wsi has been closed and freed.
			 */
			return LWS_AH_ATTACH_WSI_GONE;
#endif

	return LWS_AH_ATTACH_OK;

bail:
	/* both paths here left him on the ah wait list */

	lws_pt_unlock(pt);

	return LWS_AH_ATTACH_WAITING;
}

int __lws_header_table_detach(struct lws *wsi, int autoservice)
{
	struct lws_context *context = wsi->a.context;
	struct allocated_headers *ah = wsi->stream.ah;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws **pwsi, **pwsi_eligible;
	time_t now;

	__lws_remove_from_ah_waiting_list(wsi);

	if (!ah)
		return 0;
	lwsl_info("%s: %s: ah %p (tsi=%d, count = %d)\n", __func__,
		  lws_wsi_tag(wsi), (void *)ah, wsi->tsi,
		  pt->http.ah_count_in_use);

	/* we did have an ah attached */
	now = lws_wsi_now_wall(wsi);
	if (ah->assigned && now - ah->assigned > 3) {
		/*
		 * we're detaching the ah, but it was held an
		 * unreasonably long time
		 */
		lwsl_debug("%s: %s: ah held %ds, role/state 0x%lx 0x%x,"
			    "\n", __func__, lws_wsi_tag(wsi),
			    (int)(now - ah->assigned),
			    (unsigned long)lwsi_role(wsi), lwsi_state(wsi));
	}

	ah->assigned = 0;

	/* if we think we're detaching one, there should be one in use */
	assert(pt->http.ah_count_in_use > 0);
	/* and this specific one should have been in use */
	assert(ah->in_use);
	memset(&wsi->stream.ah, 0, sizeof(wsi->stream.ah));

#if defined(LWS_WITH_PEER_LIMITS)
	if (ah->wsi)
		lws_peer_track_ah_detach(context, wsi->peer);
#endif
	ah->wsi = NULL; /* no owner */
	wsi->stream.ah = NULL;

	/*
	 * PENDING_TIMEOUT_HOLDING_AH exists only to bound how long this wsi
	 * may sit on an ah; the attach and the reset arm it.  We just gave the
	 * ah back, so leaving it armed would later close the connection for a
	 * reason that stopped applying.
	 */
	if (wsi->pending_timeout == PENDING_TIMEOUT_HOLDING_AH) {
		/* by hand: __lws_set_timeout() has no "no timeout" form */
		lws_dll2_remove(&wsi->sul_timeout.list);
		wsi->pending_timeout = NO_PENDING_TIMEOUT;
	}

	pwsi = &pt->http.ah_wait_list;

	/* oh there is nobody on the waiting list... leave the ah unattached */
	if (!*pwsi)
		goto nobody_usable_waiting;

	/*
	 * at least one wsi on the same tsi is waiting, give it to oldest guy
	 * who is allowed to take it (if any)
	 */
	lwsl_info("%s: pt wait list %s\n", __func__, lws_wsi_tag(*pwsi));
	wsi = NULL;
	pwsi_eligible = NULL;

	while (*pwsi) {
#if defined(LWS_WITH_PEER_LIMITS)
		/* are we willing to give this guy an ah? */
		if (!lws_peer_confirm_ah_attach_ok(context, (*pwsi)->peer))
#endif
		{
			wsi = *pwsi;
			pwsi_eligible = pwsi;
		}

		pwsi = &(*pwsi)->http.ah_wait_list;
	}

	if (!wsi) /* everybody waiting already has too many ah... */
		goto nobody_usable_waiting;

	lwsl_info("%s: transferring ah to last eligible wsi in wait list "
		  "%s (wsistate 0x%lx)\n", __func__, lws_wsi_tag(wsi),
		  (unsigned long)wsi->wsistate);

	wsi->stream.ah = ah;
	ah->wsi = wsi; /* new owner */

	/*
	 * Complete the wait list bookkeeping *before* anything below can
	 * reenter the event loop.
	 *
	 * __lws_header_table_reset() with autoservice set calls
	 * lws_service_fd_tsi() on the recipient, which can close and free it
	 * (and detach its ah, unlinking it from the wait list itself).  If we
	 * still had the list cursor and the length count outstanding at that
	 * point, we would then write through a stale pwsi_eligible (truncating
	 * the list, orphaning every waiter behind him), decrement the length a
	 * second time, and touch the freed wsi.
	 */

	/* point prev guy to next guy in list instead */
	*pwsi_eligible = wsi->http.ah_wait_list;
	/* the guy who got one is out of the list */
	wsi->http.ah_wait_list = NULL;
	pt->http.ah_wait_list_length--;

	assert(!!pt->http.ah_wait_list_length ==
			!!(lws_intptr_t)pt->http.ah_wait_list);

#if defined(LWS_WITH_PEER_LIMITS) && (defined(LWS_ROLE_H1) || \
    defined(LWS_ROLE_H2))
	lws_context_lock(context, "ah detach"); /* <========================= */
	if (wsi->peer) {
		wsi->peer->http.count_ah++;
		wsi->peer->http.total_ah++;
	}
	lws_context_unlock(context); /* ====================================> */
#endif

	/*
	 * he has been stuck waiting for an ah, but now his wait is over, let
	 * him progress (a client acquires the ah before it has a socket: IO
	 * has nothing to arm for him yet)
	 */
	lwsl_info("%s: Enabling %s POLLIN\n", __func__, lws_wsi_tag(wsi));
	__lws_io_want_read(wsi, 1);

#if defined(LWS_WITH_CLIENT)
	if (lwsi_role_client(wsi) && lwsi_state(wsi) == LRS_UNCONNECTED) {
		int cr = 0;

		/*
		 * An unconnected client has no fd in the fds table and so no
		 * pending rx to autoservice; reset without it, so nothing
		 * reentrant can run before we hand him to the connect.
		 */
		__lws_header_table_reset(wsi, 0);

		/*
		 * The connect must not run under the pt lock... drop it around
		 * the call and take it again, so that on return the caller's
		 * lock ownership is exactly what it was on entry.  Leaving it
		 * dropped took lws_mutex_refcount's depth negative and let the
		 * outer holder (eg, lws_sul_http_ah_lifecheck()) walk the ah
		 * pool and the wait list believing it still held the lock.
		 */
		lws_pt_unlock(pt);

		if (!lws_client_transport_start(wsi))
			/* our client connect has failed, the wsi
			 * has been closed
			 */
			cr = -1;

		lws_pt_lock(pt, __func__);

		return cr;
	}
#endif

	__lws_header_table_reset(wsi, autoservice);

	/*
	 * The reset above may have serviced, closed and freed the recipient:
	 * wsi must not be touched again here.
	 */

	lwsl_info("%s: ah %p (tsi=%d, count = %d)\n", __func__, (void *)ah,
		  pt->tid, pt->http.ah_count_in_use);

	return 0;

bail:
	lwsl_info("%s: %s: ah %p (tsi=%d, count = %d)\n", __func__,
		  lws_wsi_tag(wsi), (void *)ah, pt->tid, pt->http.ah_count_in_use);

	return 0;

nobody_usable_waiting:
	lwsl_info("%s: nobody usable waiting\n", __func__);
	_lws_destroy_ah(pt, ah);
	pt->http.ah_count_in_use--;

	goto bail;
}

int lws_header_table_detach(struct lws *wsi, int autoservice)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n;

	lws_pt_lock(pt, __func__);
	n = __lws_header_table_detach(wsi, autoservice);
	lws_pt_unlock(pt);

	return n;
}

int
lws_hdr_fragment_length(struct lws *wsi, enum lws_token_indexes h, int frag_idx)
{
	int n;

	if (!wsi->stream.ah)
		return 0;

	n = wsi->stream.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		if (!frag_idx)
			return wsi->stream.ah->frags[n].len;
		n = lws_ah_frag_next(wsi->stream.ah, n);
	} while (frag_idx-- && n);

	return 0;
}

int
lws_hdr_extant(struct lws *wsi, enum lws_token_indexes h)
{
	struct allocated_headers *ah = wsi->stream.ah;
	int n;

	if (!ah)
		return 0;

	n = ah->frag_index[h];
	if (!n)
		return 0;

	return !!(ah->frags[n].flags & 2);
}

int lws_hdr_total_length(struct lws *wsi, enum lws_token_indexes h)
{
	struct allocated_headers *ah = wsi->stream.ah;
	size_t len = 0;
	int n;

	if (!ah)
		return 0;

	n = ah->frag_index[h];
	if (!n)
		return 0;
	do {
		/*
		 * Each fragment is stored in ah->data with a terminator after
		 * it, so the fragments and the separators we add between them
		 * can't total more than ah->data holds.  A chain that claims
		 * more is corrupt, and is not a header we can report.
		 */
		if (ah->frags[n].len > ah->data_length - len)
			return 0;
		len += ah->frags[n].len;
		n = lws_ah_frag_next(ah, n);

		if (n) {
			if (len >= ah->data_length)
				return 0;
			len++;
		}

	} while (n);

	return (int)len;
}

int lws_hdr_copy_fragment(struct lws *wsi, char *dst, int len,
				      enum lws_token_indexes h, int frag_idx)
{
	int n = 0;
	int f;

	if (!wsi->stream.ah)
		return -1;

	f = wsi->stream.ah->frag_index[h];

	if (!f)
		return -1;

	while (n < frag_idx) {
		f = lws_ah_frag_next(wsi->stream.ah, f);
		if (!f)
			return -1;
		n++;
	}

	if (wsi->stream.ah->frags[f].len >= len)
		return -2;

	memcpy(dst, wsi->stream.ah->data + wsi->stream.ah->frags[f].offset,
	       wsi->stream.ah->frags[f].len);
	dst[wsi->stream.ah->frags[f].len] = '\0';

	return wsi->stream.ah->frags[f].len;
}

int lws_hdr_copy(struct lws *wsi, char *dst, int len,
			     enum lws_token_indexes h)
{
	int toklen = lws_hdr_total_length(wsi, h), n, next, comma;

	*dst = '\0';
	if (!toklen)
		return 0;

	if (toklen >= len)
		return -1;

	if (!wsi->stream.ah)
		return -1;

	n = wsi->stream.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		/* the same walk as lws_hdr_total_length(), so the same length */
		next = lws_ah_frag_next(wsi->stream.ah, n);
		comma = next ? 1 : 0;

/*		if (h == WSI_TOKEN_HTTP_URI_ARGS)
			lwsl_notice("%s: WSI_TOKEN_HTTP_URI_ARGS '%.*s'\n",
				    __func__, (int)wsi->stream.ah->frags[n].len,
				    &wsi->stream.ah->data[
				                wsi->stream.ah->frags[n].offset]);
*/
		if (wsi->stream.ah->frags[n].len + comma >= len) {
			lwsl_wsi_notice(wsi, "blowout len");
			return -1;
		}
		strncpy(dst, &wsi->stream.ah->data[wsi->stream.ah->frags[n].offset],
		        wsi->stream.ah->frags[n].len);
		dst += wsi->stream.ah->frags[n].len;
		len -= wsi->stream.ah->frags[n].len;
		n = next;

		/*
		 * Note if you change this logic, take care about updating len
		 * and make sure lws_hdr_total_length() gives the same resulting
		 * length
		 */

		if (comma) {
			if (h == WSI_TOKEN_HTTP_COOKIE ||
			    h == WSI_TOKEN_HTTP_SET_COOKIE)
				*dst++ = ';';
			else
				if (h == WSI_TOKEN_HTTP_URI_ARGS)
					*dst++ = '&';
				else
					*dst++ = ',';
			len--;
		}
				
	} while (n);
	*dst = '\0';

	// if (h == WSI_TOKEN_HTTP_URI_ARGS)
	//	lwsl_err("%s: WSI_TOKEN_HTTP_URI_ARGS toklen %d\n", __func__, (int)toklen);

	return toklen;
}

#if defined(LWS_WITH_CUSTOM_HEADERS)
int
lws_hdr_custom_length(struct lws *wsi, const char *name, int nlen)
{
	ah_data_idx_t ll;

	if (!wsi->stream.ah)
		return -1;

	ll = wsi->stream.ah->unk_ll_head;
	while (ll) {
		if (ll + UHO_NAME >= wsi->stream.ah->data_length)
			return -1;
		if (nlen == lws_ser_ru16be(
			(uint8_t *)&wsi->stream.ah->data[ll + UHO_NLEN]) &&
		    !strncmp(name, &wsi->stream.ah->data[ll + UHO_NAME], (unsigned int)nlen))
			return lws_ser_ru16be(
				(uint8_t *)&wsi->stream.ah->data[ll + UHO_VLEN]);

		ll = lws_ser_ru32be((uint8_t *)&wsi->stream.ah->data[ll + UHO_LL]);
	}

	return -1;
}

int
lws_hdr_custom_copy(struct lws *wsi, char *dst, int len, const char *name,
		    int nlen)
{
	ah_data_idx_t ll;
	int n;

	if (!wsi->stream.ah)
		return -1;

	*dst = '\0';

	ll = wsi->stream.ah->unk_ll_head;
	while (ll) {
		if (ll + UHO_NAME >= wsi->stream.ah->data_length)
			return -1;
		if (nlen == lws_ser_ru16be(
			(uint8_t *)&wsi->stream.ah->data[ll + UHO_NLEN]) &&
		    !strncmp(name, &wsi->stream.ah->data[ll + UHO_NAME], (unsigned int)nlen)) {
			n = lws_ser_ru16be(
				(uint8_t *)&wsi->stream.ah->data[ll + UHO_VLEN]);
			if (n + 1 > len)
				return -1;
			strncpy(dst, &wsi->stream.ah->data[ll + UHO_NAME + (unsigned int)nlen], (unsigned int)n);
			dst[n] = '\0';

			return n;
		}
		ll = lws_ser_ru32be((uint8_t *)&wsi->stream.ah->data[ll + UHO_LL]);
	}

	return -1;
}

int
lws_hdr_custom_name_foreach(struct lws *wsi, lws_hdr_custom_fe_cb_t cb,
			    void *custom)
{
	ah_data_idx_t ll;

	if (!wsi->stream.ah)
		return -1;

	ll = wsi->stream.ah->unk_ll_head;

	while (ll) {
		if (ll + UHO_NAME >= wsi->stream.ah->data_length)
			return -1;

		cb(&wsi->stream.ah->data[ll + UHO_NAME],
		   lws_ser_ru16be((uint8_t *)&wsi->stream.ah->data[ll + UHO_NLEN]),
		   custom);

		ll = lws_ser_ru32be((uint8_t *)&wsi->stream.ah->data[ll + UHO_LL]);
	}

	return 0;
}
#endif

char *lws_hdr_simple_ptr(struct lws *wsi, enum lws_token_indexes h)
{
	int n;

	if (!wsi->stream.ah)
		return NULL;

	n = wsi->stream.ah->frag_index[h];
	if (!n)
		return NULL;

	return wsi->stream.ah->data + wsi->stream.ah->frags[n].offset;
}

int
lws_hdr_alias(struct lws *wsi, enum lws_token_indexes dst,
	      enum lws_token_indexes src)
{
	struct allocated_headers *ah = wsi->stream.ah;
	int s;

	if (!ah || ah->frag_index[dst])
		return -1;

	s = ah->frag_index[src];
	if (!s)
		return 0;

	/*
	 * Only src's first fragment: a token that legitimately repeats is not
	 * one worth aliasing, and the new fragment ends dst's chain, so
	 * anything later chained onto dst leaves src alone
	 */

	if (ah->nfrag + 1 >= (int)LWS_ARRAY_SIZE(ah->frags)) {
		lwsl_wsi_warn(wsi, "no hdr frag left to alias %d", (int)dst);
		return -1;
	}

	ah->nfrag++;
	ah->frags[ah->nfrag].offset = ah->frags[s].offset;
	ah->frags[ah->nfrag].len = ah->frags[s].len;
	ah->frags[ah->nfrag].nfrag = 0;
	ah->frags[ah->nfrag].flags = 2;
	ah->frag_index[dst] = ah->nfrag;

	return 0;
}

static int LWS_WARN_UNUSED_RESULT
lws_pos_in_bounds(struct lws *wsi)
{
	if (!wsi->stream.ah)
		return -1;

	if (wsi->stream.ah->pos <
	    (unsigned int)wsi->a.context->max_http_header_data)
		return 0;

	if ((int)wsi->stream.ah->pos >= (int)wsi->a.context->max_http_header_data - 1) {
		/* the peer's doing: the request is refused for it */
		lwsl_wsi_info(wsi, "Ran out of header data space");
		return 1;
	}

	/*
	 * with these tests everywhere, it should never be able to exceed
	 * the limit, only meet it
	 */
	lwsl_err("%s: pos %ld, limit %ld\n", __func__,
		 (unsigned long)wsi->stream.ah->pos,
		 (unsigned long)wsi->a.context->max_http_header_data);
	assert(0);

	return 1;
}

int LWS_WARN_UNUSED_RESULT
lws_hdr_simple_create(struct lws *wsi, enum lws_token_indexes h, const char *s)
{
	if (!*s) {
		/*
		 * If we get an empty string, then remove any entry for the
		 * header
		 */
		wsi->stream.ah->frag_index[h] = 0;

		return 0;
	}

	/* check before moving nfrag on: never leave it naming no slot */
	if (wsi->stream.ah->nfrag + 1 >= (int)LWS_ARRAY_SIZE(wsi->stream.ah->frags)) {
		lwsl_warn("More hdr frags than we can deal with, dropping\n");
		return -1;
	}
	wsi->stream.ah->nfrag++;

	if (!wsi->stream.ah->frag_index[h]) {
		wsi->stream.ah->frag_index[h] = wsi->stream.ah->nfrag;
	} else {
		int n = wsi->stream.ah->frag_index[h], nx;

		while ((nx = lws_ah_frag_next(wsi->stream.ah, n)))
			n = nx;
		wsi->stream.ah->frags[n].nfrag = wsi->stream.ah->nfrag;
	}

	wsi->stream.ah->frags[wsi->stream.ah->nfrag].offset = wsi->stream.ah->pos;
	wsi->stream.ah->frags[wsi->stream.ah->nfrag].len = 0;
	wsi->stream.ah->frags[wsi->stream.ah->nfrag].nfrag = 0;
	/*
	 * we had reason to set it: lws_hdr_extant() reads this, and h3 stores
	 * every header but :path through here, so without it nothing h3
	 * received was extant... or a stale flag from the ah's last user said
	 * it was
	 */
	wsi->stream.ah->frags[wsi->stream.ah->nfrag].flags = 2;

	do {
		if (lws_pos_in_bounds(wsi))
			return -1;

		wsi->stream.ah->data[wsi->stream.ah->pos++] = *s;
		if (*s)
			wsi->stream.ah->frags[wsi->stream.ah->nfrag].len++;
	} while (*s++);

	return 0;
}

/*
 * Why header parsing failed.  On our own client connections the peer is one
 * we chose, so that's worth a notice; on the server side the internet sends
 * garbage all day, so keep those at info as they always were.
 */
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
#define lwsl_parse_fail(_w, ...) \
	lwsl_wsi(_w, lwsi_role_client(_w) ? LLL_NOTICE : LLL_INFO, __VA_ARGS__)
#else
#define lwsl_parse_fail(_w, ...) do {} while (0)
#endif

/*
 * Store one byte of the current header, or its terminating NUL.  Returns 0,
 * or -1 if the header will not fit.
 *
 * A value longer than its token limit fails the whole request, the same as
 * one that does not fit in the ah at all.  It used to be cut at the limit
 * and the request carried on with it, so the app acted on a different URI,
 * Host, cookie or credential than the peer sent; and the rest of an over-
 * long URI, including the HTTP version, was skipped as if it was not there.
 */
static int LWS_WARN_UNUSED_RESULT
issue_char(struct lws *wsi, unsigned char c)
{
	struct allocated_headers *ah = wsi->stream.ah;

	if (lws_pos_in_bounds(wsi))
		return -1;

	/* the value can have up to the limit, then its NUL */
	if (c && ah->current_token_limit &&
	    ah->frags[ah->nfrag].len >= ah->current_token_limit) {
		lwsl_parse_fail(wsi, "header %li exceeds limit %ld",
				(long)ah->parser_state,
				(long)ah->current_token_limit);
		return -1;
	}

	ah->data[ah->pos++] = (char)c;
	ah->frags[ah->nfrag].len++;

	return 0;
}

int
lws_parse_urldecode(struct lws *wsi, uint8_t *_c)
{
	struct allocated_headers *ah = wsi->stream.ah;
	unsigned int enc = 0;
	uint8_t c = *_c;

	// lwsl_notice("ah->ups %d\n", ah->ups);

	/*
	 * PRIORITY 1
	 * special URI processing... convert %xx
	 */
	switch (ah->ues) {
	case URIES_IDLE:
		if (c == '%') {
			ah->ues = URIES_SEEN_PERCENT;
			goto swallow;
		}
		break;
	case URIES_SEEN_PERCENT:
		if (char_to_hex((char)c) < 0)
			/* illegal post-% char */
			goto forbid;

		ah->esc_stash = (char)c;
		ah->ues = URIES_SEEN_PERCENT_H1;
		goto swallow;

	case URIES_SEEN_PERCENT_H1:
		if (char_to_hex((char)c) < 0)
			/* illegal post-% char */
			goto forbid;

		*_c = (uint8_t)(unsigned int)((char_to_hex(ah->esc_stash) << 4) |
				char_to_hex((char)c));
		c = *_c;
		enc = 1;
		ah->ues = URIES_IDLE;
		break;
	}

	/*
	 * PRIORITY 2
	 * special URI processing...
	 *  convert /.. or /... or /../ etc to /
	 *  convert /./ to /
	 *  convert // or /// etc to /
	 *  leave /.dir or whatever alone
	 */

	/*
	 * Post-decode byte policing: any C0 control byte or DEL is forbidden
	 * in the request URI, whether it arrived raw or via %XX decoding.
	 *
	 * Decoded CR/LF used to terminate the urlarg value here and silently
	 * skip the rest of the request line, while other control bytes passed
	 * into the urlarg value raw, for apps to interpolate into response
	 * headers (the F-018 class); now the whole request is refused (403 on
	 * h1, connection error on h2/h3 :path).
	 *
	 * NUL used to be allowed inside urlargs ("retrieval with explicit
	 * length"), but consumers overwhelmingly treat urlarg values as C
	 * strings, so that contract was unusable in practice and is withdrawn.
	 * Spaces (from %20 or '+') and bytes >= 0x80 (UTF-8) are unaffected.
	 */
	if (c < 0x20 || c == 0x7f) {
		lwsl_parse_fail(wsi, "refusing control byte 0x%02X in uri", c);
		return LPUR_FORBID;
	}

	switch (ah->ups) {
	case URIPS_IDLE:

		/*
		 * Genuine urlarg delimiter... but only once a '?' has moved us
		 * into WSI_TOKEN_HTTP_URI_ARGS, the same guard the '?' and '/'
		 * tests below use.
		 *
		 * Before that we are still in the path, where '&' and ';' are
		 * ordinary path bytes.  Splitting there appended a second
		 * fragment to the *method URI* token, breaking the "the method
		 * URI can only be in 1 fragment" invariant asserted by the
		 * /../ backup loops and relied on by every (uri_ptr, uri_len)
		 * consumer: lws_hdr_total_length() then exceeded
		 * strlen(lws_hdr_simple_ptr()), so length-honouring consumers
		 * read past the token's NUL, while string-honouring consumers
		 * (mount matching, the access log) silently truncated the path
		 * at the first '&' or ';' and served a different resource than
		 * anything in front of us had seen.
		 */
		if ((c == '&' || c == ';') && !enc &&
		    ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS]) {
			if (issue_char(wsi, '\0') < 0)
				return -1;
			/* don't account for it */
			wsi->stream.ah->frags[wsi->stream.ah->nfrag].len--;
			/*
			 * link to next fragment... if there is one, and room
			 * for it: check before linking to it or moving nfrag
			 * on to it, so a failure leaves the chain as it was
			 */
			if (ah->nfrag + 1 >= (int)LWS_ARRAY_SIZE(ah->frags) ||
			    (unsigned int)ah->pos >=
					wsi->a.context->max_http_header_data)
				goto excessive;
			ah->frags[ah->nfrag].nfrag = (uint8_t)(ah->nfrag + 1);
			ah->nfrag++;
			/*
			 * Start the next fragment on the byte directly after
			 * the safety NUL issue_char() just wrote.
			 *
			 * An extra ++ here left one never-written byte inside
			 * the extent lws_hdr_total_length() reports for the
			 * token (which sums the fragments plus one separator
			 * byte each), ie, a byte of stale ah->data from an
			 * earlier request on an earlier connection; and it
			 * could take ah->pos one past max_http_header_data,
			 * unlike the identical '?' site below.
			 */
			ah->post_literal_equal = 0;
			ah->frags[ah->nfrag].offset = ah->pos;
			ah->frags[ah->nfrag].len = 0;
			ah->frags[ah->nfrag].nfrag = 0;
			goto swallow;
		}
		/* uriencoded = in the name part, disallow */
		if (c == '=' && enc &&
		    ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] &&
		    !ah->post_literal_equal) {
			c = '_';
			*_c =c;
		}

		/* after the real =, we don't care how many = */
		if (c == '=' && !enc)
			ah->post_literal_equal = 1;

		/*
		 * + to space, but only in the query: it is form encoding's
		 * space, in the path it is just a +
		 */
		if (c == '+' && !enc && ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS]) {
			c = ' ';
			*_c = c;
		}
		/* issue the first / always */
		if (c == '/' && !ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS])
			ah->ups = URIPS_SEEN_SLASH;
		break;
	case URIPS_SEEN_SLASH:
		/* swallow subsequent slashes */
		if (c == '/')
			goto swallow;
		/* track and swallow the first . after / */
		if (c == '.') {
			ah->ups = URIPS_SEEN_SLASH_DOT;
			goto swallow;
		}
		ah->ups = URIPS_IDLE;
		break;
	case URIPS_SEEN_SLASH_DOT:
		/* swallow second . */
		if (c == '.') {
			ah->ups = URIPS_SEEN_SLASH_DOT_DOT;
			goto swallow;
		}
		/* change /./ to / */
		if (c == '/') {
			ah->ups = URIPS_SEEN_SLASH;
			goto swallow;
		}
		/*
		 * /.? is the path ending in /. the same as /.[End of URI],
		 * so drop the . and let the ? start the args below
		 */
		if (c == '?' && !enc) {
			ah->ups = URIPS_SEEN_SLASH;
			break;
		}
		/* it was like /.dir ... regurgitate the . */
		ah->ups = URIPS_IDLE;
		if (issue_char(wsi, '.') < 0)
			return -1;
		break;

	case URIPS_SEEN_SLASH_DOT_DOT:

		/* /../ or /..[End of URI] --> backup to last / */
		if (c == '/' || c == '?') {
			/*
			 * back up one dir level if possible
			 * safe against header fragmentation because
			 * the method URI can only be in 1 fragment
			 */
			if (ah->frags[ah->nfrag].len > 2) {
				ah->pos--;
				ah->frags[ah->nfrag].len--;
				do {
					ah->pos--;
					ah->frags[ah->nfrag].len--;
				} while (ah->frags[ah->nfrag].len > 1 &&
					 ah->data[ah->pos] != '/');
			}
			ah->ups = URIPS_SEEN_SLASH;
			/*
			 * The / we backed up to is still there to stand for
			 * a / in c, but a ? must go on to start the args
			 * below: swallowing it made the args part of the path
			 */
			if (ah->frags[ah->nfrag].len > 1 || c == '?')
				break;
			goto swallow;
		}

		/*  /..[^/] ... regurgitate and allow */

		if (issue_char(wsi, '.') < 0)
			return -1;
		if (issue_char(wsi, '.') < 0)
			return -1;
		ah->ups = URIPS_IDLE;
		break;
	}

	if (c == '?' && !enc &&
	    !ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS]) { /* start of URI args */
		if (ah->ues != URIES_IDLE)
			goto forbid;

		/*
		 * The path can't be empty: on h1 the request target must
		 * start with it ("GET ?a" is no origin-form), on h2 / h3
		 * :path must be one
		 */
		if (!ah->frags[ah->nfrag].len)
			goto forbid;

		/* seal off uri header */
		if (issue_char(wsi, '\0') < 0)
			return -1;

		/* don't account for it */
		wsi->stream.ah->frags[wsi->stream.ah->nfrag].len--;

		/*
		 * move to using WSI_TOKEN_HTTP_URI_ARGS, if there's a slot and
		 * room for it
		 */
		if (ah->nfrag + 1 >= (int)LWS_ARRAY_SIZE(ah->frags) ||
		    (unsigned int)ah->pos + 1 >=
				wsi->a.context->max_http_header_data)
			goto excessive;
		ah->nfrag++;

		ah->frags[ah->nfrag].offset = ++ah->pos;
		ah->frags[ah->nfrag].len = 0;
		ah->frags[ah->nfrag].nfrag = 0;

		ah->post_literal_equal = 0;
		ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] = ah->nfrag;
		ah->ups = URIPS_IDLE;
		goto swallow;
	}

	return LPUR_CONTINUE;

swallow:
	return LPUR_SWALLOW;

forbid:
	return LPUR_FORBID;

excessive:
	return LPUR_EXCESSIVE;
}

/*
 * Log what the parser choked on: the peer, where the parser was, and the
 * bytes around the failure.  consumed is how many bytes of buf lws_parse()
 * ate before failing, so buf[consumed - 1] is the byte it refused.  Same
 * role-keyed level as lwsl_parse_fail().
 *
 * Callers do this for LPR_FAIL; the LPR_REFUSED paths do it themselves
 * before the 403 it issues on the server side overwrites the request in
 * pt->serv_buf.
 */
void
lws_parse_fail_diag(struct lws *wsi, const unsigned char *buf, int consumed,
		    int len)
{
	int level = lwsi_role_client(wsi) ? LLL_NOTICE : LLL_INFO;
	const char *tok = NULL;
	char peer[72];
	int s, e, state = -1;

	peer[0] = '\0';
#if !defined(LWS_PLAT_OPTEE)
	lws_io_peer_address(wsi, peer, sizeof(peer));
#endif

	if (consumed < 1)
		consumed = 1;
	if (consumed > len)
		consumed = len;

	/* up to 48 bytes leading up to the bad byte, and 16 after it */
	s = consumed - 48;
	if (s < 0)
		s = 0;
	e = consumed + 16;
	if (e > len)
		e = len;

	/* a real token index names the header we were collecting */
	if (wsi->stream.ah) {
		state = wsi->stream.ah->parser_state;
		tok = (const char *)lws_token_to_string((enum lws_token_indexes)state);
	}

	lwsl_wsi(wsi, level, "peer %s: parser state %d (%s), failed at byte "
			     "%d of %d (0x%02X), ah->pos %d", peer, state,
		 tok ? tok : "-", consumed - 1, len, buf[consumed - 1],
		 wsi->stream.ah ? (int)wsi->stream.ah->pos : -1);
	lwsl_hexdump_wsi(wsi, level, buf + s, (size_t)(e - s));
}

static const unsigned char methods[] = {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_POST_URI,
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
	WSI_TOKEN_OPTIONS_URI,
	WSI_TOKEN_PUT_URI,
	WSI_TOKEN_PATCH_URI,
	WSI_TOKEN_DELETE_URI,
#endif
	WSI_TOKEN_CONNECT,
	WSI_TOKEN_HEAD_URI,
};

/*
 * RFC 9112 2.3: HTTP-version = "HTTP" "/" DIGIT "." DIGIT, case-sensitive.
 * Returns 0 for HTTP/1.x, which we speak (a minor version past 1 as 1.1,
 * RFC 9110 2.5), HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED for any other
 * major version, and HTTP_STATUS_BAD_REQUEST for anything that is not a
 * version at all.
 */
static unsigned int
lws_h1_version_refusal(const char *v, size_t len)
{
	if (len != 8 || strncmp(v, "HTTP/", 5) || v[6] != '.' ||
	    v[5] < '0' || v[5] > '9' || v[7] < '0' || v[7] > '9')
		return HTTP_STATUS_BAD_REQUEST;

	if (v[5] != '1')
		return HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED;

	return 0;
}

/*
 * An h1 server is strict about the request head's line ends: CRLF only, a
 * bare CR or bare LF refuses the request.  RFC 9112 2.2 lets a recipient
 * take a bare LF as a line end, but whatever is in front of us may not, and
 * then sees what follows it as part of the line where we see another header
 * line, eg a Content-Length: a request smuggling desync.  A client stays
 * tolerant of the servers it talks to.
 */

static int
lws_h1_srv_strict(struct lws *wsi)
{
	return lwsi_role_server(wsi) && !wsi->mux_substream;
}

/*
 * Whether the head has had its first line's method token, ie, on a server,
 * whether we are past the request line and on the header lines
 */

static int
lws_h1_method_seen(const struct allocated_headers *ah)
{
	unsigned int m;

	for (m = 0; m < LWS_ARRAY_SIZE(methods); m++)
		if (ah->frag_index[methods[m]])
			return 1;

	return 0;
}

/*
 * A byte of an h1 request header's name that lws didn't recognize as a
 * header it knows (those only match valid names, see
 * lws_h1_token_usable()).  RFC 9112 5.1 / RFC 9110 5.1: a field name is a
 * token, so no controls, no SP / HT, nothing non-ASCII: whitespace between
 * the name and the colon is a request smuggling vector, as whoever is in
 * front of us may see a different name.  The name has already been
 * lowercased.
 *
 * The request line's method arrives in the name state too, and "get " is a
 * token with a space in it: this is only for a server's header names, after
 * the method.
 */

static int
lws_h1_srv_bad_name_char(struct lws *wsi, unsigned char c)
{
	if (wsi->mux_substream || !lwsi_role_server(wsi) || c == ':' ||
	    lws_http_field_name_char_valid(c, 0))
		return 0;

	return lws_h1_method_seen(wsi->stream.ah);
}

/*
 * An h1 server's request head that has not had its request line yet
 */

static int
lws_h1_srv_awaits_request_line(struct lws *wsi)
{
	if (wsi->mux_substream || !lwsi_role_server(wsi) || !lwsi_role_h1(wsi))
		return 0;

	return !lws_h1_method_seen(wsi->stream.ah);
}

/*
 * The h1 lextable is also hpack's and qpack's name table, and lws' own token
 * store.  So besides the h1 field names, which it matches through their ':'
 * ("host:"), and the tokens that start the first line of an h1 head ("get ",
 * "http/1.1 "), it knows names that are neither, and matches them with
 * nothing after them: the h2 / h3 pseudo-headers (":method"), "uri-args",
 * where lws keeps the request's urlargs, and the methods with no SP of their
 * own ("put").  On h1, "uri-args" on a header line added urlargs no request
 * line carried, and ":methodpost" set a :method different from the one the
 * request line routed on, both past the checks for header names.
 *
 * Nonzero if the lextable's token n can be taken where it was matched in an
 * h1 head: a field name, the empty line ending the head, or on a server a
 * method starting the request line, on a client the status line's version.
 */

static int
lws_h1_token_usable(struct lws *wsi, unsigned int n)
{
	const char *s = (const char *)lws_token_to_string(
					(enum lws_token_indexes)n);
	size_t l = s ? strlen(s) : 0;
	unsigned int m;

	if (n == WSI_TOKEN_CHALLENGE || (l && s[l - 1] == ':'))
		return 1;

	if (!lwsi_role_server(wsi))
		return n == WSI_TOKEN_HTTP || n == WSI_TOKEN_HTTP1_0;

	if (lws_h1_method_seen(wsi->stream.ah))
		return 0;

	for (m = 0; m < LWS_ARRAY_SIZE(methods); m++)
		if (n == methods[m])
			return 1;

	return 0;
}

/*
 * Nonzero if the lextable's token n is spelled only with bytes a field name
 * may have: then as a name on an h1 header line, it's just a name lws doesn't
 * know ("uri-args", "put").  The pseudo-headers' ':' and the SP after a
 * method can't be in one.
 */

static int
lws_h1_token_spelling_is_name(unsigned int n)
{
	const char *s = (const char *)lws_token_to_string(
					(enum lws_token_indexes)n);

	if (!s || !*s)
		return 0;

	while (*s)
		if (!lws_http_field_name_char_valid((unsigned char)*s++, 0))
			return 0;

	return 1;
}

/*
 * RFC 9112 2.2: a server ignores at least one empty line before a request
 * line (a client may send a CRLF after a POST body).  We ignore up to this
 * many; past them there is no request coming.
 */
#define LWS_H1_MAX_LEADING_EMPTY_LINES 8

/*
 * The ':' ending the name of an h1 header lws doesn't know
 */

static void
lws_h1_unknown_name_ended(struct lws *wsi)
{
	struct allocated_headers *ah = wsi->stream.ah;
#if defined(LWS_WITH_CUSTOM_HEADERS)
#if defined(_DEBUG)
	char dotstar[64];
	int uhlen;
#endif

	/* register us in the unknown hdr ll */

	if (!ah->unk_ll_head)
		ah->unk_ll_head = ah->unk_pos;

	if (ah->unk_ll_tail)
		lws_ser_wu32be((uint8_t *)&ah->data[ah->unk_ll_tail + UHO_LL],
			       ah->unk_pos);

	ah->unk_ll_tail = ah->unk_pos;

#if defined(_DEBUG)
	uhlen = (int)(ah->pos - (ah->unk_pos + UHO_NAME));
	lws_strnncpy(dotstar, &ah->data[ah->unk_pos + UHO_NAME], uhlen,
		     sizeof(dotstar));
	lwsl_debug("%s: unk header %d '%s'\n", __func__, uhlen, dotstar);
#endif

	/* set the unknown header name part length */

	lws_ser_wu16be((uint8_t *)&ah->data[ah->unk_pos],
		       (uint16_t)((ah->pos - ah->unk_pos) - UHO_NAME));

	ah->unk_value_pos = ah->pos;

	/* collect whatever's coming for its value until the next CRLF */
	ah->parser_state = WSI_TOKEN_UNKNOWN_VALUE_PART;
#else
	/* we don't keep headers we don't know: drop the name, skip the value */
	ah->pos = ah->unk_pos;
	ah->unk_pos = 0;
	ah->parser_state = WSI_TOKEN_SKIPPING;
#endif
}

/*
 * possible returns:, -1 fail, 0 ok or 2, transition to raw
 */

lws_parser_return_t LWS_WARN_UNUSED_RESULT
lws_parse(struct lws *wsi, unsigned char *buf, int *len)
{
	struct allocated_headers *ah = wsi->stream.ah;
	struct lws_context *context = wsi->a.context;
	unsigned int n, m, refusal = HTTP_STATUS_BAD_REQUEST;
	const unsigned char *start = buf;
	int r, pos, total = *len;
	unsigned char c;

	assert(wsi->stream.ah);

	do {
		(*len)--;
		c = *buf++;

		if (c == '\0') {
			lwsl_parse_fail(wsi, "rejecting NUL in header (state %d)",
					ah->parser_state);
			return LPR_FAIL;
		}

		switch (ah->parser_state) {
#if defined(LWS_WITH_CUSTOM_HEADERS)
		case WSI_TOKEN_UNKNOWN_VALUE_PART:

			/*
			 * The value ends at the CR, whose LF is then checked
			 * for like any other header's.  A CR used to be dropped
			 * wherever it came, joining what was either side of a
			 * bare CR into the value.
			 */
			if (c == '\n' && lws_h1_srv_strict(wsi))
				goto bare_lf;
			if (c == '\r' || c == '\n') {
				lws_ser_wu16be((uint8_t *)&ah->data[ah->unk_pos + 2],
					       (uint16_t)(ah->pos - ah->unk_value_pos));
				ah->parser_state = c == '\r' ?
						WSI_TOKEN_SKIPPING_SAW_CR :
						WSI_TOKEN_NAME_PART;
				ah->unk_pos = 0;
				ah->lextable_pos = 0;
				break;
			}

			/* trim leading whitespace */
			if (ah->pos != ah->unk_value_pos ||
			    (c != ' ' && c != '\t')) {

				if (lws_pos_in_bounds(wsi))
					goto too_large;

				ah->data[ah->pos++] = (char)c;
			}
			pos = ah->lextable_pos;
			break;
#endif
		default:

			lwsl_parser("WSI_TOK_(%d) '%c'\n", ah->parser_state, c);

			/*
			 * Everything that is not a real header token index has
			 * its own case above (NAME_PART, SKIPPING,
			 * SKIPPING_SAW_CR, UNKNOWN_VALUE_PART and
			 * PARSING_COMPLETE are all >= WSI_TOKEN_COUNT), so
			 * arriving here means we are collecting the value of a
			 * header lws knows, and parser_state indexes
			 * frag_index[].
			 *
			 * h2's hpack decoder also parks 255 in parser_state as
			 * its "no lws token yet" sentinel, though, and that is
			 * not a token index at all: subscripting frag_index[]
			 * with it reads off the end of the ah allocation.  That
			 * is not reachable by itself -- hpack replaces the
			 * sentinel before it hands us any name byte -- but only
			 * so long as the ah it set it on is the ah we are
			 * called with, which is a property of the h2 frame
			 * sequencing rather than of anything here.  Don't take
			 * that on trust.
			 */

			if ((unsigned int)ah->parser_state >= WSI_TOKEN_COUNT) {
				lwsl_parse_fail(wsi, "bad parser state %d",
						ah->parser_state);
				return LPR_FAIL;
			}

			/* collect into malloc'd buffers */
			/* optional initial space swallow */
			if (!ah->frags[ah->frag_index[ah->parser_state]].len &&
			    c == ' ')
				break;

			for (m = 0; m < LWS_ARRAY_SIZE(methods); m++)
				if (ah->parser_state == methods[m])
					break;
			if (m == LWS_ARRAY_SIZE(methods))
				/* it was not any of the methods */
				goto check_eol;

			/*
			 * The request line ended in the request target, with
			 * no version: an HTTP/0.9 request, which we do not
			 * speak
			 */
			if (c == '\x0d' || c == '\x0a')
				goto bad_request_line;

			/* special URI processing... end at space */

			if (c == ' ') {
				/*
				 * enforce starting with /... but only while
				 * the current fragment is still the path.
				 * After a '?' it is the urlargs, and an empty
				 * query there ("/a?") must stay empty, not
				 * become a "/" urlarg.  A '?' can't start the
				 * path, lws_parse_urldecode() refuses that.
				 */
				if (!ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] &&
				    !ah->frags[ah->nfrag].len)
					if (issue_char(wsi, '/') < 0)
						goto too_large;

				if (ah->ups == URIPS_SEEN_SLASH_DOT_DOT) {
					/*
					 * back up one dir level if possible
					 * safe against header fragmentation
					 * because the method URI can only be
					 * in 1 fragment
					 */
					if (ah->frags[ah->nfrag].len > 2) {
						ah->pos--;
						ah->frags[ah->nfrag].len--;
						do {
							ah->pos--;
							ah->frags[ah->nfrag].len--;
						} while (ah->frags[ah->nfrag].len > 1 &&
							 ah->data[ah->pos] != '/');
					}
				}

				/* begin parsing HTTP version: */
				if (issue_char(wsi, '\0') < 0)
					goto too_large;
				/* don't account for it */
				wsi->stream.ah->frags[wsi->stream.ah->nfrag].len--;
				ah->parser_state = WSI_TOKEN_HTTP;
				goto start_fragment;
			}

			r = lws_parse_urldecode(wsi, &c);
			switch (r) {
			case LPUR_CONTINUE:
				break;
			case LPUR_SWALLOW:
				goto swallow;
			case LPUR_FORBID:
				goto forbid;
			case LPUR_EXCESSIVE:
				/*
				 * Out of fragments, or of room, for the next
				 * urlarg: lws_parse_urldecode() took neither
				 */
				lwsl_parse_fail(wsi, "uri args too many or too "
						     "large (state %d)",
						     ah->parser_state);
				goto too_large;
			default:
				lwsl_parse_fail(wsi, "urldecode failed (state %d)",
						ah->parser_state);
				goto too_large;
			}
check_eol:
			/* bail at EOL */
			if (ah->parser_state != WSI_TOKEN_CHALLENGE &&
			    (c == '\x0d' || c == '\x0a')) {
				if (ah->ues != URIES_IDLE)
					goto forbid;

				/*
				 * The end of a server's request line: the whole
				 * version is here to be checked, where once
				 * only two of its characters ever were
				 */
				if (ah->parser_state == WSI_TOKEN_HTTP &&
				    lwsi_role_server(wsi) &&
				    !wsi->mux_substream) {
					refusal = lws_h1_version_refusal(
						&ah->data[ah->frags[ah->nfrag].offset],
						ah->frags[ah->nfrag].len);
					if (refusal)
						goto bad_request_line;
				}

				if (c == '\x0a') {
					if (lws_h1_srv_strict(wsi))
						goto bare_lf;
					/* broken peer */
					ah->parser_state = WSI_TOKEN_NAME_PART;
					ah->unk_pos = 0;
					ah->lextable_pos = 0;
				} else
					ah->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;

				c = '\0';
				lwsl_parser("*\n");
			}

			if (issue_char(wsi, c) < 0)
				goto too_large;
			/*
			 * Explicit zeroes are legal in URI ARGS.  They can
			 * only exist as a safety terminator after the valid
			 * part of the token contents for other types.
			 */
			if (!c && ah->parser_state != WSI_TOKEN_HTTP_URI_ARGS)
				/* don't account for safety terminator */
				wsi->stream.ah->frags[wsi->stream.ah->nfrag].len--;

swallow:
			/* per-protocol end of headers management */

			if (ah->parser_state == WSI_TOKEN_CHALLENGE)
				goto set_parsing_complete;
			break;

			/* collecting and checking a name part */
		case WSI_TOKEN_NAME_PART:
			lwsl_parser("WSI_TOKEN_NAME_PART '%c' 0x%02X "
				    "(role=0x%lx) "
				    "wsi->lextable_pos=%d\n", c, c,
				    (unsigned long)lwsi_role(wsi),
				    ah->lextable_pos);

			if (!ah->unk_pos && c == '\x0a') {
				if (lws_h1_srv_strict(wsi))
					goto bare_lf;
				/* broken peer */
				goto set_parsing_complete;
			}

			/*
			 * An empty line where a request line should start,
			 * before anything else of the head: skipped, its LF
			 * checked as any other's, a few of them
			 */
			if (c == '\x0d' && !ah->lextable_pos && !ah->nfrag &&
			    lws_h1_srv_awaits_request_line(wsi)) {
				if (++ah->leading_empty_lines >
					    LWS_H1_MAX_LEADING_EMPTY_LINES)
					goto bad_request_line;
				ah->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
				break;
			}

			/*
			 * A field name is a token, so it isn't empty: no ':'
			 * starts one.  The lextable would take it as the
			 * start of an h2 / h3 pseudo-header, and what
			 * followed as the rest of a name lws doesn't know
			 */
			if (c == ':' && !ah->lextable_pos &&
			    lws_h1_srv_strict(wsi) && lws_h1_method_seen(ah))
				goto bad_name;

			if (c >= 'A' && c <= 'Z')
				c = (unsigned char)(c + 'a' - 'A');
			/*
			 * ...in case it's an unknown header, speculatively
			 * store it as the name comes in.  If we recognize it as
			 * a known header, we'll snip this.
			 */

			if (!wsi->mux_substream && !ah->unk_pos) {
				ah->unk_pos = ah->pos;

#if defined(LWS_WITH_CUSTOM_HEADERS)
				/*
				 * Prepare new unknown header linked-list entry
				 *
				 *  - 16-bit BE: name part length
				 *  - 16-bit BE: value part length
				 *  - 32-bit BE: data offset of next, or 0
				 */
				for (n = 0; n < 8; n++)
					if (!lws_pos_in_bounds(wsi))
						ah->data[ah->pos++] = 0;
#endif
			}

			/*
			 * For mux (h2) substreams the hpack decoder captures
			 * the header name itself (including building the
			 * unknown-header storage), so we must not also lay the
			 * name bytes down here and double-advance ah->pos.
			 */
			if (!wsi->mux_substream) {
				if (lws_pos_in_bounds(wsi))
					goto too_large;

				ah->data[ah->pos++] = (char)c;
			}
			pos = ah->lextable_pos;

			/*
			 * The rest of the name of a header we don't know: it
			 * ends at its ':'
			 */
			if (pos < 0 && !wsi->mux_substream) {
				if (lws_h1_srv_awaits_request_line(wsi)) {
					/*
					 * A first token we don't know: it
					 * ends at a SP if it was a method
					 */
					if (c == ' ') {
						refusal = HTTP_STATUS_NOT_IMPLEMENTED;
						goto bad_request_line;
					}
					if (c == ':' ||
					    !lws_http_field_name_char_valid(c, 0))
						goto bad_request_line;
					break;
				}
				if (lws_h1_srv_bad_name_char(wsi, c))
					goto bad_name;
				if (c == ':')
					lws_h1_unknown_name_ended(wsi);
				break;
			}
			if (pos < 0)
				break;

			while (1) {
				if (lextable_h1[pos] & (1 << 7)) {
					/* 1-byte, fail on mismatch */
					if ((lextable_h1[pos] & 0x7f) != c) {
nope:
						ah->lextable_pos = -1;
						break;
					}
					/* fall thru */
					pos++;
					if (lextable_h1[pos] == FAIL_CHAR)
						goto nope;

					ah->lextable_pos = (int16_t)pos;
					break;
				}

				if (lextable_h1[pos] == FAIL_CHAR)
					goto nope;

				/* b7 = 0, end or 3-byte */
				if (lextable_h1[pos] < FAIL_CHAR) {
					if (!wsi->mux_substream) {
						/*
						 * We hit a terminal marker, so
						 * we recognized this header...
						 * drop the speculative name
						 * part storage
						 */
						ah->pos = ah->unk_pos;
						ah->unk_pos = 0;
					}

					ah->lextable_pos = (int16_t)pos;
					break;
				}

				if (lextable_h1[pos] == c) { /* goto */
					ah->lextable_pos = (int16_t)(pos +
						(lextable_h1[pos + 1]) +
						(lextable_h1[pos + 2] << 8));
					break;
				}

				/* fall thru goto */
				pos += 3;
				/* continue */
			}

			/*
			 * If it's h1, server needs to be on the look out for
			 * unknown methods...
			 */
			if (ah->lextable_pos < 0 && lwsi_role_h1(wsi) &&
			    lwsi_role_server(wsi)) {
				/*
				 * this is not a header we know about... did
				 * we get a valid method (GET, POST etc)
				 * already, or is this the bogus method?
				 */
				if (lws_h1_method_seen(ah)) {
					/*
					 * We have the method, this is just an
					 * unknown header then
					 */
					if (wsi->mux_substream) {
						ah->parser_state = WSI_TOKEN_SKIPPING;
						break;
					}
					/*
					 * c is where the name stopped matching
					 * any we know: eg the SP of "host :",
					 * or the ':' of a name that is the
					 * start of one we know, "accept-lang:"
					 */
					if (lws_h1_srv_bad_name_char(wsi, c))
						goto bad_name;
					if (c == ':')
						lws_h1_unknown_name_ended(wsi);
					/* else we go on collecting the name */
					break;
				}
				/*
				 * ...it's an unknown http method from a client
				 * in fact, it cannot be valid http.
				 *
				 * Are we set up to transition to another role
				 * in these cases?
				 */
				if (lws_check_opt(wsi->a.vhost->options,
		    LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG)) {
					lwsl_notice("%s: http fail fallback\n",
						    __func__);
					 /* transition to other role */
					return LPR_DO_FALLBACK;
				}

				/*
				 * A method we don't implement, if the token
				 * ends at a SP (RFC 9110 9.1: 501), or no
				 * request line at all, if the head starts with
				 * a header we don't know.  Collect the rest of
				 * the token to see which.
				 */
				if (c == ' ') {
					refusal = HTTP_STATUS_NOT_IMPLEMENTED;
					goto bad_request_line;
				}
				if (c == ':' ||
				    !lws_http_field_name_char_valid(c, 0))
					goto bad_request_line;
				break;
			}
			if (ah->lextable_pos < 0) {
				/*
				 * It's not a header that lws knows about...
				 */
#if defined(LWS_WITH_CUSTOM_HEADERS)
				if (!wsi->mux_substream) {
					/* ...collect its name, to its ':' */
					if (c == ':')
						lws_h1_unknown_name_ended(wsi);
					break;
				}
#endif
				/*
				 * ...otherwise for a client, let him ignore
				 * unknown headers coming from the server
				 */
				ah->parser_state = WSI_TOKEN_SKIPPING;
				break;
			}

			if (lextable_h1[ah->lextable_pos] < FAIL_CHAR) {
				/* terminal state */

				n = ((unsigned int)lextable_h1[ah->lextable_pos] << 8) |
						lextable_h1[ah->lextable_pos + 1];

				lwsl_parser("known hdr %d\n", n);
				for (m = 0; m < LWS_ARRAY_SIZE(methods); m++)
					if (n == methods[m] &&
					    ah->frag_index[methods[m]]) {
						lwsl_parse_fail(wsi, "duplicated method");
						return LPR_FAIL;
					}

				if (!wsi->mux_substream &&
				    !lws_h1_token_usable(wsi, n)) {
					/*
					 * No h1 field name, nor where a first
					 * line's token may be.  A server's
					 * head must start with its request
					 * line...
					 */
					if (lws_h1_srv_awaits_request_line(wsi))
						goto bad_request_line;
					/*
					 * ...and a server refuses a name with
					 * a ':' or SP in it, as any other; a
					 * client ignores the line, and drops
					 * the name kept for it
					 */
					if (!lws_h1_token_spelling_is_name(n)) {
						if (lws_h1_srv_strict(wsi)) {
							lwsl_parse_fail(wsi,
								"'%s' is no h1 "
								"field name",
								(const char *)
								lws_token_to_string(
						(enum lws_token_indexes)n));
							return LPR_FAIL;
						}
						ah->pos = ah->unk_pos;
						ah->unk_pos = 0;
						ah->parser_state =
							WSI_TOKEN_SKIPPING;
						break;
					}
					/*
					 * Otherwise it's a name we don't know,
					 * kept from its first byte and going
					 * on to its ':'
					 */
					ah->lextable_pos = -1;
					break;
				}

				if (!wsi->mux_substream) {
					/*
					 * Whether we are collecting unknown names or not,
					 * if we matched an internal header we can dispense
					 * with the header name part we were keeping
					 */
					ah->pos = ah->unk_pos;
					ah->unk_pos = 0;
				}

#if defined(LWS_ROLE_WS)
				/*
				 * WSORIGIN is protocol equiv to ORIGIN,
				 * JWebSocket likes to send it, map to ORIGIN
				 */
				if (n == WSI_TOKEN_SWORIGIN)
					n = WSI_TOKEN_ORIGIN;
#endif

				ah->parser_state = (uint8_t)
							(WSI_TOKEN_GET_URI + n);
				ah->ups = URIPS_IDLE;

				if (context->token_limits)
					ah->current_token_limit = context->
						token_limits->token_limit[
							      ah->parser_state];
				else
					ah->current_token_limit =
						wsi->a.context->max_http_header_data;

				if (ah->parser_state == WSI_TOKEN_CHALLENGE)
					goto set_parsing_complete;

				goto start_fragment;
			}
			break;

start_fragment:
			/*
			 * Check before moving nfrag on: a caller that doesn't
			 * stop at our failure (hpack did) must not find nfrag
			 * naming a slot past the end of frags[]
			 */
			if (ah->nfrag + 1 >= (int)LWS_ARRAY_SIZE(ah->frags)) {
				lwsl_parse_fail(wsi, "more hdr frags than we can "
						     "deal with (state %d)",
						     ah->parser_state);
				goto too_large;
			}
			ah->nfrag++;

			ah->frags[ah->nfrag].offset = ah->pos;
			ah->frags[ah->nfrag].len = 0;
			ah->frags[ah->nfrag].nfrag = 0;
			ah->frags[ah->nfrag].flags = 2;

			n = ah->frag_index[ah->parser_state];
			if (!n) { /* first fragment */
				ah->frag_index[ah->parser_state] = ah->nfrag;
				ah->hdr_token_idx = ah->parser_state;
				break;
			}
			/* continuation */
			while ((r = lws_ah_frag_next(ah, (int)n)))
				n = (unsigned int)r;
			ah->frags[n].nfrag = ah->nfrag;

			if (issue_char(wsi, ' ') < 0)
				goto too_large;
			break;

			/* skipping arg part of a name we didn't recognize */
		case WSI_TOKEN_SKIPPING:
			lwsl_parser("WSI_TOKEN_SKIPPING '%c'\n", c);

			if (c == '\x0a') {
				if (lws_h1_srv_strict(wsi))
					goto bare_lf;
				/* broken peer */
				ah->parser_state = WSI_TOKEN_NAME_PART;
				ah->unk_pos = 0;
				ah->lextable_pos = 0;
			}

			if (c == '\x0d')
				ah->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			break;

		case WSI_TOKEN_SKIPPING_SAW_CR:
			lwsl_parser("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
			if (ah->ues != URIES_IDLE)
				goto forbid;
			if (c == '\x0a') {
				ah->parser_state = WSI_TOKEN_NAME_PART;
				ah->unk_pos = 0;
				ah->lextable_pos = 0;
				break;
			}
			/*
			 * A bare CR: RFC 9112 2.2 has a recipient treat the
			 * element as invalid (or the CR as SP).  Something in
			 * front of us may have taken it as a line end, and
			 * seen what follows it as another header that we'd
			 * skip, so a server refuses the request
			 */
			if (lws_h1_srv_strict(wsi)) {
				lwsl_parse_fail(wsi, "bare CR in request head");
				return LPR_FAIL;
			}
			ah->parser_state = WSI_TOKEN_SKIPPING;
			break;
			/* we're done, ignore anything else */

		case WSI_PARSING_COMPLETE:
			lwsl_parser("WSI_PARSING_COMPLETE '%c'\n", c);
			break;
		}

	} while (*len);

	return LPR_OK;

bad_name:
	lwsl_parse_fail(wsi, "invalid byte 0x%02X in header name", c);

	return LPR_FAIL;

bare_lf:
	lwsl_parse_fail(wsi, "bare LF in request head");

	return LPR_FAIL;

set_parsing_complete:
	if (ah->ues != URIES_IDLE)
		goto forbid;

	/*
	 * A server's h1 request head starts with its request line, and a
	 * head without one (headers alone, or an empty line) is no request
	 * we can act on
	 */
	if (lws_h1_srv_awaits_request_line(wsi))
		goto bad_request_line;

	ah->parser_state = WSI_PARSING_COMPLETE;

	return LPR_OK;

forbid:
	lwsl_parse_fail(wsi, "forbidding on uri sanitation (state %d, "
			     "ues %d, ups %d)", ah->parser_state, ah->ues,
			     ah->ups);
	lws_parse_fail_diag(wsi, start, lws_ptr_diff(buf, start), total);
#if defined(LWS_WITH_SERVER)
	lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
#endif

	return LPR_REFUSED;

bad_request_line:
	/*
	 * No request line, or one that is not method, target and an HTTP
	 * version: 400, or 505 for a version that is not 1.x (RFC 9112 3,
	 * RFC 9110 15.6.6), or 501 for a method we do not implement (RFC 9110
	 * 9.1)
	 */
	lwsl_parse_fail(wsi, "bad request line (state %d): %u",
			ah->parser_state, refusal);
#if defined(LWS_WITH_SERVER)
	if (lwsi_role_server(wsi) && !wsi->mux_substream) {
		lws_parse_fail_diag(wsi, start, lws_ptr_diff(buf, start), total);
		/* there is no version of the request's to answer in */
		wsi->stream.request_version = HTTP_VERSION_1_1;
		lws_return_http_status(wsi, refusal, NULL);

		return LPR_REFUSED;
	}
#endif

	return LPR_FAIL;

too_large:
	/*
	 * The request line, or a header, is longer than its token limit or
	 * than the ah can hold, or has more pieces than it can track.  A
	 * server says which (RFC 9110 15.5.15, RFC 6585 5), rather than just
	 * hanging up.
	 */
	lwsl_parse_fail(wsi, "request too large (state %d)", ah->parser_state);
#if defined(LWS_WITH_SERVER)
	/*
	 * Not on an h2 stream, whose name bytes hpack feeds us mid-block: it
	 * fails the stream itself on LPR_FAIL
	 */
	if (lwsi_role_server(wsi) && !wsi->mux_substream) {
		unsigned int code = HTTP_STATUS_REQ_HEADER_FIELDS_TOO_LARGE;

		for (m = 0; m < LWS_ARRAY_SIZE(methods); m++)
			if (ah->parser_state == methods[m])
				code = HTTP_STATUS_REQ_URI_TOO_LONG;

		/*
		 * We may not have got as far as the version on the request
		 * line: then answer as the highest we speak
		 */
		wsi->stream.request_version =
			lws_hdr_total_length(wsi, WSI_TOKEN_HTTP) ?
				lws_h1_request_version(wsi) : HTTP_VERSION_1_1;

		lws_parse_fail_diag(wsi, start, lws_ptr_diff(buf, start), total);
		lws_return_http_status(wsi, code,
				       code == HTTP_STATUS_REQ_URI_TOO_LONG ?
					"Oversized request URI" :
					"Oversized headers");

		return LPR_REFUSED;
	}
#endif

	/*
	 * A client fails the response, and hpack refuses the whole h2 request
	 * once its header block is done
	 */
	return LPR_TOO_LARGE;
}

enum http_version
lws_h1_request_version(struct lws *wsi)
{
	char v[12];

	/* HTTP/1.1, or a later HTTP/1.x we answer as 1.1 (RFC 9110 2.5) */
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP) > 7 &&
	    lws_hdr_copy(wsi, v, sizeof(v) - 1, WSI_TOKEN_HTTP) > 0 &&
	    v[5] == '1' && v[7] >= '1' && v[7] <= '9')
		return HTTP_VERSION_1_1;

	return HTTP_VERSION_1_0;
}

/*
 * RFC 9110 8.6 defines Content-Length as 1*DIGIT.  strtoull() is no good for
 * it: it skips leading whitespace, accepts a leading '+' or '-', and for '-'
 * returns the negation modulo 2^64, so eg "-18446744073709551615" arrives as
 * 1 and no "is it negative" test downstream can see it.  Parse it ourselves,
 * rejecting anything that is not digits (trailing spaces are tolerated, as
 * they always have been here) and refusing to wrap.
 *
 * Returns 0 and sets *result if the value is a valid Content-Length.
 */

int
lws_http_parse_content_length(const char *in, uint64_t *result)
{
	uint64_t v = 0, lim = (uint64_t)-1;

	if (*in < '0' || *in > '9')
		return 1;

	while (*in >= '0' && *in <= '9') {
		if (v > (lim - (uint64_t)(*in - '0')) / 10)
			return 1;

		v = (v * 10) + (uint64_t)(*in++ - '0');
	}

	while (*in == ' ')
		in++;

	if (*in)
		return 1;

	*result = v;

	return 0;
}

/*
 * Is the message's Transfer-Encoding exactly one "chunked" coding?
 *
 * Only a single instance of the header whose value is "chunked" (case-
 * insensitive, surrounding whitespace ignored) qualifies.  A list of codings
 * would need each of them applied in turn, which we do not do, and a second
 * instance of the header is a list however the sender split it.
 */

int
lws_http_te_is_chunked(struct lws *wsi)
{
	char te[32], *p = te, *e;

	if (lws_hdr_copy_fragment(wsi, te, sizeof(te) - 1,
				  WSI_TOKEN_HTTP_TRANSFER_ENCODING, 1) != -1)
		return 0;

	if (lws_hdr_copy(wsi, te, sizeof(te) - 1,
			 WSI_TOKEN_HTTP_TRANSFER_ENCODING) <= 0)
		return 0;

	while (*p == ' ' || *p == '\t')
		p++;
	e = p + strlen(p);
	while (e > p && (e[-1] == ' ' || e[-1] == '\t'))
		e--;

	return e - p == 7 && !strncasecmp(p, "chunked", 7);
}

static const char * const cookie_prefixes[] = { "", "__Host-", "__Secure-" };

/*
 * Core of the cookie getters' match action: copy the whole cookie value
 * starting at vs (bounded by pe, ie, the end of the header frag, or the ';'
 * starting the next cookie in it) into buf.
 *
 * Returns 0 if it fit (buf then holds the NUL-terminated value and *max_len
 * is set to the value length) or 2 if the value, with its terminating NUL,
 * needs more than *max_len bytes.  On a nonzero return, buf and *max_len are
 * untouched: partial values are never handed out, since callers use these to
 * resolve credentials.
 */
static int
cookie_value_copy(const char *vs, const char *pe, char *buf, size_t *max_len)
{
	const char *ve = vs;

	while (ve < pe && *ve != ';')
		ve++;

	if (lws_ptr_diff_size_t(ve, vs) + 1 > *max_len)
		return 2;

	*max_len = lws_ptr_diff_size_t(ve, vs);
	memcpy(buf, vs, *max_len);
	buf[*max_len] = '\0';

	return 0;
}

int
lws_http_cookie_get(struct lws *wsi, const char *name, char *buf,
		    size_t *max_len)
{
	size_t bl;
	char *p;
	int n, m;

	for (m = 0; m < (int)LWS_ARRAY_SIZE(cookie_prefixes); m++) {
		char nbuf[128];
		const char *use_name = name;

		if (m) {
			lws_snprintf(nbuf, sizeof(nbuf), "%s%s",
				     cookie_prefixes[m], name);
			use_name = nbuf;
		}

		bl = strlen(use_name);
		n = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);
		if ((unsigned int)n < bl + 1)
			continue;

		{
			int f = wsi->stream.ah->frag_index[WSI_TOKEN_HTTP_COOKIE];
			size_t fl;

			while (f) {
				p = wsi->stream.ah->data + wsi->stream.ah->frags[f].offset;
				fl = (size_t)wsi->stream.ah->frags[f].len;
				char *pe = p + fl;
				char *vp = p;

				while (vp < pe) {
					if ((size_t)(pe - vp) > bl &&
					    !memcmp(vp, use_name, bl) &&
					    vp[bl] == '=' &&
					    (vp == p || vp[-1] == ' ' ||
					     vp[-1] == ';'))
						return cookie_value_copy(
								vp + bl + 1,
								pe, buf, max_len);
					vp++;
				}
				f = lws_ah_frag_next(wsi->stream.ah, f);
			}
		}
	}

	return 1;
}

/*
 * Same cookie extraction as lws_http_cookie_get(), but returns the n-th
 * (0-based) occurrence of the named cookie rather than only the first.
 *
 * Browsers legitimately present multiple same-name cookies at once: a
 * host-only cookie and a Domain-scoped cookie for the same name can coexist
 * in one jar (eg auth.warmcat.com host-only auth_refresh_session alongside a
 * Domain=.warmcat.com one set by a different flow).  RFC 6265 orders
 * same-path cookies oldest-first, so first-match-only resolution can pick a
 * stale value while a live one sits behind it in the same header.  Callers
 * that resolve a credential from a cookie should iterate with n = 0, 1, ...
 * until this returns nonzero.
 *
 * Returns 0 and fills buf (NUL-terminated, *max_len set to the value length)
 * if the n-th occurrence exists and fits.  Returns nonzero if there is no such
 * occurrence (1) or the value, with its terminating NUL, is too large for buf
 * (2); in those cases buf and *max_len are untouched, so no partial value is
 * ever handed out.
 *
 * Unlike lws_http_cookie_get(), no __Host- / __Secure- prefix aliases are
 * tried: it resolves exactly the name asked for, so the occurrence ordering
 * is deterministic against the raw header.
 */
int
lws_http_cookie_get_nth(struct lws *wsi, const char *name, int n,
			char *buf, size_t *max)
{
	size_t bl = strlen(name);
	char *p;

	if (n < 0 || lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE) < (int)bl + 1)
		return 1;

	{
		int f = wsi->stream.ah->frag_index[WSI_TOKEN_HTTP_COOKIE];
		size_t fl;

		while (f) {
			p = wsi->stream.ah->data + wsi->stream.ah->frags[f].offset;
			fl = (size_t)wsi->stream.ah->frags[f].len;
			char *pe = p + fl;
			char *vp = p;

			while (vp < pe) {
				if ((size_t)(pe - vp) > bl &&
				    !memcmp(vp, name, bl) && vp[bl] == '=' &&
				    (vp == p || vp[-1] == ' ' || vp[-1] == ';') &&
				    !n--)
					return cookie_value_copy(
						   vp + bl + 1,
						   pe, buf, max);
				vp++;
			}
			f = lws_ah_frag_next(wsi->stream.ah, f);
		}
	}

	return 1;
}

int
lws_http_cookie_compose(char *buf, size_t len, const char *name,
			const char *value, const char *domain,
			unsigned long long max_age, const char *expires)
{
	/*
	 * Fixed attribute text lengths, kept adjacent to the format strings
	 * below so they cannot drift apart silently
	 */
	size_t need, o = 0;
	char ma[24]; /* u64 decimal: max 20 digits + NUL */
	int mal;

	if (!name || !value)
		return -1;

	mal = lws_snprintf(ma, sizeof(ma), "%llu", max_age);

	/* "name=value" + "; Path=/" */
	need = strlen(name) + 1 + strlen(value) + 8;
	if (domain && domain[0])
		need += 9 + strlen(domain);	/* "; Domain=" */
	if (expires)
		need += 10 + strlen(expires);	/* "; Expires=" */
	need += 10 + (size_t)mal;		/* "; Max-Age=" */
	need += 32;				/* "; HttpOnly; SameSite=Lax; Secure" */

	if (!buf)
		return need <= (size_t)0x7fffffff ? (int)need : -1;

	if (need + 1 > len) {
		if (len)
			buf[0] = '\0';
		return -1;
	}

	o = (size_t)lws_snprintf(buf, len, "%s=%s; Path=/", name, value);
	if (domain && domain[0])
		o += (size_t)lws_snprintf(buf + o, len - o,
					  "; Domain=%s", domain);
	if (expires)
		o += (size_t)lws_snprintf(buf + o, len - o,
					  "; Expires=%s", expires);
	o += (size_t)lws_snprintf(buf + o, len - o,
				  "; Max-Age=%s; HttpOnly; SameSite=Lax; "
				  "Secure", ma);

	/*
	 * The precheck above means the appends cannot truncate; this postcheck
	 * turns any drift between the size accounting and the format strings
	 * into a loud failure instead of a cookie with a chopped attribute
	 * tail.
	 */
	if (o != need || strlen(buf) != need) {
		if (len)
			buf[0] = '\0';
		return -1;
	}

	return (int)need;
}


#if defined(LWS_WITH_JOSE)

#define MAX_JWT_SIZE 1024

int
lws_jwt_get_http_cookie_validate_jwt(struct lws *wsi,
				     struct lws_jwt_sign_set_cookie *i,
				     char *out, size_t *out_len)
{
	char temp[MAX_JWT_SIZE * 2];
	size_t cml = *out_len;
	const char *cp;
	int n;

	/* first use out to hold the encoded JWT */

	n = lws_http_cookie_get(wsi, i->cookie_name, out, out_len);
	if (n) {
		lwsl_debug("%s: cookie %s %s\n", __func__, i->cookie_name,
			   n == 2 ? "too large for buffer" : "not provided");
		return 1;
	}

	/* decode the JWT into temp */

	if (lws_jwt_signed_validate(wsi->a.context, i->jwk, i->alg, out,
				    *out_len, temp, sizeof(temp), out, &cml)) {
		lwsl_info("%s: jwt validation failed\n", __func__);
		return 1;
	}

	/*
	 * Copy out the decoded JWT payload into out, overwriting the
	 * original encoded JWT taken from the cookie (that has long ago been
	 * translated into allocated buffers in the JOSE object)
	 */

	if (lws_jwt_token_sanity(out, cml, i->iss, i->aud, i->csrf_in,
				 i->sub, sizeof(i->sub),
				 &i->expiry_unix_time)) {
		lwsl_notice("%s: jwt sanity failed\n", __func__);
		return 1;
	}

	/*
	 * If he's interested in his private JSON part, point him to that in
	 * the args struct (it's pointing to the data in out
	 */

	cp = lws_json_simple_find(out, cml, "\"ext\":", &i->extra_json_len);
	if (cp)
		i->extra_json = cp;

	if (!cp)
		lwsl_info("%s: no ext JWT payload\n", __func__);

	return 0;
}

/*
 * Core of the cookie helpers: sign the JWT described by \p i and format just
 * the cookie value ("__Host-name=jwt;attrs") into val.  Returns the length of
 * the value written, or -1 on failure / it did not fit.
 */

static int
jwt_sign_cookie_value(struct lws *wsi,
		      const struct lws_jwt_sign_set_cookie *i,
		      char *val, size_t val_len)
{
	char plain[MAX_JWT_SIZE + 1], temp[MAX_JWT_SIZE * 2], csrf[17],
	     esub[(sizeof(i->sub) * 6) + 8];
	int n, used = (int)sizeof(i->sub) - 1;
	size_t pl = sizeof(plain);
	unsigned long long ull;

	/*
	 * The subject goes into the JWT as a JSON string, and may have come
	 * from a user, eg a username.  Unescaped, a '"' in it ended the string
	 * early and what followed became claims of its own, eg another "ext"
	 * that the validator would find first.  esub has room for every byte
	 * of sub to escape to 6: if the escaped copy still didn't reach sub's
	 * NUL, sub is unterminated, refuse it rather than sign part of it.
	 */

	lws_json_purify(esub, i->sub, (int)sizeof(esub), &used);
	if (i->sub[used]) {
		lwsl_err("%s: unterminated sub\n", __func__);

		return -1;
	}

	/*
	 * Create a 16-char random csrf token with the same lifetime as the JWT
	 */

	lws_hex_random(wsi->a.context, csrf, sizeof(csrf));
	ull = (unsigned long long)lws_wsi_now_wall(wsi);
	if (lws_jwt_sign_compact(wsi->a.context, i->jwk, i->alg, plain, &pl,
			         temp, sizeof(temp),
			         "{\"iss\":\"%s\",\"aud\":\"%s\","
			          "\"iat\":%llu,\"nbf\":%llu,\"exp\":%llu,"
			          "\"csrf\":\"%s\",\"sub\":\"%s\"%s%s%s}",
			         i->iss, i->aud, ull, ull - 60,
			         ull + i->expiry_unix_time,
			         csrf, esub,
			         i->extra_json ? ",\"ext\":{" : "",
			         i->extra_json ? i->extra_json : "",
			         i->extra_json ? "}" : "")) {
		lwsl_err("%s: failed to create JWT\n", __func__);

		return -1;
	}

	/*
	 * There's no point the browser holding on to a JWT beyond the JWT's
	 * expiry time, so set it to be the same.
	 */

	n = lws_snprintf(val, val_len, "__Host-%s=%s;"
			 "HttpOnly;"
			 "Secure;"
			 "SameSite=None;"
			 "Path=/;"
			 "Max-Age=%lu",
			 i->cookie_name, plain, i->expiry_unix_time);

	if ((size_t)n >= val_len)
		return -1;

	return n;
}

int
lws_jwt_sign_token_set_http_cookie(struct lws *wsi,
				   const struct lws_jwt_sign_set_cookie *i,
				   uint8_t **p, uint8_t *end)
{
	char temp[MAX_JWT_SIZE * 2];
	int n;

	n = jwt_sign_cookie_value(wsi, i, temp, sizeof(temp));
	if (n < 0)
		return 1;

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SET_COOKIE,
					 (uint8_t *)temp, n, p, end)) {
		lwsl_err("%s: failed to add JWT cookie header\n", __func__);
		return 1;
	}

	return 0;
}

int
lws_jwt_sign_token_set_cookie_ascii(struct lws *wsi,
				    const struct lws_jwt_sign_set_cookie *i,
				    char *buf, size_t len)
{
	int n;

	/*
	 * We need room for the header name, at least one char of cookie value
	 * and the CRLF + NUL appended after it; reject undersized buffers up
	 * front so the size arithmetic below cannot underflow
	 */

	if (len < sizeof("set-cookie: ") + 4)
		return 1;

	/*
	 * Format the cookie value after where the header name will go,
	 * reserving room for the CRLF + NUL that we append after it
	 */

	n = jwt_sign_cookie_value(wsi, i, buf + sizeof("set-cookie: ") - 1,
				  len - sizeof("set-cookie: ") - 3);
	if (n < 0)
		return 1;

	memcpy(buf, "set-cookie: ", sizeof("set-cookie: ") - 1);
	n += (int)(sizeof("set-cookie: ") - 1);
	buf[n++] = '\x0d';
	buf[n++] = '\x0a';
	buf[n] = '\0';

	return 0;
}
#endif

int
lws_http_remove_urlarg(struct lws *wsi, const char *name)
{
	int fi, pf = 0, sl = (int)strlen(name);
	struct allocated_headers *ah = wsi->stream.ah;

	if (!ah)
		return 1;

	fi = ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS];

	while (fi) {
		struct lws_fragments *f = &ah->frags[fi];
		if (f->len >= sl && !strncmp(&ah->data[f->offset], name, (size_t)sl)) {
			/* matches... remove this fragment from the chain */
			uint8_t nx = (uint8_t)lws_ah_frag_next(ah, fi);

			if (pf)
				ah->frags[pf].nfrag = nx;
			else
				ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] = nx;

			return 0;
		}
		pf = fi;
		fi = lws_ah_frag_next(ah, fi);
	}

	return 1;
}

/*
 * lws_header_table_rx_snapshot() - mark where a client ah's response begins
 *
 * Called when the client is about to start parsing the server's reply into
 * an ah that already holds its own request tokens.  Everything the parser
 * adds after this (fragments, data, unknown headers) belongs to the response
 * and can be discarded again with lws_header_table_rx_rewind().
 */

void
lws_header_table_rx_snapshot(struct lws *wsi)
{
	struct allocated_headers *ah = wsi->stream.ah;

	if (!ah)
		return;

	ah->rx_snap_pos = ah->pos;
	ah->rx_snap_nfrag = ah->nfrag;
	ah->rx_interims = 0;
#if defined(LWS_WITH_CUSTOM_HEADERS)
	ah->rx_snap_unk_ll_head = ah->unk_ll_head;
	ah->rx_snap_unk_ll_tail = ah->unk_ll_tail;
#endif
}

/*
 * lws_header_table_rx_rewind() - discard a parsed response from a client ah
 *
 * Drops every fragment and byte the parser added since the last
 * lws_header_table_rx_snapshot(), leaving the request tokens intact, and
 * readies the parser for another response.  Used to swallow a 1xx interim
 * response and go on waiting for the final one.
 */

void
lws_header_table_rx_rewind(struct lws *wsi)
{
	struct allocated_headers *ah = wsi->stream.ah;
	int n;

	if (!ah)
		return;

	/* fragments are numbered from 1 up: anything above the mark is ours */

	for (n = 0; n < WSI_TOKEN_COUNT; n++)
		if (ah->frag_index[n] > ah->rx_snap_nfrag)
			ah->frag_index[n] = 0;

	for (n = 1; n <= (int)ah->rx_snap_nfrag; n++)
		if (ah->frags[n].nfrag > ah->rx_snap_nfrag)
			ah->frags[n].nfrag = 0;

	if (ah->rx_snap_nfrag < LWS_ARRAY_SIZE(ah->frags) - 1)
		memset(&ah->frags[ah->rx_snap_nfrag + 1], 0,
		       sizeof(ah->frags[0]) * (LWS_ARRAY_SIZE(ah->frags) -
					       ah->rx_snap_nfrag - 1));

	ah->nfrag = ah->rx_snap_nfrag;
	ah->pos = ah->rx_snap_pos;
	ah->http_response = 0;
	ah->unk_pos = 0;
#if defined(LWS_WITH_CUSTOM_HEADERS)
	ah->unk_value_pos = 0;
	ah->unk_ll_head = ah->rx_snap_unk_ll_head;
	ah->unk_ll_tail = ah->rx_snap_unk_ll_tail;
	/* the restored tail's forward link still names a discarded entry */
	if (ah->unk_ll_tail)
		lws_ser_wu32be((uint8_t *)&ah->data[ah->unk_ll_tail + UHO_LL], 0);
#endif
	ah->parser_state = WSI_TOKEN_NAME_PART;
	ah->lextable_pos = 0;
	ah->ues = URIES_IDLE;
}

/*
 * lws_http_dechunk_framing() - consume Transfer-Encoding: chunked framing
 *
 * Runs the chunk framing state machine over *buf / *len, consuming only the
 * framing bytes (chunk-size lines, the CRLF after each chunk's payload, and
 * the last-chunk / trailer terminator) and advancing *buf / *len past them.
 *
 * A chunk's payload bytes are left in place for the caller to deliver: the
 * caller subtracts what it delivered from wsi->http.chunk_remaining and sets
 * wsi->http.chunk_parser to ELCP_POST_CR when that reaches zero, then calls
 * here again for the framing that follows.
 *
 * Before the first body byte, the caller sets chunk_parser to ELCP_HEX and
 * chunk_remaining and chunk_skip to 0.
 *
 * Chunk extensions (RFC 7230 4.1.1, ";name=value" after the chunk size) and
 * trailer fields (4.1.2, header lines between the last-chunk and the final
 * CRLF) are skipped: we do not act on either, but a peer is entitled to send
 * them.  What is skipped is bounded by LWS_HTTP_CHUNK_SKIP_MAX per body so a
 * peer cannot keep us busy with an endless extension.
 *
 * Returns
 *   -1  framing error, the connection cannot be resynchronized
 *    0  stopped: either *len is exhausted, or the next bytes are chunk
 *       payload (chunk_parser == ELCP_CONTENT, chunk_remaining is the count
 *       of payload bytes still to come in this chunk)
 *    1  the last-chunk and the trailer terminator were consumed: the body is
 *       complete
 */

int
lws_http_dechunk_framing(struct lws *wsi, unsigned char **buf, size_t *len)
{
	while (wsi->http.chunk_parser != ELCP_CONTENT && *len) {
		unsigned char c = **buf;
		int n;

		switch (wsi->http.chunk_parser) {
		case ELCP_HEX:
		case ELCP_HEX_MORE:
			n = char_to_hex((char)c);
			if (n >= 0) {
				if (wsi->http.chunk_remaining >
						(INT_MAX - 15) / 16) {
					lwsl_wsi_notice(wsi, "chunk size overflow");
					return -1;
				}
				wsi->http.chunk_remaining <<= 4;
				wsi->http.chunk_remaining |= n;
				wsi->http.chunk_parser = ELCP_HEX_MORE;
				break;
			}

			/* the chunk-size must have at least one hex digit */

			if (wsi->http.chunk_parser == ELCP_HEX) {
				lwsl_wsi_notice(wsi, "chunk size not hex");
				return -1;
			}

			if (c == '\x0d') {
				wsi->http.chunk_parser = ELCP_CR;
				break;
			}

			if (c != ';' && c != ' ' && c != '\t') {
				lwsl_wsi_notice(wsi, "chunk size line garbage");
				return -1;
			}

			/* a chunk extension: skip it up to the CR */
			wsi->http.chunk_parser = ELCP_EXT;

			/* fallthru */

		case ELCP_EXT:
			if (c == '\x0d') {
				wsi->http.chunk_parser = ELCP_CR;
				break;
			}
			if (c == '\x0a') {
				lwsl_wsi_notice(wsi, "chunk extension: bare LF");
				return -1;
			}
			if (++wsi->http.chunk_skip > LWS_HTTP_CHUNK_SKIP_MAX) {
				lwsl_wsi_notice(wsi, "chunk extension too long");
				return -1;
			}
			break;

		case ELCP_CR:
			if (c != '\x0a') {
				lwsl_wsi_notice(wsi, "chunk size line: no LF");
				return -1;
			}
			if (wsi->http.chunk_remaining) {
				wsi->http.chunk_parser = ELCP_CONTENT;
				break;
			}

			/* zero-length chunk: last-chunk, trailer next */
			wsi->http.chunk_parser = ELCP_TRAILER_CR;
			break;

		case ELCP_POST_CR:
			if (c != '\x0d') {
				lwsl_wsi_notice(wsi, "chunk payload: no CR");
				return -1;
			}
			wsi->http.chunk_parser = ELCP_POST_LF;
			break;

		case ELCP_POST_LF:
			if (c != '\x0a') {
				lwsl_wsi_notice(wsi, "chunk payload: no LF");
				return -1;
			}
			wsi->http.chunk_parser = ELCP_HEX;
			wsi->http.chunk_remaining = 0;
			break;

		case ELCP_TRAILER_CR:
			/*
			 * Either the CRLF that ends the trailer section, or the
			 * first byte of a trailer field line, which we skip up
			 * to and including its LF
			 */
			if (c == '\x0d') {
				wsi->http.chunk_parser = ELCP_TRAILER_LF;
				break;
			}
			wsi->http.chunk_parser = ELCP_TRAILER_SKIP;

			/* fallthru */

		case ELCP_TRAILER_SKIP:
			if (++wsi->http.chunk_skip > LWS_HTTP_CHUNK_SKIP_MAX) {
				lwsl_wsi_notice(wsi, "chunk trailers too long");
				return -1;
			}
			/*
			 * A trailer line ends with CRLF, like the rest of the
			 * framing: a bare LF or CR is where something else
			 * framing this body may disagree with us
			 */
			if (c == '\x0a') {
				lwsl_wsi_notice(wsi, "chunk trailer: bare LF");
				return -1;
			}
			if (c == '\x0d')
				wsi->http.chunk_parser = ELCP_TRAILER_SKIP_LF;
			break;

		case ELCP_TRAILER_SKIP_LF:
			if (c != '\x0a') {
				lwsl_wsi_notice(wsi, "chunk trailer: bare CR");
				return -1;
			}
			wsi->http.chunk_parser = ELCP_TRAILER_CR;
			break;

		case ELCP_TRAILER_LF:
			if (c != '\x0a') {
				lwsl_wsi_notice(wsi, "chunk trailer: no LF");
				return -1;
			}
			(*buf)++;
			(*len)--;

			return 1;

		default:
			return -1;
		}

		(*buf)++;
		(*len)--;
	}

	return 0;
}

/*
 * Everything buffered for the wsi's output, by the transport or by the
 * compressor, has gone: a transaction completion deferred until then
 * happens now (see lws_http_transaction_completed())
 */
int
lws_http_tx_drained(struct lws *wsi)
{
#if defined(LWS_WITH_SERVER)
	if (lwsi_state_live(wsi) != LRS_TXN_COMPLETING ||
	    lws_has_buffered_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    || wsi->http.comp_ctx.buflist_comp || wsi->http.comp_ctx.may_have_more
#endif
	)
		return 0;

	lwsl_wsi_info(wsi, "output gone, doing deferred transaction completed");

	return lws_http_transaction_completed(wsi) ? -1 : 1;
#else
	return 0;
#endif
}
