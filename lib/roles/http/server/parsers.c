/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

static const unsigned char lextable[] = {
#if defined(LWS_AMAZON_RTOS) || defined(LWS_AMAZON_LINUX)
	#include "roles/http/lextable.h"
#else
	#include "../lextable.h"
#endif
};

#define FAIL_CHAR 0x08

#if defined(LWS_WITH_CUSTOM_HEADERS)

#define UHO_NLEN	0
#define UHO_VLEN	2
#define UHO_LL		4
#define UHO_NAME	8

static uint16_t
lws_un16be_get(const void *_p)
{
	const uint8_t *p = _p;

	return ((uint16_t)p[0] << 8) | p[1];
}

static void
lws_un16be_set(void *_p, uint16_t v)
{
	uint8_t *p = _p;

	*p++ = (uint8_t)(v >> 8);
	*p++ = (uint8_t)v;
}

static uint32_t
lws_un32be_get(const void *_p)
{
	const uint8_t *p = _p;

	return (uint32_t)((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static void
lws_un32be_set(void *_p, uint32_t v)
{
	uint8_t *p = _p;

	*p++ = (uint8_t)(v >> 24);
	*p++ = (uint8_t)(v >> 16);
	*p++ = (uint8_t)(v >> 8);
	*p = (uint8_t)v;
}
#endif

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
	ah->next = pt->http.ah_list;
	pt->http.ah_list = ah;
	ah->data_length = data_size;
	pt->http.ah_pool_length++;

	lwsl_info("%s: created ah %p (size %d): pool length %ld\n", __func__,
		    ah, (int)data_size, (unsigned long)pt->http.ah_pool_length);

	return ah;
}

int
_lws_destroy_ah(struct lws_context_per_thread *pt, struct allocated_headers *ah)
{
	lws_start_foreach_llp(struct allocated_headers **, a, pt->http.ah_list) {
		if ((*a) == ah) {
			*a = ah->next;
			pt->http.ah_pool_length--;
			lwsl_info("%s: freed ah %p : pool length %ld\n",
				    __func__, ah,
				    (unsigned long)pt->http.ah_pool_length);
			if (ah->data)
				lws_free(ah->data);
			lws_free(ah);

			return 0;
		}
	} lws_end_foreach_llp(a, next);

	return 1;
}

void
_lws_header_table_reset(struct allocated_headers *ah)
{
	/* init the ah to reflect no headers or data have appeared yet */
	memset(ah->frag_index, 0, sizeof(ah->frag_index));
	memset(ah->frags, 0, sizeof(ah->frags));
	ah->nfrag = 0;
	ah->pos = 0;
	ah->http_response = 0;
	ah->parser_state = WSI_TOKEN_NAME_PART;
	ah->lextable_pos = 0;
#if defined(LWS_WITH_CUSTOM_HEADERS)
	ah->unk_pos = 0;
	ah->unk_ll_head = 0;
	ah->unk_ll_tail = 0;
#endif
}

// doesn't scrub the ah rxbuffer by default, parent must do if needed

void
__lws_header_table_reset(struct lws *wsi, int autoservice)
{
	struct allocated_headers *ah = wsi->http.ah;
	struct lws_context_per_thread *pt;
	struct lws_pollfd *pfd;

	/* if we have the idea we're resetting 'our' ah, must be bound to one */
	assert(ah);
	/* ah also concurs with ownership */
	assert(ah->wsi == wsi);

	_lws_header_table_reset(ah);

	/* since we will restart the ah, our new headers are not completed */
	wsi->hdr_parsing_completed = 0;

	/* while we hold the ah, keep a timeout on the wsi */
	__lws_set_timeout(wsi, PENDING_TIMEOUT_HOLDING_AH,
			  wsi->vhost->timeout_secs_ah_idle);

	time(&ah->assigned);

	if (wsi->position_in_fds_table != LWS_NO_FDS_POS &&
	    lws_buflist_next_segment_len(&wsi->buflist, NULL) &&
	    autoservice) {
		lwsl_debug("%s: service on readbuf ah\n", __func__);

		pt = &wsi->context->pt[(int)wsi->tsi];
		/*
		 * Unlike a normal connect, we have the headers already
		 * (or the first part of them anyway)
		 */
		pfd = &pt->fds[wsi->position_in_fds_table];
		pfd->revents |= LWS_POLLIN;
		lwsl_err("%s: calling service\n", __func__);
		lws_service_fd_tsi(wsi->context, pfd, wsi->tsi);
	}
}

void
lws_header_table_reset(struct lws *wsi, int autoservice)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);

	__lws_header_table_reset(wsi, autoservice);

	lws_pt_unlock(pt);
}

static void
_lws_header_ensure_we_are_on_waiting_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws_pollargs pa;
	struct lws **pwsi = &pt->http.ah_wait_list;

	while (*pwsi) {
		if (*pwsi == wsi)
			return;
		pwsi = &(*pwsi)->http.ah_wait_list;
	}

	lwsl_info("%s: wsi: %p\n", __func__, wsi);
	wsi->http.ah_wait_list = pt->http.ah_wait_list;
	pt->http.ah_wait_list = wsi;
	pt->http.ah_wait_list_length++;

	/* we cannot accept input then */

	_lws_change_pollfd(wsi, LWS_POLLIN, 0, &pa);
}

static int
__lws_remove_from_ah_waiting_list(struct lws *wsi)
{
        struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws **pwsi =&pt->http.ah_wait_list;

	while (*pwsi) {
		if (*pwsi == wsi) {
			lwsl_info("%s: wsi %p\n", __func__, wsi);
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

int LWS_WARN_UNUSED_RESULT
lws_header_table_attach(struct lws *wsi, int autoservice)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_pollargs pa;
	int n;

	lwsl_info("%s: wsi %p: ah %p (tsi %d, count = %d) in\n", __func__,
		  (void *)wsi, (void *)wsi->http.ah, wsi->tsi,
		  pt->http.ah_count_in_use);

	if (!lwsi_role_http(wsi)) {
		lwsl_err("%s: bad role %s\n", __func__, wsi->role_ops->name);
		assert(0);
		return -1;
	}

	lws_pt_lock(pt, __func__);

	/* if we are already bound to one, just clear it down */
	if (wsi->http.ah) {
		lwsl_info("%s: cleardown\n", __func__);
		goto reset;
	}

	n = pt->http.ah_count_in_use == context->max_http_header_pool;
#if defined(LWS_WITH_PEER_LIMITS)
	if (!n) {
		n = lws_peer_confirm_ah_attach_ok(context, wsi->peer);
		if (n)
			lws_stats_bump(pt, LWSSTATS_C_PEER_LIMIT_AH_DENIED, 1);
	}
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

	wsi->http.ah = _lws_create_ah(pt, context->max_http_header_data);
	if (!wsi->http.ah) { /* we could not create an ah */
		_lws_header_ensure_we_are_on_waiting_list(wsi);

		goto bail;
	}

	wsi->http.ah->in_use = 1;
	wsi->http.ah->wsi = wsi; /* mark our owner */
	pt->http.ah_count_in_use++;

#if defined(LWS_WITH_PEER_LIMITS) && (defined(LWS_ROLE_H1) || \
    defined(LWS_ROLE_H2))
	lws_context_lock(context, "ah attach"); /* <========================= */
	if (wsi->peer)
		wsi->peer->http.count_ah++;
	lws_context_unlock(context); /* ====================================> */
#endif

	_lws_change_pollfd(wsi, 0, LWS_POLLIN, &pa);

	lwsl_info("%s: did attach wsi %p: ah %p: count %d (on exit)\n", __func__,
		  (void *)wsi, (void *)wsi->http.ah, pt->http.ah_count_in_use);

reset:
	__lws_header_table_reset(wsi, autoservice);

	lws_pt_unlock(pt);

#ifndef LWS_NO_CLIENT
	if (lwsi_role_client(wsi) && lwsi_state(wsi) == LRS_UNCONNECTED)
		if (!lws_http_client_connect_via_info2(wsi))
			/* our client connect has failed, the wsi
			 * has been closed
			 */
			return -1;
#endif

	return 0;

bail:
	lws_pt_unlock(pt);

	return 1;
}

int __lws_header_table_detach(struct lws *wsi, int autoservice)
{
	struct lws_context *context = wsi->context;
	struct allocated_headers *ah = wsi->http.ah;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_pollargs pa;
	struct lws **pwsi, **pwsi_eligible;
	time_t now;

	__lws_remove_from_ah_waiting_list(wsi);

	if (!ah)
		return 0;

	lwsl_info("%s: wsi %p: ah %p (tsi=%d, count = %d)\n", __func__,
		  (void *)wsi, (void *)ah, wsi->tsi,
		  pt->http.ah_count_in_use);

	/* we did have an ah attached */
	time(&now);
	if (ah->assigned && now - ah->assigned > 3) {
		/*
		 * we're detaching the ah, but it was held an
		 * unreasonably long time
		 */
		lwsl_debug("%s: wsi %p: ah held %ds, role/state 0x%lx 0x%x,"
			    "\n", __func__, wsi, (int)(now - ah->assigned),
			    (unsigned long)lwsi_role(wsi), lwsi_state(wsi));
	}

	ah->assigned = 0;

	/* if we think we're detaching one, there should be one in use */
	assert(pt->http.ah_count_in_use > 0);
	/* and this specific one should have been in use */
	assert(ah->in_use);
	memset(&wsi->http.ah, 0, sizeof(wsi->http.ah));

#if defined(LWS_WITH_PEER_LIMITS)
	if (ah->wsi)
		lws_peer_track_ah_detach(context, wsi->peer);
#endif
	ah->wsi = NULL; /* no owner */

	pwsi = &pt->http.ah_wait_list;

	/* oh there is nobody on the waiting list... leave the ah unattached */
	if (!*pwsi)
		goto nobody_usable_waiting;

	/*
	 * at least one wsi on the same tsi is waiting, give it to oldest guy
	 * who is allowed to take it (if any)
	 */
	lwsl_info("pt wait list %p\n", *pwsi);
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
#if defined(LWS_WITH_PEER_LIMITS)
		else
			if (!(*pwsi)->http.ah_wait_list)
				lws_stats_bump(pt,
					LWSSTATS_C_PEER_LIMIT_AH_DENIED, 1);
#endif
		pwsi = &(*pwsi)->http.ah_wait_list;
	}

	if (!wsi) /* everybody waiting already has too many ah... */
		goto nobody_usable_waiting;

	lwsl_info("%s: transferring ah to last eligible wsi in wait list "
		  "%p (wsistate 0x%lx)\n", __func__, wsi,
		  (unsigned long)wsi->wsistate);

	wsi->http.ah = ah;
	ah->wsi = wsi; /* new owner */

	__lws_header_table_reset(wsi, autoservice);
#if defined(LWS_WITH_PEER_LIMITS) && (defined(LWS_ROLE_H1) || \
    defined(LWS_ROLE_H2))
	lws_context_lock(context, "ah detach"); /* <========================= */
	if (wsi->peer)
		wsi->peer->http.count_ah++;
	lws_context_unlock(context); /* ====================================> */
#endif

	/* clients acquire the ah and then insert themselves in fds table... */
	if (wsi->position_in_fds_table != LWS_NO_FDS_POS) {
		lwsl_info("%s: Enabling %p POLLIN\n", __func__, wsi);

		/* he has been stuck waiting for an ah, but now his wait is
		 * over, let him progress */

		_lws_change_pollfd(wsi, 0, LWS_POLLIN, &pa);
	}

	/* point prev guy to next guy in list instead */
	*pwsi_eligible = wsi->http.ah_wait_list;
	/* the guy who got one is out of the list */
	wsi->http.ah_wait_list = NULL;
	pt->http.ah_wait_list_length--;

#ifndef LWS_NO_CLIENT
	if (lwsi_role_client(wsi) && lwsi_state(wsi) == LRS_UNCONNECTED) {
		lws_pt_unlock(pt);

		if (!lws_http_client_connect_via_info2(wsi)) {
			/* our client connect has failed, the wsi
			 * has been closed
			 */

			return -1;
		}
		return 0;
	}
#endif

	assert(!!pt->http.ah_wait_list_length ==
			!!(lws_intptr_t)pt->http.ah_wait_list);
bail:
	lwsl_info("%s: wsi %p: ah %p (tsi=%d, count = %d)\n", __func__,
		  (void *)wsi, (void *)ah, pt->tid, pt->http.ah_count_in_use);

	return 0;

nobody_usable_waiting:
	lwsl_info("%s: nobody usable waiting\n", __func__);
	_lws_destroy_ah(pt, ah);
	pt->http.ah_count_in_use--;

	goto bail;
}

int lws_header_table_detach(struct lws *wsi, int autoservice)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n;

	lws_pt_lock(pt, __func__);
	n = __lws_header_table_detach(wsi, autoservice);
	lws_pt_unlock(pt);

	return n;
}

LWS_VISIBLE int
lws_hdr_fragment_length(struct lws *wsi, enum lws_token_indexes h, int frag_idx)
{
	int n;

	if (!wsi->http.ah)
		return 0;

	n = wsi->http.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		if (!frag_idx)
			return wsi->http.ah->frags[n].len;
		n = wsi->http.ah->frags[n].nfrag;
	} while (frag_idx-- && n);

	return 0;
}

LWS_VISIBLE int lws_hdr_total_length(struct lws *wsi, enum lws_token_indexes h)
{
	int n;
	int len = 0;

	if (!wsi->http.ah)
		return 0;

	n = wsi->http.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		len += wsi->http.ah->frags[n].len;
		n = wsi->http.ah->frags[n].nfrag;

		if (n && h != WSI_TOKEN_HTTP_COOKIE)
			++len;

	} while (n);

	return len;
}

LWS_VISIBLE int lws_hdr_copy_fragment(struct lws *wsi, char *dst, int len,
				      enum lws_token_indexes h, int frag_idx)
{
	int n = 0;
	int f;

	if (!wsi->http.ah)
		return -1;

	f = wsi->http.ah->frag_index[h];

	if (!f)
		return -1;

	while (n < frag_idx) {
		f = wsi->http.ah->frags[f].nfrag;
		if (!f)
			return -1;
		n++;
	}

	if (wsi->http.ah->frags[f].len >= len)
		return -1;

	memcpy(dst, wsi->http.ah->data + wsi->http.ah->frags[f].offset,
	       wsi->http.ah->frags[f].len);
	dst[wsi->http.ah->frags[f].len] = '\0';

	return wsi->http.ah->frags[f].len;
}

LWS_VISIBLE int lws_hdr_copy(struct lws *wsi, char *dst, int len,
			     enum lws_token_indexes h)
{
	int toklen = lws_hdr_total_length(wsi, h);
	int n;
	int comma;

	*dst = '\0';
	if (!toklen)
		return 0;

	if (toklen >= len)
		return -1;

	if (!wsi->http.ah)
		return -1;

	n = wsi->http.ah->frag_index[h];
	if (!n)
		return 0;

	do {
		comma = (wsi->http.ah->frags[n].nfrag &&
			h != WSI_TOKEN_HTTP_COOKIE) ? 1 : 0;

		if (wsi->http.ah->frags[n].len + comma >= len)
			return -1;
		strncpy(dst, &wsi->http.ah->data[wsi->http.ah->frags[n].offset],
		        wsi->http.ah->frags[n].len);
		dst += wsi->http.ah->frags[n].len;
		len -= wsi->http.ah->frags[n].len;
		n = wsi->http.ah->frags[n].nfrag;

		if (comma)
			*dst++ = ',';
				
	} while (n);
	*dst = '\0';

	return toklen;
}

#if defined(LWS_WITH_CUSTOM_HEADERS)
LWS_VISIBLE int
lws_hdr_custom_length(struct lws *wsi, const char *name, int nlen)
{
	ah_data_idx_t ll;

	if (!wsi->http.ah || wsi->http2_substream)
		return -1;

	ll = wsi->http.ah->unk_ll_head;
	while (ll) {
		if (ll >= wsi->http.ah->data_length)
			return -1;
		if (nlen == lws_un16be_get(&wsi->http.ah->data[ll + UHO_NLEN]) &&
		    !strncmp(name, &wsi->http.ah->data[ll + UHO_NAME], nlen))
			return lws_un16be_get(&wsi->http.ah->data[ll + UHO_VLEN]);

		ll = lws_un32be_get(&wsi->http.ah->data[ll + UHO_LL]);
	}

	return -1;
}

LWS_VISIBLE int
lws_hdr_custom_copy(struct lws *wsi, char *dst, int len, const char *name,
		    int nlen)
{
	ah_data_idx_t ll;
	int n;

	if (!wsi->http.ah || wsi->http2_substream)
		return -1;

	*dst = '\0';

	ll = wsi->http.ah->unk_ll_head;
	while (ll) {
		if (ll >= wsi->http.ah->data_length)
			return -1;
		if (nlen == lws_un16be_get(&wsi->http.ah->data[ll + UHO_NLEN]) &&
		    !strncmp(name, &wsi->http.ah->data[ll + UHO_NAME], nlen)) {
			n = lws_un16be_get(&wsi->http.ah->data[ll + UHO_VLEN]);
			if (n + 1 > len)
				return -1;
			strncpy(dst, &wsi->http.ah->data[ll + UHO_NAME + nlen], n);
			dst[n] = '\0';

			return n;
		}
		ll = lws_un32be_get(&wsi->http.ah->data[ll + UHO_LL]);
	}

	return -1;
}
#endif

char *lws_hdr_simple_ptr(struct lws *wsi, enum lws_token_indexes h)
{
	int n;

	if (!wsi->http.ah)
		return NULL;

	n = wsi->http.ah->frag_index[h];
	if (!n)
		return NULL;

	return wsi->http.ah->data + wsi->http.ah->frags[n].offset;
}

static int LWS_WARN_UNUSED_RESULT
lws_pos_in_bounds(struct lws *wsi)
{
	if (!wsi->http.ah)
		return -1;

	if (wsi->http.ah->pos <
	    (unsigned int)wsi->context->max_http_header_data)
		return 0;

	if ((int)wsi->http.ah->pos == wsi->context->max_http_header_data) {
		lwsl_err("Ran out of header data space\n");
		return 1;
	}

	/*
	 * with these tests everywhere, it should never be able to exceed
	 * the limit, only meet it
	 */
	lwsl_err("%s: pos %ld, limit %ld\n", __func__,
		 (unsigned long)wsi->http.ah->pos,
		 (unsigned long)wsi->context->max_http_header_data);
	assert(0);

	return 1;
}

int LWS_WARN_UNUSED_RESULT
lws_hdr_simple_create(struct lws *wsi, enum lws_token_indexes h, const char *s)
{
	wsi->http.ah->nfrag++;
	if (wsi->http.ah->nfrag == LWS_ARRAY_SIZE(wsi->http.ah->frags)) {
		lwsl_warn("More hdr frags than we can deal with, dropping\n");
		return -1;
	}

	wsi->http.ah->frag_index[h] = wsi->http.ah->nfrag;

	wsi->http.ah->frags[wsi->http.ah->nfrag].offset = wsi->http.ah->pos;
	wsi->http.ah->frags[wsi->http.ah->nfrag].len = 0;
	wsi->http.ah->frags[wsi->http.ah->nfrag].nfrag = 0;

	do {
		if (lws_pos_in_bounds(wsi))
			return -1;

		wsi->http.ah->data[wsi->http.ah->pos++] = *s;
		if (*s)
			wsi->http.ah->frags[wsi->http.ah->nfrag].len++;
	} while (*s++);

	return 0;
}

static int LWS_WARN_UNUSED_RESULT
issue_char(struct lws *wsi, unsigned char c)
{
	unsigned short frag_len;

	if (lws_pos_in_bounds(wsi))
		return -1;

	frag_len = wsi->http.ah->frags[wsi->http.ah->nfrag].len;
	/*
	 * If we haven't hit the token limit, just copy the character into
	 * the header
	 */
	if (!wsi->http.ah->current_token_limit ||
	    frag_len < wsi->http.ah->current_token_limit) {
		wsi->http.ah->data[wsi->http.ah->pos++] = c;
		if (c)
			wsi->http.ah->frags[wsi->http.ah->nfrag].len++;
		return 0;
	}

	/* Insert a null character when we *hit* the limit: */
	if (frag_len == wsi->http.ah->current_token_limit) {
		if (lws_pos_in_bounds(wsi))
			return -1;

		wsi->http.ah->data[wsi->http.ah->pos++] = '\0';
		lwsl_warn("header %li exceeds limit %ld\n",
			  (long)wsi->http.ah->parser_state,
			  (long)wsi->http.ah->current_token_limit);
	}

	return 1;
}

int
lws_parse_urldecode(struct lws *wsi, uint8_t *_c)
{
	struct allocated_headers *ah = wsi->http.ah;
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
		if (char_to_hex(c) < 0)
			/* illegal post-% char */
			goto forbid;

		ah->esc_stash = c;
		ah->ues = URIES_SEEN_PERCENT_H1;
		goto swallow;

	case URIES_SEEN_PERCENT_H1:
		if (char_to_hex(c) < 0)
			/* illegal post-% char */
			goto forbid;

		*_c = (char_to_hex(ah->esc_stash) << 4) |
				char_to_hex(c);
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

	switch (ah->ups) {
	case URIPS_IDLE:
		if (!c)
			return -1;
		/* genuine delimiter */
		if ((c == '&' || c == ';') && !enc) {
			if (issue_char(wsi, '\0') < 0)
				return -1;
			/* link to next fragment */
			ah->frags[ah->nfrag].nfrag = ah->nfrag + 1;
			ah->nfrag++;
			if (ah->nfrag >= LWS_ARRAY_SIZE(ah->frags))
				goto excessive;
			/* start next fragment after the & */
			ah->post_literal_equal = 0;
			ah->frags[ah->nfrag].offset = ++ah->pos;
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

		/* + to space */
		if (c == '+' && !enc) {
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
			if (ah->frags[ah->nfrag].len > 1)
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

		/* seal off uri header */
		if (issue_char(wsi, '\0') < 0)
			return -1;

		/* move to using WSI_TOKEN_HTTP_URI_ARGS */
		ah->nfrag++;
		if (ah->nfrag >= LWS_ARRAY_SIZE(ah->frags))
			goto excessive;
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

static const unsigned char methods[] = {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_POST_URI,
	WSI_TOKEN_OPTIONS_URI,
	WSI_TOKEN_PUT_URI,
	WSI_TOKEN_PATCH_URI,
	WSI_TOKEN_DELETE_URI,
	WSI_TOKEN_CONNECT,
	WSI_TOKEN_HEAD_URI,
};

/*
 * possible returns:, -1 fail, 0 ok or 2, transition to raw
 */

int LWS_WARN_UNUSED_RESULT
lws_parse(struct lws *wsi, unsigned char *buf, int *len)
{
	struct allocated_headers *ah = wsi->http.ah;
	struct lws_context *context = wsi->context;
	unsigned int n, m;
	unsigned char c;
	int r, pos;

	assert(wsi->http.ah);

	do {
		(*len)--;
		c = *buf++;

		switch (ah->parser_state) {
#if defined(LWS_WITH_CUSTOM_HEADERS)
		case WSI_TOKEN_UNKNOWN_VALUE_PART:

			if (c == '\r')
				break;
			if (c == '\n') {
				lws_un16be_set(&ah->data[ah->unk_pos + 2],
					       ah->pos - ah->unk_value_pos);
				ah->parser_state = WSI_TOKEN_NAME_PART;
				ah->unk_pos = 0;
				ah->lextable_pos = 0;
				break;
			}

			/* trim leading whitespace */
			if (ah->pos != ah->unk_value_pos ||
			    (c != ' ' && c != '\t')) {

				if (lws_pos_in_bounds(wsi))
					return -1;

				ah->data[ah->pos++] = c;
			}
			pos = ah->lextable_pos;
			break;
#endif
		default:

			lwsl_parser("WSI_TOK_(%d) '%c'\n", ah->parser_state, c);

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

			/* special URI processing... end at space */

			if (c == ' ') {
				/* enforce starting with / */
				if (!ah->frags[ah->nfrag].len)
					if (issue_char(wsi, '/') < 0)
						return -1;

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
					return -1;
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
				goto excessive;
			default:
				return LPR_FAIL;
			}
check_eol:
			/* bail at EOL */
			if (ah->parser_state != WSI_TOKEN_CHALLENGE &&
			    c == '\x0d') {
				if (ah->ues != URIES_IDLE)
					goto forbid;

				c = '\0';
				ah->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
				lwsl_parser("*\n");
			}

			n = issue_char(wsi, c);
			if ((int)n < 0)
				return LPR_FAIL;
			if (n > 0)
				ah->parser_state = WSI_TOKEN_SKIPPING;

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

			if (c >= 'A' && c <= 'Z')
				c += 'a' - 'A';

#if defined(LWS_WITH_CUSTOM_HEADERS)
			/*
			 * ...in case it's an unknown header, speculatively
			 * store it as the name comes in.  If we recognize it as
			 * a known header, we'll snip this.
			 */

			if (!ah->unk_pos) {
				ah->unk_pos = ah->pos;
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
			}
#endif

			if (lws_pos_in_bounds(wsi))
				return -1;

			ah->data[ah->pos++] = c;
			pos = ah->lextable_pos;

#if defined(LWS_WITH_CUSTOM_HEADERS)
			if (pos < 0 && c == ':') {
				/*
				 * process unknown headers
				 *
				 * register us in the unknown hdr ll
				 */

				if (!ah->unk_ll_head)
					ah->unk_ll_head = ah->unk_pos;

				if (ah->unk_ll_tail)
					lws_un32be_set(&ah->data[ah->unk_ll_tail + UHO_LL],
						       ah->unk_pos);

				ah->unk_ll_tail = ah->unk_pos;

				lwsl_debug("%s: unk header %d '%.*s'\n",
					   __func__,
					   ah->pos - (ah->unk_pos + UHO_NAME),
					   ah->pos - (ah->unk_pos + UHO_NAME),
					   &ah->data[ah->unk_pos + UHO_NAME]);

				/* set the unknown header name part length */

				lws_un16be_set(&ah->data[ah->unk_pos],
					       (ah->pos - ah->unk_pos) - UHO_NAME);

				ah->unk_value_pos = ah->pos;

				/*
				 * collect whatever's coming for the unknown header
				 * argument until the next CRLF
				 */
				ah->parser_state = WSI_TOKEN_UNKNOWN_VALUE_PART;
				break;
			}
#endif
			if (pos < 0)
				break;

			while (1) {
				if (lextable[pos] & (1 << 7)) {
					/* 1-byte, fail on mismatch */
					if ((lextable[pos] & 0x7f) != c) {
nope:
						ah->lextable_pos = -1;
						break;
					}
					/* fall thru */
					pos++;
					if (lextable[pos] == FAIL_CHAR)
						goto nope;

					ah->lextable_pos = pos;
					break;
				}

				if (lextable[pos] == FAIL_CHAR)
					goto nope;

				/* b7 = 0, end or 3-byte */
				if (lextable[pos] < FAIL_CHAR) {
#if defined(LWS_WITH_CUSTOM_HEADERS)
					/*
					 * We hit a terminal marker, so we
					 * recognized this header... drop the
					 * speculative name part storage
					 */
					ah->pos = ah->unk_pos;
					ah->unk_pos = 0;
#endif
					ah->lextable_pos = pos;
					break;
				}

				if (lextable[pos] == c) { /* goto */
					ah->lextable_pos = pos +
						(lextable[pos + 1]) +
						(lextable[pos + 2] << 8);
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
				for (m = 0; m < LWS_ARRAY_SIZE(methods); m++)
					if (ah->frag_index[methods[m]]) {
						/*
						 * already had the method
						 */
#if !defined(LWS_WITH_CUSTOM_HEADERS)
						ah->parser_state = WSI_TOKEN_SKIPPING;
#endif
						break;
					}

				if (m != LWS_ARRAY_SIZE(methods))
#if defined(LWS_WITH_CUSTOM_HEADERS)
					/*
					 * We have the method, this is just an
					 * unknown header then
					 */
					goto unknown_hdr;
#else
					break;
#endif
				/*
				 * ...it's an unknown http method from a client
				 * in fact, it cannot be valid http.
				 *
				 * Are we set up to transition to another role
				 * in these cases?
				 */
				if (lws_check_opt(wsi->vhost->options,
		    LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG)) {
					lwsl_notice("%s: http fail fallback\n",
						    __func__);
					 /* transition to other role */
					return LPR_DO_FALLBACK;
				}

				lwsl_info("Unknown method - dropping\n");
				goto forbid;
			}
			if (ah->lextable_pos < 0) {
#if defined(LWS_WITH_CUSTOM_HEADERS)
				goto unknown_hdr;
#else
				/*
				 * ...otherwise for a client, let him ignore
				 * unknown headers coming from the server
				 */
				ah->parser_state = WSI_TOKEN_SKIPPING;
				break;
#endif
			}

			if (lextable[ah->lextable_pos] < FAIL_CHAR) {
				/* terminal state */

				n = ((unsigned int)lextable[ah->lextable_pos] << 8) |
						lextable[ah->lextable_pos + 1];

				lwsl_parser("known hdr %d\n", n);
				for (m = 0; m < LWS_ARRAY_SIZE(methods); m++)
					if (n == methods[m] &&
					    ah->frag_index[methods[m]]) {
						lwsl_warn("Duplicated method\n");
						return LPR_FAIL;
					}

				/*
				 * WSORIGIN is protocol equiv to ORIGIN,
				 * JWebSocket likes to send it, map to ORIGIN
				 */
				if (n == WSI_TOKEN_SWORIGIN)
					n = WSI_TOKEN_ORIGIN;

				ah->parser_state = (enum lws_token_indexes)
							(WSI_TOKEN_GET_URI + n);
				ah->ups = URIPS_IDLE;

				if (context->token_limits)
					ah->current_token_limit = context->
						token_limits->token_limit[
							      ah->parser_state];
				else
					ah->current_token_limit =
						wsi->context->max_http_header_data;

				if (ah->parser_state == WSI_TOKEN_CHALLENGE)
					goto set_parsing_complete;

				goto start_fragment;
			}
			break;

#if defined(LWS_WITH_CUSTOM_HEADERS)
unknown_hdr:
			//ah->parser_state = WSI_TOKEN_SKIPPING;
			//break;
			break;
#endif

start_fragment:
			ah->nfrag++;
excessive:
			if (ah->nfrag == LWS_ARRAY_SIZE(ah->frags)) {
				lwsl_warn("More hdr frags than we can deal with\n");
				return LPR_FAIL;
			}

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
			while (ah->frags[n].nfrag)
				n = ah->frags[n].nfrag;
			ah->frags[n].nfrag = ah->nfrag;

			if (issue_char(wsi, ' ') < 0)
				return LPR_FAIL;
			break;

			/* skipping arg part of a name we didn't recognize */
		case WSI_TOKEN_SKIPPING:
			lwsl_parser("WSI_TOKEN_SKIPPING '%c'\n", c);

			if (c == '\x0d')
				ah->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			break;

		case WSI_TOKEN_SKIPPING_SAW_CR:
			lwsl_parser("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
			if (ah->ues != URIES_IDLE)
				goto forbid;
			if (c == '\x0a') {
				ah->parser_state = WSI_TOKEN_NAME_PART;
#if defined(LWS_WITH_CUSTOM_HEADERS)
				ah->unk_pos = 0;
#endif
				ah->lextable_pos = 0;
			} else
				ah->parser_state = WSI_TOKEN_SKIPPING;
			break;
			/* we're done, ignore anything else */

		case WSI_PARSING_COMPLETE:
			lwsl_parser("WSI_PARSING_COMPLETE '%c'\n", c);
			break;
		}

	} while (*len);

	return LPR_OK;

set_parsing_complete:
	if (ah->ues != URIES_IDLE)
		goto forbid;

	if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
		if (lws_hdr_total_length(wsi, WSI_TOKEN_VERSION))
			wsi->rx_frame_type = /* temp for ws version index */
			       atoi(lws_hdr_simple_ptr(wsi, WSI_TOKEN_VERSION));

		lwsl_parser("v%02d hdrs done\n", wsi->rx_frame_type);
	}
	ah->parser_state = WSI_PARSING_COMPLETE;
	wsi->hdr_parsing_completed = 1;

	return LPR_OK;

forbid:
	lwsl_notice(" forbidding on uri sanitation\n");
	lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

	return LPR_FORBIDDEN;
}

