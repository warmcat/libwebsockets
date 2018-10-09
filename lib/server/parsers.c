/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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

#include "private-libwebsockets.h"

static const unsigned char lextable[] = {
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
	ah->next = pt->ah_list;
	pt->ah_list = ah;
	ah->data_length = data_size;
	pt->ah_pool_length++;

	lwsl_info("%s: created ah %p (size %d): pool length %d\n", __func__,
		    ah, (int)data_size, pt->ah_pool_length);

	return ah;
}

int
_lws_destroy_ah(struct lws_context_per_thread *pt, struct allocated_headers *ah)
{
	lws_start_foreach_llp(struct allocated_headers **, a, pt->ah_list) {
		if ((*a) == ah) {
			*a = ah->next;
			pt->ah_pool_length--;
			lwsl_info("%s: freed ah %p : pool length %d\n",
				    __func__, ah, pt->ah_pool_length);
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
}

// doesn't scrub the ah rxbuffer by default, parent must do if needed

void
__lws_header_table_reset(struct lws *wsi, int autoservice)
{
	struct allocated_headers *ah = wsi->ah;
	struct lws_context_per_thread *pt;
	struct lws_pollfd *pfd;

	/* if we have the idea we're resetting 'our' ah, must be bound to one */
	assert(ah);
	/* ah also concurs with ownership */
	assert(ah->wsi == wsi);

	_lws_header_table_reset(ah);

	ah->parser_state = WSI_TOKEN_NAME_PART;
	ah->lextable_pos = 0;

	/* since we will restart the ah, our new headers are not completed */
	wsi->hdr_parsing_completed = 0;

	/* while we hold the ah, keep a timeout on the wsi */
	__lws_set_timeout(wsi, PENDING_TIMEOUT_HOLDING_AH,
			wsi->vhost->timeout_secs_ah_idle);

	time(&ah->assigned);

	/*
	 * if we inherited pending rx (from socket adoption deferred
	 * processing), apply and free it.
	 */
	if (wsi->preamble_rx) {
		memcpy(ah->rx, wsi->preamble_rx, wsi->preamble_rx_len);
		ah->rxlen = wsi->preamble_rx_len;
		lws_free_set_NULL(wsi->preamble_rx);
		wsi->preamble_rx_len = 0;
		ah->rxpos = 0;

		if (autoservice) {
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
	struct lws **pwsi = &pt->ah_wait_list;

	while (*pwsi) {
		if (*pwsi == wsi)
			return;
		pwsi = &(*pwsi)->ah_wait_list;
	}

	lwsl_info("%s: wsi: %p\n", __func__, wsi);
	wsi->ah_wait_list = pt->ah_wait_list;
	pt->ah_wait_list = wsi;
	pt->ah_wait_list_length++;

	/* we cannot accept input then */

	_lws_change_pollfd(wsi, LWS_POLLIN, 0, &pa);
}

static int
__lws_remove_from_ah_waiting_list(struct lws *wsi)
{
        struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws **pwsi =&pt->ah_wait_list;

	while (*pwsi) {
		if (*pwsi == wsi) {
			lwsl_info("%s: wsi %p\n", __func__, wsi);
			/* point prev guy to our next */
			*pwsi = wsi->ah_wait_list;
			/* we shouldn't point anywhere now */
			wsi->ah_wait_list = NULL;
			pt->ah_wait_list_length--;

			return 1;
		}
		pwsi = &(*pwsi)->ah_wait_list;
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
		  (void *)wsi, (void *)wsi->ah, wsi->tsi,
		  pt->ah_count_in_use);

	lws_pt_lock(pt, __func__);

	/* if we are already bound to one, just clear it down */
	if (wsi->ah) {
		lwsl_info("%s: cleardown\n", __func__);
		goto reset;
	}

	n = pt->ah_count_in_use == context->max_http_header_pool;
#if defined(LWS_WITH_PEER_LIMITS)
	if (!n) {
		n = lws_peer_confirm_ah_attach_ok(context, wsi->peer);
		if (n)
			lws_stats_atomic_bump(wsi->context, pt,
				LWSSTATS_C_PEER_LIMIT_AH_DENIED, 1);
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

	wsi->ah = _lws_create_ah(pt, context->max_http_header_data);
	if (!wsi->ah) { /* we could not create an ah */
		_lws_header_ensure_we_are_on_waiting_list(wsi);

		goto bail;
	}

	wsi->ah->in_use = 1;
	wsi->ah->wsi = wsi; /* mark our owner */
	pt->ah_count_in_use++;

#if defined(LWS_WITH_PEER_LIMITS)
	if (wsi->peer)
		wsi->peer->count_ah++;
#endif

	_lws_change_pollfd(wsi, 0, LWS_POLLIN, &pa);

	lwsl_info("%s: did attach wsi %p: ah %p: count %d (on exit)\n", __func__,
		  (void *)wsi, (void *)wsi->ah, pt->ah_count_in_use);

reset:

	/* and reset the rx state */
	wsi->ah->rxpos = 0;
	wsi->ah->rxlen = 0;

	__lws_header_table_reset(wsi, autoservice);

	lws_pt_unlock(pt);

#ifndef LWS_NO_CLIENT
	if (wsi->state == LWSS_CLIENT_UNCONNECTED)
		if (!lws_client_connect_via_info2(wsi))
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

void
lws_header_table_force_to_detachable_state(struct lws *wsi)
{
	if (wsi->ah) {
		wsi->ah->rxpos = -1;
		wsi->ah->rxlen = -1;
		wsi->hdr_parsing_completed = 1;
	}
}

int
lws_header_table_is_in_detachable_state(struct lws *wsi)
{
	struct allocated_headers *ah = wsi->ah;

	return ah && ah->rxpos == ah->rxlen && wsi->hdr_parsing_completed;
}

int __lws_header_table_detach(struct lws *wsi, int autoservice)
{
	struct lws_context *context = wsi->context;
	struct allocated_headers *ah = wsi->ah;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_pollargs pa;
	struct lws **pwsi, **pwsi_eligible;
	time_t now;

	__lws_remove_from_ah_waiting_list(wsi);

	if (!ah)
		return 0;

	lwsl_info("%s: wsi %p: ah %p (tsi=%d, count = %d)\n", __func__,
		  (void *)wsi, (void *)ah, wsi->tsi,
		  pt->ah_count_in_use);

	if (wsi->preamble_rx) {
		lws_free_set_NULL(wsi->preamble_rx);
		wsi->preamble_rx_len = 0;
	}

	/* may not be detached while he still has unprocessed rx */
	if (!lws_header_table_is_in_detachable_state(wsi)) {
		lwsl_err("%s: %p: CANNOT DETACH rxpos:%d, rxlen:%d, "
			 "wsi->hdr_parsing_completed = %d\n", __func__, wsi,
			 ah->rxpos, ah->rxlen, wsi->hdr_parsing_completed);
		return 0;
	}

	/* we did have an ah attached */
	time(&now);
	if (ah->assigned && now - ah->assigned > 3) {
		/*
		 * we're detaching the ah, but it was held an
		 * unreasonably long time
		 */
		lwsl_debug("%s: wsi %p: ah held %ds, "
			    "ah.rxpos %d, ah.rxlen %d, mode/state %d %d,"
			    "\n", __func__, wsi,
			    (int)(now - ah->assigned),
			    ah->rxpos, ah->rxlen, wsi->mode, wsi->state);
	}

	ah->assigned = 0;

	/* if we think we're detaching one, there should be one in use */
	assert(pt->ah_count_in_use > 0);
	/* and this specific one should have been in use */
	assert(ah->in_use);
	memset(&wsi->ah, 0, sizeof(wsi->ah));
	ah->wsi = NULL; /* no owner */
#if defined(LWS_WITH_PEER_LIMITS)
	lws_peer_track_ah_detach(context, wsi->peer);
#endif

	pwsi = &pt->ah_wait_list;

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
			if (!(*pwsi)->ah_wait_list)
				lws_stats_atomic_bump(context, pt,
					LWSSTATS_C_PEER_LIMIT_AH_DENIED, 1);
#endif
		pwsi = &(*pwsi)->ah_wait_list;
	}

	if (!wsi) /* everybody waiting already has too many ah... */
		goto nobody_usable_waiting;

	lwsl_info("%s: last eligible wsi in wait list %p\n", __func__, wsi);

	wsi->ah = ah;
	ah->wsi = wsi; /* new owner */

	/* and reset the rx state */
	ah->rxpos = 0;
	ah->rxlen = 0;
	__lws_header_table_reset(wsi, autoservice);
#if defined(LWS_WITH_PEER_LIMITS)
	if (wsi->peer)
		wsi->peer->count_ah++;
#endif

	/* clients acquire the ah and then insert themselves in fds table... */
	if (wsi->position_in_fds_table != -1) {
		lwsl_info("%s: Enabling %p POLLIN\n", __func__, wsi);

		/* he has been stuck waiting for an ah, but now his wait is
		 * over, let him progress */

		_lws_change_pollfd(wsi, 0, LWS_POLLIN, &pa);
	}

	/* point prev guy to next guy in list instead */
	*pwsi_eligible = wsi->ah_wait_list;
	/* the guy who got one is out of the list */
	wsi->ah_wait_list = NULL;
	pt->ah_wait_list_length--;

#ifndef LWS_NO_CLIENT
	if (wsi->state == LWSS_CLIENT_UNCONNECTED) {
		lws_pt_unlock(pt);

		if (!lws_client_connect_via_info2(wsi)) {
			/* our client connect has failed, the wsi
			 * has been closed
			 */

			return -1;
		}
		return 0;
	}
#endif

	assert(!!pt->ah_wait_list_length == !!(lws_intptr_t)pt->ah_wait_list);
bail:
	lwsl_info("%s: wsi %p: ah %p (tsi=%d, count = %d)\n", __func__,
		  (void *)wsi, (void *)ah, pt->tid, pt->ah_count_in_use);

	return 0;

nobody_usable_waiting:
	lwsl_info("%s: nobody usable waiting\n", __func__);
	_lws_destroy_ah(pt, ah);
	pt->ah_count_in_use--;

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

	if (!wsi->ah)
		return 0;

	n = wsi->ah->frag_index[h];
	if (!n)
		return 0;
	do {
		if (!frag_idx)
			return wsi->ah->frags[n].len;
		n = wsi->ah->frags[n].nfrag;
	} while (frag_idx-- && n);

	return 0;
}

LWS_VISIBLE int lws_hdr_total_length(struct lws *wsi, enum lws_token_indexes h)
{
	int n;
	int len = 0;

	if (!wsi->ah)
		return 0;

	n = wsi->ah->frag_index[h];
	if (!n)
		return 0;
	do {
		len += wsi->ah->frags[n].len;
		n = wsi->ah->frags[n].nfrag;
	} while (n);

	return len;
}

LWS_VISIBLE int lws_hdr_copy_fragment(struct lws *wsi, char *dst, int len,
				      enum lws_token_indexes h, int frag_idx)
{
	int n = 0;
	int f;

	if (!wsi->ah)
		return -1;

	f = wsi->ah->frag_index[h];

	if (!f)
		return -1;

	while (n < frag_idx) {
		f = wsi->ah->frags[f].nfrag;
		if (!f)
			return -1;
		n++;
	}

	if (wsi->ah->frags[f].len >= len)
		return -1;

	memcpy(dst, wsi->ah->data + wsi->ah->frags[f].offset,
	       wsi->ah->frags[f].len);
	dst[wsi->ah->frags[f].len] = '\0';

	return wsi->ah->frags[f].len;
}

LWS_VISIBLE int lws_hdr_copy(struct lws *wsi, char *dst, int len,
			     enum lws_token_indexes h)
{
	int toklen = lws_hdr_total_length(wsi, h);
	int n;

	if (toklen >= len)
		return -1;

	if (!wsi->ah)
		return -1;

	n = wsi->ah->frag_index[h];
	if (!n)
		return 0;

	do {
		if (wsi->ah->frags[n].len >= len)
			return -1;
		strncpy(dst, &wsi->ah->data[wsi->ah->frags[n].offset],
		        wsi->ah->frags[n].len);
		dst += wsi->ah->frags[n].len;
		len -= wsi->ah->frags[n].len;
		n = wsi->ah->frags[n].nfrag;
	} while (n);
	*dst = '\0';

	return toklen;
}

char *lws_hdr_simple_ptr(struct lws *wsi, enum lws_token_indexes h)
{
	int n;

	n = wsi->ah->frag_index[h];
	if (!n)
		return NULL;

	return wsi->ah->data + wsi->ah->frags[n].offset;
}

static int LWS_WARN_UNUSED_RESULT
lws_pos_in_bounds(struct lws *wsi)
{
	if (wsi->ah->pos <
	    (unsigned int)wsi->context->max_http_header_data)
		return 0;

	if ((int)wsi->ah->pos == wsi->context->max_http_header_data) {
		lwsl_err("Ran out of header data space\n");
		return 1;
	}

	/*
	 * with these tests everywhere, it should never be able to exceed
	 * the limit, only meet it
	 */
	lwsl_err("%s: pos %d, limit %d\n", __func__, wsi->ah->pos,
		 wsi->context->max_http_header_data);
	assert(0);

	return 1;
}

int LWS_WARN_UNUSED_RESULT
lws_hdr_simple_create(struct lws *wsi, enum lws_token_indexes h, const char *s)
{
	wsi->ah->nfrag++;
	if (wsi->ah->nfrag == ARRAY_SIZE(wsi->ah->frags)) {
		lwsl_warn("More hdr frags than we can deal with, dropping\n");
		return -1;
	}

	wsi->ah->frag_index[h] = wsi->ah->nfrag;

	wsi->ah->frags[wsi->ah->nfrag].offset = wsi->ah->pos;
	wsi->ah->frags[wsi->ah->nfrag].len = 0;
	wsi->ah->frags[wsi->ah->nfrag].nfrag = 0;

	do {
		if (lws_pos_in_bounds(wsi))
			return -1;

		wsi->ah->data[wsi->ah->pos++] = *s;
		if (*s)
			wsi->ah->frags[wsi->ah->nfrag].len++;
	} while (*s++);

	return 0;
}

signed char char_to_hex(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

static int LWS_WARN_UNUSED_RESULT
issue_char(struct lws *wsi, unsigned char c)
{
	unsigned short frag_len;

	if (lws_pos_in_bounds(wsi))
		return -1;

	frag_len = wsi->ah->frags[wsi->ah->nfrag].len;
	/*
	 * If we haven't hit the token limit, just copy the character into
	 * the header
	 */
	if (frag_len < wsi->ah->current_token_limit) {
		wsi->ah->data[wsi->ah->pos++] = c;
		if (c)
			wsi->ah->frags[wsi->ah->nfrag].len++;
		return 0;
	}

	/* Insert a null character when we *hit* the limit: */
	if (frag_len == wsi->ah->current_token_limit) {
		if (lws_pos_in_bounds(wsi))
			return -1;

		wsi->ah->data[wsi->ah->pos++] = '\0';
		lwsl_warn("header %i exceeds limit %d\n",
			  wsi->ah->parser_state,
			  wsi->ah->current_token_limit);
	}

	return 1;
}

int
lws_parse_urldecode(struct lws *wsi, uint8_t *_c)
{
	struct allocated_headers *ah = wsi->ah;
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
			if (issue_char(wsi, c) < 0)
				return -1;
			/* swallow the terminator */
			ah->frags[ah->nfrag].len--;
			/* link to next fragment */
			ah->frags[ah->nfrag].nfrag = ah->nfrag + 1;
			ah->nfrag++;
			if (ah->nfrag >= ARRAY_SIZE(ah->frags))
				goto excessive;
			/* start next fragment after the & */
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
		if (ah->nfrag >= ARRAY_SIZE(ah->frags))
			goto excessive;
		ah->frags[ah->nfrag].offset = ah->pos;
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
	struct allocated_headers *ah = wsi->ah;
	struct lws_context *context = wsi->context;
	unsigned int n, m;
	unsigned char c;
	int r, pos;

	assert(wsi->ah);

	do {
		(*len)--;
		c = *buf++;

		switch (ah->parser_state) {
		default:

			lwsl_parser("WSI_TOK_(%d) '%c'\n", ah->parser_state, c);

			/* collect into malloc'd buffers */
			/* optional initial space swallow */
			if (!ah->frags[ah->frag_index[ah->parser_state]].len &&
			    c == ' ')
				break;

			for (m = 0; m < ARRAY_SIZE(methods); m++)
				if (ah->parser_state == methods[m])
					break;
			if (m == ARRAY_SIZE(methods))
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
				return -1;
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
				return -1;
			if (n > 0)
				ah->parser_state = WSI_TOKEN_SKIPPING;

swallow:
			/* per-protocol end of headers management */

			if (ah->parser_state == WSI_TOKEN_CHALLENGE)
				goto set_parsing_complete;
			break;

			/* collecting and checking a name part */
		case WSI_TOKEN_NAME_PART:
			lwsl_parser("WSI_TOKEN_NAME_PART '%c' 0x%02X (mode=%d) "
				    "wsi->lextable_pos=%d\n", c, c, wsi->mode,
				    ah->lextable_pos);

			if (c >= 'A' && c <= 'Z')
				c += 'a' - 'A';

			pos = ah->lextable_pos;

			while (1) {
				if (lextable[pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
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
				if (lextable[pos] < FAIL_CHAR) { /* terminal marker */
					ah->lextable_pos = pos;
					break;
				}

				if (lextable[pos] == c) { /* goto */
					ah->lextable_pos = pos + (lextable[pos + 1]) +
							(lextable[pos + 2] << 8);
					break;
				}

				/* fall thru goto */
				pos += 3;
				/* continue */
			}

			/*
			 * Server needs to look out for unknown methods...
			 */
			if (ah->lextable_pos < 0 &&
			    (wsi->mode == LWSCM_HTTP_SERVING)) {
				/* this is not a header we know about */
				for (m = 0; m < ARRAY_SIZE(methods); m++)
					if (ah->frag_index[methods[m]]) {
						/*
						 * already had the method, no idea what
						 * this crap from the client is, ignore
						 */
						ah->parser_state = WSI_TOKEN_SKIPPING;
						break;
					}
				/*
				 * hm it's an unknown http method from a client in fact,
				 * it cannot be valid http
				 */
				if (m == ARRAY_SIZE(methods)) {
					/*
					 * are we set up to accept raw in these cases?
					 */
					if (lws_check_opt(wsi->vhost->options,
						   LWS_SERVER_OPTION_FALLBACK_TO_RAW))
						return 2; /* transition to raw */

					lwsl_info("Unknown method - dropping\n");
					goto forbid;
				}
				break;
			}
			/*
			 * ...otherwise for a client, let him ignore unknown headers
			 * coming from the server
			 */
			if (ah->lextable_pos < 0) {
				ah->parser_state = WSI_TOKEN_SKIPPING;
				break;
			}

			if (lextable[ah->lextable_pos] < FAIL_CHAR) {
				/* terminal state */

				n = ((unsigned int)lextable[ah->lextable_pos] << 8) |
						lextable[ah->lextable_pos + 1];

				lwsl_parser("known hdr %d\n", n);
				for (m = 0; m < ARRAY_SIZE(methods); m++)
					if (n == methods[m] &&
					    ah->frag_index[methods[m]]) {
						lwsl_warn("Duplicated method\n");
						return -1;
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

start_fragment:
			ah->nfrag++;
excessive:
			if (ah->nfrag == ARRAY_SIZE(ah->frags)) {
				lwsl_warn("More hdr frags than we can deal with\n");
				return -1;
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
				return -1;
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

	return 0;

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

	return 0;

forbid:
	lwsl_notice(" forbidding on uri sanitation\n");
	lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

	return -1;
}

LWS_VISIBLE int lws_frame_is_binary(struct lws *wsi)
{
	return wsi->ws->frame_is_binary;
}

void
lws_add_wsi_to_draining_ext_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (wsi->ws->rx_draining_ext)
		return;

	lwsl_ext("%s: RX EXT DRAINING: Adding to list\n", __func__);

	wsi->ws->rx_draining_ext = 1;
	wsi->ws->rx_draining_ext_list = pt->rx_draining_ext_list;
	pt->rx_draining_ext_list = wsi;
}

void
lws_remove_wsi_from_draining_ext_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws **w = &pt->rx_draining_ext_list;

	if (!wsi->ws->rx_draining_ext)
		return;

	lwsl_ext("%s: RX EXT DRAINING: Removing from list\n", __func__);

	wsi->ws->rx_draining_ext = 0;

	/* remove us from context draining ext list */
	while (*w) {
		if (*w == wsi) {
			/* if us, point it instead to who we were pointing to */
			*w = wsi->ws->rx_draining_ext_list;
			break;
		}
		w = &((*w)->ws->rx_draining_ext_list);
	}
	wsi->ws->rx_draining_ext_list = NULL;
}

/*
 * client-parser.c: lws_client_rx_sm() needs to be roughly kept in
 *   sync with changes here, esp related to ext draining
 */

int
lws_rx_sm(struct lws *wsi, unsigned char c)
{
	int callback_action = LWS_CALLBACK_RECEIVE;
	int ret = 0, rx_draining_ext = 0;
	struct lws_tokens eff_buf;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	int n;
#endif

	eff_buf.token = NULL;
	eff_buf.token_len = 0;
	if (wsi->socket_is_permanently_unusable)
		return -1;

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:
		if (wsi->ws->rx_draining_ext) {
			eff_buf.token = NULL;
			eff_buf.token_len = 0;
			lws_remove_wsi_from_draining_ext_list(wsi);
			rx_draining_ext = 1;
			lwsl_debug("%s: doing draining flow\n", __func__);

			goto drain_extension;
		}
		switch (wsi->ws->ietf_spec_revision) {
		case 13:
			/*
			 * no prepended frame key any more
			 */
			wsi->ws->all_zero_nonce = 1;
			goto handle_first;

		default:
			lwsl_warn("lws_rx_sm: unknown spec version %d\n",
				  wsi->ws->ietf_spec_revision);
			break;
		}
		break;
	case LWS_RXPS_04_mask_1:
		wsi->ws->mask[1] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_mask_2;
		break;
	case LWS_RXPS_04_mask_2:
		wsi->ws->mask[2] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_mask_3;
		break;
	case LWS_RXPS_04_mask_3:
		wsi->ws->mask[3] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;

		/*
		 * start from the zero'th byte in the XOR key buffer since
		 * this is the start of a frame with a new key
		 */

		wsi->ws->mask_idx = 0;

		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_1;
		break;

	/*
	 *  04 logical framing from the spec (all this is masked when incoming
	 *  and has to be unmasked)
	 *
	 * We ignore the possibility of extension data because we don't
	 * negotiate any extensions at the moment.
	 *
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-------+-+-------------+-------------------------------+
	 *   |F|R|R|R| opcode|R| Payload len |    Extended payload length    |
	 *   |I|S|S|S|  (4)  |S|     (7)     |             (16/63)           |
	 *   |N|V|V|V|       |V|             |   (if payload len==126/127)   |
	 *   | |1|2|3|       |4|             |                               |
	 *   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	 *   |     Extended payload length continued, if payload len == 127  |
	 *   + - - - - - - - - - - - - - - - +-------------------------------+
	 *   |                               |         Extension data        |
	 *   +-------------------------------+ - - - - - - - - - - - - - - - +
	 *   :                                                               :
	 *   +---------------------------------------------------------------+
	 *   :                       Application data                        :
	 *   +---------------------------------------------------------------+
	 *
	 *  We pass payload through to userland as soon as we get it, ignoring
	 *  FIN.  It's up to userland to buffer it up if it wants to see a
	 *  whole unfragmented block of the original size (which may be up to
	 *  2^63 long!)
	 */

	case LWS_RXPS_04_FRAME_HDR_1:
handle_first:

		wsi->ws->opcode = c & 0xf;
		wsi->ws->rsv = c & 0x70;
		wsi->ws->final = !!((c >> 7) & 1);

		switch (wsi->ws->opcode) {
		case LWSWSOPC_TEXT_FRAME:
		case LWSWSOPC_BINARY_FRAME:
			wsi->ws->rsv_first_msg = (c & 0x70);
			wsi->ws->frame_is_binary =
			     wsi->ws->opcode == LWSWSOPC_BINARY_FRAME;
			wsi->ws->first_fragment = 1;
			break;
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 0xb:
		case 0xc:
		case 0xd:
		case 0xe:
		case 0xf:
			lwsl_info("illegal opcode\n");
			return -1;
		}
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN:

		wsi->ws->this_frame_masked = !!(c & 0x80);

		switch (c & 0x7f) {
		case 126:
			/* control frames are not allowed to have big lengths */
			if (wsi->ws->opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
			break;
		case 127:
			/* control frames are not allowed to have big lengths */
			if (wsi->ws->opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
			break;
		default:
			wsi->ws->rx_packet_length = c & 0x7f;
			if (wsi->ws->this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else
				if (wsi->ws->rx_packet_length)
					wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
				else {
					wsi->lws_rx_parse_state = LWS_RXPS_NEW;
					goto spill;
				}
			break;
		}
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_2:
		wsi->ws->rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		wsi->ws->rx_packet_length |= c;
		if (wsi->ws->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_8:
		if (c & 0x80) {
			lwsl_warn("b63 of length must be zero\n");
			/* kill the connection */
			return -1;
		}
#if defined __LP64__
		wsi->ws->rx_packet_length = ((size_t)c) << 56;
#else
		wsi->ws->rx_packet_length = 0;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
		wsi->ws->rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
		wsi->ws->rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
		wsi->ws->rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		wsi->ws->rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		wsi->ws->rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		wsi->ws->rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		wsi->ws->rx_packet_length |= ((size_t)c);
		if (wsi->ws->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
		wsi->ws->mask[0] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
		wsi->ws->mask[1] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
		wsi->ws->mask[2] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
		wsi->ws->mask[3] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		wsi->ws->mask_idx = 0;
		if (wsi->ws->rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:
		assert(wsi->ws->rx_ubuf);

		if (wsi->ws->rx_draining_ext)
			goto drain_extension;

		if (wsi->ws->rx_ubuf_head + LWS_PRE >=
		    wsi->ws->rx_ubuf_alloc) {
			lwsl_err("Attempted overflow \n");
			return -1;
		}
		if (wsi->ws->all_zero_nonce)
			wsi->ws->rx_ubuf[LWS_PRE +
					 (wsi->ws->rx_ubuf_head++)] = c;
		else
			wsi->ws->rx_ubuf[LWS_PRE +
			       (wsi->ws->rx_ubuf_head++)] =
				   c ^ wsi->ws->mask[
					    (wsi->ws->mask_idx++) & 3];

		if (--wsi->ws->rx_packet_length == 0) {
			/* spill because we have the whole frame */
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}

		/*
		 * if there's no protocol max frame size given, we are
		 * supposed to default to context->pt_serv_buf_size
		 */
		if (!wsi->protocol->rx_buffer_size &&
		    wsi->ws->rx_ubuf_head != wsi->context->pt_serv_buf_size)
			break;

		if (wsi->protocol->rx_buffer_size &&
		    wsi->ws->rx_ubuf_head != wsi->protocol->rx_buffer_size)
			break;

		/* spill because we filled our rx buffer */
spill:
		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		lwsl_parser("spill on %s\n", wsi->protocol->name);

		switch (wsi->ws->opcode) {
		case LWSWSOPC_CLOSE:

			/* is this an acknowledgment of our close? */
			if (wsi->state == LWSS_AWAITING_CLOSE_ACK) {
				/*
				 * fine he has told us he is closing too, let's
				 * finish our close
				 */
				lwsl_parser("seen client close ack\n");
				return -1;
			}
			if (wsi->state == LWSS_RETURNED_CLOSE_ALREADY)
				/* if he sends us 2 CLOSE, kill him */
				return -1;

			if (lws_partial_buffered(wsi)) {
				/*
				 * if we're in the middle of something,
				 * we can't do a normal close response and
				 * have to just close our end.
				 */
				wsi->socket_is_permanently_unusable = 1;
				lwsl_parser("Closing on peer close due to Pending tx\n");
				return -1;
			}

			if (user_callback_handle_rxflow(
					wsi->protocol->callback, wsi,
					LWS_CALLBACK_WS_PEER_INITIATED_CLOSE,
					wsi->user_space,
					&wsi->ws->rx_ubuf[LWS_PRE],
					wsi->ws->rx_ubuf_head))
				return -1;

			lwsl_parser("server sees client close packet\n");
			wsi->state = LWSS_RETURNED_CLOSE_ALREADY;
			/* deal with the close packet contents as a PONG */
			wsi->ws->payload_is_close = 1;
			goto process_as_ping;

		case LWSWSOPC_PING:
			lwsl_info("received %d byte ping, sending pong\n",
						 wsi->ws->rx_ubuf_head);

			if (wsi->ws->ping_pending_flag) {
				/*
				 * there is already a pending ping payload
				 * we should just log and drop
				 */
				lwsl_parser("DROP PING since one pending\n");
				goto ping_drop;
			}
process_as_ping:
			/* control packets can only be < 128 bytes long */
			if (wsi->ws->rx_ubuf_head > 128 - 3) {
				lwsl_parser("DROP PING payload too large\n");
				goto ping_drop;
			}

			/* stash the pong payload */
			memcpy(wsi->ws->ping_payload_buf + LWS_PRE,
			       &wsi->ws->rx_ubuf[LWS_PRE],
				wsi->ws->rx_ubuf_head);

			wsi->ws->ping_payload_len = wsi->ws->rx_ubuf_head;
			wsi->ws->ping_pending_flag = 1;

			/* get it sent as soon as possible */
			lws_callback_on_writable(wsi);
ping_drop:
			wsi->ws->rx_ubuf_head = 0;
			return 0;

		case LWSWSOPC_PONG:
			lwsl_info("received pong\n");
			lwsl_hexdump(&wsi->ws->rx_ubuf[LWS_PRE],
			             wsi->ws->rx_ubuf_head);

			if (wsi->pending_timeout ==
				       PENDING_TIMEOUT_WS_PONG_CHECK_GET_PONG) {
				lwsl_info("received expected PONG on wsi %p\n",
						wsi);
				lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
			}

			/* issue it */
			callback_action = LWS_CALLBACK_RECEIVE_PONG;
			break;

		case LWSWSOPC_TEXT_FRAME:
		case LWSWSOPC_BINARY_FRAME:
		case LWSWSOPC_CONTINUATION:
			break;

		default:
			lwsl_parser("passing opc %x up to exts\n",
				    wsi->ws->opcode);
			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->ws->rx_ubuf[LWS_PRE];
			eff_buf.token_len = wsi->ws->rx_ubuf_head;

			if (lws_ext_cb_active(wsi,
					      LWS_EXT_CB_EXTENDED_PAYLOAD_RX,
					      &eff_buf, 0) <= 0)
				/* not handle or fail */
				lwsl_ext("ext opc opcode 0x%x unknown\n",
					 wsi->ws->opcode);

			wsi->ws->rx_ubuf_head = 0;
			return 0;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using lws_write
		 */

		eff_buf.token = &wsi->ws->rx_ubuf[LWS_PRE];
		eff_buf.token_len = wsi->ws->rx_ubuf_head;

		if (wsi->ws->opcode == LWSWSOPC_PONG && !eff_buf.token_len)
			goto already_done;

drain_extension:
		lwsl_ext("%s: passing %d to ext\n", __func__, eff_buf.token_len);

		if (wsi->state == LWSS_RETURNED_CLOSE_ALREADY ||
		    wsi->state == LWSS_AWAITING_CLOSE_ACK)
			goto already_done;
#if !defined(LWS_WITHOUT_EXTENSIONS)
		n = lws_ext_cb_active(wsi, LWS_EXT_CB_PAYLOAD_RX, &eff_buf, 0);
#endif
		/*
		 * eff_buf may be pointing somewhere completely different now,
		 * it's the output
		 */
		wsi->ws->first_fragment = 0;
#if !defined(LWS_WITHOUT_EXTENSIONS)
		if (n < 0) {
			/*
			 * we may rely on this to get RX, just drop connection
			 */
			wsi->socket_is_permanently_unusable = 1;
			return -1;
		}
#endif
		if (rx_draining_ext && eff_buf.token_len == 0)
			goto already_done;

		if (
#if !defined(LWS_WITHOUT_EXTENSIONS)
		    n &&
#endif
		    eff_buf.token_len)
			/* extension had more... main loop will come back */
			lws_add_wsi_to_draining_ext_list(wsi);
		else
			lws_remove_wsi_from_draining_ext_list(wsi);

		if (eff_buf.token_len > 0 ||
		    callback_action == LWS_CALLBACK_RECEIVE_PONG) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback) {
				if (callback_action == LWS_CALLBACK_RECEIVE_PONG)
					lwsl_info("Doing pong callback\n");

				ret = user_callback_handle_rxflow(
						wsi->protocol->callback,
						wsi, (enum lws_callback_reasons)
						     callback_action,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
			}
			else
				lwsl_err("No callback on payload spill!\n");
		}

already_done:
		wsi->ws->rx_ubuf_head = 0;
		break;
	}

	return ret;

illegal_ctl_length:

	lwsl_warn("Control frame with xtended length is illegal\n");
	/* kill the connection */
	return -1;
}

LWS_VISIBLE size_t
lws_remaining_packet_payload(struct lws *wsi)
{
	return wsi->ws->rx_packet_length;
}

/* Once we reach LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED, we know how much
 * to expect in that state and can deal with it in bulk more efficiently.
 */

int
lws_payload_until_length_exhausted(struct lws *wsi, unsigned char **buf,
				   size_t *len)
{
	unsigned char *buffer = *buf, mask[4];
	int buffer_size, n;
	unsigned int avail;
	char *rx_ubuf;

	if (wsi->protocol->rx_buffer_size)
		buffer_size = (int)wsi->protocol->rx_buffer_size;
	else
		buffer_size = wsi->context->pt_serv_buf_size;
	avail = buffer_size - wsi->ws->rx_ubuf_head;

	/* do not consume more than we should */
	if (avail > wsi->ws->rx_packet_length)
		avail = (unsigned int)wsi->ws->rx_packet_length;

	/* do not consume more than what is in the buffer */
	if (avail > *len)
		avail = (unsigned int)(*len);

	/* we want to leave 1 byte for the parser to handle properly */
	if (avail <= 1)
		return 0;

	avail--;
	rx_ubuf = wsi->ws->rx_ubuf + LWS_PRE + wsi->ws->rx_ubuf_head;
	if (wsi->ws->all_zero_nonce)
		memcpy(rx_ubuf, buffer, avail);
	else {

		for (n = 0; n < 4; n++)
			mask[n] = wsi->ws->mask[(wsi->ws->mask_idx + n) & 3];

		/* deal with 4-byte chunks using unwrapped loop */
		n = avail >> 2;
		while (n--) {
			*(rx_ubuf++) = *(buffer++) ^ mask[0];
			*(rx_ubuf++) = *(buffer++) ^ mask[1];
			*(rx_ubuf++) = *(buffer++) ^ mask[2];
			*(rx_ubuf++) = *(buffer++) ^ mask[3];
		}
		/* and the remaining bytes bytewise */
		for (n = 0; n < (int)(avail & 3); n++)
			*(rx_ubuf++) = *(buffer++) ^ mask[n];

		wsi->ws->mask_idx = (wsi->ws->mask_idx + avail) & 3;
	}

	(*buf) += avail;
	wsi->ws->rx_ubuf_head += avail;
	wsi->ws->rx_packet_length -= avail;
	*len -= avail;

	return avail;
}
