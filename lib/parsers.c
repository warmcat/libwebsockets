/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
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

unsigned char lextable[] = {
	#include "lextable.h"
};

#define FAIL_CHAR 0x08

int LWS_WARN_UNUSED_RESULT
lextable_decode(int pos, char c)
{
	if (c >= 'A' && c <= 'Z')
		c += 'a' - 'A';

	while (1) {
		if (lextable[pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
			if ((lextable[pos] & 0x7f) != c)
				return -1;
			/* fall thru */
			pos++;
			if (lextable[pos] == FAIL_CHAR)
				return -1;
			return pos;
		}

		if (lextable[pos] == FAIL_CHAR)
			return -1;

		/* b7 = 0, end or 3-byte */
		if (lextable[pos] < FAIL_CHAR) /* terminal marker */
			return pos;

		if (lextable[pos] == c) /* goto */
			return pos + (lextable[pos + 1]) +
						(lextable[pos + 2] << 8);
		/* fall thru goto */
		pos += 3;
		/* continue */
	}
}

void
lws_reset_header_table(struct lws *wsi)
{
	/* init the ah to reflect no headers or data have appeared yet */
	memset(wsi->u.hdr.ah->frag_index, 0, sizeof(wsi->u.hdr.ah->frag_index));
	wsi->u.hdr.ah->nfrag = 0;
	wsi->u.hdr.ah->pos = 0;
}

int LWS_WARN_UNUSED_RESULT
lws_allocate_header_table(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_pollargs pa;
	struct lws **pwsi;
	int n;

	lwsl_info("%s: wsi %p: ah %p (tsi %d)\n", __func__, (void *)wsi,
		 (void *)wsi->u.hdr.ah, wsi->tsi);

	/* if we are already bound to one, just clear it down */
	if (wsi->u.hdr.ah) {
		lwsl_err("cleardown\n");
		goto reset;
	}

	lws_pt_lock(pt);
	pwsi = &pt->ah_wait_list;
	while (*pwsi) {
		if (*pwsi == wsi) {
			/* if already waiting on list, if no new ah just ret */
			if (pt->ah_count_in_use ==
			    context->max_http_header_pool) {
				lwsl_err("ah wl denied\n");
				goto bail;
			}
			/* new ah.... remove ourselves from waiting list */
			*pwsi = wsi->u.hdr.ah_wait_list;
			wsi->u.hdr.ah_wait_list = NULL;
			pt->ah_wait_list_length--;
			break;
		}
		pwsi = &(*pwsi)->u.hdr.ah_wait_list;
	}
	/*
	 * pool is all busy... add us to waiting list and return that we
	 * weren't able to deliver it right now
	 */
	if (pt->ah_count_in_use == context->max_http_header_pool) {
		lwsl_info("%s: adding %p to ah waiting list\n", __func__, wsi);
		wsi->u.hdr.ah_wait_list = pt->ah_wait_list;
		pt->ah_wait_list = wsi;
		pt->ah_wait_list_length++;

		/* we cannot accept input then */

		_lws_change_pollfd(wsi, LWS_POLLIN, 0, &pa);
		goto bail;
	}

	for (n = 0; n < context->max_http_header_pool; n++)
		if (!pt->ah_pool[n].in_use)
			break;

	/* if the count of in use said something free... */
	assert(n != context->max_http_header_pool);

	wsi->u.hdr.ah = &pt->ah_pool[n];
	wsi->u.hdr.ah->in_use = 1;
	pt->ah_count_in_use++;

	_lws_change_pollfd(wsi, 0, LWS_POLLIN, &pa);

	lwsl_info("%s: wsi %p: ah %p: count %d (on exit)\n", __func__,
		  (void *)wsi, (void *)wsi->u.hdr.ah, pt->ah_count_in_use);

	lws_pt_unlock(pt);

reset:
	lws_reset_header_table(wsi);
	time(&wsi->u.hdr.ah->assigned);

	return 0;

bail:
	lws_pt_unlock(pt);

	return 1;
}

int lws_free_header_table(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	struct allocated_headers *ah = wsi->u.hdr.ah;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_pollargs pa;
	struct lws **pwsi;
	time_t now;

	lwsl_info("%s: wsi %p: ah %p (tsi=%d, count = %d)\n", __func__, (void *)wsi,
		 (void *)wsi->u.hdr.ah, wsi->tsi, pt->ah_count_in_use);

	lws_pt_lock(pt);

	pwsi = &pt->ah_wait_list;
	if (!wsi->u.hdr.ah) { /* remove from wait list if that's all */
		if (wsi->socket_is_permanently_unusable)
			while (*pwsi) {
				if (*pwsi == wsi) {
					lwsl_info("%s: wsi %p, removing from wait list\n",
							__func__, wsi);
					*pwsi = wsi->u.hdr.ah_wait_list;
					wsi->u.hdr.ah_wait_list = NULL;
					pt->ah_wait_list_length--;
					goto bail;
				}
				pwsi = &(*pwsi)->u.hdr.ah_wait_list;
			}

		goto bail;
	}
	time(&now);
	if (now - wsi->u.hdr.ah->assigned > 3)
		lwsl_err("header assign - free time %d\n",
			 (int)(now - wsi->u.hdr.ah->assigned));
	/* if we think we're freeing one, there should be one to free */
	assert(pt->ah_count_in_use > 0);
	/* and he should have been in use */
	assert(wsi->u.hdr.ah->in_use);
	wsi->u.hdr.ah = NULL;

	if (!*pwsi) {
		ah->in_use = 0;
		pt->ah_count_in_use--;

		goto bail;
	}

	/* somebody else on same tsi is waiting, give it to him */

	lwsl_info("pt wait list %p\n", *pwsi);
	while ((*pwsi)->u.hdr.ah_wait_list)
		pwsi = &(*pwsi)->u.hdr.ah_wait_list;

	wsi = *pwsi;
	lwsl_info("last wsi in wait list %p\n", wsi);

	wsi->u.hdr.ah = ah;
	lws_reset_header_table(wsi);
	time(&wsi->u.hdr.ah->assigned);

	assert(wsi->position_in_fds_table != -1);

	lwsl_info("%s: Enabling %p POLLIN\n", __func__, wsi);
	/* his wait is over, let him progress */
	_lws_change_pollfd(wsi, 0, LWS_POLLIN, &pa);

	/* point prev guy to next guy in list instead */
	*pwsi = wsi->u.hdr.ah_wait_list;
	wsi->u.hdr.ah_wait_list = NULL;
	pt->ah_wait_list_length--;

	assert(!!pt->ah_wait_list_length == !!(int)(long)pt->ah_wait_list);
bail:
	lws_pt_unlock(pt);

	return 0;
}

/**
 * lws_hdr_fragment_length: report length of a single fragment of a header
 *		The returned length does not include the space for a
 *		terminating '\0'
 *
 * @wsi: websocket connection
 * @h: which header index we are interested in
 * @frag_idx: which fragment of @h we want to get the length of
 */

LWS_VISIBLE int
lws_hdr_fragment_length(struct lws *wsi, enum lws_token_indexes h, int frag_idx)
{
	int n;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		if (!frag_idx)
			return wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].nfrag;
	} while (frag_idx-- && n);

	return 0;
}

/**
 * lws_hdr_total_length: report length of all fragments of a header totalled up
 *		The returned length does not include the space for a
 *		terminating '\0'
 *
 * @wsi: websocket connection
 * @h: which header index we are interested in
 */

LWS_VISIBLE int lws_hdr_total_length(struct lws *wsi, enum lws_token_indexes h)
{
	int n;
	int len = 0;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		len += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].nfrag;
	} while (n);

	return len;
}

/**
 * lws_hdr_copy_fragment: copy a single fragment of the given header to a buffer
 *		The buffer length @len must include space for an additional
 *		terminating '\0', or it will fail returning -1.
 *		If the requested fragment index is not present, it fails
 *		returning -1.
 *
 * @wsi: websocket connection
 * @dst: destination buffer
 * @len: length of destination buffer
 * @h: which header index we are interested in
 * @frag_index: which fragment of @h we want to copy
 */

LWS_VISIBLE int lws_hdr_copy_fragment(struct lws *wsi, char *dst, int len,
				      enum lws_token_indexes h, int frag_idx)
{
	int n = 0;
	int f = wsi->u.hdr.ah->frag_index[h];

	if (!f)
		return -1;

	while (n < frag_idx) {
		f = wsi->u.hdr.ah->frags[f].nfrag;
		if (!f)
			return -1;
		n++;
	}

	if (wsi->u.hdr.ah->frags[f].len >= len)
		return -1;

	memcpy(dst, wsi->u.hdr.ah->data + wsi->u.hdr.ah->frags[f].offset,
	       wsi->u.hdr.ah->frags[f].len);
	dst[wsi->u.hdr.ah->frags[f].len] = '\0';

	return wsi->u.hdr.ah->frags[f].len;
}

/**
 * lws_hdr_copy: copy a single fragment of the given header to a buffer
 *		The buffer length @len must include space for an additional
 *		terminating '\0', or it will fail returning -1.
 *
 * @wsi: websocket connection
 * @dst: destination buffer
 * @len: length of destination buffer
 * @h: which header index we are interested in
 */

LWS_VISIBLE int lws_hdr_copy(struct lws *wsi, char *dst, int len,
			     enum lws_token_indexes h)
{
	int toklen = lws_hdr_total_length(wsi, h);
	int n;

	if (toklen >= len)
		return -1;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;

	do {
		strcpy(dst, &wsi->u.hdr.ah->data[wsi->u.hdr.ah->frags[n].offset]);
		dst += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].nfrag;
	} while (n);

	return toklen;
}

char *lws_hdr_simple_ptr(struct lws *wsi, enum lws_token_indexes h)
{
	int n;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return NULL;

	return wsi->u.hdr.ah->data + wsi->u.hdr.ah->frags[n].offset;
}

int LWS_WARN_UNUSED_RESULT
lws_pos_in_bounds(struct lws *wsi)
{
	if (wsi->u.hdr.ah->pos < wsi->context->max_http_header_data)
		return 0;

	if (wsi->u.hdr.ah->pos == wsi->context->max_http_header_data) {
		lwsl_err("Ran out of header data space\n");
		return 1;
	}

	/*
	 * with these tests everywhere, it should never be able to exceed
	 * the limit, only meet the limit
	 */

	lwsl_err("%s: pos %d, limit %d\n", __func__, wsi->u.hdr.ah->pos,
		 wsi->context->max_http_header_data);
	assert(0);

	return 1;
}

int LWS_WARN_UNUSED_RESULT
lws_hdr_simple_create(struct lws *wsi, enum lws_token_indexes h, const char *s)
{
	wsi->u.hdr.ah->nfrag++;
	if (wsi->u.hdr.ah->nfrag == ARRAY_SIZE(wsi->u.hdr.ah->frags)) {
		lwsl_warn("More hdr frags than we can deal with, dropping\n");
		return -1;
	}

	wsi->u.hdr.ah->frag_index[h] = wsi->u.hdr.ah->nfrag;

	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].offset = wsi->u.hdr.ah->pos;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].len = 0;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].nfrag = 0;

	do {
		if (lws_pos_in_bounds(wsi))
			return -1;

		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = *s;
		if (*s)
			wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].len++;
	} while (*s++);

	return 0;
}

static signed char char_to_hex(const char c)
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

	frag_len = wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].len;
	/*
	 * If we haven't hit the token limit, just copy the character into
	 * the header
	 */
	if (frag_len < wsi->u.hdr.current_token_limit) {
		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = c;
		if (c)
			wsi->u.hdr.ah->frags[wsi->u.hdr.ah->nfrag].len++;
		return 0;
	}

	/* Insert a null character when we *hit* the limit: */
	if (frag_len == wsi->u.hdr.current_token_limit) {
		if (lws_pos_in_bounds(wsi))
			return -1;
		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = '\0';
		lwsl_warn("header %i exceeds limit %d\n",
			  wsi->u.hdr.parser_state, wsi->u.hdr.current_token_limit);
	}

	return 1;
}

int LWS_WARN_UNUSED_RESULT
lws_parse(struct lws *wsi, unsigned char c)
{
	static const unsigned char methods[] = {
		WSI_TOKEN_GET_URI,
		WSI_TOKEN_POST_URI,
		WSI_TOKEN_OPTIONS_URI,
		WSI_TOKEN_PUT_URI,
		WSI_TOKEN_PATCH_URI,
		WSI_TOKEN_DELETE_URI,
	};
	struct allocated_headers *ah = wsi->u.hdr.ah;
	struct lws_context *context = wsi->context;
	unsigned int n, m, enc = 0;

	assert(wsi->u.hdr.ah);

	switch (wsi->u.hdr.parser_state) {
	default:

		lwsl_parser("WSI_TOK_(%d) '%c'\n", wsi->u.hdr.parser_state, c);

		/* collect into malloc'd buffers */
		/* optional initial space swallow */
		if (!ah->frags[ah->frag_index[wsi->u.hdr.parser_state]].len &&
		    c == ' ')
			break;

		for (m = 0; m < ARRAY_SIZE(methods); m++)
			if (wsi->u.hdr.parser_state == methods[m])
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

			/* begin parsing HTTP version: */
			if (issue_char(wsi, '\0') < 0)
				return -1;
			wsi->u.hdr.parser_state = WSI_TOKEN_HTTP;
			goto start_fragment;
		}

		/* special URI processing... convert %xx */

		switch (wsi->u.hdr.ues) {
		case URIES_IDLE:
			if (c == '%') {
				wsi->u.hdr.ues = URIES_SEEN_PERCENT;
				goto swallow;
			}
			break;
		case URIES_SEEN_PERCENT:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				if (issue_char(wsi, '%') < 0)
					return -1;
				wsi->u.hdr.ues = URIES_IDLE;
				/* continue on to assess c */
				break;
			}
			wsi->u.hdr.esc_stash = c;
			wsi->u.hdr.ues = URIES_SEEN_PERCENT_H1;
			goto swallow;

		case URIES_SEEN_PERCENT_H1:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				if (issue_char(wsi, '%') < 0)
					return -1;
				wsi->u.hdr.ues = URIES_IDLE;
				/* regurgitate + assess */
				if (lws_parse(wsi, wsi->u.hdr.esc_stash) < 0)
					return -1;
				/* continue on to assess c */
				break;
			}
			c = (char_to_hex(wsi->u.hdr.esc_stash) << 4) |
					char_to_hex(c);
			enc = 1;
			wsi->u.hdr.ues = URIES_IDLE;
			break;
		}

		/*
		 * special URI processing...
		 *  convert /.. or /... or /../ etc to /
		 *  convert /./ to /
		 *  convert // or /// etc to /
		 *  leave /.dir or whatever alone
		 */

		switch (wsi->u.hdr.ups) {
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
				wsi->u.hdr.post_literal_equal = 0;
				ah->frags[ah->nfrag].offset = ah->pos;
				ah->frags[ah->nfrag].len = 0;
				ah->frags[ah->nfrag].nfrag = 0;
				goto swallow;
			}
			/* uriencoded = in the name part, disallow */
			if (c == '=' && enc && !wsi->u.hdr.post_literal_equal)
				c = '_';

			/* after the real =, we don't care how many = */
			if (c == '=' && !enc)
				wsi->u.hdr.post_literal_equal = 1;

			/* + to space */
			if (c == '+' && !enc)
				c = ' ';
			/* issue the first / always */
			if (c == '/' && !ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS])
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_SEEN_SLASH:
			/* swallow subsequent slashes */
			if (c == '/')
				goto swallow;
			/* track and swallow the first . after / */
			if (c == '.') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT;
				goto swallow;
			}
			wsi->u.hdr.ups = URIPS_IDLE;
			break;
		case URIPS_SEEN_SLASH_DOT:
			/* swallow second . */
			if (c == '.') {
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
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT_DOT;
				goto swallow;
			}
			/* change /./ to / */
			if (c == '/') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
				goto swallow;
			}
			/* it was like /.dir ... regurgitate the . */
			wsi->u.hdr.ups = URIPS_IDLE;
			if (issue_char(wsi, '.') < 0)
				return -1;
			break;

		case URIPS_SEEN_SLASH_DOT_DOT:
			/* swallow prior .. chars and any subsequent . */
			if (c == '.')
				goto swallow;
			/* last issued was /, so another / == // */
			if (c == '/')
				goto swallow;
			/* last we issued was / so SEEN_SLASH */
			wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		}

		if (c == '?' && !enc &&
		    !ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS]) { /* start of URI arguments */
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

			wsi->u.hdr.post_literal_equal = 0;
			ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] = ah->nfrag;
			wsi->u.hdr.ups = URIPS_IDLE;
			goto swallow;
		}

check_eol:

		/* bail at EOL */
		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE &&
								  c == '\x0d') {
			c = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			lwsl_parser("*\n");
		}

		n = issue_char(wsi, c);
		if ((int)n < 0)
			return -1;
		if (n > 0)
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;

swallow:
		/* per-protocol end of headers management */

		if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
			goto set_parsing_complete;
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
		lwsl_parser("WSI_TOKEN_NAME_PART '%c' (mode=%d)\n", c, wsi->mode);

		wsi->u.hdr.lextable_pos =
				lextable_decode(wsi->u.hdr.lextable_pos, c);
		/*
		 * Server needs to look out for unknown methods...
		 */
		if (wsi->u.hdr.lextable_pos < 0 &&
		    wsi->mode == LWSCM_HTTP_SERVING) {
			/* this is not a header we know about */
			for (m = 0; m < ARRAY_SIZE(methods); m++)
				if (ah->frag_index[methods[m]]) {
					/*
					 * already had the method, no idea what
					 * this crap from the client is, ignore
					 */
					wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
					break;
				}
			/*
			 * hm it's an unknown http method from a client in fact,
			 * treat as dangerous
			 */
			if (m == ARRAY_SIZE(methods)) {
				lwsl_info("Unknown method - dropping\n");
				return -1;
			}
			break;
		}
		/*
		 * ...otherwise for a client, let him ignore unknown headers
		 * coming from the server
		 */
		if (wsi->u.hdr.lextable_pos < 0) {
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			break;
		}

		if (lextable[wsi->u.hdr.lextable_pos] < FAIL_CHAR) {
			/* terminal state */

			n = ((unsigned int)lextable[wsi->u.hdr.lextable_pos] << 8) |
					lextable[wsi->u.hdr.lextable_pos + 1];

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

			wsi->u.hdr.parser_state = (enum lws_token_indexes)
							(WSI_TOKEN_GET_URI + n);

			if (context->token_limits)
				wsi->u.hdr.current_token_limit =
					context->token_limits->token_limit[
						       wsi->u.hdr.parser_state];
			else
				wsi->u.hdr.current_token_limit =
					wsi->context->max_http_header_data;

			if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
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

		n = ah->frag_index[wsi->u.hdr.parser_state];
		if (!n) { /* first fragment */
			ah->frag_index[wsi->u.hdr.parser_state] = ah->nfrag;
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
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
		break;

	case WSI_TOKEN_SKIPPING_SAW_CR:
		lwsl_parser("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
		if (c == '\x0a') {
			wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
			wsi->u.hdr.lextable_pos = 0;
		} else
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
		break;
		/* we're done, ignore anything else */

	case WSI_PARSING_COMPLETE:
		lwsl_parser("WSI_PARSING_COMPLETE '%c'\n", c);
		break;
	}

	return 0;

set_parsing_complete:

	if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
		if (lws_hdr_total_length(wsi, WSI_TOKEN_VERSION))
			wsi->ietf_spec_revision =
			       atoi(lws_hdr_simple_ptr(wsi, WSI_TOKEN_VERSION));

		lwsl_parser("v%02d hdrs completed\n", wsi->ietf_spec_revision);
	}
	wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
	wsi->hdr_parsing_completed = 1;

	return 0;
}


/**
 * lws_frame_is_binary: true if the current frame was sent in binary mode
 *
 * @wsi: the connection we are inquiring about
 *
 * This is intended to be called from the LWS_CALLBACK_RECEIVE callback if
 * it's interested to see if the frame it's dealing with was sent in binary
 * mode.
 */

LWS_VISIBLE int lws_frame_is_binary(struct lws *wsi)
{
	return wsi->u.ws.frame_is_binary;
}

int
lws_rx_sm(struct lws *wsi, unsigned char c)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int callback_action = LWS_CALLBACK_RECEIVE;
	int ret = 0, n, rx_draining_ext = 0;
	struct lws_tokens eff_buf;

	if (wsi->socket_is_permanently_unusable)
		return -1;

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:
		if (wsi->u.ws.rx_draining_ext) {
			struct lws **w = &pt->rx_draining_ext_list;

			eff_buf.token = NULL;
			eff_buf.token_len = 0;
			wsi->u.ws.rx_draining_ext = 0;
			/* remove us from context draining ext list */
			while (*w) {
				if (*w == wsi) {
					*w = wsi->u.ws.rx_draining_ext_list;
					break;
				}
				w = &((*w)->u.ws.rx_draining_ext_list);
			}
			wsi->u.ws.rx_draining_ext_list = NULL;
			rx_draining_ext = 1;
			lwsl_err("%s: doing draining flow\n", __func__);

			goto drain_extension;
		}
		switch (wsi->ietf_spec_revision) {
		case 13:
			/*
			 * no prepended frame key any more
			 */
			wsi->u.ws.all_zero_nonce = 1;
			goto handle_first;

		default:
			lwsl_warn("lws_rx_sm: unknown spec version %d\n",
						       wsi->ietf_spec_revision);
			break;
		}
		break;
	case LWS_RXPS_04_mask_1:
		wsi->u.ws.mask[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_mask_2;
		break;
	case LWS_RXPS_04_mask_2:
		wsi->u.ws.mask[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_mask_3;
		break;
	case LWS_RXPS_04_mask_3:
		wsi->u.ws.mask[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;

		/*
		 * start from the zero'th byte in the XOR key buffer since
		 * this is the start of a frame with a new key
		 */

		wsi->u.ws.mask_idx = 0;

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

		wsi->u.ws.opcode = c & 0xf;
		wsi->u.ws.rsv = c & 0x70;
		wsi->u.ws.final = !!((c >> 7) & 1);

		switch (wsi->u.ws.opcode) {
		case LWSWSOPC_TEXT_FRAME:
		case LWSWSOPC_BINARY_FRAME:
			wsi->u.ws.rsv_first_msg = (c & 0x70);
			wsi->u.ws.frame_is_binary =
			     wsi->u.ws.opcode == LWSWSOPC_BINARY_FRAME;
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

		wsi->u.ws.this_frame_masked = !!(c & 0x80);

		switch (c & 0x7f) {
		case 126:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
			break;
		case 127:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
			break;
		default:
			wsi->u.ws.rx_packet_length = c & 0x7f;
			if (wsi->u.ws.this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else
				if (wsi->u.ws.rx_packet_length)
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
		wsi->u.ws.rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		wsi->u.ws.rx_packet_length |= c;
		if (wsi->u.ws.this_frame_masked)
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
		wsi->u.ws.rx_packet_length = ((size_t)c) << 56;
#else
		wsi->u.ws.rx_packet_length = 0;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		wsi->u.ws.rx_packet_length |= ((size_t)c);
		if (wsi->u.ws.this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
		wsi->u.ws.mask[0] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
		wsi->u.ws.mask[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
		wsi->u.ws.mask[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
		wsi->u.ws.mask[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		wsi->u.ws.mask_idx = 0;
		if (wsi->u.ws.rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:
		assert(wsi->u.ws.rx_ubuf);

		if (wsi->u.ws.rx_ubuf_head + LWS_PRE >=
		    wsi->u.ws.rx_ubuf_alloc) {
			lwsl_err("Attempted overflow \n");
			return -1;
		}
		if (wsi->u.ws.all_zero_nonce)
			wsi->u.ws.rx_ubuf[LWS_PRE +
					 (wsi->u.ws.rx_ubuf_head++)] = c;
		else
			wsi->u.ws.rx_ubuf[LWS_PRE +
			       (wsi->u.ws.rx_ubuf_head++)] =
				   c ^ wsi->u.ws.mask[
					    (wsi->u.ws.mask_idx++) & 3];

		if (--wsi->u.ws.rx_packet_length == 0) {
			/* spill because we have the whole frame */
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}

		/*
		 * if there's no protocol max frame size given, we are
		 * supposed to default to LWS_MAX_SOCKET_IO_BUF
		 */

		if (!wsi->protocol->rx_buffer_size &&
			 		wsi->u.ws.rx_ubuf_head !=
			 				  LWS_MAX_SOCKET_IO_BUF)
			break;
		else
			if (wsi->protocol->rx_buffer_size &&
					wsi->u.ws.rx_ubuf_head !=
						  wsi->protocol->rx_buffer_size)
			break;

		/* spill because we filled our rx buffer */
spill:
		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		lwsl_parser("spill on %s\n", wsi->protocol->name);

		switch (wsi->u.ws.opcode) {
		case LWSWSOPC_CLOSE:

			/* is this an acknowledgement of our close? */
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

			if (user_callback_handle_rxflow(
					wsi->protocol->callback, wsi,
					LWS_CALLBACK_WS_PEER_INITIATED_CLOSE,
					wsi->user_space,
					&wsi->u.ws.rx_ubuf[LWS_PRE],
					wsi->u.ws.rx_ubuf_head))
				return -1;

			lwsl_parser("server sees client close packet\n");
			wsi->state = LWSS_RETURNED_CLOSE_ALREADY;
			/* deal with the close packet contents as a PONG */
			wsi->u.ws.payload_is_close = 1;
			goto process_as_ping;

		case LWSWSOPC_PING:
			lwsl_info("received %d byte ping, sending pong\n",
						 wsi->u.ws.rx_ubuf_head);

			if (wsi->u.ws.ping_pending_flag) {
				/*
				 * there is already a pending ping payload
				 * we should just log and drop
				 */
				lwsl_parser("DROP PING since one pending\n");
				goto ping_drop;
			}
process_as_ping:
			/* control packets can only be < 128 bytes long */
			if (wsi->u.ws.rx_ubuf_head > 128 - 3) {
				lwsl_parser("DROP PING payload too large\n");
				goto ping_drop;
			}

			/* stash the pong payload */
			memcpy(wsi->u.ws.ping_payload_buf + LWS_PRE,
			       &wsi->u.ws.rx_ubuf[LWS_PRE],
				wsi->u.ws.rx_ubuf_head);

			wsi->u.ws.ping_payload_len = wsi->u.ws.rx_ubuf_head;
			wsi->u.ws.ping_pending_flag = 1;

			/* get it sent as soon as possible */
			lws_callback_on_writable(wsi);
ping_drop:
			wsi->u.ws.rx_ubuf_head = 0;
			return 0;

		case LWSWSOPC_PONG:
			lwsl_info("received pong\n");
			lwsl_hexdump(&wsi->u.ws.rx_ubuf[LWS_PRE],
			             wsi->u.ws.rx_ubuf_head);

			/* issue it */
			callback_action = LWS_CALLBACK_RECEIVE_PONG;
			break;

		case LWSWSOPC_TEXT_FRAME:
		case LWSWSOPC_BINARY_FRAME:
		case LWSWSOPC_CONTINUATION:
			break;

		default:
			lwsl_parser("passing opc %x up to exts\n",
				    wsi->u.ws.opcode);
			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->u.ws.rx_ubuf[LWS_PRE];
			eff_buf.token_len = wsi->u.ws.rx_ubuf_head;

			if (lws_ext_cb_active(wsi, LWS_EXT_CB_EXTENDED_PAYLOAD_RX,
					&eff_buf, 0) <= 0) /* not handle or fail */
				lwsl_ext("ext opc opcode 0x%x unknown\n",
							      wsi->u.ws.opcode);

			wsi->u.ws.rx_ubuf_head = 0;
			return 0;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using lws_write
		 */

		eff_buf.token = &wsi->u.ws.rx_ubuf[LWS_PRE];
		eff_buf.token_len = wsi->u.ws.rx_ubuf_head;

drain_extension:
		lwsl_ext("%s: passing %d to ext\n", __func__, eff_buf.token_len);

		if (wsi->state == LWSS_RETURNED_CLOSE_ALREADY ||
		    wsi->state == LWSS_AWAITING_CLOSE_ACK)
			goto already_done;

		n = lws_ext_cb_active(wsi, LWS_EXT_CB_PAYLOAD_RX, &eff_buf, 0);
		if (n < 0) {
			/*
			 * we may rely on this to get RX, just drop connection
			 */
			wsi->socket_is_permanently_unusable = 1;
			return -1;
		}

		if (rx_draining_ext && eff_buf.token_len == 0)
			goto already_done;

		if (n && eff_buf.token_len) {
			/* extension had more... main loop will come back */
			wsi->u.ws.rx_draining_ext = 1;
			wsi->u.ws.rx_draining_ext_list = pt->rx_draining_ext_list;
			pt->rx_draining_ext_list = wsi;
		}

		if (eff_buf.token_len > 0 ||
		    callback_action == LWS_CALLBACK_RECEIVE_PONG) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback) {

				if (callback_action == LWS_CALLBACK_RECEIVE_PONG)
					lwsl_info("Doing pong callback\n");

				ret = user_callback_handle_rxflow(
						wsi->protocol->callback,
						wsi,
						(enum lws_callback_reasons)callback_action,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
			}
			else
				lwsl_err("No callback on payload spill!\n");
		}

already_done:
		wsi->u.ws.rx_ubuf_head = 0;
		break;
	}

	return ret;

illegal_ctl_length:

	lwsl_warn("Control frame with xtended length is illegal\n");
	/* kill the connection */
	return -1;
}


/**
 * lws_remaining_packet_payload() - Bytes to come before "overall"
 *					      rx packet is complete
 * @wsi:		Websocket instance (available from user callback)
 *
 *	This function is intended to be called from the callback if the
 *  user code is interested in "complete packets" from the client.
 *  libwebsockets just passes through payload as it comes and issues a buffer
 *  additionally when it hits a built-in limit.  The LWS_CALLBACK_RECEIVE
 *  callback handler can use this API to find out if the buffer it has just
 *  been given is the last piece of a "complete packet" from the client --
 *  when that is the case lws_remaining_packet_payload() will return
 *  0.
 *
 *  Many protocols won't care becuse their packets are always small.
 */

LWS_VISIBLE size_t
lws_remaining_packet_payload(struct lws *wsi)
{
	return wsi->u.ws.rx_packet_length;
}
