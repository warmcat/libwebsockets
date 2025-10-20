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

#ifdef LWS_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/* lws_buflist */

int
lws_buflist_append_segment(struct lws_buflist **head, const uint8_t *buf,
			   size_t len)
{
	struct lws_buflist *nbuf;
	int first = !*head;
	void *p = *head;
	int sanity = 1024;

	if (!buf)
		return -1;

	assert(len);

	/* append at the tail */
	while (*head) {
		if (!--sanity) {
			lwsl_err("%s: buflist reached sanity limit\n", __func__);
			return -1;
		}
		if (*head == (*head)->next) {
			lwsl_err("%s: corrupt list points to self\n", __func__);
			return -1;
		}
		head = &((*head)->next);
	}

	(void)p;
	lwsl_info("%s: len %u first %d %p\n", __func__, (unsigned int)len,
					      first, p);

	nbuf = (struct lws_buflist *)lws_malloc(sizeof(struct lws_buflist) +
						len + LWS_PRE + 1, __func__);
	if (!nbuf) {
		lwsl_err("%s: OOM\n", __func__);
		return -1;
	}

	nbuf->len = len;
	nbuf->pos = 0;
	nbuf->next = NULL;

	/* whoever consumes this might need LWS_PRE from the start... */
	p = (uint8_t *)nbuf + sizeof(*nbuf) + LWS_PRE;
	memcpy(p, buf, len);

	*head = nbuf;

	return first; /* returns 1 if first segment just created */
}

static int
lws_buflist_destroy_segment(struct lws_buflist **head)
{
	struct lws_buflist *old = *head;

	assert(*head);
	*head = old->next;
	old->next = NULL;
	old->pos = old->len = 0;
	lws_free(old);

	return !*head; /* returns 1 if last segment just destroyed */
}

void
lws_buflist_destroy_all_segments(struct lws_buflist **head)
{
	struct lws_buflist *p = *head, *p1;

	while (p) {
		p1 = p->next;
		p->next = NULL;
		lws_free(p);
		p = p1;
	}

	*head = NULL;
}

size_t
lws_buflist_next_segment_len(struct lws_buflist **head, uint8_t **buf)
{
	struct lws_buflist *b = (*head);

	if (buf)
		*buf = NULL;

	if (!b)
		return 0;	/* there is no next segment len */

	if (!b->len && b->next)
		if (lws_buflist_destroy_segment(head))
			return 0;

	b = (*head);
	if (!b)
		return 0;	/* there is no next segment len */

	assert(b->pos < b->len);

	if (buf)
		*buf = ((uint8_t *)b) + sizeof(*b) + b->pos + LWS_PRE;

	return b->len - b->pos;
}

size_t
lws_buflist_use_segment(struct lws_buflist **head, size_t len)
{
	struct lws_buflist *b = (*head);

	assert(b);
	assert(len);
	assert(b->pos + len <= b->len);

	b->pos = b->pos + (size_t)len;

	assert(b->pos <= b->len);

	if (b->pos < b->len)
		return (unsigned int)(b->len - b->pos);

	if (lws_buflist_destroy_segment(head))
		/* last segment was just destroyed */
		return 0;

	return lws_buflist_next_segment_len(head, NULL);
}

size_t
lws_buflist_total_len(struct lws_buflist **head)
{
	struct lws_buflist *p = *head;
	size_t size = 0;

	while (p) {
		size += p->len;
		p = p->next;
	}

	return size;
}

int
lws_buflist_linear_copy(struct lws_buflist **head, size_t ofs, uint8_t *buf,
			size_t len)
{
	struct lws_buflist *p = *head;
	uint8_t *obuf = buf;
	size_t s;

	while (p && len) {
		if (ofs < p->len) {
			s = p->len - ofs;
			if (s > len)
				s = len;
			memcpy(buf, ((uint8_t *)&p[1]) + LWS_PRE + ofs, s);
			len -= s;
			buf += s;
			ofs = 0;
		} else
			ofs -= p->len;
		p = p->next;
	}

	return lws_ptr_diff(buf, obuf);
}

int
lws_buflist_linear_use(struct lws_buflist **head, uint8_t *buf, size_t len)
{
	uint8_t *obuf = buf;
	size_t s;

	while (*head && len) {
		s = (*head)->len - (*head)->pos;
		if (s > len)
			s = len;
		memcpy(buf, ((uint8_t *)((*head) + 1)) +
			    LWS_PRE + (*head)->pos, s);
		len -= s;
		buf += s;
		lws_buflist_use_segment(head, s);
	}

	return lws_ptr_diff(buf, obuf);
}

int
lws_buflist_fragment_use(struct lws_buflist **head, uint8_t *buf,
			 size_t len, char *frag_first, char *frag_fin)
{
	uint8_t *obuf = buf;
	size_t s;

	if (!*head)
		return 0;

	s = (*head)->len - (*head)->pos;
	if (s > len)
		s = len;

	if (frag_first)
		*frag_first = !(*head)->pos;

	if (frag_fin)
		*frag_fin = (*head)->pos + s == (*head)->len;

	if (!buf || !len)
		return 0;

	memcpy(buf, ((uint8_t *)((*head) + 1)) + LWS_PRE + (*head)->pos, s);
	len -= s;
	buf += s;
	lws_buflist_use_segment(head, s);

	return lws_ptr_diff(buf, obuf);
}

#if defined(_DEBUG)
void
lws_buflist_describe(struct lws_buflist **head, void *id, const char *reason)
{
#if !defined(LWS_WITH_NO_LOGS)
	struct lws_buflist *old;
	int n = 0;

	if (*head == NULL)
		lwsl_notice("%p: %s: buflist empty\n", id, reason);

	while (*head) {
		lwsl_notice("%p: %s: %d: %llu / %llu (%llu left)\n", id,
			    reason, n,
			    (unsigned long long)(*head)->pos,
			    (unsigned long long)(*head)->len,
			    (unsigned long long)(*head)->len - (*head)->pos);
		old = *head;
		head = &((*head)->next);
		if (*head == old) {
			lwsl_err("%s: next points to self\n", __func__);
			break;
		}
		n++;
	}
#endif
}
#endif

LWS_VISIBLE LWS_EXTERN void *
lws_buflist_get_frag_start_or_NULL(struct lws_buflist **head)
{
	struct lws_buflist *b = (*head);

	if (!b)
		return NULL;	/* there is no segment to work on */

	return ((uint8_t *)b) + sizeof(*b) + LWS_PRE;
}

lws_stateful_ret_t
lws_flow_feed(lws_flow_t *flow)
{
	if (flow->len)
		return LWS_SRET_OK;

	if (flow->blseglen)
		lws_buflist_use_segment(&flow->bl, flow->blseglen);

	flow->len = lws_buflist_next_segment_len(&flow->bl,
						 (uint8_t **)&flow->data);
	flow->blseglen = (uint32_t)flow->len;

	return flow->len ||
	       flow->state != LWSDLOFLOW_STATE_READ ? LWS_SRET_OK :
					              LWS_SRET_WANT_INPUT;
}

lws_stateful_ret_t
lws_flow_req(lws_flow_t *flow)
{
#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	int32_t est, ask;
#endif

	lws_flow_feed(flow);

	if (!flow->h || flow->state != LWSDLOFLOW_STATE_READ)
		return LWS_SRET_OK;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	if (flow->window) {
		est = lws_ss_get_est_peer_tx_credit(flow->h) +
			(int)lws_buflist_total_len(&flow->bl) -
			(int)flow->blseglen + (int)flow->len;

		if (est < flow->window) {
			ask = (int32_t)(flow->window - est);
			if (ask > (flow->window / 2) || !est)
				lws_ss_add_peer_tx_credit(flow->h, ask);
		}
	}
#endif

	return flow->len ||
	       flow->state != LWSDLOFLOW_STATE_READ ? LWS_SRET_OK :
					              LWS_SRET_WANT_INPUT;
}


static void
lws_wsmsg_transfer(lws_wsmsg_info_t *info)
{
	struct lws_buflist *bl = info->private_heads[info->private_source_idx],
			   *ubl = *info->head_upstream;

	/*
	 * If we arrived at a complete message, and the upstream is
	 * not blocked awaiting EOM, transfer the segments to the
	 * upstream, emptying the private buflist
	 */

	if (!bl) {
		lwsl_notice("%s: denied: no content to transfer\n", __func__);
		return;
	}

	while (bl && bl->next)
		bl = bl->next;

	if (bl->awaiting_eom) {
		lwsl_notice("%s: denied: head awaiting EOM\n", __func__);
		return;
	}

	if (!*info->head_upstream) {
		/*
		 * If the upstream is empty, create it by pointing
		 * it to the whole private chain, taking ownership
		 */

		*info->head_upstream = info->private_heads[info->private_source_idx];
		info->private_heads[info->private_source_idx] = NULL;

		lwsl_notice("%s: transferred: head -> head_upstream\n", __func__);

		return;
	}


	/* find the end of the existing upstream */

	while (ubl && ubl->next)
		ubl = ubl->next;

	if (ubl->awaiting_eom) {
		lwsl_notice("%s: denied: no content to transfer\n", __func__);
		return;
	}

	/*
	 * Add the private buflist on to the end of
	 * the upstream buflist, taking ownership
	 */

	ubl->next					= info->private_heads[info->private_source_idx];
	info->private_heads[info->private_source_idx]	= NULL; /* now it transferred upstream, private owns nothing */
}

int
lws_wsmsg_append(lws_wsmsg_info_t *info)
{
	struct lws_buflist *bl;

	/*
	 * if there's nothing already stored, the new message is complete,
	 * and the upstream is either empty, or is not blocked awaiting EOM,
	 * then just apply the message directly to the upstream.
	 */

	if (!info->private_heads[info->private_source_idx] &&
	    (info->ss_flags == (LWSSS_FLAG_SOM | LWSSS_FLAG_EOM)) &&
	    (!(*info->head_upstream) || !(*info->head_upstream)->awaiting_eom)) {

		lwsl_notice("%s: directly applying upstream\n", __func__);

		if (lws_buflist_append_segment(info->head_upstream, info->buf, info->len) < 0)
			return -1;

		/*
		 * Let's tag the tail buflist we just added,
		 * with extra information useful for debugging
		 */

		bl = *info->head_upstream;
	} else {
		/*
		 * Otherwise, apply the message to the private buflist first
		 */

		lwsl_notice("%s: applying via private buflist\n", __func__);

		if (lws_buflist_append_segment(&info->private_heads[info->private_source_idx],
					       info->buf, info->len) < 0)
			return -1;

		bl = info->private_heads[info->private_source_idx];
	}

	while (bl && bl->next)
		bl = bl->next;

	if (!bl)
		return 0;

	bl->awaiting_eom	= !(info->ss_flags & LWSSS_FLAG_EOM);
	bl->src_channel		= (unsigned char)info->private_source_idx;

	lws_wsmsg_transfer(info);

	return 0;
}

void
lws_wsmsg_destroy(struct lws_buflist *private_heads[], size_t count_private_heads)
{
	size_t m = 0;

	while (m < count_private_heads)
		lws_buflist_destroy_all_segments(&private_heads[m++]);
}

