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

	assert(buf);
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

	nbuf = (struct lws_buflist *)lws_malloc(sizeof(**head) + len, __func__);
	if (!nbuf) {
		lwsl_err("%s: OOM\n", __func__);
		return -1;
	}

	nbuf->len = len;
	nbuf->pos = 0;
	nbuf->next = NULL;

	p = (void *)nbuf->buf;
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
	if (!*head) {
		if (buf)
			*buf = NULL;

		return 0;
	}

	if (!(*head)->len && (*head)->next)
		lws_buflist_destroy_segment(head);

	if (!*head) {
		if (buf)
			*buf = NULL;

		return 0;
	}

	assert((*head)->pos < (*head)->len);

	if (buf)
		*buf = (*head)->buf + (*head)->pos;

	return (*head)->len - (*head)->pos;
}

int
lws_buflist_use_segment(struct lws_buflist **head, size_t len)
{
	assert(*head);
	assert(len);
	assert((*head)->pos + len <= (*head)->len);

	(*head)->pos += len;
	if ((*head)->pos == (*head)->len)
		lws_buflist_destroy_segment(head);

	if (!*head)
		return 0;

	return (int)((*head)->len - (*head)->pos);
}

void
lws_buflist_describe(struct lws_buflist **head, void *id)
{
	struct lws_buflist *old;
	int n = 0;

	if (*head == NULL)
		lwsl_notice("%p: buflist empty\n", id);

	while (*head) {
		lwsl_notice("%p: %d: %llu / %llu (%llu left)\n", id, n,
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
}
