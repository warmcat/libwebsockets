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

int
lws_dll2_foreach_safe(struct lws_dll2_owner *owner, void *user,
		      int (*cb)(struct lws_dll2 *d, void *user))
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, owner->head) {
		if (cb(p, user))
			return 1;
	} lws_end_foreach_dll_safe(p, tp);

	return 0;
}

void
lws_dll2_add_head(struct lws_dll2 *d, struct lws_dll2_owner *owner)
{
	if (!lws_dll2_is_detached(d)) {
		assert(0); /* only wholly detached things can be added */
		return;
	}

	/* our next guy is current first guy, if any */
	if (owner->head != d)
		d->next = owner->head;

	/* if there is a next guy, set his prev ptr to our next ptr */
	if (d->next)
		d->next->prev = d;
	/* there is nobody previous to us, we are the head */
	d->prev = NULL;

	/* set the first guy to be us */
	owner->head = d;

	if (!owner->tail)
		owner->tail = d;

	d->owner = owner;
	owner->count++;
}

void
lws_dll2_add_tail(struct lws_dll2 *d, struct lws_dll2_owner *owner)
{
	if (!lws_dll2_is_detached(d)) {
		assert(0); /* only wholly detached things can be added */
		return;
	}

	/* our previous guy is current last guy */
	d->prev = owner->tail;
	/* if there is a prev guy, set his next ptr to our prev ptr */
	if (d->prev)
		d->prev->next = d;
	/* our next ptr is NULL */
	d->next = NULL;
	/* set the last guy to be us */
	owner->tail = d;

	/* list head is also us if we're the first */
	if (!owner->head)
		owner->head = d;

	d->owner = owner;
	owner->count++;
}

void
lws_dll2_remove(struct lws_dll2 *d)
{
	if (lws_dll2_is_detached(d))
		return;

	/* if we have a next guy, set his prev to our prev */
	if (d->next)
		d->next->prev = d->prev;

	/* if we have a previous guy, set his next to our next */
	if (d->prev)
		d->prev->next = d->next;

	/* if we have phead, track the tail and head if it points to us... */

	if (d->owner->tail == d)
		d->owner->tail = d->prev;

	if (d->owner->head == d)
		d->owner->head = d->next;

	d->owner->count--;

	/* we're out of the list, we should not point anywhere any more */
	d->owner = NULL;
	d->prev = NULL;
	d->next = NULL;
}

void
lws_dll2_clear(struct lws_dll2 *d)
{
	d->owner = NULL;
	d->prev = NULL;
	d->next = NULL;
}

void
lws_dll2_owner_clear(struct lws_dll2_owner *d)
{
	d->head = NULL;
	d->tail = NULL;
	d->count = 0;
}
