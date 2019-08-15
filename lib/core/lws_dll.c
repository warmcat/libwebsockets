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

void
lws_dll_add_head(struct lws_dll *d, struct lws_dll *phead)
{
	if (!lws_dll_is_detached(d, phead)) {
		assert(0); /* only wholly detached things can be added */
		return;
	}

	/* our next guy is current first guy, if any */
	if (phead->next != d)
		d->next = phead->next;

	/* if there is a next guy, set his prev ptr to our next ptr */
	if (d->next)
		d->next->prev = d;
	/* there is nobody previous to us, we are the head */
	d->prev = NULL;

	/* set the first guy to be us */
	phead->next = d;

	/* if there was nothing on the list before, we are also now the tail */
	if (!phead->prev)
		phead->prev = d;

	assert(d->prev != d);
	assert(d->next != d);
}

void
lws_dll_add_tail(struct lws_dll *d, struct lws_dll *phead)
{
	if (!lws_dll_is_detached(d, phead)) {
		assert(0); /* only wholly detached things can be added */
		return;
	}

	/* our previous guy is current last guy */
	d->prev = phead->prev;
	/* if there is a prev guy, set his next ptr to our prev ptr */
	if (d->prev)
		d->prev->next = d;
	/* our next ptr is NULL */
	d->next = NULL;
	/* set the last guy to be us */
	phead->prev = d;

	/* list head is also us if we're the first */
	if (!phead->next)
		phead->next = d;

	assert(d->prev != d);
	assert(d->next != d);
}

void
lws_dll_insert(struct lws_dll *n, struct lws_dll *target,
	       struct lws_dll *phead, int before)
{
	if (!lws_dll_is_detached(n, phead)) {
		assert(0); /* only wholly detached things can be inserted */
		return;
	}
	if (!target) {
		/*
		 * the case where there's no target identified degenerates to
		 * a simple add at head or tail
		 */
		if (before) {
			lws_dll_add_head(n, phead);
			return;
		}
		lws_dll_add_tail(n, phead);
		return;
	}

	/*
	 * in the case there's a target "cursor", we have to do the work to
	 * stitch the new guy in appropriately
	 */

	if (before) {
		/*
		 *  we go before dd
		 *  DDp <-> DD <-> DDn   -->   DDp <-> us <-> DD <-> DDn
		 */
		/* we point forward to dd */
		n->next = target;
		/* we point back to what dd used to point back to */
		n->prev = target->prev;
		/* DDp points forward to us now */
		if (target->prev)
			target->prev->next = n;
		/* DD points back to us now */
		target->prev = n;

		/* if target was the head, we are now the head */
		if (phead->next == target)
			phead->next = n;

		/* since we are before another guy, we cannot become the tail */

	} else {
		/*
		 *  we go after dd
		 *  DDp <-> DD <-> DDn   -->   DDp <-> DD <-> us <-> DDn
		 */
		/* we point forward to what dd used to point forward to */
		n->next = target->next;
		/* we point back to dd */
		n->prev = target;
		/* DDn points back to us */
		if (target->next)
			target->next->prev = n;
		/* DD points forward to us */
		target->next = n;

		/* if target was the tail, we are now the tail */
		if (phead->prev == target)
			phead->prev = n;

		/* since we go after another guy, we cannot become the head */
	}
}

/* situation is:
 *
 *  HEAD: struct lws_dll * = &entry1
 *
 *  Entry 1: struct lws_dll  .pprev = &HEAD , .next = Entry 2
 *  Entry 2: struct lws_dll  .pprev = &entry1 , .next = &entry2
 *  Entry 3: struct lws_dll  .pprev = &entry2 , .next = NULL
 *
 *  Delete Entry1:
 *
 *   - HEAD = &entry2
 *   - Entry2: .pprev = &HEAD, .next = &entry3
 *   - Entry3: .pprev = &entry2, .next = NULL
 *
 *  Delete Entry2:
 *
 *   - HEAD = &entry1
 *   - Entry1: .pprev = &HEAD, .next = &entry3
 *   - Entry3: .pprev = &entry1, .next = NULL
 *
 *  Delete Entry3:
 *
 *   - HEAD = &entry1
 *   - Entry1: .pprev = &HEAD, .next = &entry2
 *   - Entry2: .pprev = &entry1, .next = NULL
 *
 */

void
lws_dll_remove(struct lws_dll *d)
{
	if (!d->prev && !d->next)
		return;

	/*
	 *  remove us
	 *
	 *  USp <-> us <-> USn  -->  USp <-> USn
	 */

	/* if we have a next guy, set his prev to our prev */
	if (d->next)
		d->next->prev = d->prev;

	/* set our prev guy to our next guy instead of us */
	if (d->prev)
		d->prev->next = d->next;

	/* we're out of the list, we should not point anywhere any more */
	d->prev = NULL;
	d->next = NULL;
}

void
lws_dll_remove_track_tail(struct lws_dll *d, struct lws_dll *phead)
{
	if (lws_dll_is_detached(d, phead)) {
		assert(phead->prev != d);
		assert(phead->next != d);
		return;
	}

	/* if we have a next guy, set his prev to our prev */
	if (d->next)
		d->next->prev = d->prev;

	/* if we have a previous guy, set his next to our next */
	if (d->prev)
		d->prev->next = d->next;

	if (phead->prev == d)
		phead->prev = d->prev;

	if (phead->next == d)
		phead->next = d->next;

	/* we're out of the list, we should not point anywhere any more */
	d->prev = NULL;
	d->next = NULL;
}


int
lws_dll_foreach_safe(struct lws_dll *phead, void *user,
		     int (*cb)(struct lws_dll *d, void *user))
{
	lws_start_foreach_dll_safe(struct lws_dll *, p, tp, phead->next) {
		if (cb(p, user))
			return 1;
	} lws_end_foreach_dll_safe(p, tp);

	return 0;
}
