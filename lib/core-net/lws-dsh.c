/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

#if defined(STANDALONE)
#undef lws_malloc
#define lws_malloc(a, b) malloc(a)
#undef lws_free
#define lws_free(a) free(a)
#undef lws_free_set_NULL
#define lws_free_set_NULL(a) { if (a) { free(a); a = NULL; }}
#endif


struct lws_dsh_search {
	size_t		required;
	ssize_t		natural_required;
	int		kind;
	lws_dsh_obj_t	*best;
	lws_dsh_t	*dsh;
	lws_dsh_obj_t	*tail_obj;
	void		*natural; /* coalesce address against last tail */

	lws_dsh_t	*already_checked;
	lws_dsh_t	*this_dsh;

	char		coalesce;
};

static int
_lws_dsh_alloc_tail(lws_dsh_t *dsh, int kind, const void *src1, size_t size1,
		    const void *src2, size_t size2, lws_dll2_t *replace);

static size_t
lws_dsh_align(size_t length)
{
	size_t align = sizeof(int *);

	if (length & (align - 1))
		length += align - (length & (align - 1));

	return length;
}

void
lws_dsh_empty(struct lws_dsh *dsh)
{
	lws_dsh_obj_t *obj;
	size_t oha_len;
	int n;

	if (!dsh)
		return;

	oha_len = sizeof(lws_dsh_obj_head_t) * (unsigned int)dsh->count_kinds;

	/* clear down the obj heads array */

	memset(dsh->oha, 0, oha_len);
	for (n = 0; n < dsh->count_kinds; n++) {
		dsh->oha[n].kind = n;
		dsh->oha[n].total_size = 0;
	}

	/* initially the whole buffer is on the free kind (0) list */

	obj = (lws_dsh_obj_t *)dsh->buf;
	memset(obj, 0, sizeof(*obj));
	obj->asize = dsh->buffer_size - sizeof(*obj);

	lws_dll2_add_head(&obj->list, &dsh->oha[0].owner);

	dsh->locally_free = obj->asize;
	dsh->locally_in_use = 0;
}

lws_dsh_t *
lws_dsh_create(lws_dll2_owner_t *owner, size_t buf_len, int _count_kinds)
{
	int count_kinds = _count_kinds & 0xff;
	lws_dsh_t *dsh;
	size_t oha_len;

	oha_len = sizeof(lws_dsh_obj_head_t) * (unsigned int)(++count_kinds);

	assert(buf_len);
	assert(count_kinds > 1);
	assert(buf_len > sizeof(lws_dsh_t) + oha_len);
	buf_len += 64;

	dsh = lws_malloc(sizeof(lws_dsh_t) + buf_len + oha_len, __func__);
	if (!dsh)
		return NULL;

	/* set convenience pointers to the overallocated parts */

	lws_dll2_clear(&dsh->list);
	dsh->oha = (lws_dsh_obj_head_t *)&dsh[1];
	dsh->buf = ((uint8_t *)dsh->oha) + oha_len;
	dsh->count_kinds = count_kinds;
	dsh->buffer_size = buf_len;
	dsh->being_destroyed = 0;
	dsh->splitat = 0;
	dsh->flags = (unsigned int)_count_kinds & 0xff000000u;

	lws_dsh_empty(dsh);

	if (owner)
		lws_dll2_add_head(&dsh->list, owner);

	// lws_dsh_describe(dsh, "post-init");

	return dsh;
}

/*
 * We're flicking through the hole list... if we find a suitable hole starting
 * right after the current tail, it means we can coalesce against the current
 * tail, that overrides all other considerations
 */

static int
search_best_free(struct lws_dll2 *d, void *user)
{
	struct lws_dsh_search *s = (struct lws_dsh_search *)user;
	lws_dsh_obj_t *obj = lws_container_of(d, lws_dsh_obj_t, list);

//	lwsl_debug("%s: obj %p, asize %zu (req %zu)\n", __func__, obj,
//			obj->asize, s->required);

//	if (s->tail_obj)
//	lwsl_notice("%s: tail est %d, splitat %d\n", __func__,
//			(int)(s->tail_obj->asize + (size_t)s->natural_required), (int)s->dsh->splitat);


	if (s->dsh->flags & LWS_DSHFLAG_ENABLE_COALESCE) {
		if (obj == s->natural && s->tail_obj &&
		    (int)obj->asize >= s->natural_required
		    &&
		    (!s->dsh->splitat ||
		      (size_t)(s->tail_obj->asize +
				(size_t)s->natural_required) <= s->dsh->splitat)
		    ) {
			// lwsl_user("%s: found natural\n", __func__);
			s->dsh = s->this_dsh;
			s->best = obj;
			s->coalesce = 1;
		}

		if (s->coalesce)
			return 0;
	}

	if (obj->asize >= s->required &&
	    (!s->best || obj->asize < s->best->asize)) {
		s->best = obj;
		s->dsh = s->this_dsh;
	}

	return 0;
}

static int
buf_compare(const lws_dll2_t *d, const lws_dll2_t *i)
{
	return (int)lws_ptr_diff(d, i);
}

void
lws_dsh_destroy(lws_dsh_t **pdsh)
{
	lws_dsh_t *dsh = *pdsh;

	if (!dsh)
		return;

	dsh->being_destroyed = 1;

	lws_dll2_remove(&dsh->list);
	lws_dsh_empty(dsh);

	/* everything else is in one heap allocation */

	lws_free_set_NULL(*pdsh);
}

size_t
lws_dsh_get_size(struct lws_dsh *dsh, int kind)
{
	kind++;
	assert(kind < dsh->count_kinds);

	return dsh->oha[kind].total_size;
}

static int
_lws_dsh_alloc_tail(lws_dsh_t *dsh, int kind, const void *src1, size_t size1,
		    const void *src2, size_t size2, lws_dll2_t *replace)
{
	size_t asize = sizeof(lws_dsh_obj_t) + lws_dsh_align(size1 + size2);
	struct lws_dsh_search s;

	assert(kind >= 0);
	kind++;
	assert(!dsh || kind < dsh->count_kinds);

	/*
	 * Search our free list looking for the smallest guy who will fit
	 * what we want to allocate
	 */
	s.dsh			= dsh;
	s.required		= asize;
	s.kind			= kind;
	s.best			= NULL;
	s.already_checked	= NULL;
	s.this_dsh		= dsh;
	s.natural		= NULL;
	s.coalesce		= 0;
	s.natural_required	= 0;
	/* list is at the very start, so we can cast */
	s.tail_obj		= (lws_dsh_obj_t *)dsh->oha[kind].owner.tail;

	if (s.tail_obj) {

		assert(s.tail_obj->kind == kind);

		/*
		 * there's a tail... precompute where a natural hole would
		 * have to start to be coalescable
		 */
		s.natural = (uint8_t *)s.tail_obj + s.tail_obj->asize;
		/*
		 * ... and precompute the needed hole extent (including its
		 * obj part we would no longer need if we coalesced, and
		 * accounting for any unused / alignment part in the tail
		 */
		s.natural_required = (ssize_t)(lws_dsh_align(s.tail_obj->size + size1 + size2) -
				s.tail_obj->asize + sizeof(lws_dsh_obj_t));

//		lwsl_notice("%s: natural %p, tail len %d, nreq %d, splitat %d\n", __func__, s.natural,
//				(int)s.tail_obj->size, (int)s.natural_required, (int)dsh->splitat);
	}

	if (!dsh->being_destroyed)
		lws_dll2_foreach_safe(&dsh->oha[0].owner, &s, search_best_free);

	if (!s.best) {
		//lwsl_notice("%s: no buffer has space for %lu\n",
		//		__func__, (unsigned long)asize);

		return 1;
	}

	if (s.coalesce) {
		uint8_t *nf = (uint8_t *)&s.tail_obj[1] + s.tail_obj->size,
			*e = (uint8_t *)s.best + s.best->asize, *ce;
		lws_dsh_obj_t *rh;
		size_t le;

//		lwsl_notice("%s: coalescing\n", __func__);

		/*
		 * logically remove the free list entry we're taking over the
		 * memory footprint of
		 */
		lws_dll2_remove(&s.best->list);
		s.dsh->locally_free -= s.best->asize;
		if (s.dsh->oha[kind].total_size < s.tail_obj->asize) {
			lwsl_err("%s: total_size %d, asize %d, hdr size %d\n", __func__,
					(int)s.dsh->oha[kind].total_size,
					(int)s.tail_obj->asize, (int)sizeof(lws_dsh_obj_t));

			assert(0);
		}
		s.dsh->oha[kind].total_size -= s.tail_obj->asize;
		s.dsh->locally_in_use -= s.tail_obj->asize;

		if (size1) {
			memcpy(nf, src1, size1);
			nf += size1;
		}
		if (size2) {
			memcpy(nf, src2, size2);
			nf += size2;
		}

		/*
		 * adjust the tail guy's sizes to account for the coalesced
		 * data and alignment for the end point
		 */

		s.tail_obj->size = s.tail_obj->size + size1 + size2;
		s.tail_obj->asize = sizeof(lws_dsh_obj_t) +
				    lws_dsh_align(s.tail_obj->size);

		ce = (uint8_t *)s.tail_obj + s.tail_obj->asize;
		assert(ce <= e);
		le = lws_ptr_diff_size_t(e, ce);

		/*
		 * Now we have to decide what to do with any leftovers...
		 */

		if (le < 64)
			/*
			 * just absorb it into the coalesced guy as spare, and
			 * no need for a replacement hole
			 */
			s.tail_obj->asize += le;
		else {

			rh = (lws_dsh_obj_t *)ce;

			memset(rh, 0, sizeof(*rh));
			rh->asize = le;
			lws_dll2_add_sorted(&rh->list, &s.dsh->oha[0].owner,
					    buf_compare);
			s.dsh->locally_free += rh->asize;
		}

		s.dsh->oha[kind].total_size += s.tail_obj->asize;
		s.dsh->locally_in_use += s.tail_obj->asize;

		return 0;
	}

	/* anything coming out of here must be aligned */
	assert(!(((size_t)(intptr_t)s.best) & (sizeof(int *) - 1)));

	if (s.best->asize < asize + (2 * sizeof(*s.best))) {

		// lwsl_notice("%s: exact\n", __func__);
		/*
		 * Exact fit, or close enough we can't / don't want to have to
		 * track the little bit of free area that would be left.
		 *
		 * Move the object from the free list to the oha of the
		 * desired kind
		 */
		lws_dll2_remove(&s.best->list);
		s.best->dsh = s.dsh;
		s.best->kind = kind;
		s.best->size = size1 + size2;
		memcpy(&s.best[1], src1, size1);
		if (src2)
			memcpy((uint8_t *)&s.best[1] + size1, src2, size2);

		if (replace) {
			s.best->list.prev = replace->prev;
			s.best->list.next = replace->next;
			s.best->list.owner = replace->owner;
			if (replace->prev)
				replace->prev->next = &s.best->list;
			if (replace->next)
				replace->next->prev = &s.best->list;
		} else {
			assert(!(((unsigned long)(intptr_t)(s.best)) &
					(sizeof(int *) - 1)));
			lws_dll2_add_tail(&s.best->list,
					&dsh->oha[kind].owner);
		}

		assert(s.dsh->locally_free >= s.best->asize);
		s.dsh->locally_free -= s.best->asize;
		s.dsh->locally_in_use += s.best->asize;
		dsh->oha[kind].total_size += s.best->asize;
		assert(s.dsh->locally_in_use <= s.dsh->buffer_size);
	} else {
		lws_dsh_obj_t *nf;
#if defined(_DEBUG)
		uint8_t *e = ((uint8_t *)s.best) + s.best->asize;
#endif
		/*
		 * Free area was oversize enough that we need to split it.
		 *
		 * Unlink the free area and move its header forward to account
		 * for our usage of its start area.  It's like this so that we
		 * can coalesce sequential objects.
		 */
		//lwsl_notice("%s: splitting... free reduce %zu -> %zu\n",
		//		__func__, s.best->asize, s.best->asize - asize);

		assert(s.best->asize >= asize);

		/* unlink the entire original hole object at s.best */
		lws_dll2_remove(&s.best->list);
		s.dsh->locally_free -= s.best->asize;
		s.dsh->locally_in_use += asize;

		/* latter part becomes new hole object */

		nf = (lws_dsh_obj_t *)(((uint8_t *)s.best) + asize);

		assert((uint8_t *)nf < e);

		memset(nf, 0, sizeof(*nf));
		nf->asize = s.best->asize - asize; /* rump free part only */

		assert(((uint8_t *)nf) + nf->asize <= e);

		lws_dll2_add_sorted(&nf->list, &s.dsh->oha[0].owner, buf_compare);
		s.dsh->locally_free += s.best->asize;

		/* take over s.best as the new allocated object, fill it in */

		s.best->dsh	= s.dsh;
		s.best->kind	= kind;
		s.best->size	= size1 + size2;
		s.best->asize	= asize;

	//	lwsl_notice("%s: split off kind %d\n", __func__, kind);

		assert((uint8_t *)s.best + s.best->asize < e);
		assert((uint8_t *)s.best + s.best->asize <= (uint8_t *)nf);

		if (size1)
			memcpy(&s.best[1], src1, size1);
		if (src2)
			memcpy((uint8_t *)&s.best[1] + size1, src2, size2);

		if (replace) {
			s.best->list.prev = replace->prev;
			s.best->list.next = replace->next;
			s.best->list.owner = replace->owner;
			if (replace->prev)
				replace->prev->next = &s.best->list;
			if (replace->next)
				replace->next->prev = &s.best->list;
		} else
			if (dsh) {
				assert(!(((unsigned long)(intptr_t)(s.best)) &
						(sizeof(int *) - 1)));
				lws_dll2_add_tail(&s.best->list,
						  &dsh->oha[kind].owner);
			}

		assert(s.dsh->locally_free >= asize);
		dsh->oha[kind].total_size += asize;
		assert(s.dsh->locally_in_use <= s.dsh->buffer_size);
	}

	// lws_dsh_describe(dsh, "post-alloc");

	return 0;
}

int
lws_dsh_alloc_tail(lws_dsh_t *dsh, int kind, const void *src1, size_t size1,
		   const void *src2, size_t size2)
{
	int r;

	do {
		size_t s1 = size1, s2 = size2;

		if (!dsh->splitat || !(dsh->flags & LWS_DSHFLAG_ENABLE_SPLIT)) {
			s1 = size1;
			s2 = size2;
		} else
			if (s1 > dsh->splitat) {
				s1 = dsh->splitat;
				s2 = 0;
			} else {
				if (s1 + s2 > dsh->splitat)
					s2 = dsh->splitat - s1;
			}
		r =  _lws_dsh_alloc_tail(dsh, kind, src1, s1, src2, s2, NULL);
		if (r)
			return r;
		src1 = (void *)((uint8_t *)src1 + s1);
		src2 = (void *)((uint8_t *)src2 + s2);
		size1 -= s1;
		size2 -= s2;
	} while (size1 + size2);

	return 0;
}

void
lws_dsh_consume(struct lws_dsh *dsh, int kind, size_t len)
{
	lws_dsh_obj_t *h = (lws_dsh_obj_t *)dsh->oha[kind + 1].owner.head;

	assert(len <= h->size);
	assert(h->pos + len <= h->size);

	if (len == h->size || h->pos + len == h->size) {
		lws_dsh_free((void **)&h);
		return;
	}

	assert(0);

	h->pos += len;
}

void
lws_dsh_free(void **pobj)
{
	lws_dsh_obj_t *_o = (lws_dsh_obj_t *)((uint8_t *)(*pobj) - sizeof(*_o)),
			*_o2;
	lws_dsh_t *dsh = _o->dsh;

	/* anything coming out of here must be aligned */
	assert(!(((size_t)(intptr_t)_o) & (sizeof(int *) - 1)));

	/*
	 * Remove the object from its list and place on the free list of the
	 * dsh the buffer space belongs to
	 */

	lws_dll2_remove(&_o->list);
	*pobj = NULL;

	assert(dsh->locally_in_use >= _o->asize);
	dsh->locally_free += _o->asize;
	dsh->locally_in_use -= _o->asize;
	assert(dsh->oha[_o->kind].total_size >= _o->asize);
	dsh->oha[_o->kind].total_size -= _o->asize; /* account for usage by kind */
	assert(dsh->locally_in_use <= dsh->buffer_size);

	/*
	 * The free space list is sorted in buffer address order, so detecting
	 * coalescing opportunities is cheap.  Because the free list should be
	 * continuously tending to reduce by coalescing, the sorting should not
	 * be expensive to maintain.
	 */
	_o->size = 0; /* not meaningful when on free list */
	lws_dll2_add_sorted(&_o->list, &_o->dsh->oha[0].owner, buf_compare);

	/* First check for already-free block at the end we can subsume.
	 * Because the free list is sorted, if there is such a guy he is
	 * already our list.next */

	_o2 = (lws_dsh_obj_t *)_o->list.next;
	if (_o2 && (uint8_t *)_o + _o->asize == (uint8_t *)_o2) {
		/*
		 * since we are freeing _obj, we can coalesce with a
		 * free area immediately ahead of it
		 *
		 *  [ _o (being freed) ][ _o2 (free) ]  -> [ larger _o ]
		 */
		_o->asize += _o2->asize;

		/* guy next to us was absorbed into us */
		lws_dll2_remove(&_o2->list);
	}

	/* Then check if we can be subsumed by a free block behind us.
	 * Because the free list is sorted, if there is such a guy he is
	 * already our list.prev */

	_o2 = (lws_dsh_obj_t *)_o->list.prev;
	if (_o2 && (uint8_t *)_o2 + _o2->asize == (uint8_t *)_o) {
		/*
		 * since we are freeing obj, we can coalesce it with
		 * the previous free area that abuts it
		 *
		 *  [ _o2 (free) ][ _o (being freed) ] -> [ larger _o2 ]
		 */
		_o2->asize += _o->asize;

		/* we were absorbed! */
		lws_dll2_remove(&_o->list);
	}

	// lws_dsh_describe(dsh, "post-alloc");
}

int
lws_dsh_get_head(lws_dsh_t *dsh, int kind, void **obj, size_t *size)
{
	lws_dsh_obj_t *_obj;

	if (!dsh)
		return 1;

	_obj = (lws_dsh_obj_t *)lws_dll2_get_head(&dsh->oha[kind + 1].owner);

	if (!_obj) {
		*obj = 0;
		*size = 0;

		return 1;	/* there is no head */
	}

	*obj = (void *)(&_obj[1]);
	*size = _obj->size;

	/* anything coming out of here must be aligned */
	assert(!(((unsigned long)(intptr_t)(*obj)) & (sizeof(int *) - 1)));

	return 0;	/* we returned the head */
}

#if defined(_DEBUG) && !defined(LWS_WITH_NO_LOGS)

static int
describe_kind(struct lws_dll2 *d, void *user)
{
	lws_dsh_obj_t *obj = lws_container_of(d, lws_dsh_obj_t, list);

	lwsl_notice("    _obj %p - %p, dsh %p, size %zu, asize %zu\n",
			obj, (uint8_t *)obj + obj->asize,
			obj->dsh, obj->size, obj->asize);

	return 0;
}

void
lws_dsh_describe(lws_dsh_t *dsh, const char *desc)
{
	int n = 0;

	lwsl_notice("%s: dsh %p, bufsize %zu, kinds %d, lf: %zu, liu: %zu, %s\n",
		    __func__, dsh, dsh->buffer_size, dsh->count_kinds,
		    dsh->locally_free, dsh->locally_in_use, desc);

	for (n = 0; n < dsh->count_kinds; n++) {
		lwsl_notice("  Kind %d:\n", n);
		lws_dll2_foreach_safe(&dsh->oha[n].owner, dsh, describe_kind);
	}
}
#endif
