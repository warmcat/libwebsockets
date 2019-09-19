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

/** \defgroup ll linked-lists
* ##Linked list apis
*
* simple single and doubly-linked lists
*/
///@{

/**
 * lws_start_foreach_ll(): linkedlist iterator helper start
 *
 * \param type: type of iteration, eg, struct xyz *
 * \param it: iterator var name to create
 * \param start: start of list
 *
 * This helper creates an iterator and starts a while (it) {
 * loop.  The iterator runs through the linked list starting at start and
 * ends when it gets a NULL.
 * The while loop should be terminated using lws_start_foreach_ll().
 */
#define lws_start_foreach_ll(type, it, start)\
{ \
	type it = start; \
	while (it) {

/**
 * lws_end_foreach_ll(): linkedlist iterator helper end
 *
 * \param it: same iterator var name given when starting
 * \param nxt: member name in the iterator pointing to next list element
 *
 * This helper is the partner for lws_start_foreach_ll() that ends the
 * while loop.
 */

#define lws_end_foreach_ll(it, nxt) \
		it = it->nxt; \
	} \
}

/**
 * lws_start_foreach_ll_safe(): linkedlist iterator helper start safe against delete
 *
 * \param type: type of iteration, eg, struct xyz *
 * \param it: iterator var name to create
 * \param start: start of list
 * \param nxt: member name in the iterator pointing to next list element
 *
 * This helper creates an iterator and starts a while (it) {
 * loop.  The iterator runs through the linked list starting at start and
 * ends when it gets a NULL.
 * The while loop should be terminated using lws_end_foreach_ll_safe().
 * Performs storage of next increment for situations where iterator can become invalidated
 * during iteration.
 */
#define lws_start_foreach_ll_safe(type, it, start, nxt)\
{ \
	type it = start; \
	while (it) { \
		type next_##it = it->nxt;

/**
 * lws_end_foreach_ll_safe(): linkedlist iterator helper end (pre increment storage)
 *
 * \param it: same iterator var name given when starting
 *
 * This helper is the partner for lws_start_foreach_ll_safe() that ends the
 * while loop. It uses the precreated next_ variable already stored during
 * start.
 */

#define lws_end_foreach_ll_safe(it) \
		it = next_##it; \
	} \
}

/**
 * lws_start_foreach_llp(): linkedlist pointer iterator helper start
 *
 * \param type: type of iteration, eg, struct xyz **
 * \param it: iterator var name to create
 * \param start: start of list
 *
 * This helper creates an iterator and starts a while (it) {
 * loop.  The iterator runs through the linked list starting at the
 * address of start and ends when it gets a NULL.
 * The while loop should be terminated using lws_start_foreach_llp().
 *
 * This helper variant iterates using a pointer to the previous linked-list
 * element.  That allows you to easily delete list members by rewriting the
 * previous pointer to the element's next pointer.
 */
#define lws_start_foreach_llp(type, it, start)\
{ \
	type it = &(start); \
	while (*(it)) {

#define lws_start_foreach_llp_safe(type, it, start, nxt)\
{ \
	type it = &(start); \
	type next; \
	while (*(it)) { \
		next = &((*(it))->nxt); \

/**
 * lws_end_foreach_llp(): linkedlist pointer iterator helper end
 *
 * \param it: same iterator var name given when starting
 * \param nxt: member name in the iterator pointing to next list element
 *
 * This helper is the partner for lws_start_foreach_llp() that ends the
 * while loop.
 */

#define lws_end_foreach_llp(it, nxt) \
		it = &(*(it))->nxt; \
	} \
}

#define lws_end_foreach_llp_safe(it) \
		it = next; \
	} \
}

#define lws_ll_fwd_insert(\
	___new_object,	/* pointer to new object */ \
	___m_list,	/* member for next list object ptr */ \
	___list_head	/* list head */ \
		) {\
		___new_object->___m_list = ___list_head; \
		___list_head = ___new_object; \
	}

#define lws_ll_fwd_remove(\
	___type,	/* type of listed object */ \
	___m_list,	/* member for next list object ptr */ \
	___target,	/* object to remove from list */ \
	___list_head	/* list head */ \
	) { \
                lws_start_foreach_llp(___type **, ___ppss, ___list_head) { \
                        if (*___ppss == ___target) { \
                                *___ppss = ___target->___m_list; \
                                break; \
                        } \
                } lws_end_foreach_llp(___ppss, ___m_list); \
	}


/*
 * doubly linked-list
 */

#if defined (LWS_WITH_DEPRECATED_LWS_DLL)

/*
 * This is going away in v4.1.  You can set the cmake option above to keep it
 * around temporarily.  Migrate your stuff to the more capable and robust
 * lws_dll2 below
 */

struct lws_dll {
	struct lws_dll *prev;
	struct lws_dll *next;
};

/*
 * these all point to the composed list objects... you have to use the
 * lws_container_of() helper to recover the start of the containing struct
 */

#define lws_dll_add_front lws_dll_add_head

LWS_VISIBLE LWS_EXTERN void
lws_dll_add_head(struct lws_dll *d, struct lws_dll *phead);

LWS_VISIBLE LWS_EXTERN void
lws_dll_add_tail(struct lws_dll *d, struct lws_dll *phead);

LWS_VISIBLE LWS_EXTERN void
lws_dll_insert(struct lws_dll *d, struct lws_dll *target,
	       struct lws_dll *phead, int before);

static LWS_INLINE struct lws_dll *
lws_dll_get_head(struct lws_dll *phead) { return phead->next; }

static LWS_INLINE struct lws_dll *
lws_dll_get_tail(struct lws_dll *phead) { return phead->prev; }

/*
 * caution, this doesn't track the tail in the head struct.  Use
 * lws_dll_remove_track_tail() instead of this if you want tail tracking.  Using
 * this means you can't use lws_dll_add_tail() amd
 */
LWS_VISIBLE LWS_EXTERN void
lws_dll_remove(struct lws_dll *d) LWS_WARN_DEPRECATED;

LWS_VISIBLE LWS_EXTERN void
lws_dll_remove_track_tail(struct lws_dll *d, struct lws_dll *phead);

/* another way to do lws_start_foreach_dll_safe() on a list via a cb */

LWS_VISIBLE LWS_EXTERN int
lws_dll_foreach_safe(struct lws_dll *phead, void *user,
		     int (*cb)(struct lws_dll *d, void *user));

#define lws_dll_is_detached(___dll, __head) \
	(!(___dll)->prev && !(___dll)->next && (__head)->prev != (___dll))

#endif

/*
 * lws_dll2_owner / lws_dll2 : more capable version of lws_dll.  Differences:
 *
 *  - there's an explicit lws_dll2_owner struct which holds head, tail and
 *    count of members.
 *
 *  - list members all hold a pointer to their owner.  So user code does not
 *    have to track anything about exactly what lws_dll2_owner list the object
 *    is a member of.
 *
 *  - you can use lws_dll unless you want the member count or the ability to
 *    not track exactly which list it's on.
 *
 *  - layout is compatible with lws_dll (but lws_dll apis will not update the
 *    new stuff)
 */


struct lws_dll2;
struct lws_dll2_owner;

typedef struct lws_dll2 {
	struct lws_dll2		*prev;
	struct lws_dll2		*next;
	struct lws_dll2_owner	*owner;
} lws_dll2_t;

typedef struct lws_dll2_owner {
	struct lws_dll2		*tail;
	struct lws_dll2		*head;

	uint32_t		count;
} lws_dll2_owner_t;

static LWS_INLINE int
lws_dll2_is_detached(const struct lws_dll2 *d) { return !d->owner; }

static LWS_INLINE const struct lws_dll2_owner *
lws_dll2_owner(const struct lws_dll2 *d) { return d->owner; }

static LWS_INLINE struct lws_dll2 *
lws_dll2_get_head(struct lws_dll2_owner *owner) { return owner->head; }

static LWS_INLINE struct lws_dll2 *
lws_dll2_get_tail(struct lws_dll2_owner *owner) { return owner->tail; }

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_head(struct lws_dll2 *d, struct lws_dll2_owner *owner);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_tail(struct lws_dll2 *d, struct lws_dll2_owner *owner);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_remove(struct lws_dll2 *d);

LWS_VISIBLE LWS_EXTERN int
lws_dll2_foreach_safe(struct lws_dll2_owner *owner, void *user,
		      int (*cb)(struct lws_dll2 *d, void *user));

LWS_VISIBLE LWS_EXTERN void
lws_dll2_clear(struct lws_dll2 *d);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_owner_clear(struct lws_dll2_owner *d);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_before(struct lws_dll2 *d, struct lws_dll2 *after);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_sorted(lws_dll2_t *d, lws_dll2_owner_t *own,
		    int (*compare)(const lws_dll2_t *d, const lws_dll2_t *i));

#if defined(_DEBUG)
void
lws_dll2_describe(struct lws_dll2_owner *owner, const char *desc);
#else
#define lws_dll2_describe(x, y)
#endif

/*
 * these are safe against the current container object getting deleted,
 * since the hold his next in a temp and go to that next.  ___tmp is
 * the temp.
 */

#define lws_start_foreach_dll_safe(___type, ___it, ___tmp, ___start) \
{ \
	___type ___it = ___start; \
	while (___it) { \
		___type ___tmp = (___it)->next;

#define lws_end_foreach_dll_safe(___it, ___tmp) \
		___it = ___tmp; \
	} \
}

#define lws_start_foreach_dll(___type, ___it, ___start) \
{ \
	___type ___it = ___start; \
	while (___it) {

#define lws_end_foreach_dll(___it) \
		___it = (___it)->next; \
	} \
}

///@}

