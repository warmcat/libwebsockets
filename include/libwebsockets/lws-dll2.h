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
 *
 * Note: Thanks to the structural abstraction, you can now safely use
 * continue; or break; to control the loop as if it were a standard
 * for / while loop.
 */
#define lws_start_foreach_ll(type, it, start)\
{ \
	type it = start; \
	while (it) { \
		int _c_##it = 0, _b_##it = 0; \
		for (; !_c_##it; _c_##it = 1) {

/**
 * lws_end_foreach_ll(): linkedlist iterator helper end
 *
 * \param it: same iterator var name given when starting
 * \param nxt: member name in the iterator pointing to next list element
 *
 * This helper is the partner for lws_start_foreach_ll() that ends the
 * while loop.
 *
 * Note: Thanks to the structural abstraction, you can now safely use
 * continue; or break; to control the loop as if it were a standard
 * for / while loop.
 */

#define lws_end_foreach_ll(it, nxt) \
			_b_##it = 1; \
		} \
		if (!_b_##it) break; \
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
 *
 * Note: Thanks to the structural abstraction, you can now safely use
 * continue; or break; to control the loop as if it were a standard
 * for / while loop.
 */
#define lws_start_foreach_ll_safe(type, it, start, nxt)\
{ \
	type next_##it; \
	for (type it = start; it && ((next_##it = it->nxt), 1); it = next_##it) {

/**
 * lws_end_foreach_ll_safe(): linkedlist iterator helper end (pre increment storage)
 *
 * \param it: same iterator var name given when starting
 *
 * This helper is the partner for lws_start_foreach_ll_safe() that ends the
 * while loop. It uses the precreated next_ variable already stored during
 * start.
 *
 * Note: Thanks to the structural abstraction, you can now safely use
 * continue; or break; to control the loop as if it were a standard
 * for / while loop.
 */

#define lws_end_foreach_ll_safe(it) \
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
 *
 * Note: Thanks to the structural abstraction, you can now safely use
 * continue; or break; to control the loop as if it were a standard
 * for / while loop.
 */
#define lws_start_foreach_llp(type, it, start)\
{ \
	type it = &(start); \
	while (*(it)) { \
		int _c_##it = 0, _b_##it = 0; \
		for (; !_c_##it; _c_##it = 1) {

#define lws_start_foreach_llp_safe(type, it, start, nxt)\
{ \
	type next; \
	for (type it = &(start); *(it) && ((next = &((*(it))->nxt)), 1); it = next) {

/**
 * lws_end_foreach_llp(): linkedlist pointer iterator helper end
 *
 * \param it: same iterator var name given when starting
 * \param nxt: member name in the iterator pointing to next list element
 *
 * This helper is the partner for lws_start_foreach_llp() that ends the
 * while loop.
 *
 * Note: Thanks to the structural abstraction, you can now safely use
 * continue; or break; to control the loop as if it were a standard
 * for / while loop.
 */

#define lws_end_foreach_llp(it, nxt) \
			_b_##it = 1; \
		} \
		if (!_b_##it) break; \
		it = &(*(it))->nxt; \
	} \
}

#define lws_end_foreach_llp_safe(it) \
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
 * The legacy singly-linked-list macros are banned inside libwebsockets,
 * permanently.
 * --------------------------------------------------------------------
 *
 * dll2 owners bring the member count, an owner backpointer per node and the
 * runtime _safe iterator guard; hand-rolled next-chains have been behind a
 * number of iterator-lifetime bugs here.  All list usage inside the library,
 * including self-contained datastructure internals like lwsac chunks, the
 * fts trie and dht tables, is on a one-time conversion to
 * lws_dll2_owner_t + lws_dll2_t; when the last one is converted the total
 * ban below is armed by setting LWS_DLL2_ARM_TOTAL_BAN to 1.
 *
 * When armed, the ban is enforced at compile time by poisoning the macros
 * when building the library itself: LWS_BUILDING_STATIC / LWS_BUILDING_SHARED
 * are PRIVATE to the libwebsockets compile targets, so they are defined when
 * compiling the library sources and nothing else -- plugins, minimal examples
 * and user code keep full access to the legacy macros for their own use,
 * indefinitely.
 *
 * Any use inside the library then fails at the use site with the poison
 * identifier naming the reason.
 */

/* conversion complete: the total ban is armed */
#define LWS_DLL2_ARM_TOTAL_BAN 1

#if LWS_DLL2_ARM_TOTAL_BAN && \
	(defined(LWS_BUILDING_STATIC) || defined(LWS_BUILDING_SHARED))

#undef	lws_start_foreach_ll
#undef	lws_end_foreach_ll
#undef	lws_start_foreach_ll_safe
#undef	lws_end_foreach_ll_safe
#undef	lws_start_foreach_llp
#undef	lws_end_foreach_llp
#undef	lws_start_foreach_llp_safe
#undef	lws_end_foreach_llp_safe
#undef	lws_ll_fwd_insert
#undef	lws_ll_fwd_remove

#define lws_start_foreach_ll(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_end_foreach_ll(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_start_foreach_ll_safe(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_end_foreach_ll_safe(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_start_foreach_llp(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_end_foreach_llp(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_start_foreach_llp_safe(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_end_foreach_llp_safe(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_ll_fwd_insert(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#define lws_ll_fwd_remove(...) \
	LWS_LIB_MAY_NOT_USE_LEGACY_LIST_MACROS_see_lws_dll2_h
#endif


/*
 * doubly linked-list
 */

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

	/*
	 * Monotonic "generation" of the list contents: bumped by every add*
	 * and remove, and reset to 0 by lws_dll2_owner_clear() (which also
	 * serves as the owner initializer and so writes it without reading).
	 * The _safe iterator helpers use it to cheaply notice that the list
	 * changed during the loop body, so they can validate their cached
	 * next pointer is still a list member before using it.  Since an
	 * iterable owner must have had at least one add, a live iterator's
	 * cached generation is never 0 and the clear reset is still always
	 * detectable.  Never compare generations for ordering across
	 * different owners, only inequality on the same owner.
	 */
	uint32_t		generation;
} lws_dll2_owner_t;

LWS_VISIBLE LWS_EXTERN int
lws_dll2_is_detached(const struct lws_dll2 *d);

static LWS_INLINE struct lws_dll2_owner *
lws_dll2_owner(const struct lws_dll2 *d) { return d ? d->owner : NULL; }

static LWS_INLINE struct lws_dll2 *
lws_dll2_get_head(const struct lws_dll2_owner *owner) { return owner ? owner->head : NULL; }

static LWS_INLINE struct lws_dll2 *
lws_dll2_get_tail(const struct lws_dll2_owner *owner) { return owner ? owner->tail : NULL; }

/*
 * Read-only accessors for list state, in the same NULL-tolerant style as
 * lws_dll2_get_head() / lws_dll2_get_tail(): a NULL owner or node gives 0 /
 * NULL, a detached node has no next or prev.  User code should use these
 * rather than reach into the struct members directly, so the members and
 * their invariants stay the business of lws_dll2.c alone.
 */

static LWS_INLINE uint32_t
lws_dll2_count(const struct lws_dll2_owner *owner)
{
	return owner ? owner->count : 0;
}

static LWS_INLINE int
lws_dll2_is_empty(const struct lws_dll2_owner *owner)
{
	return !lws_dll2_count(owner);
}

static LWS_INLINE struct lws_dll2 *
lws_dll2_get_next(const struct lws_dll2 *d) { return d ? d->next : NULL; }

static LWS_INLINE struct lws_dll2 *
lws_dll2_get_prev(const struct lws_dll2 *d) { return d ? d->prev : NULL; }

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_head(struct lws_dll2 *d, struct lws_dll2_owner *owner);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_tail(struct lws_dll2 *d, struct lws_dll2_owner *owner);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_remove(struct lws_dll2 *d);

typedef int (*lws_dll2_foreach_cb_t)(struct lws_dll2 *d, void *user);

LWS_VISIBLE LWS_EXTERN int
lws_dll2_foreach_safe(struct lws_dll2_owner *owner, void *user,
		      lws_dll2_foreach_cb_t cb);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_clear(struct lws_dll2 *d);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_owner_clear(struct lws_dll2_owner *d);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_before(struct lws_dll2 *d, struct lws_dll2 *after);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_insert(struct lws_dll2 *d, struct lws_dll2 *prev);

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_sorted(lws_dll2_t *d, lws_dll2_owner_t *own,
		    int (*compare)(const lws_dll2_t *d, const lws_dll2_t *i));

LWS_VISIBLE LWS_EXTERN void
lws_dll2_add_sorted_priv(lws_dll2_t *d, lws_dll2_owner_t *own, void *priv,
			 int (*compare3)(void *priv, const lws_dll2_t *d,
					 const lws_dll2_t *i));

/*
 * Returns nonzero if d is currently a member of owner's list.  Only compares
 * pointers walking the live list members; never dereferences d itself, so it
 * is safe to call with a candidate pointer that may have been freed, exactly
 * for validating cached iterator state.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dll2_is_in_list(struct lws_dll2_owner *owner, struct lws_dll2 *d);

/*
 * Guarded advance for the _safe iterator macros: validates that cand (the
 * cached next node) is still a member of ow's list if anything mutated the
 * list (ow->generation != *gen) since it was cached.  If cand went away, it
 * asserts (unless lws_dll2_guard_quiet) and recovers by restarting from the
 * live head, so even release builds stop walking into freed nodes.  Returns
 * the node the iterator should advance to.
 *
 * Notice there is deliberately no "current node" parameter to resume from
 * its successor: the supported usage is that the loop body may remove and
 * free the current node itself, so by the time this runs that pointer may
 * refer to freed memory.  Passing it here (even without dereferencing it)
 * is exactly the use-after-free pattern static analysis must reject.  The
 * consequence is that recovery revisits still-listed nodes before the
 * invalidation point; _safe loop bodies must tolerate being re-run for
 * nodes they already saw (act by predicate, not one-shot).
 */
LWS_VISIBLE LWS_EXTERN struct lws_dll2 *
_lws_dll2_safe_next(struct lws_dll2_owner *ow, uint32_t *gen,
		    struct lws_dll2 *cand);

/*
 * Guarded backwards advance for the _safe_back iterator macros: identical
 * contract to _lws_dll2_safe_next(), except the cached node it validates is
 * the one towards the head, and invalidation recovers by restarting from the
 * live tail.
 */
LWS_VISIBLE LWS_EXTERN struct lws_dll2 *
_lws_dll2_safe_prev(struct lws_dll2_owner *ow, uint32_t *gen,
		    struct lws_dll2 *cand);

/*
 * Set to nonzero by tests (or apps that must not die) to make the _safe
 * iterator guard log + recover from cached-next invalidation instead of
 * asserting.  The default, 0, asserts loudly at the exact point of the
 * misuse, which is what you want during development.
 *
 * Deliberately mutable runtime state, not a const table entry.
 */
LWS_VISIBLE LWS_EXTERN_FOR_DATA int lws_dll2_guard_quiet; /* NOSONAR */

LWS_VISIBLE LWS_EXTERN void *
_lws_dll2_search_sz_pl(lws_dll2_owner_t *own, const char *name, size_t namelen,
		      size_t dll2_ofs, size_t ptr_ofs);

/*
 * Searches objects in an owner list linearly and returns one with a given
 * member C-string matching a supplied length-provided string if it exists, else
 * NULL.
 */

#define lws_dll2_search_sz_pl(own, name, namelen, type, membd2list, membptr) \
		((type *)_lws_dll2_search_sz_pl(own, name, namelen, \
					       offsetof(type, membd2list), \
					       offsetof(type, membptr)))

static LWS_INLINE void *
_lws_dll2_owner_container(const struct lws_dll2 *d, size_t owner_ofs)
{
	return d && d->owner ?
		(void *)((char *)d->owner - owner_ofs) : NULL;
}

/*
 * lws_dll2_owner_container(): get the object containing the owner the node
 * is attached to
 *
 * \param d: lws_dll2_t * member of some listed object
 * \param type: type of the object that embeds the lws_dll2_owner_t
 * \param membowner: member name of the lws_dll2_owner_t inside type
 *
 * Returns the object whose owner member the node is attached to, or NULL if
 * the node is detached (or NULL).  This is the dll2-native way to express
 * the lws_container_of(d->owner, type, membowner) idiom.  The node
 * expression is evaluated exactly once.
 */

#define lws_dll2_owner_container(___d, ___type, ___membowner) \
	((___type *)_lws_dll2_owner_container(___d, \
					offsetof(___type, ___membowner)))

#if defined(_DEBUG)
void
lws_dll2_describe(struct lws_dll2_owner *owner, const char *desc);
#else
#define lws_dll2_describe(x, y)
#endif

/*
 * these are safe against the current container object getting deleted,
 * since they hold his next in a temp and go to that next.  ___tmp is
 * the temp.
 *
 * Additionally the iterator is guarded at runtime: if the loop body
 * removes (and possibly frees) some *other* member of the list, e.g. the
 * cached next node itself, the guarded advance validates the cached next
 * against the live list (by pointer identity only, it is never
 * dereferenced) and, if it went away, asserts with a clear reason and
 * recovers by restarting from the live head, instead of walking into
 * freed memory and failing far away with no clue why.  The fast path when
 * nothing mutated the list is a single 32-bit compare per iteration.
 *
 * NOTE: ___start must be side-effect-free since it is evaluated once into
 * a temporary.
 *
 * NOTE: the recovery path restarts from the live head, which can revisit
 * earlier nodes still on the list; loop bodies must be idempotent under
 * being re-run for a node they already saw.
 */

#define lws_start_foreach_dll_safe(___type, ___it, ___tmp, ___start) \
{ \
	___type ___tmp; \
	struct lws_dll2 *___st_##___it = (___start); \
	struct lws_dll2_owner *___ow_##___it = \
			___st_##___it ? ___st_##___it->owner : NULL; \
	uint32_t ___gen_##___it = ___ow_##___it ? \
				      ___ow_##___it->generation : 0; \
	for (___type ___it = ___st_##___it; \
	     ___it && (((___tmp) = (___it)->next), 1); \
	     ___it = _lws_dll2_safe_next(___ow_##___it, &___gen_##___it, \
					 ___tmp)) {

#define lws_end_foreach_dll_safe(___it, ___tmp) \
	} \
}

#define lws_start_foreach_dll(___type, ___it, ___start) \
{ \
	for (___type ___it = (___start); ___it; ___it = (___it)->next) {

#define lws_end_foreach_dll(___it) \
	} \
}

/*
 * These are the same as the two iterators above, but walk the list
 * backwards: ___start is normally the owner's tail, eg
 * lws_dll2_get_tail(owner), and the walk advances along ->prev until it
 * reaches the head.  As with the forwards iterators, the plain version is
 * for loops that do not touch the list membership during the body.
 */

#define lws_start_foreach_dll_back(___type, ___it, ___start) \
{ \
	for (___type ___it = (___start); ___it; ___it = (___it)->prev) {

#define lws_end_foreach_dll_back(___it) \
	} \
}

/*
 * This is the _safe version of the backwards iterator: the cached previous
 * node is validated against the live list using the same generation-count
 * guard as the forwards _safe iterator, with a single 32-bit compare per
 * iteration when nothing has mutated the list.  If the loop body removed
 * (and possibly freed) the cached previous node, it asserts with a clear
 * reason and recovers by restarting from the live tail, so loop bodies
 * must be idempotent under being re-run for nodes they already saw.
 *
 * NOTE: ___start must be side-effect-free since it is evaluated once into
 * a temporary.
 */

#define lws_start_foreach_dll_safe_back(___type, ___it, ___tmp, ___start) \
{ \
	___type ___tmp; \
	struct lws_dll2 *___st_##___it = (___start); \
	struct lws_dll2_owner *___ow_##___it = \
			___st_##___it ? ___st_##___it->owner : NULL; \
	uint32_t ___gen_##___it = ___ow_##___it ? \
				      ___ow_##___it->generation : 0; \
	for (___type ___it = ___st_##___it; \
	     ___it && (((___tmp) = (___it)->prev), 1); \
	     ___it = _lws_dll2_safe_prev(___ow_##___it, &___gen_##___it, \
					 ___tmp)) {

#define lws_end_foreach_dll_safe_back(___it, ___tmp) \
	} \
}

///@}

