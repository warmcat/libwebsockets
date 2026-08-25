/*
 * lws-api-test-dll2-guard
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the lws_dll2 _safe iterator runtime guard: classic current-node
 * removal must keep working cheaply, while a loop body that invalidates the
 * cached NEXT node (the use-after-free class seen in the QUIC close_after_rx
 * external report) must be detected at the iteration step and recovered by
 * re-seeding from the live head instead of walking into freed nodes.
 *
 * Also covers the read accessors (count / emptiness / head / tail / next /
 * prev), the owner-container resolution helper and the backwards iterators,
 * including the tail-restart recovery of the guarded backwards walk.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct tdll {
	lws_dll2_t		list;
	int			n;
};

/* the owner side of the owner-container helper test */
struct td_owner {
	lws_dll2_owner_t	ow;
};

static int ecount, seq[8], seqn, armed;
static struct tdll *
td(int n)
{
	struct tdll *t = malloc(sizeof(*t));

	if (!t)
		abort();

	memset(t, 0, sizeof(*t));
	t->n = n;

	return t;
}

/* add a node with value n at tail */
static struct tdll *
td_add(lws_dll2_owner_t *ow, int n)
{
	struct tdll *t = td(n);

	lws_dll2_add_tail(&t->list, ow);

	return t;
}

static int
cb_remove_current(struct lws_dll2 *d, void *user)
{
	struct tdll *t = lws_container_of(d, struct tdll, list);

	ecount += t->n;
	lws_dll2_remove(d);
	free(t);
	(void)user;

	return 0;
}

int main(int argc, const char **argv)
{
	lws_dll2_owner_t ow;
	struct td_owner to;
	struct tdll *A, *B, *C, *D, *Z;
	uint32_t g;
	int n, bad = 0;

	if (argc > 1 && !strcmp(argv[1], "--help")) {
		printf("usage: %s [--help]\n", argv[0]);

		return 0;
	}

	lws_set_log_level(0, NULL);

	/*
	 * 1: generation accounting on the owner
	 */

	memset(&ow, 0, sizeof(ow));
	lws_dll2_owner_clear(&ow);
	g = ow.generation;

	A = td_add(&ow, 1);
	if (ow.generation == g)
		bad++, printf("FAIL: add did not bump generation\n");
	g = ow.generation;

	if (!lws_dll2_is_in_list(&ow, &A->list))
		bad++, printf("FAIL: member not found in list\n");

	lws_dll2_remove(&A->list);
	if (ow.generation == g)
		bad++, printf("FAIL: remove did not bump generation\n");
	g = ow.generation;

	/* removed-but-still-allocated node is correctly reported as absent */
	if (lws_dll2_is_in_list(&ow, &A->list))
		bad++, printf("FAIL: removed node reported in list\n");

	/* a node that was never on any list is reported absent */
	Z = td(9);
	if (lws_dll2_is_in_list(&ow, &Z->list))
		bad++, printf("FAIL: never-attached node reported in list\n");
	free(Z);

	lws_dll2_add_tail(&A->list, &ow);
	g = ow.generation;
	lws_dll2_owner_clear(&ow);
	if (ow.generation == g)
		bad++, printf("FAIL: owner_clear did not change generation\n");
	free(A);

	if (bad)
		goto done;

	/*
	 * 2: classic supported usage, body removes the CURRENT node
	 */

	memset(&ow, 0, sizeof(ow));
	for (n = 1; n <= 6; n++)
		td_add(&ow, n);

	ecount = 0;
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, ow.head) {
		struct tdll *t = lws_container_of(p, struct tdll, list);
		ecount += t->n;
		lws_dll2_remove(p);
		free(t);
	} lws_end_foreach_dll_safe(p, p1);

	if (ecount != 1 + 2 + 3 + 4 + 5 + 6)
		bad++, printf("FAIL: current-node removal lost nodes (%d)\n",
				ecount);
	if (ow.count)
		bad++, printf("FAIL: list not drained (%u)\n", ow.count);

	/* same via the callback helper */

	for (n = 1; n <= 6; n++)
		td_add(&ow, n);

	ecount = 0;
	if (lws_dll2_foreach_safe(&ow, NULL, cb_remove_current))
		bad++, printf("FAIL: foreach_safe unexpected early return\n");
	if (ecount != 1 + 2 + 3 + 4 + 5 + 6)
		bad++, printf("FAIL: foreach_safe lost nodes (%d)\n", ecount);
	if (ow.count)
		bad++, printf("FAIL: foreach_safe list not drained\n");

	/*
	 * 3: the reported bug class... the body removes AND FREES the cached
	 *    NEXT node.  Keep the guard nonfatal so we can assert the recovery
	 *    from here.
	 *
	 *    The recovery re-seeds from the live head, so the surviving current
	 *    node A is revisited before the walk continues down the list.  The
	 *    "armed" one-shot makes the revisit explicit: _safe loop bodies
	 *    must tolerate being re-run for a node they already saw.
	 */

	memset(&ow, 0, sizeof(ow));
	A = td_add(&ow, 1);
	B = td_add(&ow, 2);
	C = td_add(&ow, 3);
	D = td_add(&ow, 4);

	assert(!lws_dll2_guard_quiet);
	lws_dll2_guard_quiet = 1;	/* tests only: recover, don't assert */

	seqn = 0;
	armed = 1;
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, ow.head) {
		struct tdll *t = lws_container_of(p, struct tdll, list);

		seq[seqn++] = t->n;

		if (t->n == 1 && armed) {
			/* free the cached-next node B under the iterator */
			assert(p1 == &B->list);
			armed = 0;
			lws_dll2_remove(p1);
			free(B);
		}
	} lws_end_foreach_dll_safe(p, p1);

	lws_dll2_guard_quiet = 0;

	/* A, then the head-restart revisits A, then C, then D */
	if (seqn != 4 || seq[0] != 1 || seq[1] != 1 || seq[2] != 3 ||
	    seq[3] != 4)
		bad++, printf("FAIL: cached-next free not recovered: "
				"n %d {%d,%d,%d,%d}\n", seqn, seq[0], seq[1],
				seq[2], seq[3]);
	if (ow.count != 3)
		bad++, printf("FAIL: recovery munged count (%u)\n", ow.count);

	lws_dll2_remove(&A->list);	free(A);
	lws_dll2_remove(&C->list);	free(C);
	lws_dll2_remove(&D->list);	free(D);

	/*
	 * 4: body frees the next TWO nodes, recovery must still track the
	 *    live list
	 */

	memset(&ow, 0, sizeof(ow));
	A = td_add(&ow, 1);
	B = td_add(&ow, 2);
	C = td_add(&ow, 3);
	D = td_add(&ow, 4);

	lws_dll2_guard_quiet = 1;
	seqn = 0;
	armed = 1;
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, ow.head) {
		struct tdll *t = lws_container_of(p, struct tdll, list);

		seq[seqn++] = t->n;

		if (t->n == 1 && armed) {
			armed = 0;
			lws_dll2_remove(&B->list);
			free(B);
			lws_dll2_remove(&C->list);
			free(C);
		}
	} lws_end_foreach_dll_safe(p, p1);
	lws_dll2_guard_quiet = 0;

	/* A, head-restart revisits A, then D */
	if (seqn != 3 || seq[0] != 1 || seq[1] != 1 || seq[2] != 4)
		bad++, printf("FAIL: double-next free not recovered: "
				"n %d {%d,%d,%d}\n", seqn, seq[0], seq[1],
				seq[2]);
	if (ow.count != 2)
		bad++, printf("FAIL: recovery munged count (%u)\n", ow.count);

	lws_dll2_remove(&A->list);	free(A);
	lws_dll2_remove(&D->list);	free(D);

	/*
	 * 5: "close everything" body frees CURRENT and NEXT... the guard
	 *    re-seeds from the live head and terminates
	 */

	memset(&ow, 0, sizeof(ow));
	A = td_add(&ow, 1);
	B = td_add(&ow, 2);
	C = td_add(&ow, 3);
	D = td_add(&ow, 4);

	lws_dll2_guard_quiet = 1;
	seqn = 0;
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, ow.head) {
		struct tdll *t = lws_container_of(p, struct tdll, list);

		seq[seqn++] = t->n;

		if (t->n == 1) {
			lws_dll2_remove(&A->list);
			free(A);
			lws_dll2_remove(&B->list);
			free(B);
		}
	} lws_end_foreach_dll_safe(p, p1);
	lws_dll2_guard_quiet = 0;

	if (seqn != 3 || seq[0] != 1 || seq[1] != 3 || seq[2] != 4)
		bad++, printf("FAIL: current+next free not recovered: "
				"n %d {%d,%d,%d}\n", seqn, seq[0], seq[1],
				seq[2]);
	if (ow.count != 2)
		bad++, printf("FAIL: recovery munged count (%u)\n", ow.count);

	lws_dll2_remove(&C->list);	free(C);
	lws_dll2_remove(&D->list);	free(D);

	/*
	 * 6: read accessors and owner-container resolution
	 */

	memset(&ow, 0, sizeof(ow));
	lws_dll2_owner_clear(&ow);

	if (!lws_dll2_is_empty(&ow) || lws_dll2_count(&ow))
		bad++, printf("FAIL: cleared owner not reported empty\n");
	if (!lws_dll2_is_empty(NULL) || lws_dll2_count(NULL))
		bad++, printf("FAIL: NULL owner not reported empty\n");
	if (lws_dll2_get_head(&ow) || lws_dll2_get_tail(&ow) ||
	    lws_dll2_get_head(NULL) || lws_dll2_get_tail(NULL))
		bad++, printf("FAIL: empty owner has a head or tail\n");
	if (lws_dll2_get_next(NULL) || lws_dll2_get_prev(NULL))
		bad++, printf("FAIL: NULL node has a next or prev\n");

	A = td_add(&ow, 1);
	B = td_add(&ow, 2);
	C = td_add(&ow, 3);
	D = td_add(&ow, 4);

	if (lws_dll2_is_empty(&ow) || lws_dll2_count(&ow) != 4)
		bad++, printf("FAIL: count wrong (%u)\n",
				(unsigned int)lws_dll2_count(&ow));
	if (lws_dll2_get_head(&ow) != &A->list ||
	    lws_dll2_get_tail(&ow) != &D->list)
		bad++, printf("FAIL: head or tail wrong\n");
	if (lws_dll2_get_next(&A->list) != &B->list ||
	    lws_dll2_get_next(&B->list) != &C->list ||
	    lws_dll2_get_next(&D->list) ||
	    lws_dll2_get_prev(&A->list) ||
	    lws_dll2_get_prev(&B->list) != &A->list ||
	    lws_dll2_get_prev(&D->list) != &C->list)
		bad++, printf("FAIL: next or prev chain wrong\n");

	/* a detached node has no links in either direction */

	lws_dll2_remove(&B->list);
	if (lws_dll2_get_next(&B->list) || lws_dll2_get_prev(&B->list) ||
	    !lws_dll2_is_detached(&B->list))
		bad++, printf("FAIL: detached node still has links\n");
	free(B);
	lws_dll2_remove(&A->list);	free(A);
	lws_dll2_remove(&C->list);	free(C);
	lws_dll2_remove(&D->list);	free(D);

	memset(&to, 0, sizeof(to));
	lws_dll2_owner_clear(&to.ow);

	Z = td_add(&to.ow, 5);
	if (lws_dll2_owner_container(&Z->list, struct td_owner, ow) != &to)
		bad++, printf("FAIL: owner container resolution wrong\n");
	if (lws_dll2_owner_container(NULL, struct td_owner, ow))
		bad++, printf("FAIL: NULL node resolves a container\n");

	lws_dll2_remove(&Z->list);
	if (lws_dll2_owner_container(&Z->list, struct td_owner, ow))
		bad++, printf("FAIL: detached node resolves a container\n");
	free(Z);

	/*
	 * 7: backwards iteration, plain and guarded
	 */

	memset(&ow, 0, sizeof(ow));
	A = td_add(&ow, 1);
	B = td_add(&ow, 2);
	C = td_add(&ow, 3);
	D = td_add(&ow, 4);

	seqn = 0;
	lws_start_foreach_dll_back(struct lws_dll2 *, p, ow.tail) {
		struct tdll *t = lws_container_of(p, struct tdll, list);

		seq[seqn++] = t->n;
	} lws_end_foreach_dll_back(p);

	if (seqn != 4 || seq[0] != 4 || seq[1] != 3 || seq[2] != 2 ||
	    seq[3] != 1)
		bad++, printf("FAIL: backwards walk order wrong: "
				"n %d {%d,%d,%d,%d}\n", seqn, seq[0], seq[1],
				seq[2], seq[3]);

	lws_dll2_remove(&A->list);	free(A);
	lws_dll2_remove(&B->list);	free(B);
	lws_dll2_remove(&C->list);	free(C);
	lws_dll2_remove(&D->list);	free(D);

	/* backwards _safe with the body removing the current node */

	memset(&ow, 0, sizeof(ow));
	for (n = 1; n <= 6; n++)
		td_add(&ow, n);

	ecount = 0;
	lws_start_foreach_dll_safe_back(struct lws_dll2 *, p, p1, ow.tail) {
		struct tdll *t = lws_container_of(p, struct tdll, list);

		ecount += t->n;
		lws_dll2_remove(p);
		free(t);
	} lws_end_foreach_dll_safe_back(p, p1);

	if (ecount != 1 + 2 + 3 + 4 + 5 + 6)
		bad++, printf("FAIL: backwards current-node removal lost "
				"nodes (%d)\n", ecount);
	if (lws_dll2_count(&ow))
		bad++, printf("FAIL: backwards walk list not drained (%u)\n",
				(unsigned int)lws_dll2_count(&ow));

	/*
	 * 8: the reported bug class in the backwards walk... the body frees
	 *    the cached PREV node.  Recovery must restart from the live tail
	 *    rather than walk into the freed node.
	 */

	memset(&ow, 0, sizeof(ow));
	A = td_add(&ow, 1);
	B = td_add(&ow, 2);
	C = td_add(&ow, 3);
	D = td_add(&ow, 4);

	assert(!lws_dll2_guard_quiet);
	lws_dll2_guard_quiet = 1;	/* tests only: recover, don't assert */

	seqn = 0;
	armed = 1;
	lws_start_foreach_dll_safe_back(struct lws_dll2 *, p, p1, ow.tail) {
		struct tdll *t = lws_container_of(p, struct tdll, list);

		seq[seqn++] = t->n;

		if (t->n == 4 && armed) {
			/* free the cached-prev node C under the iterator */
			assert(p1 == &C->list);
			armed = 0;
			lws_dll2_remove(p1);
			free(C);
		}
	} lws_end_foreach_dll_safe_back(p, p1);

	lws_dll2_guard_quiet = 0;

	/* D, then the tail-restart revisits D, then B, then A */
	if (seqn != 4 || seq[0] != 4 || seq[1] != 4 || seq[2] != 2 ||
	    seq[3] != 1)
		bad++, printf("FAIL: cached-prev free not recovered: "
				"n %d {%d,%d,%d,%d}\n", seqn, seq[0], seq[1],
				seq[2], seq[3]);
	if (lws_dll2_count(&ow) != 3)
		bad++, printf("FAIL: backwards recovery munged count (%u)\n",
				(unsigned int)lws_dll2_count(&ow));

	lws_dll2_remove(&A->list);	free(A);
	lws_dll2_remove(&B->list);	free(B);
	lws_dll2_remove(&D->list);	free(D);

done:
	if (bad)
		printf("api-test-dll2-guard: %d failures\n", bad);
	else
		printf("api-test-dll2-guard: pass\n");

	return !!bad;
}
