/*
 * lws-api-test-reclaim
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the reclaimable heap occupant registry against a simulated
 * heap limit: an allocation that would go past the limit makes the
 * allocator ask the least recently used unpinned occupants to evict, then
 * retries; pinned occupants are left alone; when nothing more can be
 * reclaimed the allocation fails cleanly and the registry keeps working.
 */

#include <libwebsockets.h>

#define BLOCK	4096

typedef struct tenant {
	lws_reclaimable_t	r;
	void			*block;
	const char		*name;
	int			evictions;
} tenant_t;

static size_t
tenant_evict(lws_reclaimable_t *r)
{
	tenant_t *t = lws_container_of(r, tenant_t, r);
	size_t freed = r->resident;

	lwsl_notice("%s: evicting %s\n", __func__, t->name);

	/* free only what can be recreated; never allocate here */
	lws_realloc(t->block, 0, __func__);
	t->block = NULL;
	r->resident = 0;
	t->evictions++;

	return freed;
}

static int
tenant_load(tenant_t *t)
{
	if (t->block)
		return 0;

	t->block = lws_realloc(NULL, BLOCK, __func__);
	if (!t->block)
		return 1;

	t->r.resident = BLOCK;
	lws_reclaimable_touch(&t->r);

	return 0;
}

int
main(int argc, const char **argv)
{
	tenant_t a = { .name = "a" }, b = { .name = "b" }, c = { .name = "c" };
	void *p1, *p2, *p3, *p4;
	size_t base;
	int e = 0;

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER, NULL);
	lwsl_user("LWS API selftest: reclaimable heap occupants\n");

	if (!lws_get_allocated_heap()) {
		lws_realloc(NULL, 16, "probe");
		if (!lws_get_allocated_heap()) {
			lwsl_user("no allocation accounting on this platform, "
				  "nothing to test\n");
			lwsl_user("Completed: PASS\n");
			return 0;
		}
	}

	a.r.evict = b.r.evict = c.r.evict = tenant_evict;
	lws_reclaimable_add(&a.r);
	lws_reclaimable_add(&b.r);
	lws_reclaimable_add(&c.r);

	/* all three resident: a is the least recently used */

	if (tenant_load(&a) || tenant_load(&b) || tenant_load(&c)) {
		lwsl_err("%s: load failed\n", __func__);
		return 1;
	}

	/* room for one more block and a bit, then the tenants must give */

	base = lws_get_allocated_heap();
	lws_heap_limit_set(base + BLOCK + BLOCK / 2);

	p1 = lws_realloc(NULL, BLOCK, "p1");
	if (!p1 || a.evictions || b.evictions || c.evictions) {
		lwsl_err("%s: 1: p1 %p a %d b %d c %d\n", __func__, p1,
			 a.evictions, b.evictions, c.evictions);
		e++;
	}

	/* over the limit: the LRU tenant, a, must be evicted to make room */

	p2 = lws_realloc(NULL, BLOCK, "p2");
	if (!p2 || a.evictions != 1 || b.evictions || c.evictions) {
		lwsl_err("%s: 2: p2 %p a %d b %d c %d\n", __func__, p2,
			 a.evictions, b.evictions, c.evictions);
		e++;
	}

	/* touching b makes c the LRU, but c is pinned: b goes instead */

	lws_reclaimable_touch(&b.r);
	lws_reclaimable_pin(&c.r);

	p3 = lws_realloc(NULL, BLOCK, "p3");
	if (!p3 || b.evictions != 1 || c.evictions) {
		lwsl_err("%s: 3: p3 %p b %d c %d\n", __func__, p3,
			 b.evictions, c.evictions);
		e++;
	}

	/* still pinned and the only thing left: the allocation must fail
	 * cleanly, not take c's block */

	p4 = lws_realloc(NULL, BLOCK, "p4");
	if (p4 || c.evictions || !c.block) {
		lwsl_err("%s: 4: p4 %p c %d\n", __func__, p4, c.evictions);
		e++;
	}

	/* unpinned, it is fair game */

	lws_reclaimable_unpin(&c.r);
	p4 = lws_realloc(NULL, BLOCK, "p4");
	if (!p4 || c.evictions != 1 || c.block) {
		lwsl_err("%s: 5: p4 %p c %d\n", __func__, p4, c.evictions);
		e++;
	}

	/* nothing left to reclaim: a clean failure, and the registry is
	 * still usable afterwards (a reload with the limit lifted) */

	if (lws_realloc(NULL, BLOCK, "p5")) {
		lwsl_err("%s: 6: allocation succeeded past the limit\n",
			 __func__);
		e++;
	}

	lws_heap_limit_set(0);
	if (tenant_load(&a) || !a.block) {
		lwsl_err("%s: 7: reload failed\n", __func__);
		e++;
	}
	if (lws_reclaim(1) != BLOCK || a.evictions != 2) {
		lwsl_err("%s: 8: explicit reclaim %d\n", __func__, a.evictions);
		e++;
	}

	lws_realloc(p1, 0, "p1");
	lws_realloc(p2, 0, "p2");
	lws_realloc(p3, 0, "p3");
	lws_realloc(p4, 0, "p4");
	lws_reclaimable_remove(&a.r);
	lws_reclaimable_remove(&b.r);
	lws_reclaimable_remove(&c.r);

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return !!e;
}
