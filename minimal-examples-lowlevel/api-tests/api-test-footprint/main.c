/*
 * lws api test footprint
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises lws_footprint the way owners use it: participants count what
 * they add, free and resize, the totals add up, shedding asks the cheapest
 * classes first and stops at the most costly class asked for, a .shed that
 * frees other participants (and itself) doesn't derail the shedding, and a
 * participant still registered when the context goes is detached safely.
 *
 * With LWS_WITH_ALLOC_SITES, it also checks lws_alloc_sites() lists what
 * lws_*alloc() holds by the reason given, through realloc and free.
 */

#include <libwebsockets.h>
#include <string.h>

typedef struct cache {
	lws_footprint_t		fp;
	size_t			spare;	/* what it could give back */
	struct cache		*victim; /* unregistered by our .shed */
	int			asked;
} cache_t;

static const char *src_idle = "test idle pool", *src_cache = "test cache",
		  *src_plain = "test plain list";

static void
cache_report(lws_footprint_t *fp, lws_footprint_report_t *r)
{
	cache_t *c = lws_container_of(fp, cache_t, fp);

	r->sheddable = c->spare;
}

static void
cache_dump(lws_footprint_t *fp)
{
	cache_t *c = lws_container_of(fp, cache_t, fp);

	lwsl_notice("    spare %u\n", (unsigned int)c->spare);
}

static size_t
cache_shed(lws_footprint_t *fp, size_t want)
{
	cache_t *c = lws_container_of(fp, cache_t, fp);
	size_t f = c->spare < want ? c->spare : want;

	c->asked++;
	c->spare -= f;
	lws_footprint_resize(fp, fp->bytes, fp->bytes - f);

	if (c->victim) {
		/* freeing this takes another participant, and us, away */
		lws_footprint_unregister(&c->victim->fp);
		lws_footprint_unregister(fp);
	}

	return f;
}

static const lws_footprint_ops_t ops_idle = {
	.shed_class	= LWSFP_SHED_IDLE,
	.report		= cache_report,
	.dump		= cache_dump,
	.shed		= cache_shed,
}, ops_cache = {
	.shed_class	= LWSFP_SHED_CACHE,
	.report		= cache_report,
	.dump		= cache_dump,
	.shed		= cache_shed,
}, ops_conn = {
	.shed_class	= LWSFP_SHED_CONN,
	.report		= cache_report,
	.shed		= cache_shed,
};

static int
expect(const char *what, long long got, long long want)
{
	if (got == want)
		return 0;

	lwsl_err("%s: %s: got %lld, expected %lld\n", __func__, what, got,
		 want);

	return 1;
}

#if defined(LWS_WITH_ALLOC_SITES)
static lws_alloc_site_t sites[256];

/* what is live with this reason, from however many callers */
static void
site_sum(const char *reason, long long *bytes, long long *count, int *sorted)
{
	lws_alloc_site_t rest;
	int n, ns;

	ns = lws_alloc_sites(sites, (int)LWS_ARRAY_SIZE(sites), &rest);
	*bytes = *count = 0;
	*sorted = 1;
	for (n = 0; n < ns; n++) {
		if (n && sites[n].bytes > sites[n - 1].bytes)
			*sorted = 0;
		if (!strcmp(sites[n].reason, reason)) {
			*bytes += (long long)sites[n].bytes;
			*count += sites[n].count;
		}
	}
}

/*
 * Every lws_*alloc() is listed by the reason it gave (only lws_realloc() is
 * exported, which allocates from NULL and frees to 0 bytes), at the size it asked
 * for, through realloc, which may move it and change its reason, until it's
 * freed
 */
static int
test_alloc_sites(void)
{
	long long bytes, count;
	uint8_t *a1, *a2, *b;
	int e = 0, sorted;

	a1 = lws_realloc(NULL, 100, "fp test a");
	a2 = lws_realloc(NULL, 100, "fp test a");
	b = lws_realloc(NULL, 5000, "fp test b");
	if (!a1 || !a2 || !b) {
		lwsl_err("%s: OOM\n", __func__);
		return 1;
	}
	memset(a1, 0x5a, 100);

	site_sum("fp test a", &bytes, &count, &sorted);
	e += expect("site a bytes", bytes, 200);
	e += expect("site a count", count, 2);
	e += expect("sites biggest first", sorted, 1);
	site_sum("fp test b", &bytes, &count, &sorted);
	e += expect("site b bytes", bytes, 5000);
	e += expect("site b count", count, 1);

	/* grown past where it can stay, it moves, and is listed anew */

	a1 = lws_realloc(a1, 30000, "fp test a2");
	if (!a1) {
		lwsl_err("%s: realloc OOM\n", __func__);
		return 1;
	}
	e += expect("realloc kept data", a1[0] == 0x5a && a1[99] == 0x5a, 1);
	site_sum("fp test a", &bytes, &count, &sorted);
	e += expect("site a after realloc", bytes, 100);
	site_sum("fp test a2", &bytes, &count, &sorted);
	e += expect("site a2 bytes", bytes, 30000);
	e += expect("site a2 count", count, 1);

	lws_realloc(a1, 0, "free");
	lws_realloc(a2, 0, "free");
	lws_realloc(b, 0, "free");

	site_sum("fp test a", &bytes, &count, &sorted);
	e += expect("site a freed", count, 0);
	site_sum("fp test a2", &bytes, &count, &sorted);
	e += expect("site a2 freed", count, 0);
	site_sum("fp test b", &bytes, &count, &sorted);
	e += expect("site b freed", count, 0);

	return e;
}
#endif

int
main(int argc, const char **argv)
{
	int e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	cache_t idle, cache1, cache2, conn, plain, late;
	struct lws_context_creation_info info;
	lws_footprint_report_t r, base;
	struct lws_context *cx;
	const char *p;
	int nbase;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lws_footprint\n");

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("context creation failed\n");
		return 1;
	}

	/* the context's own participants, eg, its vhost, are there already */
	nbase = lws_footprint_total(cx, &base);

	memset(&idle, 0, sizeof(idle));
	memset(&cache1, 0, sizeof(cache1));
	memset(&cache2, 0, sizeof(cache2));
	memset(&conn, 0, sizeof(conn));
	memset(&plain, 0, sizeof(plain));
	memset(&late, 0, sizeof(late));

	/* a participant with no ops only counts */

	lws_footprint_register(cx, &plain.fp, src_plain, NULL);
	lws_footprint_add(&plain.fp, 100);
	lws_footprint_add(&plain.fp, 200);
	lws_footprint_resize(&plain.fp, 200, 50);
	lws_footprint_sub(&plain.fp, 100);
	e += expect("plain count", (long long)plain.fp.count, 1);
	e += expect("plain bytes", (long long)plain.fp.bytes, 50);
	e += expect("plain hwm", (long long)plain.fp.bytes_hwm, 300);

	/* more freed than held doesn't wrap */

	lws_footprint_sub(&plain.fp, 1000);
	lws_footprint_sub(&plain.fp, 1000);
	e += expect("plain underflow count", (long long)plain.fp.count, 0);
	e += expect("plain underflow bytes", (long long)plain.fp.bytes, 0);
	lws_footprint_add(&plain.fp, 50);

	lws_footprint_register(cx, &idle.fp, src_idle, &ops_idle);
	lws_footprint_set_ident(&idle.fp, "pool-a");
	lws_footprint_add(&idle.fp, 1000);
	idle.spare = 400;

	lws_footprint_register(cx, &cache1.fp, src_cache, &ops_cache);
	lws_footprint_set_ident(&cache1.fp, "one");
	lws_footprint_add(&cache1.fp, 2000);
	cache1.spare = 2000;

	/* cache2's .shed takes cache1 and itself away */
	lws_footprint_register(cx, &cache2.fp, src_cache, &ops_cache);
	lws_footprint_set_ident(&cache2.fp, "two");
	lws_footprint_add(&cache2.fp, 3000);
	cache2.spare = 3000;
	cache2.victim = &cache1;

	lws_footprint_register(cx, &conn.fp, "test conn", &ops_conn);
	lws_footprint_add(&conn.fp, 5000);
	conn.spare = 5000;

	e += expect("participants", lws_footprint_total(cx, &r), nbase + 5);
	e += expect("total count", (long long)(r.count - base.count), 5);
	e += expect("total bytes", (long long)(r.bytes - base.bytes),
					50 + 1000 + 2000 + 3000 + 5000);
	e += expect("total sheddable", (long long)(r.sheddable -
				base.sheddable), 400 + 2000 + 3000 + 5000);

	lws_footprint_dump(cx, 1);

#if defined(LWS_WITH_ALLOC_SITES)
	e += test_alloc_sites();
#endif

	/* asking only for what IDLE has stops there */

	e += expect("shed idle", (long long)lws_footprint_shed(cx, 300,
						LWSFP_SHED_CONN), 300);
	e += expect("idle asked", idle.asked, 1);
	e += expect("cache1 not asked", cache1.asked, 0);
	e += expect("idle bytes", (long long)idle.fp.bytes, 700);

	/*
	 * Up to CACHE, wanting everything: idle gives its last 100, then
	 * cache1 everything, then cache2, which takes cache1 and itself away
	 * mid-shedding.  conn is never asked.
	 */

	e += expect("shed to cache", (long long)lws_footprint_shed(cx, 100000,
				LWSFP_SHED_CACHE), 100 + 2000 + 3000);
	e += expect("idle asked again", idle.asked, 2);
	e += expect("cache1 asked", cache1.asked, 1);
	e += expect("cache2 asked", cache2.asked, 1);
	e += expect("conn not asked", conn.asked, 0);
	e += expect("participants after", lws_footprint_total(cx, &r),
								nbase + 3);

	/* nothing left below CONN */

	e += expect("shed nothing", (long long)lws_footprint_shed(cx, 1,
						LWSFP_SHED_CACHE), 0);
	e += expect("shed conn", (long long)lws_footprint_shed(cx, 100000,
						LWSFP_SHED_CONN), 5000);
	e += expect("conn asked", conn.asked, 1);

	/* unregistering twice is harmless */

	lws_footprint_unregister(&idle.fp);
	lws_footprint_unregister(&idle.fp);
	lws_footprint_unregister(&conn.fp);
	e += expect("participants left", lws_footprint_total(cx, &r),
								nbase + 1);

	/* one left registered as the context goes is detached */

	lws_footprint_register(cx, &late.fp, "test outlives context", NULL);
	lws_footprint_add(&late.fp, 1);
	lws_footprint_unregister(&plain.fp);

	lws_context_destroy(cx);

	e += expect("late detached", !late.fp.list.owner, 1);
	lws_footprint_unregister(&late.fp);

	if (e)
		lwsl_user("Completed: FAIL (%d)\n", e);
	else
		lwsl_user("Completed: PASS\n");

	return !!e;
}
