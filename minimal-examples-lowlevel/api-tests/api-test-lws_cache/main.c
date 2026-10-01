/*
 * lws-api-test-lws_cache
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>

static struct lws_context *cx;
static int tests, fail;

/*
 * A sul that lives in the app and so outlives the context... used to confirm
 * the context destroy detaches it, so lws_sul_cancel() on it afterwards is a
 * NOP and not a write into the freed context
 */

static lws_sorted_usec_list_t sul_outlives_cx;
static int sul_outlives_cx_fired;

static void
sul_outlives_cx_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	sul_outlives_cx_fired++;
}

static int
test_just_l1(void)
{
	struct lws_cache_creation_info ci;
	struct lws_cache_ttl_lru *l1;
	int ret = 1;
	size_t size;
	char *po;

	lwsl_user("%s\n", __func__);

	tests++;

	/* just create a heap cache "L1" */

	memset(&ci, 0, sizeof(ci));
	ci.cx = cx;
	ci.ops = &lws_cache_ops_heap;
	ci.name = "L1";

	l1 = lws_cache_create(&ci);
	if (!l1)
		goto cdone;

	/* add two items, a has 1s expiry and b has 2s */

	if (lws_cache_write_through(l1, "a", (const uint8_t *)"is_a", 5,
				    lws_now_usecs() + LWS_US_PER_SEC, NULL))
		goto cdone;

	if (lws_cache_write_through(l1, "b", (const uint8_t *)"is_b", 5,
				    lws_now_usecs() + LWS_US_PER_SEC * 2, NULL))
		goto cdone;

	/* check they exist as intended */

	if (lws_cache_item_get(l1, "a", (const void **)&po, &size) ||
	    size != 5 || strcmp(po, "is_a"))
		goto cdone;

	if (lws_cache_item_get(l1, "b", (const void **)&po, &size) ||
	    size != 5 || strcmp(po, "is_b"))
		goto cdone;

	/* wait for 1.2s to pass, working the event loop by hand */

	lws_cancel_service(cx);
	if (lws_service(cx, 0) < 0)
		goto cdone;
#if defined(WIN32)
	Sleep(1200);
#else
	/* netbsd cares about < 1M */
	usleep(999999);
	usleep(200001);
#endif
	lws_cancel_service(cx);
	if (lws_service(cx, 0) < 0)
		goto cdone;

	lws_cancel_service(cx);
	if (lws_service(cx, 0) < 0)
		goto cdone;

	/* a only had 1s lifetime, he should be gone */

	if (!lws_cache_item_get(l1, "a", (const void **)&po, &size)) {
		lwsl_err("%s: cache: a still exists after expiry\n", __func__);
		fail++;
		goto cdone;
	}

	/* that's ok then */

	ret = 0;

cdone:
	lws_cache_destroy(&l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

static int
test_just_l1_limits(void)
{
	struct lws_cache_creation_info ci;
	struct lws_cache_ttl_lru *l1;
	int ret = 1;
	size_t size;
	char *po;

	lwsl_user("%s\n", __func__);
	tests++;

	/* just create a heap cache "L1" */

	memset(&ci, 0, sizeof(ci));
	ci.cx = cx;
	ci.ops = &lws_cache_ops_heap;
	ci.name = "L1_lim";
	ci.max_items = 1; /* ie, adding a second item destroys the first */

	l1 = lws_cache_create(&ci);
	if (!l1)
		goto cdone;

	/* add two items, a has 1s expiry and b has 2s */

	if (lws_cache_write_through(l1, "a", (const uint8_t *)"is_a", 5,
				    lws_now_usecs() + LWS_US_PER_SEC, NULL))
		goto cdone;

	if (lws_cache_write_through(l1, "b", (const uint8_t *)"is_b", 5,
				    lws_now_usecs() + LWS_US_PER_SEC * 2, NULL))
		goto cdone;

	/* only b should exit, since we limit to cache to just one entry */

	if (!lws_cache_item_get(l1, "a", (const void **)&po, &size))
		goto cdone;

	if (lws_cache_item_get(l1, "b", (const void **)&po, &size) ||
	    size != 5 || strcmp(po, "is_b"))
		goto cdone;

	/* that's ok then */

	ret = 0;

cdone:
	lws_cache_destroy(&l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

/*
 * With lws_service_set_now(), the service thread's time is what the embedder
 * says, not the platform's clock, and item expiries are in that time.  Items
 * must still expire on it.  This runs last, since once the time is external
 * it stays external.
 */

static int
test_l1_external_time(void)
{
	lws_usec_t t0 = lws_now_usecs() / 2; /* well behind the platform's */
	struct lws_cache_creation_info ci;
	struct lws_cache_ttl_lru *l1;
	int ret = 1;
	size_t size;
	char *po;

	lwsl_user("%s\n", __func__);
	tests++;

	memset(&ci, 0, sizeof(ci));
	ci.cx = cx;
	ci.ops = &lws_cache_ops_heap;
	ci.name = "L1_ext";

	l1 = lws_cache_create(&ci);
	if (!l1)
		goto cdone;

	lws_service_set_now(cx, 0, t0, 0);

	if (lws_cache_write_through(l1, "a", (const uint8_t *)"is_a", 5,
				    t0 + LWS_US_PER_SEC, NULL) ||
	    lws_cache_write_through(l1, "b", (const uint8_t *)"is_b", 5,
				    t0 + 10 * LWS_US_PER_SEC, NULL))
		goto cdone;

	/* a little time passes, then enough for a, but not b, to expire */

	lws_service_set_now(cx, 0, t0 + 10 * LWS_US_PER_MS, 0);
	lws_service_set_now(cx, 0, t0 + 2 * LWS_US_PER_SEC, 0);

	if (!lws_cache_item_get(l1, "a", (const void **)&po, &size)) {
		lwsl_err("%s: a still exists after expiry\n", __func__);
		goto cdone;
	}

	if (lws_cache_item_get(l1, "b", (const void **)&po, &size) ||
	    size != 5 || strcmp(po, "is_b")) {
		lwsl_err("%s: b is missing\n", __func__);
		goto cdone;
	}

	ret = 0;

cdone:
	lws_cache_destroy(&l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR)

static const char
	*cookie1 = "host.com\tFALSE\t/\tTRUE\t4000000000\tmycookie\tmycookievalue",
	*tag_cookie1 = "host.com|/|mycookie",
	*cookie2 = "host.com\tFALSE\t/xxx\tTRUE\t4000000000\tmycookie\tmyxxxcookievalue",
	*tag_cookie2 = "host.com|/xxx|mycookie",
	*cookie3 = "host.com\tFALSE\t/\tTRUE\t4000000000\textra\tcookie3value",
	*tag_cookie3 = "host.com|/|extra",
	*cookie4 = "host.com\tFALSE\t/yyy\tTRUE\t4000000000\tnewcookie\tnewcookievalue",
	*tag_cookie4 = "host.com|/yyy|newcookie"
;

static int
test_nsc1(void)
{
	struct lws_cache_creation_info ci;
	struct lws_cache_ttl_lru *l1 = NULL, *nsc;
	lws_cache_results_t cr;
	int n, ret = 1;
	size_t size;
	char *po;

	lwsl_user("%s\n", __func__);
	tests++;

	/* First create a netscape cookie cache object */

	memset(&ci, 0, sizeof(ci));
	ci.cx = cx;
	ci.ops = &lws_cache_ops_nscookiejar;
	ci.name = "NSC";
	ci.u.nscookiejar.filepath = "./cookies.txt";

	nsc = lws_cache_create(&ci);
	if (!nsc)
		goto cdone;

	/* Then a heap cache "L1" as a child of nsc */

	ci.ops = &lws_cache_ops_heap;
	ci.name = "L1";
	ci.parent = nsc;

	l1 = lws_cache_create(&ci);
	if (!l1)
		goto cdone;

	lws_cache_debug_dump(nsc);
	lws_cache_debug_dump(l1);

	lwsl_user("%s: add cookies to L1\n", __func__);

	/* add three cookies */

	if (lws_cache_write_through(l1, tag_cookie1,
				    (const uint8_t *)cookie1, strlen(cookie1),
				    lws_now_usecs() + LWS_US_PER_SEC, NULL)) {
		lwsl_err("%s: write1 failed\n", __func__);
		goto cdone;
	}

	lws_cache_debug_dump(nsc);
	lws_cache_debug_dump(l1);

	if (lws_cache_write_through(l1, tag_cookie2,
				    (const uint8_t *)cookie2, strlen(cookie2),
				    lws_now_usecs() + LWS_US_PER_SEC * 2, NULL)) {
		lwsl_err("%s: write2 failed\n", __func__);
		goto cdone;
	}

	lws_cache_debug_dump(nsc);
	lws_cache_debug_dump(l1);

	if (lws_cache_write_through(l1, tag_cookie3,
				    (const uint8_t *)cookie3, strlen(cookie3),
				    lws_now_usecs() + LWS_US_PER_SEC * 2, NULL)) {
		lwsl_err("%s: write3 failed\n", __func__);
		goto cdone;
	}

	lws_cache_debug_dump(nsc);
	lws_cache_debug_dump(l1);

	lwsl_user("%s: check cookies in L1\n", __func__);

	/* confirm that the cookies are individually in L1 */

	if (lws_cache_item_get(l1, tag_cookie1, (const void **)&po, &size) ||
	    size != strlen(cookie1) || memcmp(po, cookie1, size)) {
		lwsl_err("%s: L1 '%s' missing, size %llu, po %s\n", __func__,
			 tag_cookie1, (unsigned long long)size, po);
		goto cdone;
	}

	if (lws_cache_item_get(l1, tag_cookie2, (const void **)&po, &size) ||
	    size != strlen(cookie2) || memcmp(po, cookie2, size)) {
		lwsl_err("%s: L1 '%s' missing\n", __func__, tag_cookie2);
		goto cdone;
	}

	if (lws_cache_item_get(l1, tag_cookie3, (const void **)&po, &size) ||
	    size != strlen(cookie3) || memcmp(po, cookie3, size)) {
		lwsl_err("%s: L1 '%s' missing\n", __func__, tag_cookie3);
		goto cdone;
	}

	/* confirm that the cookies are individually in L2 / NSC... normally
	 * we don't do this but check via L1 so we can get it from there if
	 * present.  But as a unit test, we want to make sure it's in L2 / NSC
	 */

	lwsl_user("%s: check cookies written thru to NSC\n", __func__);

	if (lws_cache_item_get(nsc, tag_cookie1, (const void **)&po, &size) ||
	    size != strlen(cookie1) || memcmp(po, cookie1, size)) {
		lwsl_err("%s: NSC '%s' missing, size %llu, po %s\n", __func__,
			 tag_cookie1, (unsigned long long)size, po);
		goto cdone;
	}

	if (lws_cache_item_get(nsc, tag_cookie2, (const void **)&po, &size) ||
	    size != strlen(cookie2) || memcmp(po, cookie2, size)) {
		lwsl_err("%s: NSC '%s' missing\n", __func__, tag_cookie2);
		goto cdone;
	}

	if (lws_cache_item_get(nsc, tag_cookie3, (const void **)&po, &size) ||
	    size != strlen(cookie3) || memcmp(po, cookie3, size)) {
		lwsl_err("%s: NSC '%s' missing\n", __func__, tag_cookie3);
		goto cdone;
	}

	/* let's do a lookup with no results */

	lwsl_user("%s: nonexistant get must not pass\n", __func__);

	if (!lws_cache_item_get(l1, "x.com|y|z", (const void **)&po, &size)) {
		lwsl_err("%s: nonexistant found size %llu, po %s\n", __func__,
			 (unsigned long long)size, po);
		goto cdone;
	}

	/*
	 * let's try some url paths and check we get the right results set...
	 * for / and any cookie, we expect only c1 and c3 to be listed
	 */

	lwsl_user("%s: wildcard lookup 1\n", __func__);

	n = lws_cache_lookup(l1, "host.com|/|*",
			     (const void **)&cr.ptr, &cr.size);
	if (n) {
		lwsl_err("%s: lookup failed %d\n", __func__, n);
		goto cdone;
	}
	lwsl_hexdump_notice(cr.ptr, size);

	if (cr.size != 53)
		goto cdone;

	while (!lws_cache_results_walk(&cr))
		lwsl_notice("  %s (%d)\n", (const char *)cr.tag,
					   (int)cr.payload_len);

	/*
	 * for /xxx and any cookie, we expect all 3 listed
	 */

	lwsl_user("%s: wildcard lookup 2\n", __func__);

	n = lws_cache_lookup(l1, "host.com|/xxx|*",
			     (const void **)&cr.ptr, &cr.size);
	if (n) {
		lwsl_err("%s: lookup failed %d\n", __func__, n);
		goto cdone;
	}

	if (cr.size != 84)
		goto cdone;

	while (!lws_cache_results_walk(&cr))
		lwsl_notice("  %s (%d)\n", (const char *)cr.tag,
					   (int)cr.payload_len);

	/*
	 * for /yyyy and any cookie, we expect only c1 and c3
	 */

	lwsl_user("%s: wildcard lookup 3\n", __func__);

	n = lws_cache_lookup(l1, "host.com|/yyyy|*",
			     (const void **)&cr.ptr, &cr.size);
	if (n) {
		lwsl_err("%s: lookup failed %d\n", __func__, n);
		goto cdone;
	}

	if (cr.size != 53)
		goto cdone;

	while (!lws_cache_results_walk(&cr))
		lwsl_notice("  %s (%d)\n", (const char *)cr.tag,
					   (int)cr.payload_len);

	/*
	 * repeat the above test, results should come from cache
	 */

	lwsl_user("%s: wildcard lookup 4\n", __func__);

	n = lws_cache_lookup(l1, "host.com|/yyyy|*",
			     (const void **)&cr.ptr, &cr.size);
	if (n) {
		lwsl_err("%s: lookup failed %d\n", __func__, n);
		goto cdone;
	}

	if (cr.size != 53)
		goto cdone;

	while (!lws_cache_results_walk(&cr))
		lwsl_notice("  %s (%d)\n", (const char *)cr.tag,
					   (int)cr.payload_len);

	/* now let's try deleting cookie 1 */

	if (lws_cache_item_remove(l1, tag_cookie1))
		goto cdone;

	lws_cache_debug_dump(nsc);
	lws_cache_debug_dump(l1);

	/* with c1 gone, we should only get c3 */

	lwsl_user("%s: wildcard lookup 5\n", __func__);

	n = lws_cache_lookup(l1, "host.com|/|*",
			     (const void **)&cr.ptr, &cr.size);
	if (n) {
		lwsl_err("%s: lookup failed %d\n", __func__, n);
		goto cdone;
	}

	if (cr.size != 25)
		goto cdone;

	while (!lws_cache_results_walk(&cr))
		lwsl_notice("  %s (%d)\n", (const char *)cr.tag,
					   (int)cr.payload_len);

	/*
	 * let's add a fourth cookie (third in cache now we deleted one)
	 */

	if (lws_cache_write_through(l1, tag_cookie4,
				    (const uint8_t *)cookie4, strlen(cookie4),
				    lws_now_usecs() + LWS_US_PER_SEC * 2, NULL)) {
		lwsl_err("%s: write4 failed\n", __func__);
		goto cdone;
	}

	/*
	 * for /yy and any cookie, we expect only c3
	 */

	lwsl_user("%s: wildcard lookup 6\n", __func__);

	n = lws_cache_lookup(l1, "host.com|/yy|*",
			     (const void **)&cr.ptr, &cr.size);
	if (n) {
		lwsl_err("%s: lookup failed %d\n", __func__, n);
		goto cdone;
	}

	if (cr.size != 25)
		goto cdone;

	while (!lws_cache_results_walk(&cr))
		lwsl_notice("  %s (%d)\n", (const char *)cr.tag,
					   (int)cr.payload_len);

	/*
	 * for /yyy and any cookie, we expect  c3 and c4
	 */

	lwsl_user("%s: wildcard lookup 7\n", __func__);

	n = lws_cache_lookup(l1, "host.com|/yyy|*",
			     (const void **)&cr.ptr, &cr.size);
	if (n) {
		lwsl_err("%s: lookup failed %d\n", __func__, n);
		goto cdone;
	}

	if (cr.size != 57)
		goto cdone;

	while (!lws_cache_results_walk(&cr))
		lwsl_notice("  %s (%d)\n", (const char *)cr.tag,
					   (int)cr.payload_len);

	/* that's ok then */

	lwsl_user("%s: done\n", __func__);

	ret = 0;

cdone:
	/* L1 first, it refers to its parent */
	lws_cache_destroy(&l1);
	lws_cache_destroy(&nsc);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

/*
 * Create an nscookiejar level on a fresh jar file, with a heap L1 on top
 */

static int
nsc_pair_create(const char *filepath, int fresh, size_t jar_max_lines,
		struct lws_cache_ttl_lru **pnsc, struct lws_cache_ttl_lru **pl1)
{
	struct lws_cache_creation_info ci;

	memset(&ci, 0, sizeof(ci));
	ci.cx = cx;
	ci.ops = &lws_cache_ops_nscookiejar;
	ci.name = "NSC";
	ci.u.nscookiejar.filepath = filepath;
	ci.max_items = jar_max_lines; /* 0 = the jar's default */

	*pnsc = lws_cache_create(&ci);
	if (!*pnsc)
		return 1;

	if (fresh)
		/* start from an empty jar, whatever an earlier run left */
		lws_cache_expunge(*pnsc);

	ci.ops = &lws_cache_ops_heap;
	ci.name = "L1";
	ci.parent = *pnsc;
	ci.max_items = 0;

	*pl1 = lws_cache_create(&ci);
	if (!*pl1) {
		lws_cache_destroy(pnsc);
		return 1;
	}

	return 0;
}

static void
nsc_pair_destroy(struct lws_cache_ttl_lru **pnsc,
		 struct lws_cache_ttl_lru **pl1)
{
	if (*pl1)
		lws_cache_expunge(*pl1); /* also deletes the jar file */
	lws_cache_destroy(pl1);
	lws_cache_destroy(pnsc);
}

/*
 * The usual cookie flow: a cookie is stored, then a later request looks up
 * the cookies for its path and gets each result.  The get moves the cookie
 * item in front of the cached lookup result that names it, and destroying
 * the L1 cache must cope with that ordering.
 */

static int
test_nsc_lookup_get_destroy(void)
{
	struct lws_cache_ttl_lru *l1 = NULL, *nsc = NULL;
	lws_cache_results_t cr;
	int ret = 1, found = 0;
	size_t size;
	char *po;

	lwsl_user("%s\n", __func__);
	tests++;

	if (nsc_pair_create("./cookies-lgd.txt", 1, 0, &nsc, &l1))
		goto cdone;

	if (lws_cache_write_through(l1, tag_cookie1,
				    (const uint8_t *)cookie1, strlen(cookie1),
				    lws_now_usecs() + LWS_US_PER_SEC * 10, NULL))
		goto cdone;

	if (lws_cache_lookup(l1, "host.com|/|*", (const void **)&cr.ptr,
			     &cr.size))
		goto cdone;

	while (!lws_cache_results_walk(&cr)) {
		if (lws_cache_item_get(l1, (const char *)cr.tag,
				       (const void **)&po, &size) ||
		    size != strlen(cookie1) || memcmp(po, cookie1, size))
			goto cdone;
		found++;
	}

	if (found != 1)
		goto cdone;

	/*
	 * A new cookie the cached lookup result would list must not leave the
	 * stale result set there: the next lookup lists both
	 */

	if (lws_cache_write_through(l1, tag_cookie3,
				    (const uint8_t *)cookie3, strlen(cookie3),
				    lws_now_usecs() + LWS_US_PER_SEC * 10, NULL))
		goto cdone;

	if (lws_cache_lookup(l1, "host.com|/|*", (const void **)&cr.ptr,
			     &cr.size) || cr.size != 53) {
		lwsl_err("%s: stale lookup result\n", __func__);
		goto cdone;
	}

	ret = 0;

cdone:
	nsc_pair_destroy(&nsc, &l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

/*
 * Removes and writes name one specific item, so the jar must match their key
 * literally: a '*' in a key is just a character there, and only lookups take
 * wildcards.  The jar also refuses to store a line whose tag fields carry a
 * wildcard character, since that could not be told apart from a pattern.
 */

static int
test_nsc_literal_keys(void)
{
	static const char *star_line =
		"host.com\tFALSE\t/\tTRUE\t4000000000\t*\tstarvalue";
	struct lws_cache_ttl_lru *l1 = NULL, *nsc = NULL;
	lws_cache_results_t cr;
	int ret = 1;
	size_t size;
	char *po;

	lwsl_user("%s\n", __func__);
	tests++;

	if (nsc_pair_create("./cookies-lit.txt", 1, 0, &nsc, &l1))
		goto cdone;

	if (lws_cache_write_through(l1, tag_cookie1,
				    (const uint8_t *)cookie1, strlen(cookie1),
				    lws_now_usecs() + LWS_US_PER_SEC * 10, NULL) ||
	    lws_cache_write_through(l1, tag_cookie3,
				    (const uint8_t *)cookie3, strlen(cookie3),
				    lws_now_usecs() + LWS_US_PER_SEC * 10, NULL))
		goto cdone;

	/* there is no item with this literal key, nothing may go */

	if (lws_cache_item_remove(l1, "host.com|/|*"))
		goto cdone;

	/* the jar must refuse this one */

	if (!lws_cache_write_through(l1, "host.com|/|*",
				     (const uint8_t *)star_line,
				     strlen(star_line),
				     lws_now_usecs() + LWS_US_PER_SEC * 10,
				     NULL)) {
		lwsl_err("%s: jar accepted a wildcard name\n", __func__);
		goto cdone;
	}

	/* both cookies must still be in the jar itself */

	if (lws_cache_item_get(nsc, tag_cookie1, (const void **)&po, &size) ||
	    size != strlen(cookie1) || memcmp(po, cookie1, size) ||
	    lws_cache_item_get(nsc, tag_cookie3, (const void **)&po, &size) ||
	    size != strlen(cookie3) || memcmp(po, cookie3, size)) {
		lwsl_err("%s: jar lost a cookie\n", __func__);
		goto cdone;
	}

	/* ...and a lookup, which does take wildcards, lists just those two */

	if (lws_cache_lookup(l1, "host.com|/|*", (const void **)&cr.ptr,
			     &cr.size) || cr.size != 53)
		goto cdone;

	ret = 0;

cdone:
	nsc_pair_destroy(&nsc, &l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

/*
 * A jar written by something else may have empty lines (curl leaves one after
 * its header comments) and comment lines of any length.  Neither may end the
 * walk of the file early: the jar is regenerated from what the walk sees, as
 * it is when the cache is created, so anything after would be lost.  The
 * last line also has no trailing '\n' here.
 */

static const char *jar_foreign_head =
	"# Netscape HTTP Cookie File\n"
	"# written by some other cookie consumer\n"
	"\n";

static const char *jar_foreign_cookies[] = {
	"host.com\tFALSE\t/\tTRUE\t4000000000\tmycookie\tmycookievalue",
	"host.com\tFALSE\t/\tTRUE\t4000000000\textra\tcookie3value",
	NULL, /* a long comment line goes here */
	"host.com\tFALSE\t/xxx\tTRUE\t4000000000\tmycookie\tmyxxxcookievalue",
	"host.com\tFALSE\t/yyy\tTRUE\t4000000000\tnewcookie\tnewcookievalue",
	"host.com\tFALSE\t/zzz\tTRUE\t4000000000\tfifth\tfifthcookievalue",
};

static const char *jar_foreign_tags[] = {
	"host.com|/|mycookie",
	"host.com|/|extra",
	NULL,
	"host.com|/xxx|mycookie",
	"host.com|/yyy|newcookie",
	"host.com|/zzz|fifth",
};

static int
test_nsc_foreign_jar(void)
{
	struct lws_cache_ttl_lru *l1 = NULL, *nsc = NULL;
	char jar[1024], *p = jar, *end = jar + sizeof(jar);
	int ret = 1;
	size_t n, size;
	char *po;

	lwsl_user("%s\n", __func__);
	tests++;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s",
			  jar_foreign_head);
	for (n = 0; n < LWS_ARRAY_SIZE(jar_foreign_cookies); n++) {
		if (p != jar + strlen(jar_foreign_head))
			*p++ = '\n';
		if (jar_foreign_cookies[n]) {
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s",
					  jar_foreign_cookies[n]);
			continue;
		}

		/* a comment line longer than the jar's line buffer */
		*p++ = '#';
		memset(p, 'c', 300);
		p += 300;
	}

	if (lws_plat_write_file("./cookies-foreign.txt", jar,
				lws_ptr_diff_size_t(p, jar)))
		goto cdone;

	/* creating the jar level regenerates the file from the walk */

	if (nsc_pair_create("./cookies-foreign.txt", 0, 0, &nsc, &l1))
		goto cdone;

	for (n = 0; n < LWS_ARRAY_SIZE(jar_foreign_tags); n++) {
		if (!jar_foreign_tags[n])
			continue;
		if (lws_cache_item_get(nsc, jar_foreign_tags[n],
				       (const void **)&po, &size) ||
		    size != strlen(jar_foreign_cookies[n]) ||
		    memcmp(po, jar_foreign_cookies[n], size)) {
			lwsl_err("%s: lost %s\n", __func__,
				 jar_foreign_tags[n]);
			goto cdone;
		}
	}

	ret = 0;

cdone:
	nsc_pair_destroy(&nsc, &l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

/*
 * Cookie paths (and names, and domains) can be longer than 63 chars: such a
 * cookie must be stored, found again by its key and removable
 */

static int
test_nsc_long_fields(void)
{
	struct lws_cache_ttl_lru *l1 = NULL, *nsc = NULL;
	char line[1024], key[256], path[128], value[700];
	int ret = 1;
	size_t size;
	char *po;

	lwsl_user("%s\n", __func__);
	tests++;

	memset(path, 'p', 100);
	path[0] = '/';
	path[100] = '\0';

	lws_snprintf(line, sizeof(line), "host.com\tFALSE\t%s\tTRUE\t"
		     "4000000000\tlongpathcookie\tlongpathvalue", path);
	lws_snprintf(key, sizeof(key), "host.com|%s|longpathcookie", path);

	if (nsc_pair_create("./cookies-long.txt", 1, 0, &nsc, &l1))
		goto cdone;

	if (lws_cache_write_through(l1, key, (const uint8_t *)line,
				    strlen(line),
				    lws_now_usecs() + LWS_US_PER_SEC * 10, NULL))
		goto cdone;

	if (lws_cache_item_get(nsc, key, (const void **)&po, &size) ||
	    size != strlen(line) || memcmp(po, line, size)) {
		lwsl_err("%s: long path cookie not in jar\n", __func__);
		goto cdone;
	}

	if (lws_cache_item_remove(l1, key))
		goto cdone;

	if (!lws_cache_item_get(nsc, key, (const void **)&po, &size)) {
		lwsl_err("%s: long path cookie not removed\n", __func__);
		goto cdone;
	}

	/*
	 * A jar line longer than the jar's line buffer (here, from a long
	 * value) is read back in several pieces, and must come back whole
	 */

	memset(value, 'v', sizeof(value) - 1);
	value[sizeof(value) - 1] = '\0';
	lws_snprintf(line, sizeof(line), "host.com\tFALSE\t/\tTRUE\t"
		     "4000000000\tlongvalue\t%s", value);

	if (lws_cache_write_through(l1, "host.com|/|longvalue",
				    (const uint8_t *)line, strlen(line),
				    lws_now_usecs() + LWS_US_PER_SEC * 10, NULL))
		goto cdone;

	if (lws_cache_item_get(nsc, "host.com|/|longvalue", (const void **)&po,
			       &size) ||
	    size != strlen(line) || memcmp(po, line, size)) {
		lwsl_err("%s: long value cookie not read back whole\n",
			 __func__);
		goto cdone;
	}

	ret = 0;

cdone:
	nsc_pair_destroy(&nsc, &l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

/*
 * The jar's lock and temp files are its path plus a suffix: a jar path too
 * long for those to be composed whole must be refused, rather than work on
 * truncated paths that may name some other file
 */

static int
test_nsc_path_too_long(void)
{
	struct lws_cache_creation_info ci;
	struct lws_cache_ttl_lru *nsc;
	char path[320];

	lwsl_user("%s\n", __func__);
	tests++;

	memset(path, 'j', sizeof(path) - 1);
	path[0] = '.';
	path[1] = '/';
	path[sizeof(path) - 1] = '\0';

	memset(&ci, 0, sizeof(ci));
	ci.cx = cx;
	ci.ops = &lws_cache_ops_nscookiejar;
	ci.name = "NSC";
	ci.u.nscookiejar.filepath = path;

	nsc = lws_cache_create(&ci);
	if (nsc) {
		lwsl_err("%s: accepted an overlong jar path\n", __func__);
		lws_cache_destroy(&nsc);
		return 1;
	}

	return 0;
}

/*
 * Lookup result sets are cached in L1 by their wildcard key.  Two lookups
 * whose keys only differ after the first 125 chars are different lookups,
 * and must not be answered with the same result set.
 */

static int
test_nsc_long_lookup_keys(void)
{
	struct lws_cache_ttl_lru *l1 = NULL, *nsc = NULL;
	char stem[160], line[320], key[256], wc[256];
	lws_cache_results_t cr;
	int ret = 1, n;

	lwsl_user("%s\n", __func__);
	tests++;

	/* "/aaa...aaa", 131 chars */
	memset(stem, 'a', 131);
	stem[0] = '/';
	stem[131] = '\0';

	lws_snprintf(line, sizeof(line), "host.com\tFALSE\t%s/x\tTRUE\t"
		     "4000000000\tlk\tvalue", stem);
	lws_snprintf(key, sizeof(key), "host.com|%s/x|lk", stem);

	if (nsc_pair_create("./cookies-lk.txt", 1, 0, &nsc, &l1) ||
	    lws_cache_write_through(l1, key, (const uint8_t *)line,
				    strlen(line),
				    lws_now_usecs() + LWS_US_PER_SEC * 10, NULL))
		goto cdone;

	/* the cookie's own path finds it */

	lws_snprintf(wc, sizeof(wc), "host.com|%s/x|*", stem);
	if (lws_cache_lookup(l1, wc, (const void **)&cr.ptr, &cr.size) ||
	    cr.size != 8 + strlen(key) + 1) {
		lwsl_err("%s: lookup /x\n", __func__);
		goto cdone;
	}

	/* a sibling path with the same first 125 chars does not */

	lws_snprintf(wc, sizeof(wc), "host.com|%s/y|*", stem);
	n = lws_cache_lookup(l1, wc, (const void **)&cr.ptr, &cr.size);
	if (!n && cr.size) {
		lwsl_err("%s: lookup /y got /x's results\n", __func__);
		goto cdone;
	}

	ret = 0;

cdone:
	nsc_pair_destroy(&nsc, &l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}

/*
 * The jar is rewritten and scanned synchronously on the event loop, so it is
 * bounded: a host keeps at most 50 cookies and the jar at most its max_items
 * lines, the oldest going first.  And the event loop never waits for the jar
 * lock: if another process holds it, the operation just fails.
 */

static int
nsc_jar_write(struct lws_cache_ttl_lru *l1, const char *host, const char *name)
{
	char line[128], key[96];

	lws_snprintf(line, sizeof(line), "%s\tFALSE\t/\tTRUE\t4000000000\t"
		     "%s\tvalue", host, name);
	lws_snprintf(key, sizeof(key), "%s|/|%s", host, name);

	return lws_cache_write_through(l1, key, (const uint8_t *)line,
				       strlen(line),
				       lws_now_usecs() + LWS_US_PER_SEC * 10,
				       NULL);
}

static int
nsc_jar_has(struct lws_cache_ttl_lru *nsc, const char *host, const char *name)
{
	char key[96];
	size_t size;
	char *po;

	lws_snprintf(key, sizeof(key), "%s|/|%s", host, name);

	return !lws_cache_item_get(nsc, key, (const void **)&po, &size);
}

static int
test_nsc_limits(void)
{
	struct lws_cache_ttl_lru *l1 = NULL, *nsc = NULL;
	char name[16], host[16];
	lws_usec_t t;
	int ret = 1, n;

	lwsl_user("%s\n", __func__);
	tests++;

	/* a host with more than 50 cookies loses its oldest ones */

	if (nsc_pair_create("./cookies-cap.txt", 1, 0, &nsc, &l1) ||
	    nsc_jar_write(l1, "other.com", "o"))
		goto cdone;

	for (n = 0; n < 60; n++) {
		lws_snprintf(name, sizeof(name), "c%d", n);
		if (nsc_jar_write(l1, "host.com", name))
			goto cdone;
	}

	if (!nsc_jar_has(nsc, "other.com", "o") ||
	    !nsc_jar_has(nsc, "host.com", "c59") ||
	    !nsc_jar_has(nsc, "host.com", "c10") ||
	    nsc_jar_has(nsc, "host.com", "c9")) {
		lwsl_err("%s: per-host limit\n", __func__);
		goto cdone;
	}

	nsc_pair_destroy(&nsc, &l1);

	/* the jar as a whole keeps its newest max_items lines */

	if (nsc_pair_create("./cookies-cap.txt", 1, 5, &nsc, &l1))
		goto cdone;

	for (n = 0; n < 8; n++) {
		lws_snprintf(host, sizeof(host), "h%d.com", n);
		if (nsc_jar_write(l1, host, "c"))
			goto cdone;
	}

	if (!nsc_jar_has(nsc, "h7.com", "c") ||
	    !nsc_jar_has(nsc, "h3.com", "c") ||
	    nsc_jar_has(nsc, "h2.com", "c")) {
		lwsl_err("%s: jar limit\n", __func__);
		goto cdone;
	}

	nsc_pair_destroy(&nsc, &l1);

	/* somebody else holds the jar lock: fail, don't wait */

	if (lws_plat_write_file("./cookies-busy.txt.LCK", "x", 1) ||
	    nsc_pair_create("./cookies-busy.txt", 0, 0, &nsc, &l1))
		goto cdone;

	t = lws_now_usecs();
	n = nsc_jar_write(l1, "host.com", "busy");
	t = lws_now_usecs() - t;

	if (remove("./cookies-busy.txt.LCK")) {
		lwsl_err("%s: unable to remove our lock file\n", __func__);
		goto cdone;
	}

	if (!n || t > LWS_US_PER_SEC) {
		lwsl_err("%s: busy jar: %d, %dms\n", __func__, n,
			 (int)(t / LWS_US_PER_MS));
		goto cdone;
	}

	if (nsc_jar_write(l1, "host.com", "notbusy") ||
	    !nsc_jar_has(nsc, "host.com", "notbusy"))
		goto cdone;

	ret = 0;

cdone:
	nsc_pair_destroy(&nsc, &l1);

	if (ret)
		lwsl_warn("%s: fail\n", __func__);

	return ret;
}
#endif


int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

	lws_context_info_defaults(&info, NULL);lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = LWS_FD_LIMIT_PER_THREAD_MIN + 6;
	info.port = CONTEXT_PORT_NO_LISTEN;

	lwsl_user("LWS API selftest: lws_cache\n");

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (test_just_l1())
		fail++;
	if (test_just_l1_limits())
		fail++;

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR)
	if (test_nsc1())
		fail++;
	if (test_nsc_lookup_get_destroy())
		fail++;
	if (test_nsc_literal_keys())
		fail++;
	if (test_nsc_foreign_jar())
		fail++;
	if (test_nsc_long_fields())
		fail++;
	if (test_nsc_limits())
		fail++;
	if (test_nsc_long_lookup_keys())
		fail++;
	if (test_nsc_path_too_long())
		fail++;
#endif

	/* last, since it leaves the service thread on external time */
	if (test_l1_external_time())
		fail++;

	/*
	 * Schedule an app-owned sul far enough in the future it can't fire,
	 * and leave it scheduled over the context destroy... the destroy must
	 * detach it from the pt sul list, so the lws_sul_cancel() below is a
	 * NOP rather than a write into the freed context
	 */

	tests++;
	lws_sul_schedule(cx, 0, &sul_outlives_cx, sul_outlives_cx_cb,
			 3600 * LWS_US_PER_SEC);

	lws_context_destroy(cx);

	lws_sul_cancel(&sul_outlives_cx);

	if (sul_outlives_cx_fired ||
	    !lws_dll2_is_detached(&sul_outlives_cx.list)) {
		lwsl_err("%s: app sul not detached by context destroy\n",
			 __func__);
		fail++;
	}

	if (tests && !fail)
		lwsl_user("Completed: PASS\n");
	else
		lwsl_err("Completed: FAIL %d / %d\n", fail, tests);

	return !tests || fail;
}
