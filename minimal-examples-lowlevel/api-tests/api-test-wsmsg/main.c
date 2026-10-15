/*
 * lws api test wsmsg
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_wsmsg_append() queues whole messages on an upstream buflist2, holding
 * the fragments of an incomplete one on a private buflist2 per source until
 * its EOM arrives.  We check
 *
 *  - complete messages go straight upstream, in order, totals kept
 *  - a fragmented message is held privately, while other sources' complete
 *    messages carry on going upstream, then goes up whole, in order
 *  - two sources fragmenting at once each come out whole
 *  - the upstream's limit is honoured
 *  - far more segments than the old singly-linked buflist's 8192 sanity
 *    limit can be queued, and come out intact
 *  - lws_wsmsg_destroy() frees what is still held privately
 */

#include <libwebsockets.h>
#include <string.h>

#define SOURCES		3
#define MANY		20000

static struct lws_buflist2_owner upstream, priv[SOURCES];

static int
append(int src, const char *s, unsigned int flags)
{
	lws_wsmsg_info_t info;

	memset(&info, 0, sizeof(info));
	info.upstream		= &upstream;
	info.private_owners	= priv;
	info.private_source_idx	= src;
	info.buf		= (const uint8_t *)s;
	info.len		= strlen(s);
	info.ss_flags		= flags;

	return lws_wsmsg_append(&info);
}

#define WHOLE (LWSSS_FLAG_SOM | LWSSS_FLAG_EOM)

/*
 * Take everything off the upstream, joining the segments into one string with
 * '|' between them, so the order and the segment boundaries can be compared
 */

static int
drain_expect(const char *hint, const char *exp)
{
	char got[512], *p = got;
	size_t n;
	uint8_t *b;

	*p = '\0';
	while ((n = lws_buflist2_next_segment_len(&upstream, &b)) > 0) {
		if (lws_ptr_diff_size_t(got + sizeof(got), p) < n + 2) {
			lwsl_err("%s: %s: too much on upstream\n", __func__, hint);
			return 1;
		}
		if (p != got)
			*p++ = '|';
		memcpy(p, b, n);
		p += n;
		*p = '\0';
		lws_buflist2_use_segment(&upstream, n);
	}

	if (strcmp(got, exp)) {
		lwsl_err("%s: %s: got '%s', expected '%s'\n", __func__, hint,
			 got, exp);
		return 1;
	}

	if (lws_buflist2_total_len(&upstream)) {
		lwsl_err("%s: %s: upstream total %u after draining\n", __func__,
			 hint, (unsigned int)lws_buflist2_total_len(&upstream));
		return 1;
	}

	return 0;
}

static int
test_whole(void)
{
	int e = 0;

	e |= append(0, "one", WHOLE) < 0;
	e |= append(1, "two", WHOLE) < 0;
	e |= append(0, "three", WHOLE) < 0;

	if (lws_buflist2_total_len(&upstream) != 11) {
		lwsl_err("%s: upstream total %u, expected 11\n", __func__,
			 (unsigned int)lws_buflist2_total_len(&upstream));
		e = 1;
	}

	return e | drain_expect(__func__, "one|two|three");
}

static int
test_fragmented(void)
{
	int e = 0;

	e |= append(0, "a1", LWSSS_FLAG_SOM) < 0;
	e |= append(1, "x", WHOLE) < 0;
	e |= append(0, "a2", 0) < 0;
	e |= append(2, "y", WHOLE) < 0;

	/* only the complete ones are upstream so far, a1 a2 are held */
	if (lws_buflist2_total_len(&upstream) != 2 ||
	    lws_buflist2_total_len(&priv[0]) != 4) {
		lwsl_err("%s: upstream %u, priv %u, expected 2 and 4\n",
			 __func__,
			 (unsigned int)lws_buflist2_total_len(&upstream),
			 (unsigned int)lws_buflist2_total_len(&priv[0]));
		e = 1;
	}

	e |= append(0, "a3", LWSSS_FLAG_EOM) < 0;

	if (lws_buflist2_total_len(&priv[0])) {
		lwsl_err("%s: priv still holds %u after EOM\n", __func__,
			 (unsigned int)lws_buflist2_total_len(&priv[0]));
		e = 1;
	}

	return e | drain_expect(__func__, "x|y|a1|a2|a3");
}

static int
test_interleaved(void)
{
	int e = 0;

	e |= append(0, "p1", LWSSS_FLAG_SOM) < 0;
	e |= append(1, "q1", LWSSS_FLAG_SOM) < 0;
	e |= append(0, "p2", 0) < 0;
	e |= append(1, "q2", LWSSS_FLAG_EOM) < 0;
	e |= append(2, "r", WHOLE) < 0;
	e |= append(0, "p3", LWSSS_FLAG_EOM) < 0;

	return e | drain_expect(__func__, "q1|q2|r|p1|p2|p3");
}

static int
test_limit(void)
{
	int e = 0;

	upstream.limit = 8;

	e |= append(0, "12345", WHOLE) < 0;
	if (append(0, "6789", WHOLE) >= 0) {
		lwsl_err("%s: append past the limit was taken\n", __func__);
		e = 1;
	}

	upstream.limit = 0;

	return e | drain_expect(__func__, "12345");
}

static int
test_many(void)
{
	char s[16], c[16];
	lws_usec_t t = lws_now_usecs();
	size_t n;
	uint8_t *b;
	int m;

	for (m = 0; m < MANY; m++) {
		lws_snprintf(s, sizeof(s), "m%d", m);
		if (append(m % SOURCES, s, WHOLE) < 0) {
			lwsl_err("%s: append %d failed\n", __func__, m);
			return 1;
		}
	}

	if (lws_dll2_count(&upstream.owner) != MANY) {
		lwsl_err("%s: %u segments, expected %d\n", __func__,
			 (unsigned int)lws_dll2_count(&upstream.owner), MANY);
		return 1;
	}

	for (m = 0; m < MANY; m++) {
		n = lws_buflist2_next_segment_len(&upstream, &b);
		lws_snprintf(c, sizeof(c), "m%d", m);
		if (n != strlen(c) || memcmp(b, c, n)) {
			lwsl_err("%s: segment %d wrong\n", __func__, m);
			return 1;
		}
		lws_buflist2_use_segment(&upstream, n);
	}

	lwsl_user("%s: %d messages queued and drained in %dms\n", __func__,
		  MANY, (int)((lws_now_usecs() - t) / LWS_US_PER_MS));

	return drain_expect(__func__, "");
}

static int
test_destroy(void)
{
	int e = 0;

	e |= append(0, "held1", LWSSS_FLAG_SOM) < 0;
	e |= append(2, "held2", LWSSS_FLAG_SOM) < 0;

	lws_wsmsg_destroy(priv, LWS_ARRAY_SIZE(priv));

	if (lws_buflist2_total_len(&priv[0]) ||
	    lws_buflist2_total_len(&priv[2]) ||
	    !lws_dll2_is_empty(&priv[0].owner) ||
	    !lws_dll2_is_empty(&priv[2].owner)) {
		lwsl_err("%s: private lists not emptied\n", __func__);
		e = 1;
	}

	return e | drain_expect(__func__, "");
}

int
main(void)
{
	int e = 0;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API selftest: lws_wsmsg\n");

	e |= test_whole();
	e |= test_fragmented();
	e |= test_interleaved();
	e |= test_limit();
	e |= test_many();
	e |= test_destroy();

	lws_buflist2_destroy_all_segments(&upstream);
	lws_wsmsg_destroy(priv, LWS_ARRAY_SIZE(priv));

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return e;
}
