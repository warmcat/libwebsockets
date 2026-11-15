/*
 * lws-api-test-tz
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the civil time conversions, and the POSIX TZ strings lws_tz_at()
 * understands, against what glibc said about each of tzdata's, see
 * gen-vectors.py.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

static int fails;

#define expect(cond, ...) do { if (!(cond)) { lwsl_err(__VA_ARGS__); \
				fails++; } } while (0)

/* the struct has padding, so compare the members */

static int
civil_eq(const lws_civil_t *a, const lws_civil_t *b)
{
	return a->year == b->year && a->mon == b->mon && a->day == b->day &&
	       a->hour == b->hour && a->min == b->min && a->sec == b->sec &&
	       a->wday == b->wday;
}

/*
 * Known times, as civil and unix: the epoch, a leap day, the turn of the
 * century that isn't a leap year, a 4-century one that is, and the last
 * second we can convert
 */

static const struct {
	lws_civil_t		c;
	int64_t			secs;
} known[] = {
	{ { 1970,  1,  1,  0,  0,  0, 4 }, 0 },
	{ { 2000,  2, 29, 12, 34, 56, 2 }, 951827696 },
	{ { 2000,  3,  1,  0,  0,  0, 3 }, 951868800 },
	{ { 2026, 11, 15,  6, 56, 18, 0 }, 1794725778 },
	{ { 2099, 12, 31, 23, 59, 59, 4 }, 4102444799 },
	{ { 2100,  3,  1,  0,  0,  0, 1 }, 4107542400 },
	{ { 9999, 12, 31, 23, 59, 59, 5 }, 253402300799 },
};

static void
test_civil(void)
{
	static const lws_civil_t bad[] = {
		{ 1969, 12, 31, 23, 59, 59, 0 },
		{ 2026,  2, 29,  0,  0,  0, 0 },	/* not a leap year */
		{ 2100,  2, 29,  0,  0,  0, 0 },	/* nor is this */
		{ 2026, 13,  1,  0,  0,  0, 0 },
		{ 2026,  0,  1,  0,  0,  0, 0 },
		{ 2026,  4, 31,  0,  0,  0, 0 },
		{ 2026,  4, 30, 24,  0,  0, 0 },
		{ 2026,  4, 30, 23, 60,  0, 0 },
		{ 2026,  4, 30, 23, 59, 60, 0 },
		{ 10000, 1,  1,  0,  0,  0, 0 },
	};
	lws_civil_t c;
	int64_t s, day;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(known); n++) {
		expect(!lws_civil_to_unix(&known[n].c, &s) &&
		       s == known[n].secs, "%s: known %d to unix: %lld\n",
		       __func__, (int)n, (long long)s);
		expect(!lws_unix_to_civil(known[n].secs, &c) &&
		       civil_eq(&c, &known[n].c),
		       "%s: known %d to civil\n", __func__, (int)n);
	}

	for (n = 0; n < LWS_ARRAY_SIZE(bad); n++)
		expect(lws_civil_to_unix(&bad[n], &s),
		       "%s: bad %d accepted\n", __func__, (int)n);

	expect(lws_unix_to_civil(-1, &c), "%s: negative\n", __func__);
	expect(lws_unix_to_civil(253402300800ll, &c),
	       "%s: year 10000\n", __func__);

	/* the last second of every day from 1970 to 2200, there and back */

	for (day = 0; day < 84000; day++) {
		s = day * 86400 + 86399;
		if (lws_unix_to_civil(s, &c) ||
		    lws_civil_to_unix(&c, &s) || s != day * 86400 + 86399 ||
		    c.wday != (day + 4) % 7) {
			expect(0, "%s: day %lld\n", __func__, (long long)day);
			break;
		}
	}
}

static const struct {
	const char		*tz;
	int64_t			utc;
	int32_t			offset;
	const char		*abbr;
	uint8_t			dst;
} vectors[] = {
#include "tz-vectors.h"
};

static void
test_tz(void)
{
	static const char * const bad[] = {
		"", "UTC", "EST", "AB5", "<AB>5", "<+03", "<+0 3>-3", "EST5EDT,",
		"EST5EDT,M3.2.0", "EST5EDT,M13.2.0,M11.1.0",
		"EST5EDT,M3.6.0,M11.1.0", "EST5EDT,M3.2.7,M11.1.0",
		"EST5EDT,J0,J300", "EST5EDT,366,300", "EST5EDT,M3.2.0/168,J1",
		"EST25", "EST5:60", "EST5EDT,M3.2.0,M11.1.0x",
		"ESTESTESTESTEST5", "<ESTESTESTESTEST>5",
	};
	lws_tz_info_t i;
	lws_civil_t c;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(vectors); n++) {
		if (lws_tz_at(vectors[n].tz, vectors[n].utc, &i)) {
			expect(0, "%s: %s refused\n", __func__, vectors[n].tz);
			continue;
		}
		expect(i.utc_offset == vectors[n].offset &&
		       i.dst == vectors[n].dst &&
		       !strcmp(i.abbr, vectors[n].abbr),
		       "%s: %s at %lld: %d %s %d, expected %d %s %d\n",
		       __func__, vectors[n].tz, (long long)vectors[n].utc,
		       (int)i.utc_offset, i.abbr, i.dst,
		       (int)vectors[n].offset, vectors[n].abbr,
		       vectors[n].dst);
	}

	for (n = 0; n < LWS_ARRAY_SIZE(bad); n++)
		expect(lws_tz_at(bad[n], known[3].secs, &i),
		       "%s: bad %s accepted\n", __func__, bad[n]);

	expect(lws_tz_at(NULL, known[3].secs, &i), "%s: NULL\n", __func__);

	/* the local time, in Tokyo and New York */

	expect(!lws_tz_local("JST-9", known[3].secs, &c, &i) &&
	       c.year == 2026 && c.mon == 11 && c.day == 15 && c.hour == 15 &&
	       c.min == 56 && !strcmp(i.abbr, "JST"), "%s: JST\n", __func__);
	expect(!lws_tz_local("EST5EDT,M3.2.0,M11.1.0", known[3].secs, &c,
			     NULL) && c.day == 15 && c.hour == 1,
	       "%s: EST\n", __func__);

	/* a zone west of UTC has no local time at the epoch */

	expect(lws_tz_local("EST5", 0, &c, NULL), "%s: before 1970\n",
	       __func__);
}

int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: tz\n");

	test_civil();
	test_tz();

	if (fails) {
		lwsl_err("%s: %d tz tests failed\n", __func__, fails);

		return 1;
	}

	lwsl_user("Passed all %d tz tests\n", (int)LWS_ARRAY_SIZE(vectors));

	return 0;
}
