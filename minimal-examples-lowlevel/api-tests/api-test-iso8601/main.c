/*
 * lws-api-test-iso8601
 *
 * Strict lws_tokenize-based ISO8601 / RFC3339 date parsing coverage
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

struct tests {
	const char *s;
	lws_usec_t expected; /* unixtime seconds, 0 means must fail */
};

static const struct tests tests[] = {

	/* accepted forms */

	{ "2020-01-01T00:00:00Z",			1577836800 },
	{ "2020-01-01",				1577836800 }, /* date-only */
	{ "2020-01-01 12:34:56",			1577882096 }, /* space sep */
	{ "1999-12-31T23:59:59Z",			946684799 },
	{ "2020-02-29T12:00:00.500Z",		1582977600 }, /* leap day */
	{ "2020-01-01T12:34:56.123456789Z",		1577882096 }, /* fraction */
	/* zone indicators are validated but the time is taken as UTC */
	{ "2020-06-15T10:30:45+02:00",		1592217045 },
	{ "2020-06-15T10:30:45-05:00",		1592217045 },
	{ "2020-06-15T10:30:45+02",			1592217045 },
	{ "2015-07-04t05:06:07z",			1435986367 }, /* lower t,z */
	/* day out of month bounds normalizes as mktime always did */
	{ "2020-02-30",					1583020800 },
	{ "2020-02-29",					1582934400 },

	/* rejected forms */

	{ NULL,						0 },
	{ "",						0 },
	{ "2020-1-01",					0 }, /* not zero-padded */
	{ "20-01-01",					0 }, /* short year */
	{ "2020/01/01",				0 }, /* wrong separators */
	{ " 2020-01-01",				0 }, /* leading whitespace */
	{ "2020-13-01",				0 }, /* month range */
	{ "2020-00-01",				0 },
	{ "2020-01-00",				0 }, /* day range */
	{ "2020-01-32",				0 },
	{ "2020-01-01T24:00:00Z",			0 }, /* hour range */
	{ "2020-01-01T12:60:00Z",			0 }, /* minute range */
	{ "2020-01-01T12:30:60Z",			0 }, /* second range */
	{ "2020-01-01T12:00",				0 }, /* partial time */
	{ "2020-01-01T",				0 }, /* dangling separator */
	{ "2020-01-01X12:00:00",			0 }, /* bad separator */
	{ "2020-01-01T12:00:00garbage",		0 },
	{ "2020-01-01T12:00:00.Z",			0 }, /* empty fraction */
	{ "2020-01-01T12:00:00.5.5Z",		0 }, /* double fraction */
	{ "2020-01-01T12:00:00+0200",		0 }, /* offset needs colon */
	{ "2020-01-01T12:00:00Z5",			0 }, /* junk after zone */
	{ "2020-01-01T12:00:00\200",		0 }, /* broken utf-8 */
};

int main(int argc, const char **argv)
{
	char overlong[384];
	int n, fails = 0;
	lws_usec_t m;

	lwsl_user("LWS API selftest: iso8601\n");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(tests); n++) {

		if (!tests[n].s) {
			m = lws_parse_iso8601(NULL);
		} else
			m = lws_parse_iso8601(tests[n].s);

		if (m != tests[n].expected) {
			lwsl_err("%s: test %d: '%s' -> %llu (expected %llu)\n",
				 __func__, n, tests[n].s ? tests[n].s : "NULL",
				 (unsigned long long)m,
				 (unsigned long long)tests[n].expected);
			fails++;
		}
	}

	/* an overlong fraction must fail cleanly, not trip any limit */

	memcpy(overlong, "2020-01-01T12:00:00.", 20);
	memset(overlong + 20, '7', sizeof(overlong) - 1 - 20);
	overlong[sizeof(overlong) - 1] = '\0';

	m = lws_parse_iso8601(overlong);
	if (m) {
		lwsl_err("%s: overlong fraction accepted (%llu)\n", __func__,
			 (unsigned long long)m);
		fails++;
	}

	if (fails) {
		lwsl_err("Failed %d iso8601 tests\n", fails);
		return 1;
	}

	lwsl_user("Completed: ALL OK, %d tests\n", (int)LWS_ARRAY_SIZE(tests) + 1);

	return 0;
}
