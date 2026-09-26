/*
 * lws api test log-spew
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms that a sustained spew of distinct log lines is not passed through
 * to the emit function, that the tail of it is replayed in order when the
 * rate eases, and that a surge smaller than the retention ring is waved
 * through without losing a line.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#if defined(WIN32)
#include <windows.h>
#define lws_usleep(x) Sleep((x) / 1000)
#else
#include <unistd.h>
#define lws_usleep(x) usleep(x)
#endif

#define SPEW_LINES	5000
#define SURGE_LINES	100
#define REC_MAX		SPEW_LINES + SURGE_LINES + 100

/*
 * What the emit function saw, in order.  Test lines are recorded by their
 * sequence number; lws' own spew lines as negative codes.
 */

#define REC_ENTERED	-1
#define REC_HEARTBEAT	-2
#define REC_EASED	-3
#define REC_END_REPLAY	-4
#define REC_FINAL	-5
#define REC_OTHER	-6

static int rec[REC_MAX];
static unsigned int rec_count;

static void
test_emit(int level, const char *line)
{
	const char *q;
	int v = REC_OTHER;

	if (rec_count == REC_MAX)
		return;

	/* the line may carry a timestamp prefix, depending on the build */

	q = strstr(line, "tl ");
	if (q)
		v = atoi(q + 3);
	else if (strstr(line, "final"))
		v = REC_FINAL;
	else if (strstr(line, "log spew eased"))
		v = REC_EASED;
	else if (strstr(line, "end of replay"))
		v = REC_END_REPLAY;
	else if (strstr(line, "still going"))
		v = REC_HEARTBEAT;
	else if (strstr(line, "log spew:"))
		v = REC_ENTERED;

	rec[rec_count++] = v;
}

static unsigned int
count(int v)
{
	unsigned int n, c = 0;

	for (n = 0; n < rec_count; n++)
		if (rec[n] == v)
			c++;

	return c;
}

static int
find(int v)
{
	unsigned int n;

	for (n = 0; n < rec_count; n++)
		if (rec[n] == v)
			return (int)n;

	return -1;
}

/*
 * Every test line in [first, last] must appear exactly once, in order, with
 * only lws' own spew lines interleaved
 */

static int
check_run(int first, int last, const char *hint)
{
	int expect = first, e = 0;
	unsigned int n;

	for (n = 0; n < rec_count; n++) {
		if (rec[n] < first || rec[n] > last)
			continue;
		if (rec[n] != expect) {
			fprintf(stderr, "FAIL: %s: saw tl %d, expected %d\n",
				hint, rec[n], expect);
			e++;
			expect = rec[n];
		}
		expect++;
	}

	if (expect != last + 1) {
		fprintf(stderr, "FAIL: %s: run ended at %d, expected %d\n",
			hint, expect - 1, last);
		e++;
	}

	return e;
}

int
main(int argc, const char **argv)
{
	int n, e = 0, ent, eas, endr, fin, direct;
	unsigned int replayed;

	(void)argc;
	(void)argv;

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER, test_emit);

	/*
	 * 1: a modest burst well under the tracking ring passes straight
	 *    through, whatever its rate
	 */

	for (n = 0; n < 32; n++)
		lwsl_notice("tl %d\n", n);

	if (rec_count != 32 || check_run(0, 31, "burst")) {
		fprintf(stderr, "FAIL: burst: %u emitted\n", rec_count);
		e++;
	}

	lws_usleep(20000);
	rec_count = 0;

	/*
	 * 2: a spew of distinct lines: only a few may reach the emit function
	 *    while it is going
	 */

	for (n = 0; n < SPEW_LINES; n++)
		lwsl_notice("tl %d\n", n);

	direct = 0;
	for (n = 0; n < (int)rec_count; n++)
		if (rec[n] >= 0)
			direct++;

	ent = find(REC_ENTERED);
	if (ent < 0) {
		fprintf(stderr, "FAIL: spew: never entered spew mode\n");
		e++;
	}
	if (direct > SPEW_LINES / 2) {
		fprintf(stderr, "FAIL: spew: %d of %d lines emitted directly\n",
			direct, SPEW_LINES);
		e++;
	}
	if (count(REC_EASED)) {
		fprintf(stderr, "FAIL: spew: left spew mode during the spew\n");
		e++;
	}
	if (count(REC_OTHER)) {
		fprintf(stderr, "FAIL: spew: unexpected lines emitted\n");
		e++;
	}
	if (!e)
		fprintf(stderr, "spew: %u lines emitted for %d logged\n",
			rec_count, SPEW_LINES);

	/*
	 * 3: the rate eases: the next log replays the retained tail, in
	 *    order and ending with the last line of the spew, then itself
	 */

	lws_usleep(20000);
	lwsl_notice("final\n");

	eas = find(REC_EASED);
	endr = find(REC_END_REPLAY);
	fin = find(REC_FINAL);

	if (eas < 0 || endr < 0 || fin < 0 || eas > endr || endr > fin) {
		fprintf(stderr, "FAIL: ease: eased %d, end %d, final %d\n",
			eas, endr, fin);
		e++;
	} else {
		replayed = 0;
		for (n = eas + 1; n < endr; n++) {
			if (rec[n] < 0) {
				fprintf(stderr, "FAIL: ease: non-test line in "
						"replay at %d\n", n);
				e++;
				break;
			}
			if (n > eas + 1 && rec[n] != rec[n - 1] + 1) {
				fprintf(stderr, "FAIL: ease: replay out of "
						"order at %d\n", n);
				e++;
				break;
			}
			replayed++;
		}
		if (rec[endr - 1] != SPEW_LINES - 1) {
			fprintf(stderr, "FAIL: ease: replay ends at %d, not %d\n",
				rec[endr - 1], SPEW_LINES - 1);
			e++;
		}
		if (rec_count != (unsigned int)fin + 1) {
			fprintf(stderr, "FAIL: ease: %u lines after final\n",
				rec_count - (unsigned int)fin - 1);
			e++;
		}
		if (!e)
			fprintf(stderr, "ease: %u lines replayed\n", replayed);
	}

	rec_count = 0;

	/*
	 * 4: a surge that trips spew mode but fits in the retention ring is
	 *    not allowed to lose a line: everything comes out exactly once
	 *    and in order, some of it directly and the rest by replay
	 */

	for (n = 0; n < SURGE_LINES; n++)
		lwsl_notice("tl %d\n", n);

	lws_usleep(20000);
	lwsl_notice("final\n");

	if (check_run(0, SURGE_LINES - 1, "surge"))
		e++;
	if (find(REC_FINAL) != (int)rec_count - 1) {
		fprintf(stderr, "FAIL: surge: final not last\n");
		e++;
	}
	if (count(REC_OTHER)) {
		fprintf(stderr, "FAIL: surge: unexpected lines emitted\n");
		e++;
	}
	if (!e)
		fprintf(stderr, "surge: %d lines all accounted for, "
				"%s spew mode\n", SURGE_LINES,
			find(REC_ENTERED) >= 0 ? "via" : "without");

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER, NULL);

	if (e) {
		lwsl_err("Completed: FAIL (%d)\n", e);

		return 1;
	}

	lwsl_user("Completed: PASS\n");

	return 0;
}
