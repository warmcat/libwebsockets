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

/*
 * While test_emit() is installed, anything we log ourselves is fed through
 * the spew tracking under test and recorded as if it was part of it.  So
 * the verdicts are noted here and only logged at the end, once the default
 * emit function is back.
 */

#define NOTE_MAX	24

static char notes[NOTE_MAX][128];
static int note_level[NOTE_MAX];
static unsigned int note_count, notes_dropped;

#define note(_lvl, ...) do { \
		if (note_count < NOTE_MAX) { \
			note_level[note_count] = _lvl; \
			lws_snprintf(notes[note_count], sizeof(notes[0]), \
				     __VA_ARGS__); \
			note_count++; \
		} else \
			notes_dropped++; \
	} while (0)

#define fail(...) note(LLL_ERR, __VA_ARGS__)
#define pass(...) note(LLL_USER, __VA_ARGS__)

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
			fail("%s: saw tl %d, expected %d",
			     hint, rec[n], expect);
			e++;
			expect = rec[n];
		}
		expect++;
	}

	if (expect != last + 1) {
		fail("%s: run ended at %d, expected %d",
		     hint, expect - 1, last);
		e++;
	}

	return e;
}

/*
 * Log a spew of SPEW_LINES distinct lines, timed on the same clock lws uses.
 *
 * lws leaves spew mode when LWS_LOG_SPEW_EXIT_SAMPLES consecutive lines span
 * more than LWS_LOG_SPEW_EXIT_US, and it is right to: that is what the spew
 * easing looks like.  But on a loaded machine, eg, ctest -j, we can simply be
 * descheduled for that long in the middle of the loop, and then lws leaves
 * spew mode part way through.  That run doesn't test what we meant it to, so
 * we watch for it with a wide margin and return nonzero if it happened.
 */

#define STALL_SAMPLES	8	/* LWS_LOG_SPEW_EXIT_SAMPLES */
#define STALL_US	2500	/* half of LWS_LOG_SPEW_EXIT_US */
#define SPEW_ATTEMPTS	10

static int
spew(void)
{
	lws_usec_t ts[STALL_SAMPLES + 1], t;
	int n, stalled = 0;

	memset(ts, 0, sizeof(ts));

	for (n = 0; n < SPEW_LINES; n++) {
		t = lws_now_usecs();
		if (n >= STALL_SAMPLES &&
		    t - ts[(n - STALL_SAMPLES) % (STALL_SAMPLES + 1)] > STALL_US)
			stalled = 1;
		ts[n % (STALL_SAMPLES + 1)] = t;

		lwsl_notice("tl %d\n", n);
	}

	return stalled;
}

static int
check_spew_and_ease(void)
{
	int n, e = 0, ent, eas, endr, fin, direct;
	unsigned int replayed;

	/* only a few lines may have reached the emit function during it */

	direct = 0;
	for (n = 0; n < (int)rec_count; n++)
		if (rec[n] >= 0)
			direct++;

	ent = find(REC_ENTERED);
	if (ent < 0) {
		fail("spew: never entered spew mode");
		e++;
	}
	if (direct > SPEW_LINES / 2) {
		fail("spew: %d of %d lines emitted directly",
		     direct, SPEW_LINES);
		e++;
	}
	if (count(REC_EASED)) {
		fail("spew: left spew mode during the spew");
		e++;
	}
	if (count(REC_OTHER)) {
		fail("spew: unexpected lines emitted");
		e++;
	}
	if (!e)
		pass("spew: %u lines emitted for %d logged",
		     rec_count, SPEW_LINES);

	/*
	 * The rate eases: the next log replays the retained tail, in order and
	 * ending with the last line of the spew, then itself
	 */

	lws_usleep(20000);
	lwsl_notice("final\n");

	eas = find(REC_EASED);
	endr = find(REC_END_REPLAY);
	fin = find(REC_FINAL);

	if (eas < 0 || endr < 0 || fin < 0 || eas > endr || endr > fin) {
		fail("ease: eased %d, end %d, final %d",
		     eas, endr, fin);
		e++;
	} else {
		replayed = 0;
		for (n = eas + 1; n < endr; n++) {
			if (rec[n] < 0) {
				fail("ease: non-test line in replay at %d", n);
				e++;
				break;
			}
			if (n > eas + 1 && rec[n] != rec[n - 1] + 1) {
				fail("ease: replay out of order at %d", n);
				e++;
				break;
			}
			replayed++;
		}
		if (rec[endr - 1] != SPEW_LINES - 1) {
			fail("ease: replay ends at %d, not %d",
			     rec[endr - 1], SPEW_LINES - 1);
			e++;
		}
		if (rec_count != (unsigned int)fin + 1) {
			fail("ease: %u lines after final",
			     rec_count - (unsigned int)fin - 1);
			e++;
		}
		if (!e)
			pass("ease: %u lines replayed", replayed);
	}

	return e;
}

int
main(int argc, const char **argv)
{
	int n, e = 0, attempt;

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
		fail("burst: %u emitted", rec_count);
		e++;
	}

	lws_usleep(20000);
	rec_count = 0;

	/*
	 * 2: a spew of distinct lines: only a few may reach the emit function
	 *    while it is going, and when the rate eases, the next log replays
	 *    the tail of it
	 */

	for (attempt = 1; attempt <= SPEW_ATTEMPTS; attempt++) {
		if (!spew())
			break;

		/* we were descheduled: ease out of spew mode and try again */
		lws_usleep(20000);
		lwsl_notice("final\n");
		rec_count = 0;
	}

	if (attempt > SPEW_ATTEMPTS) {
		fail("spew: descheduled during every one of %d attempts",
		     SPEW_ATTEMPTS);
		e++;
	} else {
		if (attempt > 1)
			pass("spew: undisturbed on attempt %d", attempt);
		e += check_spew_and_ease();
	}

	rec_count = 0;

	/*
	 * 3: a surge that trips spew mode but fits in the retention ring is
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
		fail("surge: final not last");
		e++;
	}
	if (count(REC_OTHER)) {
		fail("surge: unexpected lines emitted");
		e++;
	}
	if (!e)
		pass("surge: %d lines all accounted for, "
		     "%s spew mode", SURGE_LINES,
		     find(REC_ENTERED) >= 0 ? "via" : "without");

	/* NULL would leave test_emit() in place */
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER,
			  lwsl_emit_stderr);

	for (n = 0; n < (int)note_count; n++) {
		if (note_level[n] == LLL_ERR)
			lwsl_err("FAIL: %s\n", notes[n]);
		else
			lwsl_user("%s\n", notes[n]);
	}
	if (notes_dropped)
		lwsl_err("FAIL: ... and %u more\n", notes_dropped);

	if (e) {
		lwsl_err("Completed: FAIL (%d)\n", e);

		return 1;
	}

	lwsl_user("Completed: PASS\n");

	return 0;
}
