/*
 * lws api test log-spew
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms that a sustained spew of distinct log lines is not passed through
 * to the emit function, that a short tail of it is replayed in order when the
 * rate eases, that a stall in the middle of a spew is recognized for what it
 * was when the spew resumes, and that a surge short enough to end within the
 * retained tail is waved through without losing a line, including when the
 * tail was lengthened at runtime by --log-spew-tail.  Where there are
 * pthreads, it also has several threads spew at once.
 *
 * CI builders are overloaded as a matter of course, so we can be starved of
 * cpu at any point, for any length of time.  lws is expected to cope with that
 * and so is this test: nothing here depends on how long anything took.  We
 * check what lws did against what lws says it saw, and the only timing we
 * rely on is that a sleep lasts at least as long as we asked.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#if defined(LWS_HAVE_PTHREAD_H)
#if defined(WIN32)
/* the ucrt time.h already defined it, don't let pthreads-win32 do it again */
#define HAVE_STRUCT_TIMESPEC
#endif
#include <pthread.h>
#endif

#if defined(WIN32)
#include <windows.h>
#define lws_usleep(x) Sleep((x) / 1000)
#else
#include <unistd.h>
#define lws_usleep(x) usleep(x)
#endif

#define SPEW_LINES	2000
#define REC_MAX		(SPEW_LINES * 2)

#define SPEW_ENTER_LINES	64	/* LWS_LOG_SPEW_TS_RING */
#define SPEW_TAIL		10	/* LWS_LOG_SPEW_TAIL_LINES */
#define SPEW_EXIT_MAX_MS	1000	/* LWS_LOG_SPEW_EXIT_MAX_US */

/* trips spew mode, but ends within the retained tail */
#define SURGE_LINES	(SPEW_ENTER_LINES - 1 + SPEW_TAIL - 3)

/* a tail set at runtime, and a surge that only fits in that one */
#define SPEW_TAIL_RT	200
#define SURGE_RT_LINES	(SPEW_ENTER_LINES - 1 + SPEW_TAIL_RT - 3)

/*
 * What the emit function saw, in order.  Test lines are recorded by their
 * sequence number; lws' own spew lines as negative codes, with the numbers
 * they report.
 */

#define REC_ENTERED	-1	/* a: exit quiet ms */
#define REC_RESUMED	-2	/* a: quiet ms that fooled it, b: exit quiet ms */
#define REC_HEARTBEAT	-3
#define REC_EASED	-4	/* a: quiet ms, b: not retained, c: replayed */
#define REC_END_REPLAY	-5
#define REC_FINAL	-6
#define REC_OTHER	-7

typedef struct {
	int		v;
	int		a;
	int		b;
	int		c;
} rec_t;

static rec_t rec[REC_MAX];
static unsigned int rec_count, rec_overflow;

/* the exit quiet lws most recently told us it is using, and if it spews */
static int exit_ms, in_spew;

/* the most lines lws should be replaying at the moment */
static int tail = SPEW_TAIL;

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

/* the number following the first occurrence of what, or -1 */

static int
num_after(const char *line, const char *what)
{
	const char *q = strstr(line, what);

	return q ? atoi(q + strlen(what)) : -1;
}

#if defined(LWS_HAVE_PTHREAD_H)

#define THREADS		4
#define THREAD_LINES	2000

/*
 * lws calls the emit function without holding its own lock, so while the
 * threads spew, what they emit is tallied under ours instead of recorded
 */

static pthread_mutex_t thr_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t thr_seen[THREADS][THREAD_LINES];
static int thr_emitted, thr_lost, thr_dupes, thr_other;
static char threads_on;

static void
thread_emit(const char *line)
{
	const char *q;
	int t, n;

	if ((q = strstr(line, "lws: log spew eased: "))) {
		q = strstr(q, " over ");
		n = q ? num_after(q, "ms, ") : -1;
		if (n < 0)
			thr_other++;
		else
			thr_lost += n;
		return;
	}
	if (strstr(line, "lws: log spew")) {
		if (strstr(line, "span over "))
			exit_ms = num_after(line, "span over ");
		return;
	}
	if (strstr(line, "final"))
		return;

	q = strstr(line, "tt ");
	if (!q || !(q = strchr(q + 3, ' '))) {
		thr_other++;
		return;
	}
	t = atoi(strstr(line, "tt ") + 3);
	n = atoi(q + 1);
	if (t < 0 || t >= THREADS || n < 0 || n >= THREAD_LINES) {
		thr_other++;
		return;
	}
	if (thr_seen[t][n])
		thr_dupes++;
	else
		thr_emitted++;
	thr_seen[t][n] = 1;
}

#endif

static void
test_emit(int level, const char *line)
{
	const char *q;
	rec_t r = { REC_OTHER, 0, 0, 0 };

	(void)level;

#if defined(LWS_HAVE_PTHREAD_H)
	if (threads_on) {
		pthread_mutex_lock(&thr_lock);
		thread_emit(line);
		pthread_mutex_unlock(&thr_lock);
		return;
	}
#endif

	/* the line may carry a timestamp prefix, depending on the build */

	if (strstr(line, "lws: log spew eased: ")) {
		r.v = REC_EASED;
		r.a = num_after(line, "eased: ");
		q = strstr(line, " over ");
		r.b = q ? num_after(q, "ms, ") : -1;
		r.c = num_after(line, "retained, last ");
		in_spew = 0;
	} else if (strstr(line, "lws: log spew: resumed after ")) {
		r.v = REC_RESUMED;
		r.a = num_after(line, "resumed after ");
		r.b = exit_ms = num_after(line, "span over ");
		in_spew = 1;
	} else if (strstr(line, "lws: log spew: still going"))
		r.v = REC_HEARTBEAT;
	else if (strstr(line, "lws: log spew: end of replay"))
		r.v = REC_END_REPLAY;
	else if (strstr(line, "lws: log spew: ")) {
		r.v = REC_ENTERED;
		r.a = exit_ms = num_after(line, "span over ");
		in_spew = 1;
	} else if ((q = strstr(line, "tl ")))
		r.v = atoi(q + 3);
	else if (strstr(line, "final"))
		r.v = REC_FINAL;

	if (rec_count == REC_MAX) {
		rec_overflow++;
		return;
	}

	rec[rec_count++] = r;
}

static unsigned int
count(int v)
{
	unsigned int n, c = 0;

	for (n = 0; n < rec_count; n++)
		if (rec[n].v == v)
			c++;

	return c;
}

static int
find(int v)
{
	unsigned int n;

	for (n = 0; n < rec_count; n++)
		if (rec[n].v == v)
			return (int)n;

	return -1;
}

/*
 * Sleep for long enough that lws must call a spew over at the next log: the
 * last lines it saw before that will span more than the exit quiet it told us
 * it is using
 */

static void
ease(void)
{
	unsigned int ms = exit_ms > 0 ? (unsigned int)exit_ms : 0;

	lws_usleep((ms + 10) * 1000);
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
		if (rec[n].v < first || rec[n].v > last)
			continue;
		if (rec[n].v != expect) {
			fail("%s: saw tl %d, expected %d",
			     hint, rec[n].v, expect);
			e++;
			expect = rec[n].v;
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
 * What lws did must agree with what it said it saw: it only called the spew
 * over after a quiet longer than the exit quiet it announced, and when it
 * turned out to be wrong, it raised the exit quiet beyond what fooled it.
 *
 * lws may judge the next phase's lines to be the last one's spew resuming, so
 * what we know of its state carries over between the phases' records.
 */

static int thr = -1, last_quiet = -1;

static int
check_decisions(const char *hint)
{
	int e = 0, want;
	unsigned int n, m;

	for (n = 0; n < rec_count; n++) {
		switch (rec[n].v) {
		case REC_ENTERED:
			thr = rec[n].a;
			last_quiet = -1;
			break;

		case REC_EASED:
			if (thr < 0 || rec[n].a < thr) {
				fail("%s: eased after %dms quiet, exit %dms",
				     hint, rec[n].a, thr);
				e++;
			}
			last_quiet = rec[n].a;

			/* it replays what it says it does, only a short tail */

			for (m = n + 1; m < rec_count &&
					rec[m].v != REC_END_REPLAY; m++)
				;
			if (m == rec_count || rec[n].c > tail ||
			    (int)(m - n - 1) != rec[n].c) {
				fail("%s: replayed %u lines, said %d", hint,
				     m - n - 1, rec[n].c);
				e++;
			}
			break;

		case REC_RESUMED:
			want = 2 * last_quiet;
			if (want > SPEW_EXIT_MAX_MS)
				want = SPEW_EXIT_MAX_MS;
			if (want < thr)
				want = thr;
			if (last_quiet < 0 || rec[n].a != last_quiet ||
			    rec[n].b < want) {
				fail("%s: resumed after %dms quiet (eased "
				     "after %d), exit %dms (was %d)", hint,
				     rec[n].a, last_quiet, rec[n].b, thr);
				e++;
			}
			thr = rec[n].b;
			last_quiet = -1;
			break;
		}
	}

	return e;
}

static int
check_spew(int stall_at)
{
	int n, e = 0, last = -1, emitted = 0, lost = 0, r;

	if (rec_overflow) {
		fail("spew: %u lines not recorded", rec_overflow);
		return 1;
	}

	if (find(REC_ENTERED) < 0) {
		fail("spew: never entered spew mode");
		e++;
	}
	if (count(REC_OTHER)) {
		fail("spew: unexpected lines emitted");
		e++;
	}

	/*
	 * Every line of the spew was either emitted once and in order, or lws
	 * owned up to not retaining it; and the spew ended with its last line,
	 * then our final one
	 */

	for (n = 0; n < (int)rec_count; n++) {
		if (rec[n].v == REC_EASED)
			lost += rec[n].b;
		if (rec[n].v < 0)
			continue;
		if (rec[n].v <= last) {
			fail("spew: tl %d after tl %d", rec[n].v, last);
			e++;
		}
		last = rec[n].v;
		emitted++;
	}
	if (emitted + lost != SPEW_LINES) {
		fail("spew: %d emitted + %d not retained, of %d",
		     emitted, lost, SPEW_LINES);
		e++;
	}
	if (last != SPEW_LINES - 1 ||
	    find(REC_FINAL) != (int)rec_count - 1) {
		fail("spew: ended at tl %d, final at %d of %u", last,
		     find(REC_FINAL), rec_count);
		e++;
	}
	if (!lost) {
		fail("spew: nothing was left out");
		e++;
	}

	e += check_decisions("spew");

	/*
	 * The stall we made certainly looked like the end of the spew, and
	 * lws must have realized its mistake when the spew carried on
	 */

	if (stall_at < 0 || rec[stall_at].v != REC_EASED) {
		fail("spew: the stall did not look like the end of it");
		e++;
	} else {
		r = -1;
		for (n = stall_at + 1; n < (int)rec_count && r < 0; n++)
			if (rec[n].v == REC_ENTERED || rec[n].v == REC_RESUMED)
				r = n;
		if (r < 0 || rec[r].v != REC_RESUMED) {
			fail("spew: continued after the stall, not resumed");
			e++;
		}
	}

	if (!e)
		pass("spew: %d of %d lines emitted, %u times called over, "
		     "%u resumed", emitted, SPEW_LINES, count(REC_EASED),
		     count(REC_RESUMED));

	return e;
}

#if defined(LWS_HAVE_PTHREAD_H)

static void *
spewer(void *d)
{
	int t = (int)(intptr_t)d, n;

	for (n = 0; n < THREAD_LINES; n++)
		lwsl_notice("tt %d %d\n", t, n);

	return NULL;
}

/*
 * lws never holds its log lock while it emits, so a replay on one thread and
 * direct emits on another may interleave, and each thread's lines are not
 * necessarily in order.  But none may come out twice, and every one of them
 * must come out or be owned up to as not retained.
 */

static int
check_threads(void)
{
	pthread_t pt[THREADS];
	int t, e = 0, started;

	threads_on = 1;
	for (started = 0; started < THREADS; started++)
		if (pthread_create(&pt[started], NULL, spewer,
				   (void *)(intptr_t)started))
			break;
	for (t = 0; t < started; t++)
		pthread_join(pt[t], NULL);

	ease();
	lwsl_notice("final\n");
	threads_on = 0;

	if (started != THREADS) {
		fail("threads: only %d of %d started", started, THREADS);
		return 1;
	}
	if (thr_dupes || thr_other) {
		fail("threads: %d emitted twice, %d unexpected lines",
		     thr_dupes, thr_other);
		e++;
	}
	if (thr_emitted + thr_lost != THREADS * THREAD_LINES) {
		fail("threads: %d emitted + %d not retained, of %d",
		     thr_emitted, thr_lost, THREADS * THREAD_LINES);
		e++;
	}
	if (!e)
		pass("threads: %d emitted of %d lines from %d threads",
		     thr_emitted, THREADS * THREAD_LINES, THREADS);

	return e;
}

#endif

static int
check_surge_rt(void)
{
#if defined(LWS_WITH_NETWORK)
	static const char *rt_argv[] = { "lws-api-test-log-spew",
					 "--log-spew-tail", "200" };
	struct lws_context_creation_info info;
#endif
	int n, e = 0;

#if defined(LWS_WITH_NETWORK)
	memset(&info, 0, sizeof(info));
	info.default_loglevel = LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER;
	/* this leaves test_emit() in place */
	lws_cmdline_option_handle_builtin((int)LWS_ARRAY_SIZE(rt_argv),
					  rt_argv, &info);
#else
	/* no builtin commandline handling without networking */
	lws_log_spew_tail_lines(SPEW_TAIL_RT);
#endif
	tail = SPEW_TAIL_RT;

	for (n = 0; n < SURGE_RT_LINES; n++)
		lwsl_notice("tl %d\n", n);

	ease();
	lwsl_notice("final\n");

	if (rec_overflow) {
		fail("surge-rt: %u lines not recorded", rec_overflow);
		e++;
	}
	if (check_run(0, SURGE_RT_LINES - 1, "surge-rt"))
		e++;
	if (find(REC_FINAL) != (int)rec_count - 1) {
		fail("surge-rt: final not last");
		e++;
	}
	if (count(REC_OTHER)) {
		fail("surge-rt: unexpected lines emitted");
		e++;
	}
	if (check_decisions("surge-rt"))
		e++;
	if (!e)
		pass("surge-rt: %d lines all accounted for with a %d line "
		     "tail, %s spew mode", SURGE_RT_LINES, SPEW_TAIL_RT,
		     find(REC_ENTERED) >= 0 ||
		     find(REC_RESUMED) >= 0 ? "via" : "without");

	/* back to the default for what follows */
	lws_log_spew_tail_lines(0);
	tail = SPEW_TAIL;

	return e;
}

int
main(int argc, const char **argv)
{
	int n, e = 0, stall_at = -1;

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
	 * 2: a spew of distinct lines: while it is going, lines only reach the
	 *    emit function when lws thinks the spew might be over, and then the
	 *    tail it retained is replayed first.
	 *
	 *    Half way through we stall for longer than lws' exit quiet, as an
	 *    overloaded box might; lws must call the spew over, then see it
	 *    resume and raise its exit quiet.  Being starved of cpu may have
	 *    done the same thing to it already, that's fine.
	 */

	for (n = 0; n < SPEW_LINES; n++) {
		if (stall_at < 0 && n >= SPEW_LINES / 2 && in_spew) {
			ease();
			stall_at = (int)rec_count;
		}
		lwsl_notice("tl %d\n", n);
	}

	/* the rate eases: the next log replays the retained tail, then itself */

	ease();
	lwsl_notice("final\n");

	e += check_spew(stall_at);

	rec_count = 0;
	rec_overflow = 0;

	/*
	 * 3: a surge that trips spew mode but ends within the retained tail is
	 *    not allowed to lose a line: everything comes out exactly once
	 *    and in order, some of it directly and the rest by replay
	 */

	for (n = 0; n < SURGE_LINES; n++)
		lwsl_notice("tl %d\n", n);

	ease();
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
	if (check_decisions("surge"))
		e++;
	if (!e)
		pass("surge: %d lines all accounted for, %s spew mode",
		     SURGE_LINES, find(REC_ENTERED) >= 0 ||
				  find(REC_RESUMED) >= 0 ? "via" : "without");

	/*
	 * 4: the same with a longer tail, set the way an app's user would, by
	 *    --log-spew-tail on the commandline: a surge that would lose its
	 *    middle with the default tail is waved through intact
	 */

	rec_count = 0;
	e += check_surge_rt();

#if defined(LWS_HAVE_PTHREAD_H)
	/*
	 * 5: several threads spew at once: the spew handling is processwide,
	 *    and lws' own threads, eg, the async queue workers, log too
	 */

	e += check_threads();
#endif

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
