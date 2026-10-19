/*
 * lws-api-test-sul-wait
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A service loop with nothing to do but wait for its next timer must sleep
 * until the timer is due, then run it: one, or a few, service turns per
 * timer.
 *
 * The waits are taken in whole ms on the default poll() loop and on libuv,
 * but the timers are scheduled in us.  If the remaining part of an interval
 * that is not a whole number of ms is rounded down, the last < 1ms before
 * every timer becomes a run of zero-wait turns, hundreds of them on a fast
 * machine, until the timer is due.
 *
 * This chains timers at intervals with sub-ms parts, from 0.2ms to 6ms, and
 * counts the lws_service() turns between each firing and the one before it.
 * A loop that sleeps needs a turn or two for each; it fails if any timer,
 * once the context has settled, took more than SUL_WAIT_MAX_TURNS.  It also checks no timer ran before it
 * was due.
 *
 * ctest runs it on the default event loop and, if built in, on libuv (any
 * built-in event lib can be chosen with --uv, --event, --glib, etc).
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

/* timers chained one after the other */
#define SUL_WAIT_TIMERS		60

/*
 * The first few timers share their turns with the context starting up (the
 * system state machine, protocol init): they are not counted
 */
#define SUL_WAIT_SETTLE		8

/*
 * Turns a single timer may take: one to run it, more if the wait woke
 * a little early (libuv's loop clock is in whole ms), or for the wake-up of
 * something else.  Rounding the wait down takes hundreds.
 */
#define SUL_WAIT_MAX_TURNS	6

/* give up on the whole thing after this, eg, if timers stop firing */
#define SUL_WAIT_LIMIT_US	(10 * LWS_US_PER_SEC)

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_chain, sul_limit;
static lws_usec_t due;
static unsigned int fired, turns, turns_at_last, turns_max, early;
static int done, timed_out;

static void
sigint_handler(int sig)
{
	(void)sig;
	done = 1;
	lws_cancel_service(cx);
}

/*
 * Intervals from 200us to ~6ms, each with a different sub-ms remainder
 */

static lws_usec_t
interval(unsigned int n)
{
	return (lws_usec_t)200 + (lws_usec_t)((n * 1237u) % 6000u);
}

static void
chain_cb(lws_sorted_usec_list_t *sul)
{
	lws_usec_t now = lws_now_usecs();
	unsigned int t = turns - turns_at_last;

	if (now < due)
		early++;

	if (fired >= SUL_WAIT_SETTLE && t > turns_max)
		turns_max = t;

	turns_at_last = turns;

	if (++fired == SUL_WAIT_TIMERS) {
		done = 1;
		lws_sul_cancel(&sul_limit);
		lws_cancel_service(cx);
		return;
	}

	due = lws_now_usecs() + interval(fired);
	lws_sul_schedule(cx, 0, sul, chain_cb, interval(fired));
}

static void
limit_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	timed_out = 1;
	done = 1;
	lws_cancel_service(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int fail = 1;

	memset(&info, 0, sizeof info);
	/* takes -d and an event lib choice, eg, --uv */
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: timers sleep until they are due\n");

	/* no vhost, nothing to wake the loop but the timers */
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_limit, limit_cb, SUL_WAIT_LIMIT_US);
	due = lws_now_usecs() + interval(0);
	lws_sul_schedule(cx, 0, &sul_chain, chain_cb, interval(0));

	while (!done && lws_service(cx, 0) >= 0)
		turns++;

	lwsl_user("%u timers fired in %u service turns, at most %u for one "
		  "timer after the first %u, %u early\n", fired, turns,
		  turns_max, SUL_WAIT_SETTLE, early);

	if (timed_out)
		lwsl_err("timers did not all fire within %ds\n",
			 (int)(SUL_WAIT_LIMIT_US / LWS_US_PER_SEC));
	else if (fired != SUL_WAIT_TIMERS)
		lwsl_err("only %u of %u timers fired\n", fired,
			 SUL_WAIT_TIMERS);
	else if (turns_max > SUL_WAIT_MAX_TURNS)
		lwsl_err("a timer took %u service turns (limit %u): the loop "
			 "did not sleep until it was due\n", turns_max,
			 SUL_WAIT_MAX_TURNS);
	else if (early)
		lwsl_err("%u timers ran before they were due\n", early);
	else
		fail = 0;

	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
