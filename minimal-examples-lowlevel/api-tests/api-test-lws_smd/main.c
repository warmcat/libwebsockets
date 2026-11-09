/*
 * lws-api-test-lws_smd
 *
 * Written in 2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This api test confirms lws_smd System Message Distribution, including that
 * messages sent before the context first services don't time out meanwhile
 */

#include <libwebsockets.h>

enum {
	LWS_SW_COUNT,
	LWS_SW_INTERVAL,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_COUNT]	= { "--count",         "Enable --count feature" },
	[LWS_SW_INTERVAL]	= { "--interval",      "Enable --interval feature" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#define HAVE_STRUCT_TIMESPEC
#include <pthread.h>
#include <signal.h>

#define THRESHOLD_PC 55

/*
 * If the service loop is gone (test timeout, SIGINT...), nothing drains the
 * smd queue any more and every send is refused.  Spam threads that make no
 * progress for this long bail out without setting completed[], so main's
 * joins return and the test reports FAIL instead of hanging until ctest
 * kills it.
 */
#define NO_PROGRESS_BAIL_US (5 * LWS_US_PER_SEC)

static unsigned int how_many_msg = 5000, ok, fail, usec_interval = 200, _exp;
static char completed[2] = { 0, 0 };

static lws_sorted_usec_list_t sul_timeout, sul_initial_drain;
struct lws_context *context;
static pthread_t thread_spam1, thread_spam2;

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	/* We should have completed the test before this fires */
	lwsl_notice("%s: test period finished\n", __func__);
	lws_default_loop_exit(context);
	lws_cancel_service(context);
}

static int
smd_cb1int(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
	   void *buf, size_t len)
{
#if 0
	lwsl_notice("%s: ts %llu, len %d\n", __func__,
		    (unsigned long long)timestamp, (int)len);
	lwsl_hexdump_notice(buf, len);
#endif
	ok++;

	return 0;
}

static int
smd_cb2int(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
	   void *buf, size_t len)
{
#if 0
	lwsl_notice("%s: ts %llu, len %d\n", __func__,
		    (unsigned long long)timestamp, (int)len);
	lwsl_hexdump_notice(buf, len);
#endif
	ok++;

	return 0;
}

/*
 * This is used in an smd participant that is deregistered before the message
 * can be delivered, it should never see any message
 */

static int
smd_cb3int(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
	   void *buf, size_t len)
{
	lwsl_err("%s: Countermanded ts %llu, len %d\n", __func__,
		    (unsigned long long)timestamp, (int)len);
	lwsl_hexdump_err(buf, len);

	fail++;

	return 0;
}

#if defined(WIN32)

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x2
#endif

/*
 * Sleep() waits are quantized to the default ~15.6ms system timer tick, so
 * pacing the spam threads with Sleep(3) actually takes ~78s for 5000
 * messages and overruns the test's 50s window.  Wait on a per-thread high
 * resolution waitable timer (Windows 10 1803+) instead: us-accurate waits
 * without touching process-wide timer resolution.  With htimer NULL (older
 * Windows), fall back to Sleep() and its tick quantization.
 */
static void
win_wait_us(HANDLE htimer, unsigned int us)
{
	LARGE_INTEGER due;

	due.QuadPart = -10 * (LONGLONG)us;
	if (htimer && SetWaitableTimer(htimer, &due, 0, NULL, NULL, 0) &&
	    WaitForSingleObject(htimer, INFINITE) == WAIT_OBJECT_0)
		return;

	Sleep(us / 1000 + 1);
}
#endif

static void *
_thread_spam(void *d)
{
#if defined(WIN32)
	unsigned int mypid = 0;
	HANDLE htimer = CreateWaitableTimerExW(NULL, NULL,
			CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
			TIMER_ALL_ACCESS);
#else
	unsigned int mypid = (unsigned int)getpid();
#endif
	unsigned int n = 0, m = (unsigned int)(intptr_t)d;
	lws_usec_t last_progress = lws_now_usecs();

	while (n < how_many_msg) {
		if (lws_smd_msg_printf(context, LWSSMDCL_SYSTEM_STATE,
					       "{\"s\":\"state\","
						"\"pid\":%u,"
						"\"msg\":%d}",
					       mypid, (unsigned int)n)) {
			fail++;

			if (lws_now_usecs() - last_progress > NO_PROGRESS_BAIL_US) {
				lwsl_err("%s: t%u: no message accepted for %ds, "
					 "giving up\n", __func__, m,
					 (int)(NO_PROGRESS_BAIL_US / LWS_US_PER_SEC));
				goto bail;
			}
		} else {
			n++;
			last_progress = lws_now_usecs();
		}
#if defined(WIN32)
		if (usec_interval)
			win_wait_us(htimer, usec_interval);
#else
		if (usec_interval)
			usleep(usec_interval);
#endif
	}

	completed[m] = 1;
	/*
	 * main's loop may already have woken for our last message and gone
	 * back to waiting: wake it to see we completed
	 */
	lws_cancel_service(context);

bail:
#if defined(WIN32)
	if (htimer)
		CloseHandle(htimer);
#endif

#if !defined(WIN32)
	pthread_exit(NULL);
#endif

	return NULL;
}

/*
 * The startup leg: on a context of its own with a short ttl, a message sent
 * before the first service must survive a wait longer than the ttl, since
 * nothing could be delivered during it; one sent after the first service and
 * then left waiting longer than the ttl must be dropped.
 */

#define STARTUP_TTL_US		(100 * LWS_US_PER_MS)
#define STARTUP_WAIT_US		(3 * STARTUP_TTL_US)

static int startup_rx, startup_expired;

typedef struct startup_deadline {
	lws_sorted_usec_list_t	sul;
	struct lws_context	*cx;
} startup_deadline_t;

/*
 * Both callbacks change what startup_service()'s loop is waiting for, from
 * inside lws_service(), which may then go on to wait for the next event: they
 * must wake it, so it returns and the loop sees the change
 */

static int
smd_cb_startup(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
	       void *buf, size_t len)
{
	startup_rx++;
	lws_cancel_service((struct lws_context *)opaque);

	return 0;
}

static void
startup_wait(void)
{
#if defined(WIN32)
	Sleep(STARTUP_WAIT_US / 1000);
#else
	usleep(STARTUP_WAIT_US);
#endif
}

static void
startup_deadline_cb(lws_sorted_usec_list_t *sul)
{
	startup_deadline_t *sd = lws_container_of(sul, startup_deadline_t, sul);

	startup_expired = 1;
	lws_cancel_service(sd->cx);
}

/*
 * Service until the participant has had n messages, or for a second.  The sul
 * makes sure the event loop wakes for the deadline, since when nothing is
 * delivered there may be nothing else scheduled to end its wait.
 */

static int
startup_service(struct lws_context *cx, int n)
{
	startup_deadline_t sd;

	memset(&sd, 0, sizeof(sd));
	sd.cx = cx;
	startup_expired = 0;
	lws_sul_schedule(cx, 0, &sd.sul, startup_deadline_cb, LWS_US_PER_SEC);

	while (startup_rx < n && !startup_expired)
		if (lws_service(cx, 0) < 0)
			break;

	lws_sul_cancel(&sd.sul);

	return startup_rx >= n;
}

static int
startup_leg(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	int ret = 1;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.smd_ttl_us = STARTUP_TTL_US;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: lws init failed\n", __func__);
		return 1;
	}

	if (!lws_smd_register(cx, cx, 0, LWSSMDCL_INTERACTION,
			      smd_cb_startup)) {
		lwsl_err("%s: smd register failed\n", __func__);
		goto bail;
	}

	/* sent before the first service, which is later than the ttl */

	if (lws_smd_msg_printf(cx, LWSSMDCL_INTERACTION, "{\"s\":\"early\"}")) {
		lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}
	startup_wait();

	if (!startup_service(cx, 1)) {
		lwsl_err("%s: message sent before the first service was "
			 "dropped\n", __func__);
		goto bail;
	}

	/* after the first service, waiting longer than the ttl drops it */

	if (lws_smd_msg_printf(cx, LWSSMDCL_INTERACTION, "{\"s\":\"late\"}")) {
		lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}
	startup_wait();

	if (startup_service(cx, 2)) {
		lwsl_err("%s: message left past its ttl was delivered\n",
			 __func__);
		goto bail;
	}

	lwsl_user("%s: PASS\n", __func__);
	ret = 0;

bail:
	lws_context_destroy(cx);

	return ret;
}

void sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static void
drained_cb(lws_sorted_usec_list_t *sul)
{
	/*
	 * spawn the test thread, it's going to spam messages at short (or zero)
	 * intervals... check we got everything
	 */

	if (pthread_create(&thread_spam1, NULL, _thread_spam, (void *)(intptr_t)0))
		lwsl_err("%s: failed to create the spamming thread\n", __func__);

	if (pthread_create(&thread_spam2, NULL, _thread_spam, (void *)(intptr_t)1))
		lwsl_err("%s: failed to create the spamming thread\n", __func__);
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		   int current, int target)
{
	// struct lws_context *context = mgr->parent;
	unsigned int n;

	if (current != LWS_SYSTATE_OPERATIONAL || target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/*
	 * Overflow the message queue too see if it handles it well, both
	 * as overflowing and in recovery.  These are all still going into the
	 * smd buffer dll2, since we don't break for the event loop to have a
	 * chance to deliver them.
	 */

	n = 0;
	while (n++ < how_many_msg)
		if (lws_smd_msg_printf(context, LWSSMDCL_SYSTEM_STATE,
				       "{\"s\":\"state\",\"test\":\"overflow\"}"))
			break;

	lwsl_notice("%s: overflow test added %u messages\n", __func__, n);
	if (n == how_many_msg) {
		lwsl_err("%s: didn't overflow\n", __func__);
		lws_default_loop_exit(context);
		return 1;
	}

	/*
	 * So we have some normal messages from earlier and now the rest of the
	 * smd buffer filled with junk overflow messages.  Before we start the
	 * actual spamming test from another thread, we need to return to the
	 * event loop so these can be cleared first.
	 */

	lws_sul_schedule(context, 0, &sul_initial_drain, drained_cb,
			 3 * LWS_US_PER_MS);

	lwsl_info("%s: operational\n", __func__);

	return 0;
}

int
main(int argc, const char **argv)
{
	lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
						system_notify_cb, "app" };
	lws_state_notify_link_t *na[] = { &notifier, NULL };
	
	struct lws_context_creation_info info;
	struct lws_smd_peer *userreg;
	const char *p;
	void *retval;

	/* the normal lws init */

	signal(SIGINT, sigint_handler);


	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_COUNT].sw)))
		how_many_msg = (unsigned int)atol(p);

	_exp = (2 * how_many_msg * THRESHOLD_PC) / 100;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_INTERVAL].sw)))
		usec_interval = (unsigned int)atol(p);

	lwsl_user("LWS API selftest: lws_smd: %u msgs at %uus interval\n",
			how_many_msg, usec_interval);

	if (startup_leg(argc, argv)) {
		lwsl_user("Completed: FAIL: startup leg\n");
		return 1;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.register_notifier_list = na;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* game over after this long */

	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb,
			 50 * (LWS_US_PER_SEC));

	/* register a messaging participant to hear INTERACTION class */

	if (!lws_smd_register(context, NULL, 0, LWSSMDCL_INTERACTION,
			      smd_cb1int)) {
		lwsl_err("%s: smd register 1 failed\n", __func__);
		goto bail;
	}

	/* register a messaging participant to hear SYSTEM_STATE class */

	if (!lws_smd_register(context, NULL, 0, LWSSMDCL_SYSTEM_STATE,
			      smd_cb2int)) {
		lwsl_err("%s: smd register 2 failed\n", __func__);
		goto bail;
	}

	/* temporarily register a messaging participant to hear a user class */

	userreg = lws_smd_register(context, NULL, 0, 1 << LWSSMDCL_USER_BASE_BITNUM,
			      smd_cb3int);
	if (!userreg) {
		lwsl_err("%s: smd register userclass failed\n", __func__);
		goto bail;
	}

	/*
	 * The event loop isn't started yet, so these smd messages are getting
	 * buffered.  Later we will deliberately overrun the buffer and wait
	 * for that to be cleared before the spam thread test.
	 */

	/* generate an INTERACTION class message */

	if (lws_smd_msg_printf(context, LWSSMDCL_INTERACTION,
			       "{\"s\":\"interaction\"}")) {
		lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/* generate a SYSTEM_STATE class message */

	if (lws_smd_msg_printf(context, LWSSMDCL_SYSTEM_STATE,
			       "{\"s\":\"state\"}")) {
		lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/* no participant listens for this class, so it should be skipped */

	if (lws_smd_msg_printf(context, LWSSMDCL_NETWORK, "{\"s\":\"network\"}")) {
		lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/* generate a user class message... */

	if (lws_smd_msg_printf(context, 1 << LWSSMDCL_USER_BASE_BITNUM,
			       "{\"s\":\"userclass\"}")) {
		lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/*
	 * ... and screw that user class message up by deregistering the only
	 * handler before it can deliver it... it should not get delivered
	 * and cleanly discarded
	 */

	lws_smd_unregister(userreg);

	/* the usual lws event loop */

	while ((!completed[0] || !completed[1]) &&
			lws_service(context, 0) >= 0)
		;

	lwsl_notice("%s: exited loop\n", __func__);

	pthread_join(thread_spam1, &retval);
	pthread_join(thread_spam2, &retval);

bail:
	lws_context_destroy(context);

	/* expect some failures since we are spinning spamming the smd queue */

	if (completed[0] && completed[1]) {
		lwsl_user("Completed: PASS: %d / %d, (busy: %d)\n", ok, _exp, fail);
		return 0;
	}

	lwsl_user("Completed: FAIL: %d / %d, (busy: %d)\n", ok, _exp, fail);

	return 1;
}
