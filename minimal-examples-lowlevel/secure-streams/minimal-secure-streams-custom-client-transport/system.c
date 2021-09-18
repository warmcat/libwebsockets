/*
 * lws-minimal-secure-streams-custom-client-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * These are apis used inside liblws-sspc that must be wired up to the client
 * host platform.
 *
 *   lws_sul_schedule() - use system event loop to schedule event in the future
 *   lws_sul_cancel() - rescind a scheduled event
 *   lws_now_usecs() - unix time in microseconds
 *   __lws_logv() - core logging function used by liblws-sspc
 */

#include "private.h"

#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>

int log_level = LLL_USER | LLL_ERR;// | LLL_WARN | LLL_NOTICE;

static int
sul_compare(const lws_dll2_t *d, const lws_dll2_t *i)
{
	lws_usec_t a = ((lws_sorted_usec_list_t *)d)->us;
	lws_usec_t b = ((lws_sorted_usec_list_t *)i)->us;

	/*
	 * Simply returning (a - b) in an int
	 * may lead to an integer overflow bug
	 */

	if (a > b)
		return 1;
	if (a < b)
		return -1;

	return 0;
}

void
lws_sul_schedule(struct lws_context_standalone *ctx, int tsi,
		 lws_sorted_usec_list_t *sul, sul_cb_t _cb, lws_usec_t _us)
{
	if (_us == (lws_usec_t)LWS_SET_TIMER_USEC_CANCEL) {
		lws_sul_cancel(sul);
		return;
	}

	lws_dll2_remove(&sul->list);

	sul->cb = _cb;
	sul->us = lws_now_usecs() + _us;

	lws_dll2_add_sorted(&sul->list, &a_cpcx.scheduler, sul_compare);
}

void
lws_sul_cancel(lws_sorted_usec_list_t *sul)
{
	lws_dll2_remove(&sul->list);
	sul->us = 0;
}

lws_usec_t
lws_now_usecs(void)
{
#if defined(LWS_HAVE_CLOCK_GETTIME)
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return (((lws_usec_t)ts.tv_sec) * LWS_US_PER_SEC) +
			((lws_usec_t)ts.tv_nsec / LWS_NS_PER_US);
#else
	struct timeval now;

	gettimeofday(&now, NULL);
	return (((lws_usec_t)now.tv_sec) * LWS_US_PER_SEC) +
			(lws_usec_t)now.tv_usec;
#endif
}

/*
 * wire up lws-sspc logs to native application logs, we just wire it up to
 * stderr
 */

void
__lws_logv(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
	   int filter, const char *_fun, const char *format, va_list ap)
{
	char logbuf[200];
	int n;

	if (!(filter & log_level))
		return;

	n = vsnprintf(logbuf, sizeof(logbuf) - 2, format, ap);
	if (n > 0 && logbuf[n - 1] != '\n') {
		logbuf[n++] = '\n';
		logbuf[n] = '\0';
	}
	fprintf(stderr, "%llu: %s", (unsigned long long)lws_now_usecs(), logbuf);
}

