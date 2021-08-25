/*
 * pico-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * These are apis used inside libwebsockets.a in LWS_ONLY_SSPC mode, that must
 * be wired up to the client host platform system apis, like its own logging
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

int log_level = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO;

static const char * const colours[] = {
	"[31;1m", /* LLL_ERR */
	"[36;1m", /* LLL_WARN */
	"[35;1m", /* LLL_NOTICE */
	"[32;1m", /* LLL_INFO */
	"[34;1m", /* LLL_DEBUG */
	"[33;1m", /* LLL_PARSER */
	"[33m", /* LLL_HEADER */
	"[33m", /* LLL_EXT */
	"[33m", /* LLL_CLIENT */
	"[33;1m", /* LLL_LATENCY */
        "[0;1m", /* LLL_USER */
	"[31m", /* LLL_THREAD */
};

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

	lws_dll2_add_sorted(&sul->list, &scheduler, sul_compare);
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
	absolute_time_t at = get_absolute_time();
	
	return (lws_usec_t)to_us_since_boot(at);
}

/*
 * wire up libwebsockets.a logs to native application logs, we just wire it up
 * to the device console in our case.
 *
 * We add the lws loglevel colour scheme ourselves.
 */

void
__lws_logv(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
	   int filter, const char *_fun, const char *format, va_list ap)
{
	int n, m = LWS_ARRAY_SIZE(colours) - 1;
	char logbuf[200], *p = logbuf, *e = logbuf + sizeof(logbuf);

	if (!(filter & log_level))
		return;

	n = 1 << (LWS_ARRAY_SIZE(colours) - 1);
	while (n) {
		if (filter & n)
			break;
		m--;
		n >>= 1;
	}

	printf("%llu: %c%s%s: ", (unsigned long long)lws_now_usecs(), 27,
			colours[m], _fun);
	if (prep && obj) {
		prep(cx, obj, &p, e);
		printf("%s: ", logbuf);
	}

	n = vsnprintf(logbuf, sizeof(logbuf) - 2, format, ap);
	if (n > 0 && logbuf[n - 1] != '\n') {
		logbuf[n++] = '\n';
		logbuf[n] = '\0';
	}
	printf("%s%c[0m", logbuf, 27);
}


