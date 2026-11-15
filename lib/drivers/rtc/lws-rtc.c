/*
 * lws abstract real time clock
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * See lws-rtc.h
 */

#include "private-lib-core.h"

int
_lws_rtc_set(struct lws_context *cx, int64_t secs)
{
	lws_civil_t c;

	if (!cx->rtc || lws_unix_to_civil(secs, &c) ||
	    cx->rtc->write(cx->rtc, &c))
		return 1;

	lwsl_cx_notice(cx, "rtc %s set to %04d-%02d-%02d %02d:%02d:%02d UTC",
		       cx->rtc->name, c.year, c.mon, c.day, c.hour, c.min,
		       c.sec);

	return 0;
}

int
lws_rtc_set_from_system(struct lws_context *cx)
{
	int64_t now = (int64_t)lws_now_secs();

	if (now < LWS_SYSTEM_TIME_PLAUSIBLE_SECS)
		return 1; /* the system clock isn't set */

	return _lws_rtc_set(cx, now);
}

int
lws_rtc_attach(struct lws_context *cx, const lws_rtc_t *rtc)
{
	lws_civil_t c;
	int64_t secs;
	int n;

	cx->rtc = NULL;

	if (!rtc->init || !rtc->read || !rtc->write || rtc->init(rtc)) {
		lwsl_cx_warn(cx, "rtc %s unusable", rtc->name);

		return 1;
	}

	cx->rtc = rtc;

	n = rtc->read(rtc, &c);
	if (n) {
		lwsl_cx_notice(cx, "rtc %s %s", rtc->name, n > 0 ?
				"time not believed, eg, its backup failed" :
				"unreadable");
		return 0;
	}

	/* what we read from the chip is untrusted until it's a real time */

	if (lws_civil_to_unix(&c, &secs) ||
	    secs < LWS_SYSTEM_TIME_PLAUSIBLE_SECS) {
		lwsl_cx_notice(cx, "rtc %s has no usable time", rtc->name);

		return 0;
	}

	lwsl_cx_notice(cx, "rtc %s: %04d-%02d-%02d %02d:%02d:%02d UTC",
		       rtc->name, c.year, c.mon, c.day, c.hour, c.min, c.sec);

	if ((int64_t)lws_now_secs() >= LWS_SYSTEM_TIME_PLAUSIBLE_SECS)
		/* the system clock was already set by something else */
		return 0;

	lws_system_time_set(cx, (lws_usec_t)secs * LWS_US_PER_SEC,
			    LWS_SYSTIME_SRC_RTC);

#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_SYS_STATE)
	/* the system state may have been waiting for the time */
	lws_state_transition_steps(&cx->mgr_system, LWS_SYSTATE_OPERATIONAL);
#endif

	return 0;
}

void
lws_rtc_detach(struct lws_context *cx)
{
	cx->rtc = NULL;
}
