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
 * A battery-backed real time clock chip keeps the time while the rest of the
 * device is off.  This class lets a device that has one know the time at boot,
 * before it has any network to ask ntp, and keeps the chip right once ntp has
 * told us the time.
 *
 * Specific chips, eg, lws_rtc_pcf8563_t, are "subclasses" that only know how
 * to read and write their registers, as UTC, with lws_civil_t.  The class
 * does the rest:
 *
 *  - lws_rtc_attach() reads the chip as soon as it is there.  If the system
 *    clock is not set yet, but the chip has a time it believes, the system
 *    clock is set from it.  lws_system_time_source() then says the time came
 *    from the rtc, and the system state can go past LWS_SYSTATE_TIME_VALID at
 *    once, without waiting for the network.
 *
 *  - With LWS_WITH_SYS_NTPCLIENT, when the system state goes past
 *    LWS_SYSTATE_TIME_VALID on time that came from the rtc, ntp is asked
 *    anyway, in the background: it no longer holds the system state up.
 *
 *  - Whenever ntp sets the time, the rtc is set from it too, so the chip
 *    is right for next time.  lws_rtc_set_from_system() does that at any other
 *    time.
 *
 * The chip is only touched from the lws event loop thread.  If its bus is
 * shared with devices used from other threads, eg, a touch controller read
 * from an OS timer, the bus needs lws_i2c_ops_t .lock and .unlock.
 */

#if !defined(__LWS_RTC_H__)
#define __LWS_RTC_H__

/*
 * This is embedded at the top of the specific chip's object, so a pointer to
 * it can be cast to the implementation object, like lws_touch_t
 */

typedef struct lws_rtc {
	int (*init)(const struct lws_rtc *rtc);
	/**< find the chip and get it ready, eg, make sure it is counting.
	 * Nonzero return = it's not there or can't be used */
	int (*read)(const struct lws_rtc *rtc, lws_civil_t *c);
	/**< read the time the chip has, in UTC.  Returns 0 if it was read and
	 * the chip believes it, 1 if it was read but the chip says it can't be
	 * believed, eg, its backup supply failed since it was set, or < 0 if it
	 * couldn't be read or isn't a time.  Only on 0 is \p c set */
	int (*write)(const struct lws_rtc *rtc, const lws_civil_t *c);
	/**< set the chip to the UTC time \p c, which the chip should believe
	 * from then on.  Returns 0, or nonzero if it could not be set, eg, it
	 * is a year the chip can't hold */

	const char		*name;
	/**< for logging */
} lws_rtc_t;

/**
 * lws_rtc_attach() - start using an rtc chip
 *
 * \param cx: the lws_context
 * \param rtc: the chip's definition, which must stay valid while the context
 *	       exists
 *
 * Initializes the chip and associates it with the context: there is one per
 * context, attaching another replaces it.  If the system clock is not set yet,
 * and the chip has a time it believes, the system clock is set from it; on
 * platforms where lws doesn't set the system clock itself, the time is given
 * to lws_system_ops_t .set_clock(), as ntp would.  Either way,
 * lws_system_time_source() then says LWS_SYSTIME_SRC_RTC, and the system
 * state is moved on, in case it was waiting for the time.
 *
 * Returns 0 if the chip is attached, whether or not its time was used, or
 * nonzero if it could not be initialized, when the context has no rtc.
 */
LWS_VISIBLE LWS_EXTERN int
lws_rtc_attach(struct lws_context *cx, const lws_rtc_t *rtc);

/**
 * lws_rtc_detach() - stop using the context's rtc chip, if any
 *
 * \param cx: the lws_context
 *
 * Eg, before the bus it is on is stopped.  The chip carries on keeping the
 * time by itself.
 */
LWS_VISIBLE LWS_EXTERN void
lws_rtc_detach(struct lws_context *cx);

/**
 * lws_rtc_set_from_system() - set the rtc chip from the system clock
 *
 * \param cx: the lws_context
 *
 * lws does this by itself whenever ntp sets the time, so it's only needed for
 * time that came from somewhere else.  Returns 0 if the chip was set, or
 * nonzero if there's no chip, the system clock is not set, or the chip could
 * not be set.
 */
LWS_VISIBLE LWS_EXTERN int
lws_rtc_set_from_system(struct lws_context *cx);

#endif
