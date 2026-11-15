/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 */

/** \defgroup tz Civil time and time zones
 * ##Civil time and time zones
 *
 * Converting between seconds since 1970 and the calendar, and finding the
 * local time in a time zone given as a POSIX TZ string, eg,
 * "CET-1CEST,M3.5.0,M10.5.0/3", without the platform's own time zone support.
 *
 * Platforms differ in what TZ strings they understand, eg, quoted zone names
 * like "<+0330>-3:30", and in how many zones a process can use at once: the
 * TZ environment variable is one zone for the whole process.  These are
 * portable, and work on any number of zones at once, eg, for showing the
 * time at home and where we are now side by side.
 *
 * The TZ strings tzdata gives, as the last line of each of its compiled zone
 * files, eg, /usr/share/zoneinfo/Europe/Paris, are the zone's rules from now
 * on: they're right for the present and future, not for past dates whose
 * rules have since changed.
 */
///@{

#if !defined(__LWS_TZ_H__)
#define __LWS_TZ_H__

/*
 * A time broken down by the calendar
 */

typedef struct lws_civil {
	int16_t			year;	/**< eg, 2026 */
	uint8_t			mon;	/**< 1 .. 12 */
	uint8_t			day;	/**< 1 .. 31 */
	uint8_t			hour;	/**< 0 .. 23 */
	uint8_t			min;	/**< 0 .. 59 */
	uint8_t			sec;	/**< 0 .. 59 */
	uint8_t			wday;	/**< 0 .. 6, 0 is Sunday */
} lws_civil_t;

/**
 * lws_civil_to_unix() - a UTC civil time as seconds since 1970
 *
 * \param c: the civil time, wday is ignored
 * \param secs: set to the seconds since 1970-01-01 00:00:00 UTC
 *
 * Returns 0, or nonzero if any field is out of its range, eg, the 30th of
 * February, in which case \p secs is not set.  Years from 1970 to 9999 can be
 * converted.
 */
LWS_VISIBLE LWS_EXTERN int
lws_civil_to_unix(const lws_civil_t *c, int64_t *secs);

/**
 * lws_unix_to_civil() - seconds since 1970 as a civil time
 *
 * \param secs: the seconds since 1970-01-01 00:00:00
 * \param c: set to the civil time, including wday
 *
 * Returns 0, or nonzero if \p secs is before 1970 or after 9999.
 */
LWS_VISIBLE LWS_EXTERN int
lws_unix_to_civil(int64_t secs, lws_civil_t *c);

/* what applies in a time zone at a moment */

typedef struct lws_tz_info {
	int32_t			utc_offset;
	/**< seconds east of UTC, eg, 3600 for CET, -18000 for EST */
	char			abbr[12];
	/**< what the time there is called then, eg, "CEST", "+0530" */
	uint8_t			dst;
	/**< it's the zone's daylight saving time then */
} lws_tz_info_t;

/**
 * lws_tz_at() - what applies in a time zone at a moment
 *
 * \param tz: the zone, as a POSIX TZ string, eg, "CET-1CEST,M3.5.0,M10.5.0/3"
 * \param utc: the moment, as seconds since 1970-01-01 00:00:00 UTC
 * \param info: set to what applies in the zone then
 *
 * Understands POSIX TZ strings with the extensions tzdata uses (RFC 8536 3.3):
 * quoted names like "<-03>3", and rule times from -167 to 167 hours.  A zone
 * with daylight saving time but no rules for when, eg, "EST5EDT", takes the
 * US rules, as glibc does.
 *
 * Returns 0, or nonzero if \p tz isn't a TZ string we understand, or \p utc
 * is before 1970 or after 9999, when \p info is not set.
 */
LWS_VISIBLE LWS_EXTERN int
lws_tz_at(const char *tz, int64_t utc, lws_tz_info_t *info);

/**
 * lws_tz_local() - the local civil time in a time zone at a moment
 *
 * \param tz: the zone, as a POSIX TZ string
 * \param utc: the moment, as seconds since 1970-01-01 00:00:00 UTC
 * \param c: set to the local time in the zone then
 * \param info: NULL, or set to what applies in the zone then
 *
 * As lws_tz_at(), and the local time.  Returns 0, or nonzero if it couldn't
 * be found, when neither \p c nor \p info is set.
 */
LWS_VISIBLE LWS_EXTERN int
lws_tz_local(const char *tz, int64_t utc, lws_civil_t *c,
	     lws_tz_info_t *info);

#endif
///@}
