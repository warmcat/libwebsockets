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
 *
 * Civil time and POSIX TZ strings, see lws-tz.h
 */

#include "private-lib-core.h"

#define SECS_PER_DAY		86400
/* 0000-03-01 to 1970-01-01, in the proleptic gregorian calendar */
#define DAYS_TO_1970		719468
#define DAYS_PER_400Y		146097
/* 1970-01-01 to 10000-01-01, the first day we can't convert */
#define DAYS_TO_10000		2932897

/* rule times and offsets are no more than this many hours (RFC 8536 3.3.1) */
#define TZ_MAX_HOURS		167

static int
is_leap(int y)
{
	return !(y % 4) && ((y % 100) || !(y % 400));
}

static int
days_in_month(int y, int m)
{
	static const uint8_t dim[] = { 31, 28, 31, 30, 31, 30,
				       31, 31, 30, 31, 30, 31 };

	return dim[m - 1] + (m == 2 && is_leap(y));
}

/*
 * Counting years from March, so the leap day is the last of the year, the
 * days from 1970-01-01 to y-m-d, for y >= 0.  After Howard Hinnant's
 * "chrono-Compatible Low-Level Date Algorithms".
 */

static int64_t
days_from_civil(int y, int m, int d)
{
	int era, yoe, doy;

	if (m <= 2)
		y--;
	era = y / 400;
	yoe = y - era * 400;
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;

	return (int64_t)era * DAYS_PER_400Y +
	       (yoe * 365 + yoe / 4 - yoe / 100 + doy) - DAYS_TO_1970;
}

int
lws_civil_to_unix(const lws_civil_t *c, int64_t *secs)
{
	if (c->year < 1970 || c->year > 9999 || c->mon < 1 || c->mon > 12 ||
	    c->day < 1 || c->day > days_in_month(c->year, c->mon) ||
	    c->hour > 23 || c->min > 59 || c->sec > 59)
		return 1;

	*secs = days_from_civil(c->year, c->mon, c->day) * SECS_PER_DAY +
		c->hour * 3600 + c->min * 60 + c->sec;

	return 0;
}

int
lws_unix_to_civil(int64_t secs, lws_civil_t *c)
{
	int64_t z = secs / SECS_PER_DAY;
	int era, doe, yoe, doy, mp, sod = (int)(secs % SECS_PER_DAY);

	if (secs < 0 || z >= DAYS_TO_10000)
		return 1;

	c->wday = (uint8_t)((z + 4) % 7); /* 1970-01-01 was a Thursday */

	z += DAYS_TO_1970;
	era = (int)(z / DAYS_PER_400Y);
	doe = (int)(z - (int64_t)era * DAYS_PER_400Y);
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	mp = (5 * doy + 2) / 153;

	c->day = (uint8_t)(doy - (153 * mp + 2) / 5 + 1);
	c->mon = (uint8_t)(mp < 10 ? mp + 3 : mp - 9);
	c->year = (int16_t)(yoe + era * 400 + (c->mon <= 2));
	c->hour = (uint8_t)(sod / 3600);
	c->min = (uint8_t)((sod / 60) % 60);
	c->sec = (uint8_t)(sod % 60);

	return 0;
}

/*
 * POSIX TZ strings, eg, "CET-1CEST,M3.5.0,M10.5.0/3":
 *
 *   std offset [dst [offset] [,start[/time],end[/time]]]
 *
 * The offsets are how far west of UTC: the opposite sign to what we report.
 */

typedef enum {
	TZR_JULIAN_NOLEAP,	/* Jn: 1 .. 365, Feb 29 is never counted */
	TZR_JULIAN,		/* n: 0 .. 365, from Jan 1 */
	TZR_MWD,		/* Mm.w.d: weekday d of week w of month m */
} tz_rule_type_t;

typedef struct tz_rule {
	int32_t			time;	/* local secs into the day, may be
					 * negative or past the day */
	uint16_t		n;
	uint8_t			type;	/* tz_rule_type_t */
	uint8_t			m, w, d;
} tz_rule_t;

typedef struct tz_spec {
	tz_rule_t		start, end;
	int32_t			std_west, dst_west;
	char			std[12], dst[12];
	uint8_t			has_dst;
} tz_spec_t;

static int
tz_num(const char **p, int max, int *v)
{
	int n = 0, digits = 0;

	while (**p >= '0' && **p <= '9') {
		n = (n * 10) + (*(*p)++ - '0');
		if (n > max || ++digits > 3)
			return 1;
	}

	*v = n;

	return !digits;
}

/* a zone name, either 3+ letters, or anything sane in <...> */

static int
tz_name(const char **p, char *name, size_t len)
{
	size_t n = 0;

	if (**p == '<') {
		(*p)++;
		while (**p && **p != '>') {
			char c = **p;

			if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			      (c >= '0' && c <= '9') || c == '+' || c == '-') ||
			    n + 1 >= len)
				return 1;
			name[n++] = c;
			(*p)++;
		}
		if (**p != '>')
			return 1;
		(*p)++;
	} else
		while ((**p >= 'A' && **p <= 'Z') || (**p >= 'a' && **p <= 'z')) {
			if (n + 1 >= len)
				return 1;
			name[n++] = *(*p)++;
		}

	name[n] = '\0';

	return n < 3;
}

/* [+|-]hh[:mm[:ss]], hh up to max */

static int
tz_hms(const char **p, int max, int32_t *secs)
{
	int neg = 0, h, m = 0, s = 0;

	if (**p == '+' || **p == '-')
		neg = *(*p)++ == '-';

	if (tz_num(p, max, &h))
		return 1;
	if (**p == ':') {
		(*p)++;
		if (tz_num(p, 59, &m))
			return 1;
		if (**p == ':') {
			(*p)++;
			if (tz_num(p, 59, &s))
				return 1;
		}
	}

	*secs = (h * 3600) + (m * 60) + s;
	if (neg)
		*secs = -*secs;

	return 0;
}

static int
tz_rule(const char **p, tz_rule_t *r)
{
	int a, b, c;

	r->time = 2 * 3600; /* 02:00 unless it says */

	switch (**p) {
	case 'J':
		(*p)++;
		if (tz_num(p, 365, &a) || a < 1)
			return 1;
		r->type = TZR_JULIAN_NOLEAP;
		r->n = (uint16_t)a;
		break;
	case 'M':
		(*p)++;
		if (tz_num(p, 12, &a) || a < 1 || *(*p)++ != '.' ||
		    tz_num(p, 5, &b) || b < 1 || *(*p)++ != '.' ||
		    tz_num(p, 6, &c))
			return 1;
		r->type = TZR_MWD;
		r->m = (uint8_t)a;
		r->w = (uint8_t)b;
		r->d = (uint8_t)c;
		break;
	default:
		if (tz_num(p, 365, &a))
			return 1;
		r->type = TZR_JULIAN;
		r->n = (uint16_t)a;
		break;
	}

	if (**p == '/') {
		(*p)++;
		return tz_hms(p, TZ_MAX_HOURS, &r->time);
	}

	return 0;
}

static int
tz_parse(const char *p, tz_spec_t *z)
{
	memset(z, 0, sizeof(*z));

	if (tz_name(&p, z->std, sizeof(z->std)) ||
	    tz_hms(&p, 24, &z->std_west))
		return 1;

	if (!*p)
		return 0; /* no daylight saving time */

	if (tz_name(&p, z->dst, sizeof(z->dst)))
		return 1;
	z->has_dst = 1;

	z->dst_west = z->std_west - 3600; /* an hour ahead unless it says */
	if (*p && *p != ',' && tz_hms(&p, 24, &z->dst_west))
		return 1;

	if (!*p) {
		/* no rules: the US ones, as glibc */
		p = ",M3.2.0,M11.1.0";
	}

	if (*p++ != ',' || tz_rule(&p, &z->start) || *p++ != ',' ||
	    tz_rule(&p, &z->end))
		return 1;

	return !!*p;
}

/* when a rule happens in year y, as local seconds since 1970 */

static int64_t
tz_rule_local(const tz_rule_t *r, int y)
{
	int64_t day = days_from_civil(y, 1, 1);
	int first, last, d;

	switch (r->type) {
	case TZR_JULIAN_NOLEAP:
		/* Feb 29 doesn't count, so from Mar 1 it's a day later */
		day += r->n - 1 + (is_leap(y) && r->n >= 60);
		break;
	case TZR_JULIAN:
		day += r->n;
		break;
	default:
		day = days_from_civil(y, r->m, 1);
		/* the first weekday d of the month, then w - 1 weeks on */
		first = (int)((day + 4) % 7);
		d = 1 + ((r->d - first + 7) % 7) + ((r->w - 1) * 7);
		/* week 5 is the last, which may be week 4 */
		last = days_in_month(y, r->m);
		while (d > last)
			d -= 7;
		day += d - 1;
		break;
	}

	return (day * SECS_PER_DAY) + r->time;
}

int
lws_tz_at(const char *tz, int64_t utc, lws_tz_info_t *info)
{
	int64_t start, end;
	lws_civil_t c;
	tz_spec_t z;
	int dst = 0;

	if (!tz || tz_parse(tz, &z) ||
	    /* the year, as it is in standard time there */
	    lws_unix_to_civil(utc - z.std_west, &c))
		return 1;

	if (z.has_dst) {
		/*
		 * The start is given in standard time, and the end in daylight
		 * saving time.  In the south, it starts later in the year than
		 * it ends.
		 */
		start = tz_rule_local(&z.start, c.year) + z.std_west;
		end = tz_rule_local(&z.end, c.year) + z.dst_west;

		if (start < end)
			dst = utc >= start && utc < end;
		else
			dst = utc < end || utc >= start;
	}

	info->dst = (uint8_t)dst;
	info->utc_offset = -(dst ? z.dst_west : z.std_west);
	lws_strncpy(info->abbr, dst ? z.dst : z.std, sizeof(info->abbr));

	return 0;
}

int
lws_tz_local(const char *tz, int64_t utc, lws_civil_t *c, lws_tz_info_t *info)
{
	lws_tz_info_t i;

	if (lws_tz_at(tz, utc, &i) ||
	    lws_unix_to_civil(utc + i.utc_offset, c))
		return 1;

	if (info)
		*info = i;

	return 0;
}
