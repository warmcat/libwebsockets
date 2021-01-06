/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"

#ifdef LWS_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if defined(LWS_PLAT_OPTEE)
void lwsl_emit_optee(int level, const char *line);
#endif

int log_level = LLL_ERR | LLL_WARN | LLL_NOTICE;
static void (*lwsl_emit)(int level, const char *line)
#ifndef LWS_PLAT_OPTEE
	= lwsl_emit_stderr
#else
	= lwsl_emit_optee;
#endif
	;
#ifndef LWS_PLAT_OPTEE
static const char * log_level_names ="EWNIDPHXCLUT??";
#endif

/*
 * Name an instance tag and attach to a group
 */

void
__lws_lc_tag(lws_lifecycle_group_t *grp, lws_lifecycle_t *lc,
	     const char *format, ...)
{
	va_list ap;
	int n = 1;

	if (*lc->gutag == '[') {
		/* appending inside [] */

		char *cp = strchr(lc->gutag, ']');
		char rend[96];
		size_t ll, k;
		int n;

		if (!cp)
			return;

		/* length of closing brace and anything else after it */
		k = strlen(cp);

		/* compute the remaining gutag unused */
		ll = sizeof(lc->gutag) - lws_ptr_diff_size_t(cp, lc->gutag) - k - 1;
		if (ll > sizeof(rend) - 1)
			ll = sizeof(rend) - 1;
		va_start(ap, format);
		n = vsnprintf(rend, ll, format, ap);
		va_end(ap);

		if ((unsigned int)n > ll)
			n = (int)ll;

		/* shove the trailer up by what we added */
		memmove(cp + n, cp, k);
		assert(k + (unsigned int)n < sizeof(lc->gutag));
		cp[k + (unsigned int)n] = '\0';
		/* copy what we added into place */
		memcpy(cp, rend, (unsigned int)n);

		return;
	}

	assert(grp);
	assert(grp->tag_prefix); /* lc group must have a tag prefix string */

	lc->gutag[0] = '[';

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API) /* ie, will have getpid if set */
	n += lws_snprintf(&lc->gutag[n], sizeof(lc->gutag) - (unsigned int)n - 1u,
			"%u|", getpid());
#endif
	n += lws_snprintf(&lc->gutag[n], sizeof(lc->gutag) - (unsigned int)n - 1u,
			"%s|%lx|", grp->tag_prefix, (unsigned long)grp->ordinal++);

	va_start(ap, format);
	n += vsnprintf(&lc->gutag[n], sizeof(lc->gutag) - (unsigned int)n -
			1u, format, ap);
	va_end(ap);

	if (n < (int)sizeof(lc->gutag) - 2) {
		lc->gutag[n++] = ']';
		lc->gutag[n++] = '\0';
	} else {
		lc->gutag[sizeof(lc->gutag) - 2] = ']';
		lc->gutag[sizeof(lc->gutag) - 1] = '\0';
	}

	lc->us_creation = (uint64_t)lws_now_usecs();
	lws_dll2_add_tail(&lc->list, &grp->owner);

#if defined(LWS_LOG_TAG_LIFECYCLE)
	lwsl_notice(" ++ %s (%d)\n", lc->gutag, (int)grp->owner.count);
#endif
}

/*
 * Normally we want to set the tag one time at creation.  But sometimes we
 * don't have enough information at that point to give it a meaningful tag, eg,
 * it's an accepted, served connection but we haven't read data from it yet
 * to find out what it wants to be.
 *
 * This allows you to append some extra info to the tag in those cases, the
 * initial tag remains the same on the lhs so it can be tracked correctly.
 */

void
__lws_lc_tag_append(lws_lifecycle_t *lc, const char *app)
{
	int n = (int)strlen(lc->gutag);

	if (n && lc->gutag[n - 1] == ']')
		n--;

	n += lws_snprintf(&lc->gutag[n], sizeof(lc->gutag) - 2u - (unsigned int)n,
			"|%s]", app);

	if ((unsigned int)n >= sizeof(lc->gutag) - 2u) {
		lc->gutag[sizeof(lc->gutag) - 2] = ']';
		lc->gutag[sizeof(lc->gutag) - 1] = '\0';
	}
}

/*
 * Remove instance from group
 */

void
__lws_lc_untag(lws_lifecycle_t *lc)
{
	//lws_lifecycle_group_t *grp;
	char buf[24];

	if (!lc->gutag[0]) { /* we never tagged this object... */
		lwsl_err("%s: %s never tagged\n", __func__, lc->gutag);
		assert(0);
		return;
	}

	if (!lc->list.owner) { /* we already untagged this object... */
		lwsl_err("%s: %s untagged twice\n", __func__, lc->gutag);
		assert(0);
		return;
	}

	//grp = lws_container_of(lc->list.owner, lws_lifecycle_group_t, owner);

	lws_humanize(buf, sizeof(buf), (uint64_t)lws_now_usecs() - lc->us_creation,
			humanize_schema_us);

#if defined(LWS_LOG_TAG_LIFECYCLE)
	lwsl_notice(" -- %s (%d) %s\n", lc->gutag, (int)lc->list.owner->count - 1, buf);
#endif

	lws_dll2_remove(&lc->list);
}

const char *
lws_lc_tag(lws_lifecycle_t *lc)
{
	return lc->gutag;
}


#if defined(LWS_LOGS_TIMESTAMP)
int
lwsl_timestamp(int level, char *p, size_t len)
{
#ifndef LWS_PLAT_OPTEE
	time_t o_now;
	unsigned long long now;
	struct timeval tv;
	struct tm *ptm = NULL;
#ifndef WIN32
	struct tm tm;
#endif
	int n;

	gettimeofday(&tv, NULL);
	o_now = tv.tv_sec;
	now = ((unsigned long long)tv.tv_sec * 10000) + (unsigned int)(tv.tv_usec / 100);

#ifndef _WIN32_WCE
#ifdef WIN32
	ptm = localtime(&o_now);
#else
	if (localtime_r(&o_now, &tm))
		ptm = &tm;
#endif
#endif
	p[0] = '\0';
	for (n = 0; n < LLL_COUNT; n++) {
		if (level != (1 << n))
			continue;

		if (ptm)
			n = lws_snprintf(p, len,
				"[%04d/%02d/%02d %02d:%02d:%02d:%04d] %c: ",
				ptm->tm_year + 1900,
				ptm->tm_mon + 1,
				ptm->tm_mday,
				ptm->tm_hour,
				ptm->tm_min,
				ptm->tm_sec,
				(int)(now % 10000), log_level_names[n]);
		else
			n = lws_snprintf(p, len, "[%llu:%04d] %c: ",
					(unsigned long long) now / 10000,
					(int)(now % 10000), log_level_names[n]);
		return n;
	}
#else
	p[0] = '\0';
#endif

	return 0;
}
#endif

#ifndef LWS_PLAT_OPTEE
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

static char tty;

static void
_lwsl_emit_stderr(int level, const char *line, int ts)
{
	char buf[50];
	int n, m = LWS_ARRAY_SIZE(colours) - 1;

	if (!tty)
		tty = (char)(isatty(2) | 2);

	buf[0] = '\0';
#if defined(LWS_LOGS_TIMESTAMP)
	if (ts)
		lwsl_timestamp(level, buf, sizeof(buf));
#endif

	if (tty == 3) {
		n = 1 << (LWS_ARRAY_SIZE(colours) - 1);
		while (n) {
			if (level & n)
				break;
			m--;
			n >>= 1;
		}
		fprintf(stderr, "%c%s%s%s%c[0m", 27, colours[m], buf, line, 27);
	} else
		fprintf(stderr, "%s%s", buf, line);
}

void
lwsl_emit_stderr(int level, const char *line)
{
	_lwsl_emit_stderr(level, line, 1);
}

void
lwsl_emit_stderr_notimestamp(int level, const char *line)
{
	_lwsl_emit_stderr(level, line, 0);
}

#endif

#if !(defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_NETWORK))
void _lws_logv(int filter, const char *format, va_list vl)
{
#if LWS_MAX_SMP == 1 && !defined(LWS_WITH_THREADPOOL)
	/* this is incompatible with multithreaded logging */
	static char buf[256];
#else
	char buf[1024];
#endif
	int n;

	if (!(log_level & filter))
		return;

	n = vsnprintf(buf, sizeof(buf) - 1, format, vl);
	(void)n;
	/* vnsprintf returns what it would have written, even if truncated */
	if (n > (int)sizeof(buf) - 1) {
		n = sizeof(buf) - 5;
		buf[n++] = '.';
		buf[n++] = '.';
		buf[n++] = '.';
		buf[n++] = '\n';
		buf[n] = '\0';
	}
	if (n > 0)
		buf[n] = '\0';
	lwsl_emit(filter, buf);
}

void _lws_log(int filter, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	_lws_logv(filter, format, ap);
	va_end(ap);
}
#endif
void lws_set_log_level(int level, void (*func)(int level, const char *line))
{
	log_level = level;
	if (func)
		lwsl_emit = func;
}

int lwsl_visible(int level)
{
	return log_level & level;
}

void
lwsl_hexdump_level(int hexdump_level, const void *vbuf, size_t len)
{
	unsigned char *buf = (unsigned char *)vbuf;
	unsigned int n;

	if (!lwsl_visible(hexdump_level))
		return;

	if (!len) {
		_lws_log(hexdump_level, "(hexdump: zero length)\n");
		return;
	}

	if (!vbuf) {
		_lws_log(hexdump_level, "(hexdump: NULL ptr)\n");
		return;
	}

	_lws_log(hexdump_level, "\n");

	for (n = 0; n < len;) {
		unsigned int start = n, m;
		char line[80], *p = line;

		p += lws_snprintf(p, 10, "%04X: ", start);

		for (m = 0; m < 16 && n < len; m++)
			p += lws_snprintf(p, 5, "%02X ", buf[n++]);
		while (m++ < 16)
			p += lws_snprintf(p, 5, "   ");

		p += lws_snprintf(p, 6, "   ");

		for (m = 0; m < 16 && (start + m) < len; m++) {
			if (buf[start + m] >= ' ' && buf[start + m] < 127)
				*p++ = (char)buf[start + m];
			else
				*p++ = '.';
		}
		while (m++ < 16)
			*p++ = ' ';

		*p++ = '\n';
		*p = '\0';
		_lws_log(hexdump_level, "%s", line);
		(void)line;
	}

	_lws_log(hexdump_level, "\n");
}

void
lwsl_hexdump(const void *vbuf, size_t len)
{
#if defined(_DEBUG)
	lwsl_hexdump_level(LLL_DEBUG, vbuf, len);
#endif
}
