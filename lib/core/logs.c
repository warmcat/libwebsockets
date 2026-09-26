/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

lws_log_cx_t log_cx = {
#if !defined(LWS_PLAT_OPTEE)
	.u.emit				= lwsl_emit_stderr,
#else
	.u.emit				= lwsl_emit_optee,
#endif
	/*
	 * Default for code that logs before or without any lws_context,
	 * or that never calls lws_set_log_level(): USER is included so
	 * a tool's own output (eg, a test's FAIL lines) is not silently
	 * filtered
	 */
	.lll_flags			= LLL_ERR | LLL_WARN | LLL_NOTICE |
					  LLL_USER,
};

#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_NO_LOGS)
static const char * log_level_names ="EWNIDPHXCLUT??";
#endif

/*
 * Name an instance tag and attach to a group
 */

void
__lws_lc_tag(struct lws_context *context, lws_lifecycle_group_t *grp,
	     lws_lifecycle_t *lc, const char *format, ...)
{
	va_list ap;
	int n = 1;

	if (*lc->gutag == '[') {
		/* appending inside [] */

		char *cp = (char *)strchr(lc->gutag, ']');
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
	n += lws_snprintf(&lc->gutag[n], sizeof(lc->gutag) -
					 (unsigned int)n - 1u, "%u|", getpid());
#endif
	n += lws_snprintf(&lc->gutag[n], sizeof(lc->gutag) -
					 (unsigned int)n - 1u, "%s|%lx|",
					 grp->tag_prefix,
					 (unsigned long)grp->ordinal++);

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

	lwsl_refcount_cx(lc->log_cx, 1);

#if defined(LWS_LOG_TAG_LIFECYCLE)
	lwsl_cx_info(context, " ++ %s (%d)", lc->gutag, (int)lws_dll2_count(&grp->owner));
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

	if (!lc->recycle_len)
		lc->recycle_len = (uint8_t)n;
	else
		n = lc->recycle_len;

	if ((unsigned int)n + 2u >= sizeof(lc->gutag)) {
		/*
		 * No room to append anything... sizeof(gutag) - 2 - n would
		 * underflow to a huge size_t and lws_snprintf() only rejects
		 * size 0.  Just make sure the tag is closed and terminated.
		 */
		lc->gutag[sizeof(lc->gutag) - 2] = ']';
		lc->gutag[sizeof(lc->gutag) - 1] = '\0';

		return;
	}

	n += lws_snprintf(&lc->gutag[n], sizeof(lc->gutag) - 2u -
					 (unsigned int)n, "|%s]", app);

	if ((unsigned int)n >= sizeof(lc->gutag) - 2u) {
		lc->gutag[sizeof(lc->gutag) - 2] = ']';
		lc->gutag[sizeof(lc->gutag) - 1] = '\0';
	}
}

/*
 * Remove instance from group
 */

void
__lws_lc_untag(struct lws_context *context, lws_lifecycle_t *lc)
{
	//lws_lifecycle_group_t *grp;
	char buf[24];

	if (!lc->gutag[0]) { /* we never tagged this object... */
		lwsl_cx_err(context, "%s never tagged", lc->gutag);
		assert(0);
		return;
	}

	if (!lws_dll2_owner(&lc->list)) { /* we already untagged this object... */
		lwsl_cx_err(context, "%s untagged twice", lc->gutag);
		assert(0);
		return;
	}

	//grp = lws_container_of(lc->list.owner, lws_lifecycle_group_t, owner);

#if defined(LWS_LOG_TAG_LIFECYCLE)
	if (lws_humanize(buf, sizeof(buf),
		     (uint64_t)lws_now_usecs() - lc->us_creation,
		     humanize_schema_us) > 0)

	lwsl_cx_info(context, " -- %s (%d) %s", lc->gutag,
		    (int)lws_dll2_count(lws_dll2_owner(&lc->list)) - 1, buf);
#endif

	lws_dll2_remove(&lc->list);

	lwsl_refcount_cx(lc->log_cx, -1);
}

const char *
lws_lc_tag(lws_lifecycle_t *lc)
{
	return lc->gutag;
}


int
lwsl_timestamp(int level, char *p, size_t len)
{
#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_NO_LOGS)
	time_t o_now;
	unsigned long long now;
	struct timeval tv;
	struct tm *ptm = NULL;
#if defined(LWS_HAVE_LOCALTIME_R)
	struct tm tm;
#endif
	int n;

	gettimeofday(&tv, NULL);
	o_now = tv.tv_sec;
	now = ((unsigned long long)tv.tv_sec * 10000) +
				(unsigned int)(tv.tv_usec / 100);

#if defined(LWS_HAVE_LOCALTIME_R)
	ptm = localtime_r(&o_now, &tm);
#else
	ptm = localtime(&o_now);
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

#if defined(LWS_PLAT_FREERTOS)
		n += lws_snprintf(p + n, len - n, "%6u: ",
#if defined(LWS_AMAZON_RTOS)
				  (unsigned int)xPortGetFreeHeapSize());
#else
				  (unsigned int)esp_get_free_heap_size());
#endif
#endif

		return n;
	}
#else
	p[0] = '\0';
#endif

	return 0;
}

uint32_t
lws_log_ratelimit_check(lws_log_ratelimit_t *rl, int64_t interval_us)
{
	lws_usec_t now = lws_now_usecs();

	if (now >= rl->next_log_us) {
		uint32_t r = rl->dropped + 1;
		rl->next_log_us = now + interval_us;
		rl->dropped = 0;
		return r;
	}

	rl->dropped++;

	return 0;
}


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
_lwsl_emit_stderr(int level, const char *line)
{
	int n, m = LWS_ARRAY_SIZE(colours) - 1;

	if (!tty)
		tty = (char)(isatty(2) | 2);

	if (tty == 3) {
		n = 1 << (LWS_ARRAY_SIZE(colours) - 1);
		while (n) {
			if (level & n)
				break;
			m--;
			n >>= 1;
		}
		fprintf(stderr, "%c%s%s%c[0m", 27, colours[m], line, 27);
	} else
		fprintf(stderr, "%s", line);
}

void
lwsl_emit_stderr(int level, const char *line)
{
	_lwsl_emit_stderr(level, line);
}

void
lwsl_emit_stderr_notimestamp(int level, const char *line)
{
	_lwsl_emit_stderr(level, line);
}

#if !defined(LWS_PLAT_FREERTOS) && !defined(LWS_PLAT_OPTEE) && !defined(LWS_PLAT_BAREMETAL)

/*
 * Helper to emit to a file
 */

void
lws_log_emit_cx_file(struct lws_log_cx *cx, int level, const char *line,
			size_t len)
{
	int fd = (int)(intptr_t)cx->stg;

	if (fd >= 0)
		if (write(fd, line, (unsigned int)len) != (ssize_t)len)
			fprintf(stderr, "Unable to write log to file\n");
}

/*
 * Helper to use a .refcount_cb to store logs in a file
 */

void
lws_log_use_cx_file(struct lws_log_cx *cx, int _new)
{
	int fd;

	if (_new > 0 && cx->refcount == 1) {
		fd = open((const char *)cx->opaque,
				LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);
		if (fd < 0)
			fprintf(stderr, "Unable to open log %s: errno %d\n",
				(const char *)cx->opaque, errno);
		cx->stg = (void *)(intptr_t)fd;

		return;
	}

	fd = (int)(intptr_t)cx->stg;

	if (_new <= 0 && cx->refcount == 0 && fd >= 0) {
		close(fd);
		cx->stg = (void *)(intptr_t)-1;
	}
}

#endif

#endif

#if !(defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_NETWORK))

#if LWS_MAX_SMP == 1 && !defined(LWS_WITH_THREADPOOL)
#define LWS_LOG_LINE_MAX	256
#else
#define LWS_LOG_LINE_MAX	1024
#endif

/*
 * The dupe and spew state below is processwide.  When there may be more than
 * one thread logging, it is guarded by a lock that is never held across a
 * call into the emit function, so an emit that itself logs cannot deadlock.
 */

#if (LWS_MAX_SMP > 1 || defined(LWS_WITH_THREADPOOL)) && \
    defined(LWS_HAVE_PTHREAD_H)
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
#define log_lock_take()		pthread_mutex_lock(&log_lock)
#define log_lock_release()	pthread_mutex_unlock(&log_lock)
#else
#define log_lock_take()
#define log_lock_release()
#endif

/*
 * Log spew handling
 *
 * A "spew" is a sustained rate of log emission that nothing downstream can
 * usefully absorb: a tight loop logging every service call, a POLLOUT storm,
 * a state machine ping-ponging.  Left alone it fills the disk, or in a test
 * harness, the RAM the logs were being captured in, within seconds.
 *
 * Back-to-back identical lines are already collapsed by the dupe detection
 * in __lws_logv().  This catches the general case where the lines differ.
 *
 * We keep a small ring of the timestamps of the last LWS_LOG_SPEW_TS_RING
 * lines that got as far as emission.  When the whole ring spans less than
 * LWS_LOG_SPEW_ENTER_US, ie, the sustained rate has exceeded
 * LWS_LOG_SPEW_TS_RING / LWS_LOG_SPEW_ENTER_US, we enter spew mode: we
 * allocate a heap ringbuffer of LWS_LOG_SPEW_RING_SIZE bytes and divert the
 * formatted lines into that instead of emitting them, so we retain the most
 * recent tail of the spew and nothing else.  A heartbeat line goes out once
 * a second so the log shows the process is alive and how much was swallowed.
 *
 * Leaving spew mode is decided over a much shorter window than entering it,
 * since a spew typically never pauses at all: once the last
 * LWS_LOG_SPEW_EXIT_SAMPLES lines span more than LWS_LOG_SPEW_EXIT_US, the
 * rate has fallen below half the entry rate, and we replay the retained tail
 * in order, free the ringbuffer and go back to emitting directly.  The
 * timestamp ring is restarted, so a full LWS_LOG_SPEW_TS_RING lines at spew
 * rate are needed before we would enter again; that stops a bursty spew
 * flapping in and out of the mode and replaying its tail each time.
 *
 * A legitimate surge of logs, eg, context creation at debug level, may be
 * fast enough to trip entry.  That costs nothing: as long as the surge
 * totals less than LWS_LOG_SPEW_RING_SIZE bytes, every line is retained and
 * replayed intact when the surge ends.  The ring size is effectively the
 * size of surge we wave through losslessly; the entry rate only decides when
 * we start paying attention.
 *
 * The exit check can only run when a log arrives.  If a spew stops dead and
 * nothing logs afterwards, the retained tail is replayed by the next log
 * whenever it comes, or by lws_context_destroy().  If the process dies
 * during a spew, the retained tail dies with it; that is the price of not
 * having written it out.
 *
 * The tunables can be overridden from the compiler command line.  A log
 * context with LLLF_LOG_SPEW_OFF in its flags bypasses all of this.
 */

#if !defined(LWS_LOG_SPEW_TS_RING)
#define LWS_LOG_SPEW_TS_RING		64
#endif
#if !defined(LWS_LOG_SPEW_ENTER_US)
#define LWS_LOG_SPEW_ENTER_US		20000
#endif
#if !defined(LWS_LOG_SPEW_EXIT_SAMPLES)
#define LWS_LOG_SPEW_EXIT_SAMPLES	8
#endif
#if !defined(LWS_LOG_SPEW_EXIT_US)
#define LWS_LOG_SPEW_EXIT_US		5000
#endif
#if !defined(LWS_LOG_SPEW_RING_SIZE)
#if defined(LWS_PLAT_FREERTOS) || defined(LWS_PLAT_BAREMETAL)
#define LWS_LOG_SPEW_RING_SIZE		2048
#else
#define LWS_LOG_SPEW_RING_SIZE		16384
#endif
#endif
#if !defined(LWS_LOG_SPEW_HEARTBEAT_US)
#define LWS_LOG_SPEW_HEARTBEAT_US	1000000
#endif

/* each retained line is [len lo][len hi][level lo][level hi][len bytes] */
#define SPEW_HDR			4

typedef struct lws_log_spew_ring {
	uint8_t		*buf;		/* NULL: not in spew mode */
	size_t		head;		/* next byte to write */
	size_t		tail;		/* oldest byte retained */
	size_t		used;
	lws_usec_t	entered;
	uint32_t	swallowed;	/* lines diverted into the ring */
	uint32_t	lost;		/* of those, pushed out again */
} lws_log_spew_ring_t;

typedef struct lws_log_spew {
	lws_usec_t		ts[LWS_LOG_SPEW_TS_RING];
	lws_log_spew_ring_t	r;
	lws_usec_t		last_heartbeat;
	unsigned int		ts_head;	/* next slot to write */
	unsigned int		ts_count;	/* valid slots */
} lws_log_spew_t;

static lws_log_spew_t spew;
static char spew_entering; /* setting the ring up: no re-entry */

enum {
	SPEW_EMIT,	/* not in spew mode, emit normally */
	SPEW_ENTERED,	/* this line entered spew mode and was retained */
	SPEW_SWALLOWED,	/* retained, say nothing */
	SPEW_HEARTBEAT,	/* retained, but it is time to show signs of life */
	SPEW_EXITED	/* spew eased: replay the ring, then emit normally */
};

/* timestamp of the line k lines before the most recent one */

static lws_usec_t
spew_ts_ago(unsigned int k)
{
	return spew.ts[(spew.ts_head + LWS_LOG_SPEW_TS_RING - 1 - k) %
		       LWS_LOG_SPEW_TS_RING];
}

static void
spew_ring_write(lws_log_spew_ring_t *r, const uint8_t *p, size_t len)
{
	size_t n = LWS_LOG_SPEW_RING_SIZE - r->head;

	if (n > len)
		n = len;
	memcpy(r->buf + r->head, p, n);
	if (len - n)
		memcpy(r->buf, p + n, len - n);
	r->head = (r->head + len) % LWS_LOG_SPEW_RING_SIZE;
	r->used += len;
}

static void
spew_ring_read(lws_log_spew_ring_t *r, uint8_t *p, size_t len)
{
	size_t n = LWS_LOG_SPEW_RING_SIZE - r->tail;

	if (n > len)
		n = len;
	memcpy(p, r->buf + r->tail, n);
	if (len - n)
		memcpy(p + n, r->buf, len - n);
	r->tail = (r->tail + len) % LWS_LOG_SPEW_RING_SIZE;
	r->used -= len;
}

/* take the oldest retained line out of the ring, 0 if nothing retained */

static size_t
spew_ring_pop(lws_log_spew_ring_t *r, char *line, size_t max, int *level)
{
	uint8_t hdr[SPEW_HDR];
	size_t len;

	if (!r->used)
		return 0;

	spew_ring_read(r, hdr, SPEW_HDR);
	len = (size_t)hdr[0] | ((size_t)hdr[1] << 8);
	*level = hdr[2] | (hdr[3] << 8);

	if (!line) {
		/* discard it */
		r->tail = (r->tail + len) % LWS_LOG_SPEW_RING_SIZE;
		r->used -= len;

		return len;
	}

	assert(len < max);
	spew_ring_read(r, (uint8_t *)line, len);
	line[len] = '\0';

	return len;
}

static void
spew_ring_push(lws_log_spew_ring_t *r, int level, const char *line, size_t len)
{
	uint8_t hdr[SPEW_HDR];
	int lv;

	if (len + SPEW_HDR > LWS_LOG_SPEW_RING_SIZE)
		/* a ring smaller than a line: keep the start of the line */
		len = LWS_LOG_SPEW_RING_SIZE - SPEW_HDR;

	/* make room by forgetting the oldest lines */

	while (LWS_LOG_SPEW_RING_SIZE - r->used < len + SPEW_HDR) {
		spew_ring_pop(r, NULL, 0, &lv);
		r->lost++;
	}

	hdr[0] = (uint8_t)(len & 0xff);
	hdr[1] = (uint8_t)(len >> 8);
	hdr[2] = (uint8_t)(level & 0xff);
	hdr[3] = (uint8_t)((level >> 8) & 0xff);
	spew_ring_write(r, hdr, SPEW_HDR);
	spew_ring_write(r, (const uint8_t *)line, len);
	r->swallowed++;
}

/*
 * Account for a line that is about to be emitted and decide its fate.
 *
 * Called with the log lock held.  If we leave spew mode, ownership of the ring
 * is handed out via *replay so the caller can replay and free it without the
 * lock, and the caller sees an empty ring here from then on.
 */

static int
spew_track(lws_usec_t now, int level, const char *line, size_t len,
	   lws_log_spew_ring_t *replay)
{
	spew.ts[spew.ts_head] = now;
	spew.ts_head = (spew.ts_head + 1) % LWS_LOG_SPEW_TS_RING;
	if (spew.ts_count < LWS_LOG_SPEW_TS_RING)
		spew.ts_count++;

	if (!spew.r.buf) {
		if (spew.ts_count < LWS_LOG_SPEW_TS_RING ||
		    now - spew_ts_ago(LWS_LOG_SPEW_TS_RING - 1) >=
						LWS_LOG_SPEW_ENTER_US)
			return SPEW_EMIT;

		/*
		 * The ring comes from the libc allocator, not lws_malloc():
		 * the lws allocator logs its allocations at debug level, and
		 * that log re-entered here while the ring was being set up,
		 * so an inner call allocated and filled one ring and the
		 * outer then installed a different buffer under the inner's
		 * counters (and with a non-recursive log lock it would have
		 * deadlocked).  The guard below refuses re-entry outright.
		 */
		if (spew_entering)
			return SPEW_EMIT;
		spew_entering = 1;
		memset(&spew.r, 0, sizeof(spew.r));
		spew.r.buf = malloc(LWS_LOG_SPEW_RING_SIZE);
		spew_entering = 0;
		if (!spew.r.buf)
			/* no memory to retain anything: keep emitting */
			return SPEW_EMIT;

		spew.r.entered = now;
		spew.last_heartbeat = now;
		spew_ring_push(&spew.r, level, line, len);

		return SPEW_ENTERED;
	}

	if (spew.ts_count > LWS_LOG_SPEW_EXIT_SAMPLES &&
	    now - spew_ts_ago(LWS_LOG_SPEW_EXIT_SAMPLES) >
						LWS_LOG_SPEW_EXIT_US) {
		*replay = spew.r;
		memset(&spew.r, 0, sizeof(spew.r));
		/* a fresh run at spew rate is needed to enter again */
		spew.ts_head = 0;
		spew.ts_count = 0;

		return SPEW_EXITED;
	}

	spew_ring_push(&spew.r, level, line, len);

	if (now - spew.last_heartbeat >= LWS_LOG_SPEW_HEARTBEAT_US) {
		spew.last_heartbeat = now;
		*replay = spew.r;

		return SPEW_HEARTBEAT;
	}

	return SPEW_SWALLOWED;
}

static void
log_emit(lws_log_cx_t *cx, int level, const char *line, size_t len)
{
	if (cx->lll_flags & LLLF_LOG_CONTEXT_AWARE)
		cx->u.emit_cx(cx, level, line, len);
	else
		cx->u.emit(level, line);
}

/* emit a line of our own about the spew, in the style of the cx */

static void
spew_emit(lws_log_cx_t *cx, int level, const char *format, ...)
{
	char b[160], *p = b, *end = b + sizeof(b) - 2;
	va_list ap;
	int n;

	b[0] = '\0';
#if !defined(LWS_LOGS_TIMESTAMP)
	if (cx->lll_flags & LLLF_LOG_TIMESTAMP)
#endif
	{
		lwsl_timestamp(level, b, sizeof(b));
		p += strlen(b);
	}

	va_start(ap, format);
	n = vsnprintf(p, lws_ptr_diff_size_t(end, p), format, ap);
	va_end(ap);
	if (n < 0)
		n = 0;
	p += n;
	if (p > end)
		p = end;
	*p++ = '\n';
	*p = '\0';

	log_emit(cx, level, b, lws_ptr_diff_size_t(p, b));
}

/* replay the retained tail of a spew in order, then free the ring */

static void
spew_replay(lws_log_cx_t *cx, int level, lws_log_spew_ring_t *r,
	    lws_usec_t now)
{
	char line[LWS_LOG_LINE_MAX + 1];
	size_t len;
	int lv;

	spew_emit(cx, level, "lws: log spew eased: swallowed %u logs over %ums,"
			     " %u oldest not retained, last %u replayed:",
		  (unsigned int)r->swallowed,
		  (unsigned int)((now - r->entered) / 1000),
		  (unsigned int)r->lost,
		  (unsigned int)(r->swallowed - r->lost));

	while ((len = spew_ring_pop(r, line, sizeof(line), &lv)))
		log_emit(cx, lv, line, len);

	spew_emit(cx, level, "lws: log spew: end of replay");

	free(r->buf); /* libc's: see spew_track() */
	r->buf = NULL;
}

/*
 * If a spew was in progress, replay and free what it retained now, rather than
 * waiting for a log that may never come.  Called from lws_context_destroy().
 */

void
lws_log_spew_flush(lws_log_cx_t *cx)
{
	lws_log_spew_ring_t r;

	if (!cx)
		cx = &log_cx;

	log_lock_take();
	r = spew.r;
	memset(&spew.r, 0, sizeof(spew.r));
	spew.ts_head = 0;
	spew.ts_count = 0;
	log_lock_release();

	if (r.buf)
		spew_replay(cx, LLL_NOTICE, &r, lws_now_usecs());
}

void
__lws_logv(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
	   int filter, uint32_t dropped, const char *_fun, const char *format, va_list vl)
{
#if LWS_MAX_SMP == 1 && !defined(LWS_WITH_THREADPOOL)
	/* this is incompatible with multithreaded logging */
	static char buf[LWS_LOG_LINE_MAX];
#else
	char buf[LWS_LOG_LINE_MAX];
#endif
	static char prev_buf[LWS_LOG_LINE_MAX];
	static uint32_t log_dupes;
	static lws_usec_t last_log_dupe_emit;
	char *p = buf, *end = p + sizeof(buf) - 1, *body_start;
	lws_log_spew_ring_t replay;
	lws_log_cx_t *cxp;
	int n, back = 0, act = SPEW_EMIT;
	lws_usec_t now;

	/*
	 * We need to handle NULL wsi etc at the wrappers as gracefully as
	 * possible
	 */

	if (!cx) {
		lws_strncpy(p, "NULL log cx: ", sizeof(buf) - 1);
		p += 13;
		/* use the processwide one for lack of anything better */
		cx = &log_cx;
	}

	cxp = cx;

	if (!(cx->lll_flags & (uint32_t)filter))
		/*
		 * logs may be produced and built in to the code but disabled
		 * at runtime
		 */
		return;

#if !defined(LWS_LOGS_TIMESTAMP)
	if (cx->lll_flags & LLLF_LOG_TIMESTAMP)
#endif
	{
		buf[0] = '\0';
		lwsl_timestamp(filter, buf, sizeof(buf));
		p += strlen(buf);
	}

	body_start = p;

	/*
	 * prepend parent log ctx content first
	 * top level cx also gets an opportunity to prepend
	 */

	while (cxp->parent) {
		cxp = cxp->parent;
		back++;
	}

	do {
		int b = back;

		cxp = cx;
		while (b--)
			cxp = cxp->parent;
		if (cxp->prepend)
			cxp->prepend(cxp, NULL, &p, end);

		back--;
	} while (back > 0);

	if (prep)
		prep(cxp, obj, &p, end);

	if (_fun)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s: ", _fun);

	/*
	 * The actual log content
	 */

	n = vsnprintf(p, lws_ptr_diff_size_t(end, p), format, vl);

	/* vnsprintf returns what it would have written, even if truncated */
	if (p + n > end - 2) {
		p = end - 5;
		*p++ = '.';
		*p++ = '.';
		*p++ = '.';
		*p++ = '\n';
		*p++ = '\0';
	} else {
		if (n > 0) {
			p += n;
			if (p[-1] == '\n')
				p--;
			if (dropped > 1)
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), " (dropped %u logs)", (unsigned int)(dropped - 1));
			if (p < end - 1) {
				*p++ = '\n';
				*p = '\0';
			}
		}
	}

	now = lws_now_usecs();

	log_lock_take();

	if (!strcmp(body_start, prev_buf)) {
		log_dupes++;
		if (now - last_log_dupe_emit < 1000000) {
			log_lock_release();
			return;
		}

		p = body_start + strlen(body_start);
		if (p > buf && p[-1] == '\n')
			p--;
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  " (swallowed %u dupes)\n", (unsigned int)log_dupes);
		log_dupes = 0;
		last_log_dupe_emit = now;
	} else {
		lws_strncpy(prev_buf, body_start, sizeof(prev_buf));
		log_dupes = 0;
		last_log_dupe_emit = now;
	}

	if (!(cx->lll_flags & LLLF_LOG_SPEW_OFF))
		act = spew_track(now, filter, buf, lws_ptr_diff_size_t(p, buf),
				 &replay);

	log_lock_release();

	switch (act) {
	case SPEW_ENTERED:
		spew_emit(cx, filter, "lws: log spew: %u logs in %ums, retaining"
				      " the last %u bytes of it until it eases",
			  LWS_LOG_SPEW_TS_RING, LWS_LOG_SPEW_ENTER_US / 1000,
			  LWS_LOG_SPEW_RING_SIZE);
		return;

	case SPEW_SWALLOWED:
		return;

	case SPEW_HEARTBEAT:
		spew_emit(cx, filter, "lws: log spew: still going, %u logs"
				      " swallowed over %us",
			  (unsigned int)replay.swallowed,
			  (unsigned int)((now - replay.entered) / 1000000));
		return;

	case SPEW_EXITED:
		spew_replay(cx, filter, &replay, now);
		break;

	default:
		break;
	}

	/*
	 * The actual emit
	 */

	log_emit(cx, filter, buf, lws_ptr_diff_size_t(p, buf));
}

void _lws_logv(int filter, const char *format, va_list vl)
{
	__lws_logv(&log_cx, NULL, NULL, filter, 0, NULL, format, vl);
}

void _lws_log(int filter, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	__lws_logv(&log_cx, NULL, NULL, filter, 0, NULL, format, ap);
	va_end(ap);
}

void _lws_log_rl(int filter, uint32_t dropped, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	__lws_logv(&log_cx, NULL, NULL, filter, dropped, NULL, format, ap);
	va_end(ap);
}

void _lws_log_cx(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
		 int filter, const char *_fun, const char *format, ...)
{
	va_list ap;

	if (!cx)
		cx = &log_cx;

	va_start(ap, format);
	__lws_logv(cx, prep, obj, filter, 0, _fun, format, ap);
	va_end(ap);
}

void _lws_log_cx_rl(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
		 int filter, uint32_t dropped, const char *_fun, const char *format, ...)
{
	va_list ap;

	if (!cx)
		cx = &log_cx;

	va_start(ap, format);
	__lws_logv(cx, prep, obj, filter, dropped, _fun, format, ap);
	va_end(ap);
}
#endif

void
lws_set_log_level(int flags, lws_log_emit_t func)
{
	log_cx.lll_flags = (uint32_t)(flags & (~LLLF_LOG_CONTEXT_AWARE));

	if (func)
		log_cx.u.emit = func;
}

int lwsl_visible(int level)
{
	return !!(log_cx.lll_flags & (uint32_t)level);
}

int lwsl_visible_cx(lws_log_cx_t *cx, int level)
{
	return !!(cx->lll_flags & (uint32_t)level);
}

void
lwsl_refcount_cx(lws_log_cx_t *cx, int _new)
{
#if LWS_MAX_SMP > 1
	volatile lws_log_cx_t *vcx = (volatile lws_log_cx_t *)cx;
#endif

	if (!cx)
		return;

#if LWS_MAX_SMP > 1
	if (!vcx->inited) {
		vcx->inited = 1;
		lws_pthread_mutex_init(&cx->refcount_lock);
		vcx->inited = 2;
	}
	while (vcx->inited != 2)
		;
	lws_pthread_mutex_lock(&cx->refcount_lock);
#endif

	if (_new > 0)
		cx->refcount++;
	else {
		assert(cx->refcount);
		cx->refcount--;
	}

	if (cx->refcount_cb)
		cx->refcount_cb(cx, _new);

#if LWS_MAX_SMP > 1
	lws_pthread_mutex_unlock(&cx->refcount_lock);
#endif
}

void
lwsl_hexdump_level_cx(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
		      int hexdump_level, const void *vbuf, size_t len)
{
	unsigned char *buf = (unsigned char *)vbuf;
	unsigned int n;

	if (!lwsl_visible_cx(cx, hexdump_level))
		return;

	if (!len) {
		_lws_log_cx(cx, prep, obj, hexdump_level, NULL,
					"(hexdump: zero length)\n");
		return;
	}

	if (!vbuf) {
		_lws_log_cx(cx, prep, obj, hexdump_level, NULL,
					"(hexdump: NULL ptr)\n");
		return;
	}

	_lws_log_cx(cx, prep, obj, hexdump_level, NULL, "\n");

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
		_lws_log_cx(cx, prep, obj, hexdump_level, NULL, "%s", line);
		(void)line;
	}

	_lws_log_cx(cx, prep, obj, hexdump_level, NULL, "\n");
}

void
lwsl_hexdump_level(int hexdump_level, const void *vbuf, size_t len)
{
	lwsl_hexdump_level_cx(&log_cx, NULL, NULL, hexdump_level, vbuf, len);
}

void
lwsl_hexdump(const void *vbuf, size_t len)
{
#if defined(_DEBUG)
	lwsl_hexdump_level(LLL_DEBUG, vbuf, len);
#endif
}
