/*
 * rt595-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * These are the bindings for our system to the libwebsockets.a imports.
 */

#include "private.h"
#include <string.h>
#include <stdio.h>

static uint32_t ticks_high, last_tick_low;

/*
 * wire up libwebsockets.a logs to native application logs, we just wire it up
 * to the device console in our case.
 *
 * We add the lws loglevel colour scheme ourselves.
 */

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


size_t
space_available(vcring_t *v)
{
	if (v->lrt < v->lrh)
		return (sizeof(v->log_ring) - v->lrh) + v->lrt;

	if (v->lrt == v->lrh)
		return sizeof(v->log_ring) - 1;

	return (v->lrt - v->lrh) - 1;
}

int
append_vcring(vcring_t *v, const uint8_t *b, size_t l)
{
	size_t r = sizeof(v->log_ring) - v->lrh;

	if (v->lrt < v->lrh) {
		/* ---t=====h--- */

		if (r > l)
			r = l;
		memcpy(v->log_ring + v->lrh, b, r);
		v->lrh += r;

		if (v->lrh >= sizeof(v->log_ring))
			v->lrh = 0;

		b += r;
		l -= r;

		if (!l)
			return 0;
	}

	/* ===h------t===   or   ht---------  */

	r = v->lrt - v->lrh;
	if (!r) {
		r = sizeof(v->log_ring) - 1;
		v->lrt = v->lrh = 0;
	}
	if (r > l)
		r = l;
	memcpy(v->log_ring + v->lrh, b, r);
	v->lrh += r;
	if (v->lrh >= sizeof(v->log_ring))
		v->lrh = 0;

	 __sync_synchronize();

	return 0;
}

size_t
next_chonk(vcring_t *v, const uint8_t ** pp)
{
	size_t c = v->lrh < v->lrt ? sizeof(v->log_ring) - v->lrt : v->lrh - v->lrt;

	*pp = v->log_ring + v->lrt;

	return c;
}

void
consume_chonk(vcring_t *v, size_t n)
{
	v->lrt += n;
	if (v->lrt >= sizeof(v->log_ring))
		v->lrt = 0;
}

int
add_log_buf(const uint8_t *b, size_t l)
{
	return append_vcring(&vcr_log, b, l);
}

void
__lws_logv(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
	   int filter, const char * const _fun, const char *format, va_list ap)
{
	int n, m = LWS_ARRAY_SIZE(colours) - 1;
	char logbuf[200], *p = logbuf, *e = logbuf + sizeof(logbuf) - 7;

	if (!(filter & log_level))
		return;

	n = 1 << (LWS_ARRAY_SIZE(colours) - 1);
	while (n) {
		if (filter & n)
			break;
		m--;
		n >>= 1;
	}

	n = snprintf(p, lws_ptr_diff(e, p), "%lu: %c%s%s: ", (unsigned long)lws_now_usecs(), 27,
			colours[m], _fun);
	p += n;
	if (prep && obj)
		prep(cx, obj, &p, e);

	n = vsnprintf(p, lws_ptr_diff(e, p), format, ap);
	p += n;

	if (p > e)
		p = e;
	if (p[-1] != '\n')
		*p++ = '\n';

	*p++ = '\r';
	*p++ = 27;
	*p++ = '[';
	*p++ = '0';
	*p++ = 'm';

	add_log_buf(logbuf, lws_ptr_diff(p, logbuf));
}


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
	uint32_t a =  *((volatile uint32_t*)0xE0001004);
	if (a < (uint32_t)last_tick_low)
		ticks_high++;
	last_tick_low = a;

	return ((((uint64_t)ticks_high)<<32) | (uint64_t)a) / 198;
}

struct timeval {
    uint32_t      tv_sec;     /* seconds */
    uint32_t tv_usec;    /* microseconds */
};


int gettimeofday(struct timeval *tv, void *tx)
{
	lws_usec_t u = lws_now_usecs();

	tv->tv_sec = u / 1000000;
	tv->tv_usec = u - (tv->tv_sec * 1000000);
}

long long atoll(const char *s)
{
	long long l = 0ll;
	char minus = *s == '-';

	if (minus)
		s++;

	while (*s) {
		if (*s < '0' || *s > '9')
			break;
		l = (long long)(l * 10ll) + (*s) - '0';
		s++;
	}

	if (minus)
		return 0ll - l;

	return l;
}

void __assert_func(const char *file, int line, const char *func, const char *failedExpr)
{
	lwsl_err("ASSERT ERROR \" %s \": file \"%s\" Line \"%d\" function name \"%s\" \n", failedExpr, file ,
	line, func);
	for (;;)
	{}
}

int getpid(void)
{
	return 0;
}

struct lws_log_cx *
lwsl_context_get_cx(struct lws_context_standalone *cx)
{
	return NULL;
}

void
lws_log_prepend_context(struct lws_log_cx *cx, void *obj, char **p, char *e)
{

}

