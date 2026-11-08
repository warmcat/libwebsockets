/*
 * Generic touch controller class
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
 * The classifier, which turns samples into interactions, is pure and only
 * knows the time it is told.  The controller class around it maps the
 * controller's coordinates to the display's, and on platforms with OS
 * timers, runs the controller from its gpio interrupt like the button class:
 * the ISR schedules a bottom half on an OS timer, which reads the
 * controller, classifies, and issues lws_smd events, which is the one thing
 * it may do with lws from outside the lws thread.  A second OS timer issues
 * a long press for controllers that say nothing while a finger is held still.
 *
 * While a finger is down, a third OS timer reads the controller again every
 * LWS_TOUCH_POLL_MS whatever its IRQ says.  An interrupt for the lift can be
 * missed, eg, coming while the bottom half for the last movement is still
 * pending, and if the chip then goes to sleep, nothing more is heard from it
 * until the next touch.  That then looked like the finger had slid there
 * from where the last drag ended, and the page jumped by the difference.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-touch.h"

typedef enum {
	LTCS_IDLE,		/* no finger */
	LTCS_DOWN,		/* down, not yet classified */
	LTCS_LONG,		/* down, long press issued */
	LTCS_SCROLL,		/* down, it has moved: only scrolls from now */
} lws_touch_classify_states_t;

#define LWS_TOUCH_POLL_MS		50

static const lws_touch_regime_t default_regime = {
	.ms_longpress			= 500,
	.px_slop			= 10,
};

static lws_usec_t
regime_us_longpress(const lws_touch_classify_t *c)
{
	const lws_touch_regime_t *r = c->regime ? c->regime : &default_regime;

	return (lws_usec_t)(r->ms_longpress ? r->ms_longpress :
				default_regime.ms_longpress) * LWS_US_PER_MS;
}

static int
beyond_slop(const lws_touch_classify_t *c, int x, int y)
{
	const lws_touch_regime_t *r = c->regime ? c->regime : &default_regime;
	int32_t dx = x - c->x0, dy = y - c->y0,
		slop = r->px_slop ? r->px_slop : default_regime.px_slop;

	return dx * dx + dy * dy > slop * slop;
}

static void
issue(lws_touch_event_cb_t cb, void *opaque, lws_touch_event_type_t type,
      int x, int y, int dx, int dy)
{
	lws_touch_event_t ev;

	ev.type	= type;
	ev.x	= (int16_t)x;
	ev.y	= (int16_t)y;
	ev.dx	= (int16_t)dx;
	ev.dy	= (int16_t)dy;

	cb(opaque, &ev);
}

/* any movement since the last report becomes a scroll */

static void
scroll_to(lws_touch_classify_t *c, int x, int y, lws_touch_event_cb_t cb,
	  void *opaque)
{
	if (x == c->xl && y == c->yl)
		return;

	c->state = LTCS_SCROLL;
	issue(cb, opaque, LWSTOUCH_EV_SCROLL, x, y, x - c->xl, y - c->yl);
	c->xl = (int16_t)x;
	c->yl = (int16_t)y;
}

void
lws_touch_classify_sample(lws_touch_classify_t *c, const lws_touch_sample_t *s,
			  lws_usec_t now, lws_touch_event_cb_t cb, void *opaque)
{
	if (s->down) {
		if (c->state == LTCS_IDLE) {
			c->state	= LTCS_DOWN;
			c->us_down	= now;
			c->x0 = c->xl	= s->x;
			c->y0 = c->yl	= s->y;
			issue(cb, opaque, LWSTOUCH_EV_DOWN, s->x, s->y, 0, 0);

			return;
		}

		if (c->state == LTCS_SCROLL || beyond_slop(c, s->x, s->y)) {
			scroll_to(c, s->x, s->y, cb, opaque);

			return;
		}

		/* still where it came down */

		lws_touch_classify_timeout(c, now, cb, opaque);

		return;
	}

	/* it lifted */

	if (c->state == LTCS_IDLE)
		return; /* we never saw it come down, or a repeated lift */

	/*
	 * A controller that doesn't report movement while the finger is down
	 * may still say where it lifted, which tells us it was a scroll
	 */

	if (s->has_pos && (c->state == LTCS_SCROLL ||
			   beyond_slop(c, s->x, s->y)))
		scroll_to(c, s->x, s->y, cb, opaque);

	/* nor might it have reported anything while it was held still */

	if (c->state == LTCS_DOWN)
		lws_touch_classify_timeout(c, now, cb, opaque);

	issue(cb, opaque, LWSTOUCH_EV_UP, c->xl, c->yl, 0, 0);

	if (c->state == LTCS_DOWN)
		issue(cb, opaque, LWSTOUCH_EV_PRESS, c->x0, c->y0, 0, 0);

	c->state = LTCS_IDLE;
}

lws_usec_t
lws_touch_classify_deadline(const lws_touch_classify_t *c)
{
	if (c->state != LTCS_DOWN)
		return 0;

	return c->us_down + regime_us_longpress(c);
}

void
lws_touch_classify_timeout(lws_touch_classify_t *c, lws_usec_t now,
			   lws_touch_event_cb_t cb, void *opaque)
{
	if (c->state != LTCS_DOWN || now < lws_touch_classify_deadline(c))
		return;

	c->state = LTCS_LONG;
	issue(cb, opaque, LWSTOUCH_EV_LONGPRESS, c->x0, c->y0, 0, 0);
}

/*
 * The controller class
 */

static void
lws_touch_emit(void *opaque, const lws_touch_event_t *ev)
{
#if defined(LWS_WITH_SYS_SMD)
	static const char * const names[] = {
		"down", "up", "press", "longpress", "scroll"
	};
	lws_touch_state_t *ts = (lws_touch_state_t *)opaque;
	const char *src = ts->touch->name ? ts->touch->name : "ts";

	if ((unsigned int)ev->type >= LWS_ARRAY_SIZE(names))
		return;

	if (ev->type == LWSTOUCH_EV_SCROLL)
		lws_smd_msg_printf(ts->ctx, LWSSMDCL_INTERACTION,
				   "{\"type\":\"touch\",\"src\":\"%s\","
				   "\"event\":\"%s\",\"x\":%d,\"y\":%d,"
				   "\"dx\":%d,\"dy\":%d}", src,
				   names[ev->type], ev->x, ev->y, ev->dx,
				   ev->dy);
	else
		lws_smd_msg_printf(ts->ctx, LWSSMDCL_INTERACTION,
				   "{\"type\":\"touch\",\"src\":\"%s\","
				   "\"event\":\"%s\",\"x\":%d,\"y\":%d}", src,
				   names[ev->type], ev->x, ev->y);
#endif
}

/*
 * The controller's coordinates are untrusted: clamp them into its extent,
 * then orient and scale them into the display's
 */

static void
lws_touch_map(const lws_touch_t *t, lws_touch_sample_t *s)
{
	int32_t x = s->x, y = s->y, nw = t->wh_native[0], nh = t->wh_native[1],
		pw = t->wh_px[0], ph = t->wh_px[1], u;

	if (nw < 1 || nh < 1 || pw < 1 || ph < 1) {
		s->has_pos = 0;
		return;
	}

	x = x < 0 ? 0 : (x >= nw ? nw - 1 : x);
	y = y < 0 ? 0 : (y >= nh ? nh - 1 : y);

	if (t->flags & LWSTOUCH_FL_SWAP_XY) {
		u = x; x = y; y = u;
		u = nw; nw = nh; nh = u;
	}

	if (t->flags & LWSTOUCH_FL_INVERT_X)
		x = nw - 1 - x;
	if (t->flags & LWSTOUCH_FL_INVERT_Y)
		y = nh - 1 - y;

	s->x = (int16_t)(x * pw / nw);
	s->y = (int16_t)(y * ph / nh);
}

void
lws_touch_service(struct lws_touch_state *ts)
{
	lws_touch_sample_t s;
	lws_usec_t dl;

	if (!ts->ready)
		return;

	memset(&s, 0, sizeof(s));
	if (ts->touch->read(ts, &s))
		return;

	if (s.has_pos)
		lws_touch_map(ts->touch, &s);

	if (s.down && !s.has_pos)
		return; /* a contact we can't place isn't usable */

	lws_touch_classify_sample(&ts->cls, &s, lws_now_usecs(),
				  lws_touch_emit, ts);

	/*
	 * Arm the long press timer when a classification starts waiting on
	 * it, and disarm it when it stops waiting... don't restart it on
	 * every sample while the finger is held, or it would never expire
	 */

	dl = lws_touch_classify_deadline(&ts->cls);
	if (!!dl != ts->lp_armed) {
		ts->lp_armed = !!dl;
#if defined(LWS_PLAT_TIMER_START)
		if (dl)
			LWS_PLAT_TIMER_START(ts->timer_lp);
		else
			LWS_PLAT_TIMER_STOP(ts->timer_lp);
#endif
	}

	/* while a finger is down, look again even if we're not told to */

	if ((ts->cls.state != LTCS_IDLE) != ts->poll_armed) {
		ts->poll_armed = ts->cls.state != LTCS_IDLE;
#if defined(LWS_PLAT_TIMER_START)
		if (ts->poll_armed)
			LWS_PLAT_TIMER_START(ts->timer_poll);
		else
			LWS_PLAT_TIMER_STOP(ts->timer_poll);
#endif
	}
}

#if defined(LWS_PLAT_TIMER_START_FROM_ISR)

/* interrupt context: just schedule the bottom half */

static void
lws_touch_irq(void *arg)
{
	lws_touch_state_t *ts = (lws_touch_state_t *)arg;

	LWS_PLAT_TIMER_START_FROM_ISR(ts->timer_bh);
}

static LWS_PLAT_TIMER_CB(lws_touch_bh, th)
{
	lws_touch_service((lws_touch_state_t *)LWS_PLAT_TIMER_CB_GET_OPAQUE(th));
}

/* a finger is down: the timer repeats until the service sees it lift */

static LWS_PLAT_TIMER_CB(lws_touch_poll, th)
{
	lws_touch_service((lws_touch_state_t *)LWS_PLAT_TIMER_CB_GET_OPAQUE(th));
}

static LWS_PLAT_TIMER_CB(lws_touch_lp, th)
{
	lws_touch_state_t *ts = LWS_PLAT_TIMER_CB_GET_OPAQUE(th);

	/* the bottom half and this are both on the OS timer task */

	ts->lp_armed = 0;
	lws_touch_classify_timeout(&ts->cls, lws_now_usecs(), lws_touch_emit,
				   ts);
}
#endif

void
lws_touch_irq_gpio_input(lws_touch_state_t *ts)
{
	const lws_touch_t *t = ts->touch;

	t->gpio->mode(t->irq_gpio, LWSGGPIO_FL_READ |
		      (t->irq_edge == LWSGGPIO_IRQ_RISING ||
		       t->irq_edge == LWSGGPIO_IRQ_HIGH ?
				LWSGGPIO_FL_PULLDOWN : LWSGGPIO_FL_PULLUP));
}

void
lws_touch_ready(lws_touch_state_t *ts)
{
	const lws_touch_t *t = ts->touch;

	ts->ready = 1;

#if defined(LWS_PLAT_TIMER_START_FROM_ISR)
	if (t->gpio->irq_mode(t->irq_gpio, t->irq_edge, lws_touch_irq, ts))
		lwsl_err("%s: %s: unable to take irq\n", __func__,
			 t->name ? t->name : "ts");
#else
	(void)t;
#endif
}

struct lws_touch_state *
lws_touch_create(struct lws_context *ctx, const lws_touch_t *touch)
{
	lws_touch_state_t *ts;

	if (!touch->read || !touch->gpio)
		return NULL;

	ts = lws_zalloc(sizeof(*ts), __func__);
	if (!ts)
		return NULL;

	ts->ctx		= ctx;
	ts->touch	= touch;
	ts->cls.regime	= touch->regime;

#if defined(LWS_PLAT_TIMER_CREATE)
	/* this only runs inbetween a gpio ISR and the bottom half */
	ts->timer_bh = LWS_PLAT_TIMER_CREATE("tsbh", 1, 0, ts,
				(TimerCallbackFunction_t)lws_touch_bh);
	/*
	 * This only runs while waiting to see if a press becomes long.  OS
	 * timers have tick granularity, so allow a tick more than the
	 * classifier waits, for it to be sure to agree it is time.
	 */
	ts->timer_lp = LWS_PLAT_TIMER_CREATE("tslp",
			(regime_us_longpress(&ts->cls) / LWS_US_PER_MS) + 10, 0,
			ts, (TimerCallbackFunction_t)lws_touch_lp);
	ts->timer_poll = LWS_PLAT_TIMER_CREATE("tspl", LWS_TOUCH_POLL_MS, 1,
			ts, (TimerCallbackFunction_t)lws_touch_poll);
	if (!ts->timer_bh || !ts->timer_lp || !ts->timer_poll)
		goto bail;
#endif

	lws_touch_irq_gpio_input(ts);

	if (!touch->init) {
		lws_touch_ready(ts);

		return ts;
	}

	if (!touch->init(ts))
		return ts;

	lwsl_err("%s: %s: init failed\n", __func__,
		 touch->name ? touch->name : "ts");

#if defined(LWS_PLAT_TIMER_CREATE)
bail:
	if (ts->timer_bh)
		LWS_PLAT_TIMER_DELETE(ts->timer_bh);
	if (ts->timer_lp)
		LWS_PLAT_TIMER_DELETE(ts->timer_lp);
	if (ts->timer_poll)
		LWS_PLAT_TIMER_DELETE(ts->timer_poll);
#endif
	lws_free(ts);

	return NULL;
}

void
lws_touch_destroy(struct lws_touch_state **pts)
{
	lws_touch_state_t *ts = *pts;

	if (!ts)
		return;

	/* the ISR opaque points at what we are about to free */

	if (ts->ready)
		ts->touch->gpio->irq_mode(ts->touch->irq_gpio,
					  LWSGGPIO_IRQ_NONE, NULL, NULL);

	lws_sul_cancel(&ts->sul);

#if defined(LWS_PLAT_TIMER_DELETE)
	LWS_PLAT_TIMER_DELETE(ts->timer_bh);
	LWS_PLAT_TIMER_DELETE(ts->timer_lp);
	LWS_PLAT_TIMER_DELETE(ts->timer_poll);
#endif

	lws_free(ts);
	*pts = NULL;
}
