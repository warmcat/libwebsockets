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
 * A touch controller reports where a finger is on a panel that sits over a
 * display.  This class turns those reports into the display's pixel
 * coordinates and classifies them into the interactions user code cares
 * about, a press, a long press, or a scroll, issued as lws_smd
 * LWSSMDCL_INTERACTION events like the button class.  Specific controllers,
 * eg, lws_touch_cst816s_t, are "subclasses" that only know how to read
 * their chip.
 *
 * The classifier is also usable on its own, eg, to treat a mouse the same
 * way.
 */

#if !defined(__LWS_TOUCH_H__)
#define __LWS_TOUCH_H__

/*
 * One report from a controller: whether a finger is in contact, and where
 */

typedef struct lws_touch_sample {
	int16_t				x;
	int16_t				y;
	uint8_t				down;
	/**< a finger is in contact */
	uint8_t				has_pos;
	/**< x and y are meaningful: always so for a down sample, but the
	 * controller may not know where a finger lifted */
} lws_touch_sample_t;

/*
 * How the stream of samples is classified.  An interaction starts when a
 * finger comes down.  If it moves more than px_slop away from where it came
 * down, it is a scroll and nothing else, however long it lasts.  Otherwise,
 * if it is still down after ms_longpress it is a long press, and if it
 * lifts before then, it is a press.
 */

typedef struct lws_touch_regime {
	uint16_t			ms_longpress;
	/**< held without moving this long is a long press, 0 = 500ms */
	uint16_t			px_slop;
	/**< moving further than this from the down point makes it a
	 * scroll, 0 = 10px */
} lws_touch_regime_t;

typedef enum {
	LWSTOUCH_EV_DOWN,
	/**< a finger came down at x, y */
	LWSTOUCH_EV_UP,
	/**< the finger lifted, x, y is where it was last seen.  Always the
	 * last event of an interaction */
	LWSTOUCH_EV_PRESS,
	/**< it lifted near where it came down, before a long press.  Issued
	 * after the UP, at the down point */
	LWSTOUCH_EV_LONGPRESS,
	/**< it was held near where it came down for ms_longpress.  Issued
	 * while it is still down, at the down point */
	LWSTOUCH_EV_SCROLL,
	/**< it moved: x, y is where it is now and dx, dy how far it moved
	 * since the last SCROLL (or since it came down, for the first) */
} lws_touch_event_type_t;

typedef struct lws_touch_event {
	lws_touch_event_type_t		type;
	int16_t				x;
	int16_t				y;
	int16_t				dx;	/* SCROLL only */
	int16_t				dy;	/* SCROLL only */
} lws_touch_event_t;

typedef void (*lws_touch_event_cb_t)(void *opaque,
				     const lws_touch_event_t *ev);

/*
 * Classifier state, zero it before first use
 */

typedef struct lws_touch_classify {
	const lws_touch_regime_t	*regime; /* NULL for the defaults */
	lws_usec_t			us_down;
	int16_t				x0, y0;	/* where it came down */
	int16_t				xl, yl;	/* last reported */
	uint8_t				state;	/* private */
} lws_touch_classify_t;

/**
 * lws_touch_classify_sample() - feed one sample to a classifier
 *
 * \param c: the classifier
 * \param s: the sample
 * \param now: the time the sample was taken
 * \param cb: called with any events the sample causes
 * \param opaque: passed to cb
 *
 * Samples may come as often or as rarely as the controller reports: a
 * controller that only reports the finger coming down and lifting is still
 * classified correctly, the scroll is just issued as one movement at the
 * end.  Repeated down samples at the same place are harmless.
 */
LWS_VISIBLE LWS_EXTERN void
lws_touch_classify_sample(lws_touch_classify_t *c, const lws_touch_sample_t *s,
			  lws_usec_t now, lws_touch_event_cb_t cb, void *opaque);

/**
 * lws_touch_classify_deadline() - when the classifier next needs to look
 *
 * \param c: the classifier
 *
 * Returns the time at which, if nothing else happened, a finger still down
 * would become a long press, or 0 if there is no such deadline.  Controllers
 * that report nothing while a finger is held still need
 * lws_touch_classify_timeout() calling at that time.
 */
LWS_VISIBLE LWS_EXTERN lws_usec_t
lws_touch_classify_deadline(const lws_touch_classify_t *c);

/**
 * lws_touch_classify_timeout() - let time pass without a sample
 *
 * \param c: the classifier
 * \param now: the time now
 * \param cb: called with any events
 * \param opaque: passed to cb
 *
 * Issues the long press if the finger is still down and the deadline has
 * passed, otherwise does nothing, so it is safe to call at any time.
 */
LWS_VISIBLE LWS_EXTERN void
lws_touch_classify_timeout(lws_touch_classify_t *c, lws_usec_t now,
			   lws_touch_event_cb_t cb, void *opaque);

/*
 * The touch controller class
 */

struct lws_touch_state; /* opaque */

enum {
	LWSTOUCH_FL_SWAP_XY		= (1 << 0),
	LWSTOUCH_FL_INVERT_X		= (1 << 1),
	LWSTOUCH_FL_INVERT_Y		= (1 << 2),
};

/*
 * This is embedded at the top of the specific controller's object, so a
 * pointer to it can be cast to the implementation object, like lws_display_t
 */

typedef struct lws_touch {
	int (*init)(struct lws_touch_state *ts);
	/**< prepare the controller, eg, reset it, and call
	 * lws_touch_ready() when it can be used, which may be later from the
	 * event loop.  Nonzero return = failed */
	int (*read)(struct lws_touch_state *ts, lws_touch_sample_t *s);
	/**< read what the controller has to report, in its own coordinates.
	 * Returns 0 and fills s, or nonzero if it could not be read */

	const lws_gpio_ops_t		*gpio;
	/**< gpio ops for the irq (and any reset) gpio */
	const lws_touch_regime_t	*regime;
	/**< NULL for the default classification regime */
	const char			*name;
	/**< used as "src" in the smd events */

	lws_display_scalar		wh_native[2];
	/**< the extent of the coordinates the controller reports */
	lws_display_scalar		wh_px[2];
	/**< the extent of the display pixels the touches should map to, the
	 * same as wh_native if the controller reports pixels */

	_lws_plat_gpio_t		irq_gpio;
	lws_gpio_irq_t			irq_edge;
	/**< the controller signals it has something to report like this */

	uint8_t				flags;
	/**< LWSTOUCH_FL_*, applied to the native coordinates in the order
	 * swap, then invert, before scaling them to wh_px */
} lws_touch_t;

/**
 * lws_touch_create() - start a touch controller
 *
 * \param ctx: the lws_context
 * \param touch: the touch controller definition, which must stay valid
 *
 * Instantiates a touch controller from its static definition and starts
 * it.  It will issue events on lws_smd from when it has come up.  The events
 * are of class LWSSMDCL_INTERACTION with a JSON payload like
 *
 *  {"type":"touch","src":"ts","event":"press","x":120,"y":64}
 *
 * where event is one of down, up, press, longpress, or scroll; scroll
 * events also carry "dx" and "dy".  x and y are in the display's pixel
 * coordinates.  Returns NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN struct lws_touch_state *
lws_touch_create(struct lws_context *ctx, const lws_touch_t *touch);

/**
 * lws_touch_destroy() - stop and free a touch controller
 *
 * \param ts: pointer to the touch controller, set to NULL
 */
LWS_VISIBLE LWS_EXTERN void
lws_touch_destroy(struct lws_touch_state **ts);

/**
 * lws_touch_service() - read and process what the controller reports
 *
 * \param ts: the touch controller
 *
 * Reads the controller, maps what it reports into display pixels, and issues
 * any resulting events.  On platforms with a gpio interrupt bottom half it
 * is called from there; other integrations, eg, polling, can call it when
 * the controller may have something to say.  Not for interrupt context.
 */
LWS_VISIBLE LWS_EXTERN void
lws_touch_service(struct lws_touch_state *ts);

#endif
