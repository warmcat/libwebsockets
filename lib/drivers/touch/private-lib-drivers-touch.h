/*
 * Generic touch controller class - private
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
 */

/*
 * The opaque, allocated, dynamic part of a touch controller.  The specific
 * controller implementations, which live in lib/drivers/touch, may use
 * ctx, touch, sul, priv and ads7.
 */

typedef struct lws_touch_state {
#if defined(LWS_PLAT_TIMER_TYPE)
	LWS_PLAT_TIMER_TYPE		timer_bh;  /* ISR bottom half */
	LWS_PLAT_TIMER_TYPE		timer_lp;  /* long press deadline */
	LWS_PLAT_TIMER_TYPE		timer_poll; /* a finger is down */
#endif
	lws_sorted_usec_list_t		sul;	   /* for the controller */
	lws_touch_classify_t		cls;

	struct lws_context		*ctx;
	const lws_touch_t		*touch;
	void				*priv;	   /* for the controller */

	uint8_t				ads7;	   /* for the controller, eg,
						    * the i2c address it was
						    * found at */
	uint8_t				ready;
	uint8_t				lp_armed;
	uint8_t				poll_armed;
} lws_touch_state_t;

/*
 * The controller calls this from the event loop when it has come up, to
 * start taking its interrupts
 */

void
lws_touch_ready(lws_touch_state_t *ts);

/*
 * Sets the irq gpio up as an input, pulled to its idle level, as it is
 * before the controller's init is called.  For a controller that drives the
 * irq line itself during init, to give it back.
 */

void
lws_touch_irq_gpio_input(lws_touch_state_t *ts);
