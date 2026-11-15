/*
 * lws abstract touch controller implementation for Hynitron CST3530 on i2c
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
 *
 * The CST3530 is one of Hynitron's CST66xx family, eg, the touch controller on
 * the LilyGo T-Display S3 Long.  Its registers have 32-bit addresses, and some
 * writes of just a register address are commands.  It reports up to five
 * contacts, the first of which is used.
 *
 * Its reset may be shared with something else, eg, on the T-Display S3 Long it
 * is the display's reset line, so the display driver resets both.  Then it is
 * given .settle_ms after init before it is looked for.
 */

#if !defined(__LWS_TOUCH_CST3530_I2C_H__)
#define __LWS_TOUCH_CST3530_I2C_H__

#define LWS_CST3530_I2C7_ADS		0x58

typedef struct lws_touch_cst3530 {
	lws_touch_t			touch;
	/**< use lws_touch_cst3530_ops to set the ops; the irq is
	 * .irq_edge = LWSGGPIO_IRQ_FALLING */
	const lws_i2c_ops_t		*i2c;
	/**< i2c ops for the bus it is on, already initialized */
	_lws_plat_gpio_t		reset_gpio;
	/**< the gpio on its active-low reset, if has_reset_gpio */
	uint16_t			settle_ms;
	/**< how long it is given to come up, after its own reset or, if
	 * there's no reset_gpio, after init.  0 = 300ms */
	uint8_t				i2c7_address;
	/**< 0 for LWS_CST3530_I2C7_ADS */
	uint8_t				has_reset_gpio;
	/**< nonzero to pulse reset_gpio at init, using touch.gpio */
} lws_touch_cst3530_t;

LWS_VISIBLE LWS_EXTERN int
lws_touch_cst3530_init(struct lws_touch_state *ts);
LWS_VISIBLE LWS_EXTERN int
lws_touch_cst3530_read(struct lws_touch_state *ts, lws_touch_sample_t *s);

#define lws_touch_cst3530_ops \
	.init = lws_touch_cst3530_init, \
	.read = lws_touch_cst3530_read

#endif
