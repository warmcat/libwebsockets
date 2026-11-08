/*
 * lws abstract touch controller implementation for Goodix GT911 on i2c
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
 * The GT911 reports up to five contacts, the first of which is used.  It
 * takes one of two i2c addresses, chosen by the level of its INT line as it
 * comes out of reset.  This doesn't reset it, since boards like the LilyGo
 * T5 4.7" S3 don't give the host its reset line, so unless told which, it
 * probes for it at both.
 *
 * At init, INT is driven high for a few ms first, which is how a GT911 is
 * woken from sleep, in case something before us left it asleep, then given
 * back to the chip.
 */

#if !defined(__LWS_TOUCH_GT911_I2C_H__)
#define __LWS_TOUCH_GT911_I2C_H__

#define LWS_GT911_I2C7_ADS		0x5d	/* INT low out of reset */
#define LWS_GT911_I2C7_ADS_ALT		0x14	/* INT high out of reset */

typedef struct lws_touch_gt911 {
	lws_touch_t			touch;
	/**< use lws_touch_gt911_ops to set the ops; .irq_edge =
	 * LWSGGPIO_IRQ_FALLING sees it report however its INT is configured,
	 * apart from as active-high level */
	const lws_i2c_ops_t		*i2c;
	/**< i2c ops for the bus it is on, already initialized */
	uint8_t				i2c7_address;
	/**< 0 to probe for it at LWS_GT911_I2C7_ADS then
	 * LWS_GT911_I2C7_ADS_ALT */
} lws_touch_gt911_t;

LWS_VISIBLE LWS_EXTERN int
lws_touch_gt911_init(struct lws_touch_state *ts);
LWS_VISIBLE LWS_EXTERN int
lws_touch_gt911_read(struct lws_touch_state *ts, lws_touch_sample_t *s);

#define lws_touch_gt911_ops \
	.init = lws_touch_gt911_init, \
	.read = lws_touch_gt911_read

#endif
