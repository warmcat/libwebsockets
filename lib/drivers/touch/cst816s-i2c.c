/*
 * lws abstract touch controller implementation for Hynitron CST816S on i2c
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
 * The chip is asleep unless a finger is on it, or was very recently, and
 * then it NAKs its i2c address.  It can't be probed or configured at init,
 * so after an optional reset we wait for its IRQ, and only then read it,
 * following the Linux hynitron-cst816x driver.  The same thing means a read
 * that fails can be taken as the finger being gone: if it was still there,
 * the chip would be awake to say so.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-touch.h"

/*
 * Six registers from 0x01 report the touch: the chip's own gesture
 * classification, which we don't use, the number of fingers down, then the
 * big-endian x and y, of which only the low 12 bits are the coordinate.
 */

#define CST816S_REG_TOUCH		0x01
#define CST816S_TOUCH_LEN		6

#define CST816S_RESET_ASSERT_MS		50
#define CST816S_RESET_SETTLE_MS		100

static const lws_touch_cst816s_t *
cst(lws_touch_state_t *ts)
{
	return lws_container_of(ts->touch, lws_touch_cst816s_t, touch);
}

static void
cst816s_reset_settled(lws_sorted_usec_list_t *sul)
{
	lws_touch_ready(lws_container_of(sul, lws_touch_state_t, sul));
}

static void
cst816s_reset_release(lws_sorted_usec_list_t *sul)
{
	lws_touch_state_t *ts = lws_container_of(sul, lws_touch_state_t, sul);

	ts->touch->gpio->set(cst(ts)->reset_gpio, 1);
	lws_sul_schedule(ts->ctx, 0, &ts->sul, cst816s_reset_settled,
			 CST816S_RESET_SETTLE_MS * LWS_US_PER_MS);
}

int
lws_touch_cst816s_init(struct lws_touch_state *ts)
{
	const lws_touch_cst816s_t *c = cst(ts);

	if (!c->i2c)
		return 1;

	if (!c->has_reset_gpio) {
		lws_touch_ready(ts);

		return 0;
	}

	/* hold it in reset, then let it go and give it time to come up */

	ts->touch->gpio->mode(c->reset_gpio, LWSGGPIO_FL_WRITE |
					     LWSGGPIO_FL_START_LOW);
	ts->touch->gpio->set(c->reset_gpio, 0);
	lws_sul_schedule(ts->ctx, 0, &ts->sul, cst816s_reset_release,
			 CST816S_RESET_ASSERT_MS * LWS_US_PER_MS);

	return 0;
}

int
lws_touch_cst816s_read(struct lws_touch_state *ts, lws_touch_sample_t *s)
{
	const lws_touch_cst816s_t *c = cst(ts);
	uint8_t b[CST816S_TOUCH_LEN];

	if (lws_i2c_read_regs(c->i2c, c->i2c7_address ? c->i2c7_address :
						LWS_CST816S_I2C7_ADS,
			      CST816S_REG_TOUCH, b, sizeof(b))) {
		/* gone back to sleep, so there's no finger on it */
		s->down = 0;
		s->has_pos = 0;

		return 0;
	}

	/*
	 * With no finger on it, what the coordinate registers hold isn't a
	 * position to trust for where it lifted: taken as one, a drag ended
	 * with a scroll to there
	 */
	s->down		= !!b[1];
	s->has_pos	= s->down;
	s->x		= (int16_t)(((b[2] & 0x0f) << 8) | b[3]);
	s->y		= (int16_t)(((b[4] & 0x0f) << 8) | b[5]);

	return 0;
}
