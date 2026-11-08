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
 * The GT911 scans continuously and, while a finger is on it, raises a new
 * report every few ms.  Each report sets the top bit of its status register,
 * and it doesn't make another until that is cleared again, so a report isn't
 * lost if its interrupt is: the class's polling while a finger is down still
 * finds it.  The finger lifting is a report too, with no contacts.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-touch.h"

/* the product id, eg, "911", then the firmware version */
#define GT911_REG_PRODUCT_ID		0x8140
#define GT911_PRODUCT_ID_LEN		6

/*
 * The configuration, starting with its version, the output resolution, how
 * many contacts it reports, and module switch 1, which has the INT trigger in
 * its low two bits and whether it swaps x and y in bit 3
 */
#define GT911_REG_CONFIG		0x8047
#define GT911_CONFIG_LEN		7

/*
 * The status, with the "report ready" bit and how many contacts it has, then
 * the first contact's track id, its little-endian x and y, its size, and a
 * reserved byte
 */
#define GT911_REG_STATUS		0x814e
#define GT911_STATUS_READY		0x80
#define GT911_STATUS_CONTACTS		0x0f
#define GT911_REPORT_LEN		(1 + 8)
#define GT911_MAX_CONTACTS		5

#define GT911_WAKE_MS			5
#define GT911_SETTLE_MS			50

static const lws_touch_gt911_t *
gt(lws_touch_state_t *ts)
{
	return lws_container_of(ts->touch, lws_touch_gt911_t, touch);
}

static uint16_t
le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

/* tell it we have the report, so it can make the next */

static int
gt911_ack(lws_touch_state_t *ts)
{
	static const uint8_t zero;

	return lws_i2c_write_regs16(gt(ts)->i2c, ts->ads7, GT911_REG_STATUS,
				    &zero, 1);
}

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)

/*
 * What it says about itself, for bringing up a new board: whether the panel
 * definition's extent and the orientation flags agree with what it reports
 */

static void
gt911_describe(lws_touch_state_t *ts, const uint8_t *id)
{
	static const char * const trig[] = { "rising", "falling", "low",
					     "high" };
	const lws_touch_t *t = ts->touch;
	uint8_t cfg[GT911_CONFIG_LEN];
	char name[5];
	int n;

	/* the id is untrusted, keep it printable */

	for (n = 0; n < 4 && id[n]; n++)
		name[n] = id[n] >= 0x20 && id[n] < 0x7f ? (char)id[n] : '.';
	name[n] = '\0';

	if (lws_i2c_read_regs16(gt(ts)->i2c, ts->ads7, GT911_REG_CONFIG, cfg,
				sizeof(cfg))) {
		lwsl_warn("%s: %s: unable to read config\n", __func__,
			  t->name ? t->name : "ts");
		return;
	}

	lwsl_notice("%s: %s: GT%s fw 0x%04x at 0x%02x: config v%u, %u x %u, "
		    "%u contacts, INT %s%s\n", __func__,
		    t->name ? t->name : "ts", name, le16(&id[4]), ts->ads7,
		    cfg[0], le16(&cfg[1]), le16(&cfg[3]), cfg[5],
		    trig[cfg[6] & 3], cfg[6] & 8 ? ", swaps x and y" : "");

	if (le16(&cfg[1]) != t->wh_native[0] ||
	    le16(&cfg[3]) != t->wh_native[1])
		lwsl_warn("%s: %s: reports %u x %u, but wh_native is %d x %d\n",
			  __func__, t->name ? t->name : "ts", le16(&cfg[1]),
			  le16(&cfg[3]), (int)t->wh_native[0],
			  (int)t->wh_native[1]);
}
#endif

static void
gt911_probe(lws_sorted_usec_list_t *sul)
{
	lws_touch_state_t *ts = lws_container_of(sul, lws_touch_state_t, sul);
	static const uint8_t ads[] = { LWS_GT911_I2C7_ADS,
				       LWS_GT911_I2C7_ADS_ALT };
	const lws_touch_gt911_t *g = gt(ts);
	const uint8_t *cand = ads;
	uint8_t id[GT911_PRODUCT_ID_LEN];
	size_t n, count = LWS_ARRAY_SIZE(ads);

	if (g->i2c7_address) {
		cand = &g->i2c7_address;
		count = 1;
	}

	for (n = 0; n < count; n++) {
		ts->ads7 = cand[n];
		if (!lws_i2c_read_regs16(g->i2c, ts->ads7, GT911_REG_PRODUCT_ID,
					 id, sizeof(id)))
			break;
	}

	if (n == count) {
		lwsl_err("%s: %s: no GT911 found\n", __func__,
			 ts->touch->name ? ts->touch->name : "ts");
		return;
	}

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	gt911_describe(ts, id);
#endif

	/* a report left over from before is stale */
	gt911_ack(ts);

	lws_touch_ready(ts);
}

static void
gt911_woken(lws_sorted_usec_list_t *sul)
{
	lws_touch_state_t *ts = lws_container_of(sul, lws_touch_state_t, sul);

	/* give INT back to the chip, and give it time to come up */

	lws_touch_irq_gpio_input(ts);
	lws_sul_schedule(ts->ctx, 0, &ts->sul, gt911_probe,
			 GT911_SETTLE_MS * LWS_US_PER_MS);
}

int
lws_touch_gt911_init(struct lws_touch_state *ts)
{
	const lws_touch_t *t = ts->touch;

	if (!gt(ts)->i2c)
		return 1;

	/* driving INT high wakes it, if it was asleep */

	t->gpio->mode(t->irq_gpio, LWSGGPIO_FL_WRITE);
	t->gpio->set(t->irq_gpio, 1);
	lws_sul_schedule(ts->ctx, 0, &ts->sul, gt911_woken,
			 GT911_WAKE_MS * LWS_US_PER_MS);

	return 0;
}

int
lws_touch_gt911_read(struct lws_touch_state *ts, lws_touch_sample_t *s)
{
	uint8_t b[GT911_REPORT_LEN];
	unsigned int contacts;

	if (lws_i2c_read_regs16(gt(ts)->i2c, ts->ads7, GT911_REG_STATUS, b,
				sizeof(b)))
		return 1;

	if (!(b[0] & GT911_STATUS_READY))
		return 1; /* nothing new since the last report */

	/* if this fails, we just see the same report again next time */
	gt911_ack(ts);

	contacts = b[0] & GT911_STATUS_CONTACTS;
	if (contacts > GT911_MAX_CONTACTS)
		return 1; /* not a report we can make sense of */

	/*
	 * With no contacts, what's in the first contact's registers is left
	 * over from before, and isn't where the finger lifted
	 */
	s->down		= !!contacts;
	s->has_pos	= s->down;
	s->x		= (int16_t)le16(&b[2]);
	s->y		= (int16_t)le16(&b[4]);

	return 0;
}
