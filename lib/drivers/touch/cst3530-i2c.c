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
 * While a finger is on it, the CST3530 raises a report every few ms.  Each is
 * taken by a command saying it's done with, after which what's read until the
 * next isn't a contact report, so a report isn't lost if its interrupt is:
 * the class's polling while a finger is down still finds it.  The finger
 * lifting is a report too, of the contact no longer being down.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-touch.h"

/*
 * Writes of just these register addresses are commands: the first wakes it
 * out of low power, the others put it in its normal reporting mode, and the
 * last says we have taken the report, so it can make the next
 */
#define CST3530_CMD_LP_OFF		0xd0000400
#define CST3530_CMD_NORMAL_1		0xd0000000
#define CST3530_CMD_NORMAL_2		0xd0000c00
#define CST3530_CMD_NORMAL_3		0xd0000100
#define CST3530_CMD_REPORT_DONE		0xd00002ab

/*
 * What it says about itself: its chip type, ending 0xcaca, the extent of the
 * coordinates it reports, its firmware version and project, and its sensor
 */
#define CST3530_REG_INFO		0xd0030000
#define CST3530_INFO_LEN		50

/*
 * The report: a little-endian checksum, the report type, the count of keys
 * in the top nibble and of contacts in the bottom one, then five bytes for
 * each key and each contact.  A contact's five are the low 8 bits of x and of
 * y, its pressure, the top 4 bits of x in the low nibble and of y in the high
 * one, then its id in the low nibble and whether it's down in the high one
 */
#define CST3530_REG_REPORT		0xd0070000
#define CST3530_REPORT_POS		0xff
#define CST3530_REPORT_HDR		4
#define CST3530_CONTACT_LEN		5
#define CST3530_MAX_CONTACTS		5

#define CST3530_RESET_ASSERT_MS		10
#define CST3530_SETTLE_MS		300
#define CST3530_PROBE_RETRY_MS		100
#define CST3530_PROBE_TRIES		5

typedef struct {
	uint8_t				tries;
} cst3530_priv_t;

static const lws_touch_cst3530_t *
cst(lws_touch_state_t *ts)
{
	return lws_container_of(ts->touch, lws_touch_cst3530_t, touch);
}

static uint16_t
le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static int
cst3530_cmd(lws_touch_state_t *ts, uint32_t cmd)
{
	return lws_i2c_write_regs32(cst(ts)->i2c, ts->ads7, cmd, NULL, 0);
}

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)

static uint32_t
le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * What it says about itself, for bringing up a new board: whether the panel
 * definition's extent agrees with what it reports
 */

static void
cst3530_describe(lws_touch_state_t *ts, const uint8_t *info)
{
	const lws_touch_t *t = ts->touch;

	lwsl_notice("%s: %s: chip 0x%08x fw 0x%08x project 0x%08x at 0x%02x: "
		    "%u x %u, %u tx x %u rx, %u keys\n", __func__,
		    t->name ? t->name : "ts", (unsigned int)le32(&info[0]),
		    (unsigned int)le32(&info[32]),
		    (unsigned int)le32(&info[36]), ts->ads7, le16(&info[28]),
		    le16(&info[30]), info[48], info[49], info[27]);

	if (le16(&info[28]) != t->wh_native[0] ||
	    le16(&info[30]) != t->wh_native[1])
		lwsl_warn("%s: %s: reports %u x %u, but wh_native is %d x %d\n",
			  __func__, t->name ? t->name : "ts", le16(&info[28]),
			  le16(&info[30]), (int)t->wh_native[0],
			  (int)t->wh_native[1]);
}
#endif

static void
cst3530_probe(lws_sorted_usec_list_t *sul)
{
	lws_touch_state_t *ts = lws_container_of(sul, lws_touch_state_t, sul);
	cst3530_priv_t *priv = (cst3530_priv_t *)ts->priv;
	const lws_touch_cst3530_t *c = cst(ts);
	uint8_t info[CST3530_INFO_LEN];

	/*
	 * The first command may only wake it, so it's sent twice, and only
	 * whether it answers what it is decides if it's there
	 */

	cst3530_cmd(ts, CST3530_CMD_LP_OFF);
	cst3530_cmd(ts, CST3530_CMD_LP_OFF);

	if (cst3530_cmd(ts, CST3530_CMD_NORMAL_1) ||
	    cst3530_cmd(ts, CST3530_CMD_NORMAL_2) ||
	    cst3530_cmd(ts, CST3530_CMD_NORMAL_3) ||
	    lws_i2c_read_regs32(c->i2c, ts->ads7, CST3530_REG_INFO, info,
				sizeof(info)) ||
	    info[2] != 0xca || info[3] != 0xca) {

		if (++priv->tries < CST3530_PROBE_TRIES) {
			lws_sul_schedule(ts->ctx, 0, &ts->sul, cst3530_probe,
					 CST3530_PROBE_RETRY_MS * LWS_US_PER_MS);
			return;
		}

		lwsl_err("%s: %s: no CST3530 answering at 0x%02x\n", __func__,
			 ts->touch->name ? ts->touch->name : "ts", ts->ads7);
		return;
	}

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	cst3530_describe(ts, info);
#endif

	/* a report left over from before is stale */
	cst3530_cmd(ts, CST3530_CMD_REPORT_DONE);

	lws_touch_ready(ts);
}

static uint16_t
settle_ms_of(const lws_touch_cst3530_t *c)
{
	return c->settle_ms ? c->settle_ms : CST3530_SETTLE_MS;
}

static void
cst3530_reset_release(lws_sorted_usec_list_t *sul)
{
	lws_touch_state_t *ts = lws_container_of(sul, lws_touch_state_t, sul);

	ts->touch->gpio->set(cst(ts)->reset_gpio, 1);
	lws_sul_schedule(ts->ctx, 0, &ts->sul, cst3530_probe,
			 settle_ms_of(cst(ts)) * LWS_US_PER_MS);
}

int
lws_touch_cst3530_init(struct lws_touch_state *ts)
{
	const lws_touch_cst3530_t *c = cst(ts);

	if (!c->i2c)
		return 1;

	ts->priv = lws_zalloc(sizeof(cst3530_priv_t), __func__);
	if (!ts->priv)
		return 1;

	ts->ads7 = c->i2c7_address ? c->i2c7_address : LWS_CST3530_I2C7_ADS;

	if (!c->has_reset_gpio) {
		lws_sul_schedule(ts->ctx, 0, &ts->sul, cst3530_probe,
				 settle_ms_of(c) * LWS_US_PER_MS);

		return 0;
	}

	/* hold it in reset, then let it go and give it time to come up */

	ts->touch->gpio->mode(c->reset_gpio, LWSGGPIO_FL_WRITE |
					     LWSGGPIO_FL_START_LOW);
	ts->touch->gpio->set(c->reset_gpio, 0);
	lws_sul_schedule(ts->ctx, 0, &ts->sul, cst3530_reset_release,
			 CST3530_RESET_ASSERT_MS * LWS_US_PER_MS);

	return 0;
}

int
lws_touch_cst3530_read(struct lws_touch_state *ts, lws_touch_sample_t *s)
{
	uint8_t b[CST3530_REPORT_HDR + CST3530_CONTACT_LEN * CST3530_MAX_CONTACTS];
	const lws_touch_cst3530_t *c = cst(ts);
	unsigned int keys, contacts, n;
	const uint8_t *p;
	uint16_t sum = 0x55;

	/* the header and one key or contact, most reports are only that */

	if (lws_i2c_read_regs32(c->i2c, ts->ads7, CST3530_REG_REPORT, b,
				CST3530_REPORT_HDR + CST3530_CONTACT_LEN))
		return 1;

	keys		= b[3] >> 4;
	contacts	= b[3] & 0x0f;

	if (b[2] != CST3530_REPORT_POS || keys + contacts > CST3530_MAX_CONTACTS)
		/* not something we use, or can make sense of */
		goto done;

	if (keys + contacts > 1 &&
	    lws_i2c_read_regs32(c->i2c, ts->ads7, CST3530_REG_REPORT, b,
				CST3530_REPORT_HDR +
				CST3530_CONTACT_LEN * (keys + contacts)))
		goto done;

	for (n = 0; n < CST3530_CONTACT_LEN * (keys + contacts); n++)
		sum = (uint16_t)(sum + b[CST3530_REPORT_HDR + n]);

	if (sum != le16(&b[0]))
		goto done;

	cst3530_cmd(ts, CST3530_CMD_REPORT_DONE);

	if (!contacts) {
		s->down = 0;
		s->has_pos = 0;

		return 0;
	}

	/* the first contact comes after any keys */

	p = &b[CST3530_REPORT_HDR + CST3530_CONTACT_LEN * keys];

	/*
	 * A contact that has lifted is still listed in the report saying so,
	 * with where it was: like the other controllers, where it lifted isn't
	 * trusted as a position
	 */
	s->down		= !!(p[4] >> 4);
	s->has_pos	= s->down;
	s->x		= (int16_t)(p[0] | ((p[3] & 0x0f) << 8));
	s->y		= (int16_t)(p[1] | ((p[3] & 0xf0) << 4));

	return 0;

done:
	/* if this fails, we just see the same report again next time */
	cst3530_cmd(ts, CST3530_CMD_REPORT_DONE);

	return 1;
}
