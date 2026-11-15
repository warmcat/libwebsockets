/*
 * lws abstract rtc implementation for NXP PCF8563 on i2c
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
 * See lws-pcf8563-i2c.h
 */

#include <libwebsockets.h>

#define REG_CTRL1		0x00
#define REG_VL_SECONDS		0x02
#define REG_CLKOUT		0x0d

#define CTRL1_TEST1		(1 << 7)
#define CTRL1_STOP		(1 << 5)
#define CTRL1_TESTC		(1 << 3)

#define VL			(1 << 7)
#define CENTURY			(1 << 7)
#define CLKOUT_FE		(1 << 7)

static uint8_t
ads(const lws_rtc_pcf8563_t *p)
{
	return p->i2c7_address ? p->i2c7_address : LWS_PCF8563_I2C7_ADS;
}

/* a BCD byte, under mask, or -1 if it isn't BCD, eg, the bus floated high */

static int
bcd(uint8_t b, uint8_t mask)
{
	b &= mask;

	if ((b & 0xf) > 9 || (b >> 4) > 9)
		return -1;

	return ((b >> 4) * 10) + (b & 0xf);
}

static uint8_t
to_bcd(int n)
{
	return (uint8_t)(((n / 10) << 4) | (n % 10));
}

int
lws_rtc_pcf8563_init(const lws_rtc_t *rtc)
{
	const lws_rtc_pcf8563_t *p = (const lws_rtc_pcf8563_t *)rtc;
	uint8_t c1, v;

	if (lws_i2c_read_regs(p->i2c, ads(p), REG_CTRL1, &c1, 1)) {
		lwsl_warn("%s: no PCF8563 at 0x%02x\n", __func__, ads(p));

		return 1;
	}

	/*
	 * Out of the test modes, but leave STOP: if it's stopped, its time is
	 * wrong, and should stay unbelieved until it's set
	 */

	if (c1 & (CTRL1_TEST1 | CTRL1_TESTC)) {
		v = c1 & CTRL1_STOP;
		if (lws_i2c_write_regs(p->i2c, ads(p), REG_CTRL1, &v, 1))
			return 1;
	}

	if (!p->keep_clkout) {
		v = 0; /* FE = 0: CLKOUT high impedance */
		if (lws_i2c_write_regs(p->i2c, ads(p), REG_CLKOUT, &v, 1))
			return 1;
	}

	lwsl_notice("%s: PCF8563 at 0x%02x%s\n", __func__, ads(p),
		    c1 & CTRL1_STOP ? ", stopped" : "");

	return 0;
}

int
lws_rtc_pcf8563_read(const lws_rtc_t *rtc, lws_civil_t *c)
{
	const lws_rtc_pcf8563_t *p = (const lws_rtc_pcf8563_t *)rtc;
	int sec, min, hour, day, wday, mon, year;
	uint8_t r[9];

	/*
	 * Read control 1 and the time in one go: the chip holds the time
	 * still while we read it, so it can't carry partway through
	 */

	if (lws_i2c_read_regs(p->i2c, ads(p), REG_CTRL1, r, sizeof(r)))
		return -1;

	sec  = bcd(r[2], 0x7f);
	min  = bcd(r[3], 0x7f);
	hour = bcd(r[4], 0x3f);
	day  = bcd(r[5], 0x3f);
	wday = r[6] & 7;
	mon  = bcd(r[7], 0x1f);
	year = bcd(r[8], 0xff);

	if (sec < 0 || sec > 59 || min < 0 || min > 59 || hour < 0 ||
	    hour > 23 || day < 1 || day > 31 || wday > 6 || mon < 1 ||
	    mon > 12 || year < 0)
		return -1;

	if ((r[0] & CTRL1_STOP) || (r[2] & VL))
		return 1; /* not counting, or it lost power since it was set */

	c->year	= (int16_t)((r[7] & CENTURY ? 2100 : 2000) + year);
	c->mon	= (uint8_t)mon;
	c->day	= (uint8_t)day;
	c->hour	= (uint8_t)hour;
	c->min	= (uint8_t)min;
	c->sec	= (uint8_t)sec;
	c->wday	= (uint8_t)wday;

	return 0;
}

int
lws_rtc_pcf8563_write(const lws_rtc_t *rtc, const lws_civil_t *c)
{
	const lws_rtc_pcf8563_t *p = (const lws_rtc_pcf8563_t *)rtc;
	uint8_t r[7], v;

	if (c->year < 2000 || c->year > 2099 || c->mon < 1 || c->mon > 12 ||
	    c->day < 1 || c->day > 31 || c->hour > 23 || c->min > 59 ||
	    c->sec > 59 || c->wday > 6)
		return 1;

	r[0] = to_bcd(c->sec);	/* VL = 0: the time is good again */
	r[1] = to_bcd(c->min);
	r[2] = to_bcd(c->hour);
	r[3] = to_bcd(c->day);
	r[4] = c->wday;
	r[5] = to_bcd(c->mon);	/* century 0: 20xx */
	r[6] = to_bcd(c->year - 2000);

	/*
	 * Holding it at STOP while it's set means it starts counting the new
	 * time as STOP is released, and not partway through a second
	 */

	v = CTRL1_STOP;
	if (lws_i2c_write_regs(p->i2c, ads(p), REG_CTRL1, &v, 1))
		return 1;

	if (lws_i2c_write_regs(p->i2c, ads(p), REG_VL_SECONDS, r, sizeof(r))) {
		/* leave it stopped: what it has is now neither time */
		lwsl_err("%s: failed setting time\n", __func__);

		return 1;
	}

	v = 0;

	return lws_i2c_write_regs(p->i2c, ads(p), REG_CTRL1, &v, 1);
}
