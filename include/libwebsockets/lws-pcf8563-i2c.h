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
 * The PCF8563 keeps the time and date in BCD, with a "VL" bit that says the
 * time can't be believed: it's set when the chip's supply, eg, its backup
 * cell, fell too low for it to keep counting, and is only cleared by setting
 * the time.  It's kept in UTC.
 *
 * It holds two digits of the year, and a century bit that toggles when they
 * roll over from 99.  What the century bit means is up to whoever sets it:
 * this driver always sets it to 0 for 2000 - 2099, and reads it as 1 meaning
 * 2100 - 2199.
 *
 * If its STOP bit is set, it isn't counting, so its time isn't believed
 * either; setting the time starts it again.  Its test modes are turned off at
 * init, and unless .keep_clkout, its CLKOUT too, which otherwise runs at
 * 32.768kHz from power on, using more of the backup cell than the clock.  Its
 * alarm and timer are left as they are.
 */

#if !defined(__LWS_RTC_PCF8563_I2C_H__)
#define __LWS_RTC_PCF8563_I2C_H__

#define LWS_PCF8563_I2C7_ADS		0x51

typedef struct lws_rtc_pcf8563 {
	lws_rtc_t			rtc;
	/**< use lws_rtc_pcf8563_ops to set the ops */
	const lws_i2c_ops_t		*i2c;
	/**< i2c ops for the bus it is on, already initialized */
	uint8_t				i2c7_address;
	/**< 0 for LWS_PCF8563_I2C7_ADS */
	uint8_t				keep_clkout;
	/**< nonzero to leave CLKOUT as it is, eg, the board uses it */
} lws_rtc_pcf8563_t;

LWS_VISIBLE LWS_EXTERN int
lws_rtc_pcf8563_init(const lws_rtc_t *rtc);
LWS_VISIBLE LWS_EXTERN int
lws_rtc_pcf8563_read(const lws_rtc_t *rtc, lws_civil_t *c);
LWS_VISIBLE LWS_EXTERN int
lws_rtc_pcf8563_write(const lws_rtc_t *rtc, const lws_civil_t *c);

#define lws_rtc_pcf8563_ops \
	.init = lws_rtc_pcf8563_init, \
	.read = lws_rtc_pcf8563_read, \
	.write = lws_rtc_pcf8563_write

#endif
