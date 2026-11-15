/*
 * lws-api-test-rtc
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the PCF8563 driver against a simulated chip behind a mock
 * lws_i2c_ops_t, and the rtc class's use of the chip from a context: setting
 * it when ntp sets the time, and from the system clock.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

/*
 * A PCF8563: sixteen registers with an auto-incrementing register pointer,
 * that NAKs any other address
 */

typedef enum {
	MB_IDLE,
	MB_ADDR,	/* after START, expecting the address byte */
	MB_REG,		/* addressed for write, expecting register address */
	MB_WDATA,	/* register address set, any more bytes are data */
	MB_RDATA,	/* addressed for read */
	MB_IGNORE,	/* not us */
} mock_bus_state_t;

typedef struct mock_pcf8563 {
	lws_i2c_ops_t		ops; /* must be first */

	uint8_t			regs[16];
	uint8_t			ptr;
	mock_bus_state_t	state;

	uint8_t			ads7;
	int			ctrl1_writes;	/* times reg 0 was written */
	uint8_t			ctrl1_first;	/* what it was first given */
} mock_pcf8563_t;

static int
mock_init(const lws_i2c_ops_t *octx)
{
	(void)octx;

	return 0;
}

static int
mock_start(const lws_i2c_ops_t *octx)
{
	mock_pcf8563_t *m = (mock_pcf8563_t *)octx;

	m->state = MB_ADDR;

	return 0;
}

static void
mock_stop(const lws_i2c_ops_t *octx)
{
	mock_pcf8563_t *m = (mock_pcf8563_t *)octx;

	m->state = MB_IDLE;
}

static int
mock_write(const lws_i2c_ops_t *octx, uint8_t data)
{
	mock_pcf8563_t *m = (mock_pcf8563_t *)octx;

	switch (m->state) {
	case MB_ADDR:
		if ((data >> 1) != m->ads7) {
			m->state = MB_IGNORE;
			return 1;
		}
		m->state = (data & 1) ? MB_RDATA : MB_REG;
		return 0;
	case MB_REG:
		m->ptr = data & 0xf;
		m->state = MB_WDATA;
		return 0;
	case MB_WDATA:
		if (!m->ptr && !m->ctrl1_writes++)
			m->ctrl1_first = data;
		m->regs[m->ptr] = data;
		m->ptr = (m->ptr + 1) & 0xf;
		return 0;
	default:
		return 1;
	}
}

static int
mock_read(const lws_i2c_ops_t *octx)
{
	mock_pcf8563_t *m = (mock_pcf8563_t *)octx;
	uint8_t b;

	if (m->state != MB_RDATA)
		return -1;

	b = m->regs[m->ptr];
	m->ptr = (m->ptr + 1) & 0xf;

	return b;
}

static void
mock_set_ack(const lws_i2c_ops_t *octx, int ack)
{
	(void)octx;
	(void)ack;
}

static mock_pcf8563_t mock;

/* the chip, as it comes out of power on reset, set to t */

static void
mock_reset(uint8_t ads7, const uint8_t t[7])
{
	memset(&mock, 0, sizeof(mock));

	mock.ops.init		= mock_init;
	mock.ops.start		= mock_start;
	mock.ops.stop		= mock_stop;
	mock.ops.write		= mock_write;
	mock.ops.read		= mock_read;
	mock.ops.set_ack	= mock_set_ack;
	mock.ads7		= ads7;

	mock.regs[0]		= 0x08;	/* TESTC */
	mock.regs[0xd]		= 0x80;	/* CLKOUT enabled, 32.768kHz */
	memcpy(&mock.regs[2], t, 7);
}

static const lws_rtc_pcf8563_t pcf = {
	.rtc = {
		lws_rtc_pcf8563_ops,
		.name		= "pcf8563",
	},
	.i2c			= &mock.ops,
};

static int fails;

/* the struct has padding, so compare the members */

static int
civil_eq(const lws_civil_t *a, const lws_civil_t *b)
{
	return a->year == b->year && a->mon == b->mon && a->day == b->day &&
	       a->hour == b->hour && a->min == b->min && a->sec == b->sec &&
	       a->wday == b->wday;
}

#define expect(cond, ...) do { if (!(cond)) { lwsl_err(__VA_ARGS__); \
				fails++; } } while (0)

/* times, as civil and unix */

static const struct {
	lws_civil_t		c;
	int64_t			secs;
} known[] = {
	{ { 1970,  1,  1,  0,  0,  0, 4 }, 0 },
	{ { 2000,  2, 29, 12, 34, 56, 2 }, 951827696 },
	{ { 2000,  3,  1,  0,  0,  0, 3 }, 951868800 },
	{ { 2026, 11, 15,  6, 56, 18, 0 }, 1794725778 },
	{ { 2099, 12, 31, 23, 59, 59, 4 }, 4102444799 },
	{ { 2100,  3,  1,  0,  0,  0, 1 }, 4107542400 },
	{ { 9999, 12, 31, 23, 59, 59, 5 }, 253402300799 },
};

static void
test_pcf8563(void)
{
	/* 2026-11-15 06:56:18, a Sunday */
	static const uint8_t t[] = { 0x18, 0x56, 0x06, 0x15, 0x00, 0x11, 0x26 };
	lws_civil_t c;

	/* nobody there */

	mock_reset(0x50, t);
	expect(pcf.rtc.init(&pcf.rtc), "%s: init without chip\n", __func__);

	/* init takes it out of test mode, and stops CLKOUT */

	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	expect(!pcf.rtc.init(&pcf.rtc), "%s: init\n", __func__);
	expect(!mock.regs[0] && !(mock.regs[0xd] & 0x80),
	       "%s: init left %02x %02x\n", __func__, mock.regs[0],
	       mock.regs[0xd]);

	expect(!pcf.rtc.read(&pcf.rtc, &c) && civil_eq(&c, &known[3].c),
	       "%s: read\n", __func__);

	/* the time is meaningless, but STOP survives init */

	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	mock.regs[0] = 0x28;
	expect(!pcf.rtc.init(&pcf.rtc) && mock.regs[0] == 0x20,
	       "%s: init lost STOP\n", __func__);
	expect(pcf.rtc.read(&pcf.rtc, &c) == 1, "%s: read stopped\n",
	       __func__);

	/* lost power since it was set */

	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	mock.regs[2] |= 0x80;
	expect(pcf.rtc.read(&pcf.rtc, &c) == 1, "%s: read VL\n", __func__);

	/* not BCD, or out of range: not a time */

	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	mock.regs[3] = 0x5a;
	expect(pcf.rtc.read(&pcf.rtc, &c) < 0, "%s: read bad bcd\n",
	       __func__);
	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	mock.regs[7] = 0x13;
	expect(pcf.rtc.read(&pcf.rtc, &c) < 0, "%s: read month 13\n",
	       __func__);
	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	mock.regs[5] = 0x00;
	expect(pcf.rtc.read(&pcf.rtc, &c) < 0, "%s: read day 0\n", __func__);

	/* the century bit, as it would be after 2099 rolled over */

	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	mock.regs[7] |= 0x80;
	expect(!pcf.rtc.read(&pcf.rtc, &c) && c.year == 2126,
	       "%s: read century\n", __func__);

	/* setting it, while stopped, clears VL and starts it again */

	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	mock.regs[0] = 0x00;
	mock.regs[2] |= 0x80;
	expect(!pcf.rtc.write(&pcf.rtc, &known[1].c), "%s: write\n",
	       __func__);
	expect(mock.ctrl1_first == 0x20 && !mock.regs[0],
	       "%s: write not stopped while set\n", __func__);
	expect(!memcmp(&mock.regs[2], "\x56\x34\x12\x29\x02\x02\x00", 7),
	       "%s: write registers\n", __func__);
	expect(!pcf.rtc.read(&pcf.rtc, &c) && civil_eq(&c, &known[1].c),
	       "%s: read back\n", __func__);

	/* it can't hold 2100 */

	expect(pcf.rtc.write(&pcf.rtc, &known[5].c), "%s: write 2100\n",
	       __func__);
}

static void
test_context(void)
{
	static const uint8_t t[] = { 0x18, 0x56, 0x06, 0x15, 0x00, 0x11, 0x26 };
	struct lws_context_creation_info info;
	struct lws_context *cx;
	lws_civil_t c;
	int64_t s, now;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		expect(0, "%s: no context\n", __func__);
		return;
	}

	expect(lws_rtc_set_from_system(cx), "%s: set without rtc\n", __func__);

	mock_reset(0x50, t);
	expect(lws_rtc_attach(cx, &pcf.rtc), "%s: attach without chip\n",
	       __func__);

	mock_reset(LWS_PCF8563_I2C7_ADS, t);
	expect(!lws_rtc_attach(cx, &pcf.rtc), "%s: attach\n", __func__);

	/*
	 * Our system clock is set, so the chip's time isn't used, but setting
	 * it from the system clock does, about now
	 */

	expect(lws_system_time_source(cx) == LWS_SYSTIME_SRC_NONE,
	       "%s: rtc time used\n", __func__);

	now = (int64_t)lws_now_secs();
	expect(!lws_rtc_set_from_system(cx) && !pcf.rtc.read(&pcf.rtc, &c) &&
	       !lws_civil_to_unix(&c, &s) && s >= now && s <= now + 2,
	       "%s: set from system\n", __func__);

	/* the time from ntp is given to the chip too */

	expect(!lws_system_time_set(cx, known[1].secs * LWS_US_PER_SEC,
				    LWS_SYSTIME_SRC_NTP) &&
	       lws_system_time_source(cx) == LWS_SYSTIME_SRC_NTP,
	       "%s: time set\n", __func__);
	expect(!pcf.rtc.read(&pcf.rtc, &c) && civil_eq(&c, &known[1].c),
	       "%s: ntp time not in rtc\n", __func__);

	/* but not from elsewhere */

	expect(!lws_system_time_set(cx, known[3].secs * LWS_US_PER_SEC,
				    LWS_SYSTIME_SRC_OTHER) &&
	       !pcf.rtc.read(&pcf.rtc, &c) && civil_eq(&c, &known[1].c),
	       "%s: other time in rtc\n", __func__);

	lws_rtc_detach(cx);
	expect(lws_rtc_set_from_system(cx), "%s: set after detach\n",
	       __func__);

	lws_context_destroy(cx);
}

int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: rtc\n");

	test_pcf8563();
	test_context();

	if (fails) {
		lwsl_err("%s: %d rtc tests failed\n", __func__, fails);

		return 1;
	}

	lwsl_user("Passed all rtc tests\n");

	return 0;
}
