/*
 * lws-api-test-i2c
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the generic i2c register helpers against a simulated peripheral
 * behind a mock lws_i2c_ops_t.  The mock checks the master keeps to the
 * bus protocol at the level of the ops, and models a typical register-file
 * device whose register pointer auto-increments.  The device can take
 * 8-bit or 16-bit register addresses, the latter for the *_regs16() helpers.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

#define MOCK_ADS7 0x15

typedef enum {
	MB_IDLE,	/* bus free */
	MB_ADDR,	/* after START, expecting the address byte */
	MB_REG,		/* addressed for write, expecting register address */
	MB_REG_LO,	/* 16-bit register address, expecting its low byte */
	MB_WDATA,	/* register address set, any more bytes are data */
	MB_RDATA,	/* addressed for read, master clocks bytes in */
	MB_RDONE,	/* master NAKed a byte, only STOP or restart is legal */
	MB_IGNORE,	/* address NAKed, bus stays ours until STOP */
} mock_bus_state_t;

typedef struct mock_i2c {
	lws_i2c_ops_t		ops; /* must be first */

	uint8_t			regs[256];
	uint16_t		ptr;	/* register pointer, regs[] holds the
					 * low 256 of them */
	uint16_t		reg_set; /* the last register address sent */
	char			reg16;	/* register addresses are 16-bit */

	mock_bus_state_t	state;
	char			ack_owed; /* a byte was read, set_ack() due */

	int			starts;
	int			stops;
	int			violations;
	int			fail_read_at; /* > 0: that read op fails */
	int			reads;
} mock_i2c_t;

static void
violation(mock_i2c_t *m, const char *why)
{
	lwsl_err("%s: bus protocol violation: %s\n", __func__, why);
	m->violations++;
}

static int
mock_init(const lws_i2c_ops_t *octx)
{
	(void)octx;

	return 0;
}

static int
mock_start(const lws_i2c_ops_t *octx)
{
	mock_i2c_t *m = (mock_i2c_t *)octx;

	if (m->ack_owed)
		violation(m, "START with an ACK still owed");

	/* START from idle, or a repeated START inside a transaction */
	m->starts++;
	m->state = MB_ADDR;

	return 0;
}

static void
mock_stop(const lws_i2c_ops_t *octx)
{
	mock_i2c_t *m = (mock_i2c_t *)octx;

	if (m->state == MB_IDLE)
		violation(m, "STOP without START");
	if (m->state == MB_RDATA)
		violation(m, "STOP while the device still expects to send");
	if (m->ack_owed)
		violation(m, "STOP with an ACK still owed");

	m->stops++;
	m->state = MB_IDLE;
}

static int
mock_write(const lws_i2c_ops_t *octx, uint8_t data)
{
	mock_i2c_t *m = (mock_i2c_t *)octx;

	switch (m->state) {
	case MB_ADDR:
		if ((data >> 1) != MOCK_ADS7) {
			m->state = MB_IGNORE;
			return 1; /* nobody home: NAK */
		}
		m->state = (data & 1) ? MB_RDATA : MB_REG;
		return 0;

	case MB_REG:
		if (m->reg16) {
			/* the most significant byte comes first */
			m->ptr = (uint16_t)(data << 8);
			m->state = MB_REG_LO;
			return 0;
		}
		m->ptr = m->reg_set = data;
		m->state = MB_WDATA;
		return 0;

	case MB_REG_LO:
		m->ptr = m->reg_set = (uint16_t)(m->ptr | data);
		m->state = MB_WDATA;
		return 0;

	case MB_WDATA:
		m->regs[m->ptr++ & 0xff] = data;
		return 0;

	case MB_IGNORE:
		return 1;

	default:
		violation(m, "write in wrong bus state");
		return 1;
	}
}

static int
mock_read(const lws_i2c_ops_t *octx)
{
	mock_i2c_t *m = (mock_i2c_t *)octx;

	if (m->state != MB_RDATA) {
		violation(m, "read when not addressed for read");
		return -1;
	}
	if (m->ack_owed) {
		violation(m, "read before acknowledging the previous byte");
		return -1;
	}

	if (++m->reads == m->fail_read_at)
		return -1;

	m->ack_owed = 1;

	return m->regs[m->ptr++ & 0xff];
}

static void
mock_set_ack(const lws_i2c_ops_t *octx, int ack)
{
	mock_i2c_t *m = (mock_i2c_t *)octx;

	if (!m->ack_owed) {
		violation(m, "acknowledge with no byte read");
		return;
	}

	m->ack_owed = 0;
	if (ack) /* bus high: NAK, the device stops sending */
		m->state = MB_RDONE;
}

static void
mock_reset(mock_i2c_t *m)
{
	int n;

	memset(m, 0, sizeof(*m));

	m->ops.init	= mock_init;
	m->ops.start	= mock_start;
	m->ops.stop	= mock_stop;
	m->ops.write	= mock_write;
	m->ops.read	= mock_read;
	m->ops.set_ack	= mock_set_ack;

	for (n = 0; n < (int)sizeof(m->regs); n++)
		m->regs[n] = (uint8_t)(0xa0 ^ n);
}

/* every transaction must have released the bus, cleanly */

static int
bus_ok(mock_i2c_t *m, int starts, const char *what)
{
	if (m->violations || m->state != MB_IDLE || m->starts != starts ||
	    m->stops != 1) {
		lwsl_err("%s: %s: violations %d, state %d, starts %d "
			 "(expected %d), stops %d\n", __func__, what,
			 m->violations, m->state, m->starts, starts, m->stops);
		return 1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	static const uint8_t w[] = { 0x11, 0x22, 0x33, 0x44 };
	int logs = LLL_USER | LLL_ERR | LLL_WARN, fails = 0;
	const char *p;
	uint8_t r[8];
	mock_i2c_t m;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: i2c\n");

	/* write then read back consecutive registers */

	mock_reset(&m);
	if (lws_i2c_write_regs(&m.ops, MOCK_ADS7, 0x40, w, sizeof(w)) ||
	    bus_ok(&m, 1, "write") || memcmp(&m.regs[0x40], w, sizeof(w)) ||
	    m.regs[0x44] != (0xa0 ^ 0x44)) {
		lwsl_err("%s: write_regs\n", __func__);
		fails++;
	}

	m.starts = m.stops = 0;
	memset(r, 0, sizeof(r));
	if (lws_i2c_read_regs(&m.ops, MOCK_ADS7, 0x40, r, sizeof(w)) ||
	    bus_ok(&m, 2, "read") || memcmp(r, w, sizeof(w))) {
		lwsl_err("%s: read_regs\n", __func__);
		fails++;
	}

	/* a single register, so its only byte is also the last, NAKed one */

	mock_reset(&m);
	if (lws_i2c_read_regs(&m.ops, MOCK_ADS7, 0x02, r, 1) ||
	    bus_ok(&m, 2, "read 1") || r[0] != (0xa0 ^ 0x02)) {
		lwsl_err("%s: read_regs single\n", __func__);
		fails++;
	}

	/* a register address write with no data is legal */

	mock_reset(&m);
	if (lws_i2c_write_regs(&m.ops, MOCK_ADS7, 0x07, NULL, 0) ||
	    bus_ok(&m, 1, "write 0") || m.ptr != 0x07) {
		lwsl_err("%s: write_regs empty\n", __func__);
		fails++;
	}

	/* a device that isn't there NAKs its address: fail, release bus */

	mock_reset(&m);
	if (!lws_i2c_read_regs(&m.ops, MOCK_ADS7 + 1, 0x00, r, 2) ||
	    bus_ok(&m, 1, "absent read")) {
		lwsl_err("%s: read_regs from absent device\n", __func__);
		fails++;
	}

	mock_reset(&m);
	if (!lws_i2c_write_regs(&m.ops, MOCK_ADS7 + 1, 0x00, w, 2) ||
	    bus_ok(&m, 1, "absent write")) {
		lwsl_err("%s: write_regs to absent device\n", __func__);
		fails++;
	}

	/* a zero-length read is refused without touching the bus */

	mock_reset(&m);
	if (!lws_i2c_read_regs(&m.ops, MOCK_ADS7, 0x00, r, 0) || m.starts ||
	    m.stops) {
		lwsl_err("%s: zero-length read\n", __func__);
		fails++;
	}

	/* a read op failing midway fails the transaction, bus released */

	mock_reset(&m);
	m.fail_read_at = 2;
	if (!lws_i2c_read_regs(&m.ops, MOCK_ADS7, 0x00, r, 4) || m.stops != 1 ||
	    m.state != MB_IDLE) {
		lwsl_err("%s: failing read\n", __func__);
		fails++;
	}

	/*
	 * 16-bit register addresses, most significant byte first: write then
	 * read back, as a GT911 touch controller is spoken to
	 */

	mock_reset(&m);
	m.reg16 = 1;
	if (lws_i2c_write_regs16(&m.ops, MOCK_ADS7, 0x8140, w, sizeof(w)) ||
	    bus_ok(&m, 1, "write16") || m.reg_set != 0x8140 ||
	    memcmp(&m.regs[0x40], w, sizeof(w))) {
		lwsl_err("%s: write_regs16\n", __func__);
		fails++;
	}

	m.starts = m.stops = 0;
	m.reg_set = 0;
	memset(r, 0, sizeof(r));
	if (lws_i2c_read_regs16(&m.ops, MOCK_ADS7, 0x8140, r, sizeof(w)) ||
	    bus_ok(&m, 2, "read16") || m.reg_set != 0x8140 ||
	    memcmp(r, w, sizeof(w))) {
		lwsl_err("%s: read_regs16\n", __func__);
		fails++;
	}

	mock_reset(&m);
	m.reg16 = 1;
	if (lws_i2c_write_regs16(&m.ops, MOCK_ADS7, 0x814e, NULL, 0) ||
	    bus_ok(&m, 1, "write16 0") || m.reg_set != 0x814e) {
		lwsl_err("%s: write_regs16 empty\n", __func__);
		fails++;
	}

	mock_reset(&m);
	m.reg16 = 1;
	if (!lws_i2c_read_regs16(&m.ops, MOCK_ADS7 + 1, 0x8140, r, 2) ||
	    bus_ok(&m, 1, "absent read16")) {
		lwsl_err("%s: read_regs16 from absent device\n", __func__);
		fails++;
	}

	mock_reset(&m);
	m.reg16 = 1;
	if (!lws_i2c_write_regs16(&m.ops, MOCK_ADS7 + 1, 0x814e, w, 1) ||
	    bus_ok(&m, 1, "absent write16")) {
		lwsl_err("%s: write_regs16 to absent device\n", __func__);
		fails++;
	}

	mock_reset(&m);
	m.reg16 = 1;
	if (!lws_i2c_read_regs16(&m.ops, MOCK_ADS7, 0x8140, r, 0) ||
	    m.starts || m.stops) {
		lwsl_err("%s: zero-length read16\n", __func__);
		fails++;
	}

	mock_reset(&m);
	m.reg16 = 1;
	m.fail_read_at = 3;
	if (!lws_i2c_read_regs16(&m.ops, MOCK_ADS7, 0x8140, r, 4) ||
	    m.stops != 1 || m.state != MB_IDLE) {
		lwsl_err("%s: failing read16\n", __func__);
		fails++;
	}

	if (fails) {
		lwsl_err("%s: %d i2c tests failed\n", __func__, fails);
		return 1;
	}

	lwsl_user("Passed all i2c tests\n");

	return 0;
}
