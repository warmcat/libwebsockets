/*
 * lws-api-test-touch
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the touch class in two parts.
 *
 * First the classifier on its own, fed sample sequences at chosen times,
 * covering controllers that stream movement and ones that only report the
 * finger coming down and lifting.
 *
 * Then whole touch controllers, a CST816S behind a simulated i2c bus and
 * gpio, from reset through to the lws_smd events they issue, with the
 * controller's coordinates mapped into display pixels.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

static int fails;

#define check(cond, ...) do { if (!(cond)) { \
		lwsl_err("%s:%d: " #cond "\n", __func__, __LINE__); \
		lwsl_err(__VA_ARGS__); fails++; } } while (0)

/*
 * Part 1: the classifier
 */

#define MS(n) ((lws_usec_t)(n) * LWS_US_PER_MS)

typedef struct {
	lws_touch_event_t	ev[16];
	int			count;
} evlog_t;

static void
evlog_cb(void *opaque, const lws_touch_event_t *ev)
{
	evlog_t *l = (evlog_t *)opaque;

	if (l->count < (int)LWS_ARRAY_SIZE(l->ev))
		l->ev[l->count] = *ev;
	l->count++;
}

typedef struct {
	char			sample;	/* 'd' down, 'u' up, 'n' up no pos,
					 * 't' timeout only */
	int16_t			x, y;
	int			ms;
} step_t;

typedef struct {
	const char		*name;
	const lws_touch_regime_t *regime;
	step_t			steps[8];
	lws_touch_event_t	expect[8]; /* ends at type -1 */
} cls_test_t;

#define END { (lws_touch_event_type_t)-1, 0, 0, 0, 0 }
#define EV(t, _x, _y) { LWSTOUCH_EV_##t, _x, _y, 0, 0 }
#define SC(_x, _y, _dx, _dy) { LWSTOUCH_EV_SCROLL, _x, _y, _dx, _dy }

static const lws_touch_regime_t tight = { .ms_longpress = 100, .px_slop = 3 };

static const cls_test_t cls_tests[] = {
	{ "tap, jitter within slop", NULL,
	  { { 'd', 100, 100, 0 }, { 'd', 103, 98, 40 }, { 'u', 104, 101, 90 },
	    { 0 } },
	  { EV(DOWN, 100, 100), EV(UP, 100, 100), EV(PRESS, 100, 100), END } },

	{ "long press by timeout", NULL,
	  { { 'd', 50, 60, 0 }, { 't', 0, 0, 499 }, { 't', 0, 0, 500 },
	    { 't', 0, 0, 900 }, { 'u', 50, 60, 1000 }, { 0 } },
	  { EV(DOWN, 50, 60), EV(LONGPRESS, 50, 60), EV(UP, 50, 60), END } },

	{ "long press seen in held samples", NULL,
	  { { 'd', 50, 60, 0 }, { 'd', 51, 60, 300 }, { 'd', 51, 61, 600 },
	    { 'd', 51, 61, 700 }, { 'u', 51, 61, 800 }, { 0 } },
	  { EV(DOWN, 50, 60), EV(LONGPRESS, 50, 60), EV(UP, 50, 60), END } },

	{ "long press only learned at the lift", NULL,
	  { { 'd', 5, 5, 0 }, { 'u', 5, 5, 800 }, { 0 } },
	  { EV(DOWN, 5, 5), EV(LONGPRESS, 5, 5), EV(UP, 5, 5), END } },

	{ "streamed scroll is never a press", NULL,
	  { { 'd', 50, 50, 0 }, { 'd', 55, 52, 20 }, { 'd', 70, 50, 40 },
	    { 'd', 80, 60, 60 }, { 'd', 80, 60, 900 }, { 'u', 80, 60, 950 },
	    { 0 } },
	  { EV(DOWN, 50, 50), SC(70, 50, 20, 0), SC(80, 60, 10, 10),
	    EV(UP, 80, 60), END } },

	{ "scroll only seen where it lifted", NULL,
	  { { 'd', 10, 10, 0 }, { 'u', 100, 10, 100 }, { 0 } },
	  { EV(DOWN, 10, 10), SC(100, 10, 90, 0), EV(UP, 100, 10), END } },

	{ "lift with no position is a press", NULL,
	  { { 'd', 10, 20, 0 }, { 'n', 0, 0, 100 }, { 0 } },
	  { EV(DOWN, 10, 20), EV(UP, 10, 20), EV(PRESS, 10, 20), END } },

	{ "lift we never saw come down", NULL,
	  { { 'u', 10, 20, 0 }, { 'n', 0, 0, 10 }, { 't', 0, 0, 900 },
	    { 0 } },
	  { END } },

	{ "long press then drag", NULL,
	  { { 'd', 10, 10, 0 }, { 't', 0, 0, 600 }, { 'd', 40, 10, 700 },
	    { 'u', 40, 10, 800 }, { 0 } },
	  { EV(DOWN, 10, 10), EV(LONGPRESS, 10, 10), SC(40, 10, 30, 0),
	    EV(UP, 40, 10), END } },

	{ "tight regime", &tight,
	  { { 'd', 10, 10, 0 }, { 'd', 12, 12, 30 }, { 'd', 13, 12, 50 },
	    { 0 } },
	  { EV(DOWN, 10, 10), SC(13, 12, 3, 2), END } },

	{ "tight regime long press", &tight,
	  { { 'd', 10, 10, 0 }, { 't', 0, 0, 100 }, { 0 } },
	  { EV(DOWN, 10, 10), EV(LONGPRESS, 10, 10), END } },
};

static void
test_classifier(void)
{
	size_t n;
	int m;

	for (n = 0; n < LWS_ARRAY_SIZE(cls_tests); n++) {
		const cls_test_t *t = &cls_tests[n];
		lws_touch_classify_t c;
		evlog_t l;

		memset(&c, 0, sizeof(c));
		memset(&l, 0, sizeof(l));
		c.regime = t->regime;

		for (m = 0; t->steps[m].sample; m++) {
			const step_t *st = &t->steps[m];
			lws_touch_sample_t s;

			if (st->sample == 't') {
				lws_touch_classify_timeout(&c, MS(st->ms),
							   evlog_cb, &l);
				continue;
			}

			s.x = st->x;
			s.y = st->y;
			s.down = st->sample == 'd';
			s.has_pos = st->sample != 'n';
			lws_touch_classify_sample(&c, &s, MS(st->ms),
						  evlog_cb, &l);
		}

		for (m = 0; (int)t->expect[m].type != -1; m++) {
			const lws_touch_event_t *e = &t->expect[m];

			if (m >= l.count) {
				check(0, "%s: missing event %d\n", t->name, m);
				break;
			}
			check(!memcmp(e, &l.ev[m], sizeof(*e)),
			      "%s: event %d: got %d %d,%d %d,%d, expected "
			      "%d %d,%d %d,%d\n", t->name, m, l.ev[m].type,
			      l.ev[m].x, l.ev[m].y, l.ev[m].dx, l.ev[m].dy,
			      e->type, e->x, e->y, e->dx, e->dy);
		}
		check(l.count == m, "%s: %d events, expected %d\n", t->name,
		      l.count, m);
	}

	/* the deadline is only there while waiting to see if it's long */
	{
		lws_touch_sample_t s = { 1, 1, 1, 1 };
		lws_touch_classify_t c;
		evlog_t l;

		memset(&c, 0, sizeof(c));
		memset(&l, 0, sizeof(l));
		check(!lws_touch_classify_deadline(&c), "idle deadline\n");
		lws_touch_classify_sample(&c, &s, MS(1000), evlog_cb, &l);
		check(lws_touch_classify_deadline(&c) == MS(1500),
		      "down deadline\n");
		lws_touch_classify_timeout(&c, MS(1500), evlog_cb, &l);
		check(!lws_touch_classify_deadline(&c), "long deadline\n");
	}
}

/*
 * Part 2: CST816S controllers on a simulated bus
 */

#define RESET_GPIO	13
#define IRQ_GPIO	5

typedef struct {
	lws_i2c_ops_t		ops; /* must be first */
	uint8_t			regs[256];
	uint8_t			ptr;
	uint8_t			asleep;	/* NAKs its address, like the chip */
	uint8_t			phase;	/* 0 address, 1 register, 2 data */
} sim_cst816s_t;

static int
sim_init(const lws_i2c_ops_t *o)
{
	(void)o;
	return 0;
}

static int
sim_start(const lws_i2c_ops_t *o)
{
	((sim_cst816s_t *)o)->phase = 0;
	return 0;
}

static void
sim_stop(const lws_i2c_ops_t *o)
{
	(void)o;
}

static int
sim_write(const lws_i2c_ops_t *o, uint8_t data)
{
	sim_cst816s_t *d = (sim_cst816s_t *)o;

	switch (d->phase) {
	case 0:
		if (d->asleep || (data >> 1) != LWS_CST816S_I2C7_ADS)
			return 1;
		d->phase = (data & 1) ? 2 : 1;
		return 0;
	case 1:
		d->ptr = data;
		d->phase = 2;
		return 0;
	default:
		d->regs[d->ptr++] = data;
		return 0;
	}
}

static int
sim_read(const lws_i2c_ops_t *o)
{
	sim_cst816s_t *d = (sim_cst816s_t *)o;

	return d->regs[d->ptr++];
}

static void
sim_set_ack(const lws_i2c_ops_t *o, int ack)
{
	(void)o;
	(void)ack;
}

static sim_cst816s_t sim = {
	.ops = {
		.init		= sim_init,
		.start		= sim_start,
		.stop		= sim_stop,
		.write		= sim_write,
		.read		= sim_read,
		.set_ack	= sim_set_ack,
	},
};

/* the finger, as the chip reports it in its registers 0x01 - 0x06 */

static void
sim_finger(int down, int x, int y)
{
	sim.asleep	= 0;
	sim.regs[1]	= 0;	/* its gesture classification, not used */
	sim.regs[2]	= (uint8_t)!!down;
	sim.regs[3]	= (uint8_t)(0x40 | ((x >> 8) & 0xf)); /* flags too */
	sim.regs[4]	= (uint8_t)x;
	sim.regs[5]	= (uint8_t)((y >> 8) & 0xf);
	sim.regs[6]	= (uint8_t)y;
}

/* the gpio, recording what happens to the reset line */

static lws_usec_t us_reset_low, us_reset_high;

static void
sim_gpio_mode(_lws_plat_gpio_t gpio, int flags)
{
	if (gpio == RESET_GPIO && (flags & LWSGGPIO_FL_WRITE) &&
	    (flags & LWSGGPIO_FL_START_LOW))
		us_reset_low = lws_now_usecs();
}

static int
sim_gpio_read(_lws_plat_gpio_t gpio)
{
	(void)gpio;
	return 1;
}

static void
sim_gpio_set(_lws_plat_gpio_t gpio, int val)
{
	if (gpio != RESET_GPIO)
		return;
	if (!val)
		us_reset_low = lws_now_usecs();
	else
		us_reset_high = lws_now_usecs();
}

static int
sim_gpio_irq_mode(_lws_plat_gpio_t gpio, lws_gpio_irq_t irq,
		  lws_gpio_irq_cb_t cb, void *arg)
{
	(void)gpio;
	(void)irq;
	(void)cb;
	(void)arg;
	return 0;
}

static const lws_gpio_ops_t sim_gpio = {
	.mode		= sim_gpio_mode,
	.read		= sim_gpio_read,
	.set		= sim_gpio_set,
	.irq_mode	= sim_gpio_irq_mode,
};

/* as fitted to a 240px round panel, and the touches are its pixels */

static const lws_touch_cst816s_t ta = {
	.touch = {
		lws_touch_cst816s_ops,
		.gpio		= &sim_gpio,
		.name		= "ta",
		.wh_native	= { 240, 240 },
		.wh_px		= { 240, 240 },
		.irq_gpio	= IRQ_GPIO,
		.irq_edge	= LWSGGPIO_IRQ_FALLING,
	},
	.i2c			= &sim.ops,
	.reset_gpio		= RESET_GPIO,
	.has_reset_gpio		= 1,
};

/* the same panel turned on its side, over a 120px display */

static const lws_touch_cst816s_t tb = {
	.touch = {
		lws_touch_cst816s_ops,
		.gpio		= &sim_gpio,
		.name		= "tb",
		.wh_native	= { 240, 240 },
		.wh_px		= { 120, 120 },
		.irq_gpio	= IRQ_GPIO,
		.irq_edge	= LWSGGPIO_IRQ_FALLING,
		.flags		= LWSTOUCH_FL_SWAP_XY | LWSTOUCH_FL_INVERT_X,
	},
	.i2c			= &sim.ops,
};

static const char * const expect_smd[] = {
	/* ta: a tap */
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"down\",\"x\":10,\"y\":20}",
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"up\",\"x\":10,\"y\":20}",
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"press\",\"x\":10,\"y\":20}",
	/* tb: a tap, mapped, the chip asleep again before it was read */
	"{\"type\":\"touch\",\"src\":\"tb\",\"event\":\"down\",\"x\":109,\"y\":5}",
	"{\"type\":\"touch\",\"src\":\"tb\",\"event\":\"up\",\"x\":109,\"y\":5}",
	"{\"type\":\"touch\",\"src\":\"tb\",\"event\":\"press\",\"x\":109,\"y\":5}",
	/* ta: a coordinate off the panel, clamped, then a drag back */
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"down\",\"x\":239,\"y\":239}",
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"scroll\",\"x\":200,\"y\":239,\"dx\":-39,\"dy\":0}",
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"up\",\"x\":200,\"y\":239}",
	/* ta: held */
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"down\",\"x\":100,\"y\":100}",
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"longpress\",\"x\":100,\"y\":100}",
	"{\"type\":\"touch\",\"src\":\"ta\",\"event\":\"up\",\"x\":100,\"y\":100}",
};

static struct lws_touch_state *tsa, *tsb;
static lws_sorted_usec_list_t sul_step;
static struct lws_context *cx;
static int smd_seen, step, done;

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{
	const char *e;

	(void)opaque;
	(void)timestamp;

	if (!(_class & LWSSMDCL_INTERACTION))
		return 0;

	if (smd_seen >= (int)LWS_ARRAY_SIZE(expect_smd)) {
		check(0, "unexpected smd %.*s\n", (int)len, (const char *)buf);
		return 0;
	}

	e = expect_smd[smd_seen++];
	check(strlen(e) == len && !memcmp(e, buf, len),
	      "smd %d: got %.*s, expected %s\n", smd_seen - 1, (int)len,
	      (const char *)buf, e);

	return 0;
}

/* each step lets the event loop run, for reset sequencing and smd */

static void
next_step(lws_sorted_usec_list_t *sul)
{
	lws_usec_t later = MS(20);

	switch (step++) {
	case 0:
		/* both reset, or not, and ready */
		check(us_reset_low && us_reset_high &&
		      us_reset_high - us_reset_low >= MS(50),
		      "reset low %lld high %lld\n", (long long)us_reset_low,
		      (long long)us_reset_high);

		sim_finger(1, 10, 20);
		lws_touch_service(tsa);
		sim_finger(0, 10, 20);
		lws_touch_service(tsa);

		sim_finger(1, 10, 20);
		lws_touch_service(tsb);
		sim.asleep = 1;
		lws_touch_service(tsb);
		lws_touch_service(tsb); /* the lift is only reported once */
		break;

	case 1:
		sim_finger(1, 0xfff, 0xfff);
		lws_touch_service(tsa);
		sim_finger(1, 200, 0xfff);
		lws_touch_service(tsa);
		sim_finger(0, 200, 0xfff);
		lws_touch_service(tsa);

		sim_finger(1, 100, 100);
		lws_touch_service(tsa);
		later = MS(600);
		break;

	case 2:
		/* still there, this chip keeps reporting while it's held */
		lws_touch_service(tsa);
		sim_finger(0, 100, 100);
		lws_touch_service(tsa);
		break;

	default:
		done = 1;
		lws_cancel_service(cx); /* don't wait in poll for more */
		return;
	}

	lws_sul_schedule(cx, 0, sul, next_step, later);
}

static void
test_controllers(void)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.early_smd_cb = smd_cb;
	info.early_smd_class_filter = LWSSMDCL_INTERACTION;

	cx = lws_create_context(&info);
	if (!cx) {
		check(0, "context creation failed\n");
		return;
	}

	tsa = lws_touch_create(cx, &ta.touch);
	tsb = lws_touch_create(cx, &tb.touch);
	check(tsa && tsb, "touch create failed\n");

	if (tsa && tsb) {
		/* give the reset time to complete */
		lws_sul_schedule(cx, 0, &sul_step, next_step, MS(200));

		while (!done && lws_service(cx, 0) >= 0)
			;
	}

	check(smd_seen == (int)LWS_ARRAY_SIZE(expect_smd),
	      "saw %d smd, expected %d\n", smd_seen,
	      (int)LWS_ARRAY_SIZE(expect_smd));

	lws_touch_destroy(&tsa);
	lws_touch_destroy(&tsb);
	check(!tsa && !tsb, "destroy didn't clear\n");

	lws_context_destroy(cx);
}

int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: touch\n");

	test_classifier();
	test_controllers();

	if (fails) {
		lwsl_err("%s: %d touch tests failed\n", __func__, fails);
		return 1;
	}

	lwsl_user("Passed all touch tests\n");

	return 0;
}
