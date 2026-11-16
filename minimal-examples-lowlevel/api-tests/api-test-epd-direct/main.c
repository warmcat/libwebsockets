/*
 * lws-api-test-epd-direct
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the driver for EPD panels with no controller of their own, against a
 * simulated panel.  The simulated transport keeps, for each pixel, where its
 * ink is between black (0) and white (INK_STEPS), and moves it one step for
 * each pass it is driven in, as the drive codes latched in its source driver
 * say.  So whatever the driver does, what the simulated panel ends up showing
 * is what the real one would, if the waveforms were right for it.
 *
 * It checks
 *
 *  - the clear after init ends with the panel white whatever it showed
 *  - an update ends with the panel showing what was blitted, and rows with
 *    nothing changing on them aren't driven
 *  - transitions of different lengths in an update end on the same pass
 *  - a row is only ever stepped over with "no drive" latched
 *  - a row whose pixels were written with some drive is written with no
 *    drive before it's stepped over, and none still holds a drive when an
 *    update is said to be complete, since active-matrix pixels go on being
 *    driven by what was last written to them
 *  - a row's data isn't changed while it's being sent, since the driver
 *    prepares the next row then
 *  - two updates started passes apart are both in flight at once
 *  - a pixel changed back while it's still moving finishes moving, then
 *    moves back
 *  - a full refresh clears the panel every so many updates
 *  - asked to, the next update committed starts with a clear, and only that
 *    one
 *  - rows are driven for the clear's drive time in its passes, and the
 *    updates' in theirs
 *  - a line blitted without pixels is white
 *  - the supplies are turned off after the passes are done
 *  - with grey levels, pixels move from whatever level they're at to the
 *    one wanted, both ways, a display with fewer levels than its waveform
 *    has its levels spread over the waveform's, and updates start on a pass
 *    that's a multiple of 4
 *  - a pixel whose span has a transition in flight waits for it to finish,
 *    unless spans are a single pixel
 *
 * Where there are pthreads, it then does it all again with the passes run on
 * a thread of their own, the way a platform's runner would, to check the two
 * sides of the driver only share what they should.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

#if defined(LWS_HAVE_PTHREAD_H) && (defined(__GNUC__) || defined(__clang__))
#define TEST_THREADS
#if defined(WIN32)
/* the ucrt time.h already defined it, don't let pthreads-win32 do it again */
#define HAVE_STRUCT_TIMESPEC
#endif
#include <pthread.h>
#include <errno.h>
#include <time.h>
#endif

static int fails;
static struct lws_context *cx;

#define check(cond, ...) do { if (!(cond)) { \
		lwsl_err("%s:%d: " #cond "\n", __func__, __LINE__); \
		lwsl_err(__VA_ARGS__); fails++; } } while (0)

/*
 * A small panel, whose rows aren't a whole number of 32-pixel words, nor of
 * 8-pixel pairs of bus bytes
 */

#define W		68
#define H		12
#define ROW_BYTES	(W / 4)
#define TAIL		2
#define INK_STEPS	4
#define GREY_LEVELS	16
#define GREY_PASSES	(GREY_LEVELS - 1)
#define MAX_PASSES	512

#define DRIVE_NS	10000
#define CLEAR_DRIVE_NS	25000

#define CODE_NONE	0
#define CODE_BLACK	1
#define CODE_WHITE	2

/*
 * The events the test waits for happen in suls, at the start of an
 * lws_service(), which would then wait in poll for something else to happen.
 * They wake it, so it returns to the test's loop
 */

#define wake() lws_cancel_service(cx)

/*
 * With a runner thread, its side writes some of the simulated panel's counts
 * while the test reads them
 */

#if defined(TEST_THREADS)
#define aget(_p)	__atomic_load_n(_p, __ATOMIC_ACQUIRE)
#define aset(_p, _v)	__atomic_store_n(_p, _v, __ATOMIC_RELEASE)
#define ainc(_p)	__atomic_fetch_add(_p, 1, __ATOMIC_ACQ_REL)
#else
#define aget(_p)	(*(_p))
#define aset(_p, _v)	(*(_p) = (_v))
#define ainc(_p)	((*(_p))++)
#endif

/* the simulated panel */

static struct {
	uint8_t		ink[H][W];
	const uint8_t	*sending;
	/**< like a DMA, the data isn't read until it's latched */
	uint8_t		loaded[ROW_BYTES + TAIL];
	/**< what it was at row_load(), to see it isn't changed */
	uint8_t		latched[ROW_BYTES + TAIL];
	int		driven[MAX_PASSES][H];
	/**< a pixel on the row was driven in that pass, 1 black, 2 white,
	 * 3 both */
	uint32_t	drive_ns[MAX_PASSES];
	/**< how long rows were driven for in that pass, 0 if none were */
	uint8_t		ink_min[H][W];
	int		px_first[H][W];
	int		px_last[H][W];
	/**< the first and last pass the pixel was driven in, or -1 */
	int		charged[H];
	/**< like a real active-matrix panel, the row's pixels go on being
	 * driven with what was last written to them until they're written
	 * again: it was last written with some drive */
	int		row;
	int		passes;
	int		powered;
	int		power_ons;
	int		power_offs;
	int		bad_skips;
	int		bad_frames;
	int		bad_loads;
	int		bad_buffers;
	int		bad_drives;
	int		bad_charged;
	int		encodes_16l;
	/**< calls of the bus' encode_16l */
} sim;

static int
sim_init(const lws_epd_direct_bus_ops_t *bus)
{
	(void)bus;

	return 0;
}

static int
sim_power(const lws_epd_direct_bus_ops_t *bus, int on)
{
	(void)bus;

	aset(&sim.powered, on);
	if (on)
		ainc(&sim.power_ons);
	else
		ainc(&sim.power_offs);
	wake();

	return 0;
}

static void
sim_frame_start(const lws_epd_direct_bus_ops_t *bus)
{
	(void)bus;

	if (!aget(&sim.powered))
		sim.bad_frames++;
	sim.row = 0;
}

static void
sim_row_load(const lws_epd_direct_bus_ops_t *bus, const uint8_t *data,
	     size_t len)
{
	(void)bus;

	if (len != sizeof(sim.loaded)) {
		sim.bad_loads++;
		return;
	}

	sim.sending = data;
	memcpy(sim.loaded, data, len);
}

/*
 * How far the simulated ink goes from black to white.  For black and white,
 * the waveforms saturate it; for grey levels, it moves a step per level, and
 * the waveforms move it exactly
 */
static int ink_max = INK_STEPS;

/* move the ink of the current row as the latched codes say */

static void
sim_apply(void)
{
	int x, c, d = 0;

	if (sim.row >= H) {
		sim.bad_frames++;
		return;
	}

	for (x = 0; x < W; x++) {
		uint8_t *ink = &sim.ink[sim.row][x];

		/* first pixel of a byte in the two most significant bits */
		c = (sim.latched[x / 4] >> ((3 - (x & 3)) * 2)) & 3;

		if (c == CODE_BLACK) {
			if (*ink)
				(*ink)--;
			d |= 1;
		}
		if (c == CODE_WHITE) {
			if (*ink < ink_max)
				(*ink)++;
			d |= 2;
		}
		if (*ink < sim.ink_min[sim.row][x])
			sim.ink_min[sim.row][x] = *ink;
		if ((c == CODE_BLACK || c == CODE_WHITE) &&
		    sim.passes < MAX_PASSES) {
			if (sim.px_first[sim.row][x] < 0)
				sim.px_first[sim.row][x] = sim.passes;
			sim.px_last[sim.row][x] = sim.passes;
		}
	}

	/* the tail must not drive anything */

	for (x = ROW_BYTES; x < ROW_BYTES + TAIL; x++)
		if (sim.latched[x] != CODE_NONE)
			sim.bad_loads++;

	if (sim.passes < MAX_PASSES)
		sim.driven[sim.passes][sim.row] |= d;
}

static void
sim_row_drive(const lws_epd_direct_bus_ops_t *bus, uint32_t drive_ns)
{
	(void)bus;

	/* every row driven in a pass is driven for the same time */

	if (sim.passes < MAX_PASSES) {
		if (!sim.drive_ns[sim.passes])
			sim.drive_ns[sim.passes] = drive_ns;
		else if (sim.drive_ns[sim.passes] != drive_ns)
			sim.bad_drives++;
	}

	if (!sim.sending) {
		sim.bad_loads++;
		return;
	}
	if (memcmp(sim.sending, sim.loaded, sizeof(sim.loaded)))
		sim.bad_buffers++;
	memcpy(sim.latched, sim.sending, sizeof(sim.latched));
	sim.sending = NULL;
	sim_apply();

	/* what's written to the row stays on its pixels */

	if (sim.row < H) {
		size_t n;

		sim.charged[sim.row] = 0;
		for (n = 0; n < ROW_BYTES; n++)
			if (sim.latched[n] != CODE_NONE)
				sim.charged[sim.row] = 1;
	}
	sim.row++;
}

static void
sim_row_skip(const lws_epd_direct_bus_ops_t *bus)
{
	size_t n;

	(void)bus;

	/* whatever's latched is driven onto the row we step over */

	for (n = 0; n < sizeof(sim.latched); n++)
		if (sim.latched[n] != CODE_NONE)
			sim.bad_skips++;

	/*
	 * Stepping over a row whose pixels still hold a drive leaves them
	 * moving: they must have been written with no drive first
	 */

	if (sim.row < H && sim.charged[sim.row])
		sim.bad_charged++;

	sim_apply();
	sim.row++;
}

static void
sim_frame_end(const lws_epd_direct_bus_ops_t *bus)
{
	(void)bus;

	if (sim.row != H)
		sim.bad_frames++;
	ainc(&sim.passes);
	wake();
}

/*
 * A bus that encodes the most common rows itself, as a platform might do it
 * faster.  This one does it just as the description of .encode_16l says, so
 * the driver's tables for it, and its use of it for runs of words with every
 * pixel in flight, are checked.
 */

static uint32_t
sim_encode_16l(uint8_t *out, const uint8_t *ft, const uint8_t *starts,
	       size_t words, const void *tables)
{
	const uint8_t *t = (const uint8_t *)tables;
	const uint32_t *codes = (const uint32_t *)(const void *)
						(t + LWS_EPDD_16L_CODES);
	uint8_t none = t[LWS_EPDD_16L_NONE], b;
	size_t x, p, n = words * 32;
	unsigned int j, st;
	uint32_t any = 0;

	if (((uintptr_t)out & 7) || ((uintptr_t)ft & 15) ||
	    ((uintptr_t)tables & 15))
		sim.bad_loads++;

	for (x = 0; x < n; x += 4) {
		b = 0;
		for (j = 0; j < 4; j++) {
			p = x + j;
			st = (starts[p / 16] >> (((p / 8) & 1) * 4)) & 0xf;
			b = (uint8_t)(b | ((codes[st << 8 | ft[p]] & 3) <<
								(6 - 2 * j)));
		}
		out[x / 4] = b;
		any |= (uint32_t)(b ^ none);
	}

	ainc(&sim.encodes_16l);

	return any;
}

#define SIM_BUS_OPS \
	.init			= sim_init, \
	.power			= sim_power, \
	.frame_start		= sim_frame_start, \
	.row_load		= sim_row_load, \
	.row_drive		= sim_row_drive, \
	.row_skip		= sim_row_skip, \
	.frame_end		= sim_frame_end, \
	.row_tail_bytes		= TAIL

static const lws_epd_direct_bus_ops_t sim_bus = {
	SIM_BUS_OPS,
}, sim_bus_16l = {
	SIM_BUS_OPS,
	.encode_16l		= sim_encode_16l,
};

static const lws_epd_direct_panel_t sim_panel = {
	.name			= "simulated",
	.source_px		= W,
	.gate_rows		= H,
	.code_black		= CODE_BLACK,
	.code_white		= CODE_WHITE,
	.code_none		= CODE_NONE,
	.ckv_max_hz		= 200000,
	.min_pass_us		= 100,
};

#define N LWS_EPDD_NONE
#define B LWS_EPDD_BLACK
#define Wh LWS_EPDD_WHITE

/*
 * Going black drives in fewer passes than going white, and not in the first
 * three, so in an update with both, it starts driving three passes later
 */

#define BLACK_LEAD	3

static const uint8_t bw_update[] = {
	/* to black, from black, white;  to white, from black, white */
	LWS_EPDD_PACK2(N, N),	LWS_EPDD_PACK2(Wh, N),
	LWS_EPDD_PACK2(N, N),	LWS_EPDD_PACK2(Wh, N),
	LWS_EPDD_PACK2(N, N),	LWS_EPDD_PACK2(Wh, N),
	LWS_EPDD_PACK2(N, B),	LWS_EPDD_PACK2(Wh, N),
	LWS_EPDD_PACK2(N, B),	LWS_EPDD_PACK2(Wh, N),
	LWS_EPDD_PACK2(N, B),	LWS_EPDD_PACK2(Wh, N),
	LWS_EPDD_PACK2(N, B),	LWS_EPDD_PACK2(Wh, N),
}, clear[] = { B, B, B, B, Wh, Wh, Wh, Wh };

#define BW_PASSES	(LWS_ARRAY_SIZE(bw_update) / 2)
#define BW_BLACK_PASSES	(BW_PASSES - BLACK_LEAD)

static const lws_epd_direct_waveform_t sim_wf = {
	.update			= bw_update,
	.update_passes		= BW_PASSES,
	.levels			= 2,
	.clear			= clear,
	.clear_len		= LWS_ARRAY_SIZE(clear),
	.drive_ns		= DRIVE_NS,
	.clear_drive_ns		= CLEAR_DRIVE_NS,
};

/*
 * 16 grey levels, for a simulated ink that moves exactly a level per pass
 * driven.  A transition drives towards where it's going in its last passes,
 * as many as the levels it moves, so they all end together.  Its clear
 * saturates the ink black, then white.
 */

static uint8_t grey_update[GREY_PASSES][GREY_LEVELS][GREY_LEVELS / 4],
	       grey_clear[2 * GREY_PASSES];

static const lws_epd_direct_waveform_t grey_wf = {
	.update			= &grey_update[0][0][0],
	.update_passes		= GREY_PASSES,
	.levels			= GREY_LEVELS,
	.clear			= grey_clear,
	.clear_len		= LWS_ARRAY_SIZE(grey_clear),
	.drive_ns		= DRIVE_NS,
	.clear_drive_ns		= CLEAR_DRIVE_NS,
}, grey_cycle_wf = {
	/* the same, driving for a different time in each pass of 4 */
	.update			= &grey_update[0][0][0],
	.update_passes		= GREY_PASSES,
	.levels			= GREY_LEVELS,
	.clear			= grey_clear,
	.clear_len		= LWS_ARRAY_SIZE(grey_clear),
	.drive_ns		= DRIVE_NS,
	.drive_cycle_ns		= { 4 * DRIVE_NS, DRIVE_NS / 10,
				    DRIVE_NS / 5, DRIVE_NS / 2 },
	.clear_drive_ns		= CLEAR_DRIVE_NS,
};

static void
build_grey_wf(void)
{
	int p, t, f, d, c;

	for (p = 0; p < GREY_PASSES; p++)
		for (t = 0; t < GREY_LEVELS; t++)
			for (f = 0; f < GREY_LEVELS; f++) {
				d = t > f ? t - f : f - t;
				c = p < GREY_PASSES - d ? N : (t > f ? Wh : B);
				grey_update[p][t][f >> 2] = (uint8_t)
					(grey_update[p][t][f >> 2] |
					 (c << (6 - 2 * (f & 3))));
			}

	for (p = 0; p < (int)LWS_ARRAY_SIZE(grey_clear); p++)
		grey_clear[p] = p < GREY_PASSES ? B : Wh;
}

/*
 * Palettes, and the Y given for each level when we blit it.  The palettes are
 * in the linear light the blitted Y is turned into before it's matched to
 * them, so the Y for each level are the ones that become exactly that.
 */

static const lws_display_colour_t palette[] = {
	PALETTE_RGBY(0, 0, 0),
	PALETTE_RGBY(255, 255, 255),
}, palette4[] = {
	PALETTE_RGBY(0, 0, 0),
	PALETTE_RGBY(22, 22, 22),
	PALETTE_RGBY(104, 104, 104),
	PALETTE_RGBY(255, 255, 255),
}, palette16[] = {
#define P(_y) PALETTE_RGBY(_y, _y, _y)
	P(0), P(1), P(3), P(7), P(13), P(22), P(33), P(47),
	P(63), P(82), P(104), P(128), P(156), P(186), P(219), P(255),
#undef P
};

static const uint8_t y_bw[] = { 0, 255 },
		     y4[] = { 0, 85, 170, 255 },
		     y16[] = { 0, 21, 34, 51, 68, 85, 102, 119,
			       136, 153, 170, 187, 204, 221, 238, 255 };

/* what each run of the tests drives */

typedef struct {
	const char			*name;
	const lws_display_colour_t	*palette;
	const uint8_t			*y;
	const lws_epd_direct_waveform_t	*wf;
	int				levels;
	/**< the display's levels */
	int				ink_max;
	int				span;
	/**< start_span_px */
	const lws_epd_direct_bus_ops_t	*bus;
} config_t;

static const config_t configs[] = {
	{ "black and white", palette, y_bw, &sim_wf, 2, INK_STEPS, 0,
								&sim_bus },
	{ "16 levels", palette16, y16, &grey_wf, 16, GREY_PASSES, 0,
								&sim_bus },
	{ "16 levels, the bus encoding rows", palette16, y16, &grey_wf, 16,
						GREY_PASSES, 0, &sim_bus_16l },
	{ "4 of 16 levels, 1-px spans", palette4, y4, &grey_wf, 4,
						GREY_PASSES, 1, &sim_bus },
	{ "16 levels, a drive cycle", palette16, y16, &grey_cycle_wf, 16,
						GREY_PASSES, 0, &sim_bus },
};

static const config_t *cfg = &configs[0];

static int cb1, cb2;

static int
completion_cb(lws_display_state_t *lds, int a)
{
	(void)lds;

	if (a == 1)
		cb1++;
	if (a == 2)
		cb2++;
	wake();

	return 0;
}

static lws_display_epd_direct_t disp = {
	.disp = {
		lws_display_epd_direct_ops,
		.ic = {
			.wh_px		= { { W, 0 }, { H, 0 } },
			.palette	= palette,
			.palette_depth	= LWS_ARRAY_SIZE(palette),
			.type		= LWSSURF_PALETTE,
			.greyscale	= 1,
		},
		.name			= "simulated EPD",
	},
	.panel				= &sim_panel,
	.wf				= &sim_wf,
	.bus				= &sim_bus,
	.cb				= completion_cb,
	.power_off_idle_ms		= 5,
};

static lws_display_state_t lds;

static int
lds_runner(void)
{
	return disp.runner != NULL;
}

/* the levels we last blitted, 0 black to cfg->levels - 1 white */
static uint8_t want[H][W];

static int
lds_runner(void);

static void
service_until(int *what, int count)
{
	lws_usec_t until = lws_now_usecs() + 5 * LWS_US_PER_SEC;

	while (aget(what) < count && lws_now_usecs() < until)
		if (lws_service(cx, 0) < 0)
			break;

	check(aget(what) >= count, "timed out waiting\n");
}

#if defined(TEST_THREADS)

/*
 * A runner on a thread of its own, like a platform's.  So the tests can do
 * things between particular passes, it can be held before a pass.
 */

static struct {
	lws_epd_direct_runner_t	r;
	pthread_t		thread;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	lws_display_state_t	*lds;
	int			kicked;
	int			hold_at;
	/**< -1, or don't start a pass once there have been this many */
	int			held;
} tr;

static void *
tr_thread(void *a)
{
	lws_usec_t us;
	struct timespec ts;

	(void)a;

	pthread_mutex_lock(&tr.lock);

	for (;;) {
		while (tr.hold_at >= 0 && aget(&sim.passes) >= tr.hold_at) {
			tr.held = 1;
			wake();
			pthread_cond_wait(&tr.cond, &tr.lock);
		}
		tr.held = 0;
		tr.kicked = 0;

		pthread_mutex_unlock(&tr.lock);
		us = lws_display_epd_direct_service(tr.lds);
		pthread_mutex_lock(&tr.lock);

		if (us == LWS_EPDD_SVC_STOP)
			break;
		if (tr.kicked)
			continue;

		if (us == LWS_EPDD_SVC_IDLE) {
			pthread_cond_wait(&tr.cond, &tr.lock);
			continue;
		}

		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += (time_t)(us / LWS_US_PER_SEC);
		ts.tv_nsec += (long)(us % LWS_US_PER_SEC) * 1000;
		if (ts.tv_nsec >= 1000000000) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000;
		}
		pthread_cond_timedwait(&tr.cond, &tr.lock, &ts);
	}

	pthread_mutex_unlock(&tr.lock);

	return NULL;
}

static int
tr_start(const lws_epd_direct_runner_t *r, lws_display_state_t *l)
{
	(void)r;

	tr.lds = l;
	tr.hold_at = -1;

	return pthread_create(&tr.thread, NULL, tr_thread, NULL);
}

static void
tr_kick(const lws_epd_direct_runner_t *r)
{
	(void)r;

	pthread_mutex_lock(&tr.lock);
	tr.kicked = 1;
	pthread_cond_signal(&tr.cond);
	pthread_mutex_unlock(&tr.lock);
}

static void
tr_stop(const lws_epd_direct_runner_t *r)
{
	pthread_mutex_lock(&tr.lock);
	tr.hold_at = -1;
	pthread_mutex_unlock(&tr.lock);

	tr_kick(r);
	pthread_join(tr.thread, NULL);
}

static const lws_epd_direct_runner_t tr_runner = {
	.start		= tr_start,
	.kick		= tr_kick,
	.stop		= tr_stop,
};

#endif

/*
 * Don't let a runner on its own thread start a pass once there have been a
 * number of passes, until release() is called.  This must be done before
 * what's committed can start passes, or the runner may already be past it.
 */

static void
hold_from(int passes)
{
#if defined(TEST_THREADS)
	if (lds_runner()) {
		pthread_mutex_lock(&tr.lock);
		tr.hold_at = passes;
		pthread_cond_signal(&tr.cond);
		pthread_mutex_unlock(&tr.lock);
	}
#else
	(void)passes;
#endif
}

/* wait until the runner is held after the passes given to hold_from() */

static void
hold_at(int passes)
{
#if defined(TEST_THREADS)
	lws_usec_t until = lws_now_usecs() + 5 * LWS_US_PER_SEC;
	int held = 0;

	if (lds_runner()) {
		while (!held && lws_now_usecs() < until) {
			pthread_mutex_lock(&tr.lock);
			held = tr.held;
			pthread_mutex_unlock(&tr.lock);
			if (!held && lws_service(cx, 0) < 0)
				break;
		}
		check(held, "runner not held\n");
		check(aget(&sim.passes) == passes, "held at pass %d, not %d\n",
		      aget(&sim.passes), passes);

		return;
	}
#endif

	/* without a runner, a pass is one lws_service() */
	service_until(&sim.passes, passes);
}

static void
release(void)
{
#if defined(TEST_THREADS)
	if (lds_runner()) {
		pthread_mutex_lock(&tr.lock);
		tr.hold_at = -1;
		pthread_cond_signal(&tr.cond);
		pthread_mutex_unlock(&tr.lock);
	}
#endif
}

static void
blit_start(void)
{
	lws_box_t box;

	memset(&box, 0, sizeof(box));
	box.w.whole = W;
	box.h.whole = H;
	lds.disp->blit(&lds, NULL, &box, NULL);
}

static void
blit_row(int y, int null_src)
{
	uint8_t line[W];
	lws_box_t box;
	int x;

	for (x = 0; x < W; x++)
		line[x] = cfg->y[want[y][x]];

	memset(&box, 0, sizeof(box));
	box.w.whole = W;
	box.y.whole = y;
	box.h.whole = 1;
	lds.disp->blit(&lds, null_src ? NULL : line, &box, NULL);
}

static void
blit_all(void)
{
	int y;

	blit_start();
	for (y = 0; y < H; y++)
		blit_row(y, 0);
}

static void
commit(void)
{
	lws_box_t box;

	memset(&box, 0, sizeof(box));
	box.w.whole = W;
	lds.disp->blit(&lds, NULL, &box, NULL);
}

static void
check_panel(const char *what)
{
	int x, y, bad = 0;

	/* the display's levels are spread evenly over the ink */

	for (y = 0; y < H; y++)
		for (x = 0; x < W; x++)
			if (sim.ink[y][x] != want[y][x] * cfg->ink_max /
							(cfg->levels - 1))
				bad++;

	check(!bad, "%s: %d pixels wrong\n", what, bad);

	/* when it's said to be done, nothing goes on moving */

	for (y = 0, bad = 0; y < H; y++)
		bad += sim.charged[y];
	check(!bad, "%s: %d rows still hold a drive\n", what, bad);
}

/* the first and last pass a row was driven in from pass p0 */

static int
first_driven(int p0, int row)
{
	int p;

	for (p = p0; p < sim.passes && p < MAX_PASSES; p++)
		if (sim.driven[p][row])
			return p;

	return -1;
}

static int
last_driven(int p0, int row)
{
	int p, last = -1;

	for (p = p0; p < sim.passes && p < MAX_PASSES; p++)
		if (sim.driven[p][row])
			last = p;

	return last;
}

static void
set_rect(int x0, int y0, int x1, int y1, uint8_t v)
{
	int x, y;

	for (y = y0; y < y1; y++)
		for (x = x0; x < x1; x++)
			want[y][x] = v;
}

/* forget which pixels were driven when */

static void
px_reset(void)
{
	int x, y;

	for (y = 0; y < H; y++)
		for (x = 0; x < W; x++)
			sim.px_first[y][x] = sim.px_last[y][x] = -1;
}

static void
test_boot(void)
{
	int x, y;

	lwsl_user("%s\n", __func__);

	/* the panel shows something random-ish, and we don't know what */

	for (y = 0; y < H; y++)
		for (x = 0; x < W; x++)
			sim.ink[y][x] = (uint8_t)((x * 7 + y * 3) %
						  (ink_max + 1));

	memset(want, cfg->levels - 1, sizeof(want));
	lws_display_state_init(&lds, cx, -1, -1, NULL, &disp.disp);
	check(lds.priv != NULL, "init failed\n");
	if (!lds.priv)
		return;

	service_until(&cb1, 1);
	check_panel("boot clear");
	/* after the clear, a pass writes no drive to the rows it drove */

	check(sim.passes == disp.wf->clear_len + 1,
	      "clear took %d passes\n", sim.passes);
	for (x = 0; x < disp.wf->clear_len; x++)
		check(sim.drive_ns[x] == CLEAR_DRIVE_NS,
		      "clear pass %d drove for %uns\n", x,
		      (unsigned int)sim.drive_ns[x]);
	for (y = 0; y < H; y++)
		check(!sim.driven[disp.wf->clear_len][y],
		      "row %d driven after the clear\n", y);
	check(!cb2, "update completion without an update\n");

	/* after the idle time, the supplies go off */

	service_until(&sim.power_offs, 1);
	check(!aget(&sim.powered), "still powered\n");
}

static void
test_update(void)
{
	int p0 = sim.passes, y, d;

	lwsl_user("%s\n", __func__);

	set_rect(5, 2, 40, 5, 0);
	blit_all();
	commit();
	service_until(&cb2, 1);
	check_panel("update");

	for (y = 0; y < H; y++) {
		d = first_driven(p0, y);
		if (y >= 2 && y < 5)
			check(d >= 0, "row %d not driven\n", y);
		else
			check(d < 0, "row %d driven, but unchanged\n", y);
	}

	/* passes with only skipped rows drive nothing */

	for (d = p0, y = 0; d < sim.passes; d++) {
		check(sim.drive_ns[d] == DRIVE_NS || !sim.drive_ns[d],
		      "update pass %d drove for %uns\n", d,
		      (unsigned int)sim.drive_ns[d]);
		y += sim.drive_ns[d] == DRIVE_NS;
	}
	check(y, "update drove no rows\n");

	/* nothing changing is complete at once */

	blit_all();
	commit();
	check(cb2 == 2, "unchanged update not complete at once\n");
}

static void
test_aligned(void)
{
	int p0 = sim.passes, c = cb2;

	lwsl_user("%s\n", __func__);

	/* in one update, row 2 goes back to white and row 7 goes black */

	set_rect(5, 2, 40, 3, 1);
	set_rect(0, 7, 20, 8, 0);
	blit_all();
	commit();
	service_until(&cb2, c + 1);
	check_panel("aligned");

	/* the shorter transition is driven later, so they end together */

	check(last_driven(p0, 2) == last_driven(p0, 7),
	      "transitions end on passes %d and %d\n",
	      last_driven(p0, 2), last_driven(p0, 7));
	check(first_driven(p0, 7) - first_driven(p0, 2) == BLACK_LEAD,
	      "to_black started at %d, to_white at %d\n",
	      first_driven(p0, 7), first_driven(p0, 2));
}

static void
test_overlap(void)
{
	int p0 = sim.passes, target, c = cb2;

	lwsl_user("%s\n", __func__);

	/* rows 0 - 1 go black */

	set_rect(0, 0, W, 2, 0);
	blit_all();
	target = aget(&sim.passes) + 2;
	hold_from(target);
	commit();

	/*
	 * Two passes later, row 7 goes back to white.  Updates start on a
	 * multiple of 4 passes, so it starts 4 passes after the first one,
	 * which is still going.
	 */

	hold_at(target);
	set_rect(0, 7, 20, 8, 1);
	blit_all();
	commit();
	release();

	service_until(&cb2, c + 1);
	check_panel("overlap");
	check(first_driven(p0, 7) - (first_driven(p0, 0) - BLACK_LEAD) == 4,
	      "second update started %d passes after the first\n",
	      first_driven(p0, 7) - (first_driven(p0, 0) - BLACK_LEAD));
	check(first_driven(p0, 7) <= last_driven(p0, 0),
	      "updates were not in flight together (%d, %d)\n",
	      first_driven(p0, 7), last_driven(p0, 0));
}

static void
test_collision(void)
{
	int target, c = cb2;

	lwsl_user("%s\n", __func__);

	/* pixel (50, 6) goes black ... */

	sim.ink_min[6][50] = INK_STEPS;
	want[6][50] = 0;
	blit_all();
	target = aget(&sim.passes) + BLACK_LEAD + 2;
	hold_from(target);
	commit();

	/*
	 * ... and is wanted white again while it's still going.  Its update
	 * starts at once, since nothing else is in flight, and is driven
	 * black from its BLACK_LEAD'th pass
	 */

	hold_at(target);
	check(sim.ink[6][50] != 0 && sim.ink[6][50] != INK_STEPS,
	      "pixel not in between (%d)\n", sim.ink[6][50]);
	want[6][50] = 1;
	blit_all();
	commit();
	release();

	service_until(&cb2, c + 1);
	check_panel("collision");
	check(sim.ink_min[6][50] == 0, "pixel didn't finish going black\n");
}

static void
test_null_line(void)
{
	int c = cb2;

	lwsl_user("%s\n", __func__);

	/* row 3 is partly black: blitting it without pixels makes it white */

	blit_start();
	blit_row(3, 1);
	set_rect(0, 3, W, 4, 1);
	commit();
	service_until(&cb2, c + 1);
	check_panel("null line");
}

static void
test_full_refresh(void)
{
	int p0, p, y, c, full;

	lwsl_user("%s\n", __func__);

	/*
	 * Every second update clears the panel first.  Updates aren't counted
	 * while there are no full refreshes, so it's the second one from here
	 */

	disp.full_refresh_every = 2;

	c = cb2;
	set_rect(60, 10, W, H, 0);
	blit_all();
	commit();
	service_until(&cb2, c + 1);

	p0 = sim.passes;
	c = cb2;
	set_rect(60, 10, W, H, 1);
	blit_all();
	commit();
	service_until(&cb2, c + 1);
	check_panel("full refresh");

	/* a clear pass drives every row of the panel black */

	for (p = p0, full = 0; p < sim.passes; p++) {
		for (y = 0; y < H; y++)
			if (!(sim.driven[p][y] & 1))
				break;
		if (y == H)
			full++;
	}
	check(full == 4, "%d passes drove the whole panel black\n", full);

	/* the clear's passes drive for longer than the update's */

	for (p = p0; p < sim.passes; p++)
		check(sim.drive_ns[p] == CLEAR_DRIVE_NS ||
		      sim.drive_ns[p] == DRIVE_NS || !sim.drive_ns[p],
		      "pass %d drove for %uns\n", p,
		      (unsigned int)sim.drive_ns[p]);
	for (p = p0, c = 0; p < sim.passes; p++)
		c += sim.drive_ns[p] == CLEAR_DRIVE_NS;
	check(c == LWS_ARRAY_SIZE(clear), "%d passes drove for the clear's time\n",
	      c);

	disp.full_refresh_every = 0;
}

/* the clear's passes since pass p0 */

static int
clear_passes(int p0)
{
	int p, c = 0;

	for (p = p0; p < sim.passes && p < MAX_PASSES; p++)
		c += sim.drive_ns[p] == CLEAR_DRIVE_NS;

	return c;
}

static void
test_clear(void)
{
	int p0, c;

	lwsl_user("%s\n", __func__);

	/*
	 * Asked for a clear, the next update to be committed starts with one,
	 * and the panel ends up showing that update
	 */

	check(disp.disp.clear && !disp.disp.clear(&lds), "clear failed\n");

	p0 = sim.passes;
	c = cb2;
	set_rect(0, 0, 30, H, 0);
	blit_all();
	commit();
	service_until(&cb2, c + 1);
	check_panel("clear");
	check(clear_passes(p0) == (int)LWS_ARRAY_SIZE(clear),
	      "%d passes drove for the clear's time\n", clear_passes(p0));

	/* only that one */

	p0 = sim.passes;
	c = cb2;
	set_rect(0, 0, 30, H, 1);
	blit_all();
	commit();
	service_until(&cb2, c + 1);
	check_panel("after clear");
	check(!clear_passes(p0), "%d clear passes after the clear\n",
	      clear_passes(p0));
}

/*
 * Grey levels: pixels go from white to levels, then from those levels to
 * others, darker and lighter.  Everything in an update ends on the same pass.
 */

/*
 * The passes from p0 that drove pixels, of updates that all started in step
 * with the one that started on p0, drove rows for the waveform's times: if it
 * has a drive cycle, the time for where they are in it.  The pass after them
 * that only writes no drive may be driven for any of them.
 */

static void
check_drive_times(int p0, const char *what)
{
	const lws_epd_direct_waveform_t *wf = cfg->wf;
	int p, y, ph, n = 0;
	uint32_t ns;

	for (p = p0; p < aget(&sim.passes) && p < MAX_PASSES; p++) {
		for (y = 0; y < H; y++)
			if (sim.driven[p][y])
				break;
		if (y == H)
			/* no pixel was driven */
			continue;

		ph = (p - p0) & (LWS_EPDD_DRIVE_CYCLE - 1);
		ns = wf->drive_cycle_ns[0] ? wf->drive_cycle_ns[ph] :
					     wf->drive_ns;
		check(sim.drive_ns[p] == ns, "%s: pass %d drove for %uns, "
		      "not %uns\n", what, p, (unsigned int)sim.drive_ns[p],
		      (unsigned int)ns);
		n++;
	}
	check(n, "%s: no rows driven\n", what);
}

static void
test_grey_update(void)
{
	int x, y, c, p0, last;

	lwsl_user("%s\n", __func__);

	for (y = 1; y < 5; y++)
		for (x = 0; x < W; x++)
			want[y][x] = (uint8_t)((x + y) % cfg->levels);

	c = cb2;
	p0 = sim.passes;
	blit_all();
	commit();
	service_until(&cb2, c + 1);
	check_panel("grey from white");
	check_drive_times(p0, "grey from white");

	for (y = 1; y < 5; y++)
		for (x = 0; x < W; x++)
			/* a step of 1 to levels - 1, so it changes */
			want[y][x] = (uint8_t)((want[y][x] + 1 +
					x % (cfg->levels - 1)) % cfg->levels);

	c = cb2;
	p0 = sim.passes;
	px_reset();
	blit_all();
	commit();
	service_until(&cb2, c + 1);
	check_panel("grey to grey");
	check_drive_times(p0, "grey to grey");

	for (y = 1, last = -1; y < 5; y++) {
		check(last < 0 || last_driven(p0, y) == last,
		      "row %d ended on pass %d, not %d\n", y,
		      last_driven(p0, y), last);
		last = last_driven(p0, y);
	}
	check(last == p0 + GREY_PASSES - 1, "ended on pass %d, not %d\n",
	      last, p0 + GREY_PASSES - 1);
}

/*
 * A pixel goes black.  While it's still going, its neighbour in its span, and
 * one in the next span, go black too.  The one in the next span starts on the
 * next multiple of 4 passes, while the first is still going; the one in its
 * span has to wait until it's done, unless spans are a single pixel.
 */

static void
test_span(void)
{
	int c = cb2, y = 8, first, next, same, span, span_q, target, p0;

	lwsl_user("%s\n", __func__);

	span = cfg->span ? cfg->span : 8;
	px_reset();
	want[y][8] = 0;
	blit_all();
	p0 = aget(&sim.passes);
	target = p0 + 6;
	hold_from(target);
	commit();

	hold_at(target);
	want[y][9] = 0;
	want[y][16] = 0;
	blit_all();
	commit();
	release();

	service_until(&cb2, c + 1);
	check_panel("span");
	/* the second update joined in step with the first */
	check_drive_times(p0, "span");

	first = sim.px_first[y][8];
	next = sim.px_first[y][16];
	same = sim.px_first[y][9];

	check(first >= 0 && next > first && next <= sim.px_last[y][8],
	      "next span's pixel driven from %d, the first %d - %d\n", next,
	      first, sim.px_last[y][8]);
	/* check() can't have a % in its condition, it's in a format */
	span_q = (next - first) & 3;
	check(!span_q, "next span's pixel started %d passes after\n",
	      next - first);

	if (span > 1)
		check(same > sim.px_last[y][8],
		      "same span's pixel driven from %d, the first until %d\n",
		      same, sim.px_last[y][8]);
	else
		check(same == next,
		      "with 1-px spans, driven from %d, not with the other at "
		      "%d\n", same, next);
}

/*
 * Being bistable, the panel only shows something animated if the display says
 * how often it can usefully be updated for it, and then no more often than
 * that.  A display that isn't bistable can be updated as often as wanted.
 */

static void
test_anim_interval(void)
{
	lws_display_t d = disp.disp;
	lws_usec_t i;

	d.anim_hz = 0;
	i = lws_display_anim_interval(&d, 500 * LWS_US_PER_MS);
	check(!i, "animated at %dus with no .anim_hz\n", (int)i);

	d.anim_hz = 4;
	i = lws_display_anim_interval(&d, 100 * LWS_US_PER_MS);
	check(i == 250 * LWS_US_PER_MS, "%dus, not limited to 4Hz\n", (int)i);
	i = lws_display_anim_interval(&d, 500 * LWS_US_PER_MS);
	check(i == 500 * LWS_US_PER_MS, "%dus, not as asked\n", (int)i);

	d.bistable = 0;
	d.anim_hz = 0;
	i = lws_display_anim_interval(&d, 100 * LWS_US_PER_MS);
	check(i == 100 * LWS_US_PER_MS, "%dus, not as asked\n", (int)i);
}

static void
run_tests(const config_t *c, const lws_epd_direct_runner_t *runner)
{
	memset(&sim, 0, sizeof(sim));
	memset(&lds, 0, sizeof(lds));
	cb1 = cb2 = 0;
	cfg = c;
	ink_max = c->ink_max;
	disp.runner = runner;
	disp.wf = c->wf;
	disp.bus = c->bus;
	disp.start_span_px = (uint8_t)c->span;
	disp.disp.ic.palette = c->palette;
	disp.disp.ic.palette_depth = (size_t)c->levels;
	px_reset();

	lwsl_user("%s, passes run %s\n", c->name,
		  runner ? "on their own thread" : "from the event loop");

	test_boot();
	if (!lds.priv)
		return;

	if (c->levels == 2) {
		test_update();
		test_aligned();
		test_overlap();
		test_collision();
		test_null_line();
		test_full_refresh();
		test_clear();
	} else {
		int e = aget(&sim.encodes_16l);

		test_grey_update();
		test_span();

		/* it was checked at init, and must have been used since */
		if (c->bus->encode_16l)
			check(e && aget(&sim.encodes_16l) > e,
			      "the bus' encode_16l used %d times\n",
			      aget(&sim.encodes_16l));
	}

	service_until(&sim.power_offs, aget(&sim.power_ons));
	check(!aget(&sim.powered), "still powered at the end\n");
	check(!sim.bad_skips, "%d rows stepped over with drive latched\n",
	      sim.bad_skips);
	check(!sim.bad_frames, "%d bad passes\n", sim.bad_frames);
	check(!sim.bad_loads, "%d bad row loads\n", sim.bad_loads);
	check(!sim.bad_buffers, "%d rows changed while being sent\n",
	      sim.bad_buffers);
	check(!sim.bad_drives, "%d passes drove rows for different times\n",
	      sim.bad_drives);
	check(!sim.bad_charged, "%d rows stepped over still holding a drive\n",
	      sim.bad_charged);

	lwsl_user("%d passes\n", aget(&sim.passes));

	lws_display_epd_direct_destroy(&lds);
	check(!lds.priv, "destroy didn't clear\n");
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int n;

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API Test - EPD direct drive\n");

	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("context creation failed\n");
		return 1;
	}

	test_anim_interval();
	build_grey_wf();

	for (n = 0; n < (int)LWS_ARRAY_SIZE(configs); n++)
		run_tests(&configs[n], NULL);

#if defined(TEST_THREADS)
	pthread_mutex_init(&tr.lock, NULL);
	pthread_cond_init(&tr.cond, NULL);
	for (n = 0; n < (int)LWS_ARRAY_SIZE(configs); n++)
		run_tests(&configs[n], &tr_runner);
	pthread_cond_destroy(&tr.cond);
	pthread_mutex_destroy(&tr.lock);
#endif

	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
