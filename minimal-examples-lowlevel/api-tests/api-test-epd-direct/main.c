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
 *  - a row's data isn't changed while it's being sent, since the driver
 *    prepares the next row then
 *  - two updates started passes apart are both in flight at once
 *  - a pixel changed back while it's still moving finishes moving, then
 *    moves back
 *  - a full refresh clears the panel every so many updates
 *  - a line blitted without pixels is white
 *  - the supplies are turned off after the passes are done
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

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
#define MAX_PASSES	512

#define CODE_NONE	0
#define CODE_BLACK	1
#define CODE_WHITE	2

/*
 * The events the test waits for happen in suls, at the start of an
 * lws_service(), which would then wait in poll for something else to happen.
 * They wake it, so it returns to the test's loop
 */

#define wake() lws_cancel_service(cx)

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
	uint8_t		ink_min[H][W];
	int		row;
	int		passes;
	int		powered;
	int		power_ons;
	int		power_offs;
	int		bad_skips;
	int		bad_frames;
	int		bad_loads;
	int		bad_buffers;
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

	sim.powered = on;
	if (on)
		sim.power_ons++;
	else
		sim.power_offs++;
	wake();

	return 0;
}

static void
sim_frame_start(const lws_epd_direct_bus_ops_t *bus)
{
	(void)bus;

	if (!sim.powered)
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
			if (*ink < INK_STEPS)
				(*ink)++;
			d |= 2;
		}
		if (*ink < sim.ink_min[sim.row][x])
			sim.ink_min[sim.row][x] = *ink;
	}

	/* the tail must not drive anything */

	for (x = ROW_BYTES; x < ROW_BYTES + TAIL; x++)
		if (sim.latched[x] != CODE_NONE)
			sim.bad_loads++;

	if (sim.passes < MAX_PASSES)
		sim.driven[sim.passes][sim.row] |= d;
}

static void
sim_row_drive(const lws_epd_direct_bus_ops_t *bus, uint32_t drive_us)
{
	(void)bus;
	(void)drive_us;

	if (!sim.sending) {
		sim.bad_loads++;
		return;
	}
	if (memcmp(sim.sending, sim.loaded, sizeof(sim.loaded)))
		sim.bad_buffers++;
	memcpy(sim.latched, sim.sending, sizeof(sim.latched));
	sim.sending = NULL;
	sim_apply();
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

	sim_apply();
	sim.row++;
}

static void
sim_frame_end(const lws_epd_direct_bus_ops_t *bus)
{
	(void)bus;

	if (sim.row != H)
		sim.bad_frames++;
	sim.passes++;
	wake();
}

static const lws_epd_direct_bus_ops_t sim_bus = {
	.init			= sim_init,
	.power			= sim_power,
	.frame_start		= sim_frame_start,
	.row_load		= sim_row_load,
	.row_drive		= sim_row_drive,
	.row_skip		= sim_row_skip,
	.frame_end		= sim_frame_end,
	.row_tail_bytes		= TAIL,
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
 * Going black is shorter than going white, and doesn't drive in its first
 * pass, so in an update with both, it starts two passes later
 */

static const uint8_t to_black[] = { N, B, B, B, B },
		     to_white[] = { Wh, Wh, Wh, Wh, Wh, Wh, Wh },
		     clear[] = { B, B, B, B, Wh, Wh, Wh, Wh };

static const lws_epd_direct_waveform_bw_t sim_wf = {
	.to_black		= to_black,
	.to_black_len		= LWS_ARRAY_SIZE(to_black),
	.to_white		= to_white,
	.to_white_len		= LWS_ARRAY_SIZE(to_white),
	.clear			= clear,
	.clear_len		= LWS_ARRAY_SIZE(clear),
	.row_drive_us		= 10,
};

static const lws_display_colour_t palette[] = {
	PALETTE_RGBY(0, 0, 0),
	PALETTE_RGBY(255, 255, 255),
};

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
	.wf_bw				= &sim_wf,
	.bus				= &sim_bus,
	.cb				= completion_cb,
	.power_off_idle_ms		= 5,
};

static lws_display_state_t lds;

/* what we last blitted, 0 black or 1 white */
static uint8_t want[H][W];

static void
service_until(int *what, int count)
{
	lws_usec_t until = lws_now_usecs() + 5 * LWS_US_PER_SEC;

	while (*what < count && lws_now_usecs() < until)
		if (lws_service(cx, 0) < 0)
			break;

	check(*what >= count, "timed out waiting\n");
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
		line[x] = want[y][x] ? 255 : 0;

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

	for (y = 0; y < H; y++)
		for (x = 0; x < W; x++)
			if (sim.ink[y][x] != (want[y][x] ? INK_STEPS : 0))
				bad++;

	check(!bad, "%s: %d pixels wrong\n", what, bad);
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

static void
test_boot(void)
{
	int x, y;

	lwsl_user("%s\n", __func__);

	/* the panel shows something random-ish, and we don't know what */

	for (y = 0; y < H; y++)
		for (x = 0; x < W; x++)
			sim.ink[y][x] = (uint8_t)((x * 7 + y * 3) % (INK_STEPS + 1));

	memset(want, 1, sizeof(want));
	lws_display_state_init(&lds, cx, -1, -1, NULL, &disp.disp);
	check(lds.priv != NULL, "init failed\n");
	if (!lds.priv)
		return;

	service_until(&cb1, 1);
	check_panel("boot clear");
	check(sim.passes == LWS_ARRAY_SIZE(clear),
	      "clear took %d passes\n", sim.passes);
	check(!cb2, "update completion without an update\n");

	/* after the idle time, the supplies go off */

	service_until(&sim.power_offs, 1);
	check(!sim.powered, "still powered\n");
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
	check(first_driven(p0, 7) - first_driven(p0, 2) ==
		(int)(LWS_ARRAY_SIZE(to_white) - LWS_ARRAY_SIZE(to_black)) + 1,
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
	commit();

	/* two passes later, rows 8 - 9 go black too */

	target = sim.passes + 2;
	service_until(&sim.passes, target);
	set_rect(10, 8, 30, 10, 0);
	blit_all();
	commit();

	service_until(&cb2, c + 1);
	check_panel("overlap");
	check(first_driven(p0, 8) > first_driven(p0, 0),
	      "second update started first\n");
	check(first_driven(p0, 8) <= last_driven(p0, 0),
	      "updates were not in flight together (%d, %d)\n",
	      first_driven(p0, 8), last_driven(p0, 0));
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
	commit();

	/* ... and is wanted white again while it's still going */

	target = sim.passes + 3;
	service_until(&sim.passes, target);
	check(sim.ink[6][50] != 0 && sim.ink[6][50] != INK_STEPS,
	      "pixel not in between (%d)\n", sim.ink[6][50]);
	want[6][50] = 1;
	blit_all();
	commit();

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

	disp.full_refresh_every = 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API Test - EPD direct drive\n");

	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("context creation failed\n");
		return 1;
	}

	test_boot();
	if (lds.priv) {
		test_update();
		test_aligned();
		test_overlap();
		test_collision();
		test_null_line();
		test_full_refresh();

		service_until(&sim.power_offs, sim.power_ons);
		check(!sim.powered, "still powered at the end\n");
		check(!sim.bad_skips, "%d rows stepped over with drive latched\n",
		      sim.bad_skips);
		check(!sim.bad_frames, "%d bad passes\n", sim.bad_frames);
		check(!sim.bad_loads, "%d bad row loads\n", sim.bad_loads);
		check(!sim.bad_buffers, "%d rows changed while being sent\n",
		      sim.bad_buffers);

		lws_display_epd_direct_destroy(&lds);
		check(!lds.priv, "destroy didn't clear\n");
	}

	lws_context_destroy(cx);

	lwsl_user("Completed: %s (%d passes)\n", fails ? "FAIL" : "PASS",
		  sim.passes);

	return !!fails;
}
