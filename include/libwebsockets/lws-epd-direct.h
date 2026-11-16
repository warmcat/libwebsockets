/*
 * lws abstract display implementation for directly-driven EPD panels
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
 * Some EPD panels, eg, E Ink's ED047TC1, have no controller of their own: the
 * source driver chips along one edge take a row of 2-bit per-pixel drive codes
 * over a parallel bus, and the gate driver along the other edge selects which
 * row they are driven onto.  Every "frame" or "pass" scans every row, and
 * moving the ink takes many passes.  What would be the controller's job, the
 * framebuffer and choosing what each pixel is driven with in each pass, is
 * done by us.
 *
 * It's done in three parts:
 *
 *  - this generic driver, implementing lws_display_t, that knows nothing
 *    about how the bits get to the panel
 *
 *  - a description of the panel, its geometry, how its drive codes are packed
 *    on the bus, and the timing limits from its datasheet
 *
 *  - a transport, lws_epd_direct_bus_ops_t, provided by the platform, that
 *    clocks rows of drive codes into the panel and works its control lines
 *
 * Panel updates are differential: we keep what level each pixel is, or is
 * going to be, and only pixels that change are driven, wherever they are; the
 * others are given the "no drive" code.  Rows with nothing to drive are
 * stepped over quickly without loading them.  Several updates can be in
 * flight at once, started at different passes, each pixel belonging to at
 * most one of them; a pixel that changes again while it is still moving
 * starts moving to the new level when its current transition has finished.
 *
 * Pixels may have 2, 4 or 16 grey levels.  Each pixel moving runs its own
 * transition from the waveform's table, chosen by the level it is moving from
 * and the one it is moving to.  Transitions start every fourth pass, and
 * pixels near each other, in "spans" of .start_span_px along a row, share
 * when they started, so a pixel whose span has a transition in flight waits
 * for it to finish before starting its own.
 */

#if !defined(__LWS_EPD_DIRECT_H__)
#define __LWS_EPD_DIRECT_H__

/*
 * What a pixel is driven with in one pass, in waveform tables
 */

enum {
	LWS_EPDD_NONE,		/* not driven, the ink stays where it is */
	LWS_EPDD_BLACK,		/* driven towards black */
	LWS_EPDD_WHITE,		/* driven towards white */
};

enum {
	LWS_EPDD_PANEL_FL_FIRST_PX_LSB		= (1 << 0),
	/**< the first pixel of a bus byte is in its two least significant
	 * bits, otherwise its two most significant */
};

/*
 * A panel model, from its datasheet.  These are const and can be shared by
 * any number of boards with that panel.
 */

typedef struct lws_epd_direct_panel {
	const char		*name;

	uint16_t		source_px;
	/**< pixels in a row, along the source drivers: must be a multiple of
	 * the pixels in a bus byte */
	uint16_t		gate_rows;
	/**< rows, along the gate driver */

	uint8_t			code_black;
	/**< the 2-bit source driver code that drives a pixel towards black */
	uint8_t			code_white;
	/**< ... towards white */
	uint8_t			code_none;
	/**< ... that leaves it alone */
	uint8_t			flags;
	/**< LWS_EPDD_PANEL_FL_ */

	/* the datasheet's timing limits, for the transport to keep to */

	uint32_t		ckv_max_hz;
	/**< gate driver clock (CKV) maximum frequency */
	uint16_t		ckv_min_high_ns;
	/**< minimum CKV high pulse width */
	uint16_t		ckv_min_low_ns;
	/**< minimum CKV low pulse width */
	uint32_t		xcl_max_hz;
	/**< source driver data clock (XCL / CKH) maximum frequency */
	uint16_t		le_min_width_ns;
	/**< minimum source latch (XLE) high pulse width */
	uint16_t		le_min_off_ns;
	/**< minimum time from XLE going low to the next data */
	uint16_t		le_min_delay_xcl_x2;
	/**< minimum time from the last XCL of a row to XLE, in half XCL
	 * cycles (the ED047TC1 says 3.5 cycles, so 7) */
	uint16_t		output_settle_us;
	/**< source driver output settling time */
	uint16_t		min_pass_us;
	/**< the shortest time a pass over all the rows may take: the
	 * datasheet's maximum frame rate, eg, 85Hz is 11765us */
} lws_epd_direct_panel_t;

/*
 * Panel models described here so far
 */

LWS_VISIBLE LWS_EXTERN_FOR_DATA const lws_epd_direct_panel_t
lws_epd_direct_panel_ed047tc1;

/*
 * Waveforms.  These depend on the ink film as much as the panel model, and on
 * temperature, and are found by trying them on the panel, or come from the
 * panel's maker.
 *
 * A transition table has, for each pass, for each level being moved to, for
 * each level being moved from, the 2-bit LWS_EPDD_* code the pixel is driven
 * with in that pass.  Level 0 is black, and the last level is white.  The
 * codes for the levels being moved from are packed four to a byte, the first
 * in the two most significant bits, so each level being moved to has
 * (levels + 3) / 4 bytes, eg, for two levels, one byte per level being moved
 * to, with its two least significant bits unused.
 *
 * Every transition lasts for all of the table's passes: one that needs fewer
 * has "no drive" in the passes it doesn't need.
 *
 * Greys are made by driving a pixel part of the way between black and white.
 * How far the ink moves for a given drive differs from pixel to pixel, so a
 * grey reached by a little drive from rest is grainy.  Driving to black first,
 * so every pixel starts from the same place, then lightening in short drives,
 * makes much smoother greys: .drive_cycle_ns lets a table do both.
 */

#define LWS_EPDD_PACK4(_c0, _c1, _c2, _c3) \
	((uint8_t)(((_c0) << 6) | ((_c1) << 4) | ((_c2) << 2) | (_c3)))
/**< the codes for moving from four levels in a row, the first lowest */
#define LWS_EPDD_PACK2(_from_black, _from_white) \
	LWS_EPDD_PACK4(_from_black, _from_white, 0, 0)
/**< the codes for moving from black, and from white, in a two-level table */

#define LWS_EPDD_MAX_PHASES	64
/**< the most passes a transition table may have */
#define LWS_EPDD_DRIVE_CYCLE	4
/**< updates start on a pass that's a multiple of this, so a drive time that
 * repeats every this many passes is the same for every update in flight */

/* the layout of the tables given to .encode_16l */
#define LWS_EPDD_16L_EXPAND		0
#define LWS_EPDD_16L_NONE		(256 * 16)
#define LWS_EPDD_16L_CODES		(LWS_EPDD_16L_NONE + 16)
#define LWS_EPDD_16L_LEN		(LWS_EPDD_16L_CODES + 16 * 256 * 4)

typedef struct lws_epd_direct_waveform {
	const uint8_t		*update;
	/**< the transition table, update_passes x levels x the packed bytes
	 * for each level */
	const uint8_t		*clear;
	/**< per pass, the LWS_EPDD_* every pixel is driven with to clear the
	 * panel, whatever it was showing; it must end with every pixel white.
	 * It's done at start, since what the panel shows then is unknown, and
	 * on the full refreshes that clean up after many differential
	 * updates */
	uint16_t		update_passes;
	/**< passes in the transition table, at most LWS_EPDD_MAX_PHASES */
	uint16_t		clear_len;
	/**< passes in clear */
	uint32_t		drive_ns;
	/**< how long each row is driven for in every pass of an update, unless
	 * drive_cycle_ns is given */
	uint32_t		drive_cycle_ns[LWS_EPDD_DRIVE_CYCLE];
	/**< all 0, or how long each row is driven for in the passes of an
	 * update, in turn: pass p of the table is driven for
	 * drive_cycle_ns[p % LWS_EPDD_DRIVE_CYCLE].  Since every update starts
	 * on a multiple of LWS_EPDD_DRIVE_CYCLE, the updates in flight always
	 * agree on the drive time, and can overlap.  It lets a table drive
	 * hard in some passes and finely in others, eg, black fully, then
	 * lighten from there in small steps */
	uint32_t		clear_drive_ns;
	/**< how long each row is driven for in every pass of a clear, which
	 * has the panel to itself; 0 means the same as drive_ns */
	uint8_t			levels;
	/**< grey levels in the transition table, 2, 4 or 16.  The display
	 * may have fewer, see lws_display_epd_direct_t */
} lws_epd_direct_waveform_t;

/*
 * The transport, implemented by the platform.  The generic driver calls these
 * from whatever runs the passes, which isn't necessarily the lws event loop
 * thread, so they mustn't call lws apis.  init() and deinit() are called from
 * the lws event loop thread, when nothing else is.
 *
 * A pass is frame_start(), then for each row in turn either row_load() then
 * row_drive(), or row_skip(), then frame_end().
 */

typedef struct lws_epd_direct_bus_ops {
	int (*init)(const struct lws_epd_direct_bus_ops *bus);
	/**< prepare the bus and control lines, with the panel unpowered.
	 * 0 = OK */
	void (*deinit)(const struct lws_epd_direct_bus_ops *bus);
	/**< release what init took, the panel is unpowered */
	int (*power)(const struct lws_epd_direct_bus_ops *bus, int on);
	/**< sequence the panel's supplies on or off, waiting out the times
	 * its datasheet requires.  0 = OK */
	void * (*alloc_dma)(const struct lws_epd_direct_bus_ops *bus,
			    size_t size);
	/**< NULL, or allocate memory row data can be sent from.  It should
	 * be at least 8-byte aligned if the bus has .encode_16l */
	void (*free_dma)(const struct lws_epd_direct_bus_ops *bus, void **p);
	/**< NULL, or free memory from alloc_dma and set *p NULL */
	void * (*alloc_fast)(const struct lws_epd_direct_bus_ops *bus,
			     size_t size);
	/**< NULL, or allocate memory the cpu can read quickly, for what is
	 * read in every pass, if the platform has slower memory that ordinary
	 * allocations may come from.  It may fail, and then an ordinary
	 * allocation is used */
	void (*free_fast)(const struct lws_epd_direct_bus_ops *bus, void **p);
	/**< NULL, or free memory from alloc_fast and set *p NULL */
	uint32_t (*encode_16l)(uint8_t *out, const uint8_t *ft,
			       const uint8_t *starts, size_t words,
			       const void *tables);
	/**< NULL, or a faster way for the platform to do the most common
	 * case of working out the bus bytes for a row in a pass: 16 levels,
	 * 8-pixel spans, the first pixel in the most significant bits of its
	 * bus byte, and every pixel of the words given in flight.
	 *
	 * For each word, 32 pixels, write 8 bus bytes at out.  Pixel x's
	 * byte ft[x] and its span's start, nibble (x / 8) % 2 of
	 * starts[x / 16], index the 32-bit code entries in tables, at
	 * LWS_EPDD_16L_CODES, by start << 8 | ft: the low 2 bits of the entry
	 * are the panel's code for the pixel.  Returns nonzero if any byte
	 * written differs from the no drive byte, which is repeated 16 times
	 * at LWS_EPDD_16L_NONE.  Before that, at 0, are 16 bytes for each
	 * starts byte, each pixel's start, which it may use.
	 *
	 * out is 8-byte aligned, ft and tables 16-byte aligned.  It's checked
	 * against the portable code when the display starts, and not used if
	 * what it does differs */
	void (*prefetch)(const struct lws_epd_direct_bus_ops *bus,
			 const void *p, size_t len);
	/**< NULL, or start bringing memory that is about to be read into the
	 * cpu's cache, without waiting for it.  It's given the next row's
	 * state while a row is being worked out, so if that's in memory
	 * behind a cache, eg, PSRAM, it can be there in time */
	void (*frame_start)(const struct lws_epd_direct_bus_ops *bus);
	/**< start a pass at the first row */
	void (*row_load)(const struct lws_epd_direct_bus_ops *bus,
			 const uint8_t *data, size_t len);
	/**< start clocking a row of drive codes into the source drivers.  It
	 * should return as soon as it has started, since the next row is
	 * prepared while it's being sent; the data stays valid until the
	 * following row_drive() returns */
	void (*row_drive)(const struct lws_epd_direct_bus_ops *bus,
			  uint32_t drive_ns);
	/**< wait for the row_load() to finish, latch it into the source
	 * driver outputs, and select the current row for drive_ns, then move
	 * on to the next row */
	void (*row_skip)(const struct lws_epd_direct_bus_ops *bus);
	/**< move on to the next row as quickly as the gate driver allows,
	 * without latching new data.  What's latched is driven onto the row
	 * briefly, so we only call this when no drive is latched */
	void (*frame_end)(const struct lws_epd_direct_bus_ops *bus);
	/**< finish the pass after the last row */

	uint16_t		row_tail_bytes;
	/**< bytes of "no drive" sent after each row's own data, if the
	 * transport needs them, eg, for timing headroom */
} lws_epd_direct_bus_ops_t;

/*
 * What runs the passes, optional.
 *
 * Passes are run by calling lws_display_epd_direct_service() until it says
 * there's nothing to do.  Without a runner, it's called from a sul on the lws
 * event loop thread, so the passes share that thread with everything else on
 * it and are delayed by it.  A platform can instead give a runner that calls
 * it from a thread of its own, eg, on another cpu core.
 *
 * The runner's thread calls only lws_display_epd_direct_service(), and the
 * bus ops from inside it, never other lws apis.
 */

#define LWS_EPDD_SVC_IDLE	((lws_usec_t)-1)
/**< nothing to do until the runner is kicked */
#define LWS_EPDD_SVC_STOP	((lws_usec_t)-2)
/**< the panel is unpowered, the runner's thread should end */

typedef struct lws_epd_direct_runner {
	int (*start)(const struct lws_epd_direct_runner *r,
		     lws_display_state_t *lds);
	/**< start a thread that calls lws_display_epd_direct_service(lds)
	 * over and over, waiting between calls for as long as it says, or
	 * until kicked.  0 = OK */
	void (*kick)(const struct lws_epd_direct_runner *r);
	/**< if the thread is waiting, have it call the service now.  Called
	 * from the lws event loop thread. */
	void (*stop)(const struct lws_epd_direct_runner *r);
	/**< kick the thread, and return once it has seen LWS_EPDD_SVC_STOP
	 * and ended */
} lws_epd_direct_runner_t;

/*
 * The display object, a subclass of lws_display_t.  The surface it presents
 * is the panel's source_px x gate_rows; give the lws_display_t .ic a
 * greyscale palette of 2, 4 or 16 levels, from black to white, the levels the
 * pixels are dithered to.  The waveform must have at least as many levels;
 * if it has more, the display's are spread evenly over them.
 */

typedef struct lws_display_epd_direct {
	lws_display_t			disp;
	/**< use lws_display_epd_direct_ops to set the ops */
	const lws_epd_direct_panel_t	*panel;
	const lws_epd_direct_waveform_t	*wf;
	const lws_epd_direct_bus_ops_t	*bus;
	const lws_epd_direct_runner_t	*runner;
	/**< NULL to run the passes from the lws event loop, or what runs
	 * them on a thread of its own */

	lws_display_completion_t	cb;
	/**< told 1 when the panel has been cleared after init, and 2 when an
	 * update has finished, ie, every pixel has reached what it was given */

	uint16_t			full_refresh_every;
	/**< 0, or clear the panel before every this many'th update, to clean
	 * up what differential updates leave behind */
	uint16_t			power_off_idle_ms;
	/**< how long the panel supplies are kept up after the last pass, in
	 * case more is coming */
	uint8_t				start_span_px;
	/**< 0 for 8, or 1, 2, 4, 8, 16 or 32: pixels along a row that share
	 * when their transitions started.  Fewer means a pixel waits less
	 * often for its neighbours, but the passes read more memory */
	uint8_t				mirror_x:1;
	/**< the surface's x runs the other way to the source drivers' */
	uint8_t				mirror_y:1;
	/**< the surface's y runs the other way to the gate driver's */
} lws_display_epd_direct_t;

LWS_VISIBLE LWS_EXTERN int
lws_display_epd_direct_init(lws_display_state_t *lds);
LWS_VISIBLE LWS_EXTERN int
lws_display_epd_direct_blit(lws_display_state_t *lds, const uint8_t *src,
			    lws_box_t *box, lws_dll2_owner_t *ids);
LWS_VISIBLE LWS_EXTERN int
lws_display_epd_direct_power(lws_display_state_t *lds, int state);
LWS_VISIBLE LWS_EXTERN int
lws_display_epd_direct_clear(lws_display_state_t *lds);

/**
 * lws_display_epd_direct_service() - run what's due on the panel
 *
 * \param lds: the display state the driver was initialized on
 *
 * Called by what runs the passes, see lws_epd_direct_runner_t, and only by
 * that.  Runs a pass if one is due, powers the panel off if it has been idle
 * long enough, and returns how many us until it wants to be called again, or
 * LWS_EPDD_SVC_IDLE if it doesn't until there's more to do, or
 * LWS_EPDD_SVC_STOP when the driver is being destroyed.
 */
LWS_VISIBLE LWS_EXTERN lws_usec_t
lws_display_epd_direct_service(lws_display_state_t *lds);

/**
 * lws_display_epd_direct_destroy() - unpower the panel and free the driver
 *
 * \param lds: the display state the driver was initialized on
 *
 * Stops the passes, which may leave pixels in between levels, turns the panel
 * supplies off and frees everything the driver allocated.  To leave the panel
 * white, show a white update and wait for it to complete first.
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_epd_direct_destroy(lws_display_state_t *lds);

#define lws_display_epd_direct_ops \
	.init = lws_display_epd_direct_init, \
	.blit = lws_display_epd_direct_blit, \
	.power = lws_display_epd_direct_power, \
	.clear = lws_display_epd_direct_clear, \
	.bistable = 1

#endif
