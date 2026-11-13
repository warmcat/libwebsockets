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
 * See include/libwebsockets/lws-epd-direct.h for the overview.
 *
 * Pixels are kept as bit planes, a 32-bit word holding 32 pixels of a row,
 * pixel x of a row in bit (x & 31) of word (x >> 5), 1 meaning white:
 *
 *  - want: what the pixel was last given in a blit
 *  - tgt:  what the pixel is, or is moving to
 *  - busy: the pixel belongs to an update that is in flight
 *
 * so when want differs from tgt, a pixel that isn't busy can join a new
 * update, and one that is busy waits for the one it's in to finish.
 *
 * An update in flight is a "slot".  It has a pair of masks for each row it
 * has pixels on, the ones becoming black and the ones becoming white, and a
 * count of the passes it has run.  Slots are made and freed by the side of
 * the driver on the lws event loop thread, which owns the planes.  What runs
 * the passes only reads the masks of slots handed to it, and only changes
 * their pass count and state, at pass boundaries.
 *
 * The passes are run from lws_display_epd_direct_service().  By default it's
 * called from a sul on the event loop thread, but a platform can give us a
 * runner that calls it from a thread of its own, see lws_epd_direct_runner_t.
 * The two sides then share only the slots' states, which are published with
 * release and read with acquire ordering, and a few flags done the same way.
 * Everything else belongs to one side or the other:
 *
 *  - event loop side: the planes, the dirty flags, making slots and freeing
 *    them, telling the caller about completions, logging
 *
 *  - runner side: the bus and everything it's given, the row buffers and
 *    drive masks, whether the panel is powered, the pass timing
 *
 * When there's a runner, the event loop side looks at the slots at the pass
 * rate while any are in flight, to collect the ones that finished.  The
 * runner never calls into lws.
 *
 * In a pass, each row is encoded while the one before it is being sent to the
 * source drivers, into the row buffer that isn't being sent, so the cpu time
 * hides inside the bus time.  A row that encodes the same as the last one that
 * was encoded, eg, every row of a clear, sends the same buffer again.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

#define EPDD_SLOTS		4
#define EPDD_NO_ROW		0xffff
/* pixels in a bus byte: each has a 2-bit code */
#define EPDD_PX_PER_BYTE	4

/* what's done with a row in a pass */

enum epdd_row_act {
	EPDD_ROW_SKIP,		/* step over it, no drive is latched */
	EPDD_ROW_NONE,		/* load and latch no drive, it has no drive */
	EPDD_ROW_DATA,		/* load and latch its drive codes */
};

/*
 * The few things the two sides share are only accessed with these.  With
 * MSVC, volatile accesses already have acquire / release ordering.
 */

static uint8_t
epdd_get(const uint8_t *p)
{
#if defined(__GNUC__) || defined(__clang__)
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
#else
	return *(const volatile uint8_t *)p;
#endif
}

static void
epdd_set(uint8_t *p, uint8_t v)
{
#if defined(__GNUC__) || defined(__clang__)
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
#else
	*(volatile uint8_t *)p = v;
#endif
}

enum epdd_slot_state {
	EPDD_SLOT_FREE,
	EPDD_SLOT_ARMED,	/* made, waiting for the next pass to start */
	EPDD_SLOT_RUNNING,	/* being driven, pass by pass */
	EPDD_SLOT_DONE,		/* driven for all its passes */
};

typedef struct epdd_slot {
	void			*blk;
	/**< the one allocation holding row_idx and masks */
	uint16_t		*row_idx;
	/**< per gate row, which pair of masks is for it, or EPDD_NO_ROW */
	uint32_t		*masks;
	/**< per row with pixels in this update, the to_black then the to_white
	 * words */
	uint16_t		pass;
	/**< passes it has been driven for */
	uint16_t		len;
	/**< passes it needs */
	uint8_t			state;
	/**< enum epdd_slot_state, shared, use epdd_get() / epdd_set() */
	uint8_t			clear;
	/**< it's the clear waveform on every pixel, it has no masks */
} epdd_slot_t;

/*
 * What the runner side counts about the passes, handed over to the event loop
 * side to log when the panel goes idle
 */

typedef struct epdd_rstats {
	lws_usec_t		start;
	/**< the first pass started */
	lws_usec_t		end;
	/**< the last pass ended */
	lws_usec_t		scan_min;
	lws_usec_t		scan_max;
	lws_usec_t		scan_sum;
	/**< how long passes took to scan the rows, not counting waiting
	 * between passes for the panel's maximum frame rate */
	uint32_t		passes;
	uint32_t		rows_driven;
	uint32_t		rows_skipped;
	uint32_t		rows_none;
	/**< rows not driven that had to be loaded to latch "no drive" */
} epdd_rstats_t;

typedef struct epdd_priv {
	lws_display_state_t	*lds;
	lws_sorted_usec_list_t	sul_pass;
	/**< without a runner, calls lws_display_epd_direct_service() */
	lws_sorted_usec_list_t	sul_poll;
	/**< with a runner, collects what it finished */
	lws_usec_t		sul_pass_due;
	/**< when sul_pass is due, if it's scheduled */

	lws_surface_error_t	*u[2];
	/**< error diffusion for two lines */

	uint32_t		*want;
	uint32_t		*tgt;
	uint32_t		*busy;
	uint8_t			*dirty;
	/**< per gate row, want may differ from tgt there */

	uint8_t			*rowbuf[2];
	/**< drive codes for a row, then its tail: one can be sent while the
	 * next row is encoded into the other */
	uint8_t			*nonebuf;
	/**< a row of "no drive", then its tail */
	uint32_t		*drv;
	/**< for each rowbuf, the pixels driven black, then white, that were
	 * packed into it: words-wide each, so 4 x words */
	uint8_t			cur;
	/**< the rowbuf last packed, which may be being sent */
	uint8_t			cur_valid;
	/**< rowbuf[cur] has been packed in this pass */

	epdd_slot_t		slot[EPDD_SLOTS];

	uint16_t		lut_b[256];
	uint16_t		lut_w[256];
	uint16_t		lut_n[256];
	/**< 8 pixels' worth of a mask to the two bus bytes of their codes,
	 * the first bus byte in the high 8 bits */

	size_t			row_bytes;
	/**< the panel's own bytes for a row, without the tail */
	size_t			plane_words;
	int			words;
	/**< 32-bit words for a row in a plane */
	uint32_t		last_word_mask;
	/**< the bits of the last word of a row that are pixels */

	uint16_t		updates;
	/**< updates since the panel was last cleared */

	/*
	 * What the panel did since it was last idle, said when it's idle
	 * again, to see how long updates take on the real thing
	 */

	epdd_rstats_t		rst;
	/**< runner side: what it's counting now */
	epdd_rstats_t		rst_pub;
	/**< what the runner side handed over, when rst_ready */
	lws_usec_t		st_commit;
	/**< 0, or the first update was committed */
	uint32_t		st_px_black;
	uint32_t		st_px_white;
	uint16_t		st_updates;
	uint16_t		st_clears;

	/* runner side */

	lws_usec_t		last_pass;
	/**< 0, or when the last pass started */
	lws_usec_t		idle_since;
	/**< 0, or when the runner found nothing to drive while powered */
	uint8_t			powered;
	uint8_t			latched_none;
	/**< what's latched in the source drivers is no drive */

	/* shared, use epdd_get() / epdd_set() */

	uint8_t			rst_ready;
	/**< the runner side handed over rst_pub, for the event loop side */
	uint8_t			power_off_req;
	/**< the event loop side wants the panel unpowered when it's idle */
	uint8_t			power_failed;
	/**< the runner side couldn't power the panel */
	uint8_t			stopping;
	/**< the runner side should unpower the panel and stop */

	/* event loop side */

	uint8_t			full_pending:1;
	/**< clear the panel when nothing is in flight */
	uint8_t			booting:1;
	/**< the clear after init hasn't finished */
	uint8_t			booted:1;
	/**< the clear after init finished, we haven't said so yet */
	uint8_t			committed:1;
	/**< an update was committed and we haven't said it finished */
} epdd_priv_t;

#define lds_to_disp(_lds) ((const lws_display_epd_direct_t *)(_lds)->disp)
#define lds_to_priv(_lds) ((epdd_priv_t *)(_lds)->priv)

static void
epdd_pass_cb(lws_sorted_usec_list_t *sul);
static void
epdd_poll_cb(lws_sorted_usec_list_t *sul);

static uint32_t *
plane_row(const epdd_priv_t *priv, uint32_t *plane, int row)
{
	return plane + (size_t)row * (size_t)priv->words;
}

static uint32_t
popcount32(uint32_t v)
{
	v = v - ((v >> 1) & 0x55555555u);
	v = (v & 0x33333333u) + ((v >> 2) & 0x33333333u);
	v = (v + (v >> 4)) & 0x0f0f0f0fu;

	return (v * 0x01010101u) >> 24;
}

/* every slot is free, so nothing is in flight or waiting to be collected */

static int
slots_idle(const epdd_priv_t *priv)
{
	int n;

	for (n = 0; n < EPDD_SLOTS; n++)
		if (epdd_get(&priv->slot[n].state) != EPDD_SLOT_FREE)
			return 0;

	return 1;
}

/* a slot that wasn't running in this pass is waiting for passes now */

static int
slots_active_other(const epdd_priv_t *priv, const uint8_t *st)
{
	int n;

	for (n = 0; n < EPDD_SLOTS; n++)
		if (st[n] != EPDD_SLOT_RUNNING &&
		    epdd_get(&priv->slot[n].state) == EPDD_SLOT_ARMED)
			return 1;

	return 0;
}

/* some slot is waiting for passes or having them */

static int
slots_active(const epdd_priv_t *priv)
{
	uint8_t st;
	int n;

	for (n = 0; n < EPDD_SLOTS; n++) {
		st = epdd_get(&priv->slot[n].state);
		if (st == EPDD_SLOT_ARMED || st == EPDD_SLOT_RUNNING)
			return 1;
	}

	return 0;
}

/*
 * What a transition of tlen passes is driven with on the slot's current
 * pass.  The transitions in a slot all end on its last pass.
 */

static uint8_t
slot_code(const epdd_slot_t *s, const uint8_t *table, uint16_t tlen)
{
	int i = (int)s->pass - ((int)s->len - (int)tlen);

	if (i < 0 || i >= (int)tlen)
		return LWS_EPDD_NONE;

	return table[i];
}

static void
build_luts(epdd_priv_t *priv, const lws_epd_direct_panel_t *panel)
{
	int m, j, shift;

	for (m = 0; m < 256; m++) {
		uint16_t b = 0, w = 0, n = 0;

		for (j = 0; j < 8; j++) {
			if (!(m & (1 << j)))
				continue;

			/* pixel j is in bus byte j / 4, the first one high */

			shift = (j < 4 ? 8 : 0);
			if (panel->flags & LWS_EPDD_PANEL_FL_FIRST_PX_LSB)
				shift += (j & 3) * 2;
			else
				shift += (3 - (j & 3)) * 2;

			b = (uint16_t)(b | ((panel->code_black & 3) << shift));
			w = (uint16_t)(w | ((panel->code_white & 3) << shift));
			n = (uint16_t)(n | ((panel->code_none & 3) << shift));
		}

		priv->lut_b[m] = b;
		priv->lut_w[m] = w;
		priv->lut_n[m] = n;
	}
}

static uint32_t *
drv_b(const epdd_priv_t *priv, int buf)
{
	return priv->drv + (size_t)buf * 2u * (size_t)priv->words;
}

static uint32_t *
drv_w(const epdd_priv_t *priv, int buf)
{
	return drv_b(priv, buf) + priv->words;
}

/*
 * Turn the drive masks for rowbuf[buf] into its bus bytes
 */

static void
pack_row(epdd_priv_t *priv, int buf)
{
	const uint32_t *db = drv_b(priv, buf), *dw = drv_w(priv, buf);
	uint8_t *p = priv->rowbuf[buf];
	size_t left = priv->row_bytes;
	int g, groups = (int)((priv->row_bytes + 1) / 2);

	for (g = 0; g < groups; g++) {
		int sh = (g & 3) * 8;
		uint8_t b = (uint8_t)(db[g >> 2] >> sh),
			w = (uint8_t)(dw[g >> 2] >> sh);
		uint16_t v = (uint16_t)(priv->lut_b[b] | priv->lut_w[w] |
					priv->lut_n[(uint8_t)~(b | w)]);

		*p++ = (uint8_t)(v >> 8);
		if (--left) {
			*p++ = (uint8_t)v;
			left--;
		}
	}
}

/*
 * Work out what the slots running drive the row with, into the drive masks
 * for rowbuf[buf].  Returns nonzero if any of it is driven.
 */

static int
encode_row(epdd_priv_t *priv, const lws_epd_direct_waveform_bw_t *wf, int row,
	   int buf)
{
	uint32_t *db = drv_b(priv, buf), *dw = drv_w(priv, buf), any = 0;
	int n, w;

	memset(db, 0, sizeof(uint32_t) * 2u * (size_t)priv->words);

	for (n = 0; n < EPDD_SLOTS; n++) {
		const epdd_slot_t *s = &priv->slot[n];
		const uint32_t *tb, *tw;
		uint8_t cb, cw;

		if (epdd_get(&s->state) != EPDD_SLOT_RUNNING)
			continue;

		if (s->clear) {
			uint32_t *d;

			cb = slot_code(s, wf->clear, wf->clear_len);
			if (cb == LWS_EPDD_NONE)
				continue;

			d = cb == LWS_EPDD_BLACK ? db : dw;
			for (w = 0; w < priv->words; w++)
				d[w] = w == priv->words - 1 ?
						priv->last_word_mask : 0xffffffffu;
			any = 1;
			continue;
		}

		if (s->row_idx[row] == EPDD_NO_ROW)
			continue;

		tb = s->masks + (size_t)s->row_idx[row] * 2u *
							(size_t)priv->words;
		tw = tb + priv->words;

		cb = slot_code(s, wf->to_black, wf->to_black_len);
		cw = slot_code(s, wf->to_white, wf->to_white_len);

		for (w = 0; w < priv->words; w++) {
			if (cb == LWS_EPDD_BLACK)
				db[w] |= tb[w];
			else if (cb == LWS_EPDD_WHITE)
				dw[w] |= tb[w];

			if (cw == LWS_EPDD_BLACK)
				db[w] |= tw[w];
			else if (cw == LWS_EPDD_WHITE)
				dw[w] |= tw[w];
		}
	}

	for (w = 0; w < priv->words; w++)
		any |= db[w] | dw[w];

	return !!any;
}

/*
 * Decide what's done with the row and get its data ready, while the row
 * before it may still be being sent from rowbuf[priv->cur].  What it's
 * encoded into is the other rowbuf, which nothing is using.
 *
 * What's latched after the rows before it decides if a row with nothing to
 * drive can be stepped over, so that's tracked as the rows are prepared, in
 * the order they go to the panel.
 */

static int
prepare_row(epdd_priv_t *priv, const lws_epd_direct_waveform_bw_t *wf,
	    int row, const uint8_t **data)
{
	int nb = priv->cur ^ 1;

	if (!encode_row(priv, wf, row, nb)) {
		/*
		 * Nothing to drive on this row.  Stepping over it drives
		 * what's latched onto it, so it must be no drive.  If it
		 * isn't, load and latch some, which costs this row the time
		 * of a driven one.
		 */
		if (priv->latched_none) {
			priv->rst.rows_skipped++;
			return EPDD_ROW_SKIP;
		}
		priv->latched_none = 1;
		priv->rst.rows_none++;
		*data = priv->nonebuf;

		return EPDD_ROW_NONE;
	}

	priv->latched_none = 0;
	priv->rst.rows_driven++;

	if (!priv->cur_valid || memcmp(drv_b(priv, nb), drv_b(priv, priv->cur),
			sizeof(uint32_t) * 2u * (size_t)priv->words)) {
		pack_row(priv, nb);
		priv->cur = (uint8_t)nb;
		priv->cur_valid = 1;
	}

	*data = priv->rowbuf[priv->cur];

	return EPDD_ROW_DATA;
}

/*
 * Runner side: one pass over every row, driving the slots that are running.
 * This side only reads the slots' masks, and changes their pass counts and
 * states.
 *
 * Returns nonzero if anything was driven.
 */

static int
epdd_pass(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	const lws_epd_direct_bus_ops_t *bus = ed->bus;
	const lws_epd_direct_waveform_bw_t *wf = ed->wf_bw;
	size_t len = priv->row_bytes + bus->row_tail_bytes;
	int n, row, rows = (int)ed->panel->gate_rows, any = 0, act, nact = 0,
	    left = 0;
	const uint8_t *data = NULL, *ndata = NULL;
	uint8_t st[EPDD_SLOTS];
	uint32_t drive_ns = wf->drive_ns;
	lws_usec_t t0;

	if (!priv->powered) {
		if (bus->power(bus, 1)) {
			/* the event loop side says so, we try again later */
			epdd_set(&priv->power_failed, 1);
			return 0;
		}
		priv->powered = 1;
		/* we don't know what the source drivers came up latching */
		priv->latched_none = 0;
	}

	/*
	 * Updates made since the last pass join at this pass boundary.  The
	 * slots running stay running, and nothing else changes them, until we
	 * say they're done.
	 */

	for (n = 0; n < EPDD_SLOTS; n++) {
		st[n] = epdd_get(&priv->slot[n].state);
		if (st[n] == EPDD_SLOT_ARMED) {
			st[n] = EPDD_SLOT_RUNNING;
			epdd_set(&priv->slot[n].state, st[n]);
		}
		if (st[n] == EPDD_SLOT_RUNNING) {
			any = 1;
			/* a clear has the panel to itself */
			if (priv->slot[n].clear && wf->clear_drive_ns)
				drive_ns = wf->clear_drive_ns;
		}
	}

	if (!any)
		return 0;

	t0 = lws_now_usecs();
	if (!priv->rst.passes++)
		priv->rst.start = t0;

	/* the slots running have changed, what was packed is stale */
	priv->cur_valid = 0;

	bus->frame_start(bus);

	act = prepare_row(priv, wf, 0, &data);

	for (row = 0; row < rows; row++) {
		if (act == EPDD_ROW_SKIP) {
			bus->row_skip(bus);
			if (row + 1 < rows)
				act = prepare_row(priv, wf, row + 1, &data);
			continue;
		}

		bus->row_load(bus, data, len);
		/* the next row is made ready while this one is sent */
		if (row + 1 < rows)
			nact = prepare_row(priv, wf, row + 1, &ndata);
		bus->row_drive(bus, drive_ns);

		act = nact;
		data = ndata;
	}

	bus->frame_end(bus);

	priv->rst.end = lws_now_usecs();
	t0 = priv->rst.end - t0;
	if (priv->rst.passes == 1 || t0 < priv->rst.scan_min)
		priv->rst.scan_min = t0;
	if (t0 > priv->rst.scan_max)
		priv->rst.scan_max = t0;
	priv->rst.scan_sum += t0;

	for (n = 0; n < EPDD_SLOTS; n++) {
		epdd_slot_t *s = &priv->slot[n];

		if (st[n] != EPDD_SLOT_RUNNING)
			continue;
		if (++s->pass < s->len)
			left = 1;
	}

	/*
	 * If this was the last pass of everything, hand over what we counted
	 * before saying the slots are done, so the event loop side has it
	 * when it sees them done
	 */

	if (!left && !slots_active_other(priv, st) &&
	    !epdd_get(&priv->rst_ready)) {
		priv->rst_pub = priv->rst;
		memset(&priv->rst, 0, sizeof(priv->rst));
		epdd_set(&priv->rst_ready, 1);
	}

	for (n = 0; n < EPDD_SLOTS; n++) {
		epdd_slot_t *s = &priv->slot[n];

		if (st[n] == EPDD_SLOT_RUNNING && s->pass >= s->len)
			epdd_set(&s->state, EPDD_SLOT_DONE);
	}

	return 1;
}

static epdd_slot_t *
free_slot(epdd_priv_t *priv)
{
	int n;

	for (n = 0; n < EPDD_SLOTS; n++)
		if (epdd_get(&priv->slot[n].state) == EPDD_SLOT_FREE)
			return &priv->slot[n];

	return NULL;
}

/*
 * Without a runner, have lws_display_epd_direct_service() called in us,
 * unless it's already going to be called sooner
 */

static void
schedule_pass(epdd_priv_t *priv, lws_usec_t us)
{
	lws_usec_t due = lws_now_usecs() + us;

	if (!lws_dll2_is_detached(&priv->sul_pass.list) &&
	    priv->sul_pass_due <= due)
		return;

	priv->sul_pass_due = due;
	lws_sul_schedule(priv->lds->ctx, 0, &priv->sul_pass, epdd_pass_cb, us);
}

/*
 * Event loop side: there's something new for the runner side to look at
 */

static void
epdd_kick(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);

	if (!ed->runner) {
		schedule_pass(priv, 0);
		return;
	}

	ed->runner->kick(ed->runner);

	/* look for what it finished at the pass rate while it's busy */

	if (lws_dll2_is_detached(&priv->sul_poll.list))
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul_poll,
				 epdd_poll_cb, ed->panel->min_pass_us);
}

/* a free slot back to how it started, the runner side isn't looking at it */

static void
slot_reset(epdd_slot_t *s)
{
	s->blk = NULL;
	s->row_idx = NULL;
	s->masks = NULL;
	s->pass = 0;
	s->len = 0;
	s->clear = 0;
}

/*
 * Clear the whole panel: every pixel is busy until it has finished, ending
 * white.  Every row is then dirty, so what was wanted is drawn after it.
 */

static void
start_clear(epdd_priv_t *priv, epdd_slot_t *s)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	int row, w;

	slot_reset(s);
	s->clear = 1;
	s->len = ed->wf_bw->clear_len;

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		uint32_t *t = plane_row(priv, priv->tgt, row),
			 *b = plane_row(priv, priv->busy, row);

		for (w = 0; w < priv->words; w++)
			t[w] = b[w] = w == priv->words - 1 ?
					priv->last_word_mask : 0xffffffffu;
		priv->dirty[row] = 1;
	}

	priv->updates = 0;
	priv->st_clears++;
	/* everything about the slot is written before the runner can see it */
	epdd_set(&s->state, EPDD_SLOT_ARMED);
}

/*
 * Start what we can of what's wanted.  Pixels that are wanted to change and
 * aren't already moving join a new slot, rows still with pixels waiting on
 * one in flight stay dirty, to be looked at again when it finishes.
 */

static void
epdd_start(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	int row, w, rows = 0, idx = 0, has_b = 0, has_w = 0;
	size_t sz;
	epdd_slot_t *s;

	if (priv->full_pending) {
		/* the clear has the whole panel, so waits for it to be idle */
		if (!slots_idle(priv))
			return;

		priv->full_pending = 0;
		start_clear(priv, &priv->slot[0]);
		epdd_kick(priv);

		return;
	}

	s = free_slot(priv);
	if (!s)
		/* the dirty rows are looked at again when one finishes */
		return;

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		const uint32_t *wa = plane_row(priv, priv->want, row),
			       *t = plane_row(priv, priv->tgt, row),
			       *b = plane_row(priv, priv->busy, row);
		uint32_t take = 0, rest = 0;

		if (!priv->dirty[row])
			continue;

		for (w = 0; w < priv->words; w++) {
			take |= (wa[w] ^ t[w]) & ~b[w];
			rest |= (wa[w] ^ t[w]) & b[w];
		}

		if (take)
			rows++;
		else if (!rest)
			priv->dirty[row] = 0;
	}

	if (!rows)
		return;

	sz = sizeof(uint16_t) * ed->panel->gate_rows;
	sz = (sz + 3) & ~(size_t)3;

	slot_reset(s);
	s->blk = lws_malloc(sz + (size_t)rows * 2u * (size_t)priv->words *
						sizeof(uint32_t), __func__);
	if (!s->blk) {
		lwsl_err("%s: OOM, the update waits\n", __func__);
		return;
	}

	s->row_idx = (uint16_t *)s->blk;
	s->masks = (uint32_t *)((uint8_t *)s->blk + sz);

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		uint32_t *wa = plane_row(priv, priv->want, row),
			 *t = plane_row(priv, priv->tgt, row),
			 *b = plane_row(priv, priv->busy, row), *tb, *tw;
		uint32_t rest = 0, any = 0;

		s->row_idx[row] = EPDD_NO_ROW;
		if (!priv->dirty[row])
			continue;

		for (w = 0; w < priv->words; w++)
			any |= (wa[w] ^ t[w]) & ~b[w];
		if (!any)
			continue;

		s->row_idx[row] = (uint16_t)idx;
		tb = s->masks + (size_t)idx * 2u * (size_t)priv->words;
		tw = tb + priv->words;
		idx++;

		for (w = 0; w < priv->words; w++) {
			uint32_t take = (wa[w] ^ t[w]) & ~b[w];

			rest |= (wa[w] ^ t[w]) & b[w];

			/* tgt 1 is white, so those taken from there go black */
			tb[w] = take & t[w];
			tw[w] = take & ~t[w];
			has_b |= !!tb[w];
			has_w |= !!tw[w];

			priv->st_px_black += popcount32(tb[w]);
			priv->st_px_white += popcount32(tw[w]);

			t[w] ^= take;
			b[w] |= take;
		}

		priv->dirty[row] = !!rest;
	}

	s->len = 0;
	if (has_b)
		s->len = ed->wf_bw->to_black_len;
	if (has_w && ed->wf_bw->to_white_len > s->len)
		s->len = ed->wf_bw->to_white_len;

	priv->st_updates++;
	/* everything about the slot is written before the runner can see it */
	epdd_set(&s->state, EPDD_SLOT_ARMED);
	epdd_kick(priv);
}

/*
 * Event loop side: the slots that finished give their pixels back.  Only the
 * event loop side frees slots.  Returns nonzero if any finished.
 */

static int
epdd_collect(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	int n, row, w, done = 0;

	for (n = 0; n < EPDD_SLOTS; n++) {
		epdd_slot_t *s = &priv->slot[n];

		/* the runner is done with it, and with the rows it drove */
		if (epdd_get(&s->state) != EPDD_SLOT_DONE)
			continue;

		done = 1;

		if (s->clear) {
			memset(priv->busy, 0, priv->plane_words *
							sizeof(uint32_t));
			if (priv->booting) {
				priv->booting = 0;
				priv->booted = 1;
			}
		} else
			for (row = 0; row < (int)ed->panel->gate_rows; row++) {
				const uint32_t *tb, *tw;
				uint32_t *b;

				if (s->row_idx[row] == EPDD_NO_ROW)
					continue;

				tb = s->masks + (size_t)s->row_idx[row] * 2u *
							(size_t)priv->words;
				tw = tb + priv->words;
				b = plane_row(priv, priv->busy, row);

				for (w = 0; w < priv->words; w++)
					b[w] &= ~(tb[w] | tw[w]);
			}

		lws_free(s->blk);
		slot_reset(s);
		epdd_set(&s->state, EPDD_SLOT_FREE);
	}

	return done;
}

/*
 * Event loop side: the panel has gone idle, say what it did since it was last
 * idle, from what the runner side handed over and what we counted
 */

static void
epdd_stats(epdd_priv_t *priv)
{
	const epdd_rstats_t *r = &priv->rst_pub;

	if (!epdd_get(&priv->rst_ready))
		return;

#if (_LWS_ENABLED_LOGS & LLL_INFO)
	if (r->passes)
		lwsl_info("%s: %u passes in %dms, scans %d / %d / %dus "
			    "(min / avg / max); rows %u driven, %u skipped, "
			    "%u latched none; px %u to black, %u to white; "
			    "%u updates, %u clears; settled %dms after "
			    "commit\n", __func__,
			    (unsigned int)r->passes,
			    (int)((r->end - r->start) / LWS_US_PER_MS),
			    (int)r->scan_min,
			    (int)(r->scan_sum / r->passes),
			    (int)r->scan_max,
			    (unsigned int)r->rows_driven,
			    (unsigned int)r->rows_skipped,
			    (unsigned int)r->rows_none,
			    (unsigned int)priv->st_px_black,
			    (unsigned int)priv->st_px_white,
			    (unsigned int)priv->st_updates,
			    (unsigned int)priv->st_clears,
			    priv->st_commit ? (int)((lws_now_usecs() -
				priv->st_commit) / LWS_US_PER_MS) : -1);
#else
	(void)r;
#endif

	priv->st_commit = 0;
	priv->st_px_black = priv->st_px_white = 0;
	priv->st_updates = priv->st_clears = 0;

	/* the runner side can hand over the next lot */
	epdd_set(&priv->rst_ready, 0);
}

static int
any_dirty(const epdd_priv_t *priv, int rows)
{
	int row;

	for (row = 0; row < rows; row++)
		if (priv->dirty[row])
			return 1;

	return 0;
}

/*
 * Tell whoever is waiting for the clear after init that it's done, and when
 * nothing is in flight and nothing is waiting, whoever is waiting for the
 * update they committed
 */

static void
epdd_check_idle(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);

	if (priv->booted) {
		priv->booted = 0;
		lwsl_info("%s: panel cleared\n", __func__);
		if (ed->cb)
			ed->cb(priv->lds, 1);
	}

	if (!slots_idle(priv) || priv->full_pending ||
	    any_dirty(priv, ed->panel->gate_rows))
		return;

	epdd_stats(priv);

	if (priv->committed) {
		priv->committed = 0;
		if (ed->cb)
			ed->cb(priv->lds, 2);
	}
}

lws_usec_t
lws_display_epd_direct_service(lws_display_state_t *lds)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(lds);
	epdd_priv_t *priv = lds_to_priv(lds);
	lws_usec_t now = lws_now_usecs(),
		   min_us = (lws_usec_t)ed->panel->min_pass_us,
		   idle_us = (lws_usec_t)ed->power_off_idle_ms * LWS_US_PER_MS;

	if (epdd_get(&priv->stopping)) {
		if (priv->powered) {
			ed->bus->power(ed->bus, 0);
			priv->powered = 0;
		}

		return LWS_EPDD_SVC_STOP;
	}

	if (slots_active(priv)) {
		/* the panel can't be scanned faster than its datasheet says */
		if (priv->last_pass && now - priv->last_pass < min_us)
			return min_us - (now - priv->last_pass);

		priv->last_pass = now;
		priv->idle_since = 0;
		epdd_pass(priv);

		if (slots_active(priv)) {
			now = lws_now_usecs() - priv->last_pass;

			return now < min_us ? min_us - now : 0;
		}
	}

	/* nothing to drive */

	if (!priv->powered) {
		epdd_set(&priv->power_off_req, 0);

		return LWS_EPDD_SVC_IDLE;
	}

	/* keep the panel powered for a while, in case more is coming */

	if (!priv->idle_since)
		priv->idle_since = now;

	if (!epdd_get(&priv->power_off_req) &&
	    now - priv->idle_since < idle_us)
		return idle_us - (now - priv->idle_since);

	ed->bus->power(ed->bus, 0);
	priv->powered = 0;
	epdd_set(&priv->power_off_req, 0);

	return LWS_EPDD_SVC_IDLE;
}

/*
 * Event loop side: collect what the runner side finished, start what was
 * waiting on it, and tell the caller about it.  Returns nonzero while
 * anything is in flight.
 */

static int
epdd_poll(epdd_priv_t *priv)
{
	if (epdd_get(&priv->power_failed)) {
		epdd_set(&priv->power_failed, 0);
		lwsl_err("%s: unable to power panel\n", __func__);
	}

	if (epdd_collect(priv))
		/* the pixels that were waiting on them can move now */
		epdd_start(priv);

	epdd_check_idle(priv);

	return !slots_idle(priv);
}

static void
epdd_pass_cb(lws_sorted_usec_list_t *sul)
{
	epdd_priv_t *priv = lws_container_of(sul, epdd_priv_t, sul_pass);
	lws_usec_t us = lws_display_epd_direct_service(priv->lds);

	epdd_poll(priv);

	if (us >= 0)
		schedule_pass(priv, us);
}

static void
epdd_poll_cb(lws_sorted_usec_list_t *sul)
{
	epdd_priv_t *priv = lws_container_of(sul, epdd_priv_t, sul_poll);
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);

	if (epdd_poll(priv))
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul_poll,
				 epdd_poll_cb, ed->panel->min_pass_us);
}

static int
check_table(const uint8_t *t, uint16_t len)
{
	uint16_t n;

	if (len && !t)
		return 1;

	for (n = 0; n < len; n++)
		if (t[n] > LWS_EPDD_WHITE)
			return 1;

	return 0;
}

static int
check_config(const lws_display_epd_direct_t *ed)
{
	const lws_surface_info_t *ic = &ed->disp.ic;
	const lws_epd_direct_panel_t *panel = ed->panel;
	const lws_epd_direct_waveform_bw_t *wf = ed->wf_bw;
	const lws_epd_direct_bus_ops_t *bus = ed->bus;

	if (!panel || !wf || !bus || !bus->init || !bus->power ||
	    !bus->frame_start || !bus->row_load || !bus->row_drive ||
	    !bus->row_skip || !bus->frame_end) {
		lwsl_err("%s: panel, waveform or bus ops missing\n", __func__);
		return 1;
	}

	if (!panel->source_px || panel->source_px % EPDD_PX_PER_BYTE ||
	    !panel->gate_rows || panel->gate_rows >= EPDD_NO_ROW ||
	    ic->wh_px[0].whole != panel->source_px ||
	    ic->wh_px[1].whole != panel->gate_rows) {
		lwsl_err("%s: surface doesn't match panel geometry\n", __func__);
		return 1;
	}

	if (!ic->greyscale || !ic->palette || ic->palette_depth != 2) {
		lwsl_err("%s: needs a 2-level greyscale palette\n", __func__);
		return 1;
	}

	if (check_table(wf->to_black, wf->to_black_len) ||
	    check_table(wf->to_white, wf->to_white_len) ||
	    check_table(wf->clear, wf->clear_len) ||
	    !wf->to_black_len || !wf->to_white_len || !wf->clear_len ||
	    !wf->drive_ns) {
		lwsl_err("%s: bad waveform\n", __func__);
		return 1;
	}

	return 0;
}

static void
epdd_free(const lws_display_epd_direct_t *ed, epdd_priv_t *priv)
{
	int n;

	for (n = 0; n < EPDD_SLOTS; n++)
		lws_free_set_NULL(priv->slot[n].blk);

	for (n = 0; n < 3; n++) {
		uint8_t **b = n < 2 ? &priv->rowbuf[n] : &priv->nonebuf;

		if (!*b)
			continue;
		if (ed->bus->free_dma)
			ed->bus->free_dma(ed->bus, (void **)b);
		else
			lws_free_set_NULL(*b);
	}

	lws_free_set_NULL(priv->drv);
	lws_free_set_NULL(priv->u[0]);
	lws_free_set_NULL(priv->want);
	lws_free(priv);
}

int
lws_display_epd_direct_init(lws_display_state_t *lds)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(lds);
	const lws_epd_direct_panel_t *panel;
	epdd_priv_t *priv;
	size_t len, pw;
	int row, w;

	if (check_config(ed))
		return 1;

	panel = ed->panel;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	priv->words = (panel->source_px + 31) / 32;
	priv->last_word_mask = panel->source_px & 31 ?
			(1u << (panel->source_px & 31)) - 1u : 0xffffffffu;
	priv->row_bytes = panel->source_px / EPDD_PX_PER_BYTE;
	pw = (size_t)priv->words * panel->gate_rows;
	priv->plane_words = pw;

	/* want, tgt and busy planes, and the per-row dirty flags */

	priv->want = lws_zalloc(3 * pw * sizeof(uint32_t) + panel->gate_rows,
				__func__);
	if (!priv->want)
		goto bail;

	priv->tgt = priv->want + pw;
	priv->busy = priv->tgt + pw;
	priv->dirty = (uint8_t *)(priv->busy + pw);

	/*
	 * The drive masks are worked on for every row of every pass, so they
	 * are a small allocation of their own, apart from the planes, which
	 * may have to go in slower memory
	 */

	priv->drv = lws_zalloc(4u * (size_t)priv->words * sizeof(uint32_t),
			       __func__);
	if (!priv->drv)
		goto bail;

	/* until told otherwise, white is wanted */

	for (row = 0; row < (int)panel->gate_rows; row++) {
		uint32_t *wa = plane_row(priv, priv->want, row);

		for (w = 0; w < priv->words; w++)
			wa[w] = w == priv->words - 1 ? priv->last_word_mask :
						       0xffffffffu;
	}

	len = priv->row_bytes + ed->bus->row_tail_bytes;
	for (w = 0; w < 3; w++) {
		uint8_t *b = ed->bus->alloc_dma ?
				ed->bus->alloc_dma(ed->bus, len) :
				lws_malloc(len, __func__);

		if (!b)
			goto bail;
		if (w < 2)
			priv->rowbuf[w] = b;
		else
			priv->nonebuf = b;
	}

	build_luts(priv, panel);

	/* the tail of every row, and all of the none row, are no drive */

	memset(priv->nonebuf, priv->lut_n[0xff] >> 8, len);
	for (w = 0; w < 2; w++)
		memset(priv->rowbuf[w] + priv->row_bytes,
		       priv->lut_n[0xff] >> 8, ed->bus->row_tail_bytes);

	if (lws_display_alloc_diffusion(&ed->disp.ic, priv->u))
		goto bail;

	if (ed->bus->init(ed->bus)) {
		lwsl_err("%s: bus init failed\n", __func__);
		goto bail;
	}

	lds->priv = priv;

	/*
	 * What the panel is showing is unknown, so clear it before anything
	 * else.  We tell the caller the display is ready when it's done.
	 */

	if (ed->runner && ed->runner->start(ed->runner, lds)) {
		lwsl_err("%s: runner start failed\n", __func__);
		lds->priv = NULL;
		if (ed->bus->deinit)
			ed->bus->deinit(ed->bus);
		goto bail;
	}

	priv->booting = 1;
	priv->full_pending = 1;
	epdd_start(priv);

	lwsl_notice("%s: %s, %ux%u\n", __func__, panel->name,
		    (unsigned int)panel->source_px,
		    (unsigned int)panel->gate_rows);

	return 0;

bail:
	lwsl_err("%s: OOM\n", __func__);
	epdd_free(ed, priv);

	return 1;
}

/*
 * Store a line of Y pixels into the want plane, dithered to black and white
 */

static void
epdd_line(lws_display_state_t *lds, const uint8_t *src, int y)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(lds);
	const lws_surface_info_t *ic = &ed->disp.ic;
	epdd_priv_t *priv = lds_to_priv(lds);
	int x, px, row, width = ic->wh_px[0].whole;
	lws_greyscale_error_t *gthis, *gnext;
	lws_display_palette_idx_t idx;
	lws_display_colour_t c;
	uint32_t *wa;

	if (y < 0 || y >= ic->wh_px[1].whole) {
		lwsl_warn("%s: line %d outside surface\n", __func__, y);
		return;
	}

	row = ed->mirror_y ? ed->panel->gate_rows - 1 - y : y;
	wa = plane_row(priv, priv->want, row);
	priv->dirty[row] = 1;

	if (!src) {
		/* a line we aren't given pixels for is white */
		for (x = 0; x < priv->words; x++)
			wa[x] = x == priv->words - 1 ? priv->last_word_mask :
						       0xffffffffu;
		return;
	}

	gthis = (lws_greyscale_error_t *)priv->u[(y & 1) ^ 1];
	gnext = (lws_greyscale_error_t *)priv->u[y & 1];

	for (x = 0; x < width; x++) {
		c = (lws_display_colour_t)((src[x] << 16) | (src[x] << 8) |
					   src[x]);
		idx = lws_display_palettize_grey(ic, ic->palette,
						 ic->palette_depth, c,
						 &gthis[x]);
		dist_err_floyd_steinberg_grey(x, width, gthis, gnext);

		px = ed->mirror_x ? width - 1 - x : x;
		if (LWSDC_R(ic->palette[idx]) >= 0x80)
			wa[px >> 5] |= 1u << (px & 31);
		else
			wa[px >> 5] &= ~(1u << (px & 31));
	}
}

int
lws_display_epd_direct_blit(lws_display_state_t *lds, const uint8_t *src,
			    lws_box_t *box, lws_dll2_owner_t *ids)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(lds);
	epdd_priv_t *priv = lds_to_priv(lds);

	(void)ids;

	if (!priv)
		return 1;

	switch (box->h.whole) {
	case 0:
		/*
		 * The lines we were given are what's wanted.  Start what can
		 * be started, the rest waits on pixels still moving
		 */
		priv->committed = 1;
		if (!priv->st_commit)
			priv->st_commit = lws_now_usecs();
		if (ed->full_refresh_every &&
		    ++priv->updates >= ed->full_refresh_every)
			priv->full_pending = 1;
		epdd_start(priv);
		epdd_check_idle(priv);
		if (slots_idle(priv))
			/* nothing changed, so there's nothing to time */
			priv->st_commit = 0;
		break;

	case 1:
		epdd_line(lds, src, box->y.whole);
		break;

	default:
		/*
		 * The start of an update, src is not pixels.  The lines that
		 * follow are dithered from scratch.
		 */
		memset(priv->u[0], 0, (size_t)(((ed->disp.ic.wh_px[0].whole +
				15) / 8) * 8) * 2u * sizeof(lws_greyscale_error_t));
		break;
	}

	return 0;
}

int
lws_display_epd_direct_power(lws_display_state_t *lds, int state)
{
	epdd_priv_t *priv = lds_to_priv(lds);

	/*
	 * The panel keeps what it shows without power.  We power it for the
	 * passes ourselves, but if we are told it's off, once nothing is in
	 * flight, there's no need to wait out the idle time
	 */

	if (priv && !state) {
		epdd_set(&priv->power_off_req, 1);
		epdd_kick(priv);
	}

	return 0;
}

void
lws_display_epd_direct_destroy(lws_display_state_t *lds)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(lds);
	epdd_priv_t *priv = lds_to_priv(lds);

	if (!priv)
		return;

	/*
	 * The runner side unpowers the panel and stops.  Without a runner, we
	 * are the runner side.
	 */

	epdd_set(&priv->stopping, 1);
	if (ed->runner)
		ed->runner->stop(ed->runner);
	else
		lws_display_epd_direct_service(lds);

	lws_sul_cancel(&priv->sul_pass);
	lws_sul_cancel(&priv->sul_poll);

	if (ed->bus->deinit)
		ed->bus->deinit(ed->bus);

	epdd_free(ed, priv);
	lds->priv = NULL;
}
