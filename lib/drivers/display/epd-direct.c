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
 * their pass count and state, at pass boundaries.  At the moment the passes
 * are run from the event loop thread too, one pass per sul callback.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

#define EPDD_SLOTS		4
#define EPDD_NO_ROW		0xffff
/* pixels in a bus byte: each has a 2-bit code */
#define EPDD_PX_PER_BYTE	4

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
	/**< enum epdd_slot_state */
	uint8_t			clear;
	/**< it's the clear waveform on every pixel, it has no masks */
} epdd_slot_t;

typedef struct epdd_priv {
	lws_display_state_t	*lds;
	lws_sorted_usec_list_t	sul_pass;
	lws_sorted_usec_list_t	sul_power;

	lws_surface_error_t	*u[2];
	/**< error diffusion for two lines */

	uint32_t		*want;
	uint32_t		*tgt;
	uint32_t		*busy;
	uint8_t			*dirty;
	/**< per gate row, want may differ from tgt there */

	uint8_t			*rowbuf;
	/**< drive codes for a row, then its tail */
	uint8_t			*nonebuf;
	/**< a row of "no drive", then its tail */
	uint32_t		*drv_b;
	uint32_t		*drv_w;
	/**< the pixels of the row being encoded driven black, and white */

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

	lws_usec_t		st_start;
	/**< the first pass started */
	lws_usec_t		st_commit;
	/**< 0, or the first update was committed */
	lws_usec_t		st_scan_min;
	lws_usec_t		st_scan_max;
	lws_usec_t		st_scan_sum;
	/**< how long passes took to scan the rows, not counting waiting
	 * between passes for the panel's maximum frame rate */
	uint32_t		st_passes;
	uint32_t		st_rows_driven;
	uint32_t		st_rows_skipped;
	uint32_t		st_rows_none;
	/**< rows not driven that had to be loaded to latch "no drive" */
	uint32_t		st_px_black;
	uint32_t		st_px_white;
	uint16_t		st_updates;
	uint16_t		st_clears;

	uint8_t			powered:1;
	uint8_t			latched_none:1;
	/**< what's latched in the source drivers is no drive */
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

static int
slots_idle(const epdd_priv_t *priv)
{
	int n;

	for (n = 0; n < EPDD_SLOTS; n++)
		if (priv->slot[n].state != EPDD_SLOT_FREE)
			return 0;

	return 1;
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

/*
 * Turn the row's drv_b / drv_w into bus bytes in priv->rowbuf
 */

static void
pack_row(epdd_priv_t *priv)
{
	uint8_t *p = priv->rowbuf;
	size_t left = priv->row_bytes;
	int g, groups = (int)((priv->row_bytes + 1) / 2);

	for (g = 0; g < groups; g++) {
		int sh = (g & 3) * 8;
		uint8_t b = (uint8_t)(priv->drv_b[g >> 2] >> sh),
			w = (uint8_t)(priv->drv_w[g >> 2] >> sh);
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
 * Work out what the slots running drive the row with into drv_b / drv_w.
 * Returns nonzero if any of it is driven.
 */

static int
encode_row(epdd_priv_t *priv, const lws_epd_direct_waveform_bw_t *wf, int row)
{
	uint32_t any = 0;
	int n, w;

	memset(priv->drv_b, 0, sizeof(uint32_t) * (size_t)priv->words);
	memset(priv->drv_w, 0, sizeof(uint32_t) * (size_t)priv->words);

	for (n = 0; n < EPDD_SLOTS; n++) {
		const epdd_slot_t *s = &priv->slot[n];
		const uint32_t *tb, *tw;
		uint8_t cb, cw;

		if (s->state != EPDD_SLOT_RUNNING)
			continue;

		if (s->clear) {
			uint32_t *d;

			cb = slot_code(s, wf->clear, wf->clear_len);
			if (cb == LWS_EPDD_NONE)
				continue;

			d = cb == LWS_EPDD_BLACK ? priv->drv_b : priv->drv_w;
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
				priv->drv_b[w] |= tb[w];
			else if (cb == LWS_EPDD_WHITE)
				priv->drv_w[w] |= tb[w];

			if (cw == LWS_EPDD_BLACK)
				priv->drv_b[w] |= tw[w];
			else if (cw == LWS_EPDD_WHITE)
				priv->drv_w[w] |= tw[w];
		}
	}

	for (w = 0; w < priv->words; w++)
		any |= priv->drv_b[w] | priv->drv_w[w];

	return !!any;
}

/*
 * One pass over every row, driving the slots that are running.  This side
 * only reads the slots' masks, and changes their pass counts and states.
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
	int n, row, any = 0;
	lws_usec_t t0;

	/* updates made since the last pass join at this pass boundary */

	for (n = 0; n < EPDD_SLOTS; n++) {
		if (priv->slot[n].state == EPDD_SLOT_ARMED)
			priv->slot[n].state = EPDD_SLOT_RUNNING;
		if (priv->slot[n].state == EPDD_SLOT_RUNNING)
			any = 1;
	}

	if (!any)
		return 0;

	if (!priv->powered) {
		lws_sul_cancel(&priv->sul_power);
		if (bus->power(bus, 1)) {
			lwsl_err("%s: unable to power panel\n", __func__);
			return 0;
		}
		priv->powered = 1;
		/* we don't know what the source drivers came up latching */
		priv->latched_none = 0;
	}

	t0 = lws_now_usecs();
	if (!priv->st_passes++)
		priv->st_start = t0;

	bus->frame_start(bus);

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		if (!encode_row(priv, wf, row)) {
			/*
			 * Nothing to drive on this row.  Stepping over it
			 * drives what's latched onto it, so it must be no
			 * drive.  If it isn't, load and latch some, which
			 * costs this row the time of a driven one.
			 */
			if (priv->latched_none) {
				bus->row_skip(bus);
				priv->st_rows_skipped++;
				continue;
			}
			bus->row_load(bus, priv->nonebuf, len);
			bus->row_drive(bus, wf->row_drive_us);
			priv->latched_none = 1;
			priv->st_rows_none++;
			continue;
		}

		pack_row(priv);
		bus->row_load(bus, priv->rowbuf, len);
		bus->row_drive(bus, wf->row_drive_us);
		priv->latched_none = 0;
		priv->st_rows_driven++;
	}

	bus->frame_end(bus);

	t0 = lws_now_usecs() - t0;
	if (priv->st_passes == 1 || t0 < priv->st_scan_min)
		priv->st_scan_min = t0;
	if (t0 > priv->st_scan_max)
		priv->st_scan_max = t0;
	priv->st_scan_sum += t0;

	for (n = 0; n < EPDD_SLOTS; n++) {
		epdd_slot_t *s = &priv->slot[n];

		if (s->state == EPDD_SLOT_RUNNING && ++s->pass >= s->len)
			s->state = EPDD_SLOT_DONE;
	}

	return 1;
}

static epdd_slot_t *
free_slot(epdd_priv_t *priv)
{
	int n;

	for (n = 0; n < EPDD_SLOTS; n++)
		if (priv->slot[n].state == EPDD_SLOT_FREE)
			return &priv->slot[n];

	return NULL;
}

static void
schedule_pass(epdd_priv_t *priv, lws_usec_t us)
{
	if (!lws_dll2_is_detached(&priv->sul_pass.list))
		return;

	lws_sul_schedule(priv->lds->ctx, 0, &priv->sul_pass, epdd_pass_cb, us);
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

	memset(s, 0, sizeof(*s));
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
	s->state = EPDD_SLOT_ARMED;
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
		schedule_pass(priv, 0);

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

	memset(s, 0, sizeof(*s));
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
	s->state = EPDD_SLOT_ARMED;
	schedule_pass(priv, 0);
}

/*
 * The slots that finished give their pixels back.  Only the event loop side
 * frees slots.  Returns nonzero if any finished.
 */

static int
epdd_collect(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	int n, row, w, done = 0;

	for (n = 0; n < EPDD_SLOTS; n++) {
		epdd_slot_t *s = &priv->slot[n];

		if (s->state != EPDD_SLOT_DONE)
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

		lws_free_set_NULL(s->blk);
		memset(s, 0, sizeof(*s));
	}

	return done;
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

	if (priv->committed) {
		priv->committed = 0;
		if (ed->cb)
			ed->cb(priv->lds, 2);
	}
}

static void
epdd_power_off_cb(lws_sorted_usec_list_t *sul)
{
	epdd_priv_t *priv = lws_container_of(sul, epdd_priv_t, sul_power);
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);

	if (!priv->powered || !slots_idle(priv))
		return;

	ed->bus->power(ed->bus, 0);
	priv->powered = 0;
}

/*
 * The panel has gone idle, say what it did since it was last idle
 */

static void
epdd_stats(epdd_priv_t *priv)
{
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	lws_usec_t now = lws_now_usecs();

	if (!priv->st_passes)
		return;

	lwsl_notice("%s: %u passes in %dms, scans %d / %d / %dus "
		    "(min / avg / max); rows %u driven, %u skipped, %u "
		    "latched none; px %u to black, %u to white; %u updates, "
		    "%u clears; settled %dms after commit\n", __func__,
		    (unsigned int)priv->st_passes,
		    (int)((now - priv->st_start) / LWS_US_PER_MS),
		    (int)priv->st_scan_min,
		    (int)(priv->st_scan_sum / priv->st_passes),
		    (int)priv->st_scan_max,
		    (unsigned int)priv->st_rows_driven,
		    (unsigned int)priv->st_rows_skipped,
		    (unsigned int)priv->st_rows_none,
		    (unsigned int)priv->st_px_black,
		    (unsigned int)priv->st_px_white,
		    (unsigned int)priv->st_updates,
		    (unsigned int)priv->st_clears,
		    priv->st_commit ?
			(int)((now - priv->st_commit) / LWS_US_PER_MS) : -1);
#endif

	priv->st_start = priv->st_commit = 0;
	priv->st_scan_min = priv->st_scan_max = priv->st_scan_sum = 0;
	priv->st_passes = priv->st_rows_driven = priv->st_rows_skipped =
			  priv->st_rows_none = 0;
	priv->st_px_black = priv->st_px_white = 0;
	priv->st_updates = priv->st_clears = 0;
}

static void
epdd_pass_cb(lws_sorted_usec_list_t *sul)
{
	epdd_priv_t *priv = lws_container_of(sul, epdd_priv_t, sul_pass);
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	lws_usec_t t0 = lws_now_usecs(), el, min_us;

	epdd_pass(priv);

	if (epdd_collect(priv))
		/* the pixels that were waiting on them can move now */
		epdd_start(priv);

	epdd_check_idle(priv);

	if (!slots_idle(priv)) {
		/* the panel can't be scanned faster than its datasheet says */
		el = lws_now_usecs() - t0;
		min_us = (lws_usec_t)ed->panel->min_pass_us;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul_pass,
				 epdd_pass_cb, el < min_us ? min_us - el : 0);
		return;
	}

	epdd_stats(priv);

	if (priv->powered)
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul_power,
				 epdd_power_off_cb,
				 (lws_usec_t)ed->power_off_idle_ms *
							LWS_US_PER_MS);
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
	    !wf->to_black_len || !wf->to_white_len || !wf->clear_len) {
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

	if (ed->bus->free_dma) {
		if (priv->rowbuf)
			ed->bus->free_dma(ed->bus, (void **)&priv->rowbuf);
		if (priv->nonebuf)
			ed->bus->free_dma(ed->bus, (void **)&priv->nonebuf);
	} else {
		lws_free_set_NULL(priv->rowbuf);
		lws_free_set_NULL(priv->nonebuf);
	}

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

	/*
	 * want, tgt and busy planes, the per-row dirty flags, and the two
	 * words-wide rows being encoded, in one allocation
	 */

	priv->want = lws_zalloc((3 * pw + 2 * (size_t)priv->words) *
				sizeof(uint32_t) + panel->gate_rows, __func__);
	if (!priv->want)
		goto bail;

	priv->tgt = priv->want + pw;
	priv->busy = priv->tgt + pw;
	priv->drv_b = priv->busy + pw;
	priv->drv_w = priv->drv_b + priv->words;
	priv->dirty = (uint8_t *)(priv->drv_w + priv->words);

	/* until told otherwise, white is wanted */

	for (row = 0; row < (int)panel->gate_rows; row++) {
		uint32_t *wa = plane_row(priv, priv->want, row);

		for (w = 0; w < priv->words; w++)
			wa[w] = w == priv->words - 1 ? priv->last_word_mask :
						       0xffffffffu;
	}

	len = priv->row_bytes + ed->bus->row_tail_bytes;
	if (ed->bus->alloc_dma) {
		priv->rowbuf = ed->bus->alloc_dma(ed->bus, len);
		priv->nonebuf = ed->bus->alloc_dma(ed->bus, len);
	} else {
		priv->rowbuf = lws_malloc(len, __func__);
		priv->nonebuf = lws_malloc(len, __func__);
	}
	if (!priv->rowbuf || !priv->nonebuf)
		goto bail;

	build_luts(priv, panel);

	/* the tail of every row, and all of the none row, are no drive */

	memset(priv->nonebuf, priv->lut_n[0xff] >> 8, len);
	memset(priv->rowbuf + priv->row_bytes, priv->lut_n[0xff] >> 8,
	       ed->bus->row_tail_bytes);

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
	 * passes ourselves, but if we are told it's off and nothing is in
	 * flight, there's no need to wait out the idle time
	 */

	if (priv && !state && priv->powered && slots_idle(priv)) {
		lws_sul_cancel(&priv->sul_power);
		epdd_power_off_cb(&priv->sul_power);
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

	lws_sul_cancel(&priv->sul_pass);
	lws_sul_cancel(&priv->sul_power);

	if (priv->powered)
		ed->bus->power(ed->bus, 0);
	if (ed->bus->deinit)
		ed->bus->deinit(ed->bus);

	epdd_free(ed, priv);
	lds->priv = NULL;
}
