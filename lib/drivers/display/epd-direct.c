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
 * A pixel's grey level is "bits" wide, 1, 2 or 4 bits for 2, 4 or 16 levels,
 * 0 black and all ones white.  Levels are kept packed in byte planes, pixel x
 * of a row in bits (x * bits) & 7 up of byte (x * bits) >> 3, and pixel states
 * in 32-bit word planes, pixel x of a row in bit (x & 31) of word (x >> 5).
 *
 * The side of the driver on the lws event loop thread keeps
 *
 *  - want:  the level the pixel was last given in a blit
 *  - tgt:   the level the pixel is, or is moving to
 *  - busy:  the pixel has a transition in flight
 *
 * so when want differs from tgt, a pixel that isn't busy, and whose span has
 * nothing busy in it, can join a new update.  Other pixels that differ wait
 * for what's in flight to finish.
 *
 * The side running the passes keeps
 *
 *  - ft:    the level the pixel is moving from, then the one it's moving to,
 *           2 x bits wide, the "to" in the low bits.  A pixel with nothing in
 *           flight has both the same, the level it's at.
 *  - rbusy: the pixel has a transition in flight
 *  - start: per span, the 4 bits of when the transitions in it started
 *
 * An update in flight is a "slot".  It's made by the event loop side, with a
 * mask of the pixels on each row that are in it and the levels they move to,
 * and handed over to the runner side.  At the next pass that's a multiple of
 * 4, the runner side puts its pixels in its own planes, and they start.  When
 * the transition table's passes are done, it takes them back out, and says
 * the slot is done.  The event loop side then frees the slot and the pixels
 * that were waiting on it can move.
 *
 * Transitions start on a pass that's a multiple of 4, so where a pixel is in
 * its transition is known from the pass count and the 4 bits of when it
 * started, in 4-pass units: there can be 64 passes in a table.  A span's
 * pixels all start together, which is why a pixel waits for a span with
 * anything in flight.  At most one update starts per 4 passes, and none lasts
 * more than 64 passes, so there are always slots enough.
 *
 * The planes and the slots' pixels are only ever touched by the side that
 * owns them.  The two sides share only the slots' states, which are published
 * with release and read with acquire ordering, and a few flags done the same
 * way.  Everything else belongs to one side or the other:
 *
 *  - event loop side: want, tgt, busy, the dirty flags, making slots and
 *    freeing them, telling the caller about completions, logging
 *
 *  - runner side: ft, rbusy, start, the pass count, the bus and everything
 *    it's given, the row buffers and drive masks, whether the panel is
 *    powered, the pass timing
 *
 * When there's a runner, the event loop side looks at the slots at the pass
 * rate while any are in flight, to collect the ones that finished.  The
 * runner never calls into lws.
 *
 * The panel is active-matrix: each pixel holds the voltage last written to it
 * until its row is written again, and goes on moving its ink with it.  So the
 * drive a pixel is given in a pass lasts until the next pass, not just while
 * its row is selected, and once it's to stop moving, its row has to be written
 * with "no drive" properly, for the full row time.  Only a row that was given
 * no drive like that can be stepped over quickly.  When the last update
 * finishes, one more pass writes "no drive" to the rows it drove last, and
 * the update isn't said to be complete until then.
 *
 * In a pass, each row is encoded while the one before it is being sent to the
 * source drivers, into the row buffer that isn't being sent, so the cpu time
 * hides inside the bus time.  Encoding looks only at the pixels with a
 * transition in flight, by rbusy, and looks up each one's drive code for the
 * pass by when its span started and its ft.  A row that encodes the same as
 * the last one that was encoded, eg, every row of a clear, sends the same
 * buffer again.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

/* updates in flight at once: one can start every 4 passes */
#define EPDD_SLOTS		((LWS_EPDD_MAX_PHASES / 4) + 2)
#define EPDD_NO_ROW		0xffff
/* pixels in a bus byte: each has a 2-bit code */
#define EPDD_PX_PER_BYTE	4
/* what's known of when a span's transitions started, in 4-pass units */
#define EPDD_STARTS		16

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
	EPDD_SLOT_ARMED,	/* made, waiting for a pass to start on */
	EPDD_SLOT_RUNNING,	/* being driven, pass by pass */
	EPDD_SLOT_DONE,		/* driven for all its passes */
};

typedef struct epdd_slot {
	void			*blk;
	/**< the one allocation holding row_idx, masks and to */
	uint16_t		*row_idx;
	/**< per gate row, which of the rows below is for it, or EPDD_NO_ROW */
	uint32_t		*masks;
	/**< per row with pixels in this update, words of which ones */
	uint8_t			*to;
	/**< per row with pixels in this update, the levels they move to, as
	 * a level plane row */
	uint32_t		pass0;
	/**< runner side: the pass it started on */
	uint16_t		len;
	/**< passes it needs */
	uint8_t			state;
	/**< enum epdd_slot_state, shared, use epdd_get() / epdd_set() */
	uint8_t			clear;
	/**< it's the clear waveform on every pixel, it has no rows */
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
	lws_usec_t		prep_sum;
	/**< how much of scan_sum went on working out what to send to the
	 * rows */
	lws_usec_t		bus_sum;
	/**< how much went on the bus' row_load() and row_drive(), which
	 * includes waiting for it */
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

	/* event loop side planes, in the one allocation at busy */

	uint32_t		*busy;
	uint8_t			*want;
	uint8_t			*tgt;
	uint8_t			*dirty;
	/**< per gate row, want may differ from tgt there */

	/* runner side planes */

	uint8_t			*ft;
	uint32_t		*rbusy;
	uint8_t			*start;
	const uint8_t		*codes;
	/**< per pass of the transition table, per ft, the LWS_EPDD_* code,
	 * for the display's levels */

	uint8_t			*charged;
	/**< per gate row, its pixels may hold a drive from the last pass
	 * that it was loaded in */
	uint8_t			*rowbuf[2];
	/**< drive codes for a row, then its tail: one can be sent while the
	 * next row is encoded into the other */
	uint8_t			*nonebuf;
	/**< a row of "no drive", then its tail */
	const uint8_t		*lut[EPDD_STARTS];
	/**< for this pass, per when a span started, the bus bits for each
	 * ft at each of the four places in a bus byte */
	uint8_t			cur;
	/**< the rowbuf last packed, which may be being sent */
	uint8_t			cur_valid;
	/**< rowbuf[cur] has been packed in this pass */
	uint8_t			fast_rbusy;
	uint8_t			fast_start;
	uint8_t			fast_codes;
	uint8_t			fast_16l;
	/**< these came from the bus' alloc_fast */
	uint8_t			use_16l;
	/**< the bus' .encode_16l is used for words with every pixel in
	 * flight */

	epdd_slot_t		slot[EPDD_SLOTS];

	uint8_t			*tables_16l;
	/**< what .encode_16l uses, LWS_EPDD_16L_LEN bytes, 16-byte aligned
	 * in tables_16l_alloc */
	void			*tables_16l_alloc;
	uint8_t			*ft_alloc;
	/**< ft, 16-byte aligned in this */
	uint8_t			*no_codes;
	/**< like a pass of codes, for transitions with nothing to drive */
	uint8_t			none_byte;
	/**< a bus byte driving none of its four pixels */

	size_t			row_bytes;
	/**< the panel's own bytes for a row, without the tail */
	size_t			plane_words;
	/**< words in a pixel state plane */
	size_t			lstride;
	/**< bytes for a row in a level plane */
	size_t			ftstride;
	/**< bytes for a row of ft */
	size_t			sstride;
	/**< bytes for a row of start */
	int			words;
	/**< 32-bit words for a row in a pixel state plane */
	uint32_t		last_word_mask;
	/**< the bits of the last word of a row that are pixels */
	uint8_t			bits;
	/**< bits in a level */
	uint8_t			span_shift;
	/**< log2 of the pixels in a span */

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
	uint32_t		st_px;
	uint16_t		st_updates;
	uint16_t		st_clears;

	/* runner side */

	lws_usec_t		last_pass;
	/**< 0, or when the last pass started */
	lws_usec_t		idle_since;
	/**< 0, or when the runner found nothing to drive while powered */
	uint32_t		pass;
	/**< passes so far, it may wrap */
	uint32_t		charged_n;
	/**< rows that may hold a drive */
	uint8_t			powered;
	uint8_t			latched_none;
	/**< what's latched in the source drivers is no drive */

	/* shared, use epdd_get() / epdd_set() */

	uint8_t			rst_ready;
	/**< the runner side handed over rst_pub, for the event loop side */
	uint8_t			rs_charged;
	/**< the runner side has rows that may hold a drive, so it has another
	 * pass to do even with no updates in flight */
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
	uint8_t			clear_next:1;
	/**< the next update to be committed starts with a clear */
} epdd_priv_t;

#define lds_to_disp(_lds) ((const lws_display_epd_direct_t *)(_lds)->disp)
#define lds_to_priv(_lds) ((epdd_priv_t *)(_lds)->priv)

static void
epdd_pass_cb(lws_sorted_usec_list_t *sul);
static void
epdd_poll_cb(lws_sorted_usec_list_t *sul);
static void
epdd_stats(epdd_priv_t *priv);

static uint32_t *
plane_row(const epdd_priv_t *priv, uint32_t *plane, int row)
{
	return plane + (size_t)row * (size_t)priv->words;
}

/*
 * Packed fields of a byte plane row: field x is "width" bits, 1, 2, 4 or 8,
 * so it never straddles a byte
 */

static unsigned int
fld_get(const uint8_t *r, int x, unsigned int width)
{
	unsigned int b = (unsigned int)x * width;

	return (r[b >> 3] >> (b & 7)) & ((1u << width) - 1u);
}

static void
fld_set(uint8_t *r, int x, unsigned int width, unsigned int v)
{
	unsigned int b = (unsigned int)x * width,
		     m = ((1u << width) - 1u) << (b & 7);

	r[b >> 3] = (uint8_t)((r[b >> 3] & ~m) | ((v << (b & 7)) & m));
}

static uint8_t *
lvl_row(const epdd_priv_t *priv, uint8_t *plane, int row)
{
	return plane + (size_t)row * priv->lstride;
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

/* the code in the waveform's transition table, in its own levels */

static uint8_t
wf_code(const lws_epd_direct_waveform_t *wf, unsigned int pass,
	unsigned int to, unsigned int from)
{
	size_t rb = ((size_t)wf->levels + 3) / 4;
	const uint8_t *r = wf->update + ((size_t)pass * wf->levels + to) * rb;

	return (uint8_t)((r[from >> 2] >> (6 - 2 * (from & 3))) & 3);
}

/*
 * A pixel's LWS_EPDD_* code as the panel's code for it, at its place in a bus
 * byte, 0 being the first pixel
 */

static uint8_t
bus_bits(const lws_epd_direct_panel_t *panel, unsigned int place, uint8_t c)
{
	const uint8_t map[4] = { panel->code_none, panel->code_black,
				 panel->code_white, panel->code_none };
	unsigned int shift = panel->flags & LWS_EPDD_PANEL_FL_FIRST_PX_LSB ?
						place * 2 : (3 - place) * 2;

	return (uint8_t)((map[c & 3] & 3) << shift);
}

/* the bus byte for four pixels all driven with the same LWS_EPDD_* code */

static uint8_t
bus_fill(const lws_epd_direct_panel_t *panel, uint8_t c)
{
	return (uint8_t)(bus_bits(panel, 0, c) | bus_bits(panel, 1, c) |
			 bus_bits(panel, 2, c) | bus_bits(panel, 3, c));
}

/*
 * The transition table in the display's levels, so a pixel's code is looked
 * up by its ft directly.  The display's levels are spread evenly over the
 * waveform's.
 *
 * Each pass has the codes four times, once for each place in a bus byte,
 * already as the panel's bits for it there.  So a bus byte is just the four
 * pixels' entries or-ed together.
 */

static void
build_codes(epdd_priv_t *priv, uint8_t *codes)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	const lws_epd_direct_waveform_t *wf = ed->wf;
	unsigned int levels = 1u << priv->bits, p, j, f, t,
		     wl = (unsigned int)wf->levels - 1u, dl = levels - 1u;

	for (p = 0; p < wf->update_passes; p++)
		for (j = 0; j < EPDD_PX_PER_BYTE; j++)
			for (f = 0; f < levels; f++)
				for (t = 0; t < levels; t++)
					*codes++ = bus_bits(ed->panel, j,
						wf_code(wf, p, (t * wl) / dl,
							(f * wl) / dl));
}

/*
 * Runner side: before a pass, which codes the transitions that started at
 * each of the 16 starts we can tell apart are driven with in it
 */

static void
pass_luts(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	size_t per = (size_t)EPDD_PX_PER_BYTE << (2 * priv->bits);
	uint32_t q = priv->pass >> 2;
	unsigned int s, p;

	for (s = 0; s < EPDD_STARTS; s++) {
		p = (((q - s) & (EPDD_STARTS - 1)) << 2) | (priv->pass & 3);
		priv->lut[s] = p < ed->wf->update_passes ?
					priv->codes + p * per : priv->no_codes;
	}

	if (priv->use_16l) {
		/*
		 * The codes for .encode_16l, by start << 8 | ft.  Its first
		 * pixel is in the most significant bits, where the last of
		 * the four places in a bus byte is the code unshifted.
		 */
		uint32_t *c = (uint32_t *)(void *)(priv->tables_16l +
						   LWS_EPDD_16L_CODES);
		unsigned int f;

		for (s = 0; s < EPDD_STARTS; s++) {
			const uint8_t *l = priv->lut[s] + 3 * 256;

			for (f = 0; f < 256; f++)
				*c++ = l[f];
		}
	}
}

/*
 * Work out what the pixels in flight on the row are driven with in this pass,
 * into the bus bytes of rowbuf[buf].  Returns nonzero if any of it is driven.
 *
 * This is done for every row of every pass while the row before is being
 * sent, and with every pixel moving it's most of what a pass costs, so it has
 * to be quick: a bus byte is the or of its four pixels' entries in the pass'
 * codes, and a word of pixels with nothing in flight is just "no drive".
 *
 * What it uses from priv is copied into locals first: the bus bytes are
 * stored through a uint8_t *, which may alias anything, so otherwise each
 * one would be read from priv again after every store.
 */

static int
encode_row(epdd_priv_t *priv, const epdd_slot_t *clear, int row, int buf)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	const uint32_t *rb = plane_row(priv, priv->rbusy, row);
	const uint8_t *ftr = priv->ft + (size_t)row * priv->ftstride,
		      *sr = priv->start + (size_t)row * priv->sstride,
		      *nc = priv->no_codes, *t16l = priv->tables_16l,
		      *lut[EPDD_STARTS], *l;
	uint32_t (*enc16l)(uint8_t *out, const uint8_t *ft,
			   const uint8_t *starts, size_t words,
			   const void *tables) =
			priv->use_16l ? ed->bus->encode_16l : NULL;
	unsigned int bits = priv->bits, ss = priv->span_shift,
		     ftw = 2u * bits, any = 0, mm, j, v;
	size_t per = (size_t)1 << ftw, k, nb, left = priv->row_bytes;
	uint8_t *o = priv->rowbuf[buf], none = priv->none_byte;
	int w, x, n, words = priv->words, quad = ss >= 2,
	    whole = (int)(ed->panel->source_px / 32);
	uint32_t m;

	if (clear) {
		uint8_t c = ed->wf->clear[priv->pass - clear->pass0];

		/* a clear has the panel to itself and drives every pixel */

		memset(o, bus_fill(ed->panel, c), left);

		return c != LWS_EPDD_NONE;
	}

	memcpy(lut, priv->lut, sizeof(lut));

	for (w = 0; w < words; w++, o += nb, left -= nb) {
		nb = left < 8 ? left : 8;
		m = rb[w];

		if (!m) {
			memset(o, none, nb);
			continue;
		}

		if (enc16l && m == 0xffffffffu && w < whole) {
			/*
			 * The platform does runs of words with every pixel
			 * in flight, other than a last word that isn't all
			 * pixels, so each is 8 bus bytes
			 */
			for (n = 1; w + n < whole &&
				    rb[w + n] == 0xffffffffu; n++)
				;
			any |= enc16l(o, ftr + w * 32, sr + w * 2, (size_t)n,
				      t16l);
			nb = (size_t)n * 8;
			w += n - 1;
			continue;
		}

		for (k = 0, x = w * 32; k < nb; k++, x += 4, m >>= 4) {
			mm = m & 0xf;
			if (!mm) {
				o[k] = none;
				continue;
			}

			if (mm == 0xf && quad) {
				/*
				 * The usual case: all four in flight, in the
				 * same span, so with the same start
				 */
				l = lut[(sr[x >> (ss + 1)] >>
					 (((unsigned int)x >> ss) & 1) * 4) & 0xf];
				if (bits == 4)
					/* an ft is a byte */
					v = (unsigned int)(l[ftr[x]] |
						l[256 + ftr[x + 1]] |
						l[512 + ftr[x + 2]] |
						l[768 + ftr[x + 3]]);
				else
					v = (unsigned int)(
					    l[fld_get(ftr, x, ftw)] |
					    l[per + fld_get(ftr, x + 1, ftw)] |
					    l[2 * per + fld_get(ftr, x + 2, ftw)] |
					    l[3 * per + fld_get(ftr, x + 3, ftw)]);
			} else
				for (j = 0, v = 0; j < EPDD_PX_PER_BYTE; j++) {
					if (!(mm & (1u << j))) {
						v |= nc[j * per];
						continue;
					}
					l = lut[fld_get(sr, (x + (int)j) >> ss,
							4)];
					v |= l[j * per + fld_get(ftr,
							x + (int)j, ftw)];
				}

			o[k] = (uint8_t)v;
			any |= v ^ none;
		}
	}

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
prepare_row_(epdd_priv_t *priv, const epdd_slot_t *clear, int row,
	     const uint8_t **data)
{
	int nb = priv->cur ^ 1;

	if (!encode_row(priv, clear, row, nb)) {
		/*
		 * Nothing to drive on this row.  If its pixels may still
		 * hold a drive from the last pass, write no drive to them
		 * for the full row time, so they stop.
		 */
		if (priv->charged[row]) {
			priv->charged[row] = 0;
			priv->charged_n--;
			priv->latched_none = 1;
			priv->rst.rows_none++;
			*data = priv->nonebuf;

			return EPDD_ROW_NONE;
		}

		/*
		 * Stepping over it drives what's latched onto it, so it must
		 * be no drive.  If it isn't, load and latch some, which costs
		 * this row the time of a driven one.
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
	if (!priv->charged[row]) {
		priv->charged[row] = 1;
		priv->charged_n++;
	}

	/* if it's the same as the last row encoded, that's sent again */

	if (!priv->cur_valid || memcmp(priv->rowbuf[nb],
				       priv->rowbuf[priv->cur],
				       priv->row_bytes)) {
		priv->cur = (uint8_t)nb;
		priv->cur_valid = 1;
	}

	*data = priv->rowbuf[priv->cur];

	return EPDD_ROW_DATA;
}

/*
 * How long this takes is counted, since it's what the core running the
 * passes does while it's not waiting for the bus.  If it's too slow, the
 * passes take longer than the panel's frame time, and every pixel is driven
 * harder than the waveform expects.
 *
 * Reading the time is only done for one row in each pass, the one in the
 * middle, and it's counted for all of them.
 */

static int
prepare_row(epdd_priv_t *priv, const epdd_slot_t *clear, int row,
	    const uint8_t **data)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	lws_usec_t t;
	int r;

	/*
	 * While this row is worked out, the next row's state can be on its
	 * way into the cache, if the platform can do that
	 */
	if (!clear && ed->bus->prefetch && row + 1 < (int)ed->panel->gate_rows)
		ed->bus->prefetch(ed->bus, priv->ft + (size_t)(row + 1) *
						priv->ftstride, priv->ftstride);

	if (row != (int)ed->panel->gate_rows / 2)
		return prepare_row_(priv, clear, row, data);

	t = lws_now_usecs();
	r = prepare_row_(priv, clear, row, data);
	priv->rst.prep_sum += (lws_now_usecs() - t) * ed->panel->gate_rows;

	return r;
}

/*
 * Runner side: the slot's pixels start their transitions on this pass, from
 * the level they're at to the one in the slot
 */

static void
slot_apply(epdd_priv_t *priv, const epdd_slot_t *s)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	unsigned int ftw = 2u * priv->bits, lm = (1u << priv->bits) - 1u,
		     q = (priv->pass >> 2) & (EPDD_STARTS - 1);
	int row, w, x;
	uint32_t m;

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		const uint32_t *sm;
		const uint8_t *to;
		uint8_t *ftr, *sr;
		uint32_t *rb;

		if (s->row_idx[row] == EPDD_NO_ROW)
			continue;

		sm = s->masks + (size_t)s->row_idx[row] * (size_t)priv->words;
		to = s->to + (size_t)s->row_idx[row] * priv->lstride;
		rb = plane_row(priv, priv->rbusy, row);
		ftr = priv->ft + (size_t)row * priv->ftstride;
		sr = priv->start + (size_t)row * priv->sstride;

		for (w = 0; w < priv->words; w++) {
			rb[w] |= sm[w];
			for (m = sm[w], x = w * 32; m; m >>= 1, x++) {
				if (!(m & 1))
					continue;
				fld_set(ftr, x, ftw,
					((fld_get(ftr, x, ftw) & lm) <<
						priv->bits) |
					fld_get(to, x, priv->bits));
				fld_set(sr, x >> priv->span_shift, 4, q);
			}
		}
	}
}

/*
 * Runner side: the slot's pixels have finished their transitions, they are at
 * the level they moved to
 */

static void
slot_retire(epdd_priv_t *priv, const epdd_slot_t *s)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	unsigned int ftw = 2u * priv->bits, lm = (1u << priv->bits) - 1u, t;
	int row, w, x;
	uint32_t m;

	if (s->clear) {
		/* every pixel is white, which is all ones */
		memset(priv->ft, 0xff, priv->ftstride * ed->panel->gate_rows);
		return;
	}

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		const uint32_t *sm;
		uint8_t *ftr;
		uint32_t *rb;

		if (s->row_idx[row] == EPDD_NO_ROW)
			continue;

		sm = s->masks + (size_t)s->row_idx[row] * (size_t)priv->words;
		rb = plane_row(priv, priv->rbusy, row);
		ftr = priv->ft + (size_t)row * priv->ftstride;

		for (w = 0; w < priv->words; w++) {
			rb[w] &= ~sm[w];
			for (m = sm[w], x = w * 32; m; m >>= 1, x++) {
				if (!(m & 1))
					continue;
				t = fld_get(ftr, x, ftw) & lm;
				fld_set(ftr, x, ftw, (t << priv->bits) | t);
			}
		}
	}
}

/*
 * Runner side: one pass over every row, driving the slots that are running.
 * This side only reads the slots' rows, and sets their start pass and
 * states.
 *
 * Returns nonzero if anything was driven.
 */

static int
epdd_pass(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	const lws_epd_direct_bus_ops_t *bus = ed->bus;
	const lws_epd_direct_waveform_t *wf = ed->wf;
	size_t len = priv->row_bytes + bus->row_tail_bytes;
	int n, row, rows = (int)ed->panel->gate_rows, any = 0, act, nact = 0,
	    left = 0;
	const uint8_t *data = NULL, *ndata = NULL;
	const epdd_slot_t *clear = NULL;
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

	for (n = 0; n < EPDD_SLOTS; n++) {
		st[n] = epdd_get(&priv->slot[n].state);
		any |= st[n] == EPDD_SLOT_RUNNING;
	}

	/*
	 * Updates start on a pass that's a multiple of 4, which is
	 * LWS_EPDD_DRIVE_CYCLE: a waveform's drive cycle relies on it.  If
	 * nothing is in flight, nothing depends on the count, so it moves on
	 * to the next one, and what's waiting starts now.
	 */

	if (!any)
		priv->pass = (priv->pass + 3u) & ~3u;

	/*
	 * Updates made since the last pass join on this pass, if they can.
	 * The slots running stay running, and nothing else changes them,
	 * until we say they're done.
	 */

	for (n = 0; n < EPDD_SLOTS; n++) {
		epdd_slot_t *s = &priv->slot[n];

		if (st[n] == EPDD_SLOT_ARMED && !(priv->pass & 3)) {
			if (!s->clear)
				slot_apply(priv, s);
			s->pass0 = priv->pass;
			st[n] = EPDD_SLOT_RUNNING;
			epdd_set(&s->state, st[n]);
		}
		if (st[n] == EPDD_SLOT_RUNNING && s->clear) {
			/* a clear has the panel to itself */
			clear = s;
			if (wf->clear_drive_ns)
				drive_ns = wf->clear_drive_ns;
		}
		any |= st[n] == EPDD_SLOT_RUNNING;
	}

	/*
	 * Updates start on a multiple of LWS_EPDD_DRIVE_CYCLE passes, so this
	 * is where every update in flight is in the cycle
	 */

	if (!clear && wf->drive_cycle_ns[0])
		drive_ns = wf->drive_cycle_ns[priv->pass %
					      LWS_EPDD_DRIVE_CYCLE];

	/* with nothing in flight, rows may still need no drive written */

	if (!any && !priv->charged_n)
		return 0;

	t0 = lws_now_usecs();
	if (!priv->rst.passes++)
		priv->rst.start = t0;

	pass_luts(priv);

	/* the slots running have changed, what was packed is stale */
	priv->cur_valid = 0;

	bus->frame_start(bus);

	act = prepare_row(priv, clear, 0, &data);

	for (row = 0; row < rows; row++) {
		if (act == EPDD_ROW_SKIP) {
			bus->row_skip(bus);
			if (row + 1 < rows)
				act = prepare_row(priv, clear, row + 1, &data);
			continue;
		}

		/* like preparing it, the bus' time for a row is sampled */
		if (row == rows / 2) {
			lws_usec_t tb = lws_now_usecs();

			bus->row_load(bus, data, len);
			priv->rst.bus_sum += (lws_now_usecs() - tb) *
								(unsigned int)rows;
		} else
			bus->row_load(bus, data, len);
		/* the next row is made ready while this one is sent */
		if (row + 1 < rows)
			nact = prepare_row(priv, clear, row + 1, &ndata);
		if (row == rows / 2) {
			lws_usec_t tb = lws_now_usecs();

			bus->row_drive(bus, drive_ns);
			priv->rst.bus_sum += (lws_now_usecs() - tb) *
								(unsigned int)rows;
		} else
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

	priv->pass++;

	for (n = 0; n < EPDD_SLOTS; n++)
		if (st[n] == EPDD_SLOT_RUNNING &&
		    priv->pass - priv->slot[n].pass0 < priv->slot[n].len)
			left = 1;

	/*
	 * If this was the last pass of everything, hand over what we counted
	 * before saying the slots are done, so the event loop side has it
	 * when it sees them done
	 */

	if (!left && !slots_active_other(priv, st) && !priv->charged_n &&
	    !epdd_get(&priv->rst_ready)) {
		priv->rst_pub = priv->rst;
		memset(&priv->rst, 0, sizeof(priv->rst));
		epdd_set(&priv->rst_ready, 1);
	}

	/* said before the slots are, so it's seen with them */
	epdd_set(&priv->rs_charged, !!priv->charged_n);

	for (n = 0; n < EPDD_SLOTS; n++) {
		epdd_slot_t *s = &priv->slot[n];

		if (st[n] == EPDD_SLOT_RUNNING &&
		    priv->pass - s->pass0 >= s->len) {
			slot_retire(priv, s);
			epdd_set(&s->state, EPDD_SLOT_DONE);
		}
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
	s->to = NULL;
	s->pass0 = 0;
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
	s->len = ed->wf->clear_len;

	/* white is all ones */
	memset(priv->tgt, 0xff, priv->lstride * ed->panel->gate_rows);

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		uint32_t *b = plane_row(priv, priv->busy, row);

		for (w = 0; w < priv->words; w++)
			b[w] = w == priv->words - 1 ? priv->last_word_mask :
						      0xffffffffu;
		priv->dirty[row] = 1;
	}

	priv->updates = 0;
	priv->st_clears++;
	/* everything about the slot is written before the runner can see it */
	epdd_set(&s->state, EPDD_SLOT_ARMED);
}

/*
 * Event loop side: of the 32 pixels in a word of a row, the ones that want a
 * level they don't have, and the ones of those that can start moving now,
 * since nothing in their span is busy
 */

static uint32_t
word_changes(const epdd_priv_t *priv, const uint8_t *wa, const uint8_t *t,
	     uint32_t busy, int w, uint32_t *take)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	int x = w * 32, x1 = x + 32, sp = 1 << priv->span_shift, k;
	uint32_t diff = 0, free = 0, sm;

	if (x1 > (int)ed->panel->source_px)
		x1 = (int)ed->panel->source_px;

	for (; x < x1; x++)
		if (fld_get(wa, x, priv->bits) != fld_get(t, x, priv->bits))
			diff |= 1u << (x & 31);

	sm = sp == 32 ? 0xffffffffu : (1u << sp) - 1u;
	for (k = 0; k < 32; k += sp)
		if (!(busy & (sm << k)))
			free |= sm << k;

	*take = diff & free;

	return diff;
}

/*
 * Start what we can of what's wanted.  Pixels that are wanted to change and
 * can move now join a new slot, rows still with pixels waiting on one in
 * flight stay dirty, to be looked at again when it finishes.
 */

static void
epdd_start(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	int row, w, x, rows = 0, idx = 0;
	uint32_t diff, take;
	size_t sz, msz;
	epdd_slot_t *s;

	/*
	 * If the runner side handed over what it counted, say it before what
	 * we start now is counted with it
	 */
	epdd_stats(priv);

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
		const uint8_t *wa = lvl_row(priv, priv->want, row),
			      *t = lvl_row(priv, priv->tgt, row);
		const uint32_t *b = plane_row(priv, priv->busy, row);
		uint32_t any_take = 0, any_diff = 0;

		if (!priv->dirty[row])
			continue;

		for (w = 0; w < priv->words; w++) {
			any_diff |= word_changes(priv, wa, t, b[w], w, &take);
			any_take |= take;
		}

		if (any_take)
			rows++;
		else if (!any_diff)
			priv->dirty[row] = 0;
	}

	if (!rows)
		return;

	sz = sizeof(uint16_t) * ed->panel->gate_rows;
	sz = (sz + 3) & ~(size_t)3;
	msz = (size_t)rows * (size_t)priv->words * sizeof(uint32_t);

	slot_reset(s);
	s->blk = lws_zalloc(sz + msz + (size_t)rows * priv->lstride, __func__);
	if (!s->blk) {
		lwsl_err("%s: OOM, the update waits\n", __func__);
		return;
	}

	s->row_idx = (uint16_t *)s->blk;
	s->masks = (uint32_t *)((uint8_t *)s->blk + sz);
	s->to = (uint8_t *)s->blk + sz + msz;

	for (row = 0; row < (int)ed->panel->gate_rows; row++) {
		uint8_t *wa = lvl_row(priv, priv->want, row),
			*t = lvl_row(priv, priv->tgt, row), *to;
		uint32_t *b = plane_row(priv, priv->busy, row), *sm,
			 rest = 0, any = 0;

		s->row_idx[row] = EPDD_NO_ROW;
		if (!priv->dirty[row])
			continue;

		for (w = 0; w < priv->words; w++) {
			word_changes(priv, wa, t, b[w], w, &take);
			any |= take;
		}
		if (!any)
			continue;

		s->row_idx[row] = (uint16_t)idx;
		sm = s->masks + (size_t)idx * (size_t)priv->words;
		to = s->to + (size_t)idx * priv->lstride;
		idx++;

		for (w = 0; w < priv->words; w++) {
			diff = word_changes(priv, wa, t, b[w], w, &take);
			rest |= diff & ~take;
			sm[w] = take;
			b[w] |= take;

			for (x = w * 32; take; take >>= 1, x++) {
				unsigned int v;

				if (!(take & 1))
					continue;

				v = fld_get(wa, x, priv->bits);
				fld_set(to, x, priv->bits, v);
				fld_set(t, x, priv->bits, v);
				priv->st_px++;
			}
		}

		priv->dirty[row] = !!rest;
	}

	s->len = ed->wf->update_passes;

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
				const uint32_t *sm;
				uint32_t *b;

				if (s->row_idx[row] == EPDD_NO_ROW)
					continue;

				sm = s->masks + (size_t)s->row_idx[row] *
							(size_t)priv->words;
				b = plane_row(priv, priv->busy, row);

				for (w = 0; w < priv->words; w++)
					b[w] &= ~sm[w];
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
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	const epdd_rstats_t *r = &priv->rst_pub;

	if (!epdd_get(&priv->rst_ready))
		return;

#if (_LWS_ENABLED_LOGS & (LLL_INFO | LLL_NOTICE))
	/*
	 * Updates come often, eg, each frame of an animation, but clears are
	 * rare: the one at boot, and each .full_refresh_every updates.  They
	 * are logged where they can be seen by default, so it's clear the
	 * panel is being driven, and how fast.
	 *
	 * So are updates whose passes took longer to scan than the panel's
	 * frame time: pixels hold their drive until the next pass, so then
	 * every pass drove them harder than the waveform expects.
	 */
	if (r->passes)
		_lws_log(priv->st_clears || r->scan_sum / r->passes >
				(lws_usec_t)ed->panel->min_pass_us ?
						LLL_NOTICE : LLL_INFO,
			    "%s: %u passes in %dms, scans %d / %d / %dus "
			    "(min / avg / max), about %dus preparing rows, "
			    "%dus in the bus; "
			    "rows %u driven, %u skipped, "
			    "%u latched none; %u px moved; %u updates, "
			    "%u clears; settled %dms after commit\n", __func__,
			    (unsigned int)r->passes,
			    (int)((r->end - r->start) / LWS_US_PER_MS),
			    (int)r->scan_min,
			    (int)(r->scan_sum / r->passes),
			    (int)r->scan_max,
			    (int)(r->prep_sum / r->passes),
			    (int)(r->bus_sum / r->passes),
			    (unsigned int)r->rows_driven,
			    (unsigned int)r->rows_skipped,
			    (unsigned int)r->rows_none,
			    (unsigned int)priv->st_px,
			    (unsigned int)priv->st_updates,
			    (unsigned int)priv->st_clears,
			    priv->st_commit ? (int)((lws_now_usecs() -
				priv->st_commit) / LWS_US_PER_MS) : -1);
#else
	(void)r;
	(void)ed;
#endif

	priv->st_commit = 0;
	priv->st_px = 0;
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
 * update they committed.  Returns nonzero while anything is in flight.
 *
 * The runner side may stop driving rows at any moment, so whether it still
 * is is looked at once: if we went on to look again, eg, to decide whether
 * to keep polling, we could stop polling having never told anyone.
 */

static int
epdd_check_idle(epdd_priv_t *priv)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(priv->lds);
	int charged = epdd_get(&priv->rs_charged);

	/* the panel is done with when nothing goes on being driven */

	if (priv->booted && !charged) {
		priv->booted = 0;
		lwsl_notice("%s: panel cleared\n", __func__);
		if (ed->cb)
			ed->cb(priv->lds, 1);
	}

	/*
	 * The runner side hands over what it counted whenever it runs out of
	 * passes to do, so each time is said separately, even if more was
	 * waiting on this side by then
	 */
	epdd_stats(priv);

	if (!slots_idle(priv) || charged)
		return 1;

	if (priv->full_pending || any_dirty(priv, ed->panel->gate_rows))
		return 0;

	if (priv->committed) {
		priv->committed = 0;
		if (ed->cb)
			ed->cb(priv->lds, 2);
	}

	return 0;
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

	if (slots_active(priv) || priv->charged_n) {
		/* the panel can't be scanned faster than its datasheet says */
		if (priv->last_pass && now - priv->last_pass < min_us)
			return min_us - (now - priv->last_pass);

		priv->last_pass = now;
		priv->idle_since = 0;
		epdd_pass(priv);

		if (slots_active(priv) || priv->charged_n) {
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

	return epdd_check_idle(priv);
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
check_waveform(const lws_epd_direct_waveform_t *wf)
{
	unsigned int p, t, f;
	uint16_t n;

	if (!wf->update || !wf->clear || !wf->update_passes ||
	    wf->update_passes > LWS_EPDD_MAX_PHASES || !wf->clear_len ||
	    !wf->drive_ns ||
	    (wf->levels != 2 && wf->levels != 4 && wf->levels != 16))
		return 1;

	/* a drive cycle is all of it or none of it */

	for (n = 0; n < LWS_EPDD_DRIVE_CYCLE; n++)
		if (!wf->drive_cycle_ns[n] != !wf->drive_cycle_ns[0])
			return 1;

	for (n = 0; n < wf->clear_len; n++)
		if (wf->clear[n] > LWS_EPDD_WHITE)
			return 1;

	/* a code that isn't one of ours means the table is mispacked */

	for (p = 0; p < wf->update_passes; p++)
		for (t = 0; t < wf->levels; t++)
			for (f = 0; f < wf->levels; f++)
				if (wf_code(wf, p, t, f) > LWS_EPDD_WHITE)
					return 1;

	return 0;
}

static int
check_config(const lws_display_epd_direct_t *ed)
{
	const lws_surface_info_t *ic = &ed->disp.ic;
	const lws_epd_direct_panel_t *panel = ed->panel;
	const lws_epd_direct_bus_ops_t *bus = ed->bus;
	size_t n;

	if (!panel || !ed->wf || !bus || !bus->init || !bus->power ||
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

	if (!ic->greyscale || !ic->palette ||
	    (ic->palette_depth != 2 && ic->palette_depth != 4 &&
	     ic->palette_depth != 16)) {
		lwsl_err("%s: needs a 2, 4 or 16-level greyscale palette\n",
			 __func__);
		return 1;
	}

	/* a pixel's level is its palette index */

	for (n = 1; n < ic->palette_depth; n++)
		if (LWSDC_R(ic->palette[n]) <= LWSDC_R(ic->palette[n - 1])) {
			lwsl_err("%s: palette must go from black to white\n",
				 __func__);
			return 1;
		}

	if (check_waveform(ed->wf) || ed->wf->levels < ic->palette_depth) {
		lwsl_err("%s: bad waveform\n", __func__);
		return 1;
	}

	if (ed->start_span_px > 32 ||
	    (ed->start_span_px & (ed->start_span_px - 1))) {
		lwsl_err("%s: bad start_span_px\n", __func__);
		return 1;
	}

	return 0;
}

/*
 * What the runner side reads in every pass goes in fast memory if the
 * platform has it, otherwise in ordinary memory
 */

static void *
alloc_fast(const lws_display_epd_direct_t *ed, size_t size, uint8_t *fast)
{
	const lws_epd_direct_bus_ops_t *bus = ed->bus;
	void *p = NULL;

	if (bus->alloc_fast && bus->free_fast)
		p = bus->alloc_fast(bus, size);

	*fast = !!p;
	if (!p)
		p = lws_malloc(size, __func__);
	if (p)
		memset(p, 0, size);

	return p;
}

static void
free_fast(const lws_display_epd_direct_t *ed, void *pp, uint8_t fast)
{
	void **p = (void **)pp;

	if (!*p)
		return;

	if (fast)
		ed->bus->free_fast(ed->bus, p);
	else
		lws_free_set_NULL(*p);
}

/*
 * The bus' .encode_16l is checked against what the portable code makes of the
 * same row, with every pixel in flight, ft having every value, and every
 * start, some of them in passes outside the transitions.  This is done before
 * anything else uses the passes' state, which is put back as it was.
 */

static int
check_16l(epdd_priv_t *priv)
{
	uint32_t pass = priv->pass;
	int x, c, a, ok;

	for (x = 0; x < (int)priv->ftstride; x++)
		priv->ft[x] = (uint8_t)(x * 37 + 11);
	for (x = 0; x < (int)priv->sstride; x++)
		priv->start[x] = (uint8_t)(x * 0x35 + 0x71);
	for (x = 0; x < priv->words; x++)
		priv->rbusy[x] = 0xffffffffu;
	priv->pass = 4 * 5 + 2;

	priv->use_16l = 1;
	pass_luts(priv);
	a = encode_row(priv, NULL, 0, 1);
	priv->use_16l = 0;
	c = encode_row(priv, NULL, 0, 0);

	ok = a == c && !memcmp(priv->rowbuf[0], priv->rowbuf[1],
			       priv->row_bytes);

	memset(priv->ft, 0xff, priv->ftstride);
	memset(priv->start, 0, priv->sstride);
	memset(priv->rbusy, 0, (size_t)priv->words * sizeof(uint32_t));
	priv->pass = pass;
	priv->use_16l = (uint8_t)ok;

	if (!ok)
		lwsl_err("%s: the bus' encode_16l differs, not using it\n",
			 __func__);

	return ok;
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

	free_fast(ed, &priv->rbusy, priv->fast_rbusy);
	free_fast(ed, &priv->start, priv->fast_start);
	free_fast(ed, &priv->codes, priv->fast_codes);
	free_fast(ed, &priv->tables_16l_alloc, priv->fast_16l);
	lws_free_set_NULL(priv->ft_alloc);
	lws_free_set_NULL(priv->charged);
	lws_free_set_NULL(priv->u[0]);
	/* the event loop side's planes are all in this one */
	lws_free_set_NULL(priv->busy);
	lws_free(priv);
}

int
lws_display_epd_direct_init(lws_display_state_t *lds)
{
	const lws_display_epd_direct_t *ed = lds_to_disp(lds);
	const lws_epd_direct_panel_t *panel;
	size_t len, pw, lp, csz;
	epdd_priv_t *priv;
	uint8_t *codes;
	int w, span;

	if (check_config(ed))
		return 1;

	panel = ed->panel;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	priv->bits = (uint8_t)(ed->disp.ic.palette_depth == 2 ? 1 :
			       (ed->disp.ic.palette_depth == 4 ? 2 : 4));
	span = ed->start_span_px ? ed->start_span_px : 8;
	while ((1 << priv->span_shift) < span)
		priv->span_shift++;

	priv->words = (panel->source_px + 31) / 32;
	priv->last_word_mask = panel->source_px & 31 ?
			(1u << (panel->source_px & 31)) - 1u : 0xffffffffu;
	priv->row_bytes = panel->source_px / EPDD_PX_PER_BYTE;
	pw = (size_t)priv->words * panel->gate_rows;
	priv->plane_words = pw;
	priv->lstride = ((size_t)panel->source_px * priv->bits + 7) / 8;
	/* each row of ft starts 16-byte aligned, for vector loads of it */
	priv->ftstride = ((((size_t)panel->source_px * 2u * priv->bits + 7) /
								8) + 15) & ~(size_t)15;
	priv->sstride = (((size_t)panel->source_px + (size_t)span - 1) /
							(size_t)span + 1) / 2;
	lp = priv->lstride * panel->gate_rows;

	/* want, tgt and busy planes, and the per-row dirty flags */

	priv->busy = lws_zalloc(pw * sizeof(uint32_t) + 2 * lp +
				panel->gate_rows, __func__);
	if (!priv->busy)
		goto bail;

	priv->want = (uint8_t *)(priv->busy + pw);
	priv->tgt = priv->want + lp;
	priv->dirty = priv->tgt + lp;

	/*
	 * Until told otherwise, white is wanted.  What the panel shows is
	 * unknown until the clear, which leaves it white.  White is all
	 * ones.
	 */

	memset(priv->want, 0xff, lp);
	memset(priv->tgt, 0xff, lp);

	/* the runner side's planes, all pixels white and not moving */

	/* 16-byte aligned, for vector loads of it, eg, by .encode_16l */
	priv->ft_alloc = lws_malloc(priv->ftstride * panel->gate_rows + 15,
				    __func__);
	if (!priv->ft_alloc)
		goto bail;
	priv->ft = (uint8_t *)(((uintptr_t)priv->ft_alloc + 15) &
							~(uintptr_t)15);
	memset(priv->ft, 0xff, priv->ftstride * panel->gate_rows);

	priv->charged = lws_zalloc(panel->gate_rows, __func__);
	if (!priv->charged)
		goto bail;

	priv->rbusy = alloc_fast(ed, pw * sizeof(uint32_t), &priv->fast_rbusy);
	priv->start = alloc_fast(ed, priv->sstride * panel->gate_rows,
				 &priv->fast_start);
	/* a pass of codes is EPDD_PX_PER_BYTE << (2 * bits), after the rest */
	csz = ((size_t)ed->wf->update_passes + 1) *
			((size_t)EPDD_PX_PER_BYTE << (2 * priv->bits));
	codes = alloc_fast(ed, csz, &priv->fast_codes);
	priv->codes = codes;
	if (!priv->rbusy || !priv->start || !codes)
		goto bail;
	build_codes(priv, codes);

	/* the last pass of codes drives nothing, for transitions not driven */

	priv->no_codes = codes + csz -
			((size_t)EPDD_PX_PER_BYTE << (2 * priv->bits));
	for (w = 0; w < EPDD_PX_PER_BYTE; w++)
		memset(priv->no_codes + ((size_t)w << (2 * priv->bits)),
		       bus_bits(panel, (unsigned int)w, LWS_EPDD_NONE),
		       (size_t)1 << (2 * priv->bits));

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

	priv->none_byte = bus_fill(panel, LWS_EPDD_NONE);

	/* the tail of every row, and all of the none row, are no drive */

	memset(priv->nonebuf, priv->none_byte, len);
	for (w = 0; w < 2; w++)
		memset(priv->rowbuf[w] + priv->row_bytes, priv->none_byte,
		       ed->bus->row_tail_bytes);

	/*
	 * If the bus can do the most common rows faster, and these are those,
	 * make the tables it uses.  The start of each pixel in 16 for each
	 * byte of two spans' starts doesn't change.
	 */

	if (ed->bus->encode_16l && priv->bits == 4 && priv->span_shift == 3 &&
	    !(panel->flags & LWS_EPDD_PANEL_FL_FIRST_PX_LSB) &&
	    panel->source_px >= 32 && (((uintptr_t)priv->rowbuf[0] |
					(uintptr_t)priv->rowbuf[1]) & 7))
		/*
		 * It's a row that the bus could encode faster, but the bus
		 * gave us row buffers it can't use for it.  Everything still
		 * works, but it should be fixed, so say so.
		 */
		lwsl_warn("%s: row buffers not 8-byte aligned, the bus "
			  "can't encode rows\n", __func__);
	else if (ed->bus->encode_16l && priv->bits == 4 &&
		 priv->span_shift == 3 &&
		 !(panel->flags & LWS_EPDD_PANEL_FL_FIRST_PX_LSB) &&
		 panel->source_px >= 32) {
		uint8_t *t;

		priv->tables_16l_alloc = alloc_fast(ed, LWS_EPDD_16L_LEN + 15,
						    &priv->fast_16l);
		if (!priv->tables_16l_alloc)
			goto bail;
		t = (uint8_t *)(((uintptr_t)priv->tables_16l_alloc + 15) &
							~(uintptr_t)15);
		priv->tables_16l = t;

		for (w = 0; w < 256; w++) {
			memset(t + LWS_EPDD_16L_EXPAND + w * 16, w & 0xf, 8);
			memset(t + LWS_EPDD_16L_EXPAND + w * 16 + 8, w >> 4, 8);
		}
		memset(t + LWS_EPDD_16L_NONE, priv->none_byte, 16);
	}

	if (lws_display_alloc_diffusion(&ed->disp.ic, priv->u))
		goto bail;

	if (ed->bus->init(ed->bus)) {
		lwsl_err("%s: bus init failed\n", __func__);
		goto bail;
	}

	lds->priv = priv;

	if (priv->tables_16l)
		check_16l(priv);

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

	lwsl_notice("%s: %s, %ux%u, %u levels, %u-px spans, %u-pass "
		    "transitions; pass state %u + %u + %uB%s%s\n", __func__,
		    panel->name, (unsigned int)panel->source_px,
		    (unsigned int)panel->gate_rows,
		    1u << priv->bits, 1u << priv->span_shift,
		    (unsigned int)ed->wf->update_passes,
		    (unsigned int)(pw * sizeof(uint32_t)),
		    (unsigned int)(priv->sstride * panel->gate_rows),
		    (unsigned int)csz,
		    priv->fast_rbusy && priv->fast_start && priv->fast_codes &&
		    (!priv->use_16l || priv->fast_16l) ? ", fast" : "",
		    priv->use_16l ? ", bus encodes rows" : "");

	return 0;

bail:
	lwsl_err("%s: OOM\n", __func__);
	epdd_free(ed, priv);

	return 1;
}

/*
 * Store a line of Y pixels into the want plane, dithered to the display's
 * levels
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
	uint8_t *wa;

	if (y < 0 || y >= ic->wh_px[1].whole) {
		lwsl_warn("%s: line %d outside surface\n", __func__, y);
		return;
	}

	row = ed->mirror_y ? ed->panel->gate_rows - 1 - y : y;
	wa = lvl_row(priv, priv->want, row);
	priv->dirty[row] = 1;

	if (!src) {
		/* a line we aren't given pixels for is white, all ones */
		memset(wa, 0xff, priv->lstride);
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

		/* the palette goes from black to white, so idx is the level */
		px = ed->mirror_x ? width - 1 - x : x;
		fld_set(wa, px, priv->bits, idx);
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
		if (priv->clear_next || (ed->full_refresh_every &&
		    ++priv->updates >= ed->full_refresh_every))
			priv->full_pending = 1;
		priv->clear_next = 0;
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

int
lws_display_epd_direct_clear(lws_display_state_t *lds)
{
	epdd_priv_t *priv = lds_to_priv(lds);

	if (!priv)
		return 1;

	/*
	 * Not now: what's wanted is the last update until the next one has
	 * all its lines, and the clear would show it again
	 */
	priv->clear_next = 1;

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
