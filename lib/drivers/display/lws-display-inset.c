/*
 * lws abstract display: the inset, the edges of the surface that can't be seen
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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
 * This is built whenever LWS_WITH_DLO or LWS_WITH_DRIVERS is: display list
 * users like the strip ui lay out, blit and take touches through it on a
 * display state they set up themselves, without the generic drivers.
 */

#include <private-lib-core.h>

void
lws_display_state_fini(lws_display_state_t *lds)
{
	lws_free_set_NULL(lds->inset_line);
}

/* how much of an extent in mm is left of it when only px of its whole are */

static void
inset_mm(lws_fx_t *mm, int whole, int px)
{
	lws_fx_t a, b, t;

	a.whole = px;
	a.frac = 0;
	b.whole = whole;
	b.frac = 0;
	lws_fx_div(&t, &a, &b);
	a = *mm;
	lws_fx_mul(mm, &a, &t);
}

int
lws_display_set_inset(lws_display_state_t *lds, const uint8_t inset[4])
{
	const lws_surface_info_t *sic = &lds->disp->ic;
	int w = sic->wh_px[0].whole - inset[0] - inset[2],
	    h = sic->wh_px[1].whole - inset[1] - inset[3];

	if (w < 1 || h < 1)
		return 1;

	if (memcmp(lds->inset, inset, sizeof(lds->inset)))
		/*
		 * Rows in the inset now may show something from before: the
		 * next updates reaching them make them white
		 */
		lds->inset_stale = (uint8_t)
			((inset[1] ? LWS_DISPLAY_INSET_STALE_TOP : 0) |
			 (inset[3] ? LWS_DISPLAY_INSET_STALE_BOTTOM : 0));

	memcpy(lds->inset, inset, sizeof(lds->inset));

	lds->ic = *sic;
	lds->ic.wh_px[0].whole = w;
	lds->ic.wh_px[0].frac = 0;
	lds->ic.wh_px[1].whole = h;
	lds->ic.wh_px[1].frac = 0;
	inset_mm(&lds->ic.wh_mm[0], sic->wh_px[0].whole, w);
	inset_mm(&lds->ic.wh_mm[1], sic->wh_px[1].whole, h);

	/* what's at the sides of the line it keeps may be in the way now */
	lws_free_set_NULL(lds->inset_line);

	return 0;
}

/* the bytes in a line of the whole surface */

static size_t
surface_line_len(const lws_display_state_t *lds)
{
	const lws_surface_info_t *sic = &lds->disp->ic;

	return (size_t)sic->wh_px[0].whole *
	       (sic->greyscale ? 1u : (sic->render_to_rgba ? 4u : 3u));
}

/* the line of the whole surface lines drawn on what can be seen go in */

static uint8_t *
inset_line(lws_display_state_t *lds)
{
	if (!lds->inset_line) {
		lds->inset_line = lws_malloc(surface_line_len(lds), __func__);
		if (lds->inset_line)
			/* the inset at its sides stays white */
			memset(lds->inset_line, 0xff, surface_line_len(lds));
	}

	return lds->inset_line;
}

/* blit the rows of the surface from y0 up to y1 white */

static int
blit_white(lws_display_state_t *lds, int y0, int y1, lws_dll2_owner_t *ids)
{
	uint8_t *line = inset_line(lds);
	lws_box_t b;

	if (!line)
		return 1;

	/* the part inside the sides is written again by the next line */
	memset(line, 0xff, surface_line_len(lds));

	memset(&b, 0, sizeof(b));
	b.w = lds->disp->ic.wh_px[0];
	b.h.whole = 1;
	for (b.y.whole = y0; b.y.whole < y1; b.y.whole++)
		if (lds->disp->blit(lds, line, &b, ids))
			return 1;

	return 0;
}

int
lws_display_blit(lws_display_state_t *lds, const uint8_t *src, lws_box_t *box,
		 lws_dll2_owner_t *ids)
{
	const lws_surface_info_t *sic = &lds->disp->ic;
	size_t bpp = sic->greyscale ? 1 : (sic->render_to_rgba ? 4 : 3);
	int top = 0, r;
	lws_box_t b;
	uint8_t *line;

	if (!(lds->inset[0] | lds->inset[1] | lds->inset[2] | lds->inset[3]))
		return lds->disp->blit(lds, src, box, ids);

	/* where it is on the surface, all the width of it */

	b = *box;
	b.y.whole += lds->inset[1];
	if (b.h.whole) {
		b.x.whole = 0;
		b.x.frac = 0;
		b.w = sic->wh_px[0];
	}

	switch (box->h.whole) {
	case 0:
		/* the end of an update: the stale rows below it first */
		if (lds->inset_due) {
			lds->inset_due = 0;
			if (blit_white(lds, sic->wh_px[1].whole - lds->inset[3],
				       sic->wh_px[1].whole, ids))
				return 1;
			lds->inset_stale = (uint8_t)(lds->inset_stale &
					~LWS_DISPLAY_INSET_STALE_BOTTOM);
		}
		break;

	case 1:
		if (!src || !(lds->inset[0] || lds->inset[2]))
			break;

		/* a line drawn on what can be seen, inside a line of it all */
		line = inset_line(lds);
		if (!line)
			return 1;
		memcpy(line + (size_t)lds->inset[0] * bpp, src,
		       (size_t)lds->ic.wh_px[0].whole * bpp);
		src = line;
		break;

	default:
		/*
		 * The start of an update.  Stale rows in the inset next to it
		 * are made white with it, so it's widened to them: its lines
		 * are still all together, for a display taking a band
		 */
		lds->inset_due = 0;
		if ((lds->inset_stale & LWS_DISPLAY_INSET_STALE_TOP) &&
		    !box->y.whole) {
			top = lds->inset[1];
			b.y.whole = 0;
			b.h.whole += top;
		}
		if ((lds->inset_stale & LWS_DISPLAY_INSET_STALE_BOTTOM) &&
		    box->y.whole + box->h.whole >= lds->ic.wh_px[1].whole) {
			lds->inset_due = 1;
			b.h.whole += lds->inset[3];
		}

		r = lds->disp->blit(lds, src, &b, ids);
		if (r || !top)
			return r;

		if (blit_white(lds, 0, top, ids))
			return 1;
		lds->inset_stale = (uint8_t)(lds->inset_stale &
					~LWS_DISPLAY_INSET_STALE_TOP);

		return 0;
	}

	return lds->disp->blit(lds, src, &b, ids);
}

int
lws_display_visible_xy(const lws_display_state_t *lds, int *x, int *y)
{
	*x -= lds->inset[0];
	*y -= lds->inset[1];

	return *x < 0 || *y < 0 || *x >= lds->ic.wh_px[0].whole ||
	       *y >= lds->ic.wh_px[1].whole;
}
