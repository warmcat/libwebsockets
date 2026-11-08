/*
 * lws abstract display
 *
 * Copyright (C) 2019 - 2022 Andy Green <andy@warmcat.com>
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
 * Display List Object: rect / rounded rect
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

/* returns where on the x axis we intercept ys (== (curr - ory) ^ 2 ) */

static void
isect(lws_circle_t *c, lws_fx_t *f, lws_fx_t *axsq)
{
	assert(axsq->whole >= 0);
	assert(c->rsq.whole >= 0);

	lws_fx_sub(f, &c->rsq, axsq);

	/*
	 * Outside the circle: that includes between -1 and 0, which has a
	 * whole of 0 and a negative frac, eg, the line through the middle of
	 * the first row of a corner of radius 0
	 */

	if (lws_neg(f)) {
		f->whole = 0;
		f->frac = 0;
	} else
		lws_fx_sqrt(f, f);

	lws_fx_sub(f, &c->r, f);
}

/* give it absolute x, returns intersection point as absolute y*/

static void
isect_y_from_x(lws_circle_t *c, lws_fx_t *x, lws_fx_t *y)
{
	lws_fx_t t, t1;

	lws_fx_sub(y, x, &c->orx);
	lws_fx_mul(&t, y, y);
	lws_fx_sub(&t1, &c->rsq, &t);
	lws_fx_sqrt(&t, &t1);
	lws_fx_add(y, &c->ory, &t);
}

/*
 * Where the rect is on the surface, and its corners, are worked out once,
 * and again if it moved, eg, a retained display list rendered again after an
 * ancestor's box was moved.  ox, oy is where its top left is on the surface.
 */

void
lws_display_dlo_rect_place(lws_dlo_rect_t *r, const lws_fx_t *ox,
			   const lws_fx_t *oy)
{
	lws_dlo_t *dlo = &r->dlo;

	if (r->init && !lws_fx_comp(ox, &r->db.x) &&
	    !lws_fx_comp(oy, &r->db.y))
		return;

	r->db.x = *ox;
	r->db.y = *oy;
	lws_fx_add(&r->right,    &r->db.x,   &dlo->box.w);
	lws_fx_add(&r->btm,      &r->db.y,   &dlo->box.h);
	lws_fx_add(&r->c[0].ory, &r->db.y,   &r->c[0].r);
	lws_fx_add(&r->c[1].ory, &r->db.y,   &r->c[1].r);
	lws_fx_sub(&r->c[2].ory, &r->btm,    &r->c[2].r);
	lws_fx_sub(&r->c[3].ory, &r->btm,    &r->c[3].r);
	lws_fx_add(&r->c[0].orx, &r->db.x,   &r->c[0].r);
	lws_fx_sub(&r->c[1].orx, &r->right,  &r->c[1].r);
	lws_fx_add(&r->c[2].orx, &r->db.x,   &r->c[2].r);
	lws_fx_sub(&r->c[3].orx, &r->right,  &r->c[3].r);

	r->init = 1;
}

/* does it have any rounded corners */

int
lws_display_dlo_rect_rounded(const lws_dlo_rect_t *r)
{
	int n;

	for (n = 0; n < 4; n++)
		if (r->c[n].r.whole || r->c[n].r.frac)
			return 1;

	return 0;
}

/* alpha scaled by the fraction f of a pixel that is covered */

static unsigned int
cover(lws_fx_t f, unsigned int alpha)
{
	return (unsigned int)(((uint64_t)f.frac * alpha) /
			      LWS_FX_FRACTION_MSD) & 0xff;
}

/*
 * What of surface line curr the placed rect covers, on a surface w px wide:
 * nonzero if none of it.  Its corners trim where the row starts and ends.
 */

int
lws_display_dlo_rect_row(lws_dlo_rect_t *r, int curr, int w,
			 lws_dlo_rect_row_t *row)
{
	lws_dlo_t *dlo = &r->dlo;
	lws_fx_t cf, y, trim, top, bot, s, e, t;
	int n;

	if (r->db.x.whole >= w)
		return 1; /* off to the right */

	/*
	 * How much of this row the rect covers vertically: a fractional top
	 * or bottom row is drawn with its alpha scaled by the overlap, so a
	 * 1px underline at y = 32.9 is one row over two, not four solid
	 * rows, and a zero-height rect draws nothing
	 */
	top.whole = curr;
	top.frac = 0;
	if (lws_fx_comp(&top, &r->db.y) < 0)
		top = r->db.y;
	bot.whole = curr + 1;
	bot.frac = 0;
	if (lws_fx_comp(&bot, &r->btm) > 0)
		bot = r->btm;
	lws_fx_sub(&row->cov, &bot, &top);
	if (row->cov.whole < 0 || (!row->cov.whole && row->cov.frac <= 0))
		return 1;

	s = r->db.x;
	lws_fx_add(&e, &s, &dlo->box.w);

	cf.whole = curr;
	cf.frac = 50000000;

	/*
	 * Account for four independently radiused corners
	 *
	 * Fractional pixel occupancy is represented by modulating alpha.
	 *
	 * We know that the subpixel intersection on the circle is at yo.frac +
	 * radius.frac which usually won't align to any pixel boundary.
	 */

	for (n = 0; n < 4; n++) {
		lws_fx_sub(&y, &cf, &r->c[n].ory);
		lws_fx_mul(&r->c[n].ys, &y, &y);
	}

	/* For this y line, find out how many x pixels we can skip at start
	 * and end before and after the first pixels that intersect */

	if (curr <= (r->c[0].ory.whole)) { /* top left trims s */
		isect(&r->c[0], &trim, &r->c[0].ys /* (cf - ory)^2 */);
		lws_fx_add(&s, &s, &trim);
	}

	if (curr <= (r->c[1].ory.whole)) { /* top right trims e */
		isect(&r->c[1], &trim, &r->c[1].ys);
		lws_fx_sub(&e, &e, &trim);
	}

	if (curr >= (r->c[2].ory.whole)) { /* bottom left trims s */
		isect(&r->c[2], &trim, &r->c[2].ys);
		lws_fx_add(&s, &s, &trim);
	}

	if (curr >= (r->c[3].ory.whole)) { /* bottom right trims e */
		isect(&r->c[3], &trim, &r->c[3].ys);
		lws_fx_sub(&e, &e, &trim);
	}

	/*
	 * The css border-triangle idiom: fill only the triangle at one corner,
	 * bounded by the diagonal to the opposite corner.  On scanline y the
	 * diagonal is at x = w.y / h from the left (or mirrored)
	 */

	if (r->tri && dlo->box.w.whole > 0 && dlo->box.h.whole > 0) {
		lws_fx_t k;

		lws_fx_set(k, (int32_t)curr, 0);
		lws_fx_sub(&k, &k, &r->db.y);        /* row in the box */
		lws_fx_mul(&t, &k, &dlo->box.w);
		lws_fx_div(&t, &t, &dlo->box.h);     /* diagonal x at this row */

		switch (r->tri) {
		case 1: /* top-left: full width at the top, shrinking */
			lws_fx_add(&e, &r->db.x, &dlo->box.w);
			lws_fx_sub(&e, &e, &t);
			break;
		case 2: /* top-right */
			lws_fx_add(&s, &r->db.x, &t);
			lws_fx_add(&e, &r->db.x, &dlo->box.w);
			break;
		case 3: /* bottom-left */
			lws_fx_add(&e, &r->db.x, &t);
			break;
		default: /* bottom-right */
			lws_fx_add(&s, &r->db.x, &dlo->box.w);
			lws_fx_sub(&s, &s, &t);
			break;
		}
	}

	/* clips */

	if (s.whole < 0)
		lws_fx_set(s, 0, 0);
	if (e.whole > w)
		lws_fx_set(e, w, 0);
	if (e.whole <= 0 || e.whole < s.whole)
		return 1; /* off to the left */

	lws_fx_sub(&t, &e, &s);
	if (lws_fx_comp(&t, &dlo->box.w) > 0)
		lws_fx_add(&e, &s, &dlo->box.w);

	/*
	 * The part of the line occupied by the rect body.  e is where it
	 * ends, so the pixel at e.whole is only covered by e.frac of it
	 */

	row->curr = curr;
	row->sfy = s;
	row->e = e;
	row->os = s.whole;
	row->le = e.whole;

	/*
	 * Between the corners, and the first and last pixels that may be only
	 * partly covered, all of the row is covered: pa .. pb are the pixels
	 * where none of the per-pixel adjustments can apply
	 */

	row->pa = s.frac ? row->os + 1 : row->os;
	row->pb = row->le - 1;
	if (curr <= r->c[0].ory.whole - 1 && row->pa <= r->c[0].orx.whole)
		row->pa = r->c[0].orx.whole + 1;
	if (curr >= r->c[2].ory.whole + 1 &&
	    row->pa < lws_fx_roundup(&r->c[2].orx))
		row->pa = lws_fx_roundup(&r->c[2].orx);
	if (curr <= r->c[1].ory.whole - 1 && row->pb >= r->c[1].orx.whole)
		row->pb = r->c[1].orx.whole - 1;
	if (curr >= r->c[3].ory.whole + 1 &&
	    row->pb >= lws_fx_roundup(&r->c[3].orx))
		row->pb = lws_fx_roundup(&r->c[3].orx) - 1;

	return 0;
}

/* the alpha, out of 255, of all of the row, from the rect's alpha */

unsigned int
lws_display_dlo_rect_row_alpha(const lws_dlo_rect_row_t *row,
			       unsigned int alpha)
{
	if (!row->cov.whole)
		alpha = cover(row->cov, alpha);

	return alpha;
}

/*
 * The alpha of pixel x of the row, from the alpha of all of the row: less
 * where the pixel is only partly covered, at the ends and on the corners
 */

unsigned int
lws_display_dlo_rect_px_alpha(lws_dlo_rect_t *r, const lws_dlo_rect_row_t *row,
			      int x, unsigned int alpha)
{
	lws_fx_t s, t2;

	if (x < row->os || x > row->le)
		return 0;

	s.whole = x;
	s.frac = 0;

	if (row->curr <= r->c[0].ory.whole - 1 && x >= r->db.x.whole &&
	    lws_fx_comp(&s, &r->c[0].orx) <= 0) {
		isect_y_from_x(&r->c[0], &s, &t2);
		lws_fx_sub(&t2, &t2, &r->c[0].r);
		lws_fx_sub(&t2, &t2, &r->c[0].r);
		if (t2.frac && lws_fx_rounddown(&t2) == row->curr)
			alpha = cover(t2, alpha);
	}
	if (row->curr <= (r->c[1].ory.whole - 1) &&
	    x >= r->c[1].orx.whole) {
		isect_y_from_x(&r->c[1], &s, &t2);
		lws_fx_sub(&t2, &t2, &r->c[1].r);
		lws_fx_sub(&t2, &t2, &r->c[1].r);
		if (t2.frac && lws_fx_rounddown(&t2) == row->curr)
			alpha = cover(t2, alpha);
	}
	if (row->curr >= (r->c[2].ory.whole + 1) &&
	    x < lws_fx_roundup(&r->c[2].orx)) {
		isect_y_from_x(&r->c[2], &s, &t2);
		if (t2.frac && lws_fx_rounddown(&t2) == row->curr)
			alpha = cover(t2, alpha);
	}
	if (row->curr >= (r->c[3].ory.whole + 1) &&
	    x >= lws_fx_roundup(&r->c[3].orx)) {
		isect_y_from_x(&r->c[3], &s, &t2);
		if (t2.frac && lws_fx_rounddown(&t2) == row->curr)
			alpha = cover(t2, alpha);
	}

	if (x == row->os && row->sfy.frac)
		alpha = (((uint64_t)(99999999 - row->sfy.frac) * alpha) /
			 LWS_FX_FRACTION_MSD) & 0xff;
	if (x == row->le)
		alpha = cover(row->e, alpha);

	return alpha;
}

/* does it have a border on any side */

static int
rect_bordered(const lws_dlo_rect_t *r)
{
	int n;

	for (n = 0; n < 4; n++)
		if ((r->b[n].whole || r->b[n].frac) && LWSDC_ALPHA(r->dcb[n]))
			return 1;

	return 0;
}

/*
 * The box inside the border of placed rect r, as a rect of its own, placed:
 * its corners are rounded by r's less the border on either side of them
 */

static void
rect_inner(const lws_dlo_rect_t *r, lws_dlo_rect_t *in)
{
	/* the sides either side of corner n: t-l, t-r, b-l, b-r */
	static const uint8_t cs[4][2] = { { 0, 3 }, { 0, 1 }, { 2, 3 },
					  { 2, 1 } };
	lws_fx_t ox, oy, *f;
	int n;

	memset(in, 0, sizeof(*in));

	lws_fx_sub(&in->dlo.box.w, &r->dlo.box.w, &r->b[1]);
	lws_fx_sub(&in->dlo.box.w, &in->dlo.box.w, &r->b[3]);
	lws_fx_sub(&in->dlo.box.h, &r->dlo.box.h, &r->b[0]);
	lws_fx_sub(&in->dlo.box.h, &in->dlo.box.h, &r->b[2]);
	f = &in->dlo.box.w;
	if (lws_neg(f))
		lws_fx_set(in->dlo.box.w, 0, 0);
	f = &in->dlo.box.h;
	if (lws_neg(f))
		lws_fx_set(in->dlo.box.h, 0, 0);

	for (n = 0; n < 4; n++) {
		const lws_fx_t *b = lws_fx_comp(&r->b[cs[n][0]],
						&r->b[cs[n][1]]) > 0 ?
					&r->b[cs[n][0]] : &r->b[cs[n][1]];

		lws_fx_sub(&in->c[n].r, &r->c[n].r, b);
		f = &in->c[n].r;
		if (lws_neg(f))
			lws_fx_set(in->c[n].r, 0, 0);
		lws_fx_mul(&in->c[n].rsq, &in->c[n].r, &in->c[n].r);
	}

	lws_fx_add(&ox, &r->db.x, &r->b[3]);
	lws_fx_add(&oy, &r->db.y, &r->b[0]);
	lws_display_dlo_rect_place(in, &ox, &oy);
}

static lws_display_colour_t
rect_alpha(lws_display_colour_t c, unsigned int alpha)
{
	return (lws_display_colour_t)((c & 0xffffff) |
		((uint32_t)((alpha * LWSDC_ALPHA(c)) / 255) << 24));
}

/*
 * Which side of r's border the pixel x, y is on, given the box inside it, in,
 * and whether line y crosses in (inner), or -1 if it should not be drawn.
 * Each corner is split between its two sides on the diagonal, unless one of
 * them isn't drawn, eg, a collapsed table cell's, when neither is: the border
 * of what is under it shows there.  Between the corners it's the side the
 * pixel is beyond the box inside on, else (where the box inside has rounded
 * corners) the nearer of the top or bottom.
 */

static int
rect_border_side(const lws_dlo_rect_t *r, const lws_dlo_rect_t *in,
		 int inner, int y, int x)
{
	lws_fx_t px, py, dx, dy, t1, t2;
	int h = -1, v = -1;

	px.whole = x;
	px.frac = 50000000;
	py.whole = y;
	py.frac = 50000000;

	if (lws_fx_comp(&px, &in->db.x) < 0)
		h = 3;
	else if (lws_fx_comp(&px, &in->right) > 0)
		h = 1;

	if (!inner || lws_fx_comp(&py, &in->db.y) < 0 ||
	    lws_fx_comp(&py, &in->btm) > 0 || h < 0) {
		/* the top or bottom, whichever is nearer the box inside */
		lws_fx_add(&t1, &in->db.y, &in->btm);
		lws_fx_add(&t2, &py, &py);
		v = lws_fx_comp(&t2, &t1) < 0 ? 0 : 2;

		if (h < 0)
			return v;
	}

	if (v < 0)
		return h;

	/* a corner */

	if (!LWSDC_ALPHA(r->dcb[h]) || !LWSDC_ALPHA(r->dcb[v]))
		return -1;

	if (h == 3)
		lws_fx_sub(&dx, &px, &r->db.x);
	else
		lws_fx_sub(&dx, &r->right, &px);
	if (!v)
		lws_fx_sub(&dy, &py, &r->db.y);
	else
		lws_fx_sub(&dy, &r->btm, &py);

	/* on the side whose edge it is nearer, for the widths of the sides */
	lws_fx_mul(&t1, &dx, &r->b[v]);
	lws_fx_mul(&t2, &dy, &r->b[h]);

	return lws_fx_comp(&t1, &t2) < 0 ? h : v;
}

/*
 * A row of a rect with a border: the box inside the border in the rect's
 * colour, and the rest, where the rect covers the row and the box inside
 * doesn't, in the colour of the border on that side
 */

static void
rect_render_bordered(struct lws_display_render_state *rs, lws_dlo_rect_t *r,
		     const lws_dlo_rect_row_t *row)
{
	lws_dlo_t *dlo = &r->dlo;
	unsigned int oa, ia, ora, ira = 0;
	lws_display_colour_t dc, bc;
	lws_dlo_rect_row_t irow;
	lws_dlo_rect_t in;
	int x, inner, side;

	rect_inner(r, &in);
	inner = !lws_display_dlo_rect_row(&in, rs->curr,
					  rs->ic->wh_px[0].whole, &irow);

	ora = lws_display_dlo_rect_row_alpha(row, 255);
	if (inner)
		ira = lws_display_dlo_rect_row_alpha(&irow, 255);

	x = row->os;
	while (x <= row->le) {
		if (inner && x == irow.pa && irow.pa <= irow.pb && ira == ora) {
			/*
			 * All of these are wholly inside the border, so the
			 * border doesn't show through any of them
			 */
			if (LWSDC_ALPHA(dlo->dc)) {
				dc = rect_alpha(dlo->dc, ira);
				lws_display_render_fill_span(rs, irow.pa,
							irow.pb + 1, &dc);
			}
			x = irow.pb + 1;
			continue;
		}

		oa = lws_display_dlo_rect_px_alpha(r, row, x, ora);
		ia = inner ? lws_display_dlo_rect_px_alpha(&in, &irow, x, ira) :
			     0;
		if (ia > oa)
			ia = oa;

		if (oa > ia) {
			side = rect_border_side(r, &in, inner, rs->curr, x);
			if (side >= 0 && LWSDC_ALPHA(r->dcb[side])) {
				bc = rect_alpha(r->dcb[side], oa - ia);
				lws_display_render_set_px(rs, x, &bc);
			}
		}

		if (ia && LWSDC_ALPHA(dlo->dc)) {
			dc = rect_alpha(dlo->dc, ia);
			lws_display_render_set_px(rs, x, &dc);
		}
		x++;
	}
}

lws_stateful_ret_t
lws_display_render_rect(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_rect_t *r = lws_container_of(dlo, lws_dlo_rect_t, dlo);
	lws_display_colour_t dc;
	unsigned int row_alpha;
	lws_dlo_rect_row_t row;
	lws_fx_t ox, oy;
	int x, bordered = rect_bordered(r);

	if (!LWSDC_ALPHA(dlo->dc) && !bordered)
		return LWS_SRET_OK;

	lws_fx_add(&ox, &rs->st[rs->sp].co.x, &dlo->box.x);
	lws_fx_add(&oy, &rs->st[rs->sp].co.y, &dlo->box.y);
	lws_display_dlo_rect_place(r, &ox, &oy);

	if (lws_display_dlo_rect_row(r, rs->curr, rs->ic->wh_px[0].whole, &row))
		return LWS_SRET_OK;

	if (bordered) {
		rect_render_bordered(rs, r, &row);

		return LWS_SRET_OK;
	}

	row_alpha = lws_display_dlo_rect_row_alpha(&row, dlo->dc >> 24);

	x = row.os;
	while (x <= row.le) {
		if (x == row.pa && row.pa <= row.pb) {
			/* all of these are the rect's colour at row_alpha */
			dc = (lws_display_colour_t)(((dlo->dc & 0xffffff) |
					(uint32_t)(row_alpha << 24)));
			lws_display_render_fill_span(rs, row.pa, row.pb + 1,
						     &dc);
			x = row.pb + 1;
			continue;
		}

		dc = (lws_display_colour_t)(((dlo->dc & 0xffffff) |
			(uint32_t)(lws_display_dlo_rect_px_alpha(r, &row, x,
						row_alpha) << 24)));
		lws_display_render_set_px(rs, x, &dc);
		x++;
	}

	return LWS_SRET_OK;
}

lws_dlo_rect_t *
lws_display_dlo_rect_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, const lws_fx_t *radii,
			 lws_display_colour_t dc)
{
	lws_dlo_rect_t *r = lws_zalloc(sizeof(*r), __func__);
	int n;

	if (!r)
		return NULL;

	r->dlo.render = lws_display_render_rect;
	r->dlo.box = *box;
	r->dlo.dc = dc;
	if (radii) {
		r->c[0].r = radii[0];
		r->c[1].r = radii[1];
		r->c[2].r = radii[2];
		r->c[3].r = radii[3];

		for (n = 0; n < 4; n++)
			lws_fx_mul(&r->c[n].rsq, &r->c[n].r, &r->c[n].r);
	}

	lws_display_dlo_add(dl, dlo_parent, &r->dlo);

	return r;
}
