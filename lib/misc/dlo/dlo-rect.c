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

	if (f->whole < 0) {
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

void
lws_display_render_rect(const lws_surface_info_t *ic, struct lws_dlo *dlo,
			const lws_box_t *origin, lws_display_scalar curr,
			uint8_t *line, lws_colour_error_t **nle)
{
	lws_dlo_rect_t *r = lws_container_of(dlo, lws_dlo_rect_t, dlo);
	lws_fx_t cf, y, w, trim, s, e, t2, sfy;
	lws_display_colour_t dc;
	lws_colour_error_t *ce;
	int n, le, os;

	if (!LWSDC_ALPHA(dlo->dc))
		return;

	if (!r->init) {
		lws_fx_add(&r->db.x,     &origin->x, &dlo->box.x);
		lws_fx_add(&r->db.y,     &origin->y, &dlo->box.y);
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

	if (lws_fx_comp(&r->db.x, &ic->wh_px[0]) >= 0)
		return; /* off to the right */

	if (curr < r->db.y.whole - 1 || curr > lws_fx_roundup(&r->btm))
		return;

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

	/* clips */

	if (s.whole < 0)
		lws_fx_set(s, 0, 0);
	if (e.whole >= ic->wh_px[0].whole)
		lws_fx_set(e, ic->wh_px[0].whole - 1, 0);
	if (e.whole <= 0 || e.whole < s.whole)
		return; /* off to the left */

	lws_fx_sub(&w, &e, &s);
	if (lws_fx_comp(&w, &dlo->box.w) > 0)
		lws_fx_add(&e, &s, &dlo->box.w);

	/* render the part of the line occupied by the rect body */

	sfy = s;
	os = s.whole;
	s.frac = 0;
	le = e.whole;
	ce = nle[!(curr & 1)];

	while (s.whole <= le) {
		unsigned int alpha = dlo->dc >> 24;

		if (curr <= r->c[0].ory.whole - 1 && s.whole >= r->db.x.whole &&
		    lws_fx_comp(&s, &r->c[0].orx) <= 0) {
			isect_y_from_x(&r->c[0], &s, &t2);
			lws_fx_sub(&t2, &t2, &r->c[0].r);
			lws_fx_sub(&t2, &t2, &r->c[0].r);
			if (t2.frac && lws_fx_rounddown(&t2) == curr)
				alpha = (((uint64_t)t2.frac * alpha) /
						LWS_FX_FRACTION_MSD) & 0xff;
		}
		if (curr <= (r->c[1].ory.whole - 1) &&
		    s.whole >= r->c[1].orx.whole) {
			isect_y_from_x(&r->c[1], &s, &t2);
			lws_fx_sub(&t2, &t2, &r->c[1].r);
			lws_fx_sub(&t2, &t2, &r->c[1].r);
			if (t2.frac && lws_fx_rounddown(&t2) == curr)
				alpha = (((uint64_t)t2.frac * alpha) /
						LWS_FX_FRACTION_MSD) & 0xff;
		}
		if (curr >= (r->c[2].ory.whole + 1) &&
		    s.whole < lws_fx_roundup(&r->c[2].orx)) {
			isect_y_from_x(&r->c[2], &s, &t2);
			if (t2.frac && lws_fx_rounddown(&t2) == curr)
				alpha = (((uint64_t)t2.frac * alpha) /
						LWS_FX_FRACTION_MSD) & 0xff;
		}

		if (curr >= (r->c[3].ory.whole + 1) &&
		    s.whole >= lws_fx_roundup(&r->c[3].orx)) {
			isect_y_from_x(&r->c[3], &s, &t2);
			if (t2.frac && lws_fx_rounddown(&t2) == curr)
				alpha = (((uint64_t)t2.frac * alpha) /
						LWS_FX_FRACTION_MSD) & 0xff;
		}

               if (s.whole == os && sfy.frac)
                       alpha = (((uint64_t)(99999999 - sfy.frac) * alpha) /
                		       LWS_FX_FRACTION_MSD) & 0xff;
               if (s.whole == le)
        	       alpha = (((uint64_t)e.frac * alpha) /
        			       LWS_FX_FRACTION_MSD) & 0xff;


		dc = (lws_display_colour_t)(((dlo->dc & 0xffffff) |
	                       (uint32_t)(alpha << 24)));

		lws_surface_set_px(ic, line, s.whole, &dc, ce);

		if (ic->type != LWSSURF_TRUECOLOR32) {
			if (s.whole != le - 1) {
				dist_err(ce, &nle[!(curr & 1)][s.whole - os + 1], 7);
				dist_err(ce, &nle[curr & 1][s.whole - os + 1], 1);
			}
			if (s.whole > os)
				dist_err(ce, &nle[curr & 1][s.whole - os- 1], 3);

			dist_err(ce, &nle[curr & 1][s.whole - os], 5);
			ce++;
		}

		s.whole++;
	}
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
