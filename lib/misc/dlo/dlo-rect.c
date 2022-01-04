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

void
lws_display_render_rect(const lws_surface_info_t *ic, struct lws_dlo *dlo,
			const lws_box_t *origin, lws_display_scalar curr,
			uint8_t *line, lws_colour_error_t **nle)
{
	lws_dlo_rect_t *dlo_rect = lws_container_of(dlo, lws_dlo_rect_t, dlo);
	lws_fixed3232_t btm, t1, t2, t3, cf, y, ys, w, rsq, trim;
	int s, e;
	lws_box_t db;

	lws_fixed3232_add(&db.x, &origin->x, &dlo->box.x);
	lws_fixed3232_add(&db.y, &origin->y, &dlo->box.y);

	lws_fixed3232_add(&btm, &db.y, &dlo->box.h);

	s = db.x.whole;
	e = s + lws_fixed3232_roundup(&dlo->box.w);

	if (s > ic->wh_px[0].whole)
		return; /* off to the right */

	if (curr < db.y.whole || curr > lws_fixed3232_roundup(&btm))
		return;

	/* account for four independently radiused corners */

	cf.whole = curr;
	cf.frac = 0;

	lws_fixed3232_add(&t1, &db.y, &dlo_rect->radius[0]);
	if (curr <= lws_fixed3232_roundup(&t1)) { /* top left trims s */
		lws_fixed3232_sub(&y, &cf, &t1);
		lws_fixed3232_mul(&ys, &y, &y);
		lws_fixed3232_mul(&rsq, &dlo_rect->radius[0],
					&dlo_rect->radius[0]);

		lws_fixed3232_sqrt(&w, lws_fixed3232_sub(&t3, &rsq, &ys));
		lws_fixed3232_sub(&trim, &dlo_rect->radius[0], &w);
		s += lws_fixed3232_roundup(&trim);
	}

	lws_fixed3232_add(&t1, &db.y, &dlo_rect->radius[1]);
	if (curr <= lws_fixed3232_roundup(&t1)) { /* top right trims e */
		lws_fixed3232_sub(&y, &cf, &t1);
		lws_fixed3232_mul(&ys, &y, &y);
		lws_fixed3232_mul(&rsq, &dlo_rect->radius[1],
					&dlo_rect->radius[1]);

		lws_fixed3232_sqrt(&w, lws_fixed3232_sub(&t3, &rsq, &ys));
		lws_fixed3232_sub(&trim, &dlo_rect->radius[1], &w);
		e -= lws_fixed3232_roundup(&trim);
	}

	lws_fixed3232_add(&t2, &db.y, &dlo->box.h);
	lws_fixed3232_sub(&t1, &t2, &dlo_rect->radius[2]);
	if (curr >= lws_fixed3232_roundup(&t1)) { /* bottom left trims s */
		lws_fixed3232_sub(&y, &cf, &t1);
		lws_fixed3232_mul(&ys, &y, &y);
		lws_fixed3232_mul(&rsq, &dlo_rect->radius[2],
					&dlo_rect->radius[2]);

		lws_fixed3232_sqrt(&w, lws_fixed3232_sub(&t3, &rsq, &ys));
		lws_fixed3232_sub(&trim, &dlo_rect->radius[2], &w);
		s += lws_fixed3232_roundup(&trim);
	}

	lws_fixed3232_add(&t2, &db.y, &dlo->box.h);
	lws_fixed3232_sub(&t1, &t2, &dlo_rect->radius[3]);
	if (curr >= lws_fixed3232_roundup(&t1)) { /* bottom right trims e */
		lws_fixed3232_sub(&y, &cf, &t1);
		lws_fixed3232_mul(&ys, &y, &y);
		lws_fixed3232_mul(&rsq, &dlo_rect->radius[3],
					&dlo_rect->radius[3]);

		lws_fixed3232_sqrt(&w, lws_fixed3232_sub(&t3, &rsq, &ys));
		lws_fixed3232_sub(&trim, &dlo_rect->radius[3], &w);
		e -= lws_fixed3232_roundup(&trim);
	}

	if (s < 0)
		s = 0;
	if (e > ic->wh_px[0].whole)
		e = ic->wh_px[0].whole - 1;
	if (e <= 0 || e < s)
		return; /* off to the left */

	lws_display_raster(ic, dlo, curr, s, e, line, nle);
}

lws_dlo_rect_t *
lws_display_dlo_rect_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, const lws_fixed3232_t *radii,
			 lws_display_colour_t dc)
{
	lws_dlo_rect_t *dlo_rect = lws_zalloc(sizeof(*dlo_rect), __func__);

	if (!dlo_rect)
		return NULL;

	dlo_rect->dlo.render = lws_display_render_rect;
	dlo_rect->dlo.box = *box;
	dlo_rect->dlo.dc = dc;
	if (radii)
		memcpy(&dlo_rect->radius, radii, sizeof(dlo_rect->radius));

	lws_display_dlo_add(dl, dlo_parent, &dlo_rect->dlo);

	return dlo_rect;
}
