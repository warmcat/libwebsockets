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
lws_display_render_rect(struct lws_display_state *lds, struct lws_dlo *dlo,
			lws_display_scalar curr, uint8_t *line,
			lws_colour_error_t **nle)
{
	lws_dlo_rect_t *dlo_rect = lws_container_of(dlo, lws_dlo_rect_t, dlo);
	int s = dlo->box.x, e = dlo->box.x + dlo->box.w, y, w;

	if (s > lds->disp->ic.wh_px[0].whole)
		return; /* off to the right */

	if (curr < dlo->box.y || curr >= dlo->box.y + dlo->box.h)
		return;

	if (dlo_rect->radius) {
		if (curr >= dlo->box.y + dlo->box.h - dlo_rect->radius) {
			y = curr - (dlo->box.y + dlo->box.h -
				    dlo_rect->radius);
			w = _isqrt(dlo_rect->radius * dlo_rect->radius - y * y);
			s += dlo_rect->radius - w;
			e -= dlo_rect->radius - w;
		} else
			if (curr < dlo->box.y + dlo_rect->radius) { /* top */
				y = curr - dlo->box.y - dlo_rect->radius;
				w = _isqrt(dlo_rect->radius *
					   dlo_rect->radius - y * y);
				s += dlo_rect->radius - w;
				e -= dlo_rect->radius - w;
			}
	}

	if (s < 0)
		s = 0;
	if (e > lds->disp->ic.wh_px[0].whole)
		e = lds->disp->ic.wh_px[0].whole - 1;
	if (e <= 0 || e < s)
		return; /* off to the left */

	lws_display_raster(lds, dlo, curr, s, e, line, nle);
}

lws_dlo_rect_t *
lws_display_dlo_rect_new(lws_displaylist_t *dl, lws_box_t *box, int radius,
			 lws_display_colour_t dc)
{
	lws_dlo_rect_t *dlo_rect = lws_zalloc(sizeof(*dlo_rect), __func__);

	if (!dlo_rect)
		return NULL;

	dlo_rect->dlo.render = lws_display_render_rect;
	dlo_rect->dlo.box = *box;
	dlo_rect->dlo.dc = dc;
	dlo_rect->radius = radius;

	lws_display_dlo_add(dl, &dlo_rect->dlo);

	return dlo_rect;
}
