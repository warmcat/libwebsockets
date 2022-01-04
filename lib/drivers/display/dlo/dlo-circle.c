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
 * Display List Object: circle
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

unsigned int
_isqrt(unsigned int n) {
	unsigned char s = n ? 64 - __builtin_clzll(n) : 1;
	unsigned int r = 0;

	s += s & 1;

	do {
		s -= 2;
		r <<= 1;
		r |= 1;
		r ^= r * r > (n >> s);
	} while (s);

	return r;
}

void
lws_display_render_circle(struct lws_display_state *lds, struct lws_dlo *dlo,
			lws_display_scalar curr, uint8_t *line,
			lws_colour_error_t **nle)
{
	int s, e, r = dlo->box.w / 2, w, y;

	if (curr < dlo->box.y || curr >= dlo->box.y + dlo->box.h)
		return;

	y = curr - (dlo->box.y + (dlo->box.h / 2)); /* -r .. 0 .. r */
	w = _isqrt(r * r - y * y);

	s = dlo->box.x + r - w;
	e = dlo->box.x + r + w;

	if (s < 0 || s > lds->disp->ic.wh_px[0].whole || e < 0 || e < s)
		return;

	if (e > lds->disp->ic.wh_px[0].whole)
		e = lds->disp->ic.wh_px[0].whole - 1;

	lws_display_raster(lds, dlo, curr, s, e, line, nle);
}

lws_dlo_circle_t *
lws_display_dlo_circle_new(lws_displaylist_t *dl, lws_box_t *box,
			 lws_display_colour_t dc)
{
	lws_dlo_circle_t *dlo_circ = lws_zalloc(sizeof(*dlo_circ), __func__);

	if (!dlo_circ)
		return NULL;

	dlo_circ->dlo.render = lws_display_render_circle;
	dlo_circ->dlo.box = *box;
	dlo_circ->dlo.dc = dc;

	lws_display_dlo_add(dl, &dlo_circ->dlo);

	return dlo_circ;
}
