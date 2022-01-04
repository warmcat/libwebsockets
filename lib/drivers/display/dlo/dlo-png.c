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
 * Display List Object: PNG
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

static void
lws_display_dlo_png_destroy(struct lws_dlo *dlo)
{
	lws_dlo_png_t *dlo_png = lws_container_of(dlo, lws_dlo_png_t, dlo);

	if (dlo_png->png)
		upng_free(dlo_png->png);
}

void
lws_display_render_png(struct lws_display_state *lds, struct lws_dlo *dlo,
		       lws_display_scalar curr, uint8_t *line,
		       lws_colour_error_t **nle)
{
	lws_dlo_png_t *dlo_png = lws_container_of(dlo, lws_dlo_png_t, dlo);
	int s = dlo->box.x, e = dlo->box.x + dlo->box.w;
	lws_display_colour_t oc, pc;
	lws_colour_error_t ce;
	const uint8_t *pix;

	if (curr - dlo->box.y > dlo->box.h)
		return;

	if (curr - dlo->box.y > (int)upng_get_height(dlo_png->png))
		return;

	if (s < 0)
		s = 0;
	if (s > lds->disp->ic.wh_px[0].whole)
		return; /* off to the right */
	if (e > lds->disp->ic.wh_px[0].whole)
		e = lds->disp->ic.wh_px[0].whole - 1;
	if (e <= 0)
		return; /* off to the left */

	lws_dlo_ensure_err_diff(dlo);

	if (upng_emit_next_line(dlo_png->png, &pix) || !pix)
		return;

	pix += ((s - dlo->box.x) * (upng_get_pixelsize(dlo_png->png) / 8));

	while (s < e && s >= dlo->box.x && s < dlo->box.x + dlo->box.w &&
			(s -dlo->box.x) < (int)upng_get_width(dlo_png->png)) {
		oc = lds->disp->palette[get_nyb(line, s) & 7] | 0xff000000;

		ce = nle[!(curr & 1)][s - dlo->box.x];

		pc = LWSDC_RGBA(pix[0], pix[1], pix[2], pix[3]);
		if (pix[3]) {
			set_nyb(line, s,
				lws_display_palettize(lds->disp, pc, oc, &ce));

			if (s != e - 1) {
				dist_err(&ce, &nle[!(curr & 1)][s - dlo->box.x + 1], 7);
				dist_err(&ce, &nle[curr & 1][s - dlo->box.x + 1], 1);
			}
			if (s > dlo->box.x)
				dist_err(&ce, &nle[curr & 1][s - dlo->box.x - 1], 3);
			dist_err(&ce, &nle[curr & 1][s - dlo->box.x], 5);
		}
		s++;
		pix += upng_get_pixelsize(dlo_png->png) / 8;
	}
}

lws_dlo_png_t *
lws_display_dlo_png_new(lws_displaylist_t *dl, lws_box_t *box,
			const uint8_t *png, size_t png_size)
{
	lws_dlo_png_t *dlo_png = lws_zalloc(sizeof(*dlo_png), __func__);
	upng_ret_t r;

	dlo_png->png = upng_new_from_bytes(png, png_size);
	if (!dlo_png->png)
		goto bail;

	dlo_png->dlo.box = *box;
	dlo_png->dlo.render = lws_display_render_png;
	dlo_png->dlo._destroy = lws_display_dlo_png_destroy;

	if (upng_header(dlo_png->png))
		goto bail;
	lwsl_user("png: w %d, h %d\n", upng_get_width(dlo_png->png),
			upng_get_height(dlo_png->png));
	/*
	 * This gets us the decoded data that can be read out and post-filtered
	 * line by line
	 */
	r = upng_decode(dlo_png->png);
	if (r) {
		lwsl_err("%s: decode failed: %d\n", __func__, r);
		goto bail;
	}

	lws_display_dlo_add(dl, &dlo_png->dlo);

	return dlo_png;

bail:
	lws_free(dlo_png);

	return NULL;
}
