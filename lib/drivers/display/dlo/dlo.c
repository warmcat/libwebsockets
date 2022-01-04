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
 * Display List Object handling
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

/*
 * For error disffusion, it's better to use YUV and prioritize reducing error
 * in Y (lumience)
 */

#if 0
static void
rgb_to_yuv(uint8_t *yuv, const uint8_t *rgb)
{
	yuv[0] =  16 + ((257 * rgb[0]) / 1000) + ((504 * rgb[1]) / 1000) +
						  ((98 * rgb[2]) / 1000);
	yuv[1] = 128 - ((148 * rgb[0]) / 1000) - ((291 * rgb[1]) / 1000) +
						 ((439 * rgb[2]) / 1000);
	yuv[2] = 128 + ((439 * rgb[0]) / 1000) - ((368 * rgb[1]) / 1000) -
						  ((71 * rgb[2]) / 1000);
}

static void
yuv_to_rgb(uint8_t *rgb, const uint8_t *_yuv)
{
	unsigned int yuv[3];

	yuv[0] = _yuv[0] - 16;
	yuv[1] = _yuv[1] - 128;
	yuv[2] = _yuv[2] - 128;

	rgb[0] = ((1164 * yuv[0]) / 1000) + ((1596 * yuv[2]) / 1000);
	rgb[1] = ((1164 * yuv[0]) / 1090) -  ((392 * yuv[1]) / 1000) -
					     ((813 * yuv[2]) / 1000);
	rgb[2] = ((1164 * yuv[0]) / 1000) + ((2017 * yuv[1]) / 1000);
}
#endif


void
lws_display_dl_init(lws_displaylist_t *dl, lws_display_state_t *ds)
{
	lws_dll2_owner_clear(&dl->dl);
	dl->ds = ds;
}

int
lws_display_dlo_add(lws_displaylist_t *dl, lws_dlo_t *dlo)
{
	lws_dll2_add_tail(&dlo->list, &dl->dl);

	return 9;
}

void
dist_err(const lws_colour_error_t *in, lws_colour_error_t *out, int sixteenths)
{
	out->rgb[0] += (sixteenths * in->rgb[0]) / 16;
	out->rgb[1] += (sixteenths * in->rgb[1]) / 16;
	out->rgb[2] += (sixteenths * in->rgb[2]) / 16;
}

void
lws_display_raster(struct lws_display_state *lds, struct lws_dlo *dlo,
			lws_display_scalar curr, int s, int e, uint8_t *line,
			lws_colour_error_t **nle)
{
	lws_display_colour_t oc;
	lws_colour_error_t ce;
	int os = s;

	if (!LWSDC_ALPHA(dlo->dc))
		return;

	if (e > lds->disp->ic.wh_px[0].whole)
		e = lds->disp->ic.wh_px[0].whole - 1;

	while (s < e) {
		oc = get_nyb(line, s);
		oc = LWSDC_RGBA(LWSDC_R(lds->disp->palette[oc]),
				LWSDC_G(lds->disp->palette[oc]),
				LWSDC_B(lds->disp->palette[oc]), 0xff);
		ce = nle[!(curr & 1)][s - os];

		set_nyb(line, s,
			lws_display_palettize(lds->disp, dlo->dc, oc, &ce));

		if (s != e - 1) {
			dist_err(&ce, &nle[!(curr & 1)][s - os + 1], 7);
			dist_err(&ce, &nle[curr & 1][s - os + 1], 1);
		}
		if (s > os)
			dist_err(&ce, &nle[curr & 1][s - os- 1], 3);

		dist_err(&ce, &nle[curr & 1][s - os], 5);

		s++;
	}
}

int
lws_dlo_ensure_err_diff(lws_dlo_t *dlo)
{
	/* defer creation of dlo's 2px-high dlo-width, 32bpp
	 * error diffusion buffer */

	if (dlo->nle[0])
		return 0;

	dlo->nle[0] = lws_zalloc(sizeof(dlo->nle[0][0]) * 2 *
					(dlo->box.w + 16 + 3), __func__);
	if (!dlo->nle[0])
		return 1;

	/*
	 * We arrange to have 16px of valid diffusion behind the official lhs,
	 * this is to manage kerning offsets at the start of line
	 */
	dlo->nle[0] += 16;

	dlo->nle[1] = dlo->nle[0] + dlo->box.w + 16 + 3;

	return 0;
}

int
lws_display_list_render_line(lws_display_render_state_t *rs)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
			      lws_dll2_get_head(&rs->displaylist->dl)) {
		lws_dlo_t *dlo = lws_container_of(p, lws_dlo_t, list);

		/*
		 * destroy display list items as soon as we're rendering
		 * beyond their bottom edge, also destroys error
		 * diffusion buffer
		 */
		if (rs->curr == dlo->box.y + dlo->box.h) {
			lws_display_dlo_destroy(&dlo);
		} else {

			if (rs->curr >= dlo->box.y &&
			    rs->curr < dlo->box.y + dlo->box.h) {

				lws_dlo_ensure_err_diff(dlo);

				/* clear down next line's error states */
				memset(dlo->nle[rs->curr & 1] - 16, 0,
				       sizeof(dlo->nle[0][0]) * (dlo->box.w + 16 + 3));

				dlo->render(rs->lds, dlo, rs->curr, rs->line,
					    &dlo->nle[0]);
			}
		}
	} lws_end_foreach_dll_safe(p, p1);

	return 0;
}


void
lws_display_dlo_destroy(lws_dlo_t **r)
{
	if (!(*r))
		return;

	lws_dll2_remove(&(*r)->list);

	if ((*r)->_destroy)
		(*r)->_destroy(*r);

	if ((*r)->nle[0]) {
		(*r)->nle[0] -= 16;
		lws_free_set_NULL((*r)->nle[0]);
	}

	lws_free_set_NULL(*r);
	*r = NULL;
}

void
lws_display_list_destroy(lws_displaylist_t *dl)
{
	while (dl->dl.head) {
		lws_dlo_t *d = lws_container_of(dl->dl.head, lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}
}

lws_display_palette_idx_t
lws_display_palettize(const lws_display_t *disp, lws_display_colour_t c,
		      lws_display_colour_t oc, lws_colour_error_t *ectx)
{
	int alpha = LWSDC_ALPHA(c), ialpha = 255 - alpha,
			best = 0x7fffffff, best_idx = 0;
	int eialpha = 255;//(int)ialpha;
	lws_colour_error_t d;
	size_t n;

	d.rgb[0] = ((LWSDC_R(c) * alpha) / 255) +
		   ((LWSDC_R(oc) * ialpha) / 255) +
			   ((ectx->rgb[0] * eialpha) / 255);
	d.rgb[1] = ((LWSDC_G(c) * alpha) / 255) +
		   ((LWSDC_G(oc) * ialpha) / 255) +
			   ((ectx->rgb[1] * eialpha) / 255);
	d.rgb[2] = ((LWSDC_B(c) * alpha) / 255) +
		   ((LWSDC_B(oc) * ialpha) / 255) +
			   ((ectx->rgb[2] * eialpha) / 255);

	if (d.rgb[0] > 255)
		d.rgb[0] = 255;
	if (d.rgb[1] > 255)
		d.rgb[1] = 255;
	if (d.rgb[2] > 255)
		d.rgb[2] = 255;
	if (d.rgb[0] < 0)
		d.rgb[0] = 0;
	if (d.rgb[1] < 0)
		d.rgb[1] = 0;
	if (d.rgb[2] < 0)
		d.rgb[2] = 0;

	/*
	 * We know what we want, considering transparency and prior error...
	 * let's pick the least bad choice from the palette
	 */

	for (n = 0; n < disp->palette_depth; n++) {
		lws_colour_error_t e;
		int sum;

		e.rgb[0] = d.rgb[0] - LWSDC_R(disp->palette[n]);
		e.rgb[1] = d.rgb[1] - LWSDC_G(disp->palette[n]);
		e.rgb[2] = d.rgb[2] - LWSDC_B(disp->palette[n]);

		sum = (e.rgb[0] * e.rgb[0]) + (e.rgb[1] * e.rgb[1]) +
					      (e.rgb[2] * e.rgb[2]);
		if (sum < best) {
			best_idx = n;
			best = sum;
			*ectx = e;
		}
	}

	return best_idx;
}

