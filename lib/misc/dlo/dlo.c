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
lws_display_dlo_add(lws_displaylist_t *dl, lws_dlo_t *dlo_parent, lws_dlo_t *dlo)
{
	lws_dll2_add_tail(&dlo->list, dlo_parent ? &dlo_parent->children : &dl->dl);

	return 9;
}

void
dist_err(const lws_colour_error_t *in, lws_colour_error_t *out, int sixteenths)
{
	out->rgb[0] = (int16_t)(out->rgb[0] + (int16_t)((sixteenths * in->rgb[0]) / 16));
	out->rgb[1] = (int16_t)(out->rgb[1] + (int16_t)((sixteenths * in->rgb[1]) / 16));
	out->rgb[2] = (int16_t)(out->rgb[2] + (int16_t)((sixteenths * in->rgb[2]) / 16));
}

void
lws_surface_set_px(const lws_surface_info_t *ic, uint8_t *line, int x,
		   const lws_display_colour_t *c, lws_colour_error_t *ce)
{
	unsigned int alpha, ialpha;
	lws_display_colour_t oc;
	uint8_t rgb[3];
	uint16_t n;

	switch (ic->type) {
	case LWSSURF_PALETTE_4BB:
		oc = ic->palette[get_nyb(line, x) % ic->palette_depth];
		oc = LWSDC_RGBA(LWSDC_R(oc), LWSDC_G(oc), LWSDC_B(oc), 0xff);
		n = lws_display_palettize(ic, *c, oc, ce);
		set_nyb(line, x, (uint8_t)n);
		break;
	case LWSSURF_TRUECOLOR32:
		oc = *(((uint32_t *)line) + x);
		alpha = LWSDC_ALPHA(*c);
		ialpha = 255 - alpha;

		rgb[0] = (uint8_t)(((LWSDC_R(*c) * alpha) / 255) +
			   ((LWSDC_R(oc) * ialpha) / 255));
		rgb[1] = (uint8_t)(((LWSDC_G(*c) * alpha) / 255) +
			   ((LWSDC_G(oc) * ialpha) / 255));
		rgb[2] = (uint8_t)(((LWSDC_B(*c) * alpha) / 255) +
			   ((LWSDC_B(oc) * ialpha) / 255));

		line += (x * 4);
		*line++ = rgb[0];
		*line++ = rgb[1];
		*line++ = rgb[2];
		*line++ = 0xff;;

		break;
	default:
		break;
	}
}

void
lws_display_raster(const lws_surface_info_t *ic, struct lws_dlo *dlo,
			lws_display_scalar curr, int s, int e, uint8_t *line,
			lws_colour_error_t **nle)
{
	lws_colour_error_t ce;
	int os = s;

	if (!LWSDC_ALPHA(dlo->dc))
		return;

	if (e > ic->wh_px[0].whole)
		e = ic->wh_px[0].whole - 1;

	while (s < e) {
		ce = nle[!(curr & 1)][s - os];

		lws_surface_set_px(ic, line, s, &dlo->dc, &ce);

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

	dlo->nle[0] = lws_zalloc(sizeof(dlo->nle[0][0]) * 2u *
				(unsigned int)(dlo->box.w.whole + 16 + 4),
				__func__);
	if (!dlo->nle[0])
		return 1;

	/*
	 * We arrange to have 16px of valid diffusion behind the official lhs,
	 * this is to manage kerning offsets at the start of line
	 */
	dlo->nle[0] += 16;

	dlo->nle[1] = dlo->nle[0] + dlo->box.w.whole + 16 + 4;

	return 0;
}

static void
lws_display_list_render_dlo_recursive(lws_display_render_state_t *rs,
				      lws_dlo_t *dlo, const lws_box_t *origin)
{
	lws_fixed3232_t t2;
	lws_box_t co;

	lws_fixed3232_add(&co.x, &origin->x, &dlo->box.x);
	lws_fixed3232_add(&co.y, &origin->y, &dlo->box.y);
	co.w = dlo->box.w;
	co.h = dlo->box.h;

	lws_fixed3232_add(&t2, &co.y, &dlo->box.h);

	/*
	 * destroy display list items as soon as we're rendering
	 * beyond their bottom edge, also destroys error
	 * diffusion buffer (notice the origin offset of any parent is
	 * accounted for since rs->curr is a display surface line index)
	 */

	if (rs->curr > lws_fixed3232_roundup(&t2)) {
		lws_display_dlo_destroy(&dlo);
		return;
	}

	if (rs->curr >= co.y.whole) {
		lws_dlo_ensure_err_diff(dlo);

		/* clear down next line's error states */
		memset(dlo->nle[rs->curr & 1] - 16, 0,
		       sizeof(dlo->nle[0][0]) *
				(unsigned int)(dlo->box.w.whole + 16 + 4));

		dlo->render(rs->ic, dlo, origin, rs->curr, rs->line,
			    &dlo->nle[0]);
	}

	if (!dlo->children.head)
		return;

	/*
	 * Go through any children recursively, with their origin set to
	 * ours, so they are "inside"
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
			      lws_dll2_get_head(&dlo->children)) {
		lws_dlo_t *cdlo = lws_container_of(p, lws_dlo_t, list);

		lws_display_list_render_dlo_recursive(rs, cdlo, &co);
	} lws_end_foreach_dll_safe(p, p1);
}

int
lws_display_list_render_line(lws_display_render_state_t *rs)
{
	lws_box_t origin;

	if (!rs->displaylist)
		return 0;

	memset(&origin, 0, sizeof(origin));
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
			      lws_dll2_get_head(&rs->displaylist->dl)) {
		lws_dlo_t *dlo = lws_container_of(p, lws_dlo_t, list);

		lws_display_list_render_dlo_recursive(rs, dlo, &origin);

	} lws_end_foreach_dll_safe(p, p1);

	return 0;
}


void
lws_display_dlo_destroy(lws_dlo_t **r)
{
	if (!(*r))
		return;

	lws_dll2_remove(&(*r)->list);

	while ((*r)->children.head) {
		lws_dlo_t *d = lws_container_of((*r)->children.head, lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}

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
lws_display_list_destroy(lws_displaylist_t **dl)
{
	if (!*dl)
		return;

	while ((*dl)->dl.head) {
		lws_dlo_t *d = lws_container_of((*dl)->dl.head, lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}
	*dl = NULL;
}

lws_display_palette_idx_t
lws_display_palettize(const lws_surface_info_t *ic, lws_display_colour_t c,
		      lws_display_colour_t oc, lws_colour_error_t *ectx)
{
	unsigned int alpha = LWSDC_ALPHA(c), ialpha = 255 - alpha;
	int best = 0x7fffffff, best_idx = 0, eialpha = 255;
	lws_colour_error_t d;
	size_t n;

	d.rgb[0] = (int16_t)(((LWSDC_R(c) * alpha) / 255) +
		   ((LWSDC_R(oc) * ialpha) / 255) +
			   (unsigned int)((ectx->rgb[0] * eialpha) / 255));
	d.rgb[1] = (int16_t)(((LWSDC_G(c) * alpha) / 255) +
		   ((LWSDC_G(oc) * ialpha) / 255) +
			   (unsigned int)((ectx->rgb[1] * eialpha) / 255));
	d.rgb[2] = (int16_t)(((LWSDC_B(c) * alpha) / 255) +
		   ((LWSDC_B(oc) * ialpha) / 255) +
			   (unsigned int)((ectx->rgb[2] * eialpha) / 255));

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

	for (n = 0; n < ic->palette_depth; n++) {
		lws_colour_error_t e;
		int sum;

		e.rgb[0] = (int16_t)((int)d.rgb[0] - (int)(LWSDC_R(ic->palette[n])));
		e.rgb[1] = (int16_t)(d.rgb[1] - (int)(LWSDC_G(ic->palette[n])));
		e.rgb[2] = (int16_t)(d.rgb[2] - (int)(LWSDC_B(ic->palette[n])));

		sum = (e.rgb[0] * e.rgb[0]) + (e.rgb[1] * e.rgb[1]) +
					      (e.rgb[2] * e.rgb[2]);
		if (sum < best) {
			best_idx = (int)n;
			best = sum;
			*ectx = e;
		}
	}

	return (lws_display_palette_idx_t)best_idx;
}

