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

void
lws_display_dlo_png_destroy(struct lws_dlo *dlo)
{
	lws_dlo_png_t *dlo_png = lws_container_of(dlo, lws_dlo_png_t, dlo);

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	lws_ss_destroy(&dlo_png->flow.h);
#endif
	lws_buflist_destroy_all_segments(&dlo_png->flow.bl);

	if (dlo_png->png)
		lws_upng_free(&dlo_png->png);
}

lws_stateful_ret_t
lws_display_render_png(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_png_t *dlo_png = lws_container_of(dlo, lws_dlo_png_t, dlo);
	lws_fx_t ax, ay, t, t1;
	lws_display_colour_t pc;
	lws_stateful_ret_t r;
	const uint8_t *pix;
	int s, e;

	if (!lws_upng_get_height(dlo_png->png)) {
		lwsl_info("%s: png does not have dimensions yet\n", __func__);
		return LWS_SRET_WANT_INPUT;
	}

	lws_fx_add(&ax, &rs->st[rs->sp].co.x, &dlo->box.x);
	lws_fx_add(&t, &ax, &dlo->box.w);
	lws_fx_add(&ay, &rs->st[rs->sp].co.y, &dlo->box.y);
	lws_fx_add(&t1, &ay, &dlo->box.h);

	s = ax.whole;
	e = lws_fx_roundup(&t);

	if (rs->curr > lws_fx_roundup(&t1))
		return LWS_SRET_OK;

	if (rs->curr - lws_fx_roundup(&ay) >
			(int)lws_upng_get_height(dlo_png->png))
		return LWS_SRET_OK;

	if (s < 0)
		s = 0;
	if (s > rs->ic->wh_px[0].whole)
		return LWS_SRET_OK; /* off to the right */
	if (e > rs->ic->wh_px[0].whole)
		e = rs->ic->wh_px[0].whole - 1;
	if (e <= 0)
		return LWS_SRET_OK; /* off to the left */

	do {
		if (lws_flow_feed(&dlo_png->flow))
			/* if he says WANT_INPUT, we have nothing in the buflist */
			return LWS_SRET_WANT_INPUT;

		pix = NULL;
		r = lws_upng_emit_next_line(dlo_png->png, &pix, &dlo_png->flow.data,
					    &dlo_png->flow.len, rs->html == 1 /* hold at metadata */);

		if (r & LWS_SRET_NO_FURTHER_IN)
			dlo_png->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;

		if (r & (LWS_SRET_FATAL | LWS_SRET_YIELD)  || r == LWS_SRET_OK)
			return r;

		r = lws_flow_req(&dlo_png->flow);
		if (r & LWS_SRET_WANT_INPUT)
			return r;

	} while (!pix);

	pix = pix + (( (unsigned int)(s - ax.whole) *
			(lws_upng_get_pixelsize(dlo_png->png) / 8)));

	while (s < e && s >= ax.whole && s < lws_fx_roundup(&t) &&
	       (s - ax.whole) < (int)lws_upng_get_width(dlo_png->png)) {

		if (lws_upng_get_pixelsize(dlo_png->png))
			pc = LWSDC_RGBA(pix[0], pix[0], pix[0], pix[1]);

		pc = LWSDC_RGBA(pix[0], pix[1], pix[2], pix[3]);

		lws_surface_set_px(rs->ic, rs->line, s, &pc);

		s++;
		pix += lws_upng_get_pixelsize(dlo_png->png) / 8;
	}

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_display_dlo_png_metadata_scan(lws_dlo_png_t *dlo_png)
{
	lws_stateful_ret_t r;
	size_t l, l1;
	const uint8_t *pix;

	/*
	 * If we don't have the image metadata yet, provide small chunks of the
	 * source data until we do have the image metadata, but small enough
	 * we can't produce any decoded pixels too early.
	 */

	while (!lws_upng_get_height(dlo_png->png) && dlo_png->flow.len) {
		l1 = l = dlo_png->flow.len > 33 ? 33 : dlo_png->flow.len;

		r = lws_upng_emit_next_line(dlo_png->png, &pix, &dlo_png->flow.data, &l, 1);
		if (r & LWS_SRET_FATAL) {
			lwsl_err("%s: hdr parse failed\n", __func__);
			return r;
		}

		dlo_png->flow.len -= l1 - l;

		if (lws_upng_get_height(dlo_png->png)) {
			lwsl_info("png: w %d, h %d\n",
					lws_upng_get_width(dlo_png->png),
					lws_upng_get_height(dlo_png->png));
			return LWS_SRET_OK;
		}
	}

	return LWS_SRET_WANT_INPUT;
}

lws_dlo_png_t *
lws_display_dlo_png_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box)
{
	lws_dlo_png_t *dlo_png = lws_zalloc(sizeof(*dlo_png), __func__);

	if (!dlo_png)
		return NULL;

	dlo_png->png = lws_upng_new();
	if (!dlo_png->png)
		goto bail;

	dlo_png->dlo.box = *box;
	dlo_png->dlo.render = lws_display_render_png;
	dlo_png->dlo._destroy = lws_display_dlo_png_destroy;

	lws_display_dlo_add(dl, dlo_parent, &dlo_png->dlo);

	return dlo_png;

bail:
	if (dlo_png->png)
		lws_upng_free(&dlo_png->png);
	lws_free(dlo_png);

	return NULL;
}
