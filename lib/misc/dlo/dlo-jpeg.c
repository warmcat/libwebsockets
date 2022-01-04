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
 * Display List Object: JPEG
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

static void
lws_display_dlo_jpeg_destroy(struct lws_dlo *dlo)
{
	lws_dlo_jpeg_t *dlo_jpeg = lws_container_of(dlo, lws_dlo_jpeg_t, dlo);

	if (dlo_jpeg->j)
		lws_jpeg_free(&dlo_jpeg->j);
}

lws_stateful_ret_t
lws_display_render_jpeg(const lws_surface_info_t *ic, struct lws_dlo *dlo,
		        const lws_box_t *origin, lws_display_scalar curr,
		        uint8_t *line, lws_colour_error_t **nle)
{
	lws_dlo_jpeg_t *dlo_jpeg = lws_container_of(dlo, lws_dlo_jpeg_t, dlo);
	lws_display_colour_t pc;
	lws_fx_t ax, ay, t, t1;
	lws_colour_error_t ce;
	lws_stateful_ret_t r;
	const uint8_t *pix;
	int s, e;

	lws_fx_add(&ax, &origin->x, &dlo->box.x);
	lws_fx_add(&t, &ax, &dlo->box.w);
	lws_fx_add(&ay, &origin->y, &dlo->box.y);
	lws_fx_add(&t1, &ay, &dlo->box.h);

	s = ax.whole;
	e = lws_fx_roundup(&t);

	if (curr > lws_fx_roundup(&t1))
		return LWS_SRET_OK;

	if (curr - lws_fx_roundup(&ay) >
			(int)lws_jpeg_get_height(dlo_jpeg->j))
		return LWS_SRET_OK;

	if (s < 0)
		s = 0;
	if (s > ic->wh_px[0].whole)
		return LWS_SRET_OK; /* off to the right */
	if (e > ic->wh_px[0].whole)
		e = ic->wh_px[0].whole - 1;
	if (e <= 0)
		return LWS_SRET_OK; /* off to the left */

	lws_dlo_ensure_err_diff(dlo);

	pix = NULL;
	r = lws_jpeg_emit_next_line(dlo_jpeg->j, &pix, &dlo_jpeg->flow.data,
				    &dlo_jpeg->flow.len);

	if (!pix)
		return LWS_SRET_OK;

	if (r == LWS_SRET_WANT_INPUT && dlo_jpeg->flow.cb)
		dlo_jpeg->flow.cb(&dlo_jpeg->flow, LWSDLOFLOW_EVENT_EMPTY);

	if (r && r != LWS_SRET_WANT_OUTPUT)
		return r;

	/*
	 * What's in pix is either 24-bit RGB 3 bytes/px, or 8-bit grayscale
	 * 1 byte/px, we have to map it on to the 32-bit RGBA rasterization buf
	 */

	pix = pix + (( (unsigned int)(s - ax.whole) *
			(lws_jpeg_get_pixelsize(dlo_jpeg->j) / 8)));

	while (s < e && s >= ax.whole && s < lws_fx_roundup(&t) &&
	       (s - ax.whole) < (int)lws_jpeg_get_width(dlo_jpeg->j)) {
		ce = nle[!(curr & 1)][s - ax.whole];

		if (lws_jpeg_get_pixelsize(dlo_jpeg->j) == 8)
			pc = LWSDC_RGBA(pix[0], pix[0], pix[0], 255);
		else
			pc = LWSDC_RGBA(pix[0], pix[1], pix[2], 255);
		{
			int sx = s - ax.whole;

			lws_surface_set_px(ic, line, s, &pc, &ce);

			if (s != e - 1) {
				dist_err(&ce, &nle[!(curr & 1)][sx + 1], 7);
				dist_err(&ce, &nle[curr & 1][sx + 1], 1);
			}
			if (s > ax.whole)
				dist_err(&ce, &nle[curr & 1][sx - 1], 3);
			dist_err(&ce, &nle[curr & 1][sx], 5);
		}
		s++;
		pix += lws_jpeg_get_pixelsize(dlo_jpeg->j) / 8;
	}

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_display_dlo_jpeg_data(lws_dlo_jpeg_t *dlo_jpeg, const uint8_t *data, size_t len)
{
	lws_stateful_ret_t r;
	size_t l, l1;
	const uint8_t *pix;

	dlo_jpeg->flow.data = data;
	dlo_jpeg->flow.len = len;

	/*
	 * If we don't have the image metadata yet, provide small chunks of the
	 * source data until we do have the image metadata, but small enough
	 * we can't produce any decoded pixels too early.
	 */

	while (!lws_jpeg_get_height(dlo_jpeg->j) && dlo_jpeg->flow.len) {
		l1 = l = dlo_jpeg->flow.len > 128 ? 128 : dlo_jpeg->flow.len;

		r = lws_jpeg_emit_next_line(dlo_jpeg->j, &pix, &dlo_jpeg->flow.data, &l);
		if (r >= LWS_SRET_FATAL) {
			lwsl_err("%s: hdr parse failed\n", __func__);
			return r;
		}

		dlo_jpeg->flow.len -= l1 - l;

		if (lws_jpeg_get_height(dlo_jpeg->j)) {
			lwsl_user("jpeg: w %d, h %d\n",
					lws_jpeg_get_width(dlo_jpeg->j),
					lws_jpeg_get_height(dlo_jpeg->j));

			if (dlo_jpeg->flow.cb)
				dlo_jpeg->flow.cb(&dlo_jpeg->flow,
						LWSDLOFLOW_EVENT_METADATA_AVAIL);
		}
	}

	if (dlo_jpeg->flow.len && dlo_jpeg->flow.cb)
		dlo_jpeg->flow.cb(&dlo_jpeg->flow, LWSDLOFLOW_EVENT_DATA_AVAIL);

	return LWS_SRET_OK;
}

lws_dlo_jpeg_t *
lws_display_dlo_jpeg_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, lws_dlo_flow_event_cb_t cb, void *arg)
{
	lws_dlo_jpeg_t *dlo_jpeg = lws_zalloc(sizeof(*dlo_jpeg), __func__);

	if (!dlo_jpeg)
		return NULL;

	dlo_jpeg->j = lws_jpeg_new();
	if (!dlo_jpeg->j)
		goto bail;

	dlo_jpeg->flow.cb = cb;
	dlo_jpeg->flow.priv = arg;

	dlo_jpeg->dlo.box = *box;
	dlo_jpeg->dlo.render = lws_display_render_jpeg;
	dlo_jpeg->dlo._destroy = lws_display_dlo_jpeg_destroy;

	lws_display_dlo_add(dl, dlo_parent, &dlo_jpeg->dlo);

	return dlo_jpeg;

bail:
	lwsl_err("%s: bailed\n", __func__);
	if (dlo_jpeg->j)
		lws_jpeg_free(&dlo_jpeg->j);

	lws_free(dlo_jpeg);

	return NULL;
}
