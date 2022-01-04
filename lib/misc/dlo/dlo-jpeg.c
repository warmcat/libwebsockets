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

void
lws_display_dlo_jpeg_destroy(struct lws_dlo *dlo)
{
	lws_dlo_jpeg_t *dlo_jpeg = lws_container_of(dlo, lws_dlo_jpeg_t, dlo);

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	lws_ss_destroy(&dlo_jpeg->flow.h);
#endif
	lws_buflist_destroy_all_segments(&dlo_jpeg->flow.bl);

	if (dlo_jpeg->j)
		lws_jpeg_free(&dlo_jpeg->j);
}

lws_stateful_ret_t
lws_display_render_jpeg(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_jpeg_t *dlo_jpeg = lws_container_of(dlo, lws_dlo_jpeg_t, dlo);
	lws_display_colour_t pc;
	lws_fx_t ax, ay, t, t1;
	lws_stateful_ret_t r;
	const uint8_t *pix;
	int s, e;

	lws_fx_add(&ax, &rs->st[rs->sp].co.x, &dlo->box.x);
	lws_fx_add(&t, &ax, &dlo->box.w);
	lws_fx_add(&ay, &rs->st[rs->sp].co.y, &dlo->box.y);
	lws_fx_add(&t1, &ay, &dlo->box.h);

	if (!lws_jpeg_get_height(dlo_jpeg->j)) {
		lwsl_info("%s: jpeg does not have dimensions yet\n", __func__);
		return LWS_SRET_WANT_INPUT;
	}

	s = ax.whole;
	e = lws_fx_roundup(&t);

	if (rs->curr > lws_fx_roundup(&t1))
		return LWS_SRET_OK;

	if (rs->curr - lws_fx_roundup(&ay) >
			(int)lws_jpeg_get_height(dlo_jpeg->j))
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
		if (lws_flow_feed(&dlo_jpeg->flow))
			/* if he says WANT_INPUT, we have nothing in the buflist */
			return LWS_SRET_WANT_INPUT;

		pix = NULL;
		r = lws_jpeg_emit_next_line(dlo_jpeg->j, &pix, &dlo_jpeg->flow.data,
					    &dlo_jpeg->flow.len, rs->html == 1);

		if (r & LWS_SRET_NO_FURTHER_IN)
			dlo_jpeg->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;

		if (r & LWS_SRET_FATAL || r == LWS_SRET_OK)
			return r;

		r = lws_flow_req(&dlo_jpeg->flow);
		if (r & LWS_SRET_WANT_INPUT)
			return r;

	} while (!pix);

	/*
	 * What's in pix is either 24-bit RGB 3 bytes/px, or 8-bit grayscale
	 * 1 byte/px, we have to map it on to either 32-bit RGBA or 16-bit YA
	 * composition buf
	 */

	pix = pix + (( (unsigned int)(s - ax.whole) *
			(lws_jpeg_get_pixelsize(dlo_jpeg->j) / 8)));

	while (s < e && s >= ax.whole && s < lws_fx_roundup(&t) &&
	       (s - ax.whole) < (int)lws_jpeg_get_width(dlo_jpeg->j)) {

		if (lws_jpeg_get_pixelsize(dlo_jpeg->j) == 8)
			pc = LWSDC_RGBA(pix[0], pix[0], pix[0], 255);
		else
			pc = LWSDC_RGBA(pix[0], pix[1], pix[2], 255);

		lws_surface_set_px(rs->ic, rs->line, s, &pc);
		s++;
		pix += lws_jpeg_get_pixelsize(dlo_jpeg->j) / 8;
	}

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_display_dlo_jpeg_metadata_scan(lws_dlo_jpeg_t *dlo_jpeg)
{
	lws_stateful_ret_t r;
	size_t l, l1;
	const uint8_t *pix;

	/*
	 * If we don't have the image metadata yet, provide small chunks of the
	 * source data until we do have the image metadata, but small enough
	 * we can't produce any decoded pixels too early.
	 */

	while (!lws_jpeg_get_height(dlo_jpeg->j) && dlo_jpeg->flow.len) {
		l1 = l = dlo_jpeg->flow.len > 128 ? 128 : dlo_jpeg->flow.len;

		r = lws_jpeg_emit_next_line(dlo_jpeg->j, &pix, &dlo_jpeg->flow.data, &l, 1);
		if (r >= LWS_SRET_FATAL) {
			lwsl_err("%s: hdr parse failed %d\n", __func__, r);
			return r;
		}

		dlo_jpeg->flow.len -= l1 - l;

		if (lws_jpeg_get_height(dlo_jpeg->j)) {
			lwsl_info("jpeg: w %d, h %d\n",
					lws_jpeg_get_width(dlo_jpeg->j),
					lws_jpeg_get_height(dlo_jpeg->j));

			return LWS_SRET_OK;
		}
	}

	return LWS_SRET_WANT_INPUT;
}

lws_dlo_jpeg_t *
lws_display_dlo_jpeg_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box)
{
	lws_dlo_jpeg_t *dlo_jpeg = lws_zalloc(sizeof(*dlo_jpeg), __func__);

	if (!dlo_jpeg)
		return NULL;

	dlo_jpeg->j = lws_jpeg_new();
	if (!dlo_jpeg->j)
		goto bail;

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
