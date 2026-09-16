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
	if (dlo_png->flow.h)
		lws_ss_destroy(&dlo_png->flow.h);
#endif
	lws_buflist_destroy_all_segments(&dlo_png->flow.bl);
	lws_free_set_NULL(dlo_png->row);

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
	lws_upng_format_t fmt;
	const uint8_t *pix;
	uint32_t wanted;
	unsigned int bypp;
	int s, e, iw, ih, bw, bh, wl;

	if (!lws_upng_get_height(dlo_png->png)) {
		if (dlo_png->flow.state == LWSDLOFLOW_STATE_READ_COMPLETED)
			return LWS_SRET_OK;

		lwsl_notice("%s: png %s does not have dimensions yet\n", __func__, dlo_png->name);
		if (rs->html == 2)
			return LWS_SRET_OK;

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

	/*
	 * The image is drawn scaled to its box (nearest neighbour): a css
	 * height on an <img> or an intrinsic size that isn't the box's.  A
	 * box side of 0 means the intrinsic size
	 */

	iw = (int)lws_upng_get_width(dlo_png->png);
	ih = (int)lws_upng_get_height(dlo_png->png);
	bw = dlo->box.w.whole > 0 ? dlo->box.w.whole : iw;
	bh = dlo->box.h.whole > 0 ? dlo->box.h.whole : ih;

	wl = rs->curr - lws_fx_roundup(&ay);
	if (wl >= bh)
		return LWS_SRET_OK;

	if (s < 0)
		s = 0;
	if (s > rs->ic->wh_px[0].whole)
		return LWS_SRET_OK; /* off to the right */
	if (e > rs->ic->wh_px[0].whole)
		e = rs->ic->wh_px[0].whole - 1;
	if (e <= 0)
		return LWS_SRET_OK; /* off to the left */

	/*
	 * The image row this sweep line wants, through the vertical scale:
	 * a re-scanned viewport can start partway down an image, so discard
	 * decoded rows until we reach it, exactly as the gif renderer
	 * retargets.  The walk enters renderers from a line above a
	 * fractional dlo top: a negative wl means "not reached the top row
	 * yet", and must clamp to 0 rather than wrap
	 */

	wanted = wl > 0 ? (uint32_t)(((int64_t)wl * ih) / bh) : 0;
	if (wanted >= (uint32_t)ih)
		wanted = (uint32_t)ih - 1;

	fmt = lws_upng_get_format(dlo_png->png);
	bypp = lws_upng_get_pixelsize(dlo_png->png) / 8;

	/*
	 * Scaled up, the same image row serves several lines: the decoder
	 * can only go forwards, so it is the copy of the last row issued
	 * that is drawn again
	 */

	if (dlo_png->emitted && wanted < dlo_png->emitted && dlo_png->row) {
		pix = dlo_png->row;
		goto draw;
	}

	do {
		/*
		 * Move on to the next buflist segment if the decoder used up
		 * the current one.  We still call the decoder with no input:
		 * it may have rows already decoded in its output ring
		 */

		lws_flow_feed(&dlo_png->flow);

		pix = NULL;
		r = lws_upng_emit_next_line(dlo_png->png, &pix, &dlo_png->flow.data,
					    &dlo_png->flow.len, rs->html == 1);

		if (r & LWS_SRET_NO_FURTHER_IN)
			dlo_png->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;

		if (r & LWS_SRET_FATAL) {
			/*
			 * The decode has failed, eg, the payload was cut
			 * short... no line is ever coming from this image.
			 * Give up on the rest of it rather than take the
			 * whole render hostage
			 */
			dlo_png->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
			lwsl_notice("%s: %s: decode failed\n", __func__,
				    dlo_png->name);
			return LWS_SRET_OK;
		}

		if (r & LWS_SRET_YIELD)
			return r;

		if (pix) {
			/* a row was issued: count it */
			dlo_png->emitted++;

			if (dlo_png->emitted > wanted)
				break;

			/*
			 * Not the row this sweep line wants yet: discard it.
			 * Keep the flow control credit topped up while we
			 * churn through the rows above the viewport
			 */

			lws_flow_req(&dlo_png->flow);
			continue;
		}

		if (r & LWS_SRET_WANT_INPUT) {
			/*
			 * The decoder drained this segment without completing
			 * a row.  Advance to the next segment if there is one
			 * (and ask the peer for more), else we have to wait...
			 * unless the payload is over, in which case what we
			 * have is all there will be: don't wait for more that
			 * is never coming
			 */

			lws_flow_req(&dlo_png->flow);
			if (dlo_png->flow.len)
				continue;

			if (dlo_png->flow.state == LWSDLOFLOW_STATE_READ_COMPLETED)
				return LWS_SRET_OK;

			return LWS_SRET_WANT_INPUT;
		}

		if (r == LWS_SRET_OK)
			/*
			 * No row and nothing pending: the decoder is past the
			 * last row.  Nothing more is coming from this image
			 */
			return LWS_SRET_OK;

		/* the decoder made progress (eg, WANT_OUTPUT) but has no
		 * complete row yet: go around */

	} while (1);

	/* keep the row, in case the next line wants it again */

	if (!dlo_png->row || dlo_png->row_len != (uint32_t)iw * bypp) {
		lws_free(dlo_png->row);
		dlo_png->row_len = (uint32_t)iw * bypp;
		dlo_png->row = lws_malloc(dlo_png->row_len, __func__);
	}
	if (dlo_png->row)
		memcpy(dlo_png->row, pix, dlo_png->row_len);

draw:
	if (s < ax.whole)
		s = ax.whole;

	while (s < e && s < ax.whole + bw) {
		const uint8_t *px = pix + ((uint32_t)(((int64_t)(s - ax.whole) *
						      iw) / bw)) * bypp;

		/*
		 * The decoder emits bypp bytes per pixel according to the PNG
		 * colour type, and the line pair buffer is only width * bypp
		 * long.  So we must decompose according to the actual format;
		 * blindly taking px[0..3] overran the allocation by up to 3
		 * bytes on the last pixel of every odd scanline.
		 */

		switch (fmt) {
		case LWS_UPNG_RGBA8:
			pc = LWSDC_RGBA(px[0], px[1], px[2], px[3]);
			break;
		case LWS_UPNG_RGBA16:
			pc = LWSDC_RGBA(px[0], px[2], px[4], px[6]);
			break;
		case LWS_UPNG_RGB8:
			pc = LWSDC_RGBA(px[0], px[1], px[2], 0xff);
			break;
		case LWS_UPNG_RGB16:
			pc = LWSDC_RGBA(px[0], px[2], px[4], 0xff);
			break;
		case LWS_UPNG_LUMINANCE_ALPHA8:
			pc = LWSDC_RGBA(px[0], px[0], px[0], px[1]);
			break;
		default:
			/* the rest are all 1 byte per pixel of luminance */
			pc = LWSDC_RGBA(px[0], px[0], px[0], 0xff);
			break;
		}

		lws_surface_set_px(rs->ic, rs->line, s, &pc);

		s++;
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
			lwsl_err("%s: %s: hdr parse failed\n", __func__, dlo_png->name);
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
			lws_box_t *box, const char *name, size_t len)
{
	lws_dlo_png_t *dlo_png = lws_zalloc(sizeof(*dlo_png), __func__);

	if (!dlo_png)
		return NULL;

	dlo_png->png = lws_upng_new();
	if (!dlo_png->png)
		goto bail;


	lws_strnncpy(dlo_png->name, name, len, sizeof(dlo_png->name));
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
