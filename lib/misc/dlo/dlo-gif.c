/*
 * lws abstract display
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
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
 * Display List Object: GIF
 *
 * The gif decoder issues rows one at a time into the shared row pool, the
 * same scheme as the svg rasterization scratch.  For progressive images the
 * decode is driven straight from the retained asset payload and the payload
 * is freed again as soon as the frame completed.
 *
 * Interlaced rows arrive in interlace order, not top-down order, and a
 * linewise renderer cannot reorder them without retaining the whole frame.
 * Re-decoding the payload from the start for each sweep line would cost
 * O(height) decodes of the whole image, so instead interlaced images are
 * decoded once into a frame of palette indices, as far as the line being
 * rendered needs, and lines are painted from that.  The frame is bounded by
 * GIF_FRAME_MAX_BYTES; bigger interlaced images are not rendered.  They are
 * rare in the wild.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

/* ceiling on the retained asset payload for one gif */

#define GIF_WHOLE_MAX_BYTES	(16 * 1024 * 1024)

/* ceiling on the decoded frame kept for an interlaced gif (2048 x 2048) */

#define GIF_FRAME_MAX_BYTES	(4 * 1024 * 1024)

void
lws_display_dlo_gif_destroy(struct lws_dlo *dlo)
{
	lws_dlo_gif_t *dlo_gif = lws_container_of(dlo, lws_dlo_gif_t, dlo);

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	if (dlo_gif->flow.h)
		lws_ss_destroy(&dlo_gif->flow.h);
#endif
	lws_buflist_destroy_all_segments(&dlo_gif->flow.bl);

	if (dlo_gif->gif)
		lws_gif_free(&dlo_gif->gif);

	lws_free(dlo_gif->whole);
	dlo_gif->whole = NULL;
	lws_free(dlo_gif->frame);
	dlo_gif->frame = NULL;
	dlo_gif->frame_have = NULL;
}

int
lws_display_dlo_gif_rx(lws_dlo_gif_t *dlo_gif, const uint8_t *buf, size_t len)
{
	if (dlo_gif->whole_done || !len)
		return 0;

	if (dlo_gif->whole_len + len > GIF_WHOLE_MAX_BYTES)
		return 1;

	if (dlo_gif->whole_len + len > dlo_gif->whole_size) {
		size_t ns = dlo_gif->whole_size ? dlo_gif->whole_size : 1024;
		uint8_t *n;

		while (ns < dlo_gif->whole_len + len)
			ns *= 2;

		n = (uint8_t *)lws_realloc(dlo_gif->whole, ns, __func__);
		if (!n)
			return 1;

		dlo_gif->whole = n;
		dlo_gif->whole_size = ns;
	}

	memcpy(dlo_gif->whole + dlo_gif->whole_len, buf, len);
	dlo_gif->whole_len += len;

	return 0;
}

/*
 * The payload is no longer needed: release it and ignore any further rx
 * on this asset
 */

static void
gif_payload_release(lws_dlo_gif_t *dlo_gif)
{
	if (!dlo_gif->whole_done) {
		lws_free_set_NULL(dlo_gif->whole);
		dlo_gif->whole_len = 0;
		dlo_gif->whole_size = 0;
		dlo_gif->pos = 0;
		dlo_gif->whole_done = 1;
	}
}

/*
 * Expand the row's palette indices into the composition line.  The source
 * row is logical-screen-wide, so the dlo box maps the screen rectangle.
 */

static lws_stateful_ret_t
gif_paint_row(struct lws_display_render_state *rs, lws_dlo_gif_t *dlo_gif,
	      lws_fx_t *ax, lws_fx_t *t, int s, int e, const uint8_t *pix)
{
	const uint8_t *pal = lws_gif_get_palette(dlo_gif->gif);
	unsigned int pal_count = lws_gif_get_palette_count(dlo_gif->gif);
	int trans = lws_gif_get_transparent_index(dlo_gif->gif);
	unsigned int iw = lws_gif_get_width(dlo_gif->gif);
	lws_display_colour_t pc;

	pix += s - ax->whole;

	while (s < e && s >= ax->whole && s < lws_fx_roundup(t) &&
	       (unsigned int)(s - ax->whole) < iw) {
		uint8_t idx = *pix++;
		uint8_t a = idx == trans ? 0 : 0xff;

		if (idx < pal_count)
			pc = LWSDC_RGBA(pal[idx * 3], pal[(idx * 3) + 1],
					pal[(idx * 3) + 2], a);
		else
			pc = LWSDC_RGBA(0, 0, 0, a);

		lws_surface_set_px(rs->ic, rs->line, s, &pc);

		s++;
	}

	return LWS_SRET_OK;
}

/*
 * Re-decode the retained payload from the start, discarding rows until the
 * one for the wanted line.  Used to re-target the streaming cursor of a
 * progressive image when it is past the line wanted, eg, the render started
 * again from the top.  Returns LWS_SRET_WANT_OUTPUT with the row at *ppix,
 * LWS_SRET_OK if no such row exists, else LWS_SRET_WANT_INPUT or FATAL.
 */

static lws_stateful_ret_t
gif_retarget_row(lws_dlo_gif_t *dlo_gif, int ty, const uint8_t **ppix)
{
	lws_gif_restart(dlo_gif->gif);
	dlo_gif->pos = 0;

	for (;;) {
		const uint8_t *p = dlo_gif->whole + dlo_gif->pos;
		size_t pl = dlo_gif->whole_len - dlo_gif->pos;
		lws_stateful_ret_t r;
		int py = -1;

		*ppix = NULL;
		r = lws_gif_emit_next_line(dlo_gif->gif, ppix, &py,
					   &p, &pl, 0);
		dlo_gif->pos = (size_t)(p - dlo_gif->whole);

		if (r & LWS_SRET_FATAL)
			return r;

		if (r == LWS_SRET_WANT_OUTPUT) {
			if (py == ty)
				return LWS_SRET_WANT_OUTPUT;
			if (py < ty)
				continue;	/* a row above the wanted line */
			return LWS_SRET_OK;	/* this line is not covered */
		}

		return r;	/* LWS_SRET_OK (no more rows) or WANT_INPUT */
	}
}

/*
 * Interlaced: decode the payload into the frame until row ty is in it, or the
 * frame or the payload so far ends.  The decode is only ever done once: the
 * frame keeps every row it reached.  Returns LWS_SRET_WANT_OUTPUT with the
 * row at *ppix, LWS_SRET_OK if the row will never exist, else
 * LWS_SRET_WANT_INPUT or FATAL.
 */

static lws_stateful_ret_t
gif_frame_row(lws_dlo_gif_t *dlo_gif, int ty, const uint8_t **ppix)
{
	size_t sw = lws_gif_get_width(dlo_gif->gif),
	       sh = lws_gif_get_height(dlo_gif->gif);
	lws_stateful_ret_t r;

	if (ty < 0 || (size_t)ty >= sh)
		return LWS_SRET_OK;

	if (!dlo_gif->frame) {
		if (dlo_gif->whole_done)
			/* the payload is gone, eg we gave up on it */
			return LWS_SRET_OK;

		if (sw * sh > GIF_FRAME_MAX_BYTES) {
			lwsl_notice("%s: %s: interlaced %ux%u too large\n",
				    __func__, dlo_gif->name, (unsigned int)sw,
				    (unsigned int)sh);

			return LWS_SRET_FATAL;
		}

		dlo_gif->frame = (uint8_t *)lws_zalloc(sw * sh + (sh + 7) / 8,
						       __func__);
		if (!dlo_gif->frame)
			return LWS_SRET_FATAL;

		dlo_gif->frame_have = dlo_gif->frame + sw * sh;

		/*
		 * Rows we already issued from a streaming decode, before we
		 * knew it was interlaced, are not in the frame: start again
		 */

		lws_gif_restart(dlo_gif->gif);
		dlo_gif->pos = 0;
	}

	while (!(dlo_gif->frame_have[ty >> 3] & (1 << (ty & 7)))) {
		const uint8_t *p, *pix = NULL;
		size_t pl;
		int py = -1;

		if (dlo_gif->whole_done)
			/* the frame is complete and the row isn't in it */
			return LWS_SRET_OK;

		p = dlo_gif->whole + dlo_gif->pos;
		pl = dlo_gif->whole_len - dlo_gif->pos;

		r = lws_gif_emit_next_line(dlo_gif->gif, &pix, &py, &p, &pl, 0);
		dlo_gif->pos = (size_t)(p - dlo_gif->whole);

		if (r & LWS_SRET_FATAL)
			return r;

		if (r == LWS_SRET_WANT_OUTPUT) {
			/*
			 * The logical screen dimensions parse again on the
			 * restart: they are the same input
			 */
			if (pix && py >= 0 && (size_t)py < sh &&
			    lws_gif_get_width(dlo_gif->gif) == sw) {
				memcpy(dlo_gif->frame + (size_t)py * sw, pix,
				       sw);
				dlo_gif->frame_have[py >> 3] |=
						(uint8_t)(1 << (py & 7));
			}
			continue;
		}

		if (r == LWS_SRET_OK) {
			/* the frame is complete: the payload is not needed */

			gif_payload_release(dlo_gif);
			continue;
		}

		return r; /* LWS_SRET_WANT_INPUT */
	}

	*ppix = dlo_gif->frame + (size_t)ty * sw;

	return LWS_SRET_WANT_OUTPUT;
}

lws_stateful_ret_t
lws_display_render_gif(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_gif_t *dlo_gif = lws_container_of(dlo, lws_dlo_gif_t, dlo);
	lws_fx_t ax, ay, t, t1;
	lws_stateful_ret_t r;
	const uint8_t *pix;
	int s, e, ty, py;

	if (!lws_gif_get_height(dlo_gif->gif)) {
		if (dlo_gif->flow.state == LWSDLOFLOW_STATE_READ_COMPLETED ||
		    rs->html == 2)
			return LWS_SRET_OK;

		lwsl_notice("%s: gif %s does not have dimensions yet\n",
			    __func__, dlo_gif->name);

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

	if (rs->curr < lws_fx_roundup(&ay))
		return LWS_SRET_OK;	/* the sweep is above us */

	if (rs->curr - lws_fx_roundup(&ay) >=
			(int)lws_gif_get_height(dlo_gif->gif))
		return LWS_SRET_OK;	/* rows are 0 .. height - 1 */

	if (s < 0)
		s = 0;
	if (s > rs->ic->wh_px[0].whole)
		return LWS_SRET_OK; /* off to the right */
	if (e > rs->ic->wh_px[0].whole)
		e = rs->ic->wh_px[0].whole - 1;
	if (e <= 0)
		return LWS_SRET_OK; /* off to the left */

	/* the row of the image this sweep line owes */

	ty = rs->curr - lws_fx_roundup(&ay);

	if (dlo_gif->frame || lws_gif_get_interlaced(dlo_gif->gif))
		/* rows only exist in interlace order */
		goto interlaced;

	/* progressive: continue the persistent decode cursor */

	for (;;) {
		const uint8_t *p = dlo_gif->whole + dlo_gif->pos;
		size_t pl = dlo_gif->whole_len - dlo_gif->pos;

		pix = NULL;
		py = -1;
		r = lws_gif_emit_next_line(dlo_gif->gif, &pix, &py,
					   &p, &pl, rs->html == 1);
		dlo_gif->pos = (size_t)(p - dlo_gif->whole);

		if (r & LWS_SRET_FATAL)
			goto fatal;

		if (r == LWS_SRET_WANT_OUTPUT) {
			if (lws_gif_get_interlaced(dlo_gif->gif))
				/* we only learned it now */
				goto interlaced;
			if (py == ty)
				return gif_paint_row(rs, dlo_gif, &ax, &t,
						     s, e, pix);
			if (py < ty) {
				/* this line re-rendered after we painted */

				continue;
			}

			/*
			 * The decoded row is for a line below us: screen
			 * rows above the image rectangle are never issued,
			 * so re-target the retained payload at this line
			 */

			goto retarget;
		}

		if (r == LWS_SRET_OK) {
			/* the frame completed: the payload is not needed */

			gif_payload_release(dlo_gif);

			return LWS_SRET_OK;
		}

		/* LWS_SRET_WANT_INPUT */

		if (dlo_gif->flow.state == LWSDLOFLOW_STATE_READ_COMPLETED) {
			/* truncated payload: render is done with it */

			gif_payload_release(dlo_gif);

			return LWS_SRET_OK;
		}

		return LWS_SRET_WANT_INPUT;
	}

retarget:
	r = gif_retarget_row(dlo_gif, ty, &pix);
	if (r & LWS_SRET_FATAL)
		goto fatal;

	if (r == LWS_SRET_WANT_OUTPUT)
		return gif_paint_row(rs, dlo_gif, &ax, &t, s, e, pix);

	if (r == LWS_SRET_WANT_INPUT &&
	    dlo_gif->flow.state != LWSDLOFLOW_STATE_READ_COMPLETED)
		return LWS_SRET_WANT_INPUT;

	return LWS_SRET_OK;

interlaced:
	r = gif_frame_row(dlo_gif, ty, &pix);
	if (r & LWS_SRET_FATAL)
		goto fatal;

	if (r == LWS_SRET_WANT_OUTPUT)
		return gif_paint_row(rs, dlo_gif, &ax, &t, s, e, pix);

	if (r == LWS_SRET_WANT_INPUT &&
	    dlo_gif->flow.state != LWSDLOFLOW_STATE_READ_COMPLETED)
		return LWS_SRET_WANT_INPUT;

	return LWS_SRET_OK;

fatal:
	/*
	 * The decode failed, eg, the payload was corrupt... no row is ever
	 * coming from this image.  Give up on the rest of it rather than
	 * take the whole render hostage
	 */

	dlo_gif->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
	gif_payload_release(dlo_gif);
	lwsl_notice("%s: %s: decode failed\n", __func__, dlo_gif->name);

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_display_dlo_gif_metadata_scan(lws_dlo_gif_t *dlo_gif)
{
	lws_stateful_ret_t r;

	/*
	 * Consume what has arrived, stopping at the end of the logical
	 * screen descriptor so image dimensions are available before the
	 * whole asset is necessarily present.  Chunks are kept small enough
	 * that decoded rows cannot be produced early.
	 */

	while (!lws_gif_get_height(dlo_gif->gif) &&
	       dlo_gif->pos < dlo_gif->whole_len) {
		const uint8_t *p = dlo_gif->whole + dlo_gif->pos;
		size_t l = dlo_gif->whole_len - dlo_gif->pos;
		const uint8_t *pix;

		if (l > 33)
			l = 33;

		r = lws_gif_emit_next_line(dlo_gif->gif, &pix, NULL,
					   &p, &l, 1);
		dlo_gif->pos = (size_t)(p - dlo_gif->whole);

		if (r & LWS_SRET_FATAL) {
			lwsl_err("%s: %s: hdr parse failed\n", __func__,
					dlo_gif->name);
			return r;
		}

		if (lws_gif_get_height(dlo_gif->gif)) {
			lwsl_info("gif: w %d, h %d\n",
					(int)lws_gif_get_width(dlo_gif->gif),
					(int)lws_gif_get_height(dlo_gif->gif));
			return LWS_SRET_OK;
		}
	}

	return LWS_SRET_WANT_INPUT;
}

lws_dlo_gif_t *
lws_display_dlo_gif_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box, const char *name, size_t len)
{
	lws_dlo_gif_t *dlo_gif = (lws_dlo_gif_t *)lws_zalloc(sizeof(*dlo_gif), __func__);

	if (!dlo_gif)
		return NULL;

	dlo_gif->gif = lws_gif_new();
	if (!dlo_gif->gif)
		goto bail;

	lws_strnncpy(dlo_gif->name, name, len, sizeof(dlo_gif->name));
	dlo_gif->dlo.box = *box;
	dlo_gif->dlo.render = lws_display_render_gif;
	dlo_gif->dlo._destroy = lws_display_dlo_gif_destroy;

	lws_display_dlo_add(dl, dlo_parent, &dlo_gif->dlo);

	return dlo_gif;

bail:
	if (dlo_gif->gif)
		lws_gif_free(&dlo_gif->gif);
	lws_free(dlo_gif);

	return NULL;
}
