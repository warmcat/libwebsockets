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
 * Display List Object: SVG
 *
 * Unlike the raster image formats, SVG scene geometry may be referenced
 * before it is defined (defs / use, gradients), so the whole document must
 * have parsed before any line can be rendered.  The streaming parse is
 * driven from the flow buflist here until the document completes; the
 * retained scene then renders any requested line directly, in any order.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

typedef struct {
	struct lws_display_render_state *rs;
	int				x;   /* device x of image col 0 */
} svg_span_ctx_t;

static int
svg_span_cb(void *user, int x0, int x1, uint32_t rgba)
{
	svg_span_ctx_t *c = (svg_span_ctx_t *)user;
	lws_display_colour_t pc = rgba;	/* same packing as LWSDC_RGBA */

	while (x0 < x1) {
		lws_surface_set_px(c->rs->ic, c->rs->line, c->x + x0, &pc);
		x0++;
	}

	return 0;
}

void
lws_display_dlo_svg_destroy(struct lws_dlo *dlo)
{
	lws_dlo_svg_t *dlo_svg = lws_container_of(dlo, lws_dlo_svg_t, dlo);

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	if (dlo_svg->flow.h)
		lws_ss_destroy(&dlo_svg->flow.h);
#endif
	lws_buflist_destroy_all_segments(&dlo_svg->flow.bl);

	if (dlo_svg->svg)
		lws_svg_free(&dlo_svg->svg);
}

lws_stateful_ret_t
lws_display_render_svg(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_svg_t *dlo_svg = lws_container_of(dlo, lws_dlo_svg_t, dlo);
	lws_fx_t ax, ay, t, t1;
	lws_svg_render_t ri;
	svg_span_ctx_t sc;
	int s, e, h;

	/*
	 * Drive the streaming document parse from anything buffered until
	 * either the document completes or we run out and must wait for
	 * more rx.  A document truncated by the connection ending is
	 * rendered as far as it parsed.
	 */

	while (!lws_svg_get_doc_complete(dlo_svg->svg)) {
		lws_stateful_ret_t r;

		if (!dlo_svg->flow.len &&
		    (lws_flow_feed(&dlo_svg->flow) || !dlo_svg->flow.len)) {
			if (dlo_svg->flow.state !=
					LWSDLOFLOW_STATE_READ_COMPLETED &&
			    rs->html != 2)
				return LWS_SRET_WANT_INPUT;
			break;	/* truncated document: render the prefix */
		}

		r = lws_svg_parse(dlo_svg->svg, &dlo_svg->flow.data,
				  &dlo_svg->flow.len, 0);
		if (r & LWS_SRET_FATAL)
			return r;
	}

	if (!lws_svg_get_width(dlo_svg->svg)) {
		/* never even parsed the root tag */

		if (dlo_svg->flow.state == LWSDLOFLOW_STATE_READ_COMPLETED ||
		    rs->html == 2)
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

	/* the line's position inside the image */

	h = lws_fx_roundup(&t1) - lws_fx_roundup(&ay);
	if (h <= 0)
		return LWS_SRET_OK;

	if (rs->curr < lws_fx_roundup(&ay) || rs->curr >= h + lws_fx_roundup(&ay))
		return LWS_SRET_OK;

	if (s < 0)
		s = 0;
	if (s > rs->ic->wh_px[0].whole)
		return LWS_SRET_OK; /* off to the right */
	if (e > rs->ic->wh_px[0].whole)
		e = rs->ic->wh_px[0].whole;

	if (e - s <= 0)
		return LWS_SRET_OK;

	ri.w = e - s;
	ri.h = h;
	ri.aa = 1;	/* area-antialiased coverage through the line alpha */

	sc.rs = rs;
	sc.x = s;

	return lws_svg_render_line(dlo_svg->svg, &ri,
				   rs->curr - lws_fx_roundup(&ay),
				   svg_span_cb, &sc);
}

lws_stateful_ret_t
lws_display_dlo_svg_metadata_scan(lws_dlo_svg_t *dlo_svg)
{
	lws_stateful_ret_t r;

	/*
	 * Consume whatever is buffered, stopping at the end of the root
	 * tag so image dimensions are available before the whole document
	 * is necessarily present.
	 */

	while (!lws_svg_get_width(dlo_svg->svg)) {
		if (lws_flow_feed(&dlo_svg->flow) || !dlo_svg->flow.len)
			return LWS_SRET_WANT_INPUT;

		r = lws_svg_parse(dlo_svg->svg, &dlo_svg->flow.data,
				  &dlo_svg->flow.len, 1);
		if (r & LWS_SRET_FATAL) {
			lwsl_err("%s: %s: hdr parse failed\n", __func__,
					dlo_svg->name);
			return r;
		}
	}

	lws_flow_req(&dlo_svg->flow);

	lwsl_info("svg: w %d, h %d\n", lws_svg_get_width(dlo_svg->svg),
					  lws_svg_get_height(dlo_svg->svg));

	return LWS_SRET_OK;
}

lws_dlo_svg_t *
lws_display_dlo_svg_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box, const char *name, size_t len)
{
	lws_dlo_svg_t *dlo_svg = lws_zalloc(sizeof(*dlo_svg), __func__);

	if (!dlo_svg)
		return NULL;

	dlo_svg->svg = lws_svg_new();
	if (!dlo_svg->svg)
		goto bail;

	lws_strnncpy(dlo_svg->name, name, len, sizeof(dlo_svg->name));
	dlo_svg->dlo.box = *box;
	dlo_svg->dlo.render = lws_display_render_svg;
	dlo_svg->dlo._destroy = lws_display_dlo_svg_destroy;

	lws_display_dlo_add(dl, dlo_parent, &dlo_svg->dlo);

	return dlo_svg;

bail:
	if (dlo_svg->svg)
		lws_svg_free(&dlo_svg->svg);
	lws_free(dlo_svg);

	return NULL;
}
