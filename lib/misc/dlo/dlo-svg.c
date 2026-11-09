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
		lws_display_render_set_px(c->rs, c->x + x0, &pc);
		x0++;
	}

	return 0;
}

/*
 * Give back everything the svg holds besides the dlo itself: its stream, any
 * payload not parsed yet, and the scene.  Only one that knows how to fetch
 * itself again is given back.
 */

void
lws_display_dlo_svg_release(lws_dlo_svg_t *dlo_svg)
{
	if (!dlo_svg->rf.url)
		return;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	if (dlo_svg->flow.h)
		lws_ss_destroy(&dlo_svg->flow.h);
#endif
	lws_buflist_destroy_all_segments(&dlo_svg->flow.bl);
	dlo_svg->flow.data = NULL;
	dlo_svg->flow.len = 0;
	dlo_svg->flow.blseglen = 0;
	dlo_svg->flow.state = LWSDLOFLOW_STATE_READ;

	if (dlo_svg->svg)
		lws_svg_free(&dlo_svg->svg);
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

	lws_free_set_NULL(dlo_svg->rf.url);
}

/*
 * The scene object only exists once there is payload for it.  Curves are
 * flattened as they're parsed, so if the box is known, tell it the size we'll
 * render at, so the flattening is no finer than the box can show.
 */

static int
dlo_svg_parser(lws_dlo_svg_t *dlo_svg)
{
	int bw = lws_fx_roundup(&dlo_svg->dlo.box.w),
	    bh = lws_fx_roundup(&dlo_svg->dlo.box.h);

	if (dlo_svg->svg)
		return 0;

	dlo_svg->svg = lws_svg_new();
	if (!dlo_svg->svg)
		return 1;

	if (bw > 0 && bh > 0)
		lws_svg_set_render_size(dlo_svg->svg, (unsigned int)bw,
					(unsigned int)bh);

	return 0;
}

/*
 * Drive the streaming document parse from anything buffered until either the
 * document completes, or we run out and must wait for more rx.  A document
 * truncated by the connection ending is rendered as far as it parsed.
 *
 * Only a stream bringing more is waited for: the html document having
 * completed says nothing about an svg, since a local one is only fetched when
 * the raster reaches it.
 *
 * If there's no heap for the scene object, it returns OK with no scene, and
 * the payload stays buffered for the next try.
 */

static lws_stateful_ret_t
dlo_svg_parse(lws_dlo_svg_t *dlo_svg)
{
	lws_dlo_t *dlo = &dlo_svg->dlo;

	if (dlo_svg->svg && !lws_svg_get_doc_complete(dlo_svg->svg)) {
		int bw = lws_fx_roundup(&dlo->box.w),
		    bh = lws_fx_roundup(&dlo->box.h);

		/* the layout may have sized it since the metadata scan */

		if (bw > 0 && bh > 0)
			lws_svg_set_render_size(dlo_svg->svg, (unsigned int)bw,
						(unsigned int)bh);
	}

	while (!lws_svg_get_doc_complete(dlo_svg->svg)) {
		lws_stateful_ret_t r;

		if (!dlo_svg->flow.len &&
		    (lws_flow_feed(&dlo_svg->flow) || !dlo_svg->flow.len)) {
			if (dlo_svg->flow.h && dlo_svg->flow.state !=
					LWSDLOFLOW_STATE_READ_COMPLETED)
				return LWS_SRET_WANT_INPUT;
			break;	/* truncated document: render the prefix */
		}

		if (dlo_svg_parser(dlo_svg))
			return LWS_SRET_OK;

		r = lws_svg_parse(dlo_svg->svg, &dlo_svg->flow.data,
				  &dlo_svg->flow.len, 0);
		if (r & LWS_SRET_FATAL) {
			dlo_svg->failed = 1;
			return r;
		}
	}

	if (!lws_svg_get_width(dlo_svg->svg) &&
	    dlo_svg->flow.state == LWSDLOFLOW_STATE_READ_COMPLETED)
		/* it came, but never even had a root tag */
		dlo_svg->failed = 1;

	return LWS_SRET_OK;
}

/*
 * What the svg holds is given back once the raster has passed it, unless it's
 * animated on a retained display list: then it's drawn again each time the
 * animation moves on, from the same scene, rather than fetched and parsed
 * again each time
 */

static void
dlo_svg_passed(struct lws_display_render_state *rs, lws_dlo_svg_t *dlo_svg)
{
	if (!rs->retained || !dlo_svg->dlo.flag_animated)
		lws_display_dlo_svg_release(dlo_svg);
}

lws_stateful_ret_t
lws_display_render_svg(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_svg_t *dlo_svg = lws_container_of(dlo, lws_dlo_svg_t, dlo);
	lws_stateful_ret_t r = LWS_SRET_OK;
	lws_fx_t ax, ay, t, t1;
	lws_svg_render_t ri;
	svg_span_ctx_t sc;
	int s, e, top, end;

	lws_fx_add(&ax, &rs->st[rs->sp].co.x, &dlo->box.x);
	lws_fx_add(&t, &ax, &dlo->box.w);
	lws_fx_add(&ay, &rs->st[rs->sp].co.y, &dlo->box.y);
	lws_fx_add(&t1, &ay, &dlo->box.h);

	top = lws_fx_roundup(&ay);
	end = lws_fx_roundup(&t1); /* one past its last line */

	if (rs->curr >= end) {
		/* the raster is past it, it has nothing more to do */
		dlo_svg_passed(rs, dlo_svg);

		return LWS_SRET_OK;
	}

	if (end <= top || rs->curr < top)
		return LWS_SRET_OK;

	s = ax.whole;
	e = lws_fx_roundup(&t);

	if (s < 0)
		s = 0;
	if (e > rs->ic->wh_px[0].whole)
		e = rs->ic->wh_px[0].whole;

	/*
	 * Nothing of it shows on this line: off to the right, or clipped
	 * away by an ancestor's overflow: hidden (eg, a window onto a list
	 * of icons).  The scene renders any line in any order, so unlike the
	 * raster decoders, there is no place to keep by being called...
	 * there's no reason to fetch or parse anything for it yet
	 */

	if (s > rs->ic->wh_px[0].whole || e - s <= 0 ||
	    (s > rs->clip_x0 ? s : rs->clip_x0) >=
				(e < rs->clip_x1 ? e : rs->clip_x1) ||
	    dlo_svg->failed)
		goto done;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS) && \
    defined(LWS_WITH_LHP)
	/*
	 * Nothing is coming and nothing is here: it was never fetched (a
	 * local file whose size the document gave), or it was given back
	 * after it was last rendered.  Fetch it now... a local file usually
	 * arrives entirely inside the connect.
	 */

	if (dlo_svg->rf.url && !dlo_svg->flow.h && !dlo_svg->svg &&
	    dlo_svg->flow.state != LWSDLOFLOW_STATE_READ_COMPLETED &&
	    !lws_buflist_total_len(&dlo_svg->flow.bl)) {
		int n = lws_dlo_ss_refetch(&dlo_svg->dlo, &dlo_svg->rf,
					   dlo_svg->flow.window,
					   LWSDLOSS_TYPE_SVG);

		if (n < 0)
			/* there's no getting it, eg, no such file */
			dlo_svg->failed = 1;
		if (n)
			/*
			 * ... or it couldn't even start, eg, no heap for
			 * the stream: try again on its next line
			 */
			goto done;
	}
#endif

	r = dlo_svg_parse(dlo_svg);
	if (r)
		return r;
	if (!lws_svg_get_width(dlo_svg->svg))
		/* nothing to render, and nothing more coming */
		goto done;

	/* drawn at another time, it may look different */
	dlo->flag_animated = !!lws_svg_get_animated(dlo_svg->svg);

	ri.w = e - s;
	ri.h = end - top;
	ri.aa = 1;	/* area-antialiased coverage through the line alpha */

	/* animations are drawn as they are at the render's time */
	lws_svg_set_time(dlo_svg->svg, rs->anim_t);

	sc.rs = rs;
	sc.x = s;

	r = lws_svg_render_line(dlo_svg->svg, &ri, rs->curr - top,
				svg_span_cb, &sc);

done:
	if (!r && rs->curr + 1 >= end)
		/* that was its last line */
		dlo_svg_passed(rs, dlo_svg);

	return r;
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

	if (dlo_svg_parser(dlo_svg))
		return LWS_SRET_FATAL;

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

#if defined(LWS_WITH_FOOTPRINT)
static size_t
lws_display_dlo_svg_heap(struct lws_dlo *dlo)
{
	lws_dlo_svg_t *dlo_svg = lws_container_of(dlo, lws_dlo_svg_t, dlo);

	return lws_buflist_total_len(&dlo_svg->flow.bl) +
	       lws_svg_heap(dlo_svg->svg) +
	       (dlo_svg->rf.url ? strlen(dlo_svg->rf.url) + 1 : 0);
}
#endif

lws_dlo_svg_t *
lws_display_dlo_svg_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box, const char *name, size_t len)
{
	lws_dlo_svg_t *dlo_svg = lws_zalloc(sizeof(*dlo_svg), __func__);

	if (!dlo_svg)
		return NULL;

	/* the scene object is created when its payload starts to arrive */

	lws_strnncpy(dlo_svg->name, name, len, sizeof(dlo_svg->name));
	dlo_svg->dlo.box = *box;
	dlo_svg->dlo.render = lws_display_render_svg;
	dlo_svg->dlo._destroy = lws_display_dlo_svg_destroy;
#if defined(LWS_WITH_FOOTPRINT)
	dlo_svg->dlo._heap = lws_display_dlo_svg_heap;
	dlo_svg->dlo.fp_name = dlo_svg->name;
#endif

	lws_display_dlo_add(dl, dlo_parent, &dlo_svg->dlo);

	return dlo_svg;
}
