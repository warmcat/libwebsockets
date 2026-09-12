/*
 * lws svg
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
 * Stateful, linewise SVG renderer for the fill-only subset of SVG.
 *
 * The document is parsed streaming (the parser is not sensitive to the input
 * chunk sizes) into a retained vector scene in a single lwsac.  Curves are
 * flattened adaptively at parse time, to a tolerance derived from the
 * viewBox size.  Individual raster lines are then produced on demand by
 * scanline intersection against the retained geometry, so any line can be
 * rendered at any time, in any order.
 *
 * The supported subset is solid fills with nonzero or evenodd winding,
 * transforms, viewBox / preserveAspectRatio mapping, group fill property
 * inheritance and opacity.  Strokes, gradients, text and filters are not
 * rendered in this phase of the work.
 */

typedef struct lws_svg lws_svg_t;

/* rgba packing is r in bits 0-7, g in 8-15, b in 16-23, alpha in 24-31, so it
 * matches lws_display_colour_t layout */

#define LWS_SVG_RGBA(_r, _g, _b, _a) (uint32_t)( \
		((uint32_t)(_r) & 0xff) | \
		(((uint32_t)(_g) & 0xff) << 8) | \
		(((uint32_t)(_b) & 0xff) << 16) | \
		(((uint32_t)(_a) & 0xff) << 24))

#define LWS_SVG_ALPHA(_c)	((uint32_t)(((_c) >> 24) & 0xff))

/*
 * Render mapping policy from preserveAspectRatio, only meaningful when a
 * viewBox exists
 */

typedef enum {
	LWS_SVG_PAR_DEFAULT,	/* xMidYMid meet */
	LWS_SVG_PAR_NONE,	/* stretch to fill */
} lws_svg_par_t;

/**
 * lws_svg_new() - create an SVG scene parse object
 *
 * Returns a new SVG scene object which should be destroyed with
 * lws_svg_free(), or NULL if OOM.
 */
LWS_VISIBLE LWS_EXTERN lws_svg_t *
lws_svg_new(void);

/**
 * lws_svg_free() - destroy an SVG scene object
 *
 * \param svg: pointer to the scene object pointer to destroy and set NULL
 *
 * This also frees the retained scene and all sub-allocations.
 */
LWS_VISIBLE LWS_EXTERN void
lws_svg_free(lws_svg_t **svg);

/**
 * lws_svg_parse() - parse streaming SVG document input
 *
 * \param svg: the SVG scene object
 * \param buf: pointer to a const uint8_t array of SVG input
 * \param len: pointer to the count of bytes available at *buf
 * \param hold_at_metadata: nonzero to stop consuming once the root <svg> tag
 *				has been parsed
 *
 * Makes SVG input available to the scene parser so it can build the retained
 * vector scene.  If the call consumed any input, *buf and *len are adjusted
 * accordingly.  The parser is stateful so it is not sensitive to the input
 * chunk sizes it is fed.
 *
 * If \p hold_at_metadata is set, parsing stops at the end of the root <svg>
 * open tag even if further input is available at *buf, so image dimensions
 * can be discovered before committing to retaining the whole document.
 *
 * Returns LWS_SRET_OK if the document has completely parsed (ie, the root
 * element has closed), or, when \p hold_at_metadata is set, as soon as the
 * root tag parsed; LWS_SRET_WANT_INPUT if the input so far was consumed and
 * more is needed to progress; or a return with LWS_SRET_FATAL set if the
 * document is too broken to process.  When LWS_SRET_OK is returned for the
 * full document case, the retained scene is complete and ready for rendering;
 * if the input ends without closing the root element, whatever parsed so far
 * is still renderable.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_svg_parse(lws_svg_t *svg, const uint8_t **buf, size_t *len,
	      char hold_at_metadata);

/**
 * lws_svg_get_width() - get intrinsic document width in px
 *
 * \param svg: the SVG scene object
 *
 * Returns the intrinsic document width in px once the root tag has been
 * parsed: the width attribute if it is in px, otherwise the viewBox width if
 * present, otherwise the CSS default replaced element width.  Returns 0 if
 * the root tag has not been parsed yet.
 */
LWS_VISIBLE LWS_EXTERN unsigned int
lws_svg_get_width(const lws_svg_t *svg);

/**
 * lws_svg_get_height() - get intrinsic document height in px
 *
 * \param svg: the SVG scene object
 *
 * As lws_svg_get_width(), but for the document height.
 */
LWS_VISIBLE LWS_EXTERN unsigned int
lws_svg_get_height(const lws_svg_t *svg);

/**
 * lws_svg_get_doc_complete() - has the whole document been parsed?
 *
 * \param svg: the SVG scene object
 *
 * Returns nonzero if the root element has closed (or an unrecoverable
 * truncated-document condition was reached), so the retained scene will not
 * change any further.
 */
LWS_VISIBLE LWS_EXTERN char
lws_svg_get_doc_complete(const lws_svg_t *svg);

/*
 * Span callback for rendered lines.  Filled spans are delivered in ascending
 * x with \p x0 the first covered pixel and \p x1 one past the last covered
 * pixel (so the span is half-open [x0, x1)).  \p rgba is the span fill colour
 * with premultiplied-opacity alpha in the top byte.  Returning nonzero stops
 * the line rendering, which then returns LWS_SRET_OK.
 */
typedef int (*lws_svg_span_cb_t)(void *user, int x0, int x1, uint32_t rgba);

typedef struct lws_svg_render {
	int w;			/* output raster width in px */
	int h;			/* output raster height in px */
} lws_svg_render_t;

/**
 * lws_svg_render_line() - render a single raster line of the scene
 *
 * \param svg: the SVG scene object
 * \param ri: render mapping info (output raster size)
 * \param y: the output line to render, 0 .. ri->h - 1
 * \param cb: callback to receive filled spans on the line
 * \param user: opaque user pointer passed to the callback
 *
 * Maps the retained user-space geometry into a ri->w x ri->h px raster
 * according to the document's viewBox and preserveAspectRatio policy, and
 * renders output line \p y of it by scanline intersection of the flattened
 * geometry, delivering the filled spans via \p cb in document order.  Sample
 * points are at pixel centres, so coverage is binary; antialiased rendering
 * can be layered on top of this later by aggregating additional subsampled
 * lines.
 *
 * Lines can be rendered in any order and repeatedly; the scene is not
 * modified except for internal scratch reallocation.  Calls on the same
 * scene object are not reentrant against each other.
 *
 * Returns LWS_SRET_OK, or LWS_SRET_FATAL if an internal allocation failed.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_svg_render_line(lws_svg_t *svg, const lws_svg_render_t *ri, int y,
		    lws_svg_span_cb_t cb, void *user);
