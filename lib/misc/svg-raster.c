/*
 * lws svg rasterization
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
 * Produces single raster lines on demand from the retained scene: a
 * binary-coverage crossing walk, or with ri->aa set, exact per-pixel
 * covered fractions from band-clipped edge ramp areas.  All pure integer
 * Q16.16 arithmetic.
 */

#include <private-lib-core.h>
#include "private-lib-misc-svg.h"

/*
 * Scanline rasterization
 */

static int
cross_cmp(const void *a, const void *b)
{
	const lws_svg_cross_t *ca = (const lws_svg_cross_t *)a;
	const lws_svg_cross_t *cb = (const lws_svg_cross_t *)b;

	return (ca->x > cb->x) - (ca->x < cb->x);
}

static int
xings_grow(lws_svg_t *ctx, size_t need)
{
	if (need <= ctx->xings_size)
		return 0;

	{
		size_t ns = ctx->xings_size ? ctx->xings_size * 2 : 64;
		lws_svg_cross_t *n;

		while (ns < need)
			ns *= 2;

		n = svg_ac_use(ctx, ns * sizeof(*ctx->xings));
		if (!n)
			return 1;
		if (ctx->xings_size)
			memcpy(n, ctx->xings,
			       ctx->xings_size * sizeof(*ctx->xings));
		ctx->xings = n;	/* old generation stays in the lwsac */
		ctx->xings_size = ns;
	}

	return 0;
}

typedef struct {
	lws_svg_span_cb_t	cb;
	void			*user;
	int			w;
	uint32_t		rgba;
} svg_emit_t;


/*
 * Exact-area antialiasing.
 *
 * For the output row band [y, y + 1), every boundary edge is clipped to the
 * band; a straight piece from (xa, ya) to (xb, yb) with ya != yb contributes
 * to the covered fraction of each pixel column p through the winding
 * integral
 *
 *   raw(p) = sum_i s_i * integral of clamp(p + 1 - x_e,i, 0, 1) dyy
 *
 * over the band, where s is the edge direction and x_e the edge x at yy.
 * Since x_e is linear in yy, each term is the integral of a linear function
 * clamped to [0, 1] (a "ramp area"), and
 *
 *   raw(p + 1) - raw(p) = sum_i s_i * tent(p + 1, x_e,i) dyy
 *
 * with tent(c, x) a unit tent centred at c, so columns only receive
 * contributions from edges passing near them.  Sweeping raw(0) + sum(D)
 * left to right yields each column's exact covered fraction; clamping its
 * magnitude gives nonzero-rule coverage.  Corners inside a pixel, thin
 * features and slivers between scanlines are all handled exactly, since
 * there are no sample lines.
 */

/*
 * Exact integral over t in [0, 1) of clamp(v(t), 0, 1), for v linear from
 * v0 to v1 (Q16.16 in and out).  Decomposes at the at-most-two clamp level
 * crossings and sums trapezoids of the clamped value.
 */

static int32_t
aa_ramp(int64_t v0, int64_t v1)
{
	int64_t t[4], sum = 0;
	int n = 0, i, j;

	t[n++] = 0;
	if ((v0 < 0) != (v1 < 0))
		t[n++] = (-v0) * SVG_Q16_1 / (v1 - v0);
	if ((v0 < SVG_Q16_1) != (v1 < SVG_Q16_1))
		t[n++] = (SVG_Q16_1 - v0) * SVG_Q16_1 / (v1 - v0);
	t[n++] = SVG_Q16_1;

	for (i = 1; i < n; i++) {
		int64_t k = t[i];

		for (j = i - 1; j >= 0 && t[j] > k; j--)
			t[j + 1] = t[j];
		t[j + 1] = k;
	}

	for (i = 0; i + 1 < n; i++) {
		int64_t dt = t[i + 1] - t[i];
		int64_t va = v0 + (v1 - v0) * t[i] / SVG_Q16_1;
		int64_t vb = v0 + (v1 - v0) * t[i + 1] / SVG_Q16_1;

		if (va < 0)
			va = 0;
		if (va > SVG_Q16_1)
			va = SVG_Q16_1;
		if (vb < 0)
			vb = 0;
		if (vb > SVG_Q16_1)
			vb = SVG_Q16_1;

		sum += (va + vb) * dt;
	}

	return (int32_t)((sum + (1 << 16)) >> 17);
}

/*
 * Accumulate one band-clipped edge into the column D terms and the raw(0)
 * base.  Device-space Q16.16; the interpolation pre-shifts by one bit to
 * keep the products inside int64.
 */

static void
aa_edge(int64_t *aa_d, int w, int64_t yt, int64_t yb,
	int64_t x0, int64_t y0, int64_t x1, int64_t y1,
	int64_t *raw0, int *alo, int *ahi)
{
	int64_t lo = yt, hi = yb, s, dy, xa, xb, den, dx;
	int p, p_lo, p_hi;

	if (y0 == y1)
		return;			/* horizontal: no winding change */

	if (y0 < y1) {
		s = 1;
	} else {
		int64_t t;

		s = -1;
		t = x0; x0 = x1; x1 = t;
		t = y0; y0 = y1; y1 = t;
	}

	if (y1 <= lo || y0 >= hi)
		return;			/* outside the band */

	if (y0 > lo)
		lo = y0;
	if (y1 < hi)
		hi = y1;
	dy = hi - lo;
	if (dy <= 0)
		return;

	den = y1 - y0;			/* > 0 */
	dx = x1 - x0;

	/*
	 * x at the clipped positions: both factors are pre-shifted one
	 * bit to keep the product in int64, so the quotient needs <<2.
	 * The quotient itself is bounded by dx, so the shift cannot
	 * overflow.
	 */

	xa = x0 + ((((dx >> 1) * ((lo - y0) >> 1)) / den) << 2);
	xb = x0 + ((((dx >> 1) * ((hi - y0) >> 1)) / den) << 2);


	/* winding integral of column 0 */

	*raw0 += s * (((int64_t)aa_ramp(SVG_Q16_1 - xa,
					SVG_Q16_1 - xb) * dy) >> 16);

	/* localized tent contributions to D(p) = raw(p + 1) - raw(p) */

	p_lo = (int)((xa < xb ? xa : xb) >> 16) - 2;
	p_hi = (int)((xa > xb ? xa : xb) >> 16) + 1;
	if (p_lo < 0)
		p_lo = 0;
	if (p_hi > w - 1)
		p_hi = w - 1;

	for (p = p_lo; p <= p_hi; p++) {
		int64_t c = (int64_t)(p + 1) << 16;
		int64_t tent = aa_ramp(xa - c + SVG_Q16_1,
				       xb - c + SVG_Q16_1) +
			       aa_ramp(c + SVG_Q16_1 - xa,
				       c + SVG_Q16_1 - xb) -
			       SVG_Q16_1;

		if (tent < 0)
			tent = 0;
		if (tent > SVG_Q16_1)
			tent = SVG_Q16_1;

		aa_d[p] += s * ((tent * dy) >> 16);
	}

	if (p_hi >= p_lo) {
		if (p_lo < *alo)
			*alo = p_lo;
		if (p_hi > *ahi)
			*ahi = p_hi;
	}
}

/* map a user-space coordinate into the device raster */

static int64_t
aa_map(int64_t u, svg_c_t vb, svg_c_t sc, svg_c_t o)
{
	return arc_sat(((((u - vb) >> 1) * sc >> 16) << 1) + o);
}

/*
 * The antialiased band pass: accumulate raw(0) and the D terms over all
 * band-clipped edges of the shape, then sweep left to right emitting
 * constant-alpha runs.
 */

static lws_stateful_ret_t
aa_band(lws_svg_t *ctx, const lws_svg_render_t *ri, int y,
	svg_c_t sx, svg_c_t sy, svg_c_t ox, svg_c_t oy,
	svg_c_t vbx, svg_c_t vby, lws_svg_span_cb_t cb, void *user)
{
	const int w = ri->w;
	const int64_t yt = (int64_t)y << 16, yb = yt + SVG_Q16_1;

	if ((size_t)w > ctx->aa_d_size) {
		size_t ns = ctx->aa_d_size ? ctx->aa_d_size * 2 : 256;
		int64_t *n;

		while (ns < (size_t)w)
			ns *= 2;

		n = svg_ac_use(ctx, ns * sizeof(*ctx->aa_d));
		if (!n)
			return LWS_SRET_FATAL;
		/* the sweep reads every column, so keep it fully zeroed */
		memset(n, 0, ns * sizeof(*n));
		ctx->aa_d = n;
		ctx->aa_d_size = ns;
	}

	lws_start_foreach_dll(lws_dll2_t *, d, lws_dll2_get_head(&ctx->shapes)) {
		lws_svg_shape_t *sh = lws_container_of(d, lws_svg_shape_t, list);
		int64_t raw0 = 0;
		int alo = w, ahi = -1;
		uint32_t base = sh->rgba & 0x00ffffff;
		int fill_a = (int)LWS_SVG_ALPHA(sh->rgba);

		if (!fill_a)
			continue;	/* nothing painted */

		lws_start_foreach_dll(lws_dll2_t *, d2,
					      lws_dll2_get_head(&sh->subs)) {
			lws_svg_sub_t *sub = lws_container_of(d2,
							lws_svg_sub_t, list);
			int64_t px, py;
			uint32_t i;

			if (!sub->npts)
				continue;

			px = aa_map(sub->pts[0].x, vbx, sx, ox);
			py = aa_map(sub->pts[0].y, vby, sy, oy);

			/* fill closes open subpaths implicitly */

			for (i = 0; i < sub->npts; i++) {
				lws_svg_pt_t *Q = &sub->pts[
					i + 1 == sub->npts ? 0 : i + 1];
				int64_t qx = aa_map(Q->x, vbx, sx, ox);
				int64_t qy = aa_map(Q->y, vby, sy, oy);

				aa_edge(ctx->aa_d, w, yt, yb,
					px, py, qx, qy, &raw0, &alo, &ahi);

				px = qx;
				py = qy;
			}
		} lws_end_foreach_dll(d2);

		/* sweep: raw(p) = raw(0) + sum of D(q < p) */

		{
			int64_t raw = raw0;
			int prev_a = -1, span0 = 0, p;

			for (p = 0; p < w; p++) {
				int64_t cov = raw < 0 ? -raw : raw;
				int alpha;

				if (cov > SVG_Q16_1)
					cov = SVG_Q16_1;
				alpha = (int)((cov * fill_a + 32768) >> 16);

				if (alpha != prev_a) {
					if (prev_a > 0)
						cb(user, span0, p, base |
						   ((uint32_t)prev_a << 24));
					prev_a = alpha;
					span0 = p;
				}

				raw += ctx->aa_d[p];
			}

			if (prev_a > 0)
				cb(user, span0, w, base |
						   ((uint32_t)prev_a << 24));
		}

		/* clear only the touched columns for the next shape */

		if (ahi >= alo)
			memset(&ctx->aa_d[alo], 0,
			       (size_t)(ahi - alo + 1) * sizeof(ctx->aa_d[0]));
	} lws_end_foreach_dll(d);

	return LWS_SRET_OK;
}

static int
emit_span(svg_emit_t *e, svg_c_t xa, svg_c_t xb)
{
	int x0, x1;

	/* pixel p is covered when xa <= p + 0.5 < xb, in Q16.16 */

	x0 = svg_ceil_q16((int64_t)xa - SVG_Q16_1 / 2);
	x1 = svg_ceil_q16((int64_t)xb - SVG_Q16_1 / 2);

	if (x0 < 0)
		x0 = 0;
	if (x1 > e->w)
		x1 = e->w;

	if (x1 <= x0)
		return 0;

	return e->cb(e->user, x0, x1, e->rgba);
}

lws_stateful_ret_t
lws_svg_render_line(lws_svg_t *ctx, const lws_svg_render_t *ri, int y,
		    lws_svg_span_cb_t cb, void *user)
{
	svg_c_t sx = SVG_Q16_1, sy = SVG_Q16_1, ox = 0, oy = 0;
	svg_c_t vbx = 0, vby = 0, ys;
	svg_emit_t e;

	if (y < 0 || y >= ri->h || ri->w <= 0)
		return LWS_SRET_OK;

	/*
	 * Map user space into the raster according to the sizing policy.
	 * Divisions are safe because the denominators are clamped
	 * positive, and the resulting scales are floored at 1/65536.
	 */

	if (ctx->has_vb && ctx->vb[2] > 0 && ctx->vb[3] > 0) {
		int64_t sxq = ((int64_t)ri->w * SVG_Q16_1 * SVG_Q16_1) /
								ctx->vb[2];
		int64_t syq = ((int64_t)ri->h * SVG_Q16_1 * SVG_Q16_1) /
								ctx->vb[3];

		sx = arc_sat(sxq);
		sy = arc_sat(syq);
		if (!sx)
			sx = 1;
		if (!sy)
			sy = 1;

		if (!ctx->par_none) {
			svg_c_t s = ctx->par_slice ?
					(sx > sy ? sx : sy) : (sx < sy ? sx : sy);

			sx = sy = s;
			ox = arc_sat(((int64_t)ri->w * SVG_Q16_1 -
				(((int64_t)ctx->vb[2] * s) >> 16)) *
				ctx->par_ax / 2);
			oy = arc_sat(((int64_t)ri->h * SVG_Q16_1 -
				(((int64_t)ctx->vb[3] * s) >> 16)) *
				ctx->par_ay / 2);
		}

		vbx = ctx->vb[0];
		vby = ctx->vb[1];
	} else {
		svg_c_t w0 = (ctx->has_w && !ctx->unit_w && ctx->width > 0) ?
				ctx->width : 0;
		svg_c_t h0 = (ctx->has_h && !ctx->unit_h && ctx->height > 0) ?
				ctx->height : 0;

		if (w0 > 0)
			sx = arc_sat(((int64_t)ri->w * SVG_Q16_1 * SVG_Q16_1) /
					w0);
		if (h0 > 0)
			sy = arc_sat(((int64_t)ri->h * SVG_Q16_1 * SVG_Q16_1) /
					h0);
	}

	/* sample the line at the pixel centre, in user space */

	ys = arc_sat((((int64_t)y * SVG_Q16_1 + SVG_Q16_1 / 2 - oy) << 16) /
								sy + vby);

	e.cb = cb;
	e.user = user;
	e.w = ri->w;

	if (ri->aa)
		return aa_band(ctx, ri, y, sx, sy, ox, oy, vbx, vby,
			       cb, user);

	lws_start_foreach_dll(lws_dll2_t *, d, lws_dll2_get_head(&ctx->shapes)) {
		lws_svg_shape_t *sh = lws_container_of(d, lws_svg_shape_t, list);
		size_t n = 0;

		if (!LWS_SVG_ALPHA(sh->rgba))
			continue;	/* nothing painted */

		lws_start_foreach_dll(lws_dll2_t *, d2,
					      lws_dll2_get_head(&sh->subs)) {
			lws_svg_sub_t *sub = lws_container_of(d2,
							lws_svg_sub_t, list);
			uint32_t i;

			if (xings_grow(ctx, n + sub->npts + 1))
				return LWS_SRET_FATAL;

			/* fill closes open subpaths implicitly, so every
			 * subpath walks a closing edge too.  The crossing
			 * interpolation keeps products inside int64 by
			 * pre-shifting; since ys lies between the endpoint
			 * ys, the quotient is bounded by the edge dx.
			 */

			for (i = 0; i < sub->npts; i++) {
				lws_svg_pt_t *p = &sub->pts[i];
				lws_svg_pt_t *q = &sub->pts[
					i + 1 == sub->npts ? 0 : i + 1];

				if ((p->y > ys) != (q->y > ys)) {
					int64_t dy = (int64_t)q->y - p->y;
					int64_t num = (((int64_t)ys - p->y) >> 1) *
						      (((int64_t)q->x - p->x) >> 1);
					int64_t xu = (int64_t)p->x +
							((num / dy) << 2);

					/* map the crossing into device space */

					ctx->xings[n].x = arc_sat(
						((((xu - (int64_t)vbx) >> 1) *
						  sx >> 16) << 1) + ox);
					ctx->xings[n].dir = q->y > p->y ? 1 : -1;
					n++;
				}
			}
		} lws_end_foreach_dll(d2);

		if (n < 2)
			continue;

		qsort(ctx->xings, n, sizeof(ctx->xings[0]), cross_cmp);

		e.rgba = sh->rgba;

		if (!sh->rule) {
			/* nonzero winding */

			int wind = 0, i, start = -1;

			for (i = 0; i < (int)n; i++) {
				if (!wind)
					start = i;
				wind += ctx->xings[i].dir;
				if (!wind && start >= 0) {
					if (emit_span(&e,
						      ctx->xings[start].x,
						      ctx->xings[i].x))
						return LWS_SRET_OK;
					start = -1;
				}
			}
		} else {
			/* even-odd */

			size_t i;

			for (i = 0; i + 1 < n; i += 2)
				if (emit_span(&e, ctx->xings[i].x,
					      ctx->xings[i + 1].x))
					return LWS_SRET_OK;
		}
	} lws_end_foreach_dll(d);

	return LWS_SRET_OK;
}
