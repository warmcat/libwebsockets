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
 * The dump has the text of the page in it, which may be a secret, eg, a
 * passphrase being typed: only in debug logging
 */
#define dlodump_loglevel                LLL_DEBUG
#if (_LWS_ENABLED_LOGS & dlodump_loglevel)
#define lwsl_dlodump(...)               _lws_log(dlodump_loglevel, __VA_ARGS__)
#else
#define lwsl_dlodump(...)
#endif

#if defined(LWS_WITH_FOOTPRINT)

/*
 * A display list holds the laid out page: every dlo, and for images their
 * payload and decoder, so it works out what it holds on demand by walking
 * the dlo tree.  The tree is only as deep as the html nesting.
 */

typedef struct {
	lws_footprint_report_t	*r;	/* or NULL, to dump instead */
	struct lws_context	*cx;
} dl_fp_walk_t;

static void
dl_fp_walk(lws_dll2_owner_t *o, dl_fp_walk_t *w)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(o)) {
		lws_dlo_t *dlo = lws_container_of(d, lws_dlo_t, list);
		size_t h = dlo->_heap ? dlo->_heap(dlo) : 0;

		if (w->r) {
			w->r->count++;
			/* the dlo is the start of its type's allocation */
			w->r->bytes += lws_fp_heap(dlo, sizeof(*dlo)) + h;
		} else if (h > 1024)
			/* the dlos holding more than their own struct */
			lwsl_cx_notice(w->cx, "fp:     %-24s %7llu B",
				       dlo->fp_name ? dlo->fp_name : "-",
				       (unsigned long long)h);

		dl_fp_walk(&dlo->children, w);
	} lws_end_foreach_dll(d);
}

static void
dl_fp_report(lws_footprint_t *fp, lws_footprint_report_t *r)
{
	lws_displaylist_t *dl = lws_container_of(fp, lws_displaylist_t, fp);
	dl_fp_walk_t w = { r, NULL };

	dl_fp_walk(&dl->dl, &w);
	if (r->bytes > fp->bytes_hwm)
		fp->bytes_hwm = r->bytes;
	r->bytes_hwm = fp->bytes_hwm;
}

static void
dl_fp_dump(lws_footprint_t *fp)
{
	lws_displaylist_t *dl = lws_container_of(fp, lws_displaylist_t, fp);
	dl_fp_walk_t w = { NULL, dl->ds->ctx };

	dl_fp_walk(&dl->dl, &w);
}

static const lws_footprint_ops_t dl_fp_ops = {
	.shed_class	= LWSFP_SHED_NONE,
	.report		= dl_fp_report,
	.dump		= dl_fp_dump,
};
#endif

void
lws_display_dl_init(lws_displaylist_t *dl, lws_display_state_t *ds)
{
	lws_dll2_owner_clear(&dl->dl);
	lws_dll2_owner_clear(&dl->glyphed);
	dl->ds = ds;
	/* the lhp that lays out into it sets this if it wants it */
	dl->hold_fonts = 0;

#if defined(LWS_WITH_FOOTPRINT)
	/*
	 * A list may be init'd again while it is registered, eg, for each
	 * page; otherwise, whatever was in the struct before is no
	 * participant of ours.  Only a list with a context takes part.
	 */
	if (!ds || !ds->ctx || dl->fp.list.owner != &ds->ctx->footprints) {
		memset(&dl->fp, 0, sizeof(dl->fp));
		if (ds && ds->ctx)
			lws_footprint_register(ds->ctx, &dl->fp, "display list",
					       &dl_fp_ops);
	}
#endif
}

int
lws_display_dlo_add(lws_displaylist_t *dl, lws_dlo_t *dlo_parent, lws_dlo_t *dlo)
{
	if (!dlo_parent && !lws_dll2_get_head(&dl->dl)) {
		/*
		 * This one is going on the display list itself, so its list
		 * node's owner is not any dlo's children owner... mark it so
		 * nobody tries to walk up from it to a "parent" dlo
		 */

		dlo->flag_toplevel = 1;
		lws_dll2_add_tail(&dlo->list, &dl->dl);

		return 0;
	}

	if (!dlo_parent) {
		if(lws_dll2_is_empty(&dl->dl))
			return 0;

		dlo_parent = lws_container_of(lws_dll2_get_head(&dl->dl), lws_dlo_t, list);
	}

	lws_dll2_add_tail(&dlo->list, &dlo_parent->children);

	return 0;
}

/* the integer square root, rounded down */

static uint32_t
isqrt32(uint32_t v)
{
	uint32_t r = 0, b = 1u << 30;

	while (b > v)
		b >>= 2;

	while (b) {
		if (v >= r + b) {
			v -= r + b;
			r = (r >> 1) + b;
		} else
			r >>= 1;
		b >>= 2;
	}

	return r;
}

int
lws_surface_visible_span(const lws_surface_info_t *ic, int y0, int y1,
			 int *x0, int *x1)
{
	int w = ic->wh_px[0].whole, h = ic->wh_px[1].whole, d, e0, e1, e, dh,
	    t = ic->round ? ic->round_top : 0;
	uint32_t c;

	*x0 = *x1 = 0;

	if (w <= 0 || h <= 0 || y0 < 0 || y1 > h || y0 >= y1)
		return 1;

	if (!ic->round) {
		*x1 = w;
		return 0;
	}

	/*
	 * Working in half pixels, so the centres of the pixels and of the
	 * circle are whole: line y's centre is 2(t + y) + 1 half pixels down
	 * the display, the circle's is the display's height dh, and its
	 * diameter is the display's shorter side.  A pixel can be seen if its
	 * centre is inside the circle.  The chord is shortest at the line of
	 * the band furthest from the middle, which is one of its ends.
	 */

	dh = h + t;
	d = w < dh ? w : dh;
	e0 = 2 * (t + y0) + 1 - dh;
	e1 = 2 * (t + y1 - 1) + 1 - dh;
	if (e0 < 0)
		e0 = -e0;
	if (e1 < 0)
		e1 = -e1;
	e = e0 > e1 ? e0 : e1;

	if (e >= d)
		return 1;

	/* the chord, in pixels, is sqrt(d^2 - e^2) */

	c = isqrt32((uint32_t)(d * d - e * e));

	/*
	 * The columns whose centres are inside it, |2x + 1 - w| <= c half
	 * pixels, so from (w - c) / 2 up to w less that
	 */

	*x0 = (w - (int)c) / 2;
	*x1 = w - *x0;

	return *x0 >= *x1;
}

/*
 * How far the view of a display list may go beyond each edge of its content:
 * on a round surface, as far as it takes to bring a corner of the content to
 * the first pixel of the circle that can be seen there, at 45 degrees from
 * the centre.  Short of that, the corner isn't in the circle: the visible
 * circle meets the square that the corner moves in only at the square's far
 * corner, so it's the circle that limits it.
 *
 * If the surface is only the lower part of the round display, .round_top, and
 * the 45 degree point is above it, the top corners go to the first pixel of
 * the circle seen on its top line instead.  aff[] is how far beyond the left,
 * right, top and bottom edges.
 */

static void
pan_affordance(const lws_surface_info_t *ic, int32_t aff[4])
{
	int32_t w = ic->wh_px[0].whole, t = ic->round_top,
		dh = ic->wh_px[1].whole + t, r = (w < dh ? w : dh) / 2,
		k, cy = dh / 2, top, c;

	aff[0] = aff[1] = aff[2] = aff[3] = 0;

	if (!ic->round || r <= 0 || t < 0)
		return;

	/* the centre less r / sqrt(2), at the left and right, and bottom */

	k = (int32_t)isqrt32((uint32_t)(r * r) / 2);
	aff[0] = aff[1] = w / 2 - k;
	aff[3] = dh / 2 - k;

	/* where the top corners go */

	top = cy - k;
	if (top < t) {
		/* above the surface: the circle on its top line */
		if (cy - t >= r)
			top = -1; /* not seen at all */
		else {
			c = (int32_t)isqrt32((uint32_t)(r * r -
						(cy - t) * (cy - t)));
			if (w / 2 - c > aff[0])
				aff[0] = aff[1] = w / 2 - c;
			top = t;
		}
	}
	if (top >= t)
		aff[2] = top - t;

	for (k = 0; k < 4; k++)
		if (aff[k] < 0)
			aff[k] = 0;
}

/*
 * The pan on one axis, kept to the content's extent there.  Content shorter
 * than the display can always be where it was laid out: on a round display,
 * if it's that short, its far corner is already inside the circle there
 */

static int32_t
pan_clamp(int64_t pan, int32_t extent, int32_t len, int32_t aff_lo,
	  int32_t aff_hi)
{
	int64_t lo = -aff_lo, hi = (int64_t)extent - len + aff_hi;

	if (hi < 0)
		hi = 0;
	if (pan < lo)
		pan = lo;
	if (pan > hi)
		pan = hi;

	return (int32_t)pan;
}

/*
 * How far across and down what is in the display list reaches.  The first dlo
 * is the root, eg, the html's background: laid out, it fills the surface it
 * was given however much is in it, so it's what is in it that counts.  That
 * may be anywhere, eg, positioned below a body with a fixed height, except
 * outside a dlo that clips what is in it
 */

static void
dl_extent(lws_displaylist_t *dl, int32_t *ew, int32_t *eh)
{
	struct {
		lws_dlo_t	*dlo;
		lws_fx_t	x, y;	/* its parent's origin */
	} st[LWS_DLO_STACK_DEPTH];
	lws_dll2_t *d = lws_dll2_get_head(&dl->dl);
	int sp = 0;
	lws_fx_t t;

	*ew = *eh = 0;
	if (!d)
		return;

	memset(st, 0, sizeof(st));
	st[0].dlo = lws_container_of(d, lws_dlo_t, list);

	while (sp >= 0) {
		lws_dlo_t *dlo = st[sp].dlo;
		lws_fx_t x, y;

		if (!dlo) {
			sp--;
			continue;
		}

		d = lws_dll2_get_next(&dlo->list);
		st[sp].dlo = d ? lws_container_of(d, lws_dlo_t, list) : NULL;

		lws_fx_add(&x, &st[sp].x, &dlo->box.x);
		lws_fx_add(&y, &st[sp].y, &dlo->box.y);

		lws_fx_add(&t, &x, &dlo->box.w);
		if (lws_fx_roundup(&t) > *ew)
			*ew = lws_fx_roundup(&t);

		/* the root is as wide as the page, but not as tall */

		lws_fx_add(&t, &y, &dlo->box.h);
		if ((sp || dlo->list.prev) && lws_fx_roundup(&t) > *eh)
			*eh = lws_fx_roundup(&t);

		d = lws_dll2_get_head(&dlo->children);
		if (!d || dlo->flag_clip || sp + 1 == (int)LWS_ARRAY_SIZE(st))
			continue;

		sp++;
		st[sp].dlo = lws_container_of(d, lws_dlo_t, list);
		st[sp].x = x;
		st[sp].y = y;
	}
}

/*
 * A retained render scans the whole display list for every line, so for each
 * dlo, note the lines of the surface that it and its children can draw on:
 * the raster can skip the subtree on all the others.  A dlo draws inside its
 * box, like its children unless they're positioned outside it, and if it
 * clips them, they can't draw outside it either.  A line either side
 * allows for the fractions and for the walk entering a dlo from the line
 * above its box.
 */

static void
dl_subtree_extents(lws_displaylist_t *dl)
{
	struct {
		lws_dlo_t	*dlo;
		lws_dlo_t	*parent; /* whose children this level is */
		lws_fx_t	y;	 /* the parent's origin */
	} st[LWS_DLO_STACK_DEPTH];
	lws_dll2_t *d = lws_dll2_get_head(&dl->dl);
	lws_dlo_t *p;
	int sp = 0;
	lws_fx_t y, t;

	if (!d)
		return;

	memset(st, 0, sizeof(st));
	st[0].dlo = lws_container_of(d, lws_dlo_t, list);

	while (sp >= 0) {
		lws_dlo_t *dlo = st[sp].dlo;

		if (!dlo) {
			/* the children of this level's parent are all in it */
			p = st[sp--].parent;
			if (sp >= 0 && st[sp].parent && p) {
				if (p->ext[0] < st[sp].parent->ext[0])
					st[sp].parent->ext[0] = p->ext[0];
				if (p->ext[1] > st[sp].parent->ext[1])
					st[sp].parent->ext[1] = p->ext[1];
			}
			continue;
		}

		d = lws_dll2_get_next(&dlo->list);
		st[sp].dlo = d ? lws_container_of(d, lws_dlo_t, list) : NULL;

		lws_fx_add(&y, &st[sp].y, &dlo->box.y);
		lws_fx_add(&t, &y, &dlo->box.h);

		dlo->ext[0] = y.whole - 1;
		dlo->ext[1] = lws_fx_roundup(&t) + 1;
		dlo->flag_ext = 1;

		d = lws_dll2_get_head(&dlo->children);
		if (d && !dlo->flag_clip) {
			if (sp + 1 == (int)LWS_ARRAY_SIZE(st)) {
				/* too deep to follow: never skip it */
				dlo->ext[0] = INT32_MIN;
				dlo->ext[1] = INT32_MAX;
			} else {
				sp++;
				st[sp].dlo = lws_container_of(d, lws_dlo_t,
							      list);
				st[sp].parent = dlo;
				st[sp].y = y;
				continue;
			}
		}

		/* nothing below it to wait for, it's complete */
		p = st[sp].parent;
		if (p) {
			if (dlo->ext[0] < p->ext[0])
				p->ext[0] = dlo->ext[0];
			if (dlo->ext[1] > p->ext[1])
				p->ext[1] = dlo->ext[1];
		}
	}
}

int
lws_display_render_pan(lws_display_render_state_t *rs, int dx, int dy)
{
	int32_t ox = rs->pan_x, oy = rs->pan_y, ew, eh, aff[4];

	dl_extent(&rs->displaylist, &ew, &eh);
	pan_affordance(rs->ic, aff);

	rs->pan_x = pan_clamp((int64_t)rs->pan_x + dx, ew,
			      rs->ic->wh_px[0].whole, aff[0], aff[1]);
	rs->pan_y = pan_clamp((int64_t)rs->pan_y + dy, eh,
			      rs->ic->wh_px[1].whole, aff[2], aff[3]);

	return rs->pan_x != ox || rs->pan_y != oy;
}

/* x is known to be on the surface */

static inline void
surface_px(const lws_surface_info_t *ic, uint8_t *line, int x,
	   const lws_display_colour_t *c)
{
	unsigned int alpha, ialpha;
	lws_display_colour_t oc;
	lws_display_colour_t y;
	uint8_t rgb[3];

	/*
	 * All alpha composition takes place at 8bpp grey or 24bpp
	 */

	if (ic->greyscale) {

		/* line composition buffer is 8-bit Y per pixel */

		oc = line[x];
		alpha = LWSDC_ALPHA(*c);
		ialpha = 255 - alpha;

		y = RGB_TO_Y(LWSDC_R(*c), LWSDC_G(*c), LWSDC_B(*c));

		line[x] = (uint8_t)(((y * alpha) / 255) +
			   ((LWSDC_R(oc) * ialpha) / 255));
		return;
	}

	/* line composition buffer is 24-bit RGB per pixel */

	line += (ic->render_to_rgba ? 4 : 3) * x;

	alpha = LWSDC_ALPHA(*c);
	ialpha = 255 - alpha;

	rgb[0] = (uint8_t)(((LWSDC_R(*c) * alpha) / 255) +
			   ((line[0] * ialpha) / 255));
	rgb[1] = (uint8_t)(((LWSDC_G(*c) * alpha) / 255) +
			   ((line[1] * ialpha) / 255));
	rgb[2] = (uint8_t)(((LWSDC_B(*c) * alpha) / 255) +
			   ((line[2] * ialpha) / 255));

	*line++ = rgb[0];
	*line++ = rgb[1];
	*line++ = rgb[2];

	if (ic->render_to_rgba)
		*line = 0xff;
}

void
lws_surface_set_px(const lws_surface_info_t *ic, uint8_t *line, int x,
		   const lws_display_colour_t *c)
{
	if (x < 0 || x >= ic->wh_px[0].whole)
		return;

	surface_px(ic, line, x, c);
}

/*
 * Recursively find out the total width and height of the contents of a DLO
 */

void
lws_dlo_contents(lws_dlo_t *parent, lws_dlo_dim_t *dim)
{
	lws_fx_t t1;

	dim->w.whole = 0;
	dim->w.frac = 0;
	dim->h.whole = 0;
	dim->h.frac = 0;

	if (!parent)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&parent->children)) {
		lws_dlo_t *child = lws_container_of(d, lws_dlo_t, list);

		lws_fx_add(&t1, &child->box.w, &child->box.x);
		/*
		 * Original recursive code added padding here.
		 * lws_fx_add(&t1, &t1, &dlo->padding[CCPAS_LEFT]);
		 * But box.w usually includes padding in LHP DLOs.
		 */
		// lws_fx_add(&t1, &t1, &child->padding[CCPAS_LEFT]);

		if (lws_fx_comp(&t1, &dim->w) > 0)
			dim->w = t1;

		lws_fx_add(&t1, &child->box.h, &child->box.y);
		// lws_fx_add(&t1, &t1, &child->padding[CCPAS_TOP]);

		if (lws_fx_comp(&t1, &dim->h) > 0)
			dim->h = t1;

	} lws_end_foreach_dll(d);

	if (lws_dll2_owner(&parent->col_list)) {
		lhp_table_col_t *tc = lws_dll2_owner_container(&parent->col_list,
					lhp_table_col_t, col_dlos);

		if (lws_fx_comp(&dim->w, &tc->width) < 0) {
	//		lws_fx_add(&t1, &tc->width, &parent->padding[CCPAS_LEFT]);
	//		lws_fx_add(&dim->w, &tc->width, &parent->padding[CCPAS_RIGHT]);
			dim->w = tc->width;
		}
	}

	if (lws_dll2_owner(&parent->row_list)) {
		lhp_table_row_t *tr = lws_dll2_owner_container(&parent->row_list,
					lhp_table_row_t, row_dlos);

		if (lws_fx_comp(&dim->h, &tr->height) < 0) {
	//		lws_fx_add(&t1, &tr->height, &parent->padding[CCPAS_TOP]);
			lws_fx_add(&dim->h, &tr->height, &parent->padding[CCPAS_BOTTOM]);
//			dim->h = tr->height;
		}
	}

/*
	lwsl_user("%s: dlo %p: FINAL w:%d -> %d h:%d -> %d\n", __func__, parent,
		  parent->box.w.whole, dim->w.whole,
		  parent->box.h.whole, dim->h.whole);
*/
}

/*
 * Some DLO is changing height, adjust its height, and that of everybody below.
 */

void
lws_display_dlo_adjust_dims(lws_dlo_t *dlo, lws_dlo_dim_t *dim)
{
	lws_dlo_dim_t delta;

	if (!dim->w.whole && !dim->h.whole)
		return;

	/* adjust the target's width / height */

	lws_fx_sub(&delta.w, &dim->w, &dlo->box.w);
	lws_fx_sub(&delta.h, &dim->h, &dlo->box.h);

	dlo->box.w = dim->w;
	dlo->box.h = dim->h;

	// lwsl_notice("%s: dlo %p: delta w:%d h:%d\n", __func__, dlo, delta.w.whole, delta.h.whole);

	/* move peers below him accordingly */

	do {
		lws_dlo_t *dp;

		/*
		 * The toplevel dlo's list node is owned by the lws_displaylist_t
		 * and not by any dlo's children owner, so we must not convert
		 * its owner to an lws_dlo_t *... and there is nothing above it
		 * to walk up to anyway.  Same story if we are detached.
		 */

		if (dlo->flag_toplevel || !lws_dll2_owner(&dlo->list))
			break;

		dp = lws_dll2_owner_container(&dlo->list, lws_dlo_t, children);

		/*
		 * Adjust y pos of siblings below us
		 */

		do {
			dlo = lws_container_of(lws_dll2_get_next(&dlo->list), lws_dlo_t, list);
			if (dlo) {
				//lwsl_notice("%s: dlo %p: adj y %d -> %d\n", __func__, dlo, dlo->box.y.whole, dlo->box.y.whole + delta.h.whole);
				lws_fx_add(&dlo->box.y, &dlo->box.y, &delta.h);
			}
		} while (dlo);


		/* go up parent chain until toplevel adjusting height of
		 * parent siblings below parent */

		if (dp->flag_toplevel)
			break;

		dlo = dp;
		//lwsl_notice("%s: dlo %p: adj h by %d\n", __func__, dlo, delta.h.whole);
		lws_fx_add(&dlo->box.h, &dlo->box.h, &delta.h);
	} while (1);
}

//#if defined(_DEBUG)
void
lws_display_dl_dump(lws_displaylist_t *dl)
{
	lws_display_render_stack_t	st[LWS_DLO_STACK_DEPTH];
						/* DLO child stack */
	int				sp = 0;
	lws_dll2_t *d = lws_dll2_get_head(&dl->dl);
#if (_LWS_ENABLED_LOGS & dlodump_loglevel)
	static const char * const ind = "                           ";
#endif
	char b[4][22], b1[4][22], dt[96];

	if (!d) {
		lwsl_dlodump("%s: empty dl\n", __func__);

		return;
	}

	lwsl_dlodump("%s\n", __func__);

	memset(&st, 0, sizeof(st));
	st[0].dlo = lws_container_of(d, lws_dlo_t, list);

	while (sp || st[0].dlo) {
		lws_dlo_t *dlo = st[sp].dlo;
		lws_box_t co;

		if (!dlo) {
			if (!sp) {
				lwsl_err("%s: underflow\n", __func__);
					return;
			}
			sp--;
			continue;
		}

		lws_fx_add(&co.x, &st[sp].co.x, &dlo->box.x);
		lws_fx_add(&co.y, &st[sp].co.y, &dlo->box.y);
		co.w = dlo->box.w;
		co.h = dlo->box.h;

		lws_snprintf(dt, sizeof(dt), "rect: RGBA 0x%08X", (unsigned int)dlo->dc);
		if (dlo->_destroy == lws_display_dlo_text_destroy) {
			lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);
			lws_snprintf(dt, sizeof(dt), "text: RGBA 0x%08X, chars: %u, %.*s",
					(unsigned int)dlo->dc, (unsigned int)text->text_len,
					(int)text->text_len, text->text ? text->text : "(empty)");
		}
		else if (dlo->render == lws_display_render_hit)
			lws_snprintf(dt, sizeof(dt), "hit: %scur %u %s",
				lws_container_of(dlo, lws_dlo_hit_t, dlo)->fill ?
					"fill " : "",
				lws_container_of(dlo, lws_dlo_hit_t, dlo)->cursor,
				lws_container_of(dlo, lws_dlo_hit_t, dlo)->url ?
				lws_container_of(dlo, lws_dlo_hit_t, dlo)->url :
					"");
#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_UPNG) && defined(LWS_WITH_CLIENT)
		else if (dlo->_destroy == lws_display_dlo_png_destroy)
			lws_snprintf(dt, sizeof(dt), "png");
#endif
#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_JPEG) && defined(LWS_WITH_CLIENT)
		else if (dlo->_destroy == lws_display_dlo_jpeg_destroy)
			lws_snprintf(dt, sizeof(dt), "jpeg");
#endif

		lws_fx_string(&dlo->box.x, b[0], sizeof(b[0]));
		lws_fx_string(&dlo->box.y, b[1], sizeof(b[1]));
		lws_fx_string(&dlo->box.w, b[2], sizeof(b[2]));
		lws_fx_string(&dlo->box.h, b[3], sizeof(b[3]));
		lws_fx_string(&co.x, b1[0], sizeof(b1[0]));
		lws_fx_string(&co.y, b1[1], sizeof(b1[1]));
		lws_fx_string(&co.w, b1[2], sizeof(b1[2]));
		lws_fx_string(&co.h, b1[3], sizeof(b1[3]));

		lwsl_dlodump("%.*s %p box: (%s, %s) [%s x %s], co: (%s, %s) [%s x %s], %s\n",
				sp, ind, dlo, b[0], b[1], b[2], b[3],
				b1[0], b1[1], b1[2], b1[3], dt);

		d = lws_dll2_get_next(&dlo->list);
		if (d)
			st[sp].dlo = lws_container_of(d, lws_dlo_t, list);
		else
			st[sp].dlo = NULL;

		/* go into any children */

		if(!lws_dll2_is_empty(&dlo->children)) {
			if (sp + 1 == LWS_ARRAY_SIZE(st)) {
				lwsl_err("%s: DLO stack overflow\n", __func__);
				return;
			}
			st[++sp].dlo = lws_container_of(
				lws_dll2_get_head(&dlo->children), lws_dlo_t, list);
			st[sp].co = co;
		}

	}
}
//#endif

void
lws_display_render_set_px(lws_display_render_state_t *rs, int x,
			  const lws_display_colour_t *c)
{
	unsigned int a = rs->opacity;
	lws_display_colour_t oc;

	if (x < rs->clip_x0 || x >= rs->clip_x1)
		return;

	if (rs->rclip) {
		/* how much of the pixel is inside the rounded clip */
		unsigned int rc = x >= rs->rclip_row.pa &&
				  x <= rs->rclip_row.pb ? rs->rclip_alpha :
			lws_display_dlo_rect_px_alpha(rs->rclip, &rs->rclip_row,
						      x, rs->rclip_alpha);

		a = (a * rc + 127) / 255;
	}

	if (a == 255) {
		lws_surface_set_px(rs->ic, rs->line, x, c);
		return;
	}

	oc = (*c & 0xffffffu) | ((lws_display_colour_t)
		((LWSDC_ALPHA(*c) * a + 127) / 255) << 24);

	lws_surface_set_px(rs->ic, rs->line, x, &oc);
}

void
lws_display_render_fill_span(lws_display_render_state_t *rs, int x0, int x1,
			     const lws_display_colour_t *c)
{
	const lws_surface_info_t *ic = rs->ic;
	lws_display_colour_t oc = *c;
	int bpp = ic->greyscale ? 1 : (ic->render_to_rgba ? 4 : 3);
	unsigned int a = rs->opacity;
	uint8_t *p;

	if (rs->rclip) {
		/*
		 * The pixels at the ends of the rounded clip's row may only be
		 * partly inside it: they are composed one at a time.  Between,
		 * all of the span is inside it as much as the row is
		 */
		while (x0 < x1 && x0 < rs->rclip_row.pa)
			lws_display_render_set_px(rs, x0++, c);
		while (x1 > x0 && x1 > rs->rclip_row.pb + 1)
			lws_display_render_set_px(rs, --x1, c);

		a = (a * rs->rclip_alpha + 127) / 255;
	}

	if (x0 < rs->clip_x0)
		x0 = rs->clip_x0;
	if (x1 > rs->clip_x1)
		x1 = rs->clip_x1;
	if (x0 < 0)
		x0 = 0;
	if (x1 > ic->wh_px[0].whole)
		x1 = ic->wh_px[0].whole;
	if (x0 >= x1)
		return;

	if (a != 255)
		oc = (*c & 0xffffffu) | ((lws_display_colour_t)
			((LWSDC_ALPHA(*c) * a + 127) / 255) << 24);

	if (LWSDC_ALPHA(oc) != 255 || ic->greyscale) {
		/* it's composed with what's there, a pixel at a time */
		while (x0 < x1)
			surface_px(ic, rs->line, x0++, &oc);

		return;
	}

	/* opaque, it just replaces what's there */

	p = rs->line + bpp * x0;
	while (x0++ < x1) {
		*p++ = (uint8_t)LWSDC_R(oc);
		*p++ = (uint8_t)LWSDC_G(oc);
		*p++ = (uint8_t)LWSDC_B(oc);
		if (bpp == 4)
			*p++ = 0xff;
	}
}

/*
 * The alpha a dlo, and so its children, are composed with: its own opacity
 * times what its ancestors' came to.  Overlapping children are each composed
 * at that, rather than css' composing them opaquely first and then the group
 * at the opacity, since there is only the line to compose into
 */

static uint8_t
dlo_opacity(const lws_display_render_stack_t *st, const lws_dlo_t *dlo)
{
	return (uint8_t)((st->opacity * (255u - dlo->opacity_inv) + 127) / 255);
}

/*
 * A dlo is clipped to what its ancestors with css overflow: hidden clip their
 * children to, st->clip.  On a line outside that, it composes nothing.  The
 * renderer is still called, since decoders keep their place by the lines they
 * are given, and the box may extend into the clip further down.
 *
 * If the innermost of those ancestors has rounded corners, st->rclip, it is
 * also clipped to them, as much as the ancestor covers each pixel, the same
 * as it is drawn itself.  Outer ones with rounded corners only clip to their
 * box.
 */

static void
dlo_clip_line(lws_display_render_state_t *rs,
	      const lws_display_render_stack_t *st)
{
	rs->rclip = NULL;

	if (rs->curr < st->clip[1] || rs->curr >= st->clip[3]) {
		rs->clip_x0 = rs->clip_x1 = 0;
		return;
	}

	rs->clip_x0 = st->clip[0];
	rs->clip_x1 = st->clip[2];

	if (!st->rclip)
		return;

	/* the row of the rounded clip is worked out once a line */

	if (rs->rclip_for != st->rclip || rs->rclip_row.curr != rs->curr) {
		rs->rclip_for = st->rclip;
		rs->rclip_none = (uint8_t)!!lws_display_dlo_rect_row(st->rclip,
				rs->curr, rs->ic->wh_px[0].whole,
				&rs->rclip_row);
		rs->rclip_row.curr = rs->curr;
		rs->rclip_alpha = lws_display_dlo_rect_row_alpha(
							&rs->rclip_row, 255);
	}

	if (rs->rclip_none || !rs->rclip_alpha) {
		rs->clip_x0 = rs->clip_x1 = 0;
		return;
	}

	if (rs->clip_x0 < rs->rclip_row.os)
		rs->clip_x0 = rs->rclip_row.os;
	if (rs->clip_x1 > rs->rclip_row.le + 1)
		rs->clip_x1 = rs->rclip_row.le + 1;

	rs->rclip = st->rclip;
}

/*
 * What the children of dlo, whose surface box is co, are clipped to: its
 * box, if it has css overflow: hidden, inside what it is clipped to itself
 */

static void
dlo_child_clip(lws_display_render_state_t *rs,
	       const lws_display_render_stack_t *st, lws_dlo_t *dlo,
	       const lws_box_t *co, lws_display_render_stack_t *cst)
{
	int32_t e, *clip = cst->clip;
	lws_dlo_rect_t *r;
	lws_fx_t t;

	memcpy(clip, st->clip, sizeof(st->clip));
	cst->rclip = st->rclip;

	if (!dlo->flag_clip)
		return;

	if (dlo->render == lws_display_render_rect) {
		r = lws_container_of(dlo, lws_dlo_rect_t, dlo);
		if (!r->tri && lws_display_dlo_rect_rounded(r)) {
			/* it may have moved since its row was worked out */
			lws_display_dlo_rect_place(r, &co->x, &co->y);
			cst->rclip = r;
			rs->rclip_for = NULL;
		}
	}

	if (co->x.whole > clip[0])
		clip[0] = co->x.whole;
	if (co->y.whole > clip[1])
		clip[1] = co->y.whole;

	lws_fx_add(&t, &co->x, &co->w);
	e = lws_fx_roundup(&t);
	if (e < clip[2])
		clip[2] = e;

	lws_fx_add(&t, &co->y, &co->h);
	e = lws_fx_roundup(&t);
	if (e < clip[3])
		clip[3] = e;
}

/*
 * Go through every DLO once, setting its id->box to the final layout for the
 * related dlo, if any
 */

lws_stateful_ret_t
lws_display_get_ids_boxes(lws_display_render_state_t *rs)
{
	lws_dll2_t *d;

	rs->lowest_id_y = 0;

	d = lws_dll2_get_head(&rs->displaylist.dl);
	if (!d)
		/* nothing in dlo */
		return LWS_SRET_OK;

	memset(&rs->st[0].co, 0, sizeof(rs->st[0].co));
	rs->st[0].dlo = lws_container_of(d, lws_dlo_t, list);

	while (rs->sp || rs->st[0].dlo) {
		lws_dlo_t *dlo = rs->st[rs->sp].dlo;
		lws_box_t co;
		lws_fx_t t2;

		if (!dlo) {
			if (rs->sp > 0)
				rs->sp--;
			else
				break;
			continue;
		}

		lws_fx_add(&co.x, &rs->st[rs->sp].co.x, &dlo->box.x);
		lws_fx_add(&co.y, &rs->st[rs->sp].co.y, &dlo->box.y);
		co.w = dlo->box.w;
		co.h = dlo->box.h;

		lws_fx_add(&t2, &co.y, &dlo->box.h);


		if (dlo->id) {
			lws_display_id_t *id = dlo->id;

			if (id) {
				id->id[sizeof(id->id) - 1] = '\0';
				lwsl_debug("%s: set id box %s\n", __func__, id->id);

				id->box = co;
			}
			if (!rs->retained)
				/*
				 * A streaming render destroys the dlos as it
				 * passes them: only a retained display list's
				 * can be found by their ids afterwards
				 */
				dlo->id = NULL;
		}


		if (co.y.whole + co.h.whole > rs->lowest_id_y) {
			rs->lowest_id_y = (lws_display_scalar)(co.y.whole + co.h.whole);
			if (rs->lowest_id_y > rs->ic->wh_px[1].whole)
				rs->lowest_id_y = (lws_display_scalar)rs->ic->wh_px[1].whole;
		}

		/* next sibling at this level if any */

		d = lws_dll2_get_next(&dlo->list);
		if (d)
			rs->st[rs->sp].dlo = lws_container_of(d,
						lws_dlo_t, list);
		else
			rs->st[rs->sp].dlo = NULL;

		/* go into any children */

		if(!lws_dll2_is_empty(&dlo->children)) {
			if (rs->sp + 1 == LWS_ARRAY_SIZE(rs->st)) {
				lwsl_err("%s: DLO stack overflow A\n",
						__func__);
				return LWS_SRET_FATAL;
			}
			rs->st[++rs->sp].dlo = lws_container_of(
				lws_dll2_get_head(&dlo->children), lws_dlo_t, list);
			rs->st[rs->sp].co = co;
			continue;
		}
	}

	lws_display_render_dump_ids(&rs->ids);

	return LWS_SRET_OK;
}

/* the dlo whose children this one is one of, or NULL at the top level */

static lws_dlo_t *
dl_parent(lws_displaylist_t *dl, const lws_dlo_t *dlo)
{
	lws_dll2_owner_t *o = lws_dll2_owner(&dlo->list);

	if (!o || o == &dl->dl)
		return NULL;

	return lws_container_of(o, lws_dlo_t, children);
}

/*
 * The dlo after this one in document order, with its children before its
 * next sibling, however deep, or NULL after the last
 */

static lws_dlo_t *
dl_next(lws_displaylist_t *dl, lws_dlo_t *dlo)
{
	lws_dll2_t *d = lws_dll2_get_head(&dlo->children);

	if (d)
		return lws_container_of(d, lws_dlo_t, list);

	while (1) {
		d = lws_dll2_get_next(&dlo->list);
		if (d)
			return lws_container_of(d, lws_dlo_t, list);

		dlo = dl_parent(dl, dlo);
		if (!dlo)
			return NULL;
	}
}

static lws_dlo_t *
dl_first(lws_displaylist_t *dl)
{
	lws_dll2_t *d = lws_dll2_get_head(&dl->dl);

	return d ? lws_container_of(d, lws_dlo_t, list) : NULL;
}

lws_dlo_t *
lws_display_dlo_by_id(lws_displaylist_t *dl, const lws_display_id_t *id)
{
	lws_dlo_t *dlo;

	if (!id)
		return NULL;

	for (dlo = dl_first(dl); dlo; dlo = dl_next(dl, dlo))
		if (dlo->id == id)
			return dlo;

	return NULL;
}

int
lws_display_dlo_origin(lws_displaylist_t *dl, const lws_dlo_t *target,
		       int *x, int *y)
{
	const lws_dlo_t *dlo = target;
	lws_fx_t ox, oy;

	if (!dlo || !lws_dll2_owner(&dlo->list))
		return 1;

	/* our box is in our parent's, and so on up to the display list */

	ox = dlo->box.x;
	oy = dlo->box.y;

	while ((dlo = dl_parent(dl, dlo))) {
		lws_fx_add(&ox, &ox, &dlo->box.x);
		lws_fx_add(&oy, &oy, &dlo->box.y);
	}

	*x = ox.whole;
	*y = oy.whole;

	return 0;
}

/* add a box of the layout, from x0, y0 up to x1, y1, to the damage */

static void
damage_add(int32_t *dmg, int32_t x0, int32_t y0, int32_t x1, int32_t y1)
{
	if (x1 <= x0 || y1 <= y0)
		return;

	if (dmg[2] <= dmg[0]) {
		dmg[0] = x0;
		dmg[1] = y0;
		dmg[2] = x1;
		dmg[3] = y1;
		return;
	}

	if (x0 < dmg[0])
		dmg[0] = x0;
	if (y0 < dmg[1])
		dmg[1] = y0;
	if (x1 > dmg[2])
		dmg[2] = x1;
	if (y1 > dmg[3])
		dmg[3] = y1;
}

/* what a dlo covers is damaged: its parent's top left is at px, py */

static void
damage_dlo(lws_display_render_state_t *rs, const lws_dlo_t *dlo, int px,
	   int py)
{
	lws_fx_t r, b;

	lws_fx_add(&r, &dlo->box.x, &dlo->box.w);
	lws_fx_add(&b, &dlo->box.y, &dlo->box.h);

	damage_add(rs->damage, px + dlo->box.x.whole, py + dlo->box.y.whole,
		   px + lws_fx_roundup(&r), py + lws_fx_roundup(&b));
}

/*
 * The element with the id, on a retained display list, and where its parent's
 * top left is in the layout, which its own box is relative to
 */

static lws_dlo_t *
render_id_dlo(lws_display_render_state_t *rs, const char *id, int *px,
	      int *py)
{
	lws_dlo_t *dlo;
	int x, y;

	if (!rs->retained)
		return NULL;

	dlo = lws_display_dlo_by_id(&rs->displaylist,
				    lws_display_render_get_id(rs, id));
	if (!dlo || lws_display_dlo_origin(&rs->displaylist, dlo, &x, &y))
		return NULL;

	*px = x - dlo->box.x.whole;
	*py = y - dlo->box.y.whole;

	return dlo;
}

int
lws_display_render_set_width(lws_display_render_state_t *rs, const char *id,
			     const lws_fx_t *w)
{
	lws_dlo_t *dlo;
	int px, py;

	dlo = render_id_dlo(rs, id, &px, &py);
	if (!dlo)
		return 1;

	damage_dlo(rs, dlo, px, py);
	dlo->box.w = *w;
	if (dlo->render == lws_display_render_rect)
		/* where its right side and corners are is worked out again */
		lws_container_of(dlo, lws_dlo_rect_t, dlo)->init = 0;
	damage_dlo(rs, dlo, px, py);

	return 0;
}

int
lws_display_render_set_text(lws_display_render_state_t *rs, const char *id,
			    const char *utf8)
{
	lws_fx_t total, word, room, shift;
	size_t len = strlen(utf8);
	lws_dlo_text_t *text;
	lws_dlo_t *el, *c;
	int px, py, ex, ey, r;

	el = render_id_dlo(rs, id, &px, &py);
	if (!el)
		return 1;

	/* what is in it must be a single run of text */

	c = lws_dll2_get_head(&el->children) ?
		lws_container_of(lws_dll2_get_head(&el->children),
				 lws_dlo_t, list) : NULL;
	if (!c || lws_dll2_get_next(&c->list) ||
	    c->_destroy != lws_display_dlo_text_destroy ||
	    !lws_dll2_is_empty(&c->children))
		return 1;

	text = lws_container_of(c, lws_dlo_text_t, dlo);

	/* the new text must all fit on the line, from where the run began */

	lws_fx_add(&room, &text->line_free, &text->dlo.box.w);
	lws_display_dlo_text_measure(text, utf8, len, &total, &word);
	if (lws_fx_comp(&total, &room) > 0)
		return 1;

	/* the text's box is in the element's */
	ex = px + el->box.x.whole;
	ey = py + el->box.y.whole;
	damage_dlo(rs, &text->dlo, ex, ey);

	/* where the run began, before the line's alignment moved it */

	lws_display_dlo_text_align_shift(text->align, &text->line_free, &shift);
	lws_fx_sub(&text->dlo.box.x, &text->dlo.box.x, &shift);

	text->dlo.box.w = room;
	r = lws_display_dlo_text_update(text, text->dlo.dc, text->indent,
					utf8, len);
	if (r < 0 || r == 2 || text->text_len != len) {
		/* no memory for it: the element is left with no text */
		lws_fx_set(text->dlo.box.w, 0, 0);
		text->text_len = 0;
		damage_dlo(rs, el, px, py);

		return 1;
	}

	/* ... and the line is aligned again, as the layout aligned it */

	text->dlo.box.w = text->bounding_box.w;
	lws_fx_sub(&text->line_free, &room, &text->dlo.box.w);
	lws_display_dlo_text_align_shift(text->align, &text->line_free, &shift);
	lws_fx_add(&text->dlo.box.x, &text->dlo.box.x, &shift);

	damage_dlo(rs, &text->dlo, ex, ey);

	return 0;
}

int
lws_display_render_damage(lws_display_render_state_t *rs, lws_box_t *box)
{
	struct {
		lws_dlo_t	*dlo;
		lws_fx_t	x, y;	/* its parent's origin */
		int32_t		clip[4]; /* what its parent's clip allows */
	} st[LWS_DLO_STACK_DEPTH];
	int32_t dmg[4], sw = rs->ic->wh_px[0].whole,
		sh = rs->ic->wh_px[1].whole;
	int sp = 0;

	memcpy(dmg, rs->damage, sizeof(dmg));
	memset(rs->damage, 0, sizeof(rs->damage));

	/* what is animated, as far as anything clipping it lets it show */

	memset(st, 0, sizeof(st));
	st[0].dlo = dl_first(&rs->displaylist);
	st[0].clip[0] = st[0].clip[1] = INT32_MIN;
	st[0].clip[2] = st[0].clip[3] = INT32_MAX;

	while (sp >= 0) {
		lws_dlo_t *dlo = st[sp].dlo;
		int32_t b[4];
		lws_dll2_t *d;
		lws_fx_t x, y, t;
		int n;

		if (!dlo) {
			sp--;
			continue;
		}

		d = lws_dll2_get_next(&dlo->list);
		st[sp].dlo = d ? lws_container_of(d, lws_dlo_t, list) : NULL;

		lws_fx_add(&x, &st[sp].x, &dlo->box.x);
		lws_fx_add(&y, &st[sp].y, &dlo->box.y);

		b[0] = x.whole;
		b[1] = y.whole;
		b[2] = lws_fx_roundup(lws_fx_add(&t, &x, &dlo->box.w));
		b[3] = lws_fx_roundup(lws_fx_add(&t, &y, &dlo->box.h));

		if (dlo->flag_animated) {
			int32_t a[4];

			for (n = 0; n < 2; n++) {
				a[n] = b[n] > st[sp].clip[n] ? b[n] :
							       st[sp].clip[n];
				a[n + 2] = b[n + 2] < st[sp].clip[n + 2] ?
					   b[n + 2] : st[sp].clip[n + 2];
			}
			damage_add(dmg, a[0], a[1], a[2], a[3]);
		}

		d = lws_dll2_get_head(&dlo->children);
		if (!d || sp + 1 == (int)LWS_ARRAY_SIZE(st))
			/* too deep to follow is too deep to be rendered */
			continue;

		sp++;
		st[sp].dlo = lws_container_of(d, lws_dlo_t, list);
		st[sp].x = x;
		st[sp].y = y;
		memcpy(st[sp].clip, st[sp - 1].clip, sizeof(st[sp].clip));
		if (dlo->flag_clip)
			for (n = 0; n < 2; n++) {
				if (b[n] > st[sp].clip[n])
					st[sp].clip[n] = b[n];
				if (b[n + 2] < st[sp].clip[n + 2])
					st[sp].clip[n + 2] = b[n + 2];
			}
	}

	/* where that is on the surface, panned as it is now */

	dmg[0] -= rs->pan_x;
	dmg[2] -= rs->pan_x;
	dmg[1] -= rs->pan_y;
	dmg[3] -= rs->pan_y;

	if (dmg[0] < 0)
		dmg[0] = 0;
	if (dmg[1] < 0)
		dmg[1] = 0;
	if (dmg[2] > sw)
		dmg[2] = sw;
	if (dmg[3] > sh)
		dmg[3] = sh;

	if (dmg[2] <= dmg[0] || dmg[3] <= dmg[1])
		return 0;

	memset(box, 0, sizeof(*box));
	box->x.whole = dmg[0];
	box->y.whole = dmg[1];
	box->w.whole = dmg[2] - dmg[0];
	box->h.whole = dmg[3] - dmg[1];

	return 1;
}

static lws_stateful_ret_t
_lws_display_list_render_line(lws_display_render_state_t *rs)
{
	lws_dll2_t *d;

	if (rs->html == 1) {
		lwsl_notice("%s: returning LWS_SRET_WANT_INPUT due to rs->html = 1\n", __func__);
		return LWS_SRET_WANT_INPUT;
	}

	if (!rs->sp && !rs->st[0].dlo) {

		/* starting a line */

		d = lws_dll2_get_head(&rs->displaylist.dl);
		if (!d)
			/* nothing in dlo */
			return LWS_SRET_OK;

		/*
		 * Each scan of a retained display list from the top notes the
		 * extents of its subtrees afresh, and a display list that
		 * hasn't had them yet gets them whichever line it starts on.
		 * A scan of a band lower down uses the extents from before, so
		 * dlos moved since then must be inside one that clips them,
		 * whose children are never skipped, like the keyboard dlo-ui
		 * drags around inside its strip
		 */
		if (rs->retained &&
		    (!rs->curr || !lws_container_of(d, lws_dlo_t,
						    list)->flag_ext))
			dl_subtree_extents(&rs->displaylist);

		/*
		 * Text keeps the glyphs it was drawn with until it's drawn
		 * again, when they are attached afresh.  Text the display
		 * won't show on this scan, eg, panned out of view, would keep
		 * them, and what they pin, for good: so they all go when a
		 * retained scan starts from the top
		 */
		if (rs->retained && !rs->curr)
			lws_start_foreach_dll_safe(struct lws_dll2 *, g, g1,
				lws_dll2_get_head(&rs->displaylist.glyphed)) {
				lws_display_dlo_text_detach_glyphs(
					lws_container_of(g, lws_dlo_text_t,
							 glyphed));
			} lws_end_foreach_dll_safe(g, g1);

		/*
		 * Laid out on the surface, the display list covers the whole
		 * of every line itself.  Panned, the view may show beyond it,
		 * which starts out white like paper
		 */

		if (rs->pan_x || rs->pan_y)
			memset(rs->line, 0xff, (size_t)rs->ic->wh_px[0].whole *
				(rs->ic->greyscale ? 1 :
				 (rs->ic->render_to_rgba ? 4 : 3)));

		memset(&rs->st[0].co, 0, sizeof(rs->st[0].co));
		rs->st[0].co.x.whole = -rs->pan_x;
		rs->st[0].co.y.whole = -rs->pan_y;
		rs->st[0].opacity = 255;
		rs->st[0].clip[0] = rs->st[0].clip[1] = INT32_MIN;
		rs->st[0].clip[2] = rs->st[0].clip[3] = INT32_MAX;
		rs->st[0].rclip = NULL;
		rs->rclip_for = NULL;
		rs->st[0].dlo = lws_container_of(d, lws_dlo_t, list);
	}

	while (rs->sp || rs->st[0].dlo) {
		lws_dlo_t *dlo = rs->st[rs->sp].dlo;
		lws_stateful_ret_t r;
		lws_box_t co;
		lws_fx_t t2;
		char passed;

		if (!dlo) {
			if (rs->sp > 0)
				rs->sp--;
			else
				break;
			continue;
		}

		if (rs->retained && dlo->flag_ext &&
		    (rs->curr + rs->pan_y < dlo->ext[0] ||
		     rs->curr + rs->pan_y > dlo->ext[1])) {
			/* nothing in this subtree draws on this line */
			d = lws_dll2_get_next(&dlo->list);
			rs->st[rs->sp].dlo = d ? lws_container_of(d, lws_dlo_t,
							  list) : NULL;
			continue;
		}

//		lwsl_notice("%s: curr %d: %d %d %d %d\n", __func__, (int)rs->curr, (int)dlo->box.x.whole, (int)dlo->box.y.whole, (int)dlo->box.w.whole, (int)dlo->box.h.whole);

		lws_fx_add(&co.x, &rs->st[rs->sp].co.x, &dlo->box.x);
		lws_fx_add(&co.y, &rs->st[rs->sp].co.y, &dlo->box.y);

		co.w = dlo->box.w;
		co.h = dlo->box.h;

		lws_fx_add(&t2, &co.y, &dlo->box.h);

		/*
		 * A streaming render destroys DLOs once the cursor has
		 * passed below them, to bound memory on small targets.  A
		 * retained render (eg, an interactive viewport that will be
		 * re-scanned at other vertical offsets) must keep them.
		 * Either way there is no need to draw them, but what is in
		 * them may reach further down than they do, eg, positioned
		 * below them, unless they clip it
		 */

		passed = rs->curr > lws_fx_roundup(&t2) &&
			 dlo->box.h.whole > 3;

		if (!passed && rs->curr >= co.y.whole - 1) {
			/* the renderer finds the dlo at the top of the stack */
			rs->opacity = dlo_opacity(&rs->st[rs->sp], dlo);
			dlo_clip_line(rs, &rs->st[rs->sp]);
			r = dlo->render(rs);
			if (r)
				/* it's rendered again when we come back */
				return r;
		}

		/* next sibling at this level if any */

		d = lws_dll2_get_next(&dlo->list);
		rs->st[rs->sp].dlo = d ? lws_container_of(d, lws_dlo_t, list) :
					 NULL;

		if (passed) {
			if (lws_dll2_is_empty(&dlo->children) ||
			    dlo->flag_clip) {
				if (!rs->retained)
					lws_display_dlo_destroy(&dlo);
				continue;
			}

			rs->opacity = dlo_opacity(&rs->st[rs->sp], dlo);
		} else if (rs->curr < co.y.whole - 1)
			/* not reached it yet */
			continue;

		/* go into any children */

		if (lws_dll2_is_empty(&dlo->children))
			continue;

		if (rs->sp + 1 == LWS_ARRAY_SIZE(rs->st)) {
			lwsl_err("%s: DLO stack overflow B\n", __func__);
			return LWS_SRET_FATAL;
		}

		rs->st[rs->sp + 1].opacity = rs->opacity;
		dlo_child_clip(rs, &rs->st[rs->sp], dlo, &co,
			       &rs->st[rs->sp + 1]);
		rs->st[++rs->sp].dlo = lws_container_of(
				lws_dll2_get_head(&dlo->children), lws_dlo_t,
				list);
		rs->st[rs->sp].co = co;
	}

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_display_list_render_line(lws_display_render_state_t *rs)
{
	lws_alloc_arena_t a = lws_alloc_arena_set(LWS_ALLOC_ARENA_BULK);
	lws_stateful_ret_t r = _lws_display_list_render_line(rs);

	lws_alloc_arena_set(a);

	return r;
}

/*
 * Cell dlos still on the row / column list must be unlinked before the owner
 * is freed, or destroying them later walks freed memory
 */

static int
dlo_clean_table_rows(lws_dll2_t *d, void *user)
{
	lhp_table_row_t *r = lws_container_of(d, lhp_table_row_t, list);

	while (lws_dll2_get_head(&r->row_dlos))
		lws_dll2_remove(lws_dll2_get_head(&r->row_dlos));

	lws_dll2_remove(d);
	lws_free(r);

	return 0;
}

static int
dlo_clean_table_cols(lws_dll2_t *d, void *user)
{
	lhp_table_col_t *c = lws_container_of(d, lhp_table_col_t, list);

	while (lws_dll2_get_head(&c->col_dlos))
		lws_dll2_remove(lws_dll2_get_head(&c->col_dlos));

	lws_dll2_remove(d);
	lws_free(c);

	return 0;
}

void
lws_display_dlo_destroy(lws_dlo_t **r)
{
	lws_dlo_t *rr = *r;

	if (!rr)
		return;

	lws_dll2_remove(&rr->list);
	lws_dll2_remove(&rr->col_list);
	lws_dll2_remove(&rr->row_list);

	while(!lws_dll2_is_empty(&rr->children)) {
		lws_dlo_t *d = lws_container_of(lws_dll2_get_head(&rr->children),
							lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}

	lws_dll2_foreach_safe(&rr->table_cols, NULL, dlo_clean_table_cols);
	lws_dll2_foreach_safe(&rr->table_rows, NULL, dlo_clean_table_rows);

	if (rr->_destroy)
		rr->_destroy(rr);

	lws_free_set_NULL(*r);
}

void
lws_display_list_destroy(struct lws_context *cx, lws_displaylist_t *dl)
{
	if (!dl)
		return;

	//lws_dlo_ss_stop_any_active(cx);

	while(!lws_dll2_is_empty(&dl->dl)) {
		lws_dlo_t *d = lws_container_of(lws_dll2_get_head(&dl->dl), lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}

	/* what it held is free: pages that didn't fit may fit now */
	lws_fonts_remote_heap_freed(cx);

#if defined(LWS_WITH_FOOTPRINT)
	lws_footprint_unregister(&dl->fp);
#endif
}

lws_dlo_filesystem_t *
lws_dlo_file_register(struct lws_context *cx, const lws_dlo_filesystem_t *f)
{
	const lws_dlo_filesystem_t *b;
	lws_dlo_filesystem_t *a;

	b = lws_dlo_file_choose(cx, f->name);

	if (b) {
		lwsl_info("%s: replacing dlo file %s\n", __func__, b->name);
		lws_dlo_file_unregister((lws_dlo_filesystem_t **)&b);
	}

	a = lws_malloc(sizeof(*a), __func__);
	if (!a)
		return NULL;

	*a = *f;
	lws_dll2_clear(&a->list);
	lws_dll2_add_tail(&a->list, &cx->dlo_file);

	lwsl_info("%s: dlo file %s registered\n", __func__, a->name);

	return a;
}

/*
 * Only needed with heap-alloc'd lws_dlo_filesystem_t
 */

void
lws_dlo_file_unregister(lws_dlo_filesystem_t **f)
{
	if (!*f)
		return;

	lws_dll2_remove(&(*f)->list);
	lws_free_set_NULL(*f);
}

void
lws_dlo_file_unregister_by_name(struct lws_context *cx, const char *name)
{
	lws_dlo_filesystem_t *a;

	a = (lws_dlo_filesystem_t *)lws_dlo_file_choose(cx, name);
	if (!a)
		return;

	lws_dll2_remove(&a->list);
	lws_free_set_NULL(a);
}

static int
_lws_dlo_file_destroy(struct lws_dll2 *d, void *user)
{
	lws_free(d);
	return 0;
}

void
lws_dlo_file_destroy(struct lws_context *cx)
{
	lws_dll2_foreach_safe(&cx->dlo_file, NULL, _lws_dlo_file_destroy);
}

const lws_dlo_filesystem_t *
lws_dlo_file_choose(struct lws_context *cx, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&cx->dlo_file)) {
		const lws_dlo_filesystem_t *pn = lws_container_of(p,
						lws_dlo_filesystem_t, list);

		if (!strcmp(name, pn->name))
			return pn;

	} lws_end_foreach_dll(p);

	return NULL;
}

static int
lws_display_id_destroy(struct lws_dll2 *d, void *user)
{
	lws_display_id_t *id = lws_container_of(d, lws_display_id_t, list);

	lws_dll2_remove(&id->list);
	lws_free(id);
	return 0;
}

void
lws_display_render_free_ids(lws_display_render_state_t *rs)
{
	lws_dlo_t *dlo;

	/* nothing is left pointing at them */

	for (dlo = dl_first(&rs->displaylist); dlo;
	     dlo = dl_next(&rs->displaylist, dlo))
		dlo->id = NULL;

	lws_dll2_foreach_safe(&rs->ids, NULL, lws_display_id_destroy);
}

lws_display_id_t *
lws_display_render_get_id(lws_display_render_state_t *rs, const char *_id)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&rs->ids)) {
		lws_display_id_t *id = lws_container_of(d, lws_display_id_t, list);

		if (!strcmp(_id, id->id))
			return id;

	} lws_end_foreach_dll(d);

	return NULL;
}

lws_display_id_t *
lws_display_render_add_id(lws_display_render_state_t *rs, const char *_id, void *priv)
{
	lws_display_id_t *id;

	id = lws_display_render_get_id(rs, _id);
	if (id) {
		id->priv_user = priv;
		return id;
	}

	id = lws_zalloc(sizeof(*id), __func__);

	if (id) {
		lws_strncpy(id->id, _id, sizeof(id->id));
		id->priv_user = priv;
		lws_dll2_add_tail(&id->list, &rs->ids);
	}

	return id;
}

void
lws_display_render_dump_ids(lws_dll2_owner_t *ids)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(ids)) {
		lws_display_id_t *id = lws_container_of(d, lws_display_id_t, list);

		if (!id->exists)
			lwsl_notice("  id: '%s' (not present)\n", id->id);
		else
			lwsl_notice("  id: '%s', (%d,%d), %dx%d\n", id->id,
					(int)id->box.x.whole, (int)id->box.y.whole,
					(int)id->box.w.whole, (int)id->box.h.whole);
	} lws_end_foreach_dll(d);
}

#if defined (LWS_WITH_FILE_OPS)

int
dlo_filesystem_fops_close(lws_fop_fd_t *fop_fd)
{
	lws_free_set_NULL(*fop_fd);
	return 0;
}

lws_fileofs_t
dlo_filesystem_fops_seek_cur(lws_fop_fd_t fop_fd,
			     lws_fileofs_t pos)
{
	if (pos < 0)
		fop_fd->pos = 0;
	else
		if (pos >= (long long)fop_fd->len)
			fop_fd->pos = fop_fd->len;
		else
			fop_fd->pos = (lws_filepos_t)pos;

	return (lws_fileofs_t)fop_fd->pos;
}

int
dlo_filesystem_fops_write(lws_fop_fd_t fop_fd, lws_filepos_t *amount,
			  uint8_t *buf, lws_filepos_t len)
{
	*amount = 0;

	return -1;
}

int
dlo_filesystem_fops_read(lws_fop_fd_t fop_fd, lws_filepos_t *amount,
		    uint8_t *buf, lws_filepos_t len)
{
	const uint8_t *p = (uint8_t *)fop_fd->filesystem_priv;
	lws_filepos_t amt = *amount;

	*amount = 0;
	if (fop_fd->len <= fop_fd->pos)
		return 0;

	if (amt > fop_fd->len - fop_fd->pos)
		amt = fop_fd->len - fop_fd->pos;

	if (amt > len)
		amt = len;

	memcpy(buf, p + fop_fd->pos, (size_t)amt);
	fop_fd->pos += amt;

	*amount = amt;

	return 0;
}

lws_fop_fd_t
lws_dlo_filesystem_fops_open(const struct lws_plat_file_ops *fops_own,
			     const struct lws_plat_file_ops *fops,
			     const char *vfs_path, const char *vpath,
			     lws_fop_flags_t *flags)
{
	const lws_dlo_filesystem_t *f = NULL;
	lws_fop_fd_t fop_fd;

	// lwsl_err("%s: %s\n", __func__, vpath);

	f = lws_dlo_file_choose(fops->cx, vpath);
	if (f) {
		/* we will handle it then */
		fop_fd = lws_zalloc(sizeof(*fop_fd), __func__);
		if (!fop_fd)
			return NULL;

		fop_fd->fops = fops_own;
		fop_fd->filesystem_priv = (void *)f->data;
		fop_fd->pos = 0;
		fop_fd->len = f->len;

		// lwsl_notice("%s: Opened %s\n", __func__, vpath);

		return fop_fd;
	} else
		lwsl_err("%s: failed to open %s\n", __func__, vpath);

	return NULL;
}

const struct lws_plat_file_ops lws_dlo_fops = {
	.LWS_FOP_OPEN		= lws_dlo_filesystem_fops_open,
	.LWS_FOP_CLOSE		= dlo_filesystem_fops_close,
	.LWS_FOP_SEEK_CUR	= dlo_filesystem_fops_seek_cur,
	.LWS_FOP_READ		= dlo_filesystem_fops_read,
	.LWS_FOP_WRITE		= dlo_filesystem_fops_write,
	.fi = { { "dlofs/", 6 } },
};

#endif

#if defined(LWS_WITH_DLO_ASSET_CACHE)
struct lws_cache_ttl_lru *
lws_dlo_asset_cache(struct lws_context *cx)
{
	return cx->dlo_asset_l1;
}
#endif
