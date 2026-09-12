/*
 * lws abstract display
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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
 * Display List LHP layout
 *
 * The html parser calls lhp_displaylist_layout() as elements start and end
 * and as text arrives, with the element stack describing everything that is
 * still open.  This turns that into a tree of DLOs whose (x, y) are offsets
 * inside the parent DLO's box.
 *
 * The approach follows CSS block / inline formatting, streamed:
 *
 *  - a block-level element gets its width from its containing block when it
 *    opens, so everything inside it can be placed as it arrives, and only its
 *    height has to wait until it closes.  Nothing already placed is moved
 *    afterwards (except the small x / y fix-ups of a line when it ends).
 *
 *  - inline elements (span, b, a...) are style scopes only; their text goes
 *    into line boxes of the nearest block container.  Text is wrapped as it
 *    arrives against the remaining width of the line, a line ends when it is
 *    full, on <br>, or when a block starts or ends.
 *
 *  - boxes whose width depends on their content (inline-block, absolute with
 *    auto width, table cells) are laid out against the width available to
 *    them while tracking the width they would take unwrapped (max-content).
 *    At close the box shrinks to min(max-content, available): if it shrinks,
 *    nothing inside it had wrapped, so nothing needs re-laying out.
 *
 *  - table columns are sized when the table closes, from the min- and
 *    max-content widths of the cells, and the cells moved into place.  Cells
 *    were laid out at the full table width, so a cell whose column ends up
 *    narrower than its max-content width keeps its wider lines (a later
 *    refinement would re-wrap those).
 *
 * Memory stays proportional to what is displayed: text past the bottom of
 * the surface is dropped as it arrives, and nothing is buffered beyond the
 * DLOs themselves.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

enum {
	LHP_BOX_NONE,		/* no box at all (html, thead, unknown) */
	LHP_BOX_INLINE,		/* style scope in the parent's lines */
	LHP_BOX_BLOCK,
	LHP_BOX_LIST_ITEM,
	LHP_BOX_INLINE_BLOCK,
	LHP_BOX_TABLE,
	LHP_BOX_ROW,
	LHP_BOX_CELL,
	LHP_BOX_BR,
	LHP_BOX_IMG,
	LHP_BOX_BODY,
};

static const lws_fx_t fx_0 = { 0, 0 }, fx_2 = { 2, 0 }, fx_100 = { 100, 0 };

/*
 * The cascade only fills in a css_* attribute pointer if some stanza that is
 * active for the element actually sets that property.  An absent attribute is
 * completely normal and means "use the CSS initial value for the property"
 */

static int
lhp_propval(const lcsp_atr_t *a, int initial)
{
	return a && a->unit == LCSP_UNIT_NONE ? a->propval : initial;
}

void
lhp_set_dlo_padding_margin(lhp_pstack_t *ps, lws_dlo_t *dlo)
{
	int n;

	for (n = 0; n < 4; n ++) {
		if (ps->css_margin[n])
			dlo->margin[n] = *lws_csp_px(ps->css_margin[n], ps);
		else
			lws_fx_set(dlo->margin[n], 0, 0);
		if (ps->css_padding[n])
			dlo->padding[n] = *lws_csp_px(ps->css_padding[n], ps);
		else
			lws_fx_set(dlo->padding[n], 0, 0);
	}
}

static int
lhp_tag_is(lhp_pstack_t *ps, const char *name, size_t len)
{
	const lhp_atr_t *a;

	if (lws_dll2_is_empty(&ps->atr))
		return 0;

	a = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);

	return a->name_len == len && !strncasecmp((const char *)&a[1], name, len);
}

/*
 * Resolve a css length to px; percentages are of base (the containing
 * block's content width), absent attributes and keywords are 0
 */

static lws_fx_t
lhp_len(lhp_pstack_t *ps, const lcsp_atr_t *a, const lws_fx_t *base)
{
	lws_fx_t t;

	if (!a || a->unit == LCSP_UNIT_NONE)
		return fx_0;

	if (a->unit == LCSP_UNIT_LENGTH_PERCENT) {
		lws_fx_mul(&t, &a->u.i, base);
		lws_fx_div(&t, &t, &fx_100);

		return t;
	}

	return *lws_csp_px(a, ps);
}

static int
lhp_is_auto(const lcsp_atr_t *a)
{
	return a && a->unit == LCSP_UNIT_NONE && a->propval == LCSP_PROPVAL_AUTO;
}

static lws_fx_t
lhp_fx_max(const lws_fx_t *a, const lws_fx_t *b)
{
	return lws_fx_comp(a, b) > 0 ? *a : *b;
}

static lws_fx_t
lhp_fx_min(const lws_fx_t *a, const lws_fx_t *b)
{
	return lws_fx_comp(a, b) < 0 ? *a : *b;
}

static lhp_pstack_t *
lhp_parent(lhp_pstack_t *ps)
{
	if (!lws_dll2_get_prev(&ps->list))
		return NULL;

	return lws_container_of(lws_dll2_get_prev(&ps->list), lhp_pstack_t,
				list);
}

/* the nearest block container at or above ps */

static lhp_pstack_t *
lhp_container(lhp_pstack_t *ps)
{
	while (ps) {
		if (ps->is_block && ps->dlo)
			return ps;
		ps = lhp_parent(ps);
	}

	return NULL;
}

static int
lhp_box_type(lhp_pstack_t *ps)
{
	const lcsp_atr_t *a = ps->css_display;

	if (lhp_tag_is(ps, "br", 2))
		return LHP_BOX_BR;
	if (lhp_tag_is(ps, "img", 3))
		return LHP_BOX_IMG;
	if (lhp_tag_is(ps, "body", 4))
		return LHP_BOX_BODY;
	if (lhp_tag_is(ps, "html", 4))
		return LHP_BOX_NONE;

	if (!a)
		return LHP_BOX_INLINE;

	if (a->unit == LCSP_UNIT_STRING) {
		const char *s = (const char *)&a[1];

		/* css3 display values the value lextable doesn't know */
		if (a->value_len >= 6 && !strncmp(s, "inline", 6))
			return LHP_BOX_INLINE_BLOCK; /* inline-flex etc */
		if (a->value_len >= 8 && !strncmp(s, "contents", 8))
			return LHP_BOX_NONE;

		return LHP_BOX_BLOCK; /* flex, grid, flow-root... */
	}

	switch (a->propval) {
	case LCSP_PROPVAL_BLOCK:
	case LCSP_PROPVAL_TABLE_CAPTION:
		return LHP_BOX_BLOCK;
	case LCSP_PROPVAL_LIST_ITEM:
		return LHP_BOX_LIST_ITEM;
	case LCSP_PROPVAL_INLINE_BLOCK:
	case LCSP_PROPVAL_INLINE_TABLE:
		return LHP_BOX_INLINE_BLOCK;
	case LCSP_PROPVAL_TABLE:
		return LHP_BOX_TABLE;
	case LCSP_PROPVAL_TABLE_ROW:
		return LHP_BOX_ROW;
	case LCSP_PROPVAL_TABLE_CELL:
		return LHP_BOX_CELL;
	case LCSP_PROPVAL_TABLE_HEADER_GROUP:
	case LCSP_PROPVAL_TABLE_ROW_GROUP:
	case LCSP_PROPVAL_TABLE_FOOTER_GROUP:
	case LCSP_PROPVAL_TABLE_COLUMN:
	case LCSP_PROPVAL_TABLE_COLUMN_GROUP:
		return LHP_BOX_NONE;
	default:
		return LHP_BOX_INLINE;
	}
}

static lws_display_colour_t
lhp_colour(const lcsp_atr_t *a, lws_display_colour_t def)
{
	if (a && a->unit == LCSP_UNIT_RGBA)
		return a->u.rgba;

	return def;
}

static void
lhp_choose_font(struct lws_context *cx, lhp_ctx_t *ctx, lhp_pstack_t *ps)
{
	lws_font_choice_t fc = {
		.family_name		= "term, serif",
		.fixed_height		= 16,
		.weight			= 400,
	};
	const lcsp_atr_t *a;

	if (ps->font)
		return;

	if (ps->font_size.whole > 0)
		fc.fixed_height = (uint16_t)(ps->font_size.whole +
			(ps->font_size.frac >= LWS_FX_FRACTION_MSD / 2));

	a = lws_css_get_prop_atr_ps(ctx, ps, LCSP_PROP_FONT_FAMILY);
	if (a && a->unit == LCSP_UNIT_STRING)
		fc.family_name = (const char *)&a[1];

	a = lws_css_get_prop_atr_ps(ctx, ps, LCSP_PROP_FONT_WEIGHT);
	if (a) {
		if (a->unit == LCSP_UNIT_NONE) {
			switch (a->propval) {
			case LCSP_PROPVAL_BOLD:
			case LCSP_PROPVAL_BOLDER:
				fc.weight = 700;
				break;
			case LCSP_PROPVAL_LIGHTER:
				fc.weight = 300;
				break;
			default:
				break;
			}
		} else if (a->u.i.whole)
			fc.weight = (uint16_t)a->u.i.whole;
	}

	a = lws_css_get_prop_atr_ps(ctx, ps, LCSP_PROP_FONT_STYLE);
	if (a && a->unit == LCSP_UNIT_NONE &&
	    (a->propval == LCSP_PROPVAL_ITALIC ||
	     a->propval == LCSP_PROPVAL_OBLIQUE))
		fc.style = 1;

	ps->font = lws_font_choose(cx, &fc);
}

/*
 * Line boxes
 */

static void
lhp_line_reset(lhp_pstack_t *c)
{
	lws_fx_set(c->curx, 0, 0);
	lws_fx_set(c->line_h, 0, 0);
	lws_fx_set(c->nowrap, 0, 0);
	c->line_first = NULL;
	c->line_asc = 0;
	c->line_desc = 0;
	c->has_line = 0;
	c->last_space = 1;
}

/*
 * The line being built in container c is complete: work out its height and
 * baseline, align the items on it vertically, apply text-align, and move
 * the cursor below it
 */

static void
lhp_line_end(lhp_ctx_t *ctx, lhp_pstack_t *c)
{
	lws_fx_t lh, shift, t, ah;
	const lcsp_atr_t *a;
	lws_dll2_t *d;

	if (!c->has_line) {
		/*
		 * Nothing was placed, but inline padding / margins may have
		 * moved the cursor: start the next line from the left anyway,
		 * or a cursor already past the width would never come back
		 */
		lhp_line_reset(c);
		return;
	}

	lws_fx_set(ah, c->line_asc + c->line_desc, 0);
	lh = lhp_fx_max(&ah, &c->line_h);

	lws_fx_set(shift, 0, 0);
	if (!c->shrink) {
		a = lws_css_get_prop_atr_ps(ctx, c, LCSP_PROP_TEXT_ALIGN);
		if (a && a->unit == LCSP_UNIT_NONE) {
			lws_fx_sub(&t, &c->cw, &c->curx);
			if (t.whole > 0) {
				if (a->propval == LCSP_PROPVAL_CENTER)
					lws_fx_div(&shift, &t, &fx_2);
				else if (a->propval == LCSP_PROPVAL_RIGHT)
					shift = t;
			}
		}
	}

	d = c->line_first ? &c->line_first->list : NULL;
	while (d) {
		lws_dlo_t *dlo = lws_container_of(d, lws_dlo_t, list);

		if (dlo->_destroy == lws_display_dlo_text_destroy) {
			lws_dlo_text_t *txt = lws_container_of(dlo,
							lws_dlo_text_t, dlo);

			/* text sits on the line's baseline */
			lws_fx_set(t, c->line_asc - txt->font_y_baseline, 0);
		} else if (dlo->flag_float) {
			/* floats hang from the top of the line */
			lws_fx_set(t, 0, 0);
		} else
			/* boxes and images sit on the bottom of the line */
			lws_fx_sub(&t, &lh, &dlo->box.h);

		lws_fx_add(&dlo->box.y, &c->oy, &c->cury);
		lws_fx_add(&dlo->box.y, &dlo->box.y, &t);
		lws_fx_add(&dlo->box.x, &dlo->box.x, &shift);

		d = lws_dll2_get_next(d);
	}

	lws_fx_add(&c->cury, &c->cury, &lh);
	lhp_line_reset(c);
}

/* an item was placed on the line at the cursor: account for it */

static void
lhp_line_item(lhp_pstack_t *c, lws_dlo_t *dlo, const lws_fx_t *w,
	      const lws_fx_t *h)
{
	if (!c->has_line) {
		c->has_line = 1;
		c->line_first = dlo;
	}

	lws_fx_add(&c->curx, &c->curx, w);
	lws_fx_add(&c->nowrap, &c->nowrap, w);
	c->maxc = lhp_fx_max(&c->maxc, &c->nowrap);

	if (h)
		c->line_h = lhp_fx_max(&c->line_h, h);
}

static void
lhp_line_text_metrics(lhp_pstack_t *c, lws_dlo_text_t *txt)
{
	if (txt->font_y_baseline > c->line_asc)
		c->line_asc = txt->font_y_baseline;
	if (txt->font_height - txt->font_y_baseline > c->line_desc)
		c->line_desc = (int16_t)(txt->font_height -
					 txt->font_y_baseline);
}

/*
 * Text content
 */

static lws_stateful_ret_t
lhp_content(lhp_ctx_t *ctx, lhp_pstack_t *ps, lws_dl_rend_t *drt)
{
	const char *text = ctx->buf;
	size_t len = (size_t)ctx->npos;
	lhp_pstack_t *c = lhp_container(ps);
	lws_display_colour_t col;
	const lcsp_atr_t *bg = NULL, *ws;
	lws_fx_t pl, pr, pt, pb, avail, total, word;
	lws_box_t box;
	int nowrap;

	if (!c || !ps->font)
		return 0;

	/* white-space: nowrap / pre: the text stays on its line and
	 * overflows rather than wrapping */
	ws = lws_css_get_prop_atr_ps(ctx, ps, LCSP_PROP_WHITE_SPACE);
	nowrap = ws && ws->unit == LCSP_UNIT_NONE &&
		 (ws->propval == LCSP_PROPVAL_NOWRAP ||
		  ws->propval == LCSP_PROPVAL_PRE);

	/* text that lands below the surface can never be seen */
	if (c->abs_y + c->cury.whole > ctx->ic.wh_px[LWS_LHPREF_HEIGHT].whole)
		return 0;

	col = lhp_colour(ps->css_color, LWSDC_RGBA(0, 0, 0, 255));

	if (ps->is_inline && ps->css_background_color &&
	    ps->css_background_color->unit == LCSP_UNIT_RGBA)
		bg = ps->css_background_color;

	pl = lhp_len(ps, ps->css_padding[CCPAS_LEFT], &c->cw);
	pr = lhp_len(ps, ps->css_padding[CCPAS_RIGHT], &c->cw);
	pt = lhp_len(ps, ps->css_padding[CCPAS_TOP], &c->cw);
	pb = lhp_len(ps, ps->css_padding[CCPAS_BOTTOM], &c->cw);

	while (len) {
		lws_dlo_rect_t *rect = NULL;
		lws_dlo_text_t *txt;
		int r;

		/* collapse whitespace at the start of a line / after a space */

		while (len && *text == ' ' && c->last_space) {
			text++;
			len--;
		}
		if (!len)
			break;

		lws_fx_sub(&avail, &c->cw, &c->curx);
		if (nowrap)
			avail = ctx->ic.wh_px[LWS_LHPREF_WIDTH];
		if (avail.whole <= 0 && c->curx.whole > 0) {
			lhp_line_end(ctx, c);
			continue;
		}

		if (bg) {
			lws_fx_t radii[4];
			int n;

			for (n = 0; n < 4; n++)
				radii[n] = ps->css_border_radius[n] ?
					*lws_csp_px(ps->css_border_radius[n], ps) :
					fx_0;

			lws_fx_set(box.x, 0, 0);
			lws_fx_set(box.y, 0, 0);
			lws_fx_set(box.w, 0, 0);
			lws_fx_set(box.h, 0, 0);
			rect = lws_display_dlo_rect_new(drt->dl, c->dlo, &box,
							radii, bg->u.rgba);
		}

		lws_fx_add(&box.x, &c->ox, &c->curx);
		lws_fx_add(&box.y, &c->oy, &c->cury);
		box.w = avail.whole > 0 ? avail : ctx->ic.wh_px[LWS_LHPREF_WIDTH];
		lws_fx_set(box.h, 0, 0);

		txt = lws_display_dlo_text_new(drt->dl, c->dlo, &box, ps->font);
		if (!txt) {
			if (rect)
				lws_display_dlo_destroy((lws_dlo_t **)&rect);
			return LWS_SRET_FATAL;
		}

		r = lws_display_dlo_text_update(txt, col, fx_0, text, len);

		if (r < 0) {
			lws_display_dlo_destroy((lws_dlo_t **)&txt);
			if (rect)
				lws_display_dlo_destroy((lws_dlo_t **)&rect);
			return LWS_SRET_FATAL;
		}

		if (r == 2) {
			/* nothing fits in what's left of the line */
			if (c->curx.whole > 0) {
				lws_display_dlo_destroy((lws_dlo_t **)&txt);
				if (rect)
					lws_display_dlo_destroy((lws_dlo_t **)&rect);
				lhp_line_end(ctx, c);
				continue;
			}

			/*
			 * A word wider than the whole line: it has to go on
			 * a line by itself and overflow
			 */
			lws_display_dlo_text_measure(txt, text, len, &total,
						     &word);
			lws_fx_add(&txt->dlo.box.w, &word, &fx_2);
			r = lws_display_dlo_text_update(txt, col, fx_0, text,
							len);
			if (r < 0 || r == 2 || !txt->text_len) {
				lws_display_dlo_destroy((lws_dlo_t **)&txt);
				if (rect)
					lws_display_dlo_destroy((lws_dlo_t **)&rect);
				return 0;
			}
		}

		txt->dlo.box.w = txt->bounding_box.w;
		txt->dlo.box.h = txt->bounding_box.h;
		lhp_line_text_metrics(c, txt);

		if (rect) {
			/* the inline element's background, behind the text */
			lws_fx_sub(&rect->dlo.box.x, &txt->dlo.box.x, &pl);
			lws_fx_sub(&rect->dlo.box.y, &txt->dlo.box.y, &pt);
			lws_fx_add(&rect->dlo.box.w, &txt->dlo.box.w, &pl);
			lws_fx_add(&rect->dlo.box.w, &rect->dlo.box.w, &pr);
			lws_fx_add(&rect->dlo.box.h, &txt->dlo.box.h, &pt);
			lws_fx_add(&rect->dlo.box.h, &rect->dlo.box.h, &pb);
			lhp_line_item(c, &rect->dlo, &fx_0, &rect->dlo.box.h);
		}

		lws_display_dlo_text_measure(txt, txt->text, txt->text_len,
					     &total, &word);
		c->minc = lhp_fx_max(&c->minc, &word);

		lhp_line_item(c, &txt->dlo, &txt->dlo.box.w, NULL);
		c->last_space = txt->text[txt->text_len - 1] == ' ';

		text += txt->text_len;
		len -= txt->text_len;

		if (r == 1)
			/* wrapped: the rest goes on the next line */
			lhp_line_end(ctx, c);
	}

	return 0;
}

/*
 * Replaced inline element: <img>
 */

static void
lhp_place_image(lhp_ctx_t *ctx, lhp_pstack_t *ps, lhp_pstack_t *c)
{
	lws_dlo_t *dlo = ps->dlo;
	lws_fx_t w, h, ml, mr, t;
	const char *p;

	if (!dlo || !c)
		return;

	/* a shared dlo for an asset used twice belongs to its first user */
	if (lws_dll2_owner(&dlo->list) != &c->dlo->children)
		return;

	w = lhp_len(ps, ps->css_width, &c->cw);
	h = lhp_len(ps, ps->css_height, &c->cw);

	p = lws_html_get_atr(ps, "width", 5);
	if (p && !w.whole)
		lws_fx_set(w, atoi(p), 0);
	p = lws_html_get_atr(ps, "height", 6);
	if (p && !h.whole)
		lws_fx_set(h, atoi(p), 0);

	if (dlo->box.w.whole < 0 || dlo->box.h.whole < 0) {
		/* asset failed: take no space */
		lws_fx_set(dlo->box.w, 0, 0);
		lws_fx_set(dlo->box.h, 0, 0);
		return;
	}

	if (!w.whole && !h.whole) {
		w = dlo->box.w;
		h = dlo->box.h;
	} else if (!w.whole && dlo->box.h.whole) {
		/* scale to keep the aspect ratio */
		lws_fx_mul(&t, &h, &dlo->box.w);
		lws_fx_div(&w, &t, &dlo->box.h);
	} else if (!h.whole && dlo->box.w.whole) {
		lws_fx_mul(&t, &w, &dlo->box.h);
		lws_fx_div(&h, &t, &dlo->box.w);
	}

	ml = lhp_len(ps, ps->css_margin[CCPAS_LEFT], &c->cw);
	mr = lhp_len(ps, ps->css_margin[CCPAS_RIGHT], &c->cw);

	lws_fx_add(&t, &c->curx, &ml);
	lws_fx_add(&t, &t, &w);
	lws_fx_add(&t, &t, &mr);
	if (c->curx.whole > 0 && lws_fx_comp(&t, &c->cw) > 0)
		lhp_line_end(ctx, c);

	lws_fx_add(&dlo->box.x, &c->ox, &c->curx);
	lws_fx_add(&dlo->box.x, &dlo->box.x, &ml);
	lws_fx_add(&dlo->box.y, &c->oy, &c->cury);
	dlo->box.w = w;
	dlo->box.h = h;

	lws_fx_add(&t, &ml, &w);
	lws_fx_add(&t, &t, &mr);
	lhp_line_item(c, dlo, &t, &h);
	c->minc = lhp_fx_max(&c->minc, &t);
	c->last_space = 0;
}

/*
 * Tables
 */

static lhp_pstack_t *
lhp_table_of(lhp_pstack_t *ps)
{
	ps = lhp_parent(ps);
	while (ps && !ps->is_table)
		ps = lhp_parent(ps);

	return ps;
}

static lhp_table_col_t *
lhp_table_col(lws_dlo_t *tdlo, unsigned int idx)
{
	lws_dll2_t *d = lws_dll2_get_head(&tdlo->table_cols);

	while (d && idx--)
		d = lws_dll2_get_next(d);

	if (d)
		return lws_container_of(d, lhp_table_col_t, list);

	return NULL;
}

/* border-spacing, or the 2px default */

static lws_fx_t
lhp_table_spacing(lhp_ctx_t *ctx, lhp_pstack_t *t)
{
	const lcsp_atr_t *a = lws_css_get_prop_atr_ps(ctx, t,
						LCSP_PROP_BORDER_SPACING);
	const lcsp_atr_t *bc = lws_css_get_prop_atr_ps(ctx, t,
						LCSP_PROP_BORDER_COLLAPSE);

	if (bc && bc->unit == LCSP_UNIT_NONE &&
	    bc->propval == LCSP_PROPVAL_COLLAPSE)
		return fx_0;

	if (a && a->unit != LCSP_UNIT_NONE)
		return lhp_len(t, a, &t->cw);

	return fx_2;
}

/*
 * All the cells are known: size the columns (CSS automatic table layout,
 * simplified) and move the cells into their final places
 */

static void
lhp_table_close(lhp_ctx_t *ctx, lhp_pstack_t *t)
{
	lws_fx_t sp = lhp_table_spacing(ctx, t), avail, smin, smax, t1, t2,
		 sdiff, x, tw;
	unsigned int n = lws_dll2_count(&t->dlo->table_cols);

	if (!n)
		return;

	/* width for columns after the spacing between and around them */

	lws_fx_set(t1, (int32_t)(n + 1), 0);
	lws_fx_mul(&t1, &t1, &sp);
	lws_fx_sub(&avail, &t->cw, &t1);

	lws_fx_set(smin, 0, 0);
	lws_fx_set(smax, 0, 0);
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&t->dlo->table_cols)) {
		lhp_table_col_t *col = lws_container_of(d, lhp_table_col_t,
							list);

		lws_fx_add(&smin, &smin, &col->min_w);
		lws_fx_add(&smax, &smax, &col->max_w);
	} lws_end_foreach_dll(d);

	lws_fx_sub(&sdiff, &smax, &smin);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&t->dlo->table_cols)) {
		lhp_table_col_t *col = lws_container_of(d, lhp_table_col_t,
							list);

		if (lws_fx_comp(&smax, &avail) <= 0) {
			col->width = col->max_w;
			if (t->explicit_w && smax.whole > 0) {
				/* stretch to the given table width */
				lws_fx_mul(&t1, &col->max_w, &avail);
				lws_fx_div(&col->width, &t1, &smax);
			}
		} else if (lws_fx_comp(&smin, &avail) >= 0 ||
			   sdiff.whole <= 0)
			col->width = col->min_w;
		else {
			/* min + share of the slack in proportion to max - min */
			lws_fx_sub(&t1, &avail, &smin);
			lws_fx_sub(&t2, &col->max_w, &col->min_w);
			lws_fx_mul(&t1, &t1, &t2);
			lws_fx_div(&t1, &t1, &sdiff);
			lws_fx_add(&col->width, &col->min_w, &t1);
		}
	} lws_end_foreach_dll(d);

	tw = sp;
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&t->dlo->table_cols)) {
		lhp_table_col_t *col = lws_container_of(d, lhp_table_col_t,
							list);

		lws_fx_add(&tw, &tw, &col->width);
		lws_fx_add(&tw, &tw, &sp);
	} lws_end_foreach_dll(d);

	/* place the cells of every row */

	lws_start_foreach_dll(struct lws_dll2 *, rd,
			      lws_dll2_get_head(&t->dlo->children)) {
		lws_dlo_t *row = lws_container_of(rd, lws_dlo_t, list);
		unsigned int idx = 0;

		if (!row->flag_row)
			continue;

		row->box.w = tw;
		x = sp;

		lws_start_foreach_dll(struct lws_dll2 *, cd,
				      lws_dll2_get_head(&row->children)) {
			lws_dlo_t *cell = lws_container_of(cd, lws_dlo_t, list);
			lhp_table_col_t *col;

			if (!cell->flag_cell)
				continue;

			col = lhp_table_col(t->dlo, idx++);
			if (!col)
				break;

			cell->box.x = x;
			cell->box.w = col->width;
			lws_fx_add(&x, &x, &col->width);
			lws_fx_add(&x, &x, &sp);
		} lws_end_foreach_dll(cd);
	} lws_end_foreach_dll(rd);

	if (!t->explicit_w) {
		t->cw = tw;
		lws_fx_add(&t->dlo->box.w, &tw, lws_csp_px(
					t->css_padding[CCPAS_LEFT], t));
		lws_fx_add(&t->dlo->box.w, &t->dlo->box.w, lws_csp_px(
					t->css_padding[CCPAS_RIGHT], t));
	}
}

/*
 * Blocks
 */

static void
lhp_list_marker(lhp_ctx_t *ctx, lhp_pstack_t *ps, lws_dl_rend_t *drt)
{
	lhp_pstack_t *list = lhp_parent(ps);
	lws_dlo_text_t *txt;
	const lcsp_atr_t *a;
	char m[16] = "-"; /* the embedded fonts rarely carry U+2022 */
	lws_box_t box;
	size_t ml;

	while (list && !lhp_tag_is(list, "ol", 2) && !lhp_tag_is(list, "ul", 2))
		list = lhp_parent(list);

	a = lws_css_get_prop_atr_ps(ctx, ps, LCSP_PROP_LIST_STYLE_TYPE);
	if (a && a->unit == LCSP_UNIT_NONE && a->propval == LCSP_PROPVAL_NONE)
		return;

	if ((list && lhp_tag_is(list, "ol", 2)) ||
	    (a && a->unit == LCSP_UNIT_NONE &&
	     a->propval == LCSP_PROPVAL_DECIMAL)) {
		if (list)
			list->idx++;
		lws_snprintf(m, sizeof(m), "%u.", list ? list->idx : 1u);
	}
	ml = strlen(m);

	lws_fx_set(box.x, 0, 0);
	box.y = ps->oy;
	lws_fx_set(box.w, 40, 0);
	lws_fx_set(box.h, 0, 0);
	txt = lws_display_dlo_text_new(drt->dl, ps->dlo, &box, ps->font);
	if (!txt)
		return;

	if (lws_display_dlo_text_update(txt, lhp_colour(ps->css_color,
				LWSDC_RGBA(0, 0, 0, 255)), fx_0, m, ml) < 0 ||
	    !txt->text_len) {
		lws_display_dlo_destroy((lws_dlo_t **)&txt);
		return;
	}

	txt->dlo.box.w = txt->bounding_box.w;
	txt->dlo.box.h = txt->bounding_box.h;

	/* right-aligned, just left of the content */
	lws_fx_set(box.x, -6, 0);
	lws_fx_sub(&txt->dlo.box.x, &box.x, &txt->dlo.box.w);
	lws_fx_add(&txt->dlo.box.x, &txt->dlo.box.x, &ps->ox);
}

static lws_stateful_ret_t
lhp_block_open(lhp_ctx_t *ctx, lhp_pstack_t *ps, lhp_pstack_t *c, int type,
	       lws_dl_rend_t *drt)
{
	lws_fx_t ml, mr, mt, pl, pr, pt, w, x, y, t, radii[4], base;
	lws_dlo_t *parent = c ? c->dlo : NULL;
	lhp_pstack_t *tbl = NULL;
	lws_box_t box;
	int n, pos;

	base = c ? c->cw : ctx->ic.wh_px[LWS_LHPREF_WIDTH];

	ml = lhp_len(ps, ps->css_margin[CCPAS_LEFT], &base);
	mr = lhp_len(ps, ps->css_margin[CCPAS_RIGHT], &base);
	mt = lhp_len(ps, ps->css_margin[CCPAS_TOP], &base);
	pl = lhp_len(ps, ps->css_padding[CCPAS_LEFT], &base);
	pr = lhp_len(ps, ps->css_padding[CCPAS_RIGHT], &base);
	pt = lhp_len(ps, ps->css_padding[CCPAS_TOP], &base);

	pos = lhp_propval(ps->css_position, LCSP_PROPVAL_STATIC);
	ps->is_abs = pos == LCSP_PROPVAL_ABSOLUTE || pos == LCSP_PROPVAL_FIXED;
	ps->is_ilevel = type == LHP_BOX_INLINE_BLOCK;

	if (type != LHP_BOX_ROW && type != LHP_BOX_CELL && !ps->is_abs) {
		const lcsp_atr_t *fl = lws_css_get_prop_atr_ps(ctx, ps,
							LCSP_PROP_FLOAT);

		/* floats: on the line, no wrap-around (yet) */
		if (fl && fl->unit == LCSP_UNIT_NONE &&
		    (fl->propval == LCSP_PROPVAL_LEFT ||
		     fl->propval == LCSP_PROPVAL_RIGHT)) {
			ps->is_ilevel = 1;
			ps->is_float = 1;
		}
	}

	/* an explicit width is the content width */

	ps->explicit_w = ps->css_width && !lhp_is_auto(ps->css_width) &&
			 ps->css_width->unit != LCSP_UNIT_NONE;
	ps->explicit_h = ps->css_height && !lhp_is_auto(ps->css_height) &&
			 ps->css_height->unit != LCSP_UNIT_NONE &&
			 ps->css_height->unit != LCSP_UNIT_LENGTH_PERCENT;

	lws_fx_set(w, 0, 0);
	if (ps->explicit_w) {
		w = lhp_len(ps, ps->css_width, &base);
		lws_fx_add(&w, &w, &pl);
		lws_fx_add(&w, &w, &pr);
	}

	lws_fx_set(x, 0, 0);
	lws_fx_set(y, 0, 0);

	switch (type) {
	case LHP_BOX_ROW:
		tbl = lhp_table_of(ps);
		if (!tbl || !c)
			return 0;
		/* rows stack in the table; cells are placed in them */
		if (c->has_line)
			lhp_line_end(ctx, c);
		y = c->cury;
		w = c->cw;
		lws_fx_set(ml, 0, 0);
		lws_fx_set(pl, 0, 0);
		lws_fx_set(pr, 0, 0);
		lws_fx_set(pt, 0, 0);
		ps->is_row = 1;
		break;

	case LHP_BOX_CELL:
		tbl = lhp_table_of(ps);
		if (!tbl || !c || !c->is_row)
			return 0;
		/* provisional: laid out at the full table width, placed
		 * properly when the table closes */
		x = c->curx;
		if (!ps->explicit_w) {
			w = tbl->cw;
			ps->shrink = 1;
		}
		lws_fx_set(ml, 0, 0);
		ps->is_cell = 1;
		ps->idx = c->idx++;
		if (!lhp_table_col(tbl->dlo, ps->idx)) {
			lhp_table_col_t *col = lws_zalloc(sizeof(*col),
							  __func__);
			if (!col)
				return LWS_SRET_FATAL;
			lws_dll2_add_tail(&col->list, &tbl->dlo->table_cols);
		}
		break;

	default:
		if (ps->is_abs) {
			/*
			 * From the surface origin; auto width shrinks.  With
			 * no parent the dlo becomes a child of the body dlo,
			 * to be moved above the normal flow when the document
			 * is complete
			 */
			parent = NULL;
			x = lhp_len(ps, ps->css_pos[CCPAS_LEFT], &base);
			y = lhp_len(ps, ps->css_pos[CCPAS_TOP], &base);
			lws_fx_add(&x, &x, &ml);
			lws_fx_add(&y, &y, &mt);
			if (!ps->explicit_w) {
				lws_fx_sub(&w, &ctx->ic.wh_px[LWS_LHPREF_WIDTH],
					   &x);
				lws_fx_sub(&w, &w, &mr);
				ps->shrink = 1;
			}
			break;
		}

		if (!c)
			return 0;

		if (ps->is_ilevel) {
			/* on the current line; placed at close */
			lws_fx_add(&x, &c->curx, &ml);
			y = c->cury;
			if (!ps->explicit_w) {
				lws_fx_sub(&w, &c->cw, &ml);
				lws_fx_sub(&w, &w, &mr);
				ps->shrink = 1;
			}
			break;
		}

		/* block-level: below whatever is in the container so far */

		if (c->has_line)
			lhp_line_end(ctx, c);

		/* adjacent vertical margins collapse to the larger */
		t = lhp_fx_max(&c->pend_mb, &mt);
		lws_fx_add(&y, &c->cury, &t);
		lws_fx_set(c->pend_mb, 0, 0);

		if (ps->explicit_w) {
			if (lhp_is_auto(ps->css_margin[CCPAS_LEFT]) &&
			    lhp_is_auto(ps->css_margin[CCPAS_RIGHT])) {
				/* centred */
				lws_fx_sub(&t, &c->cw, &w);
				lws_fx_div(&x, &t, &fx_2);
				if (x.whole < 0)
					lws_fx_set(x, 0, 0);
			} else
				x = ml;
		} else {
			x = ml;
			lws_fx_sub(&w, &c->cw, &ml);
			lws_fx_sub(&w, &w, &mr);
		}
		break;
	}

	if (w.whole < 0)
		lws_fx_set(w, 0, 0);

	/* min-width / max-width bound the content width */
	{
		const lcsp_atr_t *mx = lws_css_get_prop_atr_ps(ctx, ps,
							LCSP_PROP_MAX_WIDTH),
				 *mn = lws_css_get_prop_atr_ps(ctx, ps,
							LCSP_PROP_MIN_WIDTH);
		lws_fx_t lim;

		if (mx && mx->unit != LCSP_UNIT_NONE) {
			lim = lhp_len(ps, mx, &base);
			lws_fx_add(&lim, &lim, &pl);
			lws_fx_add(&lim, &lim, &pr);
			if (lim.whole > 0 && lws_fx_comp(&w, &lim) > 0) {
				w = lim;
				if (!ps->is_ilevel && !ps->is_abs && c &&
				    lhp_is_auto(ps->css_margin[CCPAS_LEFT]) &&
				    lhp_is_auto(ps->css_margin[CCPAS_RIGHT])) {
					lws_fx_sub(&t, &c->cw, &w);
					lws_fx_div(&x, &t, &fx_2);
				}
			}
		}
		if (mn && mn->unit != LCSP_UNIT_NONE) {
			lim = lhp_len(ps, mn, &base);
			lws_fx_add(&lim, &lim, &pl);
			lws_fx_add(&lim, &lim, &pr);
			if (lws_fx_comp(&w, &lim) < 0)
				w = lim;
		}
	}

	memset(radii, 0, sizeof(radii));
	for (n = 0; n < 4; n++)
		if (ps->css_border_radius[n])
			radii[n] = *lws_csp_px(ps->css_border_radius[n], ps);

	if (c && !ps->is_abs) {
		lws_fx_add(&box.x, &c->ox, &x);
		lws_fx_add(&box.y, &c->oy, &y);
	} else {
		box.x = x;
		box.y = y;
	}
	box.w = w;
	lws_fx_set(box.h, 0, 0);

	ps->dlo = (lws_dlo_t *)lws_display_dlo_rect_new(drt->dl, parent, &box,
				radii, lhp_colour(ps->css_background_color, 0));
	if (!ps->dlo)
		return LWS_SRET_FATAL;

	ps->dlo->flag_abs = ps->is_abs;
	ps->dlo->flag_float = ps->is_float;
	if (pos != LCSP_PROPVAL_STATIC) {
		/* a positive z-index paints it above later siblings */
		const lcsp_atr_t *zi = lws_css_get_prop_atr_ps(ctx, ps,
							LCSP_PROP_Z_INDEX);

		ps->dlo->flag_zraise = zi && zi->unit == LCSP_UNIT_NUM &&
				       zi->u.i.whole > 0;
	}
	ps->dlo->flag_row = ps->is_row;
	ps->dlo->flag_cell = ps->is_cell;
	ps->dlo->flag_block = !ps->is_ilevel && !ps->is_abs && !ps->is_row &&
			      !ps->is_cell;

	lws_lhp_tag_dlo_id(ctx, ps, ps->dlo);
	lhp_set_dlo_padding_margin(ps, ps->dlo);

	ps->is_block = 1;
	ps->is_table = type == LHP_BOX_TABLE;
	ps->ox = pl;
	ps->oy = pt;
	lws_fx_sub(&ps->cw, &w, &pl);
	lws_fx_sub(&ps->cw, &ps->cw, &pr);
	if (ps->cw.whole < 0)
		lws_fx_set(ps->cw, 0, 0);
	lws_fx_set(ps->cury, 0, 0);
	lws_fx_set(ps->maxc, 0, 0);
	lws_fx_set(ps->minc, 0, 0);
	lws_fx_set(ps->pend_mb, 0, 0);
	if (!ps->is_row)
		ps->idx = ps->is_cell ? ps->idx : 0;
	lhp_line_reset(ps);
	ps->abs_y = (c && !ps->is_abs ? c->abs_y : 0) + box.y.whole;

	if (type == LHP_BOX_LIST_ITEM)
		lhp_list_marker(ctx, ps, drt);

	return 0;
}

/* the box for element ps is complete: give it a height and place it */

static void
lhp_block_close(lhp_ctx_t *ctx, lhp_pstack_t *ps)
{
	lhp_pstack_t *c = lhp_container(lhp_parent(ps)), *tbl;
	lws_fx_t pl, pr, pt, pb, ml, mr, mb, h, w, t, t1, base;

	base = c ? c->cw : ctx->ic.wh_px[LWS_LHPREF_WIDTH];

	if (ps->has_line)
		lhp_line_end(ctx, ps);

	pl = lhp_len(ps, ps->css_padding[CCPAS_LEFT], &base);
	pr = lhp_len(ps, ps->css_padding[CCPAS_RIGHT], &base);
	pt = lhp_len(ps, ps->css_padding[CCPAS_TOP], &base);
	pb = lhp_len(ps, ps->css_padding[CCPAS_BOTTOM], &base);
	ml = lhp_len(ps, ps->css_margin[CCPAS_LEFT], &base);
	mr = lhp_len(ps, ps->css_margin[CCPAS_RIGHT], &base);
	mb = lhp_len(ps, ps->css_margin[CCPAS_BOTTOM], &base);

	if (ps->is_row) {
		lws_fx_set(pt, 0, 0);
		lws_fx_set(pb, 0, 0);
		lws_fx_set(pl, 0, 0);
		lws_fx_set(pr, 0, 0);
	}
	if (ps->is_row || ps->is_cell) {
		lws_fx_set(ml, 0, 0);
		lws_fx_set(mr, 0, 0);
		lws_fx_set(mb, 0, 0);
	}

	if (ps->is_table)
		lhp_table_close(ctx, ps);

	/* height */

	if (ps->explicit_h)
		h = lhp_len(ps, ps->css_height, &base);
	else {
		h = ps->cury;
		if (pb.whole > 0 || ps->is_cell || ps->is_ilevel || ps->is_abs)
			/* the last child's bottom margin stays inside */
			lws_fx_add(&h, &h, &ps->pend_mb);
		else
			/* ... or collapses through us to our own */
			mb = lhp_fx_max(&mb, &ps->pend_mb);
	}

	{
		const lcsp_atr_t *mn = lws_css_get_prop_atr_ps(ctx, ps,
							LCSP_PROP_MIN_HEIGHT);

		if (mn && mn->unit != LCSP_UNIT_NONE &&
		    mn->unit != LCSP_UNIT_LENGTH_PERCENT) {
			t = lhp_len(ps, mn, &base);
			if (lws_fx_comp(&h, &t) < 0)
				h = t;
		}
	}

	if (ps->is_row) {
		/* as tall as the tallest cell, and so are the cells */
		h = ps->line_h;
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&ps->dlo->children)) {
			lws_dlo_t *cell = lws_container_of(d, lws_dlo_t, list);

			if (cell->flag_cell)
				cell->box.h = h;
		} lws_end_foreach_dll(d);
	}

	lws_fx_add(&ps->dlo->box.h, &h, &pt);
	lws_fx_add(&ps->dlo->box.h, &ps->dlo->box.h, &pb);

	/* width, if it was waiting for the content */

	if (ps->shrink && !ps->is_table) {
		w = lhp_fx_min(&ps->maxc, &ps->cw);
		if (lws_fx_comp(&w, &ps->minc) < 0)
			w = ps->minc;
		lws_fx_add(&ps->dlo->box.w, &w, &pl);
		lws_fx_add(&ps->dlo->box.w, &ps->dlo->box.w, &pr);

		/* block children were given the provisional width */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&ps->dlo->children)) {
			lws_dlo_t *ch = lws_container_of(d, lws_dlo_t, list);

			if (ch->flag_block &&
			    lws_fx_comp(&ch->box.w, &w) > 0)
				ch->box.w = w;
		} lws_end_foreach_dll(d);
		ps->cw = w;
	}

	w = ps->dlo->box.w;

	if (ps->is_abs || !c)
		return;

	if (ps->is_cell) {
		/* what the column needs, and a provisional place in the row */
		tbl = lhp_table_of(ps);
		if (tbl) {
			lhp_table_col_t *col = lhp_table_col(tbl->dlo, ps->idx);

			if (col) {
				lws_fx_add(&t, &ps->minc, &pl);
				lws_fx_add(&t, &t, &pr);
				col->min_w = lhp_fx_max(&col->min_w, &t);
				lws_fx_add(&t, &ps->maxc, &pl);
				lws_fx_add(&t, &t, &pr);
				if (ps->explicit_w)
					t = w;
				col->max_w = lhp_fx_max(&col->max_w, &t);
			}
		}
		lws_fx_add(&c->curx, &c->curx, &w);
		c->line_h = lhp_fx_max(&c->line_h, &ps->dlo->box.h);
		return;
	}

	if (ps->is_row) {
		lws_fx_t sp = lhp_table_spacing(ctx, c);

		lws_fx_add(&c->cury, &c->cury, &ps->dlo->box.h);
		lws_fx_add(&c->cury, &c->cury, &sp);
		return;
	}

	if (ps->is_ilevel) {
		/* an item on the container's line */
		lws_fx_add(&t, &ml, &w);
		lws_fx_add(&t, &t, &mr);

		lws_fx_add(&t1, &c->curx, &t);
		if (c->curx.whole > 0 && lws_fx_comp(&t1, &c->cw) > 0)
			lhp_line_end(ctx, c);

		lws_fx_add(&ps->dlo->box.x, &c->ox, &c->curx);
		lws_fx_add(&ps->dlo->box.x, &ps->dlo->box.x, &ml);
		lws_fx_add(&ps->dlo->box.y, &c->oy, &c->cury);

		lhp_line_item(c, ps->dlo, &t, &ps->dlo->box.h);
		c->minc = lhp_fx_max(&c->minc, &t);
		c->last_space = 0;
		return;
	}

	/* block-level: the container continues below us */

	lws_fx_sub(&t, &ps->dlo->box.y, &c->oy);
	lws_fx_add(&c->cury, &t, &ps->dlo->box.h);
	c->pend_mb = mb;
	lhp_line_reset(c);

	/* our unwrapped width counts for the container's shrink-to-fit */
	if (ps->explicit_w || ps->is_table)
		t = w;
	else {
		lws_fx_add(&t, &ps->maxc, &pl);
		lws_fx_add(&t, &t, &pr);
	}
	lws_fx_add(&t, &t, &ml);
	lws_fx_add(&t, &t, &mr);
	c->maxc = lhp_fx_max(&c->maxc, &t);
	lws_fx_add(&t, &ps->minc, &pl);
	lws_fx_add(&t, &t, &pr);
	c->minc = lhp_fx_max(&c->minc, &t);
}

/*
 * Painting order is list order.  Positioned boxes paint above the normal
 * flow whatever their place in the source: absolute ones (already children
 * of the body dlo) and any with a positive z-index are moved, in order, to
 * the end of the body's children once the document is complete, their
 * offsets converted to body-relative on the way.
 */

static void
lhp_collect_positioned(lws_dlo_t *parent, const lws_fx_t *ox,
		       const lws_fx_t *oy, lws_dll2_owner_t *raised)
{
	lws_start_foreach_dll_safe(lws_dll2_t *, d, d1,
				   lws_dll2_get_head(&parent->children)) {
		lws_dlo_t *dlo = lws_container_of(d, lws_dlo_t, list);
		lws_fx_t cx, cy;

		lws_fx_add(&cx, ox, &dlo->box.x);
		lws_fx_add(&cy, oy, &dlo->box.y);

		lhp_collect_positioned(dlo, &cx, &cy, raised);

		if (dlo->flag_abs || dlo->flag_zraise) {
			lws_dll2_remove(d);
			dlo->box.x = cx;
			dlo->box.y = cy;
			lws_dll2_add_tail(d, raised);
		}
	} lws_end_foreach_dll_safe(d, d1);
}

static void
lhp_raise_positioned(lws_dlo_t *body)
{
	lws_dll2_owner_t raised;

	memset(&raised, 0, sizeof(raised));
	lhp_collect_positioned(body, &fx_0, &fx_0, &raised);

	while (lws_dll2_get_head(&raised)) {
		lws_dll2_t *d = lws_dll2_get_head(&raised);

		lws_dll2_remove(d);
		lws_dll2_add_tail(d, &body->children);
	}
}

/*
 * Element start / end
 */

static void
lhp_body_open(lhp_pstack_t *ps)
{
	lws_fx_t ml, mr, mt, pl, pr, pt;
	const lws_fx_t *base = &ps->dlo->box.w;

	/* the parser made the body dlo cover the surface: inset the content */

	ml = lhp_len(ps, ps->css_margin[CCPAS_LEFT], base);
	mr = lhp_len(ps, ps->css_margin[CCPAS_RIGHT], base);
	mt = lhp_len(ps, ps->css_margin[CCPAS_TOP], base);
	pl = lhp_len(ps, ps->css_padding[CCPAS_LEFT], base);
	pr = lhp_len(ps, ps->css_padding[CCPAS_RIGHT], base);
	pt = lhp_len(ps, ps->css_padding[CCPAS_TOP], base);

	lws_fx_add(&ps->ox, &ml, &pl);
	lws_fx_add(&ps->oy, &mt, &pt);
	lws_fx_sub(&ps->cw, base, &ps->ox);
	lws_fx_sub(&ps->cw, &ps->cw, &mr);
	lws_fx_sub(&ps->cw, &ps->cw, &pr);
	lws_fx_set(ps->cury, 0, 0);
	lws_fx_set(ps->pend_mb, 0, 0);
	lws_fx_set(ps->maxc, 0, 0);
	lws_fx_set(ps->minc, 0, 0);
	ps->is_block = 1;
	ps->abs_y = 0;
	lhp_line_reset(ps);
}

static lws_stateful_ret_t
lhp_elem_start(lhp_ctx_t *ctx, lhp_pstack_t *ps, struct lws_context *cx,
	       lws_dl_rend_t *drt)
{
	lhp_pstack_t *c;
	lws_fx_t t;
	int type;

	lhp_choose_font(cx, ctx, ps);

	type = lhp_box_type(ps);

	if (type == LHP_BOX_BODY) {
		if (ps->dlo)
			lhp_body_open(ps);
		return 0;
	}

	if (!ps->in_body || type == LHP_BOX_NONE)
		return 0;

	c = lhp_container(lhp_parent(ps));

	switch (type) {
	case LHP_BOX_INLINE:
		ps->is_inline = 1;
		if (c) {
			/* horizontal margin / padding take space on the line */
			t = lhp_len(ps, ps->css_margin[CCPAS_LEFT], &c->cw);
			lws_fx_add(&c->curx, &c->curx, &t);
			t = lhp_len(ps, ps->css_padding[CCPAS_LEFT], &c->cw);
			lws_fx_add(&c->curx, &c->curx, &t);
		}
		return 0;

	case LHP_BOX_BR:
		if (!c)
			return 0;
		if (!c->has_line) {
			/* an empty line still takes a line's height */
			lws_dlo_text_t *txt;
			lws_box_t box;

			lws_fx_add(&box.x, &c->ox, &c->curx);
			lws_fx_add(&box.y, &c->oy, &c->cury);
			box.w = c->cw;
			lws_fx_set(box.h, 0, 0);
			txt = lws_display_dlo_text_new(drt->dl, c->dlo, &box,
						       ps->font);
			if (txt) {
				lws_display_dlo_text_update(txt, 0, fx_0, " ", 1);
				txt->dlo.box.w = txt->bounding_box.w;
				txt->dlo.box.h = txt->bounding_box.h;
				lhp_line_text_metrics(c, txt);
				lhp_line_item(c, &txt->dlo, &fx_0, NULL);
			}
		}
		lhp_line_end(ctx, c);
		return 0;

	case LHP_BOX_IMG:
		lhp_place_image(ctx, ps, c);
		return 0;

	default:
		return lhp_block_open(ctx, ps, c, type, drt);
	}
}

static lws_stateful_ret_t
lhp_elem_end(lhp_ctx_t *ctx, lhp_pstack_t *ps)
{
	lhp_pstack_t *c;
	lws_fx_t t;

	if (ps->is_inline) {
		c = lhp_container(lhp_parent(ps));
		if (c) {
			t = lhp_len(ps, ps->css_padding[CCPAS_RIGHT], &c->cw);
			lws_fx_add(&c->curx, &c->curx, &t);
			t = lhp_len(ps, ps->css_margin[CCPAS_RIGHT], &c->cw);
			lws_fx_add(&c->curx, &c->curx, &t);
		}
		return 0;
	}

	if (!ps->is_block || !ps->dlo || lhp_tag_is(ps, "body", 4))
		return 0;

	lhp_block_close(ctx, ps);

	return 0;
}

/*
 * Generic LHP displaylist object layout callback... converts html elements
 * into DLOs on the display list
 */

lws_stateful_ret_t
lhp_displaylist_layout(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	struct lws_context *cx = (struct lws_context *)ctx->user1;
	lws_dl_rend_t *drt = (lws_dl_rend_t *)ctx->user;

	switch (reason) {
	case LHPCB_ELEMENT_START:
		if (ps->hidden)
			return 0;
		return lhp_elem_start(ctx, ps, cx, drt);

	case LHPCB_ELEMENT_END:
		if (ps->hidden)
			return 0;
		return lhp_elem_end(ctx, ps);

	case LHPCB_CONTENT:
		if (ps->hidden || !ps->in_body)
			return 0;
		return lhp_content(ctx, ps, drt);

	case LHPCB_COMPLETE:
		/*
		 * Elements still open at the end of the document (no closing
		 * tags) are closed innermost first, so their heights get
		 * accounted for
		 */
		lws_start_foreach_dll_back(lws_dll2_t *, d,
					   lws_dll2_get_tail(&ctx->stack)) {
			lhp_pstack_t *p = lws_container_of(d, lhp_pstack_t,
							   list);

			if (!p->is_block || !p->dlo || p->hidden)
				continue;

			if (lhp_tag_is(p, "body", 4))
				lhp_line_end(ctx, p);
			else
				lhp_block_close(ctx, p);
		} lws_end_foreach_dll_back(d);

		if (drt && drt->dl && lws_dll2_get_head(&drt->dl->dl))
			lhp_raise_positioned(lws_container_of(
					lws_dll2_get_head(&drt->dl->dl),
					lws_dlo_t, list));
		break;

	default:
		break;
	}

	return 0;
}
