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
 * Display List LHP layout
 *
 * The basic flow is logical elements exist in a stack as they are parsed, the
 * job of lhp_displaylist_layout() is to translate these into a tree of DLOs,
 * having parent-child relationships with (x,y) of the DLO box being an offset
 * into a local origin formed from the DLO parent box (which in turn may be
 * a child with its origin defined by its parent, etc).
 *
 * The element stack only exists while it and its parent elements are being
 * parsed, it goes out of scope as the element ends.  So we must create related
 * DLOs by stream-parsing, while we still have everything relevant to hand.
 *
 * This gets us out of having to run around fixing up DLO (x,y) as we do the
 * layout, since the DLO parent-child relationships are static even if their
 * content size isn't.
 *
 *
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

/*
 * HTML Elements we can deal with for layout
 */

enum {
	/* 0 is no match */
	LHP_ELEM_BR = 1,
	LHP_ELEM_DIV,
	LHP_ELEM_TABLE,
	LHP_ELEM_TR,
	LHP_ELEM_TD,
	LHP_ELEM_IMG,
};

static const struct {
	const char	*elem;
	uint8_t		elem_len;
} elems[] = {
	{ "br",		2 },
	{ "div",	3 },
	{ "table",	5 },
	{ "tr",		2 },
	{ "td",		2 },
	{ "img",	3 },
};

/*
 * Newline moves the psb->cury to cover text that was already placed using the
 * old psb->cury as to top of it.  So a final newline on the last line of text
 * does not create an extra blank line.
 */

static const lws_fx_t two = { 2,0 };

static void
newline(lhp_ctx_t *ctx, lhp_pstack_t *psb, lhp_pstack_t *ps,
	lws_displaylist_t *dl)
{
	int16_t group_baseline = 9999, group_height = 0;
	lws_fx_t line_height = { 0, 0 }, w, add, ew, t1;
	const struct lcsp_atr *a;
	lws_dlo_t *dlo, *d, *d1;
	int t = 0;

	if (!psb || !ps) {
		lwsl_err("%s: psb/ps NULL!\n", __func__);
		return;
	}

	dlo = (lws_dlo_t *)psb->dlo;

	lws_fx_add(&w, lws_csp_px(ps->css_padding[CCPAS_LEFT], ps),
		       lws_csp_px(ps->css_padding[CCPAS_RIGHT], ps));

	if (lws_fx_comp(&w, &psb->widest) > 0)
		psb->widest = w;

	if (!dlo || !dlo->children.tail)
		return;

	d = lws_container_of(dlo->children.tail, lws_dlo_t, list);

	/*
	 * We may be at the end of a line of text
	 *
	 * Figure out the biggest height on the line, and the total width
	 */

	while (d) {
		t |= d->_destroy == lws_display_dlo_text_destroy;
		/* find the "worst" height on the line */
		if (lws_fx_comp(&d->box.h, &line_height) > 0)
			line_height = d->box.h;

		if (d->_destroy == lws_display_dlo_text_destroy) {
			lws_dlo_text_t *text = lws_container_of(d,
						lws_dlo_text_t, dlo.list);

			if (text->font_y_baseline < group_baseline)
				group_baseline = text->font_y_baseline;
			if (text->font_height > group_height)
				group_height = text->font_height;
		}

		if (!d->flag_runon)
			break;
		d = lws_container_of(d->list.prev, lws_dlo_t, list);
	};

	/* mark the related text dlos with information about group bl and h,
	 * offset box y to align to group baseline if necessary */

	d1 = d;
	while (d) {
		if (d->_destroy == lws_display_dlo_text_destroy) {
			lws_dlo_text_t *t1 = lws_container_of(d1,
						lws_dlo_text_t, dlo.list);
			lws_fx_t ft;

			t1->group_height = group_height;
			t1->group_y_baseline = group_baseline;

			ft.whole = (t1->font_height - t1->font_y_baseline) -
					(group_height - group_baseline);
			ft.frac = 0;

			lws_fx_sub(&t1->dlo.box.y,  &t1->dlo.box.y, &ft);
		}
		if (!d1->list.next)
			break;
		d1 = lws_container_of(d1->list.next, lws_dlo_t, list);
	};

	w = psb->curx;
	ew = ctx->ic.wh_px[0];
	if (psb->css_width && psb->css_width->unit != LCSP_UNIT_NONE)
		ew = *lws_csp_px(psb->css_width, psb);
	lws_fx_sub(&ew, &ew, lws_csp_px(ps->css_margin[CCPAS_RIGHT], ps));
	lws_fx_sub(&ew, &ew, lws_csp_px(ps->css_padding[CCPAS_RIGHT], ps));

	if (lws_fx_comp(&w, &psb->widest) > 0)
		psb->widest = w;

	if (!t) /* no textual children to newline (eg, <div></div>) */
		return;

	 /*
	  * now is our chance to fix up dlos that are part of the line for
	  * text-align rule of the container.
	  */

	a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_TEXT_ALIGN);
	if (a) {

		switch (a->propval) {
		case LCSP_PROPVAL_CENTER:
			add = *lws_csp_px(ps->css_padding[CCPAS_LEFT], ps);
			lws_fx_sub(&t1, &ew, &w);
			lws_fx_div(&t1, &t1, &two);
			lws_fx_add(&add, &add, &t1);
			goto fixup;
		case LCSP_PROPVAL_RIGHT:
			lws_fx_sub(&add, &ew, &w);
			lws_fx_sub(&add, &add, &d->box.x);

fixup:
			lws_fx_add(&t1, &add, &w);
			if (lws_fx_comp(&t1, &psb->widest) > 0)
				psb->widest = t1;

			do {
				lws_fx_add(&d->box.x, &d->box.x, &add);
				if (!d->list.next)
					break;
				d = lws_container_of(d->list.next, lws_dlo_t,
							list);
			} while (1);
			break;
		default:
			break;
		}
	}

	lws_fx_add(&psb->cury, &psb->cury, &line_height);
	lws_fx_set(psb->curx, 0, 0);
	psb->dlo_set_curx = NULL;
	psb->dlo_set_cury = NULL;
	psb->runon = 0;
}

void
lhp_set_dlo_padding_margin(lhp_pstack_t *ps, lws_dlo_t *dlo)
{
	int n;

	for (n = 0; n < 4; n ++) {
		dlo->margin[n] = *lws_csp_px(ps->css_margin[n], ps);
		dlo->padding[n] = *lws_csp_px(ps->css_padding[n], ps);
	}
}

void
lhp_set_dlo_adjust_to_contents(lhp_pstack_t *ps)
{
	lhp_pstack_t *psb = lws_container_of(ps->list.prev, lhp_pstack_t, list);
	lws_dlo_dim_t dim;

	lws_dlo_contents(ps->dlo, &dim);
	lws_display_dlo_adjust_dims(ps->dlo, &dim);

	if (lws_fx_comp(&dim.w, &psb->widest) > 0)
		psb->widest = dim.w;

	if (lws_fx_comp(&dim.h, &psb->deepest) > 0)
		psb->deepest = dim.h;
}

static void
runon(lhp_pstack_t *ps, lws_dlo_t *dlo)
{
	dlo->flag_runon = (uint8_t)(ps->runon & 1);
	ps->runon = 1;
}

/*
 * Handle end-of-div, table, tr, td retrospective dlo dimension adjustment
 */

int
lws_lhp_dlo_adjust_div_type_element(lhp_ctx_t *ctx, lhp_pstack_t *psb,
				    lhp_pstack_t *pst, lhp_pstack_t *ps,
				    int elem_match)
{
	lws_dlo_rect_t *rect = (lws_dlo_rect_t *)ps->dlo;
	lws_fx_t t1, w, wd;
	char rd = 0;

	/* need this to get bottom clearance for next block */

	lws_fx_add(&ps->cury, &ps->cury,
		lws_csp_px(ps->css_padding[CCPAS_BOTTOM], ps));

	if (psb && ps->dlo &&
	    ps->css_margin[CCPAS_LEFT]->propval == LCSP_PROPVAL_AUTO &&
	    ps->css_margin[CCPAS_RIGHT]->propval == LCSP_PROPVAL_AUTO) {
		lws_dlo_rect_t *re = (lws_dlo_rect_t *)ps->dlo;

		/* h-center a div... find the available h space first */
		w = ctx->ic.wh_px[LWS_LHPREF_WIDTH];
		if (psb->css_width &&
		    psb->css_width->propval != LCSP_PROPVAL_AUTO)
			w = *lws_csp_px(psb->css_width, psb);

		lws_fx_sub(&t1, &w, &re->dlo.box.w);
		lws_fx_div(&t1, &t1, &two);
		lws_fx_sub(&wd, &t1, &re->dlo.box.x);

		lws_fx_add(&re->dlo.box.x, &re->dlo.box.x, &wd);
	}

	/* fix up the dimensions of div rectangle */
	if (!rect) {
		lwsl_notice("%s: elem %d: NO RECT\n", __func__, elem_match);
		return 1;
	}

	lhp_set_dlo_adjust_to_contents(ps);

	/* if a td, deal with columnar changes in width */

	if (ps->dlo->col_list.owner) {
		lhp_table_col_t *tc = lws_container_of(
				ps->dlo->col_list.owner,
				lhp_table_col_t, col_dlos);
		lws_fx_t wdelta, ow;

		ow = tc->width;
		lws_fx_set(tc->width, 0, 0);

		/* discover the new width of column */

		lws_start_foreach_dll(struct lws_dll2 *, c1,
				      lws_dll2_get_head(&tc->col_dlos)) {
			lws_dlo_t *dloc = lws_container_of(c1,
					lws_dlo_t, col_list);

			if (lws_fx_comp(&dloc->box.w, &tc->width) > 0)
				tc->width = dloc->box.w;
		} lws_end_foreach_dll(c1);

		/* new width - old column width */
		lws_fx_sub(&wdelta, &tc->width, &ow);

		/*
		 * Update all dlos in our column (except
		 * ourselves) with the increased column width
		 */

		lws_start_foreach_dll(struct lws_dll2 *, cold,
				      lws_dll2_get_head(&tc->col_dlos)) {
			lws_dlo_t *dloc = lws_container_of(cold,
					lws_dlo_t, col_list);

			if (dloc != &rect->dlo)
				/* we already did this for the
				 * affected dlo */
				lws_fx_add(&dloc->box.w,
					   &dloc->box.w, &wdelta);

			rd = 1;

			/* ... and then all of their row-mates
			 * to the right also need their
			 * x adjusting then */

			while (dloc->row_list.next) {
				dloc = lws_container_of(
					dloc->row_list.next,
					lws_dlo_t, row_list);

				lws_fx_add(&dloc->box.x,
					   &dloc->box.x, &wdelta);
			}
		} lws_end_foreach_dll(cold);
	}

	/* if a td, deal with row changes in height */

	if (ps->dlo->row_list.owner) {
		lhp_table_row_t *tr = lws_container_of(
				ps->dlo->row_list.owner,
				lhp_table_row_t, row_dlos);
		lws_fx_t hdelta, oh;

		oh = tr->height;
		lws_fx_set(tr->height, 0, 0);

		/* discover the new width of column */

		lws_start_foreach_dll(struct lws_dll2 *, r1,
				      lws_dll2_get_head(&tr->row_dlos)) {
			lws_dlo_t *dlor = lws_container_of(r1,
					lws_dlo_t, row_list);

			if (lws_fx_comp(&dlor->box.h, &tr->height) > 0)
				tr->height = dlor->box.h;
		} lws_end_foreach_dll(r1);

		/* new height - old row height */
		lws_fx_sub(&hdelta, &tr->height, &oh);

		/*
		 * Update all dlos in our row (except
		 * ourselves) with the increased row height
		 */

		lws_start_foreach_dll(struct lws_dll2 *, rold,
				      lws_dll2_get_head(&tr->row_dlos)) {
			lws_dlo_t *dlor = lws_container_of(rold,
					lws_dlo_t, row_list);

			if (dlor != &rect->dlo)
				/* we already did this for the
				 * affected dlo */
				lws_fx_add(&dlor->box.h,
					   &dlor->box.h, &hdelta);

			/* ... so all of their col-mates below
			 * also need their y adjusting then */

			while (dlor->col_list.next) {
				dlor = lws_container_of(
					dlor->col_list.next,
					lws_dlo_t, col_list);

				lws_fx_add(&dlor->box.y,
					   &dlor->box.y, &hdelta);
			}

			rd = 1;

		} lws_end_foreach_dll(rold);
	}

	/*
	 * Row dimensions have to be reassessed?
	 */

	if (rd) {
		lws_start_foreach_dll(struct lws_dll2 *, ro,
		       lws_dll2_get_head(&pst->dlo->children)) {
			lws_dlo_t *dlo = lws_container_of(ro, lws_dlo_t, list);
			lws_dlo_dim_t dim;

			lws_dlo_contents(dlo, &dim);
			lws_display_dlo_adjust_dims(dlo, &dim);
		} lws_end_foreach_dll(ro);
	}

	if (psb && ps->css_position->propval != LCSP_PROPVAL_ABSOLUTE) {
		/* parent should account for our margin */
		if (elem_match == LHP_ELEM_DIV) {
			lws_fx_add(&psb->curx, &psb->curx, &ps->widest);
			/* now we applied ps->widest, reset it */
			lws_fx_set(ps->widest, 0, 0);
			psb->dlo_set_curx = ps->dlo;
		} else {
			/* needed for margin between table cells */
			lws_fx_add(&psb->curx, &psb->curx, lws_csp_px(ps->css_margin[CCPAS_LEFT], ps));
			lws_fx_add(&psb->curx, &psb->curx, lws_csp_px(ps->css_margin[CCPAS_RIGHT], ps));
		}

		if (elem_match != LHP_ELEM_TD) {
			if (ps->css_display->propval != LCSP_PROPVAL_INLINE_BLOCK) {
				lws_fx_add(&psb->cury, &psb->cury, &ps->dlo->box.h);
				psb->dlo_set_cury = ps->dlo;
			}
		//	lws_fx_add(&psb->cury, &psb->cury, &ps->dlo->margin[CCPAS_BOTTOM]);
		} else
			ps->widest = ps->dlo->box.w;
	}

	return 0;
}

/*
 * Generic LHP displaylist object layout callback... converts html elements
 * into DLOs on the display list
 */

lws_stateful_ret_t
lhp_displaylist_layout(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *psb = NULL, *pst = NULL, *psp = NULL,
		     *ps = lws_container_of(ctx->stack.tail, lhp_pstack_t, list);
	struct lws_context *cx = (struct lws_context *)ctx->user1;
	lws_dl_rend_t *drt = (lws_dl_rend_t *)ctx->user;
	lws_fx_t br[4], t1, indent, ox, w, h;
	const lws_display_font_t *f = NULL;
	lhp_table_col_t *tcol = NULL;
	lhp_table_row_t *trow = NULL;
	lws_dlo_t *abut_x, *abut_y;
	uint32_t col = 0xff000000;
	lws_dlo_text_t *txt;
	const lcsp_atr_t *a;
	lws_dlo_image_t u;
	const char *pname;
	char lastm = 0;
	int elem_match;
	lws_box_t box;
	char url[128];
	int n, s = 0;

	/* default font choice */
	lws_font_choice_t fc = {
		.family_name		= "term, serif",
		.fixed_height		= 16,
		.weight			= 400,
	};

	if (!ps->font) {
		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_SIZE);
		if (a)
			fc.fixed_height = (uint16_t)a->u.i.whole;

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_FAMILY);
		if (a)
			fc.family_name = (const char *)&a[1];

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_WEIGHT);
		if (a) {
			switch (a->propval) {
			case LCSP_PROPVAL_BOLD:
				fc.weight = 700;
				break;
			case LCSP_PROPVAL_BOLDER:
				fc.weight = 800;
				break;
			default:
				if (a->u.i.whole)
					fc.weight = (uint16_t)a->u.i.whole;
				break;
			}
		}

		ps->font = lws_font_choose(cx, &fc);
	}
	f = ps->font;

	psb = lws_css_get_parent_block(ctx, ps);

	elem_match = 0;
	for (n = 0; n < (int)LWS_ARRAY_SIZE(elems); n++)
		if (ctx->npos == elems[n].elem_len &&
		    !memcmp(ctx->buf, elems[n].elem, elems[n].elem_len))
			elem_match = n + 1;

	switch (reason) {
	case LHPCB_CONSTRUCTED:
	case LHPCB_DESTRUCTED:
	case LHPCB_COMPLETE:
	case LHPCB_FAILED:
		break;

	case LHPCB_ELEMENT_START:

		switch (elem_match) {
		case LHP_ELEM_BR:
			newline(ctx, psb, ps, drt->dl);
			break;

		case LHP_ELEM_TR:
			if (!psb)
				break;

			pst = ps;
			while (pst && !pst->is_table)
				pst = lws_css_get_parent_block(ctx, pst);
			if (!pst) {
				lwsl_err("%s: td: no table found\n", __func__);
				break;
			}

			pst->curx.whole = 0;
			pst->curx.frac = 0;
			psb->dlo_set_curx = NULL;

			trow = lws_zalloc(sizeof(*trow), __func__);
			if (!trow) {
				lwsl_err("%s: OOM\n", __func__);
				return LWS_SRET_FATAL;
			}
			lws_dll2_add_tail(&trow->list, &pst->dlo->table_rows);
			trow = NULL;
			pst->td_idx = 0;

			goto do_rect;

		case LHP_ELEM_TD:
			if (!psb) {
				lwsl_err("%s: td: no psb found\n", __func__);
				break;
			}

			pst = ps;
			while (pst && !pst->is_table)
				pst = lws_css_get_parent_block(ctx, pst);
			if (!pst) {
				lwsl_err("%s: td: no table found\n", __func__);
				break;
			}

			if (pst->td_idx >= (int)pst->dlo->table_cols.count) {
				tcol = lws_zalloc(sizeof(*tcol), __func__);
				if (!tcol) {
					lwsl_err("%s: OOM\n", __func__);
					return LWS_SRET_FATAL;
				}
				lws_dll2_add_tail(&tcol->list, &pst->dlo->table_cols);
			} else {
				tcol = lws_container_of(pst->dlo->table_cols.head, lhp_table_col_t, list);
				n = pst->td_idx;
				while (n--)
					tcol = lws_container_of(tcol->list.next, lhp_table_col_t, list);
			}

			if (pst->dlo->table_rows.tail)
				trow = lws_container_of(pst->dlo->table_rows.tail, lhp_table_row_t, list);

			goto do_rect;

		case LHP_ELEM_TABLE:
			ps->is_table = 1;
			/* fallthru */
		case LHP_ELEM_DIV:

do_rect:
			lws_fx_set(box.x, 0, 0);
			lws_fx_set(box.y, 0, 0);
			lws_fx_set(box.h, 0, 0);
			lws_fx_set(box.w, 0, 0);
			abut_x = NULL;
			abut_y = NULL;

			if (ps->css_position->propval == LCSP_PROPVAL_ABSOLUTE) {
				box.x = *lws_csp_px(ps->css_pos[CCPAS_LEFT], ps);
				box.y = *lws_csp_px(ps->css_pos[CCPAS_TOP], ps);
			} else {
				if (psb) {

						/* margin adjusts our child box origin */
					lws_fx_add(&box.x, &psb->curx,
							lws_csp_px(ps->css_margin[CCPAS_LEFT], ps));
					box.y = psb->cury;
					abut_x = psb->dlo_set_curx;
					abut_y = psb->dlo_set_cury;
					//lws_fx_add(&box.y, &psb->cury,
					//	   lws_csp_px(ps->css_margin[CCPAS_TOP], ps));
				}
			}

			/* If there's an explicit width, try to go with that */

			if (ps->css_width &&
			    ps->css_width->unit != LCSP_UNIT_NONE &&
			    lws_fx_comp(lws_csp_px(ps->css_width, ps), &box.w) < 0)
				box.w = *lws_csp_px(ps->css_width, ps);

			/* !!! we rely on this being nonzero to not infinite loop at text layout */

			lws_fx_add(&box.w, &box.w,
			   lws_csp_px(ps->css_padding[CCPAS_LEFT], ps));
			lws_fx_add(&box.w, &box.w,
			   lws_csp_px(ps->css_padding[CCPAS_RIGHT], ps));

			ps->drt.w = box.w;
			ps->curx = *lws_csp_px(ps->css_padding[CCPAS_LEFT], ps);
			ps->cury = *lws_csp_px(ps->css_padding[CCPAS_TOP], ps);

			memset(br, 0, sizeof(br));

			if (ps->css_border_radius[0])
				br[0] = *lws_csp_px(ps->css_border_radius[0], ps);
			if (ps->css_border_radius[1])
				br[1] = *lws_csp_px(ps->css_border_radius[1], ps);
			if (ps->css_border_radius[2])
				br[2] = *lws_csp_px(ps->css_border_radius[2], ps);
			if (ps->css_border_radius[3])
				br[3] = *lws_csp_px(ps->css_border_radius[3], ps);

			psp = lws_container_of(ps->list.prev, lhp_pstack_t, list);

			ps->dlo = (lws_dlo_t *)lws_display_dlo_rect_new(drt->dl,
					ps->css_position->propval == LCSP_PROPVAL_ABSOLUTE ? NULL : psp->dlo,
					&box, br, ps->css_background_color ?
					  ps->css_background_color->u.rgba : 0);
			if (!ps->dlo) {
				lwsl_err("%s: FAILED to create rect\n", __func__);
				return LWS_SRET_FATAL;
			}

			ps->dlo->abut_x = abut_x;
			ps->dlo->abut_y = abut_y;

			if (psb)
				lws_fx_add(&psb->curx, &psb->curx,
					   lws_csp_px(ps->css_margin[CCPAS_RIGHT], ps));

			if (tcol)
				lws_dll2_add_tail(&ps->dlo->col_list, &tcol->col_dlos);
			if (trow)
				lws_dll2_add_tail(&ps->dlo->row_list, &trow->row_dlos);

			lws_lhp_tag_dlo_id(ctx, ps, ps->dlo);
			lhp_set_dlo_padding_margin(ps, ps->dlo);
			break;

		case LHP_ELEM_IMG:
			pname = lws_html_get_atr(ps, "src", 3);

			if (!psb)
				break;

			if (ps->css_position->propval == LCSP_PROPVAL_ABSOLUTE) {
				box.x = *lws_csp_px(ps->css_pos[CCPAS_LEFT], ps);
				box.y = *lws_csp_px(ps->css_pos[CCPAS_TOP], ps);
			} else {
				box.x = psb->curx;
				box.y = psb->cury;
			}

			lws_fx_set(box.x, 0, 0);
			lws_fx_set(box.y, 0, 0);

			if (psb) {
				lws_fx_add(&box.x, &box.x,
					lws_csp_px(psb->css_margin[CCPAS_LEFT], psb));
				lws_fx_add(&box.y, &box.y,
					lws_csp_px(psb->css_margin[CCPAS_TOP], psb));
			}

			box.h = ctx->ic.wh_px[1]; /* placeholder */
			lws_fx_sub(&box.w, &ctx->ic.wh_px[0], &box.x);

			if (ps->css_width &&
			    lws_fx_comp(lws_csp_px(ps->css_width, ps), &box.w) > 0)
				box.w = *lws_csp_px(ps->css_width, ps);

			if (lws_http_rel_to_url(url, sizeof(url),
						ctx->base_url, pname))
				break;

			if (lws_dlo_ss_find(cx, url, &u))
				break;

			lws_lhp_tag_dlo_id(ctx, ps, (lws_dlo_t *)(u.u.dlo_jpeg));

			w = *lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_WIDTH), ps);
			h = *lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_HEIGHT), ps);

			if (!w.whole || !h.whole) {
				w = ((lws_dlo_t *)(u.u.dlo_jpeg))->box.w;
				h = ((lws_dlo_t *)(u.u.dlo_jpeg))->box.w;
			}

			if (psb) {
				lws_fx_add(&psb->curx, &psb->curx, &w);
				lws_fx_add(&psb->cury, &psb->cury, &h);
				psb->dlo_set_curx = ps->dlo;
				psb->dlo_set_cury = ps->dlo;
				if (lws_fx_comp(&psb->curx, &psb->widest) > 0)
					psb->widest = psb->curx;
			}

			break;
		default:
			break;
		}
		break;

	case LHPCB_ELEMENT_END:

		if (ctx->npos == 2 && ctx->buf[0] == 'h' &&
		    ctx->buf[1] > '0' && ctx->buf[1] <= '6') {

			if (!psb)
				break;

			newline(ctx, psb, ps, drt->dl);
			lws_fx_add(&psb->cury, &psb->cury,
				lws_csp_px(ps->css_padding[CCPAS_BOTTOM], ps));
			lws_fx_add(&psb->cury, &psb->cury,
				lws_csp_px(ps->css_margin[CCPAS_BOTTOM], ps));
			break;
		}

		switch (elem_match) {

		case LHP_ELEM_TR:
			pst = ps;
			while (pst && !pst->is_table)
				pst = lws_css_get_parent_block(ctx, pst);
			if (!pst) {
				lwsl_err("%s:  /td: no table\n", __func__);
				break;
			}

			pst->tr_idx++;
			pst->td_idx = 0;
			goto do_end_rect;

		case LHP_ELEM_TD:
			pst = ps;
			while (pst && !pst->is_table)
				pst = lws_css_get_parent_block(ctx, pst);
			if (!pst) {
				lwsl_err("%s:  /td: no table\n", __func__);
				break;
			}
			pst->td_idx++;
			goto do_end_rect;


			/* fallthru */

		case LHP_ELEM_TABLE:
		case LHP_ELEM_DIV:
do_end_rect:
			ox = ps->curx;

			if (lws_fx_comp(&ox, &ps->widest) > 0)
				ps->widest = ox;

			newline(ctx, ps, ps, drt->dl);

			if (lws_lhp_dlo_adjust_div_type_element(ctx, psb, pst, ps, elem_match))
				break;

			if (lws_fx_comp(&ps->curx, &ps->widest) > 0)
				ps->widest = ps->curx;

			/* move parent on according to used area plus bottom margin */

			if (psb && ps->css_position->propval != LCSP_PROPVAL_ABSOLUTE) {

				switch (ps->css_display->propval) {
				case LCSP_PROPVAL_BLOCK:
				case LCSP_PROPVAL_TABLE:
				case LCSP_PROPVAL_TABLE_ROW:
					lws_fx_set(psb->curx, 0, 0);
					psb->dlo_set_curx = NULL;

					if (ps->css_display->propval == LCSP_PROPVAL_TABLE_ROW)
						break;
					lws_fx_add(&psb->cury, &psb->cury, lws_csp_px(ps->css_margin[CCPAS_BOTTOM], ps));
					break;

				case LCSP_PROPVAL_INLINE_BLOCK:
					//lws_fx_add(&psb->cury, &psb->cury, lws_csp_px(ps->css_margin[CCPAS_BOTTOM], ps));
					lws_fx_add(&psb->curx, &psb->curx, &ps->widest);
					lws_fx_add(&psb->curx, &psb->curx, lws_csp_px(ps->css_margin[CCPAS_RIGHT], ps));
					lws_fx_set(ps->widest, 0, 0);
					psb->dlo_set_curx = ps->dlo;
					psb->dlo_set_cury = ps->dlo;
					break;

				default:
					lws_fx_add(&psb->curx, &psb->curx, &ps->widest);
					psb->dlo_set_curx = ps->dlo;
					break;
				}

				if (lws_fx_comp(&psb->curx, &psb->widest) > 0)
					psb->widest = psb->curx;
			}

			ps->dlo = NULL;
			break;
		default:
			break;
		}
		break;

	case LHPCB_CONTENT:

		if (!ps->css_display ||
		    ps->css_display->propval == LCSP_PROPVAL_NONE)
			break;

		if (ps->css_color)
			col = ps->css_color->u.rgba;

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_SIZE);
		if (a)
			fc.fixed_height = (uint16_t)a->u.i.whole;

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_FAMILY);
		if (a)
			fc.family_name = (const char *)&a[1];

		for (n = 0; n < ctx->npos; n++)
			if (ctx->buf[n] == '\n')
				s++;

		if (s == ctx->npos)
			return 0;

		/*
		 * Let's not deal with things off the bottom of the display
		 * surface.
		 */

		if (psb && psb->cury.whole > ctx->ic.wh_px[LWS_LHPREF_HEIGHT].whole)
			return 0;

		if (!psb)
			return 0;

		f = lws_font_choose(cx, &fc);

		n = s;
		while (n < ctx->npos) {
			int m;

			lws_fx_set(box.x, 0, 0);
			lws_fx_set(box.y, 0, 0);
			lws_fx_set(box.w, 0, 0);

			if (n == s && !(psb->runon & 1)) {
				lws_fx_set(indent, 0, 0);
			} else
				indent = psb->curx;
			lws_fx_add(&box.x, &indent,
					  lws_csp_px(ps->css_padding[CCPAS_LEFT], ps));
			lws_fx_add(&box.y, &box.y, &psb->cury);

			box.h.whole = (int32_t)f->choice.fixed_height;
			box.h.frac = 0;

			if (psb->css_width &&
				(psb->css_width->propval == LCSP_PROPVAL_AUTO ||
				 ps->css_width->propval == LCSP_PROPVAL_AUTO)) {
				//lws_fx_sub(&box.w, &ctx->ic.wh_px[0], &box.x);
				box.w = ctx->ic.wh_px[0];
			} else {
				lws_fx_sub(&t1, &psb->drt.w,
					   lws_csp_px(psb->css_padding[CCPAS_LEFT], psb));
				lws_fx_sub(&box.w, &t1,
					   lws_csp_px(psb->css_padding[CCPAS_RIGHT], psb));
			}

			if (!box.w.whole)
				lws_fx_sub(&box.w, &ctx->ic.wh_px[0], &box.x);
			assert(psb);

			txt = lws_display_dlo_text_new(drt->dl,
					(lws_dlo_t *)psb->dlo, &box, f);
			if (!txt) {
				lwsl_err("%s: failed to alloc text\n", __func__);
				return 1;
			}
			runon(psb, &txt->dlo);
			txt->flags |= LWSDLO_TEXT_FLAG_WRAP;

			lhp_set_dlo_padding_margin(ps, &txt->dlo);

//			a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_TEXT_ALIGN);

			//lwsl_hexdump_notice(ctx->buf + n, (size_t)(ctx->npos - n));
			m = lws_display_dlo_text_update(txt, col, indent,
							ctx->buf + n,
							(size_t)(ctx->npos - n));
			if (m < 0) {
				lwsl_err("text_update ret %d\n", m);
				break;
			}

			if (m == 2 && lastm)
				return 0;

			lastm = m == 2;

			n = (int)((size_t)n + txt->text_len);
			txt->dlo.box.w = txt->bounding_box.w;
			txt->dlo.box.h = txt->bounding_box.h;

			lws_fx_add(&psb->curx, &psb->curx, &txt->bounding_box.w);
			psb->dlo_set_curx = &txt->dlo;

			//lwsl_user("%s: bounding width %d, m: %d, text %.*s\n",
			//	  __func__, txt->bounding_box.w.whole, m,
			//	  ctx->npos, ctx->buf);

			if (m > 0) { /* wrapping */
				newline(ctx, psb, ps, drt->dl);
				lws_fx_set(ps->curx, 0, 0);
				lws_fx_set(psb->curx, 0, 0);
				psb->dlo_set_curx = NULL;
				lws_fx_add(&ps->cury, &ps->cury, &txt->bounding_box.h);
				psb->dlo_set_cury = &txt->dlo;
			}
		}
		break;
	case LHPCB_COMMENT:
		break;
	}

	return 0;
}
