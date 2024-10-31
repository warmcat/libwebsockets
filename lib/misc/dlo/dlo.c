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

#define dlodump_loglevel                LLL_NOTICE
#if (_LWS_ENABLED_LOGS & dlodump_loglevel)
#define lwsl_dlodump(...)               _lws_log(dlodump_loglevel, __VA_ARGS__)
#else
#define lwsl_dlodump(...)
#endif

void
lws_display_dl_init(lws_displaylist_t *dl, lws_display_state_t *ds)
{
	lws_dll2_owner_clear(&dl->dl);
	dl->ds = ds;
}

int
lws_display_dlo_add(lws_displaylist_t *dl, lws_dlo_t *dlo_parent, lws_dlo_t *dlo)
{
	if (!dlo_parent && !dl->dl.head) {
		lws_dll2_add_tail(&dlo->list, &dl->dl);

		return 0;
	}

	if (!dlo_parent) {
		if (!dl->dl.head)
			return 0;

		dlo_parent = lws_container_of(dl->dl.head, lws_dlo_t, list);
	}

	lws_dll2_add_tail(&dlo->list, &dlo_parent->children);

	return 0;
}

void
lws_surface_set_px(const lws_surface_info_t *ic, uint8_t *line, int x,
		   const lws_display_colour_t *c)
{
	unsigned int alpha, ialpha;
	lws_display_colour_t oc;
	lws_display_colour_t y;
	uint8_t rgb[3];

	if (x < 0 || x >= ic->wh_px[0].whole)
		return;

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

/*
 * Recursively find out the total width and height of the contents of a DLO
 */

void
lws_dlo_contents(lws_dlo_t *parent, lws_dlo_dim_t *dim)
{
	lws_display_render_stack_t st[12]; /* DLO child stack */
	lws_dll2_t *d;
	lws_fx_t t1;
	int sp = 0;

	dim->w.whole = 0;
	dim->w.frac = 0;
	dim->h.whole = 0;
	dim->h.frac = 0;

	if (!parent)
		return;

	d = lws_dll2_get_head(&parent->children);
	if (!d)
		return;

	memset(&st, 0, sizeof(st));
	st[0].dlo = lws_container_of(d, lws_dlo_t, list);
	st[0].co.w.whole = 0;
	st[0].co.w.frac = 0;
	st[0].co.h.whole = 0;
	st[0].co.h.frac = 0;

	/* We are collecting worst dlo->box.x + dlo->box.w and .y + .h */

	while (sp || st[0].dlo) {
		lws_dlo_t *dlo = st[sp].dlo;

		if (!dlo) {
			if (!sp) {
				lwsl_err("%s: underflow\n", __func__);
				return;
			}

			if (lws_fx_comp(&st[sp].co.w, &st[sp - 1].co.w) > 0)
				st[sp - 1].co.w = st[sp].co.w;

			if (lws_fx_comp(&st[sp].co.h, &st[sp - 1].co.h) > 0)
				st[sp - 1].co.h = st[sp].co.h;

			// lwsl_notice("sp %d: passing back w: %d, h: %d\n", sp, st[sp - 1].co.w.whole, st[sp - 1].co.h.whole);

			sp--;

			continue;
		}

		lws_fx_add(&t1, &dlo->box.w, &dlo->box.x);
//		lws_fx_add(&t1, &t1, &dlo->margin[CCPAS_LEFT]);
		lws_fx_add(&t1, &t1, &dlo->padding[CCPAS_LEFT]);
//		lws_fx_add(&t1, &t1, &dlo->padding[CCPAS_RIGHT]);
//		lws_fx_add(&t1, &t1, &dlo->margin[CCPAS_RIGHT]);
		if (lws_fx_comp(&t1, &st[sp].co.w) > 0)
			st[sp].co.w = t1;

		lws_fx_add(&t1, &dlo->box.h, &dlo->box.y);
//		lws_fx_add(&t1, &t1, &dlo->margin[CCPAS_TOP]);
		lws_fx_add(&t1, &t1, &dlo->padding[CCPAS_TOP]);
//		lws_fx_add(&t1, &t1, &dlo->padding[CCPAS_BOTTOM]);
//		lws_fx_add(&t1, &t1, &dlo->margin[CCPAS_BOTTOM]);
		if (lws_fx_comp(&t1, &st[sp].co.h) > 0)
			st[sp].co.h = t1;

		d = dlo->list.next;
		if (d)
			st[sp].dlo = lws_container_of(d, lws_dlo_t, list);
		else
			st[sp].dlo = NULL;

		/* go into any children */

		if (dlo->children.head) {
			if (++sp == LWS_ARRAY_SIZE(st)) {
				lwsl_err("%s: DLO stack overflow\n", __func__);
				return;
			}
			st[sp].dlo = lws_container_of(
				dlo->children.head, lws_dlo_t, list);
			st[sp].co.w.whole = 0;
			st[sp].co.h.whole = 0;
			st[sp].co.w.frac = 0;
			st[sp].co.h.frac = 0;
		}
	}

	dim->w = st[0].co.w;
	dim->h = st[0].co.h;

	if (parent->col_list.owner) {
		lhp_table_col_t *tc = lws_container_of(parent->col_list.owner,
					lhp_table_col_t, col_dlos);

		if (lws_fx_comp(&dim->w, &tc->width) < 0) {
	//		lws_fx_add(&t1, &tc->width, &parent->padding[CCPAS_LEFT]);
	//		lws_fx_add(&dim->w, &tc->width, &parent->padding[CCPAS_RIGHT]);
			dim->w = tc->width;
		}
	}

	if (parent->row_list.owner) {
		lhp_table_row_t *tr = lws_container_of(parent->row_list.owner,
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
		lws_dlo_t *dp = lws_container_of(dlo->list.owner, lws_dlo_t, children);

		if (!dlo->list.owner)
			break;

		/*
		 * Adjust y pos of siblings below us
		 */

		do {
			dlo = lws_container_of(dlo->list.next, lws_dlo_t, list);
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
	lws_display_render_stack_t	st[12]; /* DLO child stack */
	int				sp = 0;
	lws_dll2_t *d = lws_dll2_get_head(&dl->dl);
#if (_LWS_ENABLED_LOGS & dlodump_loglevel)
	static const char * const ind = "                           ";
#endif
	char b[4][22], b1[4][22], dt[96];

	if (!d) {
		lwsl_notice("%s: empty dl\n", __func__);

		return;
	}

	lwsl_notice("%s\n", __func__);

	memset(&st, 0, sizeof(st));
	st[0].dlo = lws_container_of(d, lws_dlo_t, list);

	while (sp || st[0].dlo) {
		lws_dlo_t *dlo = st[sp].dlo;
		lws_box_t co;
		//lws_fx_t t2;

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

		d = dlo->list.next;
		if (d)
			st[sp].dlo = lws_container_of(d, lws_dlo_t, list);
		else
			st[sp].dlo = NULL;

		/* go into any children */

		if (dlo->children.head) {
			if (sp + 1 == LWS_ARRAY_SIZE(st)) {
				lwsl_err("%s: DLO stack overflow\n", __func__);
				return;
			}
			st[++sp].dlo = lws_container_of(
				dlo->children.head, lws_dlo_t, list);
			st[sp].co = co;
		}

	}
}
//#endif

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
			rs->sp--;
			continue;
		}

		lws_fx_add(&co.x, &rs->st[rs->sp].co.x, &dlo->box.x);
		lws_fx_add(&co.y, &rs->st[rs->sp].co.y, &dlo->box.y);
		co.w = dlo->box.w;
		co.h = dlo->box.h;

		lws_fx_add(&t2, &co.y, &dlo->box.h);

		if (dlo->id) {
			lws_display_id_t *id = dlo->id;

			lwsl_debug("%s: set id box %s\n", __func__, id->id);
			id->box = co;
			dlo->id = NULL; /* decouple us */
		}

		if (co.y.whole + co.h.whole > rs->lowest_id_y) {
			rs->lowest_id_y = (lws_display_scalar)(co.y.whole + co.h.whole);
			if (rs->lowest_id_y > rs->ic->wh_px[1].whole)
				rs->lowest_id_y = (lws_display_scalar)rs->ic->wh_px[1].whole;
		}

		/* next sibling at this level if any */

		d = dlo->list.next;
		if (d)
			rs->st[rs->sp].dlo = lws_container_of(d,
						lws_dlo_t, list);
		else
			rs->st[rs->sp].dlo = NULL;

		/* go into any children */

		if (dlo->children.head) {
			if (rs->sp + 1 == LWS_ARRAY_SIZE(rs->st)) {
				lwsl_err("%s: DLO stack overflow\n",
						__func__);
				return LWS_SRET_FATAL;
			}
			rs->st[++rs->sp].dlo = lws_container_of(
				dlo->children.head, lws_dlo_t, list);
			rs->st[rs->sp].co = co;
			continue;
		}
	}

	lws_display_render_dump_ids(&rs->ids);

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_display_list_render_line(lws_display_render_state_t *rs)
{
	lws_dll2_t *d;

	if (rs->html == 1)
		return LWS_SRET_WANT_INPUT;

	if (!rs->sp && !rs->st[0].dlo) {

		/* starting a line */

		d = lws_dll2_get_head(&rs->displaylist.dl);
		if (!d)
			/* nothing in dlo */
			return LWS_SRET_OK;

	//	memset(rs->line, 0, (size_t)rs->ic->wh_px[0].whole *
	//				(rs->ic->greyscale ? 1 : 3));
		memset(&rs->st[0].co, 0, sizeof(rs->st[0].co));
		rs->st[0].dlo = lws_container_of(d, lws_dlo_t, list);
	}

	while (rs->sp || rs->st[0].dlo) {
		lws_dlo_t *dlo = rs->st[rs->sp].dlo;
		lws_stateful_ret_t r;
		lws_box_t co;
		lws_fx_t t2;

		if (!dlo) {
			rs->sp--;
			continue;
		}

//		lwsl_notice("%s: curr %d: %d %d %d %d\n", __func__, (int)rs->curr, (int)dlo->box.x.whole, (int)dlo->box.y.whole, (int)dlo->box.w.whole, (int)dlo->box.h.whole);

		lws_fx_add(&co.x, &rs->st[rs->sp].co.x, &dlo->box.x);
		lws_fx_add(&co.y, &rs->st[rs->sp].co.y, &dlo->box.y);

		co.w = dlo->box.w;
		co.h = dlo->box.h;

		lws_fx_add(&t2, &co.y, &dlo->box.h);

		if (rs->curr > lws_fx_roundup(&t2)) {
			d = dlo->list.next;
			rs->st[rs->sp].dlo = d ? lws_container_of(d, lws_dlo_t,
								list) : NULL;

			lws_display_dlo_destroy(&dlo);
			continue;
		}

#if 0
		if (dlo->_destroy == lws_display_dlo_png_destroy)
			lwsl_err("png line %d %d %d %d\n", rs->curr, co.y.whole - 1,
					rs->st[rs->sp].co.y.whole, dlo->box.y.whole);
#endif

		if (rs->curr >= co.y.whole - 1) {

			r = dlo->render(rs);

			//rs->ic, dlo, &rs->st[rs->sp].co,
			//		rs->curr, rs->line, &dlo->nle[0]);
			if (r)
				return r;

			/* next sibling at this level if any */

			d = dlo->list.next;

			if (d)
				rs->st[rs->sp].dlo = lws_container_of(d,
							lws_dlo_t, list);
			else
				rs->st[rs->sp].dlo = NULL;


			/* go into any children */

			if (dlo->children.head) {
				if (rs->sp + 1 == LWS_ARRAY_SIZE(rs->st)) {
					lwsl_err("%s: DLO stack overflow\n",
							__func__);
					return LWS_SRET_FATAL;
				}
				rs->st[++rs->sp].dlo = lws_container_of(
					dlo->children.head, lws_dlo_t, list);
				rs->st[rs->sp].co = co;
				continue;
			}
		} else {
			/* next sibling at this level if any */

			d = dlo->list.next;
			if (d)
				rs->st[rs->sp].dlo = lws_container_of(d,
							lws_dlo_t, list);
			else
				rs->st[rs->sp].dlo = NULL;
		}


	}

	return LWS_SRET_OK;
}

static int
dlo_clean_table_rows(lws_dll2_t *d, void *user)
{
	lhp_table_row_t *r = lws_container_of(d, lhp_table_row_t, list);

	lws_dll2_remove(d);
	lws_free(r);

	return 0;
}

static int
dlo_clean_table_cols(lws_dll2_t *d, void *user)
{
	lhp_table_col_t *c = lws_container_of(d, lhp_table_col_t, list);

	lws_dll2_remove(d);
	lws_free(c);

	return 0;
}

void
lws_display_dlo_destroy(lws_dlo_t **r)
{
	if (!(*r))
		return;

	lws_dll2_remove(&(*r)->list);
	lws_dll2_remove(&(*r)->col_list);
	lws_dll2_remove(&(*r)->row_list);

	while ((*r)->children.head) {
		lws_dlo_t *d = lws_container_of((*r)->children.head,
							lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}

	lws_dll2_foreach_safe(&(*r)->table_cols, NULL, dlo_clean_table_cols);
	lws_dll2_foreach_safe(&(*r)->table_rows, NULL, dlo_clean_table_rows);

	if ((*r)->_destroy)
		(*r)->_destroy(*r);

	lws_free_set_NULL(*r);
	*r = NULL;
}

void
lws_display_list_destroy(lws_displaylist_t *dl)
{
	if (!dl)
		return;

	while (dl->dl.head) {
		lws_dlo_t *d = lws_container_of(dl->dl.head, lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}
}

lws_dlo_filesystem_t *
lws_dlo_file_register(struct lws_context *cx, const lws_dlo_filesystem_t *f)
{
	const lws_dlo_filesystem_t *b;
	lws_dlo_filesystem_t *a;

	b = lws_dlo_file_choose(cx, f->name);

	if (b) {
		lwsl_err("%s: dlo file %s already exists %p\n", __func__, b->name, b);
		lws_dlo_file_unregister((lws_dlo_filesystem_t **)&b);
	}

	a = lws_malloc(sizeof(*a), __func__);
	if (!a)
		return NULL;

	*a = *f;
	lws_dll2_clear(&a->list);
	lws_dll2_add_tail(&a->list, &cx->dlo_file);

	lwsl_err("%s: dlo file %s registered at %p\n", __func__, a->name, a);

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
