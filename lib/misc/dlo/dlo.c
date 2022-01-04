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
	lws_dll2_add_tail(&dlo->list, dlo_parent ? &dlo_parent->children : &dl->dl);

	return 9;
}

void
lws_surface_set_px(const lws_surface_info_t *ic, uint8_t *line, int x,
		   const lws_display_colour_t *c)
{
	unsigned int alpha, ialpha;
	lws_display_colour_t oc;
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

		line[x] = (uint8_t)(((LWSDC_R(*c) * alpha) / 255) +
			   ((LWSDC_R(oc) * ialpha) / 255));
		return;
	}

	/* line composition buffer is 24-bit RGB per pixel */

	line += 3 * x;

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
	*line = rgb[2];
}


#if defined(_DEBUG)
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
			lws_snprintf(dt, sizeof(dt), "text: RGBA 0x%08X, chars: %u, %s",
					(unsigned int)dlo->dc, (unsigned int)text->text_len, text->text);
		}
		else if (dlo->_destroy == lws_display_dlo_png_destroy)
			lws_snprintf(dt, sizeof(dt), "png");
		else if (dlo->_destroy == lws_display_dlo_jpeg_destroy)
			lws_snprintf(dt, sizeof(dt), "jpeg");

		lws_fx_string(&dlo->box.x, b[0], sizeof(b[0]));
		lws_fx_string(&dlo->box.y, b[1], sizeof(b[1]));
		lws_fx_string(&dlo->box.w, b[2], sizeof(b[2]));
		lws_fx_string(&dlo->box.h, b[3], sizeof(b[3]));
		lws_fx_string(&co.x, b1[0], sizeof(b1[0]));
		lws_fx_string(&co.y, b1[1], sizeof(b1[1]));
		lws_fx_string(&co.w, b1[2], sizeof(b1[2]));
		lws_fx_string(&co.h, b1[3], sizeof(b1[3]));

		lwsl_dlodump("%.*s box: (%s, %s) [%s x %s], co: (%s, %s) [%s x %s], %s\n",
				sp, ind, b[0], b[1], b[2], b[3], b1[0], b1[1], b1[2], b1[3], dt);

		/* go into any children */

		if (dlo->children.head) {
			if (sp + 1 == LWS_ARRAY_SIZE(st)) {
				lwsl_err("%s: DLO stack overflow\n", __func__);
				return;
			}
			st[sp++].dlo = lws_container_of(
				dlo->children.head, lws_dlo_t, list);
			st[sp].co = co;
			continue;
		}

		d = dlo->list.next;
		if (d)
			st[sp].dlo = lws_container_of(d, lws_dlo_t, list);
		else
			st[sp].dlo = NULL;
	}
}
#endif

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

		// lwsl_notice("%s: curr %d: %d %d %d %d\n", __func__, rs->curr, dlo->box.x.whole, dlo->box.y.whole, dlo->box.w.whole, dlo->box.h.whole);

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

void
lws_display_dlo_destroy(lws_dlo_t **r)
{
	if (!(*r))
		return;

	lws_dll2_remove(&(*r)->list);

	while ((*r)->children.head) {
		lws_dlo_t *d = lws_container_of((*r)->children.head,
							lws_dlo_t, list);

		lws_display_dlo_destroy(&d);
	}

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

int
lws_dlo_file_register(struct lws_context *cx, const lws_dlo_filesystem_t *f)
{
	lws_dlo_filesystem_t *a = lws_malloc(sizeof(*a), __func__);
	if (!a)
		return 1;

	*a = *f;
	lws_dll2_clear(&a->list);
	lws_dll2_add_tail(&a->list, &cx->dlo_file);

	return 0;
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
