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
 * Display List Object: non-printing hit region
 *
 * A hit region draws nothing.  It sits in the display list like any other
 * dlo, so it is positioned by the layout along with the things it belongs
 * to and moves with them, and its place in the paint order decides which of
 * several overlapping regions a point belongs to: the one painted last, the
 * one the viewer sees on top.  What it carries is metadata about the area
 * of its box: the url of a link, and the pointer shape to show over it.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

lws_stateful_ret_t
lws_display_render_hit(struct lws_display_render_state *rs)
{
	(void)rs;

	return LWS_SRET_OK;
}

void
lws_display_dlo_hit_destroy(struct lws_dlo *dlo)
{
	(void)dlo;
	/* the url lives in the same allocation as the dlo */
}

lws_dlo_hit_t *
lws_display_dlo_hit_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			const lws_box_t *box, const char *url, size_t url_len)
{
	lws_dlo_hit_t *h = lws_zalloc(sizeof(*h) + (url ? url_len + 1 : 0),
				      __func__);
	char *p;

	if (!h)
		return NULL;

	h->dlo.render = lws_display_render_hit;
	h->dlo._destroy = lws_display_dlo_hit_destroy;
	if (box)
		h->dlo.box = *box;

	if (url) {
		p = (char *)&h[1];
		memcpy(p, url, url_len);
		p[url_len] = '\0';
		h->url = p;
	}

	lws_display_dlo_add(dl, dlo_parent, &h->dlo);

	return h;
}

/*
 * Walk the whole display list in paint order, summing the box offsets, and
 * return the last hit region containing (x, y), which is the topmost one.
 * A region that fills its parent takes the parent's size, so it follows an
 * image whose dimensions arrive after it was made.
 */

lws_dlo_hit_t *
lws_display_dl_hit_test(lws_displaylist_t *dl, int x, int y, lws_box_t *abox)
{
	lws_display_render_stack_t st[64];
	lws_dlo_hit_t *hit = NULL;
	lws_dll2_t *d = lws_dll2_get_head(&dl->dl);
	int sp = 0;

	if (!d)
		return NULL;

	memset(&st, 0, sizeof(st));
	st[0].dlo = lws_container_of(d, lws_dlo_t, list);

	while (sp || st[0].dlo) {
		lws_dlo_t *dlo = st[sp].dlo;
		lws_box_t co;

		if (!dlo) {
			if (!sp)
				break;
			sp--;
			continue;
		}

		lws_fx_add(&co.x, &st[sp].co.x, &dlo->box.x);
		lws_fx_add(&co.y, &st[sp].co.y, &dlo->box.y);
		co.w = dlo->box.w;
		co.h = dlo->box.h;

		if (dlo->render == lws_display_render_hit) {
			lws_dlo_hit_t *h = lws_container_of(dlo, lws_dlo_hit_t,
							    dlo);

			if (h->fill) {
				co.w = st[sp].co.w;
				co.h = st[sp].co.h;
			}

			if (x >= co.x.whole && x < co.x.whole + co.w.whole &&
			    y >= co.y.whole && y < co.y.whole + co.h.whole) {
				hit = h;
				if (abox)
					*abox = co;
			}
		}

		d = lws_dll2_get_next(&dlo->list);
		st[sp].dlo = d ? lws_container_of(d, lws_dlo_t, list) : NULL;

		if (!lws_dll2_is_empty(&dlo->children)) {
			if (sp + 1 == (int)LWS_ARRAY_SIZE(st))
				return hit;
			st[++sp].dlo = lws_container_of(
				lws_dll2_get_head(&dlo->children),
				lws_dlo_t, list);
			st[sp].co = co;
		}
	}

	return hit;
}

lws_dlo_cursor_t
lws_display_dl_cursor_at(lws_displaylist_t *dl, int x, int y)
{
	lws_dlo_hit_t *h = lws_display_dl_hit_test(dl, x, y, NULL);

	return h ? (lws_dlo_cursor_t)h->cursor : LWS_DLO_CURSOR_DEFAULT;
}
