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
 * Display List Object: text
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

static size_t
utf8_bytes(uint8_t u)
{
	if ((u & 0x80) == 0)
		return 1;

	if ((u & 0xe0) == 0xc0)
		return 2;

	if ((u & 0xf0) == 0xe0)
		return 3;

	if ((u & 0xf8) == 0xf0)
		return 4;

	return 0;
}

void
lws_display_dlo_text_destroy(struct lws_dlo *dlo)
{
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);

	lws_free_set_NULL(text->kern);
	lws_free_set_NULL(text->text);
}

static const uint8_t *
font_psfu_uniglyph(const struct lws_display_font *font, const char *utf8,
		   size_t *m)
{
	const uint8_t *p = font->data, *u, *end = font->data + font->data_len, *ge;
	uint32_t hdrlen = ntohl(lws_ser_ru32be(p + 8)),
		 numglyph = ntohl(lws_ser_ru32be(p + 0x10)),
		 bytesperglyph = ntohl(lws_ser_ru32be(p + 0x14));
	size_t ulen = utf8_bytes((const uint8_t)*utf8);

	if (!ulen) {
		utf8 = "?";
		ulen = 1;
	}

	assert(hdrlen < 256);
	assert(numglyph < 65535);
	assert(bytesperglyph < 65535);

	p += hdrlen;
	ge = u = p + (numglyph * bytesperglyph);
	assert(u < end);

	/*
	 * For each glyph in the main part, there's an entry in the unicode
	 * table describing its identity as UTF-8.  Each UTF-8 list ends with
	 * 0xff delimiter
	 */

	while (p < ge && u < end) {
		size_t gul = 0;

		gul = utf8_bytes(*u);
		if (gul >= 1 && gul == ulen && !memcmp(u, utf8, gul)) {
			*m = gul;
			return p;
		}

		while (*u != 0xff && u < end)
			u++;

		u++;

		p += bytesperglyph;
	}

	*m = 1;

	return NULL;
}

static size_t
image_glyph(lws_dlo_text_t *text, const char *utf8,
	    lws_display_gline_t *dest, size_t dest_height)
{
	size_t glyph_len;
	const uint8_t *pxd = font_psfu_uniglyph(text->font, utf8, &glyph_len);
	uint32_t bytesperglyph = ntohl(lws_ser_ru32be(text->font->data + 0x14)),
		 h_px = ntohl(lws_ser_ru32be(text->font->data + 0x18)),
		 bytes_per_line = bytesperglyph / h_px,
		 n, y = 0, r;

	if (h_px > dest_height)
		h_px = (uint32_t)dest_height;

	while (y < h_px) {

		if (!pxd) {
			dest[y] = 0;
		} else {
			r = (sizeof(dest[0]) * 8) - 8;
			dest[y] = 0;
			for (n = 0; n < bytes_per_line; n++) {
				dest[y] = (unsigned int)(dest[y] | (unsigned int)(*pxd++ << r));
				r -= 8;
			}
		}

		y++;
	}

	return glyph_len;
}

int
lws_display_dlo_text_update(lws_dlo_text_t *text, lws_display_colour_t dc,
		lws_fixed3232_t indent, const char *utf8, size_t text_len)
{
	lws_display_gline_t profile[2][MAX_FONT_HEIGHT], probe;
	size_t n = 0, f = 0, cw, try, sp,
	       w_px = ntohl(lws_ser_ru32be(text->font->data + 0x1c)),
	       h_px = ntohl(lws_ser_ru32be(text->font->data + 0x18)),
	       last_bp_n = 0;
	uint8_t *tk, kernable = 0, r = 0;
	lws_fixed3232_t t1, eff, kern, last_bp_eff;

	if (text->kern)
		lws_free_set_NULL(text->kern);

	if (text->text)
		lws_free_set_NULL(text->text);

	text->dlo.dc = dc;

	tk = text->kern = lws_malloc(text_len * 2, __func__);
	if (!text->kern)
		return -1;

	if (h_px > MAX_FONT_HEIGHT)
		h_px = MAX_FONT_HEIGHT;

	try = w_px;
	lws_fixed_set(eff, 0, 0);

	/*
	 * Let's go through the new string glyph by glyph, we want to
	 * calculate effective kerned widths, and optionally deal with wrapping.
	 */

	while (n < text_len &&
	       lws_fixed3232_comp(lws_fixed3232_add(&t1, &eff, &indent), &text->dlo.box.w) < 0) {

		cw = image_glyph(text, &utf8[n], &profile[f][0], MAX_FONT_HEIGHT);

		if (utf8[n] == ' ' && kernable)
			kernable = 2;

		/* ie, we have a previous char to work with */

		lws_fixed_set(kern, 0, 0);
		if (kernable) {

			/* We want to find "how far left we can shift" the left
			 * of profile[f] into the right of profile[f ^ 1] */

			/* after the first time, try is the remaining
			 * width of the previous character after
			 * trimming empty solumns from the right
			 */

			probe = kernable == 2 ? 0xffffffff : 0;
			sp = try;

			while (try > 1) {
				size_t m, mask = 0;

				for (m = 0; m < h_px; m++)
					mask |= profile[f ^ 1][m] &
						((profile[f][m] | probe) >> (try - 1));

				if (mask) {
					if (try < sp)
						try++;
					break;
				}

				try--;
			}

			kern.whole = (int32_t)(sp - try); /* px to offset left */
		}

		/*
		 * We want to find how many px of this char actually
		 * have nonblank data (skip if space)
		 */

		try = w_px;
		while (try > 1 && kernable != 2) {
			size_t m, mask = 0;

			for (m = 0; m < h_px; m++)
				mask |= (profile[f][m] << try);

			if (mask) {
				if (try < w_px)
					try++;
				break;
			}

			try--;
		}

		if (n == 0)
			kern.whole = (int32_t)(w_px - try);

		if (utf8[n] == ' ') {
			try = w_px / 2;
			kernable = 0; /* next char can't kern away our space */
			if (!n)
				kern.whole = 0;
		} else
			kernable = 1;

		*tk++ = (uint8_t)kern.whole;
		*tk++ = (uint8_t)try;

		if (utf8[n] == ' ') { /* act to skip it */
			last_bp_n = n + cw;
			lws_fixed3232_sub(&last_bp_eff, &eff, &kern);
		}

		lws_fixed3232_sub(&eff, &eff, &kern);
		eff.whole += (int32_t)(try + 1);

		if (utf8[n] == '-' || utf8[n] == ',' || utf8[n] == ';' ||
		    utf8[n] == ':') { /* act to leave it in */
			last_bp_n = n + cw;
			last_bp_eff = eff;
		}

		f ^= 1;
		n += cw;
	}

	if (last_bp_n &&
	    lws_fixed3232_comp(lws_fixed3232_add(&t1, &eff, &indent), &text->dlo.box.w) >= 0) {
		lwsl_notice("%s: last_bp_n %d, eff %d.%u + indent %d.%u >= %d.%u\n",
				__func__, (int)last_bp_n,
				LWFIX(eff), LWFIX(indent),
				LWFIX(text->dlo.box.w));
		n = last_bp_n;
		eff = last_bp_eff;
		r = 1;
	}

	text->text_len = n;
	if (!n) {
		lwsl_notice("we couldn't fit anything in there, newline\n");
		return 2;
	}

	text->text = lws_malloc(n + 1, __func__);
	if (!text->text)
		return -1;

	memcpy(text->text, utf8, n);
	text->text[n] = '\0';

	memset(&text->bounding_box, 0, sizeof(text->bounding_box));
	text->bounding_box.w = eff;
	text->bounding_box.h.whole = (int32_t)h_px;

//	lwsl_notice("%s: text->bb->w %d, h %d\n", __func__,
//			text->bounding_box.w.whole, text->bounding_box.h.whole);

	return r;
}

lws_dlo_text_t *
lws_display_dlo_text_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, const lws_display_font_t *font)
{
	lws_dlo_text_t *text = lws_zalloc(sizeof(*text), __func__);

	if (!text)
		return NULL;

	text->dlo.render = font->renderer;
	text->dlo._destroy = lws_display_dlo_text_destroy;
	text->dlo.box = *box;
	text->font = font;

	lws_display_dlo_add(dl, dlo_parent, &text->dlo);

	return text;
}

void
lws_display_font_psfu_render(const lws_surface_info_t *ic, struct lws_dlo *dlo,
		const lws_box_t *origin, lws_display_scalar curr, uint8_t *line,
		lws_colour_error_t **nle)
{
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);
	int s, e, s1, r, yo;
	uint32_t bytesperglyph = ntohl(lws_ser_ru32be(text->font->data + 0x14)),
		 h_px = ntohl(lws_ser_ru32be(text->font->data + 0x18)),
		 bytes_per_line = bytesperglyph / h_px,
		 shf = 0, n, ins = 0;
	const char *txt = text->text, *txt_end = txt + text->text_len;
	lws_fixed3232_t ax, ay, t, t1, t2;
	size_t glyph_len, ci = 0;
	lws_colour_error_t ce;
	const uint8_t *pxd;

	lws_fixed3232_add(&ax, &origin->x, &dlo->box.x);
	lws_fixed3232_add(&t, &ax, &dlo->box.w);
	lws_fixed3232_add(&ay, &origin->y, &dlo->box.y);
	lws_fixed3232_add(&t1, &ay, &dlo->box.h);

	lws_fixed3232_add(&t2, &ax, &text->bounding_box.w);

	s = ax.whole;
	e = lws_fixed3232_roundup(&t2);

	if (e <= 0)
		return; /* wholly off to the left */
	if (s >= ic->wh_px[0].whole)
		return; /* wholly off to the right */

	if (e >= ic->wh_px[0].whole)
		e = ic->wh_px[0].whole;

	/* figure out our y position inside the glyph */
	yo = curr - ay.whole;
	/* if further down than glyph height, nothing to do */
	if (yo >= (int)h_px)
		return;

	memset(&ce, 0, sizeof(ce));

	while (txt < txt_end && s < e) {

		lws_dlo_ensure_err_diff(dlo);

		pxd = font_psfu_uniglyph(text->font, txt, &glyph_len);
		txt += glyph_len;

		if (!pxd) {
			shf = 0xffffffff;
		} else {
			pxd = pxd + (yo * (int)bytes_per_line);
			r = 24;
			shf = 0;
			for (n = 0; n < bytes_per_line; n++) {
				shf = (unsigned int)(shf | (unsigned int)(*pxd++ << r));
				r -= 8;
			}
		}

		r = 31;

		s1 = s - text->kern[ci];
		for (ins = 0; ins < (uint32_t)text->kern[ci + 1] + 1; ins++) {
			lws_display_colour_t c = LWSDC_RGBA(0, 0, 0, 255);
			int sx = s1 - ax.whole;

			if (s1 < 0 || s1 >= e || !(shf & (unsigned int)(1 << r)) ||
			     !((shf & (unsigned int)(1 << r)) || ins >= text->kern[ci])) {
				r--;
				s1++;
				continue;
			}
			c = dlo->dc;
			ce = nle[!(curr & 1)][s1 - ax.whole];

			lws_surface_set_px(ic, line, s1, &c, &ce);

			if (s1 != e - 1) {
				dist_err(&ce, &nle[!(curr & 1)][sx + 1], 7);
				dist_err(&ce, &nle[curr & 1][sx + 1], 1);
			}
			if (s1 > ax.whole)
				dist_err(&ce, &nle[curr & 1][sx - 1], 3);

			dist_err(&ce, &nle[curr & 1][sx], 5);

			r--;
			s1++;
		}

		s = s1;
		ci += 2;
	}
}

int
lws_font_register(struct lws_context *cx, const lws_display_font_t *f)
{
	lws_display_font_t *a = lws_malloc(sizeof(*a), __func__);
	if (!a)
		return 1;

	*a = *f;
	lws_dll2_clear(&a->list);
	lws_dll2_add_tail(&a->list, &cx->fonts);

	return 0;
}

static int
lws_font_destroy(struct lws_dll2 *d, void *user)
{
	lws_free(d);
	return 0;
}

void
lws_fonts_destroy(struct lws_context *cx)
{
	lws_dll2_foreach_safe(&cx->fonts, NULL, lws_font_destroy);
}

struct track {
	const lws_font_choice_t 	*hints;
	const lws_display_font_t	*best;
	int				best_score;
};

static int
lws_fonts_score(struct lws_dll2 *d, void *user)
{
	const lws_display_font_t *f = lws_container_of(d,
						lws_display_font_t, list);
	struct track *t = (struct track *)user;
	struct lws_tokenize ts;
	int score = 1000;

	if (t->hints->family_name) {
		memset(&ts, 0, sizeof(ts));
		ts.start = t->hints->family_name;
		ts.len = strlen(ts.start);
		ts.flags = LWS_TOKENIZE_F_COMMA_SEP_LIST;

		do {
			ts.e = (int8_t)lws_tokenize(&ts);
			if (ts.e == LWS_TOKZE_TOKEN) {
				if (!strncmp(f->choice.family_name, ts.token,
					     ts.token_len)) {
					score = 0;
					break;
				}

				if (f->choice.generic_name &&
				    !strncmp(f->choice.generic_name, ts.token,
							     ts.token_len)) {
					score -= 500;
					break;
				}
			}

		} while (ts.e > 0);
	}

	if (t->hints->weight)
		score += 5 * (t->hints->weight > f->choice.weight ?
			(t->hints->weight - f->choice.weight) :
			(f->choice.weight - t->hints->weight));

	if (t->hints->style != f->choice.style)
		score += 100;

	if (t->hints->fixed_height)
		score += 10 * (100 - (t->hints->fixed_height > f->choice.fixed_height ?
				(t->hints->fixed_height - f->choice.fixed_height) :
				(f->choice.fixed_height - t->hints->fixed_height)));

	if (score < t->best_score) {
		t->best_score = score;
		t->best = f;
	}

	return 0;
}

const lws_display_font_t *
lws_font_choose(struct lws_context *cx, const lws_font_choice_t *hints)
{
	struct track t;

	t.hints			= hints;
	t.best			= (const lws_display_font_t *)cx->fonts.head;
	t.best_score		= 99999999;

	if (t.hints)
		lws_dll2_foreach_safe(&cx->fonts, &t, lws_fonts_score);

	return t.best;
}
