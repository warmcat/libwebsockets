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

static void
lws_display_dlo_text_destroy(struct lws_dlo *dlo)
{
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);

	lws_free_set_NULL(text->kern);
//	lws_free_set_NULL(text->text);
}

static const uint8_t *
font_psfu_uniglyph(const struct lws_display_font *font, const char *utf8,
		   size_t *m)
{
	const uint8_t *p = font->data, *u, *end = font->data + font->data_len, *ge;
	uint32_t hdrlen = ntohl(lws_ser_ru32be(p + 8)),
		 numglyph = ntohl(lws_ser_ru32be(p + 0x10)),
		 bytesperglyph = ntohl(lws_ser_ru32be(p + 0x14));
	size_t ulen = utf8_bytes(*utf8);

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
		h_px = dest_height;

	while (y < h_px) {

		if (!pxd) {
			dest[y] = 0;
		} else {
			r = (sizeof(dest[0]) * 8) - 8;
			dest[y] = 0;
			for (n = 0; n < bytes_per_line; n++) {
				dest[y] |= (*pxd++ << r);
				r -= 8;
			}
		}

		y++;
	}

	return glyph_len;
}

int
lws_display_dlo_text_update(lws_dlo_text_t *text, lws_display_colour_t dc,
		lws_display_scalar indent, const char *utf8, size_t text_len)
{
	lws_display_gline_t profile[2][MAX_FONT_HEIGHT], probe;
	size_t n = 0, f = 0, cw, kern, eff = 0, try, sp,
	       w_px = ntohl(lws_ser_ru32be(text->font->data + 0x1c)),
	       h_px = ntohl(lws_ser_ru32be(text->font->data + 0x18)),
	       last_bp_n = 0, last_bp_eff = 0;
	uint8_t *tk, kernable = 0, r = 0;

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

	/*
	 * Let's go through the new string glyph by glyph, we want to
	 * calculate effective kerned widths, and optionally deal with wrapping.
	 */

	while (n < text_len && eff + indent < (size_t)text->dlo.box.w) {

		cw = image_glyph(text, &utf8[n], &profile[f][0], MAX_FONT_HEIGHT);

		if (utf8[n] == ' ' && kernable)
			kernable = 2;

		/* ie, we have a previous char to work with */

		kern = 0;
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

			kern = sp - try; /* px to offset left */
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
			kern = w_px - try;

		if (utf8[n] == ' ') {
			try = w_px / 2;
			kernable = 0; /* next char can't kern away our space */
			if (!n)
				kern = 0;
		} else
			kernable = 1;

		*tk++ = kern;
		*tk++ = try;

		if (utf8[n] == ' ') { /* act to skip it */
			last_bp_n = n + cw;
			last_bp_eff = eff - kern;
		}

		eff -= kern;
		eff += try + 1;

		if (utf8[n] == '-' || utf8[n] == ',' || utf8[n] == ';' ||
		    utf8[n] == ':') { /* act to leave it in */
			last_bp_n = n + cw;
			last_bp_eff = eff;
		}

		f ^= 1;
		n += cw;
	}

	if (last_bp_n &&
	    eff + indent >= (size_t)text->dlo.box.w) {
		lwsl_notice("%s: last_bp_n %d, eff %d + indent %d >= %d\n",
				__func__, last_bp_n, eff, indent, text->dlo.box.w);
		n = last_bp_n;
		eff = last_bp_eff;
		r = 1;
	}

	text->text_len = n;
	text->text = lws_malloc(n + 1, __func__);
	if (!text->text)
		return -1;

	memcpy(text->text, utf8, n);
	text->text[n] = '\0';

	text->bounding_box.x = 0;
	text->bounding_box.y = 0;
	text->bounding_box.w = eff;
	text->bounding_box.h = h_px;

	lwsl_notice("%s: text->bb->w %d, h %d\n", __func__, text->bounding_box.w, text->bounding_box.h);

	return r;
}

lws_dlo_text_t *
lws_display_dlo_text_new(lws_displaylist_t *dl, lws_box_t *box,
			 const lws_display_font_t *font)
{
	lws_dlo_text_t *text = lws_zalloc(sizeof(*text), __func__);

	if (!text)
		return NULL;

	text->dlo.render = font->renderer;
	text->dlo._destroy = lws_display_dlo_text_destroy;
	text->dlo.box = *box;
	text->font = font;

	lws_display_dlo_add(dl, &text->dlo);

	return text;
}

void
lws_display_font_psfu_render(struct lws_display_state *lds, struct lws_dlo *dlo,
			     lws_display_scalar curr, uint8_t *line,
			     lws_colour_error_t **nle)
{
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);
	int s = dlo->box.x, e = dlo->box.x + text->bounding_box.w, s1, r, yo;
	uint32_t bytesperglyph = ntohl(lws_ser_ru32be(text->font->data + 0x14)),
		 h_px = ntohl(lws_ser_ru32be(text->font->data + 0x18)),
		 bytes_per_line = bytesperglyph / h_px,
		 shf = 0, n, ins = 0;
	const char *txt = text->text, *txt_end = txt + text->text_len;
	size_t glyph_len, ci = 0;
	lws_colour_error_t ce;
	const uint8_t *pxd;

	if (e <= 0)
		return; /* wholly off to the left */
	if (s >= lds->disp->ic.wh_px[0].whole)
		return; /* wholly off to the right */

	if (e >= lds->disp->ic.wh_px[0].whole)
		e = lds->disp->ic.wh_px[0].whole;

	/* figure out our y position inside the glyph */
	yo = curr - dlo->box.y;
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
			pxd += yo * bytes_per_line;
			r = 24;
			shf = 0;
			for (n = 0; n < bytes_per_line; n++) {
				shf |= (*pxd++ << r);
				r -= 8;
			}
		}

		r = 31;

		s1 = s - text->kern[ci];
		for (ins = 0; ins < (uint32_t)text->kern[ci + 1] + 1; ins++) {
			lws_display_colour_t c = LWSDC_RGBA(0, 0, 0, 255), oc;

			if (s1 < 0 || s1 >= e || !(shf & (1 << r)) ||
			     !((shf & (1 << r)) || ins >= text->kern[ci])) {
				r--;
				s1++;
				continue;
			}
			c = dlo->dc;
			ce = nle[!(curr & 1)][s1 - dlo->box.x];

			oc = get_nyb(line, s1);
			set_nyb(line, s1, lws_display_palettize(lds->disp,
								c, oc, &ce));

			if (s1 != e - 1) {
				dist_err(&ce, &nle[!(curr & 1)][s1 - dlo->box.x + 1], 7);
				dist_err(&ce, &nle[curr & 1][s1 - dlo->box.x + 1], 1);
			}
			if (s1 > dlo->box.x)
				dist_err(&ce, &nle[curr & 1][s1 - dlo->box.x - 1], 3);

			dist_err(&ce, &nle[curr & 1][s1 - dlo->box.x], 5);

			r--;
			s1++;
		}

		s = s1;
		ci += 2;
	}
}

