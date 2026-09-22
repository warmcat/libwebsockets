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

static void
lws_font_choice_from_name(lws_display_font_t *a);
static int
lws_font_register_common(struct lws_context *cx, lws_display_font_t *a);


size_t
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

static int
utf8_unicode(const char *utf8, size_t *utf8_len, uint32_t *unicode)
{
	size_t glyph_len = utf8_bytes((uint8_t)*utf8);
	size_t n;

	if (!glyph_len || glyph_len > *utf8_len) {
		(*utf8_len)--;
		return 1;
	}

	if (glyph_len == 1)
		*unicode = (uint32_t)*utf8++;
	else {
		*unicode = (uint32_t)((*utf8++) & (0x7f >> glyph_len));
		for (n = 1; n < glyph_len; n++)
			*unicode = (*unicode << 6) | ((*utf8++) & 0x3f);
	}

	*utf8_len -= glyph_len;

	return 0;
}

void
lws_display_dlo_text_destroy(struct lws_dlo *dlo)
{
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);

	lws_free_set_NULL(text->kern);
	lws_free_set_NULL(text->text);

	lws_display_font_mcufont_release_glyphs(text);
	lwsac_free(&text->ac_glyphs);
}

int
lws_display_dlo_text_update(lws_dlo_text_t *text, lws_display_colour_t dc,
			    lws_fx_t indent, const char *utf8, size_t text_len)
{
	const char *outf8 = utf8;
	size_t last_bp_n = 0, tlen = text_len;
	lws_fx_t t1, eff, last_bp_eff, t2;
	uint8_t r = 0;
	char uc;

	if (text->kern)
		lws_free_set_NULL(text->kern);

	if (text->text)
		lws_free_set_NULL(text->text);

	lws_display_font_mcufont_release_glyphs(text);
	lws_dll2_owner_clear(&text->glyphs);
	lwsac_free(&text->ac_glyphs);

	text->indent = indent;
	text->dlo.dc = dc;

	lws_fx_set(eff, 0, 0);

	/*
	 * Let's go through the new string glyph by glyph, we want to
	 * calculate effective kerned widths, and optionally deal with wrapping.
	 *
	 * But we don't want to instantiate the glyph objects until we are
	 * engaged with rendering them.  Otherwise we will carry around the
	 * whole page-worth's of glyphs at once needlessly, which won't scale
	 * for text-heavy pages.  lws_display_dlo_text_attach_glyphs() does the
	 * same flow as this but to create the glyphs and is called later
	 * as the text dlo becomes rasterized during rendering.
	 */

/*	{ char b1[22]; lwsl_err("eff %s\n", lws_fx_string(&eff, b1, sizeof(b1))); }
	{ char b1[22]; lwsl_err("indent %s\n", lws_fx_string(&indent, b1, sizeof(b1))); }
	{ char b1[22]; lwsl_err("boxw %s\n", lws_fx_string(&text->dlo.box.w, b1, sizeof(b1))); } */

	while (tlen &&
	       lws_fx_comp(lws_fx_add(&t1, &eff, &indent), &text->dlo.box.w) < 0) {
		size_t ot = tlen;
		uint32_t unicode;

		if (!utf8_unicode(utf8, &tlen, &unicode)) {
			text->font->image_glyph(text, unicode, 0);

			uc = *utf8;
			utf8 += (ot - tlen);

			if (uc == ' ') { /* act to snip it if used */
				last_bp_n = tlen;
				last_bp_eff = eff;
			}

			if (!lws_display_font_mcufont_getcwidth(text, unicode, &t2))
				lws_fx_add(&eff, &eff, &t2);

			if (uc == '-' || uc == ',' || uc == ';' || uc == ':') {
				/* act to leave it in */
				last_bp_n = tlen;
				last_bp_eff = eff;
			}
		} else
			lwsl_err("%s: missing glyph\n", __func__);
	}

	if (last_bp_n &&
	    lws_fx_comp(lws_fx_add(&t1, &eff, &indent), &text->dlo.box.w) >= 0) {
		eff = last_bp_eff;
		tlen = last_bp_n;
		r = 1;
	}

	text->text_len = text_len - tlen;
	if (tlen == text_len) {
		lwsl_notice("we couldn't fit anything in there, newline\n");
		return 2;
	}

	text->text = lws_malloc(text->text_len + 1, __func__);
	if (!text->text)
		return -1;

	memcpy(text->text, outf8, text->text_len);
	text->text[text->text_len] = '\0';

	memset(&text->bounding_box, 0, sizeof(text->bounding_box));
	text->bounding_box.w = eff;
	text->bounding_box.h.whole = text->font_height;
	text->bounding_box.h.frac = 0;

	return r;
}

void
lws_display_dlo_text_measure(lws_dlo_text_t *text, const char *utf8,
			     size_t text_len, lws_fx_t *total,
			     lws_fx_t *longest_word)
{
	lws_fx_t word = { 0, 0 }, t2;
	size_t tlen = text_len;
	uint32_t unicode;

	lws_fx_set((*total), 0, 0);
	lws_fx_set((*longest_word), 0, 0);

	while (tlen) {
		size_t ot = tlen;
		char uc = *utf8;

		if (utf8_unicode(utf8, &tlen, &unicode)) {
			lwsl_err("%s: bad utf8\n", __func__);
			break;
		}
		utf8 += (ot - tlen);

		text->font->image_glyph(text, unicode, 0);
		if (lws_display_font_mcufont_getcwidth(text, unicode, &t2))
			continue;

		lws_fx_add(total, total, &t2);

		if (uc == ' ') {
			if (lws_fx_comp(&word, longest_word) > 0)
				*longest_word = word;
			lws_fx_set(word, 0, 0);
		} else
			lws_fx_add(&word, &word, &t2);
	}

	if (lws_fx_comp(&word, longest_word) > 0)
		*longest_word = word;
}

int
lws_display_dlo_text_attach_glyphs(lws_dlo_text_t *text)
{
	const char *utf8 = text->text;
	size_t tlen = text->text_len;
	lws_font_glyph_t *g = NULL;
	uint32_t unicode;
	lws_fx_t eff;
	uint8_t r = 0;

	lws_fx_set(eff, 0, 0);

	while (tlen) {
		size_t ot = tlen;

		g = NULL;
		if (!utf8_unicode(utf8, &tlen, &unicode))
			/* instantiate the glyphs this time */
			g = text->font->image_glyph(text, unicode, 1);
		if (g == NULL) {
			lwsl_warn("%s: no glyph for 0x%02X '%c'\n", __func__, (unsigned int)*utf8, *utf8);
			break;
		}

		utf8 += (ot - tlen);
		g->xpx = eff;
		lws_fx_add(&eff, &eff, &g->cwidth);
	}

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

static const char *
castrstr(const char *haystack, const char *needle)
{
	size_t sn = strlen(needle), hn = strlen(haystack), h, n;
	char c, c1;

	if (hn < sn)
		/* the needle can't fit in the haystack at all */
		return NULL;

	h = hn - sn;

	while (1) {
		for (n = 0; n < sn; n++) {
			c = (char)((haystack[h + n] >= 'A' && haystack[h + n] <= 'Z') ?
				haystack[h + n] + ('a' - 'A') : haystack[h + n]);
			c1 = (char)((needle[n] >= 'A' && needle[n] <= 'Z') ?
				needle[n] + ('a' - 'A') : needle[n]);
			if (c != c1)
				break;
		}
		if (n == sn)
			return &haystack[h];

		if (!h)
			break;
		h--;
	}

	return NULL;
}

int
lws_font_register(struct lws_context *cx, const uint8_t *data, size_t data_len)
{
	lws_display_font_t *a;
	uint32_t o, entries;
	const char *name;

	/*
	 * The font blob is untrusted data like anything else... validate the
	 * parts of the header we and the decoder rely on against data_len
	 * before we keep any of it
	 */

	if (data_len < (size_t)MCUFO16_LINE_HEIGHT + 2) {
		lwsl_err("%s: font blob too small\n", __func__);
		return 1;
	}

	if (lws_ser_ru32be(data) != LWS_FOURCC('M', 'C', 'U', 'F'))
		return 1;

	/* the full name must be a NUL-terminated string inside the blob */

	o = lws_ser_ru32be(data + MCUFO_FOFS_FULLNAME);
	if ((size_t)o >= data_len) {
		lwsl_err("%s: font name offset outside blob\n", __func__);
		return 1;
	}
	name = (const char *)data + o;
	if (!memchr(name, '\0', data_len - o)) {
		lwsl_err("%s: font name not terminated\n", __func__);
		return 1;
	}

	/* the char range tables must be inside the blob */

	entries = lws_ser_ru32be(data + MCUFO_COUNT_CHAR_RANGE_TABLES);
	o = lws_ser_ru32be(data + MCUFO_FOFS_CHAR_RANGE_TABLES);
	if (entries > 8u || (size_t)o > data_len ||
	    (data_len - o) / 16 < entries) {
		lwsl_err("%s: bad char range tables\n", __func__);
		return 1;
	}

	/*
	 * lws_font_glyph_t.x is an int8_t and the renderer counts it up to the
	 * font's declared width, so a wider font would overflow it
	 */

	if (lws_ser_ru16be(data + MCUFO16_WIDTH) > 127) {
		lwsl_err("%s: font too wide\n", __func__);
		return 1;
	}

	a = lws_zalloc(sizeof(*a), __func__);
	if (!a)
		return 1;

	a->choice.family_name = name;

	lws_font_choice_from_name(a);
	a->choice.fixed_height = lws_ser_ru16be(data + MCUFO16_LINE_HEIGHT);

	a->data = data;
	a->data_len = data_len;

	return lws_font_register_common(cx, a);
}

/* what the chooser can know about a face from its name */

static void
lws_font_choice_from_name(lws_display_font_t *a)
{
	if (castrstr(a->choice.family_name, "serif") ||
	    castrstr(a->choice.family_name, "roman"))
		a->choice.generic_name = "serif";
	else
		a->choice.generic_name = "sans";

	if (castrstr(a->choice.family_name, "italic") ||
	    castrstr(a->choice.family_name, "oblique"))
		a->choice.style = 1;

	if (castrstr(a->choice.family_name, "extrabold") ||
	    castrstr(a->choice.family_name, "extra bold"))
		a->choice.weight = 900;
	else
		if (castrstr(a->choice.family_name, "bold"))
		    a->choice.weight = 700;
		else
			if (castrstr(a->choice.family_name, "extralight") ||
			    castrstr(a->choice.family_name, "extra light"))
				a->choice.weight = 200;
			else
				if (castrstr(a->choice.family_name, "light"))
					a->choice.weight = 300;
				else
					a->choice.weight = 400;
}

/* the rest of registering a face whose choice and data are filled in */

static int
lws_font_register_common(struct lws_context *cx, lws_display_font_t *a)
{
	a->renderer = lws_display_font_mcufont_render;
	a->image_glyph = lws_display_font_mcufont_image_glyph;

	{
		lws_dlo_text_t t;

		memset(&t, 0, sizeof(t));
		t.font = a;

		lws_display_font_mcufont_getcwidth(&t, 'm', &a->em);
		a->ex.whole = a->choice.fixed_height;
		a->ex.frac = 0;
	}

	lws_dll2_clear(&a->list);
	lws_dll2_add_tail(&a->list, &cx->fonts);

	return 0;
}

/*
 * Register a font kept in a file (on the SD card, say).  Only its name and
 * metrics stay in memory: the dictionary and the glyphs it uses are brought
 * in when text is set in it, and given back when memory is short.
 */

int
lws_font_register_file(struct lws_context *cx, const char *path)
{
	lws_display_font_t *a = lws_zalloc(sizeof(*a), __func__);
	lws_mcufont_file_t *ff;
	const uint8_t *bf;
	uint32_t o;
	char *name;

	if (!a)
		return 1;

	ff = lws_zalloc(sizeof(*ff), __func__);
	if (!ff)
		goto bail;
	a->priv = (uint8_t *)ff;
	ff->cx = cx;
	ff->f = a;
	ff->path = lws_strdup(path);
	if (!ff->path)
		goto bail;
	ff->rc_core.evict = mcuf_file_core_evict_cb;
	ff->rc_glyphs.evict = mcuf_file_glyphs_evict_cb;

	/* bring the core in to read the name and metrics from */

	if (lws_display_font_mcufont_file_core(a)) {
		lwsl_warn("%s: %s: not a usable mcufont\n", __func__, path);
		goto bail;
	}

	bf = a->data;
	o = lws_ser_ru32be(bf + MCUFO_FOFS_FULLNAME);
	if (o >= ff->prefix_len ||
	    !memchr(bf + o, '\0', ff->prefix_len - o) ||
	    lws_ser_ru16be(bf + MCUFO16_WIDTH) > 127) {
		lwsl_warn("%s: %s: bad font header\n", __func__, path);
		goto bail;
	}

	/* the name has to outlive the core: a copy of our own */
	name = lws_strdup((const char *)bf + o);
	if (!name)
		goto bail;
	a->choice.family_name = name;
	lws_font_choice_from_name(a);
	a->choice.fixed_height = lws_ser_ru16be(bf + MCUFO16_LINE_HEIGHT);

	lws_reclaimable_add(&ff->rc_core);
	lws_reclaimable_add(&ff->rc_glyphs);

	lwsl_info("%s: %s: %s %u\n", __func__, path, name,
		  a->choice.fixed_height);

	return lws_font_register_common(cx, a);

bail:
	if (ff) {
		lws_display_font_mcufont_file_destroy(a);
	}
	lws_free(a);

	return 1;
}

#if defined(LWS_WITH_DIR)
static int
lws_font_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct lws_context *cx = (struct lws_context *)user;
	size_t nl = strlen(lde->name);
	char path[256];

	if (lde->type != LDOT_FILE || nl < 9 ||
	    strcmp(lde->name + nl - 8, ".mcufont"))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	if (lws_font_register_file(cx, path))
		lwsl_notice("%s: %s: not registered\n", __func__, path);

	return 0;
}

int
lws_fonts_register_dir(struct lws_context *cx, const char *dirpath)
{
	int n = (int)lws_dll2_count(&cx->fonts);

	/* lws_dir() returns 1 whether or not it could open the directory:
	 * what registered is the measure */
	lws_dir(dirpath, cx, lws_font_dir_cb);

	return (int)lws_dll2_count(&cx->fonts) - n;
}
#else
int
lws_fonts_register_dir(struct lws_context *cx, const char *dirpath)
{
	/* no directory scanning in this build (LWS_WITH_DIR off, as on
	 * esp32): nothing can be found, register files individually */
	(void)cx;
	(void)dirpath;

	return 0;
}
#endif

static int
lws_font_destroy(struct lws_dll2 *d, void *user)
{
	lws_display_font_t *a = lws_container_of(d, lws_display_font_t, list);

	if (a->priv) {
		/* a file-backed face: the name was our copy */
		lws_free((void *)a->choice.family_name);
		lws_display_font_mcufont_file_destroy(a);
	}
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
	const lws_display_font_t *f = lws_container_of(d, lws_display_font_t,
						       list);
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
		score += (t->hints->weight > f->choice.weight ?
			(t->hints->weight - f->choice.weight) :
			(f->choice.weight - t->hints->weight)) / 100;

	if (t->hints->style != f->choice.style)
		score += 100;

	if (t->hints->fixed_height)
		score += 10 * (t->hints->fixed_height > f->choice.fixed_height ?
				(t->hints->fixed_height - f->choice.fixed_height) :
				(f->choice.fixed_height - t->hints->fixed_height));

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
	t.best			= (const lws_display_font_t *)lws_dll2_get_head(&cx->fonts);
	t.best_score		= 99999999;

	if (t.hints)
		lws_dll2_foreach_safe(&cx->fonts, &t, lws_fonts_score);

	return t.best;
}
