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

int
lws_dlo_utf8_unicode(const char *utf8, size_t *utf8_len, uint32_t *unicode)
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

	lws_free_set_NULL(text->text);

	lws_display_font_mcufont_release_glyphs(text);
	lwsac_free(&text->ac_glyphs);
	lws_dll2_remove(&text->glyphed);

	if (text->font_held)
		lws_font_unpin(text->font_held);
}

/*
 * The pen's step for the next glyph of a run: the kerning against the glyph
 * before it, then its own advance.  Everything that walks a run's glyphs
 * steps with this, so the widths layout wraps and sizes boxes with are the
 * ones the glyphs are later placed at.  prev carries the glyph before from
 * call to call; start it zeroed for each run.  *kern is where the glyph sits
 * from the pen, and *step how far the pen moves on.  Nonzero if the font has
 * no glyph for it.
 */

static int
dlo_text_step(lws_dlo_text_t *text, lws_glyph_metrics_t *prev,
	      uint32_t unicode, lws_fx_t *kern, lws_fx_t *step)
{
	lws_glyph_metrics_t m;
	int k;

	if (lws_display_font_mcufont_metrics(text, unicode, &m)) {
		prev->valid = 0;
		return 1;
	}

	k = lws_display_font_mcufont_kern(prev, &m);
	lws_fx_set((*kern), k, 0);
	lws_fx_add(step, &m.adv, kern);
	*prev = m;

	return 0;
}

/*
 * How much of the utf8 text fits the text's box after its indent, in its
 * face: the count of bytes in *fitted, and their width in *eff.  It ends at
 * a break point if there is one before the box's width ran out.  Returns 1
 * if it broke there, 2 if nothing fitted, else 0
 */

static int
dlo_text_fit(lws_dlo_text_t *text, const char *utf8, size_t text_len,
	     size_t *fitted, lws_fx_t *peff)
{
	size_t last_bp_n = 0, tlen = text_len;
	lws_fx_t t1, eff, last_bp_eff, t2, k;
	lws_glyph_metrics_t prev;
	uint8_t r = 0;
	char uc;

	lws_fx_set(eff, 0, 0);
	memset(&prev, 0, sizeof(prev));

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

	while (tlen &&
	       lws_fx_comp(lws_fx_add(&t1, &eff, &text->indent),
			   &text->dlo.box.w) < 0) {
		size_t ot = tlen;
		uint32_t unicode;

		if (!lws_dlo_utf8_unicode(utf8, &tlen, &unicode)) {
			text->font->image_glyph(text, unicode, 0);

			uc = *utf8;
			utf8 += (ot - tlen);

			if (uc == ' ') { /* act to snip it if used */
				last_bp_n = tlen;
				last_bp_eff = eff;
			}

			if (!dlo_text_step(text, &prev, unicode, &k, &t2))
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
	    lws_fx_comp(lws_fx_add(&t1, &eff, &text->indent),
			&text->dlo.box.w) >= 0) {
		eff = last_bp_eff;
		tlen = last_bp_n;
		r = 1;
	}

	*fitted = text_len - tlen;
	*peff = eff;

	return tlen == text_len ? 2 : r;
}

/* the glyphs attached to the text are let go, to be attached again later */

void
lws_display_dlo_text_detach_glyphs(lws_dlo_text_t *text)
{
	lws_display_font_mcufont_release_glyphs(text);
	lws_dll2_owner_clear(&text->glyphs);
	lwsac_free(&text->ac_glyphs);
	lws_dll2_remove(&text->glyphed);
	text->glyph_row = 0;
}

static void
dlo_text_set_bounds(lws_dlo_text_t *text, const lws_fx_t *eff)
{
	memset(&text->bounding_box, 0, sizeof(text->bounding_box));
	text->bounding_box.w = *eff;
	text->bounding_box.h.whole = text->font_height;
	text->bounding_box.h.frac = 0;
}

int
lws_display_dlo_text_update(lws_dlo_text_t *text, lws_display_colour_t dc,
			    lws_fx_t indent, const char *utf8, size_t text_len)
{
	lws_fx_t eff;
	int r;

	if (text->text)
		lws_free_set_NULL(text->text);

	lws_display_dlo_text_detach_glyphs(text);

	text->indent = indent;
	text->dlo.dc = dc;

	r = dlo_text_fit(text, utf8, text_len, &text->text_len, &eff);
	if (r == 2) {
		lwsl_notice("we couldn't fit anything in there, newline\n");
		return 2;
	}

	text->text = lws_malloc(text->text_len + 1, __func__);
	if (!text->text)
		return -1;

	memcpy(text->text, utf8, text->text_len);
	text->text[text->text_len] = '\0';

	dlo_text_set_bounds(text, &eff);

	return r;
}

/*
 * The text is set again in its box, in the face it has now: as much of it as
 * fits there.  This needs no memory, so it can be done during the render,
 * when there may be none.  Returns 2 if none of it fits, else 0
 */

int
lws_display_dlo_text_refit(lws_dlo_text_t *text)
{
	lws_fx_t eff;
	size_t n;

	lws_display_dlo_text_detach_glyphs(text);

	/* the face's metrics are taken afresh from the face it has now */
	text->font_height = 0;
	text->font_y_baseline = 0;
	text->font_line_height = 0;

	if (!text->text || dlo_text_fit(text, text->text, text->text_len,
					&n, &eff) == 2) {
		text->text_len = 0;
		return 2;
	}

	text->text_len = n;
	text->text[n] = '\0';
	dlo_text_set_bounds(text, &eff);

	return 0;
}

/*
 * How far across a line its items are moved, for its alignment, when room is
 * the width of the line left over after them.  Only a whole pixel or more left
 * over moves them.
 */

void
lws_display_dlo_text_align_shift(uint8_t align, const lws_fx_t *room,
				 lws_fx_t *shift)
{
	static const lws_fx_t two = { 2, 0 };

	lws_fx_set((*shift), 0, 0);

	if (room->whole <= 0)
		return;

	if (align == LWS_DLO_TEXT_ALIGN_CENTER)
		lws_fx_div(shift, room, &two);
	else if (align == LWS_DLO_TEXT_ALIGN_RIGHT)
		*shift = *room;
}

void
lws_display_dlo_text_measure(lws_dlo_text_t *text, const char *utf8,
			     size_t text_len, lws_fx_t *total,
			     lws_fx_t *longest_word)
{
	lws_fx_t word = { 0, 0 }, t2, k;
	lws_glyph_metrics_t prev;
	size_t tlen = text_len;
	uint32_t unicode;

	memset(&prev, 0, sizeof(prev));
	lws_fx_set((*total), 0, 0);
	lws_fx_set((*longest_word), 0, 0);

	while (tlen) {
		size_t ot = tlen;
		char uc = *utf8;

		if (lws_dlo_utf8_unicode(utf8, &tlen, &unicode)) {
			lwsl_err("%s: bad utf8\n", __func__);
			break;
		}
		utf8 += (ot - tlen);

		text->font->image_glyph(text, unicode, 0);
		if (dlo_text_step(text, &prev, unicode, &k, &t2))
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
	lws_glyph_metrics_t prev;
	uint32_t unicode;
	lws_fx_t eff, step, k;
	uint8_t r = 0;

	lws_fx_set(eff, 0, 0);
	memset(&prev, 0, sizeof(prev));

	while (tlen) {
		size_t ot = tlen;

		g = NULL;
		if (!lws_dlo_utf8_unicode(utf8, &tlen, &unicode))
			/* instantiate the glyphs this time */
			g = text->font->image_glyph(text, unicode, 1);
		if (g == NULL) {
			lwsl_warn("%s: no glyph for 0x%02X '%c'\n", __func__, (unsigned int)*utf8, *utf8);
			break;
		}

		utf8 += (ot - tlen);

		if (dlo_text_step(text, &prev, unicode, &k, &step)) {
			lws_fx_set(k, 0, 0);
			step = g->cwidth;
		}
		lws_fx_add(&g->xpx, &eff, &k);
		lws_fx_add(&eff, &eff, &step);
	}

	return r;
}

#if defined(LWS_WITH_FOOTPRINT)
static size_t
lws_display_dlo_text_heap(struct lws_dlo *dlo)
{
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);

	return lws_fp_heap(text->text, text->text_len + 1);
}
#endif

lws_dlo_text_t *
lws_display_dlo_text_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, const lws_display_font_t *font)
{
	lws_dlo_text_t *text = lws_zalloc(sizeof(*text), __func__);

	if (!text)
		return NULL;

	text->dlo.render = font->renderer;
	text->dlo._destroy = lws_display_dlo_text_destroy;
#if defined(LWS_WITH_FOOTPRINT)
	text->dlo._heap = lws_display_dlo_text_heap;
#endif
	text->dlo.box = *box;
	text->font = font;

	if (dl->hold_fonts) {
		/* a render that draws it in another face still unpins this */
		lws_font_pin(font);
		text->font_held = font;
	}

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

/*
 * A font blob is untrusted data like anything else, whether from flash or
 * from a server... check the parts of the header we and the decoder rely on
 * against data_len before keeping any of it.  *pname is set to its full name.
 */

int
lws_font_blob_check(const uint8_t *data, size_t data_len, const char **pname)
{
	uint32_t o, entries;
	const char *name;

	if (data_len < (size_t)MCUFO_HDR_LEN) {
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

	if (lws_display_font_mcufont_check(data, data_len)) {
		lwsl_err("%s: bad font header or dictionary\n", __func__);
		return 1;
	}

	*pname = name;

	return 0;
}

int
lws_font_register(struct lws_context *cx, const uint8_t *data, size_t data_len)
{
	lws_display_font_t *a;
	const char *name;

	if (lws_font_blob_check(data, data_len, &name))
		return 1;

	a = lws_zalloc(sizeof(*a), __func__);
	if (!a)
		return 1;

	a->choice.family_name = name;
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

/* 1em is the width of the face's 'm', which needs the face's data */

void
lws_font_set_em(lws_display_font_t *a)
{
	lws_glyph_metrics_t m;
	lws_dlo_text_t t;

	memset(&t, 0, sizeof(t));
	t.font = a;

	if (!lws_display_font_mcufont_metrics(&t, 'm', &m))
		a->em = m.adv;
}

/*
 * The rest of making a face whose name and line height are filled in.  A
 * face from a server has no data yet: its em is set when its core page
 * first arrives, which is before layout uses it.  A family from a server is
 * never drawn with itself, only with the faces made of it at each size
 */

void
lws_font_init_common(lws_display_font_t *a)
{
	a->renderer = lws_display_font_mcufont_render;
	a->image_glyph = lws_display_font_mcufont_image_glyph;

	lws_font_choice_from_name(a);
	if (!a->priv || mcuf_file(a))
		lws_font_set_em(a);
	a->ex.whole = a->choice.fixed_height;
	a->ex.frac = 0;

	lws_dll2_clear(&a->list);
}

int
lws_font_register_common(struct lws_context *cx, lws_display_font_t *a)
{
	lws_font_init_common(a);
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
	ff->kind = LWS_MCUF_KIND_FILE;
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

	/* the core load checked the name is a string inside it */
	bf = a->data;
	o = lws_ser_ru32be(bf + MCUFO_FOFS_FULLNAME);

	/* the name has to outlive the core: a copy of our own */
	name = lws_strdup((const char *)bf + o);
	if (!name)
		goto bail;
	a->choice.family_name = name;
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

	if (mcuf_file(a)) {
		/* a file-backed face: the name was our copy */
		lws_free((void *)a->choice.family_name);
		lws_display_font_mcufont_file_destroy(a);
	}
#if defined(LWS_DLO_REMOTE_FONTS)
	/* a family from a server, and its sizes: the name is in the manifest */
	lws_mcufont_family_destroy(a);
#endif
	lws_free(d);
	return 0;
}

void
lws_fonts_destroy(struct lws_context *cx)
{
#if defined(LWS_DLO_REMOTE_FONTS)
	lws_fonts_remote_stop(cx);
#endif
	lws_dll2_foreach_safe(&cx->fonts, NULL, lws_font_destroy);
#if defined(LWS_DLO_REMOTE_FONTS)
	lws_fonts_remote_free(cx);
#endif
}

#if !defined(LWS_DLO_REMOTE_FONTS)
int
lws_fonts_register_manifest(struct lws_context *cx, const char *url)
{
	/* nothing to fetch it with in this build */
	lwsl_cx_err(cx, "needs LWS_WITH_SECURE_STREAMS and client: %s", url);

	return 1;
}
#endif

/*
 * Whether f can be used right now.  Flash faces always can, and so can
 * file-backed ones, which are read in as they are touched.  A face from a
 * server can be when its core page has arrived; otherwise it is fetched,
 * and w woken when that completes, or it can't be had for now.
 */

lws_font_residency_t
lws_font_resident(const lws_display_font_t *f, lws_font_waiter_t *w)
{
	return lws_font_text_resident(f, NULL, 0, w);
}

/*
 * Whether f can draw the utf8 text right now: for a face from a server, if
 * the pages with the text's glyphs are here too.  Any that aren't are
 * fetched as for lws_font_resident()
 */

lws_font_residency_t
lws_font_text_resident(const lws_display_font_t *f, const char *utf8,
		       size_t len, lws_font_waiter_t *w)
{
#if defined(LWS_DLO_REMOTE_FONTS)
	lws_mcufont_remote_t *r = mcuf_remote(f);

	if (r)
		return lws_mcufont_remote_resident(r, utf8, len, w);
#endif
	(void)f;
	(void)utf8;
	(void)len;
	(void)w;

	return LWS_FONT_RESIDENT;
}

/* while pinned, the pages of a face from a server can't be evicted */

void
lws_font_pin(const lws_display_font_t *f)
{
#if defined(LWS_DLO_REMOTE_FONTS)
	lws_mcufont_remote_t *r = mcuf_remote(f);

	if (r)
		lws_mcufont_remote_pin(r, 1);
#else
	(void)f;
#endif
}

void
lws_font_unpin(const lws_display_font_t *f)
{
#if defined(LWS_DLO_REMOTE_FONTS)
	lws_mcufont_remote_t *r = mcuf_remote(f);

	if (r)
		lws_mcufont_remote_pin(r, 0);
#else
	(void)f;
#endif
}

struct track {
	const lws_font_choice_t 	*hints;
	const lws_display_font_t	*best;
	int				best_score;
	uint16_t			best_size; /* of a family from a server */
	char				local; /* only faces we have here */
};

static int
lws_fonts_score(struct lws_dll2 *d, void *user)
{
	const lws_display_font_t *f = lws_container_of(d, lws_display_font_t,
						       list);
	struct track *t = (struct track *)user;
	unsigned int height = f->choice.fixed_height;
	struct lws_tokenize ts;
	uint16_t size = 0;
	int score = 1000;

	/*
	 * A family from a server is scored at the size of it closest to the
	 * height wanted.  If that size isn't here and can't be fetched now
	 * (the server failed us, or its copy is bad), it isn't a choice
	 */
#if defined(LWS_DLO_REMOTE_FONTS)
	if (mcuf_family(f)) {
		uint16_t lh;

		if (t->local ||
		    lws_mcufont_family_pick(mcuf_family(f),
					    t->hints->fixed_height, &size, &lh))
			return 0;
		height = lh;
	}
#endif

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
		score += 10 * (int)(t->hints->fixed_height > height ?
				(t->hints->fixed_height - height) :
				(height - t->hints->fixed_height));

	if (score < t->best_score) {
		t->best_score = score;
		t->best = f;
		t->best_size = size;
	}

	return 0;
}

static const lws_display_font_t *
lws_font_choose_(struct lws_context *cx, const lws_font_choice_t *hints,
		 char local)
{
	static const lws_font_choice_t none;
	struct track t;

	t.hints			= hints ? hints : &none;
	t.best			= NULL;
	t.best_score		= 99999999;
	t.best_size		= 0;
	t.local			= local;

	/* with no hints, every face scores the same and the first wins */
	lws_dll2_foreach_safe(&cx->fonts, &t, lws_fonts_score);

#if defined(LWS_DLO_REMOTE_FONTS)
	if (t.best && mcuf_family(t.best)) {
		const lws_display_font_t *f = lws_mcufont_family_face(
					mcuf_family(t.best), t.best_size);

		/* without the memory for that size, one we have here */
		return f ? f : lws_font_choose_(cx, hints, 1);
	}
#endif

	return t.best;
}

const lws_display_font_t *
lws_font_choose(struct lws_context *cx, const lws_font_choice_t *hints)
{
	return lws_font_choose_(cx, hints, 0);
}

/* the closest face that doesn't have to come from a server */

const lws_display_font_t *
lws_font_choose_local(struct lws_context *cx, const lws_font_choice_t *hints)
{
	return lws_font_choose_(cx, hints, 1);
}
