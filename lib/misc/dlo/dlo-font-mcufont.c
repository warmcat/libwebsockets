/*
 * lws abstract display
 *
 * Copyright (C) 2013 Petteri Aimonen
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
 * Display List Object: mcufont font
 *
 * The mcu decoding is rewritten from the mcufont implementation at
 * https://github.com/mcufont/mcufont, which is licensed under MIT already,
 * to use a stateful decoder.
 *
 * The decoder only brings in new compression codes when needed to produce more
 * pixels on the line of the glyphs being decoded.
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

#define DICT_START		24
#define REF_FILLZEROS		16

/*
 * How many glyph objects to allocate per lwsac chunk... the text run length
 * comes from the document, so we don't let it size the allocation itself
 */

#define LWS_DLO_GLYPH_AC_GRANULE	64

#define RLE_CODEMASK    	0xC0
#define RLE_VALMASK     	0x3F
#define RLE_ZEROS       	0x00
#define RLE_64ZEROS     	0x40
#define RLE_ONES        	0x80
#define RLE_SHADE       	0xC0

#define DICT_START7BIT  	4
#define DICT_START6BIT  	132
#define DICT_START5BIT  	196
#define DICT_START4BIT  	228
#define DICT_START3BIT  	244
#define DICT_START2BIT  	252

enum {
	RS_IDLE,
	RS_SKIP_PX,
	RS_WRITE_PX,
	RS_ALLZERO,

	COMP			= 0,
	DICT1,
	DICT1_CONT,
	DICT2,
	DICT3
};

typedef struct mcu_stack {
	const uint8_t		*dict;
	int16_t			dictlen;
	int16_t			runlen; /* for accumilation on DICT1 */
	uint8_t			byte;
	uint8_t			bitcount;
	uint8_t			state;
} mcu_stack_t;

typedef struct mcu_glyph {
	lws_font_glyph_t	fg;
	const uint8_t		*comp;

	/*
	 * The decoder's own nesting is COMP -> ref dict entry (DICT3) ->
	 * fill entry (DICT1) -> DICT1_CONT, ie, four levels; mcu_push()
	 * refuses to go deeper than the array whatever the font says
	 */

	mcu_stack_t		st[4];
	int32_t			runlen;

	int8_t			sp;

	uint8_t			runstate;
	uint8_t			alpha;
	uint8_t			code;
} mcu_glyph_t;

/*
 * Abandon the rest of this glyph safely: emit transparent pixels until the
 * render loop hits the glyph width and moves on.  Used when a font asks us to
 * do something we can't do inside our decoder state.
 */

static void
mcu_abandon_glyph(mcu_glyph_t *g)
{
	g->alpha = 0;
	g->runlen = 1000000;
	g->runstate = RS_WRITE_PX;
}

/*
 * Push a new decoder stack level and return it, or NULL if we already used
 * them all (only possible with a corrupt or hostile font)
 */

static mcu_stack_t *
mcu_push(mcu_glyph_t *g)
{
	if (g->sp < 0 || (size_t)(g->sp + 1) >= LWS_ARRAY_SIZE(g->st)) {
		lwsl_warn("%s: font glyph nesting too deep\n", __func__);
		mcu_abandon_glyph(g);

		return NULL;
	}

	return &g->st[(int)++g->sp];
}

/*
 * Pop a decoder stack level... returns nonzero if there was nothing to pop,
 * meaning the caller should stop decoding this glyph
 */

static int
mcu_pop(mcu_glyph_t *g)
{
	if (g->sp <= 0) {
		lwsl_warn("%s: font glyph stack underflow\n", __func__);
		mcu_abandon_glyph(g);

		return 1;
	}

	g->sp--;

	return 0;
}

/* Get bit count for the "fill entries" */
static uint8_t
fillentry_bitcount(uint8_t index)
{
    if (index >= DICT_START2BIT)
        return 2;
    else if (index >= DICT_START3BIT)
        return 3;
    else if (index >= DICT_START4BIT)
        return 4;
    else if (index >= DICT_START5BIT)
        return 5;
    else if (index >= DICT_START6BIT)
        return 6;
    else
        return 7;
}

void
draw_px(lws_dlo_text_t *t, mcu_glyph_t *g)
{
	lws_display_colour_t c = (lws_display_colour_t)(((lws_display_colour_t)g->alpha << 24) |
					(lws_display_colour_t)((lws_display_colour_t)t->dlo.dc & 0xffffffu));
	lws_fx_t t1, x;
	int ex;

	t1.whole = g->fg.x;

	if (!g->alpha)
		return;

	t1.frac = 0;
	lws_fx_add(&x, &g->fg.xpx, &t1);

#if 0
	{ char b1[22], b2[22], b3[22];
		lwsl_err("fadj %s = %s + %s\n",
			lws_fx_string(&x, b1, sizeof(b1)),
			lws_fx_string(&g->fg.xpx, b2, sizeof(b2)),
			lws_fx_string(&g->fg.xorg, b3, sizeof(b3))); }
#endif

	ex = x.whole;// - t->dlo.box.x.whole;
	if (ex < 0 || ex >= t->dlo.box.w.whole) {
		//lwsl_err("%s: ex %d (lim %d)\n", __func__, ex, t->dlo.box.w.whole);
		return;
	}
	lws_fx_add(&x, &x, &g->fg.xorg);

	lws_fx_add(&t1, &t->dlo.box.x, &x);
	lws_surface_set_px(t->ic, t->line, t1.whole, &c);
}

/*
 * File-backed fonts: the decoder works from absolute offsets into the font
 * blob, so a file-backed font keeps the blob's prefix (header, names,
 * dictionary, dictionary offsets) resident as .data while it is in use, and
 * serves the range tables, glyph offset tables and glyph strings from
 * copies and a cache.  Flash-resident fonts have no priv and everything is
 * simply in .data.
 */

static void
mcuf_file_core_free(lws_mcufont_file_t *ff)
{
	int n;

	lws_vfs_file_close(&ff->fd);
	lws_free_set_NULL(ff->prefix);
	lws_free_set_NULL(ff->ranges);
	for (n = 0; n < MCUFO_MAX_RANGES; n++)
		lws_free_set_NULL(ff->gofs[n]);
	ff->rc_core.resident = 0;
}

size_t
mcuf_file_core_evict_cb(lws_reclaimable_t *r)
{
	lws_mcufont_file_t *ff = lws_container_of(r, lws_mcufont_file_t, rc_core);
	size_t freed = r->resident;

	lwsl_info("%s: %s: %u\n", __func__, ff->path, (unsigned int)freed);
	mcuf_file_core_free(ff);
	ff->f->data = NULL;

	return freed;
}

size_t
mcuf_file_glyphs_evict_cb(lws_reclaimable_t *r)
{
	lws_mcufont_file_t *ff = lws_container_of(r, lws_mcufont_file_t,
						  rc_glyphs);
	size_t freed = 0;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&ff->glyphs)) {
		mcuf_gent_t *ge = lws_container_of(d, mcuf_gent_t, list);

		if (ge->pins)
			continue;

		lws_dll2_remove(&ge->list);
		freed += sizeof(*ge) + ge->len;
		ff->glyph_bytes -= sizeof(*ge) + ge->len;
		lws_free(ge);
	} lws_end_foreach_dll_safe(d, d1);

	r->resident = ff->glyph_bytes;
	lwsl_info("%s: %s: %u\n", __func__, ff->path, (unsigned int)freed);

	return freed;
}

static int
mcuf_file_read(lws_mcufont_file_t *ff, uint32_t ofs, uint8_t *buf, uint32_t len)
{
	lws_filepos_t amount = len;

	if (!ff->fd)
		return 1;

	if (lws_vfs_file_seek_set(ff->fd, (lws_fileofs_t)ofs) < 0 ||
	    lws_vfs_file_read(ff->fd, &amount, buf, len) < 0 || amount != len)
		return 1;

	return 0;
}

/*
 * Bring the core of a file-backed font into memory if it isn't, and make it
 * the font's .data.  Returns nonzero if it can't (no memory, no file).
 */

int
lws_display_font_mcufont_file_core(lws_display_font_t *f)
{
	lws_mcufont_file_t *ff = (lws_mcufont_file_t *)f->priv;
	lws_fop_flags_t fl = LWS_O_RDONLY;
	uint8_t hdr[MCUFO_HDR_LEN];
	uint32_t o, n, rt, nr, cnt, plen;
	unsigned int m;

	if (!ff)
		return 0; /* flash-resident */

	if (ff->prefix) {
		lws_reclaimable_touch(&ff->rc_core);
		return 0;
	}

	ff->fd = lws_vfs_file_open(lws_get_fops(ff->cx), ff->path, &fl);
	if (!ff->fd)
		return 1;

	ff->file_len = (uint32_t)lws_vfs_get_length(ff->fd);

	if (mcuf_file_read(ff, 0, hdr, sizeof(hdr)))
		goto bail;

	if (lws_ser_ru32be(hdr) != LWS_FOURCC('M', 'C', 'U', 'F'))
		goto bail;

	/* the prefix: up to the end of the dictionary offsets table */

	o = lws_ser_ru32be(hdr + MCUFO_FOFS_DICT_OFS);
	n = lws_ser_ru32be(hdr + MCUFO_COUNT_REF_RLE_DICT);
	if (n > 512 || o > ff->file_len)
		goto bail;
	plen = o + ((n + 1) * 2);
	rt = lws_ser_ru32be(hdr + MCUFO_FOFS_CHAR_RANGE_TABLES);
	nr = lws_ser_ru32be(hdr + MCUFO_COUNT_CHAR_RANGE_TABLES);
	if (plen > ff->file_len || nr > MCUFO_MAX_RANGES ||
	    rt > ff->file_len || (ff->file_len - rt) / 16 < nr)
		goto bail;

	ff->prefix = lws_malloc(plen, __func__);
	ff->ranges = lws_malloc(nr * 16, __func__);
	if (!ff->prefix || !ff->ranges)
		goto bail;
	if (mcuf_file_read(ff, 0, ff->prefix, plen) ||
	    mcuf_file_read(ff, rt, ff->ranges, nr * 16))
		goto bail;
	ff->prefix_len = plen;
	ff->nranges = (uint16_t)nr;
	ff->rc_core.resident = plen + nr * 16;

	/* each range's glyph offset table, and where its data ends */

	for (m = 0; m < nr; m++) {
		const uint8_t *r = ff->ranges + (m * 16);
		uint32_t ot = lws_ser_ru32be(r + 8), db = lws_ser_ru32be(r + 0xc),
			 end = rt;
		unsigned int k;

		cnt = lws_ser_ru32be(r + 4);
		if (!cnt || cnt > 0x10000 || ot > ff->file_len ||
		    (ff->file_len - ot) / 2 < cnt || db > ff->file_len)
			goto bail;

		ff->gofs[m] = lws_malloc(cnt * 2, __func__);
		if (!ff->gofs[m] ||
		    mcuf_file_read(ff, ot, (uint8_t *)ff->gofs[m], cnt * 2))
			goto bail;
		ff->rc_core.resident += cnt * 2;

		/* the data runs to the next thing in the file after it */
		for (k = 0; k < nr; k++) {
			uint32_t kt = lws_ser_ru32be(ff->ranges + (k * 16) + 8);

			if (kt > db && kt < end)
				end = kt;
		}
		ff->gend[m] = end;
	}

	f->data = ff->prefix;
	f->data_len = ff->file_len;
	lws_reclaimable_touch(&ff->rc_core);

	return 0;

bail:
	mcuf_file_core_free(ff);

	return 1;
}

void
lws_display_font_mcufont_file_destroy(lws_display_font_t *f)
{
	lws_mcufont_file_t *ff = (lws_mcufont_file_t *)f->priv;

	if (!ff)
		return;

	lws_reclaimable_remove(&ff->rc_core);
	lws_reclaimable_remove(&ff->rc_glyphs);
	mcuf_file_core_free(ff);
	while (lws_dll2_get_head(&ff->glyphs)) {
		mcuf_gent_t *ge = lws_container_of(lws_dll2_get_head(&ff->glyphs),
						   mcuf_gent_t, list);

		lws_dll2_remove(&ge->list);
		lws_free(ge);
	}
	lws_free(ff->path);
	lws_free(ff);
	f->priv = NULL;
}

/* the font blob (prefix) or NULL if it can't be made resident */

static const uint8_t *
mcuf_bf(lws_dlo_text_t *text)
{
	lws_display_font_t *f = (lws_display_font_t *)text->font;

	if (f->priv && lws_display_font_mcufont_file_core(f))
		return NULL;

	return f->data;
}

/* the char range tables */

static const uint8_t *
mcuf_ranges(const lws_display_font_t *f, const uint8_t *bf)
{
	lws_mcufont_file_t *ff = (lws_mcufont_file_t *)f->priv;

	if (ff)
		return ff->ranges;

	return bf + lws_ser_ru32be(bf + MCUFO_FOFS_CHAR_RANGE_TABLES);
}

/* glyph idx of range n: its offset from the range's data base */

static uint32_t
mcuf_glyph_ofs(const lws_display_font_t *f, const uint8_t *bf,
	       const uint8_t *r, unsigned int n, uint32_t idx)
{
	lws_mcufont_file_t *ff = (lws_mcufont_file_t *)f->priv;

	if (ff)
		return lws_ser_ru16be((const uint8_t *)&ff->gofs[n][idx]);

	return lws_ser_ru16be(bf + lws_ser_ru32be(r + 8) + (idx * 2));
}

/*
 * The compressed string of the glyph at file offset fofs, len bytes: from
 * the blob directly for a flash font, else from the cache, read from the
 * file on a miss.  With pin set the string stays resident until
 * lws_display_font_mcufont_release_glyphs() lets it go, and *ppin says
 * what to release.
 */

static const uint8_t *
mcuf_glyph(lws_dlo_text_t *text, const uint8_t *bf, uint32_t fofs,
	   uint32_t len, int pin, void **ppin)
{
	lws_display_font_t *f = (lws_display_font_t *)text->font;
	lws_mcufont_file_t *ff = (lws_mcufont_file_t *)f->priv;
	mcuf_gent_t *ge;

	if (ppin)
		*ppin = NULL;

	if (!ff)
		return bf + fofs;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ff->glyphs)) {
		ge = lws_container_of(d, mcuf_gent_t, list);

		if (ge->fofs == fofs)
			goto hit;
	} lws_end_foreach_dll(d);

	if (!len || len > 0xffff || fofs + len > ff->file_len)
		return NULL;

	ge = lws_malloc(sizeof(*ge) + len, __func__);
	if (!ge)
		return NULL;

	memset(ge, 0, sizeof(*ge));
	ge->fofs = fofs;
	ge->len = (uint16_t)len;
	if (mcuf_file_read(ff, fofs, (uint8_t *)&ge[1], len)) {
		lws_free(ge);
		return NULL;
	}
	lws_dll2_add_tail(&ge->list, &ff->glyphs);
	ff->glyph_bytes += sizeof(*ge) + len;
	ff->rc_glyphs.resident = ff->glyph_bytes;

hit:
	/* most recently used */
	lws_dll2_remove(&ge->list);
	lws_dll2_add_tail(&ge->list, &ff->glyphs);
	lws_reclaimable_touch(&ff->rc_glyphs);

	if (pin) {
		ge->pins++;
		ff->core_pins++;
		ff->rc_core.pins = ff->core_pins;
		if (ppin)
			*ppin = ge;
	}

	return (const uint8_t *)&ge[1];
}

/* the glyphs attached to text are being freed: let their strings go */

void
lws_display_font_mcufont_release_glyphs(lws_dlo_text_t *text)
{
	lws_display_font_t *f = (lws_display_font_t *)text->font;
	lws_mcufont_file_t *ff = f ? (lws_mcufont_file_t *)f->priv : NULL;

	if (!ff)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&text->glyphs)) {
		lws_font_glyph_t *fg = lws_container_of(d, lws_font_glyph_t,
							list);
		mcuf_gent_t *ge = (mcuf_gent_t *)fg->pin;

		if (ge && ge->pins) {
			ge->pins--;
			if (ff->core_pins)
				ff->core_pins--;
		}
		fg->pin = NULL;
	} lws_end_foreach_dll(d);

	ff->rc_core.pins = ff->core_pins;
}

static void
write_ref_codeword(mcu_glyph_t *g, const uint8_t *bf, uint8_t c)
{
	mcu_stack_t *st;
	uint32_t o, o1;

	if (!c) {
		g->runlen = 1;
		g->runstate = RS_SKIP_PX;
		return;
	}
	if (c <= 15) {
		g->alpha = (uint8_t)(0x11 * c);
		g->runlen = 1;
		g->runstate = RS_WRITE_PX;
		return;
	}
	if (c == REF_FILLZEROS) {
		/* Fill with zeroes to end */
		g->alpha = 0;
		g->runlen = 1000000;
		g->runstate = RS_WRITE_PX;
		return;
	}
	if (c < DICT_START)
		return;

	if (c < DICT_START + lws_ser_ru32be(bf + MCUFO_COUNT_RLE_DICT)) {
		/* write_rle_dictentry */
		st = mcu_push(g);
		if (!st)
			return;

		o1 = lws_ser_ru32be(bf + MCUFO_FOFS_DICT_OFS);
		o = lws_ser_ru16be(bf + o1 + ((c - DICT_START) * 2));
		st->dictlen = (int16_t)(lws_ser_ru16be(bf + o1 +
						((c - DICT_START + 1) * 2)) - o);

		st->dict = bf + lws_ser_ru32be(bf + MCUFO_FOFS_DICT_DATA) + o;
		st->state = DICT2;
		return;
	}

	st = mcu_push(g);
	if (!st)
		return;

	st->bitcount = fillentry_bitcount(c);
	st->byte = (uint8_t)(c - DICT_START7BIT);
	st->state = DICT1;
	g->runlen = 0;
}

static void
mcufont_next_code(mcu_glyph_t *g)
{
	lws_dlo_text_t *t = lws_dll2_owner_container(&g->fg.list, lws_dlo_text_t,
					     glyphs);
	const uint8_t *bf = (const uint8_t *)t->font->data;
	uint8_t c = *g->comp++;
	mcu_stack_t *st;
	uint32_t o, o1;

	if (c < DICT_START + lws_ser_ru32be(&bf[MCUFO_COUNT_RLE_DICT]) ||
	    c >= DICT_START + lws_ser_ru32be(&bf[MCUFO_COUNT_REF_RLE_DICT])) {
		write_ref_codeword(g, bf, c);
		return;
	}

	/* write_ref_dictentry() */

	st = mcu_push(g);
	if (!st)
		return;

	o1 = lws_ser_ru32be(bf + MCUFO_FOFS_DICT_OFS);
	o = lws_ser_ru16be(bf + o1 + ((c - DICT_START) * 2));
	st->dictlen = (int16_t)(lws_ser_ru16be(bf + o1 +
					((c - DICT_START + 1) * 2)) - o);

	st->dict = bf + lws_ser_ru32be(bf + MCUFO_FOFS_DICT_DATA) + o;
	st->state = DICT3;
}

/* lookup and append a glyph for specific unicode to the text glyph list */

/*
 * The file offset of the glyph's compressed string, and its length; 0 if
 * the font has no glyph for it (or its fallback)
 */

static uint32_t
font_mcufont_uniglyph_lookup(lws_dlo_text_t *text, const uint8_t *bf,
			     uint32_t unicode, uint32_t *plen)
{
	const lws_display_font_t *f = text->font;
	lws_mcufont_file_t *ff = (lws_mcufont_file_t *)f->priv;
	uint32_t entries = lws_ser_ru32be(&bf[MCUFO_COUNT_CHAR_RANGE_TABLES]);
	const uint8_t *r;
	unsigned int n;

	if (entries > MCUFO_MAX_RANGES) /* coverity sanity */
		return 0;

	do {
		/* each pass walks the range table from its start */
		r = mcuf_ranges(f, bf);

		for (n = 0; n < entries; n++) {
			uint32_t cs = lws_ser_ru32be(r + 0), ce = lws_ser_ru32be(r + 4);

			if (cs >= 0x100000 || !ce || ce > 0x10000)
				return 0;

			if (unicode >= cs && unicode < cs + ce) {
				uint32_t db = lws_ser_ru32be(r + 0xc), cbo, next,
					 idx = unicode - cs;

				if (db >= text->font->data_len)
					return 0;

				cbo = db + mcuf_glyph_ofs(f, bf, r, n, idx);
				if (cbo >= text->font->data_len)
					return 0;

				/*
				 * The length, for a file-backed font: to the
				 * nearest glyph start after ours, or the end
				 * of the range's data.  Identical glyphs share
				 * a string, so the table isn't in order and
				 * the next entry isn't necessarily ours
				 */
				if (plen && ff) {
					uint32_t k, oo = cbo - db;

					next = ff->gend[n];
					for (k = 0; k < ce; k++) {
						uint32_t o1 = mcuf_glyph_ofs(f,
							bf, r, n, k);

						if (o1 > oo && db + o1 < next)
							next = db + o1;
					}
					*plen = next > cbo ? next - cbo : 0;
				} else if (plen)
					*plen = 0;

				return cbo;
			}

			r += 16;
		}

		if (unicode == lws_ser_ru32be(&bf[MCUFO_UNICODE_FALLBACK]))
			return 0;
		unicode = lws_ser_ru32be(&bf[MCUFO_UNICODE_FALLBACK]);

	} while (1);
}

static mcu_glyph_t *
font_mcufont_uniglyph(lws_dlo_text_t *text, uint32_t unicode)
{
	const uint8_t *bf = mcuf_bf(text), *comp;
	uint32_t ofs, len = 0;
	mcu_glyph_t *g;
	void *pin;
	size_t n;

	if (!bf)
		return NULL;

	ofs = font_mcufont_uniglyph_lookup(text, bf, unicode, &len);
	if (!ofs)
		return NULL;

	/* pinned from now until the glyphs are released */
	comp = mcuf_glyph(text, bf, ofs, len, 1, &pin);
	if (!comp)
		return NULL;

//	lwsl_warn("%s: text->text_len %u: %c\n", __func__, text->text_len, (char)unicode);

	/*
	 * text_len is the count of bytes of the run that fitted in the box, ie,
	 * it comes from the document.  It's only a hint for how big to make the
	 * lwsac chunks, so bound it to a sane granule and let lwsac add further
	 * chunks if the run really does need that many glyphs
	 */

	n = text->text_len + 1;
	if (n > LWS_DLO_GLYPH_AC_GRANULE)
		n = LWS_DLO_GLYPH_AC_GRANULE;

	g = lwsac_use_zero(&text->ac_glyphs, sizeof(*g), n * sizeof(*g));
	if (!g) {
		lws_font_glyph_t fg;

		/* let the string go again */
		memset(&fg, 0, sizeof(fg));
		fg.pin = pin;
		lws_dll2_add_tail(&fg.list, &text->glyphs);
		lws_display_font_mcufont_release_glyphs(text);
		lws_dll2_remove(&fg.list);

		return NULL;
	}

	g->fg.pin = pin;
	g->comp = comp;
	g->fg.cwidth.whole = *g->comp++;
	g->fg.cwidth.frac = 0;

	lws_dll2_add_tail(&g->fg.list, &text->glyphs);

	return g;
}

int
lws_display_font_mcufont_getcwidth(lws_dlo_text_t *text, uint32_t unicode,
				   lws_fx_t *fx)
{
	const uint8_t *bf = mcuf_bf(text), *comp;
	uint32_t ofs, len = 0;

	if (!bf)
		return 1;

	ofs = font_mcufont_uniglyph_lookup(text, bf, unicode, &len);
	if (!ofs)
		return 1;

	/* the width is the first byte of the string: touched, not pinned */
	comp = mcuf_glyph(text, bf, ofs, len, 0, NULL);
	if (!comp)
		return 1;

	fx->whole = comp[0];
	fx->frac = 0;

	return 0;
}

lws_font_glyph_t *
lws_display_font_mcufont_image_glyph(lws_dlo_text_t *text, uint32_t unicode,
				     char attach)
{
	const uint8_t *bf = mcuf_bf(text);
	mcu_glyph_t *g;

	if (!bf)
		return NULL;

	/* one text dlo has glyphs from all the same fonts and attributes */
	if (!text->font_height) {
		text->font_height = (int16_t)lws_ser_ru16be(&bf[MCUFO16_HEIGHT]);
		text->font_y_baseline = (int16_t)(text->font_height -
				   lws_ser_ru16be(&bf[MCUFO16_BASELINE_Y]));
		text->font_line_height = (int16_t)lws_ser_ru16be(&bf[MCUFO16_LINE_HEIGHT]);
	}

	lws_display_font_mcufont_getcwidth(text, unicode, &text->_cwidth);

	if (!attach)
		return NULL;

	g = font_mcufont_uniglyph(text, unicode);
	if (!g)
		return NULL;

	g->fg.height.whole = lws_ser_ru16be(bf + MCUFO16_HEIGHT);
	g->fg.height.frac = 0;

	return &g->fg;
}

/*
 * Run every glyph's run decoder across one row of the text, at row yo of the
 * glyph bounding box.  The decoders are forward-only state: each call
 * produces the row after the one before.  With draw clear the row is
 * decoded and thrown away, to fast-forward to a row a re-scan wants
 */

static void
mcufont_row(lws_dlo_text_t *text, const uint8_t *bf, int yo, char draw)
{
	mcu_glyph_t *g;
	uint8_t c, el;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&text->glyphs)) {
		lws_font_glyph_t *fg = lws_container_of(d, lws_font_glyph_t, list);

		g = (mcu_glyph_t *)fg;
		fg->x = 0;

		while (yo < (int)fg->height.whole &&
		       fg->x < lws_ser_ru16be(bf + MCUFO16_WIDTH)) {
			switch (g->runstate) {
			case RS_IDLE:
				switch (g->st[(int)g->sp].state) {
				case COMP:
					mcufont_next_code(g);
					break;

				case DICT1_CONT:
					/* back to DICT1 after doing the skip */
					if (mcu_pop(g))
						continue;
					g->runstate = RS_SKIP_PX;
					g->runlen = 1;
					continue;

				case DICT1:
					/* write_bin_codeword() states */
					el = 0;
					while (g->st[(int)g->sp].bitcount--) {
						c = g->st[(int)g->sp].byte;
						g->st[(int)g->sp].byte >>= 1;
						if (c & 1)
							g->st[(int)g->sp].runlen++;
						else {
							if (g->st[(int)g->sp].runlen) {
								mcu_stack_t *sn;
								int rl = g->st[(int)g->sp].runlen;

								g->st[(int)g->sp].runlen = 0;
								sn = mcu_push(g);
								if (!sn) {
									el = 1;
									break;
								}
								g->alpha = 255;
								g->runstate = RS_WRITE_PX;
								g->runlen = rl;
								sn->state = DICT1_CONT;
								el = 1;
								break;
							}
							g->runstate = RS_SKIP_PX;
							g->runlen = 1;
							el = 1;
							break;
						}
					}

					if (el)
						continue;

					/* back out of DICT1 */
					if (mcu_pop(g))
						continue;

					if (g->st[(int)g->sp + 1].runlen) {
						g->alpha = 255;
						g->runstate = RS_WRITE_PX;
						g->runlen = g->st[(int)g->sp + 1].runlen;
						g->st[(int)g->sp + 1].runlen = 0;
						continue;
					}
					break;

				case DICT2: /* write_rle_dictentry */
					c = (*g->st[(int)g->sp].dict++);
					if (--g->st[(int)g->sp].dictlen <= 0 &&
					    mcu_pop(g))
						continue;
					if ((c & RLE_CODEMASK) == RLE_ZEROS) {
						g->runstate = RS_SKIP_PX;
						g->runlen = c & RLE_VALMASK;
						continue;
					}
					if ((c & RLE_CODEMASK) == RLE_64ZEROS) {
						g->runstate = RS_SKIP_PX;
						g->runlen = ((c & RLE_VALMASK) + 1) * 64;
						continue;
					}
					if ((c & RLE_CODEMASK) == RLE_ONES) {
						g->alpha = 255;
						g->runstate = RS_WRITE_PX;
						g->runlen = (c & RLE_VALMASK) + 1;
						continue;
					}
					if ((c & RLE_CODEMASK) == RLE_SHADE) {
						g->alpha = (uint8_t)(((c & RLE_VALMASK) & 0xf) * 0x11);
						g->runstate = RS_WRITE_PX;
						g->runlen = ((c & RLE_VALMASK) >> 4) + 1;
						continue;
					}
					break;

				case DICT3:
					c = *g->st[(int)g->sp].dict++;
					if (--g->st[(int)g->sp].dictlen <= 0 &&
					    mcu_pop(g))
						continue;

					write_ref_codeword(g, bf,  c);
					break;
				}
				break;
			case RS_SKIP_PX:
				fg->x++;
				if (--g->runlen)
					break;
				g->runstate = RS_IDLE;
				break;

			case RS_WRITE_PX:
				if (g->alpha && draw)
					draw_px(text, g);
				g->fg.x++;
				if (--g->runlen)
					break;
				g->runstate = RS_IDLE;
				break;

			case RS_ALLZERO:
				fg->x++;
				if (--g->runlen)
					break;
				g->runstate = RS_IDLE;
				break;
			}
		}

	} lws_end_foreach_dll(d);

}

lws_stateful_ret_t
lws_display_font_mcufont_render(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);
	const uint8_t *bf = mcuf_bf(text);
	lws_fx_t ax, ay, t, t1, t2, t3;
	int s, e, yo;

	if (!bf)
		/* can't be made resident right now: try again next line */
		return LWS_SRET_OK;

	lws_fx_add(&ax, &rs->st[rs->sp].co.x, &dlo->box.x);
	lws_fx_add(&t, &ax, &dlo->box.w);
	lws_fx_add(&ay, &rs->st[rs->sp].co.y, &dlo->box.y);
	lws_fx_add(&t1, &ay, &dlo->box.h);

	lws_fx_add(&t2, &ax, &text->bounding_box.w);

	text->curr = rs->curr;
	text->ic = rs->ic;
	text->line = rs->line;

	s = ax.whole;
	e = lws_fx_roundup(&t2);

	if (e <= 0)
		return LWS_SRET_OK; /* wholly off to the left */
	if (s >= rs->ic->wh_px[0].whole)
		return LWS_SRET_OK; /* wholly off to the right */

	if (e >= rs->ic->wh_px[0].whole)
		e = rs->ic->wh_px[0].whole;

	/* figure out our y position inside the glyph bounding box */
	yo = rs->curr - ay.whole;

	if (yo < 0)
		/* the walk enters us from the line above our box */
		return LWS_SRET_OK;

	/*
	 * The glyph run decoders only go forwards.  A retained display list
	 * is scanned more than once (a viewport re-scan, or a scan restarted
	 * by a late asset), so if this row is at or above where they have
	 * got to, start again from fresh glyphs: the ones left from the
	 * previous pass would carry on from wherever that pass stopped and
	 * emit their lower rows over the top of this line.  Appending fresh
	 * glyphs to the stale ones did exactly that.
	 */

	if (!text->glyphs.count || yo < (int)text->glyph_row) {
		lws_display_font_mcufont_release_glyphs(text);
		lwsac_free(&text->ac_glyphs);
		memset(&text->glyphs, 0, sizeof(text->glyphs));
		text->glyph_row = 0;

		lws_display_dlo_text_attach_glyphs(text);

		t3.whole = lws_ser_ru16be(bf + MCUFO16_BASELINE_X);
		t3.frac = 0;
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&text->glyphs)) {
			lws_font_glyph_t *fg = lws_container_of(d, lws_font_glyph_t, list);
			lws_fx_sub(&fg->xpx, &fg->xpx, &t3);
			fg->xorg = rs->st[rs->sp].co.x;
		} lws_end_foreach_dll(d);
	}

#if 0
	{
		uint32_t dc = 0xff0000ff;
		int s1 = s;
		/* from origin.x + dlo->box.x */
		for (s1 = ax.whole; s1 < t2.whole; s1++)
			lws_surface_set_px(ic, line, s1, &dc);

		memset(&ce, 0, sizeof(ce));
	}
#endif

	/* a re-scan can enter partway down: discard rows up to this one */

	while ((int)text->glyph_row < yo) {
		mcufont_row(text, bf, text->glyph_row, 0);
		text->glyph_row++;
	}

	mcufont_row(text, bf, yo, 1);
	text->glyph_row++;

	return LWS_SRET_OK;
}
