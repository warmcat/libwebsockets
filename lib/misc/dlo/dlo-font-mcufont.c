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
 * comes from the document, so we don't let it size the allocation itself.
 *
 * Every glyph of a run is decoding at once while the raster is on its rows,
 * and they don't need to be contiguous.  A glyph is ~120 bytes on 32-bit, so a
 * run of 40 in one chunk wanted ~4.7KB in one piece, which a fragmented heap
 * with far more than that free can't give: the run was then not drawn on
 * that line.  Chunks of 8 are ~1KB each, at the cost of a chunk header per 8.
 */

#define LWS_DLO_GLYPH_AC_GRANULE	8

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
	const uint8_t		*bf;	/* the blob with its dictionary */
	const uint8_t		*comp;
	const uint8_t		*comp_end; /* the font's string ends here */

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
	lws_display_render_set_px(t->rs, t1.whole, &c);
}

/*
 * Blobs not simply in memory in one piece, eg, file-backed fonts: the
 * decoder works from absolute offsets into the font blob, so the blob's
 * prefix (header, names, dictionary, dictionary offsets) stays resident while
 * it is in use, and the range tables, glyph offset tables and glyph strings
 * are served from copies and a cache.  Flash-resident fonts have no core and
 * everything is simply in .data.
 */

void
lws_mcuf_core_free(lws_mcuf_core_t *c)
{
	int n;

	lws_free_set_NULL(c->prefix);
	lws_free_set_NULL(c->ranges);
	for (n = 0; n < MCUFO_MAX_RANGES; n++)
		lws_free_set_NULL(c->gofs[n]);
	c->core_bytes = 0;
}

/* the cached glyph strings, or only the ones no text has attached: freed */

size_t
lws_mcuf_core_glyphs_free(lws_mcuf_core_t *c, int unpinned_only)
{
	size_t freed = 0;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&c->glyphs)) {
		mcuf_gent_t *ge = lws_container_of(d, mcuf_gent_t, list);

		if (unpinned_only && ge->pins)
			continue;

		lws_dll2_remove(&ge->list);
		freed += sizeof(*ge) + ge->len;
		c->glyph_bytes -= sizeof(*ge) + ge->len;
		lws_free(ge);
	} lws_end_foreach_dll_safe(d, d1);

	return freed;
}

/*
 * Bring in the core of the blob_len bytes of blob c->read reads from,
 * checking as it goes that it is a font we can use and the core we take
 * from it is inside it.  1 if it isn't a font we can use, -1 if there's no
 * memory for its core just now, when nothing of it is left allocated.  The
 * caller of a font that's fine but finds no memory may want it again later,
 * eg, once something gives back its heap.
 */

int
lws_mcuf_core_load(lws_mcuf_core_t *c, uint32_t blob_len)
{
	uint32_t o, n, rt, nr, cnt, plen;
	uint8_t hdr[MCUFO_HDR_LEN];
	unsigned int m;

	if (blob_len < sizeof(hdr) || c->read(c, 0, hdr, sizeof(hdr)))
		return 1;

	if (lws_ser_ru32be(hdr) != LWS_FOURCC('M', 'C', 'U', 'F'))
		return 1;

	/* the prefix: up to the end of the dictionary offsets table */

	o = lws_ser_ru32be(hdr + MCUFO_FOFS_DICT_OFS);
	n = lws_ser_ru32be(hdr + MCUFO_COUNT_REF_RLE_DICT);
	if (n > 512 || o > blob_len)
		return 1;
	plen = o + ((n + 1) * 2);
	rt = lws_ser_ru32be(hdr + MCUFO_FOFS_CHAR_RANGE_TABLES);
	nr = lws_ser_ru32be(hdr + MCUFO_COUNT_CHAR_RANGE_TABLES);
	if (plen > blob_len || nr > MCUFO_MAX_RANGES ||
	    rt > blob_len || (blob_len - rt) / 16 < nr)
		return 1;

	c->prefix = lws_malloc(plen, __func__);
	c->ranges = lws_malloc(nr * 16, __func__);
	if (!c->prefix || !c->ranges)
		goto nomem;
	if (c->read(c, 0, c->prefix, plen) ||
	    c->read(c, rt, c->ranges, nr * 16) ||
	    lws_display_font_mcufont_check(c->prefix, plen))
		goto bail;

	/* the full name must be a NUL-terminated string inside the prefix */

	o = lws_ser_ru32be(c->prefix + MCUFO_FOFS_FULLNAME);
	if (o >= plen || !memchr(c->prefix + o, '\0', plen - o))
		goto bail;

	c->prefix_len = plen;
	c->blob_len = blob_len;
	c->nranges = (uint16_t)nr;
	c->core_bytes = plen + nr * 16;

	/* each range's glyph offset table, and where its data ends */

	for (m = 0; m < nr; m++) {
		const uint8_t *r = c->ranges + (m * 16);
		uint32_t ot = lws_ser_ru32be(r + 8), db = lws_ser_ru32be(r + 0xc),
			 end = rt;
		unsigned int k;

		cnt = lws_ser_ru32be(r + 4);
		if (!cnt || cnt > 0x10000 || ot > blob_len ||
		    (blob_len - ot) / 2 < cnt || db > blob_len)
			goto bail;

		c->gofs[m] = lws_malloc(cnt * 2, __func__);
		if (!c->gofs[m])
			goto nomem;
		if (c->read(c, ot, (uint8_t *)c->gofs[m], cnt * 2))
			goto bail;
		c->core_bytes += cnt * 2;

		/* the data runs to the next thing in the blob after it */
		for (k = 0; k < nr; k++) {
			uint32_t kt = lws_ser_ru32be(c->ranges + (k * 16) + 8);

			if (kt > db && kt < end)
				end = kt;
		}
		c->gend[m] = end;
	}

	return 0;

nomem:
	lws_mcuf_core_free(c);

	return -1;

bail:
	lws_mcuf_core_free(c);

	return 1;
}

static void
mcuf_file_core_free(lws_mcufont_file_t *ff)
{
	lws_vfs_file_close(&ff->fd);
	lws_mcuf_core_free(&ff->core);
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
	size_t freed = lws_mcuf_core_glyphs_free(&ff->core, 1);

	r->resident = ff->core.glyph_bytes;
	lwsl_info("%s: %s: %u\n", __func__, ff->path, (unsigned int)freed);

	return freed;
}

static int
mcuf_file_read(lws_mcuf_core_t *c, uint32_t ofs, uint8_t *buf, uint32_t len)
{
	lws_mcufont_file_t *ff = lws_container_of(c, lws_mcufont_file_t, core);
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
	lws_mcufont_file_t *ff = mcuf_file(f);
	lws_fop_flags_t fl = LWS_O_RDONLY;

	if (!ff)
		return 0; /* flash-resident */

	if (ff->core.prefix) {
		lws_reclaimable_touch(&ff->rc_core);
		return 0;
	}

	ff->fd = lws_vfs_file_open(lws_get_fops(ff->cx), ff->path, &fl);
	if (!ff->fd)
		return 1;

	ff->core.read = mcuf_file_read;
	ff->core.rc_glyphs = &ff->rc_glyphs;
	if (lws_mcuf_core_load(&ff->core,
			       (uint32_t)lws_vfs_get_length(ff->fd))) {
		mcuf_file_core_free(ff);
		return 1;
	}

	ff->rc_core.resident = ff->core.core_bytes;
	f->data = ff->core.prefix;
	f->data_len = ff->core.blob_len;
	lws_reclaimable_touch(&ff->rc_core);

	return 0;
}

void
lws_display_font_mcufont_file_destroy(lws_display_font_t *f)
{
	lws_mcufont_file_t *ff = mcuf_file(f);

	if (!ff)
		return;

	lws_reclaimable_remove(&ff->rc_core);
	lws_reclaimable_remove(&ff->rc_glyphs);
	mcuf_file_core_free(ff);
	lws_mcuf_core_glyphs_free(&ff->core, 0);
	lws_free(ff->path);
	lws_free(ff);
	f->priv = NULL;
}

/*
 * The face's header, or NULL if it can't be made resident right now.  For a
 * file-backed face it is the start of the prefix; for a face from a server,
 * it is the copy taken from the first page that came
 */

static const uint8_t *
mcuf_bf(lws_dlo_text_t *text)
{
	lws_display_font_t *f = (lws_display_font_t *)text->font;

	if (mcuf_file(f) && lws_display_font_mcufont_file_core(f))
		return NULL;

	return f->data;
}

/*
 * The blob unicode's glyph is looked up in, its length *len, and *core, the
 * core it is served through if it isn't simply in memory in one piece: the
 * face's (the prefix, for a file-backed face), or for a face from a server,
 * the page with the glyph.  NULL if it isn't resident right now: a page of a
 * face from a server is only fetched by layout or render asking for it,
 * through lws_font_text_resident()
 */

static const uint8_t *
mcuf_src(lws_dlo_text_t *text, uint32_t unicode, size_t *len,
	 lws_mcuf_core_t **core)
{
	lws_display_font_t *f = (lws_display_font_t *)text->font;
	lws_mcufont_file_t *ff = mcuf_file(f);
#if defined(LWS_DLO_REMOTE_FONTS)
	lws_mcufont_remote_t *r = mcuf_remote(f);

	if (r)
		return lws_mcufont_remote_blob(r, unicode, len, core);
#endif
	(void)unicode;

	if (!mcuf_bf(text))
		return NULL;

	*core = ff ? &ff->core : NULL;
	*len = f->data_len;

	return f->data;
}

/* the char range tables */

static const uint8_t *
mcuf_ranges(const lws_mcuf_core_t *core, const uint8_t *bf)
{
	if (core)
		return core->ranges;

	return bf + lws_ser_ru32be(bf + MCUFO_FOFS_CHAR_RANGE_TABLES);
}

/* glyph idx of range n: its offset from the range's data base */

static uint32_t
mcuf_glyph_ofs(const lws_mcuf_core_t *core, const uint8_t *bf,
	       const uint8_t *r, unsigned int n, uint32_t idx)
{
	if (core)
		return lws_ser_ru16be((const uint8_t *)&core->gofs[n][idx]);

	return lws_ser_ru16be(bf + lws_ser_ru32be(r + 8) + (idx * 2));
}

/*
 * The compressed string of the glyph at blob offset fofs, len bytes: from
 * the blob directly if it is in one piece, or from the piece of it in
 * memory that has the whole string, else from the core's cache, read into
 * it on a miss.  With pin set, for a file-backed font, the string stays
 * resident until lws_display_font_mcufont_release_glyphs() lets it go, and
 * *ppin says what to release.
 */

static const uint8_t *
mcuf_glyph(lws_dlo_text_t *text, lws_mcuf_core_t *core, const uint8_t *bf,
	   uint32_t fofs, uint32_t len, int pin, void **ppin)
{
	lws_mcufont_file_t *ff = mcuf_file(text->font);
	mcuf_gent_t *ge;

	if (ppin)
		*ppin = NULL;

	if (!core)
		return bf + fofs;

	if (!len || len > 0xffff || fofs > core->blob_len ||
	    len > core->blob_len - fofs)
		return NULL;

	if (core->at) {
		size_t avail;
		const uint8_t *p = core->at(core, fofs, &avail);

		if (p && avail >= len)
			return p;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&core->glyphs)) {
		ge = lws_container_of(d, mcuf_gent_t, list);

		if (ge->fofs == fofs)
			goto hit;
	} lws_end_foreach_dll(d);

	ge = lws_malloc(sizeof(*ge) + len, __func__);
	if (!ge)
		return NULL;

	memset(ge, 0, sizeof(*ge));
	ge->fofs = fofs;
	ge->len = (uint16_t)len;
	if (core->read(core, fofs, (uint8_t *)&ge[1], len)) {
		lws_free(ge);
		return NULL;
	}
	lws_dll2_add_tail(&ge->list, &core->glyphs);
	core->glyph_bytes += sizeof(*ge) + len;
	if (core->rc_glyphs)
		core->rc_glyphs->resident = core->rc_glyphs_base +
					    core->glyph_bytes;

hit:
	/* most recently used */
	lws_dll2_remove(&ge->list);
	lws_dll2_add_tail(&ge->list, &core->glyphs);
	if (core->rc_glyphs)
		lws_reclaimable_touch(core->rc_glyphs);

	if (pin && ff) {
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
	lws_mcufont_file_t *ff = f ? mcuf_file(f) : NULL;

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

/*
 * The decoder indexes the dictionary offsets table by codes from the glyph
 * strings, and walks the dictionary data from the offsets it finds there,
 * without checking either against the font: so before a font is used, check
 * here that the header is one we understand, and that every dictionary entry
 * a code can reach lies inside the len bytes at bf.
 */

int
lws_display_font_mcufont_check(const uint8_t *bf, size_t len)
{
	uint32_t nrle, nref, dd, ds, dofs, n;

	if (len < MCUFO_HDR_LEN)
		return 1;

	if ((lws_ser_ru32be(bf + MCUFO_FLAGS_VER) & 0xff) != MCUFO_VERSION) {
		lwsl_err("%s: font format version %u, we need %u\n", __func__,
			 (unsigned int)(lws_ser_ru32be(bf + MCUFO_FLAGS_VER) & 0xff),
			 MCUFO_VERSION);
		return 1;
	}

	/*
	 * lws_font_glyph_t.x is an int8_t and the renderer counts it up to the
	 * font's declared width, so a wider font would overflow it
	 */

	if (lws_ser_ru16be(bf + MCUFO16_WIDTH) > 127)
		return 1;

	/* the kerning profiles cut the glyph height into this many bands */

	if (!bf[MCUFO_KERN_BANDS] ||
	    bf[MCUFO_KERN_BANDS] > MCUFO_MAX_KERN_BANDS ||
	    bf[MCUFO_KERN_BANDS] > lws_ser_ru16be(bf + MCUFO16_HEIGHT))
		return 1;

	nrle = lws_ser_ru32be(bf + MCUFO_COUNT_RLE_DICT);
	nref = lws_ser_ru32be(bf + MCUFO_COUNT_REF_RLE_DICT);
	dd = lws_ser_ru32be(bf + MCUFO_FOFS_DICT_DATA);
	ds = lws_ser_ru32be(bf + MCUFO_SIZE_DICT_DATA);
	dofs = lws_ser_ru32be(bf + MCUFO_FOFS_DICT_OFS);

	/* codes are bytes, and entry lengths have to fit the int16_t */

	if (nrle > nref || nref > 256 - DICT_START || ds > 0x7fff ||
	    dd > len || ds > len - dd ||
	    dofs > len || (len - dofs) / 2 < nref + 1)
		return 1;

	for (n = 0; n <= nref; n++)
		if (lws_ser_ru16be(bf + dofs + (n * 2)) > ds)
			return 1;

	return 0;
}

/*
 * Enter dictionary entry idx, to be walked in state.  The font's dictionary
 * was checked by lws_display_font_mcufont_check() before it was used,
 * so the entry lies inside the font... an empty one has nothing to walk
 */

static void
mcu_dict_entry(mcu_glyph_t *g, const uint8_t *bf, unsigned int idx,
	       uint8_t state)
{
	uint32_t o1 = lws_ser_ru32be(bf + MCUFO_FOFS_DICT_OFS);
	uint16_t o = lws_ser_ru16be(bf + o1 + (idx * 2)),
		 e = lws_ser_ru16be(bf + o1 + ((idx + 1) * 2));
	mcu_stack_t *st;

	if (e <= o)
		return;

	st = mcu_push(g);
	if (!st)
		return;

	st->dictlen = (int16_t)(e - o);
	st->dict = bf + lws_ser_ru32be(bf + MCUFO_FOFS_DICT_DATA) + o;
	st->state = state;
}

static void
write_ref_codeword(mcu_glyph_t *g, const uint8_t *bf, uint8_t c)
{
	mcu_stack_t *st;

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
		mcu_dict_entry(g, bf, (unsigned int)(c - DICT_START), DICT2);
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
	const uint8_t *bf = g->bf;
	uint8_t c;

	if (g->comp >= g->comp_end) {
		/* the string ended without the glyph being complete */
		mcu_abandon_glyph(g);
		return;
	}

	c = *g->comp++;

	if (c < DICT_START + lws_ser_ru32be(&bf[MCUFO_COUNT_RLE_DICT]) ||
	    c >= DICT_START + lws_ser_ru32be(&bf[MCUFO_COUNT_REF_RLE_DICT])) {
		write_ref_codeword(g, bf, c);
		return;
	}

	/* write_ref_dictentry() */

	mcu_dict_entry(g, bf, (unsigned int)(c - DICT_START), DICT3);
}

/* lookup and append a glyph for specific unicode to the text glyph list */

/*
 * The kerning profile follows the width at the start of each glyph string:
 * the first and last bands of the glyph height with ink in, and the leftmost
 * and rightmost columns with ink in the first; then for each band after, the
 * change in those as two signed nibbles, or if either is too big for that,
 * MCUFO_KERN_ESCAPE and the two columns.  Just MCUFO_NO_INK if the glyph has
 * no ink at all.  The profile's length at p, or 0 if it doesn't fit the
 * string or the font.  With m, it is unpacked into m too.
 */

static size_t
mcuf_profile(const uint8_t *bf, const uint8_t *p, const uint8_t *end,
	     lws_glyph_metrics_t *m)
{
	const uint8_t *q = p + 4;
	unsigned int b, first, last;

	if (p >= end)
		return 0;

	if (*p == MCUFO_NO_INK) {
		if (m)
			m->first = MCUFO_NO_INK;
		return 1;
	}

	/*
	 * The face's band count was checked against MCUFO_MAX_KERN_BANDS when
	 * it was loaded, but the bands index m->l[] and m->r[] here, so make
	 * sure locally.  The bands are read once and only the checked copies
	 * used after.
	 */

	if (end - p < 4)
		return 0;

	first = p[0];
	last = p[1];
	if (first > last || last >= bf[MCUFO_KERN_BANDS] ||
	    last >= MCUFO_MAX_KERN_BANDS)
		return 0;

	if (m) {
		m->first = (uint8_t)first;
		m->last = (uint8_t)last;
		m->l[first] = p[2];
		m->r[first] = p[3];
	}

	for (b = first + 1; b <= last; b++) {
		if (q >= end)
			return 0;

		if (*q == MCUFO_KERN_ESCAPE) {
			if (end - q < 3)
				return 0;
			if (m) {
				m->l[b] = q[1];
				m->r[b] = q[2];
			}
			q += 3;
			continue;
		}

		/* the nibbles are signed */
		if (m) {
			m->l[b] = (uint8_t)(m->l[b - 1] +
					    (((*q >> 4) ^ 8) - 8));
			m->r[b] = (uint8_t)(m->r[b - 1] +
					    (((*q & 0xf) ^ 8) - 8));
		}
		q++;
	}

	return (size_t)(q - p);
}

/*
 * The file offset of the glyph's compressed string, and its length; 0 if
 * the font has no glyph for it (or its fallback)
 */

static uint32_t
font_mcufont_uniglyph_lookup(const lws_mcuf_core_t *core, const uint8_t *bf,
			     size_t blen, uint32_t unicode, uint32_t *plen)
{
	uint32_t entries = lws_ser_ru32be(&bf[MCUFO_COUNT_CHAR_RANGE_TABLES]);
	const uint8_t *r;
	unsigned int n;

	if (entries > MCUFO_MAX_RANGES) /* coverity sanity */
		return 0;

	do {
		/* each pass walks the range table from its start */
		r = mcuf_ranges(core, bf);

		for (n = 0; n < entries; n++) {
			uint32_t cs = lws_ser_ru32be(r + 0), ce = lws_ser_ru32be(r + 4);

			if (cs >= 0x100000 || !ce || ce > 0x10000)
				return 0;

			if (unicode >= cs && unicode < cs + ce) {
				uint32_t db = lws_ser_ru32be(r + 0xc), cbo, next,
					 idx = unicode - cs;

				if (db >= blen)
					return 0;

				cbo = db + mcuf_glyph_ofs(core, bf, r, n, idx);
				if (cbo >= blen)
					return 0;

				/*
				 * The length, for a blob with a core: to the
				 * nearest glyph start after ours, or the end
				 * of the range's data.  Identical glyphs share
				 * a string, so the table isn't in order and
				 * the next entry isn't necessarily ours
				 */
				if (plen && core) {
					uint32_t k, oo = cbo - db;

					next = core->gend[n];
					for (k = 0; k < ce; k++) {
						uint32_t o1 = mcuf_glyph_ofs(
							core, bf, r, n, k);

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
	const uint8_t *bf, *comp;
	lws_mcuf_core_t *core;
	uint32_t ofs, len = 0;
	size_t n, blen;
	mcu_glyph_t *g;
	void *pin;

	bf = mcuf_src(text, unicode, &blen, &core);
	if (!bf)
		return NULL;

	ofs = font_mcufont_uniglyph_lookup(core, bf, blen, unicode, &len);
	if (!ofs)
		return NULL;

	/* pinned from now until the glyphs are released */
	comp = mcuf_glyph(text, core, bf, ofs, len, 1, &pin);
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
	g->bf = bf;
	g->comp = comp;
	/* a cached string is len long, else it can't run past the font */
	g->comp_end = len ? comp + len : bf + blen;
	g->fg.cwidth.whole = *g->comp++;
	g->fg.cwidth.frac = 0;

	/* the runs start after the kerning profile, if it fits the string */
	n = mcuf_profile(bf, g->comp, g->comp_end, NULL);
	g->comp = n ? g->comp + n : g->comp_end;

	lws_dll2_add_tail(&g->fg.list, &text->glyphs);

	return g;
}

int
lws_display_font_mcufont_metrics(lws_dlo_text_t *text, uint32_t unicode,
				 lws_glyph_metrics_t *m)
{
	const uint8_t *bf, *comp, *end;
	lws_mcuf_core_t *core;
	uint32_t ofs, len = 0;
	size_t blen;

	bf = mcuf_src(text, unicode, &blen, &core);
	if (!bf)
		return 1;

	ofs = font_mcufont_uniglyph_lookup(core, bf, blen, unicode, &len);
	if (!ofs)
		return 1;

	/* the width and profile start the string: touched, not pinned */
	comp = mcuf_glyph(text, core, bf, ofs, len, 0, NULL);
	if (!comp)
		return 1;

	end = len ? comp + len : bf + blen;
	if (comp >= end || !mcuf_profile(bf, comp + 1, end, m))
		return 1;

	m->adv.whole = comp[0];
	m->adv.frac = 0;
	m->gap = bf[MCUFO_KERN_GAP];
	/* each page of a face from a server has its own */
	m->blx = (uint8_t)lws_ser_ru16be(bf + MCUFO16_BASELINE_X);
	m->valid = 1;

	return 0;
}

/*
 * How far to move glyph b left, towards glyph a before it, as zero or a
 * negative count of pixels.  Find the fewest clear columns between their
 * ink, each band of a against the bands of b alongside it and either side,
 * so they don't come to touch at the corners either; and close that up to
 * the font's target gap.  The columns are counted from the left of each
 * glyph's box, which is its baseline x left of its pen position.  Never apart, and by no more than a quarter of the
 * narrower advance, so text keeps its rhythm.  A glyph with no ink, like a
 * space, stops kerning across it.
 */

int
lws_display_font_mcufont_kern(const lws_glyph_metrics_t *a,
			      const lws_glyph_metrics_t *b)
{
	int n, m, g, t, gap = 0x7fffffff, cap;

	if (!a->valid || !b->valid ||
	    a->first == MCUFO_NO_INK || b->first == MCUFO_NO_INK)
		return 0;

	for (n = a->first; n <= a->last; n++)
		for (m = n - 1 < b->first ? b->first : n - 1;
		     m <= (n + 1 > b->last ? b->last : n + 1); m++) {
			g = a->adv.whole + (b->l[m] - b->blx) -
			    (a->r[n] - a->blx) - 1;
			if (g < gap)
				gap = g;
		}

	/* whatever the font says, kerning never brings ink together */
	t = a->gap ? a->gap : 1;
	if (gap == 0x7fffffff || gap <= t)
		return 0;

	g = gap - t;
	cap = (a->adv.whole < b->adv.whole ? a->adv.whole : b->adv.whole) / 4;

	return -(g < cap ? g : cap);
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
mcufont_row(lws_dlo_text_t *text, int yo, char draw)
{
	mcu_glyph_t *g;
	uint8_t c, el;
	int w, n;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&text->glyphs)) {
		lws_font_glyph_t *fg = lws_container_of(d, lws_font_glyph_t, list);

		g = (mcu_glyph_t *)fg;
		fg->x = 0;
		/* this is tested for every px of the row, it's worth keeping */
		w = lws_ser_ru16be(g->bf + MCUFO16_WIDTH);

		while (yo < (int)fg->height.whole && fg->x < w) {
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

					write_ref_codeword(g, g->bf, c);
					break;
				}
				break;
			case RS_SKIP_PX:
			case RS_ALLZERO:
				/*
				 * Nothing is drawn for these: go to the end of
				 * the run in one, or the end of the row if the
				 * run goes on into the next one
				 */
				n = 1;
				if (g->runlen > 1) {
					n = w - fg->x;
					if (n > g->runlen)
						n = (int)g->runlen;
				}
				fg->x = (int8_t)(fg->x + n);
				g->runlen -= n;
				if (g->runlen)
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
			}
		}

	} lws_end_foreach_dll(d);

}

static lws_stateful_ret_t
mcufont_render(struct lws_display_render_state *rs, lws_dlo_text_t *text,
	       uint16_t gen);

#if defined(LWS_DLO_REMOTE_FONTS)
/*
 * How many times a render comes back for pages of a face from a server that
 * it can't have yet, and how long it gives them each time: enough to see out
 * a page's holdoff after there wasn't the memory to fetch it.  Counted for
 * the whole render, not per text, so a server that is gone costs the render
 * this once, not once per text
 */
#define LWS_DLO_FONT_RENDER_RETRIES	12
#define LWS_DLO_FONT_RENDER_RETRY_US	(250 * LWS_US_PER_MS)

/*
 * The pages of the face from a server the text was laid out in can't be had
 * now, and the caller can't lay the page out again in the faces we have
 * here, so it is drawn in the nearest one of them.  Layout placed and
 * sized it for the other face, and others may be placed after it on its
 * line, so it is set again in the face we have, in the same box: as much of
 * it as fits there.  Nonzero if there's nothing it can be drawn in
 */

static int
mcufont_render_local(lws_dlo_text_t *text, lws_mcufont_remote_t *r)
{
	const lws_display_font_t *f = lws_font_choose_local(r->cx,
							&text->font->choice);

	lwsl_cx_notice(r->cx, "%s: pages unavailable, '%.*s' in a local face",
		       r->path, (int)(text->text_len > 16 ? 16 :
				      text->text_len),
		       text->text ? text->text : "");

	if (!f) {
		/* nothing to draw it in: it isn't drawn */
		text->text_len = 0;

		return 1;
	}

	text->font = f;

	return !!lws_display_dlo_text_refit(text);
}
#endif

lws_stateful_ret_t
lws_display_font_mcufont_render(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);
	lws_mcufont_remote_t *r = mcuf_remote(text->font);
	lws_stateful_ret_t ret;
	const uint8_t *bf;

	if (!text->text_len)
		/* nothing of it is drawn */
		return LWS_SRET_OK;

#if defined(LWS_DLO_REMOTE_FONTS)
	if (r) {
		/*
		 * Pages of a face from a server may have been evicted since
		 * layout, or since we last drew a line of it.  If they are
		 * being fetched again, wait for them at this dlo.  If they
		 * can't be had just now, eg, there wasn't the memory to fetch
		 * them into, come back for them a few times.  If they still
		 * can't be had, the page is laid out again in the faces we
		 * have here, or if the caller can't do that, the text is
		 * drawn in one of them
		 */
		switch (lws_font_text_resident(text->font, text->text,
					       text->text_len,
					       rs->font_wait.cb ?
							&rs->font_wait : NULL)) {
		case LWS_FONT_PENDING:
			return LWS_SRET_WANT_INPUT;
		case LWS_FONT_UNAVAILABLE:
			if (rs->font_wait.cb &&
			    rs->font_retries < LWS_DLO_FONT_RENDER_RETRIES) {
				rs->font_retries++;
				lws_sul_schedule(r->cx, 0, rs->font_wait.sul,
						 rs->font_wait.cb,
						 LWS_DLO_FONT_RENDER_RETRY_US);
				return LWS_SRET_WANT_INPUT;
			}
			if (rs->relayout_ok) {
				/*
				 * The caller can lay the page out again in
				 * the faces we have here, as if they had been
				 * chosen from the start: drawing it in one of
				 * them in the place laid out for this one
				 * can't look right
				 */
				lwsl_cx_notice(r->cx, "%s: pages unavailable "
					       "for '%.*s', relayout",
					       r->path, (int)(text->text_len >
						       16 ? 16 : text->text_len),
					       text->text ? text->text : "");
				rs->relayout = 1;

				return LWS_SRET_FATAL;
			}
			if (mcufont_render_local(text, r))
				return LWS_SRET_OK;
			r = NULL;
			break;
		default:
			break;
		}
	}
#endif

	bf = mcuf_bf(text);
	if (!bf)
		/* can't be made resident right now: try again next line */
		return LWS_SRET_OK;

	/* the decoders point into it: it must stay for this call */
	lws_font_pin(text->font);
	ret = mcufont_render(rs, text, r ? r->gen : 0);
	lws_font_unpin(text->font);

	return ret;
}

static lws_stateful_ret_t
mcufont_render(struct lws_display_render_state *rs, lws_dlo_text_t *text,
	       uint16_t gen)
{
	lws_dlo_t *dlo = &text->dlo;
	lws_fx_t ax, ay, t, t1, t2, t3;
	int s, e, yo;

	lws_fx_add(&ax, &rs->st[rs->sp].co.x, &dlo->box.x);
	lws_fx_add(&t, &ax, &dlo->box.w);
	lws_fx_add(&ay, &rs->st[rs->sp].co.y, &dlo->box.y);
	lws_fx_add(&t1, &ay, &dlo->box.h);

	lws_fx_add(&t2, &ax, &text->bounding_box.w);

	text->curr = rs->curr;
	text->rs = rs;

	s = ax.whole;
	e = lws_fx_roundup(&t2);

	if (e <= 0)
		return LWS_SRET_OK; /* wholly off to the left */
	if (s >= rs->ic->wh_px[0].whole)
		return LWS_SRET_OK; /* wholly off to the right */

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

	/*
	 * A page of a face from a server that was evicted and fetched again
	 * since the glyphs were attached is a new copy: the decoders may point
	 * into the old one, so they have to start again from the new one in
	 * the same way
	 */

	if (!text->glyphs.count || yo < (int)text->glyph_row ||
	    gen != text->font_gen) {
		lws_display_dlo_text_detach_glyphs(text);
		text->font_gen = gen;

		lws_display_dlo_text_attach_glyphs(text);

		/*
		 * A retained display list keeps the text after it's drawn: the
		 * display list lets the glyphs go when it's next scanned from
		 * the top, so they are only held for what is on the display
		 */
		if (text->glyphs.count)
			lws_dll2_add_tail(&text->glyphed,
					  &rs->displaylist.glyphed);

		t3.frac = 0;
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&text->glyphs)) {
			lws_font_glyph_t *fg = lws_container_of(d, lws_font_glyph_t, list);

			/* each page of a face from a server has its own */
			t3.whole = lws_ser_ru16be(((mcu_glyph_t *)fg)->bf +
						  MCUFO16_BASELINE_X);
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
		mcufont_row(text, text->glyph_row, 0);
		text->glyph_row++;
	}

	mcufont_row(text, yo, 1);
	text->glyph_row++;

	return LWS_SRET_OK;
}
