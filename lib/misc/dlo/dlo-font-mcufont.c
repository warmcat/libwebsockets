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

	mcu_stack_t		st[3];
	int32_t			runlen;

	int8_t			sp;

	uint8_t			runstate;
	uint8_t			alpha;
	uint8_t			code;
} mcu_glyph_t;

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
	lws_display_colour_t c = (lws_display_colour_t)((lws_display_colour_t)(g->alpha << 24) |
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

static void
write_ref_codeword(mcu_glyph_t *g, const uint8_t *bf, uint8_t c)
{
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
		o1 = lws_ser_ru32be(bf + MCUFO_FOFS_DICT_OFS);
		o = lws_ser_ru16be(bf + o1 + ((c - DICT_START) * 2));
		g->st[(int)++g->sp].dictlen = (int16_t)(lws_ser_ru16be(bf + o1 +
						((c - DICT_START + 1) * 2)) - o);

		g->st[(int)g->sp].dict = bf + lws_ser_ru32be(bf + MCUFO_FOFS_DICT_DATA) + o;
		g->st[(int)g->sp].state = DICT2;
		return;
	}

	g->st[(int)++g->sp].bitcount = fillentry_bitcount(c);
	g->st[(int)g->sp].byte = (uint8_t)(c - DICT_START7BIT);
	g->st[(int)g->sp].state = DICT1;
	g->runlen = 0;
}

static void
mcufont_next_code(mcu_glyph_t *g)
{
	lws_dlo_text_t *t = lws_container_of(g->fg.list.owner, lws_dlo_text_t,
					     glyphs);
	const uint8_t *bf = (const uint8_t *)t->font->data;
	uint8_t c = *g->comp++;
	uint32_t o, o1;

	if (c < DICT_START + lws_ser_ru32be(&bf[MCUFO_COUNT_RLE_DICT]) ||
	    c >= DICT_START + lws_ser_ru32be(&bf[MCUFO_COUNT_REF_RLE_DICT])) {
		write_ref_codeword(g, bf, c);
		return;
	}

	/* write_ref_dictentry() */

	o1 = lws_ser_ru32be(bf + MCUFO_FOFS_DICT_OFS);
	o = lws_ser_ru16be(bf + o1 + ((c - DICT_START) * 2));
	g->st[(int)++g->sp].dictlen = (int16_t)(lws_ser_ru16be(bf + o1 +
					((c - DICT_START + 1) * 2)) - o);

	g->st[(int)g->sp].dict = bf + lws_ser_ru32be(bf + MCUFO_FOFS_DICT_DATA) + o;
	g->st[(int)g->sp].state = DICT3;
}

/* lookup and append a glyph for specific unicode to the text glyph list */

static uint32_t
font_mcufont_uniglyph_lookup(lws_dlo_text_t *text, uint32_t unicode)
{
	const uint8_t *bf = (const uint8_t *)text->font->data,
		       *r = bf + lws_ser_ru32be(&bf[MCUFO_FOFS_CHAR_RANGE_TABLES]);
	uint32_t entries = lws_ser_ru32be(&bf[MCUFO_COUNT_CHAR_RANGE_TABLES]);
	unsigned int n;

	if (entries > 8) /* coverity sanity */
		return 0;

	do {
		for (n = 0; n < entries; n++) {
			uint32_t cs = lws_ser_ru32be(r + 0), ce = lws_ser_ru32be(r + 4);

			if (cs >= 0x100000 || !ce || ce > 0x10000)
				return 0;

			if (unicode >= cs && unicode < cs + ce) {
				uint32_t cbo = lws_ser_ru32be(r + 0xc);

				if (cbo >= text->font->data_len)
					return 0;

				cbo += lws_ser_ru16be(bf +
						lws_ser_ru32be(r + 8) + ((unicode - cs) * 2));

                                 if (cbo >= text->font->data_len)
                                        return 0;

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
	const uint8_t *bf = (const uint8_t *)text->font->data;
	uint32_t ofs;
	mcu_glyph_t *g;

	ofs = font_mcufont_uniglyph_lookup(text, unicode);
	if (!ofs)
		return NULL;

//	lwsl_warn("%s: text->text_len %u: %c\n", __func__, text->text_len, (char)unicode);
	g = lwsac_use_zero(&text->ac_glyphs, sizeof(*g),
					     (text->text_len + 1) * sizeof(*g));
	if (!g)
		return NULL;

	g->comp = bf + ofs;
	g->fg.cwidth.whole = *g->comp++;
	g->fg.cwidth.frac = 0;

	lws_dll2_add_tail(&g->fg.list, &text->glyphs);

	return g;
}

int
lws_display_font_mcufont_getcwidth(lws_dlo_text_t *text, uint32_t unicode,
				   lws_fx_t *fx)
{
	const uint8_t *bf = (const uint8_t *)text->font->data;
	uint32_t ofs = font_mcufont_uniglyph_lookup(text, unicode);

	if (!ofs)
		return 1;

	fx->whole = bf[ofs];
	fx->frac = 0;

	return 0;
}

lws_font_glyph_t *
lws_display_font_mcufont_image_glyph(lws_dlo_text_t *text, uint32_t unicode,
				     char attach)
{
	const uint8_t *bf = (const uint8_t *)text->font->data;
	mcu_glyph_t *g;

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

lws_stateful_ret_t
lws_display_font_mcufont_render(struct lws_display_render_state *rs)
{
	lws_dlo_t *dlo = rs->st[rs->sp].dlo;
	lws_dlo_text_t *text = lws_container_of(dlo, lws_dlo_text_t, dlo);
	const uint8_t *bf = (const uint8_t *)text->font->data;
	lws_fx_t ax, ay, t, t1, t2, t3;
	mcu_glyph_t *g;
	int s, e, yo;
	uint8_t c, el;

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

	if (!yo) {
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
					--g->sp; /* back to DICT1 after doing the skip */
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
								g->alpha = 255;
								g->runstate = RS_WRITE_PX;
								g->runlen = g->st[(int)g->sp].runlen;
								g->st[(int)g->sp].runlen = 0;
								g->st[(int)++g->sp].state = DICT1_CONT;
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
					if (!g->sp)
						assert(0);
					g->sp--;

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
					if (!--g->st[(int)g->sp].dictlen) {
						if (!g->sp)
							assert(0);
						g->sp--;
					}
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
					if (!--g->st[(int)g->sp].dictlen) {
						if (!g->sp)
							assert(0);

						g->sp--;
					}

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
				if (g->alpha)
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

	return LWS_SRET_OK;
}
