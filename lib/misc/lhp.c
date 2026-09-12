/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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
 * Stream parser for HTML 5
 * https://w3c.github.io/html-reference/syntax.html
 *
 */

#include <private-lib-core.h>

#define FAIL_CHAR 0x08
static uint8_t css_lextable[] = { /* the css property names */
	#include "css-lextable.h"
};

static uint8_t css_propconst_lextable[] = { /* the css property values */
	#include "css-propconst-lextable.h"
};

#define LHP_AC_GRANULE 512

/*
 * Largest whole part we will accumulate for a css number; any real length is
 * orders of magnitude smaller, and this keeps the int32_t lws_fx_t whole part
 * away from overflow no matter how many digits the document offers
 */
#define LHP_CSS_MAX_WHOLE 1000000

/*
 * Most attributes we will store for one element... the element stack is capped
 * by LHP_MAX_ELEMS_NEST, but without this an element with a huge number of
 * attributes can allocate without limit until its '>' arrives
 */
#define LHP_MAX_ATR_PER_ELEM 64

enum {
	/* html */

	LHPS_INIT, /* default css injection */

	LHPS_OUTER,
	LHPS_TAG,
	LHPS_BAD_TAG,
	LHPS_DO_START_ELEM,
	LHPS_ATTRIB,
	LHPS_ATTRIB_VAL,
	LHPS_AMP,
	LHPS_AMPHASH,
	LHPS_AMPHASH_HEX,
	LHPS_SCOMMENT1,
	LHPS_SCOMMENT2,
	LHPS_COMMENT,
	LHPS_ECOMMENT1,
	LHPS_ECOMMENT2,

	/* css */

	LCSPS_CSS_OUTER,
	LCSPS_CCOM_S1,
	LCSPS_CCOM_E1,
	LCSPS_CCOM,
	LCSPS_CSS_OUTER_TAG1,
	LCSPS_CSS_NAMES,
	LCSPS_CSS_DEF_NAME,
	LCSPS_CSS_DEF_VALUE,
	LCSPS_SCOMMENT1,
	LCSPS_SCOMMENT2,
	LCSPS_COMMENT,
	LCSPS_ECOMMENT1,
	LCSPS_ECOMMENT2,

	LCSPS_CSS_STANZA,
	LCSPS_CSS_SKIP_BLOCK,	/* @-rule block we can't use */

	/* script */

	LHPS_SCRIPT,
	LHPS_SCRIPT_TAG1,
	LHPS_SCRIPT_TAG2,
};

/*
 * 17 well-known colours specified by CSS 2.1
 * https://www.w3.org/TR/CSS21/syndata.html#value-def-color
 */

#if 0
static struct cols {
	const char * const	name;
	uint32_t		rgba;
} cols[] = {
	{ "maroon", 	LWSDC_RGBA(0x80, 0x00, 0x00, 255) },
	{ "red", 	LWSDC_RGBA(0xff, 0x00, 0x00, 255) },
	{ "orange", 	LWSDC_RGBA(0xff, 0xa5, 0x00, 255) },
	{ "yellow", 	LWSDC_RGBA(0xff, 0xff, 0x00, 255) },
	{ "olive", 	LWSDC_RGBA(0x80, 0x80, 0x00, 255) },
	{ "purple", 	LWSDC_RGBA(0x80, 0x00, 0x80, 255) },
	{ "fuchsia", 	LWSDC_RGBA(0xff, 0x00, 0xff, 255) },
	{ "white", 	LWSDC_RGBA(0xff, 0xff, 0xff, 255) },
	{ "lime", 	LWSDC_RGBA(0x00, 0xff, 0x00, 255) },
	{ "green", 	LWSDC_RGBA(0x00, 0x80, 0x00, 255) },
	{ "navy", 	LWSDC_RGBA(0x00, 0x00, 0x80, 255) },
	{ "blue", 	LWSDC_RGBA(0x00, 0x00, 0xff, 255) },
	{ "aqua", 	LWSDC_RGBA(0x00, 0xff, 0xff, 255) },
	{ "teal", 	LWSDC_RGBA(0x00, 0x80, 0x80, 255) },
	{ "black", 	LWSDC_RGBA(0x00, 0x00, 0x00, 255) },
	{ "silver", 	LWSDC_RGBA(0xc0, 0xc0, 0xc0, 255) },
	{ "gray", 	LWSDC_RGBA(0x80, 0x80, 0x80, 255) },
};
#endif

/*
 * "void elements" are html elements that don't have a scope, and so don't
 * have a scope closure
 */
static const char * const void_elems[] = {
	"area", "base", "br", "col", "command", "embed", "hr", "img",
	"input", "keygen", "link", "meta", "param", "source", "track", "wbr",
	"!doctype"
};
static const uint8_t void_elems_lens[] = /* lengths for the table above */
	{ 4, 4, 2, 3, 7, 5, 2, 3, 5, 6, 4, 4, 5, 6, 5, 3, 8 };

static const struct {
	const char *name;
	uint32_t val;
} entities[] = {
	{ "quot", 34 },
	{ "amp", 38 },
	{ "apos", 39 },
	{ "lt", 60 },
	{ "gt", 62 },
	{ "nbsp", 160 },
	{ "copy", 169 },
	{ "reg", 174 },
	{ "deg", 176 },
	{ "plusmn", 177 },
	{ "sup2", 178 },
	{ "sup3", 179 },
	{ "micro", 181 },
	{ "para", 182 },
	{ "middot", 183 },
	{ "cedil", 184 },
	{ "sup1", 185 },
	{ "ordm", 186 },
	{ "raquo", 187 },
	{ "frac14", 188 },
	{ "frac12", 189 },
	{ "frac34", 190 },
	{ "iquest", 191 },
	{ "times", 215 },
	{ "divide", 247 },
	{ "mdash", 8212 },
	{ "ndash", 8211 },
	{ "bull", 8226 },
	{ "hellip", 8230 },
	{ "prime", 8242 },
	{ "Prime", 8243 },
	{ "oline", 8254 },
	{ "frasl", 8260 },
	{ "weierp", 8472 },
	{ "image", 8465 },
	{ "real", 8476 },
	{ "trade", 8482 },
	{ "alefsym", 8501 },
	{ "larr", 8592 },
	{ "uarr", 8593 },
	{ "rarr", 8594 },
	{ "darr", 8595 },
	{ "harr", 8596 },
	{ "crarr", 8629 },
	{ "lArr", 8656 },
	{ "uArr", 8657 },
	{ "rArr", 8658 },
	{ "dArr", 8659 },
	{ "hArr", 8660 },
	{ "forall", 8704 },
	{ "part", 8706 },
	{ "exist", 8707 },
	{ "empty", 8709 },
	{ "nabla", 8711 },
	{ "isin", 8712 },
	{ "notin", 8713 },
	{ "ni", 8715 },
	{ "prod", 8719 },
	{ "sum", 8721 },
	{ "minus", 8722 },
	{ "lowast", 8727 },
	{ "radic", 8730 },
	{ "prop", 8733 },
	{ "infin", 8734 },
	{ "ang", 8736 },
	{ "and", 8743 },
	{ "or", 8744 },
	{ "cap", 8745 },
	{ "cup", 8746 },
	{ "int", 8747 },
	{ "there4", 8756 },
	{ "sim", 8764 },
	{ "cong", 8773 },
	{ "asymp", 8776 },
	{ "ne", 8800 },
	{ "equiv", 8801 },
	{ "le", 8804 },
	{ "ge", 8805 },
	{ "sub", 8834 },
	{ "sup", 8835 },
	{ "nsub", 8836 },
	{ "sube", 8838 },
	{ "supe", 8839 },
	{ "oplus", 8853 },
	{ "otimes", 8855 },
	{ "perp", 8869 },
	{ "sdot", 8901 },
	{ "lceil", 8968 },
	{ "rceil", 8969 },
	{ "lfloor", 8970 },
	{ "rfloor", 8971 },
	{ "lang", 9001 },
	{ "rang", 9002 },
	{ "loz", 9674 },
	{ "spades", 9824 },
	{ "clubs", 9827 },
	{ "hearts", 9829 },
	{ "diams", 9830 },
	{ "dash", 8212 },
};

static const char *const default_css =
	"/* lws_lhp default css */"
	"html, address,blockquote, dd, div,dl, dt, fieldset, form, frame, "
	"frameset, h1, h2, h3, h4, h5, h6, noframes, ol, p, ul, center, "
	"dir, hr, menu, pre { top: 0px; right: 0px; bottom: 0px; left: 0px;"
		" unicode-bidi: embed; color: #000;"
		"padding-top: 2px; padding-left: 2px; padding-bottom: 2px; padding-right: 2px;"
		"margin-top: 2px; margin-left: 2px; margin-bottom: 2px; margin-right: 2px;"
		"position: static; width: auto; height: auto;"
			    "}\n"
	"div             { display: block; width: auto; }\n"
	"body		 { display: block}\n"
	"html, address, blockquote, dd, dl, dt, fieldset, form, h1, h2, h3, h4, "
	"h5, h6, ol, p, ul, center, dir, hr, menu, pre, header, footer, main, "
	"section, article, nav, aside, figure, figcaption, details, summary, "
	"legend, optgroup, option { display: block }\n"
	"li              { display: list-item }\n"
	"head, script, style { display: none }\n"
	"table           { display: table;  }\n"
	"tr              { display: table-row }\n"
	"thead           { display: table-header-group }\n"
	"tbody           { display: table-row-group }\n"
	"tfoot           { display: table-footer-group }\n"
	"col             { display: table-column }\n"
	"colgroup        { display: table-column-group }\n"
	"td, th          { display: table-cell }\n"
	"caption         { display: table-caption }\n"
	"th              { font-weight: bolder; text-align: center }\n"
	"caption         { text-align: center }\n"
	"body            { margin: 8px }\n"
	"h1              { font-size: 2em; margin: .67em 0 }\n"
	"h2              { font-size: 1.5em; margin: .75em 0 }\n"
	"h3              { font-size: 1.17em; margin: .83em 0 }\n"
	"h4, p, blockquote, ul, fieldset, form, ol, dl, dir, menu "
		"{ margin: 1.12em 0 }\n"
	"h5              { font-size: .83em; margin: 1.5em 0 }\n"
	"h6              { font-size: .75em; margin: 1.67em 0 }\n"
	"h1, h2, h3, h4, h5, h6, b, strong          { font-weight: bolder }\n"
	"blockquote      { margin-left: 40px; margin-right: 40px }\n"
	"i, cite, em, var, address    { font-style: italic }\n"
	" pre, tt, code, kbd, samp       { font-family: monospace }\n"
	"pre             { white-space: pre }\n"
	"button, textarea, input, select   { display: inline-block }\n"
	"big             { font-size: 1.17em }\n"
	"small, sub, sup { font-size: .83em }\n"
	"sub             { vertical-align: sub }\n"
	"sup             { vertical-align: super }\n"
	"table           { border-spacing: 2px; padding-top: 2px; padding-left: 2px; padding-bottom: 2px; padding-right: 2px; margin-top: 2px; margin-bottom: 2px; margin-left: 2px; margin-right: 2px }\n"
	"thead, tbody, tfoot           { vertical-align: middle }\n"
	"td, th, tr      { vertical-align: inherit; width: auto; padding-top: 2px; padding-left: 2px; padding-bottom: 2px; padding-right: 2px; margin-top: 2px; margin-bottom: 2px; margin-left: 2px; margin-right: 2px }\n"
	"s, strike, del  { text-decoration: line-through }\n"
	"hr              { border: 1px inset }\n"
	"ol, ul, dir, menu, dd        { margin-left: 40px }\n"
	"ol              { list-style-type: decimal }\n"
	"ol ul, ul ol, ul ul, ol ol    { margin-top: 0; margin-bottom: 0 }\n"
	"u, ins          { text-decoration: underline }\n"
	"br:before       { content: \"A\"; white-space: pre-line }\n"
	"center          { text-align: center }\n"
	"nav             { text-align: left }\n"
	"span, time, label, a, b, strong, i, em, code { display: inline }\n"
	":link, :visited { text-decoration: underline }\n"
	":focus          { outline: thin dotted invert }\n"

	"BDO[DIR=\"ltr\"]  { direction: ltr; unicode-bidi: bidi-override }"
	"BDO[DIR=\"rtl\"]  { direction: rtl; unicode-bidi: bidi-override }"

	"*[DIR=\"ltr\"]    { direction: ltr; unicode-bidi: embed }"
	"*[DIR=\"rtl\"]    { direction: rtl; unicode-bidi: embed }"

	"@media print {"
	"  h1            { page-break-before: always }\n"
	"  h1, h2, h3, h4, h5, h6    { page-break-after: avoid }\n"
	"  ul, ol, dl    { page-break-before: avoid }\n"
	"}\n"
;



static int
lhp_clean_atr(lws_dll2_t *d, void *user)
{
	lhp_atr_t *atr = lws_container_of(d, lhp_atr_t, list);

	lws_dll2_remove(d);
	lws_free(atr);

	return 0;
}

static void
lhp_clean_level(lhp_pstack_t *ps)
{
	lws_dll2_foreach_safe(&ps->atr, NULL, lhp_clean_atr);
	lws_dll2_remove(&ps->list);

	if (ps->matched)
		lws_free(ps->matched);
	lwsac_free(&ps->styleac);

	lws_free(ps);
}

int
lws_lhp_construct(lhp_ctx_t *ctx, lhp_callback cb, void *user,
		  const lws_surface_info_t *ic)
{
	lhp_pstack_t *ps = lws_zalloc(sizeof(*ps), __func__);

	if (!ps)
		return 1;

	memset(ctx, 0, sizeof(*ctx) - sizeof(ctx->buf));
	ctx->user		= user;
	ctx->ic			= *ic;

	/*
	 * these are done implicitly by the memset above
	 * ctx->state			= LHPS_INIT;
	 * ctx->sp			= 0;
	 */

	ps->cb			= cb;
	/* the document level: nothing to match, default font size */
	ps->css_resolved	= 1;
	lws_fx_set(ps->font_size, 16, 0);
	lws_dll2_add_tail(&ps->list, &ctx->stack);

	return 0;
}

static int
lhp_clean_stack(lws_dll2_t *d, void *user)
{
	lhp_pstack_t *ps = lws_container_of(d, lhp_pstack_t, list);

	lhp_clean_level(ps);
	return 0;
}

static const lws_fx_t c_254= { 2,54000000 }, c_10 = { 10,0 }, c_0 = { 0, 0 },
			     c_72 = { 72,0 }, c_6 = { 6,0 }, c_100 = { 100,0 },
			     lws_fx_2 = { 2, 0 }, lws_fx_3 = { 3, 0 },
			     lws_fx_4 = { 4, 0 }, lws_fx_96 = { 96, 0 },
			     lws_fx_254 = { 25, 40000000 },
			     lws_fx_83 = { 83, 0 }, lws_fx_120 = { 120, 0 };

/*
 * We need to go backward until we reach an absolute length for the reference
 * axis, then base off that and go forward applying relative operations (like %)
 * on it in order.
 */

static int
lws_css_compute_cascaded_length(lhp_ctx_t *ctx, int ref, lhp_pstack_t *ps,
				lws_fx_t *t1)
{
	lhp_pstack_t *psb = ps, *psmap[20];
	const struct lcsp_atr *atrmap[20];
	lws_fx_t t2;
	int amp = 0;

	do {
		const struct lcsp_atr *a;

		psb = lws_css_get_parent_block(ctx, psb);
		if (!psb)
			break;

		a = (ref == LWS_LHPREF_WIDTH) ? psb->css_width : psb->css_height;
		if (!a)
			/* skip levels that don't change it */
			continue;

		if (amp + 1 == LWS_ARRAY_SIZE(atrmap))
			/* uhh... */
			break;

		psmap[amp] = psb;
		atrmap[amp++] = a;

		if (a->unit == LCSP_UNIT_LENGTH_PERCENT ||
		    a->unit == LCSP_UNIT_ANGLE_REL_DEG ||
		    a->unit == LCSP_UNIT_NONE)
			/* need earlier info to compute... keep going back */
			continue;

		break;
	} while (1);

	/*
	 * We have the path back through the elements to the first
	 * absolute one
	 */

	while (amp-- > 0) {
		if (atrmap[amp]->unit != LCSP_UNIT_LENGTH_PERCENT) {
			*t1 = *lws_csp_px(atrmap[amp], psmap[amp]);
		} else
			if (amp)
				lws_fx_div(t1,
					lws_fx_mul(&t2, &atrmap[amp]->u.i, t1),
									&c_100);
	}

	return 0;
}

static void
lhp_fx_parse(lws_fx_t *fx, const char *str, size_t len)
{
	const char *dot = NULL;
	int i;

	for (i = 0; i < (int)len; i++)
		if (str[i] == '.') {
			dot = &str[i];
			break;
		}

	if (!dot) {
		fx->whole = atoi(str);
		fx->frac = 0;
		return;
	}

	fx->whole = atoi(str);
	fx->frac = 0;

	dot++;
	len -= (size_t)(dot - str);
	i = 10000000;
	while (len-- && *dot) {
		fx->frac += ((*dot++) - '0') * i;
		i /= 10;
	}
}

const lws_fx_t *
lws_csp_px(const lcsp_atr_t *a, lhp_pstack_t *ps)
{
	lhp_ctx_t *ctx;
	const lws_display_font_t *f;
	lws_fx_t t1, t2, t3, em, ex;
	int ref;

	assert(ps);

	if (!a)
		/*
		 * An absent attribute is normal (eg, no margins set); all
		 * callers expect a dereferenceable result, so treat it as 0
		 */

		return &c_0;

	ctx = lws_dll2_owner_container(&ps->list, lhp_ctx_t, stack);
	f = ps->font;

	/*
	 * em is the element's computed font size; the font actually chosen
	 * may be a different size if no exact match was registered
	 */

	if (ps->font_size.whole || ps->font_size.frac) {
		em = ps->font_size;
		lws_fx_div(&ex, &em, &lws_fx_2);
	} else if (f) {
		em = f->em;
		ex = f->ex;
	} else {
		*(lws_fx_t *)&a->r = c_0;
		return &a->r;
	}

	ref = lhp_prop_axis(a);

	switch (a->unit) {
	case LCSP_UNIT_LENGTH_REM:
	{
		/* relative to the root element's font size */
		lws_dll2_t *d = lws_dll2_get_head(&ctx->stack);
		lhp_pstack_t *root;

		if (!d)
			break;
		if (lws_dll2_get_next(d))
			d = lws_dll2_get_next(d);
		root = lws_container_of(d, lhp_pstack_t, list);
		if (!root->font_size.whole && !root->font_size.frac)
			break;
		return lws_fx_mul((lws_fx_t *)&a->r, &a->u.i, &root->font_size);
	}

	case LCSP_UNIT_CALC:
		{
			char buf[128], unit[8];
			const char *p = (const char *)&a[1];
			size_t len = a->value_len;
			lws_fx_t sum = { 0, 0 }, v;
			lcsp_atr_t atr;
			int op = 1;

			memset(&atr, 0, sizeof(atr));

			/* simplistic calc parser: A + B + C... */

			while (len) {
				size_t n = 0, m = 0;

				while (len && (*p == ' ' || *p == '\t' || *p == '\n')) {
					p++;
					len--;
				}

				if (len && (*p == '+' || *p == '-')) {
					op = *p++ == '+';
					len--;
					continue;
				}

				while (len && n < sizeof(buf) - 1 &&
				       ((*p >= '0' && *p <= '9') || *p == '.')) {
					buf[n++] = *p++;
					len--;
				}
				buf[n] = '\0';

				if (!n)
					break;

				lws_fx_set(atr.u.i, 0, 0);
				lhp_fx_parse(&atr.u.i, buf, n);

				while (len && m < sizeof(unit) - 1 &&
				       (*p >= 'a' && *p <= 'z')) {
					unit[m++] = *p++;
					len--;
				}
				unit[m] = '\0';

				if (len && *p == '%') {
					unit[0] = '%';
					unit[1] = '\0';
					p++;
					len--;
				}

				atr.unit = LCSP_UNIT_LENGTH_PX;
				if (!strcmp(unit, "em")) atr.unit = LCSP_UNIT_LENGTH_EM;
				if (!strcmp(unit, "ex")) atr.unit = LCSP_UNIT_LENGTH_EX;
				if (!strcmp(unit, "rem")) atr.unit = LCSP_UNIT_LENGTH_REM;
				if (!strcmp(unit, "in")) atr.unit = LCSP_UNIT_LENGTH_IN;
				if (!strcmp(unit, "cm")) atr.unit = LCSP_UNIT_LENGTH_CM;
				if (!strcmp(unit, "mm")) atr.unit = LCSP_UNIT_LENGTH_MM;
				if (!strcmp(unit, "pt")) atr.unit = LCSP_UNIT_LENGTH_PT;
				if (!strcmp(unit, "pc")) atr.unit = LCSP_UNIT_LENGTH_PC;
				if (!strcmp(unit, "%")) atr.unit = LCSP_UNIT_LENGTH_PERCENT;

				v = *lws_csp_px(&atr, ps);

				if (op)
					lws_fx_add(&sum, &sum, &v);
				else
					lws_fx_sub(&sum, &sum, &v);
			}

			*(lws_fx_t *)&a->r = sum;
			return &a->r;
		}

	case LCSP_UNIT_LENGTH_EM:
		return lws_fx_mul((lws_fx_t *)&a->r, &a->u.i, &em);

	case LCSP_UNIT_LENGTH_EX:
		return lws_fx_mul((lws_fx_t *)&a->r, &a->u.i, &ex);

	case LCSP_UNIT_LENGTH_IN:	/* (inches * 2.54 * hwmm) / hwpx */
		if (ref == LWS_LHPREF_NONE)
			break;
		return lws_fx_div((lws_fx_t *)&a->r, lws_fx_mul(&t2,
			lws_fx_mul(&t3, &a->u.i, &c_254),
				&ctx->ic.wh_mm[ref]), &ctx->ic.wh_px[ref]);

	case LCSP_UNIT_LENGTH_CM:	/* (cm * 10 * hwmm) / hwpx */
		if (ref == LWS_LHPREF_NONE)
			break;
		return lws_fx_div((lws_fx_t *)&a->r,
				lws_fx_mul(&t2,
					lws_fx_mul(&t3, &a->u.i, &c_10),
					&ctx->ic.wh_mm[ref]), &ctx->ic.wh_px[ref]);
	case LCSP_UNIT_LENGTH_MM:	/* (mm * hwmm) / hwpx */
		if (ref == LWS_LHPREF_NONE)
			break;
		return lws_fx_div((lws_fx_t *)&a->r, lws_fx_mul(&t2,
				&a->u.i, &ctx->ic.wh_mm[ref]), &ctx->ic.wh_px[ref]);

	case LCSP_UNIT_LENGTH_PT:	/* ((pt * 2.54 * hwmm) / hwpx ) / 72 */
		if (ref == LWS_LHPREF_NONE)
			break;
		return lws_fx_div((lws_fx_t *)&a->r, lws_fx_div(&t1,
			 lws_fx_mul(&t2, lws_fx_mul(&t3,
					 &a->u.i, &c_254),
					 &ctx->ic.wh_mm[ref]),
					 &ctx->ic.wh_px[ref]), &c_72);

	case LCSP_UNIT_LENGTH_PC:	/* ((pc * 2.54 * hwmm) / hwpx ) / 6 */
		if (ref == LWS_LHPREF_NONE)
			break;
		return lws_fx_div((lws_fx_t *)&a->r, lws_fx_div(&t1,
				lws_fx_mul(&t2, lws_fx_mul(&t3,
					&a->u.i, &c_254), &ctx->ic.wh_mm[ref]),
						  &ctx->ic.wh_px[ref]), &c_6);
	case LCSP_UNIT_LENGTH_PX:	/* px */
		return &a->u.i;

	case LCSP_UNIT_LENGTH_PERCENT:	/* (percent * psb->w) / 100 */
		if (ref == LWS_LHPREF_NONE)
			break;

		t1.whole = 0;
		t1.frac = 0;

		lws_css_compute_cascaded_length(ctx, ref, ps, &t1);

		return lws_fx_div((lws_fx_t *)&a->r,
				lws_fx_mul(&t2, &a->u.i, &t1), &c_100);

	default:
		break;
	}

	return &a->u.i;
}

static lhp_atr_t *
lhp_atr_new(lhp_ctx_t *ctx, size_t name_len, size_t value_len)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack), lhp_pstack_t, list);
	lhp_atr_t *a;
	size_t n;

	/*
	 * Attributes are only freed when the element level is popped, ie, at
	 * the '>'... so an element with an unbounded number of attributes can
	 * allocate without bound before we ever get there
	 */

	if (lws_dll2_count(&ps->atr) >= LHP_MAX_ATR_PER_ELEM) {
		lwsl_err("%s: too many attributes\n", __func__);
		return NULL;
	}

	/* create the element name attribute */
	a = lws_malloc(sizeof(*a) + name_len + 1 + value_len + 1,
		       "html_elem_atr");

	if (!a)
		return NULL;

	if (!lws_dll2_count(&ps->atr)) {
		/* only check the tag string, not the attributes */
		ctx->u.f.void_element = 0;

		for (n = 0; n < LWS_ARRAY_SIZE(void_elems); n++)
			if (ctx->npos == void_elems_lens[n] &&
			    !strncasecmp(void_elems[n], ctx->buf, (size_t)ctx->npos))
				ctx->u.f.void_element = 1;
	}

	lws_dll2_clear(&a->list);
	a->name_len = name_len;
	a->value_len = value_len;
	ctx->buf[ctx->npos] = '\0';
	memcpy(&a[1], ctx->buf, (unsigned int)ctx->npos + 1u);
	*(((uint8_t *)&a[1]) + name_len) = '\0';
	*(((uint8_t *)&a[1]) + name_len + 1 + value_len) = '\0';
	lws_dll2_add_tail(&a->list, &ps->atr);

	ctx->npos = 0;

	return a;
}

static int
hspace(uint8_t c)
{
	return c == ' ' || c == 9 || c == 10 || c == 12 || c == 13;
}

void
lhp_uni_emit(lhp_ctx_t *ctx)
{
	/*
	 * We can emit up to 4 bytes, and we are called from places with
	 * different npos preconditions (entity names are collected into buf
	 * itself, so npos can be right at the end of buf when we are asked to
	 * replace them by their expansion).  Refuse to emit at all unless the
	 * worst case fits, leaving buf[LHP_STRING_CHUNK] free for the NUL that
	 * various consumers add at buf[npos].
	 */

	if (ctx->npos < 0 || ctx->npos > LHP_STRING_CHUNK - 4)
		return;

	/* emit */
	if (ctx->temp <= 0x7f) {
		ctx->buf[ctx->npos++] = (char)(ctx->temp & 0x7f);
		return;
	}
	if (ctx->temp <= 0x7ff) {
		ctx->buf[ctx->npos++] = (char)(0xc0 | ((uint8_t)(ctx->temp >> 6) & 0x1f));
		goto a;
	}
	if (ctx->temp <= 0xffff) {
		ctx->buf[ctx->npos++] = (char)(0xe0 | ((uint8_t)(ctx->temp >> 12) & 0xf));
		goto b;
	}
	if (ctx->temp <= 0x10ffff) {
		ctx->buf[ctx->npos++] = (char)(0xf0 | ((uint8_t)(ctx->temp >> 18) & 7));
		ctx->buf[ctx->npos++] = (char)(0x80 | ((uint8_t)(ctx->temp >> 12) & 0x3f));
	}
b:
	ctx->buf[ctx->npos++] = (char)(0x80 | ((uint8_t)(ctx->temp >> 6) & 0x3f));
a:
	ctx->buf[ctx->npos++] = (char)(0x80 | ((uint8_t)(ctx->temp) & 0x3f));
}

static int
lcsp_append_cssval_int(lhp_ctx_t *ctx)
{
	lcsp_atr_t *atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr), LHP_AC_GRANULE);
	if (!atr)
		return 1;

	/* add this prop value atr to the def */

	//lwsl_err("%s: tf %d.%u\n", __func__, ctx->tf.whole, ctx->tf.frac);
	atr->u.i = ctx->tf;
	/* a bare number: keep it distinct from keyword atrs (unit NONE) */
	atr->unit = ctx->unit ? ctx->unit : LCSP_UNIT_NUM;

	lws_dll2_add_tail(&atr->list, &ctx->def->atrs);

	return 0;
}

static int
lcsp_append_cssval_color(lhp_ctx_t *ctx)
{
	lcsp_atr_t *atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr), LHP_AC_GRANULE);
	unsigned int r, g, b, a = 0xff;

	if (!atr)
		return 1;

	/* add this prop value atr to the def */

	switch (ctx->temp_count) {
	case 3:
		r = (ctx->temp >> 8) & 0xf;
		g = (ctx->temp >> 4) & 0xf;
		b = ctx->temp & 0xf;
		atr->u.rgba = (a << 24) | (b << 20) | (b << 16) |
				(g << 12) | (g << 8) | (r << 4) | r;
		break;
	case 4:
		r = (ctx->temp >> 12) & 0xf;
		g = (ctx->temp >> 8) & 0xf;
		b = (ctx->temp >> 4) & 0xf;
		a = ctx->temp & 0xf;
		atr->u.rgba = (a << 28) | (a << 24) | (b << 20) | (b << 16) |
				(g << 12) | (g << 8) | (r << 4) | r;
		break;
	case 6:
		r = (ctx->temp >> 16) & 0xff;
		g = (ctx->temp >> 8) & 0xff;
		b = (ctx->temp) & 0xff;
		atr->u.rgba = (a << 24) | (b << 16) | (g << 8) | r;
		break;
	case 8:
		r = (ctx->temp >> 24) & 0xff;
		g = (ctx->temp >> 16) & 0xff;
		b = (ctx->temp >> 8) & 0xff;
		a = (ctx->temp) & 0xff;
		atr->u.rgba = (a << 24) | (b << 16) | (g << 8) | r;
		break;
	}

	// lwsl_err("%s: %d, 0x%08x, 0x%08x\n", __func__, ctx->temp_count, ctx->temp, atr->u.rgba);

	atr->unit = LCSP_UNIT_RGBA;

	lws_dll2_add_tail(&atr->list, &ctx->def->atrs);

	ctx->u.f.color = 0;
	ctx->temp = 0;
	ctx->temp_count = 0;

	return 0;
}

static int lcsp_append_cssval_string(lhp_ctx_t *ctx);

/* properties whose keyword values may be colour names */

static int
lcsp_prop_takes_colour(int prop)
{
	switch (prop) {
	case LCSP_PROP_COLOR:
	case LCSP_PROP_BACKGROUND_COLOR:
	case LCSP_PROP_BACKGROUND:
	case LCSP_PROP_BORDER_COLOR:
	case LCSP_PROP_BORDER_TOP_COLOR:
	case LCSP_PROP_BORDER_RIGHT_COLOR:
	case LCSP_PROP_BORDER_BOTTOM_COLOR:
	case LCSP_PROP_BORDER_LEFT_COLOR:
	case LCSP_PROP_BORDER:
	case LCSP_PROP_BORDER_TOP:
	case LCSP_PROP_BORDER_RIGHT:
	case LCSP_PROP_BORDER_BOTTOM:
	case LCSP_PROP_BORDER_LEFT:
	case LCSP_PROP_OUTLINE_COLOR:
	case LCSP_PROP_OUTLINE:
		return 1;
	default:
		return 0;
	}
}

/* the CSS named colours pages actually use; value is 0xRRGGBB */

static const struct {
	const char	*name;
	uint32_t	rgb;
} lcsp_named_colours[] = {
	{ "black",	0x000000 }, { "white",	0xffffff },
	{ "red",	0xff0000 }, { "green",	0x008000 },
	{ "blue",	0x0000ff }, { "yellow",	0xffff00 },
	{ "gray",	0x808080 }, { "grey",	0x808080 },
	{ "silver",	0xc0c0c0 }, { "maroon",	0x800000 },
	{ "purple",	0x800080 }, { "fuchsia",	0xff00ff },
	{ "magenta",	0xff00ff }, { "lime",	0x00ff00 },
	{ "olive",	0x808000 }, { "navy",	0x000080 },
	{ "teal",	0x008080 }, { "aqua",	0x00ffff },
	{ "cyan",	0x00ffff }, { "orange",	0xffa500 },
	{ "darkgray",	0xa9a9a9 }, { "darkgrey",	0xa9a9a9 },
	{ "lightgray",	0xd3d3d3 }, { "lightgrey",	0xd3d3d3 },
	{ "dimgray",	0x696969 }, { "dimgrey",	0x696969 },
	{ "whitesmoke",	0xf5f5f5 }, { "gainsboro",	0xdcdcdc },
	{ "darkgreen",	0x006400 }, { "darkblue",	0x00008b },
	{ "darkred",	0x8b0000 }, { "lightblue",	0xadd8e6 },
	{ "lightgreen",	0x90ee90 }, { "steelblue",	0x4682b4 },
	{ "royalblue",	0x4169e1 }, { "dodgerblue",	0x1e90ff },
	{ "skyblue",	0x87ceeb }, { "slategray",	0x708090 },
	{ "slategrey",	0x708090 }, { "gold",	0xffd700 },
	{ "pink",	0xffc0cb }, { "hotpink",	0xff69b4 },
	{ "brown",	0xa52a2a }, { "tan",	0xd2b48c },
	{ "beige",	0xf5f5dc }, { "ivory",	0xfffff0 },
	{ "khaki",	0xf0e68c }, { "coral",	0xff7f50 },
	{ "salmon",	0xfa8072 }, { "crimson",	0xdc143c },
	{ "tomato",	0xff6347 }, { "orangered",	0xff4500 },
	{ "indigo",	0x4b0082 }, { "violet",	0xee82ee },
	{ "turquoise",	0x40e0d0 }, { "chocolate",	0xd2691e },
	{ "firebrick",	0xb22222 }, { "forestgreen",	0x228b22 },
	{ "seagreen",	0x2e8b57 }, { "midnightblue",	0x191970 },
	{ "lavender",	0xe6e6fa }, { "linen",	0xfaf0e6 },
	{ "snow",	0xfffafa }, { "aliceblue",	0xf0f8ff },
};

static int
lcsp_append_rgba(lhp_ctx_t *ctx, uint32_t rgba)
{
	lcsp_atr_t *atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr),
					 LHP_AC_GRANULE);

	if (!atr)
		return 1;

	atr->unit = LCSP_UNIT_RGBA;
	atr->u.rgba = rgba;
	lws_dll2_add_tail(&atr->list, &ctx->def->atrs);

	return 0;
}

/* a number in a functional value, with optional % or deg; 0 if none */

static int
lcsp_func_num(const char **pp, const char *end, lws_fx_t *v, int *pct)
{
	const char *p = *pp, *s;

	while (p < end && (*p == ' ' || *p == ',' || *p == '/'))
		p++;
	s = p;
	while (p < end && ((*p >= '0' && *p <= '9') || *p == '.' || *p == '-'))
		p++;
	if (p == s) {
		*pp = p;
		return 0;
	}
	lhp_fx_parse(v, s, (size_t)(p - s));
	*pct = p < end && *p == '%';
	while (p < end && ((*p >= 'a' && *p <= 'z') || *p == '%'))
		p++;
	*pp = p;

	return 1;
}

static uint32_t
lcsp_chan(const lws_fx_t *v, int pct, int scale)
{
	lws_fx_t t, c255 = { 255, 0 }, c100 = { 100, 0 }, cs = { scale, 0 };
	int32_t r;

	if (pct)
		lws_fx_div(&t, lws_fx_mul(&t, v, &c255), &c100);
	else
		lws_fx_mul(&t, v, &cs);

	r = lws_fx_roundup(&t);
	if (r < 0)
		r = 0;
	if (r > 255)
		r = 255;

	return (uint32_t)r;
}

/* hsl to rgb, h in degrees, s and l as 0..255 */

static uint32_t
lcsp_hsl_chan(int h, int s, int l, int n)
{
	/* CSS Color 4 algorithm with everything scaled by 255 */
	int k = (n * 30 + h) % 360, a, v;

	if (k < 0)
		k += 360;
	a = s * (l < 128 ? l : 255 - l) / 255;

	/* min(k - 3, 9 - k, 1) in twelfths of a turn -> degrees */
	v = k - 90;
	if (270 - k < v)
		v = 270 - k;
	if (v > 30)
		v = 30;
	if (v < -30)
		v = -30;

	return (uint32_t)(l - a * v / 30);
}

/*
 * A complete name( ... ) value is in buf: turn it into the right kind of
 * attribute
 */

static int
lcsp_func_value(lhp_ctx_t *ctx)
{
	const char *b = ctx->buf, *p = strchr(b, '('), *end;
	size_t nl;

	if (!p || !ctx->def)
		return 0;

	nl = (size_t)(p - b);
	p++;
	end = ctx->buf + ctx->npos - 1; /* the closing paren */

	if (nl == 4 && !strncasecmp(b, "calc", 4)) {
		lcsp_atr_t *atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr) +
					(size_t)(end - p) + 1, LHP_AC_GRANULE);
		if (!atr)
			return 1;

		atr->unit = LCSP_UNIT_CALC;
		atr->value_len = (size_t)(end - p);
		memcpy(&atr[1], p, atr->value_len);
		((char *)&atr[1])[atr->value_len] = '\0';
		lws_dll2_add_tail(&atr->list, &ctx->def->atrs);

		return 0;
	}

	if ((nl == 3 && !strncasecmp(b, "rgb", 3)) ||
	    (nl == 4 && !strncasecmp(b, "rgba", 4))) {
		lws_fx_t v[4];
		int pct[4], n = 0;
		uint32_t c[4] = { 0, 0, 0, 255 };

		while (n < 4 && lcsp_func_num(&p, end, &v[n], &pct[n]))
			n++;
		if (n < 3)
			return 0;
		c[0] = lcsp_chan(&v[0], pct[0], 1);
		c[1] = lcsp_chan(&v[1], pct[1], 1);
		c[2] = lcsp_chan(&v[2], pct[2], 1);
		if (n == 4)
			c[3] = lcsp_chan(&v[3], pct[3], 255);

		return lcsp_append_rgba(ctx, (c[3] << 24) | (c[2] << 16) |
					     (c[1] << 8) | c[0]);
	}

	if ((nl == 3 && !strncasecmp(b, "hsl", 3)) ||
	    (nl == 4 && !strncasecmp(b, "hsla", 4))) {
		lws_fx_t v[4];
		int pct[4], n = 0, h, sa, l;
		uint32_t a = 255;

		while (n < 4 && lcsp_func_num(&p, end, &v[n], &pct[n]))
			n++;
		if (n < 3)
			return 0;
		h = v[0].whole % 360;
		if (h < 0)
			h += 360;
		sa = (int)lcsp_chan(&v[1], 1, 1);
		l = (int)lcsp_chan(&v[2], 1, 1);
		if (n == 4)
			a = lcsp_chan(&v[3], pct[3], 255);

		return lcsp_append_rgba(ctx, (a << 24) |
				(lcsp_hsl_chan(h, sa, l, 4) << 16) |
				(lcsp_hsl_chan(h, sa, l, 8) << 8) |
				 lcsp_hsl_chan(h, sa, l, 0));
	}

	if (nl == 3 && !strncasecmp(b, "url", 3)) {
		lcsp_atr_t *atr;
		size_t vl;

		/* the bare address: strip whitespace and quotes */
		while (p < end && (*p == ' ' || *p == '"' || *p == '\''))
			p++;
		while (end > p && (end[-1] == ' ' || end[-1] == '"' ||
				   end[-1] == '\''))
			end--;
		vl = (size_t)(end - p);

		atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr) + vl + 1,
				     LHP_AC_GRANULE);
		if (!atr)
			return 1;

		atr->unit = LCSP_UNIT_URL;
		atr->value_len = vl;
		memcpy(&atr[1], p, vl);
		((char *)&atr[1])[vl] = '\0';
		lws_dll2_add_tail(&atr->list, &ctx->def->atrs);

		return 0;
	}

	/* var(--x), linear-gradient(...) etc: keep the text */

	return lcsp_append_cssval_string(ctx);
}

/*
 * A delimiter arrived while a keyword value was being matched: the token
 * may be a complete keyword that is also the prefix of a longer one (eg,
 * "table" vs "table-row"), which the minilex only reports when asked with a
 * NUL.  Otherwise keep it as a string value.
 */

static int
lcsp_finish_cssval_keyword(lhp_ctx_t *ctx)
{
	int r;

	if (!ctx->cssval_state || !ctx->def)
		return 0;

	r = 0;
	if (ctx->cssval_state > 0 &&
	    lws_minilex_parse(css_propconst_lextable, &ctx->cssval_state, 0,
			      &ctx->propval) == LWS_MINILEX_MATCH) {
		lcsp_atr_t *atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr),
						 LHP_AC_GRANULE);
		if (!atr)
			return 1;

		atr->propval = ctx->propval;
		lws_dll2_add_tail(&atr->list, &ctx->def->atrs);
	} else if (ctx->npos)
		r = lcsp_append_cssval_string(ctx);

	ctx->npos = 0;
	ctx->cssval_state = 0;

	return r;
}

static int
lcsp_append_cssval_string(lhp_ctx_t *ctx)
{
	lcsp_atr_t *atr;
	char *v, *c = &ctx->buf[0];

	if (c[0] == '\"' || c[0] == '\'') {
		c++;
		ctx->npos--;
	}
	if (ctx->npos && (c[ctx->npos - 1] == '\"' || c[ctx->npos - 1] == '\''))
		ctx->npos--;

	if (ctx->npos == 10 && !strncasecmp(c, "!important", 10)) {
		/* not a value: raise the precedence of the declaration */
		if (ctx->def)
			ctx->def->important = 1;
		return 0;
	}

	if (ctx->def && lcsp_prop_takes_colour((int)ctx->def->prop)) {
		size_t n;

		if (ctx->npos == 11 && !strncasecmp(c, "transparent", 11))
			return lcsp_append_rgba(ctx, 0);

		for (n = 0; n < LWS_ARRAY_SIZE(lcsp_named_colours); n++)
			if (strlen(lcsp_named_colours[n].name) == (size_t)ctx->npos &&
			    !strncasecmp(c, lcsp_named_colours[n].name,
					 (size_t)ctx->npos)) {
				uint32_t rgb = lcsp_named_colours[n].rgb;

				return lcsp_append_rgba(ctx, 0xff000000u |
					((rgb & 0xff) << 16) | (rgb & 0xff00) |
					(rgb >> 16));
			}
	}

	atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr) + (size_t)ctx->npos + 1u,
			     LHP_AC_GRANULE);
	if (!atr)
		return 1;

	v = (char *)&atr[1];
	atr->value_len = (size_t)ctx->npos;
	memcpy(v, c, (size_t)ctx->npos);
	v[ctx->npos] = '\0';
	atr->unit = LCSP_UNIT_STRING;

	//lwsl_notice("%s: %s\n", __func__, v);

	lws_dll2_add_tail(&atr->list, &ctx->def->atrs);

	return 0;
}

const char *
lws_html_get_atr(lhp_pstack_t *ps, const char *aname, size_t aname_len);

static int
lhp_element_has_class(lhp_pstack_t *ps, const char *name, size_t name_len)
{
	const char *c = lws_html_get_atr(ps, "class", 5);
	struct lws_tokenize ts;

	if (!c)
		return 0;

	memset(&ts, 0, sizeof(ts));
	ts.start = c;
	ts.len = strlen(c);
	ts.flags = LWS_TOKENIZE_F_MINUS_NONTERM;

	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		if (ts.e == LWS_TOKZE_TOKEN) {
			if (ts.token_len == name_len &&
			    !memcmp(ts.token, name, name_len))
				return 1;
		}
	} while (ts.e > 0);

	return 0;
}

/* html attribute lookup with case-insensitive name, for [attr] selectors */

static const char *
lhp_get_atr_ci(lhp_pstack_t *ps, const char *aname, size_t aname_len)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&ps->atr)) {
		const lhp_atr_t *at = lws_container_of(p, lhp_atr_t, list);
		const char *ats = (const char *)&at[1];

		if (p != lws_dll2_get_head(&ps->atr) &&
		    at->name_len == aname_len &&
		    !strncasecmp(ats, aname, aname_len))
			return ats + aname_len + 1;

	} lws_end_foreach_dll(p);

	return NULL;
}

/*
 * CSS selectors
 *
 * Selector text is kept as written, normalized so that a single space is the
 * descendant combinator, there are no spaces around '>', '+', '~', and none
 * inside [...].  Matching walks it right-to-left over the compound selectors,
 * consulting the parse stack for ancestors.
 */

static int
lhp_ident_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '-' || c == '_' ||
	       (unsigned char)c >= 0x80;
}

/* does element ps match the compound selector [p, end) ? */

static int
lhp_sel_match_compound(lhp_pstack_t *ps, const char *p, const char *end)
{
	const lhp_atr_t *ta;
	const char *tag, *s, *v;
	size_t tag_len;

	if (lws_dll2_is_empty(&ps->atr))
		/* the document level: no element here */
		return 0;

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	tag = (const char *)&ta[1];
	tag_len = ta->name_len;

	if (p >= end)
		return 0;

	while (p < end) {
		switch (*p) {
		case '*':
			p++;
			break;

		case '.':
			s = ++p;
			while (p < end && lhp_ident_char(*p))
				p++;
			if (p == s ||
			    !lhp_element_has_class(ps, s, (size_t)(p - s)))
				return 0;
			break;

		case '#':
			s = ++p;
			while (p < end && lhp_ident_char(*p))
				p++;
			v = lws_html_get_atr(ps, "id", 2);
			if (p == s || !v || strlen(v) != (size_t)(p - s) ||
			    memcmp(v, s, (size_t)(p - s)))
				return 0;
			break;

		case '[':
		{
			const char *an, *av = NULL;
			size_t anl, avl = 0, vl;
			char op = 0;

			an = ++p;
			while (p < end && *p != ']' && *p != '=' && *p != '~' &&
			       *p != '|' && *p != '^' && *p != '$' && *p != '*')
				p++;
			anl = (size_t)(p - an);
			if (p < end && *p != ']') {
				op = *p++;
				if (op != '=') {
					if (p >= end || *p != '=')
						return 0;
					p++;
				}
				if (p < end && (*p == '"' || *p == '\'')) {
					char q = *p++;

					av = p;
					while (p < end && *p != q)
						p++;
					avl = (size_t)(p - av);
					if (p < end)
						p++;
				} else {
					av = p;
					while (p < end && *p != ']')
						p++;
					avl = (size_t)(p - av);
				}
			}
			if (p >= end || *p != ']' || !anl)
				return 0;
			p++;

			v = lhp_get_atr_ci(ps, an, anl);
			if (!v)
				return 0;
			if (!op)
				break;

			vl = strlen(v);
			switch (op) {
			case '=':
				if (vl != avl || memcmp(v, av, avl))
					return 0;
				break;
			case '^':
				if (!avl || vl < avl || memcmp(v, av, avl))
					return 0;
				break;
			case '$':
				if (!avl || vl < avl ||
				    memcmp(v + vl - avl, av, avl))
					return 0;
				break;
			case '|':
				if (vl < avl || memcmp(v, av, avl) ||
				    (v[avl] && v[avl] != '-'))
					return 0;
				break;
			case '~':
			{
				struct lws_tokenize ts;
				int hit = 0;

				memset(&ts, 0, sizeof(ts));
				ts.start = v;
				ts.len = vl;
				ts.flags = LWS_TOKENIZE_F_MINUS_NONTERM |
					   LWS_TOKENIZE_F_DOT_NONTERM;
				do {
					ts.e = (int8_t)lws_tokenize(&ts);
					if (ts.e == LWS_TOKZE_TOKEN &&
					    ts.token_len == avl &&
					    !memcmp(ts.token, av, avl))
						hit = 1;
				} while (ts.e > 0 && !hit);
				if (!hit)
					return 0;
				break;
			}
			case '*':
				if (!avl || vl < avl)
					return 0;
				for (s = v; s + avl <= v + vl; s++)
					if (!memcmp(s, av, avl))
						break;
				if (s + avl > v + vl)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		}

		case ':':
			/*
			 * Pseudo-classes and pseudo-elements: we have no
			 * link, hover or focus state and don't generate
			 * ::before / ::after boxes, so these never match.
			 */
			return 0;

		default:
			if (!lhp_ident_char(*p))
				return 0;
			s = p;
			while (p < end && lhp_ident_char(*p))
				p++;
			if ((size_t)(p - s) != tag_len ||
			    strncasecmp(s, tag, tag_len))
				return 0;
			break;
		}
	}

	return 1;
}

/*
 * Match the selector [sel, end) against element ps.  '+' and '~' need
 * sibling information we don't keep, so selectors using them never match.
 */

static int
lhp_sel_match(lhp_pstack_t *ps, const char *sel, const char *end)
{
	const char *p = end;
	char comb = 0;
	int inb = 0;

	/* find the start of the rightmost compound selector */

	while (p > sel) {
		char c = p[-1];

		if (c == ']')
			inb = 1;
		else if (c == '[')
			inb = 0;
		else if (!inb && (c == ' ' || c == '>' || c == '+' || c == '~')) {
			comb = c;
			break;
		}
		p--;
	}

	if (!lhp_sel_match_compound(ps, p, end))
		return 0;

	if (!comb)
		return 1;

	end = p - 1; /* the selector text left of the combinator */
	if (end <= sel)
		return 0;

	switch (comb) {
	case ' ': /* any ancestor */
		lws_start_foreach_dll_back(lws_dll2_t *, d,
					   lws_dll2_get_prev(&ps->list)) {
			lhp_pstack_t *a = lws_container_of(d, lhp_pstack_t,
							   list);

			if (lhp_sel_match(a, sel, end))
				return 1;
		} lws_end_foreach_dll_back(d);
		return 0;

	case '>': /* the parent */
		if (!lws_dll2_get_prev(&ps->list))
			return 0;
		return lhp_sel_match(lws_container_of(
					lws_dll2_get_prev(&ps->list),
					lhp_pstack_t, list), sel, end);

	default:
		return 0;
	}
}

static uint32_t
lhp_sel_specificity(const char *p, const char *end)
{
	unsigned int a = 0, b = 0, c = 0;
	int inb = 0;

	while (p < end) {
		char ch = *p++;

		if (inb) {
			if (ch == ']')
				inb = 0;
			continue;
		}

		switch (ch) {
		case '#':
			a++;
			break;
		case '.':
			b++;
			break;
		case '[':
			b++;
			inb = 1;
			continue;
		case ':':
			if (p < end && *p == ':') {
				p++;
				c++;
			} else
				b++;
			break;
		case '*':
		case ' ':
		case '>':
		case '+':
		case '~':
			continue;
		default:
			if (!lhp_ident_char(ch))
				continue;
			c++;
			break;
		}

		/* skip the rest of the identifier (and any (...) argument) */
		while (p < end && lhp_ident_char(*p))
			p++;
		if (p < end && *p == '(') {
			while (p < end && *p != ')')
				p++;
			if (p < end)
				p++;
		}
	}

	if (a > 255)
		a = 255;
	if (b > 255)
		b = 255;
	if (c > 255)
		c = 255;

	return (a << 16) | (b << 8) | c;
}

/*
 * Split the comma-separated selector list in [buf, buf + len) into
 * normalized lcsp_names_t on the current stanza
 */

static int
lhp_css_add_names(lhp_ctx_t *ctx, const char *buf, size_t len)
{
	const char *p = buf, *end = buf + len;

	while (p < end) {
		const char *s = p, *e;
		char norm[128];
		lcsp_names_t *na;
		size_t n = 0;
		int inb = 0;

		while (p < end && *p != ',')
			p++;
		e = p;
		if (p < end)
			p++;

		while (s < e && *s == ' ')
			s++;
		while (e > s && e[-1] == ' ')
			e--;
		if (s == e)
			continue;

		while (s < e && n < sizeof(norm) - 1) {
			char c = *s++;

			if (c == '[')
				inb = 1;
			else if (c == ']')
				inb = 0;

			if (c == ' ') {
				if (inb)
					continue;
				if (n && (norm[n - 1] == '>' ||
					  norm[n - 1] == '+' ||
					  norm[n - 1] == '~'))
					continue;
				if (s < e && (*s == '>' || *s == '+' ||
					      *s == '~'))
					continue;
			}
			norm[n++] = c;
		}

		na = lwsac_use_zero(&ctx->cssac, sizeof(*na) + n + 1,
				    LHP_AC_GRANULE);
		if (!na)
			return 1;

		na->name_len = n;
		na->specificity = lhp_sel_specificity(norm, norm + n);
		memcpy(&na[1], norm, n);
		((char *)(&na[1]))[n] = '\0';
		lws_dll2_add_tail(&na->list, &ctx->stz->names);
	}

	return 0;
}

/*
 * Crude @media evaluation: enough to keep print / max-width blocks from
 * leaking into the layout.  Unknown features are treated as not matching.
 */

static int
lhp_media_feature(lhp_ctx_t *ctx, const char *p, const char *end)
{
	const char *n = p, *v;
	size_t nl;
	lws_fx_t val;
	int px, ref;

	while (p < end && *p != ':' && *p != ')')
		p++;
	nl = (size_t)(p - n);
	while (nl && n[nl - 1] == ' ')
		nl--;

	if (p >= end || *p != ':') {
		/* (color), (hover) etc: only "(color)" is something we are */
		return nl == 5 && !strncmp(n, "color", 5) &&
		       !ctx->ic.greyscale;
	}

	p++;
	while (p < end && *p == ' ')
		p++;
	v = p;

	if (nl == 11 && !strncmp(n, "orientation", 11))
		return (ctx->ic.wh_px[0].whole >= ctx->ic.wh_px[1].whole) ==
		       (end - v >= 9 && !strncmp(v, "landscape", 9));

	if ((nl == 9 && !strncmp(n, "max-width", 9)) ||
	    (nl == 9 && !strncmp(n, "min-width", 9)) ||
	    (nl == 10 && !strncmp(n, "max-height", 10)) ||
	    (nl == 10 && !strncmp(n, "min-height", 10))) {
		ref = n[4] == 'w' ? 0 : 1;
		lhp_fx_parse(&val, v, (size_t)(end - v));
		while (v < end && ((*v >= '0' && *v <= '9') || *v == '.'))
			v++;
		if (end - v >= 2 && (!strncmp(v, "em", 2) ||
				     !strncmp(v, "rem", 3)))
			val.whole *= 16;
		px = ctx->ic.wh_px[ref].whole;
		if (n[1] == 'a') /* max- */
			return px <= val.whole;
		return px >= val.whole;
	}

	return 0;
}

static int
lhp_media_query_true(lhp_ctx_t *ctx, const char *q, const char *end)
{
	/* comma-separated list: any true */
	while (q < end) {
		const char *s = q, *e;
		int all = 1, neg = 0;

		while (q < end && *q != ',')
			q++;
		e = q;
		if (q < end)
			q++;

		while (s < e && *s == ' ')
			s++;
		while (e > s && e[-1] == ' ')
			e--;

		if (e - s >= 4 && !strncmp(s, "not ", 4)) {
			neg = 1;
			s += 4;
		}
		if (e - s >= 5 && !strncmp(s, "only ", 5))
			s += 5;

		/* " and "-separated terms: all true */
		while (s < e && all) {
			const char *t = s, *te;

			while (s < e && strncmp(s, " and ", 5))
				s++;
			te = s;
			if (s < e)
				s += 5;

			if (*t == '(') {
				t++;
				if (te > t && te[-1] == ')')
					te--;
				all = lhp_media_feature(ctx, t, te);
			} else if ((te - t == 3 && !strncmp(t, "all", 3)) ||
				   (te - t == 6 && !strncmp(t, "screen", 6)))
				all = 1;
			else
				all = 0; /* print, speech, unknown */
		}

		if (all != neg)
			return 1;
	}

	return 0;
}

/*
 * Properties whose computed value passes from parent to child when the child
 * doesn't declare them (CSS 2.1 "Inherited: yes")
 */

static int
lhp_prop_inherited(int prop)
{
	switch (prop) {
	case LCSP_PROP_AZIMUTH:
	case LCSP_PROP_BORDER_COLLAPSE:
	case LCSP_PROP_BORDER_SPACING:
	case LCSP_PROP_CAPTION_SIDE:
	case LCSP_PROP_COLOR:
	case LCSP_PROP_CURSOR:
	case LCSP_PROP_DIRECTION:
	case LCSP_PROP_ELEVATION:
	case LCSP_PROP_EMPTY_CELLS:
	case LCSP_PROP_FONT_FAMILY:
	case LCSP_PROP_FONT_SIZE:
	case LCSP_PROP_FONT_STYLE:
	case LCSP_PROP_FONT_VARAIANT:
	case LCSP_PROP_FONT_WEIGHT:
	case LCSP_PROP_FONT:
	case LCSP_PROP_LETTER_SPACING:
	case LCSP_PROP_LINE_HEIGHT:
	case LCSP_PROP_LIST_STYLE_IMAGE:
	case LCSP_PROP_LIST_STYLE_POSITION:
	case LCSP_PROP_LIST_STYLE_TYPE:
	case LCSP_PROP_LIST_STYLE:
	case LCSP_PROP_ORPHANS:
	case LCSP_PROP_PITCH_RANGE:
	case LCSP_PROP_PITCH:
	case LCSP_PROP_QUOTES:
	case LCSP_PROP_RICHNESS:
	case LCSP_PROP_SPEAK_HEADER:
	case LCSP_PROP_SPEAK_NUMERAL:
	case LCSP_PROP_SPEAK_PUNCTUATION:
	case LCSP_PROP_SPEAK:
	case LCSP_PROP_SPEECH_RATE:
	case LCSP_PROP_STRESS:
	case LCSP_PROP_TEXT_ALIGN:
	case LCSP_PROP_TEXT_INDENT:
	case LCSP_PROP_TEXT_TRANSFORM:
	case LCSP_PROP_VISIBILITY:
	case LCSP_PROP_VOICE_FAMILY:
	case LCSP_PROP_VOLUME:
	case LCSP_PROP_WHITE_SPACE:
	case LCSP_PROP_WIDOWS:
	case LCSP_PROP_WORD_SPACING:
		return 1;
	default:
		return 0;
	}
}

/*
 * The winning declaration of prop among the stanzas matched by ps, or NULL
 */

static const lcsp_defs_t *
lhp_find_def2(lhp_pstack_t *ps, int prop, int prop_alt)
{
	int n, pass;

	/* pass 0: !important declarations, pass 1: the rest */

	for (pass = 0; pass < 2; pass++)
		for (n = (int)ps->nmatched - 1; n >= 0; n--) {
			lws_start_foreach_dll_back(lws_dll2_t *, d,
				lws_dll2_get_tail(&ps->matched[n].stz->defs)) {
				lcsp_defs_t *def = lws_container_of(d,
							lcsp_defs_t, list);

				if (((int)def->prop == prop ||
				     (int)def->prop == prop_alt) &&
				    !!def->important == !pass)
					return def;
			} lws_end_foreach_dll_back(d);
		}

	return NULL;
}

static const lcsp_defs_t *
lhp_find_def(lhp_pstack_t *ps, int prop)
{
	return lhp_find_def2(ps, prop, -1);
}

/*
 * The value in effect for one side of a box property that has both longhand
 * (eg, margin-top) and shorthand (eg, margin: 1px 2px) forms: whichever was
 * declared with the higher precedence wins, and a shorthand is expanded by
 * the position of its values.  These properties don't inherit, so only the
 * element's own declarations count.
 *
 * TRBL: 1 value: all; 2: top/bottom, left/right; 3: top, left/right, bottom;
 *       4: top, right, bottom, left.  idx: 0 top, 1 right, 2 bottom, 3 left
 *
 * radii: 1: all; 2: TL/BR, TR/BL; 3: TL, TR/BL, BR; 4: TL, TR, BR, BL.
 *        idx: 0 TL, 1 TR, 2 BL, 3 BR
 */

static const lcsp_atr_t *
lhp_side_atr(lhp_pstack_t *ps, int longhand, int shorthand, int idx,
	     int radii)
{
	const lcsp_defs_t *def = lhp_find_def2(ps, longhand, shorthand);
	int c, use = 0;

	if (!def || !lws_dll2_get_head(&def->atrs))
		return NULL;

	if ((int)def->prop == longhand)
		return lws_container_of(lws_dll2_get_tail(&def->atrs),
					lcsp_atr_t, list);

	c = (int)lws_dll2_count(&def->atrs);

	if (!radii) {
		switch (c) {
		case 2:
			use = (idx == 0 || idx == 2) ? 0 : 1;
			break;
		case 3:
			use = idx == 0 ? 0 : ((idx == 1 || idx == 3) ? 1 : 2);
			break;
		case 4:
			use = idx;
			break;
		default:
			use = 0;
			break;
		}
	} else {
		switch (c) {
		case 2:
			use = (idx == 0 || idx == 3) ? 0 : 1;
			break;
		case 3:
			use = idx == 0 ? 0 : ((idx == 1 || idx == 2) ? 1 : 2);
			break;
		case 4:
			use = idx == 0 ? 0 : (idx == 1 ? 1 : (idx == 3 ? 2 : 3));
			break;
		default:
			use = 0;
			break;
		}
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&def->atrs)) {
		if (!use--)
			return lws_container_of(d, lcsp_atr_t, list);
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * Find the declaration in effect for prop on element ps, listing its values
 * in ctx->active_atr and returning the last one
 */

static const lcsp_atr_t *
lhp_prop_atr_ps(lhp_ctx_t *ctx, lhp_pstack_t *ps, lcsp_props_t prop)
{
	int inh = lhp_prop_inherited((int)prop);
	lcsp_atr_ptr_t *ap;

	lws_dll2_owner_clear(&ctx->active_atr);
	lwsac_free(&ctx->propatrac);

	while (ps) {
		const lcsp_defs_t *def = lhp_find_def(ps, (int)prop);
		const lcsp_atr_t *a;

		if (!def) {
			if (!inh)
				return NULL;
			goto parent;
		}

		if (!lws_dll2_get_head(&def->atrs))
			return NULL;

		a = lws_container_of(lws_dll2_get_head(&def->atrs),
				     lcsp_atr_t, list);
		if (a->unit == LCSP_UNIT_NONE &&
		    a->propval == LCSP_PROPVAL_INHERIT)
			goto parent;

		lws_start_foreach_dll(struct lws_dll2 *, z,
				      lws_dll2_get_head(&def->atrs)) {
			lcsp_atr_ptr_t *patr = lwsac_use_zero(&ctx->propatrac,
						sizeof(*patr), LHP_AC_GRANULE);
			if (!patr)
				return NULL;

			patr->atr = lws_container_of(z, lcsp_atr_t, list);
			lws_dll2_add_tail(&patr->list, &ctx->active_atr);
		} lws_end_foreach_dll(z);

		ap = lws_container_of(lws_dll2_get_tail(&ctx->active_atr),
				      lcsp_atr_ptr_t, list);

		return ap->atr;

parent:
		if (!lws_dll2_get_prev(&ps->list))
			return NULL;
		ps = lws_container_of(lws_dll2_get_prev(&ps->list),
				      lhp_pstack_t, list);
	}

	return NULL;
}

static int
lhp_add_match(lhp_pstack_t *ps, lcsp_stanza_t *stz, uint32_t spec)
{
	lcsp_match_t *m;
	unsigned int n;

	if (ps->nmatched == 0xffff)
		return 0;

	m = lws_realloc(ps->matched, sizeof(*m) * (ps->nmatched + 1u),
			__func__);
	if (!m)
		return 1;
	ps->matched = m;

	/* stable insertion: after every entry with specificity <= ours */

	n = ps->nmatched;
	while (n && m[n - 1].specificity > spec) {
		m[n] = m[n - 1];
		n--;
	}
	m[n].stz = stz;
	m[n].specificity = spec;
	ps->nmatched++;

	return 0;
}

/*
 * Parse a style="..." attribute as a stanza that only this element matches,
 * reusing the declaration parser by nesting lws_lhp_parse() on the string.
 * The allocations go in ps->styleac so they die with the element.
 */

static int
lhp_parse_style_attr(lhp_ctx_t *ctx, lhp_pstack_t *ps, const char *val)
{
	static const uint8_t term[] = ";}";
	const uint8_t *p = (const uint8_t *)val, *pt = term;
	size_t len = strlen(val), lt = sizeof(term) - 1;
	struct lwsac *oac = ctx->cssac;
	lcsp_stanza_t *stz, *sstz = ctx->stz;
	lcsp_defs_t *sdef = ctx->def;
	int sstate = ctx->state, snpos = ctx->npos,
	    scomm = ctx->state_css_comm, stc = ctx->temp_count,
	    sprop = ctx->prop, spropval = ctx->propval, r = 0;
	int16_t scss = ctx->css_state, scssval = ctx->cssval_state;
	lcsp_css_units_t sunit = ctx->unit;
	uint32_t su = ctx->u.s, stemp = ctx->temp;
	lws_dll2_t *svars = lws_dll2_get_tail(&ctx->css_vars);
	lws_fx_t stf = ctx->tf;
	char sbuf[64];

	if (snpos < 0 || snpos > (int)sizeof(sbuf))
		return 0;
	memcpy(sbuf, ctx->buf, (size_t)snpos);

	ctx->cssac = ps->styleac;
	stz = lwsac_use_zero(&ctx->cssac, sizeof(*stz), LHP_AC_GRANULE);
	if (!stz) {
		r = 1;
		goto restore;
	}

	ctx->stz = stz;
	ctx->def = NULL;
	ctx->state = LCSPS_CSS_STANZA;
	ctx->state_css_comm = LCSPS_CSS_STANZA;
	ctx->u.s = 0;
	ctx->u.f.default_css = 1; /* no document-end processing in here */
	ctx->css_state = 0;
	ctx->cssval_state = 0;
	ctx->npos = 0;
	ctx->temp = 0;
	ctx->temp_count = 0;
	ctx->unit = LCSP_UNIT_NONE;

	if ((lws_lhp_parse(ctx, &p, &len) & LWS_SRET_FATAL) ||
	    (lws_lhp_parse(ctx, &pt, &lt) & LWS_SRET_FATAL))
		r = 1;
	else if (lws_dll2_get_head(&stz->defs) &&
		 lhp_add_match(ps, stz, 1u << 24))
		r = 1;

restore:
	/*
	 * --custom: values declared in the attribute were registered on the
	 * document-wide variable list but live in styleac, which dies with
	 * the element: unregister them
	 */
	while (lws_dll2_get_tail(&ctx->css_vars) != svars)
		lws_dll2_remove(lws_dll2_get_tail(&ctx->css_vars));

	ps->styleac = ctx->cssac;
	ctx->cssac = oac;
	ctx->stz = sstz;
	ctx->def = sdef;
	ctx->state = sstate;
	ctx->state_css_comm = scomm;
	ctx->temp_count = stc;
	ctx->prop = sprop;
	ctx->propval = spropval;
	ctx->css_state = scss;
	ctx->cssval_state = scssval;
	ctx->unit = sunit;
	ctx->u.s = su;
	ctx->temp = stemp;
	ctx->tf = stf;
	memcpy(ctx->buf, sbuf, (size_t)snpos);
	ctx->npos = snpos;

	return r;
}

/*
 * font-size is inherited as a computed px value, since relative units in the
 * declaration are relative to the parent's size
 */

static void
lhp_compute_font_size(lhp_ctx_t *ctx, lhp_pstack_t *ps, lhp_pstack_t *parent)
{
	static const lws_fx_t c16 = { 16, 0 };
	const lws_fx_t *pfs = parent && (parent->font_size.whole ||
					 parent->font_size.frac) ?
					 &parent->font_size : &c16;
	const lcsp_defs_t *def = lhp_find_def(ps, LCSP_PROP_FONT_SIZE);
	const lcsp_atr_t *a;
	lws_fx_t t, r;

	ps->font_size = *pfs;

	if (!def || !lws_dll2_get_head(&def->atrs))
		return;

	a = lws_container_of(lws_dll2_get_head(&def->atrs), lcsp_atr_t, list);

	switch (a->unit) {
	case LCSP_UNIT_NUM:
	case LCSP_UNIT_LENGTH_PX:
		r = a->u.i;
		break;
	case LCSP_UNIT_LENGTH_EM:
		lws_fx_mul(&r, &a->u.i, pfs);
		break;
	case LCSP_UNIT_LENGTH_EX:
		lws_fx_mul(&t, &a->u.i, pfs);
		lws_fx_div(&r, &t, &lws_fx_2);
		break;
	case LCSP_UNIT_LENGTH_PERCENT:
		lws_fx_mul(&t, &a->u.i, pfs);
		lws_fx_div(&r, &t, &c_100);
		break;
	case LCSP_UNIT_LENGTH_REM:
	{
		/* the root element's size is that of the level after the
		 * document level, if it has been resolved */
		const lws_fx_t *rfs = &c16;
		lws_dll2_t *d = lws_dll2_get_head(&ctx->stack);

		if (d && lws_dll2_get_next(d)) {
			lhp_pstack_t *root = lws_container_of(
					lws_dll2_get_next(d), lhp_pstack_t, list);
			if (root->font_size.whole)
				rfs = &root->font_size;
		}
		lws_fx_mul(&r, &a->u.i, rfs);
		break;
	}
	case LCSP_UNIT_LENGTH_PT: /* css px are 1/96in, pt 1/72in */
		lws_fx_mul(&t, &a->u.i, &lws_fx_4);
		lws_fx_div(&r, &t, &lws_fx_3);
		break;
	case LCSP_UNIT_LENGTH_PC:
		lws_fx_mul(&r, &a->u.i, &c16);
		break;
	case LCSP_UNIT_LENGTH_IN:
		lws_fx_mul(&r, &a->u.i, &lws_fx_96);
		break;
	case LCSP_UNIT_LENGTH_CM:
		lws_fx_mul(&t, &a->u.i, &lws_fx_96);
		lws_fx_div(&r, &t, &c_254);
		break;
	case LCSP_UNIT_LENGTH_MM:
		lws_fx_mul(&t, &a->u.i, &lws_fx_96);
		lws_fx_div(&r, &t, &lws_fx_254);
		break;
	case LCSP_UNIT_STRING:
	{
		/* absolute-size keywords, CSS2.1 table for a 16px medium */
		static const struct { const char *n; uint8_t px; } ks[] = {
			{ "xx-small", 9 }, { "x-small", 10 }, { "small", 13 },
			{ "medium", 16 }, { "large", 18 }, { "x-large", 24 },
			{ "xx-large", 32 },
		};
		const char *v = (const char *)&a[1];
		size_t n;

		if (a->value_len == 7 && !strncmp(v, "smaller", 7)) {
			lws_fx_mul(&t, pfs, &lws_fx_83);
			lws_fx_div(&r, &t, &c_100);
			break;
		}
		if (a->value_len == 6 && !strncmp(v, "larger", 6)) {
			lws_fx_mul(&t, pfs, &lws_fx_120);
			lws_fx_div(&r, &t, &c_100);
			break;
		}
		for (n = 0; n < LWS_ARRAY_SIZE(ks); n++)
			if (a->value_len == strlen(ks[n].n) &&
			    !strncmp(v, ks[n].n, a->value_len)) {
				lws_fx_set(r, ks[n].px, 0);
				goto done;
			}
		return;
	}
	default:
		return;
	}

done:
	if (r.whole > 0 || (r.whole == 0 && r.frac > 0))
		ps->font_size = r;
}

const char *
lws_html_get_atr(lhp_pstack_t *ps, const char *aname, size_t aname_len)
{
	/* look for src= attribute */
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&ps->atr)) {
		const lhp_atr_t *at = lws_container_of(p,
						lhp_atr_t, list);
		const char *ats = (const char *)&at[1];

		if (at->name_len == aname_len && !strcmp(ats, aname))
			return ats + aname_len + 1;

	} lws_end_foreach_dll(p);

	return NULL;
}

const lcsp_atr_t *
lhp_resolve_var_color(lhp_ctx_t *ctx, const lcsp_atr_t *a)
{
	const char *n;
	size_t len;

	if (a->unit != LCSP_UNIT_STRING && a->unit != LCSP_UNIT_URL)
		return a;

	/* check if it is var(--name) */
	n = (const char *)&a[1];
	if (strncmp(n, "var(--", 6))
		return a;

	n += 4; /* skip var( */
	len = 0;
	while (n[len] && n[len] != ')')
		len++;

	/* lwsl_err("RESOLVE: '%.*s'\n", (int)len, n); */

	/* look it up in css_vars */
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->css_vars)) {
		lhp_css_var_t *v = lws_container_of(d, lhp_css_var_t, list);
		const char *vn = (const char *)&v[1];

		if (v->name_len == len && !strncmp(vn, n, len)) {
			/* found it */
			if (v->def && lws_dll2_get_head(&v->def->atrs)) {
				lcsp_atr_t *ra = lws_container_of(lws_dll2_get_head(&v->def->atrs), lcsp_atr_t, list);
				if (ra->unit == LCSP_UNIT_RGBA)
					return ra;
			}
			break;
		}
	} lws_end_foreach_dll(d);

	return a;
}

/*
 * Resolve the css for the element at the top of the parse stack: collect the
 * stanzas whose selectors match it (sorted by specificity, source order
 * breaking ties), parse its style="" attribute, compute its font size and
 * fill in the layout-related property lookups.  Ancestors were resolved when
 * they were on top, and keep their results until they close.
 */

static int
lws_css_cascade(lhp_ctx_t *ctx)
{
	lhp_pstack_t *parent = NULL, *ps = lws_container_of(
			lws_dll2_get_tail(&ctx->stack), lhp_pstack_t, list);
	const char *st;
	lws_dll2_t *d;

	/* the parent element is the nearest level above us with a tag */
	d = lws_dll2_get_prev(&ps->list);
	while (d) {
		parent = lws_container_of(d, lhp_pstack_t, list);
		if (!lws_dll2_is_empty(&parent->atr) || !lws_dll2_get_prev(d))
			break;
		d = lws_dll2_get_prev(d);
	}

	if (ps->css_resolved) {
		ctx->in_body = ps->in_body;
		return 0;
	}

	ps->in_body = parent ? parent->in_body : 0;

	if (lws_dll2_is_empty(&ps->atr)) {
		/*
		 * A level pushed for a tag we haven't parsed yet: nothing to
		 * match, and it must not be marked resolved or the real
		 * element gets no css when the tag and attributes arrive
		 */
		ctx->in_body = ps->in_body;
		ps->font_size = parent ? parent->font_size : ps->font_size;
		ps->hidden = parent ? parent->hidden : 0;

		return 0;
	}

	{
		lhp_atr_t *ta = lws_container_of(lws_dll2_get_head(&ps->atr),
						 lhp_atr_t, list);

		if (ta->name_len == 4 &&
		    !strncasecmp((const char *)&ta[1], "body", 4))
			ps->in_body = 1;

		/* which stanzas have a selector matching this element? */

		lws_start_foreach_dll(struct lws_dll2 *, q,
				      lws_dll2_get_head(&ctx->css)) {
			lcsp_stanza_t *stz = lws_container_of(q, lcsp_stanza_t,
							      list);
			uint32_t best = 0;
			int hit = 0;

			lws_start_foreach_dll(struct lws_dll2 *, z,
					      lws_dll2_get_head(&stz->names)) {
				lcsp_names_t *nm = lws_container_of(z,
							lcsp_names_t, list);
				const char *n = (const char *)&nm[1];

				if (lhp_sel_match(ps, n, n + nm->name_len)) {
					if (!hit || nm->specificity > best)
						best = nm->specificity;
					hit = 1;
				}
			} lws_end_foreach_dll(z);

			if (hit && lhp_add_match(ps, stz, best))
				return 1;
		} lws_end_foreach_dll(q);

		st = lws_html_get_atr(ps, "style", 5);
		if (st && *st && !ctx->await_css_done &&
		    lhp_parse_style_attr(ctx, ps, st))
			return 1;
	}

	ps->css_resolved = 1;
	ctx->in_body = ps->in_body;

	lhp_compute_font_size(ctx, ps, parent);

	/*
	 * ... fill layout-related CSS lookups into the element
	 * stack item... these are all pointers to the attribute
	 * not necessarily computed scalars.  Eg lws_csp_px() can be
	 * used later to resolve atr like 50% to pixel values.
	 */

	ps->css_position = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_POSITION);
	ps->css_width = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_WIDTH);
	ps->css_height = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_HEIGHT);
	ps->css_display = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_DISPLAY);

	/* display: none takes the whole subtree out of the layout */
	ps->hidden = (parent && parent->hidden) ||
		     (ps->css_display &&
		      ps->css_display->unit == LCSP_UNIT_NONE &&
		      ps->css_display->propval == LCSP_PROPVAL_NONE);

	ps->css_border_radius[0] = lhp_side_atr(ps, LCSP_PROP_BORDER_TOP_LEFT_RADIUS, LCSP_PROP_BORDER_RADIUS, 0, 1);
	ps->css_border_radius[1] = lhp_side_atr(ps, LCSP_PROP_BORDER_TOP_RIGHT_RADIUS, LCSP_PROP_BORDER_RADIUS, 1, 1);
	ps->css_border_radius[2] = lhp_side_atr(ps, LCSP_PROP_BORDER_BOTTOM_LEFT_RADIUS, LCSP_PROP_BORDER_RADIUS, 2, 1);
	ps->css_border_radius[3] = lhp_side_atr(ps, LCSP_PROP_BORDER_BOTTOM_RIGHT_RADIUS, LCSP_PROP_BORDER_RADIUS, 3, 1);

	ps->css_background_color = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BACKGROUND_COLOR);
	if (!ps->css_background_color &&
	    lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BACKGROUND)) {
		/* the colour part of the background shorthand, if any */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&ctx->active_atr)) {
			lcsp_atr_ptr_t *ap = lws_container_of(d, lcsp_atr_ptr_t,
							      list);

			if (ap->atr->unit == LCSP_UNIT_RGBA ||
			    (ap->atr->unit == LCSP_UNIT_STRING &&
			     !strncmp((const char *)&ap->atr[1], "var(--", 6)))
				ps->css_background_color = ap->atr;
		} lws_end_foreach_dll(d);
	}
	if (ps->css_background_color)
		ps->css_background_color = lhp_resolve_var_color(ctx, ps->css_background_color);

	ps->css_color = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_COLOR);
	if (ps->css_color)
		ps->css_color = lhp_resolve_var_color(ctx, ps->css_color);

	ps->css_pos[CCPAS_TOP] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_TOP);
	ps->css_pos[CCPAS_RIGHT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_RIGHT);
	ps->css_pos[CCPAS_BOTTOM] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BOTTOM);
	ps->css_pos[CCPAS_LEFT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_LEFT);

	ps->css_margin[CCPAS_TOP] = lhp_side_atr(ps, LCSP_PROP_MARGIN_TOP, LCSP_PROP_MARGIN, CCPAS_TOP, 0);
	ps->css_margin[CCPAS_RIGHT] = lhp_side_atr(ps, LCSP_PROP_MARGIN_RIGHT, LCSP_PROP_MARGIN, CCPAS_RIGHT, 0);
	ps->css_margin[CCPAS_BOTTOM] = lhp_side_atr(ps, LCSP_PROP_MARGIN_BOTTOM, LCSP_PROP_MARGIN, CCPAS_BOTTOM, 0);
	ps->css_margin[CCPAS_LEFT] = lhp_side_atr(ps, LCSP_PROP_MARGIN_LEFT, LCSP_PROP_MARGIN, CCPAS_LEFT, 0);

	ps->css_padding[CCPAS_TOP] = lhp_side_atr(ps, LCSP_PROP_PADDING_TOP, LCSP_PROP_PADDING, CCPAS_TOP, 0);
	ps->css_padding[CCPAS_RIGHT] = lhp_side_atr(ps, LCSP_PROP_PADDING_RIGHT, LCSP_PROP_PADDING, CCPAS_RIGHT, 0);
	ps->css_padding[CCPAS_BOTTOM] = lhp_side_atr(ps, LCSP_PROP_PADDING_BOTTOM, LCSP_PROP_PADDING, CCPAS_BOTTOM, 0);
	ps->css_padding[CCPAS_LEFT] = lhp_side_atr(ps, LCSP_PROP_PADDING_LEFT, LCSP_PROP_PADDING, CCPAS_LEFT, 0);

	return 0;
}

void
lws_lhp_destruct(lhp_ctx_t *ctx)
{
	if (ctx->base_url) {
		free((void *)ctx->base_url);
		ctx->base_url = NULL;
	}
	lws_dll2_foreach_safe(&ctx->stack, NULL, lhp_clean_stack);
	lws_dll2_owner_clear(&ctx->active_stanzas);
	lws_dll2_owner_clear(&ctx->active_atr);
	lws_dll2_owner_clear(&ctx->css_vars);
	lwsac_free(&ctx->propatrac);
	lwsac_free(&ctx->cascadeac);
	lwsac_free(&ctx->cssac);
}

void
lws_lhp_tag_dlo_id(lhp_ctx_t *ctx, lhp_pstack_t *ps, lws_dlo_t *dlo)
{
	const char *pname;

	/* Deal with ID matching */

	pname = lws_html_get_atr(ps, "id", 2);
	if (!pname)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(ctx->ids)) {
		lws_display_id_t *id = lws_container_of(d, lws_display_id_t, list);

		if (!strcmp(pname, id->id)) {
			dlo->id = id;
			id->exists = 1;
			lwsl_debug("%s: %s tagged\n", __func__, pname);
			return;
		}

	} lws_end_foreach_dll(d);
}

/*
 * The external stylesheet referenced by a <link> has been fully parsed: the
 * link is a void element, so close it now and carry on with the html after
 * it.  Otherwise its stack level is never popped and everything after it,
 * body included, is parsed as a descendant of <head>.
 */

static void
lhp_link_css_done(lhp_ctx_t *ctx)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);

	ctx->u.s = 0;
	ctx->tag = NULL;
	ctx->tag_len = 0;
	ctx->await_css_done = 0;
	ctx->finish_css = 0;
	ctx->npos = 0;

	if (lws_dll2_count(&ctx->stack) > 1 && !lws_dll2_is_empty(&ps->atr)) {
		lhp_atr_t *a = lws_container_of(lws_dll2_get_head(&ps->atr),
						lhp_atr_t, list);

		memcpy(ctx->buf, &a[1], a->name_len);
		ctx->npos = (int)a->name_len;
		ps->cb(ctx, LHPCB_ELEMENT_END);
		ctx->npos = 0;
		lhp_clean_level(ps);
		lws_css_cascade(ctx);
	}

	ctx->state = LHPS_OUTER;
}

lws_stateful_ret_t
lws_lhp_parse(lhp_ctx_t *ctx, const uint8_t **buf, size_t *len)
{
	lhp_pstack_t *ps1, *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
						  lhp_pstack_t, list);
	struct lws_context *cx = (struct lws_context *)ctx->user1;
	lws_dl_rend_t *drt = (lws_dl_rend_t *)ctx->user;
	lws_stateful_ret_t r;
	const uint8_t *rbuf;
	size_t rsize;
	lhp_atr_t *a;

	if (ctx->await_css_done && !ctx->is_css)
		return LWS_SRET_AWAIT_RETRY;

	assert(drt);

	if (!*len && ctx->is_css && ctx->await_css_done && ctx->finish_css) {
		lhp_link_css_done(ctx);
		return LWS_SRET_AWAIT_RETRY;
	}

	while (*len) {
		uint8_t c = *(*buf)++;
		int is_term = 0;

		(*len)--;

		if (ctx->state == LHPS_DO_START_ELEM) {
			/* we are retrying the inner callback */
			(*len)++;
			(*buf)--;
		}

	//	lwsl_notice("%s: %d, '%c', %02X\n", __func__, ctx->state, c, c);

		switch (ctx->state) {

		case LHPS_INIT:

			/* default css injection first, then... */

			ctx->state = LCSPS_CSS_OUTER;
			ctx->u.f.default_css = 1;
			/*
			 * recurse (there's no stack usage to speak of) to
			 * do the default css parse first,  CSS doesn't have a
			 * way to recurse further.
			 */
			rbuf = (const uint8_t *)default_css;
			rsize = strlen(default_css);
			r = lws_lhp_parse(ctx, &rbuf, &rsize);
			if (r & LWS_SRET_FATAL) {
				lwsl_err("%s: css parse fail\n", __func__);
				return r;
			}
			ctx->u.f.default_css = 0;
			ctx->npos = 0;
			ctx->state = LHPS_OUTER;

			/* fallthru */

		case LHPS_OUTER:
			switch (c) {
			case '<':
				/*
				 * Flush pending text while the element it
				 * belongs to is still at the top of the stack,
				 * before we push the level for the next tag
				 */
				if (ctx->npos) {
					if (ctx->in_body &&
					    (ctx->npos != 1 || ctx->buf[0] != ' ')) {
						lws_css_cascade(ctx);
						ps->cb(ctx, LHPCB_CONTENT);
					}
					ctx->npos = 0;
				}

				ctx->u.s = 0;
				ctx->u.f.first = 1;

				ctx->tag = NULL;
				ctx->tag_len = 0;

				ctx->state = LHPS_TAG;

				if (lws_dll2_count(&ctx->stack) == LHP_MAX_ELEMS_NEST /* sanity */) {
					lwsl_err("%s: MAX_ELEMS_NEST\n", __func__);
					ps->cb(ctx, LHPCB_FAILED);
					return LWS_SRET_FATAL;

				}

				ps1 = lws_zalloc(sizeof(*ps1), __func__);
				if (!ps1)
					goto oom;

				/* inherit user and cb to start with */
				ps1->user	= ps->user;
				ps1->cb		= ps->cb;
				lws_dll2_owner_clear(&ps1->atr);
				lws_dll2_add_tail(&ps1->list, &ctx->stack);
				ps		= ps1;
				break;

			case '&':
				if (ctx->npos) {
					if (ctx->in_body &&
					    (ctx->npos != 1 || ctx->buf[0] != ' ')) {
						lws_css_cascade(ctx);
						ps->cb(ctx, LHPCB_CONTENT);
					}
					ctx->npos = 0;
				}
				ctx->saved_state = LHPS_OUTER;
				ctx->entity_start = 0;
				ctx->state = LHPS_AMP;
				ctx->temp_count = 0;
				continue;

			case '\t':
			case '\n':
				c = ' ';
				/* fallthru */
			default:
				if (c != ' ' || !ctx->npos ||
				    ctx->buf[ctx->npos - 1] != ' ')
					ctx->buf[ctx->npos++] = (char)c;
				break;
			}

			if (ctx->npos &&
			    (ctx->state != LHPS_OUTER ||
			     ctx->npos >= LHP_STRING_CHUNK - 4)) {
				if (ctx->in_body && (ctx->npos != 1 || ctx->buf[0] != ' ')) {
					lws_css_cascade(ctx);
					ps->cb(ctx, LHPCB_CONTENT);
				}
				ctx->npos = 0;
			}
			break;

		case LHPS_TAG:
			if (c == '!' && ctx->u.f.first) {
				ctx->state = LHPS_SCOMMENT1;
				ctx->u.f.first = 0;
				break;
			}

			if (c == '/' && ctx->u.f.first) {
				/* remove the level we just prepared for this */
				lhp_clean_level(ps);
				ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
						      lhp_pstack_t, list);
				ctx->u.f.closing = 1;
				ctx->u.f.first = 0;
				break;
			}
			ctx->u.f.first = 0;

			/* it implies the end of the tag name */

			if (hspace(c) || c == '/' || c == '>') {
				if (!ctx->u.f.tag_used && ctx->npos && !ctx->u.f.closing) {
					a = lhp_atr_new(ctx, (size_t)ctx->npos, 0);
					if (!a)
						goto oom;
					ctx->tag = (const char *)&a[1];
					ctx->tag_len = a->name_len;

					ctx->u.f.tag_used = 1;

					if (ctx->tag_len == 8 &&
					    !strncasecmp(ctx->buf, "!doctype", 8))
						ctx->u.f.doctype = 1;
				}

				if (c != '/' && c != '>') {

					/* after that, there may be attributes */
					ctx->state = LHPS_ATTRIB;
					break;
				}

				/* <style> trapdoor into inline css parsing */

				if (ctx->u.f.tag_used && c == '>' &&
				    ctx->tag_len == 5 &&
				    !strncasecmp(ctx->buf, "style", 5)) {
					ctx->npos = 5;

					ps->cb(ctx, LHPCB_ELEMENT_START);
					ctx->npos = 0;
					ctx->state = LCSPS_CSS_OUTER;
					break;
				}

				/* <script> trapdoor into skipping */

				if (ctx->u.f.tag_used && c == '>' &&
				    ctx->tag_len == 6 &&
				    !strncasecmp(ctx->buf, "script", 6) &&
				    !ctx->u.f.closing) {
					/*
					 * We don't want to parse script as
					 * text.
					 */
					ctx->npos = 0;
					ctx->state = LHPS_SCRIPT;
					break;
				}
			}

			if (ctx->u.f.void_element && c == '/') {
				/* we had something like <br and then we see a
				 * closing / */
				ctx->u.f.closing = 1;
				break;
			}

			if (c == '>') {
				ctx->state = LHPS_DO_START_ELEM;
				goto elem_start;
			}

			/* tag names may only contain 0–9, a–z, and A–Z */

			if ( //ctx->closing ||
			     c < '0' ||
			    (c > '9' && c < 'A') ||
			    (c > 'Z' && c < 'a') ||
			     c > 'z') {
				ctx->state = LHPS_BAD_TAG;
				break;
			}

			/* collect the tag name */

			if (!hspace(c))
				ctx->buf[ctx->npos++] = (char)c;
			if (ctx->npos == 32) { /* sanity */
				ctx->npos = 0;
				ctx->state = LHPS_BAD_TAG;
				break;
			}

			break;
		case LHPS_BAD_TAG:
			/* just sit it out until the element end */
			if (c != '>')
				break;

			ctx->state = LHPS_DO_START_ELEM;

			/* fallthru */

		case LHPS_DO_START_ELEM:
elem_start:
			/* present the tag in buf, if any */
			if (ctx->tag_len)
				memcpy(ctx->buf, ctx->tag, ctx->tag_len);
			ctx->buf[ctx->tag_len] = '\0';
			ctx->npos = (int)ctx->tag_len;

			if (!ctx->u.f.closing || ctx->u.f.void_element) {
				const char *pname = NULL, *rel = NULL;
				const struct lcsp_atr *aa = NULL;
				lws_dlo_ss_create_info_t i;
				lws_dlo_image_t u;
				lhp_pstack_t *psb;
				lws_dlo_t *dlo;
				lws_box_t box;
				char url[LHP_URL_LEN];

				memset(&i, 0, sizeof(i));
				lws_css_cascade(ctx);

				/*
				 * body gets a surface-sized rect to draw on;
				 * only once, since we come back through here
				 * when retrying after waiting for the dims of
				 * its background image
				 */
				if (ctx->npos == 4 && !strncmp(ctx->buf, "body", 4) &&
				    !ps->dlo) {
					lws_display_colour_t col =
						LWSDC_RGBA(255, 255, 255, 255);

					if (ps->css_background_color &&
					    ps->css_background_color->unit == LCSP_UNIT_RGBA)
						col = ps->css_background_color->u.rgba;

					ps->drt.w = ctx->ic.wh_px[LWS_LHPREF_WIDTH];
					if (ps->css_width &&
					    ps->css_width->propval != LCSP_PROPVAL_AUTO// &&
					    //lws_fx_comp(lws_csp_px(ps->css_width, ps), &box.w) < 0
					    )
						ps->drt.w = *lws_csp_px(ps->css_width, ps);

					ps->drt.h = ctx->ic.wh_px[LWS_LHPREF_HEIGHT];
					if (ps->css_height &&
					    ps->css_height->propval != LCSP_PROPVAL_AUTO) //&&
					    //lws_fx_comp(lws_csp_px(ps->css_height, ps),
						//		   &ps->drt.h) < 0)
						ps->drt.h = *lws_csp_px(ps->css_height, ps);

					/* put a default white body background behind everything */

					lws_fx_set(box.x, 0, 0);
					lws_fx_set(box.y, 0, 0);
					box.w = ps->drt.w;
					box.h = ps->drt.h;

					ps->dlo = (lws_dlo_t *)lws_display_dlo_rect_new(
							drt->dl, NULL, &box, 0,
							col);
					if (!ps->dlo)
						goto oom;

					ps->dlo->flag_toplevel = 1;

					lhp_set_dlo_padding_margin(ps, ps->dlo);
				}

				/* it's a link? */

				if (ctx->npos == 4 && !strncmp(ctx->buf, "link", 4)) {
					pname = lws_html_get_atr(ps, "href", 4);
					rel = lws_html_get_atr(ps, "rel", 3);

					if (!rel || strncmp(rel, "stylesheet", 10))
						goto issue_elem_start;
				}

				/* it's an img? */

				if (ctx->npos == 3 && !strncmp(ctx->buf, "img", 3))
					pname = lws_html_get_atr(ps, "src", 3);
				else {
					aa = lws_css_cascade_get_prop_atr(ctx,
						LCSP_PROP_BACKGROUND_IMAGE);

					/*
					 * Only string and url atrs have a
					 * NUL-terminated payload after the
					 * atr... eg, "background-image: none"
					 * is a well-known propval atr with
					 * nothing at all after it
					 */

					if (aa && aa->value_len &&
					    (aa->unit == LCSP_UNIT_STRING ||
					     aa->unit == LCSP_UNIT_URL))
						pname = (const char *)(aa + 1);
				}

				/*
				 * Without a base url we can't resolve the
				 * asset URL at all; it's not a parse error,
				 * and the element still exists for layout
				 */

				if (!pname || !ctx->base_url)
					goto issue_elem_start;

				/* we should be in an <img tag or
				 * something with a background image */

				if (lws_http_rel_to_url(url, sizeof(url),
							ctx->base_url, pname))
					goto issue_elem_start;

				/* decode percent-encoding in the URL */
				{
					char temp[LHP_URL_LEN];
					lws_strncpy(temp, url, sizeof(temp));
					lws_urldecode(url, temp, sizeof(url) - 1);
				}

				psb = lws_css_get_parent_block(ctx, ps);
				//if (!psb)
				//	lwsl_err("%s: NULL psb\n", __func__);

				lws_fx_set(box.x, 0, 0);
				lws_fx_set(box.y, 0, 0);
				lws_fx_set(box.w, 0, 0);
				lws_fx_set(box.h, 0, 0);

				if (psb) {
					box.x = psb->curx;
					box.y = psb->cury;
					lws_fx_add(&box.x, &box.x,
						lws_csp_px(psb->css_margin[CCPAS_LEFT], psb));
					lws_fx_add(&box.y, &box.y,
						lws_csp_px(psb->css_margin[CCPAS_TOP], psb));
				}

				if (ps->css_width &&
					lws_fx_comp(lws_csp_px(ps->css_width, ps), &box.w) > 0)
					box.w = *lws_csp_px(ps->css_width, ps);
				if (ps->css_height &&
					lws_fx_comp(lws_csp_px(ps->css_height, ps), &box.h) > 0)
					box.h = *lws_csp_px(ps->css_height, ps);

				memset(&u, 0, sizeof(u));

				if (!cx)
					/*
					 * Standalone parse with no lws_context
					 * (no Secure Streams backing): there
					 * is no way to look for or fetch image
					 * assets, leave the element empty
					 */
					goto issue_elem_start;

				if (lws_dlo_ss_find(cx, url, &u)) {

					i.cx			= cx;
					i.dl			= drt->dl;
					if (psb)
						i.dlo_parent	= psb->dlo;
					i.box			= &box;
					i.on_rx			= ctx->ssevcb;
					i.on_rx_sul		= ctx->ssevsul;
					i.url			= url;
					i.lhp			= ctx;
					i.u			= &u;
					i.window		= ctx->window;

					lwsl_cx_info(cx, "not already in progress: %s", url);
					if (lws_dlo_ss_create(&i, &dlo)) {
						/*
						 * we can't get it: the element
						 * is laid out without its image
						 */
						lwsl_cx_warn(cx, "Can't get %s", url);
						goto issue_elem_start;
					} else {
						lwsl_cx_info(cx, "Created SS for %s\n", url);
						if (ctx->npos == 3 && !strncmp(ctx->buf, "img", 3))
							ps->dlo = dlo;
					}
				} else {
					// lwsl_cx_warn(cx, "Found in-progress %s\n", url);
					/* an in-progress asset that isn't an
					 * image (eg, a stylesheet) has no dlo */
					if (u.u.dlo_png && ctx->npos == 3 &&
					    !strncmp(ctx->buf, "img", 3))
						ps->dlo = &u.u.dlo_png->dlo;
				}

				if (ctx->npos == 4 && !strncmp(ctx->buf, "link", 4)) {
					ps->cb(ctx, LHPCB_ELEMENT_START);
					ctx->npos = 0;
					ctx->state = LCSPS_CSS_OUTER;
					ctx->await_css_done = 1;

					return LWS_SRET_AWAIT_RETRY;
				}

				/*
				 * It's on its way to some extent and *u set...
				 *
				 * ... unless it isn't: a url that isn't an
				 * image asset (eg, a .css given as an
				 * element's src=) can be accepted for
				 * fetching without producing any image dlo
				 * for us to describe.  Nothing more we can do
				 * with it here.
				 */

				if (!u.u.dlo_png)
					goto check_closing;

				/*
				 * If he has given explicit width and height
				 * for the image, no need to wait for them
				 */

				if (lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_HEIGHT), ps)->whole &&
						lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_WIDTH), ps)->whole) {
					lwsl_cx_info(cx, "Have width and height %d x %d",
							(int)lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
								LCSP_PROP_WIDTH), ps)->whole,
							(int)lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
								LCSP_PROP_HEIGHT), ps)->whole);

					u.u.dlo_png->dlo.box.w.whole = lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_WIDTH), ps)->whole;
					u.u.dlo_png->dlo.box.h.whole = lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_HEIGHT), ps)->whole;
					goto issue_elem_start;
				}

				{
					const char *p = lws_html_get_atr(ps, "width", 5);
					if (p)
						u.u.dlo_png->dlo.box.w.whole = atoi(p);
					p = lws_html_get_atr(ps, "height", 6);
					if (p)
						u.u.dlo_png->dlo.box.h.whole = atoi(p);
				}

				if (u.u.dlo_png->dlo.box.w.whole &&
				    u.u.dlo_png->dlo.box.h.whole)
					goto issue_elem_start;

				/*
				 * Do we have the dimensions?  If not, bail
				 * from here and await a retry (maybe caused by
				 * data coming for the image)
				 */

				if (!lws_dlo_image_width(&u) ||
				    !lws_dlo_image_height(&u)) {
					/*
					 * ps->dlo is only set for body and
					 * img... for, eg, a div with a css
					 * background-image, there's nowhere to
					 * keep the retry budget, so don't
					 * spin waiting for the dimensions
					 */
					if (ps->dlo && ++ps->dlo->budget < 8) {
						lwsl_warn("%s: exiting with AWAIT_RETRY due to no dims\n", __func__);
						return LWS_SRET_AWAIT_RETRY;
					}
					lwsl_err("%s: ignoring no dims\n", __func__);
				}

				u.u.dlo_png->dlo.box.w.whole = (int32_t)lws_dlo_image_width(&u);
				u.u.dlo_png->dlo.box.h.whole = (int32_t)lws_dlo_image_height(&u);

				/* did it fail to retreive it? */

				if (u.u.dlo_png->dlo.box.w.whole < 0) {
					lwsl_notice("%s: understanding image failed\n", __func__);
					goto check_closing;
				}

				/*
				 * ... we needed it, we have it... we set it...
				 * ... let's go
				 */

issue_elem_start:
				r = ps->cb(ctx, LHPCB_ELEMENT_START);
				ctx->npos = 0;
				if (r) {
					lwsl_notice("%s: inner cb returned %d\n", __func__, r);
					return r;
				}
			}

check_closing:
			if (ctx->u.f.closing || ctx->u.f.void_element){
				if (lws_dll2_count(&ctx->stack) == 1) {
					lwsl_err("%s: element close mismatch\n", __func__);
					ps->cb(ctx, LHPCB_FAILED);
					return LWS_SRET_FATAL;
				}
			if(!lws_dll2_is_empty(&ps->atr)) {
				a = lws_container_of(
					lws_dll2_get_head(&ps->atr),
					lhp_atr_t, list);
				memcpy(ctx->buf, &a[1], a->name_len);
				ctx->npos = (int)a->name_len;
			}
				ps->cb(ctx, LHPCB_ELEMENT_END);
				ctx->npos = 0;
				/* remove the start level */
				lhp_clean_level(ps);
				lws_css_cascade(ctx);
				ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
						      lhp_pstack_t, list);
			}
			ctx->npos = 0;
			ctx->state = LHPS_OUTER;

			/*
			 * <script ...> and <style ...> with attributes came
			 * through here rather than the bare-tag trapdoors:
			 * their content is not html either
			 */
			if (!ctx->u.f.closing && !ctx->u.f.void_element &&
			    !lws_dll2_is_empty(&ps->atr)) {
				lhp_atr_t *ta = lws_container_of(
						lws_dll2_get_head(&ps->atr),
						lhp_atr_t, list);
				const char *tn = (const char *)&ta[1];

				if (ta->name_len == 6 &&
				    !strncasecmp(tn, "script", 6))
					ctx->state = LHPS_SCRIPT;
				else if (ta->name_len == 5 &&
					 !strncasecmp(tn, "style", 5))
					ctx->state = LCSPS_CSS_OUTER;
			}
			break;

		case LHPS_ATTRIB:

			if (ctx->u.f.doctype && c == '\"') {
				ctx->u.f.inq = ctx->u.f.inq ^ 1u;
				if (ctx->u.f.inq)
					break;
			}

			if ((ctx->u.f.inq || !hspace(c)) &&
			    (c != '/' || ctx->u.f.inq) && c != '>') {
				/*
				 * sanity: check before the write, and with
				 * >=, since npos can have been advanced by
				 * more than one by an entity expansion
				 */
				if (ctx->npos >= LHP_STRING_CHUNK) {
					lwsl_err("%s: string chunk\n", __func__);
					ps->cb(ctx, LHPCB_FAILED);
					return LWS_SRET_FATAL;
				}
				/* collect the attrib name */
				ctx->buf[ctx->npos++] = (char)c;
				if (c == '=') {
					ctx->nl_temp = ctx->npos - 1;
					ctx->state = LHPS_ATTRIB_VAL;
				}
				break;
			}
			if (c == '/') {
				ctx->u.f.closing = 1;
				break;
			}

			if (ctx->npos &&
			    !lhp_atr_new(ctx, (size_t)ctx->npos, 0))
				goto oom;

			if (c == '>') {
				ctx->state = LHPS_DO_START_ELEM;
				goto elem_start;
			}
			break;

		case LHPS_ATTRIB_VAL:

			if (/*ctx->u.f.doctype && */c == '\"') {
				ctx->u.f.inq = ctx->u.f.inq ^ 1u;
				if (ctx->u.f.inq)
					break;
			}

			if (c == '&') {
				ctx->saved_state = LHPS_ATTRIB_VAL;
				ctx->entity_start = ctx->npos;
				ctx->temp_count = 0;
				ctx->state = LHPS_AMP;
				break;
			}

			if ((ctx->u.f.inq || !hspace(c)) &&
			    c != '>' && c != '\'' && c != '\"') {
				/*
				 * sanity: check before the write, and with
				 * >=, since npos can have been advanced by
				 * more than one by an entity expansion
				 */
				if (ctx->npos >= LHP_STRING_CHUNK) {
					lwsl_err("%s: string chunk 2\n", __func__);
					ps->cb(ctx, LHPCB_FAILED);
					return LWS_SRET_FATAL;
				}
				/* collect the attrib value */
				ctx->buf[ctx->npos++] = (char)c;
				break;
			}
			if (c == '/') {
				ctx->u.f.closing = 1;
				break;
			}

			if (c == '\'' || c == '\"')
				break;

			if (ctx->u.f.inq)
				break;

			if (ctx->npos) {
				/*
				 * nl_temp is where the '=' sits in buf, so
				 * npos must be beyond it for the value length
				 * to be derivable.  Entity handling can reset
				 * npos out from under nl_temp; in that case
				 * just drop the attribute rather than
				 * underflow value_len.
				 */
				if (ctx->npos > ctx->nl_temp) {
					ctx->buf[ctx->npos] = '\0';
					if (!lhp_atr_new(ctx, (size_t)ctx->nl_temp,
							 (size_t)(ctx->npos -
								  ctx->nl_temp - 1)))
						goto oom;
				}
				ctx->state = LHPS_ATTRIB;
				ctx->npos = 0;
				if (c != '>')
					break;
			}

			if (c == '>') {
				ctx->state = LHPS_DO_START_ELEM;
				goto elem_start;
			}

			break;

		case LHPS_AMP:
			/* the character after the & */
			if (c == '#') {
				ctx->state = LHPS_AMPHASH;
				ctx->temp = 0;
				break;
			}

			if ((c >= 'a' && c <= 'z') ||
			    (c >= 'A' && c <= 'Z') ||
			    (c >= '0' && c <= '9')) {
				if (ctx->npos < (int)sizeof(ctx->buf) - 1)
					ctx->buf[ctx->npos++] = (char)c;
				break;
			}

			if (c == ';') {
				size_t n;

				ctx->buf[ctx->npos] = '\0';
				for (n = 0; n < LWS_ARRAY_SIZE(entities); n++) {
					if (!strcmp(ctx->buf + ctx->entity_start, entities[n].name)) {
						ctx->temp = entities[n].val;
						ctx->npos = ctx->entity_start;
						lhp_uni_emit(ctx);
						ctx->state = ctx->saved_state;
						goto done_amp;
					}
				}

				if (ctx->npos + 2 < LHP_STRING_CHUNK) {
					memmove(ctx->buf + ctx->entity_start + 1,
						ctx->buf + ctx->entity_start,
						(size_t)(ctx->npos - ctx->entity_start));
					ctx->buf[ctx->entity_start] = '&';
					ctx->buf[ctx->npos + 1] = ';';
					ctx->npos += 2;
					ctx->state = ctx->saved_state;
				} else {
					/*
					 * We're dumping what we collected...
					 * nl_temp indexes into it, so it has
					 * to go too or the attribute lengths
					 * derived from it are garbage
					 */
					ctx->npos = 0;
					ctx->nl_temp = 0;
					ctx->state = ctx->saved_state;
				}
				break;
			}

			if (ctx->npos + 1 < LHP_STRING_CHUNK) {
				memmove(ctx->buf + ctx->entity_start + 1,
					ctx->buf + ctx->entity_start,
					(size_t)(ctx->npos - ctx->entity_start));
				ctx->buf[ctx->entity_start] = '&';
				ctx->npos++;
				(*len)++;
				(*buf)--;
				ctx->state = ctx->saved_state;
			} else {
				/* as above, nl_temp indexes into what we are
				 * dropping, it can't survive it */
				ctx->npos = 0;
				ctx->nl_temp = 0;
				ctx->state = ctx->saved_state;
			}
done_amp:
			break;
		case LHPS_AMPHASH:
			/*
			 * This is either decimal or hex unicode like
			 * &#1234; or &#xfc16;
			 */
			if (c == 'x' || c == 'X') {
				ctx->state = LHPS_AMPHASH_HEX;
				break;
			}

			if (ctx->temp_count++ > 32 /* sanity */) {
				ctx->state = ctx->saved_state;
				break;
			}
			if (c == ';') {
				if (ctx->npos >= LHP_STRING_CHUNK - 5) {
					if (ctx->saved_state == LHPS_OUTER && ctx->in_body) {
						ps->cb(ctx, LHPCB_CONTENT);
						ctx->npos = 0;
					} else {
						if (ctx->saved_state != LHPS_OUTER)
							lwsl_err("%s: string chunk\n", __func__);
						ps->cb(ctx, LHPCB_FAILED);
						return LWS_SRET_FATAL;
					}
				}
				ctx->npos = ctx->entity_start;
				lhp_uni_emit(ctx);
				ctx->state = ctx->saved_state;
				break;
			}

			if (c >= '0' && c <= '9') {
				/*
				 * The digit count limit above doesn't bound
				 * the value; stop accumulating once we are
				 * already outside unicode range, so we can't
				 * overflow (the out-of-range value is still
				 * handled by lhp_uni_emit())
				 */
				if (ctx->temp <= 0x10ffff)
					ctx->temp = (ctx->temp * 10) +
						    (uint32_t)(c - '0');
			} else
				ctx->state = ctx->saved_state;

			break;

		case LHPS_AMPHASH_HEX:
			if (c == ';') {
				if (ctx->npos >= LHP_STRING_CHUNK - 5) {
					if (ctx->saved_state == LHPS_OUTER && ctx->in_body) {
						ps->cb(ctx, LHPCB_CONTENT);
						ctx->npos = 0;
					} else {
						if (ctx->saved_state != LHPS_OUTER)
							lwsl_err("%s: string chunk\n", __func__);
						ps->cb(ctx, LHPCB_FAILED);
						return LWS_SRET_FATAL;
					}
				}
				ctx->npos = ctx->entity_start;
				lhp_uni_emit(ctx);
				ctx->state = ctx->saved_state;
				break;
			}

			if (ctx->temp_count++ > 8 /* sanity */) {
				ctx->state = ctx->saved_state;
				break;
			}

			/*
			 * As for the decimal case, the digit count limit
			 * above doesn't bound the value; stop accumulating
			 * once we are already outside unicode range
			 */

			if (c >= '0' && c <= '9') {
				if (ctx->temp <= 0x10ffff)
					ctx->temp = (ctx->temp << 4) +
						    (uint32_t)(c - '0');
				break;
			}

			if (c >= 'A' && c <= 'F') {
				if (ctx->temp <= 0x10ffff)
					ctx->temp = (ctx->temp << 4) +
						    (uint32_t)(c - 'A') + 10;
				break;
			}

			if (c >= 'a' && c <= 'f') {
				if (ctx->temp <= 0x10ffff)
					ctx->temp = (ctx->temp << 4) +
						    (uint32_t)(c - 'a') + 10;
				break;
			}

			ctx->state = ctx->saved_state;
			break;
		case LHPS_SCOMMENT1: /* we have <! */
			if (c == '-') {
				ctx->state = LHPS_SCOMMENT2;
				break;
			}
			/* !doctype is an element tag */
			ctx->buf[ctx->npos++] = '!';
			ctx->buf[ctx->npos++] = (char)c;
			ctx->state = LHPS_TAG;
			break;
		case LHPS_SCOMMENT2: /* we have <!- */
			if (c == '-') {
				ctx->state = LHPS_COMMENT;
				break;
			}
			/* it can't be an element tag with - in it */
			ctx->state = LHPS_BAD_TAG;
			break;
		case LHPS_COMMENT:
			/* sanity */
			if (ctx->npos >= LHP_STRING_CHUNK - 4) {
				ps->cb(ctx, LHPCB_COMMENT);
				ctx->npos = 0;
			}
			if (c == '-') {
				ctx->state = LHPS_ECOMMENT1;
				break;
			}

			/* collect the comment */
			ctx->buf[ctx->npos++] = (char)c;
			/* sanity */
			if (ctx->npos >= LHP_STRING_CHUNK - 4) {
				ps->cb(ctx, LHPCB_COMMENT);
				ctx->npos = 0;
			}

			break;
		case LHPS_ECOMMENT1:
			if (c == '-') {
				ctx->state = LHPS_ECOMMENT2;
				break;
			}
			ctx->buf[ctx->npos++] = '-';
			ctx->buf[ctx->npos++] = (char)c;
			ctx->state = LHPS_COMMENT;
			break;
		case LHPS_ECOMMENT2:
			if (c == '>') {
				if (ctx->npos) {
					ps->cb(ctx, LHPCB_COMMENT);
					ctx->npos = 0;
				}
				/*
				 * The level pushed at the '<' was for an
				 * element; a comment isn't one, so it must
				 * not stay on the stack as an empty ancestor
				 * of everything after it
				 */
				if (lws_dll2_count(&ctx->stack) > 1 &&
				    lws_dll2_is_empty(&ps->atr)) {
					lhp_clean_level(ps);
					ps = lws_container_of(
						lws_dll2_get_tail(&ctx->stack),
						lhp_pstack_t, list);
					lws_css_cascade(ctx);
				}
				ctx->state = LHPS_OUTER;
				break;
			}
			ctx->buf[ctx->npos++] = '-';
			ctx->buf[ctx->npos++] = '-';
			ctx->buf[ctx->npos++] = (char)c;
			ctx->state = LHPS_COMMENT;
			break;

			/*
			 * CSS parser
			 */

		case LCSPS_CSS_OUTER:
			/* comments... */
			ctx->state_css_comm = LCSPS_CSS_OUTER;

			if (c == '<') {
				ctx->state = LCSPS_CSS_OUTER_TAG1;
				ctx->u.f.first = 1;
				break;
			}
			if (c == '/') {
				ctx->state = LCSPS_CCOM_S1;
				break;
			}

			if (c == '{') { /* open stanza */

				while (ctx->npos && ctx->buf[ctx->npos - 1] == ' ')
					ctx->npos--;
				ctx->buf[ctx->npos] = '\0';

				if (ctx->npos && ctx->buf[0] == '@') {
					/*
					 * @media we can evaluate: parse the
					 * rules inside as if toplevel.  Any
					 * other @-rule block (@font-face,
					 * @keyframes, print media...) must
					 * not leak its rules into the page.
					 */
					if (ctx->npos > 6 &&
					    !strncmp(ctx->buf, "@media", 6) &&
					    lhp_media_query_true(ctx,
							ctx->buf + 6,
							ctx->buf + ctx->npos)) {
						if (ctx->css_block_depth < 255)
							ctx->css_block_depth++;
					} else {
						ctx->css_skip_depth = 1;
						ctx->state = LCSPS_CSS_SKIP_BLOCK;
					}
					ctx->npos = 0;
					break;
				}

				/* create the stanza object */

				ctx->stz = lwsac_use_zero(&ctx->cssac,
							  sizeof(*ctx->stz),
							  LHP_AC_GRANULE);
				if (!ctx->stz)
					goto oom;

				/* attach the selectors to it */

				if (lhp_css_add_names(ctx, ctx->buf,
						      (size_t)ctx->npos))
					goto oom;

				/* list this stanza in our lhp context CSS */

				lws_dll2_add_tail(&ctx->stz->list, &ctx->css);

				ctx->npos = 0;
				ctx->state = LCSPS_CSS_STANZA;
				ctx->cssval_state = 0;
				ctx->css_state = 0;
				ctx->u.f.arg = 0;
				ctx->u.f.integer = 0;
				ctx->u.f.color = 0;
				break;
			}

			if (c == '}') {
				/* closing an @media block we parsed inline */
				if (ctx->css_block_depth)
					ctx->css_block_depth--;
				ctx->npos = 0;
				break;
			}

			if (c == ';') {
				/* blockless @-rule, eg @import, @charset */
				ctx->npos = 0;
				break;
			}

			/* otherwise let's collect the selector text, with
			 * whitespace collapsed to single spaces */

			if (ctx->npos >= LHP_STRING_CHUNK) {
				lwsl_err("%s: css lhs too long\n", __func__);
				return LWS_SRET_FATAL;
			}

			if (hspace(c)) {
				if (ctx->npos && ctx->buf[ctx->npos - 1] != ' ')
					ctx->buf[ctx->npos++] = ' ';
				break;
			}

			ctx->buf[ctx->npos++] = (char)c;
			break;

		case LCSPS_CSS_SKIP_BLOCK:
			/* balance braces until the @-rule block ends */
			if (c == '{' && ctx->css_skip_depth < 255)
				ctx->css_skip_depth++;
			if (c == '}' && !--ctx->css_skip_depth)
				ctx->state = LCSPS_CSS_OUTER;
			break;

		case LCSPS_CSS_STANZA:
			ctx->state_css_comm = LCSPS_CSS_STANZA;
			if (c == '}') {
				ctx->state = LCSPS_CSS_OUTER;

				if (ctx->u.f.infunc) {
					ctx->u.f.infunc = 0;
					ctx->npos = 0;
					ctx->u.f.arg = 0;
					ctx->css_state = 0;
					ctx->cssval_state = 0;
					break;
				}

				if (ctx->u.f.color) {
					lcsp_append_cssval_color(ctx);
					ctx->npos = 0;
					ctx->u.f.arg = 0;
					break;
				}
				if (ctx->u.f.integer) {/* x: 123} */
					if (lcsp_append_cssval_int(ctx))
						goto oom;

					ctx->u.f.integer = 0;
					ctx->npos = 0;
					ctx->u.f.arg = 0;
					break;
				}
				if (ctx->u.f.arg && lcsp_finish_cssval_keyword(ctx))
					goto oom;

				ctx->u.f.arg = 0;
				ctx->css_state = 0;
				ctx->cssval_state = 0;
				ctx->npos = 0;
				break;
			}
			if (c == '/') {
				ctx->state = LCSPS_CCOM_S1;
				break;
			}

			if (ctx->u.f.arg) {
				/* we're on the value side of prop: value */

				/*
				 * name( ... ) values: collect to the matching
				 * ')' (this may span input chunks) and then
				 * interpret the whole thing.  A ';' or '}'
				 * before that means a broken value: drop it.
				 */

				if (ctx->u.f.infunc && c != ';' && c != '}') {
					if (ctx->npos >= LHP_STRING_CHUNK) {
						lwsl_err("%s: func too long\n", __func__);
						goto oom;
					}
					ctx->buf[ctx->npos++] = (char)c;
					if (c == '"' || c == '\'')
						ctx->u.f.inq = ctx->u.f.inq ^ 1u;
					else if (!ctx->u.f.inq) {
						if (c == '(')
							ctx->temp_count++;
						if (c == ')' && !--ctx->temp_count) {
							ctx->u.f.infunc = 0;
							if (lcsp_func_value(ctx))
								goto oom;
							ctx->npos = 0;
							ctx->cssval_state = 0;
						}
					}
					break;
				}

				if (c == ';') {
					/* end of this declaration: restart with
					 * whatever is after the ';' */
					ctx->css_state = 0;
					ctx->u.f.arg = 0;

					if (ctx->u.f.infunc) {
						ctx->u.f.infunc = 0;
						ctx->npos = 0;
						ctx->cssval_state = 0;
						break;
					}

					if (ctx->u.f.color) {
						lcsp_append_cssval_color(ctx);
						ctx->npos = 0;
						break;
					}

					if (ctx->u.f.integer) { /* x: 123; */
						if (lcsp_append_cssval_int(ctx))
							goto oom;
						ctx->u.f.integer = 0;
						ctx->npos = 0;
						break;
					}

					if (lcsp_finish_cssval_keyword(ctx))
						goto oom;
					ctx->npos = 0;
					break;
				}

				if (ctx->u.f.color &&
					((c >= '0' && c <= '9') ||
					(c >= 'a' && c <= 'f') ||
					(c >= 'A' && c <= 'F'))) {
					/*
					 * #rrggbbaa is the longest form we
					 * understand; don't shift past the
					 * end of temp for longer garbage
					 */
					if (ctx->temp_count < 8)
						ctx->temp = (ctx->temp << 4) |
							(uint32_t)((c <= '9') ? c - '0' :
								(c >= 'a') ? 10 + (c - 'a') :
									10 + (c - 'A'));
					if (ctx->temp_count < 9)
						/* 9 == "too long", no valid
						 * length matches it */
						ctx->temp_count++;
					break;
				}

				if (!ctx->u.f.integer && hspace(c)) {
					/* space between values: complete any
					 * keyword we were matching */
					if (lcsp_finish_cssval_keyword(ctx))
						goto oom;
					break;
				}

				if (!ctx->cssval_state && !ctx->u.f.integer &&
				    ((c >= '0' && c <= '9') || c == '.')) {
					// lwsl_notice("integer...\n");
					lws_fx_set(ctx->tf, 0, 0);
					ctx->u.f.integer = LHP_CSS_PROPVAL_INT_WHOLE;
					ctx->temp = LWS_FX_FRACTION_MSD / 10;
					ctx->unit = LCSP_UNIT_NONE;
				}

				if (ctx->u.f.integer) {
					if (c == '.' &&
					    ctx->u.f.integer <= LHP_CSS_PROPVAL_INT_FRAC) {
						ctx->u.f.integer = LHP_CSS_PROPVAL_INT_FRAC;
						break;
					}

					if (ctx->u.f.integer < LHP_CSS_PROPVAL_INT_UNIT &&
					    c >= '0' && c <= '9') {
						if (ctx->u.f.integer == LHP_CSS_PROPVAL_INT_WHOLE) {
							/*
							 * tf.whole is int32_t and
							 * nothing else bounds the
							 * digit count; stop
							 * accumulating well before
							 * it can overflow
							 */
							if (ctx->tf.whole <
								   LHP_CSS_MAX_WHOLE)
								ctx->tf.whole =
								  (ctx->tf.whole * 10) +
								  (c - '0');
						} else {
							if (ctx->temp) {
								ctx->tf.frac += (int32_t)ctx->temp * (c - '0');
								ctx->temp /= 10;
							}
						}
						break;
					}
					if (hspace(c)) {
						/* a unitless number followed
						 * by more values, eg,
						 * "margin: 1em 0 2em" */
						if (ctx->u.f.integer !=
						    LHP_CSS_PROPVAL_INT_UNIT &&
						    lcsp_append_cssval_int(ctx))
							goto oom;
						ctx->u.f.integer = 0;
						ctx->npos = 0;
						break;
					}

					if (ctx->u.f.integer != LHP_CSS_PROPVAL_INT_UNIT) {
						ctx->u.f.integer = LHP_CSS_PROPVAL_INT_UNIT;
						ctx->npos = 0;
					}

					if (c == '%') {
						ctx->unit = LCSP_UNIT_LENGTH_PERCENT;
						goto issue_post;
					}

					if (ctx->npos < 4 && !ctx->unit) {

						ctx->buf[ctx->npos++] = (char)c;
						ctx->buf[ctx->npos] = '\0';

						if (ctx->npos == 2) {
							if (!strcmp(ctx->buf, "em"))
								ctx->unit = LCSP_UNIT_LENGTH_EM;
							if (!strcmp(ctx->buf, "ex"))
								ctx->unit = LCSP_UNIT_LENGTH_EX;
							if (!strcmp(ctx->buf, "in"))
								ctx->unit = LCSP_UNIT_LENGTH_IN;
							if (!strcmp(ctx->buf, "cm"))
								ctx->unit = LCSP_UNIT_LENGTH_CM;
							if (!strcmp(ctx->buf, "mm"))
								ctx->unit = LCSP_UNIT_LENGTH_MM;
							if (!strcmp(ctx->buf, "pt"))
								ctx->unit = LCSP_UNIT_LENGTH_PT;
							if (!strcmp(ctx->buf, "pc"))
								ctx->unit = LCSP_UNIT_LENGTH_PC;
							if (!strcmp(ctx->buf, "px"))
								ctx->unit = LCSP_UNIT_LENGTH_PX;
						}
						if (ctx->npos == 3) {
							if (!strcmp(ctx->buf, "rem"))
								ctx->unit = LCSP_UNIT_LENGTH_REM;
							if (!strcmp(ctx->buf, "deg"))
								ctx->unit = LCSP_UNIT_ANGLE_ABS_DEG;
							if (!strcmp(ctx->buf, "rad"))
								ctx->unit = LCSP_UNIT_ANGLE_ABS_DEG;
						}
						if (ctx->npos == 4) {
							if (!strcmp(ctx->buf, "grad"))
								ctx->unit = LCSP_UNIT_ANGLE_ABS_DEG;
						}

issue_post:
						if (ctx->unit) {
							if (lcsp_append_cssval_int(ctx))
								goto oom;
							ctx->u.f.integer = 0;
							ctx->npos = 0;
						}
						break;
					}
				}

				if (c == '#') {
					ctx->temp = 0;
					ctx->temp_count = 0;
					ctx->u.f.color = 1;
					break;
				}


				if (!is_term) {
					if (ctx->npos >= LHP_STRING_CHUNK) {
						lwsl_err("%s: prop value string too long\n", __func__);
						goto oom;
					}

					ctx->buf[ctx->npos++] = (char)c;
				}

				if (c == '(' && ctx->npos > 1 && ctx->npos < 24) {
					int n, fn = 1;

					/* only ident( starts a function */
					for (n = 0; n < ctx->npos - 1; n++)
						if (!lhp_ident_char(ctx->buf[n]))
							fn = 0;
					if (fn) {
						ctx->u.f.infunc = 1;
						ctx->u.f.inq = 0;
						ctx->temp_count = 1;
						break;
					}
				}

				switch(lws_minilex_parse(css_propconst_lextable,
							 &ctx->cssval_state,
							 c, &ctx->propval)) {
				case LWS_MINILEX_FAIL:
					/*
					 * We don't know this property value, keep
					 * eating until we can resync at next
					 * ';', or we hit the '}'.
					 */
					//lwsl_notice("minilex val fail %c\n", c);
					/* fallthru */
				case LWS_MINILEX_CONTINUE:
					if (!ctx->u.f.arg) { /* term */
						if (ctx->npos)
							lcsp_append_cssval_string(ctx);
						ctx->npos = 0;
					}
					break;
				case LWS_MINILEX_MATCH:
					/* we have an unambiguous well-known
					 * property value match */
					//lwsl_notice("propval %d\n", ctx->propval);
					{
						lcsp_atr_t *atr = lwsac_use_zero(
							  &ctx->cssac,
							  sizeof(*atr),
							  LHP_AC_GRANULE);
						if (!atr)
							goto oom;
						/* add this prop value atr to the def */

						atr->propval = ctx->propval;

						lws_dll2_add_tail(&atr->list,
								&ctx->def->atrs);

						ctx->npos = 0;
					}
					ctx->cssval_state = 0;
					break;
				}

				break;
			}

			/* we're trying to figure out the well-known prop name
			 * The matches all have the : attached, so they will
			 * match unambiguously */

			if (ctx->css_state == (int16_t)-1 && c == ';') {
				/* resync after unknown prop: restart with
				 * whatever is after the ';' */
				ctx->css_state = 0;
				break;
			}

			if (hspace(c)) {
				ctx->u.f.color = 0;
				if (ctx->css_state) /* space after the start
						     * means no match */
					ctx->css_state = (int16_t)-1;
				break;
			}

			/*
			 * Check if it looks like a CSS variable definition, eg
			 * --color-bg:
			 */

			if (c == '-' && !ctx->npos && !ctx->css_state) {
				ctx->css_state = -2; /* var name */
				ctx->buf[ctx->npos++] = (char)c;
				break;
			}

			if (ctx->css_state == -2) {
				if (c != ':') {
					if (ctx->npos < 64)
						ctx->buf[ctx->npos++] = (char)c;
					break;
				}

				/* it is a var definition */

				ctx->def = lwsac_use_zero(&ctx->cssac,
						  sizeof(*ctx->def),
						  LHP_AC_GRANULE);
				if (!ctx->def)
					goto oom;
				ctx->def->prop = LCSP_PROP__COUNT; /* var definition */
				lws_dll2_add_tail(&ctx->def->list, &ctx->stz->defs);

				{
					lhp_css_var_t *v = lwsac_use_zero(&ctx->cssac,
							sizeof(*v) + (unsigned int)ctx->npos + 1,
							LHP_AC_GRANULE);
					if (!v)
						goto oom;

					v->name_len = (size_t)ctx->npos;
					v->def = ctx->def;
					memcpy(&v[1], ctx->buf, v->name_len);
					*((uint8_t *)&v[1] + v->name_len) = '\0';
					lws_dll2_add_tail(&v->list, &ctx->css_vars);
				}

				ctx->u.f.arg = 1;
				ctx->npos = 0;
				ctx->cssval_state = 0;
				ctx->css_state = 0;
				break;
			}

			switch(lws_minilex_parse(css_lextable, &ctx->css_state,
						 c, &ctx->prop)) {
			case LWS_MINILEX_FAIL:
				/*
				 * We don't know this property, keep eating
				 * until we can resync at next ';', or we hit
				 * the '}'.
				 */
				break;
			case LWS_MINILEX_CONTINUE:
				/*
				 * ':' ends every property name; if it is
				 * still ambiguous (eg, "margin:" vs
				 * "margin-top:") ask the minilex to settle it
				 */
				if (c != ':' ||
				    lws_minilex_parse(css_lextable,
						      &ctx->css_state, 0,
						      &ctx->prop) !=
							LWS_MINILEX_MATCH)
					break;
				/* fallthru */
			case LWS_MINILEX_MATCH:
				/* we have an unambiguous match, now we are
				 * doing the property args */
				ctx->def = lwsac_use_zero(&ctx->cssac,
						  sizeof(*ctx->def),
						  LHP_AC_GRANULE);
				if (!ctx->def)
					goto oom;
				ctx->def->prop = (lcsp_props_t)ctx->prop;
				/* add this prop def to the stanza */
				lws_dll2_add_tail(&ctx->def->list, &ctx->stz->defs);
				ctx->u.f.arg = 1;
				ctx->npos = 0;
				ctx->cssval_state = 0;
				//lwsl_notice("%s: minilex prop match %d\n", __func__, ctx->prop);
				break;
			}
			break;

		case LCSPS_CCOM_S1:
			if (c == '*') {
				ctx->state = LCSPS_CCOM;
				break;
			}
			ctx->state = ctx->state_css_comm;
			break;

		case LCSPS_CSS_OUTER_TAG1:
			/*
			 * We could see <!-- or perhaps </script> if we are
			 * inside a <script> section
			 */
			if (c == '!' && ctx->u.f.first) {
				ctx->state = LCSPS_SCOMMENT1;
				ctx->u.f.first = 0;
				break;
			}
			if (ctx->state_css_comm == LCSPS_CSS_OUTER &&
			    c == '/' && ctx->u.f.first) {
				r = ctx->await_css_done;
				// lwsl_warn("leaving css for tag");
				ctx->u.s = 0;

				ctx->tag = NULL;
				ctx->tag_len = 0;
				ctx->npos = 0;
				ctx->state = LHPS_TAG;
				ctx->await_css_done = 0;
				ctx->finish_css = 0;
				if (r)
					return LWS_SRET_AWAIT_RETRY;
				ctx->u.f.closing = 1;
				break;
			}
			if (hspace(c))
				break;
			break;
		case LCSPS_CSS_NAMES:
			break;
		case LCSPS_CSS_DEF_NAME:
			break;
		case LCSPS_CSS_DEF_VALUE:
			break;

		case LCSPS_SCOMMENT1:
			if (c == '-') {
				ctx->state = LCSPS_SCOMMENT2;
				break;
			}
			/* we saw <! and then not - */
			ctx->state = ctx->state_css_comm;
			break;
		case LCSPS_SCOMMENT2:
			if (c == '-') {
				ctx->state = LCSPS_COMMENT;
				break;
			}
			/* we saw <!- and then not - */
			ctx->state = ctx->state_css_comm;
			break;

		case LCSPS_CCOM:
			/* fallthru */
		case LCSPS_COMMENT:
			/* sanity */
			if (ctx->npos >= LHP_STRING_CHUNK - 4) {
				ps->cb(ctx, LHPCB_COMMENT);
				ctx->npos = 0;
			}
			if (ctx->state == LCSPS_COMMENT && c == '-') {
				ctx->state = LCSPS_ECOMMENT1;
				break;
			}
			if (ctx->state == LCSPS_CCOM && c == '*') {
				ctx->state = LCSPS_CCOM_E1;
				break;
			}

			/* collect the comment */
			ctx->buf[ctx->npos++] = (char)c;
			/* sanity */
			if (ctx->npos >= LHP_STRING_CHUNK - 4) {
				ps->cb(ctx, LHPCB_COMMENT);
				ctx->npos = 0;
			}

			break;

		case LCSPS_CCOM_E1:
			if (c == '/') {
				if (ctx->npos) {
					ps->cb(ctx, LHPCB_COMMENT);
					ctx->npos = 0;
				}
				ctx->state = ctx->state_css_comm;
				break;
			}
			ctx->state = LCSPS_CCOM;
			break;

		case LCSPS_ECOMMENT1:
			if (c == '-') {
				ctx->state = LCSPS_ECOMMENT2;
				break;
			}
			ctx->buf[ctx->npos++] = '-';
			ctx->buf[ctx->npos++] = (char)c;
			ctx->state = LCSPS_COMMENT;
			break;

		case LCSPS_ECOMMENT2:
			if (c == '>') {
				if (ctx->npos) {
					ps->cb(ctx, LHPCB_COMMENT);
					ctx->npos = 0;
				}
				ctx->state = ctx->state_css_comm;
				break;
			}
			ctx->buf[ctx->npos++] = '-';
			ctx->buf[ctx->npos++] = '-';
			ctx->buf[ctx->npos++] = (char)c;
			ctx->state = LCSPS_COMMENT;
			break;

		case LHPS_SCRIPT:
			if (c == '<') {
				ctx->state = LHPS_SCRIPT_TAG1;
				ctx->u.f.first = 1;
				break;
			}
			break;

		case LHPS_SCRIPT_TAG1:
			if (c == '/') {
				ctx->npos = 0;
				ctx->state = LHPS_SCRIPT_TAG2;
				break;
			}
			ctx->state = c == '<' ? LHPS_SCRIPT_TAG1 : LHPS_SCRIPT;
			break;

		case LHPS_SCRIPT_TAG2:
			/*
			 * Only </script> ends the script; "</div>" inside a
			 * string literal or a comparison like i < n/2 does not
			 */
			if (lhp_ident_char((char)c) && ctx->npos < 6) {
				ctx->buf[ctx->npos++] = (char)c;
				break;
			}
			if (c == '>' && ctx->npos == 6 &&
			    !strncasecmp(ctx->buf, "script", 6)) {
				ctx->u.s = 0;
				ctx->u.f.closing = 1;
				ctx->tag = NULL;
				ctx->tag_len = 0;
				ctx->npos = 0;
				ctx->await_css_done = 0;
				ctx->finish_css = 0;
				goto elem_start;
			}
			ctx->state = c == '<' ? LHPS_SCRIPT_TAG1 : LHPS_SCRIPT;
			break;

		}
		if (!*len && ctx->is_css && ctx->await_css_done && ctx->finish_css) {
			lhp_link_css_done(ctx);
			return LWS_SRET_AWAIT_RETRY;
		}
	}

	if (!ctx->u.f.default_css && ctx->flags & LHP_FLAG_DOCUMENT_END) {
		/*
		 * if we're holding on to anything in case more comes, no more
		 * is coming and we should flush it.
		 */

		if (ctx->state == LHPS_OUTER && ctx->npos) {
			if (ctx->in_body && (ctx->npos != 1 || ctx->buf[0] != ' '))
				ps->cb(ctx, LHPCB_CONTENT);
			ctx->npos = 0;
		}

		ps->cb(ctx, LHPCB_COMPLETE);
		return LWS_SRET_NO_FURTHER_OUT;
	}

	return LWS_SRET_WANT_INPUT;

oom:
	lwsl_err("%s: OOM\n", __func__);
	ps->cb(ctx, LHPCB_FAILED);
	return LWS_SRET_FATAL;
}

/*
 * Query the css in effect for a property on the element currently being
 * parsed, see the description in lws-html.h
 */

const lcsp_atr_t *
lws_css_cascade_get_prop_atr(lhp_ctx_t *ctx, lcsp_props_t prop)
{
	if (lws_dll2_is_empty(&ctx->stack))
		return NULL;

	return lhp_prop_atr_ps(ctx, lws_container_of(
				lws_dll2_get_tail(&ctx->stack),
				lhp_pstack_t, list), prop);
}

const lcsp_atr_t *
lws_css_get_prop_atr_ps(lhp_ctx_t *ctx, lhp_pstack_t *ps, lcsp_props_t prop)
{
	return lhp_prop_atr_ps(ctx, ps, prop);
}

lhp_pstack_t *
lws_css_get_parent_block(lhp_ctx_t *ctx, lhp_pstack_t *ps)
{
	lws_start_foreach_dll_back(lws_dll2_t *, d,
				   lws_dll2_get_prev(&ps->list)) {
		lhp_pstack_t *tp = lws_container_of(d, lhp_pstack_t, list);

		if (tp->dlo)
			return tp;
	} lws_end_foreach_dll_back(d);

	return NULL;
}

const char *
lws_css_pstack_name(lhp_pstack_t *ps)
{
	lhp_atr_t *a;

	if (!ps)
		return "(null ps)";

	if(lws_dll2_is_empty(&ps->atr))
		return "no-name";

	a = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);

	return (const char *)&a[1];
}

/*
 * Some properties have an impied affinity for an axis, eg, left: references
 * the parent width if it has a % expression
 */

int
lhp_prop_axis(const lcsp_atr_t *a)
{
	const lcsp_defs_t *d;

	if (!lws_dll2_owner(&a->list))
		return LWS_LHPREF_NONE;

	d = lws_dll2_owner_container(&a->list, lcsp_defs_t, atrs);

	switch (d->prop) {
	/* referenced to height */
	case LCSP_PROP_BORDER_TOP_WIDTH:
	case LCSP_PROP_BORDER_BOTTOM_WIDTH:
	case LCSP_PROP_HEIGHT:
	case LCSP_PROP_TOP:
	case LCSP_PROP_BOTTOM:
	case LCSP_PROP_MARGIN_TOP:
	case LCSP_PROP_MARGIN_BOTTOM:
	case LCSP_PROP_PADDING_TOP:
	case LCSP_PROP_PADDING_BOTTOM:
	case LCSP_PROP_MAX_HEIGHT:
	case LCSP_PROP_MIN_HEIGHT:
		//lwsl_notice("%s: %d: LWS_LHPREF_HEIGHT\n", __func__, d->prop);
		return LWS_LHPREF_HEIGHT;

	/* referenced to width */
	case LCSP_PROP_BORDER_LEFT_WIDTH:
	case LCSP_PROP_BORDER_RIGHT_WIDTH:
	case LCSP_PROP_WHITE_SPACE:
	case LCSP_PROP_WIDTH:
	case LCSP_PROP_LEFT:
	case LCSP_PROP_RIGHT:
	case LCSP_PROP_MARGIN_LEFT:
	case LCSP_PROP_MARGIN_RIGHT:
	case LCSP_PROP_PADDING_LEFT:
	case LCSP_PROP_PADDING_RIGHT:
	case LCSP_PROP_MAX_WIDTH:
	case LCSP_PROP_MIN_WIDTH:
		//lwsl_notice("%s: %d: LWS_LHPREF_WIDTH\n", __func__, d->prop);
		return LWS_LHPREF_WIDTH;

	default:
		//lwsl_notice("%s: %d: LWS_LHPREF_NONE\n", __func__, d->prop);
		return LWS_LHPREF_NONE;
	}
}
