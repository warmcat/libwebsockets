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
	"input", "keygen", "link", "meta", "param", "source", "track", "wbr"
};
static const uint8_t void_elems_lens[] = /* lengths for the table above */
	{ 4, 4, 2, 3, 7, 5, 2, 3, 5, 6, 4, 4, 5, 6, 5, 3 };

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
	"li              { display: list-item }\n"
	"head            { display: none }\n"
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

static const lws_fx_t c_254= { 2,54000000 }, c_10 = { 10,0 },
			     c_72 = { 72,0 }, c_6 = { 6,0 }, c_100 = { 100,0 };

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

const lws_fx_t *
lws_csp_px(const lcsp_atr_t *a, lhp_pstack_t *ps)
{
	lhp_ctx_t *ctx;
	const lws_display_font_t *f;
	lws_fx_t t1, t2, t3;
	int ref;

	assert(ps);

	if (!a)
		return NULL;

	ctx = lws_container_of(ps->list.owner, lhp_ctx_t, stack);
	f = ps->font;

	ref = lhp_prop_axis(a);

	switch (a->unit) {
	case LCSP_UNIT_LENGTH_EM:
		return lws_fx_mul((lws_fx_t *)&a->r, &a->u.i, &f->em);

	case LCSP_UNIT_LENGTH_EX:
		return lws_fx_mul((lws_fx_t *)&a->r, &a->u.i, &f->ex);

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
	lhp_pstack_t *ps = lws_container_of(ctx->stack.tail, lhp_pstack_t, list);

	/* create the element name attribute */
	lhp_atr_t *a = lws_malloc(sizeof(*a) + name_len + 1 + value_len + 1,
				  "html_elem_atr");
	size_t n;

	if (!a)
		return NULL;

	if (!ps->atr.count) {
		/* only check the tag string, not the attributes */
		ctx->u.f.void_element = 0;

		/*
		 * mark ps that are elements that contain others for layout as
		 * being the parent block
		 */
		if ((name_len == 4 && !strncmp(ctx->buf, "body", 4)) ||
		    (name_len == 3 && !strncmp(ctx->buf, "div", 3)))
			ps->is_block = 1;

		for (n = 0; n < LWS_ARRAY_SIZE(void_elems); n++)
			if (ctx->npos == void_elems_lens[n] &&
			    !strncmp(void_elems[n], ctx->buf, (size_t)ctx->npos))
				ctx->u.f.void_element = 1;
	}

	lws_dll2_clear(&a->list);
	a->name_len = name_len;
	a->value_len = value_len;
	ctx->buf[ctx->npos] = '\0';
	memcpy(&a[1], ctx->buf, (unsigned int)ctx->npos + 1u);
	*(((uint8_t *)&a[1]) + name_len) = '\0';
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
	atr->unit = ctx->unit;

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

	atr = lwsac_use_zero(&ctx->cssac, sizeof(*atr) + (size_t)ctx->npos + 1u,
			     LHP_AC_GRANULE);
	if (!atr)
		return 1;

	v = (char *)&atr[1];
	atr->value_len = (size_t)ctx->npos;
	memcpy(v, c, (size_t)ctx->npos);
	v[ctx->npos] = '\0';

	//lwsl_notice("%s: %s\n", __func__, v);

	lws_dll2_add_tail(&atr->list, &ctx->def->atrs);

	return 0;
}

static int
lws_css_cascade_atr_match(lhp_ctx_t *ctx, const char *tag, size_t tag_len)
{
	lws_start_foreach_dll(struct lws_dll2 *, q, ctx->css.head) {
		lcsp_stanza_t *stz = lws_container_of(q, lcsp_stanza_t, list);

		/* ... does this stanza mention our name? */

		lws_start_foreach_dll(struct lws_dll2 *, z, stz->names.head) {
			lcsp_names_t *nm = lws_container_of(z, lcsp_names_t,
							    list);
			const char *p = (const char *)&nm[1];
			size_t nl = nm->name_len;

			if (nl && *p == '.') { /* match .mycss as mycss */
				p++;
				nl--;
			}

			if (nl == tag_len && !memcmp(p, tag, tag_len)) {

				lcsp_stanza_ptr_t *sp = lwsac_use_zero(
						&ctx->cascadeac,
						sizeof(*sp), LHP_AC_GRANULE);
				if (!sp)
					return 1;

				sp->stz = stz;
				lws_dll2_add_tail(&sp->list,
						  &ctx->active_stanzas);
				break;
			}

		} lws_end_foreach_dll(z);

	} lws_end_foreach_dll(q);

	return 0;
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

/*
 * Produce an ordered list of css stanzas that apply to the current html
 * parsing context, accounting for class="xxx" at each level
 */

static int
lws_css_cascade(lhp_ctx_t *ctx)
{
	lws_dll2_owner_clear(&ctx->active_stanzas);
	lwsac_free(&ctx->cascadeac);
	lws_dll2_owner_clear(&ctx->active_atr);
	lwsac_free(&ctx->propatrac);
	ctx->in_body = 0;

	/* let's proceed through the html element stack that applies */

	lws_start_foreach_dll(struct lws_dll2 *, p, ctx->stack.head) {
		lhp_pstack_t *ps = lws_container_of(p, lhp_pstack_t, list);

		/*
		 * if there is a css definition for the html entity at this
		 * stack level, add its stanza to the results
		 */

		lws_start_foreach_dll(struct lws_dll2 *, ha, ps->atr.head) {
			lhp_atr_t *a = lws_container_of(ha, lhp_atr_t, list);
			struct lws_tokenize ts;

			memset(&ts, 0, sizeof(ts));

			if (ha == ps->atr.head) {
				ts.start = (const char *)&a[1];
				ts.len = a->name_len;
			}


			if (a->name_len == 5 &&
			     !strcmp((const char *)&a[1], "class")) {
				ts.start = ((const char *)&a[1]) + 5 + 1;
				ts.len = a->value_len;
			}

			do {
				ts.e = (int8_t)lws_tokenize(&ts);
				if (ts.e == LWS_TOKZE_TOKEN) {

					if (ha == ps->atr.head &&
					    ts.token_len == 4 &&
					    !memcmp(ts.token, "body", 4))
						ctx->in_body = 1;

					/*
					 * let's look through the css stanzas
					 * for a tag match
					 */

					if (lws_css_cascade_atr_match(ctx,
							ts.token, ts.token_len))
						return 1;
				}

			} while (ts.e > 0);

		} lws_end_foreach_dll(ha);

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

		ps->css_border_radius[0] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BORDER_TOP_LEFT_RADIUS);
		ps->css_border_radius[1] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BORDER_TOP_RIGHT_RADIUS);
		ps->css_border_radius[2] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BORDER_BOTTOM_LEFT_RADIUS);
		ps->css_border_radius[3] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BORDER_BOTTOM_RIGHT_RADIUS);

		ps->css_background_color = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BACKGROUND_COLOR);
		ps->css_color = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_COLOR);

		ps->css_pos[CCPAS_TOP] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_TOP);
		ps->css_pos[CCPAS_RIGHT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_RIGHT);
		ps->css_pos[CCPAS_BOTTOM] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_BOTTOM);
		ps->css_pos[CCPAS_LEFT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_LEFT);

		ps->css_margin[CCPAS_TOP] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_TOP);
		ps->css_margin[CCPAS_RIGHT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_RIGHT);
		ps->css_margin[CCPAS_BOTTOM] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_BOTTOM);
		ps->css_margin[CCPAS_LEFT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);

		ps->css_padding[CCPAS_TOP] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_PADDING_TOP);
		ps->css_padding[CCPAS_RIGHT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_PADDING_RIGHT);
		ps->css_padding[CCPAS_BOTTOM] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_PADDING_BOTTOM);
		ps->css_padding[CCPAS_LEFT] = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_PADDING_LEFT);

	} lws_end_foreach_dll(p);

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

lws_stateful_ret_t
lws_lhp_parse(lhp_ctx_t *ctx, const uint8_t **buf, size_t *len)
{
	lhp_pstack_t *ps1, *ps = lws_container_of(ctx->stack.tail,
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

	if (!*len && ctx->is_css && ctx->await_css_done && ctx->finish_css)
		goto finish_css;

	while (*len) {
		uint8_t c = *(*buf)++;

		(*len)--;

		if (ctx->state == LHPS_DO_START_ELEM) {
			/* we are retrying the inner callback */
			(*len)++;
			(*buf)--;
		}

		// lwsl_notice("%s: %d, '%c', %02X\n", __func__, ctx->state, c, c);

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
			if (r >= LWS_SRET_FATAL) {
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
				ctx->u.s = 0;
				ctx->u.f.first = 1;

				ctx->tag = NULL;
				ctx->tag_len = 0;

				ctx->state = LHPS_TAG;

				if (ctx->stack.count == LHP_MAX_ELEMS_NEST /* sanity */) {
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
				ps = lws_container_of(ctx->stack.tail,
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
					// lwsl_warn("leaving html for css\n");
					ctx->state = LCSPS_CSS_OUTER;
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
				char url[128];

				memset(&i, 0, sizeof(i));
				lws_css_cascade(ctx);

				if (ctx->npos == 4 && !strncmp(ctx->buf, "body", 4)) {
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

					if (ctx->npos == 4 &&
					    !strncmp(ctx->buf, "body", 4) && aa)
						pname = (const char *)(aa + 1);
				}

				assert(ctx->base_url);

				if (!pname)
					goto issue_elem_start;

				/* we should be in an <img tag or
				 * something with a background image */

				assert(ctx->base_url);

				if (lws_http_rel_to_url(url, sizeof(url),
							ctx->base_url, pname))
					goto skip_image;

				psb = lws_css_get_parent_block(ctx, ps);
				//if (!psb)
				//	lwsl_err("%s: NULL psb\n", __func__);

				if (ctx->npos == 3 && !strncmp(ctx->buf, "img", 3)) {
					lws_fx_set(box.x, 0, 0);
					lws_fx_set(box.y, 0, 0);

					if (ps->css_position->propval == LCSP_PROPVAL_ABSOLUTE) {
					//	box.x = *lws_csp_px(ps->css_pos[CCPAS_LEFT], ps);
					///	box.y = *lws_csp_px(ps->css_pos[CCPAS_TOP], ps);
					//	abs = 1;
					} else {
						if (psb) {
							box.x = psb->curx;
							box.y = psb->cury;
						}
					}

					if (psb) {
						lws_fx_add(&box.x, &box.x,
							lws_csp_px(psb->css_margin[CCPAS_LEFT], psb));
						lws_fx_add(&box.y, &box.y,
							lws_csp_px(psb->css_margin[CCPAS_TOP], psb));
					}

					box.h = ctx->ic.wh_px[LWS_LHPREF_HEIGHT]; /* placeholder */
					lws_fx_sub(&box.w, &ctx->ic.wh_px[0], &box.x);

					if (ps->css_width &&
					    lws_fx_comp(lws_csp_px(ps->css_width, ps), &box.w) > 0)
						box.w = *lws_csp_px(ps->css_width, ps);
				}

				memset(&u, 0, sizeof(u));
				if (lws_dlo_ss_find(cx, url, &u)) {

					i.cx = cx;
					i.dl = drt->dl;
					if (psb)
						i.dlo_parent = psb->dlo;
					i.box = &box;
					i.on_rx = ctx->ssevcb;
					i.on_rx_sul = ctx->ssevsul;
					i.url = url;
					i.lhp = ctx;
					i.u = &u;
					i.window = ctx->window;

					lwsl_cx_warn(cx, "not already in progress: %s", url);
					if (lws_dlo_ss_create(&i, &dlo)) {
						/* we can't get it */
						lwsl_cx_warn(cx, "Can't get %s", url);
						goto issue_elem_start;
					} else {
						lwsl_cx_warn(cx, "Created SS for %s\n", url);
						if (psb)
							psb->dlo = dlo;
					//	else
						ps->dlo = dlo;
					}
				} else {
					// lwsl_cx_warn(cx, "Found in-progress %s\n", url);
					if (psb)
						psb->dlo = &u.u.dlo_png->dlo;
					//else
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
				 * If he has given explicit width and height
				 * for the image, no need to wait for them
				 */

				if (lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_HEIGHT), ps)->whole &&
						lws_csp_px(lws_css_cascade_get_prop_atr(ctx,
							LCSP_PROP_WIDTH), ps)->whole) {
					lwsl_cx_warn(cx, "Have width and height %d x %d",
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

				/*
				 * Do we have the dimensions?  If not, bail
				 * from here and await a retry (maybe caused by
				 * data coming for the image)
				 */

				if (!lws_dlo_image_width(&u) ||
				    !lws_dlo_image_height(&u)) {
					// lwsl_warn("%s: exiting with AWAIT_RETRY\n", __func__);
					return LWS_SRET_AWAIT_RETRY;
				}

				u.u.dlo_png->dlo.box.w.whole = (int32_t)lws_dlo_image_width(&u);
				u.u.dlo_png->dlo.box.h.whole = (int32_t)lws_dlo_image_height(&u);

				/* did it fail to retreive it? */

				if (u.u.dlo_png->dlo.box.w.whole < 0) {
					lwsl_notice("%s: understanding image failed\n", __func__);
					goto skip_image;
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

			if (ctx->u.f.closing || ctx->u.f.void_element){
				if (ctx->stack.count == 1) {
					lwsl_err("%s: element close mismatch\n", __func__);
					ps->cb(ctx, LHPCB_FAILED);
					return LWS_SRET_FATAL;
				}
				if (ps->atr.head) {
					lhp_atr_t *a = lws_container_of(ps->atr.head, lhp_atr_t, list);
					memcpy(ctx->buf, &a[1], a->name_len);
					ctx->npos = (int)a->name_len;
				}
				ps->cb(ctx, LHPCB_ELEMENT_END);
				ctx->npos = 0;
				/* remove the start level */
				lhp_clean_level(ps);
				lws_css_cascade(ctx);
				ps = lws_container_of(ctx->stack.tail,
						      lhp_pstack_t, list);
			}
skip_image:
			ctx->npos = 0;
			ctx->state = LHPS_OUTER;
			break;

		case LHPS_ATTRIB:

			if (ctx->u.f.doctype && c == '\"') {
				ctx->u.f.inq = ctx->u.f.inq ^ 1u;
				if (ctx->u.f.inq)
					break;
			}

			if ((ctx->u.f.inq || !hspace(c)) &&
			    (c != '/' || ctx->u.f.inq) && c != '>') {
				/* collect the attrib name */
				ctx->buf[ctx->npos++] = (char)c;
				/* sanity */
				if (ctx->npos == LHP_STRING_CHUNK) {
					lwsl_err("%s: string chunk\n", __func__);
					ps->cb(ctx, LHPCB_FAILED);
					return LWS_SRET_FATAL;
				}
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

			if ((ctx->u.f.inq || !hspace(c)) &&
			    c != '>' && c != '\'' && c != '\"') {
				/* collect the attrib value */
				ctx->buf[ctx->npos++] = (char)c;
				/* sanity */
				if (ctx->npos == LHP_STRING_CHUNK) {
					lwsl_err("%s: string chunk 2\n", __func__);
					ps->cb(ctx, LHPCB_FAILED);
					return LWS_SRET_FATAL;
				}
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
				ctx->buf[ctx->npos] = '\0';
				if (!lhp_atr_new(ctx, (size_t)ctx->nl_temp,
					 (size_t)ctx->npos - (size_t)ctx->nl_temp - 1u))
					goto oom;
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
			/*
			 * These are supposed to be named chars, like &dagger;
			 * but not supported yet.
			 */
			ctx->state = LHPS_OUTER;
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
				ctx->state = LHPS_OUTER;
				break;
			}
			if (c == ';') {
				if (ctx->npos >= LHP_STRING_CHUNK - 5) {
					if (ctx->in_body)
						ps->cb(ctx, LHPCB_CONTENT);
					ctx->npos = 0;
				}
				ctx->state = LHPS_OUTER;
				lhp_uni_emit(ctx);
				break;
			}

			if (c >= '0' && c <= '9')
				ctx->temp = (uint32_t)(((int)ctx->temp * 10) + ((int)c - '0'));
			else
				ctx->state = LHPS_OUTER;

			break;

		case LHPS_AMPHASH_HEX:
			if (c == ';') {
				if (ctx->npos >= LHP_STRING_CHUNK - 5) {
					if (ctx->in_body)
						ps->cb(ctx, LHPCB_CONTENT);
					ctx->npos = 0;
				}
				ctx->state = LHPS_OUTER;
				lhp_uni_emit(ctx);
				break;
			}

			if (ctx->temp_count++ > 8 /* sanity */) {
				ctx->state = LHPS_OUTER;
				break;
			}

			if (c >= '0' && c <= '9') {
				ctx->temp = (uint32_t)(((int)ctx->temp << 4) + ((int)c - '0'));
				break;
			}

			if (c >= 'A' && c <= 'F') {
				ctx->temp = (uint32_t)(((int)ctx->temp << 4) + ((int)c - 'A') + 10);
				break;
			}

			if (c >= 'a' && c <= 'f') {
				ctx->temp = (uint32_t)(((int)ctx->temp << 4) + ((int)c - 'a') + 10);
				break;
			}

			ctx->state = LHPS_OUTER;
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
				struct lws_tokenize ts;

				/* create the stanza object */

				ctx->stz = lwsac_use_zero(&ctx->cssac,
							  sizeof(*ctx->stz),
							  LHP_AC_GRANULE);
				if (!ctx->stz)
					goto oom;

				/* attach names to it */

				memset(&ts, 0, sizeof(ts));
				ts.start = ctx->buf;
				ts.len = (size_t)ctx->npos;
				ts.flags = LWS_TOKENIZE_F_COMMA_SEP_LIST |
						LWS_TOKENIZE_F_DOT_NONTERM;

				do {
					ts.e = (int8_t)lws_tokenize(&ts);
					if (ts.e == LWS_TOKZE_TOKEN) {
						lcsp_names_t *na = lwsac_use_zero(
							&ctx->cssac,
							sizeof(*na) +
							ts.token_len + 1,
							LHP_AC_GRANULE);
						if (!na)
							goto oom;

						//lwsl_notice("%s: CSS name %.*s\n",
						//	__func__,
						//	(int)ts.token_len, ts.token);

						na->name_len = ts.token_len;
						memcpy(&na[1], ts.token, ts.token_len);
						((char *)(&na[1]))[ts.token_len] = '\0';
						lws_dll2_add_tail(&na->list, &ctx->stz->names);
					}

				} while (ts.e > 0);


				/* list this stanza in our lhp context CSS */

				lws_dll2_add_tail(&ctx->stz->list, &ctx->css);

				ctx->buf[ctx->npos] = '\0';

				ctx->state = LCSPS_CSS_STANZA;
				ctx->cssval_state = 0;
				ctx->css_state = 0;
				ctx->u.f.arg = 0;
				ctx->u.f.integer = 0;
				ctx->u.f.color = 0;
				break;
			}

			/* otherwise let's collect the name pieces */

			if (ctx->npos >= LHP_STRING_CHUNK) {
				lwsl_err("%s: css lhs too long\n", __func__);
				return LWS_SRET_FATAL;
			}

			if (!hspace(c))
				ctx->buf[ctx->npos++] = (char)c;

			break;

		case LCSPS_CSS_STANZA:
			ctx->state_css_comm = LCSPS_CSS_STANZA;
			if (c == '}') {
				ctx->state = LCSPS_CSS_OUTER;

				ctx->u.f.arg = 0;

				if (ctx->u.f.color) {
					lcsp_append_cssval_color(ctx);
					ctx->npos = 0;
					break;
				}
				if (ctx->u.f.integer) {/* x: 123} */
					if (lcsp_append_cssval_int(ctx))
						goto oom;

					ctx->u.f.integer = 0;
					ctx->npos = 0;
					break;
				}
				//lwsl_notice("close curly cssval_state %d\n", ctx->cssval_state);
				if (ctx->cssval_state || ctx->npos)
					goto for_term;
				ctx->npos = 0;
				break;
			}
			if (c == '/') {
				ctx->state = LCSPS_CCOM_S1;
				break;
			}

			if (ctx->u.f.arg) {
				/* we're on the value side of prop: value */

				if (c == ';') {
					/* resync after unknown prop: restart with
					 * whatever is after the ';' */
					ctx->css_state = 0;
					ctx->u.f.arg = 0;

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
					}

					if (ctx->cssval_state)
						goto for_term;
					ctx->npos = 0;
					break;
				}

				if (ctx->cssval_state == (int16_t)-1 &&
				    hspace(c)) {
					/* resync after unknown prop: restart
					 * with whatever is after the ';' */
					ctx->cssval_state = 0;
					break;
				}

				if (ctx->u.f.color &&
					((c >= '0' && c <= '9') ||
					(c >= 'a' && c <= 'f') ||
					(c >= 'A' && c <= 'F'))) {
					ctx->temp = (uint32_t)(((int)ctx->temp << 4) |
						((c <= '9') ? c - '0' :
							(c >= 'a') ? 10 + (c - 'a') :
								10 + (c - 'A')));
					ctx->temp_count++;
					break;
				}

				if (!ctx->u.f.integer && hspace(c))
					break;

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
						if (ctx->u.f.integer == LHP_CSS_PROPVAL_INT_WHOLE)
							ctx->tf.whole =
								(ctx->tf.whole * 10) +
								(c - '0');
						else {
							if (ctx->temp) {
								ctx->tf.frac += (int32_t)ctx->temp * (c - '0');
								ctx->temp /= 10;
							}
						}
						break;
					}
					if (hspace(c)) {
						ctx->u.f.integer = 0;
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


				if (ctx->npos >= LHP_STRING_CHUNK) {
					lwsl_err("%s: prop value string too long\n", __func__);
					goto oom;
				}

				ctx->buf[ctx->npos++] = (char)c;

				/* well-known property value strings */

for_term:

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
				break;
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

finish_css:
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

		}
		if (!*len && ctx->is_css && ctx->await_css_done && ctx->finish_css)
			goto finish_css;
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
 * Query the css cascade active at this html parsing point for a list of active
 * css attributes belonging to a particular property, accounting for cascading
 * overriding inside the list.
 */

const lcsp_atr_t *
lws_css_cascade_get_prop_atr(lhp_ctx_t *ctx, lcsp_props_t prop)
{
	lcsp_atr_ptr_t *ap;

	lws_dll2_owner_clear(&ctx->active_atr);
	lwsac_free(&ctx->propatrac);

	/*
	 * Let's go through the active stanzas looking for defs that relate to
	 * the property we care about
	 */

	lws_start_foreach_dll(struct lws_dll2 *, q, ctx->active_stanzas.head) {
		lcsp_stanza_ptr_t *pstz = lws_container_of(q, lcsp_stanza_ptr_t,
							   list);

		/* each def entry in the stanza in turn */

		lws_start_foreach_dll(struct lws_dll2 *, p, pstz->stz->defs.head) {
			lcsp_defs_t *def = lws_container_of(p, lcsp_defs_t, list);

			if (def->prop == prop) {

				lws_start_foreach_dll(struct lws_dll2 *, z,
						      def->atrs.head) {
					lcsp_atr_ptr_t *patr = lwsac_use_zero(
							&ctx->propatrac,
							sizeof(*patr),
							LHP_AC_GRANULE);
					if (!patr)
						return NULL;

					patr->atr = lws_container_of(z,
							lcsp_atr_t, list);

					lws_dll2_add_tail(&patr->list,
							  &ctx->active_atr);
				} lws_end_foreach_dll(z);
			}

		} lws_end_foreach_dll(p);

	} lws_end_foreach_dll(q);

	if (!ctx->active_atr.count)
		return NULL;

	ap = lws_container_of(ctx->active_atr.tail, lcsp_atr_ptr_t, list);

	return ap->atr;
}

lhp_pstack_t *
lws_css_get_parent_block(lhp_ctx_t *ctx, lhp_pstack_t *ps)
{
	do {

		if (!ps->list.prev)
			return NULL;

		ps = lws_container_of(ps->list.prev, lhp_pstack_t, list);

		if (ps->dlo)
			return ps;

	} while(1);
}

const char *
lws_css_pstack_name(lhp_pstack_t *ps)
{
	lhp_atr_t *a;

	if (!ps)
		return "(null ps)";

	if (!ps->atr.head)
		return "no-name";

	a = lws_container_of(ps->atr.head, lhp_atr_t, list);

	return (const char *)&a[1];
}

/*
 * Some properties have an impied affinity for an axis, eg, left: references
 * the parent width if it has a % expression
 */

int
lhp_prop_axis(const lcsp_atr_t *a)
{
	const lcsp_defs_t *d = lws_container_of(a->list.owner, lcsp_defs_t, atrs);

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
