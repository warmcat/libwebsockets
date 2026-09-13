/*
 * lws svg
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
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
 * A stateful, linewise renderer for the fill-only subset of SVG.
 *
 * The document is parsed streaming into a retained vector scene in a single
 * lwsac; curves are flattened adaptively at parse time with a tolerance
 * derived from the viewBox.  Individual raster lines are then produced on
 * demand by scanline intersection against the retained flattened geometry,
 * so lines can be rendered in any order and repeatedly.
 *
 * Everything is hostile-input-safe: bounded nesting, bounded attribute
 * lengths, bounded scene sizes and hand-rolled number parsing with clamped
 * magnitudes.  No libm is used; trigonometry goes through the lws_fx
 * fixed-point operators, keeping results deterministic across platforms.
 */

#include <private-lib-core.h>

/*
 * Retained scene limits.  A document trying to exceed these produces a
 * FATAL parse result rather than exhausting memory on the target.
 */

enum {
	LWS_SVG_MAX_DEPTH	= 24,	/* open element stack */
	LWS_SVG_MAX_SHAPES	= 2048,
	LWS_SVG_MAX_PTS		= 262144, /* scene-wide flattened points */
	LWS_SVG_MAX_SUBS	= 1024,	/* subpaths per shape */
	LWS_SVG_MAX_ATTRVAL	= 65536,
	LWS_SVG_MAX_NAME	= 31,
};

/* kappa: cubic bezier approximation of a quarter circle control factor */

/*
 * All geometry is computed in pure integer arithmetic on two
 * representations, both sharing lws_fx_t's 1e-8 fractional basis:
 *
 *  - e8: int64 count of 1e-8 units, ie, the lws_fx_t (whole, frac)
 *    decomposition joined.  Values from number parsing, angles and
 *    opacity live here; trig goes through the lws_fx operators.
 *
 *  - svg_c_t: int32 Q16.16, range +/-32768 with 1/65536 resolution.
 *    All coordinates, transform matrices and raster math.  Products
 *    are computed in int64 and saturate rather than overflow, so
 *    hostile transforms clip instead of producing inf / NaN.
 */

#define SVG_E8_1		100000000ll	/* 1.0 in e8 */
#define SVG_E8_PI		314159262ll	/* pi in e8 */
#define SVG_Q16_1		65536
#define SVG_C_MAX		0x7fffffff	/* saturated Q16.16 magnitude */
#define SVG_KAPPA_Q		36204		/* 0.55228474983079356 in Q16.16 */
#define SVG_Q4_3		87381		/* 4/3 in Q16.16 */

typedef int32_t		svg_c_t;

typedef struct lws_svg_pt {
	svg_c_t			x, y;	/* user space, post-CTM, Q16.16 */
} lws_svg_pt_t;

/* e8 <-> lws_fx_t (pure integer joins of the decomposition) */

static int64_t
svg_fx_to_e8(const lws_fx_t *f)
{
	return (int64_t)f->whole * SVG_E8_1 + f->frac;
}

static void
svg_e8_to_fx(lws_fx_t *f, int64_t v)
{
	f->whole = (int32_t)(v / SVG_E8_1);
	f->frac = (int32_t)(v % SVG_E8_1);
}

/* e8 -> Q16.16 with saturation */

static svg_c_t
svg_e8_to_c(int64_t v)
{
	int64_t q = (v * SVG_Q16_1) / SVG_E8_1;

	if (q > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (q < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)q;
}

/* saturating Q16.16 helpers */

static svg_c_t
svg_qadd(int32_t a, int32_t b)
{
	int64_t r = (int64_t)a + b;

	if (r > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (r < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)r;
}

static svg_c_t
svg_qsub(int32_t a, int32_t b)
{
	int64_t r = (int64_t)a - b;

	if (r > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (r < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)r;
}

static svg_c_t
svg_qmul(int32_t a, int32_t b)
{
	int64_t r = ((int64_t)a * b) / SVG_Q16_1;

	if (r > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (r < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)r;
}

/* integer sqrt of a non-negative int64, digit-by-digit */

static int64_t
svg_isqrt64(int64_t v)
{
	uint64_t op = (uint64_t)v, res = 0, one = 1ull << 62;

	while (one > op)
		one >>= 2;

	while (one) {
		if (op >= res + one) {
			op -= res + one;
			res = (res >> 1) + one;
		} else
			res >>= 1;
		one >>= 2;
	}

	return (int64_t)res;
}

/*
 * Trig via the lws_fx fixed-point operators: pure integer, no FPU or
 * libm dependency, deterministic across platforms.  Angles are e8
 * radians in and out; sin / cos / tan results are Q16.16.
 */

static svg_c_t
svg_sin(int64_t r_e8)
{
	lws_fx_t a, res;

	svg_e8_to_fx(&a, r_e8);
	lws_fx_sin(&res, &a);

	return svg_e8_to_c(svg_fx_to_e8(&res));
}

static svg_c_t
svg_cos(int64_t r_e8)
{
	lws_fx_t a, res;

	svg_e8_to_fx(&a, r_e8);
	lws_fx_cos(&res, &a);

	return svg_e8_to_c(svg_fx_to_e8(&res));
}

static svg_c_t
svg_tan(int64_t r_e8)
{
	lws_fx_t a, res;

	svg_e8_to_fx(&a, r_e8);
	lws_fx_tan(&res, &a);

	return svg_e8_to_c(svg_fx_to_e8(&res));
}

static int64_t
svg_atan2(int64_t y_e8, int64_t x_e8)
{
	lws_fx_t fy, fx, res;

	svg_e8_to_fx(&fy, y_e8);
	svg_e8_to_fx(&fx, x_e8);
	lws_fx_atan2(&res, &fy, &fx);

	return svg_fx_to_e8(&res);
}

/* integer ceil(v / 65536), valid for the whole int64 range */

static int
svg_ceil_q16(int64_t v)
{
	return (int)((v + SVG_Q16_1 - 1) / SVG_Q16_1);
}


typedef struct lws_svg_sub {
	lws_dll2_t		list;
	lws_svg_pt_t		*pts;	/* from scene lwsac */
	uint32_t		npts;
	char			closed;
} lws_svg_sub_t;

typedef struct lws_svg_shape {
	lws_dll2_t		list;	/* document order */
	lws_dll2_owner_t	subs;
	uint32_t		rgba;	/* fill colour with composed alpha */
	char			rule;	/* 0 = nonzero, 1 = evenodd */
} lws_svg_shape_t;

/* per-open-element inherited state */

typedef struct {
	svg_c_t			m[6];	/* CTM: x' = m[0]x + m[2]y + m[4] */
	uint32_t		rgba;	/* composed fill colour */
	char			rule;
	char			suppress; /* inside defs, text, unknown... */
} svg_lvl_t;

/*
 * Minimal CSS support for <style> blocks: rules with a single simple
 * selector (element name, .class or #id) and the same presentation
 * property set the style="" attribute already understands.  Selectors
 * with anything else (pseudo-classes, combinators, attributes) and
 * at-rules are skipped leniently.
 */

enum {
	LWS_SVG_MAX_CSSRULES	= 128,
	LWS_SVG_MAX_SEL		= 48,
	LWS_SVG_MAX_CLASS	= 48,
	LWS_SVG_MAX_ID		= 24,
};

typedef struct {
	char		sel[LWS_SVG_MAX_SEL]; /* "rect", ".cls", "#id" */
	uint8_t		tier;		     /* 0 elem, 1 class, 2 id */
	uint32_t	fill;
	char		fill_set;
	int64_t		fillop, op;	/* e8 */
	char		fillop_set, op_set;
	char		rule, rule_set;
} svg_cssrule_t;

/* pending per-tag state, accumulated from attributes as they stream in */

typedef struct {
	uint32_t		fill;	/* valid when fill_present */
	char			fill_present; /* fill attr seen (incl none) */
	int64_t			fillop, op;	/* e8 */
	char			fillop_present, op_present;
	char			rule, rule_present;
	char			has_transform;
	svg_c_t			tm[6];	/* own transform list composition */
	svg_c_t			g[6];	/* shape geometry attrs */
	char			gok[6];
	char			has_d;		/* path data in working arrays */
	char			has_points;
	char			cls[LWS_SVG_MAX_CLASS]; /* class attr names */
	char			id[LWS_SVG_MAX_ID];

	/*
	 * style="" attribute declarations are kept separate from the
	 * presentation attributes, so the css cascade can be applied in
	 * the correct priority: presentation attrs < <style> rules <
	 * style="" content
	 */

	uint32_t	sa_fill;
	char		sa_fill_present;
	int64_t		sa_fillop, sa_op;	/* e8 */
	char		sa_fillop_present, sa_op_present;
	char		sa_rule, sa_rule_present;
} svg_pend_t;

typedef struct lws_svg_dpt {
	svg_c_t			x, y;	/* user space, Q16.16 */
} lws_svg_dpt_t;

typedef struct {
	uint32_t		start;	/* first index into working pts */
	char			closed;
} svg_wsub_t;

typedef enum {
	SXS_PROLOG,		/* skipping until first '<' */
	SXS_TAGNAME,
	SXS_ATTRS,
	SXS_ATTRNAME,
	SXS_ATTREQ,		/* attr name done, waiting for '=' */
	SXS_ATTRVALQ,		/* waiting for opening quote */
	SXS_ATTRVAL,		/* inside value */
	SXS_ATTRVAL_ENT,	/* inside &...; in a value */
	SXS_TEXT,		/* character data until next '<' */
	SXS_CLOSENAME,		/* after '</' */
	SXS_BANG,		/* after '<!', working out which */
	SXS_COMMENT,		/* inside <!-- ... --> */
	SXS_PI,			/* inside <? ... ?> */
	SXS_DOCTYPE,		/* inside <!...> */
	SXS_CDATA,		/* inside <![CDATA[ ... ]]> */
	SXS_DONE,		/* root element closed */
} sxs_t;

typedef enum {
	SVEK_OTHER,		/* unknown element: suppress subtree */
	SVEK_ROOT,		/* svg at document root */
	SVEK_GROUP,		/* g, a, nested svg, switch */
	SVEK_SUPPRESS,		/* known non-rendering container */
	SVEK_STYLE,		/* css stylesheet container */
	SVEK_RECT,
	SVEK_CIRCLE,
	SVEK_ELLIPSE,
	SVEK_LINE,
	SVEK_POLYLINE,
	SVEK_POLYGON,
	SVEK_PATH,
} svg_ekind_t;

/* rasterization scratch */

typedef struct {
	svg_c_t			x;	/* device-space crossing x, Q16.16 */
	int8_t			dir;	/* +1 downwards edge, -1 upwards */
} lws_svg_cross_t;

struct lws_svg {
	/* retained scene */

	struct lwsac		*ac;
	lws_dll2_owner_t	shapes;
	uint32_t		nshapes;
	uint32_t		npts;	/* scene-wide flattened point count */

	/* css rules parsed out of <style> blocks */

	svg_cssrule_t		*css;
	uint16_t		css_count;
	char			in_style;

	/* root sizing and mapping policy */

	svg_c_t			width, height;
	char			unit_w, unit_h;	/* 0 = px, 1 = percent */
	char			has_w, has_h;
	svg_c_t			vb[4];			/* minx miny w h */
	char			has_vb;
	char			par_none, par_slice;
	uint8_t			par_ax, par_ay;	/* 0 min, 1 mid, 2 max */

	svg_c_t			tol;	/* flatten tolerance, Q16.16 */

	char			root_seen;
	char			doc_complete;
	char			fatal;

	/* xml tokenizer state */

	uint8_t			ts;
	uint8_t			quote;
	uint8_t			bang_step;	/* '<!' prefix matcher */
	uint8_t			sub_step;	/* comment/cdata/pi matchers */
	uint8_t			elen;		/* entity accumulation */
	char			saw_slash;
	char			name[LWS_SVG_MAX_NAME + 1];
	char			aname[LWS_SVG_MAX_NAME + 1];
	svg_ekind_t		ekind;
	char			*vbuf;			/* attr value acc */
	size_t			vlen, vsize;
	char			ebuf[10];

	/* element style stack */

	svg_lvl_t		stk[LWS_SVG_MAX_DEPTH + 1];
	int			depth;

	svg_pend_t		pend;

	/* working geometry (user space), copied into the scene at commit */

	lws_svg_dpt_t		*wpts;
	size_t			wpts_count, wpts_size;
	svg_wsub_t		*wsubs;
	size_t			wsubs_count, wsubs_size;

	/* rasterization scratch */

	lws_svg_cross_t		*xings;
	size_t			xings_size;	/* allocated entries */
	int64_t			*aa_d;		/* aa: per-column D terms */
	size_t			aa_d_size;	/* allocated entries */
};

/*
 * Trig via the lws_fx fixed-point operators: pure integer, no FPU or
 * libm dependency, deterministic across platforms.  Angles are e8
 * radians in and out; sin / cos / tan results are Q16.16.
 */

/*
 * Number parsing.  Accepts the SVG grammar for numbers with optional
 * exponent; magnitudes are clamped so hostile input can't explode the
 * geometry math later.  Only returns non-NULL (and only advances the
 * cursor) for a well-formed number.
 */

/* skip whitespace and comma separators */

static const char *
svg_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' ||
			   *p == '\n' || *p == ','))
		p++;

	return p;
}

static const char *
svg_num(const char *p, const char *end, int64_t *r)
{
	/*
	 * Builds the value in e8 units (1e-8, matching lws_fx_t's
	 * fractional basis) with pure integer arithmetic.  Magnitudes are
	 * clamped to +/-1e6 (e8 1e14) so later fixed-point conversions and
	 * products cannot overflow: Q16.16 saturates far below that anyway.
	 */

	const int64_t cap = 1000000;		/* whole units */
	const int64_t cap_e8 = cap * SVG_E8_1;	/* 1e14, fits int64 */
	int any = 0, neg = 0;
	int64_t v = 0, fr = SVG_E8_1 / 10;

	if (p < end && (*p == '+' || *p == '-')) {
		neg = *p == '-';
		p++;
	}

	while (p < end && *p >= '0' && *p <= '9') {
		if (v < cap)
			v = v * 10 + (*p - '0');
		p++;
		any = 1;
	}

	v *= SVG_E8_1;
	if (v > cap_e8)
		v = cap_e8;

	if (p < end && *p == '.') {
		const char *q = p + 1;

		while (q < end && *q >= '0' && *q <= '9') {
			if (v < cap_e8 && fr) {
				v += (*q - '0') * fr;
				fr /= 10;
			}
			q++;
			any = 1;
		}
		/* only consume the '.' when it introduced digits */
		if (q > p + 1)
			p = q;
	}

	if (!any)
		return NULL;

	if (p < end && (*p == 'e' || *p == 'E')) {
		const char *q = p + 1;
		int eneg = 0, ev = 0, eany = 0;

		if (q < end && (*q == '+' || *q == '-')) {
			eneg = *q == '-';
			q++;
		}
		while (q < end && *q >= '0' && *q <= '9') {
			if (ev < 18)
				ev = (ev * 10) + (*q - '0');
			q++;
			eany = 1;
		}
		if (eany) {
			p = q;
			if (ev > 6)
				v = eneg ? 0 : cap_e8;
			else {
				while (ev--) {
					if (eneg) {
						v /= 10;
						if (!v)
							break;
					} else {
						if (v > cap_e8 / 10) {
							v = cap_e8;
							break;
						}
						v *= 10;
					}
				}
			}
		}
	}

	if (v > cap_e8)
		v = cap_e8;

	*r = neg ? -v : v;

	return p;
}

static char
isxmlws(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* a length with optional CSS unit; returns unit 0 = px (converted), 1 = % */

static int
svg_len(const char *s, size_t len, svg_c_t *r, char *pct)
{
	static const struct { const char *u; svg_c_t q; } units[] = {
		{ "pt",		87381 },	/* 4/3 */
		{ "pc",		1048576 },	/* 16 */
		{ "mm",		247703 },	/* 96 / 25.4 */
		{ "cm",		2477027 },	/* 96 / 2.54 */
		{ "in",		6291456 },	/* 96 */
	};
	const char *p = s, *end = s + len;
	int64_t v;

	p = svg_ws(p, end);
	p = svg_num(p, end, &v);
	if (!p)
		return 1;

	*pct = 0;

	while (p < end && isxmlws(*p))
		p++;

	if (p < end) {
		if (*p == '%')
			*pct = 1;
		else {
			unsigned int i;

			for (i = 0; i < LWS_ARRAY_SIZE(units); i++)
				if ((size_t)(end - p) >= strlen(units[i].u) &&
				    !strncmp(p, units[i].u, strlen(units[i].u))) {
					*r = svg_qmul(svg_e8_to_c(v), units[i].q);
					return 0;
				}
		}
		/* px and anything else: leave in px */
	}

	*r = svg_e8_to_c(v);

	return 0;
}

/* exact-length case-insensitive literal match */

static int
lit_match(const char *p, size_t len, const char *lit)
{
	size_t ll = strlen(lit);

	return len == ll && !strncasecmp(p, lit, ll);
}

static const struct {
	const char	*name;
	uint32_t	rgb;
} svg_named_colours[] = {
	{ "aliceblue",		0xf0f8ff }, { "antiquewhite",	0xfaebd7 },
	{ "aqua",		0x00ffff }, { "aquamarine",		0x7fffd4 },
	{ "azure",		0xf0ffff }, { "beige",		0xf5f5dc },
	{ "bisque",		0xffe4c4 }, { "black",		0x000000 },
	{ "blanchedalmond",	0xffebcd }, { "blue",		0x0000ff },
	{ "blueviolet",		0x8a2be2 }, { "brown",		0xa52a2a },
	{ "burlywood",		0xdeb887 }, { "cadetblue",		0x5f9ea0 },
	{ "chartreuse",		0x7fff00 }, { "chocolate",		0xd2691e },
	{ "coral",		0xff7f50 }, { "cornflowerblue",	0x6495ed },
	{ "cornsilk",		0xfff8dc }, { "crimson",		0xdc143c },
	{ "cyan",		0x00ffff }, { "darkblue",		0x00008b },
	{ "darkcyan",		0x008b8b }, { "darkgoldenrod",	0xb8860b },
	{ "darkgray",		0xa9a9a9 }, { "darkgreen",		0x006400 },
	{ "darkgrey",		0xa9a9a9 }, { "darkkhaki",		0xbdb76b },
	{ "darkmagenta",	0x8b008b }, { "darkolivegreen",	0x556b2f },
	{ "darkorange",		0xff8c00 }, { "darkorchid",		0x9932cc },
	{ "darkred",		0x8b0000 }, { "darksalmon",		0xe9967a },
	{ "darkseagreen",	0x8fbc8f }, { "darkslateblue",	0x483d8b },
	{ "darkslategray",	0x2f4f4f }, { "darkslategrey",	0x2f4f4f },
	{ "darkturquoise",	0x00ced1 }, { "darkviolet",		0x9400d3 },
	{ "deeppink",		0xff1493 }, { "deepskyblue",	0x00bfff },
	{ "dimgray",		0x696969 }, { "dimgrey",		0x696969 },
	{ "dodgerblue",		0x1e90ff }, { "firebrick",		0xb22222 },
	{ "floralwhite",	0xfffaf0 }, { "forestgreen",	0x228b22 },
	{ "fuchsia",		0xff00ff }, { "gainsboro",		0xdcdcdc },
	{ "ghostwhite",		0xf8f8ff }, { "gold",		0xffd700 },
	{ "goldenrod",		0xdaa520 }, { "gray",		0x808080 },
	{ "green",		0x008000 }, { "greenyellow",	0xadff2f },
	{ "grey",		0x808080 }, { "honeydew",		0xf0fff0 },
	{ "hotpink",		0xff69b4 }, { "indianred",		0xcd5c5c },
	{ "indigo",		0x4b0082 }, { "ivory",		0xfffff0 },
	{ "khaki",		0xf0e68c }, { "lavender",		0xe6e6fa },
	{ "lavenderblush",	0xfff0f5 }, { "lawngreen",		0x7cfc00 },
	{ "lemonchiffon",	0xfffacd }, { "lightblue",		0xadd8e6 },
	{ "lightcoral",		0xf08080 }, { "lightcyan",		0xe0ffff },
	{ "lightgoldenrodyellow", 0xeee8aa }, { "lightgray",	0xd3d3d3 },
	{ "lightgreen",		0x90ee90 }, { "lightgrey",		0xd3d3d3 },
	{ "lightpink",		0xffb6c1 }, { "lightsalmon",	0xffa07a },
	{ "lightseagreen",	0x20b2aa }, { "lightskyblue",	0x87cefa },
	{ "lightslategray",	0x778899 }, { "lightslategrey",	0x778899 },
	{ "lightsteelblue",	0xb0c4de }, { "lightyellow",	0xffffe0 },
	{ "lime",		0x00ff00 }, { "limegreen",		0x32cd32 },
	{ "linen",		0xfaf0e6 }, { "magenta",		0xff00ff },
	{ "maroon",		0x800000 }, { "mediumaquamarine",	0x66cdaa },
	{ "mediumblue",		0x0000cd }, { "mediumorchid",	0xba55d3 },
	{ "mediumpurple",	0x9370db }, { "mediumseagreen",	0x3cb371 },
	{ "mediumslateblue",	0x7b68ee }, { "mediumspringgreen", 0x00fa9a },
	{ "mediumturquoise",	0x48d1cc }, { "mediumvioletred", 0xc71585 },
	{ "midnightblue",	0x191970 }, { "mintcream",		0xf5fffa },
	{ "mistyrose",		0xffe4e1 }, { "moccasin",		0xffe4b5 },
	{ "navajowhite",	0xffdead }, { "navy",		0x000080 },
	{ "oldlace",		0xfdf5e6 }, { "olive",		0x808000 },
	{ "olivedrab",		0x6b8e23 }, { "orange",		0xffa500 },
	{ "orangered",		0xff4500 }, { "orchid",		0xda70d6 },
	{ "palegoldenrod",	0xeee8aa }, { "palegreen",		0x98fb98 },
	{ "paleturquoise",	0xafeeee }, { "palevioletred",	0xdb7093 },
	{ "papayawhip",		0xffefd5 }, { "peachpuff",		0xffdab9 },
	{ "peru",		0xcd853f }, { "pink",		0xffc0cb },
	{ "plum",		0xdda0dd }, { "powderblue",	0xb0e0e6 },
	{ "purple",		0x800080 }, { "rebeccapurple",	0x663399 },
	{ "red",		0xff0000 }, { "rosybrown",		0xbc8f8f },
	{ "royalblue",		0x4169e1 }, { "saddlebrown",	0x8b4513 },
	{ "salmon",		0xfa8072 }, { "sandybrown",	0xf4a460 },
	{ "seagreen",		0x2e8b57 }, { "seashell",		0xfff5ee },
	{ "sienna",		0xa0522d }, { "silver",		0xc0c0c0 },
	{ "skyblue",		0x87ceeb }, { "slateblue",		0x6a5acd },
	{ "slategray",		0x708090 }, { "slategrey",		0x708090 },
	{ "snow",		0xfffafa }, { "springgreen",	0x00ff7f },
	{ "steelblue",		0x4682b4 }, { "tan",		0xd2b48c },
	{ "teal",		0x008080 }, { "thistle",		0xd8bfd8 },
	{ "tomato",		0xff6347 }, { "turquoise",		0x40e0d0 },
	{ "violet",		0xee82ee }, { "wheat",		0xf5deb3 },
	{ "white",		0xffffff }, { "whitesmoke",	0xf5f5f5 },
	{ "yellow",		0xffff00 }, { "yellowgreen",	0x9acd32 },
};

static int
hexv(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

/*
 * Parse a CSS colour.  Returns 0 and sets *rgba on success (alpha 0 means
 * nothing will be painted), or 1 if it could not be understood.
 */

static int
svg_colour(const char *s, size_t len, uint32_t *rgba)
{
	const char *p = s, *end = s + len;
	uint32_t r, g, b, a = 255;
	int i, h[8], n;

	p = svg_ws(p, end);
	if (p >= end)
		return 1;

	if (*p == '#') {
		p++;
		for (n = 0; n < 8 && p < end; n++, p++) {
			h[n] = hexv(*p);
			if (h[n] < 0)
				break;
		}
		switch (n) {
		case 3:
			r = (uint32_t)(h[0] << 4 | h[0]);
			g = (uint32_t)(h[1] << 4 | h[1]);
			b = (uint32_t)(h[2] << 4 | h[2]);
			break;
		case 4:
			r = (uint32_t)(h[0] << 4 | h[0]);
			g = (uint32_t)(h[1] << 4 | h[1]);
			b = (uint32_t)(h[2] << 4 | h[2]);
			a = (uint32_t)(h[3] << 4 | h[3]);
			break;
		case 6:
			r = (uint32_t)(h[0] << 4 | h[1]);
			g = (uint32_t)(h[2] << 4 | h[3]);
			b = (uint32_t)(h[4] << 4 | h[5]);
			break;
		case 8:
			r = (uint32_t)(h[0] << 4 | h[1]);
			g = (uint32_t)(h[2] << 4 | h[3]);
			b = (uint32_t)(h[4] << 4 | h[5]);
			a = (uint32_t)(h[6] << 4 | h[7]);
			break;
		default:
			return 1;
		}

		*rgba = LWS_SVG_RGBA(r, g, b, a);

		return 0;
	}

	/* rgb() / rgba(), with int or percentage components */

	if ((size_t)(end - p) > 4 &&
	    (!strncmp(p, "rgb(", 4) || !strncmp(p, "rgba(", 5))) {
		char is_rgba = p[3] == 'a';
		int32_t comp[4];
		int nc;

		p += is_rgba ? 5 : 4;

		/*
		 * Components are parsed as e8 and reduced to 0..255 with
		 * rounding; percentages are v * 255 / 100.
		 */

		for (nc = 0; nc < 4; nc++) {
			int64_t v;
			int pct = 0;

			p = svg_ws(p, end);
			p = svg_num(p, end, &v);
			if (!p)
				break;
			if (p < end && *p == '%') {
				pct = 1;
				p++;
			}
			if (nc == 3) {
				/* alpha is 0..1, or a percentage of 255 */
				comp[nc] = pct ?
					(int32_t)((v * 255 + 5ll * SVG_E8_1) /
							100 / SVG_E8_1) :
					(int32_t)((v * 255 +
						SVG_E8_1 / 2) / SVG_E8_1);
			} else
				comp[nc] = pct ?
					(int32_t)((v * 255 + 5ll * SVG_E8_1) /
							100 / SVG_E8_1) :
					(int32_t)((v + SVG_E8_1 / 2) / SVG_E8_1);
			p = svg_ws(p, end);
			if (p < end && *p == ',')
				p++;
		}

		if (nc < 3)
			return 1;

		comp[0] = comp[0] < 0 ? 0 : comp[0] > 255 ? 255 : comp[0];
		comp[1] = comp[1] < 0 ? 0 : comp[1] > 255 ? 255 : comp[1];
		comp[2] = comp[2] < 0 ? 0 : comp[2] > 255 ? 255 : comp[2];
		if (is_rgba) {
			comp[3] = comp[3] < 0 ? 0 : comp[3] > 255 ? 255 :
								comp[3];
			a = (uint32_t)comp[3];
		}

		*rgba = LWS_SVG_RGBA((uint32_t)comp[0], (uint32_t)comp[1],
				     (uint32_t)comp[2], a);

		return 0;
	}

	/* named colours, case-insensitively */

	for (i = 0; i < (int)LWS_ARRAY_SIZE(svg_named_colours); i++) {
		size_t nl = strlen(svg_named_colours[i].name);
		uint32_t rgb;

		if (nl != (size_t)(end - p) ||
		    strncasecmp(p, svg_named_colours[i].name, nl))
			continue;

		rgb = svg_named_colours[i].rgb;
		*rgba = LWS_SVG_RGBA((rgb >> 16) & 0xff, (rgb >> 8) & 0xff,
				     rgb & 0xff, 0xff);
		return 0;
	}

	/* explicit no-paint forms, and unsupported paint servers */

	if (lit_match(p, (size_t)(end - p), "none") ||
	    lit_match(p, (size_t)(end - p), "transparent")) {
		*rgba = 0;	/* alpha 0: nothing painted */
		return 0;
	}

	if ((size_t)(end - p) > 4 && !strncmp(p, "url(", 4)) {
		/* gradients etc not supported in this phase: no paint */
		*rgba = 0;
		return 0;
	}

	if (lit_match(p, (size_t)(end - p), "currentColor")) {
		*rgba = LWS_SVG_RGBA(0, 0, 0, 0xff);
		return 0;
	}

	return 1;
}

/*
 * Affine helpers.  CTM layout is { a, b, c, d, e, f } applied as
 * x' = a·x + c·y + e; y' = b·x + d·y + f
 */

static void
xf_ident(svg_c_t m[6])
{
	m[0] = SVG_Q16_1; m[1] = 0; m[2] = 0; m[3] = SVG_Q16_1; m[4] = 0; m[5] = 0;
}

/* r = m ∘ t (apply t first, then m); safe when r aliases m, saturating */

static void
xf_comp(svg_c_t r[6], const svg_c_t m[6], const svg_c_t t[6])
{
	svg_c_t a = svg_qadd(svg_qmul(m[0], t[0]), svg_qmul(m[2], t[1]));
	svg_c_t b = svg_qadd(svg_qmul(m[1], t[0]), svg_qmul(m[3], t[1]));
	svg_c_t c = svg_qadd(svg_qmul(m[0], t[2]), svg_qmul(m[2], t[3]));
	svg_c_t d = svg_qadd(svg_qmul(m[1], t[2]), svg_qmul(m[3], t[3]));
	svg_c_t e = svg_qadd(svg_qadd(svg_qmul(m[0], t[4]),
				      svg_qmul(m[2], t[5])), m[4]);
	svg_c_t f = svg_qadd(svg_qadd(svg_qmul(m[1], t[4]),
				      svg_qmul(m[3], t[5])), m[5]);

	r[0] = a; r[1] = b; r[2] = c; r[3] = d; r[4] = e; r[5] = f;
}

/*
 * Parse a transform list, composing on to out[].  Unknown functions are
 * skipped leniently.
 */

static int
svg_transforms(const char *s, size_t len, svg_c_t out[6])
{
	const char *p = s, *end = s + len;
	svg_c_t t[6], arg[6];
	int na, i;

	p = svg_ws(p, end);

	while (p < end) {
		char fn[16];
		size_t fl = 0;

		while (p < end && ((*p >= 'a' && *p <= 'z') ||
				   (*p >= 'A' && *p <= 'Z')) &&
		       fl < sizeof(fn) - 1)
			fn[fl++] = *p++;
		fn[fl] = '\0';

		p = svg_ws(p, end);
		if (p >= end)
			break;
		if (*p != '(') {
			p++;	/* skip junk looking for the next function */
			continue;
		}
		p++;

		na = 0;
		p = svg_ws(p, end);
		while (p < end && na < 6) {
			int64_t v;
			const char *q = svg_num(p, end, &v);

			if (!q)
				break;
			p = q;
			arg[na++] = svg_e8_to_c(v);
			p = svg_ws(p, end);
		}
		while (p < end && *p != ')')
			p++;		/* skip anything extra leniently */
		if (p < end)
			p++;

		xf_ident(t);

		if (!strcmp(fn, "matrix") && na == 6) {
			for (i = 0; i < 6; i++)
				t[i] = arg[i];
		} else
			if (!strcmp(fn, "translate")) {
				if (na >= 1)
					t[4] = arg[0];
				if (na >= 2)
					t[5] = arg[1];
			} else
				if (!strcmp(fn, "scale")) {
					if (na >= 1) {
						t[0] = arg[0];
						t[3] = na >= 2 ? arg[1] : arg[0];
					}
				} else
					if (!strcmp(fn, "rotate")) {
						/* radians from degrees, in e8 */

						int64_t rad = (int64_t)arg[0] *
							(SVG_E8_PI / 180) / SVG_Q16_1;
						svg_c_t co = svg_cos(rad);
						svg_c_t si = svg_sin(rad);
						svg_c_t dx = 0, dy = 0;

						t[0] = co;
						t[1] = si;
						t[2] = -si;
						t[3] = co;

						/* optional rotation centre */

						if (na >= 3) {
							dx = arg[1];
							dy = arg[2];
							t[4] = svg_qadd(svg_qsub(dx,
								     svg_qmul(co, dx)),
								     svg_qmul(si, dy));
							t[5] = svg_qsub(svg_qsub(dy,
								     svg_qmul(si, dx)),
								     svg_qmul(co, dy));
						}
					} else
						if (!strcmp(fn, "skewX") && na >= 1)
							t[2] = svg_tan(
								(int64_t)arg[0] *
								(SVG_E8_PI / 180) /
									SVG_Q16_1);
						else
							if (!strcmp(fn, "skewY") &&
							    na >= 1)
								t[1] = svg_tan(
									(int64_t)arg[0] *
									(SVG_E8_PI / 180) /
										SVG_Q16_1);
							else
								continue;  /* unknown fn */

		xf_comp(out, out, t);

		p = svg_ws(p, end);
	}

	return 0;
}

/*
 * Working geometry accumulation (user space).  The working arrays are grown
 * with lws_realloc during parse and the finished shape is copied into the
 * scene lwsac with its effective CTM applied at commit time.
 */

static int
wpts_grow(lws_svg_t *ctx, size_t need)
{
	lws_svg_dpt_t *n;

	if (ctx->wpts_count + need <= ctx->wpts_size)
		return 0;

	{
		size_t ns = ctx->wpts_size ? ctx->wpts_size * 2 : 128;

		while (ns < ctx->wpts_count + need)
			ns *= 2;
		ctx->wpts_size = ns;
	}

	n = lws_realloc(ctx->wpts, ctx->wpts_size * sizeof(*ctx->wpts), __func__);
	if (!n)
		return 1;
	ctx->wpts = n;

	return 0;
}

static int
pt_add(lws_svg_t *ctx, svg_c_t x, svg_c_t y)
{
	if (ctx->npts >= LWS_SVG_MAX_PTS || wpts_grow(ctx, 1))
		return 1;

	ctx->wpts[ctx->wpts_count].x = x;
	ctx->wpts[ctx->wpts_count].y = y;
	ctx->wpts_count++;
	ctx->npts++;

	return 0;
}

/* start a new subpath beginning at x,y */

/* start a new subpath beginning at x,y */

static int
sub_start(lws_svg_t *ctx, svg_c_t x, svg_c_t y)
{
	if (ctx->wsubs_count >= LWS_SVG_MAX_SUBS)
		return 1;

	if (ctx->wsubs_count + 1 > ctx->wsubs_size) {
		svg_wsub_t *n;
		size_t ns = ctx->wsubs_size ? ctx->wsubs_size * 2 : 16;

		n = lws_realloc(ctx->wsubs, ns * sizeof(*ctx->wsubs), __func__);
		if (!n)
			return 1;
		ctx->wsubs = n;
		ctx->wsubs_size = ns;
	}

	memset(&ctx->wsubs[ctx->wsubs_count], 0, sizeof(ctx->wsubs[0]));
	ctx->wsubs[ctx->wsubs_count].start = (uint32_t)ctx->wpts_count;
	ctx->wsubs_count++;

	return pt_add(ctx, x, y);
}

static void
work_reset(lws_svg_t *ctx)
{
	ctx->wpts_count = 0;
	ctx->wsubs_count = 0;
}

/*
 * Cubic flattening by adaptive subdivision.  The flatness test uses the
 * sum of the control points' perpendicular distances from the chord, which
 * bounds the approximation error; subdivision depth is capped so hostile
 * control point arrangements cannot run away.
 */


/*
 * Cubic flattening by adaptive subdivision.  The flatness test compares
 * |d1 + d2|, the summed perpendicular distances of the control points
 * from the chord, against tol * chord.  Deltas are pre-shifted 2 bits so
 * corner-to-corner cross products stay inside int64; a couple of bits is
 * immaterial to a tolerance test.  Subdivision depth is capped so hostile
 * control point arrangements cannot run away.
 */

static int
flat_enough(lws_svg_t *ctx, svg_c_t x0, svg_c_t y0, svg_c_t x1, svg_c_t y1,
	    svg_c_t x2, svg_c_t y2, svg_c_t x3, svg_c_t y3)
{
	int64_t dx = (int64_t)x3 - x0, dy = (int64_t)y3 - y0;
	int64_t d1, d2, dd, chord;

	if (!dx && !dy) {
		/* zero chord: only the control point spread matters */

		int64_t ax = (int64_t)x1 - x0, ay = (int64_t)y1 - y0;
		int64_t bx = (int64_t)x2 - x0, by = (int64_t)y2 - y0;
		int64_t tol2 = (int64_t)ctx->tol * ctx->tol;

		return (ax >> 2) * (ax >> 2) + (ay >> 2) * (ay >> 2) <=
							tol2 * 1024 &&
		       (bx >> 2) * (bx >> 2) + (by >> 2) * (by >> 2) <=
							tol2 * 1024;
	}

	d1 = (((int64_t)x1 - x0) >> 1) * (dy >> 1) -
	     (((int64_t)y1 - y0) >> 1) * (dx >> 1);
	d2 = (((int64_t)x2 - x0) >> 1) * (dy >> 1) -
	     (((int64_t)y2 - y0) >> 1) * (dx >> 1);

	/*
	 * True test: cross <= tol * chord, both sides as raw products of
	 * Q16.16 values (units^2 * 2^32), so no rescaling of the product.
	 * The 1-bit shifts put cross at 1/4 and chord at 1/2 scale:
	 * (cross / 4) * 4 <= tol * (chord / 2) * 2.  A cross beyond 2^59
	 * can never be flat for the clamped tolerance, so clamping it
	 * keeps the shifted compare in range.
	 */

	dd = d1 + d2;
	if (dd < 0)
		dd = -dd;
	if (dd > (1ll << 59))
		return 0;	/* never flat */

	chord = svg_isqrt64((dx >> 1) * (dx >> 1) + (dy >> 1) * (dy >> 1));

	return (dd << 2) <= (int64_t)ctx->tol * chord * 2;
}

static int
flatten_cubic(lws_svg_t *ctx, svg_c_t x0, svg_c_t y0, svg_c_t x1, svg_c_t y1,
	      svg_c_t x2, svg_c_t y2, svg_c_t x3, svg_c_t y3, int depth)
{
	svg_c_t x01, y01, x12, y12, x23, y23, x012, y012, x123, y123, m;

	if (depth >= 16 || flat_enough(ctx, x0, y0, x1, y1, x2, y2, x3, y3))
		return pt_add(ctx, x3, y3);

	/* de Casteljau midpoints; averages can exceed range by 1/2 ulp */

	m = (svg_c_t)(((int64_t)x0 + x1) / 2);	x01 = m;
	m = (svg_c_t)(((int64_t)y0 + y1) / 2);	y01 = m;
	m = (svg_c_t)(((int64_t)x1 + x2) / 2);	x12 = m;
	m = (svg_c_t)(((int64_t)y1 + y2) / 2);	y12 = m;
	m = (svg_c_t)(((int64_t)x2 + x3) / 2);	x23 = m;
	m = (svg_c_t)(((int64_t)y2 + y3) / 2);	y23 = m;
	m = (svg_c_t)(((int64_t)x01 + x12) / 2);	x012 = m;
	m = (svg_c_t)(((int64_t)y01 + y12) / 2);	y012 = m;
	m = (svg_c_t)(((int64_t)x12 + x23) / 2);	x123 = m;
	m = (svg_c_t)(((int64_t)y12 + y23) / 2);	y123 = m;
	m = (svg_c_t)(((int64_t)x012 + x123) / 2);

	if (flatten_cubic(ctx, x0, y0, x01, y01, x012, y012, m,
			  (svg_c_t)(((int64_t)y012 + y123) / 2), depth + 1))
		return 1;

	return flatten_cubic(ctx, m, (svg_c_t)(((int64_t)y012 + y123) / 2),
			     x123, y123, x23, y23, x3, y3, depth + 1);
}

static int
flatten_quad(lws_svg_t *ctx, svg_c_t x0, svg_c_t y0, svg_c_t x1, svg_c_t y1,
	     svg_c_t x2, svg_c_t y2)
{
	/* exact degree elevation to a cubic: c = p + (p1 - p) * 2/3 */

	return flatten_cubic(ctx, x0, y0,
		svg_qadd(x0, (svg_c_t)(((int64_t)x1 - x0) * 2 / 3)),
		svg_qadd(y0, (svg_c_t)(((int64_t)y1 - y0) * 2 / 3)),
		svg_qadd(x2, (svg_c_t)(((int64_t)x1 - x2) * 2 / 3)),
		svg_qadd(y2, (svg_c_t)(((int64_t)y1 - y2) * 2 / 3)),
		x2, y2, 0);
}



/*
 * SVG "A" command: convert the endpoint-parameterized arc to a sequence of
 * at most 4 cubic pieces, following the SVG spec F.6.5 endpoint-to-center
 * conversion.
 */


/*
 * SVG "A" command: convert the endpoint-parameterized arc to a sequence of
 * at most 4 cubic pieces, following the SVG spec F.6.5 endpoint-to-center
 * conversion.  Coordinates are Q16.16 and angles e8 radians.  Ratios are
 * computed on reduced terms, and unit-vector products are formed before
 * scaling by the radii, so hostile radii and endpoints cannot overflow.
 */

/* delta * 1e8 / r as e8, without overflow for |delta| < 2^33, r >= 256 */

static int64_t
arc_e8_ratio(int64_t delta, svg_c_t r)
{
	return (((delta * 390625) / r) << 8);	/* 390625 = 1e8 / 256 */
}

static svg_c_t
arc_sat(int64_t v)
{
	if (v > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (v < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)v;
}

static int
flatten_arc(lws_svg_t *ctx, svg_c_t x1, svg_c_t y1, svg_c_t rx, svg_c_t ry,
	    int64_t phi, int large, int sweep, svg_c_t x2, svg_c_t y2)
{
	svg_c_t co = svg_cos(phi), si = svg_sin(phi);
	svg_c_t crx = rx, cry = ry;
	int64_t dx2, dy2, x1p, y1p, lam, coef = 0;
	int64_t cxp, cyp, t1, dt, dtn, th, hn;
	svg_c_t cx, cy;
	int nseg, i;

	if (x1 == x2 && y1 == y2)
		return 0;	/* zero-length arc */

	if (rx < 0)
		rx = (svg_c_t)-rx;
	if (ry < 0)
		ry = (svg_c_t)-ry;
	if (rx < 256 || ry < 256)	/* < 1/256 unit: degenerate */
		return pt_add(ctx, x2, y2);

	/* F.6.5.1-2: halved chord rotated into the ellipse frame */

	dx2 = ((int64_t)x1 - x2) / 2;
	dy2 = ((int64_t)y1 - y2) / 2;
	x1p = ((int64_t)co * dx2 + (int64_t)si * dy2) / SVG_Q16_1;
	y1p = ((int64_t)-si * dx2 + (int64_t)co * dy2) / SVG_Q16_1;

	/* F.6.5.5-6: lambda = x1p^2/rx^2 + y1p^2/ry^2, reduced by 8 bits */

	{
		int64_t xr = x1p >> 8, yr = y1p >> 8;
		int64_t rrx = (int64_t)rx >> 8, rry = (int64_t)ry >> 8;
		int64_t a = xr * xr, b = yr * yr;

		if (a > (1ll << 46))
			a = 1ll << 46;
		if (b > (1ll << 46))
			b = 1ll << 46;
		lam = (rrx ? (a * SVG_Q16_1) / (rrx * rrx) : (1ll << 46)) +
		      (rry ? (b * SVG_Q16_1) / (rry * rry) : (1ll << 46));
		if (lam > (1ll << 46))
			lam = 1ll << 46;
	}

	/*
	 * F.6.5.6-8: radii correction and the centre offset factor.  Since
	 * num / den reduces to (1 - lambda) / lambda, the rx^2 ry^2 sized
	 * products never need to be formed.
	 */

	if (lam > SVG_Q16_1) {
		svg_c_t s = arc_sat(svg_isqrt64(lam << 16));

		crx = svg_qmul(rx, s);
		cry = svg_qmul(ry, s);
		coef = 0;	/* num is 0 after correction */
	} else
		if (lam) {
			int64_t rat = ((SVG_Q16_1 - lam) * SVG_Q16_1) / lam;

			if (rat > (1ll << 32))
				rat = 1ll << 32;
			coef = svg_isqrt64(rat << 16);
			if (coef > (1ll << 22))
				coef = 1ll << 22;
			if (large == sweep)
				coef = -coef;
		} else
			coef = 0;	/* centre is the chord midpoint */

	/* F.6.5.10-11: ellipse frame centre offset, and absolute centre */

	{
		int64_t yr = y1p ? (y1p << 16) / cry : 0;
		int64_t xr = x1p ? (x1p << 16) / crx : 0;

		if (yr >  (1ll << 29)) yr =  1ll << 29;
		if (yr < -(1ll << 29)) yr = -(1ll << 29);
		if (xr >  (1ll << 29)) xr =  1ll << 29;
		if (xr < -(1ll << 29)) xr = -(1ll << 29);

		cxp = arc_sat(((int64_t)crx * ((coef * yr) >> 16)) >> 16);
		cyp = arc_sat(-(((int64_t)cry * ((coef * xr) >> 16)) >> 16));

		cx = arc_sat(((int64_t)x1 + x2) / 2 +
			     ((int64_t)co * cxp - (int64_t)si * cyp) /
								SVG_Q16_1);
		cy = arc_sat(((int64_t)y1 + y2) / 2 +
			     ((int64_t)si * cxp + (int64_t)co * cyp) /
								SVG_Q16_1);
	}

	/* F.6.5.4-5: start angle and sweep */

	t1 = svg_atan2(arc_e8_ratio(y1p - cyp, cry),
		       arc_e8_ratio(x1p - cxp, crx));
	dt = svg_atan2(arc_e8_ratio(-y1p - cyp, cry),
		       arc_e8_ratio(-x1p - cxp, crx)) - t1;

	if (!sweep && dt > 0)
		dt -= 2 * SVG_E8_PI;
	else
		if (sweep && dt < 0)
			dt += 2 * SVG_E8_PI;

	/* at most 4 quarter-arc pieces */

	{
		int64_t adt = dt < 0 ? -dt : dt;

		nseg = (int)((adt + 157079630) / 157079631);  /* ceil(|dt|/pi/2) */
	}
	if (nseg < 1)
		nseg = 1;
	if (nseg > 4)
		nseg = 4;

	dtn = dt / nseg;
	hn = (int64_t)svg_qmul(SVG_Q4_3, svg_tan(dtn / 4));
	th = t1;

	for (i = 0; i < nseg; i++) {
		int64_t th2 = th + dtn;
		svg_c_t c1 = svg_cos(th),  s1 = svg_sin(th);
		svg_c_t c2 = svg_cos(th2), s2 = svg_sin(th2);
		svg_c_t px1, py1, px2, py2, dx1, dy1, dx2n, dy2n;

		/* point and derivative on the rotated ellipse; unit
		 * products first, then scaled by the radii */

		px1 = svg_qsub(svg_qadd(cx, svg_qmul(svg_qmul(co, c1), crx)),
			       svg_qmul(svg_qmul(si, s1), cry));
		py1 = svg_qadd(svg_qadd(cy, svg_qmul(svg_qmul(si, c1), crx)),
			       svg_qmul(svg_qmul(co, s1), cry));
		px2 = svg_qsub(svg_qadd(cx, svg_qmul(svg_qmul(co, c2), crx)),
			       svg_qmul(svg_qmul(si, s2), cry));
		py2 = svg_qadd(svg_qadd(cy, svg_qmul(svg_qmul(si, c2), crx)),
			       svg_qmul(svg_qmul(co, s2), cry));

		dx1 = arc_sat(-(int64_t)svg_qmul(svg_qmul(co, s1), crx) -
			       (int64_t)svg_qmul(svg_qmul(si, c1), cry));
		dy1 = arc_sat(-(int64_t)svg_qmul(svg_qmul(si, s1), crx) +
			       (int64_t)svg_qmul(svg_qmul(co, c1), cry));
		dx2n = arc_sat(-(int64_t)svg_qmul(svg_qmul(co, s2), crx) -
				(int64_t)svg_qmul(svg_qmul(si, s2), cry));
		dy2n = arc_sat(-(int64_t)svg_qmul(svg_qmul(si, s2), crx) +
				(int64_t)svg_qmul(svg_qmul(co, c2), cry));

		{
			svg_c_t c1x = arc_sat((int64_t)px1 +
					((hn * dx1) >> 16));
			svg_c_t c1y = arc_sat((int64_t)py1 +
					((hn * dy1) >> 16));
			svg_c_t c2x = arc_sat((int64_t)px2 -
					((hn * dx2n) >> 16));
			svg_c_t c2y = arc_sat((int64_t)py2 -
					((hn * dy2n) >> 16));

			if (flatten_cubic(ctx, px1, py1, c1x, c1y, c2x, c2y,
					  i == nseg - 1 ? x2 : px2,
					  i == nseg - 1 ? y2 : py2, 0))
				return 1;
		}

		th = th2;
	}

	return 0;
}

/*
 * Path data parsing.  This runs at attribute completion (the whole d string
 * is available in the value buffer), building user-space subpaths into the
 * working arrays.
 */

static int
parse_path(lws_svg_t *ctx)
{
	const char *p = ctx->vbuf, *end = ctx->vbuf + ctx->vlen;
	char cmd = 0, prev_c = 0, prev_q = 0;
	svg_c_t sx = 0, sy = 0, px = 0, py = 0, pcx = 0, pcy = 0;
	svg_c_t a[6];

	work_reset(ctx);

	while (p < end) {
		int64_t v;

		p = svg_ws(p, end);
		if (p >= end)
			break;

		if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')) {
			cmd = *p++;
			p = svg_ws(p, end);	/* separators after the letter */
		} else
			if (!cmd)
				break;	/* numbers before any command */
		/* else: implicit repetition of the previous command */

		switch (cmd) {
		case 'M': case 'm': {
			svg_c_t x, y;
			char rel = cmd == 'm';
			int64_t vx, vy;

			p = svg_num(p, end, &vx);
			if (!p)
				return 0;
			p = svg_ws(p, end);
			p = svg_num(p, end, &vy);
			if (!p)
				return 0;

			x = svg_e8_to_c(vx);
			y = svg_e8_to_c(vy);
			if (rel) {
				x = svg_qadd(x, px);
				y = svg_qadd(y, py);
			}

			/*
			 * The first coordinate pair is a moveto; further
			 * pairs in the same command repeat as lineto
			 */

			if (ctx->wpts_count)
				cmd = rel ? 'l' : 'L';

			sx = px = x;
			sy = py = y;
			prev_c = prev_q = 0;
			if (sub_start(ctx, x, y))
				return 1;
			break;
		}

		case 'L': case 'l': {
			svg_c_t x, y;
			char rel = cmd == 'l';
			int64_t vx, vy;

			p = svg_num(p, end, &vx);
			if (!p)
				return 0;
			p = svg_ws(p, end);
			p = svg_num(p, end, &vy);
			if (!p)
				return 0;
			x = svg_e8_to_c(vx);
			y = svg_e8_to_c(vy);
			if (rel) {
				x = svg_qadd(x, px);
				y = svg_qadd(y, py);
			}
			if (pt_add(ctx, x, y))
				return 1;
			px = x;
			py = y;
			prev_c = prev_q = 0;
			break;
		}

		case 'H': case 'h': {
			svg_c_t x;
			int64_t vx;

			p = svg_num(p, end, &vx);
			if (!p)
				return 0;
			x = svg_e8_to_c(vx);
			if (cmd == 'h')
				x = svg_qadd(x, px);
			if (pt_add(ctx, x, py))
				return 1;
			px = x;
			prev_c = prev_q = 0;
			break;
		}

		case 'V': case 'v': {
			svg_c_t y;
			int64_t vy;

			p = svg_num(p, end, &vy);
			if (!p)
				return 0;
			y = svg_e8_to_c(vy);
			if (cmd == 'v')
				y = svg_qadd(y, py);
			if (pt_add(ctx, px, y))
				return 1;
			py = y;
			prev_c = prev_q = 0;
			break;
		}

		case 'C': case 'c': {
			int i;

			for (i = 0; i < 3; i++) {
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				a[i * 2] = svg_e8_to_c(v);
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				a[i * 2 + 1] = svg_e8_to_c(v);
			}
			if (cmd == 'c')
				for (i = 0; i < 6; i++)
					a[i] = svg_qadd(a[i],
							(i & 1) ? py : px);

			pcx = a[2];
			pcy = a[3];
			prev_c = 1;
			prev_q = 0;

			if (flatten_cubic(ctx, px, py, a[0], a[1], a[2], a[3],
					  a[4], a[5], 0))
				return 1;
			px = a[4];
			py = a[5];
			break;
		}

		case 'S': case 's': {
			svg_c_t x2, y2, x, y, x1, y1;
			int i;

			for (i = 0; i < 2; i++) {
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				a[i * 2] = svg_e8_to_c(v);
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				a[i * 2 + 1] = svg_e8_to_c(v);
			}
			x2 = a[0]; y2 = a[1]; x = a[2]; y = a[3];
			if (cmd == 's') {
				x2 = svg_qadd(x2, px); y2 = svg_qadd(y2, py);
				x = svg_qadd(x, px);   y = svg_qadd(y, py);
			}

			/* reflected previous control point when the
			 * previous command was cubic, else current point */

			x1 = prev_c ? (svg_c_t)(2 * (int64_t)px - pcx) : px;
			y1 = prev_c ? (svg_c_t)(2 * (int64_t)py - pcy) : py;

			pcx = x2;
			pcy = y2;
			prev_c = 1;
			prev_q = 0;

			if (flatten_cubic(ctx, px, py, x1, y1, x2, y2, x, y, 0))
				return 1;
			px = x;
			py = y;
			break;
		}

		case 'Q': case 'q': {
			svg_c_t x1, y1, x, y;
			int i;

			for (i = 0; i < 2; i++) {
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				a[i * 2] = svg_e8_to_c(v);
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				a[i * 2 + 1] = svg_e8_to_c(v);
			}
			x1 = a[0]; y1 = a[1]; x = a[2]; y = a[3];
			if (cmd == 'q') {
				x1 = svg_qadd(x1, px); y1 = svg_qadd(y1, py);
				x = svg_qadd(x, px);   y = svg_qadd(y, py);
			}

			pcx = x1;
			pcy = y1;
			prev_q = 1;
			prev_c = 0;

			if (flatten_quad(ctx, px, py, x1, y1, x, y))
				return 1;
			px = x;
			py = y;
			break;
		}

		case 'T': case 't': {
			svg_c_t x, y, x1, y1;
			int64_t vx, vy;

			p = svg_ws(p, end);
			p = svg_num(p, end, &vx);
			if (!p)
				return 0;
			p = svg_ws(p, end);
			p = svg_num(p, end, &vy);
			if (!p)
				return 0;
			x = svg_e8_to_c(vx);
			y = svg_e8_to_c(vy);
			if (cmd == 't') {
				x = svg_qadd(x, px);
				y = svg_qadd(y, py);
			}

			x1 = prev_q ? (svg_c_t)(2 * (int64_t)px - pcx) : px;
			y1 = prev_q ? (svg_c_t)(2 * (int64_t)py - pcy) : py;

			pcx = x1;
			pcy = y1;
			prev_q = 1;
			prev_c = 0;

			if (flatten_quad(ctx, px, py, x1, y1, x, y))
				return 1;
			px = x;
			py = y;
			break;
		}

		case 'A': case 'a': {
			svg_c_t rx, ry, x, y;
			int64_t rot = 0;
			int laf, sf, i;

			for (i = 0; i < 3; i++) {	/* rx ry x-axis-rot */
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				if (i < 2)
					a[i] = svg_e8_to_c(v);
				else
					rot = v;	/* degrees, e8 */
			}
			rx = a[0]; ry = a[1];

			/* the flags are single digits, separators optional */

			p = svg_ws(p, end);
			if (p >= end || *p < '0' || *p > '1')
				return 0;
			laf = *p++ - '0';
			p = svg_ws(p, end);
			if (p >= end || *p < '0' || *p > '1')
				return 0;
			sf = *p++ - '0';

			for (i = 0; i < 2; i++) {	/* x y */
				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				a[i] = svg_e8_to_c(v);
			}
			x = a[0];
			y = a[1];
			if (cmd == 'a') {
				x = svg_qadd(x, px);
				y = svg_qadd(y, py);
			}

			/* x-axis-rotation is degrees; the arc wants e8
			 * radians (9150 / 2^19 = pi / 180) */

			if (flatten_arc(ctx, px, py, rx, ry,
					(rot * 9150) >> 19, laf, sf, x, y))
				return 1;
			px = x;
			py = y;
			prev_c = prev_q = 0;
			break;
		}

		case 'Z': case 'z':
			/* close: current point returns to subpath start */

			if (ctx->wsubs_count) {
				ctx->wsubs[ctx->wsubs_count - 1].closed = 1;
				px = sx;
				py = sy;
			}
			prev_c = prev_q = 0;
			/* numbers following Z are invalid: stop here */
			cmd = 0;
			break;

		default:
			return 0;	/* unknown command: stop parsing */
		}
	}

	return 0;
}

/* parse a points="x,y x,y ..." list into a single working subpath */

/* parse a points="x,y x,y ..." list into a single working subpath */

static int
parse_points(lws_svg_t *ctx, char closed)
{
	const char *p = ctx->vbuf, *end = ctx->vbuf + ctx->vlen;
	svg_c_t x, y;
	int64_t v;
	int n = 0;

	work_reset(ctx);

	while (p < end) {
		p = svg_ws(p, end);
		if (p >= end)
			break;
		p = svg_num(p, end, &v);
		if (!p)
			break;
		x = svg_e8_to_c(v);
		p = svg_ws(p, end);
		p = svg_num(p, end, &v);
		if (!p)
			break;
		y = svg_e8_to_c(v);

		if (!n) {
			if (sub_start(ctx, x, y))
				return 1;
		} else
			if (pt_add(ctx, x, y))
				return 1;
		n++;
	}

	if (ctx->wsubs_count)
		ctx->wsubs[0].closed = closed;

	return 0;
}

/*
 * Commit the working geometry into the retained scene, applying the
 * effective CTM as it is copied.  Subpath sizes are derived from the next
 * subpath's start (or the working point count).
 */


/*
 * Commit the working geometry into the retained scene, applying the
 * effective CTM as it is copied.  The CTM application saturates, so
 * hostile transform stacks clip the geometry rather than producing
 * out-of-range or non-finite points.  Subpath sizes are derived from the
 * next subpath's start (or the working point count).
 */

static int
shape_commit(lws_svg_t *ctx, const svg_c_t m[6], uint32_t rgba, char rule)
{
	lws_svg_shape_t *sh;
	size_t i;

	if (!ctx->wsubs_count)
		return 0;

	if (ctx->nshapes >= LWS_SVG_MAX_SHAPES)
		return 1;

	sh = lwsac_use(&ctx->ac, sizeof(*sh), 0);
	if (!sh)
		return 1;

	memset(sh, 0, sizeof(*sh));
	sh->rgba = rgba;
	sh->rule = rule;

	for (i = 0; i < ctx->wsubs_count; i++) {
		uint32_t start = ctx->wsubs[i].start;
		uint32_t count = (i + 1 < ctx->wsubs_count ?
					ctx->wsubs[i + 1].start :
					(uint32_t)ctx->wpts_count) - start;
		lws_svg_sub_t *sub;
		uint32_t j;

		if (count < 3)
			/* cannot bound any fill area */
			continue;

		sub = lwsac_use(&ctx->ac, sizeof(*sub), 0);
		if (!sub)
			return 1;

		memset(sub, 0, sizeof(*sub));
		sub->closed = ctx->wsubs[i].closed;

		sub->pts = lwsac_use(&ctx->ac,
				     (size_t)count * sizeof(lws_svg_pt_t), 0);
		if (!sub->pts)
			return 1;
		sub->npts = count;

		for (j = 0; j < count; j++) {
			lws_svg_dpt_t *d = &ctx->wpts[start + j];

			sub->pts[j].x = svg_qadd(svg_qadd(
					svg_qmul(m[0], d->x),
					svg_qmul(m[2], d->y)), m[4]);
			sub->pts[j].y = svg_qadd(svg_qadd(
					svg_qmul(m[1], d->x),
					svg_qmul(m[3], d->y)), m[5]);
		}

		lws_dll2_add_tail(&sub->list, &sh->subs);
	}

	/* only shapes that actually kept geometry join the scene */

	if (!lws_dll2_is_empty(&sh->subs)) {
		lws_dll2_add_tail(&sh->list, &ctx->shapes);
		ctx->nshapes++;
	}

	return 0;
}

/*
 * Basic shapes.  Each fills the working arrays with user-space geometry.
 * Rounded rect corners and ellipses use the exact kappa control points, so
 * these need no trig.
 */

static int
build_rect(lws_svg_t *ctx, svg_pend_t *pd)
{
	svg_c_t x = pd->gok[0] ? pd->g[0] : 0, y = pd->gok[1] ? pd->g[1] : 0;
	svg_c_t w = pd->gok[2] ? pd->g[2] : 0, h = pd->gok[3] ? pd->g[3] : 0;
	svg_c_t rx = pd->gok[4] ? pd->g[4] : 0, ry = pd->gok[5] ? pd->g[5] : 0;

	if (w <= 0 || h <= 0)
		return 0;	/* nothing to fill */

	/* rx and ry default to each other, and clamp to half the extent */

	if (!rx && ry)
		rx = ry;
	if (!ry && rx)
		ry = rx;
	if (rx < 0)
		rx = (svg_c_t)-rx;
	if (ry < 0)
		ry = (svg_c_t)-ry;
	if (rx > w / 2)
		rx = w / 2;
	if (ry > h / 2)
		ry = h / 2;

	work_reset(ctx);
	if (sub_start(ctx, svg_qadd(x, rx), y))
		return 1;

	if (rx > 0 && ry > 0) {
		svg_c_t kx = (svg_c_t)(((int64_t)rx * SVG_KAPPA_Q) >> 16);
		svg_c_t ky = (svg_c_t)(((int64_t)ry * SVG_KAPPA_Q) >> 16);

		/* clockwise from the top edge, four quarter-arc corners */

		if (pt_add(ctx, svg_qsub(svg_qadd(x, w), rx), y))
			return 1;
		if (flatten_cubic(ctx, svg_qsub(svg_qadd(x, w), rx), y,
				  svg_qadd(svg_qsub(svg_qadd(x, w), rx), kx), y,
				  x + w, svg_qsub(svg_qadd(y, ry), ky),
				  x + w, y + ry, 0))
			return 1;
		if (pt_add(ctx, x + w, svg_qsub(svg_qadd(y, h), ry)))
			return 1;
		if (flatten_cubic(ctx, x + w, svg_qsub(svg_qadd(y, h), ry),
				  x + w,
				  svg_qadd(svg_qsub(svg_qadd(y, h), ry), ky),
				  svg_qadd(svg_qsub(svg_qadd(x, w), rx), kx), y + h,
				  svg_qsub(svg_qadd(x, w), rx), y + h, 0))
			return 1;
		if (pt_add(ctx, svg_qadd(x, rx), y + h))
			return 1;
		if (flatten_cubic(ctx, svg_qadd(x, rx), y + h,
				  svg_qsub(svg_qadd(x, rx), kx), y + h,
				  x, svg_qadd(svg_qsub(svg_qadd(y, h), ry), ky),
				  x, svg_qsub(svg_qadd(y, h), ry), 0))
			return 1;
		if (pt_add(ctx, x, svg_qadd(y, ry)))
			return 1;
		if (flatten_cubic(ctx, x, svg_qadd(y, ry), x,
				  svg_qsub(svg_qadd(y, ry), ky),
				  svg_qsub(svg_qadd(x, rx), kx), y,
				  svg_qadd(x, rx), y, 0))
			return 1;
	} else {
		if (pt_add(ctx, x + w, y) || pt_add(ctx, x + w, y + h) ||
		    pt_add(ctx, x, y + h) || pt_add(ctx, x, y))
			return 1;
	}

	ctx->wsubs[0].closed = 1;

	return 0;
}

static int
build_ellipse(lws_svg_t *ctx, svg_c_t cx, svg_c_t cy, svg_c_t rx, svg_c_t ry)
{
	svg_c_t kx = (svg_c_t)(((int64_t)rx * SVG_KAPPA_Q) >> 16);
	svg_c_t ky = (svg_c_t)(((int64_t)ry * SVG_KAPPA_Q) >> 16);

	if (rx <= 0 || ry <= 0)
		return 0;

	work_reset(ctx);
	if (sub_start(ctx, svg_qadd(cx, rx), cy))
		return 1;

	if (flatten_cubic(ctx, svg_qadd(cx, rx), cy, svg_qadd(cx, rx),
			  svg_qadd(cy, ky), svg_qadd(cx, kx),
			  svg_qadd(cy, ry), cx, svg_qadd(cy, ry), 0))
		return 1;
	if (flatten_cubic(ctx, cx, svg_qadd(cy, ry), svg_qsub(cx, kx),
			  svg_qadd(cy, ry), svg_qsub(cx, rx),
			  svg_qadd(cy, ky), svg_qsub(cx, rx), cy, 0))
		return 1;
	if (flatten_cubic(ctx, svg_qsub(cx, rx), cy, svg_qsub(cx, rx),
			  svg_qsub(cy, ky), svg_qsub(cx, kx),
			  svg_qsub(cy, ry), cx, svg_qsub(cy, ry), 0))
		return 1;
	if (flatten_cubic(ctx, cx, svg_qsub(cy, ry), svg_qadd(cx, kx),
			  svg_qsub(cy, ry), svg_qadd(cx, rx),
			  svg_qsub(cy, ky), svg_qadd(cx, rx), cy, 0))
		return 1;

	ctx->wsubs[0].closed = 1;

	return 0;
}


/*
 * Element classification
 */

static svg_ekind_t
classify(const char *name, char at_root)
{
	if (!strcmp(name, "svg"))
		return at_root ? SVEK_ROOT : SVEK_GROUP;
	if (!strcmp(name, "g") || !strcmp(name, "a") ||
	    !strcmp(name, "switch"))
		return SVEK_GROUP;

	if (!strcmp(name, "defs") || !strcmp(name, "title") ||
	    !strcmp(name, "desc") || !strcmp(name, "metadata") ||
	    !strcmp(name, "text") || !strcmp(name, "tspan") ||
	    !strcmp(name, "textPath") || !strcmp(name, "symbol") ||
	    !strcmp(name, "clipPath") || !strcmp(name, "mask") ||
	    !strcmp(name, "filter") || !strcmp(name, "marker") ||
	    !strcmp(name, "pattern") || !strcmp(name, "linearGradient") ||
	    !strcmp(name, "radialGradient") ||
	    !strcmp(name, "image") || !strcmp(name, "foreignObject") ||
	    !strcmp(name, "use") || !strcmp(name, "animate") ||
	    !strcmp(name, "set") || !strcmp(name, "animateMotion") ||
	    !strcmp(name, "animateTransform") || !strcmp(name, "script"))
		return SVEK_SUPPRESS;

	if (!strcmp(name, "style"))
		return SVEK_STYLE;

	if (!strcmp(name, "rect"))
		return SVEK_RECT;
	if (!strcmp(name, "circle"))
		return SVEK_CIRCLE;
	if (!strcmp(name, "ellipse"))
		return SVEK_ELLIPSE;
	if (!strcmp(name, "line"))
		return SVEK_LINE;
	if (!strcmp(name, "polyline"))
		return SVEK_POLYLINE;
	if (!strcmp(name, "polygon"))
		return SVEK_POLYGON;
	if (!strcmp(name, "path"))
		return SVEK_PATH;

	return SVEK_OTHER;
}

/* does the whitespace-delimited class list contain lit? */

static int
class_matches(const char *list, const char *lit)
{
	size_t ll = strlen(lit);
	const char *p = list;

	while (*p) {
		while (*p == ' ' || *p == '\t')
			p++;
		{
			const char *tok = p;

			while (*p && *p != ' ' && *p != '\t')
				p++;
			if ((size_t)(p - tok) == ll && !strncmp(tok, lit, ll))
				return 1;
		}
	}

	return 0;
}

/*
 * Compose the pending per-tag state on to an inherited level state,
 * applying the css cascade in priority order: presentation attributes,
 * then <style> rules (element selectors, then class, then id; later
 * rules of the same tier win), then the style="" attribute content.
 */

static void
level_compose(lws_svg_t *ctx, svg_lvl_t *parent, svg_pend_t *pd, svg_lvl_t *l,
	      const char *elem)
{
	uint32_t rgba = parent->rgba;
	int64_t alpha = LWS_SVG_ALPHA(rgba);	/* 0..255 in e8 units */
	int tier, i;

	*l = *parent;

	if (pd->has_transform)
		xf_comp(l->m, parent->m, pd->tm);

	if (pd->fill_present) {
		if (!LWS_SVG_ALPHA(pd->fill))
			alpha = 0;
		else {
			rgba = pd->fill & 0x00ffffff;
			alpha = LWS_SVG_ALPHA(pd->fill);
		}
	}

	if (pd->fillop_present && pd->fillop > 0)
		alpha = pd->fillop < SVG_E8_1 ?
			(alpha * pd->fillop + SVG_E8_1 / 2) / SVG_E8_1 : alpha;
	if (pd->op_present && pd->op > 0)
		alpha = pd->op < SVG_E8_1 ?
			(alpha * pd->op + SVG_E8_1 / 2) / SVG_E8_1 : alpha;

	if (pd->rule_present)
		l->rule = pd->rule;

	/* <style> rules, lowest tier first, document order inside a tier */

	for (tier = 0; tier < 3; tier++)
		for (i = 0; i < (int)ctx->css_count; i++) {
			svg_cssrule_t *r = &ctx->css[i];

			if (r->tier != tier)
				continue;

			if (tier == 0) {
				if (strcmp(r->sel, elem))
					continue;
			} else
				if (tier == 1) {
					if (!pd->cls[0] ||
					    !class_matches(pd->cls, r->sel + 1))
						continue;
				} else
					if (strcmp(r->sel + 1, pd->id))
						continue;

			if (r->fill_set) {
				if (!LWS_SVG_ALPHA(r->fill))
					alpha = 0;
				else {
					rgba = r->fill & 0x00ffffff;
					alpha = LWS_SVG_ALPHA(r->fill);
				}
			}
			if (r->fillop_set && r->fillop > 0)
				alpha = r->fillop < SVG_E8_1 ?
					(alpha * r->fillop + SVG_E8_1 / 2) /
							SVG_E8_1 : alpha;
			if (r->op_set && r->op > 0)
				alpha = r->op < SVG_E8_1 ?
					(alpha * r->op + SVG_E8_1 / 2) /
							SVG_E8_1 : alpha;
			if (r->rule_set)
				l->rule = r->rule;
		}

	/* style="" attribute content wins over everything above */

	if (pd->sa_fill_present) {
		if (!LWS_SVG_ALPHA(pd->sa_fill))
			alpha = 0;
		else {
			rgba = pd->sa_fill & 0x00ffffff;
			alpha = LWS_SVG_ALPHA(pd->sa_fill);
		}
	}
	if (pd->sa_fillop_present && pd->sa_fillop > 0)
		alpha = pd->sa_fillop < SVG_E8_1 ?
			(alpha * pd->sa_fillop + SVG_E8_1 / 2) / SVG_E8_1 :
								alpha;
	if (pd->sa_op_present && pd->sa_op > 0)
		alpha = pd->sa_op < SVG_E8_1 ?
			(alpha * pd->sa_op + SVG_E8_1 / 2) / SVG_E8_1 :
								alpha;

	if (alpha > 255)
		alpha = 255;

	l->rgba = (rgba & 0x00ffffff) |
			((uint32_t)((alpha * 2 + 1) / 2) << 24);

	if (pd->sa_rule_present)
		l->rule = pd->sa_rule;
}

/* numeric attribute helper: match attr name to a slot for the element kind */

static int
geom_slot(svg_ekind_t k, const char *aname)
{
	switch (k) {
	case SVEK_RECT:
		if (!strcmp(aname, "x"))      return 0;
		if (!strcmp(aname, "y"))      return 1;
		if (!strcmp(aname, "width"))  return 2;
		if (!strcmp(aname, "height")) return 3;
		if (!strcmp(aname, "rx"))     return 4;
		if (!strcmp(aname, "ry"))     return 5;
		break;
	case SVEK_CIRCLE:
		if (!strcmp(aname, "cx"))  return 0;
		if (!strcmp(aname, "cy"))  return 1;
		if (!strcmp(aname, "r"))   return 2;
		break;
	case SVEK_ELLIPSE:
		if (!strcmp(aname, "cx"))  return 0;
		if (!strcmp(aname, "cy"))  return 1;
		if (!strcmp(aname, "rx"))  return 2;
		if (!strcmp(aname, "ry"))  return 3;
		break;
	case SVEK_LINE:
		if (!strcmp(aname, "x1"))  return 0;
		if (!strcmp(aname, "y1"))  return 1;
		if (!strcmp(aname, "x2"))  return 2;
		if (!strcmp(aname, "y2"))  return 3;
		break;
	default:
		break;
	}

	return -1;
}

/*
 * Presentation property handling.  The same property set is understood
 * from three sources with different cascade priority: presentation
 * attributes, <style> css rules, and the style="" attribute.
 */

/* target-agnostic property parse: returns bits of what it understood */

#define SVG_PP_FILL	1
#define SVG_PP_FILLOP	2
#define SVG_PP_OP	4
#define SVG_PP_RULE	8

struct svg_pp {
	uint32_t	fill;
	int64_t		fillop, op;	/* e8 */
	char		rule;
};

static int
pp_parse(const char *name, size_t nl, const char *val, size_t vl,
	 struct svg_pp *out)
{
	int bits = 0;

	memset(out, 0, sizeof(*out));

	if (nl == 4 && !strncmp(name, "fill", 4)) {
		if (!svg_colour(val, vl, &out->fill))
			bits = SVG_PP_FILL;
	} else
		if (nl == 12 && !strncmp(name, "fill-opacity", 12)) {
			if (svg_num(val, val + vl, &out->fillop))
				bits = SVG_PP_FILLOP;
		} else
			if (nl == 7 && !strncmp(name, "opacity", 7)) {
				if (svg_num(val, val + vl, &out->op))
					bits = SVG_PP_OP;
			} else
				if (nl == 9 && !strncmp(name, "fill-rule", 9)) {
					out->rule = !!(vl == 7 &&
						       !strncmp(val, "evenodd", 7));
					bits = SVG_PP_RULE;
				}

	return bits;
}

/* apply one property item to the style="" layer of the pending state */

static void
style_prop(lws_svg_t *ctx, const char *name, size_t nl,
	   const char *val, size_t vl)
{
	svg_pend_t *pd = &ctx->pend;
	struct svg_pp pp;

	switch (pp_parse(name, nl, val, vl, &pp)) {
	case SVG_PP_FILL:
		pd->sa_fill_present = 1;
		pd->sa_fill = pp.fill;
		break;
	case SVG_PP_FILLOP:
		pd->sa_fillop_present = 1;
		pd->sa_fillop = pp.fillop;
		break;
	case SVG_PP_OP:
		pd->sa_op_present = 1;
		pd->sa_op = pp.op;
		break;
	case SVG_PP_RULE:
		pd->sa_rule_present = 1;
		pd->sa_rule = pp.rule;
		break;
	default:
		break;
	}
}

/*
 * <style> css parsing.  The stylesheet text has been accumulated in
 * ctx->vbuf; rules with one simple selector (element name, .class or
 * #id) and known properties are kept, later rules overriding earlier
 * ones of the same tier when applied.  Anything else is skipped
 * leniently: comments, at-rules (with their braces), and unusable
 * selectors.
 */

static int
css_sel_parse(const char *s, size_t len, svg_cssrule_t *r)
{
	memset(r, 0, sizeof(*r));

	if (!len || len >= sizeof(r->sel))
		return 1;

	memcpy(r->sel, s, len);
	r->sel[len] = '\0';

	if (r->sel[0] == '.') {
		r->tier = 1;
		if (len < 2)
			return 1;
	} else
		if (r->sel[0] == '#') {
			r->tier = 2;
			if (len < 2)
				return 1;
		} else {
			size_t i;

			r->tier = 0;
			for (i = 0; i < len; i++)
				if (!((r->sel[i] >= 'a' && r->sel[i] <= 'z') ||
				      (r->sel[i] >= 'A' && r->sel[i] <= 'Z') ||
				      (r->sel[i] >= '0' && r->sel[i] <= '9') ||
				      r->sel[i] == '-' || r->sel[i] == '_'))
					return 1;  /* pseudo-class, etc */
		}

	return 0;
}

static void
parse_css(lws_svg_t *ctx)
{
	const char *p = ctx->vbuf, *end = ctx->vbuf + ctx->vlen;

	/* a CDATA-wrapped stylesheet keeps its closing delimiter */

	if (ctx->vlen > 3 && !strncmp(end - 3, "]]>", 3)) {
		end -= 3;
		ctx->vlen -= 3;
	}

	while (p < end) {
		const char *ds, *de;
		struct svg_pp pp[8];
		int bits[8], np = 0, i;
		svg_cssrule_t r;

		/* skip whitespace and comments */

		while (p < end) {
			if (isxmlws(*p)) {
				p++;
				continue;
			}
			if ((size_t)(end - p) >= 2 && *p == '/' && p[1] == '*') {
				p += 2;
				while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
					p++;
				p = p + 2 < end ? p + 2 : end;
				continue;
			}
			break;
		}
		if (p >= end)
			break;

		if (*p == '@') {
			/* skip the at-rule and its declaration block */

			int depth = 0;

			while (p < end) {
				if (*p == '{')
					depth++;
				if (*p == '}') {
					if (!--depth) {
						p++;
						break;
					}
				}
				if (*p == ';' && !depth) {
					p++;
					break;
				}
				p++;
			}
			continue;
		}

		/* selector list up to '{' */

		ds = p;
		while (p < end && *p != '{' && *p != ';' && *p != '}')
			p++;
		if (p >= end || *p != '{')
			continue;	/* junk between rules */
		de = p++;

		/* declarations up to '}' */

		while (p < end && *p != '}') {
			const char *n = p, *v;

			while (p < end && *p != ':' && *p != ';' && *p != '}')
				p++;
			if (p >= end || *p != ':') {
				if (p < end && *p != '}')
					p++;
				continue;
			}
			v = ++p;
			while (p < end && *p != ';' && *p != '}')
				p++;

			{
				size_t nl = (size_t)(v - 1 - n);

				while (nl && isxmlws(n[nl - 1]))
					nl--;
				while (v < p && isxmlws(*v))
					v++;

				if (nl && p > v && np < 8) {
					bits[np] = pp_parse(n, nl, v,
							    (size_t)(p - v),
							    &pp[np]);
					np++;
				}
			}

			if (p < end && *p == ';')
				p++;
		}
		if (p < end)
			p++;		/* consume '}' */

		/* the selector list may be comma-separated */

		{
			const char *s = ds;

			while (s < de) {
				const char *c = s;

				while (c < de && *c != ',')
					c++;
				while (s < c && isxmlws(*s))
					s++;
				while (c > s && isxmlws(c[-1]))
					c--;

				if (!css_sel_parse(s, (size_t)(c - s), &r)) {
					for (i = 0; i < np; i++) {
						if (bits[i] & SVG_PP_FILL) {
							r.fill_set = 1;
							r.fill = pp[i].fill;
						}
						if (bits[i] & SVG_PP_FILLOP) {
							r.fillop_set = 1;
							r.fillop = pp[i].fillop;
						}
						if (bits[i] & SVG_PP_OP) {
							r.op_set = 1;
							r.op = pp[i].op;
						}
						if (bits[i] & SVG_PP_RULE) {
							r.rule_set = 1;
							r.rule = pp[i].rule;
						}
					}

					if (ctx->css_count < LWS_SVG_MAX_CSSRULES) {
						if (!ctx->css_count) {
							ctx->css = lws_zalloc(
								sizeof(*ctx->css) *
								LWS_SVG_MAX_CSSRULES,
								__func__);
						}
						if (ctx->css)
							ctx->css[ctx->css_count++] = r;
					}
				}

				s = c < de ? c + 1 : de;
			}
		}
	}
}


/*
 * Attribute completion.  The element kind is known, and the value is
 * NUL-terminated in ctx->vbuf with its length in ctx->vlen.
 */

static int
attr_complete(lws_svg_t *ctx)
{
	svg_pend_t *pd = &ctx->pend;
	const char *n = ctx->aname;

	/* root sizing attributes */

	if (ctx->ekind == SVEK_ROOT) {
		if (!strcmp(n, "width")) {
			if (!svg_len(ctx->vbuf, ctx->vlen, &ctx->width,
				     &ctx->unit_w))
				ctx->has_w = 1;

			return 0;
		}
		if (!strcmp(n, "height")) {
			if (!svg_len(ctx->vbuf, ctx->vlen, &ctx->height,
				     &ctx->unit_h))
				ctx->has_h = 1;

			return 0;
		}
		if (!strcmp(n, "viewBox")) {
			const char *p = ctx->vbuf,
				   *end = ctx->vbuf + ctx->vlen;
			int i;

			for (i = 0; i < 4; i++) {
				int64_t v;

				p = svg_ws(p, end);
				p = svg_num(p, end, &v);
				if (!p)
					return 0;
				ctx->vb[i] = svg_e8_to_c(v);
			}
			ctx->has_vb = 1;

			return 0;
		}
		if (!strcmp(n, "preserveAspectRatio")) {
			const char *p = ctx->vbuf,
				   *end = ctx->vbuf + ctx->vlen;

			p = svg_ws(p, end);

			if ((size_t)(end - p) >= 4 &&
			    !strncmp(p, "none", 4)) {
				ctx->par_none = 1;
			} else {
				/* "xMinYMin" .. "xMaxYMax", 8 chars */

				if ((size_t)(end - p) >= 8) {
					static const char *const axn[] = {
						"xMin", "xMid", "xMax" };
					int i;

					for (i = 0; i < 3; i++)
						if (!strncmp(p, axn[i], 4)) {
							ctx->par_ax = (uint8_t)i;
							break;
						}
					/* p[4] == 'Y'; p[5..7] = Min/Mid/Max */
					ctx->par_ay = p[5] != 'M' ? 0 :
							p[6] == 'a' ? 2 : 1;
				}

				p = svg_ws(p + 8, end);
				if ((size_t)(end - p) >= 5 &&
				    !strncmp(p, "slice", 5))
					ctx->par_slice = 1;
			}

			return 0;
		}
	}

	/* presentation attributes on any element */

	if (!strcmp(n, "fill")) {
		uint32_t rgba;

		if (!svg_colour(ctx->vbuf, ctx->vlen, &rgba)) {
			pd->fill_present = 1;
			pd->fill = rgba;
		}

		return 0;
	}

	if (!strcmp(n, "fill-opacity") || !strcmp(n, "opacity")) {
		int64_t v;

		if (svg_num(ctx->vbuf, ctx->vbuf + ctx->vlen, &v)) {
			if (n[4] == '-') {
				pd->fillop_present = 1;
				pd->fillop = v;
			} else {
				pd->op_present = 1;
				pd->op = v;
			}
		}

		return 0;
	}

	if (!strcmp(n, "fill-rule")) {
		pd->rule_present = 1;
		pd->rule = !!(ctx->vlen == 7 &&
			      !strncmp(ctx->vbuf, "evenodd", 7));

		return 0;
	}

	if (!strcmp(n, "transform")) {
		xf_ident(pd->tm);
		pd->has_transform = 1;
		svg_transforms(ctx->vbuf, ctx->vlen, pd->tm);

		return 0;
	}

	if (!strcmp(n, "class")) {
		/* css class names, whitespace separated */

		size_t o = 0, i;

		for (i = 0; i < ctx->vlen && o < sizeof(pd->cls) - 1; i++) {
			char cc = isxmlws(ctx->vbuf[i]) ? ' ' : ctx->vbuf[i];

			if (cc == ' ' && (!o || pd->cls[o - 1] == ' '))
				continue;
			pd->cls[o++] = cc;
		}
		while (o && pd->cls[o - 1] == ' ')
			o--;
		pd->cls[o] = '\0';

		return 0;
	}

	if (!strcmp(n, "id")) {
		size_t o, i;

		for (i = o = 0; i < ctx->vlen && o < sizeof(pd->id) - 1; i++)
			if (!isxmlws(ctx->vbuf[i]))
				pd->id[o++] = ctx->vbuf[i];
		pd->id[o] = '\0';

		return 0;
	}

	if (!strcmp(n, "style")) {
		const char *p = ctx->vbuf, *end = ctx->vbuf + ctx->vlen;

		while (p < end) {
			const char *cs = p, *nm, *val;
			size_t nl, vl;

			/* one "name: value;" item */

			while (p < end && *p != ';')
				p++;
			nm = cs;
			while (nm < p && isxmlws(*nm))
				nm++;
			val = cs;
			while (val < p && *val != ':')
				val++;
			if (val < p) {
				nl = (size_t)(val - nm);
				val++;
				vl = (size_t)(p - val);
				while (nl && isxmlws(nm[nl - 1]))
					nl--;
				while (vl && isxmlws(*val)) {
					val++;
					vl--;
				}
				while (vl && isxmlws(val[vl - 1]))
					vl--;

				if (nl && vl)
					style_prop(ctx, nm, nl, val, vl);
			}

			if (p < end)
				p++;
		}

		return 0;
	}

	/* geometry attributes */

	{
		int slot = geom_slot(ctx->ekind, n);

		if (slot >= 0) {
			int64_t v;

			if (svg_num(ctx->vbuf, ctx->vbuf + ctx->vlen, &v)) {
				pd->gok[slot] = 1;
				pd->g[slot] = svg_e8_to_c(v);
			}

			return 0;
		}
	}

	if (!strcmp(n, "d") && ctx->ekind == SVEK_PATH) {
		pd->has_d = 1;

		if (ctx->root_seen && !ctx->stk[ctx->depth].suppress)
			return parse_path(ctx);

		return 0;
	}

	if (!strcmp(n, "points") &&
	    (ctx->ekind == SVEK_POLYGON || ctx->ekind == SVEK_POLYLINE)) {
		pd->has_points = 1;

		if (ctx->root_seen && !ctx->stk[ctx->depth].suppress)
			return parse_points(ctx,
					    ctx->ekind == SVEK_POLYGON);

		return 0;
	}

	return 0;
}

/*
 * Element dispatch at tag end.  For containers this pushes the style stack
 * (unless self-closing); shapes build and commit their geometry.
 */

static int
element_open(lws_svg_t *ctx, char selfclose)
{
	svg_ekind_t k = ctx->ekind;
	svg_pend_t *pd = &ctx->pend;
	int ret = 0;

	switch (k) {
	case SVEK_ROOT:
		if (!ctx->root_seen) {
			ctx->root_seen = 1;

			/* the root is also a styling container */

			level_compose(ctx, &ctx->stk[0], pd, &ctx->stk[0],
				     "svg");

			if (ctx->has_vb && ctx->vb[2] > 0 && ctx->vb[3] > 0) {
				svg_c_t mn = ctx->vb[2] < ctx->vb[3] ?
						ctx->vb[2] : ctx->vb[3];

				/*
				 * Flattening tolerance ~ the smaller viewBox
				 * dimension / 1024, clamped to a sub-pixel
				 * band in user units.  Basing it on the
				 * smaller dimension matters for wide, short
				 * logo viewBoxes, where a tolerance derived
				 * from the width is coarser than the glyph
				 * features and sands the curve extrema down
				 * (visible as notches where path segments
				 * join at horizontal tangents).
				 */

				ctx->tol = (svg_c_t)(mn >> 10);
				if (ctx->tol < 16)	/* 1/4096 */
					ctx->tol = 16;
				if (ctx->tol > 8192)	/* 1/8 */
					ctx->tol = 8192;
			}

			if (selfclose)
				ctx->doc_complete = 1;

			break;
		}
		/* a nested <svg> acts as a group */
		/* fallthru */

	case SVEK_GROUP:
		if (!selfclose && ctx->root_seen) {
			if (ctx->depth + 1 >= LWS_SVG_MAX_DEPTH)
				return 1;

			level_compose(ctx, &ctx->stk[ctx->depth], pd,
				      &ctx->stk[ctx->depth + 1], ctx->name);
			ctx->depth++;
		}
		break;

	case SVEK_STYLE:
		/*
		 * The stylesheet text is accumulated from character data
		 * and CDATA into the value buffer, and parsed into rules
		 * when the element closes.  Any children are suppressed.
		 */

		if (!selfclose) {
			if (ctx->depth + 1 >= LWS_SVG_MAX_DEPTH)
				return 1;

			ctx->stk[ctx->depth + 1] = ctx->stk[ctx->depth];
			ctx->stk[ctx->depth + 1].suppress = 1;
			ctx->depth++;
			ctx->in_style = 1;
			ctx->vlen = 0;
		}
		break;

	case SVEK_SUPPRESS:
	case SVEK_OTHER:
		if (!selfclose) {
			if (ctx->depth + 1 >= LWS_SVG_MAX_DEPTH)
				return 1;

			ctx->stk[ctx->depth + 1] = ctx->stk[ctx->depth];
			ctx->stk[ctx->depth + 1].suppress = 1;
			ctx->depth++;
		}
		break;

	case SVEK_RECT:
	case SVEK_CIRCLE:
	case SVEK_ELLIPSE:
	case SVEK_LINE:
	case SVEK_POLYLINE:
	case SVEK_POLYGON:
	case SVEK_PATH:
		if (!ctx->root_seen || ctx->stk[ctx->depth].suppress)
			break;

		/*
		 * Build the geometry unless the path data / points attribute
		 * already built it at attribute completion, then commit it
		 * with the effective CTM.
		 */

		switch (k) {
		case SVEK_RECT:
			ret = build_rect(ctx, pd);
			break;
		case SVEK_CIRCLE:
			ret = build_ellipse(ctx,
					pd->gok[0] ? pd->g[0] : 0,
					pd->gok[1] ? pd->g[1] : 0,
					pd->gok[2] ? pd->g[2] : 0,
					pd->gok[2] ? pd->g[2] : 0);
			break;
		case SVEK_ELLIPSE:
			ret = build_ellipse(ctx,
					pd->gok[0] ? pd->g[0] : 0,
					pd->gok[1] ? pd->g[1] : 0,
					pd->gok[2] ? pd->g[2] : 0,
					pd->gok[3] ? pd->g[3] : 0);
			break;
		case SVEK_POLYLINE:
		case SVEK_POLYGON:
			if (!pd->has_points)
				work_reset(ctx);
			break;
		case SVEK_PATH:
			if (!pd->has_d)
				work_reset(ctx);
			break;
		default:
			work_reset(ctx);
			break;
		}

		if (ret)
			return 1;

		/* line is stroke-only: nothing to fill */

		if (k != SVEK_LINE) {
			svg_lvl_t eff;

			/* compose the shape's own presentation deltas on to
			 * the inherited level state, and commit with that */

			level_compose(ctx, &ctx->stk[ctx->depth], pd, &eff,
				      ctx->name);

			if (shape_commit(ctx, eff.m, eff.rgba, eff.rule))
				return 1;
		}

		work_reset(ctx);
		break;
	}

	/* the pending state applies to this element only */

	memset(pd, 0, sizeof(*pd));
	xf_ident(pd->tm);

	return 0;
}

static void
element_close(lws_svg_t *ctx, const char *name)
{
	if (name && !strcmp(name, "style") && ctx->in_style) {
		ctx->vbuf[ctx->vlen] = '\0';
		parse_css(ctx);
		ctx->in_style = 0;
	}

	if (!ctx->depth) {
		/* closing at root level completes the document */

		if (ctx->root_seen) {
			ctx->doc_complete = 1;
			ctx->ts = SXS_DONE;
		}

		return;
	}

	ctx->depth--;
}

/* append bytes to the attribute value accumulation buffer */

static int
vappend(lws_svg_t *ctx, const char *b, size_t len)
{
	if (ctx->vlen + len + 1 >= LWS_SVG_MAX_ATTRVAL)
		return -1;

	if (ctx->vlen + len + 2 >= ctx->vsize) {
		size_t ns = ctx->vsize;
		char *n;

		while (ctx->vlen + len + 2 >= ns)
			ns *= 2;
		n = lws_realloc(ctx->vbuf, ns, __func__);
		if (!n)
			return -1;
		ctx->vbuf = n;
		ctx->vsize = ns;
	}

	while (len--)
		ctx->vbuf[ctx->vlen++] = *b++;

	return 0;
}

/*
 * XML tokenizer.  Processes one byte at a time so it can stop anywhere for
 * streaming.  Returns 0 to continue, 1 to stop because the root tag parsed
 * (hold-at-metadata), or -1 on fatal problems.
 *
 * Some transitions need the triggering byte reprocessed in the new state;
 * those recurse one level.
 */

static const char bang_cdata[] = "[CDATA[";
static const char cdata_end[]  = "]]>";

static int
tok_step(lws_svg_t *ctx, const uint8_t c, char hold)
{
	switch (ctx->ts) {
	case SXS_PROLOG:
		if (c == '<') {
			ctx->name[0] = '\0';
			ctx->ts = SXS_TAGNAME;
		}
		break;

	case SXS_TAGNAME:
		if (!ctx->name[0] && c == '?') {
			ctx->ts = SXS_PI;
			ctx->sub_step = 0;
			break;
		}
		if (!ctx->name[0] && c == '!') {
			ctx->ts = SXS_BANG;
			ctx->bang_step = 0;
			ctx->sub_step = 0;
			break;
		}
		if (!ctx->name[0] && c == '/') {
			ctx->ts = SXS_CLOSENAME;
			ctx->name[0] = '\0';
			break;
		}
		if (c == '>' || c == '/' || isxmlws(c)) {
			if (!ctx->name[0]) {
				if (c == '>')
					ctx->ts = SXS_TEXT;
				break;	/* nothing accumulated yet */
			}

			ctx->ekind = classify(ctx->name, !ctx->root_seen);
			ctx->vlen = 0;

			if (c == '>') {
				/* an element with no attributes */

				if (element_open(ctx, 0))
					return -1;
				ctx->ts = ctx->doc_complete ?
							SXS_DONE : SXS_TEXT;

				if (hold && ctx->root_seen &&
				    !ctx->doc_complete && !ctx->depth)
					return 1;	/* hold at metadata */
				break;
			}

			ctx->saw_slash = c == '/';
			ctx->ts = SXS_ATTRS;
			break;
		}
		{
			size_t l = strlen(ctx->name);

			if (l < LWS_SVG_MAX_NAME) {
				ctx->name[l++] = (char)c;
				ctx->name[l] = '\0';
			}
		}
		break;

	case SXS_ATTRS:
		if (c == '>') {
			if (element_open(ctx, ctx->saw_slash))
				return -1;
			ctx->saw_slash = 0;
			ctx->ts = ctx->doc_complete ? SXS_DONE : SXS_TEXT;

			if (hold && ctx->root_seen && !ctx->doc_complete &&
			    !ctx->depth)
				return 1;	/* hold at metadata */
			break;
		}
		if (c == '/') {
			ctx->saw_slash = 1;
			break;
		}
		if (isxmlws(c))
			break;
		ctx->aname[0] = '\0';
		ctx->saw_slash = 0;
		ctx->ts = SXS_ATTRNAME;
		return tok_step(ctx, c, hold);	/* reprocess first name char */

	case SXS_ATTRNAME:
		if (c == '=') {
			ctx->ts = SXS_ATTRVALQ;
			break;
		}
		if (isxmlws(c)) {
			ctx->ts = SXS_ATTREQ;
			break;
		}
		if (c == '>' || c == '/') {
			/* valueless attr: ignore it, dispatch */

			if (element_open(ctx, ctx->saw_slash || c == '/'))
				return -1;
			ctx->saw_slash = 0;
			ctx->ts = ctx->doc_complete ? SXS_DONE : SXS_TEXT;
			if (hold && ctx->root_seen && !ctx->doc_complete &&
			    !ctx->depth)
				return 1;
			break;
		}
		{
			size_t l = strlen(ctx->aname);

			if (l < LWS_SVG_MAX_NAME) {
				ctx->aname[l++] = (char)c;
				ctx->aname[l] = '\0';
			}
		}
		break;

	case SXS_ATTREQ:
		if (c == '=') {
			ctx->ts = SXS_ATTRVALQ;
			break;
		}
		if (isxmlws(c))
			break;
		if (c == '>' || c == '/') {
			if (element_open(ctx, ctx->saw_slash || c == '/'))
				return -1;
			ctx->saw_slash = 0;
			ctx->ts = ctx->doc_complete ? SXS_DONE : SXS_TEXT;
			if (hold && ctx->root_seen && !ctx->doc_complete &&
			    !ctx->depth)
				return 1;
			break;
		}
		/* a new attribute begins: the previous was valueless */
		ctx->aname[0] = '\0';
		ctx->ts = SXS_ATTRNAME;
		return tok_step(ctx, c, hold);

	case SXS_ATTRVALQ:
		if (c == '\'' || c == '"') {
			ctx->quote = (uint8_t)c;
			ctx->vlen = 0;
			ctx->ts = SXS_ATTRVAL;
			break;
		}
		if (isxmlws(c))
			break;
		/* lenient unquoted value */
		ctx->quote = 0;
		ctx->vlen = 0;
		ctx->ts = SXS_ATTRVAL;
		return tok_step(ctx, c, hold);

	case SXS_ATTRVAL:
		if (ctx->quote) {
			if ((uint8_t)c == ctx->quote) {
				ctx->vbuf[ctx->vlen] = '\0';
				if (attr_complete(ctx))
					return -1;
				ctx->ts = SXS_ATTRS;
				break;
			}
		} else
			if (isxmlws(c) || c == '>' || c == '/') {
				ctx->vbuf[ctx->vlen] = '\0';
				attr_complete(ctx);
				ctx->ts = SXS_ATTRS;
				if (c == '>')
					return tok_step(ctx, c, hold);
				ctx->saw_slash = c == '/';
				break;
			}
		if (c == '&') {
			ctx->elen = 0;
			ctx->ts = SXS_ATTRVAL_ENT;
			break;
		}
		if (vappend(ctx, (const char *)&c, 1))
			return -1;
		break;

	case SXS_ATTRVAL_ENT:
		if (c == ';') {
			static const struct {
				const char	*n;
		uint32_t	cp;
			} named[] = {
				{ "amp",	'&' },
				{ "lt",		'<' },
				{ "gt",		'>' },
				{ "quot",	'"' },
				{ "apos",	'\'' },
			};
			char out[4];
			size_t nl = ctx->elen;
			uint32_t cp = 0;
			int i, ok = 0, n = 0;

			ctx->ts = SXS_ATTRVAL;

			if (nl > 1 && ctx->ebuf[0] == '#') {
				int hex = nl > 2 &&
					  (ctx->ebuf[1] | 0x20) == 'x';

				ok = 1;
				for (i = hex ? 2 : 1; i < (int)nl; i++) {
					int v = hex ? hexv(ctx->ebuf[i]) :
						      ctx->ebuf[i] - '0';

					if (v < 0 || (!hex && v > 9)) {
						ok = 0;
						break;
					}
					cp = cp * (uint32_t)(hex ? 16 : 10) +
					     (uint32_t)v;
				}
			} else
				for (i = 0; i < (int)LWS_ARRAY_SIZE(named); i++)
					if (nl == strlen(named[i].n) &&
					    !strncmp(ctx->ebuf, named[i].n, nl)) {
						cp = named[i].cp;
						ok = 1;
						break;
					}

			if (ok && cp < 0x80)
				out[n++] = (char)cp;
			else
				if (ok && cp < 0x800) {
					out[n++] = (char)(0xc0 | (cp >> 6));
					out[n++] = (char)(0x80 | (cp & 0x3f));
				} else
					if (ok && cp < 0x10000) {
						out[n++] = (char)(0xe0 | (cp >> 12));
						out[n++] = (char)(0x80 | ((cp >> 6) & 0x3f));
						out[n++] = (char)(0x80 | (cp & 0x3f));
					} else {
						/* unknown or out of range:
						 * emit the raw text */

						out[n++] = '&';
						for (i = 0; (size_t)i < nl &&
							    n < (int)sizeof(out); i++)
							out[n++] = ctx->ebuf[i];
					}

			for (i = 0; i < n; i++) {
				char cc = out[i];

				if (vappend(ctx, &cc, 1))
					return -1;
			}
			break;
		}

		if ((size_t)ctx->elen + 1 >= sizeof(ctx->ebuf)) {
			/* overlong entity: flush raw and return to the value */

			char cc = '&';
			size_t k;

			ctx->ts = SXS_ATTRVAL;
			if (vappend(ctx, &cc, 1))
				return -1;
			for (k = 0; k < ctx->elen; k++)
				if (vappend(ctx, &ctx->ebuf[k], 1))
					return -1;
			break;
		}
		ctx->ebuf[ctx->elen++] = (char)c;
		break;

	case SXS_TEXT:
		if (c == '<') {
			ctx->name[0] = '\0';
			ctx->ts = SXS_TAGNAME;
			break;
		}
		if (ctx->in_style == 1) {
			/* accumulate stylesheet character data */

			char cc = (char)c;

			if (vappend(ctx, &cc, 1))
				ctx->in_style = 2;  /* too large: stop collecting */
		}
		break;

	case SXS_CLOSENAME:
		if (c == '>') {
			element_close(ctx, ctx->name);
			ctx->ts = ctx->doc_complete ? SXS_DONE : SXS_TEXT;
			break;
		}
		if (isxmlws(c))
			break;
		{
			size_t l = strlen(ctx->name);

			if (l < LWS_SVG_MAX_NAME) {
				ctx->name[l++] = (char)c;
				ctx->name[l] = '\0';
			}
		}
		break;

	case SXS_BANG:
		/* distinguish <!--, <![CDATA[ and generic <! */

		if (ctx->bang_step == 0) {
			if (c == '-') {
				ctx->bang_step = 1;
				break;
			}
			if (c == '[') {
				/* seen "<![", the rest of "[CDATA[" */
				ctx->bang_step = 2;
				ctx->sub_step = 1;
				break;
			}
			ctx->ts = SXS_DOCTYPE;
			break;
		}
		if (ctx->bang_step == 1) {
			if (c == '-') {
				ctx->ts = SXS_COMMENT;
				ctx->sub_step = 0;
			} else
				ctx->ts = SXS_DOCTYPE;	/* "<!-" junk */
			break;
		}
		/* bang_step 2: matching [CDATA[ */

		if (c == (uint8_t)bang_cdata[ctx->sub_step]) {
			if (++ctx->sub_step >= (uint8_t)(sizeof(bang_cdata) - 1))
				ctx->ts = SXS_CDATA;
			break;
		}
		ctx->ts = SXS_DOCTYPE;
		break;

	case SXS_COMMENT:
		/* track trailing '-'s: end on '-->' */

		if (c == '-') {
			ctx->sub_step++;
			break;
		}
		if (c == '>' && ctx->sub_step >= 2) {
			ctx->ts = SXS_TEXT;
			ctx->sub_step = 0;
			break;
		}
		ctx->sub_step = 0;
		break;

	case SXS_PI:
		/* end on '?>' */

		if (c == '>') {
			if (ctx->sub_step) {
				ctx->ts = SXS_TEXT;
				ctx->sub_step = 0;
			}
			break;
		}
		ctx->sub_step = c == '?';
		break;

	case SXS_DOCTYPE:
		if (c == '>')
			ctx->ts = SXS_TEXT;
		break;

	case SXS_CDATA:
		/* end on "]]>", with correct suffix recovery.  Inside a
		 * <style>, the content including the closing delimiter is
		 * accumulated; parse_css() strips a trailing "]]>". */

		if (ctx->in_style == 1) {
			char cc = (char)c;

			if (vappend(ctx, &cc, 1))
				ctx->in_style = 2;
		}

		if (c == (uint8_t)cdata_end[ctx->sub_step]) {
			if (++ctx->sub_step >= (uint8_t)(sizeof(cdata_end) - 1))
				ctx->ts = SXS_TEXT;
			break;
		}
		if (c == ']')
			ctx->sub_step = ctx->sub_step == 2 ? 2 : 1;
		else
			ctx->sub_step = 0;
		break;

	case SXS_DONE:
		break;
	}

	return 0;
}

/*
 * Public api
 */

lws_svg_t *
lws_svg_new(void)
{
	lws_svg_t *ctx = lws_zalloc(sizeof(*ctx), __func__);

	if (!ctx)
		return NULL;

	ctx->ts = SXS_PROLOG;
	ctx->tol = 6554;	/* 0.1 in Q16.16 */
	ctx->par_ax = ctx->par_ay = 1;	/* preserveAspectRatio default Mid */
	ctx->vsize = 256;
	ctx->vbuf = lws_malloc(ctx->vsize, __func__);
	if (!ctx->vbuf) {
		lws_free(ctx);
		return NULL;
	}

	xf_ident(ctx->stk[0].m);
	ctx->stk[0].rgba = LWS_SVG_RGBA(0, 0, 0, 0xff);
	xf_ident(ctx->pend.tm);

	return ctx;
}

void
lws_svg_free(lws_svg_t **svg)
{
	lws_svg_t *ctx = *svg;

	if (!ctx)
		return;

	lwsac_free(&ctx->ac);
	lws_free(ctx->wpts);
	lws_free(ctx->wsubs);
	lws_free(ctx->xings);
	lws_free(ctx->aa_d);
	lws_free(ctx->vbuf);
	lws_free(ctx->css);
	lws_free(ctx);

	*svg = NULL;
}

lws_stateful_ret_t
lws_svg_parse(lws_svg_t *ctx, const uint8_t **buf, size_t *len, char hold)
{
	if (ctx->fatal)
		return LWS_SRET_FATAL;

	if (ctx->doc_complete)
		return LWS_SRET_OK;

	while (*len) {
		const uint8_t c = *(*buf)++;
		int r = tok_step(ctx, c, hold);

		(*len)--;

		if (r == 1)
			/* stopped after the root tag parsed for hold mode */
			return LWS_SRET_OK;

		if (r < 0) {
			ctx->fatal = 1;
			return LWS_SRET_FATAL;
		}
	}

	return ctx->doc_complete ? LWS_SRET_OK : LWS_SRET_WANT_INPUT;
}

unsigned int
lws_svg_get_width(const lws_svg_t *ctx)
{
	if (!ctx->root_seen)
		return 0;

	if (ctx->has_w && !ctx->unit_w && ctx->width > 0)
		return (unsigned int)(((int64_t)ctx->width +
					SVG_Q16_1 / 2) >> 16);

	if (ctx->has_vb && ctx->vb[2] > 0)
		return (unsigned int)(((int64_t)ctx->vb[2] +
					SVG_Q16_1 / 2) >> 16);

	return 300;	/* CSS default replaced element size */
}

unsigned int
lws_svg_get_height(const lws_svg_t *ctx)
{
	if (!ctx->root_seen)
		return 0;

	if (ctx->has_h && !ctx->unit_h && ctx->height > 0)
		return (unsigned int)(((int64_t)ctx->height +
					SVG_Q16_1 / 2) >> 16);

	if (ctx->has_vb && ctx->vb[3] > 0)
		return (unsigned int)(((int64_t)ctx->vb[3] +
					SVG_Q16_1 / 2) >> 16);

	return 150;
}

char
lws_svg_get_doc_complete(const lws_svg_t *ctx)
{
	return ctx->doc_complete;
}

/*
 * Scanline rasterization
 */

static int
cross_cmp(const void *a, const void *b)
{
	const lws_svg_cross_t *ca = (const lws_svg_cross_t *)a;
	const lws_svg_cross_t *cb = (const lws_svg_cross_t *)b;

	return (ca->x > cb->x) - (ca->x < cb->x);
}

static int
xings_grow(lws_svg_t *ctx, size_t need)
{
	if (need <= ctx->xings_size)
		return 0;

	{
		size_t ns = ctx->xings_size ? ctx->xings_size * 2 : 64;
		lws_svg_cross_t *n;

		while (ns < need)
			ns *= 2;

		n = lws_realloc(ctx->xings, ns * sizeof(*ctx->xings), __func__);
		if (!n)
			return 1;
		ctx->xings = n;
		ctx->xings_size = ns;
	}

	return 0;
}

typedef struct {
	lws_svg_span_cb_t	cb;
	void			*user;
	int			w;
	uint32_t		rgba;
} svg_emit_t;


/*
 * Exact-area antialiasing.
 *
 * For the output row band [y, y + 1), every boundary edge is clipped to the
 * band; a straight piece from (xa, ya) to (xb, yb) with ya != yb contributes
 * to the covered fraction of each pixel column p through the winding
 * integral
 *
 *   raw(p) = sum_i s_i * integral of clamp(p + 1 - x_e,i, 0, 1) dyy
 *
 * over the band, where s is the edge direction and x_e the edge x at yy.
 * Since x_e is linear in yy, each term is the integral of a linear function
 * clamped to [0, 1] (a "ramp area"), and
 *
 *   raw(p + 1) - raw(p) = sum_i s_i * tent(p + 1, x_e,i) dyy
 *
 * with tent(c, x) a unit tent centred at c, so columns only receive
 * contributions from edges passing near them.  Sweeping raw(0) + sum(D)
 * left to right yields each column's exact covered fraction; clamping its
 * magnitude gives nonzero-rule coverage.  Corners inside a pixel, thin
 * features and slivers between scanlines are all handled exactly, since
 * there are no sample lines.
 */

/*
 * Exact integral over t in [0, 1) of clamp(v(t), 0, 1), for v linear from
 * v0 to v1 (Q16.16 in and out).  Decomposes at the at-most-two clamp level
 * crossings and sums trapezoids of the clamped value.
 */

static int32_t
aa_ramp(int64_t v0, int64_t v1)
{
	int64_t t[4], sum = 0;
	int n = 0, i, j;

	t[n++] = 0;
	if ((v0 < 0) != (v1 < 0))
		t[n++] = (-v0) * SVG_Q16_1 / (v1 - v0);
	if ((v0 < SVG_Q16_1) != (v1 < SVG_Q16_1))
		t[n++] = (SVG_Q16_1 - v0) * SVG_Q16_1 / (v1 - v0);
	t[n++] = SVG_Q16_1;

	for (i = 1; i < n; i++) {
		int64_t k = t[i];

		for (j = i - 1; j >= 0 && t[j] > k; j--)
			t[j + 1] = t[j];
		t[j + 1] = k;
	}

	for (i = 0; i + 1 < n; i++) {
		int64_t dt = t[i + 1] - t[i];
		int64_t va = v0 + (v1 - v0) * t[i] / SVG_Q16_1;
		int64_t vb = v0 + (v1 - v0) * t[i + 1] / SVG_Q16_1;

		if (va < 0)
			va = 0;
		if (va > SVG_Q16_1)
			va = SVG_Q16_1;
		if (vb < 0)
			vb = 0;
		if (vb > SVG_Q16_1)
			vb = SVG_Q16_1;

		sum += (va + vb) * dt;
	}

	return (int32_t)((sum + (1 << 16)) >> 17);
}

/*
 * Accumulate one band-clipped edge into the column D terms and the raw(0)
 * base.  Device-space Q16.16; the interpolation pre-shifts by one bit to
 * keep the products inside int64.
 */

static void
aa_edge(int64_t *aa_d, int w, int64_t yt, int64_t yb,
	int64_t x0, int64_t y0, int64_t x1, int64_t y1,
	int64_t *raw0, int *alo, int *ahi)
{
	int64_t lo = yt, hi = yb, s, dy, xa, xb, den, dx;
	int p, p_lo, p_hi;

	if (y0 == y1)
		return;			/* horizontal: no winding change */

	if (y0 < y1) {
		s = 1;
	} else {
		int64_t t;

		s = -1;
		t = x0; x0 = x1; x1 = t;
		t = y0; y0 = y1; y1 = t;
	}

	if (y1 <= lo || y0 >= hi)
		return;			/* outside the band */

	if (y0 > lo)
		lo = y0;
	if (y1 < hi)
		hi = y1;
	dy = hi - lo;
	if (dy <= 0)
		return;

	den = y1 - y0;			/* > 0 */
	dx = x1 - x0;

	/*
	 * x at the clipped positions: both factors are pre-shifted one
	 * bit to keep the product in int64, so the quotient needs <<2.
	 * The quotient itself is bounded by dx, so the shift cannot
	 * overflow.
	 */

	xa = x0 + ((((dx >> 1) * ((lo - y0) >> 1)) / den) << 2);
	xb = x0 + ((((dx >> 1) * ((hi - y0) >> 1)) / den) << 2);


	/* winding integral of column 0 */

	*raw0 += s * (((int64_t)aa_ramp(SVG_Q16_1 - xa,
					SVG_Q16_1 - xb) * dy) >> 16);

	/* localized tent contributions to D(p) = raw(p + 1) - raw(p) */

	p_lo = (int)((xa < xb ? xa : xb) >> 16) - 2;
	p_hi = (int)((xa > xb ? xa : xb) >> 16) + 1;
	if (p_lo < 0)
		p_lo = 0;
	if (p_hi > w - 1)
		p_hi = w - 1;

	for (p = p_lo; p <= p_hi; p++) {
		int64_t c = (int64_t)(p + 1) << 16;
		int64_t tent = aa_ramp(xa - c + SVG_Q16_1,
				       xb - c + SVG_Q16_1) +
			       aa_ramp(c + SVG_Q16_1 - xa,
				       c + SVG_Q16_1 - xb) -
			       SVG_Q16_1;

		if (tent < 0)
			tent = 0;
		if (tent > SVG_Q16_1)
			tent = SVG_Q16_1;

		aa_d[p] += s * ((tent * dy) >> 16);
	}

	if (p_hi >= p_lo) {
		if (p_lo < *alo)
			*alo = p_lo;
		if (p_hi > *ahi)
			*ahi = p_hi;
	}
}

/* map a user-space coordinate into the device raster */

static int64_t
aa_map(int64_t u, svg_c_t vb, svg_c_t sc, svg_c_t o)
{
	return arc_sat(((((u - vb) >> 1) * sc >> 16) << 1) + o);
}

/*
 * The antialiased band pass: accumulate raw(0) and the D terms over all
 * band-clipped edges of the shape, then sweep left to right emitting
 * constant-alpha runs.
 */

static lws_stateful_ret_t
aa_band(lws_svg_t *ctx, const lws_svg_render_t *ri, int y,
	svg_c_t sx, svg_c_t sy, svg_c_t ox, svg_c_t oy,
	svg_c_t vbx, svg_c_t vby, lws_svg_span_cb_t cb, void *user)
{
	const int w = ri->w;
	const int64_t yt = (int64_t)y << 16, yb = yt + SVG_Q16_1;

	if ((size_t)w > ctx->aa_d_size) {
		size_t ns = ctx->aa_d_size ? ctx->aa_d_size * 2 : 256;
		int64_t *n;

		while (ns < (size_t)w)
			ns *= 2;

		n = lws_realloc(ctx->aa_d, ns * sizeof(*ctx->aa_d), __func__);
		if (!n)
			return LWS_SRET_FATAL;
		/* the sweep reads every column, so keep the buffer zeroed */
		memset(n + ctx->aa_d_size, 0,
		       (ns - ctx->aa_d_size) * sizeof(*n));
		ctx->aa_d = n;
		ctx->aa_d_size = ns;
	}

	lws_start_foreach_dll(lws_dll2_t *, d, lws_dll2_get_head(&ctx->shapes)) {
		lws_svg_shape_t *sh = lws_container_of(d, lws_svg_shape_t, list);
		int64_t raw0 = 0;
		int alo = w, ahi = -1;
		uint32_t base = sh->rgba & 0x00ffffff;
		int fill_a = (int)LWS_SVG_ALPHA(sh->rgba);

		if (!fill_a)
			continue;	/* nothing painted */

		lws_start_foreach_dll(lws_dll2_t *, d2,
					      lws_dll2_get_head(&sh->subs)) {
			lws_svg_sub_t *sub = lws_container_of(d2,
							lws_svg_sub_t, list);
			int64_t px, py;
			uint32_t i;

			if (!sub->npts)
				continue;

			px = aa_map(sub->pts[0].x, vbx, sx, ox);
			py = aa_map(sub->pts[0].y, vby, sy, oy);

			/* fill closes open subpaths implicitly */

			for (i = 0; i < sub->npts; i++) {
				lws_svg_pt_t *Q = &sub->pts[
					i + 1 == sub->npts ? 0 : i + 1];
				int64_t qx = aa_map(Q->x, vbx, sx, ox);
				int64_t qy = aa_map(Q->y, vby, sy, oy);

				aa_edge(ctx->aa_d, w, yt, yb,
					px, py, qx, qy, &raw0, &alo, &ahi);

				px = qx;
				py = qy;
			}
		} lws_end_foreach_dll(d2);

		/* sweep: raw(p) = raw(0) + sum of D(q < p) */

		{
			int64_t raw = raw0;
			int prev_a = -1, span0 = 0, p;

			for (p = 0; p < w; p++) {
				int64_t cov = raw < 0 ? -raw : raw;
				int alpha;

				if (cov > SVG_Q16_1)
					cov = SVG_Q16_1;
				alpha = (int)((cov * fill_a + 32768) >> 16);

				if (alpha != prev_a) {
					if (prev_a > 0)
						cb(user, span0, p, base |
						   ((uint32_t)prev_a << 24));
					prev_a = alpha;
					span0 = p;
				}

				raw += ctx->aa_d[p];
			}

			if (prev_a > 0)
				cb(user, span0, w, base |
						   ((uint32_t)prev_a << 24));
		}

		/* clear only the touched columns for the next shape */

		if (ahi >= alo)
			memset(&ctx->aa_d[alo], 0,
			       (size_t)(ahi - alo + 1) * sizeof(ctx->aa_d[0]));
	} lws_end_foreach_dll(d);

	return LWS_SRET_OK;
}

static int
emit_span(svg_emit_t *e, svg_c_t xa, svg_c_t xb)
{
	int x0, x1;

	/* pixel p is covered when xa <= p + 0.5 < xb, in Q16.16 */

	x0 = svg_ceil_q16((int64_t)xa - SVG_Q16_1 / 2);
	x1 = svg_ceil_q16((int64_t)xb - SVG_Q16_1 / 2);

	if (x0 < 0)
		x0 = 0;
	if (x1 > e->w)
		x1 = e->w;

	if (x1 <= x0)
		return 0;

	return e->cb(e->user, x0, x1, e->rgba);
}

lws_stateful_ret_t
lws_svg_render_line(lws_svg_t *ctx, const lws_svg_render_t *ri, int y,
		    lws_svg_span_cb_t cb, void *user)
{
	svg_c_t sx = SVG_Q16_1, sy = SVG_Q16_1, ox = 0, oy = 0;
	svg_c_t vbx = 0, vby = 0, ys;
	svg_emit_t e;

	if (y < 0 || y >= ri->h || ri->w <= 0)
		return LWS_SRET_OK;

	/*
	 * Map user space into the raster according to the sizing policy.
	 * Divisions are safe because the denominators are clamped
	 * positive, and the resulting scales are floored at 1/65536.
	 */

	if (ctx->has_vb && ctx->vb[2] > 0 && ctx->vb[3] > 0) {
		int64_t sxq = ((int64_t)ri->w * SVG_Q16_1 * SVG_Q16_1) /
								ctx->vb[2];
		int64_t syq = ((int64_t)ri->h * SVG_Q16_1 * SVG_Q16_1) /
								ctx->vb[3];

		sx = arc_sat(sxq);
		sy = arc_sat(syq);
		if (!sx)
			sx = 1;
		if (!sy)
			sy = 1;

		if (!ctx->par_none) {
			svg_c_t s = ctx->par_slice ?
					(sx > sy ? sx : sy) : (sx < sy ? sx : sy);

			sx = sy = s;
			ox = arc_sat(((int64_t)ri->w * SVG_Q16_1 -
				(((int64_t)ctx->vb[2] * s) >> 16)) *
				ctx->par_ax / 2);
			oy = arc_sat(((int64_t)ri->h * SVG_Q16_1 -
				(((int64_t)ctx->vb[3] * s) >> 16)) *
				ctx->par_ay / 2);
		}

		vbx = ctx->vb[0];
		vby = ctx->vb[1];
	} else {
		svg_c_t w0 = (ctx->has_w && !ctx->unit_w && ctx->width > 0) ?
				ctx->width : 0;
		svg_c_t h0 = (ctx->has_h && !ctx->unit_h && ctx->height > 0) ?
				ctx->height : 0;

		if (w0 > 0)
			sx = arc_sat(((int64_t)ri->w * SVG_Q16_1 * SVG_Q16_1) /
					w0);
		if (h0 > 0)
			sy = arc_sat(((int64_t)ri->h * SVG_Q16_1 * SVG_Q16_1) /
					h0);
	}

	/* sample the line at the pixel centre, in user space */

	ys = arc_sat((((int64_t)y * SVG_Q16_1 + SVG_Q16_1 / 2 - oy) << 16) /
								sy + vby);

	e.cb = cb;
	e.user = user;
	e.w = ri->w;

	if (ri->aa)
		return aa_band(ctx, ri, y, sx, sy, ox, oy, vbx, vby,
			       cb, user);

	lws_start_foreach_dll(lws_dll2_t *, d, lws_dll2_get_head(&ctx->shapes)) {
		lws_svg_shape_t *sh = lws_container_of(d, lws_svg_shape_t, list);
		size_t n = 0;

		if (!LWS_SVG_ALPHA(sh->rgba))
			continue;	/* nothing painted */

		lws_start_foreach_dll(lws_dll2_t *, d2,
					      lws_dll2_get_head(&sh->subs)) {
			lws_svg_sub_t *sub = lws_container_of(d2,
							lws_svg_sub_t, list);
			uint32_t i;

			if (xings_grow(ctx, n + sub->npts + 1))
				return LWS_SRET_FATAL;

			/* fill closes open subpaths implicitly, so every
			 * subpath walks a closing edge too.  The crossing
			 * interpolation keeps products inside int64 by
			 * pre-shifting; since ys lies between the endpoint
			 * ys, the quotient is bounded by the edge dx.
			 */

			for (i = 0; i < sub->npts; i++) {
				lws_svg_pt_t *p = &sub->pts[i];
				lws_svg_pt_t *q = &sub->pts[
					i + 1 == sub->npts ? 0 : i + 1];

				if ((p->y > ys) != (q->y > ys)) {
					int64_t dy = (int64_t)q->y - p->y;
					int64_t num = (((int64_t)ys - p->y) >> 1) *
						      (((int64_t)q->x - p->x) >> 1);
					int64_t xu = (int64_t)p->x +
							((num / dy) << 2);

					/* map the crossing into device space */

					ctx->xings[n].x = arc_sat(
						((((xu - (int64_t)vbx) >> 1) *
						  sx >> 16) << 1) + ox);
					ctx->xings[n].dir = q->y > p->y ? 1 : -1;
					n++;
				}
			}
		} lws_end_foreach_dll(d2);

		if (n < 2)
			continue;

		qsort(ctx->xings, n, sizeof(ctx->xings[0]), cross_cmp);

		e.rgba = sh->rgba;

		if (!sh->rule) {
			/* nonzero winding */

			int wind = 0, i, start = -1;

			for (i = 0; i < (int)n; i++) {
				if (!wind)
					start = i;
				wind += ctx->xings[i].dir;
				if (!wind && start >= 0) {
					if (emit_span(&e,
						      ctx->xings[start].x,
						      ctx->xings[i].x))
						return LWS_SRET_OK;
					start = -1;
				}
			}
		} else {
			/* even-odd */

			size_t i;

			for (i = 0; i + 1 < n; i += 2)
				if (emit_span(&e, ctx->xings[i].x,
					      ctx->xings[i + 1].x))
					return LWS_SRET_OK;
		}
	} lws_end_foreach_dll(d);

	return LWS_SRET_OK;
}
