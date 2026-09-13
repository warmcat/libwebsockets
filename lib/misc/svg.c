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

#define SVG_KAPPA		0.55228474983079356
#define SVG_PI			3.14159265358979323846

typedef struct lws_svg_pt {
	float			x, y;	/* user space, post-CTM */
} lws_svg_pt_t;

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
	double			m[6];	/* CTM: x' = m[0]x + m[2]y + m[4] */
	uint32_t		rgba;	/* composed fill colour */
	char			rule;
	char			suppress; /* inside defs, text, unknown... */
} svg_lvl_t;

/* pending per-tag state, accumulated from attributes as they stream in */

typedef struct {
	uint32_t		fill;	/* valid when fill_present */
	char			fill_present; /* fill attr seen (incl none) */
	double			fillop, op;
	char			fillop_present, op_present;
	char			rule, rule_present;
	char			has_transform;
	double			tm[6];	/* own transform list composition */
	double			g[6];	/* shape geometry attrs */
	char			gok[6];
	char			has_d;		/* path data in working arrays */
	char			has_points;
} svg_pend_t;

typedef struct lws_svg_dpt {
	double			x, y;	/* user space, pre-CTM */
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
	double			x;	/* device-space crossing x */
	int8_t			dir;	/* +1 downwards edge, -1 upwards */
} lws_svg_cross_t;

struct lws_svg {
	/* retained scene */

	struct lwsac		*ac;
	lws_dll2_owner_t	shapes;
	uint32_t		nshapes;
	uint32_t		npts;	/* scene-wide flattened point count */

	/* root sizing and mapping policy */

	double			width, height;
	char			unit_w, unit_h;	/* 0 = px, 1 = percent */
	char			has_w, has_h;
	double			vb[4];			/* minx miny w h */
	char			has_vb;
	char			par_none, par_slice;
	uint8_t			par_ax, par_ay;	/* 0 min, 1 mid, 2 max */

	double			tol;	/* flatten tolerance, user units */

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
};

/*
 * Trig via the lws_fx fixed-point operators: these wrap the integer
 * implementations so all geometry is deterministic across platforms without
 * any FPU or libm dependency.
 */

static double
svg_fx2d(const lws_fx_t *f)
{
	return (double)f->whole + (double)f->frac / 100000000.0;
}

static void
svg_d2fx(lws_fx_t *f, double r)
{
	f->whole = (int32_t)r;
	f->frac = (int32_t)((r - (double)(int32_t)r) * 100000000.0);
}

static double
svg_sin(double r)
{
	lws_fx_t a, res;

	svg_d2fx(&a, r);
	lws_fx_sin(&res, &a);

	return svg_fx2d(&res);
}

static double
svg_cos(double r)
{
	lws_fx_t a, res;

	svg_d2fx(&a, r);
	lws_fx_cos(&res, &a);

	return svg_fx2d(&res);
}

static double
svg_tan(double r)
{
	lws_fx_t a, res;

	svg_d2fx(&a, r);
	lws_fx_tan(&res, &a);

	return svg_fx2d(&res);
}

static double
svg_atan2(double y, double x)
{
	lws_fx_t fy, fx, res;

	svg_d2fx(&fy, y);
	svg_d2fx(&fx, x);
	lws_fx_atan2(&res, &fy, &fx);

	return svg_fx2d(&res);
}

static double
svg_sqrt(double v)
{
	lws_fx_t a, res;

	svg_d2fx(&a, v);
	lws_fx_sqrt(&res, &a);

	return svg_fx2d(&res);
}

/*
 * Number parsing.  Accepts the SVG grammar for numbers with optional
 * exponent; magnitudes are clamped so hostile input can't explode the
 * geometry math later.  Only returns non-NULL (and only advances the
 * cursor) for a well-formed number.
 */

static const char *
svg_num(const char *p, const char *end, double *r)
{
	int any = 0, neg = 0;
	double v = 0, fr = 0.1;

	if (p < end && (*p == '+' || *p == '-')) {
		neg = *p == '-';
		p++;
	}

	while (p < end && *p >= '0' && *p <= '9') {
		v = (v * 10.0) + (double)(*p - '0');
		p++;
		any = 1;
	}

	if (p < end && *p == '.') {
		const char *q = p + 1;

		while (q < end && *q >= '0' && *q <= '9') {
			v += (double)(*q - '0') * fr;
			fr *= 0.1;
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
			if (ev < 320)
				ev = (ev * 10) + (*q - '0');
			q++;
			eany = 1;
		}
		if (eany) {
			p = q;
			if (ev > 300)
				v = eneg ? 0.0 : 1e9;
			else
				while (ev--) {
					if (eneg)
						v /= 10.0;
					else
						v *= 10.0;
				}
		}
	}

	if (v > 1e9)
		v = 1e9;
	if (v < -1e9)
		v = -1e9;

	*r = neg ? -v : v;

	return p;
}

/* skip whitespace and comma separators */

static const char *
svg_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' ||
			   *p == '\n' || *p == ','))
		p++;

	return p;
}

static char
isxmlws(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* a length with optional CSS unit; returns unit 0 = px (converted), 1 = % */

static int
svg_len(const char *s, size_t len, double *r, char *pct)
{
	const char *p = s, *end = s + len;
	double v;

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
			size_t ul = (size_t)(end - p);

			if (ul >= 2 && !strncmp(p, "pt", 2))
				v = v * 4.0 / 3.0;
			else
				if (ul >= 2 && !strncmp(p, "pc", 2))
					v = v * 16.0;
				else
					if (ul >= 2 && !strncmp(p, "mm", 2))
						v = v * 96.0 / 25.4;
					else
						if (ul >= 2 && !strncmp(p, "cm", 2))
							v = v * 96.0 / 2.54;
						else
							if (ul >= 2 &&
							    !strncmp(p, "in", 2))
								v = v * 96.0;
			/* px and anything else: leave in px */
		}
	}

	*r = v;

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
		double comp[4];
		int nc, apct = 0;

		p += is_rgba ? 5 : 4;

		for (nc = 0; nc < 4; nc++) {
			double v;
			int pct = 0;

			p = svg_ws(p, end);
			p = svg_num(p, end, &v);
			if (!p)
				break;
			if (p < end && *p == '%') {
				pct = 1;
				p++;
			}
			if (nc == 3)
				apct = pct;
			comp[nc] = pct ? v * 255.0 / 100.0 : v;
			p = svg_ws(p, end);
			if (p < end && *p == ',')
				p++;
		}

		if (nc < 3)
			return 1;

		/* alpha is 0..1 (or a percentage), the rest are 0..255 */

		if (is_rgba) {
			double av = apct ? comp[3] : comp[3] * 255.0;

			if (av < 0)
				av = 0;
			if (av > 255)
				av = 255;
			a = (uint32_t)(av + 0.5);
		}

		*rgba = LWS_SVG_RGBA(
			comp[0] < 0 ? 0 : comp[0] > 255 ? 255 : (uint32_t)comp[0],
			comp[1] < 0 ? 0 : comp[1] > 255 ? 255 : (uint32_t)comp[1],
			comp[2] < 0 ? 0 : comp[2] > 255 ? 255 : (uint32_t)comp[2],
			a);

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
xf_ident(double m[6])
{
	m[0] = 1; m[1] = 0; m[2] = 0; m[3] = 1; m[4] = 0; m[5] = 0;
}

/* r = m ∘ t (apply t first, then m); safe when r aliases m */

static void
xf_comp(double r[6], const double m[6], const double t[6])
{
	double a = m[0] * t[0] + m[2] * t[1];
	double b = m[1] * t[0] + m[3] * t[1];
	double c = m[0] * t[2] + m[2] * t[3];
	double d = m[1] * t[2] + m[3] * t[3];
	double e = m[0] * t[4] + m[2] * t[5] + m[4];
	double f = m[1] * t[4] + m[3] * t[5] + m[5];

	r[0] = a; r[1] = b; r[2] = c; r[3] = d; r[4] = e; r[5] = f;
}

/*
 * Parse a transform list, composing on to out[].  Unknown functions are
 * skipped leniently.
 */

static int
svg_transforms(const char *s, size_t len, double out[6])
{
	const char *p = s, *end = s + len;
	double t[6], arg[6];

	p = svg_ws(p, end);

	while (p < end) {
		char fn[16];
		size_t fl = 0;
		int na = 0, i;

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

		p = svg_ws(p, end);
		while (p < end && na < 6) {
			const char *q = svg_num(p, end, &arg[na]);

			if (!q)
				break;
			p = q;
			na++;
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
						double co, si, dx = 0, dy = 0;

						arg[0] = arg[0] * SVG_PI /
									180.0;
						co = svg_cos(arg[0]);
						si = svg_sin(arg[0]);

						t[0] = co;
						t[1] = si;
						t[2] = -si;
						t[3] = co;

						/* optional rotation centre */

						if (na >= 3) {
							dx = arg[1];
							dy = arg[2];
							t[4] = dx - co * dx + si * dy;
							t[5] = dy - si * dx - co * dy;
						}
					} else
						if (!strcmp(fn, "skewX") &&
						    na >= 1)
							t[2] = svg_tan(
								arg[0] * SVG_PI /
									180.0);
						else
							if (!strcmp(fn, "skewY") &&
							    na >= 1)
								t[1] = svg_tan(
									arg[0] * SVG_PI /
										180.0);
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
pt_add(lws_svg_t *ctx, double x, double y)
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

static int
sub_start(lws_svg_t *ctx, double x, double y)
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

static int
flat_enough(lws_svg_t *ctx, double x0, double y0, double x1, double y1,
	    double x2, double y2, double x3, double y3)
{
	double dx = x3 - x0, dy = y3 - y0;
	double d1 = (x1 - x0) * dy - (y1 - y0) * dx;
	double d2 = (x2 - x0) * dy - (y2 - y0) * dx;
	double dd = d1 + d2, tol2 = ctx->tol * ctx->tol;

	if (dd < 0)
		dd = -dd;

	if (!dx && !dy) {
		/* zero chord: only the control point spread matters */

		return (x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0) <=
								tol2 * 16384 &&
		       (x2 - x0) * (x2 - x0) + (y2 - y0) * (y2 - y0) <=
								tol2 * 16384;
	}

	/* flat when (d1 + d2)² <= tol²·|chord|², avoiding any sqrt */

	return dd * dd <= tol2 * (dx * dx + dy * dy);
}

static int
flatten_cubic(lws_svg_t *ctx, double x0, double y0, double x1, double y1,
	      double x2, double y2, double x3, double y3, int depth)
{
	double x01, y01, x12, y12, x23, y23, x012, y012, x123, y123;

	if (depth >= 16 || flat_enough(ctx, x0, y0, x1, y1, x2, y2, x3, y3))
		return pt_add(ctx, x3, y3);

	x01  = (x0 + x1) / 2;     y01  = (y0 + y1) / 2;
	x12  = (x1 + x2) / 2;     y12  = (y1 + y2) / 2;
	x23  = (x2 + x3) / 2;     y23  = (y2 + y3) / 2;
	x012 = (x01 + x12) / 2;   y012 = (y01 + y12) / 2;
	x123 = (x12 + x23) / 2;   y123 = (y12 + y23) / 2;

	if (flatten_cubic(ctx, x0, y0, x01, y01, x012, y012,
			  (x012 + x123) / 2, (y012 + y123) / 2, depth + 1))
		return 1;

	return flatten_cubic(ctx, (x012 + x123) / 2, (y012 + y123) / 2,
			     x123, y123, x23, y23, x3, y3, depth + 1);
}

static int
flatten_quad(lws_svg_t *ctx, double x0, double y0, double x1, double y1,
	     double x2, double y2)
{
	/* exact degree elevation to a cubic */

	return flatten_cubic(ctx, x0, y0,
			     x0 + 2.0 / 3.0 * (x1 - x0),
			     y0 + 2.0 / 3.0 * (y1 - y0),
			     x2 + 2.0 / 3.0 * (x1 - x2),
			     y2 + 2.0 / 3.0 * (y1 - y2),
			     x2, y2, 0);
}

/*
 * SVG "A" command: convert the endpoint-parameterized arc to a sequence of
 * at most 4 cubic pieces, following the SVG spec F.6.5 endpoint-to-center
 * conversion.
 */

static int
flatten_arc(lws_svg_t *ctx, double x1, double y1, double rx, double ry,
	    double phi, int large, int sweep, double x2, double y2)
{
	double co = svg_cos(phi), si = svg_sin(phi);
	double dx2 = (x1 - x2) / 2, dy2 = (y1 - y2) / 2;
	double x1p =  co * dx2 + si * dy2;
	double y1p = -si * dx2 + co * dy2;
	double lam, num, den, coef, cxp, cyp, cx, cy, t1, dt, th, hn;
	int nseg, i;

	if (x1 == x2 && y1 == y2)
		return 0;	/* zero-length arc */

	if (rx < 0)
		rx = -rx;
	if (ry < 0)
		ry = -ry;
	if (rx < 1e-9 || ry < 1e-9)
		return pt_add(ctx, x2, y2);	/* degenerate: straight line */

	/* correct out-of-range radii */

	lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
	if (lam > 1.0) {
		double s = svg_sqrt(lam);
		rx *= s;
		ry *= s;
	}

	num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p;
	den = rx * rx * y1p * y1p + ry * ry * x1p * x1p;
	if (num < 0)
		num = 0;
	if (den < 1e-12)
		den = 1e-12;
	coef = ((large != sweep) ? 1.0 : -1.0) * svg_sqrt(num / den);

	cxp =  coef * rx * y1p / ry;
	cyp = -coef * ry * x1p / rx;

	cx = co * cxp - si * cyp + (x1 + x2) / 2;
	cy = si * cxp + co * cyp + (y1 + y2) / 2;

	t1 = svg_atan2((y1p - cyp) / ry, (x1p - cxp) / rx);
	dt = svg_atan2((-y1p - cyp) / ry, (-x1p - cxp) / rx) - t1;

	if (!sweep && dt > 0)
		dt -= 2 * SVG_PI;
	else
		if (sweep && dt < 0)
			dt += 2 * SVG_PI;

	nseg = (int)(((dt < 0 ? -dt : dt) / (SVG_PI / 2)) + 0.999999);
	if (nseg < 1)
		nseg = 1;
	if (nseg > 4)
		nseg = 4;

	hn = 4.0 / 3.0 * svg_tan(dt / (double)nseg / 4.0);
	th = t1;

	for (i = 0; i < nseg; i++) {
		double th2 = th + dt / (double)nseg;
		double c1 = svg_cos(th),  s1 = svg_sin(th);
		double c2 = svg_cos(th2), s2 = svg_sin(th2);
		/* points and derivatives on the rotated ellipse */
		double px1 = cx + co * rx * c1 - si * ry * s1;
		double py1 = cy + si * rx * c1 + co * ry * s1;
		double dx1 = co * -rx * s1 - si * ry * c1;
		double dy1 = si * -rx * s1 + co * ry * c1;
		double px2 = cx + co * rx * c2 - si * ry * s2;
		double py2 = cy + si * rx * c2 + co * ry * s2;
		double dx2n = co * -rx * s2 - si * ry * c2;
		double dy2n = si * -rx * s2 + co * ry * c2;
		int r;

		/* the final piece lands exactly on the endpoint */

		r = flatten_cubic(ctx, px1, py1,
				  px1 + hn * dx1, py1 + hn * dy1,
				  px2 - hn * dx2n, py2 - hn * dy2n,
				  i == nseg - 1 ? x2 : px2,
				  i == nseg - 1 ? y2 : py2, 0);
		if (r)
			return 1;

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
	double sx = 0, sy = 0, px = 0, py = 0, pcx = 0, pcy = 0;

	work_reset(ctx);

	while (p < end) {
		double a[6];

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
			double x, y;
			char rel = cmd == 'm';

			p = svg_num(p, end, &x);
			if (!p)
				return 0;
			p = svg_ws(p, end);
			p = svg_num(p, end, &y);
			if (!p)
				return 0;

			if (rel) {
				x += px;
				y += py;
			}

			/*
			 * The first coordinate pair is a moveto; further
			 * pairs in the same command repeat as lineto
			 */

			if (ctx->wpts_count)
				cmd = rel ? 'l' : 'L';

			sx = px = x;
			sy = py = y;
			if (sub_start(ctx, x, y))
				return 1;
			break;
		}

		case 'L': case 'l': {
			double x, y;
			char rel = cmd == 'l';

			p = svg_num(p, end, &x);
			if (!p)
				return 0;
			p = svg_ws(p, end);
			p = svg_num(p, end, &y);
			if (!p)
				return 0;
			if (rel) {
				x += px;
				y += py;
			}
			if (pt_add(ctx, x, y))
				return 1;
			px = x;
			py = y;
			break;
		}

		case 'H': case 'h': {
			double x;

			p = svg_num(p, end, &x);
			if (!p)
				return 0;
			if (cmd == 'h')
				x += px;
			if (pt_add(ctx, x, py))
				return 1;
			px = x;
			break;
		}

		case 'V': case 'v': {
			double y;

			p = svg_num(p, end, &y);
			if (!p)
				return 0;
			if (cmd == 'v')
				y += py;
			if (pt_add(ctx, px, y))
				return 1;
			py = y;
			break;
		}

		case 'C': case 'c': {
			int i;

			for (i = 0; i < 3; i++) {
				p = svg_ws(p, end);
				p = svg_num(p, end, &a[i * 2]);
				if (!p)
					return 0;
				p = svg_ws(p, end);
				p = svg_num(p, end, &a[i * 2 + 1]);
				if (!p)
					return 0;
			}
			if (cmd == 'c')
				for (i = 0; i < 6; i++)
					a[i] += (i & 1) ? py : px;

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
			double x2, y2, x, y, x1, y1;
			int i;

			for (i = 0; i < 2; i++) {
				p = svg_ws(p, end);
				p = svg_num(p, end, &a[i * 2]);
				if (!p)
					return 0;
				p = svg_ws(p, end);
				p = svg_num(p, end, &a[i * 2 + 1]);
				if (!p)
					return 0;
			}
			x2 = a[0]; y2 = a[1]; x = a[2]; y = a[3];
			if (cmd == 's') {
				x2 += px; y2 += py;
				x += px;  y += py;
			}

			/* reflected previous control point when the
			 * previous command was cubic, else current point */

			x1 = prev_c ? 2 * px - pcx : px;
			y1 = prev_c ? 2 * py - pcy : py;

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
			double x1, y1, x, y;
			int i;

			for (i = 0; i < 2; i++) {
				p = svg_ws(p, end);
				p = svg_num(p, end, &a[i * 2]);
				if (!p)
					return 0;
				p = svg_ws(p, end);
				p = svg_num(p, end, &a[i * 2 + 1]);
				if (!p)
					return 0;
			}
			x1 = a[0]; y1 = a[1]; x = a[2]; y = a[3];
			if (cmd == 'q') {
				x1 += px; y1 += py;
				x += px;  y += py;
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
			double x, y, x1, y1;

			p = svg_ws(p, end);
			p = svg_num(p, end, &x);
			if (!p)
				return 0;
			p = svg_ws(p, end);
			p = svg_num(p, end, &y);
			if (!p)
				return 0;
			if (cmd == 't') {
				x += px;
				y += py;
			}

			x1 = prev_q ? 2 * px - pcx : px;
			y1 = prev_q ? 2 * py - pcy : py;

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
			double rx, ry, rot, x, y;
			int laf, sf, i;

			for (i = 0; i < 3; i++) {	/* rx ry x-axis-rot */
				p = svg_ws(p, end);
				p = svg_num(p, end, &a[i]);
				if (!p)
					return 0;
			}
			rx = a[0]; ry = a[1]; rot = a[2];

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
				p = svg_num(p, end, &a[i]);
				if (!p)
					return 0;
			}
			x = a[0];
			y = a[1];
			if (cmd == 'a') {
				x += px;
				y += py;
			}

			if (flatten_arc(ctx, px, py, rx, ry,
					rot * SVG_PI / 180.0, laf, sf, x, y))
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

static int
parse_points(lws_svg_t *ctx, char closed)
{
	const char *p = ctx->vbuf, *end = ctx->vbuf + ctx->vlen;
	double x, y;
	int n = 0;

	work_reset(ctx);

	while (p < end) {
		p = svg_ws(p, end);
		if (p >= end)
			break;
		p = svg_num(p, end, &x);
		if (!p)
			break;
		p = svg_ws(p, end);
		p = svg_num(p, end, &y);
		if (!p)
			break;

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

static int
shape_commit(lws_svg_t *ctx, const double m[6], uint32_t rgba, char rule)
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

			sub->pts[j].x = (float)(m[0] * d->x + m[2] * d->y + m[4]);
			sub->pts[j].y = (float)(m[1] * d->x + m[3] * d->y + m[5]);
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
	double x = pd->gok[0] ? pd->g[0] : 0, y = pd->gok[1] ? pd->g[1] : 0;
	double w = pd->gok[2] ? pd->g[2] : 0, h = pd->gok[3] ? pd->g[3] : 0;
	double rx = pd->gok[4] ? pd->g[4] : 0, ry = pd->gok[5] ? pd->g[5] : 0;

	if (w <= 0 || h <= 0)
		return 0;	/* nothing to fill */

	/* rx and ry default to each other, and clamp to half the extent */

	if (!rx && ry)
		rx = ry;
	if (!ry && rx)
		ry = rx;
	if (rx < 0)
		rx = 0;
	if (ry < 0)
		ry = 0;
	if (rx > w / 2)
		rx = w / 2;
	if (ry > h / 2)
		ry = h / 2;

	work_reset(ctx);
	if (sub_start(ctx, x + rx, y))
		return 1;

	if (rx > 0 && ry > 0) {
		double kx = rx * SVG_KAPPA, ky = ry * SVG_KAPPA;

		/* clockwise from the top edge, four quarter-arc corners */

		if (pt_add(ctx, x + w - rx, y))
			return 1;
		if (flatten_cubic(ctx, x + w - rx, y, x + w - rx + kx, y,
				  x + w, y + ry - ky, x + w, y + ry, 0))
			return 1;
		if (pt_add(ctx, x + w, y + h - ry))
			return 1;
		if (flatten_cubic(ctx, x + w, y + h - ry, x + w, y + h - ry + ky,
				  x + w - rx + kx, y + h, x + w - rx, y + h, 0))
			return 1;
		if (pt_add(ctx, x + rx, y + h))
			return 1;
		if (flatten_cubic(ctx, x + rx, y + h, x + rx - kx, y + h,
				  x, y + h - ry + ky, x, y + h - ry, 0))
			return 1;
		if (pt_add(ctx, x, y + ry))
			return 1;
		if (flatten_cubic(ctx, x, y + ry, x, y + ry - ky,
				  x + rx - kx, y, x + rx, y, 0))
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
build_ellipse(lws_svg_t *ctx, double cx, double cy, double rx, double ry)
{
	double kx = rx * SVG_KAPPA, ky = ry * SVG_KAPPA;

	if (rx <= 0 || ry <= 0)
		return 0;

	work_reset(ctx);
	if (sub_start(ctx, cx + rx, cy))
		return 1;

	if (flatten_cubic(ctx, cx + rx, cy, cx + rx, cy + ky,
			  cx + kx, cy + ry, cx, cy + ry, 0))
		return 1;
	if (flatten_cubic(ctx, cx, cy + ry, cx - kx, cy + ry,
			  cx - rx, cy + ky, cx - rx, cy, 0))
		return 1;
	if (flatten_cubic(ctx, cx - rx, cy, cx - rx, cy - ky,
			  cx - kx, cy - ry, cx, cy - ry, 0))
		return 1;
	if (flatten_cubic(ctx, cx, cy - ry, cx + kx, cy - ry,
			  cx + rx, cy - ky, cx + rx, cy, 0))
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
	    !strcmp(name, "style") || !strcmp(name, "text") ||
	    !strcmp(name, "tspan") || !strcmp(name, "textPath") ||
	    !strcmp(name, "symbol") || !strcmp(name, "clipPath") ||
	    !strcmp(name, "mask") || !strcmp(name, "filter") ||
	    !strcmp(name, "marker") || !strcmp(name, "pattern") ||
	    !strcmp(name, "linearGradient") ||
	    !strcmp(name, "radialGradient") ||
	    !strcmp(name, "image") || !strcmp(name, "foreignObject") ||
	    !strcmp(name, "use") || !strcmp(name, "animate") ||
	    !strcmp(name, "set") || !strcmp(name, "animateMotion") ||
	    !strcmp(name, "animateTransform") || !strcmp(name, "script"))
		return SVEK_SUPPRESS;

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

/*
 * Compose the pending attribute deltas on to an inherited level state
 */

static void
level_compose(svg_lvl_t *parent, svg_pend_t *pd, svg_lvl_t *l)
{
	uint32_t rgba = parent->rgba;
	double alpha = (double)LWS_SVG_ALPHA(rgba);

	*l = *parent;

	if (pd->has_transform)
		xf_comp(l->m, parent->m, pd->tm);

	if (pd->fill_present) {
		if (!LWS_SVG_ALPHA(pd->fill))
			alpha = 0;
		else {
			rgba = pd->fill & 0x00ffffff;
			alpha = (double)LWS_SVG_ALPHA(pd->fill);
		}
	}

	if (pd->fillop_present && pd->fillop > 0)
		alpha *= pd->fillop < 1 ? pd->fillop : 1.0;
	if (pd->op_present && pd->op > 0)
		alpha *= pd->op < 1 ? pd->op : 1.0;

	if (alpha > 255.0)
		alpha = 255.0;

	l->rgba = (rgba & 0x00ffffff) | ((uint32_t)(alpha + 0.5) << 24);

	if (pd->rule_present)
		l->rule = pd->rule;
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

/* apply one presentation property, from an attribute or style= content */

static void
style_prop(lws_svg_t *ctx, const char *name, size_t nl,
	   const char *val, size_t vl)
{
	svg_pend_t *pd = &ctx->pend;

	if (nl == 4 && !strncmp(name, "fill", 4)) {
		uint32_t rgba;

		if (!svg_colour(val, vl, &rgba)) {
			pd->fill_present = 1;
			pd->fill = rgba;
		}
	} else
		if (nl == 12 && !strncmp(name, "fill-opacity", 12)) {
			double d;

			if (svg_num(val, val + vl, &d)) {
				pd->fillop_present = 1;
				pd->fillop = d;
			}
		} else
			if (nl == 7 && !strncmp(name, "opacity", 7)) {
				double d;

				if (svg_num(val, val + vl, &d)) {
					pd->op_present = 1;
					pd->op = d;
				}
			} else
				if (nl == 9 && !strncmp(name, "fill-rule", 9)) {
					ctx->pend.rule_present = 1;
					ctx->pend.rule = !!(vl == 7 &&
							  !strncmp(val, "evenodd", 7));
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
				p = svg_ws(p, end);
				p = svg_num(p, end, &ctx->vb[i]);
				if (!p)
					return 0;
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
		double d;

		if (svg_num(ctx->vbuf, ctx->vbuf + ctx->vlen, &d)) {
			if (n[4] == '-') {
				pd->fillop_present = 1;
				pd->fillop = d;
			} else {
				pd->op_present = 1;
				pd->op = d;
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
			double d;

			if (svg_num(ctx->vbuf, ctx->vbuf + ctx->vlen, &d)) {
				pd->gok[slot] = 1;
				pd->g[slot] = d;
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

			level_compose(&ctx->stk[0], pd, &ctx->stk[0]);

			if (ctx->has_vb && ctx->vb[2] > 0 && ctx->vb[3] > 0) {
				double mn = ctx->vb[2] < ctx->vb[3] ?
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

				ctx->tol = mn / 1024.0;
				if (ctx->tol < 1.0 / 4096.0)
					ctx->tol = 1.0 / 4096.0;
				if (ctx->tol > 0.125)
					ctx->tol = 0.125;
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

			level_compose(&ctx->stk[ctx->depth], pd,
				      &ctx->stk[ctx->depth + 1]);
			ctx->depth++;
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

			level_compose(&ctx->stk[ctx->depth], pd, &eff);

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
element_close(lws_svg_t *ctx)
{
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
		}
		break;

	case SXS_CLOSENAME:
		if (c == '>') {
			element_close(ctx);
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
				ctx->bang_step = 2;
				ctx->sub_step = 0;
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
		/* end on "]]>", with correct suffix recovery */

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
	ctx->tol = 0.1;
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
	lws_free(ctx->vbuf);
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
		return (unsigned int)(ctx->width + 0.5);

	if (ctx->has_vb && ctx->vb[2] > 0)
		return (unsigned int)(ctx->vb[2] + 0.5);

	return 300;	/* CSS default replaced element size */
}

unsigned int
lws_svg_get_height(const lws_svg_t *ctx)
{
	if (!ctx->root_seen)
		return 0;

	if (ctx->has_h && !ctx->unit_h && ctx->height > 0)
		return (unsigned int)(ctx->height + 0.5);

	if (ctx->has_vb && ctx->vb[3] > 0)
		return (unsigned int)(ctx->vb[3] + 0.5);

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

/* integer ceil, avoiding libm */

static int
iceil(double v)
{
	int iv = (int)v;

	if ((double)iv == v || v < 0)
		return iv;

	return iv + 1;
}

static int
emit_span(svg_emit_t *e, double xa, double xb)
{
	int x0, x1;

	/* pixel p is covered when xa <= p + 0.5 < xb */

	x0 = iceil(xa - 0.5);
	x1 = iceil(xb - 0.5);

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
	double sx = 1.0, sy = 1.0, ox = 0.0, oy = 0.0, vbx = 0.0, vby = 0.0;
	double ys;
	svg_emit_t e;

	if (y < 0 || y >= ri->h || ri->w <= 0)
		return LWS_SRET_OK;

	/* map user space into the raster according to the sizing policy */

	if (ctx->has_vb && ctx->vb[2] > 0 && ctx->vb[3] > 0) {
		sx = (double)ri->w / ctx->vb[2];
		sy = (double)ri->h / ctx->vb[3];

		if (!ctx->par_none) {
			double s = ctx->par_slice ?
					(sx > sy ? sx : sy) :
					(sx < sy ? sx : sy);

			sx = sy = s;
			ox = ((double)ri->w - ctx->vb[2] * s) *
						(double)ctx->par_ax / 2.0;
			oy = ((double)ri->h - ctx->vb[3] * s) *
						(double)ctx->par_ay / 2.0;
		}

		vbx = ctx->vb[0];
		vby = ctx->vb[1];
	} else {
		double w0 = (ctx->has_w && !ctx->unit_w && ctx->width > 0) ?
				ctx->width : 0;
		double h0 = (ctx->has_h && !ctx->unit_h && ctx->height > 0) ?
				ctx->height : 0;

		if (w0 > 0)
			sx = (double)ri->w / w0;
		if (h0 > 0)
			sy = (double)ri->h / h0;
	}

	/* sample the line at the pixel centre, in user space */

	ys = ((double)y + 0.5 - oy) / sy + vby;

	e.cb = cb;
	e.user = user;
	e.w = ri->w;

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
			 * subpath walks a closing edge too */

			for (i = 0; i < sub->npts; i++) {
				lws_svg_pt_t *p = &sub->pts[i];
				lws_svg_pt_t *q = &sub->pts[
					i + 1 == sub->npts ? 0 : i + 1];

				if ((p->y > ys) != (q->y > ys)) {
					double t = (ys - p->y) / (q->y - p->y);
					double xu = p->x + t * (q->x - p->x);

					ctx->xings[n].x = (xu - vbx) * sx + ox;
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
