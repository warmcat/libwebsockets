/*
 * lws svg private shared declarations
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
 * Shared between the scene parse side (svg.c) and the rasterization side
 * (svg-raster.c).
 */

#if !defined(__LWS_PRIVATE_MISC_SVG_H__)
#define __LWS_PRIVATE_MISC_SVG_H__

#include <private-lib-core.h>

/* ---- scene limits ---- */

enum {
	LWS_SVG_MAX_DEPTH	= 24,	/* open element stack */
	LWS_SVG_MAX_SHAPES	= 2048,
	LWS_SVG_MAX_PTS		= 262144, /* scene-wide flattened points */
	LWS_SVG_MAX_SUBS	= 1024,	/* subpaths per shape */
	LWS_SVG_MAX_ATTRVAL	= 65536,
	LWS_SVG_MAX_NAME	= 31,
};

/* ---- fixed-point basis ---- */

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

typedef int32_t		svg_c_t;

typedef struct lws_svg_pt {
	svg_c_t			x, y;	/* user space, post-CTM, Q16.16 */
} lws_svg_pt_t;

/* e8 <-> lws_fx_t (pure integer joins of the decomposition) */

static LWS_INLINE int64_t
svg_fx_to_e8(const lws_fx_t *f)
{
	return (int64_t)f->whole * SVG_E8_1 + f->frac;
}

static LWS_INLINE void
svg_e8_to_fx(lws_fx_t *f, int64_t v)
{
	f->whole = (int32_t)(v / SVG_E8_1);
	f->frac = (int32_t)(v % SVG_E8_1);
}

/* e8 -> Q16.16 with saturation */

static LWS_INLINE svg_c_t
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

static LWS_INLINE svg_c_t
svg_qadd(int32_t a, int32_t b)
{
	int64_t r = (int64_t)a + b;

	if (r > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (r < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)r;
}

static LWS_INLINE svg_c_t
svg_qsub(int32_t a, int32_t b)
{
	int64_t r = (int64_t)a - b;

	if (r > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (r < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)r;
}

static LWS_INLINE svg_c_t
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

/*
 * Trig via the lws_fx fixed-point operators: pure integer, no FPU or
 * libm dependency, deterministic across platforms.  Angles are e8
 * radians in and out; sin / cos / tan results are Q16.16.
 */

/* integer ceil(v / 65536), valid for the whole int64 range */

static LWS_INLINE int
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
	/* the whole object: context, working state and scene, one lwsac */

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

	/* heap accounting, for the destroy-time peak log */

	size_t			heap_now;
	size_t			heap_peak;
};
/* ---- small shared Q16.16 / e8 helpers ---- */

static LWS_INLINE svg_c_t
arc_sat(int64_t v)
{
	if (v > SVG_C_MAX)
		return (svg_c_t)SVG_C_MAX;
	if (v < -SVG_C_MAX)
		return (svg_c_t)-SVG_C_MAX;

	return (svg_c_t)v;
}

/*
 * Allocation and heap accounting: the whole svg object (context, working
 * buffers, stylesheets and retained scene) lives in a single lwsac chained
 * off ctx->ac, grown with chained doubling generations for the working
 * buffers.  svg_ac_use() is the single allocation path, and tracks the
 * peak simultaneous footprint (as lwsac total, so including chunk
 * overheads and superseded growth generations) for a destroy-time log.
 */
void *svg_ac_use(lws_svg_t *ctx, size_t nec);

#endif
