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

	/* animation */

	LWS_SVG_MAX_NODES	= 256,	/* animated elements */
	LWS_SVG_MAX_ANIMS	= 512,	/* animation elements */
	LWS_SVG_MAX_VALUES	= 64,	/* items in one values= list */
	LWS_SVG_MAX_MPTS	= 1024,	/* flattened animateMotion path */
	LWS_SVG_MAX_ARAW	= 4096,	/* an animation list attribute */
};

/*
 * The scene is taken from the object's lwsac in chunks of this size: an icon
 * a small target renders holds a few hundred bytes of scene, which a 4KB
 * default chunk would mostly waste.  A shape bigger than this gets a chunk of
 * its own, and later small ones backfill what is free in the earlier chunks.
 */

#define SVG_SCENE_CHUNK		1024

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
	int64_t q;

	/*
	 * Saturate before the multiply as well: parser output is clamped
	 * small enough, but lws_fx_tan() can hand skewX/skewY 2e17, and
	 * 2e17 * 65536 does not fit.  Anything at or beyond this maps to
	 * the clamp below anyway.
	 */
	if (v >= INT64_MAX / SVG_Q16_1)
		return (svg_c_t)SVG_C_MAX;
	if (v <= -(INT64_MAX / SVG_Q16_1))
		return (svg_c_t)-SVG_C_MAX;

	q = (v * SVG_Q16_1) / SVG_E8_1;

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
	lws_svg_pt_t		*pts;	/* in the shape's own allocation */
	uint32_t		npts;
	svg_c_t			ymin, ymax; /* of pts, so bands can skip it */
	char			closed;
} lws_svg_sub_t;

/*
 * A shape is a single scene allocation: the shape, then its subs[] array,
 * then all of its subpaths' points back to back
 */

/*
 * SMIL animation.
 *
 * An element with animation children is a node.  Everything drawn inside it
 * is held in the scene in the node's own coordinates, ie, before the
 * element's own transform, and the node's matrix e[] is worked out for the
 * time the scene is drawn at, from the static matrices and the animations.
 */

typedef enum {
	SVG_ANIM_TRANSFORM,	/* animateTransform */
	SVG_ANIM_MOTION,	/* animateMotion */
	SVG_ANIM_OPACITY,	/* animate or set of opacity */
} svg_anim_kind_t;

typedef enum {
	SVG_CALC_DISCRETE,
	SVG_CALC_LINEAR,
	SVG_CALC_PACED,
	SVG_CALC_SPLINE,
} svg_calc_t;

/* transform functions, as svg_xf_fn() makes them */

typedef enum {
	SVG_XF_MATRIX,
	SVG_XF_TRANSLATE,
	SVG_XF_SCALE,
	SVG_XF_ROTATE,
	SVG_XF_SKEWX,
	SVG_XF_SKEWY,
} svg_xf_t;

#define SVG_ANIM_NPER		3	/* numbers held for each value */

typedef struct lws_svg_anim {
	lws_dll2_t		list;	/* on the node, document order */
	lws_usec_t		begin;
	lws_usec_t		dur;	/* simple duration, 0 = indefinite */
	lws_usec_t		active;	/* active duration, -1 = indefinite */
	svg_c_t			*vals;	/* nvals * SVG_ANIM_NPER */
	svg_c_t			*kt;	/* keyTimes, nvals of them, or NULL */
	svg_c_t			*ks;	/* keySplines, 4 * (nvals - 1), or NULL */
	int64_t			*len;	/* paced: distance to each value */
	svg_c_t			mrot;	/* motion: fixed rotation, degrees */
	uint16_t		nvals;
	uint8_t			kind;	/* svg_anim_kind_t */
	uint8_t			xtype;	/* svg_xf_t, for a transform */
	uint8_t			calc;	/* svg_calc_t */
	uint8_t			sum;	/* additive="sum" */
	uint8_t			freeze;	/* fill="freeze" */
	uint8_t			mauto;	/* motion: 1 auto, 2 auto-reverse */
} lws_svg_anim_t;

typedef struct lws_svg_node {
	lws_dll2_t		list;	/* ctx->nodes, parents before children */
	struct lws_svg_node	*parent;
	lws_dll2_owner_t	anims;

	svg_c_t			pm[6];	/* where the element is placed, in
					 * the parent node's coordinates */
	svg_c_t			tm[6];	/* the element's own transform */
	int64_t			op;	/* its own opacity, e8, if has_op */

	/* worked out for the time being drawn */

	svg_c_t			e[6];	/* node coords -> root user space */
	int64_t			ope;	/* opacity, with the parents', e8 */
	char			xf;	/* e[] is not the identity */
	char			has_op;	/* its opacity is animated */
} lws_svg_node_t;

typedef struct lws_svg_shape {
	lws_dll2_t		list;	/* document order */
	lws_svg_node_t		*node;	/* innermost animated element, or NULL */
	lws_svg_sub_t		*subs;
	uint32_t		nsubs;
	uint32_t		rgba;	/* fill colour with composed alpha */
	char			rule;	/* 0 = nonzero, 1 = evenodd */
} lws_svg_shape_t;

/* per-open-element inherited state */

typedef struct {
	svg_c_t			m[6];	/* CTM: x' = m[0]x + m[2]y + m[4] */
	uint32_t		rgba;	/* composed fill colour */
	uint32_t		stroke;	/* composed stroke colour, alpha 0 = none */
	int64_t			strokeop;	/* e8 */
	svg_c_t			stroke_w;	/* user units, Q16.16 */
	int64_t			miterlimit;	/* e8, >= 1 */
	uint8_t			linecap;	/* 0 butt, 1 round, 2 square */
	uint8_t			linejoin;	/* 0 miter, 1 round, 2 bevel */
	char			rule;
	char			suppress; /* inside defs, text, unknown... */

	/* for animation of the element the level is for */

	lws_svg_node_t		*node;	/* innermost animated element */
	uint32_t		op_self; /* its own opacity, e8 */
	uint8_t			a_pre;	/* fill alpha before its own opacity */
	uint8_t			sa_pre;	/* stroke alpha before it */
	uint8_t			shape_kind; /* a shape waiting for its close
					     * tag (svg_ekind_t), or 0 */
	char			node_own; /* node is this element's own */
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

	uint32_t	stroke;
	char		stroke_set;
	int64_t		strokeop;
	char		strokeop_set;
	int64_t		strokew;	/* raw number, e8 */
	char		strokew_pct;
	char		strokew_set;
	uint8_t		linecap, linejoin;
	char		linecap_set, linejoin_set;
	int64_t		ml;
	char		ml_set;
} svg_cssrule_t;

/* pending per-tag state, accumulated from attributes as they stream in */

typedef struct {
	uint32_t		fill;	/* valid when fill_present */
	char			fill_present; /* fill attr seen (incl none) */
	int64_t			fillop, op;	/* e8 */
	char			fillop_present, op_present;
	char			rule, rule_present;

	uint32_t		stroke;
	char			stroke_present;
	int64_t			strokeop;	/* e8 */
	char			strokeop_present;
	int64_t			strokew;	/* raw number, e8 */
	char			strokew_pct;	/* it was a percentage */
	char			strokew_present;
	uint8_t			linecap, linejoin;
	char			linecap_present, linejoin_present;
	int64_t			miterlimit;	/* e8 */
	char			miterlimit_present;

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

	uint32_t	sa_stroke;
	char		sa_stroke_present;
	int64_t		sa_strokeop;
	char		sa_strokeop_present;
	int64_t		sa_strokew;		/* raw number, e8 */
	char		sa_strokew_pct;
	char		sa_strokew_present;
	uint8_t		sa_linecap, sa_linejoin;
	char		sa_linecap_present, sa_linejoin_present;
	int64_t		sa_miterlimit;
	char		sa_miterlimit_present;
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
	SVEK_ANIM,		/* animate, set, animateTransform, ... */
} svg_ekind_t;

/*
 * An animation element's attributes, gathered until its tag ends.  The lists
 * are kept as text, since how they parse depends on attributes that may come
 * after them.
 */

enum {
	SVG_AR_VALUES,
	SVG_AR_FROM,
	SVG_AR_TO,
	SVG_AR_BY,
	SVG_AR_KEYTIMES,
	SVG_AR_KEYSPLINES,

	SVG_AR_COUNT
};

typedef struct {
	char			*raw[SVG_AR_COUNT]; /* heap, or NULL */
	lws_svg_dpt_t		*mpts;	/* heap: animateMotion path points */
	size_t			mpts_size; /* allocated bytes */
	uint32_t		nmpts;
	lws_usec_t		begin, dur, rdur;
	int64_t			rcount;	/* e8, -1 = indefinite, 0 = unset */
	svg_c_t			mrot;
	char			attr[16]; /* attributeName */
	uint8_t			xtype;
	uint8_t			calc;
	uint8_t			calc_set, sum, freeze, mauto;
	uint8_t			rdur_set, rdur_indef;
	uint8_t			dur_indef;
	uint8_t			unusable; /* begin we can't do, href, ... */
} svg_apend_t;

/* rasterization scratch */

typedef struct {
	svg_c_t			x;	/* device-space crossing x, Q16.16 */
	int8_t			dir;	/* +1 downwards edge, -1 upwards */
} lws_svg_cross_t;

struct lws_svg {
	/* the whole object: context, working state and scene, one lwsac */

	struct lwsac		*ac;

	/* on svg_scratch.live; largest raster demands this object made */

	lws_dll2_t		scratch_list;
	size_t			aa_need, xings_need;
	lws_dll2_owner_t	shapes;
	uint32_t		nshapes;
	uint32_t		npts;	/* scene-wide flattened point count */

	/* css rules parsed out of <style> blocks */

	svg_cssrule_t		*css;	/* grown by doubling generations */
	uint16_t		css_count, css_cap;
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

	/*
	 * Working geometry (user space), copied into the scene at commit.
	 * These and vbuf are heap, not lwsac, so they can grow without
	 * leaving old generations behind, and be freed when the document is
	 * complete and only the scene is needed.
	 */

	lws_svg_dpt_t		*wpts;
	size_t			wpts_count, wpts_size;
	svg_wsub_t		*wsubs;
	size_t			wsubs_count, wsubs_size;

	/* the px size the scene will be rendered at, or 0 if not known */

	unsigned int		render_w, render_h;

	/* animation */

	lws_dll2_owner_t	nodes;	/* parents before children */
	svg_apend_t		*apend;	/* heap: the animation element being
					 * parsed, or NULL */
	size_t			apend_heap;
	svg_c_t			otm[6];	/* own transform of the element an
					 * animation may be of */
	int			otm_depth; /* its level, or -1 if there's
					    * been anything drawn since */
	lws_usec_t		anim_t;	/* the time the scene is drawn at */
	uint32_t		nnodes;
	uint32_t		nanims;
	char			anim_dirty; /* nodes not yet worked out for
					     * anim_t */

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
 * Shared rasterization scratch: the crossing array and the aa per-column
 * D terms are pure per-line workspace with no carried state, so a single
 * pool is shared by every live svg object (refcounted; freed when the
 * last svg is destroyed).  Rendering is single-threaded, as it already
 * must be for the display list, so turns cannot conflict.
 */

struct svg_scratch {
	lws_dll2_owner_t	live;		/* live svg objects */
	lws_svg_cross_t		*xings;
	size_t			xings_size;	/* allocated entries */
	int64_t			*aa_d;		/* aa: per-column D terms */
	size_t			aa_d_size;	/* allocated entries */
	int			refs;		/* live svg objects */
	int			refs_peak;	/* most live at once */
};

extern struct svg_scratch svg_scratch;

void svg_scratch_ref(void);
void svg_scratch_unref(void);

/*
 * Allocation and heap accounting: the svg object's retained parts (context,
 * stylesheets and scene) live in a single lwsac chained off ctx->ac, with
 * svg_ac_use() the allocation path for them.  The working buffers are
 * separate heap allocations that only live while parsing.  svg_heap_note()
 * tracks the peak simultaneous footprint of both (the lwsac as its total,
 * so including chunk overheads), with transient bytes in flight on top.
 */
void *svg_ac_use(lws_svg_t *ctx, size_t nec);
void svg_heap_note(lws_svg_t *ctx, size_t transient);

/* shared between svg.c and svg-anim.c */

void svg_ws(const char **p, const char *end);
const char *svg_num(const char *p, const char *end, int64_t *r);
int64_t svg_isqrt64(int64_t v);
int64_t svg_atan2(int64_t y_e8, int64_t x_e8);
void xf_ident(svg_c_t m[6]);
void xf_comp(svg_c_t r[6], const svg_c_t m[6], const svg_c_t t[6]);
int svg_xf_fn(svg_xf_t fn, const svg_c_t *arg, int na, svg_c_t t[6]);
int svg_parse_path(lws_svg_t *ctx);

int svg_anim_tag(lws_svg_t *ctx);
void svg_anim_attr(lws_svg_t *ctx);
int svg_anim_open(lws_svg_t *ctx);
void svg_anim_pend_free(lws_svg_t *ctx);
void svg_anim_eval(lws_svg_t *ctx);

/* a scene point mapped through an animated node, or as it is */

static LWS_INLINE void
svg_pt_xf(const lws_svg_node_t *n, const lws_svg_pt_t *in, lws_svg_pt_t *out)
{
	if (!n || !n->xf) {
		*out = *in;
		return;
	}

	out->x = svg_qadd(svg_qadd(svg_qmul(n->e[0], in->x),
				   svg_qmul(n->e[2], in->y)), n->e[4]);
	out->y = svg_qadd(svg_qadd(svg_qmul(n->e[1], in->x),
				   svg_qmul(n->e[3], in->y)), n->e[5]);
}

/* a shape's colour, with the opacity of the animated nodes it is inside */

static LWS_INLINE uint32_t
svg_shape_rgba(const lws_svg_shape_t *sh)
{
	int64_t a;

	if (!sh->node || sh->node->ope >= SVG_E8_1)
		return sh->rgba;

	a = ((int64_t)LWS_SVG_ALPHA(sh->rgba) * sh->node->ope +
						SVG_E8_1 / 2) / SVG_E8_1;

	return (sh->rgba & 0x00ffffff) | ((uint32_t)a << 24);
}

#endif
