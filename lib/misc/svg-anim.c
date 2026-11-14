/*
 * lws svg SMIL animation
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
 * The subset of SMIL animation described in lws-svg.h: <animateTransform>,
 * <animateMotion>, and <animate> / <set> of opacity, as children of the
 * element they animate.
 *
 * Nothing is drawn differently at parse time: an animated element becomes a
 * node, what is drawn inside it is kept in the scene in its own coordinates,
 * and for the time the scene is drawn at, each node's matrix and opacity are
 * worked out from its animations, top down.  The rasterizer maps the points
 * of shapes inside a node through its matrix as it draws them.
 *
 * Times are integer usecs, and all the math is the same pure integer fixed
 * point as the rest of the scene.
 */

#include "private-lib-core.h"
#include "private-lib-misc-svg.h"

/* times are clamped to +/- this, about 11.5 days, so differences can't wrap */
#define SVG_T_MAX		((lws_usec_t)1000000000000ll)
/* the furthest the time the scene is drawn at can be from 0 */
#define SVG_ANIM_T_MAX		((lws_usec_t)1 << 62)

static int
lit(const char *p, const char *end, const char *s)
{
	size_t l = strlen(s);

	return (size_t)(end - p) >= l && !strncmp(p, s, l);
}

/*
 * A SMIL timecount clock value, eg, "2s", "250ms", "1.5min", "0.5h", or a bare
 * number of seconds.  "indefinite" sets *indef.  Anything else, eg, the
 * full clock "00:02", or event and syncbase values, is -1.
 */

static int
clock_parse(const char *s, const char *end, lws_usec_t *us, uint8_t *indef)
{
	const char *p = s, *q;
	int64_t v, mul = LWS_US_PER_SEC, whole, frac;

	*indef = 0;
	svg_ws(&p, end);

	if (lit(p, end, "indefinite")) {
		*indef = 1;
		return 0;
	}

	q = svg_num(p, end, &v);
	if (!q)
		return -1;
	p = q;

	if (lit(p, end, "ms")) {
		mul = 1000;
		p += 2;
	} else if (lit(p, end, "min")) {
		mul = 60ll * LWS_US_PER_SEC;
		p += 3;
	} else if (lit(p, end, "h")) {
		mul = 3600ll * LWS_US_PER_SEC;
		p++;
	} else if (lit(p, end, "s"))
		p++;

	svg_ws(&p, end);
	if (p != end)
		return -1;

	/*
	 * v is at most 1e14 in e8 units, so neither product can overflow: the
	 * whole part is at most 1e6 * 3.6e9, the fraction under 1e8 * 3.6e9
	 */

	whole = v / SVG_E8_1;
	frac = v % SVG_E8_1;
	v = whole * mul + (frac * mul) / SVG_E8_1;

	if (v > SVG_T_MAX)
		v = SVG_T_MAX;
	if (v < -SVG_T_MAX)
		v = -SVG_T_MAX;

	*us = (lws_usec_t)v;

	return 0;
}

/*
 * A ';' separated list of items, each of up to maxk numbers, eg, "0 50 50;
 * 360 50 50", into out[] at stride numbers per item.  Returns the count of
 * items, with each one's count of numbers in nn[], or -1 if it can't be used.
 * A trailing ';' is allowed.
 */

static int
vlist(const char *s, svg_c_t *out, uint8_t *nn, int maxn, int maxk, int stride)
{
	const char *p = s, *end = s + strlen(s);
	int n = 0;

	while (1) {
		const char *ie = p, *q = p;
		int k = 0;

		while (ie < end && *ie != ';')
			ie++;

		svg_ws(&q, ie);
		if (q == ie) {
			/* an empty item is only allowed as the last */
			if (ie == end)
				break;
			return -1;
		}

		if (n >= maxn)
			return -1;

		while (q < ie) {
			const char *r;
			int64_t v;

			if (k >= maxk)
				return -1;
			r = svg_num(q, ie, &v);
			if (!r)
				return -1;
			out[n * stride + k++] = svg_e8_to_c(v);
			q = r;
			svg_ws(&q, ie);
		}

		nn[n++] = (uint8_t)k;

		if (ie == end)
			break;
		p = ie + 1;
	}

	return n;
}

static void
raw_set(lws_svg_t *ctx, int idx)
{
	svg_apend_t *ap = ctx->apend;
	char *r;

	if (ctx->vlen >= LWS_SVG_MAX_ARAW) {
		ap->unusable = 1;
		return;
	}

	r = lws_malloc(ctx->vlen + 1, __func__);
	if (!r) {
		ap->unusable = 1;
		return;
	}
	memcpy(r, ctx->vbuf, ctx->vlen + 1);

	if (ap->raw[idx]) {
		ctx->apend_heap -= strlen(ap->raw[idx]) + 1;
		lws_free(ap->raw[idx]);
	}
	ap->raw[idx] = r;
	ctx->apend_heap += ctx->vlen + 1;
	svg_heap_note(ctx, 0);
}

/*
 * An animation element's tag name was seen: what its attributes say is
 * gathered on the heap until its tag ends, since most documents have none
 */

int
svg_anim_tag(lws_svg_t *ctx)
{
	svg_anim_pend_free(ctx);

	ctx->apend = lws_zalloc(sizeof(*ctx->apend), __func__);
	if (!ctx->apend)
		return 1;

	ctx->apend_heap = sizeof(*ctx->apend);
	svg_heap_note(ctx, 0);

	return 0;
}

/*
 * The motion path is flattened with the scene's path parser, into working
 * arrays of its own: the ones it has may hold the geometry of the shape the
 * animation is inside, waiting for its close tag
 */

static void
motion_path(lws_svg_t *ctx)
{
	svg_apend_t *ap = ctx->apend;
	lws_svg_dpt_t *wpts = ctx->wpts;
	svg_wsub_t *wsubs = ctx->wsubs;
	size_t wpc = ctx->wpts_count, wps = ctx->wpts_size,
	       wsc = ctx->wsubs_count, wss = ctx->wsubs_size;
	uint32_t npts = ctx->npts;

	ctx->wpts = NULL;
	ctx->wsubs = NULL;
	ctx->wpts_count = ctx->wpts_size = 0;
	ctx->wsubs_count = ctx->wsubs_size = 0;

	if (!svg_parse_path(ctx) && ctx->wpts_count &&
	    ctx->wpts_count <= LWS_SVG_MAX_MPTS) {
		/* the points array becomes the pending animation's */
		if (ap->mpts) {
			ctx->apend_heap -= ap->mpts_size;
			lws_free(ap->mpts);
		}
		ap->mpts = ctx->wpts;
		ap->nmpts = (uint32_t)ctx->wpts_count;
		ap->mpts_size = ctx->wpts_size * sizeof(*ap->mpts);
		ctx->apend_heap += ap->mpts_size;
		ctx->wpts = NULL;
	} else
		ap->unusable = 1;

	lws_free(ctx->wpts);
	lws_free(ctx->wsubs);

	ctx->wpts = wpts;
	ctx->wsubs = wsubs;
	ctx->wpts_count = wpc;
	ctx->wpts_size = wps;
	ctx->wsubs_count = wsc;
	ctx->wsubs_size = wss;
	ctx->npts = npts;

	svg_heap_note(ctx, 0);
}

void
svg_anim_pend_free(lws_svg_t *ctx)
{
	svg_apend_t *ap = ctx->apend;
	int n;

	if (!ap)
		return;

	for (n = 0; n < SVG_AR_COUNT; n++)
		lws_free(ap->raw[n]);
	lws_free(ap->mpts);
	lws_free_set_NULL(ctx->apend);

	ctx->apend_heap = 0;
	svg_heap_note(ctx, 0);
}

/* an attribute of an animation element: ctx->aname = ctx->vbuf */

void
svg_anim_attr(lws_svg_t *ctx)
{
	static const char * const rawn[] = {
		"values", "from", "to", "by", "keyTimes", "keySplines"
	};
	svg_apend_t *ap = ctx->apend;
	const char *n = ctx->aname, *v = ctx->vbuf,
		   *end = ctx->vbuf + ctx->vlen;
	lws_usec_t us;
	uint8_t indef;
	int i;

	if (!ap)
		return;

	for (i = 0; i < (int)LWS_ARRAY_SIZE(rawn); i++)
		if (!strcmp(n, rawn[i])) {
			raw_set(ctx, i);
			return;
		}

	if (!strcmp(n, "attributeName")) {
		const char *p = v;

		svg_ws(&p, end);
		lws_strnncpy(ap->attr, p, lws_ptr_diff_size_t(end, p),
			     sizeof(ap->attr));
		return;
	}

	if (!strcmp(n, "type")) {
		static const struct {
			const char	*name;
			svg_xf_t	fn;
		} t[] = {
			{ "translate",	SVG_XF_TRANSLATE },
			{ "scale",	SVG_XF_SCALE },
			{ "rotate",	SVG_XF_ROTATE },
			{ "skewX",	SVG_XF_SKEWX },
			{ "skewY",	SVG_XF_SKEWY },
		};

		for (i = 0; i < (int)LWS_ARRAY_SIZE(t); i++)
			if (!strcmp(v, t[i].name)) {
				ap->xtype = (uint8_t)t[i].fn;
				return;
			}

		ap->unusable = 1;
		return;
	}

	if (!strcmp(n, "calcMode")) {
		static const char * const cm[] = {
			"discrete", "linear", "paced", "spline"
		};

		for (i = 0; i < (int)LWS_ARRAY_SIZE(cm); i++)
			if (!strcmp(v, cm[i])) {
				ap->calc = (uint8_t)i;
				ap->calc_set = 1;
				return;
			}

		ap->unusable = 1;
		return;
	}

	if (!strcmp(n, "begin")) {
		const char *e = v;

		/* only the first of a list of begin times */
		while (e < end && *e != ';')
			e++;

		if (clock_parse(v, e, &us, &indef) || indef)
			/* it starts on an event, or not by itself at all */
			ap->unusable = 1;
		else
			ap->begin = us;
		return;
	}

	if (!strcmp(n, "dur")) {
		if (clock_parse(v, end, &us, &indef) || indef || us <= 0)
			/* the simple duration is indefinite */
			ap->dur = 0;
		else
			ap->dur = us;
		return;
	}

	if (!strcmp(n, "repeatDur")) {
		if (!clock_parse(v, end, &us, &indef) && (indef || us >= 0)) {
			ap->rdur_set = 1;
			ap->rdur_indef = indef;
			ap->rdur = us;
		}
		return;
	}

	if (!strcmp(n, "repeatCount")) {
		const char *p = v;
		int64_t rc;

		svg_ws(&p, end);
		if (lit(p, end, "indefinite"))
			ap->rcount = -1;
		else
			if (svg_num(p, end, &rc) && rc > 0)
				ap->rcount = rc;
		return;
	}

	if (!strcmp(n, "fill")) {
		ap->freeze = !strcmp(v, "freeze");
		return;
	}

	if (!strcmp(n, "additive")) {
		ap->sum = !strcmp(v, "sum");
		return;
	}

	if (!strcmp(n, "path")) {
		if (!strcmp(ctx->name, "animateMotion"))
			motion_path(ctx);
		return;
	}

	if (!strcmp(n, "rotate")) {
		int64_t r;

		if (!strcmp(v, "auto"))
			ap->mauto = 1;
		else
			if (!strcmp(v, "auto-reverse"))
				ap->mauto = 2;
			else
				if (svg_num(v, end, &r))
					ap->mrot = svg_e8_to_c(r);
		return;
	}

	if (!strcmp(n, "href") || !strcmp(n, "xlink:href")) {
		/* only animation of the element it's inside is supported */
		lwsl_info("%s: animation of another element is not supported\n",
			  __func__);
		ap->unusable = 1;
		return;
	}

	/* eg, keyPoints, accumulate, restart: not supported, ignored */
}

/*
 * Animation of an element needs everything inside it held in its coordinates,
 * so the element becomes a node before anything inside it is in the scene.
 * Its static placement and transform move from the level to the node, and the
 * level's matrix becomes the identity, for everything inside it.
 */

static int
node_get(lws_svg_t *ctx, lws_svg_node_t **pn)
{
	svg_lvl_t *l = &ctx->stk[ctx->depth];
	lws_svg_node_t *n;

	*pn = NULL;

	if (l->node_own) {
		*pn = l->node;
		return 0;
	}

	if (ctx->otm_depth != ctx->depth) {
		lwsl_notice("%s: <%s> ignored: an animation must come before "
			    "shapes and groups in the element it animates\n",
			    __func__, ctx->name);
		return 0;
	}

	if (ctx->nnodes >= LWS_SVG_MAX_NODES)
		return 0;

	n = svg_ac_use(ctx, sizeof(*n));
	if (!n)
		return 1;

	memset(n, 0, sizeof(*n));
	n->parent = l->node;
	if (ctx->depth)
		memcpy(n->pm, ctx->stk[ctx->depth - 1].m, sizeof(n->pm));
	else
		xf_ident(n->pm);
	memcpy(n->tm, ctx->otm, sizeof(n->tm));
	xf_ident(n->e);
	n->ope = SVG_E8_1;

	xf_ident(l->m);
	l->node = n;
	l->node_own = 1;

	lws_dll2_add_tail(&n->list, &ctx->nodes);
	ctx->nnodes++;
	*pn = n;

	return 0;
}

/*
 * Check one item of a values, from, to or by list has the numbers its kind
 * needs, and fill in the ones it may leave out, eg, scale(s) is scale(s s)
 */

static int
item_fix(svg_anim_kind_t kind, uint8_t xtype, svg_c_t *v, int k)
{
	switch (kind) {
	case SVG_ANIM_TRANSFORM:
		switch (xtype) {
		case SVG_XF_TRANSLATE:
		case SVG_XF_SCALE:
			if (k < 1 || k > 2)
				return -1;
			break;
		case SVG_XF_ROTATE:
			if (k != 1 && k != 3)
				return -1;
			break;
		default:
			if (k != 1)
				return -1;
			break;
		}
		if (k < 2)
			v[1] = xtype == SVG_XF_SCALE ? v[0] : 0;
		if (k < 3)
			v[2] = 0;
		break;

	case SVG_ANIM_MOTION:
		if (k != 2)
			return -1;
		v[2] = 0;
		break;

	case SVG_ANIM_OPACITY:
		if (k != 1)
			return -1;
		if (v[0] < 0)
			v[0] = 0;
		if (v[0] > SVG_Q16_1)
			v[0] = SVG_Q16_1;
		v[1] = v[2] = 0;
		break;
	}

	return 0;
}

/* parse a one-item from, to or by list */

static int
item_parse(const char *raw, svg_anim_kind_t kind, uint8_t xtype, svg_c_t *v)
{
	uint8_t k;

	if (vlist(raw, v, &k, 1, SVG_ANIM_NPER, SVG_ANIM_NPER) != 1)
		return -1;

	return item_fix(kind, xtype, v, k);
}

/* what svg_anim_open() works with before it knows the animation is usable */

typedef struct {
	svg_c_t		vals[LWS_SVG_MAX_VALUES * SVG_ANIM_NPER];
	svg_c_t		kt[LWS_SVG_MAX_VALUES];
	svg_c_t		ks[LWS_SVG_MAX_VALUES * 4];
	uint8_t		nn[LWS_SVG_MAX_VALUES];
} svg_aopen_t;

/*
 * Work out the values from whichever of path, values, from, to and by the
 * animation has, into w->vals.  Returns the count of values, or -1 if it
 * can't be used.  A path's points are taken from the pending animation
 * directly, and 0 is returned for those.
 */

static int
anim_values(lws_svg_t *ctx, svg_aopen_t *w, svg_anim_kind_t kind)
{
	svg_apend_t *ap = ctx->apend;
	svg_lvl_t *l = &ctx->stk[ctx->depth];
	svg_c_t *base = &w->vals[0], *v1 = &w->vals[SVG_ANIM_NPER];
	char set = !strcmp(ctx->name, "set");
	int nv, i;

	if (kind == SVG_ANIM_MOTION && ap->mpts)
		return 0;

	if (!set && ap->raw[SVG_AR_VALUES]) {
		nv = vlist(ap->raw[SVG_AR_VALUES], w->vals, w->nn,
			   LWS_SVG_MAX_VALUES, SVG_ANIM_NPER, SVG_ANIM_NPER);
		if (nv <= 0)
			return -1;

		for (i = 0; i < nv; i++)
			if (item_fix(kind, ap->xtype,
				     &w->vals[i * SVG_ANIM_NPER], w->nn[i]))
				return -1;

		return nv;
	}

	/*
	 * from / to / by.  Without from, a to-animation runs from the
	 * static value, and a by-animation adds to it.  A set has only to.
	 */

	memset(base, 0, 2 * SVG_ANIM_NPER * sizeof(*base));
	if (kind == SVG_ANIM_TRANSFORM && ap->xtype == SVG_XF_SCALE)
		base[0] = base[1] = SVG_Q16_1;
	if (kind == SVG_ANIM_OPACITY)
		base[0] = (svg_c_t)(((int64_t)l->op_self * SVG_Q16_1) /
								SVG_E8_1);

	if (!set && ap->raw[SVG_AR_FROM] &&
	    item_parse(ap->raw[SVG_AR_FROM], kind, ap->xtype, base))
		return -1;

	if (ap->raw[SVG_AR_TO]) {
		if (item_parse(ap->raw[SVG_AR_TO], kind, ap->xtype, v1))
			return -1;
	} else {
		svg_c_t by[SVG_ANIM_NPER];

		if (set || !ap->raw[SVG_AR_BY] ||
		    item_parse(ap->raw[SVG_AR_BY], kind, ap->xtype, by))
			return -1;

		if (!ap->raw[SVG_AR_FROM])
			ap->sum = 1;
		for (i = 0; i < SVG_ANIM_NPER; i++)
			v1[i] = svg_qadd(base[i], by[i]);
	}

	if (!set)
		return 2;

	memcpy(base, v1, SVG_ANIM_NPER * sizeof(*base));

	return 1;
}

/*
 * The animation element's tag ended: work out its values, check its timing
 * lists agree with them, and add it to the node of the element it is inside.
 *
 * Anything we can't do correctly means the animation is ignored, as SMIL
 * says for errors, and the element is drawn as if it wasn't there.  Only
 * running out of heap is fatal.
 */

int
svg_anim_open(lws_svg_t *ctx)
{
	svg_apend_t *ap = ctx->apend;
	svg_lvl_t *l = &ctx->stk[ctx->depth];
	int nv, nkt = 0, nks = 0, i, j, ret = 0;
	svg_anim_kind_t kind;
	lws_svg_node_t *node;
	lws_svg_anim_t *a;
	svg_aopen_t *w;
	uint8_t nk[LWS_SVG_MAX_VALUES];
	size_t sz;
	uint8_t *u;

	if (!ap || !ctx->root_seen || ap->unusable ||
	    (l->suppress && !l->shape_kind) ||
	    ctx->nanims >= LWS_SVG_MAX_ANIMS)
		return 0;

	/* what it animates */

	if (!strcmp(ctx->name, "animateMotion"))
		kind = SVG_ANIM_MOTION;
	else
		if (!strcmp(ctx->name, "animateTransform")) {
			if (strcmp(ap->attr, "transform"))
				return 0;
			kind = SVG_ANIM_TRANSFORM;
			if (!ap->xtype)
				ap->xtype = SVG_XF_TRANSLATE;
		} else {
			if (strcmp(ap->attr, "opacity")) {
				lwsl_info("%s: animation of '%s' not supported\n",
					  __func__, ap->attr);
				return 0;
			}
			kind = SVG_ANIM_OPACITY;
		}

	if (!strcmp(ctx->name, "set")) {
		/* a set is a discrete animation to its to value */
		ap->calc = SVG_CALC_DISCRETE;
		ap->calc_set = 1;
	}

	if (!ap->calc_set)
		ap->calc = kind == SVG_ANIM_MOTION ? SVG_CALC_PACED :
						     SVG_CALC_LINEAR;

	/* a path is always paced: keyPoints are not supported */

	if (kind == SVG_ANIM_MOTION && ap->mpts)
		ap->calc = SVG_CALC_PACED;

	w = lws_malloc(sizeof(*w), __func__);
	if (!w)
		return 1;
	svg_heap_note(ctx, sizeof(*w));

	nv = anim_values(ctx, w, kind);
	if (!nv)
		nv = (int)ap->nmpts;
	if (nv < 1)
		/* an error, or no values to animate between */
		goto bail;

	/* keyTimes and keySplines must agree with the values */

	if (ap->raw[SVG_AR_KEYTIMES] && ap->calc != SVG_CALC_PACED) {
		nkt = vlist(ap->raw[SVG_AR_KEYTIMES], w->kt, nk,
			    LWS_SVG_MAX_VALUES, 1, 1);
		if (nkt < 1 || nkt != nv || w->kt[0])
			goto bail;
		for (i = 0; i < nkt; i++)
			if (nk[i] != 1 || w->kt[i] < 0 ||
			    w->kt[i] > SVG_Q16_1 ||
			    (i && w->kt[i] < w->kt[i - 1]))
				goto bail;
		if (ap->calc != SVG_CALC_DISCRETE &&
		    w->kt[nkt - 1] != SVG_Q16_1)
			goto bail;
	}

	if (ap->calc == SVG_CALC_SPLINE) {
		if (!ap->raw[SVG_AR_KEYSPLINES] || nv < 2)
			goto bail;
		nks = vlist(ap->raw[SVG_AR_KEYSPLINES], w->ks, nk,
			    LWS_SVG_MAX_VALUES, 4, 4);
		if (nks != nv - 1)
			goto bail;
		for (i = 0; i < nks; i++) {
			if (nk[i] != 4)
				goto bail;
			for (j = 0; j < 4; j++)
				if (w->ks[i * 4 + j] < 0 ||
				    w->ks[i * 4 + j] > SVG_Q16_1)
					goto bail;
		}
	}

	/* only running out of heap for the node is fatal */

	ret = node_get(ctx, &node);
	if (ret || !node)
		goto bail;

	/* the animation goes in the scene, in one allocation */

	sz = sizeof(*a) + (size_t)nv * sizeof(int64_t) +
	     (size_t)nv * SVG_ANIM_NPER * sizeof(svg_c_t) +
	     (size_t)nkt * sizeof(svg_c_t) + (size_t)nks * 4 * sizeof(svg_c_t);

	a = svg_ac_use(ctx, sz);
	if (!a) {
		ret = 1;
		goto bail;
	}

	memset(a, 0, sizeof(*a));
	u = (uint8_t *)(a + 1);

	a->kind = (uint8_t)kind;
	a->xtype = ap->xtype;
	a->calc = ap->calc;
	a->sum = ap->sum;
	a->freeze = ap->freeze;
	a->mauto = ap->mauto;
	a->mrot = ap->mrot;
	a->nvals = (uint16_t)nv;
	a->begin = ap->begin;
	a->dur = ap->dur;

	/* the int64 lengths go first, so they are aligned */

	a->len = (int64_t *)u;
	u += (size_t)nv * sizeof(int64_t);
	a->vals = (svg_c_t *)u;
	u += (size_t)nv * SVG_ANIM_NPER * sizeof(svg_c_t);

	if (kind == SVG_ANIM_MOTION && ap->mpts)
		for (i = 0; i < nv; i++) {
			a->vals[i * SVG_ANIM_NPER] = ap->mpts[i].x;
			a->vals[i * SVG_ANIM_NPER + 1] = ap->mpts[i].y;
			a->vals[i * SVG_ANIM_NPER + 2] = 0;
		}
	else
		memcpy(a->vals, w->vals,
		       (size_t)nv * SVG_ANIM_NPER * sizeof(svg_c_t));

	if (kind == SVG_ANIM_MOTION && a->calc == SVG_CALC_PACED) {
		/* the distance along the path to each value */

		a->len[0] = 0;
		for (i = 1; i < nv; i++) {
			const svg_c_t *p0 = &a->vals[(i - 1) * SVG_ANIM_NPER],
				      *p1 = p0 + SVG_ANIM_NPER;
			/* shifted so the squares can't overflow */
			int64_t dx = ((int64_t)p1[0] - p0[0]) >> 2,
				dy = ((int64_t)p1[1] - p0[1]) >> 2;

			a->len[i] = a->len[i - 1] +
					svg_isqrt64(dx * dx + dy * dy) * 4;
		}
	} else
		a->len = NULL;

	if (nkt) {
		a->kt = (svg_c_t *)u;
		memcpy(a->kt, w->kt, (size_t)nkt * sizeof(svg_c_t));
		u += (size_t)nkt * sizeof(svg_c_t);
	}

	if (nks) {
		a->ks = (svg_c_t *)u;
		memcpy(a->ks, w->ks, (size_t)nks * 4 * sizeof(svg_c_t));
	}

	/*
	 * The active duration: the simple duration repeated repeatCount times,
	 * limited by repeatDur.  -1 is indefinite.
	 */

	{
		lws_usec_t ac = -1, ar = -1;

		if (ap->rdur_set && !ap->rdur_indef)
			ar = ap->rdur;

		if (a->dur) {
			if (ap->rcount > 0) {
				/*
				 * dur is at most 1e12 and rcount 1e14, so
				 * neither product can overflow
				 */
				int64_t wh = ap->rcount / SVG_E8_1,
					fr = ap->rcount % SVG_E8_1;

				ac = a->dur * wh +
					(a->dur * (fr / 1000)) / 100000;
			} else
				if (!ap->rcount && !ap->rdur_set)
					ac = a->dur;
		}

		if (ac < 0 || (ar >= 0 && ar < ac))
			ac = ar;

		a->active = ac;
	}

	/* the element's own opacity is the animation's to replace */

	if (kind == SVG_ANIM_OPACITY && !node->has_op) {
		node->has_op = 1;
		node->op = l->op_self;
		l->rgba = (l->rgba & 0x00ffffff) | ((uint32_t)l->a_pre << 24);
		l->stroke = (l->stroke & 0x00ffffff) |
					((uint32_t)l->sa_pre << 24);
	}

	lws_dll2_add_tail(&a->list, &node->anims);
	ctx->nanims++;
	ctx->anim_dirty = 1;

bail:
	lws_free(w);
	svg_heap_note(ctx, 0);

	return ret;
}

/* a cubic bezier from 0 to 1 with control values c1, c2, at s, all Q16.16 */

static int64_t
bez1(int64_t c1, int64_t c2, int64_t s)
{
	int64_t is = SVG_Q16_1 - s,
		a = (3 * ((is * is) >> 16) * s) >> 16,
		b = (3 * ((is * s) >> 16) * s) >> 16,
		c = (((s * s) >> 16) * s) >> 16;

	return ((a * c1) >> 16) + ((b * c2) >> 16) + c;
}

/*
 * keySplines easing: find the s where the x bezier reaches x, and return the
 * y bezier there.  The control values are in 0..1, so x is monotonic in s.
 */

static int64_t
spline(const svg_c_t *ks, int64_t x)
{
	int64_t lo = 0, hi = SVG_Q16_1;

	while (lo < hi) {
		int64_t s = (lo + hi) / 2;

		if (bez1(ks[0], ks[2], s) < x)
			lo = s + 1;
		else
			hi = s;
	}

	return bez1(ks[1], ks[3], lo);
}

/*
 * The value of an animation at time t, into v[], and for motion, the angle of
 * the path there in degrees, Q16.16.  Returns 0 if it has no effect at t.
 */

static int
anim_sample(const lws_svg_anim_t *a, lws_usec_t t, svg_c_t *v, svg_c_t *deg)
{
	const svg_c_t *v0, *v1;
	int64_t p, f = 0;
	int n = a->nvals, i = 0, k;
	lws_usec_t el;

	if (t < a->begin)
		return 0;

	el = t - a->begin;

	if (a->active >= 0 && el >= a->active) {
		if (!a->freeze)
			return 0;

		/* frozen where the last repeat ended */

		if (!a->dur)
			p = 0;
		else {
			lws_usec_t r = a->active % a->dur;

			p = r ? (r * SVG_Q16_1) / a->dur : SVG_Q16_1;
		}
	} else
		p = a->dur ? ((el % a->dur) * SVG_Q16_1) / a->dur : 0;

	/* which pair of values p is between, and how far: i, f */

	if (n < 2) {
		i = 0;
		f = 0;
	} else
		if (a->calc == SVG_CALC_DISCRETE) {
			if (a->kt) {
				while (i + 1 < n && a->kt[i + 1] <= p)
					i++;
			} else {
				i = (int)((p * n) / SVG_Q16_1);
				if (i >= n)
					i = n - 1;
			}
			f = 0;
		} else
			if (a->len) {
				/* paced: at the same speed all along */

				int64_t total = a->len[n - 1],
					d = (total * p) / SVG_Q16_1;

				while (i + 2 < n && a->len[i + 1] <= d)
					i++;
				f = a->len[i + 1] > a->len[i] ?
					((d - a->len[i]) * SVG_Q16_1) /
						(a->len[i + 1] - a->len[i]) : 0;
				if (f > SVG_Q16_1)
					f = SVG_Q16_1;
			} else {
				if (a->kt) {
					while (i + 2 < n && a->kt[i + 1] <= p)
						i++;
					f = a->kt[i + 1] > a->kt[i] ?
						((p - a->kt[i]) * SVG_Q16_1) /
						  (a->kt[i + 1] - a->kt[i]) :
								SVG_Q16_1;
				} else {
					int64_t seg = p * (n - 1);

					i = (int)(seg >> 16);
					f = seg & 0xffff;
					if (i >= n - 1) {
						i = n - 2;
						f = SVG_Q16_1;
					}
				}
				if (f > SVG_Q16_1)
					f = SVG_Q16_1;
				if (a->calc == SVG_CALC_SPLINE && a->ks)
					f = spline(&a->ks[i * 4], f);
			}

	v0 = &a->vals[i * SVG_ANIM_NPER];
	v1 = i + 1 < n ? v0 + SVG_ANIM_NPER : v0;

	for (k = 0; k < SVG_ANIM_NPER; k++)
		v[k] = (svg_c_t)(v0[k] + ((((int64_t)v1[k] - v0[k]) * f) >> 16));

	if (a->kind == SVG_ANIM_MOTION) {
		*deg = a->mrot;

		if (a->mauto && n >= 2) {
			/* the direction of the segment it is on */

			const svg_c_t *s0 = i + 1 < n ? v0 : v0 - SVG_ANIM_NPER,
				      *s1 = s0 + SVG_ANIM_NPER;
			int64_t r = svg_atan2(
				((int64_t)s1[1] - s0[1]) * SVG_E8_1 / SVG_Q16_1,
				((int64_t)s1[0] - s0[0]) * SVG_E8_1 / SVG_Q16_1);

			*deg = (svg_c_t)((r * 180 * SVG_Q16_1) / SVG_E8_PI);
			if (a->mauto == 2)
				*deg = svg_qadd(*deg, 180 * SVG_Q16_1);
		}
	}

	return 1;
}

/*
 * Work out every node's matrix and opacity for ctx->anim_t, top down: a
 * node's parent was created before it, so is earlier in the list.
 *
 * Each node's matrix is parent node's matrix * where it is placed * motion *
 * its transform, where the transform is its static one, replaced or added to
 * by its transform animations.
 */

void
svg_anim_eval(lws_svg_t *ctx)
{
	lws_start_foreach_dll(lws_dll2_t *, d, lws_dll2_get_head(&ctx->nodes)) {
		lws_svg_node_t *n = lws_container_of(d, lws_svg_node_t, list);
		svg_c_t x[6], mo[6], t6[6], v[SVG_ANIM_NPER], deg = 0;
		int64_t op = n->op;

		memcpy(x, n->tm, sizeof(x));
		xf_ident(mo);

		lws_start_foreach_dll(lws_dll2_t *, da,
				      lws_dll2_get_head(&n->anims)) {
			lws_svg_anim_t *a = lws_container_of(da,
						lws_svg_anim_t, list);

			if (!anim_sample(a, ctx->anim_t, v, &deg))
				continue;

			switch (a->kind) {
			case SVG_ANIM_TRANSFORM:
				svg_xf_fn((svg_xf_t)a->xtype, v,
					  a->xtype == SVG_XF_ROTATE ? 3 :
					  (a->xtype == SVG_XF_TRANSLATE ||
					   a->xtype == SVG_XF_SCALE ? 2 : 1),
					  t6);
				if (a->sum)
					xf_comp(x, x, t6);
				else
					memcpy(x, t6, sizeof(x));
				break;

			case SVG_ANIM_MOTION:
				svg_xf_fn(SVG_XF_ROTATE, &deg, 1, t6);
				t6[4] = v[0];
				t6[5] = v[1];
				if (a->sum)
					xf_comp(mo, mo, t6);
				else
					memcpy(mo, t6, sizeof(mo));
				break;

			case SVG_ANIM_OPACITY:
				op = ((int64_t)v[0] * SVG_E8_1) / SVG_Q16_1;
				break;
			}
		} lws_end_foreach_dll(da);

		xf_comp(t6, n->pm, mo);
		xf_comp(t6, t6, x);

		if (n->parent) {
			xf_comp(n->e, n->parent->e, t6);
			n->ope = n->parent->ope;
		} else {
			memcpy(n->e, t6, sizeof(n->e));
			n->ope = SVG_E8_1;
		}

		if (n->has_op)
			n->ope = (n->ope * op) / SVG_E8_1;

		n->xf = n->e[0] != SVG_Q16_1 || n->e[1] || n->e[2] ||
			n->e[3] != SVG_Q16_1 || n->e[4] || n->e[5];

	} lws_end_foreach_dll(d);

	ctx->anim_dirty = 0;
}

void
lws_svg_set_time(lws_svg_t *ctx, lws_usec_t t)
{
	if (!ctx)
		return;

	/*
	 * Begins are within +/- SVG_T_MAX, so this is as far as t can go
	 * without t - begin wrapping.  It's still ~146,000 years: any clock,
	 * eg, lws_now_usecs(), which is the wall clock on some platforms.
	 */

	if (t > SVG_ANIM_T_MAX)
		t = SVG_ANIM_T_MAX;
	if (t < -SVG_ANIM_T_MAX)
		t = -SVG_ANIM_T_MAX;

	if (t != ctx->anim_t) {
		ctx->anim_t = t;
		ctx->anim_dirty = 1;
	}
}

char
lws_svg_get_animated(const lws_svg_t *ctx)
{
	return ctx && ctx->nanims;
}
