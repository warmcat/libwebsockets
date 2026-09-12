/*
 * lws-api-test-svg
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the stateful SVG linewise renderer against a generated corpus
 * covering each supported feature, with analytic checks: exact span geometry
 * for polygons, independent pixel-centre oracles for curves, invariance
 * checks for transforms, and byte-exact agreement between one-shot and
 * arbitrarily-chunked streaming parses of every corpus document.
 *
 * --dump <dir> additionally writes each corpus document and its rendered
 * coverage as .svg / .pbm pairs for eyeballing.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <unistd.h>
#endif

enum {
	LWS_SW_SVG,
	LWS_SW_OUT,
	LWS_SW_SCALE,
	LWS_SW_BG,
	LWS_SW_DUMP,
	LWS_SW_D,
	LWS_SW_HELP,

	MAX_CASES	= 1024,
	DOC_BUFSZ	= 2048,
	EYEBALL_MAXDIM	= 8192,		/* eyeball mode output size bound */
	EYEBALL_MAXDOC	= 32 * 1024 * 1024,
};

static const struct lws_switches switches[] = {
	[LWS_SW_SVG]	= { "--svg",		"Render this SVG file to a .bmp and exit" },
	[LWS_SW_OUT]	= { "--out",		"Output .bmp path (default <svg>.bmp)" },
	[LWS_SW_SCALE]	= { "--scale",		"Integer output scale (default 1)" },
	[LWS_SW_BG]	= { "--bg",		"Background rrggbb for compositing (default ffffff)" },
	[LWS_SW_DUMP]	= { "--dump",		"Directory to dump corpus svg+pbm into" },
	[LWS_SW_D]	= { "-d",		"Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

static int checks, fails;
static const char *dumpdir;

static int
hexdigit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

#define CHK(_cond, _fmt, ...) do { \
	checks++; \
	if (!(_cond)) { \
		fails++; \
		lwsl_user("FAIL L%d: " _fmt "\n", __LINE__, ##__VA_ARGS__); \
	} \
} while (0)

/* ------------------------------------------------------------------ */
/* coverage bitmap accumulated from rendered spans                     */
/* ------------------------------------------------------------------ */

typedef struct {
	int	w, h;
	int	y;		/* line being rendered */
	uint8_t	*cov;
	uint32_t last_rgba;
	char	any;
} bm_t;

static int
span_cb(void *user, int x0, int x1, uint32_t rgba)
{
	bm_t *bm = (bm_t *)user;

	bm->last_rgba = rgba;
	bm->any = 1;
	while (x0 < x1)
		bm->cov[x0++ + bm->y * bm->w] = 1;

	return 0;
}

static int
bm_alloc(bm_t *bm, int w, int h)
{
	bm->w = w;
	bm->h = h;
	bm->y = 0;
	bm->any = 0;
	bm->last_rgba = 0;
	bm->cov = malloc((size_t)w * (size_t)h);

	return bm->cov ? 0 : 1;
}

static void
bm_free(bm_t *bm)
{
	free(bm->cov);
	bm->cov = NULL;
}

static void
bm_clear(bm_t *bm)
{
	memset(bm->cov, 0, (size_t)bm->w * (size_t)bm->h);
	bm->y = 0;
	bm->any = 0;
	bm->last_rgba = 0;
}

/* render a document into a bitmap; chunk==0 feeds it in one shot,
 * otherwise in chunks of that many bytes (fixed), or -1 for a varying
 * deterministic chunk size */

static lws_stateful_ret_t
render_doc(const char *doc, size_t len, bm_t *bm, int chunkmode)
{
	lws_svg_t *svg = lws_svg_new();
	lws_svg_render_t ri;
	const uint8_t *b;
	size_t l;
	int y;

	if (!svg)
		return LWS_SRET_FATAL;

	b = (const uint8_t *)doc;
	l = len;

	if (!chunkmode) {
		if (lws_svg_parse(svg, &b, &l, 0) & LWS_SRET_FATAL)
			goto fatal;
	} else {
		size_t pos = 0;

		while (pos < len) {
			size_t n = chunkmode > 0 ? (size_t)chunkmode :
					(size_t)(1 + (pos % 7));

			if (n > len - pos)
				n = len - pos;
			b = (const uint8_t *)doc + pos;
			l = n;
			if (lws_svg_parse(svg, &b, &l, 0) & LWS_SRET_FATAL)
				goto fatal;
			pos += n - l;
			if (l) {
				/* parser stopped early: doc complete */
				pos = len;
				break;
			}
		}
	}

	ri.w = bm->w;
	ri.h = bm->h;

	bm_clear(bm);
	for (y = 0; y < bm->h; y++) {
		bm->y = y;
		if (lws_svg_render_line(svg, &ri, y, span_cb, bm) &
							LWS_SRET_FATAL)
			goto fatal;
	}

	lws_svg_free(&svg);

	return LWS_SRET_OK;

fatal:
	lws_svg_free(&svg);

	return LWS_SRET_FATAL;
}

static int
bm_equal(const bm_t *a, const bm_t *b)
{
	if (a->w != b->w || a->h != b->h)
		return 0;

	return !memcmp(a->cov, b->cov, (size_t)a->w * (size_t)a->h);
}

static int
bm_count(const bm_t *bm)
{
	size_t n = (size_t)bm->w * (size_t)bm->h;
	int count = 0;

	while (n--)
		count += bm->cov[n];

	return count;
}

static int
bm_lines(const bm_t *bm)
{
	int y, x, lines = 0;

	for (y = 0; y < bm->h; y++) {
		for (x = 0; x < bm->w; x++)
			if (bm->cov[x + y * bm->w]) {
				lines++;
				break;
			}
	}

	return lines;
}

static int
bm_bbox(const bm_t *bm, int box[4])
{
	int y, x, seen = 0;

	box[0] = box[1] = box[2] = box[3] = -1;

	for (y = 0; y < bm->h; y++)
		for (x = 0; x < bm->w; x++)
			if (bm->cov[x + y * bm->w]) {
				if (!seen) {
					box[0] = box[2] = x;
					box[1] = box[3] = y;
					seen = 1;
				} else {
					if (x < box[0]) box[0] = x;
					if (x > box[2]) box[2] = x;
					if (y < box[1]) box[1] = y;
					if (y > box[3]) box[3] = y;
				}
			}

	return seen;
}

static int
bm_mirror_sym(const bm_t *bm)
{
	int y, x;

	for (y = 0; y < bm->h; y++)
		for (x = 0; x < bm->w; x++)
			if (bm->cov[x + y * bm->w] !=
			    bm->cov[bm->w - 1 - x + y * bm->w])
				return 0;

	return 1;
}

static int
bm_vflip_sym(const bm_t *bm)
{
	int y, x;

	for (y = 0; y < bm->h; y++)
		for (x = 0; x < bm->w; x++)
			if (bm->cov[x + y * bm->w] !=
			    bm->cov[x + (bm->h - 1 - y) * bm->w])
				return 0;

	return 1;
}

/* integer ceil, matching the renderer */

static int
iceil(double v)
{
	int iv = (int)v;

	if ((double)iv == v || v < 0)
		return iv;

	return iv + 1;
}

/* ------------------------------------------------------------------ */
/* independent oracles                                                  */
/* ------------------------------------------------------------------ */

/* exact triangle fill: same centre-sampling model as the renderer */

static void
oracle_tri(bm_t *bm, const int tx[3], const int ty[3])
{
	int y, i;

	memset(bm->cov, 0, (size_t)bm->w * (size_t)bm->h);

	for (y = 0; y < bm->h; y++) {
		double xs[3], ys = (double)y + 0.5;
		int n = 0, j, k;

		for (i = 0; i < 3; i++) {
			int i2 = (i + 1) % 3;
			double y0 = (double)ty[i], y1 = (double)ty[i2];

			if ((y0 > ys) != (y1 > ys)) {
				double t = (ys - y0) / (y1 - y0);

				xs[n++] = (double)tx[i] +
						t * (double)(tx[i2] - tx[i]);
			}
		}
		if (n < 2)
			continue;

		for (j = 0; j < n; j++)
			for (k = j + 1; k < n; k++)
				if (xs[k] < xs[j]) {
					double tt = xs[j];
					xs[j] = xs[k];
					xs[k] = tt;
				}

		for (j = 0; j + 1 < n; j += 2) {
			int x0 = iceil(xs[j] - 0.5), x1 = iceil(xs[j + 1] - 0.5);

			if (x0 < 0) x0 = 0;
			if (x1 > bm->w) x1 = bm->w;
			while (x0 < x1)
				bm->cov[x0++ + y * bm->w] = 1;
		}
	}
}

/* pixel-centre circle membership; returns mismatch count vs the render */

static int
oracle_circle(const bm_t *bm, double cx, double cy, double r)
{
	int y, x, mm = 0;

	for (y = 0; y < bm->h; y++)
		for (x = 0; x < bm->w; x++) {
			double dx = (double)x + 0.5 - cx,
			       dy = (double)y + 0.5 - cy;
			char inside = dx * dx + dy * dy <= r * r;

			if (inside != bm->cov[x + y * bm->w])
				mm++;
		}

	return mm;
}

/* pixel-centre membership of a rotated ellipse */

static int
oracle_ellipse_rot(const bm_t *bm, double cx, double cy, double rx, double ry,
		   double rot)
{
	double c = 1, s = 0;
	int y, x, mm = 0;

	/* rot is in degrees; the test only uses angles with exact-enough
	 * trig from lws_fx, so take it through the same operators */

	{
		lws_fx_t a, res;

		a.whole = (int32_t)(rot * 3.14159265358979 / 180.0);
		a.frac = (int32_t)((rot * 3.14159265358979 / 180.0 -
				(double)(int32_t)(rot * 3.14159265358979 / 180.0))
				* 100000000.0);
		lws_fx_cos(&res, &a);
		c = (double)res.whole + (double)res.frac / 100000000.0;
		lws_fx_sin(&res, &a);
		s = (double)res.whole + (double)res.frac / 100000000.0;
	}

	for (y = 0; y < bm->h; y++)
		for (x = 0; x < bm->w; x++) {
			double dx = (double)x + 0.5 - cx,
			       dy = (double)y + 0.5 - cy;
			/* inverse-rotate the sample point */
			double ux =  c * dx + s * dy,
			       uy = -s * dx + c * dy;
			char inside = (ux * ux) / (rx * rx) +
				      (uy * uy) / (ry * ry) <= 1.0;

			if (inside != bm->cov[x + y * bm->w])
				mm++;
		}

	return mm;
}

/* ------------------------------------------------------------------ */
/* corpus                                                               */
/* ------------------------------------------------------------------ */

enum {
	FAM_GENERIC,		/* use the numeric expectations only */
	FAM_RECT_EXACT,		/* pa..pd = x y w h */
	FAM_CIRCLE,		/* pa pb pc = cx cy r */
	FAM_TRI_EXACT,		/* pa..pd + pe..ph */
	FAM_ORACLE_CIRCLE,	/* pa pb pc = cx cy r, pd = budget */
	FAM_ORACLE_ELLIPSE,	/* pa pb pc pd = cx cy rx ry, pe deg, pf budget */
	FAM_PAIR,		/* pa = index of identical-render twin */
	FAM_FILLRULE,		/* pa = index of evenodd twin */
	FAM_SUPPRESS,		/* exact coverage of the one visible rect */
	FAM_SYMX,		/* generic + mirror symmetry */
	FAM_SYMXSY,		/* generic + mirror and vflip symmetry */
};

#define CC_F_FULLCOVER	1	/* every pixel covered */
#define CC_F_EMPTY	2	/* nothing covered */

typedef struct {
	char	name[48];
	char	doc[DOC_BUFSZ];
	int	w, h;
	int	family;
	int	pa, pb, pc, pd, pe, pf, pg, ph;

	double	exp_area;	/* expected covered pixels */
	double	area_tol;	/* absolute tolerance */
	int	bbox[4];	/* expected inclusive bbox */
	int	bbox_tol;
	int	exp_lines;	/* nonempty line count, or -1 */
	uint32_t exp_rgba;	/* expected last span rgba, 0 = don't check */
	int	exp_w, exp_h;	/* expected intrinsic dims, 0 = don't check */
	uint32_t	flags;
} cc_t;

static cc_t corpus[MAX_CASES];
static int ncases;

static cc_t *
cc_add(const char *name, const char *fmt, ...)
{
	cc_t *cc = &corpus[ncases];
	va_list ap;

	memset(cc, 0, sizeof(*cc));
	cc->bbox[0] = cc->bbox[1] = cc->bbox[2] = cc->bbox[3] = -1;
	cc->exp_lines = -1;
	cc->exp_area = -1;
	cc->w = cc->h = 64;
	cc->exp_w = cc->exp_h = -1;

	lws_strncpy(cc->name, name, sizeof(cc->name));

	va_start(ap, fmt);
	vsnprintf(cc->doc, sizeof(cc->doc), fmt, ap);
	va_end(ap);

	ncases++;

	return cc;
}

/* a plain svg wrapper without width/height (falls back to viewBox) */

static cc_t *
cc_add_vb(const char *name, const char *body, int vw, int vh, int w, int h)
{
	cc_t *cc = cc_add(name,
		"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 %d %d\">%s</svg>",
		vw, vh, body);

	cc->w = w;
	cc->h = h;
	cc->exp_w = vw;
	cc->exp_h = vh;

	return cc;
}

static void
build_corpus_rects(void)
{
	static const int ws[] = { 1, 2, 3, 4, 5, 7, 8, 10, 13, 17, 24, 37, 61 };
	static const int hs[] = { 1, 2, 3, 5, 8, 13, 21, 60 };
	unsigned int i, j;

	for (i = 0; i < LWS_ARRAY_SIZE(ws); i++)
		for (j = 0; j < LWS_ARRAY_SIZE(hs); j++) {
			cc_t *cc = cc_add("rect",
				"<svg xmlns=\"http://www.w3.org/2000/svg\" "
				"width=\"64\" height=\"64\">"
				"<rect x=\"3\" y=\"2\" width=\"%d\" height=\"%d\"/>"
				"</svg>", ws[i], hs[j]);

			cc->family = FAM_RECT_EXACT;
			cc->pa = 3; cc->pb = 2; cc->pc = ws[i]; cc->pd = hs[j];
			cc->exp_area = (double)ws[i] * hs[j];
			cc->area_tol = 0;
			cc->bbox[0] = 3;
			cc->bbox[1] = 2;
			cc->bbox[2] = 3 + ws[i] - 1;
			cc->bbox[3] = 2 + hs[j] - 1;
			cc->bbox_tol = 0;
			cc->exp_lines = hs[j];
			cc->exp_rgba = LWS_SVG_RGBA(0, 0, 0, 255);
			cc->exp_w = cc->exp_h = 64;
		}
}

static void
build_corpus_rrects(void)
{
	static const int rs[] = { 2, 5, 10, 20 };
	static const int es[] = { 40, 60 };
	unsigned int i, j;

	for (i = 0; i < LWS_ARRAY_SIZE(rs); i++)
		for (j = 0; j < LWS_ARRAY_SIZE(es); j++) {
			int r = rs[i], e = es[j];
			/* kappa-corner rounded rect area:
			 * wh - (4 - pi) r² with rx=ry=r */
			double area = (double)e * e - 0.8584073464102069 * r * r;
			cc_t *cc = cc_add("rrect",
				"<svg xmlns=\"http://www.w3.org/2000/svg\" "
				"width=\"64\" height=\"64\">"
				"<rect x=\"2\" y=\"2\" width=\"%d\" height=\"%d\" rx=\"%d\"/>"
				"</svg>", e, e, r);

			cc->exp_area = area;
			cc->area_tol = 2 + 0.06 * (double)r * r;
			cc->bbox[0] = cc->bbox[1] = 2;
			cc->bbox[2] = cc->bbox[3] = 2 + e - 1;
			cc->bbox_tol = 1;
			cc->exp_w = cc->exp_h = 64;
		}
}

static void
build_corpus_circles(void)
{
	static const int rs[] = { 2, 3, 5, 7, 11, 16, 22, 29 };
	unsigned int i, j;

	for (i = 0; i < LWS_ARRAY_SIZE(rs); i++) {
		/* a second position that stays inside the bitmap, and is
		 * only mirror-symmetric about the bitmap centre axis at x */
		static const int pos[][2] = { { 32, 32 }, { 32, 20 } };
		int r0 = rs[i];
		int np = r0 <= 19 ? 2 : 1;

		for (j = 0; j < (unsigned int)np; j++) {
			int r = r0, cx = pos[j][0], cy = pos[j][1];
			cc_t *cc = cc_add("circle",
				"<svg xmlns=\"http://www.w3.org/2000/svg\" "
				"width=\"64\" height=\"64\">"
				"<circle cx=\"%d\" cy=\"%d\" r=\"%d\" fill=\"#080\"/>"
				"</svg>", cx, cy, r);

			cc->family = FAM_CIRCLE;
			cc->pa = cx; cc->pb = cy; cc->pc = r;
			/* pixel-centre sampling can legitimately differ from
			 * the ideal circle area by about half a pixel band
			 * around the perimeter */
			cc->exp_area = 3.14159265358979 * (double)r * r;
			cc->area_tol = 2 + 0.05 * 3.14159265358979 * r * r + r;
			cc->bbox[0] = cx - r; cc->bbox[1] = cy - r;
			cc->bbox[2] = cx + r; cc->bbox[3] = cy + r;
			cc->bbox_tol = 1;
			cc->exp_rgba = LWS_SVG_RGBA(0, 0x88, 0, 255);
			cc->exp_w = cc->exp_h = 64;
		}
	}
}

static void
build_corpus_ellipses(void)
{
	static const int er[][2] = { { 12, 6 }, { 20, 9 }, { 6, 24 },
				     { 30, 5 }, { 9, 9 }, { 26, 18 } };
	unsigned int i;

	for (i = 0; i < LWS_ARRAY_SIZE(er); i++) {
		int rx = er[i][0], ry = er[i][1];
		cc_t *cc = cc_add("ellipse",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" "
			"width=\"64\" height=\"64\">"
			"<ellipse cx=\"32\" cy=\"32\" rx=\"%d\" ry=\"%d\" fill=\"blue\"/>"
			"</svg>", rx, ry);

		cc->family = FAM_SYMXSY;
		cc->exp_area = 3.14159265358979 * (double)rx * ry;
		cc->area_tol = 2 + 0.04 * 3.14159265358979 * rx * ry;
		cc->bbox[0] = 32 - rx; cc->bbox[1] = 32 - ry;
		cc->bbox[2] = 32 + rx; cc->bbox[3] = 32 + ry;
		cc->bbox_tol = 1;
		cc->exp_w = cc->exp_h = 64;
	}
}

static void
build_corpus_polys(void)
{
	static const int ts[][6] = {
		{ 10, 10, 50, 20, 20, 50 },
		{ 5, 5, 59, 5, 5, 59 },
		{ 30, 4, 58, 40, 2, 58 },
		{ 8, 56, 12, 8, 60, 12 },
		{ 1, 1, 63, 2, 62, 63 },
		{ 40, 2, 60, 30, 40, 62 },   /* obtuse */
		{ 20, 30, 44, 30, 32, 31 },  /* sliver */
		{ 32, 32, 40, 40, 24, 40 },  /* tiny */
	};
	unsigned int i;

	for (i = 0; i < LWS_ARRAY_SIZE(ts); i++) {
		const int *t = ts[i];
		cc_t *cc = cc_add("poly-tri",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" "
			"width=\"64\" height=\"64\">"
			"<polygon points=\"%d,%d %d,%d %d,%d\"/></svg>",
			t[0], t[1], t[2], t[3], t[4], t[5]);

		cc->family = FAM_TRI_EXACT;
		cc->pa = t[0]; cc->pb = t[1]; cc->pc = t[2];
		cc->pd = t[3]; cc->pe = t[4]; cc->pf = t[5];
		cc->exp_rgba = LWS_SVG_RGBA(0, 0, 0, 255);
		cc->exp_w = cc->exp_h = 64;
	}
}

static void
build_corpus_paths(void)
{
	cc_t *cc;
	int base;

	/* circle via four explicit cubic C segments (kappa controls) */

	cc = cc_add("path-c-circle",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 32 8 C 45.25 8 56 18.75 56 32 "
		"C 56 45.25 45.25 56 32 56 C 18.75 56 8 45.25 8 32 "
		"C 8 18.75 18.75 8 32 8 Z\"/></svg>");
	cc->family = FAM_ORACLE_CIRCLE;
	cc->pa = cc->pb = 32;
	cc->pc = 24;
	cc->pd = 40;	/* mismatch budget */
	cc->exp_area = 3.14159265358979 * 24 * 24;
	cc->area_tol = 40;
	cc->exp_w = cc->exp_h = 64;

	/* circle via two half-arcs, exercising the A conversion */

	cc = cc_add("path-a-circle",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 8 32 A 24 24 0 1 0 56 32 A 24 24 0 1 0 8 32 Z\"/></svg>");
	cc->family = FAM_ORACLE_CIRCLE;
	cc->pa = cc->pb = 32;
	cc->pc = 24;
	cc->pd = 24;
	cc->exp_area = 3.14159265358979 * 24 * 24;
	cc->area_tol = 40;
	cc->exp_w = cc->exp_h = 64;

	/* rotated elliptical arc pair: two half-arcs about (32,40) with
	 * rotation 30deg chosen so no radius correction kicks in */

	cc = cc_add("path-a-ellipserot",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 6.02 25 A 30 12 30 0 1 57.98 55 "
		"A 30 12 30 0 1 6.02 25 Z\"/></svg>");
	cc->family = FAM_ORACLE_ELLIPSE;
	cc->pa = 32; cc->pb = 40; cc->pc = 30; cc->pd = 12;
	cc->pe = 30;	/* degrees */
	cc->pf = 40;	/* mismatch budget */
	cc->exp_w = cc->exp_h = 64;

	/* Q/T paths must be geometrically identical to the equivalent
	 * explicit cubic form: quad elevation is exact */

	base = ncases;
	(void)cc_add("path-q",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 8 8 Q 56 8 56 32 T 8 56 Z\"/></svg>");
	cc = cc_add("path-q-as-c",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		/* Q elevated: c1 = p0 + 2/3 (p1-p0), c2 = p2 + 2/3 (p1-p2) */
		"<path d=\"M 8 8 C 40 8 56 16 56 32 "
		/* T reflects (56,8) about (56,32) -> (56,56); elevated */
		"C 56 48 40 56 8 56 Z\"/></svg>");
	cc->family = FAM_PAIR;
	cc->pa = base;
	cc->exp_w = cc->exp_h = 64;

	/* H/V/implicit repeats and no-separator syntax */

	cc = cc_add("path-hv-compact",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M10 10H54V46H10Z\"/></svg>");
	cc->exp_area = 44.0 * 36.0;
	cc->area_tol = 0;
	cc->bbox[0] = 10; cc->bbox[1] = 10; cc->bbox[2] = 53; cc->bbox[3] = 45;
	cc->bbox_tol = 0;
	cc->exp_lines = 36;
	cc->exp_w = cc->exp_h = 64;

	/* two subpaths, both wound the same way: union coverage */

	cc = cc_add("path-two-subpaths",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 4 4 H 30 V 30 H 4 Z M 20 20 H 46 V 46 H 20 Z\"/></svg>");
	cc->exp_area = 26.0 * 26.0 + 26.0 * 26.0 - 10.0 * 10.0;
	cc->area_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* same two rects, one wound backwards: nonzero hollows the
	 * intersection, even-odd xors it... both analytically exact */

	base = ncases;
	cc = cc_add("path-rev-nonzero",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 4 4 H 30 V 30 H 4 Z M 20 20 V 46 H 46 V 20 Z\"/></svg>");
	cc->exp_area = 26.0 * 26.0 * 2.0 - 10.0 * 10.0 * 2.0;
	cc->area_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	cc = cc_add("path-rev-evenodd",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path fill-rule=\"evenodd\" d=\"M 4 4 H 30 V 30 H 4 Z "
		"M 20 20 V 46 H 46 V 20 Z\"/></svg>");
	cc->exp_area = 26.0 * 26.0 * 2.0 - 10.0 * 10.0 * 2.0;
	cc->area_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* pentagram: nonzero fills the centre, evenodd hollows it */

	base = ncases;
	(void)cc_add("pentagram-nonzero",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 32 6 L 52 52 L 8 22 L 56 22 L 12 52 Z\"/></svg>");
	cc = cc_add("pentagram-evenodd",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path fill-rule=\"evenodd\" "
		"d=\"M 32 6 L 52 52 L 8 22 L 56 22 L 12 52 Z\"/></svg>");
	cc->family = FAM_FILLRULE;
	cc->pa = base;
	cc->exp_w = cc->exp_h = 64;
}

static void
build_corpus_xforms(void)
{
	cc_t *cc;
	int base;

	/* translate: exactly shifted bitmap */

	(void)cc_add("xform-base",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<rect x=\"6\" y=\"8\" width=\"20\" height=\"14\"/></svg>");
	cc = cc_add("xform-translate",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"translate(9 5)\">"
		"<rect x=\"6\" y=\"8\" width=\"20\" height=\"14\"/></g></svg>");
	cc->exp_area = 280;
	cc->area_tol = 0;
	cc->bbox[0] = 15; cc->bbox[1] = 13; cc->bbox[2] = 34; cc->bbox[3] = 26;
	cc->bbox_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* integer upscale: exactly 4x coverage */

	cc = cc_add("xform-scale2",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"scale(2)\">"
		"<rect x=\"5\" y=\"5\" width=\"10\" height=\"6\"/></g></svg>");
	cc->exp_area = 20.0 * 12.0;
	cc->area_tol = 0;
	cc->bbox[0] = cc->bbox[1] = 10;
	cc->bbox[2] = 29; cc->bbox[3] = 21;
	cc->bbox_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* quarter-turn: exact area, rotated bbox: (12,22)-(42,42) turns
	 * to x'[22,42] y'[12,42] about (32,32) */

	cc = cc_add("xform-rot90",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"rotate(90 32 32)\">"
		"<rect x=\"12\" y=\"22\" width=\"30\" height=\"20\"/></g></svg>");
	cc->exp_area = 600;
	cc->area_tol = 2;
	cc->bbox[0] = 22; cc->bbox[1] = 12; cc->bbox[2] = 42; cc->bbox[3] = 42;
	cc->bbox_tol = 1;
	cc->exp_w = cc->exp_h = 64;

	/* arbitrary rotation: area preserved */

	cc = cc_add("xform-rot37",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"rotate(37 30 30)\">"
		"<rect x=\"14\" y=\"20\" width=\"26\" height=\"16\"/></g></svg>");
	cc->exp_area = 26.0 * 16.0;
	cc->area_tol = 26 * 16 * 0.015 + 2;
	cc->exp_w = cc->exp_h = 64;

	/* skewX(45): unit determinant, so area preserved exactly-ish */

	cc = cc_add("xform-skew45",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"skewX(45)\">"
		"<rect x=\"4\" y=\"20\" width=\"16\" height=\"16\"/></g></svg>");
	cc->exp_area = 256;
	cc->area_tol = 3;
	cc->exp_w = cc->exp_h = 64;

	/* nested transforms must equal the composed single transform */

	base = ncases;
	(void)cc_add("xform-nested",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"translate(10 4)\">"
		"<g transform=\"rotate(30)\">"
		"<g transform=\"scale(1.5)\">"
		"<circle cx=\"12\" cy=\"12\" r=\"10\"/></g></g></g></svg>");
	cc = cc_add("xform-composed",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"translate(10 4) rotate(30) scale(1.5)\">"
		"<circle cx=\"12\" cy=\"12\" r=\"10\"/></g></svg>");
	cc->family = FAM_PAIR;
	cc->pa = base;
	cc->exp_w = cc->exp_h = 64;

	/* transform on the shape itself equals the same transform on a g */

	base = ncases;
	(void)cc_add("xform-on-g",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<g transform=\"matrix(1.2 0.1 -0.2 0.9 8 6)\">"
		"<rect x=\"10\" y=\"10\" width=\"24\" height=\"16\"/></g></svg>");
	cc = cc_add("xform-on-shape",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<rect x=\"10\" y=\"10\" width=\"24\" height=\"16\" "
		"transform=\"matrix(1.2 0.1 -0.2 0.9 8 6)\"/></svg>");
	cc->family = FAM_PAIR;
	cc->pa = base;
	cc->exp_w = cc->exp_h = 64;
}

static void
build_corpus_colors(void)
{
	struct {
		const char *name, *fill;
		uint32_t rgba;
	} cs[] = {
		{ "hex3",	"#f80",	LWS_SVG_RGBA(0xff, 0x88, 0, 255) },
		{ "hex4",	"#f80c", LWS_SVG_RGBA(0xff, 0x88, 0, 0xcc) },
		{ "hex6",	"#123456", LWS_SVG_RGBA(0x12, 0x34, 0x56, 255) },
		{ "hex8",	"#12345678", LWS_SVG_RGBA(0x12, 0x34, 0x56, 0x78) },
		{ "rgbf",	"rgb(1, 22, 255)", LWS_SVG_RGBA(1, 22, 255, 255) },
		{ "rgbapct",	"rgba(100%, 0%, 50%, 0.5)",
					LWS_SVG_RGBA(255, 0, 127, 128) },
		{ "named",	"rebeccapurple", LWS_SVG_RGBA(0x66, 0x33, 0x99, 255) },
		{ "namedci",	"DODGERBLUE", LWS_SVG_RGBA(0x1e, 0x90, 0xff, 255) },
		{ "curcol",	"currentColor", LWS_SVG_RGBA(0, 0, 0, 255) },
		{ "red",	"red", LWS_SVG_RGBA(0xff, 0, 0, 255) },
	};
	unsigned int i;

	for (i = 0; i < LWS_ARRAY_SIZE(cs); i++) {
		cc_t *cc = cc_add("colour",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
			"<rect x=\"10\" y=\"10\" width=\"20\" height=\"12\" fill=\"%s\"/>"
			"</svg>", cs[i].fill);

		cc->exp_rgba = cs[i].rgba;
		cc->exp_area = 240;
		cc->area_tol = 0;
		cc->bbox[0] = 10; cc->bbox[1] = 10; cc->bbox[2] = 29; cc->bbox[3] = 21;
		cc->bbox_tol = 0;
		cc->exp_lines = 12;
		cc->exp_w = cc->exp_h = 64;
	}

	/* opacity composition */

	{
		cc_t *cc = cc_add("fillop-half",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
			"<rect x=\"4\" y=\"4\" width=\"10\" height=\"10\" "
			"fill=\"#ffffff\" fill-opacity=\"0.5\"/></svg>");
		cc->exp_rgba = LWS_SVG_RGBA(255, 255, 255, 128);
		cc->exp_area = 100;
		cc->area_tol = 0;
		cc->exp_w = cc->exp_h = 64;

		cc = cc_add("op-quarter",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
			"<g opacity=\"0.5\">"
			"<rect x=\"4\" y=\"4\" width=\"10\" height=\"10\" "
			"fill=\"#ffffff\" fill-opacity=\"0.5\"/></g></svg>");
		cc->exp_rgba = LWS_SVG_RGBA(255, 255, 255, 128);
		cc->exp_area = 100;
		cc->area_tol = 0;
		cc->exp_w = cc->exp_h = 64;
	}

	/* unpaintable fills */

	{
		cc_t *cc = cc_add("fill-none",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
			"<rect x=\"4\" y=\"4\" width=\"10\" height=\"10\" fill=\"none\"/>"
			"</svg>");
		cc->flags = CC_F_EMPTY;
		cc->exp_w = cc->exp_h = 64;

		cc = cc_add("fill-url",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
			"<rect x=\"4\" y=\"4\" width=\"10\" height=\"10\" "
			"fill=\"url(#missing)\"/></svg>");
		cc->flags = CC_F_EMPTY;
		cc->exp_w = cc->exp_h = 64;
	}

	/* inheritance and override via presentation attrs and style= */

	{
		cc_t *cc = cc_add("inherit-fill",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
			"<g fill=\"#00f\" fill-opacity=\"0.5\" style=\"fill-rule:evenodd\">"
			"<rect x=\"4\" y=\"4\" width=\"10\" height=\"10\"/></g></svg>");
		cc->exp_rgba = LWS_SVG_RGBA(0, 0, 255, 128);
		cc->exp_area = 100;
		cc->area_tol = 0;
		cc->exp_w = cc->exp_h = 64;

		cc = cc_add("style-override",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
			"<g fill=\"#00f\">"
			"<rect x=\"4\" y=\"4\" width=\"10\" height=\"10\" "
			"style=\"fill: #0f0; opacity: 0.5\"/></g></svg>");
		cc->exp_rgba = LWS_SVG_RGBA(0, 255, 0, 128);
		cc->exp_area = 100;
		cc->area_tol = 0;
		cc->exp_w = cc->exp_h = 64;
	}
}

static void
build_corpus_viewbox(void)
{
	cc_t *cc;

	/* uniform 2x scale: circle r=20 in vb becomes r=40 in device */

	cc = cc_add_vb("vb-2x",
		"<circle cx=\"48\" cy=\"24\" r=\"20\"/>", 96, 48, 192, 96);
	cc->family = FAM_ORACLE_CIRCLE;
	cc->pa = 96; cc->pb = 48; cc->pc = 40; cc->pd = 60;
	cc->exp_area = 3.14159265358979 * 40 * 40;
	cc->area_tol = 100;

	/* meet: letterbox the 96x48 content in a 96x200 box */

	cc = cc_add_vb("vb-meet",
		"<rect x=\"0\" y=\"0\" width=\"96\" height=\"48\"/>", 96, 48, 96, 200);
	cc->exp_area = 96.0 * 48.0;
	cc->area_tol = 0;
	cc->bbox[0] = 0; cc->bbox[1] = 76; cc->bbox[2] = 95; cc->bbox[3] = 123;
	cc->bbox_tol = 0;
	cc->exp_lines = 48;

	/* slice: cover the box, cropping x */

	cc = cc_add("vb-slice",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" "
		"viewBox=\"0 0 96 48\" preserveAspectRatio=\"xMidYMid slice\">"
		"<rect x=\"0\" y=\"0\" width=\"96\" height=\"48\"/></svg>");
	cc->w = 96;
	cc->h = 200;
	cc->flags = CC_F_FULLCOVER;
	cc->exp_w = 96;
	cc->exp_h = 48;

	/* none: stretch */

	cc = cc_add("vb-none",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" "
		"viewBox=\"0 0 96 48\" preserveAspectRatio=\"none\">"
		"<rect x=\"0\" y=\"0\" width=\"96\" height=\"48\"/></svg>");
	cc->w = 96;
	cc->h = 200;
	cc->flags = CC_F_FULLCOVER;
	cc->exp_w = 96;
	cc->exp_h = 48;

	/* xMaxYMax meet alignment */

	cc = cc_add("vb-xmaxymax",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" "
		"viewBox=\"0 0 96 48\" preserveAspectRatio=\"xMaxYMax meet\">"
		"<rect x=\"0\" y=\"0\" width=\"96\" height=\"48\"/></svg>");
	cc->w = 200;
	cc->h = 48;
	cc->exp_area = 96.0 * 48.0;
	cc->area_tol = 0;
	cc->bbox[0] = 104; cc->bbox[1] = 0; cc->bbox[2] = 199; cc->bbox[3] = 47;
	cc->bbox_tol = 0;
	cc->exp_w = 96;
	cc->exp_h = 48;

	/* width/height in px with no viewBox: scaled to the render size */

	cc = cc_add("pxdims",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"48\" height=\"24\">"
		"<rect x=\"0\" y=\"0\" width=\"48\" height=\"24\"/></svg>");
	cc->w = 96;
	cc->h = 48;
	cc->flags = CC_F_FULLCOVER;
	cc->exp_w = 48;
	cc->exp_h = 24;

	/* percent dims resolve via the viewBox for intrinsic size */

	cc = cc_add("percent-dims",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100%\" height=\"100%\" "
		"viewBox=\"0 0 80 40\">"
		"<rect x=\"0\" y=\"0\" width=\"80\" height=\"40\"/></svg>");
	cc->w = 80;
	cc->h = 40;
	cc->flags = CC_F_FULLCOVER;
	cc->exp_w = 80;
	cc->exp_h = 40;

	/* nothing at all: CSS default replaced element size, 1:1 render */

	cc = cc_add("no-dims",
		"<svg xmlns=\"http://www.w3.org/2000/svg\">"
		"<rect x=\"0\" y=\"0\" width=\"300\" height=\"150\"/></svg>");
	cc->w = 100;
	cc->h = 50;
	cc->flags = CC_F_FULLCOVER;
	cc->exp_w = 300;
	cc->exp_h = 150;

	/* non-zero viewBox origin is honoured */

	cc = cc_add("vb-origin",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" "
		"viewBox=\"20 10 40 40\">"
		"<rect x=\"20\" y=\"10\" width=\"40\" height=\"40\"/></svg>");
	cc->w = cc->h = 40;
	cc->flags = CC_F_FULLCOVER;
	cc->exp_w = 40;
	cc->exp_h = 40;
}

static void
build_corpus_structural(void)
{
	cc_t *cc;

	/* defs content must not render */

	cc = cc_add("defs-suppressed",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<defs><rect x=\"0\" y=\"0\" width=\"60\" height=\"60\"/>"
		"<path d=\"M 0 0 L 60 60\"/></defs>"
		"<rect x=\"8\" y=\"8\" width=\"20\" height=\"10\"/></svg>");
	cc->exp_area = 200;
	cc->area_tol = 0;
	cc->bbox[0] = 8; cc->bbox[1] = 8; cc->bbox[2] = 27; cc->bbox[3] = 17;
	cc->bbox_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* text, use, unknown subtrees must not render either */

	cc = cc_add("text-unknown-suppressed",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<text><rect x=\"0\" y=\"0\" width=\"62\" height=\"62\"/></text>"
		"<wibble><circle cx=\"32\" cy=\"32\" r=\"30\"/></wibble>"
		"<use href=\"#nope\"/>"
		"<rect x=\"4\" y=\"4\" width=\"12\" height=\"9\"/></svg>");
	cc->exp_area = 108;
	cc->area_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* xml prolog, doctype, comments, PI and CDATA wrappers tolerated */

	cc = cc_add("wrappers",
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" "
		"\"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n"
		"<!-- a comment -->\n"
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<!-- inner <!-- nest --> comment -->"
		"<![CDATA[ raw < & > ]]>"
		"<?pi content ?>"
		"<rect x=\"6\" y=\"6\" width=\"16\" height=\"8\"/>"
		"</svg>\n<!-- trailing -->\n");
	cc->exp_area = 128;
	cc->area_tol = 0;
	cc->bbox[0] = 6; cc->bbox[1] = 6; cc->bbox[2] = 21; cc->bbox[3] = 13;
	cc->bbox_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* numeric and named entities inside attributes */

	cc = cc_add("entities",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"&#77; 10 10 L 50 10 L 50 40 L 10 40 Z\" "
		"fill=\"&#35;ff0000\"/></svg>");
	cc->exp_area = 40.0 * 30.0;
	cc->area_tol = 0;
	cc->exp_rgba = LWS_SVG_RGBA(0xff, 0, 0, 255);
	cc->exp_w = cc->exp_h = 64;

	/* BOM + CRLF whitespace */

	cc = cc_add("bom-crlf",
		"\xef\xbb\xbf<svg xmlns=\"http://www.w3.org/2000/svg\" "
		"width=\"64\"\r\n height=\"64\">\r\n"
		"<rect\r\n x=\"10\" y=\"10\" width=\"10\"\r\n height=\"10\"/>\r\n"
		"</svg>");
	cc->exp_area = 100;
	cc->area_tol = 0;
	cc->exp_w = cc->exp_h = 64;

	/* line and polyline fills produce nothing (stroke-only in this
	 * phase) */

	cc = cc_add("line-empty",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<line x1=\"4\" y1=\"4\" x2=\"60\" y2=\"60\"/>"
		"<polyline points=\"4,60 60,4\"/></svg>");
	cc->flags = CC_F_EMPTY;
	cc->exp_w = cc->exp_h = 64;

	/* zero and negative geometry is dropped, rest renders */

	cc = cc_add("degenerate",
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<rect x=\"4\" y=\"4\" width=\"0\" height=\"10\"/>"
		"<rect x=\"4\" y=\"4\" width=\"10\" height=\"-3\"/>"
		"<circle cx=\"32\" cy=\"32\" r=\"0\"/>"
		"<path d=\"M 20 20 L 40 20\"/>"
		"<rect x=\"30\" y=\"30\" width=\"8\" height=\"8\"/></svg>");
	cc->exp_area = 64;
	cc->area_tol = 0;
	cc->exp_w = cc->exp_h = 64;
}

static void
build_corpus(void)
{
	build_corpus_rects();
	build_corpus_rrects();
	build_corpus_circles();
	build_corpus_ellipses();
	build_corpus_polys();
	build_corpus_paths();
	build_corpus_xforms();
	build_corpus_colors();
	build_corpus_viewbox();
	build_corpus_structural();
}

/* ------------------------------------------------------------------ */
/* per-case checking                                                    */
/* ------------------------------------------------------------------ */

/* the bitmap and coverage of the previous corpus case, for pair families
 * whose twin is always the immediately preceding case */

static bm_t pair_bm;
static int pair_cov;

static void
check_case(int idx, bm_t *bm)
{
	cc_t *cc = &corpus[idx];
	const char *nm = cc->name;
	lws_svg_t *svg;
	const uint8_t *b;
	size_t l;
	int cov, box[4];

	/* intrinsic dimensions */

	svg = lws_svg_new();
	CHK(svg, "%s: OOM", nm);
	if (!svg)
		return;
	b = (const uint8_t *)cc->doc;
	l = strlen(cc->doc);
	CHK(lws_svg_parse(svg, &b, &l, 0) == LWS_SRET_OK &&
	    lws_svg_get_doc_complete(svg),
	    "%s: doc did not parse to completion", nm);

	if (cc->exp_w >= 0)
		CHK((int)lws_svg_get_width(svg) == cc->exp_w,
				"%s: width %d vs %d", nm,
				(int)lws_svg_get_width(svg), cc->exp_w);
	if (cc->exp_h >= 0)
		CHK((int)lws_svg_get_height(svg) == cc->exp_h,
				"%s: height %d vs %d", nm,
				(int)lws_svg_get_height(svg), cc->exp_h);

	/* hold-at-metadata must yield the same dims from the root tag alone */

	{
		lws_svg_t *s2 = lws_svg_new();
		const uint8_t *b2;
		size_t l2 = strlen(cc->doc);
		lws_stateful_ret_t r;

		b2 = (const uint8_t *)cc->doc;
		r = lws_svg_parse(s2, &b2, &l2, 1);
		CHK(r == LWS_SRET_OK, "%s: hold parse returned %d", nm, r);
		CHK((int)lws_svg_get_width(s2) == (int)lws_svg_get_width(svg),
				"%s: hold dims differ", nm);
		lws_svg_free(&s2);
	}

	lws_svg_free(&svg);

	/* generic numeric expectations */

	cov = bm_count(bm);

	if (cc->flags & CC_F_EMPTY)
		CHK(!bm->any && cov == 0, "%s: expected empty render", nm);

	if (cc->flags & CC_F_FULLCOVER)
		CHK(cov == bm->w * bm->h, "%s: expected full cover, %d / %d",
					nm, cov, bm->w * bm->h);

	if (cc->exp_area >= 0) {
		CHK((double)cov >= cc->exp_area - cc->area_tol &&
		    (double)cov <= cc->exp_area + cc->area_tol,
			"%s: coverage %d vs %f (±%f)", nm, cov,
			cc->exp_area, cc->area_tol);
	}

	if (bm_bbox(bm, box)) {
		int tol = cc->bbox_tol >= 0 ? cc->bbox_tol : 0;

		if (cc->bbox[0] >= 0)
			CHK(box[0] >= cc->bbox[0] - tol &&
			    box[0] <= cc->bbox[0] + tol &&
			    box[1] >= cc->bbox[1] - tol &&
			    box[1] <= cc->bbox[1] + tol &&
			    box[2] >= cc->bbox[2] - tol &&
			    box[2] <= cc->bbox[2] + tol &&
			    box[3] >= cc->bbox[3] - tol &&
			    box[3] <= cc->bbox[3] + tol,
				"%s: bbox [%d %d %d %d] vs [%d %d %d %d] ±%d",
				nm, box[0], box[1], box[2], box[3],
				cc->bbox[0], cc->bbox[1], cc->bbox[2],
				cc->bbox[3], tol);
	} else
		CHK(!(cc->exp_area > 0), "%s: nothing rendered", nm);

	if (cc->exp_lines >= 0)
		CHK(bm_lines(bm) == cc->exp_lines,
				"%s: lines %d vs %d", nm, bm_lines(bm),
				cc->exp_lines);

	if (cc->exp_rgba)
		CHK(bm->last_rgba == cc->exp_rgba,
				"%s: rgba 0x%08x vs 0x%08x", nm, bm->last_rgba,
				cc->exp_rgba);

	/* family-specific checks */

	switch (cc->family) {
	case FAM_RECT_EXACT:
	{
		int y;

		for (y = 0; y < bm->h; y++) {
			int x, cnt = 0;

			for (x = 0; x < bm->w; x++)
				cnt += bm->cov[x + y * bm->w];
			CHK(cnt == ((y >= cc->pb && y < cc->pb + cc->pd) ?
					cc->pc : 0),
				"%s: line %d count %d", nm, y, cnt);
			if (cnt != ((y >= cc->pb && y < cc->pb + cc->pd) ?
					cc->pc : 0))
				break;
		}
		break;
	}
	case FAM_CIRCLE:
		/* mirror symmetry only holds when centred on the axis */

		if (cc->pa == 32)
			CHK(bm_mirror_sym(bm), "%s: not mirror symmetric", nm);
		CHK(oracle_circle(bm, cc->pa, cc->pb, cc->pc) <= 12 + cc->pc,
				"%s: circle oracle mismatch %d", nm,
				oracle_circle(bm, cc->pa, cc->pb, cc->pc));
		break;

	case FAM_TRI_EXACT:
	{
		static bm_t orb;	/* reused */
		static int orb_init;
		int tx[3] = { cc->pa, cc->pc, cc->pe };
		int ty[3] = { cc->pb, cc->pd, cc->pf };

		if (!orb_init) {
			CHK(!bm_alloc(&orb, bm->w, bm->h), "%s: oracle OOM", nm);
			orb_init = 1;
		}
		oracle_tri(&orb, tx, ty);
		CHK(bm_equal(bm, &orb), "%s: triangle oracle mismatch", nm);
		break;
	}

	case FAM_ORACLE_CIRCLE:
		CHK(oracle_circle(bm, cc->pa, cc->pb, cc->pc) <= cc->pd,
				"%s: circle oracle mismatch %d > %d", nm,
				oracle_circle(bm, cc->pa, cc->pb, cc->pc),
				cc->pd);
		break;

	case FAM_ORACLE_ELLIPSE:
		CHK(oracle_ellipse_rot(bm, cc->pa, cc->pb, cc->pc, cc->pd,
						cc->pe) <= cc->pf,
				"%s: ellipse oracle mismatch %d > %d", nm,
				oracle_ellipse_rot(bm, cc->pa, cc->pb,
						cc->pc, cc->pd, cc->pe), cc->pf);
		break;

	case FAM_PAIR:
		CHK(cc->pa == idx - 1, "%s: twin not the previous case", nm);
		if (cc->pa == idx - 1)
			CHK(bm_equal(bm, &pair_bm), "%s: differs from twin", nm);
		break;

	case FAM_FILLRULE:
		CHK(cc->pa == idx - 1, "%s: twin not the previous case", nm);
		if (cc->pa == idx - 1)
			CHK(cov < pair_cov,
				"%s: evenodd coverage %d not less than "
				"nonzero %d", nm, cov, pair_cov);
		break;

	case FAM_SYMX:
		CHK(bm_mirror_sym(bm), "%s: not mirror symmetric", nm);
		break;

	case FAM_SYMXSY:
		CHK(bm_mirror_sym(bm) && bm_vflip_sym(bm),
				"%s: not symmetric", nm);
		break;

	default:
		break;
	}
}

/* ------------------------------------------------------------------ */
/* dump support                                                         */
/* ------------------------------------------------------------------ */

static void
dump_case(int idx, const bm_t *bm)
{
	char path[384];
	uint8_t buf[4096];
	int n, fd, y, x, o;

	if (!dumpdir)
		return;

	lws_snprintf(path, sizeof(path), "%s/%03d-%s.svg", dumpdir, idx,
							corpus[idx].name);
	fd = lws_open(path, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);
	if (fd < 0)
		return;
	(void)write(fd, corpus[idx].doc, strlen(corpus[idx].doc));
	close(fd);

	/* portable bitmap P1 */

	n = lws_snprintf(path, sizeof(path), "%s/%03d-%s.pbm", dumpdir, idx,
							corpus[idx].name);
	fd = lws_open(path, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);
	if (fd < 0)
		return;

	n = lws_snprintf((char *)buf, sizeof(buf), "P1\n%d %d\n",
							bm->w, bm->h);
	(void)write(fd, buf, (size_t)n);

	for (y = 0; y < bm->h; y++) {
		o = 0;
		for (x = 0; x < bm->w; x++) {
			buf[o++] = bm->cov[x + y * bm->w] ? '1' : '0';
			if (o >= (int)sizeof(buf) - 4) {
				(void)write(fd, buf, (size_t)o);
				o = 0;
			}
		}
		buf[o++] = '\n';
		(void)write(fd, buf, (size_t)o);
	}
	close(fd);
}

/* ------------------------------------------------------------------ */
/* eyeball mode: render one svg file to a .bmp, like api-test-lhp-dlo   */
/* ------------------------------------------------------------------ */

static void
write_bmp_header(int fd, int w, int h)
{
	uint8_t head[54];
	int filesize = 54 + ((((w * 3) + 3) & ~3)) * h;

	memset(head, 0, sizeof(head));

	head[0] = 'B';
	head[1] = 'M';
	head[2] = (uint8_t)(filesize & 0xff);
	head[3] = (uint8_t)((filesize >> 8) & 0xff);
	head[4] = (uint8_t)((filesize >> 16) & 0xff);
	head[5] = (uint8_t)((filesize >> 24) & 0xff);
	head[10] = 54;

	head[14] = 40;
	head[18] = (uint8_t)(w & 0xff);
	head[19] = (uint8_t)((w >> 8) & 0xff);
	head[20] = (uint8_t)((w >> 16) & 0xff);
	head[21] = (uint8_t)((w >> 24) & 0xff);

	h = -h; /* top-down */
	head[22] = (uint8_t)(h & 0xff);
	head[23] = (uint8_t)((h >> 8) & 0xff);
	head[24] = (uint8_t)((h >> 16) & 0xff);
	head[25] = (uint8_t)((h >> 24) & 0xff);

	head[26] = 1;
	head[28] = 24;

	if (write(fd, head, 54) < 54)
		lwsl_err("%s: write failed\n", __func__);
}

typedef struct {
	uint8_t		*row;	/* w * 3, RGB */
	long		cov;
} eyeball_t;

static int
eyeball_span_cb(void *user, int x0, int x1, uint32_t rgba)
{
	eyeball_t *e = (eyeball_t *)user;
	uint8_t a = (uint8_t)LWS_SVG_ALPHA(rgba);
	uint8_t ia = (uint8_t)(255 - a);
	uint8_t r = (uint8_t)(rgba & 0xff),
		g = (uint8_t)((rgba >> 8) & 0xff),
		b = (uint8_t)((rgba >> 16) & 0xff);

	e->cov += x1 - x0;

	while (x0 < x1) {
		uint8_t *p = &e->row[(size_t)x0 * 3];

		p[0] = (uint8_t)((r * a + p[0] * ia) / 255);
		p[1] = (uint8_t)((g * a + p[1] * ia) / 255);
		p[2] = (uint8_t)((b * a + p[2] * ia) / 255);
		x0++;
	}

	return 0;
}

static int
eyeball(const char *inpath, const char *outpath, int scale, uint32_t bg)
{
	uint8_t bgr[3] = { (uint8_t)(bg & 0xff), (uint8_t)((bg >> 8) & 0xff),
			   (uint8_t)((bg >> 16) & 0xff) };
	uint8_t *doc, *row, pad[3] = { 0, 0, 0 };
	size_t len = 0;
	lws_stateful_ret_t r;
	lws_svg_render_t ri;
	const uint8_t *b;
	lws_svg_t *svg;
	ssize_t n;
	int fd, outfd, w, h, y, padlen, ret = 1;
	long cov = 0;

	fd = lws_open(inpath, LWS_O_RDONLY, 0);
	if (fd < 0) {
		lwsl_user("%s: unable to open %s\n", __func__, inpath);
		return 1;
	}

	doc = malloc(EYEBALL_MAXDOC);
	if (!doc)
		goto bail1;

	while (len < EYEBALL_MAXDOC) {
		n = read(fd, doc + len, EYEBALL_MAXDOC - len);
		if (n < 0) {
			lwsl_user("%s: read failed\n", __func__);
			goto bail2;
		}
		if (!n)
			break;
		len += (size_t)n;
	}
	if (len == EYEBALL_MAXDOC) {
		lwsl_user("%s: %s too large\n", __func__, inpath);
		goto bail2;
	}
	close(fd);
	fd = -1;

	svg = lws_svg_new();
	if (!svg)
		goto bail2;

	b = doc;
	{
		size_t l = len;

		r = lws_svg_parse(svg, &b, &l, 0);
	}
	if (r & LWS_SRET_FATAL) {
		lwsl_user("%s: parse FATAL\n", __func__);
		goto bail3;
	}

	w = (int)(lws_svg_get_width(svg) * (unsigned int)scale);
	h = (int)(lws_svg_get_height(svg) * (unsigned int)scale);

	lwsl_user("%s: %zu bytes, ret 0x%x, complete %d, "
		  "intrinsic %ux%u -> render %dx%d\n", __func__, len,
		  (unsigned int)r, lws_svg_get_doc_complete(svg),
		  lws_svg_get_width(svg), lws_svg_get_height(svg), w, h);

	if (!lws_svg_get_width(svg)) {
		lwsl_user("%s: no root <svg> tag parsed\n", __func__);
		goto bail3;
	}
	if (w <= 0 || h <= 0 || w > EYEBALL_MAXDIM || h > EYEBALL_MAXDIM) {
		lwsl_user("%s: output size %dx%d out of range\n", __func__, w, h);
		goto bail3;
	}

	outfd = lws_open(outpath, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC,
									0644);
	if (outfd < 0) {
		lwsl_user("%s: unable to open %s\n", __func__, outpath);
		goto bail3;
	}

	write_bmp_header(outfd, w, h);

	row = malloc((size_t)w * 3);
	if (!row)
		goto bail4;

	padlen = (4 - ((w * 3) & 3)) & 3;

	ri.w = w;
	ri.h = h;

	for (y = 0; y < h; y++) {
		eyeball_t e;
		size_t k;

		for (k = 0; k < (size_t)w; k++) {
			row[k * 3] = bgr[0];
			row[k * 3 + 1] = bgr[1];
			row[k * 3 + 2] = bgr[2];
		}

		e.row = row;
		e.cov = 0;
		if (lws_svg_render_line(svg, &ri, y, eyeball_span_cb, &e) &
							LWS_SRET_FATAL) {
			lwsl_user("%s: render FATAL at line %d\n", __func__, y);
			goto bail5;
		}
		cov += e.cov;

		/* swap RGB -> BGR */

		for (k = 0; k < (size_t)w * 3; k += 3) {
			uint8_t t = row[k];

			row[k] = row[k + 2];
			row[k + 2] = t;
		}

		if (write(outfd, row, (size_t)w * 3) < (ssize_t)((size_t)w * 3) ||
		    (padlen && write(outfd, pad, (size_t)padlen) < padlen)) {
			lwsl_user("%s: write failed\n", __func__);
			goto bail5;
		}
	}

	lwsl_user("%s: %s: %dx%d, %ld / %ld pixels covered\n", __func__,
		  outpath, w, h, cov, (long)w * h);

	ret = 0;

bail5:
	free(row);
bail4:
	close(outfd);
bail3:
	lws_svg_free(&svg);
bail2:
	free(doc);
bail1:
	if (fd >= 0)
		close(fd);

	return ret;
}

/* ------------------------------------------------------------------ */
/* robustness                                                           */
/* ------------------------------------------------------------------ */

static void
robustness(void)
{
	static const char tri[] =
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\">"
		"<path d=\"M 8 8 L 56 12 L 40 56 Z\"/></svg>";
	lws_svg_t *svg;
	const uint8_t *b;
	size_t l;
	bm_t bm;
	int i, cut;

	CHK(!bm_alloc(&bm, 64, 64), "robustness bm OOM");

	/* truncation at every offset: no crashes, defined returns */

	for (cut = 0; cut <= (int)sizeof(tri) - 1; cut++) {
		lws_stateful_ret_t r;

		svg = lws_svg_new();
		CHK(svg, "OOM");
		if (!svg)
			return;
		b = (const uint8_t *)tri;
		l = (size_t)cut;
		r = lws_svg_parse(svg, &b, &l, 0);
		/* any defined return is fine; the point is no crash or hang */
		(void)r;
		/* renders whatever prefix parsed without complaint */

		if (!(r & LWS_SRET_FATAL)) {
			lws_svg_render_t ri = { .w = 64, .h = 64 };
			int y;

			for (y = 0; y < 64; y++)
				if (lws_svg_render_line(svg, &ri, y,
						span_cb, &bm) & LWS_SRET_FATAL)
					break;
		}
		lws_svg_free(&svg);
	}
	checks++;	/* the truncation sweep as a whole is one check */

	/* deterministic single-byte mutations: must never crash or hang */

	{
		uint32_t seed = 0x12345678;
		char mutant[sizeof(tri)];

		for (i = 0; i < 400; i++) {
			lws_stateful_ret_t r;
			int y;
			lws_svg_render_t ri = { .w = 64, .h = 64 };

			memcpy(mutant, tri, sizeof(tri));
			seed = seed * 1103515245 + 12345;
			mutant[seed % (sizeof(tri) - 1)] =
					(char)(seed >> 16);

			svg = lws_svg_new();
			if (!svg)
				return;
			b = (const uint8_t *)mutant;
			l = sizeof(tri) - 1;
			r = lws_svg_parse(svg, &b, &l, 0);
			if (!(r & LWS_SRET_FATAL))
				for (y = 0; y < 64; y++)
					if (lws_svg_render_line(svg, &ri, y,
							span_cb, &bm) &
							LWS_SRET_FATAL)
						break;
			lws_svg_free(&svg);
		}
		checks++;
	}

	/* over-deep nesting is a bounded, fatal condition */

	{
		char doc[2048];
		int o = lws_snprintf(doc, sizeof(doc),
				"<svg xmlns=\"http://www.w3.org/2000/svg\">");

		for (i = 0; i < 30; i++)
			o += lws_snprintf(doc + o, sizeof(doc) - (size_t)o,
					"<g>");
		lws_snprintf(doc + o, sizeof(doc) - (size_t)o,
				"<rect x=\"1\" y=\"1\" width=\"9\" height=\"9\"/>");

		svg = lws_svg_new();
		b = (const uint8_t *)doc;
		l = strlen(doc);
		CHK(lws_svg_parse(svg, &b, &l, 0) & LWS_SRET_FATAL,
				"deep nesting not fatal");
		lws_svg_free(&svg);
	}

	/* nesting just within the cap renders */

	{
		char doc[2048];
		int o = lws_snprintf(doc, sizeof(doc),
				"<svg xmlns=\"http://www.w3.org/2000/svg\" "
				"width=\"64\" height=\"64\">");

		for (i = 0; i < 20; i++)
			o += lws_snprintf(doc + o, sizeof(doc) - (size_t)o,
					"<g>");
		o += lws_snprintf(doc + o, sizeof(doc) - (size_t)o,
				"<rect x=\"2\" y=\"2\" width=\"10\" height=\"10\"/>");
		for (i = 0; i < 20; i++)
			o += lws_snprintf(doc + o, sizeof(doc) - (size_t)o,
					"</g>");
		lws_snprintf(doc + o, sizeof(doc) - (size_t)o, "</svg>");

		svg = lws_svg_new();
		b = (const uint8_t *)doc;
		l = strlen(doc);
		CHK(lws_svg_parse(svg, &b, &l, 0) == LWS_SRET_OK,
				"20-deep nesting parse");
		{
			lws_svg_render_t ri = { .w = 64, .h = 64 };
			int y;

			bm_clear(&bm);
			for (y = 0; y < 64; y++) {
				bm.y = y;
				lws_svg_render_line(svg, &ri, y, span_cb, &bm);
			}
			CHK(bm_count(&bm) == 100, "20-deep nesting coverage %d",
					bm_count(&bm));
		}
		lws_svg_free(&svg);
	}

	/* shape-count cap is fatal */

	{
		static char doc[96 * 1024];
		int o;

		o = lws_snprintf(doc, sizeof(doc),
				"<svg xmlns=\"http://www.w3.org/2000/svg\" "
				"width=\"8\" height=\"8\">");
		for (i = 0; i < 2100; i++)
			o += lws_snprintf(doc + (size_t)o,
					sizeof(doc) - (size_t)o,
					"<rect x=\"0\" y=\"0\" width=\"1\" "
					"height=\"1\"/>");

		svg = lws_svg_new();
		b = (const uint8_t *)doc;
		l = (size_t)o;
		CHK(lws_svg_parse(svg, &b, &l, 0) & LWS_SRET_FATAL,
				"shape cap not fatal");
		lws_svg_free(&svg);
	}

	/* assorted broken and empty inputs */

	{
		static const char *bad[] = {
			"",
			"<svg/>",
			"<svg></svg>",
			"<html><body></body></html>",
			"<svg><path d=\"M nan inf L 1e999 -1e999\"/></svg>",
			"<svg><path d=\"M -1e9 -1e9 L 1e9 1e9 Z\"/></svg>",
			"<svg width=\"0\" height=\"0\"></svg>",
			"<svg <<<< >>>> <>>> ><>",
			"<svg a='1\" b=\"2' c=&#; d=>",
			"<svg><![CDATA[ unclosed",
			"<svg><!-- unclosed",
			"<svg><?pi unclosed",
			"<svg>&",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" "
				"viewBox=\"junk junk junk junk\">"
				"<rect x=\"1\" y=\"1\" width=\"5\" height=\"5\"/>"
				"</svg>",
		};
		unsigned int n;

		for (n = 0; n < LWS_ARRAY_SIZE(bad); n++) {
			lws_stateful_ret_t r;
			lws_svg_render_t ri = { .w = 16, .h = 16 };
			int y;

			svg = lws_svg_new();
			if (!svg)
				return;
			b = (const uint8_t *)bad[n];
			l = strlen(bad[n]);
			r = lws_svg_parse(svg, &b, &l, 0);
			CHK(r == LWS_SRET_OK || r == LWS_SRET_WANT_INPUT ||
			    (r & LWS_SRET_FATAL),
			    "bad input %u weird return %d", n, r);
			(void)r;
			if (!(r & LWS_SRET_FATAL))
				for (y = 0; y < 16; y++)
					lws_svg_render_line(svg, &ri, y,
							span_cb, &bm);
			lws_svg_free(&svg);
		}
		checks++;
	}

	bm_free(&bm);
}

/* ------------------------------------------------------------------ */

int
main(int argc, const char **argv)
{
	static bm_t bm, chunk_bm;
	int i, result = 0;
	const char *p, *p2;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}
	lws_set_log_level(LLL_USER, NULL);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		lws_set_log_level((int)atoi(p), NULL);

	/*
	 * Eyeball mode: render a single svg file to a .bmp like
	 * api-test-lhp-dlo, instead of running the corpus
	 */

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SVG].sw))) {
		const char *out = lws_cmdline_option(argc, argv,
						switches[LWS_SW_OUT].sw);
		const char *bgs = lws_cmdline_option(argc, argv,
						switches[LWS_SW_BG].sw);
		char tmp[300];
		int scale = 1;
		uint32_t bg = 0xffffff;
		int i;

		if ((p2 = lws_cmdline_option(argc, argv,
						switches[LWS_SW_SCALE].sw))) {
			scale = atoi(p2);
			if (scale < 1)
				scale = 1;
		}

		if (bgs && strlen(bgs) == 6) {
			bg = 0;
			for (i = 0; i < 6; i++) {
				int h = hexdigit(bgs[i]);

				if (h < 0)
					break;
				bg = (bg << 4) | (uint32_t)h;
			}
			if (i != 6)
				bg = 0xffffff;
		}

		if (!out) {
			lws_snprintf(tmp, sizeof(tmp), "%s.bmp", p);
			out = tmp;
		}

		return eyeball(p, out, scale, bg);
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_DUMP].sw)))
		dumpdir = p;

	lwsl_user("LWS SVG corpus test tool\n");

build_corpus();
lwsl_user("corpus: %d documents\n", ncases);

memset(&bm, 0, sizeof(bm));
memset(&chunk_bm, 0, sizeof(chunk_bm));
memset(&pair_bm, 0, sizeof(pair_bm));

	for (i = 0; i < ncases; i++) {
		cc_t *cc = &corpus[i];

		/* case-specific render size */

		free(bm.cov);
		if (bm_alloc(&bm, cc->w, cc->h)) {
			CHK(0, "%s: bm OOM", cc->name);
			break;
		}
		free(chunk_bm.cov);
		if (bm_alloc(&chunk_bm, cc->w, cc->h)) {
			CHK(0, "%s: bm OOM", cc->name);
			break;
		}

		CHK(render_doc(cc->doc, strlen(cc->doc), &bm, 0) ==
							LWS_SRET_OK,
			"%s: one-shot render fatal", cc->name);

		/*
		 * Streaming the same doc in arbitrary chunks must produce
		 * the byte-identical scene
		 */

		CHK(render_doc(cc->doc, strlen(cc->doc), &chunk_bm, 1) ==
							LWS_SRET_OK,
			"%s: 1-byte-chunk render fatal", cc->name);
		CHK(bm_equal(&bm, &chunk_bm),
				"%s: 1-byte chunks differ from one-shot",
				cc->name);

		CHK(render_doc(cc->doc, strlen(cc->doc), &chunk_bm, 5) ==
							LWS_SRET_OK,
			"%s: 5-byte-chunk render fatal", cc->name);
		CHK(bm_equal(&bm, &chunk_bm),
				"%s: 5-byte chunks differ from one-shot",
				cc->name);

		CHK(render_doc(cc->doc, strlen(cc->doc), &chunk_bm, -1) ==
							LWS_SRET_OK,
			"%s: varying-chunk render fatal", cc->name);
		CHK(bm_equal(&bm, &chunk_bm),
				"%s: varying chunks differ from one-shot",
				cc->name);

		check_case(i, &bm);
		dump_case(i, &bm);

		/* keep this case's bitmap for pair families */

		if (pair_bm.w != bm.w || pair_bm.h != bm.h) {
			free(pair_bm.cov);
			if (bm_alloc(&pair_bm, bm.w, bm.h)) {
				CHK(0, "%s: pair bm OOM", cc->name);
				break;
			}
		} else
			bm_clear(&pair_bm);
		memcpy(pair_bm.cov, bm.cov, (size_t)bm.w * (size_t)bm.h);
		pair_cov = bm_count(&bm);
	}

	robustness();

	bm_free(&bm);
	bm_free(&chunk_bm);
	bm_free(&pair_bm);

	lwsl_user("Completed: %s (%d checks, %d failures)\n",
		  fails ? "FAIL" : "PASS", checks, fails);
	result = fails ? 1 : 0;

	return result;
}
