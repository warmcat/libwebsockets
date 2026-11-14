/*
 * lhp edges and touch page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See edges-ui.h
 */

#include "edges-ui.h"
#include <string.h>
#include <stdlib.h>

/* the inset as it's stored in the settings: its four bytes as they are */
#define EDGES_SETTING		"lhp.inset"

/* the edges' rows, top to bottom, and which of the inset each is */

static const struct {
	const char	*name;
	char		c;	/* in its controls' hrefs */
	uint8_t		idx;	/* in the inset */
} edges[] = {
	{ "Top",	't', 1 },
	{ "Left",	'l', 0 },
	{ "Right",	'r', 2 },
	{ "Bottom",	'b', 3 },
};

static int
clamp(int v, int lo, int hi)
{
	return v < lo ? lo : (v > hi ? hi : v);
}

/* a 1px black line, along an edge of what can be seen or of the cross */

static void
line(lws_html_w_t *w, const char *id, int x, int y, int lw, int lh)
{
	lws_html_w_printf(w, "#%s { left: %dpx; top: %dpx; width: %dpx;"
			     " height: %dpx }", id, x, y, lw, lh);
}

/*
 * The sizes of things on the page.  The controls are as big as they
 * comfortably can be to press, in the middle, away from the edges.  On a round
 * display, they're smaller, to stay inside the circle
 */

typedef struct {
	int		w, h;	/* what can be seen */
	int		bs;	/* a button's size, and the targets' */
	int		fs;	/* the font's */
	int		tl;	/* a line of text's height */
	int		gap;
} sizes_t;

static void
sizes(const lws_surface_info_t *ic, sizes_t *z)
{
	z->w = ic->wh_px[0].whole;
	z->h = ic->wh_px[1].whole;
	z->bs = clamp(ic->round ? z->h / 11 : z->h / 9, 16, 56);
	z->fs = clamp((z->bs * 3) / 5, 10, 24);
	z->tl = (z->fs * 6) / 5;
	z->gap = z->bs / 4 > 2 ? z->bs / 4 : 2;
}

/*
 * Where target n is on what can be seen: near the corners, a button's size in
 * from the edges, then halfway down the sides, beside the controls.  On a
 * round display, the corners can't be seen: they're on the diagonals instead
 */

static void
target_xy(const lws_surface_info_t *ic, int n, int *x, int *y)
{
	static const int8_t where[LHP_EDGES_TARGETS][2] = {
		{ -1, -1 }, { 1, -1 }, { 1, 1 }, { -1, 1 }, { -1, 0 }, { 1, 0 }
	};
	int cx, cy, dx, dy;
	sizes_t z;

	sizes(ic, &z);
	cx = z.w / 2;
	cy = z.h / 2;
	dx = cx - z.bs;
	dy = cy - z.bs;
	if (ic->round && where[n][1]) {
		dx = (dx * 3) / 4;
		dy = (dy * 3) / 4;
	}

	*x = cx + where[n][0] * dx;
	*y = cy + where[n][1] * dy;
}

/* the lines a target is drawn with: a cross, in a square */

static const char * const target_ids[] = {
	"th", "tv", "st", "sb", "sl", "sr"
};

/* the integer square root, rounded down */

static int
isqrt(int v)
{
	int r = 0;

	while ((r + 1) * (r + 1) <= v)
		r++;

	return r;
}

/* tenths, eg, of a px, as -1.5 */

static void
tenths(lws_html_w_t *w, int t)
{
	lws_html_w_printf(w, "%s%d.%d", t < 0 ? "-" : "+", abs(t) / 10,
			  abs(t) % 10);
}

void
lhp_edges_reset(lhp_edges_t *e)
{
	memset(e, 0, sizeof(*e));
}

void
lhp_edges_touch(lhp_edges_t *e, const lws_surface_info_t *ic, int sx, int sy,
		int vx, int vy, int inside)
{
	int tx, ty;

	e->sx = sx;
	e->sy = sy;
	e->vx = vx;
	e->vy = vy;
	e->touched = 1;
	e->inside = (uint8_t)!!inside;
	e->off = 0;

	if (!inside) {
		lwsl_notice("%s: %d, %d on the surface, in the inset\n",
			    __func__, sx, sy);
		return;
	}

	/* it's measured against the target being shown */

	if (e->measured == LHP_EDGES_TARGETS)
		/* the last round was shown: this starts another */
		e->measured = 0;

	target_xy(ic, e->target, &tx, &ty);
	e->dx[e->target] = vx - tx;
	e->dy[e->target] = vy - ty;
	e->off = 1;

	lwsl_notice("%s: %d, %d (surface %d, %d): target %d at %d, %d, "
		    "off %d, %d\n", __func__, vx, vy, sx, sy, e->target + 1,
		    tx, ty, e->dx[e->target], e->dy[e->target]);

	e->measured++;
	e->target = (uint8_t)((e->target + 1) % LHP_EDGES_TARGETS);
}

int
lhp_edges_html(char *buf, size_t len, const lws_surface_info_t *ic,
	       const uint8_t inset[4], const lhp_edges_t *e)
{
	int lw, rw, x0, y0, pad, m, n, tx, ty, sdx = 0, sdy = 0, worst = 0, d;
	lws_html_w_t hw;
	sizes_t z;

	sizes(ic, &z);
	pad = (z.bs - z.tl) / 2 > 0 ? (z.bs - z.tl) / 2 : 0;
	/* the edge's name, then -, how many px, + */
	lw = z.fs * 4;
	rw = lw + 3 * z.bs + 2 * z.gap;
	x0 = (z.w - rw) / 2 > 2 ? (z.w - rw) / 2 : 2;
	/* the edges' rows, the buttons' row, and three lines of text */
	y0 = (z.h - (5 * z.bs + 5 * z.gap + 3 * z.tl)) / 2;
	if (y0 < 2)
		y0 = 2;

	lws_html_w_init(&hw, buf, len);

	lws_html_w_printf(&hw, "<!doctype html><html><head>"
		"<meta charset=\"utf-8\"><style>"
		"* { margin: 0; padding: 0 }"
		"body { background-color: #fff; color: #000; font-family: sans;"
		" font-size: %dpx }"
		".k, .r, .n, .v, .x, a { position: absolute }"
		".k { background-color: #000 }"
		".r { left: %dpx; width: %dpx; height: %dpx }"
		".n { left: 0; top: %dpx; width: %dpx; height: %dpx }"
		".v, .x { text-align: center; white-space: nowrap;"
		" overflow: hidden }"
		".v { left: %dpx; top: %dpx; width: %dpx; height: %dpx }"
		"a { display: block; background-color: #000; color: #fff;"
		" text-decoration: none; text-align: center; top: 0;"
		" width: %dpx; height: %dpx; padding-top: %dpx }"
		".m { left: %dpx } .p { left: %dpx }"
		".x { left: 0; width: %dpx; height: %dpx }",
		z.fs, x0, rw, z.bs,
		pad, lw, z.tl,
		lw + z.bs + z.gap, pad, z.bs, z.tl,
		z.bs, z.bs - pad, pad,
		lw + z.gap, lw + 2 * (z.bs + z.gap),
		z.w, z.tl);

	/* the line around the edges of what can be seen */

	line(&hw, "et", 0, 0, z.w, 1);
	line(&hw, "eb", 0, z.h - 1, z.w, 1);
	line(&hw, "el", 0, 0, 1, z.h);
	line(&hw, "er", z.w - 1, 0, 1, z.h);

	/* the rows, the buttons, and the lines of text below them */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(edges) + 1; n++)
		lws_html_w_printf(&hw, "#r%d { top: %dpx }", n,
				  y0 + n * (z.bs + z.gap));
	n = y0 + 5 * (z.bs + z.gap);
	lws_html_w_printf(&hw, "#ar { left: 0; width: %dpx }"
			       "#ad { left: %dpx; width: %dpx }"
			       "#x0 { top: %dpx } #x1 { top: %dpx }"
			       "#x2 { top: %dpx }",
			       (rw - z.gap) / 2, (rw + z.gap) / 2,
			       (rw - z.gap) / 2, n, n + z.tl, n + 2 * z.tl);

	/*
	 * The target to touch next: a cross in a square, the square a button's
	 * size, so it's clear what to aim at
	 */

	target_xy(ic, e->target, &tx, &ty);
	m = z.bs / 2;
	line(&hw, "th", tx - m, ty, 2 * m + 1, 1);
	line(&hw, "tv", tx, ty - m, 1, 2 * m + 1);
	line(&hw, "st", tx - m, ty - m, 2 * m + 1, 1);
	line(&hw, "sb", tx - m, ty + m, 2 * m + 1, 1);
	line(&hw, "sl", tx - m, ty - m, 1, 2 * m + 1);
	line(&hw, "sr", tx + m, ty - m, 1, 2 * m + 1);

	/* where the last touch landed, a dot, if it was on what can be seen */

	if (e->touched && e->inside)
		line(&hw, "d", clamp(e->vx - 2, 0, z.w - 5),
		     clamp(e->vy - 2, 0, z.h - 5), 5, 5);

	lws_html_w_printf(&hw, "</style></head><body>"
		"<div class=\"k\" id=\"et\"></div>"
		"<div class=\"k\" id=\"eb\"></div>"
		"<div class=\"k\" id=\"el\"></div>"
		"<div class=\"k\" id=\"er\"></div>");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(edges); n++)
		lws_html_w_printf(&hw, "<div class=\"r\" id=\"r%d\">"
			"<div class=\"n\">%s</div>"
			"<a class=\"m\" href=\"?%c-\">-</a>"
			"<div class=\"v\">%d</div>"
			"<a class=\"p\" href=\"?%c+\">+</a></div>",
			n, edges[n].name, edges[n].c, inset[edges[n].idx],
			edges[n].c);

	lws_html_w_printf(&hw, "<div class=\"r\" id=\"r4\">"
		"<a id=\"ar\" href=\"?reset\">Reset</a>"
		"<a id=\"ad\" href=\"?done\">Done</a></div>"
		"<div class=\"x\" id=\"x0\">Seen: %d x %d</div>"
		"<div class=\"x\" id=\"x1\">", z.w, z.h);

	if (!e->touched)
		lws_html_w_printf(&hw, "Touch the middle of the target");
	else if (e->inside)
		lws_html_w_printf(&hw, "Touch: %d, %d (surface %d, %d)",
				  e->vx, e->vy, e->sx, e->sy);
	else
		lws_html_w_printf(&hw, "Touch: in the inset (surface %d, %d)",
				  e->sx, e->sy);

	lws_html_w_printf(&hw, "</div><div class=\"x\" id=\"x2\">");

	if (e->measured == LHP_EDGES_TARGETS) {
		/* all the targets were touched: how far off they were */
		for (n = 0; n < LHP_EDGES_TARGETS; n++) {
			sdx += e->dx[n];
			sdy += e->dy[n];
			d = isqrt(e->dx[n] * e->dx[n] + e->dy[n] * e->dy[n]);
			if (d > worst)
				worst = d;
		}
		lws_html_w_printf(&hw, "Mean off ");
		tenths(&hw, (sdx * 10) / LHP_EDGES_TARGETS);
		lws_html_w_printf(&hw, ", ");
		tenths(&hw, (sdy * 10) / LHP_EDGES_TARGETS);
		lws_html_w_printf(&hw, ", worst %d px", worst);
	} else if (e->off) {
		n = (e->target + LHP_EDGES_TARGETS - 1) % LHP_EDGES_TARGETS;
		lws_html_w_printf(&hw, "Target %d of %d off %d, %d",
				  e->measured, LHP_EDGES_TARGETS, e->dx[n],
				  e->dy[n]);
	} else
		lws_html_w_printf(&hw, "Target %d of %d", e->measured + 1,
				  LHP_EDGES_TARGETS);

	lws_html_w_printf(&hw, "</div>");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(target_ids); n++)
		lws_html_w_printf(&hw, "<div class=\"k\" id=\"%s\"></div>",
				  target_ids[n]);
	if (e->touched && e->inside)
		lws_html_w_printf(&hw, "<div class=\"k\" id=\"d\"></div>");

	lws_html_w_printf(&hw, "</body></html>");

	return lws_html_w_len(&hw, buf);
}

lhp_edges_act_t
lhp_edges_href(const char *href, uint8_t inset[4])
{
	size_t n;

	if (!strcmp(href, "?reset"))
		return LHP_EDGES_ACT_RESET;
	if (!strcmp(href, "?done"))
		return LHP_EDGES_ACT_DONE;

	/* the edges' controls are ?<edge><- or +> */

	if (href[0] != '?' || !href[1] || (href[2] != '-' && href[2] != '+') ||
	    href[3])
		return LHP_EDGES_ACT_NONE;

	for (n = 0; n < LWS_ARRAY_SIZE(edges); n++) {
		uint8_t *v = &inset[edges[n].idx];

		if (href[1] != edges[n].c)
			continue;

		if (href[2] == '-') {
			if (!*v)
				return LHP_EDGES_ACT_NONE;
			(*v)--;
		} else {
			if (*v >= LHP_EDGES_MAX)
				return LHP_EDGES_ACT_NONE;
			(*v)++;
		}

		return LHP_EDGES_ACT_CHANGED;
	}

	return LHP_EDGES_ACT_NONE;
}

static lws_settings_instance_t *
settings(struct lws_context *cx)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(cx);

	return nds ? nds->si : NULL;
}

int
lhp_edges_load(struct lws_context *cx, uint8_t inset[4])
{
	lws_settings_instance_t *si = settings(cx);
	uint8_t s[4];
	size_t l = sizeof(s);
	int n;

	if (!si || si->so->get(si, EDGES_SETTING, s, &l) || l != sizeof(s))
		return 1;

	/* what is stored is untrusted until we see it is an inset we'd store */
	for (n = 0; n < 4; n++)
		if (s[n] > LHP_EDGES_MAX)
			return 1;

	memcpy(inset, s, sizeof(s));

	return 0;
}

int
lhp_edges_store(struct lws_context *cx, const uint8_t inset[4])
{
	lws_settings_instance_t *si = settings(cx);

	return !si || si->so->set(si, EDGES_SETTING, inset, 4);
}
