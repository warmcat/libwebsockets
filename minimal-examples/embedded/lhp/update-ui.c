/*
 * lhp firmware update progress page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See update-ui.h.  The page is sized the same way as the strip ui's pages,
 * so it looks like the boot overlay it follows: its title strip is the same
 * height, with its line of text in the same place, in the same colours.
 */

#include "update-ui.h"

#include <string.h>
#include <stdarg.h>

typedef struct {
	char			*p;
	char			*end;
	char			full;
} uw_t;

static void
uw_printf(uw_t *w, const char *fmt, ...) LWS_FORMAT(2);

static void
uw_printf(uw_t *w, const char *fmt, ...)
{
	size_t room = lws_ptr_diff_size_t(w->end, w->p);
	va_list ap;
	int n;

	if (w->full)
		return;

	va_start(ap, fmt);
	n = vsnprintf(w->p, room, fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= room) {
		w->full = 1;
		return;
	}

	w->p += n;
}

/* the columns that can be seen across lines y0 to y1 */

static void
span(const lws_surface_info_t *ic, int y0, int y1, int *x0, int *x1)
{
	if (y0 < 0)
		y0 = 0;
	if (y1 > ic->wh_px[1].whole)
		y1 = ic->wh_px[1].whole;

	if (lws_surface_visible_span(ic, y0, y1, x0, x1))
		*x0 = *x1 = 0;
}

/* a box of text across the columns that can be seen on its line */

static void
text_box(uw_t *w, const lws_surface_info_t *ic, const char *id, int y,
	 int lh, int fs)
{
	int x0, x1;

	span(ic, y, y + lh, &x0, &x1);
	uw_printf(w, "#%s { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		     " font-size: %dpx }", id, x0, y, x1 - x0, lh, fs);
}

/*
 * The biggest the icon can be drawn, up to its own size, centred across lines
 * y0 to y1 and inside what can be seen there; 0 if it's too small to show
 */

static int
icon_fit(const lws_surface_info_t *ic, int y0, int y1, int *iy)
{
	int s = y1 - y0, x0, x1;

	if (s > LHP_UPDATE_ICON_PX)
		s = LHP_UPDATE_ICON_PX;

	for (; s >= 16; s--) {
		*iy = y0 + (y1 - y0 - s) / 2;
		span(ic, *iy, *iy + s, &x0, &x1);
		if (x1 - x0 >= s)
			return s;
	}

	return 0;
}

int
lhp_update_html(char *buf, size_t len, const lws_surface_info_t *ic,
		const char *variant, int pc)
{
	int w = ic->wh_px[0].whole, h = ic->wh_px[1].whole, th, fs, tl, pad,
	    bh, by, bx0, bx1, bw, bx, fw, gap, vl, vfs, vy, py, is = 0, iy = 0,
	    a, ay, b, by2;
	uw_t uw;

	uw.p = buf;
	uw.end = buf + len;
	uw.full = 0;

	if (pc < 0)
		pc = 0;
	if (pc > 100)
		pc = 100;

	/*
	 * The title strip and its text, as the strip ui sizes them: on a
	 * round display, the strip is taller so its line is lower down, where
	 * the circle is wider
	 */

	th = ic->round ? h / 6 : h / 8;
	if (th < 14)
		th = 14;
	if (th > 40)
		th = 40;
	pad = h / 120 ? h / 120 : 1;
	fs = ((h / 8) * 2) / 3;
	if (fs > ((th - pad) * 5) / 6)
		/* the line must fit in the strip, which stops growing */
		fs = ((th - pad) * 5) / 6;
	if (fs < 10)
		fs = 10;
	tl = (fs * 6) / 5;
	gap = h / 40 > 2 ? h / 40 : 2;

	bh = h / 12;
	if (bh < 10)
		bh = 10;
	if (bh > 28)
		bh = 28;
	vfs = (fs * 3) / 4 > 10 ? (fs * 3) / 4 : 10;
	vl = (vfs * 6) / 5;

	if (ic->round) {
		/*
		 * The bar is across the middle, where the circle is widest,
		 * what is being updated above it and the percentage below it.
		 * The icon goes where it can be biggest, between the strip and
		 * what is being updated, or below the percentage.
		 */

		by = h / 2 - bh / 2;
		vy = by - gap - vl;
		py = by + bh + gap;

		a = icon_fit(ic, th + gap, vy - gap, &ay);
		b = icon_fit(ic, py + tl + gap, h - gap, &by2);
		if (a >= b) {
			is = a;
			iy = ay;
		} else {
			is = b;
			iy = by2;
		}
	} else {
		/*
		 * The icon, what is being updated, the bar and the percentage
		 * go one under the other, in the middle of the space below the
		 * strip, the icon as big as there is room for
		 */

		a = vl + gap + bh + gap + tl;
		is = h - th - 3 * gap - a;
		if (is > LHP_UPDATE_ICON_PX)
			is = LHP_UPDATE_ICON_PX;
		if (is > w)
			is = w;
		if (is < 16)
			is = 0;

		iy = th + (h - th - a - (is ? is + gap : 0)) / 2;
		vy = iy + (is ? is + gap : 0);
		by = vy + vl + gap;
		py = by + bh + gap;
	}

	/* the bar is three quarters of the width that can be seen there */

	span(ic, by, by + bh, &bx0, &bx1);
	bw = ((bx1 - bx0) * 3) / 4;
	bx = bx0 + (bx1 - bx0 - bw) / 2;
	fw = (bw * pc) / 100;

	uw_printf(&uw, "<!doctype html><html><head><meta charset=\"utf-8\">"
		       "<style>"
		       "* { margin: 0; padding: 0 }"
		       "body { background-color: #fff; color: #000;"
		       " font-family: sans }"
		       "#t, #tt, #v, #b, #f, #p, #i { position: absolute }"
		       "#tt, #v, #p { text-align: center; white-space: nowrap;"
		       " overflow: hidden }"
		       "#t { left: 0; top: 0; width: %dpx; height: %dpx;"
		       " background-color: " LHP_UI_STRIP_BG " }"
		       "#tt { color: " LHP_UI_STRIP_FG " }"
		       "#v { color: " LHP_UI_STRIP_BG " }"
		       "#b { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		       " background-color: #ddd; border-radius: %dpx }"
		       "#f { left: 0; top: 0; width: %dpx; height: %dpx;"
		       " background-color: " LHP_UI_STRIP_BG ";"
		       " border-radius: %dpx }",
		       w, th, bx, by, bw, bh, bh / 2, fw, bh,
		       fw < bh ? fw / 2 : bh / 2);

	/* the title's line sits at the bottom of its strip */

	text_box(&uw, ic, "tt", th - tl - pad, tl, fs);
	text_box(&uw, ic, "v", vy, vl, vfs);
	text_box(&uw, ic, "p", py, tl, fs);

	if (is)
		uw_printf(&uw, "#i { left: %dpx; top: %dpx; width: %dpx;"
			       " height: %dpx }"
			       "#i img { width: 100%%; height: 100%% }",
			       (w - is) / 2, iy, is, is);

	uw_printf(&uw, "</style></head><body>"
		       "<div id=\"t\"></div><div id=\"tt\">Updating</div>"
		       "<div id=\"v\">");

	/* it's ours, but it's only ever shown as text */

	while (variant && *variant && !uw.full) {
		char c = *variant++;

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')
			uw_printf(&uw, "%c", c);
	}

	uw_printf(&uw, "</div><div id=\"b\">");
	if (fw)
		uw_printf(&uw, "<div id=\"f\"></div>");
	uw_printf(&uw, "</div><div id=\"p\">%d%%</div>", pc);

	if (is)
		uw_printf(&uw, "<div id=\"i\"><img src=\"file://dlofs/"
			       LHP_UPDATE_ICON "\"></div>");

	uw_printf(&uw, "</body></html>");

	if (uw.full)
		return -1;

	return lws_ptr_diff(uw.p, buf);
}
