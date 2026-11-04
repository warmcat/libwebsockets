/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * Strip ui, see lws-dlo-ui.h
 *
 * Whatever changes, the html for the whole display is made again and laid
 * out, which for the few elements a small display can show is cheap.  The
 * display list is kept, and only the bands of lines of the strips that
 * changed are rendered from it and sent to the display, if it can take a
 * band.
 *
 * The geometry, which depends on the display, is worked out here and given
 * to the elements by id in a style block, after the theme and the caller's
 * css, so they can't move anything; everything the caller gave us is put in
 * the html as text.
 *
 * There are two pages: the list page, a title strip over a list strip, and
 * the edit page, a title strip over an edit strip over a keyboard strip.
 */

#include <private-lib-core.h>

#define LWS_DLO_UI_TITLE_MAX		32
#define UI_CSS_MAX			2048

/* the strips, as bits of what needs drawing */

enum {
	UI_STRIP_TITLE			= (1 << 0),
	UI_STRIP_LIST			= (1 << 1),
	UI_STRIP_EDIT			= (1 << 2),
	UI_STRIP_KEYS			= (1 << 3),
};

/* the strips each page has */

#define UI_PAGE_LIST			(UI_STRIP_TITLE | UI_STRIP_LIST)
#define UI_PAGE_EDIT			(UI_STRIP_TITLE | UI_STRIP_EDIT | \
					 UI_STRIP_KEYS)

/*
 * The keyboard.  Keys are placed in halves of the key pitch, 20 to a row;
 * the upper case layer is the lower case one, shifted
 */

enum {
	K_CHR,		/* types its cap */
	K_SHIFT,	/* the next letter is upper case */
	K_LAYER,	/* letters <-> symbols */
	K_DEL,
	K_SPACE,
	K_SHOW,		/* show what was typed, if it's masked */
	K_DONE,
};

enum {
	UI_LAYER_LOWER,
	UI_LAYER_UPPER,
	UI_LAYER_SYMBOLS,
};

typedef struct {
	const char		*cap;
	uint8_t			act;
	uint8_t			w;	/* in half keys */
} ui_key_t;

typedef struct {
	const ui_key_t		*k;
	uint8_t			count;
	uint8_t			indent;	/* in half keys */
} ui_krow_t;

#define C(_s) { _s, K_CHR, 2 }

static const ui_key_t ka0[] = {
	C("q"), C("w"), C("e"), C("r"), C("t"), C("y"), C("u"), C("i"),
	C("o"), C("p")
}, ka1[] = {
	C("a"), C("s"), C("d"), C("f"), C("g"), C("h"), C("j"), C("k"), C("l")
}, ka2[] = {
	{ "Shift", K_SHIFT, 3 }, C("z"), C("x"), C("c"), C("v"), C("b"),
	C("n"), C("m"), { "Del", K_DEL, 3 }
}, ka3[] = {
	{ "?123", K_LAYER, 3 }, { "Show", K_SHOW, 3 }, { "Space", K_SPACE, 8 },
	C("."), { "Done", K_DONE, 4 }
}, ks0[] = {
	C("1"), C("2"), C("3"), C("4"), C("5"), C("6"), C("7"), C("8"),
	C("9"), C("0")
}, ks1[] = {
	C("!"), C("@"), C("#"), C("$"), C("%"), C("^"), C("&"), C("*"),
	C("("), C(")")
}, ks2[] = {
	C("-"), C("_"), C("="), C("+"), C("["), C("]"), C("{"), C("}"),
	C("\\"), C("|")
}, ks3[] = {
	C(";"), C(":"), C("'"), C("\""), C(","), C("."), C("/"), C("<"),
	C(">"), C("?")
}, ks4[] = {
	{ "abc", K_LAYER, 3 }, C("`"), C("~"), { "Space", K_SPACE, 6 },
	{ "Del", K_DEL, 3 }, { "Done", K_DONE, 4 }
};

#define R(_k, _i) { _k, LWS_ARRAY_SIZE(_k), _i }

static const ui_krow_t kb_alpha[] = {
	R(ka0, 0), R(ka1, 1), R(ka2, 0), R(ka3, 0)
}, kb_symbols[] = {
	R(ks0, 0), R(ks1, 0), R(ks2, 0), R(ks3, 0), R(ks4, 0)
};

#undef C
#undef R

#define UI_KEYS_MAX			56
#define UI_KB_HALVES			20

/* where a key of the current layer is, on the keyboard */

typedef struct {
	const ui_key_t		*k;
	int16_t			x, y, w;
} ui_kpos_t;

typedef enum {
	UI_IDLE,
	UI_LAYOUT,	/* the html is being laid out */
	UI_SCAN,	/* bands of the display list are being rendered */
} ui_phase_t;

/* lines rendered each time round the event loop, to stay responsive */
#define UI_SCAN_BUDGET			16

struct lws_dlo_ui {
	lws_dlo_ui_info_t		i;
	lws_display_render_state_t	rs;
	lws_sorted_usec_list_t		sul_kick;

	char				title[LWS_DLO_UI_TITLE_MAX];
	char				edit_title[LWS_DLO_UI_TITLE_MAX];
	char				page_name[32];
	char				*css;	/* the caller's, or NULL */

	char				*page;	/* the html we made, while it is
						 * registered in the dlo fs */
	size_t				page_len; /* allocated */
	uint8_t				*line;	/* a line of rendered pixels */

	/* the edit page */

	char				edit[LWS_DLO_UI_EDIT_MAX];
	ui_kpos_t			keys[UI_KEYS_MAX];
	int				nkeys;
	size_t				edit_len;
	size_t				edit_max;
	int				kx, ky;	/* the keyboard is dragged by */
	int				escroll; /* px the text is dragged by */
	unsigned int			edit_gen;

	int				w, h;	/* the display */
	int				title_h;
	int				row_h;
	int				icon;
	int				pad;
	int				fs_title;
	int				fs_row;

	int				count;	/* rows in the list */
	int				focus;	/* row to keep in the middle */
	int				top;	/* the list is scrolled down by */

	lws_display_scalar		y0, y1;	/* the band being rendered */

	uint8_t				phase;	 /* ui_phase_t */
	uint8_t				page_strips; /* UI_PAGE_* shown */
	uint8_t				drag;	 /* UI_STRIP_* a drag began in */
	uint8_t				layer;	 /* UI_LAYER_* */
	uint8_t				masked;
	uint8_t				show;	 /* show masked text */
	uint8_t				stale;	 /* the html must be made and
						  * laid out again */
	uint8_t				dirty;	 /* UI_STRIP_*: to draw */
	uint8_t				drawing; /* UI_STRIP_*: being drawn */
	uint8_t				user_scrolled;
};

/*
 * The html writer: everything is appended at p, up to end.  Once something
 * didn't fit, nothing more is written and the document is refused, rather
 * than a truncated one being shown
 */

typedef struct {
	char			*p;
	char			*end;
	char			full;
} ui_w_t;

static void
ui_printf(ui_w_t *w, const char *fmt, ...) LWS_FORMAT(2);

static void
ui_printf(ui_w_t *w, const char *fmt, ...)
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

/*
 * What the caller gave us goes in the html as text, never as markup: escape
 * what html gives meaning to, and drop control characters
 */

static void
ui_text(ui_w_t *w, const char *s, size_t max)
{
	size_t n;

	for (n = 0; n < max && s[n] && !w->full; n++) {
		unsigned char c = (unsigned char)s[n];

		switch (c) {
		case '&':
			ui_printf(w, "&amp;");
			break;
		case '<':
			ui_printf(w, "&lt;");
			break;
		case '>':
			ui_printf(w, "&gt;");
			break;
		case '"':
			ui_printf(w, "&quot;");
			break;
		case '\'':
			ui_printf(w, "&#39;");
			break;
		default:
			if (c < 0x20 || c == 0x7f)
				c = '?';
			ui_printf(w, "%c", c);
			break;
		}
	}
}

/*
 * An icon is named in an attribute: only allow names that can't break out
 * of it or name anything outside the dlo filesystem
 */

static int
ui_icon_name_ok(const char *s)
{
	size_t n;

	if (!s || !*s)
		return 0;

	for (n = 0; s[n]; n++) {
		if (n == 64)
			return 0;
		if (!((s[n] >= 'a' && s[n] <= 'z') ||
		      (s[n] >= 'A' && s[n] <= 'Z') ||
		      (s[n] >= '0' && s[n] <= '9') ||
		      s[n] == '-' || s[n] == '_' || s[n] == '.'))
			return 0;
	}

	return 1;
}

/* the most the list can be scrolled down by */

static int
ui_top_max(const struct lws_dlo_ui *ui)
{
	int m = ui->count * ui->row_h - (ui->h - ui->title_h);

	return m < 0 ? 0 : m;
}

static void
ui_clamp_top(struct lws_dlo_ui *ui)
{
	int m = ui_top_max(ui);

	if (ui->top > m)
		ui->top = m;
	if (ui->top < 0)
		ui->top = 0;
}

/* the band of lines a strip takes */

static void
ui_strip_band(const struct lws_dlo_ui *ui, int strip, int *y0, int *y1)
{
	int eb = ui->title_h + ui->row_h; /* the bottom of the edit strip */

	switch (strip) {
	case UI_STRIP_TITLE:
		*y0 = 0;
		*y1 = ui->title_h;
		break;
	case UI_STRIP_EDIT:
		*y0 = ui->title_h;
		*y1 = eb;
		break;
	case UI_STRIP_KEYS:
		*y0 = eb;
		*y1 = ui->h;
		break;
	default: /* UI_STRIP_LIST */
		*y0 = ui->title_h;
		*y1 = ui->h;
		break;
	}
}

/* which of the current page's strips line y is in */

static int
ui_strip_at(const struct lws_dlo_ui *ui, int y)
{
	int s, y0, y1;

	for (s = UI_STRIP_TITLE; s <= UI_STRIP_KEYS; s <<= 1) {
		if (!(ui->page_strips & s))
			continue;
		ui_strip_band(ui, s, &y0, &y1);
		if (y >= y0 && y < y1)
			return s;
	}

	return 0;
}

/* the columns that can be seen across lines y0 to y1, on the display */

static void
ui_span(const struct lws_dlo_ui *ui, int y0, int y1, int *x0, int *x1)
{
	if (y0 < 0)
		y0 = 0;
	if (y1 > ui->h)
		y1 = ui->h;

	if (lws_surface_visible_span(&ui->i.lds->disp->ic, y0, y1, x0, x1))
		*x0 = *x1 = 0;
}

/* place the keys of the current layer, on the keyboard */

static void
ui_keys_place(struct lws_dlo_ui *ui)
{
	const ui_krow_t *rows = ui->layer == UI_LAYER_SYMBOLS ? kb_symbols :
								 kb_alpha;
	int nr = ui->layer == UI_LAYER_SYMBOLS ? (int)LWS_ARRAY_SIZE(kb_symbols) :
						 (int)LWS_ARRAY_SIZE(kb_alpha),
	    r, n, x, extra;

	ui->nkeys = 0;

	for (r = 0; r < nr; r++) {
		x = rows[r].indent;
		extra = 0;

		for (n = 0; n < rows[r].count; n++) {
			const ui_key_t *k = &rows[r].k[n];
			ui_kpos_t *kp;

			if (k->act == K_SHOW && !ui->masked) {
				/* nothing to show: the next key has its room */
				extra = k->w;
				continue;
			}

			if (ui->nkeys == UI_KEYS_MAX)
				return;

			kp = &ui->keys[ui->nkeys++];
			kp->k = k;
			kp->x = (int16_t)((x * ui->row_h) / 2);
			kp->y = (int16_t)(r * ui->row_h);
			x += k->w + extra;
			kp->w = (int16_t)((x * ui->row_h) / 2 - kp->x);
			extra = 0;
		}
	}
}

static int
ui_kb_rows(const struct lws_dlo_ui *ui)
{
	return ui->layer == UI_LAYER_SYMBOLS ? (int)LWS_ARRAY_SIZE(kb_symbols) :
					       (int)LWS_ARRAY_SIZE(kb_alpha);
}

/*
 * The keyboard is wider than a small display, and maybe taller than its
 * strip: it can be dragged until its edges reach the columns that can be
 * seen across the middle of the strip, and up until its last row is in the
 * middle of a round one
 */

static void
ui_clamp_kb(struct lws_dlo_ui *ui)
{
	int kw = (UI_KB_HALVES * ui->row_h) / 2, kh = ui_kb_rows(ui) * ui->row_h,
	    y0, y1, x0, x1, m, sh;

	ui_strip_band(ui, UI_STRIP_KEYS, &y0, &y1);
	sh = y1 - y0;
	ui_span(ui, y0 + sh / 2 - 1, y0 + sh / 2 + 1, &x0, &x1);

	if (kw > x1 - x0) {
		if (ui->kx > x0)
			ui->kx = x0;
		if (ui->kx < x1 - kw)
			ui->kx = x1 - kw;
	} else
		ui->kx = (ui->w - kw) / 2;

	m = ui->i.lds->disp->ic.round ? sh / 2 + ui->row_h / 2 - kh :
					sh - kh;
	if (m > 0)
		m = 0;
	if (ui->ky < m)
		ui->ky = m;
	if (ui->ky > 0)
		ui->ky = 0;
}

/* the edit text is shown with a caret, centred, its tail if it is long */

static int
ui_edit_char_w(const struct lws_dlo_ui *ui)
{
	/* wider than most glyphs of the face, so what's shown fits */
	return (ui->fs_row * 2) / 3;
}

static int
ui_edit_vis(const struct lws_dlo_ui *ui)
{
	int x0, x1, y0, y1, n;

	ui_strip_band(ui, UI_STRIP_EDIT, &y0, &y1);
	ui_span(ui, y0, y1, &x0, &x1);

	/* the caret takes one */
	n = (x1 - x0 - 4 * ui->pad) / ui_edit_char_w(ui) - 1;

	return n < 1 ? 1 : n;
}

static void
ui_clamp_escroll(struct lws_dlo_ui *ui)
{
	int m = ((int)ui->edit_len - ui_edit_vis(ui)) * ui_edit_char_w(ui);

	if (m < 0)
		m = 0;
	if (ui->escroll > m)
		ui->escroll = m;
	if (ui->escroll < 0)
		ui->escroll = 0;
}

/*
 * How the strips are made to work, then the default theme, which the
 * caller's css follows, so it can override it
 */

static const char * const ui_css =
	"* { margin: 0; padding: 0 }"
	"body { background-color: #fff; color: #000; font-family: sans }"
	"#ui { position: absolute; left: 0; top: 0 }"
	"#t, #l, #e, #k { position: absolute; left: 0; overflow: hidden }"
	"#tt { position: absolute; text-align: center; white-space: nowrap;"
		" overflow: hidden }"
	".r, .k, #et { position: absolute; display: flex;"
		" justify-content: center; align-items: center;"
		" overflow: hidden }"
	".x { white-space: nowrap }"
	".d { opacity: 0.25 }"

	/* the theme */

	"#ui { background-color: #fff }"
	"#t { background-color: #24476b }"
	"#tt { color: #fff }"
	".f { background-color: #ccc; border-radius: 4px }"
	"#et { background-color: #eee; border-radius: 4px }"
	".k { background-color: #ddd; border-radius: 4px }"
	".ks { background-color: #b8bcc8 }"
	".ka { background-color: #24476b; color: #fff }";

/* the edit page's strips, after the title strip */

static void
ui_html_edit(struct lws_dlo_ui *ui, ui_w_t *w)
{
	int y0, y1, ky0, ky1, x0, x1, n, vis, end, start, kx, ky;
	char t[LWS_DLO_UI_EDIT_MAX + 2];
	const ui_kpos_t *kp;

	ui_strip_band(ui, UI_STRIP_EDIT, &y0, &y1);
	ui_strip_band(ui, UI_STRIP_KEYS, &ky0, &ky1);

	ui_printf(w, "#e { top: %dpx; width: %dpx; height: %dpx }"
		     "#k { top: %dpx; width: %dpx; height: %dpx }",
		     y0, ui->w, y1 - y0, ky0, ui->w, ky1 - ky0);

	/* the edit box, across what can be seen of its strip */

	ui_span(ui, y0, y1, &x0, &x1);
	ui_printf(w, "#et { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		     " font-size: %dpx }", x0 + ui->pad, ui->pad,
		     x1 - x0 - 2 * ui->pad, y1 - y0 - 2 * ui->pad, ui->fs_row);

	/* only the keys that can be seen in the strip are in the html */

	kx = ui->kx;
	ky = ui->ky;
	ui_printf(w, ".k { font-size: %dpx }", ui->fs_row);
	for (n = 0; n < ui->nkeys; n++) {
		kp = &ui->keys[n];
		if (kx + kp->x + kp->w <= 0 || kx + kp->x >= ui->w ||
		    ky + kp->y + ui->row_h <= 0 || ky + kp->y >= ky1 - ky0)
			continue;
		ui_printf(w, "#k%d { left: %dpx; top: %dpx; width: %dpx;"
			     " height: %dpx }", n, kx + kp->x + ui->pad,
			     ky + kp->y + ui->pad, kp->w - 2 * ui->pad,
			     ui->row_h - 2 * ui->pad);
	}

	ui_printf(w, "</style></head><body><div id=\"ui\"><div id=\"t\">"
		     "<div id=\"tt\">");
	ui_text(w, ui->edit_title, sizeof(ui->edit_title));

	/*
	 * What was typed, or as many stars, as much as fits of it, ending
	 * where it has been dragged to, and a caret if that's its end
	 */

	vis = ui_edit_vis(ui);
	end = (int)ui->edit_len - ui->escroll / ui_edit_char_w(ui);
	if (end < 0)
		end = 0;
	start = end - vis < 0 ? 0 : end - vis;
	for (n = start; n < end; n++)
		t[n - start] = ui->masked && !ui->show ? '*' : ui->edit[n];
	if (end == (int)ui->edit_len)
		t[n++ - start] = '_';
	t[n - start] = '\0';

	ui_printf(w, "</div></div><div id=\"e\"><div id=\"et\">"
		     "<div class=\"x\">");
	ui_text(w, t, sizeof(t));
	lws_explicit_bzero(t, sizeof(t));
	ui_printf(w, "</div></div></div><div id=\"k\">");

	for (n = 0; n < ui->nkeys && !w->full; n++) {
		const char *cap;
		char c[2];

		kp = &ui->keys[n];
		if (kx + kp->x + kp->w <= 0 || kx + kp->x >= ui->w ||
		    ky + kp->y + ui->row_h <= 0 || ky + kp->y >= ky1 - ky0)
			continue;

		cap = kp->k->cap;
		if (kp->k->act == K_CHR && ui->layer == UI_LAYER_UPPER) {
			c[0] = (char)toupper((unsigned char)cap[0]);
			c[1] = '\0';
			cap = c;
		}
		if (kp->k->act == K_SHOW && ui->show)
			cap = "Hide";

		ui_printf(w, "<div class=\"k%s%s\" id=\"k%d\">"
			     "<div class=\"x\">",
			  kp->k->act == K_CHR ? "" : " ks",
			  (kp->k->act == K_SHIFT &&
			   ui->layer == UI_LAYER_UPPER) ||
			  (kp->k->act == K_SHOW && ui->show) ? " ka" : "", n);
		ui_text(w, cap, 8);
		ui_printf(w, "</div></div>");
	}

	ui_printf(w, "</div></div></body></html>");
}

static int
ui_html(struct lws_dlo_ui *ui, char *buf, size_t len)
{
	int lh = ui->h - ui->title_h, tl = (ui->fs_title * 6) / 5,
	    rl = (ui->fs_row * 6) / 5, x0, x1, y0, n, first, last, ry;
	lws_dlo_ui_row_t row;
	ui_w_t w;

	w.p = buf;
	w.end = buf + len;
	w.full = 0;

	ui_printf(&w, "<!doctype html><html><head><meta charset=\"utf-8\">"
		      "<style>%s%s", ui_css, ui->css ? ui->css : "");

	ui_printf(&w, "#ui { width: %dpx; height: %dpx }"
		      "#t { top: 0; width: %dpx; height: %dpx }",
		      ui->w, ui->h, ui->w, ui->title_h);

	/* the title's line sits at the bottom of its strip */

	ui_span(ui, ui->title_h - tl - ui->pad, ui->title_h - ui->pad, &x0, &x1);
	ui_printf(&w, "#tt { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		      " font-size: %dpx }", x0, ui->title_h - tl - ui->pad,
		      x1 - x0, tl, ui->fs_title);

	if (ui->page_strips == UI_PAGE_EDIT) {
		ui_html_edit(ui, &w);
		goto done;
	}

	ui_printf(&w, "#l { top: %dpx; width: %dpx; height: %dpx }",
		      ui->title_h, ui->w, lh);

	/*
	 * Only the rows that can be seen are in the html, each positioned
	 * where it is in the strip as scrolled, and kept to the columns that
	 * can be seen across its line of text, which is in its middle
	 */

	first = ui->top / ui->row_h;
	last = (ui->top + lh + ui->row_h - 1) / ui->row_h;
	if (last > ui->count)
		last = ui->count;

	for (n = first; n < last; n++) {
		ry = n * ui->row_h - ui->top;
		y0 = ui->title_h + ry + (ui->row_h - rl) / 2;
		ui_span(ui, y0 < ui->title_h ? ui->title_h : y0, y0 + rl,
			&x0, &x1);

		ui_printf(&w, "#r%d { left: %dpx; top: %dpx; width: %dpx;"
			      " height: %dpx; font-size: %dpx }", n, x0, ry,
			      x1 - x0, ui->row_h, ui->fs_row);
	}

	ui_printf(&w, ".i { width: %dpx; height: %dpx; margin-right: %dpx }"
		      ".i img { width: 100%%; height: 100%% }</style></head>"
		      "<body><div id=\"ui\"><div id=\"t\"><div id=\"tt\">",
		      ui->icon, ui->icon, ui->pad * 2);
	ui_text(&w, ui->title, sizeof(ui->title));
	ui_printf(&w, "</div></div><div id=\"l\">");

	for (n = first; n < last && !w.full; n++) {
		memset(&row, 0, sizeof(row));
		if (ui->i.row(ui->i.opaque, n, &row))
			continue;

		ui_printf(&w, "<div class=\"r%s\" id=\"r%d\">",
			  row.state == LWS_DLO_UI_ROW_DIM ? " d" :
			  (row.state == LWS_DLO_UI_ROW_FOCUS ? " f" : ""), n);
		if (ui_icon_name_ok(row.icon))
			ui_printf(&w, "<div class=\"i\"><img src=\"%s\">"
				      "</div>", row.icon);
		ui_printf(&w, "<div class=\"x\">");
		ui_text(&w, row.text, sizeof(row.text));
		ui_printf(&w, "</div></div>");
	}

	ui_printf(&w, "</div></div></body></html>");

done:
	if (w.full)
		return -1;

	return lws_ptr_diff(w.p, buf);
}

static void
ui_page_free(struct lws_dlo_ui *ui)
{
	/* it may have held what was typed */
	lws_explicit_bzero(ui->page, ui->page_len);
	lws_free_set_NULL(ui->page);
}

static void
ui_page_drop(struct lws_dlo_ui *ui)
{
	if (!ui->page)
		return;

	lws_dlo_file_unregister_by_name(ui->i.cx, ui->page_name);
	ui_page_free(ui);
}

static void
ui_render(lws_sorted_usec_list_t *sul);

/* the html changed: make it again and lay it out, then draw what's dirty */

static int
ui_layout(struct lws_dlo_ui *ui)
{
	size_t len = 2048 + (ui->css ? strlen(ui->css) : 0) +
		     (ui->page_strips == UI_PAGE_EDIT ?
			(size_t)UI_KEYS_MAX * 192 :
			(size_t)((ui->h / ui->row_h) + 2) * 512);
	lws_dlo_filesystem_t f;
	char url[64];
	int n;

	ui_page_drop(ui);

	ui->page = lws_malloc(len, __func__);
	if (!ui->page)
		return 1;
	ui->page_len = len;

	n = ui_html(ui, ui->page, len);
	if (n < 0) {
		lwsl_err("%s: html too large\n", __func__);
		ui_page_free(ui);
		return 1;
	}

	memset(&f, 0, sizeof(f));
	f.name = ui->page_name;
	f.data = ui->page;
	f.len = (size_t)n;
	if (!lws_dlo_file_register(ui->i.cx, &f)) {
		ui_page_free(ui);
		return 1;
	}

	/* the old layout is finished with */

	lws_lhp_ss_cancel(&ui->rs);
	lws_display_list_destroy(ui->i.cx, &ui->rs.displaylist);
	lws_display_render_free_ids(&ui->rs);
	lws_display_dl_init(&ui->rs.displaylist, ui->i.lds);

	memset(ui->rs.st, 0, sizeof(ui->rs.st));
	ui->rs.sp = 0;
	ui->rs.curr = 0;
	ui->rs.ic = &ui->i.lds->disp->ic;
	ui->rs.lds = ui->i.lds;
	/* the display list is kept, to render bands of it again */
	ui->rs.retained = 1;
	/* the ui is shown before there's any network */
	ui->rs.fonts_local = 1;

	ui->stale = 0;
	ui->phase = UI_LAYOUT;
	ui->i.lds->display_busy = 1;

	lws_snprintf(url, sizeof(url), "file://dlofs/%s", ui->page_name);
	if (lws_lhp_ss_browse(ui->i.cx, &ui->rs, url, ui_render)) {
		lwsl_err("%s: browse failed\n", __func__);
		ui->phase = UI_IDLE;
		ui->i.lds->display_busy = 0;
		ui_page_drop(ui);
		return 1;
	}

	return 0;
}

/* start rendering the bands of the strips that are dirty */

static int
ui_scan_start(struct lws_dlo_ui *ui)
{
	const lws_surface_info_t *ic = &ui->i.lds->disp->ic;
	size_t lw = (size_t)ui->w * (ic->greyscale ? 1 : 3);
	int s, y0, y1, b0 = ui->h, b1 = 0;
	lws_box_t box;

	ui->drawing = ui->dirty & ui->page_strips;
	ui->dirty = 0;

	/*
	 * The strips are bands of whole lines, one above the other: the band
	 * drawn runs from the top of the first that changed to the bottom of
	 * the last.  If the display can only take whole updates, it gets
	 * everything
	 */

	for (s = UI_STRIP_TITLE; s <= UI_STRIP_KEYS; s <<= 1) {
		if (!(ui->drawing & s))
			continue;
		ui_strip_band(ui, s, &y0, &y1);
		if (y0 < b0)
			b0 = y0;
		if (y1 > b1)
			b1 = y1;
	}

	ui->y0 = 0;
	ui->y1 = (lws_display_scalar)ui->h;
	if (ic->band && b1 > b0) {
		ui->y0 = (lws_display_scalar)b0;
		ui->y1 = (lws_display_scalar)b1;
	}

	if (ui->y1 - ui->y0 < 2) {
		/* a one-line blit would be taken for line data */
		ui->y0 = 0;
		ui->y1 = (lws_display_scalar)ui->h;
	}

	if (!ui->line) {
		ui->line = lws_malloc(lw, __func__);
		if (!ui->line)
			return 1;
	}

#if defined(LWS_WITH_SECURE_STREAMS) && defined(LWS_WITH_CLIENT)
	/* image decode state only goes forwards: start them again */
	lws_dlo_ss_renew_images(ui->i.cx);
#endif

	memset(ui->rs.st, 0, sizeof(ui->rs.st));
	ui->rs.sp = 0;
	ui->rs.curr = ui->y0;
	ui->rs.line = ui->line;

	ui->phase = UI_SCAN;
	ui->i.lds->display_busy = 1;

	/* tell the display the window the lines are for */

	memset(&box, 0, sizeof(box));
	box.w.whole = (int32_t)ui->w;
	box.y.whole = ui->y0;
	box.h.whole = ui->y1 - ui->y0;
	ui->i.lds->disp->blit(ui->i.lds, (uint8_t *)&ui->rs, &box,
			      &ui->rs.ids);

	return 0;
}

static void
ui_scan_end(struct lws_dlo_ui *ui)
{
	lws_box_t box;

	ui->phase = UI_IDLE;
	ui->drawing = 0;

	/*
	 * A zero-height blit ends the update: the display's completion
	 * callback is told, and clears display_busy, maybe from in here
	 */

	memset(&box, 0, sizeof(box));
	box.w.whole = (int32_t)ui->w;
	ui->i.lds->disp->blit(ui->i.lds, ui->line, &box, &ui->rs.ids);

	ui->rs.line = NULL;
	lws_free_set_NULL(ui->line);

	if (ui->dirty || ui->stale)
		lws_dlo_ui_kick(ui);
}

static void
ui_render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	struct lws_dlo_ui *ui = lws_container_of(rs, struct lws_dlo_ui, rs);
	int budget = UI_SCAN_BUDGET;
	lws_stateful_ret_t r;
	lws_box_t box;

	switch (ui->phase) {
	case UI_LAYOUT:
		if (rs->html == 1)
			/* the layout isn't finished: it calls us again */
			return;

		if (rs->layout_failed)
			lwsl_warn("%s: layout incomplete\n", __func__);

		lws_display_get_ids_boxes(rs);

		/* the whole of what changed is drawn from the new layout */

		if (ui_scan_start(ui)) {
			lwsl_err("%s: OOM\n", __func__);
			ui->phase = UI_IDLE;
			ui->i.lds->display_busy = 0;
			return;
		}
		break;

	case UI_SCAN:
		break;

	default:
		/* eg, an image arrived after we drew it */
		return;
	}

	memset(&box, 0, sizeof(box));
	box.w.whole = (int32_t)ui->w;
	box.h.whole = 1;

	while (rs->curr < ui->y1) {
		if (!budget--) {
			lws_sul_schedule(ui->i.cx, 0, &rs->sul, ui_render, 1);
			return;
		}

		r = lws_display_list_render_line(rs);
		if (r & LWS_SRET_WANT_INPUT) {
			/* eg, an image is still arriving */
			lws_sul_schedule(ui->i.cx, 0, &rs->sul, ui_render,
					 LWS_US_PER_MS);
			return;
		}
		if (r & LWS_SRET_YIELD) {
			lws_sul_schedule(ui->i.cx, 0, &rs->sul, ui_render, 1);
			return;
		}
		if (r & LWS_SRET_FATAL) {
			lwsl_err("%s: render failed\n", __func__);
			break;
		}

		box.y.whole = rs->curr;
		ui->i.lds->disp->blit(ui->i.lds, rs->line, &box, &rs->ids);
		rs->curr++;
	}

	ui_scan_end(ui);
}

static void
ui_kick_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_dlo_ui *ui = lws_container_of(sul, struct lws_dlo_ui,
						 sul_kick);

	if (ui->phase != UI_IDLE || ui->i.lds->display_busy)
		/* we are kicked again when it's free */
		return;

	if (ui->stale) {
		if (ui_layout(ui))
			/* we keep what we had, and try again next change */
			ui->dirty = 0;
		return;
	}

	if (ui->dirty && ui_scan_start(ui)) {
		lwsl_err("%s: OOM\n", __func__);
		ui->phase = UI_IDLE;
		ui->i.lds->display_busy = 0;
		ui->dirty = 0;
		return;
	}

	if (ui->phase == UI_SCAN)
		ui_render(&ui->rs.sul);
}

void
lws_dlo_ui_kick(struct lws_dlo_ui *ui)
{
	if (ui && (ui->stale || ui->dirty))
		lws_sul_schedule(ui->i.cx, 0, &ui->sul_kick, ui_kick_cb, 1);
}

struct lws_dlo_ui *
lws_dlo_ui_create(const lws_dlo_ui_info_t *info)
{
	const lws_surface_info_t *ic = &info->lds->disp->ic;
	struct lws_dlo_ui *ui;

	size_t cl = 0;

	if (!info->row)
		return NULL;

	if (info->css) {
		/* it goes in a style element: it mustn't be able to end it */
		cl = strlen(info->css);
		if (cl > UI_CSS_MAX || strchr(info->css, '<')) {
			lwsl_err("%s: css refused\n", __func__);
			return NULL;
		}
	}

	ui = lws_zalloc(sizeof(*ui) + (cl ? cl + 1 : 0), __func__);
	if (!ui)
		return NULL;

	ui->i = *info;
	if (cl) {
		ui->css = (char *)&ui[1];
		memcpy(ui->css, info->css, cl + 1);
	}
	ui->i.css = NULL; /* it is ui->css */
	ui->w = ic->wh_px[0].whole;
	ui->h = ic->wh_px[1].whole;
	ui->focus = -1;
	ui->page_strips = UI_PAGE_LIST;

	lws_snprintf(ui->page_name, sizeof(ui->page_name), "lws-dlo-ui-%p.html",
		     (void *)ui);

	/*
	 * The sizes follow from the display's height: the title strip is an
	 * eighth of it, the list's rows tall enough for an icon a finger can
	 * press where the display is big enough for that.  At the top of a
	 * round display, little can be seen: there the title strip is taller,
	 * so its line of text is lower, where the circle is wider
	 */

	ui->title_h = ic->round ? ui->h / 6 : ui->h / 8;
	if (ui->title_h < 14)
		ui->title_h = 14;
	if (ui->title_h > 40)
		ui->title_h = 40;

	ui->icon = ui->h >= 400 ? 48 : (ui->h >= 200 ? 32 :
					(ui->h >= 100 ? 24 : 16));
	ui->pad = ui->icon / 16 ? ui->icon / 16 : 1;
	ui->row_h = ui->icon + 2 * ui->pad;

	/* the title's text is sized as for a rectangular display */
	ui->fs_title = (ui->h / 8) * 2 / 3;
	if (ui->fs_title < 10)
		ui->fs_title = 10;
	ui->fs_row = ui->icon >= 32 ? 16 : (ui->icon >= 24 ? 12 : 10);

	if (ui->w < 16 || ui->h < ui->title_h + ui->row_h * 3) {
		lwsl_err("%s: display too small\n", __func__);
		lws_free(ui);
		return NULL;
	}

	return ui;
}

void
lws_dlo_ui_destroy(struct lws_dlo_ui **pui)
{
	struct lws_dlo_ui *ui = *pui;

	if (!ui)
		return;

	lws_sul_cancel(&ui->sul_kick);

	switch (ui->phase) {
	case UI_LAYOUT:
		ui->i.lds->display_busy = 0;
		break;
	case UI_SCAN:
		/* the display has a window open: end the update */
		ui->dirty = ui->stale = 0;
		ui_scan_end(ui);
		break;
	default:
		break;
	}

	lws_lhp_ss_cancel(&ui->rs);
	lws_sul_cancel(&ui->rs.sul);
	lws_display_list_destroy(ui->i.cx, &ui->rs.displaylist);
	lws_display_render_free_ids(&ui->rs);
	lws_free_set_NULL(ui->line);
	ui_page_drop(ui);
	lws_explicit_bzero(ui->edit, sizeof(ui->edit));

	lws_free_set_NULL(*pui);
}

void
lws_dlo_ui_set_title(struct lws_dlo_ui *ui, const char *title)
{
	char t[LWS_DLO_UI_TITLE_MAX];

	lws_strncpy(t, title ? title : "", sizeof(t));
	if (!strcmp(t, ui->title))
		return;

	memcpy(ui->title, t, sizeof(t));
	if (ui->page_strips != UI_PAGE_LIST)
		/* it's shown when the list page is again */
		return;

	ui->stale = 1;
	ui->dirty |= UI_STRIP_TITLE;
	lws_dlo_ui_kick(ui);
}

void
lws_dlo_ui_set_list(struct lws_dlo_ui *ui, int count, int focus)
{
	if (count < 0)
		count = 0;
	if (focus >= count)
		focus = -1;

	ui->count = count;

	if (focus >= 0 && (focus != ui->focus || !ui->user_scrolled)) {
		/* the focus row in the middle of the list */
		ui->top = focus * ui->row_h -
			  (ui->h - ui->title_h - ui->row_h) / 2;
		ui->user_scrolled = 0;
	}
	ui->focus = focus;
	ui_clamp_top(ui);

	if (ui->page_strips != UI_PAGE_LIST)
		return;

	ui->stale = 1;
	ui->dirty |= UI_STRIP_LIST;
	lws_dlo_ui_kick(ui);
}

/* a page is shown, the whole of it changed */

static void
ui_page_show(struct lws_dlo_ui *ui, uint8_t strips)
{
	ui->page_strips = strips;
	ui->drag = 0;
	ui->stale = 1;
	ui->dirty |= strips;
	lws_dlo_ui_kick(ui);
}

static void
ui_edit_end(struct lws_dlo_ui *ui)
{
	lws_explicit_bzero(ui->edit, sizeof(ui->edit));
	ui->edit_len = 0;
	ui->edit_gen++;
	ui_page_show(ui, UI_PAGE_LIST);
}

int
lws_dlo_ui_edit(struct lws_dlo_ui *ui, const char *title, size_t max,
		unsigned int flags)
{
	if (!ui->i.done || !max || max >= sizeof(ui->edit))
		return 1;

	lws_strncpy(ui->edit_title, title ? title : "",
		    sizeof(ui->edit_title));
	lws_explicit_bzero(ui->edit, sizeof(ui->edit));
	ui->edit_len = 0;
	ui->edit_max = max;
	ui->edit_gen++;
	ui->masked = !!(flags & LWS_DLO_UI_EDIT_MASKED);
	ui->show = 0;
	ui->escroll = 0;
	ui->layer = UI_LAYER_LOWER;
	ui_keys_place(ui);

	/* the keyboard starts with its top row in the middle of the strip */
	ui->kx = (ui->w - (UI_KB_HALVES * ui->row_h) / 2) / 2;
	ui->ky = 0;
	ui_clamp_kb(ui);

	ui_page_show(ui, UI_PAGE_EDIT);

	return 0;
}

/* the edit text, or what the keys show, changed */

static void
ui_edit_changed(struct lws_dlo_ui *ui, uint8_t strips)
{
	ui->stale = 1;
	ui->dirty |= strips;
	lws_dlo_ui_kick(ui);
}

static void
ui_key(struct lws_dlo_ui *ui, const ui_key_t *k)
{
	unsigned int gen;
	char c;

	switch (k->act) {
	case K_CHR:
	case K_SPACE:
		if (ui->edit_len >= ui->edit_max)
			return;
		c = k->act == K_SPACE ? ' ' : k->cap[0];
		if (ui->layer == UI_LAYER_UPPER) {
			c = (char)toupper((unsigned char)c);
			/* a shift is for one letter */
			ui->layer = UI_LAYER_LOWER;
			ui_edit_changed(ui, UI_STRIP_KEYS);
		}
		ui->edit[ui->edit_len++] = c;
		ui->edit[ui->edit_len] = '\0';
		ui->escroll = 0;
		ui_edit_changed(ui, UI_STRIP_EDIT);
		break;

	case K_DEL:
		if (!ui->edit_len)
			return;
		ui->edit[--ui->edit_len] = '\0';
		ui->escroll = 0;
		ui_edit_changed(ui, UI_STRIP_EDIT);
		break;

	case K_SHIFT:
		ui->layer = ui->layer == UI_LAYER_UPPER ? UI_LAYER_LOWER :
							  UI_LAYER_UPPER;
		ui_edit_changed(ui, UI_STRIP_KEYS);
		break;

	case K_LAYER:
		ui->layer = ui->layer == UI_LAYER_SYMBOLS ? UI_LAYER_LOWER :
							    UI_LAYER_SYMBOLS;
		ui_keys_place(ui);
		ui_clamp_kb(ui);
		ui_edit_changed(ui, UI_STRIP_KEYS);
		break;

	case K_SHOW:
		ui->show = !ui->show;
		ui_edit_changed(ui, UI_STRIP_EDIT | UI_STRIP_KEYS);
		break;

	case K_DONE:
		/*
		 * The caller may keep us editing, eg, if what was typed isn't
		 * acceptable, or start editing something else
		 */
		gen = ui->edit_gen;
		if (ui->i.done(ui->i.opaque, ui->edit) ||
		    ui->edit_gen != gen)
			return;
		ui_edit_end(ui);
		break;
	}
}

/* a press in the keyboard strip, at x, y on the display */

static int
ui_key_press(struct lws_dlo_ui *ui, int x, int y)
{
	int y0, y1, n;

	ui_strip_band(ui, UI_STRIP_KEYS, &y0, &y1);
	x -= ui->kx;
	y -= y0 + ui->ky;

	for (n = 0; n < ui->nkeys; n++) {
		const ui_kpos_t *kp = &ui->keys[n];

		if (x >= kp->x && x < kp->x + kp->w &&
		    y >= kp->y && y < kp->y + ui->row_h) {
			ui_key(ui, kp->k);
			return 1;
		}
	}

	return 0;
}

static int
ui_json_int(const void *buf, size_t len, const char *name, int *v)
{
	const char *p;
	char num[8];
	size_t al;

	p = lws_json_simple_find(buf, len, name, &al);
	if (!p || !al || al >= sizeof(num))
		return 1;

	lws_strnncpy(num, p, al, sizeof(num));
	*v = atoi(num);

	return 0;
}

int
lws_dlo_ui_touch(struct lws_dlo_ui *ui, const void *buf, size_t len)
{
	int x, y, dx, dy, v, idx, strip;
	unsigned int gen;

	if (lws_json_simple_strcmp(buf, len, "\"type\":", "touch") ||
	    ui_json_int(buf, len, "\"x\":", &x) ||
	    ui_json_int(buf, len, "\"y\":", &y) ||
	    x < 0 || x >= ui->w || y < 0 || y >= ui->h)
		return 0;

	strip = ui_strip_at(ui, y);

	if (!lws_json_simple_strcmp(buf, len, "\"event\":", "down")) {
		/* a drag moves what is in the strip it began in */
		ui->drag = (uint8_t)strip;
		return 0;
	}

	if (!lws_json_simple_strcmp(buf, len, "\"event\":", "scroll")) {
		if (ui_json_int(buf, len, "\"dx\":", &dx) ||
		    ui_json_int(buf, len, "\"dy\":", &dy))
			return 0;

		switch (ui->drag) {
		case UI_STRIP_LIST:
			/* the list follows the finger */
			v = ui->top;
			ui->top -= dy;
			ui_clamp_top(ui);
			if (ui->top == v)
				return 1;
			ui->user_scrolled = 1;
			ui->stale = 1;
			ui->dirty |= UI_STRIP_LIST;
			lws_dlo_ui_kick(ui);
			return 1;

		case UI_STRIP_EDIT:
			/* dragging it right shows what was typed earlier */
			v = ui->escroll;
			ui->escroll += dx;
			ui_clamp_escroll(ui);
			if (ui->escroll / ui_edit_char_w(ui) !=
			    v / ui_edit_char_w(ui))
				ui_edit_changed(ui, UI_STRIP_EDIT);
			return 1;

		case UI_STRIP_KEYS:
			v = ui->kx;
			idx = ui->ky;
			ui->kx += dx;
			ui->ky += dy;
			ui_clamp_kb(ui);
			if (ui->kx != v || ui->ky != idx)
				ui_edit_changed(ui, UI_STRIP_KEYS);
			return 1;

		default:
			return 0;
		}
	}

	/* a press is reported where it began */

	if (lws_json_simple_strcmp(buf, len, "\"event\":", "press"))
		return 0;

	switch (strip) {
	case UI_STRIP_TITLE:
		if (ui->page_strips != UI_PAGE_EDIT) {
			if (!ui->i.title)
				return 0;
			ui->i.title(ui->i.opaque);
			return 1;
		}
		/* going back from editing abandons it */
		gen = ui->edit_gen;
		ui->i.done(ui->i.opaque, NULL);
		if (ui->edit_gen == gen)
			ui_edit_end(ui);
		return 1;

	case UI_STRIP_KEYS:
		return ui_key_press(ui, x, y);

	case UI_STRIP_LIST:
		idx = (y - ui->title_h + ui->top) / ui->row_h;
		if (idx >= ui->count)
			return 0;
		if (ui->i.pick)
			ui->i.pick(ui->i.opaque, idx);
		return 1;

	default:
		return 0;
	}
}
