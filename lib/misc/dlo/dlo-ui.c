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
 * When what is shown changes, the html for the whole display is made again
 * and laid out.  The display list is kept, and only the bands of lines of
 * the strips that changed are rendered from it and sent to the display, if
 * it can take a band.
 *
 * Dragging the keyboard doesn't change what is shown, only where: the whole
 * keyboard is laid out once, in one element, and a drag just moves that
 * element's dlo in the display list, and renders the keyboard's strip again.
 *
 * The geometry, which depends on the display, is worked out here and given
 * to the elements by id in a style block, after the theme and the caller's
 * css, so they can't move anything; everything the caller gave us is put in
 * the html as text.
 *
 * There are four pages: the list page, a title strip over a list strip, the
 * edit page, a title strip over an edit strip over a keyboard strip, the
 * frame page, a title strip over the caller's body, and the dialog page, a
 * title strip over a panel of the caller's html.  The frame's html is the
 * title strip over nothing, white: the ui only draws all of it to show the
 * frame before the caller has anything in its body.  Otherwise the caller
 * draws the display, taking the title strip's lines from us.
 *
 * The dialog's html is laid out in one element, #pc: scrolling the panel
 * moves its dlo, like dragging the keyboard, and the cursor on its links is
 * a ring of rects added to it after layout, so neither lays it out again.
 * The links are found in the laid out display list, in document order.
 *
 * The status capsule, and its icons, are boxes styled by the css, so they
 * need nothing from the dlo filesystem and are sized for the display.
 */

#include <private-lib-core.h>

#define LWS_DLO_UI_TITLE_MAX		32
#define UI_CSS_MAX			2048
#define UI_BUTTON_NAME_MAX		16

/* the strips, as bits of what needs drawing */

enum {
	UI_STRIP_TITLE			= (1 << 0),
	UI_STRIP_LIST			= (1 << 1),
	UI_STRIP_EDIT			= (1 << 2),
	UI_STRIP_KEYS			= (1 << 3),
	UI_STRIP_BODY			= (1 << 4),	/* the caller's */
	UI_STRIP_PANEL			= (1 << 5),	/* the caller's html */
};

/* the strips each page has */

#define UI_PAGE_LIST			(UI_STRIP_TITLE | UI_STRIP_LIST)
#define UI_PAGE_EDIT			(UI_STRIP_TITLE | UI_STRIP_EDIT | \
					 UI_STRIP_KEYS)
#define UI_PAGE_FRAME			(UI_STRIP_TITLE | UI_STRIP_BODY)
#define UI_PAGE_DIALOG			(UI_STRIP_TITLE | UI_STRIP_PANEL)

/* the most links a dialog's panel can have, that can be pressed */
#define UI_HITS_MAX			32
/* the default for the most html the panel can be */
#define UI_DIALOG_HTML_MAX		4096
/*
 * lhp drops what it would lay out below the surface, so the dialog is laid
 * out on one this many displays tall, for its panel to scroll down to
 */
#define UI_DIALOG_LAYOUT_DISPLAYS	8

/* a link on the panel, where it is in the panel's content, #pc */

typedef struct {
	const lws_dlo_hit_t	*hit;	/* while laid out */
	int			x, y, w, h;
} ui_hit_t;

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
	lws_surface_info_t		body_ic; /* the frame's body */

	char				title[LWS_DLO_UI_TITLE_MAX];
	char				edit_title[LWS_DLO_UI_TITLE_MAX];
	char				page_name[32];
	char				status_button[UI_BUTTON_NAME_MAX];
	char				*css;	/* the caller's, or NULL */

	/* the dialog page */

	lws_dlo_ui_dialog_t		dlg;	/* .css is dlg_css */
	char				*dlg_css; /* the caller's, or NULL */
	lws_dlo_t			*pc;	/* the panel's content, while
						 * laid out */
	lws_dlo_rect_t			*ring[4]; /* the cursor, while laid out */
	ui_hit_t			hits[UI_HITS_MAX];
	int				nhits;
	int				pcur;	/* the link the cursor is on */
	int				pscroll; /* px the panel is scrolled by */
	int				pc_h;	/* how tall its content is */
	int				pc_ox, pc_oy; /* where its content's top
						       * left is on the display,
						       * not scrolled */

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
	lws_dlo_t			*kb;	/* the keyboard's dlo, which a drag
						 * moves, while laid out */
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
	int				cursor;	/* row the cursor is on */
	int				kcur;	/* key the cursor is on */

	/* the status capsule, where it is on the display, if it's shown */
	int				cap_x0, cap_x1, cap_y0, cap_y1;
	int8_t				st_wlan;	/* bars, or NONE */
	int8_t				st_batt;	/* quarters, or NONE */
	uint8_t				st_chg;

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
	uint8_t				nav;	 /* the cursor is shown */
	uint8_t				frame_full; /* draw all the frame */
	uint8_t				frame_lines; /* the caller is partway
						      * through the title
						      * strip's lines */
	uint8_t				edit_ret; /* UI_PAGE_*: the page an
						   * edit goes back to */
	uint8_t				keep;	 /* LWS_DLO_UI_EDIT_KEEP */
};

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
	default: /* UI_STRIP_LIST, UI_STRIP_BODY, UI_STRIP_PANEL */

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

	for (s = UI_STRIP_TITLE; s <= UI_STRIP_PANEL; s <<= 1) {
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

/*
 * The title's line of text sits at the bottom of its strip, and the status
 * capsule, if it's shown, at the right end of the same lines
 */

static void
ui_title_line(const struct lws_dlo_ui *ui, int *y0, int *y1)
{
	*y0 = ui->title_h - (ui->fs_title * 6) / 5 - ui->pad;
	*y1 = ui->title_h - ui->pad;
}

/* the inside of the capsule is split into its icons with this much padding */

static int
ui_status_pad(const struct lws_dlo_ui *ui)
{
	int p = (ui->cap_y1 - ui->cap_y0) / 6;

	return p < 1 ? 1 : p;
}

/* how wide the battery icon is, for the capsule's height */

static int
ui_status_batt_w(int ih)
{
	return (ih * 3) / 2;
}

/* where the capsule is, sized for the icons it shows */

static void
ui_status_place(struct lws_dlo_ui *ui)
{
	int y0, y1, x0, x1, ih, cp, w;

	ui->cap_x0 = ui->cap_x1 = 0;

	if (ui->st_wlan == LWS_DLO_UI_STATUS_NONE &&
	    ui->st_batt == LWS_DLO_UI_STATUS_NONE)
		return;

	/* as tall as the title's text, in the middle of its line */
	ui_title_line(ui, &y0, &y1);
	ui->cap_y0 = y0 + (y1 - y0 - ui->fs_title) / 2;
	ui->cap_y1 = ui->cap_y0 + ui->fs_title;
	cp = ui_status_pad(ui);
	ih = ui->fs_title - 2 * cp;
	if (ih < 4)
		return;

	w = cp;
	if (ui->st_wlan != LWS_DLO_UI_STATUS_NONE)
		w += ih + cp;
	if (ui->st_batt != LWS_DLO_UI_STATUS_NONE)
		w += ui_status_batt_w(ih) + cp;
	/* its round ends */
	w += ih / 2;

	ui_span(ui, ui->cap_y0, ui->cap_y1, &x0, &x1);
	if (x1 - x0 < 2 * w)
		/* it would leave no room for the title */
		return;

	ui->cap_x1 = x1 - ui->pad;
	ui->cap_x0 = ui->cap_x1 - w;
}

/*
 * The columns the title's text can use: what can be seen of its line, less
 * the capsule's width at both ends, so the title stays in the middle.  If
 * that leaves it less than half, eg, at the top of a round display, it has
 * what is left of the capsule instead
 */

static void
ui_title_span(const struct lws_dlo_ui *ui, int *x0, int *x1)
{
	int y0, y1, w = ui->cap_x1 - ui->cap_x0;

	ui_title_line(ui, &y0, &y1);
	ui_span(ui, y0, y1, x0, x1);

	if (!w)
		return;

	if ((*x1 - *x0) - 2 * (w + 2 * ui->pad) >= (*x1 - *x0) / 2) {
		*x0 += w + 2 * ui->pad;
		*x1 -= w + 2 * ui->pad;
		return;
	}

	*x1 = ui->cap_x0 - ui->pad;
}

/*
 * The columns the dialog's html is laid out across, and how much of the
 * panel can be seen: on a round display, its content is as wide as the
 * circle at the bottom of the title strip, and it can be seen as far as that
 * is from the bottom
 */

static void
ui_panel_geom(const struct lws_dlo_ui *ui, int *x0, int *x1, int *vh)
{
	int y1 = ui->i.lds->disp->ic.round ? ui->h - ui->title_h : ui->h;

	ui_span(ui, ui->title_h, y1, x0, x1);
	*x0 += ui->pad;
	*x1 -= ui->pad;
	if (*x1 < *x0)
		*x1 = *x0;
	*vh = y1 - ui->title_h;
}

static int
ui_pscroll_max(const struct lws_dlo_ui *ui)
{
	int x0, x1, vh, m;

	ui_panel_geom(ui, &x0, &x1, &vh);
	m = ui->pc_h - vh;

	return m < 0 ? 0 : m;
}

/* how far the panel is scrolled is kept to how far it can be */

static void
ui_pscroll_clamp(struct lws_dlo_ui *ui)
{
	int m = ui_pscroll_max(ui);

	if (ui->pscroll > m)
		ui->pscroll = m;
	if (ui->pscroll < 0)
		ui->pscroll = 0;
}

/*
 * The panel's content is moved to where it's scrolled to.  Only when it's
 * laid out, or a scan starts: the render mustn't see it move under it
 */

static void
ui_pscroll_apply(struct lws_dlo_ui *ui)
{
	ui_pscroll_clamp(ui);

	if (ui->pc)
		lws_fx_set(ui->pc->box.y, -ui->pscroll, 0);
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
	"#t, #l, #e, #k, #p { position: absolute; left: 0; overflow: hidden }"
	/* what's wider than the panel is clipped, to be inside the circle */
	"#pc { position: absolute; overflow: hidden }"
	"#tt { position: absolute; text-align: center; white-space: nowrap;"
		" overflow: hidden }"
	".r, .k, #et { position: absolute; display: flex;"
		" justify-content: center; align-items: center;"
		" overflow: hidden }"
	".x { white-space: nowrap }"
	".d { opacity: 0.25 }"
	"#s, .sb, #sbo, #sbi, #sbf, #sbc, #sbn { position: absolute;"
		" overflow: hidden }"

	/* the theme */

	"#ui { background-color: #fff }"
	"#t { background-color: #24476b }"
	"#tt { color: #fff }"
	".f { background-color: #ccc; border-radius: 4px }"
	"#et { background-color: #eee; border-radius: 4px }"
	".k { background-color: #ddd; border-radius: 4px }"
	".ks { background-color: #b8bcc8 }"
	".ka { background-color: #24476b; color: #fff }"
	".c { background-color: #24476b; color: #fff; border-radius: 4px;"
		" opacity: 1 }"
	".kc { background-color: #000; color: #fff }"
	"#s { background-color: #fff }"
	".sb, #sbo, #sbn, #sbf { background-color: #24476b }"
	".sb { opacity: 0.3 }"
	".so { opacity: 1 }"
	"#sbi { background-color: #fff }"
	"#sbc { background-color: #2a8f3a }";

/* where the capsule's icons are in it */

static void
ui_status_css(const struct lws_dlo_ui *ui, lws_html_w_t *w)
{
	int ch = ui->cap_y1 - ui->cap_y0, cp = ui_status_pad(ui),
	    ih = ch - 2 * cp, x = ih / 4 + cp, n, g, bw, bh, ow, oh, ot, nw,
	    fw;

	if (ui->cap_x1 == ui->cap_x0)
		return;

	lws_html_w_printf(w, "#s { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		     " border-radius: %dpx }", ui->cap_x0, ui->cap_y0,
		     ui->cap_x1 - ui->cap_x0, ch, ch / 2);

	if (ui->st_wlan != LWS_DLO_UI_STATUS_NONE) {
		/* bars getting taller, standing on the bottom of the icon */
		g = ih / 8 ? ih / 8 : 1;
		bw = (ih - (LWS_DLO_UI_WLAN_BARS - 1) * g) /
							LWS_DLO_UI_WLAN_BARS;
		if (bw < 1)
			bw = 1;
		for (n = 0; n < LWS_DLO_UI_WLAN_BARS; n++) {
			bh = (ih * (n + 1)) / LWS_DLO_UI_WLAN_BARS;
			if (bh < 1)
				bh = 1;
			lws_html_w_printf(w, "#sb%d { left: %dpx; top: %dpx;"
				     " width: %dpx; height: %dpx }", n,
				     x + n * (bw + g), cp + ih - bh, bw, bh);
		}
		x += ih + cp;
	}

	if (ui->st_batt == LWS_DLO_UI_STATUS_NONE)
		return;

	/* an outline with a nub on its right, filled as far as charged */

	nw = ui_status_batt_w(ih) / 10 ? ui_status_batt_w(ih) / 10 : 1;
	ow = ui_status_batt_w(ih) - nw;
	oh = (ih * 2) / 3 < 5 ? 5 : (ih * 2) / 3;
	ot = cp + (ih - oh) / 2;
	fw = ((ow - 4) * ui->st_batt) / 4;
	if (fw < 0)
		fw = 0;

	lws_html_w_printf(w, "#sbo { left: %dpx; top: %dpx; width: %dpx; height: %dpx }"
		     "#sbn { left: %dpx; top: %dpx; width: %dpx; height: %dpx }"
		     "#sbi { left: %dpx; top: %dpx; width: %dpx; height: %dpx }",
		     x, ot, ow, oh, x + ow, ot + oh / 4, nw, oh - 2 * (oh / 4),
		     x + 1, ot + 1, ow - 2, oh - 2);
	if (ui->st_batt)
		lws_html_w_printf(w, "#%s { left: %dpx; top: %dpx; width: %dpx;"
			     " height: %dpx }", ui->st_chg ? "sbc" : "sbf",
			     x + 2, ot + 2, fw, oh - 4);
}

/* the capsule, inside the title strip */

static void
ui_status_html(const struct lws_dlo_ui *ui, lws_html_w_t *w)
{
	int n;

	if (ui->cap_x1 == ui->cap_x0)
		return;

	lws_html_w_printf(w, "<div id=\"s\">");

	if (ui->st_wlan != LWS_DLO_UI_STATUS_NONE)
		for (n = 0; n < LWS_DLO_UI_WLAN_BARS; n++)
			lws_html_w_printf(w, "<div class=\"sb%s\" id=\"sb%d\"></div>",
				  n < ui->st_wlan ? " so" : "", n);

	if (ui->st_batt != LWS_DLO_UI_STATUS_NONE) {
		lws_html_w_printf(w, "<div id=\"sbo\"></div><div id=\"sbi\"></div>");
		if (ui->st_batt)
			lws_html_w_printf(w, "<div id=\"%s\"></div>",
				  ui->st_chg ? "sbc" : "sbf");
		lws_html_w_printf(w, "<div id=\"sbn\"></div>");
	}

	lws_html_w_printf(w, "</div>");
}

/* the edit page's strips, after the title strip */

static void
ui_html_edit(struct lws_dlo_ui *ui, lws_html_w_t *w)
{
	int y0, y1, ky0, ky1, x0, x1, n, vis, end, start;
	char t[LWS_DLO_UI_EDIT_MAX + 2];
	const ui_kpos_t *kp;

	ui_strip_band(ui, UI_STRIP_EDIT, &y0, &y1);
	ui_strip_band(ui, UI_STRIP_KEYS, &ky0, &ky1);

	lws_html_w_printf(w, "#e { top: %dpx; width: %dpx; height: %dpx }"
		     "#k { top: %dpx; width: %dpx; height: %dpx }",
		     y0, ui->w, y1 - y0, ky0, ui->w, ky1 - ky0);

	/* the edit box, across what can be seen of its strip */

	ui_span(ui, y0, y1, &x0, &x1);
	lws_html_w_printf(w, "#et { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		     " font-size: %dpx }", x0 + ui->pad, ui->pad,
		     x1 - x0 - 2 * ui->pad, y1 - y0 - 2 * ui->pad, ui->fs_row);

	/*
	 * All the keys are in the keyboard, #kb, wherever it was dragged to:
	 * a drag only moves #kb's dlo, without laying it out again
	 */

	lws_html_w_printf(w, "#kb { position: absolute; left: %dpx; top: %dpx;"
		     " width: %dpx; height: %dpx }.k { font-size: %dpx }",
		     ui->kx, ui->ky, (UI_KB_HALVES * ui->row_h) / 2,
		     ui_kb_rows(ui) * ui->row_h, ui->fs_row);
	for (n = 0; n < ui->nkeys; n++) {
		kp = &ui->keys[n];
		lws_html_w_printf(w, "#k%d { left: %dpx; top: %dpx; width: %dpx;"
			     " height: %dpx }", n, kp->x + ui->pad,
			     kp->y + ui->pad, kp->w - 2 * ui->pad,
			     ui->row_h - 2 * ui->pad);
	}

	lws_html_w_printf(w, "</style></head><body><div id=\"ui\"><div id=\"t\">"
		     "<div id=\"tt\">");
	lws_html_w_text(w, ui->edit_title, sizeof(ui->edit_title));
	lws_html_w_printf(w, "</div>");
	ui_status_html(ui, w);

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

	lws_html_w_printf(w, "</div><div id=\"e\"><div id=\"et\">"
		     "<div class=\"x\">");
	lws_html_w_text(w, t, sizeof(t));
	lws_explicit_bzero(t, sizeof(t));
	lws_html_w_printf(w, "</div></div></div><div id=\"k\"><div id=\"kb\">");

	for (n = 0; n < ui->nkeys && !w->full; n++) {
		const char *cap;
		char c[2];

		kp = &ui->keys[n];
		cap = kp->k->cap;
		if (kp->k->act == K_CHR && ui->layer == UI_LAYER_UPPER) {
			c[0] = (char)toupper((unsigned char)cap[0]);
			c[1] = '\0';
			cap = c;
		}
		if (kp->k->act == K_SHOW && ui->show)
			cap = "Hide";

		lws_html_w_printf(w, "<div class=\"k%s%s%s\" id=\"k%d\">"
			     "<div class=\"x\">",
			  kp->k->act == K_CHR ? "" : " ks",
			  (kp->k->act == K_SHIFT &&
			   ui->layer == UI_LAYER_UPPER) ||
			  (kp->k->act == K_SHOW && ui->show) ? " ka" : "",
			  ui->nav && n == ui->kcur ? " kc" : "", n);
		lws_html_w_text(w, cap, 8);
		lws_html_w_printf(w, "</div></div>");
	}

	lws_html_w_printf(w, "</div></div></div></body></html>");
}

static int
ui_html(struct lws_dlo_ui *ui, char *buf, size_t len)
{
	int lh = ui->h - ui->title_h, tl = (ui->fs_title * 6) / 5,
	    x0, x1, y0, n, first, last, ry, ix0,
	    ix1, round = ui->i.lds->disp->ic.round;
	lws_dlo_ui_row_t row;
	lws_html_w_t w;

	lws_html_w_init(&w, buf, len);

	lws_html_w_printf(&w, "<!doctype html><html><head><meta charset=\"utf-8\">"
		      "<style>%s%s", ui_css, ui->css ? ui->css : "");

	lws_html_w_printf(&w, "#ui { width: %dpx; height: %dpx }"
		      "#t { top: 0; width: %dpx; height: %dpx }",
		      ui->w, ui->h, ui->w, ui->title_h);

	/* the title's line sits at the bottom of its strip */

	ui_title_span(ui, &x0, &x1);
	if (x1 < x0)
		x1 = x0;
	lws_html_w_printf(&w, "#tt { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		      " font-size: %dpx }", x0, ui->title_h - tl - ui->pad,
		      x1 - x0, tl, ui->fs_title);
	ui_status_css(ui, &w);

	if (ui->page_strips == UI_PAGE_EDIT) {
		ui_html_edit(ui, &w);
		goto done;
	}

	if (ui->page_strips == UI_PAGE_DIALOG) {
		int vh;

		/*
		 * Below the title strip, the panel is the caller's html, in
		 * #pc, which is scrolled by moving its dlo.  The caller's css
		 * comes first, so it can't move them
		 */
		ui_panel_geom(ui, &x0, &x1, &vh);
		if (ui->dlg_css)
			lws_html_w_printf(&w, "%s", ui->dlg_css);
		lws_html_w_printf(&w, "#p { top: %dpx; width: %dpx; height: %dpx }"
			      "#pc { left: %dpx; top: 0; width: %dpx;"
			      " font-size: %dpx }</style></head><body>"
			      "<div id=\"ui\"><div id=\"t\"><div id=\"tt\">",
			      ui->title_h, ui->w, vh, x0,
			      x1 - x0, ui->fs_row);
		lws_html_w_text(&w, ui->title, sizeof(ui->title));
		lws_html_w_printf(&w, "</div>");
		ui_status_html(ui, &w);
		lws_html_w_printf(&w, "</div><div id=\"p\"><div id=\"pc\">");
		ui->dlg.html(ui->dlg.opaque, &w);
		lws_html_w_printf(&w, "</div></div></div></body></html>");
		goto done;
	}

	if (ui->page_strips == UI_PAGE_FRAME) {
		/* below the title strip, the body is the caller's */
		lws_html_w_printf(&w, "</style></head><body><div id=\"ui\">"
			      "<div id=\"t\"><div id=\"tt\">");
		lws_html_w_text(&w, ui->title, sizeof(ui->title));
		lws_html_w_printf(&w, "</div>");
		ui_status_html(ui, &w);
		lws_html_w_printf(&w, "</div></div></body></html>");
		goto done;
	}

	lws_html_w_printf(&w, "#l { top: %dpx; width: %dpx; height: %dpx }",
		      ui->title_h, ui->w, lh);

	/*
	 * Only the rows that can be seen are in the html, each positioned
	 * where it is in the strip as scrolled, and kept to the columns that
	 * can be seen across all of it, so the background of a highlighted
	 * one is all inside the circle.
	 *
	 * On a round display, a row's icon and text start at the left edge of
	 * the circle instead of being centred, from where all of its icon can
	 * be seen: the icons follow the circle round, and the rows away from
	 * the middle, where it's narrow, show less of their text
	 */

	if (round)
		lws_html_w_printf(&w, ".r { justify-content: flex-start }");

	first = ui->top / ui->row_h;
	last = (ui->top + lh + ui->row_h - 1) / ui->row_h;
	if (last > ui->count)
		last = ui->count;

	for (n = first; n < last; n++) {
		ry = n * ui->row_h - ui->top;
		y0 = ui->title_h + ry;
		ui_span(ui, y0 < ui->title_h ? ui->title_h : y0,
			y0 + ui->row_h, &x0, &x1);

		if (round) {
			y0 = ui->title_h + ry + ui->pad;
			ui_span(ui, y0 < ui->title_h ? ui->title_h : y0,
				y0 + ui->icon, &ix0, &ix1);
			if (ix1 > ix0 && ix0 + ui->pad < x1)
				x0 = ix0 + ui->pad;
		}

		lws_html_w_printf(&w, "#r%d { left: %dpx; top: %dpx; width: %dpx;"
			      " height: %dpx; font-size: %dpx }", n, x0, ry,
			      x1 - x0, ui->row_h, ui->fs_row);
	}

	lws_html_w_printf(&w, ".i { width: %dpx; height: %dpx; margin-right: %dpx }"
		      ".i img { width: 100%%; height: 100%% }</style></head>"
		      "<body><div id=\"ui\"><div id=\"t\"><div id=\"tt\">",
		      ui->icon, ui->icon, ui->pad * 2);
	lws_html_w_text(&w, ui->title, sizeof(ui->title));
	lws_html_w_printf(&w, "</div>");
	ui_status_html(ui, &w);
	lws_html_w_printf(&w, "</div><div id=\"l\">");

	for (n = first; n < last && !w.full; n++) {
		memset(&row, 0, sizeof(row));
		if (ui->i.row(ui->i.opaque, n, &row))
			continue;

		lws_html_w_printf(&w, "<div class=\"r%s%s\" id=\"r%d\">",
			  row.state == LWS_DLO_UI_ROW_DIM ? " d" :
			  (row.state == LWS_DLO_UI_ROW_FOCUS ? " f" : ""),
			  ui->nav && n == ui->cursor ? " c" : "", n);
		if (ui_icon_name_ok(row.icon))
			lws_html_w_printf(&w, "<div class=\"i\"><img src=\"%s\">"
				      "</div>", row.icon);
		lws_html_w_printf(&w, "<div class=\"x\">");
		lws_html_w_text(&w, row.text, sizeof(row.text));
		lws_html_w_printf(&w, "</div></div>");
	}

	lws_html_w_printf(&w, "</div></div></body></html>");

done:
	return lws_html_w_len(&w, buf);
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
	size_t len = 3072 + (ui->css ? strlen(ui->css) : 0);
	lws_dlo_filesystem_t f;
	char url[64];
	int n;

	switch (ui->page_strips) {
	case UI_PAGE_EDIT:
		len += (size_t)UI_KEYS_MAX * 192;
		break;
	case UI_PAGE_DIALOG:
		len += (ui->dlg_css ? strlen(ui->dlg_css) : 0) +
		       (ui->dlg.html_max ? ui->dlg.html_max :
					   UI_DIALOG_HTML_MAX);
		break;
	default:
		len += (size_t)((ui->h / ui->row_h) + 2) * 512;
		break;
	}
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
	ui->kb = NULL;
	ui->pc = NULL;
	memset(ui->ring, 0, sizeof(ui->ring));
	ui->nhits = 0;
	lws_display_dl_init(&ui->rs.displaylist, ui->i.lds);

	/*
	 * To find the keyboard's dlo after layout, to move it for drags, or
	 * the dialog's content, to scroll it
	 */
	if ((ui->page_strips == UI_PAGE_EDIT &&
	     !lws_display_render_add_id(&ui->rs, "kb", NULL)) ||
	    (ui->page_strips == UI_PAGE_DIALOG &&
	     !lws_display_render_add_id(&ui->rs, "pc", NULL))) {
		ui_page_drop(ui);
		return 1;
	}

	memset(ui->rs.st, 0, sizeof(ui->rs.st));
	ui->rs.sp = 0;
	ui->rs.curr = 0;
	ui->rs.ic = &ui->i.lds->disp->ic;
	ui->rs.lds = ui->i.lds;
	/*
	 * The panel's content can be taller than the display: it's laid out
	 * further down than can be seen, the viewport still the display
	 */
	ui->rs.layout_h = ui->page_strips == UI_PAGE_DIALOG ?
				UI_DIALOG_LAYOUT_DISPLAYS * ui->h : 0;
	/* the display list is kept, to render bands of it again */
	ui->rs.retained = 1;
	/* the ui is shown before there's any network */
	ui->rs.fonts_local = 1;

	ui->stale = 0;
	ui->phase = UI_LAYOUT;
	/*
	 * Laying the frame out doesn't draw anything: the caller may be
	 * drawing its body meanwhile.  Otherwise the display is ours, and we
	 * draw on it as soon as the layout is complete
	 */
	if (ui->page_strips != UI_PAGE_FRAME)
		ui->i.lds->display_busy = 1;

	lws_snprintf(url, sizeof(url), "file://dlofs/%s", ui->page_name);
	if (lws_lhp_ss_browse(ui->i.cx, &ui->rs, url, ui_render)) {
		lwsl_err("%s: browse failed\n", __func__);
		ui->phase = UI_IDLE;
		if (ui->page_strips != UI_PAGE_FRAME)
			ui->i.lds->display_busy = 0;
		ui_page_drop(ui);
		return 1;
	}

	return 0;
}

/*
 * Each link of the panel, in document order, where it is in the panel's
 * content.  A link laid out in pieces, eg, text that wrapped, is one link,
 * across all of them
 */

static int
ui_hit_cb(void *opaque, lws_dlo_hit_t *h, const lws_box_t *b)
{
	struct lws_dlo_ui *ui = (struct lws_dlo_ui *)opaque;
	int x = b->x.whole - ui->pc_ox, y = b->y.whole - ui->pc_oy,
	    x1 = x + b->w.whole, y1 = y + b->h.whole;
	ui_hit_t *ht;

	if (!h->url || !h->url[0] || b->w.whole <= 0 || b->h.whole <= 0)
		return 0;

	if (ui->nhits) {
		ht = &ui->hits[ui->nhits - 1];
		if (!strcmp(ht->hit->url, h->url)) {
			if (x < ht->x) {
				ht->w += ht->x - x;
				ht->x = x;
			}
			if (y < ht->y) {
				ht->h += ht->y - y;
				ht->y = y;
			}
			if (x1 > ht->x + ht->w)
				ht->w = x1 - ht->x;
			if (y1 > ht->y + ht->h)
				ht->h = y1 - ht->y;
			return 0;
		}
	}

	if (ui->nhits == UI_HITS_MAX)
		/* the rest can't be reached by the cursor, only pressed */
		return 1;

	ht = &ui->hits[ui->nhits++];
	ht->hit = h;
	ht->x = x;
	ht->y = y;
	ht->w = b->w.whole;
	ht->h = b->h.whole;

	return 0;
}

static void
ui_ring_place(struct lws_dlo_ui *ui);

/* the dialog was laid out: find its content and links */

static void
ui_panel_laid_out(struct lws_dlo_ui *ui)
{
	int x, y;

	ui->nhits = 0;
	if (!ui->pc)
		return;

	ui->pc_h = ui->pc->box.h.whole;
	lws_fx_set(ui->pc->box.y, 0, 0);
	if (lws_display_dlo_origin(&ui->rs.displaylist, ui->pc, &x, &y)) {
		ui->pc = NULL;
		return;
	}
	ui->pc_ox = x;
	ui->pc_oy = y;

	lws_display_dl_hit_foreach(&ui->rs.displaylist, ui_hit_cb, ui);

	/* where it was scrolled to, and the cursor, are kept if they can be */
	ui_pscroll_apply(ui);
	if (ui->pcur >= ui->nhits)
		ui->pcur = ui->nhits - 1;
	if (ui->nav)
		ui_ring_place(ui);
}

/*
 * The cursor on the dialog: a ring of four rects around the link it's on,
 * in the panel's content so it scrolls with it.  They're made once per
 * layout, and only moved, or hidden by being transparent
 */

static void
ui_ring_place(struct lws_dlo_ui *ui)
{
	int t = ui->pad < 2 ? 2 : ui->pad, n, x, y, w, h;
	const ui_hit_t *ht;
	lws_box_t b[4];

	if (!ui->pc)
		return;

	if (!ui->nav || ui->pcur < 0 || ui->pcur >= ui->nhits) {
		for (n = 0; n < 4; n++)
			if (ui->ring[n])
				ui->ring[n]->dlo.dc = 0;
		return;
	}

	ht = &ui->hits[ui->pcur];
	x = ht->x - t;
	y = ht->y - t;
	w = ht->w + 2 * t;
	h = ht->h + 2 * t;

	memset(b, 0, sizeof(b));
	/* top, bottom, left, right */
	lws_fx_set(b[0].x, x, 0);
	lws_fx_set(b[0].y, y, 0);
	lws_fx_set(b[0].w, w, 0);
	lws_fx_set(b[0].h, t, 0);
	b[1] = b[0];
	lws_fx_set(b[1].y, y + h - t, 0);
	lws_fx_set(b[2].x, x, 0);
	lws_fx_set(b[2].y, y, 0);
	lws_fx_set(b[2].w, t, 0);
	lws_fx_set(b[2].h, h, 0);
	b[3] = b[2];
	lws_fx_set(b[3].x, x + w - t, 0);

	for (n = 0; n < 4; n++) {
		if (!ui->ring[n]) {
			ui->ring[n] = lws_display_dlo_rect_new(
					&ui->rs.displaylist, ui->pc, &b[n],
					NULL, 0);
			if (!ui->ring[n])
				return;
		}
		ui->ring[n]->dlo.box = b[n];
		/* where it is is worked out again */
		ui->ring[n]->init = 0;
		ui->ring[n]->dlo.dc = LWSDC_RGBA(0x24, 0x47, 0x6b, 0xff);
	}
}

/* scroll the panel so the link the cursor is on can be seen, and show it */

static void
ui_pcur_show(struct lws_dlo_ui *ui)
{
	int x0, x1, vh, t = ui->pad < 2 ? 2 : ui->pad;
	const ui_hit_t *ht;

	if (ui->pcur >= 0 && ui->pcur < ui->nhits) {
		ht = &ui->hits[ui->pcur];
		ui_panel_geom(ui, &x0, &x1, &vh);
		if (ht->y - t < ui->pscroll)
			ui->pscroll = ht->y - t;
		if (ht->y + ht->h + t > ui->pscroll + vh)
			ui->pscroll = ht->y + ht->h + t - vh;
		ui_pscroll_clamp(ui);
	}

	/* the panel and the cursor are moved when it's next drawn */
	ui->dirty |= UI_STRIP_PANEL;
	lws_dlo_ui_kick(ui);
}

/* the link idx was pressed: tell the caller its href */

static void
ui_dialog_press(struct lws_dlo_ui *ui, int idx)
{
	char href[256];

	if (idx < 0 || idx >= ui->nhits || !ui->dlg.action)
		return;

	/* the hit goes when the panel is laid out again, eg, by the caller */
	lws_strncpy(href, ui->hits[idx].hit->url, sizeof(href));
	ui->dlg.action(ui->dlg.opaque, href);
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

	/* of the frame, we draw its body, white, only when drawing all of it */
	if (ui->page_strips == UI_PAGE_FRAME && !ui->frame_full)
		ui->drawing &= (uint8_t)~UI_STRIP_BODY;

	/*
	 * The strips are bands of whole lines, one above the other: the band
	 * drawn runs from the top of the first that changed to the bottom of
	 * the last.  If the display can only take whole updates, it gets
	 * everything
	 */

	for (s = UI_STRIP_TITLE; s <= UI_STRIP_PANEL; s <<= 1) {
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

	/* the keyboard is where it has been dragged to since it was laid out */
	if (ui->kb) {
		lws_fx_set(ui->kb->box.x, ui->kx, 0);
		lws_fx_set(ui->kb->box.y, ui->ky, 0);
	}
	/* and the dialog's content where it's scrolled to, and its cursor */
	ui_pscroll_apply(ui);
	if (ui->page_strips == UI_PAGE_DIALOG)
		ui_ring_place(ui);

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
	ui->frame_full = 0;

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

/* the next step of the layout or scan, from the sul or directly */

static void
ui_render_step(struct lws_dlo_ui *ui)
{
	lws_display_render_state_t *rs = &ui->rs;
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

		/* before the ids are decoupled from the dlos */
		ui->kb = lws_display_dlo_by_id(&rs->displaylist,
				      lws_display_render_get_id(rs, "kb"));
		ui->pc = lws_display_dlo_by_id(&rs->displaylist,
				      lws_display_render_get_id(rs, "pc"));
		lws_display_get_ids_boxes(rs);
		ui_panel_laid_out(ui);

		if (ui->page_strips == UI_PAGE_FRAME) {
			/* whether, and how, it's drawn is decided when idle */
			ui->phase = UI_IDLE;
			if (ui->dirty || ui->stale)
				lws_dlo_ui_kick(ui);
			return;
		}

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
ui_render(lws_sorted_usec_list_t *sul)
{
	ui_render_step(lws_container_of(sul, struct lws_dlo_ui, rs.sul));
}

/*
 * The frame page: its title strip is laid out again whenever it changed and
 * the caller isn't partway through drawing it, even while the caller is
 * drawing its body.  What changed is drawn by us only when the display is
 * free, and then only if we're asked to draw all of it, or it's just the title
 * strip and the display can take it as a band.  A bistable display gets it
 * with the caller's next update, and other displays are drawn again by the
 * caller, if it wants to be told.
 */

static void
ui_frame_kick(struct lws_dlo_ui *ui)
{
	const lws_display_t *disp = ui->i.lds->disp;

	if (ui->frame_lines && !ui->i.lds->display_busy)
		/* the caller's update ended before the strip's last line */
		ui->frame_lines = 0;

	if (ui->stale) {
		if (ui->frame_lines)
			/* frame_line() kicks us after its last line */
			return;
		if (ui_layout(ui))
			ui->dirty = 0;
		return;
	}

	if (!ui->dirty || ui->i.lds->display_busy)
		return;

	if (ui->frame_full || disp->ic.band) {
		if (ui_scan_start(ui)) {
			lwsl_err("%s: OOM\n", __func__);
			ui->phase = UI_IDLE;
			ui->i.lds->display_busy = 0;
			ui->dirty = 0;
			return;
		}
		ui_render_step(ui);
		return;
	}

	if (disp->bistable || !ui->i.frame_redraw)
		/* frame_line() clears it, when the caller draws it */
		return;

	ui->dirty = 0;
	ui->i.frame_redraw(ui->i.opaque);
}

static void
ui_kick_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_dlo_ui *ui = lws_container_of(sul, struct lws_dlo_ui,
						 sul_kick);

	if (ui->phase != UI_IDLE)
		return;

	if (ui->page_strips == UI_PAGE_FRAME) {
		ui_frame_kick(ui);
		return;
	}

	if (ui->i.lds->display_busy)
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
		ui_render_step(ui);
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

	size_t cl = 0, n;

	if (!info->row)
		return NULL;

	if (info->status_button) {
		/* it goes in the JSON of the events it issues */
		for (n = 0; info->status_button[n]; n++)
			if (n == UI_BUTTON_NAME_MAX - 1 ||
			    !((info->status_button[n] >= 'a' &&
			       info->status_button[n] <= 'z') ||
			      (info->status_button[n] >= '0' &&
			       info->status_button[n] <= '9') ||
			      info->status_button[n] == '-' ||
			      info->status_button[n] == '_')) {
				lwsl_err("%s: status_button refused\n",
					 __func__);
				return NULL;
			}
	}

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
	if (info->status_button)
		lws_strncpy(ui->status_button, info->status_button,
			    sizeof(ui->status_button));
	ui->i.status_button = NULL; /* it is ui->status_button */
	ui->w = ic->wh_px[0].whole;
	ui->h = ic->wh_px[1].whole;
	ui->focus = -1;
	ui->cursor = -1;
	ui->pcur = -1;
	ui->edit_ret = UI_PAGE_LIST;
	ui->st_wlan = ui->st_batt = LWS_DLO_UI_STATUS_NONE;
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

	/*
	 * The frame's body is the display below the title strip, as many
	 * pixels to the mm.  On a round display, it's the part of the circle
	 * below the strip, so a page shown in it can be panned to bring what
	 * is in the corners the circle cuts off into view
	 */

	ui->body_ic = *ic;
	ui->body_ic.wh_px[1].whole = ui->h - ui->title_h;
	ui->body_ic.wh_px[1].frac = 0;
	if (ui->h) {
		lws_fx_t a, t;

		lws_fx_set(a, ui->h - ui->title_h, 0);
		lws_fx_div(&t, &a, &ic->wh_px[1]);
		lws_fx_mul(&ui->body_ic.wh_mm[1], &ic->wh_mm[1], &t);
	}
	ui->body_ic.round_top = (int16_t)(ic->round ? ui->title_h : 0);

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
	ui->kb = NULL;
	lws_free_set_NULL(ui->line);
	ui_page_drop(ui);
	lws_explicit_bzero(ui->edit, sizeof(ui->edit));
	lws_free_set_NULL(ui->dlg_css);

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
	if (ui->page_strips == UI_PAGE_EDIT)
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
	if (ui->cursor >= count)
		ui->cursor = count - 1;
	ui_clamp_top(ui);

	if (ui->page_strips == UI_PAGE_EDIT) {
		/* the edit goes back to the list */
		ui->edit_ret = UI_PAGE_LIST;
		return;
	}

	if (ui->page_strips == UI_PAGE_FRAME ||
	    ui->page_strips == UI_PAGE_DIALOG) {
		/* the list page takes the whole display again */
		ui->page_strips = UI_PAGE_LIST;
		ui->drag = 0;
		ui->frame_full = 0;
		ui->frame_lines = 0;
		ui->dirty |= UI_PAGE_LIST;
	}

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
	ui->keep = 0;
	/* back to the page it was edited from */
	ui_page_show(ui, ui->edit_ret);
}

static void
ui_kcur_place(struct lws_dlo_ui *ui);

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
	ui->keep = !!(flags & LWS_DLO_UI_EDIT_KEEP);
	if (ui->page_strips != UI_PAGE_EDIT)
		/* editing from it: an edit started from an edit keeps this */
		ui->edit_ret = ui->page_strips == UI_PAGE_DIALOG ?
					UI_PAGE_DIALOG : UI_PAGE_LIST;
	ui->show = 0;
	ui->escroll = 0;
	ui->layer = UI_LAYER_LOWER;
	ui_keys_place(ui);

	/* the keyboard starts with its top row in the middle of the strip */
	ui->kx = (ui->w - (UI_KB_HALVES * ui->row_h) / 2) / 2;
	ui->ky = 0;
	ui_clamp_kb(ui);

	/* using buttons, the cursor starts on the first key, in view */
	ui->kcur = 0;
	if (ui->nav)
		ui_kcur_place(ui);

	ui_page_show(ui, UI_PAGE_EDIT);

	return 0;
}

int
lws_dlo_ui_edit_set(struct lws_dlo_ui *ui, const char *text)
{
	size_t n = strlen(text);

	if (ui->page_strips != UI_PAGE_EDIT || n > ui->edit_max)
		return 1;

	lws_explicit_bzero(ui->edit, sizeof(ui->edit));
	memcpy(ui->edit, text, n);
	ui->edit_len = n;
	ui->escroll = 0;
	ui->stale = 1;
	ui->dirty |= UI_STRIP_EDIT;
	lws_dlo_ui_kick(ui);

	return 0;
}

/*
 * Going back from editing abandons it, the caller is told: with what was
 * typed, if it should be kept however the edit ends
 */

static void
ui_edit_abandon(struct lws_dlo_ui *ui)
{
	unsigned int gen = ui->edit_gen;

	ui->i.done(ui->i.opaque, ui->keep ? ui->edit : NULL);
	if (ui->edit_gen == gen)
		ui_edit_end(ui);
}

int
lws_dlo_ui_edit_abandon(struct lws_dlo_ui *ui)
{
	if (ui->page_strips != UI_PAGE_EDIT)
		return 1;

	ui_edit_abandon(ui);

	return 0;
}

int
lws_dlo_ui_dialog(struct lws_dlo_ui *ui, const lws_dlo_ui_dialog_t *d)
{
	char *css = NULL;
	size_t cl;

	if (!d->html)
		return 1;

	if (d->css) {
		/* it goes in a style element: it mustn't be able to end it */
		cl = strlen(d->css);
		if (cl > UI_CSS_MAX || strchr(d->css, '<')) {
			lwsl_err("%s: css refused\n", __func__);
			return 1;
		}
		css = lws_malloc(cl + 1, __func__);
		if (!css)
			return 1;
		memcpy(css, d->css, cl + 1);
	}

	if (ui->page_strips == UI_PAGE_EDIT) {
		ui_edit_abandon(ui);
		if (ui->page_strips == UI_PAGE_EDIT) {
			/* the done callback started another edit */
			lws_free(css);
			return 1;
		}
	}

	lws_free_set_NULL(ui->dlg_css);
	ui->dlg_css = css;
	ui->dlg = *d;
	ui->dlg.css = NULL; /* it is ui->dlg_css */

	/* it starts at the top, the cursor on its first link */
	ui->pscroll = 0;
	ui->pcur = 0;
	ui->frame_full = 0;
	ui->frame_lines = 0;
	ui_page_show(ui, UI_PAGE_DIALOG);

	return 0;
}

void
lws_dlo_ui_dialog_changed(struct lws_dlo_ui *ui)
{
	if (ui->page_strips != UI_PAGE_DIALOG)
		/* it's written again when it's shown again anyway */
		return;

	ui->stale = 1;
	ui->dirty |= UI_STRIP_PANEL;
	lws_dlo_ui_kick(ui);
}


void
lws_dlo_ui_frame(struct lws_dlo_ui *ui, unsigned int flags)
{
	if (ui->page_strips == UI_PAGE_EDIT) {
		ui_edit_abandon(ui);
		if (ui->page_strips == UI_PAGE_EDIT)
			/* the done callback started another edit */
			return;
	}

	ui->page_strips = UI_PAGE_FRAME;
	ui->drag = 0;
	ui->nav = 0;
	ui->frame_lines = 0;
	ui->frame_full = !!(flags & LWS_DLO_UI_FRAME_DRAW);
	/* otherwise, the caller draws it */
	ui->dirty = ui->frame_full ? UI_PAGE_FRAME : 0;
	ui->stale = 1;
	lws_dlo_ui_kick(ui);
}

const lws_surface_info_t *
lws_dlo_ui_frame_body(struct lws_dlo_ui *ui, int *y)
{
	if (y)
		*y = ui->title_h;

	return &ui->body_ic;
}

lws_stateful_ret_t
lws_dlo_ui_frame_line(struct lws_dlo_ui *ui, int y, uint8_t *line)
{
	lws_display_render_state_t *rs = &ui->rs;
	lws_stateful_ret_t r;

	if (ui->page_strips != UI_PAGE_FRAME || y < 0 || y >= ui->title_h ||
	    ui->phase == UI_SCAN)
		return LWS_SRET_FATAL;

	if (!y) {
		/* the caller starts drawing the title strip, maybe again */
		ui->frame_lines = 0;
		if (ui->stale || ui->phase == UI_LAYOUT) {
			/* it's laid out first, as it is now */
			lws_dlo_ui_kick(ui);
			return LWS_SRET_WANT_INPUT;
		}

		/* until the last line, it isn't laid out again */
		ui->frame_lines = 1;
		memset(rs->st, 0, sizeof(rs->st));
		rs->sp = 0;
	}

	if (!ui->frame_lines)
		/* the caller must start from the first line */
		return LWS_SRET_FATAL;

	rs->curr = (lws_display_scalar)y;
	rs->line = line;
	r = lws_display_list_render_line(rs);
	rs->line = NULL;

	if (r & (LWS_SRET_WANT_INPUT | LWS_SRET_YIELD))
		return r & (LWS_SRET_WANT_INPUT | LWS_SRET_YIELD);
	if (r & LWS_SRET_FATAL) {
		ui->frame_lines = 0;
		return LWS_SRET_FATAL;
	}

	if (y == ui->title_h - 1) {
		/* the caller has drawn the title strip as it is now */
		ui->frame_lines = 0;
		ui->dirty &= (uint8_t)~UI_STRIP_TITLE;
		lws_dlo_ui_kick(ui);
	}

	return LWS_SRET_OK;
}

void
lws_dlo_ui_set_status(struct lws_dlo_ui *ui, const lws_dlo_ui_status_t *status)
{
	int8_t wlan = LWS_DLO_UI_STATUS_NONE, batt = LWS_DLO_UI_STATUS_NONE;
	uint8_t chg = 0;

	if (status) {
		/* what is shown: bars, and the charge in quarters */
		if (status->wlan >= 0)
			wlan = (int8_t)(status->wlan > LWS_DLO_UI_WLAN_BARS ?
					LWS_DLO_UI_WLAN_BARS : status->wlan);
		if (status->battery >= 0) {
			batt = (int8_t)(((status->battery > 100 ? 100 :
					  status->battery) + 12) / 25);
			chg = !!status->charging;
		}
	}

	if (wlan == ui->st_wlan && batt == ui->st_batt && chg == ui->st_chg)
		return;

	ui->st_wlan = wlan;
	ui->st_batt = batt;
	ui->st_chg = chg;
	ui_status_place(ui);

	ui->stale = 1;
	ui->dirty |= UI_STRIP_TITLE;
	lws_dlo_ui_kick(ui);
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

	if (lws_json_simple_strcmp(buf, len, "\"type\":", "touch") ||
	    ui_json_int(buf, len, "\"x\":", &x) ||
	    ui_json_int(buf, len, "\"y\":", &y) ||
	    x < 0 || x >= ui->w || y < 0 || y >= ui->h)
		return 0;

	strip = ui_strip_at(ui, y);

	if (ui->nav && ui->page_strips == UI_PAGE_DIALOG) {
		/* it's being touched: the cursor goes, without a new layout */
		ui->nav = 0;
		ui->dirty |= UI_STRIP_PANEL;
		lws_dlo_ui_kick(ui);
	} else if (ui->nav && ui->page_strips != UI_PAGE_FRAME) {
		/* it's being touched: the cursor goes */
		ui->nav = 0;
		ui->stale = 1;
		ui->dirty |= ui->page_strips == UI_PAGE_EDIT ? UI_STRIP_KEYS :
							       UI_STRIP_LIST;
		lws_dlo_ui_kick(ui);
	}

	if (strip == UI_STRIP_BODY) {
		/* it's the caller's, but a drag that began in it is too */
		if (!lws_json_simple_strcmp(buf, len, "\"event\":", "down"))
			ui->drag = UI_STRIP_BODY;
		return 0;
	}

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
		case UI_STRIP_PANEL:
			/* the panel follows the finger */
			v = ui->pscroll;
			ui->pscroll -= dy;
			ui_pscroll_clamp(ui);
			if (ui->pscroll == v)
				return 1;
			ui->dirty |= UI_STRIP_PANEL;
			lws_dlo_ui_kick(ui);
			return 1;

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
			if (ui->kx == v && ui->ky == idx)
				return 1;

			if (ui->stale || (!ui->kb && ui->phase != UI_LAYOUT)) {
				/*
				 * Either it will be laid out again anyway, or
				 * it isn't laid out to be moved
				 */
				ui_edit_changed(ui, UI_STRIP_KEYS);
				return 1;
			}

			/*
			 * Just move the keyboard as it was, or is being, laid
			 * out, when its strip is next rendered
			 */
			ui->dirty |= UI_STRIP_KEYS;
			lws_dlo_ui_kick(ui);
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
		v = ui->cap_x0 - ui->row_h / 2;
		if (v <= ui->w / 2)
			/* the middle, where the title is, stays the title */
			v = ui->w / 2 + 1;
		if (ui->cap_x1 != ui->cap_x0 && ui->status_button[0] &&
		    x >= (v < ui->cap_x0 ? v : ui->cap_x0)) {
			/*
			 * The capsule is a button, for a finger: all of the
			 * strip from a little before it, to the right edge,
			 * leaving the title its middle
			 */
#if defined(LWS_WITH_SYS_SMD)
			lws_smd_msg_printf(ui->i.cx, LWSSMDCL_INTERACTION,
					   "{\"type\":\"button\","
					   "\"src\":\"ui/%s\","
					   "\"event\":\"click\"}",
					   ui->status_button);
#endif
			return 1;
		}

		if (ui->page_strips != UI_PAGE_EDIT) {
			if (!ui->i.title)
				return 0;
			ui->i.title(ui->i.opaque);
			return 1;
		}
		/* going back from editing abandons it */
		ui_edit_abandon(ui);
		return 1;

	case UI_STRIP_KEYS:
		return ui_key_press(ui, x, y);

	case UI_STRIP_PANEL:
		/*
		 * The topmost link where it was pressed, as the panel was laid
		 * out and scrolled when it was drawn
		 */
		if (ui->phase == UI_LAYOUT || !ui->pc)
			return 1;
		x -= ui->pc_ox;
		y -= ui->pc_oy - ui->pscroll;
		for (idx = ui->nhits - 1; idx >= 0; idx--) {
			const ui_hit_t *ht = &ui->hits[idx];

			if (x >= ht->x && x < ht->x + ht->w &&
			    y >= ht->y && y < ht->y + ht->h)
				break;
		}
		ui_dialog_press(ui, idx);
		return 1;

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

/*
 * The cursor on the list: the focus row, or the first that can be seen, the
 * first time.  The list is scrolled to keep the row it is on in view
 */

static void
ui_cursor_show(struct lws_dlo_ui *ui)
{
	int lh = ui->h - ui->title_h;

	if (ui->cursor < 0 || ui->cursor >= ui->count)
		ui->cursor = ui->focus >= 0 ? ui->focus :
			     (ui->top + ui->row_h - 1) / ui->row_h;
	if (ui->cursor >= ui->count)
		ui->cursor = ui->count - 1;
	if (ui->cursor < 0)
		ui->cursor = 0;

	if (ui->cursor * ui->row_h < ui->top) {
		ui->top = ui->cursor * ui->row_h;
		ui->user_scrolled = 1;
	}
	if ((ui->cursor + 1) * ui->row_h > ui->top + lh) {
		ui->top = (ui->cursor + 1) * ui->row_h - lh;
		ui->user_scrolled = 1;
	}
	ui_clamp_top(ui);

	ui->stale = 1;
	ui->dirty |= UI_STRIP_LIST;
	lws_dlo_ui_kick(ui);
}

static int
ui_nav_list(struct lws_dlo_ui *ui, lws_dlo_ui_nav_t nav)
{
	switch (nav) {
	case LWS_DLO_UI_NAV_UP:
	case LWS_DLO_UI_NAV_DOWN:
		if (!ui->count)
			return 0;
		if (ui->nav && ui->cursor >= 0)
			ui->cursor += nav == LWS_DLO_UI_NAV_UP ? -1 : 1;
		ui->nav = 1;
		ui_cursor_show(ui);
		return 1;

	case LWS_DLO_UI_NAV_ENTER:
		if (!ui->count)
			return 0;
		if (!ui->nav) {
			/* the first time, it only shows where it is */
			ui->nav = 1;
			ui_cursor_show(ui);
			return 1;
		}
		if (ui->i.pick && ui->cursor >= 0 && ui->cursor < ui->count)
			ui->i.pick(ui->i.opaque, ui->cursor);
		return 1;

	case LWS_DLO_UI_NAV_ESC:
		if (!ui->i.title)
			return 0;
		ui->i.title(ui->i.opaque);
		return 1;

	default:
		return 0;
	}
}

/*
 * The key the cursor goes to: along its row, or to the row above or below,
 * the key nearest across
 */

static int
ui_kcur_move(const struct lws_dlo_ui *ui, lws_dlo_ui_nav_t nav)
{
	const ui_kpos_t *c = &ui->keys[ui->kcur];
	int n, best = ui->kcur, bd = INT32_MAX, cx = c->x + c->w / 2, ty, d,
	    first = -1, last = -1;

	switch (nav) {
	case LWS_DLO_UI_NAV_LEFT:
	case LWS_DLO_UI_NAV_RIGHT:
		/* along the row, around to the other end */
		for (n = 0; n < ui->nkeys; n++)
			if (ui->keys[n].y == c->y) {
				if (first < 0)
					first = n;
				last = n;
			}
		if (nav == LWS_DLO_UI_NAV_LEFT)
			return ui->kcur == first ? last : ui->kcur - 1;
		return ui->kcur == last ? first : ui->kcur + 1;

	default:
		ty = c->y + (nav == LWS_DLO_UI_NAV_UP ? -ui->row_h : ui->row_h);
		for (n = 0; n < ui->nkeys; n++) {
			if (ui->keys[n].y != ty)
				continue;
			d = ui->keys[n].x + ui->keys[n].w / 2 - cx;
			if (d < 0)
				d = -d;
			if (d < bd) {
				bd = d;
				best = n;
			}
		}
		return best;
	}
}

/* move the keyboard so the key the cursor is on can be seen */

static void
ui_kcur_place(struct lws_dlo_ui *ui)
{
	const ui_kpos_t *kp;
	int y0, y1, x0, x1, ky;

	if (ui->kcur < 0 || ui->kcur >= ui->nkeys)
		ui->kcur = 0;
	kp = &ui->keys[ui->kcur];

	ui_strip_band(ui, UI_STRIP_KEYS, &y0, &y1);

	ky = y0 + ui->ky + kp->y;
	if (ky < y0)
		ui->ky = -kp->y;
	if (ky + ui->row_h > y1)
		ui->ky = y1 - y0 - kp->y - ui->row_h;

	ky = y0 + ui->ky + kp->y;
	ui_span(ui, ky, ky + ui->row_h, &x0, &x1);
	if (ui->kx + kp->x < x0)
		ui->kx = x0 - kp->x;
	if (ui->kx + kp->x + kp->w > x1)
		ui->kx = x1 - kp->x - kp->w;

	ui_clamp_kb(ui);
}

static void
ui_kcur_show(struct lws_dlo_ui *ui)
{
	ui_kcur_place(ui);
	ui_edit_changed(ui, UI_STRIP_KEYS);
}

static int
ui_nav_edit(struct lws_dlo_ui *ui, lws_dlo_ui_nav_t nav)
{
	if (!ui->nkeys)
		return 0;

	switch (nav) {
	case LWS_DLO_UI_NAV_ESC:
		ui_edit_abandon(ui);
		return 1;

	case LWS_DLO_UI_NAV_ENTER:
		if (!ui->nav) {
			/* the first time, it only shows where it is */
			ui->nav = 1;
			ui_kcur_show(ui);
			return 1;
		}
		ui_key(ui, ui->keys[ui->kcur].k);
		if (ui->page_strips != UI_PAGE_EDIT)
			/* Done, and the edit is over */
			return 1;
		/* eg, the layer changed, and with it the keys */
		if (ui->kcur >= ui->nkeys)
			ui->kcur = ui->nkeys - 1;
		ui_kcur_show(ui);
		return 1;

	default:
		if (ui->nav)
			ui->kcur = ui_kcur_move(ui, nav);
		ui->nav = 1;
		ui_kcur_show(ui);
		return 1;
	}
}

/*
 * The link the cursor goes to: the one before or after it in the html, or
 * the nearest above or below it, preferring those straight above or below
 */

static int
ui_pcur_move(const struct lws_dlo_ui *ui, lws_dlo_ui_nav_t nav)
{
	const ui_hit_t *c = &ui->hits[ui->pcur];
	int n, best = ui->pcur, bd = INT32_MAX, cx = c->x + c->w / 2, d, dx;

	switch (nav) {
	case LWS_DLO_UI_NAV_LEFT:
		return ui->pcur ? ui->pcur - 1 : ui->pcur;
	case LWS_DLO_UI_NAV_RIGHT:
		return ui->pcur + 1 < ui->nhits ? ui->pcur + 1 : ui->pcur;
	default:
		for (n = 0; n < ui->nhits; n++) {
			const ui_hit_t *o = &ui->hits[n];

			if (nav == LWS_DLO_UI_NAV_UP ? o->y + o->h > c->y :
						       o->y < c->y + c->h)
				/* not wholly above, or below */
				continue;

			d = nav == LWS_DLO_UI_NAV_UP ? c->y - (o->y + o->h) :
						       o->y - (c->y + c->h);
			dx = o->x + o->w / 2 - cx;
			d = d * 4 + (dx < 0 ? -dx : dx);
			if (d < bd) {
				bd = d;
				best = n;
			}
		}
		return best;
	}
}

static int
ui_nav_dialog(struct lws_dlo_ui *ui, lws_dlo_ui_nav_t nav)
{
	int n;

	if (nav == LWS_DLO_UI_NAV_ESC) {
		if (!ui->i.title)
			return 0;
		ui->i.title(ui->i.opaque);
		return 1;
	}

	if (!ui->nhits)
		return 0;

	if (!ui->nav || ui->pcur < 0 || ui->pcur >= ui->nhits) {
		/* the first time, it only shows where it is: the first seen */
		for (n = 0; n < ui->nhits - 1; n++)
			if (ui->hits[n].y + ui->hits[n].h > ui->pscroll)
				break;
		ui->pcur = n;
		ui->nav = 1;
		ui_pcur_show(ui);
		return 1;
	}

	if (nav == LWS_DLO_UI_NAV_ENTER) {
		ui_dialog_press(ui, ui->pcur);
		return 1;
	}

	ui->pcur = ui_pcur_move(ui, nav);
	ui_pcur_show(ui);

	return 1;
}

int
lws_dlo_ui_nav(struct lws_dlo_ui *ui, lws_dlo_ui_nav_t nav)
{
	switch (ui->page_strips) {
	case UI_PAGE_LIST:
		return ui_nav_list(ui, nav);
	case UI_PAGE_EDIT:
		return ui_nav_edit(ui, nav);
	case UI_PAGE_DIALOG:
		return ui_nav_dialog(ui, nav);

	default:
		/* the frame's body is the caller's */
		return 0;
	}
}

int
lws_dlo_ui_interaction(struct lws_dlo_ui *ui, const void *buf, size_t len)
{
	static const char * const names[] = {
		"up", "down", "left", "right", "enter", "esc"
	};
	const char *p, *slash;
	size_t al, n, nl;

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "touch"))
		return lws_dlo_ui_touch(ui, buf, len);

	if (lws_json_simple_strcmp(buf, len, "\"type\":", "button") ||
	    lws_json_simple_strcmp(buf, len, "\"event\":", "click"))
		return 0;

	/* the button's name is what follows the controller's, eg, bc/up */

	p = lws_json_simple_find(buf, len, "\"src\":", &al);
	if (!p)
		return 0;
	slash = memchr(p, '/', al);
	if (slash) {
		al -= lws_ptr_diff_size_t(slash + 1, p);
		p = slash + 1;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(names); n++) {
		nl = strlen(names[n]);
		if (al == nl && !memcmp(p, names[n], nl))
			return lws_dlo_ui_nav(ui, (lws_dlo_ui_nav_t)n);
	}

	return 0;
}
