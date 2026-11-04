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
 * to the elements by id in a style block; everything the caller gave us is
 * put in the html as text.
 */

#include <private-lib-core.h>

#define LWS_DLO_UI_TITLE_MAX		32

/* the strips, as bits of what needs drawing */

enum {
	UI_STRIP_TITLE			= (1 << 0),
	UI_STRIP_LIST			= (1 << 1),
};

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
	char				page_name[32];

	char				*page;	/* the html we made, while it is
						 * registered in the dlo fs */
	uint8_t				*line;	/* a line of rendered pixels */

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

static const char * const ui_css =
	"* { margin: 0; padding: 0 }"
	"body { background-color: #fff; color: #000; font-family: sans }"
	"#ui { position: absolute; left: 0; top: 0; background-color: #fff }"
	"#t, #l { position: absolute; left: 0; overflow: hidden }"
	"#tr { position: absolute; height: 1px; background-color: #888 }"
	"#tt { position: absolute; text-align: center; white-space: nowrap;"
		" overflow: hidden }"
	".r { position: absolute; display: flex; justify-content: center;"
		" align-items: center; overflow: hidden }"
	".x { white-space: nowrap }"
	".d { opacity: 0.25 }"
	".f { background-color: #ccc; border-radius: 4px }";

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
		      "<style>%s", ui_css);

	ui_printf(&w, "#ui { width: %dpx; height: %dpx }"
		      "#t { top: 0; width: %dpx; height: %dpx }"
		      "#l { top: %dpx; width: %dpx; height: %dpx }",
		      ui->w, ui->h, ui->w, ui->title_h,
		      ui->title_h, ui->w, lh);

	/* the title's line sits at the bottom of its strip */

	ui_span(ui, ui->title_h - tl - ui->pad, ui->title_h - ui->pad, &x0, &x1);
	ui_printf(&w, "#tt { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		      " font-size: %dpx }", x0, ui->title_h - tl - ui->pad,
		      x1 - x0, tl, ui->fs_title);

	/* and a rule under it, as wide as can be seen there */

	ui_span(ui, ui->title_h - 1, ui->title_h, &x0, &x1);
	ui_printf(&w, "#tr { left: %dpx; top: %dpx; width: %dpx }",
		  x0, ui->title_h - 1, x1 - x0);

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
	ui_printf(&w, "</div><div id=\"tr\"></div></div><div id=\"l\">");

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

	if (w.full)
		return -1;

	return lws_ptr_diff(w.p, buf);
}

static void
ui_page_drop(struct lws_dlo_ui *ui)
{
	if (!ui->page)
		return;

	lws_dlo_file_unregister_by_name(ui->i.cx, ui->page_name);
	lws_free_set_NULL(ui->page);
}

static void
ui_render(lws_sorted_usec_list_t *sul);

/* the html changed: make it again and lay it out, then draw what's dirty */

static int
ui_layout(struct lws_dlo_ui *ui)
{
	size_t len = 2048 + (size_t)((ui->h / ui->row_h) + 2) * 512;
	lws_dlo_filesystem_t f;
	char url[64];
	int n;

	ui_page_drop(ui);

	ui->page = lws_malloc(len, __func__);
	if (!ui->page)
		return 1;

	n = ui_html(ui, ui->page, len);
	if (n < 0) {
		lwsl_err("%s: html too large\n", __func__);
		lws_free_set_NULL(ui->page);
		return 1;
	}

	memset(&f, 0, sizeof(f));
	f.name = ui->page_name;
	f.data = ui->page;
	f.len = (size_t)n;
	if (!lws_dlo_file_register(ui->i.cx, &f)) {
		lws_free_set_NULL(ui->page);
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
	lws_box_t box;

	ui->drawing = ui->dirty;
	ui->dirty = 0;

	/*
	 * The strips are bands of whole lines, the title above the list.  If
	 * the display can only take whole updates, it gets everything
	 */

	ui->y0 = 0;
	ui->y1 = (lws_display_scalar)ui->h;
	if (ic->band) {
		if (!(ui->drawing & UI_STRIP_TITLE))
			ui->y0 = (lws_display_scalar)ui->title_h;
		if (!(ui->drawing & UI_STRIP_LIST))
			ui->y1 = (lws_display_scalar)ui->title_h;
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

	if (!info->row)
		return NULL;

	ui = lws_zalloc(sizeof(*ui), __func__);
	if (!ui)
		return NULL;

	ui->i = *info;
	ui->w = ic->wh_px[0].whole;
	ui->h = ic->wh_px[1].whole;
	ui->focus = -1;

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

	if (ui->w < 16 || ui->h < ui->title_h + ui->row_h) {
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

	ui->stale = 1;
	ui->dirty |= UI_STRIP_LIST;
	lws_dlo_ui_kick(ui);
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
	int x, y, dy, top, idx;

	if (lws_json_simple_strcmp(buf, len, "\"type\":", "touch") ||
	    ui_json_int(buf, len, "\"x\":", &x) ||
	    ui_json_int(buf, len, "\"y\":", &y) ||
	    x < 0 || x >= ui->w || y < ui->title_h || y >= ui->h)
		/* only the list does anything with touches */
		return 0;

	if (!lws_json_simple_strcmp(buf, len, "\"event\":", "scroll")) {
		if (ui_json_int(buf, len, "\"dy\":", &dy))
			return 0;

		/* the list follows the finger */

		top = ui->top;
		ui->top -= dy;
		ui_clamp_top(ui);
		if (ui->top == top)
			return 1;

		ui->user_scrolled = 1;
		ui->stale = 1;
		ui->dirty |= UI_STRIP_LIST;
		lws_dlo_ui_kick(ui);

		return 1;
	}

	if (lws_json_simple_strcmp(buf, len, "\"event\":", "press"))
		return 0;

	idx = (y - ui->title_h + ui->top) / ui->row_h;
	if (idx >= ui->count)
		return 0;

	if (ui->i.pick)
		ui->i.pick(ui->i.opaque, idx);

	return 1;
}
