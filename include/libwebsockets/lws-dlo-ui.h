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
 * Strip ui: a finished user interface for small displays, made of
 * horizontal strips stacked down the display, each clipped to itself.
 *
 * For the list and edit pages, the caller doesn't write any html: it says what
 * each strip holds, as data, and is told what the user picked.  The ui makes the html itself, lays it
 * out with lhp and renders it with dlo like any other page, and keeps the
 * display list so it can resolve touches against it and redraw a strip on its
 * own.  On a display that can update a band of lines (lws_surface_info_t
 * .band), only the strips that changed are sent to it.
 *
 * It shows one of four pages.  Down the display, the list page has
 *
 *  - a title strip, saying where we are, eg, "Boot", then "AP".  Pressing it
 *    tells the caller, if it wants to know.
 *
 *  - a list strip, taking the rest of the display: rows of an optional icon
 *    and a line of text, centred.  It scrolls by dragging it, or to keep the
 *    row the caller says is the focus in its middle.  Pressing a row tells the
 *    caller which it was.
 *
 * and the edit page, shown by lws_dlo_ui_edit(), has
 *
 *  - the title strip, saying what is being typed, eg, "Passphrase".  Pressing
 *    it abandons the edit.
 *
 *  - an edit strip, showing what was typed, or as many stars if it is masked,
 *    and a caret.  If it is too long to show, the end is shown: dragging the
 *    strip sideways shows the rest.
 *
 *  - a keyboard strip, taking the rest of the display.  The keyboard is
 *    owned by the ui: it has lower and upper case and symbol layers, with a
 *    key to shift the next letter, to change layer, to delete, and Done.  If
 *    what is typed is masked, a key shows it until it is pressed again.  The
 *    keyboard is bigger than a small display: it is dragged around in its
 *    strip to reach the keys.
 *
 * and the frame page, shown by lws_dlo_ui_frame(), has
 *
 *  - the title strip, eg, saying which page of the application it is
 *
 *  - below it, the body: the rest of the display is the caller's, to show
 *    its own content in, eg, a page browsed with lhp.  The ui doesn't draw
 *    it: the caller lays its content out on the surface the body is, see
 *    lws_dlo_ui_frame_body(), and draws the whole display, getting the lines
 *    of the title strip from the ui with lws_dlo_ui_frame_line().
 *
 * and the dialog page, shown by lws_dlo_ui_dialog(), has
 *
 *  - the title strip, saying what the dialog is, eg, "Settings".  Pressing it
 *    tells the caller, eg, to close the dialog.
 *
 *  - below it, the panel: html the caller writes, eg, a table and some
 *    editable fields, laid out across what can be seen of the display.  If it
 *    is taller than that, dragging it scrolls it, up to 8 displays' worth;
 *    any more isn't laid out.  Each <a href="..."> in it
 *    is something to press: pressing it tells the caller the href, which is
 *    the caller's own, eg, "ap:3" or "edit:hostname".  The caller writes the
 *    html again whenever what it shows changes, eg, a list kept up to date.
 *    So a dialog of the application's own needs only the html, and what to do
 *    for each href; editing a field is the edit page, which comes back to the
 *    dialog when it ends.
 *
 * Each strip moves only by drags that begin in it, and dragging never changes
 * what was typed; only pressing keys does.
 *
 * On every page, the title strip can show a capsule at its right end, with
 * small icons saying how the system is, eg, how strong the wlan signal is and
 * how charged the battery is, see lws_dlo_ui_set_status().  Pressing it is
 * like pressing a button: the ui issues an interaction event for it, see
 * lws_dlo_ui_info_t .status_button, so a physical button and the capsule can
 * do the same thing, eg, open the settings.
 *
 * The ui can be used with buttons, or anything else that can say which way
 * to go, instead of touch: see lws_dlo_ui_nav().  A cursor then shows which
 * row of the list, which key of the keyboard, or which link of a dialog,
 * ENTER will press.
 *
 * On a round display (lws_surface_info_t .round), what is in each strip, and
 * each row of the list, is kept to the columns of the circle that can be seen
 * where it is.
 *
 * How it looks is set by css, which the caller may add to, see
 * lws_dlo_ui_info_t .css.  The elements it can style are
 *
 *  - #ui: the whole display
 *  - #t: the title strip, #tt: its text
 *  - #s: the status capsule, .sb: a bar of the wlan icon, with .so if it is
 *    lit, #sbo: the battery icon's outline, #sbn: its nub, #sbi: its
 *    inside, #sbf: how charged it is, or #sbc instead if it is charging
 *  - #l: the list strip, .r: a row of the list, with .f if it's the focus
 *    row, or .d if it's dim, and .c if the cursor is on it, .i: a row's icon,
 *    .x: a row's text
 *  - #e: the edit strip, #et: the box of text in it
 *  - #k: the keyboard strip, .k: a key, with .ks if it is not a letter or
 *    symbol, .ka if what it changes is on, eg, shift, and .kc if the cursor
 *    is on it
 *  - #p: the dialog's panel, #pc: the caller's html in it, which the caller
 *    styles with its own css, see lws_dlo_ui_dialog_t .css
 *
 * The positions and sizes of these follow from the display, and are set by
 * the ui after the caller's css, so css can't change them; colours, borders
 * and the like are its to set.
 *
 * The ui uses the display while it draws: it sets lds->display_busy, and as
 * with any other update, the display's completion callback clears it when the
 * update is finished.  It should then call lws_dlo_ui_kick(), so anything that
 * changed meanwhile is drawn.  The ui only uses the faces built in, so it can
 * be shown before there is any network.
 *
 * While the list, edit or dialog page is shown, the display is the ui's: nothing else
 * should be drawn on it meanwhile.  While the frame page is shown, the body is
 * the caller's, and the ui only draws the title strip by itself, when it
 * changed and the display can take a band of lines.  Laying the ui out again
 * only stops its own document, so the caller's content can still be arriving
 * while it is.
 */

#if !defined(__LWS_DLO_UI_H__)
#define __LWS_DLO_UI_H__

struct lws_dlo_ui;

typedef enum {
	LWS_DLO_UI_ROW_NORMAL,
	LWS_DLO_UI_ROW_DIM,	/* eg, not reached yet, or not available */
	LWS_DLO_UI_ROW_FOCUS,	/* highlighted, and scrolled to the middle of
				 * the list, unless the user has scrolled it */
} lws_dlo_ui_row_state_t;

#define LWS_DLO_UI_ROW_TEXT_MAX		64

typedef struct lws_dlo_ui_row {
	const char		*icon;
	/**< NULL, or the name of an image in the dlo filesystem, eg,
	 * "boot-1-setup.svg", that must stay registered while the ui exists */
	char			text[LWS_DLO_UI_ROW_TEXT_MAX];
	/**< the row's line of text, as text: it may come from anywhere, eg,
	 * an SSID anyone nearby can choose, and is never taken as markup */
	uint8_t			state;
	/**< lws_dlo_ui_row_state_t */
} lws_dlo_ui_row_t;

/*
 * Fill in row idx of the list, which arrives zeroed.  Return nonzero if there
 * is no such row any more: it is left out.
 */
typedef int (*lws_dlo_ui_row_cb_t)(void *opaque, int idx,
				   lws_dlo_ui_row_t *row);

/* row idx of the list was pressed */
typedef void (*lws_dlo_ui_pick_cb_t)(void *opaque, int idx);

/* the title strip of the list or frame page was pressed */
typedef void (*lws_dlo_ui_title_cb_t)(void *opaque);

/*
 * The frame page's title strip changed, on a display that can only take an
 * update of all of it: the caller should draw the whole display again, eg,
 * its body as it was, when it can.  See lws_dlo_ui_info_t .frame_redraw
 */
typedef void (*lws_dlo_ui_frame_redraw_cb_t)(void *opaque);

/*
 * Done was pressed on the edit page: text is what was typed.  Or the title
 * was pressed, abandoning the edit: text is NULL.
 *
 * Return 0 when it is finished with: the list page is shown again, and what
 * was typed is cleared from memory.  Returning nonzero after Done keeps it
 * being edited, eg, if it isn't acceptable; after abandoning, the edit ends
 * anyway.  text may be a secret: copy what's needed and don't log it.
 *
 * It is called from inside lws_dlo_ui_touch(): it may call the other apis on
 * the ui, eg, to edit something else, but not destroy it.
 */
typedef int (*lws_dlo_ui_done_cb_t)(void *opaque, const char *text);

/*
 * Writing the html of a dialog's panel, see lws_dlo_ui_dialog_t .html: the
 * caller's markup with lws_html_w_printf(), and anything that isn't the
 * caller's own, eg, an SSID, with lws_html_w_text(), which escapes it.  If
 * the html becomes longer than lws_dlo_ui_dialog_t .html_max, the rest isn't
 * written, and the panel isn't shown.
 */
typedef lws_html_w_t lws_dlo_ui_html_t;

/* write the panel's html, see lws_dlo_ui_dialog() */
typedef void (*lws_dlo_ui_dialog_html_cb_t)(void *opaque, lws_dlo_ui_html_t *h);

/*
 * The link to href was pressed on the dialog's panel.  As for done, it may
 * call the other apis, eg, to edit something, or close the dialog by
 * showing another page, but not destroy the ui.
 */
typedef void (*lws_dlo_ui_dialog_action_cb_t)(void *opaque, const char *href);

typedef struct lws_dlo_ui_info {
	struct lws_context		*cx;
	lws_display_state_t		*lds;
	/**< the display the ui is shown on */
	void				*opaque;
	/**< passed to the callbacks */
	lws_dlo_ui_row_cb_t		row;
	/**< fills in the list's rows */
	lws_dlo_ui_pick_cb_t		pick;
	/**< NULL, or told which row of the list was pressed.  As for done,
	 * it may call the other apis, but not destroy the ui */
	lws_dlo_ui_title_cb_t		title;
	/**< NULL, or told the title strip of the list or frame page was
	 * pressed, or ESC was given on the list page (lws_dlo_ui_nav()), eg,
	 * to go back, or to show another list.  As for pick, it may call the
	 * other apis, but not destroy the ui */
	lws_dlo_ui_done_cb_t		done;
	/**< NULL, or told what was typed on the edit page: needed to use
	 * lws_dlo_ui_edit() */
	lws_dlo_ui_frame_redraw_cb_t	frame_redraw;
	/**< NULL, or told the frame page's title strip changed, eg, its
	 * status, on a display that can't take a band of lines, which isn't
	 * bistable: see lws_dlo_ui_frame().  If NULL, the change is drawn
	 * with the caller's next update of the display */
	const char			*css;
	/**< NULL, or css that follows the ui's own theme, so it can change
	 * how the ui looks, eg, "#t { background-color: #800 }": see the
	 * elements above.  It is copied.  It is the caller's own: it can't
	 * contain '<', and is limited to 2KB */
	const char			*status_button;
	/**< NULL, or the name of the button the status capsule is, eg,
	 * "settings": pressing the capsule issues a LWSSMDCL_INTERACTION
	 * event, as a button of that name being clicked does, see
	 * lws-button.h, from "ui": {"type":"button","src":"ui/settings",
	 * "event":"click"}.  It is copied: up to 15 of a-z, 0-9, '-' or '_' */
} lws_dlo_ui_info_t;

/*
 * What the status capsule shows: see lws_dlo_ui_set_status().  The ui only
 * draws it again when what is shown changes, eg, the battery icon shows its
 * charge in quarters, so a percent less doesn't redraw it
 */

#define LWS_DLO_UI_STATUS_NONE		-1	/* the icon isn't shown */
#define LWS_DLO_UI_WLAN_BARS		4	/* the most bars the wlan has */

typedef struct lws_dlo_ui_status {
	int8_t				wlan;
	/**< LWS_DLO_UI_STATUS_NONE, 0 if it isn't associated, or how strong
	 * its signal is, 1 to LWS_DLO_UI_WLAN_BARS */
	int8_t				battery;
	/**< LWS_DLO_UI_STATUS_NONE if there's no battery, or how charged it
	 * is, 0 to 100 percent */
	uint8_t				charging;
	/**< the battery is being charged */
} lws_dlo_ui_status_t;

/* which way to go, eg, from buttons, see lws_dlo_ui_nav() */

typedef enum {
	LWS_DLO_UI_NAV_UP,
	LWS_DLO_UI_NAV_DOWN,
	LWS_DLO_UI_NAV_LEFT,
	LWS_DLO_UI_NAV_RIGHT,
	LWS_DLO_UI_NAV_ENTER,
	LWS_DLO_UI_NAV_ESC,
} lws_dlo_ui_nav_t;

/* lws_dlo_ui_frame() flags */

#define LWS_DLO_UI_FRAME_DRAW		(1 << 0)
/**< the ui draws all of the display now, the body white, eg, to show the
 * frame at once while the caller's content isn't ready yet */

#define LWS_DLO_UI_EDIT_MAX		64	/* including the NUL */

#define LWS_DLO_UI_EDIT_MASKED		(1 << 0)
/**< what is typed is shown as stars, eg, a passphrase */
#define LWS_DLO_UI_EDIT_KEEP		(1 << 1)
/**< leaving the edit any way, eg, pressing the title, or another page being
 * shown, gives the done callback what was typed, as Done does, instead of
 * NULL: eg, for a setting whose changes should stick however the user goes
 * on.  Its return is ignored then: the edit ends anyway.  Not for secrets */

/* what a dialog page shows, see lws_dlo_ui_dialog() */

typedef struct lws_dlo_ui_dialog {
	lws_dlo_ui_dialog_html_cb_t	html;
	/**< writes the panel's html, each time it's laid out */
	lws_dlo_ui_dialog_action_cb_t	action;
	/**< told the href of a link pressed on the panel */
	void				*opaque;
	/**< passed to .html and .action, eg, the dialog's own state, which
	 * may not be the ui's creator's */
	const char			*css;
	/**< NULL, or css for the panel's html, after the ui's.  It is copied.
	 * It is the caller's own: it can't contain '<', and is limited to 2KB */
	size_t				html_max;
	/**< the most the panel's html can be, or 0 for 4KB: if what .html
	 * writes is longer, it isn't shown */
} lws_dlo_ui_dialog_t;

/**
 * lws_dlo_ui_create() - make a strip ui on a display
 *
 * \param info: what the ui is shown on, and the callbacks: copied
 *
 * The ui is empty, and nothing is drawn, until it is given a title or list.
 * The display must stay valid until the ui is destroyed.
 *
 * Returns the ui, or NULL on OOM.
 */
LWS_VISIBLE LWS_EXTERN struct lws_dlo_ui *
lws_dlo_ui_create(const lws_dlo_ui_info_t *info);

/**
 * lws_dlo_ui_destroy() - stop and free a strip ui
 *
 * \param pui: pointer to the ui, set to NULL
 *
 * Stops any layout or drawing it was doing, and frees everything it holds.
 * What it last drew stays on the display.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_destroy(struct lws_dlo_ui **pui);

/**
 * lws_dlo_ui_set_title() - set what the title strip says
 *
 * \param ui: the ui
 * \param title: the title, as text, copied: it is cut off if it is too long
 *
 * It is drawn when the display is next free, if it changed.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_set_title(struct lws_dlo_ui *ui, const char *title);

/**
 * lws_dlo_ui_set_list() - say the list has changed
 *
 * \param ui: the ui
 * \param count: how many rows the list has now
 * \param focus: the row to keep in the middle of the list, or -1
 *
 * The rows are asked for again from the row callback, and the list is drawn
 * when the display is next free.  A new focus row is scrolled to even if the
 * user scrolled the list meanwhile.  If the frame or dialog page is shown,
 * the list page is shown instead.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_set_list(struct lws_dlo_ui *ui, int count, int focus);

/**
 * lws_dlo_ui_edit() - show the edit page, to type something in
 *
 * \param ui: the ui
 * \param title: what the title strip says while editing, eg, "Passphrase"
 * \param max: the most that can be typed, less than LWS_DLO_UI_EDIT_MAX
 * \param flags: LWS_DLO_UI_EDIT_MASKED, LWS_DLO_UI_EDIT_KEEP, or 0
 *
 * Starts with nothing typed, the lower case layer of the keyboard, and the
 * keyboard centred across its strip.  The done callback is told what was
 * typed, then the page it was edited from, the list or a dialog, is shown
 * again; while editing, changes to the list page's title and list, or the
 * dialog's html, are kept until then.
 *
 * What is typed is cleared from the ui's memory when the edit ends, and the
 * html it was shown in, when that is made again.  Returns 0 if editing
 * started, or nonzero if the ui has no done callback or max is out of range.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_edit(struct lws_dlo_ui *ui, const char *title, size_t max,
		unsigned int flags);

/**
 * lws_dlo_ui_edit_set() - replace what has been typed on the edit page
 *
 * \param ui: the ui, which is editing
 * \param text: what to show as typed, eg, the hostname being changed, copied
 *
 * Call after lws_dlo_ui_edit(), so the edit starts with something already
 * there to change.  Don't give it secrets: they would be shown until
 * deleted.  Returns 0 if it was set, or nonzero if the ui isn't editing, or
 * text is longer than the edit's max.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_edit_set(struct lws_dlo_ui *ui, const char *text);

/**
 * lws_dlo_ui_edit_abandon() - end an edit, as pressing the title would
 *
 * \param ui: the ui
 *
 * If the ui is editing, the done callback is told it was abandoned: with
 * what was typed if it was started with LWS_DLO_UI_EDIT_KEEP, otherwise
 * NULL.  Then the page it was edited from is shown again, unless the done
 * callback started another edit.  Eg, a dialog being closed while one of its
 * fields is being edited ends the edit first, so it's kept.  Returns 0 if
 * an edit was abandoned, or nonzero if the ui wasn't editing.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_edit_abandon(struct lws_dlo_ui *ui);

/**
 * lws_dlo_ui_dialog() - show the dialog page: the title strip over html
 *
 * \param ui: the ui
 * \param d: what the dialog shows, and the callbacks: copied
 *
 * Shows the title strip, saying the title, see lws_dlo_ui_set_title(), over
 * the panel, whose html d->html writes inside a div, so it can be a fragment,
 * eg, a <table> and some <div>s.  Each <a href="..."> in it can be pressed,
 * or reached with the cursor (lws_dlo_ui_nav()), and d->action is told its
 * href.  It's started at the top; an edit in progress is abandoned, as
 * pressing its title would.
 *
 * A dialog can edit a field with lws_dlo_ui_edit() when one of its links is
 * pressed: when the edit ends, the dialog is shown again.  Showing another
 * page, eg, with lws_dlo_ui_frame() or lws_dlo_ui_set_list(), closes it.
 *
 * Returns 0 if it's shown, or nonzero if d has no html callback, or its css
 * is refused, or OOM.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_dialog(struct lws_dlo_ui *ui, const lws_dlo_ui_dialog_t *d);

/**
 * lws_dlo_ui_dialog_changed() - what the dialog shows changed
 *
 * \param ui: the ui
 *
 * The panel's html is written again, laid out and drawn when the display is
 * next free, eg, as a list it shows changes.  Where it was scrolled to, and
 * which link the cursor is on, are kept.  If it is being edited from, it's
 * written again when it is shown again anyway.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_dialog_changed(struct lws_dlo_ui *ui);

/**
 * lws_dlo_ui_frame() - show the frame page, the title strip over a body
 *
 * \param ui: the ui
 * \param flags: LWS_DLO_UI_FRAME_DRAW, or 0
 *
 * Shows the title strip, saying the list page's title, see
 * lws_dlo_ui_set_title(), over the caller's own content.  An edit in progress
 * is abandoned, as pressing its title would.
 *
 * The caller lays its content out on the surface lws_dlo_ui_frame_body()
 * gives, and draws the whole display itself, taking the lines of the title
 * strip from lws_dlo_ui_frame_line().  With LWS_DLO_UI_FRAME_DRAW, the ui
 * draws the whole display itself now, with the body white, when the display
 * is next free.
 *
 * When the title or the status changes while the frame is shown, the ui draws
 * the title strip again by itself on a display that can take a band of lines.
 * On a bistable display, eg, an EPD that takes seconds for an update, it's
 * drawn with the caller's next update of the display.  Otherwise the
 * info's frame_redraw callback is told, to draw the whole display again.
 *
 * Going back to the list page, with lws_dlo_ui_set_list(), or editing, with
 * lws_dlo_ui_edit(), takes the whole display again.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_frame(struct lws_dlo_ui *ui, unsigned int flags);

/**
 * lws_dlo_ui_frame_body() - the surface the frame's body is
 *
 * \param ui: the ui
 * \param y: set to how far down the display the body starts, or NULL
 *
 * Returns the surface the caller lays its content out on, and renders it to:
 * as wide as the display, as tall as what is below the title strip, and as
 * many pixels to the mm.  Its line y is line y + *y on the display.  On a
 * round display, it's round too, with .round_top saying it's the part of the
 * circle below the title strip, so lws_display_render_pan() lets a page in it
 * be moved to bring what is in the corners the circle cuts off into view.
 * It's valid while the ui exists.
 */
LWS_VISIBLE LWS_EXTERN const lws_surface_info_t *
lws_dlo_ui_frame_body(struct lws_dlo_ui *ui, int *y);

/**
 * lws_dlo_ui_frame_line() - render a line of the frame's title strip
 *
 * \param ui: the ui, showing the frame page
 * \param y: the line of the display, above the body
 * \param line: where to render it, a line of the display's pixels, as the
 *		display's lws_display_render_state_t .line is
 *
 * For the caller drawing the whole display while the frame page is shown,
 * for the lines above the body.  Call it for each, from the first, then the
 * body's: the title strip isn't laid out again until the last has been.
 *
 * Returns LWS_SRET_OK when the line is rendered, or LWS_SRET_WANT_INPUT if
 * the title strip isn't laid out yet, eg, it just changed, or LWS_SRET_YIELD
 * if it isn't finished: call it for the same line again a little later.
 * LWS_SRET_FATAL means it can't be rendered, eg, the frame isn't shown.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_dlo_ui_frame_line(struct lws_dlo_ui *ui, int y, uint8_t *line);

/**
 * lws_dlo_ui_set_status() - say what the status capsule shows
 *
 * \param ui: the ui
 * \param status: what to show, copied, or NULL for no capsule
 *
 * The capsule is at the right end of the title strip, on a round display at
 * the right end of the part of it that can be seen.  It's drawn again when the
 * display is next free, if what it shows changed.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_set_status(struct lws_dlo_ui *ui, const lws_dlo_ui_status_t *status);

/**
 * lws_dlo_ui_nav() - move the cursor, or press what it is on
 *
 * \param ui: the ui
 * \param nav: which way to go
 *
 * For using the ui with buttons, or anything else that can say which way, eg,
 * a rotary encoder.  The first time, a cursor is shown, on the focus row of
 * the list, or else the first that can be seen, or on the keyboard's first
 * key, without doing anything else.  It shows, on whichever page, until the ui
 * is touched: an edit started meanwhile has it on its first key, in view.
 *
 * On the list page, UP and DOWN move the cursor, scrolling the list to keep it
 * in view; ENTER picks its row, and ESC is like pressing the title.  On the
 * edit page, the arrows move the cursor across the keys, moving the keyboard
 * to keep it in view; ENTER presses its key, and ESC abandons the edit.  On
 * the dialog page, LEFT and RIGHT move the cursor to the link before or after
 * it in the html, UP and DOWN to the nearest link above or below it,
 * scrolling the panel to keep it in view; ENTER presses its link, and ESC is
 * like pressing the title.  On the frame page, nothing is the ui's.
 *
 * Returns nonzero if the ui acted on it, else 0, eg, LEFT on the list page,
 * so the caller can do something else with it.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_nav(struct lws_dlo_ui *ui, lws_dlo_ui_nav_t nav);

/**
 * lws_dlo_ui_interaction() - give the ui an interaction event
 *
 * \param ui: the ui
 * \param buf: the LWSSMDCL_INTERACTION smd event's JSON payload
 * \param len: its length
 *
 * Touches go to lws_dlo_ui_touch().  Clicks of buttons named "up", "down",
 * "left", "right", "enter" and "esc", whatever issued them, eg,
 * {"type":"button","src":"bc/up","event":"click"}, go to lws_dlo_ui_nav().
 * So a caller can give it every interaction event, whether the board has a
 * touch panel or buttons.  Returns nonzero if the ui acted on the event.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_interaction(struct lws_dlo_ui *ui, const void *buf, size_t len);

/**
 * lws_dlo_ui_touch() - give the ui a touch event
 *
 * \param ui: the ui
 * \param buf: the touch smd event's JSON payload, see lws_touch_create()
 * \param len: its length
 *
 * Dragging the list scrolls it, and pressing a row of it calls the pick
 * callback; on the edit page, pressing keys types, dragging moves the edit
 * text or keyboard.  On the dialog page, dragging the panel scrolls it, and
 * pressing a link calls the action callback.  Pressing the status capsule,
 * or the title strip from a little before it to its right end, issues its
 * button event; on a small display, where the capsule takes much of the
 * strip, that's from the middle of the strip rightward.
 * The ui needs the down events, to know which strip a drag began in.  On the
 * frame page, touches on the body are not the ui's: they are the caller's to
 * act on, at y less how far down the body starts.  Returns nonzero if the ui
 * acted on the event.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_touch(struct lws_dlo_ui *ui, const void *buf, size_t len);

/**
 * lws_dlo_ui_kick() - the display may be free again
 *
 * \param ui: the ui
 *
 * Call from the display's completion callback when an update finished, so
 * anything about the ui that changed while the display was busy is drawn.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_kick(struct lws_dlo_ui *ui);

#endif
