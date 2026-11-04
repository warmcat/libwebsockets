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
 * The caller doesn't write any html: it says what each strip holds, as data,
 * and is told what the user picked.  The ui makes the html itself, lays it
 * out with lhp and renders it with dlo like any other page, and keeps the
 * display list so it can resolve touches against it and redraw a strip on its
 * own.  On a display that can update a band of lines (lws_surface_info_t
 * .band), only the strips that changed are sent to it.
 *
 * It shows one of two pages.  Down the display, the list page has
 *
 *  - a title strip, saying where we are, eg, "Boot", then "AP"
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
 * Each strip moves only by drags that begin in it, and dragging never changes
 * what was typed; only pressing keys does.
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
 *  - #l: the list strip, .r: a row of the list, with .f if it's the focus
 *    row, or .d if it's dim, .i: a row's icon, .x: a row's text
 *  - #e: the edit strip, #et: the box of text in it
 *  - #k: the keyboard strip, .k: a key, with .ks if it is not a letter or
 *    symbol, and .ka if what it changes is on, eg, shift
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
 * The display is the ui's while it exists: nothing else should be browsed on
 * to it meanwhile, since laying the ui out again stops any other document's
 * assets on the context, as lws_lhp_ss_cancel() does.
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
	lws_dlo_ui_done_cb_t		done;
	/**< NULL, or told what was typed on the edit page: needed to use
	 * lws_dlo_ui_edit() */
	const char			*css;
	/**< NULL, or css that follows the ui's own theme, so it can change
	 * how the ui looks, eg, "#t { background-color: #800 }": see the
	 * elements above.  It is copied.  It is the caller's own: it can't
	 * contain '<', and is limited to 2KB */
} lws_dlo_ui_info_t;

#define LWS_DLO_UI_EDIT_MAX		64	/* including the NUL */

#define LWS_DLO_UI_EDIT_MASKED		(1 << 0)
/**< what is typed is shown as stars, eg, a passphrase */

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
 * user scrolled the list meanwhile.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ui_set_list(struct lws_dlo_ui *ui, int count, int focus);

/**
 * lws_dlo_ui_edit() - show the edit page, to type something in
 *
 * \param ui: the ui
 * \param title: what the title strip says while editing, eg, "Passphrase"
 * \param max: the most that can be typed, less than LWS_DLO_UI_EDIT_MAX
 * \param flags: LWS_DLO_UI_EDIT_MASKED, or 0
 *
 * Starts with nothing typed, the lower case layer of the keyboard, and the
 * keyboard centred across its strip.  The done callback is told what was
 * typed, then the list page is shown again; while editing, changes to the
 * list page's title and list are kept until then.
 *
 * What is typed is cleared from the ui's memory when the edit ends, and the
 * html it was shown in, when that is made again.  Returns 0 if editing
 * started, or nonzero if the ui has no done callback or max is out of range.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ui_edit(struct lws_dlo_ui *ui, const char *title, size_t max,
		unsigned int flags);

/**
 * lws_dlo_ui_touch() - give the ui a touch event
 *
 * \param ui: the ui
 * \param buf: the touch smd event's JSON payload, see lws_touch_create()
 * \param len: its length
 *
 * Dragging the list scrolls it, and pressing a row of it calls the pick
 * callback; on the edit page, pressing keys types, dragging moves the edit
 * text or keyboard.  The ui needs the down events, to know which strip a
 * drag began in.  Returns nonzero if the ui acted on the event.
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
