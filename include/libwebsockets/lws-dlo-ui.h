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
 * Down the display there are
 *
 *  - a title strip, saying where we are, eg, "Boot", then "AP"
 *
 *  - a list strip, taking the rest of the display: rows of an optional icon
 *    and a line of text, centred.  It scrolls by dragging it, or to keep the
 *    row the caller says is the focus in its middle.  Pressing a row tells the
 *    caller which it was.
 *
 * On a round display (lws_surface_info_t .round), what is in each strip, and
 * each row of the list, is kept to the columns of the circle that can be seen
 * where it is.
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

typedef struct lws_dlo_ui_info {
	struct lws_context		*cx;
	lws_display_state_t		*lds;
	/**< the display the ui is shown on */
	void				*opaque;
	/**< passed to the callbacks */
	lws_dlo_ui_row_cb_t		row;
	/**< fills in the list's rows */
	lws_dlo_ui_pick_cb_t		pick;
	/**< NULL, or told which row of the list was pressed */
} lws_dlo_ui_info_t;

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
 * lws_dlo_ui_touch() - give the ui a touch event
 *
 * \param ui: the ui
 * \param buf: the touch smd event's JSON payload, see lws_touch_create()
 * \param len: its length
 *
 * Dragging the list scrolls it, and pressing a row of it calls the pick
 * callback.  Returns nonzero if the ui acted on the event.
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
