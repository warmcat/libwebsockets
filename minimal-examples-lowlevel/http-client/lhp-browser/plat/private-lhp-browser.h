/*
 * lhp-browser plat interface
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * Made available under the Creative Commons CC0 1.0 Universal Public Domain
 * Dedication.
 *
 * The app core (main.c) fills a document framebuffer, scrolls a viewport
 * over it, re-browses on window resize and resolves clicks.  A plat/
 * backend only has to put a resizable window on screen, present rectangles
 * of the framebuffer, and forward input events translated to the core's
 * terms.  unix.c implements it with X11; native mac and win32 backends can
 * slot in alongside later.
 */

#if !defined(__PRIVATE_LHP_BROWSER_H__)
#define __PRIVATE_LHP_BROWSER_H__

#include <libwebsockets.h>

/* app core state, defined in main.c */

struct lhp_browser {
	int			doc_h;   /* laid-out document height */
	int			vw, vh;  /* window (viewport) size */
	int			pin_h;   /* 0, or --doc-h layout height cap */
	int			scroll_y;
	int			scan_epoch; /* bumped to restart the viewport scan */
	int			scan_done;  /* the current viewport scan completed */
	int			quitting;
	int			active;

	lws_sorted_usec_list_t	sul_relayout;
	lws_sorted_usec_list_t	sul_scan;
	lws_sorted_usec_list_t	sul_shot;
};

extern struct lhp_browser win;
extern struct lws_context *cx;
extern lws_surface_info_t ic;
extern lws_display_render_state_t drs;

/* logical keys the core understands: plat backends translate their own
 * key events into these */

typedef enum {
	LHPBK_UP,
	LHPBK_DOWN,
	LHPBK_PAGE_UP,
	LHPBK_PAGE_DOWN,
	LHPBK_HOME,
	LHPBK_END,
	LHPBK_QUIT,
} lhp_browser_key_t;

/*
 * Provided by the app core (main.c), called by the plat backend
 */

/* move the viewport by delta document px (negative = up) */
extern void
lhp_browser_scroll(int delta);

/* a click at window coords x,y */
extern void
lhp_browser_click(int x, int y);

/* a logical key press */
extern void
lhp_browser_key(lhp_browser_key_t k);

/* the window changed size (the core debounces the relayout) */
extern void
lhp_browser_resize(int w, int h);

/* window content was lost (exposed): the core re-scans the viewport */
extern void
lhp_browser_repaint(void);

/*
 * Provided by each plat backend (unix.c today; mac / win32 later)
 */

/* create the initial w x h window, nonzero on failure */
extern int
lhp_browser_plat_init(int w, int h);

/*
 * Present one rendered document line at window row wy: the core renders
 * line-by-line into a single line buffer, exactly as it would to an EPD,
 * and there is no framebuffer
 */
extern void
lhp_browser_plat_line(int wy, const uint8_t *rgb, int w);

/* present window rows wy..wy+wh-1 as blank paper */
extern void
lhp_browser_plat_clear(int wy, int wh);

/*
 * Present the staged viewport to the window atomically: lines are staged
 * one at a time as they render (as an EPD line renderer would), and the
 * window shows the new frame in one step, so a partial scan is never
 * sampled mid-update
 */
extern void
lhp_browser_plat_present(void);

/* pump window events until there is nothing immediate to do; nonzero when
 * the app should exit */
extern int
lhp_browser_plat_pump(void);

/* the app core services lws non-blockingly and then sleeps in the backend
 * until window input is possible, or timeout_ms passed: lws itself parks
 * in a days-long poll when it has nothing pending, and the window fd is
 * not in its wait set, so the backend must own the bounded wait */
extern void
lhp_browser_plat_wait(int timeout_ms);

extern void
lhp_browser_plat_destroy(void);

#endif
