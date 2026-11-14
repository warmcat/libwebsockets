/*
 * lhp edges and touch page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A page for finding out the display's inset, the px at its edges that can't
 * be seen, eg, under a bezel or a touch panel's mask (see lws_display_t
 * .inset), and for seeing if touches land where they are on the display.
 *
 * It's a 1px black line around the edges of what can be seen, inside the
 * inset in use, with a row of controls for each edge: - and + make the inset
 * there a px smaller or bigger, moving the line out or in, with how many px
 * it is between them.  The inset is right when the line is just seen all the
 * way round.  Below them, the size of what can be seen.
 *
 * For the touch panel, there's a target to touch, a cross in a square: a
 * touch that isn't on a control is marked with a dot where the panel says it
 * landed, and measured against it, then the next target is shown.  There are
 * LHP_EDGES_TARGETS of them, near the corners and halfway down the sides: once
 * all are touched, the mean of how far off the touches were, and the worst,
 * are shown, then the next touch starts another round.  If the touches are all
 * off in the same direction, it's the touch panel that's not where the display
 * is.  Each is also logged.
 *
 * The inset found is stored in the settings, and used from then on instead of
 * the board's, see lhp_edges_load().
 */

#if !defined(__LHP_EDGES_UI_H__)
#define __LHP_EDGES_UI_H__

#include <libwebsockets.h>

/* the biggest inset at any edge the page goes to */
#define LHP_EDGES_MAX		64

/* the most the page's html can be */
#define LHP_EDGES_HTML_MAX	4096

/* how many targets there are to touch in a round */
#define LHP_EDGES_TARGETS	6

/* the touches on the page, and how far they were from the targets */

typedef struct lhp_edges {
	int		sx, sy;		/* the last, on the display's surface */
	int		vx, vy;		/* the last, on what can be seen */
	/* how far the touch on each target of the round was from it */
	int		dx[LHP_EDGES_TARGETS], dy[LHP_EDGES_TARGETS];
	uint8_t		touched;	/* there was one */
	uint8_t		inside;		/* the last was on what can be seen */
	uint8_t		off;		/* the last was measured on a target */
	uint8_t		target;		/* the target to touch next */
	uint8_t		measured;	/* how many of the round's were */
} lhp_edges_t;

typedef enum {
	LHP_EDGES_ACT_NONE,
	LHP_EDGES_ACT_CHANGED,		/* the inset was changed */
	LHP_EDGES_ACT_RESET,		/* go back to the board's inset */
	LHP_EDGES_ACT_DONE,		/* finished with the page */
} lhp_edges_act_t;

/**
 * lhp_edges_html() - write the page's html
 *
 * \param buf: where to write it
 * \param len: its size
 * \param ic: what can be seen of the display, lws_display_state_t .ic
 * \param inset: the inset in use, left, top, right, bottom
 * \param e: the touches on it
 *
 * Returns the length of the html, or -1 if it didn't fit.
 */
int
lhp_edges_html(char *buf, size_t len, const lws_surface_info_t *ic,
	       const uint8_t inset[4], const lhp_edges_t *e);

/*
 * Forget the touches, eg, the inset changed, so the targets are somewhere
 * else.  The first target is shown next.
 */
void
lhp_edges_reset(lhp_edges_t *e);

/**
 * lhp_edges_touch() - a touch on the page that wasn't on a control
 *
 * \param e: the touches on it
 * \param ic: what can be seen of the display, lws_display_state_t .ic
 * \param sx: where it was on the display's surface, x
 * \param sy: and y
 * \param vx: where it was on what can be seen, if inside, x
 * \param vy: and y
 * \param inside: it was on what can be seen, not in the inset
 *
 * If it was on what can be seen, it's measured against the target shown,
 * and the next is shown.
 */
void
lhp_edges_touch(lhp_edges_t *e, const lws_surface_info_t *ic, int sx, int sy,
		int vx, int vy, int inside);

/**
 * lhp_edges_href() - a link on the page was pressed
 *
 * \param href: its href, as written
 * \param inset: the inset in use, changed if it's one of the edges' controls
 *
 * Returns what it asks for.  LHP_EDGES_ACT_CHANGED is only returned if the
 * inset was changed, eg, not a - at an edge that's already 0.
 */
lhp_edges_act_t
lhp_edges_href(const char *href, uint8_t inset[4]);

/**
 * lhp_edges_load() - the inset stored in the settings, if any
 *
 * \param cx: the lws context, whose netdevs have the settings
 * \param inset: set to the stored inset
 *
 * Returns 0 if one was stored, or nonzero if not, or it isn't one we could
 * have stored.
 */
int
lhp_edges_load(struct lws_context *cx, uint8_t inset[4]);

/* store the inset in the settings, returning nonzero if it couldn't be */
int
lhp_edges_store(struct lws_context *cx, const uint8_t inset[4]);

#endif
