/*
 * lhp grey levels page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A page showing each grey level the display can show, for seeing how evenly
 * spaced they really are, eg, while tuning an EPD's waveform.  It's two rows
 * of equal-width bars, one bar per level, filling what can be seen: the top
 * row goes from black to white, left to right, and the bottom row from white
 * to black.  It has nothing on it but the bars, so it can be photographed and
 * measured by scripts/epd-grey-levels.py.
 *
 * On a greyscale display with a palette, eg, an EPD, there's a bar for each
 * of its palette's levels.  The grey written in the html for each is the one
 * the display turns into exactly that level, so each bar is all one level,
 * not dithered from its neighbours.  Otherwise, it's LHP_GREYS_DEFAULT evenly
 * spaced greys.
 *
 * It's left by pressing anywhere on it, or the settings button.
 */

#if !defined(__LHP_GREYS_UI_H__)
#define __LHP_GREYS_UI_H__

#include <libwebsockets.h>

/* the most levels the page shows */
#define LHP_GREYS_MAX		16

/* how many greys it shows on a display without a greyscale palette */
#define LHP_GREYS_DEFAULT	16

/* the most the page's html can be */
#define LHP_GREYS_HTML_MAX	5120

/**
 * lhp_greys_usable() - is the page any use on this display
 *
 * \param ic: what can be seen of the display, lws_display_state_t .ic
 *
 * It's not on a display with a palette of colours, where the greys would only
 * be dithered from them, or one with more levels than LHP_GREYS_MAX.
 */
int
lhp_greys_usable(const lws_surface_info_t *ic);

/**
 * lhp_greys_html() - write the page's html
 *
 * \param buf: where to write it
 * \param len: its size
 * \param ic: what can be seen of the display, lws_display_state_t .ic
 *
 * Returns the length of the html, or -1 if it didn't fit, or the page isn't
 * usable on the display.
 */
int
lhp_greys_html(char *buf, size_t len, const lws_surface_info_t *ic);

#endif
