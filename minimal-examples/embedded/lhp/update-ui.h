/*
 * lhp firmware update progress page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * While an update is downloaded, the display shows a page titled "Updating"
 * in a strip like the boot overlay's (lws-dlo-ui.h), what is being updated,
 * and a bar filling up with how much of it has arrived.  Everything on it is
 * placed for the display it is shown on, so on a round display it is all
 * inside the circle.
 *
 * Nothing here is platform-specific: the caller says what display it is for,
 * and shows the html however it shows pages.
 */

#if !defined(__LHP_UPDATE_UI_H__)
#define __LHP_UPDATE_UI_H__

#include <libwebsockets.h>

/* the example's colours, for its title strips, as css colours */
#define LHP_UI_STRIP_BG		"#1a5c3a"
#define LHP_UI_STRIP_FG		"#ffe680"

/* the name the update icon is registered with in the dlo filesystem */
#define LHP_UPDATE_ICON		"update-icon.png"
/* ... and its size in px, it's drawn smaller if it doesn't fit */
#define LHP_UPDATE_ICON_PX	96

/*
 * lhp_update_html() - the html of the update page
 *
 * \param buf: where to write it
 * \param len: the size of buf
 * \param ic: the display it's for
 * \param variant: what is being updated, eg, lws_ota_variant_name(), or NULL
 * \param pc: how much of the update has arrived, in percent
 *
 * Returns the length of the html, or -1 if it didn't fit in buf.
 */
int
lhp_update_html(char *buf, size_t len, const lws_surface_info_t *ic,
		const char *variant, int pc);

#endif
