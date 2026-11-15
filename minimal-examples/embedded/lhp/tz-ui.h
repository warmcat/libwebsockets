/*
 * lhp time zones, and the page for picking them on a map
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The device knows two time zones: "home", where it is usually, and
 * optionally "away", where it is now, eg, while travelling, so it can show
 * the time in both.  Each is a zone of tzdata, eg, "Europe/London", stored in
 * the settings by its name.  Until a home zone is picked, it's UTC.
 *
 * The zones and their rules are compiled in, from tzdata's zone1970.tab and
 * the POSIX TZ strings of its compiled zones, by contrib/assets/tz/gen-tz.py,
 * and the local time in them is found with lws_tz_local(), not the platform's
 * own time zone support: it's the same on every platform, and both zones can
 * be used at once.
 *
 * The page for picking them is a map of the world, with a dot at the
 * principal city of each zone: pressing on the map picks the zone whose city
 * is nearest.  Below it, a row each for home and away, with the zone and the
 * time there; pressing a row's name makes it the one the map sets, shown
 * black, and pressing "Off" / "On" turns away off and on.  "Done" stores
 * them.  The zones picked are marked on the map, H and A.
 *
 * Like the edges page (edges-ui.h), it's a generated page that's all of what
 * can be seen, and it's pressed on, so it's only offered with a touch panel.
 */

#if !defined(__LHP_TZ_UI_H__)
#define __LHP_TZ_UI_H__

#include <libwebsockets.h>

/* the most the page's html can be */
#define LHP_TZ_HTML_MAX		4096

typedef enum {
	LHP_TZ_HOME,
	LHP_TZ_AWAY,

	LHP_TZ_COUNT
} lhp_tz_which_t;

typedef struct lhp_tz {
	int16_t		zone[LHP_TZ_COUNT];	/* in the table, or -1 */
	uint8_t		picking;		/* lhp_tz_which_t the map sets */
} lhp_tz_t;

typedef enum {
	LHP_TZ_ACT_NONE,
	LHP_TZ_ACT_CHANGED,		/* something on the page changed */
	LHP_TZ_ACT_DONE,		/* finished with the page */
} lhp_tz_act_t;

/*
 * Register the map in the dlo filesystem, and load the zones from the
 * settings, if there are any.  Returns 0, or nonzero if the map couldn't be
 * registered.
 */
int
lhp_tz_init(struct lws_context *cx, lhp_tz_t *t);

/* unregister the map */
void
lhp_tz_deinit(struct lws_context *cx);

/* store the zones in the settings.  Returns 0, or nonzero if it failed */
int
lhp_tz_store(struct lws_context *cx, const lhp_tz_t *t);

/* is there an away zone */
int
lhp_tz_away(const lhp_tz_t *t);

/*
 * The zone's tzdata name, eg, "Europe/London", or "UTC" for a home zone
 * that's not been picked, or NULL for no away zone
 */
const char *
lhp_tz_name(const lhp_tz_t *t, lhp_tz_which_t which);

/*
 * The local time in the zone at utc, eg, "Sun 15 Nov 15:56 JST", or without
 * the day, eg, "15:56 JST".  Returns the length, or -1 if there's no such
 * zone, or it doesn't fit.
 */
int
lhp_tz_format(const lhp_tz_t *t, lhp_tz_which_t which, int64_t utc, int day,
	      char *buf, size_t len);

/**
 * lhp_tz_html() - write the page's html
 *
 * \param buf: where to write it
 * \param len: its size
 * \param ic: what can be seen of the display, lws_display_state_t .ic
 * \param t: the zones
 * \param utc: the time to show in them
 *
 * Returns the length of the html, or -1 if it didn't fit.
 */
int
lhp_tz_html(char *buf, size_t len, const lws_surface_info_t *ic,
	    const lhp_tz_t *t, int64_t utc);

/*
 * A press at x, y on what can be seen, on the page: href is the link that was
 * pressed, if any.  On the map, the zone being picked is set to the nearest.
 */
lhp_tz_act_t
lhp_tz_press(const lws_surface_info_t *ic, lhp_tz_t *t, const char *href,
	     int x, int y);

#endif
