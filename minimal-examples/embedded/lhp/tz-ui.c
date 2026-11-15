/*
 * lhp time zones, and the page for picking them on a map
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See tz-ui.h
 */

#include "tz-ui.h"
#include <string.h>
#include <math.h>

#if !defined(M_PI)
#define M_PI			3.14159265358979323846
#endif

#include "boot-icons.h"

typedef struct {
	const char	*name;	/* tzdata's, eg, "Europe/London" */
	int16_t		lat;	/* of its principal city, in 1/100 degree */
	int16_t		lon;
	const char	*tz;	/* POSIX TZ string */
} zone_t;

/* made by contrib/assets/tz/gen-tz.py, which also made the map */

static const zone_t zones[] = {
#include "tz-zones.h"
};

#define MAP_NAME		"tz-map.svg"

/* how they're stored in the settings: the zone's name, or "-" for none */
static const char * const setting[] = { "lhp.tz.home", "lhp.tz.away" };

/* the longest tzdata zone name is 30 */
#define NAME_MAX_LEN		40

static int
clamp(int v, int lo, int hi)
{
	return v < lo ? lo : (v > hi ? hi : v);
}

static lws_settings_instance_t *
settings(struct lws_context *cx)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(cx);

	return nds ? nds->si : NULL;
}

static int
zone_by_name(const char *name)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(zones); n++)
		if (!strcmp(zones[n].name, name))
			return (int)n;

	return -1;
}

int
lhp_tz_init(struct lws_context *cx, lhp_tz_t *t)
{
	lws_settings_instance_t *si = settings(cx);
	char name[NAME_MAX_LEN + 1];
	lws_dlo_filesystem_t f;
	size_t l;
	int n;

	memset(t, 0, sizeof(*t));

	for (n = 0; n < LHP_TZ_COUNT; n++) {
		t->zone[n] = -1;

		/* what is stored is untrusted until we see it is a zone we have */
		l = sizeof(name) - 1;
		if (!si || si->so->get(si, setting[n], (uint8_t *)name, &l) ||
		    l >= sizeof(name))
			continue;
		name[l] = '\0';
		t->zone[n] = (int16_t)zone_by_name(name);
	}

	memset(&f, 0, sizeof(f));
	f.name = MAP_NAME;
	f.data = tz_map;
	f.len = sizeof(tz_map);

	return !lws_dlo_file_register(cx, &f);
}

void
lhp_tz_deinit(struct lws_context *cx)
{
	lws_dlo_file_unregister_by_name(cx, MAP_NAME);
}

int
lhp_tz_store(struct lws_context *cx, const lhp_tz_t *t)
{
	lws_settings_instance_t *si = settings(cx);
	const char *name;
	int n;

	if (!si)
		return 1;

	for (n = 0; n < LHP_TZ_COUNT; n++) {
		name = t->zone[n] < 0 ? "-" : zones[t->zone[n]].name;
		if (si->so->set(si, setting[n], (const uint8_t *)name,
				strlen(name)))
			return 1;
	}

	return 0;
}

int
lhp_tz_away(const lhp_tz_t *t)
{
	return t->zone[LHP_TZ_AWAY] >= 0;
}

const char *
lhp_tz_name(const lhp_tz_t *t, lhp_tz_which_t which)
{
	if (t->zone[which] >= 0)
		return zones[t->zone[which]].name;

	return which == LHP_TZ_HOME ? "UTC" : NULL;
}

int
lhp_tz_format(const lhp_tz_t *t, lhp_tz_which_t which, int64_t utc, int day,
	      char *buf, size_t len)
{
	static const char * const wd[] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char * const mn[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	const char *tz;
	lws_tz_info_t i;
	lws_civil_t c;
	int n;

	if (t->zone[which] >= 0)
		tz = zones[t->zone[which]].tz;
	else if (which == LHP_TZ_HOME)
		tz = "UTC0";
	else
		return -1;

	if (lws_tz_local(tz, utc, &c, &i))
		return -1;

	if (day)
		n = lws_snprintf(buf, len, "%s %d %s %02d:%02d %s",
				 wd[c.wday], c.day, mn[c.mon - 1], c.hour,
				 c.min, i.abbr);
	else
		n = lws_snprintf(buf, len, "%02d:%02d %s", c.hour, c.min,
				 i.abbr);

	return (size_t)n >= len - 1 ? -1 : n;
}

/*
 * Where things are on the page: the map is as big as it can be across the
 * top, with the rows for home, away, and Done below it
 */

typedef struct {
	int		w, h;		/* what can be seen */
	int		bs;		/* a row's height */
	int		fs;		/* the font's */
	int		tl;		/* a line of text's height */
	int		gap;
	int		bw;		/* a button's width */
	int		mx, my, mw, mh;	/* the map */
	int		ry;		/* the first row */
} layout_t;

static void
layout(const lws_surface_info_t *ic, layout_t *z)
{
	int rows;

	z->w = ic->wh_px[0].whole;
	z->h = ic->wh_px[1].whole;
	z->bs = clamp(z->h / 10, 16, 56);
	z->fs = clamp((z->bs * 3) / 5, 10, 24);
	z->tl = (z->fs * 6) / 5;
	z->gap = clamp(z->bs / 6, 2, 8);
	z->bw = z->fs * 4;

	rows = 3 * (z->bs + z->gap);

	z->mw = z->w;
	z->mh = (z->mw * TZ_MAP_H) / TZ_MAP_W;
	if (z->mh > z->h - rows - z->gap) {
		z->mh = z->h - rows - z->gap;
		if (z->mh < 1)
			z->mh = 1;
		z->mw = (z->mh * TZ_MAP_W) / TZ_MAP_H;
	}
	z->mx = (z->w - z->mw) / 2;
	z->my = 0;
	z->ry = z->my + z->mh + z->gap;
}

/* where a zone's city is on the map, on the page */

static void
zone_xy(const layout_t *z, int idx, int *x, int *y)
{
	*x = z->mx + (int)(((int32_t)zones[idx].lon + 18000) * z->mw / 36000);
	*y = z->my + (int)(((TZ_MAP_LAT_TOP * 100) - (int32_t)zones[idx].lat) *
			   z->mh / ((TZ_MAP_LAT_TOP - TZ_MAP_LAT_BOT) * 100));
}

/* the zone whose city is nearest the point, in 1/100 degree */

static int
nearest(int lat, int lon)
{
	double best = 1e30, cl = cos((double)lat * M_PI / 18000.0), d, dx, dy;
	int n, b = -1;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(zones); n++) {
		dx = fabs((double)(zones[n].lon - lon));
		if (dx > 18000.0)
			dx = 36000.0 - dx; /* the other way round the earth */
		dx *= cl;
		dy = (double)(zones[n].lat - lat);
		d = (dx * dx) + (dy * dy);
		if (d < best) {
			best = d;
			b = n;
		}
	}

	return b;
}

int
lhp_tz_html(char *buf, size_t len, const lws_surface_info_t *ic,
	    const lhp_tz_t *t, int64_t utc)
{
	static const char * const label[] = { "Home", "Away" };
	static const char * const mark[] = { "H", "A" };
	int n, x, y, pad, ms, tx;
	char tm[32];
	lws_html_w_t hw;
	layout_t z;

	layout(ic, &z);
	pad = (z.bs - z.tl) / 2 > 0 ? (z.bs - z.tl) / 2 : 0;
	ms = z.tl;
	tx = z.bw + z.gap;

	lws_html_w_init(&hw, buf, len);

	lws_html_w_printf(&hw, "<html><head><style>"
		"* { margin: 0; padding: 0 }"
		"body { font-family: sun; font-size: %dpx;"
		" background-color: #fff; color: #000 }"
		".p, .r, a, .x, .m { position: absolute }"
		".p { left: %dpx; top: %dpx; width: %dpx; height: %dpx }"
		"img { display: block; width: %dpx; height: %dpx }"
		".r { left: 0; width: %dpx; height: %dpx }"
		"a { display: block; top: 0; height: %dpx; padding-top: %dpx;"
		" text-align: center; text-decoration: none;"
		" border: 2px solid #000; background-color: #fff;"
		" color: #000 }"
		"a.k { background-color: #000; color: #fff }"
		".n { left: 0; width: %dpx } .o { left: %dpx; width: %dpx }"
		".x { left: %dpx; top: %dpx; width: %dpx; height: %dpx;"
		" white-space: nowrap; overflow: hidden }"
		".m { width: %dpx; height: %dpx; border: 1px solid #000;"
		" background-color: #fff; text-align: center;"
		" font-size: %dpx }",
		z.fs,
		z.mx, z.my, z.mw, z.mh,
		z.mw, z.mh,
		z.w, z.bs,
		z.bs - pad - 4, pad,
		z.bw - 4, z.w - z.bw, z.bw - 4,
		tx, pad, z.w - (2 * tx), z.tl,
		ms - 2, ms - 2, (z.fs * 4) / 5);

	for (n = 0; n < 3; n++)
		lws_html_w_printf(&hw, "#r%d { top: %dpx }", n,
				  z.ry + n * (z.bs + z.gap));
	lws_html_w_printf(&hw, "#d { left: %dpx; width: %dpx }",
			  (z.w - (2 * z.bw)) / 2, (2 * z.bw) - 4);

	/* the zones picked, marked on the map, centred on their city */

	for (n = 0; n < LHP_TZ_COUNT; n++) {
		if (t->zone[n] < 0)
			continue;
		zone_xy(&z, t->zone[n], &x, &y);
		lws_html_w_printf(&hw, "#m%d { left: %dpx; top: %dpx }", n,
				  clamp(x - ms / 2, 0, z.w - ms),
				  clamp(y - ms / 2, 0, z.h - ms));
	}

	lws_html_w_printf(&hw, "</style></head><body>"
			       "<div class=\"p\"><img src=\"" MAP_NAME "\">"
			       "</div>");

	for (n = 0; n < LHP_TZ_COUNT; n++)
		if (t->zone[n] >= 0)
			lws_html_w_printf(&hw, "<div class=\"m\" id=\"m%d\">"
					  "%s</div>", n, mark[n]);

	/*
	 * A row each for home and away: the button to press to pick it on the
	 * map, black if it's the one being picked, the zone and the time
	 * there, and for away, a button to turn it off or on
	 */

	for (n = 0; n < LHP_TZ_COUNT; n++) {
		lws_html_w_printf(&hw, "<div class=\"r\" id=\"r%d\">"
				  "<a class=\"n%s\" href=\"?p%d\">%s</a>"
				  "<div class=\"x\">", n,
				  t->picking == n ? " k" : "", n, label[n]);

		if (lhp_tz_name(t, (lhp_tz_which_t)n)) {
			lws_html_w_text(&hw, lhp_tz_name(t, (lhp_tz_which_t)n),
					NAME_MAX_LEN);
			if (lhp_tz_format(t, (lhp_tz_which_t)n, utc, 0, tm,
					  sizeof(tm)) > 0) {
				lws_html_w_printf(&hw, "  ");
				lws_html_w_text(&hw, tm, sizeof(tm));
			}
		} else
			lws_html_w_printf(&hw, t->picking == n ?
					  "Press where you are on the map" :
					  "Off");

		lws_html_w_printf(&hw, "</div>");
		if (n == LHP_TZ_AWAY)
			lws_html_w_printf(&hw, "<a class=\"o\" href=\"?o\">"
					  "%s</a>", lhp_tz_away(t) ? "Off" :
							"On");
		lws_html_w_printf(&hw, "</div>");
	}

	lws_html_w_printf(&hw, "<div class=\"r\" id=\"r2\">"
			       "<a class=\"k\" id=\"d\" href=\"?done\">Done</a>"
			       "</div></body></html>");

	return lws_html_w_len(&hw, buf);
}

lhp_tz_act_t
lhp_tz_press(const lws_surface_info_t *ic, lhp_tz_t *t, const char *href,
	     int x, int y)
{
	int lat, lon, zi;
	layout_t z;

	if (href) {
		if (!strcmp(href, "?done"))
			return LHP_TZ_ACT_DONE;

		if (!strcmp(href, "?p0") || !strcmp(href, "?p1")) {
			t->picking = (uint8_t)(href[2] - '0');
			return LHP_TZ_ACT_CHANGED;
		}

		if (!strcmp(href, "?o")) {
			if (lhp_tz_away(t)) {
				t->zone[LHP_TZ_AWAY] = -1;
				t->picking = LHP_TZ_HOME;
			} else
				/* the next press on the map sets it */
				t->picking = LHP_TZ_AWAY;
			return LHP_TZ_ACT_CHANGED;
		}

		return LHP_TZ_ACT_NONE;
	}

	layout(ic, &z);
	if (x < z.mx || x >= z.mx + z.mw || y < z.my || y >= z.my + z.mh)
		return LHP_TZ_ACT_NONE;

	lon = ((x - z.mx) * 36000) / z.mw - 18000;
	lat = (TZ_MAP_LAT_TOP * 100) - ((y - z.my) *
			(TZ_MAP_LAT_TOP - TZ_MAP_LAT_BOT) * 100) / z.mh;

	zi = nearest(lat, lon);
	if (zi < 0 || t->picking >= LHP_TZ_COUNT)
		return LHP_TZ_ACT_NONE;

	lwsl_notice("%s: lat %d, lon %d (1/100 deg): %s\n", __func__, lat,
		    lon, zones[zi].name);

	t->zone[t->picking] = (int16_t)zi;

	return LHP_TZ_ACT_CHANGED;
}
