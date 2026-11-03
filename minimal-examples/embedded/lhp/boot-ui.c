/*
 * lhp boot status overlay
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See boot-ui.h.  The look is in boot.css below, the geometry, which depends
 * on the display, is worked out here and given to the overlay's elements by
 * id in the html.  Everything the overlay refers to is in the dlo filesystem,
 * since it has to be shown before there is any network: so is its text, in
 * whatever face is built in.
 */

#include "boot-ui.h"

#include <string.h>
#include <time.h>

#include "boot-icons.h"

static const char * const boot_css =
	"* { margin: 0; padding: 0 }"
	"body { background-color: #fff; color: #000; font-family: sans }"
	"#ov { position: absolute; left: 0; top: 0; background-color: #fff }"
	"#win { position: absolute; overflow: hidden }"
	"#list { position: relative; border-spacing: 0 }"
	".ic { border-radius: 4px }"
	".tx { white-space: nowrap }"
	".pending { opacity: 0.25 }"
	".focus { background-color: #ccc }";

static const struct {
	const char		*name;
	const uint8_t		*data;
	size_t			len;
} icons[] = {
	{ "boot-1-setup.svg",	 boot_icon_setup,    sizeof(boot_icon_setup) },
	{ "boot-2-wlan.svg",	 boot_icon_wlan,     sizeof(boot_icon_wlan) },
	{ "boot-3-ipv4.svg",	 boot_icon_ipv4,     sizeof(boot_icon_ipv4) },
	{ "boot-4-ipv6.svg",	 boot_icon_ipv6,     sizeof(boot_icon_ipv6) },
	{ "boot-5-internet.svg", boot_icon_internet, sizeof(boot_icon_internet) },
	{ "boot-6-date.svg",	 boot_icon_date,     sizeof(boot_icon_date) },
	{ "boot-7-ota.svg",	 boot_icon_ota,      sizeof(boot_icon_ota) },
	{ "boot-8-auth.svg",	 boot_icon_auth,     sizeof(boot_icon_auth) },
};

typedef char lhp_boot_icons_match[
		LWS_ARRAY_SIZE(icons) == LHP_BOOT_COUNT ? 1 : -1];

int
lhp_boot_init(struct lws_context *cx, lhp_boot_t *b,
	      const lws_surface_info_t *ic, lws_netdev_instance_wifi_t *wnd)
{
	lws_dlo_filesystem_t f;
	size_t n;

	memset(b, 0, sizeof(*b));
	b->cx = cx;
	b->ic = ic;
	b->wnd = wnd;

	memset(&f, 0, sizeof(f));
	f.name = "boot.css";
	f.data = boot_css;
	f.len = strlen(boot_css);
	if (!lws_dlo_file_register(cx, &f))
		return 1;

	for (n = 0; n < LWS_ARRAY_SIZE(icons); n++) {
		f.name = icons[n].name;
		f.data = icons[n].data;
		f.len = icons[n].len;
		if (!lws_dlo_file_register(cx, &f)) {
			lhp_boot_deinit(b);
			return 1;
		}
	}

	return 0;
}

void
lhp_boot_deinit(lhp_boot_t *b)
{
	size_t n;

	lws_dlo_file_unregister_by_name(b->cx, "boot.css");
	for (n = 0; n < LWS_ARRAY_SIZE(icons); n++)
		lws_dlo_file_unregister_by_name(b->cx, icons[n].name);
}

int
lhp_boot_set(lhp_boot_t *b, lhp_boot_stage_t s, int reached)
{
	uint16_t r = b->reached;

	if (s >= LHP_BOOT_COUNT)
		return 0;

	if (reached)
		b->reached = (uint16_t)(b->reached | (1u << s));
	else
		b->reached = (uint16_t)(b->reached & ~(1u << s));

	return r != b->reached;
}

lhp_boot_stage_t
lhp_boot_focus(const lhp_boot_t *b)
{
	int n;

	for (n = 0; n < LHP_BOOT_COUNT; n++)
		if (n != LHP_BOOT_IPV6 && !(b->reached & (1u << n)))
			return (lhp_boot_stage_t)n;

	return LHP_BOOT_COUNT;
}

/*
 * The html writer: everything is appended at p, up to end.  Once something
 * didn't fit, nothing more is written and the result is refused, rather than
 * a truncated document being shown
 */

typedef struct {
	char			*p;
	char			*end;
	char			full;
} bw_t;

static void
bw_printf(bw_t *w, const char *fmt, ...) LWS_FORMAT(2);

static void
bw_printf(bw_t *w, const char *fmt, ...)
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
 * Text that came from outside, eg an SSID anyone nearby can choose, is put
 * in the html as text, never as markup: escape what html gives meaning to,
 * and drop control characters
 */

static void
bw_text(bw_t *w, const char *s, size_t max)
{
	size_t n;

	for (n = 0; n < max && s[n] && !w->full; n++) {
		unsigned char c = (unsigned char)s[n];

		switch (c) {
		case '&':
			bw_printf(w, "&amp;");
			break;
		case '<':
			bw_printf(w, "&lt;");
			break;
		case '>':
			bw_printf(w, "&gt;");
			break;
		case '"':
			bw_printf(w, "&quot;");
			break;
		case '\'':
			bw_printf(w, "&#39;");
			break;
		default:
			if (c < 0x20 || c == 0x7f)
				c = '?';
			bw_printf(w, "%c", c);
			break;
		}
	}
}

/*
 * What we have to say about each stage, on its row next to its icon.  It is
 * one line, cut off by the window if it is too long: the rows are all the
 * same height, so the row being worked on can be found and shown.
 */

static void
lhp_boot_text_wlan(const lhp_boot_t *b, int reached, bw_t *w)
{
	uint32_t seen = b->wnd ? lws_dll2_count(&b->wnd->scan) : 0;

	if (b->wnd && b->wnd->current_attempt_ssid[0]) {
		if (!reached)
			bw_printf(w, "Looking for ");
		bw_text(w, b->wnd->current_attempt_ssid,
			sizeof(b->wnd->current_attempt_ssid));
		return;
	}

	if (reached)
		return;

	bw_printf(w, "Looking for an AP");
	if (seen)
		bw_printf(w, ", %u seen", (unsigned int)seen);
}

static void
lhp_boot_text_date(bw_t *w)
{
	struct tm tm;
	char d[32];
	time_t t = time(NULL);

	if (!gmtime_r(&t, &tm) ||
	    !strftime(d, sizeof(d), "%Y-%m-%d %H:%M UTC", &tm))
		return;

	bw_text(w, d, sizeof(d));
}

static void
lhp_boot_text_ota(const lhp_boot_t *b, bw_t *w)
{
	static const char * const ota_state[] = {
		"", "Checking for updates", "Up to date", "Updating",
		"Update check failed", "Updates disabled"
	};

#if defined(LWS_WITH_OTA)
	bw_text(w, lws_ota_variant_name(), 64);
	if (b->ota && b->ota < LWS_ARRAY_SIZE(ota_state))
		bw_printf(w, ": ");
#endif

	if (b->ota < LWS_ARRAY_SIZE(ota_state))
		bw_printf(w, "%s", ota_state[b->ota]);
}

static void
lhp_boot_text(const lhp_boot_t *b, lhp_boot_stage_t s, lhp_boot_stage_t f,
	      bw_t *w)
{
	static const char * const cpd[] = {
		"Checking connectivity", "", "Captive portal", "No internet"
	};
	int reached = !!(b->reached & (1u << s));
	lws_cpd_result_t c;

	if (!reached && s > f && s != LHP_BOOT_OTA)
		/* we haven't got to it yet: there's nothing to say */
		return;

	switch (s) {
	case LHP_BOOT_SETUP:
		bw_printf(w, reached ? "Wifi credentials stored" :
				       "No wifi credentials");
		break;

	case LHP_BOOT_WLAN:
		lhp_boot_text_wlan(b, reached, w);
		break;

	case LHP_BOOT_IPV4:
		if (reached)
			bw_text(w, b->ipv4, sizeof(b->ipv4));
		else
			bw_printf(w, "Waiting for an address");
		break;

	case LHP_BOOT_IPV6:
		/* we never wait for it, it's only shown if we have one */
		if (reached)
			bw_text(w, b->ipv6, sizeof(b->ipv6));
		break;

	case LHP_BOOT_INTERNET:
		if (reached) {
			bw_printf(w, "Connected");
			break;
		}
		c = lws_system_cpd_state_get(b->cx);
		if ((size_t)c < LWS_ARRAY_SIZE(cpd))
			bw_printf(w, "%s", cpd[c]);
		break;

	case LHP_BOOT_DATE:
		if (reached)
			lhp_boot_text_date(w);
		else
			bw_printf(w, "Asking for the time");
		break;

	case LHP_BOOT_OTA:
		/* the variant is known from the start */
		lhp_boot_text_ota(b, w);
		break;

	case LHP_BOOT_AUTH:
		bw_printf(w, reached ? "Signed in" : "Signing in");
		break;

	default:
		break;
	}
}

int
lhp_boot_html(const lhp_boot_t *b, char *buf, size_t len)
{
	int W = b->ic->wh_px[0].whole, H = b->ic->wh_px[1].whole;
	static const int sizes[] = { 48, 32, 24 };
	lhp_boot_stage_t f = lhp_boot_focus(b);
	int m = 2, i = 24, pad, row, rows, wh, top = 0, ow, fs, tp, n;
	bw_t w;

	if (len < 2)
		return -1;

	w.p = buf;
	w.end = buf + len;
	w.full = 0;

	/*
	 * The biggest icons the whole list fits the display at.  If even the
	 * smallest don't fit, the list is shown through a window as tall as
	 * the display, offset so the row of the stage being worked on is in
	 * the middle of it: as that moves on, so does the list
	 */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(sizes); n++) {
		pad = sizes[n] / 16;
		if (LHP_BOOT_COUNT * (sizes[n] + 2 * pad) + 2 * m <= H) {
			i = sizes[n];
			break;
		}
	}
	pad = i / 16;
	row = i + 2 * pad;

	rows = (H - 2 * m) / row;
	if (rows > LHP_BOOT_COUNT)
		rows = LHP_BOOT_COUNT;
	if (rows < 1)
		rows = 1;
	wh = rows < LHP_BOOT_COUNT ? H - 2 * m : rows * row;

	if (rows < LHP_BOOT_COUNT) {
		/* all done is shown as the last stage being worked on */
		n = f < LHP_BOOT_COUNT ? (int)f : LHP_BOOT_COUNT - 1;
		top = n * row - (wh - row) / 2;
		if (top > LHP_BOOT_COUNT * row - wh)
			top = LHP_BOOT_COUNT * row - wh;
		if (top < 0)
			top = 0;
	}

	/* on a big display, the overlay only needs the top left of it */
	ow = W <= 320 ? W : W / 2;
	fs = H <= 64 ? 10 : (i >= 48 ? 16 : 12);
	/* the text in the middle of its row, for a line about 1.2em tall */
	tp = (row - (fs * 6) / 5) / 2;
	if (tp < 0)
		tp = 0;

	bw_printf(&w, "<!doctype html><html><head><meta charset=\"utf-8\">"
		"<link rel=\"stylesheet\" href=\"boot.css\"><style>"
		"#ov { width: %dpx; height: %dpx }"
		"#win { left: %dpx; top: %dpx; width: %dpx; height: %dpx }"
		"#list { top: -%dpx }"
		".ic { width: %dpx; height: %dpx; padding: %dpx }"
		".ic img { width: %dpx; height: %dpx }"
		".tx { width: %dpx; height: %dpx; padding-top: %dpx; "
			"padding-left: %dpx; font-size: %dpx }"
		"</style></head><body><div id=\"ov\">"
		"<div id=\"win\"><table id=\"list\">",
		ow, wh + 2 * m,
		m, m, ow - 2 * m, wh,
		top,
		i, i, pad,
		i, i,
		ow - 2 * m - row - 2 * m, row - tp, tp, 2 * m, fs);

	for (n = 0; n < LHP_BOOT_COUNT; n++) {
		const char *cl = n == (int)f ? "focus" :
				((b->reached & (1u << n)) ? "done" : "pending");

		bw_printf(&w, "<tr><td class=\"ic %s\"><img src=\"%s\"></td>"
			      "<td class=\"tx %s\">", cl, icons[n].name, cl);
		lhp_boot_text(b, (lhp_boot_stage_t)n, f, &w);
		bw_printf(&w, "</td></tr>");
	}

	bw_printf(&w, "</table></div></div></body></html>");

	if (w.full)
		return -1;

	return lws_ptr_diff(w.p, buf);
}
