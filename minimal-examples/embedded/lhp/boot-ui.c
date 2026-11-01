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
	"#list { position: relative }"
	".ic { border-radius: 4px }"
	".pending { opacity: 0.25 }"
	".focus { background-color: #ccc }"
	"#info { position: absolute; overflow: hidden }"
	".t { font-weight: bold }";

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

static const char * const stage_title[] = {
	"Setup", "Wifi", "IPv4", "IPv6", "Internet", "Date", "Firmware",
	"Account", "Ready"
};

/* the most APs we list while looking for one we can join */
#define LHP_BOOT_MAX_APS	8

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

static void
bw_line(bw_t *w, const char *label, const char *val, size_t max)
{
	bw_printf(w, "<div>%s", label);
	if (val)
		bw_text(w, val, max);
	bw_printf(w, "</div>");
}

static void
lhp_boot_info_aps(const lhp_boot_t *b, bw_t *w)
{
	int n = 0;

	if (!b->wnd)
		return;

	/* the scan list is kept sorted strongest-first from the head */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&b->wnd->scan)) {
		lws_wifi_sta_t *s = lws_container_of(d, lws_wifi_sta_t, list);

		if (n++ == LHP_BOOT_MAX_APS)
			break;

		bw_printf(w, "<div>%d ", rssi_averaged(s));
		/* the ssid is stored after the lws_wifi_sta_t */
		bw_text(w, (const char *)&s[1], 32);
		bw_printf(w, "</div>");
	} lws_end_foreach_dll(d);
}

static void
lhp_boot_info_date(bw_t *w)
{
	struct tm tm;
	char d[32];
	time_t t = time(NULL);

	if (!gmtime_r(&t, &tm) ||
	    !strftime(d, sizeof(d), "%Y-%m-%d %H:%M UTC", &tm))
		return;

	bw_line(w, "", d, sizeof(d));
}

static void
lhp_boot_info_ota(const lhp_boot_t *b, bw_t *w)
{
	static const char * const ota_state[] = {
		"", "Checking for updates", "Up to date", "Updating",
		"Update check failed", "Updates disabled"
	};
#if defined(LWS_WITH_OTA)
	const lws_system_ops_t *ops = lws_system_get_ops(b->cx);
	uint64_t fw = 0;
	struct tm tm;
	char d[32];
	time_t t;

	bw_line(w, "", lws_ota_variant_name(), 64);

	if (ops && ops->ota_ops.ota_get_last_fw_unixtime &&
	    !ops->ota_ops.ota_get_last_fw_unixtime(&fw)) {
		t = (time_t)fw;
		if (gmtime_r(&t, &tm) &&
		    strftime(d, sizeof(d), "%Y-%m-%d %H:%M", &tm))
			bw_line(w, "", d, sizeof(d));
	}
#endif

	if (b->ota < LWS_ARRAY_SIZE(ota_state) && b->ota)
		bw_line(w, "", ota_state[b->ota], 32);
}

/* information about the stage being worked on, for #info */

static void
lhp_boot_info(const lhp_boot_t *b, lhp_boot_stage_t f, bw_t *w)
{
	static const char * const cpd[] = {
		"", "", "Captive portal", "No internet"
	};
	lws_cpd_result_t c;

	bw_printf(w, "<div class=\"t\">%s</div>", stage_title[f]);

	switch (f) {
	case LHP_BOOT_SETUP:
		bw_line(w, "No wifi credentials", NULL, 0);
		lhp_boot_info_aps(b, w);
		break;

	case LHP_BOOT_WLAN:
		if (b->wnd && b->wnd->current_attempt_ssid[0])
			bw_line(w, "Joining ", b->wnd->current_attempt_ssid,
				sizeof(b->wnd->current_attempt_ssid));
		else
			bw_line(w, "Looking for an AP", NULL, 0);
		lhp_boot_info_aps(b, w);
		break;

	case LHP_BOOT_IPV4:
		if (b->wnd)
			bw_line(w, "", b->wnd->current_attempt_ssid,
				sizeof(b->wnd->current_attempt_ssid));
		bw_line(w, "Waiting for an address", NULL, 0);
		break;

	case LHP_BOOT_INTERNET:
		bw_line(w, "", b->ipv4, sizeof(b->ipv4));
		if (b->ipv6[0])
			bw_line(w, "", b->ipv6, sizeof(b->ipv6));
		c = lws_system_cpd_state_get(b->cx);
		if (c > LWS_CPD_INTERNET_OK && (size_t)c < LWS_ARRAY_SIZE(cpd))
			bw_line(w, cpd[c], NULL, 0);
		else
			bw_line(w, "Checking connectivity", NULL, 0);
		break;

	case LHP_BOOT_DATE:
		bw_line(w, "Asking for the time", NULL, 0);
		break;

	case LHP_BOOT_OTA:
		lhp_boot_info_ota(b, w);
		lhp_boot_info_date(w);
		break;

	case LHP_BOOT_AUTH:
		bw_line(w, "Signing in", NULL, 0);
		lhp_boot_info_date(w);
		break;

	default:
		lhp_boot_info_ota(b, w);
		lhp_boot_info_date(w);
		break;
	}
}

int
lhp_boot_html(const lhp_boot_t *b, char *buf, size_t len)
{
	int W = b->ic->wh_px[0].whole, H = b->ic->wh_px[1].whole;
	static const int sizes[] = { 48, 32, 24 };
	lhp_boot_stage_t f = lhp_boot_focus(b);
	int m = 2, i = 24, pad, row, rows = 2, top = 0, ow, il, fs, n;
	bw_t w;

	if (len < 2)
		return -1;

	w.p = buf;
	w.end = buf + len;
	w.full = 0;

	/*
	 * The biggest icons the whole list fits the display at, or if even the
	 * smallest don't fit, a window of two rows onto the list: the last
	 * stage we reached, and the one being worked on
	 */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(sizes); n++) {
		pad = sizes[n] / 16;
		if (LHP_BOOT_COUNT * (sizes[n] + 2 * pad) + 2 * m <= H) {
			i = sizes[n];
			rows = LHP_BOOT_COUNT;
			break;
		}
	}
	pad = i / 16;
	row = i + 2 * pad;

	if (rows < LHP_BOOT_COUNT) {
		top = (int)f - 1;
		if (top > LHP_BOOT_COUNT - rows)
			top = LHP_BOOT_COUNT - rows;
		if (top < 0)
			top = 0;
	}

	/* on a big display, the overlay only needs the top left of it */
	ow = W <= 320 ? W : W / 2;
	il = m + row + 2 * m;
	fs = H <= 64 ? 10 : (i >= 48 ? 16 : 12);

	bw_printf(&w, "<!doctype html><html><head><meta charset=\"utf-8\">"
		"<link rel=\"stylesheet\" href=\"boot.css\"><style>"
		"#ov { width: %dpx; height: %dpx }"
		"#win { left: %dpx; top: %dpx; width: %dpx; height: %dpx }"
		"#list { top: -%dpx }"
		".ic { width: %dpx; height: %dpx; padding: %dpx }"
		".ic img { width: %dpx; height: %dpx }"
		"#info { left: %dpx; top: %dpx; width: %dpx; height: %dpx; "
			"font-size: %dpx }"
		"</style></head><body><div id=\"ov\">"
		"<div id=\"win\"><div id=\"list\">",
		ow, rows * row + 2 * m,
		m, m, row, rows * row,
		top * row,
		i, i, pad,
		i, i,
		il, m, ow - il - m, rows * row, fs);

	for (n = 0; n < LHP_BOOT_COUNT; n++)
		bw_printf(&w, "<div class=\"ic %s\"><img src=\"%s\"></div>",
			  n == (int)f ? "focus" :
			  ((b->reached & (1u << n)) ? "done" : "pending"),
			  icons[n].name);

	bw_printf(&w, "</div></div><div id=\"info\">");
	lhp_boot_info(b, f, &w);
	bw_printf(&w, "</div></div></body></html>");

	if (w.full)
		return -1;

	return lws_ptr_diff(w.p, buf);
}
