/*
 * lhp boot status overlay
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See boot-ui.h.  Everything the overlay refers to is in the dlo filesystem,
 * since it has to be shown before there is any network: so is its text, in
 * whatever face is built in.
 */

#include "boot-ui.h"

#include <string.h>
#include <time.h>

#include "boot-icons.h"

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
	      lws_netdev_instance_wifi_t *wnd)
{
	lws_dlo_filesystem_t f;
	size_t n;

	memset(b, 0, sizeof(*b));
	b->cx = cx;
	b->wnd = wnd;

	memset(&f, 0, sizeof(f));
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
 * The row text writer: everything is appended at p, up to end.  Once
 * something didn't fit, nothing more is written
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
 * Text that came from outside, eg an SSID anyone nearby can choose, may be
 * anything: the strip ui only ever shows the row text as text
 */

static void
bw_text(bw_t *w, const char *s, size_t max)
{
	size_t n;

	for (n = 0; n < max && s[n] && !w->full; n++)
		bw_printf(w, "%c", s[n]);
}

/*
 * What we have to say about each stage, on its row next to its icon.  It is
 * one line, cut off if it is too long for the row.
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
		if (b->own_ap[0]) {
			/* we're an AP, to be set up from a browser */
			bw_printf(w, "Join ");
			bw_text(w, b->own_ap, sizeof(b->own_ap));
			bw_printf(w, ", browse ");
			bw_text(w, b->own_ip, sizeof(b->own_ip));
			break;
		}
		/* the AP we will look for, from what is stored */
		if (!b->ap[0]) {
			bw_printf(w, reached ? "Configured" : "Not configured");
			break;
		}
		bw_text(w, b->ap, sizeof(b->ap));
		if (b->aps > 1)
			bw_printf(w, " and %u more", (unsigned int)(b->aps - 1));
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
lhp_boot_row(const lhp_boot_t *b, int idx, lws_dlo_ui_row_t *row)
{
	lhp_boot_stage_t f = lhp_boot_focus(b);
	bw_t w;

	if (idx < 0 || idx >= LHP_BOOT_COUNT)
		return 1;

	row->icon = icons[idx].name;
	row->state = idx == (int)f ? LWS_DLO_UI_ROW_FOCUS :
			((b->reached & (1u << idx)) ? LWS_DLO_UI_ROW_NORMAL :
						      LWS_DLO_UI_ROW_DIM);

	w.p = row->text;
	w.end = row->text + sizeof(row->text);
	w.full = 0;
	lhp_boot_text(b, (lhp_boot_stage_t)idx, f, &w);

	return 0;
}
