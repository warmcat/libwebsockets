/*
 * lhp settings dialog
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See settings-ui.h
 */

#include "settings-ui.h"
#include <string.h>

#include "boot-icons.h"

/*
 * The icons, in the dlo filesystem, since the settings may be shown before
 * there is any network.  The key and globe are the boot overlay's, meaning
 * the same things here.
 */

static const struct {
	const char		*name;
	const uint8_t		*data;
	size_t			len;
} icons[] = {
	{ "set-key.svg",	boot_icon_setup,	sizeof(boot_icon_setup) },
	{ "set-net.svg",	boot_icon_internet,	sizeof(boot_icon_internet) },
	{ "set-cog.svg",	settings_icon_cog,	sizeof(settings_icon_cog) },
	{ "set-bin.svg",	settings_icon_forget,	sizeof(settings_icon_forget) },
	{ "set-ok.svg",		settings_icon_ok,	sizeof(settings_icon_ok) },
	{ "set-no.svg",		settings_icon_refused,	sizeof(settings_icon_refused) },
	{ "set-fail.svg",	settings_icon_failed,	sizeof(settings_icon_failed) },
	{ "set-sig0.svg",	settings_icon_sig0,	sizeof(settings_icon_sig0) },
	{ "set-sig1.svg",	settings_icon_sig1,	sizeof(settings_icon_sig1) },
	{ "set-sig2.svg",	settings_icon_sig2,	sizeof(settings_icon_sig2) },
	{ "set-sig3.svg",	settings_icon_sig3,	sizeof(settings_icon_sig3) },
	{ "set-sig4.svg",	settings_icon_sig4,	sizeof(settings_icon_sig4) },
};

/*
 * The dialog's css.  The APs are a table with a line around and between its
 * rows, so they read as one list.  Each AP's row is three cells, so it fits a
 * small display: its signal, its SSID over a smaller line of what we know
 * about it, then the icons to press, which are bigger, with some room around
 * them, to be easier to hit with a finger.  The hostname is shaded, like an
 * editbox.
 */

static const char dlg_css[] =
	"a { text-decoration: none; color: #000 }"
	".s { color: #24476b; margin-top: 4px }"
	".d { color: #888 }"
	".st { font-size: 0.75em }"
	"table { border-collapse: collapse; border: 1px solid #b4bcc6 }"
	"td { padding: 2px 3px 2px 0; vertical-align: middle;"
		" border-top: 1px solid #b4bcc6 }"
	"td.g { padding: 2px 3px }"
	"img { width: 1.25em; height: 1.25em }"
	"img.g { width: 20px; height: 20px }"
	"a.i { display: inline-block; padding: 2px }"
	"a.i img { width: 24px; height: 24px }"
	"a.e { display: block; background-color: #e4e8ec; padding: 3px 4px;"
		" margin: 2px 0 8px 0 }";

/*
 * The most html an AP's row can be, with its signal, all its icons and an SSID
 * of 32 characters that each need escaping, eg, &quot;
 */
#define AP_ROW_HTML_MAX		576

/* WPA passphrases are 8 to 63 characters */
#define PASSPHRASE_MIN		8
#define PASSPHRASE_MAX		63

int
lhp_rssi_bars(int rssi)
{
	if (rssi >= -55)
		return 4;
	if (rssi >= -65)
		return 3;
	if (rssi >= -75)
		return 2;

	return 1;
}

/*
 * Order-independent signature of the set of APs in the scan list, and their
 * signal bars, so we can tell when the APs shown are stale without listing
 * them again on every scan.  The averaged rssi jitters, but the bars it is
 * shown as change much less often, so the bars are in it and the rssi itself
 * and the ordering are deliberately left out.
 */

static uint32_t
scan_sig(const lhp_settings_t *s)
{
	uint32_t sig = 0;

	if (!s->wnd)
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&s->wnd->scan)) {
		lws_wifi_sta_t *w = lws_container_of(d, lws_wifi_sta_t, list);
		uint32_t h = 2166136261u;
		int n;

		for (n = 0; n < LWS_ETH_ALEN; n++)
			h = (h ^ w->bssid[n]) * 16777619u;
		h = (h ^ (uint8_t)w->ch) * 16777619u;
		h = (h ^ (uint8_t)lhp_rssi_bars(rssi_averaged(w))) * 16777619u;

		sig += h;
	} lws_end_foreach_dll(d);

	return sig;
}

static int
ap_find(const lhp_settings_t *s, const char *ssid)
{
	int n;

	for (n = 0; n < s->ap_count; n++)
		if (!strcmp(s->aps[n].ssid, ssid))
			return n;

	return -1;
}

/*
 * The APs to list: the networks in the scan results, the strongest BSS of
 * each, strongest first as the scan is sorted, then those we have credentials
 * for that weren't seen.  Hidden networks, with no SSID, can't be picked.
 */

static void
aps_update(lhp_settings_t *s)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(s->cx);
	lhp_settings_ap_t *a;
	int n;

	s->ap_count = 0;
	s->scan_sig = scan_sig(s);

	if (s->wnd) {
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&s->wnd->scan)) {
			lws_wifi_sta_t *w = lws_container_of(d,
						lws_wifi_sta_t, list);
			char ssid[33];

			if (s->ap_count == LHP_SET_AP_MAX)
				break;

			lws_strnncpy(ssid, w->ssid, w->ssid_len, sizeof(ssid));
			if (!ssid[0] || ap_find(s, ssid) >= 0)
				continue;

			a = &s->aps[s->ap_count++];
			memset(a, 0, sizeof(*a));
			memcpy(a->ssid, ssid, sizeof(a->ssid));
			a->auth = (uint8_t)w->authmode;
			a->open = w->authmode == LWS_WIFI_AUTH_OPEN;
			a->seen = 1;
			a->bars = (uint8_t)lhp_rssi_bars(rssi_averaged(w));
		} lws_end_foreach_dll(d);
	}

	/*
	 * Which we have credentials for, how joining them went, and those we
	 * have that weren't seen
	 */

	lws_netdev_credentials_hold(nds);

	lws_start_foreach_dll(struct lws_dll2 *, c,
			      lws_dll2_get_head(&nds->owner_creds)) {
		const lws_wifi_creds_t *cr = lws_container_of(c,
						lws_wifi_creds_t, list);

		n = ap_find(s, cr->ssid);
		if (n < 0) {
			if (s->ap_count == LHP_SET_AP_MAX || !cr->ssid[0])
				continue;

			n = s->ap_count++;
			a = &s->aps[n];
			memset(a, 0, sizeof(*a));
			lws_strncpy(a->ssid, cr->ssid, sizeof(a->ssid));
			a->open = !cr->passphrase[0];
		}

		a = &s->aps[n];
		a->stored = 1;
		a->last_join = cr->last_join;
		a->internet = cr->internet;
	} lws_end_foreach_dll(c);

	lws_netdev_credentials_release(nds);
}

static void
img(lws_dlo_ui_html_t *h, const char *name)
{
	lws_html_w_printf(h, "<img src=\"%s\">", name);
}

/*
 * The dialog's html, written each time it's laid out: the APs are listed
 * again then, so the indexes in its links are those of what is shown
 */

static void
dlg_html(void *opaque, lws_dlo_ui_html_t *h)
{
	char hn[LWS_NETDEV_HOSTNAME_MAX + 1];
	lhp_settings_t *s = (lhp_settings_t *)opaque;
	const lhp_settings_ap_t *a;
	int n;

	aps_update(s);

	lws_html_w_printf(h, "<div class=\"s\">WLAN</div>");

	if (!s->ap_count)
		/* there's nothing to pick, but say why */
		lws_html_w_printf(h, "<div class=\"d\">%s</div>",
				       s->wnd ? "Scanning..." : "No WLAN");
	else
		lws_html_w_printf(h, "<table>");

	for (n = 0; n < s->ap_count; n++) {
		a = &s->aps[n];

		/*
		 * Its signal first, all the bars unlit if it wasn't seen.
		 * Those we have credentials for but can't see are dimmed.
		 */
		lws_html_w_printf(h, "<tr%s><td class=\"g\"><img "
				       "class=\"g\" src=\"set-sig%d.svg\">"
				       "</td><td><div>",
				       a->seen ? "" : " class=\"d\"",
				       (int)a->bars);
		lws_html_w_text(h, a->ssid, sizeof(a->ssid));
		lws_html_w_printf(h, "</div><div class=\"st\">");
		if (a->stored && !a->open)
			img(h, "set-key.svg");
		if (a->seen)
			lws_html_w_printf(h, "%s ", lws_wifi_auth_name(
						(lws_wifi_auth_t)a->auth));

		/* how the last try to join it went */
		switch (a->last_join) {
		case LWS_WIFI_JOIN_OK:
			img(h, "set-ok.svg");
			break;
		case LWS_WIFI_JOIN_AUTH_FAILED:
			img(h, "set-no.svg");
			break;
		case LWS_WIFI_JOIN_FAILED:
			img(h, "set-fail.svg");
			break;
		default:
			break;
		}

		if (a->internet)
			img(h, "set-net.svg");
		lws_html_w_printf(h, "</div></td><td>");
		/* an open AP that's stored has no passphrase to set */
		if (!a->open || !a->stored)
			lws_html_w_printf(h, "<a class=\"i\" href=\"set:%d\">"
					       "<img src=\"set-cog.svg\"></a>", n);
		if (a->stored)
			lws_html_w_printf(h, "<a class=\"i\" "
					       "href=\"forget:%d\"><img "
					       "src=\"set-bin.svg\"></a>", n);
		lws_html_w_printf(h, "</td></tr>");
	}

	if (s->ap_count)
		lws_html_w_printf(h, "</table>");

	if (lws_netdev_hostname_get(lws_netdevs_from_ctx(s->cx), hn,
				    sizeof(hn)) < 0)
		lws_strncpy(hn, "-", sizeof(hn));

	lws_html_w_printf(h, "<div class=\"s\">Hostname</div>"
				  "<a class=\"e\" href=\"host\">");
	lws_html_w_text(h, hn, sizeof(hn));
	lws_html_w_printf(h, "</a>");
}

/* the AP a link is for, eg, "set:3" for prefix "set:", or -1 */

static int
ap_of(const lhp_settings_t *s, const char *href, const char *prefix)
{
	size_t pl = strlen(prefix);
	int n = 0;

	if (strncmp(href, prefix, pl) || !href[pl])
		return -1;

	for (href += pl; *href; href++) {
		if (*href < '0' || *href > '9' || n >= LHP_SET_AP_MAX)
			return -1;
		n = (n * 10) + (*href - '0');
	}

	return n < s->ap_count ? n : -1;
}

/*
 * Store the credentials for the AP being edited.  The wifi netdev scans
 * while it isn't joined, and joins the strongest AP it has credentials for.
 */

static int
store(lhp_settings_t *s, const char *passphrase)
{
	if (lws_netdev_credentials_add(lws_netdevs_from_ctx(s->cx), s->ssid,
				       passphrase)) {
		lwsl_err("%s: unable to store credentials\n", __func__);
		return 1;
	}

	lwsl_user("%s: stored credentials for %s\n", __func__, s->ssid);

	if (s->flags & LHP_SET_FL_EXIT_ON_STORE)
		lhp_settings_exit(s);
	else
		lws_dlo_ui_dialog_changed(s->ui);

	return 0;
}

static void
edit_passphrase(lhp_settings_t *s)
{
	/*
	 * It's shown as it's typed, so typos can be seen on the small
	 * keyboard.  It starts empty, even if one is stored for the AP:
	 * Done replaces that one.  What's stored is never shown.
	 */
	if (lws_dlo_ui_edit(s->ui, "Passphrase", PASSPHRASE_MAX, 0)) {
		lwsl_err("%s: unable to edit passphrase\n", __func__);
		return;
	}

	s->editing = LHP_SET_EDIT_PASSPHRASE;
}

static void
edit_hostname(lhp_settings_t *s)
{
	char hn[LWS_NETDEV_HOSTNAME_MAX + 1];

	/* however the edit is left, it's stored if it's valid */
	if (lws_dlo_ui_edit(s->ui, "Hostname", LWS_NETDEV_HOSTNAME_MAX,
			    LWS_DLO_UI_EDIT_KEEP)) {
		lwsl_err("%s: unable to edit hostname\n", __func__);
		return;
	}

	s->editing = LHP_SET_EDIT_HOSTNAME;

	/* it starts as it is, to be changed */
	if (lws_netdev_hostname_get(lws_netdevs_from_ctx(s->cx), hn,
				    sizeof(hn)) >= 0)
		lws_dlo_ui_edit_set(s->ui, hn);
}

/* a link on the dialog was pressed */

static void
dlg_action(void *opaque, const char *href)
{
	lhp_settings_t *s = (lhp_settings_t *)opaque;
	int n;

	if (!strcmp(href, "host")) {
		edit_hostname(s);
		return;
	}

	n = ap_of(s, href, "set:");
	if (n >= 0) {
		lws_strncpy(s->ssid, s->aps[n].ssid, sizeof(s->ssid));
		if (s->aps[n].open)
			/* there's nothing to type */
			store(s, "");
		else
			edit_passphrase(s);
		return;
	}

	n = ap_of(s, href, "forget:");
	if (n < 0)
		return;

	if (lws_netdev_credentials_remove(lws_netdevs_from_ctx(s->cx),
					  s->aps[n].ssid))
		lwsl_err("%s: unable to forget %s\n", __func__, s->aps[n].ssid);
	else
		lwsl_user("%s: forgot %s\n", __func__, s->aps[n].ssid);

	lws_dlo_ui_dialog_changed(s->ui);
}

int
lhp_settings_init(lhp_settings_t *s, struct lws_context *cx,
		  lws_netdev_instance_wifi_t *wnd,
		  lhp_settings_exit_cb_t exit_cb, void *opaque)
{
	lws_dlo_filesystem_t f;
	size_t n;

	memset(s, 0, sizeof(*s));
	s->cx = cx;
	s->wnd = wnd;
	s->exit_cb = exit_cb;
	s->opaque = opaque;

	memset(&f, 0, sizeof(f));
	for (n = 0; n < LWS_ARRAY_SIZE(icons); n++) {
		f.name = icons[n].name;
		f.data = icons[n].data;
		f.len = icons[n].len;
		if (!lws_dlo_file_register(cx, &f))
			return 1;
	}

	return 0;
}

void
lhp_settings_deinit(lhp_settings_t *s)
{
	size_t n;

	lhp_settings_close(s);

	for (n = 0; n < LWS_ARRAY_SIZE(icons); n++)
		lws_dlo_file_unregister_by_name(s->cx, icons[n].name);
}

void
lhp_settings_open(lhp_settings_t *s, struct lws_dlo_ui *ui,
		  unsigned int flags)
{
	lws_dlo_ui_dialog_t d;

	s->ui = ui;
	s->flags = (uint8_t)flags;
	s->editing = LHP_SET_EDIT_NONE;

	memset(&d, 0, sizeof(d));
	d.html = dlg_html;
	d.action = dlg_action;
	d.opaque = s;
	d.css = dlg_css;
	d.html_max = LHP_SET_AP_MAX * AP_ROW_HTML_MAX + 512;

	lws_dlo_ui_set_title(ui, "Settings");
	if (lws_dlo_ui_dialog(ui, &d)) {
		lwsl_err("%s: unable to show the dialog\n", __func__);
		return;
	}

	s->shown = 1;
}

void
lhp_settings_close(lhp_settings_t *s)
{
	if (!s->shown)
		return;

	if (s->editing != LHP_SET_EDIT_NONE)
		/* the edit is told it ended while the settings still own it */
		lws_dlo_ui_edit_abandon(s->ui);

	s->shown = 0;
	s->editing = LHP_SET_EDIT_NONE;
}

void
lhp_settings_exit(lhp_settings_t *s)
{
	if (!s->shown)
		return;

	lhp_settings_close(s);

	if (s->exit_cb)
		s->exit_cb(s->opaque);
}

int
lhp_settings_shown(const lhp_settings_t *s)
{
	return s->shown;
}

void
lhp_settings_scan(lhp_settings_t *s)
{
	if (s->shown && scan_sig(s) != s->scan_sig)
		lws_dlo_ui_dialog_changed(s->ui);
}

void
lhp_settings_changed(lhp_settings_t *s)
{
	if (s->shown)
		lws_dlo_ui_dialog_changed(s->ui);
}

/* pressing the title closes the settings */

void
lhp_settings_title(lhp_settings_t *s)
{
	lhp_settings_exit(s);
}

/*
 * text is what was typed: a secret if it's a passphrase, or NULL if that was
 * abandoned.  A hostname is given however its edit ended.
 */

int
lhp_settings_done(lhp_settings_t *s, const char *text)
{
	lhp_settings_edit_t e = (lhp_settings_edit_t)s->editing;

	/* the edit is over, unless we keep it, before anything else happens */
	s->editing = LHP_SET_EDIT_NONE;

	if (!text)
		return 0;

	switch (e) {
	case LHP_SET_EDIT_PASSPHRASE:
		if (strlen(text) < PASSPHRASE_MIN || store(s, text)) {
			/* keep typing, or try again */
			s->editing = (uint8_t)e;
			return 1;
		}
		return 0;

	case LHP_SET_EDIT_HOSTNAME:
		/* nothing typed goes back to the default hostname */
		if (lws_netdev_hostname_set(lws_netdevs_from_ctx(s->cx), text)) {
			/*
			 * Not a valid hostname: after Done, it's still being
			 * edited; otherwise the edit ends, leaving it as it was
			 */
			s->editing = (uint8_t)e;
			return 1;
		}
		/* the dialog shows it, being laid out again after the edit */
		return 0;

	default:
		return 0;
	}
}
