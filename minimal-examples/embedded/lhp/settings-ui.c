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
 * there is any network, and served beside them to a browser.  The key and
 * globe are the boot overlay's, meaning the same things here.
 */

#define SVG "image/svg+xml"

static const lws_wifi_provision_file_t icons[] = {
	{ LWS_WIFI_SETTINGS_ICON_KEY,	boot_icon_setup,
	  sizeof(boot_icon_setup), SVG },
	{ LWS_WIFI_SETTINGS_ICON_NET,	boot_icon_internet,
	  sizeof(boot_icon_internet), SVG },
	{ LWS_WIFI_SETTINGS_ICON_COG,	settings_icon_cog,
	  sizeof(settings_icon_cog), SVG },
	{ LWS_WIFI_SETTINGS_ICON_FORGET, settings_icon_forget,
	  sizeof(settings_icon_forget), SVG },
	{ LWS_WIFI_SETTINGS_ICON_OK,	settings_icon_ok,
	  sizeof(settings_icon_ok), SVG },
	{ LWS_WIFI_SETTINGS_ICON_REFUSED, settings_icon_refused,
	  sizeof(settings_icon_refused), SVG },
	{ LWS_WIFI_SETTINGS_ICON_FAILED, settings_icon_failed,
	  sizeof(settings_icon_failed), SVG },
	{ LWS_WIFI_SETTINGS_ICON_SIG "0.svg", settings_icon_sig0,
	  sizeof(settings_icon_sig0), SVG },
	{ LWS_WIFI_SETTINGS_ICON_SIG "1.svg", settings_icon_sig1,
	  sizeof(settings_icon_sig1), SVG },
	{ LWS_WIFI_SETTINGS_ICON_SIG "2.svg", settings_icon_sig2,
	  sizeof(settings_icon_sig2), SVG },
	{ LWS_WIFI_SETTINGS_ICON_SIG "3.svg", settings_icon_sig3,
	  sizeof(settings_icon_sig3), SVG },
	{ LWS_WIFI_SETTINGS_ICON_SIG "4.svg", settings_icon_sig4,
	  sizeof(settings_icon_sig4), SVG },
};

/*
 * The most html an AP's row can be, with its signal, all its icons and an SSID
 * of 32 characters that each need escaping, eg, &quot;, and %-encoding in its
 * links
 */
#define AP_ROW_HTML_MAX		640

/* WPA passphrases are 8 to 63 characters */
#define PASSPHRASE_MIN		8
#define PASSPHRASE_MAX		63

const lws_wifi_provision_file_t *
lhp_settings_icons(size_t *count)
{
	*count = LWS_ARRAY_SIZE(icons);

	return icons;
}

/*
 * The dialog's html, written each time it's laid out: the APs are listed
 * again then
 */

static void
dlg_html(void *opaque, lws_dlo_ui_html_t *h)
{
	char hn[LWS_NETDEV_HOSTNAME_MAX + 1];
	lhp_settings_t *s = (lhp_settings_t *)opaque;

	s->scan_sig = lws_netdev_wifi_scan_sig(s->wnd);
	s->ap_count = lws_netdev_wifi_ap_list(lws_netdevs_from_ctx(s->cx),
					      s->wnd, s->aps, LHP_SET_AP_MAX);

	if (s->note[0]) {
		lws_html_w_printf(h, "<div class=\"d\">");
		lws_html_w_text(h, s->note, sizeof(s->note));
		lws_html_w_printf(h, "</div>");
	}

	if (lws_netdev_hostname_get(lws_netdevs_from_ctx(s->cx), hn,
				    sizeof(hn)) < 0)
		hn[0] = '\0';

	lws_wifi_settings_html(h, s->aps, s->ap_count, !!s->wnd, hn);
}

/* what we listed about ssid, or NULL */

static const lws_wifi_ap_info_t *
ap_listed(const lhp_settings_t *s, const char *ssid)
{
	int n;

	for (n = 0; n < s->ap_count; n++)
		if (!strcmp(s->aps[n].ssid, ssid))
			return &s->aps[n];

	return NULL;
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

	if (s->stored_cb)
		s->stored_cb(s->opaque);

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
	const lws_wifi_ap_info_t *a;
	char ssid[33];

	switch (lws_wifi_settings_href(href, ssid, sizeof(ssid))) {
	case LWS_WIFI_SETTINGS_ACT_HOSTNAME:
		edit_hostname(s);
		break;

	case LWS_WIFI_SETTINGS_ACT_SET:
		lws_strncpy(s->ssid, ssid, sizeof(s->ssid));
		a = ap_listed(s, ssid);
		if (a && a->open)
			/* there's nothing to type */
			store(s, "");
		else
			edit_passphrase(s);
		break;

	case LWS_WIFI_SETTINGS_ACT_FORGET:
		if (lws_netdev_credentials_remove(lws_netdevs_from_ctx(s->cx),
						  ssid))
			lwsl_err("%s: unable to forget %s\n", __func__, ssid);
		else
			lwsl_user("%s: forgot %s\n", __func__, ssid);

		lws_dlo_ui_dialog_changed(s->ui);
		break;

	default:
		break;
	}
}

int
lhp_settings_init(lhp_settings_t *s, struct lws_context *cx,
		  lws_netdev_instance_wifi_t *wnd,
		  lhp_settings_exit_cb_t exit_cb,
		  lhp_settings_stored_cb_t stored_cb, void *opaque)
{
	lws_dlo_filesystem_t f;
	size_t n;

	memset(s, 0, sizeof(*s));
	s->cx = cx;
	s->wnd = wnd;
	s->exit_cb = exit_cb;
	s->stored_cb = stored_cb;
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
	d.css = lws_wifi_settings_css();
	d.html_max = LHP_SET_AP_MAX * AP_ROW_HTML_MAX + 1024;

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
	if (s->shown && lws_netdev_wifi_scan_sig(s->wnd) != s->scan_sig)
		lws_dlo_ui_dialog_changed(s->ui);
}

void
lhp_settings_note(lhp_settings_t *s, const char *note)
{
	lws_strncpy(s->note, note ? note : "", sizeof(s->note));
	lhp_settings_changed(s);
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
