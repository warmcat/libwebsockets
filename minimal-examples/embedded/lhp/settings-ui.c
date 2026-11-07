/*
 * lhp settings pages
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

/* rows of the "Settings" page */

enum {
	TOP_ROW_WLAN,
	TOP_ROW_HOSTNAME,

	TOP_ROWS
};

/*
 * Rows of an AP's page.  An open AP has no passphrase to change, so it only
 * has the Forget row.  It's the last, so the cursor doesn't start on it.
 */

enum {
	AP_ROW_PASSPHRASE,
	AP_ROW_FORGET,
};

static int
ap_row(const lhp_settings_t *s, int idx)
{
	return s->ssid_open ? (idx ? -1 : AP_ROW_FORGET) : idx;
}

/* WPA passphrases are 8 to 63 characters */
#define PASSPHRASE_MIN		8
#define PASSPHRASE_MAX		63

/*
 * Order-independent signature of the set of APs in the scan list, so we can
 * tell when the APs shown are stale without listing them again on every scan:
 * the averaged rssi jitters, so rssi and ordering are deliberately left out
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
			a->open = w->authmode == LWS_WIFI_AUTHMODE_OPEN;
			a->seen = 1;
		} lws_end_foreach_dll(d);
	}

	/* which we have credentials for, and those we have that weren't seen */

	lws_netdev_credentials_hold(nds);

	lws_start_foreach_dll(struct lws_dll2 *, c,
			      lws_dll2_get_head(&nds->owner_creds)) {
		const lws_wifi_creds_t *cr = lws_container_of(c,
						lws_wifi_creds_t, list);

		n = ap_find(s, cr->ssid);
		if (n >= 0) {
			s->aps[n].stored = 1;
			continue;
		}

		if (s->ap_count == LHP_SET_AP_MAX || !cr->ssid[0])
			continue;

		a = &s->aps[s->ap_count++];
		memset(a, 0, sizeof(*a));
		lws_strncpy(a->ssid, cr->ssid, sizeof(a->ssid));
		a->open = !cr->passphrase[0];
		a->stored = 1;
	} lws_end_foreach_dll(c);

	lws_netdev_credentials_release(nds);
}

/* say what the page shows now: the ui draws it when the display is free */

static void
show(lhp_settings_t *s, lhp_settings_page_t page)
{
	s->page = (uint8_t)page;

	switch (page) {
	case LHP_SET_TOP:
		lws_dlo_ui_set_title(s->ui, "Settings");
		lws_dlo_ui_set_list(s->ui, TOP_ROWS, -1);
		break;

	case LHP_SET_WLAN:
		aps_update(s);
		lws_dlo_ui_set_title(s->ui, "WLAN");
		/* with none, there's a row saying so */
		lws_dlo_ui_set_list(s->ui, s->ap_count ? s->ap_count : 1, -1);
		break;

	case LHP_SET_AP:
		lws_dlo_ui_set_title(s->ui, s->ssid);
		lws_dlo_ui_set_list(s->ui, s->ssid_open ? 1 : 2, -1);
		break;

	default:
		break;
	}
}

static void
finish(lhp_settings_t *s)
{
	s->page = LHP_SET_NONE;
	s->editing = LHP_SET_EDIT_NONE;

	if (s->exit_cb)
		s->exit_cb(s->opaque);
}

/*
 * Store the credentials for the AP that was picked.  The wifi netdev scans
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

	s->editing = LHP_SET_EDIT_NONE;

	if (s->flags & LHP_SET_FL_EXIT_ON_STORE) {
		finish(s);
		return 0;
	}

	show(s, LHP_SET_WLAN);

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

	if (lws_dlo_ui_edit(s->ui, "Hostname", LWS_NETDEV_HOSTNAME_MAX, 0)) {
		lwsl_err("%s: unable to edit hostname\n", __func__);
		return;
	}

	s->editing = LHP_SET_EDIT_HOSTNAME;

	/* it starts as it is, to be changed */
	if (lws_netdev_hostname_get(lws_netdevs_from_ctx(s->cx), hn,
				    sizeof(hn)) >= 0)
		lws_dlo_ui_edit_set(s->ui, hn);
}

void
lhp_settings_init(lhp_settings_t *s, struct lws_context *cx,
		  lws_netdev_instance_wifi_t *wnd,
		  lhp_settings_exit_cb_t exit_cb, void *opaque)
{
	memset(s, 0, sizeof(*s));
	s->cx = cx;
	s->wnd = wnd;
	s->exit_cb = exit_cb;
	s->opaque = opaque;
}

void
lhp_settings_open(lhp_settings_t *s, struct lws_dlo_ui *ui,
		  lhp_settings_page_t page, unsigned int flags)
{
	s->ui = ui;
	s->flags = (uint8_t)flags;
	s->editing = LHP_SET_EDIT_NONE;

	show(s, page == LHP_SET_WLAN ? LHP_SET_WLAN : LHP_SET_TOP);
}

void
lhp_settings_close(lhp_settings_t *s)
{
	s->page = LHP_SET_NONE;
	s->editing = LHP_SET_EDIT_NONE;
}

int
lhp_settings_shown(const lhp_settings_t *s)
{
	return s->page != LHP_SET_NONE;
}

void
lhp_settings_scan(lhp_settings_t *s)
{
	if (s->page == LHP_SET_WLAN && scan_sig(s) != s->scan_sig)
		show(s, LHP_SET_WLAN);
}

int
lhp_settings_row(lhp_settings_t *s, int idx, lws_dlo_ui_row_t *row)
{
	char hn[LWS_NETDEV_HOSTNAME_MAX + 1];

	switch (s->page) {
	case LHP_SET_TOP:
		switch (idx) {
		case TOP_ROW_WLAN:
			lws_strncpy(row->text, "WLAN", sizeof(row->text));
			return 0;
		case TOP_ROW_HOSTNAME:
			if (lws_netdev_hostname_get(lws_netdevs_from_ctx(s->cx),
						    hn, sizeof(hn)) < 0)
				lws_strncpy(hn, "-", sizeof(hn));
			lws_snprintf(row->text, sizeof(row->text),
				     "Hostname: %s", hn);
			return 0;
		}
		return 1;

	case LHP_SET_WLAN:
		if (!s->ap_count && !idx) {
			/* there's nothing to pick, but say why */
			lws_strncpy(row->text, s->wnd ? "Scanning..." :
						"No WLAN", sizeof(row->text));
			row->state = LWS_DLO_UI_ROW_DIM;
			return 0;
		}
		if (idx < 0 || idx >= s->ap_count)
			return 1;

		lws_strncpy(row->text, s->aps[idx].ssid, sizeof(row->text));
		/*
		 * The ones we can join are highlighted, those we have
		 * credentials for but can't see now are dimmed
		 */
		if (!s->aps[idx].seen)
			row->state = LWS_DLO_UI_ROW_DIM;
		else if (s->aps[idx].stored)
			row->state = LWS_DLO_UI_ROW_FOCUS;
		return 0;

	case LHP_SET_AP:
		switch (ap_row(s, idx)) {
		case AP_ROW_PASSPHRASE:
			lws_strncpy(row->text, "Change passphrase",
				    sizeof(row->text));
			return 0;
		case AP_ROW_FORGET:
			lws_strncpy(row->text, "Forget", sizeof(row->text));
			return 0;
		}
		return 1;

	default:
		return 1;
	}
}

void
lhp_settings_pick(lhp_settings_t *s, int idx)
{
	switch (s->page) {
	case LHP_SET_TOP:
		if (idx == TOP_ROW_WLAN)
			show(s, LHP_SET_WLAN);
		else if (idx == TOP_ROW_HOSTNAME)
			edit_hostname(s);
		break;

	case LHP_SET_WLAN:
		if (idx < 0 || idx >= s->ap_count)
			break;

		lws_strncpy(s->ssid, s->aps[idx].ssid, sizeof(s->ssid));
		s->ssid_open = s->aps[idx].open;

		if (s->aps[idx].stored) {
			show(s, LHP_SET_AP);
			break;
		}

		if (s->ssid_open)
			store(s, "");
		else
			edit_passphrase(s);
		break;

	case LHP_SET_AP:
		if (ap_row(s, idx) == AP_ROW_PASSPHRASE) {
			edit_passphrase(s);
			break;
		}
		if (ap_row(s, idx) != AP_ROW_FORGET)
			break;

		if (lws_netdev_credentials_remove(lws_netdevs_from_ctx(s->cx),
						  s->ssid))
			lwsl_err("%s: unable to forget %s\n", __func__,
				 s->ssid);
		else
			lwsl_user("%s: forgot %s\n", __func__, s->ssid);
		show(s, LHP_SET_WLAN);
		break;

	default:
		break;
	}
}

/* pressing the title goes back a page, or from "Settings", out of them */

void
lhp_settings_title(lhp_settings_t *s)
{
	switch (s->page) {
	case LHP_SET_AP:
		show(s, LHP_SET_WLAN);
		break;
	case LHP_SET_WLAN:
		show(s, LHP_SET_TOP);
		break;
	case LHP_SET_TOP:
		finish(s);
		break;
	default:
		break;
	}
}

/* text is what was typed, a secret if it's a passphrase, or NULL if abandoned */

int
lhp_settings_done(lhp_settings_t *s, const char *text)
{
	lhp_settings_edit_t e = (lhp_settings_edit_t)s->editing;

	if (!text) {
		/* back to the page it was edited from */
		s->editing = LHP_SET_EDIT_NONE;
		return 0;
	}

	switch (e) {
	case LHP_SET_EDIT_PASSPHRASE:
		if (strlen(text) < PASSPHRASE_MIN)
			/* keep typing */
			return 1;
		if (store(s, text))
			/* keep it, to try again */
			return 1;
		s->editing = LHP_SET_EDIT_NONE;
		return 0;

	case LHP_SET_EDIT_HOSTNAME:
		/* nothing typed goes back to the default hostname */
		if (lws_netdev_hostname_set(lws_netdevs_from_ctx(s->cx), text))
			/* not a valid hostname: keep editing it */
			return 1;
		s->editing = LHP_SET_EDIT_NONE;
		/* the hostname row says what it is now */
		show(s, LHP_SET_TOP);
		return 0;

	default:
		return 0;
	}
}
