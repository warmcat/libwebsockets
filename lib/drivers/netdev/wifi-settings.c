/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The wifi settings, as html: the APs we know of, scanned and stored, and the
 * hostname.  The same html is shown as a dialog on a device's own display,
 * and served to a browser by the device, eg, while it is an AP to be given
 * credentials, see lws_wifi_provision_create().  Its links are the same in
 * both, see lws_wifi_settings_href().
 */

#include "private-lib-core.h"

/*
 * Small icons, in the dialog's text size or a bit bigger to press, with a line
 * around and between the APs' rows so they read as one list.  Each AP's row is
 * three cells, so it fits a small display: its signal, its SSID over a smaller
 * line of what we know about it, then the icons to press.  When the SSID and
 * its line are a link, it's a block, so all of the cell can be pressed.  The
 * hostname is shaded, like an editbox.
 */

static const char settings_css[] =
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
		" margin: 2px 0 8px 0 }"
	"a.n { display: block }";

const char *
lws_wifi_settings_css(void)
{
	return settings_css;
}

int
lws_wifi_rssi_bars(int rssi)
{
	if (rssi >= -55)
		return 4;
	if (rssi >= -65)
		return 3;
	if (rssi >= -75)
		return 2;

	return 1;
}

uint32_t
lws_netdev_wifi_scan_sig(const lws_netdev_instance_wifi_t *wnd)
{
	uint32_t sig = 0;

	if (!wnd)
		return 0;

	/*
	 * Order-independent, and of the bars rather than the averaged rssi,
	 * which jitters while the bars it is shown as change much less often
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&wnd->scan)) {
		lws_wifi_sta_t *w = lws_container_of(d, lws_wifi_sta_t, list);
		uint32_t h = 2166136261u;
		int n;

		for (n = 0; n < LWS_ETH_ALEN; n++)
			h = (h ^ w->bssid[n]) * 16777619u;
		h = (h ^ (uint8_t)w->ch) * 16777619u;
		h = (h ^ (uint8_t)lws_wifi_rssi_bars(rssi_averaged(w))) *
								16777619u;
		sig += h;
	} lws_end_foreach_dll(d);

	return sig;
}

static int
ap_find(const lws_wifi_ap_info_t *aps, int count, const char *ssid)
{
	int n;

	for (n = 0; n < count; n++)
		if (!strcmp(aps[n].ssid, ssid))
			return n;

	return -1;
}

int
lws_netdev_wifi_ap_list(lws_netdevs_t *nds,
			const lws_netdev_instance_wifi_t *wnd,
			lws_wifi_ap_info_t *aps, int max)
{
	lws_wifi_ap_info_t *a;
	int count = 0, n;

	/*
	 * The networks in the scan results, the strongest BSS of each,
	 * strongest first as the scan is sorted.  Hidden networks, with no
	 * SSID, can't be picked.
	 */

	if (wnd) {
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&wnd->scan)) {
			lws_wifi_sta_t *w = lws_container_of(d,
						lws_wifi_sta_t, list);
			char ssid[33];

			if (count == max)
				break;

			lws_strnncpy(ssid, w->ssid, w->ssid_len, sizeof(ssid));
			if (!ssid[0] || ap_find(aps, count, ssid) >= 0)
				continue;

			a = &aps[count++];
			memset(a, 0, sizeof(*a));
			memcpy(a->ssid, ssid, sizeof(a->ssid));
			a->auth = w->authmode;
			a->open = w->authmode == LWS_WIFI_AUTH_OPEN;
			a->seen = 1;
			a->bars = (uint8_t)lws_wifi_rssi_bars(rssi_averaged(w));
		} lws_end_foreach_dll(d);
	}

	/*
	 * Which we have credentials for, how joining them went, and those we
	 * have that weren't seen, after the others
	 */

	lws_netdev_credentials_hold(nds);

	lws_start_foreach_dll(struct lws_dll2 *, c,
			      lws_dll2_get_head(&nds->owner_creds)) {
		const lws_wifi_creds_t *cr = lws_container_of(c,
						lws_wifi_creds_t, list);

		n = ap_find(aps, count, cr->ssid);
		if (n < 0) {
			if (count == max || !cr->ssid[0])
				continue;

			n = count++;
			a = &aps[n];
			memset(a, 0, sizeof(*a));
			lws_strncpy(a->ssid, cr->ssid, sizeof(a->ssid));
			a->open = !cr->passphrase[0];
		}

		a = &aps[n];
		a->stored = 1;
		a->last_join = cr->last_join;
		a->internet = cr->internet;
	} lws_end_foreach_dll(c);

	lws_netdev_credentials_release(nds);

	return count;
}

static void
img(lws_html_w_t *w, const char *name)
{
	lws_html_w_printf(w, "<img src=\"%s\">", name);
}

static void
link_icon(lws_html_w_t *w, const char *act, const char *ssid, const char *icon)
{
	lws_html_w_printf(w, "<a class=\"i\" href=\"?%s=", act);
	lws_html_w_urlarg(w, ssid, 32);
	lws_html_w_printf(w, "\"><img src=\"%s\"></a>", icon);
}

void
lws_wifi_settings_html(lws_html_w_t *w, const lws_wifi_ap_info_t *aps,
		       int count, int have_wlan, const char *hostname)
{
	const lws_wifi_ap_info_t *a;
	int n;

	lws_html_w_printf(w, "<div class=\"s\">WLAN</div>");

	if (!count)
		/* there's nothing to pick, but say why */
		lws_html_w_printf(w, "<div class=\"d\">%s</div>",
				  have_wlan ? "Scanning..." : "No WLAN");
	else
		lws_html_w_printf(w, "<table>");

	for (n = 0; n < count; n++) {
		a = &aps[n];

		/*
		 * Its signal first, all the bars unlit if it wasn't seen.
		 * Those we have credentials for but can't see are dimmed.
		 */
		lws_html_w_printf(w, "<tr%s><td class=\"g\"><img class=\"g\" "
				  "src=\"" LWS_WIFI_SETTINGS_ICON_SIG "%d.svg\">"
				  "</td><td>", a->seen ? "" : " class=\"d\"",
				  (int)(a->bars > 4 ? 4 : a->bars));

		/*
		 * With no passphrase of ours for it, there's nothing to lose by
		 * pressing its name: it does what its cog does.  One we have
		 * isn't replaced so easily, only by its cog.
		 */
		if (!a->stored) {
			lws_html_w_printf(w, "<a class=\"n\" href=\"?set=");
			lws_html_w_urlarg(w, a->ssid, 32);
			lws_html_w_printf(w, "\">");
		}

		lws_html_w_printf(w, "<div>");
		lws_html_w_text(w, a->ssid, sizeof(a->ssid));
		lws_html_w_printf(w, "</div><div class=\"st\">");
		if (a->stored && !a->open)
			img(w, LWS_WIFI_SETTINGS_ICON_KEY);
		if (a->seen)
			lws_html_w_printf(w, "%s ", lws_wifi_auth_name(
						(lws_wifi_auth_t)a->auth));

		/* how the last try to join it went */
		switch (a->last_join) {
		case LWS_WIFI_JOIN_OK:
			img(w, LWS_WIFI_SETTINGS_ICON_OK);
			break;
		case LWS_WIFI_JOIN_AUTH_FAILED:
			img(w, LWS_WIFI_SETTINGS_ICON_REFUSED);
			break;
		case LWS_WIFI_JOIN_FAILED:
			img(w, LWS_WIFI_SETTINGS_ICON_FAILED);
			break;
		default:
			break;
		}

		if (a->internet)
			img(w, LWS_WIFI_SETTINGS_ICON_NET);
		lws_html_w_printf(w, "</div>%s</td><td>",
				  a->stored ? "" : "</a>");
		/* an open AP that's stored has no passphrase to set */
		if (!a->open || !a->stored)
			link_icon(w, "set", a->ssid, LWS_WIFI_SETTINGS_ICON_COG);
		if (a->stored)
			link_icon(w, "forget", a->ssid,
				  LWS_WIFI_SETTINGS_ICON_FORGET);
		lws_html_w_printf(w, "</td></tr>");
	}

	if (count)
		lws_html_w_printf(w, "</table>");

	lws_html_w_printf(w, "<div class=\"s\">Hostname</div>"
			     "<a class=\"e\" href=\"?host\">");
	lws_html_w_text(w, hostname && *hostname ? hostname : "-",
			LWS_NETDEV_HOSTNAME_MAX);
	lws_html_w_printf(w, "</a>");
}

lws_wifi_settings_act_t
lws_wifi_settings_href(const char *href, char *ssid, size_t ssid_len)
{
	static const struct {
		const char		*prefix;
		lws_wifi_settings_act_t	act;
	} acts[] = {
		{ "?set=",	LWS_WIFI_SETTINGS_ACT_SET },
		{ "?forget=",	LWS_WIFI_SETTINGS_ACT_FORGET },
	};
	/* a 32-character SSID, all of it %-encoded */
	char dec[(32 * 3) + 1];
	size_t n, pl;

	if (!strcmp(href, "?host"))
		return LWS_WIFI_SETTINGS_ACT_HOSTNAME;

	for (n = 0; n < LWS_ARRAY_SIZE(acts); n++) {
		pl = strlen(acts[n].prefix);
		if (strncmp(href, acts[n].prefix, pl))
			continue;

		/*
		 * Decoded into room for more than an SSID can be, so one too
		 * long is refused rather than truncated into another
		 */
		if (!href[pl] || strlen(href + pl) >= sizeof(dec) ||
		    lws_urldecode(dec, href + pl, (int)sizeof(dec)) ||
		    !dec[0] || strlen(dec) > 32 || strlen(dec) >= ssid_len)
			return LWS_WIFI_SETTINGS_ACT_NONE;

		lws_strncpy(ssid, dec, ssid_len);

		return acts[n].act;
	}

	return LWS_WIFI_SETTINGS_ACT_NONE;
}
