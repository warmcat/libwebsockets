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
 * Giving a device wifi credentials when it has none it can use: it becomes an
 * AP of its own, and serves the wifi settings to whoever joins it, see
 * lws_wifi_provision_create()
 */

#include "private-lib-core.h"

#define PROV_PORT_DEFAULT		80
#define PROV_JOIN_WAIT_S_DEFAULT	60
#define PROV_RESET_WINDOW_S_DEFAULT	10
#define PROV_RESET_HOLD_S_DEFAULT	5
/* how long the page saying we're restarting has to reach the browser */
#define PROV_REBOOT_DELAY_US		(3 * LWS_US_PER_SEC)
/* how long the led acknowledges a reset before we restart */
#define PROV_RESET_ACK_US		(2 * LWS_US_PER_SEC)
/* the most APs listed, as on the device's own settings */
#define PROV_AP_MAX			12
/* the settings' html, and room for the rest of the page around it */
#define PROV_SETTINGS_MAX		((PROV_AP_MAX * \
					  LWS_WIFI_SETTINGS_AP_HTML_MAX) + 512)
#define PROV_PAGE_MAX			(PROV_SETTINGS_MAX + 2048)
/* WPA passphrases are 8 to 63 characters */
#define PASSPHRASE_MIN			8
#define PASSPHRASE_MAX			63

struct lws_wifi_provision {
	lws_wifi_provision_info_t	i;
	struct lws_smd_peer		*smd;
	struct lws_vhost		*vh;

	lws_sorted_usec_list_t		sul_join;	/* waiting to join */
	lws_sorted_usec_list_t		sul_window;	/* reset button window */
	lws_sorted_usec_list_t		sul_hold;	/* reset button held */
	lws_sorted_usec_list_t		sul_reboot;

	struct lws_protocols		protocols[3];
	struct lws_http_mount		mount;

	/* scratch for listing the APs, we're single-threaded */
	lws_wifi_ap_info_t		aps[PROV_AP_MAX];

	char				ssid[LWS_NETDEV_HOSTNAME_MAX + 1];
	char				url[32];
	char				joining[33]; /* stored to be joined */

	uint8_t				state; /* lws_wifi_provision_state_t */
	uint8_t				ap; /* we're an AP, serving the settings */
	uint8_t				window_open;
};

/* each http transaction */

struct pss {
	struct lws_spa			*spa;
	char				*page;
	const lws_wifi_provision_file_t	*file;
	size_t				len;
	size_t				sent;
	char				post;
};

#if defined(LWS_ROLE_WS)
/*
 * each browser showing the settings, with a websocket to us to be sent the
 * APs again when they change
 */

struct pss_ws {
	uint32_t			sig;	/* of what was sent last */
	uint8_t				sent;	/* anything was */
};

#define PROV_WS_PROTOCOL		"lws-wifi-settings"
#endif

enum {
	PRM_ACT,
	PRM_SSID,
	PRM_PASS,
	PRM_HOST,
};

static const char * const param_names[] = {
	"act",
	"ssid",
	"pass",
	"host",
};

/* served as wifi.css after lws_wifi_settings_css(), for the pages' own parts */

static const char page_css[] =
	"body { font-family: sans-serif; margin: 12px; max-width: 32em }"
	"h1 { font-size: 1.25em; color: #24476b }"
	"input { display: block; width: 100%; box-sizing: border-box;"
		" font-size: 1em; padding: 4px; margin: 4px 0 8px 0 }"
	"button { font-size: 1em; padding: 4px 16px; margin-right: 8px }"
	".err { color: #b00020 }";

#if defined(LWS_ROLE_WS)
/*
 * served as wifi.js: keeps the settings' list of APs live, as the device
 * sends it again over a websocket.  It's html we wrote, its text escaped.
 */

static const char page_js[] =
	"(function () {\n"
	"\t\"use strict\";\n"
	"\tvar w = document.getElementById(\"w\");\n"
	"\n"
	"\tif (!w || !window.WebSocket)\n"
	"\t\treturn;\n"
	"\n"
	"\tfunction connect() {\n"
	"\t\tvar ws = new WebSocket((location.protocol === \"https:\" ?\n"
	"\t\t\t\"wss://\" : \"ws://\") + location.host + \"/\",\n"
	"\t\t\t\"" PROV_WS_PROTOCOL "\");\n"
	"\n"
	"\t\tws.onmessage = function (e) {\n"
	"\t\t\tw.innerHTML = e.data;\n"
	"\t\t};\n"
	"\t\t/* eg, it restarted: it may be back */\n"
	"\t\tws.onclose = function () {\n"
	"\t\t\tsetTimeout(connect, 5000);\n"
	"\t\t};\n"
	"\t}\n"
	"\n"
	"\tconnect();\n"
	"}());\n";

static const lws_wifi_provision_file_t file_js = {
	"wifi.js", page_js, sizeof(page_js) - 1, "text/javascript"
};
#endif

static void
prov_state(struct lws_wifi_provision *p, lws_wifi_provision_state_t st)
{
	if (p->state == (uint8_t)st)
		return;

	p->state = (uint8_t)st;
	if (p->i.cb)
		p->i.cb(p->i.opaque, st);
}

static void
prov_led(struct lws_wifi_provision *p, const lws_led_sequence_def_t *seq)
{
	if (p->i.lls && p->i.led)
		lws_led_transition(p->i.lls, p->i.led, seq,
				   &lws_pwmseq_linear_wipe);
}

static void
prov_ap_stop(struct lws_wifi_provision *p);

/*
 * What the settings show may have changed, eg, a scan finished, or something
 * was stored: each browser showing them is sent them again if they did
 */

static void
prov_live(struct lws_wifi_provision *p)
{
#if defined(LWS_ROLE_WS)
	const struct lws_protocols *pr;

	if (!p->vh)
		return;

	pr = lws_vhost_name_to_protocol(p->vh, PROV_WS_PROTOCOL);
	if (pr)
		lws_callback_on_writable_all_protocol_vhost(p->vh, pr);
#endif
}

static void
prov_reboot_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_wifi_provision *p = lws_container_of(sul,
				struct lws_wifi_provision, sul_reboot);
	const lws_system_ops_t *ops = lws_system_get_ops(p->i.cx);

	if (ops && ops->reboot) {
		lwsl_notice("%s: restarting\n", __func__);
		ops->reboot();
		return;
	}

	/*
	 * We can't restart: stop being an AP, so the station can join what was
	 * stored, the way it does when credentials are stored while it's
	 * running
	 */
	lwsl_notice("%s: no reboot op, carrying on\n", __func__);
	prov_ap_stop(p);
	prov_state(p, LWS_WIFI_PROV_IDLE);
}

static void
prov_reboot(struct lws_wifi_provision *p, lws_usec_t us)
{
	prov_state(p, LWS_WIFI_PROV_REBOOT);
	lws_sul_schedule(p->i.cx, 0, &p->sul_reboot, prov_reboot_cb, us);
}

/*
 * The http side: the settings page, a page for each of its links, and the
 * forms on those posting back to it
 */

static void
page_start(struct lws_wifi_provision *p, lws_html_w_t *w, const char *title,
	   int live)
{
	lws_html_w_printf(w, "<!doctype html><html><head><meta charset=\"utf-8\">"
			     "<meta name=\"viewport\" content=\"width=device-"
			     "width, initial-scale=1\"><title>");
	lws_html_w_text(w, title, 64);
	lws_html_w_printf(w, "</title><link rel=\"stylesheet\" "
			     "href=\"wifi.css\">");
#if defined(LWS_ROLE_WS)
	if (live)
		lws_html_w_printf(w, "<script src=\"wifi.js\" defer></script>");
#endif
	lws_html_w_printf(w, "</head><body>");
	if (p->i.header_html)
		/* the caller's own */
		lws_html_w_printf(w, "%s", p->i.header_html);
	lws_html_w_printf(w, "<h1>");
	lws_html_w_text(w, title, 64);
	lws_html_w_printf(w, "</h1>");
}

static void
page_end(lws_html_w_t *w)
{
	lws_html_w_printf(w, "</body></html>");
}

static void
form_start(lws_html_w_t *w, const char *act, const char *ssid)
{
	lws_html_w_printf(w, "<form method=\"post\" action=\"./\">"
			     "<input type=\"hidden\" name=\"act\" value=\"%s\">",
			     act);
	if (ssid) {
		lws_html_w_printf(w, "<input type=\"hidden\" name=\"ssid\" "
				     "value=\"");
		lws_html_w_text(w, ssid, 32);
		lws_html_w_printf(w, "\">");
	}
}

static void
form_end(lws_html_w_t *w, const char *button)
{
	lws_html_w_printf(w, "<button type=\"submit\">%s</button>"
			     "<a href=\"./\">Back</a></form>", button);
}

/* the settings as they are now, also what's sent to keep them live */

static void
settings_html(struct lws_wifi_provision *p, lws_html_w_t *w)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(p->i.cx);
	char hn[LWS_NETDEV_HOSTNAME_MAX + 1];
	int n;

	if (lws_netdev_hostname_get(nds, hn, sizeof(hn)) < 0)
		hn[0] = '\0';

	n = lws_netdev_wifi_ap_list(nds, p->i.wnd, p->aps, PROV_AP_MAX);
	lws_wifi_settings_html(w, p->aps, n, 1, hn);
}

static void
page_settings(struct lws_wifi_provision *p, lws_html_w_t *w)
{
	page_start(p, w, "Settings", 1);
	/* what wifi.js replaces with what we send it */
	lws_html_w_printf(w, "<div id=\"w\">");
	settings_html(p, w);
	lws_html_w_printf(w, "</div>");
	page_end(w);
}

static void
page_set(struct lws_wifi_provision *p, lws_html_w_t *w, const char *ssid,
	 const char *err)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(p->i.cx);
	int n, open = 0;

	/* if it's in range and open, there's no passphrase to type */
	n = lws_netdev_wifi_ap_list(nds, p->i.wnd, p->aps, PROV_AP_MAX);
	while (n--)
		if (!strcmp(p->aps[n].ssid, ssid) && p->aps[n].seen)
			open = p->aps[n].open;

	page_start(p, w, open ? "Join" : "Passphrase", 0);
	if (err)
		lws_html_w_printf(w, "<p class=\"err\">%s</p>", err);
	lws_html_w_printf(w, "<p>");
	lws_html_w_text(w, ssid, 32);
	lws_html_w_printf(w, "</p>");
	form_start(w, "set", ssid);

	/*
	 * It's shown as it's typed, as on the device's own display, so typos
	 * can be seen.  What is stored is never shown, it starts empty.
	 */
	if (!open)
		lws_html_w_printf(w, "<input type=\"text\" name=\"pass\" "
				     "minlength=\"%d\" maxlength=\"%d\" "
				     "autocomplete=\"off\" autocapitalize=\"none\" "
				     "spellcheck=\"false\" required autofocus>",
				     PASSPHRASE_MIN, PASSPHRASE_MAX);
	form_end(w, open ? "Join" : "Done");
	page_end(w);
}

static void
page_forget(struct lws_wifi_provision *p, lws_html_w_t *w, const char *ssid)
{
	page_start(p, w, "Forget", 0);
	lws_html_w_printf(w, "<p>");
	lws_html_w_text(w, ssid, 32);
	lws_html_w_printf(w, "</p>");
	form_start(w, "forget", ssid);
	form_end(w, "Forget");
	page_end(w);
}

static void
page_host(struct lws_wifi_provision *p, lws_html_w_t *w, const char *err)
{
	char hn[LWS_NETDEV_HOSTNAME_MAX + 1];

	if (lws_netdev_hostname_get(lws_netdevs_from_ctx(p->i.cx), hn,
				    sizeof(hn)) < 0)
		hn[0] = '\0';

	page_start(p, w, "Hostname", 0);
	if (err)
		lws_html_w_printf(w, "<p class=\"err\">%s</p>", err);
	form_start(w, "host", NULL);
	lws_html_w_printf(w, "<input type=\"text\" name=\"host\" "
			     "maxlength=\"%d\" autocomplete=\"off\" "
			     "autocapitalize=\"none\" spellcheck=\"false\" "
			     "value=\"", LWS_NETDEV_HOSTNAME_MAX);
	lws_html_w_text(w, hn, sizeof(hn));
	lws_html_w_printf(w, "\">");
	form_end(w, "Done");
	page_end(w);
}

static void
page_restarting(struct lws_wifi_provision *p, lws_html_w_t *w)
{
	page_start(p, w, "Restarting", 0);
	lws_html_w_printf(w, "<p>Restarting to join ");
	lws_html_w_text(w, p->joining, sizeof(p->joining));
	lws_html_w_printf(w, "</p><p>If it can't, it will be at ");
	lws_html_w_text(w, p->ssid, sizeof(p->ssid));
	lws_html_w_printf(w, " again.</p>");
	page_end(w);
}

/* send what's in pss->page, or the file, as the response */

static int
respond(struct lws *wsi, struct pss *pss, unsigned int code,
	const char *mimetype)
{
	/* the security headers, eg, the CSP, take most of it */
	uint8_t buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	if (lws_add_http_common_headers(wsi, code, mimetype, pss->len, &p,
					end) ||
	    /* it changes with the scans and what's stored */
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CACHE_CONTROL,
				(const uint8_t *)"no-store", 8, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	lws_callback_on_writable(wsi);

	return 0;
}

static int
respond_page(struct lws *wsi, struct pss *pss, lws_html_w_t *w)
{
	int n = lws_html_w_len(w, pss->page);

	if (n < 0) {
		lwsl_err("%s: page too big\n", __func__);
		return lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
					      NULL) ? -1 : 0;
	}

	pss->len = (size_t)n;

	return respond(wsi, pss, HTTP_STATUS_OK, "text/html; charset=utf-8");
}

static int
page_alloc(struct pss *pss, lws_html_w_t *w)
{
	pss->page = lws_malloc(PROV_PAGE_MAX, __func__);
	if (!pss->page)
		return 1;

	lws_html_w_init(w, pss->page, PROV_PAGE_MAX);

	return 0;
}

static void
pss_free(struct pss *pss)
{
	if (pss->spa) {
		lws_spa_destroy(pss->spa);
		pss->spa = NULL;
	}
	lws_free_set_NULL(pss->page);
}

/* a GET of the settings, or a page for one of their links */

static int
http_get(struct lws_wifi_provision *p, struct lws *wsi, struct pss *pss,
	 const char *path)
{
	char ssid[33];
	lws_html_w_t w;
	size_t n;
	int r;

	if (strcmp(path, "/") && *path) {
		if (*path == '/')
			path++;

		if (!strcmp(path, "wifi.css")) {
			if (page_alloc(pss, &w))
				return -1;
			lws_html_w_printf(&w, "%s%s%s", lws_wifi_settings_css(),
					  page_css, p->i.css ? p->i.css : "");
			r = lws_html_w_len(&w, pss->page);
			if (r < 0)
				return lws_return_http_status(wsi,
					HTTP_STATUS_INTERNAL_SERVER_ERROR,
					NULL) ? -1 : 0;
			pss->len = (size_t)r;

			return respond(wsi, pss, HTTP_STATUS_OK, "text/css");
		}

#if defined(LWS_ROLE_WS)
		if (!strcmp(path, file_js.name)) {
			pss->file = &file_js;
			pss->len = file_js.len;

			return respond(wsi, pss, HTTP_STATUS_OK,
				       file_js.mimetype);
		}
#endif

		for (n = 0; n < p->i.count_files; n++)
			if (!strcmp(path, p->i.files[n].name)) {
				pss->file = &p->i.files[n];
				pss->len = pss->file->len;

				return respond(wsi, pss, HTTP_STATUS_OK,
					       pss->file->mimetype);
			}

		return lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND,
					      NULL) ? -1 : 0;
	}

	if (page_alloc(pss, &w))
		return -1;

	/* the same links as the settings on the device's own display */

	r = lws_get_urlarg_by_name_safe(wsi, "set", ssid, sizeof(ssid));
	if (r > 0) {
		page_set(p, &w, ssid, NULL);
		return respond_page(wsi, pss, &w);
	}

	r = lws_get_urlarg_by_name_safe(wsi, "forget", ssid, sizeof(ssid));
	if (r > 0) {
		page_forget(p, &w, ssid);
		return respond_page(wsi, pss, &w);
	}

	if (lws_get_urlarg_by_name_safe(wsi, "host", ssid, sizeof(ssid)) >= 0) {
		page_host(p, &w, NULL);
		return respond_page(wsi, pss, &w);
	}

	page_settings(p, &w);

	return respond_page(wsi, pss, &w);
}

static int
redirect(struct lws *wsi, int code, const char *to)
{
	uint8_t buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	/* it has no body: the transaction is complete, keepalive or not */
	if (lws_http_redirect(wsi, code, (const uint8_t *)to,
			      (int)strlen(to), &p, end) < 0 ||
	    lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static int
see_settings(struct lws *wsi)
{
	/* the settings again, by GET, so reloading doesn't post it again */
	return redirect(wsi, HTTP_STATUS_SEE_OTHER, "./");
}

/*
 * Whether the request is for us, by our address, or for some other host that
 * the captive dns made us, eg, the url a phone checks for internet with.  A
 * request with no Host, eg, http/1.0, can only be for us.
 */

static int
for_us(struct lws_wifi_provision *p, struct lws *wsi)
{
	char host[64], *colon;
	int n;

	if (!p->i.wnd->ap_ipv4[0] ||
	    !lws_hdr_total_length(wsi, WSI_TOKEN_HOST))
		return 1;

	n = lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST);
	if (n <= 0)
		/* too long to be our address */
		return 0;

	/* our address is IPv4, any :port is after it */
	colon = strchr(host, ':');
	if (colon)
		*colon = '\0';

	return !strcmp(host, p->i.wnd->ap_ipv4);
}

/* a form was posted */

static int
http_post(struct lws_wifi_provision *p, struct lws *wsi, struct pss *pss)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(p->i.cx);
	const char *act = lws_spa_get_string(pss->spa, PRM_ACT),
		   *ssid = lws_spa_get_string(pss->spa, PRM_SSID),
		   *pass = lws_spa_get_string(pss->spa, PRM_PASS),
		   *host = lws_spa_get_string(pss->spa, PRM_HOST);
	lws_html_w_t w;
	size_t pl;

	if (!act)
		goto bad;

	if (!strcmp(act, "host")) {
		/* nothing typed goes back to the default */
		if (!lws_netdev_hostname_set(nds, host ? host : "")) {
			prov_live(p);
			return see_settings(wsi);
		}

		if (page_alloc(pss, &w))
			return -1;
		page_host(p, &w, "Use a-z, 0-9 and '-', not at the start or "
				 "end");

		return respond_page(wsi, pss, &w);
	}

	if (!ssid || !*ssid || strlen(ssid) > 32)
		goto bad;

	if (!strcmp(act, "forget")) {
		if (lws_netdev_credentials_remove(nds, ssid))
			lwsl_warn("%s: nothing to forget\n", __func__);
		else
			prov_live(p);

		return see_settings(wsi);
	}

	if (strcmp(act, "set"))
		goto bad;

	/* an open AP is posted with no passphrase */
	pl = pass ? strlen(pass) : 0;
	if (pl && (pl < PASSPHRASE_MIN || pl > PASSPHRASE_MAX)) {
		if (page_alloc(pss, &w))
			return -1;
		page_set(p, &w, ssid, "A passphrase is 8 to 63 characters");

		return respond_page(wsi, pss, &w);
	}

	if (lws_netdev_credentials_add(nds, ssid, pl ? pass : "")) {
		lwsl_err("%s: unable to store credentials\n", __func__);
		return lws_return_http_status(wsi,
				HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL) ? -1 : 0;
	}

	lwsl_user("%s: stored credentials for %s\n", __func__, ssid);
	lws_strncpy(p->joining, ssid, sizeof(p->joining));

	if (page_alloc(pss, &w))
		return -1;
	page_restarting(p, &w);

	/* restart to join it, once this page has had time to arrive */
	lws_wifi_provision_stored(p);

	return respond_page(wsi, pss, &w);

bad:
	return lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL) ?
									-1 : 0;
}

static int
callback_provision(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct lws_wifi_provision *p;
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 1024];
	size_t chunk;
	int n;

	switch (reason) {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
	{
		/* user is the args here, not a pss */
		struct lws_filter_network_conn_args *fa =
				(struct lws_filter_network_conn_args *)user;
		char ads[64];

		/*
		 * Somebody joined our AP and connected: rare, and the first
		 * thing to look for when a browser can't reach us
		 */
		ads[0] = '\0';
		if (fa)
			lws_sa46_write_numeric_address(
					(lws_sockaddr46 *)&fa->cli_addr,
					ads, sizeof(ads));
		lwsl_notice("%s: connection from %s\n", __func__, ads);
		break;
	}
#endif

	case LWS_CALLBACK_HTTP:
		p = (struct lws_wifi_provision *)lws_vhost_user(
							lws_get_vhost(wsi));
		if (!p || !pss)
			return -1;

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
		{
			char ua[192]; /* a browser's can be long */

			/*
			 * The path, never the body, which holds the passphrase.
			 * The user agent tells a browser from the phone's own
			 * check of whether the network has internet.
			 */
			if (lws_hdr_copy(wsi, ua, sizeof(ua),
					 WSI_TOKEN_HTTP_USER_AGENT) <= 0)
				ua[0] = '\0';
			lwsl_notice("%s: %s %s (%s)\n", __func__,
				    lws_hdr_total_length(wsi,
					WSI_TOKEN_POST_URI) ? "POST" :
				    (lws_hdr_total_length(wsi,
					WSI_TOKEN_HEAD_URI) ? "HEAD" : "GET"),
				    (const char *)in, ua);
		}
#endif

		/* what a transaction before on the connection left, if any */
		pss_free(pss);
		memset(pss, 0, sizeof(*pss));

		/*
		 * For another host, eg, a phone checking for internet: what's
		 * here is the settings, at our own address
		 */
		if (!for_us(p, wsi))
			return redirect(wsi, HTTP_STATUS_FOUND, p->url);

		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
			if (strcmp((const char *)in, "/") && *(const char *)in)
				return lws_return_http_status(wsi,
					HTTP_STATUS_NOT_FOUND, NULL) ? -1 : 0;
			/* the form comes in the body */
			pss->post = 1;

			return 0;
		}

		return http_get(p, wsi, pss, (const char *)in);

	case LWS_CALLBACK_HTTP_BODY:
		if (!pss || !pss->post)
			return -1;

		if (!pss->spa) {
			/* the most any of them can be, a hostname less so */
			pss->spa = lws_spa_create(wsi, param_names,
					LWS_ARRAY_SIZE(param_names), 256,
					NULL, NULL);
			if (!pss->spa)
				return -1;
		}

		if (lws_spa_process(pss->spa, in, (int)len))
			return -1;

		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		p = (struct lws_wifi_provision *)lws_vhost_user(
							lws_get_vhost(wsi));
		if (!p || !pss || !pss->post)
			return -1;

		if (!pss->spa)
			/* an empty form */
			return lws_return_http_status(wsi,
					HTTP_STATUS_BAD_REQUEST, NULL) ? -1 : 0;

		lws_spa_finalize(pss->spa);
		n = http_post(p, wsi, pss);

		/* it held a passphrase */
		lws_spa_destroy(pss->spa);
		pss->spa = NULL;

		return n;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || (!pss->page && !pss->file))
			break;

		chunk = pss->len - pss->sent;
		if (chunk > sizeof(buf) - LWS_PRE)
			chunk = sizeof(buf) - LWS_PRE;

		memcpy(buf + LWS_PRE, (pss->file ?
				(const char *)pss->file->data : pss->page) +
				pss->sent, chunk);
		pss->sent += chunk;

		if (lws_write(wsi, buf + LWS_PRE, chunk,
			      pss->sent == pss->len ? LWS_WRITE_HTTP_FINAL :
						      LWS_WRITE_HTTP) !=
							(int)chunk)
			return -1;

		if (pss->sent != pss->len) {
			lws_callback_on_writable(wsi);
			break;
		}

		pss_free(pss);
		pss->file = NULL;

		if (lws_http_transaction_completed(wsi))
			return -1;
		break;

	case LWS_CALLBACK_CLOSED_HTTP:
	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (pss)
			pss_free(pss);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_ROLE_WS)

/*
 * The browser showing the settings has a websocket to us: it's sent them when
 * it connects, then again whenever they're different, as wifi.js shows them
 */

static int
callback_settings_ws(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct pss_ws *pss = (struct pss_ws *)user;
	struct lws_wifi_provision *p;
	uint32_t sig = 2166136261u;
	lws_html_w_t w;
	char *buf;
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		p = (struct lws_wifi_provision *)lws_vhost_user(
							lws_get_vhost(wsi));
		/*
		 * Only from our own pages: with the captive dns, a page of any
		 * other host is at our address as well
		 */
		if (!p || !for_us(p, wsi)) {
			lwsl_notice("%s: refusing websocket for another host\n",
				    __func__);
			return 1;
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/* they may have changed since the page was served */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		p = (struct lws_wifi_provision *)lws_vhost_user(
							lws_get_vhost(wsi));
		if (!p || !pss)
			return -1;

		buf = lws_malloc(LWS_PRE + PROV_SETTINGS_MAX, __func__);
		if (!buf)
			return -1;

		lws_html_w_init(&w, buf + LWS_PRE, PROV_SETTINGS_MAX);
		settings_html(p, &w);
		n = lws_html_w_len(&w, buf + LWS_PRE);
		if (n < 0) {
			lwsl_err("%s: settings too big\n", __func__);
			lws_free(buf);
			return -1;
		}

		/* only if they're different from what was sent last */
		for (m = 0; m < n; m++)
			sig = (sig ^ (uint8_t)buf[LWS_PRE + m]) * 16777619u;

		if (pss->sent && sig == pss->sig) {
			lws_free(buf);
			break;
		}

		m = lws_write(wsi, (unsigned char *)buf + LWS_PRE, (size_t)n,
			      LWS_WRITE_TEXT);
		lws_free(buf);
		if (m < n)
			return -1;

		pss->sig = sig;
		pss->sent = 1;
		break;

	case LWS_CALLBACK_RECEIVE:
		/* there's nothing for the browser to tell us this way */
		break;

	default:
		break;
	}

	return 0;
}

#endif

/*
 * Being an AP, and serving the settings on it
 */

static int
prov_ap_start(struct lws_wifi_provision *p)
{
	struct lws_context_creation_info info;
	unsigned int port;

	if (p->ap)
		return 0;

	if (lws_netdev_wifi_ap(&p->i.wnd->inst, p->ssid,
			       p->i.ap_passphrase)) {
		lwsl_err("%s: unable to be an AP\n", __func__);
		return 1;
	}

	port = p->i.port ? p->i.port : PROV_PORT_DEFAULT;
	if (port == 80)
		lws_snprintf(p->url, sizeof(p->url), "http://%s/",
			     p->i.wnd->ap_ipv4);
	else
		lws_snprintf(p->url, sizeof(p->url), "http://%s:%u/",
			     p->i.wnd->ap_ipv4, port);

	memset(&info, 0, sizeof(info));
	info.vhost_name		= "wifi-provision";
	info.port		= (int)port;
	/* only on our AP, not wherever the station joins */
	info.iface		= p->i.wnd->ap_ipv4[0] ? p->i.wnd->ap_ipv4 :
							  NULL;
	info.protocols		= p->protocols;
	info.mounts		= &p->mount;
	info.user		= p;
	info.options		= LWS_SERVER_OPTION_DISABLE_IPV6 |
			LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	p->vh = lws_create_vhost(p->i.cx, &info);
	if (!p->vh) {
		lwsl_err("%s: unable to serve the settings\n", __func__);
		lws_netdev_wifi_ap(&p->i.wnd->inst, NULL, NULL);
		return 1;
	}

#if defined(LWS_WITH_SYS_CAPTIVE_DNS)
	/*
	 * Every name is us to whoever joins, so their OS's check for internet
	 * comes to us, and is redirected to the settings: it tells them the
	 * network wants them to sign in, and shows the settings.  Without it,
	 * the settings are still at our address, if they know it.
	 */
	if (p->i.wnd->ap_ipv4[0] &&
	    lws_captive_dns_start(p->i.cx, p->i.wnd->ap_ipv4, p->i.dns_port))
		lwsl_warn("%s: no captive dns\n", __func__);
#endif

	lwsl_user("%s: join %s, then visit %s\n", __func__, p->ssid, p->url);
	p->ap = 1;

	prov_led(p, &lws_pwmseq_double_blink_endless);
	prov_state(p, LWS_WIFI_PROV_AP);

	return 0;
}

static void
prov_ap_stop(struct lws_wifi_provision *p)
{
#if defined(LWS_WITH_SYS_CAPTIVE_DNS)
	if (p->ap)
		lws_captive_dns_stop(p->i.cx);
#endif

	if (p->vh) {
		lws_vhost_destroy(p->vh);
		p->vh = NULL;
	}

	if (!p->ap)
		return;

	p->ap = 0;
	lws_netdev_wifi_ap(&p->i.wnd->inst, NULL, NULL);
	p->url[0] = '\0';
	prov_led(p, &lws_pwmseq_static_off);
	if (p->state == LWS_WIFI_PROV_AP)
		prov_state(p, LWS_WIFI_PROV_IDLE);
}

/*
 * Can we expect the credentials we have to work?  Not if there are none, or
 * every AP refused its passphrase the last time it was tried.  If none ever
 * worked, we give them a while to join before we decide they don't: returns
 * 1 to be an AP now, 0 to wait and see, or -1 if one of them worked before, so
 * we leave it to the station to find it again.
 */

static int
prov_creds_hopeless(struct lws_wifi_provision *p)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(p->i.cx);
	int count = 0, refused = 0, worked = 0;

	lws_netdev_credentials_hold(nds);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&nds->owner_creds)) {
		const lws_wifi_creds_t *c = lws_container_of(d,
						lws_wifi_creds_t, list);

		count++;
		if (c->last_join == LWS_WIFI_JOIN_AUTH_FAILED)
			refused++;
		if (c->last_join == LWS_WIFI_JOIN_OK || c->internet)
			worked++;
	} lws_end_foreach_dll(d);

	lws_netdev_credentials_release(nds);

	if (!count || refused == count)
		return 1;

	return worked ? -1 : 0;
}

static void
prov_join_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_wifi_provision *p = lws_container_of(sul,
				struct lws_wifi_provision, sul_join);

	if (p->i.wnd->joined || p->state != LWS_WIFI_PROV_IDLE)
		return;

	lwsl_notice("%s: unable to join with the credentials we have\n",
		    __func__);
	prov_ap_start(p);
}

static void
prov_window_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_wifi_provision *p = lws_container_of(sul,
				struct lws_wifi_provision, sul_window);

	/* a hold already begun can still finish */
	p->window_open = 0;
}

static void
prov_reset_ack_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_wifi_provision *p = lws_container_of(sul,
				struct lws_wifi_provision, sul_reboot);

	/* everything comes up again with nothing stored */
	prov_reboot(p, 1);
}

static void
prov_hold_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_wifi_provision *p = lws_container_of(sul,
				struct lws_wifi_provision, sul_hold);

	/*
	 * A button that was already down when it was enabled sends no "up"
	 * when it's released, nor do we see one sent before we joined smd:
	 * if we can, check it's really still held
	 */
	if (p->i.buttons &&
	    !lws_button_is_down(p->i.buttons, p->i.reset_button)) {
		lwsl_notice("%s: reset button was released\n", __func__);
		return;
	}

	lwsl_user("%s: reset button held: forgetting the wifi credentials\n",
		  __func__);

	if (lws_netdev_credentials_clear(lws_netdevs_from_ctx(p->i.cx)))
		lwsl_err("%s: unable to forget them\n", __func__);

	prov_led(p, &lws_pwmseq_blink_fast_endless);
	prov_state(p, LWS_WIFI_PROV_RESET);
	lws_sul_schedule(p->i.cx, 0, &p->sul_reboot, prov_reset_ack_cb,
			 PROV_RESET_ACK_US);
}

/* the reset button went down, or was already down when we started */

static void
prov_hold_start(struct lws_wifi_provision *p)
{
	if (!p->window_open || p->state == LWS_WIFI_PROV_RESET ||
	    p->state == LWS_WIFI_PROV_REBOOT)
		return;

	lwsl_notice("%s: reset button down\n", __func__);

	lws_sul_schedule(p->i.cx, 0, &p->sul_hold, prov_hold_cb,
			 (lws_usec_t)(p->i.reset_hold_s ? p->i.reset_hold_s :
						PROV_RESET_HOLD_S_DEFAULT) *
						LWS_US_PER_SEC);
}

/* is it an event from the button called name, eg, "bc/user" for "user" */

static int
prov_is_button(const void *buf, size_t len, const char *name)
{
	size_t al, nl = strlen(name);
	const char *s;

	if (lws_json_simple_strcmp(buf, len, "\"type\":", "button"))
		return 0;

	s = lws_json_simple_find((const char *)buf, len, "\"src\":", &al);

	return s && al > nl && s[al - nl - 1] == '/' &&
	       !memcmp(s + al - nl, name, nl);
}

static int
prov_smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
	    void *buf, size_t len)
{
	struct lws_wifi_provision *p = (struct lws_wifi_provision *)opaque;
	const char *s;
	size_t al;

	if (_class & LWSSMDCL_INTERACTION) {
		if (!p->i.reset_button || !prov_is_button(buf, len,
							  p->i.reset_button))
			return 0;

		if (!lws_json_simple_strcmp(buf, len, "\"event\":", "down")) {
			prov_hold_start(p);
			return 0;
		}

		if (!lws_json_simple_strcmp(buf, len, "\"event\":", "up"))
			/* it wasn't held long enough */
			lws_sul_cancel(&p->sul_hold);

		return 0;
	}

	if (!(_class & LWSSMDCL_NETWORK))
		return 0;

	/*
	 * Eg, a scan finished, or how joining an AP went: what the settings
	 * show may be different.  Nothing is sent unless it is.
	 */
	if (p->ap)
		prov_live(p);

	if (lws_json_simple_strcmp(buf, len, "\"type\":", "ipacq"))
		return 0;

	s = lws_json_simple_find(buf, len, "\"if\":", &al);
	if (!s || al != strlen(p->i.wnd->inst.name) ||
	    strncmp(s, p->i.wnd->inst.name, al))
		return 0;

	/* the station got an address: what we have works */
	lws_sul_cancel(&p->sul_join);

	if (p->state == LWS_WIFI_PROV_AP) {
		/*
		 * Eg, the AP was only off for a while: we needn't be one.  Not
		 * if we're restarting, eg, to join something else stored.
		 */
		lwsl_notice("%s: joined after all, no longer an AP\n",
			    __func__);
		prov_ap_stop(p);
	}

	return 0;
}

struct lws_wifi_provision *
lws_wifi_provision_create(const lws_wifi_provision_info_t *i)
{
	struct lws_wifi_provision *p;
	int h;

	if (!i->cx || !i->wnd)
		return NULL;

	p = lws_zalloc(sizeof(*p), __func__);
	if (!p)
		return NULL;

	p->i = *i;

	p->protocols[0].name = "lws-wifi-provision";
	p->protocols[0].callback = callback_provision;
	p->protocols[0].per_session_data_size = sizeof(struct pss);

#if defined(LWS_ROLE_WS)
	p->protocols[1].name = PROV_WS_PROTOCOL;
	p->protocols[1].callback = callback_settings_ws;
	p->protocols[1].per_session_data_size = sizeof(struct pss_ws);
#endif

	p->mount.mountpoint = "/";
	p->mount.mountpoint_len = 1;
	p->mount.origin = p->protocols[0].name;
	p->mount.origin_protocol = LWSMPRO_CALLBACK;

	/* our AP is named for us, so it's told apart from others like us */
	if (lws_netdev_hostname_get(lws_netdevs_from_ctx(i->cx), p->ssid,
				    sizeof(p->ssid)) < 0)
		lws_strncpy(p->ssid, "lws", sizeof(p->ssid));

	p->smd = lws_smd_register(i->cx, p, 0, LWSSMDCL_INTERACTION |
						LWSSMDCL_NETWORK, prov_smd_cb);
	if (!p->smd) {
		lws_free(p);
		return NULL;
	}

	/* the reset button can be held from now, for a while */

	if (i->reset_button) {
		p->window_open = 1;
		lws_sul_schedule(i->cx, 0, &p->sul_window, prov_window_cb,
				 (lws_usec_t)(i->reset_window_s ?
					      i->reset_window_s :
					      PROV_RESET_WINDOW_S_DEFAULT) *
					      LWS_US_PER_SEC);

		/* it may be held already, eg, since the device started */
		if (i->buttons &&
		    lws_button_is_down(i->buttons, i->reset_button) == 1)
			prov_hold_start(p);
	}

	h = prov_creds_hopeless(p);
	if (h > 0) {
		lwsl_notice("%s: no usable wifi credentials\n", __func__);
		if (prov_ap_start(p)) {
			lws_wifi_provision_destroy(&p);
			return NULL;
		}
	} else if (!h)
		/* none worked before: see if they do now */
		lws_sul_schedule(i->cx, 0, &p->sul_join, prov_join_cb,
				 (lws_usec_t)(i->join_wait_s ? i->join_wait_s :
					      PROV_JOIN_WAIT_S_DEFAULT) *
					      LWS_US_PER_SEC);

	return p;
}

void
lws_wifi_provision_destroy(struct lws_wifi_provision **pp)
{
	struct lws_wifi_provision *p = *pp;

	if (!p)
		return;

	lws_sul_cancel(&p->sul_join);
	lws_sul_cancel(&p->sul_window);
	lws_sul_cancel(&p->sul_hold);
	lws_sul_cancel(&p->sul_reboot);

	if (p->smd)
		lws_smd_unregister(p->smd);

	prov_ap_stop(p);

	lws_free(p);
	*pp = NULL;
}

lws_wifi_provision_state_t
lws_wifi_provision_state(const struct lws_wifi_provision *p)
{
	return p ? (lws_wifi_provision_state_t)p->state : LWS_WIFI_PROV_IDLE;
}

const char *
lws_wifi_provision_ap_ssid(const struct lws_wifi_provision *p)
{
	return p && p->ap ? p->ssid : NULL;
}

const char *
lws_wifi_provision_url(const struct lws_wifi_provision *p)
{
	return p && p->ap ? p->url : NULL;
}

void
lws_wifi_provision_stored(struct lws_wifi_provision *p)
{
	/* a browser showing the settings sees the AP is stored */
	if (p)
		prov_live(p);

	if (!p || !p->ap || p->state == LWS_WIFI_PROV_REBOOT)
		/*
		 * The station joins it by itself, when it next scans, or
		 * we're restarting already
		 */
		return;

	prov_reboot(p, PROV_REBOOT_DELAY_US);
}
