/*
 * lws-api-test-wifi-provision
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks the wifi settings html, and giving a device wifi credentials while
 * it is an AP of its own (lws_wifi_provision_create()), with a wifi netdev
 * whose AP is this host, 127.0.0.1, and settings kept in memory.  It checks
 *
 *  - lws_html_w_t escapes text and url arguments, and refuses what doesn't
 *    fit rather than give something truncated
 *
 *  - lws_wifi_settings_href() understands the settings' links, and refuses
 *    SSIDs that are too long
 *
 *  - with no credentials, it becomes an AP at once, named for the hostname,
 *    and serves the settings: the APs scanned, the settings' css, the icons
 *    given to it, and 404 for anything else
 *
 *  - with LWS_WITH_SYS_CAPTIVE_DNS, while it's an AP, the captive dns says
 *    what a phone checks for internet with is us
 *
 *  - a request for another host, eg, the url a phone or Firefox checks for
 *    internet with, is redirected to the settings, and a form posted to
 *    another host isn't acted on
 *
 *  - the page for an AP's link has a form for its passphrase, and a
 *    passphrase that is too short is refused
 *
 *  - the hostname can be set, and one that isn't valid is refused
 *
 *  - storing a passphrase stores the credentials, says it's restarting, and
 *    the system's reboot op is called a few seconds later
 *
 *  - with credentials that never worked, it waits for them to join, then
 *    becomes an AP when they don't, and stops being one if they join after all
 *
 *  - the reset button already held when it starts isn't taken as held once
 *    it's let go, even with no "up" event, and lws_button_is_down() says how
 *    it is
 *
 *  - holding the reset button, from before it starts, forgets the
 *    credentials and restarts
 *
 *  - with credentials that worked before, it doesn't become an AP
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_PORT,
	LWS_SW_DNS_PORT,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	  = { "--port",	    "Port to serve the settings on" },
	[LWS_SW_DNS_PORT] = { "--dns-port", "UDP port for the captive dns" },
	[LWS_SW_HELP]	  = { "--help",	    "Show this help information" },
};

#define BLOBS		4

/* the settings store, in memory */

static struct {
	char		name[32];
	uint8_t		*data;
	size_t		len;
} blobs[BLOBS];

static struct lws_context *cx;
static struct lws_wifi_provision *prov;
static lws_netdev_instance_wifi_t wnd;
static int fail, port = 7681, dns_port = 5353, reboots, step, ap_ups, ap_downs,
	   states[8], interrupted;
static char ap_ssid[33];

static void
expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("FAIL: %s\n", what);
		fail = 1;
	} else
		lwsl_info("ok: %s\n", what);
}

static int
mem_get(lws_settings_instance_t *si, const char *name, uint8_t *dest,
	size_t *max_actual)
{
	int n;

	for (n = 0; n < BLOBS; n++)
		if (blobs[n].data && !strcmp(blobs[n].name, name)) {
			if (dest)
				memcpy(dest, blobs[n].data,
				       *max_actual < blobs[n].len ?
						*max_actual : blobs[n].len);
			*max_actual = blobs[n].len;

			return 0;
		}

	return 1;
}

static int
mem_set(lws_settings_instance_t *si, const char *name, const uint8_t *src,
	size_t len)
{
	int n, f = -1;

	for (n = 0; n < BLOBS; n++) {
		if (blobs[n].data && !strcmp(blobs[n].name, name)) {
			f = n;
			break;
		}
		if (!blobs[n].data && f < 0)
			f = n;
	}
	if (f < 0)
		return 1;

	free(blobs[f].data);
	blobs[f].data = malloc(len ? len : 1);
	if (!blobs[f].data)
		return 1;
	memcpy(blobs[f].data, src, len);
	blobs[f].len = len;
	lws_strncpy(blobs[f].name, name, sizeof(blobs[f].name));

	return 0;
}

static const lws_settings_ops_t mem_ops = {
	.get		= mem_get,
	.set		= mem_set,
};

/* a wifi netdev, whose AP is this host */

static int
fake_ap(struct lws_netdev_instance *nd, const char *ssid,
	const char *passphrase)
{
	lws_netdev_instance_wifi_t *w = (lws_netdev_instance_wifi_t *)nd;

	if (!ssid) {
		w->flags &= (uint8_t)~LNDIW_MODE_AP;
		w->ap_ipv4[0] = '\0';
		ap_downs++;
		return 0;
	}

	lws_strncpy(ap_ssid, ssid, sizeof(ap_ssid));
	lws_strncpy(w->ap_ipv4, "127.0.0.1", sizeof(w->ap_ipv4));
	w->flags |= LNDIW_MODE_AP;
	ap_ups++;

	return 0;
}

static int
fake_event(struct lws_netdev_instance *nd, lws_usec_t timestamp, void *buf,
	   size_t len)
{
	return 0;
}

static const lws_netdev_ops_t fake_ops = {
	.event		= fake_event,
	.ap		= fake_ap,
};

/* an AP in the scan results */

static void
scan_add(const char *ssid, uint8_t last, lws_wifi_auth_t auth, int rssi)
{
	size_t sl = strlen(ssid);
	lws_wifi_sta_t *w = calloc(1, sizeof(*w) + sl + 1);

	if (!w)
		return;

	w->ssid = (char *)&w[1];
	memcpy(w->ssid, ssid, sl + 1);
	w->ssid_len = (uint8_t)sl;
	w->bssid[5] = last;
	w->authmode = (uint8_t)auth;
	w->rssi[0] = (lws_wifi_rssi_t)rssi;
	w->rssi_avg = (int16_t)rssi;
	w->rssi_count = 1;
	lws_dll2_add_tail(&w->list, &wnd.scan);
}

static void
scan_empty(void)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&wnd.scan)) {
		lws_wifi_sta_t *w = lws_container_of(d, lws_wifi_sta_t, list);

		lws_dll2_remove(d);
		free(w);
	} lws_end_foreach_dll_safe(d, d1);
}

static int
do_reboot(void)
{
	reboots++;

	return 0;
}

static const lws_system_ops_t system_ops = {
	.reboot		= do_reboot,
};

static int
stored_pass(const char *ssid, char *pp, size_t len)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(cx);
	int r = 1;

	*pp = '\0';
	lws_netdev_credentials_hold(nds);

	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&nds->owner_creds)) {
		lws_wifi_creds_t *c = lws_container_of(p, lws_wifi_creds_t,
						       list);

		if (!strcmp(c->ssid, ssid)) {
			lws_strncpy(pp, c->passphrase, len);
			r = 0;
		}
	} lws_end_foreach_dll(p);

	lws_netdev_credentials_release(nds);

	return r;
}

static void
prov_cb(void *opaque, lws_wifi_provision_state_t state)
{
	states[state]++;
}

/*
 * The reset button, on a gpio we fake: it's active low, and has no edges to
 * interrupt on, as if it was held from before it was enabled, so it sends no
 * events at all and is only seen by lws_button_is_down()
 */

static int btn_down;
static struct lws_button_state *bcs;

static void
fake_gpio_mode(_lws_plat_gpio_t gpio, int flags)
{
}

static int
fake_gpio_read(_lws_plat_gpio_t gpio)
{
	return !btn_down;
}

static void
fake_gpio_set(_lws_plat_gpio_t gpio, int val)
{
}

static int
fake_gpio_irq_mode(_lws_plat_gpio_t gpio, lws_gpio_irq_t irq,
		   lws_gpio_irq_cb_t cb, void *arg)
{
	return 0;
}

static const lws_gpio_ops_t fake_gpio = {
	.mode		= fake_gpio_mode,
	.read		= fake_gpio_read,
	.set		= fake_gpio_set,
	.irq_mode	= fake_gpio_irq_mode,
};

static const lws_button_map_t bcm[] = {
	{ .gpio = 0, .smd_interaction_name = "user" },
};

static const lws_button_controller_t bc = {
	.smd_bc_name		= "bc",
	.gpio_ops		= &fake_gpio,
	.button_map		= bcm,
	.count_buttons		= LWS_ARRAY_SIZE(bcm),
};

static const char svg[] = "<svg xmlns=\"http://www.w3.org/2000/svg\"/>";

static const lws_wifi_provision_file_t files[] = {
	{ "set-cog.svg", svg, sizeof(svg) - 1, "image/svg+xml" },
};

static void
prov_start(const char *reset_button, struct lws_button_state *buttons)
{
	lws_wifi_provision_info_t i;

	memset(&i, 0, sizeof(i));
	i.cx = cx;
	i.wnd = &wnd;
	i.reset_button = reset_button;
	i.buttons = buttons;
	i.files = files;
	i.count_files = LWS_ARRAY_SIZE(files);
	i.cb = prov_cb;
	i.port = (uint16_t)port;
	i.dns_port = (uint16_t)dns_port;
	i.join_wait_s = 1;
	i.reset_window_s = 5;
	i.reset_hold_s = 1;

	memset(states, 0, sizeof(states));
	prov = lws_wifi_provision_create(&i);
	expect(!!prov, "created");
}

/*
 * The requests made of the settings server, one after another, and what
 * the response must have in it
 */

/* our address with the port, as a browser sends it in Host: */
static char host_port[32];

static const struct req {
	const char	*path;
	const char	*post;		/* NULL for GET */
	int		status;
	const char	*has[3];
	const char	*host;		/* NULL for our address */
	char		to_settings;	/* redirected to them */
} reqs[] = {
	/*
	 * What a phone and Firefox check for internet with, that the captive
	 * dns made us: they're sent to the settings
	 */
	{ "/generate_204", NULL, 302, { NULL, NULL, NULL },
				"connectivitycheck.gstatic.com", 1 },
	{ "/canonical.html", NULL, 302, { NULL, NULL, NULL },
				"detectportal.firefox.com", 1 },
	{ "/", "act=set&ssid=TestAP&pass=sneaky%20pass", 302,
				{ NULL, NULL, NULL }, "example.com", 1 },
	{ "/", NULL, 200, { "href=\"?set=TestAP\"", NULL, NULL },
				host_port, 0 },
	{ "/", NULL, 200, { "href=\"?set=TestAP\"",
			    "Open &amp; &lt;AP&gt;",
			    "href=\"?set=Open%20%26%20%3CAP%3E\"" }, NULL, 0 },
	{ "/?set=TestAP", NULL, 200, { "name=\"pass\"",
				       "name=\"ssid\" value=\"TestAP\"", NULL },
				NULL, 0 },
	{ "/?set=Open%20%26%20%3CAP%3E", NULL, 200, { ">Join<",
		"value=\"Open &amp; &lt;AP&gt;\"", NULL }, NULL, 0 },
	{ "/?host", NULL, 200, { "name=\"host\"", "value=\"lws-a1b2c3\"",
				 NULL }, NULL, 0 },
	{ "/wifi.css", NULL, 200, { "border-collapse", NULL, NULL },
				NULL, 0 },
	{ "/set-cog.svg", NULL, 200, { "<svg", NULL, NULL }, NULL, 0 },
	{ "/nothing", NULL, 404, { NULL, NULL, NULL }, NULL, 0 },
	{ "/", "act=set&ssid=TestAP&pass=short", 200,
				{ "8 to 63", NULL, NULL }, NULL, 0 },
	{ "/", "act=nonsense&ssid=TestAP", 400, { NULL, NULL, NULL },
				NULL, 0 },
	{ "/", "act=host&host=Bad_Host", 200, { "class=\"err\"", NULL, NULL },
				NULL, 0 },
	{ "/", "act=host&host=newname", 303, { NULL, NULL, NULL }, NULL, 0 },
	{ "/", NULL, 200, { ">newname<", NULL, NULL }, NULL, 0 },
	{ "/", "act=set&ssid=TestAP&pass=correct%20horse", 200,
				{ "Restarting to join TestAP", NULL, NULL },
				NULL, 0 },
};

static char body[16384], location[64];
static size_t body_len;
static int req_idx = -1, status;

static void
next_step(lws_sorted_usec_list_t *sul);
static lws_sorted_usec_list_t sul_step;

static void
req_check(void)
{
	const struct req *r = &reqs[req_idx];
	char what[128];
	int n;

	body[body_len] = '\0';
	lws_snprintf(what, sizeof(what), "%s %s: status %d", r->post ?
		     "POST" : "GET", r->path, r->status);
	expect(status == r->status, what);
	if (status != r->status)
		lwsl_err("  got %d\n", status);

	if (r->to_settings) {
		char pp[64];

		lws_snprintf(what, sizeof(what), "%s %s: to the settings",
			     r->host, r->path);
		expect(lws_wifi_provision_url(prov) &&
		       !strcmp(location, lws_wifi_provision_url(prov)), what);
		/* a form posted to another host isn't acted on */
		if (r->post)
			expect(!!stored_pass("TestAP", pp, sizeof(pp)),
			       "form for another host not stored");
	}

	for (n = 0; n < 3 && r->has[n]; n++) {
		lws_snprintf(what, sizeof(what), "%s: has %s", r->path,
			     r->has[n]);
		expect(!!strstr(body, r->has[n]), what);
	}
}

static int
callback_client(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	/* the request in flight, none before the first */
	const struct req *r = req_idx >= 0 ? &reqs[req_idx] : NULL;
	char cl[16];
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "?");
		fail = 1;
		interrupted = 1;
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (!r || !r->post)
			break;

		lws_snprintf(cl, sizeof(cl), "%u", (unsigned int)strlen(r->post));
		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				(const uint8_t *)"application/x-www-form-urlencoded",
				33, (uint8_t **)in, (uint8_t *)in + len) ||
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_LENGTH,
				(const uint8_t *)cl, (int)strlen(cl),
				(uint8_t **)in, (uint8_t *)in + len))
			return -1;

		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!r || !r->post)
			break;

		n = lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "%s",
				 r->post);
		lws_client_http_body_pending(wsi, 0);
		if (lws_write(wsi, p, (size_t)n, LWS_WRITE_HTTP_FINAL) != n)
			return -1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		if (lws_hdr_copy(wsi, location, sizeof(location),
				 WSI_TOKEN_HTTP_LOCATION) <= 0)
			location[0] = '\0';
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (body_len + len < sizeof(body) - 1) {
			memcpy(body + body_len, in, len);
			body_len += len;
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char *px = (char *)buf + LWS_PRE;
			int lenx = (int)(sizeof(buf) - LWS_PRE);

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		req_check();
		lws_sul_schedule(cx, 0, &sul_step, next_step, 1);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_WITH_SYS_CAPTIVE_DNS)
/*
 * While we're an AP, the captive dns answers whoever joined: asked the address
 * of what a phone checks for internet with, it's us
 */

static uint8_t dnsq[LWS_PRE + 64];
static size_t dnsq_len;
static int dns_answered;

static int
callback_dns(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	static const uint8_t lo[] = { 127, 0, 0, 1 };
	const uint8_t *r = (const uint8_t *)in;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (lws_write(wsi, dnsq + LWS_PRE, dnsq_len, LWS_WRITE_RAW) !=
							(int)dnsq_len)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		/* the same id, one answer, and it ends with our address */
		expect(len == dnsq_len + 16 && !memcmp(r, dnsq + LWS_PRE, 2) &&
		       lws_ser_ru16be(r + 6) == 1 &&
		       !memcmp(r + len - 4, lo, 4), "captive dns answer");
		dns_answered = 1;
		lws_sul_schedule(cx, 0, &sul_step, next_step, 1);

		return -1; /* done with this client */

	default:
		break;
	}

	return 0;
}

static void
dns_ask(void)
{
	static const char name[] = "\x11" "connectivitycheck" "\x07" "gstatic"
				   "\x03" "com";
	uint8_t *q = dnsq + LWS_PRE;

	/* id 0x5a5a, recursion desired, one question: A, IN */
	memset(q, 0, 12);
	q[0] = q[1] = 0x5a;
	q[2] = 0x01;
	q[5] = 1;
	memcpy(q + 12, name, sizeof(name)); /* with the root's 0 */
	dnsq_len = 12 + sizeof(name);
	q[dnsq_len++] = 0;
	q[dnsq_len++] = 1;
	q[dnsq_len++] = 0;
	q[dnsq_len++] = 1;

	if (!lws_create_adopt_udp(lws_get_vhost_by_name(cx, "default"),
				  "127.0.0.1", dns_port, 0, "dns", NULL, NULL,
				  NULL, NULL, "dns")) {
		lwsl_err("%s: unable to make dns client\n", __func__);
		fail = 1;
	}
}
#endif

static const struct lws_protocols protocols[] = {
	{ "client", callback_client, 0, 0, 0, NULL, 0 },
#if defined(LWS_WITH_SYS_CAPTIVE_DNS)
	{ "dns", callback_dns, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static void
request(void)
{
	struct lws_client_connect_info i;
	const struct req *r = &reqs[req_idx];

	body_len = 0;
	status = 0;

	memset(&i, 0, sizeof(i));
	i.context = cx;
	i.port = port;
	i.address = "127.0.0.1";
	i.path = r->path;
	i.host = r->host ? r->host : i.address;
	i.origin = i.address;
	i.method = r->post ? "POST" : "GET";
	i.protocol = protocols[0].name;
	i.alpn = "http/1.1";
	/* we want to see the redirect after a form, not follow it */
	i.ssl_connection = LCCSCF_HTTP_NO_FOLLOW_REDIRECT;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: unable to connect\n", __func__);
		fail = 1;
		interrupted = 1;
	}
}

/* what happens after the requests, as the time comes */

enum {
	ST_DNS,			/* the captive dns, while we're an AP */
	ST_REQUESTS,
	ST_REBOOTED,		/* credentials stored, expecting a reboot */
	ST_JOIN_WAIT,		/* credentials that never worked */
	ST_JOINED,		/* they join while we're an AP */
	ST_HELD,		/* reset button held from the start... */
	ST_RELEASED,		/* ... let go before long enough */
	ST_RESET,		/* reset button held */
	ST_WORKED,		/* credentials that worked before */
	ST_DONE
};

static lws_usec_t step_due;

static void
next_step(lws_sorted_usec_list_t *sul)
{
	char pp[64];

	switch (step) {
	case ST_DNS:
#if defined(LWS_WITH_SYS_CAPTIVE_DNS)
		if (!dnsq_len) {
			dns_ask();
			/* if it isn't answered by then, it never will be */
			lws_sul_schedule(cx, 0, &sul_step, next_step,
					 3 * LWS_US_PER_SEC);
			return;
		}
		expect(dns_answered, "captive dns answered");
#endif
		step = ST_REQUESTS;
		/* fallthru */

	case ST_REQUESTS:
		if (++req_idx < (int)LWS_ARRAY_SIZE(reqs)) {
			request();
			return;
		}

		/* the last stored credentials, and a restart is coming */
		expect(!stored_pass("TestAP", pp, sizeof(pp)) &&
		       !strcmp(pp, "correct horse"), "credentials stored");
		expect(lws_wifi_provision_state(prov) == LWS_WIFI_PROV_REBOOT,
		       "rebooting");
		step = ST_REBOOTED;
		step_due = lws_now_usecs() + 5 * LWS_US_PER_SEC;
		lws_sul_schedule(cx, 0, &sul_step, next_step, LWS_US_PER_SEC);
		return;

	case ST_REBOOTED:
		if (!reboots && lws_now_usecs() < step_due) {
			lws_sul_schedule(cx, 0, &sul_step, next_step,
					 LWS_US_PER_SEC / 4);
			return;
		}
		expect(reboots == 1, "rebooted");
		lws_wifi_provision_destroy(&prov);
		expect(ap_downs == 1 && !(wnd.flags & LNDIW_MODE_AP),
		       "destroy stops the AP");

		/*
		 * As if we restarted: the credentials stored never worked, so
		 * they get a while to join before we're an AP again
		 */
		prov_start("user", NULL);
		expect(lws_wifi_provision_state(prov) == LWS_WIFI_PROV_IDLE &&
		       ap_ups == 1, "waiting to join");
		step = ST_JOIN_WAIT;
		lws_sul_schedule(cx, 0, &sul_step, next_step,
				 3 * LWS_US_PER_SEC / 2);
		return;

	case ST_JOIN_WAIT:
		expect(lws_wifi_provision_state(prov) == LWS_WIFI_PROV_AP &&
		       ap_ups == 2, "AP when they didn't join");
		lws_snprintf(pp, sizeof(pp), "http://127.0.0.1:%d/", port);
		expect(lws_wifi_provision_url(prov) &&
		       !strcmp(lws_wifi_provision_url(prov), pp), "url");

		/* the station gets an address after all */
		lws_smd_msg_printf(cx, LWSSMDCL_NETWORK,
				   "{\"type\":\"ipacq\",\"if\":\"wl0\","
				   "\"ipv4\":\"192.168.1.2\"}");
		step = ST_JOINED;
		lws_sul_schedule(cx, 0, &sul_step, next_step,
				 LWS_US_PER_SEC / 2);
		return;

	case ST_JOINED:
		expect(lws_wifi_provision_state(prov) == LWS_WIFI_PROV_IDLE &&
		       ap_downs == 2 && !lws_wifi_provision_url(prov),
		       "no longer an AP once joined");

		/*
		 * The reset button is down from before we start, as if pressed
		 * as soon as the device started.  It has no edges to send
		 * events on, so we can only know it's down by looking.
		 */
		lws_wifi_provision_destroy(&prov);
		expect(lws_button_is_down(bcs, "user") == 0 &&
		       lws_button_is_down(bcs, "nonexistent") == -1,
		       "button up, unknown button");
		btn_down = 1;
		expect(lws_button_is_down(bcs, "user") == 1, "button down");
		prov_start("user", bcs);
		step = ST_HELD;
		lws_sul_schedule(cx, 0, &sul_step, next_step,
				 LWS_US_PER_SEC / 2);
		return;

	case ST_HELD:
		/* it's let go before it's held long enough, with no "up" */
		btn_down = 0;
		step = ST_RELEASED;
		lws_sul_schedule(cx, 0, &sul_step, next_step,
				 3 * LWS_US_PER_SEC / 2);
		return;

	case ST_RELEASED:
		expect(!states[LWS_WIFI_PROV_RESET] && reboots == 1 &&
		       !stored_pass("TestAP", pp, sizeof(pp)),
		       "let go before long enough, no reset");

		/* this time it's held from the start until it resets */
		lws_wifi_provision_destroy(&prov);
		btn_down = 1;
		prov_start("user", bcs);
		step = ST_RESET;
		lws_sul_schedule(cx, 0, &sul_step, next_step,
				 4 * LWS_US_PER_SEC);
		return;

	case ST_RESET:
		expect(states[LWS_WIFI_PROV_RESET] == 1, "reset");
		expect(stored_pass("TestAP", pp, sizeof(pp)),
		       "credentials forgotten");
		expect(reboots == 2, "rebooted after reset");
		lws_wifi_provision_destroy(&prov);
		btn_down = 0;

		/* credentials that worked before: never an AP */
		expect(!lws_netdev_credentials_add(lws_netdevs_from_ctx(cx),
						   "TestAP", "correct horse"),
		       "store again");
		lws_strncpy(wnd.current_attempt_ssid, "TestAP",
			    sizeof(wnd.current_attempt_ssid));
		lws_smd_msg_printf(cx, LWSSMDCL_NETWORK,
				   "{\"type\":\"ipacq\",\"if\":\"wl0\","
				   "\"ipv4\":\"192.168.1.2\"}");
		step = ST_WORKED;
		lws_sul_schedule(cx, 0, &sul_step, next_step,
				 LWS_US_PER_SEC / 2);
		return;

	case ST_WORKED:
		if (step_due != 1) {
			/* the netdev noted it joined: as if we restarted */
			wnd.joined = 0;
			prov_start(NULL, NULL);
			step_due = 1;
			lws_sul_schedule(cx, 0, &sul_step, next_step,
					 2 * LWS_US_PER_SEC);
			return;
		}
		expect(lws_wifi_provision_state(prov) == LWS_WIFI_PROV_IDLE &&
		       ap_ups == 2, "never an AP when they worked before");
		lws_wifi_provision_destroy(&prov);
		step = ST_DONE;
		interrupted = 1;
		return;
	}
}

/* the html writer, and the settings' links */

static void
test_html(void)
{
	char buf[64], ssid[33];
	lws_html_w_t w;

	lws_html_w_init(&w, buf, sizeof(buf));
	lws_html_w_printf(&w, "<a href=\"?x=");
	lws_html_w_urlarg(&w, "a b&\"<", 32);
	lws_html_w_printf(&w, "\">");
	lws_html_w_text(&w, "<'&\">\x01", 32);
	expect(lws_html_w_len(&w, buf) > 0 &&
	       !strcmp(buf, "<a href=\"?x=a%20b%26%22%3C\">"
			    "&lt;&#39;&amp;&quot;&gt;?"), "html escaping");

	lws_html_w_init(&w, buf, 8);
	lws_html_w_printf(&w, "123456789");
	expect(lws_html_w_len(&w, buf) < 0 && !buf[0], "html overflow");

	expect(lws_wifi_settings_href("?set=My%20AP", ssid, sizeof(ssid)) ==
	       LWS_WIFI_SETTINGS_ACT_SET && !strcmp(ssid, "My AP"), "href set");
	expect(lws_wifi_settings_href("?forget=x", ssid, sizeof(ssid)) ==
	       LWS_WIFI_SETTINGS_ACT_FORGET && !strcmp(ssid, "x"),
	       "href forget");
	expect(lws_wifi_settings_href("?host", ssid, sizeof(ssid)) ==
	       LWS_WIFI_SETTINGS_ACT_HOSTNAME, "href host");
	expect(lws_wifi_settings_href("?set=", ssid, sizeof(ssid)) ==
	       LWS_WIFI_SETTINGS_ACT_NONE &&
	       lws_wifi_settings_href("?set=%zz", ssid, sizeof(ssid)) ==
	       LWS_WIFI_SETTINGS_ACT_NONE &&
	       lws_wifi_settings_href("elsewhere", ssid, sizeof(ssid)) ==
	       LWS_WIFI_SETTINGS_ACT_NONE &&
	       lws_wifi_settings_href(
		       "?set=123456789012345678901234567890123", ssid,
		       sizeof(ssid)) == LWS_WIFI_SETTINGS_ACT_NONE,
	       "href refused");
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_netdevs_t *nds;
	const char *p;
	int n;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	signal(SIGINT, sigint_handler);
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API Test - wifi provision\n");

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw);
	if (p)
		port = atoi(p);
	p = lws_cmdline_option(argc, argv, switches[LWS_SW_DNS_PORT].sw);
	if (p)
		dns_port = atoi(p);
	lws_snprintf(host_port, sizeof(host_port), "127.0.0.1:%d", port);

	test_html();

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	/* there's no internet to detect here, it's taken as there being some */
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_CPD_BYPASS;
	info.protocols = protocols;
	info.system_ops = &system_ops;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the client's vhost */
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("unable to create client vhost\n");
		goto bail;
	}

	nds = lws_netdevs_from_ctx(cx);
	nds->si = lws_settings_init(&mem_ops, NULL);
	if (!nds->si)
		goto bail;

	memset(&wnd, 0, sizeof(wnd));
	wnd.inst.type = LWSNDTYP_WIFI;
	wnd.inst.ops = &fake_ops;
	wnd.inst.name = "wl0";
	wnd.inst.mac[3] = 0xa1;
	wnd.inst.mac[4] = 0xb2;
	wnd.inst.mac[5] = 0xc3;
	lws_dll2_add_tail(&wnd.inst.list, &nds->owner);

	bcs = lws_button_controller_create(cx, &bc);
	if (!bcs)
		goto bail;
	lws_button_enable(bcs, 0, lws_button_get_bit(bcs, "user"));

	scan_add("TestAP", 1, LWS_WIFI_AUTH_WPA2, -50);
	scan_add("Open & <AP>", 2, LWS_WIFI_AUTH_OPEN, -70);

	/* nothing is stored: we're an AP at once */
	prov_start(NULL, NULL);
	expect(lws_wifi_provision_state(prov) == LWS_WIFI_PROV_AP &&
	       states[LWS_WIFI_PROV_AP] == 1 && ap_ups == 1 &&
	       !strcmp(ap_ssid, "lws-a1b2c3") &&
	       lws_wifi_provision_ap_ssid(prov) &&
	       !strcmp(lws_wifi_provision_ap_ssid(prov), "lws-a1b2c3"),
	       "AP with no credentials");

	lws_sul_schedule(cx, 0, &sul_step, next_step, 1);

	n = 0;
	while (n >= 0 && !interrupted)
		n = lws_service(cx, 0);

	expect(step == ST_DONE, "all steps");

	lws_sul_cancel(&sul_step);
	lws_wifi_provision_destroy(&prov);
	scan_empty();
	lws_dll2_remove(&wnd.inst.list);
	lws_settings_deinit(&nds->si);
	lws_button_controller_destroy(bcs);

bail:
	lws_context_destroy(cx);

	for (n = 0; n < BLOBS; n++)
		free(blobs[n].data);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
