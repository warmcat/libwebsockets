/*
 * main
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * General main() for embedded LHP examples.  Board-specific stuff like
 * differences in platform / device / display availability and bringup is in
 * ./main/devices.c in the individual directories.
 *
 * Everything on the display is html, laid out and rendered by lhp.
 *
 * From boot, a strip ui (lws-dlo-ui.h) titled "Boot" lists the boot stages
 * (see boot-ui.c) as they are reached.  Until the network is up it can only
 * use what is built in, a font and the stage icons, from the dlo filesystem.
 * On a landscape display, the boot list is a column at the left, and the
 * product's own html, eg, a picture of it, is shown right of it, see
 * product.cmake: it all goes when booting is over, as the boot list does.
 * If no wifi credentials are stored, once a scan has found some APs, the
 * settings dialog (see settings-ui.c) lists them instead, for the user to set
 * the passphrase of one.
 *
 * If there are no wifi credentials we can use, the device also becomes an AP
 * of its own, named for its hostname, and serves the same settings to a
 * browser on it, eg, http://192.168.4.1/, and a led the board names flashes
 * meanwhile: so boards without a display, or a way to use the settings on it,
 * can be set up too.  Once credentials are stored either way, it restarts to
 * join the AP.  Holding the button the board names for a few seconds soon
 * after starting forgets the credentials, see lws_wifi_provision_create().
 *
 * Once the system is OPERATIONAL and
 * the first update check has told us we're on the latest firmware (or failed,
 * or there's no OTA), the boot list is replaced by the frame: the same title
 * strip, saying which page is shown, over the application html.
 *
 * At the right of the title strip, a status capsule shows the wlan signal,
 * and the battery on boards with one.  Pressing it, or a button named
 * "settings", shows the settings dialog: the APs we can join, how joining
 * them went, and the hostname.  Pressing it again, or the dialog's title,
 * closes it, and what was shown goes on.  They need a touch display, or
 * buttons named "up", "down", "left", "right" and "enter" to move around them
 * and the keyboard, and "esc" if there is one, to go back.
 *
 * The application is a placeholder for now: it visits each URL in the
 * board's carousel once, rendering it on the display via LHP, and showing
 * each for 10s once it is on the display, the last one too, then it ends.
 * On a touch display, the page shown can be dragged around, to see the rest
 * of one longer or wider than the display.  Each drag gives the page another
 * 10s before the carousel moves on.  Pressing a link stops the carousel.
 * While the settings are shown, the carousel waits.
 * An EPD keeps its image with no power, so it should be left white for
 * storage: there a white page is shown after the last one, and it ends once
 * that is on the display.
 *
 * Ending means everything is torn down: the devices, then the lws context.  The
 * free heap should be back to what it was before the context was created; if
 * it is, "Completed: PASS" is logged for CI, otherwise "Completed: FAIL".
 *
 * If an update is found, a modal update display with its progress is shown
 * whatever else was on the display.
 *
 * These examples are currently available for a bunch of ESP32 variants... but
 * there is no ESP32-specific code here except the reboot and task glue.
 */

#include "main.h"
#include "boot-ui.h"
#include "settings-ui.h"
#include "update-ui.h"
#include "edges-ui.h"
#include "greys-ui.h"
#include "tz-ui.h"

struct lws_context *cx;
struct lws_touch_state *tcs;
lhp_battery_cb_t plat_battery;
const char *plat_status_led, *plat_reset_button;

/* how long we wait after OPERATIONAL for the first update check to end */
#define BOOT_OTA_WAIT_US	(90 * LWS_US_PER_SEC)
/*
 * How often the update display is drawn again, to move its spinner on and
 * show the progress: drawing it takes time from fetching and flashing the
 * update, so only what changed is drawn again, if it can be.  A display that
 * can't show animation, eg, an EPD taking seconds to update, has no spinner,
 * and is only drawn again when the progress changed, and less often.
 */
#define UPDATE_SHOW_US		(LWS_US_PER_SEC / 2)
#define UPDATE_SHOW_STILL_US	(3 * LWS_US_PER_SEC)
/* the update page's url, once it's laid out */
#define UPDATE_URL		"file://dlofs/update.html"
/* how often the status capsule is brought up to date */
#define STATUS_US		(5 * LWS_US_PER_SEC)
/* the longest the first page waits for the frame to be drawn before it */
#define HANDOVER_WAIT_US	(5 * LWS_US_PER_SEC)

static enum {
	UI_BOOT,	/* the boot overlay */
	UI_APP,		/* the application html */
} ui;

/* how long each page of the carousel is shown, once it is on the display */
#define CAROUSEL_PAGE_US	(10 * LWS_US_PER_SEC)
/*
 * The page's images are drawn again each time it's panned, after the render
 * let go of them; this much heap keeps the small ones that came, so they
 * needn't be fetched again each time.  It's kept small, to leave the heap
 * for whatever else the device is doing
 */
#define ASSET_CACHE_BYTES	(128 * 1024)

/*
 * How much less free heap than before the context was created we accept after
 * it was destroyed.  Some things the platform allocates on first use stay
 * allocated, eg, in wifi, lwip and mbedtls: on 7col that's about 7KB.
 */
#define HEAP_RETURN_MARGIN	8192

/*
 * The carousel runs once: browsing its last url, then that url displayed for
 * as long as the others.  On an EPD, a white page is shown then, for storage
 */
static enum {
	CAROUSEL_RUNNING,
	CAROUSEL_LAST,		/* browsing the last url */
	CAROUSEL_SHOWING_LAST,	/* the last url is on the display */
	CAROUSEL_BLANKING,	/* on an EPD: the white page is being drawn */
	CAROUSEL_DONE
} carousel_phase;
static int carousel, page_no, update_pc, update_pc_shown = -1;
static lws_sorted_usec_list_t sul_app, sul_boot_timeout, sul_ui, sul_status,
			      sul_settings;
/* when the update display was last shown */
static lws_usec_t update_shown_us;
static char display_ready, boot_dirty, boot_done, seen_operational,
	    finished;
/* how many APs the boot list said were seen */
static uint32_t scan_count_shown;
/*
 * The display update in progress is the application's, not the strip ui's:
 * only the end of the application's moves the carousel on
 */
static char app_drawing;
/* the frame is being drawn, before the first page */
static char handover;
/*
 * On an EPD, the boot list is being cleaned off before the first page, which
 * may take a while to come
 */
static char boot_blanking;
/* the display was left all white: the next page needn't be cleared first */
static char display_white;
/* the frame's title strip changed while the display was busy */
static char frame_redraw_pending;
/* the settings were shown at boot, because no AP was stored */
static char settings_offered;
/* a drag began on the application page: it moves the page */
static char app_drag;
/* how far drags moved the page while the display was busy */
static int pan_dx, pan_dy;

static void
pan_kick(void);
static struct lws_plat_file_ops dlo_fops;
static lws_display_render_state_t rs;
static lhp_boot_t boot;
static uint8_t flip;

/*
 * The boot overlay, the settings, and the frame over the application's pages
 * are a strip ui: we say what its title and list hold, and it draws them
 */

struct lws_dlo_ui *sui;
static lhp_settings_t settings;
/* becomes an AP to be given credentials, if we have none we can use */
static struct lws_wifi_provision *prov;

/* the generated page in the dlo filesystem that is being shown, if any */
static char *page;
static const char *page_name;

/*
 * Our own generated page that is pressed on is shown, all of what can be seen,
 * until it's finished with
 */
static enum {
	GEN_NONE,
	GEN_EDGES,		/* the edges and touch page, see edges-ui.h */
	GEN_GREYS,		/* the grey levels page, see greys-ui.h */
	GEN_TZ,			/* the time zone page, see tz-ui.h */
} gen_page;
/* the application's page to go back to after it, if there was one */
static char gen_back[sizeof(lds.current_url)];
/* the touches on the edges page */
static lhp_edges_t edges;
/* the time zones, home and away */
static lhp_tz_t tz;

extern const char *carousel_urls[];

#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
#include "./static-policy.h"
#else
#include "./policy.h"
#endif

static const uint8_t jit_trust_blob[] = {
#include "./trust_blob.h"
};

static const char * const ui_css =
	"body { font-family: sun; font-size: 12pt; background-color: #fff; }";

static lws_dlo_filesystem_t fs_ui_css = {
	.name			= "ui.css",
	.data			= ui_css,
};

static const lws_led_sequence_def_t *seqs[] = {
	&lws_pwmseq_static_on,
	&lws_pwmseq_static_off,
	&lws_pwmseq_sine_endless_slow,
	&lws_pwmseq_sine_endless_fast,
};

static void
ui_kick(void);

static int
jit_trust_query(struct lws_context *cx, const uint8_t *skid,
		size_t skid_len, void *got_opaque)
{
	const uint8_t *der = NULL;
	size_t der_len = 0;

	/*
	 * For this example, we look up SKIDs using a trust table that's
	 * compiled in, synchronously.  Lws provides the necessary helper.
	 *
	 * Only a return of 0 means it found a trusted CA and set der and
	 * der_len, otherwise we tell the completion helper there is none.
	 */

	if (lws_tls_jit_trust_blob_queury_skid(jit_trust_blob,
					       sizeof(jit_trust_blob), skid,
					       skid_len, &der, &der_len)) {
		der = NULL;
		der_len = 0;
	}

	lwsl_info("%s: %s (len %d)\n", __func__,
		  der ? "found" : "not trusted", (int)der_len);

	/* Once we have a result, pass it to the completion helper */

	return lws_tls_jit_trust_got_cert_cb(cx, got_opaque, skid, skid_len,
					     der, der_len);
}

static int
do_reboot(void)
{
	esp_restart();
	return 0;
}

/*
 * Generated pages: html we made, registered in the dlo filesystem while it is
 * being shown, so lhp can browse it as file://dlofs/<name>.  It is only
 * dropped once the display has finished with it.
 */

static void
page_drop(void)
{
	if (!page)
		return;

	lws_dlo_file_unregister_by_name(cx, page_name);
	free(page);
	page = NULL;
}

/*
 * Takes ownership of html, a heap allocation of len bytes and more.  ids, if
 * not NULL, are of the elements that are changed in place once it's laid out
 */

static int
page_show(const char *name, char *html, int len, const char * const *ids)
{
	lws_dlo_filesystem_t f;
	char url[64];

	page_drop();

	memset(&f, 0, sizeof(f));
	f.name = name;
	f.data = html;
	f.len = (size_t)len;

	if (!lws_dlo_file_register(cx, &f)) {
		free(html);
		return 1;
	}

	page = html;
	page_name = name;

	/* the display is brought up when the page is on it */
	lws_snprintf(url, sizeof(url), "file://dlofs/%s", name);
	if (init_browse(cx, &rs, url, 0, ids)) {
		lwsl_err("%s: init_browse %s failed\n", __func__, url);
		lds.display_busy = 0;
		page_drop();
		return 1;
	}
	app_drawing = 1;

	return 0;
}

/* browse url as the application's page, framed */

static void
app_browse(const char *url)
{
	/* the display is brought up when the page is on it */
	if (init_browse(cx, &rs, url, 1, NULL)) {
		lwsl_err("%s: init_browse %s failed\n", __func__, url);
		lds.display_busy = 0;
		return;
	}

	app_drawing = 1;
}

static int
boot_have_creds(void);
static void
boot_changed(void);
static void
app_next(lws_sorted_usec_list_t *sul);
static void
app_reshow(lws_sorted_usec_list_t *sul);
static int
app_frame(unsigned int flags);
static void
sui_drop(void);

/*
 * The settings need a way to move around them and the keyboard: a touch
 * display, or buttons
 */

static int
settings_usable(void)
{
	static const char * const nav[] = {
		"up", "down", "left", "right", "enter"
	};
	size_t n;

	if (tcs)
		return 1;
	if (!bcs)
		return 0;

	for (n = 0; n < LWS_ARRAY_SIZE(nav); n++)
		if (!lws_button_get_bit(bcs, nav[n]))
			return 0;

	return 1;
}

static void
settings_open(unsigned int flags)
{
	if (!sui || lhp_settings_shown(&settings) || !settings_usable())
		return;

	if (ui == UI_APP) {
		if (carousel_phase == CAROUSEL_BLANKING || finished)
			/* it's ending */
			return;

		/* the carousel waits until they're finished with */
		lws_sul_cancel(&sul_app);
		handover = 0;
	}

	lwsl_notice("%s\n", __func__);
	lhp_settings_open(&settings, sui, flags);
}

/*
 * The settings were closed by the user.  We're told from inside the ui's
 * callbacks, which may show the dialog again after: decide what to show from
 * the event loop instead.
 */

static void
settings_exit_cb(lws_sorted_usec_list_t *sul)
{
	if (!sui || lhp_settings_shown(&settings))
		/* they were shown again meanwhile */
		return;

	lwsl_notice("%s\n", __func__);

	if (ui == UI_BOOT) {
		/* the boot list again, showing any AP stored meanwhile */
		lhp_boot_set(&boot, LHP_BOOT_SETUP, boot_have_creds());
		boot_dirty = 1;
		ui_kick();
		return;
	}

	/* the page that was shown, framed again, then the carousel goes on */

	if (carousel_phase == CAROUSEL_SHOWING_LAST)
		/* it's shown for as long again, once it's on the display */
		carousel_phase = CAROUSEL_LAST;

	lws_sul_schedule(cx, 0, &sul_app, app_reshow, 1);
}

static void
settings_exit(void *opaque)
{
	lws_sul_schedule(cx, 0, &sul_settings, settings_exit_cb, 1);
}

/*
 * Credentials were stored on the display: if we're an AP to be given them,
 * we restart to join it, as when they're stored from a browser
 */

static void
settings_stored(void *opaque)
{
	lws_wifi_provision_stored(prov);
}

/*
 * Our own generated pages: the edges and touch page, for finding out the
 * display's inset and seeing if touches land where they are on it, the grey
 * levels page, and the time zone page.  Each is unframed, all of what can be
 * seen, so the strip ui is dropped while it's shown, and made again after, the
 * size of what can be seen then.
 */

#define GEN_MAX2(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#define GEN_HTML_MAX GEN_MAX2(GEN_MAX2(LHP_EDGES_HTML_MAX, LHP_TZ_HTML_MAX), \
			      LHP_GREYS_HTML_MAX)

static const char *
gen_name(void)
{
	switch (gen_page) {
	case GEN_EDGES:
		return "edges";
	case GEN_GREYS:
		return "greys";
	case GEN_TZ:
		return "tz";
	default:
		return "none";
	}
}

static int
gen_show(void)
{
	char name[16], *html;
	int len;

	html = malloc(GEN_HTML_MAX);
	if (!html)
		return 1;

	switch (gen_page) {
	case GEN_EDGES:
		len = lhp_edges_html(html, GEN_HTML_MAX, &lds.ic, lds.inset,
				     &edges);
		break;
	case GEN_GREYS:
		len = lhp_greys_html(html, GEN_HTML_MAX, &lds.ic);
		break;
	case GEN_TZ:
		len = lhp_tz_html(html, GEN_HTML_MAX, &lds.ic, &tz,
				  (int64_t)lws_now_secs());
		break;
	default:
		len = -1;
		break;
	}
	if (len < 0) {
		lwsl_err("%s: unable to write the %s page\n", __func__,
			 gen_name());
		free(html);
		return 1;
	}

	lws_snprintf(name, sizeof(name), "%s.html", gen_name());

	return page_show(name, html, len, NULL);
}

/*
 * Finished with the page: what was found on it is kept, eg, the inset is used
 * from now on
 */

static void
gen_leave(void)
{
	switch (gen_page) {
	case GEN_EDGES:
		lwsl_notice("%s: inset %d, %d, %d, %d\n", __func__,
			    lds.inset[0], lds.inset[1], lds.inset[2],
			    lds.inset[3]);
		if (lhp_edges_store(cx, lds.inset))
			lwsl_warn("%s: unable to store the inset\n", __func__);
		break;
	case GEN_TZ:
		lwsl_notice("%s: time zones %s, %s\n", __func__,
			    lhp_tz_name(&tz, LHP_TZ_HOME),
			    lhp_tz_away(&tz) ? lhp_tz_name(&tz, LHP_TZ_AWAY) :
					       "no away");
		if (lhp_tz_store(cx, &tz))
			lwsl_warn("%s: unable to store the time zones\n",
				  __func__);
		break;
	default:
		break;
	}

	gen_page = GEN_NONE;

	/* what's shown next is all different */
	if (lds.disp->clear)
		lds.disp->clear(&lds);

	if (ui == UI_BOOT) {
		/* the boot list again, laid out on what can be seen now */
		lhp_boot_set(&boot, LHP_BOOT_SETUP, boot_have_creds());
		boot_dirty = 1;
		ui_kick();
		return;
	}

	/* the page that was shown, laid out again, then the carousel goes on */

	if (carousel_phase == CAROUSEL_SHOWING_LAST)
		carousel_phase = CAROUSEL_LAST;

	page_drop();
	if (!gen_back[0] || app_frame(0)) {
		lws_sul_schedule(cx, 0, &sul_app, app_next, 1);
		return;
	}

	app_browse(gen_back);
}

static void
gen_open_cb(lws_sorted_usec_list_t *sul)
{
	if (gen_page == GEN_NONE)
		/* something else took the display meanwhile, eg, an update */
		return;

	if (lds.display_busy) {
		lws_sul_schedule(cx, 0, &sul_settings, gen_open_cb,
				 LWS_US_PER_SEC / 10);
		return;
	}

	lwsl_notice("%s: %s\n", __func__, gen_name());

	/* a generated page isn't there to go back to */
	gen_back[0] = '\0';
	if (ui == UI_APP && strncmp(lds.current_url, "file://dlofs/", 13))
		lws_strncpy(gen_back, lds.current_url, sizeof(gen_back));

	sui_drop();
	switch (gen_page) {
	case GEN_EDGES:
		lhp_edges_reset(&edges);
		break;
	case GEN_TZ:
		/* a press on the map sets home, until away is pressed */
		tz.picking = LHP_TZ_HOME;
		break;
	default:
		break;
	}

	if (lds.disp->clear)
		lds.disp->clear(&lds);
	if (gen_show()) {
		lwsl_err("%s: unable to show the page\n", __func__);
		gen_leave();
	}
}

/*
 * "Edges and touch", "Grey levels" or "Time zones" was pressed in the
 * settings.  We're told from inside the ui's callbacks, and the ui is dropped
 * for the page: do it from the event loop instead.  It's the page's from now,
 * so nothing else is shown meanwhile.
 */

static void
settings_edges(void *opaque)
{
	gen_page = GEN_EDGES;
	lws_sul_schedule(cx, 0, &sul_settings, gen_open_cb, 1);
}

static void
settings_greys(void *opaque)
{
	gen_page = GEN_GREYS;
	lws_sul_schedule(cx, 0, &sul_settings, gen_open_cb, 1);
}

static void
settings_tz(void *opaque)
{
	gen_page = GEN_TZ;
	lws_sul_schedule(cx, 0, &sul_settings, gen_open_cb, 1);
}

/*
 * The boards show the demo's phase on the same led that's flashed while we're
 * an AP to be set up, or forgetting the credentials: then that's left alone
 */

void
lhp_demo_phase(int phase)
{
	if (plat_status_led &&
	    lws_wifi_provision_state(prov) != LWS_WIFI_PROV_IDLE)
		return;

	show_demo_phase(phase);
}

/*
 * Whether we're an AP to be set up from a browser changed: the boot list and
 * the settings say so while we are
 */

static void
prov_state(void *opaque, lws_wifi_provision_state_t state)
{
	const char *ssid = lws_wifi_provision_ap_ssid(prov),
		   *url = lws_wifi_provision_url(prov);
	char note[96];

	lwsl_notice("%s: %d\n", __func__, (int)state);

	boot.own_ap[0] = boot.own_ip[0] = '\0';
	note[0] = '\0';

	if (ssid && url && wnd) {
		lws_strncpy(boot.own_ap, ssid, sizeof(boot.own_ap));
		lws_strncpy(boot.own_ip, wnd->ap_ipv4, sizeof(boot.own_ip));
		lws_snprintf(note, sizeof(note), "Or join %s and browse %s",
			     ssid, url);
	}

	lhp_settings_note(&settings, note);
	boot_changed();
}

/* the strip ui's callbacks: while the settings are shown, they're theirs */

static int
sui_row(void *opaque, int idx, lws_dlo_ui_row_t *row)
{
	/* the settings are a dialog: the only list is the boot one */
	if (ui == UI_BOOT)
		return lhp_boot_row(&boot, idx, row);

	return 1;
}

static int
sui_done(void *opaque, const char *text)
{
	if (lhp_settings_shown(&settings))
		return lhp_settings_done(&settings, text);

	return 0;
}

/*
 * Pressing the title closes the settings.  On the boot list, it shows them,
 * eg, to add credentials for another AP, or change them for one
 */

static void
sui_title(void *opaque)
{
	if (lhp_settings_shown(&settings)) {
		lhp_settings_title(&settings);
		return;
	}

	if (ui == UI_BOOT)
		settings_open(0);
}

/*
 * The frame's title strip changed, on a display that can only take an update
 * of all of it: draw the page again as it is, under it.  If the page wasn't
 * kept to draw again, the change is shown with the next one.
 */

static void
sui_frame_redraw(void *opaque)
{
	if (lds.display_busy) {
		frame_redraw_pending = 1;
		return;
	}

	frame_redraw_pending = 0;
	if (ui == UI_APP && !redraw_page(&rs))
		app_drawing = 1;
}

/* say what the status capsule shows now: the ui draws it if it changed */

static void
status_update(void)
{
	lws_dlo_ui_status_t st;
	int rssi, pc, chg = 0;

	if (!sui)
		return;

	memset(&st, 0, sizeof(st));
	st.wlan = LWS_DLO_UI_STATUS_NONE;
	st.battery = LWS_DLO_UI_STATUS_NONE;

	if (wnd)
		st.wlan = (int8_t)(lws_netdev_wifi_rssi(&wnd->inst, &rssi) ?
						0 : lws_wifi_rssi_bars(rssi));

	if (plat_battery && !plat_battery(&pc, &chg)) {
		st.battery = (int8_t)(pc < 0 ? 0 : (pc > 100 ? 100 : pc));
		st.charging = !!chg;
	}

	lws_dlo_ui_set_status(sui, &st);
}

static void
status_cb(lws_sorted_usec_list_t *sul)
{
	status_update();
	lws_sul_schedule(cx, 0, &sul_status, status_cb, STATUS_US);
}

static int
sui_create(void)
{
	lws_dlo_ui_info_t i;

	if (sui)
		return 0;

	memset(&i, 0, sizeof(i));
	i.cx = cx;
	i.lds = &lds;
	i.row = sui_row;
	i.title = sui_title;
	i.done = sui_done;
	i.frame_redraw = sui_frame_redraw;
	/* pressing the status capsule is a "settings" button click */
	i.status_button = "settings";
	/* the title strip in the example's colours */
	i.css = "#t { background-color: " LHP_UI_STRIP_BG " }"
		"#tt { color: " LHP_UI_STRIP_FG " }"
		LHP_UI_STRIP_MONO;

	sui = lws_dlo_ui_create(&i);
	if (!sui) {
		lwsl_err("%s: unable to create ui\n", __func__);
		return 1;
	}

	if (ui == UI_BOOT) {
		lws_dlo_ui_aside_t a;

		/*
		 * The product's own beside the boot list, if the display is
		 * landscape: it goes with the boot list
		 */
		lhp_boot_aside(&a);
		if (lws_dlo_ui_set_aside(sui, &a))
			lwsl_warn("%s: no boot aside\n", __func__);
	}

	/* the capsule shows the status from the start, and keeps up with it */
	status_cb(&sul_status);

	return 0;
}

static void
sui_drop(void)
{
	lhp_settings_close(&settings);
	lws_sul_cancel(&sul_status);
	frame_redraw_pending = 0;
	/* no frame is coming to start the first page after */
	if (handover) {
		handover = 0;
		lws_sul_schedule(cx, 0, &sul_app, app_next, 1);
	}
	lws_dlo_ui_destroy(&sui);
}

/*
 * Show the frame over the application's page, titled with which page it is.
 * With LWS_DLO_UI_FRAME_DRAW, the ui draws the frame at once, over a white
 * body, otherwise it's drawn with the page.
 */

static int
app_frame(unsigned int flags)
{
	char title[16];

	if (sui_create())
		return 1;

	lws_snprintf(title, sizeof(title), "Page %d", page_no);
	lws_dlo_ui_set_title(sui, title);
	lws_dlo_ui_frame(sui, flags);

	return 0;
}

/* say what the boot list shows now: it draws it when the display is free */

static void
sui_show(void)
{
	lhp_boot_stage_t f;

	if (sui_create() || lhp_settings_shown(&settings))
		return;

	scan_count_shown = wnd ? lws_dll2_count(&wnd->scan) : 0;

	/*
	 * With no AP stored, there's nothing to join: once some are seen, we
	 * show them to pick one from, once.  Once it's stored, or the user
	 * goes back from them, it's the boot list again.
	 */
	if (!settings_offered && scan_count_shown &&
	    !(boot.reached & (1u << LHP_BOOT_SETUP)) && settings_usable()) {
		settings_offered = 1;
		lhp_settings_open(&settings, sui, LHP_SET_FL_EXIT_ON_STORE);
		return;
	}

	/* all done is shown as the last stage being worked on */

	f = lhp_boot_focus(&boot);
	lws_dlo_ui_set_title(sui, "Boot");
	lws_dlo_ui_set_list(sui, LHP_BOOT_COUNT,
			    f < LHP_BOOT_COUNT ? (int)f : LHP_BOOT_COUNT - 1);
}

/* a stage was reached, or something the overlay shows changed */

static void
boot_changed(void)
{
	if (ui != UI_BOOT)
		return;

	boot_dirty = 1;
	ui_kick();
}

/* the overlay comes down once we're OPERATIONAL and the first update check
 * has ended one way or another */

static void
boot_finish(void)
{
	if (!seen_operational || boot_done)
		return;

	lws_sul_cancel(&sul_boot_timeout);
	boot_done = 1;
	ui_kick();
}

static void
boot_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_warn("%s: no update check result, carrying on\n", __func__);
	boot_finish();
}

/*
 * Whether any wifi credentials are stored, which is the first boot stage, and
 * the AP they are for, which the overlay shows: the first stored, and how many
 * more.  The credentials are only kept in memory while something is using
 * them.
 */

static int
boot_have_creds(void)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(cx);
	lws_wifi_creds_t *c;
	uint32_t count;
	int have;

	boot.ap[0] = '\0';
	boot.aps = 0;

	lws_netdev_credentials_hold(nds);

	have = !!lws_dll2_get_head(&nds->owner_creds);
	if (have) {
		c = lws_container_of(lws_dll2_get_head(&nds->owner_creds),
				     lws_wifi_creds_t, list);
		lws_strncpy(boot.ap, c->ssid, sizeof(boot.ap));
		count = lws_dll2_count(&nds->owner_creds);
		boot.aps = (uint8_t)(count > 255 ? 255 : count);
	}

	lws_netdev_credentials_release(nds);

	return have;
}

/*
 * The update page already on the display is brought up to date in place: the
 * progress changed on it, and only that and the spinner drawn again.  Returns
 * 0 if that was started, or there was nothing to do, else nonzero, when the
 * page must be made and laid out again
 */

static int
update_in_place(void)
{
	if (strcmp(lds.current_url, UPDATE_URL))
		/* something else was shown meanwhile */
		return 1;

	if (update_pc != update_pc_shown && lhp_update_progress(&rs, update_pc))
		return 1;

	return redraw_damage(&rs) > 0;
}

static void
update_show(void)
{
	char *html;
	int len;

	/* stop the application meanwhile */
	lws_sul_cancel(&sul_app);

	if (update_pc_shown >= 0 && !update_in_place())
		goto shown;

	html = malloc(2048);
	if (!html)
		return;

	len = lhp_update_html(html, 2048, &lds.ic,
#if defined(LWS_WITH_OTA)
			      lws_ota_variant_name(),
#else
			      NULL,
#endif
			      update_pc,
			      !!lws_display_anim_interval(lds.disp,
							  UPDATE_SHOW_US));
	if (len < 0) {
		lwsl_err("%s: update page too big\n", __func__);
		free(html);
		return;
	}

	page_show("update.html", html, len, lhp_update_ids);

shown:
	update_pc_shown = update_pc;
	update_shown_us = lws_now_usecs();
}

/* the placeholder application: the next page of the carousel */

static void
app_next(lws_sorted_usec_list_t *sul)
{
	lws_system_states_t st = (lws_system_states_t)
				lws_system_get_state_manager(cx)->state;

	if (st == LWS_SYSTATE_AWAITING_MODAL_UPDATING ||
	    st == LWS_SYSTATE_MODAL_UPDATING)
		/* the update display has the display now */
		return;

	if (lds.display_busy) {
		lws_sul_schedule(cx, 0, &sul_app, app_next, LWS_US_PER_SEC);
		return;
	}

	if (!carousel_urls[carousel] || lhp_settings_shown(&settings) ||
	    gen_page)
		/* the one pass through the carousel already ended, or the
		 * settings or a generated page are shown: it goes on when
		 * they're finished with */
		return;

	lwsl_notice("%s: %s\n", __func__, carousel_urls[carousel]);

	page_drop();
	/*
	 * A different page: a display that can, eg, an EPD that only changes
	 * the pixels that differ, is cleared first, so nothing is left behind
	 * from the last one, unless it was left white
	 */
	if (lds.disp->clear && !display_white)
		lds.disp->clear(&lds);
	display_white = 0;
	/* if the white page never came, its end isn't the first page's */
	boot_blanking = 0;
	/* whether the frame was drawn before the first page or not */
	handover = 0;
	page_no = carousel + 1;
	app_frame(0);
#if defined(LWS_WITH_FOOTPRINT)
	/* what holds the heap as the next page starts */
	lws_footprint_dump(cx, 1);
#endif
	app_browse(carousel_urls[carousel++]);
	if (!carousel_urls[carousel])
		carousel_phase = CAROUSEL_LAST;
}

/*
 * After the settings, the page that was shown, framed again: drawn again as
 * it was laid out if it was kept, otherwise browsed again
 */

static void
app_reshow(lws_sorted_usec_list_t *sul)
{
	if (lds.display_busy) {
		lws_sul_schedule(cx, 0, &sul_app, app_reshow, LWS_US_PER_SEC);
		return;
	}

	if (app_frame(0) || !lds.current_url[0]) {
		lws_sul_schedule(cx, 0, &sul_app, app_next, 1);
		return;
	}

	if (!redraw_page(&rs)) {
		app_drawing = 1;
		return;
	}

	page_drop();
	app_browse(lds.current_url);
}

/*
 * Leave all of the display white, the frame too, eg, on an EPD, which keeps
 * showing what was on it
 */

static int
blank_show(void)
{
	static const char blank[] = "<!doctype html><html><head>"
		"<meta charset=\"utf-8\" />"
		"<link rel=\"stylesheet\" href=\"ui.css\"></head>"
		"<body></body></html>";
	char *html;

	html = malloc(sizeof(blank));
	if (!html)
		return 1;
	memcpy(html, blank, sizeof(blank));

	if (lds.disp->clear)
		lds.disp->clear(&lds);
	sui_drop();

	return page_show("blank.html", html, (int)sizeof(blank) - 1, NULL);
}

/*
 * The last page has been shown long enough: we are done, but on an EPD,
 * leave it white first
 */

static void
app_last_shown(lws_sorted_usec_list_t *sul)
{
	if (carousel_phase != CAROUSEL_SHOWING_LAST)
		/* the user took over meanwhile */
		return;

	if (!lds.disp->bistable) {
		/* the event loop ends and app_main() tears everything down */
		carousel_phase = CAROUSEL_DONE;
		finished = 1;
		return;
	}

	if (lds.display_busy) {
		lws_sul_schedule(cx, 0, &sul_app, app_last_shown,
				 LWS_US_PER_SEC);
		return;
	}

	lwsl_notice("%s: leaving the display white\n", __func__);
	carousel_phase = CAROUSEL_BLANKING;
	if (blank_show()) {
		carousel_phase = CAROUSEL_SHOWING_LAST;
		lws_sul_schedule(cx, 0, &sul_app, app_last_shown,
				 LWS_US_PER_SEC);
	}
}

/*
 * Decide what the display should show next.  It's done whenever something
 * changed, and when the display finishes an update: while it's busy, nothing
 * happens until then.  So on a slow display, the next update shows the state
 * as it is by then, however many changes it went through meanwhile.
 */

static void
ui_kick_cb(lws_sorted_usec_list_t *sul)
{
	lws_system_states_t st = (lws_system_states_t)
				lws_system_get_state_manager(cx)->state;

	if (!display_ready || lds.display_busy)
		return;

	if (st == LWS_SYSTATE_AWAITING_MODAL_UPDATING ||
	    st == LWS_SYSTATE_MODAL_UPDATING) {
		lws_usec_t every = lws_display_anim_interval(lds.disp,
							     UPDATE_SHOW_US);

		/* the update display takes over, whatever else is going on */
		gen_page = GEN_NONE;
		sui_drop();
		if (!every && update_pc_shown == update_pc)
			/* there's no spinner to move on */
			return;

		/*
		 * The first is shown at once, then no more often than the
		 * spinner is moved on, with the progress by then
		 */
		if (update_pc_shown >= 0) {
			lws_usec_t due = update_shown_us +
					 (every ? every : UPDATE_SHOW_STILL_US),
				   now = lws_now_usecs();

			if (now < due) {
				lws_sul_schedule(cx, 0, &sul_ui, ui_kick_cb,
						 due - now);
				return;
			}
		}

		update_show();
		return;
	}

	if (ui == UI_APP || gen_page)
		/* the application paces itself, and a generated page is
		 * shown until it's finished with */
		return;

	if (boot_done && !lhp_settings_shown(&settings)) {
		lwsl_notice("%s: boot complete, starting application\n",
			    __func__);
		ui = UI_APP;

		/*
		 * The boot list is replaced by the frame, titled with the
		 * first page.  An EPD takes long enough to update that we
		 * only show it with the first page.  One that can be cleared,
		 * eg, a directly-driven one that only changes the px that
		 * differ, updates quickly enough that meanwhile, the boot list
		 * is cleaned off it, so it's white while the first page is
		 * fetched and laid out.  Otherwise the frame is drawn now, and
		 * the first page is browsed once it's on the display
		 */
		page_no = 1;
		if (lds.disp->bistable) {
			if (lds.disp->clear) {
				boot_blanking = 1;
				if (!blank_show()) {
					/* in case it can't be drawn */
					lws_sul_schedule(cx, 0, &sul_app,
							 app_next,
							 HANDOVER_WAIT_US);
					return;
				}
				/* it can't be, eg, OOM: the first page
				 * clears it */
				boot_blanking = 0;
			}
		} else if (!app_frame(LWS_DLO_UI_FRAME_DRAW)) {
			handover = 1;
			/* in case the frame can't be drawn, eg, OOM */
			lws_sul_schedule(cx, 0, &sul_app, app_next,
					 HANDOVER_WAIT_US);
			return;
		}

		lws_sul_schedule(cx, 0, &sul_app, app_next, 1);
		return;
	}

	if (boot_dirty) {
		boot_dirty = 0;
		sui_show();
	}
}

/*
 * What changed is often learned inside a callback from lws, eg, a state
 * notification or the OTA stream's: decide from the event loop instead
 */

static void
ui_kick(void)
{
	lws_sul_schedule(cx, 0, &sul_ui, ui_kick_cb, 1);
}

static int
ota_progress(lws_ota_ret_t state, int percent)
{
	switch (state) {
	case LWSOTARET_UP_TO_DATE:
		boot.ota = LHP_BOOT_OTA_UP_TO_DATE;
		lhp_boot_set(&boot, LHP_BOOT_OTA, 1);
		boot_changed();
		boot_finish();
		break;

	case LWSOTARET_UPDATE_AVAILABLE:
		/* the modal update display will take over */
		boot.ota = LHP_BOOT_OTA_UPDATE;
		boot_changed();
		break;

	case LWSOTARET_FAILED:
		/* not fatal: we carry on with the firmware we have */
		boot.ota = LHP_BOOT_OTA_FAILED;
		boot_changed();
		boot_finish();
		break;

	case LWSOTARET_PROGRESS:
	case LWSOTARET_COMPLETED:
		update_pc = state == LWSOTARET_COMPLETED ? 100 : percent;
		ui_kick();
		break;

	default:
		break;
	}

	return 0;
}

/*
 * The time was set, from the rtc at boot or from ntp: lws already stepped the
 * system clock, and set the rtc from ntp's time.  The boot list shows the
 * time, and where it came from.
 */

static int
clock_set(lws_usec_t us)
{
	boot_changed();

	return 0;
}

static lws_system_ops_t system_ops = {
	.reboot				   = do_reboot,
	.set_clock			   = clock_set,
#if defined(LWS_WITH_OTA)

	.ota_ops			   = {
		.ota_start		   = lws_plat_ota_start,
		.ota_queue		   = lws_plat_ota_queue,
		.ota_detach		   = lws_plat_ota_detach,
		.ota_report_current	   = lws_plat_ota_report_current,
		.ota_get_last_fw_unixtime  = lws_plat_ota_get_last_fw_unixtime,
		.ota_progress		   = ota_progress,
	},
#endif
	.jit_trust_query		   = jit_trust_query
};

int
display_completion_cb(lws_display_state_t *lds, int a)
{
	char was_app;

	lwsl_info("%s: %d\n", __func__, a);

	switch (a) {

	case 1: /* display initialization finished */
		display_ready = 1;
		break;

	case 2: /* display update finished */

		lds->display_busy = 0;
		was_app = app_drawing;
		app_drawing = 0;

		/*
		 * Something new is on the display: bring it up to show it.
		 * Only now it's there, or it would show what was there before,
		 * from cold, whatever the panel's memory came up with
		 */
		lws_display_state_active(lds);
		lhp_demo_phase(LWS_LHPCD_PHASE_IDLE);
		page_drop();

		/* the strip ui draws anything that changed meanwhile */
		lws_dlo_ui_kick(sui);
		if (frame_redraw_pending)
			sui_frame_redraw(NULL);
		/* and the page is drawn where it was dragged to meanwhile */
		pan_kick();

		if (!was_app) {
			/* it was the strip ui's */
			if (handover && ui == UI_APP) {
				/* the frame is on the display: the first page */
				handover = 0;
				lws_sul_schedule(lds->ctx, 0, &sul_app,
						 app_next, 1);
			}
			break;
		}

		if (boot_blanking) {
			/* the boot list is cleaned off: the first page */
			boot_blanking = 0;
			if (update_pc_shown < 0) {
				display_white = 1;
				lws_sul_schedule(lds->ctx, 0, &sul_app,
						 app_next, 1);
			}
			break;
		}

		if (ui != UI_APP || carousel_phase == CAROUSEL_DONE ||
		    update_pc_shown >= 0 || lhp_settings_shown(&settings) ||
		    gen_page)
			/* the settings' or a generated page's exit draws it
			 * again, and goes on */
			break;

		if (carousel_phase == CAROUSEL_LAST) {
			/* the last page is on the display: show it a while */
			carousel_phase = CAROUSEL_SHOWING_LAST;
			lws_sul_schedule(lds->ctx, 0, &sul_app, app_last_shown,
					 CAROUSEL_PAGE_US);
			break;
		}

		if (carousel_phase == CAROUSEL_SHOWING_LAST)
			/* app_last_shown() is still to come */
			break;

		if (carousel_phase == CAROUSEL_BLANKING) {
			/*
			 * On an EPD, the white page after the last is on the
			 * display: we are done, the event loop ends and
			 * app_main() tears everything down
			 */
			carousel_phase = CAROUSEL_DONE;
			finished = 1;
			break;
		}

		/* show this page a while, then browse the next */

		lws_sul_schedule(lds->ctx, 0, &sul_app, app_next,
				 CAROUSEL_PAGE_US);
		break;
	}

	ui_kick();

	return 0;
}

/*
 * A touch press resolves to whatever link is displayed where it landed, and
 * navigates to it.  The display list that was rendered is kept
 * while it is displayed so this can be done; see init_browse() in lhp-ss.c.
 *
 * Scrolls and long presses are not presses: the finger moved, so it did not
 * mean to press what it started on, or it was held, which asks for something
 * else that this example doesn't have.  A scroll that began on the page drags
 * it around instead, see page_drag().
 */

static int
json_int(const void *buf, size_t len, const char *name, int *v)
{
	const char *p;
	char num[8];
	size_t al;

	p = lws_json_simple_find(buf, len, name, &al);
	if (!p || !al || al >= sizeof(num))
		return 1;

	lws_strnncpy(num, p, al, sizeof(num));
	*v = atoi(num);

	return 0;
}

static int
json_coord(const void *buf, size_t len, const char *name, int *v)
{
	return json_int(buf, len, name, v) || *v < 0;
}

/* is there a settled application page on the display to touch? */

static int
app_page_shown(void)
{
	lws_system_states_t st = (lws_system_states_t)
				lws_system_get_state_manager(cx)->state;

	return ui == UI_APP && rs.html == 2 && !lhp_settings_shown(&settings) &&
	       !gen_page && st != LWS_SYSTATE_AWAITING_MODAL_UPDATING &&
	       st != LWS_SYSTATE_MODAL_UPDATING;
}

/*
 * Move the page by what it was dragged meanwhile, and draw it there, once
 * the display is free: the render must not see the page move under it, and
 * a drag faster than the display can follow only draws where it got to
 */

static void
pan_kick(void)
{
	if ((!pan_dx && !pan_dy) || lds.display_busy)
		return;

	if (!app_page_shown()) {
		pan_dx = pan_dy = 0;
		return;
	}

	if (!lws_display_render_pan(&rs, pan_dx, pan_dy)) {
		/* it's as far as it goes that way already */
		pan_dx = pan_dy = 0;
		return;
	}

	if (!redraw_page(&rs)) {
		app_drawing = 1;
		pan_dx = pan_dy = 0;
	}
}

/* the page follows the finger, without being laid out again */

static void
page_drag(const void *buf, size_t len)
{
	int dx, dy;

	if (!app_drag || !app_page_shown() ||
	    json_int(buf, len, "\"dx\":", &dx) ||
	    json_int(buf, len, "\"dy\":", &dy))
		return;

	/* the user is looking at it: show it for as long again from now */

	if (carousel_phase == CAROUSEL_RUNNING)
		lws_sul_schedule(cx, 0, &sul_app, app_next, CAROUSEL_PAGE_US);
	if (carousel_phase == CAROUSEL_SHOWING_LAST)
		lws_sul_schedule(cx, 0, &sul_app, app_last_shown,
				 CAROUSEL_PAGE_US);

	/* the finger moving right shows more of the left of the page */
	pan_dx -= dx;
	pan_dy -= dy;
	pan_kick();
}

static void
touch_press(const void *buf, size_t len)
{
	char url[sizeof(lds.current_url)];
	lws_dlo_hit_t *h;
	int x, y, top = 0;

	if (!app_page_shown() || lds.display_busy)
		/* there's no settled application page to press on */
		return;

	if (json_coord(buf, len, "\"x\":", &x) ||
	    json_coord(buf, len, "\"y\":", &y) ||
	    /* it's on the surface, the page is on what can be seen of it */
	    lws_display_visible_xy(&lds, &x, &y))
		return;

	/* the page is below the frame's title strip */
	if (sui)
		lws_dlo_ui_frame_body(sui, &top);
	y -= top;
	if (y < 0)
		return;

	/* where it is on the page, wherever the page was dragged to */

	h = lws_display_dl_hit_test(&rs.displaylist, x + (int)rs.pan_x,
				    y + (int)rs.pan_y, NULL);
	if (!h || !h->url)
		return;

	if (lws_http_rel_to_url(url, sizeof(url), lds.current_url, h->url)) {
		lwsl_warn("%s: can't follow %s\n", __func__, h->url);
		return;
	}

	lwsl_notice("%s: %d,%d: %s\n", __func__, x, y, url);

	/* the user is driving now, the carousel stops */

	lws_sul_cancel(&sul_app);
	carousel_phase = CAROUSEL_DONE;

	page_drop();
	app_browse(url);
}

/*
 * A touch press on the edges page: on one of its controls, it does what that
 * says, otherwise it's measured against the target shown, see edges-ui.h
 */

static void
edges_press(const void *buf, size_t len)
{
	lhp_edges_act_t act = LHP_EDGES_ACT_NONE;
	int sx, sy, x, y, inside;
	lws_dlo_hit_t *h;
	uint8_t inset[4];

	if (lds.display_busy || rs.html != 2 || sui)
		/* it's being drawn, or not shown yet, so what's where isn't
		 * settled */
		return;

	if (json_coord(buf, len, "\"x\":", &sx) ||
	    json_coord(buf, len, "\"y\":", &sy))
		return;

	x = sx;
	y = sy;
	inside = !lws_display_visible_xy(&lds, &x, &y);

	memcpy(inset, lds.inset, sizeof(inset));
	if (inside) {
		/* the page is all of what can be seen, and isn't dragged */
		h = lws_display_dl_hit_test(&rs.displaylist, x, y, NULL);
		if (h && h->url)
			act = lhp_edges_href(h->url, inset);
	}

	switch (act) {
	case LHP_EDGES_ACT_DONE:
		gen_leave();
		return;

	case LHP_EDGES_ACT_RESET:
	case LHP_EDGES_ACT_CHANGED:
		if (act == LHP_EDGES_ACT_RESET)
			/* the board's own */
			memcpy(inset, lds.disp->inset, sizeof(inset));

		if (lws_display_set_inset(&lds, inset))
			/* it would leave nothing to see */
			return;

		lwsl_notice("%s: inset %d, %d, %d, %d\n", __func__,
			    inset[0], inset[1], inset[2], inset[3]);
		/* the targets are laid out on what can be seen now */
		lhp_edges_reset(&edges);
		break;

	default:
		lhp_edges_touch(&edges, &lds.ic, sx, sy, x, y, inside);
		break;
	}

	if (gen_show())
		lwsl_err("%s: unable to show the edges page\n", __func__);
}

/*
 * A touch press on the grey levels page: it has nothing to press, so anywhere
 * leaves it, once it's shown
 */

static void
greys_press(void)
{
	if (lds.display_busy || rs.html != 2 || sui)
		return;

	gen_leave();
}

/*
 * A touch press on the time zone page: on one of its controls, it does what
 * that says, and on the map, it picks the zone nearest, see tz-ui.h
 */

static void
tz_press(const void *buf, size_t len)
{
	const char *href = NULL;
	lws_dlo_hit_t *h;
	int x, y;

	if (lds.display_busy || rs.html != 2 || sui)
		/* it's being drawn, or not shown yet, so what's where isn't
		 * settled */
		return;

	if (json_coord(buf, len, "\"x\":", &x) ||
	    json_coord(buf, len, "\"y\":", &y) ||
	    /* the page is all of what can be seen, and isn't dragged */
	    lws_display_visible_xy(&lds, &x, &y))
		return;

	h = lws_display_dl_hit_test(&rs.displaylist, x, y, NULL);
	if (h && h->url)
		href = h->url;

	switch (lhp_tz_press(&lds.ic, &tz, href, x, y)) {
	case LHP_TZ_ACT_DONE:
		gen_leave();
		return;
	case LHP_TZ_ACT_CHANGED:
		break;
	default:
		return;
	}

	if (gen_show())
		lwsl_err("%s: unable to show the time zone page\n", __func__);
}

/* is it an event from a button called name, eg, "bc/settings" or "ui/settings" */

static int
is_button(const void *buf, size_t len, const char *name)
{
	size_t al, nl = strlen(name);
	const char *p;

	if (lws_json_simple_strcmp(buf, len, "\"type\":", "button"))
		return 0;

	p = lws_json_simple_find((const char *)buf, len, "\"src\":", &al);

	return p && al > nl && p[al - nl - 1] == '/' &&
	       !memcmp(p + al - nl, name, nl);
}

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{
	const char *p;
	size_t al;

	/* boards without leds have no led controller */
	if (lls && !lws_json_simple_strcmp(buf, len, "\"src\":", "bc/user") &&
	    !lws_json_simple_strcmp(buf, len, "\"event\":", "click")) {
		lws_led_transition(lls, "blue", seqs[flip & 3],
				   &lws_pwmseq_linear_wipe);
		flip++;
	}

	if (_class & LWSSMDCL_INTERACTION) {
		/*
		 * The strip ui acts on touches on it, and buttons named for
		 * moving around it, see lws_dlo_ui_interaction()
		 */
		int acted = sui && lws_dlo_ui_interaction(sui, buf, len);

		if (!acted && !lws_json_simple_strcmp(buf, len, "\"type\":",
						      "touch")) {
			/* touches on the frame's body are on the page */
			if (!lws_json_simple_strcmp(buf, len, "\"event\":",
						    "down"))
				/* a drag beginning now moves the page */
				app_drag = (char)app_page_shown();
			else if (!lws_json_simple_strcmp(buf, len,
						"\"event\":", "scroll"))
				page_drag(buf, len);
			else if (!lws_json_simple_strcmp(buf, len,
						"\"event\":", "press")) {
				if (gen_page == GEN_EDGES)
					edges_press(buf, len);
				else if (gen_page == GEN_GREYS)
					greys_press();
				else if (gen_page == GEN_TZ)
					tz_press(buf, len);
				else
					touch_press(buf, len);
			}
		} else if (!acted &&
			   !lws_json_simple_strcmp(buf, len, "\"event\":",
						   "click") &&
			   is_button(buf, len, "settings")) {
			/*
			 * A button, or pressing the status capsule: it shows
			 * the settings, or if they're shown, closes them as
			 * their title would, keeping a hostname being edited.
			 * The grey levels page has nothing on it to press, so
			 * the button leaves it, on a board without touch.
			 */
			if (gen_page == GEN_GREYS)
				gen_leave();
			else if (lhp_settings_shown(&settings))
				lhp_settings_exit(&settings);
			else
				settings_open(0);
		}

		/*
		 * Any kind of user interaction brings the display back up and
		 * resets the dimming / blanking timers
		 */
		lws_display_state_active(&lds);
	}

	if (!(_class & LWSSMDCL_NETWORK))
		return 0;

	lwsl_hexdump_info(buf, len);

	/*
	 * platform-private wifi event 1 is WIFI_EVENT_SCAN_DONE on esp32: the
	 * settings show the APs seen, and the boot list says how many there
	 * are while we have none to join
	 */

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "priv") &&
	    !lws_json_simple_strcmp(buf, len, "\"ev\":", "1")) {
		if (lhp_settings_shown(&settings))
			lhp_settings_scan(&settings);
		else if (ui == UI_BOOT &&
			 lhp_boot_focus(&boot) <= LHP_BOOT_WLAN && wnd &&
			 lws_dll2_count(&wnd->scan) != scan_count_shown)
			boot_changed();
		return 0;
	}

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "linkup") ||
	    !lws_json_simple_strcmp(buf, len, "\"type\":", "linkdown"))
		/* the capsule shows it at once */
		status_update();

	/*
	 * The settings show how joining each AP went, and if the internet was
	 * reached through it: what the netdev noted for these is listed when
	 * the dialog is laid out
	 */
	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "linkup") ||
	    !lws_json_simple_strcmp(buf, len, "\"type\":", "linkdown") ||
	    !lws_json_simple_strcmp(buf, len, "\"type\":", "ipacq") ||
	    !lws_json_simple_strcmp(buf, len, "\"type\":", "cpd"))
		lhp_settings_changed(&settings);

	if (ui != UI_BOOT)
		return 0;

	/* the network events the boot overlay shows */

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "linkup")) {
		lhp_boot_set(&boot, LHP_BOOT_SETUP, 1);
		if (lhp_boot_set(&boot, LHP_BOOT_WLAN, 1))
			boot_changed();
		return 0;
	}

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "linkdown")) {
		lhp_boot_set(&boot, LHP_BOOT_WLAN, 0);
		lhp_boot_set(&boot, LHP_BOOT_IPV4, 0);
		lhp_boot_set(&boot, LHP_BOOT_IPV6, 0);
		boot.ipv4[0] = boot.ipv6[0] = '\0';
		boot_changed();
		return 0;
	}

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "ipacq")) {
		p = lws_json_simple_find(buf, len, "\"ipv4\":", &al);
		if (p) {
			lws_strnncpy(boot.ipv4, p, al, sizeof(boot.ipv4));
			lhp_boot_set(&boot, LHP_BOOT_IPV4, 1);
			boot_changed();
		}
		p = lws_json_simple_find(buf, len, "\"ipv6\":", &al);
		if (p) {
			lws_strnncpy(boot.ipv6, p, al, sizeof(boot.ipv6));
			lhp_boot_set(&boot, LHP_BOOT_IPV6, 1);
			boot_changed();
		}
		return 0;
	}

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "cpd")) {
		/* the overlay shows a captive portal or no internet itself */
		lhp_boot_set(&boot, LHP_BOOT_INTERNET,
			     !lws_json_simple_strcmp(buf, len, "\"result\":",
						     "OK"));
		boot_changed();
		return 0;
	}

	return 0;
}

/* the boot stages that being at system state st means are reached */

static void
boot_states(int st)
{
	if (st >= LWS_SYSTATE_TIME_VALID && st <= LWS_SYSTATE_OPERATIONAL &&
	    lhp_boot_set(&boot, LHP_BOOT_DATE, 1))
		boot_changed();

	/* AUTH1 and AUTH2 are behind us */
	if (st > LWS_SYSTATE_AUTH2 && st <= LWS_SYSTATE_OPERATIONAL &&
	    lhp_boot_set(&boot, LHP_BOOT_AUTH, 1))
		boot_changed();
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		 int current, int target)
{
	if (current == target) {
		/* we arrived at a state */

		boot_states(current);

		if (current == LWS_SYSTATE_AWAITING_MODAL_UPDATING)
			/* the update display takes over the display */
			ui_kick();

		if (current == LWS_SYSTATE_OPERATIONAL) {
			if (!seen_operational) {
				seen_operational = 1;
#if defined(LWS_WITH_OTA)
				/* the first update check is coming */
				boot.ota = LHP_BOOT_OTA_CHECKING;
				lws_sul_schedule(cx, 0, &sul_boot_timeout,
						 boot_timeout_cb,
						 BOOT_OTA_WAIT_US);
				boot_changed();
#else
				boot.ota = LHP_BOOT_OTA_DISABLED;
				boot_finish();
#endif
			}

			if (update_pc_shown >= 0) {
				/* an update didn't happen: back to the app */
				update_pc_shown = -1;
				if (ui == UI_APP)
					lws_sul_schedule(cx, 0, &sul_app,
							 app_next, 1);
				else
					boot_changed();
			}
		}
	}

	if (current != LWS_SYSTATE_MODAL_UPDATING &&
	    target == LWS_SYSTATE_MODAL_UPDATING) {

		/*
		 * do we feel like we should okay the transition to
		 * MODAL_UPDATING?  Or are we busy using heap right now?  If
		 * not yet, the OTA asks again each second.
		 */

		if (update_pc_shown < 0) {
			/* did not start showing the modal update display yet */
			ui_kick();

			return 1;
		}

		if (lds.display_busy)
			/* still updating display / using heap for that */
			return 1;

		/*
		 * We are showing the update display, and we're not busy
		 * updating the display any more... at least we don't have any
		 * objection now to the transition
		 */
		return 0;
	}

	return 0;
}

/*
 * Undo everything app_main() did, while the context still exists, then destroy
 * the context.  The free heap after should be what it was before the context
 * was created, less whatever the platform keeps.
 */

static void
teardown(uint32_t heap_before)
{
	uint32_t heap_after;

	lws_wifi_provision_destroy(&prov);

	/* a touch board kept what it displayed to resolve presses against */
	lws_display_list_destroy(cx, &rs.displaylist);
	lws_display_render_free_ids(&rs);
	page_drop();
	sui_drop();
	lhp_settings_deinit(&settings);
	lhp_tz_deinit(cx);
	lhp_boot_deinit(&boot);
	lhp_update_deinit(cx);

	lws_display_state_off(&lds);
	deinit_plat_devices(cx);
	lws_display_state_fini(&lds);

	lws_context_destroy(cx);
	cx = NULL;

	heap_after = (uint32_t)esp_get_free_heap_size();

	lwsl_notice("%s: free heap %u before context, %u after destroy "
		    "(%d), low water %u\n", __func__, (unsigned int)heap_before,
		    (unsigned int)heap_after,
		    (int)heap_after - (int)heap_before,
		    (unsigned int)esp_get_minimum_free_heap_size());

	/* In CI, sai-expect looks for this string for success */

	if (heap_after + HEAP_RETURN_MARGIN >= heap_before)
		lwsl_notice("Completed: PASS\n");
	else
		lwsl_err("Completed: FAIL: %u bytes of heap not returned\n",
			 (unsigned int)(heap_before - heap_after));
}

void
app_main(void)
{
	struct lws_context_creation_info *info;
	uint32_t heap_before;
	lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
					     system_notify_cb, "app" };
	lws_state_notify_link_t *na[] = { &notifier, NULL };
	uint8_t inset[4];

	lws_set_log_level(LLL_USER | LLL_NOTICE | LLL_WARN | LLL_ERR, NULL);

        lws_netdev_plat_init();
        lws_netdev_plat_wifi_init();

	/* what we should come back to after the context is destroyed */
	heap_before = (uint32_t)esp_get_free_heap_size();

        info = malloc(sizeof(*info));
        if (!info)
		goto spin;

	memset(info, 0, sizeof(*info));

#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	info->pss_policies_json		= ss_policy;
#else
	info->pss_policies		= &_ss_static_policy_entry;
#endif
	info->options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info->port			= CONTEXT_PORT_NO_LISTEN;
	info->early_smd_cb		= smd_cb;
	info->early_smd_class_filter	= LWSSMDCL_INTERACTION |
					  LWSSMDCL_SYSTEM_STATE |
					  LWSSMDCL_NETWORK;
	info->smd_ttl_us		= 20 * LWS_USEC_PER_SEC; /* we can spend a long time in display */
	info->system_ops		= &system_ops;
	info->register_notifier_list	= na;
#if defined(LWS_WITH_DLO_ASSET_CACHE)
	info->dlo_asset_cache_max_footprint = ASSET_CACHE_BYTES;
#endif

	cx = lws_create_context(info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		goto spin;
	}

	/*
	 * We don't need this after context creation... things it pointed to
	 * still need to exist though since the context copied the pointers.
	 */

	free(info);

	/*
	 * Make a soft copy of the dlo fops, insert it in fops chain so that
	 * the plat one is first, as expected by the VFS code
	 */

	dlo_fops = lws_dlo_fops;
	dlo_fops.cx = cx;
	dlo_fops.next = lws_get_fops(cx)->next; /* insert after plat */
	lws_get_fops(cx)->next = &dlo_fops;

	if (lhp_update_init(cx))
		lwsl_warn("%s: no update spinner\n", __func__);
	fs_ui_css.len = strlen((const char *)fs_ui_css.data);
	lws_dlo_file_register(cx, &fs_ui_css);

	/* devices and init are in devices.c */

	if (init_plat_devices(cx))
		goto spin;

	/*
	 * The inset found on the edges page, if one was stored, instead of the
	 * board's, before anything is laid out on what can be seen
	 */
	if (!lhp_edges_load(cx, inset)) {
		lwsl_notice("%s: stored inset %d, %d, %d, %d\n", __func__,
			    inset[0], inset[1], inset[2], inset[3]);
		if (lws_display_set_inset(&lds, inset))
			lwsl_warn("%s: stored inset leaves nothing\n",
				  __func__);
	}

	/* the time zones stored, and the map to pick them on */
	if (lhp_tz_init(cx, &tz))
		goto spin;

	/*
	 * The settings, shown on the strip ui when asked for.  The edges and
	 * time zone pages are pressed on, so they're only offered with a touch
	 * panel.  The grey levels page is left by the settings button too, so
	 * it's offered whenever the display can show it.
	 */
	if (lhp_settings_init(&settings, cx, wnd, settings_exit,
			      settings_stored, tcs ? settings_edges : NULL,
			      lhp_greys_usable(&lds.ic) ? settings_greys : NULL,
			      tcs ? settings_tz : NULL, &tz, NULL))
		goto spin;

	/* the boot overlay, shown when the display is ready */

	if (lhp_boot_init(cx, &boot, wnd))
		goto spin;
	boot.tz = &tz;
	/*
	 * The system state may already be past where the notifier marks
	 * stages reached, eg, an rtc gave us the time while the devices were
	 * initialized
	 */
	boot_states(lws_system_get_state_manager(cx)->state);
	lhp_boot_set(&boot, LHP_BOOT_SETUP, boot_have_creds());
	boot_dirty = 1;

	/*
	 * If we have no wifi credentials we can use, we become an AP to be
	 * given them from a browser, as well as on the display
	 */

	if (wnd) {
		lws_wifi_provision_info_t pi;

		memset(&pi, 0, sizeof(pi));
		pi.cx			= cx;
		pi.wnd			= wnd;
		pi.lls			= lls;
		pi.led			= plat_status_led;
		pi.reset_button		= plat_reset_button;
		pi.buttons		= bcs;
		/* the settings' images, served beside them */
		pi.files		= lhp_settings_files(&pi.count_files);
		/* the product's own, at the top of them, as on the display */
		pi.header_html		= lhp_settings_header_html();
		pi.css			= lhp_settings_header_css();
		pi.cb			= prov_state;

		prov = lws_wifi_provision_create(&pi);
		if (!prov)
			lwsl_warn("%s: can't be set up from a browser\n",
				  __func__);
	}

	lhp_demo_phase(LWS_LHPCD_PHASE_IDLE);

	/* the lws event loop */

	do {
		taskYIELD();
		lws_service(cx, 0);
	} while (!finished);

	lwsl_notice("%s: exited event loop\n", __func__);

	teardown(heap_before);


spin:
	while (1) {
		vTaskDelay(10);
		taskYIELD();
	}
}
