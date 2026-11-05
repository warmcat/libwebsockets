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
 * If no wifi credentials are stored, once a scan has found some APs, it lists
 * those instead, titled "AP", strongest first, for the user to pick one on a
 * touch display.  Once the system is OPERATIONAL and the first update check
 * has told us we're on the latest firmware (or failed, or there's no OTA),
 * the ui comes down and the application html is shown instead.
 *
 * The application is a placeholder for now: it visits each URL in the
 * board's carousel once, rendering it on the display via LHP, and showing
 * each for 10s once it is on the display, the last one too, then it ends.
 * On a touch display, the page shown can be dragged around, to see the rest
 * of one longer or wider than the display, or on a round display, what is in
 * the corners the circle doesn't show.  Each drag gives the page another 10s
 * before the carousel moves on.  Pressing a link stops the carousel.
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
#include <esp_wifi_types.h>
#include "boot-ui.h"
#include "update-ui.h"

struct lws_context *cx;
struct lws_touch_state *tcs;

/* how long we wait after OPERATIONAL for the first update check to end */
#define BOOT_OTA_WAIT_US	(90 * LWS_US_PER_SEC)
/*
 * How often the update display shows the progress: drawing it takes time
 * from fetching and flashing the update
 */
#define UPDATE_SHOW_US		(3 * LWS_US_PER_SEC)

static enum {
	UI_BOOT,	/* the boot overlay */
	UI_APP,		/* the application html */
} ui;

/* how long each page of the carousel is shown, once it is on the display */
#define CAROUSEL_PAGE_US	(10 * LWS_US_PER_SEC)

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
static int carousel, update_pc, update_pc_shown = -1;
static lws_sorted_usec_list_t sul_app, sul_boot_timeout, sul_ui;
/* when the update display was last shown */
static lws_usec_t update_shown_us;
static char display_ready, boot_dirty, boot_done, seen_operational,
	    finished;
static uint32_t scan_sig_shown;
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
 * The boot overlay, or the APs to pick from, are a strip ui: we say what its
 * title and list hold, and it draws them.  The APs are a copy of the scan
 * results as they were when the list was last set, so a row picked is the AP
 * that was shown there.
 */

#define AP_LIST_MAX		16

static struct lws_dlo_ui *sui;
static char sui_aps;	/* the list is of the APs, not the boot stages */
static char sui_want_aps; /* the APs were asked for, by pressing the title */
static char aps[AP_LIST_MAX][33];
static char aps_open[AP_LIST_MAX];	/* needs no passphrase */
static char aps_stored[AP_LIST_MAX];	/* we have credentials for it */
static int ap_count;
static char sui_ssid[33];	/* the AP picked, whose passphrase is typed */

/* the generated page in the dlo filesystem that is being shown, if any */
static char *page;
static const char *page_name;

extern const char *carousel_urls[];

#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
#include "./static-policy.h"
#else
#include "./policy.h"
#endif

static const uint8_t jit_trust_blob[] = {
#include "./trust_blob.h"
};

static const uint8_t update_icon[] = {
#include "update-icon.png.h"
};
static const lws_dlo_filesystem_t fs_update_icon = {
	.name			= "update-icon.png",
	.data			= &update_icon,
	.len			= sizeof(update_icon)
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

/* takes ownership of html, a heap allocation of len bytes and more */

static int
page_show(const char *name, char *html, int len)
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
	if (init_browse(cx, &rs, url)) {
		lwsl_err("%s: init_browse %s failed\n", __func__, url);
		lds.display_busy = 0;
		page_drop();
		return 1;
	}

	return 0;
}

/*
 * Order-independent signature of the set of APs in the scan list, so we can
 * tell when what the boot overlay says about the APs seen while it looks for
 * one is stale, without redrawing on every
 * scan (the averaged rssi jitters, so rssi and ordering are deliberately left
 * out)
 */

static uint32_t
scan_sig(void)
{
	uint32_t sig = 0;

	if (!wnd)
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&wnd->scan)) {
		lws_wifi_sta_t *w = lws_container_of(d, lws_wifi_sta_t, list);
		uint32_t h = 2166136261u;
		int n;

		for (n = 0; n < 6; n++)
			h = (h ^ w->bssid[n]) * 16777619u;
		h = (h ^ (uint8_t)w->ch) * 16777619u;

		sig += h;
	} lws_end_foreach_dll(d);

	return sig;
}

/*
 * The networks in the scan results, the strongest BSS of each, strongest
 * first as the scan is sorted.  Hidden ones, with no SSID, can't be picked.
 */

static void
aps_update(void)
{
	lws_netdevs_t *nds = lws_netdevs_from_ctx(cx);
	int n;

	ap_count = 0;
	if (!wnd)
		return;

	/* which we have credentials for */
	lws_netdev_credentials_hold(nds);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&wnd->scan)) {
		lws_wifi_sta_t *w = lws_container_of(d, lws_wifi_sta_t, list);
		char ssid[33];

		if (ap_count == AP_LIST_MAX)
			break;

		lws_strnncpy(ssid, w->ssid, w->ssid_len, sizeof(ssid));
		if (!ssid[0])
			continue;

		for (n = 0; n < ap_count; n++)
			if (!strcmp(aps[n], ssid))
				break;

		if (n < ap_count)
			continue;

		aps_open[ap_count] = w->authmode == WIFI_AUTH_OPEN;
		aps_stored[ap_count] = 0;
		lws_start_foreach_dll(struct lws_dll2 *, c,
				      lws_dll2_get_head(&nds->owner_creds)) {
			if (!strcmp(lws_container_of(c, lws_wifi_creds_t,
						     list)->ssid, ssid))
				aps_stored[ap_count] = 1;
		} lws_end_foreach_dll(c);
		memcpy(aps[ap_count++], ssid, sizeof(ssid));
	} lws_end_foreach_dll(d);

	lws_netdev_credentials_release(nds);
}

static int
sui_row(void *opaque, int idx, lws_dlo_ui_row_t *row)
{
	if (!sui_aps)
		return lhp_boot_row(&boot, idx, row);

	if (idx < 0 || idx >= ap_count)
		return 1;

	lws_strncpy(row->text, aps[idx], sizeof(row->text));
	/* the ones we can already join are highlighted */
	if (aps_stored[idx])
		row->state = LWS_DLO_UI_ROW_FOCUS;

	return 0;
}

static int
boot_have_creds(void);
static void
boot_changed(void);

/*
 * Store the credentials for the AP that was picked.  The wifi netdev keeps
 * scanning while it has none, and joins it when it next sees it
 */

static void
sui_store(const char *passphrase)
{
	if (lws_netdev_credentials_add(lws_netdevs_from_ctx(cx), sui_ssid,
				       passphrase)) {
		lwsl_err("%s: unable to store credentials\n", __func__);
		return;
	}

	lwsl_user("%s: stored credentials for %s\n", __func__, sui_ssid);

	/* the boot overlay goes on to show it being joined */
	sui_want_aps = 0;
	lhp_boot_set(&boot, LHP_BOOT_SETUP, boot_have_creds());
	boot_changed();
}

static void
sui_pick(void *opaque, int idx)
{
	if (!sui_aps || idx < 0 || idx >= ap_count)
		return;

	lws_strncpy(sui_ssid, aps[idx], sizeof(sui_ssid));

	if (aps_open[idx]) {
		sui_store("");
		return;
	}

	/*
	 * WPA passphrases are up to 63 characters.  It's shown as it's typed,
	 * so typos can be seen on the small keyboard.  It starts empty, even
	 * if one is stored for the AP: Done replaces that one
	 */
	if (lws_dlo_ui_edit(sui, "Passphrase", 63, 0))
		lwsl_err("%s: unable to edit passphrase\n", __func__);
}

/* the passphrase was typed, or text is NULL if it was abandoned */

static int
sui_done(void *opaque, const char *text)
{
	if (!text)
		/* back to the list of APs */
		return 0;

	if (strlen(text) < 8)
		/* WPA passphrases are at least 8 characters: keep typing */
		return 1;

	sui_store(text);

	return 0;
}

/*
 * Pressing the title goes between the boot stages and the APs, eg, to add
 * credentials for another AP, or change them for one
 */

static void
sui_title(void *opaque)
{
	sui_want_aps = !sui_aps;
	boot_changed();
}

static void
sui_drop(void)
{
	lws_dlo_ui_destroy(&sui);
}

/* say what the strip ui shows now: it draws it when the display is free */

static void
sui_show(void)
{
	lhp_boot_stage_t f;

	if (!sui) {
		lws_dlo_ui_info_t i;

		memset(&i, 0, sizeof(i));
		i.cx = cx;
		i.lds = &lds;
		i.row = sui_row;
		i.pick = sui_pick;
		i.title = sui_title;
		i.done = sui_done;
		/* the title strip in the example's colours */
		i.css = "#t { background-color: " LHP_UI_STRIP_BG " }"
			"#tt { color: " LHP_UI_STRIP_FG " }";

		sui = lws_dlo_ui_create(&i);
		if (!sui) {
			lwsl_err("%s: unable to create ui\n", __func__);
			return;
		}
	}

	scan_sig_shown = scan_sig();
	aps_update();

	sui_aps = (sui_want_aps || !(boot.reached & (1u << LHP_BOOT_SETUP))) &&
		  ap_count;
	if (sui_aps) {
		lws_dlo_ui_set_title(sui, "AP");
		lws_dlo_ui_set_list(sui, ap_count, -1);
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

static void
update_show(void)
{
	char *html = malloc(2048);
	int len;

	if (!html)
		return;

	/* stop the application meanwhile */
	lws_sul_cancel(&sul_app);

	len = lhp_update_html(html, 2048, &lds.disp->ic,
#if defined(LWS_WITH_OTA)
			      lws_ota_variant_name(),
#else
			      NULL,
#endif
			      update_pc);
	if (len < 0) {
		lwsl_err("%s: update page too big\n", __func__);
		free(html);
		return;
	}

	update_pc_shown = update_pc;
	update_shown_us = lws_now_usecs();
	page_show("update.html", html, len);
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

	if (!carousel_urls[carousel])
		/* the one pass through the carousel already ended */
		return;

	lwsl_notice("%s: %s\n", __func__, carousel_urls[carousel]);

	page_drop();
#if defined(LWS_WITH_FOOTPRINT)
	/* what holds the heap as the next page starts */
	lws_footprint_dump(cx, 1);
#endif
	/* the display is brought up when the page is on it */
	if (init_browse(cx, &rs, carousel_urls[carousel++])) {
		lwsl_err("%s: init_browse failed\n", __func__);
		lds.display_busy = 0;
	}
	if (!carousel_urls[carousel])
		carousel_phase = CAROUSEL_LAST;
}

/*
 * The last page has been shown long enough: we are done, but on an EPD,
 * leave it white first
 */

static void
app_last_shown(lws_sorted_usec_list_t *sul)
{
	static const char blank[] = "<!doctype html><html><head>"
		"<meta charset=\"utf-8\" />"
		"<link rel=\"stylesheet\" href=\"ui.css\"></head>"
		"<body></body></html>";
	char *html;

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

	html = malloc(sizeof(blank));
	if (!html) {
		lws_sul_schedule(cx, 0, &sul_app, app_last_shown,
				 LWS_US_PER_SEC);
		return;
	}
	memcpy(html, blank, sizeof(blank));

	lwsl_notice("%s: leaving the display white\n", __func__);
	carousel_phase = CAROUSEL_BLANKING;
	if (page_show("blank.html", html, (int)sizeof(blank) - 1)) {
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
		/* the update display takes over, whatever else is going on */
		sui_drop();
		if (update_pc_shown == update_pc)
			return;

		/*
		 * The first is shown at once, then no more often than
		 * UPDATE_SHOW_US, showing the progress by then
		 */
		if (update_pc_shown >= 0) {
			lws_usec_t due = update_shown_us + UPDATE_SHOW_US,
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

	if (ui == UI_APP)
		/* the application paces itself */
		return;

	if (boot_done) {
		lwsl_notice("%s: boot complete, starting application\n",
			    __func__);
		ui = UI_APP;
		sui_drop();
		lhp_boot_deinit(&boot);
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

static lws_system_ops_t system_ops = {
	.reboot				   = do_reboot,
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
	lwsl_info("%s: %d\n", __func__, a);

	switch (a) {

	case 1: /* display initialization finished */
		display_ready = 1;
		break;

	case 2: /* display update finished */

		lds->display_busy = 0;

		/*
		 * Something new is on the display: bring it up to show it.
		 * Only now it's there, or it would show what was there before,
		 * from cold, whatever the panel's memory came up with
		 */
		lws_display_state_active(lds);
		show_demo_phase(LWS_LHPCD_PHASE_IDLE);
		page_drop();

		/* the strip ui draws anything that changed meanwhile */
		lws_dlo_ui_kick(sui);
		/* and the page is drawn where it was dragged to meanwhile */
		pan_kick();

		if (ui != UI_APP || carousel_phase == CAROUSEL_DONE ||
		    update_pc_shown >= 0)
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

	return ui == UI_APP && rs.html == 2 &&
	       st != LWS_SYSTATE_AWAITING_MODAL_UPDATING &&
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

	if (!redraw_page(&rs))
		pan_dx = pan_dy = 0;
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
	int x, y;

	if (!app_page_shown() || lds.display_busy)
		/* there's no settled application page to press on */
		return;

	if (json_coord(buf, len, "\"x\":", &x) ||
	    json_coord(buf, len, "\"y\":", &y))
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
	if (init_browse(cx, &rs, url)) {
		lwsl_err("%s: init_browse %s failed\n", __func__, url);
		lds.display_busy = 0;
	}
}

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{
	const char *p;
	size_t al;

	if (!lws_json_simple_strcmp(buf, len, "\"src\":", "bc/user") &&
	    !lws_json_simple_strcmp(buf, len, "\"event\":", "click")) {
		lws_led_transition(lls, "blue", seqs[flip & 3],
				   &lws_pwmseq_linear_wipe);
		flip++;
	}

	if ((_class & LWSSMDCL_INTERACTION) &&
	    !lws_json_simple_strcmp(buf, len, "\"type\":", "touch")) {
		/* while the strip ui is up, touches are for it */
		if (sui)
			lws_dlo_ui_touch(sui, buf, len);
		else if (!lws_json_simple_strcmp(buf, len, "\"event\":",
						 "down"))
			/* a drag beginning now moves the page, if it's up */
			app_drag = (char)app_page_shown();
		else if (!lws_json_simple_strcmp(buf, len, "\"event\":",
						 "scroll"))
			page_drag(buf, len);
		else if (!lws_json_simple_strcmp(buf, len, "\"event\":",
						 "press"))
			touch_press(buf, len);
	}

	if (_class & LWSSMDCL_INTERACTION)
		/*
		 * Any kind of user interaction brings the display back up and
		 * resets the dimming / blanking timers
		 */
		lws_display_state_active(&lds);

	if (!(_class & LWSSMDCL_NETWORK) || ui != UI_BOOT)
		return 0;

	lwsl_hexdump_info(buf, len);

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

	/*
	 * platform-private wifi event 1 is WIFI_EVENT_SCAN_DONE on esp32: the
	 * ui says how many APs it sees while we have none to join, and lists
	 * them to pick from if none is stored
	 */

	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "priv") &&
	    !lws_json_simple_strcmp(buf, len, "\"ev\":", "1") &&
	    lhp_boot_focus(&boot) <= LHP_BOOT_WLAN &&
	    scan_sig() != scan_sig_shown)
		boot_changed();

	return 0;
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		 int current, int target)
{
	if (current == target) {
		/* we arrived at a state */

		if (current >= LWS_SYSTATE_TIME_VALID &&
		    current <= LWS_SYSTATE_OPERATIONAL &&
		    lhp_boot_set(&boot, LHP_BOOT_DATE, 1))
			boot_changed();

		/* AUTH1 and AUTH2 are behind us */
		if (current > LWS_SYSTATE_AUTH2 &&
		    current <= LWS_SYSTATE_OPERATIONAL &&
		    lhp_boot_set(&boot, LHP_BOOT_AUTH, 1))
			boot_changed();

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

	/* a touch board kept what it displayed to resolve presses against */
	lws_display_list_destroy(cx, &rs.displaylist);
	lws_display_render_free_ids(&rs);
	page_drop();
	sui_drop();
	lhp_boot_deinit(&boot);

	lws_display_state_off(&lds);
	deinit_plat_devices(cx);

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

	lws_dlo_file_register(cx, &fs_update_icon);
	fs_ui_css.len = strlen((const char *)fs_ui_css.data);
	lws_dlo_file_register(cx, &fs_ui_css);

	/* devices and init are in devices.c */

	if (init_plat_devices(cx))
		goto spin;

	/* the boot overlay, shown when the display is ready */

	if (lhp_boot_init(cx, &boot, wnd))
		goto spin;
	lhp_boot_set(&boot, LHP_BOOT_SETUP, boot_have_creds());
	boot_dirty = 1;

	show_demo_phase(LWS_LHPCD_PHASE_IDLE);

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
