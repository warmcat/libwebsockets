/*
 * main
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * General main() for embedded LHP examples.  Board-specific stuff like
 * differences in platform / device / display availability and bringup is in
 * ./main/devices.c in the individual directories.
 *
 * This example moves through a carousel of URLs every 10s and updates the
 * display with them via LHP.
 *
 * These examples are currently available for a bunch of ESP32 variants... but
 * there is no ESP32-specific code here.
 */

#include "main.h"

struct lws_context *cx;

static lws_dlo_filesystem_t *fs_splash_html, *fs_update_html;
static char did_splash, seen_operational, subsequent;
static int carousel, boot_step = -1, lbs, update_pc, lupc = -1;
static lws_sorted_usec_list_t sul_display_update;
static struct lws_plat_file_ops dlo_fops;
static lws_display_render_state_t rs;
static uint8_t flip;

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
	"body { font-family: sun; font-size: 12pt; background-color: #fff; }"
	"h1 { font-family: sans; font-size: 32px; text-align: center; margin-bottom: 12px; color:#000; }"
	".vari { font-family: sans; font-size: 20px; text-align: center; margin-bottom: 4px; color:#00f; }"
	".icon { display: block; width: 96px; height: 96px; color: #000; margin-left: auto; margin-right:auto; margin-bottom: 10px }"
	".bar { display: inline; width: 260px; height: 30px; color: #fff; background-color: #000; margin-left: auto; margin-right:auto; padding-left:4px; padding-right:4px; padding-top:4px; padding-bottom: 4px; margin-bottom: 48px }"
	".c { display: inline-block; background-color: #ccf; width: 50%; padding-top: 1px; padding-bottom: 1px; }";

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
	 * DER will remain NULL if no match.
	 */

	lws_tls_jit_trust_blob_queury_skid(jit_trust_blob,
					   sizeof(jit_trust_blob), skid,
					   skid_len, &der, &der_len);

	if (der)
		lwsl_info("%s: found len %d\n", __func__, (int)der_len);
	else
		lwsl_info("%s: not trusted\n", __func__);

	/* Once we have a result, pass it to the completion helper */

	return lws_tls_jit_trust_got_cert_cb(cx, got_opaque, skid, skid_len,
					     der, der_len);
}

static int
do_reboot(void)
{
	esp_restart();
}

static int
display_update(lws_display_state_t *lds)
{
	char *p;

	if (lupc == update_pc)
		return 0;

	lws_dlo_file_unregister(&fs_update_html);
	lws_display_state_active(lds);

	if (lds->display_busy)
		return 0;

	lwsl_err("%s\n", __func__);

	/* Do modal update display instead of normal display content */

	fs_update_html = malloc(sizeof(*fs_update_html) + 1024);
	if (!fs_update_html)
		return 0;

	/* stop the carousel */
	lws_sul_cancel(&sul_display_update);

	memset(fs_update_html, 0, sizeof(*fs_update_html));
	fs_update_html->name = "update.html";
	fs_update_html->data = p = (char *)(fs_update_html + 1);

	fs_update_html->len = lws_snprintf(p, 1024,
		"<!doctype html><html>"
		"<head><meta charset=\"utf-8\" /><link rel=\"stylesheet\" href=\"ui.css\"></head>"
		   "<style>.done { background-color: #fff; color: #000; width: %dpx; height: 20px; padding-top: 1px; font-size: 20pt; text-align: center }</style>"
		"<body><h1>UPDATING</h1>"
		"<div class=\"vari\">%s</div><br>"
		"<div class=\"bar\" id=\"progress\"><div class=\"done\">%d%%</div></div>"
		"<div class=\"icon\"><img src=\"file://dlofs/update-icon.png\"></div><br>"
		"</body></html>",
		update_pc *  3,
		lws_ota_variant_name(),
		update_pc);

	lws_dlo_file_register(cx, fs_update_html);

	//lws_display_render_add_id(&rs, "progress", NULL);
	lupc = update_pc;

	if (init_browse(cx, &rs, "file://dlofs/update.html"))
		lwsl_err("%s: init_browse failed\n", __func__);

	return 0;
}

static int
ota_progress(lws_ota_ret_t state, int percent)
{
	update_pc = percent;
	display_update(&lds);

	return 0;
}

static lws_system_ops_t system_ops = {
	.reboot				   = do_reboot,
	.ota_ops			   = {
		.ota_start		   = lws_plat_ota_start,
		.ota_queue		   = lws_plat_ota_queue,
		.ota_report_current	   = lws_plat_ota_report_current,
		.ota_get_last_fw_unixtime  = lws_plat_ota_get_last_fw_unixtime,
		.ota_progress		   = ota_progress,
	},
	.jit_trust_query		   = jit_trust_query
};

static void
start_frame(lws_sorted_usec_list_t *sul)
{
	if (lds.display_busy) {
		lws_sul_schedule(cx, 0, &sul_display_update, start_frame,
				 LWS_US_PER_SEC);

		return;
	}

        /* browsing / waiting / layout */

        show_demo_phase(LWS_LHPCD_PHASE_FETCHING);

	if (lws_system_get_state_manager(cx)->state == LWS_SYSTATE_MODAL_UPDATING)
		return;

	if (lws_system_get_state_manager(cx)->state == LWS_SYSTATE_AWAITING_MODAL_UPDATING) { //&&
	    //strcmp(lds.current_url, "file://dlofs/update.html")) {

		display_update(&lds);
		return;
	}

	if (fs_update_html)
		lws_dlo_file_unregister(&fs_update_html);

	lwsl_notice("%s: %s\n", __func__, carousel_urls[carousel]);

         if (init_browse(cx, &rs, carousel_urls[carousel++]))
                 lwsl_err("%s: init_browse failed\n", __func__);
         if (!carousel_urls[carousel])
                 carousel = 0;
}

static int
display_splash(lws_display_state_t *lds)
{
	char *p, age[32], varbuf[64];
	uint64_t fw = 0;
	lws_dll2_t *d;

	lwsl_err("%s: boot_step %d... fs_splash_html %p, choose splash.html %p\n", __func__, boot_step, fs_splash_html, lws_dlo_file_choose(cx, "splash.html"));

	if (lbs == boot_step || did_splash || fs_splash_html)
		return 0;

	if (boot_step < 0)
		boot_step = 0;

	if (lds->display_busy)
		return 0;

	if (boot_step > LWS_SYSTATE_OPERATIONAL)
		return 0;

	if (boot_step == LWS_SYSTATE_OPERATIONAL)
		did_splash = 1;

	fs_splash_html = malloc(sizeof(*fs_splash_html) + 4096);
	if (!fs_splash_html)
		return 0;

	lds->display_busy = 1;

	memset(fs_splash_html, 0, sizeof(*fs_splash_html));
	fs_splash_html->name = "splash.html";
	p = (char *)(fs_splash_html + 1);
	fs_splash_html->data = p;

	age[0] = '\0';
	if (!system_ops.ota_ops.ota_get_last_fw_unixtime(&fw)) {
		struct tm lt;
		time_t t = (time_t)fw;

		localtime_r(&t, &lt);
		strftime(age, sizeof(age), "%Y-%m-%d %H:%M:%S UTC", &lt);
	} else
		strcpy(age, "unknown");

	strncpy(varbuf, lws_ota_variant_name(), sizeof(varbuf));

	fs_splash_html->len = lws_snprintf(p, 4096,
		"<!doctype html><html><head><meta charset=\"utf-8\" /><link rel=\"stylesheet\" href=\"ui.css\"></head>"
		   "<style>.done { background-color: #fff; color: #000; width: %dpx; height: 20px; padding-top: 1px; font-size: 20pt; text-align: center }</style>"
		"<body>"
			"<div class=\"c\"><h1>Booting</h1>"
			"<div class=\"bar\" id=\"progress\"><div class=\"done\">%d%%</div></div>"
			"%s<br>%s"
			"</div>"
			"<div class=\"c\">"
			"<table><tr><td>RSSI</td><td>Ch</td><td>BSSID</td></tr>",

		(boot_step * 250) / 13,
		(boot_step * 100) / 13,
		varbuf, age
//				lds->disp->ic.wh_px[0].whole,
//				lds->disp->ic.wh_px[1].whole,
		);

	d = wnd->scan.tail;
	while (d) {
		lws_wifi_sta_t *w = lws_container_of(d, lws_wifi_sta_t, list);

		fs_splash_html->len += lws_snprintf(p + fs_splash_html->len,
						    4096 - fs_splash_html->len,
				"<tr><td>%d</td><td>%d</td><td>%s</td></tr>",
				rssi_averaged(w), w->ch, (const char *)&w[1]);
		d = d->prev;
	};

	fs_splash_html->len += lws_snprintf(p + fs_splash_html->len, 4096 - fs_splash_html->len, "</table></div></body></html>");

	lbs = boot_step;

	if (!lws_dlo_file_register(cx, fs_splash_html))
		lwsl_err("registering splash failed\n");

	lws_display_render_free_ids(&rs);
//	if (!strcmp(lds->current_url, "file://dlofs/splash.html"))
		/* subsequent update... do partial */
//		lws_display_render_add_id(&rs, "progress", NULL);

	if (init_browse(cx, &rs, "file://dlofs/splash.html")) {
		lwsl_err("%s: init_browse ended badly\n", __func__);
		lws_dlo_file_unregister_by_name(cx, "splash.html");
		free(fs_splash_html);
		fs_splash_html = NULL;
	}

	if (did_splash)
		lws_display_render_free_ids(&rs);

	return 0;
}

int
display_completion_cb(lws_display_state_t *lds, int a)
{
	lwsl_warn("%s: %d\n", __func__, a);

	switch (a) {

	case 1: /* display initialization finished */
		if (!did_splash)
			display_splash(lds);
	break;

	case 2: /* display update finished */

		lds->display_busy = 0;
		show_demo_phase(LWS_LHPCD_PHASE_IDLE);

		if (fs_splash_html) {
			lws_dlo_file_unregister_by_name(cx, fs_splash_html->name);
			free(fs_splash_html);
			fs_splash_html = NULL;
			lws_display_state_active(lds);
		}

		if (!did_splash) {
			display_splash(lds);
			return 0;
		}

		/* trigger doing the next browse */

		lws_sul_schedule(lds->ctx, 0, &sul_display_update, start_frame,
				 subsequent ? 10 * LWS_US_PER_SEC : 1);
		subsequent = 1;
		break;
	}

	return 0;
}


static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{
	if (!lws_json_simple_strcmp(buf, len, "\"src\":", "bc/user") &&
	    !lws_json_simple_strcmp(buf, len, "\"event\":", "click")) {
		lws_led_transition(lls, "blue", seqs[flip & 3],
				   &lws_pwmseq_linear_wipe);
		flip++;
	}

	lwsl_hexdump_notice(buf, len);

	if (_class & LWSSMDCL_INTERACTION)
		/*
		 * Any kind of user interaction brings the display back up and
		 * resets the dimming / blanking timers
		 */
		lws_display_state_active(&lds);

	return 0;
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		   int current, int target)
{
	if (current == LWS_SYSTATE_OPERATIONAL &&
	    target == LWS_SYSTATE_OPERATIONAL)
		seen_operational = 1;

	if (current == target) {
		boot_step = current;

		if (!strcmp(lds.current_url, "file://dlofs/splash.html"))
			display_splash(&lds);
	}

	if (current != LWS_SYSTATE_MODAL_UPDATING &&
	    target == LWS_SYSTATE_MODAL_UPDATING) {

		/* do we feel like we should okay the transition to
		 * MODAL_UPDATING?  Or are we busy using heap right now?
		 */

		if (strcmp(lds.current_url, "file://dlofs/update.html")) {
			/* did not start showing the modal update display yet */
			lws_sul_schedule(cx, 0, &sul_display_update, start_frame, 1);

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

void 
app_main(void)
{
	struct lws_context_creation_info *info;
	lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
					     system_notify_cb, "app" };
	lws_state_notify_link_t *na[] = { &notifier, NULL };

	lws_set_log_level(LLL_USER | LLL_NOTICE | LLL_WARN | LLL_ERR, NULL);

        lws_netdev_plat_init();
        lws_netdev_plat_wifi_init();

        info = malloc(sizeof(*info));
        if (!info)
		goto spin;

	memset(info, 0, sizeof(*info));

#if 1
#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	info->pss_policies_json		= ss_policy;
#else
	info->pss_policies		= &_ss_static_policy_entry;
#endif
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

	show_demo_phase(LWS_LHPCD_PHASE_IDLE);

	/* the lws event loop */

	do {
		taskYIELD();
		lws_service(cx, 0);
	} while (1);

	lwsl_notice("%s: exited event loop\n", __func__);


spin:
	vTaskDelay(10);
	taskYIELD();
	goto spin;
}
