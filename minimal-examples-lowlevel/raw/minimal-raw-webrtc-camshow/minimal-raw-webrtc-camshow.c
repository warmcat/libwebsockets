/*
 * lws-minimal-raw-webrtc-camshow
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#define LWS_DLL
#define _GNU_SOURCE
#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#include "../../../plugins/protocol_lws_rtc_camera/protocol_lws_rtc_camera.h"
#include "../../../plugins/protocol_lws_webrtc/protocol_lws_webrtc.h"

enum {
	LWS_SW_HEIGHT,
	LWS_SW_NAME,
	LWS_SW_URL,
	LWS_SW_VIDEO_DEVICE,
	LWS_SW_WIDTH,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_HEIGHT]	= { "--height",        "Enable --height feature" },
	[LWS_SW_NAME]	= { "--name",          "Enable --name feature" },
	[LWS_SW_URL]	= { "--url",           "Enable --url feature" },
	[LWS_SW_VIDEO_DEVICE]	= { "--video-device",  "Enable --video-device feature" },
	[LWS_SW_WIDTH]	= { "--width",         "Enable --width feature" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

static const char *url = "wss://127.0.0.1:7681";
static const char *devs_list = "/dev/video0";
static char *devices_copy = NULL;
static const char *client_name;
static uint32_t app_width = 1280;
static uint32_t app_height = 720;

static struct lws_context *cx;
static lws_state_notify_link_t nl;
static struct lws_rtc_camera_ops *cam_ops;
static struct lws_rtc_camera_ops pre_ops;

static void
my_state_cb(const char *dev, enum lws_rtc_camera_states state)
{
	lwsl_notice("%s: Device %s reached state %d\n", __func__, dev ? dev : "?", (int)state);
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *context = lws_system_context_from_system_mgr(mgr);

	switch (target) {
        case LWS_SYSTATE_OPERATIONAL:
                if (current != LWS_SYSTATE_OPERATIONAL)
                        break;

                struct lws_vhost *vh = lws_get_vhost_by_name(context, "camshow-clients");
                if (!vh) {
                        lwsl_err("camshow-clients vhost missing\n");
                        return -1;
                }

                if (!cam_ops || !cam_ops->attach) {
                        lwsl_err("cam_ops not populated by plugin\n");
                        return -1;
                }

                if (!devices_copy)
                        devices_copy = strdup(devs_list);

                char *p = devices_copy;
                char *token;

                while ((token = strsep(&p, ","))) {
                        lwsl_notice("Attaching %s to WebRTC mixer\n", token);
                        if (cam_ops->attach(vh, url, token, client_name, app_width, app_height))
                                lwsl_err("Failed to queue attach for %s\n", token);
                }

                break;
	}
	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static int interrupted;

void sigint_handler(int signum) {
    interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *opt;

	lws_context_info_defaults(&info, NULL);
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_cmdline_option_handle_builtin(argc, argv, &info);

	info.port = CONTEXT_PORT_NO_LISTEN;

	if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_URL].sw))) url = opt;
	if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_VIDEO_DEVICE].sw))) devs_list = opt;
	if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_NAME].sw))) client_name = opt;
	if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_WIDTH].sw))) app_width = (uint32_t)atoi(opt);
	if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_HEIGHT].sw))) app_height = (uint32_t)atoi(opt);

	signal(SIGINT, sigint_handler);

	nl.name = "app";
	nl.notify_cb = app_system_state_nf;
	info.register_notifier_list = app_notifier_list;

#if defined(LWS_WITH_PLUGINS)
	static const char * const plugin_dirs[] = {
		LWS_PLUGIN_DIR "/",
		NULL
	};
	info.plugin_dirs = plugin_dirs;
#endif

	/*
	 * Provide the state_cb up front so the plugin has it when it overwrites
	 * the pointer to point to its own op struct.
	 */
	pre_ops.state_cb = my_state_cb;
	cam_ops = &pre_ops;

	struct lws_context_creation_info vinfo;
	memset(&vinfo, 0, sizeof(vinfo));
	vinfo.vhost_name = "camshow-clients";
	vinfo.port = CONTEXT_PORT_NO_LISTEN;
	vinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	static struct lws_webrtc_ops webrtc_ops;

	/* For lws-webrtc-udp */
	static struct lws_protocol_vhost_options pvo_we_udp_status = { NULL, NULL, "status", "ok" };
	static struct lws_protocol_vhost_options pvo_we_udp = { NULL, &pvo_we_udp_status, "lws-webrtc-udp", "" };

	/* For lws-webrtc */
	static struct lws_protocol_vhost_options pvo_we_ops = { NULL, NULL, "lws-webrtc-ops", (void *)&webrtc_ops };
	static struct lws_protocol_vhost_options pvo_we_status = { &pvo_we_ops, NULL, "status", "ok" };
	static struct lws_protocol_vhost_options pvo_we = { &pvo_we_udp, &pvo_we_status, "lws-webrtc", "" };

	/* For lws-rtc-camera-v4l2 */
	static struct lws_protocol_vhost_options pvo_cam_v4l2_status = { NULL, NULL, "status", "ok" };
	static struct lws_protocol_vhost_options pvo_cam_v4l2 = { &pvo_we, &pvo_cam_v4l2_status, "lws-rtc-camera-v4l2", "" };

	/* For lws-rtc-camera */
	static struct lws_protocol_vhost_options pvo_cam_we_ops = { NULL, NULL, "lws-webrtc-ops", (void *)&webrtc_ops };
	static struct lws_protocol_vhost_options pvo_ops = { &pvo_cam_we_ops, NULL, "lws-rtc-camera-ops", (void *)&cam_ops };
	static struct lws_protocol_vhost_options pvo_cam_status = { &pvo_ops, NULL, "status", "ok" };
	static struct lws_protocol_vhost_options pvo = { &pvo_cam_v4l2, &pvo_cam_status, "lws-rtc-camera", "" };

	vinfo.pvo = &pvo;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

	struct lws_vhost *vh = lws_create_vhost(cx, &vinfo);
	if (!vh) {
		lwsl_err("Failed to create vhost\n");
		return 1;
	}

	while (!interrupted)
		if (lws_service(cx, 0) < 0)
			break;

	lws_context_destroy(cx);

	if (devices_copy) free(devices_copy);

	return 0;
}
