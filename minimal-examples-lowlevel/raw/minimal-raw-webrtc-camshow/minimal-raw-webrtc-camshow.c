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
#include "../../../include/libwebsockets/lws-auth-device-client.h"

static struct lws_auth_device_client_api *auth_api;

enum {
	LWS_SW_HEIGHT,
	LWS_SW_NAME,
	LWS_SW_URL,
	LWS_SW_VIDEO_DEVICE,
	LWS_SW_WIDTH,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_HEIGHT]	= { "--height",        "Video capture height in pixels (default 720)" },
	[LWS_SW_NAME]	= { "--name",          "Client peer name to identify in mixer" },
	[LWS_SW_URL]	= { "--url",           "WebSockets URL to connect to (default wss://127.0.0.1:7681)" },
	[LWS_SW_VIDEO_DEVICE]	= { "--video-device",  "V4L2 video device path (default /dev/video0)" },
	[LWS_SW_WIDTH]	= { "--width",         "Video capture width in pixels (default 1280)" },
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

                if (!auth_api || !auth_api->start_auth_flow) {
                        lwsl_err("auth_api not populated by plugin\n");
                        return -1;
                }

                auth_api->start_auth_flow(vh, url, "camshow");

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

static int
set_clock(lws_usec_t us)
{
	struct timeval tv;
	int n;
	tv.tv_sec = us / LWS_US_PER_SEC;
	tv.tv_usec = us % LWS_US_PER_SEC;
	n = settimeofday(&tv, NULL);
	if (n) {
		lwsl_err("%s: settimeofday failed: %d\n", __func__, n);
		return 1;
	}
	lwsl_notice("%s: system time successfully updated via NTP!\n", __func__);
	return 0;
}

static void start_app_attach(struct lws_vhost *vh, const char *logical_name, const char *access_token)
{
	char *devices_copy_local = strdup(devs_list);
	char *p = devices_copy_local, *token;

        while ((token = strsep(&p, ","))) {
		lwsl_notice("Attaching %s to WebRTC mixer\n", token);
		if (cam_ops->attach(vh, url, token, client_name, app_width, app_height, access_token))
			lwsl_err("Failed to queue attach for %s\n", token);
	}

        free(devices_copy_local);
}

static void pairing_indication(struct lws_vhost *vh, const char *logical_name, int start)
{
	lwsl_notice("\n\n*** BLINK BLINK BLINK: Identify triggered by Admin for %s ***\n\n", logical_name);
}

static void display_code(struct lws_vhost *vh, const char *logical_name, const char *user_code)
{
	lwsl_notice("\n\n=======================================\n");
	lwsl_notice("   PAIRING REQUIRED FOR %s\n", logical_name);
	lwsl_notice("   User Code: %s\n", user_code);
	lwsl_notice("=======================================\n\n");
}

static struct lws_auth_device_client_ops auth_ops = {
	.abi_version = LWS_AUTH_DEVICE_CLIENT_ABI_VERSION,
	.auth_success = start_app_attach,
	.pairing_indication = pairing_indication,
	.display_code = display_code,
};

static const lws_system_ops_t system_ops = {
	.set_clock = set_clock,
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *opt;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS minimal raw webrtc camshow [--url <wss url>] [--video-device <device>] [--name <client name>] [--width <width>] [--height <height>]\n");
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

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

	info.system_ops = &system_ops;

	static const struct lws_protocols protocols[] = {
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	};
	info.protocols = protocols;

	/* Wire up cert trust bundle so wss:// connections can verify the peer */
	info.client_ssl_ca_filepath = "/etc/ssl/certs/ca-certificates.crt";


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
	vinfo.client_ssl_ca_filepath = info.client_ssl_ca_filepath;

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

	/* For lws-auth-device-client */
	static struct lws_protocol_vhost_options pvo_auth_api = { NULL, NULL, "lws-auth-client-api", (void *)&auth_api };
	static struct lws_protocol_vhost_options pvo_auth_ops = { &pvo_auth_api, NULL, "app-auth-ops", (void *)&auth_ops };
	static struct lws_protocol_vhost_options pvo_auth_status = { &pvo_auth_ops, NULL, "status", "ok" };
	static struct lws_protocol_vhost_options pvo_auth = { &pvo, &pvo_auth_status, "lws-auth-device-client", "" };

	vinfo.pvo = &pvo_auth;

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
