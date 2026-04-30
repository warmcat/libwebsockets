/*
 * libwebsockets - lws-rtc-camera plugin
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
 */

#define LWS_DLL
#define _GNU_SOURCE
#include <libwebsockets.h>

#include <string.h>
#include <signal.h>
#include <stdlib.h>

#include "protocol_lws_rtc_camera.h"
#include "webcam-media.h"
#include <libwebsockets/lws-alsa.h>

#include "../protocol_lws_webrtc/protocol_lws_webrtc.h"

struct per_vhost_data {
	struct vhd_webrtc       *vhd;
	struct lws_context *cx;
	struct lws_rtc_camera_ops *app_ops;
};

struct attach_args {
	char *device_path;
	char *audio_device_path;
	char *name;
	char *auth_token;
	uint32_t width;
	uint32_t height;
};

const struct lws_webrtc_ops *we_ops = NULL;
static struct lws_rtc_camera_ops my_ops;

#if defined(LWS_WITH_OPUS)
static void alsa_audio_cb(void *user_data, const uint8_t *payload, size_t len)
{
	struct pss_camshow *app_state = (struct pss_camshow *)user_data;
	if (we_ops && we_ops->send_audio && we_ops->get_media && app_state->pss) {
		we_ops->send_audio(we_ops->get_media(app_state->pss), payload, len, 0);
	}
}
#endif

static void
emit_state(struct lws_vhost *vh, const char *dev, enum lws_rtc_camera_states state)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(vh, lws_vhost_name_to_protocol(vh, "lws-rtc-camera"));
	if (!vhd || !vhd->app_ops || !vhd->app_ops->state_cb) return;

	vhd->app_ops->state_cb(dev, state);
}

static int
api_attach(struct lws_vhost *vh, const char *url, const char *device_path, const char *audio_device_path, const char *name, uint32_t width, uint32_t height, const char *auth_token)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(vh, lws_vhost_name_to_protocol(vh, "lws-rtc-camera"));
	if (!vhd || !url) return -1;

	struct lws_client_connect_info i;
	const char *path;
	lws_parse_uri_t *puri;

	memset(&i, 0, sizeof(i));
	i.context = vhd->cx;
	i.vhost = vh;

	puri = lws_parse_uri_create(url);
	if (!puri) {
		lwsl_err("Failed to parse mixer URL: %s\n", url);
		return -1;
	}

	path = puri->path;

	char path_buffer[256];
	if (path[0] != '/') {
		lws_snprintf(path_buffer, sizeof(path_buffer), "/%s", path);
		path = path_buffer;
	}

	struct attach_args *args = malloc(sizeof(*args));
	if (!args) return -1;
	args->device_path = strdup(device_path);
	args->audio_device_path = audio_device_path ? strdup(audio_device_path) : strdup("default");
	args->name = name ? strdup(name) : NULL;
	args->auth_token = auth_token ? strdup(auth_token) : NULL;
	args->width = width;
	args->height = height;

	i.address = puri->host;
	i.port = puri->port;
	i.path = path;
	i.host = i.address;
	i.origin = i.address;
	i.protocol = "lws-webrtc-mixer";
	i.local_protocol_name = "lws-rtc-camera";
	i.opaque_user_data = args;

	if (!strcmp(puri->scheme, "https") || !strcmp(puri->scheme, "wss"))
		i.ssl_connection = LCCSCF_USE_SSL;

	emit_state(vh, device_path, LWS_RTC_CAMERA_STATE_CONNECTING);

	struct lws *wsi = lws_client_connect_via_info(&i);
	if (!wsi) {
		emit_state(vh, device_path, LWS_RTC_CAMERA_STATE_ERROR);
		free(args->device_path);
		if (args->name) free((void *)args->name);
		if (args->auth_token) free((void *)args->auth_token);
		free(args);
		lws_parse_uri_destroy(&puri);
		return -1;
	}

	lws_parse_uri_destroy(&puri);

	return 0;
}

static int
api_detach(struct lws_vhost *vh, const char *device_path)
{
    /* Stub for explicit connection detach */
    lwsl_err("%s: explicit detach not implemented\n", __func__);
    return -1;
}


static int
callback_rtc_camera(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	int n;

	if (reason != LWS_CALLBACK_PROTOCOL_INIT &&
			reason != LWS_CALLBACK_PROTOCOL_DESTROY &&
			reason != LWS_CALLBACK_RAW_RX_FILE) {
		if (vhd && vhd->vhd && we_ops && we_ops->shared_callback) {
			n = we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);
			if (n)
				return n;
		}
	}

	switch (reason) {
		case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
			struct attach_args *args = (struct attach_args *)lws_get_opaque_user_data(wsi);
			unsigned char **p = (unsigned char **)in;
			unsigned char *end = (*p) + len;

			if (args && args->auth_token) {
				char cookie[512];
				int n = lws_snprintf(cookie, sizeof(cookie), "auth_session=%s", args->auth_token);
				if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE, (unsigned char *)cookie, n, p, end))
					return -1;
			}
			break;
		}
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			{
				struct pss_camshow *app_state = NULL;
				
				if (!we_ops || !we_ops->get_user_data)
					break;
					
				app_state = (struct pss_camshow *)we_ops->get_user_data((struct pss_webrtc *)user);
				if (app_state) {
					if (app_state->send_presence_report) {
						const char *rep = "{\"type\":\"presence_report\",\"joined\":true}";
						if (we_ops && we_ops->send_text)
							we_ops->send_text(app_state->pss, rep, strlen(rep));
						app_state->send_presence_report = 0;
					}
				}
			}
			break;

		case LWS_CALLBACK_CLIENT_RECEIVE:
			{
				struct pss_camshow *app_state = NULL;
				
				if (!we_ops || !we_ops->get_user_data)
					break;
					
				app_state = (struct pss_camshow *)we_ops->get_user_data((struct pss_webrtc *)user);
				if (app_state && in && len > 0) {
					size_t al = 0;
					if (lws_json_simple_find((const char *)in, len, "\"type\":\"presence_check\"", &al)) {
						app_state->send_presence_report = 1;
						lws_callback_on_writable(wsi);
					}

					if (lws_json_simple_find((const char *)in, len, "\"type\":\"peer_ip\"", &al)) {
						const char *p = lws_json_simple_find((const char *)in, len, "\"ip\":", &al);
						if (p) {
							char ip_buf[64];
							size_t nl = al;
							if (*p == '\"') { p++; nl -= 2; }
							if (nl >= sizeof(ip_buf)) nl = sizeof(ip_buf) - 1;
							memcpy(ip_buf, p, nl);
							ip_buf[nl] = '\0';
							if (we_ops && we_ops->create_offer) {
								we_ops->create_offer(app_state->pss);
							}
						}
					}

					if (lws_json_simple_find((const char *)in, len, "\"type\":\"request_caps\"", &al) ||
							lws_json_simple_find((const char *)in, len, "\"request_caps\"", &al)) {
						if (app_state->ops && app_state->ops->send_capabilities)
							app_state->ops->send_capabilities(app_state);
#if defined(LWS_WITH_OPUS)
						if (app_state->alsa_cap) {
							char abuf[1024];
							int n = lws_alsa_opus_send_capabilities(app_state->alsa_cap, abuf, sizeof(abuf));
							if (n > 0 && we_ops && we_ops->send_text)
								we_ops->send_text(app_state->pss, abuf, (size_t)n);
						}
#endif
					}

					if (lws_json_simple_find((const char *)in, len, "\"type\":\"set_control\"", &al)) {
						const char *p = (const char *)in;
						long long id = -1, val = 0;

						char buf[32];
						if ((p = lws_json_simple_find((const char *)in, len, "\"id\":", &al))) {
							if (al >= sizeof(buf)) al = sizeof(buf) - 1;
							memcpy(buf, p, al);
							buf[al] = '\0';
							id = atoll(buf);
						}
						if ((p = lws_json_simple_find((const char *)in, len, "\"val\":", &al))) {
							if (al >= sizeof(buf)) al = sizeof(buf) - 1;
							memcpy(buf, p, al);
							buf[al] = '\0';
							val = atoll(buf);
						}

						if (id != -1) {
							size_t kl;
							const char *k = lws_json_simple_find((const char *)in, len, "\"kind\":", &kl);
							if (k && !strncmp(k, "\"audio\"", 7)) {
#if defined(LWS_WITH_OPUS)
								if (app_state->alsa_cap)
									lws_alsa_opus_set_control(app_state->alsa_cap, (uint32_t)id, (long)val);
#endif
							} else {
								if (app_state->ops && app_state->ops->set_control) {
									app_state->ops->set_control(app_state, (uint32_t)id, (int32_t)val);
								}
							}
						}
					}
				}
			}
			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:
			{
				struct pss_camshow *app_state;
				struct pss_webrtc *we_pss = (struct pss_webrtc *)user;
				struct attach_args *args = (struct attach_args *)lws_get_opaque_user_data(wsi);

				emit_state(lws_get_vhost(wsi), args ? args->device_path : "?", LWS_RTC_CAMERA_STATE_ESTABLISHED);

				app_state = malloc(sizeof(struct pss_camshow));
				if (!app_state) return -1;
				memset(app_state, 0, sizeof(*app_state));

				if (we_ops && we_ops->set_user_data)
					we_ops->set_user_data(we_pss, app_state);

				app_state->video_device = args && args->device_path ? strdup(args->device_path) : strdup("/dev/video0");
				app_state->audio_device = args && args->audio_device_path ? strdup(args->audio_device_path) : strdup("default");

				app_state->pss = we_pss;
				app_state->context = lws_get_context(wsi);
				app_state->vhost = lws_get_vhost(wsi);

				app_state->width = args && args->width ? args->width : 1280;
				app_state->height = args && args->height ? args->height : 720;
				app_state->target_width = app_state->width;
				app_state->target_height = app_state->height;

#if defined(LWS_WITH_MEDIA_RK_MPI)
				app_state->ops = &pipeline_rk_mpi;
#else
				app_state->ops = &pipeline_v4l2;
#endif

				if (app_state->ops && app_state->ops->init(app_state) < 0) {
					free(app_state);
					return -1;
				}

				if (app_state->ops) {
					int fd = app_state->ops->get_event_fd(app_state);
					if (fd >= 0) {
						struct lws_adopt_desc ad;
						memset(&ad, 0, sizeof(ad));
						ad.vh = lws_get_vhost(wsi);
						ad.type = LWS_ADOPT_RAW_FILE_DESC;
						ad.fd.filefd = (lws_filefd_type)(long)fd;
						ad.vh_prot_name = "lws-rtc-camera-v4l2";
						app_state->wsi_v4l2 = lws_adopt_descriptor_vhost_via_info(&ad);
						if (app_state->wsi_v4l2) {
							lws_set_wsi_user(app_state->wsi_v4l2, app_state);
						}
					}
				}

#if defined(LWS_WITH_OPUS)
				struct lws_alsa_info ainfo;
				memset(&ainfo, 0, sizeof(ainfo));
				ainfo.device_name = app_state->audio_device;
				ainfo.rate = AUDIO_RATE;
				ainfo.channels = AUDIO_CHANNELS;
				ainfo.samples_per_frame = AUDIO_SAMPLES_PER_FRAME;

				app_state->alsa_cap = lws_alsa_opus_capture_create(&ainfo, alsa_audio_cb, app_state);
				if (app_state->alsa_cap) {
					int fd = lws_alsa_opus_get_fd(app_state->alsa_cap);
					if (fd >= 0) {
						struct lws_adopt_desc ad;
						memset(&ad, 0, sizeof(ad));
						ad.vh = lws_get_vhost(wsi);
						ad.type = LWS_ADOPT_RAW_FILE_DESC;
						ad.fd.filefd = (lws_filefd_type)(long)fd;
						ad.vh_prot_name = "lws-rtc-camera-v4l2";
						app_state->wsi_alsa = lws_adopt_descriptor_vhost_via_info(&ad);
						if (app_state->wsi_alsa) {
							lws_set_wsi_user(app_state->wsi_alsa, app_state);
						}
					}
				}
#endif

				lws_callback_on_writable(wsi);

				char json[256];
				const char *name = args && args->name ? args->name : strrchr(app_state->video_device, '/');
				if (name && name[0] == '/') name++; else if (!name) name = app_state->video_device;

				char esc_name[384];
				lws_json_purify(esc_name, name, sizeof(esc_name), NULL);
				lws_snprintf(json, sizeof(json), "{\"type\":\"join\",\"name\":\"%s\",\"out_only\":true}", esc_name);

				if (we_ops && we_ops->send_text)
					we_ops->send_text(app_state->pss, json, strlen(json));
				app_state->join_sent = 1;

				if (app_state->ops && app_state->ops->send_capabilities) {
					app_state->ops->send_capabilities(app_state);
				}
#if defined(LWS_WITH_OPUS)
				if (app_state->alsa_cap) {
					char abuf[1024];
					int n = lws_alsa_opus_send_capabilities(app_state->alsa_cap, abuf, sizeof(abuf));
					if (n > 0) {
						lwsl_notice("%s: Sending audio capabilities (%d bytes): %s\n", __func__, n, abuf);
						if (we_ops && we_ops->send_text)
							we_ops->send_text(app_state->pss, abuf, (size_t)n);
					} else {
						lwsl_warn("%s: No audio capabilities found\n", __func__);
					}
				}
#endif
				app_state->caps_sent = 1;

				char stats_json[128];
				lws_snprintf(stats_json, sizeof(stats_json),
						"{\"type\":\"stats\",\"stats\":\"%dx%d (Fmt %08x)\"}",
						app_state->width, app_state->height, app_state->pixelformat);

				if (we_ops && we_ops->send_text) {
					we_ops->send_text(app_state->pss, stats_json, strlen(stats_json));
					app_state->stats_sent = 1;
				}

				lws_set_timer_usecs(wsi, 1000000);

				if (args) {
					if (args->name) free(args->name);
					if (args->device_path) free(args->device_path);
					if (args->audio_device_path) free(args->audio_device_path);
					if (args->auth_token) free(args->auth_token);
					free(args);
				}
				break;
			}

		case LWS_CALLBACK_PROTOCOL_INIT: {
				const struct lws_protocol_vhost_options *pvo;

				vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct per_vhost_data));

				lwsl_err("LWS_CALLBACK_PROTOCOL_INIT for lws-rtc-camera\n");
				if (!vhd)
					return -1;
				vhd->vhd = (struct vhd_webrtc *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc"));
				vhd->cx = lws_get_context(wsi);

				/* Parse local PVOs */
				pvo = (const struct lws_protocol_vhost_options *)in;
				while (pvo) {
					lwsl_err("PVO FOUND: %s\n", pvo->name);
					if (!strcmp(pvo->name, "lws-webrtc-ops")) {
						if (pvo->value) {
							lwsl_notice("Found we_ops!\n");
							we_ops = (const struct lws_webrtc_ops *)pvo->value;
						}
					}
					if (!strcmp(pvo->name, "lws-rtc-camera-ops")) {
						if (pvo->value) {
							lwsl_err("Populating cam_ops\n");
							my_ops.abi_version = LWS_RTC_CAMERA_OPS_ABI_VERSION;
							my_ops.attach = api_attach;
							my_ops.detach = api_detach;
							vhd->app_ops = *((struct lws_rtc_camera_ops **)pvo->value);
							my_ops.state_cb = vhd->app_ops->state_cb;

							*((const struct lws_rtc_camera_ops **)pvo->value) = &my_ops;
						} else {
							lwsl_err("cam_ops PVO value was NULL\n");
						}
					}
					pvo = pvo->next;
				}
				break;
			}

		case LWS_CALLBACK_TIMER:
			{
				if (we_ops && we_ops->get_user_data) {
					struct pss_camshow *app_state = (struct pss_camshow *)we_ops->get_user_data(user);
					if (app_state) {
						unsigned long long fps = app_state->packets_sent - app_state->packets_sent_last;

						char stats_json[128];
						lws_snprintf(stats_json, sizeof(stats_json),
								"{\"type\":\"stats\",\"stats\":\"%dx%d -> %dx%d @ %llufps\"}",
								app_state->width, app_state->height, app_state->width, app_state->height, fps);

						if (we_ops && we_ops->send_text) {
							we_ops->send_text(app_state->pss, stats_json, strlen(stats_json));
						}

						app_state->packets_sent_last = app_state->packets_sent;
						lws_set_timer_usecs(wsi, 1000000);
					}
				}
				break;
			}

		case LWS_CALLBACK_GET_PSS_SIZE:
			{
				const struct lws_protocols *cur_p = lws_get_protocol(wsi);
				if (cur_p && !strcmp(cur_p->name, "lws-rtc-camera-v4l2"))
					return 0;

				const struct lws_protocols *p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
				if (p)
					return (int)p->per_session_data_size;
				return 0;
			}

		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			lwsl_err("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__, in ? (char *)in : "(null)");
			{
				struct attach_args *args = (struct attach_args *)lws_get_opaque_user_data(wsi);
				emit_state(lws_get_vhost(wsi), args ? args->device_path : "?", LWS_RTC_CAMERA_STATE_ERROR);
			}
			break;

		case LWS_CALLBACK_CLIENT_CLOSED:
			if (we_ops && we_ops->get_user_data) {
				struct pss_camshow *app_state = (struct pss_camshow *)we_ops->get_user_data(user);
				if (app_state) {
					emit_state(lws_get_vhost(wsi), app_state->video_device ? app_state->video_device : "?", LWS_RTC_CAMERA_STATE_CLOSED);
					if (app_state->ops && app_state->ops->deinit)
						app_state->ops->deinit(app_state);
#if defined(LWS_WITH_OPUS)
					if (app_state->alsa_cap)
						lws_alsa_opus_capture_destroy(&app_state->alsa_cap);
#endif
					if (app_state->video_device) free((void *)app_state->video_device);
					if (app_state->audio_device) free((void *)app_state->audio_device);
					free(app_state);
					we_ops->set_user_data((struct pss_webrtc *)user, NULL);
				}
			}
			break;

		case LWS_CALLBACK_CLOSED:
			/* fallthrough */

		case LWS_CALLBACK_RAW_RX_FILE:
			{
				struct pss_camshow *app_state = (struct pss_camshow *)user;
				if (app_state && wsi == app_state->wsi_v4l2) {
					if (app_state->ops && app_state->ops->process_rx)
						app_state->ops->process_rx(app_state);
				}
#if defined(LWS_WITH_OPUS)
				else if (app_state && wsi == app_state->wsi_alsa) {
					if (app_state->alsa_cap)
						lws_alsa_opus_read(app_state->alsa_cap);
				}
#endif
			}
			break;

		default: break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws-rtc-camera-v4l2", /* Used for file descriptor adoption mapping */
		callback_rtc_camera,
		0,
		4096,
		0, NULL, 0
	},
	{
		"lws-rtc-camera",
		callback_rtc_camera,
		0,
		4096,
		0, NULL, 0
	},
};

LWS_VISIBLE const lws_plugin_protocol_t lws_rtc_camera = {
	.hdr = {
		.name = "lws rtc camera plugin",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 0
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols)
};
