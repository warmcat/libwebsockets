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
#include <errno.h>

#include "webcam-media.h"

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <arpa/inet.h>

#include "../../../plugins/protocol_lws_webrtc.h"

/* The "vhost" data now only holds the plugin vhd pointer shared by all connections */
struct per_vhost_data {
	struct vhd_webrtc       *vhd;
};

static const char *url = "https://127.0.0.1:7681";
static const char *devs_list = "/dev/video0";
static char *devices_copy = NULL;
static struct lws_context *cx;
static lws_state_notify_link_t nl;

const struct lws_webrtc_ops *we_ops;

static struct lws_context *cx;
static const char *url;
static const char *devs_list;
static char *devices_copy;
static const char *client_name;
static uint32_t app_width = 1280;
static uint32_t app_height = 720;

extern int
lws_v4l2_native_ioctl(struct lws_v4l2_ctx *ctx, unsigned long request, void *arg);

static int
v4l2_init(struct pss_camshow *pss)
{
	struct lws_v4l2_info info;

	memset(&info, 0, sizeof(info));
	info.device_path = pss->video_device;
	info.width = pss->width;
	info.height = pss->height;
	info.pixelformat = V4L2_PIX_FMT_H264;

	pss->v4l2_ctx = lws_v4l2_create(&info);
	if (!pss->v4l2_ctx) {
		lwsl_err("%s: Failed to create V4L2 context for %s\n", __func__, pss->video_device);
		return -1;
	}

	lws_v4l2_get_info(pss->v4l2_ctx, &info);
	pss->width = info.width;
	pss->height = info.height;
	pss->pixelformat = info.pixelformat;

	lwsl_notice("%s: V4L2 negotiated %dx%d, format 0x%x for %s\n", __func__, pss->width, pss->height, pss->pixelformat, pss->video_device);

	/* Auto-detect if we need transcoding */
	if (pss->pixelformat != V4L2_PIX_FMT_H264) {
		lwsl_notice("%s: Device %s is not H.264 (fmt 0x%x), forcing AV1 transcoding\n", __func__, pss->video_device, pss->pixelformat);
		pss->force_av1 = 1;
	}

	media_update_scaler(pss);

	pss->yuv_size = (pss->width * pss->height * 3) / 2;
	if (pss->yuv_frame) free(pss->yuv_frame);
	pss->yuv_frame = malloc(pss->yuv_size);
	if (!pss->yuv_frame)
		goto bail;

	if (media_init(pss) < 0)
		goto bail;

	return 0;

bail:
	lws_v4l2_destroy((struct lws_v4l2_ctx **)&pss->v4l2_ctx);
	return -1;
}

static int interrupted;

/* Storage for the ops provided by the plugin */
static struct lws_webrtc_ops we_ops_storage;

/*
 * We need to serialize controls into a JSON buffer.
 * Since lws_v4l2_enum_controls uses a callback, we'll pass a struct to it.
 */
struct json_dump_ctx {
	char		*p;
	char		*end;
	int		first;
};

static int
json_control_cb(void *user, const struct lws_v4l2_control *c)
{
	struct json_dump_ctx *j = (struct json_dump_ctx *)user;
	char safe_name[256];
	int len;

	lwsl_notice("%s: Found control '%s' (id %u)\n", __func__, c->name, c->id);

	if (lws_ptr_diff_size_t(j->end, j->p) < 128)
		return 1;

	if (!j->first)
		*j->p++ = ',';

	j->first = 0;

	lws_json_purify(safe_name, c->name, sizeof(safe_name), &len);

	j->p += lws_snprintf(
			j->p, lws_ptr_diff_size_t(j->end, j->p),
			"{\"id\":%u,\"type\":%u,\"name\":\"%s\","
			"\"min\":%d,\"max\":%d,\"step\":%d,\"val\":%d}",
			c->id, c->type, safe_name, c->min, c->max, c->step, c->val);

	return 0;
}

static void
send_capabilities(struct pss_camshow *pss)
{
	struct v4l2_queryctrl q;
	struct json_dump_ctx j;
	char buf[4096];

	if (!pss->v4l2_ctx) {
		lwsl_err("%s: No v4l2_ctx, cannot send capabilities\n", __func__);
		return;
	}

	memset(&q, 0, sizeof(q));
	q.id            = V4L2_CTRL_FLAG_NEXT_CTRL;

	j.p             = buf + LWS_PRE;
	j.end           = &buf[sizeof(buf)];
	j.first         = 1;

	j.p += lws_snprintf(j.p, lws_ptr_diff_size_t(j.end, j.p),
			"{\"type\":\"capabilities\",\"kind\":\"video\",\"controls\":[");

	lws_v4l2_enum_controls(pss->v4l2_ctx, json_control_cb, &j);

	j.p += lws_snprintf(j.p, lws_ptr_diff_size_t(j.end, j.p), "]}");

	lwsl_hexdump_notice(buf + LWS_PRE, lws_ptr_diff_size_t(j.p, buf + LWS_PRE));

	if (we_ops && we_ops->send_text)
		we_ops->send_text(pss->pss, buf + LWS_PRE, lws_ptr_diff_size_t(j.p, buf + LWS_PRE));
}

static int
callback_webrtc_camshow(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	/* user is pss_webrtc for main WSI, but pss_camshow for capture WSI */
	int n;


	/* Forwarding to Shared WebRTC Plugin */
	if (reason != LWS_CALLBACK_PROTOCOL_INIT &&
			reason != LWS_CALLBACK_PROTOCOL_DESTROY &&
			reason != LWS_CALLBACK_RAW_RX_FILE) { /* Don't forward capture events to WebRTC plugin directly */
		if (vhd && vhd->vhd && we_ops && we_ops->shared_callback) {
			n = we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);
			if (n)
				return n;
		}
	}

	switch (reason) {
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			{
				struct pss_camshow *app_state = (struct pss_camshow *)we_ops->get_user_data((struct pss_webrtc *)user);
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
				struct pss_camshow *app_state = (struct pss_camshow *)we_ops->get_user_data((struct pss_webrtc *)user);
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

							struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
							if (vhd && vhd->vhd) {
								lwsl_notice("%s: Received Peer IP '%s' from Mixer, setting as STUN candidate\n", __func__, ip_buf);
							}

							/* Now that we have our public TCP IP, we can generate the SDP offer */
							if (we_ops && we_ops->create_offer) {
								lwsl_notice("%s: Generating SDP offer with new STUN IP...\n", __func__);
								we_ops->create_offer(app_state->pss);
							}
						}
					}

					if (lws_json_simple_find((const char *)in, len, "\"type\":\"request_caps\"", &al) ||
							lws_json_simple_find((const char *)in, len, "\"request_caps\"", &al)) {
						lwsl_notice("%s: Received request_caps, sending capabilities\n", __func__);
						/* We might generally not have writability here, but we can request it.
						   However, send_capabilities logic assumes we are inside WRITEABLE if we just call it?
						   No, send_capabilities calls we_ops->send_text which writes to pss->pss.
						   That operation queues the write. It does NOT need to be in WRITEABLE callback of *this* wsi possibly?
						   Wait, `we_ops->send_text` usually queues.
						   But `minimal-raw-webrtc-camshow` is the client connection.
						   Safest is to set flag and request callback.
						   But let's try calling it directly as `send_text` should queue. */
						send_capabilities(app_state);
					}

					if (lws_json_simple_find((const char *)in, len, "\"type\":\"set_control\"", &al)) {
						/* {"type":"set_control","id":123,"val":456} */
						const char *p = (const char *)in;
						long long id = -1, val = 0;

						char buf[32];
						if ((p = lws_json_simple_find((const char *)in, len, "\"id\":", &al))) {
							// lws_strnncpy(buf, p, sizeof(buf), al);
							if (al >= sizeof(buf)) al = sizeof(buf) - 1;
							memcpy(buf, p, al);
							buf[al] = '\0';
							id = atoll(buf);
							lwsl_notice("PARSED ID: '%.*s' -> %lld\n", (int)al, p, id);
						}
						if ((p = lws_json_simple_find((const char *)in, len, "\"val\":", &al))) {
							// lws_strnncpy(buf, p, sizeof(buf), al);
							if (al >= sizeof(buf)) al = sizeof(buf) - 1;
							memcpy(buf, p, al);
							buf[al] = '\0';
							val = atoll(buf);
							lwsl_notice("PARSED VAL: '%.*s' -> %lld\n", (int)al, p, val);
						}

						if (id != -1) {
							lwsl_notice("%s: Setting control ID %lld to %lld\n", __func__, id, val);
							if (app_state->v4l2_ctx) {
								lws_v4l2_set_control(app_state->v4l2_ctx, (uint32_t)id, (int32_t)val);
							}
						}
					}
				}
			}
			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED: /* Client established to Mixer */
			{
				struct pss_camshow *app_state;
				struct pss_webrtc *we_pss = (struct pss_webrtc *)user;

				/* Allocate our application state */
				app_state = malloc(sizeof(struct pss_camshow));
				if (!app_state) return -1;
				memset(app_state, 0, sizeof(*app_state));

				/* Link it to the WebRTC PSS */
				if (we_ops && we_ops->set_user_data)
					we_ops->set_user_data(we_pss, app_state);

				const char *dev_path = (const char *)lws_get_opaque_user_data(wsi);
				if (!dev_path) dev_path = "/dev/video0";

				app_state->video_device = strdup(dev_path);
				lwsl_notice("%s: Connected to Mixer for device %s\n", __func__, app_state->video_device);

				app_state->pss = we_pss; /* Store the WebRTC PSS in our state */
				app_state->context = lws_get_context(wsi);
				app_state->vhost = lws_get_vhost(wsi);

				/* resolution set by args or default */
				app_state->width = app_width;
				app_state->height = app_height;
				app_state->target_width = app_width;
				app_state->target_height = app_height;

				if (v4l2_init(app_state) < 0) {
					free(app_state);
					return -1;
				}

				/* We NO LONGER Initiate Offer here. We wait for {"type":"peer_ip"} from Mixer! */

				/* Start Capture */
				if (app_state->v4l2_ctx) {
					struct lws_adopt_desc ad;
					memset(&ad, 0, sizeof(ad));
					ad.vh = lws_get_vhost(wsi);
					ad.type = LWS_ADOPT_RAW_FILE_DESC;
					ad.fd.filefd = (lws_filefd_type)(long)lws_v4l2_get_fd(app_state->v4l2_ctx);
					ad.vh_prot_name = "lws-webrtc-camshow-v4l2"; /* Use the 0-sized PSS protocol */
					app_state->wsi_v4l2 = lws_adopt_descriptor_vhost_via_info(&ad);
					if (app_state->wsi_v4l2) {
						/* Set the user data of the capture wsi to point to our APP STATE */
						lws_set_wsi_user(app_state->wsi_v4l2, app_state);
					}
				}

				/* Kick off the handshake process by requesting WRITEABLE to send our "join" message */
				lws_callback_on_writable(wsi);

				/* Send our initial messages IMMEDIATELY using the buflist queue */
				char json[256];
				const char *name = client_name;
				if (!name) {
					name = strrchr(app_state->video_device, '/');
					if (name) name++; else name = app_state->video_device;
				}

				/* Tell mixer we are OUT-ONLY (camera source), so don't send us video */
				char esc_name[384];
				lws_json_purify(esc_name, name, sizeof(esc_name), NULL);
				lws_snprintf(json, sizeof(json), "{\"type\":\"join\",\"name\":\"%s\",\"out_only\":true}", esc_name);
				lwsl_notice("%s: Queuing Join JSON: %s\n", __func__, json);

				if (we_ops && we_ops->send_text)
					we_ops->send_text(app_state->pss, json, strlen(json));
				app_state->join_sent = 1;

				lwsl_notice("%s: Queuing send_capabilities...\n", __func__);
				send_capabilities(app_state);
				app_state->caps_sent = 1;

				char stats_json[128];
				lws_snprintf(stats_json, sizeof(stats_json),
						"{\"type\":\"stats\",\"stats\":\"%dx%d (Fmt %08x)\"}",
						app_state->width, app_state->height, app_state->pixelformat);

				if (we_ops && we_ops->send_text) {
					we_ops->send_text(app_state->pss, stats_json, strlen(stats_json));
					lwsl_notice("%s: Queuing Stats: %s\n", __func__, stats_json);
					app_state->stats_sent = 1;
				}

				/* 1Hz timer for logging stats */
				lws_set_timer_usecs(wsi, 1000000);

				break;
			}

		case LWS_CALLBACK_PROTOCOL_INIT:
			{
				const struct lws_protocols *p;

				lwsl_vhost_notice(lws_get_vhost(wsi), "lws-webrtc-camshow: PROTOCOL_INIT");

				/* Alloc VHD (once per vhost) */
				vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct per_vhost_data));
				if (!vhd) return -1;

				/* Assign ops globally */
				we_ops = &we_ops_storage;

				p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
				if (p) {
					vhd->vhd = (struct vhd_webrtc *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), p);
				}

				if (!we_ops) {
					lwsl_err("%s: lws-webrtc protocol not found on vhost\n", __func__);
					return -1;
				}
				if (!vhd->vhd) {
					lwsl_err("%s: lws-webrtc vhost private data missing (failed init?)\n", __func__);
					return -1;
				}
				if (we_ops->abi_version != LWS_WEBRTC_OPS_ABI_VERSION) {
					lwsl_err("%s: lws-webrtc ABI mismatch (got %u, expected %u)\n",
							__func__, we_ops->abi_version, LWS_WEBRTC_OPS_ABI_VERSION);
					return -1;
				}
				break;
			}
			break;

		case LWS_CALLBACK_TIMER:
			{
				if (we_ops && we_ops->get_user_data) {
					struct pss_camshow *app_state = (struct pss_camshow *)we_ops->get_user_data(user);
					if (app_state) {
						unsigned long long fps = app_state->packets_sent - app_state->packets_sent_last;
						lwsl_info("%s: camshow sent %llu video frames to WebRTC engine (+%llu in 1s)\n",
								__func__,
								(unsigned long long)app_state->packets_sent,
								fps);

						char stats_json[128];
						lws_snprintf(stats_json, sizeof(stats_json),
								"{\"type\":\"stats\",\"stats\":\"%dx%d -> %dx%d @ %llufps (Excellent)\"}",
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
				if (cur_p && !strcmp(cur_p->name, "lws-webrtc-camshow-v4l2"))
					return 0;

				const struct lws_protocols *p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
				if (p)
					return (int)p->per_session_data_size;
				return 0;
			}

		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			lwsl_err("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__, in ? (char *)in : "(null)");
			/* Fallthrough to clean up if needed, though usually just error */
			break;

		case LWS_CALLBACK_CLIENT_CLOSED:
			if (we_ops && we_ops->get_user_data) {
				struct pss_camshow *app_state = (struct pss_camshow *)we_ops->get_user_data(user);
				if (app_state) {
					lwsl_notice("%s: Closing connection for %s\n", __func__, app_state->video_device ? app_state->video_device : "?");
					if (app_state->v4l2_ctx) lws_v4l2_destroy((struct lws_v4l2_ctx **)&app_state->v4l2_ctx);
					if (app_state->jpeg_dec) lws_jpeg_free((lws_jpeg_t **)&app_state->jpeg_dec);
					if (app_state->yuv_frame) free(app_state->yuv_frame);
					if (app_state->video_device) free((void*)app_state->video_device);
					media_deinit(app_state);
					free(app_state);
					we_ops->set_user_data((struct pss_webrtc *)user, NULL);
				} else {
					lwsl_notice("%s: Client Closed (no app state)\n", __func__);
				}
			}
			break;

		case LWS_CALLBACK_CLOSED: /* Handle server-side close too if we were server, but we are client */
			/* fallthrough */

		case LWS_CALLBACK_RAW_RX_FILE:
			/* This comes from the capture wsi (lws-webrtc-camshow-v4l2 protocol) */
			/* The 'user' pointer for THIS WSI was manually set to 'app_state' */
			{
				struct pss_camshow *app_state = (struct pss_camshow *)user;
				if (app_state && wsi == app_state->wsi_v4l2) {
					struct v4l2_buffer buf_v;

					memset(&buf_v, 0, sizeof(buf_v));
					buf_v.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
					buf_v.memory = V4L2_MEMORY_MMAP;
					if (lws_v4l2_native_ioctl(app_state->v4l2_ctx, VIDIOC_DQBUF, &buf_v) >= 0) {
						app_state->frame_count++;
						if (we_ops && we_ops->send_video && app_state->pss) {
							media_process_video_frame(app_state, (int)buf_v.index, (size_t)buf_v.bytesused);
						}
						if (lws_v4l2_native_ioctl(app_state->v4l2_ctx, VIDIOC_QBUF, &buf_v) < 0)
							lwsl_err("%s: VIDIOC_QBUF failed: %s\n", __func__, strerror(errno));
					}
				}
			}
			break;

		default: break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{ "lws-webrtc-camshow", callback_webrtc_camshow, 0, 4096, 0, NULL, 0 },
	{ "lws-webrtc-camshow-v4l2", callback_webrtc_camshow, 0, 4096, 0, NULL, 0 }, /* 0 PSS size for capture wsi */
	LWS_PROTOCOL_LIST_TERM
};

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *context = lws_system_context_from_system_mgr(mgr);

	switch (target) {
		case LWS_SYSTATE_OPERATIONAL:
			if (current == LWS_SYSTATE_OPERATIONAL) {

				struct lws_vhost *vh = lws_get_vhost_by_name(context, "camshow-clients");
				if (vh) {
					lwsl_notice("%s: camshow-clients vhost already exists, skipping creation\n", __func__);
					return 0;
				}

				/* Create ONE vhost for all connections */
				{
					struct lws_context_creation_info vinfo;
					memset(&vinfo, 0, sizeof(vinfo));
					vinfo.vhost_name = "camshow-clients";
					vinfo.protocols = protocols;
					vinfo.port = CONTEXT_PORT_NO_LISTEN;
					vinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

					static struct lws_protocol_vhost_options pvo_ops = { NULL, NULL, "lws-webrtc-ops", (void *)&we_ops_storage };
					static struct lws_protocol_vhost_options pvo_udp = { NULL, NULL, "lws-webrtc-udp", "ok" };
					static struct lws_protocol_vhost_options pvo1 = { &pvo_udp, NULL, "lws-webrtc-camshow", "ok" };
					static struct lws_protocol_vhost_options pvo = { &pvo1, &pvo_ops, "lws-webrtc", "ok" };
					vinfo.pvo = &pvo;

					vh = lws_create_vhost(context, &vinfo);
				}

				if (!vh) {
					lwsl_err("Failed to create vhost\n");
					return -1;
				}

				/* Loop through devices and initiate connections */
				if (!devices_copy)
					devices_copy = strdup(devs_list);

				char *p = devices_copy;
				char *token;

				while ((token = strsep(&p, ","))) {
					struct lws_client_connect_info i;
					const char *prot, *ads, *path;
					char uri[256];
					int port;

					memset(&i, 0, sizeof(i));
					i.context = context;
					i.vhost = vh;

					lws_strncpy(uri, url, sizeof(uri));
					if (lws_parse_uri(uri, &prot, &ads, &port, &path)) {
						lwsl_err("Failed to parse URL: %s\n", url);
						continue;
					}

					char path_buffer[256];
					if (path[0] != '/') {
						lws_snprintf(path_buffer, sizeof(path_buffer), "/%s", path);
						path = path_buffer;
					}

					lwsl_notice("Connecting camshow client for device: %s to %s://%s:%d%s\n",
							token, prot, ads, port, path);

					i.address = ads;
					i.port = port;
					i.path = path;
					i.host = i.address;
					i.origin = i.address;
					i.protocol = "lws-webrtc-mixer"; // The subprotocol to request
					i.local_protocol_name = "lws-webrtc-camshow"; // The local handler
					i.opaque_user_data = (void *)token; // Pass device path

					if (!strcmp(prot, "https") || !strcmp(prot, "wss"))
						i.ssl_connection = LCCSCF_USE_SSL;

					lws_client_connect_via_info(&i);
				}
			}
			break;
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

void sigint_handler(int signum) {
    interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *opt;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	info.port = CONTEXT_PORT_NO_LISTEN; /* Client only */
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	static const char * const plugin_dirs[] = { "./lib", "./build/lib", NULL };
	info.plugin_dirs = plugin_dirs;

	/* Config parsing */
	/* Config parsing */
	if ((opt = lws_cmdline_option(argc, argv, "--url"))) {
		url = opt;
	}

	/* Parse devices */
	if ((opt = lws_cmdline_option(argc, argv, "--video-device"))) {
		devs_list = opt;
	}

	/* Parse name */
	if ((opt = lws_cmdline_option(argc, argv, "--name"))) {
		client_name = opt;
	}

	/* Parse resolution */
	if ((opt = lws_cmdline_option(argc, argv, "--width"))) {
		app_width = (uint32_t)atoi(opt);
	}
	if ((opt = lws_cmdline_option(argc, argv, "--height"))) {
		app_height = (uint32_t)atoi(opt);
	}

	signal(SIGINT, sigint_handler);

	nl.name = "app";
	nl.notify_cb = app_system_state_nf;
	info.register_notifier_list = app_notifier_list;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

	while (!interrupted)
		if (lws_service(cx, 0) < 0)
			break;

	lws_context_destroy(cx);

	if (devices_copy) free(devices_copy);

	return 0;
}
