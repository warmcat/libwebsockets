/*
 * lws-minimal-raw-webrtc-webcam
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>

#include "webcam-media.h"

#if !defined(WIN32) && !defined(_WIN32)
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <arpa/inet.h>
#include <libwebsockets/lws-v4l2.h>
#include <libwebsockets/lws-alsa.h>
#include <libwebsockets/lws-rtp.h>

const struct lws_webrtc_ops *we_ops;

int
relay_to_session(struct pss_webrtc *pss, void *user)
{
	struct relay_data *rd = (struct relay_data *)user;

	if (rd->is_video) {
		uint32_t pts = (uint32_t)(lws_now_usecs() * 9 / 100);
		return we_ops->send_video(we_ops->get_media(pss), rd->buf, rd->len, LWS_WEBRTC_CODEC_H264, pts);
	}

	return we_ops->send_audio(we_ops->get_media(pss), rd->buf, rd->len, 0);
}

static int
v4l2_init(struct per_vhost_data *vhd)
{
	struct lws_v4l2_info info;

	memset(&info, 0, sizeof(info));
	info.device_path = vhd->video_device;
	info.width = vhd->width;
	info.height = vhd->height;
	info.pixelformat = V4L2_PIX_FMT_H264;

	vhd->v4l2_ctx = lws_v4l2_create(&info);
	if (!vhd->v4l2_ctx) {
		lwsl_err("%s: Failed to create V4L2 context\n", __func__);
		return -1;
	}

	lws_v4l2_get_info(vhd->v4l2_ctx, &info);
	vhd->width = info.width;
	vhd->height = info.height;
	vhd->pixelformat = info.pixelformat;

	lwsl_notice("%s: V4L2 negotiated %dx%d, format 0x%x\n", __func__, vhd->width, vhd->height, vhd->pixelformat);

	media_update_scaler(vhd);

	vhd->yuv_size = (vhd->width * vhd->height * 3) / 2;
	if (vhd->yuv_frame) free(vhd->yuv_frame);
	vhd->yuv_frame = malloc(vhd->yuv_size);
	if (!vhd->yuv_frame)
		goto bail;

	if (media_init(vhd) < 0)
		goto bail;

	return 0;

bail:
	lws_v4l2_destroy(&vhd->v4l2_ctx);
	return -1;
}

static void
v4l2_reinit(struct per_vhost_data *vhd)
{
	lwsl_notice("%s: Re-initializing V4L2 with %dx%d\n", __func__, vhd->target_width, vhd->target_height);

	if (vhd->wsi_v4l2) {
		lws_set_timeout(vhd->wsi_v4l2, PENDING_TIMEOUT_KILLED_BY_PARENT, LWS_TO_KILL_ASYNC);
		vhd->wsi_v4l2 = NULL;
	}

	if (vhd->v4l2_ctx)
		lws_v4l2_destroy(&vhd->v4l2_ctx);

	vhd->width = vhd->target_width;
	vhd->height = vhd->target_height;

	if (v4l2_init(vhd) == 0) {
		struct lws_adopt_desc ad;
		memset(&ad, 0, sizeof(ad));
		ad.vh = we_ops->get_vhost(vhd->vhd);
		ad.type = LWS_ADOPT_RAW_FILE_DESC;
		ad.fd.filefd = (lws_filefd_type)(long)lws_v4l2_get_fd(vhd->v4l2_ctx);
		ad.vh_prot_name = "lws-webrtc-webcam";
		vhd->wsi_v4l2 = lws_adopt_descriptor_vhost_via_info(&ad);
	}
}

static int interrupted;
static lws_state_notify_link_t nl, *const app_notifier_list[] = {&nl, NULL};

static int
append_v4l2_control(void *user, const struct lws_v4l2_control *c)
{
	char **p = (char **)user;
	int n;

	n = lws_snprintf(*p, 256, "{\"id\":%u,\"name\":\"%s\",\"min\":%d,\"max\":%d,\"step\":%d,\"val\":%d},",
			 c->id, c->name, c->min, c->max, c->step, c->val);
	if (n > 0)
		*p += n;

	return 0;
}

static int
append_alsa_control(void *user, const struct lws_alsa_control *c)
{
	char **p = (char **)user;
	int n;

	n = lws_snprintf(*p, 256, "{\"id\":%u,\"name\":\"%s\",\"min\":%ld,\"max\":%ld,\"step\":%ld,\"val\":%ld},",
			 c->id, c->name, c->min, c->max, c->step, c->val);
	if (n > 0)
		*p += n;

	return 0;
}

static void
send_controls(struct lws *wsi, struct per_vhost_data *vhd)
{
	char buf[LWS_PRE + 2048], *p = buf + LWS_PRE, *start = p;

	p += lws_snprintf(p, 128, "{\"type\":\"device_controls\",\"video\":[");
	lws_v4l2_enum_controls(vhd->v4l2_ctx, append_v4l2_control, &p);
	if (*(p-1) == ',') p--;
	p += lws_snprintf(p, 128, "],\"audio\":[");
	lws_alsa_enum_controls(vhd->alsa_ctx, append_alsa_control, &p);
	if (*(p-1) == ',') p--;
	p += lws_snprintf(p, 64, "]}");

	lws_write(wsi, (uint8_t *)start, lws_ptr_diff_size_t(p, start), LWS_WRITE_TEXT);
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_HTTP_FILE_COMPLETION) {
		lwsl_info("%s: HTTP_FILE_COMPLETION\n", __func__);
                return -1;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_webrtc_webcam(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	int n;

	if (reason == LWS_CALLBACK_RECEIVE) {
		lwsl_warn("%s: LWS_CALLBACK_RECEIVE (%zu bytes): %.*s\n", __func__, len, (int)len, (const char *)in);
	}

	if (reason != LWS_CALLBACK_PROTOCOL_INIT &&
	    reason != LWS_CALLBACK_PROTOCOL_DESTROY) {
		if (vhd && vhd->vhd && we_ops && we_ops->shared_callback) {
			n = we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);
			if (n)
				return n;
		}
	}

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		send_controls(wsi, vhd);
		break;

	case LWS_CALLBACK_RECEIVE:
	{
		size_t alen;
		const char *val = lws_json_simple_find((const char *)in, len, "\"type\":", &alen);
		if (val && !strncmp(val, "\"request_res\"", 13)) {
			const char *w = lws_json_simple_find((const char *)in, len, "\"width\":", &alen);
			const char *h = lws_json_simple_find((const char *)in, len, "\"height\":", &alen);
			if (w && h) {
				vhd->target_width = (uint32_t)atoi(w);
				vhd->target_height = (uint32_t)atoi(h);
				lwsl_notice("%s: Requested resolution switch to %dx%d\n", __func__, vhd->target_width, vhd->target_height);
				v4l2_reinit(vhd);
			}
		}

		if (val && !strncmp(val, "\"set_control\"", 13)) {
			const char *kind = lws_json_simple_find((const char *)in, len, "\"kind\":", &alen);
			const char *id = lws_json_simple_find((const char *)in, len, "\"id\":", &alen);
			const char *v = lws_json_simple_find((const char *)in, len, "\"val\":", &alen);
			if (kind && id && v) {
				uint32_t cid = (uint32_t)atoi(id);
				int32_t cval = (int32_t)atoi(v);
				if (!strncmp(kind, "\"video\"", 7))
					lws_v4l2_set_control(vhd->v4l2_ctx, cid, cval);
				else
					lws_alsa_set_control(vhd->alsa_ctx, cid, (long)cval);
			}
		}
	}
		break;

	case LWS_CALLBACK_PROTOCOL_INIT:
	{
		const struct lws_protocols *p;
		struct lws_alsa_info ainfo;

		lwsl_vhost_notice(lws_get_vhost(wsi), "lws-webrtc-webcam: PROTOCOL_INIT");

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct per_vhost_data));
		if (!vhd)
			return -1;

		p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
		if (p) {
			vhd->vhd = (struct vhd_webrtc *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), p);
			we_ops = (const struct lws_webrtc_ops *)p->user;
		}

		if (!vhd->vhd || !we_ops || we_ops->abi_version != LWS_WEBRTC_OPS_ABI_VERSION) {
			lwsl_err("%s: plugin WebRTC missing or ABI mismatch (got %u, expected %u)\n",
				 __func__, we_ops ? we_ops->abi_version : 0, LWS_WEBRTC_OPS_ABI_VERSION);
			return -1;
		}

		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		const struct lws_protocol_vhost_options *pvo_dev = NULL;

		if (pvo)
			pvo_dev = lws_pvo_search(pvo, "video-device");

		if (pvo_dev && pvo_dev->value)
			vhd->video_device = pvo_dev->value;
		else
			vhd->video_device = "/dev/video0";

		vhd->width = LWS_RTP_VIDEO_WIDTH_720P;
                vhd->height = LWS_RTP_VIDEO_HEIGHT_720P;
		vhd->target_width = LWS_RTP_VIDEO_WIDTH_360P;
		vhd->target_height = LWS_RTP_VIDEO_HEIGHT_360P;

		int err;
		vhd->opus_enc = opus_encoder_create(AUDIO_RATE, AUDIO_CHANNELS, OPUS_APPLICATION_VOIP, &err);

		v4l2_init(vhd);

		memset(&ainfo, 0, sizeof(ainfo));
		ainfo.device_name = "default";
		ainfo.rate = AUDIO_RATE;
		ainfo.channels = AUDIO_CHANNELS;
		vhd->alsa_ctx = lws_alsa_create_capture(&ainfo);

		if (vhd->v4l2_ctx) {
			struct lws_adopt_desc ad;
			memset(&ad, 0, sizeof(ad));
			ad.vh = we_ops->get_vhost(vhd->vhd);
			ad.type = LWS_ADOPT_RAW_FILE_DESC;
			ad.fd.filefd = (lws_filefd_type)(long)lws_v4l2_get_fd(vhd->v4l2_ctx);
			ad.vh_prot_name = "lws-webrtc-webcam";
			vhd->wsi_v4l2 = lws_adopt_descriptor_vhost_via_info(&ad);
		}

		if (vhd->alsa_ctx) {
			lws_sock_file_fd_type u;
			u.filefd = (lws_filefd_type)(long long)lws_alsa_get_fd(vhd->alsa_ctx);
			vhd->wsi_alsa = lws_adopt_descriptor_vhost(we_ops->get_vhost(vhd->vhd), LWS_ADOPT_RAW_FILE_DESC, u, "lws-webrtc-webcam", NULL);
		}
		break;
	}

	case LWS_CALLBACK_GET_PSS_SIZE:
	{
		const struct lws_protocols *p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
		if (p)
			return (int)p->per_session_data_size;
		return 0;
	}

	case LWS_CALLBACK_RAW_RX_FILE:
		if (wsi == vhd->wsi_alsa) {
			n = lws_alsa_read(vhd->alsa_ctx, vhd->audio_samples, AUDIO_SAMPLES_PER_FRAME);
			if (n <= 0)
				return 0;
			int opus_len = opus_encode(vhd->opus_enc, vhd->audio_samples,
						   (int)n, vhd->opus_out,
						   sizeof(vhd->opus_out));
			if (opus_len > 0 && we_ops && we_ops->send_audio) {
				struct relay_data rd_a = { vhd->opus_out, (size_t)opus_len, 0 };
				we_ops->foreach_session(vhd->vhd, relay_to_session, &rd_a);
			}
		} else {
			struct v4l2_buffer buf_v;
			void *start;
			size_t len;

			memset(&buf_v, 0, sizeof(buf_v));
			buf_v.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			buf_v.memory = V4L2_MEMORY_MMAP;
			if (ioctl(lws_v4l2_get_fd(vhd->v4l2_ctx), VIDIOC_DQBUF, &buf_v) >= 0) {
				vhd->frame_count++;
				if (we_ops && we_ops->send_video) {
					if (vhd->pixelformat == V4L2_PIX_FMT_H264) {
						lws_v4l2_get_buffer(vhd->v4l2_ctx, (int)buf_v.index, &start, &len);
						struct relay_data rd_v = { start, buf_v.bytesused, 1 };
						we_ops->foreach_session(vhd->vhd, relay_to_session, &rd_v);
					} else {
						media_process_video_frame(vhd, (int)buf_v.index, (size_t)buf_v.bytesused);
					}
				}
				if (ioctl(lws_v4l2_get_fd(vhd->v4l2_ctx), VIDIOC_QBUF, &buf_v) < 0)
					lwsl_err("%s: VIDIOC_QBUF failed: %s\n", __func__, strerror(errno));
			}
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lws_alsa_destroy(&vhd->alsa_ctx);
		lws_v4l2_destroy(&vhd->v4l2_ctx);
		if (vhd->opus_enc)
			opus_encoder_destroy(vhd->opus_enc);
		if (vhd->jpeg_dec)
			lws_jpeg_free((lws_jpeg_t **)&vhd->jpeg_dec);
		free(vhd->yuv_frame);
		media_deinit(vhd);
		break;

	default: break;
	}

	return 0;
}

#else
static int interrupted;
static lws_state_notify_link_t nl, *const app_notifier_list[] = {&nl, NULL};

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_webrtc_webcam(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	return 0;
}

#endif

static struct lws_protocols protocols[] = {
	{ "app-http", callback_http, 0, 0, 0, NULL, 0 },
	{ "lws-webrtc-webcam", callback_webrtc_webcam, 0, 4096, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_http_mount mount = {
	.mountpoint = "/", .origin = "./mount-origin", .def = "index.html",
	.protocol = "app-http", .origin_protocol = LWSMPRO_FILE, .mountpoint_len = 1,
};

void sigint_handler(int sig) { interrupted = 1; }

static struct lws_protocol_vhost_options pvos[] = {
        { &pvos[1], &pvos[3], "lws-webrtc", "ok" },
        { NULL, &pvos[2], "external-ip", "127.0.0.1" },
        { NULL, NULL, "video-device", "/dev/video0" },
        { &pvos[1], &pvos[4], "lws-webrtc-udp", "ok" },
        { &pvos[1], &pvos[5], "lws-webrtc-webcam", "ok" },
        { NULL, NULL, "app-http", "ok" },
};

static int
app_system_state_nf(lws_state_manager_t *mgr,
                    lws_state_notify_link_t *link, int current,
                    int target) {
        struct lws_context *cx = lws_system_context_from_system_mgr(mgr);
        struct lws_context_creation_info info;
        struct lws_vhost *vh;

        switch (target) {
        case LWS_SYSTATE_OPERATIONAL:
                if (current == LWS_SYSTATE_OPERATIONAL)
                        break;

                lwsl_user("%s: OPERATIONAL->creating vhost\n", __func__);
                memset(&info, 0, sizeof(info));
                info.vhost_name         = "webrtc";
		info.port		= 7681;
		info.protocols          = protocols;
                info.pvo                = pvos;
                info.mounts             = &mount;
                info.options            = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

                vh = lws_create_vhost(cx, &info);
                if (!vh) {
                        lwsl_err("vhost creation failed\n");
                        return 0;
                }

                lws_finalize_startup(cx, __func__);
                break;
        }

        return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	const char *opt;

        lws_context_info_defaults(&info, NULL);
        lws_cmdline_option_handle_builtin(argc, argv, &info);

	if (lws_cmdline_option(argc, argv, "--help")) {
		printf("Usage: %s [options]\n", argv[0]);
		printf("Options:\n");
		printf("  --help		Show this help message\n");
		printf("  --video-device	Video device to use (default: /dev/video0)\n");
		printf("  --ip = IP		IP address to bind to (default: 127.0.0.1)\n");
		printf("  --mount-origin = DIR	Directory to serve (default: ./mount-origin)\n");
		return 0;
	}

        signal(SIGINT, sigint_handler);

	info.port               	= 7681;
	info.protocols          	= protocols;
	info.pvo                	= pvos;
        info.options            	= LWS_SERVER_OPTION_SKIP_PROTOCOL_INIT |
					  LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	static const char * const plugin_dirs[] = { "./lib", "./build/lib", NULL };
	info.plugin_dirs = plugin_dirs;

        nl.name				= "app";
        nl.notify_cb			= app_system_state_nf;
        info.register_notifier_list	= app_notifier_list;

        if ((opt = lws_cmdline_option(argc, argv, "--ip")))
                pvos[1].value = opt;
        if ((opt = lws_cmdline_option(argc, argv, "--video-device")))
                pvos[2].value = opt;
	if ((opt = lws_cmdline_option(argc, argv, "--mount-origin")))
                mount.origin = opt;

        cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

        while (!interrupted)
                if (lws_service(cx, 0) < 0)
                        break;

	lws_context_destroy(cx);

        return lws_cmdline_passfail(argc, argv, 0);
}
