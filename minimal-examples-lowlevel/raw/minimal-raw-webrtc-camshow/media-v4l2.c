/*
 * lws-minimal-raw-webrtc-camshow
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include "webcam-media.h"

#include <libwebsockets.h>
#include <string.h>
#include <errno.h>
#include <linux/videodev2.h>
#include <libwebsockets/lws-transcode.h>
#include <libwebsockets/lws-v4l2.h>

extern const struct lws_webrtc_ops *we_ops;

int
media_update_scaler(struct pss_camshow *pss)
{
#if defined(LWS_WITH_TRANSCODE)
	if (pss->sws_ctx)
		lws_transcode_scaler_destroy(&pss->sws_ctx);

	pss->sws_ctx = lws_transcode_scaler_create(pss->width, pss->height,
			pss->target_width, pss->target_height);

	if (pss->avframe_scaled)
		lws_transcode_frame_free(&pss->avframe_scaled);

	pss->avframe_scaled = lws_transcode_frame_alloc(pss->target_width, pss->target_height);

	if (pss->tcc_enc) {
		struct lws_transcode_info info;

		lws_transcode_destroy(&pss->tcc_enc);

		memset(&info, 0, sizeof(info));
		info.codec = pss->force_av1 ? LWS_TCC_AV1 : LWS_TCC_H264;
		info.width = pss->target_width;
		info.height = pss->target_height;
		info.fps = 30;
		info.bitrate = 1000000;

		pss->tcc_enc = lws_transcode_encoder_create(&info);
	}
#endif

	return 0;
}

int
media_init(struct pss_camshow *pss)
{
	struct lws_transcode_info info;

	memset(&info, 0, sizeof(info));
	info.codec = pss->force_av1 ? LWS_TCC_AV1 : LWS_TCC_H264;

	if (pss->width != pss->target_width || pss->height != pss->target_height) {
		info.width = pss->target_width;
		info.height = pss->target_height;
	} else {
		info.width = pss->width;
		info.height = pss->height;
	}
	info.fps = 30;
	info.bitrate = 1000000;

	/* If camera provides native H.264 and we aren't forcing AV1, we don't need a transcode encoder! */
	if (pss->pixelformat == V4L2_PIX_FMT_H264 && !pss->force_av1) {
		lwsl_notice("%s: Hardware H.264 offload detected! Skipping libx264 instantiation.\n", __func__);
		return 0;
	}

#if defined(LWS_WITH_TRANSCODE)
	pss->tcc_enc = lws_transcode_encoder_create(&info);
	if (!pss->tcc_enc)
		return -1;

	pss->avframe = lws_transcode_frame_alloc(pss->width, pss->height);
	if (!pss->avframe)
		return -1;

	return 0;
#else
	lwsl_err("%s: Non-H264 formats require LWS_WITH_TRANSCODE\n", __func__);
	return -1;
#endif
}

void
media_deinit(struct pss_camshow *pss)
{
#if defined(LWS_WITH_TRANSCODE)
	if (pss->tcc_enc) lws_transcode_destroy(&pss->tcc_enc);
	if (pss->avframe) lws_transcode_frame_free(&pss->avframe);
	if (pss->avframe_scaled) lws_transcode_frame_free(&pss->avframe_scaled);
	if (pss->sws_ctx) lws_transcode_scaler_destroy(&pss->sws_ctx);
#endif
}

int
media_process_video_frame(struct pss_camshow *pss, int index, size_t len)
{
	void *start;

	/*
	 * We passed the actual payload length (bytesused) in 'len'.
	 * Do NOT pass &len to lws_v4l2_get_buffer, or it will overwrite it
	 * with the full buffer capacity (e.g. 307200)!
	 */
	if (lws_v4l2_get_buffer(pss->v4l2_ctx, index, &start, NULL) < 0)
		return -1;

	{
		static int once;
		if (!once) {
			lwsl_notice("%s: FIRST FRAME: fmt 0x%x, len %zu, w %d, h %d, force_av1 %d\n",
					__func__, pss->pixelformat, len, pss->width, pss->height, pss->force_av1);
			once = 1;
		}
	}

	/* If native H.264 and we want H.264, passthrough */
	if (pss->pixelformat == V4L2_PIX_FMT_H264 && !pss->force_av1) {
		int is_h264 = 0;
		if (len >= 4) {
			const uint8_t *p = (const uint8_t *)start;
			if ((p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1) ||
					(p[0] == 0 && p[1] == 0 && p[2] == 1))
				is_h264 = 1;
		}

		if (is_h264) {
			/* The driver might report 'bytesused' as full buffer size (capacity).
			 * Since H.264 RBSP always ends with a stop bit (non-zero byte),
			 * we can safely strip all trailing zeros to find the true end of the frame.
			 * Optimized: Scan 8 bytes at a time (uint64_t) for speed.
			 */
			uint8_t *p_start = (uint8_t *)start;
			uint8_t *p_end = p_start + len;
			size_t orig_len = len;

			// 1. Scan bytes until aligned to 8-byte boundary
			while (((uintptr_t)p_end & 7) && p_end > p_start) {
				if (*(p_end - 1) != 0) goto strip_done;
				p_end--;
			}

			// 2. Scan 8 bytes at a time
			uint64_t *p_end64 = (uint64_t *)p_end;
			uint64_t *p_start64 = (uint64_t *)((uintptr_t)(p_start + 7u) & ~7u); // Align up

			while (p_end64 > p_start64) {
				if (*(p_end64 - 1) != 0) break;
				p_end64--;
			}
			p_end = (uint8_t *)p_end64;

			// 3. Scan remaining bytes
			while (p_end > p_start) {
				if (*(p_end - 1) != 0) break;
				p_end--;
			}

strip_done:
			len = (size_t)(p_end - p_start);

			/* Debug: Log if we stripped significant zeros */
			/* Debug: Log if we stripped significant zeros */
			if (len < orig_len) {
				static int stripped_once;
				if (!stripped_once && (orig_len - len) > 100) {
					lwsl_notice("%s: Stripped trailing zeros: Orig %zu -> New %zu\n", __func__, orig_len, len);
					stripped_once = 1;
				}
			}
		}

		/* Sanity check: If logic above failed or user wants passthrough */
		if (is_h264 || (!is_h264 && len != pss->width * pss->height && len != pss->width * pss->height * 2)) {
			if (we_ops && we_ops->send_video) {
				we_ops->send_video(we_ops->get_media((struct pss_webrtc *)pss->pss), start, len, LWS_WEBRTC_CODEC_H264, (uint32_t)(lws_now_usecs() * 9 / 100));
				pss->packets_sent++;
			}
			return 0;
		}
	}

#if defined(LWS_WITH_TRANSCODE)
	uint8_t *buf;
	size_t out_len;
	enum lws_webrtc_codec codec = pss->force_av1 ? LWS_WEBRTC_CODEC_AV1 : LWS_WEBRTC_CODEC_H264;

	/* If we skipped transcoder allocation for native H.264 but somehow reached here, abort */
	if (!pss->tcc_enc || !pss->avframe) {
		lwsl_err("%s: Missing transcoder allocation for non-native H.264 frame!\n", __func__);
		return -1;
	}

	/* Otherwise transcode */
	if (pss->pixelformat == V4L2_PIX_FMT_MJPEG) {
		if (lws_transcode_mjpeg_to_yuv420p(pss->jpeg_dec, start, len, pss->yuv_frame, pss->width, pss->height) < 0)
			return -1;
	} else if (pss->pixelformat == V4L2_PIX_FMT_YUYV || len == pss->width * pss->height * 2) {
		lws_transcode_yuyv_to_yuv420p(start, pss->yuv_frame, pss->width, pss->height);
	} else if (len == pss->width * pss->height) {
		/* Treat Y8/Grey raw as YUV420p (Y plane only, UV = 128) */
		memcpy(pss->yuv_frame, start, len);
		memset(pss->yuv_frame + len, 128, (size_t)(pss->width * pss->height) / 2);
	}

	lws_transcode_frame_import_yuv(pss->avframe, pss->yuv_frame);

	if (pss->width != pss->target_width || pss->height != pss->target_height) {
		lws_transcode_scale(pss->sws_ctx, pss->avframe, pss->avframe_scaled);
		if (lws_transcode_encode(pss->tcc_enc, pss->avframe_scaled, &buf, &out_len) >= 0) {
			if (we_ops && we_ops->send_video) {
				we_ops->send_video(we_ops->get_media((struct pss_webrtc *)pss->pss), buf, out_len, codec, (uint32_t)(lws_now_usecs() * 9 / 100));
				pss->packets_sent++;
			}
		}
	} else {
		if (lws_transcode_encode(pss->tcc_enc, pss->avframe, &buf, &out_len) >= 0) {
			if (we_ops && we_ops->send_video) {
				we_ops->send_video(we_ops->get_media((struct pss_webrtc *)pss->pss), buf, out_len, codec, (uint32_t)(lws_now_usecs() * 9 / 100));
				pss->packets_sent++;
			}
		}
	}

	return 0;
#else
	lwsl_err("%s: Transcoding disabled but received non-H264 passthrough frame!\n", __func__);
	return -1;
#endif
}

/*
 * V4L2 + FFmpeg pipeline backend implementation
 */

static int media_v4l2_init(struct pss_camshow *pss)
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

static int media_v4l2_get_event_fd(struct pss_camshow *pss)
{
	return lws_v4l2_get_fd(pss->v4l2_ctx);
}

static int media_v4l2_process_rx(struct pss_camshow *pss)
{
	struct v4l2_buffer buf_v;

	memset(&buf_v, 0, sizeof(buf_v));
	buf_v.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf_v.memory = V4L2_MEMORY_MMAP;
	if (lws_v4l2_native_ioctl(pss->v4l2_ctx, VIDIOC_DQBUF, &buf_v) >= 0) {
		pss->frame_count++;
		if (we_ops && we_ops->send_video && pss->pss) {
			media_process_video_frame(pss, (int)buf_v.index, (size_t)buf_v.bytesused);
		}
		if (lws_v4l2_native_ioctl(pss->v4l2_ctx, VIDIOC_QBUF, &buf_v) < 0)
			lwsl_err("%s: VIDIOC_QBUF failed: %s\n", __func__, strerror(errno));
	}
	return 0;
}

struct json_dump_ctx {
	char		*p;
	char		*end;
	int		first;
};

static int json_control_cb(void *user, const struct lws_v4l2_control *c)
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

static int media_v4l2_send_capabilities(struct pss_camshow *pss)
{
	struct v4l2_queryctrl q;
	struct json_dump_ctx j;
	char buf[4096];

	if (!pss->v4l2_ctx) {
		lwsl_err("%s: No v4l2_ctx, cannot send capabilities\n", __func__);
		return -1;
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

	return 0;
}

static int media_v4l2_set_control(struct pss_camshow *pss, uint32_t id, int32_t val)
{
	if (pss->v4l2_ctx) {
		lws_v4l2_set_control(pss->v4l2_ctx, id, val);
	}
	return 0;
}

static void media_v4l2_deinit(struct pss_camshow *pss)
{
	if (pss->v4l2_ctx) lws_v4l2_destroy((struct lws_v4l2_ctx **)&pss->v4l2_ctx);
	if (pss->jpeg_dec) lws_jpeg_free((lws_jpeg_t **)&pss->jpeg_dec);
	if (pss->yuv_frame) free(pss->yuv_frame);
	if (pss->video_device) free((void*)pss->video_device);
	media_deinit(pss);
}

const struct lws_cam_pipeline_ops pipeline_v4l2 = {
	.name = "v4l2_ffmpeg",
	.init = media_v4l2_init,
	.get_event_fd = media_v4l2_get_event_fd,
	.process_rx = media_v4l2_process_rx,
	.send_capabilities = media_v4l2_send_capabilities,
	.set_control = media_v4l2_set_control,
	.deinit = media_v4l2_deinit,
};
