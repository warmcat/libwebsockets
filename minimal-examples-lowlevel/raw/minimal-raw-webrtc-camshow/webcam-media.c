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
#include <linux/videodev2.h>
#include <libwebsockets/lws-transcode.h>
#include <libwebsockets/lws-v4l2.h>

extern const struct lws_webrtc_ops *we_ops;

int
media_update_scaler(struct pss_camshow *pss)
{
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

	pss->tcc_enc = lws_transcode_encoder_create(&info);
	if (!pss->tcc_enc)
		return -1;

	pss->avframe = lws_transcode_frame_alloc(pss->width, pss->height);
	if (!pss->avframe)
		return -1;

	return 0;
}

void
media_deinit(struct pss_camshow *pss)
{
	if (pss->tcc_enc) lws_transcode_destroy(&pss->tcc_enc);
	if (pss->avframe) lws_transcode_frame_free(&pss->avframe);
	if (pss->avframe_scaled) lws_transcode_frame_free(&pss->avframe_scaled);
	if (pss->sws_ctx) lws_transcode_scaler_destroy(&pss->sws_ctx);
}

int
media_process_video_frame(struct pss_camshow *pss, int index, size_t len)
{
	void *start;
	uint8_t *buf;
	size_t out_len;
	enum lws_webrtc_codec codec = pss->force_av1 ? LWS_WEBRTC_CODEC_AV1 : LWS_WEBRTC_CODEC_H264;

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
}
