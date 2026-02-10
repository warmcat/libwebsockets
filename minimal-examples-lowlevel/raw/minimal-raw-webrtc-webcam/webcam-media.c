#include "webcam-media.h"

#include <libwebsockets.h>
#include <string.h>
#include <linux/videodev2.h>
#include <libwebsockets/lws-transcode.h>
#include <libwebsockets/lws-v4l2.h>

// Local conversion helpers removed, now using lws_transcode_... versions from core

int
media_update_scaler(struct per_vhost_data *vhd)
{
	if (vhd->sws_ctx)
		lws_transcode_scaler_destroy(&vhd->sws_ctx);

	vhd->sws_ctx = lws_transcode_scaler_create(vhd->width, vhd->height,
						     vhd->target_width, vhd->target_height);

	if (vhd->avframe_scaled)
		lws_transcode_frame_free(&vhd->avframe_scaled);

	vhd->avframe_scaled = lws_transcode_frame_alloc(vhd->target_width, vhd->target_height);

	if (vhd->tcc_enc) {
		struct lws_transcode_info info;

		lws_transcode_destroy(&vhd->tcc_enc);

		memset(&info, 0, sizeof(info));
		info.codec = LWS_TCC_H264;
		info.width = vhd->target_width;
		info.height = vhd->target_height;
		info.fps = 30;
		info.bitrate = 1000000;

		vhd->tcc_enc = lws_transcode_encoder_create(&info);
	}

	return 0;
}

int
media_init(struct per_vhost_data *vhd)
{
	struct lws_transcode_info info;

	memset(&info, 0, sizeof(info));
	info.codec = LWS_TCC_H264;
	if (vhd->width != vhd->target_width || vhd->height != vhd->target_height) {
		info.width = vhd->target_width;
		info.height = vhd->target_height;
	} else {
		info.width = vhd->width;
		info.height = vhd->height;
	}
	info.fps = 30;
	info.bitrate = 1000000;

	vhd->tcc_enc = lws_transcode_encoder_create(&info);
	if (!vhd->tcc_enc)
		return -1;

	vhd->avframe = lws_transcode_frame_alloc(vhd->width, vhd->height);
	if (!vhd->avframe)
		return -1;

	return 0;
}

void
media_deinit(struct per_vhost_data *vhd)
{
	if (vhd->tcc_enc) lws_transcode_destroy(&vhd->tcc_enc);
	if (vhd->avframe) lws_transcode_frame_free(&vhd->avframe);
	if (vhd->avframe_scaled) lws_transcode_frame_free(&vhd->avframe_scaled);
	if (vhd->sws_ctx) lws_transcode_scaler_destroy(&vhd->sws_ctx);
}

int
media_process_video_frame(struct per_vhost_data *vhd, int index, size_t len)
{
	void *start;
	size_t full_len;
	uint8_t *buf;
	size_t out_len;

	if (lws_v4l2_get_buffer(vhd->v4l2_ctx, index, &start, &full_len) < 0)
		return -1;

	if (vhd->pixelformat == V4L2_PIX_FMT_MJPEG) {
		if (lws_transcode_mjpeg_to_yuv420p(vhd->jpeg_dec, start, len, vhd->yuv_frame, vhd->width, vhd->height) < 0)
			return -1;
	} else if (vhd->pixelformat == V4L2_PIX_FMT_YUYV) {
		lws_transcode_yuyv_to_yuv420p(start, vhd->yuv_frame, vhd->width, vhd->height);
	}

	lws_transcode_frame_import_yuv(vhd->avframe, vhd->yuv_frame);

	if (vhd->width != vhd->target_width || vhd->height != vhd->target_height) {
		lws_transcode_scale(vhd->sws_ctx, vhd->avframe, vhd->avframe_scaled);
		if (lws_transcode_encode(vhd->tcc_enc, vhd->avframe_scaled, &buf, &out_len) >= 0) {
			struct relay_data rd_v = { buf, out_len, 1 };
			we_ops->foreach_session(vhd->vhd, relay_to_session, &rd_v);
		}
	} else {
		if (lws_transcode_encode(vhd->tcc_enc, vhd->avframe, &buf, &out_len) >= 0) {
			struct relay_data rd_v = { buf, out_len, 1 };
			we_ops->foreach_session(vhd->vhd, relay_to_session, &rd_v);
		}
	}

	return 0;
}
