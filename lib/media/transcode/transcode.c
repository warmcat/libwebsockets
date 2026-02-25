/*
 * libwebsockets - small server side websockets and web server implementation
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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * LIABILITY, WHETHER IN AN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <libwebsockets.h>

#include <libavcodec/avcodec.h>
#include <libavutil/opt.h>
#include <libavutil/imgutils.h>
#include <libswscale/swscale.h>

#include "private-lib-core.h"

struct lws_transcode_ctx {
	AVCodecContext		*avctx;
	AVPacket		*avpkt;
	const AVCodec		*codec;
};

struct lws_transcode_ctx *
lws_transcode_encoder_create(const struct lws_transcode_info *info)
{
	struct lws_transcode_ctx *ctx = lws_zalloc(sizeof(*ctx), "transcode-ctx");
	const char *enc_name;

	if (!ctx)
		return NULL;

	if (info->codec == LWS_TCC_AV1) {
		ctx->codec = avcodec_find_encoder_by_name("librav1e");
		if (!ctx->codec)
			ctx->codec = avcodec_find_encoder_by_name("libsvtav1");
		if (!ctx->codec)
			ctx->codec = avcodec_find_encoder(AV_CODEC_ID_AV1);
	} else {
		ctx->codec = avcodec_find_encoder_by_name("libx264");
		if (!ctx->codec)
			ctx->codec = avcodec_find_encoder_by_name("libopenh264");
		if (!ctx->codec)
			ctx->codec = avcodec_find_encoder(AV_CODEC_ID_H264);
	}

	if (!ctx->codec) {
		lwsl_err("%s: Failed to find ANY encoder for codec %d\n", __func__, info->codec);
		goto bail;
	}
	enc_name = ctx->codec->name;
	lwsl_notice("%s: Using encoder: %s\n", __func__, enc_name);

	ctx->avctx = avcodec_alloc_context3(ctx->codec);
	if (!ctx->avctx)
		goto bail;

	ctx->avctx->width = (int)info->width;
	ctx->avctx->height = (int)info->height;
	ctx->avctx->time_base = (AVRational){1, (int)info->fps};
	ctx->avctx->framerate = (AVRational){(int)info->fps, 1};
	ctx->avctx->pix_fmt = AV_PIX_FMT_YUV420P;
	ctx->avctx->bit_rate = (int64_t)info->bitrate;
	ctx->avctx->gop_size = (int)info->fps;
	ctx->avctx->max_b_frames = 0;
	ctx->avctx->thread_count = 0; /* Auto detection */
	ctx->avctx->delay = 0;
	ctx->avctx->flags |= AV_CODEC_FLAG_LOW_DELAY;

	if (info->codec == LWS_TCC_AV1) {
		if (!strcmp(enc_name, "librav1e")) {
			av_opt_set(ctx->avctx->priv_data, "speed", "10", 0);
			av_opt_set(ctx->avctx->priv_data, "low_latency", "true", 0);
		} else if (!strcmp(enc_name, "libsvtav1")) {
			av_opt_set(ctx->avctx->priv_data, "preset", "13", 0);
			av_opt_set(ctx->avctx->priv_data, "tune", "0", 0);
			av_opt_set(ctx->avctx->priv_data, "svtav1-params", "rc=1:lookahead=0", 0);
		} else {
			/* Generic or other encoder options if needed */
			lwsl_warn("%s: Using generic options for AV1 encoder %s\n", __func__, enc_name);
			/* aom defaults normally ok, maybe set usage=realtime/cpu-used=8 if libaom-av1 */
			if (!strcmp(enc_name, "libaom-av1")) {
				av_opt_set(ctx->avctx->priv_data, "usage", "realtime", 0);
				av_opt_set(ctx->avctx->priv_data, "cpu-used", "8", 0);
				av_opt_set(ctx->avctx->priv_data, "row-mt", "1", 0);
				av_opt_set(ctx->avctx->priv_data, "tile-columns", "2", 0);
				av_opt_set(ctx->avctx->priv_data, "tile-rows", "2", 0);
				av_opt_set(ctx->avctx->priv_data, "lag-in-frames", "0", 0);
			}
		}
	} else {
		if (!strcmp(enc_name, "libx264")) {
			char x264_opts[128];
			av_opt_set(ctx->avctx->priv_data, "preset", "ultrafast", 0);
			av_opt_set(ctx->avctx->priv_data, "tune", "zerolatency", 0);
			lws_snprintf(x264_opts, sizeof(x264_opts),
				"repeat-headers=1:annexb=1:keyint=%d:rc-lookahead=0:vbv-maxrate=%d:vbv-bufsize=%d",
				(int)info->fps,
				(int)(info->bitrate / 1000),         /* Max rate in kbps */
				(int)(info->bitrate / 1000));        /* Buffer size in kbits (~1 sec buffer) */
			av_opt_set(ctx->avctx->priv_data, "x264-params", x264_opts, 0);
		}
	}

	if (avcodec_open2(ctx->avctx, ctx->codec, NULL) != 0)
		goto bail;

	ctx->avpkt = av_packet_alloc();
	if (!ctx->avpkt)
		goto bail;

	return ctx;

bail:
	lws_transcode_destroy(&ctx);
	return NULL;
}

struct lws_transcode_ctx *
lws_transcode_decoder_create(enum lws_transcode_codec codec)
{
	struct lws_transcode_ctx *ctx = lws_zalloc(sizeof(*ctx), "transcode-ctx");
	if (!ctx)
		return NULL;

	if (codec == LWS_TCC_AV1) {
		ctx->codec = avcodec_find_decoder_by_name("libdav1d");
		if (!ctx->codec)
			ctx->codec = avcodec_find_decoder(AV_CODEC_ID_AV1);
	} else
		ctx->codec = avcodec_find_decoder(AV_CODEC_ID_H264);
	if (!ctx->codec)
		goto bail;

	ctx->avctx = avcodec_alloc_context3(ctx->codec);
	if (!ctx->avctx)
		goto bail;

	ctx->avctx->flags |= AV_CODEC_FLAG_LOW_DELAY;

	if (avcodec_open2(ctx->avctx, ctx->codec, NULL) != 0)
		goto bail;

	ctx->avpkt = av_packet_alloc();
	if (!ctx->avpkt)
		goto bail;

	return ctx;

bail:
	lws_transcode_destroy(&ctx);
	return NULL;
}

void
lws_transcode_destroy(struct lws_transcode_ctx **ctx)
{
	if (!ctx || !*ctx)
		return;

	if ((*ctx)->avctx)
		avcodec_free_context(&(*ctx)->avctx);
	if ((*ctx)->avpkt)
		av_packet_free(&(*ctx)->avpkt);

	lws_free(*ctx);
	*ctx = NULL;
}

void *
lws_transcode_frame_alloc(uint32_t w, uint32_t h)
{
	AVFrame *frame = av_frame_alloc();
	if (!frame)
		return NULL;

	frame->format = AV_PIX_FMT_YUV420P;
	frame->width = (int)w;
	frame->height = (int)h;

	if (av_frame_get_buffer(frame, 32) < 0) {
		av_frame_free(&frame);
		return NULL;
	}

	return (void *)frame;
}

void
lws_transcode_frame_free(void **frame)
{
	if (!frame || !*frame)
		return;

	AVFrame *f = (AVFrame *)(*frame);
	av_frame_free(&f);
	*frame = NULL;
}

int
lws_transcode_decode(struct lws_transcode_ctx *ctx, const uint8_t *buf, size_t len, void *frame)
{
	int ret;

	if (buf && len > 0) {
		ctx->avpkt->data = (uint8_t *)buf;
		ctx->avpkt->size = (int)len;

		ret = avcodec_send_packet(ctx->avctx, ctx->avpkt);
		if (ret < 0 && ret != AVERROR(EAGAIN) && ret != AVERROR_EOF)
			return ret;
	}

	ret = avcodec_receive_frame(ctx->avctx, (AVFrame *)frame);
	return ret; /* Returns 0 if frame retrieved, or AVERROR(EAGAIN) if needs more data */
}

int
lws_transcode_encode(struct lws_transcode_ctx *ctx, void *frame, uint8_t **buf, size_t *len)
{
	int ret;

	ret = avcodec_send_frame(ctx->avctx, (AVFrame *)frame);
	if (ret < 0)
		return ret;

	ret = avcodec_receive_packet(ctx->avctx, ctx->avpkt);
	if (ret < 0)
		return ret;

	*buf = ctx->avpkt->data;
	*len = (size_t)ctx->avpkt->size;

	return 0;
}

void *
lws_transcode_scaler_create(uint32_t src_w, uint32_t src_h, uint32_t dst_w, uint32_t dst_h)
{
	struct SwsContext *sws = sws_getContext((int)src_w, (int)src_h, AV_PIX_FMT_YUV420P,
						(int)dst_w, (int)dst_h, AV_PIX_FMT_YUV420P,
						SWS_BILINEAR, NULL, NULL, NULL);
	return (void *)sws;
}

void
lws_transcode_scaler_destroy(void **sws)
{
	if (!sws || !*sws)
		return;

	sws_freeContext((struct SwsContext *)(*sws));
	*sws = NULL;
}

int
lws_transcode_scale(void *sws, void *src_frame, void *dst_frame)
{
	AVFrame *src = (AVFrame *)src_frame;
	AVFrame *dst = (AVFrame *)dst_frame;

	return sws_scale((struct SwsContext *)sws, (const uint8_t * const*)src->data, src->linesize,
			  0, src->height, dst->data, dst->linesize);
}

void
lws_transcode_yuyv_to_yuv420p(const uint8_t *yuyv, uint8_t *yuv, uint32_t w, uint32_t h)
{
	uint8_t *y = yuv;
	uint8_t *u = yuv + (w * h);
	uint8_t *v = yuv + (w * h) + (w * h) / 4;
	uint32_t i, j;

	for (i = 0; i < h; i++) {
		for (j = 0; j < w; j += 2) {
			*y++ = yuyv[(i * w + j) * 2];
			*y++ = yuyv[(i * w + j + 1) * 2];
			if (i % 2 == 0) {
				*u++ = yuyv[(i * w + j) * 2 + 1];
				*v++ = yuyv[(i * w + j) * 2 + 3];
			}
		}
	}
}

int
lws_transcode_mjpeg_to_yuv420p(void *jpeg_dec, const uint8_t *mjpeg, size_t len, uint8_t *yuv, uint32_t w, uint32_t h)
{
	lws_jpeg_t *dec = (lws_jpeg_t *)jpeg_dec;
	const uint8_t *buf = mjpeg;
	size_t size = len;
	const uint8_t *line;
	lws_stateful_ret_t r;
	uint32_t y_row = 0;

	while (y_row < h) {
		r = lws_jpeg_emit_next_line(dec, &line, &buf, &size, 0);
		if (r == LWS_SRET_WANT_INPUT)
			break;
		if (r >= LWS_SRET_FATAL)
			return -1;
		if (r == LWS_SRET_WANT_OUTPUT) {
			uint8_t *y_plane = yuv + (y_row * w);
			uint8_t *u_plane = yuv + (w * h) + (y_row / 2) * (w / 2);
			uint8_t *v_plane = yuv + (w * h) + (w * h) / 4 + (y_row / 2) * (w / 2);

			for (uint32_t x = 0; x < w; x++) {
				/* ITU-R BT.601 Integer Constants */
				int r_val = line[x * 3], g_val = line[x * 3 + 1], b_val = line[x * 3 + 2];
				y_plane[x] = (uint8_t)(( (  66 * r_val + 129 * g_val +  25 * b_val + 128) >> 8) + 16);
				if (y_row % 2 == 0 && x % 2 == 0) {
					u_plane[x / 2] = (uint8_t)(( ( -38 * r_val -  74 * g_val + 112 * b_val + 128) >> 8) + 128);
					v_plane[x / 2] = (uint8_t)(( ( 112 * r_val -  94 * g_val -  18 * b_val + 128) >> 8) + 128);
				}
			}
			y_row++;
		}
		if (r == LWS_SRET_OK)
			break;
	}

	return 0;
}

int
lws_transcode_frame_import_yuv(void *frame, uint8_t *yuv_buf)
{
	AVFrame *f = (AVFrame *)frame;

	return av_image_fill_arrays(f->data, f->linesize, yuv_buf,
				     AV_PIX_FMT_YUV420P, f->width, f->height, 1);
}

uint8_t **
lws_transcode_frame_get_data(void *frame)
{
	return ((AVFrame *)frame)->data;
}

int *
lws_transcode_frame_get_linesize(void *frame)
{
	return ((AVFrame *)frame)->linesize;
}

int
lws_transcode_frame_get_width(void *frame)
{
	return ((AVFrame *)frame)->width;
}

int
lws_transcode_frame_get_height(void *frame)
{
	return ((AVFrame *)frame)->height;
}
