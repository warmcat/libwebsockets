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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __LWS_TRANSCODE_H__
#define __LWS_TRANSCODE_H__

struct lws_transcode_ctx;

enum lws_transcode_codec {
	LWS_TCC_H264,
	LWS_TCC_AV1,
};

struct lws_transcode_info {
	enum lws_transcode_codec	codec;
	uint32_t			width;
	uint32_t			height;
	uint32_t			fps;
	uint32_t			bitrate;
};

LWS_VISIBLE LWS_EXTERN struct lws_transcode_ctx *
lws_transcode_encoder_create(const struct lws_transcode_info *info);

LWS_VISIBLE LWS_EXTERN struct lws_transcode_ctx *
lws_transcode_decoder_create(enum lws_transcode_codec codec);

LWS_VISIBLE LWS_EXTERN void
lws_transcode_destroy(struct lws_transcode_ctx **ctx);

/*
 * We need to abstract the frame so the user doesn't need to include ffmpeg headers.
 * But for now, we'll just use void * and internal casting.
 */

LWS_VISIBLE LWS_EXTERN void *
lws_transcode_frame_alloc(uint32_t w, uint32_t h);

LWS_VISIBLE LWS_EXTERN void
lws_transcode_frame_free(void **frame);

LWS_VISIBLE LWS_EXTERN int
lws_transcode_decode(struct lws_transcode_ctx *ctx, const uint8_t *buf, size_t len, void *frame);

LWS_VISIBLE LWS_EXTERN int
lws_transcode_encode(struct lws_transcode_ctx *ctx, void *frame, uint8_t **buf, size_t *len);

LWS_VISIBLE LWS_EXTERN void *
lws_transcode_scaler_create(uint32_t src_w, uint32_t src_h, uint32_t dst_w, uint32_t dst_h);

LWS_VISIBLE LWS_EXTERN void
lws_transcode_scaler_destroy(void **sws);

LWS_VISIBLE LWS_EXTERN int
lws_transcode_scale(void *sws, void *src_frame, void *dst_frame);

LWS_VISIBLE LWS_EXTERN void
lws_transcode_yuyv_to_yuv420p(const uint8_t *yuyv, uint8_t *yuv, uint32_t w, uint32_t h);

LWS_VISIBLE LWS_EXTERN int
lws_transcode_mjpeg_to_yuv420p(void *jpeg_dec, const uint8_t *mjpeg, size_t len, uint8_t *yuv, uint32_t w, uint32_t h);

LWS_VISIBLE LWS_EXTERN int
lws_transcode_frame_import_yuv(void *frame, uint8_t *yuv_buf);

LWS_VISIBLE LWS_EXTERN uint8_t **
lws_transcode_frame_get_data(void *frame);

LWS_VISIBLE LWS_EXTERN int *
lws_transcode_frame_get_linesize(void *frame);

LWS_VISIBLE LWS_EXTERN int
lws_transcode_frame_get_width(void *frame);

LWS_VISIBLE LWS_EXTERN int
lws_transcode_frame_get_height(void *frame);

#endif
