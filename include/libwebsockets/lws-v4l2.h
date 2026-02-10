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

#ifndef __LWS_V4L2_H__
#define __LWS_V4L2_H__

struct lws_v4l2_ctx;

struct lws_v4l2_info {
	const char	*device_path;
	uint32_t	width;
	uint32_t	height;
	uint32_t	pixelformat; /* V4L2_PIX_FMT_... */
};

struct lws_v4l2_control {
	uint32_t	id;
	uint32_t	type;
	char		name[32];
	int32_t		min;
	int32_t		max;
	int32_t		step;
	int32_t		def;
	int32_t		val;
};

typedef int (*lws_v4l2_control_cb)(void *user, const struct lws_v4l2_control *c);

LWS_VISIBLE LWS_EXTERN struct lws_v4l2_ctx *
lws_v4l2_create(const struct lws_v4l2_info *info);

LWS_VISIBLE LWS_EXTERN void
lws_v4l2_destroy(struct lws_v4l2_ctx **ctx);

LWS_VISIBLE LWS_EXTERN int
lws_v4l2_get_buffer(struct lws_v4l2_ctx *ctx, int index, void **start, size_t *len);

LWS_VISIBLE LWS_EXTERN int
lws_v4l2_get_fd(struct lws_v4l2_ctx *ctx);

LWS_VISIBLE LWS_EXTERN int
lws_v4l2_get_info(struct lws_v4l2_ctx *ctx, struct lws_v4l2_info *info);

LWS_VISIBLE LWS_EXTERN int
lws_v4l2_enum_controls(struct lws_v4l2_ctx *ctx, lws_v4l2_control_cb cb, void *user);

LWS_VISIBLE LWS_EXTERN int
lws_v4l2_set_control(struct lws_v4l2_ctx *ctx, uint32_t id, int32_t val);

#endif
