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

#ifndef __LWS_ALSA_H__
#define __LWS_ALSA_H__

struct lws_alsa_ctx;

struct lws_alsa_info {
	const char	*device_name; /* e.g. "default" */
	uint32_t	rate;
	uint32_t	channels;
	uint32_t	samples_per_frame;
};

struct lws_alsa_control {
	uint32_t	id;
	char		name[64];
	long		min;
	long		max;
	long		step;
	long		val;
};

typedef int (*lws_alsa_control_cb)(void *user, const struct lws_alsa_control *c);

LWS_VISIBLE LWS_EXTERN struct lws_alsa_ctx *
lws_alsa_create_capture(const struct lws_alsa_info *info);

LWS_VISIBLE LWS_EXTERN void
lws_alsa_destroy(struct lws_alsa_ctx **ctx);

LWS_VISIBLE LWS_EXTERN int
lws_alsa_get_fd(struct lws_alsa_ctx *ctx);

LWS_VISIBLE LWS_EXTERN int
lws_alsa_read(struct lws_alsa_ctx *ctx, void *buf, size_t samples);

LWS_VISIBLE LWS_EXTERN int
lws_alsa_enum_controls(struct lws_alsa_ctx *ctx, lws_alsa_control_cb cb, void *user);

LWS_VISIBLE LWS_EXTERN int
lws_alsa_set_control(struct lws_alsa_ctx *ctx, uint32_t id, long val);

#endif
