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

#if !defined(__LWS_LATENCY_H__)
#define __LWS_LATENCY_H__

#if defined(LWS_WITH_LATENCY)

#define LWS_LATENCY_BUCKET_US (100000) /* 100ms buckets */
#define LWS_LATENCY_RING_SIZE (200)    /* 20 seconds total history */

typedef struct lws_latency_bucket {
	uint64_t	bucket_start_us;
	uint32_t	lat_us;
	uint32_t	worst_lat_us;
	uint32_t	events;
	char		req_info[64];
	char		annotation[64];
	char		worst_protocol[32];
	char		worst_time[32];
} lws_latency_bucket_t;

LWS_VISIBLE LWS_EXTERN int
lws_latency_get_json(struct lws_context *context, int tsi, uint64_t since_us,
		     char *buf, size_t max_len);

struct lws_context_per_thread;

LWS_VISIBLE LWS_EXTERN void
lws_latency_cb_start(struct lws_context_per_thread *pt);

LWS_VISIBLE LWS_EXTERN void
lws_latency_cb_end(struct lws_context_per_thread *pt, const char *pn);

#endif /* LWS_WITH_LATENCY */
#endif
