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

#include "private-lib-core.h"

#if defined(LWS_WITH_LATENCY)

LWS_VISIBLE void
lws_latency_cb_start(struct lws_context_per_thread *pt)
{
	lws_usec_t now = lws_now_usecs();

	pt->latency_cb_start = now;

	uint64_t bs = (uint64_t)now / LWS_LATENCY_BUCKET_US;

	if (pt->latency_ring[pt->latency_idx].bucket_start_us != bs) {
		pt->latency_idx = (pt->latency_idx + 1) % LWS_LATENCY_RING_SIZE;
		memset(&pt->latency_ring[pt->latency_idx], 0, sizeof(pt->latency_ring[0]));
		pt->latency_ring[pt->latency_idx].bucket_start_us = bs;
	}
}

LWS_VISIBLE void
lws_latency_cb_end(struct lws_context_per_thread *pt, const char *pn)
{
	lws_usec_t now = lws_now_usecs();
	uint32_t lat_us;
	uint64_t bs;

	if (!pt->latency_cb_start)
		return;

	lat_us = (uint32_t)(now - pt->latency_cb_start);

	pt->latency_last_cb_end = now;
	bs = (uint64_t)now / LWS_LATENCY_BUCKET_US;

	if (pt->latency_ring[pt->latency_idx].bucket_start_us != bs) {
		char temp_req_info[64];
		char temp_anno[64];
		temp_req_info[0] = '\0';
		temp_anno[0] = '\0';

		/* carry over any req_info written during this prolonged callback */
		if (pt->latency_ring[pt->latency_idx].req_info[0])
			lws_strncpy(temp_req_info, pt->latency_ring[pt->latency_idx].req_info, sizeof(temp_req_info));

		if (pt->latency_ring[pt->latency_idx].annotation[0])
			lws_strncpy(temp_anno, pt->latency_ring[pt->latency_idx].annotation, sizeof(temp_anno));

		pt->latency_idx = (pt->latency_idx + 1) % LWS_LATENCY_RING_SIZE;
		memset(&pt->latency_ring[pt->latency_idx], 0, sizeof(pt->latency_ring[0]));
		pt->latency_ring[pt->latency_idx].bucket_start_us = bs;

		if (temp_req_info[0])
			lws_strncpy(pt->latency_ring[pt->latency_idx].req_info, temp_req_info, sizeof(pt->latency_ring[0].req_info));
		if (temp_anno[0])
			lws_strncpy(pt->latency_ring[pt->latency_idx].annotation, temp_anno, sizeof(pt->latency_ring[0].annotation));
	}

	pt->latency_ring[pt->latency_idx].lat_us += lat_us;
	if (lat_us > pt->latency_ring[pt->latency_idx].worst_lat_us) {
		pt->latency_ring[pt->latency_idx].worst_lat_us = lat_us;
		lws_strncpy(pt->latency_ring[pt->latency_idx].worst_protocol,
			    pn ? pn : "none",
			    sizeof(pt->latency_ring[0].worst_protocol));
		lwsl_timestamp(LLL_LATENCY,
			       pt->latency_ring[pt->latency_idx].worst_time,
			       sizeof(pt->latency_ring[0].worst_time));
	}
	pt->latency_ring[pt->latency_idx].events++;
}

int
lws_latency_get_json(struct lws_context *context, int tsi, uint64_t since_us,
		     char *buf, size_t max_len)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	char *p = buf, *end = buf + max_len - 1;
	int count = 0, first = 1;
	uint32_t old = pt->latency_idx;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"buckets\":[");

	/* We want to walk the ring forward from oldest to newest */
	for (uint32_t n = 0; n < LWS_LATENCY_RING_SIZE; n++) {
		uint32_t i = (old + 1 + n) % LWS_LATENCY_RING_SIZE;
		lws_latency_bucket_t *b = &pt->latency_ring[i];

		if (!b->bucket_start_us)
			continue;

		uint64_t bs_us = b->bucket_start_us * LWS_LATENCY_BUCKET_US;
		if (since_us && bs_us <= since_us)
			continue;

		if (!first)
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",");
		first = 0;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"start\":%llu,\"lat\":%u,\"wrst\":%u,\"ev\":%u,"
			  "\"req_info\":\"%s\","
			  "\"anno\":\"%s\","
			  "\"proto\":\"%s\",\"ts\":\"%s\"}",
			  (unsigned long long)bs_us,
			  b->lat_us, b->worst_lat_us, b->events,
			  b->req_info[0] ? b->req_info : "",
			  b->annotation[0] ? b->annotation : "",
			  b->worst_protocol[0] ? b->worst_protocol : "none",
			  b->worst_time[0] ? b->worst_time : "-");
		count++;
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");
	return count;
}
#endif
