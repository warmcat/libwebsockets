/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

int
lws_det_lat_active(struct lws_context *context)
{
	return !!context->detailed_latency_cb;
}

int
lws_det_lat_cb(struct lws_context *context, lws_detlat_t *d)
{
	int n;

	if (!context->detailed_latency_cb)
		return 0;

	n = context->detailed_latency_cb(context, d);

	memset(&d->latencies, 0, sizeof(d->latencies));

	return n;
}

static const char types[] = "rwNCTt????";
int
lws_det_lat_plot_cb(struct lws_context *context, const lws_detlat_t *d)
{
	char buf[80], *p = buf, *end = &p[sizeof(buf) - 1];

	if (!context->detailed_latency_filepath)
		return 1;

	if (context->latencies_fd == -1) {
		context->latencies_fd = open(context->detailed_latency_filepath,
				LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);
		if (context->latencies_fd == -1)
			return 1;
	}

	p += lws_snprintf(p, lws_ptr_diff(end, p),
			  "%llu %c %u %u %u %u %u %zu %zu\n",
			  (unsigned long long)lws_now_usecs(), types[d->type],
			  d->latencies[LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE],
			  d->latencies[LAT_DUR_PROXY_CLIENT_WRITE_TO_PROXY_RX],
			  d->latencies[LAT_DUR_PROXY_PROXY_REQ_TO_WRITE],
			  d->latencies[LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE] +
			  d->latencies[LAT_DUR_PROXY_CLIENT_WRITE_TO_PROXY_RX] +
			  d->latencies[LAT_DUR_PROXY_PROXY_REQ_TO_WRITE],
			  d->latencies[LAT_DUR_PROXY_RX_TO_ONWARD_TX],
			  d->acc_size, d->req_size);

	write(context->latencies_fd, buf, lws_ptr_diff(p, buf));

	return 0;
}
