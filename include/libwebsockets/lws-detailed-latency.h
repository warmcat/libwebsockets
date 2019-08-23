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
 *
 * included from libwebsockets.h
 */

enum {

	/* types of latency, all nonblocking except name resolution */

	LDLT_READ,	/* time taken to read LAT_DUR_PROXY_RX_TO_CLIENT_WRITE */
	LDLT_WRITE,
	LDLT_NAME_RESOLUTION, /* BLOCKING: LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE */
	LDLT_CONNECTION, /* conn duration: LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE */
	LDLT_TLS_NEG_CLIENT, /* tls conn duration: LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE */
	LDLT_TLS_NEG_SERVER, /* tls conn duration: LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE */

	LDLT_USER,

	/* interval / duration elements in latencies array */

	LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE				= 0,
		/* us the client spent waiting to write to proxy */
	LAT_DUR_PROXY_CLIENT_WRITE_TO_PROXY_RX,
		/* us the packet took to be received by proxy */
	LAT_DUR_PROXY_PROXY_REQ_TO_WRITE,
		/* us the proxy has to wait before it could write */
	LAT_DUR_PROXY_RX_TO_ONWARD_TX,
		/* us the proxy spent waiting to write to destination, or
		 * if nonproxied, then time between write request and write */

	LAT_DUR_USERCB, /* us duration of user callback */

	LAT_DUR_STEPS /* last */
};

typedef struct lws_detlat {
	lws_usec_t		earliest_write_req;
	lws_usec_t		earliest_write_req_pre_write;
		/**< use this for interval comparison */
	const char		*aux; /* name for name resolution timing */
	int			type;
	uint32_t		latencies[LAT_DUR_STEPS];
	size_t			req_size;
	size_t			acc_size;
} lws_detlat_t;

typedef int (*det_lat_buf_cb_t)(struct lws_context *context,
				const lws_detlat_t *d);

/**
 * lws_det_lat_cb() - inject your own latency records
 *
 * \param context: the lws_context
 * \param d: the lws_detlat_t you have prepared
 *
 * For proxying or similar cases where latency information is available from
 * user code rather than lws itself, you can generate your own latency callback
 * events with your own lws_detlat_t.
 */

LWS_VISIBLE LWS_EXTERN int
lws_det_lat_cb(struct lws_context *context, lws_detlat_t *d);

/*
 * detailed_latency_plot_cb() - canned save to file in plottable format cb
 *
 * \p context: the lws_context
 * \p d: the detailed latency event information
 *
 * This canned callback makes it easy to export the detailed latency information
 * to a file.  Just set the context creation members like this
 *
 * #if defined(LWS_WITH_DETAILED_LATENCY)
 *	info.detailed_latency_cb = lws_det_lat_plot_cb;
 *	info.detailed_latency_filepath = "/tmp/lws-latency-results";
 * #endif
 *
 * and you will get a file containing information like this
 *
 * 718823864615 N 10589 0 0 10589 0 0 0
 * 718823880837 C 16173 0 0 16173 0 0 0
 * 718823913063 T 32212 0 0 32212 0 0 0
 * 718823931835 r 0 0 0 0 232 30 256
 * 718823948757 r 0 0 0 0 40 30 256
 * 718823948799 r 0 0 0 0 83 30 256
 * 718823965602 r 0 0 0 0 27 30 256
 * 718823965617 r 0 0 0 0 43 30 256
 * 718823965998 r 0 0 0 0 12 28 256
 * 718823983887 r 0 0 0 0 74 3 4096
 * 718823986411 w 16 87 7 110 9 80 80
 * 718824006358 w 8 68 6 82 6 80 80
 *
 * which is easy to grep and pass to gnuplot.
 *
 * The columns are
 *
 *  - unix time in us
 *  - N = Name resolution, C = TCP Connection, T = TLS negotiation server,
 *    t = TLS negotiation client, r = Read, w = Write
 *  - us duration, for w time client spent waiting to write
 *  - us duration, for w time data spent in transit to proxy
 *  - us duration, for w time proxy waited to send data
 *  - as a convenience, sum of last 3 columns above
 *  - us duration, time spent in callback
 *  - last 2 are actual / requested size in bytes
 */
LWS_VISIBLE LWS_EXTERN int
lws_det_lat_plot_cb(struct lws_context *context, const lws_detlat_t *d);

/**
 * lws_det_lat_active() - indicates if latencies are being measured
 *
 * \context: lws_context
 *
 * Returns 0 if latency measurement has not been set up (the callback is NULL).
 * Otherwise returns 1
 */
LWS_VISIBLE LWS_EXTERN int
lws_det_lat_active(struct lws_context *context);
