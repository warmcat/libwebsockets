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

/*
 * Stats are all uint64_t numbers that start at 0.
 * Index names here have the convention
 *
 *  _C_ counter
 *  _B_ byte count
 *  _MS_ millisecond count
 */

enum {
	LWSSTATS_C_CONNECTIONS, /**< count incoming connections */
	LWSSTATS_C_API_CLOSE, /**< count calls to close api */
	LWSSTATS_C_API_READ, /**< count calls to read from socket api */
	LWSSTATS_C_API_LWS_WRITE, /**< count calls to lws_write API */
	LWSSTATS_C_API_WRITE, /**< count calls to write API */
	LWSSTATS_C_WRITE_PARTIALS, /**< count of partial writes */
	LWSSTATS_C_WRITEABLE_CB_REQ, /**< count of writable callback requests */
	LWSSTATS_C_WRITEABLE_CB_EFF_REQ, /**< count of effective writable callback requests */
	LWSSTATS_C_WRITEABLE_CB, /**< count of writable callbacks */
	LWSSTATS_C_SSL_CONNECTIONS_FAILED, /**< count of failed SSL connections */
	LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED, /**< count of accepted SSL connections */
	LWSSTATS_C_SSL_ACCEPT_SPIN, /**< count of SSL_accept() attempts */
	LWSSTATS_C_SSL_CONNS_HAD_RX, /**< count of accepted SSL conns that have had some RX */
	LWSSTATS_C_TIMEOUTS, /**< count of timed-out connections */
	LWSSTATS_C_SERVICE_ENTRY, /**< count of entries to lws service loop */
	LWSSTATS_B_READ, /**< aggregate bytes read */
	LWSSTATS_B_WRITE, /**< aggregate bytes written */
	LWSSTATS_B_PARTIALS_ACCEPTED_PARTS, /**< aggreate of size of accepted write data from new partials */
	LWSSTATS_US_SSL_ACCEPT_LATENCY_AVG, /**< aggregate delay in accepting connection */
	LWSSTATS_US_WRITABLE_DELAY_AVG, /**< aggregate delay between asking for writable and getting cb */
	LWSSTATS_US_WORST_WRITABLE_DELAY, /**< single worst delay between asking for writable and getting cb */
	LWSSTATS_US_SSL_RX_DELAY_AVG, /**< aggregate delay between ssl accept complete and first RX */
	LWSSTATS_C_PEER_LIMIT_AH_DENIED, /**< number of times we would have given an ah but for the peer limit */
	LWSSTATS_C_PEER_LIMIT_WSI_DENIED, /**< number of times we would have given a wsi but for the peer limit */
	LWSSTATS_C_CONNS_CLIENT, /**< attempted client conns */
	LWSSTATS_C_CONNS_CLIENT_FAILED, /**< failed client conns */

	/* Add new things just above here ---^
	 * This is part of the ABI, don't needlessly break compatibility
	 *
	 * UPDATE stat_names in stats.c in sync with this!
	 */
	LWSSTATS_SIZE
};

#if defined(LWS_WITH_STATS)

LWS_VISIBLE LWS_EXTERN uint64_t
lws_stats_get(struct lws_context *context, int index);
LWS_VISIBLE LWS_EXTERN void
lws_stats_log_dump(struct lws_context *context);
#else
static LWS_INLINE uint64_t
lws_stats_get(struct lws_context *context, int index) { (void)context; (void)index;  return 0; }
static LWS_INLINE void
lws_stats_log_dump(struct lws_context *context) { (void)context; }
#endif
