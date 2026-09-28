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
 *
 * output.c: the app's tx, as sansIO takes it.  lws_write() hands the role
 * the app's payload to frame in place, in its LWS_PRE headroom, and the
 * framed bytes go to IO with the push (lws_io_tx_push()).
 * lws_send_pipe_choked() answers for what sansIO holds itself, then asks IO
 * about the transport.  See READMEs/README.sans-io-split.md.
 */

#include "private-lib-core.h"

int
lws_write(struct lws *wsi, unsigned char *buf, size_t len,
	  enum lws_write_protocol wp)
{
	int m;

	if ((int)len < 0) {
		lwsl_wsi_err(wsi, "suspicious len int %d, ulong %lu",
				  (int)len, (unsigned long)len);
		return -1;
	}

#ifdef LWS_WITH_ACCESS_LOG
	wsi->stream.access_log.sent += len;
#endif

	assert(wsi->role_ops);

	if (!lws_rops_fidx(wsi->role_ops, LWS_ROPS_write_role_protocol))
		m = lws_io_tx_push(wsi, buf, len);
	else
		m = lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_write_role_protocol).
				write_role_protocol(wsi, buf, len, &wp);

#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->a.vhost)
		lws_metric_event(wsi->a.vhost->mt_traffic_tx, (char)
				 (m < 0 ? METRES_NOGO : METRES_GO), len);
#endif

	return m;
}

int
lws_send_pipe_choked(struct lws *wsi)
{
	struct lws *wsi_eff;

#if !defined(LWS_WITHOUT_EXTENSIONS)
	if (wsi->ws && wsi->ws->tx_draining_ext)
		return 1;
#endif

#if defined(LWS_WITH_HTTP2)
	wsi_eff = lws_wsi_socket_owner(wsi);

	/*
	 * ws-over-h2: whole DATA frames parked on the stream awaiting h2
	 * tx credit (see lws_h2_frame_write) mean the pipe is choked for
	 * this stream even though the network wsi could accept bytes.
	 * Only a partial send chokes it: an h3 stream's frames in quic's
	 * queue or in flight are quic's, which throttles the stream by its
	 * tx credit; waiting on their acks here allowed one write per round
	 * trip.
	 */
	if (wsi_eff != wsi && lws_has_buflist_out(wsi))
		return 1;
#else
	wsi_eff = wsi;
#endif

	/* treat the fact we got a truncated send pending as if we're choked */
	if (lws_has_buffered_out(wsi_eff)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    || wsi->http.comp_ctx.buflist_comp ||
	       wsi->http.comp_ctx.may_have_more
#endif
	    )
		return 1;

	/* then whether the transport would take another write without blocking */

	return lws_io_tx_choked(wsi_eff);
}
