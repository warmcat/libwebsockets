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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * lws-io-ops.h: the four requests the sansIO half of lws makes of the IO
 * half.  See READMEs/README.sans-io-split.md, "The interface" and "The
 * headers".
 *
 * sansIO asks IO for exactly these: call my tx when the transport can take
 * bytes, feed or stop feeding my rx, wake me at this deadline, and release
 * my transport.  It asks through the names it always has (
 * lws_callback_on_writable(), lws_rx_flow_control(), lws_set_timeout() and
 * lws_sul_schedule(), lws_close_free_wsi()); at the bottom of each, where
 * the request reaches the transport, it goes through this struct.
 *
 * IO fills it in for the normal build (lws_io_ops_default).  An embedder of
 * the sansIO half alone supplies its own in
 * lws_context_creation_info.io_ops, and a port that returns its requests as
 * polled outputs implements the same four.
 */

typedef struct lws_io_ops {
	int (*want_write)(struct lws *wsi);
	/**< the wsi's transport connection should be written when it can take
	 * bytes: IO will call the wsi's writeable handling then.  wsi is the
	 * connection with the transport (a mux parent, not its stream).
	 * Called with the wsi's service thread lock held.  0 = ok */
	int (*want_read)(struct lws *wsi, int on);
	/**< feed (on) or stop feeding (off) the wsi's rx from its transport.
	 * Called with the wsi's service thread lock held.  0 = ok */
	void (*deadline)(struct lws_context *cx, int tsi, lws_usec_t us);
	/**< the earliest deadline on service thread tsi moved to us (an
	 * absolute lws_now_usecs() time): sansIO must be serviced by then.
	 * A deadline that is cancelled is not announced; a wake that finds
	 * nothing due is harmless.  May be NULL: the built-in event loops
	 * ask what is due each time round instead. */
	void (*close)(struct lws *wsi);
	/**< the wsi is done with its transport: release it (tls session,
	 * fd, its place in the poll set).  Called from the wsi's close path
	 * with the context and vhost locks held. */
} lws_io_ops_t;

/*
 * IO's own: the requests reach the poll set and the socket.  An embedder
 * that only wants to hear the requests takes a copy and wraps the ops it
 * listens to (api-test-sansio does).
 */
LWS_VISIBLE LWS_EXTERN_FOR_DATA const lws_io_ops_t lws_io_ops_default;
