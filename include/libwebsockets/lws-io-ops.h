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
 * lws-io-ops.h: the requests the sansIO half of lws makes of the IO half.
 * See READMEs/README.sans-io-split.md, "The interface" and "The headers".
 *
 * sansIO asks IO for exactly these: call my tx when the transport can take
 * bytes, feed or stop feeding my rx, wake me at this deadline, and release
 * my transport.  It asks through the names it always has (
 * lws_callback_on_writable(), lws_rx_flow_control(), lws_set_timeout() and
 * lws_sul_schedule(), lws_close_free_wsi()); at the bottom of each, where
 * the request reaches the transport, it goes through this struct.  Two more
 * are about the transport itself: a datagram connection's path moved, and
 * a connection moved to another wsi.
 *
 * IO fills it in for the normal build (lws_io_ops_default).  An embedder of
 * the sansIO half alone supplies its own in
 * lws_context_creation_info.io_ops, and a port that returns its requests as
 * polled outputs implements the same.
 */

/*
 * The close request reaches the transport in phases, in this order over a
 * connection's close: not every close has every phase
 */
enum lws_io_close_phase {
	LWS_IOCLOSE_QUIESCE,	/* nothing of the transport's may act on the
				 * wsi any more: connect attempts and their
				 * timers, dns, the wait for a socket */
	LWS_IOCLOSE_UNWATCH,	/* a restart follows: stop watching the
				 * transport, keep it for the release */
	LWS_IOCLOSE_SHUTDOWN,	/* stop sending: a tls close_notify when there
				 * is a session, else the write side */
	LWS_IOCLOSE_STAGE,	/* keep the transport until the peer has
				 * finished, and say when it has */
	LWS_IOCLOSE_RELEASE,	/* release it all: tls session, fd, its place
				 * in the poll set */
};

/*
 * A datagram connection's path: which address its datagrams go to is its
 * protocol's decision (quic's connection migration, RFC 9000 9); the socket
 * that reaches it is IO's
 */
enum lws_io_path_op {
	LWS_IOPATH_COMMIT,	/* the peer is at this address now: report it
				 * as the connection's peer, and aim a
				 * connected socket there if it is not */
	LWS_IOPATH_NEW_SOCKET,	/* move onto a fresh socket (a new local
				 * port) connected to this address, closing
				 * the old; the reported peer is unchanged */
};

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
	int (*close)(struct lws *wsi, int phase);
	/**< the wsi's transport is closing, by enum lws_io_close_phase.
	 * QUIESCE, UNWATCH and RELEASE return 0.  SHUTDOWN returns 1 when
	 * the tls shutdown wants more service (the close re-enters as the
	 * transport becomes readable or writable), 2 when it has wanted that
	 * too often and will not complete, 0 when the write side is shut,
	 * -1 when the shutdown failed.  STAGE returns 1 when the transport
	 * can be kept until the peer finishes, so the close continues when
	 * the peer's end arrives through rx, 0 when it cannot.  Called from
	 * the wsi's close path with the context and vhost locks held. */
	int (*path)(struct lws *wsi, int op, const union lws_sockaddr46 *peer);
	/**< the datagram connection wsi's path changed, by enum
	 * lws_io_path_op.  wsi is the connection, which on a server shares
	 * its listener's socket: there is nothing to aim, and COMMIT only
	 * records the peer.  A wsi on a transport (lws_set_transport()) has no
	 * socket either.  Called without the service thread lock.  0 = ok,
	 * nonzero when the socket could not be aimed or made: after a failed
	 * NEW_SOCKET the old socket is still in place if the new one could
	 * not be opened, else the wsi is left with none.  May be NULL when no
	 * datagram connection is carried. */
	int (*transfer)(struct lws *from, struct lws *to);
	/**< the connection sansIO knew as from goes on as to (a quic
	 * connection leaving the wsi that dialled it for its own network
	 * wsi, a kept-warm connection joining the wsi that queued on it):
	 * the socket, its place in the poll set, its event-loop watcher and
	 * its tls session move to to.  Called with or without the service
	 * thread lock.  0 = ok, nonzero when to could not take them: what
	 * could be handed on is to's, and goes when to is closed. */
} lws_io_ops_t;

/*
 * IO's own: the requests reach the poll set and the socket.  An embedder
 * that only wants to hear the requests takes a copy and wraps the ops it
 * listens to (api-test-sansio does).
 */
LWS_VISIBLE LWS_EXTERN_FOR_DATA const lws_io_ops_t lws_io_ops_default;
