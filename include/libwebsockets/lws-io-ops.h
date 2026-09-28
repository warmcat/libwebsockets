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
 * the request reaches the transport, it goes through this struct.  The rest
 * are about the transport and its object themselves: a datagram
 * connection's path moved, a connection object was made, and a connection
 * moved to another object.
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
	LWS_IOCLOSE_UNWATCH,	/* stop watching the transport, keep it for
				 * the release (a restart follows, or a
				 * file's user hears it close first) */
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
	 * QUIESCE returns 1 when the wsi was still waiting for its socket
	 * (for dns, or for the fd budget): its user was never told it
	 * existed, so the close owes it the close callback; else 0.
	 * UNWATCH and RELEASE return 0.  SHUTDOWN returns 1 when
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
	void (*created)(struct lws *wsi);
	/**< a connection object was just made: IO sets up its half of it, as
	 * having no transport yet (no socket, no place in the poll set).
	 * Its end is the close's RELEASE, and a move to another object is
	 * transfer.  May be NULL when the embedder's IO keeps nothing of its
	 * own in the object. */
	int (*transfer)(struct lws *from, struct lws *to);
	/**< the connection sansIO knew as from goes on as to (a quic
	 * connection leaving the wsi that dialled it for its own network
	 * wsi, a kept-warm connection joining the wsi that queued on it):
	 * the socket, its place in the poll set, its event-loop watcher and
	 * its tls session move to to.  Called with or without the service
	 * thread lock.  0 = ok, nonzero when to could not take them: what
	 * could be handed on is to's, and goes when to is closed. */

	/*
	 * tx: the transport taking sansIO's bytes
	 */

	int (*tx_push)(struct lws *wsi, unsigned char *buf, size_t len);
	/**< tx, in its push spelling: take these bytes for wsi's transport
	 * now.  IO takes them all, keeping what the transport does not take
	 * at once and sending it first when it can, and returns len; -1 when
	 * the transport failed.  buf NULL continues such a partial, returning
	 * what of it went.  What sansIO produces when IO asks is the pull (the
	 * role's tx op); the push is for what the app's writeable pass hands
	 * lws_write(), framed in place in its LWS_PRE headroom so it is not
	 * copied, and the one-shot messages of the proxy legs (socks, http
	 * CONNECT) composed at a state change.  Called on the wsi's service
	 * thread. */
	void (*tx_now)(struct lws *wsi);
	/**< the datagram connection wsi has datagrams that must go now, not
	 * on its next writeable pass (a closing quic connection's
	 * CONNECTION_CLOSE): IO pulls its tx now.  May be NULL when no
	 * datagram connection is carried. */
	int (*tx_choked)(struct lws *wsi);
	/**< would the transport under wsi, the connection owning it, not
	 * take bytes now?  1 if a write would block, else 0.  What sansIO
	 * holds itself (a partial send, a compression remainder, frames
	 * waiting for tx credit) it has already answered for:
	 * lws_send_pipe_choked() asks this last. */
	int (*tx_file)(struct lws *wsi);
	/**< the server wsi is sending a file: while the transport takes more,
	 * ask the file for its next payload (lws_http_file_tx()) and write it,
	 * and when it is done and nothing of it is left buffered, complete the
	 * response.  <0 the wsi should be closed, >0 the file was sent and its
	 * completion delivered, 0 more is to be sent on a later writeable
	 * pass.  IO's is lws_serve_http_file_fragment().  May be NULL in a
	 * build without files (LWS_WITH_FILE_OPS) or server. */

	/*
	 * service: sansIO's handling of a connection, run now
	 */

	int (*service_writable)(struct lws *wsi);
	/**< want_write served now rather than on the next turn of the loop:
	 * service wsi as though its transport had just said it can take
	 * bytes, so a role gets its first protocol write out in the same call
	 * that saw the transport come up.  0 ok, -1 failed, 1 the wsi was
	 * closed in the service. */
	int (*service_now)(struct lws *wsi);
	/**< service wsi now as though its transport had rx pending, for a
	 * role that already holds bytes for it (a pipelined request that got
	 * its header table).  <0 failed, 1 the wsi was closed in the service,
	 * 0 otherwise; a wsi with no transport yet gets 0. */
	void (*wake)(struct lws *wsi);
	/**< make sure wsi's service thread comes round its loop soon, without
	 * waiting for its transport or a deadline: sansIO left work for the
	 * pass that runs at the top of each turn for connections holding
	 * buffered rx.  Callable with the service thread lock held. */

	/*
	 * rx at the app's pace
	 */

	int (*http_client_read)(struct lws *wsi, char **buf, int *len);
	/**< the app pulls its client response body: read from wsi's
	 * transport what fits the app's buffer, *buf of *len (or, with *buf
	 * NULL, IO's own), and hand it to sansIO's body rx, which delivers
	 * the payload to the app; *buf and *len are left describing what was
	 * read.  0 ok, -1 the connection failed.  IO's is
	 * lws_http_client_read().  May be NULL in a build without an http
	 * client. */
} lws_io_ops_t;

/*
 * IO's own: the requests reach the poll set and the socket.  An embedder
 * that only wants to hear the requests takes a copy and wraps the ops it
 * listens to (api-test-sansio does).
 */
LWS_VISIBLE LWS_EXTERN_FOR_DATA const lws_io_ops_t lws_io_ops_default;
