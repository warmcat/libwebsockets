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
 * sansIO asks IO for exactly these, and nothing else: the four requests
 * of the loop (call my tx when the transport can take bytes, feed or stop
 * feeding my rx, the earliest deadline moved, release my transport), which
 * it spells as it always has (lws_callback_on_writable(),
 * lws_rx_flow_control(), lws_set_timeout() and lws_sul_schedule(),
 * lws_close_free_wsi()) and which reach this struct at the bottom; the
 * connection object's (made, moved to another object, its datagram path);
 * and, grouped below by theme, the client transport, the tls session, tx,
 * service, the app's rx pull and the vhost.  The platform's clock and
 * random source, lws_now_usecs() and lws_get_random(), are dependencies
 * rather than requests.  What sansIO asks of features lws' own IO provides
 * (a cgi child process, a jit-trust vhost) is not here: no other IO
 * supplies them, and they are private to lws.  README.sans-io-split.md,
 * "The contract", lists them.
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

struct lws_client_connect_info;

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
	 * the transport: a client's, as its protocol decides about it, and
	 * what IO knows of a connection's peer
	 */

	struct lws *(*transport_start)(struct lws *wsi);
	/**< the client wsi's request is ready to go (it waited for its header
	 * table and has it): start its transport, dns first.  Returns wsi, or
	 * NULL when it failed and wsi was closed and freed. */
	int (*transport_connected)(struct lws *wsi);
	/**< the socks or http CONNECT leg the client wsi's role ran over the
	 * raw transport is done, the tunnel is up: carry on with the
	 * transport (tls, if it has it, then the role hears the transport is
	 * up).  0 ok, -1 failed and the wsi should be closed. */
	void (*transport_established)(struct lws *wsi);
	/**< the client wsi's role made its transport inside its own protocol
	 * (quic's handshake completed): it won any race for the connection,
	 * so drop what else was trying to be it (the tcp connects racing it,
	 * their timers, the h3 grace). */
	int (*transport_failed)(struct lws *wsi);
	/**< such a role's transport failed before it was up: retarget the
	 * connection if possible (the next dns result, then tcp instead of
	 * udp) and return 1, else 0 and the close goes on.  May be NULL when
	 * no such role is carried. */
	struct lws *(*client_connect)(const struct lws_client_connect_info *i);
	/**< make a new client connection, as the public
	 * lws_client_connect_via_info() does, which is IO's: the http server
	 * asks for the onward leg of a proxied transaction.  Returns the new
	 * wsi or NULL.  May be NULL without http proxying. */
	const char *(*peer_address)(struct lws *wsi, char *buf, size_t len);
	/**< the address of wsi's peer, as numeric text into buf of len
	 * (a mux stream's is its network connection's), returning buf.  IO's
	 * is lws_get_peer_simple().  May be NULL: sansIO then says
	 * "unknown". */

#if defined(LWS_WITH_TLS)
	/*
	 * the tls session, which is IO's: what sansIO asks of it.  Only in a
	 * build with tls.
	 */

	void *(*tls_session)(struct lws *wsi);
	/**< the tls library's session object for wsi's connection, handed to
	 * the user with the ESTABLISHED callbacks, or NULL when it has none.
	 * May be NULL: no connection has a session. */
	const uint8_t *(*tls_hs_ca_id)(struct lws *wsi);
	/**< which CA store verified the peer's certificate in wsi's server
	 * handshake (the id of the vhost's client CA it was made with), for
	 * binding an mTLS connection only to vhosts trusting that CA; NULL
	 * when nothing was recorded.  May be NULL. */
	int (*tls_peer_cert_info)(struct lws *wsi, enum lws_tls_cert_info type,
				  union lws_tls_cert_info_results *buf,
				  size_t len);
	/**< information of type from the peer's certificate on wsi's
	 * connection into buf, as the public lws_tls_peer_cert_info(), which
	 * is IO's.  0 ok, nonzero when there is none.  May be NULL: there is
	 * never any. */

	/* quic runs the tls handshake inside its own packets */

	int (*tls_quic_session)(struct lws *wsi, lws_tls_quic_secret_cb cb);
	/**< make the quic connection wsi's tls session, set up for quic: cb
	 * is called with each traffic secret as the handshake derives it.  A
	 * client's is made when its transport is up, a server's when the
	 * connection's first Initial arrives; a server vhost without tls has
	 * none to make.  0 ok, -1 it could not be made. */
	int (*tls_quic_handshake)(struct lws *wsi, int level, const uint8_t *in,
				  size_t in_len, uint8_t *out, size_t *out_len);
	/**< feed in, the handshake bytes of CRYPTO frames at encryption
	 * level, to wsi's session and advance the handshake; with out, what
	 * it has to send next is put there, *out_len being its size on entry
	 * and what was written on return.  IO's is the public
	 * lws_tls_quic_advance_handshake(): <0 the handshake failed. */
	int (*tls_quic_set_tp)(struct lws *wsi, const uint8_t *tp, size_t tp_len);
	/**< set the quic transport parameters extension wsi's handshake will
	 * carry.  0 ok. */
	int (*tls_quic_get_tp)(struct lws *wsi, const uint8_t **tp,
			       size_t *tp_len);
	/**< point *tp at the peer's quic transport parameters from the
	 * handshake, *tp_len long.  0 ok, nonzero when there are none yet. */
	int (*tls_confirm_peer_cert)(struct lws *wsi, char *ebuf,
				     size_t ebuf_len);
	/**< the client quic connection wsi's handshake is done: is the
	 * server's certificate acceptable under its LCCSCF_ flags, as tls
	 * over tcp decides it.  0 yes, else nonzero with the reason in
	 * ebuf. */
	int (*tls_quic_aead)(struct lws *wsi);
	/**< the packet protection AEAD wsi's handshake negotiated, an enum
	 * lws_tls_quic_aead. */
	int (*tls_quic_alert)(struct lws *wsi);
	/**< the tls alert wsi's failed handshake raised, for quic's
	 * CONNECTION_CLOSE, or 0. */
	int (*tls_quic_alpn)(struct lws *wsi, char *buf, size_t len);
	/**< the alpn wsi's handshake selected: 1 with it copied into buf of
	 * len, 0 when there is none. */
#endif

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
	int (*flag_pending_rx)(struct lws *wsi);
	/**< mark wsi as having rx pending, so the service pass running now
	 * services it without waiting on its transport: for a role holding
	 * bytes it has not finished with (ws extension data still draining).
	 * Called from the role's service_flag_pending op with the service
	 * thread lock held.  1 the wsi is watched for rx and will be
	 * serviced, else 0. */
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

	/*
	 * the vhost and the context: a vhost's creation and destruction are
	 * IO's, and so is the process the context runs in
	 */

	int (*finalize_startup)(struct lws_context *cx, const char *where);
	/**< every vhost's protocols have had their first init and none asked
	 * to keep them (LWS_SERVER_OPTION_VH_SKIP_PRIV_DROP): the process may
	 * drop its initial privileges now, as the public
	 * lws_finalize_startup(), which is IO's, does.  where names the
	 * caller for the log.  0 ok, nonzero failed.  May be NULL: there are
	 * no privileges to drop. */

	void (*vhost_destroy)(struct lws_vhost *vh);
	/**< the last connection bound to vh, which is being destroyed, went:
	 * finish destroying it (its protocols' destroy callbacks, its listen
	 * sockets, its tls contexts, its memory).  Called with the context
	 * lock held. */
} lws_io_ops_t;

/*
 * IO's own: the requests reach the poll set and the socket.  An embedder
 * that only wants to hear the requests takes a copy and wraps the ops it
 * listens to (api-test-sansio does).
 */
LWS_VISIBLE LWS_EXTERN_FOR_DATA const lws_io_ops_t lws_io_ops_default;
