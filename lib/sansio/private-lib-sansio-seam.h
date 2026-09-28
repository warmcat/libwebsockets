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
 * private-lib-sansio-seam.h: the sansIO half's requests of IO, as sansIO
 * code spells them (README.sans-io-split.md, "The interface").  Each is a
 * call through the context's lws_io_ops_t (include/libwebsockets/lws-io-ops.h),
 * which IO fills in with lws_io_ops_default and an embedder of the sansIO half
 * with its own, so the sansIO objects reference nothing of IO's for them.
 *
 * The wrappers are for the sansIO sources, which compile with
 * LWS_SANSIO_CHECK: they keep the names the requests always had, so the call
 * sites do not change.  IO's own implementations of the same names, and
 * their prototypes (private-lib-io.h), are what every other source sees and
 * what lws_io_ops_default points to.  A request whose IO implementation is
 * public api is spelled lws_io_...() here.
 *
 * Requests not yet converted are still plain prototypes below, visible to
 * both halves.  The public spellings of the others (lws_callback_on_writable(),
 * lws_set_timeout(), lws_sul_schedule(), lws_rx_flow_control(),
 * lws_close_free_wsi(), lws_write()) are visible as public api.
 */

#if !defined(__LWS_PRIVATE_LIB_SANSIO_SEAM_H__)
#define __LWS_PRIVATE_LIB_SANSIO_SEAM_H__

#if defined(LWS_SANSIO_CHECK)

/*
 * tx (lws_io_ops_t tx_push, tx_now, tx_choked, tx_file)
 */

/* tx, in its push spelling: lws_io_ops_t.tx_push */
static LWS_INLINE int LWS_WARN_UNUSED_RESULT
lws_io_tx_push(struct lws *wsi, unsigned char *buf, size_t len)
{
	return wsi->a.context->io_ops->tx_push(wsi, buf, len);
}

#if defined(LWS_WITH_UDP)
/* a datagram connection's tx, now: lws_io_ops_t.tx_now */
static LWS_INLINE void
lws_io_tx_now(struct lws *wsi)
{
	if (wsi->a.context->io_ops->tx_now)
		wsi->a.context->io_ops->tx_now(wsi);
}
#endif

/*
 * whether the transport under wsi, the connection owning it, would not take
 * bytes now: lws_io_ops_t.tx_choked, for lws_send_pipe_choked()
 */
static LWS_INLINE int
lws_io_tx_choked(struct lws *wsi)
{
	return wsi->a.context->io_ops->tx_choked(wsi);
}

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_FILE_OPS)
/*
 * drive the wsi's file into the transport while it takes more:
 * lws_io_ops_t.tx_file, IO's lws_serve_http_file_fragment()
 */
static LWS_INLINE int
lws_io_tx_file(struct lws *wsi)
{
	return wsi->a.context->io_ops->tx_file(wsi);
}
#endif

#endif /* LWS_SANSIO_CHECK */

#if defined(LWS_WITH_CGI)
/*
 * An http transaction's cgi is a child process IO runs for it: its request
 * body is written to the child's stdin, and the child's end of it closed,
 * as sansIO says; the child is killed, and it and its pipes released, when
 * the transaction is done with it
 */
struct lws_cgi_args;
int
lws_cgi_stdin_write(struct lws_cgi_args *args);
void
lws_cgi_stdin_body_end(struct lws *wsi);
void
lws_cgi_remove_and_kill(struct lws *wsi);
void
lws_cgi_release(struct lws *wsi);
#endif

/* the connection's peer, as IO knows it, as text ("unknown" if none) */
void
lws_io_peer_address(struct lws *wsi, char *buf, size_t len);

#if defined(LWS_WITH_TLS_JIT_TRUST)
/*
 * a vhost made for a jit-trusted peer lost its last connection: IO keeps it
 * a grace period in case another comes, then destroys it
 */
void
lws_tls_jit_trust_vh_start_grace(struct lws_vhost *vh);
#endif

/*
 * the last connection bound to a vhost that is being destroyed went: IO
 * finishes destroying it (a vhost's creation and destruction are IO's)
 */
void
__lws_vhost_destroy2(struct lws_vhost *vh);

/* want_write, served now rather than on the next turn of the loop */
int
lws_service_wsi_as_writable(struct lws *wsi);

/* rx now: the header table's autoservice, for a wsi that was waiting on one */
int
lws_io_service_now(struct lws *wsi);

#if defined(LWS_WITH_TLS)
/*
 * What sansIO may ask of the connection's tls session, which is IO's: the
 * library's session object (handed to the user with ESTABLISHED), which CA's
 * store verified the peer (mTLS vhost binding), whether the server's
 * certificate is acceptable under the connection's LCCSCF_ flags (quic
 * confirms it when its handshake is done, as tls does for tcp).  quic runs
 * the handshake in its own packets, so it also asks for its session to be
 * made, and what the handshake settled: the AEAD, the alert, the alpn.
 */
void *
lws_tls_session_ptr(struct lws *wsi);
const uint8_t *
lws_tls_wsi_hs_ca_id(struct lws *wsi);
int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len);
#if defined(LWS_ROLE_QUIC)
int
lws_tls_quic_session(struct lws *wsi, lws_tls_quic_secret_cb cb);
int
lws_tls_quic_aead_type(struct lws *wsi);
int
lws_tls_quic_alert(struct lws *wsi);
int
lws_tls_quic_alpn(struct lws *wsi, char *buf, size_t len);
#endif
#endif
#if defined(LWS_WITH_CLIENT)
/*
 * transport: the socks or CONNECT leg a client role ran over the raw
 * transport is done, the tunnel is up; IO carries on (tls, then transport up)
 */
int
lws_client_transport_connected(struct lws *wsi);
/*
 * transport: the client's request is ready to go (it got its header table):
 * IO starts its transport, dns first.  Returns the wsi, or NULL when it was
 * closed and freed
 */
struct lws *
lws_client_transport_start(struct lws *wsi);
#if defined(LWS_WITH_TLS_JIT_TRUST)
/*
 * transport: a restarted client may belong on another vhost now, the one
 * whose trust store (jit trust) is for its new address: IO rebinds it
 */
void
lws_client_transport_rebind(struct lws *wsi);
#endif
/*
 * transport: a role that makes its transport inside its own protocol (quic's
 * handshake) has made it; it won any race for the connection, and IO drops
 * what else it had trying to be it
 */
void
lws_client_transport_established(struct lws *wsi);
#if defined(LWS_ROLE_H3) || defined(LWS_ROLE_QUIC)
/*
 * transport: such a role's transport failed before it was up; IO retargets
 * the connection if it can (the next address, then tcp) and returns 1, else 0
 */
int
lws_client_transport_failed(struct lws *wsi);
#endif
#endif

#endif
