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
 * private-lib-sansio-seam.h: the sansIO half's requests of IO, in today's
 * private spellings (README.sans-io-split.md, "The interface").  This
 * header stays visible under LWS_SANSIO_CHECK, when the rest of IO's
 * prototypes are hidden, so what the check reports is exactly the calls
 * that are not the interface.  The public spellings (lws_callback_on_writable(),
 * lws_set_timeout(), lws_sul_schedule(), lws_rx_flow_control(),
 * lws_close_free_wsi(), lws_write()) are visible as public api.
 */

#if !defined(__LWS_PRIVATE_LIB_SANSIO_SEAM_H__)
#define __LWS_PRIVATE_LIB_SANSIO_SEAM_H__

/*
 * tx, in its push spelling: hand IO these bytes for the transport now; IO
 * takes them all, buffering what the transport does not take at once, and
 * returns len, or -1 when the transport failed.  buf NULL continues such a
 * partial, returning what of it went.  What sansIO produces when IO asks is the pull (the role's tx op);
 * the push is for what the app's writeable pass hands lws_write(), framed in
 * place in its LWS_PRE headroom so it is not copied, and the one-shot messages
 * of the proxy legs (socks, http CONNECT), composed at a state change.
 */
int LWS_WARN_UNUSED_RESULT
lws_io_tx_push(struct lws *wsi, unsigned char *buf, size_t len);

/* want_write, served now rather than on the next turn of the loop */
int
lws_service_wsi_as_writable(struct lws *wsi);
#if defined(LWS_WITH_UDP)
/*
 * the same for a datagram connection's tx alone: IO pulls its datagrams now
 * (a closing connection's CONNECTION_CLOSE), without a writeable pass
 */
void
lws_io_tx_now(struct lws *wsi);
#endif

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
