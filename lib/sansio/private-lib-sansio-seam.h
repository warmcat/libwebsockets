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
 * The requests of lws' own IO's features (the cgi, jit trust) go the same
 * way through the context's lws_io_plumbing_t (private-lib-core-net.h),
 * which is not part of that contract.  A member that may be NULL is checked
 * here, and the request answered as though it could not be done.
 *
 * The wrappers are for the sansIO sources, which compile with
 * LWS_SANSIO_CHECK: they keep the names the requests always had, so the call
 * sites do not change.  IO's own implementations of the same names, and
 * their prototypes (private-lib-io.h), are what every other source sees and
 * what lws_io_ops_default points to.  A request whose IO implementation is
 * public api is spelled lws_io_...() here.
 *
 * The four requests sansIO has always spelled as public api
 * (lws_callback_on_writable(), lws_rx_flow_control(), lws_close_free_wsi(),
 * and the deadlines of lws_set_timeout() / lws_sul_schedule()) reach the
 * same struct inside sansIO and the neither half's timer lists.
 */

#if !defined(__LWS_PRIVATE_LIB_SANSIO_SEAM_H__)
#define __LWS_PRIVATE_LIB_SANSIO_SEAM_H__

#if defined(LWS_SANSIO_CHECK)

#if !defined(LWS_WITH_LATENCY) && !defined(LWS_WITH_SYS_METRICS)
/*
 * Time is an input (README.sans-io-split.md, "Time"): sansIO asks the
 * service thread's time, lws_wsi_now() / lws_wsi_now_wall() and friends,
 * never the clock.  A read of lws' clock in a sansIO source fails to compile
 * here, naming the line.  Only measurements of how long lws really took
 * read it, LWS_WITH_LATENCY's and the metrics calipers
 * (LWS_WITH_SYS_METRICS, lws-metrics.h), so the check is off in a build
 * with either.  (libc's time() is not caught: a system header declaring it
 * after this would break.)
 */
#define lws_now_usecs()	sansio_asks_lws_wsi_now_not_the_clock()
#define lws_now_secs()	sansio_asks_lws_wsi_now_wall_not_the_clock()
#endif

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
	if (!wsi->a.context->io_ops->tx_file)
		return -1; /* nothing can send it: close */

	return wsi->a.context->io_ops->tx_file(wsi);
}
#endif

/*
 * the transport (lws_io_ops_t transport_start, transport_connected,
 * transport_established, transport_failed, client_connect, peer_address;
 * IO's plumbing's transport_rebind)
 */

#if defined(LWS_WITH_CLIENT)
/*
 * the client's request is ready to go (it got its header table): IO starts
 * its transport, dns first.  Returns the wsi, or NULL when it was closed and
 * freed
 */
static LWS_INLINE struct lws *
lws_client_transport_start(struct lws *wsi)
{
	return wsi->a.context->io_ops->transport_start(wsi);
}

/*
 * the socks or CONNECT leg a client role ran over the raw transport is done,
 * the tunnel is up; IO carries on (tls, then transport up)
 */
static LWS_INLINE int
lws_client_transport_connected(struct lws *wsi)
{
	return wsi->a.context->io_ops->transport_connected(wsi);
}

/*
 * a role that makes its transport inside its own protocol (quic's handshake)
 * has made it; it won any race for the connection, and IO drops what else it
 * had trying to be it
 */
static LWS_INLINE void
lws_client_transport_established(struct lws *wsi)
{
	wsi->a.context->io_ops->transport_established(wsi);
}

#if defined(LWS_ROLE_H3) || defined(LWS_ROLE_QUIC)
/*
 * such a role's transport failed before it was up; IO retargets the
 * connection if it can (the next address, then tcp) and returns 1, else 0
 */
static LWS_INLINE int
lws_client_transport_failed(struct lws *wsi)
{
	if (!wsi->a.context->io_ops->transport_failed)
		return 0; /* nowhere else to go: the close goes on */

	return wsi->a.context->io_ops->transport_failed(wsi);
}
#endif

#if defined(LWS_WITH_TLS_JIT_TRUST)
/*
 * a restarted client may belong on another vhost now, the one whose trust
 * store (jit trust) is for its new address: IO rebinds it (IO's plumbing)
 */
static LWS_INLINE void
lws_client_transport_rebind(struct lws *wsi)
{
	if (wsi->a.context->io_plumbing->transport_rebind)
		wsi->a.context->io_plumbing->transport_rebind(wsi);
}
#endif

#if defined(LWS_WITH_HTTP_PROXY)
/*
 * a new client connection, the onward leg of a proxied http transaction:
 * lws_io_ops_t.client_connect, IO's lws_client_connect_via_info()
 */
static LWS_INLINE struct lws *
lws_io_client_connect(const struct lws_client_connect_info *i)
{
	if (!i->context->io_ops->client_connect)
		return NULL; /* no onward leg can be made */

	return i->context->io_ops->client_connect(i);
}
#endif
#endif

/*
 * the connection's peer address as text, into buf: lws_io_ops_t.peer_address,
 * IO's lws_io_peer_address().  Returns buf.
 */
static LWS_INLINE const char *
lws_io_peer_address(struct lws *wsi, char *buf, size_t len)
{
	if (!wsi->a.context->io_ops->peer_address) {
		lws_strncpy(buf, "unknown", len);
		return buf;
	}

	return wsi->a.context->io_ops->peer_address(wsi, buf, len);
}

#if defined(LWS_WITH_TLS)
/*
 * the tls session (lws_io_ops_t tls_...): what sansIO may ask of the
 * connection's tls session, which is IO's
 */

/* the library's session object, handed to the user with ESTABLISHED */
static LWS_INLINE void *
lws_tls_session_ptr(struct lws *wsi)
{
	if (!wsi->a.context->io_ops->tls_session)
		return NULL;

	return wsi->a.context->io_ops->tls_session(wsi);
}

/* which CA's store verified the peer (mTLS vhost binding) */
static LWS_INLINE const uint8_t *
lws_tls_wsi_hs_ca_id(struct lws *wsi)
{
	if (!wsi->a.context->io_ops->tls_hs_ca_id)
		return NULL;

	return wsi->a.context->io_ops->tls_hs_ca_id(wsi);
}

/* the peer's certificate: IO's lws_tls_peer_cert_info() */
static LWS_INLINE int
lws_io_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
			  union lws_tls_cert_info_results *buf, size_t len)
{
	if (!wsi->a.context->io_ops->tls_peer_cert_info)
		return -1;

	return wsi->a.context->io_ops->tls_peer_cert_info(wsi, type, buf, len);
}

#if defined(LWS_ROLE_QUIC)
/*
 * quic runs the tls handshake in its own packets: it asks for its session
 * to be made, feeds it the CRYPTO frames' bytes, sets and gets the transport
 * parameters, and asks what the handshake settled: whether the server's
 * certificate is acceptable under the connection's LCCSCF_ flags, the AEAD,
 * the alert, the alpn
 */
static LWS_INLINE int
lws_tls_quic_session(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	return wsi->a.context->io_ops->tls_quic_session(wsi, cb);
}

/* IO's lws_tls_quic_advance_handshake() */
static LWS_INLINE int
lws_io_tls_quic_handshake(struct lws *wsi, int level, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t *out_len)
{
	return wsi->a.context->io_ops->tls_quic_handshake(wsi, level, in,
							  in_len, out, out_len);
}

/* IO's lws_tls_quic_set_transport_parameters() */
static LWS_INLINE int
lws_io_tls_quic_set_tp(struct lws *wsi, const uint8_t *tp, size_t tp_len)
{
	return wsi->a.context->io_ops->tls_quic_set_tp(wsi, tp, tp_len);
}

/* IO's lws_tls_quic_get_transport_parameters() */
static LWS_INLINE int
lws_io_tls_quic_get_tp(struct lws *wsi, const uint8_t **tp, size_t *tp_len)
{
	return wsi->a.context->io_ops->tls_quic_get_tp(wsi, tp, tp_len);
}

#if defined(LWS_WITH_CLIENT)
static LWS_INLINE int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	return wsi->a.context->io_ops->tls_confirm_peer_cert(wsi, ebuf,
							     ebuf_len);
}
#endif

static LWS_INLINE int
lws_tls_quic_aead_type(struct lws *wsi)
{
	return wsi->a.context->io_ops->tls_quic_aead(wsi);
}

static LWS_INLINE int
lws_tls_quic_alert(struct lws *wsi)
{
	return wsi->a.context->io_ops->tls_quic_alert(wsi);
}

static LWS_INLINE int
lws_tls_quic_alpn(struct lws *wsi, char *buf, size_t len)
{
	return wsi->a.context->io_ops->tls_quic_alpn(wsi, buf, len);
}
#endif
#endif

/*
 * service (lws_io_ops_t service_writable, service_now, flag_pending_rx,
 * wake) and the app's rx pull (http_client_read)
 */

/* want_write, served now rather than on the next turn of the loop */
static LWS_INLINE int
lws_service_wsi_as_writable(struct lws *wsi)
{
	return wsi->a.context->io_ops->service_writable(wsi);
}

/* rx now: the header table's autoservice, for a wsi that was waiting on one */
static LWS_INLINE int
lws_io_service_now(struct lws *wsi)
{
	return wsi->a.context->io_ops->service_now(wsi);
}

/* rx pending this pass: a role still has buffered rx to drain for the wsi */
static LWS_INLINE int
lws_io_flag_pending_rx(struct lws *wsi)
{
	return wsi->a.context->io_ops->flag_pending_rx(wsi);
}

/*
 * make sure the wsi's service thread comes round its loop soon, for work
 * left to its forced-service pass: lws_io_ops_t.wake, IO's
 * lws_cancel_service_pt()
 */
static LWS_INLINE void
lws_io_wake(struct lws *wsi)
{
	wsi->a.context->io_ops->wake(wsi);
}

#if defined(LWS_WITH_CLIENT) && \
    (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3))
/*
 * the app's pull of a client response body: lws_io_ops_t.http_client_read,
 * IO's lws_http_client_read()
 */
static LWS_INLINE int
lws_io_http_client_read(struct lws *wsi, char **buf, int *len)
{
	if (!wsi->a.context->io_ops->http_client_read)
		return -1;

	return wsi->a.context->io_ops->http_client_read(wsi, buf, len);
}
#endif

/*
 * the vhost and the context (lws_io_ops_t vhost_destroy, finalize_startup;
 * IO's plumbing's vhost_jit_grace): a vhost's creation and destruction are IO's, and so is
 * the process the context runs in
 */

/*
 * every vhost's protocols had their first init: IO may drop the process's
 * privileges now, IO's lws_finalize_startup()
 */
static LWS_INLINE int
lws_io_finalize_startup(struct lws_context *cx, const char *where)
{
	if (!cx->io_ops->finalize_startup)
		return 0;

	return cx->io_ops->finalize_startup(cx, where);
}

/*
 * the last connection bound to a vhost that is being destroyed went: IO
 * finishes destroying it
 */
static LWS_INLINE void
__lws_vhost_destroy2(struct lws_vhost *vh)
{
	vh->context->io_ops->vhost_destroy(vh);
}

#if defined(LWS_WITH_TLS_JIT_TRUST)
/*
 * a vhost made for a jit-trusted peer lost its last connection: IO keeps it
 * a grace period in case another comes, then destroys it (IO's plumbing)
 */
static LWS_INLINE void
lws_tls_jit_trust_vh_start_grace(struct lws_vhost *vh)
{
	if (vh->context->io_plumbing->vhost_jit_grace)
		vh->context->io_plumbing->vhost_jit_grace(vh);
}
#endif

#if defined(LWS_WITH_CGI)
/*
 * the cgi (IO's plumbing, cgi_...): an http transaction's cgi is a child
 * process IO runs for it
 */

/* start the child for the transaction info->wsi: IO's lws_cgi_via_info() */
static LWS_INLINE int
lws_io_cgi_start(struct lws_cgi_info *info)
{
	const lws_io_plumbing_t *p = info->wsi->a.context->io_plumbing;

	if (!p->cgi_start)
		return -1;

	return p->cgi_start(info);
}

/*
 * relay what the child wrote on its stdout to the transaction wsi, headers
 * first: IO's lws_cgi_write_split_stdout_headers()
 */
static LWS_INLINE int
lws_io_cgi_stdout_tx(struct lws *wsi)
{
	const lws_io_plumbing_t *p = wsi->a.context->io_plumbing;

	if (!p->cgi_stdout_tx)
		return -1;

	return p->cgi_stdout_tx(wsi);
}

/* the request body to the child's stdin, as much as its pipe takes now */
static LWS_INLINE int
lws_cgi_stdin_write(struct lws_cgi_args *args)
{
	struct lws *siwsi = args->stdwsi[LWS_STDIN];

	if (!siwsi || !siwsi->a.context->io_plumbing->cgi_stdin_write)
		return -1; /* the stdin is gone */

	return siwsi->a.context->io_plumbing->cgi_stdin_write(args);
}

/* the request body is complete: the child's stdin is closed */
static LWS_INLINE void
lws_cgi_stdin_body_end(struct lws *wsi)
{
	if (wsi->a.context->io_plumbing->cgi_stdin_body_end)
		wsi->a.context->io_plumbing->cgi_stdin_body_end(wsi);
}

/* what the child wrote on its stderr, from its stderr pipe wsi, into buf */
static LWS_INLINE int
lws_cgi_stderr_read(struct lws *stdwsi, char *buf, size_t len)
{
	if (!stdwsi || !stdwsi->a.context->io_plumbing->cgi_stderr_read)
		return -1;

	return stdwsi->a.context->io_plumbing->cgi_stderr_read(stdwsi, buf,
							       len);
}

/* the transaction is going: the child is killed */
static LWS_INLINE void
lws_cgi_remove_and_kill(struct lws *wsi)
{
	if (wsi->a.context->io_plumbing->cgi_remove_and_kill)
		wsi->a.context->io_plumbing->cgi_remove_and_kill(wsi);
}

/* the transaction is done with its cgi: it and its pipes are released */
static LWS_INLINE void
lws_cgi_release(struct lws *wsi)
{
	if (wsi->a.context->io_plumbing->cgi_release)
		wsi->a.context->io_plumbing->cgi_release(wsi);
}
#endif

#endif /* LWS_SANSIO_CHECK */




#endif
