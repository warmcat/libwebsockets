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
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"

#if defined(LWS_ROLE_QUIC)
extern void
gnutls_quic_bio_free(struct lws *wsi);
#endif

#if defined(LWS_WITH_TCP_TLS)
int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	int n;

	if (!wsi->io->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	n = (int)gnutls_record_recv((gnutls_session_t)wsi->io->tls.ssl, buf, len);

	/*
	 * gnutls can call back into us from in there (keylog, session ticket,
	 * verify), and a callback that closed the wsi took the session with
	 * it... everything below dereferences wsi->io->tls.ssl again (C-417)
	 */

	if (!wsi->io->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_TLS_SESSIONS)
	/*
	 * A TLS 1.3 server sends its session ticket after the handshake, and
	 * gnutls took it in in there if it came: the session may only now be
	 * one we can resume
	 */
	if (lwsi_role_client(wsi))
		lws_tls_session_new_gnutls(wsi);
#endif

	if (n > 0) {
		struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

		if (gnutls_record_check_pending((gnutls_session_t)wsi->io->tls.ssl)) {
			if (lws_dll2_is_detached(&wsi->io->tls.dll_pending_tls))
				lws_dll2_add_head(&wsi->io->tls.dll_pending_tls,
						  &pt->tls.dll_pending_tls_owner);
		} else
			__lws_ssl_remove_wsi_from_buffered_list(wsi);

		if (wsi->a.context->tls_ops->fake_POLLIN_for_buffered)
			wsi->a.context->tls_ops->fake_POLLIN_for_buffered(pt);

		return n;
	}

	if (!n) {
		__lws_ssl_remove_wsi_from_buffered_list(wsi);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->io->tls.ssl) == 0)
			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

		wsi->io->tls_read_wanted_write = 1;
		lws_callback_on_writable(wsi);
		__lws_change_pollfd(wsi, LWS_POLLIN, 0);
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	if (n == GNUTLS_E_REHANDSHAKE) {
		/*
		 * The peer wants to renegotiate.  We never do: for a server it
		 * is a cheap asymmetric CPU amplifier (a few hundred bytes in,
		 * a key exchange and a private key signature out) on a
		 * connection whose handshake restriction slot has already been
		 * handed back, and for a client it would let the server
		 * present a different certificate after the peer identity
		 * check latched.
		 *
		 * gnutls never renegotiates by itself, it just tells us, so
		 * this is where the openssl ctxs' SSL_OP_NO_RENEGOTIATION
		 * (C-406) lands on this backend: drop the connection.
		 */
		lwsl_wsi_notice(wsi, "peer asked to renegotiate, refusing");

		return LWS_SSL_CAPABLE_ERROR;
	}

	lwsl_info("gnutls_record_recv error %d\n", n);

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	int n;

	if (!wsi->io->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	n = (int)gnutls_record_send((gnutls_session_t)wsi->io->tls.ssl, buf, len);
	if (n >= 0)
		return n;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->io->tls.ssl) == 1)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->io->tls.ssl)
		return 0;

	return (int)gnutls_record_check_pending((gnutls_session_t)wsi->io->tls.ssl);
}
#endif

/*
 * The session now belongs to wsi (lws_tls_transfer_wsi()): the session ptr is
 * how our callbacks (keylog, server name, quic) find the wsi, so it must
 * follow the session
 */
void
lws_tls_conn_set_wsi(struct lws *wsi)
{
	gnutls_session_set_ptr((gnutls_session_t)wsi->io->tls.ssl, wsi);
}

int
lws_ssl_close(struct lws *wsi)
{
#if defined(LWS_ROLE_QUIC)
	gnutls_quic_bio_free(wsi);
#endif

	if (wsi->io->tls.ssl) {
		/*
		 * The session was offered to the client cache while the
		 * connection was intact (LWS_IOCLOSE_QUIESCE): by now a quic
		 * connection has lost the netconn its session tag is made from
		 */
		gnutls_deinit((gnutls_session_t)wsi->io->tls.ssl);
		wsi->io->tls.ssl = NULL;
	}

	__lws_ssl_remove_wsi_from_buffered_list(wsi);

	lws_tls_restrict_return(wsi);

	if (wsi->io->tls.ctx_ref) {
		lws_tls_ctx_ref_unref(wsi->io->tls.ctx_ref);
		wsi->io->tls.ctx_ref = NULL;
	}

	return 0;
}

#if defined(LWS_WITH_SERVER)
/*
 * A server handshake completed: does the client cert it presented satisfy
 * the vhost's policy?  tcp's accept below and quic's handshake completion
 * (lws_tls_quic_server_confirm_peer()) both ask.  0 if he may go on.
 */
int
lws_tls_server_client_cert_check(struct lws *wsi)
{
	gnutls_session_t session = (gnutls_session_t)wsi->io->tls.ssl;
	int opt_req = lws_check_opt(wsi->a.vhost->options,
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT);
	int opt_opt = lws_check_opt(wsi->a.vhost->options,
			LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED);
	union lws_tls_cert_info_results ir;
	unsigned int status = 0;
	gnutls_datum_t out;
	char rbuf[160];

	if (!opt_req && !opt_opt)
		return 0;

	/*
	 * The vhost asked for client certs.  gnutls does not verify presented
	 * client certs as part of the handshake by itself (GNUTLS_CERT_REQUIRE
	 * only requires one to be there), so the outcome is both enforced and
	 * made visible here
	 */

	if (gnutls_certificate_verify_peers2(session, &status) < 0) {
		lwsl_notice("%s: vh %s: mTLS: no client cert presented\n",
			    __func__, wsi->a.vhost->name);

		/* absent cert is only OK if it was optional */
		return !opt_opt;
	}

	if (status) {
		/*
		 * Presented, but did not verify: reject.
		 *
		 * LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED does not excuse
		 * this.  openssl's SSL_VERIFY_PEER (which is what lws asks for
		 * there) means "no cert is OK, a bad cert is not", and mbedtls
		 * was brought to the same rule in C-359: only the *absence* of
		 * a cert is tolerated, since an app reading the CN or SAN
		 * afterwards to authorize would otherwise be reading an
		 * unvalidated identity.
		 */

		rbuf[0] = '\0';
		if (!gnutls_certificate_verification_status_print(status,
				gnutls_certificate_type_get(session), &out, 0)) {
			lws_strncpy(rbuf, (const char *)out.data,
				    sizeof(rbuf) - 1);
			gnutls_free(out.data);
		}

		lwsl_notice("%s: vh %s: mTLS: rejecting client cert: %s\n",
			    __func__, wsi->a.vhost->name,
			    rbuf[0] ? rbuf : "verification failed");

		return 1;
	}

	/*
	 * Anything that did not verify was refused above, so this really is
	 * an authenticated identity.  The app can ask for the same answer
	 * with LWS_TLS_CERT_INFO_VERIFIED
	 */

	if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
				   &ir, sizeof(ir.ns.name)))
		lws_strncpy(ir.ns.name, "unknown", sizeof(ir.ns.name));

	lwsl_notice("%s: vh %s: mTLS: accepted verified client cert CN=%s\n",
		    __func__, wsi->a.vhost->name, ir.ns.name);

	return 0;
}
#endif

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_TCP_TLS)
enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	int n;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _g_ssl_acc_start = lws_now_usecs();
#endif

	if (!wsi->io->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	wsi->io->skip_fallback = 1;

	n = gnutls_handshake((gnutls_session_t)wsi->io->tls.ssl);
	lwsl_debug("%s: gnutls_handshake returned %d\n", __func__, n);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _g_ssl_acc_start) / 1000);
		if (ms > 2 && !wsi->io->tls.ssl_accept_in_bg)
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _g_ssl_acc_start, 2000, "ssl_accept:%dms", ms);
	}
#endif

	if (n == GNUTLS_E_SUCCESS) {
		if (lws_tls_server_client_cert_check(wsi))
			return LWS_SSL_CAPABLE_ERROR;

		return LWS_SSL_CAPABLE_DONE;
	}

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->io->tls.ssl) == 0) {
			if (!wsi->io->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		} else {
			if (!wsi->io->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, LWS_POLLIN, LWS_POLLOUT))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}
	}

	/*
	 * The handshake failed for good: say why, and if it was about the
	 * peer certificate, render the verification status in human terms.
	 *
	 * An SNI name we refused has already been reported, with the name, by
	 * the server name hook... don't say it again with less information.
	 */
	if (n != GNUTLS_E_UNRECOGNIZED_NAME) {
		unsigned int status = 0;
		char rbuf[160];

		rbuf[0] = '\0';
		if (!gnutls_certificate_verify_peers2(
				(gnutls_session_t)wsi->io->tls.ssl, &status)) {
			gnutls_datum_t out;

			if (!gnutls_certificate_verification_status_print(
					status,
					gnutls_certificate_type_get(
						(gnutls_session_t)wsi->io->tls.ssl),
					&out, 0)) {
				lws_strncpy(rbuf, (const char *)out.data,
					    sizeof(rbuf) - 1);
				gnutls_free(out.data);
			}
		}

		lwsl_notice("%s: vh %s: server TLS handshake failed: %s (%d)%s%s\n",
			    __func__, wsi->a.vhost->name,
			    gnutls_strerror(n), n,
			    rbuf[0] ? ", peer cert: " : "", rbuf);
	}

	return LWS_SSL_CAPABLE_ERROR;
}
#endif

#if defined(LWS_WITH_TCP_TLS)
enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	int n;

	if (!wsi->io->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	n = gnutls_handshake((gnutls_session_t)wsi->io->tls.ssl);
	if (n == GNUTLS_E_SUCCESS) {
#if defined(LWS_WITH_CLIENT)
		wsi->tls_session_reused = gnutls_session_is_resumed((gnutls_session_t)wsi->io->tls.ssl) ? 1 : 0;
#endif
		/*
		 * Nothing is cached here: under TLS 1.3 the ticket is still to
		 * come, it is cached from the reads (lws_ssl_capable_read())
		 */
		return LWS_SSL_CAPABLE_DONE;
	}

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->io->tls.ssl) == 0) {
			if (lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		} else {
			if (lws_change_pollfd(wsi, LWS_POLLIN, LWS_POLLOUT))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}
	}

	lwsl_info("gnutls_handshake (client) failed: %s (%d)\n", gnutls_strerror(n), n);

	if (errbuf)
		snprintf(errbuf, len, "GnuTLS handshake failed: %s", gnutls_strerror(n));

	return LWS_SSL_CAPABLE_ERROR;
}
#endif

int
lws_ssl_get_error(struct lws *wsi, int n)
{
	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (!wsi->io->tls.ssl)
			return 2; /* SSL_ERROR_WANT_READ */

		if (gnutls_record_get_direction((gnutls_session_t)wsi->io->tls.ssl) == 0)
			return 2; /* SSL_ERROR_WANT_READ */

		return 3; /* SSL_ERROR_WANT_WRITE */
	}

	return n;
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int n;

	if (!wsi->io->tls.ssl)
		return LWS_SSL_CAPABLE_DONE;

	n = gnutls_bye((gnutls_session_t)wsi->io->tls.ssl, GNUTLS_SHUT_WR);
	if (n == GNUTLS_E_SUCCESS)
		return LWS_SSL_CAPABLE_DONE;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->io->tls.ssl) == 1)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

#if defined(LWS_WITH_SERVER)
enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	if (wsi->io->tls.ssl) {
		__lws_tls_shutdown(wsi);
		gnutls_deinit((gnutls_session_t)wsi->io->tls.ssl);
		wsi->io->tls.ssl = NULL;
	}

	return LWS_SSL_CAPABLE_DONE;
}
#endif

#if defined(LWS_WITH_CLIENT)
#if defined(LWS_WITH_TLS_JIT_TRUST)
/*
 * gnutls_x509_crt_get_{subject,authority}_key_id() want the whole KID to fit;
 * like the other backends we take any KID, and treat only the start of one
 * that is longer than lws_tls_kid_t can hold as significant
 */

static void
lws_gnutls_kid(int r, const uint8_t *kid, size_t len, lws_tls_kid_t *dest)
{
	if (r < 0)
		return;

	if (len > sizeof(dest->kid))
		len = sizeof(dest->kid);

	memcpy(dest->kid, kid, len);
	dest->kid_len = (uint8_t)len;
}

/*
 * Collect the SKID and AKID of each cert the peer sent into the wsi's
 * kid_chain for JIT Trust, which sorts them out and asks the system for the
 * CA that the top of the chain names.  None of these certs are trusted by
 * being seen here, even if a misconfigured server sends us its root.
 */

static void
lws_gnutls_collect_peer_kids(struct lws *wsi, gnutls_session_t session)
{
	lws_tls_kid_chain_t *ch = &wsi->io->tls.kid_chain;
	const gnutls_datum_t *certs;
	unsigned int n, count = 0;
	gnutls_x509_crt_t crt;
	uint8_t kid[64];
	size_t len;
	int r;

	/* only the chain we are looking at now counts */
	memset(ch, 0, sizeof(*ch));

	certs = gnutls_certificate_get_peers(session, &count);
	if (!certs)
		return;

	for (n = 0; n < count &&
		    (size_t)ch->count < LWS_ARRAY_SIZE(ch->akid); n++) {

		if (gnutls_x509_crt_init(&crt) < 0)
			return;

		if (gnutls_x509_crt_import(crt, &certs[n],
					   GNUTLS_X509_FMT_DER) < 0) {
			gnutls_x509_crt_deinit(crt);
			continue;
		}

		len = sizeof(kid);
		r = gnutls_x509_crt_get_subject_key_id(crt, kid, &len, NULL);
		lws_gnutls_kid(r, kid, len, &ch->skid[ch->count]);

		len = sizeof(kid);
		r = gnutls_x509_crt_get_authority_key_id(crt, kid, &len, NULL);
		lws_gnutls_kid(r, kid, len, &ch->akid[ch->count]);

		gnutls_x509_crt_deinit(crt);
		ch->count++;
	}
}
#endif

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	gnutls_session_t session = (gnutls_session_t)wsi->io->tls.ssl;
	unsigned int status = 0, allowed = 0;
	char hostname[128];
	int n;

	if (!session)
		return -1;

	/*
	 * gnutls_certificate_verify_peers2() only walks the chain to a trust
	 * anchor... whose name the certificate carries is not its business.
	 * Unless the connection asked us not to, the peer name has to go to
	 * the "3" variant, which is what does for us what
	 * X509_VERIFY_PARAM_set1_host() does on the openssl backend
	 */

	if (wsi->use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)
		n = gnutls_certificate_verify_peers2(session, &status);
	else {
		if (lws_gnutls_client_hostname(wsi, hostname,
					       sizeof(hostname))) {
			lws_snprintf(ebuf, ebuf_len, "no hostname to check "
				     "the peer certificate against");
			return -1;
		}

		n = gnutls_certificate_verify_peers3(session, hostname,
						     &status);
	}

	if (n < 0) {
		lws_snprintf(ebuf, ebuf_len,
			     "gnutls_certificate_verify_peers failed");
		goto refused;
	}

	if (!status)
		goto accepted;

	/*
	 * The same flag semantics as the openssl backend: ALLOW_INSECURE and
	 * friends forgive chain problems, but only
	 * LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK (handled above, by not
	 * asking for the name check at all) forgives the wrong name
	 */

	if (wsi->use_ssl & LCCSCF_ALLOW_INSECURE)
		allowed = status & (unsigned int)~GNUTLS_CERT_UNEXPECTED_OWNER;

	if (wsi->use_ssl & LCCSCF_ALLOW_SELFSIGNED)
		allowed |= GNUTLS_CERT_SIGNER_NOT_FOUND |
			   GNUTLS_CERT_SIGNER_NOT_CA;

	if (wsi->use_ssl & LCCSCF_ALLOW_EXPIRED)
		allowed |= GNUTLS_CERT_EXPIRED | GNUTLS_CERT_NOT_ACTIVATED;

	/*
	 * GNUTLS_CERT_INVALID is just the "something below is set" summary
	 * bit, it is meaningless on its own... let it go if everything it is
	 * summarizing was allowed
	 */

	if (allowed)
		allowed |= GNUTLS_CERT_INVALID;

	if (!(status & ~allowed)) {
		lwsl_info("%s: allowing anyway\n", __func__);
		goto accepted;
	}

	{
		gnutls_datum_t ds;

		if (!gnutls_certificate_verification_status_print(status,
				gnutls_certificate_type_get(session), &ds, 0)) {
			lws_snprintf(ebuf, ebuf_len, "Peer cert verify "
				     "failed: %s", ds.data);
			gnutls_free(ds.data);
		} else
			lws_snprintf(ebuf, ebuf_len, "Peer cert verify failed "
				     "with status 0x%x", status);
	}

	lwsl_notice("%s: %s\n", __func__, ebuf);

#if defined(LWS_WITH_TLS_JIT_TRUST)
	/*
	 * We did not have the CA to validate the chain.  Hand the key
	 * identifiers of the peer's certs to JIT trust, which asks the system
	 * for the CA and, if it gets it, makes a vhost trusting it for the
	 * retry.
	 */
	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
		lws_gnutls_collect_peer_kids(wsi, session);
		lws_tls_jit_trust_sort_kids(wsi, &wsi->io->tls.kid_chain);
	}
#endif

refused:
#if defined(LWS_WITH_TLS_SESSIONS)
	/*
	 * A resumed session carries the cert of the connection it came from,
	 * which gnutls checked again above: if that no longer passes, nor will
	 * the next connection offering it
	 */
	if (gnutls_session_is_resumed(session))
		lws_tls_session_forget_gnutls(wsi);
#endif

	return -1;

accepted:
#if defined(LWS_WITH_TLS_SESSIONS)
	/* the session may be cached now, under this connection's posture */
	wsi->io->tls.peer_confirmed = 1;
#endif

	return 0;
}
#endif

static int
tops_fake_POLLIN_for_buffered_gnutls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_gnutls = {
	.fake_POLLIN_for_buffered = tops_fake_POLLIN_for_buffered_gnutls,
};
