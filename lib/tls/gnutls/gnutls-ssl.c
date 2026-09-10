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

	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	n = (int)gnutls_record_recv((gnutls_session_t)wsi->tls.ssl, buf, len);

	/*
	 * gnutls can call back into us from in there (keylog, session ticket,
	 * verify), and a callback that closed the wsi took the session with
	 * it... everything below dereferences wsi->tls.ssl again (C-417)
	 */

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	if (n > 0) {
		struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

		if (gnutls_record_check_pending((gnutls_session_t)wsi->tls.ssl)) {
			if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
				lws_dll2_add_head(&wsi->tls.dll_pending_tls,
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
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 0)
			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

		wsi->tls_read_wanted_write = 1;
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

	if (!wsi->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	n = (int)gnutls_record_send((gnutls_session_t)wsi->tls.ssl, buf, len);
	if (n >= 0)
		return n;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 1)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	return (int)gnutls_record_check_pending((gnutls_session_t)wsi->tls.ssl);
}
#endif

int
lws_ssl_close(struct lws *wsi)
{
#if defined(LWS_ROLE_QUIC)
	gnutls_quic_bio_free(wsi);
#endif

	if (wsi->tls.ssl) {
#if defined(LWS_WITH_TLS_SESSIONS)
		lws_tls_session_new_gnutls(wsi);
#endif
		gnutls_deinit((gnutls_session_t)wsi->tls.ssl);
		wsi->tls.ssl = NULL;
	}

	__lws_ssl_remove_wsi_from_buffered_list(wsi);

	lws_tls_restrict_return(wsi);

	if (wsi->tls.ctx_ref) {
		lws_tls_ctx_ref_unref(wsi->tls.ctx_ref);
		wsi->tls.ctx_ref = NULL;
	}

	return 0;
}

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_TCP_TLS)
enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	int n;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _g_ssl_acc_start = lws_now_usecs();
#endif

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	wsi->skip_fallback = 1;

	n = gnutls_handshake((gnutls_session_t)wsi->tls.ssl);
	lwsl_debug("%s: gnutls_handshake returned %d\n", __func__, n);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _g_ssl_acc_start) / 1000);
		if (ms > 2 && !wsi->tls.ssl_accept_in_bg)
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _g_ssl_acc_start, 2000, "ssl_accept:%dms", ms);
	}
#endif

	if (n == GNUTLS_E_SUCCESS) {
		int opt_req = lws_check_opt(wsi->a.vhost->options,
				LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT);
		int opt_opt = lws_check_opt(wsi->a.vhost->options,
				LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED);

		if (opt_req || opt_opt) {
			/*
			 * The vhost asked for client certs.  gnutls does not
			 * verify presented client certs as part of the
			 * handshake by itself, so the outcome is both
			 * enforced and made visible here
			 */
			unsigned int status = 0;

			if (gnutls_certificate_verify_peers2(
					(gnutls_session_t)wsi->tls.ssl,
					&status) < 0) {
				lwsl_notice("%s: vh %s: mTLS: no client cert presented\n",
					    __func__, wsi->a.vhost->name);

				/* absent cert is only OK if it was optional */
				if (!opt_opt)
					return LWS_SSL_CAPABLE_ERROR;
			} else if (status) {
				/*
				 * Presented, but did not verify: reject.
				 *
				 * LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED does
				 * not excuse this.  openssl's SSL_VERIFY_PEER
				 * (which is what lws asks for there) means "no
				 * cert is OK, a bad cert is not", and mbedtls
				 * was brought to the same rule in C-359: only
				 * the *absence* of a cert is tolerated, since
				 * an app reading the CN or SAN afterwards to
				 * authorize would otherwise be reading an
				 * unvalidated identity.
				 */
				gnutls_datum_t out;
				char rbuf[160];

				rbuf[0] = '\0';
				if (!gnutls_certificate_verification_status_print(
						status,
						gnutls_certificate_type_get(
							(gnutls_session_t)wsi->tls.ssl),
						&out, 0)) {
					lws_strncpy(rbuf, (const char *)out.data,
						    sizeof(rbuf) - 1);
					gnutls_free(out.data);
				}

				lwsl_notice("%s: vh %s: mTLS: rejecting client "
					    "cert: %s\n", __func__,
					    wsi->a.vhost->name,
					    rbuf[0] ? rbuf : "verification failed");

				return LWS_SSL_CAPABLE_ERROR;
			} else {
				union lws_tls_cert_info_results ir;
				char cn[80];

				if (!lws_tls_peer_cert_info(wsi,
						LWS_TLS_CERT_INFO_COMMON_NAME,
						&ir, sizeof(ir)))
					lws_strncpy(cn, ir.ns.name, sizeof(cn));
				else
					lws_strncpy(cn, "unknown", sizeof(cn));

				/*
				 * Anything that did not verify was refused
				 * above, so this really is an authenticated
				 * identity.  The app can ask for the same
				 * answer with LWS_TLS_CERT_INFO_VERIFIED
				 */

				lwsl_notice("%s: vh %s: mTLS: accepted verified "
					    "client cert CN=%s\n", __func__,
					    wsi->a.vhost->name, cn);
			}
		}

		return LWS_SSL_CAPABLE_DONE;
	}

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 0) {
			if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		} else {
			if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, LWS_POLLIN, LWS_POLLOUT))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}
	}

	/*
	 * The handshake failed for good: say why, and if it was about the
	 * peer certificate, render the verification status in human terms
	 */
	{
		unsigned int status = 0;
		char rbuf[160];

		rbuf[0] = '\0';
		if (!gnutls_certificate_verify_peers2(
				(gnutls_session_t)wsi->tls.ssl, &status)) {
			gnutls_datum_t out;

			if (!gnutls_certificate_verification_status_print(
					status,
					gnutls_certificate_type_get(
						(gnutls_session_t)wsi->tls.ssl),
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

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_ERROR;

	n = gnutls_handshake((gnutls_session_t)wsi->tls.ssl);
	if (n == GNUTLS_E_SUCCESS) {
#if defined(LWS_WITH_CLIENT)
		wsi->tls_session_reused = gnutls_session_is_resumed((gnutls_session_t)wsi->tls.ssl) ? 1 : 0;
#endif
#if defined(LWS_WITH_TLS_SESSIONS)
		lws_tls_session_new_gnutls(wsi);
#endif
		lws_tls_server_conn_alpn(wsi);
		return LWS_SSL_CAPABLE_DONE;
	}

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 0) {
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
		if (!wsi->tls.ssl)
			return 2; /* SSL_ERROR_WANT_READ */

		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 0)
			return 2; /* SSL_ERROR_WANT_READ */

		return 3; /* SSL_ERROR_WANT_WRITE */
	}

	return n;
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int n;

	if (!wsi->tls.ssl)
		return LWS_SSL_CAPABLE_DONE;

	n = gnutls_bye((gnutls_session_t)wsi->tls.ssl, GNUTLS_SHUT_WR);
	if (n == GNUTLS_E_SUCCESS)
		return LWS_SSL_CAPABLE_DONE;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 1)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

#if defined(LWS_WITH_SERVER)
enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	if (wsi->tls.ssl) {
		__lws_tls_shutdown(wsi);
		gnutls_deinit((gnutls_session_t)wsi->tls.ssl);
		wsi->tls.ssl = NULL;
	}

	return LWS_SSL_CAPABLE_DONE;
}
#endif

#if defined(LWS_WITH_CLIENT)
int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	gnutls_session_t session = (gnutls_session_t)wsi->tls.ssl;
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

	if (wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)
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
		return -1;
	}

	if (!status)
		return 0;

	/*
	 * The same flag semantics as the openssl backend: ALLOW_INSECURE and
	 * friends forgive chain problems, but only
	 * LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK (handled above, by not
	 * asking for the name check at all) forgives the wrong name
	 */

	if (wsi->tls.use_ssl & LCCSCF_ALLOW_INSECURE)
		allowed = status & (unsigned int)~GNUTLS_CERT_UNEXPECTED_OWNER;

	if (wsi->tls.use_ssl & LCCSCF_ALLOW_SELFSIGNED)
		allowed |= GNUTLS_CERT_SIGNER_NOT_FOUND |
			   GNUTLS_CERT_SIGNER_NOT_CA;

	if (wsi->tls.use_ssl & LCCSCF_ALLOW_EXPIRED)
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
		return 0;
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

	return -1;
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
