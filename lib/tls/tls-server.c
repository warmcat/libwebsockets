/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#if defined(LWS_WITH_SERVER)

/*
 * SNI for the backends that have no servername callback
 * --------------------------------------------------------------------------
 *
 * BearSSL hands the server the SNI name only from inside its certificate
 * chain "choose" hook, which runs after the ClientHello extensions have
 * already been matched (so ALPN and the cipher suite list are settled by
 * then), and Schannel has no such hook at all: AcceptSecurityContext()
 * consumes the ClientHello with the credential handle already chosen.
 *
 * On both of those, the only place the vhost decision can still change the
 * certificate, the client-certificate policy and the ALPN list is before the
 * TLS library sees the first record at all.  So they take the name out of the
 * ClientHello themselves, with the parser below, and then select and bind the
 * vhost with lws_tls_server_sni_select() exactly as the other backends' SNI
 * callbacks do.
 */

/*
 * Find the SNI hostname in a TLS ClientHello.
 *
 * Everything in \p buf is attacker-chosen: it is literally the first bytes he
 * sent us.  So every length is checked against the bytes actually remaining
 * before it is used, no extension ordering is assumed, and the name is only
 * accepted if it is something we are willing to hand to a string API.
 *
 * We only look inside the first TLS record.  A ClientHello fragmented across
 * several records is legal but is not something any TLS client does, and
 * reassembling it would mean de-framing the handshake stream ahead of the TLS
 * library; such a peer is simply treated as having sent no SNI, ie, he is
 * served by the vhost that accepted him.
 *
 * \p buf: the bytes the peer sent, from the start of the connection
 * \p len: how many of them we have
 * \p name: where to write the NUL-terminated hostname
 * \p name_len: sizeof(*name)
 *
 * Returns one of the LWS_TLS_CH_SNI_* results.  On _MORE the caller should
 * come back with more bytes, up to whatever cap it is willing to buffer;
 * beyond that cap it must stop asking and treat it as _NONE.
 */

int
lws_tls_client_hello_sni(const uint8_t *buf, size_t len, char *name,
			 size_t name_len)
{
	size_t pos, end, lim, n, u;

	if (!name || name_len < 2)
		return LWS_TLS_CH_SNI_NONE;

	*name = '\0';

	/* TLS plaintext record header: type(1) legacy_version(2) length(2) */

	if (len < 5)
		return LWS_TLS_CH_SNI_MORE;

	if (buf[0] != 0x16 /* handshake */ || buf[1] != 0x03)
		/*
		 * Not a TLS 1.x handshake record (an SSLv2-style hello comes
		 * here too, and carries no SNI by construction).  Nothing for
		 * us to say about it: let the TLS backend deal with it.
		 */
		return LWS_TLS_CH_SNI_NONE;

	end = 5 + (((size_t)buf[3] << 8) | buf[4]);

	if (end <= 5 || end > 5 + 16384)
		/* a record length TLS does not allow */
		return LWS_TLS_CH_SNI_NONE;

	if (len < end)
		return LWS_TLS_CH_SNI_MORE;

	/* handshake message header: msg_type(1) length(3) */

	pos = 5;

	if (end - pos < 4 || buf[pos] != 1 /* client_hello */)
		return LWS_TLS_CH_SNI_NONE;

	n = ((size_t)buf[pos + 1] << 16) | ((size_t)buf[pos + 2] << 8) |
	     (size_t)buf[pos + 3];
	pos += 4;

	if (n > end - pos)
		/* the ClientHello continues in a later record, see above */
		return LWS_TLS_CH_SNI_NONE;

	end = pos + n;

	/* client_version(2) + random(32) */

	if (end - pos < 34)
		return LWS_TLS_CH_SNI_NONE;
	pos += 34;

	/* legacy_session_id */

	if (end - pos < 1)
		return LWS_TLS_CH_SNI_NONE;
	n = buf[pos++];
	if (n > end - pos)
		return LWS_TLS_CH_SNI_NONE;
	pos += n;

	/* cipher_suites */

	if (end - pos < 2)
		return LWS_TLS_CH_SNI_NONE;
	n = ((size_t)buf[pos] << 8) | buf[pos + 1];
	pos += 2;
	if (n > end - pos)
		return LWS_TLS_CH_SNI_NONE;
	pos += n;

	/* legacy_compression_methods */

	if (end - pos < 1)
		return LWS_TLS_CH_SNI_NONE;
	n = buf[pos++];
	if (n > end - pos)
		return LWS_TLS_CH_SNI_NONE;
	pos += n;

	/*
	 * Extensions.  They are optional (a TLS 1.0 hello may simply stop
	 * here), and they may come in any order.
	 */

	if (end - pos < 2)
		return LWS_TLS_CH_SNI_NONE;
	n = ((size_t)buf[pos] << 8) | buf[pos + 1];
	pos += 2;
	if (n > end - pos)
		return LWS_TLS_CH_SNI_NONE;
	end = pos + n;

	while (end - pos >= 4) {
		unsigned int type = ((unsigned int)buf[pos] << 8) | buf[pos + 1];

		n = ((size_t)buf[pos + 2] << 8) | buf[pos + 3];
		pos += 4;
		if (n > end - pos)
			return LWS_TLS_CH_SNI_NONE;

		if (type) { /* 0 = server_name (RFC 6066) */
			pos += n;
			continue;
		}

		/*
		 * ServerNameList: list_length(2) then NameType(1) length(2).
		 *
		 * A server_name extension we cannot make sense of at all is
		 * treated as him not having named anything (_NONE, ie, he
		 * keeps the accepting vhost, and the tls library gets to have
		 * its own opinion about the malformed hello).  It is only
		 * once he has actually named a host that a name we will not
		 * act on becomes _BAD, ie, refused: that is the same answer
		 * the other backends give a name that matches no vhost.
		 */

		lim = pos + n;

		if (lim - pos < 2)
			return LWS_TLS_CH_SNI_NONE;
		n = ((size_t)buf[pos] << 8) | buf[pos + 1];
		pos += 2;
		if (n > lim - pos)
			return LWS_TLS_CH_SNI_NONE;
		lim = pos + n;

		while (lim - pos >= 3) {
			unsigned int nt = buf[pos];

			n = ((size_t)buf[pos + 1] << 8) | buf[pos + 2];
			pos += 3;
			if (n > lim - pos)
				return LWS_TLS_CH_SNI_NONE;

			if (nt) { /* 0 = host_name, the only one defined */
				pos += n;
				continue;
			}

			if (!n || n >= name_len)
				return LWS_TLS_CH_SNI_BAD;

			/*
			 * It is going into strcmp() against vhost names, and
			 * into the logs at info level... only take it if it
			 * is printable, NUL-free ASCII
			 */

			for (u = 0; u < n; u++)
				if (buf[pos + u] <= ' ' || buf[pos + u] > '~')
					return LWS_TLS_CH_SNI_BAD;

			memcpy(name, buf + pos, n);
			name[n] = '\0';

			return LWS_TLS_CH_SNI_FOUND;
		}

		/* a server_name extension with no host_name in it */

		return LWS_TLS_CH_SNI_NONE;
	}

	return LWS_TLS_CH_SNI_NONE;
}

/*
 * Send a fatal TLS alert ourselves, before any TLS library owns the
 * connection.  \p ver is the two legacy_version bytes from the record header
 * he sent, echoed back so that even a peer that only speaks an old version
 * can parse the record.
 */

void
lws_tls_server_send_alert(struct lws *wsi, const uint8_t *ver, uint8_t desc)
{
	uint8_t rec[7];

	rec[0] = 0x15;		/* content type: alert */
	rec[1] = ver[0];
	rec[2] = ver[1];
	rec[3] = 0;
	rec[4] = 2;		/* record length */
	rec[5] = 2;		/* AlertLevel: fatal */
	rec[6] = desc;

	/*
	 * Best effort: we are dropping him either way, and 7 bytes into a
	 * fresh socket does not block in practice
	 */

	(void)send(wsi->desc.sockfd, (const char *)rec, sizeof(rec),
		   MSG_NOSIGNAL);
}

/*
 * Apply the SNI name a backend dug out of the ClientHello itself.
 *
 * \p servername: the name he sent, or NULL if he sent none or sent something
 *		  unusable as a name
 *
 * Returns 0 if the handshake may go ahead, using whatever vhost the wsi is
 * bound to when we return (the selected one, or still the accepting one if he
 * sent no SNI).  Returns 1 if he must be refused: the caller sends the fatal
 * unrecognized_name alert and drops him.
 */

int
lws_tls_server_sni_select(struct lws *wsi, const char *servername)
{
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	LWS_RATELIMIT_DEFINE_STATIC(rl);
#endif
	struct lws_vhost *vhost;

	if (!servername)
		/*
		 * He sent no SNI, so he named nothing to steer with: he is
		 * served by the vhost that accepted him, like on every other
		 * backend
		 */
		return 0;

	vhost = lws_select_vhost_sni(wsi->a.context, wsi->a.vhost->listen_port,
				     servername);
	if (!vhost) {
		lwsl_info("SNI: none: %s:%d\n", servername,
			  wsi->a.vhost->listen_port);

		/*
		 * He named something that is not served on this listener, and
		 * no vhost there is the nominated sni-fallback.  Refuse him
		 * rather than let him pick an arbitrary vhost's certificate
		 * and client-certificate policy with an unknown name (C-424).
		 *
		 * The name is his to choose, so it stays out of the notice
		 * level line; it is logged just above at info level.
		 */

		lwsl_ratelimit_notice(&rl, 10 * LWS_US_PER_SEC, "%s: refused "
				      "tls connection on port %d, its SNI name "
				      "matches no vhost there and none is the "
				      "sni-fallback\n", __func__,
				      wsi->a.vhost->listen_port);

		return 1;
	}

	lwsl_info("SNI: Found: %s:%d\n", servername, wsi->a.vhost->listen_port);

	if (!vhost->tls.ssl_ctx) {
		lwsl_info("SNI: %s has no tls ctx yet\n", servername);

		return 0;
	}

	if (vhost->being_destroyed) {
		lwsl_info("SNI: %s is being destroyed\n", servername);

		return 0;
	}

	/*
	 * This is the handshake being set up on the vhost that is going to
	 * run it, so it binds as an SNI bind: it records which vhost's client
	 * CA store will vouch for any client cert (C-318), and marks the wsi
	 * so the post-accept ctx-to-vhost adaptation leaves it alone (C-409).
	 */

	lws_vhost_bind_wsi_sni(vhost, wsi);

	return 0;
}

static void
lws_sul_tls_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = lws_container_of(sul,
			struct lws_context_per_thread, sul_tls);

	lws_tls_check_all_cert_lifetimes(pt->context);

	__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &pt->sul_tls,
			    (lws_usec_t)24 * 3600 * LWS_US_PER_SEC);
}

int
lws_context_init_server_ssl(const struct lws_context_creation_info *info,
			    struct lws_vhost *vhost)
{
	struct lws_context *context = vhost->context;
	lws_fakewsi_def_plwsa(&vhost->context->pt[0]);

	lws_fakewsi_prep_plwsa_ctx(vhost->context);

	if (!lws_check_opt(info->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		vhost->tls.use_ssl = 0;

		return 0;
	}

	/*
	 * If he is giving a server cert, take it as a sign he wants to use
	 * it on this vhost.  User code can leave the cert filepath NULL and
	 * set the LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX option itself, in
	 * which case he's expected to set up the cert himself at
	 * LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, which
	 * provides the vhost SSL_CTX * in the user parameter.
	 */
	if (info->ssl_cert_filepath || info->server_ssl_cert_mem)
		vhost->options |= LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX;

	if (info->port != CONTEXT_PORT_NO_LISTEN) {

		vhost->tls.use_ssl = lws_check_opt(vhost->options,
					LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX);

		if (vhost->tls.use_ssl && info->ssl_cipher_list)
			lwsl_notice(" SSL ciphers: '%s'\n",
						info->ssl_cipher_list);

		lwsl_info(" Vhost '%s' using %sTLS mode\n",
			    vhost->name, vhost->tls.use_ssl ? "" : "non-");
	}

	/*
	 * give him a fake wsi with context + vhost set, so he can use
	 * lws_get_context() in the callback
	 */
	plwsa->vhost = vhost; /* not a real bound wsi */

	/*
	 * as a server, if we are requiring clients to identify themselves
	 * then set the backend up for it
	 */
	if (lws_check_opt(info->options,
			  LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT))
		/* Normally SSL listener rejects non-ssl, optionally allow */
		vhost->tls.allow_non_ssl_on_ssl_port = 1;

	/*
	 * give user code a chance to load certs into the server
	 * allowing it to verify incoming client certs
	 */
	if (vhost->tls.use_ssl) {
		if (lws_tls_server_vhost_backend_init(info, vhost, (struct lws *)plwsa))
			return -1;

		if (vhost->tls.ssl_ctx && !vhost->tls.active_ctx_ref)
			vhost->tls.active_ctx_ref = lws_tls_ctx_ref_create(vhost, vhost->tls.ssl_ctx);

		/*
		 * A backend that cannot enforce the vhost's client-cert
		 * policy must be able to refuse the vhost here rather than
		 * let it come up accepting anonymous peers
		 */
		if (vhost->tls.ssl_ctx &&
		    lws_tls_server_client_cert_verify_config(vhost))
			return -1;

		/*
		 * With LWS_SERVER_OPTION_IGNORE_MISSING_CERT and no cert yet,
		 * the backend freed the ctx and NULLed it (mbedtls, openssl,
		 * bearssl, gnutls and schannel all do).  User code given a
		 * NULL ssl_ctx here has nothing it can load certs into and
		 * would just dereference it, so hold the callback until the
		 * cert arrives and the ctx is regenerated.
		 */

		if (vhost->tls.ssl_ctx &&
		    vhost->protocols[0].callback((struct lws *)plwsa,
			    LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
			    vhost->tls.ssl_ctx, vhost, 0))
			return -1;
	}

	if (vhost->tls.use_ssl)
		lws_context_init_alpn(vhost);

	/* check certs in a few seconds (after protocol init) and then once a day */

	context->pt[0].sul_tls.cb = lws_sul_tls_cb;
	__lws_sul_insert_us(&context->pt[0].pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &context->pt[0].sul_tls,
			    (lws_usec_t)5 * LWS_US_PER_SEC);

	return 0;
}
#endif

#if defined(LWS_WITH_TCP_TLS)

/*
 * Which vhost owns the tls ctx this connection actually handshaked under?
 *
 * Normally that is the vhost whose tls.ssl_ctx it is.  But if the vhost's
 * certificate was rotated between the ctx being taken for this connection and
 * the handshake completing, the vhost's tls.ssl_ctx is already the
 * replacement, and the ctx in use has been parked on that vhost's
 * retired_ctx_list.  Matching only the active ctx then finds no vhost at all,
 * and a connection that SNI had moved to a permissive vhost stays bound to
 * the (possibly mTLS) vhost that accepted it.
 */

static struct lws_vhost *
lws_tls_vhost_owning_ctx(struct lws_context *cx, lws_tls_ctx *ctx)
{
	struct lws_vhost *vh;

	if (!ctx)
		return NULL;

	vh = lws_vhost_first(cx);
	while (vh) {
		if (!vh->being_destroyed && vh->tls.ssl_ctx == ctx)
			return vh;
		vh = lws_vhost_next(vh);
	}

	vh = lws_vhost_first(cx);
	while (vh) {
		if (!vh->being_destroyed) {
			lws_start_foreach_dll(struct lws_dll2 *, d,
				  lws_dll2_get_head(&vh->tls.retired_ctx_list)) {
				struct lws_tls_ctx_ref *r = lws_container_of(d,
						struct lws_tls_ctx_ref, list);

				if (r->ctx == ctx)
					return vh;
			} lws_end_foreach_dll(d);
		}
		vh = lws_vhost_next(vh);
	}

	return NULL;
}

int
lws_tls_server_accept_completed(struct lws *wsi, int n)
{
	struct lws_context *context = wsi->a.context;
	struct lws_vhost *vh;

	lwsl_info("SSL_accept says %d\n", n);
	switch (n) {
	case LWS_SSL_CAPABLE_DONE:
		lws_tls_restrict_return_handshake(wsi);
		break;
	case LWS_SSL_CAPABLE_ERROR:
		lws_tls_restrict_return_handshake(wsi);
		lwsl_info("%s: SSL_accept failed socket %u: %d\n",
				__func__, wsi->desc.sockfd, n);
		wsi->socket_is_permanently_unusable = 1;
		return 1;

	default: /* MORE_SERVICE */
		// lwsl_notice("%s: %s: MORE_SERVICE (%d), setting LRS_SSL_ACK_PENDING\n", __func__, lws_wsi_tag(wsi), n);
		if (n == LWS_SSL_CAPABLE_MORE_SERVICE_READ) {
			if (lws_change_pollfd(wsi, 0, LWS_POLLIN))
				return 1;
		} else if (n == LWS_SSL_CAPABLE_MORE_SERVICE_WRITE) {
			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
				return 1;
		}
		lwsi_set_state(wsi, LRS_SSL_ACK_PENDING);
		return 0;
	}

	/*
	 * Adapt our vhost to match the SNI SSL_CTX that was chosen.
	 *
	 * Backends whose SNI callback binds the wsi itself have already done
	 * this authoritatively (and on mbedtls the ctx does not even follow
	 * the SNI selection, so looking it up here would move him back to the
	 * listening vhost).  Leave those alone.
	 */

	if (wsi->tls.ssl && !wsi->tls.sni_vh_bound) {
		vh = lws_tls_vhost_owning_ctx(context, lws_tls_ctx_from_wsi(wsi));
		if (vh) {
			lwsl_info("setting wsi to vh %s\n", vh->name);
			/*
			 * lws_vhost_bind_wsi() releases the count we hold on
			 * the accepting vhost itself, so we must NOT unbind
			 * here first: doing so clears wsi->a.vhost, and both
			 * of the refusals in lws_vhost_bind_wsi() (the dying
			 * vhost one and the mTLS rebind one) are conditioned
			 * on it being non-NULL, ie, unbinding first silently
			 * turns them off for this rebind.
			 *
			 * Neither refusal can wrongly reject the SNI move:
			 * this vhost's SSL_CTX and verify mode are what the
			 * handshake just completed under, so if it requires a
			 * client cert, the peer already presented a verified
			 * one... which is exactly what we record here first,
			 * whether or not the bind is then allowed, since it
			 * is a fact about the handshake rather than about
			 * where he ends up bound (C-318).
			 */
			lws_tls_wsi_record_hs_ca(wsi, vh);
			lws_vhost_bind_wsi(vh, wsi);
		} else {
			lwsl_wsi_notice(wsi, "no vhost owns the tls ctx this "
					     "connection handshaked under");
			lws_tls_wsi_record_hs_ca(wsi, wsi->a.vhost);
		}
	}

	/*
	 * Whichever vhost he ends up on, this handshake has to satisfy that
	 * vhost's client-certificate policy.  If a rebind above (or in the
	 * SNI callback) was refused, he is still on the vhost that accepted
	 * him, while the handshake completed under the policy of the vhost he
	 * named... which may not have asked for a client cert at all.  We
	 * cannot ask for one now, so drop the connection rather than serve
	 * him from an mTLS vhost whose requirement he did not meet.
	 */

	if (wsi->tls.ssl && wsi->a.vhost &&
	    lws_vhost_mtls_unsatisfied(wsi, wsi->a.vhost)) {
		lwsl_wsi_notice(wsi, "dropping: vh %s requires a client cert "
				     "this handshake did not provide",
				     wsi->a.vhost->name);
		wsi->socket_is_permanently_unusable = 1;

		return 1;
	}

	/* OK, we are accepted... give him some time to negotiate */
	lws_set_timeout(wsi, PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
			(int)context->timeout_secs);

	lwsi_set_state(wsi, LRS_ESTABLISHED);
	if (lws_tls_server_conn_alpn(wsi)) {
		lwsl_warn("%s: fail on alpn\n", __func__);
		return 1; /* fail */
	}
	lwsl_debug("accepted new SSL conn\n");


	/* continue establishment */
	wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	return 0;
}

int
lws_server_socket_service_ssl(struct lws *wsi, lws_sockfd_type accept_fd, char from_pollin)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	ssize_t s;
	int n;

	if (!LWS_SSL_ENABLED(wsi->a.vhost))
		return 0;

	switch (lwsi_state(wsi)) {
	case LRS_SSL_INIT:

		if (wsi->tls.ssl)
			lwsl_err("%s: leaking ssl\n", __func__);
		if (accept_fd == LWS_SOCK_INVALID)
			assert(0);

		if (lws_tls_restrict_borrow(wsi)) {
			lwsl_err("%s: failed on ssl restriction\n", __func__);
			return 1;
		}

#if defined(LWS_WITH_LATENCY)
		lws_usec_t _ssl_new_start = lws_now_usecs();
#endif

		if (lws_tls_server_new_nonblocking(wsi, accept_fd)) {
			lwsl_err("%s: failed on lws_tls_server_new_nonblocking\n", __func__);
			if (accept_fd != LWS_SOCK_INVALID)
				compatible_close(accept_fd);
			lws_tls_restrict_return(wsi);
			goto fail;
		}

#if defined(LWS_WITH_LATENCY)
		{
			unsigned int ms = (unsigned int)((lws_now_usecs() - _ssl_new_start) / 1000);
			if (ms > 2)
				lws_latency_note(pt, _ssl_new_start, 2000, "sslnew:%dms", ms);
		}
#endif

		/*
		 * we are not accepted yet, but we need to enter ourselves
		 * as a live connection.  That way we can retry when more
		 * pieces come if we're not sorted yet
		 */
		lwsi_set_state(wsi, LRS_SSL_ACK_PENDING);

		lws_pt_lock(pt, __func__);
		if (__insert_wsi_socket_into_fds(context, wsi)) {
			lwsl_err("%s: failed to insert into fds\n", __func__);
			/* we must not leave the pt locked on the error path */
			lws_pt_unlock(pt);
			goto fail;
		}
		lws_pt_unlock(pt);

		lws_set_timeout(wsi, PENDING_TIMEOUT_SSL_ACCEPT,
				(int)context->timeout_secs);

		lwsl_debug("inserted SSL accept into fds, trying SSL_accept\n");

		/* fallthru */

	case LRS_SSL_ACK_PENDING:

		// lwsl_notice("%s: %s: entering LRS_SSL_ACK_PENDING, from_pollin=%d\n", __func__, lws_wsi_tag(wsi), from_pollin);

		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_err("%s: lws_change_pollfd failed\n", __func__);
			goto fail;
		}

		if (wsi->a.vhost->tls.allow_non_ssl_on_ssl_port && !wsi->skip_fallback) {
			/*
			 * We came here by POLLIN, so there is supposed to be
			 * something to read...
			 */

			s = recv(wsi->desc.sockfd, (char *)pt->serv_buf,
				 context->pt_serv_buf_size, MSG_PEEK);
			/*
			 * We have LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT..
			 * this just means don't hang up on him because of no
			 * tls hello... what happens next is driven by
			 * additional option flags:
			 *
			 * none: fail the connection
			 *
			 * LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS:
			 *     Destroy the TLS, issue a redirect using plaintext
			 *     http (this may not be accepted by a client that
			 *     has visited the site before and received an STS
			 *     header).
			 *
			 * LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER:
			 *     Destroy the TLS, continue and serve normally
			 *     using http
			 *
			 * LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG:
			 *     Destroy the TLS, apply whatever role and protocol
			 *     were told in the vhost info struct
			 *     .listen_accept_role / .listen_accept_protocol and
			 *     continue with that
			 */

			if (s >= 1 && pt->serv_buf[0] >= ' ') {
				/*
				* TLS content-type for Handshake is 0x16, and
				* for ChangeCipherSpec Record, it's 0x14
				*
				* A non-ssl session will start with the HTTP
				* method in ASCII.  If we see it's not a legit
				* SSL handshake kill the SSL for this
				* connection and try to handle as a HTTP
				* connection upgrade directly.
				*/
				wsi->tls.use_ssl = 0;

				lws_tls_server_abort_connection(wsi);
				/*
				 * care... this creates wsi with no ssl when ssl
				 * is enabled and normally mandatory
				 */
				wsi->tls.ssl = NULL;

				/*
				 * The backend lws_ssl_close() paths that return
				 * the tls restriction slot and the vhost
				 * SSL_CTX ref are all gated on wsi->tls.ssl,
				 * which we just cleared.  So we have to hand
				 * both back here, or an unauthenticated peer
				 * can permanently exhaust
				 * .simultaneous_ssl_restriction (which also
				 * gates accepts) and pin the vhost's SSL_CTX,
				 * with one plaintext byte per connection.
				 */

				lws_tls_restrict_return(wsi);
				if (wsi->tls.ctx_ref) {
					lws_tls_ctx_ref_unref(wsi->tls.ctx_ref);
					wsi->tls.ctx_ref = NULL;
				}

				if (lws_check_opt(wsi->a.vhost->options,
				    LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS)) {
					lwsl_info("%s: redirecting from http "
						  "to https\n", __func__);
					wsi->tls.redirect_to_https = 1;
					goto notls_accepted;
				}

				if (lws_check_opt(wsi->a.vhost->options,
				LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER)) {
					lwsl_info("%s: allowing unencrypted "
						  "http service on tls port\n",
						  __func__);
					goto notls_accepted;
				}

				if (lws_check_opt(wsi->a.vhost->options,
		    LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG)) {
					if (lws_http_to_fallback(wsi, NULL, 0))
						goto fail;
					lwsl_info("%s: allowing non-tls "
						  "fallback\n", __func__);
					goto notls_accepted;
				}

				char ipbuf[64];

				lws_get_peer_simple(wsi, ipbuf, sizeof(ipbuf));
				lwsl_notice("%s: client did not send a valid "
					    "tls hello (default vhost %s) from %s\n",
					    __func__, wsi->a.vhost->name, ipbuf);
				lwsl_hexdump_notice(pt->serv_buf, s > 256 ? 256 : (size_t)s);
				goto fail;
			}
			if (!s) {
				/*
				 * POLLIN but nothing to read is supposed to
				 * mean the connection is gone, we should
				 * fail out...
				 *
				 */
				lwsl_debug("%s: PEEKed 0 (from_pollin %d)\n",
					  __func__, from_pollin);
				if (!from_pollin) {
					/*
					 * If this wasn't actually info from a
					 * pollin let it go around again until
					 * either data came or we still get told
					 * zero length peek AND POLLIN
					 */
					if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
						lwsl_err("%s: change_pollfd failed\n",
							  __func__);
						return -1;
					}

					lwsl_info("SSL_ERROR_WANT_READ\n");
					return 0;
				}

				/*
				 * treat as remote closed
				 */

				goto fail;
			}
			if (s < 0 && (LWS_ERRNO == LWS_EAGAIN ||
				      LWS_ERRNO == LWS_EWOULDBLOCK)) {

				/*
				 * well, we get no way to know ssl or not
				 * so go around again waiting for something
				 * to come and give us a hint, or timeout the
				 * connection.
				 */
				// lwsl_notice("%s: %s: punting (no data peeked)\n", __func__, lws_wsi_tag(wsi));
				if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
					lwsl_err("%s: change_pollfd failed\n",
						  __func__);
					return -1;
				}

				lwsl_info("SSL_ERROR_WANT_READ\n");
				return 0;
			}
		}

		/* normal SSL connection processing path */

#if defined(LWS_WITH_ASYNC_QUEUE)
		if (lwsi_state(wsi) != LRS_AWAITING_SSL_ACCEPT && context->count_async_threads) {
			struct lws_async_job *job;

			if (lws_change_pollfd(wsi, LWS_POLLIN | LWS_POLLOUT, 0)) {
				lwsl_err("%s: lws_change_pollfd failed\n", __func__);
				goto fail;
			}

			job = lws_zalloc(sizeof(*job), "async ssl job");
			if (!job)
				goto fail;

			job->wsi = wsi;
			wsi->async_worker_job = job;
			job->type = LWS_AQ_SSL_ACCEPT;

			//lwsl_notice("%s: %s: QUEUING LWS_AQ_SSL_ACCEPT\n", __func__, lws_wsi_tag(wsi));

			pthread_mutex_lock(&context->async_worker_mutex);
			if (lws_dll2_count(&context->async_worker_waiting) >=
			    (uint32_t)(context->count_async_threads * 10)) {
				pthread_mutex_unlock(&context->async_worker_mutex);
				lws_free(job);
				wsi->async_worker_job = NULL;
				goto fail;
			}
			lws_dll2_add_tail(&job->list, &context->async_worker_waiting);

			if (context->async_worker_threads_idle == 0 &&
			    context->async_worker_threads_active < context->count_async_threads) {
				pthread_t pt_th;
				context->async_worker_threads_active++;
				if (pthread_create(&pt_th, NULL, lws_async_worker_worker, context) == 0)
					pthread_detach(pt_th);
				else
					context->async_worker_threads_active--;
			}

			/* wake up any idle worker threads */
			pthread_cond_signal(&context->async_worker_cond);

			pthread_mutex_unlock(&context->async_worker_mutex);

			lwsi_set_state(wsi, LRS_AWAITING_SSL_ACCEPT);
			return 0;
		}
#endif

		errno = 0;
#if defined(LWS_WITH_LATENCY)
		lws_usec_t _ssl_acc_start = lws_now_usecs();
#endif
		n = lws_tls_server_accept(wsi);

#if defined(LWS_WITH_LATENCY)
		{
			unsigned int ms = (unsigned int)((lws_now_usecs() - _ssl_acc_start) / 1000);
			if (ms > 2)
				lws_latency_note(pt, _ssl_acc_start, 2000, "sslacc:%dms", ms);
		}
#endif

		if (lws_tls_server_accept_completed(wsi, n))
			goto fail;

		if (lwsi_state(wsi) != LRS_ESTABLISHED)
			return 0;

		break;

	default:
		break;
	}

	return 0;

notls_accepted:
	lwsi_set_state(wsi, LRS_ESTABLISHED);

	return 0;

fail:
	return 1;
}
#endif

