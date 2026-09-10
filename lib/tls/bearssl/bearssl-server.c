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
#include "private-lib-tls-bearssl.h"


int
lws_tls_vhost_backend_create_ctx(struct lws_vhost *vhost)
{
	struct lws_tls_ctx *ctx;

	ctx = lws_zalloc(sizeof(*ctx), "bearssl server ctx");
	if (!ctx)
		return 1;

	vhost->tls.ssl_ctx = ctx;

	/* the app's override for the TLS 1.2 floor, see
	 * lws_bearssl_engine_set_floor() */
	ctx->options_clear = vhost->tls.ssl_options_clear;

	return 0;
}



int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
			  struct lws_vhost *vhost, struct lws *wsi)
{
	int n;

	/*
	 * mTLS is not implemented on this backend (see the note on
	 * lws_tls_server_client_cert_verify_config() in bearssl-x509.c)...
	 * refuse to create a vhost that asks for it rather than accept every
	 * anonymous client on a vhost the app believes is protected
	 */

	if (lws_tls_bearssl_vh_wants_client_certs(vhost)) {
		lwsl_err("%s: vh %s: BearSSL backend has no client cert "
			 "verification, refusing vhost\n", __func__,
			 vhost->name);

		return 1;
	}

	if (lws_tls_vhost_backend_create_ctx(vhost))
		return 1;

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem))
		return 0;

	n = (int)lws_tls_generic_cert_checks(vhost, info->ssl_cert_filepath,
					     info->ssl_private_key_filepath);

	if (n == LWS_TLS_EXTANT_NO &&
	    (vhost->options & LWS_SERVER_OPTION_IGNORE_MISSING_CERT)) {
		lwsl_notice("No certs found, continuing without SSL_CTX\n");
		lws_free_set_NULL(vhost->tls.ssl_ctx);
		return 0;
	}

	n = lws_tls_server_certs_load(vhost, wsi, info->ssl_cert_filepath,
			info->ssl_private_key_filepath,
			info->server_ssl_cert_mem,
			info->server_ssl_cert_mem_len,
			info->server_ssl_private_key_mem,
			info->server_ssl_private_key_mem_len);

	if (n) {
		lwsl_err("%s: failed to load certs\n", __func__);
		return 1;
	}

	return 0;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_tls_conn *conn;

	conn = lws_zalloc(sizeof(*conn), "bearssl conn");
	if (!conn)
		return -1;

	wsi->tls.ssl = (lws_tls_conn *)conn;
	conn->is_client = 0;
	wsi->tls.ctx_ref = lws_tls_ctx_ref_get(wsi->a.vhost);
	conn->ctx = wsi->tls.ctx_ref ? wsi->tls.ctx_ref->ctx : wsi->a.vhost->tls.ssl_ctx;

	return 0;
}

/*
 * Server-side SNI.
 *
 * BearSSL does expose the name the client asked for, but only from inside
 * the br_ssl_server_policy_class "choose" hook, and by the time that runs the
 * engine has already matched the ALPN list and reduced the cipher suites to
 * those common with the ClientHello... both of which are set up from the
 * vhost.  Worse, whether the engine can speak RSA or EC suites at all was
 * decided by which br_ssl_server_init_full_*() we called before the
 * handshake, so a "choose" hook could not move the connection onto a vhost
 * whose key is of the other type.
 *
 * So we take the name out of the ClientHello ourselves (peeking at the
 * socket, the engine still reads the same bytes afterwards) and select the
 * vhost before the engine is initialized at all.  Then the chain, the key,
 * the suite profile, the client-cert policy, the ALPN list and the session
 * cache are all the selected vhost's from the start.
 *
 * Returns 0 if the handshake may proceed on wsi's (possibly just changed)
 * vhost, 1 if we need more bytes from him first, or -1 if he has been refused
 * (the alert is already on its way).
 */

static int
lws_bearssl_server_sni(struct lws *wsi)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	struct lws_vhost *vh = wsi->a.vhost;
	struct lws_tls_ctx_ref *ref;
	char name[256];
	uint8_t ver[2];
	int s, n;

	/*
	 * Peek: we must not consume anything, the engine is going to read the
	 * ClientHello from the socket itself in the usual way.
	 *
	 * We peek into the connection's own record input buffer: the engine
	 * is not initialized yet, so nothing owns it, and it is by definition
	 * big enough for the largest record TLS can send us.  (Using the pt
	 * serv buf instead would not be safe on the async accept worker.)
	 */

	s = (int)recv(wsi->desc.sockfd, (char *)conn->iobuf_in,
		      LWS_POSIX_LENGTH_CAST(sizeof(conn->iobuf_in)), MSG_PEEK);
	if (s <= 0) {
		if (s < 0 && (LWS_ERRNO == LWS_EAGAIN ||
			      LWS_ERRNO == LWS_EWOULDBLOCK))
			return 1;

		/*
		 * He hung up, or the socket is broken... nothing to decide,
		 * let the engine discover it the same way it did before
		 */

		return 0;
	}

	n = lws_tls_client_hello_sni(conn->iobuf_in, (size_t)s, name,
				     sizeof(name));

	if (n == LWS_TLS_CH_SNI_MORE) {
		if ((size_t)s < sizeof(conn->iobuf_in))
			/* the rest of his ClientHello is still coming */
			return 1;

		/*
		 * He filled the record buffer without completing a
		 * ClientHello, so there is no name in there to find
		 */

		n = LWS_TLS_CH_SNI_NONE;
	}

	if (n == LWS_TLS_CH_SNI_NONE)
		/* he named nothing: he is served by the vhost that accepted him */
		return 0;

	if (n == LWS_TLS_CH_SNI_FOUND && !lws_tls_server_sni_select(wsi, name)) {

		if (wsi->a.vhost == vh)
			return 0;

		/*
		 * We moved him to another vhost: the lifetime reference the
		 * accept took has to follow, or the handshake would run with
		 * the accepting vhost's chain and key
		 */

		ref = lws_tls_ctx_ref_get(wsi->a.vhost);
		if (wsi->tls.ctx_ref)
			lws_tls_ctx_ref_unref(wsi->tls.ctx_ref);
		wsi->tls.ctx_ref = ref;
		conn->ctx = ref ? ref->ctx : wsi->a.vhost->tls.ssl_ctx;

		return 0;
	}

	/*
	 * Either he named something served by no vhost on this listener, or
	 * what he put in the server_name extension is not usable as a name.
	 * Refuse him with the same fatal alert the other backends send, and
	 * echo the record version he used so he can parse it.
	 */

	ver[0] = conn->iobuf_in[1];
	ver[1] = conn->iobuf_in[2];

	lws_tls_server_send_alert(wsi, ver, LWS_TLS_ALERT_UNRECOGNIZED_NAME);

	wsi->socket_is_permanently_unusable = 1;

	return -1;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	unsigned st;
	int err;

	if (!conn->initialized) {
		/*
		 * the ctx the accept took the lifetime reference on... the
		 * vhost's current tls.ssl_ctx may already be a different one
		 * (cert rotation), and BearSSL keeps the chain / key / cache
		 * pointers we give it for the life of the connection
		 */
		struct lws_tls_ctx *ctx;
		int n = lws_bearssl_server_sni(wsi);

		if (n < 0)
			return LWS_SSL_CAPABLE_ERROR;

		if (n > 0)
			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

		/* the SNI selection may have moved us to another vhost's ctx */

		ctx = conn->ctx;

		if (lws_tls_bearssl_vh_wants_client_certs(wsi->a.vhost)) {
			lwsl_err("%s: vh %s wants client certs, unsupported\n",
				 __func__, wsi->a.vhost->name);

			return LWS_SSL_CAPABLE_ERROR;
		}

		if (!ctx || !ctx->chain) {
			lwsl_err("%s: no server certs\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		if (ctx->is_rsa) {
			br_ssl_server_init_full_rsa(&conn->u.server, ctx->chain, ctx->chain_len, &ctx->rsa_key);
		} else {
			br_ssl_server_init_full_ec(&conn->u.server, ctx->chain, ctx->chain_len,
						   BR_KEYTYPE_EC, &ctx->ec_key);
		}

		/* must follow br_ssl_server_init_full_*(), which set the
		 * version range back to TLS 1.0 - 1.2 */
		lws_bearssl_engine_set_floor(&conn->u.server.eng,
					     ctx->options_clear);

		br_ssl_engine_set_buffers_bidi(&conn->u.server.eng, conn->iobuf_in, sizeof(conn->iobuf_in), conn->iobuf_out, sizeof(conn->iobuf_out));

		if (wsi->a.vhost->tls.alpn_ctx.len) {
			lws_bearssl_set_alpn(conn, wsi->a.vhost->tls.alpn_ctx.data,
					     wsi->a.vhost->tls.alpn_ctx.len);
		}

#if defined(LWS_WITH_TLS_SESSIONS)
		if (ctx->lru_buffer)
			br_ssl_server_set_cache(&conn->u.server, &ctx->lru.vtable);
#endif

		br_ssl_server_reset(&conn->u.server);
		conn->initialized = 1;
	}

	st = br_ssl_engine_current_state(&conn->u.server.eng);
	if (st == BR_SSL_CLOSED) {
		err = br_ssl_engine_last_error(&conn->u.server.eng);
		lwsl_err("%s: BearSSL handshake failed: %d\n", __func__, err);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (lws_bearssl_pump(wsi) < 0) {
		lwsl_err("%s: BearSSL pump failed\n", __func__);
		return LWS_SSL_CAPABLE_ERROR;
	}

	st = br_ssl_engine_current_state(&conn->u.server.eng);
	if (st == BR_SSL_CLOSED) {
		err = br_ssl_engine_last_error(&conn->u.server.eng);
		lwsl_err("%s: BearSSL handshake failed: %d\n", __func__, err);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (st & BR_SSL_SENDREC)
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	if (st & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) {
		lwsl_info("%s: server accept OK\n", __func__);

		if (lws_ssl_pending(wsi)) {
			struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
			if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
				lws_dll2_add_head(&wsi->tls.dll_pending_tls,
						  &pt->tls.dll_pending_tls_owner);
		}

		return LWS_SSL_CAPABLE_DONE;
	}

	return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
}


enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	return LWS_SSL_CAPABLE_ERROR;
}
