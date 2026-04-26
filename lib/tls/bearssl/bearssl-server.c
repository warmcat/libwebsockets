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
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
			  struct lws_vhost *vhost, struct lws *wsi)
{
	int n = lws_tls_server_certs_load(vhost, wsi, info->ssl_cert_filepath,
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
	conn->ctx = wsi->a.vhost->tls.ssl_ctx;

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	struct lws_tls_ctx *ctx = wsi->a.vhost->tls.ssl_ctx;
	unsigned st;
	int err;

	if (!conn->initialized) {
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

		br_ssl_engine_set_buffer(&conn->u.server.eng, conn->iobuf_in, sizeof(conn->iobuf_in), 1);
		br_ssl_engine_set_buffer(&conn->u.server.eng, conn->iobuf_out, sizeof(conn->iobuf_out), 0);

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
