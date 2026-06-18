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

int openssl_websocket_private_data_index;

int lws_ssl_get_error(struct lws *wsi, int n)
{
	return 0;
}

void lws_ssl_destroy(struct lws_vhost *vhost)
{
}

int
lws_bearssl_pump(struct lws *wsi)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	unsigned st;
	int progressed = 0;

	if (!conn)
		return -1;

	st = br_ssl_engine_current_state(&conn->u.engine);

	while (1) {
		unsigned old_st = 0;
		do {
			old_st = st;
			st = br_ssl_engine_current_state(&conn->u.engine);
		} while (st != old_st && st != BR_SSL_CLOSED);

		if (st == BR_SSL_CLOSED) {
			int err = br_ssl_engine_last_error(&conn->u.engine);
			if (err) {
				lwsl_info("%s: BearSSL engine closed with err %d\n", __func__, err);
				return -1;
			}
			return 0;
		}

		if (st & BR_SSL_SENDREC) {
			size_t len;
			unsigned char *buf = br_ssl_engine_sendrec_buf(&conn->u.engine, &len);
			int n = (int)send(wsi->desc.sockfd, (const char *)buf, len, MSG_NOSIGNAL);
			// lwsl_notice("%s: sendrec_buf len %zu, send n=%d\n", __func__, len, n);
			if (n > 0) {
				br_ssl_engine_sendrec_ack(&conn->u.engine, (size_t)n);
				progressed = 1;
				continue;
			}
			if (n < 0 && (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK))
				break;
			lwsl_info("%s: send err %d\n", __func__, LWS_ERRNO);
			return -1;
		}

		if (st & BR_SSL_RECVREC) {
			size_t len;
			unsigned char *buf = br_ssl_engine_recvrec_buf(&conn->u.engine, &len);
			int n = (int)recv(wsi->desc.sockfd, (char *)buf, len, 0);
			// lwsl_notice("%s: recvrec_buf len %d, recv n=%d\n", __func__, (int)len, n);
			if (n > 0) {
				br_ssl_engine_recvrec_ack(&conn->u.engine, (size_t)n);
				progressed = 1;
				continue;
			}
			if (n < 0 && (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK))
				break;
			if (n == 0) {
				lwsl_notice("%s: peer closed\n", __func__);
				return -1;
			}
			lwsl_info("%s: recv err %d\n", __func__, LWS_ERRNO);
			return -1;
		}

		break;
	}
	int pending = lws_ssl_pending(wsi);
	// lwsl_notice("%s: pump exit progressed=%d, pending=%d, st=%x\n", __func__, progressed, pending, st);
	if (pending) {
		struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
		if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
			lws_dll2_add_head(&wsi->tls.dll_pending_tls,
					  &pt->tls.dll_pending_tls_owner);
	}

	return progressed;
}

int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	size_t alen;
	unsigned char *abuf;

	unsigned st;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	if (!conn)
		return LWS_SSL_CAPABLE_ERROR;

	do {
		/* 1. Drain whatever is already decrypted */
		st = br_ssl_engine_current_state(&conn->u.engine);
		if (st == BR_SSL_CLOSED)
			return LWS_SSL_CAPABLE_ERROR;

		if (st & BR_SSL_RECVAPP) {
			abuf = br_ssl_engine_recvapp_buf(&conn->u.engine, &alen);
			if (alen == 0) {
				br_ssl_engine_recvapp_ack(&conn->u.engine, 0);
				/* empty record consumed, pump again to get actual data */
			} else {
				if (alen > len)
					alen = len;
				memcpy(buf, abuf, alen);
				br_ssl_engine_recvapp_ack(&conn->u.engine, alen);

				if (lws_ssl_pending(wsi)) {
					if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
						lws_dll2_add_head(&wsi->tls.dll_pending_tls,
								  &pt->tls.dll_pending_tls_owner);
				} else
					lws_ssl_remove_wsi_from_buffered_list(wsi);

				return (int)alen;
			}
		}

		/* 2. Pump the engine to read from socket and decrypt */
		int pump_ret = lws_bearssl_pump(wsi);

		/* 3. Check again if anything was decrypted */
		st = br_ssl_engine_current_state(&conn->u.engine);
		if (st == BR_SSL_CLOSED)
			return LWS_SSL_CAPABLE_ERROR;

		if (st & BR_SSL_RECVAPP) {
			abuf = br_ssl_engine_recvapp_buf(&conn->u.engine, &alen);
			if (alen == 0) {
				br_ssl_engine_recvapp_ack(&conn->u.engine, 0);
				continue;
			} else {
				if (alen > len)
					alen = len;
				memcpy(buf, abuf, alen);
				br_ssl_engine_recvapp_ack(&conn->u.engine, alen);

				if (lws_ssl_pending(wsi)) {
					if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
						lws_dll2_add_head(&wsi->tls.dll_pending_tls,
								  &pt->tls.dll_pending_tls_owner);
				} else
					lws_ssl_remove_wsi_from_buffered_list(wsi);

				return (int)alen;
			}
		}

		lws_ssl_remove_wsi_from_buffered_list(wsi);

		if (pump_ret < 0)
			return LWS_SSL_CAPABLE_ERROR;

		st = br_ssl_engine_current_state(&conn->u.engine);
		if (st & BR_SSL_SENDREC)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	} while (1);
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	size_t alen;
	unsigned char *abuf;
	unsigned st;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	if (!conn)
		return LWS_SSL_CAPABLE_ERROR;

	if (conn->pending_app_data_len) {
		if (lws_bearssl_pump(wsi) < 0)
			return LWS_SSL_CAPABLE_ERROR;

		st = br_ssl_engine_current_state(&conn->u.engine);
		if (st == BR_SSL_CLOSED)
			return LWS_SSL_CAPABLE_ERROR;

		if (st & BR_SSL_SENDREC)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		int ret = (int)conn->pending_app_data_len;
		conn->pending_app_data_len = 0;
		return ret;
	}

	abuf = br_ssl_engine_sendapp_buf(&conn->u.engine, &alen);
	if (alen > 0) {
		if (alen > len)
			alen = len;
		memcpy(abuf, buf, alen);
		br_ssl_engine_sendapp_ack(&conn->u.engine, alen);
		br_ssl_engine_flush(&conn->u.engine, 0);

		if (lws_bearssl_pump(wsi) < 0)
			return LWS_SSL_CAPABLE_ERROR;

		st = br_ssl_engine_current_state(&conn->u.engine);
		if (st == BR_SSL_CLOSED)
			return LWS_SSL_CAPABLE_ERROR;

		if (st & BR_SSL_SENDREC) {
			conn->pending_app_data_len = alen;
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}

		return (int)alen;
	}

	st = br_ssl_engine_current_state(&conn->u.engine);
	if (st & BR_SSL_RECVREC)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	return LWS_SSL_CAPABLE_ERROR;
}

int lws_ssl_pending(struct lws *wsi)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	size_t alen;

	if (!wsi->tls.ssl)
		return lws_ssl_pending_no_ssl(wsi);

	if (!conn)
		return 0;

	if (br_ssl_engine_current_state(&conn->u.engine) & BR_SSL_RECVAPP)
		return 1;

	br_ssl_engine_recvapp_buf(&conn->u.engine, &alen);
	return alen > 0;
}

void lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
}

int lws_ssl_close(struct lws *wsi)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;

	if (!conn)
		return 0;

	if (conn->client_hostname)
		lws_free(conn->client_hostname);

	if (conn->peer_cert)
		lws_x509_destroy(&conn->peer_cert);
#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (conn->temp_cert)
		lws_x509_destroy(&conn->temp_cert);
#endif

	if (conn->alpn_strings) {
		size_t i;
		for (i = 0; i < conn->alpn_strings_count; i++) {
			if (conn->alpn_strings[i])
				lws_free(conn->alpn_strings[i]);
		}
		lws_free(conn->alpn_strings);
	}

	lws_free(conn);
	wsi->tls.ssl = NULL;

	if (wsi->tls.ctx_ref) {
		lws_tls_ctx_ref_unref(wsi->tls.ctx_ref);
		wsi->tls.ctx_ref = NULL;
	}

	return 0;
}

void lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
}

void lws_ssl_context_destroy(struct lws_context *context)
{
}

lws_tls_ctx * lws_tls_ctx_from_wsi(struct lws *wsi)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	if (!conn)
		return NULL;
	return conn->ctx;
}

enum lws_ssl_capable_status __lws_tls_shutdown(struct lws *wsi)
{
	return LWS_SSL_CAPABLE_ERROR;
}

static int
tops_fake_POLLIN_for_buffered_bearssl(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_bearssl = {
	.fake_POLLIN_for_buffered = tops_fake_POLLIN_for_buffered_bearssl,
};

int lws_context_init_ssl_library(struct lws_context *cx,
				 const struct lws_context_creation_info *info)
{
	return 0;
}

void lws_context_deinit_ssl_library(struct lws_context *context)
{
}

#if defined(LWS_WITH_TLS_SESSIONS)
void
lws_tls_session_cache(struct lws_vhost *vh, uint32_t ttl)
{
	/* Default to 1hr max recommendation from RFC5246 F.1.4 */
	vh->tls.tls_session_cache_ttl = !ttl ? 3600 : ttl;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return;

	if (vh->tls.ssl_ctx) {
		uint32_t max = vh->tls_session_cache_max ? vh->tls_session_cache_max : 10;
		size_t buflen = max * 128; /* approx 100 bytes per session + overhead */
		vh->tls.ssl_ctx->lru_buffer = lws_malloc(buflen, "bearssl lru cache");
		if (vh->tls.ssl_ctx->lru_buffer) {
			br_ssl_session_cache_lru_init(&vh->tls.ssl_ctx->lru,
						      vh->tls.ssl_ctx->lru_buffer,
						      buflen);
		}
	}
}

#else
int lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port, lws_tls_sess_cb_t cb_save, void *opq) { return -1; }
int lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port, lws_tls_sess_cb_t cb_load, void *opq) { return -1; }
int lws_tls_session_is_reused(struct lws *wsi) { return 0; }
int lws_tls_session_vh_destroy(struct lws_vhost *vh) { return 0; }
#endif

void
lws_tls_vhost_backend_free_ctx(lws_tls_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->chain) {
		size_t i;
		for (i = 0; i < ctx->chain_len; i++)
			if (ctx->chain[i].data)
				lws_free(ctx->chain[i].data);
		lws_free(ctx->chain);
	}

#if defined(LWS_WITH_TLS_SESSIONS)
	if (ctx->lru_buffer)
		lws_free(ctx->lru_buffer);
#endif

	lws_free(ctx);
}

int
lws_bearssl_set_alpn(struct lws_tls_conn *conn, const uint8_t *alpn, size_t alpn_len)
{
	size_t count = 0;
	size_t offset = 0;
	size_t idx = 0;

	if (!alpn || !alpn_len)
		return 0;

	/* 1. Count strings */
	while (offset < alpn_len) {
		uint8_t len = alpn[offset];
		if (offset + 1 + len > alpn_len)
			break;
		count++;
		offset += 1 + len;
	}

	if (!count)
		return 0;

	/* 2. Allocate the array of string pointers */
	conn->alpn_strings = lws_malloc(sizeof(char *) * count, "bearssl alpn");
	if (!conn->alpn_strings)
		return -1;

	/* 3. Allocate and copy each string */
	offset = 0;
	while (offset < alpn_len && idx < count) {
		uint8_t len = alpn[offset];
		conn->alpn_strings[idx] = lws_malloc(len + 1, "bearssl alpn str");
		if (!conn->alpn_strings[idx]) {
			/* Cleanup previously allocated strings on failure */
			while (idx > 0)
				lws_free(conn->alpn_strings[--idx]);
			lws_free(conn->alpn_strings);
			conn->alpn_strings = NULL;
			return -1;
		}
		memcpy(conn->alpn_strings[idx], &alpn[offset + 1], len);
		conn->alpn_strings[idx][len] = '\0';
		idx++;
		offset += 1 + len;
	}
	conn->alpn_strings_count = count;

	/* 4. Set the protocols on the engine */
	br_ssl_engine_set_protocol_names(&conn->u.engine, (const char **)conn->alpn_strings, count);

	return 0;
}
