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
#include "private-lib-tls-mbedtls.h"

#if defined(LWS_ROLE_QUIC)
extern void
mbedtls_quic_bio_free(struct lws *wsi);
#endif

void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	if (!lws_check_opt(vhost->context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return;

	if (vhost->tls.ssl_ctx)
		lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_ctx);
	if (!vhost->tls.user_supplied_ssl_ctx && vhost->tls.ssl_client_ctx)
		lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_client_ctx);

	if (vhost->tls.x509_client_CA)
		lws_free(vhost->tls.x509_client_CA);
}

#if defined(LWS_WITH_TCP_TLS)
int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n = 0, m;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	errno = 0;
	n = mbedtls_ssl_read(&wsi->tls.ssl->ssl, buf, len);
#if defined(LWS_PLAT_FREERTOS)
	if (!n && errno == LWS_ENOTCONN) {
		lwsl_debug("%s: SSL_read ENOTCONN\n", lws_wsi_tag(wsi));
		return LWS_SSL_CAPABLE_ERROR;
	}
#endif

	lwsl_debug("%s: %s: mbedtls_ssl_read says %d\n", __func__, lws_wsi_tag(wsi), n);
	/* manpage: returning 0 means connection shut down */
	if (!n || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		wsi->socket_is_permanently_unusable = 1;

		return LWS_SSL_CAPABLE_ERROR;
	}

	if (n < 0) {
		m = n;
		lwsl_debug("%s: %s: ssl err %d errno %d\n", __func__, lws_wsi_tag(wsi), m, errno);
		if (errno == LWS_ENOTCONN)
			/* If the socket isn't connected anymore, bail out. */
			goto do_err1;

#if defined(LWS_PLAT_FREERTOS)
		if (errno == LWS_ECONNABORTED)
			goto do_err1;
#endif

		if (m == MBEDTLS_ERR_SSL_WANT_READ) {
			lwsl_debug("%s: WANT_READ\n", __func__);
			lwsl_debug("%s: LWS_SSL_CAPABLE_MORE_SERVICE_READ\n", lws_wsi_tag(wsi));
			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		}
		if (m == MBEDTLS_ERR_SSL_WANT_WRITE) {
			lwsl_info("%s: WANT_WRITE\n", __func__);
			lwsl_debug("%s: LWS_SSL_CAPABLE_MORE_SERVICE_WRITE\n", lws_wsi_tag(wsi));
			wsi->tls_read_wanted_write = 1;
			lws_callback_on_writable(wsi);
			__lws_change_pollfd(wsi, LWS_POLLIN, 0);
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}

do_err1:
		wsi->socket_is_permanently_unusable = 1;

#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->a.vhost)
		lws_metric_event(wsi->a.vhost->mt_traffic_rx, METRES_NOGO, 0);
#endif
		__lws_ssl_remove_wsi_from_buffered_list(wsi);

		return LWS_SSL_CAPABLE_ERROR;
	}

#if defined(LWS_TLS_LOG_PLAINTEXT_RX)
	/*
	 * If using mbedtls type tls library, this is the earliest point for all
	 * paths to dump what was received as decrypted data from the tls tunnel
	 */
	lwsl_notice("%s: len %d\n", __func__, n);
	lwsl_hexdump_notice(buf, (size_t)n);
#endif

#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->a.vhost)
		lws_metric_event(wsi->a.vhost->mt_traffic_rx,
				 METRES_GO /* rx */, (u_mt_t)n);
#endif

	/*
	 * if it was our buffer that limited what we read,
	 * check if SSL has additional data pending inside SSL buffers.
	 *
	 * Because these won't signal at the network layer with POLLIN
	 * and if we don't realize, this data will sit there forever
	 */
	if (n != (int)len)
		goto bail;
	if (!wsi->tls.ssl)
		goto bail;

	if (mbedtls_ssl_get_bytes_avail(&wsi->tls.ssl->ssl)) {
		if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
			lws_dll2_add_head(&wsi->tls.dll_pending_tls,
					  &pt->tls.dll_pending_tls_owner);
	} else
		__lws_ssl_remove_wsi_from_buffered_list(wsi);

	return n;
bail:
	lws_ssl_remove_wsi_from_buffered_list(wsi);

	return n;
}

int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	return (int)mbedtls_ssl_get_bytes_avail(&wsi->tls.ssl->ssl);
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	int n, m;

#if defined(LWS_TLS_LOG_PLAINTEXT_TX)
	/*
	 * If using mbedtls type tls library, this is the last point for all
	 * paths before sending data into the tls tunnel, where you can dump it
	 * and see what is being sent.
	 */
	lwsl_notice("%s: len %d\n", __func__, (int)len);
	lwsl_hexdump_notice(buf, len);
#endif

	if (!wsi->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	n = mbedtls_ssl_write(&wsi->tls.ssl->ssl, buf, len);
	if (n > 0) {
#if defined(LWS_WITH_SYS_METRICS)
		if (wsi->a.vhost)
			lws_metric_event(wsi->a.vhost->mt_traffic_tx,
					 METRES_GO, (u_mt_t)n);
#endif
		return n;
	}

	m = n;
	if (m == MBEDTLS_ERR_SSL_WANT_READ) {
		lwsl_notice("%s: want read\n", __func__);

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	if (m == MBEDTLS_ERR_SSL_WANT_WRITE) {
		lws_set_blocking_send(wsi);
		lwsl_debug("%s: want write\n", __func__);

		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	lwsl_debug("%s failed: %d\n",__func__, m);
	wsi->socket_is_permanently_unusable = 1;

#if defined(LWS_WITH_SYS_METRICS)
		if (wsi->a.vhost)
			lws_metric_event(wsi->a.vhost->mt_traffic_tx,
					 METRES_NOGO, (u_mt_t)n);
#endif

	return LWS_SSL_CAPABLE_ERROR;
}
#endif

int openssl_SSL_CTX_private_data_index;

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
	/* OpenSSL specific */
}


int
lws_ssl_close(struct lws *wsi)
{
	lws_sockfd_type n;

	if (!wsi->tls.ssl)
		return 0; /* not handled */

#if defined (LWS_HAVE_SSL_SET_INFO_CALLBACK)
	/* kill ssl callbacks, becausse we will remove the fd from the
	 * table linking it to the wsi
	 */
	if (wsi->a.vhost->tls.ssl_info_event_mask)
		SSL_set_info_callback(wsi->tls.ssl, NULL);
#endif

#if defined(LWS_TLS_SYNTHESIZE_CB)
	lws_sul_cancel(&wsi->tls.sul_cb_synth);
	/*
	 * ... check the session in case it did not live long enough to get
	 * the scheduled callback to sample it
	 */
	lws_sess_cache_synth_cb(&wsi->tls.sul_cb_synth);
#endif

	n = wsi->desc.sockfd;
	if (!wsi->socket_is_permanently_unusable) {
		mbedtls_ssl_close_notify(&wsi->tls.ssl->ssl);
	}
	compatible_close(n);
#if defined(LWS_ROLE_QUIC)
	mbedtls_quic_bio_free(wsi);
#endif
	mbedtls_ssl_free(&wsi->tls.ssl->ssl);
	lws_free(wsi->tls.ssl);
	wsi->tls.ssl = NULL;

	lws_tls_restrict_return(wsi);

	if (wsi->tls.ctx_ref) {
		lws_tls_ctx_ref_unref(wsi->tls.ctx_ref);
		wsi->tls.ctx_ref = NULL;
	}

	return 1; /* handled */
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	if (vhost->tls.ssl_ctx)
		lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_ctx);

	if (!vhost->tls.user_supplied_ssl_ctx && vhost->tls.ssl_client_ctx)
		lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_client_ctx);
#if defined(LWS_WITH_ACME)
	lws_tls_acme_sni_cert_destroy(vhost);
#endif
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return NULL;

	return wsi->tls.ssl->ctx;
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int n = mbedtls_ssl_close_notify(&wsi->tls.ssl->ssl);

	lwsl_debug("mbedtls_ssl_close_notify=%d for fd %d\n", n, wsi->desc.sockfd);

	if (n == 0) {
		/* successful completion */
		(void)shutdown(wsi->desc.sockfd, SHUT_WR);
		return LWS_SSL_CAPABLE_DONE;
	}

	if (n == MBEDTLS_ERR_SSL_WANT_READ) {
		__lws_change_pollfd(wsi, 0, LWS_POLLIN);
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
		__lws_change_pollfd(wsi, 0, LWS_POLLOUT);
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}


static int
tops_fake_POLLIN_for_buffered_mbedtls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_mbedtls = {
	.fake_POLLIN_for_buffered = tops_fake_POLLIN_for_buffered_mbedtls,
};

void
lws_tls_vhost_backend_free_ctx(lws_tls_ctx *ctx)
{
	if (!ctx)
		return;

	mbedtls_ssl_config_free(&ctx->conf);

	if (ctx->chain) {
		mbedtls_x509_crt_free(ctx->chain);
		lws_free(ctx->chain);
	}
	if (ctx->ca_chain) {
		mbedtls_x509_crt_free(ctx->ca_chain);
		lws_free(ctx->ca_chain);
	}
	if (ctx->key) {
		mbedtls_pk_free(ctx->key);
		lws_free(ctx->key);
	}

	lws_free(ctx);
}
