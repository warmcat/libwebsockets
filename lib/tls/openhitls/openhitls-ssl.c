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
 * OpenHiTLS core SSL/TLS operations
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

#if defined(LWS_WITH_TLS_KEYLOG)
void
lws_openhitls_klog_dump(HITLS_Ctx *ctx, const char *line)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData(ctx);
	char path[128], hdr[128], ts[64];
	size_t w = 0, wx = 0;
	int fd, t;

	if (!wsi || !wsi->a.context->keylog_file[0] || !wsi->a.vhost)
		return;

	lws_snprintf(path, sizeof(path), "%s.%s", wsi->a.context->keylog_file,
			wsi->a.vhost->name);

	fd = open(path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (fd == -1) {
		lwsl_vhost_warn(wsi->a.vhost, "Failed to append %s", path);
		return;
	}

	if (!strncmp(line, "SERVER_HANDSHAKE_TRAFFIC_SECRET", 31)) {
		w += (size_t)write(fd, "\n# ", 3);
		wx += 3;
		t = lwsl_timestamp(LLL_WARN, ts, sizeof(ts));
		wx += (size_t)t;
		w += (size_t)write(fd, ts, (size_t)t);

		t = lws_snprintf(hdr, sizeof(hdr), "%s\n", wsi->lc.gutag);
		w += (size_t)write(fd, hdr, (size_t)t);
		wx += (size_t)t;

		lwsl_vhost_warn(wsi->a.vhost, "appended ssl keylog: %s", path);
	}

	wx += strlen(line) + 1;
	w += (size_t)write(fd, line,
#if defined(WIN32)
			(unsigned int)
#endif
			strlen(line));
	w += (size_t)write(fd, "\n", 1);
	close(fd);

	if (w != wx)
		lwsl_vhost_warn(wsi->a.vhost, "Failed to write %s", path);
}
#endif

/*
 * BSL_UIO helper functions
 */

int
lws_openhitls_describe_cipher(struct lws *wsi)
{
#if !defined(LWS_WITH_NO_LOGS)
	const HITLS_Cipher *cipher;
	const char *desc = "";
	const char *name = "(NONE)";
	const char *std_name = "(NONE)";
	uint8_t desc_buf[160] = {0};
	int32_t version = 0;

	if (!wsi || !wsi->tls.ssl) {
		return 0;
	}

	cipher = HITLS_GetCurrentCipher(wsi->tls.ssl);
	if (!cipher) {
		lwsl_info("%s: %s: no negotiated cipher\n", __func__,
			  lws_wsi_tag(wsi));
		return 0;
	}

	if (HITLS_CFG_GetCipherSuiteName(cipher)) {
		name = (const char *)HITLS_CFG_GetCipherSuiteName(cipher);
	}
	if (HITLS_CFG_GetCipherSuiteStdName(cipher)) {
		std_name = (const char *)HITLS_CFG_GetCipherSuiteStdName(cipher);
	}
	if (HITLS_CFG_GetDescription(cipher, desc_buf,
				     (int32_t)sizeof(desc_buf)) == HITLS_SUCCESS &&
	    desc_buf[0]) {
		desc = (const char *)desc_buf;
	}
	(void)HITLS_CFG_GetCipherVersion(cipher, &version);

	lwsl_info("%s: %s: %s, %s, 0x%x, %s\n", __func__, lws_wsi_tag(wsi),
		  name, std_name, (unsigned int)version, desc);
#endif
	return 0;
}

int
lws_ssl_get_error(struct lws *wsi, int n)
{
	n = HITLS_GetError(wsi->tls.ssl, n);

	if (n == HITLS_ERR_TLS || n == HITLS_ERR_SYSCALL) {
		const char *desc = BSL_ERR_GetString(n);

		lwsl_debug("%s: %p 0x%x (errno %d)\n", __func__,
			   (void *)wsi->tls.ssl, n, LWS_ERRNO);
		if (!wsi->tls.err_helper[0] && desc && desc[0]) {
			lws_strncpy(wsi->tls.err_helper, desc,
							    sizeof(wsi->tls.err_helper));
		}
		lws_tls_err_describe_clear();
	}

	return n;
}

#if defined(LWS_WITH_SERVER)
static int32_t
lws_context_init_ssl_pem_passwd_cb(char *buf, int32_t bufLen, int32_t flag,
				   void *userdata)
{
	struct lws_context_creation_info *info =
			(struct lws_context_creation_info *)userdata;

	(void)flag;

	lws_strncpy(buf, info->ssl_private_key_password, (size_t)bufLen);

	return (int32_t)strlen(buf);
}
#endif

#if defined(LWS_WITH_CLIENT)
static int32_t
lws_context_init_ssl_pem_passwd_client_cb(char *buf, int32_t bufLen, int32_t flag,
					  void *userdata)
{
	struct lws_context_creation_info *info =
			(struct lws_context_creation_info *)userdata;
	const char *p;

	(void)flag;

	p = info->ssl_private_key_password;
	if (info->client_ssl_private_key_password) {
		p = info->client_ssl_private_key_password;
	}

	lws_strncpy(buf, p, (size_t)bufLen);

	return (int32_t)strlen(buf);
}
#endif

void
lws_ssl_bind_passphrase(lws_tls_ctx *ssl_ctx, int is_client,
			const struct lws_context_creation_info *info)
{
	HITLS_Config *config;

	if (
#if defined(LWS_WITH_SERVER)
		!info->ssl_private_key_password
#endif
#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_CLIENT)
			&&
#endif
#if defined(LWS_WITH_CLIENT)
	    !info->client_ssl_private_key_password
#endif
		    )
		{
		return;
	}

	config = ssl_ctx;
	/*
	 * password provided, set ssl callback and user data
	 * for checking password which will be trigered during
	 * HITLS_CFG_UsePrivateKeyFile function
	 */
	HITLS_CFG_SetDefaultPasswordCbUserdata(config, (void *)info);
	HITLS_CFG_SetDefaultPasswordCb(config, is_client ?
#if defined(LWS_WITH_CLIENT)
				      lws_context_init_ssl_pem_passwd_client_cb:
#else
					NULL:
#endif
#if defined(LWS_WITH_SERVER)
				      lws_context_init_ssl_pem_passwd_cb
#else
				      	NULL
#endif
				  );
}

#if defined(LWS_WITH_CLIENT)
static void
lws_ssl_destroy_client_ctx(struct lws_vhost *vhost)
{
	if (vhost->tls.user_supplied_ssl_ctx || !vhost->tls.ssl_client_ctx) {
		return;
	}

	if (vhost->tls.tcr && --vhost->tls.tcr->refcount) {
		return;
	}

	HITLS_CFG_FreeConfig(vhost->tls.ssl_client_ctx);
	vhost->tls.ssl_client_ctx = NULL;

	vhost->context->tls.count_client_contexts--;

	if (vhost->tls.tcr) {
		lws_dll2_remove(&vhost->tls.tcr->cc_list);
		lws_free(vhost->tls.tcr);
		vhost->tls.tcr = NULL;
	}
}
#endif

void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	if (!lws_check_opt(vhost->context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		return;
	}

	if (vhost->tls.ssl_ctx) {
		lws_tls_ctx *ctx = vhost->tls.ssl_ctx;

		HITLS_CFG_FreeConfig(ctx);
		vhost->tls.ssl_ctx = NULL;
	}

#if defined(LWS_WITH_CLIENT)
	lws_ssl_destroy_client_ctx(vhost);
#endif
}

int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	uint32_t readlen = 0;
	int ret, n, m;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

#ifndef WIN32
	errno = 0;
#else
	WSASetLastError(0);
#endif
	ret = HITLS_Read(wsi->tls.ssl, buf, (uint32_t)len, &readlen);
#if defined(LWS_PLAT_FREERTOS)
	if (ret != HITLS_SUCCESS && errno == LWS_ENOTCONN) {
		lwsl_debug("%s: SSL_read ENOTCONN\n", lws_wsi_tag(wsi));
		return LWS_SSL_CAPABLE_ERROR;
	}
#endif
	lwsl_debug("%s: SSL_read says %d\n", lws_wsi_tag(wsi), ret);

	/* Translate HITLS error into a generic error code, then handle */
	n = (ret == HITLS_SUCCESS) ? (int)readlen : 0;

	if (n <= 0) {
		m = lws_ssl_get_error(wsi, ret);
		lwsl_debug("%s: ssl err %d errno %d\n", lws_wsi_tag(wsi), m, LWS_ERRNO);
		/* unclean, eg closed conn */
		if (m == HITLS_ERR_TLS || m == HITLS_ERR_SYSCALL ||
		    LWS_ERRNO == LWS_ENOTCONN) {
			wsi->socket_is_permanently_unusable = 1;
#if defined(LWS_WITH_SYS_METRICS)
			if (wsi->a.vhost)
				lws_metric_event(wsi->a.vhost->mt_traffic_rx,
						 METRES_NOGO, 0);
#endif
			return LWS_SSL_CAPABLE_ERROR;
		}

		/* retryable */
		if (m == HITLS_WANT_READ) {
			lwsl_debug("%s: WANT_READ\n", __func__);
			lwsl_debug("%s: LWS_SSL_CAPABLE_MORE_SERVICE_READ\n", lws_wsi_tag(wsi));
			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		}
		if (m == HITLS_WANT_WRITE) {
			lwsl_info("%s: WANT_WRITE\n", __func__);
			lwsl_debug("%s: LWS_SSL_CAPABLE_MORE_SERVICE_WRITE\n", lws_wsi_tag(wsi));
			wsi->tls_read_wanted_write = 1;
			lws_callback_on_writable(wsi);
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}

		/* keep on trucking it seems */
	}

#if defined(LWS_TLS_LOG_PLAINTEXT_RX)
	/*
	 * If using openssl type tls library, this is the earliest point for all
	 * paths to dump what was received as decrypted data from the tls tunnel
	 */
	lwsl_notice("%s: len %d\n", __func__, n);
	lwsl_hexdump_notice(buf, (size_t)n);
#endif

#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->a.vhost)
		lws_metric_event(wsi->a.vhost->mt_traffic_rx,
				 METRES_GO, (u_mt_t)n);
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

	if (HITLS_GetReadPendingBytes(wsi->tls.ssl)) {
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
	if (!wsi->tls.ssl) {
		return 0;
	}

	return (int)HITLS_GetReadPendingBytes(wsi->tls.ssl);
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	uint32_t writelen = 0;
	int ret;

#if defined(LWS_TLS_LOG_PLAINTEXT_TX)
	lwsl_notice("%s: len %u\n", __func__, (unsigned int)len);
	lwsl_hexdump_notice(buf, len);
#endif

	if (!wsi->tls.ssl) {
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);
	}

	ret = HITLS_Write(wsi->tls.ssl, buf, (uint32_t)len, &writelen);

	if (ret == HITLS_SUCCESS) {
#if defined(LWS_WITH_SYS_METRICS)
		if (wsi->a.vhost) {
			lws_metric_event(wsi->a.vhost->mt_traffic_tx,
									 METRES_GO, (u_mt_t)writelen);
		}
#endif
		return (int)writelen;
	}

	/* Handle non-blocking and error cases */
	ret = lws_ssl_get_error(wsi, ret);
	if (ret != HITLS_ERR_SYSCALL) {
		if (ret == HITLS_WANT_READ) {
			lwsl_notice("%s: want read during write\n", __func__);
			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		}

		if (ret == HITLS_WANT_WRITE) {
			lws_set_blocking_send(wsi);
			lwsl_debug("%s: want write\n", __func__);
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}
	}

	lwsl_debug("%s: write error: 0x%x\n", __func__, ret);
	lws_tls_err_describe_clear();

	wsi->socket_is_permanently_unusable = 1;
#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->a.vhost) {
		lws_metric_event(wsi->a.vhost->mt_traffic_tx, METRES_NOGO, 0);
	}
#endif
	return LWS_SSL_CAPABLE_ERROR;
}

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
	struct lws *wsi;
	struct lws_context *context;
	struct lws_ssl_info si;
	BSL_UIO *uio;
	lws_sockfd_type fd = LWS_SOCK_INVALID;

	context = (struct lws_context *)HITLS_CFG_GetConfigUserData(HITLS_GetConfig(ssl));
	if (!context)
		return;

	uio = HITLS_GetUio(ssl);
	if (!uio)
		return;

	if (BSL_UIO_Ctrl(uio, BSL_UIO_GET_FD, sizeof(fd), &fd) != BSL_SUCCESS)
		return;

	if (fd < 0 || (fd - lws_plat_socket_offset()) < 0) {
		return;
	}

	wsi = wsi_from_fd(context, fd);
	if (!wsi || !wsi->a.vhost || !wsi->a.protocol) {
		return;
	}

	if (!(where & wsi->a.vhost->tls.ssl_info_event_mask)) {
		return;
	}

	si.where = where;
	si.ret = ret;

	if (user_callback_handle_rxflow(wsi->a.protocol->callback,
					wsi, LWS_CALLBACK_SSL_INFO,
					wsi->user_space, &si, 0)) {
		lws_set_timeout(wsi, PENDING_TIMEOUT_KILLED_BY_SSL_INFO, -1);
	}
}

int
lws_ssl_close(struct lws *wsi)
{
	lws_sockfd_type n;
	BSL_UIO *uio;

	if (!wsi->tls.ssl) {
		return 0;
	} /* not handled */

	if (wsi->a.vhost->tls.ssl_info_event_mask) {
		(void)HITLS_SetInfoCb(wsi->tls.ssl, NULL);
	}

#if defined(LWS_TLS_SYNTHESIZE_CB)
	lws_sul_cancel(&wsi->tls.sul_cb_synth);
	lws_sess_cache_synth_cb(&wsi->tls.sul_cb_synth);
#endif

	/*
	 * Get the fd before any cleanup that may invalidate it.
	 */
	uio = HITLS_GetUio(wsi->tls.ssl);
	BSL_UIO_Ctrl(uio, BSL_UIO_GET_FD, sizeof(lws_sockfd_type), &n);

	

	if (lws_socket_is_valid(n))
		compatible_close(n);
	HITLS_Free(wsi->tls.ssl);
	wsi->tls.ssl = NULL;
	lws_tls_restrict_return(wsi);

	return 1; /* handled */
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	if (vhost->tls.ssl_ctx) {
		lws_tls_ctx *ctx = (lws_tls_ctx *)vhost->tls.ssl_ctx;

		HITLS_CFG_FreeConfig(ctx);
		vhost->tls.ssl_ctx = NULL;
	}

#if defined(LWS_WITH_CLIENT)
	lws_ssl_destroy_client_ctx(vhost);
#endif

#if defined(LWS_WITH_ACME)
	lws_tls_acme_sni_cert_destroy(vhost);
#endif
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
	(void)context;

	/* OpenHiTLS doesn't require global cleanup */
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	if (!wsi->tls.ssl) {
		return NULL;
	}

	return (lws_tls_ctx *)HITLS_GetGlobalConfig(wsi->tls.ssl);
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int ret;
	uint32_t state = 0;

	ret = HITLS_Close(wsi->tls.ssl);
	lwsl_debug("%s: HITLS_Close=%d for fd %d\n", __func__, ret,
		   wsi->desc.sockfd);
	HITLS_GetShutdownState(wsi->tls.ssl, &state);

	if (state == (HITLS_SENT_SHUTDOWN | HITLS_RECEIVED_SHUTDOWN)) {
		shutdown(wsi->desc.sockfd, SHUT_WR);
		return LWS_SSL_CAPABLE_DONE;
	}
	if (state == HITLS_SENT_SHUTDOWN) {
		__lws_change_pollfd(wsi, 0, LWS_POLLIN);
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
	int error = HITLS_GetError(wsi->tls.ssl, ret);
	if (error != HITLS_ERR_SYSCALL && error != HITLS_ERR_TLS) {
		if (error == HITLS_WANT_READ) {
			lwsl_debug("(wants read)\n");
			__lws_change_pollfd(wsi, 0, LWS_POLLIN);
			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		}
		if (error == HITLS_WANT_WRITE) {
			lwsl_debug("(wants write)\n");
			__lws_change_pollfd(wsi, 0, LWS_POLLOUT);
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}
	}
	return LWS_SSL_CAPABLE_ERROR;
}

static int
tops_fake_POLLIN_for_buffered_openhitls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_openhitls = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_openhitls,
        /* process_cleanup */ NULL,
};
