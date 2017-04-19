/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "private-libwebsockets.h"

/* workaround for mingw */
#if !defined(ECONNABORTED)
#define ECONNABORTED 103
#endif

int lws_alloc_vfs_file(struct lws_context *context, const char *filename, uint8_t **buf,
		lws_filepos_t *amount)
{
	lws_filepos_t len;
	lws_fop_flags_t	flags = LWS_O_RDONLY;
	lws_fop_fd_t fops_fd = lws_vfs_file_open(
				lws_get_fops(context), filename, &flags);
	int ret = 1;

	if (!fops_fd)
		return 1;

	len = lws_vfs_get_length(fops_fd);

	*buf = malloc(len);
	if (!buf)
		goto bail;

	if (lws_vfs_file_read(fops_fd, amount, *buf, len))
		goto bail;

	ret = 0;
bail:
	lws_vfs_file_close(&fops_fd);

	return ret;
}

#if defined(LWS_WITH_ESP32)
int alloc_file(struct lws_context *context, const char *filename, uint8_t **buf,
	       lws_filepos_t *amount)
{
	nvs_handle nvh;
	size_t s;
	int n = 0;

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
	if (nvs_get_blob(nvh, filename, NULL, &s) != ESP_OK) {
		n = 1;
		goto bail;
	}
	*buf = malloc(s);
	if (!*buf) {
		n = 2;
		goto bail;
	}
	if (nvs_get_blob(nvh, filename, (char *)*buf, &s) != ESP_OK)
		n = 1;

	*amount = s;

bail:
	nvs_close(nvh);

	return n;
}
#endif

int openssl_websocket_private_data_index,
    openssl_SSL_CTX_private_data_index;

int lws_ssl_get_error(struct lws *wsi, int n)
{
	if (!wsi->ssl)
		return 99;
	lwsl_debug("%s: %p %d\n", __func__, wsi->ssl, n);
	return SSL_get_error(wsi->ssl, n);
}

/* Copies a string describing the code returned by lws_ssl_get_error(),
 * which may also contain system error information in the case of SSL_ERROR_SYSCALL,
 * into buf up to len.
 * Returns a pointer to buf.
 *
 * Note: the lws_ssl_get_error() code is *not* an error code that can be passed
 * to ERR_error_string(),
 *
 * ret is the return value originally passed to lws_ssl_get_error(), needed to disambiguate
 * SYS_ERROR_SYSCALL.
 *
 * See man page for SSL_get_error().
 *
 * Not thread safe, uses strerror()
 */
char* lws_ssl_get_error_string(int status, int ret, char *buf, size_t len) {
	switch (status) {
	case SSL_ERROR_NONE: return strncpy(buf, "SSL_ERROR_NONE", len);
	case SSL_ERROR_ZERO_RETURN: return strncpy(buf, "SSL_ERROR_ZERO_RETURN", len);
	case SSL_ERROR_WANT_READ: return strncpy(buf, "SSL_ERROR_WANT_READ", len);
	case SSL_ERROR_WANT_WRITE: return strncpy(buf, "SSL_ERROR_WANT_WRITE", len);
	case SSL_ERROR_WANT_CONNECT: return strncpy(buf, "SSL_ERROR_WANT_CONNECT", len);
	case SSL_ERROR_WANT_ACCEPT: return strncpy(buf, "SSL_ERROR_WANT_ACCEPT", len);
	case SSL_ERROR_WANT_X509_LOOKUP: return strncpy(buf, "SSL_ERROR_WANT_X509_LOOKUP", len);
	case SSL_ERROR_SYSCALL:
		switch (ret) {
                case 0:
                        snprintf(buf, len, "SSL_ERROR_SYSCALL: EOF");
                        return buf;
                case -1:
#ifndef LWS_PLAT_OPTEE
			snprintf(buf, len, "SSL_ERROR_SYSCALL: %s", strerror(errno));
#else
			snprintf(buf, len, "SSL_ERROR_SYSCALL: %d", errno);
#endif
			return buf;
                default:
                        return strncpy(buf, "SSL_ERROR_SYSCALL", len);
	}
	case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
	default: return "SSL_ERROR_UNKNOWN";
	}
}

void
lws_ssl_elaborate_error(void)
{
#if defined(LWS_WITH_ESP32)
#else
	char buf[256];
	u_long err;

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		lwsl_err("*** %s\n", buf);
	}
#endif
}

#if !defined(LWS_WITH_ESP32)

static int
lws_context_init_ssl_pem_passwd_cb(char * buf, int size, int rwflag, void *userdata)
{
	struct lws_context_creation_info * info =
			(struct lws_context_creation_info *)userdata;

	strncpy(buf, info->ssl_private_key_password, size);
	buf[size - 1] = '\0';

	return strlen(buf);
}

void
lws_ssl_bind_passphrase(SSL_CTX *ssl_ctx, struct lws_context_creation_info *info)
{
	if (!info->ssl_private_key_password)
		return;
	/*
	 * password provided, set ssl callback and user data
	 * for checking password which will be trigered during
	 * SSL_CTX_use_PrivateKey_file function
	 */
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)info);
	SSL_CTX_set_default_passwd_cb(ssl_ctx, lws_context_init_ssl_pem_passwd_cb);
}
#endif

int
lws_context_init_ssl_library(struct lws_context_creation_info *info)
{
#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
	lwsl_notice(" Compiled with CyaSSL support\n");
#else
	lwsl_notice(" Compiled with wolfSSL support\n");
#endif
#else
#if defined(LWS_USE_BORINGSSL)
	lwsl_notice(" Compiled with BoringSSL support\n");
#else
	lwsl_notice(" Compiled with OpenSSL support\n");
#endif
#endif
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		lwsl_notice(" SSL disabled: no LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT\n");
		return 0;
	}

	/* basic openssl init */

	lwsl_notice("Doing SSL library init\n");

#if !defined(LWS_WITH_ESP32)
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "lws", NULL, NULL, NULL);

	openssl_SSL_CTX_private_data_index = SSL_CTX_get_ex_new_index(0,
			NULL, NULL, NULL, NULL);
#endif

	return 0;
}

LWS_VISIBLE void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	if (!lws_check_opt(vhost->context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return;

	if (vhost->ssl_ctx)
		SSL_CTX_free(vhost->ssl_ctx);
	if (!vhost->user_supplied_ssl_ctx && vhost->ssl_client_ctx)
		SSL_CTX_free(vhost->ssl_client_ctx);
#if !defined(LWS_WITH_ESP32)

// after 1.1.0 no need
#if (OPENSSL_VERSION_NUMBER <  0x10100000)
// <= 1.0.1f = old api, 1.0.1g+ = new api
#if (OPENSSL_VERSION_NUMBER <= 0x1000106f) || defined(USE_WOLFSSL)
	ERR_remove_state(0);
#else
#if OPENSSL_VERSION_NUMBER >= 0x1010005f && \
    !defined(LIBRESSL_VERSION_NUMBER) && \
    !defined(OPENSSL_IS_BORINGSSL)
	ERR_remove_thread_state();
#else
	ERR_remove_thread_state(NULL);
#endif
#endif
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif
#endif
}

LWS_VISIBLE void
lws_ssl_remove_wsi_from_buffered_list(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (!wsi->pending_read_list_prev &&
	    !wsi->pending_read_list_next &&
	    pt->pending_read_list != wsi)
		/* we are not on the list */
		return;

	/* point previous guy's next to our next */
	if (!wsi->pending_read_list_prev)
		pt->pending_read_list = wsi->pending_read_list_next;
	else
		wsi->pending_read_list_prev->pending_read_list_next =
			wsi->pending_read_list_next;

	/* point next guy's previous to our previous */
	if (wsi->pending_read_list_next)
		wsi->pending_read_list_next->pending_read_list_prev =
			wsi->pending_read_list_prev;

	wsi->pending_read_list_prev = NULL;
	wsi->pending_read_list_next = NULL;
}

LWS_VISIBLE int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, int len)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n = 0;
#if !defined(LWS_WITH_ESP32)
	int ssl_read_errno = 0;
#endif

	if (!wsi->ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	errno = 0;
	n = SSL_read(wsi->ssl, buf, len);
#if defined(LWS_WITH_ESP32)
	if (!n && errno == ENOTCONN) {
		lwsl_debug("%p: SSL_read ENOTCONN\n", wsi);
		return LWS_SSL_CAPABLE_ERROR;
	}
#endif

	lwsl_debug("%p: SSL_read says %d\n", wsi, n);
	/* manpage: returning 0 means connection shut down */
	if (!n) {
		n = lws_ssl_get_error(wsi, n);
		lwsl_debug("%p: ssl err %d errno %d\n", wsi, n, errno);
		if (n == SSL_ERROR_ZERO_RETURN)
			return LWS_SSL_CAPABLE_ERROR;

		if (n == SSL_ERROR_SYSCALL) {
#if !defined(LWS_WITH_ESP32)
			int err = ERR_get_error();
			if (err == 0 && (ssl_read_errno == EPIPE ||
					 ssl_read_errno == ECONNABORTED ||
					 ssl_read_errno == 0))
				return LWS_SSL_CAPABLE_ERROR;
#endif
		}

		lwsl_err("%s failed: %s\n",__func__,
			 ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
		lws_ssl_elaborate_error();

		return LWS_SSL_CAPABLE_ERROR;
	}

	if (n < 0) {
		n = lws_ssl_get_error(wsi, n);
		if (n ==  SSL_ERROR_WANT_READ || SSL_want_read(wsi->ssl)) {
			lwsl_debug("%s: WANT_READ\n", __func__);
			lwsl_debug("%p: LWS_SSL_CAPABLE_MORE_SERVICE\n", wsi);
			return LWS_SSL_CAPABLE_MORE_SERVICE;
		}
		if (n ==  SSL_ERROR_WANT_WRITE || SSL_want_write(wsi->ssl)) {
			lwsl_debug("%s: WANT_WRITE\n", __func__);
			lwsl_debug("%p: LWS_SSL_CAPABLE_MORE_SERVICE\n", wsi);
			return LWS_SSL_CAPABLE_MORE_SERVICE;
		}


		lwsl_err("%s failed2: %s\n",__func__,
				 ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
			lws_ssl_elaborate_error();

		return LWS_SSL_CAPABLE_ERROR;
	}

	if (wsi->vhost)
		wsi->vhost->conn_stats.rx += n;

	lws_restart_ws_ping_pong_timer(wsi);

	/*
	 * if it was our buffer that limited what we read,
	 * check if SSL has additional data pending inside SSL buffers.
	 *
	 * Because these won't signal at the network layer with POLLIN
	 * and if we don't realize, this data will sit there forever
	 */
	if (n != len)
		goto bail;
	if (!wsi->ssl)
		goto bail;

	if (!SSL_pending(wsi->ssl))
		goto bail;

	if (wsi->pending_read_list_next)
		return n;
	if (wsi->pending_read_list_prev)
		return n;
	if (pt->pending_read_list == wsi)
		return n;

	/* add us to the linked list of guys with pending ssl */
	if (pt->pending_read_list)
		pt->pending_read_list->pending_read_list_prev = wsi;

	wsi->pending_read_list_next = pt->pending_read_list;
	wsi->pending_read_list_prev = NULL;
	pt->pending_read_list = wsi;

	return n;
bail:
	lws_ssl_remove_wsi_from_buffered_list(wsi);

	return n;
}

LWS_VISIBLE int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->ssl)
		return 0;

	return SSL_pending(wsi->ssl);
}

LWS_VISIBLE int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, int len)
{
	int n;
#if !defined(LWS_WITH_ESP32)
       	int ssl_read_errno = 0;
#endif

	if (!wsi->ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	n = SSL_write(wsi->ssl, buf, len);
	if (n > 0)
		return n;

	n = lws_ssl_get_error(wsi, n);
	if (n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) {
		if (n == SSL_ERROR_WANT_WRITE) {
			lwsl_debug("%s: WANT_WRITE\n", __func__);
			lws_set_blocking_send(wsi);
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE;
	}

 if (n == SSL_ERROR_ZERO_RETURN)
  return LWS_SSL_CAPABLE_ERROR;

#if !defined(LWS_WITH_ESP32)
 if (n == SSL_ERROR_SYSCALL) {

  int err = ERR_get_error();
  if (err == 0
    && (ssl_read_errno == EPIPE
     || ssl_read_errno == ECONNABORTED
     || ssl_read_errno == 0))
    return LWS_SSL_CAPABLE_ERROR;
 }
#endif

 lwsl_err("%s failed: %s\n",__func__,
   ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
	lws_ssl_elaborate_error();

	return LWS_SSL_CAPABLE_ERROR;
}

static int
lws_gate_accepts(struct lws_context *context, int on)
{
	struct lws_vhost *v = context->vhost_list;

	lwsl_info("gating accepts %d\n", on);

	while (v) {
		if (v->use_ssl &&  v->lserv_wsi) /* gate ability to accept incoming connections */
			if (lws_change_pollfd(v->lserv_wsi, (LWS_POLLIN) * !on, (LWS_POLLIN) * on))
				lwsl_err("Unable to set accept POLLIN %d\n", on);

		v = v->vhost_next;
	}

	return 0;
}

LWS_VISIBLE int
lws_ssl_close(struct lws *wsi)
{
	lws_sockfd_type n;

	if (!wsi->ssl)
		return 0; /* not handled */

	n = SSL_get_fd(wsi->ssl);
	SSL_shutdown(wsi->ssl);
	compatible_close(n);
	SSL_free(wsi->ssl);
	wsi->ssl = NULL;

	if (wsi->context->simultaneous_ssl_restriction &&
	    wsi->context->simultaneous_ssl-- ==
			    wsi->context->simultaneous_ssl_restriction)
		/* we made space and can do an accept */
		lws_gate_accepts(wsi->context, 1);

	return 1; /* handled */
}

/* leave all wsi close processing to the caller */

LWS_VISIBLE int
lws_server_socket_service_ssl(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n, m;
#if !defined(USE_WOLFSSL) && !defined(LWS_WITH_ESP32)
	BIO *bio;
#endif
        char buf[256];

	if (!LWS_SSL_ENABLED(wsi->vhost))
		return 0;

	switch (wsi->mode) {
	case LWSCM_SSL_INIT:
	case LWSCM_SSL_INIT_RAW:
		if (wsi->ssl)
			lwsl_err("%s: leaking ssl\n", __func__);
		if (accept_fd == LWS_SOCK_INVALID)
			assert(0);
		if (context->simultaneous_ssl_restriction &&
		    context->simultaneous_ssl >= context->simultaneous_ssl_restriction) {
			lwsl_notice("unable to deal with SSL connection\n");
			return 1;
		}
		errno = 0;
		wsi->ssl = SSL_new(wsi->vhost->ssl_ctx);
		if (wsi->ssl == NULL) {
			lwsl_err("SSL_new failed: %d (errno %d)\n",
				 lws_ssl_get_error(wsi, 0), errno);

			lws_ssl_elaborate_error();
			if (accept_fd != LWS_SOCK_INVALID)
				compatible_close(accept_fd);
			goto fail;
		}
		if (context->simultaneous_ssl_restriction &&
		    ++context->simultaneous_ssl == context->simultaneous_ssl_restriction)
			/* that was the last allowed SSL connection */
			lws_gate_accepts(context, 0);

#if !defined(LWS_WITH_ESP32)
		SSL_set_ex_data(wsi->ssl,
			openssl_websocket_private_data_index, wsi);
#endif
		SSL_set_fd(wsi->ssl, accept_fd);

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
		CyaSSL_set_using_nonblock(wsi->ssl, 1);
#else
		wolfSSL_set_using_nonblock(wsi->ssl, 1);
#endif
#else
#if defined(LWS_WITH_ESP32)
		lws_plat_set_socket_options(wsi->vhost, accept_fd);
#else
		SSL_set_mode(wsi->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		bio = SSL_get_rbio(wsi->ssl);
		if (bio)
			BIO_set_nbio(bio, 1); /* nonblocking */
		else
			lwsl_notice("NULL rbio\n");
		bio = SSL_get_wbio(wsi->ssl);
		if (bio)
			BIO_set_nbio(bio, 1); /* nonblocking */
		else
			lwsl_notice("NULL rbio\n");
#endif
#endif

		/*
		 * we are not accepted yet, but we need to enter ourselves
		 * as a live connection.  That way we can retry when more
		 * pieces come if we're not sorted yet
		 */

		if (wsi->mode == LWSCM_SSL_INIT)
			wsi->mode = LWSCM_SSL_ACK_PENDING;
		else
			wsi->mode = LWSCM_SSL_ACK_PENDING_RAW;

		if (insert_wsi_socket_into_fds(context, wsi)) {
			lwsl_err("%s: failed to insert into fds\n", __func__);
			goto fail;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_SSL_ACCEPT,
				context->timeout_secs);

		lwsl_debug("inserted SSL accept into fds, trying SSL_accept\n");

		/* fallthru */

	case LWSCM_SSL_ACK_PENDING:
	case LWSCM_SSL_ACK_PENDING_RAW:
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_err("%s: lws_change_pollfd failed\n", __func__);
			goto fail;
		}

		lws_latency_pre(context, wsi);

		if (wsi->vhost->allow_non_ssl_on_ssl_port) {

			n = recv(wsi->desc.sockfd, (char *)pt->serv_buf, context->pt_serv_buf_size,
				 MSG_PEEK);

		/*
		 * optionally allow non-SSL connect on SSL listening socket
		 * This is disabled by default, if enabled it goes around any
		 * SSL-level access control (eg, client-side certs) so leave
		 * it disabled unless you know it's not a problem for you
		 */

			if (n >= 1 && pt->serv_buf[0] >= ' ') {
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
				wsi->use_ssl = 0;

				SSL_shutdown(wsi->ssl);
				SSL_free(wsi->ssl);
				wsi->ssl = NULL;
				if (lws_check_opt(context->options,
				    LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS))
					wsi->redirect_to_https = 1;
				goto accepted;
			}
			if (!n) /*
				 * connection is gone, or nothing to read
				 * if it's gone, we will timeout on
				 * PENDING_TIMEOUT_SSL_ACCEPT
				 */
				break;
			if (n < 0 && (LWS_ERRNO == LWS_EAGAIN ||
				      LWS_ERRNO == LWS_EWOULDBLOCK)) {
				/*
				 * well, we get no way to know ssl or not
				 * so go around again waiting for something
				 * to come and give us a hint, or timeout the
				 * connection.
				 */
				m = SSL_ERROR_WANT_READ;
				goto go_again;
			}
		}

		/* normal SSL connection processing path */

		n = SSL_accept(wsi->ssl);
		lws_latency(context, wsi,
			"SSL_accept LWSCM_SSL_ACK_PENDING\n", n, n == 1);
		lwsl_info("SSL_accept says %d\n", n);
		if (n == 1)
			goto accepted;

		m = lws_ssl_get_error(wsi, n);

#if defined(LWS_WITH_ESP32)
		if (m == 5 && errno == 11)
			m = SSL_ERROR_WANT_READ;
#endif

go_again:
		if (m == SSL_ERROR_WANT_READ || SSL_want_read(wsi->ssl)) {
			if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
				lwsl_err("%s: WANT_READ change_pollfd failed\n", __func__);
				goto fail;
			}

			lwsl_info("SSL_ERROR_WANT_READ\n");
			break;
		}
		if (m == SSL_ERROR_WANT_WRITE || SSL_want_write(wsi->ssl)) {
			lwsl_debug("%s: WANT_WRITE\n", __func__);

			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
				lwsl_err("%s: WANT_WRITE change_pollfd failed\n", __func__);
				goto fail;
			}

			break;
		}

                lwsl_err("SSL_accept failed socket %u: %s\n", wsi->desc.sockfd,
                         lws_ssl_get_error_string(m, n, buf, sizeof(buf)));
		lws_ssl_elaborate_error();
		goto fail;

accepted:
		/* OK, we are accepted... give him some time to negotiate */
		lws_set_timeout(wsi, PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
				context->timeout_secs);

		if (wsi->mode == LWSCM_SSL_ACK_PENDING_RAW)
			wsi->mode = LWSCM_RAW;
		else
			wsi->mode = LWSCM_HTTP_SERVING;

		lws_http2_configure_if_upgraded(wsi);

		lwsl_debug("accepted new SSL conn\n");
		break;
	}

	return 0;

fail:
	return 1;
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	if (vhost->ssl_ctx)
		SSL_CTX_free(vhost->ssl_ctx);

	if (!vhost->user_supplied_ssl_ctx && vhost->ssl_client_ctx)
		SSL_CTX_free(vhost->ssl_client_ctx);
}

void
lws_ssl_context_destroy(struct lws_context *context)
{

#if !defined(LWS_WITH_ESP32)

// after 1.1.0 no need
#if (OPENSSL_VERSION_NUMBER <  0x10100000)
// <= 1.0.1f = old api, 1.0.1g+ = new api
#if (OPENSSL_VERSION_NUMBER <= 0x1000106f) || defined(USE_WOLFSSL)
	ERR_remove_state(0);
#else
#if OPENSSL_VERSION_NUMBER >= 0x1010005f && \
    !defined(LIBRESSL_VERSION_NUMBER) && \
    !defined(OPENSSL_IS_BORINGSSL)
	ERR_remove_thread_state();
#else
	ERR_remove_thread_state(NULL);
#endif
#endif
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif
#endif
}
