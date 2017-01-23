/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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

#if defined(LWS_USE_POLARSSL)
static const int ciphers[] =
{
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	0
};

static int urandom_bytes(void *ctx, unsigned char *dest, size_t len)
{
	int cur;
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0)
		return -1;

	while (len) {
		cur = read(fd, dest, len);
		if (cur < 0)
			continue;
		len -= cur;
	}
	close(fd);

	return 0;
}

static void pssl_debug(void *ctx, int level, const char *str)
{
    lwsl_err("PolarSSL [level %d]: %s", level, str);
}

#endif

int openssl_websocket_private_data_index,
    openssl_SSL_CTX_private_data_index;

int lws_ssl_get_error(struct lws *wsi, int n)
{
#if defined(LWS_USE_POLARSSL)
#define ERR_error_string(a, b) ""
	return n;
#else
#if defined(LWS_USE_MBEDTLS)
	return n;
#else
	return SSL_get_error(wsi->ssl, n);
#endif
#endif
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
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else

	char buf[256];
	u_long err;

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		lwsl_err("*** %s\n", buf);
	}
#endif
#endif
}


#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
static int
lws_context_init_ssl_pem_passwd_cb(char * buf, int size, int rwflag, void *userdata)
{
	struct lws_context_creation_info * info =
			(struct lws_context_creation_info *)userdata;

	strncpy(buf, info->ssl_private_key_password, size);
	buf[size - 1] = '\0';

	return strlen(buf);
}
#endif
#endif

void
lws_ssl_bind_passphrase(SSL_CTX *ssl_ctx, struct lws_context_creation_info *info)
{
	if (!info->ssl_private_key_password)
		return;
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
	/*
	 * password provided, set ssl callback and user data
	 * for checking password which will be trigered during
	 * SSL_CTX_use_PrivateKey_file function
	 */
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)info);
	SSL_CTX_set_default_passwd_cb(ssl_ctx, lws_context_init_ssl_pem_passwd_cb);
#endif
#endif
}

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
#if defined(LWS_USE_POLARSSL)
	lwsl_notice(" Compiled with PolarSSL support\n");
#else
#if defined(LWS_USE_MBEDTLS)
	lwsl_notice(" Compiled with mbedTLS support\n");
#else
#if defined(LWS_USE_BORINGSSL)
	lwsl_notice(" Compiled with BoringSSL support\n");
#else
	lwsl_notice(" Compiled with OpenSSL support\n");
#endif
#endif
#endif
#endif

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		lwsl_notice(" SSL disabled: no LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT\n");
		return 0;
	}

	/* basic openssl init */

#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else

	lwsl_notice("Doing SSL library init\n");

	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "lws", NULL, NULL, NULL);

	openssl_SSL_CTX_private_data_index = SSL_CTX_get_ex_new_index(0,
			NULL, NULL, NULL, NULL);
#endif
#endif

	return 0;
}


LWS_VISIBLE void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	if (!lws_check_opt(vhost->context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return;

#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else

	if (vhost->ssl_ctx)
		SSL_CTX_free(vhost->ssl_ctx);
	if (!vhost->user_supplied_ssl_ctx && vhost->ssl_client_ctx)
		SSL_CTX_free(vhost->ssl_client_ctx);

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
#endif
}

LWS_VISIBLE void
lws_decode_ssl_error(void)
{
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
	char buf[256];
	u_long err;
	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		lwsl_err("*** %lu %s\n", err, buf);
	}
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

	if (!wsi->ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
	n = SSL_read(wsi->ssl, buf, len);
#endif
#endif

	/* manpage: returning 0 means connection shut down */
	if (!n) {
			lwsl_err("%s failed: %s\n",__func__,
				 ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
			lws_decode_ssl_error();

		return LWS_SSL_CAPABLE_ERROR;
	}

	if (n < 0) {
		n = lws_ssl_get_error(wsi, n);
		if (n ==  SSL_ERROR_WANT_READ || n ==  SSL_ERROR_WANT_WRITE)
			return LWS_SSL_CAPABLE_MORE_SERVICE;

		lwsl_err("%s failed2: %s\n",__func__,
				 ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
			lws_decode_ssl_error();

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
#if defined(LWS_USE_POLARSSL)
	if (ssl_get_bytes_avail(wsi->ssl) <= 0)
		goto bail;
#else
#if defined(LWS_USE_MBEDTLS)
#else
	if (!SSL_pending(wsi->ssl))
		goto bail;
#endif
#endif
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
#if defined(LWS_USE_POLARSSL)
	return ssl_get_bytes_avail(wsi->ssl) > 0;
#else
#if defined(LWS_USE_MBEDTLS)
	return ssl_get_bytes_avail(wsi->ssl) > 0;;
#else
	return SSL_pending(wsi->ssl);
#endif
#endif
}

LWS_VISIBLE int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, int len)
{
	int n;

	if (!wsi->ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

#if defined(LWS_USE_POLARSSL)
	n = ssl_write(wsi->ssl, buf, len);
#else
#if defined(LWS_USE_MBEDTLS)
#else
	n = SSL_write(wsi->ssl, buf, len);
#endif
#endif
	if (n > 0)
		return n;

	n = lws_ssl_get_error(wsi, n);
	if (n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) {
		if (n == SSL_ERROR_WANT_WRITE)
			lws_set_blocking_send(wsi);
		return LWS_SSL_CAPABLE_MORE_SERVICE;
	}
		lwsl_err("%s failed: %s\n",__func__,
				 ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
			lws_decode_ssl_error();


	return LWS_SSL_CAPABLE_ERROR;
}

LWS_VISIBLE int
lws_ssl_close(struct lws *wsi)
{
	int n;

	if (!wsi->ssl)
		return 0; /* not handled */

#if defined(LWS_USE_POLARSSL)
	ssl_close_notify(wsi->ssl);
	(void)n; /* we need to close the fd? */
	ssl_free(wsi->ssl);
#else
#if defined(LWS_USE_MBEDTLS)
#else
	n = SSL_get_fd(wsi->ssl);
	SSL_shutdown(wsi->ssl);
	compatible_close(n);
	SSL_free(wsi->ssl);
#endif
#endif
	wsi->ssl = NULL;

	return 1; /* handled */
}

/* leave all wsi close processing to the caller */

LWS_VISIBLE int
lws_server_socket_service_ssl(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n, m;
#if !defined(USE_WOLFSSL) && !defined(LWS_USE_POLARSSL) && !defined(LWS_USE_MBEDTLS)
	BIO *bio;
#endif
        char buf[256];

	if (!LWS_SSL_ENABLED(wsi->vhost))
		return 0;

	switch (wsi->mode) {
	case LWSCM_SSL_INIT:

		if (wsi->ssl)
			lwsl_err("%s: leaking ssl\n", __func__);
		if (accept_fd == LWS_SOCK_INVALID)
			assert(0);

#if defined(LWS_USE_POLARSSL)
	{
		ssl_session *ssn;
		int rc;

		wsi->ssl = lws_zalloc(sizeof(ssl_context));
		ssn = lws_zalloc(sizeof(ssl_session));

		rc = ssl_init(wsi->ssl);
		if (rc) {
			lwsl_err("ssl_init failed\n");
			goto fail;
		}

		ssl_set_endpoint(wsi->ssl, SSL_IS_SERVER);
		ssl_set_authmode(wsi->ssl, SSL_VERIFY_OPTIONAL);
		ssl_set_rng(wsi->ssl, urandom_bytes, NULL);
		ssl_set_dbg(wsi->ssl, pssl_debug, NULL);
		ssl_set_bio(wsi->ssl, net_recv, &wsi->sock, net_send, &wsi->sock);

		ssl_set_ciphersuites(wsi->ssl, ciphers);

		ssl_set_session(wsi->ssl, ssn);

		ssl_set_ca_chain(wsi->ssl, &wsi->vhost->ssl_ctx->ca,
				 NULL, NULL);

		ssl_set_own_cert_rsa(wsi->ssl,
				&wsi->vhost->ssl_ctx->certificate,
				&wsi->vhost->ssl_ctx->key);

//		ssl_set_dh_param(wsi->ssl, my_dhm_P, my_dhm_G);

		lwsl_err("%s: polarssl init done\n", __func__);
	}
#else
#if defined(LWS_USE_MBEDTLS)
#else
		wsi->ssl = SSL_new(wsi->vhost->ssl_ctx);
		if (wsi->ssl == NULL) {
			lwsl_err("SSL_new failed: %s\n",
				 ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
			lws_decode_ssl_error();
			if (accept_fd != LWS_SOCK_INVALID)
				compatible_close(accept_fd);
			goto fail;
		}

		SSL_set_ex_data(wsi->ssl,
			openssl_websocket_private_data_index, wsi);

		SSL_set_fd(wsi->ssl, accept_fd);
#endif
#endif

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
		CyaSSL_set_using_nonblock(wsi->ssl, 1);
#else
		wolfSSL_set_using_nonblock(wsi->ssl, 1);
#endif
#else
#if defined(LWS_USE_POLARSSL)

#else
#if defined(LWS_USE_MBEDTLS)
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
#endif

		/*
		 * we are not accepted yet, but we need to enter ourselves
		 * as a live connection.  That way we can retry when more
		 * pieces come if we're not sorted yet
		 */

		wsi->mode = LWSCM_SSL_ACK_PENDING;
		if (insert_wsi_socket_into_fds(context, wsi)) {
			lwsl_err("%s: failed to insert into fds\n", __func__);
			goto fail;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_SSL_ACCEPT,
				context->timeout_secs);

		lwsl_info("inserted SSL accept into fds, trying SSL_accept\n");

		/* fallthru */

	case LWSCM_SSL_ACK_PENDING:

		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_err("%s: lws_change_pollfd failed\n", __func__);
			goto fail;
		}

		lws_latency_pre(context, wsi);

		n = recv(wsi->sock, (char *)pt->serv_buf, context->pt_serv_buf_size,
			 MSG_PEEK);

		/*
		 * optionally allow non-SSL connect on SSL listening socket
		 * This is disabled by default, if enabled it goes around any
		 * SSL-level access control (eg, client-side certs) so leave
		 * it disabled unless you know it's not a problem for you
		 */

		if (wsi->vhost->allow_non_ssl_on_ssl_port) {
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
#if defined(LWS_USE_POLARSSL)
				ssl_close_notify(wsi->ssl);
				ssl_free(wsi->ssl);
#else
#if defined(LWS_USE_MBEDTLS)
#else
				SSL_shutdown(wsi->ssl);
				SSL_free(wsi->ssl);
#endif
#endif
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
#if defined(LWS_USE_POLARSSL)
		n = ssl_handshake(wsi->ssl);
#else
#if defined(LWS_USE_MBEDTLS)
#else
		n = SSL_accept(wsi->ssl);
#endif
#endif
		lws_latency(context, wsi,
			"SSL_accept LWSCM_SSL_ACK_PENDING\n", n, n == 1);

		if (n == 1)
			goto accepted;

		m = lws_ssl_get_error(wsi, n);
go_again:
		if (m == SSL_ERROR_WANT_READ) {
			if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
				lwsl_err("%s: WANT_READ change_pollfd failed\n", __func__);
				goto fail;
			}

			lwsl_info("SSL_ERROR_WANT_READ\n");
			break;
		}
		if (m == SSL_ERROR_WANT_WRITE) {
			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
				lwsl_err("%s: WANT_WRITE change_pollfd failed\n", __func__);
				goto fail;
			}

			break;
		}

                lwsl_err("SSL_accept failed socket %u: %s\n", wsi->sock,
                         lws_ssl_get_error_string(m, n, buf, sizeof(buf)));
		lws_ssl_elaborate_error();
		goto fail;

accepted:
		/* OK, we are accepted... give him some time to negotiate */
		lws_set_timeout(wsi, PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
				context->timeout_secs);

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
	if (vhost->ssl_ctx) {
#if defined(LWS_USE_POLARSSL)
		lws_free(vhost->ssl_ctx);
#else
#if defined(LWS_USE_MBEDTLS)
#else
		SSL_CTX_free(vhost->ssl_ctx);
#endif
#endif
	}
	if (!vhost->user_supplied_ssl_ctx && vhost->ssl_client_ctx) {
#if defined(LWS_USE_POLARSSL)
		lws_free(vhost->ssl_client_ctx);
#else
#if defined(LWS_USE_MBEDTLS)
#else
		SSL_CTX_free(vhost->ssl_client_ctx);
#endif
#endif
	}
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else

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
#endif
}
