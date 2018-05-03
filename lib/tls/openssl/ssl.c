/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#include "core/private.h"
#include <errno.h>

int openssl_websocket_private_data_index,
	   openssl_SSL_CTX_private_data_index;

int lws_ssl_get_error(struct lws *wsi, int n)
{
	int m;

	if (!wsi->tls.ssl)
		return 99;

	m = SSL_get_error(wsi->tls.ssl, n);
	lwsl_debug("%s: %p %d -> %d (errno %d)\n", __func__, wsi->tls.ssl, n, m, errno);

	return m;
}

char* lws_ssl_get_error_string(int status, int ret, char *buf, size_t len) {
	switch (status) {
	case SSL_ERROR_NONE:
		return lws_strncpy(buf, "SSL_ERROR_NONE", len);
	case SSL_ERROR_ZERO_RETURN:
		return lws_strncpy(buf, "SSL_ERROR_ZERO_RETURN", len);
	case SSL_ERROR_WANT_READ:
		return lws_strncpy(buf, "SSL_ERROR_WANT_READ", len);
	case SSL_ERROR_WANT_WRITE:
		return lws_strncpy(buf, "SSL_ERROR_WANT_WRITE", len);
	case SSL_ERROR_WANT_CONNECT:
		return lws_strncpy(buf, "SSL_ERROR_WANT_CONNECT", len);
	case SSL_ERROR_WANT_ACCEPT:
		return lws_strncpy(buf, "SSL_ERROR_WANT_ACCEPT", len);
	case SSL_ERROR_WANT_X509_LOOKUP:
		return lws_strncpy(buf, "SSL_ERROR_WANT_X509_LOOKUP", len);
	case SSL_ERROR_SYSCALL:
		switch (ret) {
                case 0:
                        lws_snprintf(buf, len, "SSL_ERROR_SYSCALL: EOF");
                        return buf;
                case -1:
#ifndef LWS_PLAT_OPTEE
			lws_snprintf(buf, len, "SSL_ERROR_SYSCALL: %s",
				     strerror(errno));
#else
			lws_snprintf(buf, len, "SSL_ERROR_SYSCALL: %d", errno);
#endif
			return buf;
                default:
                        return strncpy(buf, "SSL_ERROR_SYSCALL", len);
	}
	case SSL_ERROR_SSL:
		return "SSL_ERROR_SSL";
	default:
		return "SSL_ERROR_UNKNOWN";
	}
}

void
lws_ssl_elaborate_error(void)
{
	char buf[256];
	u_long err;

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		lwsl_info("*** %s\n", buf);
	}
}

static int
lws_context_init_ssl_pem_passwd_cb(char * buf, int size, int rwflag,
				   void *userdata)
{
	struct lws_context_creation_info * info =
			(struct lws_context_creation_info *)userdata;

	strncpy(buf, info->ssl_private_key_password, size);
	buf[size - 1] = '\0';

	return (int)strlen(buf);
}

void
lws_ssl_bind_passphrase(SSL_CTX *ssl_ctx,
			const struct lws_context_creation_info *info)
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

int
lws_context_init_ssl_library(const struct lws_context_creation_info *info)
{
#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
	lwsl_info(" Compiled with CyaSSL support\n");
#else
	lwsl_info(" Compiled with wolfSSL support\n");
#endif
#else
#if defined(LWS_WITH_BORINGSSL)
	lwsl_info(" Compiled with BoringSSL support\n");
#else
	lwsl_info(" Compiled with OpenSSL support\n");
#endif
#endif
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT)) {
		lwsl_info(" SSL disabled: no LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT\n");
		return 0;
	}

	/* basic openssl init */

	lwsl_info("Doing SSL library init\n");

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "lws", NULL, NULL, NULL);

	openssl_SSL_CTX_private_data_index = SSL_CTX_get_ex_new_index(0,
			NULL, NULL, NULL, NULL);

	return 0;
}

LWS_VISIBLE void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	if (!lws_check_opt(vhost->context->options,
			   LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return;

	if (vhost->tls.ssl_ctx)
		SSL_CTX_free(vhost->tls.ssl_ctx);
	if (!vhost->tls.user_supplied_ssl_ctx && vhost->tls.ssl_client_ctx)
		SSL_CTX_free(vhost->tls.ssl_client_ctx);

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
	// after 1.1.0 no need
#if  (OPENSSL_VERSION_NUMBER >= 0x10002000) && (OPENSSL_VERSION_NUMBER <= 0x10100000)
	SSL_COMP_free_compression_methods();
#endif
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif
}

LWS_VISIBLE int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, int len)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n = 0, m;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	lws_stats_atomic_bump(context, pt, LWSSTATS_C_API_READ, 1);

	errno = 0;
	n = SSL_read(wsi->tls.ssl, buf, len);
#if defined(LWS_WITH_ESP32)
	if (!n && errno == ENOTCONN) {
		lwsl_debug("%p: SSL_read ENOTCONN\n", wsi);
		return LWS_SSL_CAPABLE_ERROR;
	}
#endif
#if defined(LWS_WITH_STATS)
	if (!wsi->seen_rx) {
                lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_MS_SSL_RX_DELAY,
				time_in_microseconds() - wsi->accept_start_us);
                lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_SSL_CONNS_HAD_RX, 1);
		wsi->seen_rx = 1;
	}
#endif


	lwsl_debug("%p: SSL_read says %d\n", wsi, n);
	/* manpage: returning 0 means connection shut down */
	if (!n || (n == -1 && errno == ENOTCONN)) {
		wsi->socket_is_permanently_unusable = 1;

		return LWS_SSL_CAPABLE_ERROR;
	}

	if (n < 0) {
		m = lws_ssl_get_error(wsi, n);
		lwsl_debug("%p: ssl err %d errno %d\n", wsi, m, errno);
		if (m == SSL_ERROR_ZERO_RETURN ||
		    m == SSL_ERROR_SYSCALL)
			return LWS_SSL_CAPABLE_ERROR;

		if (SSL_want_read(wsi->tls.ssl)) {
			lwsl_debug("%s: WANT_READ\n", __func__);
			lwsl_debug("%p: LWS_SSL_CAPABLE_MORE_SERVICE\n", wsi);
			return LWS_SSL_CAPABLE_MORE_SERVICE;
		}
		if (SSL_want_write(wsi->tls.ssl)) {
			lwsl_debug("%s: WANT_WRITE\n", __func__);
			lwsl_debug("%p: LWS_SSL_CAPABLE_MORE_SERVICE\n", wsi);
			return LWS_SSL_CAPABLE_MORE_SERVICE;
		}
		wsi->socket_is_permanently_unusable = 1;

		return LWS_SSL_CAPABLE_ERROR;
	}

	lws_stats_atomic_bump(context, pt, LWSSTATS_B_READ, n);

	if (wsi->vhost)
		wsi->vhost->conn_stats.rx += n;

	// lwsl_hexdump_err(buf, n);

	/*
	 * if it was our buffer that limited what we read,
	 * check if SSL has additional data pending inside SSL buffers.
	 *
	 * Because these won't signal at the network layer with POLLIN
	 * and if we don't realize, this data will sit there forever
	 */
	if (n != len)
		goto bail;
	if (!wsi->tls.ssl)
		goto bail;

	if (!SSL_pending(wsi->tls.ssl))
		goto bail;

	if (wsi->tls.pending_read_list_next)
		return n;
	if (wsi->tls.pending_read_list_prev)
		return n;
	if (pt->tls.pending_read_list == wsi)
		return n;

	/* add us to the linked list of guys with pending ssl */
	if (pt->tls.pending_read_list)
		pt->tls.pending_read_list->tls.pending_read_list_prev = wsi;

	wsi->tls.pending_read_list_next = pt->tls.pending_read_list;
	wsi->tls.pending_read_list_prev = NULL;
	pt->tls.pending_read_list = wsi;

	return n;
bail:
	lws_ssl_remove_wsi_from_buffered_list(wsi);

	return n;
}

LWS_VISIBLE int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	return SSL_pending(wsi->tls.ssl);
}

LWS_VISIBLE int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, int len)
{
	int n, m;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	n = SSL_write(wsi->tls.ssl, buf, len);
	if (n > 0)
		return n;

	m = lws_ssl_get_error(wsi, n);
	if (m != SSL_ERROR_SYSCALL) {
		if (m == SSL_ERROR_WANT_READ || SSL_want_read(wsi->tls.ssl)) {
			lwsl_notice("%s: want read\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE;
		}

		if (m == SSL_ERROR_WANT_WRITE || SSL_want_write(wsi->tls.ssl)) {
			lws_set_blocking_send(wsi);

			lwsl_notice("%s: want write\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE;
		}
	}

	lwsl_debug("%s failed: %s\n",__func__, ERR_error_string(m, NULL));
	lws_ssl_elaborate_error();

	wsi->socket_is_permanently_unusable = 1;

	return LWS_SSL_CAPABLE_ERROR;
}

void
lws_ssl_info_callback(const SSL *ssl, int where, int ret)
{
	struct lws *wsi;
	struct lws_context *context;
	struct lws_ssl_info si;

#ifndef USE_WOLFSSL
	context = (struct lws_context *)SSL_CTX_get_ex_data(
					SSL_get_SSL_CTX(ssl),
					openssl_SSL_CTX_private_data_index);
#else
	context = (struct lws_context *)SSL_CTX_get_ex_data(
					SSL_get_SSL_CTX((SSL*) ssl),
					openssl_SSL_CTX_private_data_index);
#endif
	if (!context)
		return;
	wsi = wsi_from_fd(context, SSL_get_fd(ssl));
	if (!wsi)
		return;

	if (!(where & wsi->vhost->tls.ssl_info_event_mask))
		return;

	si.where = where;
	si.ret = ret;

	if (user_callback_handle_rxflow(wsi->protocol->callback,
						   wsi, LWS_CALLBACK_SSL_INFO,
						   wsi->user_space, &si, 0))
		lws_set_timeout(wsi, PENDING_TIMEOUT_KILLED_BY_SSL_INFO, -1);
}


LWS_VISIBLE int
lws_ssl_close(struct lws *wsi)
{
	lws_sockfd_type n;

	if (!wsi->tls.ssl)
		return 0; /* not handled */

#if defined (LWS_HAVE_SSL_SET_INFO_CALLBACK)
	/* kill ssl callbacks, becausse we will remove the fd from the
	 * table linking it to the wsi
	 */
	if (wsi->vhost->tls.ssl_info_event_mask)
		SSL_set_info_callback(wsi->tls.ssl, NULL);
#endif

	n = SSL_get_fd(wsi->tls.ssl);
	if (!wsi->socket_is_permanently_unusable)
		SSL_shutdown(wsi->tls.ssl);
	compatible_close(n);
	SSL_free(wsi->tls.ssl);
	wsi->tls.ssl = NULL;

	if (wsi->context->simultaneous_ssl_restriction &&
	    wsi->context->simultaneous_ssl-- ==
			    wsi->context->simultaneous_ssl_restriction)
		/* we made space and can do an accept */
		lws_gate_accepts(wsi->context, 1);

	// lwsl_notice("%s: ssl restr %d, simul %d\n", __func__,
	//		wsi->context->simultaneous_ssl_restriction,
	//		wsi->context->simultaneous_ssl);

#if defined(LWS_WITH_STATS)
	wsi->context->updated = 1;
#endif

	return 1; /* handled */
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	if (vhost->tls.ssl_ctx)
		SSL_CTX_free(vhost->tls.ssl_ctx);

	if (!vhost->tls.user_supplied_ssl_ctx && vhost->tls.ssl_client_ctx)
		SSL_CTX_free(vhost->tls.ssl_client_ctx);
#if defined(LWS_WITH_ACME)
	lws_tls_acme_sni_cert_destroy(vhost);
#endif
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
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
	// after 1.1.0 no need
#if  (OPENSSL_VERSION_NUMBER >= 0x10002000) && (OPENSSL_VERSION_NUMBER <= 0x10100000)
	SSL_COMP_free_compression_methods();
#endif
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return NULL;

	return SSL_get_SSL_CTX(wsi->tls.ssl);
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int n;

	n = SSL_shutdown(wsi->tls.ssl);
	lwsl_debug("SSL_shutdown=%d for fd %d\n", n, wsi->desc.sockfd);
	switch (n) {
	case 1: /* successful completion */
		n = shutdown(wsi->desc.sockfd, SHUT_WR);
		return LWS_SSL_CAPABLE_DONE;

	case 0: /* needs a retry */
		__lws_change_pollfd(wsi, 0, LWS_POLLIN);
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	default: /* fatal error, or WANT */
		n = SSL_get_error(wsi->tls.ssl, n);
		if (n != SSL_ERROR_SYSCALL && n != SSL_ERROR_SSL) {
			if (SSL_want_read(wsi->tls.ssl)) {
				lwsl_debug("(wants read)\n");
				__lws_change_pollfd(wsi, 0, LWS_POLLIN);
				return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
			}
			if (SSL_want_write(wsi->tls.ssl)) {
				lwsl_debug("(wants write)\n");
				__lws_change_pollfd(wsi, 0, LWS_POLLOUT);
				return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
			}
		}
		return LWS_SSL_CAPABLE_ERROR;
	}
}
#if !defined(LWS_PLAT_OPTEE)
static int
dec(char c)
{
	return c - '0';
}
#endif

static time_t
lws_tls_openssl_asn1time_to_unix(ASN1_TIME *as)
{
#if !defined(LWS_PLAT_OPTEE)

	const char *p = (const char *)as->data;
	struct tm t;

	/* [YY]YYMMDDHHMMSSZ */

	memset(&t, 0, sizeof(t));

	if (strlen(p) == 13) {
		t.tm_year = (dec(p[0]) * 10) + dec(p[1]) + 100;
		p += 2;
	} else {
		t.tm_year = (dec(p[0]) * 1000) + (dec(p[1]) * 100) +
			    (dec(p[2]) * 10) + dec(p[3]);
		p += 4;
	}
	t.tm_mon = (dec(p[0]) * 10) + dec(p[1]) - 1;
	p += 2;
	t.tm_mday = (dec(p[0]) * 10) + dec(p[1]) - 1;
	p += 2;
	t.tm_hour = (dec(p[0]) * 10) + dec(p[1]);
	p += 2;
	t.tm_min = (dec(p[0]) * 10) + dec(p[1]);
	p += 2;
	t.tm_sec = (dec(p[0]) * 10) + dec(p[1]);
	t.tm_isdst = 0;

	return mktime(&t);
#else
	return (time_t)-1;
#endif
}

int
lws_tls_openssl_cert_info(X509 *x509, enum lws_tls_cert_info type,
			  union lws_tls_cert_info_results *buf, size_t len)
{
	X509_NAME *xn;
#if !defined(LWS_PLAT_OPTEE)
	char *p;
#endif

	if (!x509)
		return -1;

	switch (type) {
	case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		buf->time = lws_tls_openssl_asn1time_to_unix(
					X509_get_notBefore(x509));
		if (buf->time == (time_t)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_VALIDITY_TO:
		buf->time = lws_tls_openssl_asn1time_to_unix(
					X509_get_notAfter(x509));
		if (buf->time == (time_t)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_COMMON_NAME:
#if defined(LWS_PLAT_OPTEE)
		return -1;
#else
		xn = X509_get_subject_name(x509);
		if (!xn)
			return -1;
		X509_NAME_oneline(xn, buf->ns.name, (int)len - 2);
		p = strstr(buf->ns.name, "/CN=");
		if (p)
			memmove(buf->ns.name, p + 4, strlen(p + 4) + 1);
		buf->ns.len = (int)strlen(buf->ns.name);
		return 0;
#endif
	case LWS_TLS_CERT_INFO_ISSUER_NAME:
		xn = X509_get_issuer_name(x509);
		if (!xn)
			return -1;
		X509_NAME_oneline(xn, buf->ns.name, (int)len - 1);
		buf->ns.len = (int)strlen(buf->ns.name);
		return 0;

	case LWS_TLS_CERT_INFO_USAGE:
#if defined(LWS_HAVE_X509_get_key_usage)
		buf->usage = X509_get_key_usage(x509);
		break;
#else
		return -1;
#endif

	case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
	{
#ifndef USE_WOLFSSL
		size_t klen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), NULL);
		uint8_t *tmp, *ptmp;

		if (klen <= 0 || klen > len)
			return -1;

		tmp = (uint8_t *)OPENSSL_malloc(klen);
		if (!tmp)
			return -1;

		ptmp = tmp;
		if (i2d_X509_PUBKEY(
			      X509_get_X509_PUBKEY(x509), &ptmp) != (int)klen ||
		    !ptmp || lws_ptr_diff(ptmp, tmp) != (int)klen) {
			lwsl_info("%s: cert public key extraction failed\n",
				  __func__);
			if (ptmp)
				OPENSSL_free(tmp);

			return -1;
		}

		buf->ns.len = (int)klen;
		memcpy(buf->ns.name, tmp, klen);
		OPENSSL_free(tmp);
#endif
		return 0;
	}
	default:
		return -1;
	}

	return 0;
}

LWS_VISIBLE LWS_EXTERN int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
		        union lws_tls_cert_info_results *buf, size_t len)
{
#if defined(LWS_HAVE_SSL_CTX_get0_certificate)
	X509 *x509 = SSL_CTX_get0_certificate(vhost->tls.ssl_ctx);

	return lws_tls_openssl_cert_info(x509, type, buf, len);
#else
	lwsl_notice("openssl is too old to support %s\n", __func__);

	return -1;
#endif
}

LWS_VISIBLE int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	int rc = 0;
	X509 *x509;

	wsi = lws_get_network_wsi(wsi);

	x509 = SSL_get_peer_certificate(wsi->tls.ssl);

	if (!x509) {
		lwsl_debug("no peer cert\n");

		return -1;
	}

	switch (type) {
	case LWS_TLS_CERT_INFO_VERIFIED:
		buf->verified = SSL_get_verify_result(wsi->tls.ssl) == X509_V_OK;
		break;
	default:
		rc = lws_tls_openssl_cert_info(x509, type, buf, len);
	}

	X509_free(x509);

	return rc;
}

static int
tops_fake_POLLIN_for_buffered_openssl(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

static int
tops_periodic_housekeeping_openssl(struct lws_context *context, time_t now)
{
	int n;

	n = lws_compare_time_t(context, now, context->tls.last_cert_check_s);
	if ((!context->tls.last_cert_check_s || n > (24 * 60 * 60)) &&
	    !lws_tls_check_all_cert_lifetimes(context))
		context->tls.last_cert_check_s = now;

	return 0;
}

const struct lws_tls_ops tls_ops_openssl = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_openssl,
	/* periodic_housekeeping */	tops_periodic_housekeeping_openssl,

};
