/*
 * libwebsockets - OpenSSL-specific server functions
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

extern int openssl_websocket_private_data_index,
	   openssl_SSL_CTX_private_data_index;

static int
OpenSSL_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	SSL *ssl;
	int n;
	struct lws *wsi;

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());

	/*
	 * !!! nasty openssl requires the index to come as a library-scope
	 * static
	 */
	wsi = SSL_get_ex_data(ssl, openssl_websocket_private_data_index);

	n = wsi->vhost->protocols[0].callback(wsi,
			LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
					   x509_ctx, ssl, preverify_ok);

	/* convert return code from 0 = OK to 1 = OK */
	return !n;
}

int
lws_tls_server_client_cert_verify_config(struct lws_context_creation_info *info,
					 struct lws_vhost *vh)
{
	int verify_options = SSL_VERIFY_PEER;

	/* as a server, are we requiring clients to identify themselves? */

	if (!lws_check_opt(info->options,
			  LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT))
		return 0;

	if (!lws_check_opt(info->options,
			   LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
		verify_options |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	SSL_CTX_set_session_id_context(vh->ssl_ctx, (uint8_t *)vh->context,
				       sizeof(void *));

	/* absolutely require the client cert */
	SSL_CTX_set_verify(vh->ssl_ctx, verify_options, OpenSSL_verify_callback);

	return 0;
}

#if defined(SSL_TLSEXT_ERR_NOACK) && !defined(OPENSSL_NO_TLSEXT)
static int
lws_ssl_server_name_cb(SSL *ssl, int *ad, void *arg)
{
	struct lws_context *context = (struct lws_context *)arg;
	struct lws_vhost *vhost, *vh;
	const char *servername;

	if (!ssl)
		return SSL_TLSEXT_ERR_NOACK;

	/*
	 * We can only get ssl accepted connections by using a vhost's ssl_ctx
	 * find out which listening one took us and only match vhosts on the
	 * same port.
	 */
	vh = context->vhost_list;
	while (vh) {
		if (!vh->being_destroyed && vh->ssl_ctx == SSL_get_SSL_CTX(ssl))
			break;
		vh = vh->vhost_next;
	}

	if (!vh) {
		assert(vh); /* can't match the incoming vh? */
		return SSL_TLSEXT_ERR_OK;
	}

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername) {
		/* the client doesn't know what hostname it wants */
		lwsl_info("SNI: Unknown ServerName: %s\n", servername);

		return SSL_TLSEXT_ERR_OK;
	}

	vhost = lws_select_vhost(context, vh->listen_port, servername);
	if (!vhost) {
		lwsl_info("SNI: none: %s:%d\n", servername, vh->listen_port);

		return SSL_TLSEXT_ERR_OK;
	}

	lwsl_info("SNI: Found: %s:%d\n", servername, vh->listen_port);

	/* select the ssl ctx from the selected vhost for this conn */
	SSL_set_SSL_CTX(ssl, vhost->ssl_ctx);

	return SSL_TLSEXT_ERR_OK;
}
#endif

int
lws_tls_server_vhost_backend_init(struct lws_context_creation_info *info,
				  struct lws_vhost *vhost,
				  struct lws *wsi)
{
#if defined(LWS_HAVE_OPENSSL_ECDH_H)
	const char *ecdh_curve = "prime256v1";
	EC_KEY *ecdh, *EC_key = NULL;
	EVP_PKEY *pkey;
	X509 *x = NULL;
	int ecdh_nid;
	int KeyType;
#if defined(LWS_HAVE_SSL_EXTRA_CHAIN_CERTS)
	STACK_OF(X509) *extra_certs = NULL;
#endif
#endif
	SSL_METHOD *method = (SSL_METHOD *)SSLv23_server_method();
	unsigned long error;
	int n;

	if (!method) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl method %lu: %s\n",
				error, ERR_error_string(error,
				      (char *)vhost->context->pt[0].serv_buf));
		return 1;
	}
	vhost->ssl_ctx = SSL_CTX_new(method);	/* create context */
	if (!vhost->ssl_ctx) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
				error, ERR_error_string(error,
				      (char *)vhost->context->pt[0].serv_buf));
		return 1;
	}

	SSL_CTX_set_ex_data(vhost->ssl_ctx, openssl_SSL_CTX_private_data_index,
			    (char *)vhost->context);
	/* Disable SSLv2 and SSLv3 */
	SSL_CTX_set_options(vhost->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(vhost->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
	SSL_CTX_set_options(vhost->ssl_ctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_options(vhost->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

	if (info->ssl_cipher_list)
		SSL_CTX_set_cipher_list(vhost->ssl_ctx, info->ssl_cipher_list);

#if !defined(LWS_WITH_MBEDTLS) && !defined(OPENSSL_NO_TLSEXT)
	SSL_CTX_set_tlsext_servername_callback(vhost->ssl_ctx,
					       lws_ssl_server_name_cb);
	SSL_CTX_set_tlsext_servername_arg(vhost->ssl_ctx, vhost->context);
#endif

	if (info->ssl_ca_filepath &&
	    !SSL_CTX_load_verify_locations(vhost->ssl_ctx,
					   info->ssl_ca_filepath, NULL)) {
		lwsl_err("%s: SSL_CTX_load_verify_locations unhappy\n",
			 __func__);
	}

	if (info->ssl_options_set)
		SSL_CTX_set_options(vhost->ssl_ctx, info->ssl_options_set);

/* SSL_clear_options introduced in 0.9.8m */
#if (OPENSSL_VERSION_NUMBER >= 0x009080df) && !defined(USE_WOLFSSL)
	if (info->ssl_options_clear)
		SSL_CTX_clear_options(vhost->ssl_ctx, info->ssl_options_clear);
#endif

	lwsl_info(" SSL options 0x%lX\n", SSL_CTX_get_options(vhost->ssl_ctx));
	if (!vhost->use_ssl || !info->ssl_cert_filepath)
		return 0;

	/*
	 * The user code can choose to either pass the cert and
	 * key filepaths using the info members like this, or it can
	 * leave them NULL; force the vhost SSL_CTX init using the info
	 * options flag LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX; and
	 * set up the cert himself using the user callback
	 * LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, which
	 * happened just above and has the vhost SSL_CTX * in the user
	 * parameter.
	 */
	/* set the local certificate from CertFile */
	n = SSL_CTX_use_certificate_chain_file(vhost->ssl_ctx,
					       info->ssl_cert_filepath);
	if (n != 1) {
		error = ERR_get_error();
		lwsl_err("problem getting cert '%s' %lu: %s\n",
			 info->ssl_cert_filepath, error, ERR_error_string(error,
			       (char *)vhost->context->pt[0].serv_buf));

		return 1;
	}
	lws_ssl_bind_passphrase(vhost->ssl_ctx, info);

	if (info->ssl_private_key_filepath != NULL) {
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(vhost->ssl_ctx,
						info->ssl_private_key_filepath,
					        SSL_FILETYPE_PEM) != 1) {
			error = ERR_get_error();
			lwsl_err("ssl problem getting key '%s' %lu: %s\n",
				 info->ssl_private_key_filepath, error,
				 ERR_error_string(error,
				      (char *)vhost->context->pt[0].serv_buf));
			return 1;
		}
	} else
		if (vhost->protocols[0].callback(wsi,
			LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY,
			vhost->ssl_ctx, NULL, 0)) {
			lwsl_err("ssl private key not set\n");

			return 1;
		}

	/* verify private key */
	if (!SSL_CTX_check_private_key(vhost->ssl_ctx)) {
		lwsl_err("Private SSL key doesn't match cert\n");

		return 1;
	}

#if defined(LWS_HAVE_OPENSSL_ECDH_H)
	if (info->ecdh_curve)
		ecdh_curve = info->ecdh_curve;

	ecdh_nid = OBJ_sn2nid(ecdh_curve);
	if (NID_undef == ecdh_nid) {
		lwsl_err("SSL: Unknown curve name '%s'", ecdh_curve);
		return 1;
	}

	ecdh = EC_KEY_new_by_curve_name(ecdh_nid);
	if (NULL == ecdh) {
		lwsl_err("SSL: Unable to create curve '%s'", ecdh_curve);
		return 1;
	}
	SSL_CTX_set_tmp_ecdh(vhost->ssl_ctx, ecdh);
	EC_KEY_free(ecdh);

	SSL_CTX_set_options(vhost->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);

	lwsl_notice(" SSL ECDH curve '%s'\n", ecdh_curve);

	if (lws_check_opt(vhost->context->options, LWS_SERVER_OPTION_SSL_ECDH))
		lwsl_notice(" Using ECDH certificate support\n");

	/* Get X509 certificate from ssl context */
#if !defined(LWS_HAVE_SSL_EXTRA_CHAIN_CERTS)
	x = sk_X509_value(vhost->ssl_ctx->extra_certs, 0);
#else
	SSL_CTX_get_extra_chain_certs_only(vhost->ssl_ctx, &extra_certs);
	if (extra_certs)
		x = sk_X509_value(extra_certs, 0);
	else
		lwsl_err("%s: no extra certs\n", __func__);
#endif
	if (!x) {
		lwsl_err("%s: x is NULL\n", __func__);
		return 0; // !!!
	}
	/* Get the public key from certificate */
	pkey = X509_get_pubkey(x);
	if (!pkey) {
		lwsl_err("%s: pkey is NULL\n", __func__);

		return 1;
	}
	/* Get the key type */
	KeyType = EVP_PKEY_type(EVP_PKEY_id(pkey));

	if (EVP_PKEY_EC != KeyType) {
		lwsl_notice("Key type is not EC\n");
		return 0;
	}
	/* Get the key */
	EC_key = EVP_PKEY_get1_EC_KEY(pkey);
	/* Set ECDH parameter */
	if (!EC_key) {
		lwsl_err("%s: ECDH key is NULL \n", __func__);
		return 1;
	}
	SSL_CTX_set_tmp_ecdh(vhost->ssl_ctx, EC_key);

	EC_KEY_free(EC_key);
#else
	lwsl_notice(" OpenSSL doesn't support ECDH\n");
#endif

	return 0;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
#if !defined(USE_WOLFSSL)
	BIO *bio;
#endif

	errno = 0;
	wsi->ssl = SSL_new(wsi->vhost->ssl_ctx);
	if (wsi->ssl == NULL) {
		lwsl_err("SSL_new failed: %d (errno %d)\n",
			 lws_ssl_get_error(wsi, 0), errno);

		lws_ssl_elaborate_error();
		return 1;
	}

	SSL_set_ex_data(wsi->ssl, openssl_websocket_private_data_index, wsi);
	SSL_set_fd(wsi->ssl, (int)(long long)accept_fd);

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
	CyaSSL_set_using_nonblock(wsi->ssl, 1);
#else
	wolfSSL_set_using_nonblock(wsi->ssl, 1);
#endif
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

#if defined (LWS_HAVE_SSL_SET_INFO_CALLBACK)
		if (wsi->vhost->ssl_info_event_mask)
			SSL_set_info_callback(wsi->ssl, lws_ssl_info_callback);
#endif

	return 0;
}

int
lws_tls_server_abort_connection(struct lws *wsi)
{
	SSL_shutdown(wsi->ssl);
	SSL_free(wsi->ssl);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	int m, n = SSL_accept(wsi->ssl);

	if (n == 1)
		return LWS_SSL_CAPABLE_DONE;

	m = lws_ssl_get_error(wsi, n);

	if (m == SSL_ERROR_SYSCALL || m == SSL_ERROR_SSL)
		return LWS_SSL_CAPABLE_ERROR;

	if (m == SSL_ERROR_WANT_READ || SSL_want_read(wsi->ssl)) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		lwsl_info("SSL_ERROR_WANT_READ\n");
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
	if (m == SSL_ERROR_WANT_WRITE || SSL_want_write(wsi->ssl)) {
		lwsl_debug("%s: WANT_WRITE\n", __func__);

		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

