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

extern int openssl_websocket_private_data_index,
    openssl_SSL_CTX_private_data_index;

extern void
lws_ssl_bind_passphrase(SSL_CTX *ssl_ctx, struct lws_context_creation_info *info);

extern int lws_ssl_get_error(struct lws *wsi, int n);

int
lws_ssl_client_bio_create(struct lws *wsi)
{
#if defined(LWS_USE_POLARSSL)
	return 0;
#else
#if defined(LWS_USE_MBEDTLS)
#else
	struct lws_context *context = wsi->context;
	const char *hostname = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_HOST);
	X509_VERIFY_PARAM *param;

	(void)hostname;
	(void)param;

	wsi->ssl = SSL_new(wsi->vhost->ssl_client_ctx);
	if (!wsi->ssl) {
		lwsl_err("SSL_new failed: %s\n",
		         ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
		lws_decode_ssl_error();
		return -1;
	}

#if defined LWS_HAVE_X509_VERIFY_PARAM_set1_host
	param = SSL_get0_param(wsi->ssl);
	/* Enable automatic hostname checks */
	X509_VERIFY_PARAM_set_hostflags(param,
					X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	X509_VERIFY_PARAM_set1_host(param, hostname, 0);
	/* Configure a non-zero callback if desired */
	SSL_set_verify(wsi->ssl, SSL_VERIFY_PEER, 0);
#endif

#ifndef USE_WOLFSSL
	SSL_set_mode(wsi->ssl,  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
	/*
	 * use server name indication (SNI), if supported,
	 * when establishing connection
	 */
#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
#ifdef CYASSL_SNI_HOST_NAME
	CyaSSL_UseSNI(wsi->ssl, CYASSL_SNI_HOST_NAME, hostname, strlen(hostname));
#endif
#else
#ifdef WOLFSSL_SNI_HOST_NAME
	wolfSSL_UseSNI(wsi->ssl, WOLFSSL_SNI_HOST_NAME, hostname, strlen(hostname));
#endif
#endif
#else
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_set_tlsext_host_name(wsi->ssl, hostname);
#endif
#endif

#ifdef USE_WOLFSSL
	/*
	 * wolfSSL/CyaSSL does certificate verification differently
	 * from OpenSSL.
	 * If we should ignore the certificate, we need to set
	 * this before SSL_new and SSL_connect is called.
	 * Otherwise the connect will simply fail with error code -155
	 */
#ifdef USE_OLD_CYASSL
	if (wsi->use_ssl == 2)
		CyaSSL_set_verify(wsi->ssl, SSL_VERIFY_NONE, NULL);
#else
	if (wsi->use_ssl == 2)
		wolfSSL_set_verify(wsi->ssl, SSL_VERIFY_NONE, NULL);
#endif
#endif /* USE_WOLFSSL */

	wsi->client_bio = BIO_new_socket(wsi->sock, BIO_NOCLOSE);
	SSL_set_bio(wsi->ssl, wsi->client_bio, wsi->client_bio);

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
	CyaSSL_set_using_nonblock(wsi->ssl, 1);
#else
	wolfSSL_set_using_nonblock(wsi->ssl, 1);
#endif
#else
	BIO_set_nbio(wsi->client_bio, 1); /* nonblocking */
#endif

	SSL_set_ex_data(wsi->ssl, openssl_websocket_private_data_index,
			context);

	return 0;
#endif
#endif
}

int
lws_ssl_client_connect1(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	int n = 0;

	lws_latency_pre(context, wsi);
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
	n = SSL_connect(wsi->ssl);
#endif
#endif
	lws_latency(context, wsi,
	  "SSL_connect LWSCM_WSCL_ISSUE_HANDSHAKE", n, n > 0);

	if (n < 0) {
		n = lws_ssl_get_error(wsi, n);

		if (n == SSL_ERROR_WANT_READ)
			goto some_wait;

		if (n == SSL_ERROR_WANT_WRITE) {
			/*
			 * wants us to retry connect due to
			 * state of the underlying ssl layer...
			 * but since it may be stalled on
			 * blocked write, no incoming data may
			 * arrive to trigger the retry.
			 * Force (possibly many times if the SSL
			 * state persists in returning the
			 * condition code, but other sockets
			 * are getting serviced inbetweentimes)
			 * us to get called back when writable.
			 */
			lwsl_info("%s: WANT_WRITE... retrying\n", __func__);
			lws_callback_on_writable(wsi);
some_wait:
			wsi->mode = LWSCM_WSCL_WAITING_SSL;

			return 0; /* no error */
		}
		n = -1;
	}

	if (n <= 0) {
		/*
		 * retry if new data comes until we
		 * run into the connection timeout or win
		 */
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
		n = ERR_get_error();

		if (n != SSL_ERROR_NONE) {
			struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
			char *p = (char *)&pt->serv_buf[0];
			char *sb = p;
			lwsl_err("SSL connect error %lu: %s\n",
				n, ERR_error_string(n, sb));
			return -1;
		}
#endif
#endif
	}

	return 1;
}

int
lws_ssl_client_connect2(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char *p = (char *)&pt->serv_buf[0];
	char *sb = p;
#endif
#endif
	int n = 0;

	if (wsi->mode == LWSCM_WSCL_WAITING_SSL) {
		lws_latency_pre(context, wsi);
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
		n = SSL_connect(wsi->ssl);
#endif
#endif
		lws_latency(context, wsi,
			    "SSL_connect LWSCM_WSCL_WAITING_SSL", n, n > 0);

		if (n < 0) {
			n = lws_ssl_get_error(wsi, n);

			if (n == SSL_ERROR_WANT_READ) {
				wsi->mode = LWSCM_WSCL_WAITING_SSL;

				return 0; /* no error */
			}

			if (n == SSL_ERROR_WANT_WRITE) {
				/*
				 * wants us to retry connect due to
				 * state of the underlying ssl layer...
				 * but since it may be stalled on
				 * blocked write, no incoming data may
				 * arrive to trigger the retry.
				 * Force (possibly many times if the SSL
				 * state persists in returning the
				 * condition code, but other sockets
				 * are getting serviced inbetweentimes)
				 * us to get called back when writable.
				 */
				lwsl_info("SSL_connect WANT_WRITE... retrying\n");
				lws_callback_on_writable(wsi);

				wsi->mode = LWSCM_WSCL_WAITING_SSL;

				return 0; /* no error */
			}
			n = -1;
		}

		if (n <= 0) {
			/*
			 * retry if new data comes until we
			 * run into the connection timeout or win
			 */
#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
			n = ERR_get_error();
			if (n != SSL_ERROR_NONE) {
				lwsl_err("SSL connect error %lu: %s\n",
					 n, ERR_error_string(n, sb));
				return -1;
			}
#endif
#endif
		}
	}

#if defined(LWS_USE_POLARSSL)
#else
#if defined(LWS_USE_MBEDTLS)
#else
#ifndef USE_WOLFSSL
	/*
	 * See comment above about wolfSSL certificate
	 * verification
	 */
	lws_latency_pre(context, wsi);
	n = SSL_get_verify_result(wsi->ssl);
	lws_latency(context, wsi,
		"SSL_get_verify_result LWS_CONNMODE..HANDSHAKE",
						      n, n > 0);

	if (n != X509_V_OK) {
		if ((n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
		     n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) && wsi->use_ssl == 2) {
			lwsl_notice("accepting self-signed certificate\n");
		} else {
			lwsl_err("server's cert didn't look good, X509_V_ERR = %d: %s\n",
				 n, ERR_error_string(n, sb));
			lws_ssl_elaborate_error();
			return -1;
		}
	}
#endif /* USE_WOLFSSL */
#endif
#endif

	return 1;
}


int lws_context_init_client_ssl(struct lws_context_creation_info *info,
			        struct lws_vhost *vhost)
{
#if defined(LWS_USE_POLARSSL)
	return 0;
#else
#if defined(LWS_USE_MBEDTLS)
#else
	int error;
	int n;
	SSL_METHOD *method;
	struct lws wsi;

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return 0;

	if (info->provided_client_ssl_ctx) {
		/* use the provided OpenSSL context if given one */
		vhost->ssl_client_ctx = info->provided_client_ssl_ctx;
		/* nothing for lib to delete */
		vhost->user_supplied_ssl_ctx = 1;
		return 0;
	}

	if (info->port != CONTEXT_PORT_NO_LISTEN)
		return 0;

	/* basic openssl init */

	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	method = (SSL_METHOD *)SSLv23_client_method();
	if (!method) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl method %lu: %s\n",
			error, ERR_error_string(error,
				      (char *)vhost->context->pt[0].serv_buf));
		return 1;
	}
	/* create context */
	vhost->ssl_client_ctx = SSL_CTX_new(method);
	if (!vhost->ssl_client_ctx) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
			error, ERR_error_string(error,
				      (char *)vhost->context->pt[0].serv_buf));
		return 1;
	}

#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(vhost->ssl_client_ctx,
						 SSL_OP_NO_COMPRESSION);
#endif
	SSL_CTX_set_options(vhost->ssl_client_ctx,
				       SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (info->ssl_cipher_list)
		SSL_CTX_set_cipher_list(vhost->ssl_client_ctx,
						info->ssl_cipher_list);

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS))
		/* loads OS default CA certs */
		SSL_CTX_set_default_verify_paths(vhost->ssl_client_ctx);
#endif

	/* openssl init for cert verification (for client sockets) */
	if (!info->ssl_ca_filepath) {
		if (!SSL_CTX_load_verify_locations(
			vhost->ssl_client_ctx, NULL,
					     LWS_OPENSSL_CLIENT_CERTS))
			lwsl_err(
			    "Unable to load SSL Client certs from %s "
			    "(set by --with-client-cert-dir= "
			    "in configure) --  client ssl isn't "
			    "going to work", LWS_OPENSSL_CLIENT_CERTS);
	} else
		if (!SSL_CTX_load_verify_locations(
			vhost->ssl_client_ctx, info->ssl_ca_filepath,
							  NULL))
			lwsl_err(
				"Unable to load SSL Client certs "
				"file from %s -- client ssl isn't "
				"going to work", info->ssl_ca_filepath);
		else
			lwsl_info("loaded ssl_ca_filepath\n");

	/*
	 * callback allowing user code to load extra verification certs
	 * helping the client to verify server identity
	 */

	/* support for client-side certificate authentication */
	if (info->ssl_cert_filepath) {
		n = SSL_CTX_use_certificate_chain_file(vhost->ssl_client_ctx,
						       info->ssl_cert_filepath);
		if (n != 1) {
			lwsl_err("problem getting cert '%s' %lu: %s\n",
				info->ssl_cert_filepath,
				ERR_get_error(),
				ERR_error_string(ERR_get_error(),
				(char *)vhost->context->pt[0].serv_buf));
			return 1;
		}
	}
	if (info->ssl_private_key_filepath) {
		lws_ssl_bind_passphrase(vhost->ssl_client_ctx, info);
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(vhost->ssl_client_ctx,
		    info->ssl_private_key_filepath, SSL_FILETYPE_PEM) != 1) {
			lwsl_err("use_PrivateKey_file '%s' %lu: %s\n",
				info->ssl_private_key_filepath,
				ERR_get_error(),
				ERR_error_string(ERR_get_error(),
				      (char *)vhost->context->pt[0].serv_buf));
			return 1;
		}

		/* verify private key */
		if (!SSL_CTX_check_private_key(vhost->ssl_client_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			return 1;
		}
	}

	/*
	 * give him a fake wsi with context set, so he can use
	 * lws_get_context() in the callback
	 */
	memset(&wsi, 0, sizeof(wsi));
	wsi.vhost = vhost;
	wsi.context = vhost->context;

	vhost->protocols[0].callback(&wsi,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
				       vhost->ssl_client_ctx, NULL, 0);

	return 0;
#endif
#endif
}
