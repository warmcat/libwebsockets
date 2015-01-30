/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2014 Andy Green <andy@warmcat.com>
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
 #include <openssl/err.h>

int openssl_websocket_private_data_index;

static int lws_context_init_ssl_pem_passwd_cb(char * buf, int size, int rwflag, void *userdata)
{
	struct lws_context_creation_info * info = (struct lws_context_creation_info *)userdata;

	strncpy(buf, info->ssl_private_key_password, size);
	buf[size - 1] = '\0';

	return strlen(buf);
}

static void lws_ssl_bind_passphrase(SSL_CTX *ssl_ctx,
				    struct lws_context_creation_info *info)
{
	if (!info->ssl_private_key_password)
		return;
	/*
	 * password provided, set ssl callback and user data
	 * for checking password which will be trigered during
	 * SSL_CTX_use_PrivateKey_file function
	 */
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)info);
	SSL_CTX_set_default_passwd_cb(ssl_ctx,
				      lws_context_init_ssl_pem_passwd_cb);
}

#ifndef LWS_NO_SERVER
static int
OpenSSL_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	SSL *ssl;
	int n;
	struct libwebsocket_context *context;

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());

	/*
	 * !!! nasty openssl requires the index to come as a library-scope
	 * static
	 */
	context = SSL_get_ex_data(ssl, openssl_websocket_private_data_index);

	n = context->protocols[0].callback(NULL, NULL,
		LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
						   x509_ctx, ssl, preverify_ok);

	/* convert return code from 0 = OK to 1 = OK */
	return !n;
}

LWS_VISIBLE int
lws_context_init_server_ssl(struct lws_context_creation_info *info,
		     struct libwebsocket_context *context)
{
	SSL_METHOD *method;
	int error;
	int n;

	if (info->port != CONTEXT_PORT_NO_LISTEN) {

		context->use_ssl = info->ssl_cert_filepath != NULL;

#ifdef USE_CYASSL
		lwsl_notice(" Compiled with CYASSL support\n");
#else
		lwsl_notice(" Compiled with OpenSSL support\n");
#endif
		
		if (info->ssl_cipher_list)
			lwsl_notice(" SSL ciphers: '%s'\n", info->ssl_cipher_list);

		if (context->use_ssl)
			lwsl_notice(" Using SSL mode\n");
		else
			lwsl_notice(" Using non-SSL mode\n");
	}

	/* basic openssl init */

	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "libwebsockets", NULL, NULL, NULL);

	/*
	 * Firefox insists on SSLv23 not SSLv3
	 * Konq disables SSLv2 by default now, SSLv23 works
	 *
	 * SSLv23_server_method() is the openssl method for "allow all TLS
	 * versions", compared to e.g. TLSv1_2_server_method() which only allows
	 * tlsv1.2. Unwanted versions must be disabled using SSL_CTX_set_options()
	 */

	method = (SSL_METHOD *)SSLv23_server_method();
	if (!method) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl method %lu: %s\n", 
			error, ERR_error_string(error,
					      (char *)context->service_buffer));
		return 1;
	}
	context->ssl_ctx = SSL_CTX_new(method);	/* create context */
	if (!context->ssl_ctx) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
			error, ERR_error_string(error,
					      (char *)context->service_buffer));
		return 1;
	}

	/* Disable SSLv2 and SSLv3 */
	SSL_CTX_set_options(context->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(context->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
	SSL_CTX_set_options(context->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (info->ssl_cipher_list)
		SSL_CTX_set_cipher_list(context->ssl_ctx,
						info->ssl_cipher_list);

	/* as a server, are we requiring clients to identify themselves? */

	if (info->options &
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) {

		/* absolutely require the client cert */

		SSL_CTX_set_verify(context->ssl_ctx,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						       OpenSSL_verify_callback);

		/*
		 * give user code a chance to load certs into the server
		 * allowing it to verify incoming client certs
		 */

		context->protocols[0].callback(context, NULL,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
						     context->ssl_ctx, NULL, 0);
	}

	if (info->options & LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT) {
		/* Normally SSL listener rejects non-ssl, optionally allow */
		context->allow_non_ssl_on_ssl_port = 1;
	}

	if (context->use_ssl) {

		/* openssl init for server sockets */

		/* set the local certificate from CertFile */
		n = SSL_CTX_use_certificate_chain_file(context->ssl_ctx,
					info->ssl_cert_filepath);
		if (n != 1) {
			error = ERR_get_error();
			lwsl_err("problem getting cert '%s' %lu: %s\n",
				info->ssl_cert_filepath,
				error,
				ERR_error_string(error,
					      (char *)context->service_buffer));
			return 1;
		}
		lws_ssl_bind_passphrase(context->ssl_ctx, info);

		if (info->ssl_private_key_filepath != NULL) {
			/* set the private key from KeyFile */
			if (SSL_CTX_use_PrivateKey_file(context->ssl_ctx,
				     info->ssl_private_key_filepath,
						       SSL_FILETYPE_PEM) != 1) {
				error = ERR_get_error();
				lwsl_err("ssl problem getting key '%s' %lu: %s\n",
					info->ssl_private_key_filepath,
						error,
						ERR_error_string(error,
						      (char *)context->service_buffer));
				return 1;
			}
		}
		else {
			if (context->protocols[0].callback(context, NULL,
				LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY,
						context->ssl_ctx, NULL, 0)) {
				lwsl_err("ssl private key not set\n");
				return 1;
			}
		}

		/* verify private key */
		if (!SSL_CTX_check_private_key(context->ssl_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			return 1;
		}

		/*
		 * SSL is happy and has a cert it's content with
		 * If we're supporting HTTP2, initialize that
		 */
		
		lws_context_init_http2_ssl(context);
	}
	
	return 0;
}
#endif

LWS_VISIBLE void
lws_ssl_destroy(struct libwebsocket_context *context)
{
	if (context->ssl_ctx)
		SSL_CTX_free(context->ssl_ctx);
	if (!context->user_supplied_ssl_ctx && context->ssl_client_ctx)
		SSL_CTX_free(context->ssl_client_ctx);

#if (OPENSSL_VERSION_NUMBER < 0x01000000) || defined(USE_CYASSL)
	ERR_remove_state(0);
#else
	ERR_remove_thread_state(NULL);
#endif
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

LWS_VISIBLE void
libwebsockets_decode_ssl_error(void)
{
	char buf[256];
	u_long err;

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		lwsl_err("*** %lu %s\n", err, buf);
	}
}

#ifndef LWS_NO_CLIENT

int lws_context_init_client_ssl(struct lws_context_creation_info *info,
			    struct libwebsocket_context *context)
{
	int error;
	int n;
	SSL_METHOD *method;

	if (info->provided_client_ssl_ctx) {
		/* use the provided OpenSSL context if given one */
		context->ssl_client_ctx = info->provided_client_ssl_ctx;
		/* nothing for lib to delete */
		context->user_supplied_ssl_ctx = 1;
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
				      (char *)context->service_buffer));
		return 1;
	}
	/* create context */
	context->ssl_client_ctx = SSL_CTX_new(method);
	if (!context->ssl_client_ctx) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
			error, ERR_error_string(error,
				      (char *)context->service_buffer));
		return 1;
	}

#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(context->ssl_client_ctx,
						 SSL_OP_NO_COMPRESSION);
#endif
	SSL_CTX_set_options(context->ssl_client_ctx,
				       SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (info->ssl_cipher_list)
		SSL_CTX_set_cipher_list(context->ssl_client_ctx,
						info->ssl_cipher_list);

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
	if (!(info->options & LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS))
		/* loads OS default CA certs */
		SSL_CTX_set_default_verify_paths(context->ssl_client_ctx);
#endif

	/* openssl init for cert verification (for client sockets) */
	if (!info->ssl_ca_filepath) {
		if (!SSL_CTX_load_verify_locations(
			context->ssl_client_ctx, NULL,
					     LWS_OPENSSL_CLIENT_CERTS))
			lwsl_err(
			    "Unable to load SSL Client certs from %s "
			    "(set by --with-client-cert-dir= "
			    "in configure) --  client ssl isn't "
			    "going to work", LWS_OPENSSL_CLIENT_CERTS);
	} else
		if (!SSL_CTX_load_verify_locations(
			context->ssl_client_ctx, info->ssl_ca_filepath,
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
		n = SSL_CTX_use_certificate_chain_file(
			context->ssl_client_ctx,
					info->ssl_cert_filepath);
		if (n != 1) {
			lwsl_err("problem getting cert '%s' %lu: %s\n",
				info->ssl_cert_filepath,
				ERR_get_error(),
				ERR_error_string(ERR_get_error(),
				(char *)context->service_buffer));
			return 1;
		}
	} 
	if (info->ssl_private_key_filepath) {
		lws_ssl_bind_passphrase(context->ssl_client_ctx, info);
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(context->ssl_client_ctx,
		    info->ssl_private_key_filepath, SSL_FILETYPE_PEM) != 1) {
			lwsl_err("use_PrivateKey_file '%s' %lu: %s\n",
				info->ssl_private_key_filepath,
				ERR_get_error(),
				ERR_error_string(ERR_get_error(),
				      (char *)context->service_buffer));
			return 1;
		}

		/* verify private key */
		if (!SSL_CTX_check_private_key(
					context->ssl_client_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			return 1;
		}
	} 

	context->protocols[0].callback(context, NULL,
		LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
		context->ssl_client_ctx, NULL, 0);
	
	return 0;
}
#endif

LWS_VISIBLE void
lws_ssl_remove_wsi_from_buffered_list(struct libwebsocket_context *context,
		     struct libwebsocket *wsi)
{
	if (!wsi->pending_read_list_prev &&
	    !wsi->pending_read_list_next &&
	    context->pending_read_list != wsi)
		/* we are not on the list */
		return;

	/* point previous guy's next to our next */
	if (!wsi->pending_read_list_prev)
		context->pending_read_list = wsi->pending_read_list_next;
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
lws_ssl_capable_read(struct libwebsocket_context *context,
		     struct libwebsocket *wsi, unsigned char *buf, int len)
{
	int n;

	if (!wsi->ssl)
		return lws_ssl_capable_read_no_ssl(context, wsi, buf, len);

	n = SSL_read(wsi->ssl, buf, len);
	if (n >= 0) {
		/* 
		 * if it was our buffer that limited what we read,
		 * check if SSL has additional data pending inside SSL buffers.
		 * 
		 * Because these won't signal at the network layer with POLLIN
		 * and if we don't realize, this data will sit there forever
		 */
		if (n == len && wsi->ssl && SSL_pending(wsi->ssl)) {
			if (!wsi->pending_read_list_next && !wsi->pending_read_list_prev) {
				/* add us to the linked list of guys with pending ssl */
				if (context->pending_read_list)
					context->pending_read_list->pending_read_list_prev = wsi;
				wsi->pending_read_list_next = context->pending_read_list;
				wsi->pending_read_list_prev = NULL;
				context->pending_read_list = wsi;
			}
		} else
			lws_ssl_remove_wsi_from_buffered_list(context, wsi);

		return n;
	}
	n = SSL_get_error(wsi->ssl, n);
	if (n ==  SSL_ERROR_WANT_READ || n ==  SSL_ERROR_WANT_WRITE)
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	return LWS_SSL_CAPABLE_ERROR; 
}

LWS_VISIBLE int
lws_ssl_capable_write(struct libwebsocket *wsi, unsigned char *buf, int len)
{
	int n;

	if (!wsi->ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);
	
	n = SSL_write(wsi->ssl, buf, len);
	if (n >= 0)
		return n;

	n = SSL_get_error(wsi->ssl, n);
	if (n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) {
		if (n == SSL_ERROR_WANT_WRITE)
			lws_set_blocking_send(wsi);
		return LWS_SSL_CAPABLE_MORE_SERVICE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

LWS_VISIBLE int
lws_ssl_close(struct libwebsocket *wsi)
{
	int n;

	if (!wsi->ssl)
		return 0; /* not handled */

	n = SSL_get_fd(wsi->ssl);
	SSL_shutdown(wsi->ssl);
	compatible_close(n);
	SSL_free(wsi->ssl);

	return 1; /* handled */
}

LWS_VISIBLE int
lws_server_socket_service_ssl(struct libwebsocket_context *context,
		struct libwebsocket **pwsi, struct libwebsocket *new_wsi,
			int accept_fd, struct libwebsocket_pollfd *pollfd)
{
	int n, m;
	struct libwebsocket *wsi = *pwsi;
#ifndef USE_CYASSL
	BIO *bio;
#endif

	if (!LWS_SSL_ENABLED(context))
		return 0;

	switch (wsi->mode) {
	case LWS_CONNMODE_SERVER_LISTENER:

		if (!new_wsi) {
			lwsl_err("no new_wsi\n");
			return 0;
		}

		new_wsi->ssl = SSL_new(context->ssl_ctx);
		if (new_wsi->ssl == NULL) {
			lwsl_err("SSL_new failed: %s\n",
			    ERR_error_string(SSL_get_error(
			    new_wsi->ssl, 0), NULL));
			    libwebsockets_decode_ssl_error();
			lws_free(new_wsi);
			compatible_close(accept_fd);
			break;
		}

		SSL_set_ex_data(new_wsi->ssl,
			openssl_websocket_private_data_index, context);

		SSL_set_fd(new_wsi->ssl, accept_fd);

#ifdef USE_CYASSL
		CyaSSL_set_using_nonblock(new_wsi->ssl, 1);
#else
		SSL_set_mode(new_wsi->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		bio = SSL_get_rbio(new_wsi->ssl);
		if (bio)
			BIO_set_nbio(bio, 1); /* nonblocking */
		else
			lwsl_notice("NULL rbio\n");
		bio = SSL_get_wbio(new_wsi->ssl);
		if (bio)
			BIO_set_nbio(bio, 1); /* nonblocking */
		else
			lwsl_notice("NULL rbio\n");
#endif

		/*
		 * we are not accepted yet, but we need to enter ourselves
		 * as a live connection.  That way we can retry when more
		 * pieces come if we're not sorted yet
		 */

		*pwsi = new_wsi;
		wsi = *pwsi;
		wsi->mode = LWS_CONNMODE_SSL_ACK_PENDING;
		insert_wsi_socket_into_fds(context, wsi);

		libwebsocket_set_timeout(wsi, PENDING_TIMEOUT_SSL_ACCEPT,
							AWAITING_TIMEOUT);

		lwsl_info("inserted SSL accept into fds, trying SSL_accept\n");

		/* fallthru */

	case LWS_CONNMODE_SSL_ACK_PENDING:

		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0))
			goto fail;

		lws_libev_io(context, wsi, LWS_EV_STOP | LWS_EV_WRITE);

		lws_latency_pre(context, wsi);

		n = recv(wsi->sock, context->service_buffer,
			sizeof(context->service_buffer), MSG_PEEK);

		/*
		 * optionally allow non-SSL connect on SSL listening socket
		 * This is disabled by default, if enabled it goes around any
		 * SSL-level access control (eg, client-side certs) so leave
		 * it disabled unless you know it's not a problem for you
		 */

		if (context->allow_non_ssl_on_ssl_port && n >= 1 &&
					context->service_buffer[0] >= ' ') {
			/*
			 * TLS content-type for Handshake is 0x16
			 * TLS content-type for ChangeCipherSpec Record is 0x14
			 *
			 * A non-ssl session will start with the HTTP method in
			 * ASCII.  If we see it's not a legit SSL handshake
			 * kill the SSL for this connection and try to handle
			 * as a HTTP connection upgrade directly.
			 */
			wsi->use_ssl = 0;
			SSL_shutdown(wsi->ssl);
			SSL_free(wsi->ssl);
			wsi->ssl = NULL;
			goto accepted;
		}

		/* normal SSL connection processing path */

		n = SSL_accept(wsi->ssl);
		lws_latency(context, wsi,
			"SSL_accept LWS_CONNMODE_SSL_ACK_PENDING\n", n, n == 1);

		if (n == 1)
			goto accepted;

		m = SSL_get_error(wsi->ssl, n);
		lwsl_debug("SSL_accept failed %d / %s\n",
						  m, ERR_error_string(m, NULL));

		if (m == SSL_ERROR_WANT_READ) {
			if (lws_change_pollfd(wsi, 0, LWS_POLLIN))
				goto fail;

			lws_libev_io(context, wsi, LWS_EV_START | LWS_EV_READ);

			lwsl_info("SSL_ERROR_WANT_READ\n");
			break;
		}
		if (m == SSL_ERROR_WANT_WRITE) {
			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
				goto fail;

			lws_libev_io(context, wsi, LWS_EV_START | LWS_EV_WRITE);
			break;
		}
		lwsl_debug("SSL_accept failed skt %u: %s\n",
					 pollfd->fd, ERR_error_string(m, NULL));
		goto fail;

accepted:
		/* OK, we are accepted... give him some time to negotiate */
		libwebsocket_set_timeout(wsi,
			PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
							AWAITING_TIMEOUT);

		wsi->mode = LWS_CONNMODE_HTTP_SERVING;

		lws_http2_configure_if_upgraded(wsi);

		lwsl_debug("accepted new SSL conn\n");
		break;
	}

	return 0;
	
fail:
	return 1;
}

LWS_VISIBLE void
lws_ssl_context_destroy(struct libwebsocket_context *context)
{
	if (context->ssl_ctx)
		SSL_CTX_free(context->ssl_ctx);
	if (!context->user_supplied_ssl_ctx && context->ssl_client_ctx)
		SSL_CTX_free(context->ssl_client_ctx);

#if (OPENSSL_VERSION_NUMBER < 0x01000000) || defined(USE_CYASSL)
	ERR_remove_state(0);
#else
	ERR_remove_thread_state(NULL);
#endif
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}
