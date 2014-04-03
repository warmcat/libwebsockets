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

int openssl_websocket_private_data_index;

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

	/* basic openssl init */

	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "libwebsockets", NULL, NULL, NULL);

	/*
	 * Firefox insists on SSLv23 not SSLv3
	 * Konq disables SSLv2 by default now, SSLv23 works
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
		/* verify private key */
		if (!SSL_CTX_check_private_key(context->ssl_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			return 1;
		}

		/* SSL is happy and has a cert it's content with */
	}
	
	return 0;
}

LWS_VISIBLE void
lws_ssl_destroy(struct libwebsocket_context *context)
{
	if (context->ssl_ctx)
		SSL_CTX_free(context->ssl_ctx);
	if (context->ssl_client_ctx)
		SSL_CTX_free(context->ssl_client_ctx);

	ERR_remove_state(0);
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

	if (info->port != CONTEXT_PORT_NO_LISTEN)
		return 0;

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
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(context->ssl_client_ctx,
			     info->ssl_private_key_filepath,
					       SSL_FILETYPE_PEM) != 1) {
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