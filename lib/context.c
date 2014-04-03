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

#ifdef LWS_OPENSSL_SUPPORT
int openssl_websocket_private_data_index;
#endif

#ifndef LWS_BUILD_HASH
#define LWS_BUILD_HASH "unknown-build-hash"
#endif

static const char *library_version = LWS_LIBRARY_VERSION " " LWS_BUILD_HASH;

/**
 * lws_get_library_version: get version and git hash library built from
 *
 *	returns a const char * to a string like "1.1 178d78c"
 *	representing the library version followed by the git head hash it
 *	was built from
 */

LWS_VISIBLE const char *
lws_get_library_version(void)
{
	return library_version;
}

#ifdef LWS_OPENSSL_SUPPORT
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
#endif

/**
 * libwebsocket_create_context() - Create the websocket handler
 * @info:	pointer to struct with parameters
 *
 *	This function creates the listening socket (if serving) and takes care
 *	of all initialization in one step.
 *
 *	After initialization, it returns a struct libwebsocket_context * that
 *	represents this server.  After calling, user code needs to take care
 *	of calling libwebsocket_service() with the context pointer to get the
 *	server's sockets serviced.  This can be done in the same process context
 *	or a forked process, or another thread,
 *
 *	The protocol callback functions are called for a handful of events
 *	including http requests coming in, websocket connections becoming
 *	established, and data arriving; it's also called periodically to allow
 *	async transmission.
 *
 *	HTTP requests are sent always to the FIRST protocol in @protocol, since
 *	at that time websocket protocol has not been negotiated.  Other
 *	protocols after the first one never see any HTTP callack activity.
 *
 *	The server created is a simple http server by default; part of the
 *	websocket standard is upgrading this http connection to a websocket one.
 *
 *	This allows the same server to provide files like scripts and favicon /
 *	images or whatever over http and dynamic data over websockets all in
 *	one place; they're all handled in the user callback.
 */

LWS_VISIBLE struct libwebsocket_context *
libwebsocket_create_context(struct lws_context_creation_info *info)
{
	struct libwebsocket_context *context = NULL;
	char *p;
	int n;
#ifdef LWS_OPENSSL_SUPPORT
	SSL_METHOD *method;
	int error;
#endif

#ifndef LWS_NO_DAEMONIZE
	int pid_daemon = get_daemonize_pid();
#endif

	lwsl_notice("Initial logging level %d\n", log_level);
	lwsl_notice("Library version: %s\n", library_version);
#ifdef LWS_USE_IPV6
	if (!(info->options & LWS_SERVER_OPTION_DISABLE_IPV6))
		lwsl_notice("IPV6 compiled in and enabled\n");
	else
		lwsl_notice("IPV6 compiled in but disabled\n");
#else
	lwsl_notice("IPV6 not compiled in\n");
#endif
#ifdef LWS_USE_LIBEV
	if (info->options & LWS_SERVER_OPTION_LIBEV)
		lwsl_notice("libev support compiled in and enabled\n");
	else
		lwsl_notice("libev support compiled in but disabled\n");
#else
	lwsl_notice("libev support not compiled in\n");
#endif
	lwsl_info(" LWS_MAX_HEADER_LEN: %u\n", LWS_MAX_HEADER_LEN);
	lwsl_info(" LWS_MAX_PROTOCOLS: %u\n", LWS_MAX_PROTOCOLS);
#ifndef LWS_NO_EXTENSIONS
	lwsl_info(" LWS_MAX_EXTENSIONS_ACTIVE: %u\n",
						LWS_MAX_EXTENSIONS_ACTIVE);
#else
	lwsl_notice(" Configured without extension support\n");
#endif
	lwsl_info(" SPEC_LATEST_SUPPORTED: %u\n", SPEC_LATEST_SUPPORTED);
	lwsl_info(" AWAITING_TIMEOUT: %u\n", AWAITING_TIMEOUT);
	if (info->ssl_cipher_list)
		lwsl_info(" SSL ciphers: '%s'\n", info->ssl_cipher_list);
	lwsl_info(" SYSTEM_RANDOM_FILEPATH: '%s'\n", SYSTEM_RANDOM_FILEPATH);
	lwsl_info(" LWS_MAX_ZLIB_CONN_BUFFER: %u\n", LWS_MAX_ZLIB_CONN_BUFFER);

	if (lws_plat_context_early_init())
		return NULL;

	context = (struct libwebsocket_context *)
				malloc(sizeof(struct libwebsocket_context));
	if (!context) {
		lwsl_err("No memory for websocket context\n");
		return NULL;
	}
	memset(context, 0, sizeof(*context));
#ifndef LWS_NO_DAEMONIZE
	context->started_with_parent = pid_daemon;
	lwsl_notice(" Started with daemon pid %d\n", pid_daemon);
#endif

	context->listen_service_extraseen = 0;
	context->protocols = info->protocols;
	context->listen_port = info->port;
	context->http_proxy_port = 0;
	context->http_proxy_address[0] = '\0';
	context->options = info->options;
	context->iface = info->iface;
	/* to reduce this allocation, */
	context->max_fds = getdtablesize();
	lwsl_notice(" static allocation: %u + (%u x %u fds) = %u bytes\n",
		sizeof(struct libwebsocket_context),
		sizeof(struct libwebsocket_pollfd) +
					sizeof(struct libwebsocket *),
		context->max_fds,
		sizeof(struct libwebsocket_context) +
		((sizeof(struct libwebsocket_pollfd) +
					sizeof(struct libwebsocket *)) *
							     context->max_fds));

	context->fds = (struct libwebsocket_pollfd *)
				malloc(sizeof(struct libwebsocket_pollfd) *
							      context->max_fds);
	if (context->fds == NULL) {
		lwsl_err("Unable to allocate fds array for %d connections\n",
							      context->max_fds);
		free(context);
		return NULL;
	}

	context->lws_lookup = (struct libwebsocket **)
		      malloc(sizeof(struct libwebsocket *) * context->max_fds);
	if (context->lws_lookup == NULL) {
		lwsl_err(
		  "Unable to allocate lws_lookup array for %d connections\n",
							      context->max_fds);
		free(context->fds);
		free(context);
		return NULL;
	}
	memset(context->lws_lookup, 0, sizeof(struct libwebsocket *) *
							context->max_fds);

	if (lws_plat_init_fd_tables(context)) {
		free(context->lws_lookup);
		free(context->fds);
		free(context);
		return NULL;
	}

#ifndef LWS_NO_EXTENSIONS
	context->extensions = info->extensions;
#endif
	context->user_space = info->user;

	strcpy(context->canonical_hostname, "unknown");

#ifndef LWS_NO_SERVER
	if (!(info->options & LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME)) {
		/* find canonical hostname */
		gethostname((char *)context->canonical_hostname,
				       sizeof(context->canonical_hostname) - 1);

		lwsl_notice(" canonical_hostname = %s\n",
					context->canonical_hostname);
	}
#endif

	/* split the proxy ads:port if given */

	if (info->http_proxy_address) {
		strncpy(context->http_proxy_address, info->http_proxy_address,
				      sizeof(context->http_proxy_address) - 1);
		context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';
		context->http_proxy_port = info->http_proxy_port;
	} else {
#ifdef HAVE_GETENV
		p = getenv("http_proxy");
		if (p) {
			strncpy(context->http_proxy_address, p,
				       sizeof(context->http_proxy_address) - 1);
			context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';

			p = strchr(context->http_proxy_address, ':');
			if (p == NULL) {
				lwsl_err("http_proxy needs to be ads:port\n");
				goto bail;
			}
			*p = '\0';
			context->http_proxy_port = atoi(p + 1);
		}
#endif
	}

	if (context->http_proxy_address[0])
		lwsl_notice(" Proxy %s:%u\n",
				context->http_proxy_address,
						      context->http_proxy_port);

#ifndef LWS_NO_SERVER
	if (info->port != CONTEXT_PORT_NO_LISTEN) {

#ifdef LWS_OPENSSL_SUPPORT
		context->use_ssl = info->ssl_cert_filepath != NULL &&
					 info->ssl_private_key_filepath != NULL;
#ifdef USE_CYASSL
		lwsl_notice(" Compiled with CYASSL support\n");
#else
		lwsl_notice(" Compiled with OpenSSL support\n");
#endif
		if (context->use_ssl)
			lwsl_notice(" Using SSL mode\n");
		else
			lwsl_notice(" Using non-SSL mode\n");

#else
		if (info->ssl_cert_filepath != NULL &&
				       info->ssl_private_key_filepath != NULL) {
			lwsl_notice(" Not compiled for OpenSSl support!\n");
			goto bail;
		}
		lwsl_notice(" Compiled without SSL support\n");
#endif

		lwsl_notice(
			" per-conn mem: %u + %u headers + protocol rx buf\n",
				sizeof(struct libwebsocket),
					      sizeof(struct allocated_headers));
	}
#endif

#ifdef LWS_OPENSSL_SUPPORT

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
		goto bail;
	}
	context->ssl_ctx = SSL_CTX_new(method);	/* create context */
	if (!context->ssl_ctx) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
			error, ERR_error_string(error,
					      (char *)context->service_buffer));
		goto bail;
	}

#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(context->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
	SSL_CTX_set_options(context->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (info->ssl_cipher_list)
		SSL_CTX_set_cipher_list(context->ssl_ctx,
						info->ssl_cipher_list);

	if (lws_context_init_client(info, context))
		goto bail;

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
			goto bail;
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
			goto bail;
		}
		/* verify private key */
		if (!SSL_CTX_check_private_key(context->ssl_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			goto bail;
		}

		/* SSL is happy and has a cert it's content with */
	}
#endif

	if (lws_context_init_server(info, context))
		goto bail;

	/*
	 * drop any root privs for this process
	 * to listen on port < 1023 we would have needed root, but now we are
	 * listening, we don't want the power for anything else
	 */
	lws_plat_drop_app_privileges(info);

	/* initialize supported protocols */

	for (context->count_protocols = 0;
		info->protocols[context->count_protocols].callback;
						   context->count_protocols++) {

		lwsl_parser("  Protocol: %s\n",
				info->protocols[context->count_protocols].name);

		info->protocols[context->count_protocols].owning_server =
									context;
		info->protocols[context->count_protocols].protocol_index =
						       context->count_protocols;

		/*
		 * inform all the protocols that they are doing their one-time
		 * initialization if they want to
		 */
		info->protocols[context->count_protocols].callback(context,
			       NULL, LWS_CALLBACK_PROTOCOL_INIT, NULL, NULL, 0);
	}

	/*
	 * give all extensions a chance to create any per-context
	 * allocations they need
	 */

	if (info->port != CONTEXT_PORT_NO_LISTEN) {
		if (lws_ext_callback_for_each_extension_type(context, NULL,
				LWS_EXT_CALLBACK_SERVER_CONTEXT_CONSTRUCT,
								   NULL, 0) < 0)
			goto bail;
	} else
		if (lws_ext_callback_for_each_extension_type(context, NULL,
				LWS_EXT_CALLBACK_CLIENT_CONTEXT_CONSTRUCT,
								   NULL, 0) < 0)
			goto bail;

	return context;

bail:
	libwebsocket_context_destroy(context);
	return NULL;
}

/**
 * libwebsocket_context_destroy() - Destroy the websocket context
 * @context:	Websocket context
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */
LWS_VISIBLE void
libwebsocket_context_destroy(struct libwebsocket_context *context)
{
	int n;
	struct libwebsocket_protocols *protocol = context->protocols;

#ifdef LWS_LATENCY
	if (context->worst_latency_info[0])
		lwsl_notice("Worst latency: %s\n", context->worst_latency_info);
#endif

	for (n = 0; n < context->fds_count; n++) {
		struct libwebsocket *wsi =
					context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		libwebsocket_close_and_free_session(context,
			wsi, LWS_CLOSE_STATUS_NOSTATUS /* no protocol close */);
		n--;
	}

	/*
	 * give all extensions a chance to clean up any per-context
	 * allocations they might have made
	 */
	if (context->listen_port) {
		if (lws_ext_callback_for_each_extension_type(context, NULL,
			 LWS_EXT_CALLBACK_SERVER_CONTEXT_DESTRUCT, NULL, 0) < 0)
			return;
	} else
		if (lws_ext_callback_for_each_extension_type(context, NULL,
			 LWS_EXT_CALLBACK_CLIENT_CONTEXT_DESTRUCT, NULL, 0) < 0)
			return;

	/*
	 * inform all the protocols that they are done and will have no more
	 * callbacks
	 */

	while (protocol->callback) {
		protocol->callback(context, NULL, LWS_CALLBACK_PROTOCOL_DESTROY,
				NULL, NULL, 0);
		protocol++;
	}

	lws_plat_context_early_destroy(context);

#ifdef LWS_OPENSSL_SUPPORT
	if (context->ssl_ctx)
		SSL_CTX_free(context->ssl_ctx);
	if (context->ssl_client_ctx)
		SSL_CTX_free(context->ssl_client_ctx);

	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif

	if (context->fds)
		free(context->fds);
	if (context->lws_lookup)
		free(context->lws_lookup);

	free(context);

	lws_plat_context_late_destroy(context);
}
