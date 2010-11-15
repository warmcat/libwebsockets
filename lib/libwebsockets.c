/*
 * libwebsockets - small server side websockets and web server implementation
 * 
 * Copyright (C) 2010 Andy Green <andy@warmcat.com>
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
SSL_CTX *ssl_ctx;
int use_ssl;
#endif


extern int 
libwebsocket_read(struct libwebsocket *wsi, unsigned char * buf, size_t len);


/* document the generic callback (it's a fake prototype under this) */
/**
 * callback() - User server actions
 * @wsi:	Opaque websocket instance pointer
 * @reason:	The reason for the call
 * @user:	Pointer to per-session user data allocated by library
 * @in:		Pointer used for some callback reasons
 * @len:	Length set for some callback reasons
 * 
 * 	This callback is the way the user controls what is served.  All the
 * 	protocol detail is hidden and handled by the library.
 * 
 * 	For each connection / session there is user data allocated that is
 * 	pointed to by "user".  You set the size of this user data area when
 * 	the library is initialized with libwebsocket_create_server.
 * 
 * 	You get an opportunity to initialize user data when called back with
 * 	LWS_CALLBACK_ESTABLISHED reason.
 * 
 * 	LWS_CALLBACK_ESTABLISHED:  after successful websocket handshake
 * 
 * 	LWS_CALLBACK_CLOSED: when the websocket session ends
 *
 * 	LWS_CALLBACK_SEND: opportunity to send to client (you would use
 * 				libwebsocket_write() taking care about the
 * 				special buffer requirements
 * 	LWS_CALLBACK_RECEIVE: data has appeared for the server, it can be
 *				found at *in and is len bytes long
 *
 *  	LWS_CALLBACK_HTTP: an http request has come from a client that is not
 * 				asking to upgrade the connection to a websocket
 * 				one.  This is a chance to serve http content,
 * 				for example, to send a script to the client
 * 				which will then open the websockets connection.
 * 				@in points to the URI path requested and 
 * 				libwebsockets_serve_http_file() makes it very
 * 				simple to send back a file to the client.
 */
extern int callback(struct libwebsocket * wsi,
			 enum libwebsocket_callback_reasons reason, void * user,
							  void *in, size_t len);


void 
libwebsocket_close_and_free_session(struct libwebsocket *wsi)
{
	int n = wsi->state;

	wsi->state = WSI_STATE_DEAD_SOCKET;

	if (wsi->protocol->callback && n == WSI_STATE_ESTABLISHED)
		wsi->protocol->callback(wsi, LWS_CALLBACK_CLOSED,
						      wsi->user_space, NULL, 0);

	for (n = 0; n < WSI_TOKEN_COUNT; n++)
		if (wsi->utf8_token[n].token)
			free(wsi->utf8_token[n].token);

//	fprintf(stderr, "closing fd=%d\n", wsi->sock);

#ifdef LWS_OPENSSL_SUPPORT
	if (use_ssl) {
		n = SSL_get_fd(wsi->ssl);
		SSL_shutdown(wsi->ssl);
		close(n);
		SSL_free(wsi->ssl);
	} else {
#endif
		shutdown(wsi->sock, SHUT_RDWR);
		close(wsi->sock);
#ifdef LWS_OPENSSL_SUPPORT
	}
#endif
	if (wsi->user_space)
		free(wsi->user_space);

	free(wsi);
}

/**
 * libwebsocket_create_server() - Create the listening websockets server
 * @port:	Port to listen on
 * @protocols:	Array of structures listing supported protocols and a protocol-
 * 		specific callback for each one.  The list is ended with an
 * 		entry that has a NULL callback pointer.
 * @ssl_cert_filepath:	If libwebsockets was compiled to use ssl, and you want
 * 			to listen using SSL, set to the filepath to fetch the
 * 			server cert from, otherwise NULL for unencrypted
 * @ssl_private_key_filepath: filepath to private key if wanting SSL mode,
 * 			else ignored
 * @gid:	group id to change to after setting listen socket, or -1.
 * @uid:	user id to change to after setting listen socket, or -1.
 * 
 * 	This function creates the listening socket and takes care
 * 	of all initialization in one step.
 *
 * 	It does not return since it sits in a service loop and operates via the
 * 	callbacks given in @protocol.  User code should fork before calling
 * 	libwebsocket_create_server() if it wants to do other things in
 * 	parallel other than serve websockets.
 * 
 * 	The protocol callback functions are called for a handful of events
 * 	including http requests coming in, websocket connections becoming
 * 	established, and data arriving; it's also called periodically to allow
 * 	async transmission.
 *
 * 	HTTP requests are sent always to the FIRST protocol in @protocol, since
 * 	at that time websocket protocol has not been negotiated.  Other
 * 	protocols after the first one never see any HTTP callack activity.
 * 
 * 	The server created is a simple http server by default; part of the
 * 	websocket standard is upgrading this http connection to a websocket one.
 * 
 * 	This allows the same server to provide files like scripts and favicon /
 * 	images or whatever over http and dynamic data over websockets all in
 * 	one place; they're all handled in the user callback.
 */

int libwebsocket_create_server(int port,
			       const struct libwebsocket_protocols *protocols,
			       const char * ssl_cert_filepath,
			       const char * ssl_private_key_filepath,
			       int gid, int uid)
{
	int n;
	int client;
	int sockfd;
	int fd;
	unsigned int clilen;
	struct sockaddr_in serv_addr, cli_addr;
	struct libwebsocket *wsi[MAX_CLIENTS + 1];
	struct pollfd fds[MAX_CLIENTS + 1];
	int fds_count = 0;
	unsigned char buf[1024];
	int opt = 1;

#ifdef LWS_OPENSSL_SUPPORT
	SSL_METHOD *method;
	char ssl_err_buf[512];

	use_ssl = ssl_cert_filepath != NULL && ssl_private_key_filepath != NULL;
	if (use_ssl)
		fprintf(stderr, " Compiled with SSL support, using it\n");
	else
		fprintf(stderr, " Compiled with SSL support, not using it\n");

#else
	if (ssl_cert_filepath != NULL && ssl_private_key_filepath != NULL) {
		fprintf(stderr, " Not compiled for OpenSSl support!\n");
		return -1;
	}
	fprintf(stderr, " Compiled without SSL support, serving unencrypted\n");
#endif

#ifdef LWS_OPENSSL_SUPPORT
	if (use_ssl) {
		SSL_library_init();

		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

			// Firefox insists on SSLv23 not SSLv3
			// Konq disables SSLv2 by default now, SSLv23 works

		method = SSLv23_server_method();   // create server instance
		if (!method) {
			fprintf(stderr, "problem creating ssl method: %s\n",
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return -1;
		}
		ssl_ctx = SSL_CTX_new(method);	/* create context */
		if (!ssl_ctx) {
			printf("problem creating ssl context: %s\n",
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return -1;
		}
		/* set the local certificate from CertFile */
		n = SSL_CTX_use_certificate_file(ssl_ctx,
					ssl_cert_filepath, SSL_FILETYPE_PEM);
		if (n != 1) {
			fprintf(stderr, "problem getting cert '%s': %s\n",
				ssl_cert_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return -1;
		}
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx,
						ssl_private_key_filepath,
						SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "ssl problem getting key '%s': %s\n",
						ssl_private_key_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return (-1);
		}
		/* verify private key */
		if (!SSL_CTX_check_private_key(ssl_ctx)) {
			fprintf(stderr, "Private SSL key doesn't match cert\n");
			return (-1);
		}

		/* SSL is happy and has a cert it's content with */
	}
#endif
  
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "ERROR opening socket");
		return -1;
	}
	
	/* allow us to restart even if old sockets in TIME_WAIT */
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	n = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (n < 0) {
              fprintf(stderr, "ERROR on binding to port %d (%d %d)\n", port, n,
									 errno);
              return -1;
        }
 
	/* drop any root privs for this process */

	if (gid != -1)
		if (setgid(gid))
			fprintf(stderr, "setgid: %s\n", strerror(errno));
	if (uid != -1)
		if (setuid(uid))
			fprintf(stderr, "setuid: %s\n", strerror(errno));

 	/*
	 * sit there listening for connects, accept and service connections
	 * in a poll loop, without any forking
	 */

	listen(sockfd, 5);
	fprintf(stderr, " Listening on port %d\n", port);
 	
	fds[0].fd = sockfd;
	fds_count = 1;
	fds[0].events = POLLIN;
    
	while (1) {

 		n = poll(fds, fds_count, 50);
		if (n < 0 || fds[0].revents & (POLLERR | POLLHUP)) {
			fprintf(stderr, "Listen Socket dead\n");
			goto fatal;
		}
		if (n == 0) /* poll timeout */
			goto poll_out;

		if (fds[0].revents & POLLIN) {

			/* listen socket got an unencrypted connection... */

			clilen = sizeof(cli_addr);
			fd  = accept(sockfd,
				     (struct sockaddr *)&cli_addr,
							       &clilen);
			if (fd < 0) {
				fprintf(stderr, "ERROR on accept");
				continue;
			}

			if (fds_count >= MAX_CLIENTS) {
				fprintf(stderr, "too busy");
				close(fd);
				continue;
			}

			wsi[fds_count] = malloc(sizeof(struct libwebsocket));
			if (!wsi[fds_count])
				return -1;

#ifdef LWS_OPENSSL_SUPPORT
			if (use_ssl) {

				wsi[fds_count]->ssl = SSL_new(ssl_ctx);
				if (wsi[fds_count]->ssl == NULL) {
					fprintf(stderr, "SSL_new failed: %s\n",
					    ERR_error_string(SSL_get_error(
					        wsi[fds_count]->ssl, 0), NULL));
					free(wsi[fds_count]);
					continue;
				}

				SSL_set_fd(wsi[fds_count]->ssl, fd);

				n = SSL_accept(wsi[fds_count]->ssl);
				if (n != 1) {
					/*
					 * browsers seem to probe with various
					 * ssl params which fail then retry
					 * and succeed
					 */
					debug("SSL_accept failed skt %u: %s\n",
						fd,
						ERR_error_string(SSL_get_error(
						wsi[fds_count]->ssl, n), NULL));
					SSL_free(wsi[fds_count]->ssl);
					free(wsi[fds_count]);
					continue;
				}
				debug("accepted new SSL conn  "
				      "port %u on fd=%d SSL ver %s\n",
					ntohs(cli_addr.sin_port), fd,
					  SSL_get_version(wsi[fds_count]->ssl));
				
			} else
#endif
				debug("accepted new conn  port %u on fd=%d\n",
						  ntohs(cli_addr.sin_port), fd);
			
			/* intialize the instance struct */

			wsi[fds_count]->sock = fd;
			wsi[fds_count]->state = WSI_STATE_HTTP;
			wsi[fds_count]->name_buffer_pos = 0;

			for (n = 0; n < WSI_TOKEN_COUNT; n++) {
				wsi[fds_count]->utf8_token[n].token = NULL;
				wsi[fds_count]->utf8_token[n].token_len = 0;
			}

			/*
			 * these can only be set once the protocol is known
			 * we set an unestablished connection's protocol pointer
			 * to the start of the supported list, so it can look
			 * for matching ones during the handshake
			 */
			wsi[fds_count]->protocol = protocols;
			wsi[fds_count]->user_space = NULL;

			/*
			 * Default protocol is 76
			 * After 76, there's a header specified to inform which
			 * draft the client wants, when that's seen we modify
			 * the individual connection's spec revision accordingly
			 */
			wsi[fds_count]->ietf_spec_revision = 76;

			fds[fds_count].events = POLLIN;
			fds[fds_count++].fd = fd;

			/*
			 * make sure NO events are seen yet on this new socket
			 * (otherwise we inherit old fds[client].revents from
			 * previous socket there and die mysteriously! )
			 */
			fds[client].revents = 0;
		}
		
		/* check for activity on client sockets */
		
		for (client = 1; client < fds_count; client++) {
			
			/* handle session socket closed */
			
			if (fds[client].revents & (POLLERR | POLLHUP)) {
				
				debug("Session Socket %d %p (fd=%d) dead\n",
					      client, wsi[client], fds[client]);

				libwebsocket_close_and_free_session(
								   wsi[client]);
				goto nuke_this;
			}
			
			/* any incoming data ready? */

			if (!(fds[client].revents & POLLIN))
				continue;

#ifdef LWS_OPENSSL_SUPPORT
			if (use_ssl)
				n = SSL_read(wsi[client]->ssl, buf, sizeof buf);
			else
#endif
				n = recv(fds[client].fd, buf, sizeof(buf), 0);

			if (n < 0) {
				fprintf(stderr, "Socket read returned %d\n", n);
				continue;
			}
			if (!n) {
//				fprintf(stderr, "POLLIN with 0 len waiting\n");
				libwebsocket_close_and_free_session(
								   wsi[client]);
				goto nuke_this;
			}
			
			/* service incoming data */

			if (libwebsocket_read(wsi[client], buf, n) >= 0)
				continue;
			
			/*
			 * it closed and nuked wsi[client], so remove the
			 * socket handle and wsi from our service list
			 */
nuke_this:

			debug("nuking wsi %p, fsd_count = %d\n",
						   wsi[client], fds_count - 1);

			fds_count--;
			for (n = client; n < fds_count; n++) {
				fds[n] = fds[n + 1];
				wsi[n] = wsi[n + 1];
			}
			break;
		}

poll_out:		
		for (client = 1; client < fds_count; client++) {

			if (wsi[client]->state != WSI_STATE_ESTABLISHED)
				continue;

			wsi[client]->protocol->callback(wsi[client],
							LWS_CALLBACK_SEND, 
							wsi[client]->user_space,
								       NULL, 0);
		}
		
		continue;		
	}
	
fatal:
	/* listening socket */
	close(fds[0].fd);
	for (client = 1; client < fds_count; client++)
		libwebsocket_close_and_free_session(wsi[client]);

#ifdef LWS_OPENSSL_SUPPORT
	SSL_CTX_free(ssl_ctx);
#endif
	kill(0, SIGTERM);
	
	return 0;
}


