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

void
libwebsocket_close_and_free_session(struct libwebsocket *wsi)
{
	int n;

	if ((unsigned long)wsi < LWS_MAX_PROTOCOLS)
		return;

	n = wsi->state;

	wsi->state = WSI_STATE_DEAD_SOCKET;

	if (wsi->protocol->callback && n == WSI_STATE_ESTABLISHED)
		wsi->protocol->callback(wsi, LWS_CALLBACK_CLOSED,
						      wsi->user_space, NULL, 0);

	for (n = 0; n < WSI_TOKEN_COUNT; n++)
		if (wsi->utf8_token[n].token)
			free(wsi->utf8_token[n].token);

/*	fprintf(stderr, "closing fd=%d\n", wsi->sock); */

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

static int
libwebsocket_poll_connections(struct libwebsocket_context *this)
{
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_BROADCAST_PAYLOAD +
						  LWS_SEND_BUFFER_POST_PADDING];
	int client = this->count_protocols + 1;
	struct libwebsocket *wsi;
	int n;
	size_t len;

	/* check for activity on client sockets */

	for (; client < this->fds_count; client++) {

		/* handle session socket closed */

		if (this->fds[client].revents & (POLLERR | POLLHUP)) {

			debug("Session Socket %d %p (fd=%d) dead\n",
				  client, this->wsi[client], this->fds[client]);

			libwebsocket_close_and_free_session(this->wsi[client]);
			goto nuke_this;
		}

		/* any incoming data ready? */

		if (!(this->fds[client].revents & POLLIN))
			continue;

		/* broadcast? */

		if ((unsigned long)this->wsi[client] < LWS_MAX_PROTOCOLS) {

			/* get the issued broadcast payload from the socket */

			len = read(this->fds[client].fd,
				   buf + LWS_SEND_BUFFER_PRE_PADDING,
				   MAX_BROADCAST_PAYLOAD);

			if (len < 0) {
				fprintf(stderr,
					   "Error reading broadcast payload\n");
				continue;
			}

			/* broadcast it to all guys with this protocol index */

			for (n = this->count_protocols + 1;
						     n < this->fds_count; n++) {

				wsi = this->wsi[n];

				if ((unsigned long)wsi < LWS_MAX_PROTOCOLS)
					continue;

				/*
				 * never broadcast to non-established
				 * connection
				 */

				if (wsi->state != WSI_STATE_ESTABLISHED)
					continue;

				/* only to clients connected to us */
				
				if (wsi->client_mode)
					continue;

				/*
				 * only broadcast to connections using
				 * the requested protocol
				 */

				if (wsi->protocol->protocol_index !=
					  (int)(unsigned long)this->wsi[client])
					continue;

				/* broadcast it to this connection */

				wsi->protocol->callback(wsi,
					LWS_CALLBACK_BROADCAST,
					wsi->user_space,
					buf + LWS_SEND_BUFFER_PRE_PADDING, len);
			}

			continue;
		}

#ifdef LWS_OPENSSL_SUPPORT
		if (this->use_ssl)
			n = SSL_read(this->wsi[client]->ssl, buf, sizeof buf);
		else
#endif
			n = recv(this->fds[client].fd, buf, sizeof buf, 0);

		if (n < 0) {
			fprintf(stderr, "Socket read returned %d\n", n);
			continue;
		}
		if (!n) {
			libwebsocket_close_and_free_session(this->wsi[client]);
			goto nuke_this;
		}

		/* service incoming data */

		if (libwebsocket_read(this->wsi[client], buf, n) >= 0)
			continue;

		/*
		 * it closed and nuked wsi[client], so remove the
		 * socket handle and wsi from our service list
		 */
nuke_this:

		debug("nuking wsi %p, fsd_count = %d\n",
					this->wsi[client], this->fds_count - 1);

		this->fds_count--;
		for (n = client; n < this->fds_count; n++) {
			this->fds[n] = this->fds[n + 1];
			this->wsi[n] = this->wsi[n + 1];
		}
		break;
	}

	return 0;
}


int
libwebsocket_service(struct libwebsocket_context *this, int timeout_ms)
{
	int n;
	int client;
	unsigned int clilen;
	struct sockaddr_in cli_addr;
	int fd;

	/* stay dead once we are dead */

	if (this == NULL)
		return 1;

	/* don't check listen socket if we are not listening */

	if (this->listen_port)
		n = poll(this->fds, this->fds_count, timeout_ms);
	else
		n = poll(&this->fds[1], this->fds_count - 1, timeout_ms);
	

	if (n < 0 || this->fds[0].revents & (POLLERR | POLLHUP)) {
		fprintf(stderr, "Listen Socket dead\n");
		goto fatal;
	}
	if (n == 0) /* poll timeout */
		return 0;

	/* handle accept on listening socket? */

	for (client = 0; client < this->count_protocols + 1; client++) {

		if (!this->fds[client].revents & POLLIN)
			continue;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		fd  = accept(this->fds[client].fd,
			     (struct sockaddr *)&cli_addr, &clilen);
		if (fd < 0) {
			fprintf(stderr, "ERROR on accept");
			continue;
		}

		if (this->fds_count >= MAX_CLIENTS) {
			fprintf(stderr, "too busy");
			close(fd);
			continue;
		}

		if (client) {
			/*
			 * accepting a connection to broadcast socket
			 * set wsi to be protocol index not pointer
			 */

			this->wsi[this->fds_count] =
			      (struct libwebsocket *)(long)(client - 1);

			goto fill_in_fds;
		}

		/* accepting connection to main listener */

		this->wsi[this->fds_count] =
				    malloc(sizeof(struct libwebsocket));
		if (!this->wsi[this->fds_count]) {
			fprintf(stderr, "Out of memory for new connection\n");
			continue;
		}

#ifdef LWS_OPENSSL_SUPPORT
		if (this->use_ssl) {

			this->wsi[this->fds_count]->ssl = SSL_new(ssl_ctx);
			if (this->wsi[this->fds_count]->ssl == NULL) {
				fprintf(stderr, "SSL_new failed: %s\n",
				    ERR_error_string(SSL_get_error(
				    this->wsi[this->fds_count]->ssl, 0),
								 NULL));
				free(this->wsi[this->fds_count]);
				continue;
			}

			SSL_set_fd(this->wsi[this->fds_count]->ssl, fd);

			n = SSL_accept(this->wsi[this->fds_count]->ssl);
			if (n != 1) {
				/*
				 * browsers seem to probe with various
				 * ssl params which fail then retry
				 * and succeed
				 */
				debug("SSL_accept failed skt %u: %s\n",
				      fd,
				      ERR_error_string(SSL_get_error(
				      this->wsi[this->fds_count]->ssl,
							     n), NULL));
				SSL_free(
				       this->wsi[this->fds_count]->ssl);
				free(this->wsi[this->fds_count]);
				continue;
			}
			debug("accepted new SSL conn  "
			      "port %u on fd=%d SSL ver %s\n",
				ntohs(cli_addr.sin_port), fd,
				  SSL_get_version(this->wsi[
						this->fds_count]->ssl));

		} else
#endif
			debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), fd);

		/* intialize the instance struct */

		this->wsi[this->fds_count]->sock = fd;
		this->wsi[this->fds_count]->state = WSI_STATE_HTTP;
		this->wsi[this->fds_count]->name_buffer_pos = 0;
		this->wsi[this->fds_count]->client_mode = 0;

		for (n = 0; n < WSI_TOKEN_COUNT; n++) {
			this->wsi[this->fds_count]->
					     utf8_token[n].token = NULL;
			this->wsi[this->fds_count]->
					    utf8_token[n].token_len = 0;
		}

		/*
		 * these can only be set once the protocol is known
		 * we set an unestablished connection's protocol pointer
		 * to the start of the supported list, so it can look
		 * for matching ones during the handshake
		 */
		this->wsi[this->fds_count]->protocol = this->protocols;
		this->wsi[this->fds_count]->user_space = NULL;

		/*
		 * Default protocol is 76 / 00
		 * After 76, there's a header specified to inform which
		 * draft the client wants, when that's seen we modify
		 * the individual connection's spec revision accordingly
		 */
		this->wsi[this->fds_count]->ietf_spec_revision = 0;

fill_in_fds:

		/*
		 * make sure NO events are seen yet on this new socket
		 * (otherwise we inherit old fds[client].revents from
		 * previous socket there and die mysteriously! )
		 */
		this->fds[this->fds_count].revents = 0;

		this->fds[this->fds_count].events = POLLIN;
		this->fds[this->fds_count++].fd = fd;

	}

	/* service anything incoming on websocket connection */

	libwebsocket_poll_connections(this);

	/* this round is done */

	return 0;

fatal:

	/* close listening skt and per-protocol broadcast sockets */
	for (client = 0; client < this->fds_count; client++)
		close(this->fds[0].fd);

#ifdef LWS_OPENSSL_SUPPORT
	SSL_CTX_free(ssl_ctx);
#endif
	kill(0, SIGTERM);

	if (this)
		free(this);

	this = NULL;

	/* inform caller we are dead */

	return 1;
}


/**
 * libwebsocket_create_context() - Create the websocket handler
 * @port:	Port to listen on... you can use 0 to suppress listening on
 * 		any port, that's what you want if you are not running a
 * 		websocket server at all but just using it as a client
 * @protocols:	Array of structures listing supported protocols and a protocol-
 *		specific callback for each one.  The list is ended with an
 *		entry that has a NULL callback pointer.
 *	        It's not const because we write the owning_server member
 * @ssl_cert_filepath:	If libwebsockets was compiled to use ssl, and you want
 *			to listen using SSL, set to the filepath to fetch the
 *			server cert from, otherwise NULL for unencrypted
 * @ssl_private_key_filepath: filepath to private key if wanting SSL mode,
 *			else ignored
 * @gid:	group id to change to after setting listen socket, or -1.
 * @uid:	user id to change to after setting listen socket, or -1.
 *
 *	This function creates the listening socket and takes care
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

struct libwebsocket_context *
libwebsocket_create_context(int port,
			       struct libwebsocket_protocols *protocols,
			       const char *ssl_cert_filepath,
			       const char *ssl_private_key_filepath,
			       int gid, int uid)
{
	int n;
	int sockfd = 0;
	int fd;
	struct sockaddr_in serv_addr, cli_addr;
	int opt = 1;
	struct libwebsocket_context *this = NULL;
	unsigned int slen;

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
		return NULL;
	}
	fprintf(stderr, " Compiled without SSL support, serving unencrypted\n");
#endif

#ifdef LWS_OPENSSL_SUPPORT
	if (use_ssl) {
		SSL_library_init();

		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

		/*
		 * Firefox insists on SSLv23 not SSLv3
		 * Konq disables SSLv2 by default now, SSLv23 works
		 */

		method = (SSL_METHOD *)SSLv23_server_method();
		if (!method) {
			fprintf(stderr, "problem creating ssl method: %s\n",
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		ssl_ctx = SSL_CTX_new(method);	/* create context */
		if (!ssl_ctx) {
			printf("problem creating ssl context: %s\n",
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* set the local certificate from CertFile */
		n = SSL_CTX_use_certificate_file(ssl_ctx,
					ssl_cert_filepath, SSL_FILETYPE_PEM);
		if (n != 1) {
			fprintf(stderr, "problem getting cert '%s': %s\n",
				ssl_cert_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx,
						ssl_private_key_filepath,
						       SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "ssl problem getting key '%s': %s\n",
						ssl_private_key_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* verify private key */
		if (!SSL_CTX_check_private_key(ssl_ctx)) {
			fprintf(stderr, "Private SSL key doesn't match cert\n");
			return NULL;
		}

		/* SSL is happy and has a cert it's content with */
	}
#endif

	/* selftest */

	if (lws_b64_selftest())
		return NULL;


	this = malloc(sizeof(struct libwebsocket_context));

	this->protocols = protocols;
	this->listen_port = port;

	/* set up our external listening socket we serve on */

	if (port) {

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			fprintf(stderr, "ERROR opening socket");
			return NULL;
		}

		/* allow us to restart even if old sockets in TIME_WAIT */
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = INADDR_ANY;
		serv_addr.sin_port = htons(port);

		n = bind(sockfd, (struct sockaddr *) &serv_addr,
							     sizeof(serv_addr));
		if (n < 0) {
			fprintf(stderr, "ERROR on binding to port %d (%d %d)\n",
								port, n, errno);
			return NULL;
		}
	}

	/* drop any root privs for this process */

	if (gid != -1)
		if (setgid(gid))
			fprintf(stderr, "setgid: %s\n", strerror(errno));
	if (uid != -1)
		if (setuid(uid))
			fprintf(stderr, "setuid: %s\n", strerror(errno));

	/*
	 * prepare the poll() fd array... it's like this
	 *
	 * [0] = external listening socket
	 * [1 .. this->count_protocols] = per-protocol broadcast sockets
	 * [this->count_protocols + 1 ... this->fds_count-1] = connection skts
	 */

	this->fds_count = 1;
	this->fds[0].fd = sockfd;
	this->fds[0].events = POLLIN;
	this->count_protocols = 0;
#ifdef LWS_OPENSSL_SUPPORT
	this->use_ssl = use_ssl;
#endif

	if (port) {
		listen(sockfd, 5);
		fprintf(stderr, " Listening on port %d\n", port);
	}

	/* set up our internal broadcast trigger sockets per-protocol */

	for (; protocols[this->count_protocols].callback;
						      this->count_protocols++) {
		protocols[this->count_protocols].owning_server = this;
		protocols[this->count_protocols].protocol_index =
							  this->count_protocols;

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			fprintf(stderr, "ERROR opening socket");
			return NULL;
		}

		/* allow us to restart even if old sockets in TIME_WAIT */
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		serv_addr.sin_port = 0; /* pick the port for us */

		n = bind(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
		if (n < 0) {
			fprintf(stderr, "ERROR on binding to port %d (%d %d)\n",
								port, n, errno);
			return NULL;
		}

		slen = sizeof cli_addr;
		n = getsockname(fd, (struct sockaddr *)&cli_addr, &slen);
		if (n < 0) {
			fprintf(stderr, "getsockname failed\n");
			return NULL;
		}
		protocols[this->count_protocols].broadcast_socket_port =
						       ntohs(cli_addr.sin_port);
		listen(fd, 5);

		debug("  Protocol %s broadcast socket %d\n",
				protocols[this->count_protocols].name,
						      ntohs(cli_addr.sin_port));

		this->fds[this->fds_count].fd = fd;
		this->fds[this->fds_count].events = POLLIN;
		/* wsi only exists for connections, not broadcast listener */
		this->wsi[this->fds_count] = NULL;
		this->fds_count++;
	}

	return this;
}


#ifndef LWS_NO_FORK

/**
 * libwebsockets_fork_service_loop() - Optional helper function forks off
 *				  a process for the websocket server loop.
 * 				You don't have to use this but if not, you
 * 				have to make sure you are calling
 * 				libwebsocket_service periodically to service
 * 				the websocket traffic
 * @this:	server context returned by creation function
 */

int
libwebsockets_fork_service_loop(struct libwebsocket_context *this)
{
	int client;
	int fd;
	struct sockaddr_in cli_addr;
	int n;

	n = fork();
	if (n < 0)
		return n;

	if (!n) {

		/* main process context */

		for (client = 1; client < this->count_protocols + 1; client++) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
			if (fd < 0) {
				fprintf(stderr, "Unable to create socket\n");
				return -1;
			}
			cli_addr.sin_family = AF_INET;
			cli_addr.sin_port = htons(
			     this->protocols[client - 1].broadcast_socket_port);
			cli_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
			n = connect(fd, (struct sockaddr *)&cli_addr,
							       sizeof cli_addr);
			if (n < 0) {
				fprintf(stderr, "Unable to connect to "
						"broadcast socket %d, %s\n",
						client, strerror(errno));
				return -1;
			}

			this->protocols[client - 1].broadcast_socket_user_fd =
									     fd;
		}


		return 0;
	}

	/* we want a SIGHUP when our parent goes down */
	prctl(PR_SET_PDEATHSIG, SIGHUP);

	/* in this forked process, sit and service websocket connections */

	while (1)
		if (libwebsocket_service(this, 1000))
			return -1;

	return 0;
}

#endif

/**
 * libwebsockets_get_protocol() - Returns a protocol pointer from a websocket
 *				  connection.
 * @wsi:	pointer to struct websocket you want to know the protocol of
 *
 *
 *	This is useful to get the protocol to broadcast back to from inside
 * the callback.
 */

const struct libwebsocket_protocols *
libwebsockets_get_protocol(struct libwebsocket *wsi)
{
	return wsi->protocol;
}

/**
 * libwebsockets_broadcast() - Sends a buffer to the callback for all active
 *				  connections of the given protocol.
 * @protocol:	pointer to the protocol you will broadcast to all members of
 * @buf:  buffer containing the data to be broadcase.  NOTE: this has to be
 *		allocated with LWS_SEND_BUFFER_PRE_PADDING valid bytes before
 *		the pointer and LWS_SEND_BUFFER_POST_PADDING afterwards in the
 *		case you are calling this function from callback context.
 * @len:	length of payload data in buf, starting from buf.
 *
 *	This function allows bulk sending of a packet to every connection using
 * the given protocol.  It does not send the data directly; instead it calls
 * the callback with a reason type of LWS_CALLBACK_BROADCAST.  If the callback
 * wants to actually send the data for that connection, the callback itself
 * should call libwebsocket_write().
 *
 * libwebsockets_broadcast() can be called from another fork context without
 * having to take any care about data visibility between the processes, it'll
 * "just work".
 */


int
libwebsockets_broadcast(const struct libwebsocket_protocols *protocol,
						 unsigned char *buf, size_t len)
{
	struct libwebsocket_context *this = protocol->owning_server;
	int n;

	if (!protocol->broadcast_socket_user_fd) {
		/*
		 * We are either running unforked / flat, or we are being
		 * called from poll thread context
		 * eg, from a callback.  In that case don't use sockets for
		 * broadcast IPC (since we can't open a socket connection to
		 * a socket listening on our own thread) but directly do the
		 * send action.
		 *
		 * Locking is not needed because we are by definition being
		 * called in the poll thread context and are serialized.
		 */

		for (n = this->count_protocols + 1; n < this->fds_count; n++) {

			if ((unsigned long)this->wsi[n] < LWS_MAX_PROTOCOLS)
				continue;

			/* never broadcast to non-established connection */
			if (this->wsi[n]->state != WSI_STATE_ESTABLISHED)
				continue;

			/* only broadcast to guys using requested protocol */
			if (this->wsi[n]->protocol != protocol)
				continue;

			this->wsi[n]->protocol->callback(this->wsi[n],
					 LWS_CALLBACK_BROADCAST,
					 this->wsi[n]->user_space,
					 buf, len);
		}

		return 0;
	}

	/*
	 * We're being called from a different process context than the server
	 * loop.  Instead of broadcasting directly, we send our
	 * payload on a socket to do the IPC; the server process will serialize
	 * the broadcast action in its main poll() loop.
	 *
	 * There's one broadcast socket listening for each protocol supported
	 * set up when the websocket server initializes
	 */

	n = send(protocol->broadcast_socket_user_fd, buf, len, 0);

	return n;
}
