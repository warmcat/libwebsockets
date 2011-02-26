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
#include <ifaddrs.h>

/*
 * In-place str to lower case
 */

static void
strtolower(char *s)
{
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

/* file descriptor hash management */

struct libwebsocket *
wsi_from_fd(struct libwebsocket_context *this, int fd)
{
	int h = LWS_FD_HASH(fd);
	int n = 0;

	for (n = 0; n < this->fd_hashtable[h].length; n++)
		if (this->fd_hashtable[h].wsi[n]->sock == fd)
			return this->fd_hashtable[h].wsi[n];

	return NULL;
}

int
insert_wsi(struct libwebsocket_context *this, struct libwebsocket *wsi)
{
	int h = LWS_FD_HASH(wsi->sock);

	if (this->fd_hashtable[h].length == MAX_CLIENTS - 1) {
		fprintf(stderr, "hash table overflow\n");
		return 1;
	}

	this->fd_hashtable[h].wsi[this->fd_hashtable[h].length++] = wsi;

	return 0;
}

int
delete_from_fd(struct libwebsocket_context *this, int fd)
{
	int h = LWS_FD_HASH(fd);
	int n = 0;

	for (n = 0; n < this->fd_hashtable[h].length; n++)
		if (this->fd_hashtable[h].wsi[n]->sock == fd) {
			while (n < this->fd_hashtable[h].length) {
				this->fd_hashtable[h].wsi[n] =
					       this->fd_hashtable[h].wsi[n + 1];
				n++;
			}
			this->fd_hashtable[h].length--;

			return 0;
		}

	fprintf(stderr, "Failed to find fd %d requested for "
						   "delete in hashtable\n", fd);
	return 1;
}

#ifdef LWS_OPENSSL_SUPPORT
static void
libwebsockets_decode_ssl_error(void)
{
	char buf[256];
	u_long err;

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		fprintf(stderr, "*** %s\n", buf);
	}
}
#endif


static int
interface_to_sa(const char* ifname, struct sockaddr_in *addr, size_t addrlen)
{
	int rc = -1;
	struct ifaddrs *ifr;
	struct ifaddrs *ifc;
	struct sockaddr_in *sin;

	getifaddrs(&ifr);
	for (ifc = ifr; ifc != NULL; ifc = ifc->ifa_next) {
		if (strcmp(ifc->ifa_name, ifname))
			continue;
		if (ifc->ifa_addr == NULL)
			continue;
		sin = (struct sockaddr_in *)ifc->ifa_addr;
		if (sin->sin_family != AF_INET)
			continue;
		memcpy(addr, sin, addrlen);
		rc = 0; 
	}

	freeifaddrs(ifr);

	return rc;
}

void
libwebsocket_close_and_free_session(struct libwebsocket_context *this,
			 struct libwebsocket *wsi, enum lws_close_status reason)
{
	int n;
	int old_state;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 2 +
						  LWS_SEND_BUFFER_POST_PADDING];

	if (!wsi)
		return;

	old_state = wsi->state;

	if (old_state == WSI_STATE_DEAD_SOCKET)
		return;

	/* remove this fd from wsi mapping hashtable */

	delete_from_fd(this, wsi->sock);

	/* delete it from the internal poll list if still present */

	for (n = 0; n < this->fds_count; n++) {
		if (this->fds[n].fd != wsi->sock)
			continue;
		while (n < this->fds_count - 1) {
			this->fds[n] = this->fds[n + 1];
			n++;
		}
		this->fds_count--;
		/* we only have to deal with one */
		n = this->fds_count;
	}

	/* remove also from external POLL support via protocol 0 */

	this->protocols[0].callback(this, wsi,
		    LWS_CALLBACK_DEL_POLL_FD, (void *)(long)wsi->sock, NULL, 0);

	wsi->close_reason = reason;

	/*
	 * signal we are closing, libsocket_write will
	 * add any necessary version-specific stuff.  If the write fails,
	 * no worries we are closing anyway.  If we didn't initiate this
	 * close, then our state has been changed to
	 * WSI_STATE_RETURNED_CLOSE_ALREADY and we will skip this
	 */

	if (old_state == WSI_STATE_ESTABLISHED)
		libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], 0,
							       LWS_WRITE_CLOSE);

	wsi->state = WSI_STATE_DEAD_SOCKET;

	/* tell the user it's all over for this guy */

	if (wsi->protocol->callback && old_state == WSI_STATE_ESTABLISHED)
		wsi->protocol->callback(this, wsi, LWS_CALLBACK_CLOSED,
						      wsi->user_space, NULL, 0);

	/* free up his allocations */

	for (n = 0; n < WSI_TOKEN_COUNT; n++)
		if (wsi->utf8_token[n].token)
			free(wsi->utf8_token[n].token);

/*	fprintf(stderr, "closing fd=%d\n", wsi->sock); */

#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
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
 * libwebsockets_hangup_on_client() - Server calls to terminate client
 * 					connection
 * @this:	libwebsockets context
 * @fd:		Connection socket descriptor
 */

void
libwebsockets_hangup_on_client(struct libwebsocket_context *this, int fd)
{
	struct libwebsocket *wsi = wsi_from_fd(this, fd);

	if (wsi == NULL)
		return;

	libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
}


/**
 * libwebsockets_get_peer_addresses() - Get client address information
 * @fd:		Connection socket descriptor
 * @name:	Buffer to take client address name
 * @name_len:	Length of client address name buffer
 * @rip:	Buffer to take client address IP qotted quad
 * @rip_len:	Length of client address IP buffer
 *
 *	This function fills in @name and @rip with the name and IP of
 * 	the client connected with socket descriptor @fd.  Names may be
 * 	truncated if there is not enough room.  If either cannot be
 * 	determined, they will be returned as valid zero-length strings.
 */

void
libwebsockets_get_peer_addresses(int fd, char *name, int name_len,
					char *rip, int rip_len)
{
	unsigned int len;
	struct sockaddr_in sin;
	struct hostent *host;
	struct hostent *host1;
	char ip[128];
	char *p;
	int n;

	rip[0] = '\0';
	name[0] = '\0';

	len = sizeof sin;
	if (getpeername(fd, (struct sockaddr *) &sin, &len) < 0) {
		perror("getpeername");
		return;
	}
		
	host = gethostbyaddr((char *) &sin.sin_addr, sizeof sin.sin_addr,
								       AF_INET);
	if (host == NULL) {
		perror("gethostbyaddr");
		return;
	}

	strncpy(name, host->h_name, name_len);
	name[name_len - 1] = '\0';

	host1 = gethostbyname(host->h_name);
	if (host1 == NULL)
		return;
	p = (char *)host1;
	n = 0;
	while (p != NULL) {
		p = host1->h_addr_list[n++];
		if (p == NULL)
			continue;
		if (host1->h_addrtype != AF_INET)
			continue;

		sprintf(ip, "%d.%d.%d.%d",
				p[0], p[1], p[2], p[3]);
		p = NULL;
		strncpy(rip, ip, rip_len);
		rip[rip_len - 1] = '\0';
	}
}

/**
 * libwebsocket_service_fd() - Service polled socket with something waiting
 * @this:	Websocket context
 * @pollfd:	The pollfd entry describing the socket fd and which events
 * 		happened.
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */

int
libwebsocket_service_fd(struct libwebsocket_context *this,
							  struct pollfd *pollfd)
{
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_BROADCAST_PAYLOAD +
						  LWS_SEND_BUFFER_POST_PADDING];
	struct libwebsocket *wsi;
	struct libwebsocket *new_wsi;
	int n;
	int m;
	size_t len;
	int accept_fd;
	unsigned int clilen;
	struct sockaddr_in cli_addr;
	struct timeval tv;
	static const char magic_websocket_guid[] =
					 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	static const char magic_websocket_04_masking_guid[] =
					 "61AC5F19-FBBA-4540-B96F-6561F1AB40A8";
	char hash[20];
	char pkt[1024];
	char *p = &pkt[0];
	const char *pc;
	int okay = 0;
#ifdef LWS_OPENSSL_SUPPORT
	char ssl_err_buf[512];
#endif
	/*
	 * you can call us with pollfd = NULL to just allow the once-per-second
	 * global timeout checks; if less than a second since the last check
	 * it returns immediately then.
	 */

	gettimeofday(&tv, NULL);

	if (this->last_timeout_check_s != tv.tv_sec) {
		this->last_timeout_check_s = tv.tv_sec;

		/* global timeout check once per second */

		for (n = 0; n < this->fds_count; n++) {
			wsi = wsi_from_fd(this, this->fds[n].fd);
			if (!wsi->pending_timeout)
				continue;

			/*
			 * if we went beyond the allowed time, kill the
			 * connection
			 */

			if (tv.tv_sec > wsi->pending_timeout_limit)
				libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
		}
	}

	/* just here for timeout management? */

	if (pollfd == NULL)
		return 0;

	/* no, here to service a socket descriptor */

	wsi = wsi_from_fd(this, pollfd->fd);

	if (wsi == NULL)
		return 1;

	switch (wsi->mode) {
	case LWS_CONNMODE_SERVER_LISTENER:

		/* pollin means a client has connected to us then */

		if (!pollfd->revents & POLLIN)
			break;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		if (accept_fd < 0) {
			fprintf(stderr, "ERROR on accept");
			break;
		}

		if (this->fds_count >= MAX_CLIENTS) {
			fprintf(stderr, "too busy to accept new client\n");
			close(accept_fd);
			break;
		}

		/*
		 * look at who we connected to and give user code a chance
		 * to reject based on client IP.  There's no protocol selected
		 * yet so we issue this to protocols[0]
		 */

		if ((this->protocols[0].callback)(this, wsi,
				LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
					     (void*)(long)accept_fd, NULL, 0)) {
			fprintf(stderr, "Callback denied network connection\n");
			close(accept_fd);
			break;
		}

		/* accepting connection to main listener */

		new_wsi = malloc(sizeof(struct libwebsocket));
		if (new_wsi == NULL) {
			fprintf(stderr, "Out of memory for new connection\n");
			break;
		}

		memset(new_wsi, 0, sizeof (struct libwebsocket));
		new_wsi->sock = accept_fd;
		new_wsi->pending_timeout = NO_PENDING_TIMEOUT;

#ifdef LWS_OPENSSL_SUPPORT
		new_wsi->ssl = NULL;

		if (this->use_ssl) {

			new_wsi->ssl = SSL_new(this->ssl_ctx);
			if (new_wsi->ssl == NULL) {
				fprintf(stderr, "SSL_new failed: %s\n",
				    ERR_error_string(SSL_get_error(
				    new_wsi->ssl, 0), NULL));
				    libwebsockets_decode_ssl_error();
				free(new_wsi);
				break;
			}

			SSL_set_fd(new_wsi->ssl, accept_fd);

			n = SSL_accept(new_wsi->ssl);
			if (n != 1) {
				/*
				 * browsers seem to probe with various
				 * ssl params which fail then retry
				 * and succeed
				 */
				debug("SSL_accept failed skt %u: %s\n",
				      pollfd->fd,
				      ERR_error_string(SSL_get_error(
				      new_wsi->ssl, n), NULL));
				SSL_free(
				       new_wsi->ssl);
				free(new_wsi);
				break;
			}
			
			debug("accepted new SSL conn  "
			      "port %u on fd=%d SSL ver %s\n",
				ntohs(cli_addr.sin_port), accept_fd,
				  SSL_get_version(new_wsi->ssl));

		} else
#endif
			debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), accept_fd);

		/* intialize the instance struct */

		new_wsi->state = WSI_STATE_HTTP;
		new_wsi->name_buffer_pos = 0;
		new_wsi->mode = LWS_CONNMODE_WS_SERVING;

		for (n = 0; n < WSI_TOKEN_COUNT; n++) {
			new_wsi->utf8_token[n].token = NULL;
			new_wsi->utf8_token[n].token_len = 0;
		}

		/*
		 * these can only be set once the protocol is known
		 * we set an unestablished connection's protocol pointer
		 * to the start of the supported list, so it can look
		 * for matching ones during the handshake
		 */
		new_wsi->protocol = this->protocols;
		new_wsi->user_space = NULL;

		/*
		 * Default protocol is 76 / 00
		 * After 76, there's a header specified to inform which
		 * draft the client wants, when that's seen we modify
		 * the individual connection's spec revision accordingly
		 */
		new_wsi->ietf_spec_revision = 0;

		insert_wsi(this, new_wsi);

		/*
		 * make sure NO events are seen yet on this new socket
		 * (otherwise we inherit old fds[client].revents from
		 * previous socket there and die mysteriously! )
		 */
		this->fds[this->fds_count].revents = 0;

		this->fds[this->fds_count].events = POLLIN;
		this->fds[this->fds_count++].fd = accept_fd;

		/* external POLL support via protocol 0 */
		this->protocols[0].callback(this, new_wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)accept_fd, NULL, POLLIN);

		break;

	case LWS_CONNMODE_BROADCAST_PROXY_LISTENER:

		/* as we are listening, POLLIN means accept() is needed */
	
		if (!pollfd->revents & POLLIN)
			break;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		if (accept_fd < 0) {
			fprintf(stderr, "ERROR on accept");
			break;
		}

		if (this->fds_count >= MAX_CLIENTS) {
			fprintf(stderr, "too busy to accept new broadcast "
							      "proxy client\n");
			close(accept_fd);
			break;
		}

		/* create a dummy wsi for the connection and add it */

		new_wsi = malloc(sizeof(struct libwebsocket));
		memset(new_wsi, 0, sizeof (struct libwebsocket));
		new_wsi->sock = accept_fd;
		new_wsi->mode = LWS_CONNMODE_BROADCAST_PROXY;
		new_wsi->state = WSI_STATE_ESTABLISHED;
		/* note which protocol we are proxying */
		new_wsi->protocol_index_for_broadcast_proxy =
					wsi->protocol_index_for_broadcast_proxy;
		insert_wsi(this, new_wsi);

		/* add connected socket to internal poll array */

		this->fds[this->fds_count].revents = 0;
		this->fds[this->fds_count].events = POLLIN;
		this->fds[this->fds_count++].fd = accept_fd;

		/* external POLL support via protocol 0 */
		this->protocols[0].callback(this, new_wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)accept_fd, NULL, POLLIN);

		break;

	case LWS_CONNMODE_BROADCAST_PROXY:

		/* handle session socket closed */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			debug("Session Socket %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			libwebsocket_close_and_free_session(this, wsi,
						       LWS_CLOSE_STATUS_NORMAL);
			return 1;
		}

		/* the guy requested a callback when it was OK to write */

		if (pollfd->revents & POLLOUT) {

			/* one shot */

			pollfd->events &= ~POLLOUT;

			/* external POLL support via protocol 0 */
			this->protocols[0].callback(this, wsi,
				LWS_CALLBACK_CLEAR_MODE_POLL_FD,
				(void *)(long)wsi->sock, NULL, POLLOUT);

			wsi->protocol->callback(this, wsi,
				LWS_CALLBACK_CLIENT_WRITEABLE,
				wsi->user_space,
				NULL, 0);
		}

		/* any incoming data ready? */

		if (!(pollfd->revents & POLLIN))
			break;

		/* get the issued broadcast payload from the socket */

		len = read(pollfd->fd, buf + LWS_SEND_BUFFER_PRE_PADDING,
							 MAX_BROADCAST_PAYLOAD);
		if (len < 0) {
			fprintf(stderr, "Error reading broadcast payload\n");
			break;
		}

		/* broadcast it to all guys with this protocol index */

		for (n = 0; n < FD_HASHTABLE_MODULUS; n++) {

			for (m = 0; m < this->fd_hashtable[n].length; m++) {

				new_wsi = this->fd_hashtable[n].wsi[m];

				/* only to clients we are serving to */

				if (new_wsi->mode != LWS_CONNMODE_WS_SERVING)
					continue;

				/*
				 * never broadcast to non-established
				 * connection
				 */

				if (new_wsi->state != WSI_STATE_ESTABLISHED)
					continue;

				/*
				 * only broadcast to connections using
				 * the requested protocol
				 */

				if (new_wsi->protocol->protocol_index !=
					wsi->protocol_index_for_broadcast_proxy)
					continue;

				/* broadcast it to this connection */

				new_wsi->protocol->callback(this, new_wsi,
					LWS_CALLBACK_BROADCAST,
					new_wsi->user_space,
					buf + LWS_SEND_BUFFER_PRE_PADDING, len);
			}
		}
		break;

	case LWS_CONNMODE_WS_CLIENT_WAITING_PROXY_REPLY:

		/* handle proxy hung up on us */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			fprintf(stderr, "Proxy connection %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		n = recv(wsi->sock, pkt, sizeof pkt, 0);
		if (n < 0) {
			libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			fprintf(stderr, "ERROR reading from proxy socket\n");
			return 1;
		}

		pkt[13] = '\0';
		if (strcmp(pkt, "HTTP/1.0 200 ") != 0) {
			libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			fprintf(stderr, "ERROR from proxy: %s\n", pkt);
			return 1;
		}

		/* clear his proxy connection timeout */

		libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* fallthru */

	case LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE:

	#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->use_ssl) {

			wsi->ssl = SSL_new(this->ssl_client_ctx);
			wsi->client_bio = BIO_new_socket(wsi->sock, BIO_NOCLOSE);
			SSL_set_bio(wsi->ssl, wsi->client_bio, wsi->client_bio);

			SSL_set_ex_data(wsi->ssl,
			      this->openssl_websocket_private_data_index, this);

			if (SSL_connect(wsi->ssl) <= 0) {
				fprintf(stderr, "SSL connect error %s\n",
					ERR_error_string(ERR_get_error(),
								  ssl_err_buf));
				libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
				return 1;
			}

			n = SSL_get_verify_result(wsi->ssl);
			if (n != X509_V_OK) && (
				n != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
							   wsi->use_ssl != 2)) {

				fprintf(stderr, "server's cert didn't "
							   "look good %d\n", n);
				libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
				return 1;
			}
		} else {
			wsi->ssl = NULL;
	#endif


	#ifdef LWS_OPENSSL_SUPPORT
		}
	#endif

		/*
		 * create the random key
		 */

		n = read(this->fd_random, hash, 16);
		if (n != 16) {
			fprintf(stderr, "Unable to read from random dev %s\n",
							SYSTEM_RANDOM_FILEPATH);
			free(wsi->c_path);
			free(wsi->c_host);
			if (wsi->c_origin)
				free(wsi->c_origin);
			if (wsi->c_protocol)
				free(wsi->c_protocol);
			libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		lws_b64_encode_string(hash, 16, wsi->key_b64,
							   sizeof wsi->key_b64);

		/*
		 * 04 example client handshake
		 *
		 * GET /chat HTTP/1.1
		 * Host: server.example.com
		 * Upgrade: websocket
		 * Connection: Upgrade
		 * Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
		 * Sec-WebSocket-Origin: http://example.com
		 * Sec-WebSocket-Protocol: chat, superchat
		 * Sec-WebSocket-Version: 4
		 */

		p += sprintf(p, "GET %s HTTP/1.1\x0d\x0a", wsi->c_path);
		p += sprintf(p, "Host: %s\x0d\x0a", wsi->c_host);
		p += sprintf(p, "Upgrade: websocket\x0d\x0a");
		p += sprintf(p, "Connection: Upgrade\x0d\x0a"
					"Sec-WebSocket-Key: ");
		strcpy(p, wsi->key_b64);
		p += strlen(wsi->key_b64);
		p += sprintf(p, "\x0d\x0a");
		if (wsi->c_origin)
			p += sprintf(p, "Sec-WebSocket-Origin: %s\x0d\x0a",
								 wsi->c_origin);
		if (wsi->c_protocol)
			p += sprintf(p, "Sec-WebSocket-Protocol: %s\x0d\x0a",
							       wsi->c_protocol);
		p += sprintf(p, "Sec-WebSocket-Version: %d\x0d\x0a\x0d\x0a",
						       wsi->ietf_spec_revision);

		/* done with these now */

		free(wsi->c_path);
		free(wsi->c_host);
		if (wsi->c_origin)
			free(wsi->c_origin);

		/* prepare the expected server accept response */

		strcpy((char *)buf, wsi->key_b64);
		strcpy((char *)&buf[strlen((char *)buf)], magic_websocket_guid);

		SHA1(buf, strlen((char *)buf), (unsigned char *)hash);

		lws_b64_encode_string(hash, 20,
				wsi->initial_handshake_hash_base64,
				     sizeof wsi->initial_handshake_hash_base64);

		/* send our request to the server */

	#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->use_ssl)
			n = SSL_write(wsi->ssl, pkt, p - pkt);
		else
	#endif
			n = send(wsi->sock, pkt, p - pkt, 0);

		if (n < 0) {
			fprintf(stderr, "ERROR writing to client socket\n");
			libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		wsi->parser_state = WSI_TOKEN_NAME_PART;
		wsi->mode = LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY;
		libwebsocket_set_timeout(wsi,
				PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE, 5);

		break;

	case LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY:

		/* handle server hung up on us */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			fprintf(stderr, "Server connection %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			goto bail3;
		}


		/* interpret the server response */

		/*
		 *  HTTP/1.1 101 Switching Protocols
		 *  Upgrade: websocket
		 *  Connection: Upgrade
		 *  Sec-WebSocket-Accept: me89jWimTRKTWwrS3aRrL53YZSo=
		 *  Sec-WebSocket-Nonce: AQIDBAUGBwgJCgsMDQ4PEC==
		 *  Sec-WebSocket-Protocol: chat
		 */

	#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->use_ssl)
			len = SSL_read(wsi->ssl, pkt, sizeof pkt);
		else
	#endif
			len = recv(wsi->sock, pkt, sizeof pkt, 0);

		if (len < 0) {
			fprintf(stderr,
				  "libwebsocket_client_handshake read error\n");
			goto bail3;
		}

		p = pkt;
		for (n = 0; n < len; n++)
			libwebsocket_parse(wsi, *p++);

		if (wsi->parser_state != WSI_PARSING_COMPLETE) {
			fprintf(stderr, "libwebsocket_client_handshake "
					"server response ailed parsing\n");
			goto bail3;
		}

		/*
		 * well, what the server sent looked reasonable for syntax.
		 * Now let's confirm it sent all the necessary headers
		 */

		 if (!wsi->utf8_token[WSI_TOKEN_HTTP].token_len ||
			!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
			!wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len ||
			!wsi->utf8_token[WSI_TOKEN_ACCEPT].token_len ||
			(!wsi->utf8_token[WSI_TOKEN_NONCE].token_len &&
					   wsi->ietf_spec_revision == 4) ||
			(!wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len &&
						     wsi->c_protocol != NULL)) {
			fprintf(stderr, "libwebsocket_client_handshake "
						"missing required header(s)\n");
			pkt[len] = '\0';
			fprintf(stderr, "%s", pkt);
			goto bail3;
		}

		/*
		 * Everything seems to be there, now take a closer look at what
		 * is in each header
		 */

		strtolower(wsi->utf8_token[WSI_TOKEN_HTTP].token);
		if (strcmp(wsi->utf8_token[WSI_TOKEN_HTTP].token,
						   "101 switching protocols")) {
			fprintf(stderr, "libwebsocket_client_handshake "
					"server sent bad HTTP response '%s'\n",
					 wsi->utf8_token[WSI_TOKEN_HTTP].token);
			goto bail3;
		}

		strtolower(wsi->utf8_token[WSI_TOKEN_UPGRADE].token);
		if (strcmp(wsi->utf8_token[WSI_TOKEN_UPGRADE].token,
								 "websocket")) {
			fprintf(stderr, "libwebsocket_client_handshake server "
					"sent bad Upgrade header '%s'\n",
				      wsi->utf8_token[WSI_TOKEN_UPGRADE].token);
			goto bail3;
		}

		strtolower(wsi->utf8_token[WSI_TOKEN_CONNECTION].token);
		if (strcmp(wsi->utf8_token[WSI_TOKEN_CONNECTION].token,
								   "upgrade")) {
			fprintf(stderr, "libwebsocket_client_handshake server "
					"sent bad Connection hdr '%s'\n",
				   wsi->utf8_token[WSI_TOKEN_CONNECTION].token);
			goto bail3;
		}


		pc = wsi->c_protocol;

		/*
		 * confirm the protocol the server wants to talk was in the list
		 * of protocols we offered
		 */

		if (!wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len) {

			/*
			 * no protocol name to work from,
			 * default to first protocol
			 */
			wsi->protocol = &this->protocols[0];

			free(wsi->c_protocol);

			goto check_accept;
		}

		while (*pc && !okay) {
			if ((!strncmp(pc,
				wsi->utf8_token[WSI_TOKEN_PROTOCOL].token,
			   wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len)) &&
		 (pc[wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len] == ',' ||
		   pc[wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len] == '\0')) {
				okay = 1;
				continue;
			}
			while (*pc && *pc != ',')
				pc++;
			while (*pc && *pc != ' ')
				pc++;
		}

		/* done with him now */

		if (wsi->c_protocol)
			free(wsi->c_protocol);


		if (!okay) {
			fprintf(stderr, "libwebsocket_client_handshake server "
						"sent bad protocol '%s'\n",
				     wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
			goto bail2;
		}

		/*
		 * identify the selected protocol struct and set it
		 */
		n = 0;
		wsi->protocol = NULL;
		while (this->protocols[n].callback) {
			if (strcmp(wsi->utf8_token[WSI_TOKEN_PROTOCOL].token,
					       this->protocols[n].name) == 0)
				wsi->protocol = &this->protocols[n];
			n++;
		}

		if (wsi->protocol == NULL) {
			fprintf(stderr, "libwebsocket_client_handshake server "
					"requested protocol '%s', which we "
					"said we supported but we don't!\n",
				     wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
			goto bail2;
		}

	check_accept:
		/*
		 * Confirm his accept token is the one we precomputed
		 */

		if (strcmp(wsi->utf8_token[WSI_TOKEN_ACCEPT].token,
					  wsi->initial_handshake_hash_base64)) {
			fprintf(stderr, "libwebsocket_client_handshake server "
				"sent bad ACCEPT '%s' vs computed '%s'\n",
				wsi->utf8_token[WSI_TOKEN_ACCEPT].token,
					    wsi->initial_handshake_hash_base64);
			goto bail2;
		}

		if (wsi->ietf_spec_revision == 4) {
			/*
			 * Calculate the 04 masking key to use when
			 * sending data to server
			 */

			strcpy((char *)buf, wsi->key_b64);
			p = (char *)buf + strlen(wsi->key_b64);
			strcpy(p, wsi->utf8_token[WSI_TOKEN_NONCE].token);
			p += wsi->utf8_token[WSI_TOKEN_NONCE].token_len;
			strcpy(p, magic_websocket_04_masking_guid);
			SHA1(buf, strlen((char *)buf), wsi->masking_key_04);
		}

		/* allocate the per-connection user memory (if any) */

		if (wsi->protocol->per_session_data_size) {
			wsi->user_space = malloc(
					  wsi->protocol->per_session_data_size);
			if (wsi->user_space  == NULL) {
				fprintf(stderr, "Out of memory for "
							   "conn user space\n");
				goto bail2;
			}
		} else
			wsi->user_space = NULL;

		/* clear his proxy connection timeout */

		libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* mark him as being alive */

		wsi->state = WSI_STATE_ESTABLISHED;
		wsi->mode = LWS_CONNMODE_WS_CLIENT;

		fprintf(stderr, "handshake OK for protocol %s\n",
							   wsi->protocol->name);

		/* call him back to inform him he is up */

		wsi->protocol->callback(this, wsi,
				 LWS_CALLBACK_CLIENT_ESTABLISHED,
				 wsi->user_space,
				 NULL, 0);

		break;

bail3:
		if (wsi->c_protocol)
			free(wsi->c_protocol);

bail2:
		libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
		return 1;
		

	case LWS_CONNMODE_WS_SERVING:
	case LWS_CONNMODE_WS_CLIENT:

		/* handle session socket closed */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			fprintf(stderr, "Session Socket %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		/* the guy requested a callback when it was OK to write */

		if (pollfd->revents & POLLOUT) {

			pollfd->events &= ~POLLOUT;

			/* external POLL support via protocol 0 */
			this->protocols[0].callback(this, wsi,
				LWS_CALLBACK_CLEAR_MODE_POLL_FD,
				(void *)(long)wsi->sock, NULL, POLLOUT);

			wsi->protocol->callback(this, wsi,
				LWS_CALLBACK_CLIENT_WRITEABLE,
				wsi->user_space,
				NULL, 0);
		}

		/* any incoming data ready? */

		if (!(pollfd->revents & POLLIN))
			break;

#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->ssl)
			n = SSL_read(wsi->ssl, buf, sizeof buf);
		else
#endif
			n = recv(pollfd->fd, buf, sizeof buf, 0);

		if (n < 0) {
			fprintf(stderr, "Socket read returned %d\n", n);
			break;
		}
		if (!n) {
			libwebsocket_close_and_free_session(this, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);
			return 1;
		}

		/* service incoming data */

		n = libwebsocket_read(this, wsi, buf, n);
		if (n >= 0)
			break;

		/* we closed wsi */

		return 1;
	}

	return 0;
}


/**
 * libwebsocket_context_destroy() - Destroy the websocket context
 * @this:	Websocket context
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */
void
libwebsocket_context_destroy(struct libwebsocket_context *this)
{
	int n;
	int m;
	struct libwebsocket *wsi;

	for (n = 0; n < FD_HASHTABLE_MODULUS; n++)
		for (m = 0; m < this->fd_hashtable[n].length; m++) {
			wsi = this->fd_hashtable[n].wsi[m];
			libwebsocket_close_and_free_session(this, wsi,
						    LWS_CLOSE_STATUS_GOINGAWAY);
		}

	close(this->fd_random);

#ifdef LWS_OPENSSL_SUPPORT
	if (this->ssl_ctx)
		SSL_CTX_free(this->ssl_ctx);
	if (this->ssl_client_ctx)
		SSL_CTX_free(this->ssl_client_ctx);
#endif

	free(this);
}

/**
 * libwebsocket_service() - Service any pending websocket activity
 * @this:	Websocket context
 * @timeout_ms:	Timeout for poll; 0 means return immediately if nothing needed
 *		service otherwise block and service immediately, returning
 *		after the timeout if nothing needed service.
 *
 *	This function deals with any pending websocket traffic, for three
 *	kinds of event.  It handles these events on both server and client
 *	types of connection the same.
 *
 *	1) Accept new connections to our context's server
 *
 *	2) Perform pending broadcast writes initiated from other forked
 *	   processes (effectively serializing asynchronous broadcasts)
 *
 *	3) Call the receive callback for incoming frame data received by
 *	    server or client connections.
 *
 *	You need to call this service function periodically to all the above
 *	functions to happen; if your application is single-threaded you can
 *	just call it in your main event loop.
 *
 *	Alternatively you can fork a new process that asynchronously handles
 *	calling this service in a loop.  In that case you are happy if this
 *	call blocks your thread until it needs to take care of something and
 *	would call it with a large nonzero timeout.  Your loop then takes no
 *	CPU while there is nothing happening.
 *
 *	If you are calling it in a single-threaded app, you don't want it to
 *	wait around blocking other things in your loop from happening, so you
 *	would call it with a timeout_ms of 0, so it returns immediately if
 *	nothing is pending, or as soon as it services whatever was pending.
 */


int
libwebsocket_service(struct libwebsocket_context *this, int timeout_ms)
{
	int n;

	/* stay dead once we are dead */

	if (this == NULL)
		return 1;

	/* wait for something to need service */

	n = poll(this->fds, this->fds_count, timeout_ms);
	if (n == 0) /* poll timeout */
		return 0;

	if (n < 0) {
		/*
		fprintf(stderr, "Listen Socket dead\n");
		*/
		return 1;
	}

	/* handle accept on listening socket? */

	for (n = 0; n < this->fds_count; n++)
		if (this->fds[n].revents)
			libwebsocket_service_fd(this, &this->fds[n]);

	return 0;
}

/**
 * libwebsocket_callback_on_writable() - Request a callback when this socket
 *					 becomes able to be written to without
 *					 blocking
 *
 * @this:	libwebsockets context
 * @wsi:	Websocket connection instance to get callback for
 */

int
libwebsocket_callback_on_writable(struct libwebsocket_context *this,
						       struct libwebsocket *wsi)
{
	int n;

	for (n = 0; n < this->fds_count; n++)
		if (this->fds[n].fd == wsi->sock) {
			this->fds[n].events |= POLLOUT;
			n = this->fds_count;
		}

	/* external POLL support via protocol 0 */
	this->protocols[0].callback(this, wsi,
		LWS_CALLBACK_SET_MODE_POLL_FD,
		(void *)(long)wsi->sock, NULL, POLLOUT);

	return 1;
}

/**
 * libwebsocket_callback_on_writable_all_protocol() - Request a callback for
 *			all connections using the given protocol when it
 *			becomes possible to write to each socket without
 *			blocking in turn.
 *
 * @protocol:	Protocol whose connections will get callbacks
 */

int
libwebsocket_callback_on_writable_all_protocol(
				  const struct libwebsocket_protocols *protocol)
{
	struct libwebsocket_context *this = protocol->owning_server;
	int n;
	int m;
	struct libwebsocket *wsi;

	for (n = 0; n < FD_HASHTABLE_MODULUS; n++) {

		for (m = 0; m < this->fd_hashtable[n].length; m++) {

			wsi = this->fd_hashtable[n].wsi[m];

			if (wsi->protocol == protocol)
				libwebsocket_callback_on_writable(this, wsi);
		}
	}

	return 0;
}

/**
 * libwebsocket_set_timeout() - marks the wsi as subject to a timeout
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 * @reason:	timeout reason
 * @secs:	how many seconds
 */

void
libwebsocket_set_timeout(struct libwebsocket *wsi,
					  enum pending_timeout reason, int secs)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	wsi->pending_timeout_limit = tv.tv_sec + secs;
	wsi->pending_timeout = reason;
}


/**
 * libwebsocket_get_socket_fd() - returns the socket file descriptor
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 */

int
libwebsocket_get_socket_fd(struct libwebsocket *wsi)
{
	return wsi->sock;
}

/**
 * libwebsocket_rx_flow_control() - Enable and disable socket servicing for
 *				receieved packets.
 *
 * If the output side of a server process becomes choked, this allows flow
 * control for the input side.
 *
 * @wsi:	Websocket connection instance to get callback for
 * @enable:	0 = disable read servicing for this connection, 1 = enable
 */

int
libwebsocket_rx_flow_control(struct libwebsocket *wsi, int enable)
{
	struct libwebsocket_context *this = wsi->protocol->owning_server;
	int n;

	for (n = 0; n < this->fds_count; n++)
		if (this->fds[n].fd == wsi->sock) {
			if (enable)
				this->fds[n].events |= POLLIN;
			else
				this->fds[n].events &= ~POLLIN;

			return 0;
		}

	if (enable)
		/* external POLL support via protocol 0 */
		this->protocols[0].callback(this, wsi,
			LWS_CALLBACK_SET_MODE_POLL_FD,
			(void *)(long)wsi->sock, NULL, POLLIN);
	else
		/* external POLL support via protocol 0 */
		this->protocols[0].callback(this, wsi,
			LWS_CALLBACK_CLEAR_MODE_POLL_FD,
			(void *)(long)wsi->sock, NULL, POLLIN);


	fprintf(stderr, "libwebsocket_callback_on_writable "
						     "unable to find socket\n");
	return 1;
}

/**
 * libwebsocket_canonical_hostname() - returns this host's hostname
 *
 * This is typically used by client code to fill in the host parameter
 * when making a client connection.  You can only call it after the context
 * has been created.
 *
 * @this:	Websocket context
 */


extern const char *
libwebsocket_canonical_hostname(struct libwebsocket_context *this)
{
	return (const char *)this->canonical_hostname;
}


static void sigpipe_handler(int x)
{
}

#ifdef LWS_OPENSSL_SUPPORT
static int
OpenSSL_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{

	SSL *ssl;
	int n;
//	struct libwebsocket_context *this;

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());

	/*
	 * !!! can't get this->openssl_websocket_private_data_index
	 * can't store as a static either
	 */
//	this = SSL_get_ex_data(ssl, this->openssl_websocket_private_data_index);
	
	n = this->protocols[0].callback(NULL, NULL,
		LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
						   x509_ctx, ssl, preverify_ok);

	/* convert return code from 0 = OK to 1 = OK */

	if (!n)
		n = 1;
	else
		n = 0;

	return n;
}
#endif


/**
 * libwebsocket_create_context() - Create the websocket handler
 * @port:	Port to listen on... you can use 0 to suppress listening on
 *		any port, that's what you want if you are not running a
 *		websocket server at all but just using it as a client
 * @interface:  NULL to bind the listen socket to all interfaces, or the
 *		interface name, eg, "eth2"
 * @protocols:	Array of structures listing supported protocols and a protocol-
 *		specific callback for each one.  The list is ended with an
 *		entry that has a NULL callback pointer.
 *		It's not const because we write the owning_server member
 * @ssl_cert_filepath:	If libwebsockets was compiled to use ssl, and you want
 *			to listen using SSL, set to the filepath to fetch the
 *			server cert from, otherwise NULL for unencrypted
 * @ssl_private_key_filepath: filepath to private key if wanting SSL mode,
 *			else ignored
 * @gid:	group id to change to after setting listen socket, or -1.
 * @uid:	user id to change to after setting listen socket, or -1.
 * @options:	0, or LWS_SERVER_OPTION_DEFEAT_CLIENT_MASK
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
libwebsocket_create_context(int port, const char *interface,
			       struct libwebsocket_protocols *protocols,
			       const char *ssl_cert_filepath,
			       const char *ssl_private_key_filepath,
			       int gid, int uid, unsigned int options)
{
	int n;
	int sockfd = 0;
	int fd;
	struct sockaddr_in serv_addr, cli_addr;
	int opt = 1;
	struct libwebsocket_context *this = NULL;
	unsigned int slen;
	char *p;
	char hostname[1024];
	struct hostent *he;
	struct libwebsocket *wsi;

#ifdef LWS_OPENSSL_SUPPORT
	SSL_METHOD *method;
	char ssl_err_buf[512];
#endif

	this = malloc(sizeof(struct libwebsocket_context));
	if (!this) {
		fprintf(stderr, "No memory for websocket context\n");
		return NULL;
	}
	this->protocols = protocols;
	this->listen_port = port;
	this->http_proxy_port = 0;
	this->http_proxy_address[0] = '\0';
	this->options = options;
	this->fds_count = 0;

	this->fd_random = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);
	if (this->fd_random < 0) {
		fprintf(stderr, "Unable to open random device %s %d\n",
				       SYSTEM_RANDOM_FILEPATH, this->fd_random);
		return NULL;
	}

	/* find canonical hostname */

	hostname[(sizeof hostname) - 1] = '\0';
	gethostname(hostname, (sizeof hostname) - 1);
	he = gethostbyname(hostname);
	if (he) {
		strncpy(this->canonical_hostname, he->h_name,
					   sizeof this->canonical_hostname - 1);
		this->canonical_hostname[sizeof this->canonical_hostname - 1] =
									   '\0';
	} else
		strncpy(this->canonical_hostname, hostname,
					   sizeof this->canonical_hostname - 1);

	/* split the proxy ads:port if given */

	p = getenv("http_proxy");
	if (p) {
		strncpy(this->http_proxy_address, p,
					   sizeof this->http_proxy_address - 1);
		this->http_proxy_address[
				    sizeof this->http_proxy_address - 1] = '\0';

		p = strchr(this->http_proxy_address, ':');
		if (p == NULL) {
			fprintf(stderr, "http_proxy needs to be ads:port\n");
			return NULL;
		}
		*p = '\0';
		this->http_proxy_port = atoi(p + 1);

		fprintf(stderr, "Using proxy %s:%u\n",
				this->http_proxy_address,
							this->http_proxy_port);
	}

	if (port) {

#ifdef LWS_OPENSSL_SUPPORT
		this->use_ssl = ssl_cert_filepath != NULL &&
					       ssl_private_key_filepath != NULL;
		if (this->use_ssl)
			fprintf(stderr, " Compiled with SSL support, "
								  "using it\n");
		else
			fprintf(stderr, " Compiled with SSL support, "
							      "not using it\n");

#else
		if (ssl_cert_filepath != NULL &&
					     ssl_private_key_filepath != NULL) {
			fprintf(stderr, " Not compiled for OpenSSl support!\n");
			return NULL;
		}
		fprintf(stderr, " Compiled without SSL support, "
						       "serving unencrypted\n");
#endif
	}

	/* ignore SIGPIPE */

	signal(SIGPIPE, sigpipe_handler);


#ifdef LWS_OPENSSL_SUPPORT

	/* basic openssl init */

	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	this->openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "libwebsockets", NULL, NULL, NULL);

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
	this->ssl_ctx = SSL_CTX_new(method);	/* create context */
	if (!this->ssl_ctx) {
		fprintf(stderr, "problem creating ssl context: %s\n",
			ERR_error_string(ERR_get_error(), ssl_err_buf));
		return NULL;
	}

	/* client context */

	method = (SSL_METHOD *)SSLv23_client_method();
	if (!method) {
		fprintf(stderr, "problem creating ssl method: %s\n",
			ERR_error_string(ERR_get_error(), ssl_err_buf));
		return NULL;
	}
	this->ssl_client_ctx = SSL_CTX_new(method);	/* create context */
	if (!this->ssl_client_ctx) {
		fprintf(stderr, "problem creating ssl context: %s\n",
			ERR_error_string(ERR_get_error(), ssl_err_buf));
		return NULL;
	}


	/* openssl init for cert verification (used with client sockets) */

	if (!SSL_CTX_load_verify_locations(this->ssl_client_ctx, NULL,
						    LWS_OPENSSL_CLIENT_CERTS)) {
		fprintf(stderr, "Unable to load SSL Client certs from %s "
			"(set by --with-client-cert-dir= in configure) -- "
			" client ssl isn't going to work",
						      LWS_OPENSSL_CLIENT_CERTS);
	}

	/*
	 * callback allowing user code to load extra verification certs
	 * helping the client to verify server identity
	 */

	this->protocols[0].callback(this, NULL,
		LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
		this->ssl_client_ctx, NULL, 0);

	/* as a server, are we requiring clients to identify themselves? */

	if (options & LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) {

		/* absolutely require the client cert */
		
		SSL_CTX_set_verify(this->ssl_ctx,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						       OpenSSL_verify_callback);

		/*
		 * give user code a chance to load certs into the server
		 * allowing it to verify incoming client certs
		 */

		this->protocols[0].callback(this, NULL,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
							this->ssl_ctx, NULL, 0);
	}

	if (this->use_ssl) {

		/* openssl init for server sockets */

		/* set the local certificate from CertFile */
		n = SSL_CTX_use_certificate_file(this->ssl_ctx,
					ssl_cert_filepath, SSL_FILETYPE_PEM);
		if (n != 1) {
			fprintf(stderr, "problem getting cert '%s': %s\n",
				ssl_cert_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(this->ssl_ctx,
						ssl_private_key_filepath,
						       SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "ssl problem getting key '%s': %s\n",
						ssl_private_key_filepath,
				ERR_error_string(ERR_get_error(), ssl_err_buf));
			return NULL;
		}
		/* verify private key */
		if (!SSL_CTX_check_private_key(this->ssl_ctx)) {
			fprintf(stderr, "Private SSL key doesn't match cert\n");
			return NULL;
		}

		/* SSL is happy and has a cert it's content with */
	}
#endif

	/* selftest */

	if (lws_b64_selftest())
		return NULL;

	/* fd hashtable init */

	for (n = 0; n < FD_HASHTABLE_MODULUS; n++)
		this->fd_hashtable[n].length = 0;

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
		if (interface == NULL)
			serv_addr.sin_addr.s_addr = INADDR_ANY;
		else
			interface_to_sa(interface, &serv_addr,
						sizeof(serv_addr));
		serv_addr.sin_port = htons(port);

		n = bind(sockfd, (struct sockaddr *) &serv_addr,
							     sizeof(serv_addr));
		if (n < 0) {
			fprintf(stderr, "ERROR on binding to port %d (%d %d)\n",
								port, n, errno);
			return NULL;
		}

		wsi = malloc(sizeof(struct libwebsocket));
		memset(wsi, 0, sizeof (struct libwebsocket));
		wsi->sock = sockfd;
		wsi->mode = LWS_CONNMODE_SERVER_LISTENER;
		insert_wsi(this, wsi);

		listen(sockfd, 5);
		fprintf(stderr, " Listening on port %d\n", port);

		/* list in the internal poll array */
		
		this->fds[this->fds_count].fd = sockfd;
		this->fds[this->fds_count++].events = POLLIN;

		/* external POLL support via protocol 0 */
		this->protocols[0].callback(this, wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)sockfd, NULL, POLLIN);

	}

	/* drop any root privs for this process */

	if (gid != -1)
		if (setgid(gid))
			fprintf(stderr, "setgid: %s\n", strerror(errno));
	if (uid != -1)
		if (setuid(uid))
			fprintf(stderr, "setuid: %s\n", strerror(errno));


	/* set up our internal broadcast trigger sockets per-protocol */

	for (this->count_protocols = 0;
			protocols[this->count_protocols].callback;
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

		/* dummy wsi per broadcast proxy socket */

		wsi = malloc(sizeof(struct libwebsocket));
		memset(wsi, 0, sizeof (struct libwebsocket));
		wsi->sock = fd;
		wsi->mode = LWS_CONNMODE_BROADCAST_PROXY_LISTENER;
		/* note which protocol we are proxying */
		wsi->protocol_index_for_broadcast_proxy = this->count_protocols;
		insert_wsi(this, wsi);

		/* list in internal poll array */

		this->fds[this->fds_count].fd = fd;
		this->fds[this->fds_count].events = POLLIN;
		this->fds[this->fds_count].revents = 0;
		this->fds_count++;

		/* external POLL support via protocol 0 */
		this->protocols[0].callback(this, wsi,
			LWS_CALLBACK_ADD_POLL_FD,
			(void *)(long)fd, NULL, POLLIN);
	}

	return this;
}


#ifndef LWS_NO_FORK

/**
 * libwebsockets_fork_service_loop() - Optional helper function forks off
 *				  a process for the websocket server loop.
 *				You don't have to use this but if not, you
 *				have to make sure you are calling
 *				libwebsocket_service periodically to service
 *				the websocket traffic
 * @this:	server context returned by creation function
 */

int
libwebsockets_fork_service_loop(struct libwebsocket_context *this)
{
	int fd;
	struct sockaddr_in cli_addr;
	int n;
	int p;

	n = fork();
	if (n < 0)
		return n;

	if (!n) {

		/* main process context */

		/*
		 * set up the proxy sockets to allow broadcast from
		 * service process context
		 */

		for (p = 0; p < this->count_protocols; p++) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
			if (fd < 0) {
				fprintf(stderr, "Unable to create socket\n");
				return -1;
			}
			cli_addr.sin_family = AF_INET;
			cli_addr.sin_port = htons(
			     this->protocols[p].broadcast_socket_port);
			cli_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
			n = connect(fd, (struct sockaddr *)&cli_addr,
							       sizeof cli_addr);
			if (n < 0) {
				fprintf(stderr, "Unable to connect to "
						"broadcast socket %d, %s\n",
						n, strerror(errno));
				return -1;
			}

			this->protocols[p].broadcast_socket_user_fd = fd;
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
	int m;
	struct libwebsocket * wsi;

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

		for (n = 0; n < FD_HASHTABLE_MODULUS; n++) {

			for (m = 0; m < this->fd_hashtable[n].length; m++) {

				wsi = this->fd_hashtable[n].wsi[m];

				if (wsi->mode != LWS_CONNMODE_WS_SERVING)
					continue;

				/*
				 * never broadcast to
				 * non-established connections
				 */
				if (wsi->state != WSI_STATE_ESTABLISHED)
					continue;

				/* only broadcast to guys using
				 * requested protocol
				 */
				if (wsi->protocol != protocol)
					continue;

				wsi->protocol->callback(this, wsi,
					 LWS_CALLBACK_BROADCAST,
					 wsi->user_space,
					 buf, len);
			}
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

	n = send(protocol->broadcast_socket_user_fd, buf, len, MSG_NOSIGNAL);

	return n;
}
