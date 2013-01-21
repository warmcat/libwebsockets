/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
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

#ifdef WIN32
#include <tchar.h>
#include <io.h>
#else
#ifdef LWS_BUILTIN_GETIFADDRS
#include <getifaddrs.h>
#else
#include <ifaddrs.h>
#endif
#include <sys/un.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#ifdef LWS_OPENSSL_SUPPORT
extern int openssl_websocket_private_data_index;

static void
libwebsockets_decode_ssl_error(void)
{
	char buf[256];
	u_long err;

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		lwsl_err("*** %s\n", buf);
	}
}
#endif

int
interface_to_sa(const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	int rc = -1;
#ifdef WIN32
	/* TODO */
#else
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
#endif
	return rc;
}

struct libwebsocket *
libwebsocket_create_new_server_wsi(struct libwebsocket_context *context)
{
	struct libwebsocket *new_wsi;
	int n;

	new_wsi = (struct libwebsocket *)malloc(sizeof(struct libwebsocket));
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	memset(new_wsi, 0, sizeof(struct libwebsocket));
#ifndef LWS_NO_EXTENSIONS
	new_wsi->count_active_extensions = 0;
#endif
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;

	/* intialize the instance struct */

	new_wsi->state = WSI_STATE_HTTP;
	new_wsi->u.hdr.name_buffer_pos = 0;
	new_wsi->mode = LWS_CONNMODE_HTTP_SERVING;

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
	new_wsi->protocol = context->protocols;
	new_wsi->user_space = NULL;

	/*
	 * Default protocol is 76 / 00
	 * After 76, there's a header specified to inform which
	 * draft the client wants, when that's seen we modify
	 * the individual connection's spec revision accordingly
	 */
	new_wsi->ietf_spec_revision = 0;

	return new_wsi;
}

int lws_server_socket_service(struct libwebsocket_context *context,
			struct libwebsocket *wsi, struct pollfd *pollfd)
{
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1 +
			 MAX_BROADCAST_PAYLOAD + LWS_SEND_BUFFER_POST_PADDING];
	struct libwebsocket *new_wsi;
	int accept_fd;
	unsigned int clilen;
	struct sockaddr_in cli_addr;
	int n;
	int opt = 1;
	ssize_t len;

	switch (wsi->mode) {

	case LWS_CONNMODE_HTTP_SERVING:

		/* handle http headers coming in */

		/* any incoming data ready? */

		if (pollfd->revents & POLLIN) {

	#ifdef LWS_OPENSSL_SUPPORT
			if (wsi->ssl)
				len = SSL_read(wsi->ssl, buf, sizeof buf);
			else
	#endif
				len = recv(pollfd->fd, buf, sizeof buf, 0);

			if (len < 0) {
				lwsl_debug("Socket read returned %d\n", len);
				if (errno != EINTR && errno != EAGAIN)
					libwebsocket_close_and_free_session(context,
						       wsi, LWS_CLOSE_STATUS_NOSTATUS);
				return 0;
			}
			if (!len) {
				libwebsocket_close_and_free_session(context, wsi,
							    LWS_CLOSE_STATUS_NOSTATUS);
				return 0;
			}

			n = libwebsocket_read(context, wsi, buf, len);
			if (n < 0)
				/* we closed wsi */
				return 0;
		}

		/* this handles POLLOUT for http serving fragments */

		if (!(pollfd->revents & POLLOUT))
			break;

		/* one shot */
		pollfd->events &= ~POLLOUT;
		
		if (wsi->state != WSI_STATE_HTTP_ISSUING_FILE)
			break;

		if (libwebsockets_serve_http_file_fragment(context, wsi) < 0)
			libwebsocket_close_and_free_session(context, wsi,
					       LWS_CLOSE_STATUS_NOSTATUS);
		else
			if (wsi->state == WSI_STATE_HTTP && wsi->protocol->callback)
				if (user_callback_handle_rxflow(wsi->protocol->callback, context, wsi, LWS_CALLBACK_HTTP_FILE_COMPLETION, wsi->user_space,
								wsi->u.http.filepath, wsi->u.http.filepos))
					libwebsocket_close_and_free_session(context, wsi, LWS_CLOSE_STATUS_NOSTATUS);
		break;

	case LWS_CONNMODE_SERVER_LISTENER:

		/* pollin means a client has connected to us then */

		if (!(pollfd->revents & POLLIN))
			break;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		if (accept_fd < 0) {
			lwsl_warn("ERROR on accept: %s\n", strerror(errno));
			break;
		}

		/* Disable Nagle */
		opt = 1;
		setsockopt(accept_fd, IPPROTO_TCP, TCP_NODELAY,
					      (const void *)&opt, sizeof(opt));

		/*
		 * look at who we connected to and give user code a chance
		 * to reject based on client IP.  There's no protocol selected
		 * yet so we issue this to protocols[0]
		 */

		if ((context->protocols[0].callback)(context, wsi,
				LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
					   (void *)(long)accept_fd, NULL, 0)) {
			lwsl_debug("Callback denied network connection\n");
			compatible_close(accept_fd);
			break;
		}

		new_wsi = libwebsocket_create_new_server_wsi(context);
		if (new_wsi == NULL) {
			compatible_close(accept_fd);
			break;
		}

		new_wsi->sock = accept_fd;


#ifdef LWS_OPENSSL_SUPPORT
		new_wsi->ssl = NULL;

		if (context->use_ssl) {

			new_wsi->ssl = SSL_new(context->ssl_ctx);
			if (new_wsi->ssl == NULL) {
				lwsl_err("SSL_new failed: %s\n",
				    ERR_error_string(SSL_get_error(
				    new_wsi->ssl, 0), NULL));
				    libwebsockets_decode_ssl_error();
				free(new_wsi);
				compatible_close(accept_fd);
				break;
			}

			SSL_set_ex_data(new_wsi->ssl,
				openssl_websocket_private_data_index, context);

			SSL_set_fd(new_wsi->ssl, accept_fd);

			n = SSL_accept(new_wsi->ssl);
			if (n != 1) {
				/*
				 * browsers seem to probe with various
				 * ssl params which fail then retry
				 * and succeed
				 */
				lwsl_debug("SSL_accept failed skt %u: %s\n",
				      pollfd->fd,
				      ERR_error_string(SSL_get_error(
				      new_wsi->ssl, n), NULL));
				SSL_free(
				       new_wsi->ssl);
				free(new_wsi);
				compatible_close(accept_fd);
				break;
			}

			lwsl_debug("accepted new SSL conn  "
			      "port %u on fd=%d SSL ver %s\n",
				ntohs(cli_addr.sin_port), accept_fd,
				  SSL_get_version(new_wsi->ssl));

		} else
#endif
			lwsl_debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), accept_fd);

		insert_wsi_socket_into_fds(context, new_wsi);
		break;

#ifndef LWS_NO_FORK
	case LWS_CONNMODE_BROADCAST_PROXY_LISTENER:

		/* as we are listening, POLLIN means accept() is needed */

		if (!(pollfd->revents & POLLIN))
			break;

		/* listen socket got an unencrypted connection... */

		clilen = sizeof(cli_addr);
		accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
								       &clilen);
		if (accept_fd < 0) {
			lwsl_warn("ERROR on accept %d\n", accept_fd);
			return 0;
		}

		/* create a dummy wsi for the connection and add it */

		new_wsi = (struct libwebsocket *)malloc(sizeof(struct libwebsocket));
		if (new_wsi == NULL) {
			lwsl_err("Out of mem\n");
			goto bail_prox_listener;
		}
		memset(new_wsi, 0, sizeof (struct libwebsocket));
		new_wsi->sock = accept_fd;
		new_wsi->mode = LWS_CONNMODE_BROADCAST_PROXY;
		new_wsi->state = WSI_STATE_ESTABLISHED;
#ifndef LWS_NO_EXTENSIONS
		new_wsi->count_active_extensions = 0;
#endif
		/* note which protocol we are proxying */
		new_wsi->protocol_index_for_broadcast_proxy =
					wsi->protocol_index_for_broadcast_proxy;

		insert_wsi_socket_into_fds(context, new_wsi);
		break;

bail_prox_listener:
		compatible_close(accept_fd);
		break;

	case LWS_CONNMODE_BROADCAST_PROXY:

		/* handle session socket closed */

		if (pollfd->revents & (POLLERR | POLLHUP)) {

			lwsl_debug("Session Socket %p (fd=%d) dead\n",
				(void *)wsi, pollfd->fd);

			libwebsocket_close_and_free_session(context, wsi,
						       LWS_CLOSE_STATUS_NORMAL);
			return 0;
		}

		/*
		 * either extension code with stuff to spill, or the user code,
		 * requested a callback when it was OK to write
		 */

		if (pollfd->revents & POLLOUT)
			if (lws_handle_POLLOUT_event(context, wsi,
								 pollfd) < 0) {
				libwebsocket_close_and_free_session(
					context, wsi, LWS_CLOSE_STATUS_NORMAL);
				return 0;
			}

		/* any incoming data ready? */

		if (!(pollfd->revents & POLLIN))
			break;

		/* get the issued broadcast payload from the socket */

		len = read(pollfd->fd, buf + LWS_SEND_BUFFER_PRE_PADDING,
							 MAX_BROADCAST_PAYLOAD);
		if (len < 0) {
			lwsl_err("Error reading broadcast payload\n");
			break;
		}

		/* broadcast it to all guys with this protocol index */

		for (n = 0; n < context->fds_count; n++) {

			new_wsi = context->lws_lookup[context->fds[n].fd];
			if (new_wsi == NULL)
				continue;

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

			user_callback_handle_rxflow(new_wsi->protocol->callback, context, new_wsi,
				LWS_CALLBACK_BROADCAST,
				new_wsi->user_space,
				buf + LWS_SEND_BUFFER_PRE_PADDING, len);
		}
		break;
#endif
	default:
		break;
	}
	return 0;
}
