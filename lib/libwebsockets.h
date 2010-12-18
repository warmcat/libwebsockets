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

#ifndef __LIBWEBSOCKET_H__
#define __LIBWEBSOCKET_H__


enum libwebsocket_callback_reasons {
	LWS_CALLBACK_ESTABLISHED,
	LWS_CALLBACK_CLOSED,
	LWS_CALLBACK_RECEIVE,
	LWS_CALLBACK_HTTP,
	LWS_CALLBACK_BROADCAST,
};

enum libwebsocket_write_protocol {
	LWS_WRITE_TEXT,
	LWS_WRITE_BINARY,
	LWS_WRITE_HTTP
};

struct libwebsocket;
struct libwebsocket_context;

/**
 * struct libwebsocket_protocols - 	List of protocols and handlers server
 * 					supports.
 * @name:	Protocol name that must match the one given in the client
 * 		Javascript new WebSocket(url, 'protocol') name
 * @callback:	The service callback used for this protocol.  It allows the
 * 		service action for an entire protocol to be encapsulated in
 * 		the protocol-specific callback
 * @per_session_data_size:	Each new connection using this protocol gets
 * 		this much memory allocated on connection establishment and
 * 		freed on connection takedown.  A pointer to this per-connection
 * 		allocation is passed into the callback in the 'user' parameter
 * @owning_server:	the server init call fills in this opaque pointer when
 * 		registering this protocol with the server.
 * @broadcast_socket_port: the server init call fills this in with the
 * 		localhost port number used to forward broadcasts for this
 * 		protocol
 * @broadcast_socket_user_fd:  the server init call fills this in ... the main()
 * 		process context can write to this socket to perform broadcasts
 * 		(use the libwebsockets_broadcast() api to do this instead,
 * 		it works from any process context)
 * @protocol_index: which protocol we are starting from zero
 *
 * 	This structure represents one protocol supported by the server.  An
 * 	array of these structures is passed to libwebsocket_create_server()
 * 	allows as many protocols as you like to be handled by one server.
 */

struct libwebsocket_protocols {
	const char *name;
	int (*callback)(struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len);
	size_t per_session_data_size;

	/*
	 * below are filled in on server init and can be left uninitialized,
	 * no need for user to use them directly either
	 */
	
	struct libwebsocket_context *owning_server;
	int broadcast_socket_port;
	int broadcast_socket_user_fd;
	int protocol_index;
};

extern int libwebsocket_create_server(int port,
		  struct libwebsocket_protocols *protocols,
		  const char *ssl_cert_filepath,
		  const char *ssl_private_key_filepath, int gid, int uid);

/*
 * IMPORTANT NOTICE!
 *
 * When sending with websocket protocol (LWS_WRITE_TEXT or LWS_WRITE_BINARY)
 * the send buffer has to have LWS_SEND_BUFFER_PRE_PADDING bytes valid BEFORE
 * buf, and LWS_SEND_BUFFER_POST_PADDING bytes valid AFTER (buf + len).
 *
 * This allows us to add protocol info before and after the data, and send as
 * one packet on the network without payload copying, for maximum efficiency.
 *
 * So for example you need this kind of code to use libwebsocket_write with a
 * 128-byte payload
 *
 *   char buf[LWS_SEND_BUFFER_PRE_PADDING + 128 + LWS_SEND_BUFFER_POST_PADDING];
 *
 *   // fill your part of the buffer... for example here it's all zeros
 *   memset(&buf[LWS_SEND_BUFFER_PRE_PADDING], 0, 128);
 *
 *   libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], 128);
 *
 * When sending LWS_WRITE_HTTP, there is no protocol addition and you can just
 * use the whole buffer without taking care of the above.
 */

#define LWS_SEND_BUFFER_PRE_PADDING 12
#define LWS_SEND_BUFFER_POST_PADDING 1

extern int
libwebsocket_write(struct libwebsocket *wsi, unsigned char *buf, size_t len,
				     enum libwebsocket_write_protocol protocol);

extern int
libwebsockets_serve_http_file(struct libwebsocket *wsi, const char *file,
						     const char *content_type);

/* notice - you need the pre- and post- padding allocation for buf below */

extern int
libwebsockets_broadcast(const struct libwebsocket_protocols * protocol,
						unsigned char *buf, size_t len);

extern const struct libwebsocket_protocols *
libwebsockets_get_protocol(struct libwebsocket *wsi);

#endif
