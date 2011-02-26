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

#include <poll.h>

#define CONTEXT_PORT_NO_LISTEN 0


enum libwebsocket_context_options {
	LWS_SERVER_OPTION_DEFEAT_CLIENT_MASK = 1,
	LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT = 2,
};

enum libwebsocket_callback_reasons {
	LWS_CALLBACK_ESTABLISHED,
	LWS_CALLBACK_CLIENT_ESTABLISHED,
	LWS_CALLBACK_CLOSED,
	LWS_CALLBACK_RECEIVE,
	LWS_CALLBACK_CLIENT_RECEIVE,
	LWS_CALLBACK_CLIENT_RECEIVE_PONG,
	LWS_CALLBACK_CLIENT_WRITEABLE,
	LWS_CALLBACK_HTTP,
	LWS_CALLBACK_BROADCAST,
	LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
	LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
	LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,

	/* external poll() management support */
	LWS_CALLBACK_ADD_POLL_FD,
	LWS_CALLBACK_DEL_POLL_FD,
	LWS_CALLBACK_SET_MODE_POLL_FD,
	LWS_CALLBACK_CLEAR_MODE_POLL_FD,
};

enum libwebsocket_write_protocol {
	LWS_WRITE_TEXT,
	LWS_WRITE_BINARY,
	LWS_WRITE_HTTP,

	/* special 04+ opcodes */

	LWS_WRITE_CLOSE,
	LWS_WRITE_PING,
	LWS_WRITE_PONG,

	/* flags */

	LWS_WRITE_NO_FIN = 0x40,
	/*
	 * client packet payload goes out on wire unmunged
	 * only useful for security tests since normal servers cannot
	 * decode the content if used
	 */
	LWS_WRITE_CLIENT_IGNORE_XOR_MASK = 0x80
};

/*
 * you need these to look at headers that have been parsed if using the
 * LWS_CALLBACK_FILTER_CONNECTION callback.  If a header from the enum
 * list below is absent, .token = NULL and token_len = 0.  Otherwise .token
 * points to .token_len chars containing that header content.
 */

struct lws_tokens {
	char *token;
	int token_len;
};

enum lws_token_indexes {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_HOST,
	WSI_TOKEN_CONNECTION,
	WSI_TOKEN_KEY1,
	WSI_TOKEN_KEY2,
	WSI_TOKEN_PROTOCOL,
	WSI_TOKEN_UPGRADE,
	WSI_TOKEN_ORIGIN,
	WSI_TOKEN_DRAFT,
	WSI_TOKEN_CHALLENGE,

	/* new for 04 */
	WSI_TOKEN_KEY,
	WSI_TOKEN_VERSION,
	WSI_TOKEN_SWORIGIN,

	/* new for 05 */
	WSI_TOKEN_EXTENSIONS,

	/* client receives these */
	WSI_TOKEN_ACCEPT,
	WSI_TOKEN_NONCE,
	WSI_TOKEN_HTTP,

	/* always last real token index*/
	WSI_TOKEN_COUNT,
	/* parser state additions */
	WSI_TOKEN_NAME_PART,
	WSI_TOKEN_SKIPPING,
	WSI_TOKEN_SKIPPING_SAW_CR,
	WSI_PARSING_COMPLETE
};

/*
 * From 06 sped
   1000

      1000 indicates a normal closure, meaning whatever purpose the
      connection was established for has been fulfilled.

   1001

      1001 indicates that an endpoint is "going away", such as a server
      going down, or a browser having navigated away from a page.

   1002

      1002 indicates that an endpoint is terminating the connection due
      to a protocol error.

   1003

      1003 indicates that an endpoint is terminating the connection
      because it has received a type of data it cannot accept (e.g. an
      endpoint that understands only text data may send this if it
      receives a binary message.)

   1004

      1004 indicates that an endpoint is terminating the connection
      because it has received a message that is too large.
*/

enum lws_close_status {
	LWS_CLOSE_STATUS_NOSTATUS = 0,
	LWS_CLOSE_STATUS_NORMAL = 1000,
	LWS_CLOSE_STATUS_GOINGAWAY = 1001,
	LWS_CLOSE_STATUS_PROTOCOL_ERR = 1002,
	LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE = 1003,
	LWS_CLOSE_STATUS_PAYLOAD_TOO_LARGE = 1004,
};

struct libwebsocket;
struct libwebsocket_context;

/* document the generic callback (it's a fake prototype under this) */
/**
 * callback() - User server actions
 * @context:	Websockets context
 * @wsi:	Opaque websocket instance pointer
 * @reason:	The reason for the call
 * @user:	Pointer to per-session user data allocated by library
 * @in:		Pointer used for some callback reasons
 * @len:	Length set for some callback reasons
 *
 *	This callback is the way the user controls what is served.  All the
 *	protocol detail is hidden and handled by the library.
 *
 *	For each connection / session there is user data allocated that is
 *	pointed to by "user".  You set the size of this user data area when
 *	the library is initialized with libwebsocket_create_server.
 *
 *	You get an opportunity to initialize user data when called back with
 *	LWS_CALLBACK_ESTABLISHED reason.
 *
 *	LWS_CALLBACK_ESTABLISHED:  after the server completes a handshake with
 *				an incoming client
 *
 *      LWS_CALLBACK_CLIENT_ESTABLISHED: after your client connection completed
 *				a handshake with the remote server
 *
 *	LWS_CALLBACK_CLOSED: when the websocket session ends
 *
 *	LWS_CALLBACK_BROADCAST: signal to send to client (you would use
 *				libwebsocket_write() taking care about the
 *				special buffer requirements
 *
 *	LWS_CALLBACK_RECEIVE: data has appeared for this server endpoint from a
 *				remote client, it can be found at *in and is
 *				len bytes long
 *
 *	LWS_CALLBACK_CLIENT_RECEIVE_PONG: if you elected to see PONG packets,
 *				they appear with this callback reason.  PONG
 *				packets only exist in 04+ protocol
 *
 *	LWS_CALLBACK_CLIENT_RECEIVE: data has appeared from the server for the
 *				client connection, it can be found at *in and
 *				is len bytes long
 *
 *	LWS_CALLBACK_HTTP: an http request has come from a client that is not
 *				asking to upgrade the connection to a websocket
 *				one.  This is a chance to serve http content,
 *				for example, to send a script to the client
 *				which will then open the websockets connection.
 *				@in points to the URI path requested and
 *				libwebsockets_serve_http_file() makes it very
 *				simple to send back a file to the client.
 *
 *	LWS_CALLBACK_CLIENT_WRITEABLE:  if you call
 *		libwebsocket_callback_on_writable() on a connection, you will
 *		get this callback coming when the connection socket is able to
 *		accept another write packet without blocking.  If it already
 *		was able to take another packet without blocking, you'll get
 *		this callback at the next call to the service loop function.
 *
 *	LWS_CALLBACK_FILTER_NETWORK_CONNECTION: called when a client connects to
 *		the server at network level; the connection is accepted but then
 *		passed to this callback to decide whether to hang up immediately
 *		or not, based on the client IP.  @user contains the connection
 *		socket's descriptor.  Return non-zero to terminate
 *		the connection before sending or receiving anything.
 * 		Because this happens immediately after the network connection
 *		from the client, there's no websocket protocol selected yet so
 *		this callback is issued only to protocol 0.
 *
 * 	LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: called when the handshake has
 * 		been received and parsed from the client, but the response is
 * 		not sent yet.  Return non-zero to disallow the connection.
 *		@user is a pointer to an array of struct lws_tokens, you can
 *		use the header enums lws_token_indexes from libwebsockets.h
 *		to check for and read the supported header presence and
 *		content before deciding to allow the handshake to proceed or
 *		to kill the connection.
 *
 * 	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS: if configured for
 * 		including OpenSSL support, this callback allows your user code
 * 		to perform extra SSL_CTX_load_verify_locations() or similar
 *		calls to direct OpenSSL where to find certificates the client
 *		can use to confirm the remote server identity.  @user is the
 *		OpenSSL SSL_CTX*
 *
 *	LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS: if configured for
 *		including OpenSSL support, this callback allows your user code
 *		to load extra certifcates into the server which allow it to
 *		verify the validity of certificates returned by clients.  @user
 *		is the server's OpenSSL SSL_CTX*
 *
 *	LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION: if the
 *		libwebsockets context was created with the option
 *		LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT, then this
 *		callback is generated during OpenSSL verification of the cert
 *		sent from the client.  It is sent to protocol[0] callback as
 *		no protocol has been negotiated on the connection yet.
 *		Notice that the libwebsockets context and wsi are both NULL
 *		during this callback.  See
 *		 http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
 *		to understand more detail about the OpenSSL callback that
 *		generates this libwebsockets callback and the meanings of the
 *		arguments passed.  In this callback, @user is the x509_ctx,
 *		@in is the ssl pointer and @len is preverify_ok
 *		Notice that this callback maintains libwebsocket return
 *		conventions, return 0 to mean the cert is OK or 1 to fail it.
 *		This also means that if you don't handle this callback then
 *		the default callback action of returning 0 allows the client
 *		certificates.
 *
 *	The next four reasons are optional and only need taking care of if you
 * 	will be integrating libwebsockets sockets into an external polling
 * 	array.
 * 
 * 	LWS_CALLBACK_ADD_POLL_FD: libwebsocket deals with its poll() loop
 * 		internally, but in the case you are integrating with another
 * 		server you will need to have libwebsocket sockets share a
 * 		polling array with the other server.  This and the other
 * 		POLL_FD related callbacks let you put your specialized
 * 		poll array interface code in the callback for protocol 0, the
 * 		first protocol you support, usually the HTTP protocol in the
 * 		serving case.  This callback happens when a socket needs to be
 *		added to the polling loop: @user contains the fd, and
 * 		@len is the events bitmap (like, POLLIN).  If you are using the
 *		internal polling loop (the "service" callback), you can just
 * 		ignore these callbacks.
 *
 * 	LWS_CALLBACK_DEL_POLL_FD: This callback happens when a socket descriptor
 * 		needs to be removed from an external polling array.  @user is
 * 		the socket desricptor.  If you are using the internal polling
 * 		loop, you can just ignore it.
 *
 * 	LWS_CALLBACK_SET_MODE_POLL_FD: This callback happens when libwebsockets
 * 		wants to modify the events for the socket descriptor in @user.
 *		The handler should OR @len on to the events member of the pollfd
 * 		struct for this socket descriptor.  If you are using the
 *		internal polling loop, you can just ignore it.
 *
 *	LWS_CALLBACK_CLEAR_MODE_POLL_FD: This callback occurs when libwebsockets
 * 		wants to modify the events for the socket descriptor in @user.
 *		The handler should AND ~@len on to the events member of the
 * 		pollfd struct for this socket descriptor.  If you are using the
 *		internal polling loop, you can just ignore it.
 */
extern int callback(struct libwebsocket_context * context,
			struct libwebsocket *wsi,
			 enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len);

/**
 * struct libwebsocket_protocols -	List of protocols and handlers server
 *					supports.
 * @name:	Protocol name that must match the one given in the client
 *		Javascript new WebSocket(url, 'protocol') name
 * @callback:	The service callback used for this protocol.  It allows the
 *		service action for an entire protocol to be encapsulated in
 *		the protocol-specific callback
 * @per_session_data_size:	Each new connection using this protocol gets
 *		this much memory allocated on connection establishment and
 *		freed on connection takedown.  A pointer to this per-connection
 *		allocation is passed into the callback in the 'user' parameter
 * @owning_server:	the server init call fills in this opaque pointer when
 *		registering this protocol with the server.
 * @broadcast_socket_port: the server init call fills this in with the
 *		localhost port number used to forward broadcasts for this
 *		protocol
 * @broadcast_socket_user_fd:  the server init call fills this in ... the main()
 *		process context can write to this socket to perform broadcasts
 *		(use the libwebsockets_broadcast() api to do this instead,
 *		it works from any process context)
 * @protocol_index: which protocol we are starting from zero
 *
 *	This structure represents one protocol supported by the server.  An
 *	array of these structures is passed to libwebsocket_create_server()
 *	allows as many protocols as you like to be handled by one server.
 */

struct libwebsocket_protocols {
	const char *name;
	int (*callback)(struct libwebsocket_context * context,
			struct libwebsocket *wsi,
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

extern struct libwebsocket_context *
libwebsocket_create_context(int port, const char * interface,
		  struct libwebsocket_protocols *protocols,
		  const char *ssl_cert_filepath,
		  const char *ssl_private_key_filepath, int gid, int uid,
		  unsigned int options);

extern void
libwebsocket_context_destroy(struct libwebsocket_context *context);

extern int
libwebsockets_fork_service_loop(struct libwebsocket_context *context);

extern int
libwebsocket_service(struct libwebsocket_context *context, int timeout_ms);

extern int
libwebsocket_service_fd(struct libwebsocket_context *context,
							 struct pollfd *pollfd);

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

/*
 * this is the frame nonce plus two header plus 8 length
 * 2 byte prepend on close will already fit because control frames cannot use
 * the big length style
 */

#define LWS_SEND_BUFFER_PRE_PADDING (4 + 10)
#define LWS_SEND_BUFFER_POST_PADDING 1

extern int
libwebsocket_write(struct libwebsocket *wsi, unsigned char *buf, size_t len,
				     enum libwebsocket_write_protocol protocol);

extern int
libwebsockets_serve_http_file(struct libwebsocket *wsi, const char *file,
						     const char *content_type);

/* notice - you need the pre- and post- padding allocation for buf below */

extern int
libwebsockets_broadcast(const struct libwebsocket_protocols *protocol,
						unsigned char *buf, size_t len);

extern const struct libwebsocket_protocols *
libwebsockets_get_protocol(struct libwebsocket *wsi);

extern int
libwebsocket_callback_on_writable(struct libwebsocket_context *context,
						      struct libwebsocket *wsi);

extern int
libwebsocket_callback_on_writable_all_protocol(
				 const struct libwebsocket_protocols *protocol);

extern int
libwebsocket_get_socket_fd(struct libwebsocket *wsi);

extern int
libwebsocket_rx_flow_control(struct libwebsocket *wsi, int enable);

extern size_t
libwebsockets_remaining_packet_payload(struct libwebsocket *wsi);

extern struct libwebsocket *
libwebsocket_client_connect(struct libwebsocket_context *clients,
			      const char *address,
			      int port,
			      int ssl_connection,
			      const char *path,
			      const char *host,
			      const char *origin,
			      const char *protocol,
			      int ietf_version_or_minus_one);

extern const char *
libwebsocket_canonical_hostname(struct libwebsocket_context *context);


extern void
libwebsockets_get_peer_addresses(int fd, char *name, int name_len,
					char *rip, int rip_len);

extern void
libwebsockets_hangup_on_client(struct libwebsocket_context *context, int fd);

extern void
libwebsocket_close_and_free_session(struct libwebsocket_context *context,
			       struct libwebsocket *wsi, enum lws_close_status);

#endif
