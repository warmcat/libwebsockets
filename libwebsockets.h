#ifndef __LIBWEBSOCKET_H__
#define __LIBWEBSOCKET_H__


enum libwebsocket_callback_reasons {
	LWS_CALLBACK_ESTABLISHED,
	LWS_CALLBACK_CLOSED,
	LWS_CALLBACK_SEND,
	LWS_CALLBACK_RECEIVE,
	LWS_CALLBACK_HTTP
};

enum libwebsocket_write_protocol {
	LWS_WRITE_TEXT,
	LWS_WRITE_BINARY,
	LWS_WRITE_HTTP
};

struct libwebsocket;

/**
 * libwebsocket_callback() - User server actions
 * @wsi:	Opaque websocket instance pointer
 * @reason:	The reason for the call
 * @in:		Pointer used for some callback reasons
 * @len:	Length set for some callback reasons
 * 
 * 	This callback is the way the user controls what is served.  All the
 * 	protocol detail is hidden and handled by the library.
 * 
 * 	LWS_CALLBACK_ESTABLISHED:  after successful websocket handshake
 * 	LWS_CALLBACK_CLOSED: when the websocket session ends
 * 	LWS_CALLBACK_SEND: opportunity to send to client (you would use
 * 				libwebsocket_write() taking care about the
 * 				special buffer requirements
 * 	LWS_CALLBACK_RECEIVE: data has appeared for the server, it can be
 * 				found at *in and is len bytes long
 * 	LWS_CALLBACK_HTTP: an http request has come from a client that is not
 * 				asking to upgrade the connection to a websocket
 * 				one.  This is a chance to serve http content,
 * 				for example, to send a script to the client
 * 				which will then open the websockets connection.
 * 				libwebsocket_get_uri() lets you find out the
 * 				URI path requested and 
 * 				libwebsockets_serve_http_file() makes it very
 * 				simple to send back a file to the client.
 */

extern int libwebsocket_create_server(int port,
		  int (*callback)(struct libwebsocket *wsi,
				  enum libwebsocket_callback_reasons reason,
				  void *in, size_t len), int protocol);

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
libwebsocket_write(struct libwebsocket *, unsigned char *buf, size_t len,
				     enum libwebsocket_write_protocol protocol);
extern const char *
libwebsocket_get_uri(struct libwebsocket *wsi);

extern int
libwebsockets_serve_http_file(struct libwebsocket *wsi, const char * file,
						     const char * content_type);

#endif
