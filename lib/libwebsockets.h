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
	LWS_CALLBACK_SEND,
	LWS_CALLBACK_RECEIVE,
	LWS_CALLBACK_HTTP,
	LWS_CALLBACK_PROTOCOL_FILTER,
};

enum libwebsocket_write_protocol {
	LWS_WRITE_TEXT,
	LWS_WRITE_BINARY,
	LWS_WRITE_HTTP
};

struct libwebsocket;

extern int libwebsocket_create_server(int port,
		  int (*callback)(struct libwebsocket *wsi,
				  enum libwebsocket_callback_reasons reason,
				  void *user, void *in, size_t len),
					       int protocol, size_t user_space,
					       const char * ssl_cert_filepath,
					const char * ssl_private_key_filepath,
							      int gid, int uid);

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

extern int
libwebsockets_serve_http_file(struct libwebsocket *wsi, const char * file,
						     const char * content_type);

#endif
