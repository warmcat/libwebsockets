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

/*
 * -04 of the protocol (actually the 80th version) has a radically different
 * handshake.  The 04 spec gives the following idea
 *
 *    The handshake from the client looks as follows:
 *
 *      GET /chat HTTP/1.1
 *      Host: server.example.com
 *      Upgrade: websocket
 *      Connection: Upgrade
 *      Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
 *      Sec-WebSocket-Origin: http://example.com
 *      Sec-WebSocket-Protocol: chat, superchat
 *	Sec-WebSocket-Version: 4
 *
 *  The handshake from the server looks as follows:
 *
 *       HTTP/1.1 101 Switching Protocols
 *       Upgrade: websocket
 *       Connection: Upgrade
 *       Sec-WebSocket-Accept: me89jWimTRKTWwrS3aRrL53YZSo=
 *       Sec-WebSocket-Nonce: AQIDBAUGBwgJCgsMDQ4PEC==
 *       Sec-WebSocket-Protocol: chat
 */

/*
 * We have to take care about parsing because the headers may be split
 * into multiple fragments.  They may contain unknown headers with arbitrary
 * argument lengths.  So, we parse using a single-character at a time state
 * machine that is completely independent of packet size.
 */

int
libwebsocket_read(struct libwebsocket_context *context,
		     struct libwebsocket *wsi, unsigned char * buf, size_t len)
{
	size_t n;

	switch (wsi->state) {
	case WSI_STATE_HTTP_ISSUING_FILE:
	case WSI_STATE_HTTP:
		wsi->state = WSI_STATE_HTTP_HEADERS;
		wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
		wsi->u.hdr.lextable_pos = 0;
		/* fallthru */
	case WSI_STATE_HTTP_HEADERS:

		lwsl_parser("issuing %d bytes to parser\n", (int)len);
#ifdef _DEBUG
		//fwrite(buf, 1, len, stderr);
#endif

#ifndef LWS_NO_CLIENT

//		lwsl_info("mode=%d\n", wsi->mode);

		switch (wsi->mode) {
		case LWS_CONNMODE_WS_CLIENT_WAITING_PROXY_REPLY:
		case LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE:
		case LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY:
		case LWS_CONNMODE_WS_CLIENT_WAITING_EXTENSION_CONNECT:
		case LWS_CONNMODE_WS_CLIENT:
			for (n = 0; n < len; n++)
				libwebsocket_client_rx_sm(wsi, *buf++);

			return 0;
		default:
			break;
		}
#endif
#ifndef LWS_NO_SERVER
		/* LWS_CONNMODE_WS_SERVING */

		extern int handshake_0405(struct libwebsocket_context *context, struct libwebsocket *wsi);

		for (n = 0; n < len; n++)
			libwebsocket_parse(wsi, *buf++);

		if (wsi->u.hdr.parser_state != WSI_PARSING_COMPLETE)
			break;

		lwsl_parser("seem to be serving, mode is %d\n", wsi->mode);

		lwsl_parser("libwebsocket_parse sees parsing complete\n");

		/* is this websocket protocol or normal http 1.0? */

		if (!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
			     !wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len) {
			wsi->state = WSI_STATE_HTTP;
			if (wsi->protocol->callback)
				if (wsi->protocol->callback(context, wsi,
								LWS_CALLBACK_HTTP, wsi->user_space,
								wsi->utf8_token[WSI_TOKEN_GET_URI].token,
								wsi->utf8_token[WSI_TOKEN_GET_URI].token_len)) {
					lwsl_info("LWS_CALLBACK_HTTP wanted to close\n");
					goto bail;
				}
			return 0;
		}

		if (!wsi->protocol)
			lwsl_err("NULL protocol at libwebsocket_read\n");


		/*
		 * It's websocket
		 *
		 * Make sure user side is happy about protocol
		 */

		while (wsi->protocol->callback) {

			if (wsi->utf8_token[WSI_TOKEN_PROTOCOL].token == NULL) {
				if (wsi->protocol->name == NULL)
					break;
			} else
				if (wsi->protocol->name && strcmp(
				     wsi->utf8_token[WSI_TOKEN_PROTOCOL].token,
						      wsi->protocol->name) == 0)
					break;

			wsi->protocol++;
		}

		/* we didn't find a protocol he wanted? */

		if (wsi->protocol->callback == NULL) {
			if (wsi->utf8_token[WSI_TOKEN_PROTOCOL].token == NULL)
				lwsl_err("[no protocol] "
					"not supported (use NULL .name)\n");
			else
				lwsl_err("Requested protocol %s "
						"not supported\n",
				     wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
			goto bail;
		}

		/*
		 * find out which spec version the client is using
		 * if this header is not given, we default to 00 (aka 76)
		 */

		if (wsi->utf8_token[WSI_TOKEN_VERSION].token_len)
			wsi->ietf_spec_revision =
				 atoi(wsi->utf8_token[WSI_TOKEN_VERSION].token);

		/*
		 * Give the user code a chance to study the request and
		 * have the opportunity to deny it
		 */

		if ((wsi->protocol->callback)(wsi->protocol->owning_server, wsi,
				LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
						&wsi->utf8_token[0], NULL, 0)) {
			lwsl_warn("User code denied connection\n");
			goto bail;
		}


		/*
		 * Perform the handshake according to the protocol version the
		 * client announced
		 */

		switch (wsi->ietf_spec_revision) {
		case 13:
			lwsl_parser("libwebsocket_parse calling handshake_04\n");
			if (handshake_0405(context, wsi)) {
				lwsl_info("handshake_0405 xor 05 has failed the connection\n");
				goto bail;
			}
			break;

		default:
			lwsl_warn("Unknown client spec version %d\n",
						       wsi->ietf_spec_revision);
			goto bail;
		}

		wsi->mode = LWS_CONNMODE_WS_SERVING;

		/* union transition */
		memset(&wsi->u, 0, sizeof wsi->u);

		lwsl_parser("accepted v%02d connection\n",
						       wsi->ietf_spec_revision);
#endif
		break;

	case WSI_STATE_AWAITING_CLOSE_ACK:
	case WSI_STATE_ESTABLISHED:
#ifndef LWS_NO_CLIENT
		switch (wsi->mode) {
		case LWS_CONNMODE_WS_CLIENT:
			for (n = 0; n < len; n++)
				if (libwebsocket_client_rx_sm(wsi, *buf++) < 0) {
					lwsl_info("client rx has bailed\n");
					goto bail;
				}

			return 0;
		default:
			break;
		}
#endif
#ifndef LWS_NO_SERVER
		/* LWS_CONNMODE_WS_SERVING */

		if (libwebsocket_interpret_incoming_packet(wsi, buf, len) < 0) {
			lwsl_info("interpret_incoming_packet has bailed\n");
			goto bail;
		}
#endif
		break;
	default:
		lwsl_err("libwebsocket_read: Unhandled state\n");
		break;
	}

	return 0;

bail:
	lwsl_info("closing connection at libwebsocket_read bail:\n");
	libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);

	return -1;
}
