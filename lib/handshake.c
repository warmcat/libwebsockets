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

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
/*
 * We have to take care about parsing because the headers may be split
 * into multiple fragments.  They may contain unknown headers with arbitrary
 * argument lengths.  So, we parse using a single-character at a time state
 * machine that is completely independent of packet size.
 */

LWS_VISIBLE int
libwebsocket_read(struct libwebsocket_context *context,
		     struct libwebsocket *wsi, unsigned char *buf, size_t len)
{
	size_t n;
	int body_chunk_len;
	unsigned char *last_char;

	switch (wsi->state) {
#ifdef LWS_USE_HTTP2
	case WSI_STATE_HTTP2_AWAIT_CLIENT_PREFACE:
	case WSI_STATE_HTTP2_ESTABLISHED_PRE_SETTINGS:
	case WSI_STATE_HTTP2_ESTABLISHED:
		n = 0;
		while (n < len) {
			/*
			 * we were accepting input but now we stopped doing so
			 */
			if (!(wsi->rxflow_change_to & LWS_RXFLOW_ALLOW)) {
				lws_rxflow_cache(wsi, buf, n, len);

				return 1;
			}

			/* account for what we're using in rxflow buffer */
			if (wsi->rxflow_buffer)
				wsi->rxflow_pos++;
			if (lws_http2_parser(context, wsi, buf[n++]))
				goto bail;
		}
		break;
#endif
http_new:
	case WSI_STATE_HTTP:
		wsi->hdr_parsing_completed = 0;
		/* fallthru */
	case WSI_STATE_HTTP_ISSUING_FILE:
		wsi->state = WSI_STATE_HTTP_HEADERS;
		wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
		wsi->u.hdr.lextable_pos = 0;
		/* fallthru */
	case WSI_STATE_HTTP_HEADERS:
		lwsl_parser("issuing %d bytes to parser\n", (int)len);

		if (lws_handshake_client(wsi, &buf, len))
			goto bail;

		last_char = buf;
		if (lws_handshake_server(context, wsi, &buf, len))
			/* Handshake indicates this session is done. */
			goto bail;

		/* It's possible that we've exhausted our data already, but
		 * lws_handshake_server doesn't update len for us. Figure out how
		 * much was read, so that we can proceed appropriately: */
		len -= (buf - last_char);

		if (!wsi->hdr_parsing_completed)
			/* More header content on the way */
			goto read_ok;

		switch (wsi->state) {
			case WSI_STATE_HTTP:
			case WSI_STATE_HTTP_HEADERS:
				goto http_complete;
			case WSI_STATE_HTTP_ISSUING_FILE:
				goto read_ok;
			case WSI_STATE_HTTP_BODY:
				wsi->u.http.content_remain = wsi->u.http.content_length;
				goto http_postbody;
			default:
				break;
		}
		break;

	case WSI_STATE_HTTP_BODY:
http_postbody:
		while (len && wsi->u.http.content_remain) {
			/* Copy as much as possible, up to the limit of:
			 * what we have in the read buffer (len)
			 * remaining portion of the POST body (content_remain)
			 */
			body_chunk_len = min(wsi->u.http.content_remain,len);
			wsi->u.http.content_remain -= body_chunk_len;
			len -= body_chunk_len;

			if (wsi->protocol->callback) {
				n = wsi->protocol->callback(
					wsi->protocol->owning_server, wsi,
					LWS_CALLBACK_HTTP_BODY, wsi->user_space,
					buf, body_chunk_len);
				if (n)
					goto bail;
			}
			buf += body_chunk_len;

			if (!wsi->u.http.content_remain)  {
				/* he sent the content in time */
				libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
				if (wsi->protocol->callback) {
					n = wsi->protocol->callback(
						wsi->protocol->owning_server, wsi,
						LWS_CALLBACK_HTTP_BODY_COMPLETION,
						wsi->user_space, NULL, 0);
					if (n)
						goto bail;
				}
				goto http_complete;
			} else
				libwebsocket_set_timeout(wsi,
					PENDING_TIMEOUT_HTTP_CONTENT,
					AWAITING_TIMEOUT);
		}
		break;

	case WSI_STATE_ESTABLISHED:
	case WSI_STATE_AWAITING_CLOSE_ACK:
		if (lws_handshake_client(wsi, &buf, len))
			goto bail;
		switch (wsi->mode) {
		case LWS_CONNMODE_WS_SERVING:

			if (libwebsocket_interpret_incoming_packet(wsi, buf, len) < 0) {
				lwsl_info("interpret_incoming_packet has bailed\n");
				goto bail;
			}
			break;
		}
		break;
	default:
		lwsl_err("libwebsocket_read: Unhandled state\n");
		break;
	}

read_ok:
	/* Nothing more to do for now. */
	lwsl_debug("libwebsocket_read: read_ok\n");

	return 0;

http_complete:
	lwsl_debug("libwebsocket_read: http_complete\n");

	/* Did the client want to keep the HTTP connection going? */

	if (wsi->u.http.connection_type == HTTP_CONNECTION_KEEP_ALIVE) {
		lwsl_debug("libwebsocket_read: keep-alive\n");
		wsi->state = WSI_STATE_HTTP;
		wsi->mode = LWS_CONNMODE_HTTP_SERVING;

		/* He asked for it to stay alive indefinitely */
		libwebsocket_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		if (lws_allocate_header_table(wsi))
			goto bail;

		/* If we're (re)starting on headers, need other implied init */
		wsi->u.hdr.ues = URIES_IDLE;

		/* If we have more data, loop back around: */
		if (len)
			goto http_new;

		return 0;
	}

bail:
	lwsl_debug("closing connection at libwebsocket_read bail:\n");

	libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);

	return -1;
}
