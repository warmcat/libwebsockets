/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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
 *
 * Returns <0 for error or length of chars consumed from buf (up to len)
 */

int
lws_read_h1(struct lws *wsi, unsigned char *buf, lws_filepos_t len)
{
	unsigned char *last_char, *oldbuf = buf;
	lws_filepos_t body_chunk_len;
	size_t n;

	// lwsl_notice("%s: h1 path: wsi state 0x%x\n", __func__, lwsi_state(wsi));

	switch (lwsi_state(wsi)) {

	case LRS_ISSUING_FILE:
		return 0;

	case LRS_ESTABLISHED:

		if (lwsi_role_non_ws_client(wsi))
			break;

		if (lwsi_role_ws(wsi))
			goto ws_mode;

		wsi->hdr_parsing_completed = 0;

		/* fallthru */

	case LRS_HEADERS:
		if (!wsi->ah) {
			lwsl_err("%s: LRS_HEADERS: NULL ah\n", __func__);
			assert(0);
		}
		lwsl_parser("issuing %d bytes to parser\n", (int)len);

		if (lws_handshake_client(wsi, &buf, (size_t)len))
			goto bail;

		last_char = buf;
		if (lws_handshake_server(wsi, &buf, (size_t)len))
			/* Handshake indicates this session is done. */
			goto bail;

		/* we might have transitioned to RAW */
		if (lwsi_role_raw(wsi))
			 /* we gave the read buffer to RAW handler already */
			goto read_ok;

		/*
		 * It's possible that we've exhausted our data already, or
		 * rx flow control has stopped us dealing with this early,
		 * but lws_handshake_server doesn't update len for us.
		 * Figure out how much was read, so that we can proceed
		 * appropriately:
		 */
		len -= (buf - last_char);
//		lwsl_debug("%s: thinks we have used %ld\n", __func__, (long)len);

		if (!wsi->hdr_parsing_completed)
			/* More header content on the way */
			goto read_ok;

		switch (lwsi_state(wsi)) {
			case LRS_ESTABLISHED:
			case LRS_HEADERS:
				goto read_ok;
			case LRS_ISSUING_FILE:
				goto read_ok;
			case LRS_BODY:
				wsi->http.rx_content_remain =
						wsi->http.rx_content_length;
				if (wsi->http.rx_content_remain)
					goto http_postbody;

				/* there is no POST content */
				goto postbody_completion;
			default:
				break;
		}
		break;

	case LRS_BODY:
http_postbody:
		//lwsl_notice("http post body\n");
		while (len && wsi->http.rx_content_remain) {
			/* Copy as much as possible, up to the limit of:
			 * what we have in the read buffer (len)
			 * remaining portion of the POST body (content_remain)
			 */
			body_chunk_len = min(wsi->http.rx_content_remain, len);
			wsi->http.rx_content_remain -= body_chunk_len;
			len -= body_chunk_len;
#ifdef LWS_WITH_CGI
			if (wsi->cgi) {
				struct lws_cgi_args args;

				args.ch = LWS_STDIN;
				args.stdwsi = &wsi->cgi->stdwsi[0];
				args.data = buf;
				args.len = body_chunk_len;

				/* returns how much used */
				n = user_callback_handle_rxflow(
					wsi->protocol->callback,
					wsi, LWS_CALLBACK_CGI_STDIN_DATA,
					wsi->user_space,
					(void *)&args, 0);
				if ((int)n < 0)
					goto bail;
			} else {
#endif
				n = wsi->protocol->callback(wsi,
					LWS_CALLBACK_HTTP_BODY, wsi->user_space,
					buf, (size_t)body_chunk_len);
				if (n)
					goto bail;
				n = (size_t)body_chunk_len;
#ifdef LWS_WITH_CGI
			}
#endif
			buf += n;

			if (wsi->http.rx_content_remain)  {
				lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
						wsi->context->timeout_secs);
				break;
			}
			/* he sent all the content in time */
postbody_completion:
#ifdef LWS_WITH_CGI
			/*
			 * If we're running a cgi, we can't let him off the
			 * hook just because he sent his POST data
			 */
			if (wsi->cgi)
				lws_set_timeout(wsi, PENDING_TIMEOUT_CGI,
						wsi->context->timeout_secs);
			else
#endif
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
#ifdef LWS_WITH_CGI
			if (!wsi->cgi)
#endif
			{
				lwsl_info("HTTP_BODY_COMPLETION\n");
				n = wsi->protocol->callback(wsi,
					LWS_CALLBACK_HTTP_BODY_COMPLETION,
					wsi->user_space, NULL, 0);
				if (n)
					goto bail;

				if (wsi->http2_substream)
					lwsi_set_state(wsi, LRS_ESTABLISHED);
			}

			break;
		}
		break;

	case LRS_AWAITING_CLOSE_ACK:
	case LRS_WAITING_TO_SEND_CLOSE:
	case LRS_SHUTDOWN:

ws_mode:

		if (lws_handshake_client(wsi, &buf, (size_t)len))
			goto bail;

		switch (lwsi_role(wsi)) {
		case LWSI_ROLE_WS1_SERVER:
		case LWSI_ROLE_WS2_SERVER:
			/*
			 * for h2 we are on the swsi
			 */
			if (lws_interpret_incoming_packet(wsi, &buf,
							  (size_t)len) < 0) {
				lwsl_info("interpret_incoming_packet bailed\n");
				goto bail;
			}
			break;
		}
		break;

	case LRS_DEFERRING_ACTION:
		lwsl_debug("%s: LRS_DEFERRING_ACTION\n", __func__);
		break;

	case LRS_SSL_ACK_PENDING:
		break;

	case LRS_DEAD_SOCKET:
		lwsl_err("%s: Unhandled state LRS_DEAD_SOCKET\n", __func__);
		assert(0);
		/* fallthru */

	default:
		lwsl_err("%s: Unhandled state %d\n", __func__, lwsi_state(wsi));
		goto bail;
	}

read_ok:
	/* Nothing more to do for now */
//	lwsl_info("%s: %p: read_ok, used %ld (len %d, state %d)\n", __func__,
//		  wsi, (long)(buf - oldbuf), (int)len, wsi->state);

	return lws_ptr_diff(buf, oldbuf);

bail:
	/*
	 * h2 / h2-ws calls us recursively in lws_read()->lws_h2_parser()->
	 * lws_read() pattern, having stripped the h2 framing in the middle.
	 *
	 * When taking down the whole connection, make sure that only the
	 * outer lws_read() does the wsi close.
	 */
	if (!wsi->outer_will_close)
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "lws_read bail");

	return -1;
}
