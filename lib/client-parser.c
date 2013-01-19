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
#include <io.h>
#endif

int libwebsocket_client_rx_sm(struct libwebsocket *wsi, unsigned char c)
{
	int n;
	unsigned char buf[20 + 4];
	int callback_action = LWS_CALLBACK_CLIENT_RECEIVE;
	int handled;
	struct lws_tokens eff_buf;
	int m;

//	lwsl_parser(" CRX: %02X %d\n", c, wsi->lws_rx_parse_state);

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:

		switch (wsi->ietf_spec_revision) {
		/* Firefox 4.0b6 likes this as of 30 Oct */
		case 0:
			if (c == 0xff)
				wsi->lws_rx_parse_state = LWS_RXPS_SEEN_76_FF;
			if (c == 0) {
				wsi->lws_rx_parse_state =
						       LWS_RXPS_EAT_UNTIL_76_FF;
				wsi->rx_user_buffer_head = 0;
			}
			break;
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 13:
	/*
	 *  04 logical framing from the spec (all this is masked when
	 *  incoming and has to be unmasked)
	 *
	 * We ignore the possibility of extension data because we don't
	 * negotiate any extensions at the moment.
	 *
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-------+-+-------------+-------------------------------+
	 *   |F|R|R|R| opcode|R| Payload len |    Extended payload length    |
	 *   |I|S|S|S|  (4)  |S|     (7)     |             (16/63)           |
	 *   |N|V|V|V|       |V|             |   (if payload len==126/127)   |
	 *   | |1|2|3|       |4|             |                               |
	 *   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	 *   |     Extended payload length continued, if payload len == 127  |
	 *   + - - - - - - - - - - - - - - - +-------------------------------+
	 *   |                               |         Extension data        |
	 *   +-------------------------------+ - - - - - - - - - - - - - - - +
	 *   :                                                               :
	 *   +---------------------------------------------------------------+
	 *   :                       Application data                        :
	 *   +---------------------------------------------------------------+
	 *
	 *  We pass payload through to userland as soon as we get it, ignoring
	 *  FIN.  It's up to userland to buffer it up if it wants to see a
	 *  whole unfragmented block of the original size (which may be up to
	 *  2^63 long!)
	 *
	 *  Notice in v7 RSV4 is set to indicate 32-bit frame key is coming in
	 *  after length, unlike extension data which is now deprecated, this
	 *  does not impact the payload length calculation.
	 */

		/*
		 * 04 spec defines the opcode like this: (1, 2, and 3 are
		 * "control frame" opcodes which may not be fragmented or
		 * have size larger than 126)
		 *
		 *       frame-opcode           =
		 *		  %x0 ; continuation frame
		 *		/ %x1 ; connection close
		 *		/ %x2 ; ping
		 *		/ %x3 ; pong
		 *		/ %x4 ; text frame
		 *		/ %x5 ; binary frame
		 *		/ %x6-F ; reserved
		 *
		 *		FIN (b7)
		 */

			if (wsi->ietf_spec_revision < 7)
				switch (c & 0xf) {
				case LWS_WS_OPCODE_04__CONTINUATION:
					wsi->opcode =
						LWS_WS_OPCODE_07__CONTINUATION;
					break;
				case LWS_WS_OPCODE_04__CLOSE:
					wsi->opcode = LWS_WS_OPCODE_07__CLOSE;
					break;
				case LWS_WS_OPCODE_04__PING:
					wsi->opcode = LWS_WS_OPCODE_07__PING;
					break;
				case LWS_WS_OPCODE_04__PONG:
					wsi->opcode = LWS_WS_OPCODE_07__PONG;
					break;
				case LWS_WS_OPCODE_04__TEXT_FRAME:
					wsi->opcode =
						  LWS_WS_OPCODE_07__TEXT_FRAME;
					break;
				case LWS_WS_OPCODE_04__BINARY_FRAME:
					wsi->opcode =
						LWS_WS_OPCODE_07__BINARY_FRAME;
					break;
				default:
					lwsl_warn("reserved opcodes not "
						   "usable pre v7 protocol\n");
					return -1;
				}
			else
				wsi->opcode = c & 0xf;
			wsi->rsv = (c & 0x70);
			wsi->final = !!((c >> 7) & 1);
			switch (wsi->opcode) {
			case LWS_WS_OPCODE_07__TEXT_FRAME:
			case LWS_WS_OPCODE_07__BINARY_FRAME:
				wsi->frame_is_binary = wsi->opcode == LWS_WS_OPCODE_07__BINARY_FRAME;
				break;
			}
			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
			break;

		default:
			lwsl_err("client_rx_sm doesn't know how "
				"to handle spec version %02d\n",
						       wsi->ietf_spec_revision);
			break;
		}
		break;


	case LWS_RXPS_04_FRAME_HDR_LEN:

		if ((c & 0x80) && wsi->ietf_spec_revision < 7) {
			lwsl_warn("Frame has extensions set illegally 4\n");
			/* kill the connection */
			return -1;
		}

		wsi->this_frame_masked = !!(c & 0x80);

		switch (c & 0x7f) {
		case 126:
			/* control frames are not allowed to have big lengths */
			if (wsi->opcode & 8)
				goto illegal_ctl_length;
			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
			break;
		case 127:
			/* control frames are not allowed to have big lengths */
			if (wsi->opcode & 8)
				goto illegal_ctl_length;
			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
			break;
		default:
			wsi->rx_packet_length = c;
			if (wsi->this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else {
				if (c)
					wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
				else {
					wsi->lws_rx_parse_state = LWS_RXPS_NEW;
					goto spill;
				}
			}
			break;
		}
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_2:
		wsi->rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		wsi->rx_packet_length |= c;
		if (wsi->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else {
			if (wsi->rx_packet_length)
				wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
			else {
				wsi->lws_rx_parse_state = LWS_RXPS_NEW;
				goto spill;
			}
		}
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_8:
		if (c & 0x80) {
			lwsl_warn("b63 of length must be zero\n");
			/* kill the connection */
			return -1;
		}
#if defined __LP64__
		wsi->rx_packet_length = ((size_t)c) << 56;
#else
		wsi->rx_packet_length = 0;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
		wsi->rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
		wsi->rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
		wsi->rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		wsi->rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		wsi->rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		wsi->rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		wsi->rx_packet_length |= (size_t)c;
		if (wsi->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else {
			if (wsi->rx_packet_length)
				wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
			else {
				wsi->lws_rx_parse_state = LWS_RXPS_NEW;
				goto spill;
			}
		}
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
		wsi->frame_masking_nonce_04[0] = c;
		if (c)
			wsi->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
		wsi->frame_masking_nonce_04[1] = c;
		if (c)
			wsi->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
		wsi->frame_masking_nonce_04[2] = c;
		if (c)
			wsi->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
		wsi->frame_masking_nonce_04[3] = c;
		if (c)
			wsi->all_zero_nonce = 0;

		if (wsi->rx_packet_length)
			wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		else {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		break;

	case LWS_RXPS_EAT_UNTIL_76_FF:
		if (c == 0xff) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto issue;
		}
		wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
					      (wsi->rx_user_buffer_head++)] = c;

		if (wsi->rx_user_buffer_head != MAX_USER_RX_BUFFER)
			break;
issue:
		if (wsi->protocol->callback)
			wsi->protocol->callback(wsi->protocol->owning_server,
						wsi,
						LWS_CALLBACK_CLIENT_RECEIVE,
						wsi->user_space,
			  &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
						      wsi->rx_user_buffer_head);
		wsi->rx_user_buffer_head = 0;
		break;
	case LWS_RXPS_SEEN_76_FF:
		if (c)
			break;

		lwsl_parser("Seen that client is requesting "
				"a v76 close, sending ack\n");
		buf[0] = 0xff;
		buf[1] = 0;
		n = libwebsocket_write(wsi, buf, 2, LWS_WRITE_HTTP);
		if (n < 0) {
			lwsl_warn("LWS_RXPS_SEEN_76_FF: ERROR writing to socket\n");
			return -1;
		}
		lwsl_parser("  v76 close ack sent, server closing skt\n");
		/* returning < 0 will get it closed in parent */
		return -1;

	case LWS_RXPS_PULLING_76_LENGTH:
		break;

	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:
		if ((!wsi->this_frame_masked) || wsi->all_zero_nonce)
			wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->rx_user_buffer_head++)] = c;
		else
			wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->rx_user_buffer_head++)] =
							  wsi->xor_mask(wsi, c);

		if (--wsi->rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		if (wsi->rx_user_buffer_head != MAX_USER_RX_BUFFER)
			break;
spill:

		handled = 0;

		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		switch (wsi->opcode) {
		case LWS_WS_OPCODE_07__CLOSE:
			/* is this an acknowledgement of our close? */
			if (wsi->state == WSI_STATE_AWAITING_CLOSE_ACK) {
				/*
				 * fine he has told us he is closing too, let's
				 * finish our close
				 */
				lwsl_parser("seen server's close ack\n");
				return -1;
			}
			lwsl_parser("client sees server close packet len = %d\n", wsi->rx_user_buffer_head);
			/* parrot the close packet payload back */
			n = libwebsocket_write(wsi, (unsigned char *)
			   &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				     wsi->rx_user_buffer_head, LWS_WRITE_CLOSE);
			lwsl_parser("client writing close ack returned %d\n", n);
			wsi->state = WSI_STATE_RETURNED_CLOSE_ALREADY;
			/* close the connection */
			return -1;

		case LWS_WS_OPCODE_07__PING:
			lwsl_info("client received ping, doing pong\n");
			/* parrot the ping packet payload back as a pong*/
			n = libwebsocket_write(wsi, (unsigned char *)
			    &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				    wsi->rx_user_buffer_head, LWS_WRITE_PONG);
			handled = 1;
			break;

		case LWS_WS_OPCODE_07__PONG:
			lwsl_info("client receied pong\n");
			lwsl_hexdump(&wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				    wsi->rx_user_buffer_head);
			/* keep the statistics... */
			wsi->pings_vs_pongs--;

			/* issue it */
			callback_action = LWS_CALLBACK_CLIENT_RECEIVE_PONG;
			break;

		case LWS_WS_OPCODE_07__CONTINUATION:
		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
			break;

		default:

			lwsl_parser("Reserved opcode 0x%2X\n", wsi->opcode);
			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->rx_user_buffer[
						   LWS_SEND_BUFFER_PRE_PADDING];
			eff_buf.token_len = wsi->rx_user_buffer_head;

			for (n = 0; n < wsi->count_active_extensions; n++) {
				m = wsi->active_extensions[n]->callback(
					wsi->protocol->owning_server,
					wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_EXTENDED_PAYLOAD_RX,
					    wsi->active_extensions_user[n],
								   &eff_buf, 0);
				if (m)
					handled = 1;
			}

			if (!handled) {
				lwsl_ext("Unhandled extended opcode "
					"0x%x - ignoring frame\n", wsi->opcode);
				wsi->rx_user_buffer_head = 0;

				return 0;
			}

			break;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using libwebsocket_write
		 */
		if (handled)
			goto already_done;

		eff_buf.token = &wsi->rx_user_buffer[
						LWS_SEND_BUFFER_PRE_PADDING];
		eff_buf.token_len = wsi->rx_user_buffer_head;

		for (n = 0; n < wsi->count_active_extensions; n++) {
			m = wsi->active_extensions[n]->callback(
				wsi->protocol->owning_server,
				wsi->active_extensions[n], wsi,
				LWS_EXT_CALLBACK_PAYLOAD_RX,
				wsi->active_extensions_user[n],
				&eff_buf, 0);
			if (m < 0) {
				lwsl_ext(
					"Extension '%s' failed to handle payload!\n",
						wsi->active_extensions[n]->name);
				return -1;
			}
		}

		if (eff_buf.token_len > 0) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback) {
				if (callback_action == LWS_CALLBACK_CLIENT_RECEIVE_PONG)
					lwsl_info("Client doing pong callback\n");
				wsi->protocol->callback(
						wsi->protocol->owning_server,
						wsi,
			(enum libwebsocket_callback_reasons)callback_action,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
			}
		}
already_done:
		wsi->rx_user_buffer_head = 0;
		break;
	default:
		lwsl_err("client rx illegal state\n");
		return 1;
	}

	return 0;

illegal_ctl_length:

	lwsl_warn("Control frame asking for "
				"extended length is illegal\n");
	/* kill the connection */
	return -1;

}


