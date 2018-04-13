/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#include <private-libwebsockets.h>

#define LWS_CPYAPP(ptr, str) { strcpy(ptr, str); ptr += strlen(str); }

/*
 * client-parser.c: lws_client_rx_sm() needs to be roughly kept in
 *   sync with changes here, esp related to ext draining
 */

int
lws_ws_rx_sm(struct lws *wsi, unsigned char c)
{
	int callback_action = LWS_CALLBACK_RECEIVE;
	int ret = 0, rx_draining_ext = 0;
	struct lws_tokens eff_buf;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	int n;
#endif

	eff_buf.token = NULL;
	eff_buf.token_len = 0;
	if (wsi->socket_is_permanently_unusable)
		return -1;

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:
		if (wsi->ws->rx_draining_ext) {
			eff_buf.token = NULL;
			eff_buf.token_len = 0;
			lws_remove_wsi_from_draining_ext_list(wsi);
			rx_draining_ext = 1;
			lwsl_debug("%s: doing draining flow\n", __func__);

			goto drain_extension;
		}
		switch (wsi->ws->ietf_spec_revision) {
		case 13:
			/*
			 * no prepended frame key any more
			 */
			wsi->ws->all_zero_nonce = 1;
			goto handle_first;

		default:
			lwsl_warn("lws_ws_rx_sm: unknown spec version %d\n",
				  wsi->ws->ietf_spec_revision);
			break;
		}
		break;
	case LWS_RXPS_04_mask_1:
		wsi->ws->mask[1] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_mask_2;
		break;
	case LWS_RXPS_04_mask_2:
		wsi->ws->mask[2] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_mask_3;
		break;
	case LWS_RXPS_04_mask_3:
		wsi->ws->mask[3] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;

		/*
		 * start from the zero'th byte in the XOR key buffer since
		 * this is the start of a frame with a new key
		 */

		wsi->ws->mask_idx = 0;

		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_1;
		break;

	/*
	 *  04 logical framing from the spec (all this is masked when incoming
	 *  and has to be unmasked)
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
	 */

	case LWS_RXPS_04_FRAME_HDR_1:
handle_first:

		wsi->ws->opcode = c & 0xf;
		wsi->ws->rsv = c & 0x70;
		wsi->ws->final = !!((c >> 7) & 1);

		switch (wsi->ws->opcode) {
		case LWSWSOPC_TEXT_FRAME:
		case LWSWSOPC_BINARY_FRAME:
			wsi->ws->rsv_first_msg = (c & 0x70);
			wsi->ws->frame_is_binary =
			     wsi->ws->opcode == LWSWSOPC_BINARY_FRAME;
			wsi->ws->first_fragment = 1;
			break;
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 0xb:
		case 0xc:
		case 0xd:
		case 0xe:
		case 0xf:
			lwsl_info("illegal opcode\n");
			return -1;
		}
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN:

		wsi->ws->this_frame_masked = !!(c & 0x80);

		switch (c & 0x7f) {
		case 126:
			/* control frames are not allowed to have big lengths */
			if (wsi->ws->opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
			break;
		case 127:
			/* control frames are not allowed to have big lengths */
			if (wsi->ws->opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
			break;
		default:
			wsi->ws->rx_packet_length = c & 0x7f;
			if (wsi->ws->this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else
				if (wsi->ws->rx_packet_length)
					wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
				else {
					wsi->lws_rx_parse_state = LWS_RXPS_NEW;
					goto spill;
				}
			break;
		}
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_2:
		wsi->ws->rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		wsi->ws->rx_packet_length |= c;
		if (wsi->ws->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_8:
		if (c & 0x80) {
			lwsl_warn("b63 of length must be zero\n");
			/* kill the connection */
			return -1;
		}
#if defined __LP64__
		wsi->ws->rx_packet_length = ((size_t)c) << 56;
#else
		wsi->ws->rx_packet_length = 0;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
		wsi->ws->rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
		wsi->ws->rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
		wsi->ws->rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		wsi->ws->rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		wsi->ws->rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		wsi->ws->rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		wsi->ws->rx_packet_length |= ((size_t)c);
		if (wsi->ws->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
		wsi->ws->mask[0] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
		wsi->ws->mask[1] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
		wsi->ws->mask[2] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
		wsi->ws->mask[3] = c;
		if (c)
			wsi->ws->all_zero_nonce = 0;
		wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		wsi->ws->mask_idx = 0;
		if (wsi->ws->rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:
		assert(wsi->ws->rx_ubuf);

		if (wsi->ws->rx_draining_ext)
			goto drain_extension;

		if (wsi->ws->rx_ubuf_head + LWS_PRE >=
		    wsi->ws->rx_ubuf_alloc) {
			lwsl_err("Attempted overflow \n");
			return -1;
		}
		if (wsi->ws->all_zero_nonce)
			wsi->ws->rx_ubuf[LWS_PRE +
					 (wsi->ws->rx_ubuf_head++)] = c;
		else
			wsi->ws->rx_ubuf[LWS_PRE +
			       (wsi->ws->rx_ubuf_head++)] =
				   c ^ wsi->ws->mask[
					    (wsi->ws->mask_idx++) & 3];

		if (--wsi->ws->rx_packet_length == 0) {
			/* spill because we have the whole frame */
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}

		/*
		 * if there's no protocol max frame size given, we are
		 * supposed to default to context->pt_serv_buf_size
		 */
		if (!wsi->protocol->rx_buffer_size &&
		    wsi->ws->rx_ubuf_head != wsi->context->pt_serv_buf_size)
			break;

		if (wsi->protocol->rx_buffer_size &&
		    wsi->ws->rx_ubuf_head != wsi->protocol->rx_buffer_size)
			break;

		/* spill because we filled our rx buffer */
spill:
		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		lwsl_parser("spill on %s\n", wsi->protocol->name);

		switch (wsi->ws->opcode) {
		case LWSWSOPC_CLOSE:

			/* is this an acknowledgment of our close? */
			if (lwsi_state(wsi) == LRS_AWAITING_CLOSE_ACK) {
				/*
				 * fine he has told us he is closing too, let's
				 * finish our close
				 */
				lwsl_parser("seen client close ack\n");
				return -1;
			}
			if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
				/* if he sends us 2 CLOSE, kill him */
				return -1;

			if (lws_partial_buffered(wsi)) {
				/*
				 * if we're in the middle of something,
				 * we can't do a normal close response and
				 * have to just close our end.
				 */
				wsi->socket_is_permanently_unusable = 1;
				lwsl_parser("Closing on peer close due to Pending tx\n");
				return -1;
			}

			if (user_callback_handle_rxflow(
					wsi->protocol->callback, wsi,
					LWS_CALLBACK_WS_PEER_INITIATED_CLOSE,
					wsi->user_space,
					&wsi->ws->rx_ubuf[LWS_PRE],
					wsi->ws->rx_ubuf_head))
				return -1;

			lwsl_parser("server sees client close packet\n");
			lwsi_set_state(wsi, LRS_RETURNED_CLOSE);
			/* deal with the close packet contents as a PONG */
			wsi->ws->payload_is_close = 1;
			goto process_as_ping;

		case LWSWSOPC_PING:
			lwsl_info("received %d byte ping, sending pong\n",
						 wsi->ws->rx_ubuf_head);

			if (wsi->ws->ping_pending_flag) {
				/*
				 * there is already a pending ping payload
				 * we should just log and drop
				 */
				lwsl_parser("DROP PING since one pending\n");
				goto ping_drop;
			}
process_as_ping:
			/* control packets can only be < 128 bytes long */
			if (wsi->ws->rx_ubuf_head > 128 - 3) {
				lwsl_parser("DROP PING payload too large\n");
				goto ping_drop;
			}

			/* stash the pong payload */
			memcpy(wsi->ws->ping_payload_buf + LWS_PRE,
			       &wsi->ws->rx_ubuf[LWS_PRE],
				wsi->ws->rx_ubuf_head);

			wsi->ws->ping_payload_len = wsi->ws->rx_ubuf_head;
			wsi->ws->ping_pending_flag = 1;

			/* get it sent as soon as possible */
			lws_callback_on_writable(wsi);
ping_drop:
			wsi->ws->rx_ubuf_head = 0;
			return 0;

		case LWSWSOPC_PONG:
			lwsl_info("received pong\n");
			lwsl_hexdump(&wsi->ws->rx_ubuf[LWS_PRE],
			             wsi->ws->rx_ubuf_head);

			if (wsi->pending_timeout ==
				       PENDING_TIMEOUT_WS_PONG_CHECK_GET_PONG) {
				lwsl_info("received expected PONG on wsi %p\n",
						wsi);
				lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
			}

			/* issue it */
			callback_action = LWS_CALLBACK_RECEIVE_PONG;
			break;

		case LWSWSOPC_TEXT_FRAME:
		case LWSWSOPC_BINARY_FRAME:
		case LWSWSOPC_CONTINUATION:
			break;

		default:
			lwsl_parser("passing opc %x up to exts\n",
				    wsi->ws->opcode);
			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->ws->rx_ubuf[LWS_PRE];
			eff_buf.token_len = wsi->ws->rx_ubuf_head;

			if (lws_ext_cb_active(wsi,
					      LWS_EXT_CB_EXTENDED_PAYLOAD_RX,
					      &eff_buf, 0) <= 0)
				/* not handle or fail */
				lwsl_ext("ext opc opcode 0x%x unknown\n",
					 wsi->ws->opcode);

			wsi->ws->rx_ubuf_head = 0;
			return 0;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using lws_write
		 */

		eff_buf.token = &wsi->ws->rx_ubuf[LWS_PRE];
		eff_buf.token_len = wsi->ws->rx_ubuf_head;

		if (wsi->ws->opcode == LWSWSOPC_PONG && !eff_buf.token_len)
			goto already_done;

drain_extension:
		lwsl_ext("%s: passing %d to ext\n", __func__, eff_buf.token_len);

		if (lwsi_state(wsi) == LRS_RETURNED_CLOSE ||
		    lwsi_state(wsi) == LRS_AWAITING_CLOSE_ACK)
			goto already_done;
#if !defined(LWS_WITHOUT_EXTENSIONS)
		n = lws_ext_cb_active(wsi, LWS_EXT_CB_PAYLOAD_RX, &eff_buf, 0);
#endif
		/*
		 * eff_buf may be pointing somewhere completely different now,
		 * it's the output
		 */
		wsi->ws->first_fragment = 0;
#if !defined(LWS_WITHOUT_EXTENSIONS)
		if (n < 0) {
			/*
			 * we may rely on this to get RX, just drop connection
			 */
			wsi->socket_is_permanently_unusable = 1;
			return -1;
		}
#endif
		if (rx_draining_ext && eff_buf.token_len == 0)
			goto already_done;

		if (
#if !defined(LWS_WITHOUT_EXTENSIONS)
		    n &&
#endif
		    eff_buf.token_len)
			/* extension had more... main loop will come back */
			lws_add_wsi_to_draining_ext_list(wsi);
		else
			lws_remove_wsi_from_draining_ext_list(wsi);

		if (eff_buf.token_len > 0 ||
		    callback_action == LWS_CALLBACK_RECEIVE_PONG) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback) {
				if (callback_action == LWS_CALLBACK_RECEIVE_PONG)
					lwsl_info("Doing pong callback\n");

				ret = user_callback_handle_rxflow(
						wsi->protocol->callback,
						wsi, (enum lws_callback_reasons)
						     callback_action,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
			}
			else
				lwsl_err("No callback on payload spill!\n");
		}

already_done:
		wsi->ws->rx_ubuf_head = 0;
		break;
	}

	return ret;

illegal_ctl_length:

	lwsl_warn("Control frame with xtended length is illegal\n");
	/* kill the connection */
	return -1;
}


LWS_VISIBLE size_t
lws_remaining_packet_payload(struct lws *wsi)
{
	return wsi->ws->rx_packet_length;
}

LWS_VISIBLE int lws_frame_is_binary(struct lws *wsi)
{
	return wsi->ws->frame_is_binary;
}

void
lws_add_wsi_to_draining_ext_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (wsi->ws->rx_draining_ext)
		return;

	lwsl_ext("%s: RX EXT DRAINING: Adding to list\n", __func__);

	wsi->ws->rx_draining_ext = 1;
	wsi->ws->rx_draining_ext_list = pt->rx_draining_ext_list;
	pt->rx_draining_ext_list = wsi;
}

void
lws_remove_wsi_from_draining_ext_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws **w = &pt->rx_draining_ext_list;

	if (!wsi->ws->rx_draining_ext)
		return;

	lwsl_ext("%s: RX EXT DRAINING: Removing from list\n", __func__);

	wsi->ws->rx_draining_ext = 0;

	/* remove us from context draining ext list */
	while (*w) {
		if (*w == wsi) {
			/* if us, point it instead to who we were pointing to */
			*w = wsi->ws->rx_draining_ext_list;
			break;
		}
		w = &((*w)->ws->rx_draining_ext_list);
	}
	wsi->ws->rx_draining_ext_list = NULL;
}

LWS_EXTERN void
lws_restart_ws_ping_pong_timer(struct lws *wsi)
{
	if (!wsi->context->ws_ping_pong_interval ||
	    !lwsi_role_ws(wsi))
		return;

	wsi->ws->time_next_ping_check = (time_t)lws_now_secs();
}

static int
lws_0405_frame_mask_generate(struct lws *wsi)
{
	int n;
	/* fetch the per-frame nonce */

	n = lws_get_random(lws_get_context(wsi), wsi->ws->mask, 4);
	if (n != 4) {
		lwsl_parser("Unable to read from random device %s %d\n",
			    SYSTEM_RANDOM_FILEPATH, n);
		return 1;
	}

	/* start masking from first byte of masking key buffer */
	wsi->ws->mask_idx = 0;

	return 0;
}

/* Once we reach LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED, we know how much
 * to expect in that state and can deal with it in bulk more efficiently.
 */

int
lws_payload_until_length_exhausted(struct lws *wsi, unsigned char **buf,
				   size_t *len)
{
	unsigned char *buffer = *buf, mask[4];
	int buffer_size, n;
	unsigned int avail;
	char *rx_ubuf;

	if (wsi->protocol->rx_buffer_size)
		buffer_size = (int)wsi->protocol->rx_buffer_size;
	else
		buffer_size = wsi->context->pt_serv_buf_size;
	avail = buffer_size - wsi->ws->rx_ubuf_head;

	/* do not consume more than we should */
	if (avail > wsi->ws->rx_packet_length)
		avail = (unsigned int)wsi->ws->rx_packet_length;

	/* do not consume more than what is in the buffer */
	if (avail > *len)
		avail = (unsigned int)(*len);

	/* we want to leave 1 byte for the parser to handle properly */
	if (avail <= 1)
		return 0;

	avail--;
	rx_ubuf = wsi->ws->rx_ubuf + LWS_PRE + wsi->ws->rx_ubuf_head;
	if (wsi->ws->all_zero_nonce)
		memcpy(rx_ubuf, buffer, avail);
	else {

		for (n = 0; n < 4; n++)
			mask[n] = wsi->ws->mask[(wsi->ws->mask_idx + n) & 3];

		/* deal with 4-byte chunks using unwrapped loop */
		n = avail >> 2;
		while (n--) {
			*(rx_ubuf++) = *(buffer++) ^ mask[0];
			*(rx_ubuf++) = *(buffer++) ^ mask[1];
			*(rx_ubuf++) = *(buffer++) ^ mask[2];
			*(rx_ubuf++) = *(buffer++) ^ mask[3];
		}
		/* and the remaining bytes bytewise */
		for (n = 0; n < (int)(avail & 3); n++)
			*(rx_ubuf++) = *(buffer++) ^ mask[n];

		wsi->ws->mask_idx = (wsi->ws->mask_idx + avail) & 3;
	}

	(*buf) += avail;
	wsi->ws->rx_ubuf_head += avail;
	wsi->ws->rx_packet_length -= avail;
	*len -= avail;

	return avail;
}


int
lws_server_init_wsi_for_ws(struct lws *wsi)
{
	int n;

	lwsi_set_state(wsi, LRS_ESTABLISHED);
	lws_restart_ws_ping_pong_timer(wsi);

	/*
	 * create the frame buffer for this connection according to the
	 * size mentioned in the protocol definition.  If 0 there, use
	 * a big default for compatibility
	 */

	n = (int)wsi->protocol->rx_buffer_size;
	if (!n)
		n = wsi->context->pt_serv_buf_size;
	n += LWS_PRE;
	wsi->ws->rx_ubuf = lws_malloc(n + 4 /* 0x0000ffff zlib */, "rx_ubuf");
	if (!wsi->ws->rx_ubuf) {
		lwsl_err("Out of Mem allocating rx buffer %d\n", n);
		return 1;
	}
	wsi->ws->rx_ubuf_alloc = n;
	lwsl_debug("Allocating RX buffer %d\n", n);

#if !defined(LWS_WITH_ESP32)
	if (!wsi->parent_carries_io &&
	    !wsi->h2_stream_carries_ws)
		if (setsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_SNDBUF,
		       (const char *)&n, sizeof n)) {
			lwsl_warn("Failed to set SNDBUF to %d", n);
			return 1;
		}
#endif

	/* notify user code that we're ready to roll */

	if (wsi->protocol->callback)
		if (wsi->protocol->callback(wsi, LWS_CALLBACK_ESTABLISHED,
					    wsi->user_space,
#ifdef LWS_WITH_TLS
					    wsi->ssl,
#else
					    NULL,
#endif
					    wsi->h2_stream_carries_ws))
			return 1;

	lwsl_debug("ws established\n");

	return 0;
}



LWS_VISIBLE int
lws_is_final_fragment(struct lws *wsi)
{
       lwsl_info("%s: final %d, rx pk length %ld, draining %ld\n", __func__,
			wsi->ws->final, (long)wsi->ws->rx_packet_length,
			(long)wsi->ws->rx_draining_ext);
	return wsi->ws->final && !wsi->ws->rx_packet_length &&
	       !wsi->ws->rx_draining_ext;
}

LWS_VISIBLE int
lws_is_first_fragment(struct lws *wsi)
{
	return wsi->ws->first_fragment;
}

LWS_VISIBLE unsigned char
lws_get_reserved_bits(struct lws *wsi)
{
	return wsi->ws->rsv;
}

LWS_VISIBLE LWS_EXTERN int
lws_get_close_length(struct lws *wsi)
{
	return wsi->ws->close_in_ping_buffer_len;
}

LWS_VISIBLE LWS_EXTERN unsigned char *
lws_get_close_payload(struct lws *wsi)
{
	return &wsi->ws->ping_payload_buf[LWS_PRE];
}

LWS_VISIBLE LWS_EXTERN void
lws_close_reason(struct lws *wsi, enum lws_close_status status,
		 unsigned char *buf, size_t len)
{
	unsigned char *p, *start;
	int budget = sizeof(wsi->ws->ping_payload_buf) - LWS_PRE;

	assert(lwsi_role_ws(wsi));

	start = p = &wsi->ws->ping_payload_buf[LWS_PRE];

	*p++ = (((int)status) >> 8) & 0xff;
	*p++ = ((int)status) & 0xff;

	if (buf)
		while (len-- && p < start + budget)
			*p++ = *buf++;

	wsi->ws->close_in_ping_buffer_len = lws_ptr_diff(p, start);
}

static int
lws_is_ws_with_ext(struct lws *wsi)
{
#if defined(LWS_WITHOUT_EXTENSIONS)
	return 0;
#else
	return lwsi_role_ws(wsi) && !!wsi->count_act_ext;
#endif
}

static int
rops_handle_POLLIN_ws(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_pollfd *pollfd)
{
	struct lws_tokens eff_buf;
	unsigned int pending = 0;
	char draining_flow = 0;
	int n = 0, m;
#if defined(LWS_WITH_HTTP2)
	struct lws *wsi1;
#endif

	// lwsl_notice("%s: %s\n", __func__, wsi->protocol->name);

	lwsl_info("%s: wsistate 0x%x, pollout %d\n", __func__,
		   wsi->wsistate, pollfd->revents & LWS_POLLOUT);

	/*
	 * something went wrong with parsing the handshake, and
	 * we ended up back in the event loop without completing it
	 */
	if (lwsi_state(wsi) == LRS_PRE_WS_SERVING_ACCEPT) {
		wsi->socket_is_permanently_unusable = 1;
		return LWS_HPI_RET_CLOSE_HANDLED;
	}

	if (lwsi_state(wsi) == LRS_WAITING_CONNECT) {
#if !defined(LWS_NO_CLIENT)
		if ((pollfd->revents & LWS_POLLOUT) &&
		    lws_handle_POLLOUT_event(wsi, pollfd)) {
			lwsl_debug("POLLOUT event closed it\n");
			return LWS_HPI_RET_CLOSE_HANDLED;
		}

		n = lws_client_socket_service(wsi, pollfd, NULL);
		if (n)
			return LWS_HPI_RET_DIE;
#endif
		return LWS_HPI_RET_HANDLED;
	}

	/* 1: something requested a callback when it was OK to write */

	if ((pollfd->revents & LWS_POLLOUT) &&
	    lwsi_state_can_handle_POLLOUT(wsi) &&
	    lws_handle_POLLOUT_event(wsi, pollfd)) {
		if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
			lwsi_set_state(wsi, LRS_FLUSHING_BEFORE_CLOSE);
		/* the write failed... it's had it */
		wsi->socket_is_permanently_unusable = 1;
		return LWS_HPI_RET_CLOSE_HANDLED;
	}

	if (lwsi_state(wsi) == LRS_RETURNED_CLOSE ||
	    lwsi_state(wsi) == LRS_WAITING_TO_SEND_CLOSE ||
	    lwsi_state(wsi) == LRS_AWAITING_CLOSE_ACK) {
		/*
		 * we stopped caring about anything except control
		 * packets.  Force flow control off, defeat tx
		 * draining.
		 */
		lws_rx_flow_control(wsi, 1);
		if (wsi->ws)
			wsi->ws->tx_draining_ext = 0;
	}

	if (wsi->ws && wsi->ws->tx_draining_ext)
		/*
		 * We cannot deal with new RX until the TX ext path has
		 * been drained.  It's because new rx will, eg, crap on
		 * the wsi rx buf that may be needed to retain state.
		 *
		 * TX ext drain path MUST go through event loop to avoid
		 * blocking.
		 */
		return LWS_HPI_RET_HANDLED;

	if (lws_is_flowcontrolled(wsi))
		/* We cannot deal with any kind of new RX because we are
		 * RX-flowcontrolled.
		 */
		return LWS_HPI_RET_HANDLED;

#if defined(LWS_WITH_HTTP2)
	if (wsi->http2_substream || wsi->upgraded_to_http2) {
		wsi1 = lws_get_network_wsi(wsi);
		if (wsi1 && wsi1->trunc_len)
			/* We cannot deal with any kind of new RX
			 * because we are dealing with a partial send
			 * (new RX may trigger new http_action() that
			 * expect to be able to send)
			 */
			return LWS_HPI_RET_HANDLED;
	}
#endif

	/* 2: RX Extension needs to be drained
	 */

	if (lwsi_role_ws(wsi) && wsi->ws && wsi->ws->rx_draining_ext) {

		lwsl_ext("%s: RX EXT DRAINING: Service\n", __func__);
#ifndef LWS_NO_CLIENT
		if (lwsi_role_client(wsi)) {
			n = lws_client_rx_sm(wsi, 0);
			if (n < 0)
				/* we closed wsi */
				n = 0;
		} else
#endif
			n = lws_ws_rx_sm(wsi, 0);

		return LWS_HPI_RET_HANDLED;
	}

	if (wsi->ws && wsi->ws->rx_draining_ext)
		/*
		 * We have RX EXT content to drain, but can't do it
		 * right now.  That means we cannot do anything lower
		 * priority either.
		 */
		return LWS_HPI_RET_HANDLED;

	/* 3: RX Flowcontrol buffer / h2 rx scratch needs to be drained
	 */

	eff_buf.token_len = lws_buflist_next_segment_len(&wsi->buflist_rxflow,
						(uint8_t **)&eff_buf.token);
	if (eff_buf.token_len) {
		lwsl_info("draining rxflow (len %d)\n", eff_buf.token_len);
		draining_flow = 1;
		goto drain;
	}

#if defined(LWS_WITH_HTTP2)
	if (wsi->upgraded_to_http2) {
		struct lws_h2_netconn *h2n = wsi->h2.h2n;

		if (h2n->rx_scratch_len) {
			lwsl_info("%s: %p: h2 rx pos = %d len = %d\n",
				  __func__, wsi, h2n->rx_scratch_pos,
				  h2n->rx_scratch_len);
			eff_buf.token = (char *)h2n->rx_scratch +
					h2n->rx_scratch_pos;
			eff_buf.token_len = h2n->rx_scratch_len;

			h2n->rx_scratch_len = 0;
			goto drain;
		}
	}
#endif

	/* 4: any incoming (or ah-stashed incoming rx) data ready?
	 * notice if rx flow going off raced poll(), rx flow wins
	 */

	if (!(pollfd->revents & pollfd->events & LWS_POLLIN) && !wsi->ah)
		return LWS_HPI_RET_HANDLED;

read:
	if (lws_is_flowcontrolled(wsi)) {
		lwsl_info("%s: %p should be rxflow (bm 0x%x)..\n",
			    __func__, wsi, wsi->rxflow_bitmap);
		return LWS_HPI_RET_HANDLED;
	}

	if (wsi->ah && wsi->ah->rxlen == wsi->ah->rxpos) {
		/* we drained the excess data in the ah */
		lwsl_info("%s: %p: dropping ah on ws post-upgrade\n", __func__, wsi);
		lws_header_table_force_to_detachable_state(wsi);
		lws_header_table_detach(wsi, 0);
	} else
		if (wsi->ah)
			lwsl_info("%s: %p: unable to drop yet %d vs %d\n",
				    __func__, wsi, wsi->ah->rxpos, wsi->ah->rxlen);

	if (wsi->ah && wsi->ah->rxlen - wsi->ah->rxpos) {
		lwsl_info("%s: %p: inherited ah rx %d\n", __func__,
				wsi, wsi->ah->rxlen - wsi->ah->rxpos);
		eff_buf.token_len = wsi->ah->rxlen - wsi->ah->rxpos;
		eff_buf.token = (char *)wsi->ah->rx + wsi->ah->rxpos;
	} else {
		if (!(lwsi_role_client(wsi) &&
		      (lwsi_state(wsi) != LRS_ESTABLISHED &&
		       lwsi_state(wsi) != LRS_H2_WAITING_TO_SEND_HEADERS))) {
			/*
			 * extension may not consume everything
			 * (eg, pmd may be constrained
			 * as to what it can output...) has to go in
			 * per-wsi rx buf area.
			 * Otherwise in large temp serv_buf area.
			 */

#if defined(LWS_WITH_HTTP2)
			if (wsi->upgraded_to_http2) {
				if (!wsi->h2.h2n->rx_scratch) {
					wsi->h2.h2n->rx_scratch =
						lws_malloc(
						wsi->vhost->h2_rx_scratch_size,
						 "h2 rx scratch");
					if (!wsi->h2.h2n->rx_scratch)
						return LWS_HPI_RET_CLOSE_HANDLED;
				}
				eff_buf.token = wsi->h2.h2n->rx_scratch;
				eff_buf.token_len = wsi->vhost->h2_rx_scratch_size;
			} else
#endif
			{
				eff_buf.token = (char *)pt->serv_buf;
				if (lws_is_ws_with_ext(wsi)) {
					eff_buf.token_len =
						wsi->ws->rx_ubuf_alloc;
				} else {
					eff_buf.token_len =
					      wsi->context->pt_serv_buf_size;
				}

				if ((unsigned int)eff_buf.token_len >
		 	 	 	 	 wsi->context->pt_serv_buf_size)
					eff_buf.token_len =
						wsi->context->pt_serv_buf_size;
			}

			if ((int)pending > eff_buf.token_len)
				pending = eff_buf.token_len;

			eff_buf.token_len = lws_ssl_capable_read(wsi,
				(unsigned char *)eff_buf.token,
				pending ? (int)pending :
				eff_buf.token_len);
			switch (eff_buf.token_len) {
			case 0:
				lwsl_info("%s: zero length read\n",
					  __func__);
				return LWS_HPI_RET_CLOSE_HANDLED;
			case LWS_SSL_CAPABLE_MORE_SERVICE:
				lwsl_info("SSL Capable more service\n");
				return LWS_HPI_RET_HANDLED;
			case LWS_SSL_CAPABLE_ERROR:
				lwsl_info("%s: LWS_SSL_CAPABLE_ERROR\n",
						__func__);
				return LWS_HPI_RET_CLOSE_HANDLED;
			}
			// lwsl_notice("Actual RX %d\n", eff_buf.token_len);

			/*
			 * coverity thinks ssl_capable_read() may read over
			 * 2GB.  Dissuade it...
			 */
			eff_buf.token_len &= 0x7fffffff;
		}
	}

drain:

	/*
	 * give any active extensions a chance to munge the buffer
	 * before parse.  We pass in a pointer to an lws_tokens struct
	 * prepared with the default buffer and content length that's in
	 * there.  Rather than rewrite the default buffer, extensions
	 * that expect to grow the buffer can adapt .token to
	 * point to their own per-connection buffer in the extension
	 * user allocation.  By default with no extensions or no
	 * extension callback handling, just the normal input buffer is
	 * used then so it is efficient.
	 */
	m = 0;
	do {
#if !defined(LWS_WITHOUT_EXTENSIONS)
		m = lws_ext_cb_active(wsi, LWS_EXT_CB_PACKET_RX_PREPARSE,
				      &eff_buf, 0);
		if (m < 0)
			return LWS_HPI_RET_CLOSE_HANDLED;
#endif

		/* service incoming data */

		if (eff_buf.token_len) {
			/*
			 * if draining from rxflow buffer, not
			 * critical to track what was used since at the
			 * use it bumps wsi->rxflow_pos.  If we come
			 * around again it will pick up from where it
			 * left off.
			 */
#if defined(LWS_ROLE_H2)
			if (lwsi_role_h2(wsi) && lwsi_state(wsi) != LRS_BODY)
				n = lws_read_h2(wsi, (unsigned char *)eff_buf.token,
					     eff_buf.token_len);
			else
#endif
				n = lws_read_h1(wsi, (unsigned char *)eff_buf.token,
					     eff_buf.token_len);

			if (n < 0) {
				/* we closed wsi */
				n = 0;
				return LWS_HPI_RET_DIE;
			}
		}

		eff_buf.token = NULL;
		eff_buf.token_len = 0;
	} while (m);

	if (wsi->ah
#if !defined(LWS_NO_CLIENT)
			&& !wsi->client_h2_alpn
#endif
			) {
		lwsl_info("%s: %p: detaching ah\n", __func__, wsi);
		lws_header_table_force_to_detachable_state(wsi);
		lws_header_table_detach(wsi, 0);
	}

	pending = lws_ssl_pending(wsi);
	if (pending) {
		if (lws_is_ws_with_ext(wsi))
			pending = pending > wsi->ws->rx_ubuf_alloc ?
				wsi->ws->rx_ubuf_alloc : pending;
		else
			pending = pending > wsi->context->pt_serv_buf_size ?
				wsi->context->pt_serv_buf_size : pending;
		goto read;
	}

	if (draining_flow && /* were draining, now nothing left */
	    !lws_buflist_next_segment_len(&wsi->buflist_rxflow, NULL)) {
		lwsl_info("%s: %p flow buf: drained\n", __func__, wsi);
		/* having drained the rxflow buffer, can rearm POLLIN */
#ifdef LWS_NO_SERVER
		n =
#endif
		__lws_rx_flow_control(wsi);
		/* n ignored, needed for NO_SERVER case */
	}

	/* n = 0 */
	return LWS_HPI_RET_HANDLED;
}


int rops_handle_POLLOUT_ws(struct lws *wsi)
{
	int write_type = LWS_WRITE_PONG;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_tokens eff_buf;
	int ret, m;
#endif
	int n;

	// lwsl_notice("%s: %s\n", __func__, wsi->protocol->name);

	/* Priority 3: pending control packets (pong or close)
	 *
	 * 3a: close notification packet requested from close api
	 */

	if (lwsi_state(wsi) == LRS_WAITING_TO_SEND_CLOSE) {
		lwsl_debug("sending close packet\n");
		wsi->waiting_to_send_close_frame = 0;
		n = lws_write(wsi, &wsi->ws->ping_payload_buf[LWS_PRE],
			      wsi->ws->close_in_ping_buffer_len,
			      LWS_WRITE_CLOSE);
		if (n >= 0) {
			lwsi_set_state(wsi, LRS_AWAITING_CLOSE_ACK);
			lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_ACK, 5);
			lwsl_debug("sent close indication, awaiting ack\n");

			return LWS_HP_RET_BAIL_OK;
		}

		return LWS_HP_RET_BAIL_DIE;
	}

	/* else, the send failed and we should just hang up */

	if ((lwsi_role_ws(wsi) && wsi->ws->ping_pending_flag) ||
	    (lwsi_state(wsi) == LRS_RETURNED_CLOSE &&
	     wsi->ws->payload_is_close)) {

		if (wsi->ws->payload_is_close)
			write_type = LWS_WRITE_CLOSE;

		n = lws_write(wsi, &wsi->ws->ping_payload_buf[LWS_PRE],
			      wsi->ws->ping_payload_len, write_type);
		if (n < 0)
			return LWS_HP_RET_BAIL_DIE;

		/* well he is sent, mark him done */
		wsi->ws->ping_pending_flag = 0;
		if (wsi->ws->payload_is_close) {
			// assert(0);
			/* oh... a close frame was it... then we are done */
			return LWS_HP_RET_BAIL_DIE;
		}

		/* otherwise for PING, leave POLLOUT active either way */
		return LWS_HP_RET_BAIL_OK;
	}

	if (lwsi_role_client(wsi) && !wsi->socket_is_permanently_unusable &&
	    wsi->ws->send_check_ping) {

		lwsl_info("issuing ping on wsi %p\n", wsi);
		wsi->ws->send_check_ping = 0;
		n = lws_write(wsi, &wsi->ws->ping_payload_buf[LWS_PRE],
			      0, LWS_WRITE_PING);
		if (n < 0)
			return LWS_HP_RET_BAIL_DIE;

		/*
		 * we apparently were able to send the PING in a reasonable time
		 * now reset the clock on our peer to be able to send the
		 * PONG in a reasonable time.
		 */

		lws_set_timeout(wsi, PENDING_TIMEOUT_WS_PONG_CHECK_GET_PONG,
				wsi->context->timeout_secs);

		return LWS_HP_RET_BAIL_OK;
	}

	/* Priority 4: if we are closing, not allowed to send more data frags
	 *	       which means user callback or tx ext flush banned now
	 */
	if (lwsi_state(wsi) == LRS_RETURNED_CLOSE)
		return LWS_HP_RET_USER_SERVICE;

	/* Priority 5: Tx path extension with more to send
	 *
	 *	       These are handled as new fragments each time around
	 *	       So while we must block new writeable callback to enforce
	 *	       payload ordering, but since they are always complete
	 *	       fragments control packets can interleave OK.
	 */
	if (lwsi_role_client(wsi) && wsi->ws->tx_draining_ext) {
		lwsl_ext("SERVICING TX EXT DRAINING\n");
		if (lws_write(wsi, NULL, 0, LWS_WRITE_CONTINUATION) < 0)
			return LWS_HP_RET_BAIL_DIE;
		/* leave POLLOUT active */
		return LWS_HP_RET_BAIL_OK;
	}

	/* Priority 6: extensions
	 */
#if !defined(LWS_WITHOUT_EXTENSIONS)
	m = lws_ext_cb_active(wsi, LWS_EXT_CB_IS_WRITEABLE, NULL, 0);
	if (m)
		return LWS_HP_RET_BAIL_DIE;

	if (!wsi->extension_data_pending)
		return LWS_HP_RET_USER_SERVICE;

	/*
	 * check in on the active extensions, see if they
	 * had pending stuff to spill... they need to get the
	 * first look-in otherwise sequence will be disordered
	 *
	 * NULL, zero-length eff_buf means just spill pending
	 */

	ret = 1;
	if (wsi->role_ops == &role_ops_raw_skt ||
	    wsi->role_ops == &role_ops_raw_file)
		ret = 0;

	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* give every extension a chance to spill */

		m = lws_ext_cb_active(wsi, LWS_EXT_CB_PACKET_TX_PRESEND,
				      &eff_buf, 0);
		if (m < 0) {
			lwsl_err("ext reports fatal error\n");
			return LWS_HP_RET_BAIL_DIE;
		}
		if (m)
			/*
			 * at least one extension told us he has more
			 * to spill, so we will go around again after
			 */
			ret = 1;

		/* assuming they gave us something to send, send it */

		if (eff_buf.token_len) {
			n = lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
					  eff_buf.token_len);
			if (n < 0) {
				lwsl_info("closing from POLLOUT spill\n");
				return LWS_HP_RET_BAIL_DIE;
			}
			/*
			 * Keep amount spilled small to minimize chance of this
			 */
			if (n != eff_buf.token_len) {
				lwsl_err("Unable to spill ext %d vs %d\n",
							  eff_buf.token_len, n);
				return LWS_HP_RET_BAIL_DIE;
			}
		} else
			continue;

		/* no extension has more to spill */

		if (!ret)
			continue;

		/*
		 * There's more to spill from an extension, but we just sent
		 * something... did that leave the pipe choked?
		 */

		if (!lws_send_pipe_choked(wsi))
			/* no we could add more */
			continue;

		lwsl_info("choked in POLLOUT service\n");

		/*
		 * Yes, he's choked.  Leave the POLLOUT masked on so we will
		 * come back here when he is unchoked.  Don't call the user
		 * callback to enforce ordering of spilling, he'll get called
		 * when we come back here and there's nothing more to spill.
		 */

		return LWS_HP_RET_BAIL_OK;
	}

	wsi->extension_data_pending = 0;
#endif

	return LWS_HP_RET_USER_SERVICE;
}

static int
rops_periodic_checks_ws(struct lws_context *context, int tsi, time_t now)
{
	struct lws_vhost *vh;

	if (!context->ws_ping_pong_interval ||
	    context->last_ws_ping_pong_check_s >= now + 10)
		return 0;

	vh = context->vhost_list;
	context->last_ws_ping_pong_check_s = now;

	while (vh) {
		int n;

		lws_vhost_lock(vh);

		for (n = 0; n < vh->count_protocols; n++) {
			struct lws *wsi = vh->same_vh_protocol_list[n];

			while (wsi) {
				if (lwsi_role_ws(wsi) &&
				    !wsi->socket_is_permanently_unusable &&
				    !wsi->ws->send_check_ping &&
				    wsi->ws->time_next_ping_check &&
				    lws_compare_time_t(context, now,
					wsi->ws->time_next_ping_check) >
				       context->ws_ping_pong_interval) {

					lwsl_info("req pp on wsi %p\n",
						  wsi);
					wsi->ws->send_check_ping = 1;
					lws_set_timeout(wsi,
					PENDING_TIMEOUT_WS_PONG_CHECK_SEND_PING,
						context->timeout_secs);
					lws_callback_on_writable(wsi);
					wsi->ws->time_next_ping_check =
						now;
				}
				wsi = wsi->same_vh_protocol_next;
			}
		}

		lws_vhost_unlock(vh);
		vh = vh->vhost_next;
	}

	return 0;
}

static int
rops_service_flag_pending_ws(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws *wsi;
	int forced = 0;

	/* POLLIN faking (the pt lock is taken by the parent) */

	/*
	 * 1) For all guys with already-available ext data to drain, if they are
	 * not flowcontrolled, fake their POLLIN status
	 */
	wsi = pt->rx_draining_ext_list;
	while (wsi) {
		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & LWS_POLLIN;
		if (pt->fds[wsi->position_in_fds_table].revents & LWS_POLLIN)
			forced = 1;

		wsi = wsi->ws->rx_draining_ext_list;
	}

	return forced;
}

static int
rops_close_via_role_protocol_ws(struct lws *wsi, enum lws_close_status reason)
{
	if (!wsi->ws->close_in_ping_buffer_len && /* already a reason */
	     (reason == LWS_CLOSE_STATUS_NOSTATUS ||
	      reason == LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY))
		return 0;

	lwsl_debug("%s: sending close indication...\n", __func__);

	/* if no prepared close reason, use 1000 and no aux data */

	if (!wsi->ws->close_in_ping_buffer_len) {
		wsi->ws->close_in_ping_buffer_len = 2;
		wsi->ws->ping_payload_buf[LWS_PRE] = (reason >> 8) & 0xff;
		wsi->ws->ping_payload_buf[LWS_PRE + 1] = reason & 0xff;
	}

	wsi->waiting_to_send_close_frame = 1;
	lwsi_set_state(wsi, LRS_WAITING_TO_SEND_CLOSE);
	__lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_SEND, 5);

	lws_callback_on_writable(wsi);

	return 1;
}

static int
rops_close_role_ws(struct lws_context_per_thread *pt, struct lws *wsi)
{
	if (wsi->ws->rx_draining_ext) {
		struct lws **w = &pt->rx_draining_ext_list;

		wsi->ws->rx_draining_ext = 0;
		/* remove us from context draining ext list */
		while (*w) {
			if (*w == wsi) {
				*w = wsi->ws->rx_draining_ext_list;
				break;
			}
			w = &((*w)->ws->rx_draining_ext_list);
		}
		wsi->ws->rx_draining_ext_list = NULL;
	}

	if (wsi->ws->tx_draining_ext) {
		struct lws **w = &pt->tx_draining_ext_list;

		wsi->ws->tx_draining_ext = 0;
		/* remove us from context draining ext list */
		while (*w) {
			if (*w == wsi) {
				*w = wsi->ws->tx_draining_ext_list;
				break;
			}
			w = &((*w)->ws->tx_draining_ext_list);
		}
		wsi->ws->tx_draining_ext_list = NULL;
	}
	lws_free_set_NULL(wsi->ws->rx_ubuf);

	if (wsi->trunc_alloc)
		/* not going to be completed... nuke it */
		lws_free_set_NULL(wsi->trunc_alloc);

	wsi->ws->ping_payload_len = 0;
	wsi->ws->ping_pending_flag = 0;

	return 0;
}

static int
rops_write_role_protocol_ws(struct lws *wsi, unsigned char *buf, size_t len,
			    enum lws_write_protocol *wp)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int masked7 = lwsi_role_client(wsi);
	unsigned char is_masked_bit = 0;
	unsigned char *dropmask = NULL;
	struct lws_tokens eff_buf;
	size_t orig_len = len;
	int pre = 0, n;

	if (wsi->ws->tx_draining_ext) {
		/* remove us from the list */
		struct lws **w = &pt->tx_draining_ext_list;

		wsi->ws->tx_draining_ext = 0;
		/* remove us from context draining ext list */
		while (*w) {
			if (*w == wsi) {
				*w = wsi->ws->tx_draining_ext_list;
				break;
			}
			w = &((*w)->ws->tx_draining_ext_list);
		}
		wsi->ws->tx_draining_ext_list = NULL;
		*wp = (wsi->ws->tx_draining_stashed_wp & 0xc0) |
				LWS_WRITE_CONTINUATION;

		lwsl_ext("FORCED draining wp to 0x%02X\n", *wp);
	}

	lws_restart_ws_ping_pong_timer(wsi);

	if (((*wp) & 0x1f) == LWS_WRITE_HTTP ||
	    ((*wp) & 0x1f) == LWS_WRITE_HTTP_FINAL ||
	    ((*wp) & 0x1f) == LWS_WRITE_HTTP_HEADERS_CONTINUATION ||
	    ((*wp) & 0x1f) == LWS_WRITE_HTTP_HEADERS)
		goto send_raw;



	/* if we are continuing a frame that already had its header done */

	if (wsi->ws->inside_frame) {
		lwsl_debug("INSIDE FRAME\n");
		goto do_more_inside_frame;
	}

	wsi->ws->clean_buffer = 1;

	/*
	 * give a chance to the extensions to modify payload
	 * the extension may decide to produce unlimited payload erratically
	 * (eg, compression extension), so we require only that if he produces
	 * something, it will be a complete fragment of the length known at
	 * the time (just the fragment length known), and if he has
	 * more we will come back next time he is writeable and allow him to
	 * produce more fragments until he's drained.
	 *
	 * This allows what is sent each time it is writeable to be limited to
	 * a size that can be sent without partial sends or blocking, allows
	 * interleaving of control frames and other connection service.
	 */
	eff_buf.token = (char *)buf;
	eff_buf.token_len = (int)len;

	switch ((int)*wp) {
	case LWS_WRITE_PING:
	case LWS_WRITE_PONG:
	case LWS_WRITE_CLOSE:
		break;
	default:
#if !defined(LWS_WITHOUT_EXTENSIONS)
		lwsl_debug("LWS_EXT_CB_PAYLOAD_TX\n");
		n = lws_ext_cb_active(wsi, LWS_EXT_CB_PAYLOAD_TX, &eff_buf, *wp);
		if (n < 0)
			return -1;

		if (n && eff_buf.token_len) {
			lwsl_debug("drain len %d\n", (int)eff_buf.token_len);
			/* extension requires further draining */
			wsi->ws->tx_draining_ext = 1;
			wsi->ws->tx_draining_ext_list =
					pt->tx_draining_ext_list;
			pt->tx_draining_ext_list = wsi;
			/* we must come back to do more */
			lws_callback_on_writable(wsi);
			/*
			 * keep a copy of the write type for the overall
			 * action that has provoked generation of these
			 * fragments, so the last guy can use its FIN state.
			 */
			wsi->ws->tx_draining_stashed_wp = *wp;
			/* this is definitely not actually the last fragment
			 * because the extension asserted he has more coming
			 * So make sure this intermediate one doesn't go out
			 * with a FIN.
			 */
			*wp |= LWS_WRITE_NO_FIN;
		}
#endif
		if (eff_buf.token_len && wsi->ws->stashed_write_pending) {
			wsi->ws->stashed_write_pending = 0;
			*wp = ((*wp) & 0xc0) | (int)wsi->ws->stashed_write_type;
		}
	}

	/*
	 * an extension did something we need to keep... for example, if
	 * compression extension, it has already updated its state according
	 * to this being issued
	 */
	if ((char *)buf != eff_buf.token) {
		/*
		 * ext might eat it, but not have anything to issue yet.
		 * In that case we have to follow his lead, but stash and
		 * replace the write type that was lost here the first time.
		 */
		if (len && !eff_buf.token_len) {
			if (!wsi->ws->stashed_write_pending)
				wsi->ws->stashed_write_type = (char)(*wp) & 0x3f;
			wsi->ws->stashed_write_pending = 1;
			return (int)len;
		}
		/*
		 * extension recreated it:
		 * need to buffer this if not all sent
		 */
		wsi->ws->clean_buffer = 0;
	}

	buf = (unsigned char *)eff_buf.token;
	len = eff_buf.token_len;

	if (!buf) {
		lwsl_err("null buf (%d)\n", (int)len);
		return -1;
	}

	switch (wsi->ws->ietf_spec_revision) {
	case 13:
		if (masked7) {
			pre += 4;
			dropmask = &buf[0 - pre];
			is_masked_bit = 0x80;
		}

		switch ((*wp) & 0xf) {
		case LWS_WRITE_TEXT:
			n = LWSWSOPC_TEXT_FRAME;
			break;
		case LWS_WRITE_BINARY:
			n = LWSWSOPC_BINARY_FRAME;
			break;
		case LWS_WRITE_CONTINUATION:
			n = LWSWSOPC_CONTINUATION;
			break;

		case LWS_WRITE_CLOSE:
			n = LWSWSOPC_CLOSE;
			break;
		case LWS_WRITE_PING:
			n = LWSWSOPC_PING;
			break;
		case LWS_WRITE_PONG:
			n = LWSWSOPC_PONG;
			break;
		default:
			lwsl_warn("lws_write: unknown write opc / wp\n");
			return -1;
		}

		if (!((*wp) & LWS_WRITE_NO_FIN))
			n |= 1 << 7;

		if (len < 126) {
			pre += 2;
			buf[-pre] = n;
			buf[-pre + 1] = (unsigned char)(len | is_masked_bit);
		} else {
			if (len < 65536) {
				pre += 4;
				buf[-pre] = n;
				buf[-pre + 1] = 126 | is_masked_bit;
				buf[-pre + 2] = (unsigned char)(len >> 8);
				buf[-pre + 3] = (unsigned char)len;
			} else {
				pre += 10;
				buf[-pre] = n;
				buf[-pre + 1] = 127 | is_masked_bit;
#if defined __LP64__
					buf[-pre + 2] = (len >> 56) & 0x7f;
					buf[-pre + 3] = len >> 48;
					buf[-pre + 4] = len >> 40;
					buf[-pre + 5] = len >> 32;
#else
					buf[-pre + 2] = 0;
					buf[-pre + 3] = 0;
					buf[-pre + 4] = 0;
					buf[-pre + 5] = 0;
#endif
				buf[-pre + 6] = (unsigned char)(len >> 24);
				buf[-pre + 7] = (unsigned char)(len >> 16);
				buf[-pre + 8] = (unsigned char)(len >> 8);
				buf[-pre + 9] = (unsigned char)len;
			}
		}
		break;
	}

do_more_inside_frame:

	/*
	 * Deal with masking if we are in client -> server direction and
	 * the wp demands it
	 */

	if (masked7) {
		if (!wsi->ws->inside_frame)
			if (lws_0405_frame_mask_generate(wsi)) {
				lwsl_err("frame mask generation failed\n");
				return -1;
			}

		/*
		 * in v7, just mask the payload
		 */
		if (dropmask) { /* never set if already inside frame */
			for (n = 4; n < (int)len + 4; n++)
				dropmask[n] = dropmask[n] ^ wsi->ws->mask[
					(wsi->ws->mask_idx++) & 3];

			/* copy the frame nonce into place */
			memcpy(dropmask, wsi->ws->mask, 4);
		}
	}

	if (lwsi_role_h2_ENCAPSULATION(wsi)) {
		struct lws *encap = lws_get_network_wsi(wsi);

		assert(encap != wsi);
		return encap->role_ops->write_role_protocol(wsi, buf - pre,
							len + pre, wp);
	}

	switch ((*wp) & 0x1f) {
	case LWS_WRITE_TEXT:
	case LWS_WRITE_BINARY:
	case LWS_WRITE_CONTINUATION:
		if (!wsi->h2_stream_carries_ws) {

			/*
			 * give any active extensions a chance to munge the
			 * buffer before send.  We pass in a pointer to an
			 * lws_tokens struct prepared with the default buffer
			 * and content length that's in there.  Rather than
			 * rewrite the default buffer, extensions that expect
			 * to grow the buffer can adapt .token to point to their
			 * own per-connection buffer in the extension user
			 * allocation.  By default with no extensions or no
			 * extension callback handling, just the normal input
			 * buffer is used then so it is efficient.
			 *
			 * callback returns 1 in case it wants to spill more
			 * buffers
			 *
			 * This takes care of holding the buffer if send is
			 * incomplete, ie, if wsi->ws->clean_buffer is 0
			 * (meaning an extension meddled with the buffer).  If
			 * wsi->ws->clean_buffer is 1, it will instead return
			 * to the user code how much OF THE USER BUFFER was
			 * consumed.
			 */

			n = lws_issue_raw_ext_access(wsi, buf - pre, len + pre);
			wsi->ws->inside_frame = 1;
			if (n <= 0)
				return n;

			if (n == (int)len + pre) {
				/* everything in the buffer was handled
				 * (or rebuffered...) */
				wsi->ws->inside_frame = 0;
				return (int)orig_len;
			}

			/*
			 * it is how many bytes of user buffer got sent... may
			 * be < orig_len in which case callback when writable
			 * has already been arranged and user code can call
			 * lws_write() again with the rest later.
			 */

			return n - pre;
		}
		break;
	default:
		break;
	}

send_raw:
	return lws_issue_raw(wsi, (unsigned char *)buf - pre, len + pre);
}

static int
rops_close_kill_connection_ws(struct lws *wsi, enum lws_close_status reason)
{
	/* deal with ws encapsulation in h2 */
#if defined(LWS_WITH_HTTP2)
	if (wsi->http2_substream && wsi->h2_stream_carries_ws)
		return role_ops_h2.close_kill_connection(wsi, reason);

	return 0;
#else
	return 0;
#endif
}

static int
rops_callback_on_writable_ws(struct lws *wsi)
{
	if (lws_ext_cb_active(wsi, LWS_EXT_CB_REQUEST_ON_WRITEABLE, NULL, 0))
		return 1;
#if defined(LWS_WITH_HTTP2)
	if (lwsi_role_h2_ENCAPSULATION(wsi)) {
		/* we know then that it has an h2 parent */
		struct lws *enc = role_ops_h2.encapsulation_parent(wsi);

		assert(enc);
		if (enc->role_ops->callback_on_writable(wsi))
			return 1;
	}
#endif
	return 0;
}

struct lws_role_ops role_ops_ws = {
	/* role name */			"ws",
	/* alpn id */			NULL,
	/* check_upgrades */		NULL,
	/* init_context */		NULL,
	/* init_vhost */		NULL,
	/* periodic_checks */		rops_periodic_checks_ws,
	/* service_flag_pending */	rops_service_flag_pending_ws,
	/* handle_POLLIN */		rops_handle_POLLIN_ws,
	/* handle_POLLOUT */		rops_handle_POLLOUT_ws,
	/* perform_user_POLLOUT */	NULL,
	/* callback_on_writable */	rops_callback_on_writable_ws,
	/* tx_credit */			NULL,
	/* write_role_protocol */	rops_write_role_protocol_ws,
	/* rxflow_cache */		NULL,
	/* encapsulation_parent */	NULL,
	/* alpn_negotiated */		NULL,
	/* close_via_role_protocol */	rops_close_via_role_protocol_ws,
	/* close_role */		rops_close_role_ws,
	/* close_kill_connection */	rops_close_kill_connection_ws,
	/* destroy_role */		NULL,
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_CLIENT_WRITEABLE,
					  LWS_CALLBACK_SERVER_WRITEABLE },
	/* close cb clnt, srv */	{ LWS_CALLBACK_CLIENT_CLOSED,
					  LWS_CALLBACK_CLOSED },
};
