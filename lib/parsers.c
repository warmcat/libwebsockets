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

#include "private-libwebsockets.h"

#ifdef WIN32
#include <io.h>
#endif

static const struct lws_tokens lws_tokens[WSI_TOKEN_COUNT] = {

	/* win32 can't do C99 */

/*	[WSI_TOKEN_GET_URI]	=	*/{ "GET ",			 4 },
/*	[WSI_TOKEN_HOST]	=	*/{ "Host:",			 5 },
/*	[WSI_TOKEN_CONNECTION]	=	*/{ "Connection:",		11 },
/*	[WSI_TOKEN_KEY1]	=	*/{ "Sec-WebSocket-Key1:",	19 },
/*	[WSI_TOKEN_KEY2]	=	*/{ "Sec-WebSocket-Key2:",	19 },
/*	[WSI_TOKEN_PROTOCOL]	=	*/{ "Sec-WebSocket-Protocol:",	23 },
/*	[WSI_TOKEN_UPGRADE]	=	*/{ "Upgrade:",			 8 },
/*	[WSI_TOKEN_ORIGIN]	=	*/{ "Origin:",			 7 },
/*	[WSI_TOKEN_DRAFT]	=	*/{ "Sec-WebSocket-Draft:",	20 },
/*	[WSI_TOKEN_CHALLENGE]	=	*/{ "\x0d\x0a",			 2 },

/*	[WSI_TOKEN_KEY]		=	*/{ "Sec-WebSocket-Key:",	18 },
/*	[WSI_TOKEN_VERSION]	=	*/{ "Sec-WebSocket-Version:",	22 },
/*	[WSI_TOKEN_SWORIGIN]=		*/{ "Sec-WebSocket-Origin:",	21 },

/*	[WSI_TOKEN_EXTENSIONS]	=	*/{ "Sec-WebSocket-Extensions:", 25 },

/*	[WSI_TOKEN_ACCEPT]	=	*/{ "Sec-WebSocket-Accept:",	21 },
/*	[WSI_TOKEN_NONCE]	=	*/{ "Sec-WebSocket-Nonce:",	20 },
/*	[WSI_TOKEN_HTTP]	=	*/{ "HTTP/1.1 ",		 9 },
/*	[WSI_TOKEN_MUXURL]	=	*/{ "",		 -1 },

};

int libwebsocket_parse(struct libwebsocket *wsi, unsigned char c)
{
	int n;

	switch (wsi->parser_state) {
	case WSI_TOKEN_GET_URI:
	case WSI_TOKEN_HOST:
	case WSI_TOKEN_CONNECTION:
	case WSI_TOKEN_KEY1:
	case WSI_TOKEN_KEY2:
	case WSI_TOKEN_PROTOCOL:
	case WSI_TOKEN_UPGRADE:
	case WSI_TOKEN_ORIGIN:
	case WSI_TOKEN_SWORIGIN:
	case WSI_TOKEN_DRAFT:
	case WSI_TOKEN_CHALLENGE:
	case WSI_TOKEN_KEY:
	case WSI_TOKEN_VERSION:
	case WSI_TOKEN_ACCEPT:
	case WSI_TOKEN_NONCE:
	case WSI_TOKEN_EXTENSIONS:
	case WSI_TOKEN_HTTP:
	case WSI_TOKEN_MUXURL:

		debug("WSI_TOKEN_(%d) '%c'\n", wsi->parser_state, c);

		/* collect into malloc'd buffers */
		/* optional space swallow */
		if (!wsi->utf8_token[wsi->parser_state].token_len && c == ' ')
			break;

		/* special case space terminator for get-uri */
		if (wsi->parser_state == WSI_TOKEN_GET_URI && c == ' ') {
			wsi->utf8_token[wsi->parser_state].token[
			   wsi->utf8_token[wsi->parser_state].token_len] = '\0';
//			debug("uri '%s'\n", wsi->utf8_token[wsi->parser_state].token);
			wsi->parser_state = WSI_TOKEN_SKIPPING;
			break;
		}

		/* allocate appropriate memory */
		if (wsi->utf8_token[wsi->parser_state].token_len ==
						   wsi->current_alloc_len - 1) {
			/* need to extend */
			wsi->current_alloc_len += LWS_ADDITIONAL_HDR_ALLOC;
			if (wsi->current_alloc_len >= LWS_MAX_HEADER_LEN) {
				/* it's waaay to much payload, fail it */
				strcpy(wsi->utf8_token[wsi->parser_state].token,
				   "!!! Length exceeded maximum supported !!!");
				wsi->parser_state = WSI_TOKEN_SKIPPING;
				break;
			}
			wsi->utf8_token[wsi->parser_state].token =
			       realloc(wsi->utf8_token[wsi->parser_state].token,
							wsi->current_alloc_len);
		}

		/* bail at EOL */
		if (wsi->parser_state != WSI_TOKEN_CHALLENGE && c == '\x0d') {
			wsi->utf8_token[wsi->parser_state].token[
			   wsi->utf8_token[wsi->parser_state].token_len] = '\0';
			wsi->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			debug("*\n");
			break;
		}

		wsi->utf8_token[wsi->parser_state].token[
			    wsi->utf8_token[wsi->parser_state].token_len++] = c;

		/* per-protocol end of headers management */

		if (wsi->parser_state != WSI_TOKEN_CHALLENGE)
			break;

		/* -76 has no version header ... server */
		if (!wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
		   wsi->mode != LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY &&
			      wsi->utf8_token[wsi->parser_state].token_len != 8)
			break;

		/* -76 has no version header ... client */
		if (!wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
		   wsi->mode == LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY &&
			wsi->utf8_token[wsi->parser_state].token_len != 16)
			break;

		/* <= 03 has old handshake with version header needs 8 bytes */
		if (wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
			 atoi(wsi->utf8_token[WSI_TOKEN_VERSION].token) < 4 &&
			      wsi->utf8_token[wsi->parser_state].token_len != 8)
			break;

		/* no payload challenge in 01 + */

		if (wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
			   atoi(wsi->utf8_token[WSI_TOKEN_VERSION].token) > 0) {
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len = 0;
			free(wsi->utf8_token[WSI_TOKEN_CHALLENGE].token);
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token = NULL;
		}

		/* For any supported protocol we have enough payload */

		debug("Setting WSI_PARSING_COMPLETE\n");
		wsi->parser_state = WSI_PARSING_COMPLETE;
		break;

	case WSI_INIT_TOKEN_MUXURL:
		wsi->parser_state = WSI_TOKEN_MUXURL;
		wsi->current_alloc_len = LWS_INITIAL_HDR_ALLOC;

		wsi->utf8_token[wsi->parser_state].token =
					 malloc(wsi->current_alloc_len);
		wsi->utf8_token[wsi->parser_state].token_len = 0;
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
		debug("WSI_TOKEN_NAME_PART '%c'\n", c);

		if (wsi->name_buffer_pos == sizeof(wsi->name_buffer) - 1) {
			/* name bigger than we can handle, skip until next */
			wsi->parser_state = WSI_TOKEN_SKIPPING;
			break;
		}
		wsi->name_buffer[wsi->name_buffer_pos++] = c;
		wsi->name_buffer[wsi->name_buffer_pos] = '\0';

		for (n = 0; n < WSI_TOKEN_COUNT; n++) {
			if (wsi->name_buffer_pos != lws_tokens[n].token_len)
				continue;
			if (strcasecmp(lws_tokens[n].token, wsi->name_buffer))
				continue;
			debug("known hdr '%s'\n", wsi->name_buffer);

			/*
			 * WSORIGIN is protocol equiv to ORIGIN,
			 * JWebSocket likes to send it, map to ORIGIN
			 */
			if (n == WSI_TOKEN_SWORIGIN)
				n = WSI_TOKEN_ORIGIN;

			wsi->parser_state = WSI_TOKEN_GET_URI + n;

			n = WSI_TOKEN_COUNT;

			/*  If the header has been seen already, just append */
			if (wsi->utf8_token[wsi->parser_state].token)
				continue;

			wsi->current_alloc_len = LWS_INITIAL_HDR_ALLOC;
			wsi->utf8_token[wsi->parser_state].token =
						 malloc(wsi->current_alloc_len);
			wsi->utf8_token[wsi->parser_state].token_len = 0;
		}

		/* colon delimiter means we just don't know this name */

		if (wsi->parser_state == WSI_TOKEN_NAME_PART) {
			if (c == ':') {
				debug("skipping unknown header '%s'\n",
							  wsi->name_buffer);
				wsi->parser_state = WSI_TOKEN_SKIPPING;
				break;
			}

			if (c == ' ' &&
				!wsi->utf8_token[WSI_TOKEN_GET_URI].token_len) {
				debug("unknown method '%s'\n",
							  wsi->name_buffer);
				wsi->parser_state = WSI_TOKEN_GET_URI;
				wsi->current_alloc_len = LWS_INITIAL_HDR_ALLOC;
				wsi->utf8_token[WSI_TOKEN_GET_URI].token =
						 malloc(wsi->current_alloc_len);
				break;
			}
		}

		if (wsi->parser_state != WSI_TOKEN_CHALLENGE)
			break;

		/* don't look for payload when it can just be http headers */

		if (!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len) {
			/* they're HTTP headers, not websocket upgrade! */
			debug("Setting WSI_PARSING_COMPLETE "
							 "from http headers\n");
			wsi->parser_state = WSI_PARSING_COMPLETE;
		}

		/* 04 version has no packet content after end of hdrs */

		if (wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
			 atoi(wsi->utf8_token[WSI_TOKEN_VERSION].token) >= 4) {
			debug("04 header completed\n");
			wsi->parser_state = WSI_PARSING_COMPLETE;
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len = 0;
			free(wsi->utf8_token[WSI_TOKEN_CHALLENGE].token);
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token = NULL;
		}

		/* client parser? */

		if (wsi->ietf_spec_revision >= 4) {
			debug("04 header completed\n");
			wsi->parser_state = WSI_PARSING_COMPLETE;
		}

		break;

		/* skipping arg part of a name we didn't recognize */
	case WSI_TOKEN_SKIPPING:
		debug("WSI_TOKEN_SKIPPING '%c'\n", c);
		if (c == '\x0d')
			wsi->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
		break;
	case WSI_TOKEN_SKIPPING_SAW_CR:
		debug("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
		if (c == '\x0a')
			wsi->parser_state = WSI_TOKEN_NAME_PART;
		else
			wsi->parser_state = WSI_TOKEN_SKIPPING;
		wsi->name_buffer_pos = 0;
		break;
		/* we're done, ignore anything else */
	case WSI_PARSING_COMPLETE:
		debug("WSI_PARSING_COMPLETE '%c'\n", c);
		break;

	default:	/* keep gcc happy */
		break;
	}

	return 0;
}

unsigned char
xor_no_mask(struct libwebsocket *wsi, unsigned char c)
{
	return c;
}

unsigned char
xor_mask_04(struct libwebsocket *wsi, unsigned char c)
{
	c ^= wsi->masking_key_04[wsi->frame_mask_index++];
	if (wsi->frame_mask_index == 20)
		wsi->frame_mask_index = 0;

	return c;
}

unsigned char
xor_mask_05(struct libwebsocket *wsi, unsigned char c)
{
	return c ^ wsi->frame_masking_nonce_04[(wsi->frame_mask_index++) & 3];
}



int
libwebsocket_rx_sm(struct libwebsocket *wsi, unsigned char c)
{
	int n;
	unsigned char buf[20 + 4];
	struct lws_tokens eff_buf;
	int handled;
	int m;

#if 0
	fprintf(stderr, "RX: %02X ", c);
#endif

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:

		switch (wsi->ietf_spec_revision) {
		/* Firefox 4.0b6 likes this as of 30 Oct 2010 */
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
			wsi->all_zero_nonce = 1;
			wsi->frame_masking_nonce_04[0] = c;
			if (c)
				wsi->all_zero_nonce = 0;
			wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_1;
			break;
		case 7:
		case 8:
		case 13:
			/*
			 * no prepended frame key any more
			 */
			wsi->all_zero_nonce = 1;
			goto handle_first;

		default:
			fprintf(stderr, "libwebsocket_rx_sm doesn't know "
			    "about spec version %d\n", wsi->ietf_spec_revision);
			break;
		}
		break;
	case LWS_RXPS_04_MASK_NONCE_1:
		wsi->frame_masking_nonce_04[1] = c;
		if (c)
			wsi->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_2;
		break;
	case LWS_RXPS_04_MASK_NONCE_2:
		wsi->frame_masking_nonce_04[2] = c;
		if (c)
			wsi->all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_3;
		break;
	case LWS_RXPS_04_MASK_NONCE_3:
		wsi->frame_masking_nonce_04[3] = c;
		if (c)
			wsi->all_zero_nonce = 0;

		if (wsi->protocol->owning_server->options &
					   LWS_SERVER_OPTION_DEFEAT_CLIENT_MASK)
			goto post_mask;

		if (wsi->ietf_spec_revision > 4)
			goto post_sha1;

		/*
		 * we are able to compute the frame key now
		 * it's a SHA1 of ( frame nonce we were just sent, concatenated
		 * with the connection masking key we computed at handshake
		 * time ) -- yeah every frame from the client invokes a SHA1
		 * for no real reason so much for lightweight.
		 */

		buf[0] = wsi->frame_masking_nonce_04[0];
		buf[1] = wsi->frame_masking_nonce_04[1];
		buf[2] = wsi->frame_masking_nonce_04[2];
		buf[3] = wsi->frame_masking_nonce_04[3];

		memcpy(buf + 4, wsi->masking_key_04, 20);

		/*
		 * wsi->frame_mask_04 will be our recirculating 20-byte XOR key
		 * for this frame
		 */

		SHA1((unsigned char *)buf, 4 + 20, wsi->frame_mask_04);

post_sha1:

		/*
		 * start from the zero'th byte in the XOR key buffer since
		 * this is the start of a frame with a new key
		 */

		wsi->frame_mask_index = 0;

post_mask:
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

		/*
		 * 04 spec defines the opcode like this: (1, 2, and 3 are
		 * "control frame" opcodes which may not be fragmented or
		 * have size larger than 126)
		 *
		 *       frame-opcode           =
		 *	       %x0 ; continuation frame
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
			c = wsi->xor_mask(wsi, c);

		/* translate all incoming opcodes into v7+ map */
		if (wsi->ietf_spec_revision < 7)
			switch (c & 0xf) {
			case LWS_WS_OPCODE_04__CONTINUATION:
				wsi->opcode = LWS_WS_OPCODE_07__CONTINUATION;
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
				wsi->opcode = LWS_WS_OPCODE_07__TEXT_FRAME;
				break;
			case LWS_WS_OPCODE_04__BINARY_FRAME:
				wsi->opcode = LWS_WS_OPCODE_07__BINARY_FRAME;
				break;
			default:
				fprintf(stderr, "reserved opcodes not "
						    "usable pre v7 protocol\n");
				return -1;
			}
		else
			wsi->opcode = c & 0xf;
		wsi->rsv = (c & 0x70);
		wsi->final = !!((c >> 7) & 1);

		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN:

		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);

		if ((c & 0x80) && wsi->ietf_spec_revision < 7) {
			fprintf(stderr, "Frame has extensions "
							   "set illegally 2\n");
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
			wsi->rx_packet_length = c & 0x7f;
			if (wsi->this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else
				wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
			break;
		}
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_2:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);

		wsi->rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);

		wsi->rx_packet_length |= c;
		if (wsi->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_8:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
		if (c & 0x80) {
			fprintf(stderr, "b63 of length must be zero\n");
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
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
#if defined __LP64__
		wsi->rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
#if defined __LP64__
		wsi->rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
#if defined __LP64__
		wsi->rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
		wsi->rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
		wsi->rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
		wsi->rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		if (wsi->ietf_spec_revision < 7)
			c = wsi->xor_mask(wsi, c);
		wsi->rx_packet_length |= ((size_t)c);
		if (wsi->this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
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
			  wsi, LWS_CALLBACK_RECEIVE,
			  wsi->user_space,
			  &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
			  wsi->rx_user_buffer_head);
		wsi->rx_user_buffer_head = 0;
		break;
	case LWS_RXPS_SEEN_76_FF:
		if (c)
			break;

		debug("Seen that client is requesting "
				"a v76 close, sending ack\n");
		buf[0] = 0xff;
		buf[1] = 0;
		n = libwebsocket_write(wsi, buf, 2, LWS_WRITE_HTTP);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			return -1;
		}
		debug("  v76 close ack sent, server closing skt\n");
		/* returning < 0 will get it closed in parent */
		return -1;

	case LWS_RXPS_PULLING_76_LENGTH:
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
		wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		wsi->frame_mask_index = 0;
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:
		if (wsi->ietf_spec_revision < 4 ||
			 (wsi->all_zero_nonce && wsi->ietf_spec_revision >= 5))
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
		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		debug("spill on %s\n", wsi->protocol->name);

		switch (wsi->opcode) {
		case LWS_WS_OPCODE_07__CLOSE:
			/* is this an acknowledgement of our close? */
			if (wsi->state == WSI_STATE_AWAITING_CLOSE_ACK) {
				/*
				 * fine he has told us he is closing too, let's
				 * finish our close
				 */
				debug("seen client close ack\n");
				return -1;
			}
			debug("server sees client close packet\n");
			/* parrot the close packet payload back */
			n = libwebsocket_write(wsi, (unsigned char *)
			   &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				     wsi->rx_user_buffer_head, LWS_WRITE_CLOSE);
			wsi->state = WSI_STATE_RETURNED_CLOSE_ALREADY;
			/* close the connection */
			return -1;

		case LWS_WS_OPCODE_07__PING:
			/* parrot the ping packet payload back as a pong */
			n = libwebsocket_write(wsi, (unsigned char *)
			    &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				    wsi->rx_user_buffer_head, LWS_WRITE_PONG);
			/* ... then just drop it */
			wsi->rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__PONG:
			/* keep the statistics... */
			wsi->pings_vs_pongs--;
			/* ... then just drop it */
			wsi->rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__CONTINUATION:
		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
			break;

		default:

			debug("passing opcode %x up to exts\n", wsi->opcode);

			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->rx_user_buffer[
						   LWS_SEND_BUFFER_PRE_PADDING];
			eff_buf.token_len = wsi->rx_user_buffer_head;

			handled = 0;
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

			if (!handled)
				fprintf(stderr, "Unhandled extended opcode "
					"0x%x - ignoring frame\n", wsi->opcode);

			wsi->rx_user_buffer_head = 0;
			return 0;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using libwebsocket_write
		 */

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
				fprintf(stderr,
			          "Extension '%s' failed to handle payload!",
			        	      wsi->active_extensions[n]->name);
				return -1;
			}
		}

		if (eff_buf.token_len > 0) {
		    eff_buf.token[eff_buf.token_len] = '\0';

		    if (wsi->protocol->callback)
			    wsi->protocol->callback(wsi->protocol->owning_server,
						    wsi, LWS_CALLBACK_RECEIVE,
						    wsi->user_space,
			                	    eff_buf.token,
						    eff_buf.token_len);
		    else
			    fprintf(stderr, "No callback on payload spill!");
		}

		wsi->rx_user_buffer_head = 0;
		break;
	}

	return 0;

illegal_ctl_length:

	fprintf(stderr, "Control frame asking for "
			"extended length is illegal\n");
	/* kill the connection */
	return -1;
}


int libwebsocket_client_rx_sm(struct libwebsocket *wsi, unsigned char c)
{
	int n;
	unsigned char buf[20 + 4];
	int callback_action = LWS_CALLBACK_CLIENT_RECEIVE;
	int handled;
	struct lws_tokens eff_buf;
	int m;

	debug(" CRX: %02X %d\n", c, wsi->lws_rx_parse_state);

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
					fprintf(stderr, "reserved opcodes not "
						   "usable pre v7 protocol\n");
					return -1;
				}
			else
				wsi->opcode = c & 0xf;
			wsi->rsv = (c & 0x70);
			wsi->final = !!((c >> 7) & 1);

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
			break;

		default:
			fprintf(stderr, "client_rx_sm doesn't know how "
				"to handle spec version %02d\n",
						       wsi->ietf_spec_revision);
			break;
		}
		break;


	case LWS_RXPS_04_FRAME_HDR_LEN:

		if ((c & 0x80) && wsi->ietf_spec_revision < 7) {
			fprintf(stderr,
				      "Frame has extensions set illegally 4\n");
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
			fprintf(stderr, "b63 of length must be zero\n");
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

		debug("Seen that client is requesting "
				"a v76 close, sending ack\n");
		buf[0] = 0xff;
		buf[1] = 0;
		n = libwebsocket_write(wsi, buf, 2, LWS_WRITE_HTTP);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			return -1;
		}
		debug("  v76 close ack sent, server closing skt\n");
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
				debug("seen server's close ack\n");
				return -1;
			}
			debug("client sees server close packet len = %d\n", wsi->rx_user_buffer_head);
			/* parrot the close packet payload back */
			n = libwebsocket_write(wsi, (unsigned char *)
			   &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				     wsi->rx_user_buffer_head, LWS_WRITE_CLOSE);
			debug("client writing close ack returned %d\n", n);
			wsi->state = WSI_STATE_RETURNED_CLOSE_ALREADY;
			/* close the connection */
			return -1;

		case LWS_WS_OPCODE_07__PING:
			/* parrot the ping packet payload back as a pong*/
			n = libwebsocket_write(wsi, (unsigned char *)
			    &wsi->rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				    wsi->rx_user_buffer_head, LWS_WRITE_PONG);
			handled = 1;
			break;

		case LWS_WS_OPCODE_07__PONG:
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

			debug("Reserved opcode 0x%2X\n", wsi->opcode);
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
				fprintf(stderr, "Unhandled extended opcode "
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
				fprintf(stderr,
					"Extension '%s' failed to handle payload!",
						wsi->active_extensions[n]->name);
				return -1;
			}
		}

		if (eff_buf.token_len > 0) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback)
				wsi->protocol->callback(
						wsi->protocol->owning_server,
						wsi, callback_action,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
		}
already_done:
		wsi->rx_user_buffer_head = 0;
		break;
	default:
		fprintf(stderr, "client rx illegal state\n");
		return 1;
	}

	return 0;

illegal_ctl_length:

	fprintf(stderr, "Control frame asking for "
				"extended length is illegal\n");
	/* kill the connection */
	return -1;

}



int libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						 unsigned char *buf, size_t len)
{
	size_t n;

#ifdef DEBUG
	fprintf(stderr, "received %d byte packet\n", (int)len);
	for (n = 0; n < len; n++)
		fprintf(stderr, "%02X ", buf[n]);
	fprintf(stderr, "\n");
#endif

	/* let the rx protocol state machine have as much as it needs */

	n = 0;
	while (n < len)
		if (libwebsocket_rx_sm(wsi, buf[n++]) < 0)
			return -1;

	return 0;
}


static int
libwebsocket_0405_frame_mask_generate(struct libwebsocket *wsi)
{
	char buf[4 + 20];
	int n;

	/* fetch the per-frame nonce */

	n = libwebsockets_get_random(wsi->protocol->owning_server,
						wsi->frame_masking_nonce_04, 4);
	if (n != 4) {
		fprintf(stderr, "Unable to read from random device %s %d\n",
						     SYSTEM_RANDOM_FILEPATH, n);
		return 1;
	}

	/* start masking from first byte of masking key buffer */
	wsi->frame_mask_index = 0;

	if (wsi->ietf_spec_revision != 4)
		return 0;

	/* 04 only does SHA-1 more complex key */

	/*
	 * the frame key is the frame nonce (4 bytes) followed by the
	 * connection masking key, hashed by SHA1
	 */

	memcpy(buf, wsi->frame_masking_nonce_04, 4);

	memcpy(buf + 4, wsi->masking_key_04, 20);

	/* concatenate the nonce with the connection key then hash it */

	SHA1((unsigned char *)buf, 4 + 20, wsi->frame_mask_04);

	return 0;
}

void lws_stderr_hexdump(unsigned char *buf, size_t len)
{
	int n;
	int m;
	int start;

	fprintf(stderr, "\n");

	for (n = 0; n < len;) {
		start = n;

		fprintf(stderr, "%04X: ", start);

		for (m = 0; m < 16 && n < len; m++)
			fprintf(stderr, "%02X ", buf[n++]);
		while (m++ < 16)
			fprintf(stderr, "   ");

		fprintf(stderr, "   ");

		for (m = 0; m < 16 && (start + m) < len; m++) {
			if (buf[start + m] >= ' ' && buf[start + m] <= 127)
				fprintf(stderr, "%c", buf[start + m]);
			else
				fprintf(stderr, ".");
		}
		while (m++ < 16)
			fprintf(stderr, " ");

		fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
}

int lws_issue_raw(struct libwebsocket *wsi, unsigned char *buf, size_t len)
{
	int n;
	int m;

	/*
	 * one of the extensions is carrying our data itself?  Like mux?
	 */

	for (n = 0; n < wsi->count_active_extensions; n++) {
		/*
		 * there can only be active extensions after handshake completed
		 * so we can rely on protocol being set already in here
		 */
		m = wsi->active_extensions[n]->callback(
				wsi->protocol->owning_server,
				wsi->active_extensions[n], wsi,
				LWS_EXT_CALLBACK_PACKET_TX_DO_SEND,
				     wsi->active_extensions_user[n], &buf, len);
		if (m < 0) {
			fprintf(stderr, "Extension reports fatal error\n");
			return -1;
		}
		if (m) /* handled */ {
/*			fprintf(stderr, "ext sent it\n"); */
			return 0;
		}
	}

	if (!wsi->sock)
		fprintf(stderr, "** error 0 sock but expected to send\n");

	/*
	 * nope, send it on the socket directly
	 */

#if 0
	fprintf(stderr, "  TX: ");
	lws_stderr_hexdump(buf, len);
#endif

#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
		n = SSL_write(wsi->ssl, buf, len);
		if (n < 0) {
			fprintf(stderr,
				   "ERROR writing to socket\n");
			return -1;
		}
	} else {
#endif
		n = send(wsi->sock, buf, len, MSG_NOSIGNAL);
		if (n < 0) {
			fprintf(stderr,
				   "ERROR writing to socket\n");
			return -1;
		}
#ifdef LWS_OPENSSL_SUPPORT
	}
#endif
	return 0;
}

int
lws_issue_raw_ext_access(struct libwebsocket *wsi,
						 unsigned char *buf, size_t len)
{
	int ret;
	struct lws_tokens eff_buf;
	int m;
	int n;

	eff_buf.token = (char *)buf;
	eff_buf.token_len = len;

	/*
	 * while we have original buf to spill ourselves, or extensions report
	 * more in their pipeline
	 */

	ret = 1;
	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;

		/* show every extension the new incoming data */

		for (n = 0; n < wsi->count_active_extensions; n++) {
			m = wsi->active_extensions[n]->callback(
					wsi->protocol->owning_server,
					wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_PACKET_TX_PRESEND,
				   wsi->active_extensions_user[n], &eff_buf, 0);
			if (m < 0) {
				fprintf(stderr, "Extension: fatal error\n");
				return -1;
			}
			if (m)
				/*
				 * at least one extension told us he has more
				 * to spill, so we will go around again after
				 */
				ret = 1;
		}

		/* assuming they left us something to send, send it */

		if (eff_buf.token_len)
			if (lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
							    eff_buf.token_len))
				return -1;

		debug("written %d bytes to client\n", eff_buf.token_len);

		/* no extension has more to spill */

		if (!ret)
			break;

		/* we used up what we had */

		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/*
		 * Did that leave the pipe choked?
		 */

		if (!lws_send_pipe_choked(wsi))
			/* no we could add more */
			continue;

		debug("choked\n");

		/*
		 * Yes, he's choked.  Don't spill the rest now get a callback
		 * when he is ready to send and take care of it there
		 */
		libwebsocket_callback_on_writable(
					     wsi->protocol->owning_server, wsi);
		wsi->extension_data_pending = 1;
		ret = 0;
	}

	return 0;
}

/**
 * libwebsocket_write() - Apply protocol then write data to client
 * @wsi:	Websocket instance (available from user callback)
 * @buf:	The data to send.  For data being sent on a websocket
 *		connection (ie, not default http), this buffer MUST have
 *		LWS_SEND_BUFFER_PRE_PADDING bytes valid BEFORE the pointer
 *		and an additional LWS_SEND_BUFFER_POST_PADDING bytes valid
 *		in the buffer after (buf + len).  This is so the protocol
 *		header and trailer data can be added in-situ.
 * @len:	Count of the data bytes in the payload starting from buf
 * @protocol:	Use LWS_WRITE_HTTP to reply to an http connection, and one
 *		of LWS_WRITE_BINARY or LWS_WRITE_TEXT to send appropriate
 *		data on a websockets connection.  Remember to allow the extra
 *		bytes before and after buf if LWS_WRITE_BINARY or LWS_WRITE_TEXT
 *		are used.
 *
 *	This function provides the way to issue data back to the client
 *	for both http and websocket protocols.
 *
 *	In the case of sending using websocket protocol, be sure to allocate
 *	valid storage before and after buf as explained above.  This scheme
 *	allows maximum efficiency of sending data and protocol in a single
 *	packet while not burdening the user code with any protocol knowledge.
 */

int libwebsocket_write(struct libwebsocket *wsi, unsigned char *buf,
			  size_t len, enum libwebsocket_write_protocol protocol)
{
	int n;
	int pre = 0;
	int post = 0;
	int shift = 7;
	int masked7 = wsi->mode == LWS_CONNMODE_WS_CLIENT &&
						  wsi->xor_mask != xor_no_mask;
	unsigned char *dropmask = NULL;
	unsigned char is_masked_bit = 0;
	struct lws_tokens eff_buf;
	int m;

	if (len == 0 && protocol != LWS_WRITE_CLOSE) {
		fprintf(stderr, "zero length libwebsocket_write attempt\n");
		return 0;
	}

	if (protocol == LWS_WRITE_HTTP)
		goto send_raw;

	/* websocket protocol, either binary or text */

	if (wsi->state != WSI_STATE_ESTABLISHED)
		return -1;

	/* give a change to the extensions to modify payload */
	eff_buf.token = (char *)buf;
	eff_buf.token_len = len;

	for (n = 0; n < wsi->count_active_extensions; n++) {
		m = wsi->active_extensions[n]->callback(
			wsi->protocol->owning_server,
			wsi->active_extensions[n], wsi,
			LWS_EXT_CALLBACK_PAYLOAD_TX,
			wsi->active_extensions_user[n], &eff_buf, 0);
		if (m < 0)
			return -1;
	}

	buf = (unsigned char *)eff_buf.token;
	len = eff_buf.token_len;

	switch (wsi->ietf_spec_revision) {
	/* chrome likes this as of 30 Oct 2010 */
	/* Firefox 4.0b6 likes this as of 30 Oct 2010 */
	case 0:
		if ((protocol & 0xf) == LWS_WRITE_BINARY) {
			/* in binary mode we send 7-bit used length blocks */
			pre = 1;
			while (len & (127 << shift)) {
				pre++;
				shift += 7;
			}
			n = 0;
			shift -= 7;
			while (shift >= 0) {
				if (shift)
					buf[0 - pre + n] =
						  ((len >> shift) & 127) | 0x80;
				else
					buf[0 - pre + n] =
						  ((len >> shift) & 127);
				n++;
				shift -= 7;
			}
			break;
		}

		/* frame type = text, length-free spam mode */

		pre = 1;
		buf[-pre] = 0;
		buf[len] = 0xff; /* EOT marker */
		post = 1;
		break;

	case 7:
	case 8:
	case 13:
		if (masked7) {
			pre += 4;
			dropmask = &buf[0 - pre];
			is_masked_bit = 0x80;
		}
		/* fallthru */
	case 4:
	case 5:
	case 6:
		switch (protocol & 0xf) {
		case LWS_WRITE_TEXT:
			if (wsi->ietf_spec_revision < 7)
				n = LWS_WS_OPCODE_04__TEXT_FRAME;
			else
				n = LWS_WS_OPCODE_07__TEXT_FRAME;
			break;
		case LWS_WRITE_BINARY:
			if (wsi->ietf_spec_revision < 7)
				n = LWS_WS_OPCODE_04__BINARY_FRAME;
			else
				n = LWS_WS_OPCODE_07__BINARY_FRAME;
			break;
		case LWS_WRITE_CONTINUATION:
			if (wsi->ietf_spec_revision < 7)
				n = LWS_WS_OPCODE_04__CONTINUATION;
			else
				n = LWS_WS_OPCODE_07__CONTINUATION;
			break;

		case LWS_WRITE_CLOSE:
			if (wsi->ietf_spec_revision < 7)
				n = LWS_WS_OPCODE_04__CLOSE;
			else
				n = LWS_WS_OPCODE_07__CLOSE;

			/*
			 * v5 mandates the first byte of close packet
			 * in both client and server directions
			 */

			switch (wsi->ietf_spec_revision) {
			case 0:
			case 4:
				break;
			case 5:
				/* we can do this because we demand post-buf */

				if (len < 1)
					len = 1;

				switch (wsi->mode) {
				case LWS_CONNMODE_WS_SERVING:
					/*
					fprintf(stderr, "LWS_WRITE_CLOSE S\n");
					*/
					buf[0] = 'S';
					break;
				case LWS_CONNMODE_WS_CLIENT:
					/*
					fprintf(stderr, "LWS_WRITE_CLOSE C\n");
					*/
					buf[0] = 'C';
					break;
				default:
					break;
				}
				break;
			default:
				/*
				 * 06 has a 2-byte status code in network order
				 * we can do this because we demand post-buf
				 */

				if (wsi->close_reason) {
					/* reason codes count as data bytes */
					buf -= 2;
					buf[0] = wsi->close_reason >> 8;
					buf[1] = wsi->close_reason;
					len += 2;
				}
				break;
			}
			break;
		case LWS_WRITE_PING:
			if (wsi->ietf_spec_revision < 7)
				n = LWS_WS_OPCODE_04__PING;
			else
				n = LWS_WS_OPCODE_07__PING;

			wsi->pings_vs_pongs++;
			break;
		case LWS_WRITE_PONG:
			if (wsi->ietf_spec_revision < 7)
				n = LWS_WS_OPCODE_04__PONG;
			else
				n = LWS_WS_OPCODE_07__PONG;
			break;
		default:
			fprintf(stderr, "libwebsocket_write: unknown write "
							 "opcode / protocol\n");
			return -1;
		}

		if (!(protocol & LWS_WRITE_NO_FIN))
			n |= 1 << 7;

		if (len < 126) {
			pre += 2;
			buf[-pre] = n;
			buf[-pre + 1] = len | is_masked_bit;
		} else {
			if (len < 65536) {
				pre += 4;
				buf[-pre] = n;
				buf[-pre + 1] = 126 | is_masked_bit;
				buf[-pre + 2] = len >> 8;
				buf[-pre + 3] = len;
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
				buf[-pre + 6] = len >> 24;
				buf[-pre + 7] = len >> 16;
				buf[-pre + 8] = len >> 8;
				buf[-pre + 9] = len;
			}
		}
		break;
	}

	/*
	 * Deal with masking if we are in client -> server direction and
	 * the protocol demands it
	 */

	if (wsi->mode == LWS_CONNMODE_WS_CLIENT &&
						 wsi->ietf_spec_revision >= 4) {

		/*
		 * this is only useful for security tests where it's required
		 * to control the raw packet payload content
		 */

		if (!(protocol & LWS_WRITE_CLIENT_IGNORE_XOR_MASK) &&
						wsi->xor_mask != xor_no_mask) {

			if (libwebsocket_0405_frame_mask_generate(wsi)) {
				fprintf(stderr, "libwebsocket_write: "
					      "frame mask generation failed\n");
				return 1;
			}


			if (wsi->ietf_spec_revision < 7)
				/*
				 * use the XOR masking against everything we
				 * send past the frame key
				 */
				for (n = -pre; n < ((int)len + post); n++)
					buf[n] = wsi->xor_mask(wsi, buf[n]);
			else
				/*
				 * in v7, just mask the payload
				 */
				for (n = 0; n < (int)len; n++)
					dropmask[n + 4] =
					   wsi->xor_mask(wsi, dropmask[n + 4]);


			if (wsi->ietf_spec_revision < 7) {
				/* make space for the frame nonce in clear */
				pre += 4;

				dropmask = &buf[0 - pre];
			}

			if (dropmask)
				/* copy the frame nonce into place */
				memcpy(dropmask,
					       wsi->frame_masking_nonce_04, 4);

		} else {
			if (wsi->ietf_spec_revision < 7) {

				/* make space for the frame nonce in clear */
				pre += 4;

				buf[0 - pre] = 0;
				buf[1 - pre] = 0;
				buf[2 - pre] = 0;
				buf[3 - pre] = 0;
			} else {
				if (dropmask && wsi->xor_mask != xor_no_mask) {
					dropmask[0] = 0;
					dropmask[1] = 0;
					dropmask[2] = 0;
					dropmask[3] = 0;
				}
			}
		}

	}

send_raw:

#if 0
	fprintf(stderr, "send %ld: ", len + post);
	for (n = -pre; n < ((int)len + post); n++)
		fprintf(stderr, "%02X ", buf[n]);

	fprintf(stderr, "\n");
#endif

	if (protocol == LWS_WRITE_HTTP) {
		if (lws_issue_raw(wsi, (unsigned char *)buf - pre,
							      len + pre + post))
			return -1;

		return 0;
	}

	/*
	 * give any active extensions a chance to munge the buffer
	 * before send.  We pass in a pointer to an lws_tokens struct
	 * prepared with the default buffer and content length that's in
	 * there.  Rather than rewrite the default buffer, extensions
	 * that expect to grow the buffer can adapt .token to
	 * point to their own per-connection buffer in the extension
	 * user allocation.  By default with no extensions or no
	 * extension callback handling, just the normal input buffer is
	 * used then so it is efficient.
	 *
	 * callback returns 1 in case it wants to spill more buffers
	 */

	return lws_issue_raw_ext_access(wsi, buf - pre, len + pre + post);
}


/**
 * libwebsockets_serve_http_file() - Send a file back to the client using http
 * @wsi:		Websocket instance (available from user callback)
 * @file:		The file to issue over http
 * @content_type:	The http content type, eg, text/html
 *
 *	This function is intended to be called from the callback in response
 *	to http requests from the client.  It allows the callback to issue
 *	local files down the http link in a single step.
 */

int libwebsockets_serve_http_file(struct libwebsocket *wsi, const char *file,
						       const char *content_type)
{
	int fd;
	struct stat stat_buf;
	char buf[512];
	char *p = buf;
	int n;

#ifdef WIN32
	fd = open(file, O_RDONLY | _O_BINARY);
#else
	fd = open(file, O_RDONLY);
#endif
	if (fd < 1) {
		p += sprintf(p, "HTTP/1.0 400 Bad\x0d\x0a"
			"Server: libwebsockets\x0d\x0a"
			"\x0d\x0a"
		);
		libwebsocket_write(wsi, (unsigned char *)buf, p - buf,
								LWS_WRITE_HTTP);

		return -1;
	}

	fstat(fd, &stat_buf);
	p += sprintf(p, "HTTP/1.0 200 OK\x0d\x0a"
			"Server: libwebsockets\x0d\x0a"
			"Content-Type: %s\x0d\x0a"
			"Content-Length: %u\x0d\x0a"
			"\x0d\x0a", content_type,
					(unsigned int)stat_buf.st_size);

	libwebsocket_write(wsi, (unsigned char *)buf, p - buf, LWS_WRITE_HTTP);

	n = 1;
	while (n > 0) {
		n = read(fd, buf, 512);
		if (n <= 0)
			continue;
		libwebsocket_write(wsi, (unsigned char *)buf, n,
								LWS_WRITE_HTTP);
	}

	close(fd);

	return 0;
}


/**
 * libwebsockets_remaining_packet_payload() - Bytes to come before "overall"
 *					      rx packet is complete
 * @wsi:		Websocket instance (available from user callback)
 *
 *	This function is intended to be called from the callback if the
 *  user code is interested in "complete packets" from the client.
 *  libwebsockets just passes through payload as it comes and issues a buffer
 *  additionally when it hits a built-in limit.  The LWS_CALLBACK_RECEIVE
 *  callback handler can use this API to find out if the buffer it has just
 *  been given is the last piece of a "complete packet" from the client --
 *  when that is the case libwebsockets_remaining_packet_payload() will return
 *  0.
 *
 *  Many protocols won't care becuse their packets are always small.
 */

size_t
libwebsockets_remaining_packet_payload(struct libwebsocket *wsi)
{
	return wsi->rx_packet_length;
}
