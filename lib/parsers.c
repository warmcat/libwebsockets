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

unsigned char lextable[] = {
	#include "lextable.h"
};

#define FAIL_CHAR 0x08

int lextable_decode(int pos, char c)
{

	c = tolower(c);

	while (1) {
		if (lextable[pos] & (1 << 7)) { /* 1-byte, fail on mismatch */
			if ((lextable[pos] & 0x7f) != c)
				return -1;
			/* fall thru */
			pos++;
			if (lextable[pos] == FAIL_CHAR)
				return -1;
			return pos;
		}

		if (lextable[pos] == FAIL_CHAR)
			return -1;

		/* b7 = 0, end or 3-byte */
		if (lextable[pos] < FAIL_CHAR) /* terminal marker */
			return pos;

		if (lextable[pos] == c) /* goto */
			return pos + (lextable[pos + 1]) +
						(lextable[pos + 2] << 8);
		/* fall thru goto */
		pos += 3;
		/* continue */
	}
}

int lws_allocate_header_table(struct libwebsocket *wsi)
{
	/* Be sure to free any existing header data to avoid mem leak: */
	lws_free_header_table(wsi);
	wsi->u.hdr.ah = lws_malloc(sizeof(*wsi->u.hdr.ah));
	if (wsi->u.hdr.ah == NULL) {
		lwsl_err("Out of memory\n");
		return -1;
	}
	memset(wsi->u.hdr.ah->frag_index, 0, sizeof(wsi->u.hdr.ah->frag_index));
	wsi->u.hdr.ah->next_frag_index = 0;
	wsi->u.hdr.ah->pos = 0;

	return 0;
}

int lws_free_header_table(struct libwebsocket *wsi)
{
	lws_free2(wsi->u.hdr.ah);
	wsi->u.hdr.ah = NULL;
	return 0;
};

LWS_VISIBLE int lws_hdr_total_length(struct libwebsocket *wsi, enum lws_token_indexes h)
{
	int n;
	int len = 0;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;
	do {
		len += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].next_frag_index;
	} while (n);

	return len;
}

LWS_VISIBLE int lws_hdr_copy(struct libwebsocket *wsi, char *dest, int len,
						enum lws_token_indexes h)
{
	int toklen = lws_hdr_total_length(wsi, h);
	int n;

	if (toklen >= len)
		return -1;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return 0;

	do {
		strcpy(dest,
			&wsi->u.hdr.ah->data[wsi->u.hdr.ah->frags[n].offset]);
		dest += wsi->u.hdr.ah->frags[n].len;
		n = wsi->u.hdr.ah->frags[n].next_frag_index;
	} while (n);

	return toklen;
}

char *lws_hdr_simple_ptr(struct libwebsocket *wsi, enum lws_token_indexes h)
{
	int n;

	n = wsi->u.hdr.ah->frag_index[h];
	if (!n)
		return NULL;

	return &wsi->u.hdr.ah->data[wsi->u.hdr.ah->frags[n].offset];
}

int lws_hdr_simple_create(struct libwebsocket *wsi,
				enum lws_token_indexes h, const char *s)
{
	wsi->u.hdr.ah->next_frag_index++;
	if (wsi->u.hdr.ah->next_frag_index ==
	       sizeof(wsi->u.hdr.ah->frags) / sizeof(wsi->u.hdr.ah->frags[0])) {
		lwsl_warn("More hdr frags than we can deal with, dropping\n");
		return -1;
	}

	wsi->u.hdr.ah->frag_index[h] = wsi->u.hdr.ah->next_frag_index;

	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len = 0;
	wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].next_frag_index =
									      0;

	do {
		if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
			lwsl_err("Ran out of header data space\n");
			return -1;
		}
		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = *s;
		if (*s)
			wsi->u.hdr.ah->frags[
					wsi->u.hdr.ah->next_frag_index].len++;
	} while (*s++);

	return 0;
}

static char char_to_hex(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

static int issue_char(struct libwebsocket *wsi, unsigned char c)
{
	if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
		lwsl_warn("excessive header content\n");
		return -1;
	}

	if( wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len >= 
		wsi->u.hdr.current_token_limit) {
		lwsl_warn("header %i exceeds limit\n", wsi->u.hdr.parser_state);
		return 1;
	};

	wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = c;
	if (c)
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len++;

	return 0;
}

int libwebsocket_parse(
		struct libwebsocket_context *context,
		struct libwebsocket *wsi, unsigned char c)
{
	int n;

	switch (wsi->u.hdr.parser_state) {
	default:

		lwsl_parser("WSI_TOK_(%d) '%c'\n", wsi->u.hdr.parser_state, c);

		/* collect into malloc'd buffers */
		/* optional initial space swallow */
		if (!wsi->u.hdr.ah->frags[wsi->u.hdr.ah->frag_index[
				      wsi->u.hdr.parser_state]].len && c == ' ')
			break;

		if ((wsi->u.hdr.parser_state != WSI_TOKEN_GET_URI) &&
			(wsi->u.hdr.parser_state != WSI_TOKEN_POST_URI) &&
			(wsi->u.hdr.parser_state != WSI_TOKEN_OPTIONS_URI))
			goto check_eol;

		/* special URI processing... end at space */

		if (c == ' ') {
			/* enforce starting with / */
			if (!wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len)
				if (issue_char(wsi, '/') < 0)
					return -1;

			/* begin parsing HTTP version: */
			if (issue_char(wsi, '\0') < 0)
				return -1;
			wsi->u.hdr.parser_state = WSI_TOKEN_HTTP;
			goto start_fragment;
		}

		/* special URI processing... convert %xx */

		switch (wsi->u.hdr.ues) {
		case URIES_IDLE:
			if (c == '%') {
				wsi->u.hdr.ues = URIES_SEEN_PERCENT;
				goto swallow;
			}
			break;
		case URIES_SEEN_PERCENT:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				if (issue_char(wsi, '%') < 0)
					return -1;
				wsi->u.hdr.ues = URIES_IDLE;
				/* continue on to assess c */
				break;
			}
			wsi->u.hdr.esc_stash = c;
			wsi->u.hdr.ues = URIES_SEEN_PERCENT_H1;
			goto swallow;
			
		case URIES_SEEN_PERCENT_H1:
			if (char_to_hex(c) < 0) {
				/* regurgitate */
				issue_char(wsi, '%');
				wsi->u.hdr.ues = URIES_IDLE;
				/* regurgitate + assess */
				if (libwebsocket_parse(context, wsi, wsi->u.hdr.esc_stash) < 0)
					return -1;
				/* continue on to assess c */
				break;
			}
			c = (char_to_hex(wsi->u.hdr.esc_stash) << 4) |
					char_to_hex(c);
			wsi->u.hdr.ues = URIES_IDLE;
			break;
		}

		/*
		 * special URI processing... 
		 *  convert /.. or /... or /../ etc to /
		 *  convert /./ to /
		 *  convert // or /// etc to /
		 *  leave /.dir or whatever alone
		 */

		switch (wsi->u.hdr.ups) {
		case URIPS_IDLE:
			/* issue the first / always */
			if (c == '/')
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_SEEN_SLASH:
			/* swallow subsequent slashes */
			if (c == '/')
				goto swallow;
			/* track and swallow the first . after / */
			if (c == '.') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT;
				goto swallow;
			}
			wsi->u.hdr.ups = URIPS_IDLE;
			break;
		case URIPS_SEEN_SLASH_DOT:
			/* swallow second . */
			if (c == '.') {
				/* 
				 * back up one dir level if possible
				 * safe against header fragmentation because
				 * the method URI can only be in 1 fragment
				 */
				if (wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len > 2) {
					wsi->u.hdr.ah->pos--;
					wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len--;
					do {
						wsi->u.hdr.ah->pos--;
						wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len--;
					} while (wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len > 1 &&
							wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos] != '/');
				}
				wsi->u.hdr.ups = URIPS_SEEN_SLASH_DOT_DOT;
				goto swallow;
			}
			/* change /./ to / */
			if (c == '/') {
				wsi->u.hdr.ups = URIPS_SEEN_SLASH;
				goto swallow;
			}
			/* it was like /.dir ... regurgitate the . */
			wsi->u.hdr.ups = URIPS_IDLE;
			issue_char(wsi, '.');
			break;
			
		case URIPS_SEEN_SLASH_DOT_DOT:
			/* swallow prior .. chars and any subsequent . */
			if (c == '.')
				goto swallow;
			/* last issued was /, so another / == // */
			if (c == '/')
				goto swallow;
			/* last we issued was / so SEEN_SLASH */
			wsi->u.hdr.ups = URIPS_SEEN_SLASH;
			break;
		case URIPS_ARGUMENTS:
			/* leave them alone */
			break;
		}

		if (c == '?') { /* start of URI arguments */
			/* seal off uri header */
			wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = '\0';

			/* move to using WSI_TOKEN_HTTP_URI_ARGS */
			wsi->u.hdr.ah->next_frag_index++;
			wsi->u.hdr.ah->frags[
				wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
			wsi->u.hdr.ah->frags[
					wsi->u.hdr.ah->next_frag_index].len = 0;
			wsi->u.hdr.ah->frags[
			    wsi->u.hdr.ah->next_frag_index].next_frag_index = 0;

			wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP_URI_ARGS] =
						 wsi->u.hdr.ah->next_frag_index;

			/* defeat normal uri path processing */
			wsi->u.hdr.ups = URIPS_ARGUMENTS;
			goto swallow;
		}

check_eol:

		/* bail at EOL */
		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE &&
								  c == '\x0d') {
			c = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			lwsl_parser("*\n");
		}

		n = issue_char(wsi, c);
		if (n < 0)
			return -1;
		if (n > 0)
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;

swallow:
		/* per-protocol end of headers management */

		if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
			goto set_parsing_complete;
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
		lwsl_parser("WSI_TOKEN_NAME_PART '%c'\n", c);

		wsi->u.hdr.lextable_pos =
				lextable_decode(wsi->u.hdr.lextable_pos, c);

		if (wsi->u.hdr.lextable_pos < 0) {
			/* this is not a header we know about */
			if (wsi->u.hdr.ah->frag_index[WSI_TOKEN_GET_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_POST_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_OPTIONS_URI] ||
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP]) {
				/*
				 * already had the method, no idea what
				 * this crap is, ignore
				 */
				wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
				break;
			}
			/*
			 * hm it's an unknown http method in fact,
			 * treat as dangerous
			 */

			lwsl_info("Unknown method - dropping\n");
			return -1;
		}
		if (lextable[wsi->u.hdr.lextable_pos] < FAIL_CHAR) {

			/* terminal state */

			n = ((unsigned int)lextable[wsi->u.hdr.lextable_pos] << 8) |
					lextable[wsi->u.hdr.lextable_pos + 1];

			lwsl_parser("known hdr %d\n", n);
			if (n == WSI_TOKEN_GET_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_GET_URI]) {
				lwsl_warn("Duplicated GET\n");
				return -1;
			}
			if (n == WSI_TOKEN_POST_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_POST_URI]) {
				lwsl_warn("Duplicated POST\n");
				return -1;
			}
			if (n == WSI_TOKEN_OPTIONS_URI &&
				wsi->u.hdr.ah->frag_index[WSI_TOKEN_OPTIONS_URI]) {
				lwsl_warn("Duplicated OPTIONS\n");
				return -1;
			}

			/*
			 * WSORIGIN is protocol equiv to ORIGIN,
			 * JWebSocket likes to send it, map to ORIGIN
			 */
			if (n == WSI_TOKEN_SWORIGIN)
				n = WSI_TOKEN_ORIGIN;

			wsi->u.hdr.parser_state = (enum lws_token_indexes)
							(WSI_TOKEN_GET_URI + n);

			if (context->token_limits)
				wsi->u.hdr.current_token_limit =
					context->token_limits->token_limit[wsi->u.hdr.parser_state];
			else
				wsi->u.hdr.current_token_limit = sizeof(wsi->u.hdr.ah->data);

			if (wsi->u.hdr.parser_state == WSI_TOKEN_CHALLENGE)
				goto set_parsing_complete;

			goto start_fragment;
		}
		break;

start_fragment:
		wsi->u.hdr.ah->next_frag_index++;
		if (wsi->u.hdr.ah->next_frag_index ==
				sizeof(wsi->u.hdr.ah->frags) /
					      sizeof(wsi->u.hdr.ah->frags[0])) {
			lwsl_warn("More hdr frags than we can deal with\n");
			return -1;
		}

		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].offset =
							     wsi->u.hdr.ah->pos;
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len = 0;
		wsi->u.hdr.ah->frags[
			    wsi->u.hdr.ah->next_frag_index].next_frag_index = 0;

		n = wsi->u.hdr.ah->frag_index[wsi->u.hdr.parser_state];
		if (!n) { /* first fragment */
			wsi->u.hdr.ah->frag_index[wsi->u.hdr.parser_state] =
						 wsi->u.hdr.ah->next_frag_index;
			break;
		}
		/* continuation */
		while (wsi->u.hdr.ah->frags[n].next_frag_index)
				n = wsi->u.hdr.ah->frags[n].next_frag_index;
		wsi->u.hdr.ah->frags[n].next_frag_index =
						 wsi->u.hdr.ah->next_frag_index;

		if (wsi->u.hdr.ah->pos == sizeof(wsi->u.hdr.ah->data)) {
			lwsl_warn("excessive header content\n");
			return -1;
		}

		wsi->u.hdr.ah->data[wsi->u.hdr.ah->pos++] = ' ';
		wsi->u.hdr.ah->frags[wsi->u.hdr.ah->next_frag_index].len++;
		break;

		/* skipping arg part of a name we didn't recognize */
	case WSI_TOKEN_SKIPPING:
		lwsl_parser("WSI_TOKEN_SKIPPING '%c'\n", c);

		if (c == '\x0d')
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
		break;

	case WSI_TOKEN_SKIPPING_SAW_CR:
		lwsl_parser("WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
		if (c == '\x0a') {
			wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
			wsi->u.hdr.lextable_pos = 0;
		} else
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
		break;
		/* we're done, ignore anything else */

	case WSI_PARSING_COMPLETE:
		lwsl_parser("WSI_PARSING_COMPLETE '%c'\n", c);
		break;
	}

	return 0;

set_parsing_complete:

	if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
		if (lws_hdr_total_length(wsi, WSI_TOKEN_VERSION))
			wsi->ietf_spec_revision =
			       atoi(lws_hdr_simple_ptr(wsi, WSI_TOKEN_VERSION));

		lwsl_parser("v%02d hdrs completed\n", wsi->ietf_spec_revision);
	}
	wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
	wsi->hdr_parsing_completed = 1;

	return 0;
}


/**
 * lws_frame_is_binary: true if the current frame was sent in binary mode
 *
 * @wsi: the connection we are inquiring about
 *
 * This is intended to be called from the LWS_CALLBACK_RECEIVE callback if
 * it's interested to see if the frame it's dealing with was sent in binary
 * mode.
 */

LWS_VISIBLE int lws_frame_is_binary(struct libwebsocket *wsi)
{
	return wsi->u.ws.frame_is_binary;
}

int
libwebsocket_rx_sm(struct libwebsocket *wsi, unsigned char c)
{
	int n;
	struct lws_tokens eff_buf;
	int ret = 0;

	switch (wsi->lws_rx_parse_state) {
	case LWS_RXPS_NEW:

		switch (wsi->ietf_spec_revision) {
		case 13:
			/*
			 * no prepended frame key any more
			 */
			wsi->u.ws.all_zero_nonce = 1;
			goto handle_first;

		default:
			lwsl_warn("lws_rx_sm: unknown spec version %d\n",
						       wsi->ietf_spec_revision);
			break;
		}
		break;
	case LWS_RXPS_04_MASK_NONCE_1:
		wsi->u.ws.frame_masking_nonce_04[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_2;
		break;
	case LWS_RXPS_04_MASK_NONCE_2:
		wsi->u.ws.frame_masking_nonce_04[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_04_MASK_NONCE_3;
		break;
	case LWS_RXPS_04_MASK_NONCE_3:
		wsi->u.ws.frame_masking_nonce_04[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;

		/*
		 * start from the zero'th byte in the XOR key buffer since
		 * this is the start of a frame with a new key
		 */

		wsi->u.ws.frame_mask_index = 0;

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

		wsi->u.ws.opcode = c & 0xf;
		wsi->u.ws.rsv = c & 0x70;
		wsi->u.ws.final = !!((c >> 7) & 1);

		switch (wsi->u.ws.opcode) {
		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
			wsi->u.ws.frame_is_binary =
			     wsi->u.ws.opcode == LWS_WS_OPCODE_07__BINARY_FRAME;
			break;
		}
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN:

		wsi->u.ws.this_frame_masked = !!(c & 0x80);

		switch (c & 0x7f) {
		case 126:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_2;
			break;
		case 127:
			/* control frames are not allowed to have big lengths */
			if (wsi->u.ws.opcode & 8)
				goto illegal_ctl_length;

			wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_8;
			break;
		default:
			wsi->u.ws.rx_packet_length = c & 0x7f;
			if (wsi->u.ws.this_frame_masked)
				wsi->lws_rx_parse_state =
						LWS_RXPS_07_COLLECT_FRAME_KEY_1;
			else
				if (wsi->u.ws.rx_packet_length)
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
		wsi->u.ws.rx_packet_length = c << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN16_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN16_1:
		wsi->u.ws.rx_packet_length |= c;
		if (wsi->u.ws.this_frame_masked)
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
		wsi->u.ws.rx_packet_length = ((size_t)c) << 56;
#else
		wsi->u.ws.rx_packet_length = 0;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_7;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_7:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 48;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_6;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_6:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 40;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_5;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_5:
#if defined __LP64__
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 32;
#endif
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_4;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_4:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 24;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_3;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_3:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 16;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_2;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_2:
		wsi->u.ws.rx_packet_length |= ((size_t)c) << 8;
		wsi->lws_rx_parse_state = LWS_RXPS_04_FRAME_HDR_LEN64_1;
		break;

	case LWS_RXPS_04_FRAME_HDR_LEN64_1:
		wsi->u.ws.rx_packet_length |= ((size_t)c);
		if (wsi->u.ws.this_frame_masked)
			wsi->lws_rx_parse_state =
					LWS_RXPS_07_COLLECT_FRAME_KEY_1;
		else
			wsi->lws_rx_parse_state =
				LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_1:
		wsi->u.ws.frame_masking_nonce_04[0] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_2;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_2:
		wsi->u.ws.frame_masking_nonce_04[1] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_3;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_3:
		wsi->u.ws.frame_masking_nonce_04[2] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state = LWS_RXPS_07_COLLECT_FRAME_KEY_4;
		break;

	case LWS_RXPS_07_COLLECT_FRAME_KEY_4:
		wsi->u.ws.frame_masking_nonce_04[3] = c;
		if (c)
			wsi->u.ws.all_zero_nonce = 0;
		wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
		wsi->u.ws.frame_mask_index = 0;
		if (wsi->u.ws.rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:

		if (!wsi->u.ws.rx_user_buffer) {
			lwsl_err("NULL user buffer...\n");
			return 1;
		}

		if (wsi->u.ws.all_zero_nonce)
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] = c;
		else
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] =
				   c ^ wsi->u.ws.frame_masking_nonce_04[
					    (wsi->u.ws.frame_mask_index++) & 3];

		if (--wsi->u.ws.rx_packet_length == 0) {
			/* spill because we have the whole frame */
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}

		/*
		 * if there's no protocol max frame size given, we are
		 * supposed to default to LWS_MAX_SOCKET_IO_BUF
		 */

		if (!wsi->protocol->rx_buffer_size &&
			 		wsi->u.ws.rx_user_buffer_head !=
			 				  LWS_MAX_SOCKET_IO_BUF)
			break;
		else
			if (wsi->protocol->rx_buffer_size &&
					wsi->u.ws.rx_user_buffer_head !=
						  wsi->protocol->rx_buffer_size)
			break;

		/* spill because we filled our rx buffer */
spill:
		/*
		 * is this frame a control packet we should take care of at this
		 * layer?  If so service it and hide it from the user callback
		 */

		lwsl_parser("spill on %s\n", wsi->protocol->name);

		switch (wsi->u.ws.opcode) {
		case LWS_WS_OPCODE_07__CLOSE:
			/* is this an acknowledgement of our close? */
			if (wsi->state == WSI_STATE_AWAITING_CLOSE_ACK) {
				/*
				 * fine he has told us he is closing too, let's
				 * finish our close
				 */
				lwsl_parser("seen client close ack\n");
				return -1;
			}
			lwsl_parser("server sees client close packet\n");
			/* parrot the close packet payload back */
			n = libwebsocket_write(wsi, (unsigned char *)
				&wsi->u.ws.rx_user_buffer[
					LWS_SEND_BUFFER_PRE_PADDING],
					wsi->u.ws.rx_user_buffer_head,
							       LWS_WRITE_CLOSE);
			if (n < 0)
				lwsl_info("write of close ack failed %d\n", n);
			wsi->state = WSI_STATE_RETURNED_CLOSE_ALREADY;
			/* close the connection */
			return -1;

		case LWS_WS_OPCODE_07__PING:
			lwsl_info("received %d byte ping, sending pong\n",
						 wsi->u.ws.rx_user_buffer_head);

			if (wsi->u.ws.ping_payload_len) {
				/* 
				 * there is already a pending ping payload
				 * we should just log and drop
				 */
				lwsl_parser("DROP PING since one pending\n");
				goto ping_drop;
			}
			
			/* control packets can only be < 128 bytes long */
			if (wsi->u.ws.ping_payload_len > 128 - 4) {
				lwsl_parser("DROP PING payload too large\n");
				goto ping_drop;
			}
			
			/* if existing buffer is too small, drop it */
			if (wsi->u.ws.ping_payload_buf &&
			    wsi->u.ws.ping_payload_alloc < wsi->u.ws.rx_user_buffer_head) {
				lws_free2(wsi->u.ws.ping_payload_buf);
			}

			/* if no buffer, allocate it */
			if (!wsi->u.ws.ping_payload_buf) {
				wsi->u.ws.ping_payload_buf = lws_malloc(wsi->u.ws.rx_user_buffer_head
									+ LWS_SEND_BUFFER_PRE_PADDING);
				wsi->u.ws.ping_payload_alloc = wsi->u.ws.rx_user_buffer_head;
			}
			
			/* stash the pong payload */
			memcpy(wsi->u.ws.ping_payload_buf + LWS_SEND_BUFFER_PRE_PADDING,
			       &wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				wsi->u.ws.rx_user_buffer_head);
			
			wsi->u.ws.ping_payload_len = wsi->u.ws.rx_user_buffer_head;
			
			/* get it sent as soon as possible */
			libwebsocket_callback_on_writable(wsi->protocol->owning_server, wsi);
ping_drop:
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__PONG:
			/* ... then just drop it */
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
		case LWS_WS_OPCODE_07__CONTINUATION:
			break;

		default:
			lwsl_parser("passing opc %x up to exts\n",
							wsi->u.ws.opcode);
			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->u.ws.rx_user_buffer[
						   LWS_SEND_BUFFER_PRE_PADDING];
			eff_buf.token_len = wsi->u.ws.rx_user_buffer_head;

			if (lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_EXTENDED_PAYLOAD_RX,
					&eff_buf, 0) <= 0) /* not handle or fail */
				lwsl_ext("ext opc opcode 0x%x unknown\n",
							      wsi->u.ws.opcode);

			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;
		}

		/*
		 * No it's real payload, pass it up to the user callback.
		 * It's nicely buffered with the pre-padding taken care of
		 * so it can be sent straight out again using libwebsocket_write
		 */

		eff_buf.token = &wsi->u.ws.rx_user_buffer[
						LWS_SEND_BUFFER_PRE_PADDING];
		eff_buf.token_len = wsi->u.ws.rx_user_buffer_head;
		
		if (lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_PAYLOAD_RX, &eff_buf, 0) < 0)
			return -1;

		if (eff_buf.token_len > 0) {
			eff_buf.token[eff_buf.token_len] = '\0';

			if (wsi->protocol->callback)
				ret = user_callback_handle_rxflow(
						wsi->protocol->callback,
						wsi->protocol->owning_server,
						wsi, LWS_CALLBACK_RECEIVE,
						wsi->user_space,
						eff_buf.token,
						eff_buf.token_len);
		    else
			    lwsl_err("No callback on payload spill!\n");
		}

		wsi->u.ws.rx_user_buffer_head = 0;
		break;
	}

	return ret;

illegal_ctl_length:

	lwsl_warn("Control frame with xtended length is illegal\n");
	/* kill the connection */
	return -1;
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

LWS_VISIBLE size_t
libwebsockets_remaining_packet_payload(struct libwebsocket *wsi)
{
	return wsi->u.ws.rx_packet_length;
}
