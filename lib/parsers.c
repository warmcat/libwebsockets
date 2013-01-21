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


unsigned char lextable[] = {
/* pos 0: state 0 */
   0x47 /* 'G' */, 0x07 /* to pos 14 state 1 */,
   0x48 /* 'H' */, 0x0A /* to pos 22 state 5 */,
   0x43 /* 'C' */, 0x0F /* to pos 34 state 10 */,
   0x53 /* 'S' */, 0x19 /* to pos 56 state 21 */,
   0x55 /* 'U' */, 0x3F /* to pos 134 state 51 */,
   0x4F /* 'O' */, 0x46 /* to pos 150 state 59 */,
   0x8D /* '.' */, 0x52 /* to pos 176 state 72 */,
/* pos 14: state 1 */
   0xC5 /* 'E' */, 0x01 /* to pos 16 state 2 */,
/* pos 16: state 2 */
   0xD4 /* 'T' */, 0x01 /* to pos 18 state 3 */,
/* pos 18: state 3 */
   0xA0 /* ' ' */, 0x01 /* to pos 20 state 4 */,
/* pos 20: state 4 */
   0x80, 0x00 /* terminal marker */, 
/* pos 22: state 5 */
   0x6F /* 'o' */, 0x02 /* to pos 26 state 6 */,
   0xD4 /* 'T' */, 0x76 /* to pos 260 state 114 */,
/* pos 26: state 6 */
   0xF3 /* 's' */, 0x01 /* to pos 28 state 7 */,
/* pos 28: state 7 */
   0xF4 /* 't' */, 0x01 /* to pos 30 state 8 */,
/* pos 30: state 8 */
   0xBA /* ':' */, 0x01 /* to pos 32 state 9 */,
/* pos 32: state 9 */
   0x81, 0x00 /* terminal marker */, 
/* pos 34: state 10 */
   0xEF /* 'o' */, 0x01 /* to pos 36 state 11 */,
/* pos 36: state 11 */
   0xEE /* 'n' */, 0x01 /* to pos 38 state 12 */,
/* pos 38: state 12 */
   0xEE /* 'n' */, 0x01 /* to pos 40 state 13 */,
/* pos 40: state 13 */
   0xE5 /* 'e' */, 0x01 /* to pos 42 state 14 */,
/* pos 42: state 14 */
   0xE3 /* 'c' */, 0x01 /* to pos 44 state 15 */,
/* pos 44: state 15 */
   0xF4 /* 't' */, 0x01 /* to pos 46 state 16 */,
/* pos 46: state 16 */
   0xE9 /* 'i' */, 0x01 /* to pos 48 state 17 */,
/* pos 48: state 17 */
   0xEF /* 'o' */, 0x01 /* to pos 50 state 18 */,
/* pos 50: state 18 */
   0xEE /* 'n' */, 0x01 /* to pos 52 state 19 */,
/* pos 52: state 19 */
   0xBA /* ':' */, 0x01 /* to pos 54 state 20 */,
/* pos 54: state 20 */
   0x82, 0x00 /* terminal marker */, 
/* pos 56: state 21 */
   0xE5 /* 'e' */, 0x01 /* to pos 58 state 22 */,
/* pos 58: state 22 */
   0xE3 /* 'c' */, 0x01 /* to pos 60 state 23 */,
/* pos 60: state 23 */
   0xAD /* '-' */, 0x01 /* to pos 62 state 24 */,
/* pos 62: state 24 */
   0xD7 /* 'W' */, 0x01 /* to pos 64 state 25 */,
/* pos 64: state 25 */
   0xE5 /* 'e' */, 0x01 /* to pos 66 state 26 */,
/* pos 66: state 26 */
   0xE2 /* 'b' */, 0x01 /* to pos 68 state 27 */,
/* pos 68: state 27 */
   0xD3 /* 'S' */, 0x01 /* to pos 70 state 28 */,
/* pos 70: state 28 */
   0xEF /* 'o' */, 0x01 /* to pos 72 state 29 */,
/* pos 72: state 29 */
   0xE3 /* 'c' */, 0x01 /* to pos 74 state 30 */,
/* pos 74: state 30 */
   0xEB /* 'k' */, 0x01 /* to pos 76 state 31 */,
/* pos 76: state 31 */
   0xE5 /* 'e' */, 0x01 /* to pos 78 state 32 */,
/* pos 78: state 32 */
   0xF4 /* 't' */, 0x01 /* to pos 80 state 33 */,
/* pos 80: state 33 */
   0xAD /* '-' */, 0x01 /* to pos 82 state 34 */,
/* pos 82: state 34 */
   0x4B /* 'K' */, 0x08 /* to pos 98 state 35 */,
   0x50 /* 'P' */, 0x10 /* to pos 116 state 42 */,
   0x44 /* 'D' */, 0x27 /* to pos 164 state 66 */,
   0x56 /* 'V' */, 0x2F /* to pos 182 state 75 */,
   0x4F /* 'O' */, 0x36 /* to pos 198 state 83 */,
   0x45 /* 'E' */, 0x3C /* to pos 212 state 90 */,
   0x41 /* 'A' */, 0x46 /* to pos 234 state 101 */,
   0xCE /* 'N' */, 0x4C /* to pos 248 state 108 */,
/* pos 98: state 35 */
   0xE5 /* 'e' */, 0x01 /* to pos 100 state 36 */,
/* pos 100: state 36 */
   0xF9 /* 'y' */, 0x01 /* to pos 102 state 37 */,
/* pos 102: state 37 */
   0x31 /* '1' */, 0x03 /* to pos 108 state 38 */,
   0x32 /* '2' */, 0x04 /* to pos 112 state 40 */,
   0xBA /* ':' */, 0x25 /* to pos 180 state 74 */,
/* pos 108: state 38 */
   0xBA /* ':' */, 0x01 /* to pos 110 state 39 */,
/* pos 110: state 39 */
   0x83, 0x00 /* terminal marker */, 
/* pos 112: state 40 */
   0xBA /* ':' */, 0x01 /* to pos 114 state 41 */,
/* pos 114: state 41 */
   0x84, 0x00 /* terminal marker */, 
/* pos 116: state 42 */
   0xF2 /* 'r' */, 0x01 /* to pos 118 state 43 */,
/* pos 118: state 43 */
   0xEF /* 'o' */, 0x01 /* to pos 120 state 44 */,
/* pos 120: state 44 */
   0xF4 /* 't' */, 0x01 /* to pos 122 state 45 */,
/* pos 122: state 45 */
   0xEF /* 'o' */, 0x01 /* to pos 124 state 46 */,
/* pos 124: state 46 */
   0xE3 /* 'c' */, 0x01 /* to pos 126 state 47 */,
/* pos 126: state 47 */
   0xEF /* 'o' */, 0x01 /* to pos 128 state 48 */,
/* pos 128: state 48 */
   0xEC /* 'l' */, 0x01 /* to pos 130 state 49 */,
/* pos 130: state 49 */
   0xBA /* ':' */, 0x01 /* to pos 132 state 50 */,
/* pos 132: state 50 */
   0x85, 0x00 /* terminal marker */, 
/* pos 134: state 51 */
   0xF0 /* 'p' */, 0x01 /* to pos 136 state 52 */,
/* pos 136: state 52 */
   0xE7 /* 'g' */, 0x01 /* to pos 138 state 53 */,
/* pos 138: state 53 */
   0xF2 /* 'r' */, 0x01 /* to pos 140 state 54 */,
/* pos 140: state 54 */
   0xE1 /* 'a' */, 0x01 /* to pos 142 state 55 */,
/* pos 142: state 55 */
   0xE4 /* 'd' */, 0x01 /* to pos 144 state 56 */,
/* pos 144: state 56 */
   0xE5 /* 'e' */, 0x01 /* to pos 146 state 57 */,
/* pos 146: state 57 */
   0xBA /* ':' */, 0x01 /* to pos 148 state 58 */,
/* pos 148: state 58 */
   0x86, 0x00 /* terminal marker */, 
/* pos 150: state 59 */
   0xF2 /* 'r' */, 0x01 /* to pos 152 state 60 */,
/* pos 152: state 60 */
   0xE9 /* 'i' */, 0x01 /* to pos 154 state 61 */,
/* pos 154: state 61 */
   0xE7 /* 'g' */, 0x01 /* to pos 156 state 62 */,
/* pos 156: state 62 */
   0xE9 /* 'i' */, 0x01 /* to pos 158 state 63 */,
/* pos 158: state 63 */
   0xEE /* 'n' */, 0x01 /* to pos 160 state 64 */,
/* pos 160: state 64 */
   0xBA /* ':' */, 0x01 /* to pos 162 state 65 */,
/* pos 162: state 65 */
   0x87, 0x00 /* terminal marker */, 
/* pos 164: state 66 */
   0xF2 /* 'r' */, 0x01 /* to pos 166 state 67 */,
/* pos 166: state 67 */
   0xE1 /* 'a' */, 0x01 /* to pos 168 state 68 */,
/* pos 168: state 68 */
   0xE6 /* 'f' */, 0x01 /* to pos 170 state 69 */,
/* pos 170: state 69 */
   0xF4 /* 't' */, 0x01 /* to pos 172 state 70 */,
/* pos 172: state 70 */
   0xBA /* ':' */, 0x01 /* to pos 174 state 71 */,
/* pos 174: state 71 */
   0x88, 0x00 /* terminal marker */, 
/* pos 176: state 72 */
   0x8A /* '.' */, 0x01 /* to pos 178 state 73 */,
/* pos 178: state 73 */
   0x89, 0x00 /* terminal marker */, 
/* pos 180: state 74 */
   0x8A, 0x00 /* terminal marker */, 
/* pos 182: state 75 */
   0xE5 /* 'e' */, 0x01 /* to pos 184 state 76 */,
/* pos 184: state 76 */
   0xF2 /* 'r' */, 0x01 /* to pos 186 state 77 */,
/* pos 186: state 77 */
   0xF3 /* 's' */, 0x01 /* to pos 188 state 78 */,
/* pos 188: state 78 */
   0xE9 /* 'i' */, 0x01 /* to pos 190 state 79 */,
/* pos 190: state 79 */
   0xEF /* 'o' */, 0x01 /* to pos 192 state 80 */,
/* pos 192: state 80 */
   0xEE /* 'n' */, 0x01 /* to pos 194 state 81 */,
/* pos 194: state 81 */
   0xBA /* ':' */, 0x01 /* to pos 196 state 82 */,
/* pos 196: state 82 */
   0x8B, 0x00 /* terminal marker */, 
/* pos 198: state 83 */
   0xF2 /* 'r' */, 0x01 /* to pos 200 state 84 */,
/* pos 200: state 84 */
   0xE9 /* 'i' */, 0x01 /* to pos 202 state 85 */,
/* pos 202: state 85 */
   0xE7 /* 'g' */, 0x01 /* to pos 204 state 86 */,
/* pos 204: state 86 */
   0xE9 /* 'i' */, 0x01 /* to pos 206 state 87 */,
/* pos 206: state 87 */
   0xEE /* 'n' */, 0x01 /* to pos 208 state 88 */,
/* pos 208: state 88 */
   0xBA /* ':' */, 0x01 /* to pos 210 state 89 */,
/* pos 210: state 89 */
   0x8C, 0x00 /* terminal marker */, 
/* pos 212: state 90 */
   0xF8 /* 'x' */, 0x01 /* to pos 214 state 91 */,
/* pos 214: state 91 */
   0xF4 /* 't' */, 0x01 /* to pos 216 state 92 */,
/* pos 216: state 92 */
   0xE5 /* 'e' */, 0x01 /* to pos 218 state 93 */,
/* pos 218: state 93 */
   0xEE /* 'n' */, 0x01 /* to pos 220 state 94 */,
/* pos 220: state 94 */
   0xF3 /* 's' */, 0x01 /* to pos 222 state 95 */,
/* pos 222: state 95 */
   0xE9 /* 'i' */, 0x01 /* to pos 224 state 96 */,
/* pos 224: state 96 */
   0xEF /* 'o' */, 0x01 /* to pos 226 state 97 */,
/* pos 226: state 97 */
   0xEE /* 'n' */, 0x01 /* to pos 228 state 98 */,
/* pos 228: state 98 */
   0xF3 /* 's' */, 0x01 /* to pos 230 state 99 */,
/* pos 230: state 99 */
   0xBA /* ':' */, 0x01 /* to pos 232 state 100 */,
/* pos 232: state 100 */
   0x8D, 0x00 /* terminal marker */, 
/* pos 234: state 101 */
   0xE3 /* 'c' */, 0x01 /* to pos 236 state 102 */,
/* pos 236: state 102 */
   0xE3 /* 'c' */, 0x01 /* to pos 238 state 103 */,
/* pos 238: state 103 */
   0xE5 /* 'e' */, 0x01 /* to pos 240 state 104 */,
/* pos 240: state 104 */
   0xF0 /* 'p' */, 0x01 /* to pos 242 state 105 */,
/* pos 242: state 105 */
   0xF4 /* 't' */, 0x01 /* to pos 244 state 106 */,
/* pos 244: state 106 */
   0xBA /* ':' */, 0x01 /* to pos 246 state 107 */,
/* pos 246: state 107 */
   0x8E, 0x00 /* terminal marker */, 
/* pos 248: state 108 */
   0xEF /* 'o' */, 0x01 /* to pos 250 state 109 */,
/* pos 250: state 109 */
   0xEE /* 'n' */, 0x01 /* to pos 252 state 110 */,
/* pos 252: state 110 */
   0xE3 /* 'c' */, 0x01 /* to pos 254 state 111 */,
/* pos 254: state 111 */
   0xE5 /* 'e' */, 0x01 /* to pos 256 state 112 */,
/* pos 256: state 112 */
   0xBA /* ':' */, 0x01 /* to pos 258 state 113 */,
/* pos 258: state 113 */
   0x8F, 0x00 /* terminal marker */, 
/* pos 260: state 114 */
   0xD4 /* 'T' */, 0x01 /* to pos 262 state 115 */,
/* pos 262: state 115 */
   0xD0 /* 'P' */, 0x01 /* to pos 264 state 116 */,
/* pos 264: state 116 */
   0xAF /* '/' */, 0x01 /* to pos 266 state 117 */,
/* pos 266: state 117 */
   0xB1 /* '1' */, 0x01 /* to pos 268 state 118 */,
/* pos 268: state 118 */
   0xAE /* '.' */, 0x01 /* to pos 270 state 119 */,
/* pos 270: state 119 */
   0xB1 /* '1' */, 0x01 /* to pos 272 state 120 */,
/* pos 272: state 120 */
   0xA0 /* ' ' */, 0x01 /* to pos 274 state 121 */,
/* pos 274: state 121 */
   0x90, 0x00 /* terminal marker */, 
/* total size 276 bytes */
};

int lextable_decode(int pos, char c)
{
	while (pos >= 0) {
		if (lextable[pos + 1] == 0) // terminal marker
			return pos;

		if ((lextable[pos] & 0x7f) == c)
			return pos + (lextable[pos + 1] << 1);

		if (lextable[pos] & 0x80)
			return -1;

		pos += 2;
	}
	return pos;
}



int libwebsocket_parse(struct libwebsocket *wsi, unsigned char c)
{
	int n;

	switch (wsi->u.hdr.parser_state) {
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

		lwsl_parser("WSI_TOKEN_(%d) '%c'\n", wsi->u.hdr.parser_state, c);

		/* collect into malloc'd buffers */
		/* optional space swallow */
		if (!wsi->utf8_token[wsi->u.hdr.parser_state].token_len && c == ' ')
			break;

		/* special case space terminator for get-uri */
		if (wsi->u.hdr.parser_state == WSI_TOKEN_GET_URI && c == ' ') {
			wsi->utf8_token[wsi->u.hdr.parser_state].token[
			   wsi->utf8_token[wsi->u.hdr.parser_state].token_len] = '\0';
//			lwsl_parser("uri '%s'\n", wsi->utf8_token[wsi->u.hdr.parser_state].token);
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			break;
		}

		/* allocate appropriate memory */
		if (wsi->utf8_token[wsi->u.hdr.parser_state].token_len ==
						   wsi->u.hdr.current_alloc_len - 1) {
			/* need to extend */
			wsi->u.hdr.current_alloc_len += LWS_ADDITIONAL_HDR_ALLOC;
			if (wsi->u.hdr.current_alloc_len >= LWS_MAX_HEADER_LEN) {
				/* it's waaay to much payload, fail it */
				strcpy(wsi->utf8_token[wsi->u.hdr.parser_state].token,
				   "!!! Length exceeded maximum supported !!!");
				wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
				break;
			}
			wsi->utf8_token[wsi->u.hdr.parser_state].token = (char *)
			       realloc(wsi->utf8_token[wsi->u.hdr.parser_state].token,
							wsi->u.hdr.current_alloc_len);
			if (wsi->utf8_token[wsi->u.hdr.parser_state].token == NULL) {
				lwsl_err("Out of mem\n");
				return -1;
			}
		}

		/* bail at EOL */
		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE && c == '\x0d') {
			wsi->utf8_token[wsi->u.hdr.parser_state].token[
			   wsi->utf8_token[wsi->u.hdr.parser_state].token_len] = '\0';
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			lwsl_parser("*\n");
			break;
		}

		wsi->utf8_token[wsi->u.hdr.parser_state].token[
			    wsi->utf8_token[wsi->u.hdr.parser_state].token_len++] = c;

		/* per-protocol end of headers management */

		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE)
			break;

		/* -76 has no version header ... server */
		if (!wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
		   wsi->mode != LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY &&
			      wsi->utf8_token[wsi->u.hdr.parser_state].token_len != 8)
			break;

		/* -76 has no version header ... client */
		if (!wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
		   wsi->mode == LWS_CONNMODE_WS_CLIENT_WAITING_SERVER_REPLY &&
			wsi->utf8_token[wsi->u.hdr.parser_state].token_len != 16)
			break;

		/* <= 03 has old handshake with version header needs 8 bytes */
		if (wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
			 atoi(wsi->utf8_token[WSI_TOKEN_VERSION].token) < 4 &&
			      wsi->utf8_token[wsi->u.hdr.parser_state].token_len != 8)
			break;

		/* no payload challenge in 01 + */

		if (wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
			   atoi(wsi->utf8_token[WSI_TOKEN_VERSION].token) > 0) {
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len = 0;
			free(wsi->utf8_token[WSI_TOKEN_CHALLENGE].token);
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token = NULL;
		}

		/* For any supported protocol we have enough payload */

		lwsl_parser("Setting WSI_PARSING_COMPLETE\n");
		wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
		break;

	case WSI_INIT_TOKEN_MUXURL:
		wsi->u.hdr.parser_state = WSI_TOKEN_MUXURL;
		wsi->u.hdr.current_alloc_len = LWS_INITIAL_HDR_ALLOC;

		wsi->utf8_token[wsi->u.hdr.parser_state].token = (char *)
					 malloc(wsi->u.hdr.current_alloc_len);
		if (wsi->utf8_token[wsi->u.hdr.parser_state].token == NULL) {
			lwsl_err("Out of mem\n");
			return -1;
		}
		wsi->utf8_token[wsi->u.hdr.parser_state].token_len = 0;
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
		lwsl_parser("WSI_TOKEN_NAME_PART '%c'\n", c);

		if (wsi->u.hdr.name_buffer_pos == sizeof(wsi->u.hdr.name_buffer) - 1) {
			/* name bigger than we can handle, skip until next */
			wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
			break;
		}
		wsi->u.hdr.name_buffer[wsi->u.hdr.name_buffer_pos++] = c;
		wsi->u.hdr.name_buffer[wsi->u.hdr.name_buffer_pos] = '\0';

		wsi->u.hdr.lextable_pos = lextable_decode(wsi->u.hdr.lextable_pos, c);
		if (lextable[wsi->u.hdr.lextable_pos + 1] == 0) {

			n = lextable[wsi->u.hdr.lextable_pos] & 0x7f;

			lwsl_parser("known hdr '%s'\n", wsi->u.hdr.name_buffer);

			/*
			 * WSORIGIN is protocol equiv to ORIGIN,
			 * JWebSocket likes to send it, map to ORIGIN
			 */
			if (n == WSI_TOKEN_SWORIGIN)
				n = WSI_TOKEN_ORIGIN;

			wsi->u.hdr.parser_state = (enum lws_token_indexes) (WSI_TOKEN_GET_URI + n);

			n = WSI_TOKEN_COUNT;

			/*  If the header has been seen already, just append */
			if (!wsi->utf8_token[wsi->u.hdr.parser_state].token) {

				wsi->u.hdr.current_alloc_len = LWS_INITIAL_HDR_ALLOC;
				wsi->utf8_token[wsi->u.hdr.parser_state].token = (char *)
							 malloc(wsi->u.hdr.current_alloc_len);
				if (wsi->utf8_token[wsi->u.hdr.parser_state].token == NULL) {
					lwsl_err("Out of mem\n");
					return -1;
				}
				wsi->utf8_token[wsi->u.hdr.parser_state].token_len = 0;
			}
		}

		/* colon delimiter means we just don't know this name */

		if (wsi->u.hdr.parser_state == WSI_TOKEN_NAME_PART) {
			if (c == ':') {
				lwsl_parser("skipping unknown header '%s'\n",
							  wsi->u.hdr.name_buffer);
				wsi->u.hdr.parser_state = WSI_TOKEN_SKIPPING;
				break;
			}

			if (c == ' ' &&
				!wsi->utf8_token[WSI_TOKEN_GET_URI].token_len) {
				lwsl_parser("unknown method '%s'\n",
							  wsi->u.hdr.name_buffer);
				wsi->u.hdr.parser_state = WSI_TOKEN_GET_URI;
				wsi->u.hdr.current_alloc_len = LWS_INITIAL_HDR_ALLOC;
				wsi->utf8_token[WSI_TOKEN_GET_URI].token =
					(char *)malloc(wsi->u.hdr.current_alloc_len);
				if (wsi->utf8_token[WSI_TOKEN_GET_URI].token == NULL) {
					lwsl_err("Out of mem\n");
					return -1;
				}
				break;
			}
		}

		if (wsi->u.hdr.parser_state != WSI_TOKEN_CHALLENGE)
			break;

		/* don't look for payload when it can just be http headers */

		if (!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len) {
			/* they're HTTP headers, not websocket upgrade! */
			lwsl_parser("Setting WSI_PARSING_COMPLETE "
							 "from http headers\n");
			wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
		}

		/* 04 version has no packet content after end of hdrs */

		if (wsi->utf8_token[WSI_TOKEN_VERSION].token_len &&
			 atoi(wsi->utf8_token[WSI_TOKEN_VERSION].token) >= 4) {
			lwsl_parser("04 header completed\n");
			wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len = 0;
			free(wsi->utf8_token[WSI_TOKEN_CHALLENGE].token);
			wsi->utf8_token[WSI_TOKEN_CHALLENGE].token = NULL;
		}

		/* client parser? */

		lwsl_parser("04 header completed\n");
		wsi->u.hdr.parser_state = WSI_PARSING_COMPLETE;

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
		wsi->u.hdr.name_buffer_pos = 0;
		break;
		/* we're done, ignore anything else */
	case WSI_PARSING_COMPLETE:
		lwsl_parser("WSI_PARSING_COMPLETE '%c'\n", c);
		break;

	default:	/* keep gcc happy */
		break;
	}

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

int lws_frame_is_binary(struct libwebsocket *wsi)
{
	return wsi->u.ws.frame_is_binary;
}

int
libwebsocket_rx_sm(struct libwebsocket *wsi, unsigned char c)
{
	int n;
	struct lws_tokens eff_buf;
#ifndef LWS_NO_EXTENSIONS
	int handled;
	int m;
#endif

#if 0
	lwsl_debug("RX: %02X ", c);
#endif

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
			lwsl_warn("libwebsocket_rx_sm doesn't know "
			    "about spec version %d\n", wsi->ietf_spec_revision);
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

		wsi->u.ws.opcode = c & 0xf;
		wsi->u.ws.rsv = c & 0x70;
		wsi->u.ws.final = !!((c >> 7) & 1);
		switch (wsi->u.ws.opcode) {
		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
			wsi->u.ws.frame_is_binary = wsi->u.ws.opcode == LWS_WS_OPCODE_07__BINARY_FRAME;
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
				wsi->lws_rx_parse_state =
					LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED;
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
		break;


	case LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED:

		if (wsi->u.ws.all_zero_nonce)
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] = c;
		else
			wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING +
			       (wsi->u.ws.rx_user_buffer_head++)] =
		c ^ wsi->u.ws.frame_masking_nonce_04[(wsi->u.ws.frame_mask_index++) & 3];

		if (--wsi->u.ws.rx_packet_length == 0) {
			wsi->lws_rx_parse_state = LWS_RXPS_NEW;
			goto spill;
		}
		if (wsi->u.ws.rx_user_buffer_head != MAX_USER_RX_BUFFER)
			break;
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
			   &wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING],
				     wsi->u.ws.rx_user_buffer_head, LWS_WRITE_CLOSE);
			if (n)
				lwsl_info("write of close ack failed %d\n", n);
			wsi->state = WSI_STATE_RETURNED_CLOSE_ALREADY;
			/* close the connection */
			return -1;

		case LWS_WS_OPCODE_07__PING:
			lwsl_info("received %d byte ping, sending pong\n", wsi->u.ws.rx_user_buffer_head);
			lwsl_hexdump(&wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING], wsi->u.ws.rx_user_buffer_head);
			/* parrot the ping packet payload back as a pong */
			n = libwebsocket_write(wsi, (unsigned char *)
			    &wsi->u.ws.rx_user_buffer[LWS_SEND_BUFFER_PRE_PADDING], wsi->u.ws.rx_user_buffer_head, LWS_WRITE_PONG);
			/* ... then just drop it */
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__PONG:
			/* keep the statistics... */
			wsi->u.ws.pings_vs_pongs--;
			/* ... then just drop it */
			wsi->u.ws.rx_user_buffer_head = 0;
			return 0;

		case LWS_WS_OPCODE_07__TEXT_FRAME:
		case LWS_WS_OPCODE_07__BINARY_FRAME:
		case LWS_WS_OPCODE_07__CONTINUATION:
			break;

		default:
#ifndef LWS_NO_EXTENSIONS
			lwsl_parser("passing opcode %x up to exts\n", wsi->u.ws.opcode);

			/*
			 * It's something special we can't understand here.
			 * Pass the payload up to the extension's parsing
			 * state machine.
			 */

			eff_buf.token = &wsi->u.ws.rx_user_buffer[
						   LWS_SEND_BUFFER_PRE_PADDING];
			eff_buf.token_len = wsi->u.ws.rx_user_buffer_head;

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
#endif
				lwsl_ext("Unhandled extended opcode "
					"0x%x - ignoring frame\n", wsi->u.ws.opcode);

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
#ifndef LWS_NO_EXTENSIONS
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
#endif
		if (eff_buf.token_len > 0) {
		    eff_buf.token[eff_buf.token_len] = '\0';

		    if (wsi->protocol->callback)
			    user_callback_handle_rxflow(wsi->protocol->callback,
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

	return 0;

illegal_ctl_length:

	lwsl_warn("Control frame asking for "
			"extended length is illegal\n");
	/* kill the connection */
	return -1;
}


int libwebsocket_interpret_incoming_packet(struct libwebsocket *wsi,
						 unsigned char *buf, size_t len)
{
	size_t n;
	int m;
	int clear_rxflow = !!wsi->u.ws.rxflow_buffer;
	struct libwebsocket_context *context = wsi->protocol->owning_server;

#if 0
	lwsl_parser("received %d byte packet\n", (int)len);
	lwsl_hexdump(buf, len);
#endif

	if (buf && wsi->u.ws.rxflow_buffer)
		lwsl_err("!!!! libwebsocket_interpret_incoming_packet: was pending rxflow, data loss\n");

	/* let the rx protocol state machine have as much as it needs */

	n = 0;
	if (!buf) {
		lwsl_info("dumping stored rxflow buffer len %d pos=%d\n", wsi->u.ws.rxflow_len, wsi->u.ws.rxflow_pos);
		buf = wsi->u.ws.rxflow_buffer;
		n = wsi->u.ws.rxflow_pos;
		len = wsi->u.ws.rxflow_len;
		/* let's pretend he's already allowing input */
		context->fds[wsi->position_in_fds_table].events |= POLLIN;
	}

	while (n < len) {
		if (!(context->fds[wsi->position_in_fds_table].events & POLLIN)) {
			/* his RX is flowcontrolled */
			if (!wsi->u.ws.rxflow_buffer) { /* a new rxflow in effect, buffer it and warn caller */
				lwsl_info("new rxflow input buffer len %d\n", len - n);
				wsi->u.ws.rxflow_buffer = (unsigned char *)malloc(len - n);
				wsi->u.ws.rxflow_len = len - n;
				wsi->u.ws.rxflow_pos = 0;
				memcpy(wsi->u.ws.rxflow_buffer, buf + n, len - n);
			} else {
				lwsl_info("re-using rxflow input buffer\n");
				/* rxflow while we were spilling previous rxflow buffer */
				wsi->u.ws.rxflow_pos = n;
			}
			return 1;
		}
		m = libwebsocket_rx_sm(wsi, buf[n]);
		if (m < 0)
			return -1;
		n++;
	}

	if (clear_rxflow) {
		lwsl_info("flow: clearing it\n");
		free(wsi->u.ws.rxflow_buffer);
		wsi->u.ws.rxflow_buffer = NULL;
		context->fds[wsi->position_in_fds_table].events &= ~POLLIN;
	}

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
	return wsi->u.ws.rx_packet_length;
}
