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

void md5(const unsigned char *input, int ilen, unsigned char output[16]);

static int interpret_key(const char *key, unsigned int *result)
{
	char digits[20];
	int digit_pos = 0;
	const char *p = key;
	int spaces = 0;
	
	while (*p) {
		if (isdigit(*p)) {
			if (digit_pos == sizeof(digits) - 1)
				return -1;
			digits[digit_pos++] = *p;
		}
		p++;
	}
	digits[digit_pos] = '\0';
	if (!digit_pos)
		return -2;
		
	while (*key) {
		if (*key == ' ')
			spaces++;
		key++;
	}
	
	if (!spaces)
		return -3;
		
	*result = atol(digits) / spaces;
	
	return 0;
}

/*
 * We have to take care about parsing because the headers may be split
 * into multiple fragments.  They may contain unknown headers with arbitrary
 * argument lengths.  So, we parse using a single-character at a time state
 * machine that is completely independent of packet size.
 */

int 
libwebsocket_read(struct libwebsocket *wsi, unsigned char * buf, size_t len)
{
	size_t n;
	char *p;
	unsigned int key1, key2;
	unsigned char sum[16];
	char *response;
	
	switch (wsi->state) {
	case WSI_STATE_HTTP:
		wsi->state = WSI_STATE_HTTP_HEADERS;
		wsi->parser_state = WSI_TOKEN_NAME_PART;
		/* fallthru */
	case WSI_STATE_HTTP_HEADERS:
	
		debug("issuing %d bytes to parser\n", (int)len);	
#ifdef DEBUG
		fwrite(buf, 1, len, stderr);
#endif
		for (n = 0; n< len; n++)
			libwebsocket_parse(wsi, *buf++);
			
		if (wsi->parser_state != WSI_PARSING_COMPLETE)
			break;

		/* is this websocket protocol or normal http 1.0? */
		
		if (!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
			     !wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len) {
			if (wsi->callback)
				(wsi->callback)(wsi, LWS_CALLBACK_HTTP,
							&wsi->user_space[0],
								       NULL, 0);
			wsi->state = WSI_STATE_HTTP;
			return 0;
		}

		/* Websocket - confirm we have all the necessary pieces */
		
		if (!wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len ||
			!wsi->utf8_token[WSI_TOKEN_HOST].token_len ||
			!wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len ||
			!wsi->utf8_token[WSI_TOKEN_KEY1].token_len ||
				     !wsi->utf8_token[WSI_TOKEN_KEY2].token_len)
			/* completed header processing, but missing some bits */
			goto bail;
		
		/* create the response packet */
		
		/* make a buffer big enough for everything */
		
		response = malloc(256 +
			wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len +
			wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len +
			wsi->utf8_token[WSI_TOKEN_HOST].token_len +
			wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len +
			wsi->utf8_token[WSI_TOKEN_GET_URI].token_len +
			wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len);
		if (!response) {
			fprintf(stderr, "Out of memory for response buffer\n");
			goto bail;
		}
		
		p = response;
		strcpy(p,   "HTTP/1.1 101 WebSocket Protocol Handshake\x0d\x0a"
						  "Upgrade: WebSocket\x0d\x0a");
		p += strlen("HTTP/1.1 101 WebSocket Protocol Handshake\x0d\x0a"
						  "Upgrade: WebSocket\x0d\x0a");
		strcpy(p,   "Connection: Upgrade\x0d\x0a"
			    "Sec-WebSocket-Origin: ");
		p += strlen("Connection: Upgrade\x0d\x0a"
			    "Sec-WebSocket-Origin: ");
		strcpy(p, wsi->utf8_token[WSI_TOKEN_ORIGIN].token);
		p += wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len;
#ifdef LWS_OPENSSL_SUPPORT
		if (use_ssl) {
			strcpy(p,   "\x0d\x0aSec-WebSocket-Location: wss://");
			p += strlen("\x0d\x0aSec-WebSocket-Location: wss://");
		} else {
#endif
			strcpy(p,   "\x0d\x0aSec-WebSocket-Location: ws://");
			p += strlen("\x0d\x0aSec-WebSocket-Location: ws://");
#ifdef LWS_OPENSSL_SUPPORT
		}
#endif
		strcpy(p, wsi->utf8_token[WSI_TOKEN_HOST].token);
		p += wsi->utf8_token[WSI_TOKEN_HOST].token_len;
		strcpy(p, wsi->utf8_token[WSI_TOKEN_GET_URI].token);
		p += wsi->utf8_token[WSI_TOKEN_GET_URI].token_len;

		if (wsi->utf8_token[WSI_TOKEN_PROTOCOL].token) {
			strcpy(p,   "\x0d\x0aSec-WebSocket-Protocol: ");
			p += strlen("\x0d\x0aSec-WebSocket-Protocol: ");
			strcpy(p, wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
			p += wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len;
		}

		strcpy(p,   "\x0d\x0a\x0d\x0a");
		p += strlen("\x0d\x0a\x0d\x0a");
		
		/* convert the two keys into 32-bit integers */
		
		if (interpret_key(wsi->utf8_token[WSI_TOKEN_KEY1].token, &key1))
			goto bail;
		if (interpret_key(wsi->utf8_token[WSI_TOKEN_KEY2].token, &key2))
			goto bail;
			
		/* lay them out in network byte order (MSB first */

		sum[0] = key1 >> 24;
		sum[1] = key1 >> 16;
		sum[2] = key1 >> 8;
		sum[3] = key1;
		sum[4] = key2 >> 24;
		sum[5] = key2 >> 16;
		sum[6] = key2 >> 8;
		sum[7] = key2;
		
		/* follow them with the challenge token we were sent */
		
		memcpy(&sum[8], wsi->utf8_token[WSI_TOKEN_CHALLENGE].token, 8);

		/* 
		 * compute the md5sum of that 16-byte series and use as our
		 * payload after our headers
		 */

		md5(sum, 16, (unsigned char *)p);
		p += 16;

		/* it's complete: go ahead and send it */
		
		debug("issuing response packet %d len\n",
							   (int)(p - response));
#ifdef DEBUG
		fwrite(response, 1,  p - response, stderr);
#endif
		n = libwebsocket_write(wsi, (unsigned char *)response, p - response,
								LWS_WRITE_HTTP);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			goto bail;
		}
		
		/* alright clean up and set ourselves into established state */

		free(response);
		wsi->state = WSI_STATE_ESTABLISHED;
		wsi->lws_rx_parse_state = LWS_RXPS_NEW;
		
		/* notify user code that we're ready to roll */
				
		if (wsi->callback)
			wsi->callback(wsi, LWS_CALLBACK_ESTABLISHED,
						&wsi->user_space[0], NULL, 0);
		break;

	case WSI_STATE_ESTABLISHED:
		if (libwebsocket_interpret_incoming_packet(wsi, buf, len) < 0)
			goto bail;
		break;
	default:
		break;
	}
	
	return 0;
	
bail:
	libwebsocket_close_and_free_session(wsi);
	return -1;
}
