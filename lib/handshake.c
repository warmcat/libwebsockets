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

#define LWS_CPYAPP(ptr, str) { strcpy(ptr, str); ptr += strlen(str); }
#define LWS_CPYAPP_TOKEN(ptr, tok) { strcpy(p, wsi->utf8_token[tok].token); \
		p += wsi->utf8_token[tok].token_len; }

static int
interpret_key(const char *key, unsigned long *result)
{
	char digits[20];
	int digit_pos = 0;
	const char *p = key;
	unsigned int spaces = 0;
	unsigned long acc = 0;
	int rem = 0;

	while (*p) {
		if (!isdigit(*p)) {
			p++;
			continue;
		}
		if (digit_pos == sizeof(digits) - 1)
			return -1;
		digits[digit_pos++] = *p++;
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

	p = &digits[0];
	while (*p) {
		rem = (rem * 10) + ((*p++) - '0');
		acc = (acc * 10) + (rem / spaces);
		rem -= (rem / spaces) * spaces;
	}

	if (rem) {
		fprintf(stderr, "nonzero handshake remainder\n");
		return -1;
	}

	*result = acc;

	return 0;
}


static int
handshake_00(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	unsigned long key1, key2;
	unsigned char sum[16];
	char *response;
	char *p;
	int n;

	/* Confirm we have all the necessary pieces */

	if (!wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len ||
		!wsi->utf8_token[WSI_TOKEN_HOST].token_len ||
		!wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len ||
		!wsi->utf8_token[WSI_TOKEN_KEY1].token_len ||
			     !wsi->utf8_token[WSI_TOKEN_KEY2].token_len)
		/* completed header processing, but missing some bits */
		goto bail;

	/* allocate the per-connection user memory (if any) */
	if (wsi->protocol->per_session_data_size &&
					  !libwebsocket_ensure_user_space(wsi))
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
	LWS_CPYAPP(p, "HTTP/1.1 101 WebSocket Protocol Handshake\x0d\x0a"
		      "Upgrade: WebSocket\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Sec-WebSocket-Origin: ");
	strcpy(p, wsi->utf8_token[WSI_TOKEN_ORIGIN].token);
	p += wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len;
#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Location: wss://");
	} else {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Location: ws://");
	}
#else
	LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Location: ws://");
#endif

	LWS_CPYAPP_TOKEN(p, WSI_TOKEN_HOST);
	LWS_CPYAPP_TOKEN(p, WSI_TOKEN_GET_URI);

	if (wsi->utf8_token[WSI_TOKEN_PROTOCOL].token) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Protocol: ");
		LWS_CPYAPP_TOKEN(p, WSI_TOKEN_PROTOCOL);
	}

	LWS_CPYAPP(p, "\x0d\x0a\x0d\x0a");

	/* convert the two keys into 32-bit integers */

	if (interpret_key(wsi->utf8_token[WSI_TOKEN_KEY1].token, &key1))
		goto bail;
	if (interpret_key(wsi->utf8_token[WSI_TOKEN_KEY2].token, &key2))
		goto bail;

	/* lay them out in network byte order (MSB first */

	sum[0] = (unsigned char)(key1 >> 24);
	sum[1] = (unsigned char)(key1 >> 16);
	sum[2] = (unsigned char)(key1 >> 8);
	sum[3] = (unsigned char)(key1);
	sum[4] = (unsigned char)(key2 >> 24);
	sum[5] = (unsigned char)(key2 >> 16);
	sum[6] = (unsigned char)(key2 >> 8);
	sum[7] = (unsigned char)(key2);

	/* follow them with the challenge token we were sent */

	memcpy(&sum[8], wsi->utf8_token[WSI_TOKEN_CHALLENGE].token, 8);

	/*
	 * compute the md5sum of that 16-byte series and use as our
	 * payload after our headers
	 */

	MD5(sum, 16, (unsigned char *)p);
	p += 16;

	/* it's complete: go ahead and send it */

	debug("issuing response packet %d len\n", (int)(p - response));
#ifdef DEBUG
	fwrite(response, 1,  p - response, stderr);
#endif
	n = libwebsocket_write(wsi, (unsigned char *)response,
					  p - response, LWS_WRITE_HTTP);
	if (n < 0) {
		fprintf(stderr, "ERROR writing to socket");
		goto bail;
	}

	/* alright clean up and set ourselves into established state */

	free(response);
	wsi->state = WSI_STATE_ESTABLISHED;
	wsi->lws_rx_parse_state = LWS_RXPS_NEW;

	/* notify user code that we're ready to roll */

	if (wsi->protocol->callback)
		wsi->protocol->callback(wsi->protocol->owning_server,
				wsi, LWS_CALLBACK_ESTABLISHED,
					  wsi->user_space, NULL, 0);

	return 0;

bail:
	return -1;
}

/*
 * Perform the newer BASE64-encoded handshake scheme
 */

static int
handshake_0405(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	static const char *websocket_magic_guid_04 =
					 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	static const char *websocket_magic_guid_04_masking =
					 "61AC5F19-FBBA-4540-B96F-6561F1AB40A8";
	char accept_buf[MAX_WEBSOCKET_04_KEY_LEN + 37];
	char nonce_buf[256];
	char mask_summing_buf[256 + MAX_WEBSOCKET_04_KEY_LEN + 37];
	unsigned char hash[20];
	int n;
	char *response;
	char *p;
	char *m = mask_summing_buf;
	int nonce_len = 0;
	int accept_len;
	char *c;
	char ext_name[128];
	struct libwebsocket_extension *ext;
	int ext_count = 0;
	int more = 1;

	if (!wsi->utf8_token[WSI_TOKEN_HOST].token_len ||
	    !wsi->utf8_token[WSI_TOKEN_KEY].token_len) {
		debug("handshake_04 missing pieces\n");
		/* completed header processing, but missing some bits */
		goto bail;
	}

	if (wsi->utf8_token[WSI_TOKEN_KEY].token_len >=
						     MAX_WEBSOCKET_04_KEY_LEN) {
		fprintf(stderr, "Client sent handshake key longer "
			   "than max supported %d\n", MAX_WEBSOCKET_04_KEY_LEN);
		goto bail;
	}

	strcpy(accept_buf, wsi->utf8_token[WSI_TOKEN_KEY].token);
	strcpy(accept_buf + wsi->utf8_token[WSI_TOKEN_KEY].token_len,
						       websocket_magic_guid_04);

	SHA1((unsigned char *)accept_buf,
			wsi->utf8_token[WSI_TOKEN_KEY].token_len +
					 strlen(websocket_magic_guid_04), hash);

	accept_len = lws_b64_encode_string((char *)hash, 20, accept_buf,
							     sizeof accept_buf);
	if (accept_len < 0) {
		fprintf(stderr, "Base64 encoded hash too long\n");
		goto bail;
	}

	/* allocate the per-connection user memory (if any) */
	if (wsi->protocol->per_session_data_size &&
					  !libwebsocket_ensure_user_space(wsi))
		goto bail;

	/* create the response packet */

	/* make a buffer big enough for everything */

	response = malloc(256 +
		wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len +
		wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len +
		wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len);
	if (!response) {
		fprintf(stderr, "Out of memory for response buffer\n");
		goto bail;
	}

	p = response;
	LWS_CPYAPP(p, "HTTP/1.1 101 Switching Protocols\x0d\x0a"
		      "Upgrade: WebSocket\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Sec-WebSocket-Accept: ");
	strcpy(p, accept_buf);
	p += accept_len;

	if (wsi->ietf_spec_revision == 4) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Nonce: ");

		/* select the nonce */

		n = libwebsockets_get_random(wsi->protocol->owning_server,
								      hash, 16);
		if (n != 16) {
			fprintf(stderr, "Unable to read random device %s %d\n",
						     SYSTEM_RANDOM_FILEPATH, n);
			if (wsi->user_space)
				free(wsi->user_space);
			goto bail;
		}

		/* encode the nonce */

		nonce_len = lws_b64_encode_string((const char *)hash, 16,
						   nonce_buf, sizeof nonce_buf);
		if (nonce_len < 0) {
			fprintf(stderr, "Failed to base 64 encode the nonce\n");
			if (wsi->user_space)
				free(wsi->user_space);
			goto bail;
		}

		/* apply the nonce */

		strcpy(p, nonce_buf);
		p += nonce_len;
	}

	if (wsi->utf8_token[WSI_TOKEN_PROTOCOL].token) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Protocol: ");
		LWS_CPYAPP_TOKEN(p, WSI_TOKEN_PROTOCOL);
	}

	/*
	 * Figure out which extensions the client has that we want to
	 * enable on this connection, and give him back the list
	 */

	if (wsi->utf8_token[WSI_TOKEN_EXTENSIONS].token_len) {

		/*
		 * break down the list of client extensions
		 * and go through them
		 */

		c = wsi->utf8_token[WSI_TOKEN_EXTENSIONS].token;
		debug("wsi->utf8_token[WSI_TOKEN_EXTENSIONS].token = %s\n",
				  wsi->utf8_token[WSI_TOKEN_EXTENSIONS].token);
		wsi->count_active_extensions = 0;
		n = 0;
		while (more) {

			if (*c && (*c != ',' && *c != ' ' && *c != '\t')) {
				ext_name[n] = *c++;
				if (n < sizeof(ext_name) - 1)
					n++;
				continue;
			}
			ext_name[n] = '\0';
			if (!*c)
				more = 0;
			else {
				c++;
				if (!n)
					continue;
			}

			/* check a client's extension against our support */

			ext = wsi->protocol->owning_server->extensions;

			while (ext && ext->callback) {

				if (strcmp(ext_name, ext->name)) {
					ext++;
					continue;
				}

				/*
				 * oh, we do support this one he
				 * asked for... but let's ask user
				 * code if it's OK to apply it on this
				 * particular connection + protocol
				 */

				n = wsi->protocol->owning_server->
					protocols[0].callback(
						wsi->protocol->owning_server,
						wsi,
					  LWS_CALLBACK_CONFIRM_EXTENSION_OKAY,
						  wsi->user_space, ext_name, 0);

				/*
				 * zero return from callback means
				 * go ahead and allow the extension,
				 * it's what we get if the callback is
				 * unhandled
				 */

				if (n) {
					ext++;
					continue;
				}

				/* apply it */

				if (ext_count)
					*p++ = ',';
				else
					LWS_CPYAPP(p,
					 "\x0d\x0aSec-WebSocket-Extensions: ");
				p += sprintf(p, "%s", ext_name);
				ext_count++;

				/* instantiate the extension on this conn */

				wsi->active_extensions_user[
					wsi->count_active_extensions] =
					     malloc(ext->per_session_data_size);
				memset(wsi->active_extensions_user[
					wsi->count_active_extensions], 0,
						    ext->per_session_data_size);

				wsi->active_extensions[
					  wsi->count_active_extensions] = ext;

				/* allow him to construct his context */

				ext->callback(wsi->protocol->owning_server,
						ext, wsi,
						LWS_EXT_CALLBACK_CONSTRUCT,
						wsi->active_extensions_user[
					wsi->count_active_extensions], NULL, 0);

				wsi->count_active_extensions++;
				debug("wsi->count_active_extensions <- %d",
						  wsi->count_active_extensions);

				ext++;
			}

			n = 0;
		}
	}

	/* end of response packet */

	LWS_CPYAPP(p, "\x0d\x0a\x0d\x0a");

	if (wsi->ietf_spec_revision == 4) {

		/*
		 * precompute the masking key the client will use from the SHA1
		 * hash of ( base 64 client key we were sent, concatenated with
		 * the bse 64 nonce we sent, concatenated with a magic constant
		 * guid specified by the 04 standard )
		 *
		 * We store the hash in the connection's wsi ready to use with
		 * undoing the masking the client has done on framed data it
		 * sends (we send our data to the client in clear).
		 */

		strcpy(mask_summing_buf, wsi->utf8_token[WSI_TOKEN_KEY].token);
		m += wsi->utf8_token[WSI_TOKEN_KEY].token_len;
		strcpy(m, nonce_buf);
		m += nonce_len;
		strcpy(m, websocket_magic_guid_04_masking);
		m += strlen(websocket_magic_guid_04_masking);

		SHA1((unsigned char *)mask_summing_buf, m - mask_summing_buf,
							   wsi->masking_key_04);
	}

	if (!lws_any_extension_handled(context, wsi,
			LWS_EXT_CALLBACK_HANDSHAKE_REPLY_TX,
						     response, p - response)) {

		/* okay send the handshake response accepting the connection */

		debug("issuing response packet %d len\n", (int)(p - response));
	#ifdef DEBUG
		fwrite(response, 1,  p - response, stderr);
	#endif
		n = libwebsocket_write(wsi, (unsigned char *)response,
						  p - response, LWS_WRITE_HTTP);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			goto bail;
		}

	}

	/* alright clean up and set ourselves into established state */

	free(response);
	wsi->state = WSI_STATE_ESTABLISHED;
	wsi->lws_rx_parse_state = LWS_RXPS_NEW;
	wsi->rx_packet_length = 0;

	/* notify user code that we're ready to roll */

	if (wsi->protocol->callback)
		wsi->protocol->callback(wsi->protocol->owning_server,
				wsi, LWS_CALLBACK_ESTABLISHED,
					  wsi->user_space, NULL, 0);

	return 0;


bail:
	return -1;
}


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
	case WSI_STATE_HTTP:
		wsi->state = WSI_STATE_HTTP_HEADERS;
		wsi->parser_state = WSI_TOKEN_NAME_PART;
		/* fallthru */
	case WSI_STATE_HTTP_HEADERS:

		debug("issuing %d bytes to parser\n", (int)len);
#ifdef DEBUG
		fwrite(buf, 1, len, stderr);
#endif

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

		/* LWS_CONNMODE_WS_SERVING */

		for (n = 0; n < len; n++)
			libwebsocket_parse(wsi, *buf++);

		if (wsi->parser_state != WSI_PARSING_COMPLETE)
			break;

		debug("seem to be serving, mode is %d\n", wsi->mode);

		debug("libwebsocket_parse sees parsing complete\n");

		/* is this websocket protocol or normal http 1.0? */

		if (!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
			     !wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len) {
			wsi->state = WSI_STATE_HTTP;
			if (wsi->protocol->callback)
				if (wsi->protocol->callback(context, wsi,
								LWS_CALLBACK_HTTP, wsi->user_space,
								wsi->utf8_token[WSI_TOKEN_GET_URI].token,
								wsi->utf8_token[WSI_TOKEN_GET_URI].token_len))
					goto bail;
			return 0;
		}

		if (!wsi->protocol)
			fprintf(stderr, "NULL protocol at libwebsocket_read\n");

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
				fprintf(stderr, "[no protocol] "
					"not supported (use NULL .name)\n");
			else
				fprintf(stderr, "Requested protocol %s "
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
			fprintf(stderr, "User code denied connection\n");
			goto bail;
		}


		/*
		 * Perform the handshake according to the protocol version the
		 * client announced
		 */

		switch (wsi->ietf_spec_revision) {
		case 0: /* applies to 76 and 00 */
			wsi->xor_mask = xor_no_mask;
			if (handshake_00(context, wsi))
				goto bail;
			break;
		case 4: /* 04 */
			wsi->xor_mask = xor_mask_04;
			debug("libwebsocket_parse calling handshake_04\n");
			if (handshake_0405(context, wsi))
				goto bail;
			break;
		case 5:
		case 6:
		case 7:
		case 8:
		case 13:
			wsi->xor_mask = xor_mask_05;
			debug("libwebsocket_parse calling handshake_04\n");
			if (handshake_0405(context, wsi))
				goto bail;
			break;

		default:
			fprintf(stderr, "Unknown client spec version %d\n",
						       wsi->ietf_spec_revision);
			goto bail;
		}

		debug("accepted v%02d connection\n",
						       wsi->ietf_spec_revision);

		break;

	case WSI_STATE_AWAITING_CLOSE_ACK:
	case WSI_STATE_ESTABLISHED:
		switch (wsi->mode) {
		case LWS_CONNMODE_WS_CLIENT:
			for (n = 0; n < len; n++)
				if (libwebsocket_client_rx_sm(wsi, *buf++) < 0)
					goto bail;

			return 0;
		default:
			break;
		}

		/* LWS_CONNMODE_WS_SERVING */

		if (libwebsocket_interpret_incoming_packet(wsi, buf, len) < 0)
			goto bail;

		break;
	default:
		break;
	}

	return 0;

bail:
	libwebsocket_close_and_free_session(context, wsi,
						     LWS_CLOSE_STATUS_NOSTATUS);

	return -1;
}
