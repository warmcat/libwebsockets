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

#define LWS_CPYAPP(ptr, str) { strcpy(ptr, str); ptr += strlen(str); }
#define LWS_CPYAPP_TOKEN(ptr, tok) { strcpy(p, wsi->utf8_token[tok].token); \
		p += wsi->utf8_token[tok].token_len; }

/*
 * Perform the newer BASE64-encoded handshake scheme
 */

int
handshake_0405(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	static const char *websocket_magic_guid_04 =
					 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	char accept_buf[MAX_WEBSOCKET_04_KEY_LEN + 37];
	unsigned char hash[20];
	int n;
	char *response;
	char *p;
	int accept_len;
#ifndef LWS_NO_EXTENSIONS
	char *c;
	char ext_name[128];
	struct libwebsocket_extension *ext;
	int ext_count = 0;
	int more = 1;
#endif

	if (!wsi->utf8_token[WSI_TOKEN_HOST].token_len ||
	    !wsi->utf8_token[WSI_TOKEN_KEY].token_len) {
		lwsl_parser("handshake_04 missing pieces\n");
		/* completed header processing, but missing some bits */
		goto bail;
	}

	if (wsi->utf8_token[WSI_TOKEN_KEY].token_len >=
						     MAX_WEBSOCKET_04_KEY_LEN) {
		lwsl_warn("Client sent handshake key longer "
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
		lwsl_warn("Base64 encoded hash too long\n");
		goto bail;
	}

	/* allocate the per-connection user memory (if any) */
	if (wsi->protocol->per_session_data_size &&
					  !libwebsocket_ensure_user_space(wsi))
		goto bail;

	/* create the response packet */

	/* make a buffer big enough for everything */

	response = (char *)malloc(256 +
		wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len +
		wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len +
		wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len);
	if (!response) {
		lwsl_err("Out of memory for response buffer\n");
		goto bail;
	}

	p = response;
	LWS_CPYAPP(p, "HTTP/1.1 101 Switching Protocols\x0d\x0a"
		      "Upgrade: WebSocket\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Sec-WebSocket-Accept: ");
	strcpy(p, accept_buf);
	p += accept_len;

	if (wsi->utf8_token[WSI_TOKEN_PROTOCOL].token) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Protocol: ");
		LWS_CPYAPP_TOKEN(p, WSI_TOKEN_PROTOCOL);
	}

#ifndef LWS_NO_EXTENSIONS
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
		lwsl_parser("wsi->utf8_token[WSI_TOKEN_EXTENSIONS].token = %s\n",
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
				if (wsi->active_extensions_user[
					 wsi->count_active_extensions] == NULL) {
					lwsl_err("Out of mem\n");
					free(response);
					goto bail;
				}
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
				lwsl_parser("wsi->count_active_extensions <- %d\n",
						  wsi->count_active_extensions);

				ext++;
			}

			n = 0;
		}
	}
#endif
	/* end of response packet */

	LWS_CPYAPP(p, "\x0d\x0a\x0d\x0a");

#ifndef LWS_NO_EXTENSIONS
	if (!lws_any_extension_handled(context, wsi,
			LWS_EXT_CALLBACK_HANDSHAKE_REPLY_TX,
						     response, p - response))
#endif
	{
		/* okay send the handshake response accepting the connection */

		lwsl_parser("issuing response packet %d len\n", (int)(p - response));
	#ifdef DEBUG
		fwrite(response, 1,  p - response, stderr);
	#endif
		n = libwebsocket_write(wsi, (unsigned char *)response,
						  p - response, LWS_WRITE_HTTP);
		if (n < 0) {
			lwsl_debug("handshake_0405: ERROR writing to socket\n");
			goto bail;
		}

	}

	/* alright clean up and set ourselves into established state */

	free(response);
	wsi->state = WSI_STATE_ESTABLISHED;
	wsi->lws_rx_parse_state = LWS_RXPS_NEW;
	wsi->u.ws.rx_packet_length = 0;

	/* notify user code that we're ready to roll */

	if (wsi->protocol->callback)
		wsi->protocol->callback(wsi->protocol->owning_server,
				wsi, LWS_CALLBACK_ESTABLISHED,
					  wsi->user_space, NULL, 0);

	return 0;


bail:
	return -1;
}

