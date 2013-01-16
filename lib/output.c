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

static int
libwebsocket_0405_frame_mask_generate(struct libwebsocket *wsi)
{
	char buf[4 + 20];
	int n;

	/* fetch the per-frame nonce */

	n = libwebsockets_get_random(wsi->protocol->owning_server,
						wsi->frame_masking_nonce_04, 4);
	if (n != 4) {
		lwsl_parser("Unable to read from random device %s %d\n",
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

#ifdef _DEBUG

void lwsl_hexdump(void *vbuf, size_t len)
{
	int n;
	int m;
	int start;
	unsigned char *buf = (unsigned char *)vbuf;
	char line[80];
	char *p;

	lwsl_parser("\n");

	for (n = 0; n < len;) {
		start = n;
		p = line;

		p += sprintf(p, "%04X: ", start);

		for (m = 0; m < 16 && n < len; m++)
			p += sprintf(p, "%02X ", buf[n++]);
		while (m++ < 16)
			p += sprintf(p, "   ");

		p += sprintf(p, "   ");

		for (m = 0; m < 16 && (start + m) < len; m++) {
			if (buf[start + m] >= ' ' && buf[start + m] <= 127)
				*p++ = buf[start + m];
			else
				*p++ = '.';
		}
		while (m++ < 16)
			*p++ = ' ';

		*p++ = '\n';
		*p = '\0';
		lwsl_debug(line);
	}
	lwsl_debug("\n");
}

#endif

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
			lwsl_ext("Extension reports fatal error\n");
			return -1;
		}
		if (m) /* handled */ {
/*			lwsl_ext("ext sent it\n"); */
			return 0;
		}
	}

	if (!wsi->sock)
		lwsl_warn("** error 0 sock but expected to send\n");

	/*
	 * nope, send it on the socket directly
	 */

#if 0
	lwsl_debug("  TX: ");
	lws_stderr_hexdump(buf, len);
#endif

#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
		n = SSL_write(wsi->ssl, buf, len);
		if (n < 0) {
			lwsl_debug("ERROR writing to socket\n");
			return -1;
		}
	} else {
#endif
		n = send(wsi->sock, buf, len, MSG_NOSIGNAL);
		if (n < 0) {
			lwsl_debug("ERROR writing to socket\n");
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
				lwsl_ext("Extension: fatal error\n");
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

		lwsl_parser("written %d bytes to client\n", eff_buf.token_len);

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

		lwsl_debug("choked\n");

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
		lwsl_warn("zero length libwebsocket_write attempt\n");
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
					lwsl_debug("LWS_WRITE_CLOSE S\n");
					*/
					buf[0] = 'S';
					break;
				case LWS_CONNMODE_WS_CLIENT:
					/*
					lwsl_debug("LWS_WRITE_CLOSE C\n");
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
			lwsl_warn("libwebsocket_write: unknown write "
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
				lwsl_err("libwebsocket_write: "
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
	lwsl_debug("send %ld: ", len + post);
	for (n = -pre; n < ((int)len + post); n++)
		lwsl_debug("%02X ", buf[n]);

	lwsl_debug("\n");
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
 * @context:		libwebsockets context
 * @wsi:		Websocket instance (available from user callback)
 * @file:		The file to issue over http
 * @content_type:	The http content type, eg, text/html
 *
 *	This function is intended to be called from the callback in response
 *	to http requests from the client.  It allows the callback to issue
 *	local files down the http link in a single step.
 */

int libwebsockets_serve_http_file(struct libwebsocket_context *context,
			struct libwebsocket *wsi, const char *file,
						       const char *content_type)
{
	int fd;
	struct stat stat_buf;
	char buf[1400];
	char *p = buf;
	int n, m;

	strncpy(wsi->filepath, file, sizeof wsi->filepath);
	wsi->filepath[sizeof(wsi->filepath) - 1] = '\0';

#ifdef WIN32
	fd = open(wsi->filepath, O_RDONLY | _O_BINARY);
#else
	fd = open(wsi->filepath, O_RDONLY);
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
	wsi->filelen = stat_buf.st_size;
	p += sprintf(p, "HTTP/1.0 200 OK\x0d\x0a"
			"Server: libwebsockets\x0d\x0a"
			"Content-Type: %s\x0d\x0a"
			"Content-Length: %u\x0d\x0a"
			"\x0d\x0a", content_type,
					(unsigned int)stat_buf.st_size);

	n = libwebsocket_write(wsi, (unsigned char *)buf, p - buf, LWS_WRITE_HTTP);
	if (n) {
		close(fd);
		return n;
	}

	wsi->filepos = 0;
	wsi->state = WSI_STATE_HTTP_ISSUING_FILE;

	while (!lws_send_pipe_choked(wsi)) {

		n = read(fd, buf, sizeof buf);
		if (n > 0) {
			wsi->filepos += n;
			m = libwebsocket_write(wsi, (unsigned char *)buf, n, LWS_WRITE_HTTP);
			if (m) {
				close(fd);
				return m;
			}
		}

		if (n < 0) {
			close(fd);
			return -1;
		}

		if (n < sizeof(buf) || wsi->filepos == wsi->filelen) {
			/* oh, we were able to finish here! */
			wsi->state = WSI_STATE_HTTP;
			close(fd);

			if (wsi->protocol->callback(context, wsi, LWS_CALLBACK_HTTP_FILE_COMPLETION, wsi->user_space,
							wsi->filepath, wsi->filepos))
				libwebsocket_close_and_free_session(context, wsi, LWS_CLOSE_STATUS_NOSTATUS);

			return 0;
		}
	}

	/* we choked, no worries schedule service for the rest of it */

	libwebsocket_callback_on_writable(context, wsi);

	close(fd);

	return 0;
}

int libwebsockets_serve_http_file_fragment(struct libwebsocket_context *context,
							struct libwebsocket *wsi)
{
	int fd;
	int ret = 0;
	char buf[1400];
	int n;

#ifdef WIN32
	fd = open(wsi->filepath, O_RDONLY | _O_BINARY);
#else
	fd = open(wsi->filepath, O_RDONLY);
#endif
	if (fd < 1)
		return -1;

	lseek(fd, wsi->filepos, SEEK_SET);

	while (!lws_send_pipe_choked(wsi)) {
		n = read(fd, buf, sizeof buf);
		if (n > 0) {
			libwebsocket_write(wsi, (unsigned char *)buf, n, LWS_WRITE_HTTP);
			wsi->filepos += n;
		}

		if (n < 0) {
			close(fd);
			return -1;
		}

		if (n < sizeof(buf) || wsi->filepos == wsi->filelen) {
			wsi->state = WSI_STATE_HTTP;
			close(fd);
			return 0;
		}
	}

	libwebsocket_callback_on_writable(context, wsi);

	close(fd);

	return ret;
}


