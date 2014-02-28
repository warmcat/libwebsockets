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

static int
libwebsocket_0405_frame_mask_generate(struct libwebsocket *wsi)
{
	int n;

	/* fetch the per-frame nonce */

	n = libwebsockets_get_random(wsi->protocol->owning_server,
					   wsi->u.ws.frame_masking_nonce_04, 4);
	if (n != 4) {
		lwsl_parser("Unable to read from random device %s %d\n",
						     SYSTEM_RANDOM_FILEPATH, n);
		return 1;
	}

	/* start masking from first byte of masking key buffer */
	wsi->u.ws.frame_mask_index = 0;

	return 0;
}

#ifdef _DEBUG

LWS_VISIBLE void lwsl_hexdump(void *vbuf, size_t len)
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
			if (buf[start + m] >= ' ' && buf[start + m] < 127)
				*p++ = buf[start + m];
			else
				*p++ = '.';
		}
		while (m++ < 16)
			*p++ = ' ';

		*p++ = '\n';
		*p = '\0';
		lwsl_debug("%s", line);
	}
	lwsl_debug("\n");
}

#endif

/*
 * notice this returns number of bytes consumed, or -1
 */

int lws_issue_raw(struct libwebsocket *wsi, unsigned char *buf, size_t len)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;
	int n;
	size_t real_len = len;

#ifndef LWS_NO_EXTENSIONS
	int m;

	if (wsi->truncated_send_malloc &&
		(buf < wsi->truncated_send_malloc ||
			buf > (wsi->truncated_send_malloc + wsi->truncated_send_len +  wsi->truncated_send_offset))) {
		lwsl_err("****** %x Sending something else while pending truncated ...\n", wsi);
		assert(0);
	}

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
			n = m;
			goto handle_truncated_send;
		}
	}
#endif
	if (wsi->sock < 0)
		lwsl_warn("** error invalid sock but expected to send\n");

	/*
	 * nope, send it on the socket directly
	 */

#if 0
	lwsl_debug("  TX: ");
	lws_hexdump(buf, len);
#endif

#if 0
	/* test partial send support by forcing multiple sends on everything */
	len = len / 2;
	if (!len)
		len = 1;
#endif

	lws_latency_pre(context, wsi);
#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
		n = SSL_write(wsi->ssl, buf, len);
		lws_latency(context, wsi, "SSL_write lws_issue_raw", n, n >= 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EINTR) {
				n = 0;
				goto handle_truncated_send;
			}
			lwsl_debug("ERROR writing to socket\n");
			return -1;
		}
	} else {
#endif
		n = send(wsi->sock, buf, len, MSG_NOSIGNAL);
		lws_latency(context, wsi, "send lws_issue_raw", n, n == len);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EINTR) {
				n = 0;
				goto handle_truncated_send;
			}
			lwsl_debug("ERROR writing len %d to skt %d\n", len, n);
			return -1;
		}
#ifdef LWS_OPENSSL_SUPPORT
	}
#endif

handle_truncated_send:

	/*
	 * already handling a truncated send?
	 */
	if (wsi->truncated_send_malloc) {
		lwsl_info("***** %x partial send moved on by %d (vs %d)\n", wsi, n, real_len);
		wsi->truncated_send_offset += n;
		wsi->truncated_send_len -= n;

		if (!wsi->truncated_send_len) {
			lwsl_info("***** %x partial send completed\n", wsi);
			/* done with it */
			free(wsi->truncated_send_malloc);
			wsi->truncated_send_malloc = NULL;
			n = real_len;
		} else
			libwebsocket_callback_on_writable(
					     wsi->protocol->owning_server, wsi);

		return n;
	}

	if (n < real_len) {
		if (wsi->u.ws.clean_buffer)
			/*
			 * This buffer unaffected by extension rewriting.
			 * It means the user code is expected to deal with
			 * partial sends.  (lws knows the header was already
			 * sent, so on next send will just resume sending
			 * payload)
			 */
			 return n;

		/*
		 * Newly truncated send.  Buffer the remainder (it will get
		 * first priority next time the socket is writable)
		 */
		lwsl_info("***** %x new partial sent %d from %d total\n", wsi, n, real_len);

		wsi->truncated_send_malloc = malloc(real_len - n);
		if (!wsi->truncated_send_malloc) {
			lwsl_err("truncated send: unable to malloc %d\n",
								  real_len - n);
			return -1;
		}

		wsi->truncated_send_offset = 0;
		wsi->truncated_send_len = real_len - n;
		memcpy(wsi->truncated_send_malloc, buf + n, real_len - n);

		libwebsocket_callback_on_writable(
					     wsi->protocol->owning_server, wsi);

		return real_len;
	}

	return n;
}

#ifdef LWS_NO_EXTENSIONS
int
lws_issue_raw_ext_access(struct libwebsocket *wsi,
						 unsigned char *buf, size_t len)
{
	return lws_issue_raw(wsi, buf, len);
}
#else
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

		if ((char *)buf != eff_buf.token)
			wsi->u.ws.clean_buffer = 0; /* extension recreated it: we need to buffer this if not all sent */

		/* assuming they left us something to send, send it */

		if (eff_buf.token_len) {
			n = lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
							    eff_buf.token_len);
			if (n < 0)
				return -1;

			/* always either sent it all or privately buffered */
		}

		lwsl_parser("written %d bytes to client\n", eff_buf.token_len);

		/* no extension has more to spill?  Then we can go */

		if (!ret)
			break;

		/* we used up what we had */

		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/*
		 * Did that leave the pipe choked?
		 * Or we had to hold on to some of it?
		 */

		if (!lws_send_pipe_choked(wsi) &&
					!wsi->truncated_send_malloc)
			/* no we could add more, lets's do that */
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

	return len;
}
#endif

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
 *
 *	Return may be -1 for a fatal error needing connection close, or a
 *	positive number reflecting the amount of bytes actually sent.  This
 *	can be less than the requested number of bytes due to OS memory
 *	pressure at any given time.
 */

LWS_VISIBLE int libwebsocket_write(struct libwebsocket *wsi, unsigned char *buf,
			  size_t len, enum libwebsocket_write_protocol protocol)
{
	int n;
	int pre = 0;
	int post = 0;
	int masked7 = wsi->mode == LWS_CONNMODE_WS_CLIENT;
	unsigned char *dropmask = NULL;
	unsigned char is_masked_bit = 0;
	size_t orig_len = len;
#ifndef LWS_NO_EXTENSIONS
	struct lws_tokens eff_buf;
	int m;
#endif

	if (len == 0 && protocol != LWS_WRITE_CLOSE &&
		     protocol != LWS_WRITE_PING && protocol != LWS_WRITE_PONG) {
		lwsl_warn("zero length libwebsocket_write attempt\n");
		return 0;
	}

	if (protocol == LWS_WRITE_HTTP)
		goto send_raw;

	/* websocket protocol, either binary or text */

	if (wsi->state != WSI_STATE_ESTABLISHED)
		return -1;

	/* if we are continuing a frame that already had its header done */

	if (wsi->u.ws.inside_frame)
		goto do_more_inside_frame;

	/* if he wants all partials buffered, never have a clean_buffer */
	wsi->u.ws.clean_buffer = !wsi->protocol->no_buffer_all_partial_tx;

#ifndef LWS_NO_EXTENSIONS
	/*
	 * give a chance to the extensions to modify payload
	 * pre-TX mangling is not allowed to truncate
	 */
	eff_buf.token = (char *)buf;
	eff_buf.token_len = len;

	switch (protocol) {
	case LWS_WRITE_PING:
	case LWS_WRITE_PONG:
	case LWS_WRITE_CLOSE:
		break;
	default:

		for (n = 0; n < wsi->count_active_extensions; n++) {
			m = wsi->active_extensions[n]->callback(
				wsi->protocol->owning_server,
				wsi->active_extensions[n], wsi,
				LWS_EXT_CALLBACK_PAYLOAD_TX,
				wsi->active_extensions_user[n], &eff_buf, 0);
			if (m < 0)
				return -1;
		}
	}

	/*
	 * an extension did something we need to keep... for example, if
	 * compression extension, it has already updated its state according
	 * to this being issued
	 */
	if ((char *)buf != eff_buf.token)
		wsi->u.ws.clean_buffer = 0; /* we need to buffer this if not all sent */

	buf = (unsigned char *)eff_buf.token;
	len = eff_buf.token_len;
#endif

	switch (wsi->ietf_spec_revision) {
	case 13:

		if (masked7) {
			pre += 4;
			dropmask = &buf[0 - pre];
			is_masked_bit = 0x80;
		}

		switch (protocol & 0xf) {
		case LWS_WRITE_TEXT:
			n = LWS_WS_OPCODE_07__TEXT_FRAME;
			break;
		case LWS_WRITE_BINARY:
			n = LWS_WS_OPCODE_07__BINARY_FRAME;
			break;
		case LWS_WRITE_CONTINUATION:
			n = LWS_WS_OPCODE_07__CONTINUATION;
			break;

		case LWS_WRITE_CLOSE:
			n = LWS_WS_OPCODE_07__CLOSE;

			/*
			 * 06+ has a 2-byte status code in network order
			 * we can do this because we demand post-buf
			 */

			if (wsi->u.ws.close_reason) {
				/* reason codes count as data bytes */
				buf -= 2;
				buf[0] = wsi->u.ws.close_reason >> 8;
				buf[1] = wsi->u.ws.close_reason;
				len += 2;
			}
			break;
		case LWS_WRITE_PING:
			n = LWS_WS_OPCODE_07__PING;
			break;
		case LWS_WRITE_PONG:
			n = LWS_WS_OPCODE_07__PONG;
			break;
		default:
			lwsl_warn("lws_write: unknown write opc / protocol\n");
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

do_more_inside_frame:

	/*
	 * Deal with masking if we are in client -> server direction and
	 * the protocol demands it
	 */

	if (wsi->mode == LWS_CONNMODE_WS_CLIENT) {

		if (!wsi->u.ws.inside_frame)
			if (libwebsocket_0405_frame_mask_generate(wsi)) {
				lwsl_err("lws_write: frame mask generation failed\n");
				return -1;
			}

		/*
		 * in v7, just mask the payload
		 */
		if (dropmask) { /* never set if already inside frame */
			for (n = 4; n < (int)len + 4; n++)
				dropmask[n] = dropmask[n] ^
				wsi->u.ws.frame_masking_nonce_04[
					(wsi->u.ws.frame_mask_index++) & 3];

			/* copy the frame nonce into place */
			memcpy(dropmask, wsi->u.ws.frame_masking_nonce_04, 4);
		}
	}

send_raw:

#if 0
	lwsl_debug("send %ld: ", len + pre + post);
	lwsl_hexdump(&buf[-pre], len + pre + post);
#endif

	switch (protocol) {
	case LWS_WRITE_CLOSE:
/*		lwsl_hexdump(&buf[-pre], len + post); */
	case LWS_WRITE_HTTP:
	case LWS_WRITE_PONG:
	case LWS_WRITE_PING:
		return lws_issue_raw(wsi, (unsigned char *)buf - pre,
							      len + pre + post);
	default:
		break;
	}

	wsi->u.ws.inside_frame = 1;

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
	 *
	 * This takes care of holding the buffer if send is incomplete, ie,
	 * if wsi->u.ws.clean_buffer is 0 (meaning an extension meddled with
	 * the buffer).  If wsi->u.ws.clean_buffer is 1, it will instead
	 * return to the user code how much OF THE USER BUFFER was consumed.
	 */

	n = lws_issue_raw_ext_access(wsi, buf - pre, len + pre + post);
	if (n < 0)
		return n;

	if (n == len + pre + post) {
		/* everything in the buffer was handled (or rebuffered...) */
		wsi->u.ws.inside_frame = 0;
		return orig_len;
	}

	/*
	 * it is how many bytes of user buffer got sent... may be < orig_len
	 * in which case callback when writable has already been arranged
	 * and user code can call libwebsocket_write() again with the rest
	 * later.
	 */

	return n - (pre + post);
}

LWS_VISIBLE int libwebsockets_serve_http_file_fragment(
		struct libwebsocket_context *context, struct libwebsocket *wsi)
{
#if defined(WIN32) || defined(_WIN32)
	DWORD n;
#else
	int n;
#endif
	int m;

	while (!lws_send_pipe_choked(wsi)) {

		if (wsi->truncated_send_malloc) {
			lws_issue_raw(wsi, wsi->truncated_send_malloc +
					wsi->truncated_send_offset,
							wsi->truncated_send_len);
			continue;
		}

		if (wsi->u.http.filepos == wsi->u.http.filelen)
			goto all_sent;

#if defined(WIN32) || defined(_WIN32)
		if (!ReadFile(wsi->u.http.fd, context->service_buffer,
						sizeof(context->service_buffer), &n, NULL))
			return -1; /* caller will close */
#else
		n = read(wsi->u.http.fd, context->service_buffer,
					       sizeof(context->service_buffer));

		if (n < 0)
			return -1; /* caller will close */
#endif
		if (n) {
			m = libwebsocket_write(wsi, context->service_buffer, n,
								LWS_WRITE_HTTP);
			if (m < 0)
				return -1;

			wsi->u.http.filepos += m;
			if (m != n) {
				/* adjust for what was not sent */
#if defined(WIN32) || defined(_WIN32)
				SetFilePointer(wsi->u.http.fd, m - n, NULL, FILE_CURRENT);
#else
				lseek(wsi->u.http.fd, m - n, SEEK_CUR);
#endif
			}
		}
all_sent:
		if (!wsi->truncated_send_malloc &&
				wsi->u.http.filepos == wsi->u.http.filelen) {
			wsi->state = WSI_STATE_HTTP;

			if (wsi->protocol->callback)
				/* ignore callback returned value */
				user_callback_handle_rxflow(
					wsi->protocol->callback, context, wsi,
					LWS_CALLBACK_HTTP_FILE_COMPLETION,
					wsi->user_space, NULL, 0);
			return 1;  /* >0 indicates completed */
		}
	}

	lwsl_info("choked before able to send whole file (post)\n");
	libwebsocket_callback_on_writable(context, wsi);

	return 0; /* indicates further processing must be done */
}
