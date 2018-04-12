/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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

/*
 * notice this returns number of bytes consumed, or -1
 */
int lws_issue_raw(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	size_t real_len = len;
	unsigned int n;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	int m;
#endif

	// lwsl_hexdump_notice(buf, len);

	/*
	 * Detect if we got called twice without going through the
	 * event loop to handle pending.  This would be caused by either
	 * back-to-back writes in one WRITABLE (illegal) or calling lws_write()
	 * from outside the WRITABLE callback (illegal).
	 */
	if (wsi->could_have_pending) {
		lwsl_hexdump_level(LLL_ERR, buf, len);
		lwsl_err("** %p: vh: %s, prot: %s, role %s: "
			 "Illegal back-to-back write of %lu detected...\n",
			 wsi, wsi->vhost->name, wsi->protocol->name,
			 wsi->role_ops->name,
			 (unsigned long)len);
		// assert(0);

		return -1;
	}

	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_API_WRITE, 1);

	if (!len)
		return 0;
	/* just ignore sends after we cleared the truncation buffer */
	if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE && !wsi->trunc_len)
		return (int)len;

	if (wsi->trunc_len && (buf < wsi->trunc_alloc ||
	    buf > (wsi->trunc_alloc + wsi->trunc_len + wsi->trunc_offset))) {
		lwsl_hexdump_level(LLL_ERR, buf, len);
		lwsl_err("** %p: vh: %s, prot: %s, Sending new %lu, pending truncated ...\n"
			 "   It's illegal to do an lws_write outside of\n"
			 "   the writable callback: fix your code\n",
			 wsi, wsi->vhost->name, wsi->protocol->name,
			 (unsigned long)len);
		assert(0);

		return -1;
	}
#if !defined(LWS_WITHOUT_EXTENSIONS)
	m = lws_ext_cb_active(wsi, LWS_EXT_CB_PACKET_TX_DO_SEND, &buf, (int)len);
	if (m < 0)
		return -1;
	if (m) /* handled */ {
		n = m;
		goto handle_truncated_send;
	}
#endif
	if (!wsi->http2_substream && !lws_socket_is_valid(wsi->desc.sockfd))
		lwsl_warn("** error invalid sock but expected to send\n");

	/* limit sending */
	if (wsi->protocol->tx_packet_size)
		n = (int)wsi->protocol->tx_packet_size;
	else {
		n = (int)wsi->protocol->rx_buffer_size;
		if (!n)
			n = context->pt_serv_buf_size;
	}
	n += LWS_PRE + 4;
	if (n > len)
		n = (int)len;

	/* nope, send it on the socket directly */
	lws_latency_pre(context, wsi);
	n = lws_ssl_capable_write(wsi, buf, n);
	lws_latency(context, wsi, "send lws_issue_raw", n, n == len);

	/* something got written, it can have been truncated now */
	wsi->could_have_pending = 1;

	switch (n) {
	case LWS_SSL_CAPABLE_ERROR:
		/* we're going to close, let close know sends aren't possible */
		wsi->socket_is_permanently_unusable = 1;
		return -1;
	case LWS_SSL_CAPABLE_MORE_SERVICE:
		/*
		 * nothing got sent, not fatal.  Retry the whole thing later,
		 * ie, implying treat it was a truncated send so it gets
		 * retried
		 */
		n = 0;
		break;
	}
#if !defined(LWS_WITHOUT_EXTENSIONS)
handle_truncated_send:
#endif
	/*
	 * we were already handling a truncated send?
	 */
	if (wsi->trunc_len) {
		lwsl_info("%p partial adv %d (vs %ld)\n", wsi, n, (long)real_len);
		wsi->trunc_offset += n;
		wsi->trunc_len -= n;

		if (!wsi->trunc_len) {
			lwsl_info("** %p partial send completed\n", wsi);
			/* done with it, but don't free it */
			n = (int)real_len;
			if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE) {
				lwsl_info("** %p signalling to close now\n", wsi);
				return -1; /* retry closing now */
			}
		}
		/* always callback on writeable */
		lws_callback_on_writable(wsi);

		return n;
	}

	if ((unsigned int)n == real_len)
		/* what we just sent went out cleanly */
		return n;

	/*
	 * Newly truncated send.  Buffer the remainder (it will get
	 * first priority next time the socket is writable).
	 */
	lwsl_debug("%p new partial sent %d from %lu total\n", wsi, n,
		    (unsigned long)real_len);

	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_WRITE_PARTIALS, 1);
	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_B_PARTIALS_ACCEPTED_PARTS, n);

	/*
	 *  - if we still have a suitable malloc lying around, use it
	 *  - or, if too small, reallocate it
	 *  - or, if no buffer, create it
	 */
	if (!wsi->trunc_alloc || real_len - n > wsi->trunc_alloc_len) {
		lws_free(wsi->trunc_alloc);

		wsi->trunc_alloc_len = (unsigned int)(real_len - n);
		wsi->trunc_alloc = lws_malloc(real_len - n,
					      "truncated send alloc");
		if (!wsi->trunc_alloc) {
			lwsl_err("truncated send: unable to malloc %lu\n",
				 (unsigned long)(real_len - n));
			return -1;
		}
	}
	wsi->trunc_offset = 0;
	wsi->trunc_len = (unsigned int)(real_len - n);
	memcpy(wsi->trunc_alloc, buf + n, real_len - n);

#if !defined(LWS_WITH_ESP32)
	if (lws_wsi_is_udp(wsi)) {
		/* stash original destination for fulfilling UDP partials */
		wsi->udp->sa_pending = wsi->udp->sa;
		wsi->udp->salen_pending = wsi->udp->salen;
	}
#endif

	/* since something buffered, force it to get another chance to send */
	lws_callback_on_writable(wsi);

	return (int)real_len;
}

LWS_VISIBLE int lws_write(struct lws *wsi, unsigned char *buf, size_t len,
			  enum lws_write_protocol wp)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (wsi->parent_carries_io) {
		struct lws_write_passthru pas;

		pas.buf = buf;
		pas.len = len;
		pas.wp = wp;
		pas.wsi = wsi;

		if (wsi->parent->protocol->callback(wsi->parent,
				LWS_CALLBACK_CHILD_WRITE_VIA_PARENT,
				wsi->parent->user_space,
				(void *)&pas, 0))
			return 1;

		return (int)len;
	}

	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_API_LWS_WRITE, 1);

	if ((int)len < 0) {
		lwsl_err("%s: suspicious len int %d, ulong %lu\n", __func__,
				(int)len, (unsigned long)len);
		return -1;
	}

	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_B_WRITE, len);

#ifdef LWS_WITH_ACCESS_LOG
	wsi->access_log.sent += len;
#endif
	if (wsi->vhost)
		wsi->vhost->conn_stats.tx += len;

	assert(wsi->role_ops);
	if (!wsi->role_ops->write_role_protocol)
		return lws_issue_raw(wsi, buf, len);

	return wsi->role_ops->write_role_protocol(wsi, buf, len, &wp);
}

LWS_VISIBLE int lws_serve_http_file_fragment(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_process_html_args args;
	lws_filepos_t amount, poss;
	unsigned char *p, *pstart;
#if defined(LWS_WITH_RANGES)
	unsigned char finished = 0;
#endif
	int n, m;

	lwsl_debug("wsi->http2_substream %d\n", wsi->http2_substream);

	do {

		if (wsi->trunc_len) {
			if (lws_issue_raw(wsi, wsi->trunc_alloc +
					  wsi->trunc_offset,
					  wsi->trunc_len) < 0) {
				lwsl_info("%s: closing\n", __func__);
				goto file_had_it;
			}
			break;
		}

		if (wsi->http.filepos == wsi->http.filelen)
			goto all_sent;

		n = 0;

		pstart = pt->serv_buf + LWS_H2_FRAME_HEADER_LENGTH;

		p = pstart;

#if defined(LWS_WITH_RANGES)
		if (wsi->http.range.count_ranges && !wsi->http.range.inside) {

			lwsl_notice("%s: doing range start %llu\n", __func__,
				    wsi->http.range.start);

			if ((long long)lws_vfs_file_seek_cur(wsi->http.fop_fd,
						   wsi->http.range.start -
						   wsi->http.filepos) < 0)
				goto file_had_it;

			wsi->http.filepos = wsi->http.range.start;

			if (wsi->http.range.count_ranges > 1) {
				n =  lws_snprintf((char *)p,
						context->pt_serv_buf_size -
						LWS_H2_FRAME_HEADER_LENGTH,
					"_lws\x0d\x0a"
					"Content-Type: %s\x0d\x0a"
					"Content-Range: bytes %llu-%llu/%llu\x0d\x0a"
					"\x0d\x0a",
					wsi->http.multipart_content_type,
					wsi->http.range.start,
					wsi->http.range.end,
					wsi->http.range.extent);
				p += n;
			}

			wsi->http.range.budget = wsi->http.range.end -
						   wsi->http.range.start + 1;
			wsi->http.range.inside = 1;
		}
#endif

		poss = context->pt_serv_buf_size - n - LWS_H2_FRAME_HEADER_LENGTH;

		if (wsi->http.tx_content_length)
			if (poss > wsi->http.tx_content_remain)
				poss = wsi->http.tx_content_remain;

		/*
		 * if there is a hint about how much we will do well to send at
		 * one time, restrict ourselves to only trying to send that.
		 */
		if (wsi->protocol->tx_packet_size &&
		    poss > wsi->protocol->tx_packet_size)
			poss = wsi->protocol->tx_packet_size;

		if (wsi->role_ops->tx_credit) {
			lws_filepos_t txc = wsi->role_ops->tx_credit(wsi);

			if (!txc) {
				lwsl_info("%s: came here with no tx credit\n",
						__func__);
				return 0;
			}
			if (txc < poss)
				poss = txc;

			/*
			 * consumption of the actual payload amount sent will be
			 * handled when the role data frame is sent
			 */
		}

#if defined(LWS_WITH_RANGES)
		if (wsi->http.range.count_ranges) {
			if (wsi->http.range.count_ranges > 1)
				poss -= 7; /* allow for final boundary */
			if (poss > wsi->http.range.budget)
				poss = wsi->http.range.budget;
		}
#endif
		if (wsi->sending_chunked) {
			/* we need to drop the chunk size in here */
			p += 10;
			/* allow for the chunk to grow by 128 in translation */
			poss -= 10 + 128;
		}

		if (lws_vfs_file_read(wsi->http.fop_fd, &amount, p, poss) < 0)
			goto file_had_it; /* caller will close */

		if (wsi->sending_chunked)
			n = (int)amount;
		else
			n = lws_ptr_diff(p, pstart) + (int)amount;

		lwsl_debug("%s: sending %d\n", __func__, n);

		if (n) {
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
					context->timeout_secs);

			if (wsi->interpreting) {
				args.p = (char *)p;
				args.len = n;
				args.max_len = (unsigned int)poss + 128;
				args.final = wsi->http.filepos + n ==
					     wsi->http.filelen;
				args.chunked = wsi->sending_chunked;
				if (user_callback_handle_rxflow(
				     wsi->vhost->protocols[
				     (int)wsi->protocol_interpret_idx].callback,
				     wsi, LWS_CALLBACK_PROCESS_HTML,
				     wsi->user_space, &args, 0) < 0)
					goto file_had_it;
				n = args.len;
				p = (unsigned char *)args.p;
			} else
				p = pstart;

#if defined(LWS_WITH_RANGES)
			if (wsi->http.range.send_ctr + 1 ==
				wsi->http.range.count_ranges && // last range
			    wsi->http.range.count_ranges > 1 && // was 2+ ranges (ie, multipart)
			    wsi->http.range.budget - amount == 0) {// final part
				n += lws_snprintf((char *)pstart + n, 6,
					"_lws\x0d\x0a"); // append trailing boundary
				lwsl_debug("added trailing boundary\n");
			}
#endif
			m = lws_write(wsi, p, n,
				      wsi->http.filepos + amount == wsi->http.filelen ?
					LWS_WRITE_HTTP_FINAL :
					LWS_WRITE_HTTP
				);
			if (m < 0)
				goto file_had_it;

			wsi->http.filepos += amount;

#if defined(LWS_WITH_RANGES)
			if (wsi->http.range.count_ranges >= 1) {
				wsi->http.range.budget -= amount;
				if (wsi->http.range.budget == 0) {
					lwsl_notice("range budget exhausted\n");
					wsi->http.range.inside = 0;
					wsi->http.range.send_ctr++;

					if (lws_ranges_next(&wsi->http.range) < 1) {
						finished = 1;
						goto all_sent;
					}
				}
			}
#endif

			if (m != n) {
				/* adjust for what was not sent */
				if (lws_vfs_file_seek_cur(wsi->http.fop_fd,
							   m - n) ==
							     (lws_fileofs_t)-1)
					goto file_had_it;
			}
		}

all_sent:
		if ((!wsi->trunc_len && wsi->http.filepos >= wsi->http.filelen)
#if defined(LWS_WITH_RANGES)
		    || finished)
#else
		)
#endif
		     {
			lwsi_set_state(wsi, LRS_ESTABLISHED);
			/* we might be in keepalive, so close it off here */
			lws_vfs_file_close(&wsi->http.fop_fd);
			
			lwsl_debug("file completed\n");

			if (wsi->protocol->callback &&
			    user_callback_handle_rxflow(wsi->protocol->callback,
					    	    	wsi, LWS_CALLBACK_HTTP_FILE_COMPLETION,
					    	    	wsi->user_space, NULL,
					    	    	0) < 0) {
					/*
					 * For http/1.x, the choices from
					 * transaction_completed are either
					 * 0 to use the connection for pipelined
					 * or nonzero to hang it up.
					 *
					 * However for http/2. while we are
					 * still interested in hanging up the
					 * nwsi if there was a network-level
					 * fatal error, simply completing the
					 * transaction is a matter of the stream
					 * state, not the root connection at the
					 * network level
					 */
					if (wsi->http2_substream)
						return 1;
					else
						return -1;
				}

			return 1;  /* >0 indicates completed */
		}
	} while (0); // while (!lws_send_pipe_choked(wsi))

	lws_callback_on_writable(wsi);

	return 0; /* indicates further processing must be done */

file_had_it:
	lws_vfs_file_close(&wsi->http.fop_fd);

	return -1;
}

LWS_VISIBLE int
lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n = 0;

	lws_stats_atomic_bump(context, pt, LWSSTATS_C_API_READ, 1);

	if (lws_wsi_is_udp(wsi)) {
#if !defined(LWS_WITH_ESP32)
		wsi->udp->salen = sizeof(wsi->udp->sa);
		n = recvfrom(wsi->desc.sockfd, (char *)buf, len, 0,
			     &wsi->udp->sa, &wsi->udp->salen);
#endif
	} else
		n = recv(wsi->desc.sockfd, (char *)buf, len, 0);

	if (n >= 0) {
		if (wsi->vhost)
			wsi->vhost->conn_stats.rx += n;
		lws_stats_atomic_bump(context, pt, LWSSTATS_B_READ, n);
		lws_restart_ws_ping_pong_timer(wsi);

		return n;
	}

	if (LWS_ERRNO == LWS_EAGAIN ||
	    LWS_ERRNO == LWS_EWOULDBLOCK ||
	    LWS_ERRNO == LWS_EINTR)
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	lwsl_notice("error on reading from skt : %d\n", LWS_ERRNO);
	return LWS_SSL_CAPABLE_ERROR;
}

LWS_VISIBLE int
lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	int n = 0;

	if (lws_wsi_is_udp(wsi)) {
#if !defined(LWS_WITH_ESP32)
		if (wsi->trunc_len)
			n = sendto(wsi->desc.sockfd, buf, len, 0, &wsi->udp->sa_pending, wsi->udp->salen_pending);
		else
			n = sendto(wsi->desc.sockfd, buf, len, 0, &wsi->udp->sa, wsi->udp->salen);
#endif
	} else
		n = send(wsi->desc.sockfd, (char *)buf, len, MSG_NOSIGNAL);
//	lwsl_info("%s: sent len %d result %d", __func__, len, n);
	if (n >= 0)
		return n;

	if (LWS_ERRNO == LWS_EAGAIN ||
	    LWS_ERRNO == LWS_EWOULDBLOCK ||
	    LWS_ERRNO == LWS_EINTR) {
		if (LWS_ERRNO == LWS_EWOULDBLOCK) {
			lws_set_blocking_send(wsi);
		}

		return LWS_SSL_CAPABLE_MORE_SERVICE;
	}

	lwsl_debug("ERROR writing len %d to skt fd %d err %d / errno %d\n",
			len, wsi->desc.sockfd, n, LWS_ERRNO);

	return LWS_SSL_CAPABLE_ERROR;
}

LWS_VISIBLE int
lws_ssl_pending_no_ssl(struct lws *wsi)
{
	(void)wsi;
#if defined(LWS_WITH_ESP32)
	return 100;
#else
	return 0;
#endif
}
