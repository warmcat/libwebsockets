/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "private-lib-core.h"

/*
 * Tell the role that everything IO buffered for the wsi's transport has gone
 * out.  Returns what its tx_drained op says, 0 for a role without one.
 */
int
lws_io_tx_drained(struct lws *wsi)
{
	if (!wsi->role_ops ||
	    !lws_rops_fidx(wsi->role_ops, LWS_ROPS_tx_drained))
		return 0;

	return lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_tx_drained).
							tx_drained(wsi);
}

/*
 * notice this returns number of bytes consumed, or -1
 */
int
lws_io_tx_push(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_context *context = lws_get_context(wsi);
	size_t real_len = len;
	unsigned int n, m;
	int queued = 0, draining = 0;

	/*
	 * If you're looking to dump data being sent down the tls tunnel, see
	 * lws_ssl_capable_write() in lib/tls/mbedtls/mbedtls-ssl.c or
	 * lib/tls/openssl/openssl-ssl.c.
	 *
	 * There's also a corresponding lws_ssl_capable_read() in those files
	 * where you can enable a dump of decrypted data as soon as it was
	 * read.
	 */

	/*
	 * just ignore sends after we cleared the truncation buffer... of a
	 * close that has started.  A live connection that is to close once
	 * flushed (LCS_CLOSE_WHEN_FLUSHED, lws_raw_transaction_completed()) is
	 * not in a close yet, and what it sends still goes.
	 */
	if (lwsi_close(wsi) == LCS_FLUSHING_BEFORE_CLOSE &&
	    !lws_has_buffered_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    && !wsi->http.comp_ctx.may_have_more
#endif
	    )
		return (int)len;

	/*
	 * A partial send goes first.  An h3 stream's frames that quic holds,
	 * queued or in flight, are not ahead of these in lws' order: quic
	 * sends and retransmits them.
	 */
	if (buf && lws_has_buflist_out(wsi)) {
		lwsl_wsi_info(wsi, "** prot: %s, incr buflist_out by %lu",
				   wsi->a.protocol->name, (unsigned long)len);

		/*
		 * already buflist ahead of this, add it on the tail of the
		 * buflist, then ignore it for now and act like we're flushing
		 * the buflist...
		 */

		if (lws_buflist_append_segment(&wsi->buflist_out, buf, len))
			return -1;

		/*
		 * The caller's bytes are all taken (queued): what we return
		 * is what happened to them, not how much of the earlier
		 * partial the drain below managed, which callers comparing the
		 * return to their length were reading as a failed write and
		 * killing the connection over
		 */
		queued = (int)len;
		buf = NULL;
		len = 0;
	}

	if (wsi->buflist_out) {
		/* we have to drain the earliest buflist_out stuff first */

		len = lws_buflist_next_segment_len(&wsi->buflist_out, &buf);
		real_len = len;
		draining = 1;

		lwsl_wsi_debug(wsi, "draining %d", (int)len);
	}

	if (!len || !buf)
		return 0;

	if (!wsi->mux_substream && !lws_socket_is_valid(wsi->io->desc.sockfd))
		lwsl_wsi_err(wsi, "invalid sock");

	/* limit sending */
	if (wsi->a.protocol->tx_packet_size)
		n = (unsigned int)wsi->a.protocol->tx_packet_size;
	else {
		n = (unsigned int)wsi->a.protocol->rx_buffer_size;
		if (!n)
			n = context->pt_serv_buf_size;
	}
	n += LWS_PRE + 4;
	if (n > len)
		n = (unsigned int)len;

	/* nope, send it on the socket directly */

	if (lws_fi(&wsi->fic, "sendfail"))
		m = (unsigned int)LWS_SSL_CAPABLE_ERROR;
	else
		m = (unsigned int)lws_ssl_capable_write(wsi, buf, n);

	// lwsl_wsi_info(wsi, "ssl_capable_write (%d) says %d", n, m);

	switch ((int)m) {
	case LWS_SSL_CAPABLE_ERROR:
		/* we're going to close, let close know sends aren't possible */
		lwsi_set_skt_unusable(wsi, 1);
		return -1;
	case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
	case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
		/*
		 * nothing got sent, not fatal.  Retry the whole thing later,
		 * ie, implying treat it was a truncated send so it gets
		 * retried
		 */
		m = 0;
		break;
	}

	if ((int)m < 0)
		m = 0;

	/*
	 * n is never more than real_len, but the remainder below is taken from
	 * real_len, so check against that as well
	 */
	if (m > n || m > real_len) {
		/* a tls backend claiming more than we offered it is broken */
		lwsl_wsi_err(wsi, "wrote %u of %u", m, n);
		lwsi_set_skt_unusable(wsi, 1);
		return -1;
	}

	/*
	 * we were sending this from buflist_out?  Then not sending everything
	 * is a small matter of advancing ourselves only by the amount we did
	 * send in the buflist.
	 */
	if (draining) {
		if (m) {
			lwsl_wsi_info(wsi, "partial adv %d (vs %ld)",
					   m, (long)real_len);
			lws_buflist_use_segment(&wsi->buflist_out, m);
		}

		if (!lws_has_buflist_out(wsi)) {
			lwsl_wsi_info(wsi, "buflist_out flushed");

			m = (unsigned int)real_len;
			if (lwsi_flushing_to_close(wsi)) {
				lwsl_wsi_info(wsi, "*signalling to close now");
				return -1; /* retry closing now */
			}

			/* what waited for the output to be gone is the role's */
			switch (lws_io_tx_drained(wsi)) {
			case -1:
				return -1;
			case 1:
				return queued ? queued : (int)real_len;
			default:
				break;
			}
		}
		/* always callback on writeable */
		lws_callback_on_writable(wsi);

		return queued ? queued : (int)m;
	}

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	if (wsi->http.comp_ctx.may_have_more)
		lws_callback_on_writable(wsi);
#endif

	if (m == real_len)
		/* what we just sent went out cleanly */
		return (int)m;

	/*
	 * We were not able to send everything... and we were not sending from
	 * an existing buflist_out.  So we are starting a fresh buflist_out, by
	 * buffering the unsent remainder on it.
	 * (it will get first priority next time the socket is writable).
	 */
	lwsl_wsi_debug(wsi, "new partial sent %d from %lu total",
			    m, (unsigned long)real_len);

	if (lws_buflist_append_segment(&wsi->buflist_out, buf + m,
				       real_len - m) < 0)
		return -1;

#if defined(LWS_WITH_UDP)
	if (lws_wsi_is_udp(wsi))
		/* stash original destination for fulfilling UDP partials */
		wsi->io->udp->sa46_pending = wsi->io->udp->sa46;
#endif

	/* since something buffered, force it to get another chance to send */
	lws_callback_on_writable(wsi);

	return (int)real_len;
}

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_FILE_OPS)
/*
 * The send loop of a served file: IO's side of the file's tx (see
 * README.sans-io-split.md, "A content source's tx").  While the transport
 * can take more, ask lws_http_file_tx() for the next payload and write it;
 * when the file is done and nothing of it is left buffered here, the
 * response is complete.
 *
 * <0: error, the wsi should be closed.  >0: the file was completely sent
 * and its completion delivered.  0: more service is needed later, the wsi
 * should be left alone.
 */
int
lws_serve_http_file_fragment(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	unsigned char *buf = pt->serv_buf + LWS_PRE, *p = NULL;
	enum lws_write_protocol wp;
	int n, m, last, sb;

	do {
		/*
		 * priority 1: a partial send.  An h3 stream's frames that
		 * quic holds, queued or in flight, are quic's to send; waiting
		 * on their acks here sent one chunk per round trip.
		 */

		if (lws_has_buflist_out(wsi)) {
			if (lws_io_tx_push(wsi, NULL, 0) < 0) {
				lwsl_wsi_info(wsi, "closing");
				goto had_it;
			}
			break;
		}

		/* priority 2: buffered pre-compression-transform */

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
		if (wsi->http.comp_ctx.buflist_comp ||
		    wsi->http.comp_ctx.may_have_more) {
			enum lws_write_protocol cwp = LWS_WRITE_HTTP;

			lwsl_wsi_info(wsi, "completing comp partial (buflist %p, may %d)",
				      wsi->http.comp_ctx.buflist_comp,
				      wsi->http.comp_ctx.may_have_more);

			if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_write_role_protocol) &&
			    lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_write_role_protocol).
					write_role_protocol(wsi, NULL, 0, &cwp) < 0) {
				lwsl_wsi_info(wsi, "signalling to close");
				goto had_it;
			}
			lws_callback_on_writable(wsi);

			break;
		}
#endif

		sb = lws_servbuf_claim(pt, buf,
				       wsi->a.context->pt_serv_buf_size - LWS_PRE,
				       "file tx");
		n = lws_http_file_tx(wsi, buf,
				     wsi->a.context->pt_serv_buf_size - LWS_PRE,
				     &p, &wp, &last);
		if (n == LWS_TX_FAIL || n == LWS_TX_WAIT) {
			lws_servbuf_release(pt, sb);
			return n == LWS_TX_FAIL ? -1 : 0;
		}

		if (n > 0) {
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
					(int)wsi->a.context->timeout_secs);

			m = lws_write(wsi, p, (size_t)n, wp);
			lws_servbuf_release(pt, sb);
			if (m < 0)
				goto had_it;
			if (m != n) {
				/*
				 * The role would not take it: an h2 stream
				 * the peer already closed bins its writes.
				 * The response cannot complete on it.
				 */
				lwsl_wsi_notice(wsi, "role took %d of %d", m, n);
				goto had_it;
			}
		} else {
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
			/*
			 * Nothing more of the file (or it was empty): but a
			 * compressed body only ends when the compressor is
			 * told it has, which flushes it and, on h1, sends the
			 * last chunk.  If no lump went to it as final, the end
			 * goes on its own now.
			 */
			if (wsi->http.lcs &&
			    !wsi->http.comp_ctx.final_on_input_side &&
			    lws_write(wsi, buf, 0, LWS_WRITE_HTTP_FINAL) < 0) {
				lws_servbuf_release(pt, sb);
				goto had_it;
			}
#endif
			lws_servbuf_release(pt, sb);
			last = 1;
		}

		/*
		 * the file is sent when lws holds none of it; waiting for the
		 * transport to send and the peer to ack it is the transaction
		 * completion's business
		 */
		if (last && !lws_has_buflist_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
		    && !wsi->http.comp_ctx.buflist_comp &&
		    !wsi->http.comp_ctx.may_have_more
#endif
		   )
			return lws_http_file_complete(wsi);

		/*
		 * while(1) here causes us to spam the whole file contents into
		 * a hugely bloated output buffer if it ever can't send the
		 * whole chunk...
		 */
	} while (!lws_send_pipe_choked(wsi));

	lws_callback_on_writable(wsi);

	return 0; /* indicates further processing must be done */

had_it:
	lws_http_file_tx_abort(wsi);

	return -1;
}
#endif

int
lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, size_t len)
{
	int n = 0, en;

	if (wsi->io->transport) {
		n = wsi->io->transport->read(wsi, wsi->io->transport_opaque,
					    buf, len);
		/* only the documented returns reach the pump's switch */
		if (n < LWS_SSL_CAPABLE_MORE_SERVICE_WRITE || n > (int)len)
			n = LWS_SSL_CAPABLE_ERROR;

		return n;
	}

	errno = 0;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _lws_start = lws_now_usecs();
#endif

#if defined(LWS_WITH_UDP)
	if (lws_wsi_is_udp(wsi)) {
		socklen_t slt = sizeof(wsi->io->udp->sa46);

		if (wsi->io->pending_sock_err) {
			/* the icmp error the service loop took from the socket */
			en = wsi->io->pending_sock_err;
			wsi->io->pending_sock_err = 0;
			n = -1;
		} else {
			n = (int)recvfrom(wsi->io->desc.sockfd, (char *)buf,
					LWS_POSIX_LENGTH_CAST(len), 0,
					sa46_sockaddr(&wsi->io->udp->sa46), &slt);
			en = LWS_ERRNO;
		}
	} else
#endif
	{
		n = (int)recv(wsi->io->desc.sockfd, (char *)buf,
				LWS_POSIX_LENGTH_CAST(len), 0);
		en = LWS_ERRNO;
	}

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _lws_start) / 1000);
		if (ms > 2) {
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _lws_start, 2000, "recv:%dms", ms);
		}
	}
#endif

	if (n >= 0) {

		if (!n && wsi->io->unix_skt)
			goto do_err;

#if defined(LWS_WITH_UDP)
		/*
		 * A zero-length datagram is a completely legal datagram and,
		 * unlike a stream socket, does not indicate EOF... it must not
		 * be turned into an error that destroys the UDP wsi
		 */
		if (!n && lws_wsi_is_udp(wsi))
			return 0;
#endif

		/*
		 * See https://libwebsockets.org/
		 * pipermail/libwebsockets/2019-March/007857.html
		 */
		if (!n && !wsi->io->unix_skt)
			goto do_err;

#if defined(LWS_WITH_SYS_METRICS) && defined(LWS_WITH_SERVER)
		if (wsi->a.vhost)
			lws_metric_event(wsi->a.vhost->mt_traffic_rx,
					 METRES_GO /* rx */, (unsigned int)n);
#endif

		return n;
	}

	if (en == LWS_EAGAIN ||
	    en == LWS_EWOULDBLOCK ||
	    en == LWS_EINTR)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

do_err:
#if defined(LWS_WITH_SYS_METRICS) && defined(LWS_WITH_SERVER)
	if (wsi->a.vhost)
		lws_metric_event(wsi->a.vhost->mt_traffic_rx, METRES_NOGO, 0u);
#endif

	lwsl_wsi_info(wsi, "error on reading from skt : %d, errno %d", n, en);

	return LWS_SSL_CAPABLE_ERROR;
}

/*
 * io_ops tx_choked (lws-io-ops.h): would the transport under wsi, the
 * connection owning it, block a write now.  What sansIO holds itself,
 * lws_send_pipe_choked() has already answered for.
 *
 * A connection on a transport (lws_set_transport()) is written through the
 * transport, not its fd, which is only its place in the poll set: the fd's
 * writability says nothing about it.  The transport takes what it can and
 * a short write leaves the rest buffered, which sansIO answers for, so it
 * is not choked here.  A connection with no socket (yet, or any more) has
 * nothing to take a write.  Otherwise the platform asks the socket.
 */
int
lws_io_tx_choked_pollfd(struct lws *wsi)
{
	if (wsi->io->transport)
		return 0;

	if (!lws_socket_is_valid(wsi->io->desc.sockfd))
		return 1;

	return lws_plat_tx_choked(wsi);
}

int
lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, size_t len)
{
	int n = 0, en = 0;

	if (wsi->io->transport)
		return wsi->io->transport->write(wsi, wsi->io->transport_opaque,
						buf, len);
#if defined(LWS_PLAT_OPTEE)
	ssize_t send(int sockfd, const void *buf, size_t len, int flags);
#endif

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _lws_start = lws_now_usecs();
#endif

#if defined(LWS_WITH_UDP)
	if (lws_wsi_is_udp(wsi)) {

		if (lws_fi(&wsi->fic, "udp_tx_loss")) {
			/* pretend it was sent */
			n = (int)(ssize_t)len;
			goto post_send;
		}

		if (wsi->io->pending_sock_err) {
			/* the icmp error the service loop took from the socket */
			en = wsi->io->pending_sock_err;
			wsi->io->pending_sock_err = 0;
			n = -1;
			goto post_send;
		}

		if (lws_has_buffered_out(wsi))
			n = (int)sendto(wsi->io->desc.sockfd, (const char *)buf,
				   LWS_POSIX_LENGTH_CAST(len), 0, sa46_sockaddr(&wsi->io->udp->sa46_pending),
				   sa46_socklen(&wsi->io->udp->sa46_pending));
		else if (wsi->io->udp->sa46.sa4.sin_family == AF_UNSPEC)
			/*
			 * No peer is recorded: a socket the application
			 * connected itself before adopting it, which sends to
			 * its connected peer with no destination given (an
			 * AF_UNSPEC one is refused with EINVAL)
			 */
			n = (int)sendto(wsi->io->desc.sockfd, (const char *)buf,
				   LWS_POSIX_LENGTH_CAST(len), 0, NULL, 0);
		else
			n = (int)sendto(wsi->io->desc.sockfd, (const char *)buf,
				   LWS_POSIX_LENGTH_CAST(len), 0, sa46_sockaddr(&wsi->io->udp->sa46),
				   sa46_socklen(&wsi->io->udp->sa46));

		if (n < 0 && LWS_ERRNO == LWS_EISCONN)
			n = (int)sendto(wsi->io->desc.sockfd, (const char *)buf,
				   LWS_POSIX_LENGTH_CAST(len), 0, NULL, 0);
	} else
#endif
		if (wsi->role_ops->file_handle)
			n = (int)write((int)(lws_intptr_t)wsi->io->desc.filefd, buf,
					LWS_POSIX_LENGTH_CAST(len));
		else
			n = (int)send(wsi->io->desc.sockfd, (char *)buf,
					LWS_POSIX_LENGTH_CAST(len), MSG_NOSIGNAL);
//	lwsl_info("%s: sent len %d result %d", __func__, len, n);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _lws_start) / 1000);
		if (ms > 2) {
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _lws_start, 2000, "send:%dms", ms);
		}
	}
#endif

	en = LWS_ERRNO;

#if defined(LWS_WITH_UDP)
post_send:
#endif
	if (n >= 0)
		return n;

	if (en == LWS_EAGAIN ||
	    en == LWS_EWOULDBLOCK ||
	    en == LWS_EINTR) {
		if (en == LWS_EWOULDBLOCK) {
			lws_set_blocking_send(wsi);
		}

		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	lwsl_wsi_debug(wsi, "ERROR writing len %d to skt fd %d err %d / errno %d",
			    (int)(ssize_t)len, wsi->io->desc.sockfd, n, en);

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_pending_no_ssl(struct lws *wsi)
{
	(void)wsi;
#if defined(LWS_PLAT_FREERTOS)
	return 100;
#else
	return 0;
#endif
}
