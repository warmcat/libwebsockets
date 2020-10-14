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
 * notice this returns number of bytes consumed, or -1
 */
int
lws_issue_raw(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	size_t real_len = len;
	unsigned int n, m;

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
	 * Detect if we got called twice without going through the
	 * event loop to handle pending.  Since that guarantees extending any
	 * existing buflist_out it's inefficient.
	 */
	if (0 && buf && wsi->could_have_pending) {
		lwsl_hexdump_level(LLL_INFO, buf, len);
		lwsl_info("** %p: vh: %s, prot: %s, role %s: "
			  "Inefficient back-to-back write of %lu detected...\n",
			  wsi, wsi->a.vhost ? wsi->a.vhost->name : "no vhost",
			  wsi->a.protocol->name, wsi->role_ops->name,
			  (unsigned long)len);
	}

	lws_stats_bump(pt, LWSSTATS_C_API_WRITE, 1);

	/* just ignore sends after we cleared the truncation buffer */
	if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE &&
	    !lws_has_buffered_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    && !wsi->http.comp_ctx.may_have_more
#endif
	    )
		return (int)len;

	if (buf && lws_has_buffered_out(wsi)) {
		lwsl_info("** %p: vh: %s, prot: %s, incr buflist_out by %lu\n",
			  wsi, wsi->a.vhost ? wsi->a.vhost->name : "no vhost",
			  wsi->a.protocol->name, (unsigned long)len);

		/*
		 * already buflist ahead of this, add it on the tail of the
		 * buflist, then ignore it for now and act like we're flushing
		 * the buflist...
		 */

		if (lws_buflist_append_segment(&wsi->buflist_out, buf, len))
			return -1;

		buf = NULL;
		len = 0;
	}

	if (wsi->buflist_out) {
		/* we have to drain the earliest buflist_out stuff first */

		len = lws_buflist_next_segment_len(&wsi->buflist_out, &buf);
		real_len = len;

		lwsl_debug("%s: draining %d\n", __func__, (int)len);
	}

	if (!len || !buf)
		return 0;

	if (!wsi->mux_substream && !lws_socket_is_valid(wsi->desc.sockfd))
		lwsl_err("%s: invalid sock %p\n", __func__, wsi);

	/* limit sending */
	if (wsi->a.protocol->tx_packet_size)
		n = (int)wsi->a.protocol->tx_packet_size;
	else {
		n = (int)wsi->a.protocol->rx_buffer_size;
		if (!n)
			n = context->pt_serv_buf_size;
	}
	n += LWS_PRE + 4;
	if (n > len)
		n = (int)len;

	/* nope, send it on the socket directly */

	m = lws_ssl_capable_write(wsi, buf, n);
	lwsl_info("%s: ssl_capable_write (%d) says %d\n", __func__, n, m);

	/* something got written, it can have been truncated now */
	wsi->could_have_pending = 1;

	switch (m) {
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
		m = 0;
		break;
	}

	if ((int)m < 0)
		m = 0;

	/*
	 * we were sending this from buflist_out?  Then not sending everything
	 * is a small matter of advancing ourselves only by the amount we did
	 * send in the buflist.
	 */
	if (lws_has_buffered_out(wsi)) {
		if (m) {
			lwsl_info("%p partial adv %d (vs %ld)\n", wsi, m,
					(long)real_len);
			lws_buflist_use_segment(&wsi->buflist_out, m);
		}

		if (!lws_has_buffered_out(wsi)) {
			lwsl_info("%s: wsi %p: buflist_out flushed\n",
				  __func__, wsi);

			m = (int)real_len;
			if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE) {
				lwsl_info("*%p signalling to close now\n", wsi);
				return -1; /* retry closing now */
			}

			if (wsi->close_when_buffered_out_drained) {
				wsi->close_when_buffered_out_drained = 0;
				return -1;
			}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
#if defined(LWS_WITH_SERVER)
			if (wsi->http.deferred_transaction_completed) {
				lwsl_notice("%s: partial completed, doing "
					    "deferred transaction completed\n",
					    __func__);
				wsi->http.deferred_transaction_completed = 0;
				return lws_http_transaction_completed(wsi) ?
							-1 : (int)real_len;
			}
#endif
#endif
#if defined(LWS_ROLE_WS)
			/* Since buflist_out flushed, we're not inside a frame any more */
			if (wsi->ws)
				wsi->ws->inside_frame = 0;
#endif
		}
		/* always callback on writeable */
		lws_callback_on_writable(wsi);

		return m;
	}

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	if (wsi->http.comp_ctx.may_have_more)
		lws_callback_on_writable(wsi);
#endif

	if (m == real_len)
		/* what we just sent went out cleanly */
		return m;

	/*
	 * We were not able to send everything... and we were not sending from
	 * an existing buflist_out.  So we are starting a fresh buflist_out, by
	 * buffering the unsent remainder on it.
	 * (it will get first priority next time the socket is writable).
	 */
	lwsl_debug("%p new partial sent %d from %lu total\n", wsi, m,
		    (unsigned long)real_len);

	if (lws_buflist_append_segment(&wsi->buflist_out, buf + m,
				       real_len - m) < 0)
		return -1;

	lws_stats_bump(pt, LWSSTATS_C_WRITE_PARTIALS, 1);
	lws_stats_bump(pt, LWSSTATS_B_PARTIALS_ACCEPTED_PARTS, m);

#if defined(LWS_WITH_UDP)
	if (lws_wsi_is_udp(wsi))
		/* stash original destination for fulfilling UDP partials */
		wsi->udp->sa46_pending = wsi->udp->sa46;
#endif

	/* since something buffered, force it to get another chance to send */
	lws_callback_on_writable(wsi);

	return (int)real_len;
}

int
lws_write(struct lws *wsi, unsigned char *buf, size_t len,
	  enum lws_write_protocol wp)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
#if defined(LWS_WITH_DETAILED_LATENCY)
	lws_usec_t us;
#endif
	int m;

	lws_stats_bump(pt, LWSSTATS_C_API_LWS_WRITE, 1);

	if ((int)len < 0) {
		lwsl_err("%s: suspicious len int %d, ulong %lu\n", __func__,
				(int)len, (unsigned long)len);
		return -1;
	}

	lws_stats_bump(pt, LWSSTATS_B_WRITE, len);

#ifdef LWS_WITH_ACCESS_LOG
	wsi->http.access_log.sent += len;
#endif
#if defined(LWS_WITH_SERVER_STATUS)
	if (wsi->a.vhost)
		wsi->a.vhost->conn_stats.tx += len;
#endif
#if defined(LWS_WITH_DETAILED_LATENCY)
	us = lws_now_usecs();
#endif

	assert(wsi->role_ops);
	if (!wsi->role_ops->write_role_protocol)
		return lws_issue_raw(wsi, buf, len);

	m = wsi->role_ops->write_role_protocol(wsi, buf, len, &wp);
	if (m < 0)
		return m;

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (wsi->a.context->detailed_latency_cb) {
		wsi->detlat.req_size = len;
		wsi->detlat.acc_size = m;
		wsi->detlat.type = LDLT_WRITE;
		if (wsi->detlat.earliest_write_req_pre_write)
			wsi->detlat.latencies[LAT_DUR_PROXY_PROXY_REQ_TO_WRITE] =
					us - wsi->detlat.earliest_write_req_pre_write;
		else
			wsi->detlat.latencies[LAT_DUR_PROXY_PROXY_REQ_TO_WRITE] = 0;
		wsi->detlat.latencies[LAT_DUR_USERCB] = lws_now_usecs() - us;
		lws_det_lat_cb(wsi->a.context, &wsi->detlat);

	}
#endif

	return m;
}

int
lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n = 0;

	lws_stats_bump(pt, LWSSTATS_C_API_READ, 1);

	errno = 0;
#if defined(LWS_WITH_UDP)
	if (lws_wsi_is_udp(wsi)) {
		socklen_t slt = sizeof(wsi->udp->sa46);

		n = recvfrom(wsi->desc.sockfd, (char *)buf, len, 0,
				sa46_sockaddr(&wsi->udp->sa46), &slt);
	} else
#endif
		n = recv(wsi->desc.sockfd, (char *)buf, len, 0);

	if (n >= 0) {

		if (!n && wsi->unix_skt)
			return LWS_SSL_CAPABLE_ERROR;

		/*
		 * See https://libwebsockets.org/
		 * pipermail/libwebsockets/2019-March/007857.html
		 */
		if (!n)
			return LWS_SSL_CAPABLE_ERROR;

#if defined(LWS_WITH_SERVER_STATUS)
		if (wsi->a.vhost)
			wsi->a.vhost->conn_stats.rx += n;
#endif
		lws_stats_bump(pt, LWSSTATS_B_READ, n);

		return n;
	}

	if (LWS_ERRNO == LWS_EAGAIN ||
	    LWS_ERRNO == LWS_EWOULDBLOCK ||
	    LWS_ERRNO == LWS_EINTR)
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	lwsl_info("error on reading from skt : %d\n", LWS_ERRNO);
	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	int n = 0;
#if defined(LWS_PLAT_OPTEE)
	ssize_t send(int sockfd, const void *buf, size_t len, int flags);
#endif

#if defined(LWS_WITH_UDP)
	if (lws_wsi_is_udp(wsi)) {
		if (wsi->a.context->udp_loss_sim_tx_pc) {
			uint16_t u16;
			/*
			 * We should randomly drop some of these
			 */

			if (lws_get_random(wsi->a.context, &u16, 2) == 2 &&
			    ((u16 * 100) / 0xffff) <=
				    wsi->a.context->udp_loss_sim_tx_pc) {
				lwsl_warn("%s: dropping udp tx\n", __func__);
				/* pretend it was sent */
				n = len;
				goto post_send;
			}
		}
		if (lws_has_buffered_out(wsi))
			n = sendto(wsi->desc.sockfd, (const char *)buf,
				   len, 0, sa46_sockaddr(&wsi->udp->sa46_pending),
				   sa46_socklen(&wsi->udp->sa46_pending));
		else
			n = sendto(wsi->desc.sockfd, (const char *)buf,
				   len, 0, sa46_sockaddr(&wsi->udp->sa46),
				   sa46_socklen(&wsi->udp->sa46));
	} else
#endif
		if (wsi->role_ops->file_handle)
			n = write((int)(lws_intptr_t)wsi->desc.filefd, buf, len);
		else
			n = send(wsi->desc.sockfd, (char *)buf, len, MSG_NOSIGNAL);
//	lwsl_info("%s: sent len %d result %d", __func__, len, n);

#if defined(LWS_WITH_UDP)
post_send:
#endif
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
