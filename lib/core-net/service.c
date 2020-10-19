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

int
lws_callback_as_writeable(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int n, m;

	lws_stats_bump(pt, LWSSTATS_C_WRITEABLE_CB, 1);
#if defined(LWS_WITH_STATS)
	if (wsi->active_writable_req_us) {
		uint64_t ul = lws_now_usecs() -
			      wsi->active_writable_req_us;

		lws_stats_bump(pt, LWSSTATS_US_WRITABLE_DELAY_AVG, ul);
		lws_stats_max(pt, LWSSTATS_US_WORST_WRITABLE_DELAY, ul);
		wsi->active_writable_req_us = 0;
	}
#endif
#if defined(LWS_WITH_DETAILED_LATENCY)
	if (wsi->a.context->detailed_latency_cb && lwsi_state_est(wsi)) {
		lws_usec_t us = lws_now_usecs();

		wsi->detlat.earliest_write_req_pre_write =
					wsi->detlat.earliest_write_req;
		wsi->detlat.earliest_write_req = 0;
		wsi->detlat.latencies[LAT_DUR_PROXY_RX_TO_ONWARD_TX] =
		      ((uint32_t)us - wsi->detlat.earliest_write_req_pre_write);
	}
#endif
	n = wsi->role_ops->writeable_cb[lwsi_role_server(wsi)];
	m = user_callback_handle_rxflow(wsi->a.protocol->callback,
					wsi, (enum lws_callback_reasons) n,
					wsi->user_space, NULL, 0);

	return m;
}

int
lws_handle_POLLOUT_event(struct lws *wsi, struct lws_pollfd *pollfd)
{
	volatile struct lws *vwsi = (volatile struct lws *)wsi;
	int n;

	// lwsl_notice("%s: %p\n", __func__, wsi);

	vwsi->leave_pollout_active = 0;
	vwsi->handling_pollout = 1;
	/*
	 * if another thread wants POLLOUT on us, from here on while
	 * handling_pollout is set, he will only set leave_pollout_active.
	 * If we are going to disable POLLOUT, we will check that first.
	 */
	wsi->could_have_pending = 0; /* clear back-to-back write detection */

	/*
	 * user callback is lowest priority to get these notifications
	 * actually, since other pending things cannot be disordered
	 *
	 * Priority 1: pending truncated sends are incomplete ws fragments
	 *	       If anything else sent first the protocol would be
	 *	       corrupted.
	 *
	 *	       These are post- any compression transform
	 */

	if (lws_has_buffered_out(wsi)) {
		//lwsl_notice("%s: completing partial\n", __func__);
		if (lws_issue_raw(wsi, NULL, 0) < 0) {
			lwsl_info("%s signalling to close\n", __func__);
			goto bail_die;
		}
		/* leave POLLOUT active either way */
		goto bail_ok;
	} else
		if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE) {
			wsi->socket_is_permanently_unusable = 1;
			goto bail_die; /* retry closing now */
		}

	/* Priority 2: pre- compression transform */

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	if (wsi->http.comp_ctx.buflist_comp ||
	    wsi->http.comp_ctx.may_have_more) {
		enum lws_write_protocol wp = LWS_WRITE_HTTP;

		lwsl_info("%s: completing comp partial (buflist_comp %p, may %d)\n",
				__func__, wsi->http.comp_ctx.buflist_comp,
				wsi->http.comp_ctx.may_have_more
				);

		if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_write_role_protocol) &&
		    lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_write_role_protocol).
					write_role_protocol(wsi, NULL, 0, &wp) < 0) {
			lwsl_info("%s signalling to close\n", __func__);
			goto bail_die;
		}
		lws_callback_on_writable(wsi);

		goto bail_ok;
	}
#endif

#ifdef LWS_WITH_CGI
	/*
	 * A cgi connection's wire protocol remains h1 or h2.  He is just
	 * getting his data from his child cgis.
	 */
	if (wsi->http.cgi) {
		/* also one shot */
		if (pollfd)
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				lwsl_info("failed at set pollfd\n");
				return 1;
			}
		goto user_service_go_again;
	}
#endif

	/* if we got here, we should have wire protocol ops set on the wsi */
	assert(wsi->role_ops);

	if (!lws_rops_fidx(wsi->role_ops, LWS_ROPS_handle_POLLOUT))
		goto bail_ok;

	n = lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_handle_POLLOUT).
							handle_POLLOUT(wsi);
	switch (n) {
	case LWS_HP_RET_BAIL_OK:
		goto bail_ok;
	case LWS_HP_RET_BAIL_DIE:
		goto bail_die;
	case LWS_HP_RET_DROP_POLLOUT:
	case LWS_HP_RET_USER_SERVICE:
		break;
	default:
		assert(0);
	}

	/* one shot */

	if (pollfd) {
		int eff = vwsi->leave_pollout_active;

		if (!eff) {
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				lwsl_info("failed at set pollfd\n");
				goto bail_die;
			}
		}

		vwsi->handling_pollout = 0;

		/* cannot get leave_pollout_active set after the above */
		if (!eff && wsi->leave_pollout_active) {
			/*
			 * got set inbetween sampling eff and clearing
			 * handling_pollout, force POLLOUT on
			 */
			lwsl_debug("leave_pollout_active\n");
			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
				lwsl_info("failed at set pollfd\n");
				goto bail_die;
			}
		}

		vwsi->leave_pollout_active = 0;
	}

	if (lwsi_role_client(wsi) && !wsi->hdr_parsing_completed &&
	     lwsi_state(wsi) != LRS_H2_WAITING_TO_SEND_HEADERS &&
	     lwsi_state(wsi) != LRS_ISSUE_HTTP_BODY)
		goto bail_ok;

	if (n == LWS_HP_RET_DROP_POLLOUT)
		goto bail_ok;


#ifdef LWS_WITH_CGI
user_service_go_again:
#endif

	if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_perform_user_POLLOUT)) {
		if (lws_rops_func_fidx(wsi->role_ops,
				       LWS_ROPS_perform_user_POLLOUT).
						perform_user_POLLOUT(wsi) == -1)
			goto bail_die;
		else
			goto bail_ok;
	}

	lwsl_debug("%s: %p: non mux: wsistate 0x%lx, ops %s\n", __func__, wsi,
		   (unsigned long)wsi->wsistate, wsi->role_ops->name);

	vwsi = (volatile struct lws *)wsi;
	vwsi->leave_pollout_active = 0;

	n = lws_callback_as_writeable(wsi);
	vwsi->handling_pollout = 0;

	if (vwsi->leave_pollout_active)
		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
			goto bail_die;

	return n;

	/*
	 * since these don't disable the POLLOUT, they are always doing the
	 * right thing for leave_pollout_active whether it was set or not.
	 */

bail_ok:
	vwsi->handling_pollout = 0;
	vwsi->leave_pollout_active = 0;

	return 0;

bail_die:
	vwsi->handling_pollout = 0;
	vwsi->leave_pollout_active = 0;

	return -1;
}

int
lws_rxflow_cache(struct lws *wsi, unsigned char *buf, int n, int len)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	uint8_t *buffered;
	size_t blen;
	int ret = LWSRXFC_CACHED, m;

	/* his RX is flowcontrolled, don't send remaining now */
	blen = lws_buflist_next_segment_len(&wsi->buflist, &buffered);
	if (blen) {
		if (buf >= buffered && buf + len <= buffered + blen &&
		    blen != (size_t)len) {
			/*
			 * rxflow while we were spilling prev rxflow
			 *
			 * len indicates how much was unused, then... so trim
			 * the head buflist to match that situation
			 */

			lws_buflist_use_segment(&wsi->buflist, blen - len);
			lwsl_debug("%s: trim existing rxflow %d -> %d\n",
					__func__, (int)blen, (int)len);

			return LWSRXFC_TRIMMED;
		}
		ret = LWSRXFC_ADDITIONAL;
	}

	/* a new rxflow, buffer it and warn caller */

	lwsl_debug("%s: rxflow append %d\n", __func__, len - n);
	m = lws_buflist_append_segment(&wsi->buflist, buf + n, len - n);

	if (m < 0)
		return LWSRXFC_ERROR;
	if (m) {
		lwsl_debug("%s: added %p to rxflow list\n", __func__, wsi);
		if (lws_dll2_is_detached(&wsi->dll_buflist))
			lws_dll2_add_head(&wsi->dll_buflist, &pt->dll_buflist_owner);
	}

	return ret;
}

/* this is used by the platform service code to stop us waiting for network
 * activity in poll() when we have something that already needs service
 */

int
lws_service_adjust_timeout(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt;

	if (!context)
		return 1;

#if defined(LWS_WITH_SYS_SMD)
	if (!tsi && lws_smd_message_pending(context)) {
		lws_smd_msg_distribute(context);
		if (lws_smd_message_pending(context))
			return 0;
	}
#endif

	pt = &context->pt[tsi];

#if defined(LWS_WITH_EXTERNAL_POLL)
	{
		lws_usec_t u = __lws_sul_service_ripe(pt->pt_sul_owner,
				      LWS_COUNT_PT_SUL_OWNERS, lws_now_usecs());
		if (u < timeout_ms * 1000)
			timeout_ms = u / 1000;
	}
#endif

	/*
	 * Figure out if we really want to wait in poll()... we only need to
	 * wait if really nothing already to do and we have to wait for
	 * something from network
	 */
#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	/* 1) if we know we are draining rx ext, do not wait in poll */
	if (pt->ws.rx_draining_ext_list)
		return 0;
#endif

#if defined(LWS_WITH_TLS)
	/* 2) if we know we have non-network pending data,
	 *    do not wait in poll */

	if (pt->context->tls_ops &&
	    pt->context->tls_ops->fake_POLLIN_for_buffered &&
	    pt->context->tls_ops->fake_POLLIN_for_buffered(pt))
			return 0;
#endif

	/*
	 * 4) If there is any wsi with rxflow buffered and in a state to process
	 *    it, we should not wait in poll
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d, pt->dll_buflist_owner.head) {
		struct lws *wsi = lws_container_of(d, struct lws, dll_buflist);

		if (!lws_is_flowcontrolled(wsi) &&
		     lwsi_state(wsi) != LRS_DEFERRING_ACTION)
			return 0;

	/*
	 * 5) If any guys with http compression to spill, we shouldn't wait in
	 *    poll but hurry along and service them
	 */

	} lws_end_foreach_dll(d);

	return timeout_ms;
}

/*
 * POLLIN said there is something... we must read it, and either use it; or
 * if other material already in the buflist append it and return the buflist
 * head material.
 */
int
lws_buflist_aware_read(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_tokens *ebuf, char fr, const char *hint)
{
	int n, e, bns;
	uint8_t *ep, *b;

	// lwsl_debug("%s: wsi %p: %s: prior %d\n", __func__, wsi, hint, prior);
	// lws_buflist_describe(&wsi->buflist, wsi, __func__);

	(void)hint;
	if (!ebuf->token)
		ebuf->token = pt->serv_buf + LWS_PRE;
	if (!ebuf->len ||
	    (unsigned int)ebuf->len > wsi->a.context->pt_serv_buf_size - LWS_PRE)
		ebuf->len = wsi->a.context->pt_serv_buf_size - LWS_PRE;

	e = ebuf->len;
	ep = ebuf->token;

	/* h2 or muxed stream... must force the read due to HOL blocking */

	if (wsi->mux_substream)
		fr = 1;

	/* there's something on the buflist? */

	bns = (int)lws_buflist_next_segment_len(&wsi->buflist, &ebuf->token);
	b = ebuf->token;

	if (!fr && bns)
		goto buflist_material;

	/* we're going to read something */

	ebuf->token = ep;
	ebuf->len = n = lws_ssl_capable_read(wsi, ep, e);

	lwsl_debug("%s: wsi %p: %s: ssl_capable_read %d\n", __func__,
			wsi, hint, ebuf->len);

	if (!bns && /* only acknowledge error when we handled buflist content */
	    n == LWS_SSL_CAPABLE_ERROR) {
		lwsl_debug("%s: SSL_CAPABLE_ERROR\n", __func__);
		return -1;
	}

	if (n <= 0 && bns)
		/*
		 * There wasn't anything to read yet, but there's something
		 * on the buflist to give him
		 */
		goto buflist_material;

	/* we read something */

	if (fr && bns) {
		/*
		 * Stash what we read, since there's earlier buflist material
		 */

		n = lws_buflist_append_segment(&wsi->buflist, ebuf->token, ebuf->len);
		if (n < 0)
			return -1;
		if (n && lws_dll2_is_detached(&wsi->dll_buflist))
			lws_dll2_add_head(&wsi->dll_buflist,
					  &pt->dll_buflist_owner);

		goto buflist_material;
	}

	/*
	 * directly return what we read
	 */

	return 0;

buflist_material:

	ebuf->token = b;
	if (e < bns)
		/* restrict to e, if more than e available */
		ebuf->len = e;
	else
		ebuf->len = bns;

	return 1; /* from buflist */
}

int
lws_buflist_aware_finished_consuming(struct lws *wsi, struct lws_tokens *ebuf,
				     int used, int buffered, const char *hint)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int m;

	//lwsl_debug("%s %s consuming buffered %d used %zu / %zu\n", __func__, hint,
	//		buffered, (size_t)used, (size_t)ebuf->len);
	// lws_buflist_describe(&wsi->buflist, wsi, __func__);

	/* it's in the buflist; we didn't use any */

	if (!used && buffered)
		return 0;

	if (used && buffered) {
		if (wsi->buflist) {
			m = (int)lws_buflist_use_segment(&wsi->buflist, (size_t)used);
			// lwsl_notice("%s: used %d, next %d\n", __func__, used, m);
			// lws_buflist_describe(&wsi->buflist, wsi, __func__);
			if (m)
				return 0;
		}

		lwsl_info("%s: removed %p from dll_buflist\n", __func__, wsi);
		lws_dll2_remove(&wsi->dll_buflist);

		return 0;
	}

	/* any remainder goes on the buflist */

	if (used != ebuf->len) {
		// lwsl_notice("%s %s bac appending %d\n", __func__, hint,
		//		ebuf->len - used);
		m = lws_buflist_append_segment(&wsi->buflist,
					       ebuf->token + used,
					       ebuf->len - used);
		if (m < 0)
			return 1; /* OOM */
		if (m) {
			lwsl_debug("%s: added %p to rxflow list\n",
				   __func__, wsi);
			if (lws_dll2_is_detached(&wsi->dll_buflist))
				lws_dll2_add_head(&wsi->dll_buflist,
					 &pt->dll_buflist_owner);
		}
		// lws_buflist_describe(&wsi->buflist, wsi, __func__);
	}

	return 0;
}

void
lws_service_do_ripe_rxflow(struct lws_context_per_thread *pt)
{
	struct lws_pollfd pfd;

	if (!pt->dll_buflist_owner.head)
		return;

	/*
	 * service all guys with pending rxflow that reached a state they can
	 * accept the pending data
	 */

	lws_pt_lock(pt, __func__);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   pt->dll_buflist_owner.head) {
		struct lws *wsi = lws_container_of(d, struct lws, dll_buflist);

		pfd.events = LWS_POLLIN;
		pfd.revents = LWS_POLLIN;
		pfd.fd = -1;

		lwsl_debug("%s: rxflow processing: %p fc=%d, 0x%lx\n", __func__,
			   wsi, lws_is_flowcontrolled(wsi),
			   (unsigned long)wsi->wsistate);

		if (!lws_is_flowcontrolled(wsi) &&
		    lwsi_state(wsi) != LRS_DEFERRING_ACTION) {
			pt->inside_lws_service = 1;

			if (lws_rops_func_fidx(wsi->role_ops,
					       LWS_ROPS_handle_POLLIN).
						handle_POLLIN(pt, wsi, &pfd) ==
						   LWS_HPI_RET_PLEASE_CLOSE_ME)
				lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
						"close_and_handled");
			pt->inside_lws_service = 0;
		}

	} lws_end_foreach_dll_safe(d, d1);

	lws_pt_unlock(pt);
}

/*
 * guys that need POLLIN service again without waiting for network action
 * can force POLLIN here if not flowcontrolled, so they will get service.
 *
 * Return nonzero if anybody got their POLLIN faked
 */
int
lws_service_flag_pending(struct lws_context *context, int tsi)
{
	struct lws_context_per_thread *pt;
	int forced = 0;

	if (!context)
		return 1;

	pt = &context->pt[tsi];

	lws_pt_lock(pt, __func__);

	/*
	 * 1) If there is any wsi with a buflist and in a state to process
	 *    it, we should not wait in poll
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d, pt->dll_buflist_owner.head) {
		struct lws *wsi = lws_container_of(d, struct lws, dll_buflist);

		if (!lws_is_flowcontrolled(wsi) &&
		     lwsi_state(wsi) != LRS_DEFERRING_ACTION) {
			forced = 1;
			break;
		}
	} lws_end_foreach_dll(d);

#if defined(LWS_ROLE_WS)
	forced |= lws_rops_func_fidx(&role_ops_ws,
				     LWS_ROPS_service_flag_pending).
					service_flag_pending(context, tsi);
#endif

#if defined(LWS_WITH_TLS)
	/*
	 * 2) For all guys with buffered SSL read data already saved up, if they
	 * are not flowcontrolled, fake their POLLIN status so they'll get
	 * service to use up the buffered incoming data, even though their
	 * network socket may have nothing
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
			lws_dll2_get_head(&pt->tls.dll_pending_tls_owner)) {
		struct lws *wsi = lws_container_of(p, struct lws,
						   tls.dll_pending_tls);

		if (wsi->position_in_fds_table >= 0) {

			pt->fds[wsi->position_in_fds_table].revents |=
				pt->fds[wsi->position_in_fds_table].events &
								LWS_POLLIN;
			if (pt->fds[wsi->position_in_fds_table].revents &
								LWS_POLLIN)
				/*
				 * We're not going to remove the wsi from the
				 * pending tls list.  The processing will have
				 * to do it if he exhausts the pending tls.
				 */
				forced = 1;
		}

	} lws_end_foreach_dll_safe(p, p1);
#endif

	lws_pt_unlock(pt);

	return forced;
}

int
lws_service_fd_tsi(struct lws_context *context, struct lws_pollfd *pollfd,
		   int tsi)
{
	struct lws_context_per_thread *pt;
	struct lws *wsi;

	if (!context || context->being_destroyed1)
		return -1;

	pt = &context->pt[tsi];

	if (!pollfd) {
		/*
		 * calling with NULL pollfd for periodic background processing
		 * is no longer needed and is now illegal.
		 */
		assert(pollfd);
		return -1;
	}
	assert(lws_socket_is_valid(pollfd->fd));

	/* no, here to service a socket descriptor */
	wsi = wsi_from_fd(context, pollfd->fd);
	if (!wsi)
		/* not lws connection ... leave revents alone and return */
		return 0;

#if LWS_MAX_SMP > 1
	if (wsi->undergoing_init_from_other_pt)
		/*
		 * Temporary situation that other service thread is initializing
		 * this wsi right now for use on our service thread.
		 */
		return 0;
#endif

	/*
	 * so that caller can tell we handled, past here we need to
	 * zero down pollfd->revents after handling
	 */

	/* handle session socket closed */

	if ((!(pollfd->revents & pollfd->events & LWS_POLLIN)) &&
	    (pollfd->revents & LWS_POLLHUP)) {
		wsi->socket_is_permanently_unusable = 1;
		lwsl_debug("Session Socket %p (fd=%d) dead\n",
			   (void *)wsi, pollfd->fd);

		goto close_and_handled;
	}

#ifdef _WIN32
	if (pollfd->revents & LWS_POLLOUT)
		wsi->sock_send_blocking = FALSE;
#endif

	if ((!(pollfd->revents & pollfd->events & LWS_POLLIN)) &&
	    (pollfd->revents & LWS_POLLHUP)) {
		lwsl_debug("pollhup\n");
		wsi->socket_is_permanently_unusable = 1;
		goto close_and_handled;
	}

#if defined(LWS_WITH_TLS)
	if (lwsi_state(wsi) == LRS_SHUTDOWN &&
	    lws_is_ssl(wsi) && wsi->tls.ssl) {
		switch (__lws_tls_shutdown(wsi)) {
		case LWS_SSL_CAPABLE_DONE:
		case LWS_SSL_CAPABLE_ERROR:
			goto close_and_handled;

		case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
		case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			goto handled;
		}
	}
#endif
	wsi->could_have_pending = 0; /* clear back-to-back write detection */
	pt->inside_lws_service = 1;

	/* okay, what we came here to do... */

	/* if we got here, we should have wire protocol ops set on the wsi */
	assert(wsi->role_ops);

	// lwsl_notice("%s: %s: wsistate 0x%x\n", __func__, wsi->role_ops->name,
	//	    wsi->wsistate);

	switch (lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_handle_POLLIN).
					       handle_POLLIN(pt, wsi, pollfd)) {
	case LWS_HPI_RET_WSI_ALREADY_DIED:
		pt->inside_lws_service = 0;
		return 1;
	case LWS_HPI_RET_HANDLED:
		break;
	case LWS_HPI_RET_PLEASE_CLOSE_ME:
		//lwsl_notice("%s: %s pollin says please close me\n", __func__,
		//		wsi->role_ops->name);
close_and_handled:
		lwsl_debug("%p: Close and handled\n", wsi);
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "close_and_handled");
#if defined(_DEBUG) && defined(LWS_WITH_LIBUV)
		/*
		 * confirm close has no problem being called again while
		 * it waits for libuv service to complete the first async
		 * close
		 */
		if (!strcmp(context->event_loop_ops->name, "libuv"))
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "close_and_handled uv repeat test");
#endif
		/*
		 * pollfd may point to something else after the close
		 * due to pollfd swapping scheme on delete on some platforms
		 * we can't clear revents now because it'd be the wrong guy's
		 * revents
		 */
		pt->inside_lws_service = 0;
		return 1;
	default:
		assert(0);
	}
#if defined(LWS_WITH_TLS)
handled:
#endif
	pollfd->revents = 0;
	pt->inside_lws_service = 0;

	return 0;
}

int
lws_service_fd(struct lws_context *context, struct lws_pollfd *pollfd)
{
	return lws_service_fd_tsi(context, pollfd, 0);
}

int
lws_service(struct lws_context *context, int timeout_ms)
{
	struct lws_context_per_thread *pt;
	int n;

	if (!context)
		return 1;

	pt = &context->pt[0];
	pt->inside_service = 1;

	if (context->event_loop_ops->run_pt) {
		/* we are configured for an event loop */
		context->event_loop_ops->run_pt(context, 0);

		pt->inside_service = 0;

		return 1;
	}
	n = lws_plat_service(context, timeout_ms);

	pt->inside_service = 0;

	return n;
}

int
lws_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt;
	int n;

	if (!context)
		return 1;

	pt = &context->pt[tsi];
	pt->inside_service = 1;
#if LWS_MAX_SMP > 1
	pt->self = pthread_self();
#endif

	if (context->event_loop_ops->run_pt) {
		/* we are configured for an event loop */
		context->event_loop_ops->run_pt(context, tsi);

		pt->inside_service = 0;

		return 1;
	}

	n = _lws_plat_service_tsi(context, timeout_ms, tsi);

	pt->inside_service = 0;

	return n;
}
