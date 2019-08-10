/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#include "core/private.h"

int
lws_callback_as_writeable(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
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

	n = wsi->role_ops->writeable_cb[lwsi_role_server(wsi)];

	m = user_callback_handle_rxflow(wsi->protocol->callback,
					wsi, (enum lws_callback_reasons) n,
					wsi->user_space, NULL, 0);

	return m;
}

LWS_VISIBLE int
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

		if (wsi->role_ops->write_role_protocol(wsi, NULL, 0, &wp) < 0) {
			lwsl_info("%s signalling to close\n", __func__);
			goto bail_die;
		}
		lws_callback_on_writable(wsi);

		goto bail_ok;
	}
#endif

#ifdef LWS_WITH_CGI
	/*
	 * A cgi master's wire protocol remains h1 or h2.  He is just getting
	 * his data from his child cgis.
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

	if (!wsi->role_ops->handle_POLLOUT)
		goto bail_ok;

	switch ((wsi->role_ops->handle_POLLOUT)(wsi)) {
	case LWS_HP_RET_BAIL_OK:
		goto bail_ok;
	case LWS_HP_RET_BAIL_DIE:
		goto bail_die;
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


#ifdef LWS_WITH_CGI
user_service_go_again:
#endif

	if (wsi->role_ops->perform_user_POLLOUT) {
		if (wsi->role_ops->perform_user_POLLOUT(wsi) == -1)
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
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
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

	m = lws_buflist_append_segment(&wsi->buflist, buf + n, len - n);

	if (m < 0)
		return LWSRXFC_ERROR;
	if (m) {
		lwsl_debug("%s: added %p to rxflow list\n", __func__, wsi);
		lws_dll2_add_head(&wsi->dll_buflist, &pt->dll_buflist_owner);
	}

	return ret;
}

/* this is used by the platform service code to stop us waiting for network
 * activity in poll() when we have something that already needs service
 */

LWS_VISIBLE LWS_EXTERN int
lws_service_adjust_timeout(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];

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
		       struct lws_tokens *ebuf)
{
	int n, prior = (int)lws_buflist_next_segment_len(&wsi->buflist, NULL);

	ebuf->token = pt->serv_buf;
	ebuf->len = lws_ssl_capable_read(wsi, pt->serv_buf,
					 wsi->context->pt_serv_buf_size);

	if (ebuf->len == LWS_SSL_CAPABLE_MORE_SERVICE && prior)
		goto get_from_buflist;

	if (ebuf->len <= 0)
		return 0;

	/* nothing in buflist already?  Then just use what we read */

	if (!prior)
		return 0;

	/* stash what we read */

	n = lws_buflist_append_segment(&wsi->buflist, ebuf->token,
				       ebuf->len);
	if (n < 0)
		return -1;
	if (n) {
		lwsl_debug("%s: added %p to rxflow list\n", __func__, wsi);
		lws_dll2_add_head(&wsi->dll_buflist, &pt->dll_buflist_owner);
	}

	/* get the first buflist guy in line */

get_from_buflist:

	ebuf->len = (int)lws_buflist_next_segment_len(&wsi->buflist,
						      &ebuf->token);

	return 1; /* came from buflist */
}

int
lws_buflist_aware_consume(struct lws *wsi, struct lws_tokens *ebuf, int used,
			  int buffered)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int m;

	/* it's in the buflist; we didn't use any */

	if (!used && buffered)
		return 0;

	if (used && buffered) {
		m = lws_buflist_use_segment(&wsi->buflist, used);
		lwsl_info("%s: draining rxflow: used %d, next %d\n",
			    __func__, used, m);
		if (m)
			return 0;

		lwsl_info("%s: removed %p from dll_buflist\n", __func__, wsi);
		lws_dll2_remove(&wsi->dll_buflist);

		return 0;
	}

	/* any remainder goes on the buflist */

	if (used != ebuf->len) {
		m = lws_buflist_append_segment(&wsi->buflist,
					       ebuf->token + used,
					       ebuf->len - used);
		if (m < 0)
			return 1; /* OOM */
		if (m) {
			lwsl_debug("%s: added %p to rxflow list\n",
				   __func__, wsi);
			lws_dll2_add_head(&wsi->dll_buflist,
					 &pt->dll_buflist_owner);
		}
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
		    lwsi_state(wsi) != LRS_DEFERRING_ACTION &&
		    (wsi->role_ops->handle_POLLIN)(pt, wsi, &pfd) ==
						   LWS_HPI_RET_PLEASE_CLOSE_ME)
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "close_and_handled");

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
	struct lws_context_per_thread *pt = &context->pt[tsi];
	int forced = 0;

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
	forced |= role_ops_ws.service_flag_pending(context, tsi);
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

		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & LWS_POLLIN;
		if (pt->fds[wsi->position_in_fds_table].revents & LWS_POLLIN) {
			forced = 1;
			/*
			 * he's going to get serviced now, take him off the
			 * list of guys with buffered SSL.  If he still has some
			 * at the end of the service, he'll get put back on the
			 * list then.
			 */
			__lws_ssl_remove_wsi_from_buffered_list(wsi);
		}

	} lws_end_foreach_dll_safe(p, p1);
#endif

	lws_pt_unlock(pt);

	return forced;
}

LWS_VISIBLE int
lws_service_fd_tsi(struct lws_context *context, struct lws_pollfd *pollfd,
		   int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws *wsi;

	if (!context || context->being_destroyed1 )
		return -1;

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

	/* okay, what we came here to do... */

	/* if we got here, we should have wire protocol ops set on the wsi */
	assert(wsi->role_ops);

	// lwsl_notice("%s: %s: wsistate 0x%x\n", __func__, wsi->role_ops->name,
	//	    wsi->wsistate);

	switch ((wsi->role_ops->handle_POLLIN)(pt, wsi, pollfd)) {
	case LWS_HPI_RET_WSI_ALREADY_DIED:
		return 1;
	case LWS_HPI_RET_HANDLED:
		break;
	case LWS_HPI_RET_PLEASE_CLOSE_ME:
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
		if (context->event_loop_ops == &event_loop_ops_uv)
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "close_and_handled uv repeat test");
#endif
		/*
		 * pollfd may point to something else after the close
		 * due to pollfd swapping scheme on delete on some platforms
		 * we can't clear revents now because it'd be the wrong guy's
		 * revents
		 */
		return 1;
	default:
		assert(0);
	}
#if defined(LWS_WITH_TLS)
handled:
#endif
	pollfd->revents = 0;

	if (!context->protocol_init_done)
		if (lws_protocol_init(context)) {
			lwsl_err("%s: lws_protocol_init failed\n", __func__);
			return -1;
		}

	return 0;
}

LWS_VISIBLE int
lws_service_fd(struct lws_context *context, struct lws_pollfd *pollfd)
{
	return lws_service_fd_tsi(context, pollfd, 0);
}

LWS_VISIBLE int
lws_service(struct lws_context *context, int timeout_ms)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	int n;

	if (!context)
		return 1;

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

LWS_VISIBLE int
lws_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	int n;

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
