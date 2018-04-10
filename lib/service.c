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

#include "private-libwebsockets.h"

int
lws_callback_as_writeable(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int n, m;

	lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_WRITEABLE_CB, 1);
#if defined(LWS_WITH_STATS)
	if (wsi->active_writable_req_us) {
		uint64_t ul = time_in_microseconds() -
			      wsi->active_writable_req_us;

		lws_stats_atomic_bump(wsi->context, pt,
				      LWSSTATS_MS_WRITABLE_DELAY, ul);
		lws_stats_atomic_max(wsi->context, pt,
				     LWSSTATS_MS_WORST_WRITABLE_DELAY, ul);
		wsi->active_writable_req_us = 0;
	}
#endif

	switch (lwsi_role(wsi)) {
	case LWSI_ROLE_RAW_SOCKET:
		n = LWS_CALLBACK_RAW_WRITEABLE;
		break;
	case LWSI_ROLE_RAW_FILE:
		n = LWS_CALLBACK_RAW_WRITEABLE_FILE;
		break;
	case LWSI_ROLE_WS1_CLIENT:
	case LWSI_ROLE_WS2_CLIENT:
		n = LWS_CALLBACK_CLIENT_WRITEABLE;
		break;
	case LWSI_ROLE_H1_CLIENT:
	case LWSI_ROLE_H2_CLIENT:
		n = LWS_CALLBACK_CLIENT_HTTP_WRITEABLE;
		break;
	case LWSI_ROLE_WS1_SERVER:
	case LWSI_ROLE_WS2_SERVER:
		n = LWS_CALLBACK_SERVER_WRITEABLE;
		break;
	default:
		n = LWS_CALLBACK_HTTP_WRITEABLE;
		break;
	}

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

	lwsl_info("%s: %p\n", __func__, wsi);

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
	 */

	if (wsi->trunc_len) {
		//lwsl_notice("%s: completing partial\n", __func__);
		if (lws_issue_raw(wsi, wsi->trunc_alloc + wsi->trunc_offset,
				  wsi->trunc_len) < 0) {
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

#ifdef LWS_WITH_CGI
	/*
	 * A cgi master's wire protocol remains h1 or h2.  He is just getting
	 * his data from his child cgis.
	 */
	if (wsi->cgi) {
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
	assert(wsi->pops);

	switch ((wsi->pops->handle_POLLOUT)(wsi)) {
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

	if (wsi->parent_carries_io) {
		vwsi->handling_pollout = 0;
		vwsi->leave_pollout_active = 0;

		return lws_callback_as_writeable(wsi);
	}

	if (pollfd) {
		int eff = vwsi->leave_pollout_active;

		if (!eff)
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
				lwsl_info("failed at set pollfd\n");
				goto bail_die;
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

	if (lwsi_role_client(wsi) &&
	    !wsi->hdr_parsing_completed &&
	     lwsi_state(wsi) != LRS_H2_WAITING_TO_SEND_HEADERS)
		goto bail_ok;


#ifdef LWS_WITH_CGI
user_service_go_again:
#endif

#if defined(LWS_WITH_HTTP2)
	/* this is the network wsi */
	if (lwsi_role_h2(wsi)) {
		/* distribute his writeability amongst his children */
		if (lws_handle_POLLOUT_event_h2(wsi) == -1)
			goto bail_die;

		goto bail_ok;
	}
#endif
	
	lwsl_debug("%s: %p: non http2: wsistate 0x%x, ops %s\n", __func__, wsi,
		   wsi->wsistate, wsi->pops->name);

	vwsi = (volatile struct lws *)wsi;
	vwsi->leave_pollout_active = 0;

	n = lws_callback_as_writeable(wsi);
	vwsi->handling_pollout = 0;

	if (vwsi->leave_pollout_active)
		lws_change_pollfd(wsi, 0, LWS_POLLOUT);

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

static int
__lws_service_timeout_check(struct lws *wsi, time_t sec)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int n = 0;

	(void)n;

	/*
	 * if extensions want in on it (eg, we are a mux parent)
	 * give them a chance to service child timeouts
	 */
	if (lws_ext_cb_active(wsi, LWS_EXT_CB_1HZ, NULL, sec) < 0)
		return 0;

	/*
	 * if we went beyond the allowed time, kill the
	 * connection
	 */
	if (wsi->dll_timeout.prev &&
	    lws_compare_time_t(wsi->context, sec, wsi->pending_timeout_set) >
			       wsi->pending_timeout_limit) {

		if (wsi->desc.sockfd != LWS_SOCK_INVALID &&
		    wsi->position_in_fds_table >= 0)
			n = pt->fds[wsi->position_in_fds_table].events;

		lws_stats_atomic_bump(wsi->context, pt, LWSSTATS_C_TIMEOUTS, 1);

		/* no need to log normal idle keepalive timeout */
		if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
			lwsl_info("wsi %p: TIMEDOUT WAITING on %d "
				  "(did hdr %d, ah %p, wl %d, pfd "
				  "events %d) %llu vs %llu\n",
				  (void *)wsi, wsi->pending_timeout,
				  wsi->hdr_parsing_completed, wsi->ah,
				  pt->ah_wait_list_length, n,
				  (unsigned long long)sec,
				  (unsigned long long)wsi->pending_timeout_limit);
#if defined(LWS_WITH_CGI)
		if (wsi->cgi)
			lwsl_notice("CGI timeout: %s\n", wsi->cgi->summary);
#endif

		/*
		 * Since he failed a timeout, he already had a chance to do
		 * something and was unable to... that includes situations like
		 * half closed connections.  So process this "failed timeout"
		 * close as a violent death and don't try to do protocol
		 * cleanup like flush partials.
		 */
		wsi->socket_is_permanently_unusable = 1;
		if (lwsi_state(wsi) == LRS_WAITING_SSL && wsi->protocol)
			wsi->protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
				wsi->user_space,
				(void *)"Timed out waiting SSL", 21);

		__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "timeout");

		return 1;
	}

	return 0;
}

int lws_rxflow_cache(struct lws *wsi, unsigned char *buf, int n, int len)
{
#if defined(LWS_WITH_HTTP2)
	if (wsi->upgraded_to_http2) {
		struct lws_h2_netconn *h2n = wsi->h2.h2n;

		assert(h2n->rx_scratch);
		buf += n;
		len -= n;
		assert ((char *)buf >= (char *)h2n->rx_scratch &&
			(char *)&buf[len] <=
			    (char *)&h2n->rx_scratch[wsi->vhost->h2_rx_scratch_size]);

		h2n->rx_scratch_pos = lws_ptr_diff(buf, h2n->rx_scratch);
		h2n->rx_scratch_len = len;

		lwsl_info("%s: %p: pausing h2 rx_scratch\n", __func__, wsi);

		return 0;
	}
#endif
	/* his RX is flowcontrolled, don't send remaining now */
	if (wsi->rxflow_buffer) {
		if (buf >= wsi->rxflow_buffer &&
		    &buf[len - 1] < &wsi->rxflow_buffer[wsi->rxflow_len]) {
			/* rxflow while we were spilling prev rxflow */
			lwsl_info("%s: staying in rxflow buf\n", __func__);
			return 1;
		} else {
			lwsl_err("%s: conflicting rxflow buf, "
				 "current %p len %d, new %p len %d\n", __func__,
				 wsi->rxflow_buffer, wsi->rxflow_len, buf, len);
			assert(0);
			return 1;
		}
	}

	/* a new rxflow, buffer it and warn caller */
	lwsl_info("%s: new rxflow input buffer len %d\n", __func__, len - n);
	wsi->rxflow_buffer = lws_malloc(len - n, "rxflow buf");
	if (!wsi->rxflow_buffer)
		return -1;

	wsi->rxflow_len = len - n;
	wsi->rxflow_pos = 0;
	memcpy(wsi->rxflow_buffer, buf + n, len - n);

	return 0;
}

/* this is used by the platform service code to stop us waiting for network
 * activity in poll() when we have something that already needs service
 */

LWS_VISIBLE LWS_EXTERN int
lws_service_adjust_timeout(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct allocated_headers *ah;

	/* Figure out if we really want to wait in poll()
	 * We only need to wait if really nothing already to do and we have
	 * to wait for something from network
	 */

	/* 1) if we know we are draining rx ext, do not wait in poll */
	if (pt->rx_draining_ext_list)
		return 0;

#if defined(LWS_WITH_TLS)
	/* 2) if we know we have non-network pending data, do not wait in poll */
	if (lws_ssl_anybody_has_buffered_read_tsi(context, tsi)) {
		lwsl_info("ssl buffered read\n");
		return 0;
	}
#endif

	/* 3) if any ah has pending rx, do not wait in poll */
	ah = pt->ah_list;
	while (ah) {
		if (ah->rxpos != ah->rxlen || (ah->wsi && ah->wsi->preamble_rx)) {
			if (!ah->wsi) {
				assert(0);
			}
			// lwsl_debug("ah pending force\n");
			return 0;
		}
		ah = ah->next;
	}

	return timeout_ms;
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
	struct allocated_headers *ah;
#if defined(LWS_WITH_TLS)
	struct lws *wsi_next;
#endif
	struct lws *wsi;
	int forced = 0;

	lws_pt_lock(pt, __func__);

	/* POLLIN faking */

	/*
	 * 1) For all guys with already-available ext data to drain, if they are
	 * not flowcontrolled, fake their POLLIN status
	 */
	wsi = pt->rx_draining_ext_list;
	while (wsi) {
		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & LWS_POLLIN;
		if (pt->fds[wsi->position_in_fds_table].revents & LWS_POLLIN) {
			forced = 1;
			break;
		}
		wsi = wsi->ws->rx_draining_ext_list;
	}

#if defined(LWS_WITH_TLS)
	/*
	 * 2) For all guys with buffered SSL read data already saved up, if they
	 * are not flowcontrolled, fake their POLLIN status so they'll get
	 * service to use up the buffered incoming data, even though their
	 * network socket may have nothing
	 */
	wsi = pt->pending_read_list;
	while (wsi) {
		wsi_next = wsi->pending_read_list_next;
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

		wsi = wsi_next;
	}
#endif
	/*
	 * 3) For any wsi who have an ah with pending RX who did not
	 * complete their current headers, and are not flowcontrolled,
	 * fake their POLLIN status so they will be able to drain the
	 * rx buffered in the ah
	 */
	ah = pt->ah_list;
	while (ah) {
		if ((ah->rxpos != ah->rxlen &&
		    !ah->wsi->hdr_parsing_completed) || ah->wsi->preamble_rx) {
			pt->fds[ah->wsi->position_in_fds_table].revents |=
				pt->fds[ah->wsi->position_in_fds_table].events &
					LWS_POLLIN;
			if (pt->fds[ah->wsi->position_in_fds_table].revents &
			    LWS_POLLIN) {
				forced = 1;
				break;
			}
		}
		ah = ah->next;
	}

	lws_pt_unlock(pt);

	return forced;
}

static int
lws_service_periodic_checks(struct lws_context *context,
			    struct lws_pollfd *pollfd, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	lws_sockfd_type our_fd = 0, tmp_fd;
	struct allocated_headers *ah;
	struct lws *wsi;
	int timed_out = 0;
	time_t now;
	int n = 0, m;

	if (!context->protocol_init_done)
		if (lws_protocol_init(context))
			return -1;

	time(&now);

	/*
	 * handle case that system time was uninitialized when lws started
	 * at boot, and got initialized a little later
	 */
	if (context->time_up < 1464083026 && now > 1464083026)
		context->time_up = now;

	if (context->last_timeout_check_s &&
	    now - context->last_timeout_check_s > 100) {
		/*
		 * There has been a discontiguity.  Any stored time that is
		 * less than context->time_discontiguity should have context->
		 * time_fixup added to it.
		 *
		 * Some platforms with no RTC will experience this as a normal
		 * event when ntp sets their clock, but we can have started
		 * long before that with a 0-based unix time.
		 */

		context->time_discontiguity = now;
		context->time_fixup = now - context->last_timeout_check_s;

		lwsl_notice("time discontiguity: at old time %llus, "
			    "new time %llus: +%llus\n",
			    (unsigned long long)context->last_timeout_check_s,
			    (unsigned long long)context->time_discontiguity,
			    (unsigned long long)context->time_fixup);

		context->last_timeout_check_s = now - 1;
	}

	if (!lws_compare_time_t(context, context->last_timeout_check_s, now))
		return 0;

	context->last_timeout_check_s = now;

#if defined(LWS_WITH_STATS)
	if (!tsi && now - context->last_dump > 10) {
		lws_stats_log_dump(context);
		context->last_dump = now;
	}
#endif

	lws_plat_service_periodic(context);
	lws_check_deferred_free(context, 0);

#if defined(LWS_WITH_PEER_LIMITS)
	lws_peer_cull_peer_wait_list(context);
#endif

	/* retire unused deprecated context */
#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_WITH_ESP32)
#if LWS_POSIX && !defined(_WIN32)
	if (context->deprecated && !context->count_wsi_allocated) {
		lwsl_notice("%s: ending deprecated context\n", __func__);
		kill(getpid(), SIGINT);
		return 0;
	}
#endif
#endif
	/* global timeout check once per second */

	if (pollfd)
		our_fd = pollfd->fd;

	/*
	 * Phase 1: check every wsi on the timeout check list
	 */

	lws_pt_lock(pt, __func__);

	lws_start_foreach_dll_safe(struct lws_dll_lws *, d, d1,
				   context->pt[tsi].dll_head_timeout.next) {
		wsi = lws_container_of(d, struct lws, dll_timeout);
		tmp_fd = wsi->desc.sockfd;
		if (__lws_service_timeout_check(wsi, now)) {
			/* he did time out... */
			if (tmp_fd == our_fd)
				/* it was the guy we came to service! */
				timed_out = 1;
			/* he's gone, no need to mark as handled */
		}
	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * Phase 2: double-check active ah timeouts independent of wsi
	 *	    timeout status
	 */

	ah = pt->ah_list;
	while (ah) {
		int len;
		char buf[256];
		const unsigned char *c;

		if (!ah->in_use || !ah->wsi || !ah->assigned ||
		    (ah->wsi->vhost &&
		     lws_compare_time_t(context, now, ah->assigned) <
		     ah->wsi->vhost->timeout_secs_ah_idle + 360)) {
			ah = ah->next;
			continue;
		}

		/*
		 * a single ah session somehow got held for
		 * an unreasonable amount of time.
		 *
		 * Dump info on the connection...
		 */
		wsi = ah->wsi;
		buf[0] = '\0';
#if !defined(LWS_PLAT_OPTEE)
		lws_get_peer_simple(wsi, buf, sizeof(buf));
#else
		buf[0] = '\0';
#endif
		lwsl_notice("ah excessive hold: wsi %p\n"
			    "  peer address: %s\n"
			    "  ah rxpos %u, rxlen %u, pos %u\n",
			    wsi, buf, ah->rxpos, ah->rxlen,
			    ah->pos);
		buf[0] = '\0';
		m = 0;
		do {
			c = lws_token_to_string(m);
			if (!c)
				break;
			if (!(*c))
				break;

			len = lws_hdr_total_length(wsi, m);
			if (!len || len > (int)sizeof(buf) - 1) {
				m++;
				continue;
			}

			if (lws_hdr_copy(wsi, buf,
					 sizeof buf, m) > 0) {
				buf[sizeof(buf) - 1] = '\0';

				lwsl_notice("   %s = %s\n",
					    (const char *)c, buf);
			}
			m++;
		} while (1);

		/* explicitly detach the ah */

		lws_header_table_force_to_detachable_state(wsi);
		lws_header_table_detach(wsi, 0);

		/* ... and then drop the connection */

		m = 0;
		if (wsi->desc.sockfd == our_fd) {
			m = timed_out;

			/* it was the guy we came to service! */
			timed_out = 1;
		}

		if (!m) /* if he didn't already timeout */
			__lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					     "excessive ah");

		ah = pt->ah_list;
	}

	lws_pt_unlock(pt);

#if 0
	{
		char s[300], *p = s;

		for (n = 0; n < context->count_threads; n++)
			p += sprintf(p, " %7lu (%5d), ",
				     context->pt[n].count_conns,
				     context->pt[n].fds_count);

		lwsl_notice("load: %s\n", s);
	}
#endif
	/*
	 * Phase 3: vhost / protocol timer callbacks
	 */

	wsi = NULL;
	lws_start_foreach_ll(struct lws_vhost *, v, context->vhost_list) {
		struct lws_timed_vh_protocol *nx;
		if (v->timed_vh_protocol_list) {
			lws_start_foreach_ll(struct lws_timed_vh_protocol *,
					q, v->timed_vh_protocol_list) {
				if (now >= q->time) {
					if (!wsi)
						wsi = lws_zalloc(sizeof(*wsi), "cbwsi");
					wsi->context = context;
					wsi->vhost = v;
					wsi->protocol = q->protocol;
					lwsl_debug("timed cb: vh %s, protocol %s, reason %d\n", v->name, q->protocol->name, q->reason);
					q->protocol->callback(wsi, q->reason, NULL, NULL, 0);
					nx = q->next;
					lws_timed_callback_remove(v, q);
					q = nx;
					continue; /* we pointed ourselves to the next from the now-deleted guy */
				}
			} lws_end_foreach_ll(q, next);
		}
	} lws_end_foreach_ll(v, vhost_next);
	if (wsi)
		lws_free(wsi);

	/*
	 * Phase 4: check for unconfigured vhosts due to required
	 *	    interface missing before
	 */

	lws_context_lock(context);
	lws_start_foreach_llp(struct lws_vhost **, pv,
			      context->no_listener_vhost_list) {
		struct lws_vhost *v = *pv;
		lwsl_debug("deferred iface: checking if on vh %s\n", (*pv)->name);
		if (lws_context_init_server(NULL, *pv) == 0) {
			/* became happy */
			lwsl_notice("vh %s: became connected\n", v->name);
			*pv = v->no_listener_vhost_list;
			v->no_listener_vhost_list = NULL;
			break;
		}
	} lws_end_foreach_llp(pv, no_listener_vhost_list);
	lws_context_unlock(context);

	/*
	 * Phase 5: role periodic checks
	 */
#if defined(LWS_ROLE_WS)
	wire_ops_ws.periodic_checks(context, tsi, now);
#endif
#if defined(LWS_ROLE_CGI)
	wire_ops_cgi.periodic_checks(context, tsi, now);
#endif

	/*
	 * Phase 6: check the remaining cert lifetime daily
	 */
#if defined(LWS_WITH_TLS)
	n = lws_compare_time_t(context, now, context->last_cert_check_s);
	if ((!context->last_cert_check_s || n > (24 * 60 * 60)) &&
	    !lws_tls_check_all_cert_lifetimes(context))
		context->last_cert_check_s = now;
#endif

	return timed_out;
}

LWS_VISIBLE int
lws_service_fd_tsi(struct lws_context *context, struct lws_pollfd *pollfd,
		   int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws *wsi;

	/* the socket we came to service timed out, nothing to do */
	if (lws_service_periodic_checks(context, pollfd, tsi) || !pollfd)
		return 0;

	/* no, here to service a socket descriptor */
	wsi = wsi_from_fd(context, pollfd->fd);
	if (!wsi)
		/* not lws connection ... leave revents alone and return */
		return 0;

	/*
	 * so that caller can tell we handled, past here we need to
	 * zero down pollfd->revents after handling
	 */

#if LWS_POSIX
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

#endif

	if ((!(pollfd->revents & pollfd->events & LWS_POLLIN)) &&
	    (pollfd->revents & LWS_POLLHUP)) {
		lwsl_debug("pollhup\n");
		wsi->socket_is_permanently_unusable = 1;
		goto close_and_handled;
	}

#if defined(LWS_WITH_TLS)
	if (lwsi_state(wsi) == LRS_SHUTDOWN && lws_is_ssl(wsi) && wsi->ssl) {
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
	assert(wsi->pops);

	// lwsl_notice("%s: %s: wsistate 0x%x\n", __func__, wsi->pops->name,
	//	    wsi->wsistate);

	switch ((wsi->pops->handle_POLLIN)(pt, wsi, pollfd)) {
	case LWS_HPI_RET_DIE:
		return 1;
	case LWS_HPI_RET_HANDLED:
		break;
	case LWS_HPI_RET_CLOSE_HANDLED:
close_and_handled:
		lwsl_debug("%p: Close and handled\n", wsi);
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "close_and_handled");
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

handled:
	pollfd->revents = 0;

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
	return lws_plat_service(context, timeout_ms);
}

LWS_VISIBLE int
lws_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	return _lws_plat_service_tsi(context, timeout_ms, tsi);
}

