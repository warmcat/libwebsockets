/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

#if defined(WIN32)

/*
 * Windows doesn't offer a Posix connect() event... we use a sul
 * to check the connection status periodically while a connection
 * is ongoing.
 *
 * Leaving this to POLLOUT to retry which is the way for Posix
 * platforms instead on win32 causes event-loop busywaiting
 * so for win32 we manage the retry interval directly with the sul.
 */

void
lws_client_win32_conn_async_check(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws,
					   win32_sul_connect_async_check);

	lwsl_wsi_debug(wsi, "checking ongoing connection attempt");
	lws_client_connect_3_connect(wsi, NULL, NULL, 0, NULL);
}

#endif

void
lws_client_conn_wait_timeout(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws,
					   sul_connect_timeout);

	/*
	 * This is used to constrain the time we're willing to wait for a
	 * connection before giving up on it and retrying.
	 */

	lwsl_wsi_info(wsi, "connect wait timeout has fired");
	lws_client_connect_3_connect(wsi, NULL, NULL, 0, NULL);
}

void
lws_client_happy_eyeballs_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws,
					   sul_happy_eyeballs);

	lwsl_wsi_info(wsi, "happy eyeballs timer fired, initiating parallel connect");
	lws_client_connect_3_connect(wsi, NULL, NULL, 0, NULL);
}

void
lws_client_h3_grace_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_h3_grace);

	lwsl_wsi_notice(wsi, "H3 grace timer expired, abandoning QUIC race");

	/* Mark H3 as FAILED in cache with 5s TTL */
	if (wsi->a.context->h3_cap_cache && wsi->stash && wsi->stash->cis[CIS_HOST]) {
		lws_h3_cap_info_t cap;
		memset(&cap, 0, sizeof(cap));
		cap.state = LWS_H3_STATE_FAILED_IGNORE;
		lws_cache_write_through(wsi->a.context->h3_cap_cache, wsi->stash->cis[CIS_HOST], 
					(const uint8_t *)&cap, sizeof(cap), 
					lws_now_usecs() + (5000000ll), NULL);
	}

	/* Abort QUIC and revert to TCP */
	if (wsi->role_ops && strcmp(wsi->role_ops->name, "quic") == 0) {
		if (lws_socket_is_valid(wsi->desc.sockfd)) {
			struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
			lws_pt_lock(pt, __func__);
			__remove_wsi_socket_from_fds(wsi);
			lws_pt_unlock(pt);
			compatible_close(wsi->desc.sockfd);
			wsi->desc.sockfd = LWS_SOCK_INVALID;
		}

		if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_close_kill_connection))
			lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_close_kill_connection).close_kill_connection(wsi, LWS_CLOSE_STATUS_NOSTATUS);

		/* Promote the first parallel TCP connection */
		int first_valid = -1;
		for (int i = 0; i < wsi->parallel_count; i++) {
			if (wsi->parallel_conns[i].is_valid) {
				first_valid = i;
				break;
			}
		}
		if (first_valid != -1) {
			const struct lws_role_ops *r = lws_role_by_name("h2");
			if (!r) r = lws_role_by_name("h1");
			if (r) {
				lws_role_transition(wsi, LWSIFR_CLIENT, LRS_WAITING_CONNECT, r);
			}
			wsi->desc.sockfd = wsi->parallel_conns[first_valid].desc.sockfd;
			wsi->position_in_fds_table = wsi->parallel_conns[first_valid].position_in_fds_table;
			wsi->parallel_conns[first_valid].is_valid = 0;
			/* We changed the primary fd, the event loop will trigger POLLOUT if it's connected */
		} else {
			/* No TCP sockets survived? Fail connection. */
			lws_client_connect_3_connect(wsi, NULL, NULL, 0, NULL);
		}
	}
}

void
lws_client_dns_retry_timeout(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws,
					   sul_connect_timeout);

	/*
	 * This limits the amount of dns lookups we will try before
	 * giving up and failing... it reuses sul_connect_timeout, which
	 * isn't officially used until we connected somewhere.
	 */

	lwsl_wsi_info(wsi, "dns retry");
	if (!lws_client_connect_2_dnsreq_MAY_CLOSE_WSI(wsi))
		lwsl_notice("DNS lookup failed");
}

/*
 * Figure out if an ongoing connect() has arrived at a final disposition or not
 *
 * We can check using getsockopt if our connect actually completed.
 * Posix connect() allows nonblocking to redo the connect to
 * find out if it succeeded.
 */

typedef enum {
	LCCCR_CONNECTED			= 1,
	LCCCR_CONTINUE			= 0,
	LCCCR_FAILED			= -1,
} lcccr_t;

static lcccr_t
lws_client_connect_check(struct lws *wsi, lws_sockfd_type fd, int *real_errno)
{
#if !defined(LWS_WITH_NO_LOGS)
	char t16[16];
#endif
	int en = 0;
#if !defined(WIN32)
	int e;
	socklen_t sl = sizeof(e);
#endif

	(void)en;

	/*
	 * This resets SO_ERROR after reading it.  If there's an error
	 * condition, the connect definitively failed.
	 */

#if !defined(WIN32)
	if (!getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &sl)) {

		en = LWS_ERRNO;
		if (!e) {
			lwsl_wsi_debug(wsi, "getsockopt: conn OK errno %s",
					lws_errno_describe(en, t16, sizeof(t16)));

			return LCCCR_CONNECTED;
		}

		lwsl_wsi_notice(wsi, "getsockopt fd %d says %s", fd,
				lws_errno_describe(e, t16, sizeof(t16)));

		*real_errno = e;

		return LCCCR_FAILED;
	}
#else
	fd_set write_set, except_set;
	struct timeval tv;
	int ret;

#if defined(LWS_WITH_UNIX_SOCK)
	if (wsi->unix_skt) {
		char buf;
		int n = recv((int)fd, &buf, 1, MSG_PEEK);
		if (n >= 0 || LWS_ERRNO == WSAEWOULDBLOCK) {
			lwsl_wsi_debug(wsi, "AF_UNIX recv MSG_PEEK ok, conn OK");
			return LCCCR_CONNECTED;
		}
		en = LWS_ERRNO;
		if (en == WSAENOTCONN)
			return LCCCR_CONTINUE;
		*real_errno = en;
		return LCCCR_FAILED;
	}
#endif

	FD_ZERO(&write_set);
	FD_ZERO(&except_set);
	FD_SET(fd, &write_set);
	FD_SET(fd, &except_set);

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	ret = select((int)fd + 1, NULL, &write_set, &except_set, &tv);
	if (FD_ISSET(fd, &write_set)) {
		/* actually connected */
		lwsl_wsi_debug(wsi, "select write fd set, conn OK");
		return LCCCR_CONNECTED;
	}

	if (FD_ISSET(fd, &except_set)) {
		/* Failed to connect */
		lwsl_wsi_notice(wsi, "connect failed, select exception fd set");
		return LCCCR_FAILED;
	}

	if (!ret) {
		lwsl_wsi_debug(wsi, "select timeout");
		return LCCCR_CONTINUE;
	}

	en = LWS_ERRNO;
#endif

	lwsl_wsi_notice(wsi, "connection check FAILED: %s",
			lws_errno_describe(*real_errno || en, t16, sizeof(t16)));

	return LCCCR_FAILED;
}

/*
 * We come here to fire off a connect, and to check its disposition later.
 *
 * If it did not complete before the individual attempt timeout, we will try to
 * connect again with the next dns result.
 */

#if defined(LWS_WITH_CLIENT)

void
lws_remove_parallel_fd_safely(struct lws *wsi, int pidx)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int hole_pos = wsi->parallel_conns[pidx].position_in_fds_table;
	int last_pos = (int)pt->fds_count - 1;
	int saved_pos = wsi->position_in_fds_table;
	lws_sock_file_fd_type saved_fd = wsi->desc;

	wsi->desc.sockfd = wsi->parallel_conns[pidx].desc.sockfd;
	wsi->position_in_fds_table = hole_pos;

	__remove_wsi_socket_from_fds(wsi);
	compatible_close(wsi->parallel_conns[pidx].desc.sockfd);
	wsi->parallel_conns[pidx].is_valid = 0;

	wsi->desc = saved_fd;

	if (saved_pos == last_pos)
		wsi->position_in_fds_table = hole_pos;
	else
		wsi->position_in_fds_table = saved_pos;

	for (int i = 0; i < wsi->parallel_count; i++) {
		if (wsi->parallel_conns[i].is_valid && wsi->parallel_conns[i].position_in_fds_table == last_pos) {
			wsi->parallel_conns[i].position_in_fds_table = hole_pos;
		}
	}
}

static void
promote_parallel_fd(struct lws *wsi, int pidx)
{
	wsi->desc.sockfd = wsi->parallel_conns[pidx].desc.sockfd;
	wsi->position_in_fds_table = wsi->parallel_conns[pidx].position_in_fds_table;
	wsi->parallel_conns[pidx].is_valid = 0;
}
#endif

struct lws *
lws_client_connect_3_https_cb(struct lws *wsi, const char *ads,
			      const struct addrinfo *result, int n, void *opaque)
{
	struct lws *real_wsi = (struct lws *)opaque;
	if (n == 0 && result && real_wsi->a.context->h3_cap_cache) {
		lws_h3_state_t state = LWS_H3_STATE_HTTPS_RECORD_EXISTS;
		/* Cache the capability with a 1 hour TTL */
		lws_cache_write_through(real_wsi->a.context->h3_cap_cache, ads,
					(const uint8_t *)&state, sizeof(state),
					lws_now_usecs() + (3600ll * LWS_US_PER_SEC), NULL);
	}
	return real_wsi;
}

struct lws *
lws_client_connect_3_connect(struct lws *wsi, const char *ads,
			     const struct addrinfo *result, int n, void *opaque)
{
#if defined(LWS_WITH_UNIX_SOCK)
	struct sockaddr_un sau;
#endif
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const char *cce = "Unable to connect", *iface, *local_port;
	const struct sockaddr *psa = NULL;
	uint16_t port = wsi->conn_port;
	char dcce[128], t16[16];
	lws_dns_sort_t *curr;
	ssize_t plen = 0;
	lws_dll2_t *d;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	int cfail;
#endif
	int m, af = 0, en;
	int is_parallel = 0;
	int pidx = -1;
	lws_sockfd_type new_fd = LWS_SOCK_INVALID;
	int saved_pos = -1;
	lws_sock_file_fd_type saved_fd;

	/*
	 * If we come here with result set, we need to convert getaddrinfo
	 * results to a lws_dns_sort_t list one time and free the results.
	 *
	 * We use this pattern because ASYNC_DNS will callback here with the
	 * results when it gets them (and may come here more than once, eg, for
	 * AAAA then A or vice-versa)
	 */

	if (result) {
		lws_sul_cancel(&wsi->sul_connect_timeout);

#if defined(LWS_WITH_CONMON)
		/* append a copy from before the sorting */
		lws_conmon_append_copy_new_dns_results(wsi, result);
#endif

		lws_sort_dns(wsi, result);
#if defined(LWS_WITH_SYS_ASYNC_DNS)
		lws_async_dns_freeaddrinfo(&result);
#else
		freeaddrinfo((struct addrinfo *)result);
#endif
		result = NULL;
	}

#if defined(LWS_WITH_UNIX_SOCK)
	memset(&sau, 0, sizeof(sau));
#endif

	/*
	 * async dns calls back here for everybody who cares when it gets a
	 * result... but if we are piggybacking, we do not want to connect
	 * ourselves
	 */

	if (!lws_dll2_is_detached(&wsi->dll2_cli_txn_queue))
		return wsi;

	if (n < 0 &&  /* calling back with a problem */
	    !wsi->dns_sorted_list.count && /* there's no results */
	    !lws_socket_is_valid(wsi->desc.sockfd) && /* no attempt ongoing */
	    !wsi->speculative_connect_owner.count /* no spec attempt */ ) {
		lwsl_wsi_notice(wsi, "dns lookup failed %d", n);

		/*
		 * DNS lookup itself failed... let's try again until we
		 * timeout
		 */

		lwsi_set_state(wsi, LRS_UNCONNECTED);
		lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->sul_connect_timeout,
				 lws_client_dns_retry_timeout,
						 LWS_USEC_PER_SEC);
		return wsi;

//		cce = "dns lookup failed";
//		goto oom4;
	}

	/*
	 * We come back here again when we think the connect() may have
	 * completed one way or the other, we can't proceed until we know we
	 * actually connected.
	 */

	struct lws_pollfd *pollfd = (struct lws_pollfd *)opaque;
	lws_sockfd_type check_fd = pollfd ? pollfd->fd : LWS_SOCK_INVALID;

	int is_quic_race = (wsi->role_ops && !strcmp(wsi->role_ops->name, "quic") && wsi->sul_h3_grace.list.owner);
	if ((lwsi_state(wsi) == LRS_WAITING_CONNECT || (is_quic_race && pollfd != NULL)) &&
	    (lws_socket_is_valid(wsi->desc.sockfd) || wsi->parallel_count > 0)) {
		if (lwsi_state(wsi) == LRS_WAITING_CONNECT && !wsi->sul_connect_timeout.list.owner)
			/* no ongoing timeout for one */
			goto connect_to;

		if (check_fd == LWS_SOCK_INVALID) {
#if defined(WIN32)
			/* on Windows, FD_CONNECT and sul async check pass NULL opaque.
			 * we need to check the primary fd and parallel fds until we find one
			 * that completed or failed. */
			if (lws_socket_is_valid(wsi->desc.sockfd)) {
				int real_errno = 0;
				if (lws_client_connect_check(wsi, wsi->desc.sockfd, &real_errno) != LCCCR_CONTINUE) {
					check_fd = wsi->desc.sockfd;
				}
			}
			if (check_fd == LWS_SOCK_INVALID) {
				for (m = 0; m < wsi->parallel_count; m++) {
					if (wsi->parallel_conns[m].is_valid) {
						int real_errno = 0;
						if (lws_client_connect_check(wsi, wsi->parallel_conns[m].desc.sockfd, &real_errno) != LCCCR_CONTINUE) {
							check_fd = wsi->parallel_conns[m].desc.sockfd;
							break;
						}
					}
				}
			}
#endif
		}

		if (check_fd != LWS_SOCK_INVALID) {
			int real_errno = 0;
			int pidx = -1;

			if (check_fd != wsi->desc.sockfd) {
				for (m = 0; m < wsi->parallel_count; m++)
					if (wsi->parallel_conns[m].is_valid && wsi->parallel_conns[m].desc.sockfd == check_fd)
						pidx = m;
				if (pidx == -1)
					return NULL; /* obsolete parallel check? */
			}

			switch (lws_client_connect_check(wsi, check_fd, &real_errno)) {
			case LCCCR_CONNECTED:
				if (is_quic_race && pidx != -1) {
					int saved_pos_tmp = wsi->position_in_fds_table;
					lws_sock_file_fd_type saved_fd_tmp = wsi->desc;
					lwsl_wsi_notice(wsi, "TCP connected, waiting for QUIC grace");
					wsi->desc.sockfd = wsi->parallel_conns[pidx].desc.sockfd;
					wsi->position_in_fds_table = wsi->parallel_conns[pidx].position_in_fds_table;
					if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
						/* ignore */
					}
					wsi->desc = saved_fd_tmp;
					wsi->position_in_fds_table = saved_pos_tmp;
					return NULL;
				}
				lws_sul_cancel(&wsi->sul_happy_eyeballs);
				if (pidx != -1)
					promote_parallel_fd(wsi, pidx);
				/* close all remaining parallel */
				for (m = 0; m < wsi->parallel_count; m++)
						/* A parallel socket failed. Just close it and remove from fds */
						lws_remove_parallel_fd_safely(wsi, m);
				wsi->parallel_count = 0;
				goto conn_good;
			case LCCCR_CONTINUE:
#if defined(WIN32)
				lws_sul_schedule(wsi->a.context, 0, &wsi->win32_sul_connect_async_check,
					lws_client_win32_conn_async_check,
					wsi->a.context->win32_connect_check_interval_usec);
#endif
				return NULL;

			default:
				if (!real_errno)
					real_errno = LWS_ERRNO;
				lws_snprintf(dcce, sizeof(dcce), "conn fail: %s",
					     lws_errno_describe(real_errno, t16, sizeof(t16)));
				cce = dcce;
				lwsl_wsi_debug(wsi, "%s", dcce);
				lws_metrics_caliper_report(wsi->cal_conn, METRES_NOGO);

				if (pidx != -1) {
					lws_remove_parallel_fd_safely(wsi, pidx);
					return wsi; /* keep waiting for others */
				} else {
					/* primary failed */
					__remove_wsi_socket_from_fds(wsi);
					compatible_close(wsi->desc.sockfd);
					wsi->desc.sockfd = LWS_SOCK_INVALID;
					/* if we have a parallel running, promote it */
					for (m = 0; m < wsi->parallel_count; m++) {
						if (wsi->parallel_conns[m].is_valid) {
							promote_parallel_fd(wsi, m);
							return wsi;
						}
					}
					/* all failed */
					wsi->parallel_count = 0;
					goto try_next_dns_result;
				}
			}
		} else {
			/* timer fired, or no specific fd. Just proceed to pop next if available */
			if (!wsi->dns_sorted_list.count || wsi->parallel_count >= LWS_MAX_PARALLEL_CONNS)
				return wsi;
		}
	}

#if defined(LWS_WITH_UNIX_SOCK)

	if (ads && *ads == '+') {
		ads++;
		memset(&wsi->sa46_peer, 0, sizeof(wsi->sa46_peer));
		sau.sun_family = AF_UNIX;
		strncpy(sau.sun_path, ads, sizeof(sau.sun_path));
		sau.sun_path[sizeof(sau.sun_path) - 1] = '\0';

		lwsl_wsi_info(wsi, "Unix skt: %s", ads);

		if (sau.sun_path[0] == '@')
			sau.sun_path[0] = '\0';

		goto ads_known;
	}
#endif

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	if (n == LADNS_RET_FAILED) {
		lwsl_wsi_notice(wsi, "adns failed %s", ads);
		/*
		 * Caller that is giving us LADNS_RET_FAILED will deal
		 * with cleanup
		 */
		return NULL;
	}
#endif

	/*
	 * Let's try directly connecting to each of the results in turn until
	 * one works, or we run out of results...
	 *
	 * We have a sorted dll2 list with the head one most preferable
	 */

	if (!wsi->dns_sorted_list.count)
		goto failed1;

	while (wsi->dns_sorted_list.count) {
		cce = "Unable to connect";

	/*
	 * Copy the wsi head sorted dns result into the wsi->sa46_peer, and
	 * remove and free the original from the sorted list
	 */

	d = lws_dll2_get_head(&wsi->dns_sorted_list);
	curr = lws_container_of(d, lws_dns_sort_t, list);

	lws_dll2_remove(&curr->list);
	wsi->sa46_peer = curr->dest;
#if defined(LWS_WITH_UDP)
	if (wsi->udp)
		wsi->udp->sa46 = curr->dest;
#endif
#if defined(LWS_WITH_ROUTING)
	wsi->peer_route_uidx = curr->uidx;
	lwsl_wsi_info(wsi, "peer_route_uidx %d", wsi->peer_route_uidx);
#endif

	lws_free(curr);

	sa46_sockport(&wsi->sa46_peer, htons(port));

	psa = sa46_sockaddr(&wsi->sa46_peer);
	n = (int)sa46_socklen(&wsi->sa46_peer);

#if defined(LWS_WITH_UNIX_SOCK)
ads_known:
#endif

	/*
	 * Now we prepared psa, if not already connecting, create the related
	 * socket and add to the fds
	 */

	if (!lws_socket_is_valid(wsi->desc.sockfd) || wsi->parallel_count < LWS_MAX_PARALLEL_CONNS) {

		is_parallel = lws_socket_is_valid(wsi->desc.sockfd);
		pidx = is_parallel ? wsi->parallel_count++ : -1;
		new_fd = LWS_SOCK_INVALID;
		saved_pos = -1;

		if (wsi->a.context->event_loop_ops->check_client_connect_ok &&
		    wsi->a.context->event_loop_ops->check_client_connect_ok(wsi)
		) {
			cce = "waiting for event loop watcher to close";
			goto oom4;
		}

#if defined(LWS_WITH_UNIX_SOCK)
		if (wsi->unix_skt) {
			af = AF_UNIX;
			new_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		}
		else
#endif
		{
			af = wsi->sa46_peer.sa4.sin_family;
			int want_udp = 0;
#if defined(LWS_WITH_UDP)
			want_udp = wsi->udp || (wsi->role_ops && !strcmp(wsi->role_ops->name, "quic") && !is_parallel);
#else
			want_udp = (wsi->role_ops && !strcmp(wsi->role_ops->name, "quic") && !is_parallel);
#endif
			new_fd = socket(wsi->sa46_peer.sa4.sin_family, want_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
		}

		if (!lws_socket_is_valid(new_fd)) {
			en = LWS_ERRNO;

			lws_snprintf(dcce, sizeof(dcce),
				     "conn fail: skt creation: %s",
				     lws_errno_describe(en, t16, sizeof(t16)));
			cce = dcce;
			lwsl_wsi_warn(wsi, "%s", dcce);
			if (is_parallel) wsi->parallel_count--;
			goto try_next_dns_result;
		}

#if defined(LWS_WITH_UDP)
		if (!wsi->udp && strcmp(wsi->role_ops->name, "quic") != 0 && lws_plat_set_socket_options(wsi->a.vhost, new_fd,
#else
		if (strcmp(wsi->role_ops->name, "quic") != 0 && lws_plat_set_socket_options(wsi->a.vhost, new_fd,
#endif
#if defined(LWS_WITH_UNIX_SOCK)
						wsi->unix_skt)) {
#else
						0)) {
#endif
			en = LWS_ERRNO;

			lws_snprintf(dcce, sizeof(dcce),
				     "conn fail: skt options: %s",
				     lws_errno_describe(en, t16, sizeof(t16)));
			cce = dcce;
			lwsl_wsi_warn(wsi, "%s", dcce);
			compatible_close(new_fd);
			if (is_parallel) wsi->parallel_count--;
			goto try_next_dns_result;
		}

#if defined(LWS_WITH_UDP)
		if (wsi->udp || !strcmp(wsi->role_ops->name, "quic")) {
#else
		if (!strcmp(wsi->role_ops->name, "quic")) {
#endif
			if (lws_plat_set_nonblocking(new_fd)) {
				cce = "conn fail: set nonblocking";
				compatible_close(new_fd);
				if (is_parallel) wsi->parallel_count--;
				goto try_next_dns_result;
			}
		}

		/* apply requested socket options */
		if (lws_plat_set_socket_options_ip(new_fd,
						   wsi->c_pri, wsi->flags))
			lwsl_wsi_warn(wsi, "unable to set ip options");

		lwsl_wsi_debug(wsi, "WAITING_CONNECT");
		lwsi_set_state(wsi, LRS_WAITING_CONNECT);

		if (is_parallel) {
			wsi->parallel_conns[pidx].desc.sockfd = new_fd;
			wsi->parallel_conns[pidx].is_valid = 1;
			wsi->parallel_conns[pidx].position_in_fds_table = LWS_NO_FDS_POS;
			
			/* setup swap */
			saved_pos = wsi->position_in_fds_table;
			saved_fd = wsi->desc;
			wsi->desc.sockfd = new_fd;
			wsi->position_in_fds_table = LWS_NO_FDS_POS;
		} else {
			wsi->desc.sockfd = new_fd;
		}

		if (wsi->a.context->event_loop_ops->sock_accept)
			if (wsi->a.context->event_loop_ops->sock_accept(wsi)) {
				lws_snprintf(dcce, sizeof(dcce),
					     "conn fail: sock accept");
				cce = dcce;
				lwsl_wsi_warn(wsi, "%s", dcce);
				if (is_parallel) {
					wsi->position_in_fds_table = saved_pos;
					wsi->desc = saved_fd;
					wsi->parallel_conns[pidx].is_valid = 0;
					wsi->parallel_count--;
				} else {
					wsi->desc.sockfd = LWS_SOCK_INVALID;
				}
				compatible_close(new_fd);
				goto try_next_dns_result;
			}

		lws_pt_lock(pt, __func__);
		if (__insert_wsi_socket_into_fds(wsi->a.context, wsi)) {
			lws_snprintf(dcce, sizeof(dcce),
				     "conn fail: insert fd");
			cce = dcce;
			lws_pt_unlock(pt);
			compatible_close(new_fd);
			if (is_parallel) {
				wsi->parallel_count--;
				wsi->position_in_fds_table = saved_pos;
				wsi->desc = saved_fd;
			}
			goto try_next_dns_result;
		}
		lws_pt_unlock(pt);

		/*
		 * The fd + wsi combination is entered into the wsi tables
		 * at this point, with a pollfd
		 *
		 * Past here, we can't simply free the structs as error
		 * handling as oom4 does.
		 *
		 * We can run the whole close flow, or unpick the fds inclusion
		 * and anything else we have done.
		 */

		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lws_snprintf(dcce, sizeof(dcce),
				     "conn fail: change pollfd");
			cce = dcce;
			goto try_next_dns_result_fds;
		}

		if (!wsi->a.protocol)
			wsi->a.protocol = &wsi->a.vhost->protocols[0];

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CONNECT_RESPONSE,
				wsi->a.vhost->connect_timeout_secs);

		iface = lws_wsi_client_stash_item(wsi, CIS_IFACE,
						  _WSI_TOKEN_CLIENT_IFACE);

		local_port = lws_wsi_client_stash_item(wsi, CIS_LOCALPORT,
						  _WSI_TOKEN_CLIENT_LOCALPORT);

		if ((iface && *iface) || (local_port && atoi(local_port))) {
			m = lws_socket_bind(wsi->a.vhost, wsi, wsi->desc.sockfd,
					    (local_port ? atoi(local_port) : 0), iface, af);
			if (m < 0) {
				lws_snprintf(dcce, sizeof(dcce),
					     "conn fail: socket bind");
				cce = dcce;
				goto try_next_dns_result_fds;
			}
		}

#if defined(LWS_WITH_IPV6) && (defined(LWS_AMAZON_RTOS) || defined(LWS_ESP_PLATFORM))
		/*
		 * For IPv6 link-local addresses on FreeRTOS/lwIP, getaddrinfo()
		 * does not set sin6_scope_id. Set it from the iface stash so
		 * connect() can route to the correct network interface.
		 */
		if (iface && *iface &&
		    wsi->sa46_peer.sa4.sin_family == AF_INET6 &&
		    !wsi->sa46_peer.sa6.sin6_scope_id) {
			unsigned long scope = lws_get_addr_scope(wsi, iface);
			if (scope)
				wsi->sa46_peer.sa6.sin6_scope_id = (uint32_t)scope;
		}
#endif
	}

#if defined(LWS_WITH_UNIX_SOCK)
	if (wsi->unix_skt) {
		psa = (const struct sockaddr *)&sau;
		if (sau.sun_path[0]) {
#if defined(WIN32)
			n = (int)(sizeof(uint16_t) + strlen(sau.sun_path) + 1);
#else
			n = (int)(sizeof(uint16_t) + strlen(sau.sun_path));
#endif
		} else
			n = (int)(sizeof(uint16_t) +
					strlen(&sau.sun_path[1]) + 1);
	} else
#endif

	if (!psa) /* coverity */
		goto try_next_dns_result_fds;

	/*
	 * The actual connection attempt
	 */

#if defined(LWS_ESP_PLATFORM)
	errno = 0;
#endif

	/* grab a copy for peer tracking */
#if defined(LWS_WITH_UNIX_SOCK)
	if (!wsi->unix_skt)
#endif
		memmove(&wsi->sa46_peer, psa, (unsigned int)n);

	/*
	 * Finally, make the actual connection attempt
	 */

#if defined(LWS_WITH_SYS_METRICS)
	if (wsi->cal_conn.mt) {
		lws_metrics_caliper_report(wsi->cal_conn, METRES_NOGO);
	}
	lws_metrics_caliper_bind(wsi->cal_conn, wsi->a.context->mt_conn_tcp);
#endif

	wsi->socket_is_permanently_unusable = 0;

	if (lws_fi(&wsi->fic, "conn_cb_rej") ||
	    user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
			LWS_CALLBACK_CONNECTING, wsi->user_space,
			(void *)(intptr_t)wsi->desc.sockfd, 0)) {
		lwsl_wsi_info(wsi, "CONNECTION CB closed");
		goto failed1;
	}

	{
		char buf[64];

		lws_sa46_write_numeric_address((lws_sockaddr46 *)psa, buf, sizeof(buf));
		lwsl_wsi_info(wsi, "trying %s", buf);
	}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	cfail = lws_fi(&wsi->fic, "connfail");
	if (cfail)
		m = -1;
	else
#endif
#if defined(LWS_WITH_LATENCY)
		lws_usec_t _conn_start = lws_now_usecs();
#endif

		m = connect(wsi->desc.sockfd, (const struct sockaddr *)psa,
			    (socklen_t)n);

#if defined(LWS_WITH_LATENCY)
		{
			unsigned int ms = (unsigned int)((lws_now_usecs() - _conn_start) / 1000);
			if (ms > 2) {
				struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
				lws_latency_note(pt, _conn_start, 2000, "connect:%dms", ms);
			}
		}
#endif

#if defined(LWS_WITH_CONMON)
	wsi->conmon_datum = lws_now_usecs();
	wsi->conmon.ciu_sockconn = 0;
#endif

	if (m == -1) {
		/*
		 * Since we're nonblocking, connect not having completed is not
		 * necessarily indicating any problem... we have to look at
		 * either errno or the socket to understand if we actually
		 * failed already...
		 */

		int errno_copy = LWS_ERRNO;

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		if (cfail)
			/* fake an abnormal, fatal situation */
			errno_copy = 999;
#endif

		lwsl_wsi_debug(wsi, "connect: fd %d, %s",
				wsi->desc.sockfd,
				lws_errno_describe(errno_copy, t16, sizeof(t16)));

		if (errno_copy &&
		    errno_copy != LWS_EALREADY &&
		    errno_copy != LWS_EINPROGRESS &&
		    errno_copy != LWS_EWOULDBLOCK
#ifdef _WIN32
		 && errno_copy != WSAEINVAL
                 && errno_copy != WSAEISCONN
#endif
		) {
			/*
			 * The connect() failed immediately...
			 */

#if defined(LWS_WITH_CONMON)
			wsi->conmon.ciu_sockconn = (lws_conmon_interval_us_t)
					(lws_now_usecs() - wsi->conmon_datum);
#endif

			lws_metrics_caliper_report(wsi->cal_conn, METRES_NOGO);

#if defined(_DEBUG)
#if defined(LWS_WITH_UNIX_SOCK)
			if (!wsi->unix_skt) {
#endif

			char nads[48];

			lws_sa46_write_numeric_address(&wsi->sa46_peer, nads,
						       sizeof(nads));

			lws_snprintf(dcce, sizeof(dcce),
				     "conn fail: %s: %s:%d",
				     lws_errno_describe(errno_copy, t16, sizeof(t16)),
				     nads, port);
			cce = dcce;

			wsi->sa46_peer.sa4.sin_family = 0;
			lwsl_wsi_info(wsi, "%s", cce);
#if defined(LWS_WITH_UNIX_SOCK)
			} else {
				lws_snprintf(dcce, sizeof(dcce),
					     "conn fail: %s: UDS %s",
					     lws_errno_describe(errno_copy, t16, sizeof(t16)), ads);
				cce = dcce;
				lwsl_wsi_info(wsi, "%s", cce);
			}
#endif
#endif
			goto try_next_dns_result_fds;
		}

#if defined(WIN32)
		if (lws_plat_check_connection_error(wsi))
			goto try_next_dns_result_fds;

		if (errno_copy == WSAEISCONN)
			goto conn_good;
#endif

		if (is_parallel) {
			/* restore swap */
			wsi->parallel_conns[pidx].position_in_fds_table = wsi->position_in_fds_table;
			wsi->position_in_fds_table = saved_pos;
			wsi->desc = saved_fd;
		}

		/*
		 * The connection attempt is ongoing asynchronously... let's set
		 * a specialized timeout for this connect attempt completion, it
		 * uses wsi->sul_connect_timeout just for this purpose
		 */

		lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->sul_connect_timeout,
				 lws_client_conn_wait_timeout,
				 wsi->a.context->timeout_secs *
						 LWS_USEC_PER_SEC);

		/* schedule happy eyeballs timer if we have more dns results and the event loop supports it */
		if (wsi->dns_sorted_list.count && !strcmp(wsi->a.context->event_loop_ops->name, "poll")) {
			extern void lws_client_happy_eyeballs_cb(lws_sorted_usec_list_t *sul);
			lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->sul_happy_eyeballs,
					lws_client_happy_eyeballs_cb,
					200 * LWS_US_PER_MS);
		}
#if defined(WIN32)
		/*
		 * Windows is not properly POSIX, we have to manually schedule a
		 * callback to poll checking its status
		 */

		lws_sul_schedule(wsi->a.context, 0, &wsi->win32_sul_connect_async_check,
				 lws_client_win32_conn_async_check,
				 wsi->a.context->win32_connect_check_interval_usec
		);
#else
		/*
		 * POSIX platforms must do specifically a POLLOUT poll to hear
		 * about the connect completion as a POLLOUT event
		 */

		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
			goto try_next_dns_result_fds;
#endif

		return wsi;
	} else if (!is_parallel && wsi->role_ops && !strcmp(wsi->role_ops->name, "quic")) {
		/* QUIC connect immediately succeeds. Schedule grace and happy eyeballs. */
		uint32_t grace_us = LWS_QUIC_GRACE_DEFAULT_US;
		if (wsi->a.context->h3_cap_cache && wsi->stash && wsi->stash->cis[CIS_HOST]) {
			const void *item = NULL;
			size_t item_len = 0;
			if (!lws_cache_item_get(wsi->a.context->h3_cap_cache, wsi->stash->cis[CIS_HOST], &item, &item_len) &&
			    item_len == sizeof(lws_h3_cap_info_t)) {
				const lws_h3_cap_info_t *cap = (const lws_h3_cap_info_t *)item;
				if (cap->state == LWS_H3_STATE_KNOWN_GOOD)
					grace_us = cap->latency_us + LWS_QUIC_GRACE_MARGIN_US;
				else if (cap->state == LWS_H3_STATE_HTTPS_RECORD_EXISTS)
					grace_us = LWS_QUIC_GRACE_DEFAULT_US;
			}
		}
		lwsl_wsi_notice(wsi, "QUIC socket created, starting grace timer %uus", (unsigned int)grace_us);
		lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->sul_h3_grace,
				 lws_client_h3_grace_cb, grace_us);

		if (wsi->dns_sorted_list.count && !strcmp(wsi->a.context->event_loop_ops->name, "poll")) {
			extern void lws_client_happy_eyeballs_cb(lws_sorted_usec_list_t *sul);
			lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->sul_happy_eyeballs,
					lws_client_happy_eyeballs_cb, 1);
		}
	}

conn_good:

	if (is_parallel) {
		/* promote parallel to primary right away */
		wsi->parallel_conns[pidx].position_in_fds_table = wsi->position_in_fds_table;
		wsi->position_in_fds_table = saved_pos;
		wsi->desc = saved_fd;

		/* kill primary */
		lws_pt_lock(pt, __func__);
		__remove_wsi_socket_from_fds(wsi);
		lws_pt_unlock(pt);
		compatible_close(wsi->desc.sockfd);

		promote_parallel_fd(wsi, pidx);
	}

#if defined(LWS_WITH_CLIENT)
	int is_quic_race = (wsi->role_ops && !strcmp(wsi->role_ops->name, "quic") && wsi->sul_h3_grace.list.owner);
	if (!is_quic_race) {
		/* kill all remaining parallel connections */
		for (int i = 0; i < wsi->parallel_count; i++) {
			if (wsi->parallel_conns[i].is_valid) {
				lws_remove_parallel_fd_safely(wsi, i);
			}
		}
		wsi->parallel_count = 0;
	} else {
		lwsl_wsi_notice(wsi, "QUIC reached conn_good, keeping %d parallel TCP sockets alive", wsi->parallel_count);
	}
#endif

	/*
	 * The connection has happened
	 */

#if defined(LWS_WITH_CONMON)
	wsi->conmon.ciu_sockconn = (lws_conmon_interval_us_t)
					(lws_now_usecs() - wsi->conmon_datum);
#endif

#if !defined(LWS_PLAT_OPTEE)
	{
		socklen_t salen = sizeof(wsi->sa46_local);
#if defined(_DEBUG)
		char buf[64];
#endif
		if (getsockname((int)wsi->desc.sockfd,
				(struct sockaddr *)&wsi->sa46_local,
				&salen) == -1) {
			en = LWS_ERRNO;
			lwsl_info("getsockname: %s\n", lws_errno_describe(en, t16, sizeof(t16)));
		} else {
#if defined(LWS_WITH_IPV6)
			if (wsi->sa46_peer.sa4.sin_family == AF_INET6 &&
			    wsi->sa46_local.sa4.sin_family == AF_INET6) {
				const uint8_t *pb = (const uint8_t *)&wsi->sa46_peer.sa6.sin6_addr;
				const uint8_t *lb = (const uint8_t *)&wsi->sa46_local.sa6.sin6_addr;
				int peer_is_ll = (pb[0] == 0xfe && (pb[1] & 0xc0) == 0x80);
				int local_is_ll = (lb[0] == 0xfe && (lb[1] & 0xc0) == 0x80);

				if (local_is_ll && !peer_is_ll) {
					lwsl_wsi_notice(wsi, "rejecting global v6 peer with link-local src");
					cce = "incompatible v6 scopes";
					goto try_next_dns_result_fds;
				}
			}
#endif
		}
#if defined(_DEBUG)
#if defined(LWS_WITH_UNIX_SOCK)
		if (wsi->unix_skt)
			buf[0] = '\0';
		else
#endif
			lws_sa46_write_numeric_address(&wsi->sa46_local, buf, sizeof(buf));

		lwsl_wsi_info(wsi, "source ads %s", buf);
#endif
	}
#endif
	lws_sul_cancel(&wsi->sul_connect_timeout);
#if defined(WIN32)
	lws_sul_cancel(&wsi->win32_sul_connect_async_check);
#endif
	lws_metrics_caliper_report(wsi->cal_conn, METRES_GO);

#if defined(LWS_ROLE_QUIC)
	if (strcmp(wsi->role_ops->name, "quic") != 0)
#endif
		lws_addrinfo_clean(wsi);

	if (wsi->a.protocol)
		wsi->a.protocol->callback(wsi, LWS_CALLBACK_WSI_CREATE,
					  wsi->user_space, NULL, 0);

	lwsl_wsi_debug(wsi, "going into connect_4");

	return lws_client_connect_4_established(wsi, NULL, plen);

oom4:
	/*
	 * We get here if we're trying to clean up a connection attempt that
	 * didn't make it as far as getting inserted into the wsi / fd tables
	 */

	if (lwsi_role_client(wsi) && wsi->a.protocol
				/* && lwsi_state_est(wsi) */)
		lws_inform_client_conn_fail(wsi,(void *)cce, strlen(cce));

	/* take care that we might be inserted in fds already */
	if (wsi->position_in_fds_table != LWS_NO_FDS_POS)
		/* do the full wsi close flow */
		goto failed1;

	lws_metrics_caliper_report(wsi->cal_conn, METRES_NOGO);

	/*
	 * We can't be an active client connection any more, if we thought
	 * that was what we were going to be doing.  It should be if we are
	 * failing by oom4 path, we are still called by
	 * lws_client_connect_via_info() and will be returning NULL to that,
	 * so nobody else should have had a chance to queue on us.
	 */
	{
		struct lws_vhost *vhost = wsi->a.vhost;
		lws_sockfd_type sfd = wsi->desc.sockfd;

		//lws_vhost_lock(vhost);
		__lws_free_wsi(wsi); /* acquires vhost lock in wsi reset */
		//lws_vhost_unlock(vhost);

		sanity_assert_no_wsi_traces(vhost->context, wsi);
		sanity_assert_no_sockfd_traces(vhost->context, sfd);
	}

	return NULL;

connect_to:
	/*
	 * It looks like the sul_connect_timeout fired
	 */
	lwsl_wsi_info(wsi, "abandoning connect due to timeout");

try_next_dns_result_fds:
	lws_pt_lock(pt, __func__);
	if (is_parallel) {
		/* If we're failing after swap was restored, we need to manually swap it back temporarily */
		if (wsi->desc.sockfd != new_fd) {
			wsi->desc.sockfd = new_fd;
			wsi->position_in_fds_table = wsi->parallel_conns[pidx].position_in_fds_table;
		}
		__remove_wsi_socket_from_fds(wsi);
		wsi->parallel_conns[pidx].is_valid = 0;
	} else {
		__remove_wsi_socket_from_fds(wsi);
	}
	lws_pt_unlock(pt);

	/*
	 * We are killing the socket but leaving
	 */
	if (is_parallel) {
		compatible_close(new_fd);
		/* restore primary */
		wsi->position_in_fds_table = saved_pos;
		wsi->desc = saved_fd;
	} else {
		compatible_close(wsi->desc.sockfd);
		wsi->desc.sockfd = LWS_SOCK_INVALID;
		
#if defined(LWS_WITH_CLIENT)
		/* promote a parallel connection to primary if possible */
		int first_valid = -1;
		for (int i = 0; i < wsi->parallel_count; i++) {
			if (wsi->parallel_conns[i].is_valid) {
				first_valid = i;
				break;
			}
		}
		if (first_valid != -1) {
			wsi->desc.sockfd = wsi->parallel_conns[first_valid].desc.sockfd;
			wsi->position_in_fds_table = wsi->parallel_conns[first_valid].position_in_fds_table;
			wsi->parallel_conns[first_valid].is_valid = 0;
		}
#endif
	}

try_next_dns_result:
#if defined(LWS_WITH_CLIENT)
	{
		int any_valid = lws_socket_is_valid(wsi->desc.sockfd);
		for (int i = 0; i < wsi->parallel_count; i++) {
			if (wsi->parallel_conns[i].is_valid)
				any_valid = 1;
		}
		if (any_valid) {
			/* some connection is still running */
			return wsi;
		}
	}
#endif

		lws_sul_cancel(&wsi->sul_connect_timeout);
#if defined(WIN32)
		lws_sul_cancel(&wsi->win32_sul_connect_async_check);
#endif
	}

	lws_addrinfo_clean(wsi);
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

failed1:
	lws_sul_cancel(&wsi->sul_connect_timeout);
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect3");

	return NULL;
}
