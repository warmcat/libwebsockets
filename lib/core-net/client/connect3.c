/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

void
lws_client_conn_wait_timeout(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws,
					   sul_connect_timeout);

	/*
	 * This is used to constrain the time we're willing to wait for a
	 * connection before giving up on it and retrying.
	 */

	lwsl_info("%s: connect wait timeout has fired\n", __func__);
	lws_client_connect_3_connect(wsi, NULL, NULL, 0, NULL);
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
lws_client_connect_check(struct lws *wsi)
{
#if !defined(WIN32)
	socklen_t sl = sizeof(int);
	int e = 0;

	/*
	 * This resets SO_ERROR after reading it.  If there's an error
	 * condition, the connect definitively failed.
	 */

	if (!getsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_ERROR, &e, &sl)) {
		if (!e) {
			lwsl_debug("%s: getsockopt check: conn OK errno %d\n",
				   __func__, errno);

			return LCCCR_CONNECTED;
		}

		lwsl_debug("%s: getsockopt fd %d says err %d\n", __func__,
			   wsi->desc.sockfd, e);
	}

#else
	if (!connect(wsi->desc.sockfd, NULL, 0))
		return LCCCR_CONNECTED;

	if (!LWS_ERRNO || LWS_ERRNO == WSAEINVAL ||
			  LWS_ERRNO == WSAEWOULDBLOCK ||
			  LWS_ERRNO == WSAEALREADY) {
		lwsl_info("%s: errno %d\n", __func__, errno);

		return LCCCR_CONTINUE;
	}
#endif

	lwsl_info("%s: connect check take as FAILED\n", __func__);

	return LCCCR_FAILED;
}

/*
 * We come here to fire off a connect, and to check its disposition later.
 *
 * If it did not complete before the individual attempt timeout, we will try to
 * connect again with the next dns result.
 */

struct lws *
lws_client_connect_3_connect(struct lws *wsi, const char *ads,
			     const struct addrinfo *result, int n, void *opaque)
{
#if defined(LWS_WITH_UNIX_SOCK)
	struct sockaddr_un sau;
#endif
#ifdef LWS_WITH_IPV6
	char ipv6only = lws_check_opt(wsi->a.vhost->options,
				      LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
				      LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE);
#endif
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const struct sockaddr *psa = NULL;
	uint16_t port = wsi->c_port;
	const char *cce, *iface;
	lws_sockaddr46 sa46;
	ssize_t plen = 0;
	int m;

       if (n == LWS_CONNECT_COMPLETION_GOOD)
               goto conn_good;

#if defined(LWS_WITH_IPV6) && defined(__ANDROID__)
	ipv6only = 0;
#endif

	/*
	 * async dns calls back here for everybody who cares when it gets a
	 * result... but if we are piggybacking, we do not want to connect
	 * ourselves
	 */

	if (!lws_dll2_is_detached(&wsi->dll2_cli_txn_queue))
		return wsi;

	/*
	 * We come back here again when we think the connect() may have
	 * completed one way or the other, we can't proceed until we know we
	 * actually connected.
	 */

	if (lwsi_state(wsi) == LRS_WAITING_CONNECT &&
	    lws_socket_is_valid(wsi->desc.sockfd)) {

		if (!result && !wsi->sul_connect_timeout.list.owner)
			/* no dns results and no ongoing timeout for one */
			goto connect_to;

		switch (lws_client_connect_check(wsi)) {
		case LCCCR_CONNECTED:
			/*
			 * Oh, it has happened...
			 */
			goto conn_good;
		case LCCCR_CONTINUE:
			return NULL;
		default:
			lwsl_debug("%s: getsockopt check: conn fail: errno %d\n",
					__func__, LWS_ERRNO);
			goto try_next_dns_result_fds;
		}
	}

#if defined(LWS_WITH_UNIX_SOCK)
	if (ads && *ads == '+') {
		ads++;
		memset(&sa46, 0, sizeof(sa46));
		memset(&sau, 0, sizeof(sau));
		sau.sun_family = AF_UNIX;
		strncpy(sau.sun_path, ads, sizeof(sau.sun_path));
		sau.sun_path[sizeof(sau.sun_path) - 1] = '\0';

		lwsl_info("%s: Unix skt: %s\n", __func__, ads);

		if (sau.sun_path[0] == '@')
			sau.sun_path[0] = '\0';

		goto ads_known;
	}
#endif

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	if (n == LADNS_RET_FAILED) {
		lwsl_notice("%s: adns failed %s\n", __func__, ads);
		/*
		 * Caller that is giving us LADNS_RET_FAILED will deal
		 * with cleanup
		 */
		return NULL;
	}
#endif

	if (!wsi->dns_results) {
		wsi->dns_results_next = wsi->dns_results = result;
		if (result)
			lwsl_debug("%s: result %p result->ai_next %p\n",
					__func__, result, result->ai_next);
	}

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (lwsi_state(wsi) == LRS_WAITING_DNS &&
	    wsi->a.context->detailed_latency_cb) {
		wsi->detlat.type = LDLT_NAME_RESOLUTION;
		wsi->detlat.latencies[LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE] =
			lws_now_usecs() -
			wsi->detlat.earliest_write_req_pre_write;
		wsi->detlat.latencies[LAT_DUR_USERCB] = 0;
		lws_det_lat_cb(wsi->a.context, &wsi->detlat);
		wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
	}
#endif
#if defined(LWS_CLIENT_HTTP_PROXYING) && (defined(LWS_ROLE_H1) || \
					  defined(LWS_ROLE_H2))

	/*
	 * Decide what it is we need to connect to:
	 *
	 * Priority 1: connect to http proxy
	 */

	if (wsi->a.vhost->http.http_proxy_port) {
		port = wsi->a.vhost->http.http_proxy_port;
#else
		if (0) {
#endif

#if defined(LWS_WITH_SOCKS5)

	/*
	 * Priority 2: Connect to SOCK5 Proxy
	 */

	} else if (wsi->a.vhost->socks_proxy_port) {
		if (lws_socks5c_generate_msg(wsi, SOCKS_MSG_GREETING, &plen)) {
			cce = "socks msg too large";
			goto oom4;
		}

		lwsl_client("Sending SOCKS Greeting\n");
		ads = wsi->a.vhost->socks_proxy_address;
		port = wsi->a.vhost->socks_proxy_port;
#endif
	}

	if (n || !wsi->dns_results) {
		/* lws_getaddrinfo46 failed, there is no usable result */
		lwsl_notice("%s: lws_getaddrinfo46 failed %d\n", __func__, n);

		cce = "ipv6 lws_getaddrinfo46 failed";
		goto oom4;
	}

	/*
	 * Let's try directly connecting to each of the results in turn until
	 * one works, or we run out of results...
	 */

next_dns_result:

	/*
	 * Make a possibly 4->6 adapted copy of the next dns result in sa46
	 */

	psa = (const struct sockaddr *)&sa46;
	n = sizeof(struct sockaddr_in6);
	memset(&sa46, 0, sizeof(sa46));

	switch (wsi->dns_results_next->ai_family) {
	case AF_INET:
#if defined(LWS_WITH_IPV6)
		if (ipv6only) {
			lws_sa46_4to6(&sa46, &((struct sockaddr_in *)
				      wsi->dns_results_next->ai_addr)->sin_addr,
				      port);
			break;
		}
#endif
		sa46.sa4.sin_family = AF_INET;
		sa46.sa4.sin_addr.s_addr =
			((struct sockaddr_in *)wsi->dns_results_next->ai_addr)->
								sin_addr.s_addr;
		sa46.sa4.sin_port = htons(port);
		n = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
#if defined(LWS_WITH_IPV6)
		if (!wsi->ipv6)
			goto try_next_dns_result;

		lws_sa46_copy_address(&sa46, &((struct sockaddr_in6 *)
				       wsi->dns_results_next->ai_addr)->
					       sin6_addr, AF_INET6);

		sa46.sa6.sin6_scope_id = ((struct sockaddr_in6 *)
				wsi->dns_results_next->ai_addr)->sin6_scope_id;
		sa46.sa6.sin6_flowinfo = ((struct sockaddr_in6 *)
				wsi->dns_results_next->ai_addr)->sin6_flowinfo;
		sa46.sa6.sin6_port = htons(port);
#else
		goto try_next_dns_result;	/* ipv4 only can't use this */
#endif
		break;
	}

#if defined(LWS_WITH_UNIX_SOCK)
ads_known:
#endif

	/*
	 * Now we prepared sa46, if not already connecting, create the related
	 * socket and add to the fds
	 */

	if (!lws_socket_is_valid(wsi->desc.sockfd)) {

		if (wsi->a.context->event_loop_ops->check_client_connect_ok &&
		    wsi->a.context->event_loop_ops->check_client_connect_ok(wsi)
		) {
			cce = "waiting for event loop watcher to close";
			goto oom4;
		}

#if defined(LWS_WITH_UNIX_SOCK)
		if (wsi->unix_skt)
			wsi->desc.sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
		else
#endif
			wsi->desc.sockfd = socket(sa46.sa4.sin_family,
						  SOCK_STREAM, 0);

		if (!lws_socket_is_valid(wsi->desc.sockfd)) {
			lwsl_warn("Unable to open socket\n");
			goto try_next_dns_result;
		}

		if (lws_plat_set_socket_options(wsi->a.vhost, wsi->desc.sockfd,
#if defined(LWS_WITH_UNIX_SOCK)
						wsi->unix_skt)) {
#else
						0)) {
#endif
			lwsl_err("Failed to set wsi socket options\n");
			goto try_next_dns_result_closesock;
		}

		lwsl_debug("%s: %p: WAITING_CONNECT\n", __func__, wsi);
		lwsi_set_state(wsi, LRS_WAITING_CONNECT);

		if (wsi->a.context->event_loop_ops->sock_accept)
			if (wsi->a.context->event_loop_ops->sock_accept(wsi))
				goto try_next_dns_result_closesock;

		lws_pt_lock(pt, __func__);
		if (__insert_wsi_socket_into_fds(wsi->a.context, wsi)) {
			lws_pt_unlock(pt);
			goto try_next_dns_result_closesock;
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

		if (lws_change_pollfd(wsi, 0, LWS_POLLIN))
			goto try_next_dns_result_fds;

		if (!wsi->a.protocol)
			wsi->a.protocol = &wsi->a.vhost->protocols[0];

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CONNECT_RESPONSE,
				wsi->a.vhost->connect_timeout_secs);

		iface = lws_wsi_client_stash_item(wsi, CIS_IFACE,
						  _WSI_TOKEN_CLIENT_IFACE);

		if (iface && *iface) {
			m = lws_socket_bind(wsi->a.vhost, wsi->desc.sockfd, 0,
					    iface, wsi->ipv6);
			if (m < 0)
				goto try_next_dns_result_fds;
		}
	}

#if defined(LWS_WITH_UNIX_SOCK)
	if (wsi->unix_skt) {
		psa = (const struct sockaddr *)&sau;
		if (sau.sun_path[0])
			n = (int)(sizeof(uint16_t) + strlen(sau.sun_path));
		else
			n = (int)(sizeof(uint16_t) +
					strlen(&sau.sun_path[1]) + 1);
	} else
#endif

	if (!psa) /* coverity */
		goto try_next_dns_result_fds;

	/*
	 * The actual connection attempt
	 */

#if defined(LWS_WITH_DETAILED_LATENCY)
	wsi->detlat.earliest_write_req =
		wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
#endif

#if defined(LWS_ESP_PLATFORM)
	errno = 0;
#endif

	/* grab a copy for peer tracking */
#if defined(LWS_WITH_UNIX_SOCK)
	if (!wsi->unix_skt)
#endif
		memcpy(&wsi->sa46_peer, psa, n);

	/*
	 * Finally, make the actual connection attempt
	 */

	m = connect(wsi->desc.sockfd, (const struct sockaddr *)psa, n);
	if (m == -1) {
		/*
		 * Since we're nonblocking, connect not having completed is not
		 * necessarily indicating any problem... we have to look at
		 * either errno or the socket to understand if we actually
		 * failed already...
		 */

		int errno_copy = LWS_ERRNO;

		lwsl_debug("%s: connect: errno: %d\n", __func__, errno_copy);

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

#if defined(_DEBUG)
			char nads[48];

			lws_sa46_write_numeric_address(&sa46, nads,
						       sizeof(nads));
			lwsl_info("%s: Connect failed: %s port %d\n", __func__,
				  nads, port);
#endif

			goto try_next_dns_result_fds;
		}

#if defined(WIN32)
		if (lws_plat_check_connection_error(wsi))
			goto try_next_dns_result_fds;

		if (errno_copy == WSAEISCONN)
			goto conn_good;
#endif

		/*
		 * The connection attempt is ongoing asynchronously... let's set
		 * a specialized timeout for this connect attempt completion, it
		 * uses wsi->sul_connect_timeout just for this purpose
		 */

		lws_sul_schedule(wsi->a.context, 0, &wsi->sul_connect_timeout,
				 lws_client_conn_wait_timeout,
				 wsi->a.context->timeout_secs *
						 LWS_USEC_PER_SEC);

#if !defined(WIN32)
		/*
		 * must do specifically a POLLOUT poll to hear
		 * about the connect completion
		 */
		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
			goto try_next_dns_result_fds;
#endif

		return wsi;
	}

conn_good:

	/*
	 * The connection has happened
	 */

	lws_sul_cancel(&wsi->sul_connect_timeout);
	lwsl_info("%s: Connection started %p\n", __func__, wsi->dns_results);

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (wsi->a.context->detailed_latency_cb) {
		wsi->detlat.type = LDLT_CONNECTION;
		wsi->detlat.latencies[LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE] =
			lws_now_usecs() -
			wsi->detlat.earliest_write_req_pre_write;
		wsi->detlat.latencies[LAT_DUR_USERCB] = 0;
		lws_det_lat_cb(wsi->a.context, &wsi->detlat);
		wsi->detlat.earliest_write_req =
			wsi->detlat.earliest_write_req_pre_write =
							lws_now_usecs();
	}
#endif

	lws_addrinfo_clean(wsi);

	if (wsi->a.protocol)
		wsi->a.protocol->callback(wsi, LWS_CALLBACK_WSI_CREATE,
					  wsi->user_space, NULL, 0);

	lwsl_debug("%s: going into connect_4\n", __func__);
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

		lws_vhost_lock(vhost);
		__lws_free_wsi(wsi);
		lws_vhost_unlock(vhost);

		sanity_assert_no_wsi_traces(vhost->context, wsi);
		sanity_assert_no_sockfd_traces(vhost->context, sfd);
	}

	return NULL;

connect_to:
	/*
	 * It looks like the sul_connect_timeout fired
	 */
	lwsl_info("%s: abandoning connect due to timeout\n", __func__);

try_next_dns_result_fds:
	__remove_wsi_socket_from_fds(wsi);

try_next_dns_result_closesock:
	/*
	 * We are killing the socket but leaving
	 */
	compatible_close(wsi->desc.sockfd);
	wsi->desc.sockfd = LWS_SOCK_INVALID;

try_next_dns_result:
	lws_sul_cancel(&wsi->sul_connect_timeout);
	if (wsi->dns_results_next) {
		wsi->dns_results_next = wsi->dns_results_next->ai_next;
		if (wsi->dns_results_next)
			goto next_dns_result;
	}
	lws_addrinfo_clean(wsi);
	cce = "Unable to connect";
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

failed1:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect3");

	return NULL;
}
