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
	char ni[48];
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
	* We can check using getsockopt if our connect actually completed.
	* Posix connect() allows nonblocking to redo the connect to
	* find out if it succeeded, for win32 we have to use this path
	* and take WSAEALREADY as a successful connect.
	*/

	if (lwsi_state(wsi) == LRS_WAITING_CONNECT &&
	    lws_socket_is_valid(wsi->desc.sockfd)) {
#if !defined(WIN32)
		socklen_t sl = sizeof(int);
		int e = 0;
#endif

		if (!result && /* no dns results... */
		    /* no ongoing connect timeout */
		    !wsi->sul_connect_timeout.list.owner)
			goto connect_to;
#if defined(WIN32)
		if (!connect(wsi->desc.sockfd, NULL, 0)) {
			goto conn_good;
               } else {
			if (!LWS_ERRNO ||
			    LWS_ERRNO == WSAEINVAL ||
			    LWS_ERRNO == WSAEWOULDBLOCK ||
			    LWS_ERRNO == WSAEALREADY) {
				lwsl_info("%s: errno %d\n", __func__, errno);
				return NULL;
			}
			lwsl_info("%s: connect check take as FAILED\n",
				  __func__);
		}
#else
		/*
		* this resets SO_ERROR after reading it.  If there's an error
		* condition the connect definitively failed.
		*/

		if (!getsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_ERROR,
				&e, &sl)) {
			if (!e) {
				lwsl_debug("%s: getsockopt check: "
					   "conn OK errno %d\n", __func__,
					   errno);

				goto conn_good;
			}

			lwsl_debug("%s: getsockopt fd %d says err %d\n",
				   __func__, wsi->desc.sockfd, e);
		}
#endif

		lwsl_debug("%s: getsockopt check: conn fail: errno %d\n",
				__func__, LWS_ERRNO);
		goto try_next_result_fds;
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
#if defined(LWS_CLIENT_HTTP_PROXYING) && \
	(defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))

	/* Decide what it is we need to connect to:
	 *
	 * Priority 1: connect to http proxy */

	if (wsi->a.vhost->http.http_proxy_port) {
		port = wsi->a.vhost->http.http_proxy_port;
#else
		if (0) {
#endif

#if defined(LWS_WITH_SOCKS5)

	/* Priority 2: Connect to SOCK5 Proxy */

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

	memset(&sa46, 0, sizeof(sa46));

	if (n || !wsi->dns_results) {
		/* lws_getaddrinfo46 failed, there is no usable result */
		lwsl_notice("%s: lws_getaddrinfo46 failed %d\n",
				__func__, n);

		cce = "ipv6 lws_getaddrinfo46 failed";
		goto oom4;
	}

	/*
	 * Let's try connecting to each of the results in turn until one works
	 * or we run out of results
	 */

next_result:

	psa = (const struct sockaddr *)&sa46;
	n = sizeof(sa46);
	memset(&sa46, 0, sizeof(sa46));

	switch (wsi->dns_results_next->ai_family) {
	case AF_INET:
#if defined(LWS_WITH_IPV6)
		if (ipv6only) {
			sa46.sa4.sin_family = AF_INET6;

			/* map IPv4 to IPv6 */
			memset((char *)&sa46.sa6.sin6_addr, 0,
						sizeof(sa46.sa6.sin6_addr));
			sa46.sa6.sin6_addr.s6_addr[10] = 0xff;
			sa46.sa6.sin6_addr.s6_addr[11] = 0xff;
			memcpy(&sa46.sa6.sin6_addr.s6_addr[12],
				&((struct sockaddr_in *)
				    wsi->dns_results_next->ai_addr)->sin_addr,
							sizeof(struct in_addr));
			sa46.sa6.sin6_port = htons(port);
			ni[0] = '\0';
			lws_write_numeric_address(sa46.sa6.sin6_addr.s6_addr,
						  16, ni, sizeof(ni));
			lwsl_info("%s: %s ipv4->ipv6 %s\n", __func__,
				  ads ? ads : "(null)", ni);
			break;
		}
#endif
		sa46.sa4.sin_family = AF_INET;
		sa46.sa4.sin_addr.s_addr =
			((struct sockaddr_in *)wsi->dns_results_next->ai_addr)->
								sin_addr.s_addr;
		memset(&sa46.sa4.sin_zero, 0, sizeof(sa46.sa4.sin_zero));
		sa46.sa4.sin_port = htons(port);
		n = sizeof(struct sockaddr_in);
		lws_write_numeric_address((uint8_t *)&sa46.sa4.sin_addr.s_addr,
					  4, ni, sizeof(ni));
		lwsl_info("%s: %s ipv4 %s\n", __func__,
					ads ? ads : "(null)", ni);
		break;
	case AF_INET6:
#if defined(LWS_WITH_IPV6)
		if (!wsi->ipv6)
			goto try_next_result;
		sa46.sa4.sin_family = AF_INET6;
		memcpy(&sa46.sa6.sin6_addr,
		       &((struct sockaddr_in6 *)
				       wsi->dns_results_next->ai_addr)->
				       sin6_addr, sizeof(struct in6_addr));
		sa46.sa6.sin6_scope_id = ((struct sockaddr_in6 *)
				wsi->dns_results_next->ai_addr)->sin6_scope_id;
		sa46.sa6.sin6_flowinfo = ((struct sockaddr_in6 *)
				wsi->dns_results_next->ai_addr)->sin6_flowinfo;
		sa46.sa6.sin6_port = htons(port);
		lws_write_numeric_address((uint8_t *)&sa46.sa6.sin6_addr,
				16, ni, sizeof(ni));
		lwsl_info("%s: %s ipv6 %s\n", __func__,
				ads ? ads : "(null)", ni);
#else
		goto try_next_result;	/* ipv4 only can't use this */
#endif
		break;
	}

#if defined(LWS_WITH_UNIX_SOCK)
ads_known:
#endif

	/* now we decided on ipv4 or ipv6, set the port and create socket*/

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
			goto try_next_result;
		}

		if (lws_plat_set_socket_options(wsi->a.vhost, wsi->desc.sockfd,
#if defined(LWS_WITH_UNIX_SOCK)
						wsi->unix_skt)) {
#else
						0)) {
#endif
			lwsl_err("Failed to set wsi socket options\n");
			goto try_next_result_closesock;
		}

		lwsl_debug("%s: %p: WAITING_CONNECT\n", __func__, wsi);
		lwsi_set_state(wsi, LRS_WAITING_CONNECT);

		if (wsi->a.context->event_loop_ops->sock_accept)
			if (wsi->a.context->event_loop_ops->sock_accept(wsi))
				goto try_next_result_closesock;

		lws_pt_lock(pt, __func__);
		if (__insert_wsi_socket_into_fds(wsi->a.context, wsi)) {
			lws_pt_unlock(pt);
			goto try_next_result_closesock;
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
			goto try_next_result_fds;

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
				goto try_next_result_fds;
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
		goto try_next_result_fds;

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

	m = connect(wsi->desc.sockfd, (const struct sockaddr *)psa, n);
	if (m == -1) {
		int errno_copy = LWS_ERRNO;

		lwsl_debug("%s: connect says errno: %d\n", __func__,
								errno_copy);

		if (errno_copy && errno_copy != LWS_EALREADY &&
		    errno_copy != LWS_EINPROGRESS &&
		    errno_copy != LWS_EWOULDBLOCK
#ifdef _WIN32
			&& errno_copy != WSAEINVAL
                       && errno_copy != WSAEISCONN
#endif
		) {
#if defined(_DEBUG)
			char nads[48];
			lws_sa46_write_numeric_address(&sa46, nads,
								sizeof(nads));
			lwsl_info("%s: Connect failed: %s port %d\n",
				    __func__, nads, port);
#endif
			goto try_next_result_fds;
		}

#if defined(WIN32)
		if (lws_plat_check_connection_error(wsi))
			goto try_next_result_fds;
               if (errno_copy == WSAEISCONN)
                       goto conn_good;
#endif

		/*
		 * Let's set a specialized timeout for this connect attempt
		 * completion, it uses wsi->sul_connect_timeout just for this
		 * purpose
		 */

		lws_sul_schedule(wsi->a.context, 0, &wsi->sul_connect_timeout,
				 lws_client_conn_wait_timeout,
				 wsi->a.context->timeout_secs *
						 LWS_USEC_PER_SEC);

		/*
		 * must do specifically a POLLOUT poll to hear
		 * about the connect completion
		 */
#if !defined(WIN32)
		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT))
			goto try_next_result_fds;
#endif

		return wsi;
	}

conn_good:
	lws_sul_cancel(&wsi->sul_connect_timeout);
	lwsl_info("%s: Connection started %p\n", __func__, wsi->dns_results);

	/* the tcp connection has happend */

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

try_next_result_fds:
	__remove_wsi_socket_from_fds(wsi);

try_next_result_closesock:
	/*
	 * We are killing the socket but leaving
	 */
	compatible_close(wsi->desc.sockfd);
	wsi->desc.sockfd = LWS_SOCK_INVALID;

try_next_result:
	lws_sul_cancel(&wsi->sul_connect_timeout);
	if (wsi->dns_results_next) {
		wsi->dns_results_next = wsi->dns_results_next->ai_next;
		if (wsi->dns_results_next)
			goto next_result;
	}
	lws_addrinfo_clean(wsi);
	cce = "Unable to connect";

//failed:
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

failed1:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect2");

	return NULL;
}
