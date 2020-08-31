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

#if !defined(LWS_WITH_SYS_ASYNC_DNS)
static int
lws_getaddrinfo46(struct lws *wsi, const char *ads, struct addrinfo **result)
{
	struct addrinfo hints;
	int n;

	memset(&hints, 0, sizeof(hints));
	*result = NULL;

	hints.ai_socktype = SOCK_STREAM;

#ifdef LWS_WITH_IPV6
	if (wsi->ipv6) {

#if !defined(__ANDROID__)
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_V4MAPPED;
#endif
	} else
#endif
	{
		hints.ai_family = PF_UNSPEC;
	}

	n = getaddrinfo(ads, NULL, &hints, result);

	lwsl_info("%s: getaddrinfo '%s' says %d\n", __func__, ads, n);

	return n;
}
#endif

struct lws *
lws_client_connect_4_established(struct lws *wsi, struct lws *wsi_piggyback,
				 ssize_t plen)
{
#if defined(LWS_CLIENT_HTTP_PROXYING)
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
#endif
	const char *meth;
	struct lws_pollfd pfd;
	const char *cce = "";
	int n, m, rawish = 0;

	meth = lws_wsi_client_stash_item(wsi, CIS_METHOD,
					 _WSI_TOKEN_CLIENT_METHOD);

	if (meth && (!strcmp(meth, "RAW")
#if defined(LWS_ROLE_MQTT)
		     || !strcmp(meth, "MQTT")
#endif
	))
		rawish = 1;

	if (wsi_piggyback)
		goto send_hs;

#if defined(LWS_CLIENT_HTTP_PROXYING)
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	/* we are connected to server, or proxy */

	/* http proxy */
	if (wsi->a.vhost->http.http_proxy_port) {
		const char *cpa;

		cpa = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
						_WSI_TOKEN_CLIENT_PEER_ADDRESS);
		if (!cpa)
			goto failed;

		lwsl_info("%s: going via proxy\n", __func__);

		plen = lws_snprintf((char *)pt->serv_buf, 256,
			"CONNECT %s:%u HTTP/1.1\x0d\x0a"
			"Host: %s:%u\x0d\x0a"
			"User-agent: lws\x0d\x0a", cpa, wsi->ocport,
						   cpa, wsi->ocport);

#if defined(LWS_WITH_HTTP_BASIC_AUTH)
		if (wsi->a.vhost->proxy_basic_auth_token[0])
			plen += lws_snprintf((char *)pt->serv_buf + plen, 256,
					"Proxy-authorization: basic %s\x0d\x0a",
					wsi->a.vhost->proxy_basic_auth_token);
#endif

		plen += lws_snprintf((char *)pt->serv_buf + plen, 5, "\x0d\x0a");

		/* lwsl_hexdump_notice(pt->serv_buf, plen); */

		/*
		 * OK from now on we talk via the proxy, so connect to that
		 */
		if (wsi->stash)
			wsi->stash->cis[CIS_ADDRESS] =
				wsi->a.vhost->http.http_proxy_address;
		else
			if (lws_hdr_simple_create(wsi,
					_WSI_TOKEN_CLIENT_PEER_ADDRESS,
					  wsi->a.vhost->http.http_proxy_address))
			goto failed;
		wsi->c_port = wsi->a.vhost->http.http_proxy_port;

		n = send(wsi->desc.sockfd, (char *)pt->serv_buf, (int)plen,
			 MSG_NOSIGNAL);
		if (n < 0) {
			lwsl_debug("ERROR writing to proxy socket\n");
			cce = "proxy write failed";
			goto failed;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
				wsi->a.context->timeout_secs);

		lwsi_set_state(wsi, LRS_WAITING_PROXY_REPLY);

		return wsi;
	}
#endif
#endif

	/* coverity */
	if (!wsi->a.protocol)
		return NULL;

#if defined(LWS_WITH_SOCKS5)
	if (lwsi_state(wsi) != 	LRS_ESTABLISHED)
		switch (lws_socks5c_greet(wsi, &cce)) {
		case -1:
			goto failed;
		case 1:
			return wsi;
		default:
			break;
		}
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
send_hs:

	if (wsi_piggyback &&
	    !lws_dll2_is_detached(&wsi->dll2_cli_txn_queue)) {
		/*
		 * We are pipelining on an already-established connection...
		 * we can skip tls establishment.
		 *
		 * Set these queued guys to a state where they won't actually
		 * send their headers until we decide later.
		 */

		lwsi_set_state(wsi, LRS_H2_WAITING_TO_SEND_HEADERS);

		/*
		 * we can't send our headers directly, because they have to
		 * be sent when the parent is writeable.  The parent will check
		 * for anybody on his client transaction queue that is in
		 * LRS_H1C_ISSUE_HANDSHAKE2, and let them write.
		 *
		 * If we are trying to do this too early, before the master
		 * connection has written his own headers, then it will just
		 * wait in the queue until it's possible to send them.
		 */
		lws_callback_on_writable(wsi_piggyback);
#if defined(LWS_WITH_DETAILED_LATENCY)
		wsi->detlat.earliest_write_req =
			wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
#endif
		lwsl_info("%s: wsi %p: waiting to send hdrs (par state 0x%x)\n",
			    __func__, wsi, lwsi_state(wsi_piggyback));
	} else {
		lwsl_info("%s: wsi %p: %s %s client created own conn (raw %d) vh %sm st 0x%x\n",
			    __func__, wsi, wsi->role_ops->name,
			    wsi->a.protocol->name, rawish, wsi->a.vhost->name,
			    lwsi_state(wsi));

		/* we are making our own connection */

		if (!rawish) {
			if (lwsi_state(wsi) != LRS_H1C_ISSUE_HANDSHAKE2)
				lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE);
		} else {
			/* for a method = "RAW" connection, this makes us
			 * established */

#if defined(LWS_WITH_TLS) && !defined(LWS_WITH_MBEDTLS)

			/* we have connected if we got here */

			if (lwsi_state(wsi) == LRS_WAITING_CONNECT &&
			    (wsi->tls.use_ssl & LCCSCF_USE_SSL)) {
				int result;

				/*
				 * We can retry this... just cook the SSL BIO
				 * the first time
				 */

				result = lws_client_create_tls(wsi, &cce, 1);
				lwsl_debug("%s: create_tls said %d\n", __func__, result);
				switch (result) {
				case CCTLS_RETURN_DONE:
					break;
				case CCTLS_RETURN_RETRY:
					return wsi;
				default:
					goto failed;
				}

				/*
				 * We succeeded to negotiate a new client tls tunnel.
				 * If it's h2 alpn, we have arranged to send to h2
				 * prefix and set our state to
				 * LRS_H2_WAITING_TO_SEND_HEADERS already.
				 */

				lwsl_notice("%s: wsi %p: tls established st 0x%x\n",
					    __func__, wsi, lwsi_state(wsi));

				if (lwsi_state(wsi) != LRS_H2_WAITING_TO_SEND_HEADERS)
					lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);
				lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND,
						wsi->a.context->timeout_secs);

				goto provoke_service;
			}
#endif

			/* clear his established timeout */
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

			m = wsi->role_ops->adoption_cb[0];
			if (m) {
				n = user_callback_handle_rxflow(
						wsi->a.protocol->callback, wsi,
						m, wsi->user_space, NULL, 0);
				if (n < 0) {
					lwsl_info("LWS_CALLBACK_RAW_PROXY_CLI_ADOPT failed\n");
					goto failed;
				}
			}

			/* service.c pollout processing wants this */
			wsi->hdr_parsing_completed = 1;
#if defined(LWS_ROLE_MQTT)
			if (!strcmp(meth, "MQTT")) {
#if defined(LWS_WITH_TLS)
				if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
					lwsi_set_state(wsi, LRS_WAITING_SSL);
					return wsi;
				}
#endif
				lwsl_info("%s: settings LRS_MQTTC_IDLE\n",
					  __func__);
				lwsi_set_state(wsi, LRS_MQTTC_IDLE);

				/*
				 * provoke service to issue the CONNECT directly.
				 */
				lws_set_timeout(wsi, PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
						wsi->a.context->timeout_secs);

				assert(lws_socket_is_valid(wsi->desc.sockfd));

				pfd.fd = wsi->desc.sockfd;
				pfd.events = LWS_POLLIN;
				pfd.revents = LWS_POLLOUT;

				lwsl_info("%s: going to service fd\n", __func__);
				n = lws_service_fd(wsi->a.context, &pfd);
				if (n < 0) {
					cce = "first service failed";
					goto failed;
				}
				if (n) /* returns 1 on failure after closing wsi */
					return NULL;
				return wsi;
			}
#endif
			lwsl_info("%s: setting ESTABLISHED\n", __func__);
			lwsi_set_state(wsi, LRS_ESTABLISHED);

			return wsi;
		}

		/*
		 * provoke service to issue the handshake directly.
		 *
		 * we need to do it this way because in the proxy case, this is
		 * the next state and executed only if and when we get a good
		 * proxy response inside the state machine... but notice in
		 * SSL case this may not have sent anything yet with 0 return,
		 * and won't until many retries from main loop.  To stop that
		 * becoming endless, cover with a timeout.
		 */
#if defined(LWS_WITH_TLS) && !defined(LWS_WITH_MBEDTLS)
provoke_service:
#endif
		lws_set_timeout(wsi, PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
				wsi->a.context->timeout_secs);

		assert(lws_socket_is_valid(wsi->desc.sockfd));

		pfd.fd = wsi->desc.sockfd;
		pfd.events = LWS_POLLIN;
		pfd.revents = LWS_POLLIN;

		n = lws_service_fd(wsi->a.context, &pfd);
		if (n < 0) {
			cce = "first service failed";
			goto failed;
		}
		if (n) /* returns 1 on failure after closing wsi */
			return NULL;
	}
#endif
	return wsi;

failed:
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect2");

	return NULL;
}

void
lws_client_conn_wait_timeout(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_connect_timeout);

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
		    !wsi->sul_connect_timeout.list.owner /* no ongoing connect timeout */)
			goto connect_to;
#if defined(WIN32)
		if (!connect(wsi->desc.sockfd, NULL, 0)) {
			goto conn_good;
               } else {
			if (!LWS_ERRNO || LWS_ERRNO == WSAEINVAL ||
			    LWS_ERRNO == WSAEWOULDBLOCK || LWS_ERRNO == WSAEALREADY) {
				lwsl_info("%s: errno %d\n", __func__, errno);
				return NULL;
			}
			lwsl_info("%s: connect check take as FAILED\n", __func__);
		}
#else
		/*
		* this resets SO_ERROR after reading it.  If there's an error
		* condition the connect definitively failed.
		*/

		if (!getsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_ERROR,
				&e, &sl)) {
			if (!e) {
				lwsl_debug("%s: getsockopt check: conn OK errno %d\n",
					   __func__, errno);

				goto conn_good;
			}

			lwsl_debug("%s: getsockopt fd %d says err %d\n", __func__,
					wsi->desc.sockfd, e);
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
		lwsl_info("%s: %s ipv4 %s\n", __func__, ads ? ads : "(null)", ni);
		break;
	case AF_INET6:
#if defined(LWS_WITH_IPV6)
		if (!wsi->ipv6)
			goto try_next_result;
		sa46.sa4.sin_family = AF_INET6;
		memcpy(&sa46.sa6.sin6_addr,
		       &((struct sockaddr_in6 *)wsi->dns_results_next->ai_addr)->
				       sin6_addr, sizeof(struct in6_addr));
		sa46.sa6.sin6_scope_id = ((struct sockaddr_in6 *)
				wsi->dns_results_next->ai_addr)->sin6_scope_id;
		sa46.sa6.sin6_flowinfo = ((struct sockaddr_in6 *)
				wsi->dns_results_next->ai_addr)->sin6_flowinfo;
		sa46.sa6.sin6_port = htons(port);
		lws_write_numeric_address((uint8_t *)&sa46.sa6.sin6_addr,
				16, ni, sizeof(ni));
		lwsl_info("%s: %s ipv6 %s\n", __func__, ads ? ads : "(null)", ni);
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
		    wsi->a.context->event_loop_ops->check_client_connect_ok(wsi)) {
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
			n = (int)(sizeof(uint16_t) + strlen(&sau.sun_path[1]) + 1);
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
	m = connect(wsi->desc.sockfd, (const struct sockaddr *)psa, n);
	if (m == -1) {
		int errno_copy = LWS_ERRNO;

		lwsl_debug("%s: connect says errno: %d\n", __func__, errno_copy);

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
			lws_sa46_write_numeric_address(&sa46, nads, sizeof(nads));
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
				 wsi->a.context->timeout_secs * LWS_USEC_PER_SEC);

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

	if (lwsi_role_client(wsi) && wsi->a.protocol /* && lwsi_state_est(wsi) */)
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

struct lws *
lws_client_connect_2_dnsreq(struct lws *wsi)
{
	struct addrinfo *result = NULL;
	const char *meth = NULL, *ads;
#if defined(LWS_WITH_IPV6)
	struct sockaddr_in addr;
	const char *iface;
#endif
	const char *adsin;
	int n, port = 0;
	struct lws *w;

	if (lwsi_state(wsi) == LRS_WAITING_DNS ||
	    lwsi_state(wsi) == LRS_WAITING_CONNECT) {
		lwsl_info("%s: LRS_WAITING_DNS / CONNECT\n", __func__);

		return wsi;
	}

	/*
	 * The first job is figure out if we want to pipeline on or just join
	 * an existing "active connection" to the same place
	 */

	meth = lws_wsi_client_stash_item(wsi, CIS_METHOD,
					 _WSI_TOKEN_CLIENT_METHOD);

	/* we only pipeline connections that said it was okay */

	if (!wsi->client_pipeline) {
		lwsl_debug("%s: new conn on no pipeline flag\n", __func__);

		goto solo;
	}

	/* only pipeline things we associate with being a stream */

	if (meth && strcmp(meth, "RAW") && strcmp(meth, "GET") &&
		    strcmp(meth, "POST") && strcmp(meth, "PUT") &&
		    strcmp(meth, "UDP") && strcmp(meth, "MQTT"))
		goto solo;

	/* consult active connections to find out disposition */

	adsin = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
					  _WSI_TOKEN_CLIENT_PEER_ADDRESS);

	if (!adsin)
		/*
		 * This cannot happen since user code must provide the client
		 * address to get this far, it's here to satisfy Coverity
		 */
		return NULL;

	switch (lws_vhost_active_conns(wsi, &w, adsin)) {
	case ACTIVE_CONNS_SOLO:
		break;
	case ACTIVE_CONNS_MUXED:
		lwsl_notice("%s: ACTIVE_CONNS_MUXED\n", __func__);
		if (lwsi_role_h2(wsi)) {

			if (wsi->a.protocol->callback(wsi,
						    LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
						    wsi->user_space, NULL, 0))
				goto failed1;

			//lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);
			//lwsi_set_state(w, LRS_ESTABLISHED);
			lws_callback_on_writable(wsi);
		}

		return wsi;
	case ACTIVE_CONNS_QUEUED:
		lwsl_debug("%s: ACTIVE_CONNS_QUEUED st 0x%x: \n", __func__, lwsi_state(wsi));
		if (lwsi_state(wsi) == LRS_UNCONNECTED) {
			if (lwsi_role_h2(w))
				lwsi_set_state(wsi, LRS_H2_WAITING_TO_SEND_HEADERS);
			else
				lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);
		}

		return lws_client_connect_4_established(wsi, w, 0);
	}

solo:
	wsi->addrinfo_idx = 0;

	/*
	 * clients who will create their own fresh connection keep a copy of
	 * the hostname they originally connected to, in case other connections
	 * want to use it too
	 */

	if (!wsi->cli_hostname_copy) {
		if (wsi->stash && wsi->stash->cis[CIS_HOST])
			wsi->cli_hostname_copy =
					lws_strdup(wsi->stash->cis[CIS_HOST]);
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		else {
			char *pa = lws_hdr_simple_ptr(wsi,
					      _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			if (pa)
				wsi->cli_hostname_copy = lws_strdup(pa);
		}
#endif
	}

	/*
	 * If we made our own connection, and we're doing a method that can
	 * take a pipeline, we are an "active client connection".
	 *
	 * Add ourselves to the vhost list of those so that others can
	 * piggyback on our transaction queue
	 */

	if (meth && (!strcmp(meth, "RAW") || !strcmp(meth, "GET") ||
		     !strcmp(meth, "POST") || !strcmp(meth, "PUT") ||
		     !strcmp(meth, "MQTT")) &&
	    lws_dll2_is_detached(&wsi->dll2_cli_txn_queue) &&
	    lws_dll2_is_detached(&wsi->dll_cli_active_conns)) {
		lws_vhost_lock(wsi->a.vhost);
		lwsl_info("%s: adding active conn %p\n", __func__, wsi);
		/* caution... we will have to unpick this on oom4 path */
		lws_dll2_add_head(&wsi->dll_cli_active_conns,
				 &wsi->a.vhost->dll_cli_active_conns_owner);
		lws_vhost_unlock(wsi->a.vhost);
	}

	/*
	 * unix socket destination?
	 */

	if (wsi->stash)
		ads = wsi->stash->cis[CIS_ADDRESS];
	else
		ads = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS);

	/*
	 * Since address must be given at client creation, should not be
	 * possible, but necessary to satisfy coverity
	 */
	if (!ads)
		return NULL;

#if defined(LWS_WITH_UNIX_SOCK)
	if (*ads == '+') {
		wsi->unix_skt = 1;
		n = 0;
		goto next_step;
	}
#endif

	/*
	 * start off allowing ipv6 on connection if vhost allows it
	 */
	wsi->ipv6 = LWS_IPV6_ENABLED(wsi->a.vhost);
#ifdef LWS_WITH_IPV6
	if (wsi->stash)
		iface = wsi->stash->cis[CIS_IFACE];
	else
		iface = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_IFACE);

	if (wsi->ipv6 && iface &&
	    inet_pton(AF_INET, iface, &addr.sin_addr) == 1) {
		lwsl_notice("%s: client connection forced to IPv4\n", __func__);
		wsi->ipv6 = 0;
	}
#endif

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
		ads = wsi->a.vhost->http.http_proxy_address;
		port = wsi->a.vhost->http.http_proxy_port;
#else
		if (0) {
#endif

#if defined(LWS_WITH_SOCKS5)

	/* Priority 2: Connect to SOCK5 Proxy */

	} else if (wsi->a.vhost->socks_proxy_port) {
		lwsl_client("Sending SOCKS Greeting\n");
		ads = wsi->a.vhost->socks_proxy_address;
		port = wsi->a.vhost->socks_proxy_port;
#endif
	} else {

		/* Priority 3: Connect directly */

		/* ads already set */
		port = wsi->c_port;
	}

	/*
	 * prepare the actual connection
	 * to whatever we decided to connect to
	 */
	lwsi_set_state(wsi, LRS_WAITING_DNS);

	lwsl_info("%s: %p: lookup %s:%u\n", __func__, wsi, ads, port);
	(void)port;

#if defined(LWS_WITH_DETAILED_LATENCY)
	wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
#endif
#if !defined(LWS_WITH_SYS_ASYNC_DNS)
	if (wsi->dns_results)
		n = 0;
	else
		n = lws_getaddrinfo46(wsi, ads, &result);
#else
	lwsi_set_state(wsi, LRS_WAITING_DNS);
	/* this is either FAILED, CONTINUING, or already called connect_4 */

	n = lws_async_dns_query(wsi->a.context, wsi->tsi, ads, LWS_ADNS_RECORD_A,
				lws_client_connect_3_connect, wsi, NULL);
	if (n == LADNS_RET_FAILED_WSI_CLOSED)
		return NULL;

	if (n == LADNS_RET_FAILED)
		goto failed1;

	return wsi;
#endif

#if defined(LWS_WITH_UNIX_SOCK)
next_step:
#endif
	return lws_client_connect_3_connect(wsi, ads, result, n, NULL);

//#if defined(LWS_WITH_SYS_ASYNC_DNS)
failed1:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect2");

	return NULL;
//#endif
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)

static uint8_t hnames2[] = {
	_WSI_TOKEN_CLIENT_ORIGIN,
	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	_WSI_TOKEN_CLIENT_METHOD,
	_WSI_TOKEN_CLIENT_IFACE,
	_WSI_TOKEN_CLIENT_ALPN
};

/**
 * lws_client_reset() - retarget a connected wsi to start over with a new
 * 			connection (ie, redirect)
 *			this only works if still in HTTP, ie, not upgraded yet
 * wsi:		connection to reset
 * address:	network address of the new server
 * port:	port to connect to
 * path:	uri path to connect to on the new server
 * host:	host header to send to the new server
 */
struct lws *
lws_client_reset(struct lws **pwsi, int ssl, const char *address, int port,
		 const char *path, const char *host, char weak)
{
#if defined(LWS_ROLE_WS)
	struct _lws_websocket_related *ws;
#endif
	char *stash, *p;
	struct lws *wsi;
	size_t size = 0;
	int n;

	if (!pwsi)
		return NULL;

	wsi = *pwsi;

	lwsl_debug("%s: wsi %p: redir %d: %s\n", __func__, wsi, wsi->redirects,
			address);

	if (wsi->redirects == 3) {
		lwsl_err("%s: Too many redirects\n", __func__);
		return NULL;
	}
	wsi->redirects++;

	/*
	 * goal is to close our role part, close the sockfd, detach the ah
	 * but leave our wsi extant and still bound to whatever vhost it was
	 */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(hnames2); n++)
		size += lws_hdr_total_length(wsi, hnames2[n]) + (size_t)1;

	if (size < (size_t)lws_hdr_total_length(wsi, _WSI_TOKEN_CLIENT_URI) + 1)
		size = lws_hdr_total_length(wsi, _WSI_TOKEN_CLIENT_URI) + (size_t)1;

	/*
	 * The incoming address and host can be from inside the existing ah
	 * we are going to detach and reattch
	 */

	size += strlen(path) + 1 + strlen(address) + 1 + strlen(host) + 1 + 1;

	p = stash = lws_malloc(size, __func__);
	if (!stash)
		return NULL;

	/*
	 * _WSI_TOKEN_CLIENT_ORIGIN,
	 * _WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	 * _WSI_TOKEN_CLIENT_METHOD,
	 * _WSI_TOKEN_CLIENT_IFACE,
	 * _WSI_TOKEN_CLIENT_ALPN
	 * address
	 * host
	 * path
	 */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(hnames2); n++)
		if (lws_hdr_total_length(wsi, hnames2[n]) &&
		    lws_hdr_simple_ptr(wsi, hnames2[n])) {
			memcpy(p, lws_hdr_simple_ptr(wsi, hnames2[n]), (size_t)(
			       lws_hdr_total_length(wsi, hnames2[n]) + 1));
			p += (size_t)(lws_hdr_total_length(wsi, hnames2[n]) + 1);
		} else
			*p++ = '\0';

	memcpy(p, address, strlen(address) + (size_t)1);
	address = p;
	p += strlen(address) + 1;
	memcpy(p, host, strlen(host) + (size_t)1);
	host = p;
	p += strlen(host) + 1;
	memcpy(p, path, strlen(path) + (size_t)1);
	path = p;

	if (!port) {
		lwsl_info("%s: forcing port 443\n", __func__);

		port = 443;
		ssl = 1;
	}

	lwsl_info("redirect ads='%s', port=%d, path='%s', ssl = %d, pifds %d\n",
		   address, port, path, ssl, wsi->position_in_fds_table);

	__remove_wsi_socket_from_fds(wsi);
#if defined(LWS_ROLE_WS)
	if (weak) {
		ws = wsi->ws;
		wsi->ws = NULL;
	}
#endif
	__lws_reset_wsi(wsi); /* detaches ah here */
#if defined(LWS_ROLE_WS)
	if (weak)
		wsi->ws = ws;
#endif
	wsi->client_pipeline = 1;

	/* close the connection by hand */

#if defined(LWS_WITH_TLS)
	lws_ssl_close(wsi);
#endif

	if (wsi->role_ops && wsi->role_ops->close_kill_connection)
		wsi->role_ops->close_kill_connection(wsi, 1);

	if (wsi->a.context->event_loop_ops->close_handle_manually)
		wsi->a.context->event_loop_ops->close_handle_manually(wsi);
	else
		if (wsi->desc.sockfd != LWS_SOCK_INVALID)
			compatible_close(wsi->desc.sockfd);

#if defined(LWS_WITH_TLS)
	if (!ssl)
		wsi->tls.use_ssl &= ~LCCSCF_USE_SSL;
	else
		wsi->tls.use_ssl |= LCCSCF_USE_SSL;
#else
	if (ssl) {
		lwsl_err("%s: not configured for ssl\n", __func__);
		goto bail;
	}
#endif

	if (wsi->a.protocol && wsi->role_ops && wsi->protocol_bind_balance) {
		wsi->a.protocol->callback(wsi,
				wsi->role_ops->protocol_unbind_cb[
				       !!lwsi_role_server(wsi)],
				       wsi->user_space, (void *)__func__, 0);

		wsi->protocol_bind_balance = 0;
	}

	wsi->desc.sockfd = LWS_SOCK_INVALID;
	lws_role_transition(wsi, LWSIFR_CLIENT, LRS_UNCONNECTED, &role_ops_h1);
//	wsi->a.protocol = NULL;
	if (wsi->a.protocol)
		lws_bind_protocol(wsi, wsi->a.protocol, "client_reset");
	wsi->pending_timeout = NO_PENDING_TIMEOUT;
	wsi->c_port = port;
	wsi->hdr_parsing_completed = 0;

	if (lws_header_table_attach(wsi, 0)) {
		lwsl_err("%s: failed to get ah\n", __func__);
		goto bail;
	}
	//_lws_header_table_reset(wsi->http.ah);

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS, address))
		goto bail;

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_HOST, host))
		goto bail;

	/*
	 * _WSI_TOKEN_CLIENT_ORIGIN,
	 * _WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	 * _WSI_TOKEN_CLIENT_METHOD,
	 * _WSI_TOKEN_CLIENT_IFACE,
	 * _WSI_TOKEN_CLIENT_ALPN
	 * address
	 * host
	 * path
	 */

	p = stash;
	for (n = 0; n < (int)LWS_ARRAY_SIZE(hnames2); n++) {
		if (lws_hdr_simple_create(wsi, hnames2[n], p))
			goto bail;
		p += lws_hdr_total_length(wsi, hnames2[n]) + (size_t)1;
	}

	stash[0] = '/';
	memmove(&stash[1], path, size - 1 < strlen(path) + 1 ?
					size - 1 : strlen(path) + (size_t)1);
	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_URI, stash))
		goto bail;

	lws_free_set_NULL(stash);

#if defined(LWS_WITH_HTTP2)
	if (wsi->client_mux_substream)
		wsi->h2.END_STREAM = wsi->h2.END_HEADERS = 0;
#endif

	*pwsi = lws_client_connect_2_dnsreq(wsi);

	return *pwsi;

bail:
	lws_free_set_NULL(stash);

	return NULL;
}

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_WITH_HUBBUB)
hubbub_error
html_parser_cb(const hubbub_token *token, void *pw)
{
	struct lws_rewrite *r = (struct lws_rewrite *)pw;
	char buf[1024], *start = buf + LWS_PRE, *p = start,
	     *end = &buf[sizeof(buf) - 1], dotstar[128];
	size_t i;

	switch (token->type) {
	case HUBBUB_TOKEN_DOCTYPE:

		lws_strnncpy(dotstar, token->data.doctype.name.ptr,
			     token->data.doctype.name.len, sizeof(dotstar));

		p += lws_snprintf(p, end - p, "<!DOCTYPE %s %s ",
				  dotstar, token->data.doctype.force_quirks ?
						"(force-quirks) " : "");

		if (token->data.doctype.public_missing)
			lwsl_debug("\tpublic: missing\n");
		else {
			lws_strnncpy(dotstar, token->data.doctype.public_id.ptr,
				     token->data.doctype.public_id.len,
				     sizeof(dotstar));
			p += lws_snprintf(p, end - p, "PUBLIC \"%s\"\n",
					  dotstar);
		}

		if (token->data.doctype.system_missing)
			lwsl_debug("\tsystem: missing\n");
		else {
			lws_strnncpy(dotstar, token->data.doctype.system_id.ptr,
				     token->data.doctype.system_id.len,
				     sizeof(dotstar));
			p += lws_snprintf(p, end - p, " \"%s\">\n", dotstar);
		}

		break;
	case HUBBUB_TOKEN_START_TAG:
		lws_strnncpy(dotstar, token->data.tag.name.ptr,
			     token->data.tag.name.len, sizeof(dotstar));
		p += lws_snprintf(p, end - p, "<%s", dotstar);

/*				(token->data.tag.self_closing) ?
						"(self-closing) " : "",
				(token->data.tag.n_attributes > 0) ?
						"attributes:" : "");
*/
		for (i = 0; i < token->data.tag.n_attributes; i++) {
			if (!hstrcmp(&token->data.tag.attributes[i].name, "href", 4) ||
			    !hstrcmp(&token->data.tag.attributes[i].name, "action", 6) ||
			    !hstrcmp(&token->data.tag.attributes[i].name, "src", 3)) {
				const char *pp = (const char *)token->data.tag.attributes[i].value.ptr;
				int plen = (int) token->data.tag.attributes[i].value.len;

				if (strncmp(pp, "http:", 5) && strncmp(pp, "https:", 6)) {

					if (!hstrcmp(&token->data.tag.attributes[i].value,
						     r->from, r->from_len)) {
						pp += r->from_len;
						plen -= r->from_len;
					}
					lws_strnncpy(dotstar,
						token->data.tag.attributes[i].name.ptr,
						token->data.tag.attributes[i].name.len,
						sizeof(dotstar));

					p += lws_snprintf(p, end - p, " %s=\"%s",
							  dotstar, r->to);
					lws_strnncpy(dotstar, pp, plen, sizeof(dotstar));
					p += lws_snprintf(p, end - p, " /%s\"", dotstar);
					continue;
				}
			}

			lws_strnncpy(dotstar,
				token->data.tag.attributes[i].name.ptr,
				token->data.tag.attributes[i].name.len,
				sizeof(dotstar));

			p += lws_snprintf(p, end - p, " %s=\"", dotstar);
			lws_strnncpy(dotstar,
				token->data.tag.attributes[i].value.ptr,
				token->data.tag.attributes[i].value.len,
				sizeof(dotstar));
			p += lws_snprintf(p, end - p, "%s\"", dotstar);
		}
		p += lws_snprintf(p, end - p, ">");
		break;
	case HUBBUB_TOKEN_END_TAG:
		lws_strnncpy(dotstar, token->data.tag.name.ptr,
			     token->data.tag.name.len, sizeof(dotstar));
		p += lws_snprintf(p, end - p, "</%s", dotstar);
/*
				(token->data.tag.self_closing) ?
						"(self-closing) " : "",
				(token->data.tag.n_attributes > 0) ?
						"attributes:" : "");
*/
		for (i = 0; i < token->data.tag.n_attributes; i++) {
			lws_strnncpy(dotstar,
				     token->data.tag.attributes[i].name.ptr,
				     token->data.tag.attributes[i].name.len,
				     sizeof(dotstar));
			p += lws_snprintf(p, end - p, " %s='", dotstar);
			lws_strnncpy(dotstar,
				     token->data.tag.attributes[i].value.ptr,
				     token->data.tag.attributes[i].value.len,
				     sizeof(dotstar));
			p += lws_snprintf(p, end - p, "%s'\n", dotstar);
		}
		p += lws_snprintf(p, end - p, ">");
		break;
	case HUBBUB_TOKEN_COMMENT:
		lws_strnncpy(dotstar, token->data.comment.ptr,
			     token->data.comment.len, sizeof(dotstar));
		p += lws_snprintf(p, end - p, "<!-- %s -->\n",  dotstar);
		break;
	case HUBBUB_TOKEN_CHARACTER:
		if (token->data.character.len == 1) {
			if (*token->data.character.ptr == '<') {
				p += lws_snprintf(p, end - p, "&lt;");
				break;
			}
			if (*token->data.character.ptr == '>') {
				p += lws_snprintf(p, end - p, "&gt;");
				break;
			}
			if (*token->data.character.ptr == '&') {
				p += lws_snprintf(p, end - p, "&amp;");
				break;
			}
		}
		lws_strnncpy(dotstar, token->data.character.ptr,
			     token->data.character.len, sizeof(dotstar));
		p += lws_snprintf(p, end - p, "%s", dotstar);
		break;
	case HUBBUB_TOKEN_EOF:
		p += lws_snprintf(p, end - p, "\n");
		break;
	}

	if (r->wsi->a.protocol_bind_balance &&
	    user_callback_handle_rxflow(r->wsi->a.protocol->callback,
			r->wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
			r->wsi->user_space, start, p - start))
		return -1;

	return HUBBUB_OK;
}
#endif

#endif

static const uint8_t hnames[] = {
	_WSI_TOKEN_CLIENT_PEER_ADDRESS,
	_WSI_TOKEN_CLIENT_URI,
	_WSI_TOKEN_CLIENT_HOST,
	_WSI_TOKEN_CLIENT_ORIGIN,
	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	_WSI_TOKEN_CLIENT_METHOD,
	_WSI_TOKEN_CLIENT_IFACE,
	_WSI_TOKEN_CLIENT_ALPN
};

struct lws *
lws_http_client_connect_via_info2(struct lws *wsi)
{
	struct client_info_stash *stash = wsi->stash;
	int n;

	lwsl_debug("%s: %p (stash %p)\n", __func__, wsi, stash);

	if (!stash)
		return wsi;

	wsi->a.opaque_user_data = wsi->stash->opaque_user_data;

	if (stash->cis[CIS_METHOD] && (!strcmp(stash->cis[CIS_METHOD], "RAW") ||
				      !strcmp(stash->cis[CIS_METHOD], "MQTT")))
		goto no_ah;

	/*
	 * we're not necessarily in a position to action these right away,
	 * stash them... we only need during connect phase so into a temp
	 * allocated stash
	 */
	for (n = 0; n < (int)LWS_ARRAY_SIZE(hnames); n++)
		if (hnames[n] && stash->cis[n]) {
			if (lws_hdr_simple_create(wsi, hnames[n], stash->cis[n]))
				goto bail1;
		}

#if defined(LWS_WITH_SOCKS5)
	if (!wsi->a.vhost->socks_proxy_port)
		lws_free_set_NULL(wsi->stash);
#endif

no_ah:
	wsi->a.context->count_wsi_allocated++;

	return lws_client_connect_2_dnsreq(wsi);

bail1:
#if defined(LWS_WITH_SOCKS5)
	if (!wsi->a.vhost->socks_proxy_port)
		lws_free_set_NULL(wsi->stash);
#endif

	return NULL;
}
