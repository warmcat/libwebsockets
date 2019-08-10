#include "core/private.h"

static int
lws_getaddrinfo46(struct lws *wsi, const char *ads, struct addrinfo **result)
{
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	*result = NULL;

#ifdef LWS_WITH_IPV6
	if (wsi->ipv6) {

#if !defined(__ANDROID__)
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_V4MAPPED;
#endif
	} else
#endif
	{
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
	}

	return getaddrinfo(ads, NULL, &hints, result);
}


struct lws *
lws_client_connect_3(struct lws *wsi, struct lws *wsi_piggyback, ssize_t plen)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	const char *meth = NULL;
	struct lws_pollfd pfd;
	const char *cce = "";
	int n, m, rawish = 0;

	if (wsi->stash)
		meth = wsi->stash->method;
	else
		meth = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);

	if (meth && !strcmp(meth, "RAW"))
		rawish = 1;

	if (wsi_piggyback)
		goto send_hs;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	/* we are connected to server, or proxy */

	/* http proxy */
	if (wsi->vhost->http.http_proxy_port) {

		/*
		 * OK from now on we talk via the proxy, so connect to that
		 *
		 * (will overwrite existing pointer,
		 * leaving old string/frag there but unreferenced)
		 */
		if (wsi->stash) {
			lws_free(wsi->stash->address);
			wsi->stash->address =
				lws_strdup(wsi->vhost->http.http_proxy_address);
			if (!wsi->stash->address)
				goto failed;
		} else
			if (lws_hdr_simple_create(wsi,
					_WSI_TOKEN_CLIENT_PEER_ADDRESS,
					  wsi->vhost->http.http_proxy_address))
			goto failed;
		wsi->c_port = wsi->vhost->http.http_proxy_port;

		n = send(wsi->desc.sockfd, (char *)pt->serv_buf, (int)plen,
			 MSG_NOSIGNAL);
		if (n < 0) {
			lwsl_debug("ERROR writing to proxy socket\n");
			cce = "proxy write failed";
			goto failed;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
				AWAITING_TIMEOUT);

		lwsi_set_state(wsi, LRS_WAITING_PROXY_REPLY);

		return wsi;
	}
#endif
#if defined(LWS_WITH_SOCKS5)
	/* socks proxy */
	else if (wsi->vhost->socks_proxy_port) {
		n = send(wsi->desc.sockfd, (char *)pt->serv_buf, plen,
			 MSG_NOSIGNAL);
		if (n < 0) {
			lwsl_debug("ERROR writing socks greeting\n");
			cce = "socks write failed";
			goto failed;
		}

		lws_set_timeout(wsi,
				PENDING_TIMEOUT_AWAITING_SOCKS_GREETING_REPLY,
				AWAITING_TIMEOUT);

		lwsi_set_state(wsi, LRS_WAITING_SOCKS_GREETING_REPLY);

		return wsi;
	}
#endif
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
send_hs:

	if (wsi_piggyback &&
	    !lws_dll2_is_detached(&wsi->dll2_cli_txn_queue)) {
		/*
		 * We are pipelining on an already-established connection...
		 * we can skip tls establishment.
		 */

		lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);

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
		lwsl_info("%s: wsi %p: waiting to send hdrs (par state 0x%x)\n",
			    __func__, wsi, lwsi_state(wsi_piggyback));
	} else {
		lwsl_info("%s: wsi %p: %s %s client created own conn (raw %d)\n",
			    __func__, wsi, wsi->role_ops->name,
			    wsi->protocol->name, rawish);

		/* we are making our own connection */
		if (!rawish)
			lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE);
		else {
			/* for a method = "RAW" connection, this makes us
			 * established */

			/* clear his established timeout */
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

			m = wsi->role_ops->adoption_cb[0];
			if (m) {
				n = user_callback_handle_rxflow(
						wsi->protocol->callback, wsi,
						m, wsi->user_space, NULL, 0);
				if (n < 0) {
					lwsl_info("LWS_CALLBACK_RAW_PROXY_CLI_ADOPT failed\n");
					goto failed;
				}
			}

			/* service.c pollout processing wants this */
			wsi->hdr_parsing_completed = 1;
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

		lws_set_timeout(wsi, PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
				AWAITING_TIMEOUT);

		assert(lws_socket_is_valid(wsi->desc.sockfd));

		pfd.fd = wsi->desc.sockfd;
		pfd.events = LWS_POLLIN;
		pfd.revents = LWS_POLLIN;

		n = lws_service_fd(wsi->context, &pfd);
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

struct lws *
lws_client_connect_2(struct lws *wsi)
{
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	const char *adsin;
	ssize_t plen = 0;
#endif
#if defined(LWS_WITH_UNIX_SOCK)
	struct sockaddr_un sau;
	char unix_skt = 0;
#endif
	int n, port = 0;
	const char *cce = "", *iface;
	const struct sockaddr *psa;
	const char *meth = NULL;
	struct addrinfo *result;
	const char *ads;
	sockaddr46 sa46;

#ifdef LWS_WITH_IPV6
	char ipv6only = lws_check_opt(wsi->vhost->options,
			LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
			LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE);
	struct sockaddr_in addr;
#if defined(__ANDROID__)
	ipv6only = 0;
#endif
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (!wsi->http.ah && !wsi->stash) {
		cce = "ah was NULL at cc2";
		lwsl_err("%s\n", cce);
		goto oom4;
	}

	/* we can only piggyback GET or POST */

	if (wsi->stash)
		meth = wsi->stash->method;
	else
		meth = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);

	if (meth && strcmp(meth, "GET") && strcmp(meth, "POST"))
		goto create_new_conn;

	/* we only pipeline connections that said it was okay */

	if (!wsi->client_pipeline)
		goto create_new_conn;

	/*
	 * let's take a look first and see if there are any already-active
	 * client connections we can piggy-back on.
	 */

	adsin = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS);

	lws_vhost_lock(wsi->vhost); /* ----------------------------------- { */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&wsi->vhost->dll_cli_active_conns_owner)) {
		struct lws *w = lws_container_of(d, struct lws,
						 dll_cli_active_conns);

		lwsl_debug("%s: check %s %s %d %d\n", __func__, adsin,
			   w->cli_hostname_copy, wsi->c_port, w->c_port);

		if (w != wsi && w->cli_hostname_copy &&
		    !strcmp(adsin, w->cli_hostname_copy) &&
#if defined(LWS_WITH_TLS)
		    (wsi->tls.use_ssl & LCCSCF_USE_SSL) ==
		     (w->tls.use_ssl & LCCSCF_USE_SSL) &&
#endif
		    wsi->c_port == w->c_port) {

			/* someone else is already connected to the right guy */

			/* do we know for a fact pipelining won't fly? */
			if (w->keepalive_rejected) {
				lwsl_info("defeating pipelining due to no "
					    "keepalive on server\n");
				lws_vhost_unlock(wsi->vhost); /* } ---------- */
				goto create_new_conn;
			}
#if defined (LWS_WITH_HTTP2)
			/*
			 * h2: in usable state already: just use it without
			 *     going through the queue
			 */
			if (w->client_h2_alpn &&
			    (lwsi_state(w) == LRS_H2_WAITING_TO_SEND_HEADERS ||
			     lwsi_state(w) == LRS_ESTABLISHED)) {

				lwsl_info("%s: just join h2 directly\n",
						__func__);

				wsi->client_h2_alpn = 1;
				lws_wsi_h2_adopt(w, wsi);
				lws_vhost_unlock(wsi->vhost); /* } ---------- */

				return wsi;
			}
#endif

			lwsl_info("apply %p to txn queue on %p state 0x%lx\n",
				  wsi, w, (unsigned long)w->wsistate);
			/*
			 * ...let's add ourselves to his transaction queue...
			 * we are adding ourselves at the HEAD
			 */
			lws_dll2_add_head(&wsi->dll2_cli_txn_queue,
					  &w->dll2_cli_txn_queue_owner);

			/*
			 * h1: pipeline our headers out on him,
			 * and wait for our turn at client transaction_complete
			 * to take over parsing the rx.
			 */
			lws_vhost_unlock(wsi->vhost); /* } ---------- */
			return lws_client_connect_3(wsi, w, plen);
		}

	} lws_end_foreach_dll_safe(d, d1);

	lws_vhost_unlock(wsi->vhost); /* } ---------------------------------- */

create_new_conn:
#endif

	/*
	 * clients who will create their own fresh connection keep a copy of
	 * the hostname they originally connected to, in case other connections
	 * want to use it too
	 */

	if (!wsi->cli_hostname_copy) {
		if (wsi->stash)
			wsi->cli_hostname_copy = lws_strdup(wsi->stash->host);
		else {
			char *pa = lws_hdr_simple_ptr(wsi,
					      _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			if (pa)
				wsi->cli_hostname_copy = lws_strdup(pa);
		}
	}

	/*
	 * If we made our own connection, and we're doing a method that can take
	 * a pipeline, we are an "active client connection".
	 *
	 * Add ourselves to the vhost list of those so that others can
	 * piggyback on our transaction queue
	 */

	if (meth && (!strcmp(meth, "GET") || !strcmp(meth, "POST")) &&
	    lws_dll2_is_detached(&wsi->dll2_cli_txn_queue) &&
	    lws_dll2_is_detached(&wsi->dll_cli_active_conns)) {
		lws_vhost_lock(wsi->vhost);
		/* caution... we will have to unpick this on oom4 path */
		lws_dll2_add_head(&wsi->dll_cli_active_conns,
				 &wsi->vhost->dll_cli_active_conns_owner);
		lws_vhost_unlock(wsi->vhost);
	}

	/*
	 * unix socket destination?
	 */

	if (wsi->stash)
		ads = wsi->stash->address;
	else
		ads = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS);
#if defined(LWS_WITH_UNIX_SOCK)
	if (*ads == '+') {
		ads++;
		memset(&sau, 0, sizeof(sau));
		sau.sun_family = AF_UNIX;
		strncpy(sau.sun_path, ads, sizeof(sau.sun_path));
		sau.sun_path[sizeof(sau.sun_path) - 1] = '\0';

		lwsl_info("%s: Unix skt: %s\n", __func__, ads);

		if (sau.sun_path[0] == '@')
			sau.sun_path[0] = '\0';

		unix_skt = 1;
		goto ads_known;
	}
#endif

	/*
	 * start off allowing ipv6 on connection if vhost allows it
	 */
	wsi->ipv6 = LWS_IPV6_ENABLED(wsi->vhost);
#ifdef LWS_WITH_IPV6
	if (wsi->stash)
		iface = wsi->stash->iface;
	else
		iface = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_IFACE);

	if (wsi->ipv6 && iface &&
	    inet_pton(AF_INET, iface, &addr.sin_addr) == 1) {
		lwsl_notice("%s: client connection forced to IPv4\n", __func__);
		wsi->ipv6 = 0;
	}
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)

	/* Decide what it is we need to connect to:
	 *
	 * Priority 1: connect to http proxy */

	if (wsi->vhost->http.http_proxy_port) {
		plen = lws_snprintf((char *)pt->serv_buf, 256,
			"CONNECT %s:%u HTTP/1.0\x0d\x0a"
			"User-agent: libwebsockets\x0d\x0a",
			ads, wsi->c_port);

		if (wsi->vhost->proxy_basic_auth_token[0])
			plen += lws_snprintf((char *)pt->serv_buf + plen, 256,
					"Proxy-authorization: basic %s\x0d\x0a",
					wsi->vhost->proxy_basic_auth_token);

		plen += lws_snprintf((char *)pt->serv_buf + plen, 5, "\x0d\x0a");
		ads = wsi->vhost->http.http_proxy_address;
		port = wsi->vhost->http.http_proxy_port;
#else
		if (0) {
#endif

#if defined(LWS_WITH_SOCKS5)

	/* Priority 2: Connect to SOCK5 Proxy */

	} else if (wsi->vhost->socks_proxy_port) {
		if (socks_generate_msg(wsi, SOCKS_MSG_GREETING, &plen)) {
			cce = "socks msg too large";
			goto oom4;
		}

		lwsl_client("Sending SOCKS Greeting\n");
		ads = wsi->vhost->socks_proxy_address;
		port = wsi->vhost->socks_proxy_port;
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

       lwsl_info("%s: %p: address %s:%u\n", __func__, wsi, ads, port);

       n = lws_getaddrinfo46(wsi, ads, &result);
	memset(&sa46, 0, sizeof(sa46));
#ifdef LWS_WITH_IPV6
	if (wsi->ipv6) {
		struct sockaddr_in6 *sa6;

		if (n || !result) {
			/* lws_getaddrinfo46 failed, there is no usable result */
			lwsl_notice("%s: lws_getaddrinfo46 failed %d\n",
					__func__, n);
			cce = "ipv6 lws_getaddrinfo46 failed";
			goto oom4;
		}

		sa6 = ((struct sockaddr_in6 *)result->ai_addr);
		sa46.sa6.sin6_family = AF_INET6;
		switch (result->ai_family) {
		case AF_INET:
			if (ipv6only)
				break;
			/* map IPv4 to IPv6 */
			memset((char *)&sa46.sa6.sin6_addr, 0,
						sizeof(sa46.sa6.sin6_addr));
			sa46.sa6.sin6_addr.s6_addr[10] = 0xff;
			sa46.sa6.sin6_addr.s6_addr[11] = 0xff;
			memcpy(&sa46.sa6.sin6_addr.s6_addr[12],
				&((struct sockaddr_in *)result->ai_addr)->sin_addr,
							sizeof(struct in_addr));
			lwsl_notice("uplevelling AF_INET to AF_INET6\n");
			break;

		case AF_INET6:
			memcpy(&sa46.sa6.sin6_addr, &sa6->sin6_addr,
						sizeof(struct in6_addr));
			sa46.sa6.sin6_scope_id = sa6->sin6_scope_id;
			sa46.sa6.sin6_flowinfo = sa6->sin6_flowinfo;
			break;
		default:
			lwsl_err("Unknown address family\n");
			freeaddrinfo(result);
			cce = "unknown address family";
			goto oom4;
		}
	} else
#endif /* use ipv6 */

	/* use ipv4 */
	{
		void *p = NULL;

		if (!n) {
			struct addrinfo *res = result;

			/* pick the first AF_INET (IPv4) result */

			while (!p && res) {
				switch (res->ai_family) {
				case AF_INET:
					p = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
					break;
				}

				res = res->ai_next;
			}
#if defined(LWS_FALLBACK_GETHOSTBYNAME)
		} else if (n == EAI_SYSTEM) {
			struct hostent *host;

			lwsl_info("ipv4 getaddrinfo err, try gethostbyname\n");
			host = gethostbyname(ads);
			if (host) {
				p = host->h_addr;
			} else {
				lwsl_err("gethostbyname failed\n");
				cce = "gethostbyname (ipv4) failed";
				goto oom4;
			}
#endif
		} else {
			lwsl_err("getaddrinfo failed: %d\n", n);
			cce = "getaddrinfo failed";
			goto oom4;
		}

		if (!p) {
			if (result)
				freeaddrinfo(result);
			lwsl_err("Couldn't identify address\n");
			cce = "unable to lookup address";
			goto oom4;
		}

		sa46.sa4.sin_family = AF_INET;
		sa46.sa4.sin_addr = *((struct in_addr *)p);
		memset(&sa46.sa4.sin_zero, 0, sizeof(sa46.sa4.sin_zero));
	}

	if (result)
		freeaddrinfo(result);

#if defined(LWS_WITH_UNIX_SOCK)
ads_known:
#endif

	/* now we decided on ipv4 or ipv6, set the port */

	if (!lws_socket_is_valid(wsi->desc.sockfd)) {

		if (wsi->context->event_loop_ops->check_client_connect_ok &&
		    wsi->context->event_loop_ops->check_client_connect_ok(wsi)) {
			cce = "waiting for event loop watcher to close";
			goto oom4;
		}

#if defined(LWS_WITH_UNIX_SOCK)
		if (unix_skt) {
			wsi->unix_skt = 1;
			wsi->desc.sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
		} else
#endif
		{

#ifdef LWS_WITH_IPV6
		if (wsi->ipv6)
			wsi->desc.sockfd = socket(AF_INET6, SOCK_STREAM, 0);
		else
#endif
			wsi->desc.sockfd = socket(AF_INET, SOCK_STREAM, 0);
		}

		if (!lws_socket_is_valid(wsi->desc.sockfd)) {
			lwsl_warn("Unable to open socket\n");
			cce = "unable to open socket";
			goto oom4;
		}

		if (lws_plat_set_socket_options(wsi->vhost, wsi->desc.sockfd,
#if defined(LWS_WITH_UNIX_SOCK)
						unix_skt)) {
#else
						0)) {
#endif
			lwsl_err("Failed to set wsi socket options\n");
			compatible_close(wsi->desc.sockfd);
			cce = "set socket opts failed";
			goto oom4;
		}

		lwsi_set_state(wsi, LRS_WAITING_CONNECT);

#if !defined(LWS_AMAZON_RTOS)
		if (wsi->context->event_loop_ops->accept)
			if (wsi->context->event_loop_ops->accept(wsi)) {
				compatible_close(wsi->desc.sockfd);
				cce = "event loop accept failed";
				goto oom4;
			}
#endif

		if (__insert_wsi_socket_into_fds(wsi->context, wsi)) {
			compatible_close(wsi->desc.sockfd);
			cce = "insert wsi failed";
			goto oom4;
		}

		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			compatible_close(wsi->desc.sockfd);
			cce = "change_pollfd failed";
			goto oom4;
		}

		/*
		 * past here, we can't simply free the structs as error
		 * handling as oom4 does.  We have to run the whole close flow.
		 */

		if (!wsi->protocol)
			wsi->protocol = &wsi->vhost->protocols[0];

		wsi->protocol->callback(wsi, LWS_CALLBACK_WSI_CREATE,
					wsi->user_space, NULL, 0);

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CONNECT_RESPONSE,
				AWAITING_TIMEOUT);

		if (wsi->stash)
			iface = wsi->stash->iface;
		else
			iface = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_IFACE);

		if (iface) {
			n = lws_socket_bind(wsi->vhost, wsi->desc.sockfd, 0,
					    iface, wsi->ipv6);
			if (n < 0) {
				cce = "unable to bind socket";
				goto failed;
			}
		}
	}

#if defined(LWS_WITH_UNIX_SOCK)
	if (unix_skt) {
		psa = (const struct sockaddr *)&sau;
		n = sizeof(sau);
	} else
#endif

	{
#ifdef LWS_WITH_IPV6
		if (wsi->ipv6) {
			sa46.sa6.sin6_port = htons(port);
			n = sizeof(struct sockaddr_in6);
			psa = (const struct sockaddr *)&sa46;
		} else
#endif
		{
			sa46.sa4.sin_port = htons(port);
			n = sizeof(struct sockaddr);
			psa = (const struct sockaddr *)&sa46;
		}
	}

	if (connect(wsi->desc.sockfd, (const struct sockaddr *)psa, n) == -1 ||
	    LWS_ERRNO == LWS_EISCONN) {
		if (LWS_ERRNO == LWS_EALREADY ||
		    LWS_ERRNO == LWS_EINPROGRESS ||
		    LWS_ERRNO == LWS_EWOULDBLOCK
#ifdef _WIN32
			|| LWS_ERRNO == WSAEINVAL
#endif
		) {
			lwsl_client("nonblocking connect retry (errno = %d)\n",
				    LWS_ERRNO);

			if (lws_plat_check_connection_error(wsi)) {
				cce = "socket connect failed";
				goto failed;
			}

			/*
			 * must do specifically a POLLOUT poll to hear
			 * about the connect completion
			 */
			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
				cce = "POLLOUT set failed";
				goto failed;
			}

			return wsi;
		}

		if (LWS_ERRNO != LWS_EISCONN) {
			lwsl_notice("Connect failed errno=%d\n", LWS_ERRNO);
			cce = "connect failed";
			goto failed;
		}
	}



	return lws_client_connect_3(wsi, NULL, plen);


oom4:
	if (lwsi_role_client(wsi) && wsi->protocol /* && lwsi_state_est(wsi) */)
		lws_inform_client_conn_fail(wsi,(void *)cce, strlen(cce));

	/* take care that we might be inserted in fds already */
	if (wsi->position_in_fds_table != LWS_NO_FDS_POS)
		goto failed1;

	/*
	 * We can't be an active client connection any more, if we thought
	 * that was what we were going to be doing.  It should be if we are
	 * failing by oom4 path, we are still called by
	 * lws_client_connect_via_info() and will be returning NULL to that,
	 * so nobody else should have had a chance to queue on us.
	 */
	{
		struct lws_vhost *vhost = wsi->vhost;

		lws_vhost_lock(vhost);
		__lws_free_wsi(wsi);
		lws_vhost_unlock(vhost);
	}

	return NULL;

failed:
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

failed1:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect2");

	return NULL;
}


#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)

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
LWS_VISIBLE struct lws *
lws_client_reset(struct lws **pwsi, int ssl, const char *address, int port,
		 const char *path, const char *host)
{
	char origin[300] = "", protocol[300] = "", method[32] = "",
	     iface[16] = "", alpn[32] = "", *p;
	struct lws *wsi;

	if (!pwsi)
		return NULL;

	wsi = *pwsi;

	if (wsi->redirects == 3) {
		lwsl_err("%s: Too many redirects\n", __func__);
		return NULL;
	}
	wsi->redirects++;

	p = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_ORIGIN);
	if (p)
		lws_strncpy(origin, p, sizeof(origin));

	p = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS);
	if (p)
		lws_strncpy(protocol, p, sizeof(protocol));

	p = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
	if (p)
		lws_strncpy(method, p, sizeof(method));

	p = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_IFACE);
	if (p)
		lws_strncpy(iface, p, sizeof(iface));

	p = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_ALPN);
	if (p)
		lws_strncpy(alpn, p, sizeof(alpn));

	if (!port) {
		port = 443;
		ssl = 1;
	}

	lwsl_info("redirect ads='%s', port=%d, path='%s', ssl = %d\n",
		   address, port, path, ssl);

	/* close the connection by hand */

#if defined(LWS_WITH_TLS)
	lws_ssl_close(wsi);
#endif

	__remove_wsi_socket_from_fds(wsi);

	if (wsi->context->event_loop_ops->close_handle_manually)
		wsi->context->event_loop_ops->close_handle_manually(wsi);
	else
		compatible_close(wsi->desc.sockfd);

#if defined(LWS_WITH_TLS)
	wsi->tls.use_ssl = ssl;
#else
	if (ssl) {
		lwsl_err("%s: not configured for ssl\n", __func__);
		return NULL;
	}
#endif

	wsi->desc.sockfd = LWS_SOCK_INVALID;
	lwsi_set_state(wsi, LRS_UNCONNECTED);
	wsi->protocol = NULL;
	wsi->pending_timeout = NO_PENDING_TIMEOUT;
	wsi->c_port = port;
	wsi->hdr_parsing_completed = 0;
	_lws_header_table_reset(wsi->http.ah);

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS, address))
		return NULL;

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_HOST, host))
		return NULL;

	if (origin[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_ORIGIN,
					  origin))
			return NULL;
	if (protocol[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
					  protocol))
			return NULL;
	if (method[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_METHOD,
					  method))
			return NULL;

	if (iface[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_IFACE,
					  iface))
			return NULL;
	if (alpn[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_ALPN,
					  alpn))
			return NULL;

	origin[0] = '/';
	strncpy(&origin[1], path, sizeof(origin) - 2);
	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_URI, origin))
		return NULL;

	*pwsi = lws_client_connect_2(wsi);

	return *pwsi;
}

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_WITH_HUBBUB)
hubbub_error
html_parser_cb(const hubbub_token *token, void *pw)
{
	struct lws_rewrite *r = (struct lws_rewrite *)pw;
	char buf[1024], *start = buf + LWS_PRE, *p = start,
	     *end = &buf[sizeof(buf) - 1];
	size_t i;

	switch (token->type) {
	case HUBBUB_TOKEN_DOCTYPE:

		p += lws_snprintf(p, end - p, "<!DOCTYPE %.*s %s ",
				(int) token->data.doctype.name.len,
				token->data.doctype.name.ptr,
				token->data.doctype.force_quirks ?
						"(force-quirks) " : "");

		if (token->data.doctype.public_missing)
			lwsl_debug("\tpublic: missing\n");
		else
			p += lws_snprintf(p, end - p, "PUBLIC \"%.*s\"\n",
				(int) token->data.doctype.public_id.len,
				token->data.doctype.public_id.ptr);

		if (token->data.doctype.system_missing)
			lwsl_debug("\tsystem: missing\n");
		else
			p += lws_snprintf(p, end - p, " \"%.*s\">\n",
				(int) token->data.doctype.system_id.len,
				token->data.doctype.system_id.ptr);

		break;
	case HUBBUB_TOKEN_START_TAG:
		p += lws_snprintf(p, end - p, "<%.*s", (int)token->data.tag.name.len,
				token->data.tag.name.ptr);

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
					p += lws_snprintf(p, end - p, " %.*s=\"%s/%.*s\"",
					       (int) token->data.tag.attributes[i].name.len,
					       token->data.tag.attributes[i].name.ptr,
					       r->to, plen, pp);
					continue;
				}
			}

			p += lws_snprintf(p, end - p, " %.*s=\"%.*s\"",
				(int) token->data.tag.attributes[i].name.len,
				token->data.tag.attributes[i].name.ptr,
				(int) token->data.tag.attributes[i].value.len,
				token->data.tag.attributes[i].value.ptr);
		}
		p += lws_snprintf(p, end - p, ">");
		break;
	case HUBBUB_TOKEN_END_TAG:
		p += lws_snprintf(p, end - p, "</%.*s", (int) token->data.tag.name.len,
				token->data.tag.name.ptr);
/*
				(token->data.tag.self_closing) ?
						"(self-closing) " : "",
				(token->data.tag.n_attributes > 0) ?
						"attributes:" : "");
*/
		for (i = 0; i < token->data.tag.n_attributes; i++) {
			p += lws_snprintf(p, end - p, " %.*s='%.*s'\n",
				(int) token->data.tag.attributes[i].name.len,
				token->data.tag.attributes[i].name.ptr,
				(int) token->data.tag.attributes[i].value.len,
				token->data.tag.attributes[i].value.ptr);
		}
		p += lws_snprintf(p, end - p, ">");
		break;
	case HUBBUB_TOKEN_COMMENT:
		p += lws_snprintf(p, end - p, "<!-- %.*s -->\n",
				(int) token->data.comment.len,
				token->data.comment.ptr);
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

		p += lws_snprintf(p, end - p, "%.*s", (int) token->data.character.len,
				token->data.character.ptr);
		break;
	case HUBBUB_TOKEN_EOF:
		p += lws_snprintf(p, end - p, "\n");
		break;
	}

	if (r->wsi->protocol_bind_balance &&
	    user_callback_handle_rxflow(r->wsi->protocol->callback,
			r->wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
			r->wsi->user_space, start, p - start))
		return -1;

	return HUBBUB_OK;
}
#endif

#endif

struct lws *
lws_http_client_connect_via_info2(struct lws *wsi)
{
	struct client_info_stash *stash = wsi->stash;

	lwsl_debug("%s: %p (stash %p)\n", __func__, wsi, stash);

	if (!stash)
		return wsi;

	wsi->opaque_user_data = wsi->stash->opaque_user_data;

	if (stash->method && !strcmp(stash->method, "RAW"))
		goto no_ah;

	/*
	 * we're not necessarily in a position to action these right away,
	 * stash them... we only need during connect phase so into a temp
	 * allocated stash
	 */
	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS,
				  stash->address))
		goto bail1;

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_URI, stash->path))
		goto bail1;

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_HOST, stash->host))
		goto bail1;

	if (stash->origin)
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_ORIGIN,
					  stash->origin))
			goto bail1;
	/*
	 * this is a list of protocols we tell the server we're okay with
	 * stash it for later when we compare server response with it
	 */
	if (stash->protocol)
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
					  stash->protocol))
			goto bail1;
	if (stash->method)
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_METHOD,
					  stash->method))
			goto bail1;
	if (stash->iface)
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_IFACE,
					  stash->iface))
			goto bail1;
	if (stash->alpn)
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_ALPN,
					  stash->alpn))
			goto bail1;

#if defined(LWS_WITH_SOCKS5)
	if (!wsi->vhost->socks_proxy_port)
		lws_client_stash_destroy(wsi);
#endif

no_ah:
	wsi->context->count_wsi_allocated++;

	return lws_client_connect_2(wsi);

bail1:
#if defined(LWS_WITH_SOCKS5)
	if (!wsi->vhost->socks_proxy_port)
		lws_free_set_NULL(wsi->stash);
#endif

	return NULL;
}

#if defined(LWS_WITH_SOCKS5)
int
socks_generate_msg(struct lws *wsi, enum socks_msg_type type, ssize_t *msg_len)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	uint8_t *p = pt->serv_buf, *end = &p[context->pt_serv_buf_size];
	ssize_t n, passwd_len;
	short net_num;
	char *cp;

	switch (type) {
	case SOCKS_MSG_GREETING:
		if (lws_ptr_diff(end, p) < 4)
			return 1;
		/* socks version, version 5 only */
		*p++ = SOCKS_VERSION_5;
		/* number of methods */
		*p++ = 2;
		/* username password method */
		*p++ = SOCKS_AUTH_USERNAME_PASSWORD;
		/* no authentication method */
		*p++ = SOCKS_AUTH_NO_AUTH;
		break;

	case SOCKS_MSG_USERNAME_PASSWORD:
		n = strlen(wsi->vhost->socks_user);
		passwd_len = strlen(wsi->vhost->socks_password);

		if (n > 254 || passwd_len > 254)
			return 1;

		if (lws_ptr_diff(end, p) < 3 + n + passwd_len)
			return 1;

		/* the subnegotiation version */
		*p++ = SOCKS_SUBNEGOTIATION_VERSION_1;

		/* length of the user name */
		*p++ = n;
		/* user name */
		memcpy(p, wsi->vhost->socks_user, n);
		p += n;

		/* length of the password */
		*p++ = passwd_len;

		/* password */
		memcpy(p, wsi->vhost->socks_password, passwd_len);
		p += passwd_len;
		break;

	case SOCKS_MSG_CONNECT:
		n = strlen(wsi->stash->address);

		if (n > 254 || lws_ptr_diff(end, p) < 5 + n + 2)
			return 1;

		cp = (char *)&net_num;

		/* socks version */
		*p++ = SOCKS_VERSION_5;
		/* socks command */
		*p++ = SOCKS_COMMAND_CONNECT;
		/* reserved */
		*p++ = 0;
		/* address type */
		*p++ = SOCKS_ATYP_DOMAINNAME;
		/* length of ---> */
		*p++ = n;

		/* the address we tell SOCKS proxy to connect to */
		memcpy(p, wsi->stash->address, n);
		p += n;

		net_num = htons(wsi->c_port);

		/* the port we tell SOCKS proxy to connect to */
		*p++ = cp[0];
		*p++ = cp[1];

		break;
		
	default:
		return 1;
	}

	*msg_len = lws_ptr_diff(p, pt->serv_buf);

	return 0;
}
#endif
