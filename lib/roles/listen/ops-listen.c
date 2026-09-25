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

/* accept4() lives behind _GNU_SOURCE on glibc, and must be set before the
 * first system header is pulled in */
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <private-lib-core.h>

static void
lws_accept_pause_cb(lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = lws_container_of(sul, struct lws, sul_validity);

	if (lws_io_want_read(wsi, 1))
		lwsl_wsi_info(wsi, "fail");
}

static lws_handling_result_t
rops_handle_POLLIN_listen(struct lws_context_per_thread *pt, struct lws *wsi,
			  struct lws_pollfd *pollfd)
{
	struct lws_context *context = wsi->a.context;
	struct lws_filter_network_conn_args filt;
	lws_sock_file_fd_type fd;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _listen_start = lws_now_usecs();
#endif

	memset(&filt, 0, sizeof(filt));

	/* if our vhost is going down, ignore it */

	if (wsi->a.vhost->being_destroyed)
		return LWS_HPI_RET_HANDLED;

	/* pollin means a client has connected to us then
	 *
	 * pollout is a hack on esp32 for background accepts signalling
	 * they completed
	 */

	do {
		struct lws *cwsi;
		int opts = LWS_ADOPT_SOCKET | LWS_ADOPT_ALLOW_SSL;

		if (!(pollfd->revents & (LWS_POLLIN | LWS_POLLOUT)) ||
		    !(pollfd->events & LWS_POLLIN))
			break;

#if defined(LWS_WITH_TLS)
		/*
		 * can we really accept it, with regards to SSL limit?
		 * another vhost may also have had POLLIN on his
		 * listener this round and used it up already
		 */
		if (wsi->a.vhost->tls.use_ssl &&
		    context->simultaneous_ssl_restriction &&
		    context->simultaneous_ssl ==
				  context->simultaneous_ssl_restriction)
			/*
			 * no... ignore it, he won't come again until
			 * we are below the simultaneous_ssl_restriction
			 * limit and POLLIN is enabled on him again
			 */
			break;
#endif
		/* listen socket got an unencrypted connection... */

		filt.clilen = sizeof(filt.cli_addr);

		/*
		 * We cannot identify the peer who is in the listen
		 * socket connect queue before we accept it; even if
		 * we could, not accepting it due to PEER_LIMITS would
		 * block the connect queue for other legit peers.
		 */

#if defined(LWS_WITH_LATENCY)
		lws_usec_t _acc_start = lws_now_usecs();
#endif

#if defined(LWS_HAVE_ACCEPT4)
		/*
		 * Take the accepted fd already CLOEXEC... otherwise a spawn
		 * racing on another pt between here and the fcntl() done in
		 * lws_plat_set_socket_options() below inherits the accepted
		 * connection
		 */

		filt.accept_fd = accept4((int)pollfd->fd,
					 (struct sockaddr *)&filt.cli_addr,
					 &filt.clilen, SOCK_CLOEXEC);

		if (filt.accept_fd == LWS_SOCK_INVALID && LWS_ERRNO == ENOSYS) {

			/*
			 * libc knows about it, but the kernel we ended up
			 * running on does not... fall back to the racy way
			 */

			filt.clilen = sizeof(filt.cli_addr);
			filt.accept_fd = accept((int)pollfd->fd,
					(struct sockaddr *)&filt.cli_addr,
					&filt.clilen);
		}
#else
		filt.accept_fd = accept((int)pollfd->fd,
					(struct sockaddr *)&filt.cli_addr,
					&filt.clilen);
#endif

#if defined(LWS_WITH_LATENCY)
		{
			unsigned int ms = (unsigned int)((lws_now_usecs() - _acc_start) / 1000);
			if (ms > 2)
				lws_latency_note(pt, _acc_start, 2000, "accept:%dms", ms);
		}
#endif
		if (filt.accept_fd == LWS_SOCK_INVALID) {
			int m = LWS_ERRNO;

			if (m == LWS_EAGAIN ||
			    m == LWS_EWOULDBLOCK) {
				break;
			}
			lwsl_err("accept: errno %d\n", m);

			if (
#if defined(WSAEMFILE)
			    m == WSAEMFILE ||
#endif
#if defined(EMFILE)
			    m == EMFILE ||
#endif
#if defined(ENFILE)
			    m == ENFILE ||
#endif
			    0) {
				if (lws_io_want_read(wsi, 0))
					lwsl_wsi_info(wsi, "failed disable POLLIN");

				/*
				 * must be scheduled on the listener's own tsi:
				 * the cb does lws_change_pollfd() on this
				 * wsi, ie, mutates pt[wsi->tsi]->fds
				 */
				lws_sul_schedule(context, wsi->tsi,
						 &wsi->sul_validity,
						 lws_accept_pause_cb,
						 100 * LWS_US_PER_MS);
				break;
			}

			return LWS_HPI_RET_HANDLED;
		}

		if (context->being_destroyed) {
			compatible_close(filt.accept_fd);

			return LWS_HPI_RET_PLEASE_CLOSE_ME;
		}

		lws_plat_set_socket_options(wsi->a.vhost, filt.accept_fd, 0);

#if defined(LWS_WITH_IPV6)
		lwsl_debug("accepted new conn port %u on fd=%d\n",
			((filt.cli_addr.ss_family == AF_INET6) ?
			ntohs(((struct sockaddr_in6 *) &filt.cli_addr)->sin6_port) :
			ntohs(((struct sockaddr_in *) &filt.cli_addr)->sin_port)),
			filt.accept_fd);
#else
		{
		struct sockaddr_in sain;

		memcpy(&sain, &filt.cli_addr, sizeof(sain));
		lwsl_debug("accepted new conn port %u on fd=%d\n",
			   ntohs(sain.sin_port),
			   filt.accept_fd);
		}
#endif

		/*
		 * look at who we connected to and give user code a
		 * chance to reject based on client IP.  There's no
		 * protocol selected yet so we issue this to
		 * protocols[0]
		 */
		if ((wsi->a.vhost->protocols[0].callback)(wsi,
				LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
				(void *)&filt,
				(void *)(lws_intptr_t)filt.accept_fd, 0)) {
			lwsl_debug("Callback denied net connection\n");
			compatible_close(filt.accept_fd);
			return LWS_HPI_RET_HANDLED;
		}

		if (!(wsi->a.vhost->options &
			LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG))
			opts |= LWS_ADOPT_HTTP;

#if defined(LWS_WITH_TLS)
		if (!wsi->a.vhost->tls.use_ssl)
#endif
			opts &= ~LWS_ADOPT_ALLOW_SSL;

#if defined(LWS_WITH_LATENCY)
		lws_usec_t _adopt_start = lws_now_usecs();
#endif

		fd.sockfd = filt.accept_fd;
		cwsi = lws_adopt_descriptor_vhost(wsi->a.vhost, (lws_adoption_type)opts, fd,
				wsi->a.vhost->listen_accept_protocol, NULL);

#if defined(LWS_WITH_LATENCY)
		{
			unsigned int ms = (unsigned int)((lws_now_usecs() - _adopt_start) / 1000);
			if (ms > 2)
				lws_latency_note(pt, _adopt_start, 2000, "adopt:%dms", ms);
		}
#endif
		if (!cwsi) {
			lwsl_info("%s: vh %s: adopt failed\n", __func__,
					wsi->a.vhost->name);

			/* already closed cleanly as necessary */
			return LWS_HPI_RET_WSI_ALREADY_DIED;
		}
/*
		if (lws_server_socket_service_ssl(cwsi, accept_fd, 1)) {
			lws_close_free_wsi(cwsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "listen svc fail");
			return LWS_HPI_RET_WSI_ALREADY_DIED;
		}

		lwsl_info("%s: new %s: wsistate 0x%lx, role_ops %s\n",
			    __func__, lws_wsi_tag(cwsi), (unsigned long)cwsi->wsistate,
			    cwsi->role_ops->name);
*/

	} while (pt->fds_count < context->fd_limit_per_thread - 1 &&
		 wsi->position_in_fds_table != LWS_NO_FDS_POS &&
		 lws_poll_listen_fd(&pt->fds[wsi->position_in_fds_table]) > 0);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _listen_start) / 1000);
		if (ms > 2)
			lws_latency_note(pt, _listen_start, 2000, "listen:%dms", ms);
	}
#endif

	return LWS_HPI_RET_HANDLED;
}

lws_handling_result_t
rops_handle_POLLOUT_listen(struct lws *wsi)
{
	return LWS_HP_RET_USER_SERVICE;
}

static const lws_rops_t rops_table_listen[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_listen },
	/*  2 */ { .handle_POLLOUT	  = rops_handle_POLLOUT_listen },
};

const struct lws_role_ops role_ops_listen = {
	/* role name */			"listen",
	/* alpn id */			NULL,

	/* rops_table */		rops_table_listen,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x01,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x20,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x00,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x00,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x00,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x00,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x00,
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x00,
					},

	/* adoption_cb clnt, srv */	{ 0, 0 },
	/* rx_cb clnt, srv */		{ 0, 0 },
	/* writeable cb clnt, srv */	{ 0, 0 },
	/* close cb clnt, srv */	{ 0, 0 },
	/* protocol_bind_cb c,s */	{ 0, 0 },
	/* protocol_unbind_cb c,s */	{ 0, 0 },
	/* file_handle */		0,
};

/*
 * The vhost's listen sockets: created, bound, optioned and adopted with the
 * listen role.  IO's, moved here from the http server role, whose business
 * is what arrives on them.
 */

#if !defined(SOL_TCP) && defined(IPPROTO_TCP)
#define SOL_TCP IPPROTO_TCP
#endif

struct vh_sock_args {
	const struct lws_context_creation_info	*info;
	struct lws_vhost			*vhost;
	int					af;
};


static int
check_extant(struct lws_dll2 *d, void *user)
{
	struct lws *wsi = lws_container_of(d, struct lws, listen_list);
	struct vh_sock_args *a = (struct vh_sock_args *)user;

	if (!lws_vhost_compare_listen(wsi->a.vhost, a->vhost))
		return 0;

	if (wsi->af != a ->af)
		return 0;

	if (a->info && a->info->vh_listen_sockfd &&
	    wsi->desc.sockfd != a->info->vh_listen_sockfd)
		return 0;

	lwsl_notice(" using listen skt from vhost %s\n", wsi->a.vhost->name);

	return 1;
}

#if defined(LWS_ROLE_QUIC)
static int
check_extant_quic(struct lws_dll2 *d, void *user)
{
        struct lws *wsi = lws_container_of(d, struct lws, listen_list);
        struct vh_sock_args *a = (struct vh_sock_args *)user;

        if (!lws_vhost_compare_listen(wsi->a.vhost, a->vhost))
                return 0;

        if (strcmp(wsi->role_ops->name, "quic"))
                return 0;

        return 1;
}
#endif

/*
 * Creates a single listen socket of a specific AF
 */

int
_lws_vhost_init_server_af(struct vh_sock_args *a)
{
	struct lws_context *cx = a->vhost->context;
	struct lws_context_per_thread *pt;
	int n, opt = 1, limit = 1, san = 2;
	lws_sockfd_type sockfd;
	struct lws *wsi;
	int m = 0, is = 0;
#if defined(LWS_WITH_IPV6) && defined(IPV6_V6ONLY)
#if defined(LWS_WITH_IPV4)
	/*
	 * The v6 listener is v6-only, a separate AF_INET listener serves v4
	 */
	int value = 1;
#else
	/*
	 * IPv6-only build: no separate AF_INET listener can exist, so make
	 * the listener dual-stack by default, letting v4 peers still reach
	 * us via v4-mapped addresses.  Explicitly setting
	 * IPV6_V6ONLY_MODIFY|_VALUE still forces v6-only.
	 */
	int value = lws_check_opt(a->vhost->options,
				  LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
				  LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE);
#endif
#endif

	(void)opt;

	lwsl_info("%s: af %d\n", __func__, (int)a->af);

	if (lws_vhost_foreach_listen_wsi(a->vhost->context, a, check_extant))
		return 0;

deal:

	if (!san--)
		return -1;

	if (a->vhost->iface && (!a->info || !a->info->vh_listen_sockfd)) {

		/*
		 * let's check before we do anything else about the disposition
		 * of the interface he wants to bind to...
		 */
		is = lws_socket_bind(a->vhost, NULL, LWS_SOCK_INVALID,
				     a->vhost->listen_port, a->vhost->iface,
				     a->af);
		lwsl_debug("initial if check says %d\n", is);

		if (is == LWS_ITOSA_BUSY)
			/* treat as fatal */
			return -1;

		if (!lws_dll2_is_detached(&a->vhost->no_listener_vlist)) {
			/* on the list */
			if (is >= LWS_ITOSA_USABLE) {
				/* ... and shouldn't be: remove it */
				lwsl_debug("deferred iface: removing vh %s\n",
						a->vhost->name);
				lws_dll2_remove(&a->vhost->no_listener_vlist);
				goto done_list;
			}
			goto done_list;
		}

		/* not on the list... */

		if (is < LWS_ITOSA_USABLE) {

			/* ... but needs to be: so add it */

			lwsl_debug("deferred iface: adding vh %s\n",
					a->vhost->name);
			lws_dll2_add_head(&a->vhost->no_listener_vlist,
					  &cx->no_listener_vhost_owner);
		}

done_list:

		switch (is) {
		default:
			break;
		case LWS_ITOSA_NOT_EXIST:
			/* can't add it */
			if (!a->info)
				return -1;

			/* first time */
			lwsl_err("%s: VH %s: iface %s port %d DOESN'T EXIST\n",
				 __func__, a->vhost->name, a->vhost->iface,
				 a->vhost->listen_port);

			return (a->info->options &
				LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND) ==
				LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND ?
				-1 : 1;

		case LWS_ITOSA_NOT_USABLE:
			/* can't add it */
			if (!a->info) /* first time */
				return -1;

			lwsl_err("%s: VH %s: iface %s port %d NOT USABLE\n",
				 __func__, a->vhost->name, a->vhost->iface,
				 a->vhost->listen_port);

			return (a->info->options &
				LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND) ==
				LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND ?
				-1 : 1;
		}
	} else {
		if (a->info && a->info->vh_listen_sockfd) {
			a->vhost->iface = "inherited";
			a->vhost->listen_port = a->info->port;
		}
	}

	(void)n;
#if defined(__linux__)
	/*
	 * A Unix domain sockets cannot be bound multiple times, even if we
	 * set the SO_REUSE* options on.
	 *
	 * However on recent linux, each thread is able to independently listen.
	 *
	 * So we can assume creating just one listening socket for a multi-
	 * threaded environment will typically work.
	 */
	if (a->af != AF_UNIX)
		limit = cx->count_threads;
#endif

	if (cx->lws_stub && !LWS_UNIX_SOCK_ENABLED(a->vhost))
		limit = 0;

	for (m = 0; m < limit; m++) {

		if (a->info && a->info->vh_listen_sockfd)
		{
#if defined(_WIN32)
			if (!DuplicateHandle(GetCurrentProcess(),
					(HANDLE)a->info->vh_listen_sockfd,
					GetCurrentProcess(), (HANDLE*)&sockfd, 0,
					FALSE, DUPLICATE_SAME_ACCESS))
				sockfd = LWS_SOCK_INVALID;
#else
#if defined(LWS_PLAT_FREERTOS)
			sockfd = a->info->vh_listen_sockfd;
#else
			sockfd = dup(a->info->vh_listen_sockfd);
#endif
#endif
		}
		else
			sockfd = lws_fi(&a->vhost->fic, "listenskt") ?
					LWS_SOCK_INVALID :
					socket(a->af, SOCK_STREAM, 0);

		if (sockfd == LWS_SOCK_INVALID) {
			lwsl_err("ERROR opening socket\n");
			return 1;
		}

#if defined(WIN32) && defined(LWS_WITH_UNIX_SOCK)
		if (a->af != AF_UNIX) {
#endif
#if (defined(WIN32) || defined(_WIN32)) && defined(SO_EXCLUSIVEADDRUSE)
		/*
		 * only accept that we are the only listener on the port
		 * https://msdn.microsoft.com/zh-tw/library/
		 *    windows/desktop/ms740621(v=vs.85).aspx
		 *
		 * for lws, to match Linux, we default to exclusive listen
		 */
		if (!lws_check_opt(a->vhost->options,
				LWS_SERVER_OPTION_ALLOW_LISTEN_SHARE)) {
			if (setsockopt(sockfd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
				       (const void *)&opt, sizeof(opt)) < 0) {
				lwsl_err("reuseaddr failed\n");
				compatible_close(sockfd);
				return -1;
			}
		} else
#endif

#if defined(SO_REUSEADDR)
		/*
		 * allow us to restart even if old sockets in TIME_WAIT
		 */
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			       (const void *)&opt, sizeof(opt)) < 0) {
			lwsl_err("reuseaddr failed\n");
			compatible_close(sockfd);
			return -1;
		}
#endif
#if defined(WIN32) && defined(LWS_WITH_UNIX_SOCK)
		}
#endif

#if defined(LWS_WITH_IPV6) && defined(IPV6_V6ONLY)
		/*
		 * If we have an ipv6 listen socket, in dual builds it only
		 * accepts ipv6 since there is a separate ipv4 listen socket
		 * as well (if ipv4 is enabled).  In IPv6-only builds it is
		 * dual-stack by default so v4-mapped peers can reach us.
		 */
		if (a->af == AF_INET6 && (!a->info || !a->info->vh_listen_sockfd) &&
		    setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
			       (const void*)&value, sizeof(value)) < 0) {
			lwsl_err("ipv6 only failed\n");

			compatible_close(sockfd);
			return -1;
		}
#endif

#if defined(__linux__) && defined(SO_REUSEPORT)
		/* keep coverity happy */
#if LWS_MAX_SMP > 1
		n = 1;
#else
		n = lws_check_opt(a->vhost->options,
				  LWS_SERVER_OPTION_ALLOW_LISTEN_SHARE);
#endif
		if (n || cx->count_threads > 1) /* ... also implied by threads > 1 */
			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
					(const void *)&opt, sizeof(opt)) < 0) {
				lwsl_info("reuseport failed\n");
//				compatible_close(sockfd);
//				return -1;
			}
#endif
#if defined(LWS_WITH_UNIX_SOCK)
		lws_plat_set_socket_options(a->vhost, sockfd, a->af == AF_UNIX);
#else
		lws_plat_set_socket_options(a->vhost, sockfd, 0);
#endif

		if (!a->info || !a->info->vh_listen_sockfd) {
			is = lws_socket_bind(a->vhost, NULL, sockfd,
					     a->vhost->listen_port,
					     a->vhost->iface, a->af);

			if (is == LWS_ITOSA_BUSY) {
				/* treat as fatal */
				compatible_close(sockfd);

				return -1;
			}

			/*
			 * There is a race where the network device may come up and then
			 * go away and fail here.  So correctly handle unexpected failure
			 * here despite we earlier confirmed it.
			 */
			if (is < 0) {
				lwsl_info("%s: lws_socket_bind says %d\n", __func__, is);
				compatible_close(sockfd);
				if (a->vhost->iface)
					goto deal;
				return -1;
			}
		}

		/*
		 * Create the listen wsi and customize it
		 */

		lws_context_lock(cx, __func__);
		wsi = __lws_wsi_create_with_role(cx, m, &role_ops_listen, NULL);
		lws_context_unlock(cx);
		if (wsi == NULL) {
			lwsl_err("Out of mem\n");
			goto bail;
		}

		wsi->af = (uint8_t)a->af;

#ifdef LWS_WITH_UNIX_SOCK
		if (LWS_UNIX_SOCK_ENABLED(a->vhost)) {
			wsi->unix_skt = 1;
		} else
#endif
		{
			a->vhost->listen_port = is;
			lwsl_debug("%s: lws_socket_bind says %d\n", __func__, is);
		}

		wsi->desc.sockfd = sockfd;
		wsi->a.protocol = a->vhost->protocols;
		lws_vhost_bind_wsi(a->vhost, wsi);
		wsi->listener = 1;

		if (wsi->a.context->event_loop_ops->init_vhost_listen_wsi)
			wsi->a.context->event_loop_ops->init_vhost_listen_wsi(wsi);

		pt = &cx->pt[m];
		lws_pt_lock(pt, __func__);

		if (__insert_wsi_socket_into_fds(cx, wsi)) {
			lwsl_notice("inserting wsi socket into fds failed\n");
			lws_pt_unlock(pt);
			goto bail;
		}

		lws_dll2_remove(&wsi->pre_natal);

		lws_dll2_add_tail(&wsi->listen_list, &a->vhost->listen_wsi);
		lws_pt_unlock(pt);

#if defined(WIN32) && defined(TCP_FASTOPEN)
		if (a->vhost->fo_listen_queue) {
			int optval = 1;
			if (setsockopt(wsi->desc.sockfd, IPPROTO_TCP,
				       TCP_FASTOPEN,
				       (const char*)&optval, sizeof(optval)) < 0) {
#if (_LWS_ENABLED_LOGS & LLL_WARN)
				int error = LWS_ERRNO;
				lwsl_warn("%s: TCP_NODELAY failed with error %d\n",
						__func__, error);
#endif
			}
		}
#else
#if defined(TCP_FASTOPEN)
		if (a->vhost->fo_listen_queue) {
			int qlen = a->vhost->fo_listen_queue;

			if (setsockopt(wsi->desc.sockfd, SOL_TCP, TCP_FASTOPEN,
				       &qlen, sizeof(qlen)))
				lwsl_warn("%s: TCP_FASTOPEN failed\n", __func__);
		}
#endif
#endif

		n = listen(wsi->desc.sockfd, LWS_SOMAXCONN);
		if (n < 0) {
			lwsl_err("listen failed with error %d\n", LWS_ERRNO);
			lws_dll2_remove(&wsi->listen_list);
			__remove_wsi_socket_from_fds(wsi);
			goto bail;
		}

		if (wsi) {
			if (a->info && a->info->vh_listen_sockfd)
				a->vhost->listen_port = a->info->port;

			__lws_lc_tag(a->vhost->context,
				     &a->vhost->context->lcg[LWSLCG_WSI],
				     &wsi->lc, "listen|%s|%s|%d",
				     a->vhost->name,
				     a->vhost->iface ? a->vhost->iface : "",
				     (int)a->vhost->listen_port);
		}

	} /* for each thread able to independently listen */

	if (!lws_check_opt(cx->options, LWS_SERVER_OPTION_EXPLICIT_VHOSTS)) {
#ifdef LWS_WITH_UNIX_SOCK
		if (a->af == AF_UNIX)
			lwsl_info(" Listening on \"%s\"\n", a->vhost->iface);
		else
#endif
			lwsl_info(" Listening on %s:%d\n",
					a->vhost->iface,
					a->vhost->listen_port);
        }

	// info->port = vhost->listen_port;

	return 0;

bail:
	lwsl_err("%s: bailing\n", __func__);
	compatible_close(sockfd);

	return -1;
}


int
_lws_vhost_init_server(const struct lws_context_creation_info *info,
		       struct lws_vhost *vhost)
{
	struct vh_sock_args a;
	int n;

	a.info = info;
	a.vhost = vhost;

	if (info) {
		vhost->iface = info->iface;
		vhost->listen_port = info->port;
	}

	/* set up our external listening socket we serve on */

	if (vhost->listen_port == CONTEXT_PORT_NO_LISTEN ||
	    vhost->listen_port == CONTEXT_PORT_NO_LISTEN_SERVER)
		return 0;

	if (info && info->vh_listen_sockfd) {
		a.af = AF_UNSPEC;
		goto single;
	}

	/*
	 * Let's figure out what AF(s) we want this vhost to listen on.
	 *
	 * We want AF_UNIX alone if that's what's told
	 */

#if defined(LWS_WITH_UNIX_SOCK)
	/*
	 * If unix socket, ask for that and we are done
	 */
	if (LWS_UNIX_SOCK_ENABLED(vhost)) {
		a.af = AF_UNIX;
		return _lws_vhost_init_server_af(&a);
	}
#endif

	/*
	 * We may support both ipv4 and ipv6, but get a numeric vhost listen
	 * iface that is unambiguously ipv4 or ipv6, meaning we can only listen
	 * for the related AF then.
	 */

	if (vhost->iface) {
		uint8_t buf[16];
		int q;

		q = lws_parse_numeric_address(vhost->iface, buf, sizeof(buf));

		if (q == 4) {
#if defined(LWS_WITH_IPV4)
			if (LWS_IPV4_ENABLED(vhost)) {
				a.af = AF_INET;
				goto single;
			}
#endif
			lwsl_err("%s: ipv4 not supported on %s\n", __func__,
					vhost->name);
			return 1;
		}

		if (q == 16) {
#if defined(LWS_WITH_IPV6)
			if (LWS_IPV6_ENABLED(vhost)) {
				a.af = AF_INET6;
				goto single;
			}
#endif
			lwsl_err("%s: ipv6 not supported on %s\n", __func__,
					vhost->name);
			return 1;
		}
	}

	/*
	 * ... if we make it here, we would want to listen on AF_INET and
	 * AF_INET6 unless one or the other is forbidden
	 */

#if defined(LWS_WITH_IPV6)
	if (!(LWS_IPV6_ENABLED(vhost) &&
	      (vhost->options & LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY) &&
	      (vhost->options & LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE))) {
#endif
#if defined(LWS_WITH_IPV4)
		if (LWS_IPV4_ENABLED(vhost)) {
			a.af = AF_INET;
			n = _lws_vhost_init_server_af(&a);
			if (n)
				return n;
		}
#endif

#if defined(LWS_WITH_IPV6)
	}

	if (LWS_IPV6_ENABLED(vhost)) {
		a.af = AF_INET6;
		n = _lws_vhost_init_server_af(&a);
		if (n)
			return n;
	}
#endif

	goto check_quic;

single:
	n = _lws_vhost_init_server_af(&a);
	if (n)
		return n;

check_quic:
#if defined(LWS_ROLE_QUIC)
	{
		const char *alpn = vhost->tls.alpn ? vhost->tls.alpn : vhost->context->tls.alpn_default;
		if (!vhost->context->lws_stub &&
		    LWS_SSL_ENABLED(vhost) &&
		    alpn &&
		    (strstr(alpn, "h3") || strstr(alpn, "lws-quic")) &&
		    !lws_vhost_foreach_listen_wsi(vhost->context, &a, check_extant_quic)) {
			
#if defined(LWS_WITH_IPV6)
			if (LWS_IPV6_ENABLED(vhost)) {
				const char *ads6 = vhost->iface ? vhost->iface : "::";
				if (!lws_create_adopt_udp(vhost, ads6, vhost->listen_port,
							  LWS_CAUDP_BIND, "quic", vhost->iface, NULL,
							  NULL, NULL, "quic_listen")) {
					lwsl_vhost_err(vhost, "Failed to bind QUIC IPv6 UDP listener");
				}
			}
#endif
#if defined(LWS_WITH_IPV4)
			if (LWS_IPV4_ENABLED(vhost) &&
			    (!vhost->iface || !LWS_IPV6_ENABLED(vhost) ||
			    (vhost->options & LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE))) {
				const char *ads4 = vhost->iface ? vhost->iface : "0.0.0.0";
				if (!lws_create_adopt_udp(vhost, ads4, vhost->listen_port,
							  LWS_CAUDP_BIND, "quic", vhost->iface, NULL,
							  NULL, NULL, "quic_listen")) {
					lwsl_vhost_err(vhost, "Failed to bind QUIC IPv4 UDP listener");
				}
			}
#endif
		}
	}
#endif
	return 0;
}
