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

static int
lws_get_idlest_tsi(struct lws_context *context)
{
	unsigned int lowest = ~0;
	int n = 0, hit = -1;

	for (; n < context->count_threads; n++) {
		lwsl_notice("%s: %d %d\n", __func__, context->pt[n].fds_count, context->fd_limit_per_thread - 1);
		if ((unsigned int)context->pt[n].fds_count !=
		    context->fd_limit_per_thread - 1 &&
		    (unsigned int)context->pt[n].fds_count < lowest) {
			lowest = context->pt[n].fds_count;
			hit = n;
		}
	}

	return hit;
}

struct lws *
lws_create_new_server_wsi(struct lws_vhost *vhost, int fixed_tsi)
{
	struct lws *new_wsi;
	int n = fixed_tsi;

	if (n < 0)
		n = lws_get_idlest_tsi(vhost->context);

	if (n < 0) {
		lwsl_err("no space for new conn\n");
		return NULL;
	}

	new_wsi = lws_zalloc(sizeof(struct lws), "new server wsi");
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->wsistate |= LWSIFR_SERVER;
	new_wsi->tsi = n;
	lwsl_debug("new wsi %p joining vhost %s, tsi %d\n", new_wsi,
		   vhost->name, new_wsi->tsi);

	lws_vhost_bind_wsi(vhost, new_wsi);
	new_wsi->context = vhost->context;
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;
	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;
	new_wsi->retry_policy = vhost->retry_policy;

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (vhost->context->detailed_latency_cb)
		new_wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
#endif

	/* initialize the instance struct */

	lwsi_set_state(new_wsi, LRS_UNCONNECTED);
	new_wsi->hdr_parsing_completed = 0;

#ifdef LWS_WITH_TLS
	new_wsi->tls.use_ssl = LWS_SSL_ENABLED(vhost);
#endif

	/*
	 * these can only be set once the protocol is known
	 * we set an un-established connection's protocol pointer
	 * to the start of the supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = vhost->protocols;
	new_wsi->user_space = NULL;
	new_wsi->desc.sockfd = LWS_SOCK_INVALID;
	new_wsi->position_in_fds_table = LWS_NO_FDS_POS;

	vhost->context->count_wsi_allocated++;

	/*
	 * outermost create notification for wsi
	 * no user_space because no protocol selection
	 */
	vhost->protocols[0].callback(new_wsi, LWS_CALLBACK_WSI_CREATE, NULL,
				     NULL, 0);

	return new_wsi;
}


/* if not a socket, it's a raw, non-ssl file descriptor */

static struct lws *
lws_adopt_descriptor_vhost1(struct lws_vhost *vh, lws_adoption_type type,
			    const char *vh_prot_name, struct lws *parent)
{
	struct lws_context *context = vh->context;
	struct lws_context_per_thread *pt;
	struct lws *new_wsi;
	int n;

	/*
	 * Notice that in SMP case, the wsi may be being created on an
	 * entirely different pt / tsi for load balancing.  In that case as
	 * we initialize it, it may become "live" concurrently unexpectedly...
	 */

	n = -1;
	if (parent)
		n = parent->tsi;
	new_wsi = lws_create_new_server_wsi(vh, n);
	if (!new_wsi)
		return NULL;

	pt = &context->pt[(int)new_wsi->tsi];
	lws_stats_bump(pt, LWSSTATS_C_CONNECTIONS, 1);

	if (parent) {
		new_wsi->parent = parent;
		new_wsi->sibling_list = parent->child_list;
		parent->child_list = new_wsi;
	}

	if (vh_prot_name) {
		new_wsi->protocol = lws_vhost_name_to_protocol(new_wsi->vhost,
							       vh_prot_name);
		if (!new_wsi->protocol) {
			lwsl_err("Protocol %s not enabled on vhost %s\n",
				 vh_prot_name, new_wsi->vhost->name);
			goto bail;
		}
		if (lws_ensure_user_space(new_wsi)) {
		       lwsl_notice("OOM trying to get user_space\n");
			goto bail;
		}
	}

	if (lws_role_call_adoption_bind(new_wsi, type, vh_prot_name)) {
		lwsl_err("%s: no role for desc type 0x%x\n", __func__, type);
		goto bail;
	}

	return new_wsi;

bail:
       lwsl_notice("%s: exiting on bail\n", __func__);
	if (parent)
		parent->child_list = new_wsi->sibling_list;
	if (new_wsi->user_space)
		lws_free(new_wsi->user_space);

	vh->context->count_wsi_allocated--;

	lws_vhost_unbind_wsi(new_wsi);
	lws_free(new_wsi);

	return NULL;
}

static struct lws *
lws_adopt_descriptor_vhost2(struct lws *new_wsi, lws_adoption_type type,
			    lws_sock_file_fd_type fd)
{
	struct lws_context_per_thread *pt =
			&new_wsi->context->pt[(int)new_wsi->tsi];
	int n;

	/* enforce that every fd is nonblocking */

	if (type & LWS_ADOPT_SOCKET) {
		if (lws_plat_set_nonblocking(fd.sockfd)) {
			lwsl_err("%s: unable to set sockfd %d nonblocking\n",
				 __func__, fd.sockfd);
			goto fail;
		}
	}
#if !defined(WIN32)
	else
		if (lws_plat_set_nonblocking(fd.filefd)) {
			lwsl_err("%s: unable to set filefd nonblocking\n",
				 __func__);
			goto fail;
		}
#endif

	new_wsi->desc = fd;

	if (!LWS_SSL_ENABLED(new_wsi->vhost) ||
	    !(type & LWS_ADOPT_SOCKET))
		type &= ~LWS_ADOPT_ALLOW_SSL;

	/*
	 * A new connection was accepted. Give the user a chance to
	 * set properties of the newly created wsi. There's no protocol
	 * selected yet so we issue this to the vhosts's default protocol,
	 * itself by default protocols[0]
	 */
	new_wsi->wsistate |= LWSIFR_SERVER;
	n = LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED;
	if (new_wsi->role_ops->adoption_cb[lwsi_role_server(new_wsi)])
		n = new_wsi->role_ops->adoption_cb[lwsi_role_server(new_wsi)];

#if !defined(LWS_AMAZON_RTOS)
	if (new_wsi->context->event_loop_ops->accept)
		if (new_wsi->context->event_loop_ops->accept(new_wsi))
			goto fail;
#endif

#if LWS_MAX_SMP > 1
	/*
	 * Caution: after this point the wsi is live on its service thread
	 * which may be concurrent to this.  We mark the wsi as still undergoing
	 * init in another pt so the assigned pt leaves it alone.
	 */
	new_wsi->undergoing_init_from_other_pt = 1;
#endif

	if (!(type & LWS_ADOPT_ALLOW_SSL)) {
		lws_pt_lock(pt, __func__);
		if (__insert_wsi_socket_into_fds(new_wsi->context, new_wsi)) {
			lws_pt_unlock(pt);
			lwsl_err("%s: fail inserting socket\n", __func__);
			goto fail;
		}
		lws_pt_unlock(pt);
	}
#if defined(LWS_WITH_SERVER)
	 else
		if (lws_server_socket_service_ssl(new_wsi, fd.sockfd)) {
			lwsl_info("%s: fail ssl negotiation\n", __func__);
			goto fail;
		}
#endif

	/*
	 *  by deferring callback to this point, after insertion to fds,
	 * lws_callback_on_writable() can work from the callback
	 */
	if ((new_wsi->protocol->callback)(new_wsi, n, new_wsi->user_space,
					  NULL, 0))
		goto fail;

	/* role may need to do something after all adoption completed */

	lws_role_call_adoption_bind(new_wsi, type | _LWS_ADOPT_FINISH,
				    new_wsi->protocol->name);

#if LWS_MAX_SMP > 1
	/* its actual pt can service it now */

	new_wsi->undergoing_init_from_other_pt = 0;
#endif

	lws_cancel_service_pt(new_wsi);

	return new_wsi;

fail:
	if (type & LWS_ADOPT_SOCKET)
		lws_close_free_wsi(new_wsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "adopt skt fail");

	return NULL;
}


/* if not a socket, it's a raw, non-ssl file descriptor */

LWS_VISIBLE struct lws *
lws_adopt_descriptor_vhost(struct lws_vhost *vh, lws_adoption_type type,
			   lws_sock_file_fd_type fd, const char *vh_prot_name,
			   struct lws *parent)
{
	struct lws *new_wsi;
#if defined(LWS_WITH_PEER_LIMITS)
	struct lws_peer *peer = NULL;

	if (type & LWS_ADOPT_SOCKET) {
		peer = lws_get_or_create_peer(vh, fd.sockfd);

		if (peer && vh->context->ip_limit_wsi &&
		    peer->count_wsi >= vh->context->ip_limit_wsi) {
			lwsl_notice("Peer reached wsi limit %d\n",
					vh->context->ip_limit_wsi);
			lws_stats_bump(&vh->context->pt[0],
					      LWSSTATS_C_PEER_LIMIT_WSI_DENIED,
					      1);
			return NULL;
		}
	}
#endif

	new_wsi = lws_adopt_descriptor_vhost1(vh, type, vh_prot_name, parent);
	if (!new_wsi) {
		if (type & LWS_ADOPT_SOCKET)
			compatible_close(fd.sockfd);
		return NULL;
	}

#if defined(LWS_WITH_PEER_LIMITS)
	if (peer)
		lws_peer_add_wsi(vh->context, peer, new_wsi);
#endif

	return lws_adopt_descriptor_vhost2(new_wsi, type, fd);
}

LWS_VISIBLE struct lws *
lws_adopt_socket_vhost(struct lws_vhost *vh, lws_sockfd_type accept_fd)
{
	lws_sock_file_fd_type fd;

	fd.sockfd = accept_fd;
	return lws_adopt_descriptor_vhost(vh, LWS_ADOPT_SOCKET |
			LWS_ADOPT_HTTP | LWS_ADOPT_ALLOW_SSL, fd, NULL, NULL);
}

LWS_VISIBLE struct lws *
lws_adopt_socket(struct lws_context *context, lws_sockfd_type accept_fd)
{
	return lws_adopt_socket_vhost(context->vhost_list, accept_fd);
}

/* Common read-buffer adoption for lws_adopt_*_readbuf */
static struct lws*
adopt_socket_readbuf(struct lws *wsi, const char *readbuf, size_t len)
{
	struct lws_context_per_thread *pt;
	struct lws_pollfd *pfd;
	int n;

	if (!wsi)
		return NULL;

	if (!readbuf || len == 0)
		return wsi;

	if (wsi->position_in_fds_table == LWS_NO_FDS_POS)
		return wsi;

	pt = &wsi->context->pt[(int)wsi->tsi];

	n = lws_buflist_append_segment(&wsi->buflist, (const uint8_t *)readbuf,
				       len);
	if (n < 0)
		goto bail;
	if (n)
		lws_dll2_add_head(&wsi->dll_buflist, &pt->dll_buflist_owner);

	/*
	 * we can't process the initial read data until we can attach an ah.
	 *
	 * if one is available, get it and place the data in his ah rxbuf...
	 * wsi with ah that have pending rxbuf get auto-POLLIN service.
	 *
	 * no autoservice because we didn't get a chance to attach the
	 * readbuf data to wsi or ah yet, and we will do it next if we get
	 * the ah.
	 */
	if (wsi->http.ah || !lws_header_table_attach(wsi, 0)) {

		lwsl_notice("%s: calling service on readbuf ah\n", __func__);

		/*
		 * unlike a normal connect, we have the headers already
		 * (or the first part of them anyway).
		 * libuv won't come back and service us without a network
		 * event, so we need to do the header service right here.
		 */
		pfd = &pt->fds[wsi->position_in_fds_table];
		pfd->revents |= LWS_POLLIN;
		lwsl_err("%s: calling service\n", __func__);
		if (lws_service_fd_tsi(wsi->context, pfd, wsi->tsi))
			/* service closed us */
			return NULL;

		return wsi;
	}
	lwsl_err("%s: deferring handling ah\n", __func__);

	return wsi;

bail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
			   "adopt skt readbuf fail");

	return NULL;
}

#if defined(LWS_WITH_CLIENT)
static struct lws *
lws_create_adopt_udp2(struct lws *wsi, const char *ads,
		      const struct addrinfo *r, int n, void *opaque)
{
	lws_sock_file_fd_type sock;

	assert(wsi);

	if (!wsi->dns_results)
		wsi->dns_results_next = wsi->dns_results = r;

	if (n < 0 || !r)
		goto bail;

	while (wsi->dns_results_next) {

		/*
		 * We have done the dns lookup, identify the result we want
		 * if any, and then complete the adoption by binding wsi to
		 * socket opened on it.
		 *
		 * Ignore the weak assumptions about protocol driven by port
		 * number and force to DGRAM / UDP since that's what this
		 * function is for.
		 */

		sock.sockfd = socket(wsi->dns_results_next->ai_family,
				     SOCK_DGRAM, IPPROTO_UDP);

		if (sock.sockfd == LWS_SOCK_INVALID)
			goto resume;

		if (wsi->do_bind &&
		    bind(sock.sockfd, wsi->dns_results_next->ai_addr,
#if defined(_WIN32)
			 (int)wsi->dns_results_next->ai_addrlen
#else
			 wsi->dns_results_next->ai_addrlen
#endif
								    ) == -1) {
			lwsl_notice("%s: bind failed\n", __func__);
			goto resume;
		}

		if (!wsi->do_bind) {
			((struct sockaddr_in *)wsi->dns_results_next->ai_addr)->
						sin_port = htons(wsi->c_port);

			if (connect(sock.sockfd, wsi->dns_results_next->ai_addr,
				     wsi->dns_results_next->ai_addrlen) == -1) {
				lwsl_err("%s: conn fd %d fam %d %s:%u failed "
					 "(salen %d) errno %d\n", __func__,
					 sock.sockfd,
					 wsi->dns_results_next->ai_addr->sa_family,
					 ads ? ads : "null", wsi->c_port,
					 (int)wsi->dns_results_next->ai_addrlen,
					 LWS_ERRNO);
				compatible_close(sock.sockfd);
				goto resume;
			}

			memcpy(&wsi->udp->sa, wsi->dns_results_next->ai_addr,
			       wsi->dns_results_next->ai_addrlen);
			wsi->udp->salen = wsi->dns_results_next->ai_addrlen;
		}

		/* complete the udp socket adoption flow */

		lws_addrinfo_clean(wsi);
		return lws_adopt_descriptor_vhost2(wsi,
						LWS_ADOPT_RAW_SOCKET_UDP, sock);

resume:
		wsi->dns_results_next = wsi->dns_results_next->ai_next;
	}

	lwsl_err("%s: unable to create INET socket\n", __func__);
	lws_addrinfo_clean(wsi);

bail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "adopt udp2 fail");

	return NULL;
}

struct lws *
lws_create_adopt_udp(struct lws_vhost *vhost, const char *ads, int port,
		     int flags, const char *protocol_name,
		     struct lws *parent_wsi)
{
#if !defined(LWS_PLAT_OPTEE)
	struct lws *wsi;

	lwsl_info("%s: %s:%u\n", __func__, ads ? ads : "null", port);

	/* create the logical wsi without any valid fd */

	wsi = lws_adopt_descriptor_vhost1(vhost, LWS_ADOPT_RAW_SOCKET_UDP,
						 protocol_name, parent_wsi);
	if (!wsi) {
		lwsl_err("%s: udp wsi creation failed\n", __func__);
		goto bail;
	}
	wsi->do_bind = !!(flags & LWS_CAUDP_BIND);
	wsi->c_port = port;

#if !defined(LWS_WITH_SYS_ASYNC_DNS)
	{
		struct addrinfo *r, h;
		char buf[16];
		int n;

		memset(&h, 0, sizeof(h));
		h.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
		h.ai_socktype = SOCK_DGRAM;
		h.ai_protocol = IPPROTO_UDP;
		h.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
		h.ai_flags |= AI_ADDRCONFIG;
#endif

		/* if the dns lookup is synchronous, do the whole thing now */
		lws_snprintf(buf, sizeof(buf), "%u", port);
		n = getaddrinfo(ads, buf, &h, &r);
		if (n) {
#if !defined(LWS_PLAT_FREERTOS)
			lwsl_info("%s: getaddrinfo error: %s\n", __func__,
				  gai_strerror(n));
#else
			lwsl_info("%s: getaddrinfo error: %s\n", __func__,
					strerror(n));
#endif
			freeaddrinfo(r);
			goto bail1;
		}
		/* complete it immediately after the blocking dns lookup
		 * finished... free r when connect either completed or failed */
		wsi = lws_create_adopt_udp2(wsi, ads, r, 0, NULL);

		return wsi;
	}
#else
	if (ads) {
		/*
		 * with async dns, use the wsi as the point about which to do
		 * the dns lookup and have it call the second part when it's
		 * done.
		 *
		 * Keep a refcount on the results and free it when we connected
		 * or definitively failed.
		 */
		if (lws_async_dns_query(vhost->context, 0, ads,
					LWS_ADNS_RECORD_A,
					lws_create_adopt_udp2, wsi, NULL) ==
							     LADNS_RET_FAILED) {
			lwsl_err("%s: async dns failed\n", __func__);
			wsi = NULL;
			/*
			 * It was already closed by calling callback with error
			 * from lws_async_dns_query()
			 */
			goto bail;
		}
	} else
		wsi = lws_create_adopt_udp2(wsi, ads, NULL, 0, NULL);

	/* dns lookup is happening asynchronously */

	return wsi;
#endif
#if !defined(LWS_WITH_SYS_ASYNC_DNS)
bail1:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "adopt udp2 fail");
#endif
bail:
	return wsi;
#else
	return NULL;
#endif
}
#endif

LWS_VISIBLE struct lws *
lws_adopt_socket_readbuf(struct lws_context *context, lws_sockfd_type accept_fd,
			 const char *readbuf, size_t len)
{
        return adopt_socket_readbuf(lws_adopt_socket(context, accept_fd),
				    readbuf, len);
}

LWS_VISIBLE struct lws *
lws_adopt_socket_vhost_readbuf(struct lws_vhost *vhost,
			       lws_sockfd_type accept_fd,
			       const char *readbuf, size_t len)
{
        return adopt_socket_readbuf(lws_adopt_socket_vhost(vhost, accept_fd),
				    readbuf, len);
}
