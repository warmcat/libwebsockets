/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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

#ifdef LWS_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#endif

int log_level = LLL_ERR | LLL_WARN | LLL_NOTICE;
static void (*lwsl_emit)(int level, const char *line) = lwsl_emit_stderr;

static const char * const log_level_names[] = {
	"ERR",
	"WARN",
	"NOTICE",
	"INFO",
	"DEBUG",
	"PARSER",
	"HEADER",
	"EXTENSION",
	"CLIENT",
	"LATENCY",
};

void
lws_free_wsi(struct lws *wsi)
{
	if (!wsi)
		return;

	/* Protocol user data may be allocated either internally by lws
	 * or by specified the user.
	 * We should only free what we allocated. */
	if (wsi->protocol && wsi->protocol->per_session_data_size &&
	    wsi->user_space && !wsi->user_space_externally_allocated)
		lws_free(wsi->user_space);

	lws_free_set_NULL(wsi->rxflow_buffer);
	lws_free_set_NULL(wsi->trunc_alloc);

	if (wsi->u.hdr.ah)
		/* we're closing, losing some rx is OK */
		wsi->u.hdr.ah->rxpos = wsi->u.hdr.ah->rxlen;

	/* we may not have an ah, but may be on the waiting list... */
	lws_header_table_detach(wsi, 0);

	wsi->context->count_wsi_allocated--;
	lwsl_debug("%s: %p, remaining wsi %d\n", __func__, wsi,
			wsi->context->count_wsi_allocated);

	lws_free(wsi);
}

static void
lws_remove_from_timeout_list(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	if (!wsi->timeout_list_prev) /* ie, not part of the list */
		return;

	lws_pt_lock(pt);
	/* if we have a next guy, set his prev to our prev */
	if (wsi->timeout_list)
		wsi->timeout_list->timeout_list_prev = wsi->timeout_list_prev;
	/* set our prev guy to our next guy instead of us */
	*wsi->timeout_list_prev = wsi->timeout_list;

	/* we're out of the list, we should not point anywhere any more */
	wsi->timeout_list_prev = NULL;
	wsi->timeout_list = NULL;
	lws_pt_unlock(pt);
}

/**
 * lws_set_timeout() - marks the wsi as subject to a timeout
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 * @reason:	timeout reason
 * @secs:	how many seconds
 */

LWS_VISIBLE void
lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	time_t now;

	lws_pt_lock(pt);

	time(&now);

	if (reason && !wsi->timeout_list_prev) {
		/* our next guy is current first guy */
		wsi->timeout_list = pt->timeout_list;
		/* if there is a next guy, set his prev ptr to our next ptr */
		if (wsi->timeout_list)
			wsi->timeout_list->timeout_list_prev = &wsi->timeout_list;
		/* our prev ptr is first ptr */
		wsi->timeout_list_prev = &pt->timeout_list;
		/* set the first guy to be us */
		*wsi->timeout_list_prev = wsi;
	}

	lwsl_debug("%s: %p: %d secs\n", __func__, wsi, secs);
	wsi->pending_timeout_limit = now + secs;
	wsi->pending_timeout = reason;

	lws_pt_unlock(pt);

	if (!reason)
		lws_remove_from_timeout_list(wsi);
}

void
lws_close_free_wsi(struct lws *wsi, enum lws_close_status reason)
{
	struct lws_context_per_thread *pt;
	struct lws **pwsi, *wsi1, *wsi2;
	struct lws_context *context;
	struct lws_tokens eff_buf;
	int n, m, ret;

	if (!wsi)
		return;

	context = wsi->context;
	pt = &context->pt[(int)wsi->tsi];

	/* if we have children, close them first */
	if (wsi->child_list) {
		wsi2 = wsi->child_list;
		while (wsi2) {
			//lwsl_notice("%s: closing %p: close child %p\n",
			//		__func__, wsi, wsi2);
			wsi1 = wsi2->sibling_list;
			//lwsl_notice("%s: closing %p: next sibling %p\n",
			//		__func__, wsi2, wsi1);
			wsi2->parent = NULL;
			/* stop it doing shutdown processing */
			wsi2->socket_is_permanently_unusable = 1;
			lws_close_free_wsi(wsi2, reason);
			wsi2 = wsi1;
		}
		wsi->child_list = NULL;
	}

#ifdef LWS_WITH_CGI
	if (wsi->mode == LWSCM_CGI) {
		/* we are not a network connection, but a handler for CGI io */
		if (wsi->parent && wsi->parent->cgi)
		/* end the binding between us and master */
		wsi->parent->cgi->stdwsi[(int)wsi->cgi_channel] = NULL;
		wsi->socket_is_permanently_unusable = 1;

		goto just_kill_connection;
	}

	if (wsi->cgi) {
		/* we have a cgi going, we must kill it */
		wsi->cgi->being_closed = 1;
		lws_cgi_kill(wsi);
	}
#endif

	if (wsi->mode == LWSCM_HTTP_SERVING_ACCEPTED &&
	    wsi->u.http.fd != LWS_INVALID_FILE) {
		lws_plat_file_close(wsi, wsi->u.http.fd);
		wsi->u.http.fd = LWS_INVALID_FILE;
		context->protocols[0].callback(wsi, LWS_CALLBACK_CLOSED_HTTP,
					       wsi->user_space, NULL, 0);
	}
	if (wsi->socket_is_permanently_unusable ||
	    reason == LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY ||
	    wsi->state == LWSS_SHUTDOWN)
		goto just_kill_connection;

	wsi->state_pre_close = wsi->state;

	switch (wsi->state_pre_close) {
	case LWSS_DEAD_SOCKET:
		return;

	/* we tried the polite way... */
	case LWSS_AWAITING_CLOSE_ACK:
		goto just_kill_connection;

	case LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE:
		if (wsi->trunc_len) {
			lws_callback_on_writable(wsi);
			return;
		}
		lwsl_info("wsi %p completed LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE\n", wsi);
		goto just_kill_connection;
	default:
		if (wsi->trunc_len) {
			lwsl_info("wsi %p entering LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE\n", wsi);
			wsi->state = LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE;
			lws_set_timeout(wsi, PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE, 5);
			return;
		}
		break;
	}

	if (wsi->mode == LWSCM_WSCL_WAITING_CONNECT ||
	    wsi->mode == LWSCM_WSCL_ISSUE_HANDSHAKE)
		goto just_kill_connection;

	if (wsi->mode == LWSCM_HTTP_SERVING)
		context->protocols[0].callback(wsi, LWS_CALLBACK_CLOSED_HTTP,
					       wsi->user_space, NULL, 0);
	if (wsi->mode == LWSCM_HTTP_CLIENT)
		context->protocols[0].callback(wsi, LWS_CALLBACK_CLOSED_CLIENT_HTTP,
					       wsi->user_space, NULL, 0);

	/*
	 * are his extensions okay with him closing?  Eg he might be a mux
	 * parent and just his ch1 aspect is closing?
	 */

	if (lws_ext_cb_active(wsi,
		      LWS_EXT_CB_CHECK_OK_TO_REALLY_CLOSE, NULL, 0) > 0) {
		lwsl_ext("extension vetoed close\n");
		return;
	}

	/*
	 * flush any tx pending from extensions, since we may send close packet
	 * if there are problems with send, just nuke the connection
	 */

	do {
		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* show every extension the new incoming data */

		m = lws_ext_cb_active(wsi,
			  LWS_EXT_CB_FLUSH_PENDING_TX, &eff_buf, 0);
		if (m < 0) {
			lwsl_ext("Extension reports fatal error\n");
			goto just_kill_connection;
		}
		if (m)
			/*
			 * at least one extension told us he has more
			 * to spill, so we will go around again after
			 */
			ret = 1;

		/* assuming they left us something to send, send it */

		if (eff_buf.token_len)
			if (lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
					  eff_buf.token_len) !=
			    eff_buf.token_len) {
				lwsl_debug("close: ext spill failed\n");
				goto just_kill_connection;
			}
	} while (ret);

	/*
	 * signal we are closing, lws_write will
	 * add any necessary version-specific stuff.  If the write fails,
	 * no worries we are closing anyway.  If we didn't initiate this
	 * close, then our state has been changed to
	 * LWSS_RETURNED_CLOSE_ALREADY and we will skip this.
	 *
	 * Likewise if it's a second call to close this connection after we
	 * sent the close indication to the peer already, we are in state
	 * LWSS_AWAITING_CLOSE_ACK and will skip doing this a second time.
	 */

	if (wsi->state_pre_close == LWSS_ESTABLISHED &&
	    (wsi->u.ws.close_in_ping_buffer_len || /* already a reason */
	     (reason != LWS_CLOSE_STATUS_NOSTATUS &&
	     (reason != LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY)))) {
		lwsl_debug("sending close indication...\n");

		/* if no prepared close reason, use 1000 and no aux data */
		if (!wsi->u.ws.close_in_ping_buffer_len) {
			wsi->u.ws.close_in_ping_buffer_len = 2;
			wsi->u.ws.ping_payload_buf[LWS_PRE] =
				(reason >> 16) & 0xff;
			wsi->u.ws.ping_payload_buf[LWS_PRE + 1] =
				reason & 0xff;
		}

		n = lws_write(wsi, &wsi->u.ws.ping_payload_buf[LWS_PRE],
			      wsi->u.ws.close_in_ping_buffer_len,
			      LWS_WRITE_CLOSE);
		if (n >= 0) {
			/*
			 * we have sent a nice protocol level indication we
			 * now wish to close, we should not send anything more
			 */
			wsi->state = LWSS_AWAITING_CLOSE_ACK;

			/*
			 * ...and we should wait for a reply for a bit
			 * out of politeness
			 */
			lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_ACK, 1);
			lwsl_debug("sent close indication, awaiting ack\n");

			return;
		}

		lwsl_info("close: sending close packet failed, hanging up\n");

		/* else, the send failed and we should just hang up */
	}

just_kill_connection:
	if (wsi->parent) {
		/* detach ourselves from parent's child list */
		pwsi = &wsi->parent->child_list;
		while (*pwsi) {
			if (*pwsi == wsi) {
				lwsl_notice("%s: detach %p from parent %p\n",
						__func__, wsi, wsi->parent);
				*pwsi = wsi->sibling_list;
				break;
			}
			pwsi = &(*pwsi)->sibling_list;
		}
		if (*pwsi)
			lwsl_err("%s: failed to detach from parent\n",
					__func__);
	}

#if LWS_POSIX
	/*
	 * Testing with ab shows that we have to stage the socket close when
	 * the system is under stress... shutdown any further TX, change the
	 * state to one that won't emit anything more, and wait with a timeout
	 * for the POLLIN to show a zero-size rx before coming back and doing
	 * the actual close.
	 */
	if (wsi->state != LWSS_SHUTDOWN &&
	    reason != LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY &&
	    !wsi->socket_is_permanently_unusable) {
		lwsl_info("%s: shutting down connection: %p (sock %d)\n", __func__, wsi, wsi->sock);
		n = shutdown(wsi->sock, SHUT_WR);
		if (n)
			lwsl_debug("closing: shutdown ret %d\n", LWS_ERRNO);

// This causes problems with disconnection when the events are half closing connection
// FD_READ | FD_CLOSE (33)
#ifndef _WIN32_WCE
		/* libuv: no event available to guarantee completion */
		if (!LWS_LIBUV_ENABLED(context)) {

			lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN);
			wsi->state = LWSS_SHUTDOWN;
			lws_set_timeout(wsi, PENDING_TIMEOUT_SHUTDOWN_FLUSH,
					context->timeout_secs);
			return;
		}
#endif
	}
#endif

	lwsl_info("%s: real just_kill_connection: %p (sockfd %d)\n", __func__,
		  wsi, wsi->sock);
#ifdef LWS_WITH_HTTP_PROXY
	if (wsi->rw) {
		lws_rewrite_destroy(wsi->rw);
		wsi->rw = NULL;
	}
#endif
	/*
	 * we won't be servicing or receiving anything further from this guy
	 * delete socket from the internal poll list if still present
	 */
	lws_ssl_remove_wsi_from_buffered_list(wsi);
	lws_remove_from_timeout_list(wsi);

	/* checking return redundant since we anyway close */
	remove_wsi_socket_from_fds(wsi);

	wsi->state = LWSS_DEAD_SOCKET;

	lws_free_set_NULL(wsi->rxflow_buffer);

	if (wsi->state_pre_close == LWSS_ESTABLISHED ||
	    wsi->mode == LWSCM_WS_SERVING ||
	    wsi->mode == LWSCM_WS_CLIENT) {

		if (wsi->u.ws.rx_draining_ext) {
			struct lws **w = &pt->rx_draining_ext_list;

			wsi->u.ws.rx_draining_ext = 0;
			/* remove us from context draining ext list */
			while (*w) {
				if (*w == wsi) {
					*w = wsi->u.ws.rx_draining_ext_list;
					break;
				}
				w = &((*w)->u.ws.rx_draining_ext_list);
			}
			wsi->u.ws.rx_draining_ext_list = NULL;
		}

		if (wsi->u.ws.tx_draining_ext) {
			struct lws **w = &pt->tx_draining_ext_list;

			wsi->u.ws.tx_draining_ext = 0;
			/* remove us from context draining ext list */
			while (*w) {
				if (*w == wsi) {
					*w = wsi->u.ws.tx_draining_ext_list;
					break;
				}
				w = &((*w)->u.ws.tx_draining_ext_list);
			}
			wsi->u.ws.tx_draining_ext_list = NULL;
		}
		lws_free_set_NULL(wsi->u.ws.rx_ubuf);

		if (wsi->trunc_alloc)
			/* not going to be completed... nuke it */
			lws_free_set_NULL(wsi->trunc_alloc);

		wsi->u.ws.ping_payload_len = 0;
		wsi->u.ws.ping_pending_flag = 0;
	}

	/* tell the user it's all over for this guy */

	if (wsi->protocol && wsi->protocol->callback &&
	    ((wsi->state_pre_close == LWSS_ESTABLISHED) ||
	    (wsi->state_pre_close == LWSS_RETURNED_CLOSE_ALREADY) ||
	    (wsi->state_pre_close == LWSS_AWAITING_CLOSE_ACK) ||
	    (wsi->state_pre_close == LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE) ||
	    (wsi->mode == LWSCM_WS_CLIENT && wsi->state_pre_close == LWSS_HTTP) ||
	    (wsi->mode == LWSCM_WS_SERVING && wsi->state_pre_close == LWSS_HTTP))) {
		lwsl_debug("calling back CLOSED\n");
		wsi->protocol->callback(wsi, LWS_CALLBACK_CLOSED,
					wsi->user_space, NULL, 0);
	} else if (wsi->mode == LWSCM_HTTP_SERVING_ACCEPTED) {
		lwsl_debug("calling back CLOSED_HTTP\n");
		context->protocols[0].callback(wsi, LWS_CALLBACK_CLOSED_HTTP,
					       wsi->user_space, NULL, 0 );
	} else if (wsi->mode == LWSCM_WSCL_WAITING_SERVER_REPLY ||
		   wsi->mode == LWSCM_WSCL_WAITING_CONNECT) {
		lwsl_debug("Connection closed before server reply\n");
		context->protocols[0].callback(wsi,
					LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
					wsi->user_space, NULL, 0);
	} else
		lwsl_debug("not calling back closed mode=%d state=%d\n",
			   wsi->mode, wsi->state_pre_close);

	/* deallocate any active extension contexts */

	if (lws_ext_cb_active(wsi, LWS_EXT_CB_DESTROY, NULL, 0) < 0)
		lwsl_warn("extension destruction failed\n");
	/*
	 * inform all extensions in case they tracked this guy out of band
	 * even though not active on him specifically
	 */
	if (lws_ext_cb_all_exts(context, wsi,
		       LWS_EXT_CB_DESTROY_ANY_WSI_CLOSING, NULL, 0) < 0)
		lwsl_warn("ext destroy wsi failed\n");

	wsi->socket_is_permanently_unusable = 1;

#ifdef LWS_USE_LIBUV
	if (LWS_LIBUV_ENABLED(context)) {
		/* libuv has to do his own close handle processing asynchronously */
		lws_libuv_closehandle(wsi);

		return;
	}
#endif

	lws_close_free_wsi_final(wsi);
}

void
lws_close_free_wsi_final(struct lws *wsi)
{
	int n;

	if (!lws_ssl_close(wsi) && lws_socket_is_valid(wsi->sock)) {
#if LWS_POSIX
		//lwsl_err("*** closing sockfd %d\n", wsi->sock);
		n = compatible_close(wsi->sock);
		if (n)
			lwsl_debug("closing: close ret %d\n", LWS_ERRNO);

#else
		compatible_close(wsi->sock);
#endif
		wsi->sock = LWS_SOCK_INVALID;
	}

	/* outermost destroy notification for wsi (user_space still intact) */
	wsi->context->protocols[0].callback(wsi, LWS_CALLBACK_WSI_DESTROY,
				       wsi->user_space, NULL, 0);

	lws_free_wsi(wsi);
}

#if LWS_POSIX
LWS_VISIBLE int
interface_to_sa(struct lws_context *context, const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	int ipv6 = 0;
#ifdef LWS_USE_IPV6
	ipv6 = LWS_IPV6_ENABLED(context);
#endif
	(void)context;

	return lws_interface_to_sa(ipv6, ifname, addr, addrlen);
}
#endif

LWS_VISIBLE int
lws_get_addresses(struct lws_context *context, void *ads, char *name,
		  int name_len, char *rip, int rip_len)
{
#if LWS_POSIX
	struct addrinfo ai, *res;
	struct sockaddr_in addr4;

	if (rip)
		rip[0] = '\0';
	name[0] = '\0';
	addr4.sin_family = AF_UNSPEC;

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context)) {
		if (!lws_plat_inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ads)->sin6_addr, rip, rip_len)) {
			lwsl_err("inet_ntop", strerror(LWS_ERRNO));
			return -1;
		}

		// Strip off the IPv4 to IPv6 header if one exists
		if (strncmp(rip, "::ffff:", 7) == 0)
			memmove(rip, rip + 7, strlen(rip) - 6);

		getnameinfo((struct sockaddr *)ads,
				sizeof(struct sockaddr_in6), name,
							name_len, NULL, 0, 0);

		return 0;
	} else
#endif
	{
		struct addrinfo *result;

		memset(&ai, 0, sizeof ai);
		ai.ai_family = PF_UNSPEC;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_flags = AI_CANONNAME;

		if (getnameinfo((struct sockaddr *)ads,
				sizeof(struct sockaddr_in),
				name, name_len, NULL, 0, 0))
			return -1;

		if (!rip)
			return 0;

		if (getaddrinfo(name, NULL, &ai, &result))
			return -1;

		res = result;
		while (addr4.sin_family == AF_UNSPEC && res) {
			switch (res->ai_family) {
			case AF_INET:
				addr4.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
				addr4.sin_family = AF_INET;
				break;
			}

			res = res->ai_next;
		}
		freeaddrinfo(result);
	}

	if (addr4.sin_family == AF_UNSPEC)
		return -1;

	if (lws_plat_inet_ntop(AF_INET, &addr4.sin_addr, rip, rip_len) == NULL)
		return -1;

	return 0;
#else
	(void)context;
	(void)ads;
	(void)name;
	(void)name_len;
	(void)rip;
	(void)rip_len;

	return -1;
#endif
}

/**
 * lws_get_peer_addresses() - Get client address information
 * @wsi:	Local struct lws associated with
 * @fd:		Connection socket descriptor
 * @name:	Buffer to take client address name
 * @name_len:	Length of client address name buffer
 * @rip:	Buffer to take client address IP dotted quad
 * @rip_len:	Length of client address IP buffer
 *
 *	This function fills in @name and @rip with the name and IP of
 *	the client connected with socket descriptor @fd.  Names may be
 *	truncated if there is not enough room.  If either cannot be
 *	determined, they will be returned as valid zero-length strings.
 */

LWS_VISIBLE void
lws_get_peer_addresses(struct lws *wsi, lws_sockfd_type fd, char *name,
		       int name_len, char *rip, int rip_len)
{
#if LWS_POSIX
	socklen_t len;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin4;
	struct lws_context *context = wsi->context;
	int ret = -1;
	void *p;

	rip[0] = '\0';
	name[0] = '\0';

	lws_latency_pre(context, wsi);

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context)) {
		len = sizeof(sin6);
		p = &sin6;
	} else
#endif
	{
		len = sizeof(sin4);
		p = &sin4;
	}

	if (getpeername(fd, p, &len) < 0) {
		lwsl_warn("getpeername: %s\n", strerror(LWS_ERRNO));
		goto bail;
	}

	ret = lws_get_addresses(context, p, name, name_len, rip, rip_len);

bail:
	lws_latency(context, wsi, "lws_get_peer_addresses", ret, 1);
#else
	(void)wsi;
	(void)fd;
	(void)name;
	(void)name_len;
	(void)rip;
	(void)rip_len;
#endif
}

/**
 * lws_context_user() - get the user data associated with the context
 * @context: Websocket context
 *
 *	This returns the optional user allocation that can be attached to
 *	the context the sockets live in at context_create time.  It's a way
 *	to let all sockets serviced in the same context share data without
 *	using globals statics in the user code.
 */
LWS_EXTERN void *
lws_context_user(struct lws_context *context)
{
	return context->user_space;
}


/**
 * lws_callback_all_protocol() - Callback all connections using
 *				the given protocol with the given reason
 *
 * @protocol:	Protocol whose connections will get callbacks
 * @reason:	Callback reason index
 */

LWS_VISIBLE int
lws_callback_all_protocol(struct lws_context *context,
			  const struct lws_protocols *protocol, int reason)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	unsigned int n, m = context->count_threads;
	struct lws *wsi;

	while (m--) {
		for (n = 0; n < pt->fds_count; n++) {
			wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->protocol == protocol)
				protocol->callback(wsi, reason, wsi->user_space,
						   NULL, 0);
		}
		pt++;
	}

	return 0;
}

#if LWS_POSIX

/**
 * lws_get_socket_fd() - returns the socket file descriptor
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 */

LWS_VISIBLE int
lws_get_socket_fd(struct lws *wsi)
{
	return wsi->sock;
}

#endif

#ifdef LWS_LATENCY
void
lws_latency(struct lws_context *context, struct lws *wsi, const char *action,
	    int ret, int completed)
{
	unsigned long long u;
	char buf[256];

	u = time_in_microseconds();

	if (!action) {
		wsi->latency_start = u;
		if (!wsi->action_start)
			wsi->action_start = u;
		return;
	}
	if (completed) {
		if (wsi->action_start == wsi->latency_start)
			sprintf(buf,
			  "Completion first try lat %lluus: %p: ret %d: %s\n",
					u - wsi->latency_start,
						      (void *)wsi, ret, action);
		else
			sprintf(buf,
			  "Completion %lluus: lat %lluus: %p: ret %d: %s\n",
				u - wsi->action_start,
					u - wsi->latency_start,
						      (void *)wsi, ret, action);
		wsi->action_start = 0;
	} else
		sprintf(buf, "lat %lluus: %p: ret %d: %s\n",
			      u - wsi->latency_start, (void *)wsi, ret, action);

	if (u - wsi->latency_start > context->worst_latency) {
		context->worst_latency = u - wsi->latency_start;
		strcpy(context->worst_latency_info, buf);
	}
	lwsl_latency("%s", buf);
}
#endif



/**
 * lws_rx_flow_control() - Enable and disable socket servicing for
 *				received packets.
 *
 * If the output side of a server process becomes choked, this allows flow
 * control for the input side.
 *
 * @wsi:	Websocket connection instance to get callback for
 * @enable:	0 = disable read servicing for this connection, 1 = enable
 */

LWS_VISIBLE int
lws_rx_flow_control(struct lws *wsi, int enable)
{
	if (enable == (wsi->rxflow_change_to & LWS_RXFLOW_ALLOW))
		return 0;

	lwsl_info("%s: (0x%p, %d)\n", __func__, wsi, enable);
	wsi->rxflow_change_to = LWS_RXFLOW_PENDING_CHANGE | !!enable;

	return 0;
}

/**
 * lws_rx_flow_allow_all_protocol() - Allow all connections with this protocol to receive
 *
 * When the user server code realizes it can accept more input, it can
 * call this to have the RX flow restriction removed from all connections using
 * the given protocol.
 *
 * @protocol:	all connections using this protocol will be allowed to receive
 */

LWS_VISIBLE void
lws_rx_flow_allow_all_protocol(const struct lws_context *context,
			       const struct lws_protocols *protocol)
{
	const struct lws_context_per_thread *pt = &context->pt[0];
	struct lws *wsi;
	unsigned int n, m = context->count_threads;

	while (m--) {
		for (n = 0; n < pt->fds_count; n++) {
			wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->protocol == protocol)
				lws_rx_flow_control(wsi, LWS_RXFLOW_ALLOW);
		}
		pt++;
	}
}


/**
 * lws_canonical_hostname() - returns this host's hostname
 *
 * This is typically used by client code to fill in the host parameter
 * when making a client connection.  You can only call it after the context
 * has been created.
 *
 * @context:	Websocket context
 */
LWS_VISIBLE extern const char *
lws_canonical_hostname(struct lws_context *context)
{
	return (const char *)context->canonical_hostname;
}

int user_callback_handle_rxflow(lws_callback_function callback_function,
				struct lws *wsi,
				enum lws_callback_reasons reason, void *user,
				void *in, size_t len)
{
	int n;

	n = callback_function(wsi, reason, user, in, len);
	if (!n)
		n = _lws_rx_flow_control(wsi);

	return n;
}


/**
 * lws_set_proxy() - Setups proxy to lws_context.
 * @context:	pointer to struct lws_context you want set proxy to
 * @proxy: pointer to c string containing proxy in format address:port
 *
 * Returns 0 if proxy string was parsed and proxy was setup.
 * Returns -1 if @proxy is NULL or has incorrect format.
 *
 * This is only required if your OS does not provide the http_proxy
 * environment variable (eg, OSX)
 *
 *   IMPORTANT! You should call this function right after creation of the
 *   lws_context and before call to connect. If you call this
 *   function after connect behavior is undefined.
 *   This function will override proxy settings made on lws_context
 *   creation with genenv() call.
 */

LWS_VISIBLE int
lws_set_proxy(struct lws_context *context, const char *proxy)
{
	char *p;
	char authstring[96];

	if (!proxy)
		return -1;

	p = strchr(proxy, '@');
	if (p) { /* auth is around */

		if ((unsigned int)(p - proxy) > sizeof(authstring) - 1)
			goto auth_too_long;

		strncpy(authstring, proxy, p - proxy);
		// null termination not needed on input
		if (lws_b64_encode_string(authstring, (p - proxy),
		    context->proxy_basic_auth_token,
		    sizeof context->proxy_basic_auth_token) < 0)
			goto auth_too_long;

		lwsl_notice(" Proxy auth in use\n");

		proxy = p + 1;
	} else
		context->proxy_basic_auth_token[0] = '\0';

	strncpy(context->http_proxy_address, proxy,
				sizeof(context->http_proxy_address) - 1);
	context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';

	p = strchr(context->http_proxy_address, ':');
	if (!p && !context->http_proxy_port) {
		lwsl_err("http_proxy needs to be ads:port\n");

		return -1;
	} else {
		if (p) {
			*p = '\0';
			context->http_proxy_port = atoi(p + 1);
		}
	}

	lwsl_notice(" Proxy %s:%u\n", context->http_proxy_address,
						context->http_proxy_port);

	return 0;

auth_too_long:
	lwsl_err("proxy auth too long\n");

	return -1;
}

/**
 * lws_get_protocol() - Returns a protocol pointer from a websocket
 *				  connection.
 * @wsi:	pointer to struct websocket you want to know the protocol of
 *
 *
 *	Some apis can act on all live connections of a given protocol,
 *	this is how you can get a pointer to the active protocol if needed.
 */

LWS_VISIBLE const struct lws_protocols *
lws_get_protocol(struct lws *wsi)
{
	return wsi->protocol;
}

LWS_VISIBLE int
lws_is_final_fragment(struct lws *wsi)
{
	lwsl_info("%s: final %d, rx pk length %d, draining %d", __func__,
			wsi->u.ws.final, wsi->u.ws.rx_packet_length,
			wsi->u.ws.rx_draining_ext);
	return wsi->u.ws.final && !wsi->u.ws.rx_packet_length && !wsi->u.ws.rx_draining_ext;
}

LWS_VISIBLE unsigned char
lws_get_reserved_bits(struct lws *wsi)
{
	return wsi->u.ws.rsv;
}

int
lws_ensure_user_space(struct lws *wsi)
{
	lwsl_info("%s: %p protocol %p\n", __func__, wsi, wsi->protocol);
	if (!wsi->protocol)
		return 1;

	/* allocate the per-connection user memory (if any) */

	if (wsi->protocol->per_session_data_size && !wsi->user_space) {
		wsi->user_space = lws_zalloc(wsi->protocol->per_session_data_size);
		if (wsi->user_space  == NULL) {
			lwsl_err("Out of memory for conn user space\n");
			return 1;
		}
	} else
		lwsl_info("%s: %p protocol pss %u, user_space=%d\n",
			  __func__, wsi, wsi->protocol->per_session_data_size,
			  wsi->user_space);
	return 0;
}

/**
 * lwsl_timestamp: generate logging timestamp string
 *
 * @level:	logging level
 * @p:		char * buffer to take timestamp
 * @len:	length of p
 *
 * returns length written in p
 */
LWS_VISIBLE int
lwsl_timestamp(int level, char *p, int len)
{
	time_t o_now = time(NULL);
	unsigned long long now;
	struct tm *ptm = NULL;
#ifndef WIN32
	struct tm tm;
#endif
	int n;

#ifndef _WIN32_WCE
#ifdef WIN32
	ptm = localtime(&o_now);
#else
	if (localtime_r(&o_now, &tm))
		ptm = &tm;
#endif
#endif
	p[0] = '\0';
	for (n = 0; n < LLL_COUNT; n++) {
		if (level != (1 << n))
			continue;
		now = time_in_microseconds() / 100;
		if (ptm)
			n = snprintf(p, len,
				"[%04d/%02d/%02d %02d:%02d:%02d:%04d] %s: ",
				ptm->tm_year + 1900,
				ptm->tm_mon,
				ptm->tm_mday,
				ptm->tm_hour,
				ptm->tm_min,
				ptm->tm_sec,
				(int)(now % 10000), log_level_names[n]);
		else
			n = snprintf(p, len, "[%llu:%04d] %s: ",
					(unsigned long long) now / 10000,
					(int)(now % 10000), log_level_names[n]);
		return n;
	}

	return 0;
}

LWS_VISIBLE void lwsl_emit_stderr(int level, const char *line)
{
	char buf[50];

	lwsl_timestamp(level, buf, sizeof(buf));

	fprintf(stderr, "%s%s", buf, line);
}

LWS_VISIBLE void _lws_logv(int filter, const char *format, va_list vl)
{
	char buf[256];

	if (!(log_level & filter))
		return;

	vsnprintf(buf, sizeof(buf), format, vl);
	buf[sizeof(buf) - 1] = '\0';

	lwsl_emit(filter, buf);
}

LWS_VISIBLE void _lws_log(int filter, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	_lws_logv(filter, format, ap);
	va_end(ap);
}

/**
 * lws_set_log_level() - Set the logging bitfield
 * @level:	OR together the LLL_ debug contexts you want output from
 * @log_emit_function:	NULL to leave it as it is, or a user-supplied
 *			function to perform log string emission instead of
 *			the default stderr one.
 *
 *	log level defaults to "err", "warn" and "notice" contexts enabled and
 *	emission on stderr.
 */

LWS_VISIBLE void lws_set_log_level(int level,
				   void (*func)(int level, const char *line))
{
	log_level = level;
	if (func)
		lwsl_emit = func;
}

/**
 * lws_use_ssl() - Find out if connection is using SSL
 * @wsi:	websocket connection to check
 *
 *	Returns 0 if the connection is not using SSL, 1 if using SSL and
 *	using verified cert, and 2 if using SSL but the cert was not
 *	checked (appears for client wsi told to skip check on connection)
 */
LWS_VISIBLE int
lws_is_ssl(struct lws *wsi)
{
#ifdef LWS_OPENSSL_SUPPORT
	return wsi->use_ssl;
#else
	(void)wsi;
	return 0;
#endif
}

/**
 * lws_partial_buffered() - find out if lws buffered the last write
 * @wsi:	websocket connection to check
 *
 * Returns 1 if you cannot use lws_write because the last
 * write on this connection is still buffered, and can't be cleared without
 * returning to the service loop and waiting for the connection to be
 * writeable again.
 *
 * If you will try to do >1 lws_write call inside a single
 * WRITEABLE callback, you must check this after every write and bail if
 * set, ask for a new writeable callback and continue writing from there.
 *
 * This is never set at the start of a writeable callback, but any write
 * may set it.
 */

LWS_VISIBLE int
lws_partial_buffered(struct lws *wsi)
{
	return !!wsi->trunc_len;
}

void lws_set_protocol_write_pending(struct lws *wsi,
				    enum lws_pending_protocol_send pend)
{
	lwsl_info("setting pps %d\n", pend);

	if (wsi->pps)
		lwsl_err("pps overwrite\n");
	wsi->pps = pend;
	lws_rx_flow_control(wsi, 0);
	lws_callback_on_writable(wsi);
}

LWS_VISIBLE size_t
lws_get_peer_write_allowance(struct lws *wsi)
{
#ifdef LWS_USE_HTTP2
	/* only if we are using HTTP2 on this connection */
	if (wsi->mode != LWSCM_HTTP2_SERVING)
		return -1;
	/* user is only interested in how much he can send, or that he can't  */
	if (wsi->u.http2.tx_credit <= 0)
		return 0;

	return wsi->u.http2.tx_credit;
#else
	(void)wsi;
	return -1;
#endif
}

LWS_VISIBLE void
lws_union_transition(struct lws *wsi, enum connection_mode mode)
{
	lwsl_debug("%s: %p: mode %d\n", __func__, wsi, mode);
	memset(&wsi->u, 0, sizeof(wsi->u));
	wsi->mode = mode;
}

LWS_VISIBLE struct lws_plat_file_ops *
lws_get_fops(struct lws_context *context)
{
	return &context->fops;
}

LWS_VISIBLE LWS_EXTERN struct lws_context *
lws_get_context(const struct lws *wsi)
{
	return wsi->context;
}

LWS_VISIBLE LWS_EXTERN int
lws_get_count_threads(struct lws_context *context)
{
	return context->count_threads;
}

LWS_VISIBLE LWS_EXTERN void *
lws_wsi_user(struct lws *wsi)
{
	return wsi->user_space;
}

LWS_VISIBLE LWS_EXTERN struct lws *
lws_get_parent(const struct lws *wsi)
{
	return wsi->parent;
}

LWS_VISIBLE LWS_EXTERN struct lws *
lws_get_child(const struct lws *wsi)
{
	return wsi->child_list;
}

LWS_VISIBLE LWS_EXTERN void
lws_close_reason(struct lws *wsi, enum lws_close_status status,
		 unsigned char *buf, size_t len)
{
	unsigned char *p, *start;
	int budget = sizeof(wsi->u.ws.ping_payload_buf) - LWS_PRE;

	assert(wsi->mode == LWSCM_WS_SERVING || wsi->mode == LWSCM_WS_CLIENT);

	start = p = &wsi->u.ws.ping_payload_buf[LWS_PRE];

	*p++ = (((int)status) >> 8) & 0xff;
	*p++ = ((int)status) & 0xff;

	if (buf)
		while (len-- && p < start + budget)
			*p++ = *buf++;

	wsi->u.ws.close_in_ping_buffer_len = p - start;
}

LWS_EXTERN int
_lws_rx_flow_control(struct lws *wsi)
{
	/* there is no pending change */
	if (!(wsi->rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE)) {
		lwsl_debug("%s: no pending change\n", __func__);
		return 0;
	}

	/* stuff is still buffered, not ready to really accept new input */
	if (wsi->rxflow_buffer) {
		/* get ourselves called back to deal with stashed buffer */
		lws_callback_on_writable(wsi);
		return 0;
	}

	/* pending is cleared, we can change rxflow state */

	wsi->rxflow_change_to &= ~LWS_RXFLOW_PENDING_CHANGE;

	lwsl_info("rxflow: wsi %p change_to %d\n", wsi,
			      wsi->rxflow_change_to & LWS_RXFLOW_ALLOW);

	/* adjust the pollfd for this wsi */

	if (wsi->rxflow_change_to & LWS_RXFLOW_ALLOW) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: fail\n", __func__);
			return -1;
		}
	} else
		if (lws_change_pollfd(wsi, LWS_POLLIN, 0))
			return -1;

	return 0;
}

LWS_EXTERN int
lws_check_utf8(unsigned char *state, unsigned char *buf, size_t len)
{
	static const unsigned char e0f4[] = {
		0xa0 | ((2 - 1) << 2) | 1, /* e0 */
		0x80 | ((4 - 1) << 2) | 1, /* e1 */
		0x80 | ((4 - 1) << 2) | 1, /* e2 */
		0x80 | ((4 - 1) << 2) | 1, /* e3 */
		0x80 | ((4 - 1) << 2) | 1, /* e4 */
		0x80 | ((4 - 1) << 2) | 1, /* e5 */
		0x80 | ((4 - 1) << 2) | 1, /* e6 */
		0x80 | ((4 - 1) << 2) | 1, /* e7 */
		0x80 | ((4 - 1) << 2) | 1, /* e8 */
		0x80 | ((4 - 1) << 2) | 1, /* e9 */
		0x80 | ((4 - 1) << 2) | 1, /* ea */
		0x80 | ((4 - 1) << 2) | 1, /* eb */
		0x80 | ((4 - 1) << 2) | 1, /* ec */
		0x80 | ((2 - 1) << 2) | 1, /* ed */
		0x80 | ((4 - 1) << 2) | 1, /* ee */
		0x80 | ((4 - 1) << 2) | 1, /* ef */
		0x90 | ((3 - 1) << 2) | 2, /* f0 */
		0x80 | ((4 - 1) << 2) | 2, /* f1 */
		0x80 | ((4 - 1) << 2) | 2, /* f2 */
		0x80 | ((4 - 1) << 2) | 2, /* f3 */
		0x80 | ((1 - 1) << 2) | 2, /* f4 */

		0,			   /* s0 */
		0x80 | ((4 - 1) << 2) | 0, /* s2 */
		0x80 | ((4 - 1) << 2) | 1, /* s3 */
	};
	unsigned char s = *state;

	while (len--) {
		unsigned char c = *buf++;

		if (!s) {
			if (c >= 0x80) {
				if (c < 0xc2 || c > 0xf4)
					return 1;
				if (c < 0xe0)
					s = 0x80 | ((4 - 1) << 2);
				else
					s = e0f4[c - 0xe0];
			}
		} else {
			if (c < (s & 0xf0) ||
			    c >= (s & 0xf0) + 0x10 + ((s << 2) & 0x30))
				return 1;
			s = e0f4[21 + (s & 3)];
		}
	}

	*state = s;

	return 0;
}

/**
 * lws_parse_uri:	cut up prot:/ads:port/path into pieces
 *			Notice it does so by dropping '\0' into input string
 *			and the leading / on the path is consequently lost
 *
 * @p:			incoming uri string.. will get written to
 * @prot:		result pointer for protocol part (https://)
 * @ads:		result pointer for address part
 * @port:		result pointer for port part
 * @path:		result pointer for path part
 */

LWS_VISIBLE LWS_EXTERN int
lws_parse_uri(char *p, const char **prot, const char **ads, int *port,
	      const char **path)
{
	const char *end;
	static const char *slash = "/";

	/* cut up the location into address, port and path */
	*prot = p;
	while (*p && (*p != ':' || p[1] != '/' || p[2] != '/'))
		p++;
	if (!*p) {
		end = p;
		p = (char *)*prot;
		*prot = end;
	} else {
		*p = '\0';
		p += 3;
	}
	*ads = p;
	if (!strcmp(*prot, "http") || !strcmp(*prot, "ws"))
		*port = 80;
	else if (!strcmp(*prot, "https") || !strcmp(*prot, "wss"))
		*port = 443;

	while (*p && *p != ':' && *p != '/')
		p++;
	if (*p == ':') {
		*p++ = '\0';
		*port = atoi(p);
		while (*p && *p != '/')
			p++;
	}
	*path = slash;
	if (*p) {
		*p++ = '\0';
		if (*p)
			*path = p;
	}

	return 0;
}

#ifdef LWS_NO_EXTENSIONS

/* we need to provide dummy callbacks for internal exts
 * so user code runs when faced with a lib compiled with
 * extensions disabled.
 */

int
lws_extension_callback_pm_deflate(struct lws_context *context,
                                  const struct lws_extension *ext,
                                  struct lws *wsi,
                                  enum lws_extension_callback_reasons reason,
                                  void *user, void *in, size_t len)
{
	(void)context;
	(void)ext;
	(void)wsi;
	(void)reason;
	(void)user;
	(void)in;
	(void)len;

	return 0;
}
#endif

LWS_EXTERN int
lws_socket_bind(struct lws_context *context, int sockfd, int port,
		const char *iface)
{
#if LWS_POSIX
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 serv_addr6;
#endif
	struct sockaddr_in serv_addr4;
	socklen_t len = sizeof(struct sockaddr);
	int n;
	struct sockaddr_in sin;
	struct sockaddr *v;

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context)) {
		v = (struct sockaddr *)&serv_addr6;
		n = sizeof(struct sockaddr_in6);
		bzero((char *) &serv_addr6, sizeof(serv_addr6));
		serv_addr6.sin6_addr = in6addr_any;
		serv_addr6.sin6_family = AF_INET6;
		serv_addr6.sin6_port = htons(port);
	} else
#endif
	{
		v = (struct sockaddr *)&serv_addr4;
		n = sizeof(serv_addr4);
		bzero((char *) &serv_addr4, sizeof(serv_addr4));
		serv_addr4.sin_addr.s_addr = INADDR_ANY;
		serv_addr4.sin_family = AF_INET;

		if (iface &&
		    interface_to_sa(context, iface,
				    (struct sockaddr_in *)v, n) < 0) {
			lwsl_err("Unable to find interface %s\n", iface);
			return -1;
		}

		serv_addr4.sin_port = htons(port);
	} /* ipv4 */

	n = bind(sockfd, v, n);
	if (n < 0) {
		lwsl_err("ERROR on binding to port %d (%d %d)\n",
					      port, n, LWS_ERRNO);
		return -1;
	}

	if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
		lwsl_warn("getsockname: %s\n", strerror(LWS_ERRNO));
	else
		port = ntohs(sin.sin_port);
#endif

	return port;
}

LWS_VISIBLE LWS_EXTERN int
lws_urlencode(const char *in, int inlen, char *out, int outlen)
{
	const char *hex = "0123456789ABCDEF";
	char *start = out, *end = out + outlen;

	while (inlen-- && out > end - 4) {
		if ((*in >= 'A' && *in <= 'Z') ||
		    (*in >= 'a' && *in <= 'z') ||
		    (*in >= '0' && *in <= '9') ||
		    *in == '-' ||
		    *in == '_' ||
		    *in == '.' ||
		    *in == '~')
			*out++ = *in++;
		else {
			*out++ = '%';
			*out++ = hex[(*in) >> 4];
			*out++ = hex[(*in++) & 15];
		}
	}
	*out = '\0';

	if (out >= end - 4)
		return -1;

	return out - start;
}

LWS_VISIBLE LWS_EXTERN int
lws_is_cgi(struct lws *wsi) {
#ifdef LWS_WITH_CGI
	return !!wsi->cgi;
#else
	return 0;
#endif
}

#ifdef LWS_WITH_CGI

static struct lws *
lws_create_basic_wsi(struct lws_context *context, int tsi)
{
	struct lws *new_wsi;

	if ((unsigned int)context->pt[tsi].fds_count ==
	    context->fd_limit_per_thread - 1) {
		lwsl_err("no space for new conn\n");
		return NULL;
	}

	new_wsi = lws_zalloc(sizeof(struct lws));
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->tsi = tsi;
	new_wsi->context = context;
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;
	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/* intialize the instance struct */

	new_wsi->state = LWSS_CGI;
	new_wsi->mode = LWSCM_CGI;
	new_wsi->hdr_parsing_completed = 0;
	new_wsi->position_in_fds_table = -1;

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = context->protocols;
	new_wsi->user_space = NULL;
	new_wsi->ietf_spec_revision = 0;
	new_wsi->sock = LWS_SOCK_INVALID;
	context->count_wsi_allocated++;

	return new_wsi;
}

/**
 * lws_cgi: spawn network-connected cgi process
 *
 * @wsi: connection to own the process
 * @exec_array: array of "exec-name" "arg1" ... "argn" NULL
 */

LWS_VISIBLE LWS_EXTERN int
lws_cgi(struct lws *wsi, char * const *exec_array, int script_uri_path_len,
	int timeout_secs)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char *env_array[30], cgi_path[400], e[1024], *p = e,
	     *end = p + sizeof(e) - 1, tok[256];
	struct lws_cgi *cgi;
	int n, m, i;

	/*
	 * give the master wsi a cgi struct
	 */

	wsi->cgi = lws_zalloc(sizeof(*wsi->cgi));
	if (!wsi->cgi) {
		lwsl_err("%s: OOM\n", __func__);
		return -1;
	}

	cgi = wsi->cgi;
	cgi->wsi = wsi; /* set cgi's owning wsi */

	/* create pipes for [stdin|stdout] and [stderr] */

	for (n = 0; n < 3; n++)
		if (pipe(cgi->pipe_fds[n]) == -1)
			goto bail1;

	/* create cgi wsis for each stdin/out/err fd */

	for (n = 0; n < 3; n++) {
		cgi->stdwsi[n] = lws_create_basic_wsi(wsi->context, wsi->tsi);
		if (!cgi->stdwsi[n])
			goto bail2;
		cgi->stdwsi[n]->cgi_channel = n;
		/* read side is 0, stdin we want the write side, others read */
		cgi->stdwsi[n]->sock = cgi->pipe_fds[n][!!(n == 0)];
		fcntl(cgi->pipe_fds[n][!!(n == 0)], F_SETFL, O_NONBLOCK);
	}

	for (n = 0; n < 3; n++) {
		if (insert_wsi_socket_into_fds(wsi->context, cgi->stdwsi[n]))
			goto bail3;
		cgi->stdwsi[n]->parent = wsi;
		cgi->stdwsi[n]->sibling_list = wsi->child_list;
		wsi->child_list = cgi->stdwsi[n];
	}

	lws_change_pollfd(cgi->stdwsi[LWS_STDIN], LWS_POLLIN, LWS_POLLOUT);
	lws_change_pollfd(cgi->stdwsi[LWS_STDOUT], LWS_POLLOUT, LWS_POLLIN);
	lws_change_pollfd(cgi->stdwsi[LWS_STDERR], LWS_POLLOUT, LWS_POLLIN);

	lwsl_debug("%s: fds in %d, out %d, err %d\n", __func__,
		   cgi->stdwsi[LWS_STDIN]->sock, cgi->stdwsi[LWS_STDOUT]->sock,
		   cgi->stdwsi[LWS_STDERR]->sock);

	lws_set_timeout(wsi, PENDING_TIMEOUT_CGI, timeout_secs);

	/* the cgi stdout is always sending us http1.x header data first */
	wsi->hdr_state = LCHS_HEADER;

	/* add us to the pt list of active cgis */
	cgi->cgi_list = pt->cgi_list;
	pt->cgi_list = cgi;

	/* prepare his CGI env */

	n = 0;

	if (lws_is_ssl(wsi))
		env_array[n++] = "HTTPS=ON";
	if (wsi->u.hdr.ah) {
		snprintf(cgi_path, sizeof(cgi_path) - 1, "REQUEST_URI=%s",
			 lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI));
		cgi_path[sizeof(cgi_path) - 1] = '\0';
		env_array[n++] = cgi_path;
		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
			env_array[n++] = "REQUEST_METHOD=POST";
		else
			env_array[n++] = "REQUEST_METHOD=GET";

		env_array[n++] = p;
		p += snprintf(p, end - p, "QUERY_STRING=");
		/* dump the individual URI Arg parameters */
		m = 0;
		while (1) {
			i = lws_hdr_copy_fragment(wsi, tok, sizeof(tok),
					     WSI_TOKEN_HTTP_URI_ARGS, m);
			if (i < 0)
				break;
			i = lws_urlencode(tok, i, p, end - p);
			p += i;
			*p++ = '&';
			m++;
		}
		if (m)
			p--;
		*p++ = '\0';

		env_array[n++] = p;
		p += snprintf(p, end - p, "PATH_INFO=%s",
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI) +
			      script_uri_path_len);
		p++;
	}
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_REFERER)) {
		env_array[n++] = p;
		p += snprintf(p, end - p, "HTTP_REFERER=%s",
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_REFERER));
		p++;
	}
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HOST)) {
		env_array[n++] = p;
		p += snprintf(p, end - p, "HTTP_HOST=%s",
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST));
		p++;
	}
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_USER_AGENT)) {
		env_array[n++] = p;
		p += snprintf(p, end - p, "USER_AGENT=%s",
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_USER_AGENT));
		p++;
	}
	env_array[n++] = p;
	p += snprintf(p, end - p, "SCRIPT_PATH=%s", exec_array[2]) + 1;

	env_array[n++] = "SERVER_SOFTWARE=libwebsockets";
	env_array[n++] = "PATH=/bin:/usr/bin:/usr/local/bin:/var/www/cgi-bin";
	env_array[n] = NULL;

#if 0
	for (m = 0; m < n; m++)
		lwsl_err("    %s\n", env_array[m]);
#endif

	/* we are ready with the redirection pipes... run the thing */
#if !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
	cgi->pid = fork();
#else
	cgi->pid = vfork();
#endif
	if (cgi->pid < 0) {
		lwsl_err("fork failed, errno %d", errno);
		goto bail3;
	}

	if (cgi->pid)
		/* we are the parent process */
		return 0;

	/* We are the forked process, redirect and kill inherited things.
	 *
	 * Because of vfork(), we cannot do anything that changes pages in
	 * the parent environment.  Stuff that changes kernel state for the
	 * process is OK.  Stuff that happens after the execvpe() is OK.
	 */

	for (n = 0; n < 3; n++) {
		if (dup2(cgi->pipe_fds[n][!(n == 0)], n) < 0) {
			lwsl_err("%s: stdin dup2 failed\n", __func__);
			goto bail3;
		}
		close(cgi->pipe_fds[n][!(n == 0)]);
	}

#if !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
	for (m = 0; m < n; m++) {
		p = strchr(env_array[m], '=');
		*p++ = '\0';
		setenv(env_array[m], p, 1);
	}
	execvp(exec_array[0], &exec_array[0]);
#else
	execvpe(exec_array[0], &exec_array[0], &env_array[0]);
#endif

	exit(1);

bail3:
	/* drop us from the pt cgi list */
	pt->cgi_list = cgi->cgi_list;

	while (--n >= 0)
		remove_wsi_socket_from_fds(wsi->cgi->stdwsi[n]);
bail2:
	for (n = 0; n < 3; n++)
		if (wsi->cgi->stdwsi[n])
			lws_free_wsi(cgi->stdwsi[n]);

bail1:
	for (n = 0; n < 3; n++) {
		if (cgi->pipe_fds[n][0])
			close(cgi->pipe_fds[n][0]);
		if (cgi->pipe_fds[n][1])
			close(cgi->pipe_fds[n][1]);
	}

	lws_free_set_NULL(wsi->cgi);

	lwsl_err("%s: failed\n", __func__);

	return -1;
}
/**
 * lws_cgi_write_split_headers: write cgi output accounting for header part
 *
 * @wsi: connection to own the process
 */
LWS_VISIBLE LWS_EXTERN int
lws_cgi_write_split_stdout_headers(struct lws *wsi)
{
	int n, m;
	char buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
	     *end = &buf[sizeof(buf) - 1 - LWS_PRE], c;

	while (wsi->hdr_state != LHCS_PAYLOAD) {
		/* we have to separate header / finalize and
		 * payload chunks, since they need to be
		 * handled separately
		 */
		n = read(lws_get_socket_fd(wsi->cgi->stdwsi[LWS_STDOUT]), &c, 1);
		if (n < 0) {
			if (errno != EAGAIN)
				return -1;
			else
				n = 0;
		}
		if (n) {
			//lwsl_err("-- %c\n", c);
			switch (wsi->hdr_state) {
			case LCHS_HEADER:
				*p++ = c;
				if (c == '\x0d') {
					wsi->hdr_state = LCHS_LF1;
					break;
				}
				break;
			case LCHS_LF1:
				*p++ = c;
				if (c == '\x0a') {
					wsi->hdr_state = LCHS_CR2;
					break;
				}
				/* we got \r[^\n]... it's unreasonable */
				return -1;
			case LCHS_CR2:
				if (c == '\x0d') {
					/* drop the \x0d */
					wsi->hdr_state = LCHS_LF2;
					break;
				}
				*p++ = c;
				break;
			case LCHS_LF2:
				if (c == '\x0a') {
					wsi->hdr_state = LHCS_PAYLOAD;
					/* drop the \0xa ... finalize will add it if needed */
					lws_finalize_http_header(wsi,
							(unsigned char **)&p,
							(unsigned char *)end);
					break;
				}
				/* we got \r\n\r[^\n]... it's unreasonable */
				return -1;
			case LHCS_PAYLOAD:
				break;
			}
		}

		/* ran out of input, ended the headers, or filled up the headers buf */
		if (!n || wsi->hdr_state == LHCS_PAYLOAD || (p + 4) == end) {

			m = lws_write(wsi, (unsigned char *)start,
				      p - start, LWS_WRITE_HTTP_HEADERS);
			if (m < 0)
				return -1;
			/* writeability becomes uncertain now we wrote
			 * something, we must return to the event loop
			 */

			return 0;
		}
	}
	//lwsl_err("%s: stdout\n", __func__);
	n = read(lws_get_socket_fd(wsi->cgi->stdwsi[LWS_STDOUT]),
		 start, sizeof(buf) - LWS_PRE);

	if (n < 0 && errno != EAGAIN)
		return -1;
	if (n > 0) {
		m = lws_write(wsi, (unsigned char *)start, n,
			      LWS_WRITE_HTTP);
		//lwsl_notice("write %d\n", m);
		if (m < 0)
			return -1;
	}

	return 0;
}

/**
 * lws_cgi_kill: terminate cgi process associated with wsi
 *
 * @wsi: connection to own the process
 */
LWS_VISIBLE LWS_EXTERN int
lws_cgi_kill(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws_cgi **pcgi = &pt->cgi_list;
	struct lws_cgi_args args;
	int n, status, do_close = 0;

	if (!wsi->cgi)
		return 0;

//	lwsl_notice("%s: wsi %p\n", __func__, wsi);

	assert(wsi->cgi);

	if (wsi->cgi->pid > 0) {
		/* kill the process */
		n = kill(wsi->cgi->pid, SIGTERM);
		if (n < 0) {
			lwsl_err("%s: failed\n", __func__);
			return 1;
		}
		waitpid(wsi->cgi->pid, &status, 0); /* !!! may hang !!! */
	}

	args.stdwsi = &wsi->cgi->stdwsi[0];

	if (wsi->cgi->pid != -1 && user_callback_handle_rxflow(
			wsi->protocol->callback,
			wsi, LWS_CALLBACK_CGI_TERMINATED,
			wsi->user_space,
			(void *)&args, 0)) {
		wsi->cgi->pid = -1;
		do_close = !wsi->cgi->being_closed;
	}

	/* remove us from the cgi list */
	while (*pcgi) {
		if (*pcgi == wsi->cgi) {
			/* drop us from the pt cgi list */
			*pcgi = (*pcgi)->cgi_list;
			break;
		}
		pcgi = &(*pcgi)->cgi_list;
	}

	for (n = 0 ; n < 3; n++) {
		if (wsi->cgi->pipe_fds[n][!!(n == 0)] >= 0) {
			close(wsi->cgi->pipe_fds[n][!!(n == 0)]);
			wsi->cgi->pipe_fds[n][!!(n == 0)] = -1;
		}
	}

	lws_free_set_NULL(wsi->cgi);

	if (do_close)
		lws_close_free_wsi(wsi, 0);

	return 0;
}

LWS_EXTERN int
lws_cgi_kill_terminated(struct lws_context_per_thread *pt)
{
	struct lws_cgi **pcgi = &pt->cgi_list, *cgi;
	int status;

	/* check all the subprocesses on the cgi list for termination */
	while (*pcgi) {
		/* get the next one because we may close current one next */
		cgi = *pcgi;
		pcgi = &(*pcgi)->cgi_list;

		if (cgi->pid > 0 &&
		    waitpid(cgi->pid, &status, WNOHANG) > 0) {
			cgi->pid = 0;
			lws_cgi_kill(cgi->wsi);
			pcgi = &pt->cgi_list;
		}
	}

	return 0;
}
#endif
