/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
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


void
__lws_free_wsi(struct lws *wsi)
{
	if (!wsi)
		return;

	/*
	 * Protocol user data may be allocated either internally by lws
	 * or by specified the user. We should only free what we allocated.
	 */
	if (wsi->protocol && wsi->protocol->per_session_data_size &&
	    wsi->user_space && !wsi->user_space_externally_allocated)
		lws_free(wsi->user_space);

	lws_buflist_destroy_all_segments(&wsi->buflist);
	lws_buflist_destroy_all_segments(&wsi->buflist_out);
	lws_free_set_NULL(wsi->udp);

	if (wsi->vhost && wsi->vhost->lserv_wsi == wsi)
		wsi->vhost->lserv_wsi = NULL;
#if !defined(LWS_NO_CLIENT)
	if (wsi->vhost)
		lws_dll2_remove(&wsi->dll_cli_active_conns);
#endif
	wsi->context->count_wsi_allocated--;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	__lws_header_table_detach(wsi, 0);
#endif
	__lws_same_vh_protocol_remove(wsi);
#if !defined(LWS_NO_CLIENT)
	lws_client_stash_destroy(wsi);
	lws_free_set_NULL(wsi->cli_hostname_copy);
#endif

	if (wsi->role_ops->destroy_role)
		wsi->role_ops->destroy_role(wsi);

#if defined(LWS_WITH_PEER_LIMITS)
	lws_peer_track_wsi_close(wsi->context, wsi->peer);
	wsi->peer = NULL;
#endif

	/* since we will destroy the wsi, make absolutely sure now */

#if defined(LWS_WITH_OPENSSL)
	__lws_ssl_remove_wsi_from_buffered_list(wsi);
#endif
	__lws_wsi_remove_from_sul(wsi);

	if (wsi->context->event_loop_ops->destroy_wsi)
		wsi->context->event_loop_ops->destroy_wsi(wsi);

	lws_vhost_unbind_wsi(wsi);

	lwsl_debug("%s: %p, remaining wsi %d\n", __func__, wsi,
			wsi->context->count_wsi_allocated);

	lws_free(wsi);
}


void
lws_remove_child_from_any_parent(struct lws *wsi)
{
	struct lws **pwsi;
	int seen = 0;

	if (!wsi->parent)
		return;

	/* detach ourselves from parent's child list */
	pwsi = &wsi->parent->child_list;
	while (*pwsi) {
		if (*pwsi == wsi) {
			lwsl_info("%s: detach %p from parent %p\n", __func__,
				  wsi, wsi->parent);

			if (wsi->parent->protocol)
				wsi->parent->protocol->callback(wsi,
						LWS_CALLBACK_CHILD_CLOSING,
					       wsi->parent->user_space, wsi, 0);

			*pwsi = wsi->sibling_list;
			seen = 1;
			break;
		}
		pwsi = &(*pwsi)->sibling_list;
	}
	if (!seen)
		lwsl_err("%s: failed to detach from parent\n", __func__);

	wsi->parent = NULL;
}

#if !defined(LWS_NO_CLIENT)
static int
lws_close_trans_q_leader(struct lws_dll2 *d, void *user)
{
	struct lws *w = lws_container_of(d, struct lws, dll2_cli_txn_queue);

	__lws_close_free_wsi(w, -1, "trans q leader closing");

	return 0;
}

void
lws_inform_client_conn_fail(struct lws *wsi, void *arg, size_t len)
{
	if (wsi->already_did_cce)
		return;

	wsi->already_did_cce = 1;
	lws_stats_bump(&wsi->context->pt[(int)wsi->tsi],
		       LWSSTATS_C_CONNS_CLIENT_FAILED, 1);

	if (!wsi->protocol)
		return;

	wsi->protocol->callback(wsi,
			        LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
				wsi->user_space, arg, len);
}
#endif

void
__lws_close_free_wsi(struct lws *wsi, enum lws_close_status reason,
		     const char *caller)
{
	struct lws_context_per_thread *pt;
	struct lws *wsi1, *wsi2;
	struct lws_context *context;
#if !defined(LWS_NO_CLIENT)
	long rl = (long)(int)reason;
#endif
	int n;

	lwsl_info("%s: %p: caller: %s\n", __func__, wsi, caller);

	if (!wsi)
		return;

	lws_access_log(wsi);

	context = wsi->context;
	pt = &context->pt[(int)wsi->tsi];
	lws_stats_bump(pt, LWSSTATS_C_API_CLOSE, 1);

#if !defined(LWS_NO_CLIENT)

	lws_free_set_NULL(wsi->cli_hostname_copy);

	/*
	 * if we have wsi in our transaction queue, if we are closing we
	 * must go through and close all those first
	 */
	if (wsi->vhost) {

		/* we are no longer an active client connection that can piggyback */
		lws_dll2_remove(&wsi->dll_cli_active_conns);

		if (rl != -1l)
			lws_vhost_lock(wsi->vhost);

		lws_dll2_foreach_safe(&wsi->dll2_cli_txn_queue_owner, NULL,
				      lws_close_trans_q_leader);

		/*
		 * !!! If we are closing, but we have pending pipelined
		 * transaction results we already sent headers for, that's going
		 * to destroy sync for HTTP/1 and leave H2 stream with no live
		 * swsi.`
		 *
		 * However this is normal if we are being closed because the
		 * transaction queue leader is closing.
		 */
		lws_dll2_remove(&wsi->dll2_cli_txn_queue);
		if (rl != -1l)
			lws_vhost_unlock(wsi->vhost);
	}
#endif

	/* if we have children, close them first */
	if (wsi->child_list) {
		wsi2 = wsi->child_list;
		while (wsi2) {
			wsi1 = wsi2->sibling_list;
			wsi2->parent = NULL;
			/* stop it doing shutdown processing */
			wsi2->socket_is_permanently_unusable = 1;
			__lws_close_free_wsi(wsi2, reason,
					     "general child recurse");
			wsi2 = wsi1;
		}
		wsi->child_list = NULL;
	}

	if (wsi->role_ops == &role_ops_raw_file) {
		lws_remove_child_from_any_parent(wsi);
		__remove_wsi_socket_from_fds(wsi);
		if (wsi->protocol)
			wsi->protocol->callback(wsi, wsi->role_ops->close_cb[0],
					wsi->user_space, NULL, 0);
		goto async_close;
	}

	wsi->wsistate_pre_close = wsi->wsistate;

#ifdef LWS_WITH_CGI
	if (wsi->role_ops == &role_ops_cgi) {

		// lwsl_debug("%s: closing stdwsi index %d\n", __func__, (int)wsi->cgi_channel);

		/* we are not a network connection, but a handler for CGI io */
		if (wsi->parent && wsi->parent->http.cgi) {

			if (wsi->parent->child_list == wsi && !wsi->sibling_list)
				lws_cgi_remove_and_kill(wsi->parent);

			/* end the binding between us and master */
			wsi->parent->http.cgi->stdwsi[(int)wsi->cgi_channel] =
									NULL;
		}
		wsi->socket_is_permanently_unusable = 1;

		goto just_kill_connection;
	}

	if (wsi->http.cgi)
		lws_cgi_remove_and_kill(wsi);
#endif

#if !defined(LWS_NO_CLIENT)
	lws_client_stash_destroy(wsi);
#endif

	if (wsi->role_ops == &role_ops_raw_skt) {
		wsi->socket_is_permanently_unusable = 1;
		goto just_kill_connection;
	}
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (lwsi_role_http(wsi) && lwsi_role_server(wsi) &&
	    wsi->http.fop_fd != NULL)
		lws_vfs_file_close(&wsi->http.fop_fd);
#endif

	if (lwsi_state(wsi) == LRS_DEAD_SOCKET)
		return;

	if (wsi->socket_is_permanently_unusable ||
	    reason == LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY ||
	    lwsi_state(wsi) == LRS_SHUTDOWN)
		goto just_kill_connection;

	switch (lwsi_state_PRE_CLOSE(wsi)) {
	case LRS_DEAD_SOCKET:
		return;

	/* we tried the polite way... */
	case LRS_WAITING_TO_SEND_CLOSE:
	case LRS_AWAITING_CLOSE_ACK:
	case LRS_RETURNED_CLOSE:
		goto just_kill_connection;

	case LRS_FLUSHING_BEFORE_CLOSE:
		if (lws_has_buffered_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
		    || wsi->http.comp_ctx.buflist_comp ||
		    wsi->http.comp_ctx.may_have_more
#endif
		 ) {
			lws_callback_on_writable(wsi);
			return;
		}
		lwsl_info("%p: end LRS_FLUSHING_BEFORE_CLOSE\n", wsi);
		goto just_kill_connection;
	default:
		if (lws_has_buffered_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
				|| wsi->http.comp_ctx.buflist_comp ||
		    wsi->http.comp_ctx.may_have_more
#endif
		) {
			lwsl_info("%p: LRS_FLUSHING_BEFORE_CLOSE\n", wsi);
			lwsi_set_state(wsi, LRS_FLUSHING_BEFORE_CLOSE);
			__lws_set_timeout(wsi,
				PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE, 5);
			return;
		}
		break;
	}

	if (lwsi_state(wsi) == LRS_WAITING_CONNECT ||
	    lwsi_state(wsi) == LRS_H1C_ISSUE_HANDSHAKE)
		goto just_kill_connection;

	if (!wsi->told_user_closed && wsi->user_space && wsi->protocol &&
	    wsi->protocol_bind_balance) {
		wsi->protocol->callback(wsi,
				wsi->role_ops->protocol_unbind_cb[
				       !!lwsi_role_server(wsi)],
				       wsi->user_space, (void *)__func__, 0);
		wsi->protocol_bind_balance = 0;
	}

	/*
	 * signal we are closing, lws_write will
	 * add any necessary version-specific stuff.  If the write fails,
	 * no worries we are closing anyway.  If we didn't initiate this
	 * close, then our state has been changed to
	 * LRS_RETURNED_CLOSE and we will skip this.
	 *
	 * Likewise if it's a second call to close this connection after we
	 * sent the close indication to the peer already, we are in state
	 * LRS_AWAITING_CLOSE_ACK and will skip doing this a second time.
	 */

	if (wsi->role_ops->close_via_role_protocol &&
	    wsi->role_ops->close_via_role_protocol(wsi, reason))
		return;

just_kill_connection:

#if defined(LWS_WITH_FILE_OPS) && (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))
       if (lwsi_role_http(wsi) && lwsi_role_server(wsi) &&
           wsi->http.fop_fd != NULL)
	       lws_vfs_file_close(&wsi->http.fop_fd);
#endif

#if defined(LWS_WITH_HTTP_PROXY)
	if (wsi->http.buflist_post_body)
		lws_buflist_destroy_all_segments(&wsi->http.buflist_post_body);
#endif

	if (wsi->role_ops->close_kill_connection)
		wsi->role_ops->close_kill_connection(wsi, reason);

	n = 0;

	if (!wsi->told_user_closed && wsi->user_space &&
	    wsi->protocol_bind_balance && wsi->protocol) {
		lwsl_debug("%s: %p: DROP_PROTOCOL %s\n", __func__, wsi,
			   wsi->protocol ? wsi->protocol->name: "NULL");
		if (wsi->protocol)
			wsi->protocol->callback(wsi,
				wsi->role_ops->protocol_unbind_cb[
				       !!lwsi_role_server(wsi)],
				       wsi->user_space, (void *)__func__, 0);
		wsi->protocol_bind_balance = 0;
	}

#if !defined(LWS_NO_CLIENT)
	if ((lwsi_state(wsi) == LRS_WAITING_SERVER_REPLY ||
	     lwsi_state(wsi) == LRS_WAITING_CONNECT) &&
	     !wsi->already_did_cce && wsi->protocol) {
		static const char _reason[] = "closed before established";

		lws_inform_client_conn_fail(wsi,
			(void *)_reason, sizeof(_reason));
	}
#endif

	/*
	 * Testing with ab shows that we have to stage the socket close when
	 * the system is under stress... shutdown any further TX, change the
	 * state to one that won't emit anything more, and wait with a timeout
	 * for the POLLIN to show a zero-size rx before coming back and doing
	 * the actual close.
	 */
	if (wsi->role_ops != &role_ops_raw_skt && !lwsi_role_client(wsi) &&
	    lwsi_state(wsi) != LRS_SHUTDOWN &&
	    lwsi_state(wsi) != LRS_UNCONNECTED &&
	    reason != LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY &&
	    !wsi->socket_is_permanently_unusable) {

#if defined(LWS_WITH_TLS)
		if (lws_is_ssl(wsi) && wsi->tls.ssl) {
			n = 0;
			switch (__lws_tls_shutdown(wsi)) {
			case LWS_SSL_CAPABLE_DONE:
			case LWS_SSL_CAPABLE_ERROR:
			case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
			case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
			case LWS_SSL_CAPABLE_MORE_SERVICE:
				break;
			}
		} else
#endif
		{
			lwsl_info("%s: shutdown conn: %p (sk %d, state 0x%x)\n",
				  __func__, wsi, (int)(long)wsi->desc.sockfd,
				  lwsi_state(wsi));
			if (!wsi->socket_is_permanently_unusable &&
			    lws_socket_is_valid(wsi->desc.sockfd)) {
				wsi->socket_is_permanently_unusable = 1;
				n = shutdown(wsi->desc.sockfd, SHUT_WR);
			}
		}
		if (n)
			lwsl_debug("closing: shutdown (state 0x%x) ret %d\n",
				   lwsi_state(wsi), LWS_ERRNO);

		/*
		 * This causes problems on WINCE / ESP32 with disconnection
		 * when the events are half closing connection
		 */
#if !defined(_WIN32_WCE) && !defined(LWS_WITH_ESP32)
		/* libuv: no event available to guarantee completion */
		if (!wsi->socket_is_permanently_unusable &&
		    lws_socket_is_valid(wsi->desc.sockfd) &&
		    lwsi_state(wsi) != LRS_SHUTDOWN &&
		    context->event_loop_ops->periodic_events_available) {
			__lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN);
			lwsi_set_state(wsi, LRS_SHUTDOWN);
			__lws_set_timeout(wsi, PENDING_TIMEOUT_SHUTDOWN_FLUSH,
					  context->timeout_secs);

			return;
		}
#endif
	}

	lwsl_debug("%s: real just_kill_connection: %p (sockfd %d)\n", __func__,
		   wsi, wsi->desc.sockfd);

#ifdef LWS_WITH_HUBBUB
	if (wsi->http.rw) {
		lws_rewrite_destroy(wsi->http.rw);
		wsi->http.rw = NULL;
	}
#endif

	if (wsi->http.pending_return_headers)
		lws_free_set_NULL(wsi->http.pending_return_headers);

	/*
	 * we won't be servicing or receiving anything further from this guy
	 * delete socket from the internal poll list if still present
	 */
	__lws_ssl_remove_wsi_from_buffered_list(wsi);
	__lws_wsi_remove_from_sul(wsi);

	//if (wsi->told_event_loop_closed) // cgi std close case (dummy-callback)
	//	return;

	// lwsl_notice("%s: wsi %p, fd %d\n", __func__, wsi, wsi->desc.sockfd);

	/* checking return redundant since we anyway close */
	if (wsi->desc.sockfd != LWS_SOCK_INVALID)
		__remove_wsi_socket_from_fds(wsi);
	else
		__lws_same_vh_protocol_remove(wsi);

	lwsi_set_state(wsi, LRS_DEAD_SOCKET);
	lws_buflist_destroy_all_segments(&wsi->buflist);
	lws_dll2_remove(&wsi->dll_buflist);

	if (wsi->role_ops->close_role)
	    wsi->role_ops->close_role(pt, wsi);

	/* tell the user it's all over for this guy */

	if ((lwsi_state_est_PRE_CLOSE(wsi) ||
	    /* raw skt adopted but didn't complete tls hs should CLOSE */
	    (wsi->role_ops == &role_ops_raw_skt && !lwsi_role_client(wsi)) ||
	     lwsi_state_PRE_CLOSE(wsi) == LRS_WAITING_SERVER_REPLY) &&
	    !wsi->told_user_closed &&
	    wsi->role_ops->close_cb[lwsi_role_server(wsi)]) {
		const struct lws_protocols *pro = wsi->protocol;

		if (!wsi->protocol && wsi->vhost && wsi->vhost->protocols)
			pro = &wsi->vhost->protocols[0];

		if (pro && (!wsi->upgraded_to_http2 || !lwsi_role_client(wsi)))
			/*
			 * The network wsi for a client h2 connection shouldn't
			 * call back for its role: the child stream connections
			 * own the role.  Otherwise h2 will call back closed
			 * one too many times as the children do it and then
			 * the closing network stream.
			 */
			pro->callback(wsi,
			      wsi->role_ops->close_cb[lwsi_role_server(wsi)],
			      wsi->user_space, NULL, 0);
		wsi->told_user_closed = 1;
	}

async_close:
	lws_remove_child_from_any_parent(wsi);
	wsi->socket_is_permanently_unusable = 1;

	if (wsi->context->event_loop_ops->wsi_logical_close)
		if (wsi->context->event_loop_ops->wsi_logical_close(wsi))
			return;

	__lws_close_free_wsi_final(wsi);
}

void
__lws_close_free_wsi_final(struct lws *wsi)
{
	int n;

	if (!wsi->shadow &&
	    lws_socket_is_valid(wsi->desc.sockfd) && !lws_ssl_close(wsi)) {
		lwsl_debug("%s: wsi %p: fd %d\n", __func__, wsi, wsi->desc.sockfd);
		n = compatible_close(wsi->desc.sockfd);
		if (n)
			lwsl_debug("closing: close ret %d\n", LWS_ERRNO);

		wsi->desc.sockfd = LWS_SOCK_INVALID;
	}

	/* outermost destroy notification for wsi (user_space still intact) */
	if (wsi->vhost)
		wsi->vhost->protocols[0].callback(wsi, LWS_CALLBACK_WSI_DESTROY,
						  wsi->user_space, NULL, 0);

#ifdef LWS_WITH_CGI
	if (wsi->http.cgi) {

		for (n = 0; n < 3; n++) {
			if (wsi->http.cgi->pipe_fds[n][!!(n == 0)] == 0)
				lwsl_err("ZERO FD IN CGI CLOSE");

			if (wsi->http.cgi->pipe_fds[n][!!(n == 0)] >= 0) {
				close(wsi->http.cgi->pipe_fds[n][!!(n == 0)]);
				wsi->http.cgi->pipe_fds[n][!!(n == 0)] = LWS_SOCK_INVALID;
			}
		}

		lws_free_set_NULL(wsi->http.cgi);
	}
#endif

	__lws_free_wsi(wsi);
}


void
lws_close_free_wsi(struct lws *wsi, enum lws_close_status reason, const char *caller)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);
	__lws_close_free_wsi(wsi, reason, caller);
	lws_pt_unlock(pt);
}


