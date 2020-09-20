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

#if defined(LWS_WITH_CLIENT)
static int
lws_close_trans_q_leader(struct lws_dll2 *d, void *user)
{
	struct lws *w = lws_container_of(d, struct lws, dll2_cli_txn_queue);

	__lws_close_free_wsi(w, -1, "trans q leader closing");

	return 0;
}
#endif

void
__lws_reset_wsi(struct lws *wsi)
{
	if (!wsi)
		return;

#if defined(LWS_WITH_CLIENT)

	lws_free_set_NULL(wsi->cli_hostname_copy);

	/*
	 * if we have wsi in our transaction queue, if we are closing we
	 * must go through and close all those first
	 */
	if (wsi->a.vhost) {

		/* we are no longer an active client connection that can piggyback */
		lws_dll2_remove(&wsi->dll_cli_active_conns);

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
	}
#endif

	if (wsi->a.vhost) {
		lws_vhost_lock(wsi->a.vhost);
		lws_dll2_remove(&wsi->vh_awaiting_socket);
		lws_vhost_unlock(wsi->a.vhost);
	}

	/*
	 * Protocol user data may be allocated either internally by lws
	 * or by specified the user. We should only free what we allocated.
	 */
	if (wsi->a.protocol && wsi->a.protocol->per_session_data_size &&
	    wsi->user_space && !wsi->user_space_externally_allocated) {
		/* confirm no sul left scheduled in user data itself */
		lws_sul_debug_zombies(wsi->a.context, wsi->user_space,
				wsi->a.protocol->per_session_data_size, __func__);
		lws_free_set_NULL(wsi->user_space);
	}

	/*
	 * Don't let buflist content or state from the wsi's previous life
	 * carry over to the new life
	 */

	lws_buflist_destroy_all_segments(&wsi->buflist);
	lws_dll2_remove(&wsi->dll_buflist);
	lws_buflist_destroy_all_segments(&wsi->buflist_out);
#if defined(LWS_WITH_UDP)
	if (wsi->udp) {
		/* confirm no sul left scheduled in wsi->udp itself */
		lws_sul_debug_zombies(wsi->a.context, wsi->udp,
				      sizeof(*wsi->udp), "close udp wsi");
		lws_free_set_NULL(wsi->udp);
	}
#endif
	wsi->retry = 0;

#if defined(LWS_WITH_CLIENT)
	lws_dll2_remove(&wsi->dll2_cli_txn_queue);
	lws_dll2_remove(&wsi->dll_cli_active_conns);
#endif

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	lws_async_dns_cancel(wsi);
#endif

#if defined(LWS_WITH_HTTP_PROXY)
	if (wsi->http.buflist_post_body)
		lws_buflist_destroy_all_segments(&wsi->http.buflist_post_body);
#endif

	if (wsi->a.vhost && wsi->a.vhost->lserv_wsi == wsi)
		wsi->a.vhost->lserv_wsi = NULL;
#if defined(LWS_WITH_CLIENT)
	if (wsi->a.vhost)
		lws_dll2_remove(&wsi->dll_cli_active_conns);
#endif
	wsi->a.context->count_wsi_allocated--;

	__lws_same_vh_protocol_remove(wsi);
#if defined(LWS_WITH_CLIENT)
	lws_free_set_NULL(wsi->stash);
	lws_free_set_NULL(wsi->cli_hostname_copy);
#endif

#if defined(LWS_WITH_PEER_LIMITS)
	lws_peer_track_wsi_close(wsi->a.context, wsi->peer);
	wsi->peer = NULL;
#endif

	/* since we will destroy the wsi, make absolutely sure now */

#if defined(LWS_WITH_OPENSSL)
	__lws_ssl_remove_wsi_from_buffered_list(wsi);
#endif
	__lws_wsi_remove_from_sul(wsi);

	if (wsi->role_ops->destroy_role)
		wsi->role_ops->destroy_role(wsi);

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	__lws_header_table_detach(wsi, 0);
#endif
}

void
__lws_free_wsi(struct lws *wsi)
{
	if (!wsi)
		return;

	__lws_reset_wsi(wsi);
	__lws_wsi_remove_from_sul(wsi);

	if (wsi->a.context->event_loop_ops->destroy_wsi)
		wsi->a.context->event_loop_ops->destroy_wsi(wsi);

	lws_vhost_unbind_wsi(wsi);

	lwsl_debug("%s: %p, remaining wsi %d, tsi fds count %d\n", __func__, wsi,
			wsi->a.context->count_wsi_allocated,
			wsi->a.context->pt[(int)wsi->tsi].fds_count);

	/* confirm no sul left scheduled in wsi itself */
	lws_sul_debug_zombies(wsi->a.context, wsi, sizeof(wsi), __func__);

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

			if (wsi->parent->a.protocol)
				wsi->parent->a.protocol->callback(wsi,
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

#if defined(LWS_WITH_CLIENT)
void
lws_inform_client_conn_fail(struct lws *wsi, void *arg, size_t len)
{
	lws_addrinfo_clean(wsi);

	if (wsi->already_did_cce)
		return;

	wsi->already_did_cce = 1;
	lws_stats_bump(&wsi->a.context->pt[(int)wsi->tsi],
		       LWSSTATS_C_CONNS_CLIENT_FAILED, 1);

	if (!wsi->a.protocol)
		return;

	if (!wsi->client_suppress_CONNECTION_ERROR)
		wsi->a.protocol->callback(wsi,
					LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
					wsi->user_space, arg, len);
}
#endif

void
lws_addrinfo_clean(struct lws *wsi)
{
#if defined(LWS_WITH_CLIENT)
	struct lws_dll2 *d = lws_dll2_get_head(&wsi->dns_sorted_list), *d1;

	while (d) {
		lws_dns_sort_t *r = lws_container_of(d, lws_dns_sort_t, list);

		d1 = d->next;
		lws_dll2_remove(d);
		lws_free(r);

		d = d1;
	}
#endif
}

void
__lws_close_free_wsi(struct lws *wsi, enum lws_close_status reason,
		     const char *caller)
{
	struct lws_context_per_thread *pt;
	const struct lws_protocols *pro;
	struct lws_context *context;
	struct lws *wsi1, *wsi2;
	int n, ccb;

	lwsl_info("%s: %p: caller: %s\n", __func__, wsi, caller);

	if (!wsi)
		return;

	lws_access_log(wsi);

	if (!lws_dll2_is_detached(&wsi->dll_buflist)) {
		lwsl_info("%s: wsi %p: going down with stuff in buflist\n",
				__func__, wsi); }

	context = wsi->a.context;
	pt = &context->pt[(int)wsi->tsi];

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	if (wsi == context->async_dns.wsi)
		context->async_dns.wsi = NULL;
#endif

	lws_pt_assert_lock_held(pt);

	lws_stats_bump(pt, LWSSTATS_C_API_CLOSE, 1);

#if defined(LWS_WITH_CLIENT)

	lws_free_set_NULL(wsi->cli_hostname_copy);

	lws_addrinfo_clean(wsi);
#endif

#if defined(LWS_WITH_HTTP2)
	if (wsi->mux_stream_immortal)
		lws_http_close_immortal(wsi);
#endif

	/* if we have children, close them first */
	if (wsi->child_list) {
		wsi2 = wsi->child_list;
		while (wsi2) {
			wsi1 = wsi2->sibling_list;
//			wsi2->parent = NULL;
			/* stop it doing shutdown processing */
			wsi2->socket_is_permanently_unusable = 1;
			__lws_close_free_wsi(wsi2, reason,
					     "general child recurse");
			wsi2 = wsi1;
		}
		wsi->child_list = NULL;
	}

#if defined(LWS_ROLE_RAW_FILE)
	if (wsi->role_ops == &role_ops_raw_file) {
		lws_remove_child_from_any_parent(wsi);
		__remove_wsi_socket_from_fds(wsi);
		if (wsi->a.protocol)
			wsi->a.protocol->callback(wsi, wsi->role_ops->close_cb[0],
					wsi->user_space, NULL, 0);
		goto async_close;
	}
#endif

	wsi->wsistate_pre_close = wsi->wsistate;

#ifdef LWS_WITH_CGI
	if (wsi->role_ops == &role_ops_cgi) {

		// lwsl_debug("%s: closing stdwsi index %d\n", __func__, (int)wsi->lsp_channel);

		/* we are not a network connection, but a handler for CGI io */
		if (wsi->parent && wsi->parent->http.cgi) {

			/*
			 * We need to keep the logical cgi around so we can
			 * drain it
			 */

//			if (wsi->parent->child_list == wsi && !wsi->sibling_list)
//				lws_cgi_remove_and_kill(wsi->parent);

			/* end the binding between us and network connection */
			if (wsi->parent->http.cgi && wsi->parent->http.cgi->lsp)
				wsi->parent->http.cgi->lsp->stdwsi[(int)wsi->lsp_channel] =
									NULL;
		}
		wsi->socket_is_permanently_unusable = 1;

		goto just_kill_connection;
	}

	if (wsi->http.cgi)
		lws_cgi_remove_and_kill(wsi);
#endif

#if defined(LWS_WITH_CLIENT)
	lws_free_set_NULL(wsi->stash);
#endif

	if (wsi->role_ops == &role_ops_raw_skt) {
		wsi->socket_is_permanently_unusable = 1;
		goto just_kill_connection;
	}
#if defined(LWS_WITH_FILE_OPS) && (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))
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
	    lwsi_state(wsi) == LRS_WAITING_DNS ||
	    lwsi_state(wsi) == LRS_H1C_ISSUE_HANDSHAKE)
		goto just_kill_connection;

	if (!wsi->told_user_closed && wsi->user_space && wsi->a.protocol &&
	    wsi->protocol_bind_balance) {
		wsi->a.protocol->callback(wsi,
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

	lws_sul_cancel(&wsi->sul_connect_timeout);
#if defined(LWS_WITH_SYS_ASYNC_DNS)
	lws_async_dns_cancel(wsi);
#endif

#if defined(LWS_WITH_HTTP_PROXY)
	if (wsi->http.buflist_post_body)
		lws_buflist_destroy_all_segments(&wsi->http.buflist_post_body);
#endif
#if defined(LWS_WITH_UDP)
	if (wsi->udp) {
		/* confirm no sul left scheduled in wsi->udp itself */
		lws_sul_debug_zombies(wsi->a.context, wsi->udp,
					sizeof(*wsi->udp), "close udp wsi");

		lws_free_set_NULL(wsi->udp);
	}
#endif

	if (wsi->role_ops->close_kill_connection)
		wsi->role_ops->close_kill_connection(wsi, reason);

	n = 0;

	if (!wsi->told_user_closed && wsi->user_space &&
	    wsi->protocol_bind_balance && wsi->a.protocol) {
		lwsl_debug("%s: %p: DROP_PROTOCOL %s\n", __func__, wsi,
			   wsi->a.protocol ? wsi->a.protocol->name: "NULL");
		if (wsi->a.protocol)
			wsi->a.protocol->callback(wsi,
				wsi->role_ops->protocol_unbind_cb[
				       !!lwsi_role_server(wsi)],
				       wsi->user_space, (void *)__func__, 0);
		wsi->protocol_bind_balance = 0;
	}

#if defined(LWS_WITH_SECURE_STREAMS) && defined(LWS_WITH_SERVER)
	if (wsi->for_ss) {
		/*
		 * We were adopted for a particular ss, but, eg, we may not
		 * have succeeded with the connection... we are closing which is
		 * good, but we have to invalidate any pointer the related ss
		 * handle may be holding on us
		 */
		lws_ss_handle_t *h = (lws_ss_handle_t *)wsi->a.opaque_user_data;

		if (h) {
			h->wsi = NULL;
			wsi->a.opaque_user_data = NULL;
		}
	}
#endif

#if defined(LWS_WITH_CLIENT)
	if ((
#if defined(LWS_ROLE_WS)
		/*
		 * If our goal is a ws upgrade, effectively we did not reach
		 * ESTABLISHED if we did not get the upgrade server reply
		 */
		(lwsi_state(wsi) == LRS_WAITING_SERVER_REPLY &&
		 wsi->role_ops == &role_ops_ws) ||
#endif
	     lwsi_state(wsi) == LRS_WAITING_DNS ||
	     lwsi_state(wsi) == LRS_WAITING_CONNECT) &&
	     !wsi->already_did_cce && wsi->a.protocol) {
		static const char _reason[] = "closed before established";

		lwsl_debug("%s: closing in unestablished state 0x%x\n",
				__func__, lwsi_state(wsi));
		wsi->socket_is_permanently_unusable = 1;

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
				  __func__, wsi, (int)(lws_intptr_t)wsi->desc.sockfd,
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
#if !defined(_WIN32_WCE) && !defined(LWS_PLAT_FREERTOS)
		/* libuv: no event available to guarantee completion */
		if (!wsi->socket_is_permanently_unusable &&
		    lws_socket_is_valid(wsi->desc.sockfd) &&
		    lwsi_state(wsi) != LRS_SHUTDOWN &&
		    (context->event_loop_ops->flags & LELOF_ISPOLL)) {
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
	__remove_wsi_socket_from_fds(wsi);

	lwsi_set_state(wsi, LRS_DEAD_SOCKET);
	lws_buflist_destroy_all_segments(&wsi->buflist);
	lws_dll2_remove(&wsi->dll_buflist);

	if (wsi->role_ops->close_role)
	    wsi->role_ops->close_role(pt, wsi);

	/* tell the user it's all over for this guy */

	ccb = 0;
	if ((lwsi_state_est_PRE_CLOSE(wsi) ||
	    /* raw skt adopted but didn't complete tls hs should CLOSE */
	    (wsi->role_ops == &role_ops_raw_skt && !lwsi_role_client(wsi)) ||
	     lwsi_state_PRE_CLOSE(wsi) == LRS_WAITING_SERVER_REPLY) &&
	    !wsi->told_user_closed &&
	    wsi->role_ops->close_cb[lwsi_role_server(wsi)]) {
		if (!wsi->upgraded_to_http2 || !lwsi_role_client(wsi))
			ccb = 1;
			/*
			 * The network wsi for a client h2 connection shouldn't
			 * call back for its role: the child stream connections
			 * own the role.  Otherwise h2 will call back closed
			 * one too many times as the children do it and then
			 * the closing network stream.
			 */
	}

	if (!wsi->told_user_closed &&
	    !lws_dll2_is_detached(&wsi->vh_awaiting_socket))
		/*
		 * He's a guy who go started with dns, but failed or is
		 * caught with a shutdown before he got the result.  We have
		 * to issue him a close cb
		 */
		ccb = 1;

	pro = wsi->a.protocol;

	if (wsi->already_did_cce)
		/*
		 * If we handled this by CLIENT_CONNECTION_ERROR, it's
		 * mutually exclusive with CLOSE
		 */
		ccb = 0;

#if defined(LWS_WITH_CLIENT)
	if (!ccb && (lwsi_state_PRE_CLOSE(wsi) & LWSIFS_NOT_EST) &&
			lwsi_role_client(wsi)) {
		lws_inform_client_conn_fail(wsi, "Closed before conn", 18);
	}
#endif
	if (ccb) {

		if (!wsi->a.protocol && wsi->a.vhost && wsi->a.vhost->protocols)
			pro = &wsi->a.vhost->protocols[0];

		if (pro)
			pro->callback(wsi,
				wsi->role_ops->close_cb[lwsi_role_server(wsi)],
				wsi->user_space, NULL, 0);
		wsi->told_user_closed = 1;
	}

#if defined(LWS_ROLE_RAW_FILE)
async_close:
#endif
	lws_remove_child_from_any_parent(wsi);
	wsi->socket_is_permanently_unusable = 1;

	if (wsi->a.context->event_loop_ops->wsi_logical_close)
		if (wsi->a.context->event_loop_ops->wsi_logical_close(wsi))
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

		__remove_wsi_socket_from_fds(wsi);
		if (lws_socket_is_valid(wsi->desc.sockfd))
			delete_from_fd(wsi->a.context, wsi->desc.sockfd);

#if !defined(LWS_PLAT_FREERTOS) && !defined(WIN32) && !defined(LWS_PLAT_OPTEE)
		delete_from_fdwsi(wsi->a.context, wsi);
#endif

		sanity_assert_no_sockfd_traces(wsi->a.context, wsi->desc.sockfd);

		wsi->desc.sockfd = LWS_SOCK_INVALID;
	}

	/* outermost destroy notification for wsi (user_space still intact) */
	if (wsi->a.vhost)
		wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_WSI_DESTROY,
						  wsi->user_space, NULL, 0);

#ifdef LWS_WITH_CGI
	if (wsi->http.cgi) {
		lws_spawn_piped_destroy(&wsi->http.cgi->lsp);
		lws_sul_cancel(&wsi->http.cgi->sul_grace);
		lws_free_set_NULL(wsi->http.cgi);
	}
#endif

	__lws_wsi_remove_from_sul(wsi);
	sanity_assert_no_wsi_traces(wsi->a.context, wsi);
	__lws_free_wsi(wsi);
}


void
lws_close_free_wsi(struct lws *wsi, enum lws_close_status reason, const char *caller)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);
	__lws_close_free_wsi(wsi, reason, caller);
	lws_pt_unlock(pt);
}


