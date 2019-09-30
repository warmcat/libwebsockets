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

#if defined (_DEBUG)
void lwsi_set_role(struct lws *wsi, lws_wsi_state_t role)
{
	wsi->wsistate = (wsi->wsistate & (~LWSI_ROLE_MASK)) | role;

	lwsl_debug("lwsi_set_role(%p, 0x%lx)\n", wsi,
					(unsigned long)wsi->wsistate);
}

void lwsi_set_state(struct lws *wsi, lws_wsi_state_t lrs)
{
	wsi->wsistate = (wsi->wsistate & (~LRS_MASK)) | lrs;

	lwsl_debug("lwsi_set_state(%p, 0x%lx)\n", wsi,
					(unsigned long)wsi->wsistate);
}
#endif


void
lws_vhost_bind_wsi(struct lws_vhost *vh, struct lws *wsi)
{
	if (wsi->vhost == vh)
		return;
	lws_context_lock(vh->context, __func__); /* ---------- context { */
	wsi->vhost = vh;
	vh->count_bound_wsi++;
	lws_context_unlock(vh->context); /* } context ---------- */
	lwsl_info("%s: vh %s: count_bound_wsi %d\n",
		    __func__, vh->name, vh->count_bound_wsi);
	assert(wsi->vhost->count_bound_wsi > 0);
}

void
lws_vhost_unbind_wsi(struct lws *wsi)
{
	if (!wsi->vhost)
		return;

	lws_context_lock(wsi->context, __func__); /* ---------- context { */

	assert(wsi->vhost->count_bound_wsi > 0);
	wsi->vhost->count_bound_wsi--;
	lwsl_info("%s: vh %s: count_bound_wsi %d\n", __func__,
		  wsi->vhost->name, wsi->vhost->count_bound_wsi);

	if (!wsi->vhost->count_bound_wsi &&
	    wsi->vhost->being_destroyed) {
		/*
		 * We have closed all wsi that were bound to this vhost
		 * by any pt: nothing can be servicing any wsi belonging
		 * to it any more.
		 *
		 * Finalize the vh destruction
		 */
		__lws_vhost_destroy2(wsi->vhost);
	}
	wsi->vhost = NULL;

	lws_context_unlock(wsi->context); /* } context ---------- */
}

LWS_VISIBLE struct lws *
lws_get_network_wsi(struct lws *wsi)
{
	if (!wsi)
		return NULL;

#if defined(LWS_WITH_HTTP2)
	if (!wsi->http2_substream
#if defined(LWS_WITH_CLIENT)
			&& !wsi->client_h2_substream
#endif
	)
		return wsi;

	while (wsi->h2.parent_wsi)
		wsi = wsi->h2.parent_wsi;
#endif

	return wsi;
}


LWS_VISIBLE LWS_EXTERN const struct lws_protocols *
lws_vhost_name_to_protocol(struct lws_vhost *vh, const char *name)
{
	int n;

	for (n = 0; n < vh->count_protocols; n++)
		if (vh->protocols[n].name && !strcmp(name, vh->protocols[n].name))
			return &vh->protocols[n];

	return NULL;
}

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

LWS_VISIBLE int
lws_callback_all_protocol_vhost_args(struct lws_vhost *vh,
			  const struct lws_protocols *protocol, int reason,
			  void *argp, size_t len)
{
	struct lws_context *context = vh->context;
	struct lws_context_per_thread *pt = &context->pt[0];
	unsigned int n, m = context->count_threads;
	struct lws *wsi;

	while (m--) {
		for (n = 0; n < pt->fds_count; n++) {
			wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->vhost == vh && (wsi->protocol == protocol ||
						 !protocol))
				wsi->protocol->callback(wsi, reason,
						wsi->user_space, argp, len);
		}
		pt++;
	}

	return 0;
}

LWS_VISIBLE int
lws_callback_all_protocol_vhost(struct lws_vhost *vh,
			  const struct lws_protocols *protocol, int reason)
{
	return lws_callback_all_protocol_vhost_args(vh, protocol, reason, NULL, 0);
}

LWS_VISIBLE LWS_EXTERN int
lws_callback_vhost_protocols(struct lws *wsi, int reason, void *in, int len)
{
	int n;

	for (n = 0; n < wsi->vhost->count_protocols; n++)
		if (wsi->vhost->protocols[n].callback(wsi, reason, NULL, in, len))
			return 1;

	return 0;
}

LWS_VISIBLE LWS_EXTERN int
lws_callback_vhost_protocols_vhost(struct lws_vhost *vh, int reason, void *in,
				   size_t len)
{
	int n;
	struct lws *wsi = lws_zalloc(sizeof(*wsi), "fake wsi");

	if (!wsi)
		return 1;

	wsi->context = vh->context;
	lws_vhost_bind_wsi(vh, wsi);

	for (n = 0; n < wsi->vhost->count_protocols; n++) {
		wsi->protocol = &vh->protocols[n];
		if (wsi->protocol->callback(wsi, reason, NULL, in, len)) {
			lws_free(wsi);
			return 1;
		}
	}

	lws_free(wsi);

	return 0;
}


LWS_VISIBLE int
lws_rx_flow_control(struct lws *wsi, int _enable)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	int en = _enable;

	// h2 ignores rx flow control atm
	if (lwsi_role_h2(wsi) || wsi->http2_substream ||
	    lwsi_role_h2_ENCAPSULATION(wsi))
		return 0; // !!!

	lwsl_info("%s: %p 0x%x\n", __func__, wsi, _enable);

	if (!(_enable & LWS_RXFLOW_REASON_APPLIES)) {
		/*
		 * convert user bool style to bitmap style... in user simple
		 * bool style _enable = 0 = flow control it, = 1 = allow rx
		 */
		en = LWS_RXFLOW_REASON_APPLIES | LWS_RXFLOW_REASON_USER_BOOL;
		if (_enable & 1)
			en |= LWS_RXFLOW_REASON_APPLIES_ENABLE_BIT;
	}

	lws_pt_lock(pt, __func__);

	/* any bit set in rxflow_bitmap DISABLEs rxflow control */
	if (en & LWS_RXFLOW_REASON_APPLIES_ENABLE_BIT)
		wsi->rxflow_bitmap &= ~(en & 0xff);
	else
		wsi->rxflow_bitmap |= en & 0xff;

	if ((LWS_RXFLOW_PENDING_CHANGE | (!wsi->rxflow_bitmap)) ==
	    wsi->rxflow_change_to)
		goto skip;

	wsi->rxflow_change_to = LWS_RXFLOW_PENDING_CHANGE |
				(!wsi->rxflow_bitmap);

	lwsl_info("%s: %p: bitmap 0x%x: en 0x%x, ch 0x%x\n", __func__, wsi,
		  wsi->rxflow_bitmap, en, wsi->rxflow_change_to);

	if (_enable & LWS_RXFLOW_REASON_FLAG_PROCESS_NOW ||
	    !wsi->rxflow_will_be_applied) {
		en = __lws_rx_flow_control(wsi);
		lws_pt_unlock(pt);

		return en;
	}

skip:
	lws_pt_unlock(pt);

	return 0;
}

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

int user_callback_handle_rxflow(lws_callback_function callback_function,
				struct lws *wsi,
				enum lws_callback_reasons reason, void *user,
				void *in, size_t len)
{
	int n;

	wsi->rxflow_will_be_applied = 1;
	n = callback_function(wsi, reason, user, in, len);
	wsi->rxflow_will_be_applied = 0;
	if (!n)
		n = __lws_rx_flow_control(wsi);

	return n;
}

LWS_EXTERN int
__lws_rx_flow_control(struct lws *wsi)
{
	struct lws *wsic = wsi->child_list;

	// h2 ignores rx flow control atm
	if (lwsi_role_h2(wsi) || wsi->http2_substream ||
	    lwsi_role_h2_ENCAPSULATION(wsi))
		return 0; // !!!

	/* if he has children, do those if they were changed */
	while (wsic) {
		if (wsic->rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE)
			__lws_rx_flow_control(wsic);

		wsic = wsic->sibling_list;
	}

	/* there is no pending change */
	if (!(wsi->rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE))
		return 0;

	/* stuff is still buffered, not ready to really accept new input */
	if (lws_buflist_next_segment_len(&wsi->buflist, NULL)) {
		/* get ourselves called back to deal with stashed buffer */
		lws_callback_on_writable(wsi);
		// return 0;
	}

	/* now the pending is cleared, we can change rxflow state */

	wsi->rxflow_change_to &= ~LWS_RXFLOW_PENDING_CHANGE;

	lwsl_info("rxflow: wsi %p change_to %d\n", wsi,
		  wsi->rxflow_change_to & LWS_RXFLOW_ALLOW);

	/* adjust the pollfd for this wsi */

	if (wsi->rxflow_change_to & LWS_RXFLOW_ALLOW) {
		lwsl_info("%s: reenable POLLIN\n", __func__);
		// lws_buflist_describe(&wsi->buflist, NULL, __func__);
		if (__lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: fail\n", __func__);
			return -1;
		}
	} else
		if (__lws_change_pollfd(wsi, LWS_POLLIN, 0))
			return -1;

	return 0;
}


LWS_VISIBLE const struct lws_protocols *
lws_get_protocol(struct lws *wsi)
{
	return wsi->protocol;
}


int
lws_ensure_user_space(struct lws *wsi)
{
	if (!wsi->protocol)
		return 0;

	/* allocate the per-connection user memory (if any) */

	if (wsi->protocol->per_session_data_size && !wsi->user_space) {
		wsi->user_space = lws_zalloc(
			    wsi->protocol->per_session_data_size, "user space");
		if (wsi->user_space == NULL) {
			lwsl_err("%s: OOM\n", __func__);
			return 1;
		}
	} else
		lwsl_debug("%s: %p protocol pss %lu, user_space=%p\n", __func__,
			   wsi, (long)wsi->protocol->per_session_data_size,
			   wsi->user_space);
	return 0;
}

LWS_VISIBLE void *
lws_adjust_protocol_psds(struct lws *wsi, size_t new_size)
{
	((struct lws_protocols *)lws_get_protocol(wsi))->per_session_data_size =
		new_size;

	if (lws_ensure_user_space(wsi))
			return NULL;

	return wsi->user_space;
}



LWS_VISIBLE int
lws_is_ssl(struct lws *wsi)
{
#if defined(LWS_WITH_TLS)
	return wsi->tls.use_ssl & LCCSCF_USE_SSL;
#else
	(void)wsi;
	return 0;
#endif
}

#if defined(LWS_WITH_TLS) && !defined(LWS_WITH_MBEDTLS)
LWS_VISIBLE lws_tls_conn*
lws_get_ssl(struct lws *wsi)
{
	return wsi->tls.ssl;
}
#endif

LWS_VISIBLE int
lws_partial_buffered(struct lws *wsi)
{
	return lws_has_buffered_out(wsi);
}

LWS_VISIBLE lws_fileofs_t
lws_get_peer_write_allowance(struct lws *wsi)
{
	if (!wsi->role_ops->tx_credit)
		return -1;
	return wsi->role_ops->tx_credit(wsi);
}

LWS_VISIBLE void
lws_role_transition(struct lws *wsi, enum lwsi_role role, enum lwsi_state state,
		    const struct lws_role_ops *ops)
{
#if defined(_DEBUG)
	const char *name = "(unset)";
#endif
	wsi->wsistate = role | state;
	if (ops)
		wsi->role_ops = ops;
#if defined(_DEBUG)
	if (wsi->role_ops)
		name = wsi->role_ops->name;
	lwsl_debug("%s: %p: wsistate 0x%lx, ops %s\n", __func__, wsi,
		   (unsigned long)wsi->wsistate, name);
#endif
}

LWS_VISIBLE LWS_EXTERN int
lws_parse_uri(char *p, const char **prot, const char **ads, int *port,
	      const char **path)
{
	const char *end;
	char unix_skt = 0;

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
	if (*p == '+') /* unix skt */
		unix_skt = 1;

	*ads = p;
	if (!strcmp(*prot, "http") || !strcmp(*prot, "ws"))
		*port = 80;
	else if (!strcmp(*prot, "https") || !strcmp(*prot, "wss"))
		*port = 443;

	if (*p == '[') {
		++(*ads);
		while (*p && *p != ']')
			p++;
		if (*p)
			*p++ = '\0';
	} else
		while (*p && *p != ':' && (unix_skt || *p != '/'))
			p++;

	if (*p == ':') {
		*p++ = '\0';
		*port = atoi(p);
		while (*p && *p != '/')
			p++;
	}
	*path = "/";
	if (*p) {
		*p++ = '\0';
		if (*p)
			*path = p;
	}

	return 0;
}

/* ... */

LWS_VISIBLE LWS_EXTERN const char *
lws_get_urlarg_by_name(struct lws *wsi, const char *name, char *buf, int len)
{
	int n = 0, sl = (int)strlen(name);

	while (lws_hdr_copy_fragment(wsi, buf, len,
			  WSI_TOKEN_HTTP_URI_ARGS, n) >= 0) {

		if (!strncmp(buf, name, sl))
			return buf + sl;

		n++;
	}

	return NULL;
}


#if defined(LWS_WITHOUT_EXTENSIONS)

/* we need to provide dummy callbacks for internal exts
 * so user code runs when faced with a lib compiled with
 * extensions disabled.
 */

LWS_VISIBLE int
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

LWS_EXTERN int
lws_set_extension_option(struct lws *wsi, const char *ext_name,
			 const char *opt_name, const char *opt_val)
{
	return -1;
}
#endif

LWS_VISIBLE LWS_EXTERN int
lws_is_cgi(struct lws *wsi) {
#ifdef LWS_WITH_CGI
	return !!wsi->http.cgi;
#else
	return 0;
#endif
}

const struct lws_protocol_vhost_options *
lws_pvo_search(const struct lws_protocol_vhost_options *pvo, const char *name)
{
	while (pvo) {
		if (!strcmp(pvo->name, name))
			break;

		pvo = pvo->next;
	}

	return pvo;
}

int
lws_pvo_get_str(void *in, const char *name, const char **result)
{
	const struct lws_protocol_vhost_options *pv =
		lws_pvo_search((const struct lws_protocol_vhost_options *)in,
				name);

	if (!pv)
		return 1;

	*result = (const char *)pv->value;

	return 0;
}

int
lws_broadcast(struct lws_context_per_thread *pt, int reason, void *in, size_t len)
{
	struct lws_vhost *v = pt->context->vhost_list;
	int n, ret = 0;

	pt->fake_wsi->context = pt->context;

	while (v) {
		const struct lws_protocols *p = v->protocols;
		pt->fake_wsi->vhost = v; /* not a real bound wsi */

		for (n = 0; n < v->count_protocols; n++) {
			pt->fake_wsi->protocol = p;
			if (p->callback &&
			    p->callback(pt->fake_wsi, reason, NULL, in, len))
				ret |= 1;
			p++;
		}
		v = v->vhost_next;
	}

	return ret;
}

LWS_VISIBLE LWS_EXTERN void *
lws_wsi_user(struct lws *wsi)
{
	return wsi->user_space;
}

LWS_VISIBLE LWS_EXTERN void
lws_set_wsi_user(struct lws *wsi, void *data)
{
	if (wsi->user_space_externally_allocated)
		wsi->user_space = data;
	else
		lwsl_err("%s: Cannot set internally-allocated user_space\n",
			 __func__);
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

LWS_VISIBLE LWS_EXTERN void *
lws_get_opaque_parent_data(const struct lws *wsi)
{
	return wsi->opaque_parent_data;
}

LWS_VISIBLE LWS_EXTERN void
lws_set_opaque_parent_data(struct lws *wsi, void *data)
{
	wsi->opaque_parent_data = data;
}

LWS_VISIBLE LWS_EXTERN void *
lws_get_opaque_user_data(const struct lws *wsi)
{
	return wsi->opaque_user_data;
}

LWS_VISIBLE LWS_EXTERN void
lws_set_opaque_user_data(struct lws *wsi, void *data)
{
	wsi->opaque_user_data = data;
}

LWS_VISIBLE LWS_EXTERN int
lws_get_child_pending_on_writable(const struct lws *wsi)
{
	return wsi->parent_pending_cb_on_writable;
}

LWS_VISIBLE LWS_EXTERN void
lws_clear_child_pending_on_writable(struct lws *wsi)
{
	wsi->parent_pending_cb_on_writable = 0;
}



LWS_VISIBLE LWS_EXTERN const char *
lws_get_vhost_name(struct lws_vhost *vhost)
{
	return vhost->name;
}

LWS_VISIBLE LWS_EXTERN int
lws_get_vhost_port(struct lws_vhost *vhost)
{
	return vhost->listen_port;
}

LWS_VISIBLE LWS_EXTERN void *
lws_get_vhost_user(struct lws_vhost *vhost)
{
	return vhost->user;
}

LWS_VISIBLE LWS_EXTERN const char *
lws_get_vhost_iface(struct lws_vhost *vhost)
{
	return vhost->iface;
}

LWS_VISIBLE lws_sockfd_type
lws_get_socket_fd(struct lws *wsi)
{
	if (!wsi)
		return -1;
	return wsi->desc.sockfd;
}


LWS_VISIBLE struct lws_vhost *
lws_vhost_get(struct lws *wsi)
{
	return wsi->vhost;
}

LWS_VISIBLE struct lws_vhost *
lws_get_vhost(struct lws *wsi)
{
	return wsi->vhost;
}

LWS_VISIBLE const struct lws_protocols *
lws_protocol_get(struct lws *wsi)
{
	return wsi->protocol;
}

#if defined(LWS_WITH_UDP)
LWS_VISIBLE const struct lws_udp *
lws_get_udp(const struct lws *wsi)
{
	return wsi->udp;
}
#endif

LWS_VISIBLE LWS_EXTERN struct lws_context *
lws_get_context(const struct lws *wsi)
{
	return wsi->context;
}

#if defined(LWS_WITH_CLIENT)
int
_lws_generic_transaction_completed_active_conn(struct lws *wsi)
{
	struct lws *wsi_eff = lws_client_wsi_effective(wsi);

	/*
	 * Are we constitutionally capable of having a queue, ie, we are on
	 * the "active client connections" list?
	 *
	 * If not, that's it for us.
	 */

	if (lws_dll2_is_detached(&wsi->dll_cli_active_conns))
		return 0; /* no new transaction */

	/* if this was a queued guy, close him and remove from queue */

	if (wsi->transaction_from_pipeline_queue) {
		lwsl_debug("closing queued wsi %p\n", wsi_eff);
		/* so the close doesn't trigger a CCE */
		wsi_eff->already_did_cce = 1;
		__lws_close_free_wsi(wsi_eff,
			LWS_CLOSE_STATUS_CLIENT_TRANSACTION_DONE,
			"queued client done");
	}

	/* after the first one, they can only be coming from the queue */
	wsi->transaction_from_pipeline_queue = 1;

	wsi->hdr_parsing_completed = 0;

	/* is there a new tail after removing that one? */
	wsi_eff = lws_client_wsi_effective(wsi);

	/*
	 * Do we have something pipelined waiting?
	 * it's OK if he hasn't managed to send his headers yet... he's next
	 * in line to do that...
	 */
	if (wsi_eff == wsi) {
		/*
		 * Nothing pipelined... we should hang around a bit
		 * in case something turns up...
		 */
		lwsl_info("%s: nothing pipelined waiting\n", __func__);
		lwsi_set_state(wsi, LRS_IDLING);

		lws_set_timeout(wsi, PENDING_TIMEOUT_CLIENT_CONN_IDLE, 5);

		return 0; /* no new transaction right now */
	}

	return 1; /* new transaction */
}
#endif

LWS_VISIBLE int LWS_WARN_UNUSED_RESULT
lws_raw_transaction_completed(struct lws *wsi)
{
	if (lws_has_buffered_out(wsi)) {
		/*
		 * ...so he tried to send something large, but it went out
		 * as a partial, but he immediately called us to say he wants
		 * to close the connection.
		 *
		 * Defer the close until the last part of the partial is sent.
		 *
		 */
		lwsl_debug("%s: %p: deferring due to partial\n", __func__, wsi);
		wsi->close_when_buffered_out_drained = 1;
		lws_callback_on_writable(wsi);

		return 0;
	}

	return -1;
}

int
lws_bind_protocol(struct lws *wsi, const struct lws_protocols *p,
		  const char *reason)
{
//	if (wsi->protocol == p)
//		return 0;
	const struct lws_protocols *vp = wsi->vhost->protocols, *vpo;

	if (wsi->protocol && wsi->protocol_bind_balance) {
		wsi->protocol->callback(wsi,
		       wsi->role_ops->protocol_unbind_cb[!!lwsi_role_server(wsi)],
					wsi->user_space, (void *)reason, 0);
		wsi->protocol_bind_balance = 0;
	}
	if (!wsi->user_space_externally_allocated)
		lws_free_set_NULL(wsi->user_space);

	lws_same_vh_protocol_remove(wsi);

	wsi->protocol = p;
	if (!p)
		return 0;

	if (lws_ensure_user_space(wsi))
		return 1;

	if (p > vp && p < &vp[wsi->vhost->count_protocols])
		lws_same_vh_protocol_insert(wsi, (int)(p - vp));
	else {
		int n = wsi->vhost->count_protocols;
		int hit = 0;

		vpo = vp;

		while (n--) {
			if (p->name && vp->name && !strcmp(p->name, vp->name)) {
				hit = 1;
				lws_same_vh_protocol_insert(wsi, (int)(vp - vpo));
				break;
			}
			vp++;
		}
		if (!hit)
			lwsl_err("%s: %p is not in vhost '%s' protocols list\n",
				 __func__, p, wsi->vhost->name);
	}

	if (wsi->protocol->callback(wsi, wsi->role_ops->protocol_bind_cb[
				    !!lwsi_role_server(wsi)],
				    wsi->user_space, NULL, 0))
		return 1;

	wsi->protocol_bind_balance = 1;

	return 0;
}

void
lws_http_close_immortal(struct lws *wsi)
{
	struct lws *nwsi;

	if (!wsi->http2_substream)
		return;

	assert(wsi->h2_stream_immortal);
	wsi->h2_stream_immortal = 0;

	nwsi = lws_get_network_wsi(wsi);
	lwsl_debug("%s: %p %p %d\n", __func__, wsi, nwsi,
				     nwsi->immortal_substream_count);
	assert(nwsi->immortal_substream_count);
	nwsi->immortal_substream_count--;
	if (!nwsi->immortal_substream_count)
		/*
		 * since we closed the only immortal stream on this nwsi, we
		 * need to reapply a normal timeout regime to the nwsi
		 */
		lws_set_timeout(nwsi, PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE,
				wsi->vhost->keepalive_timeout ?
				    wsi->vhost->keepalive_timeout : 31);
}

void
lws_http_mark_immortal(struct lws *wsi)
{
	struct lws *nwsi;

	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	if (!wsi->http2_substream
#if defined(LWS_WITH_CLIENT)
			&& !wsi->client_h2_substream
#endif
	) {
		lwsl_err("%s: not h2 substream\n", __func__);
		return;
	}

	nwsi = lws_get_network_wsi(wsi);

	lwsl_debug("%s: %p %p %d\n", __func__, wsi, nwsi,
				     nwsi->immortal_substream_count);

	wsi->h2_stream_immortal = 1;
	assert(nwsi->immortal_substream_count < 255); /* largest count */
	nwsi->immortal_substream_count++;
	if (nwsi->immortal_substream_count == 1)
		lws_set_timeout(nwsi, NO_PENDING_TIMEOUT, 0);
}


int
lws_http_mark_sse(struct lws *wsi)
{
	lws_http_headers_detach(wsi);
	lws_http_mark_immortal(wsi);

	if (wsi->http2_substream)
		wsi->h2_stream_carries_sse = 1;

	return 0;
}
