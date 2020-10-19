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
		if (hnames[n] && stash->cis[n] &&
		    lws_hdr_simple_create(wsi, hnames[n], stash->cis[n]))
			goto bail1;

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

struct lws *
lws_client_connect_via_info(const struct lws_client_connect_info *i)
{
	const char *local = i->protocol;
	struct lws *wsi, *safe = NULL;
	const struct lws_protocols *p;
	size_t s = sizeof(struct lws);
	const char *cisin[CIS_COUNT];
	int tid = 0, n, m;
	size_t size;
	char *pc;

	if (i->context->requested_kill)
		return NULL;

	if (!i->context->protocol_init_done)
		if (lws_protocol_init(i->context))
			return NULL;

	/*
	 * If we have .local_protocol_name, use it to select the local protocol
	 * handler to bind to.  Otherwise use .protocol if http[s].
	 */
	if (i->local_protocol_name)
		local = i->local_protocol_name;

	lws_stats_bump(&i->context->pt[tid], LWSSTATS_C_CONNS_CLIENT, 1);

	/* PHASE 1: create a bare wsi */

#if defined(LWS_WITH_EVENT_LIBS)
	s += i->context->event_loop_ops->evlib_size_wsi;
#endif

	wsi = lws_zalloc(s, "client wsi");
	if (wsi == NULL)
		goto bail;

#if defined(LWS_WITH_EVENT_LIBS)
	wsi->evlib_wsi = (uint8_t *)wsi + sizeof(*wsi);
#endif

	/*
	 * Until we exit, we can report connection failure directly to the
	 * caller without needing to call through to protocol CONNECTION_ERROR.
	 */
	wsi->client_suppress_CONNECTION_ERROR = 1;

	if (i->keep_warm_secs)
		wsi->keep_warm_secs = i->keep_warm_secs;
	else
		wsi->keep_warm_secs = 5;

	wsi->a.context = i->context;
	wsi->desc.sockfd = LWS_SOCK_INVALID;
	wsi->seq = i->seq;
	wsi->flags = i->ssl_connection;
	if (i->retry_and_idle_policy)
		wsi->retry_policy = i->retry_and_idle_policy;
	else
		wsi->retry_policy = &i->context->default_retry;

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (i->context->detailed_latency_cb)
		wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
#endif

	if (i->ssl_connection & LCCSCF_WAKE_SUSPEND__VALIDITY)
		wsi->conn_validity_wakesuspend = 1;

	wsi->a.vhost = NULL;
	if (!i->vhost) {
		struct lws_vhost *v = i->context->vhost_list;

		if (!v) { /* coverity */
			lwsl_err("%s: no vhost\n", __func__);
			goto bail;
		}
		if (!strcmp(v->name, "system"))
			v = v->vhost_next;
		lws_vhost_bind_wsi(v, wsi);
	} else
		lws_vhost_bind_wsi(i->vhost, wsi);

	if (!wsi->a.vhost) {
		lwsl_err("%s: No vhost in the context\n", __func__);

		goto bail;
	}

#if LWS_MAX_SMP > 1
	tid = wsi->a.vhost->protocols[0].callback(wsi,
				LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
#endif

	/*
	 * PHASE 2: if SMP, bind the client to whatever tsi the current thread
	 * represents
	 */

#if LWS_MAX_SMP > 1
	lws_context_lock(i->context, "client find tsi");

	for (n = 0; n < i->context->count_threads; n++)
		if (i->context->pt[n].service_tid == tid) {
			lwsl_info("%s: client binds to caller tsi %d\n",
				  __func__, n);
			wsi->tsi = n;
#if defined(LWS_WITH_DETAILED_LATENCY)
			wsi->detlat.tsi = n;
#endif
			break;
		}

	/*
	 * this binding is sort of provisional, since when we try to insert
	 * into the pt fds, there may be no space and it will fail
	 */

	lws_context_unlock(i->context);
#endif

	/*
	 * PHASE 3: Choose an initial role for the wsi and do role-specific init
	 *
	 * Note the initial role may not reflect the final role, eg,
	 * we may want ws, but first we have to go through h1 to get that
	 */

	if (lws_role_call_client_bind(wsi, i) < 0) {
		lwsl_err("%s: unable to bind to role\n", __func__);

		goto bail;
	}
	lwsl_info("%s: role binding to %s\n", __func__, wsi->role_ops->name);

	/*
	 * PHASE 4: fill up the wsi with stuff from the connect_info as far as
	 * it can go.  It's uncertain because not only is our connection
	 * going to complete asynchronously, we might have bound to h1 and not
	 * even be able to get ahold of an ah immediately.
	 */

	wsi->user_space = NULL;
	wsi->pending_timeout = NO_PENDING_TIMEOUT;
	wsi->position_in_fds_table = LWS_NO_FDS_POS;
	wsi->ocport = wsi->c_port = i->port;
	wsi->sys_tls_client_cert = i->sys_tls_client_cert;

#if defined(LWS_ROLE_H2)
	wsi->txc.manual_initial_tx_credit =
			(int32_t)i->manual_initial_tx_credit;
#endif

	wsi->a.protocol = &wsi->a.vhost->protocols[0];
	wsi->client_pipeline = !!(i->ssl_connection & LCCSCF_PIPELINE);
	wsi->client_no_follow_redirect = !!(i->ssl_connection &
					    LCCSCF_HTTP_NO_FOLLOW_REDIRECT);

	/*
	 * PHASE 5: handle external user_space now, generic alloc is done in
	 * role finalization
	 */

	if (i->userdata) {
		wsi->user_space_externally_allocated = 1;
		wsi->user_space = i->userdata;
	}

	if (local) {
		lwsl_info("%s: vh %s protocol binding to %s\n", __func__,
				wsi->a.vhost->name, local);
		p = lws_vhost_name_to_protocol(wsi->a.vhost, local);
		if (p)
			lws_bind_protocol(wsi, p, __func__);
		else
			lwsl_info("%s: unknown protocol %s\n", __func__, local);

		lwsl_info("%s: wsi %p: %s %s entry\n",
			    __func__, wsi, wsi->role_ops->name,
			    wsi->a.protocol ? wsi->a.protocol->name : "none");
	}

	/*
	 * PHASE 5: handle external user_space now, generic alloc is done in
	 * role finalization
	 */

	if (!wsi->user_space && i->userdata) {
		wsi->user_space_externally_allocated = 1;
		wsi->user_space = i->userdata;
	}

#if defined(LWS_WITH_TLS)
	wsi->tls.use_ssl = i->ssl_connection;
#else
	if (i->ssl_connection & LCCSCF_USE_SSL) {
		lwsl_err("%s: lws not configured for tls\n", __func__);
		goto bail;
	}
#endif

	/*
	 * PHASE 6: stash the things from connect_info that we can't process
	 * right now, eg, if http binding, without an ah.  If h1 and no ah, we
	 * will go on the ah waiting list and process those things later (after
	 * the connect_info and maybe the things pointed to have gone out of
	 * scope)
	 *
	 * However these things are stashed in a generic way at this point,
	 * with no relationship to http or ah
	 */

	cisin[CIS_ADDRESS]	= i->address;
	cisin[CIS_PATH]		= i->path;
	cisin[CIS_HOST]		= i->host;
	cisin[CIS_ORIGIN]	= i->origin;
	cisin[CIS_PROTOCOL]	= i->protocol;
	cisin[CIS_METHOD]	= i->method;
	cisin[CIS_IFACE]	= i->iface;
	cisin[CIS_ALPN]		= i->alpn;

	size = sizeof(*wsi->stash);

	/*
	 * Let's overallocate the stash object with space for all the args
	 * in one hit.
	 */
	for (n = 0; n < CIS_COUNT; n++)
		if (cisin[n])
			size += strlen(cisin[n]) + 1;

	wsi->stash = lws_malloc(size, "client stash");
	if (!wsi->stash) {
		lwsl_err("%s: OOM\n", __func__);
		goto bail1;
	}
	/* all the pointers default to NULL, but no need to zero the args */
	memset(wsi->stash, 0, sizeof(*wsi->stash));

	wsi->a.opaque_user_data = wsi->stash->opaque_user_data =
		i->opaque_user_data;
	pc = (char *)&wsi->stash[1];

	for (n = 0; n < CIS_COUNT; n++)
		if (cisin[n]) {
			wsi->stash->cis[n] = pc;
			m = (int)strlen(cisin[n]) + 1;
			memcpy(pc, cisin[n], m);
			pc += m;
		}

	/*
	 * at this point user callbacks like
	 * LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER will be interested to
	 * know the parent... eg for proxying we can grab extra headers from
	 * the parent's incoming ah and add them to the child client handshake
	 */

	if (i->parent_wsi) {
		lwsl_info("%s: created child %p of parent %p\n", __func__,
			  wsi, i->parent_wsi);
		wsi->parent = i->parent_wsi;
		safe = wsi->sibling_list = i->parent_wsi->child_list;
		i->parent_wsi->child_list = wsi;
	}

	/*
	 * PHASE 7: Do any role-specific finalization processing.  We can still
	 * see important info things via wsi->stash
	 */

	if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_client_bind)) {

		int n = lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_client_bind).
							client_bind(wsi, NULL);

		if (n && i->parent_wsi) {
			/* unpick from parent */

			i->parent_wsi->child_list = safe;
		}

		if (n < 0)
			/* we didn't survive, wsi is freed */
			goto bail2;

		if (n)
			/* something else failed, wsi needs freeing */
			goto bail;
	}

	/* let the caller's optional wsi storage have the wsi we created */

	if (i->pwsi)
		*i->pwsi = wsi;

	/* PHASE 8: notify protocol with role-specific connected callback */

	/* raw socket per se doesn't want this... raw socket proxy wants it... */

	if (wsi->role_ops != &role_ops_raw_skt ||
	    (i->local_protocol_name &&
	     !strcmp(i->local_protocol_name, "raw-proxy"))) {
		lwsl_debug("%s: wsi %p: adoption cb %d to %s %s\n", __func__,
			   wsi, wsi->role_ops->adoption_cb[0],
			   wsi->role_ops->name, wsi->a.protocol->name);

		wsi->a.protocol->callback(wsi, wsi->role_ops->adoption_cb[0],
				wsi->user_space, NULL, 0);
	}

#if defined(LWS_WITH_HUBBUB)
	if (i->uri_replace_to)
		wsi->http.rw = lws_rewrite_create(wsi, html_parser_cb,
					     i->uri_replace_from,
					     i->uri_replace_to);
#endif

	if (i->method && (!strcmp(i->method, "RAW") // ||
//			  !strcmp(i->method, "MQTT")
	)) {

		/*
		 * Not for MQTT here, since we don't know if we will
		 * pipeline it or not...
		 */

#if defined(LWS_WITH_TLS)

		wsi->tls.ssl = NULL;

		if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
			const char *cce = NULL;

			switch (
#if !defined(LWS_WITH_SYS_ASYNC_DNS)
			lws_client_create_tls(wsi, &cce, 1)
#else
			lws_client_create_tls(wsi, &cce, 0)
#endif
			) {
			case 1:
				return wsi;
			case 0:
				break;
			default:
				goto bail3;
			}
		}
#endif


		/* fallthru */

		wsi = lws_http_client_connect_via_info2(wsi);
	}

	if (wsi)
		/*
		 * If it subsequently fails, report CONNECTION_ERROR,
		 * because we're going to return a non-error return now.
		 */
		wsi->client_suppress_CONNECTION_ERROR = 0;

	return wsi;

#if defined(LWS_WITH_TLS)
bail3:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "tls start fail");

	return NULL;
#endif

bail1:
	lws_free_set_NULL(wsi->stash);

bail:
	lws_free(wsi);
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
bail2:
#endif

#if defined(LWS_WITH_TLS)
	if (i->ssl_connection & LCCSCF_USE_SSL)
		lws_tls_restrict_return(i->context);
#endif

	if (i->pwsi)
		*i->pwsi = NULL;

	lws_stats_bump(&i->context->pt[tid], LWSSTATS_C_CONNS_CLIENT_FAILED, 1);

	return NULL;
}
