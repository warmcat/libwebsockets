/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

int
lws_role_call_alpn_negotiated(struct lws *wsi, const char *alpn)
{
	int is_quic;

	if (!alpn)
		return 0;

#if !defined(LWS_ESP_PLATFORM)
	lwsl_wsi_info(wsi, "'%s'", alpn);
#endif

	/*
	 * A QUIC-transport wsi always hands the negotiated ALPN to its current
	 * (quic) role for filtering and possible migration to the h3 role, and
	 * must never be claimed by the by-ALPN-string fallback below: a TCP
	 * ALPN like "h2" negotiated on top of the UDP transport would
	 * transition the wsi to the h2 role where it can never make progress.
	 */
	is_quic = wsi->role_ops && !strcmp(wsi->role_ops->name, "quic");

	/* First try the WSI's current role if it matches the ALPN or if it's QUIC */
	if (wsi->role_ops && lws_rops_fidx(wsi->role_ops, LWS_ROPS_alpn_negotiated) &&
	    (is_quic ||
	     (wsi->role_ops->alpn && !strcmp(wsi->role_ops->alpn, alpn)))) {
			lwsl_wsi_info(wsi, "lws_role_call_alpn_negotiated: Matched WSI current role: %s", wsi->role_ops->name);
#if defined(LWS_WITH_SERVER)
			lws_metrics_tag_wsi_add(wsi, "upg", wsi->role_ops->name);
#endif
			return (lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_alpn_negotiated)).
						   alpn_negotiated(wsi, alpn);
	}

	/* ... but a QUIC wsi has nowhere else to go: leave the decision to the
	 * quic role's caller, which should fail the connection */

	if (is_quic)
		return 0;

	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (ar->alpn && !strcmp(ar->alpn, alpn) &&
		    lws_rops_fidx(ar, LWS_ROPS_alpn_negotiated)) {
			// lwsl_wsi_notice(wsi, "lws_role_call_alpn_negotiated: Matched fallback role: %s", ar->name);
#if defined(LWS_WITH_SERVER)
			lws_metrics_tag_wsi_add(wsi, "upg", ar->name);
#endif
			return (lws_rops_func_fidx(ar, LWS_ROPS_alpn_negotiated)).
						   alpn_negotiated(wsi, alpn);
		}
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;
	return 0;
}

#if defined(LWS_WITH_CLIENT)
int
lws_role_call_client_bind(struct lws *wsi,
			  const struct lws_client_connect_info *i)
{
	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (lws_rops_fidx(ar, LWS_ROPS_client_bind)) {
			int m = (lws_rops_func_fidx(ar, LWS_ROPS_client_bind)).
							client_bind(wsi, i);

			if (m < 0)
				return m;
			if (m)
				return 0;
		}
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;

	/* fall back to raw socket role if, eg, h1 not configured */

	if (lws_rops_fidx(&role_ops_raw_skt, LWS_ROPS_client_bind) &&
	    (lws_rops_func_fidx(&role_ops_raw_skt, LWS_ROPS_client_bind)).
					client_bind(wsi, i))
		return 0;

	return 1;
}
#endif

void *
lws_protocol_vh_priv_zalloc(struct lws_vhost *vhost,
			    const struct lws_protocols *prot, int size)
{
	int n = 0;

	if (!vhost || !prot || !vhost->protocols || !prot->name)
		return NULL;

	/* allocate the vh priv array only on demand */
	if (!vhost->protocol_vh_privs) {
		vhost->protocol_vh_privs = (void **)lws_zalloc(
				(size_t)vhost->count_protocols * sizeof(void *),
				"protocol_vh_privs");

		if (!vhost->protocol_vh_privs)
			return NULL;
	}

	while (n < vhost->count_protocols && &vhost->protocols[n] != prot)
		n++;

	if (n == vhost->count_protocols) {
		n = 0;
		while (n < vhost->count_protocols) {
			if (vhost->protocols[n].name &&
			    !strcmp(vhost->protocols[n].name, prot->name))
				break;
			n++;
		}

		if (n == vhost->count_protocols) {
			lwsl_vhost_err(vhost, "unknown protocol %p", prot);
			return NULL;
		}
	}

	vhost->protocol_vh_privs[n] = lws_zalloc((size_t)size, "vh priv");
	return vhost->protocol_vh_privs[n];
}

void *
lws_protocol_vh_priv_get(struct lws_vhost *vhost,
			 const struct lws_protocols *prot)
{
	int n = 0;

	if (!vhost || !vhost->protocols ||
	    !vhost->protocol_vh_privs || !prot || !prot->name)
		return NULL;

	while (n < vhost->count_protocols && &vhost->protocols[n] != prot)
		n++;

	if (n == vhost->count_protocols) {
		n = 0;
		while (n < vhost->count_protocols) {
			if (vhost->protocols[n].name &&
			    !strcmp(vhost->protocols[n].name, prot->name))
				break;
			n++;
		}

		if (n == vhost->count_protocols) {
			lwsl_vhost_err(vhost, "unknown protocol %p (%s)", prot, prot->name);
			return NULL;
		}
	}

	return vhost->protocol_vh_privs[n];
}

void *
lws_vhd_find_by_pvo(struct lws_context *cx, const char *protname,
		    const char *pvo_name, const char *pvo_value)
{
	struct lws_vhost *vh;
	int n;

	/* let's go through all the vhosts */

	vh = lws_vhost_first(cx);
	while (vh) {

		if (vh->protocol_vh_privs) {

		for (n = 0; n < vh->count_protocols; n++) {
			const struct lws_protocol_vhost_options *pv;

			/*
			 * a plugin that counted its list terminator as a
			 * protocol leaves a NULL name in the table
			 */
			if (!vh->protocols[n].name ||
			    strcmp(vh->protocols[n].name, protname))
				continue;

			/* this vh has an instance of the required protocol */

			pv = lws_pvo_search(vh->pvo, protname);
			if (!pv)
				continue;

			pv = lws_pvo_search(pv->options, pvo_name);
			if (!pv)
				continue;

			/* ... he also has a pvo of the right name... */
			if (!strcmp(pv->value, pvo_value))
				/*
				 * ... yes, the pvo has the right value too,
				 * return a pointer to this vhost-protocol
				 * private alloc (ie, its "vhd")
				 */
				return vh->protocol_vh_privs[n];
		}
		} else
			lwsl_vhost_notice(vh, "no privs yet");
		vh = lws_vhost_next(vh);
	}

	return NULL;
}

const struct lws_protocol_vhost_options *
lws_vhost_protocol_options(struct lws_vhost *vh, const char *name)
{
	const struct lws_protocol_vhost_options *pvo = vh->pvo;

	if (!name)
		return NULL;

	while (pvo) {
		if (!strcmp(pvo->name, name))
			return pvo;
		pvo = pvo->next;
	}

	return NULL;
}

int
#define lws_vh_pinit_set(vh, n) \
	((vh)->protocol_init[(n) >> 3] |= (uint8_t)(1 << ((n) & 7)))

lws_protocol_init_vhost(struct lws_vhost *vh, int *any)
{
	const struct lws_protocol_vhost_options *pvo, *pvo1;
	int n;

	if (!vh->protocol_init) {
		vh->protocol_init = lws_zalloc(((size_t)vh->count_protocols + 7) / 8,
					       "protocol_init");
		if (!vh->protocol_init)
			return 1;
	}
#if defined(LWS_PLAT_FREERTOS)
	struct lws_a _lwsa, *lwsa = &_lwsa;

	memset(&_lwsa, 0, sizeof(_lwsa));
#else
#if defined(__COVERITY__)
	struct lws _lws = { 0 };
#else
	struct lws _lws;

	memset((void *)&_lws, 0, sizeof(_lws));
#endif
	struct lws_a *lwsa = &_lws.a;

	/* a made-up wsi for the callbacks: no transport */
	_lws.io = vh->context->fake_io;
#endif

	lwsa->context = vh->context;
	lwsa->vhost = vh;

	/* initialize supported protocols on this vhost */

	/* Pass 1: init plugins first */

	for (n = vh->plugin_protocol_bind;
	     n < vh->plugin_protocol_bind + vh->plugin_protocol_count; n++) {
		lwsa->protocol = &vh->protocols[n];
		if (!vh->protocols[n].name)
			continue;

		pvo = lws_vhost_protocol_options(vh, vh->protocols[n].name);
		if (pvo) {
			/*
			 * linked list of options specific to
			 * vh + protocol
			 */
			pvo1 = pvo;
			pvo = pvo1->options;

			while (pvo) {
				lwsl_vhost_debug(vh, "protocol \"%s\", "
						     "option \"%s\"",
						     vh->protocols[n].name,
						     pvo->name);

				if (!strcmp(pvo->name, "default")) {
					lwsl_vhost_info(vh, "Setting default "
							     "protocol to %s",
							     vh->protocols[n].name);
					vh->default_protocol_index = (unsigned char)n;
				}
				if (!strcmp(pvo->name, "raw")) {
					lwsl_vhost_info(vh, "Setting raw "
							     "protocol to %s",
							     vh->protocols[n].name);
					vh->raw_protocol_index = (unsigned char)n;
				}
				pvo = pvo->next;
			}
		} else
			lwsl_vhost_debug(vh, "not instantiating %s",
					     vh->protocols[n].name);

#if defined(LWS_WITH_TLS)
		if (any)
			*any |= !!vh->tls.ssl_ctx;
#endif

		pvo = lws_vhost_protocol_options(vh, vh->protocols[n].name);

		/*
		 * inform all the protocols that they are doing their
		 * one-time initialization if they want to.
		 *
		 * NOTE the fakewsi is garbage, except the key pointers that are
		 * prepared in case the protocol handler wants to touch them
		 */

		if (pvo || (vh->options & LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS)

#if !defined(LWS_WITH_PROTOCOL_PLUGINS)
				/*
				 * with plugins, you have to explicitly
				 * instantiate them per-vhost with pvos.
				 *
				 * Without plugins, not setting the vhost pvo
				 * list at creation enables all the protocols
				 * by default, for backwards compatibility
				 */
				|| !vh->pvo
#endif
		) {
			lwsl_vhost_info(vh, "init %s.%s", vh->name,
					vh->protocols[n].name);
			if (vh->protocols[n].callback((struct lws *)lwsa,
					LWS_CALLBACK_PROTOCOL_INIT, NULL,
					(void *)(pvo ? pvo->options : NULL),
					0)) {
				if (vh->protocol_vh_privs && vh->protocol_vh_privs[n]) {
					lws_free(vh->protocol_vh_privs[n]);
					vh->protocol_vh_privs[n] = NULL;
				}
				lwsl_vhost_warn(vh, "protocol %s failed init",
					vh->protocols[n].name);


			} else
				lws_vh_pinit_set(vh, n);
		}
	}

	/* Pass 2: init non-plugins */

	for (n = 0; n < vh->count_protocols; n++) {
		if (n >= vh->plugin_protocol_bind &&
		    n < vh->plugin_protocol_bind + vh->plugin_protocol_count)
			continue;

		lwsa->protocol = &vh->protocols[n];
		if (!vh->protocols[n].name)
			continue;

		pvo = lws_vhost_protocol_options(vh, vh->protocols[n].name);
		if (pvo) {
			/*
			 * linked list of options specific to
			 * vh + protocol
			 */
			pvo1 = pvo;
			pvo = pvo1->options;

			while (pvo) {
				lwsl_vhost_debug(vh, "protocol \"%s\", "
						     "option \"%s\"",
						     vh->protocols[n].name,
						     pvo->name);

				if (!strcmp(pvo->name, "default")) {
					lwsl_vhost_info(vh, "Setting default "
							     "protocol to %s",
							     vh->protocols[n].name);
					vh->default_protocol_index = (unsigned char)n;
				}
				if (!strcmp(pvo->name, "raw")) {
					lwsl_vhost_info(vh, "Setting raw "
							     "protocol to %s",
							     vh->protocols[n].name);
					vh->raw_protocol_index = (unsigned char)n;
				}
				pvo = pvo->next;
			}
		} else
			lwsl_vhost_debug(vh, "not instantiating %s",
					     vh->protocols[n].name);

#if defined(LWS_WITH_TLS)
		if (any)
			*any |= !!vh->tls.ssl_ctx;
#endif

		pvo = lws_vhost_protocol_options(vh, vh->protocols[n].name);

		/*
		 * inform all the protocols that they are doing their
		 * one-time initialization if they want to.
		 *
		 * NOTE the fakewsi is garbage, except the key pointers that are
		 * prepared in case the protocol handler wants to touch them
		 */

		if (pvo || (vh->options & LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS)

#if !defined(LWS_WITH_PROTOCOL_PLUGINS)
				/*
				 * with plugins, you have to explicitly
				 * instantiate them per-vhost with pvos.
				 *
				 * Without plugins, not setting the vhost pvo
				 * list at creation enables all the protocols
				 * by default, for backwards compatibility
				 */
				|| !vh->pvo
#endif
		) {
			lwsl_vhost_info(vh, "init %s.%s", vh->name,
					vh->protocols[n].name);
			if (vh->protocols[n].callback((struct lws *)lwsa,
					LWS_CALLBACK_PROTOCOL_INIT, NULL,
					(void *)(pvo ? pvo->options : NULL),
					0)) {
				if (vh->protocol_vh_privs && vh->protocol_vh_privs[n]) {
					lws_free(vh->protocol_vh_privs[n]);
					vh->protocol_vh_privs[n] = NULL;
				}
				lwsl_vhost_warn(vh, "protocol %s failed init",
					vh->protocols[n].name);


			} else
				lws_vh_pinit_set(vh, n);
		}
	}

	vh->created_vhost_protocols = 1;

	return 0;
}

/*
 * inform every vhost that hasn't already done it, that
 * his protocols are initializing
 */
int
lws_protocol_init(struct lws_context *context)
{
	struct lws_vhost *vh = lws_vhost_first(context);
	int any = 0, r = 0, spd = 0;

	if (context->doing_protocol_init)
		return 0;

	context->doing_protocol_init = 1;

	lwsl_cx_info(context, "\n");

	while (vh) {

		spd |= lws_check_opt(vh->options, LWS_SERVER_OPTION_VH_SKIP_PRIV_DROP);

		/* only do the protocol init once for a given vhost */
		if (vh->created_vhost_protocols ||
		    (lws_check_opt(vh->options, LWS_SERVER_OPTION_SKIP_PROTOCOL_INIT)))
			goto next;

		if (lws_protocol_init_vhost(vh, &any)) {
			lwsl_vhost_warn(vh, "init vhost %s failed", vh->name);
			r = -1;
		}
next:
		vh = lws_vhost_next(vh);
	}

	context->doing_protocol_init = 0;

	if (r)
		lwsl_cx_warn(context, "some protocols did not init");

	if (!context->protocol_init_done) {

		context->protocol_init_done = 1;
		if (!spd)
			lws_io_finalize_startup(context, __func__);

		return 0;
	}

	return 0;
}


void *
lws_vhost_user(struct lws_vhost *vhost)
{
	return vhost->user;
}

int
lws_get_vhost_listen_port(struct lws_vhost *vhost)
{
	return vhost->listen_port;
}


#if defined(LWS_WITH_NETWORK)

struct lws_vhost *
lws_get_vhost_by_name(struct lws_context *context, const char *name)
{
	lws_start_foreach_vhost(v, context) {
		if (!v->being_destroyed && !strcmp(v->name, name))
			return v;

	} lws_end_foreach_vhost(v);

	return NULL;
}


#if defined(LWS_WITH_CLIENT)
/*
 * This is the logic checking to see if the new connection wsi should have a
 * pipelining or muxing relationship with an existing "active connection" to
 * the same endpoint under the same conditions.
 *
 * This was originally in the client code but since the list is held on the
 * vhost (to ensure the same client tls ctx is involved) it's cleaner in vhost.c
 *
 * ACTIVE_CONNS_QUEUED: We're queued on an active connection, set *nwsi to that
 * ACTIVE_CONNS_MUXED: We are joining an active mux conn *nwsi as a child
 * ACTIVE_CONNS_SOLO: There's no existing conn to join either way
 */

#if defined(LWS_WITH_TLS)
/*
 * The tls flags two connections must agree on before one may ride on the
 * other's tls session: whether tls is used at all, and every opt-out from
 * peer validation.
 */
#define LWS_ACTIVE_CONN_TLS_MASK (LCCSCF_USE_SSL | \
				  LCCSCF_ALLOW_SELFSIGNED | \
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | \
				  LCCSCF_ALLOW_EXPIRED | \
				  LCCSCF_ALLOW_INSECURE)
#endif

int
lws_vhost_active_conns(struct lws *wsi, struct lws **nwsi, const char *adsin)
{
#if defined(LWS_WITH_TLS)
#if defined(LWS_ROLE_H1)
	const char *my_alpn = lws_wsi_client_stash_item(wsi, CIS_ALPN,
							_WSI_TOKEN_CLIENT_ALPN);
#endif
#endif
#if defined(LWS_WITH_TLS)
#if defined(LWS_ROLE_H1)
	char newconn_cannot_use_h1 = 0;

	if ((wsi->use_ssl & LCCSCF_USE_SSL) &&
	    my_alpn && !(char *)strstr(my_alpn, "http/1.1"))
		/*
		 * new guy wants to use tls, he specifies the alpn and he does
		 * not list h1 as a choice ==> he can't bind to existing h1
		 */
		newconn_cannot_use_h1 = 1;
#endif
#endif

	if (!lws_dll2_is_detached(&wsi->dll2_cli_txn_queue)) {
		struct lws *w = lws_dll2_owner_container(&wsi->dll2_cli_txn_queue, struct lws,
				dll2_cli_txn_queue_owner);
		*nwsi = w;

		return ACTIVE_CONNS_QUEUED;
	}

#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_MQTT)
	if (wsi->mux.parent_wsi) {
		/*
		 * We already decided...
		 */

		*nwsi = wsi->mux.parent_wsi;

		return ACTIVE_CONNS_MUXED;
	}
#endif

	lws_context_lock(wsi->a.context, __func__); /* -------------- cx { */
	lws_vhost_lock(wsi->a.vhost); /* ----------------------------------- { */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&wsi->a.vhost->dll_cli_active_conns_owner)) {
		struct lws *w = lws_container_of(d, struct lws,
						 dll_cli_active_conns);

		lwsl_wsi_debug(wsi, "check %s %s %s %d %d",
				    lws_wsi_tag(w), adsin,
				    w->cli_hostname_copy ? w->cli_hostname_copy :
							    "null",
				    wsi->c_port, w->c_port);

		if (w != wsi &&
		    /*
		     * "same internet protocol"... this is a bit tricky,
		     * since h2 start out as h1, and may stay at h1.
		     *
		     * But an idle h1 connection cannot be used by a connection
		     * request that doesn't have http/1.1 in its alpn list...
		     *
		     * An established h3 connection is represented here by
		     * its quic network wsi, whose role is quic, not http:
		     * a new http connection to the same origin can ride it
		     * as another h3 stream (the "just join h3" below).
		     */
		    (w->role_ops == wsi->role_ops ||
		     (lwsi_role_http(w) && lwsi_role_http(wsi))
#if defined(LWS_ROLE_H3)
		     || (lwsi_role_http(wsi) && w->role_ops &&
			 !strcmp(w->role_ops->name, "quic") &&
			 lws_wsi_client_nwsi_migrated(w))
#endif
		    ) &&
		     /* ... same role, or at least both some kind of http */
		    w->cli_hostname_copy && !strcmp(adsin, w->cli_hostname_copy) &&
		    /* same endpoint hostname */
#if defined(LWS_WITH_TLS)
#if defined(LWS_ROLE_H1)
		   !(newconn_cannot_use_h1 && w->role_ops == &role_ops_h1) &&
#endif
		   /* if we can't use h1, old guy must not be h1 */
		    (wsi->use_ssl & LWS_ACTIVE_CONN_TLS_MASK) ==
		     (w->use_ssl & LWS_ACTIVE_CONN_TLS_MASK) &&
		     /*
		      * Must both agree on tls use or not, and on which parts
		      * of peer validation they opted out of.
		      *
		      * A piggybacking connection never does a handshake of its
		      * own (see lws_client_connect_4_established()), it just
		      * rides the existing one.  So if we let a connection that
		      * asked for full validation share a connection that was
		      * established with, eg, LCCSCF_ALLOW_SELFSIGNED, its
		      * request and credentials silently travel over a TLS
		      * session nobody authenticated... the same hazard
		      * lws_tls_session_tag_from_wsi() keeps out of the session
		      * resumption cache, by segregating the tags.
		      */
#endif
		    wsi->c_port == w->c_port) {
			/* same endpoint port */

			/*
			 * There's already an active connection.
			 *
			 * The server may have told the existing active
			 * connection that it doesn't support pipelining...
			 */
			if (w->keepalive_rejected) {
				lwsl_wsi_notice(w, "defeating pipelining");
				goto solo;
			}

#if defined(LWS_WITH_HTTP2)
			/*
			 * h2: if in usable state already: just use it without
			 *     going through the queue
			 */
			if (lwsi_role_h2(w) && lws_wsi_client_nwsi_migrated(w) &&
			    (lwsi_state(w) == LRS_H2_WAITING_TO_SEND_HEADERS ||
			     lwsi_state(w) == LRS_ESTABLISHED ||
			     lwsi_state(w) == LRS_IDLING)) {

				lwsl_wsi_info(w, "just join h2 directly 0x%x",
						   lwsi_state(w));

				if (lwsi_state(w) == LRS_IDLING) {
					/*
					 * Kept warm by
					 * lws_wsi_mux_client_idle_check() after
					 * its last stream closed.  LRS_IDLING does
					 * not carry LWSIFS_POCB, so its POLLOUT is
					 * never serviced and the child-walking
					 * POLLOUT loop that sends a new stream's
					 * HEADERS never runs: put it back into the
					 * LRS_ESTABLISHED it uses while actively
					 * muxing, and drop the keep-warm timeout,
					 * it is in use again.
					 */
					/*
					 * ...but only once the adopt has succeeded:
					 * revived and stripped of its timeout before
					 * an adopt the peer's stream limit refuses,
					 * it sat ESTABLISHED with no streams, no
					 * timeout and nothing that could ever wake
					 * it, for ever
					 */
					if (lws_wsi_h2_adopt(w, wsi)) {
						lws_wsi_event(w, LWS_WSIEV_CONN_REUSED);
						lws_set_timeout(w, NO_PENDING_TIMEOUT, 0);
						lws_vhost_unlock(wsi->a.vhost); /* } ---------- */
						lws_context_unlock(wsi->a.context); /* -------------- cx { */

						*nwsi = w;

						return ACTIVE_CONNS_MUXED;
					}
				} else if (lws_wsi_h2_adopt(w, wsi)) {
					lws_vhost_unlock(wsi->a.vhost); /* } ---------- */
					lws_context_unlock(wsi->a.context); /* -------------- cx { */

					*nwsi = w;

					return ACTIVE_CONNS_MUXED;
				}

				/*
				 * The peer's concurrent stream limit is
				 * reached: queue on the connection below and
				 * get adopted when a stream closes
				 */
			}
#endif

#if defined(LWS_ROLE_H3)
			/*
			 * h3: if in usable state already: just use it without
			 *     going through the queue
			 */
			if ((w->role_ops && !strcmp(w->role_ops->name, "quic")) && lws_wsi_client_nwsi_migrated(w) &&
			    (lwsi_state(w) == LRS_H2_WAITING_TO_SEND_HEADERS ||
			     lwsi_state(w) == LRS_ESTABLISHED ||
			     lwsi_state(w) == LRS_IDLING)) {

				lwsl_wsi_info(w, "just join h3 directly 0x%x",
						   lwsi_state(w));


				if (lws_wsi_h3_adopt(w, wsi)) {
					/* See the h2 branch above: a kept-warm
					 * mux connection must leave LRS_IDLING so
					 * its POLLOUT is serviced and the new
					 * stream's headers get sent, once it has
					 * a stream. */
					if (lwsi_state(w) == LRS_IDLING) {
						lws_wsi_event(w, LWS_WSIEV_CONN_REUSED);
						lws_set_timeout(w, NO_PENDING_TIMEOUT, 0);
					}
					lws_vhost_unlock(wsi->a.vhost); /* } ---------- */
					lws_context_unlock(wsi->a.context); /* -------------- cx { */

					*nwsi = w;

					return ACTIVE_CONNS_MUXED;
				}
			}
#endif

#if defined(LWS_ROLE_MQTT)
			/*
			 * MQTT: if in usable state already: just use it without
			 *	 going through the queue
			 */

			if (lwsi_role_mqtt(wsi) && lws_wsi_client_nwsi_migrated(w) &&
			    lwsi_state(w) == LRS_ESTABLISHED) {

				if (lws_wsi_mqtt_adopt(w, wsi)) {
					lwsl_wsi_notice(w, "join mqtt directly");
					lws_dll2_remove(&wsi->dll2_cli_txn_queue);
					wsi->client_mux_substream = 1;

					lws_vhost_unlock(wsi->a.vhost); /* } ---------- */
					lws_context_unlock(wsi->a.context); /* -------------- cx { */

					return ACTIVE_CONNS_MUXED;
				}
			}
#endif

			/*
			 * If the connection is viable but not yet in a usable
			 * state, let's attach ourselves to it and wait for it
			 * to get there or fail.
			 */

			lwsl_wsi_info(wsi, "apply txn queue %s, state 0x%lx",
					     lws_wsi_tag(w),
					     (unsigned long)w->wsistate);
			/*
			 * ...let's add ourselves to his transaction queue...
			 * we are adding ourselves at the TAIL
			 */
			lws_dll2_add_tail(&wsi->dll2_cli_txn_queue,
					  &w->dll2_cli_txn_queue_owner);

			/*
			 * An h2 / h3 leader kept warm in IDLING whose adopt was
			 * refused (peer stream limit) stays IDLING, and this
			 * hand-off is the h1 pipeline's: it must not run on a
			 * mux leader
			 */
			if (lwsi_state(w) == LRS_IDLING && lwsi_role_h1(w)) {
				if (_lws_generic_transaction_completed_active_conn(&w, 0) < 0)
					/*
					 * The idle leader could not hand us its
					 * connection: we are back on its queue,
					 * and it closes, taking us with it,
					 * told our connection failed
					 */
					lws_set_timeout(w, 1, LWS_TO_KILL_ASYNC);
				else
					/*
					 * An idle h1 leader with us as its only
					 * queued transaction hands us its
					 * connection right away and dies: we
					 * are off the queue holding a live
					 * socket, ready to send our request
					 */
					if (lws_dll2_is_detached(
						&wsi->dll2_cli_txn_queue))
						lws_wsi_event(wsi,
							LWS_WSIEV_TRANSPORT_UP);
			}

			/*
			 * For eg, h1 next we'd pipeline our headers out on him,
			 * and wait for our turn at client transaction_complete
			 * to take over parsing the rx.
			 */
			lws_vhost_unlock(wsi->a.vhost); /* } ---------- */
			lws_context_unlock(wsi->a.context); /* -------------- cx { */

			*nwsi = w;

			return ACTIVE_CONNS_QUEUED;
		}

	} lws_end_foreach_dll_safe(d, d1);

solo:
	lws_vhost_unlock(wsi->a.vhost); /* } ---------------------------------- */
	lws_context_unlock(wsi->a.context); /* -------------- cx { */

	/* there is nobody already connected in the same way */

	return ACTIVE_CONNS_SOLO;
}
#endif
#endif

const char *
lws_vh_tag(struct lws_vhost *vh)
{
	return lws_lc_tag(&vh->lc);
}

struct lws_log_cx *
lwsl_vhost_get_cx(struct lws_vhost *vh)
{
	if (!vh)
		return NULL;

	return vh->lc.log_cx;
}

void
lws_log_prepend_vhost(struct lws_log_cx *cx, void *obj, char **p, char *e)
{
	struct lws_vhost *vh = (struct lws_vhost *)obj;

	*p += lws_snprintf(*p, lws_ptr_diff_size_t(e, (*p)), "%s: ",
							lws_vh_tag(vh));
}

/*
 * stitch protocol choice into the vh protocol linked list
 * We always insert ourselves at the start of the list
 *
 * X <-> B
 * X <-> pAn <-> pB
 *
 * Illegal to attach more than once without detach inbetween
 */
void
lws_same_vh_protocol_insert(struct lws *wsi, int n)
{
	lws_context_lock(wsi->a.context, __func__);
	lws_vhost_lock(wsi->a.vhost);

	lws_dll2_remove(&wsi->same_vh_protocol);
	lws_dll2_add_head(&wsi->same_vh_protocol,
			  &wsi->a.vhost->same_vh_protocol_owner[n]);

	lws_vhost_unlock(wsi->a.vhost);
	lws_context_unlock(wsi->a.context);
}

void
__lws_same_vh_protocol_remove(struct lws *wsi)
{
	if (wsi->a.vhost && wsi->a.vhost->same_vh_protocol_owner)
		lws_dll2_remove(&wsi->same_vh_protocol);
}

void
lws_same_vh_protocol_remove(struct lws *wsi)
{
	if (!wsi->a.vhost)
		return;

	lws_context_lock(wsi->a.context, __func__);
	lws_vhost_lock(wsi->a.vhost);

	__lws_same_vh_protocol_remove(wsi);

	lws_vhost_unlock(wsi->a.vhost);
	lws_context_unlock(wsi->a.context);
}
