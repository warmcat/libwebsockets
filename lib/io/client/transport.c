/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 *
 * The client transport machine (README.sans-io-split.md): dns, the tcp
 * connect and its racers, and the tls handshake are IO's, and the role hears
 * of them once, through its client_transport_up op, when the transport it
 * asked for is up.  The socks and http CONNECT legs in between are protocol
 * bytes and stay the role's rx; when a tunnel comes up the role says so with
 * lws_client_transport_connected() and IO carries on from there.
 */

#include "private-lib-core.h"

#if defined(LWS_WITH_CLIENT)

#if defined(LWS_WITH_TLS)
static int
lws_client_is_quic(struct lws *wsi)
{
#if defined(LWS_ROLE_QUIC)
	return wsi->role_ops && !strcmp(wsi->role_ops->name, "quic");
#else
	(void)wsi;

	return 0;
#endif
}
#endif

/*
 * The client wsi's connection could not go on, and was closed: 1 when the
 * close freed it, 2 when it lives on in its close (a restart, a staged
 * close).  Either way it is not to be touched further in this pass.
 */
static int
lws_client_transport_closed(lws_handling_result_t hr)
{
	return hr == LWS_HPI_RET_WSI_ALREADY_DIED ? 1 : 2;
}

/*
 * The transport the role asked for is up.  A role that starts its own
 * protocol from here says so with client_transport_up; otherwise the user
 * hears the connection exists and the role's state machine takes it from
 * there.  Returns 0, or what lws_client_transport_closed() says when the
 * connection could not go on.
 */
static int
lws_client_transport_up(struct lws *wsi)
{
	const lws_sockaddr46 *peer = lws_io_peer(wsi);
	const char *cce;
	int n, m;

#if defined(LWS_WITH_UDP)
	/*
	 * The connection's peer address is the last connect attempt's, and a
	 * tcp racer to another of the dns results may have been started after
	 * the datagram socket was aimed: the datagram peer is where that is
	 */
	if (wsi->io->udp)
		peer = &wsi->io->udp->sa46;
#endif

	if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_client_transport_up)) {
		lws_handling_result_t hr = lws_rops_func_fidx(wsi->role_ops,
				       LWS_ROPS_client_transport_up).
					client_transport_up(wsi, peer);

		switch (hr) {
		case LWS_HPI_RET_HANDLED:
			return 0;
		case LWS_HPI_RET_WSI_ALREADY_DIED:
		case LWS_HPI_RET_CLOSING:
			/* the role closed it itself */
			return lws_client_transport_closed(hr);
		default:
			cce = "role transport up failed";
			goto failed;
		}
	}

	/* clear his established timeout */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	/*
	 * The transport is up before the user hears of it (as C-556 in the
	 * raw role): a callback that completes or closes the connection
	 * leaves it in a close phase, from which TRANSPORT_UP raised
	 * afterwards has no row
	 */
	lws_wsi_event(wsi, LWS_WSIEV_TRANSPORT_UP);

	m = wsi->role_ops->adoption_cb[0];
	if (m) {
		n = user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
						(enum lws_callback_reasons)m,
						wsi->user_space, NULL, 0);
		if (n < 0) {
			cce = "adoption callback failed";
			goto failed;
		}
	}

	return 0;

failed:
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

	return lws_client_transport_closed(_lws_close_free_wsi(wsi,
			LWS_CLOSE_STATUS_NOSTATUS, "client transport up"));
}

/*
 * The socket is connected to the peer, or to the proxy and the tunnel through
 * it is up: start tls if the connection asked for it, else the transport is
 * up now.  Returns 0 (the transport is up, or its tls handshake is under way
 * and the transport stage finishes it), or what lws_client_transport_closed()
 * says when the connection could not go on.
 */
int
lws_client_transport_connected(struct lws *wsi)
{
#if defined(LWS_WITH_TLS)
	const char *cce = "";
#endif

	/* an h1 client's tcp is up before its tls: the protocol hears it */
	if (lwsi_role_http(wsi))
		lws_wsi_event(wsi, LWS_WSIEV_SOCKET_CONNECTED);

#if defined(LWS_WITH_TLS)
	/* quic drives its own tls handshake inside its packets */
	if ((wsi->use_ssl & LCCSCF_USE_SSL) && !lws_client_is_quic(wsi)) {
		/*
		 * We can retry this... just cook the SSL BIO the first
		 * time
		 */
		switch (lws_client_create_tls(wsi, &cce, 1)) {
		case CCTLS_RETURN_DONE:
			break;
		case CCTLS_RETURN_RETRY:
			/*
			 * The handshake is under way (LTS_WAITING_SSL): the
			 * transport stage carries it on as the socket becomes
			 * readable or writable, under a timeout
			 */
			lws_set_timeout(wsi, PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
					(int)wsi->a.context->timeout_secs);

			return 0;
		default:
			lws_inform_client_conn_fail(wsi, (void *)cce,
						    strlen(cce));

			return lws_client_transport_closed(_lws_close_free_wsi(
					wsi, LWS_CLOSE_STATUS_NOSTATUS,
					"client create tls"));
		}
	}
#endif

	return lws_client_transport_up(wsi);
}

/*
 * A role whose transport is made inside its own protocol says when it is up:
 * quic's connection exists once its handshake, inside its packets, is done.
 * It has won the race for the connection (README.sans-io-split.md): the tcp
 * connects racing it as the fallback, the timers pacing them and the h3
 * grace, and any dns still out for it, go now, while this wsi still holds
 * them and before the role moves the connection anywhere else.
 */
void
lws_client_transport_established(struct lws *wsi)
{
	lws_io_abort_connect(wsi);
}

#if defined(LWS_ROLE_H3) || defined(LWS_ROLE_QUIC)
/*
 * A role that makes its transport inside its own protocol says when that
 * failed before it was up (quic: its handshake never completed).  Retargeting
 * the connection is IO's: the next of the sorted dns results for another quic
 * attempt, and after those tcp, with the learned h3 alternative and the
 * cached h3 alpn for the origin forgotten.  Returns 1 when the connection was
 * retargeted (it goes on as a redirect-marked restart), 0 when there is
 * nothing left to try and the failure stands.
 */
int
lws_client_transport_failed(struct lws *wsi)
{
	const char *path = wsi->stash ? wsi->stash->cis[CIS_PATH] : lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI);
	const char *host = wsi->stash ? wsi->stash->cis[CIS_HOST] : lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_HOST);
	/* the header table has the address once the stash is gone */
	const char *ads = lws_wsi_client_stash_item(wsi, CIS_ADDRESS, _WSI_TOKEN_CLIENT_PEER_ADDRESS);
	char ads_fallback[48];

	/* the next dns result, if there is one left, is the fallback */
	if (lws_io_dns_next(wsi, ads_fallback, sizeof(ads_fallback))) {
		if (ads_fallback[0] && host && path) {
			lwsl_wsi_notice(wsi, "QUIC fail, trying next DNS result %s", ads_fallback);
			lws_addrinfo_clean(wsi);
			if (lws_client_reset(&wsi,
					!!(wsi->use_ssl & LCCSCF_USE_SSL),
					ads_fallback, wsi->c_port, path, host, 1)) {
				return 1;
			}
		}
	}

	if (!ads) ads = host;

	if (ads && host && path) {
		wsi->tried_quic = 0;
		lwsl_wsi_notice(wsi, "QUIC connection failed, falling back to TCP");
		/*
		 * Forget any learned h3 alternative for this origin,
		 * it just failed... per RFC 7838 return to the origin
		 * until the alternative is advertised again
		 */
		lws_client_alt_svc_forget(wsi);
		lws_addrinfo_clean(wsi);

		/*
		 * Invalidate any cached h3 ALPN for this host:port so
		 * the post-reset connect path does not immediately try
		 * QUIC again.  We write "h2" with a short (60 s) TTL so
		 * the preference is temporary -- QUIC may work again
		 * later when transient conditions clear.
		 */
		if (wsi->a.context->alpn_cache && wsi->c_port) {
			char _key[256];
			void *_p;
			lws_snprintf(_key, sizeof(_key), "alpn_%s_%u",
				     ads, wsi->c_port);
			lws_cache_write_through(wsi->a.context->alpn_cache,
						_key, (const uint8_t *)"h2", 3,
						lws_now_usecs() +
						(60LL * LWS_US_PER_SEC),
						&_p);
		}
		/*
		 * Clear discovered ALPN so connect_2_restart does not
		 * see h3 from the cache-hit path.  Keep the original
		 * offered ALPN for the retry, so an h1 streamtype does
		 * not silently become h2... but if h3 was explicitly
		 * offered, fall back to the TCP alpns for the retry.
		 */
		wsi->io->alpn_discovered[0] = '\0';
		/* the QUIC attempt had set wsi alpn to h3, recover
		 * the original from the ah headers, or TCP alpns */
		if (strstr(wsi->alpn, "h3")) {
			const char *orig = lws_hdr_simple_ptr(wsi,
						_WSI_TOKEN_CLIENT_ALPN);

			if (!orig || strstr(orig, "h3"))
				orig = "h2,http/1.1";

			lws_strncpy(wsi->alpn, orig,
				    sizeof(wsi->alpn));
		}

		if (lws_client_reset(&wsi,
				!!(wsi->use_ssl & LCCSCF_USE_SSL),
				ads, wsi->c_port, path, host, 1)) {
			/* Successfully scheduled fallback */
			return 1;
		}
	}

	return 0;
}
#endif

#if defined(LWS_WITH_TLS_JIT_TRUST)
/*
 * A restarted client may belong on another vhost now: the one jit trust
 * keeps for its new endpoint, whose trust store knows that peer.
 */
void
lws_client_transport_rebind(struct lws *wsi)
{
	const struct lws_protocols *pr = NULL;
	struct lws_vhost *vh = NULL;

	if (!wsi->stash || !wsi->stash->cis[CIS_ADDRESS])
		return;

	lws_tls_jit_trust_vhost_bind(wsi->a.context,
				     wsi->stash->cis[CIS_ADDRESS], wsi->c_port,
				     wsi->stash->cis[CIS_HOST], &vh);
	if (!vh || vh == wsi->a.vhost)
		return;

	/*
	 * His protocol is an entry in the old vhost's own protocol table,
	 * which goes when that vhost does: he must take the same protocol
	 * from the new vhost's table.  If it has none, he stays where he is.
	 */
	if (wsi->a.protocol) {
		if (wsi->a.protocol->name)
			pr = lws_vhost_name_to_protocol(vh,
							wsi->a.protocol->name);
		if (!pr) {
			lwsl_wsi_notice(wsi, "vh %s lacks protocol, not moved",
					vh->name);
			return;
		}
	}

	/*
	 * Rebind through the proper helper: it unbinds the old vhost itself
	 * (unbinding here first would clear wsi->a.vhost and disarm its
	 * dying-vhost and mTLS rebind refusals, which test that)
	 */
	lws_vhost_bind_wsi(vh, wsi);

	if (pr && wsi->a.vhost == vh)
		wsi->a.protocol = pr;
}
#endif

/*
 * A connection whose bytes a transport carries (lws_set_transport()): there
 * is no dns lookup or connect, the fd it was given is its place in the poll
 * set, and the transport is connected from the start.  Returns the wsi, or
 * NULL when it was closed and freed.
 */
struct lws *
lws_client_connect_transport(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const char *cce = "transport insert fd";

	lws_wsi_event(wsi, LWS_WSIEV_CONNECT_START);

	/*
	 * The fd the transport was given is the connection's only way to its
	 * peer, and the connection's close took it.  So a transport-carried
	 * connection cannot be restarted the way a dialed one can (a
	 * redirect, a digest auth retry): it fails instead of going into the
	 * poll set with no fd.
	 */
	if (!lws_socket_is_valid(wsi->io->desc.sockfd)) {
		cce = "transport connection cannot restart";
		goto failed;
	}

	if (wsi->a.context->event_loop_ops->sock_accept &&
	    wsi->a.context->event_loop_ops->sock_accept(wsi)) {
		cce = "transport sock accept";
		goto failed;
	}

	lws_pt_lock(pt, __func__);
	if (__insert_wsi_socket_into_fds(wsi->a.context, wsi)) {
		lws_pt_unlock(pt);
		goto failed;
	}
	lws_pt_unlock(pt);

	lws_metrics_caliper_report(wsi->cal_conn, METRES_GO);

	if (wsi->a.protocol)
		wsi->a.protocol->callback(wsi, LWS_CALLBACK_WSI_CREATE,
					  wsi->user_space, NULL, 0);

	return lws_client_connect_4_established(wsi, NULL, 0);

failed:
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client transport");

	return NULL;
}

/*
 * The client transport phases IO drives itself, before any role sees the
 * pass: the dns lookup, the connect (and its racers) and the tls handshake.
 * Returns 0 when this is not such a pass (the role's rx and handler take it),
 * 1 when the wsi died in it, 2 when it was consumed here.
 */
int
lws_client_transport_stage(struct lws *wsi, struct lws_pollfd *pollfd)
{
#if defined(LWS_WITH_TLS)
	char ebuf[128];
	int n;
#endif

	if (!lwsi_role_client(wsi))
		return 0;

	switch (lwsi_transport(wsi)) {
	case LTS_WAITING_DNS:
		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 */
		if (!lws_client_connect_2_dnsreq_MAY_CLOSE_WSI(wsi))
			return 1;

		/* either still pending connection, or changed mode */
		return 2;

	case LTS_WAITING_CONNECT:
		/*
		 * A writeable socket is this fd's attempt completing, a
		 * hangup or error its failure; connect_3 dispositions either,
		 * for the primary or for a racer on the same wsi (the racer's
		 * fd is what poll reported), so a live racer can still win
		 * rather than the whole wsi being killed here.
		 */
		if ((pollfd->revents & (LWS_POLLOUT | LWS_POLLHUP)) &&
		    !lws_client_connect_3_connect(wsi, NULL, NULL, 0, pollfd))
			return 1;

		return 2;

#if defined(LWS_WITH_TLS)
	case LTS_WAITING_SSL:
		/* quic drives its own tls handshake inside its packets */
		if (lws_client_is_quic(wsi))
			return 0;

		/*
		 * The handshake asks for writeable itself when it needs it:
		 * the pass's POLLOUT is one-shot here
		 */
		if ((pollfd->revents & LWS_POLLOUT) &&
		    lws_change_pollfd(wsi, LWS_POLLOUT, 0))
			goto fail;

		n = lws_ssl_client_connect2(wsi, ebuf, sizeof(ebuf));
		if (!n)
			return 2; /* more service */
		if (n < 0) {
			lws_inform_client_conn_fail(wsi, (void *)ebuf,
						    strlen(ebuf));
			goto fail;
		}

		if (lws_client_transport_up(wsi))
			return 1;

		return 2;
#endif
	default:
		return 0;
	}

#if defined(LWS_WITH_TLS)
fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client tls");

	return 1;
#endif
}

#endif /* LWS_WITH_CLIENT */
