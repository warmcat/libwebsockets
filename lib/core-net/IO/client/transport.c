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
 * The transport the role asked for is up.  A role that starts its own
 * protocol from here says so with client_transport_up; otherwise the user
 * hears the connection exists and the role's state machine takes it from
 * there.  Returns 0, or 1 when the wsi is closed and freed.
 */
static int
lws_client_transport_up(struct lws *wsi)
{
	const char *cce;
	int n, m;

	if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_client_transport_up)) {
		n = lws_rops_func_fidx(wsi->role_ops,
				       LWS_ROPS_client_transport_up).
					client_transport_up(wsi);
		if (n < 0) {
			cce = "role transport up failed";
			goto failed;
		}

		return !!n; /* 1: the role closed it already */
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
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client transport up");

	return 1;
}

/*
 * The socket is connected to the peer, or to the proxy and the tunnel through
 * it is up: start tls if the connection asked for it, else the transport is
 * up now.  Returns 0 (the transport is up, or its tls handshake is under way
 * and the transport stage finishes it), or 1 when the wsi is closed and freed.
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
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "client create tls");

			return 1;
		}
	}
#endif

	return lws_client_transport_up(wsi);
}

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
