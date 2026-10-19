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
 * What a server connection sends first, looked at before its tls or its role
 * sees any of it
 * --------------------------------------------------------------------------
 *
 * Two things want to see a connection's first bytes before anything else:
 *
 *  - a PROXY v2 header (lws-proxy-v2.h), from a proxy in a vhost's
 *    .proxy_v2_trusted list, saying who the client it forwards really is.  It
 *    is taken off the connection, so whatever follows sees only the client's
 *    bytes, and the client it names becomes the connection's peer address;
 *
 *  - the SNI name in the ClientHello, in case it names a vhost whose
 *    .tls_passthrough says to pass the connection, still encrypted, to
 *    another server that terminates the tls itself.
 *
 * So an accepted connection on a listener where either applies is held in a
 * "pre-accept" stage, which IO owns, as it does the tls accept, until both
 * are settled.  The ClientHello is only peeked, never read, so a connection
 * that is not passed through goes on to the listener's tls, on any tls
 * backend, or its role, exactly as if it had just been accepted.  One that
 * is passed through becomes a raw connection spliced to a new raw client
 * connection to the server, which is sent our PROXY v2 header first if the
 * vhost says so.
 *
 * Peeking leaves the bytes in the socket, so a level-triggered POLLIN keeps
 * firing while we wait for the rest of a ClientHello, or of a header, that
 * arrived in pieces: then POLLIN is taken off, and given back a little later
 * by a timer, so we look again without spinning.  The connection's accept
 * timeout bounds how long that can go on.
 *
 * What we do then must be proportional to what the peer sends, not to how
 * long it makes us wait: a peer that sends most of a ClientHello and goes
 * quiet must not have it copied and parsed again every few ms until the
 * timeout.  So the wait backs off each time, and the ClientHello is only
 * peeked and parsed again once more of it has arrived.
 */

#include "private-lib-core.h"

/*
 * How long to wait before peeking again at a partial header or ClientHello:
 * 10ms the first time, doubling each time after, up to 160ms
 */
#define LWS_PRE_ACCEPT_REPEEK_US	(10 * LWS_US_PER_MS)
#define LWS_PRE_ACCEPT_REPEEK_MAX_SHIFT	4

/* stop reading one side while this much is queued for the other */
#define LWS_PASSTHROUGH_HIGH		(256 * 1024)
#define LWS_PASSTHROUGH_LOW		(64 * 1024)

enum {
	PT_ACC,		/* the client's connection we accepted */
	PT_ONW		/* ours, onward to the server */
};

typedef struct lws_proxy_v2_trust {
	lws_dll2_t		list;
	lws_sockaddr46		sa46;
	int			net_len;
} lws_proxy_v2_trust_t;

/*
 * One passed through connection, shared by its two legs, which reach it
 * through their opaque user data.  The last leg to close frees it.
 */
typedef struct lws_passthrough_conn {
	struct lws		*wsi[2];
	struct lws_buflist	*bl[2];		/* waiting to be written to wsi[n] */
	size_t			queued[2];
	uint8_t			closed[2];
	uint8_t			rx_held[2];	/* we stopped reading wsi[n] */
} lws_passthrough_conn_t;

/* ------------------------------------------------------------------ config */

static int
lws_passthrough_parse_trusted(struct lws_vhost *vh, const char *list)
{
	struct lws_tokenize ts;
	lws_proxy_v2_trust_t *t;
	char tok[64];

	lws_tokenize_init(&ts, list, LWS_TOKENIZE_F_COMMA_SEP_LIST |
				     LWS_TOKENIZE_F_NO_INTEGERS |
				     LWS_TOKENIZE_F_DOT_NONTERM |
				     LWS_TOKENIZE_F_MINUS_NONTERM |
				     LWS_TOKENIZE_F_COLON_NONTERM |
				     LWS_TOKENIZE_F_SLASH_NONTERM);
	ts.len = strlen(list);

	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		switch (ts.e) {
		case LWS_TOKZE_TOKEN:
			if (lws_tokenize_cstr(&ts, tok, sizeof(tok)))
				goto bad;
			t = lws_zalloc(sizeof(*t), __func__);
			if (!t)
				return 1;
			if (lws_parse_cidr(tok, &t->sa46, &t->net_len)) {
				lws_free(t);
				goto bad;
			}
			lws_dll2_add_tail(&t->list, &vh->proxy_v2_trusted);
			break;
		case LWS_TOKZE_DELIMITER:
		case LWS_TOKZE_ENDED:
			break;
		default:
			goto bad;
		}
	} while (ts.e > 0);

	return 0;

bad:
	lwsl_vhost_err(vh, "proxy-v2-trusted: '%s' is not a list of numeric "
		       "addresses or netblocks", list);

	return 1;
}

int
lws_passthrough_vhost_init(struct lws_vhost *vh,
			   const struct lws_context_creation_info *info)
{
	if (info->proxy_v2_trusted && *info->proxy_v2_trusted &&
	    lws_passthrough_parse_trusted(vh, info->proxy_v2_trusted))
		return 1;

	if (info->tls_passthrough && *info->tls_passthrough) {
		char host[256];
		const char *colon;
		size_t hl;
		int port;

		/* host:port, or [v6]:port */

		colon = strrchr(info->tls_passthrough, ':');
		if (!colon || colon == info->tls_passthrough)
			goto bad_target;
		port = atoi(colon + 1);
		if (port < 1 || port > 65535)
			goto bad_target;

		hl = lws_ptr_diff_size_t(colon, info->tls_passthrough);
		if (info->tls_passthrough[0] == '[') {
			if (hl < 3 || colon[-1] != ']')
				goto bad_target;
			lws_strnncpy(host, info->tls_passthrough + 1, hl - 2,
				     sizeof(host));
		} else
			lws_strnncpy(host, info->tls_passthrough, hl,
				     sizeof(host));
		if (!host[0] || strchr(host, '[') || strchr(host, ']'))
			goto bad_target;

		vh->passthrough_host = lws_strdup(host);
		if (!vh->passthrough_host)
			return 1;
		vh->passthrough_port = (uint16_t)port;
		vh->passthrough_proxy_v2 = !!info->tls_passthrough_proxy_v2;

#if defined(LWS_ROLE_QUIC)
		/*
		 * Its quic is relayed too if we can say who the client is,
		 * to a server given numerically: there is no time to resolve
		 * a name while a client's Initials wait
		 */
		if (vh->passthrough_proxy_v2 &&
		    !lws_sa46_parse_numeric_address(host,
						    &vh->passthrough_sa46)) {
			sa46_sockport(&vh->passthrough_sa46,
				      htons((uint16_t)port));
			vh->context->count_quic_passthrough++;
		} else
			memset(&vh->passthrough_sa46, 0,
			       sizeof(vh->passthrough_sa46));
#endif

		lwsl_vhost_notice(vh, "tls for %s passed through to %s:%d%s",
				  vh->name, host, port,
				  vh->passthrough_proxy_v2 ?
						" with a PROXY v2 header" : "");
	}

	return 0;

bad_target:
	lwsl_vhost_err(vh, "tls-passthrough: '%s' is not host:port",
		       info->tls_passthrough);

	return 1;
}

#if defined(LWS_ROLE_QUIC)
static void
lws_qpt_vhost_gone(struct lws_vhost *vh);
#endif

void
lws_passthrough_vhost_destroy(struct lws_vhost *vh)
{
#if defined(LWS_ROLE_QUIC)
	if (vh->passthrough_sa46.sa4.sin_family) {
		vh->context->count_quic_passthrough--;
		memset(&vh->passthrough_sa46, 0, sizeof(vh->passthrough_sa46));
	}
	lws_qpt_vhost_gone(vh);
#endif

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vh->proxy_v2_trusted)) {
		lws_dll2_remove(d);
		lws_free(lws_container_of(d, lws_proxy_v2_trust_t, list));
	} lws_end_foreach_dll_safe(d, d1);

	lws_free_set_NULL(vh->passthrough_host);
}

/* -------------------------------------------------------------- pre-accept */

/*
 * Does any vhost on lv's listener trust peer to send a PROXY v2 header?  If
 * so, a connection from it on that listener is held in the pre-accept stage
 * for it, and attributed to the client it names.
 */
int
lws_proxy_v2_trusts(struct lws_vhost *lv, const lws_sockaddr46 *peer)
{
	struct lws_vhost *v;

	for (v = lws_vhost_first(lv->context); v; v = lws_vhost_next(v)) {
		if (v->being_destroyed ||
		    (v != lv && !lws_vhost_compare_listen(v, lv)))
			continue;

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&v->proxy_v2_trusted)) {
			lws_proxy_v2_trust_t *t = lws_container_of(d,
						lws_proxy_v2_trust_t, list);

			if (!lws_sa46_on_net(peer, &t->sa46, t->net_len))
				return 1;
		} lws_end_foreach_dll(d);
	}

	return 0;
}

/*
 * Called when a server connection is adopted, before its tls or role sees
 * anything.  Returns 1 if it is held in the pre-accept stage: from a proxy
 * any vhost on the listener trusts for a PROXY v2 header, or on a listener
 * where some vhost is passed through.
 */
int
lws_pre_accept_wanted(struct lws *wsi, int tls)
{
	struct lws_vhost *lv = wsi->a.vhost, *v;
	lws_sockaddr46 peer;
	socklen_t sl = sizeof(peer);
	int trusted = 0, sni = 0;

	memset(&peer, 0, sizeof(peer));
	if (!getpeername(wsi->io->desc.sockfd, (struct sockaddr *)&peer, &sl))
		trusted = lws_proxy_v2_trusts(lv, &peer);

	for (v = lws_vhost_first(wsi->a.context); v; v = lws_vhost_next(v))
		if (!v->being_destroyed && v->passthrough_host &&
		    (v == lv || lws_vhost_compare_listen(v, lv)))
			sni = 1;

	if (!trusted && !sni)
		return 0;

	wsi->io->pre_accept	= 1;
	wsi->io->pa_tls		= tls ? 1 : 0;
	wsi->io->pa_proxy_v2	= trusted ? 1 : 0;
	wsi->io->pa_sni		= sni ? 1 : 0;

	return 1;
}

static void
lws_pre_accept_repeek_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_io_adjunct *io = lws_container_of(sul,
					struct lws_io_adjunct, sul_pre_accept);

	if (lws_change_pollfd(io->wsi, 0, LWS_POLLIN))
		lws_set_timeout(io->wsi, PENDING_TIMEOUT_USER_OK,
				LWS_TO_KILL_ASYNC);
}

/*
 * Some of what we need has arrived, but not all of it: stop POLLIN firing for
 * the bytes we already saw, and look again in a moment
 */
static int
lws_pre_accept_wait(struct lws *wsi)
{
	lws_usec_t us = LWS_PRE_ACCEPT_REPEEK_US <<
			(wsi->io->pa_waits < LWS_PRE_ACCEPT_REPEEK_MAX_SHIFT ?
			 wsi->io->pa_waits : LWS_PRE_ACCEPT_REPEEK_MAX_SHIFT);

	/*
	 * Backing off whether or not more came meanwhile: the peer cannot buy
	 * itself a look every 10ms by sending a byte at a time either
	 */
	if (wsi->io->pa_waits < 255)
		wsi->io->pa_waits++;

	if (lws_change_pollfd(wsi, LWS_POLLIN, 0))
		return 1;

	lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->io->sul_pre_accept,
			 lws_pre_accept_repeek_cb, us);

	return 0;
}

void
lws_pre_accept_destroy(struct lws *wsi)
{
	lws_sul_cancel(&wsi->io->sul_pre_accept);
	lws_free_set_NULL(wsi->io->pa_peek);
	wsi->io->pre_accept = 0;
}

/*
 * Peek at up to len of what the peer sent so far.  Returns how much there is,
 * 0 if nothing yet, or -1 if he hung up or the socket failed.
 */
static ssize_t
lws_pre_accept_peek(struct lws *wsi, uint8_t *buf, size_t len)
{
	ssize_t s = recv(wsi->io->desc.sockfd, (char *)buf,
			 LWS_POSIX_LENGTH_CAST(len), MSG_PEEK);

	if (s > 0)
		return s;

	if (s < 0 && (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK ||
		      LWS_ERRNO == LWS_EINTR))
		return 0;

	return -1;
}

/*
 * The PROXY v2 header a trusted proxy must start with.  Returns 0 when it has
 * been taken, 1 if we must wait for more of it, or -1 to drop him.
 */
static int
lws_pre_accept_proxy_v2(struct lws *wsi)
{
	uint8_t hdr[LWS_PROXY_V2_MAX];
	char peer[64], client[64];
#if defined(LWS_WITH_PEER_LIMITS)
	struct lws_peer *pl;
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	int ah_held;
#endif
#endif
	lws_proxy_v2_t pv;
	ssize_t s;
	int n;

	s = lws_pre_accept_peek(wsi, hdr, sizeof(hdr));
	if (s <= 0)
		return s ? -1 : 1;

	lws_get_peer_simple_fd(wsi->io->desc.sockfd, peer, sizeof(peer));

	n = lws_proxy_v2_header_len(hdr, (size_t)s);
	if (n < 0) {
		lwsl_wsi_warn(wsi, "trusted proxy %s did not start with a "
			      "PROXY v2 header: dropped", peer);
		return -1;
	}
	if (!n || s < n)
		return 1;

	/* take exactly the header off the connection, nothing after it */
	if (recv(wsi->io->desc.sockfd, (char *)hdr, LWS_POSIX_LENGTH_CAST(n),
		 0) != n)
		return -1;

	if (lws_proxy_v2_parse(hdr, (size_t)n, &pv)) {
		lwsl_wsi_warn(wsi, "trusted proxy %s sent an invalid PROXY v2 "
			      "header: dropped", peer);
		return -1;
	}

	if (!pv.local) {
		if (pv.dgram) {
			lwsl_wsi_warn(wsi, "trusted proxy %s forwarded a "
				      "datagram client on a stream: dropped",
				      peer);
			return -1;
		}
		wsi->io->pstack[1].sa46 = pv.src;
		wsi->io->pstack_count = 2;
	}

	client[0] = '\0';
	if (!pv.local)
		lws_sa46_write_numeric_address(&pv.src, client, sizeof(client));
	lwsl_wsi_info(wsi, "proxy %s forwards %s", peer,
		      pv.local ? "its own connection" : client);

#if defined(LWS_WITH_PEER_LIMITS)
	/*
	 * Adoption left a trusted proxy's connection uncounted (see
	 * lws_adopt_descriptor_vhost_via_info()): now we know who it is, it
	 * counts against the client named, as a QUIC client the proxy relays
	 * does, or for a LOCAL header, the proxy's own connection, against the
	 * proxy.  Otherwise every client behind the proxy shares one budget,
	 * and any one of them can spend it for all the others.
	 */
	pl = lws_get_or_create_peer_sa46(wsi->a.vhost, pv.local ?
					 &wsi->io->pstack[0].sa46 : &pv.src);
	if (lws_peer_wsi_limit_reached(wsi->a.context, pl,
				       wsi->io->desc.sockfd)) {
		lwsl_wsi_info(wsi, "%s %s at its connection limit: dropped",
			      pv.local ? "proxy" : "client",
			      pv.local ? peer : client);
		return -1;
	}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	/*
	 * An http role attaches an ah at adoption, when nobody was counting
	 * him: give it back while he is still nobody's, and ask again once he
	 * is the peer's, so that it is counted against the peer, and
	 * ip_limit_ah may leave him waiting for one like any other connection
	 * of the peer's.  Nothing has been read into it yet: the role only
	 * reads once we are done here.
	 */
	ah_held = !!wsi->stream.ah;
	if (ah_held)
		lws_header_table_detach(wsi, 0);
#endif

	lws_peer_add_wsi(wsi->a.context, pl, wsi);

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (ah_held) {
		/* attached, or waiting for one: both leave him as he was */
		n = lws_header_table_attach(wsi, 0);
		/* only autoservice or a client connect can close him in there */
		assert(n != LWS_AH_ATTACH_WSI_GONE);
	}
#endif
#endif

	return 0;
}

static int
lws_passthrough_start(struct lws *wsi, struct lws_vhost *vh, const char *sni);

int
lws_pre_accept_service(struct lws *wsi)
{
	struct lws_vhost *vh;
	char name[256];
	ssize_t s;
	int n;

	/* nothing is written to him from here until we know what he is */
	if (lws_change_pollfd(wsi, LWS_POLLOUT, 0))
		return 1;

	if (wsi->io->pa_proxy_v2) {
		n = lws_pre_accept_proxy_v2(wsi);
		if (n < 0)
			return 1;
		if (n)
			return lws_pre_accept_wait(wsi);
		wsi->io->pa_proxy_v2 = 0;
		/* the ClientHello gets its own backoff */
		wsi->io->pa_waits = 0;
	}

	if (wsi->io->pa_sni) {
		size_t pending;

		/*
		 * POLLIN only says the bytes we already looked at are still
		 * there: if the platform can tell us nothing was added to
		 * them, don't copy and parse them again to find that out
		 */
		if (wsi->io->pa_seen &&
		    !lws_plat_rx_pending(wsi->io->desc.sockfd, &pending) &&
		    pending <= wsi->io->pa_seen)
			return lws_pre_accept_wait(wsi);

		if (!wsi->io->pa_peek) {
			wsi->io->pa_peek = lws_malloc(LWS_TLS_CH_MAX, __func__);
			if (!wsi->io->pa_peek)
				return 1;
		}

		s = lws_pre_accept_peek(wsi, wsi->io->pa_peek, LWS_TLS_CH_MAX);
		if (s < 0)
			return 1;
		if (!s)
			/* nothing yet: POLLIN will tell us */
			return 0;

		if ((size_t)s <= wsi->io->pa_seen)
			/* nothing new since we last looked */
			return lws_pre_accept_wait(wsi);
		wsi->io->pa_seen = (size_t)s;

		n = lws_tls_client_hello_sni(wsi->io->pa_peek, (size_t)s, name,
					     sizeof(name));
		if (n == LWS_TLS_CH_SNI_MORE && s < LWS_TLS_CH_MAX)
			return lws_pre_accept_wait(wsi);

		wsi->io->pa_sni = 0;

		if (n == LWS_TLS_CH_SNI_FOUND) {
			vh = lws_select_vhost_by_name(wsi->a.context,
					wsi->a.vhost->listen_port, name);
			if (vh && vh->passthrough_host) {
				lws_pre_accept_destroy(wsi);

				return lws_passthrough_start(wsi, vh, name);
			}
		}
	}

	lws_pre_accept_destroy(wsi);

	if (wsi->io->pa_tls)
		/* he goes on to the tls accept, as if just accepted */
		return lws_server_socket_service_ssl(wsi, wsi->io->desc.sockfd,
						     1);

	if (wsi->a.vhost->passthrough_host) {
		/*
		 * The listener belongs to a vhost that is passed through and
		 * has no tls of its own, so there is nothing else here to
		 * serve him with.  A tls vhost on the same port must be made
		 * before any passed through one to own the listener.
		 */
		lwsl_wsi_info(wsi, "not for a passed through vhost, and "
			      "nothing else on this listener: dropped");
		return 1;
	}

	/*
	 * The role reads what he sent, unless he is waiting for an ah to read
	 * it into since he became the named client's
	 * (lws_pre_accept_proxy_v2()).  The role refuses to read without one,
	 * so readable meanwhile, he would be reported, and refused, on every
	 * poll until an ah frees up (G-209): he stays deaf until the ah's
	 * arrival turns POLLIN on (__lws_header_table_detach()).
	 */
#if defined(LWS_WITH_PEER_LIMITS) && \
    (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))
	if (lws_header_table_is_waiting(wsi))
		return lws_change_pollfd(wsi, LWS_POLLIN, 0);
#endif

	return lws_change_pollfd(wsi, 0, LWS_POLLIN);
}

/* ----------------------------------------------------------------- splicing */

static void
lws_passthrough_rx_hold(lws_passthrough_conn_t *c, int side, int hold)
{
	if (!c->wsi[side] || c->rx_held[side] == hold)
		return;

	c->rx_held[side] = (uint8_t)hold;
	lws_rx_flow_control(c->wsi[side], !hold);
}

static void
lws_passthrough_conn_free(lws_passthrough_conn_t *c)
{
	lws_buflist_destroy_all_segments(&c->bl[PT_ACC]);
	lws_buflist_destroy_all_segments(&c->bl[PT_ONW]);
	lws_free(c);
}

/*
 * One leg went: the other goes too once it has written what is waiting for
 * it, and the conn goes with the last of them
 */
static void
lws_passthrough_leg_gone(lws_passthrough_conn_t *c, int side)
{
	int other = !side;

	c->wsi[side] = NULL;
	c->closed[side] = 1;
	lws_buflist_destroy_all_segments(&c->bl[side]);
	c->queued[side] = 0;

	if (!c->wsi[other]) {
		if (c->closed[other])
			lws_passthrough_conn_free(c);
		return;
	}

	if (!c->queued[other])
		lws_set_timeout(c->wsi[other], PENDING_TIMEOUT_USER_OK,
				LWS_TO_KILL_ASYNC);
	else
		lws_callback_on_writable(c->wsi[other]);
}

static int
lws_passthrough_queue(lws_passthrough_conn_t *c, int to, const void *buf,
		      size_t len)
{
	if (lws_buflist_append_segment(&c->bl[to], buf, len) < 0)
		return 1;

	c->queued[to] += len;
	if (c->wsi[to])
		lws_callback_on_writable(c->wsi[to]);

	/* the side it came from waits for the other to catch up */
	if (c->queued[to] >= LWS_PASSTHROUGH_HIGH)
		lws_passthrough_rx_hold(c, !to, 1);

	return 0;
}

static int
lws_passthrough_callback(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{
	lws_passthrough_conn_t *c = (lws_passthrough_conn_t *)
						lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + 4096];
	int side, n;
	size_t m;

	if (!c)
		return 0;

	side = c->wsi[PT_ONW] == wsi ? PT_ONW : PT_ACC;

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		/* the server is there: he may talk to it */
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
		if (c->wsi[PT_ACC]) {
			lws_set_timeout(c->wsi[PT_ACC], NO_PENDING_TIMEOUT, 0);
			lws_passthrough_rx_hold(c, PT_ACC, 0);
		}
		if (c->queued[PT_ONW])
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_wsi_notice(wsi, "unable to reach the passed through "
				"server: %s", in ? (const char *)in : "?");
		lws_set_opaque_user_data(wsi, NULL);
		lws_passthrough_leg_gone(c, PT_ONW);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (lws_passthrough_queue(c, !side, in, len))
			return -1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		m = (size_t)lws_buflist_fragment_use(&c->bl[side],
				buf + LWS_PRE, sizeof(buf) - LWS_PRE, NULL, NULL);
		if (!m)
			break;
		n = lws_write(wsi, buf + LWS_PRE, m, LWS_WRITE_RAW);
		if (n < (int)m)
			return -1;
		c->queued[side] -= m;

		if (c->queued[side] <= LWS_PASSTHROUGH_LOW)
			lws_passthrough_rx_hold(c, !side, 0);

		if (c->queued[side])
			lws_callback_on_writable(wsi);
		else if (c->closed[!side])
			/* all he will get from the other side is written */
			return -1;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		lws_set_opaque_user_data(wsi, NULL);
		lws_passthrough_leg_gone(c, side);
		break;

	default:
		break;
	}

	(void)user;

	return 0;
}

const struct lws_protocols lws_passthrough_protocol = {
	.name		= "lws-tls-passthrough",
	.callback	= lws_passthrough_callback,
};

/*
 * The ClientHello on wsi names vh, which is passed through: make wsi a raw
 * connection of the vhost's passthrough protocol, and connect onward to the
 * server.  Returns nonzero to drop him.
 */
static int
lws_passthrough_start(struct lws *wsi, struct lws_vhost *vh, const char *sni)
{
	const struct lws_protocols *p;
	struct lws_client_connect_info i;
	lws_passthrough_conn_t *c;
	char peer[64];

	p = lws_vhost_name_to_protocol(vh, lws_passthrough_protocol.name);
	if (!p)
		return 1;

	c = lws_zalloc(sizeof(*c), __func__);
	if (!c)
		return 1;

	/* he belongs to the passed through vhost now */
	lws_vhost_bind_wsi(vh, wsi);
	if (wsi->a.vhost != vh) {
		lws_free(c);
		return 1;
	}

	c->wsi[PT_ACC] = wsi;
	lws_set_opaque_user_data(wsi, c);
	lws_bind_protocol(wsi, p, __func__);
	lws_wsi_event_role(wsi, LWS_WSIEV_RAW_UPGRADED, &role_ops_raw_skt);
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	lws_header_table_detach(wsi, 0);
#endif

	/*
	 * Nothing is read from him until the server is reached: what he sent
	 * is still in the socket, since we only peeked at it
	 */
	c->rx_held[PT_ACC] = 1;
	lws_rx_flow_control(wsi, 0);
	lws_set_timeout(wsi, PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
			(int)wsi->a.context->timeout_secs);

	lws_get_peer_simple(wsi, peer, sizeof(peer));

	if (vh->passthrough_proxy_v2) {
		uint8_t hdr[LWS_PROXY_V2_MAX];
		lws_proxy_v2_t pv;
		socklen_t sl;
		int n;

		memset(&pv, 0, sizeof(pv));

		/* the client, as we know it, which a proxy before us may say */
		if (wsi->io->pstack_count > 1)
			pv.src = wsi->io->pstack[1].sa46;
		else {
			sl = sizeof(pv.src);
			if (getpeername(wsi->io->desc.sockfd,
					(struct sockaddr *)&pv.src, &sl))
				goto bail;
		}
		sl = sizeof(pv.dst);
		if (getsockname(wsi->io->desc.sockfd,
				(struct sockaddr *)&pv.dst, &sl))
			goto bail;
#if defined(LWS_WITH_IPV6)
		/* the same family for both, as a v4-mapped listener gives */
		if (pv.src.sa4.sin_family == AF_INET &&
		    pv.dst.sa4.sin_family == AF_INET6 &&
		    lws_sa46_is_ipv4_mapped(&pv.dst)) {
			lws_sockaddr46 d = pv.dst;

			memset(&pv.dst, 0, sizeof(pv.dst));
			pv.dst.sa4.sin_family = AF_INET;
			memcpy(&pv.dst.sa4.sin_addr,
			       &d.sa6.sin6_addr.s6_addr[12], 4);
			pv.dst.sa4.sin_port = d.sa6.sin6_port;
		}
#endif
		lws_strncpy(pv.authority, sni, sizeof(pv.authority));

		n = lws_proxy_v2_render(&pv, hdr, sizeof(hdr));
		if (n < 0 || lws_passthrough_queue(c, PT_ONW, hdr, (size_t)n))
			goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context		= wsi->a.context;
	i.vhost			= vh;
	i.address		= vh->passthrough_host;
	i.port			= vh->passthrough_port;
	i.host			= i.address;
	i.method		= "RAW";
	i.local_protocol_name	= lws_passthrough_protocol.name;
	i.opaque_user_data	= c;
	i.pwsi			= &c->wsi[PT_ONW];

	lwsl_wsi_notice(wsi, "%s for %s passed through to %s:%u", peer, sni,
			vh->passthrough_host, vh->passthrough_port);

	if (!lws_client_connect_via_info(&i) && !c->closed[PT_ONW]) {
		/* it failed before it could tell us */
		c->wsi[PT_ONW] = NULL;
		c->closed[PT_ONW] = 1;
	}

	if (c->closed[PT_ONW]) {
		/* he is ours to drop: his close frees the conn */
		lws_buflist_destroy_all_segments(&c->bl[PT_ONW]);
		c->queued[PT_ONW] = 0;

		return 1;
	}

	return 0;

bail:
	lws_set_opaque_user_data(wsi, NULL);
	lws_passthrough_conn_free(c);

	return 1;
}

#if defined(LWS_ROLE_QUIC)
/* ------------------------------------------------------------ quic relay */

/*
 * QUIC passthrough
 * --------------------------------------------------------------------------
 *
 * A passed through vhost's QUIC goes the same way as its tcp, when its
 * .tls_passthrough is a numeric address and .tls_passthrough_proxy_v2 is set.
 *
 * On the front, a datagram arriving on a quic listener is looked at before the
 * quic role sees it:
 *
 *  - one whose DCID belongs to a relayed flow goes to the server, and if it
 *    came from a new address, the flow follows the client there;
 *
 *  - an Initial for a DCID we don't know is decrypted with the keys anyone
 *    can derive from its DCID (RFC 9001 5.2), and the SNI read from its
 *    ClientHello, holding the datagrams until the ClientHello is whole.  If
 *    it names a passed through vhost, a flow is made and they all go to the
 *    server; otherwise they go to the quic role as if just received.
 *
 * Every datagram to the server is sent from our udp socket for the vhost,
 * after a PROXY v2 header naming the client, and every datagram from the
 * server must start with one naming the client it is for.  So the server's
 * quic sees each client's real address, and runs its own path validation when
 * a client moves: we only send where it says.  The server's connection IDs
 * are learned from the long headers it sends, since a client goes on to use
 * them; a server that issues more with NEW_CONNECTION_ID, which lws does
 * not, would need them encoded so we could route them.
 *
 * On a server, a datagram from an address in .proxy_v2_trusted must start
 * with exactly one PROXY v2 header, or it is dropped; it is taken off, the
 * client it names is the datagram's peer as far as quic knows, and the relay
 * is remembered, so what quic sends that client goes back through it, with a
 * header naming the client.  Nobody else's datagrams are looked at for one.
 */

#define LWS_QPT_FLOW_IDLE_US		(60 * LWS_US_PER_SEC)
#define LWS_QPT_RELAYED_IDLE_US		(120 * LWS_US_PER_SEC)
#define LWS_QPT_PENDING_US		(500 * LWS_US_PER_MS)
#define LWS_QPT_SWEEP_US		(10 * LWS_US_PER_SEC)
#define LWS_QPT_PENDING_DGRAMS		8
#define LWS_QPT_MAX_FLOWS		4096
#define LWS_QPT_MAX_RELAYED		4096
#define LWS_QPT_MAX_PENDING		64
#define LWS_QPT_MAX_CIDS		4
#define LWS_QPT_MAX_DGRAM		4096

/*
 * An address as a map key, with nothing undefined in it.  A relayed client is
 * also keyed by the port of the listener it came in on: a process can be a
 * front as well as a server behind one, and the front's own clients must not
 * be taken for the server's.
 */
typedef struct lws_qpt_addr_key {
	uint8_t			addr[16];	/* v4 as v4-mapped v6 */
	uint16_t		port;
	uint16_t		lport;		/* our listener's, or 0 */
} lws_qpt_addr_key_t;

/* front: one connection we relay to a server */
typedef struct lws_qpt_flow {
	lws_dll2_t		list;		/* cx->pt_qflow_owner */
	struct lws_vhost	*vh;		/* the passed through vhost */
	int			listen_port;	/* where the client reaches us */
	lws_sockaddr46		client;		/* where it is now */
	lws_sockaddr46		prev_client;	/* where it was before */
	lws_usec_t		last;
	struct lws_quic_cid	cid[LWS_QPT_MAX_CIDS];
	int			count_cids;
} lws_qpt_flow_t;

/* front: a datagram held while the ClientHello is still coming */
typedef struct lws_qpt_dgram {
	lws_dll2_t		list;
	lws_sockaddr46		peer;
	size_t			len;
	uint8_t			ecn;
	/* the datagram follows */
} lws_qpt_dgram_t;

/* front: an Initial whose ClientHello we have not seen all of yet */
typedef struct lws_qpt_pending {
	lws_dll2_t		list;		/* cx->pt_qpending_owner */
	lws_sorted_usec_list_t	sul;
	struct lws_context	*cx;
	int			listen_port;
	struct lws_quic_cid	dcid;
	lws_dll2_owner_t	held;		/* lws_qpt_dgram_t */
	uint8_t			crypto[LWS_TLS_CH_MAX];
	uint8_t			have[LWS_TLS_CH_MAX / 8];
} lws_qpt_pending_t;

/* server: a client a trusted relay forwards */
typedef struct lws_qpt_relayed {
	lws_dll2_t		list;		/* cx->pt_relayed_owner */
	lws_qpt_addr_key_t	key;
	lws_sockaddr46		relay;		/* the relay's socket */
	lws_sockaddr46		front;		/* what the client sent to */
	lws_usec_t		last;
} lws_qpt_relayed_t;

static void
lws_qpt_key(const lws_sockaddr46 *sa, lws_qpt_addr_key_t *k)
{
	memset(k, 0, sizeof(*k));
#if defined(LWS_WITH_IPV6)
	if (sa->sa4.sin_family == AF_INET6) {
		memcpy(k->addr, &sa->sa6.sin6_addr, 16);
		k->port = sa->sa6.sin6_port;
		return;
	}
#endif
	k->addr[10] = k->addr[11] = 0xff;
	memcpy(&k->addr[12], &sa->sa4.sin_addr, 4);
	k->port = sa->sa4.sin_port;
}

static int
lws_qpt_same_addr(const lws_sockaddr46 *a, const lws_sockaddr46 *b)
{
	lws_qpt_addr_key_t ka, kb;

	lws_qpt_key(a, &ka);
	lws_qpt_key(b, &kb);

	return !memcmp(&ka, &kb, sizeof(ka));
}

static int
lws_qpt_maps(struct lws_context *cx)
{
	lws_map_info_t mi;

	memset(&mi, 0, sizeof(mi));
	mi.modulo = 64;

	if (!cx->pt_qflows)
		cx->pt_qflows = lws_map_create(&mi);
	if (!cx->pt_qpending)
		cx->pt_qpending = lws_map_create(&mi);
	if (!cx->pt_relayed)
		cx->pt_relayed = lws_map_create(&mi);

	return !cx->pt_qflows || !cx->pt_qpending || !cx->pt_relayed;
}

static void *
lws_qpt_lookup(struct lws_map *map, const void *key, size_t kl)
{
	struct lws_map_item *it;
	void *v;

	if (!map)
		return NULL;

	it = lws_map_item_lookup(map, (const lws_map_key_t)key, kl);
	if (!it)
		return NULL;

	/*
	 * The value is stored straight after the key, so it is only as
	 * aligned as the key length makes it: copy it out
	 */

	memcpy(&v, lws_map_item_value(it), sizeof(v));

	return v;
}

static void
lws_qpt_unmap(struct lws_map *map, const void *key, size_t kl)
{
	struct lws_map_item *it;

	if (map && (it = lws_map_item_lookup(map, (const lws_map_key_t)key, kl)))
		lws_map_item_destroy(it);
}

/* one of the quic listeners on port, to send a client a datagram from */
static struct lws *
lws_qpt_listener(struct lws_context *cx, int port)
{
	struct lws_vhost *v;

	for (v = lws_vhost_first(cx); v; v = lws_vhost_next(v)) {
		if (v->being_destroyed || v->listen_port != port)
			continue;
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&v->listen_wsi)) {
			struct lws *lw = lws_container_of(d, struct lws,
							  listen_list);

			if (lw->role_ops == &role_ops_quic && lw->io->udp &&
			    lws_socket_is_valid(lw->io->desc.sockfd))
				return lw;
		} lws_end_foreach_dll(d);
	}

	return NULL;
}

static void
lws_qpt_flow_destroy(struct lws_context *cx, lws_qpt_flow_t *f)
{
	int n;

	for (n = 0; n < f->count_cids; n++)
		lws_qpt_unmap(cx->pt_qflows, &f->cid[n], sizeof(f->cid[n]));
	lws_dll2_remove(&f->list);
	lws_free(f);
}

static int
lws_qpt_flow_add_cid(struct lws_context *cx, lws_qpt_flow_t *f,
		     const struct lws_quic_cid *cid)
{
	struct lws_quic_cid k;
	int n;

	memset(&k, 0, sizeof(k));
	k.len = cid->len;
	memcpy(k.id, cid->id, cid->len);

	for (n = 0; n < f->count_cids; n++)
		if (!memcmp(&f->cid[n], &k, sizeof(k)))
			return 0;

	if (f->count_cids == LWS_QPT_MAX_CIDS ||
	    lws_qpt_lookup(cx->pt_qflows, &k, sizeof(k)))
		/* full, or somebody else's */
		return 1;

	if (!lws_map_item_create(cx->pt_qflows, (const lws_map_key_t)&k,
				 sizeof(k), (const lws_map_value_t)&f,
				 sizeof(f)))
		return 1;

	f->cid[f->count_cids++] = k;

	return 0;
}

static void
lws_qpt_pending_destroy(lws_qpt_pending_t *pd)
{
	lws_sul_cancel(&pd->sul);
	lws_qpt_unmap(pd->cx->pt_qpending, &pd->dcid, sizeof(pd->dcid));
	lws_dll2_remove(&pd->list);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&pd->held)) {
		lws_dll2_remove(d);
		lws_free(lws_container_of(d, lws_qpt_dgram_t, list));
	} lws_end_foreach_dll_safe(d, d1);
	lws_free(pd);
}

static void
lws_qpt_relayed_destroy(struct lws_context *cx, lws_qpt_relayed_t *r)
{
	lws_qpt_unmap(cx->pt_relayed, &r->key, sizeof(r->key));
	lws_dll2_remove(&r->list);
	lws_free(r);
}

static void
lws_qpt_sweep_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context *cx = lws_container_of(sul, struct lws_context,
						  sul_pt_sweep);
	lws_usec_t now = lws_now_usecs();

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->pt_qflow_owner)) {
		lws_qpt_flow_t *f = lws_container_of(d, lws_qpt_flow_t, list);

		if (now - f->last > LWS_QPT_FLOW_IDLE_US)
			lws_qpt_flow_destroy(cx, f);
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->pt_relayed_owner)) {
		lws_qpt_relayed_t *r = lws_container_of(d, lws_qpt_relayed_t,
							list);

		if (now - r->last > LWS_QPT_RELAYED_IDLE_US)
			lws_qpt_relayed_destroy(cx, r);
	} lws_end_foreach_dll_safe(d, d1);

	if (lws_dll2_count(&cx->pt_qflow_owner) ||
	    lws_dll2_count(&cx->pt_relayed_owner))
		lws_sul_schedule(cx, 0, &cx->sul_pt_sweep, lws_qpt_sweep_cb,
				 LWS_QPT_SWEEP_US);
}

static void
lws_qpt_sweep_arm(struct lws_context *cx)
{
	if (!lws_dll2_is_detached(&cx->sul_pt_sweep.list))
		return;

	lws_sul_schedule(cx, 0, &cx->sul_pt_sweep, lws_qpt_sweep_cb,
			 LWS_QPT_SWEEP_US);
}

void
lws_quic_passthrough_context_destroy(struct lws_context *cx)
{
	lws_sul_cancel(&cx->sul_pt_sweep);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->pt_qpending_owner)) {
		lws_qpt_pending_destroy(lws_container_of(d, lws_qpt_pending_t,
							 list));
	} lws_end_foreach_dll_safe(d, d1);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->pt_qflow_owner)) {
		lws_qpt_flow_destroy(cx, lws_container_of(d, lws_qpt_flow_t,
							  list));
	} lws_end_foreach_dll_safe(d, d1);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->pt_relayed_owner)) {
		lws_qpt_relayed_destroy(cx, lws_container_of(d,
						lws_qpt_relayed_t, list));
	} lws_end_foreach_dll_safe(d, d1);

	lws_map_destroy(&cx->pt_qflows);
	lws_map_destroy(&cx->pt_qpending);
	lws_map_destroy(&cx->pt_relayed);
}

/* a vhost is going: nothing may still lead to it */
static void
lws_qpt_vhost_gone(struct lws_vhost *vh)
{
	struct lws_context *cx = vh->context;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->pt_qflow_owner)) {
		lws_qpt_flow_t *f = lws_container_of(d, lws_qpt_flow_t, list);

		if (f->vh == vh)
			lws_qpt_flow_destroy(cx, f);
	} lws_end_foreach_dll_safe(d, d1);
}

/* ---- front */

/*
 * Our udp socket to the server of passed through vh, made when it is first
 * needed
 */
static struct lws *
lws_qpt_server_wsi(struct lws_vhost *vh)
{
	if (vh->passthrough_qwsi)
		return vh->passthrough_qwsi;

	/*
	 * In the server's own family: our udp sockets are v6-only, so a v6
	 * one can't reach a v4 server even as a v4-mapped address
	 */
	vh->passthrough_qwsi = lws_create_adopt_udp(vh,
#if defined(LWS_WITH_IPV6)
				vh->passthrough_sa46.sa4.sin_family ==
						AF_INET6 ? "::" :
#endif
				"0.0.0.0", 0, LWS_CAUDP_BIND,
				lws_quic_passthrough_protocol.name, NULL, NULL,
				vh, NULL, NULL);

	return vh->passthrough_qwsi;
}

/* a client's datagram, after a PROXY v2 header naming it, to the server */
static void
lws_qpt_to_server(lws_qpt_flow_t *f, const uint8_t *buf, size_t len,
		  const lws_sockaddr46 *client)
{
	uint8_t b[LWS_PROXY_V2_MAX + LWS_QPT_MAX_DGRAM];
	struct lws *sw = lws_qpt_server_wsi(f->vh), *lw;
	lws_sockaddr46 dest = f->vh->passthrough_sa46;
	lws_proxy_v2_t pv;
	int n;

	if (!sw || !lws_socket_is_valid(sw->io->desc.sockfd) ||
	    len > LWS_QPT_MAX_DGRAM)
		return;

	memset(&pv, 0, sizeof(pv));
	pv.dgram = 1;
	pv.src = *client;
	lw = lws_qpt_listener(f->vh->context, f->listen_port);
	if (lw)
		pv.dst = lw->io->udp->sa46;
#if defined(LWS_WITH_IPV6)
	/* the header wants both in one family */
	if (pv.src.sa4.sin_family != pv.dst.sa4.sin_family) {
		if (pv.src.sa4.sin_family == AF_INET6) {
			memset(&pv.dst, 0, sizeof(pv.dst));
			pv.dst.sa6.sin6_family = AF_INET6;
		} else {
			memset(&pv.dst, 0, sizeof(pv.dst));
			pv.dst.sa4.sin_family = AF_INET;
		}
	}
#endif
	if (!pv.dst.sa4.sin_family)
		pv.dst.sa4.sin_family = pv.src.sa4.sin_family;

	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	if (n < 0)
		return;
	memcpy(b + n, buf, len);

	lws_io_send_dgram(sw, b, (size_t)n + len, &dest);
}

/* the CRYPTO frames of an Initial, into the pending ClientHello */
static void
lws_qpt_crypto_cb(void *user, uint64_t offset, const uint8_t *buf, size_t len)
{
	lws_qpt_pending_t *pd = (lws_qpt_pending_t *)user;
	size_t n;

	if (offset >= sizeof(pd->crypto))
		return;
	if (len > sizeof(pd->crypto) - offset)
		len = sizeof(pd->crypto) - (size_t)offset;

	memcpy(pd->crypto + offset, buf, len);
	for (n = (size_t)offset; n < (size_t)offset + len; n++)
		pd->have[n >> 3] = (uint8_t)(pd->have[n >> 3] | (1 << (n & 7)));
}

static size_t
lws_qpt_contiguous(const lws_qpt_pending_t *pd)
{
	size_t n = 0;

	while (n < sizeof(pd->crypto) && (pd->have[n >> 3] & (1 << (n & 7))))
		n++;

	return n;
}

static int
lws_qpt_hold(lws_qpt_pending_t *pd, const uint8_t *buf, size_t len,
	     const lws_sockaddr46 *peer, uint8_t ecn)
{
	lws_qpt_dgram_t *dg;

	if (lws_dll2_count(&pd->held) >= LWS_QPT_PENDING_DGRAMS ||
	    len > LWS_QPT_MAX_DGRAM)
		return 1;

	dg = lws_malloc(sizeof(*dg) + len, __func__);
	if (!dg)
		return 1;

	memset(dg, 0, sizeof(*dg));
	dg->peer = *peer;
	dg->len = len;
	dg->ecn = ecn;
	memcpy(&dg[1], buf, len);
	lws_dll2_add_tail(&dg->list, &pd->held);

	return 0;
}

/* the held datagrams go to the quic role after all, as if just received */
static void
lws_qpt_release_local(lws_qpt_pending_t *pd)
{
	struct lws *lw = lws_qpt_listener(pd->cx, pd->listen_port);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&pd->held)) {
		lws_qpt_dgram_t *dg = lws_container_of(d, lws_qpt_dgram_t,
						       list);

		lws_dll2_remove(d);
		if (lw)
			lws_rops_func_fidx(lw->role_ops, LWS_ROPS_rx_dgram).
				rx_dgram(lw, (uint8_t *)&dg[1], dg->len,
					 &dg->peer, dg->ecn);
		lws_free(dg);
	} lws_end_foreach_dll_safe(d, d1);
}

static void
lws_qpt_pending_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lws_qpt_pending_t *pd = lws_container_of(sul, lws_qpt_pending_t, sul);

	/* the rest of it never came: the quic role can make what it can of it */
	lws_qpt_release_local(pd);
	lws_qpt_pending_destroy(pd);
}

/* a passed through vhost on port that quic may be relayed for, by name */
static struct lws_vhost *
lws_qpt_vhost(struct lws_context *cx, int port, const char *name)
{
	struct lws_vhost *vh = lws_select_vhost_by_name(cx, port, name);

	if (!vh || !vh->passthrough_host || !vh->passthrough_proxy_v2 ||
	    !vh->passthrough_sa46.sa4.sin_family)
		return NULL;

	return vh;
}

static int
lws_qpt_port_has_passthrough(struct lws_context *cx, int port)
{
	struct lws_vhost *v;

	for (v = lws_vhost_first(cx); v; v = lws_vhost_next(v))
		if (!v->being_destroyed && v->listen_port == port &&
		    v->passthrough_sa46.sa4.sin_family &&
		    v->passthrough_proxy_v2)
			return 1;

	return 0;
}

/*
 * Decide what the pending Initial is, now that more of its ClientHello may be
 * here.  Returns 1 if the datagram that brought it was taken, 0 if it goes on
 * to the quic role.
 */
static int
lws_qpt_decide(struct lws *listener, lws_qpt_pending_t *pd,
	       const uint8_t *buf, size_t len, const lws_sockaddr46 *peer,
	       uint8_t ecn)
{
	struct lws_context *cx = listener->a.context;
	struct lws_vhost *vh = NULL;
	lws_qpt_flow_t *f;
	char name[256];
	int n;

	n = lws_tls_client_hello_msg_sni(pd->crypto, lws_qpt_contiguous(pd),
					 name, sizeof(name));
	if (n == LWS_TLS_CH_SNI_MORE) {
		if (!lws_qpt_hold(pd, buf, len, peer, ecn)) {
			if (lws_dll2_is_detached(&pd->sul.list))
				lws_sul_schedule(cx, listener->tsi, &pd->sul,
						 lws_qpt_pending_timeout_cb,
						 LWS_QPT_PENDING_US);
			return 1;
		}
		/* more of it than we will hold */
		n = LWS_TLS_CH_SNI_NONE;
	}

	if (n == LWS_TLS_CH_SNI_FOUND)
		vh = lws_qpt_vhost(cx, listener->a.vhost->listen_port, name);

	if (!vh ||
	    lws_dll2_count(&cx->pt_qflow_owner) >= LWS_QPT_MAX_FLOWS) {
		/* not ours: the quic role gets them all, this one last */
		lws_qpt_release_local(pd);
		lws_qpt_pending_destroy(pd);

		return 0;
	}

	f = lws_zalloc(sizeof(*f), __func__);
	if (!f)
		goto local;
	f->vh = vh;
	f->listen_port = listener->a.vhost->listen_port;
	f->client = *peer;
	f->last = lws_now_usecs();
	lws_dll2_add_tail(&f->list, &cx->pt_qflow_owner);
	if (lws_qpt_flow_add_cid(cx, f, &pd->dcid)) {
		lws_qpt_flow_destroy(cx, f);
		goto local;
	}
	lws_qpt_sweep_arm(cx);

	{
		char pa[64];

		lws_sa46_write_numeric_address(&f->client, pa, sizeof(pa));
		lwsl_vhost_notice(vh, "quic from %s for %s passed through to "
				  "%s:%u", pa, name, vh->passthrough_host,
				  vh->passthrough_port);
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&pd->held)) {
		lws_qpt_dgram_t *dg = lws_container_of(d, lws_qpt_dgram_t,
						       list);

		lws_qpt_to_server(f, (const uint8_t *)&dg[1], dg->len,
				  &dg->peer);
	} lws_end_foreach_dll_safe(d, d1);
	lws_qpt_to_server(f, buf, len, peer);
	lws_qpt_pending_destroy(pd);

	return 1;

local:
	lws_qpt_release_local(pd);
	lws_qpt_pending_destroy(pd);

	return 0;
}

int
lws_quic_passthrough_rx(struct lws *listener, uint8_t *buf, size_t len,
			const lws_sockaddr46 *peer, uint8_t ecn)
{
	struct lws_context *cx = listener->a.context;
	struct lws_quic_cid dcid, scid, k;
	lws_qpt_pending_t *pd;
	lws_qpt_flow_t *f;
	int initial;

	if (!cx->count_quic_passthrough || !listener->a.vhost ||
	    lws_quic_dgram_cids(buf, len, &dcid, &scid, &initial))
		return 0;

	memset(&k, 0, sizeof(k));
	k.len = dcid.len;
	memcpy(k.id, dcid.id, dcid.len);

	/*
	 * Only on the port the flow came in on: a process can be a server
	 * behind a relay as well as a front, and the server's listener must
	 * not take its own relayed datagrams for a flow to relay
	 */
	f = (lws_qpt_flow_t *)lws_qpt_lookup(cx->pt_qflows, &k, sizeof(k));
	if (f && f->listen_port != listener->a.vhost->listen_port)
		return 0;
	if (f) {
		if (!lws_qpt_same_addr(&f->client, peer)) {
			char pa[64];

			/*
			 * The client moved, or claims to: the server's quic
			 * sees the new address in the header and validates
			 * the path itself before it trusts it
			 */
			f->prev_client = f->client;
			f->client = *peer;
			lws_sa46_write_numeric_address(&f->client, pa,
						       sizeof(pa));
			lwsl_vhost_info(f->vh, "quic flow seen from %s", pa);
		}
		f->last = lws_now_usecs();
		lws_qpt_to_server(f, buf, len, peer);

		return 1;
	}

	pd = (lws_qpt_pending_t *)lws_qpt_lookup(cx->pt_qpending, &k,
						 sizeof(k));
	if (pd && pd->listen_port != listener->a.vhost->listen_port)
		return 0;
	if (!pd) {
		/*
		 * Not for a connection the quic role already has: eg, the
		 * client's later Initials carry the CID its server chose,
		 * whose keys can't be derived from it
		 */
		if (!initial || lws_quic_find_child_by_dcid(listener, &dcid) ||
		    !lws_qpt_port_has_passthrough(cx,
					listener->a.vhost->listen_port) ||
		    lws_dll2_count(&cx->pt_qpending_owner) >=
							LWS_QPT_MAX_PENDING ||
		    lws_qpt_maps(cx))
			return 0;

		pd = lws_zalloc(sizeof(*pd), __func__);
		if (!pd)
			return 0;
		pd->cx = cx;
		pd->listen_port = listener->a.vhost->listen_port;
		pd->dcid = k;
		if (!lws_map_item_create(cx->pt_qpending,
					 (const lws_map_key_t)&k, sizeof(k),
					 (const lws_map_value_t)&pd,
					 sizeof(pd))) {
			lws_free(pd);
			return 0;
		}
		lws_dll2_add_tail(&pd->list, &cx->pt_qpending_owner);
	}

	if (initial &&
	    lws_quic_initial_crypto_peek(buf, len, lws_qpt_crypto_cb, pd) &&
	    !lws_dll2_count(&pd->held)) {
		/* nothing we can read: it is the quic role's to judge */
		lws_qpt_pending_destroy(pd);

		return 0;
	}

	return lws_qpt_decide(listener, pd, buf, len, peer, ecn);
}

/*
 * A datagram from the server, on our socket for its vhost: it must start with
 * a PROXY v2 header naming the client it is for
 */
static void
lws_qpt_from_server(struct lws *wsi, const uint8_t *buf, size_t len)
{
	struct lws_vhost *vh = wsi->a.vhost;
	struct lws_context *cx = vh->context;
	const lws_sockaddr46 *to = NULL;
	struct lws_quic_cid dcid, scid;
	lws_qpt_flow_t *f = NULL;
	lws_proxy_v2_t pv;
	struct lws *lw;
	int hl, initial;

	if (!lws_get_udp(wsi) ||
	    !lws_qpt_same_addr(&lws_get_udp(wsi)->sa46, &vh->passthrough_sa46))
		/* only the server we relay to speaks for its clients */
		return;

	hl = lws_proxy_v2_header_len(buf, len);
	if (hl <= 0 || (size_t)hl >= len ||
	    lws_proxy_v2_parse(buf, (size_t)hl, &pv) || pv.local ||
	    !pv.dgram)
		return;
	buf += hl;
	len -= (size_t)hl;

	/*
	 * Only to an address one of our flows to this server has seen its
	 * client at: where it is now, or where it was before it moved, since
	 * the server keeps answering there until it has validated the new
	 * path, and a move we were shown may not even be real
	 */
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->pt_qflow_owner)) {
		lws_qpt_flow_t *ff = lws_container_of(d, lws_qpt_flow_t, list);

		if (ff->vh == vh) {
			if (lws_qpt_same_addr(&ff->client, &pv.dst)) {
				f = ff;
				to = &ff->client;
				break;
			}
			if (ff->prev_client.sa4.sin_family &&
			    lws_qpt_same_addr(&ff->prev_client, &pv.dst)) {
				f = ff;
				to = &ff->prev_client;
				break;
			}
		}
	} lws_end_foreach_dll(d);
	if (!f)
		return;

	/* the server's connection IDs, which the client goes on to use */
	if (!lws_quic_dgram_cids(buf, len, &dcid, &scid, &initial) &&
	    scid.len)
		lws_qpt_flow_add_cid(cx, f, &scid);

	/* to that address as we know it */
	lw = lws_qpt_listener(cx, f->listen_port);
	if (lw)
		lws_io_send_dgram(lw, buf, len, to);
}

static int
lws_quic_passthrough_callback(struct lws *wsi, enum lws_callback_reasons reason,
			      void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		lws_qpt_from_server(wsi, (const uint8_t *)in, len);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (wsi->a.vhost && wsi->a.vhost->passthrough_qwsi == wsi)
			wsi->a.vhost->passthrough_qwsi = NULL;
		break;

	default:
		break;
	}

	(void)user;

	return 0;
}

const struct lws_protocols lws_quic_passthrough_protocol = {
	.name		= "lws-quic-passthrough",
	.callback	= lws_quic_passthrough_callback,
};

/* ---- server */

/* does a vhost on listener's listener trust peer to send PROXY v2? */
static int
lws_qpt_trusted(struct lws *listener, const lws_sockaddr46 *peer)
{
	struct lws_vhost *lv = listener->a.vhost, *v;

	for (v = lws_vhost_first(listener->a.context); v; v = lws_vhost_next(v)) {
		if (v->being_destroyed ||
		    (v != lv && !lws_vhost_compare_listen(v, lv)))
			continue;

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&v->proxy_v2_trusted)) {
			lws_proxy_v2_trust_t *t = lws_container_of(d,
						lws_proxy_v2_trust_t, list);

			if (!lws_sa46_on_net(peer, &t->sa46, t->net_len))
				return 1;
		} lws_end_foreach_dll(d);
	}

	return 0;
}

int
lws_relayed_dgram_rx(struct lws *listener, uint8_t **buf, size_t *len,
		     lws_sockaddr46 *peer)
{
	struct lws_context *cx = listener->a.context;
	lws_qpt_relayed_t *r;
	lws_qpt_addr_key_t k;
	lws_proxy_v2_t pv;
	int hl;

	if (!listener->a.vhost || !lws_qpt_trusted(listener, peer))
		return 0;

	hl = lws_proxy_v2_header_len(*buf, *len);
	if (hl <= 0 || (size_t)hl >= *len ||
	    lws_proxy_v2_parse(*buf, (size_t)hl, &pv) || pv.local ||
	    !pv.dgram) {
		lwsl_wsi_info(listener, "datagram from a trusted relay "
			      "without a valid PROXY v2 header dropped");
		return 1;
	}

#if defined(LWS_WITH_IPV6)
	/* in the listener's family, as the socket reports its peers */
	if (listener->io->udp &&
	    listener->io->udp->sa46.sa4.sin_family == AF_INET6 &&
	    pv.src.sa4.sin_family == AF_INET) {
		uint8_t a4[4];
		uint16_t port = ntohs(pv.src.sa4.sin_port);

		memcpy(a4, &pv.src.sa4.sin_addr, 4);
		memset(&pv.src, 0, sizeof(pv.src));
		lws_sa46_4to6(&pv.src, a4, port);
	}
#endif

	if (lws_qpt_maps(cx))
		return 1;

	lws_qpt_key(&pv.src, &k);
	k.lport = (uint16_t)listener->a.vhost->listen_port;
	r = (lws_qpt_relayed_t *)lws_qpt_lookup(cx->pt_relayed, &k, sizeof(k));
	if (!r) {
		if (lws_dll2_count(&cx->pt_relayed_owner) >=
							LWS_QPT_MAX_RELAYED)
			lws_qpt_relayed_destroy(cx, lws_container_of(
				lws_dll2_get_head(&cx->pt_relayed_owner),
				lws_qpt_relayed_t, list));

		r = lws_zalloc(sizeof(*r), __func__);
		if (!r)
			return 1;
		r->key = k;
		if (!lws_map_item_create(cx->pt_relayed,
					 (const lws_map_key_t)&k, sizeof(k),
					 (const lws_map_value_t)&r,
					 sizeof(r))) {
			lws_free(r);
			return 1;
		}
	} else
		lws_dll2_remove(&r->list);

	/* most recently used last, so the head is what goes first */
	lws_dll2_add_tail(&r->list, &cx->pt_relayed_owner);
	r->relay = *peer;
	r->front = pv.dst;
	r->last = lws_now_usecs();
	lws_qpt_sweep_arm(cx);

	*peer = pv.src;
	*buf += hl;
	*len -= (size_t)hl;

	return 0;
}

int
lws_relayed_dgram_tx(struct lws *nwsi, lws_sockfd_type fd, const uint8_t *buf,
		     size_t len, const lws_sockaddr46 *dest, int *sent)
{
	uint8_t b[LWS_PROXY_V2_MAX + LWS_QPT_MAX_DGRAM];
	struct lws_context *cx = nwsi->a.context;
	lws_qpt_relayed_t *r;
	lws_qpt_addr_key_t k;
	lws_proxy_v2_t pv;
	int n;

	if (!cx->pt_relayed || !lws_dll2_count(&cx->pt_relayed_owner))
		return 0;

	if (!nwsi->a.vhost)
		return 0;
	lws_qpt_key(dest, &k);
	k.lport = (uint16_t)nwsi->a.vhost->listen_port;
	r = (lws_qpt_relayed_t *)lws_qpt_lookup(cx->pt_relayed, &k, sizeof(k));
	if (!r)
		return 0;

	*sent = LWS_SSL_CAPABLE_ERROR;
	if (len > LWS_QPT_MAX_DGRAM)
		return 1;

	memset(&pv, 0, sizeof(pv));
	pv.dgram = 1;
	pv.dst = *dest;
	if (r->front.sa4.sin_family == dest->sa4.sin_family)
		pv.src = r->front;
	else
		pv.src.sa4.sin_family = dest->sa4.sin_family;

	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	if (n < 0)
		return 1;
	memcpy(b + n, buf, len);

	/*
	 * Back through the relay, on a listener of the relay's family, which
	 * need not be the client's that the caller chose the socket by
	 */
	if (nwsi->a.vhost) {
		lws_start_foreach_dll(struct lws_dll2 *, d,
				lws_dll2_get_head(&nwsi->a.vhost->listen_wsi)) {
			struct lws *lw = lws_container_of(d, struct lws,
							  listen_list);

			if (lw->io->udp && lw->io->udp->sa46.sa4.sin_family ==
						r->relay.sa4.sin_family &&
			    lws_socket_is_valid(lw->io->desc.sockfd)) {
				fd = lw->io->desc.sockfd;
				break;
			}
		} lws_end_foreach_dll(d);
	}

	n = (int)sendto(fd, (const char *)b, LWS_POSIX_LENGTH_CAST((size_t)n + len),
			0, sa46_sockaddr(&r->relay), sa46_socklen(&r->relay));
	if (n >= 0)
		*sent = (int)len;
	else if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK ||
		 LWS_ERRNO == LWS_EINTR)
		*sent = LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	return 1;
}
#endif
