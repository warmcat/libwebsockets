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
 */

#include "private-lib-core.h"

/* how long to wait before peeking again at a partial header or ClientHello */
#define LWS_PRE_ACCEPT_REPEEK_US	(10 * LWS_US_PER_MS)

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

void
lws_passthrough_vhost_destroy(struct lws_vhost *vh)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vh->proxy_v2_trusted)) {
		lws_dll2_remove(d);
		lws_free(lws_container_of(d, lws_proxy_v2_trust_t, list));
	} lws_end_foreach_dll_safe(d, d1);

	lws_free_set_NULL(vh->passthrough_host);
}

/* -------------------------------------------------------------- pre-accept */

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
	int have_peer, trusted = 0, sni = 0;

	memset(&peer, 0, sizeof(peer));
	have_peer = !getpeername(wsi->io->desc.sockfd,
				 (struct sockaddr *)&peer, &sl);

	for (v = lws_vhost_first(wsi->a.context); v; v = lws_vhost_next(v)) {
		if (v->being_destroyed ||
		    (v != lv && !lws_vhost_compare_listen(v, lv)))
			continue;

		if (v->passthrough_host)
			sni = 1;

		if (!have_peer || trusted)
			continue;

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&v->proxy_v2_trusted)) {
			lws_proxy_v2_trust_t *t = lws_container_of(d,
						lws_proxy_v2_trust_t, list);

			if (!lws_sa46_on_net(&peer, &t->sa46, t->net_len)) {
				trusted = 1;
				break;
			}
		} lws_end_foreach_dll(d);
	}

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
	if (lws_change_pollfd(wsi, LWS_POLLIN, 0))
		return 1;

	lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->io->sul_pre_accept,
			 lws_pre_accept_repeek_cb, LWS_PRE_ACCEPT_REPEEK_US);

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
		wsi->io->sa46_proxied = pv.src;
		wsi->io->proxied = 1;
	}

	client[0] = '\0';
	if (!pv.local)
		lws_sa46_write_numeric_address(&pv.src, client, sizeof(client));
	lwsl_wsi_info(wsi, "proxy %s forwards %s", peer,
		      pv.local ? "its own connection" : client);

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
	}

	if (wsi->io->pa_sni) {
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

	/* the role reads what he sent */
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
		if (wsi->io->proxied)
			pv.src = wsi->io->sa46_proxied;
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
