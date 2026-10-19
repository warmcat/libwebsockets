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
 * The peer address stack: who a connection's peer is, layer by layer, each
 * layer tagged with how far it can be believed.  pstack[0] in the io adjunct
 * is the transport's own peer, and a claim about the client (a trusted
 * front's PROXY v2 header) is pushed above it.  Entries change only through
 * the helpers here: a new address starts at the cred its writer gives it,
 * and nothing lowers the cred of an address in place.
 */

#include "private-lib-core.h"

static const char * const cred_names[] = {
	"none", "hearsay", "vouched", "routable", "crypto"
};
static const char cred_initials[] = "nhvrc";

static const char * const kind_names[] = {
	"socket", "local", "proxy-v2", "relay", "xff", "datagram"
};

typedef char lws_peer_cred_names_match[
	LWS_ARRAY_SIZE(cred_names) == LWS_PEER_CRED_CRYPTO + 1 &&
	sizeof(cred_initials) == LWS_PEER_CRED_CRYPTO + 2 ? 1 : -1];
typedef char lws_peer_kind_names_match[
	LWS_ARRAY_SIZE(kind_names) == LWS_PEER_KIND_DATAGRAM + 1 ? 1 : -1];
/* the connection's stack is never deeper than a walk can give */
typedef char lws_peer_stack_fits_walk[
	LWS_PEER_STACK_MAX <= LWS_PEER_WALK_MAX ? 1 : -1];

const char *
lws_peer_cred_name(lws_peer_cred_t cred)
{
	if ((unsigned int)cred >= LWS_ARRAY_SIZE(cred_names))
		return "?";

	return cred_names[cred];
}

const char *
lws_peer_kind_name(lws_peer_kind_t kind)
{
	if ((unsigned int)kind >= LWS_ARRAY_SIZE(kind_names))
		return "?";

	return kind_names[kind];
}

static uint16_t
lws_peer_port(const lws_sockaddr46 *sa46)
{
#if defined(LWS_WITH_IPV6)
	if (sa46->sa4.sin_family == AF_INET6)
		return ntohs(sa46->sa6.sin6_port);
#endif
	if (sa46->sa4.sin_family == AF_INET)
		return ntohs(sa46->sa4.sin_port);

	return 0;
}

/* the same address, and port when want_port */
static int
lws_peer_same(const lws_sockaddr46 *a, const lws_sockaddr46 *b, int want_port)
{
	if (lws_sa46_compare_ads(a, b))
		return 0;

	return !want_port || lws_peer_port(a) == lws_peer_port(b);
}

/*
 * The wsi whose io adjunct holds the stack for a connection or a stream on
 * it: the netconn wsi on QUIC (above it, the mux chain goes on to the shared
 * listener, which is nobody's peer), otherwise the network wsi
 */
struct lws *
lws_io_peer_conn(struct lws *wsi)
{
#if defined(LWS_WITH_UDP) && defined(LWS_ROLE_QUIC)
	while (wsi && !wsi->quic.qn && wsi->mux.parent_wsi)
		wsi = wsi->mux.parent_wsi;

	if (wsi && wsi->quic.qn)
		return wsi;
#endif

	return lws_get_network_wsi(wsi);
}

/*
 * The transport's own peer, pstack[0].  The same address and port keep the
 * better of their cred and the one given; a different one starts at the one
 * given.  Any claim above it stays.
 */
void
lws_io_peer_set(struct lws *wsi, const lws_sockaddr46 *sa46,
		lws_peer_kind_t kind, lws_peer_cred_t cred)
{
	lws_peer_entry_t *e = &wsi->io->pstack[0];

	if (wsi->io->pstack_count && lws_peer_same(&e->sa46, sa46, 1) &&
	    e->kind == (uint8_t)kind && e->cred > (uint8_t)cred)
		cred = (lws_peer_cred_t)e->cred;

	if (&e->sa46 != sa46)
		e->sa46 = *sa46;
	e->kind = (uint8_t)kind;
	e->cred = (uint8_t)cred;

	if (!wsi->io->pstack_count)
		wsi->io->pstack_count = 1;
}

/*
 * A datagram came from src.  A socket with a peer of its own (connected, or
 * made to talk to one address, like the DHCP client's PF_PACKET socket whose
 * sources are not even IP addresses) keeps it: that is still who it talks
 * to.  On one without (bound, or an unconnected descriptor the user
 * adopted), the source is all there is, so it stands as the peer, but as a
 * DATAGRAM entry, which nothing takes for a peer the socket is fixed to.
 */
void
lws_io_peer_datagram(struct lws *wsi, const lws_sockaddr46 *src)
{
	if (wsi->io->pstack_count &&
	    wsi->io->pstack[0].kind == LWS_PEER_KIND_SOCKET)
		return;

	lws_io_peer_set(wsi, src, LWS_PEER_KIND_DATAGRAM,
			LWS_PEER_CRED_HEARSAY);
}

/*
 * The IP address the transport is fixed to talk to, the one its route can
 * be judged by: the socket's own peer, not a datagram's last source, an
 * AF_UNIX peer or a claim above it.  NULL if there is none.
 */
const lws_sockaddr46 *
lws_io_peer_route_dest(struct lws *wsi)
{
	const lws_peer_entry_t *e = &wsi->io->pstack[0];

	if (!wsi->io->pstack_count || e->kind != LWS_PEER_KIND_SOCKET)
		return NULL;

	if (e->sa46.sa4.sin_family == AF_INET
#if defined(LWS_WITH_IPV6)
	    || e->sa46.sa4.sin_family == AF_INET6
#endif
	   )
		return &e->sa46;

	return NULL;
}

/*
 * A claim about the client, on top of what we have.  Returns nonzero if
 * there is no transport entry under it, or no room above it.
 */
int
lws_io_peer_push(struct lws *wsi, const lws_sockaddr46 *sa46,
		 lws_peer_kind_t kind, lws_peer_cred_t cred)
{
	lws_peer_entry_t *e;

	if (!wsi->io->pstack_count ||
	    wsi->io->pstack_count >= LWS_PEER_STACK_MAX)
		return 1;

	e = &wsi->io->pstack[wsi->io->pstack_count++];
	e->sa46 = *sa46;
	e->kind = (uint8_t)kind;
	e->cred = (uint8_t)cred;

	return 0;
}

int
lws_peer_walk(struct lws *wsi, lws_peer_entry_t *dest, int max)
{
	struct lws *cw = lws_io_peer_conn(wsi);
	int n, count = 0;

	if (!cw || max <= 0)
		return 0;

	/* top first */
	for (n = (int)cw->io->pstack_count - 1; n >= 0 && count < max; n--)
		dest[count++] = cw->io->pstack[n];

	return count;
}

static int
lws_peer_effective_idx(const lws_peer_entry_t *e, int count)
{
	int n;

	for (n = 0; n < count; n++)
		if (e[n].cred >= LWS_PEER_CRED_VOUCHED)
			return n;

	return 0;
}

int
lws_peer_effective(struct lws *wsi, lws_peer_entry_t *dest)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];
	int count = lws_peer_walk(wsi, e, LWS_ARRAY_SIZE(e));

	if (!count)
		return 1;

	*dest = e[lws_peer_effective_idx(e, count)];

	return 0;
}

int
lws_peer_raise(struct lws *wsi, const lws_sockaddr46 *seen,
	       lws_peer_cred_t cred)
{
	struct lws *cw = lws_io_peer_conn(wsi);
	int n, want_port, matched = 0;
	lws_peer_entry_t *e;

	if (!cw || !seen || cred == LWS_PEER_CRED_NONE ||
	    (unsigned int)cred > LWS_PEER_CRED_CRYPTO)
		return 1;

	want_port = !!lws_peer_port(seen);

	for (n = 0; n < (int)cw->io->pstack_count; n++) {
		e = &cw->io->pstack[n];
		if (!lws_peer_same(&e->sa46, seen, want_port))
			continue;
		matched = 1;
		if (e->cred < (uint8_t)cred)
			e->cred = (uint8_t)cred;
	}

	return !matched;
}

/*
 * Appending to a bounded text buffer, remembering whether anything was cut
 * off.  There is always room kept for the NUL.
 */
typedef struct lws_peer_desc {
	char		*p;
	char		*end;
	char		cut;
} lws_peer_desc_t;

static void
lws_peer_desc_add(lws_peer_desc_t *d, const char *s)
{
	size_t l = strlen(s), room = lws_ptr_diff_size_t(d->end, d->p);

	if (d->cut)
		return;

	if (l > room) {
		l = room;
		d->cut = 1;
	}

	memcpy(d->p, s, l);
	d->p += l;
	*d->p = '\0';
}

static void
lws_peer_desc_address(lws_peer_desc_t *d, const lws_peer_entry_t *e,
		      int with_port)
{
	lws_sockaddr46 sa46 = e->sa46;
	uint16_t port = lws_peer_port(&sa46);
	char ads[48], t[64];

	if (e->kind == LWS_PEER_KIND_LOCAL) {
		lws_peer_desc_add(d, "unix");
		return;
	}

	if (lws_sa46_write_numeric_address(&sa46, ads, sizeof(ads)) < 0) {
		lws_peer_desc_add(d, "unknown");
		return;
	}

	if (!with_port || !port) {
		lws_peer_desc_add(d, ads);
		return;
	}

#if defined(LWS_WITH_IPV6)
	if (sa46.sa4.sin_family == AF_INET6)
		lws_snprintf(t, sizeof(t), "[%s]:%u", ads, (unsigned int)port);
	else
#endif
		lws_snprintf(t, sizeof(t), "%s:%u", ads, (unsigned int)port);

	lws_peer_desc_add(d, t);
}

const char *
lws_peer_entries_describe(const lws_peer_entry_t *e, int count, char *buf,
			  size_t len, int flags)
{
	int token = !!(flags & LWS_PEER_DESC_TOKEN);
	lws_peer_desc_t d;
	char t[32];
	int n;

	if (!len)
		return buf;

	d.p	= buf;
	d.end	= buf + len - 1;
	d.cut	= 0;
	*buf	= '\0';

	if (count <= 0) {
		lws_peer_desc_add(&d, "unknown");
		goto done;
	}

	/* the common access log case looks as it always has */
	if (token && count == 1 && e[0].kind == LWS_PEER_KIND_SOCKET &&
	    e[0].cred == LWS_PEER_CRED_ROUTABLE) {
		lws_peer_desc_address(&d, &e[0], 0);
		goto done;
	}

	for (n = 0; n < count; n++) {
		if (n)
			lws_peer_desc_add(&d, token ? "<" : " < ");

		lws_peer_desc_address(&d, &e[n], 1);

		if (token) {
			t[0] = '~';
			t[1] = e[n].cred < sizeof(cred_initials) - 1 ?
					cred_initials[e[n].cred] : '?';
			t[2] = '\0';
		} else
			lws_snprintf(t, sizeof(t), " %s/%s",
				     lws_peer_kind_name(
					     (lws_peer_kind_t)e[n].kind),
				     lws_peer_cred_name(
					     (lws_peer_cred_t)e[n].cred));
		lws_peer_desc_add(&d, t);
	}

done:
	if (d.cut) {
		/* say it was cut short, where there is room to */
		if (len >= 4)
			memcpy(buf + len - 4, "...", 4);
	}

	return buf;
}

const char *
lws_peer_describe(struct lws *wsi, char *buf, size_t len, int flags)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];

	return lws_peer_entries_describe(e,
				lws_peer_walk(wsi, e, LWS_ARRAY_SIZE(e)),
				buf, len, flags);
}
