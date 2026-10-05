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
 * Direct queries: one question to one particular server, eg, to see if an
 * authoritative server is serving a record yet.  They share nothing with
 * the resolver's queries but the response parser: no cache, no nameserver
 * list, no CNAME chasing, no DNSSEC.  Each has its own UDP socket aimed at
 * its server, on the async dns protocol, which hands us the wsi when its
 * opaque is one of ours.
 */

#include "private-lib-core.h"
#include "private-lib-async-dns.h"

/* how long we wait for an answer before asking again, then giving up */
static const uint32_t direct_bo[] = { 1000, 2000, 3000, 4000 };

struct lws_adns_direct {
	lws_dll2_t			list;	/* dns->direct */
	lws_sorted_usec_list_t		sul;	/* resend / time out */
	struct lws_context		*cx;
	struct lws			*wsi;
	lws_async_dns_direct_cb_t	cb;
	void				*opaque;
	lws_sockaddr46			server;

	lws_adns_direct_rr_t		rrs[LWS_ADNS_DIRECT_MAX_RRS];
	int				count;

	uint16_t			tid;
	uint16_t			qtype;
	uint16_t			pkt_len;
	uint8_t				tries;

	char				name[DNS_MAX];
	uint8_t				pkt[LWS_PRE + DNS_PACKET_LEN];
};

static uint16_t
direct_port(const lws_sockaddr46 *sa46)
{
#if defined(LWS_WITH_IPV6)
	if (sa46->sa4.sin_family == AF_INET6)
		return sa46->sa6.sin6_port;
#endif

	return sa46->sa4.sin_port;
}

static int
direct_is_ours(lws_async_dns_t *dns, const void *opaque)
{
	if (!opaque)
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->direct)) {
		if (opaque == lws_container_of(d, struct lws_adns_direct, list))
			return 1;
	} lws_end_foreach_dll(d);

	return 0;
}

/* unhook from everything, without calling back */

static void
direct_destroy(struct lws_adns_direct *ad)
{
	lws_sul_cancel(&ad->sul);
	lws_dll2_remove(&ad->list);

	if (ad->wsi) {
		/* it goes away by itself: it must not find us any more */
		lws_set_opaque_user_data(ad->wsi, NULL);
		lws_set_timeout(ad->wsi, 1, LWS_TO_KILL_ASYNC);
		ad->wsi = NULL;
	}

	lws_free(ad);
}

static void
direct_complete(struct lws_adns_direct *ad, lws_async_dns_retcode_t ret,
		uint8_t rcode, uint8_t aa)
{
	lws_adns_direct_result_t r;

	memset(&r, 0, sizeof(r));
	r.ret		= ret;
	r.rcode		= rcode;
	r.authoritative	= aa;
	r.rrs		= ad->rrs;
	r.count		= ret == LADNS_RET_FOUND ? ad->count : 0;

	/*
	 * Off the list first: the callback may start or cancel other direct
	 * queries.  The rdata points into the datagram being handled, which
	 * outlives the callback.
	 */
	lws_dll2_remove(&ad->list);
	ad->cb(ad->opaque, &r);
	direct_destroy(ad);
}

static void
direct_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_adns_direct *ad = lws_container_of(sul,
					struct lws_adns_direct, sul);

	if (ad->tries == LWS_ARRAY_SIZE(direct_bo)) {
		lwsl_cx_info(ad->cx, "%s: no answer about %s", __func__,
			     ad->name);
		direct_complete(ad, LADNS_RET_TIMEDOUT, 0, 0);
		return;
	}

	lws_sul_schedule(ad->cx, 0, &ad->sul, direct_sul_cb,
			 (lws_usec_t)direct_bo[ad->tries++] * LWS_US_PER_MS);

	if (ad->wsi)
		lws_callback_on_writable(ad->wsi);
}

/* collects the answer RRs of the type we asked for */

static int
direct_rr_cb(const char *name, void *opaque, uint32_t ttl,
	     adns_query_type_t type, uint16_t rrpaylen, const uint8_t *payload)
{
	struct lws_adns_direct *ad = (struct lws_adns_direct *)opaque;

	if ((uint16_t)type != ad->qtype ||
	    ad->count == (int)LWS_ARRAY_SIZE(ad->rrs))
		return 0;

	ad->rrs[ad->count].rdata	= payload;
	ad->rrs[ad->count].ttl		= ttl;
	ad->rrs[ad->count].type		= (uint16_t)type;
	ad->rrs[ad->count].len		= rrpaylen;
	ad->count++;

	return 0;
}

static void
direct_rx(struct lws_adns_direct *ad, const uint8_t *pkt, size_t len)
{
	uint16_t flags;
	uint8_t rcode;
	int n;

	/*
	 * Anyone can send us a datagram: only one that is an answer to this
	 * question, from this server, with our tid, ends the query.  The rest
	 * are ignored, so they can't cut it short.
	 */

	if (len < DHO_SIZEOF || len > LWS_ADNS_MAX_PAYLOAD ||
	    lws_ser_ru16be(pkt + DHO_TID) != ad->tid ||
	    lws_ser_ru16be(pkt + DHO_NQUERIES) != 1)
		return;

	flags = lws_ser_ru16be(pkt + DHO_FLAGS);
	if (!(flags & 0x8000) ||	/* not a response */
	    (flags & 0x7800) ||		/* not a standard query */
	    (flags & 0x0200))		/* truncated */
		return;

	rcode = (uint8_t)(flags & 0xf);
	ad->count = 0;

	/* this also checks the question is the one we asked */
	n = lws_adns_iterate_type(ad->qtype, 0, pkt, (int)len, ad->name,
				  direct_rr_cb, ad, NULL);
	if (n < 0) {
		lwsl_cx_notice(ad->cx, "%s: ignoring malformed answer about %s",
			       __func__, ad->name);
		ad->count = 0;
		return;
	}

	direct_complete(ad, !rcode ? LADNS_RET_FOUND :
			    (rcode == 3 ? LADNS_RET_NXDOMAIN : LADNS_RET_FAILED),
			rcode, !!(flags & 0x0400));
}

/*
 * The async dns protocol hands us its callbacks for a wsi whose opaque is
 * one of ours.  Returns 1 if it was, having dealt with it.
 */

int
lws_adns_direct_callback(struct lws *wsi, enum lws_callback_reasons reason,
			 void *in, size_t len)
{
	lws_async_dns_t *dns = &lws_get_context(wsi)->async_dns;
	struct lws_adns_direct *ad;
	lws_sockaddr46 src;

	ad = (struct lws_adns_direct *)lws_get_opaque_user_data(wsi);
	if (!direct_is_ours(dns, ad))
		return 0;

	switch (reason) {
	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!wsi->io->udp)
			break;
		wsi->io->udp->sa46 = ad->server;
		if (lws_write(wsi, ad->pkt + LWS_PRE, ad->pkt_len, 0) !=
							(int)ad->pkt_len)
			lwsl_cx_info(ad->cx, "%s: send failed, retrying",
				     __func__);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!wsi->io->udp || !in)
			break;
		/*
		 * recvfrom() left the datagram's source here, which is also
		 * where we send to: restore our server first
		 */
		src = wsi->io->udp->sa46;
		wsi->io->udp->sa46 = ad->server;
		if (direct_port(&src) != direct_port(&ad->server) ||
		    lws_sa46_compare_ads(&src, &ad->server))
			break;
		direct_rx(ad, (const uint8_t *)in, len);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		/* our socket went away under us: the query can't go on */
		ad->wsi = NULL;
		direct_complete(ad, LADNS_RET_FAILED, 0, 0);
		break;

	default:
		break;
	}

	return 1;
}

/* the question, without recursion desired, for name / qtype */

static int
direct_compose(struct lws_adns_direct *ad)
{
	uint8_t *p = ad->pkt + LWS_PRE, *e = p + DNS_PACKET_LEN, *pl;
	const char *n = ad->name;
	size_t total = 1;

	memset(p, 0, DHO_SIZEOF);
	lws_ser_wu16be(p + DHO_TID, ad->tid);
	lws_ser_wu16be(p + DHO_NQUERIES, 1);
	p += DHO_SIZEOF;

	while (*n) {
		const char *dot = strchr(n, '.');
		size_t l = dot ? (size_t)(dot - n) : strlen(n);

		if (!l) {
			/* only a trailing '.' may be empty */
			if (dot && !dot[1])
				break;
			return 1;
		}
		total += l + 1;
		if (l > 63 || total > 255 || p + 1 + l + 4 > e)
			return 1;

		pl = p++;
		*pl = (uint8_t)l;
		memcpy(p, n, l);
		p += l;
		n += l;
		if (*n)
			n++;
	}

	*p++ = 0;
	lws_ser_wu16be(p, ad->qtype);
	p += 2;
	lws_ser_wu16be(p, 1); /* IN class */
	p += 2;

	ad->pkt_len = (uint16_t)lws_ptr_diff(p, ad->pkt + LWS_PRE);

	return 0;
}

struct lws_adns_direct *
lws_async_dns_query_direct(struct lws_context *cx,
			   const lws_sockaddr46 *server, const char *name,
			   adns_query_type_t qtype,
			   lws_async_dns_direct_cb_t cb, void *opaque)
{
	struct lws_adns_direct *ad;
	char ads[48];

	if (!cx || !server || !name || !cb || strlen(name) >= DNS_MAX ||
	    (server->sa4.sin_family != AF_INET
#if defined(LWS_WITH_IPV6)
	     && server->sa4.sin_family != AF_INET6
#endif
	    ) || (uint32_t)qtype > 0xffff || !lws_vhost_first(cx))
		return NULL;

	ad = lws_zalloc(sizeof(*ad), __func__);
	if (!ad)
		return NULL;

	ad->cx		= cx;
	ad->cb		= cb;
	ad->opaque	= opaque;
	ad->server	= *server;
	ad->qtype	= (uint16_t)qtype;
	if (!direct_port(&ad->server))
		sa46_sockport(&ad->server, htons(53));
	lws_strncpy(ad->name, name, sizeof(ad->name));

	if (lws_get_random(cx, &ad->tid, sizeof(ad->tid)) != sizeof(ad->tid) ||
	    direct_compose(ad)) {
		lwsl_cx_warn(cx, "%s: can't ask about '%s'", __func__, name);
		lws_free(ad);

		return NULL;
	}

	/* before the wsi exists, so its first callbacks find us */
	lws_dll2_add_tail(&ad->list, &cx->async_dns.direct);

	lws_sa46_write_numeric_address(&ad->server, ads, sizeof(ads));
	ad->wsi = lws_create_adopt_udp(lws_vhost_first(cx), ads,
				       ntohs(direct_port(&ad->server)), 0,
				       "lws-async-dns", NULL, NULL, ad, NULL,
				       "adns-direct");
	if (!ad->wsi || !ad->wsi->io->udp) {
		lwsl_cx_warn(cx, "%s: no socket to %s", __func__, ads);
		if (ad->wsi)
			/* adoption didn't complete: it is closing by itself */
			lws_set_opaque_user_data(ad->wsi, NULL);
		ad->wsi = NULL;
		lws_dll2_remove(&ad->list);
		lws_free(ad);

		return NULL;
	}
	ad->wsi->io->udp->sa46 = ad->server;

	direct_sul_cb(&ad->sul);

	return ad;
}

void
lws_async_dns_query_direct_cancel(struct lws_adns_direct **pd)
{
	if (!pd || !*pd)
		return;

	direct_destroy(*pd);
	*pd = NULL;
}

/* the context is going away: drop them all without calling back */

void
lws_adns_direct_deinit(lws_async_dns_t *dns)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->direct)) {
		direct_destroy(lws_container_of(d, struct lws_adns_direct,
						list));
	} lws_end_foreach_dll_safe(d, d1);
}
