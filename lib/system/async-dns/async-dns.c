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
#include "private-lib-async-dns.h"

static const uint32_t botable[] = { 500, 1000, 1250, 5000
				/* in case everything just dog slow */ };
static const lws_retry_bo_t retry_policy = {
	botable, LWS_ARRAY_SIZE(botable), LWS_ARRAY_SIZE(botable),
	/* don't conceal after the last table entry */ 0, 0, 20 };

void
lws_adns_q_destroy(lws_adns_q_t *q)
{
	lws_dll2_remove(&q->sul.list);
	lws_dll2_remove(&q->list);
	lws_free(q);
}

lws_adns_q_t *
lws_adns_get_query(lws_async_dns_t *dns, adns_query_type_t qtype,
		   lws_dll2_owner_t *owner, uint16_t tid, const char *name)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(owner)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

		if (!name && (tid & 0xfffe) == (q->tid & 0xfffe))
			return q;

		if (name && q->qtype == ((tid & 1) ? LWS_ADNS_RECORD_AAAA :
						     LWS_ADNS_RECORD_A) &&
		    !strcasecmp(name, (const char *)&q[1])) {
			if (owner == &dns->cached) {
				/* Keep sorted by LRU: move to the head */
				lws_dll2_remove(&q->list);
				lws_dll2_add_head(&q->list, &dns->cached);
			}

			return q;
		}
	} lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

void
lws_async_dns_drop_server(struct lws_context *context)
{
	context->async_dns.dns_server_set = 0;
	lws_set_timeout(context->async_dns.wsi, 1, LWS_TO_KILL_ASYNC);
	context->async_dns.wsi = NULL;
}

int
lws_async_dns_complete(lws_adns_q_t *q, lws_adns_cache_t *c)
{

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&q->wsi_adns)) {
		struct lws *w = lws_container_of(d, struct lws, adns);

		lws_dll2_remove(d);
		if (c && c->results) {
			lwsl_debug("%s: q: %p, c: %p, refcount %d -> %d\n",
				    __func__, q, c, c->refcount, c->refcount + 1);
			c->refcount++;
		}
		w->adns_cb(w, (const char *)&q[1], c ? c->results : NULL, 0,
				q->opaque);
	} lws_end_foreach_dll_safe(d, d1);

	if (q->standalone_cb) {
		if (c && c->results) {
			lwsl_debug("%s: q: %p, c: %p, refcount %d -> %d\n",
				    __func__, q, c, c->refcount, c->refcount + 1);
			c->refcount++;
		}

		q->standalone_cb(NULL, (const char *)&q[1],
				 c ? c->results : NULL, 0, q->opaque);
	}

	return 0;
}

static void
lws_async_dns_sul_cb_retry(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, sul);

	// lwsl_notice("%s\n", __func__);

	lws_callback_on_writable(q->dns->wsi);
}

static void
lws_async_dns_writeable(struct lws *wsi, lws_adns_q_t *q)
{
	uint8_t pkt[LWS_PRE + DNS_PACKET_LEN], *e = &pkt[sizeof(pkt)], *p, *pl;
	int m, n, which;
	const char *name;

	// lwsl_notice("%s: %p\n", __func__, q);

	/*
	 * UDP is not reliable, it can be locally dropped, or dropped
	 * by any intermediary or the remote peer.  So even though we
	 * will do the write in a moment, we schedule another request
	 * for rewrite according to the wsi retry policy.
	 *
	 * If the result came before, we'll cancel it as part of the
	 * wsi close.
	 *
	 * If we have already reached the end of our concealed retries
	 * in the policy, just close without another write.
	 */
	if (lws_dll2_is_detached(&q->sul.list) &&
	    lws_retry_sul_schedule_retry_wsi(wsi, &q->sul,
				       lws_async_dns_sul_cb_retry, &q->retry)) {
		/* we have reached the end of our concealed retries */
		lwsl_notice("%s: failing query\n", __func__);
		/*
		 * our policy is to force reloading the dns server info
		 * if our connection ever timed out, in case it or the
		 * routing state changed
		 */

		lws_async_dns_drop_server(q->context);
		goto qfail;
	}

	name = (const char *)&q[1];

	p = &pkt[LWS_PRE];
	memset(p, 0, DHO_SIZEOF);

#if defined(LWS_WITH_IPV6)
	if (!q->responded) {
		/* must pick between ipv6 and ipv4 */
		which = q->sent[0] >= q->sent[1];
		q->sent[which]++;
		q->asked = 3; /* want results for 4 & 6 before done */
	} else
		which = q->responded & 1;
#else
	which = 0;
	q->asked = 1;
#endif

	/* we hack b0 of the tid to be 0 = A, 1 = AAAA */

	lws_ser_wu16be(&p[DHO_TID],
#if defined(LWS_WITH_IPV6)
			which ? q->tid | 1 :
#endif
			q->tid);
	lws_ser_wu16be(&p[DHO_FLAGS], (1 << 8));
	lws_ser_wu16be(&p[DHO_NQUERIES], 1);

	p += DHO_SIZEOF;

	/* start of label-formatted qname */

	pl = p++;

	do {
		if (*name == '.' || !*name) {
			*pl = lws_ptr_diff(p, pl + 1);
			pl = p;
			*p++ = 0; /* also serves as terminal length */
			if (!*name++)
				break;
		} else
			*p++ = *name++;
	} while (p + 6 < e);

	if (p + 6 >= e) {
		assert(0);
		lwsl_err("%s: name too big\n", __func__);
		goto qfail;
	}

	lws_ser_wu16be(p, which ? LWS_ADNS_RECORD_AAAA :
				     LWS_ADNS_RECORD_A);
	p += 2;

	lws_ser_wu16be(p, 1); /* IN class */
	p += 2;

	assert(p < pkt + sizeof(pkt) - LWS_PRE);
	n = lws_ptr_diff(p, pkt + LWS_PRE);
	m = lws_write(wsi, pkt + LWS_PRE, n, 0);
	if (m != n) {
		lwsl_notice("%s: dns write failed %d %d errno %d\n", __func__,
			    m, n, errno);
		goto qfail;
	}

#if defined(LWS_WITH_IPV6)
	if (!q->responded && q->sent[0] != q->sent[1])
		lws_callback_on_writable(wsi);
#endif

	/* if we did anything, check one more time */
	lws_callback_on_writable(wsi);

	return;

qfail:
	lwsl_warn("%s: failing query doing NULL completion\n", __func__);
	/*
	 * in ipv6 case, we made a cache entry for the first response but
	 * evidently the second response didn't come in time, purge the
	 * incomplete cache entry
	 */
	if (q->firstcache)
		lws_adns_cache_destroy(q->firstcache);
	lws_async_dns_complete(q, NULL);
	lws_adns_q_destroy(q);
}

static int
callback_async_dns(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct lws_async_dns *dns = &(lws_get_context(wsi)->async_dns);

	switch (reason) {

	/* callbacks related to raw socket descriptor */

        case LWS_CALLBACK_RAW_ADOPT:
		// lwsl_user("LWS_CALLBACK_RAW_ADOPT\n");
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		// lwsl_user("LWS_CALLBACK_RAW_CLOSE\n");
		break;

	case LWS_CALLBACK_RAW_RX:
		// lwsl_user("LWS_CALLBACK_RAW_RX (%d)\n", (int)len);
		// lwsl_hexdump_level(LLL_NOTICE, in, len);
		lws_adns_parse_udp(dns, in, len);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		// lwsl_notice("%s: WRITABLE\n", __func__);

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   dns->waiting.head) {
			lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t,
							   list);

			if (lws_dll2_is_detached(&q->sul.list) &&
			    (!q->asked || q->responded != q->asked))
				lws_async_dns_writeable(wsi, q);
		} lws_end_foreach_dll_safe(d, d1);
		break;

	default:
		break;
	}

	return 0;
}

struct lws_protocols lws_async_dns_protocol = {
	"lws-async-dns", callback_async_dns, 0, 0
};

int
lws_async_dns_init(struct lws_context *context)
{
	lws_async_dns_t *dns = &context->async_dns;
	char ads[48];
	int n;

	if (!context->vhost_list) { /* coverity... system vhost always present */
		lwsl_err("%s: no system vhost\n", __func__);
		return 1;
	}

	memset(&dns->sa46, 0, sizeof(dns->sa46));

#if defined(LWS_WITH_SYS_DHCP_CLIENT)
	if (lws_dhcpc_status(context, &dns->sa46))
		goto ok;
#endif

	n = lws_plat_asyncdns_init(context, &dns->sa46);
	if (n < 0) {
		lwsl_warn("%s: no valid dns server, retry\n", __func__);

		return 1;
	}

	if (n != LADNS_CONF_SERVER_CHANGED)
		return 0;

#if defined(LWS_WITH_SYS_DHCP_CLIENT)
ok:
#endif
	dns->sa46.sa4.sin_port = htons(53);
	lws_write_numeric_address((uint8_t *)&dns->sa46.sa4.sin_addr.s_addr, 4,
				  ads, sizeof(ads));

	context->async_dns.wsi = lws_create_adopt_udp(context->vhost_list, ads,
				      53, 0, lws_async_dns_protocol.name, NULL,
				      NULL, NULL, &retry_policy);
	if (!dns->wsi) {
		lwsl_err("%s: foreign socket adoption failed\n", __func__);
		return 1;
	}

	dns->dns_server_set = 1;

	return 0;
}

lws_adns_cache_t *
lws_adns_get_cache(lws_async_dns_t *dns, const char *name)
{
	lws_adns_cache_t *c;
	const char *cn;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->cached)) {
		c = lws_container_of(d, lws_adns_cache_t, list);
		cn = (const char *)&c[1];

		if (name && !c->incomplete && !strcasecmp(name, cn)) {
			/* Keep sorted by LRU: move to the head */
			lws_dll2_remove(&c->list);
			lws_dll2_add_head(&c->list, &dns->cached);

			return c;
		}
	} lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

void
lws_adns_cache_destroy(lws_adns_cache_t *c)
{
	lws_dll2_remove(&c->sul.list);
	lws_dll2_remove(&c->list);
	if (c->chain)
		lws_free(c->chain);
	lws_free(c);
}

static int
cache_clean(struct lws_dll2 *d, void *user)
{
	lws_adns_cache_destroy(lws_container_of(d, lws_adns_cache_t, list));

	return 0;
}

void
sul_cb_expire(struct lws_sorted_usec_list *sul)
{
	lws_adns_cache_t *c = lws_container_of(sul, lws_adns_cache_t, sul);

	lws_adns_cache_destroy(c);
}

void
lws_async_dns_freeaddrinfo(const struct addrinfo **pai)
{
	lws_adns_cache_t *c;

	if (!*pai)
		return;

	/*
	 * First query may have been empty... if second has something, we
	 * fixed up the first result to point to second... but it means
	 * looking backwards from ai, which is c->result, which is the second
	 * packet's results, doesn't get us to the firstcache pointer.
	 *
	 * Adjust c to the firstcache in this case.
	 */

	c = &((lws_adns_cache_t *)(*pai))[-1];
	if (c->firstcache)
		c = c->firstcache;

	lwsl_debug("%s: c %p, %s, refcount %d -> %d\n", __func__, c,
		   (c->results && c->results->ai_canonname) ?
				c->results->ai_canonname : "none",
						c->refcount, c->refcount - 1);

	assert(c->refcount > 0);
	c->refcount--;
	*pai = NULL;
}

void
lws_async_dns_trim_cache(lws_async_dns_t *dns)
{
	lws_adns_cache_t *c1;

	if (dns->cached.count + 1< MAX_CACHE_ENTRIES)
		return;

	c1 = lws_container_of(lws_dll2_get_tail(&dns->cached),
						lws_adns_cache_t, list);
	if (c1->refcount)
		lwsl_notice("%s: wsi %p: refcount %d on purge\n",
				__func__, c1, c1->refcount);
	else
		lws_adns_cache_destroy(c1);
}


static int
clean(struct lws_dll2 *d, void *user)
{
	lws_adns_q_destroy(lws_container_of(d, lws_adns_q_t, list));

	return 0;
}

void
lws_async_dns_deinit(lws_async_dns_t *dns)
{
	lws_dll2_foreach_safe(&dns->waiting, NULL, clean);
	lws_dll2_foreach_safe(&dns->cached, NULL, cache_clean);
}


static int
cancel(struct lws_dll2 *d, void *user)
{
	lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d3, d4,
				   lws_dll2_get_head(&q->wsi_adns)) {
		struct lws *w = lws_container_of(d3, struct lws, adns);

		if (user == w) {
			lws_dll2_remove(d3);
			if (!q->wsi_adns.count)
				lws_adns_q_destroy(q);
			return 1;
		}
	} lws_end_foreach_dll_safe(d3, d4);

	return 0;
}

void
lws_async_dns_cancel(struct lws *wsi)
{
	lws_async_dns_t *dns = &wsi->a.context->async_dns;

	lws_dll2_foreach_safe(&dns->waiting, wsi, cancel);
}


static int
check_tid(struct lws_dll2 *d, void *user)
{
	lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

	return q->tid == (uint16_t)(intptr_t)user;
}

int
lws_async_dns_get_new_tid(struct lws_context *context, lws_adns_q_t *q)
{
	lws_async_dns_t *dns = &context->async_dns;
	int budget = 10;

	/*
	 * Make the TID unpredictable, but must be unique amongst ongoing ones
	 */
	do {
		uint16_t tid;

		if (lws_get_random(context, &tid, 2) != 2)
			return -1;

		if (lws_dll2_foreach_safe(&dns->waiting,
					  (void *)(intptr_t)tid, check_tid))
			continue;

		q->tid = tid;

		return 0;

	} while (budget--);

	lwsl_err("%s: unable to get unique tid\n", __func__);

	return -1;
}

struct temp_q {
	lws_adns_q_t tq;
	char name[48];
};

lws_async_dns_retcode_t
lws_async_dns_query(struct lws_context *context, int tsi, const char *name,
		    adns_query_type_t qtype, lws_async_dns_cb_t cb,
		    struct lws *wsi, void *opaque)
{
	lws_async_dns_t *dns = &context->async_dns;
	size_t nlen = strlen(name);
	lws_sockaddr46 *sa46;
	lws_adns_cache_t *c;
	struct addrinfo *ai;
	struct temp_q tmq;
	lws_adns_q_t *q;
	uint8_t ads[16];
	char *p;
	int m;

#if !defined(LWS_WITH_IPV6)
	if (qtype == LWS_ADNS_RECORD_AAAA) {
		lwsl_err("%s: ipv6 not enabled\n", __func__);
		goto failed;
	}
#endif

	if (nlen >= DNS_MAX - 1)
		goto failed;

	/*
	 * we magically know 'localhost' and 'localhost6' if IPv6, this is a
	 * sort of canned /etc/hosts
	 */

	if (!strcmp(name, "localhost"))
		name = "127.0.0.1";

#if defined(LWS_WITH_IPV6)
	if (!strcmp(name, "localhost6"))
		name = "::1";
#endif

	if (wsi) {
		if (!lws_dll2_is_detached(&wsi->adns)) {
			lwsl_err("%s: wsi %p already bound to query %p\n",
					__func__, wsi, wsi->adns.owner);
			goto failed;
		}
		wsi->adns_cb = cb;
	}

	/* there's a done, cached query we can just reuse? */

	c = lws_adns_get_cache(dns, name);
	if (c) {
		lwsl_err("%s: using cached, c->results %p\n", __func__, c->results);
		m = c->results ? LADNS_RET_FOUND : LADNS_RET_FAILED;
		if (c->results)
			c->refcount++;
		cb(wsi, name, c->results, m, opaque);

		return m;
	}

	/*
	 * It's a 1.2.3.4 type IP address already?  We don't need a dns
	 * server set up to be able to create an addrinfo result for that.
	 *
	 * Create it as a cached object so it follows the refcount lifecycle
	 * of any other result
	 */

	m = lws_parse_numeric_address(name, ads, sizeof(ads));
	if (m == 4
#if defined(LWS_WITH_IPV6)
		|| m == 16
#endif
	) {
		lws_async_dns_trim_cache(dns);

		c = lws_zalloc(sizeof(lws_adns_cache_t) +
			       sizeof(struct addrinfo) +
			       sizeof(lws_sockaddr46) + nlen + 1, "adns-numip");
		if (!c)
			goto failed;

		ai = (struct addrinfo *)&c[1];
		sa46 = (lws_sockaddr46 *)&ai[1];

		ai->ai_socktype = SOCK_STREAM;
		memcpy(&sa46[1], name, nlen + 1);
		ai->ai_canonname = (char *)&sa46[1];

		c->results = ai;
		memset(&tmq.tq, 0, sizeof(tmq.tq));
		tmq.tq.opaque = opaque;
		if (wsi) {
			wsi->adns_cb = cb;
			lws_dll2_add_head(&wsi->adns, &tmq.tq.wsi_adns);
		} else
			tmq.tq.standalone_cb = cb;
		lws_strncpy(tmq.name, name, sizeof(tmq.name));

		lws_dll2_add_head(&c->list, &dns->cached);
		lws_sul_schedule(context, 0, &c->sul, sul_cb_expire,
				 lws_now_usecs() + (3600ll * LWS_US_PER_SEC));
	}

	if (m == 4) {
		ai->ai_family = sa46->sa4.sin_family = AF_INET;
		ai->ai_addrlen = sizeof(sa46->sa4);
		ai->ai_addr = (struct sockaddr *)&sa46->sa4;
		memcpy(&sa46->sa4.sin_addr, ads, m);

		lws_async_dns_complete(&tmq.tq, c);

		return LADNS_RET_FOUND;
	}

#if defined(LWS_WITH_IPV6)
	if (m == 16) {
		ai->ai_family = sa46->sa6.sin6_family = AF_INET6;
		ai->ai_addrlen = sizeof(sa46->sa6);
		ai->ai_addr = (struct sockaddr *)&sa46->sa6;
		memcpy(&sa46->sa6.sin6_addr, ads, m);

		lws_async_dns_complete(&tmq.tq, c);

		return LADNS_RET_FOUND;
	}
#endif

	/*
	 * to try anything else we need a remote server configured...
	 */

	if (!context->async_dns.dns_server_set &&
	    lws_async_dns_init(context)) {
		lwsl_notice("%s: init failed\n", __func__);
		goto failed;
	}

	/* there's an ongoing query we can share the result of */

	q = lws_adns_get_query(dns, qtype, &dns->waiting, 0, name);
	if (q) {
		lwsl_debug("%s: dns piggybacking: %d:%s\n", __func__,
				qtype, name);
		if (wsi)
			lws_dll2_add_head(&wsi->adns, &q->wsi_adns);

		return LADNS_RET_CONTINUING;
	}

	/*
	 * Allocate new query / queries... this is a bit complicated because
	 * multiple queries in one packet are not supported peoperly in DNS
	 * itself, and there's no reliable other way to get both ipv6 and ipv4
	 * (AAAA and A) responses in one hit.
	 *
	 * If we don't support ipv6, it's simple, we just ask for A and that's
	 * it.  But if we do support ipv6, we need to ask twice, once for A
	 * and in a separate query, again for AAAA.
	 *
	 * For ipv6, A / ipv4 is routable over ipv6.  So we always ask for A
	 * first and then if ipv6, AAAA separately.
	 *
	 * Allocate for DNS_MAX, because we may recurse and alter what we're
	 * looking for.
	 *
	 * 0             sizeof(*q)                  sizeof(*q) + DNS_MAX
	 * [lws_adns_q_t][ name (DNS_MAX reserved) ] [ name \0 ]
	 */

	q = (lws_adns_q_t *)lws_malloc(sizeof(*q) + DNS_MAX + nlen + 1,
					__func__);
	if (!q)
		goto failed;
	memset(q, 0, sizeof(*q));

	if (wsi)
		lws_dll2_add_head(&wsi->adns, &q->wsi_adns);

	q->qtype = (uint16_t)qtype;

	if (lws_async_dns_get_new_tid(context, q))
		goto failed;

	q->tid &= 0xfffe;
	q->context = context;
	q->tsi = tsi;
	q->opaque = opaque;
	q->dns = dns;

	if (!wsi)
		q->standalone_cb = cb;

	/* schedule a retry according to the retry policy on the wsi */
	if (lws_retry_sul_schedule_retry_wsi(dns->wsi, &q->sul,
					 lws_async_dns_sul_cb_retry, &q->retry))
		goto failed;

	/*
	 * We may rewrite the copy at +sizeof(*q) for CNAME recursion.  Keep
	 * a second copy at + sizeof(*q) + DNS_MAX so we can create the cache
	 * entry for the original name, not the last CNAME we met.
	 */

	p = (char *)&q[1];
	while (nlen--) {
		*p++ = tolower(*name++);
		p[DNS_MAX - 1] = p[-1];
	}
	*p = '\0';
	p[DNS_MAX] = '\0';

	lws_callback_on_writable(dns->wsi);

	lws_dll2_add_head(&q->list, &dns->waiting);

	lwsl_debug("%s: created new query\n", __func__);

	return LADNS_RET_CONTINUING;

failed:
	cb(wsi, NULL, NULL, LADNS_RET_FAILED, opaque);

	return LADNS_RET_FAILED;
}
