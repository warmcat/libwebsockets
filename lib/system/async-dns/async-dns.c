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

static const uint32_t botable[] = { 300, 500, 700, 1250, 5000
				/* in case everything just dog slow */ };
static const lws_retry_bo_t retry_policy = {
	botable, LWS_ARRAY_SIZE(botable),
	/*
	 * conceal_count: don't conceal after the last table entry, ie, the
	 * query fails once we have been through the backoff table.
	 * LWS_RETRY_CONCEAL_ALWAYS here (which is what this used to say) makes
	 * lws_retry_get_delay_ms() conceal forever, since the try counter
	 * saturates at the same 0xffff it compares against... a query that is
	 * never answered then retransmits every 5s for the life of the
	 * process, and a standalone (wsi-less) one is never failed at all.
	 */
	LWS_ARRAY_SIZE(botable), 0, 0, 20 };

extern struct lws_protocols lws_async_dns_protocol;

/* the port we ask the nameservers on: 53, unless a test says otherwise */

static uint16_t
lws_adns_ns_port(void)
{
	const char *env_port = getenv("LWS_ASYNCDNS_PORT");

	if (env_port)
		return (uint16_t)atoi(env_port);

	return 53;
}

/*
 * How many sockets we open before queries share them (see lws_adns_sock_t):
 * a small fds table, as a client's is, holds the LWS_FD_LIMIT_INTERNAL_ADNS
 * it reserves for us, a bigger one more, up to LWS_ADNS_SOCKS_MAX
 */

static unsigned int
lws_adns_socks_max(struct lws_context *cx)
{
	unsigned int n = cx->fd_limit_per_thread / 16;

	if (n < LWS_FD_LIMIT_INTERNAL_ADNS)
		n = LWS_FD_LIMIT_INTERNAL_ADNS;
	if (n > LWS_ADNS_SOCKS_MAX)
		n = LWS_ADNS_SOCKS_MAX;

	return n;
}

static lws_adns_sock_t *
lws_adns_sock_from_opaque(lws_async_dns_t *dns, const void *opaque)
{
	if (!opaque)
		return NULL;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->socks)) {
		if (opaque == lws_container_of(d, lws_adns_sock_t, list))
			return lws_container_of(d, lws_adns_sock_t, list);
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * The socket can't be used any more: new queries don't find it, nothing more
 * is sent on it, and anything still arriving on it is ignored.  The queries
 * still holding it take another at their next retry.
 */

static void
lws_adns_sock_retire(lws_adns_sock_t *s)
{
	lws_dll2_remove(&s->list);
	s->dsrv = NULL;

	if (s->wsi) {
		lws_set_opaque_user_data(s->wsi, NULL);
		lws_set_timeout(s->wsi, 1, LWS_TO_KILL_ASYNC);
		s->wsi = NULL;
	}
}

/* its wsi is closing by itself, eg, the route to the nameserver went away */

static void
lws_adns_sock_lost_wsi(lws_adns_sock_t *s)
{
	lws_set_opaque_user_data(s->wsi, NULL);
	s->wsi = NULL;
	lws_adns_sock_retire(s);

	if (!s->users)
		lws_free(s);
}

static void
lws_adns_sock_unuse(lws_adns_sock_t *s)
{
	assert(s->users);
	if (s->users && --s->users)
		return;

	lws_adns_sock_retire(s);
	lws_free(s);
}

void
lws_async_dns_wsi_closing(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;
	lws_adns_sock_t *s;

	lws_context_lock(cx, __func__); /* ------------------------ cx { */

	s = lws_adns_sock_from_opaque(&cx->async_dns, wsi->a.opaque_user_data);
	if (s) {
		if (s->adopting)
			/* lws_adns_sock_create() deals with it */
			s->closed_adopting = 1;
		else
			if (s->wsi == wsi)
				lws_adns_sock_lost_wsi(s);
	}

	lws_context_unlock(cx); /* } cx */
}

/* a new socket to dsrv, on a port of our own random choosing */

static lws_adns_sock_t *
lws_adns_sock_create(struct lws_context *cx, lws_async_dns_server_t *dsrv)
{
	uint16_t port = lws_adns_ns_port();
	lws_adns_sock_t *s;
	struct lws *wsi;
	char ads[48];

	if (!lws_vhost_first(cx)) { /* coverity... system vhost always present */
		lwsl_cx_err(cx, "no system vhost");
		return NULL;
	}

	s = lws_zalloc(sizeof(*s), __func__);
	if (!s)
		return NULL;

	s->dsrv = dsrv;
	sa46_sockport(&dsrv->sa46, htons(port));
	lws_sa46_write_numeric_address(&dsrv->sa46, ads, sizeof(ads));

	/*
	 * Listed before the wsi exists, so its first callbacks find us.  The
	 * numeric address means the adoption completes, or fails, inside the
	 * call: until it returns, callbacks only note a close.
	 */
	lws_dll2_add_tail(&s->list, &cx->async_dns.socks);
	s->adopting = 1;

	wsi = lws_create_adopt_udp(lws_vhost_first(cx), ads, port,
				   LWS_CAUDP_RANDOM_PORT,
				   lws_async_dns_protocol.name, NULL, NULL, s,
				   &retry_policy, "asyncdns");
	s->adopting = 0;

	/*
	 * lws_create_adopt_udp() only allocates wsi->io->udp once the raw-skt
	 * adoption actually completes.  If it did not (eg, the nameserver
	 * address produced no usable route), the wsi is closing by itself.
	 */
	if (s->closed_adopting || !wsi || !wsi->io->udp) {
		lwsl_cx_notice(cx, "no socket to nameserver %s", ads);
		if (wsi && !s->closed_adopting)
			lws_set_opaque_user_data(wsi, NULL);
		lws_dll2_remove(&s->list);
		lws_free(s);

		return NULL;
	}

	s->wsi = wsi;
	wsi->io->udp->sa46 = dsrv->sa46;

	return s;
}

/*
 * A socket to ask dsrv from: a new one if we may open another, else the
 * least used one to dsrv that may still take queries, else, rather than fail
 * the query, the least used one to dsrv at all.  The use cap only rotates the
 * ports while we can: it's no reason to refuse a lookup, which would let
 * whoever can make us do lookups, eg, by spoofing sources for the DNSBL
 * checks, fail everybody else's.  Only when there is no socket to dsrv and
 * none can be opened, eg, we are out of fds, is there nothing to ask from.
 */

static lws_adns_sock_t *
lws_adns_sock_get(struct lws_context *cx, lws_async_dns_server_t *dsrv)
{
	lws_async_dns_t *dns = &cx->async_dns;
	lws_adns_sock_t *s, *fresh = NULL, *least = NULL;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->socks)) {
		s = lws_container_of(d, lws_adns_sock_t, list);

		if (s->dsrv == dsrv && !s->adopting) {
			if (!least || s->users < least->users)
				least = s;
			if (s->uses < LWS_ADNS_SOCK_MAX_USES &&
			    (!fresh || s->users < fresh->users))
				fresh = s;
		}
	} lws_end_foreach_dll(d);

	if (!least || lws_dll2_count(&dns->socks) < lws_adns_socks_max(cx)) {
		s = lws_adns_sock_create(cx, dsrv);
		if (s)
			return s;
		/* eg, we are out of fds: one we already have will do */
	}

	return fresh ? fresh : least;
}

static int
lws_adns_q_sock_add(lws_adns_q_t *q, lws_async_dns_server_t *dsrv)
{
	lws_adns_sock_t *s = lws_adns_sock_get(q->context, dsrv);
	lws_adns_qsock_t *qs;

	if (!s)
		return 1;

	s->users++;
	s->uses++;

	qs = lws_zalloc(sizeof(*qs), __func__);
	if (!qs) {
		lws_adns_sock_unuse(s);
		return 1;
	}

	qs->sock = s;
	lws_dll2_add_tail(&qs->list, &q->socks);

	return 0;
}

static void
lws_adns_q_socks_release(lws_adns_q_t *q)
{
	struct lws_dll2 *d;

	while ((d = lws_dll2_get_head(&q->socks))) {
		lws_adns_qsock_t *qs = lws_container_of(d, lws_adns_qsock_t,
							list);

		lws_dll2_remove(d);
		lws_adns_sock_unuse(qs->sock);
		lws_free(qs);
	}
}

int
lws_adns_q_socks_bind(lws_adns_q_t *q)
{
	lws_adns_q_socks_release(q);

	/* the first is to q->dsrv: the one we are writeable on */

	if (!q->dsrv || lws_adns_q_sock_add(q, q->dsrv))
		return 1;

	if (q->broadsiding)
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				lws_dll2_get_head(&q->dns->nameservers)) {
			lws_async_dns_server_t *dsrv = lws_container_of(d,
						lws_async_dns_server_t, list);

			/* we just won't race the ones we can't ask */
			if (dsrv != q->dsrv)
				lws_adns_q_sock_add(q, dsrv);
		} lws_end_foreach_dll_safe(d, d1);

	return 0;
}

static lws_adns_sock_t *
lws_adns_q_sock(lws_adns_q_t *q)
{
	struct lws_dll2 *d = lws_dll2_get_head(&q->socks);

	return d ? lws_container_of(d, lws_adns_qsock_t, list)->sock : NULL;
}

struct lws *
lws_adns_q_wsi(lws_adns_q_t *q)
{
	lws_adns_sock_t *s = lws_adns_q_sock(q);

	return s ? s->wsi : NULL;
}

int
lws_adns_q_uses_wsi(lws_adns_q_t *q, const struct lws *wsi)
{
	if (wsi == q->wsi_tcp)
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&q->socks)) {
		if (lws_container_of(d, lws_adns_qsock_t, list)->sock->wsi ==
									wsi)
			return 1;
	} lws_end_foreach_dll(d);

	return 0;
}

/* q's suls are on its own pt, which may not be the one we are serving */

void
lws_adns_q_sul_cancel(lws_adns_q_t *q, lws_sorted_usec_list_t *sul)
{
	lws_sul_cancel_tsi(q->context, q->tsi, sul);
}

/*
 * Schedule a sul on pt tsi.  If that is another thread's, it only sees the
 * new deadline when it next wakes, so wake it now.
 */

void
lws_adns_sul_schedule(struct lws_context *cx, int tsi,
		      lws_sorted_usec_list_t *sul, sul_cb_t cb, lws_usec_t us)
{
	lws_sul_schedule(cx, tsi, sul, cb, us);
#if LWS_MAX_SMP > 1
	if (lws_pthread_self_to_tsi(cx) != tsi && cx->pt[tsi].pipe_wsi)
		lws_plat_pipe_signal(cx, tsi);
#endif
}

/* q's suls are on its own pt */

static void
lws_adns_q_sul_schedule(lws_adns_q_t *q, lws_sorted_usec_list_t *sul,
			sul_cb_t cb, lws_usec_t us)
{
	lws_adns_sul_schedule(q->context, q->tsi, sul, cb, us);
}

static void
lws_async_dns_sul_cb_retry(struct lws_sorted_usec_list *sul);

/* the next resend of q's questions, as wsi's retry policy says */

static int
lws_adns_q_retry_schedule(lws_adns_q_t *q, struct lws *wsi)
{
	char conceal;
	lws_usec_t us = (lws_usec_t)lws_retry_get_delay_ms(q->context,
					wsi->retry_policy, &q->retry,
					&conceal) * LWS_US_PER_MS;

	if (!conceal)
		/* the retries are used up */
		return 1;

	lws_adns_q_sul_schedule(q, &q->sul, lws_async_dns_sul_cb_retry, us);

	return 0;
}

void
lws_adns_q_destroy(lws_adns_q_t *q)
{
	lws_metrics_caliper_report(q->metcal, (char)q->go_nogo);

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	lws_adns_dnssec_q_destroy(q);
#endif

	lws_adns_q_sul_cancel(q, &q->sul);
	lws_adns_q_sul_cancel(q, &q->write_sul);
	lws_adns_q_sul_cancel(q, &q->deadline_sul);
	lws_dll2_remove(&q->list);

	lws_adns_q_socks_release(q);

	if (q->wsi_tcp) {
		q->wsi_tcp->a.opaque_user_data = NULL;
		lws_set_timeout(q->wsi_tcp, 1, LWS_TO_KILL_ASYNC);
		q->wsi_tcp = NULL;
	}

	if (q->tcp_rx_buf) {
		lws_free(q->tcp_rx_buf);
		q->tcp_rx_buf = NULL;
	}

	if (q->firstcache) {
		lws_adns_cache_unref(q->firstcache);
		q->firstcache = NULL;
	}

	lws_free(q);
}

static int
lws_adns_q_finishing(lws_adns_q_t *q)
{
	return lws_dll2_owner(&q->list) == &q->dns->finishing;
}

#if LWS_MAX_SMP > 1
static void
lws_adns_q_finish_cb(lws_sorted_usec_list_t *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, sul);

	lws_async_dns_complete(q, q->finish_found ? q->firstcache : NULL);
	lws_adns_q_destroy(q);
}
#endif

/*
 * q is over, with its results in c (which is q->firstcache), or failed if c is
 * NULL: tell its requesters and destroy it.
 *
 * The requesters must hear about it on q's own service thread, where they
 * live.  If we are on another, eg, the one the answer arrived on, q stops
 * here: it leaves the waiting list, so no more answers or writes find it,
 * and its own thread finishes it as soon as it wakes.  Until then a
 * requester going away can still cancel it as usual.
 */

void
lws_adns_q_finish(lws_adns_q_t *q, lws_adns_cache_t *c)
{
	assert(!c || c == q->firstcache);

	if (lws_adns_q_finishing(q))
		/* its own thread is already going to finish it */
		return;

#if LWS_MAX_SMP > 1
	{
		int tsi = lws_pthread_self_to_tsi(q->context);

		if (tsi >= 0 && tsi != q->tsi) {
			q->finish_found = !!c;
			lws_adns_q_sul_cancel(q, &q->write_sul);
			lws_adns_q_sul_cancel(q, &q->deadline_sul);
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
			/* nor may a validation it waited on come back to it */
			lws_adns_dnssec_q_destroy(q);
#endif
			lws_dll2_remove(&q->list);
			lws_dll2_add_tail(&q->list, &q->dns->finishing);
			lws_adns_q_sul_schedule(q, &q->sul,
						lws_adns_q_finish_cb, 0);

			return;
		}
	}
#endif

	lws_async_dns_complete(q, c);
	lws_adns_q_destroy(q);
}

lws_adns_q_t *
lws_adns_get_query(lws_async_dns_t *dns, adns_query_type_t qtype,
		   uint16_t tid, const char *name, int tsi)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->waiting)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

		/* only an address lookup asks a second question, the AAAA */
		if (!name && (tid == q->tid[0]
#if defined(LWS_WITH_IPV6)
			      || (lws_adns_q_is_addr(q) && tid == q->tid[1])
#endif
		   ))
			return q;

		/* a requester is only called back on its own thread */
		if (name && q->tsi == tsi) {
			/* q->qtype only ever holds the RR type, not the
			 * LWS_ADNS_* option flags the caller may pass */
			adns_query_type_t qt = (adns_query_type_t)
							(qtype & 0xffff);
			int type_match;

			/*
			 * An address lookup is one query object issuing both
			 * an A and an AAAA question, so either of those can be
			 * served by a pending address lookup... but anything
			 * else must match the type that is actually pending,
			 * or eg a DNSKEY requester rides on an A query and is
			 * handed addresses (or, with no wsi to attach, is
			 * never called back at all).
			 */

			if (qt == LWS_ADNS_RECORD_A ||
			    qt == LWS_ADNS_RECORD_AAAA)
				type_match = q->qtype == LWS_ADNS_RECORD_A ||
					     q->qtype == LWS_ADNS_RECORD_AAAA;
			else
				type_match = !qt || q->qtype == qt;

			/*
			 * The working copy of the name at +0 is whatever we
			 * are asking the nameserver about just now, which may
			 * be a CNAME target or a search list candidate: the
			 * pristine copy at +DNS_MAX is the name the requester
			 * asked for, and what the result is cached against
			 */
			if (type_match &&
			    !strcasecmp(name, (const char *)&q[1] + DNS_MAX))
				return q;
		}

	} lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

lws_async_dns_retcode_t
lws_async_dns_complete(lws_adns_q_t *q, lws_adns_cache_t *c)
{
	int rc;
	lws_async_dns_retcode_t ret = LADNS_RET_FOUND;
	struct lws_dll2 *d;
	const char *name;

	/*
	 * The requester callbacks are user code (they run the connect flow,
	 * CLIENT_CONNECTION_ERROR etc); any of them may synchronously close
	 * a *different* requester wsi piggybacked on this query.  That close
	 * cancels the wsi's dns wait, which would destroy q outright when it
	 * sees the last requester go, while we are still iterating q and our
	 * caller still uses q afterwards.
	 *
	 * So: while completing, cancel() detaches the closing wsi but leaves
	 * q alive; and we never cache a "next" pointer across a callback.
	 * Each serviced requester is removed from q first, so q's head is
	 * always an unserviced, still-interested wsi, and wsis freed by other
	 * callbacks were unlinked from q by their own cancel path.
	 */
	/*
	 * NXDOMAIN is an authoritative statement that the name does not exist,
	 * tell the requester so distinctly from the resolver having failed to
	 * answer (LADNS_RET_FAILED), which is what its dns retry budget is for
	 */

	if (!c)
		rc = LADNS_RET_FAILED;
	else if (!c->results && !c->rr_results && c->nxdomain)
		rc = LADNS_RET_NXDOMAIN;
	else
		rc = LADNS_RET_FOUND;
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if (rc >= 0 && q->dnssec_valid) {
		rc |= LWS_ADNS_DNSSEC_VALID;
		/* so a later requester served from the cache is told too */
		if (c) {
			uint32_t now = (uint32_t)lws_now_secs();
			lws_usec_t until = 0;

			c->dnssec_valid = 1;

			/*
			 * ... but only for as long as what we validated is
			 * valid: the entry's life so far came from the TTL on
			 * the wire, which no signature covers
			 */
			if ((int32_t)(q->dnssec_expires - now) > 0)
				until = (lws_usec_t)(q->dnssec_expires - now) *
								LWS_US_PER_SEC;
			if (c->sul.us - lws_now_usecs() > until)
				lws_sul_schedule(q->context, 0, &c->sul,
						 sul_cb_expire, until);
		}
	}
#endif

	q->completing = 1;

	/*
	 * The requesters are told about the name they asked for, the pristine
	 * copy at +DNS_MAX: the working copy at +0 is the last name we asked
	 * the nameserver about, which may be a CNAME target or a search list
	 * candidate, and the cache entry and its ai_canonname are made
	 * against the pristine one too
	 */
	name = (const char *)&q[1] + DNS_MAX;

	while ((d = lws_dll2_get_head(&q->wsi_adns))) {
		struct lws *w = lws_container_of(d, struct lws_io_adjunct, adns)->wsi;

		lws_dll2_remove(d);

		if (c && c->results) {
			lwsl_wsi_debug(w, "q: %p, c: %p, refcount %d -> %d",
				    q, c, (int)c->refcount,
				    (int)c->refcount + 1);
			c->refcount++;
		}
		lws_set_timeout(w, NO_PENDING_TIMEOUT, 0);
		if (w->io->adns_cb(w, name, c ? c->results : NULL,
			       rc, q->opaque) == NULL) {
			lwsl_info("%s: failed\n", __func__);
			ret = LADNS_RET_FAILED_WSI_CLOSED;
		}
	}

	/*
	 * The completing state has to extend over the standalone callback as
	 * well: it runs user code that may legitimately try to cancel and
	 * destroy this very query (eg, lws_async_dns_cancel_by_opaque() from
	 * an opaque that is being freed by the callback itself).  Our caller
	 * still uses q after we return, so it must stay protected until the
	 * whole completion is over.
	 */

	if (q->standalone_cb) {
		if (c && c->results)
			c->refcount++;

		if (q->standalone_cb(NULL, name, c ? c->results : NULL, rc,
				     q->opaque) == NULL)
			ret = LADNS_RET_FAILED_WSI_CLOSED;
	}

	q->completing = 0;

	lws_adns_dump(q->dns);

	return ret;
}

static void
lws_async_dns_sul_cb_retry(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, sul);
	struct lws *wsi = lws_adns_q_wsi(q);

	lwsl_wsi_info(wsi, "in");
	lws_adns_dump(q->dns);

	if (!wsi && !q->is_tcp) {
		/*
		 * Its socket went away, eg, a send on it failed: it asks from
		 * a new one
		 */
		if (lws_adns_q_socks_bind(q)) {
			lwsl_cx_notice(q->context, "%s: no socket to ask from",
				       (const char *)&q[1]);
			if (q->firstcache) {
				lws_adns_cache_destroy(q->firstcache);
				q->firstcache = NULL;
			}
			lws_adns_q_finish(q, NULL);

			return;
		}
		wsi = lws_adns_q_wsi(q);
	}

	q->is_retry = 1;
	if (wsi)
		lws_callback_on_writable(wsi);
}

static void
lws_async_dns_sul_cb_deadline(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, deadline_sul);

	/*
	 * Hard backstop on the query lifetime: however it got stuck (a
	 * resolver that answers nothing, a DNSSEC sub-lookup that never
	 * completes, a retry policy that conceals more than we expected), it
	 * may not live forever.  A standalone (wsi-less) query has no
	 * requester wsi whose own timeout would eventually reap it.
	 */

	lwsl_cx_notice(q->context, "async dns query %s timed out",
		       (const char *)&q[1]);

	if (q->firstcache) {
		lws_adns_cache_destroy(q->firstcache);
		q->firstcache = NULL;
	}

	lws_adns_q_finish(q, NULL);
}

static void
lws_async_dns_writeable(struct lws *wsi, lws_adns_q_t *q)
{
	uint8_t pkt[LWS_PRE + DNS_PACKET_LEN], *e = &pkt[sizeof(pkt)], *p, *pl;
	int m, n, which;
	const char *name;

	/*
	 * We managed to get to the point of being WRITEABLE, which is not a
	 * given if no routes.  So call off the write_sul timeout for that.
	 */
	lws_adns_q_sul_cancel(q, &q->write_sul);

	if (!q->is_retry && q->sent[0]
#if defined(LWS_WITH_IPV6)
	         && q->sent[0] == q->sent[1]
#endif
	)
		return;

	q->is_retry = 0;

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
	    lws_adns_q_retry_schedule(q, wsi)) {
		/*
		 * We have reached the end of our concealed retries.  The
		 * socket goes with the query, so the next query asks from a
		 * new one, in case the routing changed.
		 */
		lwsl_wsi_info(wsi, "failing query");
		goto qfail;
	}

	name = (const char *)&q[1];

	p = &pkt[LWS_PRE];
	memset(p, 0, DHO_SIZEOF);

#if defined(LWS_WITH_IPV6)
	/*
	 * This covers both dual-stack and IPv6-only builds: we want results
	 * for A and AAAA before we consider the query complete (asked = 3).
	 * In an IPv6-only build, A results are normalized to v4-mapped IPv6
	 * addresses later, so they remain usable on dual-stack hosts.
	 */
	if (q->qtype != LWS_ADNS_RECORD_A && q->qtype != LWS_ADNS_RECORD_AAAA) {
		which = 0;
		q->sent[0]++;
		q->sent[1]++; /* match states to avoid ipv6 duplicate writeable loop */
		q->asked = 1;
	} else if (q->ipv4_only && q->qtype == LWS_ADNS_RECORD_A) {
		which = 0;
		q->sent[0]++;
		q->sent[1]++; /* also mark ipv6 state sent to avoid AAAA query */
		q->asked = 1;
	} else if (q->ipv6_only && q->qtype == LWS_ADNS_RECORD_A) {
		which = 1;
		q->sent[0]++; /* also mark ipv4 state sent to avoid A query */
		q->sent[1]++;
		q->asked = 2; /* b1 = the AAAA response is the whole query */
	} else if (!q->responded) {
		/* must pick between ipv6 and ipv4 */
		which = q->sent[0] > q->sent[1];
		q->sent[which]++;
		q->asked = 3; /* want results for 4 & 6 before done */
	} else
		which = q->responded & 1;
#else
	which = 0;
	q->asked = 1;
#endif

	lwsl_wsi_info(wsi, "%s, which %d", name, which);

	/* the A (or only) question has tid[0], the AAAA one tid[1] */

	lws_ser_wu16be(&p[DHO_TID], q->tid[which]);

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	/*
	 * RD, and CD only if we validate this answer ourselves: then we want
	 * the records and signatures whatever the upstream thinks of them, and
	 * judge them by our own anchors.  Otherwise CD would stop a validating
	 * upstream refusing bogus data, and we would take it unchecked.
	 */
	lws_ser_wu16be(&p[DHO_FLAGS], (1 << 8) |
				      (lws_adns_q_validates(q) ? (1 << 4) : 0));
#else
	lws_ser_wu16be(&p[DHO_FLAGS], (1 << 8)); /* RD */
#endif

	lws_ser_wu16be(&p[DHO_NQUERIES], 1);
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if (q->dns->dnssec_mode || q->want_dnssec)
		lws_ser_wu16be(&p[DHO_NOTHER], 1); /* 1 additional record (EDNS0 OPT) */
#endif

	p += DHO_SIZEOF;

	/* start of label-formatted qname */

	pl = p++;
	*pl = 0; /* terminal length: also covers the empty/root-name case,
		  * where the do/while below breaks on the first iteration
		  * (l == 0) before ever writing *pl.  For a non-empty name
		  * this is overwritten with the first label's length when that
		  * label completes; for "." / "" it stays 0, which is exactly
		  * the DNS root label, and avoids sending an uninitialised
		  * byte in the query (oss-fuzz / valgrind). */

	do {
		if (*name == '.' || !*name) {
			int l = (int)lws_ptr_diff(p, pl + 1);
			if (l == 0) {
				/* skip empty label (e.g. trailing dot) */
				if (!*name++)
					break;
				continue;
			}
			*pl = (uint8_t)l;
			pl = p;
			*p++ = 0; /* also serves as terminal length */
			if (!*name++)
				break;
		} else
			*p++ = (uint8_t)*name++;
	} while (p + 6 < e);

	if (p + 6 >= e) {
		assert(0);
		lwsl_wsi_err(wsi, "name too big");
		goto qfail;
	}

	if (q->qtype == LWS_ADNS_RECORD_A || q->qtype == LWS_ADNS_RECORD_AAAA)
		lws_ser_wu16be(p, which ? LWS_ADNS_RECORD_AAAA : LWS_ADNS_RECORD_A);
	else
		lws_ser_wu16be(p, q->qtype);
	p += 2;

	lws_ser_wu16be(p, 1); /* IN class */
	p += 2;

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if (q->dns->dnssec_mode || q->want_dnssec) {
		/* Append EDNS0 OPT record with DO (DNSSEC-OK) bit */
		*p++ = 0; /* Name: root */
		lws_ser_wu16be(p, 41); /* Type: OPT (41) */
		p += 2;
		lws_ser_wu16be(p, DNS_PACKET_LEN); /* UDP payload size */
		p += 2;
		*p++ = 0; /* Extended RCODE */
		*p++ = 0; /* Version */
		lws_ser_wu16be(p, 0x8000); /* Flags: DO bit (bit 0 of 16-bit flags) */
		p += 2;
		lws_ser_wu16be(p, 0); /* RDLEN: 0 */
		p += 2;
	}
#endif

	assert(p < pkt + sizeof(pkt) - LWS_PRE);
	n = lws_ptr_diff(p, pkt + LWS_PRE);

	if (q->broadsiding && wsi->io->udp) {
		/* we race the question to every nameserver we have a socket to */
		m = -1;
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&q->socks)) {
			lws_adns_sock_t *s = lws_container_of(d,
					lws_adns_qsock_t, list)->sock;
			int m2;

			if (!s->wsi)
				continue;

			m2 = lws_write(s->wsi, pkt + LWS_PRE, (unsigned int)n, 0);
			if (s->wsi == wsi)
				m = m2;
			else if (m2 != n)
				/* its socket is unusable now, see below */
				lws_adns_sock_retire(s);
		} lws_end_foreach_dll_safe(d, d1);
	} else {
		if (!wsi->io->udp) {
			lws_ser_wu16be(pkt + LWS_PRE - 2, (uint16_t)n);
			m = lws_write(wsi, pkt + LWS_PRE - 2, (unsigned int)n + 2, 0);
		} else
			m = lws_write(wsi, pkt + LWS_PRE, (unsigned int)n, 0);
	}

	if (m != (wsi->io->udp ? n : n + 2)) {
		lwsl_wsi_notice(wsi, "dns write failed %d %d errno %d",
			    m, n, errno);
		/*
		 * The failed send left the socket unusable (lws_io_tx_push()),
		 * eg, it took the icmp error for a datagram sent while the
		 * nameserver was not listening.  Nothing else closes it, and
		 * any other query using it would wait on it for a writeable
		 * that never comes: retire it, so they ask from a new one at
		 * their next retry
		 */
		if (lws_adns_q_sock(q) && lws_adns_q_sock(q)->wsi == wsi)
			lws_adns_sock_retire(lws_adns_q_sock(q));
		goto qfail;
	}

#if defined(LWS_WITH_IPV6)
	if (!q->responded && q->sent[0] != q->sent[1]) {
		lwsl_wsi_debug(wsi, "request writeable for ipv6");
		lws_callback_on_writable(wsi);
	}
#endif

	return;

qfail:
	lwsl_wsi_warn(wsi, "failing query doing NULL completion");
	/*
	 * in ipv6 case, we made a cache entry for the first response but
	 * evidently the second response didn't come in time, purge the
	 * incomplete cache entry
	 */
	if (q->firstcache) {
		lwsl_wsi_debug(wsi, "destroy firstcache");
		lws_adns_cache_destroy(q->firstcache);
		q->firstcache = NULL;
	}
	if (q->dsrv) {
		lws_adapt_report_val(q->dsrv->adapt, 20000000, lws_now_usecs());
	}
	lws_adns_q_finish(q, NULL);
}

/* the callbacks on one of the queries' UDP sockets */

static void
lws_adns_sock_callback(struct lws *wsi, lws_adns_sock_t *s,
		       enum lws_callback_reasons reason, void *in, size_t len)
{
	struct lws_async_dns *dns = &(lws_get_context(wsi)->async_dns);
	lws_async_dns_server_t *dsrv = s->dsrv;
	lws_sockaddr46 src;

	if (s->adopting) {
		/* lws_adns_sock_create() deals with it */
		if (reason == LWS_CALLBACK_RAW_CLOSE)
			s->closed_adopting = 1;

		return;
	}

	switch (reason) {
	case LWS_CALLBACK_RAW_CLOSE:
		/* its queries ask from another at their next retry */
		if (s->wsi == wsi)
			lws_adns_sock_lost_wsi(s);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!wsi->io->udp || !in)
			break;

		/*
		 * recvfrom() left the datagram's source in wsi->io->udp->sa46,
		 * which is also where we send to... put the nameserver we
		 * chose back first, so a foreign datagram cannot redirect our
		 * queries to whoever sent it.
		 */

		src = wsi->io->udp->sa46;
		wsi->io->udp->sa46 = dsrv->sa46;

		/*
		 * An answer only means anything if it came from the server we
		 * asked.  The socket is connect()ed to the nameserver, so the
		 * kernel already dropped everything else, but we don't rely on
		 * it: without this, an off-path attacker who can reach our
		 * port would only have to guess the tid to poison any name.
		 */

		if (src.sa4.sin_port != dsrv->sa46.sa4.sin_port ||
		    lws_sa46_compare_ads(&src, &dsrv->sa46)) {
			char a1[48], a2[48];

			lws_sa46_write_numeric_address(&src, a1, sizeof(a1));
			lws_sa46_write_numeric_address(&dsrv->sa46, a2,
						       sizeof(a2));
			lwsl_wsi_notice(wsi, "dns answer from unexpected source "
					"%s port %u (AF %d), we asked %s port %u",
					a1, ntohs(src.sa4.sin_port),
					(int)src.sa4.sin_family, a2,
					ntohs(dsrv->sa46.sa4.sin_port));
			break;
		}

		/* only taken by a query that asked on this socket... */
		lws_adns_parse_via(dns, in, len, dsrv, wsi);
		/* ... which may have finished with it, and s with it */
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		/*
		 * The queries whose own socket this is: a broadsiding one
		 * writes on its sockets to the other nameservers along with it
		 */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&dns->waiting)) {
			lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t,
							   list);

			/* a failed send retires the socket: wsi no longer matches */
			if (lws_adns_q_wsi(q) == wsi && !q->is_synthetic &&
			    (!q->asked || q->responded != q->asked) &&
			    !q->is_tcp)
				lws_async_dns_writeable(wsi, q);
		} lws_end_foreach_dll_safe(d, d1);
		break;

	default:
		break;
	}
}

/* the callbacks on one of our own connections, holding the context lock */

static int
lws_adns_wsi_callback(struct lws *wsi, struct lws_async_dns *dns,
		      enum lws_callback_reasons reason, void *in, size_t len)
{
	lws_adns_sock_t *s;

	/* a direct query's own socket: its opaque is not a sock or a q */
	if (lws_adns_direct_callback(wsi, reason, in, len))
		return 0;

	/* one of the queries' UDP sockets */
	s = lws_adns_sock_from_opaque(dns, wsi->a.opaque_user_data);
	if (s) {
		lws_adns_sock_callback(wsi, s, reason, in, len);
		return 0;
	}

	/* otherwise it's a query's TCP connection, or a socket we let go of */

	if (!wsi->io->udp) {
		lws_adns_q_t *q = (lws_adns_q_t *)wsi->a.opaque_user_data;

		if (!q)
			return 0;

		if (lws_adns_q_finishing(q) &&
		    reason != LWS_CALLBACK_CLIENT_CONNECTION_ERROR &&
		    reason != LWS_CALLBACK_RAW_CLOSE)
			/* it's over: nothing more is sent or taken for it */
			return 0;

		switch (reason) {
		case LWS_CALLBACK_RAW_CONNECTED:
			lws_callback_on_writable(wsi);
			break;
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			/*
			 * The TCP fallback attempt could not connect (eg, the
			 * DNS server doesn't accept TCP).  This is reliably
			 * delivered to us on the wsi's connect failure path,
			 * before the wsi is freed; without it q->wsi_tcp would
			 * dangle at the freed wsi.
			 */
		case LWS_CALLBACK_RAW_CLOSE:
			if (q->wsi_tcp != wsi)
				/* stale notification for a wsi we already
				 * disowned */
				break;
			q->wsi_tcp = NULL;
			wsi->a.opaque_user_data = NULL;
			if (q->go_nogo != METRES_GO)
				lws_adns_q_finish(q, NULL);
			break;
		case LWS_CALLBACK_RAW_RX:
			/* accumulate bytes */
			if (!q->has_tcp_len) {
				const uint8_t *in8 = (const uint8_t *)in;

				while (len && !q->has_tcp_len) {
					q->tcp_rx_len = (uint16_t)((q->tcp_rx_len << 8) | *in8++);
					q->tcp_rx_pos++;
					len--;
					if (q->tcp_rx_pos == 2) {
						if (q->tcp_rx_len < DHO_SIZEOF ||
						    q->tcp_rx_len > LWS_ADNS_MAX_PAYLOAD) {
							lwsl_wsi_notice(wsi, "adns tcp len bad");
							return -1;
						}
						q->has_tcp_len = 1;
						q->tcp_rx_pos = 0;
						q->tcp_rx_buf = lws_malloc((size_t)q->tcp_rx_len + 1, "adns tcp");
						if (!q->tcp_rx_buf) {
							lwsl_wsi_err(wsi, "OOM");
							return -1;
						}
					}
				}
				in = (void *)in8;
			}

			if (q->has_tcp_len && len) {
				size_t chunk = len;
				if (q->tcp_rx_pos + chunk > (size_t)q->tcp_rx_len)
					chunk = (size_t)(q->tcp_rx_len - q->tcp_rx_pos);
				memcpy(q->tcp_rx_buf + q->tcp_rx_pos, in, chunk);
				q->tcp_rx_pos = (uint16_t)(q->tcp_rx_pos + chunk);

				if (q->tcp_rx_pos == q->tcp_rx_len) {
					/* we have the whole message */
					lws_adns_parse_via(dns, q->tcp_rx_buf,
							   q->tcp_rx_len,
							   q->dsrv, wsi);
					/* TCP connection is done */
					return -1;
				}
			}
			break;
		case LWS_CALLBACK_RAW_WRITEABLE:
			if (!q->is_retry && q->sent[0]
#if defined(LWS_WITH_IPV6)
	         && q->sent[0] == q->sent[1]
#endif
			)
				break;
			lws_async_dns_writeable(wsi, q);
			break;
		default:
			break;
		}
		return 0;
	}

	return 0;
}

static int
callback_async_dns(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct lws_async_dns *dns = &(lws_get_context(wsi)->async_dns);
	int n;

	/*
	 * Only the reasons about one of our own connections, the nameserver's
	 * UDP wsi or a query's TCP fallback wsi, may look past wsi->a.  The
	 * others, like PROTOCOL_INIT or EVENT_WAIT_CANCELLED, come with a
	 * wsi made up for the callback, which on freertos is only a
	 * struct lws_a on the stack: it has no wsi->io at all.
	 */

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
	case LWS_CALLBACK_RAW_CONNECTED:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_RAW_CLOSE:
	case LWS_CALLBACK_RAW_RX:
	case LWS_CALLBACK_RAW_WRITEABLE:
		break;
	default:
		return 0;
	}

	lws_context_lock(wsi->a.context, __func__); /* ------------ cx { */
	n = lws_adns_wsi_callback(wsi, dns, reason, in, len);
	lws_context_unlock(wsi->a.context); /* } cx */

	return n;
}

lws_async_dns_server_t *
__lws_async_dns_server_find(lws_async_dns_t *dns, const lws_sockaddr46 *sa46)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&dns->nameservers)) {
		lws_async_dns_server_t *s = lws_container_of(d,
						lws_async_dns_server_t, list);

		if (!lws_sa46_compare_ads(sa46, &s->sa46))
			return s;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* require: context lock */

lws_async_dns_server_t *
__lws_async_dns_server_add(lws_async_dns_t *dns, const lws_sockaddr46 *sa46)
{
	lws_async_dns_server_t *s;

	s = __lws_async_dns_server_find(dns, sa46);
	if (s) {
		s->refcount++;
		return s;
	}

	s = lws_zalloc(sizeof(*s), __func__);

	if (s) {
		s->sa46 = *sa46;
		lws_dll2_add_tail(&s->list, &dns->nameservers);
		s->refcount++;
		/* 1 level (just tracking values), 5s short decay, 60s long decay */
		s->adapt = lws_adapt_create(1, 5 * LWS_US_PER_SEC, 60 * LWS_US_PER_SEC);
	}

	return s;
}

/* require: context lock */

static void
__lws_async_dns_server_destroy(lws_async_dns_server_t *dsrv)
{
	lws_async_dns_t *dns;

	if (!dsrv)
		return;

	dsrv->refcount--;
	if (dsrv->refcount)
		return;

	dns = (lws_async_dns_t *)lws_dll2_owner(&dsrv->list);

	if (dns) {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				lws_dll2_get_head(&dns->waiting)) {
			lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

			if (q->dsrv == dsrv) {
				/* this query will never be answered, clean it up cleanly */
				lwsl_cx_notice(dns->cx, "failing query attached to removed DNS server");
				q->dsrv = NULL;
				lws_adns_q_finish(q, NULL);
			}
		} lws_end_foreach_dll_safe(d, d1);

		/* nor may one finishing on its own thread remember it */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&dns->finishing)) {
			lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

			if (q->dsrv == dsrv)
				q->dsrv = NULL;
		} lws_end_foreach_dll(d);
	}

	if (dns)
		/*
		 * Any sockets to it still held are a broadsiding query's, whose
		 * own nameserver is another: they are no use any more
		 */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&dns->socks)) {
			lws_adns_sock_t *s = lws_container_of(d,
						lws_adns_sock_t, list);

			if (s->dsrv == dsrv)
				lws_adns_sock_retire(s);
		} lws_end_foreach_dll_safe(d, d1);

	lws_dll2_remove(&dsrv->list);

	if (dsrv->adapt)
		lws_adapt_destroy(&dsrv->adapt);

	lws_free(dsrv);
}

void
__lws_async_dns_server_remove(lws_async_dns_t *dns, const lws_sockaddr46 *sa46)
{
	lws_async_dns_server_t *dsrv = __lws_async_dns_server_find(dns, sa46);

	if (!dsrv)
		return;

	__lws_async_dns_server_destroy(dsrv);
}

int
lws_async_dns_server_add(struct lws_context *cx, const lws_sockaddr46 *sa46)
{
	lws_async_dns_server_t *dsrv;
	int r;

	lws_context_lock(cx, __func__);
	dsrv = __lws_async_dns_server_add(&cx->async_dns, sa46);
	if (dsrv)
		dsrv->pinned = 1;
	r = !!dsrv;
	lws_context_unlock(cx);

	return r;
}

void
lws_async_dns_server_remove(struct lws_context *cx, const lws_sockaddr46 *sa46)
{
	lws_context_lock(cx, __func__);
	__lws_async_dns_server_remove(&cx->async_dns, sa46);
	lws_context_unlock(cx);
}

struct lws_protocols lws_async_dns_protocol = {
	"lws-async-dns", callback_async_dns, 0, 0, 0, NULL, 0
};

lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_async_dns_t *dns)
{
	lws_async_dns_server_check_t s = LADNS_CONF_SERVER_SAME;
	lws_async_dns_server_t *dsrv;
	lws_sockaddr46 sa46t;
	int n = 0, any_pinned = 0, ndots = 1;

	/*
	 * The search list goes with the platform's resolver configuration
	 * even when the nameservers themselves are pinned by user code
	 */
	n = lws_plat_asyncdns_get_search(context, dns->search,
					 sizeof(dns->search), &ndots);
	dns->search_count = n > 0 ? (uint8_t)n : 0;
	dns->ndots = (uint8_t)ndots;
	n = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
				   lws_dll2_get_head(&dns->nameservers)) {
		dsrv = lws_container_of(d, lws_async_dns_server_t, list);
		if (dsrv->pinned)
			any_pinned = 1;
		dsrv->seen = 0;
	} lws_end_foreach_dll(d);

	if (!any_pinned) {
		while (lws_plat_asyncdns_get_server(context, n++, &sa46t) == 0) {
			dsrv = __lws_async_dns_server_find(dns, &sa46t);
			if (!dsrv) {
				dsrv = __lws_async_dns_server_add(dns, &sa46t);
				s = LADNS_CONF_SERVER_CHANGED;
			}
			if (dsrv)
				dsrv->seen = 1;
		}
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->nameservers)) {
		dsrv = lws_container_of(d, lws_async_dns_server_t, list);
		if (!dsrv->seen && !dsrv->pinned) {
			__lws_async_dns_server_remove(dns, &dsrv->sa46);
			s = LADNS_CONF_SERVER_CHANGED;
		}
	} lws_end_foreach_dll_safe(d, d1);

	return s;
}

#if defined(LWS_WITH_SYS_SMD)
static int
lws_adns_smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
		void *buf, size_t len);
static void
lws_adns_watch_start(struct lws_context *cx);
#endif

int
lws_async_dns_init(struct lws_context *context)
{
	lws_async_dns_t *dns = &context->async_dns;
	int n;

	/*
	 * The lws_system_ops mode is only the default, taken the first time
	 * we are initialized, which is during lws_create_context(), before
	 * anyone can have called lws_async_dns_dnssec_set_mode().  We are
	 * called again for every nameserver reload, including the one the
	 * SMD watcher triggers on the first service pass, and one a peer can
	 * provoke by making the servers look dead: taking the ops value again
	 * then silently put a mode set with the setter, eg, REQUIRE, back to
	 * OFF.
	 */
	if (!dns->cx) {
		const lws_system_ops_t *ops = lws_system_get_ops(context);

		lws_async_dns_dnssec_set_mode(context, ops ?
			(lws_async_dns_dnssec_mode_t)ops->async_dns_dnssec_mode :
			LWS_ADNS_DNSSEC_OFF);
	}

	dns->cx = context;

#if defined(LWS_WITH_SYS_SMD)
	/*
	 * Register the single lws-side SMD consumer of DNS server change
	 * events before the watcher can produce any, including the gratuitous
	 * initial report from lws_adns_watch_start() below.
	 */
	if (!dns->smd_peer)
		dns->smd_peer = lws_smd_register(context, context, 0,
						 LWSSMDCL_DNS,
						 lws_adns_smd_cb);
#endif

	/* the queries open their sockets to the servers as they need them */
	lws_context_lock(context, __func__); /* ------------------- cx { */
	lws_plat_asyncdns_init(context, dns);
	n = !lws_dll2_count(&dns->nameservers);
	lws_context_unlock(context); /* } cx */

#if defined(LWS_WITH_SYS_SMD)
	lws_adns_watch_start(context);
#endif

	if (n) {
		lwsl_cx_warn(context, "no valid dns server, retry");

		return 1;
	}

	return 0;
}

LWS_VISIBLE int
lws_async_dns_server_reload(struct lws_context *context)
{
	return lws_async_dns_init(context);
}

#if defined(LWS_WITH_SYS_SMD)

/*
 * Platform DNS server change watching
 *
 * Platforms expose their effective DNS server list via
 * lws_plat_asyncdns_get_server() (resolv.conf, android system properties,
 * macOS dynamic store, windows GetNetworkParams...).  Some platforms can
 * also tell us when it changed (macOS dynamic store notifications on a
 * dispatch queue); everywhere else we poll on a sul.
 *
 * Either way it comes to the same place: flatten the platform list into a
 * deterministic string and, if it differs from the last one we published,
 * send it out on SMD class LWSSMDCL_DNS as JSON like
 * {"ns":["1.1.1.1"],"search":["lan"],"ndots":1}.
 *
 * The SMD message is a trigger for lws_adns_smd_cb() to requery the
 * platform for the authoritative list and apply it, and an event for user
 * observers; it's deliberately not the payload the resolver itself consumes
 * (SMD delivery is best-effort, so the control path must not depend on it).
 * Equally, we only commit watch_last when we managed to publish, so a
 * failed send is retried at the next acquisition pass.
 */

static lws_usec_t
lws_adns_watch_interval(void)
{
#if defined(LWS_HAVE_GETENV)
	const char *e = getenv("LWS_ASYNCDNS_WATCH_MS");
#else
	const char *e = NULL;
#endif
	/*
	 * The interval only bounds worst-case detection latency on platforms
	 * without push notifications (and retries of unpublished lists); the
	 * default is set so it's negligible compared to a DNS round trip.
	 * The LWS_ASYNCDNS_WATCH_MS env override (giving the poll interval in
	 * ms) is for tests.
	 */

	if (e && atoi(e) > 0)
		return (lws_usec_t)atoi(e) * LWS_US_PER_MS;

	return 3 * LWS_US_PER_SEC;
}

/*
 * Pull the platform's current effective server list into buf as a
 * deterministic JSON object body like
 *
 *   "ns":["192.168.1.1","1.1.1.1"],"search":["lan"],"ndots":1
 *
 * with each list truncated at entry boundaries if the whole can't fit.  The
 * search list is in it so a change to that alone is seen as well.
 */

static size_t
lws_adns_watch_append(char *buf, size_t len, size_t used, const char *s,
		      size_t sl, int first)
{
	if (used + sl + 4 > len) /* quotes, comma, NUL */
		return used;

	if (!first)
		buf[used++] = ',';
	buf[used++] = '"';
	memcpy(buf + used, s, sl);
	used += sl;
	buf[used++] = '"';
	buf[used] = '\0';

	return used;
}

static void
lws_adns_watch_acquire(struct lws_context *cx, char *buf, size_t len)
{
	char search[LWS_ADNS_SEARCH_BUF], *sd = search;
	lws_sockaddr46 sa46;
	size_t used = 0;
	int idx = 0, n, ndots = 1;

	if (len < 44) {
		buf[0] = '\0';
		return;
	}

	/* the SMD message wraps it in braces, and vsnprintf() wants a NUL */
	len -= 4;

	used = (size_t)lws_snprintf(buf, len, "\"ns\":[");

	while (lws_plat_asyncdns_get_server(cx, idx, &sa46) == 0) {
		char ads[48];

		lws_sa46_write_numeric_address(&sa46, ads, sizeof(ads));
		used = lws_adns_watch_append(buf, len - 24, used, ads,
					     strlen(ads), !idx);
		idx++;
	}

	used += (size_t)lws_snprintf(buf + used, len - used, "],\"search\":[");

	n = lws_plat_asyncdns_get_search(cx, search, sizeof(search), &ndots);
	for (idx = 0; idx < n; idx++) {
		used = lws_adns_watch_append(buf, len - 12, used, sd,
					     strlen(sd), !idx);
		sd += strlen(sd) + 1;
	}

	lws_snprintf(buf + used, len - used, "],\"ndots\":%d", ndots);
}

void
lws_adns_watch_trigger(struct lws_context *cx)
{
	lws_async_dns_t *dns = &cx->async_dns;
	char buf[LWS_ASYNCDNS_WATCH_BUF];

	if (!dns->watch_started)
		return;

	lws_adns_watch_acquire(cx, buf, sizeof(buf));

	/*
	 * On freertos, lws_mutex_lock() is an expression (it returns 0 for
	 * OK), so the result has to be consumed like smd.c does
	 */

	if (lws_mutex_lock(dns->lock_watch))
		return;

	if (!strcmp(buf, dns->watch_last)) {
		lws_mutex_unlock(dns->lock_watch);
		return;
	}

	if (!lws_smd_msg_printf(cx, LWSSMDCL_DNS, "{%s}", buf)) {
		lws_strncpy(dns->watch_last, buf, sizeof(dns->watch_last));
		lwsl_cx_notice(cx, "platform DNS servers now: {%s}", buf);
	} else
		lwsl_cx_notice(cx, "unable to publish DNS server list");

	lws_mutex_unlock(dns->lock_watch);
}

static void
lws_adns_sul_watch_cb(lws_sorted_usec_list_t *sul)
{
	lws_async_dns_t *dns = lws_container_of(sul, lws_async_dns_t, sul_watch);

	lws_adns_watch_trigger(dns->cx);
	lws_sul_schedule(dns->cx, 0, &dns->sul_watch, lws_adns_sul_watch_cb,
			 lws_adns_watch_interval());
}

/*
 * Boot gate retry: while the LWS_SYSTATE_DNS gate is denying, periodically
 * run an acquisition pass AND re-attempt the state walk.  The re-attempt is
 * the critical half: without it, the walk is only retried if a server ever
 * appears (via the SMD path), so a platform that stays serverless would
 * hold the context pre-OPERATIONAL forever.
 */

static void
lws_adns_sul_gate_cb(lws_sorted_usec_list_t *sul)
{
	lws_async_dns_t *dns = lws_container_of(sul, lws_async_dns_t, sul_gate);

	lws_adns_watch_trigger(dns->cx);

#if defined(LWS_WITH_SYS_STATE)
	if (dns->cx->mgr_system.state < LWS_SYSTATE_OPERATIONAL)
		lws_state_transition_steps(&dns->cx->mgr_system,
					   LWS_SYSTATE_OPERATIONAL);
#endif
}

/*
 * Called from the LWS_SYSTATE_DNS gate while it's denying the transition
 * because we have no servers yet: make sure an acquisition pass and a
 * transition re-attempt happen soon.
 */

void
lws_adns_kick(struct lws_context *cx)
{
	if (cx->async_dns.watch_started)
		lws_sul_schedule(cx, 0, &cx->async_dns.sul_gate,
				 lws_adns_sul_gate_cb,
				 250 * LWS_US_PER_MS);
}

static void
lws_adns_watch_start(struct lws_context *cx)
{
	lws_async_dns_t *dns = &cx->async_dns;

	if (dns->watch_started)
		return;

	dns->watch_started = 1;
	lws_mutex_init(dns->lock_watch);

	/*
	 * Seed the compare cache with what init just acquired and publish the
	 * initial list gratuitously, so observers get the current state at
	 * context creation deterministically.
	 */

	lws_adns_watch_acquire(cx, dns->watch_last,
			       sizeof(dns->watch_last));

	if (!lws_smd_msg_printf(cx, LWSSMDCL_DNS, "{%s}", dns->watch_last))
		lwsl_cx_notice(cx, "platform DNS servers: {%s}",
				dns->watch_last);

#if defined(__APPLE__)
	if (lws_plat_asyncdns_watch_start(cx))
		lwsl_cx_notice(cx, "native DNS watch unavailable, polling");
#endif

	lws_sul_schedule(cx, 0, &dns->sul_watch, lws_adns_sul_watch_cb,
			 lws_adns_watch_interval());
}

/*
 * Must be called before the context's SMD peers and locks are destroyed.
 * Stops any platform push watcher, stops the poll sul and drops our SMD
 * peer registration.
 */

void
lws_adns_smd_destroy(struct lws_context *cx)
{
	lws_async_dns_t *dns = &cx->async_dns;

	if (!dns->watch_started)
		return;

	dns->watch_started = 0;

	lws_sul_cancel(&dns->sul_watch);
	lws_sul_cancel(&dns->sul_gate);

#if defined(__APPLE__)
	lws_plat_asyncdns_watch_stop(cx);
#endif

	if (dns->smd_peer) {
		lws_smd_unregister(dns->smd_peer);
		dns->smd_peer = NULL;
	}

	lws_mutex_destroy(dns->lock_watch);
}

/*
 * The single lws-side SMD listener for DNS server change events.  The
 * message body is informational (see lws_adns_watch_trigger()): treat the
 * event as a trigger to requery the platform and apply whatever we find
 * there.
 */

static int
lws_adns_smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
		void *buf, size_t len)
{
	struct lws_context *cx = (struct lws_context *)opaque;

	(void)buf;
	(void)len;
	(void)timestamp;

	if (_class != LWSSMDCL_DNS)
		return 0;

	lws_async_dns_server_reload(cx);

#if defined(LWS_WITH_SYS_STATE)
	/*
	 * If we were holding the system state at LWS_SYSTATE_DNS waiting for
	 * a server to appear, try to move on now.
	 */
	if (cx->mgr_system.state < LWS_SYSTATE_OPERATIONAL)
		lws_state_transition_steps(&cx->mgr_system,
					   LWS_SYSTATE_OPERATIONAL);
#endif

	return 0;
}

int
lws_adns_servers_known(struct lws_context *cx)
{
	return !!lws_dll2_count(&cx->async_dns.nameservers);
}

/*
 * The LWS_SYSTATE_DNS gate: hold transitions while we have no DNS servers,
 * so user code waiting for OPERATIONAL can rely on lookups working... but
 * only for a bounded time.  A platform that never produces a server (an
 * offline device, a restricted daemon environment, or a discovery source
 * we can't read) must not wedge the context pre-OPERATIONAL forever; after
 * the wait we proceed with a notice and the watcher keeps fixing the
 * server list in the background if one appears later.
 */

static lws_usec_t
lws_adns_gate_max_us(void)
{
#if defined(LWS_HAVE_GETENV)
	const char *e = getenv("LWS_ASYNCDNS_GATE_MAX_MS");
#else
	const char *e = NULL;
#endif

	if (e && atoi(e) > 0)
		return (lws_usec_t)atoi(e) * LWS_US_PER_MS;

	return 10 * LWS_US_PER_SEC;
}

int
lws_adns_gate_ok(struct lws_context *cx)
{
	lws_async_dns_t *dns = &cx->async_dns;
	lws_usec_t now;

	if (lws_adns_servers_known(cx))
		return 1;

	now = lws_now_usecs();

	if (!dns->time_gate_first) {
		dns->time_gate_first = now;

		return 0;
	}

	if (now - dns->time_gate_first > lws_adns_gate_max_us()) {
		lwsl_cx_notice(cx,
			"no platform DNS servers after %dms, proceeding",
			(int)(lws_adns_gate_max_us() / LWS_US_PER_MS));

		return 1;
	}

	return 0;
}

#else /* no SMD */

int
lws_adns_servers_known(struct lws_context *cx)
{
	(void)cx;

	return 1;
}

int
lws_adns_gate_ok(struct lws_context *cx)
{
	(void)cx;

	return 1;
}

void
lws_adns_kick(struct lws_context *cx)
{
	(void)cx;
}

void
lws_adns_smd_destroy(struct lws_context *cx)
{
	(void)cx;
}

#endif

/*
 * Find a completed cache entry for \p name that holds records of \p qtype
 * (for A or AAAA, addresses).  The cache may hold several entries for one
 * name, eg, its A records and its DNSKEY RRset, or the same records from a
 * query that validated them and from one that didn't; if \p need_valid, only
 * an entry whose query validated it will do.
 */

lws_adns_cache_t *
lws_adns_get_cache(lws_async_dns_t *dns, const char *name, uint16_t qtype,
		   int need_valid)
{
	lws_adns_cache_t *c;

	if (!name) {
		assert(0);
		return NULL;
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->cached)) {
		lws_adns_rr_t *rr;
		int found = 0;

		c = lws_container_of(d, lws_adns_cache_t, list);

		if (c->incomplete || strcasecmp(name, c->name))
			continue;

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
		if (need_valid && !c->dnssec_valid)
			continue;
#else
		(void)need_valid;
#endif

		if (qtype == LWS_ADNS_RECORD_A || qtype == LWS_ADNS_RECORD_AAAA)
			found = !!c->results;
		else
			for (rr = c->rr_results; rr && !found; rr = rr->next)
				found = rr->type == qtype;

		if (found) {
			/* Keep sorted by LRU: move to the head */
			lws_dll2_remove(&c->list);
			lws_dll2_add_head(&c->list, &dns->cached);

			return c;
		}
	} lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

#if defined(_DEBUG)

void
lws_adns_server_dump(lws_async_dns_server_t *dsrv)
{
#if (_LWS_ENABLED_LOGS & LLL_INFO)
	lws_async_dns_t *dns = (lws_async_dns_t *)lws_dll2_owner(&dsrv->list);
	char ads[64];

	lws_sa46_write_numeric_address(&dsrv->sa46, ads, sizeof(ads));
	lwsl_cx_info(dns->cx, "nameserver: '%s'", ads);

	lws_start_foreach_dll(struct lws_dll2 *, d,
				   lws_dll2_get_head(&dns->waiting)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);
		if (q->dsrv == dsrv || q->broadsiding)
			lwsl_wsi_info(lws_adns_q_wsi(q),
				      "q: '%s', sent %d, resp %d%s",
				      (const char *)&q[1], q->sent[0], q->responded,
				      q->broadsiding ? " (broadsiding)" : "");
	} lws_end_foreach_dll(d);
#endif
}

void
lws_adns_dump(lws_async_dns_t *dns)
{
#if (_LWS_ENABLED_LOGS & LLL_INFO)
	lws_async_dns_server_t *dsrv;
	lws_adns_cache_t *c;

	if (!dns)
		return;

	lwsl_cx_info(dns->cx, "ADNS cache %u entries, %u sockets",
			(unsigned int)lws_dll2_count(&dns->cached),
			(unsigned int)lws_dll2_count(&dns->socks));

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->cached)) {
		c = lws_container_of(d, lws_adns_cache_t, list);

		lwsl_cx_info(dns->cx, "cache: '%s', exp: %lldus, incomp %d, "
			  "fl 0x%x, refc %d, res %p\n", c->name,
			  (long long)(c->sul.us - lws_now_usecs()),
			  c->incomplete, c->flags, (int)c->refcount,
			  c->results);
	} lws_end_foreach_dll(d);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->nameservers)) {
		dsrv = lws_container_of(d, lws_async_dns_server_t, list);
		lws_adns_server_dump(dsrv);
	} lws_end_foreach_dll(d);
#endif
}
#endif

void
lws_adns_cache_destroy(lws_adns_cache_t *c)
{
	/* its expiry is on pt 0, and we may be serving another */
	lws_sul_cancel_tsi(c->cx, 0, &c->sul);
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

/*
 * Drop one hold on the cache entry.  If its TTL already ran out while it
 * was held, the last hold going is what frees it.
 */

void
lws_adns_cache_unref(lws_adns_cache_t *c)
{
	assert(c->refcount > 0);
	if (c->refcount)
		c->refcount--;

	if (!c->refcount && c->expired)
		lws_adns_cache_destroy(c);
}

void
sul_cb_expire(struct lws_sorted_usec_list *sul)
{
	lws_adns_cache_t *c = lws_container_of(sul, lws_adns_cache_t, sul);

	if (c->refcount) {
		/*
		 * Somebody still holds it: its query may be waiting for the
		 * second half of an A / AAAA pair to chain on, or a requester
		 * not returned the results yet, eg, when the TTL was 0.  Take
		 * it out of the cache so nobody new finds it, and leave the
		 * free to the last holder.
		 */
		lws_dll2_remove(&c->list);
		c->expired = 1;

		return;
	}

	lws_adns_cache_destroy(c);
}

void
sul_cb_write(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, write_sul);

	/*
	 * Something's up, we couldn't even get from write request to
	 * WRITEABLE within the timeout, let alone the result... fail
	 * the query and everyone riding on it...
	 */

	lwsl_wsi_info(lws_adns_q_wsi(q), "failing");
	lws_adns_dump(q->dns);

	if (q->dsrv) {
		lws_adapt_report_val(q->dsrv->adapt, 20000000, lws_now_usecs());
	}

	lws_adns_q_finish(q, NULL); /* no cache to relate to */
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

	lws_context_lock(c->cx, __func__); /* --------------------- cx { */

	lwsl_debug("%s: c %p, %s, refcount %d\n", __func__, c,
		   (c->results && c->results->ai_canonname) ?
				c->results->ai_canonname : "none",
						(int)c->refcount);

	*pai = NULL;
	lws_adns_cache_unref(c);

	lws_context_unlock(c->cx); /* } cx */
}

void
lws_async_dns_trim_cache(lws_async_dns_t *dns)
{
	lws_adns_cache_t *c1;

	if (lws_dll2_count(&dns->cached) + 1< MAX_CACHE_ENTRIES)
		return;

	/* we want to make space for one new one */

	if (!lws_dll2_count(&dns->cached))
		return;

	c1 = lws_container_of(lws_dll2_get_tail(&dns->cached),
						lws_adns_cache_t, list);
	if (c1->refcount)
		lwsl_cx_info(dns->cx, "acache %p: refcount %d on purge",
				c1, (int)c1->refcount);
	else
		lws_adns_cache_destroy(c1);
}


static int
clean(struct lws_dll2 *d, void *user)
{
	lws_adns_q_destroy(lws_container_of(d, lws_adns_q_t, list));

	return 0;
}

static int
ns_clean(struct lws_dll2 *d, void *user)
{
	lws_async_dns_server_t *dsrv = lws_container_of(d,
					lws_async_dns_server_t, list);
	lws_async_dns_t *dns = (lws_async_dns_t *)lws_dll2_owner(&dsrv->list);

	/* Since waiting queue is now on dns, we can't iterate dsrv->waiting. We should just let dns deinit handle the global queue. But we can clean up any queries specifically bound to this server if not broadsiding. */
	lws_start_foreach_dll_safe(struct lws_dll2 *, dwait, dwait1,
				   lws_dll2_get_head(&dns->waiting)) {
		lws_adns_q_t *q = lws_container_of(dwait, lws_adns_q_t, list);
		if (q->dsrv == dsrv && !q->broadsiding) {
			clean(dwait, user);
		}
	} lws_end_foreach_dll_safe(dwait, dwait1);

	__lws_async_dns_server_destroy(dsrv);

	return 0;
}

void
lws_async_dns_deinit(lws_async_dns_t *dns)
{
	lws_adns_direct_deinit(dns);
	lws_dll2_foreach_safe(&dns->waiting, NULL, clean);
	lws_dll2_foreach_safe(&dns->finishing, NULL, clean);
	lws_dll2_foreach_safe(&dns->nameservers, NULL, ns_clean);
	lws_dll2_foreach_safe(&dns->cached, NULL, cache_clean);
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	/* after the queries: a zone being authenticated has one in flight */
	lws_adns_dnssec_deinit(dns);
#endif
}

static int
cancel(struct lws_dll2 *d, void *user)
{
	lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d3, d4,
				   lws_dll2_get_head(&q->wsi_adns)) {
		struct lws *w = lws_container_of(d3, struct lws_io_adjunct, adns)->wsi;

		if (user == w) {
			/*
			 * This is an ongoing query that our wsi was involved
			 * in... detach it from the query, and if nothing left
			 * interested in the query, destroy it.
			 *
			 * Since the wsi can only be running one query at a time
			 * currently, we can bail if we got a hit.
			 */
			lws_dll2_remove(d3);
			if (!lws_dll2_count(&q->wsi_adns) && !q->completing)
				lws_adns_q_destroy(q);
			return 1;
		}
	} lws_end_foreach_dll_safe(d3, d4);

	return 0;
}

/*
 * Let's go through all ongoing async dns queries, detaching wsi from any it
 * is involved in, and destroying the query if that was the only consumer.
 */

void
lws_async_dns_cancel(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;

	lws_context_lock(cx, __func__); /* ------------------------ cx { */
	if (!lws_dll2_foreach_safe(&cx->async_dns.waiting, wsi, cancel))
		lws_dll2_foreach_safe(&cx->async_dns.finishing, wsi, cancel);
	lws_context_unlock(cx); /* } cx */
}

static int
cancel_by_opaque(struct lws_dll2 *d, void *user)
{
	lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

	if (q->standalone_cb && q->opaque == user) {
		/*
		 * The object the callback would be invoked on is going away,
		 * so the callback and opaque are detached first; a resolver
		 * reply for this query can no longer reach it.
		 */
		q->standalone_cb = NULL;
		q->opaque = NULL;

		/*
		 * If wsi(s) piggybacked on this query, they still want the
		 * answer... leave it to the last one out to destroy q.
		 */
		if (!lws_dll2_count(&q->wsi_adns) && !q->completing)
			lws_adns_q_destroy(q);
	}

	return 0;
}

void
lws_async_dns_cancel_by_opaque(struct lws_context *cx, void *opaque)
{
	lws_context_lock(cx, __func__); /* ------------------------ cx { */
	lws_dll2_foreach_safe(&cx->async_dns.waiting, opaque, cancel_by_opaque);
	lws_dll2_foreach_safe(&cx->async_dns.finishing, opaque,
			      cancel_by_opaque);
	lws_context_unlock(cx); /* } cx */
}


static int
check_tid(struct lws_dll2 *d, void *user)
{
	lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);
	uint16_t check = (uint16_t)(intptr_t)user;

	return check == q->tid[0] || check == q->tid[1];
}

/*
 * Give q a new pair of tids, for its A (or only) and AAAA questions.  The tid
 * is all an off-path spoofer has to guess besides our source port, so each is
 * a full 16 bits from the CSPRNG, independent of the other (RFC 5452 4.3),
 * and unique among the queries in flight, including q's own previous ones,
 * so a late answer to an earlier question can't match.
 */

int
lws_async_dns_get_new_tid(struct lws_context *context, lws_adns_q_t *q)
{
	uint16_t nt[2];
	int n, budget;

	assert(q->dsrv);

	for (n = 0; n < (int)LWS_ARRAY_SIZE(nt); n++) {
		budget = 10;

		do {
			if (lws_get_random(context, &nt[n], sizeof(nt[n])) !=
							sizeof(nt[n]))
				return -1;

			if ((!n || nt[n] != nt[0]) &&
			    !lws_dll2_foreach_safe(&q->dns->waiting,
						   (void *)(intptr_t)nt[n],
						   check_tid))
				break;
		} while (--budget);

		if (!budget) {
			lwsl_cx_err(context, "unable to get unique tid");

			return -1;
		}
	}

	q->tid[0] = nt[0];
	q->tid[1] = nt[1];

	return 0;
}

/* max matching addresses we will collect from the hosts file */

#define LWS_ADNS_HOSTS_MAX_MATCHES 4

#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_PLAT_FREERTOS)

/*
 * Search /etc/hosts or similar for the DNS name
 *
 * Collects up to max_ads matching addresses from any lines mentioning name,
 * returning the number collected (0 if none).  lens[] gets the length of the
 * corresponding address in ads (4 or 16).  This mirrors getaddrinfo()
 * semantics for the hosts file, ie, a name with both v4 and v6 lines yields
 * both addresses, so happy-eyeballs can race them.
 */

int
lws_adns_scan_hostsfile(const char *name, uint8_t *ads, uint8_t *lens,
			int max_ads, int qtype)
{
	char had_ads = 0, buf[128], finalized = 0;
	uint8_t t[16];
	int fd, l = 0, ol = -1, count = 0;
	size_t nl = strlen(name);
	struct lws_tokenize ts;

#if defined(WIN32)
	int s;

	fd = _open("C:\\Windows\\System32\\Drivers\\etc\\hosts", LWS_O_RDONLY);
#else
	ssize_t s;

	fd = open("/etc/hosts", LWS_O_RDONLY);
#endif

	if (fd < 0)
		return 0;

	memset(&ts, 0, sizeof(ts));
	ts.flags = LWS_TOKENIZE_F_EXPECT_MORE | LWS_TOKENIZE_F_MINUS_NONTERM |
		   LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_NO_FLOATS |
		   LWS_TOKENIZE_F_NO_INTEGERS | LWS_TOKENIZE_F_HASH_COMMENT |
		   LWS_TOKENIZE_F_COLON_NONTERM;

	do {

#if defined(WIN32)
		s = _read(fd, buf, sizeof(buf) - 1);
#else
		s = read(fd, buf, sizeof(buf) - 1);
#endif
		if (s <= 0) {
			finalized = 1;
			ts.flags = (uint16_t)(ts.flags & (~LWS_TOKENIZE_F_EXPECT_MORE));
			s = 0;
		}

		ts.start = (char *)buf;
		ts.len = (size_t)s;

		do {
			ts.e = (int8_t)lws_tokenize(&ts);
			if (ts.e == LWS_TOKZE_WANT_READ)
				break;

			if (ts.effline != ol) {
				had_ads = 0;
				ol = ts.effline;
			}

			if (ts.e == LWS_TOKZE_TOKEN && had_ads && l &&
			    nl == ts.token_len &&
			    !memcmp(name, ts.token, ts.token_len)) {
				/* it's a hit */
				if ((qtype == LWS_ADNS_RECORD_A && l == 4) ||
#if defined(LWS_WITH_IPV6)
				    (qtype == LWS_ADNS_RECORD_A && l == 16) ||
#endif
				    (qtype == LWS_ADNS_RECORD_AAAA && l == 16) ||
				    (qtype != LWS_ADNS_RECORD_A && qtype != LWS_ADNS_RECORD_AAAA)) {
					if (count < max_ads) {
						memcpy(ads + (size_t)count * 16, t,
						       (size_t)l);
						lens[count] = (uint8_t)l;
						count++;
					}
				}
			}
			if (ts.e == LWS_TOKZE_TOKEN && !had_ads && ts.token_len < 50) {
				/* we're getting an ipv4 or ipv6 numads */
				char temp_ads[64];
				memcpy(temp_ads, ts.token, ts.token_len);
				temp_ads[ts.token_len] = '\0';
				l = lws_parse_numeric_address(temp_ads, t, sizeof(t));
				had_ads = 1;
			}

		} while (ts.e > 0); /* no error yet */

	} while (!finalized); /* whole file, so we get every matching line */

#if defined(WIN32)
	_close(fd);
#else
	close(fd);
#endif

	return count;
}
#endif

uint16_t
lws_adns_get_tid(struct lws_adns_q *q)
{
	return q->tid[0];
}

uint16_t
lws_adns_get_tid_aaaa(struct lws_adns_q *q)
{
	return q->tid[1];
}

struct lws_async_dns *
lws_adns_get_async_dns(struct lws_adns_q *q)
{
	return q->dns;
}

struct lws_async_dns_server *
lws_adns_get_server(struct lws_adns_q *q)
{
	return q->dsrv;
}

/*
 * A query that is answered at once, from the hosts file or a numeric address,
 * is completed through a temporary on the stack.  lws_async_dns_complete()
 * and the requesters find the name behind it as they do behind a real query,
 * so it has the same two DNS_MAX regions: the working copy at +0, and the
 * pristine copy the requesters are told about at +DNS_MAX.
 */

struct temp_q {
	lws_adns_q_t tq;
	char name[DNS_MAX * 2];
};

/*
 * The search list
 *
 * A name with fewer dots than the resolver's ndots is asked about under each
 * search domain in turn and then as given; one with at least ndots dots is
 * asked about as given and then under each search domain.  That is the order
 * libc tries them in, so a name resolves to the same thing through us as it
 * does through getaddrinfo().  A name ending in a dot is absolute and is only
 * asked about as given, as is any name when there is no search list.
 *
 * The candidates are made from the pristine copy of the name at +DNS_MAX
 * behind q, into the working copy at +0 that the question is composed from.
 * The result is cached against the pristine name, so the next lookup of it
 * is answered from the cache without searching again.
 */

/*
 * Write the candidate for step into the working copy of the name, or return
 * nonzero if it doesn't fit, so it's skipped
 */

static int
lws_adns_q_search_name(lws_adns_q_t *q, int step)
{
	const char *orig = (const char *)&q[1] + DNS_MAX, *sd = q->dns->search;
	int bare = q->search_bare_first ? 0 : (int)q->dns->search_count, n;
	char *w = (char *)&q[1];
	size_t ol = strlen(orig), sl;

	if (step == bare) {
		memcpy(w, orig, ol + 1);

		return 0;
	}

	n = q->search_bare_first ? step - 1 : step;
	while (n--)
		sd += strlen(sd) + 1;

	sl = strlen(sd);
	if (ol + 1 + sl >= DNS_MAX)
		return 1;

	memcpy(w, orig, ol);
	w[ol] = '.';
	memcpy(w + ol + 1, sd, sl + 1);

	return 0;
}

void
lws_adns_q_search_start(lws_adns_q_t *q)
{
	const char *orig = (const char *)&q[1] + DNS_MAX;
	size_t ol = strlen(orig), n;
	int dots = 0;

	q->search_steps = 0;
	q->search_step = 0;

	if (!q->dns->search_count || !ol || orig[ol - 1] == '.')
		return;

	for (n = 0; n < ol; n++)
		dots += orig[n] == '.';

	q->search_bare_first = dots >= q->dns->ndots;
	q->search_steps = (uint8_t)(q->dns->search_count + 1);

	/* the first candidate that fits */
	while (q->search_step < q->search_steps &&
	       lws_adns_q_search_name(q, q->search_step))
		q->search_step++;

	if (q->search_step >= q->search_steps) {
		/* none did, ask as given */
		q->search_steps = 0;
		memcpy((char *)&q[1], orig, ol + 1);

		return;
	}

	lwsl_cx_info(q->context, "%s: searching, asking about %s", orig,
		     (const char *)&q[1]);
}

/*
 * The candidate we asked about doesn't exist: ask about the next one.
 * Returns 0 if the query was restarted for it, 1 if there are no more and
 * the answer we have is the one that stands, or -1 if the query can't be
 * restarted and must be failed.
 */

int
lws_adns_q_search_next(lws_adns_q_t *q)
{
	if (!q->search_steps)
		return 1;

	do {
		q->search_step++;
		if (q->search_step >= q->search_steps) {
			q->search_steps = 0;

			return 1;
		}
	} while (lws_adns_q_search_name(q, q->search_step));

	if (lws_adns_q_restart(q))
		return -1;

	lwsl_cx_info(q->context, "%s: searching, now asking about %s",
		     (const char *)&q[1] + DNS_MAX, (const char *)&q[1]);

	return 0;
}

static lws_async_dns_retcode_t
__lws_async_dns_query(struct lws_context *context, int tsi, const char *name,
		      adns_query_type_t qtype, lws_async_dns_cb_t cb,
		      struct lws *wsi, void *opaque, struct lws_adns_q **pq)
{
	lws_async_dns_t *dns = &context->async_dns;
	lws_async_dns_server_t *dsrv;
	size_t nlen = strlen(name);
	lws_sockaddr46 *sa46;
	lws_adns_cache_t *c;
	struct addrinfo *ai, *ai_prev = NULL;
	struct temp_q tmq;
	lws_adns_q_t *q;
	/* room for several hosts-file / numeric matches, 16B each */
	uint8_t ads[LWS_ADNS_HOSTS_MAX_MATCHES * 16];
	uint8_t ads_lens[LWS_ADNS_HOSTS_MAX_MATCHES];
	int matches = 0;
	char *p;
	int m = 0;
	uint8_t want_dnssec = (qtype & LWS_ADNS_WANT_DNSSEC) ? 1 : 0;
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	/* the same decision lws_adns_q_validates() makes for a new query */
	int validates = (dns->dnssec_mode == LWS_ADNS_DNSSEC_REQUIRE ||
			 want_dnssec) &&
			!(qtype & LWS_ADNS_INDICATE_LACKS_DNSSEC);
#endif

	qtype = (adns_query_type_t)(qtype & ~(uint32_t)LWS_ADNS_WANT_DNSSEC);

	lwsl_cx_info(context, "entry %s", name);
	lws_adns_dump(dns);

#if !defined(LWS_WITH_IPV6)
	if (qtype == LWS_ADNS_RECORD_AAAA) {
		lwsl_cx_err(context, "ipv6 not enabled");
		goto failed;
	}
#endif

	if (nlen >= DNS_MAX - 1)
		goto failed;

	if (wsi) {
		if (!lws_dll2_is_detached(&wsi->io->adns)) {
			lwsl_cx_err(context, "%s already bound to query %p",
					lws_wsi_tag(wsi), lws_dll2_owner(&wsi->io->adns));
			goto failed;
		}
		wsi->io->adns_cb = cb;
	}

	/*
	 * There's a done, cached query we can just reuse?
	 *
	 * A query that has to validate can't be served what some query that
	 * didn't validate left in the cache: those records were handed out as
	 * plain FOUND, which a requester not looking for LWS_ADNS_DNSSEC_VALID
	 * takes as good.
	 */

	c = (qtype & LWS_ADNS_NOCACHE) ? NULL :
		lws_adns_get_cache(dns, name, (uint16_t)(qtype & 0xffff),
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
				   validates
#else
				   0
#endif
				   );
	qtype = (adns_query_type_t)(qtype & ~(uint32_t)LWS_ADNS_NOCACHE);

	if (c) {
		lwsl_cx_info(context, "%s: using cached, c->results %p, c->rr_results %p",
			  name, c->results, c->rr_results);
		m = (c->results || c->rr_results) ? LADNS_RET_FOUND :
		    (c->nxdomain ? LADNS_RET_NXDOMAIN : LADNS_RET_FAILED);
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
		/*
		 * Served from the cache, a validated result is still validated:
		 * without this, the second requester of a name within its TTL
		 * never saw LWS_ADNS_DNSSEC_VALID and, failing closed, refused
		 * what the first one had accepted
		 */
		if (m == LADNS_RET_FOUND && c->dnssec_valid)
			m |= LWS_ADNS_DNSSEC_VALID;
#endif
		/*
		 * The callback gets c->results and releases it with
		 * lws_async_dns_freeaddrinfo(); with only rr_results it gets
		 * NULL and has nothing to release, so taking a reference for
		 * that case pinned the entry for ever and, once it reached the
		 * LRU tail, stopped the cache trim freeing anything at all.
		 */
		if (c->results)
			c->refcount++;

#if defined(LWS_WITH_SYS_METRICS)
		lws_metric_event(context->mt_adns_cache,  METRES_GO, 0);
#endif

		if (cb(wsi, name, c->results, m, opaque) == NULL)
			return LADNS_RET_FAILED_WSI_CLOSED;

		return m;
	} else
		lwsl_cx_info(context, "%s uncached", name);

#if defined(LWS_WITH_SYS_METRICS)
	lws_metric_event(context->mt_adns_cache, METRES_NOGO, 0);
#endif

	/*
	 * It's a 1.2.3.4 or ::1 type IP address already?  We don't need a dns
	 * server set up to be able to create an addrinfo result for that.
	 *
	 * Create it as a cached object so it follows the refcount lifecycle
	 * of any other result
	 */

	if ((qtype & 0xff) == LWS_ADNS_RECORD_A || (qtype & 0xff) == LWS_ADNS_RECORD_AAAA) {
		m = lws_parse_numeric_address(name, ads, 16);
		if (m < 0 && lws_host_is_ambiguous_numeric(name)) {
			/*
			 * Eg, "012.0.0.1": libc would make 10.0.0.1 of it,
			 * the nameserver something else again; it is not a
			 * name or an address we can agree with anyone about
			 */
			lwsl_cx_notice(context, "ambiguous numeric host");
			goto failed;
		}
#if !defined(LWS_WITH_IPV6)
		if (m == 16) {
			/*
			 * It's a valid ipv6 literal, but this build has no
			 * ipv6... we cannot make a usable addrinfo for it and
			 * the synthesis below would emit a zeroed one, with
			 * ai_family 0 and ai_addr NULL, as a successful
			 * result.  Fail the lookup instead.
			 */
			lwsl_cx_notice(context, "ipv6 literal in ipv4-only build");
			goto failed;
		}
#endif
		if (m == 4
#if defined(LWS_WITH_IPV6)
		    || m == 16
#endif
		) {
			ads_lens[0] = (uint8_t)m;
			matches = 1;
		}

#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_PLAT_FREERTOS)
		if (!matches && !(qtype & LWS_ADNS_IGNORE_HOSTS_FILE))
			/*
			 * Not directly numeric and not explicitly bypassing...
			 * look through /etc/hosts
			 */
			matches = lws_adns_scan_hostsfile(name, ads, ads_lens,
					LWS_ADNS_HOSTS_MAX_MATCHES, qtype & 0xff);
#endif

		/*
		 * "localhost" and any name under it (RFC 6761 6.3).  Like the
		 * hosts file scan and a nameserver, an A query is answered
		 * with both families: a hosts file without localhost, as
		 * Windows' is by default, must not leave a client asking for
		 * it unable to reach a server only on ::1
		 */
		if (!matches && lws_host_is_localhost(name)) {
#if defined(LWS_WITH_IPV4)
			if ((qtype & 0xff) == LWS_ADNS_RECORD_A) {
				ads[0] = 127; ads[1] = 0; ads[2] = 0; ads[3] = 1;
				ads_lens[0] = 4;
				matches = 1;
			}
#endif
#if defined(LWS_WITH_IPV6)
			if ((qtype & 0xff) == LWS_ADNS_RECORD_A ||
			    (qtype & 0xff) == LWS_ADNS_RECORD_AAAA) {
				memset(ads + (size_t)matches * 16, 0, 15);
				ads[(size_t)matches * 16 + 15] = 1;
				ads_lens[matches++] = 16;
			}
#endif
		}
	}

	if (matches) {
		lws_async_dns_trim_cache(dns);

		/* compose an addrinfo chain with one node per match */

		c = lws_zalloc(sizeof(lws_adns_cache_t) +
			       (size_t)matches * adns_align_len(
					sizeof(struct addrinfo) +
					sizeof(lws_sockaddr46)) +
			       nlen + 1, "adns-numip");
		if (!c)
			goto failed;

		c->cx = context;
		c->results = (struct addrinfo *)&c[1];
		ai = c->results;
		for (m = 0; m < matches; m++) {
			sa46 = (lws_sockaddr46 *)&ai[1];

			if (m)
				ai_prev->ai_next = ai;
			ai->ai_socktype = SOCK_STREAM;
			if (!m) {
				char *nm = (char *)c->results +
					  (size_t)matches * adns_align_len(
						sizeof(struct addrinfo) +
						sizeof(lws_sockaddr46));
				memcpy(nm, name, nlen + 1);
				c->name = nm;
				ai->ai_canonname = nm;
			}

			if (ads_lens[m] == 4) {
				ai->ai_family = sa46->sa4.sin_family = AF_INET;
				ai->ai_addrlen = sizeof(sa46->sa4);
				ai->ai_addr = (struct sockaddr *)&sa46->sa4;
				memcpy(&sa46->sa4.sin_addr,
				       ads + (size_t)m * 16, 4);
			}
#if defined(LWS_WITH_IPV6)
			else {
				ai->ai_family = sa46->sa6.sin6_family = AF_INET6;
				ai->ai_addrlen = sizeof(sa46->sa6);
				ai->ai_addr = (struct sockaddr *)&sa46->sa6;
				memcpy(&sa46->sa6.sin6_addr,
				       ads + (size_t)m * 16, 16);
			}
#endif

			ai_prev = ai;
			ai = (struct addrinfo *)adns_align_ptr(&sa46[1]);
		}

		memset(&tmq.tq, 0, sizeof(tmq.tq));
		tmq.tq.opaque = opaque;
		if (wsi) {
			wsi->io->adns_cb = cb;
			lws_dll2_add_head(&wsi->io->adns, &tmq.tq.wsi_adns);
		} else
			tmq.tq.standalone_cb = cb;
		lws_strncpy(tmq.name, name, DNS_MAX);
		lws_strncpy(tmq.name + DNS_MAX, name, DNS_MAX);

		lws_dll2_add_head(&c->list, &dns->cached);
		lws_sul_schedule(context, 0, &c->sul, sul_cb_expire,
				 3600ll * LWS_US_PER_SEC);

		lws_adns_dump(dns);

		return lws_async_dns_complete(&tmq.tq, c);
	}

	/*
	 * A name under "localhost" that we could not answer above, eg, a
	 * record type other than A or AAAA, is still never asked of a
	 * nameserver (RFC 6761 6.3)
	 */

	if (lws_host_is_localhost(name)) {
		lwsl_cx_info(context, "no %d record for loopback %s",
			     qtype & 0xff, name);
		goto failed;
	}

	/*
	 * to try anything else we need a remote server configured...
	 */

	if (!lws_dll2_get_head(&context->async_dns.nameservers) &&
	    lws_async_dns_init(context)) {
		lwsl_cx_notice(context, "init failed");
		goto failed;
	}

	/*
	 * There's an ongoing query we can share the result of?
	 *
	 * Only a wsi requester can ride on one: q holds exactly one
	 * standalone_cb / opaque pair and it is already taken by whoever
	 * created it.  Riding anyway used to drop a standalone caller's cb and
	 * opaque on the floor, so it never heard back and, for the DNSSEC
	 * DNSKEY sub-lookup, leaked its validation context.  A standalone
	 * requester gets a separate query with its own tid instead.
	 *
	 * Like the cache above, a requester that has to validate can't be
	 * served by a query that doesn't, eg, one made with
	 * LWS_ADNS_INDICATE_LACKS_DNSSEC: it would be handed the unvalidated
	 * answer as plain FOUND, which the connect path takes as good.
	 */

	q = lws_adns_get_query(dns, qtype, 0, name, tsi);
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if (q && validates && !lws_adns_q_validates(q))
		q = NULL;
#endif
	if (q && wsi) {
		lwsl_cx_debug(context, "dns piggybacking: %d:%s",
				qtype, name);
		lws_dll2_add_head(&wsi->io->adns, &q->wsi_adns);

		return LADNS_RET_CONTINUING;
	}

	/*
	 * Two DNS_MAX regions behind q: the working copy of the name at +0,
	 * which lws_adns_iterate() may overwrite with a CNAME target of up to
	 * DNS_MAX - 1 chars, and the pristine copy of the original name at
	 * +DNS_MAX, which is what we create the cache entry against.  Sizing
	 * the first one on the original name's length instead let a long
	 * CNAME target run off the end of the allocation.
	 */

	q = lws_zalloc(sizeof(*q) + (DNS_MAX * 2), "adns-q");
	if (!q) {
		lwsl_cx_err(context, "OOM");
		goto failed;
	}

	if (wsi)
		lws_dll2_add_head(&wsi->io->adns, &q->wsi_adns);

	q->qtype = (uint16_t)qtype;
	q->want_dnssec = want_dnssec != 0;
	if (wsi && wsi->a.vhost) {
		/*
		 * Don't ask for address families the wsi's vhost / context
		 * disallows (runtime LWS_SERVER_OPTION_DISABLE_IPV[46], eg,
		 * from the -4 / -6 commandline switches).  In an IPv6-only
		 * build A results are normalized to v4-mapped and remain
		 * usable, so those always keep asking for both.
		 */
#if defined(LWS_WITH_IPV6)
		if (!LWS_IPV6_ENABLED(wsi->a.vhost))
			q->ipv4_only = 1;
#endif
#if defined(LWS_WITH_IPV4) && defined(LWS_WITH_IPV6)
		if (!LWS_IPV4_ENABLED(wsi->a.vhost))
			q->ipv6_only = 1;
#endif
	}
	if (qtype & LWS_ADNS_SYNTHETIC)
		q->is_synthetic = 1;
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if (qtype & LWS_ADNS_INDICATE_LACKS_DNSSEC)
		q->lacks_dnssec = 1;
#endif

	q->context = context;
	q->tsi = (uint8_t)tsi;
	q->opaque = opaque;
	q->dns = dns;

	/* Evaluate the optimal server */
	{
		lws_async_dns_server_t *best_dsrv = NULL;
		uint64_t best_rtt = ~(uint64_t)0;
		int all_failed = 1;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->nameservers)) {
			lws_async_dns_server_t *s = lws_container_of(d, lws_async_dns_server_t, list);
			uint64_t v = lws_adapt_get_val(s->adapt, 0, 1);
			/* 10 seconds means virtually down or unknown */
			if (!v || v > 10000000) {
				q->broadsiding = 1;
			} else {
				all_failed = 0;
			}
			if (v && v < best_rtt) {
				best_rtt = v;
				best_dsrv = s;
			}
		} lws_end_foreach_dll_safe(d, d1);

		if (lws_dll2_count(&dns->nameservers) && all_failed &&
		    !dns->in_parse) {
			if (lws_now_usecs() - dns->time_last_reload > 5000000) {
				lwsl_cx_notice(context, "Async DNS fallback reload triggered");
				lws_async_dns_server_reload(context);
				dns->time_last_reload = lws_now_usecs();
			}
		}

		if (q->broadsiding)
			/* Just peg it to the first for tracking purposes, but it will be skipped visually */
			dsrv = lws_container_of(lws_dll2_get_head(
				&context->async_dns.nameservers), lws_async_dns_server_t, list);
		else if (best_dsrv)
			/* Pick servers near the 'best' round-robin style maybe, or just pick the best. For simplicity: best one */
			dsrv = best_dsrv;
		else
			dsrv = lws_container_of(lws_dll2_get_head(
				&context->async_dns.nameservers), lws_async_dns_server_t, list);


		q->dsrv = dsrv;
	}

	/*
	 * If we can't get a socket to the chosen DNS server (eg, it could not
	 * be created, as happens in an IPv6-only build where the only
	 * nameserver was discovered as an IPv4 literal that maps to an
	 * unreachable ::ffff: address, or we are out of fds and have no socket
	 * to it we can share), we cannot actually issue the query.  Fail it
	 * cleanly.
	 */
	if (!dsrv || lws_adns_q_socks_bind(q)) {
		lwsl_cx_notice(context, "no socket to ask a nameserver from");
		goto failed_unpublished_q;
	}

	q->issue_time = lws_now_usecs();

	if (lws_async_dns_get_new_tid(context, q)) {
		lwsl_cx_err(context, "tid fail");
		goto failed_unpublished_q;
	}

	if (pq)
		*pq = q;

	if (!wsi)
		q->standalone_cb = cb;

	/* schedule a retry according to the retry policy on the wsi */
	if (lws_adns_q_retry_schedule(q, lws_adns_q_wsi(q)))
		goto failed_unpublished_q;

	/* fail us if we can't write by this timeout */
	lws_adns_q_sul_schedule(q, &q->write_sul, sul_cb_write,
				LWS_US_PER_SEC);

	/* ... and fail us if the whole query isn't done by this one */
	lws_adns_q_sul_schedule(q, &q->deadline_sul,
				lws_async_dns_sul_cb_deadline,
				DNS_QUERY_TIMEOUT * LWS_US_PER_SEC);

	/*
	 * We may rewrite the copy at +sizeof(*q) for CNAME recursion.  Keep
	 * a second copy at + sizeof(*q) + DNS_MAX so we can create the cache
	 * entry for the original name, not the last CNAME we met.
	 */

	p = (char *)&q[1];
	while (nlen--) {
		*p++ = (char)tolower((uint8_t)*name++);
		p[DNS_MAX - 1] = p[-1];
	}
	*p = '\0';
	p[DNS_MAX] = '\0';

	/* ... which may make the working copy the first search candidate */
	lws_adns_q_search_start(q);

	lws_callback_on_writable(lws_adns_q_wsi(q));

	lws_dll2_add_head(&q->list, &dns->waiting);

	lws_metrics_caliper_bind(q->metcal, context->mt_conn_dns);
	q->go_nogo = METRES_NOGO;
	/* caliper is reported in lws_adns_q_destroy */

	lwsl_cx_info(context, "created new query: %s", name);
	lws_adns_dump(dns);

	return LADNS_RET_CONTINUING;

failed_unpublished_q:
	/*
	 * We are failing after q was allocated, but before it was published on
	 * dns->waiting and before its metrics caliper was bound... so nothing
	 * will ever find it again to destroy it.  The failed: path below only
	 * does the user callback, so we have to take q down by hand here:
	 * otherwise q leaks and, worse, the requester wsi stays linked into the
	 * orphaned q->wsi_adns owner and can never issue another DNS query for
	 * the rest of its life (it trips the "already bound" check above).
	 */
	if (wsi)
		lws_dll2_remove(&wsi->io->adns);
	lws_adns_q_sul_cancel(q, &q->sul);
	lws_adns_q_sul_cancel(q, &q->write_sul);
	lws_adns_q_sul_cancel(q, &q->deadline_sul);
	lws_adns_q_socks_release(q);
	if (pq)
		*pq = NULL;
	lws_free(q);

failed:
	lwsl_cx_notice(context, "failed");
	if (!cb(wsi, NULL, NULL, LADNS_RET_FAILED, opaque))
		return LADNS_RET_FAILED_WSI_CLOSED;

	return LADNS_RET_FAILED;
}

lws_async_dns_retcode_t
lws_async_dns_query(struct lws_context *context, int tsi, const char *name,
		    adns_query_type_t qtype, lws_async_dns_cb_t cb,
		    struct lws *wsi, void *opaque, struct lws_adns_q **pq)
{
	lws_async_dns_retcode_t r;

	/* a connection's lookup belongs to, and calls back on, its thread */
	if (wsi)
		tsi = wsi->tsi;

	if (tsi < 0 || tsi >= context->count_threads)
		tsi = 0;

	lws_context_lock(context, __func__); /* ------------------- cx { */
	r = __lws_async_dns_query(context, tsi, name, qtype, cb, wsi, opaque,
				  pq);
	lws_context_unlock(context); /* } cx */

	return r;
}

int
lws_async_dns_create_tcp_wsi(lws_adns_q_t *q)
{
#if defined(LWS_WITH_CLIENT)
	struct lws_client_connect_info i;
	char ads[48];

	if (q->wsi_tcp)
		return 0;

	memset(&i, 0, sizeof(i));
	i.context = q->context;
	i.vhost = q->context->vhost_system;

	lws_sa46_write_numeric_address(&q->dsrv->sa46, ads, sizeof(ads));
	i.address = ads;
	i.port = lws_adns_ns_port();
	i.ssl_connection = 0;
	i.method = "RAW";
	i.local_protocol_name = lws_async_dns_protocol.name;
	i.opaque_user_data = q;

	q->is_tcp = 1;
	q->has_tcp_len = 0;
	q->tcp_rx_pos = 0;

	q->wsi_tcp = lws_client_connect_via_info(&i);
	if (!q->wsi_tcp) {
		lwsl_cx_err(q->context, "adns tcp connect fail");
		return 1;
	}

	return 0;
#else
	return 1;
#endif
}

void
lws_async_dns_dnssec_set_mode(struct lws_context *context,
			      lws_async_dns_dnssec_mode_t mode)
{
	/*
	 * Someone asked for some kind of DNSSEC but we don't know which: the
	 * safe reading is the one that validates
	 */
	switch (mode) {
	case LWS_ADNS_DNSSEC_OFF:
	case LWS_ADNS_DNSSEC_REQUIRE:
	case LWS_ADNS_DNSSEC_TOLERATE:
		break;
	default:
		lwsl_cx_err(context, "unknown DNSSEC mode %d, using REQUIRE",
			    (int)mode);
		mode = LWS_ADNS_DNSSEC_REQUIRE;
		break;
	}

	/* nameserver reloads keep it, see lws_async_dns_init() */
	lws_context_lock(context, __func__); /* ------------------- cx { */
	context->async_dns.dnssec_mode = (uint8_t)mode;
	lws_context_unlock(context); /* } cx */
}

#if !defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
int
lws_async_dns_dnssec_set_root_anchors(struct lws_context *context,
				      const lws_adns_ds_anchor_t *anchors,
				      size_t count)
{
	(void)context;
	(void)anchors;
	(void)count;

	return 1; /* there is no DNSSEC validation in this build */
}
#endif

static const uint8_t *
__lws_async_dns_get_rr_cache(struct lws_context *context, const char *name,
			     adns_query_type_t qtype, uint16_t *paylen)
{
	lws_adns_cache_t *c;
	lws_adns_rr_t *rr;

	/*
	 * The same records may be cached from a query that validated them and
	 * from one that didn't; a caller acting on LWS_ADNS_DNSSEC_VALID wants
	 * the ones that were validated
	 */

	c = lws_adns_get_cache(&context->async_dns, name, (uint16_t)qtype, 1);
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if (!c)
		c = lws_adns_get_cache(&context->async_dns, name,
				       (uint16_t)qtype, 0);
#endif
	if (!c)
		return NULL;

	for (rr = c->rr_results; rr; rr = rr->next)
		if (rr->type == qtype) {
			if (paylen)
				*paylen = rr->paylen;
			return (const uint8_t *)&rr[1];
		}

	return NULL;
}

const uint8_t *
lws_async_dns_get_rr_cache(struct lws_context *context, const char *name,
			   adns_query_type_t qtype, uint16_t *paylen)
{
	const uint8_t *r;

	if (!context || !name)
		return NULL;

	lws_context_lock(context, __func__); /* ------------------- cx { */
	r = __lws_async_dns_get_rr_cache(context, name, qtype, paylen);
	lws_context_unlock(context); /* } cx */

	return r;
}

static int
__lws_async_dns_get_alpn(struct lws_context *context, const char *name,
			 const char *alpn)
{
	uint16_t paylen;
	const uint8_t *rr = __lws_async_dns_get_rr_cache(context, name,
						LWS_ADNS_RECORD_HTTPS, &paylen);
	int pos = 2;
	int limit;

	if (!rr || paylen < 3)
		return 0;

	/* TargetName: sequence of labels ending in 0 */
	limit = 128;
	while (limit-- && pos < paylen && rr[pos]) {
		if (pos + rr[pos] + 1 > paylen)
			return 0;
		pos += rr[pos] + 1;
	}
	if (pos >= paylen)
		return 0;
	pos++; /* Skip the 0 length label */

	/* SvcParams */
	limit = 128;
	while (limit-- && pos + 4 <= paylen) {
		uint16_t key = (uint16_t)((rr[pos] << 8) | rr[pos + 1]);
		uint16_t len = (uint16_t)((rr[pos + 2] << 8) | rr[pos + 3]);
		pos += 4;

		if (pos + len > paylen)
			break;

		if (key == 1) { /* alpn */
			uint16_t i = 0;
			int limit2 = 128;
			while (limit2-- && i < len) {
				uint8_t slen = rr[pos + i];
				if (i + 1 + slen > len)
					break;
				if (slen == strlen(alpn) && !strncmp((const char *)&rr[pos + i + 1], alpn, strlen(alpn)))
					return 1;
				i = (uint16_t)(i + slen + 1);
			}
		}
		pos += len;
	}

	return 0;
}

int
lws_async_dns_get_alpn(struct lws_context *context, const char *name,
		       const char *alpn)
{
	int r;

	if (!context || !name || !alpn)
		return 0;

	/* the record is in the cache, which another thread may change */
	lws_context_lock(context, __func__); /* ------------------- cx { */
	r = __lws_async_dns_get_alpn(context, name, alpn);
	lws_context_unlock(context); /* } cx */

	return r;
}
