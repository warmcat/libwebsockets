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
#include "private-lib-async-dns.h"


/* updates *dest, returns chars used from ls directly, else -1 for fail */

int
lws_adns_parse_label(const uint8_t *pkt, int len, const uint8_t *ls, int budget,
		     char **dest, size_t dl)
{
	const uint8_t *e = pkt + len, *ols = ls;
	char pointer = 0;
	int n, readsize = 0, consumed = -1;
	uint8_t ll;

	if (len < DHO_SIZEOF || len > LWS_ADNS_MAX_PAYLOAD)
		return -1;

	if (budget < 1)
		return 0;

	/* caller must catch end of labels, but might have passed us root */
	if (!*ls) {
		if (dl < 2)
			return -1;
		(*dest)[0] = '.';
		(*dest)[1] = '\0';
		*dest += 1;
		return 1;
	}

again1:
	if (ls >= e)
		return -1;

	if (((*ls) & 0xc0) == 0xc0) {
		if (budget < 2)
			return -1;
		/* pointer into message pkt to name to actually use */
		n = lws_ser_ru16be(ls) & 0x3fff;
               if (n < DHO_SIZEOF || n >= len) {
			lwsl_notice("%s: illegal name pointer\n", __func__);

			return -1;
		}

		/* dereference the label pointer */

		/*
		 * If this is the first pointer we encountered, the consumption
		 * of the input from the caller's perspective ends here (plus
		 * the 2-byte pointer).
		 */
		if (consumed == -1)
			consumed = lws_ptr_diff(ls, ols) + 2;

		ls = pkt + n;

		/* are we being fuzzed or messed with? */
		if (((*ls) & 0xc0) == 0xc0) {
			/* ... pointer to pointer is unreasonable */
			lwsl_notice("%s: label ptr to ptr invalid\n", __func__);

			return -1;
		} /* loops of pointers are not allowed, but ptr->label->ptr is */
		pointer = 1;
	}

	if (ls >= e)
		return -1;

	ll = *ls++;
	if (ls + ll + 1 > e) {
		lwsl_notice("%s: label len invalid, %d vs %d\n", __func__,
			    lws_ptr_diff((ls + ll + 1), pkt), lws_ptr_diff(e, pkt));

		return -1;
	}

	/*
	 * If we are following a pointer, ls is not linearly related to ols any
	 * more.  So we can't check it against the budget from ols.
	 *
	 * We already checked that the new ls and the label length are within
	 * the packet boundaries (e).
	 */

	if (!pointer && ll > lws_ptr_diff_size_t(ls, ols) + (size_t)budget) {
		lwsl_notice("%s: label too long %d vs %d (rem budget %d)\n",
				__func__, ll, budget,
				(int)(lws_ptr_diff_size_t(ls, ols) + (size_t)budget));

		return -1;
	}

	if ((unsigned int)(ll + 2 + readsize) > dl) {
		lwsl_notice("%s: qname too large\n", __func__);

		return -1;
	}

	/* copy the label content into place */

	memcpy(*dest, ls, ll);
	(*dest)[ll] = '.';
	(*dest)[ll + 1] = '\0';
	*dest += ll + 1;
	ls += ll;
	readsize += ll + 1;

	if (pointer) {
		if (*ls)
			goto again1;

		/*
		 * special fun rule... if whole qname was a pointer label,
		 * it has no 00 terminator afterwards
		 */

		return consumed;
	}


	if (*ls)
		goto again1;

	ls++;

	/*
	 * If we didn't use a pointer, consumed is still -1, and we return
	 * the linear consumption
	 */
	return lws_ptr_diff(ls, ols);
}


/* locally query the response packet */

struct label_stack {
	char name[DNS_MAX + 10];
	int enl;
	const uint8_t *p;
};

/*
 * Walk the response packet, calling back to the user-provided callback for each
 * A (and AAAA if LWS_IPV6=1) record with a matching name found in there.
 *
 * Able to recurse using an explicit non-CPU stack to resolve CNAME usages
 *
 * Return -1: unexpectedly failed
 *         0: found
 *         1: didn't find anything matching
 */

int
lws_adns_iterate(lws_adns_q_t *q, const uint8_t *pkt, int len,
		 const char *expname, lws_async_dns_find_t cb, void *opaque)
{
	const uint8_t *e = pkt + len, *p, *pay;
	struct label_stack stack[8];
	int n = 0, stp = 0, ansc, m;
	uint16_t rrtype, rrpaylen;
	char *sp, inq;
	uint32_t ttl;

	if (len < DHO_SIZEOF || len > LWS_ADNS_MAX_PAYLOAD)
		return -1;

	lws_strncpy(stack[0].name, expname, sizeof(stack[0].name));
	stack[0].enl = (int)strlen(expname);

start:
	ansc = lws_ser_ru16be(pkt + DHO_NANSWERS) + lws_ser_ru16be(pkt + DHO_NAUTH);
	p = pkt + DHO_SIZEOF;
	inq = 1;

	/*
	 * The response also includes the query... and we have to parse it
	 * so we can understand we reached the response... there's a QNAME
	 * made up of labels and then 2 x 16-bit fields, for query type and
	 * query class
	 */


	while (p + 14 < e && (inq || ansc)) {

		if (!inq && !stp)
			ansc--;

		/*
		 * First is the name the query applies to... two main
		 * formats can appear here, one is a pointer to
		 * elsewhere in the message, the other separately
		 * provides len / data for each dotted "label", so for
		 * "warmcat.com" warmcat and com are given each with a
		 * prepended length byte.  Any of those may be a pointer
		 * to somewhere else in the packet :-/
		 *
		 * Paranoia is appropriate since the name length must be
		 * parsed out before the rest of the RR can be used and
		 * we can be attacked with absolutely any crafted
		 * content easily via UDP.
		 *
		 * So parse the name and additionally confirm it matches
		 * what the query the TID belongs to actually asked for.
		 */

		sp = stack[0].name;

		/* while we have more labels */

		n = lws_adns_parse_label(pkt, len, p, lws_ptr_diff(e, p), &sp,
					 sizeof(stack[0].name) -
					 lws_ptr_diff_size_t(sp, stack[0].name));
		if (n < 0)
			return -1;

		p += n;

		if (p + (inq ? 5 : 14) > e)
			return -1;

		/*
		 * p is now just after the decoded RR name, pointing at: type
		 *
		 * We sent class = 1 = IN query... response must match
		 */

		if (lws_ser_ru16be(&p[2]) != 1) {
			lwsl_err("%s: non-IN response 0x%x\n", __func__,
						lws_ser_ru16be(&p[2]));

			return -1;
		}

		if (inq) {
			lwsl_debug("%s: reached end of inq\n", __func__);
			inq = 0;
			p += 4;
			continue;
		}

		/* carefully validate the claimed RR payload length */

		rrpaylen = lws_ser_ru16be(&p[8]);
		if (p + 10 + rrpaylen > e) { /* it may be == e */
			lwsl_notice("%s: invalid RR data length\n", __func__);

			return -1;
		}

		ttl = lws_ser_ru32be(&p[4]);
		rrtype = lws_ser_ru16be(&p[0]);
		p += 10; /* point to the payload */
		pay = p;

		/*
		 * Compare the RR names, allowing for the decoded labelname
		 * to have an extra '.' at the end.
		 */

		n = lws_ptr_diff(sp, stack[0].name);
		if (n > 0 && stack[0].name[n - 1] == '.')
			n--;

		m = stack[stp].enl;
		if (m > 0 && stack[stp].name[m - 1] == '.')
			m--;

		if (n < 1 || n != m ||
		    strncmp(stack[0].name, stack[stp].name, (unsigned int)n)) {
			lwsl_notice("%s: skipping %s vs %s\n", __func__,
			stack[0].name, stack[stp].name);
			goto skip;
		}

		/*
		 * It's something we could be interested in...
		 *
		 * We can skip RRs we don't understand.  But we need to deal
		 * with at least these and their payloads:
		 *
		 *    A:      4: ipv4 address
		 *    AAAA:  16: ipv6 address (if asked for AAAA)
		 *    CNAME:  ?: labelized name
		 *
		 * If we hit a CNAME we need to try to dereference it with
		 * stuff that is in the same response packet and judge it
		 * from that, without losing our place here.  CNAMEs may
		 * point to CNAMEs to whatever depth we're willing to handle.
		 */

		switch (rrtype) {

		case LWS_ADNS_RECORD_AAAA:
			if (rrpaylen != 16) {
				lwsl_err("%s: unexpected rrpaylen\n", __func__);
				return -1;
			}
#if defined(LWS_WITH_IPV6)
			goto do_cb;
#else
			break;
#endif

		case LWS_ADNS_RECORD_A:
			if (rrpaylen != 4) {
				lwsl_err("%s: unexpected rrpaylen4\n", __func__);

				return -1;
			}
#if defined(LWS_WITH_IPV6)
do_cb:
#endif
			cb(stack[0].name, opaque, ttl, rrtype, rrpaylen, p);
			break;

		case LWS_ADNS_RECORD_CNAME:
			if (rrpaylen == 0) {
				lwsl_notice("%s: CNAME with empty RDATA, skipping\n", __func__);
				goto skip;
			}
			/*
			 * The name the CNAME refers to MAY itself be
			 * included elsewhere in the response packet.
			 *
			 * So switch tack, stack where to resume from and
			 * search for the decoded CNAME label name definition
			 * instead.
			 *
			 * First decode the CNAME label payload into the next
			 * stack level buffer for it.
			 */

			if (++stp == (int)LWS_ARRAY_SIZE(stack)) {
				lwsl_notice("%s: CNAMEs too deep\n", __func__);

				return -1;
			}
			sp = stack[stp].name;
			/* get the cname alias */
			n = lws_adns_parse_label(pkt, len, p, rrpaylen, &sp,
						 sizeof(stack[stp].name) -
						 lws_ptr_diff_size_t(sp, stack[stp].name));
			/* includes case name won't fit */
			if (n < 0)
				return -1;

			p += n;

			if (p > e)
				return -1;
#if 0
			/* it should have exactly reached rrpaylen if only one
			 * CNAME, else somewhere in the middle */

			if (p != pay + rrpaylen) {
				lwsl_err("%s: cname name bad len %d\n", __func__, rrpaylen);

				return -1;
			}
#endif
			// lwsl_notice("%s: recursing looking for %s\n", __func__, stack[stp].name);

			lwsl_info("%s: recursing looking for %s\n", __func__,
					stack[stp].name);

			stack[stp].enl = lws_ptr_diff(sp, stack[stp].name);
			/* when we unstack, resume from here */
			stack[stp].p = pay + rrpaylen;
			goto start;

		case LWS_ADNS_RECORD_RRSIG:
		case LWS_ADNS_RECORD_DNSKEY:
		case LWS_ADNS_RECORD_DS:
		case LWS_ADNS_RECORD_NSEC:
		case LWS_ADNS_RECORD_NSEC3:
		case LWS_ADNS_RECORD_SOA:
			/* We pass these DNSSEC-related records to the callback so
			 * it can store/evaluate them.
			 */
			// lwsl_notice("lws_adns_iterate: Calling CB for DNSSEC RR %d (len %d)\n", rrtype, rrpaylen);
			cb(stack[0].name, opaque, ttl, rrtype, rrpaylen, p);
			break;

		default:
			lwsl_notice("lws_adns_iterate: IGNORING UNKNOWN RR %d\n", rrtype);
			break;
		}

skip:
		p += rrpaylen;
	}

	if (!stp)
		return 1; /* we didn't find anything, but we didn't error */

	lwsl_info("%s: '%s' -> CNAME '%s' resolution not provided, recursing\n",
			__func__, ((const char *)&q[1]) + DNS_MAX,
			stack[stp].name);

	/*
	 * This implies there wasn't any usable definition for the
	 * CNAME in the end, eg, only AAAA when we needed an A.
	 *
	 * It's also legit if the DNS just returns the CNAME, and that server
	 * did not directly know the next step in resolution of the CNAME, so
	 * instead of putting the resolution elsewhere in the response, has
	 * told us just the CNAME and left it to us to find out its resolution
	 * separately.
	 *
	 * Reset this request to be for the CNAME, and restart the request
	 * action with a new tid.
	 */

	if (lws_async_dns_get_new_tid(q->context, q))
		return -1;

	LADNS_MOST_RECENT_TID(q) &= 0xfffe;
	q->asked = q->responded = 0;
#if defined(LWS_WITH_IPV6)
	q->sent[1] = 0;
#endif
	q->sent[0] = 0;
	q->is_synthetic = 0;
	q->recursion++;
	if (q->recursion == DNS_RECURSION_LIMIT) {
		lwsl_err("%s: recursion overflow\n", __func__);

		return -1;
	}

	if (q->firstcache)
		lws_adns_cache_destroy(q->firstcache);
	q->firstcache = NULL;

	/* overwrite the query name with the CNAME */

	n = 0;
	{
		char *cp = (char *)&q[1];

		while (stack[stp].name[n])
			*cp++ = (char)tolower(stack[stp].name[n++]);
		/* trim the following . if any */
		if (n && cp[-1] == '.')
			cp--;
		*cp = '\0';
	}

	if (q->dsrv && q->dsrv->wsi)
		lws_callback_on_writable(q->dsrv->wsi);

	return 2;
}

int
lws_async_dns_estimate(const char *name, void *opaque, uint32_t ttl,
			adns_query_type_t type, uint16_t rrpaylen, const uint8_t *payload)
{
	size_t *est = (size_t *)opaque, my;

	my = sizeof(struct addrinfo);
	if (type == LWS_ADNS_RECORD_AAAA)
		my += sizeof(struct sockaddr_in6);
	else
		my += sizeof(struct sockaddr_in);

	/* DNSSEC records don't produce addrinfos, but need storage if we cache them
	 * or pass them inside lws. Often we just evaluate them inline. But if
	 * we need to stash them, we should do so.
	 */
	if (type == LWS_ADNS_RECORD_DNSKEY || type == LWS_ADNS_RECORD_RRSIG ||
	    type == LWS_ADNS_RECORD_DS || type == LWS_ADNS_RECORD_NSEC ||
	    type == LWS_ADNS_RECORD_NSEC3 || type == LWS_ADNS_RECORD_SOA) {
		/* We'll stash them as lws_adns_rr_t directly after the A records */
		my += sizeof(lws_adns_rr_t) + rrpaylen;
	}

	*est += my;

	return 0;
}

struct adstore {
	const char *name;
	struct addrinfo *pos;
	struct addrinfo *prev;
	lws_adns_rr_t *rr_first;
	lws_adns_rr_t *rr_pos;
	int ctr;
	uint32_t smallest_ttl;
	uint8_t flags;
};

/*
 * Callback for each A or AAAA record, creating getaddrinfo-compatible results
 * into the preallocated exact-sized storage.
 */
int
lws_async_dns_store(const char *name, void *opaque, uint32_t ttl,
		    adns_query_type_t type, uint16_t rrpaylen,
		    const uint8_t *payload)
{
	struct adstore *adst = (struct adstore *)opaque;
#if defined(_DEBUG)
	char buf[48];
#endif
	size_t i;

	/*
	 * DNSSEC records do not produce IPv4/IPv6 address entries.
	 * We stash them into lws_adns_rr_t linked list.
	 */
	if (type == LWS_ADNS_RECORD_RRSIG || type == LWS_ADNS_RECORD_DNSKEY ||
	    type == LWS_ADNS_RECORD_DS || type == LWS_ADNS_RECORD_NSEC ||
	    type == LWS_ADNS_RECORD_NSEC3 || type == LWS_ADNS_RECORD_SOA) {
		lws_adns_rr_t *rr = (lws_adns_rr_t *)adst->pos;

		rr->next = NULL;
		rr->type = type;
		rr->paylen = rrpaylen;
		memcpy(&rr[1], payload, rrpaylen);

		if (!adst->rr_first)
			adst->rr_first = rr;
		else
			adst->rr_pos->next = rr;
		adst->rr_pos = rr;

		/* Advance the generic allocation pointer for the next item */
		adst->pos = (struct addrinfo *)((uint8_t *)adst->pos +
					sizeof(lws_adns_rr_t) + rrpaylen);
		return 0;
	}

	if (ttl < adst->smallest_ttl || !adst->ctr)
		adst->smallest_ttl = ttl;

	if (adst->prev)
		adst->prev->ai_next = adst->pos;
	adst->prev = adst->pos;

	adst->pos->ai_flags = 0;
	adst->pos->ai_family = type == LWS_ADNS_RECORD_AAAA ?
						AF_INET6 : AF_INET;
	adst->pos->ai_socktype = SOCK_STREAM;
	adst->pos->ai_protocol = IPPROTO_UDP; /* no meaning */
	adst->pos->ai_addrlen = type == LWS_ADNS_RECORD_AAAA ?
						sizeof(struct sockaddr_in6) :
						sizeof(struct sockaddr_in);
	adst->pos->ai_canonname = (char *)adst->name;
	adst->pos->ai_addr = (struct sockaddr *)&adst->pos[1];
	adst->pos->ai_next = NULL;

#if defined(LWS_WITH_IPV6)
	if (type == LWS_ADNS_RECORD_AAAA) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&adst->pos[1];

		i = sizeof(*in6);
		memset(in6, 0, i);
		in6->sin6_family = (sa_family_t)adst->pos->ai_family;
		memcpy(in6->sin6_addr.s6_addr, payload, 16);
		adst->flags |= 2;
	} else
#endif
	{
		struct sockaddr_in *in = (struct sockaddr_in *)&adst->pos[1];

		i = sizeof(*in);
		memset(in, 0, i);
		in->sin_family = (sa_family_t)adst->pos->ai_family;
		memcpy(&in->sin_addr.s_addr, payload, 4);
		adst->flags |= 1;
	}

	adst->pos = (struct addrinfo *)((uint8_t *)adst->pos +
					sizeof(struct addrinfo) + i);

#if defined(_DEBUG)
	if (lws_write_numeric_address(payload,
				type == LWS_ADNS_RECORD_AAAA ? 16 : 4,
							buf, sizeof(buf)) > 0)
		lwsl_info("%s: %d: %s: %s\n", __func__, adst->ctr,
				adst->name, buf);
#endif
	adst->ctr++;

	return 0;
}

/*
 * We want to parse out all A or AAAA records
 */

void
lws_adns_parse_udp(lws_async_dns_t *dns, const uint8_t *pkt, size_t len,
		   lws_async_dns_server_t *dsrv)
{
	const char *nm, *nmcname;
	lws_adns_cache_t *c;
	struct adstore adst;
	lws_adns_q_t *q;
	int n;
	size_t est;

	// lwsl_hexdump_notice(pkt, len);

	/* we have to at least have the header */

	if (len < DHO_SIZEOF || len > LWS_ADNS_MAX_PAYLOAD)
		return;

	/* we asked with one query, so anything else is bogus */

	if (lws_ser_ru16be(pkt + DHO_NQUERIES) != 1)
		return;

	/* match both A and AAAA queries if any */

	q = lws_adns_get_query(dns, 0, lws_ser_ru16be(pkt + DHO_TID), NULL);
	if (!q) {
		lwsl_info("%s: dropping unknown query tid 0x%x\n",
			    __func__, lws_ser_ru16be(pkt + DHO_TID));

		return;
	}

#if 0
	{
		int rcode = lws_ser_ru16be(pkt + DHO_FLAGS) & 0x0F;
		lwsl_notice("%s: Received DNS response for %s, RCODE=%d, ANSWERS=%d\n",
			__func__, ((const char *)&q[1]) + DNS_MAX, rcode, lws_ser_ru16be(pkt + DHO_NANSWERS));
	}
#endif

	/*
	 * we may have recursed and the packet we just got started earlier than
	 * the current TID we are working with... if so, ignore it
	 */

	if ((lws_ser_ru16be(pkt + DHO_TID) & 0xfffe) !=
			(LADNS_MOST_RECENT_TID(q) & 0xfffe))
		return;

	if (q->qtype == LWS_ADNS_RECORD_A || q->qtype == LWS_ADNS_RECORD_AAAA)
		n = 1 << (lws_ser_ru16be(pkt + DHO_TID) & 1);
	else
		n = 1;

	if (q->responded & n) {
		lwsl_notice("%s: dup\n", __func__);
		return;
	}

	if (dsrv && q->broadsiding && q->issue_time) {
		/* Record response time for the server that won the race! */
		lws_adapt_report_val(dsrv->adapt, (uint64_t)(lws_now_usecs() - q->issue_time), lws_now_usecs());
	} else if (q->dsrv && q->issue_time) {
		/* Record response time for the pre-selected server */
		lws_adapt_report_val(q->dsrv->adapt, (uint64_t)(lws_now_usecs() - q->issue_time), lws_now_usecs());
	}

	q->responded = (uint8_t)(q->responded | n);

	/* did we get truncated? */
	if ((lws_ser_ru16be(pkt + DHO_FLAGS) & 0x0200) && !q->is_tcp) {
		lwsl_notice("%s: ADNS truncated, falling back to TCP for %s\n",
			    __func__, ((const char *)&q[1]) + DNS_MAX);

		q->responded = (uint8_t)(q->responded & ~n);
		q->asked = 0;
		q->sent[0] = 0;
#if defined(LWS_WITH_IPV6)
		q->sent[1] = 0;
#endif
		if (lws_async_dns_create_tcp_wsi(q)) {
			q->go_nogo = METRES_NOGO;
			goto fail_out;
		}

		return;
	}

	/* we want to confirm the results against what we last requested... */

	nmcname = ((const char *)&q[1]);

	/*
	 * First walk the packet figuring out the allocation needed for all
	 * the results.  Produce the following layout at c
	 *
	 *  lws_adns_cache_t: new cache object
	 *  [struct addrinfo + struct sockaddr_in or _in6]: for each A or AAAA
	 *  char []: copy of resolved name
	 */

	/* but we want to create the cache entry against the original request */

	nm = ((const char *)&q[1]) + DNS_MAX;
	n = (int)strlen(nm) + 1;

	est = sizeof(lws_adns_cache_t) + (unsigned int)n;
	if (lws_ser_ru16be(pkt + DHO_NANSWERS) || lws_ser_ru16be(pkt + DHO_NAUTH)) {
		int ir = lws_adns_iterate(q, pkt, (int)len, nmcname,
					  lws_async_dns_estimate, &est);
		if (ir < 0)
			goto fail_out;

		if (ir == 2) /* CNAME recursive resolution */
			return;
	}

	lwsl_info("%s: create cache entry for %s, %zu\n", __func__, nm,
			est - sizeof(lws_adns_cache_t));
	c = lws_malloc(est + 1, "async-dns-entry");
	if (!c) {
		lwsl_err("%s: OOM %zu\n", __func__, est);
		goto fail_out;
	}
	memset(c, 0, sizeof(*c));

	/* place it at end, no need to care about alignment padding */
	c->name = adst.name = ((const char *)c) + est - n;
	memcpy((char *)c->name, nm, (unsigned int)n);

	/*
	 * Then walk the packet again, placing the objects we accounted for
	 * the first time into the result allocation after the cache object
	 * and copy of the name
	 */

	adst.pos = (struct addrinfo *)&c[1];
	adst.prev = NULL;
	adst.rr_first = NULL;
	adst.rr_pos = NULL;
	adst.ctr = 0;
	adst.smallest_ttl = 3600;
	adst.flags = 0;

	/*
	 * smallest_ttl applies as it is to empty results (NXDOMAIN), or is
	 * set to the minimum ttl seen in all the results.
	 */

	if ((lws_ser_ru16be(pkt + DHO_NANSWERS) || lws_ser_ru16be(pkt + DHO_NAUTH)) &&
	    lws_adns_iterate(q, pkt, (int)len, nmcname, lws_async_dns_store, &adst) < 0) {
		lws_free(c);
		goto fail_out;
	}

	if (lws_ser_ru16be(pkt + DHO_NANSWERS) || lws_ser_ru16be(pkt + DHO_NAUTH)) {
		c->results = adst.ctr ? (struct addrinfo *)&c[1] : NULL;
		c->rr_results = adst.rr_first;

		if (q->last && c->results) /* chain the second one on */
			*q->last = c->results;
		else if (c->results) /* first one had no results, set first guy's c->results */
			if (q->firstcache)
				q->firstcache->results = c->results;
	}

	if (adst.prev) /* so we know where to continue the addrinfo list */
		/* can be NULL if first resp empty */
		q->last = &adst.prev->ai_next;

	if (q->firstcache) { /* also need to free chain when we free this guy */
		q->firstcache->chain = c;
		c->firstcache = q->firstcache;
	} else {

		q->firstcache = c;
		c->refcount++;
		c->incomplete = !q->responded;// != q->asked;

		/*
		 * Only register the first one into the cache...
		 * Trim the oldest cache entry if necessary
		 */

		lws_async_dns_trim_cache(dns);

		/*
		 * cache the first results object... if a second one comes,
		 * we won't directly register it but will chain it on to this
		 * first one and continue to addinfo ai_next linked list from
		 * the first into the second
		 */

		c->flags = adst.flags;
		lws_dll2_add_head(&c->list, &dns->cached);
		lwsl_notice("%s: added %s to cache, rr_results = %p, ttl = %u\n", __func__, c->name, c->rr_results, adst.smallest_ttl);
		lws_sul_schedule(q->context, 0, &c->sul, sul_cb_expire,
				 lws_now_usecs() +
				 (adst.smallest_ttl * LWS_US_PER_SEC));
	}

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if ((q->dns->dnssec_mode == LWS_ADNS_DNSSEC_REQUIRE) && !q->lacks_dnssec) {
		if (lws_ser_ru16be(pkt + DHO_NANSWERS) > 0 || q->responded == q->asked) {
			if (!q->dnssec_valid && !q->dnssec_verify_rrsig) {
				n = lws_adns_dnssec_verify(q, pkt, len);
				if (n < 0) {
					q->go_nogo = METRES_NOGO;
					goto fail_out;
				}
				if (n == 0)
					q->dnssec_valid = 1;
			}
		}
	} else {
		q->dnssec_valid = 1;
	}
#endif

	if ((q->qtype == LWS_ADNS_RECORD_A || q->qtype == LWS_ADNS_RECORD_AAAA) &&
	    q->responded != q->asked)
		return;

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	if (q->dnssec_verify_rrsig)
		return;
	if (!q->dnssec_valid) {
		q->go_nogo = METRES_NOGO;
		goto fail_out;
	}
#endif

	/*
	 * Now we captured everything into the new object, return the
	 * addrinfo results, if any, to all interested wsi, if any...
	 */

	lwsl_notice("%s: Calling lws_async_dns_complete for %s\n", __func__, q->firstcache ? q->firstcache->name : "NULL");
	c->incomplete = 0;
	lws_async_dns_complete(q, q->firstcache);

	q->go_nogo = METRES_GO;

	/*
	 * the query is completely finished with
	 */

fail_out:
	if (q->go_nogo != METRES_GO) {
		lws_async_dns_complete(q, NULL);
		if (q->firstcache) {
			lws_adns_cache_destroy(q->firstcache);
			q->firstcache = NULL;
		}
	}
	lws_adns_q_destroy(q);
}

