/*
 * libwebsockets ACME client protocol plugin
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
 * dns-01: waiting for the authoritative servers to serve the challenge
 *
 * The ACME server looks the challenge TXT up at the domain's authoritative
 * servers, and a resolver on its way there may cache a negative answer if
 * it asks too soon.  So before we tell it to look, we ask every one of
 * those servers ourselves, directly, until they all serve the TXT.
 *
 * A name server counts as serving it when one of its addresses answers
 * with the TXT, and none of its addresses answers without it.  An address
 * that doesn't answer at all, eg, one we have no route to, says nothing.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#endif
#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>

#include "private-acme-client.h"

#if defined(LWS_WITH_SYS_ASYNC_DNS) && defined(LWS_WITH_AUTHORITATIVE_DNS)

/* does name, which may end with '.', equal want, ignoring case? */

static int
acme_dns_name_is(const char *name, const char *want)
{
	size_t nl = strlen(name), wl = strlen(want);

	if (nl && name[nl - 1] == '.')
		nl--;
	if (wl && want[wl - 1] == '.')
		wl--;

	return nl == wl && !strncasecmp(name, want, nl);
}

/* a host name we can ask for: dotted labels of letters, digits, '-' */

static int
acme_dns_host_ok(const char *h, size_t len)
{
	size_t n, lab = 0;

	if (!len || len > 253)
		return 0;

	for (n = 0; n < len; n++) {
		char c = h[n];

		if (c == '.') {
			if (!lab)
				return 0;
			lab = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_') ||
		    ++lab > 63)
			return 0;
	}

	return 1;
}

int
acme_dns_zone_ns(const char *zone, size_t len, const char *domain,
		 struct acme_dns_ns *ns, int max)
{
	struct auth_dns_zone z;
	int count = 0, n;

	memset(&z, 0, sizeof(z));
	if (lws_auth_dns_parse_zone_buf(zone, len, &z))
		return -1;

	/* the NS records of the apex */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z.rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d,
					struct auth_dns_rrset, list);

		if (rs->type != 2 /* NS */ || !rs->name ||
		    !acme_dns_name_is(rs->name, domain))
			continue;

		lws_start_foreach_dll(struct lws_dll2 *, d2,
				      lws_dll2_get_head(&rs->rr_list)) {
			struct auth_dns_rr *rr = lws_container_of(d2,
						struct auth_dns_rr, list);
			size_t l;

			if (count == max || !rr->rdata)
				continue;
			l = rr->rdata_len;
			if (l && rr->rdata[l - 1] == '.')
				l--;
			if (!acme_dns_host_ok(rr->rdata, l) ||
			    l >= sizeof(ns[0].host)) {
				lwsl_notice("%s: unusable NS in zone\n",
					    __func__);
				continue;
			}
			memset(&ns[count], 0, sizeof(ns[count]));
			memcpy(ns[count].host, rr->rdata, l);
			ns[count].host[l] = '\0';
			count++;
		} lws_end_foreach_dll(d2);
	} lws_end_foreach_dll(d);

	/* glue: addresses the zone itself gives the name servers */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z.rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d,
					struct auth_dns_rrset, list);

		if ((rs->type != 1 && rs->type != 28) || !rs->name)
			continue;

		for (n = 0; n < count; n++) {
			if (!acme_dns_name_is(rs->name, ns[n].host))
				continue;

			lws_start_foreach_dll(struct lws_dll2 *, d2,
					      lws_dll2_get_head(&rs->rr_list)) {
				struct auth_dns_rr *rr = lws_container_of(d2,
						struct auth_dns_rr, list);
				lws_sockaddr46 *sa;

				if (ns[n].glue_count ==
					(int)LWS_ARRAY_SIZE(ns[n].glue) ||
				    !rr->wire_rdata)
					continue;
				sa = &ns[n].glue[ns[n].glue_count];
				memset(sa, 0, sizeof(*sa));
				if (rs->type == 1 && rr->wire_rdata_len == 4) {
					sa->sa4.sin_family = AF_INET;
					memcpy(&sa->sa4.sin_addr,
					       rr->wire_rdata, 4);
					ns[n].glue_count++;
				}
#if defined(LWS_WITH_IPV6)
				if (rs->type == 28 && rr->wire_rdata_len == 16) {
					sa->sa6.sin6_family = AF_INET6;
					memcpy(&sa->sa6.sin6_addr,
					       rr->wire_rdata, 16);
					ns[n].glue_count++;
				}
#endif
			} lws_end_foreach_dll(d2);
		}
	} lws_end_foreach_dll(d);

	lws_auth_dns_free_zone(&z);

	return count;
}

int
acme_dns_txt_has(const uint8_t *rdata, size_t len, const char *value)
{
	size_t vl = strlen(value), n = 0;

	/* TXT RDATA is one or more <length><string> */

	while (n < len) {
		size_t l = rdata[n++];

		if (l > len - n)
			return 0;
		if (l == vl && !memcmp(rdata + n, value, vl))
			return 1;
		n += l;
	}

	return 0;
}

/* --- waiting for the servers --- */

/* what an address said the last time it answered */
enum {
	AW_UNKNOWN,	/* it hasn't answered yet */
	AW_HAS,		/* answered with the TXT */
	AW_LACKS,	/* answered authoritatively without it */
};

struct acme_dns_wait;

struct acme_dns_wait_srv {
	struct acme_dns_wait		*w;
	struct lws_adns_direct		*q;
	struct acme_dns_server		s;
	uint8_t				state;
};

struct acme_dns_wait {
	struct lws_context		*cx;
	lws_sorted_usec_list_t		sul_round;
	lws_sorted_usec_list_t		sul_deadline;
	acme_dns_wait_cb_t		cb;
	void				*opaque;
	lws_usec_t			interval;
	int				count;
	char				qname[256];
	char				value[128];
	struct acme_dns_wait_srv	srv[ACME_DNS_WAIT_MAX_SERVERS];
};

/* is every name server serving it? */

static int
acme_dns_wait_ready(struct acme_dns_wait *w, char *lag, size_t lag_len)
{
	char *p = lag, *e = lag + lag_len;
	int n, m, ready = 1;

	*lag = '\0';

	for (n = 0; n < w->count; n++) {
		int has = 0, lacks = 0, seen = 0;

		/* only the first entry of each name server sums it up */
		for (m = 0; m < n; m++)
			if (!strcmp(w->srv[m].s.ns, w->srv[n].s.ns))
				seen = 1;
		if (seen)
			continue;

		for (m = n; m < w->count; m++) {
			if (strcmp(w->srv[m].s.ns, w->srv[n].s.ns))
				continue;
			has |= w->srv[m].state == AW_HAS;
			lacks |= w->srv[m].state == AW_LACKS;
		}

		if (has && !lacks)
			continue;

		ready = 0;
		p += lws_snprintf(p, lws_ptr_diff_size_t(e, p), "%s%s",
				  p == lag ? "" : ", ", w->srv[n].s.ns);
	}

	return ready;
}

/* calls back, if there is still a callback, and frees w */

static void
acme_dns_wait_finish(struct acme_dns_wait *w, int ok, const char *why)
{
	acme_dns_wait_cb_t cb = w->cb;
	void *opaque = w->opaque;
	int n;

	lws_sul_cancel(&w->sul_round);
	lws_sul_cancel(&w->sul_deadline);
	for (n = 0; n < w->count; n++)
		if (w->srv[n].q)
			lws_async_dns_query_direct_cancel(&w->srv[n].q);

	if (cb)
		cb(opaque, ok, why);

	free(w);
}

static void
acme_dns_wait_answer(void *opaque, const lws_adns_direct_result_t *r)
{
	struct acme_dns_wait_srv *s = (struct acme_dns_wait_srv *)opaque;
	struct acme_dns_wait *w = s->w;
	char lag[512];
	int n;

	s->q = NULL;

	/*
	 * Only an authoritative answer tells us anything: a timeout or a
	 * refusal leaves what the address said before standing
	 */
	if (r->authoritative && (r->ret == LADNS_RET_FOUND ||
				 r->ret == LADNS_RET_NXDOMAIN)) {
		s->state = AW_LACKS;
		for (n = 0; n < r->count; n++)
			if (acme_dns_txt_has(r->rrs[n].rdata, r->rrs[n].len,
					     w->value))
				s->state = AW_HAS;
	}

	if (acme_dns_wait_ready(w, lag, sizeof(lag)))
		acme_dns_wait_finish(w, 1, NULL);
}

/*
 * Every interval, ask again every address that isn't serving it yet and
 * isn't still busy with the last question, so one that never answers
 * doesn't hold up the others
 */

static void
acme_dns_wait_round_cb(lws_sorted_usec_list_t *sul)
{
	struct acme_dns_wait *w = lws_container_of(sul, struct acme_dns_wait,
						   sul_round);
	int n;

	for (n = 0; n < w->count; n++) {
		struct acme_dns_wait_srv *s = &w->srv[n];

		if (s->state == AW_HAS || s->q)
			continue;

		s->q = lws_async_dns_query_direct(w->cx, &s->s.sa46, w->qname,
						  LWS_ADNS_RECORD_TXT,
						  acme_dns_wait_answer, s);
	}

	lws_sul_schedule(w->cx, 0, &w->sul_round, acme_dns_wait_round_cb,
			 w->interval);
}

static void
acme_dns_wait_deadline_cb(lws_sorted_usec_list_t *sul)
{
	struct acme_dns_wait *w = lws_container_of(sul, struct acme_dns_wait,
						   sul_deadline);
	char lag[512], why[640];

	acme_dns_wait_ready(w, lag, sizeof(lag));
	lws_snprintf(why, sizeof(why), "%s didn't serve the dns-01 challenge "
		     "in time", lag);
	acme_dns_wait_finish(w, 0, why);
}

struct acme_dns_wait *
acme_dns_wait_start(struct lws_context *cx, const char *qname,
		    const char *value, const struct acme_dns_server *servers,
		    int count, lws_usec_t timeout, lws_usec_t interval,
		    acme_dns_wait_cb_t cb, void *opaque)
{
	struct acme_dns_wait *w;
	int n;

	if (count <= 0 || count > ACME_DNS_WAIT_MAX_SERVERS ||
	    strlen(qname) >= sizeof(w->qname) ||
	    strlen(value) >= sizeof(w->value))
		return NULL;

	w = calloc(1, sizeof(*w));
	if (!w)
		return NULL;

	w->cx		= cx;
	w->cb		= cb;
	w->opaque	= opaque;
	w->interval	= interval;
	w->count	= count;
	lws_strncpy(w->qname, qname, sizeof(w->qname));
	lws_strncpy(w->value, value, sizeof(w->value));

	for (n = 0; n < count; n++) {
		w->srv[n].w = w;
		w->srv[n].s = servers[n];
	}

	lws_sul_schedule(cx, 0, &w->sul_deadline, acme_dns_wait_deadline_cb,
			 timeout);
	acme_dns_wait_round_cb(&w->sul_round);

	return w;
}

void
acme_dns_wait_destroy(struct acme_dns_wait **pw)
{
	if (!*pw)
		return;

	(*pw)->cb = NULL;
	acme_dns_wait_finish(*pw, 0, NULL);
	*pw = NULL;
}

#endif
