/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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


#define DNS_MAX			96	/* Maximum host name		*/
#define DNS_RECURSION_LIMIT	3
#define DNS_PACKET_LEN		1400	/* Buffer size for DNS packet	*/
#define MAX_CACHE_ENTRIES	10	/* Dont cache more than that	*/
#define DNS_QUERY_TIMEOUT	30	/* Query timeout, seconds	*/

/*
 * ... when we completed a query then the query object is destroyed and a
 * cache object below is created with the results in getaddrinfo format
 * appended to the allocation
 */

typedef struct lws_adns_cache {
	lws_sorted_usec_list_t	sul;	/* for cache TTL management */
	lws_dll2_t		list;

	struct lws_adns_cache	*firstcache;
	struct lws_adns_cache	*chain;
	struct addrinfo		*results;
	uint8_t			flags;	/* b0 = has ipv4, b1 = has ipv6 */
	char			refcount;
	char			incomplete;
	/* name, and then result struct addrinfos overallocated here */
} lws_adns_cache_t;

/*
 * these objects are used while a query is ongoing...
 */

typedef struct {
	lws_sorted_usec_list_t	sul;	/* per-query write retry timer */
	lws_dll2_t		list;

	lws_dll2_owner_t	wsi_adns;
	lws_async_dns_cb_t	standalone_cb;	/* if not associated to wsi */
	struct lws_context	*context;
	void			*opaque;
	struct addrinfo		**last;
	lws_async_dns_t		*dns;

	lws_adns_cache_t	*firstcache;

	lws_async_dns_retcode_t	ret;
	uint16_t		tid;
	uint16_t		qtype;
	uint16_t		retry;
	uint8_t			tsi;

#if defined(LWS_WITH_IPV6)
	uint8_t			sent[2];
#else
	uint8_t			sent[1];
#endif
	uint8_t			asked;
	uint8_t			responded;

	uint8_t			recursion;

	/* name overallocated here */
} lws_adns_q_t;

enum {
	DHO_TID,
	DHO_FLAGS = 2,
	DHO_NQUERIES = 4,
	DHO_NANSWERS = 6,
	DHO_NAUTH = 8,
	DHO_NOTHER = 10,

	DHO_SIZEOF = 12 /* last */
};

void
lws_adns_q_destroy(lws_adns_q_t *q);

void
sul_cb_expire(struct lws_sorted_usec_list *sul);

void
lws_adns_cache_destroy(lws_adns_cache_t *c);

int
lws_async_dns_complete(lws_adns_q_t *q, lws_adns_cache_t *c);

lws_adns_cache_t *
lws_adns_get_cache(lws_async_dns_t *dns, const char *name);

void
lws_adns_parse_udp(lws_async_dns_t *dns, const uint8_t *pkt, size_t len);

lws_adns_q_t *
lws_adns_get_query(lws_async_dns_t *dns, adns_query_type_t qtype,
		   lws_dll2_owner_t *owner, uint16_t tid, const char *name);

void
lws_async_dns_trim_cache(lws_async_dns_t *dns);

int
lws_async_dns_get_new_tid(struct lws_context *context, lws_adns_q_t *q);
