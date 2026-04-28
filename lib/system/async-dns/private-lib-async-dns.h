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


#define DNS_MAX			128	/* Maximum host name		*/
#define DNS_RECURSION_LIMIT	4
#define DNS_PACKET_LEN		1400	/* Buffer size for DNS packet	*/
#define MAX_CACHE_ENTRIES	10	/* Dont cache more than that	*/
#define DNS_QUERY_TIMEOUT	30	/* Query timeout, seconds	*/
#define LWS_ADNS_MAX_PAYLOAD	1500	/* Maximum TCP payload size    */

#if defined(LWS_WITH_SYS_ASYNC_DNS)

/* RFC 4034, 5702, 6605, etc DNSSEC Algorithm Numbers */
typedef enum {
	LWS_ADNS_DSA_RSA_MD5			= 1,  /* RFC 2537 */
	LWS_ADNS_DSA_DH				= 2,  /* RFC 2539 */
	LWS_ADNS_DSA_DSA			= 3,  /* RFC 2536 */
	LWS_ADNS_DSA_ECC			= 4,  /* RFC 2536 */
	LWS_ADNS_DSA_RSA_SHA1			= 5,  /* RFC 3110 */
	LWS_ADNS_DSA_DSA_NSEC3_SHA1		= 6,  /* RFC 5155 */
	LWS_ADNS_DSA_RSA_SHA1_NSEC3_SHA1	= 7,  /* RFC 5155 */
	LWS_ADNS_DSA_RSA_SHA256			= 8,  /* RFC 5702 */
	LWS_ADNS_DSA_RSA_SHA512			= 10, /* RFC 5702 */
	LWS_ADNS_DSA_ECC_GOST			= 12, /* RFC 5933 */
	LWS_ADNS_DSA_ECDSAP256SHA256		= 13, /* RFC 6605 */
	LWS_ADNS_DSA_ECDSAP384SHA384		= 14, /* RFC 6605 */
	LWS_ADNS_DSA_ED25519			= 15, /* RFC 8080 */
	LWS_ADNS_DSA_ED448			= 16, /* RFC 8080 */
} lws_dnssec_algo_t;

/* RFC 4034 DNSKEY Protocol Field */
#define LWS_ADNS_DNSKEY_PROTOCOL_DNSSEC	3

/*
 * ... when we completed a query then the query object is destroyed and a
 * appended to the allocation
 */

typedef struct lws_adns_rr {
	struct lws_adns_rr	*next;
	adns_query_type_t	type;
	uint16_t		paylen;
	/* payload follows */
} lws_adns_rr_t;

typedef struct lws_adns_cache {
	lws_sorted_usec_list_t	sul;	/* for cache TTL management */
	lws_dll2_t		list;

	struct lws_adns_cache	*firstcache;
	struct lws_adns_cache	*chain;
	struct addrinfo		*results;
	struct lws_adns_rr	*rr_results; /* For DNSKEY, DS, RRSIG, etc. */
	const char		*name;
	uint8_t			flags;	/* b0 = has ipv4, b1 = has ipv6 */
	char			refcount;
	char			incomplete;
	/* addrinfo, lws_sa46, then name overallocated here */
} lws_adns_cache_t;

/*
 * these objects are used while a query is ongoing...
 */

typedef int (*lws_async_dns_find_t)(const char *name, void *opaque,
		uint32_t ttl, adns_query_type_t type, uint16_t rrpaylen,
		const uint8_t *payload);

typedef struct lws_adns_q {
	lws_sorted_usec_list_t	sul;	/* per-query write retry timer */
	lws_sorted_usec_list_t	write_sul;	/* fail if unable to write by this time */
	lws_dll2_t		list;

	lws_metrics_caliper_compose(metcal)

	lws_dll2_owner_t	wsi_adns;
	lws_async_dns_cb_t	standalone_cb;	/* if not associated to wsi */
	struct lws_context	*context;
	void			*opaque;
	struct addrinfo		**last;
	lws_async_dns_t		*dns;
	lws_async_dns_server_t	*dsrv;

	lws_adns_cache_t	*firstcache;

	lws_async_dns_retcode_t	ret;
	uint16_t		tid[3]; /* last 3 sent tid */
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
	uint8_t			tids;
	uint8_t			go_nogo;

	uint8_t			is_retry:1;
	uint8_t			is_synthetic:1; /* test will deliver canned */
	uint8_t			is_tcp:1;
	uint8_t			has_tcp_len:1;
	uint8_t			want_dnssec:1;
#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	uint8_t			dnssec_valid:1;  /* results are verified */
	uint8_t			dnssec_chk_cname:1; /* currently checking a CNAME */
	uint8_t			dnssec_verify_rrsig:1; /* waiting on RRSIG verify */
	uint8_t			lacks_dnssec:1; /* per-query DNSSEC override */
#endif

	struct lws		*wsi_tcp;
	uint8_t			*tcp_rx_buf;
	uint16_t		tcp_rx_len;
	uint16_t		tcp_rx_pos;

	lws_usec_t		issue_time;
	uint8_t			broadsiding;

	/* name overallocated here */
} lws_adns_q_t;

#define LADNS_MOST_RECENT_TID(_q) \
		_q->tid[_q->tids ? ((int)(_q->tids - 1) % (int)LWS_ARRAY_SIZE(_q->tid)) : 0]

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

lws_async_dns_retcode_t
lws_async_dns_complete(lws_adns_q_t *q, lws_adns_cache_t *c);

lws_adns_cache_t *
lws_adns_get_cache(lws_async_dns_t *dns, const char *name);

lws_adns_q_t *
lws_adns_get_query(lws_async_dns_t *dns, adns_query_type_t qtype,
		   uint16_t tid, const char *name);

void
lws_async_dns_trim_cache(lws_async_dns_t *dns);

int
lws_async_dns_get_new_tid(struct lws_context *context, lws_adns_q_t *q);

int
lws_async_dns_create_tcp_wsi(lws_adns_q_t *q);



/* require: context lock on this set */

lws_async_dns_server_t *
__lws_async_dns_server_find(lws_async_dns_t *dns, const lws_sockaddr46 *sa46);
lws_async_dns_server_t *
__lws_async_dns_server_find_wsi(lws_async_dns_t *dns, struct lws *wsi);
lws_async_dns_server_t *
__lws_async_dns_server_add(lws_async_dns_t *dns, const lws_sockaddr46 *sa46);
void
__lws_async_dns_server_remove(lws_async_dns_t *dns, const lws_sockaddr46 *sa46);

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
int
lws_adns_dnssec_verify(lws_adns_q_t *q, const uint8_t *pkt, size_t len);
#endif

int
lws_adns_iterate(lws_adns_q_t *q, const uint8_t *pkt, int len,
		 const char *expname, lws_async_dns_find_t cb, void *opaque);

void
lws_adns_parse_udp(lws_async_dns_t *dns, const uint8_t *pkt, size_t len,
		   lws_async_dns_server_t *dsrv);

int
lws_adns_parse_label(const uint8_t *pkt, int len, const uint8_t *ls, int budget,
		     char **dest, size_t dl);

#if defined(_DEBUG)
void
lws_adns_dump(lws_async_dns_t *dns);
#else
#define lws_adns_dump(_d)
#endif

/*
 * Hardcoded root DS records for Unbound-like trust anchor bootstrapping.
 * These are the current ICANN root zone KSK DS records.
 */
static const struct {
	uint16_t keytag;
	uint8_t algo;
	uint8_t digest_type;
	const char *digest_hex;
} lws_adns_root_ds[] = {
	/* Key tag 20326 (KSK-2017) */
	{ 20326, 8, 2, "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d" },
	/* Key tag 38696 (KSK-2024) */
	{ 38696, 8, 2, "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2afe" }
};

#endif

