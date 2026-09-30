/*
 * lws-api-test-dnssec-chain
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms the async-dns DNSSEC validator only believes a signer's keys once
 * they are authenticated by a chain of DS records from the trust anchor.
 *
 * We make a private signed hierarchy with keys minted at startup:
 *
 *   .           KSK + ZSK, the KSK's DS is set as our only trust anchor
 *   tld.        KSK + ZSK, DS signed by the root ZSK
 *   zone.tld.   KSK (P-256) + ZSK (P-384), DS signed by the tld ZSK
 *   bad.tld.    as zone.tld, but its DS RRSIG is corrupted
 *   rogue.tld.  its DNSKEY RRset is signed by a KSK its DS doesn't vouch for
 *
 * and serve it from a fake nameserver on a loopback UDP socket of our own,
 * that the resolver is pointed at.  Then, with the context's DNSSEC mode left
 * OFF and each query asking with LWS_ADNS_WANT_DNSSEC, which is what the DHT
 * DNSSEC plugin does, we check that
 *
 *  - a DS answer from the parent zone validates (the plugin's lookup),
 *  - an A answer signed by the zone's ZSK validates,
 *  - the zone's own DNSKEY RRset validates: its keys are of different lengths,
 *    so this also checks the canonical RRset order is by RDATA,
 *  - the DS asked for again is answered from the cache, still validated,
 *  - answers from bad.tld and rogue.tld don't validate,
 *  - a name whose signed CNAME points at a signed name validates, with the
 *    target's address, and the target is asked about on its own even though
 *    the CNAME answer brought its records along,
 *  - a name whose CNAME is unsigned doesn't validate, although the name it
 *    points at would,
 *  - each zone's keys were only fetched once for all of that,
 *  - once the trust anchor is replaced by one that matches no root key,
 *    nothing validates any more,
 *  - the context can be destroyed while a chain walk is in flight.
 *
 * Nothing leaves the machine.
 */

#include <libwebsockets.h>

#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define T_TICK_US		(5 * LWS_US_PER_MS)
#define T_DEADLINE_US		(20 * LWS_US_PER_SEC)
#define T_TTL			3600

#define ALG_P256		13
#define ALG_P384		14

#define RR_A			1
#define RR_CNAME		5
#define RR_DS			43
#define RR_RRSIG		46
#define RR_DNSKEY		48

#define FLAGS_ZSK		256
#define FLAGS_KSK		257

struct tkey {
	struct lws_genec_ctx		ctx;
	struct lws_gencrypto_keyelem	el[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	uint8_t				rdata[4 + 96];
	uint16_t			rdlen;
	uint16_t			tag;
	uint8_t				alg;
};

enum {
	K_ROOT_KSK, K_ROOT_ZSK,
	K_TLD_KSK, K_TLD_ZSK,
	K_ZONE_KSK, K_ZONE_ZSK,
	K_BAD_KSK, K_BAD_ZSK,
	K_ROGUE_DS_KSK, K_ROGUE_KSK, K_ROGUE_ZSK,

	K_COUNT
};

static const struct {
	uint16_t	flags;
	uint8_t		alg;
} key_def[K_COUNT] = {
	{ FLAGS_KSK, ALG_P256 }, { FLAGS_ZSK, ALG_P256 },
	{ FLAGS_KSK, ALG_P256 }, { FLAGS_ZSK, ALG_P256 },
	{ FLAGS_KSK, ALG_P256 }, { FLAGS_ZSK, ALG_P384 },
	{ FLAGS_KSK, ALG_P256 }, { FLAGS_ZSK, ALG_P256 },
	{ FLAGS_KSK, ALG_P256 }, { FLAGS_KSK, ALG_P256 }, { FLAGS_ZSK, ALG_P256 },
};

static struct tkey keys[K_COUNT];

/* one RRset we serve, with its single RRSIG */

#define MAX_RDATA	3

struct trrset {
	const char	*owner;		/* "" for the root */
	const char	*signer;
	uint16_t	type;
	int		signing_key;	/* -1: unsigned */
	int		rd_keys[MAX_RDATA];	/* DNSKEY: the keys, DS: key */
	int		rd_count;
	int		corrupt;	/* spoil the signature */
	const char	*target;	/* CNAME: where it points */
	int		with_target;	/* CNAME: answer for the target too */

	/* made at startup */
	uint8_t		owner_wire[64];
	size_t		owner_wire_len;
	uint8_t		rdata[MAX_RDATA][160];
	uint16_t	rdlen[MAX_RDATA];
	uint8_t		rrsig[256];
	uint16_t	rrsig_len;

	int		asked;		/* how many times the resolver asked */
};

static const uint8_t a_www[] = { 127, 0, 0, 7 };

#define RRSET(_owner, _signer, _type, _key, _corrupt, _count, ...) \
	{ .owner = _owner, .signer = _signer, .type = _type, \
	  .signing_key = _key, .corrupt = _corrupt, .rd_count = _count, \
	  .rd_keys = { __VA_ARGS__ } }

#define CNAME(_owner, _target, _key, _with_target) \
	{ .owner = _owner, .signer = "zone.tld", .type = RR_CNAME, \
	  .signing_key = _key, .rd_count = 1, .target = _target, \
	  .with_target = _with_target }

static struct trrset rrsets[] = {
	RRSET("",		"",		RR_DNSKEY, K_ROOT_KSK,	0,
		2, K_ROOT_KSK, K_ROOT_ZSK),
	RRSET("tld",		"",		RR_DS,	   K_ROOT_ZSK,	0,
		1, K_TLD_KSK),
	RRSET("tld",		"tld",		RR_DNSKEY, K_TLD_KSK,	0,
		2, K_TLD_KSK, K_TLD_ZSK),

	RRSET("zone.tld",	"tld",		RR_DS,	   K_TLD_ZSK,	0,
		1, K_ZONE_KSK),
	RRSET("zone.tld",	"zone.tld",	RR_DNSKEY, K_ZONE_KSK,	0,
		2, K_ZONE_KSK, K_ZONE_ZSK),
	RRSET("www.zone.tld",	"zone.tld",	RR_A,	   K_ZONE_ZSK,	0,
		1, -1),

	RRSET("bad.tld",	"tld",		RR_DS,	   K_TLD_ZSK,	1,
		1, K_BAD_KSK),
	RRSET("bad.tld",	"bad.tld",	RR_DNSKEY, K_BAD_KSK,	0,
		2, K_BAD_KSK, K_BAD_ZSK),
	RRSET("www.bad.tld",	"bad.tld",	RR_A,	   K_BAD_ZSK,	0,
		1, -1),

	RRSET("rogue.tld",	"tld",		RR_DS,	   K_TLD_ZSK,	0,
		1, K_ROGUE_DS_KSK),
	RRSET("rogue.tld",	"rogue.tld",	RR_DNSKEY, K_ROGUE_KSK,	0,
		2, K_ROGUE_KSK, K_ROGUE_ZSK),
	RRSET("www.rogue.tld",	"rogue.tld",	RR_A,	   K_ROGUE_ZSK,	0,
		1, -1),

	/*
	 * A signed CNAME to a signed name, answered with the target's records
	 * as a recursive resolver would, and an unsigned CNAME to the same
	 * name, answered without them, so the target has to be asked about
	 */
	CNAME("alias.zone.tld",	"www.zone.tld",	K_ZONE_ZSK,	1),
	CNAME("plain.zone.tld",	"www.zone.tld",	-1,		0),
};

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_tick;
static lws_usec_t deadline;
static int ns_fd = -1, step, step_started, step_result, step_done, fails;
static int ns_drop_root, teardown_ticks, step_www_asked;
static uint8_t step_ads[4];

static int
name_wire(const char *name, uint8_t *w, size_t wl)
{
	size_t o = 0;

	while (*name) {
		const char *e = strchr(name, '.');
		size_t l = e ? (size_t)(e - name) : strlen(name);

		if (!l || l > 63 || o + l + 2 > wl)
			return -1;
		w[o++] = (uint8_t)l;
		memcpy(w + o, name, l);
		o += l;
		name += l + (e ? 1 : 0);
	}
	w[o++] = 0;

	return (int)o;
}

static int
labels(const char *name)
{
	int n = *name ? 1 : 0;

	while (*name)
		if (*name++ == '.')
			n++;

	return n;
}

static uint16_t
key_tag(const uint8_t *k, size_t l)
{
	uint32_t ac = 0;
	size_t i;

	for (i = 0; i < l; i++)
		ac += (i & 1) ? k[i] : (uint32_t)k[i] << 8;
	ac += (ac >> 16) & 0xffff;

	return (uint16_t)ac;
}

static int
make_key(struct tkey *k, uint16_t flags, uint8_t alg)
{
	size_t cl = alg == ALG_P256 ? 32 : 48;

	if (lws_genecdsa_create(&k->ctx, cx, NULL) ||
	    lws_genecdsa_new_keypair(&k->ctx, alg == ALG_P256 ? "P-256" :
							       "P-384", k->el))
		return -1;

	if (k->el[LWS_GENCRYPTO_EC_KEYEL_X].len != cl ||
	    k->el[LWS_GENCRYPTO_EC_KEYEL_Y].len != cl)
		return -1;

	k->alg = alg;
	k->rdata[0] = (uint8_t)(flags >> 8);
	k->rdata[1] = (uint8_t)flags;
	k->rdata[2] = 3; /* protocol */
	k->rdata[3] = alg;
	memcpy(k->rdata + 4, k->el[LWS_GENCRYPTO_EC_KEYEL_X].buf, cl);
	memcpy(k->rdata + 4 + cl, k->el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, cl);
	k->rdlen = (uint16_t)(4 + cl * 2);
	k->tag = key_tag(k->rdata, k->rdlen);

	return 0;
}

/* DS RDATA for key k at owner, SHA-256 digest */

static int
make_ds(const char *owner, const struct tkey *k, uint8_t *rd, uint16_t *rdlen)
{
	struct lws_genhash_ctx hc;
	uint8_t w[64];
	int wl = name_wire(owner, w, sizeof(w));

	if (wl < 0)
		return -1;

	rd[0] = (uint8_t)(k->tag >> 8);
	rd[1] = (uint8_t)k->tag;
	rd[2] = k->alg;
	rd[3] = 2; /* SHA-256 */

	if (lws_genhash_init(&hc, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&hc, w, (size_t)wl) ||
	    lws_genhash_update(&hc, k->rdata, k->rdlen) ||
	    lws_genhash_destroy(&hc, rd + 4))
		return -1;

	*rdlen = 4 + 32;

	return 0;
}

/* RFC 4034 6.3: RRs of the set ordered by their RDATA alone */

static struct trrset *sort_set;

static int
rd_cmp(const void *a, const void *b)
{
	int ia = *(const int *)a, ib = *(const int *)b;
	uint16_t la = sort_set->rdlen[ia], lb = sort_set->rdlen[ib];
	int c = memcmp(sort_set->rdata[ia], sort_set->rdata[ib],
		       la < lb ? la : lb);

	return c ? c : (la < lb ? -1 : la > lb);
}

static int
sign_rrset(struct trrset *s)
{
	const struct tkey *k;
	enum lws_genhash_types ht;
	uint32_t now = (uint32_t)lws_now_secs();
	int order[MAX_RDATA], i, sl, kb;
	uint8_t hash[64], hdr[10], *p = s->rrsig;
	struct lws_genhash_ctx hc;
	size_t siglen;

	if (s->signing_key < 0)
		return 0; /* served without an RRSIG */

	k = &keys[s->signing_key];
	ht = k->alg == ALG_P256 ? LWS_GENHASH_TYPE_SHA256 :
				  LWS_GENHASH_TYPE_SHA384;
	kb = k->alg == ALG_P256 ? 256 : 384;
	siglen = (size_t)kb / 4;

	p[0] = (uint8_t)(s->type >> 8);
	p[1] = (uint8_t)s->type;
	p[2] = k->alg;
	p[3] = (uint8_t)labels(s->owner);
	lws_ser_wu32be(p + 4, T_TTL);
	lws_ser_wu32be(p + 8, now + 86400);	/* expiration */
	lws_ser_wu32be(p + 12, now - 3600);	/* inception */
	p[16] = (uint8_t)(k->tag >> 8);
	p[17] = (uint8_t)k->tag;
	sl = name_wire(s->signer, p + 18, sizeof(s->rrsig) - 18);
	if (sl < 0)
		return -1;

	for (i = 0; i < s->rd_count; i++)
		order[i] = i;
	sort_set = s;
	qsort(order, (size_t)s->rd_count, sizeof(order[0]), rd_cmp);

	lws_ser_wu16be(hdr, s->type);
	lws_ser_wu16be(hdr + 2, 1);
	lws_ser_wu32be(hdr + 4, T_TTL);

	if (lws_genhash_init(&hc, ht) ||
	    lws_genhash_update(&hc, p, 18 + (size_t)sl))
		return -1;

	for (i = 0; i < s->rd_count; i++) {
		lws_ser_wu16be(hdr + 8, s->rdlen[order[i]]);
		if (lws_genhash_update(&hc, s->owner_wire, s->owner_wire_len) ||
		    lws_genhash_update(&hc, hdr, sizeof(hdr)) ||
		    lws_genhash_update(&hc, s->rdata[order[i]],
				       s->rdlen[order[i]]))
			return -1;
	}

	if (lws_genhash_destroy(&hc, hash))
		return -1;

	if (lws_genecdsa_hash_sign_jws((struct lws_genec_ctx *)&k->ctx, hash,
				       ht, kb, p + 18 + sl, siglen) < 0)
		return -1;

	if (s->corrupt)
		p[18 + sl + 5] ^= 0x55;

	s->rrsig_len = (uint16_t)(18 + (size_t)sl + siglen);

	return 0;
}

static int
make_hierarchy(void)
{
	size_t n;
	int i;

	for (i = 0; i < K_COUNT; i++)
		if (make_key(&keys[i], key_def[i].flags, key_def[i].alg)) {
			lwsl_err("%s: key %d failed\n", __func__, i);
			return -1;
		}

	for (n = 0; n < LWS_ARRAY_SIZE(rrsets); n++) {
		struct trrset *s = &rrsets[n];
		int wl = name_wire(s->owner, s->owner_wire,
				   sizeof(s->owner_wire));

		if (wl < 0)
			return -1;
		s->owner_wire_len = (size_t)wl;

		for (i = 0; i < s->rd_count; i++) {
			switch (s->type) {
			case RR_DNSKEY:
				memcpy(s->rdata[i], keys[s->rd_keys[i]].rdata,
				       keys[s->rd_keys[i]].rdlen);
				s->rdlen[i] = keys[s->rd_keys[i]].rdlen;
				break;
			case RR_DS:
				if (make_ds(s->owner, &keys[s->rd_keys[i]],
					    s->rdata[i], &s->rdlen[i]))
					return -1;
				break;
			case RR_CNAME:
				wl = name_wire(s->target, s->rdata[i],
					       sizeof(s->rdata[i]));
				if (wl < 0)
					return -1;
				s->rdlen[i] = (uint16_t)wl;
				break;
			default:
				memcpy(s->rdata[i], a_www, sizeof(a_www));
				s->rdlen[i] = sizeof(a_www);
				break;
			}
		}

		if (sign_rrset(s)) {
			lwsl_err("%s: signing %s/%d failed\n", __func__,
				 s->owner, s->type);
			return -1;
		}
	}

	return 0;
}

/* ---- the fake nameserver ---- */

static struct trrset *
find_rrset(const char *owner, uint16_t type)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(rrsets); n++)
		if (!strcmp(rrsets[n].owner, owner) && rrsets[n].type == type)
			return &rrsets[n];

	return NULL;
}

static int
ns_socket(uint16_t *port)
{
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family		= AF_INET;
	sin.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) ||
	    getsockname(fd, (struct sockaddr *)&sin, &sl) ||
	    fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		close(fd);
		return -1;
	}

	*port = ntohs(sin.sin_port);

	return fd;
}

/*
 * One RR with owner \p ow, or if that's NULL, a pointer to the qname... the
 * caller made sure there's room
 */

static size_t
put_rr(uint8_t *o, const struct trrset *ow, uint16_t type, const uint8_t *rd,
       uint16_t rdlen)
{
	size_t n = 2;

	if (ow) {
		memcpy(o, ow->owner_wire, ow->owner_wire_len);
		n = ow->owner_wire_len;
	} else {
		o[0] = 0xc0;
		o[1] = 12;
	}

	lws_ser_wu16be(o + n, type);
	lws_ser_wu16be(o + n + 2, 1);
	lws_ser_wu32be(o + n + 4, T_TTL);
	lws_ser_wu16be(o + n + 8, rdlen);
	memcpy(o + n + 10, rd, rdlen);

	return n + 10u + rdlen;
}

/* the RRset and its RRSIG, if it has one; returns the count of RRs */

static int
put_rrset(uint8_t *resp, size_t *o, const struct trrset *s,
	  const struct trrset *ow)
{
	int i;

	for (i = 0; i < s->rd_count; i++)
		*o += put_rr(resp + *o, ow, s->type, s->rdata[i], s->rdlen[i]);

	if (!s->rrsig_len)
		return s->rd_count;

	*o += put_rr(resp + *o, ow, RR_RRSIG, s->rrsig, s->rrsig_len);

	return s->rd_count + 1;
}

static void
ns_answer(const uint8_t *q, size_t ql, const struct sockaddr *peer,
	  socklen_t peer_len)
{
	uint8_t resp[1024], qn[64];
	size_t o = 12, qe, n;
	struct trrset *s = NULL, *t = NULL;
	int known = 0, ans = 0;
	uint16_t qtype;

	/* the qname, lowercased; a query has no compression pointers */

	while (o < ql && q[o]) {
		if (q[o] > 63 || o + q[o] + 1 >= ql)
			return;
		o += (size_t)q[o] + 1;
	}
	if (o + 5 > ql || o - 12 + 1 > sizeof(qn))
		return;

	for (n = 12; n <= o; n++)
		qn[n - 12] = (uint8_t)tolower(q[n]);
	qtype = lws_ser_ru16be(q + o + 1);
	qe = o + 5;

	for (n = 0; n < LWS_ARRAY_SIZE(rrsets); n++)
		if (rrsets[n].owner_wire_len == o - 12 + 1 &&
		    !memcmp(rrsets[n].owner_wire, qn, o - 12 + 1)) {
			known = 1;
			if (rrsets[n].type == qtype ||
			    rrsets[n].type == RR_CNAME)
				s = &rrsets[n];
		}

	memcpy(resp, q, qe);
	resp[2] = 0x81;			/* QR + RD */
	resp[3] = known ? 0x80 : 0x83;	/* RA, NOERROR or NXDOMAIN */
	lws_ser_wu16be(resp + 4, 1);
	lws_ser_wu16be(resp + 6, 0);
	lws_ser_wu16be(resp + 8, 0);
	lws_ser_wu16be(resp + 10, 0);
	o = qe;

	if (s) {
		s->asked++;
		if (ns_drop_root && !*s->owner)
			return; /* never answered */
		ans = put_rrset(resp, &o, s, NULL);

		/*
		 * Like a recursive resolver, answer for the CNAME's target
		 * too, if we have what was asked for there
		 */
		if (s->type == RR_CNAME && s->with_target && qtype != RR_CNAME)
			t = find_rrset(s->target, qtype);
		if (t)
			ans += put_rrset(resp, &o, t, t);

		lws_ser_wu16be(resp + 6, (uint16_t)ans);
	}

	if (sendto(ns_fd, (const char *)resp, o, 0, peer, peer_len) < 0)
		lwsl_err("%s: sendto failed, errno %d\n", __func__, errno);
}

static void
ns_service(void)
{
	for (;;) {
		struct sockaddr_storage peer;
		socklen_t peer_len = sizeof(peer);
		uint8_t pkt[512];
		ssize_t n = recvfrom(ns_fd, (char *)pkt, sizeof(pkt), 0,
				     (struct sockaddr *)&peer, &peer_len);

		if (n < 12)
			return;

		ns_answer(pkt, (size_t)n, (struct sockaddr *)&peer, peer_len);
	}
}

static int
times_asked(const char *owner, uint16_t type)
{
	struct trrset *s = find_rrset(owner, type);

	return s ? s->asked : -1;
}

/* ---- the queries ---- */

struct tstep {
	const char	*name;
	uint32_t	qtype;
	int		expect_valid;
	int		check_a;
	int		from_cache;	/* must be answered from the cache */
	int		bogus_anchor;	/* set a wrong trust anchor first */
};

static const struct tstep steps[] = {
	/*
	 * A signed CNAME to www.zone.tld: nothing is authenticated yet, so
	 * the CNAME has to wait for the walk down to zone.tld before we may
	 * follow it
	 */
	{ "alias.zone.tld",	RR_A,		1, 1, 0, 0 },
	/* what the DHT DNSSEC plugin asks: DS from the parent */
	{ "zone.tld",		RR_DS,		1, 0, 0, 0 },
	/* data signed by the zone's ZSK */
	{ "www.zone.tld",	RR_A,		1, 1, 0, 0 },
	/* the zone's own keys, of mixed lengths, as an answer */
	{ "zone.tld",		RR_DNSKEY,	1, 0, 0, 0 },
	/* the same DS again: from the cache, and still validated */
	{ "zone.tld",		RR_DS,		1, 0, 1, 0 },
	/* the tld's signature over bad.tld's DS is spoiled */
	{ "www.bad.tld",	RR_A,		0, 0, 0, 0 },
	/* rogue.tld's DNSKEY RRset isn't signed by the key its DS names */
	{ "www.rogue.tld",	RR_A,		0, 0, 0, 0 },
	/* an unsigned CNAME to it isn't believed */
	{ "plain.zone.tld",	RR_A,		0, 0, 0, 0 },
	/* after the anchor is replaced by one that matches no root key */
	{ "www.zone.tld",	RR_A | LWS_ADNS_NOCACHE, 0, 0, 0, 1 },
};

static struct lws *
query_cb(struct lws *wsi, const char *ads, const struct addrinfo *a, int n,
	 void *opaque)
{
	const struct addrinfo *ac = a;

	(void)ads;
	(void)opaque;

	step_result = n;
	memset(step_ads, 0, sizeof(step_ads));

	for (; ac; ac = ac->ai_next)
		if (ac->ai_family == AF_INET)
			memcpy(step_ads,
			       &((struct sockaddr_in *)ac->ai_addr)->sin_addr, 4);

	lws_async_dns_freeaddrinfo(&a);
	step_done = 1;

	return wsi ? wsi : LADNS_NO_WSI_BUT_OK;
}

static int
set_bogus_anchor(void)
{
	/* the tld's KSK, as if it were the root's: matches no root key */
	lws_adns_ds_anchor_t an;
	uint8_t rd[4 + 32];
	uint16_t rdlen;

	if (make_ds("", &keys[K_TLD_KSK], rd, &rdlen))
		return -1;

	memset(&an, 0, sizeof(an));
	an.key_tag	= keys[K_TLD_KSK].tag;
	an.algorithm	= ALG_P256;
	an.digest_type	= 2;
	an.digest	= rd + 4;
	an.digest_len	= 32;

	return lws_async_dns_dnssec_set_root_anchors(cx, &an, 1);
}

static void
step_check(void)
{
	const struct tstep *t = &steps[step];
	int found = step_result >= 0 &&
		    (step_result & ~LWS_ADNS_DNSSEC_VALID) == LADNS_RET_FOUND;
	int valid = found && (step_result & LWS_ADNS_DNSSEC_VALID);

	if (valid != t->expect_valid) {
		lwsl_err("step %d (%s type %u): result 0x%x, expected %s\n",
			 step, t->name, (unsigned int)(t->qtype & 0xffff),
			 step_result, t->expect_valid ? "valid" : "failure");
		fails++;
		return;
	}

	if (t->check_a && memcmp(step_ads, a_www, sizeof(a_www))) {
		lwsl_err("step %d: wrong address\n", step);
		fails++;
		return;
	}

	if (!strcmp(t->name, "alias.zone.tld") &&
	    times_asked("www.zone.tld", RR_A) != step_www_asked + 1) {
		/*
		 * The target's records came with the CNAME, but they are
		 * only good once the target's own answer validated
		 */
		lwsl_err("step %d: the CNAME target wasn't asked about\n",
			 step);
		fails++;
		return;
	}

	if ((t->qtype & 0xffff) == RR_DS && valid) {
		const struct trrset *s = find_rrset(t->name, RR_DS);
		uint16_t pl = 0;
		const uint8_t *ds = lws_async_dns_get_rr_cache(cx, t->name,
						LWS_ADNS_RECORD_DS, &pl);

		if (!s || !ds || pl != s->rdlen[0] ||
		    memcmp(ds, s->rdata[0], pl)) {
			lwsl_err("step %d: cached DS isn't the one we served\n",
				 step);
			fails++;
			return;
		}
	}

	lwsl_user("step %d (%s type %u): %s as expected\n", step, t->name,
		  (unsigned int)(t->qtype & 0xffff),
		  valid ? "validated" : "refused");
}

static void
check_asked(const char *owner, uint16_t type, int want)
{
	int n = times_asked(owner, type);

	if (n != want) {
		lwsl_err("'%s' type %u was asked %d times, expected %d\n",
			 owner, type, n, want);
		fails++;
	}
}

static int
step_start(void)
{
	const struct tstep *t = &steps[step];
	int n, ds_asked = times_asked("zone.tld", RR_DS);

	if (t->bogus_anchor) {
		/*
		 * Each zone's keys were only fetched once for everything so
		 * far; zone.tld's DS and DNSKEY RRsets were also each asked
		 * for once as an answer to authenticate
		 */
		check_asked("", RR_DNSKEY, 1);
		check_asked("tld", RR_DS, 1);
		check_asked("tld", RR_DNSKEY, 1);
		check_asked("zone.tld", RR_DS, 2);
		check_asked("zone.tld", RR_DNSKEY, 2);

		if (set_bogus_anchor()) {
			lwsl_err("%s: setting the anchor failed\n", __func__);
			return -1;
		}
	}

	step_done = 0;
	step_result = LADNS_RET_FAILED;
	step_www_asked = times_asked("www.zone.tld", RR_A);

	n = lws_async_dns_query(cx, 0, t->name, (adns_query_type_t)(t->qtype |
					LWS_ADNS_WANT_DNSSEC |
					LWS_ADNS_IGNORE_HOSTS_FILE),
				query_cb, NULL, NULL, NULL);

	if (t->from_cache) {
		/* this one must have been answered from the cache */
		if (n == LADNS_RET_CONTINUING || !step_done ||
		    times_asked("zone.tld", RR_DS) != ds_asked) {
			lwsl_err("%s: repeated DS wasn't served from cache\n",
				 __func__);
			fails++;
		}
	}

	return 0;
}

/*
 * The last leg destroys the context while a chain walk is in flight: a query
 * is parked on zone.tld, which waits on tld, which waits on the root, whose
 * DNSKEY fetch the nameserver never answers.  Under ASan, that shows the
 * teardown frees all of it without anything calling back into freed memory.
 */

static void
teardown_start(void)
{
	/* the anchor changed, so the chain was walked again, from the root */
	check_asked("", RR_DNSKEY, 2);

	/*
	 * Back to the built-in anchors: that also forgets the zones that just
	 * failed, so they are walked again, rather than failed from the store
	 */
	if (lws_async_dns_dnssec_set_root_anchors(cx, NULL, 0)) {
		lwsl_err("%s: restoring the built-in anchors failed\n",
			 __func__);
		fails++;
	}

	ns_drop_root = 1;
	step_done = 0;

	if (lws_async_dns_query(cx, 0, "www.zone.tld",
				(adns_query_type_t)(RR_A | LWS_ADNS_NOCACHE |
						LWS_ADNS_WANT_DNSSEC |
						LWS_ADNS_IGNORE_HOSTS_FILE),
				query_cb, NULL, NULL, NULL) !=
							LADNS_RET_CONTINUING) {
		lwsl_err("%s: query didn't start\n", __func__);
		fails++;
	}
}

static int
teardown_tick(void)
{
	if (++teardown_ticks < 20)
		return 0;

	if (step_done || times_asked("", RR_DNSKEY) != 3) {
		lwsl_err("%s: the walk isn't parked on the root's keys\n",
			 __func__);
		fails++;
	} else
		lwsl_user("teardown with the chain walk in flight\n");

	lws_default_loop_exit(cx);

	return 1;
}

static void
sul_tick_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	ns_service();

	if (lws_now_usecs() > deadline) {
		lwsl_err("%s: timed out in step %d\n", __func__, step);
		fails++;
		lws_default_loop_exit(cx);
		return;
	}

	if (step == (int)LWS_ARRAY_SIZE(steps)) {
		if (teardown_tick())
			return;
		goto again;
	}

	if (!step_started) {
		step_started = 1;
		if (step_start()) {
			fails++;
			lws_default_loop_exit(cx);
			return;
		}
	}

	if (step_done) {
		step_check();
		step_started = 0;
		if (++step == (int)LWS_ARRAY_SIZE(steps))
			teardown_start();
	}

again:
	lws_sul_schedule(cx, 0, &sul_tick, sul_tick_cb, T_TICK_US);
}

int
main(int argc, const char **argv)
{
	static const char *servers[] = { "127.0.0.1", NULL };
	struct lws_context_creation_info info;
	lws_adns_ds_anchor_t an;
	uint8_t anchor_rd[4 + 32];
	uint16_t anchor_rdlen, port;
	char portstr[16];
	int i;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: DNSSEC chain of trust\n");

	ns_fd = ns_socket(&port);
	if (ns_fd < 0) {
		lwsl_err("can't make the nameserver socket\n");
		return 1;
	}

	/* point the resolver's nameserver port at our fake nameserver */
	lws_snprintf(portstr, sizeof(portstr), "%u", port);
	setenv("LWS_ASYNCDNS_PORT", portstr, 1);

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.async_dns_servers	= servers;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		close(ns_fd);
		return 1;
	}

	/* only the pinned nameserver, ie, only our own fake one */
	{
		lws_sockaddr46 sa46;
		int index = 0;

		while (!lws_plat_asyncdns_get_server(cx, index++, &sa46))
			lws_async_dns_server_remove(cx, &sa46);
	}

	if (make_hierarchy()) {
		fails++;
		goto bail;
	}

	/* our root KSK is the only trust anchor */

	if (make_ds("", &keys[K_ROOT_KSK], anchor_rd, &anchor_rdlen)) {
		fails++;
		goto bail;
	}
	memset(&an, 0, sizeof(an));
	an.key_tag	= keys[K_ROOT_KSK].tag;
	an.algorithm	= ALG_P256;
	an.digest_type	= 2;
	an.digest	= anchor_rd + 4;
	an.digest_len	= 32;
	if (lws_async_dns_dnssec_set_root_anchors(cx, &an, 1)) {
		fails++;
		goto bail;
	}

	deadline = lws_now_usecs() + T_DEADLINE_US;
	lws_sul_schedule(cx, 0, &sul_tick, sul_tick_cb, T_TICK_US);

	while (lws_service(cx, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_tick);
	lws_context_destroy(cx);

	for (i = 0; i < K_COUNT; i++) {
		lws_genec_destroy(&keys[i].ctx);
		lws_genec_destroy_elements(keys[i].el);
	}
	close(ns_fd);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
