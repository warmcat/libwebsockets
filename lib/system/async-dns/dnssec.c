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
 * Asynchronous DNSSEC validation.
 *
 * An RRset is only valid if its RRSIG verifies with a key of the signer's
 * zone, and that key may only be believed once the zone's DNSKEY RRset has
 * itself been authenticated (RFC 4035 5):
 *
 *  - the zone's DS RRset is fetched from its parent, and its RRSIG must
 *    verify with a key of the parent zone, which has to have been
 *    authenticated the same way first, up to the root,
 *
 *  - the zone's DNSKEY RRset is fetched, and its RRSIG must verify with a
 *    key in it that matches one of those DS (for the root, one of our trust
 *    anchors); only then are the keys in that RRset used to verify anything
 *    else signed by the zone.
 *
 * Authenticated zones are kept in a small store on the resolver, so the chain
 * is walked once per zone per key TTL, not once per lookup.  A zone that could
 * not be authenticated is also remembered for a few seconds, so a failing
 * chain is not rewalked for every query that needs it.
 *
 * The chain material is fetched with queries that do not validate themselves
 * (the walk is what validates them); every step of the walk is driven from a
 * sul, so neither a query answered from the cache nor a zone settling ever
 * completes anything on its caller's stack.
 *
 * Unsigned delegations are not proven with NSEC / NSEC3: a zone with no DS
 * fails to authenticate, and so does anything signed by it.
 */

#include "private-lib-core.h"
#include "private-lib-async-dns.h"
#ifndef _WIN32
#include <arpa/inet.h>
#endif

#if defined(LWS_WITH_SYS_ASYNC_DNS)

/* q->dnssec_vctx_waiting[] slot for a given response bit (b0 = A, b1 = AAAA) */
#define lws_dnssec_vctx_idx(_resp) ((unsigned int)(_resp) >> 1)

#define LWS_DNSSEC_MAX_ZONES		16 /* zones in the authenticated store */
#define LWS_DNSSEC_FAIL_HOLD_SECS	10 /* before a failed zone is retried */
#define LWS_DNSSEC_MAX_RRSET		16 /* records in an RRset we will hash */

/* DNSKEY flags, RFC 4034 2.1.1 and RFC 5011 7 */
#define LWS_DNSKEY_FLAG_ZONE		0x0100
#define LWS_DNSKEY_FLAG_REVOKE		0x0080

/*
 * A set of records we hold on to, each one as
 *
 *   [ type: u16be ] [ rdlen: u16be ] [ rdata ]
 */

typedef struct lws_dnssec_rrs {
	uint8_t			*buf;
	size_t			len;
} lws_dnssec_rrs_t;

struct lws_dnssec_zone;
struct lws_dnssec_zone_waiter;

typedef void (*lws_dnssec_zone_settled_t)(struct lws_dnssec_zone_waiter *w,
					  struct lws_dnssec_zone *z);

/* something waiting for a zone to be authenticated, or to fail to */

typedef struct lws_dnssec_zone_waiter {
	lws_dll2_t			list; /* on the zone's waiters */
	lws_dnssec_zone_settled_t	cb;
} lws_dnssec_zone_waiter_t;

typedef enum {
	LDZ_IDLE,		/* nothing done yet, or reset after expiry */
	LDZ_FETCH_DS,		/* our DS RRset is being fetched */
	LDZ_WAIT_PARENT,	/* waiting on the zone that signed our DS */
	LDZ_FETCH_DNSKEY,	/* our DNSKEY RRset is being fetched */
	LDZ_TRUSTED,		/* ->keys is authenticated until ->expires */
	LDZ_FAILED,		/* not authenticated, until ->expires */
} lws_dnssec_zone_state_t;

typedef struct lws_dnssec_zone {
	lws_dll2_t		list;	  /* dns->dnssec_zones, MRU at head */
	lws_sorted_usec_list_t	sul;	  /* drives the walk */
	lws_dll2_owner_t	waiters;  /* lws_dnssec_zone_waiter_t */
	lws_dnssec_zone_waiter_t pw;	  /* us waiting on our parent */
	lws_async_dns_t		*dns;

	lws_dnssec_rrs_t	mat;	  /* fetched, not yet verified */
	lws_dnssec_rrs_t	ds;	  /* our authenticated DS RRset */
	lws_dnssec_rrs_t	keys;	  /* our authenticated DNSKEY RRset */

	uint32_t		expires;  /* unix time, from the RRSIGs */
	uint8_t			state;	  /* lws_dnssec_zone_state_t */
	uint8_t			step_ok;  /* the step we waited on worked */
	uint8_t			settling:1;
	uint8_t			stale:1;  /* the trust anchors changed */

	char			name[DNS_MAX]; /* lowercase, no final '.', root "" */
} lws_dnssec_zone_t;

struct lws_dnssec_val_ctx {
	lws_dnssec_zone_waiter_t zw;	/* on the signer zone's waiters */
	lws_adns_q_t		*original_q;
	uint8_t			resp_bit; /* which response of original_q */
	uint8_t			algorithm;
	uint16_t		key_tag;

	uint16_t		sig_len;
	uint8_t			sig_buf[512];

	uint8_t			hash[64];

	/* unix time the RRSIG stops vouching for the RRset */
	uint32_t		expires;

	/*
	 * If we are validating the queried name's CNAME, where it points:
	 * the query is restarted for it once the CNAME validated.  Else "".
	 */
	char			cname[DNS_MAX];
};

struct rrsig_search {
	lws_adns_q_t *q;
	uint16_t want_type; /* the RRset type this response was asked for */
	const uint8_t *rrsig_payload;
	uint16_t rrsig_paylen;
	uint16_t type_covered;
	uint8_t algorithm;
	uint8_t labels;
	uint32_t original_ttl;
	uint32_t sig_expiration;
	uint32_t sig_inception;
	uint16_t key_tag;
	char signer_name[DNS_MAX];
	int found;
};

struct rr_canonical {
	uint8_t data[768];
	size_t len;
	size_t rd_off; /* where the RDATA starts in data[] */
};

struct rrset_search {
	const uint8_t *pkt; /* the response, to expand names in RDATA with */
	int pkt_len;
	uint16_t type_covered;
	const char *name; /* From query or RRSIG */
	uint32_t original_ttl;

	int count;
	int bad; /* a record of the RRset couldn't be hashed */
	struct rr_canonical records[LWS_DNSSEC_MAX_RRSET];
};

static void
lws_dnssec_zone_sul_cb(lws_sorted_usec_list_t *sul);

static int
lws_dnssec_name_wire(const char *name, uint8_t *wire, size_t wire_len);

static int
name_to_wire(const char *name, int rrsig_labels, uint8_t *wire)
{
	const char *p = name;
	uint8_t *wp = wire;
	uint8_t *len_ptr = wp++;
	int l = 0, labels = 0;

	while (*p) {
		if (*p++ == '.') labels++;
	}
	if (p != name && *(p-1) != '.') labels++;

	int skip = labels > rrsig_labels ? labels - rrsig_labels : 0;
	if (skip) {
		*len_ptr = 1;
		*wp++ = '*';
		len_ptr = wp++;
	}

	p = name;
	while (*p) {
		if (skip > 0) {
			if (*p == '.') skip--;
			p++;
			continue;
		}
		if (*p == '.') {
			*len_ptr = (uint8_t)l;
			len_ptr = wp++;
			l = 0;
		} else {
			*wp++ = (uint8_t)((*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p);
			l++;
		}
		p++;
	}
	*len_ptr = (uint8_t)l;
	if (l > 0)
		*wp++ = 0;
	return (int)(wp - wire);
}

/*
 * RFC 4034 6.3: the records of an RRset are ordered by their RDATA alone, as
 * a left-justified octet sequence where the absence of an octet sorts before
 * a zero octet.  The whole canonical RR can't be compared instead, since its
 * RDLENGTH comes before the RDATA and orders records of different lengths by
 * length.
 */

static int
lws_dnssec_rdata_cmp(const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
	int c = memcmp(a, b, al < bl ? al : bl);

	if (c)
		return c;

	return al < bl ? -1 : (al > bl);
}

static int
cmp_rr(const void *a, const void *b)
{
	const struct rr_canonical *ra = (const struct rr_canonical *)a;
	const struct rr_canonical *rb = (const struct rr_canonical *)b;

	return lws_dnssec_rdata_cmp(ra->data + ra->rd_off, ra->len - ra->rd_off,
				    rb->data + rb->rd_off, rb->len - rb->rd_off);
}

static int
lws_dnssec_rrset_cb(const char *name, void *opaque, uint32_t ttl,
		    adns_query_type_t type, uint16_t rrpaylen,
		    const uint8_t *payload)
{
	struct rrset_search *s = (struct rrset_search *)opaque;
	int nl = (int)strlen(name);
	int sl = (int)strlen(s->name);
	struct rr_canonical *r;
	uint8_t *p;

	if (type != s->type_covered)
		return 0;

	if (nl && name[nl - 1] == '.')
		nl--;
	if (sl && s->name[sl - 1] == '.')
		sl--;

	/*
	 * Owner names compare case-insensitively (RFC 4343), as
	 * lws_adns_iterate() matched them when it stored the records: a
	 * record we stored but left out of the hash here would be published
	 * as validated without the signature covering it.
	 */
	if (nl != sl || strncasecmp(name, s->name, (size_t)nl))
		return 0;

	/*
	 * Every record of the RRset we store goes into the hash, or the
	 * validation fails: skipping one that won't fit would leave it
	 * published as validated beside the ones the signature covers
	 */

	if (s->count >= LWS_DNSSEC_MAX_RRSET) {
		s->bad = 1;
		return -1;
	}

	r = &s->records[s->count];
	p = r->data;

	p += name_to_wire(name, 255, p);

	*p++ = (uint8_t)(type >> 8);
	*p++ = (uint8_t)type;

	*p++ = 0;
	*p++ = 1; /* IN */

	*p++ = (uint8_t)(s->original_ttl >> 24);
	*p++ = (uint8_t)(s->original_ttl >> 16);
	*p++ = (uint8_t)(s->original_ttl >> 8);
	*p++ = (uint8_t)s->original_ttl;

	*p++ = (uint8_t)(rrpaylen >> 8);
	*p++ = (uint8_t)rrpaylen;

	if ((size_t)(p - r->data) + rrpaylen > sizeof(r->data)) {
		s->bad = 1;
		return -1;
	}

	r->rd_off = (size_t)(p - r->data);

	if (type == LWS_ADNS_RECORD_CNAME) {
		/*
		 * RFC 4034 6.2: the name in a CNAME's RDATA is hashed in
		 * its canonical form, uncompressed and lowercased, whatever
		 * form it took in the packet.  It's decoded the same way
		 * lws_adns_iterate() decoded the target we would chase.
		 */
		char tn[DNS_MAX + 10], *sp = tn;
		int n = lws_adns_parse_label(s->pkt, s->pkt_len, payload,
					     rrpaylen, &sp, sizeof(tn));

		if (n >= 0)
			n = lws_dnssec_name_wire(tn, p,
						 sizeof(r->data) - r->rd_off);
		if (n < 0) {
			s->bad = 1;
			return -1;
		}

		lws_ser_wu16be(p - 2, (uint16_t)n);
		p += n;
	} else if (rrpaylen) {
		memcpy(p, payload, rrpaylen);
		p += rrpaylen;
	}

	r->len = (size_t)(p - r->data);
	s->count++; /* only now is it part of the RRset we hash */

	return 0;
}

static int
lws_dnssec_rrsig_cb(const char *name, void *opaque, uint32_t ttl,
		    adns_query_type_t type, uint16_t rrpaylen,
		    const uint8_t *payload)
{
	struct rrsig_search *s = (struct rrsig_search *)opaque;

	if (type != LWS_ADNS_RECORD_RRSIG)
		return 0;

	if (rrpaylen < 18)
		return 0;

	/*
	 * Only an RRSIG over the type we asked for, and so over the records
	 * we stored from this response, can vouch for them.  Taking whatever
	 * RRSIG came last let a signature over some other RRset (or the
	 * authority section's) stand for unsigned answer records.
	 */
	if (lws_ser_ru16be(&payload[0]) != s->want_type)
		return 0;
	/* Parse RRSIG RDATA payload... */
	s->type_covered = lws_ser_ru16be(&payload[0]);
	s->algorithm = payload[2];
	s->labels = payload[3];
	s->original_ttl = lws_ser_ru32be(&payload[4]);
	s->sig_expiration = lws_ser_ru32be(&payload[8]);
	s->sig_inception = lws_ser_ru32be(&payload[12]);
	s->key_tag = lws_ser_ru16be(&payload[16]);

	/*
	 * The signer name follows the key tag; the caller expands it with the
	 * packet, which we don't have here
	 */

	s->found = 1;
	/* Save the payload offset for full extraction later */
	s->rrsig_payload = payload;
	s->rrsig_paylen = rrpaylen;

	return 0;
}

/*
 * Canonical wire form of a DNS name (RFC 4034 6.2): each label preceded by its
 * length byte, lowercased, terminated by the root label.  Names decoded by
 * lws_adns_parse_label() carry a trailing '.', and the root name is just ".".
 *
 * Returns the count of bytes used at \p wire, or -1.
 */

static int
lws_dnssec_name_wire(const char *name, uint8_t *wire, size_t wire_len)
{
	const char *p = name;
	size_t used = 0;

	while (*p) {
		size_t l = 0;

		while (p[l] && p[l] != '.')
			l++;

		if (l) {
			if (l > 63 || used + l + 1 >= wire_len)
				return -1;

			wire[used++] = (uint8_t)l;

			while (l--) {
				char c = *p++;

				wire[used++] = (uint8_t)((c >= 'A' && c <= 'Z') ?
							 c + 32 : c);
			}
		}

		if (*p == '.')
			p++;
	}

	if (used + 1 > wire_len)
		return -1;
	wire[used++] = 0;

	return (int)used;
}

/*
 * Decode an uncompressed wire name, as found inside RDATA we keep, to both
 * our zone name form (lowercase, no final '.', root is "") in \p text, and
 * its canonical wire form in \p canon.  RFC 4034 3.1.7: the signer name in an
 * RRSIG is never compressed, and a compression pointer inside RDATA we copied
 * out of the packet would point at nothing anyway.
 *
 * Returns the count of wire bytes consumed, or -1.
 */

static int
lws_dnssec_wire_name(const uint8_t *p, size_t len, char *text, size_t tlen,
		     uint8_t *canon, size_t clen)
{
	size_t o = 0, t = 0;

	while (1) {
		uint8_t l;

		if (o >= len || o >= clen)
			return -1;

		l = p[o];
		canon[o] = l;
		o++;

		if (!l)
			break;

		if (l > 63 || o + l > len || o + l >= clen)
			return -1;

		if (t) {
			if (t + 1 >= tlen)
				return -1;
			text[t++] = '.';
		}

		while (l--) {
			uint8_t c = p[o];

			if (c >= 'A' && c <= 'Z')
				c = (uint8_t)(c + 32);
			canon[o++] = c;
			if (t + 1 >= tlen)
				return -1;
			text[t++] = (char)c;
		}
	}

	if (o > 255)
		return -1;

	text[t] = '\0';

	return (int)o;
}

/*
 * The name the zone store keys on: lowercase, without the final '.', and the
 * root is "".
 */

static int
lws_dnssec_zone_norm(const char *in, char *out, size_t olen)
{
	size_t n = strlen(in);

	if (n && in[n - 1] == '.')
		n--;

	if (n >= olen)
		return -1;

	for (size_t i = 0; i < n; i++) {
		char c = in[i];

		if (c == '.' && (!i || in[i - 1] == '.'))
			return -1; /* empty label */

		out[i] = (char)((c >= 'A' && c <= 'Z') ? c + 32 : c);
	}
	out[n] = '\0';

	return 0;
}

static int
lws_dnssec_label_count(const char *name)
{
	int labels = 0;

	while (*name) {
		if (*name == '.') {
			name++;
			continue;
		}
		labels++;
		while (*name && *name != '.')
			name++;
	}

	return labels;
}

/*
 * RFC 4035 5.3.1: the RRSIG's signer name must be the name of the zone that
 * contains the RRset, ie, it must be the owner name itself or an ancestor of
 * it.  Without this check the peer chooses which zone's key we go and fetch
 * to "validate" his answer with, and the name he chooses is then used
 * verbatim as a query name and as a cache key.
 *
 * Both names arrive here as lws_adns_parse_label() produced them, ie, with an
 * optional trailing '.', and the root is "" or ".".
 *
 * Returns 1 if \p signer may sign an RRset owned by \p owner.
 */

static int
lws_dnssec_signer_covers(const char *signer, const char *owner)
{
	size_t sl = strlen(signer), ol = strlen(owner);

	if (sl && signer[sl - 1] == '.')
		sl--;
	if (ol && owner[ol - 1] == '.')
		ol--;

	if (!sl) /* the root zone is an ancestor of everything */
		return 1;

	if (sl > ol)
		return 0;

	if (sl != ol && owner[ol - sl - 1] != '.')
		/* it must break at a label boundary, not mid-label */
		return 0;

	return !strncasecmp(owner + (ol - sl), signer, sl);
}

static int
lws_dnssec_alg_hash(uint8_t alg, enum lws_genhash_types *ht)
{
	switch (alg) {
	case LWS_ADNS_DSA_RSA_SHA256:
	case LWS_ADNS_DSA_ECDSAP256SHA256:
		*ht = LWS_GENHASH_TYPE_SHA256;
		return 0;
	case LWS_ADNS_DSA_RSA_SHA512:
		*ht = LWS_GENHASH_TYPE_SHA512;
		return 0;
	case LWS_ADNS_DSA_ECDSAP384SHA384:
		*ht = LWS_GENHASH_TYPE_SHA384;
		return 0;
	default:
		return -1; /* not an algorithm we validate */
	}
}

/* RFC 4034 Appendix B, over the whole DNSKEY RDATA (not alg 1) */

static uint16_t
lws_dnssec_key_tag(const uint8_t *kn, size_t keylen)
{
	uint32_t ac = 0;
	size_t i;

	for (i = 0; i < keylen; ++i)
		ac += (i & 1) ? kn[i] : (uint32_t)kn[i] << 8;
	ac += (ac >> 16) & 0xFFFF;

	return (uint16_t)(ac & 0xFFFF);
}

/*
 * May this DNSKEY RDATA be used to verify an RRSIG made with \p alg and
 * \p key_tag?  Only a zone key can sign RRsets, and a revoked key signs
 * nothing we believe.
 */

static int
lws_dnssec_key_usable(const uint8_t *kn, size_t keylen, uint8_t alg,
		      uint16_t key_tag)
{
	uint16_t flags;

	if (keylen < 5)
		return 0;

	flags = lws_ser_ru16be(kn);

	return (flags & LWS_DNSKEY_FLAG_ZONE) &&
	       !(flags & LWS_DNSKEY_FLAG_REVOKE) &&
	       kn[2] == LWS_ADNS_DNSKEY_PROTOCOL_DNSSEC && kn[3] == alg &&
	       lws_dnssec_key_tag(kn, keylen) == key_tag;
}

/*
 * Verify \p sig over \p hash with the public key in DNSKEY RDATA \p kn.
 * Returns 0 if it verified.
 */

static int
lws_dnssec_sig_verify(struct lws_context *cx, uint8_t alg, const uint8_t *kn,
		      size_t keylen, const uint8_t *hash, const uint8_t *sig,
		      size_t sig_len)
{
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_MAX_KEYEL_COUNT];
	const uint8_t *key_data = kn + 4;
	size_t key_data_len = keylen - 4;
	enum lws_genhash_types ht;
	int ret = -1;

	if (keylen < 5 || lws_dnssec_alg_hash(alg, &ht))
		return -1;

	memset(el, 0, sizeof(el));

	if (alg == LWS_ADNS_DSA_ECDSAP256SHA256 ||
	    alg == LWS_ADNS_DSA_ECDSAP384SHA384) {
		size_t curvelen = alg == LWS_ADNS_DSA_ECDSAP256SHA256 ? 32 : 48;
		const char *crv = alg == LWS_ADNS_DSA_ECDSAP256SHA256 ?
							"P-256" : "P-384";
		struct lws_genec_ctx ctx;

		if (key_data_len != curvelen * 2) {
			lwsl_info("%s: ECDSA key length %d, expected %d\n",
				  __func__, (int)key_data_len,
				  (int)(curvelen * 2));
			return -1;
		}

		el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = (uint8_t *)crv;
		el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(crv) + 1;
		el[LWS_GENCRYPTO_EC_KEYEL_X].buf = (uint8_t *)key_data;
		el[LWS_GENCRYPTO_EC_KEYEL_X].len = (uint32_t)curvelen;
		el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = (uint8_t *)key_data + curvelen;
		el[LWS_GENCRYPTO_EC_KEYEL_Y].len = (uint32_t)curvelen;

		memset(&ctx, 0, sizeof(ctx));
		if (lws_genecdsa_create(&ctx, cx, NULL))
			return -1;

		if (!lws_genecdsa_set_key(&ctx, el) &&
		    lws_genecdsa_hash_sig_verify_jws(&ctx, hash, ht,
				(int)(curvelen * 8), sig, sig_len) >= 0)
			ret = 0;

		lws_genec_destroy(&ctx);

		return ret;
	}

	/* RSA, RFC 3110 2: exponent length, exponent, modulus */

	{
		struct lws_genrsa_ctx ctx;
		const uint8_t *exp = &key_data[1], *mod;
		size_t explen = key_data[0];

		if (!explen) {
			if (key_data_len < 3)
				return -1;
			explen = lws_ser_ru16be(&key_data[1]);
			exp = &key_data[3];
		}

		if ((size_t)(exp - key_data) + explen >= key_data_len)
			return -1;

		mod = exp + explen;

		el[LWS_GENCRYPTO_RSA_KEYEL_E].buf = (uint8_t *)exp;
		el[LWS_GENCRYPTO_RSA_KEYEL_E].len = (uint32_t)explen;
		el[LWS_GENCRYPTO_RSA_KEYEL_N].buf = (uint8_t *)mod;
		el[LWS_GENCRYPTO_RSA_KEYEL_N].len = (uint32_t)
				(key_data_len - lws_ptr_diff_size_t(mod, key_data));

		memset(&ctx, 0, sizeof(ctx));
		if (lws_genrsa_create(&ctx, el, cx, LGRSAM_PKCS1_1_5, ht))
			return -1;

		if (!lws_genrsa_hash_sig_verify(&ctx, hash, ht, sig, sig_len))
			ret = 0;

		lws_genrsa_destroy(&ctx);
	}

	return ret;
}

/*
 * RFC 4034 5.1.4: a DS record authenticates a DNSKEY if
 *
 *    DS digest == H(canonical owner name | DNSKEY RDATA)
 *
 * \p kn / \p keylen is the whole DNSKEY RDATA (flags, protocol, algorithm and
 * the public key).  Returns 1 if the DS authenticates the key.
 */

static int
lws_dnssec_ds_matches_dnskey(const char *zone, const uint8_t *kn, size_t keylen,
			     uint8_t digest_type, const uint8_t *digest,
			     size_t digest_len)
{
	uint8_t wire[DNS_MAX + 8], res[64];
	enum lws_genhash_types ht;
	struct lws_genhash_ctx hc;
	int n;

	switch (digest_type) {
	case 2: /* SHA-256, RFC 4509 */
		ht = LWS_GENHASH_TYPE_SHA256;
		break;
	case 4: /* SHA-384, RFC 6605 */
		ht = LWS_GENHASH_TYPE_SHA384;
		break;
	default:
		/* SHA-1 (1) and GOST (3) are not acceptable to us */
		return 0;
	}

	if (digest_len != (size_t)lws_genhash_size(ht))
		return 0;

	n = lws_dnssec_name_wire(zone, wire, sizeof(wire));
	if (n < 0)
		return 0;

	if (lws_genhash_init(&hc, ht))
		return 0;

	if (lws_genhash_update(&hc, wire, (size_t)n) ||
	    lws_genhash_update(&hc, kn, keylen)) {
		lws_genhash_destroy(&hc, NULL);

		return 0;
	}

	if (lws_genhash_destroy(&hc, res))
		return 0;

	return !lws_timingsafe_bcmp(res, digest, (uint32_t)digest_len);
}

static void
lws_dnssec_rrs_free(lws_dnssec_rrs_t *r)
{
	lws_free_set_NULL(r->buf);
	r->len = 0;
}

static int
lws_dnssec_rrs_add(lws_dnssec_rrs_t *r, uint16_t type, const uint8_t *rd,
		   uint16_t rdlen)
{
	uint8_t *nb = lws_realloc(r->buf, r->len + 4u + rdlen, "dnssec-rrs");

	if (!nb)
		return -1;

	r->buf = nb;
	lws_ser_wu16be(nb + r->len, type);
	lws_ser_wu16be(nb + r->len + 2, rdlen);
	if (rdlen)
		memcpy(nb + r->len + 4, rd, rdlen);
	r->len += 4u + rdlen;

	return 0;
}

/* iterate the records in \p r; returns 0 at the end */

static int
lws_dnssec_rrs_next(const lws_dnssec_rrs_t *r, size_t *pos, uint16_t *type,
		    const uint8_t **rd, uint16_t *rdlen)
{
	uint16_t l;

	if (*pos + 4 > r->len)
		return 0;

	/* bound the length itself, not a sum, so it's clean when we return */
	l = lws_ser_ru16be(r->buf + *pos + 2);
	if (l > r->len - *pos - 4)
		return 0;

	*type = lws_ser_ru16be(r->buf + *pos);
	*rdlen = l;
	*rd = r->buf + *pos + 4;
	*pos += 4u + l;

	return 1;
}

/* the records in \p from of \p type, appended to \p to */

static int
lws_dnssec_rrs_take(lws_dnssec_rrs_t *to, const lws_dnssec_rrs_t *from,
		    uint16_t type)
{
	const uint8_t *rd;
	uint16_t t, rdlen;
	size_t pos = 0;

	while (lws_dnssec_rrs_next(from, &pos, &t, &rd, &rdlen))
		if (t == type && lws_dnssec_rrs_add(to, t, rd, rdlen))
			return -1;

	return 0;
}

/*
 * Copy the \p type records a query for \p name just left in the cache, and
 * the RRSIGs over them, into \p out.  Returns 0 if there were any.
 */

static int
lws_dnssec_rrs_from_cache(lws_async_dns_t *dns, const char *name,
			  uint16_t type, lws_dnssec_rrs_t *out)
{
	lws_adns_cache_t *c = lws_adns_get_cache(dns, name, type, 0);
	lws_adns_rr_t *rr;

	if (!c)
		return -1;

	for (rr = c->rr_results; rr; rr = rr->next) {
		const uint8_t *rd = (const uint8_t *)&rr[1];

		if ((rr->type == type ||
		     (rr->type == LWS_ADNS_RECORD_RRSIG && rr->paylen >= 2 &&
		      lws_ser_ru16be(rd) == type)) &&
		    lws_dnssec_rrs_add(out, (uint16_t)rr->type, rd, rr->paylen))
			return -1;
	}

	return 0;
}

/*
 * The ICANN root zone KSK DS records, our trust anchors unless the user set
 * some others with lws_async_dns_dnssec_set_root_anchors().
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

/* the trust anchors as a DS RRset, as if they were the root's DS */

static int
lws_dnssec_anchors(lws_async_dns_t *dns, lws_dnssec_rrs_t *r)
{
	size_t i;

	if (!dns->dnssec_anchors) {
		lws_dnssec_rrs_t b = { NULL, 0 };

		for (i = 0; i < LWS_ARRAY_SIZE(lws_adns_root_ds); i++) {
			uint8_t rd[4 + 32];

			lws_ser_wu16be(rd, lws_adns_root_ds[i].keytag);
			rd[2] = lws_adns_root_ds[i].algo;
			rd[3] = lws_adns_root_ds[i].digest_type;

			if (lws_hex_to_byte_array(lws_adns_root_ds[i].digest_hex,
						  rd + 4, 32) != 32 ||
			    lws_dnssec_rrs_add(&b, LWS_ADNS_RECORD_DS, rd,
					       sizeof(rd))) {
				lws_dnssec_rrs_free(&b);
				return -1;
			}
		}

		dns->dnssec_anchors = b.buf;
		dns->dnssec_anchors_len = b.len;
	}

	r->buf = dns->dnssec_anchors;
	r->len = dns->dnssec_anchors_len;

	return 0;
}

/*
 * Is DNSKEY RDATA \p kn authenticated by one of zone \p z's DS records, or for
 * the root, by one of our trust anchors?
 */

static int
lws_dnssec_zone_ds_matches(lws_dnssec_zone_t *z, const uint8_t *kn,
			   size_t keylen)
{
	lws_dnssec_rrs_t dsset;
	const uint8_t *rd;
	uint16_t t, rdlen, tag;
	size_t pos = 0;

	if (keylen < 5)
		return 0;

	if (*z->name)
		dsset = z->ds;
	else if (lws_dnssec_anchors(z->dns, &dsset))
		return 0;

	tag = lws_dnssec_key_tag(kn, keylen);

	while (lws_dnssec_rrs_next(&dsset, &pos, &t, &rd, &rdlen))
		if (t == LWS_ADNS_RECORD_DS && rdlen > 4 &&
		    lws_ser_ru16be(rd) == tag && rd[2] == kn[3] &&
		    lws_dnssec_ds_matches_dnskey(z->name, kn, keylen, rd[3],
						 rd + 4, (size_t)rdlen - 4))
			return 1;

	return 0;
}

/*
 * RFC 4034 3.1.8.1: the RRSIG RDATA up to the signature, with the signer name
 * canonical, then each RR of the set in canonical form and order, with the
 * original TTL
 */

static int
lws_dnssec_rrsig_hash(enum lws_genhash_types ht, const uint8_t *rrsig,
		      const uint8_t *signer, size_t signer_len,
		      const uint8_t *owner, size_t owner_len, uint16_t type,
		      const uint8_t * const *recs, const uint16_t *lens,
		      int nrecs, uint8_t *hash)
{
	struct lws_genhash_ctx hc;
	uint8_t hdr[10];
	int j;

	lws_ser_wu16be(hdr, type);
	lws_ser_wu16be(hdr + 2, 1); /* IN */
	memcpy(hdr + 4, rrsig + 4, 4); /* the original TTL */

	if (lws_genhash_init(&hc, ht))
		return -1;

	if (lws_genhash_update(&hc, rrsig, 18) ||
	    lws_genhash_update(&hc, signer, signer_len))
		goto bail;

	for (j = 0; j < nrecs; j++) {
		lws_ser_wu16be(hdr + 8, lens[j]);
		if (lws_genhash_update(&hc, owner, owner_len) ||
		    lws_genhash_update(&hc, hdr, sizeof(hdr)) ||
		    lws_genhash_update(&hc, recs[j], lens[j]))
			goto bail;
	}

	return lws_genhash_destroy(&hc, hash);

bail:
	lws_genhash_destroy(&hc, NULL);

	return -1;
}

/*
 * Is there an RRSIG in \p mat over the \p type RRset of \p owner, also in
 * \p mat, that was made by \p signer with a key in \p keyset, and verifies?
 * If \p ksk_of is given, the key must also be authenticated by that zone's DS.
 *
 * On success, *expires is set to when the RRset stops being valid: the
 * earlier of the signature's expiry and its original TTL from now.
 *
 * Returns 0 if the RRset verified.
 */

static int
lws_dnssec_rrs_verify(struct lws_context *cx, const char *owner, uint16_t type,
		      const lws_dnssec_rrs_t *mat, const char *signer,
		      const lws_dnssec_rrs_t *keyset,
		      lws_dnssec_zone_t *ksk_of, uint32_t *expires)
{
	const uint8_t *recs[LWS_DNSSEC_MAX_RRSET], *rd;
	uint16_t lens[LWS_DNSSEC_MAX_RRSET], t, rdlen;
	uint32_t now = (uint32_t)lws_now_secs();
	uint8_t ow[DNS_MAX + 2];
	int nrecs = 0, owl, labels, i;
	size_t pos = 0;

	owl = lws_dnssec_name_wire(owner, ow, sizeof(ow));
	if (owl < 0)
		return -1;
	labels = lws_dnssec_label_count(owner);

	/* the RRset, in canonical order */

	while (lws_dnssec_rrs_next(mat, &pos, &t, &rd, &rdlen)) {
		if (t != type)
			continue;
		if (nrecs == LWS_DNSSEC_MAX_RRSET)
			return -1;

		for (i = nrecs; i > 0 && lws_dnssec_rdata_cmp(rd, rdlen,
					recs[i - 1], lens[i - 1]) < 0; i--) {
			recs[i] = recs[i - 1];
			lens[i] = lens[i - 1];
		}
		recs[i] = rd;
		lens[i] = rdlen;
		nrecs++;
	}

	if (!nrecs)
		return -1;

	pos = 0;
	while (lws_dnssec_rrs_next(mat, &pos, &t, &rd, &rdlen)) {
		uint8_t hash[64], scanon[256];
		uint32_t ottl, sexp, sinc;
		enum lws_genhash_types ht;
		char sname[DNS_MAX];
		const uint8_t *k;
		uint16_t kt, klen, tag;
		size_t kpos = 0;
		int n;

		if (t != LWS_ADNS_RECORD_RRSIG || rdlen < 19 ||
		    lws_ser_ru16be(rd) != type ||
		    /* no wildcard expansion of the records we walk with */
		    rd[3] != labels ||
		    lws_dnssec_alg_hash(rd[2], &ht))
			continue;

		ottl = lws_ser_ru32be(rd + 4);
		sexp = lws_ser_ru32be(rd + 8);
		sinc = lws_ser_ru32be(rd + 12);
		tag  = lws_ser_ru16be(rd + 16);

		/* RFC 4035 5.3.1, in RFC 1982 serial arithmetic */
		if ((int32_t)(now - sinc) < 0 || (int32_t)(sexp - now) < 0)
			continue;

		n = lws_dnssec_wire_name(rd + 18, (size_t)rdlen - 18, sname,
					 sizeof(sname), scanon, sizeof(scanon));
		if (n < 0 || strcmp(sname, signer) ||
		    (size_t)rdlen - 18 - (size_t)n < 1)
			continue;

		if (lws_dnssec_rrsig_hash(ht, rd, scanon, (size_t)n, ow,
					  (size_t)owl, type, recs, lens, nrecs,
					  hash))
			return -1;

		while (lws_dnssec_rrs_next(keyset, &kpos, &kt, &k, &klen)) {
			if (kt != LWS_ADNS_RECORD_DNSKEY ||
			    !lws_dnssec_key_usable(k, klen, rd[2], tag) ||
			    (ksk_of && !lws_dnssec_zone_ds_matches(ksk_of, k,
								   klen)))
				continue;

			if (lws_dnssec_sig_verify(cx, rd[2], k, klen, hash,
						  rd + 18 + n,
						  (size_t)rdlen - 18 - (size_t)n))
				continue;

			/* sexp - now is positive, we checked above */
			*expires = now + (ottl < sexp - now ? ottl : sexp - now);

			return 0;
		}
	}

	return -1;
}

/* ---- the store of authenticated zones ---- */

static void
lws_dnssec_zone_destroy(lws_dnssec_zone_t *z)
{
	lws_sul_cancel(&z->sul);
	/* the fetch we may have in flight must not call back into us */
	lws_async_dns_cancel_by_opaque(z->dns->cx, z);
	lws_dll2_remove(&z->pw.list);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&z->waiters)) {
		lws_dll2_remove(d);
	} lws_end_foreach_dll_safe(d, d1);

	lws_dnssec_rrs_free(&z->mat);
	lws_dnssec_rrs_free(&z->ds);
	lws_dnssec_rrs_free(&z->keys);
	lws_dll2_remove(&z->list);
	lws_free(z);
}

static int
lws_dnssec_zone_is_settled(const lws_dnssec_zone_t *z)
{
	return z->state == LDZ_TRUSTED || z->state == LDZ_FAILED;
}

/*
 * Find, or make, the store's entry for zone \p name.  A settled entry that
 * has expired is reset, so it is walked again.  Returns NULL if the name is
 * unusable, or the store is full of zones that are still in use.
 */

static lws_dnssec_zone_t *
lws_dnssec_zone_get(lws_async_dns_t *dns, const char *name)
{
	lws_dnssec_zone_t *z = NULL, *victim = NULL;
	uint32_t now = (uint32_t)lws_now_secs();
	char nm[DNS_MAX];

	if (lws_dnssec_zone_norm(name, nm, sizeof(nm)))
		return NULL;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->dnssec_zones)) {
		lws_dnssec_zone_t *e = lws_container_of(d, lws_dnssec_zone_t,
							list);

		if (!strcmp(e->name, nm)) {
			z = e;
			break;
		}

		/* the least recently used one we could let go of */
		if (lws_dnssec_zone_is_settled(e) && !e->settling &&
		    !lws_dll2_count(&e->waiters))
			victim = e;
	} lws_end_foreach_dll(d);

	if (z) {
		if (lws_dnssec_zone_is_settled(z) && !z->settling &&
		    (int32_t)(z->expires - now) <= 0) {
			lwsl_info("%s: zone '%s' expired\n", __func__, nm);
			lws_dnssec_rrs_free(&z->ds);
			lws_dnssec_rrs_free(&z->keys);
			z->state = LDZ_IDLE;
		}

		lws_dll2_remove(&z->list);
		lws_dll2_add_head(&z->list, &dns->dnssec_zones);

		return z;
	}

	if (lws_dll2_count(&dns->dnssec_zones) >= LWS_DNSSEC_MAX_ZONES) {
		if (!victim) {
			lwsl_notice("%s: zone store full\n", __func__);
			return NULL;
		}
		lws_dnssec_zone_destroy(victim);
	}

	z = lws_zalloc(sizeof(*z), "dnssec-zone");
	if (!z)
		return NULL;

	z->dns = dns;
	lws_strncpy(z->name, nm, sizeof(z->name));
	lws_dll2_add_head(&z->list, &dns->dnssec_zones);

	return z;
}

/* start walking the chain for \p z, if nothing did yet */

static void
lws_dnssec_zone_kick(lws_dnssec_zone_t *z)
{
	if (z->state == LDZ_IDLE)
		lws_sul_schedule(z->dns->cx, 0, &z->sul,
				 lws_dnssec_zone_sul_cb, 1);
}

static void
lws_dnssec_zone_settle(lws_dnssec_zone_t *z, int trusted)
{
	struct lws_dll2 *d;

	if (z->stale)
		/* the anchors it was walked from are gone */
		trusted = 0;

	lws_dnssec_rrs_free(&z->mat);
	lws_dnssec_rrs_free(&z->ds);

	if (trusted) {
		lwsl_info("%s: zone '%s' authenticated\n", __func__, z->name);
		z->state = LDZ_TRUSTED;
	} else {
		lwsl_notice("%s: zone '%s' not authenticated\n", __func__,
			    *z->name ? z->name : ".");
		lws_dnssec_rrs_free(&z->keys);
		z->state = LDZ_FAILED;
		z->expires = (uint32_t)lws_now_secs() +
				(z->stale ? 0 : LWS_DNSSEC_FAIL_HOLD_SECS);
	}
	z->stale = 0;

	/*
	 * A waiter may complete a query, ie, run user code that issues more
	 * queries: settling keeps us out of the store's eviction meanwhile
	 */

	z->settling = 1;
	while ((d = lws_dll2_get_head(&z->waiters))) {
		lws_dnssec_zone_waiter_t *w = lws_container_of(d,
					lws_dnssec_zone_waiter_t, list);

		lws_dll2_remove(d);
		w->cb(w, z);
	}
	z->settling = 0;
}

static struct lws *
lws_dnssec_zone_fetch_cb(struct lws *wsi, const char *name,
			 const struct addrinfo *ai, int n, void *opaque)
{
	lws_dnssec_zone_t *z = (lws_dnssec_zone_t *)opaque;

	(void)name;

	if (ai)
		lws_async_dns_freeaddrinfo(&ai);

	/*
	 * Take what we were answered now, while the cache entry is certainly
	 * still there; what it means is worked out from the sul
	 */

	if (n >= 0 && (n & ~LWS_ADNS_DNSSEC_VALID) == LADNS_RET_FOUND)
		z->step_ok = !lws_dnssec_rrs_from_cache(z->dns,
				*z->name ? z->name : ".",
				z->state == LDZ_FETCH_DS ? LWS_ADNS_RECORD_DS :
							   LWS_ADNS_RECORD_DNSKEY,
				&z->mat);

	lws_sul_schedule(z->dns->cx, 0, &z->sul, lws_dnssec_zone_sul_cb, 1);

	return wsi ? wsi : LADNS_NO_WSI_BUT_OK;
}

/*
 * Fetch our DS or DNSKEY RRset with its RRSIGs.  The query itself doesn't
 * validate, since what it brings back is exactly what we are validating, and
 * it skips the cache, since what is there may have come from a query that
 * didn't ask for the RRSIGs.
 */

static void
lws_dnssec_zone_fetch(lws_dnssec_zone_t *z, uint16_t type)
{
	z->state = type == LWS_ADNS_RECORD_DS ? LDZ_FETCH_DS : LDZ_FETCH_DNSKEY;
	z->step_ok = 0;
	lws_dnssec_rrs_free(&z->mat);

	if (lws_async_dns_query(z->dns->cx, 0, *z->name ? z->name : ".",
				(adns_query_type_t)(type |
						LWS_ADNS_WANT_DNSSEC |
						LWS_ADNS_INDICATE_LACKS_DNSSEC |
						LWS_ADNS_NOCACHE),
				lws_dnssec_zone_fetch_cb, NULL, z, NULL) !=
							LADNS_RET_CONTINUING)
		/*
		 * It's over already, and if the callback got called, it
		 * scheduled us: this is only for the case it didn't
		 */
		lws_sul_schedule(z->dns->cx, 0, &z->sul,
				 lws_dnssec_zone_sul_cb, 1);
}

/* the zone that signed our DS RRset has been authenticated, or failed to be */

static void
lws_dnssec_zone_parent_settled(lws_dnssec_zone_waiter_t *w,
			       lws_dnssec_zone_t *p)
{
	lws_dnssec_zone_t *z = lws_container_of(w, lws_dnssec_zone_t, pw);
	uint32_t exp;

	z->step_ok = p->state == LDZ_TRUSTED &&
		     !lws_dnssec_rrs_verify(z->dns->cx, z->name,
					    LWS_ADNS_RECORD_DS, &z->mat,
					    p->name, &p->keys, NULL, &exp) &&
		     !lws_dnssec_rrs_take(&z->ds, &z->mat, LWS_ADNS_RECORD_DS);

	if (z->step_ok)
		/* our keys can't outlive the parent keys that vouched for them */
		z->expires = (int32_t)(p->expires - exp) < 0 ? p->expires : exp;
	else
		lwsl_notice("%s: DS RRset of '%s' not signed by a key of '%s'\n",
			    __func__, z->name, *p->name ? p->name : ".");

	lws_sul_schedule(z->dns->cx, 0, &z->sul, lws_dnssec_zone_sul_cb, 1);
}

/*
 * We have our DS RRset, but not authenticated: its RRSIG names the zone that
 * has to vouch for it, which must be a proper ancestor of ours.  Wait on that
 * zone being authenticated in turn.
 */

static int
lws_dnssec_zone_find_parent(lws_dnssec_zone_t *z)
{
	char sname[DNS_MAX];
	lws_dnssec_zone_t *p;
	int found = 0;
	uint8_t scanon[256];
	const uint8_t *rd;
	uint16_t t, rdlen;
	size_t pos = 0;

	while (!found && lws_dnssec_rrs_next(&z->mat, &pos, &t, &rd, &rdlen))
		if (t == LWS_ADNS_RECORD_RRSIG && rdlen > 18 &&
		    lws_ser_ru16be(rd) == LWS_ADNS_RECORD_DS &&
		    lws_dnssec_wire_name(rd + 18, (size_t)rdlen - 18, sname,
					 sizeof(sname), scanon,
					 sizeof(scanon)) > 0 &&
		    strcmp(sname, z->name) &&
		    lws_dnssec_signer_covers(sname, z->name))
			found = 1;

	if (!found) {
		lwsl_notice("%s: no usable RRSIG over DS of '%s'\n", __func__,
			    z->name);
		return -1;
	}

	p = lws_dnssec_zone_get(z->dns, sname);
	if (!p)
		return -1;

	z->state = LDZ_WAIT_PARENT;
	z->step_ok = 0;
	z->pw.cb = lws_dnssec_zone_parent_settled;

	if (lws_dnssec_zone_is_settled(p)) {
		lws_dnssec_zone_parent_settled(&z->pw, p);

		return 0;
	}

	lws_dll2_add_tail(&z->pw.list, &p->waiters);
	lws_dnssec_zone_kick(p);

	return 0;
}

/*
 * We have our DNSKEY RRset: it's authenticated if its RRSIG verifies with a
 * key in it that one of our authenticated DS (for the root, a trust anchor)
 * vouches for.
 */

static int
lws_dnssec_zone_take_keys(lws_dnssec_zone_t *z)
{
	uint32_t exp;

	if (lws_dnssec_rrs_verify(z->dns->cx, z->name, LWS_ADNS_RECORD_DNSKEY,
				  &z->mat, z->name, &z->mat, z, &exp)) {
		lwsl_notice("%s: DNSKEY RRset of '%s' not signed by a key its "
			    "DS vouches for\n", __func__,
			    *z->name ? z->name : ".");
		return -1;
	}

	lws_dnssec_rrs_free(&z->keys);
	if (lws_dnssec_rrs_take(&z->keys, &z->mat, LWS_ADNS_RECORD_DNSKEY))
		return -1;

	if (!*z->name || (int32_t)(exp - z->expires) < 0)
		z->expires = exp;

	return 0;
}

static void
lws_dnssec_zone_sul_cb(lws_sorted_usec_list_t *sul)
{
	lws_dnssec_zone_t *z = lws_container_of(sul, lws_dnssec_zone_t, sul);

	switch (z->state) {
	case LDZ_IDLE:
		lws_dnssec_zone_fetch(z, *z->name ? LWS_ADNS_RECORD_DS :
						    LWS_ADNS_RECORD_DNSKEY);
		return;

	case LDZ_FETCH_DS:
		if (!z->step_ok || lws_dnssec_zone_find_parent(z))
			break;
		return;

	case LDZ_WAIT_PARENT:
		if (!z->step_ok)
			break;
		lws_dnssec_zone_fetch(z, LWS_ADNS_RECORD_DNSKEY);
		return;

	case LDZ_FETCH_DNSKEY:
		if (!z->step_ok || lws_dnssec_zone_take_keys(z))
			break;
		lws_dnssec_zone_settle(z, 1);
		return;

	default:
		return;
	}

	lws_dnssec_zone_settle(z, 0);
}

/* ---- validating an RRset from a response ---- */

static void
lws_dnssec_vctx_free(struct lws_dnssec_val_ctx *vctx)
{
	unsigned int idx = lws_dnssec_vctx_idx(vctx->resp_bit);

	lws_dll2_remove(&vctx->zw.list);
	if (vctx->original_q &&
	    vctx->original_q->dnssec_vctx_waiting[idx] == vctx)
		vctx->original_q->dnssec_vctx_waiting[idx] = NULL;

	lws_free(vctx);
}

/* does the RRSIG verify with one of the signer zone's authenticated keys? */

static int
lws_dnssec_vctx_check(const struct lws_dnssec_val_ctx *vctx,
		      const lws_dnssec_zone_t *z, struct lws_context *cx)
{
	const uint8_t *k;
	uint16_t t, klen;
	size_t pos = 0;

	if (z->state != LDZ_TRUSTED)
		return -1;

	while (lws_dnssec_rrs_next(&z->keys, &pos, &t, &k, &klen))
		if (t == LWS_ADNS_RECORD_DNSKEY &&
		    lws_dnssec_key_usable(k, klen, vctx->algorithm,
					  vctx->key_tag) &&
		    !lws_dnssec_sig_verify(cx, vctx->algorithm, k, klen,
					   vctx->hash, vctx->sig_buf,
					   vctx->sig_len))
			return 0;

	lwsl_notice("%s: RRSIG does not verify with a key of '%s'\n", __func__,
		    *z->name ? z->name : ".");

	return -1;
}

/*
 * An RRset of q validated with an RRSIG good until \p expires and a key of
 * zone \p z: the results can't be believed past either
 */

static void
lws_dnssec_q_validated(lws_adns_q_t *q, uint32_t expires,
		       const lws_dnssec_zone_t *z)
{
	if ((int32_t)(z->expires - expires) < 0)
		expires = z->expires;

	if (!q->dnssec_expires || (int32_t)(expires - q->dnssec_expires) < 0)
		q->dnssec_expires = expires;
}

/*
 * The zone our RRSIG's signer names settled while our query was suspended
 * waiting on it: finish this response's validation, and if that was all the
 * query was waiting for, complete it.
 */

static void
lws_dnssec_vctx_settled(lws_dnssec_zone_waiter_t *w, lws_dnssec_zone_t *z)
{
	struct lws_dnssec_val_ctx *vctx = lws_container_of(w,
					struct lws_dnssec_val_ctx, zw);
	lws_adns_q_t *q = vctx->original_q;
	uint8_t rb = vctx->resp_bit;
	int valid = !lws_dnssec_vctx_check(vctx, z, q->context);
	char target[DNS_MAX];

	if (valid)
		lws_dnssec_q_validated(q, vctx->expires, z);

	/* restarting q frees any vctx it still has, so take a copy */
	lws_strncpy(target, vctx->cname, sizeof(target));
	lws_dnssec_vctx_free(vctx);

	q->dnssec_verify_rrsig = (uint8_t)(q->dnssec_verify_rrsig & ~rb);

	if (*target) {
		/*
		 * It was the queried name's CNAME that we validated: only
		 * now may we go and ask about where it points
		 */
		q->dnssec_chk_cname = 0;
		if (valid && !lws_adns_q_cname_restart(q, target))
			return;

		goto fail;
	}

	if (valid) {
		q->dnssec_valid_mask = (uint8_t)(q->dnssec_valid_mask | rb);

		/*
		 * The other half of an A / AAAA pair may still be to come,
		 * or be validating: only the last one out completes the query
		 */

		if (q->responded != q->asked || q->dnssec_verify_rrsig)
			return;

		if (q->dnssec_need_mask && !q->dnssec_stale &&
		    (q->dnssec_valid_mask & q->dnssec_need_mask) ==
						q->dnssec_need_mask) {
			q->dnssec_valid = 1;
			/* validated: the cache entry may be found now */
			if (q->firstcache)
				q->firstcache->incomplete = 0;
			lws_async_dns_complete(q, q->firstcache);
			q->go_nogo = METRES_GO;
			lws_adns_q_destroy(q);

			return;
		}

		lwsl_notice("%s: not all responses validated\n", __func__);
	}

fail:
	q->go_nogo = METRES_NOGO;
	lws_async_dns_complete(q, NULL);
	if (q->firstcache) {
		lws_adns_cache_destroy(q->firstcache);
		q->firstcache = NULL;
	}
	lws_adns_q_destroy(q);
}

/*
 * Called from lws_adns_q_destroy() for every query, so a validation context
 * can't outlive the query it belongs to, or be left on a zone's waiters
 */

void
lws_adns_dnssec_q_destroy(lws_adns_q_t *q)
{
	unsigned int n;

	for (n = 0; n < LWS_ARRAY_SIZE(q->dnssec_vctx_waiting); n++)
		if (q->dnssec_vctx_waiting[n])
			lws_dnssec_vctx_free(q->dnssec_vctx_waiting[n]);
}

/*
 * Validate the \p want_type RRset of the queried name in the response at
 * \p pkt, which is response \p resp of q.  If \p cname is given, the RRset is
 * the queried name's CNAME, pointing to \p cname.
 *
 * \p stored is the count of records of the RRset we act on: the RRset we
 * hash must be exactly those, no more and no fewer.
 *
 * Returning > 0 means validation is in progress (the signer's zone is
 * still being authenticated).
 * Returning 0 means validation succeeded.
 * Returning < 0 means validation failed.
 */

static int
lws_dnssec_verify_rrset(lws_adns_q_t *q, const uint8_t *pkt, size_t len,
			uint8_t resp, uint16_t want_type, int stored,
			const char *cname)
{
	struct rrsig_search s;

	/* Find RRSIGs in the packet relating to the question */
	memset(&s, 0, sizeof(s));
	s.q = q;
	s.want_type = want_type;

	/*
	 * The name we asked about in the query this responds to: after a
	 * CNAME was chased, that's the CNAME target, and it's that name's
	 * records that have to validate
	 */
	const char *nmcname = ((const char *)&q[1]);

	lws_adns_iterate(q, pkt, (int)len, nmcname, lws_dnssec_rrsig_cb, &s,
			 NULL);

	if (!s.found) {
		/* No RRSIG found. If we REQUIRE DNSSEC, this is a failure if the zone should be signed.
		 * For now, tolerate it or reject based on mode.
		 */
		lwsl_notice("%s: missing RRSIG\n", __func__);

		return -1;
	}

	/* Parse the signer name from the previously found payload. */
	if (s.rrsig_payload) {
		struct lws_genhash_ctx hash_ctx;
		enum lws_genhash_types hashtype;
		const uint8_t *p = s.rrsig_payload + 18; /* After key tag */
		struct lws_dnssec_val_ctx *vctx;
		char *sp = s.signer_name;
		uint32_t rrsig_expires;
		lws_dnssec_zone_t *z;
		int n = lws_adns_parse_label(pkt, (int)len, p,
					     (int)(len - lws_ptr_diff_size_t(p, pkt)),
					     &sp, sizeof(s.signer_name));
		if (n < 0) {
			lwsl_notice("%s: bad signer name\n", __func__);
			return -1;
		}

		if (!lws_dnssec_signer_covers(s.signer_name, nmcname)) {
			lwsl_notice("%s: RRSIG signer '%s' does not cover '%s'\n",
				    __func__, s.signer_name, nmcname);

			return -1;
		}

		/*
		 * RFC 4035 5.3.1: the labels field counts the labels of the
		 * owner name the signature was made over; fewer means it was
		 * made over a wildcard, more is simply invalid
		 */

		if ((int)s.labels > lws_dnssec_label_count(nmcname)) {
			lwsl_notice("%s: RRSIG labels %d > %d\n", __func__,
				    s.labels, lws_dnssec_label_count(nmcname));

			return -1;
		}

		lwsl_info("%s: Found RRSIG covering %d signed by %s\n",
				__func__, s.type_covered, s.signer_name);

		int rrsig_rdata_up_to_sig_len = 18 + n;
		int sig_len = s.rrsig_paylen - rrsig_rdata_up_to_sig_len;

		if (sig_len < 0) {
			lwsl_notice("%s: RRSIG payload too short\n", __func__);
			return -1;
		}

		if (lws_dnssec_alg_hash(s.algorithm, &hashtype))
			return -1;

		/*
		 * RFC 4035 5.3.1: the validator's current time must lie within
		 * the RRSIG inception .. expiration window, using RFC 1982
		 * serial arithmetic.  Without this an expired (or not yet
		 * valid) signature captured earlier validates forever.
		 */
		{
			uint32_t now = (uint32_t)lws_now_secs();

			if ((int32_t)(now - s.sig_inception) < 0 ||
			    (int32_t)(s.sig_expiration - now) < 0) {
				lwsl_notice("%s: RRSIG outside validity window\n",
					    __func__);
				return -1;
			}

			/*
			 * RFC 4035 5.3.3: an RRset validated with it is good
			 * until the earlier of the signature's expiration
			 * and its Original TTL from now; the TTL on the wire
			 * isn't signed.  sig_expiration - now is positive,
			 * we just checked.
			 */
			rrsig_expires = now + (s.original_ttl <
					       s.sig_expiration - now ?
						s.original_ttl :
						s.sig_expiration - now);
		}

		if (lws_genhash_init(&hash_ctx, hashtype))
			return -1;

		/* s.rrsig_payload points to the RRSIG type covered through rdata */

		if (lws_genhash_update(&hash_ctx, s.rrsig_payload, (size_t)rrsig_rdata_up_to_sig_len)) {
			lws_genhash_destroy(&hash_ctx, NULL);
			return -1;
		}

		struct rrset_search rs;
		memset(&rs, 0, sizeof(rs));
		rs.pkt = pkt;
		rs.pkt_len = (int)len;
		rs.type_covered = s.type_covered;
		rs.name = nmcname;
		rs.original_ttl = s.original_ttl;

		lws_adns_iterate(q, pkt, (int)len, nmcname, lws_dnssec_rrset_cb,
				 &rs, NULL);

		/*
		 * What the signature covers must be exactly what we act on:
		 * the records we stored, or for a CNAME, the one record
		 * (RFC 2181 10.1) that lws_adns_iterate() gave us the target
		 * of.  A record we couldn't hash fails it.
		 */
		if (rs.bad || rs.count != stored) {
			lwsl_notice("%s: RRset of %d (%d stored)%s\n", __func__,
				    rs.count, stored, rs.bad ? ", unhashable" : "");
			lws_genhash_destroy(&hash_ctx, NULL);
			return -1;
		}

		qsort(rs.records, (size_t)rs.count, sizeof(struct rr_canonical), cmp_rr);

		for (int i = 0; i < rs.count; i++) {
			if (lws_genhash_update(&hash_ctx, rs.records[i].data, rs.records[i].len)) {
				lws_genhash_destroy(&hash_ctx, NULL);
				return -1;
			}
		}

		vctx = lws_zalloc(sizeof(*vctx), "dnssec_val");
		if (!vctx) {
			lws_genhash_destroy(&hash_ctx, NULL);
			return -1;
		}

		if (lws_genhash_destroy(&hash_ctx, vctx->hash)) {
			lws_free(vctx);
			return -1;
		}

		vctx->resp_bit		= resp;
		vctx->algorithm		= s.algorithm;
		vctx->key_tag		= s.key_tag;
		vctx->expires		= rrsig_expires;
		if (cname)
			lws_strncpy(vctx->cname, cname, sizeof(vctx->cname));

		if (sig_len > (int)sizeof(vctx->sig_buf)) {
			lwsl_err("%s: signature too large for buffer\n", __func__);
			lws_free(vctx);
			return -1;
		}
		vctx->sig_len = (uint16_t)sig_len;
		memcpy(vctx->sig_buf, s.rrsig_payload + rrsig_rdata_up_to_sig_len,
		       (size_t)sig_len);

		/*
		 * The RRSIG can only be checked with a key of the signer's
		 * zone that was authenticated down the chain from the root.
		 */

		z = lws_dnssec_zone_get(q->dns, s.signer_name);
		if (!z) {
			lws_free(vctx);
			return -1;
		}

		if (lws_dnssec_zone_is_settled(z)) {
			n = lws_dnssec_vctx_check(vctx, z, q->context);
			if (!n)
				lws_dnssec_q_validated(q, rrsig_expires, z);
			lws_free(vctx);

			return n ? -1 : 0;
		}

		/*
		 * We suspend completion of q until the zone settles.  Our
		 * response's bit in q->dnssec_verify_rrsig is clear here (our
		 * caller only calls us when it is).
		 */

		vctx->original_q = q;
		vctx->zw.cb = lws_dnssec_vctx_settled;
		lws_dll2_add_tail(&vctx->zw.list, &z->waiters);
		q->dnssec_verify_rrsig = (uint8_t)(q->dnssec_verify_rrsig | resp);
		q->dnssec_vctx_waiting[lws_dnssec_vctx_idx(resp)] = vctx;
		lws_dnssec_zone_kick(z);

		return 1;
	}

	return 0;
}

int
lws_adns_dnssec_verify(lws_adns_q_t *q, const uint8_t *pkt, size_t len,
		       uint8_t resp, int stored)
{
	/*
	 * This is the entry point called from async-dns-parse.c
	 * when an A or AAAA response with an RRSIG is received (or generally
	 * any type we want to validate).
	 *
	 * Returning > 0 means validation is in progress (the signer's zone is
	 * still being authenticated).
	 * Returning 0 means validation succeeded or DNSSEC is off/tolerate.
	 * Returning < 0 means validation failed.
	 */

	/*
	 * A query that must validate (REQUIRE, or asked with WANT_DNSSEC)
	 * goes through the whole process whatever the context mode: under
	 * OFF this used to return 0 at once, which the caller took as
	 * "validated" and reported as LWS_ADNS_DNSSEC_VALID.
	 */
	if (!lws_adns_q_validates(q))
		return 0;

	return lws_dnssec_verify_rrset(q, pkt, len, resp,
				       lws_adns_q_resp_type(q, resp), stored,
				       NULL);
}

int
lws_adns_dnssec_cname(lws_adns_q_t *q, const uint8_t *pkt, size_t len,
		      uint8_t resp, const char *target)
{
	/*
	 * An unsigned CNAME, or one signed by a zone that isn't the queried
	 * name's, would let whoever answered point a validating lookup at a
	 * name of his choosing... whose own answers he can then sign
	 * perfectly well.  So the CNAME RRset of the queried name has to
	 * validate before we ask about the target, and then the target's
	 * answers have to validate on their own (lws_adns_q_cname_restart()
	 * forgets all validation state).
	 */
	int n = lws_dnssec_verify_rrset(q, pkt, len, resp,
					LWS_ADNS_RECORD_CNAME, 1, target);

	if (n < 0)
		return -1;

	if (n) {
		/*
		 * Waiting for the CNAME's zone to be authenticated: the
		 * vctx restarts or fails q when it settles.  Meanwhile the
		 * old name's answers are ignored, so stop retrying it.
		 */
		q->dnssec_chk_cname = 1;
		lws_sul_cancel(&q->sul);

		return 0;
	}

	return lws_adns_q_cname_restart(q, target) ? -1 : 0;
}

void
lws_adns_dnssec_deinit(lws_async_dns_t *dns)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->dnssec_zones)) {
		lws_dnssec_zone_destroy(lws_container_of(d, lws_dnssec_zone_t,
							 list));
	} lws_end_foreach_dll_safe(d, d1);

	lws_free_set_NULL(dns->dnssec_anchors);
	dns->dnssec_anchors_len = 0;
}

int
lws_async_dns_dnssec_set_root_anchors(struct lws_context *context,
				      const lws_adns_ds_anchor_t *anchors,
				      size_t count)
{
	lws_async_dns_t *dns = &context->async_dns;
	lws_dnssec_rrs_t r = { NULL, 0 };
	size_t i;

	for (i = 0; anchors && i < count; i++) {
		const lws_adns_ds_anchor_t *a = &anchors[i];
		uint8_t rd[4 + 64];
		size_t want;

		switch (a->digest_type) {
		case 2:
			want = 32;
			break;
		case 4:
			want = 48;
			break;
		default:
			want = 0;
			break;
		}

		if (!want || !a->digest || a->digest_len != want) {
			lwsl_cx_err(context, "anchor %d: bad digest",
				    (int)i);
			lws_dnssec_rrs_free(&r);
			return 1;
		}

		lws_ser_wu16be(rd, a->key_tag);
		rd[2] = a->algorithm;
		rd[3] = a->digest_type;
		memcpy(rd + 4, a->digest, want);

		if (lws_dnssec_rrs_add(&r, LWS_ADNS_RECORD_DS, rd,
				       (uint16_t)(4 + want))) {
			lws_dnssec_rrs_free(&r);
			return 1;
		}
	}

	lws_free(dns->dnssec_anchors);
	dns->dnssec_anchors = r.buf; /* NULL: the built-in ones next time */
	dns->dnssec_anchors_len = r.len;

	/*
	 * Everything authenticated so far chains up to the old anchors:
	 * settled zones are expired now, and a walk in progress may have
	 * used them already, so it settles as not authenticated.
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->dnssec_zones)) {
		lws_dnssec_zone_t *z = lws_container_of(d, lws_dnssec_zone_t,
							list);

		if (lws_dnssec_zone_is_settled(z))
			z->expires = (uint32_t)lws_now_secs();
		else if (z->state != LDZ_IDLE)
			z->stale = 1;
	} lws_end_foreach_dll(d);

	/*
	 * ... and so does every answer we validated with them: cached ones
	 * aren't reported, or served, as validated any more, and a query that
	 * validated part of its answer already can't complete as validated
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->cached)) {
		lws_container_of(d, lws_adns_cache_t, list)->dnssec_valid = 0;
	} lws_end_foreach_dll(d);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dns->waiting)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

		if (q->dnssec_expires)
			q->dnssec_stale = 1;
	} lws_end_foreach_dll(d);

	return 0;
}

#endif /* LWS_WITH_SYS_ASYNC_DNS */
