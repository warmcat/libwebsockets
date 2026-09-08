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
 * Asynchronous DNSSEC validation state machine.
 */

#include "private-lib-core.h"
#include "private-lib-async-dns.h"
#ifndef _WIN32
#include <arpa/inet.h>
#endif

#if defined(LWS_WITH_SYS_ASYNC_DNS)

struct lws_dnssec_val_ctx {
	lws_adns_q_t *original_q;
	uint8_t algorithm;
	uint16_t key_tag;

	uint16_t sig_len;
	uint8_t sig_buf[512];

	uint8_t hash[64];

	char signer_name[DNS_MAX];
};

struct rrsig_search {
	lws_adns_q_t *q;
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
};

struct rrset_search {
	uint16_t type_covered;
	const char *name; /* From query or RRSIG */
	uint32_t original_ttl;

	int count;
	struct rr_canonical records[16];
};

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

static int
cmp_rr(const void *a, const void *b)
{
	const struct rr_canonical *ra = (const struct rr_canonical *)a;
	const struct rr_canonical *rb = (const struct rr_canonical *)b;
	size_t min_len = ra->len < rb->len ? ra->len : rb->len;
	int c = memcmp(ra->data, rb->data, min_len);
	if (c == 0) {
		if (ra->len < rb->len) return -1;
		if (ra->len > rb->len) return 1;
		return 0;
	}
	return c;
}

static int
lws_dnssec_rrset_cb(const char *name, void *opaque, uint32_t ttl,
		    adns_query_type_t type, uint16_t rrpaylen,
		    const uint8_t *payload)
{
	struct rrset_search *s = (struct rrset_search *)opaque;
	int nl = (int)strlen(name);
	int sl = (int)strlen(s->name);

	if (type != s->type_covered)
		return 0;

	if (nl && name[nl - 1] == '.')
		nl--;
	if (sl && s->name[sl - 1] == '.')
		sl--;

	if (nl != sl || strncmp(name, s->name, (size_t)nl))
		return 0;

	if (s->count >= 16)
		return 0;

	struct rr_canonical *r = &s->records[s->count++];
	uint8_t *p = r->data;

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

	if ((size_t)(p - r->data) + rrpaylen > sizeof(r->data))
		return -1;

	if (rrpaylen) {
		memcpy(p, payload, rrpaylen);
		p += rrpaylen;
	}

	r->len = (size_t)(p - r->data);
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

	/* Parse RRSIG RDATA payload... */
	s->type_covered = lws_ser_ru16be(&payload[0]);
	s->algorithm = payload[2];
	s->labels = payload[3];
	s->original_ttl = lws_ser_ru32be(&payload[4]);
	s->sig_expiration = lws_ser_ru32be(&payload[8]);
	s->sig_inception = lws_ser_ru32be(&payload[12]);
	s->key_tag = lws_ser_ru16be(&payload[16]);

	/* The signer name is in wire format right after the keytag.
	 * But wait, we don't have the original packet or total length explicitly in this callback.
	 * We'll use the query's saved packet for name expansion.
	 * However, `payload` points directly to the data, and since the name is right there,
	 * we can just use `lws_adns_parse_label` BUT we need `pkt` and `len` from context.
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

/*
 * RFC 4035 5.2: a DNSKEY may only be used to validate an RRset once the key
 * itself has been authenticated, by a DS record in the parent zone that chains
 * up to a trust anchor we already hold.  Without that, an attacker who can
 * answer both the original query and our DNSKEY sub-query just signs his own
 * forged RRset with his own key, answers the DNSKEY lookup with it, and we
 * "validate" it.
 *
 * We hold the ICANN root KSK DS records in lws_adns_root_ds[], so a DNSKEY of
 * the root zone can be authenticated here directly.
 *
 * INCOMPLETE: for a zone below the root, closing the chain additionally needs
 *
 *  - the DS RRset of the zone fetched from its parent, and its RRSIG validated
 *    with the parent zone's already-authenticated DNSKEY, repeated up to the
 *    root, and
 *
 *  - within each zone, the DS matching the KSK, the DNSKEY RRset's own RRSIG
 *    validated with that KSK, and only then the ZSK from that validated RRset
 *    used on the data RRset.
 *
 * Neither exists yet, so any key below the root counts as unauthenticated here
 * and validation fails closed, rather than trusting a key the peer handed us.
 */

static int
lws_dnssec_dnskey_authenticated(const char *zone, uint16_t key_tag, uint8_t algo,
				const uint8_t *kn, size_t keylen)
{
	size_t i;

	if (*zone && strcmp(zone, "."))
		return 0; /* below the root: no validated DS available to us */

	for (i = 0; i < LWS_ARRAY_SIZE(lws_adns_root_ds); i++) {
		uint8_t dig[32];

		if (lws_adns_root_ds[i].keytag != key_tag ||
		    lws_adns_root_ds[i].algo != algo)
			continue;

		if (lws_hex_to_byte_array(lws_adns_root_ds[i].digest_hex, dig,
					  (int)sizeof(dig)) != (int)sizeof(dig))
			continue;

		if (lws_dnssec_ds_matches_dnskey(zone, kn, keylen,
						 lws_adns_root_ds[i].digest_type,
						 dig, sizeof(dig)))
			return 1;
	}

	return 0;
}

static struct lws *
lws_dnssec_dnskey_cb(struct lws *wsi, const char *name, const struct addrinfo *data, int m, void *opaque)
{
	struct lws_dnssec_val_ctx *vctx = (struct lws_dnssec_val_ctx *)opaque;
	lws_adns_q_t *q = vctx->original_q;
	lws_adns_cache_t *c;
	int is_async;

	if (!q)
		return wsi;

	is_async = q->dnssec_verify_rrsig;

	/*
	 * We only get here in REQUIRE mode (see lws_adns_parse_udp()), ie, the
	 * user asked us to only accept validated results.  If we could not get
	 * the signer's DNSKEY, we cannot validate anything and must fail the
	 * query closed... setting lacks_dnssec here instead would let anybody
	 * who can make the DNSKEY lookup fail (an empty answer, NXDOMAIN, a
	 * forged failure) downgrade REQUIRE to "accept whatever came".
	 */

	if (m != LWS_ADNS_DNSSEC_VALID && m != 0 && m != LWS_ADNS_DNSSEC_INVALID) {
		lwsl_notice("%s: DNSKEY lookup failed (ret=%d)\n", __func__, m);
		goto fail;
	}

	c = lws_adns_get_cache(q->dns, vctx->signer_name);
	if (!c || !c->rr_results) {
		lwsl_notice("%s: DNSKEY cache absent\n", __func__);
		goto fail;
	}

	lws_adns_rr_t *rr = c->rr_results;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_MAX_KEYEL_COUNT];
	int valid = 0;

	memset(el, 0, sizeof(el));

	while (rr) {
		if (rr->type == LWS_ADNS_RECORD_DNSKEY && rr->paylen >= 4) {
			const uint8_t *kn = (const uint8_t *)&rr[1];
			uint8_t protocol = kn[2];
			uint8_t alg = kn[3];

			if (protocol == LWS_ADNS_DNSKEY_PROTOCOL_DNSSEC && alg == vctx->algorithm) {
				uint32_t ac = 0;
				int i, keylen = rr->paylen;

				if (alg == LWS_ADNS_DSA_RSA_MD5) {
					ac = (uint32_t)kn[keylen - 3] << 8;
					ac += kn[keylen - 2];
				} else {
					for (i = 0; i < keylen; ++i)
						ac += (i & 1) ? kn[i] : (uint32_t)kn[i] << 8;
					ac += (ac >> 16) & 0xFFFF;
				}
				uint16_t calc_tag = (uint16_t)(ac & 0xFFFF);

				if (calc_tag == vctx->key_tag) {
					const uint8_t *key_data = &kn[4];
					int key_data_len = keylen - 4;

					/*
					 * The key has to be authenticated itself
					 * before we may believe anything it
					 * signed... otherwise we would only be
					 * confirming that the answer is signed
					 * by a key that came with the answer.
					 */

					if (!lws_dnssec_dnskey_authenticated(
							vctx->signer_name,
							calc_tag, alg, kn,
							(size_t)keylen)) {
						lwsl_notice("%s: DNSKEY for %s "
							    "not authenticated by "
							    "a DS chaining to a "
							    "trust anchor\n",
							    __func__,
							    vctx->signer_name);
						break;
					}

					if (alg == LWS_ADNS_DSA_ECDSAP256SHA256 || alg == LWS_ADNS_DSA_ECDSAP384SHA384) {
						struct lws_genec_ctx ctx;

						memset(&ctx, 0, sizeof(ctx));
						size_t curvelen = (alg == LWS_ADNS_DSA_ECDSAP256SHA256) ? 32 : 48;
						enum lws_genhash_types hashtype = (alg == LWS_ADNS_DSA_ECDSAP256SHA256) ? LWS_GENHASH_TYPE_SHA256 : LWS_GENHASH_TYPE_SHA384;

						if (key_data_len == (int)(curvelen * 2)) {
							const char *crv = (alg == LWS_ADNS_DSA_ECDSAP256SHA256) ? "P-256" : "P-384";
							el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = (uint8_t *)crv;
							el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(crv) + 1;
							el[LWS_GENCRYPTO_EC_KEYEL_X].buf = (uint8_t *)key_data;
							el[LWS_GENCRYPTO_EC_KEYEL_X].len = (uint32_t)curvelen;
							el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = (uint8_t *)key_data + curvelen;
							el[LWS_GENCRYPTO_EC_KEYEL_Y].len = (uint32_t)curvelen;

							if (lws_genecdsa_create(&ctx, q->context, NULL) == 0) {
								if (lws_genecdsa_set_key(&ctx, el) == 0) {
									int res = lws_genecdsa_hash_sig_verify_jws(&ctx, vctx->hash, hashtype, (int)(curvelen * 8), vctx->sig_buf, (size_t)vctx->sig_len);
									if (res >= 0) {
										lwsl_notice("%s: ECDSA RRSIG verified successfully!\n", __func__);
										valid = 1;
									} else {
										lwsl_notice("%s: ECDSA verification failed: %d\n", __func__, res);
									}
								} else {
									lwsl_notice("%s: genecdsa_set_key failed\n", __func__);
								}
								lws_genec_destroy(&ctx);
							} else {
								lwsl_notice("%s: lws_genecdsa_create failed\n", __func__);
							}
						} else {
							lwsl_notice("%s: ECDSA length mismatch: key_data_len=%d, expected=%d\n", __func__, key_data_len, (int)(curvelen * 2));
						}
					} else if (alg == LWS_ADNS_DSA_RSA_SHA256 || alg == LWS_ADNS_DSA_RSA_SHA512) {
						struct lws_genrsa_ctx ctx;

						memset(&ctx, 0, sizeof(ctx));
						enum lws_genhash_types hashtype = (alg == LWS_ADNS_DSA_RSA_SHA256) ? LWS_GENHASH_TYPE_SHA256 : LWS_GENHASH_TYPE_SHA512;

						if (key_data_len < 1)
							break;

						int explen = key_data[0];
						const uint8_t *exp = &key_data[1];

						if (explen == 0) {
							if (key_data_len < 3)
								break;
							explen = lws_ser_ru16be(&key_data[1]);
							exp = &key_data[3];
						}

						if ((int)(exp - key_data) + explen > key_data_len)
							break;

						const uint8_t *mod = exp + explen;
						int modlen = key_data_len - (int)(mod - key_data);

						if (modlen > 0) {
							el[LWS_GENCRYPTO_RSA_KEYEL_E].buf = (uint8_t *)exp;
							el[LWS_GENCRYPTO_RSA_KEYEL_E].len = (uint32_t)explen;
							el[LWS_GENCRYPTO_RSA_KEYEL_N].buf = (uint8_t *)mod;
							el[LWS_GENCRYPTO_RSA_KEYEL_N].len = (uint32_t)modlen;
							if (lws_genrsa_create(&ctx, el, q->context, LGRSAM_PKCS1_1_5, hashtype) == 0) {
								int res = lws_genrsa_hash_sig_verify(&ctx, vctx->hash, hashtype, vctx->sig_buf, (size_t)vctx->sig_len);
								if (res == 0) {
									lwsl_notice("%s: RSA RRSIG verified successfully!\n", __func__);
									valid = 1;
								} else {
									lwsl_notice("%s: RSA verification failed: %d\n", __func__, res);
								}
								lws_genrsa_destroy(&ctx);
							}
						}
					}

					break;
				}
			}
		}
		rr = rr->next;
	}

	if (!valid) {
		lwsl_notice("%s: Cryptographic verification of RRSIG failed\n", __func__);
		goto fail;
	}

	q->dnssec_verify_rrsig = 0;
	q->dnssec_valid = 1;

	if (is_async && q->responded == q->asked) {
		lws_async_dns_complete(q, q->firstcache);
		lws_adns_q_destroy(q);
	}

	lws_free(vctx);
	return wsi;

fail:
	q->dnssec_verify_rrsig = 0;
	if ((q->dns->dnssec_mode == LWS_ADNS_DNSSEC_REQUIRE) &&
	    !q->lacks_dnssec) {
		q->go_nogo = METRES_NOGO;
		if (is_async) lws_async_dns_complete(q, NULL);
		if (q->firstcache) {
			lws_adns_cache_destroy(q->firstcache);
			q->firstcache = NULL;
		}
	} else {
		if (is_async && q->responded == q->asked) {
			lws_async_dns_complete(q, q->firstcache);
		} else if (!is_async && q->responded != q->asked) {
			lws_free(vctx);
			return wsi;
		} else if (is_async && q->responded != q->asked) {
			lws_free(vctx);
			return wsi;
		}
	}
	if (is_async) lws_adns_q_destroy(q);
	lws_free(vctx);
	return wsi;
}

int
lws_adns_dnssec_verify(lws_adns_q_t *q, const uint8_t *pkt, size_t len)
{
	struct rrsig_search s;

	/*
	 * This is the entry point called from async-dns-parse.c
	 * when an A or AAAA response with an RRSIG is received (or generally
	 * any type we want to validate).
	 *
	 * Returning > 0 means validation is in progress (async sub-queries running).
	 * Returning 0 means validation succeeded or DNSSEC is off/tolerate.
	 * Returning < 0 means validation failed.
	 */

	if (q->dns->dnssec_mode == LWS_ADNS_DNSSEC_OFF)
		return 0;

	/* Find RRSIGs in the packet relating to the question */
	memset(&s, 0, sizeof(s));
	s.q = q;

	/* The query name is at &q[1] (with CNAME overwrites possible, but original
	 * query name is what we asked for).
	 */
	const char *nmcname = ((const char *)&q[1]);

	lws_adns_iterate(q, pkt, (int)len, nmcname, lws_dnssec_rrsig_cb, &s);

	if (!s.found) {
		/* No RRSIG found. If we REQUIRE DNSSEC, this is a failure if the zone should be signed.
		 * For now, tolerate it or reject based on mode.
		 */
		if (q->dns->dnssec_mode == LWS_ADNS_DNSSEC_REQUIRE) {
			lwsl_notice("%s: missing RRSIG\n", __func__);
			return -1;
		}
		return 0;
	}

	/* Parse the signer name from the previously found payload. */
	if (s.rrsig_payload) {
		struct lws_genhash_ctx hash_ctx;
		enum lws_genhash_types hashtype;
		const uint8_t *p = s.rrsig_payload + 18; /* After key tag */
		char *sp = s.signer_name;
		int n = lws_adns_parse_label(pkt, (int)len, p,
					     (int)(len - lws_ptr_diff_size_t(p, pkt)),
					     &sp, sizeof(s.signer_name));
		if (n < 0) {
			lwsl_notice("%s: bad signer name\n", __func__);
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

		switch (s.algorithm) {
		case LWS_ADNS_DSA_RSA_SHA256:
			hashtype = LWS_GENHASH_TYPE_SHA256;
			break;
		case LWS_ADNS_DSA_RSA_SHA512:
			hashtype = LWS_GENHASH_TYPE_SHA512;
			break;
		case LWS_ADNS_DSA_ECDSAP256SHA256:
			hashtype = LWS_GENHASH_TYPE_SHA256;
			break;
		case LWS_ADNS_DSA_ECDSAP384SHA384:
			hashtype = LWS_GENHASH_TYPE_SHA384;
			break;
		default:
			return -1;
		}

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
		}

		if (lws_genhash_init(&hash_ctx, hashtype))
			return -1;

		lwsl_notice("Hashing RRSIG payload (len %d):\n", rrsig_rdata_up_to_sig_len);
		/* s.rrsig_payload points to the RRSIG type covered through rdata */

		if (lws_genhash_update(&hash_ctx, s.rrsig_payload, (size_t)rrsig_rdata_up_to_sig_len)) {
			lws_genhash_destroy(&hash_ctx, NULL);
			return -1;
		}

		struct rrset_search rs;
		memset(&rs, 0, sizeof(rs));
		rs.type_covered = s.type_covered;
		rs.name = nmcname;
		rs.original_ttl = s.original_ttl;

		lws_adns_iterate(q, pkt, (int)len, nmcname, lws_dnssec_rrset_cb, &rs);

		qsort(rs.records, (size_t)rs.count, sizeof(struct rr_canonical), cmp_rr);

		for (int i = 0; i < rs.count; i++) {
			lwsl_notice("Hashing sorted canonical RR %d (len %d):\n", i, (int)rs.records[i].len);
			lwsl_hexdump_notice(rs.records[i].data, rs.records[i].len);
			if (lws_genhash_update(&hash_ctx, rs.records[i].data, rs.records[i].len)) {
				lws_genhash_destroy(&hash_ctx, NULL);
				return -1;
			}
		}

		struct lws_dnssec_val_ctx *vctx = lws_zalloc(sizeof(*vctx), "dnssec_val");
		if (!vctx) {
			lws_genhash_destroy(&hash_ctx, NULL);
			return -1;
		}

		if (lws_genhash_destroy(&hash_ctx, vctx->hash)) {
			lws_free(vctx);
			return -1;
		}

		vctx->original_q	= q;
		vctx->algorithm		= s.algorithm;
		vctx->key_tag		= s.key_tag;

		vctx->sig_len = (uint16_t)sig_len;
		if (sig_len <= (int)sizeof(vctx->sig_buf)) {
			memcpy(vctx->sig_buf, s.rrsig_payload + rrsig_rdata_up_to_sig_len, (size_t)sig_len);
		} else {
			/* hash_ctx was already finalized above */
			lwsl_err("%s: signature too large for buffer\n", __func__);
			lws_free(vctx);
			return -1;
		}

		lws_strncpy(vctx->signer_name, s.signer_name, sizeof(vctx->signer_name));

		/* We suspend completion of `q` if the DNSKEY lookup goes async.
		 * Temporarily set this to 0 so the callback knows if it was called synchronously. */
		q->dnssec_verify_rrsig = 0;

		int ret = lws_async_dns_query(q->context, q->tsi, s.signer_name,
					LWS_ADNS_RECORD_DNSKEY, lws_dnssec_dnskey_cb,
					NULL, vctx, NULL);

		if (ret == LADNS_RET_CONTINUING) {
			/* Async lookup initiated */
			q->dnssec_verify_rrsig = 1;
			return 1;
		}

		if (ret == LADNS_RET_FAILED) {
			/* Query failed to allocate/initiate synchronously (no callback fired) */
			lws_free(vctx);
			return -1;
		} else if (ret < 0) {
			/* Callback WAS called synchronously and already freed vctx */
			return -1;
		}

		/* Synchronous result from cache. The callback was already executed! */
		if ((q->dns->dnssec_mode == LWS_ADNS_DNSSEC_REQUIRE) && !q->lacks_dnssec) {
			return q->dnssec_valid ? 0 : -1;
		}

		return 0;
	}

	return 0;
}

#endif /* LWS_WITH_SYS_ASYNC_DNS */
