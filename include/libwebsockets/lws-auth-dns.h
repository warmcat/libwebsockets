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
 */

#if defined(LWS_WITH_AUTHORITATIVE_DNS)

struct auth_dns_rr {
	lws_dll2_t list;

	char *rdata;
	size_t rdata_len;

	uint8_t *wire_rdata;
	size_t wire_rdata_len;
};

struct auth_dns_rrset {
	lws_dll2_t list;
	lws_dll2_owner_t rr_list;

	char *name;
	uint32_t ttl;
	uint16_t class_;
	uint16_t type;
};

struct auth_dns_zone {
	lws_dll2_owner_t rrset_list;
	char default_ttl[16];
	char origin[256];
	unsigned int origin_lines;	/* $ORIGIN directives the text had */
};

LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_parse_zone_buf(const char *buf, size_t len, struct auth_dns_zone *zone);

/**
 * lws_auth_dns_zone_check_origin() - confirm a parsed zone is one domain's
 *
 * \param z: the zone as lws_auth_dns_parse_zone_buf() parsed it
 * \param domain: the domain the zone must be for, with or without its
 *		  trailing dot, or NULL to only check the zone is coherent
 *
 * A zone's identity is its origin, but zone text can carry any number of
 * $ORIGIN lines, and each one changes the origin for the records after it.
 * Anything that binds zone text to a domain (signing it with that domain's
 * keys, accepting it as signed by them, installing it as that domain's zone)
 * must agree with the parser that will serve it about which domain that is.
 *
 * Returns 0 if the text set its origin with exactly one $ORIGIN line, that
 * origin is \p domain (ignoring case) when \p domain is given, and every
 * owner name in the zone is the origin or a name below it.  Otherwise
 * nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_zone_check_origin(const struct auth_dns_zone *z,
			       const char *domain);

/*
 * The clock skew allowed either side of an RRSIG's validity period when
 * deciding whether a zone is valid now.  lws_auth_dns_sign_zone() starts the
 * period an hour before signing, so this is only for clocks that are wrong.
 */
#define LWS_AUTH_DNS_RRSIG_SKEW_SECS	300

enum lws_auth_dns_zone_validity_result {
	LWS_AUTH_DNS_ZV_OK,		/**< signed, and every RRSIG valid now */
	LWS_AUTH_DNS_ZV_NO_SOA,		/**< no apex SOA with a serial */
	LWS_AUTH_DNS_ZV_UNSIGNED,	/**< no RRSIG over the apex SOA */
	LWS_AUTH_DNS_ZV_NOT_YET_VALID,	/**< an RRSIG's inception is ahead */
	LWS_AUTH_DNS_ZV_EXPIRED,	/**< an RRSIG has expired */
};

/**
 * struct lws_auth_dns_zone_validity - a zone's serial and signing times
 *
 * The times are absolute: RRSIG times are 32-bit serial numbers (RFC 4034
 * 3.1.5), taken here as the instant nearest the time they were compared with.
 */
struct lws_auth_dns_zone_validity {
	uint32_t	serial;		/**< the apex SOA's serial */
	time_t		soa_inception;	/**< latest inception of an RRSIG over
					  * the apex SOA, ie, when the zone was
					  * last signed */
	time_t		inception;	/**< latest inception of any RRSIG */
	time_t		expiration;	/**< earliest expiration of any RRSIG */
	unsigned int	rrsigs;		/**< count of RRSIG RRs */
	uint8_t		soa_signed;	/**< an RRSIG covers the apex SOA */
};

/**
 * lws_auth_dns_zone_validity() - is a parsed zone signed and in date
 *
 * \param z: the zone as lws_auth_dns_parse_zone_buf() parsed it
 * \param now: the time to check the RRSIGs' validity periods at
 * \param skew: seconds of clock skew to allow either side of each period,
 *		eg, LWS_AUTH_DNS_RRSIG_SKEW_SECS
 * \param v: filled with what was found, as far as it got
 *
 * A signed zone is only good for the validity periods of its RRSIGs, and a
 * copy of it can be replayed by anyone who ever saw it.  Anything taking a
 * signed zone from somewhere else needs to know that it is in date, and how
 * new it is.  This looks at the RRSIG times and the SOA serial only: it does
 * not verify any signature, so it is for zones whose integrity is already
 * established some other way (eg, a JWS over the zone text checked against
 * the domain's DS), or for use with lws_auth_dns_verify_zone().
 *
 * Returns LWS_AUTH_DNS_ZV_OK if the zone has an apex SOA with a serial, an
 * RRSIG over that SOA, and every RRSIG in the zone is inside its validity
 * period at \p now (give or take \p skew), otherwise the first reason it is
 * not, from enum lws_auth_dns_zone_validity_result.
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_zone_validity(const struct auth_dns_zone *z, time_t now,
			   unsigned int skew,
			   struct lws_auth_dns_zone_validity *v);

LWS_VISIBLE LWS_EXTERN void
lws_auth_dns_free_zone(struct auth_dns_zone *z);

/**
 * lws_auth_dns_zone_cut() - the delegation a name is at or below, if any
 *
 * \param z: the zone as lws_auth_dns_parse_zone_buf() parsed it
 * \param name: a name in the zone, with or without its trailing dot
 *
 * An NS RRset at an owner below the zone apex makes that owner a delegation
 * point, a zone cut.  The zone is not authoritative for anything at or below
 * a cut, apart from the DS RRset at the cut itself: an authoritative server
 * answers queries for those names with a referral to the cut's NS RRset, and
 * never from whatever else the zone text has there.
 *
 * Returns the NS RRset of the topmost cut at or above \p name, or NULL if
 * \p name is not at or below a delegation.
 */
LWS_VISIBLE LWS_EXTERN struct auth_dns_rrset *
lws_auth_dns_zone_cut(struct auth_dns_zone *z, const char *name);

#define LWS_AUTH_DNS_NSEC3_HASH_LEN 20 /* SHA-1, the only NSEC3 hash */

/*
 * Anything hashing a zone's NSEC3 owner names spends the zone's iteration
 * count of CPU per hash, and the zone can be untrusted (eg, DHT-published).
 * RFC 5155 A.1 caps useful iterations at 150 and RFC 9276 deprecates any
 * value above 0, so zones asking for more are not hashed.
 */
#define LWS_AUTH_DNS_MAX_NSEC3_ITERATIONS 150

/**
 * lws_auth_dns_nsec3_hash() - RFC 5155 hashed owner name
 *
 * \param wire: the owner name in canonical wire form (lowercased labels,
 *		 terminating root label)
 * \param wire_len: length of \p wire
 * \param salt: the NSEC3 salt, or NULL if \p salt_len is 0
 * \param salt_len: length of \p salt
 * \param iterations: the NSEC3 additional iterations
 * \param hash: LWS_AUTH_DNS_NSEC3_HASH_LEN bytes of output
 *
 * Returns 0 on success.  The signer names each NSEC3 by this hash, and an
 * authoritative server picks the NSEC3 proving a denial by the same hash of
 * the query name, so both must use it for resolvers to agree with them.
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_nsec3_hash(const uint8_t *wire, size_t wire_len,
			const uint8_t *salt, size_t salt_len,
			unsigned int iterations, uint8_t *hash);

/* the largest DNSKEY RDATA we express: 4 + 3 + e + 8192-bit RSA n */
#define LWS_AUTH_DNS_DNSKEY_WIRE_MAX 1040

/*
 * A key's DNSKEY record, and the DS record for it the parent zone publishes,
 * as the registrar asks for them
 */

struct lws_auth_dns_key_records {
	char		dnskey[((LWS_AUTH_DNS_DNSKEY_WIRE_MAX - 4 + 2) / 3) * 4 + 16];
			/**< DNSKEY RDATA, "<flags> 3 <alg> <base64 public key>" */
	char		ds[128];
			/**< DS RDATA, "<keytag> <alg> <digest type> <DIGEST>" */
	char		digest[97];
			/**< the DS digest alone, as uppercase hex */
	uint16_t	keytag;
	uint8_t		alg;		/**< DNSSEC algorithm, 8, 13 or 14 */
	uint8_t		digest_type;	/**< 2 (SHA-256), or 4 (SHA-384) for alg 14 */
};

/**
 * lws_auth_dns_key_records() - a key's DNSKEY and DS records
 *
 * \param jwk: the key, only its public part is used
 * \param origin: the zone the key signs, eg "example.com."
 * \param flags: DNSKEY flags, 257 for a KSK, 256 for a ZSK
 * \param r: the records are written here
 *
 * These are what lws_auth_dns_sign_zone() publishes and signs with, so for
 * the KSK, what the registrar needs in order to publish the DS in the parent
 * zone.  They are all public.
 *
 * Returns 0 on success, or nonzero if the key has no DNSSEC algorithm (eg,
 * P-521) or is too large to express.
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_key_records(struct lws_jwk *jwk, const char *origin, int flags,
			 struct lws_auth_dns_key_records *r);

struct lws_auth_dns_sign_info {
	const char			*input_filepath;
	const char			*output_filepath;
	const char			*jws_filepath;      /* Path to output signed JWS of the zone */
	const char			*zsk_jwk_filepath;  /* Path to ZSK JWK config */
	const char			*ksk_jwk_filepath;  /* Path to KSK JWK config */
	const char *			(*subst_cb)(struct lws_auth_dns_sign_info *info, const char *name);
	void				*subst_priv;
	const char			**subst_names;      /* For lws_strexp fallback */
	const char			**subst_values;
	time_t				sign_validity_start_time; /* 0 = now */
	uint32_t			sign_validity_duration;   /* 0 = 30 days */
	int				num_substs;
	const char			*ipv4;              /* detected external addresses, */
	const char			*ipv6;              /* for subst_cb's ${EXTIP4} / ${EXTIP6} */
	struct lws_context		*cx;                /* For logging/alloc */
	const char			*domain;            /* NULL, or the only zone the input may be, see lws_auth_dns_zone_check_origin() */
	time_t				verify_time;        /* verify only: when the RRSIGs must be valid, 0 = now */

	const char			*curr_line;
	size_t				curr_line_len;
	uint8_t				skip_line;
};

/**
 * lws_auth_dns_sign_zone() - read, sign and output an authoritative DNS zone
 *
 * \param info: the params for configuring the sign operation
 *
 * The input zone must pass lws_auth_dns_zone_check_origin() against
 * \p info->domain (or, with that NULL, against itself), otherwise nothing
 * is signed and nonzero is returned.
 *
 * As RFC 4035 2.2 requires, the NS RRset at a delegation point (an owner
 * below the apex with an NS RRset) and glue (A / AAAA RRsets at or below a
 * delegation point, at a name some NS RR names) are not signed, and the
 * NSEC3 chain does not include the names below a delegation point.  A DS
 * RRset at a delegation point is signed.  A zone that holds anything else
 * at or below a delegation point (occluded data), or a DS RRset anywhere but
 * at a delegation point, is refused.
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_sign_zone(struct lws_auth_dns_sign_info *info);

/**
 * lws_auth_dns_verify_zone() - verify a signed zone is signed by the given keys
 *
 * \param info: the params for configuring the verify operation
 *
 * Reads the signed zone text at \p info->input_filepath and checks that it is
 * completely and validly signed by the keys the caller trusts for it:
 *
 *  - the zone must pass lws_auth_dns_zone_check_origin() against
 *    \p info->domain (or, with that NULL, against itself)
 *  - the apex DNSKEY RRset must contain the KSK in the JWK at
 *    \p info->ksk_jwk_filepath (required, as a DNSKEY with flags 257), and if
 *    \p info->zsk_jwk_filepath is given, that ZSK (flags 256)
 *  - the DNSKEY RRset must carry a valid RRSIG made by that KSK
 *  - every authoritative RRset other than RRSIG, including the NSEC3 chain
 *    and NSEC3PARAM, must carry at least one valid RRSIG made by a zone key
 *    in that DNSKEY RRset
 *  - an owner below the apex with an NS RRset is only taken as a delegation
 *    point if the zone's NSEC3 RR for it (with the apex NSEC3PARAM's
 *    parameters, which must not exceed LWS_AUTH_DNS_MAX_NSEC3_ITERATIONS)
 *    lists NS and not SOA, so only delegations the signer made are exempt
 *    from being signed.  Zones using NSEC3 opt-out for insecure delegations
 *    therefore do not verify.
 *  - per RFC 4035 2.2, the NS RRset at a delegation point and glue (A / AAAA
 *    at or below one, at a name an NS RR names) must not be signed, the DS
 *    RRset at a delegation point must be, and nothing else may be at or
 *    below a delegation point, nor a DS anywhere else
 *  - every RRSIG in the zone must be valid: over an RRset its owner has,
 *    signed by the zone apex, with the owner's label count and the RRset's
 *    TTL as its original TTL, inside its inception / expiration period at
 *    \p info->verify_time (0 means now), of an algorithm the signer uses
 *    (RSASHA256 (8), ECDSAP256SHA256 (13), ECDSAP384SHA384 (14), and also
 *    RSASHA512 (10)), and verifying with a DNSKEY of the matching algorithm
 *    and key tag that has the Zone Key flag and is not revoked
 *  - every record must be one the parser could put in wire form
 *
 * What is not checked is whether the NSEC3 chain is complete and agrees with
 * the zone's names and types: its records are signed like any others, so
 * they cannot be forged, but a chain with a gap only fails to prove some
 * denials.
 *
 * Only the public parts of the JWKs are used, so they may be public-only.
 * \p info->jws_filepath is not used: the JWS over the zone text that
 * lws_auth_dns_sign_zone() also produces is checked separately, eg, with
 * lws_jws_sig_confirm_compact_b64() and the KSK.
 *
 * Returns 0 if the zone verified, otherwise nonzero, with the reason logged
 * at error level.
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_verify_zone(struct lws_auth_dns_sign_info *info);

#endif
