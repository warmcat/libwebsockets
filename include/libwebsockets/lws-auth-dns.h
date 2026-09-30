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
};

LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_parse_zone_buf(const char *buf, size_t len, struct auth_dns_zone *zone);

LWS_VISIBLE LWS_EXTERN void
lws_auth_dns_free_zone(struct auth_dns_zone *z);

#define LWS_AUTH_DNS_NSEC3_HASH_LEN 20 /* SHA-1, the only NSEC3 hash */

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

	const char			*curr_line;
	size_t				curr_line_len;
	uint8_t				skip_line;
};

/**
 * lws_auth_dns_sign_zone() - read, sign and output an authoritative DNS zone
 *
 * \param info: the params for configuring the sign operation
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_sign_zone(struct lws_auth_dns_sign_info *info);

/**
 * lws_auth_dns_verify_zone() - read, parse and verify RRSIGs from an authoritative DNS zone
 *
 * \param info: the params for configuring the verify operation
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_verify_zone(struct lws_auth_dns_sign_info *info);

#endif
