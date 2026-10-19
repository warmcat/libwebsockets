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


#ifndef _PRIVATE_LIB_SYSTEM_DNSSEC_CRYPTO_H_
#define _PRIVATE_LIB_SYSTEM_DNSSEC_CRYPTO_H_

/*
 * The DNSSEC key and signature primitives, shared by everything in lws that
 * validates RRSIGs: the async-dns validator and the authoritative zone
 * verifier.  They agree on which algorithms are usable, what a key tag is,
 * which DNSKEYs may sign and how a DNSKEY's public key verifies a signature
 * by being the same code.
 */

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

/* DNSKEY flags, RFC 4034 2.1.1 and RFC 5011 7 */
#define LWS_DNSKEY_FLAG_ZONE		0x0100
#define LWS_DNSKEY_FLAG_REVOKE		0x0080

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC) || \
    defined(LWS_WITH_AUTHORITATIVE_DNS)

/*
 * The hash an RRSIG of DNSSEC algorithm \p alg is made over, in *ht.
 * Returns 0, or -1 if \p alg is not one we validate.
 */
int
lws_dnssec_alg_hash(uint8_t alg, enum lws_genhash_types *ht);

/* RFC 4034 Appendix B, over the whole DNSKEY RDATA (not alg 1) */
uint16_t
lws_dnssec_key_tag(const uint8_t *kn, size_t keylen);

/*
 * May this DNSKEY RDATA be used to verify an RRSIG made with \p alg and
 * \p key_tag?  Only a zone key can sign RRsets, and a revoked key signs
 * nothing we believe.  Returns nonzero if so.
 */
int
lws_dnssec_key_usable(const uint8_t *kn, size_t keylen, uint8_t alg,
		      uint16_t key_tag);

/*
 * Verify \p sig over \p hash, made with algorithm \p alg, with the public
 * key in DNSKEY RDATA \p kn.  Returns 0 if it verified.
 */
int
lws_dnssec_sig_verify(struct lws_context *cx, uint8_t alg, const uint8_t *kn,
		      size_t keylen, const uint8_t *hash, const uint8_t *sig,
		      size_t sig_len);

#endif
#endif
