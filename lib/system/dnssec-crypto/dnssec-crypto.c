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


/*
 * DNSSEC key and signature primitives shared by the async-dns validator and
 * the authoritative zone verifier, see private-lib-system-dnssec-crypto.h
 */

#include "private-lib-core.h"
#include "private-lib-system-dnssec-crypto.h"

int
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

uint16_t
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

int
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

int
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
