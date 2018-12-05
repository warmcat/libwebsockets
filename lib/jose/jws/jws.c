/*
 * libwebsockets - JSON Web Signature support
 *
 * Copyright (C) 2017 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"
#include "private.h"

LWS_VISIBLE int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max)
{
	int n;

	n = lws_b64_encode_string_url(in, in_len, out, out_max - 1);
	if (n < 0)
		return n; /* too large for output buffer */

	/* trim the terminal = */
	while (n && out[n - 1] == '=')
		n--;

	out[n] = '\0';

	return n;
}

LWS_VISIBLE int
lws_jws_encode_section(const char *in, size_t in_len, int first, char **p,
		       char *end)
{
	int n, len = (end - *p) - 1;
	char *p_entry = *p;

	if (len < 3)
		return -1;

	if (!first)
		*(*p)++ = '.';

	n = lws_jws_base64_enc(in, in_len, *p, len - 1);
	if (n < 0)
		return -1;

	*p += n;

	return (*p) - p_entry;
}

static int
lws_jws_find_sig(const char *in, size_t len)
{
	const char *p = in + len - 1;

	while (len--)
		if (*p == '.')
			return (p + 1) - in;
		else
			p--;

	lwsl_notice("%s failed\n", __func__);
	return -1;
}

LWS_VISIBLE int
lws_jws_confirm_sig(const char *in, size_t len, struct lws_jwk *jwk,
		    struct lws_context *context)
{
	int sig_pos = lws_jws_find_sig(in, len), pos = 0, n, m, h_len;
	enum enum_genrsa_mode padding = LGRSAM_PKCS1_1_5;
	uint8_t digest[LWS_GENHASH_LARGEST];
	const struct lws_jose_jwe_alg *args = NULL;
	struct lws_genhash_ctx hash_ctx;
	struct lws_genec_ctx ecdsactx;
	struct lws_genrsa_ctx rsactx;
	struct lws_genhmac_ctx ctx;
	char buf[2048];

	/* 1) there has to be a signature */

	if (sig_pos < 0)
		return -1;

	/* 2) find length of first, hdr, block */

	while (pos < (int)len && in[pos] != '.')
		pos++;
	if (pos == (int)len)
		return -1;

	/* 3) Decode the header block */

	n = lws_b64_decode_string_len(in, pos, buf, sizeof(buf) - 1);
	if (n < 0)
		return -1;

	/* 4) Require either:
	 *      typ: JWT (if present) and alg: HS256/384/512
	 *      typ: JWT (if present) and alg: RS256/384/512
	 *      typ: JWT (if present) and alg: ES256/384/512
	 */

	m = lws_jws_parse_jose(&args, (unsigned char *)buf, n);
	if (m < 0) {
		lwsl_notice("parse got %d: alg %s\n", m, args->alg);
		return -1;
	}

	/* 5) decode the B64URL signature part into buf / m */

	m = lws_b64_decode_string_len(in + sig_pos, len - sig_pos,
				      buf, sizeof(buf) - 1);

	switch (args->algtype_signing) {
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
		padding = LGRSAM_PKCS1_OAEP_PSS;
		/* fallthru */
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:

		/* RSASSA-PKCS1-v1_5 or OAEP using SHA-256/384/512 */

		if (jwk->kty != LWS_GENCRYPTO_KYT_RSA)
			return -1;

		/* 6(RSA): compute the hash of the payload into "digest" */

		if (lws_genhash_init(&hash_ctx, args->hash_type))
			return -1;

		if (lws_genhash_update(&hash_ctx, (uint8_t *)in, sig_pos - 1)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}
		if (lws_genhash_destroy(&hash_ctx, digest))
			return -1;

		h_len = lws_genhash_size(args->hash_type);

		if (lws_genrsa_create(&rsactx, jwk->e, context, padding)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = lws_genrsa_hash_sig_verify(&rsactx, digest, args->hash_type,
					       (uint8_t *)buf, m);

		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lwsl_notice("decrypt fail\n");
			return -1;
		}

		break;

	case LWS_JOSE_ENCTYPE_NONE:

		/* SHA256/384/512 HMAC */

		h_len = lws_genhmac_size(args->hmac_type);
		if (m < 0 || m != h_len)
			return -1;

		/* 6) compute HMAC over payload */

		if (lws_genhmac_init(&ctx, args->hmac_type,
				     jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
				     jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len))
			return -1;

		if (lws_genhmac_update(&ctx, (uint8_t *)in, sig_pos - 1)) {
			lws_genhmac_destroy(&ctx, NULL);

			return -1;
		}
		if (lws_genhmac_destroy(&ctx, digest))
			return -1;

		/* 7) Compare the computed and decoded hashes */

		if (memcmp(digest, buf, h_len)) {
			lwsl_notice("digest mismatch\n");

			return -1;
		}

		break;

	case LWS_JOSE_ENCTYPE_ECDSA:

		/* ECDSA using SHA-256/384/512 */

		/* the key coming in with this makes sense, right? */

		/* has to be an EC key :-) */
		if (jwk->kty != LWS_GENCRYPTO_KYT_EC)
			return -1;

		/* key must state its curve */
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
			return -1;

		/* key must match the selected alg curve */
		if (strcmp((const char *)jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
			   args->curve_name))
			return -1;

		/* compute the hash of the payload into "digest" */

		if (lws_genhash_init(&hash_ctx, args->hash_type))
			return -1;

		if (lws_genhash_update(&hash_ctx, (uint8_t *)in, sig_pos - 1)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}
		if (lws_genhash_destroy(&hash_ctx, digest))
			return -1;

		h_len = lws_genhash_size(args->hash_type);

		if (lws_genecdsa_create(&ecdsactx, context, NULL)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		if (lws_genecdsa_set_key(&ecdsactx, jwk->e)) {
			lws_genec_destroy(&ecdsactx);
			lwsl_notice("%s: ec key import fail\n", __func__);
			return -1;
		}

		n = lws_genecdsa_hash_sig_verify(&ecdsactx, digest,
						 args->hash_type,
						 (uint8_t *)buf, m);

		lws_genec_destroy(&ecdsactx);
		if (n < 0) {
			lwsl_notice("decrypt fail\n");
			return -1;
		}

		break;

	default:
		lwsl_err("%s: unknown alg from jose\n", __func__);
		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_jws_sign_from_b64(const char *b64_hdr, size_t hdr_len, const char *b64_pay,
		      size_t pay_len, char *b64_sig, size_t sig_len,
		      const struct lws_jose_jwe_alg *args,
		      struct lws_jwk *jwk,
		      struct lws_context *context)
{
	enum enum_genrsa_mode padding = LGRSAM_PKCS1_1_5;
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genec_ctx ecdsactx;
	struct lws_genrsa_ctx rsactx;
	int n, m;
	uint8_t *buf;

	if (lws_genhash_init(&hash_ctx, args->hash_type))
		return -1;

	if (b64_hdr) {
		if (lws_genhash_update(&hash_ctx, (uint8_t *)b64_hdr, hdr_len))
			goto hash_fail;
		if (lws_genhash_update(&hash_ctx, (uint8_t *)".", 1))
			goto hash_fail;
	}
	if (lws_genhash_update(&hash_ctx, (uint8_t *)b64_pay, pay_len))
		goto hash_fail;

	if (lws_genhash_destroy(&hash_ctx, digest))
		return -1;

	switch (args->algtype_signing) {
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
		padding = LGRSAM_PKCS1_OAEP_PSS;
		/* fallthru */
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:

		if (jwk->kty != LWS_GENCRYPTO_KYT_RSA)
			return -1;

		if (lws_genrsa_create(&rsactx, jwk->e, context, padding)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
		buf = lws_malloc(n, "jws sign");
		if (!buf)
			return -1;

		n = lws_genrsa_hash_sign(&rsactx, digest, args->hash_type, buf, n);
		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lws_free(buf);

			return -1;
		}

		n = lws_jws_base64_enc((char *)buf, n, b64_sig, sig_len);
		lws_free(buf);

		return n;

	case LWS_JOSE_ENCTYPE_NONE:
		return lws_jws_base64_enc((char *)digest,
					  lws_genhash_size(args->hash_type),
					  b64_sig, sig_len);
	case LWS_JOSE_ENCTYPE_ECDSA:
		/* ECDSA using SHA-256/384/512 */

		/* the key coming in with this makes sense, right? */

		/* has to be an EC key :-) */
		if (jwk->kty != LWS_GENCRYPTO_KYT_EC)
			return -1;

		/* key must state its curve */
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
			return -1;

		/* must have all his pieces for a private key */
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf ||
		    !jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf ||
		    !jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf)
			return -1;

		/* key must match the selected alg curve */
		if (strcmp((const char *)jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
			   args->curve_name))
			return -1;

		if (lws_genecdsa_create(&ecdsactx, context, NULL)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		if (lws_genecdsa_set_key(&ecdsactx, jwk->e)) {
			lws_genec_destroy(&ecdsactx);
			lwsl_notice("%s: ec key import fail\n", __func__);
			return -1;
		}
		m = jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len;
		buf = lws_malloc(m, "jws sign");
		if (!buf)
			return -1;

		n = lws_genecdsa_hash_sign(&ecdsactx, digest, args->hash_type,
					   (uint8_t *)buf, m);
		lws_genec_destroy(&ecdsactx);
		if (n < 0) {
			lwsl_notice("decrypt fail\n");
			return -1;
		}
		n = lws_jws_base64_enc((char *)buf, m, b64_sig, sig_len);
		lws_free(buf);

		return n;

	default:
		break;
	}

	/* unknown key type */

	return -1;

hash_fail:
	lws_genhash_destroy(&hash_ctx, NULL);
	return -1;
}
