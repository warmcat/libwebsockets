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
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genrsa_ctx rsactx;
	struct lws_genhmac_ctx ctx;
	struct cb_hdr_s args;
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
		lwsl_notice("parse got %d: alg %s\n", m, args.alg);
		return -1;
	}

	/* 5) decode the B64URL signature part into buf / m */

	m = lws_b64_decode_string_len(in + sig_pos, len - sig_pos,
				      buf, sizeof(buf) - 1);

	switch (args.algtype) {
	case LWS_JWK_ENCTYPE_RSASSA:

		/* RSASSA-PKCS1-v1_5 using SHA-256/384/512 */

		/* 6(RSA): compute the hash of the payload into "digest" */

		if (lws_genhash_init(&hash_ctx, args.hash_type))
			return -1;

		if (lws_genhash_update(&hash_ctx, (uint8_t *)in, sig_pos - 1)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}
		if (lws_genhash_destroy(&hash_ctx, digest))
			return -1;

		h_len = lws_genhash_size(args.hash_type);

		if (lws_genrsa_create(&rsactx, jwk->e, context,
				      LGRSAM_PKCS1_1_5)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = lws_genrsa_public_verify(&rsactx, digest, args.hash_type,
					     (uint8_t *)buf, m);

		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lwsl_notice("decrypt fail\n");
			return -1;
		}

		break;

	case LWS_JWK_ENCTYPE_NONE:

		/* SHA256/384/512 HMAC */

		h_len = lws_genhmac_size(args.hmac_type);
		if (m < 0 || m != h_len)
			return -1;

		/* 6) compute HMAC over payload */

		if (lws_genhmac_init(&ctx, args.hmac_type,
				     jwk->e[JWK_RSA_KEYEL_E].buf,
				     jwk->e[JWK_RSA_KEYEL_E].len))
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

	case LWS_JWK_ENCTYPE_EC:

		lwsl_err("%s: EC not supported yet\n", __func__);
		return -1;

	default:
		lwsl_err("%s: unknown alg from jose\n", __func__);
		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_jws_sign_from_b64(const char *b64_hdr, size_t hdr_len, const char *b64_pay,
		      size_t pay_len, char *b64_sig, size_t sig_len,
		      enum lws_genhash_types hash_type, struct lws_jwk *jwk,
		      struct lws_context *context)
{
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genrsa_ctx rsactx;
	uint8_t *buf;
	int n;

	if (lws_genhash_init(&hash_ctx, hash_type))
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

	if (jwk->kty == LWS_JWK_KYT_RSA) {
		if (lws_genrsa_create(&rsactx, jwk->e, context, LGRSAM_PKCS1_1_5)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = jwk->e[JWK_RSA_KEYEL_N].len;
		buf = lws_malloc(n, "jws sign");
		if (!buf)
			return -1;

		n = lws_genrsa_public_sign(&rsactx, digest, hash_type, buf, n);
		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lws_free(buf);

			return -1;
		}

		n = lws_jws_base64_enc((char *)buf, n, b64_sig, sig_len);
		lws_free(buf);

		return n;
	}

	if (jwk->kty == LWS_JWK_KYT_OCT)
		return lws_jws_base64_enc((char *)digest,
					  lws_genhash_size(hash_type),
					  b64_sig, sig_len);

	/* unknown key type */

	return -1;

hash_fail:
	lws_genhash_destroy(&hash_ctx, NULL);
	return -1;
}

LWS_VISIBLE int
lws_jws_create_packet(struct lws_jwk *jwk, const char *payload, size_t len,
		      const char *nonce, char *out, size_t out_len,
		      struct lws_context *context)
{
	char *buf, *start, *p, *end, *p1, *end1, *b64_hdr, *b64_pay;
	int n, b64_hdr_len, b64_pay_len;

	/*
	 * This buffer is local to the function, the actual output
	 * is prepared into vhd->buf.  Only the plaintext protected header
	 * (which contains the public key, 512 bytes for 4096b) goes in
	 * here temporarily.
	 */
	n = LWS_PRE + 2048;
	buf = malloc(n);
	if (!buf) {
		lwsl_notice("%s: malloc %d failed\n", __func__, n);
		return -1;
	}

	p = start = buf + LWS_PRE;
	end = buf + n - LWS_PRE - 1;

	/*
	 * temporary JWS protected header plaintext
	 */

	p += lws_snprintf(p, end - p, "{\"alg\":\"RS256\",\"jwk\":");
	n = lws_jwk_export(jwk, 0, p, end - p);
	if (n < 0) {
		lwsl_notice("failed to export jwk\n");

		goto bail;
	}
	p += n;
	p += lws_snprintf(p, end - p, ",\"nonce\":\"%s\"}", nonce);

	/*
	 * prepare the signed outer JSON with all the parts in
	 */

	p1 = out;
	end1 = out + out_len - 1;

	p1 += lws_snprintf(p1, end1 - p1, "{\"protected\":\"");
	b64_hdr = p1;
	n = lws_jws_base64_enc(start, p - start, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode protected\n", __func__);
		goto bail;
	}
	b64_hdr_len = n;
	p1 += n;

	p1 += lws_snprintf(p1, end1 - p1, "\",\"payload\":\"");
	b64_pay = p1;
	n = lws_jws_base64_enc(payload, len, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode payload\n", __func__);
		goto bail;
	}
	b64_pay_len = n;

	p1 += n;
	p1 += lws_snprintf(p1, end1 - p1, "\",\"signature\":\"");

	/*
	 * taking the b64 protected header and the b64 payload, sign them
	 * and place the signature into the packet
	 */
	n = lws_jws_sign_from_b64(b64_hdr, b64_hdr_len, b64_pay, b64_pay_len,
				  p1, end1 - p1, LWS_GENHASH_TYPE_SHA256, jwk,
				  context);
	if (n < 0) {
		lwsl_notice("sig gen failed\n");

		goto bail;
	}
	p1 += n;
	p1 += lws_snprintf(p1, end1 - p1, "\"}");

	free(buf);

	return p1 - out;

bail:
	free(buf);

	return -1;
}
