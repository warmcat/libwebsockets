/*
 * libwebsockets - JSON Web Signature support
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
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

/*
 * JSON Web Signature is defined in RFC7515
 *
 * https://tools.ietf.org/html/rfc7515
 *
 * It's basically a way to wrap some JSON with a JSON "header" describing the
 * crypto, and a signature, all in a BASE64 wrapper with elided terminating '='.
 *
 * The signature stays with the content, it serves a different purpose than eg
 * a TLS tunnel to transfer it.
 *
 * RFC7518 (JSON Web Algorithms) says for the "alg" names
 *
 * | HS256        | HMAC using SHA-256            | Required           |
 * | HS384        | HMAC using SHA-384            | Optional           |
 * | HS512        | HMAC using SHA-512            | Optional           |
 * | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
 * | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
 * |              | SHA-384                       |                    |
 * | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
 * |              | SHA-512                       |                    |
 * | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
 * | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
 * | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
 *
 * Boulder (FOSS ACME provider) supports RS256, ES256, ES384 and ES512
 * currently.  The "Recommended+" just means it is recommended but will likely
 * be "very recommended" soon.
 *
 * We support HS256/384/512 for symmetric crypto, but the choice for the
 * asymmetric crypto isn't as easy to make.
 *
 * Normally you'd choose the EC option but these are defined to use the
 * "NIST curves" (RFC7518 3.4) which are believed to be insecure.
 *
 * https://safecurves.cr.yp.to/
 *
 * For that reason we implement RS256/384/512 for asymmetric.
 */

#if defined(LWS_WITH_SELFTESTS)
static const char
	   *test1	= "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}",
	   *test1_enc	= "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
	   *test2	= "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n"
			  " \"http://example.com/is_root\":true}",
	   *test2_enc	= "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQ"
			  "ogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
	   *key_jwk	= "{\"kty\":\"oct\",\r\n"
			  " \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQ"
			  "Lr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}",
	   *hash_enc	= "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	   /* the key from worked example in RFC7515 A-1, as a JWK */
	   *rfc7515_rsa_key =
	"{\"kty\":\"RSA\","
	" \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
	 "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
	 "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
	 "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
	 "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
	 "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\","
	"\"e\":\"AQAB\","
	"\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
	 "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
	 "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
	 "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
	 "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
	 "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\","
	"\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
	 "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
	 "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\","
	"\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
	 "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
	 "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\","
	"\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
	 "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
	 "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\","
	"\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
	 "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
	 "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\","
	"\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
	 "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
	 "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\""
	"}",
	   *rfc7515_rsa_a1 = /* the signed worked example in RFC7515 A-1 */
	 "eyJhbGciOiJSUzI1NiJ9"
	 ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
	 "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	 ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
	 "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
	 "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
	 "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
	 "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
	 "p0igcN_IoypGlUPQGe77Rw";
#endif

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


static const char * const jhdr_tok[] = {
	"typ",
	"alg",
};
enum enum_jhdr_tok {
	JHP_TYP,
	JHP_ALG
};
struct cb_hdr_s {
	enum lws_genhash_types hash_type;
	enum lws_genhmac_types hmac_type;
	char alg[10];
	int is_rsa:1;
};

static signed char
cb_hdr(struct lejp_ctx *ctx, char reason)
{
	struct cb_hdr_s *s = (struct cb_hdr_s *)ctx->user;

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case JHP_TYP: /* it is optional */
		if (strcmp(ctx->buf, "JWT"))
			return -1;
		break;
	case JHP_ALG:
		lws_strncpy(s->alg, ctx->buf, sizeof(s->alg));
		if (!strcmp(ctx->buf, "HS256")) {
			s->hmac_type = LWS_GENHMAC_TYPE_SHA256;
			break;
		}
		if (!strcmp(ctx->buf, "HS384")) {
			s->hmac_type = LWS_GENHMAC_TYPE_SHA384;
			break;
		}
		if (!strcmp(ctx->buf, "HS512")) {
			s->hmac_type = LWS_GENHMAC_TYPE_SHA512;
			break;
		}
		if (!strcmp(ctx->buf, "RS256")) {
			s->hash_type = LWS_GENHASH_TYPE_SHA256;
			s->is_rsa = 1;
			break;
		}
		if (!strcmp(ctx->buf, "RS384")) {
			s->hash_type = LWS_GENHASH_TYPE_SHA384;
			s->is_rsa = 1;
			break;
		}
		if (!strcmp(ctx->buf, "RS512")) {
			s->hash_type = LWS_GENHASH_TYPE_SHA512;
			s->is_rsa = 1;
			break;
		}
		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_jws_confirm_sig(const char *in, size_t len, struct lws_jwk *jwk)
{
	int sig_pos = lws_jws_find_sig(in, len), pos = 0, n, m, h_len;
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genrsa_ctx rsactx;
	struct lws_genhmac_ctx ctx;
	struct cb_hdr_s args;
	struct lejp_ctx jctx;
	char buf[2048];

	/* 1) there has to be a signature */

	if (sig_pos < 0)
		return -1;

	/* 2) find length of first, hdr, block */

	while (in[pos] != '.' && pos < (int)len)
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
	 */

	args.alg[0] = '\0';
	args.is_rsa = 0;
	lejp_construct(&jctx, cb_hdr, &args, jhdr_tok, ARRAY_SIZE(jhdr_tok));
	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)buf, n);
	lejp_destruct(&jctx);
	if (m < 0) {
		lwsl_notice("parse got %d: alg %s\n", m, args.alg);
		return -1;
	}

	/* 5) decode the B64URL signature part into buf / m */

	m = lws_b64_decode_string_len(in + sig_pos, len - sig_pos,
				      buf, sizeof(buf) - 1);

	if (args.is_rsa) {

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

		if (lws_genrsa_create(&rsactx, &jwk->el)) {
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

		return 0;
	}

	/* SHA256/384/512 HMAC */

	h_len = lws_genhmac_size(args.hmac_type);
	if (m < 0 || m != h_len)
		return -1;

	/* 6) compute HMAC over payload */

	if (lws_genhmac_init(&ctx, args.hmac_type, jwk->el.e[JWK_KEY_E].buf,
			     jwk->el.e[JWK_KEY_E].len))
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

	return 0;
}

LWS_VISIBLE int
lws_jws_sign_from_b64(const char *b64_hdr, size_t hdr_len, const char *b64_pay,
		      size_t pay_len, char *b64_sig, size_t sig_len,
		      enum lws_genhash_types hash_type, struct lws_jwk *jwk)
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

	if (!strcmp(jwk->keytype, "RSA")) {
		if (lws_genrsa_create(&rsactx, &jwk->el)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = jwk->el.e[JWK_KEY_N].len;
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

	if (!strcmp(jwk->keytype, "oct"))
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
		      const char *nonce, char *out, size_t out_len)
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
				  p1, end1 - p1, LWS_GENHASH_TYPE_SHA256, jwk);
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


#if defined(LWS_WITH_SELFTESTS)
/*
 * These are the inputs and outputs from the worked example in RFC7515
 * Appendix A.1.
 *
 * 1) has a fixed header + payload, and a fixed SHA256 HMAC key, and must give
 * a fixed BASE64URL result.
 *
 * 2) has a fixed header + payload and is signed with a key given in JWK format
 */
int
lws_jws_selftest(void)
{
	struct lws_genhmac_ctx ctx;
	struct lws_jwk jwk;
	char buf[2048], *p = buf, *end = buf + sizeof(buf) - 1, *enc_ptr, *p1;
	uint8_t digest[LWS_GENHASH_LARGEST];
	int n;

	/* Test 1: SHA256 on RFC7515 worked example */

	/* 1.1: decode the JWK oct key */

	if (lws_jwk_import(&jwk, key_jwk, strlen(key_jwk)) < 0) {
		lwsl_notice("Failed to decode JWK test key\n");
		return -1;
	}

	/* 1.2: create JWS known hdr + known payload */

	n = lws_jws_encode_section(test1, strlen(test1), 1, &p, end);
	if (n < 0)
		goto bail;
	if (strcmp(buf, test1_enc))
		goto bail;

	enc_ptr = p + 1; /* + 1 skips the . */
	n = lws_jws_encode_section(test2, strlen(test2), 0, &p, end);
	if (n < 0)
		goto bail;
	if (strcmp(enc_ptr, test2_enc))
		goto bail;

	/* 1.3: use HMAC SHA-256 with known key on the hdr . payload */

	if (lws_genhmac_init(&ctx, LWS_GENHMAC_TYPE_SHA256,
			     jwk.el.e[JWK_KEY_E].buf, jwk.el.e[JWK_KEY_E].len))
		goto bail;
	if (lws_genhmac_update(&ctx, (uint8_t *)buf, p - buf))
		goto bail_destroy_hmac;
	lws_genhmac_destroy(&ctx, digest);

	/* 1.4: append a base64 encode of the computed HMAC digest */

	enc_ptr = p + 1; /* + 1 skips the . */
	n = lws_jws_encode_section((const char *)digest, 32, 0, &p, end);
	if (n < 0)
		goto bail;
	if (strcmp(enc_ptr, hash_enc)) /* check against known B64URL hash */
		goto bail;

	/* 1.5: Check we can agree the signature matches the payload */

	if (lws_jws_confirm_sig(buf, p - buf, &jwk) < 0) {
		lwsl_notice("confirm sig failed\n");
		goto bail;
	}

	lws_jwk_destroy(&jwk); /* finished with the key from the first test */

	/* Test 2: RSA256 on RFC7515 worked example */

	/* 2.1: turn the known JWK key for the RSA test into a lws_jwk */

	if (lws_jwk_import(&jwk, rfc7515_rsa_key, strlen(rfc7515_rsa_key))) {
		lwsl_notice("Failed to read JWK key\n");
		goto bail2;
	}

	/* 2.2: check the signature on the test packet from RFC7515 A-1 */

	if (lws_jws_confirm_sig(rfc7515_rsa_a1, strlen(rfc7515_rsa_a1),
				&jwk) < 0) {
		lwsl_notice("confirm rsa sig failed\n");
		goto bail;
	}

	/* 2.3: generate our own signature for a copy of the test packet */

	memcpy(buf, rfc7515_rsa_a1, strlen(rfc7515_rsa_a1));

	/* set p to second . */
	p = strchr(buf + 1, '.');
	p1 = strchr(p + 1, '.');

	n = lws_jws_sign_from_b64(buf, p - buf, p + 1, p1 - (p + 1),
				  p1 + 1, sizeof(buf) - (p1 - buf) - 1,
				  LWS_GENHASH_TYPE_SHA256, &jwk);
	if (n < 0)
		goto bail;

	puts(buf);

	/* 2.4: confirm our signature can be verified */

	if (lws_jws_confirm_sig(buf, (p1 + 1 + n) - buf, &jwk) < 0) {
		lwsl_notice("confirm rsa sig 2 failed\n");
		goto bail;
	}

	lws_jwk_destroy(&jwk);

	/* end */

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;

bail_destroy_hmac:
	lws_genhmac_destroy(&ctx, NULL);

bail:
	lws_jwk_destroy(&jwk);
bail2:
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;
}
#endif
