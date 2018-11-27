/*
 * lws-api-test-jose - RFC7515 jws tests
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

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
test_jws(struct lws_context *context)
{
	struct lws_genhmac_ctx ctx;
	struct lws_jwk jwk;
	char buf[2048], *p = buf, *end = buf + sizeof(buf) - 1, *enc_ptr, *p1;
	uint8_t digest[LWS_GENHASH_LARGEST];
	int n;

	/* Test 1: SHA256 on RFC7515 worked example */

	/* 1.1: decode the JWK oct key */

	if (lws_jwk_import(&jwk, NULL, NULL, key_jwk, strlen(key_jwk)) < 0) {
		lwsl_notice("Failed to decode JWK test key\n");
		return -1;
	}
	if (jwk.kty != LWS_JWK_KYT_OCT) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jwk.kty);

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
			     jwk.e[JWK_OCT_KEYEL_K].buf,
			     jwk.e[JWK_OCT_KEYEL_K].len))
		goto bail;
	if (lws_genhmac_update(&ctx, (uint8_t *)buf, p - buf))
		goto bail_destroy_hmac;
	lws_genhmac_destroy(&ctx, digest);

	/* 1.4: append a base64 encode of the computed HMAC digest */

	enc_ptr = p + 1; /* + 1 skips the . */
	n = lws_jws_encode_section((const char *)digest, 32, 0, &p, end);
	if (n < 0)
		goto bail;
	if (strcmp(enc_ptr, hash_enc)) { /* check against known B64URL hash */
		lwsl_err("%s: b64 enc of computed HMAC mismatches '%s' '%s'\n",
			 __func__, enc_ptr, hash_enc);
		goto bail;
	}

	/* 1.5: Check we can agree the signature matches the payload */

	if (lws_jws_confirm_sig(buf, p - buf, &jwk, context) < 0) {
		lwsl_notice("confirm sig failed\n");
		goto bail;
	}

	lws_jwk_destroy(&jwk); /* finished with the key from the first test */

	/* Test 2: RSA256 on RFC7515 worked example */

	/* 2.1: turn the known JWK key for the RSA test into a lws_jwk */

	if (lws_jwk_import(&jwk, NULL, NULL,
			   rfc7515_rsa_key, strlen(rfc7515_rsa_key))) {
		lwsl_notice("%s: 2.2: Failed to read JWK key\n", __func__);
		goto bail2;
	}

	if (jwk.kty != LWS_JWK_KYT_RSA) {
		lwsl_err("%s: 2.2: kty: %d instead of RSA\n", __func__, jwk.kty);
	}

	/* 2.2: check the signature on the test packet from RFC7515 A-1 */

	if (lws_jws_confirm_sig(rfc7515_rsa_a1, strlen(rfc7515_rsa_a1),
				&jwk, context) < 0) {
		lwsl_notice("%s: 2.2: confirm rsa sig failed\n", __func__);
		goto bail;
	}

	/* 2.3: generate our own signature for a copy of the test packet */

	memcpy(buf, rfc7515_rsa_a1, strlen(rfc7515_rsa_a1));

	/* set p to second . */
	p = strchr(buf + 1, '.');
	p1 = strchr(p + 1, '.');

	n = lws_jws_sign_from_b64(buf, p - buf, p + 1, p1 - (p + 1),
				  p1 + 1, sizeof(buf) - (p1 - buf) - 1,
				  LWS_GENHASH_TYPE_SHA256, &jwk, context);
	if (n < 0) {
		lwsl_err("%s: failed signing test packet\n", __func__);
		goto bail;
	}

	// puts(buf);

	/* 2.4: confirm our signature can be verified */

	if (lws_jws_confirm_sig(buf, (p1 + 1 + n) - buf, &jwk, context) < 0) {
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
