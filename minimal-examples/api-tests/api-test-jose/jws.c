/*
 * lws-api-test-jose - RFC7515 jws tests
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
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
 */

/* for none, the compact serialization format is b64u(jose hdr).b64u(payload) */

static const char *none_cser =
	  "eyJhbGciOiJub25lIn0"
	  "."
	  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
	  "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
	  *none_jose = "{\"alg\":\"none\"}",
	  *none_payload	= "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n"
			  " \"http://example.com/is_root\":true}";

int
test_jws_none(struct lws_context *context)
{
	struct lws_jws_map map;
	struct lws_jose jose;
	char temp[2048];
	int n, temp_len = sizeof(temp), ret = -1;

	lws_jose_init(&jose);

	/* A.5 Unsecured JSON "none" RFC7515 worked example */

	/* decode the b64.b64[.b64] compact serialization blocks */
	n = lws_jws_compact_decode(none_cser, strlen(none_cser), &map, NULL,
				   temp, &temp_len);
	if (n != 2) {
		lwsl_err("%s: concat_map failed\n", __func__);
		goto bail;
	}

		/* confirm the decoded JOSE header is exactly what we expect */
		if (strncmp(none_jose, map.buf[LJWS_JOSE], map.len[LJWS_JOSE])) {
			lwsl_err("%s: jose b64 decode wrong\n", __func__);
			goto bail;
		}

	/* parse the JOSE header */
	if (lws_jws_parse_jose(&jose, map.buf[LJWS_JOSE],
			       map.len[LJWS_JOSE],
			       (char *)lws_concat_temp(temp, temp_len),
			       &temp_len) < 0 || !jose.alg) {
		lwsl_err("%s: JOSE parse failed\n", __func__);
		goto bail;
	}

		/* confirm we used the "none" alg as expected from JOSE hdr */
		if (strcmp(jose.alg->alg, "none")) {
			lwsl_err("%s: JOSE header has wrong alg\n", __func__);
			goto bail;
		}

		/* confirm the payload is literally what we expect */
		if (strncmp(none_payload, map.buf[LJWS_PYLD],
					  map.len[LJWS_PYLD])) {
			lwsl_err("%s: payload b64 decode wrong\n", __func__);
			goto bail;
		}

	/* end */

	ret = 0;

bail:
	lws_jose_destroy(&jose);

	if (ret)
		lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}



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
	   *hash_enc	= "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
;

int
test_jws_HS256(struct lws_context *context)
{
	char buf[2048], temp[256], *p = buf, *end = buf + sizeof(buf) - 1, *enc_ptr;
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_jws_map map;
	int temp_len = sizeof(temp);
	struct lws_genhmac_ctx ctx;
	struct lws_jose jose;
	struct lws_jwk jwk;
	struct lws_jws jws;
	int n;

	lws_jose_init(&jose);
	lws_jws_init(&jws, &jwk, context);

	/* Test 1: SHA256 on RFC7515 worked example */

	/* parse the JOSE header */

	if (lws_jws_parse_jose(&jose, test1, strlen(test1), temp, &temp_len) < 0 ||
			!jose.alg) {
		lwsl_err("%s: JOSE parse failed\n", __func__);
		goto bail;
	}

		/* confirm we used the "none" alg as expected from JOSE hdr */
		if (strcmp(jose.alg->alg, "HS256")) {
			lwsl_err("%s: JOSE header has wrong alg\n", __func__);
			goto bail;
		}

	/* 1.1: import the JWK oct key */

	if (lws_jwk_import(&jwk, NULL, NULL, key_jwk, strlen(key_jwk)) < 0) {
		lwsl_notice("Failed to decode JWK test key\n");
		return -1;
	}
		if (jwk.kty != LWS_GENCRYPTO_KTY_OCT) {
			lwsl_err("%s: unexpected kty %d\n", __func__, jwk.kty);

			return -1;
		}

	/* 1.2: create JWS known hdr + known payload */

	n = lws_jws_encode_section(test1, strlen(test1), 1, &p, end);
	if (n < 0) {
		goto bail;
	}

		if (strcmp(buf, test1_enc))
			goto bail;

	enc_ptr = p + 1; /* + 1 skips the . */
	n = lws_jws_encode_section(test2, strlen(test2), 0, &p, end);
	if (n < 0) {
		goto bail;
	}

		if (strcmp(enc_ptr, test2_enc))
			goto bail;

	/* 1.3: use HMAC SHA-256 with known key on the hdr . payload */

	if (lws_genhmac_init(&ctx, jose.alg->hmac_type,
			     jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf,
			     jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len))
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

	if (lws_jws_sig_confirm_compact_b64(buf, p - buf, &map, &jwk, context,
			lws_concat_temp(temp, temp_len), &temp_len) < 0) {
		lwsl_notice("%s: confirm sig failed\n", __func__);
		goto bail;
	}

	lws_jws_destroy(&jws);
	lws_jwk_destroy(&jwk);
	lws_jose_destroy(&jose);

	/* end */

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;

bail_destroy_hmac:
	lws_genhmac_destroy(&ctx, NULL);

bail:
	lws_jws_destroy(&jws);
	lws_jwk_destroy(&jwk);
	lws_jose_destroy(&jose);
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;
}


static const char
	/* the key from worked example in RFC7515 A-2, as a JWK */
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
	"p0igcN_IoypGlUPQGe77Rw"
;

int
test_jws_RS256(struct lws_context *context)
{
	struct lws_jws_map map;
	struct lws_jose jose;
	struct lws_jwk jwk;
	struct lws_jws jws;
	char temp[2048], *in;
	int n, l, temp_len = sizeof(temp);

	lws_jose_init(&jose);
	lws_jws_init(&jws, &jwk, context);

	/* Test 2: RS256 on RFC7515 worked example */

	if (lws_gencrypto_jws_alg_to_definition("RS256", &jose.alg)) {
		lwsl_err("%s: RS256 not supported\n", __func__);
		goto bail;
	}

	/* 2.1: import the jwk */

	if (lws_jwk_import(&jwk, NULL, NULL,
			   rfc7515_rsa_key, strlen(rfc7515_rsa_key))) {
		lwsl_notice("%s: 2.2: Failed to read JWK key\n", __func__);
		goto bail2;
	}

	if (jwk.kty != LWS_GENCRYPTO_KTY_RSA) {
		lwsl_err("%s: 2.2: kty: %d instead of RSA\n", __func__, jwk.kty);
		goto bail;
	}

	/* 2.2: check the signature on the test packet from RFC7515 A-1 */

	if (lws_jws_sig_confirm_compact_b64(rfc7515_rsa_a1,
					    strlen(rfc7515_rsa_a1), &map,
					    &jwk, context, temp, &temp_len) < 0) {
		lwsl_notice("%s: 2.2: confirm rsa sig failed\n", __func__);
		goto bail;
	}

	if (lws_jws_b64_compact_map(rfc7515_rsa_a1, strlen(rfc7515_rsa_a1),
				   &jws.map_b64) != 3) {
		lwsl_notice("%s: lws_jws_b64_compact_map failed\n", __func__);
		goto bail;
	}

	/* 2.3: generate our own signature for a copy of the test packet */

	in = lws_concat_temp(temp, temp_len);
	l = strlen(rfc7515_rsa_a1);
	if (temp_len < l + 1)
		goto bail;
	memcpy(in, rfc7515_rsa_a1, l + 1);
	temp_len -= l + 1;

	if (lws_jws_b64_compact_map(in, l, &jws.map_b64) != 3) {
		lwsl_notice("%s: lws_jws_b64_compact_map failed\n", __func__);
		goto bail;
	}

	/* overwrite the copy of the known b64 sig (it's all placed inside temp) */
	n = lws_jws_sign_from_b64(&jose, &jws,
				  (char *)jws.map_b64.buf[LJWS_SIG],
				  jws.map_b64.len[LJWS_SIG] + 8);
	if (n < 0) {
		lwsl_err("%s: failed signing test packet\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_SIG] = n;

	/* 2.4: confirm our signature can be verified */

	in[l] = '\0';
	if (lws_jws_sig_confirm_compact_b64(in, l, &map, &jwk, context, lws_concat_temp(temp, temp_len), &temp_len) < 0) {
		lwsl_notice("%s: 2.2: confirm rsa sig failed\n", __func__);
		goto bail;
	}

	lws_jwk_destroy(&jwk);

	/* end */

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;

bail:
	lws_jwk_destroy(&jwk);
bail2:
	lws_jws_destroy(&jws);
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;
}

static const char
	*es256_jose = "{\"alg\":\"ES256\"}",
	*es256_payload	= "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n"
			  " \"http://example.com/is_root\":true}",
	*es256_cser =
	    "eyJhbGciOiJFUzI1NiJ9"
	    "."
	    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
	    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	    "."
	    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
	    "pmWQxfKTUJqPP3-Kg6NU1Q",
	*es256_jwk =
	"{"
		"\"kty\":\"EC\","
		"\"crv\":\"P-256\","
		"\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
		"\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\","
		"\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\""
	"}"
#if 0
			,
	rfc7515_ec_a3_R[] = {
		 14, 209,  33,  83, 121,  99, 108,  72,  60,  47, 127,  21,  88,
		  7, 212,   2, 163, 178,  40,   3,  58, 249, 124, 126,  23, 129,
		154, 195,  22, 158, 166, 101
	},
	rfc7515_ec_a3_S[] = {
		197,  10,   7, 211, 140,  60, 112, 229, 216, 241,  45, 175,
		  8,  74,  84, 128, 166, 101, 144, 197, 242, 147,  80, 154,
		143,  63, 127, 138, 131, 163,  84, 213
	}
#endif
;

int
test_jws_ES256(struct lws_context *context)
{
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_jws_map map;
	struct lws_jose jose;
	struct lws_jwk jwk;
	struct lws_jws jws;
	char temp[2048], *p;
	int ret = -1, l, n, temp_len = sizeof(temp);

	/* A.3 "ES256" RFC7515 worked example - verify */

	lws_jose_init(&jose);

	/* decode the b64.b64[.b64] compact serialization blocks */
	if (lws_jws_compact_decode(es256_cser, strlen(es256_cser),
				   &jws.map, &jws.map_b64,
				   temp, &temp_len) != 3) {
		lwsl_err("%s: concat_map failed\n", __func__);
		goto bail;
	}

		/* confirm the decoded JOSE header is exactly what we expect */
		if (jws.map.len[LJWS_JOSE] != strlen(es256_jose) ||
		    strncmp(es256_jose, jws.map.buf[LJWS_JOSE],
				    jws.map.len[LJWS_JOSE])) {
			lwsl_err("%s: jose b64 decode wrong\n", __func__);
			goto bail;
		}

		/* confirm the decoded payload is exactly what we expect */
		if (jws.map.len[LJWS_PYLD] != strlen(es256_payload) ||
		    strncmp(es256_payload, jws.map.buf[LJWS_PYLD],
					    jws.map.len[LJWS_PYLD])) {
			lwsl_err("%s: payload b64 decode wrong\n", __func__);
			goto bail;
		}

	/* parse the JOSE header */
	if (lws_jws_parse_jose(&jose, jws.map.buf[LJWS_JOSE],
			       jws.map.len[LJWS_JOSE],
			       (char *)lws_concat_temp(temp, temp_len), &temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);
		goto bail;
	}

		/* confirm we used "ES256" alg we expect from the JOSE hdr */
		if (strcmp(jose.alg->alg, "ES256")) {
			lwsl_err("%s: JOSE header has wrong alg\n", __func__);
			goto bail;
		}

	jws.jwk = &jwk;
	jws.context = context;

	/* import the ES256 jwk */
	if (lws_jwk_import(&jwk, NULL, NULL, es256_jwk, strlen(es256_jwk))) {
		lwsl_notice("%s: Failed to read JWK key\n", __func__);
		goto bail;
	}

		/* sanity */
		if (jwk.kty != LWS_GENCRYPTO_KTY_EC) {
			lwsl_err("%s: kty: %d instead of EC\n",
					__func__, jwk.kty);
			goto bail1;
		}

	if (lws_jws_sig_confirm(&jws.map_b64, &jws.map, &jwk, context) < 0) {
		lwsl_notice("%s: confirm EC sig failed\n", __func__);
		goto bail1;
	}

	/* A.3 "ES256" RFC7515 worked example - sign */

	l = strlen(es256_cser);
	if (temp_len < l + 1)
		goto bail1;
	p = lws_concat_temp(temp, temp_len);
	memcpy(p, es256_cser, l + 1);
	temp_len -= l + 1;

	/* scan the b64 compact serialization string to map the blocks */
	if (lws_jws_b64_compact_map(p, l, &jws.map_b64) != 3)
		goto bail1;

	/* create the hash of the protected b64 part */
	if (lws_genhash_init(&hash_ctx, jose.alg->hash_type) ||
	    lws_genhash_update(&hash_ctx, jws.map_b64.buf[LJWS_JOSE],
			    jws.map_b64.len[LJWS_JOSE]) ||
	    lws_genhash_update(&hash_ctx, ".", 1) ||
	    lws_genhash_update(&hash_ctx, jws.map_b64.buf[LJWS_PYLD],
			    jws.map_b64.len[LJWS_PYLD]) ||
	    lws_genhash_destroy(&hash_ctx, digest)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		goto bail1;
	}

	lwsl_hexdump(jws.map_b64.buf[LJWS_SIG], jws.map_b64.len[LJWS_SIG]);

	/* overwrite the copy of the known b64 sig (it's placed inside buf) */
	n = lws_jws_sign_from_b64(&jose, &jws,
				  (char *)jws.map_b64.buf[LJWS_SIG],
				  jws.map_b64.len[LJWS_SIG] + 8);
	if (n < 0) {
		lwsl_err("%s: failed signing test packet\n", __func__);
		goto bail1;
	}
	jws.map_b64.len[LJWS_SIG] = n;

	lwsl_hexdump(jws.map_b64.buf[LJWS_SIG], jws.map_b64.len[LJWS_SIG]);

	/* 2.4: confirm our generated signature can be verified */

//	lwsl_err("p %p, l %d\n", p, (int)l);
	p[l] = '\0';
	if (lws_jws_sig_confirm_compact_b64(p, l, &map, &jwk, context, lws_concat_temp(temp, temp_len), &temp_len) < 0) {
		lwsl_notice("%s: confirm our EC sig failed\n", __func__);
		goto bail1;
	}

	/* end */
	ret =  0;

bail1:
	lws_jwk_destroy(&jwk);
	lws_jose_destroy(&jose);

bail:
	lwsl_notice("%s: selftest %s\n", __func__, ret ? "FAIL" : "OK");

	return ret;
}

static const char
	*es512_jose = "{\"alg\":\"ES512\"}",
	*es512_payload	= "Payload",
	*es512_cser =
	     "eyJhbGciOiJFUzUxMiJ9"
	     "."
	     "UGF5bG9hZA"
	     "."
	     "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq"
	     "wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp"
	     "EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn",
	*es512_jwk =
	   "{"
	      "\"kty\":\"EC\","
	      "\"crv\":\"P-521\","
	      "\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_"
	           "NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\","
	      "\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl"
	           "y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\","
	      "\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA"
	           "xerEzgdRhajnu0ferB0d53vM9mE15j2C\""
	   "}"
;

int
test_jws_ES512(struct lws_context *context)
{
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_jws_map map;
	struct lws_jose jose;
	struct lws_jwk jwk;
	struct lws_jws jws;
	char temp[2048], *p;
	int ret = -1, l, n, temp_len = sizeof(temp);

	/* A.4 "ES512" RFC7515 worked example - verify */

	lws_jose_init(&jose);

	/* decode the b64.b64[.b64] compact serialization blocks */
	if (lws_jws_compact_decode(es512_cser, strlen(es512_cser),
				   &jws.map, &jws.map_b64, temp,
				   &temp_len) != 3) {
		lwsl_err("%s: concat_map failed\n", __func__);
		goto bail;
	}

		/* confirm the decoded JOSE header is exactly what we expect */
		if (jws.map.len[LJWS_JOSE] != strlen(es512_jose) ||
		    strncmp(es512_jose, jws.map.buf[LJWS_JOSE],
				        jws.map.len[LJWS_JOSE])) {
			lwsl_err("%s: jose b64 decode wrong\n", __func__);
			goto bail;
		}

		/* confirm the decoded payload is exactly what we expect */
		if (jws.map.len[LJWS_PYLD] != strlen(es512_payload) ||
		    strncmp(es512_payload, jws.map.buf[LJWS_PYLD],
					   jws.map.len[LJWS_PYLD])) {
			lwsl_err("%s: payload b64 decode wrong\n", __func__);
			goto bail;
		}

	/* parse the JOSE header */
	if (lws_jws_parse_jose(&jose, jws.map.buf[LJWS_JOSE],
			      jws.map.len[LJWS_JOSE],
			      lws_concat_temp(temp, temp_len), &temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);
		goto bail;
	}

		/* confirm we used "es512" alg we expect from the JOSE hdr */
		if (strcmp(jose.alg->alg, "ES512")) {
			lwsl_err("%s: JOSE header has wrong alg\n", __func__);
			goto bail;
		}

	jws.jwk = &jwk;
	jws.context = context;

	/* import the es512 jwk */
	if (lws_jwk_import(&jwk, NULL, NULL, es512_jwk, strlen(es512_jwk))) {
		lwsl_notice("%s: Failed to read JWK key\n", __func__);
		goto bail;
	}

		/* sanity */
		if (jwk.kty != LWS_GENCRYPTO_KTY_EC) {
			lwsl_err("%s: kty: %d instead of EC\n",
					__func__, jwk.kty);
			goto bail1;
		}

	if (lws_jws_sig_confirm(&jws.map_b64, &jws.map, &jwk, context) < 0) {
		lwsl_notice("%s: confirm EC sig failed\n", __func__);
		goto bail1;
	}

	/* A.3 "es512" RFC7515 worked example - sign */

	l = strlen(es512_cser);
	if (temp_len < l)
		goto bail1;
	p = lws_concat_temp(temp, temp_len);
	memcpy(p, es512_cser, l + 1);
	temp_len -= (l + 1);

	/* scan the b64 compact serialization string to map the blocks */
	if (lws_jws_b64_compact_map(p, l, &jws.map_b64) != 3)
		goto bail1;

	/* create the hash of the protected b64 part */
	if (lws_genhash_init(&hash_ctx, jose.alg->hash_type) ||
	    lws_genhash_update(&hash_ctx, jws.map_b64.buf[LJWS_JOSE],
			       jws.map_b64.len[LJWS_JOSE]) ||
	    lws_genhash_update(&hash_ctx, ".", 1) ||
	    lws_genhash_update(&hash_ctx, jws.map_b64.buf[LJWS_PYLD],
			       jws.map_b64.len[LJWS_PYLD]) ||
	    lws_genhash_destroy(&hash_ctx, digest)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		goto bail1;
	}

	/* overwrite the copy of the known b64 sig (it's placed inside buf) */
	n = lws_jws_sign_from_b64(&jose, &jws,
				  (char *)jws.map_b64.buf[LJWS_SIG], 1024);
	if (n < 0) {
		lwsl_err("%s: failed signing test packet\n", __func__);
		goto bail1;
	}
	jws.map_b64.len[LJWS_SIG] = n;

	/* 2.4: confirm our generated signature can be verified */

	p[l] = '\0';

	if (lws_jws_sig_confirm_compact_b64(p, l, &map, &jwk, context,
			lws_concat_temp(temp, temp_len), &temp_len) < 0) {
		lwsl_notice("%s: confirm our ECDSA sig failed\n", __func__);
		goto bail1;
	}

	/* end */
	ret =  0;

bail1:
	lws_jwk_destroy(&jwk);
	lws_jose_destroy(&jose);

bail:
	lwsl_notice("%s: selftest %s\n", __func__, ret ? "FAIL" : "OK");

	return ret;
}

int
test_jws(struct lws_context *context)
{
	int n = 0;

	n |= test_jws_none(context);
	n |= test_jws_HS256(context);
	n |= test_jws_RS256(context);
	n |= test_jws_ES256(context);
	n |= test_jws_ES512(context);

	return n;
}
