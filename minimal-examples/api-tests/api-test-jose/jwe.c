/*
 * lws-api-test-jose - RFC7516 jwe tests
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>


/* A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 */

/* "Live long and prosper." */
static
uint8_t

#if 0
lws_jwe_ex_a2_plaintext[] = {
	76, 105, 118, 101, 32, 108, 111, 110,
	103, 32, 97, 110, 100, 32,  112, 114,
	111, 115, 112, 101, 114, 46
},
#endif
*lws_jwe_ex_a2_jose_hdr = (uint8_t *)
	"{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\"}",

*lws_jwe_ex_a2_jose_hdr_b64utf8 = (unsigned char *)
	"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",

lws_jwe_ex_a2_cek[] = {
	  4, 211,  31, 197,  84, 157, 252, 254,
	 11, 100, 157, 250,  63, 170, 106, 206,
	107, 124, 212,  45, 111, 107,   9, 219,
	200, 177,   0, 240, 143, 156,  44, 207
},

*lws_jwe_ex_a2_jwk_json = (uint8_t *)
"{"
 "\"kty\":\"RSA\","
 "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
	 "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
	 "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
	 "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
	 "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
	 "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\","
 "\"e\":\"AQAB\","
 "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
	 "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
	 "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
	 "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
	 "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
	 "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\","
 "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
	 "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
	 "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\","
 "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
	 "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
	 "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\","
 "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
	 "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
	 "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\","
 "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
	 "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
	 "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\","
 "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
	 "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
	 "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\""
"}",

lws_jwe_ex_a2_jwk_enc_key[] = {
	  80, 104,  72,  58,  11, 130, 236, 139,
	 132, 189, 255, 205,  61,  86, 151, 176,
	  99,  40,  44, 233, 176, 189, 205,  70,
	 202, 169,  72,  40, 226, 181, 156, 223,
	 120, 156, 115, 232, 150, 209, 145, 133,
	 104, 112, 237, 156, 116, 250,  65, 102,
	 212, 210, 103, 240, 177,  61,  93,  40,
	  71, 231, 223, 226, 240, 157,  15,  31,
	 150,  89, 200, 215, 198, 203, 108,  70,
	 117,  66, 212, 238, 193, 205,  23, 161,
	 169, 218, 243, 203, 128, 214, 127, 253,
	 215, 139,  43,  17, 135, 103, 179, 220,
	  28,   2, 212, 206, 131, 158, 128,  66,
	  62, 240,  78, 186, 141, 125, 132, 227,
	  60, 137,  43,  31, 152, 199,  54,  72,
	  34, 212, 115,  11, 152, 101,  70,  42,
	 219, 233, 142,  66, 151, 250, 126, 146,
	 141, 216, 190,  73,  50, 177, 146,   5,
	  52, 247,  28, 197,  21,  59, 170, 247,
	 181,  89, 131, 241, 169, 182, 246,  99,
	  15,  36, 102, 166, 182, 172, 197, 136,
	 230, 120,  60,  58, 219, 243, 149,  94,
	 222, 150, 154, 194, 110, 227, 225, 112,
	  39,  89, 233, 112, 207, 211, 241, 124,
	 174,  69, 221, 179, 107, 196, 225, 127,
	 167, 112, 226,  12, 242,  16,  24,  28,
	 120, 182, 244, 213, 244, 153, 194, 162,
	  69, 160, 244, 248,  63, 165, 141,   4,
	 207, 249, 193,  79, 131,   0, 169, 233,
	 127, 167, 101, 151, 125,  56, 112, 111,
	 248,  29, 232,  90,  29, 147, 110, 169,
	 146, 114, 165, 204,  71, 136,  41, 252
}
#if 0
,
*lws_jwe_ex_a2_jwk_enc_key_b64 = (uint8_t *)
	"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"
	"1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"
	"HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"
	"NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"
	"rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"
	"-B3oWh2TbqmScqXMR4gp_A",

lws_jwe_ex_a2_iv[] = {
	  3,  22,  60,  12,  43,  67, 104, 105,
	108, 108, 105,  99, 111, 116, 104, 101
},

*lws_jwe_ex_a2_iv_b64 = (uint8_t *)
	"AxY8DCtDaGlsbGljb3RoZQ",

lws_jwe_ex_a2_aad[] = {
	101, 121,  74, 104,  98,  71,  99, 105,
	 79, 105,  74,  83,  85,  48,  69, 120,
	 88, 122,  85, 105,  76,  67,  74, 108,
	 98, 109,  77, 105,  79, 105,  74,  66,
	 77,  84,  73,  52,  81,  48,  74,  68,
	 76,  85, 104,  84,  77, 106,  85,  50,
	 73, 110,  48
},

lws_jwe_ex_a2_ciphertext[] = {
	 40,  57,  83, 181, 119,  33, 133, 148,
	198, 185, 243,  24, 152, 230,   6,  75,
	129, 223, 127,  19, 210,  82, 183, 230,
	168,  33, 215, 104, 143, 112,  56, 102
},

*lws_jwe_ex_a2_ciphertext_b64 = (uint8_t *)
	"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",

lws_jwe_ex_a2_authtag[] = {
	246,  17, 244, 190,   4,  95,  98,   3,
	231,   0, 115, 157, 242, 203, 100, 191
},

*lws_jwe_ex_a2_authtag_b64 = (uint8_t *)
	"9hH0vgRfYgPnAHOd8stkvw",

*lws_jwe_ex_a2_aggregated = (uint8_t *)
	"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
	"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"
	"1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"
	"HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"
	"NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"
	"rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"
	"-B3oWh2TbqmScqXMR4gp_A."
	"AxY8DCtDaGlsbGljb3RoZQ."
	"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
	"9hH0vgRfYgPnAHOd8stkvw"
#endif
;

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
test_jwe(struct lws_context *context)
{
	struct lws_genrsa_ctx rsactx;
	struct lws_jwk jwk;
	uint8_t enc_cek[sizeof(lws_jwe_ex_a2_jwk_enc_key) + 2048];
	char buf[2048], *p = buf, *end = buf + sizeof(buf) - 1;
	int n;

	/* Test 1: A.2 */

	/* Decode the JWK JSON key */

	if (lws_jwk_import(&jwk, NULL, NULL, (char *)lws_jwe_ex_a2_jwk_json,
			   strlen((char *)lws_jwe_ex_a2_jwk_json)) < 0) {
		lwsl_notice("Failed to decode JWK test key\n");
		return -1;
	}

	if (jwk.kty != LWS_JWK_KYT_RSA) {
		lwsl_err("%s: unexpected kty %d\n", __func__, jwk.kty);

		return -1;
	}

	/* A.2.1: encode JOSE header and confirm matches official string */

	n = lws_jws_encode_section((char *)lws_jwe_ex_a2_jose_hdr,
				   strlen((char *)lws_jwe_ex_a2_jose_hdr), 1,
				   &p, end);
	if (n < 0)
		goto bail;
	if (strcmp(buf, (char *)lws_jwe_ex_a2_jose_hdr_b64utf8))
		goto bail;

	/* A.2.3: Encrypt the CEK with the recipient's public key using the
	 *        RSAES-PKCS1-v1_5 algorithm to produce the JWE Encrypted Key.
	 */

	if (lws_genrsa_create(&rsactx, jwk.e, context)) {
		lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
			    __func__);
		goto bail;
	}

	memset(enc_cek, 0, sizeof(enc_cek));

	n = lws_genrsa_public_encrypt(&rsactx, lws_jwe_ex_a2_cek,
				      sizeof(lws_jwe_ex_a2_cek), enc_cek);
	lws_genrsa_destroy(&rsactx);
	if (n < 0) {
		lwsl_err("%s: encrypt cek fail\n", __func__);
		goto bail;
	}
#if 0
	if (memcmp(enc_cek, lws_jwe_ex_a2_jwk_enc_key, sizeof(enc_cek))) {
		lwsl_err("%s: encrypt cek wrong output\n", __func__);
		lwsl_hexdump_notice(enc_cek, sizeof(enc_cek));
		lwsl_hexdump_notice(lws_jwe_ex_a2_jwk_enc_key,
				    sizeof(lws_jwe_ex_a2_jwk_enc_key));
		goto bail;
	}


	enc_ptr = p + 1; /* + 1 skips the . */
	n = lws_jws_encode_section(test2, strlen(test2), 0, &p, end);
	if (n < 0)
		goto bail;
	if (strcmp(enc_ptr, test2_enc))
		goto bail;

	/* 1.3: use HMAC SHA-256 with known key on the hdr . payload */

	if (lws_genhmac_init(&ctx, LWS_GENHMAC_TYPE_SHA256,
			     jwk.el.e[JWK_RSA_KEYEL_E].buf,
			     jwk.el.e[JWK_RSA_KEYEL_E].len))
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
#endif
	lws_jwk_destroy(&jwk);

	/* end */

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;
#if 0
bail_destroy_hmac:
	lws_genhmac_destroy(&ctx, NULL);
#endif
bail:
	lws_jwk_destroy(&jwk);
//bail2:
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;

}
