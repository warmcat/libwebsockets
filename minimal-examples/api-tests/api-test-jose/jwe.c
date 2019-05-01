/*
 * lws-api-test-jose - RFC7516 jwe tests
 *
 * Written in 2010-2018 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

/*
 * These are the inputs and outputs from the worked example in RFC7516
 * Appendix A.1   {"alg":"RSA-OAEP","enc":"A256GCM"}
 */


static char

*ex_a1_ptext =
	"The true sign of intelligence is not knowledge but imagination.",

*ex_a1_compact =
	"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
	"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
	"ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
	"Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
	"mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
	"1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
	"6UklfCpIMfIjf7iGdXKHzg."
	"48V1_ALb6US04U3b."
	"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
	"SdiwkIr3ajwQzaBtQD_A."
	"XFBoMYUZodetZdvTiFvSkQ",

	*ex_a1_jwk_json =
	"{\"kty\":\"RSA\","
	  "\"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW"
		"cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S"
		"psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a"
		"sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS"
		"tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj"
		"YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\","
	  "\"e\":\"AQAB\","
	  "\"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N"
		"WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9"
		"3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk"
		"qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl"
		"t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd"
		"VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\","
	  "\"p\":\"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-"
		"SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf"
		"fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0\","
	  "\"q\":\"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm"
		"UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX"
		"IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc\","
	  "\"dp\":\"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL"
		"hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827"
		"rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE\","
	  "\"dq\":\"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj"
		"ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB"
		"UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis\","
	  "\"qi\":\"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7"
		"AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3"
		"eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\""
	"}"
;

static int
test_jwe_a1(struct lws_context *context)
{
	struct lws_jwe jwe;
	char temp[2048], compact[2048];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, ex_a1_jwk_json,
			   strlen(ex_a1_jwk_json)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode(ex_a1_compact, strlen(ex_a1_compact),
				   &jwe.jws.map, &jwe.jws.map_b64, temp,
				   &temp_len) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < strlen(ex_a1_ptext) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ex_a1_ptext,
			        strlen(ex_a1_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ex_a1_ptext, strlen(ex_a1_ptext));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	/*
	 * Canned decrypt worked properly... let's also try encoding the
	 * plaintext ourselves and decoding that...
	 */
	lws_jwe_destroy(&jwe);
	temp_len = sizeof(temp);
	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, ex_a1_jwk_json,
			   strlen(ex_a1_jwk_json)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	if (lws_gencrypto_jwe_alg_to_definition("RSA-OAEP", &jwe.jose.alg)) {
		lwsl_err("Unknown cipher alg \"RSA-OAEP\"\n");
		goto bail;
	}
	if (lws_gencrypto_jwe_enc_to_definition("A256GCM", &jwe.jose.enc_alg)) {
		lwsl_err("Unknown payload enc alg \"A256GCM\"\n");
		goto bail;
	}

	/* we require a JOSE-formatted header to do the encryption */

	jwe.jws.map.buf[LJWS_JOSE] = temp;
	jwe.jws.map.len[LJWS_JOSE] = lws_snprintf(temp, temp_len,
			"{\"alg\":\"%s\",\"enc\":\"%s\"}", "RSA-OAEP", "A256GCM");
	temp_len -= jwe.jws.map.len[LJWS_JOSE];

	/*
	 * dup the plaintext into the ciphertext element, it will be
	 * encrypted in-place to a ciphertext of the same length
	 */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_CTXT,
				lws_concat_temp(temp, temp_len), &temp_len,
				ex_a1_ptext, strlen(ex_a1_ptext), 0)) {
		lwsl_notice("%s: Not enough temp space for ptext\n", __func__);
		goto bail;
	}

	/* CEK size is determined by hash / hmac size */

	n = lws_gencrypto_bits_to_bytes(jwe.jose.enc_alg->keybits_fixed);
	if (lws_jws_randomize_element(context, &jwe.jws.map, LJWE_EKEY,
				      lws_concat_temp(temp, temp_len),
				      &temp_len, n,
				      LWS_JWE_LIMIT_KEY_ELEMENT_BYTES)) {
		lwsl_err("Problem getting random\n");
		goto bail;
	}

	n = lws_jwe_encrypt(&jwe, lws_concat_temp(temp, temp_len),
			    &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt failed\n", __func__);
		goto bail;
	}
	n = lws_jwe_render_compact(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n",
			 __func__, n);
		goto bail;
	}

	// puts(compact);

	/*
	 * Okay... what happens when we try to decode what we created?
	 */

	lws_jwe_destroy(&jwe);
	lws_jwe_init(&jwe, context);
	temp_len = sizeof(temp);

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode(compact, strlen(compact), &jwe.jws.map,
				   &jwe.jws.map_b64, temp, &temp_len) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, ex_a1_jwk_json,
			   strlen(ex_a1_jwk_json)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: generated lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}


/* A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
 *
 * This example encrypts the plaintext "Live long and prosper." to the
 * recipient using RSAES-PKCS1-v1_5 for key encryption and
 * AES_128_CBC_HMAC_SHA_256 for content encryption.
 */

/* "Live long and prosper." */
static uint8_t

ex_a2_ptext[] = {
	76, 105, 118, 101, 32, 108, 111, 110,
	103, 32, 97, 110, 100, 32,  112, 114,
	111, 115, 112, 101, 114, 46
}, *lws_jwe_ex_a2_jwk_json = (uint8_t *)
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

*ex_a2_compact = (uint8_t *)
	"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
	"."
	"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"
	"1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"
	"HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"
	"NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"
	"rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"
	"-B3oWh2TbqmScqXMR4gp_A"
	"."
	"AxY8DCtDaGlsbGljb3RoZQ"
	"."
	"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
	"."
	"9hH0vgRfYgPnAHOd8stkvw"
;

static int
test_jwe_a2(struct lws_context *context)
{
	struct lws_jwe jwe;
	char temp[2048];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, (char *)lws_jwe_ex_a2_jwk_json,
			   strlen((char *)lws_jwe_ex_a2_jwk_json)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode((const char *)ex_a2_compact,
				   strlen((char *)ex_a2_compact),
				   &jwe.jws.map, &jwe.jws.map_b64,
				   (char *)temp, &temp_len) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(ex_a2_ptext) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ex_a2_ptext,
			        sizeof(ex_a2_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ex_a2_ptext, sizeof(ex_a2_ptext));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

/* JWE creation using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
 *
 * This example encrypts a different, larger plaintext using the jwk key from
 * the test above, and AES_128_CBC_HMAC_SHA_256 for content encryption.
 */

static const char *rsa256a128_jose =
		"{ \"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\"}";

static uint8_t

	/* plaintext is 1024 bytes from /dev/urandom */

ra_ptext_1024[] = {
		0xfe, 0xc6, 0x4f, 0x3e, 0x4a, 0x19, 0xe9, 0xd7,
		0xc2, 0x13, 0xe7, 0xc5, 0x78, 0x6e, 0x71, 0xf6,
		0x6e, 0xdd, 0x04, 0xaf, 0xaa, 0x4e, 0xa8, 0xad,
		0xd8, 0xe0, 0xb3, 0x32, 0x97, 0x43, 0x7c, 0xd8,
		0xd1, 0x5f, 0x56, 0xac, 0x70, 0xaf, 0x7d, 0x0b,
		0x40, 0xa1, 0x96, 0x71, 0x7c, 0xc4, 0x4a, 0x37,
		0x0b, 0xa6, 0x06, 0xb3, 0x8c, 0x87, 0xee, 0xb6,
		0x15, 0xfe, 0xaa, 0x60, 0x7e, 0x7f, 0xdc, 0xb0,
		0xff, 0x96, 0x4b, 0x30, 0x60, 0xcf, 0xc6, 0x5d,
		0x09, 0x6a, 0x6f, 0x66, 0x0c, 0x5f, 0xb0, 0x6f,
		0x61, 0xa6, 0x26, 0x02, 0xbd, 0x46, 0xda, 0xa3,
		0x73, 0x19, 0x17, 0xff, 0xe0, 0x5f, 0x30, 0x72,
		0x7d, 0x17, 0xd8, 0xb2, 0xbe, 0x84, 0x3e, 0x4d,
		0x76, 0xbd, 0x62, 0x5d, 0x63, 0xfe, 0x11, 0x32,
		0x11, 0x41, 0xdc, 0xed, 0x96, 0xfd, 0x31, 0x38,
		0x6a, 0x84, 0x55, 0x7a, 0x33, 0x3f, 0x37, 0xc3,
		0x37, 0x7b, 0xc1, 0xb7, 0x89, 0x00, 0x39, 0xa6,
		0x94, 0x91, 0xb7, 0x19, 0x6b, 0x1d, 0x99, 0xeb,
		0xf6, 0x10, 0xb9, 0xd2, 0xcd, 0x15, 0x0d, 0xbc,
		0x24, 0x34, 0x9a, 0x52, 0x64, 0x21, 0x72, 0x1e,
		0x9a, 0x00, 0xf2, 0xcf, 0xf1, 0x7d, 0x1a, 0x12,
		0x8d, 0x39, 0xbc, 0xf9, 0x09, 0xfd, 0xd9, 0x22,
		0x27, 0x28, 0xe1, 0x3a, 0x0b, 0x82, 0xba, 0x9a,
		0xe5, 0x9d, 0xa8, 0x12, 0x6e, 0xf5, 0x4b, 0xc7,
		0x2b, 0x9c, 0xdc, 0xfe, 0xf3, 0xe8, 0x74, 0x65,
		0x3d, 0xe0, 0xaa, 0x64, 0xf3, 0x43, 0xa4, 0x88,
		0xa8, 0xbe, 0x60, 0xdb, 0xfd, 0x2d, 0x3b, 0x84,
		0x82, 0x8f, 0x4d, 0xbb, 0xe4, 0xa9, 0x59, 0xe3,
		0x6c, 0x52, 0x45, 0xe4, 0x34, 0xdb, 0x28, 0x0e,
		0x4a, 0x44, 0xb6, 0x9a, 0x25, 0x9b, 0x3b, 0xae,
		0xe1, 0x12, 0x1d, 0x1c, 0x66, 0x7d, 0xb9, 0x5b,
		0x5f, 0xc2, 0x4a, 0xaa, 0xd2, 0xe9, 0x65, 0xe2,
		0x85, 0x6f, 0xf6, 0x67, 0x66, 0x8e, 0x0b, 0xd2,
		0x60, 0xf8, 0x43, 0x60, 0x04, 0x9b, 0xa9, 0x3a,
		0x6a, 0x3c, 0x02, 0x3c, 0x08, 0x9d, 0x60, 0x1c,
		0xc4, 0x27, 0x3e, 0xff, 0xd0, 0x70, 0x94, 0x43,
		0x3e, 0x9e, 0x69, 0x19, 0x22, 0xf0, 0xec, 0x26,
		0x2d, 0xa5, 0x71, 0xf3, 0x92, 0x61, 0x95, 0xce,
		0xc3, 0xc0, 0xa0, 0xc3, 0x98, 0x22, 0xdd, 0x32,
		0x3c, 0x48, 0xcb, 0xd1, 0x61, 0xa0, 0xaa, 0x9a,
		0x7e, 0x5a, 0xfa, 0x26, 0x46, 0x49, 0xfc, 0x9c,
		0xaa, 0x21, 0x06, 0x45, 0xf1, 0xa0, 0xc9, 0xef,
		0x6b, 0x89, 0xf2, 0x01, 0x20, 0x54, 0xfa, 0x0a,
		0x23, 0xff, 0xbd, 0x64, 0x35, 0x94, 0xfd, 0x35,
		0x70, 0x52, 0x94, 0x66, 0xc5, 0xd0, 0x27, 0xc1,
		0x8f, 0x6d, 0xc4, 0xa3, 0x34, 0xc2, 0xea, 0xf0,
		0xb3, 0x0d, 0x6c, 0x13, 0xb5, 0xc9, 0x6e, 0x5c,
		0xeb, 0x8b, 0x7b, 0xf5, 0x21, 0x4c, 0xe3, 0xb7,
		0x73, 0x6d, 0x07, 0xaa, 0x44, 0xc4, 0xba, 0xc5,
		0xa5, 0x0e, 0x75, 0x28, 0xb7, 0x50, 0x22, 0x54,
		0xa7, 0xe1, 0x2e, 0xfd, 0x20, 0xcd, 0xa4, 0x31,
		0xa3, 0xb2, 0x73, 0x98, 0x7c, 0x3c, 0x8f, 0xa3,
		0x40, 0x8a, 0xaf, 0x31, 0xfa, 0xf9, 0x70, 0x4d,
		0x83, 0x10, 0xc4, 0xa0, 0x9c, 0xd6, 0xa3, 0xd5,
		0x07, 0xaf, 0xaf, 0x35, 0x15, 0xd0, 0x84, 0x09,
		0x20, 0x36, 0x88, 0xac, 0x6f, 0x16, 0x5e, 0x03,
		0xa9, 0xfc, 0xb3, 0x2d, 0x01, 0x57, 0xb3, 0xed,
		0x4b, 0x55, 0x2b, 0xbc, 0x92, 0x87, 0x3e, 0x27,
		0xc4, 0x2c, 0x44, 0xac, 0x05, 0x5f, 0x26, 0xe7,
		0xe9, 0xb0, 0x2d, 0x6b, 0x3c, 0x8c, 0xd2, 0xb4,
		0x3c, 0xb4, 0x86, 0xfe, 0x68, 0x99, 0x2a, 0x42,
		0xac, 0xa4, 0xb3, 0x89, 0x61, 0xb3, 0xd1, 0xdf,
		0x9b, 0x58, 0xc7, 0x81, 0x62, 0x87, 0x26, 0x52,
		0x51, 0xe7, 0x7d, 0x7c, 0x37, 0x14, 0xe5, 0x19,
		0x28, 0x34, 0x3e, 0x95, 0x17, 0x36, 0x12, 0xf9,
		0x5e, 0xc1, 0x3c, 0x9c, 0x28, 0x70, 0x06, 0xdf,
		0xc4, 0x6d, 0x25, 0x04, 0x46, 0xe0, 0x95, 0xf0,
		0xc8, 0x57, 0x48, 0x27, 0x26, 0xf3, 0xf7, 0x19,
		0xbe, 0xea, 0xb4, 0xd4, 0x64, 0xaf, 0x67, 0x7c,
		0xf5, 0xa9, 0xfb, 0x85, 0x4a, 0x43, 0x9c, 0x62,
		0x06, 0x5e, 0x28, 0x2a, 0x7b, 0x1e, 0xb3, 0x07,
		0xe7, 0x19, 0x32, 0xa4, 0x4e, 0xb4, 0xce, 0xe0,
		0x92, 0x56, 0xf5, 0x10, 0xcb, 0x56, 0x34, 0x4b,
		0x0d, 0xe1, 0xd3, 0x6d, 0xfe, 0xf0, 0x44, 0xf7,
		0x22, 0x1d, 0x5e, 0x6b, 0xa7, 0xa5, 0x83, 0x2e,
		0xeb, 0x14, 0xf2, 0xd7, 0x27, 0x5a, 0x2a, 0xd2,
		0x55, 0x35, 0xe6, 0x7e, 0xd9, 0x3b, 0xac, 0x4e,
		0x5a, 0x22, 0x46, 0xd5, 0x7b, 0x57, 0x9c, 0x58,
		0xfe, 0xd0, 0xda, 0xbf, 0x7d, 0xe9, 0x8c, 0xb7,
		0xba, 0x88, 0xf1, 0xc3, 0x82, 0x53, 0xc3, 0x66,
		0x20, 0x51, 0x12, 0xd3, 0xf9, 0xaf, 0xe9, 0xcb,
		0xc1, 0x7a, 0xe6, 0x22, 0x44, 0xa5, 0xdf, 0x18,
		0xb3, 0x6e, 0x6c, 0xba, 0xf3, 0xc6, 0x24, 0x5a,
		0x1c, 0x67, 0xa6, 0xa5, 0xb4, 0xb1, 0x35, 0xdf,
		0x5a, 0x60, 0x5c, 0x0b, 0x66, 0xd3, 0x1f, 0x4e,
		0x7c, 0xcb, 0x93, 0x7e, 0x2f, 0x6d, 0xbd, 0xce,
		0x26, 0x52, 0x44, 0xee, 0xbb, 0xd8, 0x8f, 0xf2,
		0x67, 0x38, 0x0d, 0x3b, 0xaa, 0x21, 0x73, 0xf8,
		0x3b, 0x54, 0x9d, 0x4e, 0x5e, 0xf1, 0xa2, 0x18,
		0x5a, 0xf1, 0x6c, 0x32, 0xbf, 0x0a, 0x73, 0x14,
		0x48, 0x4f, 0x56, 0xc0, 0x87, 0x6d, 0x3b, 0x16,
		0xcc, 0x3f, 0x44, 0x19, 0x85, 0x22, 0x43, 0x5f,
		0x8c, 0x29, 0xbd, 0xa0, 0xce, 0x84, 0xd9, 0x4a,
		0xcf, 0x00, 0x6b, 0x37, 0x35, 0xe0, 0xb3, 0xc9,
		0xd1, 0x58, 0xd1, 0x1b, 0xc3, 0x6f, 0xe3, 0x50,
		0xdb, 0xa6, 0x5e, 0x03, 0x18, 0xe5, 0xe2, 0xc1,
		0x97, 0xd5, 0xf8, 0x42, 0x6f, 0xe6, 0x61, 0x80,
		0xc9, 0x7c, 0xc6, 0x83, 0xf0, 0xad, 0x70, 0x13,
		0x0e, 0x26, 0x75, 0xc0, 0x12, 0x23, 0x14, 0xef,
		0x1f, 0xdf, 0xfd, 0x47, 0x99, 0x9f, 0x22, 0xf3,
		0x57, 0x21, 0xdc, 0x38, 0xe4, 0x79, 0x87, 0x5b,
		0x67, 0x66, 0xdd, 0x0b, 0xe0, 0xae, 0xb5, 0x97,
		0xd8, 0xa6, 0x5d, 0x02, 0xcf, 0x6b, 0x84, 0x19,
		0xc1, 0xbb, 0x25, 0xd2, 0x10, 0xb9, 0x63, 0xeb,
		0x4b, 0x27, 0x8d, 0x05, 0x31, 0xce, 0x3b, 0x0c,
		0x5f, 0xd4, 0x83, 0x47, 0xa4, 0x8b, 0xc4, 0x76,
		0x33, 0x74, 0x1a, 0x07, 0xf8, 0x18, 0x82, 0x1c,
		0x8e, 0x01, 0x75, 0x78, 0xea, 0xd9, 0x72, 0x61,
		0x71, 0xa9, 0x09, 0x44, 0x7b, 0x0f, 0x12, 0xcf,
		0x4c, 0x76, 0x7b, 0x69, 0xc8, 0x64, 0x98, 0x60,
		0x45, 0xb6, 0xc7, 0x6b, 0xd8, 0x43, 0x99, 0x08,
		0xc9, 0xd3, 0x6f, 0x01, 0x4f, 0x57, 0x6f, 0x49,
		0x4f, 0x4f, 0x72, 0xa4, 0xa2, 0x45, 0xe1, 0x0e,
		0xf2, 0x08, 0x3e, 0x67, 0xc3, 0x83, 0x5b, 0xb1,
		0x24, 0xc0, 0xe0, 0x3a, 0xf5, 0x1f, 0xf2, 0x06,
		0x4b, 0xa7, 0x6f, 0xd2, 0xb2, 0x81, 0x96, 0x91,
		0x42, 0xb1, 0x53, 0x65, 0x3a, 0x12, 0xcd, 0x33,
		0xb3, 0x7e, 0x79, 0xc0, 0x46, 0xf6, 0xd8, 0x4a,
		0x22, 0x35, 0xb8, 0x3f, 0xe4, 0x08, 0x88, 0x49,
		0x3c, 0x73, 0x9a, 0x44, 0xe3, 0x3b, 0xcc, 0xc4,
		0xae, 0x7c, 0xbe, 0xfd, 0xa6, 0x4a, 0xd4, 0x26,
		0x52, 0x58, 0x81, 0x30, 0x66, 0x44, 0x54, 0xc8,
		0xe4, 0x7c, 0x5b, 0x63, 0x06, 0x60, 0x94, 0x62,
		0xe5, 0x47, 0x45, 0xfb, 0x58, 0xf5, 0x6a, 0x7c,
		0xb2, 0x35, 0x08, 0x03, 0x15, 0x68, 0xb3, 0x13,
		0xa5, 0xbd, 0xf2, 0x1e, 0x2e, 0x1c, 0x8f, 0xc6,
		0xc7, 0xd1, 0xa9, 0x64, 0x37, 0x2b, 0x23, 0xfa,
		0x7e, 0x56, 0x22, 0xf0, 0x8a, 0xbd, 0xeb, 0x04
},

r256a128_cek[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
}
;

static int
test_jwe_ra_ptext_1024(struct lws_context *context, char *jwk_txt, int jwk_len)
{
	char temp[4096], compact[4096];
	struct lws_jwe jwe;
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	/* reuse the rsa private key from the JWE Appendix 2 test above */

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, jwk_txt, jwk_len) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* dup the plaintext, it will be replaced in-situ by the ciphertext */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_CTXT,
				lws_concat_temp(temp, temp_len), &temp_len,
				ra_ptext_1024, sizeof(ra_ptext_1024), 0)) {
		lwsl_notice("%s: Not enough temp space for ptext\n", __func__);
		goto bail;
	}

	/* dup the cek, since it will be replaced by the encrypted key */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_EKEY,
				lws_concat_temp(temp, temp_len), &temp_len,
				r256a128_cek, sizeof(r256a128_cek),
				LWS_JWE_LIMIT_KEY_ELEMENT_BYTES)) {
		lwsl_notice("%s: Not enough temp space for EKEY\n", __func__);
		goto bail;
	}

	jwe.jws.map.buf[LJWE_JOSE] = rsa256a128_jose;
	jwe.jws.map.len[LJWE_JOSE] = strlen(rsa256a128_jose);

	n = lws_jwe_parse_jose(&jwe.jose, jwe.jws.map.buf[LJWE_JOSE],
			       jwe.jws.map.len[LJWE_JOSE],
			       lws_concat_temp(temp, temp_len), &temp_len);
	if (n < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	n = lws_jwe_encrypt(&jwe, lws_concat_temp(temp, temp_len),
			    &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_render_compact(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n", __func__, n);
		goto bail;
	}

	// puts(compact);

	lws_jwe_destroy(&jwe);
	lws_jwe_init(&jwe, context);
	temp_len = sizeof(temp);

	/* now we created the encrypted version, see if we can decrypt it */

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, jwk_txt, jwk_len) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	if (lws_jws_compact_decode(compact, n, &jwe.jws.map, &jwe.jws.map_b64,
				   temp, &temp_len) != 5) {
		lwsl_err("%s: failed to parse generated compact\n", __func__);

		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(ra_ptext_1024) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ra_ptext_1024,
			        sizeof(ra_ptext_1024))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ra_ptext_1024, sizeof(ra_ptext_1024));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);

	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

static const char *rsa256a192_jose =
		"{ \"alg\":\"RSA1_5\",\"enc\":\"A192CBC-HS384\"}";

static const uint8_t r256a192_cek[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
}
;

static int
test_jwe_r256a192_ptext(struct lws_context *context, char *jwk_txt, int jwk_len)
{
	struct lws_jwe jwe;
	char temp[4096], compact[4096];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	/* reuse the rsa private key from the JWE Appendix 2 test above */

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, jwk_txt, jwk_len) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/*
	 * dup the plaintext into the ciphertext element, it will be
	 * encrypted in-place to a ciphertext of the same length
	 */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_CTXT,
				lws_concat_temp(temp, temp_len), &temp_len,
				ra_ptext_1024, sizeof(ra_ptext_1024), 0)) {
		lwsl_notice("%s: Not enough temp space for ptext\n", __func__);
		goto bail;
	}

	/* copy the cek, since it will be replaced by the encrypted key */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_EKEY,
				lws_concat_temp(temp, temp_len), &temp_len,
				r256a192_cek, sizeof(r256a192_cek),
				LWS_JWE_LIMIT_KEY_ELEMENT_BYTES)) {
		lwsl_err("Problem getting random\n");
		goto bail;
	}

	jwe.jws.map.buf[LJWE_JOSE] = rsa256a192_jose;
	jwe.jws.map.len[LJWE_JOSE] = strlen(rsa256a192_jose);

	n = lws_jwe_parse_jose(&jwe.jose, jwe.jws.map.buf[LJWE_JOSE],
			       jwe.jws.map.len[LJWE_JOSE],
			       lws_concat_temp(temp, temp_len), &temp_len);
	if (n < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	n = lws_jwe_encrypt(&jwe, lws_concat_temp(temp, temp_len),
			    &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_render_compact(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n", __func__, n);
		goto bail;
	}

	// puts(compact);

	/* now we created the encrypted version, see if we can decrypt it */

	lws_jwe_destroy(&jwe);
	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, jwk_txt, jwk_len) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	if (lws_jws_compact_decode(compact, n, &jwe.jws.map, &jwe.jws.map_b64,
				   temp, &temp_len) != 5) {
		lwsl_err("%s: failed to parse generated compact\n", __func__);

		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(ra_ptext_1024) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ra_ptext_1024,
			        sizeof(ra_ptext_1024))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ra_ptext_1024, sizeof(ra_ptext_1024));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);

	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}


static const char *rsa256a256_jose =
		"{ \"alg\":\"RSA1_5\",\"enc\":\"A256CBC-HS512\"}";

static const uint8_t r256a256_cek[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
}
;

static int
test_jwe_r256a256_ptext(struct lws_context *context, char *jwk_txt, int jwk_len)
{
	struct lws_jwe jwe;
	char temp[4096], compact[4096];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	/* reuse the rsa private key from the JWE Appendix 2 test above */

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, jwk_txt, jwk_len) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/*
	 * dup the plaintext into the ciphertext element, it will be
	 * encrypted in-place to a ciphertext of the same length
	 */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_CTXT,
				lws_concat_temp(temp, temp_len), &temp_len,
				ra_ptext_1024, sizeof(ra_ptext_1024), 0)) {
		lwsl_notice("%s: Not enough temp space for ptext\n", __func__);
		goto bail;
	}

	/* copy the cek, since it will be replaced by the encrypted key */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_EKEY,
				lws_concat_temp(temp, temp_len), &temp_len,
				r256a256_cek, sizeof(r256a256_cek),
				LWS_JWE_LIMIT_KEY_ELEMENT_BYTES)) {
		lwsl_err("Problem getting random\n");
		goto bail;
	}

	jwe.jws.map.buf[LJWE_JOSE] = rsa256a256_jose;
	jwe.jws.map.len[LJWE_JOSE] = strlen(rsa256a256_jose);

	n = lws_jwe_parse_jose(&jwe.jose, rsa256a256_jose, strlen(rsa256a256_jose),
			       lws_concat_temp(temp, temp_len), &temp_len);
	if (n < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	n = lws_jwe_encrypt(&jwe, lws_concat_temp(temp, temp_len),
			    &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_render_compact(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n", __func__, n);
		goto bail;
	}

	// puts(compact);

	/* now we created the encrypted version, see if we can decrypt it */

	lws_jwe_destroy(&jwe);
	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, jwk_txt, jwk_len) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	if (lws_jws_compact_decode(compact, n, &jwe.jws.map, &jwe.jws.map_b64,
				   temp, &temp_len) != 5) {
		lwsl_err("%s: failed to parse generated compact\n", __func__);

		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(ra_ptext_1024) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ra_ptext_1024,
			        sizeof(ra_ptext_1024))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ra_ptext_1024, sizeof(ra_ptext_1024));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);

	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

/* produced by running the minimal example `lws-crypto-jwk -t RSA -b 2048 -c` */

static const char *rsa_key_2048 =
	"{"
		"\"e\":\"AQAB\","
		"\"kty\":\"RSA\","
		"\"n\":\"lBJdvUq-9_8hlcduIWuBjRb0tGzzAvS4foqoNCO7g-rOXMdeAcmq"
		 "aSzWTbkaGIc3L1I4-Q3TOZtxn2UhuDlShZRIhM6JCQuUVNVAF3TD7oXxHtZ"
		 "LJ7y_BqCUlrAmW31lu-nVmhY2G3xW26yXWUsDbCxz0hfLbVnXRSvVKLzYWm"
		 "_yyrFyEWfxB8peDocvKGh879z_aPCKE3PDOEl2AsgzYfpnWCLytkgnrTeL6"
		 "qY8HXxvvV-Jw-XMaRiwH0VldpIjs4DaoN35Kj1Ex7QOZznTkbYtMIqse8bR"
		 "LoR8Irkxbc5ncUAuX1KSV6lpPtelsA3RtEjJ4NHV-5eEABiYh8_CFQ\","
		"\"d\":\"DDpguQ9RVQFMoJC5z2hlkvq91kvsXPv2Y9Dcki256xYlg55H7Pre"
		 "p__hahrABR2Jg6QVJhArt5ABjUnDQ_JL69HH6VvLD6RVVBTQ-FRBZ_3HYKY"
		 "Oynx5BA7tJm1BRatF5FkBCvq27i8nAc4vfjAb22o9CFvEW3FLaKAgOCncQ3"
		 "Tnbz9CddH89n7DXw4kBFI8q5ugF_aRIg5-i42W_hQinLaBhZ_zhAuE-nvlt"
		 "ZnhDal8cX3T60lNoUrDOlirqEOXKO3gXCHpm3csZ6nabHYD1UCyHOmi2RsR"
		 "pzjaiqjXdPbwPzQoh2DcYpavNrf1mtHiqTwLZDTJIRHWHufJzHf-sw\","
		"\"p\":\"ySeC3FtvzduDEL-FX4JqbRN06PdBhUmosCkymmbBjriuLNpkGkG-"
		 "1ex7r-M8neUBZbctmDdih6cpLZ8hjZv3eEDZ4b5Z2LqZnja4QvVoWLUs4Fb"
		 "NN_PxJCR5H28uUfT6ThxqT0Nb2enb8Dyp0Qxvd7eJUeYz6jOt7pEK-ErTB4"
		 "M\","
		"\"q\":\"vHG2Pd6QUH7vFZjJtXwmlVnrz5tdJvUPQvz7ggeM69cqhf4vLajz"
		 "sqP9GhJr7bEkp6vKVdZGmfEdiFRD8cssIZq651oAO5Wr7zZd2mR_hG9jZx7"
		 "8Davfuxr4SZNN-bmoxO6dbDi-X2c7fvMI2YeJwL4groNKyiosdUYILTrYRI"
		 "c\","
		"\"dp\":\"h5Gqf2rcokgEQGBjuigCJDtNuskRjoxDNV6-rRL99nt_X9lcR9n"
		 "xjOnRvowOyXeTBoN7JjCFpllBxm6ORYtNMO28KomIsimo6NmGPBJ7XfXVJe"
		 "k6bDBrX-l4_HeJJ1FM9SHvgDYsjGQxh-rKpIqWAYBf-yOD758e5T85vndnX"
		 "JM\","
		"\"dq\":\"K9LiB-dfdmjenw4mMp-JtYfw8Bn4gtvQzcpZjzbETgB-8iRXwm2"
		 "dJvk-HjcUhHWCyb-I0YeAacKKFK9MEconHDWIq87haPn4vyvMjcJ7aUgiPN"
		 "QW1_MVl8TA4xNvudi0Z__5-jYEB9nRG0fX0gbUQU-19_-uf-9o4WkE88fQj"
		 "bc\","
		"\"qi\":\"LEkTRqmomn9UiASeRfAKw-Z5q7cye9CSL4luSexFvA3Du7Oin-s"
		 "L9a7F3nJN4CuYzhtNMxQ0hM7k6ExzhDhXDlNRHxnNEDt81-CFRV98v7GVWV"
		 "SH1KnaKf9wgegxSSm-x536ki2SI8EN4k4qkqRF0iLVHZK7CgnWMbtt6tnpp"
		 "3k\""
	"}";
/* produced by running the minimal example `lws-crypto-jwk -t RSA -b 4096 -c` */

static const char *rsa_key_4096 =
	"{"
		"\"e\":\"AQAB\","
		"\"kty\":\"RSA\","
		"\"n\":\"uiLBz1SUgd4eQ0okg6tlPdk9QUhTsqXmiJXygWVFgzT45E5_Rfkq"
		 "vZ2fwAqQ8DvxkDTUWiKpeXMpPRNWG5GxuBuq9n7xdA1vn1eQi8LoekB28dg"
		 "3MwMfozVSKCzyxG1f81xPE5x3EMVhCcx6hshhlMEHkzNNhE07d-oRO87ZC0"
		 "z_5L3Vh03uJBXaDKVlsgHAazoHLhn6G4odqv-ro54T6Nx1eEtyTnMmFY5ND"
		 "V4rN0SjQvSefbZZtsrtby8Z0JmeyvynmDwOINj7FpmPmpFLoWGXntc2yxPP"
		 "8SHnqfT9ESh94fxCMxRhDNohgpegRHyiYwj3M5ZYY6reCZYfOQONSWmc8yp"
		 "NBMJqj4LuJ2bTMGAFS17ZP4ZZWm5RP9ax100Dgk0yxP1UrybG5dCfJRQvHC"
		 "ncxG_aL6cSQu2o4fXqlJsNHxk3FjHtV_CMZ3tqvGTvwrs4yxvKwKv6r3fRh"
		 "KL01bGOePzp9THkHW2-lzVj6kUwnxBdHGZE6fcAnczOdp8ZIEdV1w6ThimC"
		 "m3Bw_TIyl3tkuxRWXpc_d6Q4iiSVKGKCvUvfAlESpTA4tIhQkij-T9FEoj2"
		 "WE2H1D35AKmjcfLCh6yszu8cmDNedn862pwnawE2RvRFAyuI113fLQeCbCz"
		 "tQ1JHuD8cnQt0hpGzReTa5UJ8OEOGIlyXNdWZyTpk\","
		"\"d\":\"G2ZW582AT-6xvz-IiP5fuJ9EMloygeuEeEo0aMJO3X3cfoUknJkN"
		 "ZtyvYa5cgBSe3la8hKkyD9_5K9WvGP9VLTAbdk4g_m-k5QyXiU9PeAGJ0Nd"
		 "-Zqq4y0Zj2eil8u7Tz0fhFxay-zvG6VGZnsIcBTD2C7_jUwyoaqJA17A_CH"
		 "gU-ifMqS56VgMGdlKZmf7Cg7ZGzM1DoS6vZ9bbfgoczaw4OZVHlg9Cxa0NI"
		 "CDi1S-sJcTLGN_RLISKN5H0J54ZfzF6fUEn5kNykLTZrAvj2XV7g4UUOogn"
		 "1cvjJYRcBVzTzQKcfxbqo2DvymDGFZbQM6pj80rYJ5HFPh2EapjggPN8hXp"
		 "NlTNDEvC84QFv0lo2E-0nVWQqcyHtXd431O1JH2h5X822zKjXxkaztQSCj9"
		 "YP7AdAeoxIaWOa3aO1vcwURH2WWaNV-_KXVkPJNzfo9-bGYwblMw_RIqIkN"
		 "BDayTb8rBuQHTCE_tSEHgoSnkityGpr8j_vgA-Fa-SqmdqUlbklVpwA_Mq_"
		 "UH7RCaqe91dWxRhS_7c85tFMRFCKOcaRXkwxEpP2LD1AYe8yvVQlr0Se8_d"
		 "RefuQcC-BECwMW-TCgR3VxAuL7ExNTYe4bhBD8WYXsHP7wDXWX2Q4v7IRzj"
		 "cfVIdpTNYuWEd69PvXBCuy75hmDniSmS3Xps3ItGU\","
		"\"p\":\"961BtLSIZkHO7Vu1KfaA3urcwGpISKJiTSB5Nh6npxJr9mSjzv_f"
		 "e8VoxCX6CWGY0SEeQNUQ6ceTnAAxkSHtZJQGed598jBtxIexAWEE7oc9s9d"
		 "b0cWu4QWIVZYXrcOTEWmK1kWN4PXmnnQknrWQF49adn81BaOXqoL-tahe7f"
		 "faXzXe0RXuohK543ZKbuuHQ2TxqFG7CZpXiH_qn1Syao32u0V3iDFpmmCUV"
		 "h9O2JCzfo8sAosTrnQwC0pXz3Nvr_9Cnk6bMluJoMrwB1Ywg_DPQ1WvpYHO"
		 "URezEOqVC8Y3zrko199TMX2COKGNFgutVpnzxs2_h0PyINUmwrY4zQ\","
		"\"q\":\"wGQRaxy_gBafbrVJy4f32O0a2FQHzmS--WgHhoteDoF6ZAajLcV0"
		 "GEvb-AVmFER1Wii62BFaFJOYQIegELvnBFFzD6oHJRX7bM4m36G8J_TC1o9"
		 "T1IFnxOpaoFDf4JWf2k7DCXClGg_zueyOD8fj8F6j2nqpOfytuLmikHcWMc"
		 "dGTHTCRtQmvOk3pm0uk2qR0cQb5L3Ocv45tCKr55tMc6Zx3DKkMt1kmUwd2"
		 "HFfk_0WM6R7q4LNGIjwl8dwiERppLKA8xao9i3jOOdFEfAD-Zqv8H-32cyH"
		 "Mg6Guo4tPNAYSzcsz8nbEYPtKVVm-PDuM2cx0iaKnS8BIK2XTbzc_Q\","
		"\"dp\":\"ZXLWIwp_hEMYWyjhP9r0VlqlKTtfeEDrOuQ-Qei0iz6EclwurK8"
		 "p_yyRCSb1D7qmOaLzHWMollllINUDeIsJDdWEAY8cz4L-sy1RV1tCBeHnaC"
		 "6iMX5jb1Aw072y3T3qk4tDjxjWUHroh6bTCR8dckkJqNfaBAFKMlGNuyLIH"
		 "3kSPUV3ivUM1d4NvhnJyz02HmjOgz9W-Uv65rJei_zJR9P2aCbAG00CEHXW"
		 "zJ_uT86VdxV11WTaHu8Abt94sER8Tv6jbuyLrUjJSs9VGew32xNcEhya4ZQ"
		 "VyimG8zri6fu7CDXXgPS8wtzB5ihl_c2ypnJQ4_GKrgEqwEAOrFqvUQ\","
		"\"dq\":\"uzlmngcm8R6S3qi7fL7_2fG7uyPjSN5P3uR21l8QFCu6kFbJO8S"
		 "4muBP20hds4F_dlLGqXgRYo7TjpCtmztQsKoWv_ql41hGCfeAawa41WViqm"
		 "xmlxmrgzzRHsw1YhgZrNgTAz_E290EQT3Mbd0HnCZtbDMMNisIYAj_A3lwd"
		 "tbHOaYyXb0dSZ_nkSUVO05tQ2aGAo8Xtl5ih0NqaQR_XNhwW2pI0lsTB__D"
		 "15tU-O5FSdJaq2ip8KNrBzmF8IYrDKTNykKWAKRdSEX_uFoLdD8t0mxn3SM"
		 "luffa8vdjXJfh3GiASmHUt3HcPOooQEAufoWBPVJWeGqCvWtRH8yYfQ\","
		"\"qi\":\"h-e9es5J49OUF48gSXUI8cynZ8ydv5cThXc1deV3mil_7_7Hg8E"
		 "jV3gAErO4l-irHJplFmHFZvU1ud4zs1gtBt5TA-EeeepYOHMSssWDvDK3WI"
		 "zsM6C3vcNTSkT-ihaSFmPWHCVwJ1R3auWfeI2In3at0jd4t-OK-cCcGZXb7"
		 "90-EnyyDcdFTU9WfwVSOJffRGjoUYX8DexavClv7CBzPhpdUzGoeyarNaG4"
		 "z9MI8Q8txHyHgc_D70lZUum1cj0bZwgEj6yDzOPzSgUmICFJiLDDj93oPaI"
		 "v-5CQ_Ckju7icexc_kuuYTKBOLTj_vfaURnV3KCHul2UljUYOxkfeNQ\""
	"}";

static const char *rsa_key_4096_no_optional =
	"{"
		"\"e\":\"AQAB\","
		"\"kty\":\"RSA\","
		"\"n\":\"uiLBz1SUgd4eQ0okg6tlPdk9QUhTsqXmiJXygWVFgzT45E5_Rfkq"
		 "vZ2fwAqQ8DvxkDTUWiKpeXMpPRNWG5GxuBuq9n7xdA1vn1eQi8LoekB28dg"
		 "3MwMfozVSKCzyxG1f81xPE5x3EMVhCcx6hshhlMEHkzNNhE07d-oRO87ZC0"
		 "z_5L3Vh03uJBXaDKVlsgHAazoHLhn6G4odqv-ro54T6Nx1eEtyTnMmFY5ND"
		 "V4rN0SjQvSefbZZtsrtby8Z0JmeyvynmDwOINj7FpmPmpFLoWGXntc2yxPP"
		 "8SHnqfT9ESh94fxCMxRhDNohgpegRHyiYwj3M5ZYY6reCZYfOQONSWmc8yp"
		 "NBMJqj4LuJ2bTMGAFS17ZP4ZZWm5RP9ax100Dgk0yxP1UrybG5dCfJRQvHC"
		 "ncxG_aL6cSQu2o4fXqlJsNHxk3FjHtV_CMZ3tqvGTvwrs4yxvKwKv6r3fRh"
		 "KL01bGOePzp9THkHW2-lzVj6kUwnxBdHGZE6fcAnczOdp8ZIEdV1w6ThimC"
		 "m3Bw_TIyl3tkuxRWXpc_d6Q4iiSVKGKCvUvfAlESpTA4tIhQkij-T9FEoj2"
		 "WE2H1D35AKmjcfLCh6yszu8cmDNedn862pwnawE2RvRFAyuI113fLQeCbCz"
		 "tQ1JHuD8cnQt0hpGzReTa5UJ8OEOGIlyXNdWZyTpk\","
		"\"d\":\"G2ZW582AT-6xvz-IiP5fuJ9EMloygeuEeEo0aMJO3X3cfoUknJkN"
		 "ZtyvYa5cgBSe3la8hKkyD9_5K9WvGP9VLTAbdk4g_m-k5QyXiU9PeAGJ0Nd"
		 "-Zqq4y0Zj2eil8u7Tz0fhFxay-zvG6VGZnsIcBTD2C7_jUwyoaqJA17A_CH"
		 "gU-ifMqS56VgMGdlKZmf7Cg7ZGzM1DoS6vZ9bbfgoczaw4OZVHlg9Cxa0NI"
		 "CDi1S-sJcTLGN_RLISKN5H0J54ZfzF6fUEn5kNykLTZrAvj2XV7g4UUOogn"
		 "1cvjJYRcBVzTzQKcfxbqo2DvymDGFZbQM6pj80rYJ5HFPh2EapjggPN8hXp"
		 "NlTNDEvC84QFv0lo2E-0nVWQqcyHtXd431O1JH2h5X822zKjXxkaztQSCj9"
		 "YP7AdAeoxIaWOa3aO1vcwURH2WWaNV-_KXVkPJNzfo9-bGYwblMw_RIqIkN"
		 "BDayTb8rBuQHTCE_tSEHgoSnkityGpr8j_vgA-Fa-SqmdqUlbklVpwA_Mq_"
		 "UH7RCaqe91dWxRhS_7c85tFMRFCKOcaRXkwxEpP2LD1AYe8yvVQlr0Se8_d"
		 "RefuQcC-BECwMW-TCgR3VxAuL7ExNTYe4bhBD8WYXsHP7wDXWX2Q4v7IRzj"
		 "cfVIdpTNYuWEd69PvXBCuy75hmDniSmS3Xps3ItGU\","
		"\"p\":\"961BtLSIZkHO7Vu1KfaA3urcwGpISKJiTSB5Nh6npxJr9mSjzv_f"
		 "e8VoxCX6CWGY0SEeQNUQ6ceTnAAxkSHtZJQGed598jBtxIexAWEE7oc9s9d"
		 "b0cWu4QWIVZYXrcOTEWmK1kWN4PXmnnQknrWQF49adn81BaOXqoL-tahe7f"
		 "faXzXe0RXuohK543ZKbuuHQ2TxqFG7CZpXiH_qn1Syao32u0V3iDFpmmCUV"
		 "h9O2JCzfo8sAosTrnQwC0pXz3Nvr_9Cnk6bMluJoMrwB1Ywg_DPQ1WvpYHO"
		 "URezEOqVC8Y3zrko199TMX2COKGNFgutVpnzxs2_h0PyINUmwrY4zQ\","
		"\"q\":\"wGQRaxy_gBafbrVJy4f32O0a2FQHzmS--WgHhoteDoF6ZAajLcV0"
		 "GEvb-AVmFER1Wii62BFaFJOYQIegELvnBFFzD6oHJRX7bM4m36G8J_TC1o9"
		 "T1IFnxOpaoFDf4JWf2k7DCXClGg_zueyOD8fj8F6j2nqpOfytuLmikHcWMc"
		 "dGTHTCRtQmvOk3pm0uk2qR0cQb5L3Ocv45tCKr55tMc6Zx3DKkMt1kmUwd2"
		 "HFfk_0WM6R7q4LNGIjwl8dwiERppLKA8xao9i3jOOdFEfAD-Zqv8H-32cyH"
		 "Mg6Guo4tPNAYSzcsz8nbEYPtKVVm-PDuM2cx0iaKnS8BIK2XTbzc_Q\""
	"}";

/* This is a compact JWE containing the plaintext ra_ptext_1024 for the key
 * lws_jwe_ex_a2_jwk_json... produced by  test test above running on OpenSSL.
 */

static char *jwe_compact_rsa_cbc_openssl =
	"eyAiYWxnIjoiUlNBMV81IiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9"
	"."
	"mWXwMv4hxwgKbUAyMFAuHxiKjg62Z5owkFYLgxho5FNT3Hm5ZGiF8plS5W3NwUTmv8t6C"
	"I0kV5cOOJXE_PXPaOptsie2aoQR-_Bs6gAFixa7aZNsnsMF4lMAiIy7VkrvP2qh0s04y2"
	"2poOLfmS93tB9AyWdlnQ6Z-U1wzrM9kncqO9GpPol9M4WnAss1ZtTE-9Tbc7dMHURHbZb"
	"vHn2h625pBD8oD_s0osRav8YEw7jNeQjW_ch4pI6HRox-hf0dyLtk9yFCtBjxbCvysadW"
	"SlZPJBj0HYv0BVqCK0fETi7URx4MCJ3zgCJnpAuQo2yq1yQzXwOYcFoLIvY0jIm44A"
	"."
	"WINMABhU_GQKJarmmTP_-g"
	"."
	"V9kHAh9ajE558EPj_zX6p_C903MevMPJLcMU4MWhfhwe1cFW_0io-LvZfcF_Xj7aNoIZd"
	"vPXJ0On_jHPFsnwe4dus6kuh8RrSKFFV0sGIv-FFXrKB99FFRY_8BTPsYFrcqt_8EV2Af"
	"p7toaVOO15WXOEH6Ym81a3aOWCVGdj_akMN46Qx_JrQaql-Xs_fL2HdpaEWHHTV2ac9aY"
	"ah7o0Ojl9UnzkHyXieRgrjXymvCcT0te3D4OQJhrv7TzH_hfKu621O-Frmkr-NvQGSNcl"
	"fVgRkte2ks34j5HPqEbJQWWKG3IDfkPRvWmDZzEXW_JTrK_1r1FM-aYtY79tLnir8Zw7I"
	"WCczD-XmtlOJNYA2Ss5dbjoJDtevbqaZWVl-sDSwO1xdf-DUfiemep7S7IFoFAdl0vXLT"
	"YtuNBxuFw-cP2Kwi8RyF__uENo4vD003cI4htqSYIYXeyAVqWIkmsP1BFpT7MGixfvhAu"
	"VCj_ToJmowGY3bOHiMuzyT9M7wtCCiCySEBARVU-EdQBXj8X-quSj-0OnBtxXChUS4QXw"
	"q2pNn3UKSMsxqvHR25HQq_6U2AbvNHxKhup3luzn0T27uy0l3XeWSz_48SwJZKRnbYPtC"
	"n5Jd5mRdr5GxihpNwupaO4BWnHZo_fHUTI9-Z18lpj_4QB-c3dzDL15xFN4HEZ5lv2iO5"
	"zMiRI_NlVVDdA9lqGpn4IyO44osHQieBraUjWF8X5cSXDoqktXDVymAdrxe0fYZQca6Bq"
	"CsBqFTYae4CG01SpG46ysfwAXmsTEKPzj7uiOguFCRB4hClTd-Q8R2axj9JNT1jU_Vb7U"
	"GKFBGeDJt5PDXJyvW5rHyiQDewykf0Lpvdp39yITT8qARmJl2SwCrDCPADZ4TwwobT42B"
	"J_Cq5IKgEOeuS3S7NOdOfXxmAcNfN0yujKbmfiOxnXhwnepQ-TnpgTV0nv8snBRITN7mS"
	"EgflqQlKAZus_0mDbHmBmw1nY-0q4qMWI03IEwMC57-p4JLshnWgIAupnFCGp9nyi4E_s"
	"GVyQlGCxzC5VSH1Hba3rvbulQGxx_kGk0j56NGhGsQEzqvSuI4xgIsGMPo1Ii7xUh68dd"
	"BzJRzaov9oDTgnWM5-hoEQQoazW7hDKAFPYccC6zqX0fnI7vBIIBZsjUsol6-5bdujpb4"
	"l3LRGCjULXlSPbnNGzyk5R-mIwQC8aM9wcIiZZdcdHdr4meMNr3HmpG_B5xtBmENAJAvU"
	"K3DO6pro2xhypuNKYtOAdH0Xyl8QBPIJ0EFVH6_1V-H_gHs2MLMIqGfUmFCuRev60APcw"
	"Pbf-GZxLeXLutPq2DOl1HD0XLNtYL1dB1aw2j4L8OJREOC_N-KpIH3g"
	"."
	"n4QRlTzW2urRnNiJlwQkZw"
;


static int
test_jwe_r256a128_jwe_openssl(struct lws_context *context)
{
	struct lws_jwe jwe;
	char temp[2048];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, (char *)lws_jwe_ex_a2_jwk_json,
			   strlen((char *)lws_jwe_ex_a2_jwk_json)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode((const char *)jwe_compact_rsa_cbc_openssl,
				   strlen((char *)jwe_compact_rsa_cbc_openssl),
				   &jwe.jws.map, &jwe.jws.map_b64,
				   temp, &temp_len) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(ra_ptext_1024) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ra_ptext_1024,
			        sizeof(ra_ptext_1024))) {
		lwsl_err("%s: plaintext RSA/AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ra_ptext_1024, sizeof(ra_ptext_1024));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}


/* This is a compact JWE containing the plaintext ra_ptext_1024 for the key
 * lws_jwe_ex_a2_jwk_json... produced by  test test above running on mbedTLS.
 */

static char
*jwe_compact_rsa_cbc_mbedtls =
	"eyAiYWxnIjoiUlNBMV81IiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9.oBqKJ06UJs2oryPLWZKyI8743GC0geUt_xaKLMaPtApp__swG2w0IhNtmkIBKA9LeeGyiCWKpGGzOlQUR5YSxrT99PnincHXw_pkCprOvi4j3oxThJ2pFRx-CBc9ZgPJ3Kje1QifOueT3vQt_65iiyXmqyc5PDxzuV0L_KtrA_jEsm2m1JVBMOX--qzXjYyqx_dc87d43TXY_4kuTmAtqVpQe7ixKJlUViPVSzuASyeLEUTIaNlALuEWial1wP-ICF37OQzOcZRH3OVZObrcZi1aWkDOLxF4qO4I_GtpuAgZT732a7gnobR-T2oyBpimcqCVEk88Wa7cYyBXZvAOUA.fNLEFh1mjdlyc3WKw0I2Kg.e8X-11K9yXK0KkK-8ikplEWFViruqduaKPDOA7x6lKpBk8l3RFX1aqC4s0WVc1eN0qd-fB__EoO_AIG1xsfw1ie2IDWV0p18ZaRkQRN9Th5UU-W9C9XyPFQUxcl7ShKRE-yKJU-VdZDk6L2-07FH3s-voVKx0oqLIYqkkXp9a2jvnzrZ0Psujs4PSCHOZEgcS8PNdMmdsjDHLsb0NDMifOSlXk2Mp6V2SizXRIPJtOkVJGKwuBc7FbdO02GnzzVXldiLC7GI0zoRsnSJndF8yc3pMrMQhoVRktkBClAcIujD_OxJwHG-i3OJqUg1uVfci86RoQrnULoygvB7apX_WMxF7eXXJdXbG8sPLLCf0SW4sgvuSclOHL2UXzGi6Tp_l1XjxFQTzVEfUaj7i0gD2wM74Ru79RX8yO0m-5qOOwkySU1lEXqbLTuxjJXD9WLcTQQmF0Nm5myTUyNOl7xKpeDpnNt5A0L8o6SW6iJ3DwZEzhMxk3JWQOYtQP1J2sgwAKEDM6SkGzTy9QXpCEoraKp2UEzunux9S6-roYpzgEFT2RZrq3Hg_JyequTtrcNaoiEKd5szJvE6pUc25WEjDzgg79v_n40gQm688mO62kiVBThVmc88u2JVlNpzVQFUfKt-bu2Xxiqn5lRfEMK93EEPZRd8n12vBq5aJKvvEpPN1AC4HaMepf78Ob0GNTYGR-70zSS0ErecCeIgUJ1CttE2Nn0qEOfbQcO48SjeIltecl9DRzeLT3tPN3Z4BqbzSX8kKU5LStUX5YC-obM_0Ss7swXJM19I1O-QH8VbHZl-9TADR6BLzmrsJQ9_BL_uTB6uPdLhYfqWw6VUf0eMLaqvsY92vV5-JVQqyv7s70FNLT1-8P94k79ZGiLvNdDNZgGsmRQOwA2Vk6snHI0oUYGj7NeEK4O64ZfNRZJgPfWnxtQ-LIhSYCJvxFGL7ZMoA_ijKl9_v_bRqd03_7o8YQisw2luDYqLa87Dh9u9tacOoraGAzcEBIAh-BOcnIrQEt5KoSbly5xNAkfqj7QDvL0vPHArZ5E3Gb_k3VbKjsqCzvisNMEjm887Z-Dc6tW4Y2OceYf-rfUDvJ3EXZ66CWSQ7yKhPVcP1RRtNUFEqLoIAkA4aEAAS2ZPKVHIJQwyMzbbNFAuvY_7piNYprAI5lySFcA1cz_hKl6s9xmqbAkH2XGZZduw5Nv-aY_LMXujjhmblqE2Ocej91xTdgMe74Ftr1b3y9FvPPVSqNjpTSfujCi5L57LOpjT78do8eSrDz6coG0zeRUybjWeTszoiYbif_NlyAcMScO5OMZHNkre6L8u-AVeYSKTGsdpK7em_iLN8cGSEjZABNAr_A9Lfg.6Qb_Qf-ktX0DRHWUHAJxDQ"
;

static int
test_jwe_r256a128_jwe_mbedtls(struct lws_context *context)
{
	struct lws_jwe jwe;
	char temp[2048];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, (char *)lws_jwe_ex_a2_jwk_json,
			   strlen((char *)lws_jwe_ex_a2_jwk_json)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode((const char *)jwe_compact_rsa_cbc_mbedtls,
				   strlen((char *)jwe_compact_rsa_cbc_mbedtls),
				   &jwe.jws.map, &jwe.jws.map_b64,
				   temp, &temp_len) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(ra_ptext_1024) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ra_ptext_1024,
			        sizeof(ra_ptext_1024))) {
		lwsl_err("%s: plaintext RSA/AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ra_ptext_1024, sizeof(ra_ptext_1024));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);

	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}



/* A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
 *
 * This example encrypts the plaintext "Live long and prosper." to the
 * recipient using AES Key Wrap for key encryption and
 * AES_128_CBC_HMAC_SHA_256 for content encryption.
 */

/* "Live long and prosper." */
static uint8_t

ex_a3_ptext[] = {
	76, 105, 118, 101, 32, 108, 111, 110,
	103, 32, 97, 110, 100, 32,  112, 114,
	111, 115, 112, 101, 114, 46
},

*ex_a3_compact = (uint8_t *)
	"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
	"."
	"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
	"."
	"AxY8DCtDaGlsbGljb3RoZQ"
	"."
	"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
	"."
	"U0m_YmjN04DJvceFICbCVQ",

*ex_a3_key = (uint8_t *)
	"{\"kty\":\"oct\","
	   "\"k\":\"GawgguFyGrWKav7AX4VKUg\""
	"}"
;

static int
test_jwe_a3(struct lws_context *context)
{
	struct lws_jwe jwe;
	char temp[2048];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, (char *)ex_a3_key,
			   strlen((char *)ex_a3_key)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode((const char *)ex_a3_compact,
				   strlen((char *)ex_a3_compact),
				   &jwe.jws.map, &jwe.jws.map_b64, temp,
				   &temp_len)  != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(ex_a3_ptext) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], ex_a3_ptext,
			        sizeof(ex_a3_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(ex_a3_ptext, sizeof(ex_a3_ptext));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

/* JWA B.2.  Test Cases for AES_192_CBC_HMAC_SHA_384
 *
 * Unfortunately JWA just gives this test case as hex literals, not
 * inside a JWE.  So we have to prepare the inputs "by hand".
 */

static uint8_t

jwa_b2_ptext[] = {
	0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
	0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74,
	0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
	0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20,
	0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
	0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69,
	0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
	0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74,
	0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
	0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65,
	0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
	0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e,
	0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65
},

jwa_b2_rawkey[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
},

jwa_b2_iv[] = {
	0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd,
	0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04
},

jwa_b2_e[] = {
	0xea, 0x65, 0xda, 0x6b, 0x59, 0xe6, 0x1e, 0xdb,
	0x41, 0x9b, 0xe6, 0x2d, 0x19, 0x71, 0x2a, 0xe5,
	0xd3, 0x03, 0xee, 0xb5, 0x00, 0x52, 0xd0, 0xdf,
	0xd6, 0x69, 0x7f, 0x77, 0x22, 0x4c, 0x8e, 0xdb,
	0x00, 0x0d, 0x27, 0x9b, 0xdc, 0x14, 0xc1, 0x07,
	0x26, 0x54, 0xbd, 0x30, 0x94, 0x42, 0x30, 0xc6,
	0x57, 0xbe, 0xd4, 0xca, 0x0c, 0x9f, 0x4a, 0x84,
	0x66, 0xf2, 0x2b, 0x22, 0x6d, 0x17, 0x46, 0x21,
	0x4b, 0xf8, 0xcf, 0xc2, 0x40, 0x0a, 0xdd, 0x9f,
	0x51, 0x26, 0xe4, 0x79, 0x66, 0x3f, 0xc9, 0x0b,
	0x3b, 0xed, 0x78, 0x7a, 0x2f, 0x0f, 0xfc, 0xbf,
	0x39, 0x04, 0xbe, 0x2a, 0x64, 0x1d, 0x5c, 0x21,
	0x05, 0xbf, 0xe5, 0x91, 0xba, 0xe2, 0x3b, 0x1d,
	0x74, 0x49, 0xe5, 0x32, 0xee, 0xf6, 0x0a, 0x9a,
	0xc8, 0xbb, 0x6c, 0x6b, 0x01, 0xd3, 0x5d, 0x49,
	0x78, 0x7b, 0xcd, 0x57, 0xef, 0x48, 0x49, 0x27,
	0xf2, 0x80, 0xad, 0xc9, 0x1a, 0xc0, 0xc4, 0xe7,
	0x9c, 0x7b, 0x11, 0xef, 0xc6, 0x00, 0x54, 0xe3
},

jwa_b2_a[] = { /* "The second principle of Auguste Kerckhoffs" */
	0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f,
	0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20,
	0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
	0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66,
	0x66, 0x73
},

jwa_b2_tag[] = {
	0x84, 0x90, 0xac, 0x0e, 0x58, 0x94, 0x9b, 0xfe,
	0x51, 0x87, 0x5d, 0x73, 0x3f, 0x93, 0xac, 0x20,
	0x75, 0x16, 0x80, 0x39, 0xcc, 0xc7, 0x33, 0xd7

}
;

static int
test_jwa_b2(struct lws_context *context)
{
	struct lws_jwe jwe;
	int n, ret = -1;
	char buf[2048];

	lws_jwe_init(&jwe, context);

	/*
	 * normally all this is interpreted from the JWE blob.  But we don't
	 * have JWE test vectors for AES_256_CBC_HMAC_SHA_512, just a standalone
	 * one.  So we have to create it all by hand.
	 *
	 * See test_jwe_a3 above for a more normal usage pattern.
	 */

	lws_jwk_dup_oct(&jwe.jwk, jwa_b2_rawkey, sizeof(jwa_b2_rawkey));

	memcpy(buf, jwa_b2_e, sizeof(jwa_b2_e));

	jwe.jws.map.buf[LJWE_IV] = (char *)jwa_b2_iv;
	jwe.jws.map.len[LJWE_IV] = sizeof(jwa_b2_iv);

	jwe.jws.map.buf[LJWE_CTXT] = buf;
	jwe.jws.map.len[LJWE_CTXT] = sizeof(jwa_b2_e);

	jwe.jws.map.buf[LJWE_ATAG] = (char *)jwa_b2_tag;
	jwe.jws.map.len[LJWE_ATAG] = sizeof(jwa_b2_tag);

	/*
	 * Normally this comes from the JOSE header.  But this test vector
	 * doesn't have one... so...
	 */

	if (lws_gencrypto_jwe_alg_to_definition("A128KW", &jwe.jose.alg))
		goto bail;
	if (lws_gencrypto_jwe_enc_to_definition("A192CBC-HS384",
						&jwe.jose.enc_alg))
		goto bail;

	n = lws_jwe_auth_and_decrypt_cbc_hs(&jwe, jwa_b2_rawkey,
						    jwa_b2_a, sizeof(jwa_b2_a));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_a_cbc_hs_decrypt failed\n", __func__);

		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(jwa_b2_ptext) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT],jwa_b2_ptext,
			        sizeof(jwa_b2_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(jwa_b2_ptext, sizeof(jwa_b2_ptext));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}



/* JWA B.3.  Test Cases for AES_256_CBC_HMAC_SHA_512
 *
 * Unfortunately JWA just gives this test case as hex literals, not
 * inside a JWE.  So we have to prepare the inputs "by hand".
 */

static uint8_t

jwa_b3_ptext[] = {
	0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
	0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74,
	0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
	0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20,
	0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
	0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69,
	0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
	0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74,
	0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
	0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65,
	0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
	0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e,
	0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65
},


jwa_b3_rawkey[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
},

jwa_b3_iv[] = {
	0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd,
	0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04
},

jwa_b3_e[] = {
	0x4a, 0xff, 0xaa, 0xad, 0xb7, 0x8c, 0x31, 0xc5,
	0xda, 0x4b, 0x1b, 0x59, 0x0d, 0x10, 0xff, 0xbd,
	0x3d, 0xd8, 0xd5, 0xd3, 0x02, 0x42, 0x35, 0x26,
	0x91, 0x2d, 0xa0, 0x37, 0xec, 0xbc, 0xc7, 0xbd,
	0x82, 0x2c, 0x30, 0x1d, 0xd6, 0x7c, 0x37, 0x3b,
	0xcc, 0xb5, 0x84, 0xad, 0x3e, 0x92, 0x79, 0xc2,
	0xe6, 0xd1, 0x2a, 0x13, 0x74, 0xb7, 0x7f, 0x07,
	0x75, 0x53, 0xdf, 0x82, 0x94, 0x10, 0x44, 0x6b,
	0x36, 0xeb, 0xd9, 0x70, 0x66, 0x29, 0x6a, 0xe6,
	0x42, 0x7e, 0xa7, 0x5c, 0x2e, 0x08, 0x46, 0xa1,
	0x1a, 0x09, 0xcc, 0xf5, 0x37, 0x0d, 0xc8, 0x0b,
	0xfe, 0xcb, 0xad, 0x28, 0xc7, 0x3f, 0x09, 0xb3,
	0xa3, 0xb7, 0x5e, 0x66, 0x2a, 0x25, 0x94, 0x41,
	0x0a, 0xe4, 0x96, 0xb2, 0xe2, 0xe6, 0x60, 0x9e,
	0x31, 0xe6, 0xe0, 0x2c, 0xc8, 0x37, 0xf0, 0x53,
	0xd2, 0x1f, 0x37, 0xff, 0x4f, 0x51, 0x95, 0x0b,
	0xbe, 0x26, 0x38, 0xd0, 0x9d, 0xd7, 0xa4, 0x93,
	0x09, 0x30, 0x80, 0x6d, 0x07, 0x03, 0xb1, 0xf6,
},

jwa_b3_a[] = { /* "The second principle of Auguste Kerckhoffs" */
	0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f,
	0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20,
	0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
	0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66,
	0x66, 0x73
},

jws_b3_tag[] = {
	0x4d, 0xd3, 0xb4, 0xc0, 0x88, 0xa7, 0xf4, 0x5c,
	0x21, 0x68, 0x39, 0x64, 0x5b, 0x20, 0x12, 0xbf,
	0x2e, 0x62, 0x69, 0xa8, 0xc5, 0x6a, 0x81, 0x6d,
	0xbc, 0x1b, 0x26, 0x77, 0x61, 0x95, 0x5b, 0xc5
}
;

static int
test_jwa_b3(struct lws_context *context)
{
	struct lws_jwe jwe;
	char buf[2048];
	int n, ret = -1;

	lws_jwe_init(&jwe, context);

	/*
	 * normally all this is interpreted from the JWE blob.  But we don't
	 * have JWE test vectors for AES_256_CBC_HMAC_SHA_512, just a standalone
	 * one.  So we have to create it all by hand.
	 *
	 * See test_jwe_a3 above for a more normal usage pattern.
	 */

	lws_jwk_dup_oct(&jwe.jwk, jwa_b3_rawkey, sizeof(jwa_b3_rawkey));

	memcpy(buf, jwa_b3_e, sizeof(jwa_b3_e));

	jwe.jws.map.buf[LJWE_IV] = (char *)jwa_b3_iv;
	jwe.jws.map.len[LJWE_IV] = sizeof(jwa_b3_iv);

	jwe.jws.map.buf[LJWE_CTXT] = buf;
	jwe.jws.map.len[LJWE_CTXT] = sizeof(jwa_b3_e);

	jwe.jws.map.buf[LJWE_ATAG] = (char *)jws_b3_tag;
	jwe.jws.map.len[LJWE_ATAG] = sizeof(jws_b3_tag);

	/*
	 * Normally this comes from the JOSE header.  But this test vector
	 * doesn't feature one...
	 */

	if (lws_gencrypto_jwe_alg_to_definition("A128KW", &jwe.jose.alg))
		goto bail;
	if (lws_gencrypto_jwe_enc_to_definition("A256CBC-HS512",
						&jwe.jose.enc_alg))
		goto bail;

	n = lws_jwe_auth_and_decrypt_cbc_hs(&jwe, jwa_b3_rawkey,
						    jwa_b3_a, sizeof(jwa_b3_a));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_a_cbc_hs_decrypt failed\n", __func__);

		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < sizeof(jwa_b3_ptext) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT],jwa_b3_ptext,
			        sizeof(jwa_b3_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(jwa_b3_ptext, sizeof(jwa_b3_ptext));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);

	if (ret)
		lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

/* JWA C.  Example ECDH-ES Key Agreement Computation
 *
 * This example uses ECDH-ES Key Agreement and the Concat KDF to derive
 * the CEK in the manner described in Section 4.6.  In this example, the
 * ECDH-ES Direct Key Agreement mode ("alg" value "ECDH-ES") is used to
 * produce an agreed-upon key for AES GCM with a 128-bit key ("enc"
 * value "A128GCM").
 *
 * In this example, a producer Alice is encrypting content to a consumer
 * Bob.  The producer (Alice) generates an ephemeral key for the key
 * agreement computation.
 *
 * JWA Appendix C where this comes from ONLY goes as far as to confirm the
 * direct derived key, it doesn't do any AES128-GCM.
 */

static const char

*ex_jwa_c_jose =
	"{\"alg\":\"ECDH-ES\","
	 "\"enc\":\"A128GCM\","
	 "\"apu\":\"QWxpY2U\","	/* b64u("Alice") */
	 "\"apv\":\"Qm9i\","	/* b64u("Bob") */
	 "\"epk\":" /* public part of A's ephemeral key */
	 "{\"kty\":\"EC\","
	  "\"crv\":\"P-256\","
	  "\"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\","
	  "\"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\""
	 "}"
	"}"
;

static uint8_t
ex_jwa_c_z[] = {
	158,  86, 217,  29, 129, 113,  53, 211,
	114, 131,  66, 131, 191, 132,  38, 156,
	251,  49, 110, 163, 218, 128, 106,  72,
	246, 218, 167, 121, 140, 254, 144, 196
},
ex_jwa_c_derived_key[] = {
	 86, 170, 141, 234, 248,  35, 109,  32,
	 92,  34,  40, 205, 113, 167,  16,  26
};


static int
test_jwa_c(struct lws_context *context)
{
	struct lws_jwe jwe;
	char temp[2048], *p;
	int ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	/*
	 * again the JWA Appendix C test vectors are not in the form of a
	 * complete JWE, but just the JWE JOSE header, so we must fake up the
	 * pieces and perform just the (normally internal) key agreement step
	 * for this test.
	 *
	 * See test_jwe_a3 above for a more normal usage pattern.
	 */

	if (lws_jwe_parse_jose(&jwe.jose, ex_jwa_c_jose, strlen(ex_jwa_c_jose),
			       temp, &temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	/*
	 * The ephemeral key has been parsed into a jwk "jwe.jose.jwk_ephemeral"
	 *
	 *  In this example, the ECDH-ES Direct Key Agreement mode ("alg" value
	 *  "ECDH-ES") is used to produce an agreed-upon key for AES GCM with a
	 *  128-bit key ("enc" value "A128GCM").
	 */

	p = lws_concat_temp(temp, temp_len);

	if (lws_jwa_concat_kdf(&jwe, 1, (uint8_t *)p,
			       ex_jwa_c_z, sizeof(ex_jwa_c_z))) {
		lwsl_err("%s: lws_jwa_concat_kdf failed\n", __func__);

		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (lws_timingsafe_bcmp(p, ex_jwa_c_derived_key,
			        sizeof(ex_jwa_c_derived_key))) {
		lwsl_err("%s: ECDH-ES direct derived key wrong\n", __func__);
		lwsl_hexdump_notice(ex_jwa_c_derived_key,
				    sizeof(ex_jwa_c_derived_key));
		lwsl_hexdump_notice(p, sizeof(ex_jwa_c_derived_key));
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);

	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n", __func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}


/*
 * ECDH-ES Homebrew Encryption test
 */

static const char

	/* peer key */

*ecdhes_t1_peer_p256_public_key = /* as below but with d removed */
	"{"
	 "\"crv\":\"P-256\","
	 "\"kty\":\"EC\","
	 "\"x\":\"ySlIGttmXG80WPjDO01QaXg7oAzW3NE-a-GF0NDGk_E\","
	 "\"y\":\"i08k5z4ppqgtnLK8lh5qw4qp2FhxPdGjovgilajluuw\""
	"}",

*ecdhes_t1_peer_p256_private_key = /* created by ./lws-crypto-jwk -t EC */
	"{"
	 "\"crv\":\"P-256\","
	 "\"d\":\"ldszv0_cGFMkjxaPspGCP6X0NAaVCVeK48oH4RzT2T0\","
	 "\"kty\":\"EC\","
	 "\"x\":\"ySlIGttmXG80WPjDO01QaXg7oAzW3NE-a-GF0NDGk_E\","
	 "\"y\":\"i08k5z4ppqgtnLK8lh5qw4qp2FhxPdGjovgilajluuw\""
	"}",

*ecdhes_t1_peer_p384_public_key = /* as below but with d removed */
	"{\"crv\":\"P-384\","
	 "\"kty\":\"EC\","
	 "\"x\":\"injKcygDoG1AuP044ct88r_2DNinHr1CGqy4q2Sy5yo034Y"
		 "7yQ5_NT-lEUXrzlIW\","
	 "\"y\":\"y52QaJLhVm-ts8xa1jL8GkmwGm_dX6xV1PSq4s3pbwx2Hu9"
		 "X29z5WYcTPFOCPtwJ\"}",

*ecdhes_t1_peer_p384_private_key = /* created by ./lws-crypto-jwk -t EC -v "P-384" */
	"{\"crv\":\"P-384\","
	 "\"d\":\"jYGze6ZwZxrflVx_I2lYWNf9GkfbeQNRwQCdtZhBlb85lk-"
		 "SAvaZuNiRUs_eWmPQ\","
	 "\"kty\":\"EC\","
	 "\"x\":\"injKcygDoG1AuP044ct88r_2DNinHr1CGqy4q2Sy5yo034Y"
		 "7yQ5_NT-lEUXrzlIW\","
	 "\"y\":\"y52QaJLhVm-ts8xa1jL8GkmwGm_dX6xV1PSq4s3pbwx2Hu9"
		 "X29z5WYcTPFOCPtwJ\"}",

 *ecdhes_t1_peer_p521_public_key = /* as below but with d removed */
	"{\"crv\":\"P-521\","
	 "\"kty\":\"EC\","
	 "\"x\":\"AYe0gAkPzzjeQW5Ek9tVrWdfi0u6k7LVUru-b2x7V9EM3d"
		 "L4SbQiS1p2j2gmZ2a6aDoKDRU_2E4u9EQrlswlty-g\","
	 "\"y\":\"AEAIIRkVL0WhtDlDSM7dciBtL1dOo5UPiW7ixIOv5K75Mo"
		 "uFNWO7cFmcxaCOn9459ex0giVyptmX_956C_DWabG6\"}",

*ecdhes_t1_peer_p521_private_key = /* created by ./lws-crypto-jwk -t EC -v "P-521" */
	"{\"crv\":\"P-521\","
	 "\"d\":\"AUer7_-qJtQtDWN6CMeGB20rzTa648kpsfidTOu3lnn6__"
		 "yOXkMj1yTYUBjVOnUjGHiTU1rCGsw4CyF-1nDRe7SM\","
	 "\"kty\":\"EC\","
	 "\"x\":\"AYe0gAkPzzjeQW5Ek9tVrWdfi0u6k7LVUru-b2x7V9EM3d"
		 "L4SbQiS1p2j2gmZ2a6aDoKDRU_2E4u9EQrlswlty-g\","
	 "\"y\":\"AEAIIRkVL0WhtDlDSM7dciBtL1dOo5UPiW7ixIOv5K75Mo"
		 "uFNWO7cFmcxaCOn9459ex0giVyptmX_956C_DWabG6\"}",

*ecdhes_t1_jose_hdr_es_128 =
	"{\"alg\":\"ECDH-ES\",\"enc\":\"A128CBC-HS256\"}",

*ecdhes_t1_jose_hdr_es_192 =
	"{\"alg\":\"ECDH-ES\",\"enc\":\"A192CBC-HS384\"}",

*ecdhes_t1_jose_hdr_es_256 =
	"{\"alg\":\"ECDH-ES\",\"enc\":\"A256CBC-HS512\"}",

*ecdhes_t1_jose_hdr_esakw128_128 =
	"{\"alg\":\"ECDH-ES+A128KW\",\"enc\":\"A128CBC-HS256\"}",

*ecdhes_t1_jose_hdr_esakw192_192 =
	"{\"alg\":\"ECDH-ES+A192KW\",\"enc\":\"A192CBC-HS384\"}",

*ecdhes_t1_jose_hdr_esakw256_256 =
	"{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256CBC-HS512\"}",

*ecdhes_t1_plaintext =
	"This test plaintext is exactly 64 bytes long when unencrypted..."
;

static int
test_ecdhes_t1(struct lws_context *context, const char *jose_hdr,
	       const char *peer_pubkey, const char *peer_privkey)
{
	char temp[3072], compact[2048];
	int n, ret = -1, temp_len = sizeof(temp);
	struct lws_jwe jwe;

	lws_jwe_init(&jwe, context);

	/* read and interpret our canned JOSE header, setting the algorithm */

	if (lws_jws_dup_element(&jwe.jws.map, LJWS_JOSE,
				lws_concat_temp(temp, temp_len), &temp_len,
				jose_hdr, strlen(jose_hdr), 0))
		goto bail;

	if (lws_jwe_parse_jose(&jwe.jose, jose_hdr, strlen(jose_hdr),
			       temp, &temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	/* for ecdh-es encryption, we need the peer's pubkey */

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, (char *)peer_pubkey,
			   strlen((char *)peer_pubkey)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/*
	 * dup the plaintext into the ciphertext element, it will be
	 * encrypted in-place to a ciphertext of the same length
	 */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_CTXT,
				lws_concat_temp(temp, temp_len), &temp_len,
				ecdhes_t1_plaintext,
				strlen(ecdhes_t1_plaintext), 0)) {
		lwsl_notice("%s: Not enough temp space for ptext\n", __func__);
		goto bail;
	}

	/*
	 * perform the actual encryption
	 */

	n = lws_jwe_encrypt(&jwe, lws_concat_temp(temp, temp_len), &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt failed\n", __func__);
		goto bail;
	}

	/*
	 * format for output
	 */

	n = lws_jwe_render_flattened(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n",
			 __func__, n);
		goto bail;
	}

	// puts(compact);

	n = lws_jwe_render_compact(&jwe, compact, sizeof(compact));
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n",
			 __func__, n);
		goto bail;
	}

	// puts(compact);

	/* okay, let's try to decrypt the whole thing, as the recipient
	 * getting the compact.  jws->jwk needs to be our private key.  */

	lws_jwe_destroy(&jwe);
	temp_len = sizeof(temp);
	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, (char *)peer_privkey,
			   strlen((char *)peer_privkey)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode(compact, strlen(compact), &jwe.jws.map,
				   &jwe.jws.map_b64, temp, &temp_len) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len),
				     &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: %s selftest failed +++++++++++++++++++\n",
			 __func__, jose_hdr);
	else
		lwsl_notice("%s: %s selftest OK\n", __func__, jose_hdr);

	return ret;
}

/* AES Key Wrap and AES_XXX_CBC_HMAC_SHA_YYY variations
 *
 * These were created by, eg
 *
 *   echo -n "plaintext0123456" | \
 *   ./lws-crypto-jwe -e "A192KW A256CBC-HS512" -k aes192.key
 */

/* "Live long and prosper." */
static const char
	*akw_ptext = "plaintext0123456",
	*akw_ct_128_128 = "eyJhbGciOiJBMTI4S1ciLCAiZW5jIjoiQTEyOENCQy1IUzI1NiJ9.zbTfhhWePf1UrCRDxJD_-8eAQr2AoWAL51_nNOv0L4nV3P0e4_9ARA.qWehIhy4j4_gh_h5MF9ZEw.GD40YH6NeNOEkhhxC9ryZA.PEuU6V3rhYXeoxENrAzDgw",
	*akw_ct_128_192 = "eyJhbGciOiJBMTI4S1ciLCAiZW5jIjoiQTE5MkNCQy1IUzM4NCJ9.zpkr45xH_kSJ5eTBv5dGo5PN_A6YdC4JoJSOw3_VTqcOeAYyCkCAXeGWugqIVLzMzBKgtXdabO8.O28MVhkgfketu5sxQK4Ffw.j25N7luxh251kQwpAoYURQ.Pm_NOj0KZzUq2fV9ARpHxT3Iach9feLK",
	*akw_ct_128_256 = "eyJhbGciOiJBMTI4S1ciLCAiZW5jIjoiQTI1NkNCQy1IUzUxMiJ9.VvFmi121jliyh_UKzsBv7HR3TVY7-yALpcdlasHqdzmfISd8LFU5oc2fEhfn3_TKfCbgRycm5M3103NEMbVSiNULZWvJAPFe.7uLHGFO1g-PgD9YkjPbvoA.AlPwQPWSqGaB_em4qEEyjw.0LgTLld5pSffZnzGG6IRWEwXg7HhClmwP4m_p1yKnHw",
	*akw_ct_192_128 = "eyJhbGciOiJBMTkyS1ciLCAiZW5jIjoiQTEyOENCQy1IUzI1NiJ9.kxlmi-xn0JN-ZlnSfkVDP-fXvricJ-L63WP2bWddWEiVK4m-os2trw.iarAWaeV873kh5s7HjoZ4Q.nFHEpnnIxvbCiYfFfsLj7Q.karz-h-R93dJgwN_YZyPmw",
	*akw_ct_192_192 = "eyJhbGciOiJBMTkyS1ciLCAiZW5jIjoiQTE5MkNCQy1IUzM4NCJ9.D869MEk-JERZU_4MgFuL_6Pg24LUEbXlTvGj-t_JUnNFsJ0p8fk5L-iOATqPmx2g7AyVWgcUqU0.RrxzDsy6Bne1pzx99PBGsA.C-ZWmMwd1uswYkvhKX2_jg.bIFY0TmGuohI2APxDZyFUYpa6s1Mx2j1",
	*akw_ct_192_256 = "eyJhbGciOiJBMTkyS1ciLCAiZW5jIjoiQTI1NkNCQy1IUzUxMiJ9.XNOBw0Dy1paAX2_XGkZYm2Zm455i8InAVMqM3aOrVDpXYBAADuZ_Ke_dlo3Fc8J5b9m_KNCUtVUU8f3KV0sY-yESsqyZTSXk.n3wEIV1-tL50JAp4H19Y1w.ODPd-oxmpCai9CzqaO0P3Q.b9z08hJTySSVSOw-4qp5lrTEcUur46L-RRB-SEcqPpk",
	*akw_ct_256_128 = "eyJhbGciOiJBMjU2S1ciLCAiZW5jIjoiQTEyOENCQy1IUzI1NiJ9.THaIbHUOHkr7McMeiQqIO_gBcm61F0BKx79JXkzQVVSF7m0u7Z6uhA.RAU8Yx_a9rbWeqr_0YyLZA.zzfdv55bM-qblTxaR5pNzQ.cySMIOTOcEoFkcVn0D6RKQ",
	*akw_ct_256_192 = "eyJhbGciOiJBMjU2S1ciLCAiZW5jIjoiQTE5MkNCQy1IUzM4NCJ9.gFcfX6fVrpmDJWN5jPqSWEvpOOoNuV4Yn2KO47p1wGsdw5qIw3r5AO5U8zOEtoGNVX68IC8vkpo.9w3tBsve4e-77lI-S9cFog.Vj3L009JDipPJlHY0tS4Iw.WYGgCedW4SmxleDF3P6Hx26BUXxnizxl",
	*akw_ct_256_256 = "eyJhbGciOiJBMjU2S1ciLCAiZW5jIjoiQTI1NkNCQy1IUzUxMiJ9.ldhqlMf2LJrZ7EDl-oZvaqi0b_KPGy4cMRx2QDpKtTg92tTSWF7ALVHPPCyT4qccIybP4rygajKfdC_Q_UE16KFyUvXhBgaj.S9OCmKpY0zDkArLF5XsrJw.zvJ1X-zuHsrwLXGJJbglPA.WaRKb7Le2ZQ30pGQAV3sfp-YY1563KXxPURHQ8ntdPc",
	*akw_key_128 = "{\"k\":\"JjVJVh8JsXvKf9qgHHWWBA\",\"kty\":\"oct\"}",
	*akw_key_192 = "{\"k\":\"BYF6urCMDRMKFXXRxXrDSVtW71AUZghj\",\"kty\":\"oct\"}",
	*akw_key_256 = "{\"k\":\"cSHyZXGEfnlgKud21cM6tAxRyXnK6xbWRTsyLUegTMk\",\"kty\":\"oct\"}"
;

static int
test_akw_decrypt(struct lws_context *context, const char *test_name,
		 const char *ciphertext, const char *key)
{
	struct lws_jwe jwe;
	char temp[2048];
	int n, ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, key, strlen(key)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	/* converts a compact serialization to jws b64 + decoded maps */
	if (lws_jws_compact_decode(ciphertext, strlen(ciphertext),
				   &jwe.jws.map, &jwe.jws.map_b64,
				   temp, &temp_len) != 5) {
		lwsl_err("%s: lws_jws_compact_decode failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_auth_and_decrypt(&jwe, lws_concat_temp(temp, temp_len), &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_auth_and_decrypt failed\n",
			 __func__);
		goto bail;
	}

	/* allowing for trailing padding, confirm the plaintext */
	if (jwe.jws.map.len[LJWE_CTXT] < strlen(akw_ptext) ||
	    lws_timingsafe_bcmp(jwe.jws.map.buf[LJWE_CTXT], akw_ptext,
			        strlen(akw_ptext))) {
		lwsl_err("%s: plaintext AES decrypt wrong\n", __func__);
		lwsl_hexdump_notice(akw_ptext, strlen(akw_ptext));
		lwsl_hexdump_notice(jwe.jws.map.buf[LJWE_CTXT],
				    jwe.jws.map.len[LJWE_CTXT]);
		goto bail;
	}

	ret = 0;

bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest %s failed +++++++++++++++++++\n",
			__func__, test_name);
	else
		lwsl_notice("%s: selftest %s OK\n", __func__, test_name);

	return ret;
}

static int
test_akw_encrypt(struct lws_context *context, const char *test_name,
		 const char *alg, const char *enc, const char *ciphertext,
		 const char *key, char *compact, int compact_len)
{
	struct lws_jwe jwe;
	char temp[4096];
	int ret = -1, n, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwk_import(&jwe.jwk, NULL, NULL, key, strlen(key)) < 0) {
		lwsl_notice("%s: Failed to decode JWK test key\n", __func__);
		goto bail;
	}

	if (lws_gencrypto_jwe_alg_to_definition(alg, &jwe.jose.alg)) {
		lwsl_err("Unknown cipher alg %s\n", alg);
		goto bail;
	}
	if (lws_gencrypto_jwe_enc_to_definition(enc, &jwe.jose.enc_alg)) {
		lwsl_err("Unknown payload enc alg %s\n", enc);
		goto bail;
	}

	/* we require a JOSE-formatted header to do the encryption */

	jwe.jws.map.buf[LJWS_JOSE] = temp;
	jwe.jws.map.len[LJWS_JOSE] = lws_snprintf(temp, temp_len,
			"{\"alg\":\"%s\", \"enc\":\"%s\"}", alg, enc);
	temp_len -= jwe.jws.map.len[LJWS_JOSE];

	/*
	 * dup the plaintext into the ciphertext element, it will be
	 * encrypted in-place to a ciphertext of the same length
	 */

	if (lws_jws_dup_element(&jwe.jws.map, LJWE_CTXT,
				lws_concat_temp(temp, temp_len), &temp_len,
				akw_ptext, strlen(akw_ptext), 0)) {
		lwsl_notice("%s: Not enough temp space for ptext\n", __func__);
		goto bail;
	}

	/* CEK size is determined by hash / hmac size */

	n = lws_gencrypto_bits_to_bytes(jwe.jose.enc_alg->keybits_fixed);
	if (lws_jws_randomize_element(context, &jwe.jws.map, LJWE_EKEY,
				      lws_concat_temp(temp, temp_len),
				      &temp_len, n,
				      LWS_JWE_LIMIT_KEY_ELEMENT_BYTES)) {
		lwsl_err("Problem getting random\n");
		goto bail;
	}

	n = lws_jwe_encrypt(&jwe, lws_concat_temp(temp, temp_len),
			    &temp_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_encrypt failed\n", __func__);
		goto bail;
	}

	n = lws_jwe_render_compact(&jwe, compact, compact_len);
	if (n < 0) {
		lwsl_err("%s: lws_jwe_render_compact failed: %d\n",
			 __func__, n);
		goto bail;
	}

	ret = 0;
bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest %s failed +++++++++++++++++++\n",
			__func__, test_name);
	else
		lwsl_notice("%s: selftest %s OK\n", __func__, test_name);

	return ret;
}

/*
 * Check we can handle multi-recipient JWE
 */

static char *complete =
    "{"
      "\"protected\":"
       "\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\","
      "\"unprotected\":"
       "{\"jku\":\"https://server.example.com/keys.jwks\"},"
      "\"recipients\":["

	"{\"header\":"
         "{\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"},"
        "\"encrypted_key\":"
         "\"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-"
          "kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx"
          "GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3"
          "YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh"
          "cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg"
          "wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A\"},"

       "{\"header\":"
         "{\"alg\":\"A128KW\",\"kid\":\"7\"},"
        "\"encrypted_key\":"
         "\"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"}],"

      "\"iv\":"
       "\"AxY8DCtDaGlsbGljb3RoZQ\","
      "\"ciphertext\":"
       "\"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\","
      "\"tag\":"
       "\"Mz-VPPyU4RlcuYv1IwIvzw\""
     "}\""
;

static int
test_jwe_json_complete(struct lws_context *context)
{
	struct lws_jwe jwe;
	char temp[4096];
	int ret = -1, temp_len = sizeof(temp);

	lws_jwe_init(&jwe, context);

	if (lws_jwe_parse_jose(&jwe.jose, complete, strlen(complete),
			       temp, &temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);

		goto bail;
	}

	if (jwe.jose.recipients != 2) {
		lwsl_err("%s: wrong recipients count %d\n", __func__,
			 jwe.jose.recipients);
		goto bail;
	}

	ret = 0;
bail:
	lws_jwe_destroy(&jwe);
	if (ret)
		lwsl_err("%s: selftest failed +++++++++++++++++++\n",
			__func__);
	else
		lwsl_notice("%s: selftest OK\n", __func__);

	return ret;
}

int
test_jwe(struct lws_context *context)
{
	char compact[4096];
	int n = 0;

	n |= test_jwe_json_complete(context);

	n |= test_ecdhes_t1(context, ecdhes_t1_jose_hdr_es_128,
			    ecdhes_t1_peer_p256_public_key,
			    ecdhes_t1_peer_p256_private_key);
	n |= test_ecdhes_t1(context, ecdhes_t1_jose_hdr_es_192,
			    ecdhes_t1_peer_p384_public_key,
			    ecdhes_t1_peer_p384_private_key);
	n |= test_ecdhes_t1(context, ecdhes_t1_jose_hdr_es_256,
			    ecdhes_t1_peer_p521_public_key,
			    ecdhes_t1_peer_p521_private_key);

	n |= test_ecdhes_t1(context, ecdhes_t1_jose_hdr_esakw128_128,
			    ecdhes_t1_peer_p256_public_key,
			    ecdhes_t1_peer_p256_private_key);
	n |= test_ecdhes_t1(context, ecdhes_t1_jose_hdr_esakw192_192,
			    ecdhes_t1_peer_p384_public_key,
			    ecdhes_t1_peer_p384_private_key);
	n |= test_ecdhes_t1(context, ecdhes_t1_jose_hdr_esakw256_256,
			    ecdhes_t1_peer_p521_public_key,
			    ecdhes_t1_peer_p521_private_key);

	n |= test_jwe_a1(context);

	n |= test_jwe_a2(context);

	n |= test_jwe_ra_ptext_1024(context, (char *)lws_jwe_ex_a2_jwk_json,
				    strlen((char *)lws_jwe_ex_a2_jwk_json));
	n |= test_jwe_r256a192_ptext(context, (char *)lws_jwe_ex_a2_jwk_json,
				     strlen((char *)lws_jwe_ex_a2_jwk_json));
	n |= test_jwe_r256a256_ptext(context, (char *)lws_jwe_ex_a2_jwk_json,
				     strlen((char *)lws_jwe_ex_a2_jwk_json));
	n |= test_jwe_ra_ptext_1024(context, (char *)rsa_key_2048,
				    strlen((char *)rsa_key_2048));
	n |= test_jwe_r256a192_ptext(context, (char *)rsa_key_2048,
				     strlen((char *)rsa_key_2048));
	n |= test_jwe_r256a256_ptext(context, (char *)rsa_key_2048,
				     strlen((char *)rsa_key_2048));
	n |= test_jwe_ra_ptext_1024(context, (char *)rsa_key_4096,
				    strlen((char *)rsa_key_4096));
	n |= test_jwe_r256a192_ptext(context, (char *)rsa_key_4096,
				     strlen((char *)rsa_key_4096));
	n |= test_jwe_r256a256_ptext(context, (char *)rsa_key_4096,
				     strlen((char *)rsa_key_4096));
	n |= test_jwe_ra_ptext_1024(context, (char *)rsa_key_4096_no_optional,
				    strlen((char *)rsa_key_4096_no_optional));
	n |= test_jwe_r256a192_ptext(context, (char *)rsa_key_4096_no_optional,
				     strlen((char *)rsa_key_4096_no_optional));
	n |= test_jwe_r256a256_ptext(context, (char *)rsa_key_4096_no_optional,
				     strlen((char *)rsa_key_4096_no_optional));

	/* AESKW decrypt all variations */

	n |= test_akw_decrypt(context, "d-a128kw_128", akw_ct_128_128, akw_key_128);
	n |= test_akw_decrypt(context, "d-a128kw_192", akw_ct_128_192, akw_key_128);
	n |= test_akw_decrypt(context, "d-a128kw_256", akw_ct_128_256, akw_key_128);
	n |= test_akw_decrypt(context, "d-a192kw_128", akw_ct_192_128, akw_key_192);
	n |= test_akw_decrypt(context, "d-a192kw_192", akw_ct_192_192, akw_key_192);
	n |= test_akw_decrypt(context, "d-a192kw_256", akw_ct_192_256, akw_key_192);
	n |= test_akw_decrypt(context, "d-a256kw_128", akw_ct_256_128, akw_key_256);
	n |= test_akw_decrypt(context, "d-a256kw_192", akw_ct_256_192, akw_key_256);
	n |= test_akw_decrypt(context, "d-a256kw_256", akw_ct_256_256, akw_key_256);

	/* AESKW encrypt then confirm decrypt */

	if (!test_akw_encrypt(context, "ed-128kw_128", "A128KW", "A128CBC-HS256",
			akw_ptext, akw_key_128, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-128kw_128", compact, akw_key_128);
	else
		n = -1;
	if (!test_akw_encrypt(context, "ed-128kw_192", "A128KW", "A192CBC-HS384",
			akw_ptext, akw_key_128, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-128kw_192", compact, akw_key_128);
	else
		n = -1;
	if (!test_akw_encrypt(context, "ed-128kw_256", "A128KW", "A256CBC-HS512",
			akw_ptext, akw_key_128, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-128kw_256", compact, akw_key_128);
	else
		n = -1;

	if (!test_akw_encrypt(context, "ed-192kw_128", "A192KW", "A128CBC-HS256",
			akw_ptext, akw_key_192, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-192kw_128", compact, akw_key_192);
	else
		n = -1;
	if (!test_akw_encrypt(context, "ed-192kw_192", "A192KW", "A192CBC-HS384",
			akw_ptext, akw_key_192, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-192kw_192", compact, akw_key_192);
	else
		n = -1;
	if (!test_akw_encrypt(context, "ed-192kw_256", "A192KW", "A256CBC-HS512",
			akw_ptext, akw_key_192, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-192kw_256", compact, akw_key_192);
	else
		n = -1;

	if (!test_akw_encrypt(context, "ed-256kw_128", "A256KW", "A128CBC-HS256",
			akw_ptext, akw_key_256, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-256kw_128", compact, akw_key_256);
	else
		n = -1;
	if (!test_akw_encrypt(context, "ed-256kw_192", "A256KW", "A192CBC-HS384",
			akw_ptext, akw_key_256, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-256kw_192", compact, akw_key_256);
	else
		n = -1;
	if (!test_akw_encrypt(context, "ed-256kw_256", "A256KW", "A256CBC-HS512",
			akw_ptext, akw_key_256, compact, sizeof(compact)))
		n |= test_akw_decrypt(context, "ed-256kw_256", compact, akw_key_256);
	else
		n = -1;

	n |= test_jwe_r256a128_jwe_openssl(context);
	n |= test_jwe_r256a128_jwe_mbedtls(context);
	n |= test_jwe_a3(context);
	n |= test_jwa_b2(context);
	n |= test_jwa_b3(context);
	n |= test_jwa_c(context);

	return n;
}
