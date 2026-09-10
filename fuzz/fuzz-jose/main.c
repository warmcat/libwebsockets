/*
 * libwebsockets - libFuzzer target for JOSE (JWK / JWS / JWE) parsing
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
 *
 * The JSON framing underneath is already covered by fuzz-lejp; this target is
 * for the layer above it: JWK key-element import, JOSE header parsing, JWS
 * compact / flattened decoding and signature confirmation, and JWE decoding
 * and auth+decrypt against fixed keys.  These take untrusted input in the
 * SSO and auth-dns deployments.
 *
 * Input layout:
 *
 *   [0]     selects the operation (mod 8)
 *   [1]     selects the fixed verification key (mod 3): oct / RSA / EC
 *   [2..]   the JSON or compact-serialization payload
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

static struct lws_context *cx;

/* RFC7515 A.1 HS256 key */
static const char key_oct[] =
	"{\"kty\":\"oct\",\r\n"
	" \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQ"
	"Lr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";

/* RFC7516 A.2 RSA key */
static const char key_rsa[] =
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
	"}";

/* RFC7517 A.2 EC P-256 private key */
static const char key_ec[] =
	"{\"kty\":\"EC\","
	"\"crv\":\"P-256\","
	"\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
	"\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
	"\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","
	"\"use\":\"enc\","
	"\"kid\":\"1\"}";

static const char * const keys[] = { key_oct, key_rsa, key_ec };

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct lws_context_creation_info info;

	(void)argc;
	(void)argv;

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);

	return cx ? 0 : 1;
}

static int
jwk_cb(struct lws_jwk *s, void *user)
{
	(void)s;
	(void)user;

	return 0;
}

static int
fixed_key(struct lws_jwk *jwk, unsigned int which)
{
	const char *k = keys[which % LWS_ARRAY_SIZE(keys)];

	memset(jwk, 0, sizeof(*jwk));

	return lws_jwk_import(jwk, NULL, NULL, k, strlen(k));
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lws_jws_map map, map_b64;
	struct lws_jose jose;
	struct lws_jwk jwk;
	struct lws_jws jws;
	struct lws_jwe jwe;
	unsigned int sel, key;
	char temp[4096], *buf;
	int temp_len;
	size_t len;

	if (size < 2)
		return 0;

	sel = data[0] % 8;
	key = data[1];
	len = size - 2;

	/* NUL-terminated copy: some entry points take a cstring */
	buf = malloc(len + 1);
	if (!buf)
		return 0;
	memcpy(buf, data + 2, len);
	buf[len] = '\0';

	temp_len = sizeof(temp);

	switch (sel) {
	case 0: /* single JWK import */
		memset(&jwk, 0, sizeof(jwk));
		lws_jwk_import(&jwk, NULL, NULL, buf, len);
		lws_jwk_destroy(&jwk);
		break;

	case 1: /* JWK set ("keys": [...]) import with per-key callback */
		memset(&jwk, 0, sizeof(jwk));
		lws_jwk_import(&jwk, jwk_cb, NULL, buf, len);
		lws_jwk_destroy(&jwk);
		break;

	case 2: /* JWS compact serialization: decode + confirm signature */
		if (fixed_key(&jwk, key) < 0)
			break;
		lws_jws_init(&jws, &jwk, cx);
		if (lws_jws_compact_decode(buf, (int)len, &map, &map_b64,
					   temp, &temp_len) > 0) {
			temp_len = sizeof(temp);
			lws_jws_sig_confirm_compact_b64(buf, len, &jws.map,
							&jwk, cx, temp,
							&temp_len);
		}
		lws_jws_destroy(&jws);
		lws_jwk_destroy(&jwk);
		break;

	case 3: /* JWS flattened JSON serialization: confirm signature */
		if (fixed_key(&jwk, key) < 0)
			break;
		lws_jws_init(&jws, &jwk, cx);
		lws_jws_sig_confirm_json(buf, len, &jws, &jwk, cx, temp,
					 &temp_len);
		lws_jws_destroy(&jws);
		lws_jwk_destroy(&jwk);
		break;

	case 4: /* JOSE header parse, as JWS then as JWE */
		lws_jose_init(&jose);
		lws_jws_parse_jose(&jose, buf, (int)len, temp, &temp_len);
		lws_jose_destroy(&jose);

		temp_len = sizeof(temp);
		lws_jose_init(&jose);
		lws_jwe_parse_jose(&jose, buf, (int)len, temp, &temp_len);
		lws_jose_destroy(&jose);
		break;

	case 5: /* JWE compact serialization: decode + auth + decrypt */
		lws_jwe_init(&jwe, cx);
		if (fixed_key(&jwe.jwk, key) < 0) {
			lws_jwe_destroy(&jwe);
			break;
		}
		if (lws_jws_compact_decode(buf, (int)len, &jwe.jws.map,
					   &jwe.jws.map_b64, temp,
					   &temp_len) == 5)
			lws_jwe_auth_and_decrypt(&jwe,
					lws_concat_temp(temp, temp_len),
					&temp_len);
		lws_jwe_destroy(&jwe);
		break;

	case 6: /* JWE flattened JSON serialization: parse + auth + decrypt */
		lws_jwe_init(&jwe, cx);
		if (fixed_key(&jwe.jwk, key) < 0) {
			lws_jwe_destroy(&jwe);
			break;
		}
		if (!lws_jwe_json_parse(&jwe, (const uint8_t *)buf, (int)len,
					temp, &temp_len))
			lws_jwe_auth_and_decrypt(&jwe,
					lws_concat_temp(temp, temp_len),
					&temp_len);
		lws_jwe_destroy(&jwe);
		break;

	case 7: /* JWK import then export round trip */
		memset(&jwk, 0, sizeof(jwk));
		if (lws_jwk_import(&jwk, NULL, NULL, buf, len) >= 0) {
			temp_len = sizeof(temp);
			lws_jwk_export(&jwk, LWSJWKF_EXPORT_PRIVATE, temp,
				       &temp_len);
		}
		lws_jwk_destroy(&jwk);
		break;

	default:
		break;
	}

	free(buf);

	return 0;
}
