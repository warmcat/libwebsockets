/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"
#include "private-lib-jose-jws.h"

/*
 * Currently only support flattened or compact (implicitly single signature)
 */

static const char * const jws_json[] = {
	"protected", /* base64u */
	"header", /* JSON */
	"payload", /* base64u payload */
	"signature", /* base64u signature */

	//"signatures[].protected",
	//"signatures[].header",
	//"signatures[].signature"
};

enum lws_jws_json_tok {
	LJWSJT_PROTECTED,
	LJWSJT_HEADER,
	LJWSJT_PAYLOAD,
	LJWSJT_SIGNATURE,

	// LJWSJT_SIGNATURES_PROTECTED,
	// LJWSJT_SIGNATURES_HEADER,
	// LJWSJT_SIGNATURES_SIGNATURE,
};

/* parse a JWS complete or flattened JSON object */

struct jws_cb_args {
	struct lws_jws *jws;

	char *temp;
	int *temp_len;
};

static signed char
lws_jws_json_cb(struct lejp_ctx *ctx, char reason)
{
	struct jws_cb_args *args = (struct jws_cb_args *)ctx->user;
	int n, m;

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {

	/* strings */

	case LJWSJT_PROTECTED:  /* base64u: JOSE: must contain 'alg' */
		m = LJWS_JOSE;
		goto append_string;
	case LJWSJT_PAYLOAD:	/* base64u */
		m = LJWS_PYLD;
		goto append_string;
	case LJWSJT_SIGNATURE:  /* base64u */
		m = LJWS_SIG;
		goto append_string;

	case LJWSJT_HEADER:	/* unprotected freeform JSON */
		break;

	default:
		return -1;
	}

	return 0;

append_string:

	if (*args->temp_len < ctx->npos) {
		lwsl_err("%s: out of parsing space\n", __func__);
		return -1;
	}

	/*
	 * We keep both b64u and decoded in temp mapped using map / map_b64,
	 * the jws signature is actually over the b64 content not the plaintext,
	 * and we can't do it until we see the protected alg.
	 */

	if (!args->jws->map_b64.buf[m]) {
		args->jws->map_b64.buf[m] = args->temp;
		args->jws->map_b64.len[m] = 0;
	}

	memcpy(args->temp, ctx->buf, ctx->npos);
	args->temp += ctx->npos;
	*args->temp_len -= ctx->npos;
	args->jws->map_b64.len[m] += ctx->npos;

	if (reason == LEJPCB_VAL_STR_END) {
		args->jws->map.buf[m] = args->temp;

		n = lws_b64_decode_string_len(
			(const char *)args->jws->map_b64.buf[m],
			args->jws->map_b64.len[m],
			(char *)args->temp, *args->temp_len);
		if (n < 0) {
			lwsl_err("%s: b64 decode failed: in len %d, m %d\n", __func__, (int)args->jws->map_b64.len[m], m);
			return -1;
		}

		args->temp += n;
		*args->temp_len -= n;
		args->jws->map.len[m] = n;
	}

	return 0;
}

static int
lws_jws_json_parse(struct lws_jws *jws, const uint8_t *buf, int len,
		   char *temp, int *temp_len)
{
	struct jws_cb_args args;
	struct lejp_ctx jctx;
	int m = 0;

	args.jws = jws;
	args.temp = temp;
	args.temp_len = temp_len;

	lejp_construct(&jctx, lws_jws_json_cb, &args, jws_json,
		       LWS_ARRAY_SIZE(jws_json));

	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)buf, len);
	lejp_destruct(&jctx);
	if (m < 0) {
		lwsl_notice("%s: parse returned %d\n", __func__, m);
		return -1;
	}

	return 0;
}

void
lws_jws_init(struct lws_jws *jws, struct lws_jwk *jwk,
	     struct lws_context *context)
{
	memset(jws, 0, sizeof(*jws));
	jws->context = context;
	jws->jwk = jwk;
}

static void
lws_jws_map_bzero(struct lws_jws_map *map)
{
	int n;

	/* no need to scrub first jose header element (it can be canned then) */

	for (n = 1; n < LWS_JWS_MAX_COMPACT_BLOCKS; n++)
		if (map->buf[n])
			lws_explicit_bzero((void *)map->buf[n], map->len[n]);
}

void
lws_jws_destroy(struct lws_jws *jws)
{
	lws_jws_map_bzero(&jws->map);
	jws->jwk = NULL;
}

int
lws_jws_dup_element(struct lws_jws_map *map, int idx, char *temp, int *temp_len,
		    const void *in, size_t in_len, size_t actual_alloc)
{
	if (!actual_alloc)
		actual_alloc = in_len;

	if ((size_t)*temp_len < actual_alloc)
		return -1;

	memcpy(temp, in, in_len);

	map->len[idx] = in_len;
	map->buf[idx] = temp;

	*temp_len -= actual_alloc;

	return 0;
}

int
lws_jws_encode_b64_element(struct lws_jws_map *map, int idx,
			   char *temp, int *temp_len, const void *in,
			   size_t in_len)
{
	int n;

	if (*temp_len < lws_base64_size((int)in_len))
		return -1;

	n = lws_jws_base64_enc(in, in_len, temp, *temp_len);
	if (n < 0)
		return -1;

	map->len[idx] = n;
	map->buf[idx] = temp;

	*temp_len -= n;

	return 0;
}

int
lws_jws_randomize_element(struct lws_context *context, struct lws_jws_map *map,
			  int idx, char *temp, int *temp_len, size_t random_len,
			  size_t actual_alloc)
{
	if (!actual_alloc)
		actual_alloc = random_len;

	if ((size_t)*temp_len < actual_alloc)
		return -1;

	map->len[idx] = random_len;
	map->buf[idx] = temp;

	if (lws_get_random(context, temp, random_len) != random_len) {
		lwsl_err("Problem getting random\n");
		return -1;
	}

	*temp_len -= actual_alloc;

	return 0;
}

int
lws_jws_alloc_element(struct lws_jws_map *map, int idx, char *temp,
		      int *temp_len, size_t len, size_t actual_alloc)
{
	if (!actual_alloc)
		actual_alloc = len;

	if ((size_t)*temp_len < actual_alloc)
		return -1;

	map->len[idx] = len;
	map->buf[idx] = temp;
	*temp_len -= actual_alloc;

	return 0;
}

int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max)
{
	int n;

	n = lws_b64_encode_string_url(in, in_len, out, out_max - 1);
	if (n < 0) {
		lwsl_notice("%s: in len %d too large for %d out buf\n",
				__func__, (int)in_len, (int)out_max);
		return n; /* too large for output buffer */
	}

	/* trim the terminal = */
	while (n && out[n - 1] == '=')
		n--;

	out[n] = '\0';

	return n;
}

int
lws_jws_b64_compact_map(const char *in, int len, struct lws_jws_map *map)
{
	int me = 0;

	memset(map, 0, sizeof(*map));

	map->buf[me] = (char *)in;
	map->len[me] = 0;

	while (len--) {
		if (*in++ == '.') {
			if (++me == LWS_JWS_MAX_COMPACT_BLOCKS)
				return -1;
			map->buf[me] = (char *)in;
			map->len[me] = 0;
			continue;
		}
		map->len[me]++;
	}

	return me + 1;
}

/* b64 in, map contains decoded elements, if non-NULL,
 * map_b64 set to b64 elements
 */

int
lws_jws_compact_decode(const char *in, int len, struct lws_jws_map *map,
		       struct lws_jws_map *map_b64, char *out,
		       int *out_len)
{
	int blocks, n, m = 0;

	if (!map_b64)
		map_b64 = map;

	memset(map_b64, 0, sizeof(*map_b64));
	memset(map, 0, sizeof(*map));

	blocks = lws_jws_b64_compact_map(in, len, map_b64);

	if (blocks > LWS_JWS_MAX_COMPACT_BLOCKS)
		return -1;

	while (m < blocks) {
		n = lws_b64_decode_string_len(map_b64->buf[m], map_b64->len[m],
					      out, *out_len);
		if (n < 0) {
			lwsl_err("%s: b64 decode failed\n", __func__);
			return -1;
		}
		/* replace the map entry with the decoded content */
		if (n)
			map->buf[m] = out;
		else
			map->buf[m] = NULL;
		map->len[m++] = n;
		out += n;
		*out_len -= n;

		if (*out_len < 1)
			return -1;
	}

	return blocks;
}

static int
lws_jws_compact_decode_map(struct lws_jws_map *map_b64, struct lws_jws_map *map,
			   char *out, int *out_len)
{
	int n, m = 0;

	for (n = 0; n < LWS_JWS_MAX_COMPACT_BLOCKS; n++) {
		n = lws_b64_decode_string_len(map_b64->buf[m], map_b64->len[m],
					      out, *out_len);
		if (n < 0) {
			lwsl_err("%s: b64 decode failed\n", __func__);
			return -1;
		}
		/* replace the map entry with the decoded content */
		map->buf[m] = out;
		map->len[m++] = n;
		out += n;
		*out_len -= n;

		if (*out_len < 1)
			return -1;
	}

	return 0;
}

int
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

int
lws_jws_compact_encode(struct lws_jws_map *map_b64, /* b64-encoded */
		       const struct lws_jws_map *map,	/* non-b64 */
		       char *buf, int *len)
{
	int n, m;

	for (n = 0; n < LWS_JWS_MAX_COMPACT_BLOCKS; n++) {
		if (!map->buf[n]) {
			map_b64->buf[n] = NULL;
			map_b64->len[n] = 0;
			continue;
		}
		m = lws_jws_base64_enc(map->buf[n], map->len[n], buf, *len);
		if (m < 0)
			return -1;
		buf += m;
		*len -= m;
		if (*len < 1)
			return -1;
	}

	return 0;
}

/*
 * This takes both a base64 -encoded map and a plaintext map.
 *
 * JWS demands base-64 encoded elements for hash computation and at least for
 * the JOSE header and signature, decoded versions too.
 */

int
lws_jws_sig_confirm(struct lws_jws_map *map_b64, struct lws_jws_map *map,
		    struct lws_jwk *jwk, struct lws_context *context)
{
	enum enum_genrsa_mode padding = LGRSAM_PKCS1_1_5;
	char temp[256];
	int n, h_len, b = 3, temp_len = sizeof(temp);
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genec_ctx ecdsactx;
	struct lws_genrsa_ctx rsactx;
	struct lws_genhmac_ctx ctx;
	struct lws_jose jose;

	lws_jose_init(&jose);

	/* only valid if no signature or key */
	if (!map_b64->buf[LJWS_SIG] && !map->buf[LJWS_UHDR])
		b = 2;

	if (lws_jws_parse_jose(&jose, map->buf[LJWS_JOSE], map->len[LJWS_JOSE],
			       temp, &temp_len) < 0 || !jose.alg) {
		lwsl_notice("%s: parse failed\n", __func__);
		return -1;
	}

	if (!strcmp(jose.alg->alg, "none")) {
		/* "none" compact serialization has 2 blocks: jose.payload */
		if (b != 2 || jwk)
			return -1;

		/* the lack of a key matches the lack of a signature */
		return 0;
	}

	/* all other have 3 blocks: jose.payload.sig */
	if (b != 3 || !jwk) {
		lwsl_notice("%s: %d blocks\n", __func__, b);
		return -1;
	}

	switch (jose.alg->algtype_signing) {
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
		padding = LGRSAM_PKCS1_OAEP_PSS;
		/* fallthru */
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:

		/* RSASSA-PKCS1-v1_5 or OAEP using SHA-256/384/512 */

		if (jwk->kty != LWS_GENCRYPTO_KTY_RSA)
			return -1;

		/* 6(RSA): compute the hash of the payload into "digest" */

		if (lws_genhash_init(&hash_ctx, jose.alg->hash_type))
			return -1;

		/*
		 * JWS Signing Input value:
		 *
		 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
		 * 	BASE64URL(JWS Payload)
		 */

		if (lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_JOSE],
						  map_b64->len[LJWS_JOSE]) ||
		    lws_genhash_update(&hash_ctx, ".", 1) ||
		    lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_PYLD],
						  map_b64->len[LJWS_PYLD]) ||
		    lws_genhash_destroy(&hash_ctx, digest)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}
		// h_len = lws_genhash_size(jose.alg->hash_type);

		if (lws_genrsa_create(&rsactx, jwk->e, context, padding,
				LWS_GENHASH_TYPE_UNKNOWN)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = lws_genrsa_hash_sig_verify(&rsactx, digest,
					       jose.alg->hash_type,
					       (uint8_t *)map->buf[LJWS_SIG],
					       map->len[LJWS_SIG]);

		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lwsl_notice("%s: decrypt fail\n", __func__);
			return -1;
		}

		break;

	case LWS_JOSE_ENCTYPE_NONE: /* HSxxx */

		/* SHA256/384/512 HMAC */

		h_len = lws_genhmac_size(jose.alg->hmac_type);

		/* 6) compute HMAC over payload */

		if (lws_genhmac_init(&ctx, jose.alg->hmac_type,
				     jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
				     jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len))
			return -1;

		/*
		 * JWS Signing Input value:
		 *
		 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
		 *   BASE64URL(JWS Payload)
		 */

		if (lws_genhmac_update(&ctx, map_b64->buf[LJWS_JOSE],
					     map_b64->len[LJWS_JOSE]) ||
		    lws_genhmac_update(&ctx, ".", 1) ||
		    lws_genhmac_update(&ctx, map_b64->buf[LJWS_PYLD],
					     map_b64->len[LJWS_PYLD]) ||
		    lws_genhmac_destroy(&ctx, digest)) {
			lws_genhmac_destroy(&ctx, NULL);

			return -1;
		}

		/* 7) Compare the computed and decoded hashes */

		if (lws_timingsafe_bcmp(digest, map->buf[2], h_len)) {
			lwsl_notice("digest mismatch\n");

			return -1;
		}

		break;

	case LWS_JOSE_ENCTYPE_ECDSA:

		/* ECDSA using SHA-256/384/512 */

		/* Confirm the key coming in with this makes sense */

		/* has to be an EC key :-) */
		if (jwk->kty != LWS_GENCRYPTO_KTY_EC)
			return -1;

		/* key must state its curve */
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
			return -1;

		/* key must match the selected alg curve */
		if (strcmp((const char *)jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
				jose.alg->curve_name))
			return -1;

		/*
		 * JWS Signing Input value:
		 *
		 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
		 * 	BASE64URL(JWS Payload)
		 *
		 * Validating the JWS Signature is a bit different from the
		 * previous examples.  We need to split the 64 member octet
		 * sequence of the JWS Signature (which is base64url decoded
		 * from the value encoded in the JWS representation) into two
		 * 32 octet sequences, the first representing R and the second
		 * S.  We then pass the public key (x, y), the signature (R, S),
		 * and the JWS Signing Input (which is the initial substring of
		 * the JWS Compact Serialization representation up until but not
		 * including the second period character) to an ECDSA signature
		 * verifier that has been configured to use the P-256 curve with
		 * the SHA-256 hash function.
		 */

		if (lws_genhash_init(&hash_ctx, jose.alg->hash_type) ||
		    lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_JOSE],
						  map_b64->len[LJWS_JOSE]) ||
		    lws_genhash_update(&hash_ctx, ".", 1) ||
		    lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_PYLD],
						  map_b64->len[LJWS_PYLD]) ||
		    lws_genhash_destroy(&hash_ctx, digest)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}

		h_len = lws_genhash_size(jose.alg->hash_type);

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

		n = lws_genecdsa_hash_sig_verify_jws(&ecdsactx, digest,
						     jose.alg->hash_type,
						     jose.alg->keybits_fixed,
						  (uint8_t *)map->buf[LJWS_SIG],
						     map->len[LJWS_SIG]);
		lws_genec_destroy(&ecdsactx);
		if (n < 0) {
			lwsl_notice("%s: verify fail\n", __func__);
			return -1;
		}

		break;

	default:
		lwsl_err("%s: unknown alg from jose\n", __func__);
		return -1;
	}

	return 0;
}

/* it's already a b64 map, we will make a temp plain version */

int
lws_jws_sig_confirm_compact_b64_map(struct lws_jws_map *map_b64,
				    struct lws_jwk *jwk,
			            struct lws_context *context,
			            char *temp, int *temp_len)
{
	struct lws_jws_map map;
	int n;

	n = lws_jws_compact_decode_map(map_b64, &map, temp, temp_len);
	if (n > 3 || n < 0)
		return -1;

	return lws_jws_sig_confirm(map_b64, &map, jwk, context);
}

/*
 * it's already a compact / concatenated b64 string, we will make a temp
 * plain version
 */

int
lws_jws_sig_confirm_compact_b64(const char *in, size_t len,
				struct lws_jws_map *map, struct lws_jwk *jwk,
				struct lws_context *context,
				char *temp, int *temp_len)
{
	struct lws_jws_map map_b64;
	int n;

	if (lws_jws_b64_compact_map(in, len, &map_b64) < 0)
		return -1;

	n = lws_jws_compact_decode(in, len, map, &map_b64, temp, temp_len);
	if (n > 3 || n < 0)
		return -1;

	return lws_jws_sig_confirm(&map_b64, map, jwk, context);
}

/* it's already plain, we will make a temp b64 version */

int
lws_jws_sig_confirm_compact(struct lws_jws_map *map, struct lws_jwk *jwk,
			    struct lws_context *context, char *temp,
			    int *temp_len)
{
	struct lws_jws_map map_b64;

	if (lws_jws_compact_encode(&map_b64, map, temp, temp_len) < 0)
		return -1;

	return lws_jws_sig_confirm(&map_b64, map, jwk, context);
}

int
lws_jws_sig_confirm_json(const char *in, size_t len,
			 struct lws_jws *jws, struct lws_jwk *jwk,
			 struct lws_context *context,
			 char *temp, int *temp_len)
{
	if (lws_jws_json_parse(jws, (const uint8_t *)in, len, temp, temp_len)) {
		lwsl_err("%s: lws_jws_json_parse failed\n", __func__);

		return -1;
	}
	return lws_jws_sig_confirm(&jws->map_b64, &jws->map, jwk, context);
}


int
lws_jws_sign_from_b64(struct lws_jose *jose, struct lws_jws *jws,
		      char *b64_sig, size_t sig_len)
{
	enum enum_genrsa_mode pad = LGRSAM_PKCS1_1_5;
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genec_ctx ecdsactx;
	struct lws_genrsa_ctx rsactx;
	uint8_t *buf;
	int n, m;

	if (jose->alg->hash_type == LWS_GENHASH_TYPE_UNKNOWN &&
	    jose->alg->hmac_type == LWS_GENHMAC_TYPE_UNKNOWN &&
	    !strcmp(jose->alg->alg, "none"))
		return 0;

	if (lws_genhash_init(&hash_ctx, jose->alg->hash_type) ||
	    lws_genhash_update(&hash_ctx, jws->map_b64.buf[LJWS_JOSE],
					  jws->map_b64.len[LJWS_JOSE]) ||
	    lws_genhash_update(&hash_ctx, ".", 1) ||
	    lws_genhash_update(&hash_ctx, jws->map_b64.buf[LJWS_PYLD],
					  jws->map_b64.len[LJWS_PYLD]) ||
	    lws_genhash_destroy(&hash_ctx, digest)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		return -1;
	}

	switch (jose->alg->algtype_signing) {
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
		pad = LGRSAM_PKCS1_OAEP_PSS;
		/* fallthru */
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:

		if (jws->jwk->kty != LWS_GENCRYPTO_KTY_RSA)
			return -1;

		if (lws_genrsa_create(&rsactx, jws->jwk->e, jws->context,
				      pad, LWS_GENHASH_TYPE_UNKNOWN)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = jws->jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
		buf = lws_malloc(lws_base64_size(n), "jws sign");
		if (!buf)
			return -1;

		n = lws_genrsa_hash_sign(&rsactx, digest, jose->alg->hash_type,
					 buf, n);
		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lwsl_err("%s: lws_genrsa_hash_sign failed\n", __func__);
			lws_free(buf);

			return -1;
		}

		n = lws_jws_base64_enc((char *)buf, n, b64_sig, sig_len);
		lws_free(buf);
		if (n < 0) {
			lwsl_err("%s: lws_jws_base64_enc failed\n", __func__);
		}

		return n;

	case LWS_JOSE_ENCTYPE_NONE:
		return lws_jws_base64_enc((char *)digest,
					 lws_genhash_size(jose->alg->hash_type),
					  b64_sig, sig_len);
	case LWS_JOSE_ENCTYPE_ECDSA:
		/* ECDSA using SHA-256/384/512 */

		/* the key coming in with this makes sense, right? */

		/* has to be an EC key :-) */
		if (jws->jwk->kty != LWS_GENCRYPTO_KTY_EC)
			return -1;

		/* key must state its curve */
		if (!jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
			return -1;

		/* must have all his pieces for a private key */
		if (!jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf ||
		    !jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf ||
		    !jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf)
			return -1;

		/* key must match the selected alg curve */
		if (strcmp((const char *)
				jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
			    jose->alg->curve_name))
			return -1;

		if (lws_genecdsa_create(&ecdsactx, jws->context, NULL)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		if (lws_genecdsa_set_key(&ecdsactx, jws->jwk->e)) {
			lws_genec_destroy(&ecdsactx);
			lwsl_notice("%s: ec key import fail\n", __func__);
			return -1;
		}
		m = lws_gencrypto_bits_to_bytes(jose->alg->keybits_fixed) * 2;
		buf = lws_malloc(m, "jws sign");
		if (!buf)
			return -1;

		n = lws_genecdsa_hash_sign_jws(&ecdsactx, digest,
					       jose->alg->hash_type,
					       jose->alg->keybits_fixed,
					       (uint8_t *)buf, m);
		lws_genec_destroy(&ecdsactx);
		if (n < 0) {
			lws_free(buf);
			lwsl_notice("%s: lws_genecdsa_hash_sign_jws fail\n",
					__func__);
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
}

/*
 * Flattened JWS JSON:
 *
 *  {
 *    "payload":   "<payload contents>",
 *    "protected": "<integrity-protected header contents>",
 *    "header":    <non-integrity-protected header contents>,
 *    "signature": "<signature contents>"
 *   }
 */

int
lws_jws_write_flattened_json(struct lws_jws *jws, char *flattened, size_t len)
{
	size_t n = 0;

	if (len < 1)
		return 1;

	n += lws_snprintf(flattened + n, len - n , "{\"payload\": \"");
	lws_strnncpy(flattened + n, jws->map_b64.buf[LJWS_PYLD],
			jws->map_b64.len[LJWS_PYLD], len - n);
	n += strlen(flattened + n);

	n += lws_snprintf(flattened + n, len - n , "\",\n \"protected\": \"");
	lws_strnncpy(flattened + n, jws->map_b64.buf[LJWS_JOSE],
			jws->map_b64.len[LJWS_JOSE], len - n);
	n += strlen(flattened + n);

	if (jws->map_b64.buf[LJWS_UHDR]) {
		n += lws_snprintf(flattened + n, len - n , "\",\n \"header\": ");
		lws_strnncpy(flattened + n, jws->map_b64.buf[LJWS_UHDR],
				jws->map_b64.len[LJWS_UHDR], len - n);
		n += strlen(flattened + n);
	}

	n += lws_snprintf(flattened + n, len - n , "\",\n \"signature\": \"");
	lws_strnncpy(flattened + n, jws->map_b64.buf[LJWS_SIG],
			jws->map_b64.len[LJWS_SIG], len - n);
	n += strlen(flattened + n);

	n += lws_snprintf(flattened + n, len - n , "\"}\n");

	return (n >= len - 1);
}

int
lws_jws_write_compact(struct lws_jws *jws, char *compact, size_t len)
{
	size_t n = 0;

	if (len < 1)
		return 1;

	lws_strnncpy(compact + n, jws->map_b64.buf[LJWS_JOSE],
		     jws->map_b64.len[LJWS_JOSE], len - n);
	n += strlen(compact + n);
	lws_strnncpy(compact + n, jws->map_b64.buf[LJWS_PYLD],
		     jws->map_b64.len[LJWS_PYLD], len - n);
	n += strlen(compact + n);
	lws_strnncpy(compact + n, jws->map_b64.buf[LJWS_SIG],
		     jws->map_b64.len[LJWS_SIG], len - n);
	n += strlen(compact + n);

	return n >= len - 1;
}
