/*
 * libwebsockets - JSON Web Encryption support
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
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
 *
 *
 * This supports RFC7516 JSON Web Encryption
 *
 */
#include "core/private.h"
#include "jose/jwe/private.h"

#if 0
static const char * const jwe_complete_tokens[] = {
	"protected",
	"recipients[].header",
	"recipients[].header.alg",
	"recipients[].header.kid",
	"recipients[].encrypted_key",
	"iv",
	"ciphertext",
	"tag",
};

enum enum_jwe_complete_tokens {
	LWS_EJCT_PROTECTED,
	LWS_EJCT_HEADER,
	LWS_EJCT_HEADER_ALG,
	LWS_EJCT_HEADER_KID,
	LWS_EJCT_RECIP_ENC_KEY,
	LWS_EJCT_IV,
	LWS_EJCT_CIPHERTEXT,
	LWS_EJCT_TAG,
};

struct complete_cb_args {
	struct lws_jws_compact_map *map;
	struct lws_jws_compact_map *map_b64;
	char *out;
	int out_len;
};


static int
do_map(struct complete_cb_args *args, int index, char *b64, int len)
{
	return 0;
}

static signed char
lws_jwe_parse_complete_cb(struct lejp_ctx *ctx, char reason)
{
	struct complete_cb_args *args = (struct complete_cb_args *)ctx->user;

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {

	/* strings */

	case LWS_EJCT_PROTECTED:
	case LWS_EJCT_HEADER:
	case LWS_EJCT_HEADER_ALG:
	case LWS_EJCT_HEADER_KID:
	case LWS_EJCT_RECIP_ENC_KEY:
	case LWS_EJCT_IV:
	case LWS_EJCT_CIPHERTEXT:
	case LWS_EJCT_TAG:
	}

	return 0;
}

LWS_VISIBLE int
lws_jws_complete_decode(const char *json_in, int len,
			struct lws_jws_compact_map *map,
			struct lws_jws_compact_map *map_b64, char *out,
			int out_len)
{

	struct complete_cb_args args;
	struct lejp_ctx jctx;
	int blocks, n, m = 0;

	if (!map_b64)
		map_b64 = map;

	memset(map_b64, 0, sizeof(*map_b64));
	memset(map, 0, sizeof(*map));

	args.map = map;
	args.map_b64 = map_b64;
	args.out = out;
	args.out_len = out_len;

	lejp_construct(&jctx, lws_jwe_parse_complete_cb, &args,
		       jwe_complete_tokens,
		       LWS_ARRAY_SIZE(jwe_complete_tokens));

	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)json_in, len);
	lejp_destruct(&jctx);
}
#endif

static uint8_t *
be32(uint32_t i, uint32_t *p32)
{
	uint8_t *p = (uint8_t *)p32;

	*p++ = (i >> 24) & 0xff;
	*p++ = (i >> 16) & 0xff;
	*p++ = (i >> 8) & 0xff;
	*p++ = i & 0xff;

	return (uint8_t *)p32;
}

/*
 * The key derivation process derives the agreed-upon key from the
 * shared secret Z established through the ECDH algorithm, per
 * Section 6.2.2.2 of [NIST.800-56A].
 *
 * out must be prepared to take at least 32 bytes or the encrypted key size,
 * whichever is larger.
 */

int
lws_jwa_concat_kdf(struct lws_jose *jose, struct lws_jws *jws, int direct,
		   uint8_t *out, const uint8_t *shared_secret, int sslen)
{
	int hlen = lws_genhash_size(LWS_GENHASH_TYPE_SHA256), aidlen;
	struct lws_genhash_ctx hash_ctx;
	uint32_t ctr = 1, t;
	const char *aid;

	/*
	 * Hash
	 *
	 * AlgorithmID || PartyUInfo || PartyVInfo
	 * 	{|| SuppPubInfo }{|| SuppPrivInfo }
	 *
	 * AlgorithmID
	 *
	 * The AlgorithmID value is of the form Datalen || Data, where Data
	 * is a variable-length string of zero or more octets, and Datalen is
	 * a fixed-length, big-endian 32-bit counter that indicates the
	 * length (in octets) of Data.  In the Direct Key Agreement case,
	 * Data is set to the octets of the ASCII representation of the "enc"
	 * Header Parameter value.  In the Key Agreement with Key Wrapping
	 * case, Data is set to the octets of the ASCII representation of the
	 * "alg" (algorithm) Header Parameter value.
	 */

	aid = direct ? jose->enc_alg->alg : jose->alg->alg;
	aidlen = strlen(aid);

	/*
	 *   PartyUInfo (PartyVInfo is the same deal)
	 *
	 *    The PartyUInfo value is of the form Datalen || Data, where Data is
	 *    a variable-length string of zero or more octets, and Datalen is a
	 *    fixed-length, big-endian 32-bit counter that indicates the length
	 *    (in octets) of Data.  If an "apu" (agreement PartyUInfo) Header
	 *    Parameter is present, Data is set to the result of base64url
	 *    decoding the "apu" value and Datalen is set to the number of
	 *    octets in Data.  Otherwise, Datalen is set to 0 and Data is set to
	 *    the empty octet sequence
	 *
	 *   SuppPubInfo
	 *
	 *    This is set to the keydatalen represented as a 32-bit big-endian
	 *    integer.
	 *
	 *   keydatalen
	 *
	 *    This is set to the number of bits in the desired output key.  For
	 *    "ECDH-ES", this is length of the key used by the "enc" algorithm.
	 *    For "ECDH-ES+A128KW", "ECDH-ES+A192KW", and "ECDH-ES+A256KW", this
	 *    is 128, 192, and 256, respectively.
	 *
	 *    Compute Hash i = H(counter || Z || OtherInfo).
	 *
	 *    We must iteratively hash over key material that's larger than
	 *    one hash output size (256b for SHA-256)
	 */

	while (ctr <= (uint32_t)(jose->enc_alg->keybits_fixed / hlen)) {

		/*
		 * Key derivation is performed using the Concat KDF, as defined
		 * in Section 5.8.1 of [NIST.800-56A], where the Digest Method
		 * is SHA-256.
		 */

		if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256))
			return -1;

		if (/* counter */
		    lws_genhash_update(&hash_ctx, be32(ctr++, &t), 4) ||
		    /* Z */
		    lws_genhash_update(&hash_ctx, shared_secret, sslen) ||
		    /* other info */
		    lws_genhash_update(&hash_ctx, be32(strlen(aid), &t), 4) ||
		    lws_genhash_update(&hash_ctx, aid, aidlen) ||
		    lws_genhash_update(&hash_ctx,
				       be32(jose->e[LJJHI_APU].len, &t), 4) ||
		    lws_genhash_update(&hash_ctx, jose->e[LJJHI_APU].buf,
						  jose->e[LJJHI_APU].len) ||
		    lws_genhash_update(&hash_ctx,
				       be32(jose->e[LJJHI_APV].len, &t), 4) ||
		    lws_genhash_update(&hash_ctx, jose->e[LJJHI_APV].buf,
						  jose->e[LJJHI_APV].len) ||
		    lws_genhash_update(&hash_ctx,
				       be32(jose->enc_alg->keybits_fixed, &t),
					    4) ||
		    lws_genhash_destroy(&hash_ctx, out)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}

		out += hlen;
	}

	return 0;
}

LWS_VISIBLE void
lws_jwe_be64(uint64_t c, uint8_t *p8)
{
	int n;

	for (n = 56; n >= 0; n -= 8)
		*p8++ = (uint8_t)((c >> n) & 0xff);
}

LWS_VISIBLE int
lws_jwe_auth_and_decrypt(struct lws_jose *jose, struct lws_jws *jws)
{
	int valid_aescbc_hmac, valid_aesgcm;
	char temp[512];
	int temp_len = sizeof(temp);

	if (lws_jwe_parse_jose(jose, jws->map.buf[LJWS_JOSE],
			       jws->map.len[LJWS_JOSE],
			       temp, &temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);
		return -1;
	}

	valid_aescbc_hmac = jose->enc_alg &&
		jose->enc_alg->algtype_crypto == LWS_JOSE_ENCTYPE_AES_CBC &&
		(jose->enc_alg->hmac_type == LWS_GENHMAC_TYPE_SHA256 ||
		 jose->enc_alg->hmac_type == LWS_GENHMAC_TYPE_SHA384 ||
		 jose->enc_alg->hmac_type == LWS_GENHMAC_TYPE_SHA512);

	valid_aesgcm = jose->enc_alg &&
		jose->enc_alg->algtype_crypto == LWS_JOSE_ENCTYPE_AES_GCM;

	/* RSA + AESCBC */

	if ((!strcmp(jose->alg->alg,     "RSA1_5") ||
	     !strcmp(jose->alg->alg,   "RSA-OAEP")) && valid_aescbc_hmac)
		return lws_jwe_auth_and_decrypt_rsa_aes_cbc_hs(jose, jws);

	/* RSA + AESGCM */

	if ((!strcmp(jose->alg->alg,     "RSA1_5") ||
	     !strcmp(jose->alg->alg,   "RSA-OAEP")) && valid_aesgcm)
		return lws_jwe_auth_and_decrypt_rsa_aes_gcm(jose, jws);

	/* AESKW */

	if ((!strcmp(jose->alg->alg,    "A128KW") ||
	     !strcmp(jose->alg->alg,    "A192KW") ||
	     !strcmp(jose->alg->alg,    "A256KW")) && valid_aescbc_hmac)
		return lws_jwe_auth_and_decrypt_aeskw_cbc_hs(jose, jws);

	lwsl_err("%s: unknown cipher alg combo %s / %s\n", __func__,
			jose->alg->alg, jose->enc_alg ?
					jose->enc_alg->alg : "NULL");

	return -1;
}
LWS_VISIBLE int
lws_jwe_encrypt(struct lws_jose *jose, struct lws_jws *jws,
		char *temp, int *temp_len)
{
	int valid_aescbc_hmac, valid_aesgcm;

	valid_aesgcm = jose->enc_alg &&
		jose->enc_alg->algtype_crypto == LWS_JOSE_ENCTYPE_AES_GCM;

	if (lws_jwe_parse_jose(jose, jws->map.buf[LJWS_JOSE],
			       jws->map.len[LJWS_JOSE], temp, temp_len) < 0) {
		lwsl_err("%s: JOSE parse failed\n", __func__);
		return -1;
	}

	valid_aescbc_hmac = jose->enc_alg &&
		jose->enc_alg->algtype_crypto == LWS_JOSE_ENCTYPE_AES_CBC &&
		(jose->enc_alg->hmac_type == LWS_GENHMAC_TYPE_SHA256 ||
		 jose->enc_alg->hmac_type == LWS_GENHMAC_TYPE_SHA384 ||
		 jose->enc_alg->hmac_type == LWS_GENHMAC_TYPE_SHA512);

	/* RSA + AESCBC */

	if ((!strcmp(jose->alg->alg,     "RSA1_5") ||
	     !strcmp(jose->alg->alg,   "RSA-OAEP")) && valid_aescbc_hmac)
		return lws_jwe_encrypt_rsa_aes_cbc_hs(jose, jws, temp, temp_len);

	/* RSA + AESGCM */

	if ((!strcmp(jose->alg->alg,     "RSA1_5") ||
	     !strcmp(jose->alg->alg,   "RSA-OAEP")) && valid_aesgcm)
		return lws_jwe_encrypt_rsa_aes_gcm(jose, jws, temp, temp_len);

	/* AESKW */

	if ((!strcmp(jose->alg->alg,    "A128KW") ||
	     !strcmp(jose->alg->alg,    "A192KW") ||
	     !strcmp(jose->alg->alg,    "A256KW")) && valid_aescbc_hmac)
		return lws_jwe_encrypt_aeskw_cbc_hs(jose, jws, temp, temp_len);

	lwsl_err("%s: unknown cipher alg combo %s / %s\n", __func__,
			jose->alg->alg, jose->enc_alg ?
					jose->enc_alg->alg : "NULL");

	return -1;
}

/*
 * JWE Compact Serialization consists of
 *
 *     BASE64URL(UTF8(JWE Protected Header)) || '.' ||
 *     BASE64URL(JWE Encrypted Key)	     || '.' ||
 *     BASE64URL(JWE Initialization Vector)  || '.' ||
 *     BASE64URL(JWE Ciphertext)	     || '.' ||
 *     BASE64URL(JWE Authentication Tag)
 */

LWS_VISIBLE int
lws_jwe_write_compact(struct lws_jose *jose, struct lws_jws *jws,
		      char *out, size_t out_len)
{
	size_t orig = out_len;
	int n;

	n = lws_jws_base64_enc(jws->map.buf[LJWS_JOSE],
			       jws->map.len[LJWS_JOSE], out, out_len);
	if (n < 0 || (int)out_len == n) {
		lwsl_info("%s: unable to encode JOSE\n", __func__);
		return n;
	}

	out += n;
	*out++ = '.';
	out_len -= n + 1;

	n = lws_jws_base64_enc(jws->map.buf[LJWE_EKEY],
			       jws->map.len[LJWE_EKEY], out, out_len);
	if (n < 0 || (int)out_len == n) {
		lwsl_info("%s: unable to encode EKEY\n", __func__);
		return n;
	}

	out += n;
	*out++ = '.';
	out_len -= n + 1;
	n = lws_jws_base64_enc(jws->map.buf[LJWE_IV],
			       jws->map.len[LJWE_IV], out, out_len);
	if (n < 0 || (int)out_len == n) {
		lwsl_info("%s: unable to encode IV\n", __func__);
		return n;
	}

	out += n;
	*out++ = '.';
	out_len -= n + 1;

	n = lws_jws_base64_enc(jws->map.buf[LJWE_CTXT],
			       jws->map.len[LJWE_CTXT], out, out_len);
	if (n < 0 || (int)out_len == n) {
		lwsl_info("%s: unable to encode CTXT\n", __func__);
		return n;
	}

	out += n;
	*out++ = '.';
	out_len -= n + 1;
	n = lws_jws_base64_enc(jws->map.buf[LJWE_ATAG],
			       jws->map.len[LJWE_ATAG], out, out_len);
	if (n < 0 || (int)out_len == n) {
		lwsl_info("%s: unable to encode ATAG\n", __func__);
		return n;
	}

	out += n;
	*out++ = '\0';
	out_len -= n;

	return orig - out_len;
}

LWS_VISIBLE int
lws_jwe_create_packet(struct lws_jose *jose, struct lws_jwk *jwk,
		      const char *payload, size_t len,
		      const char *nonce, char *out, size_t out_len,
		      struct lws_context *context)
{
	char *buf, *start, *p, *end, *p1, *end1;
	struct lws_jws jws;
	int n;

	lws_jws_init(&jws, jwk, context);

	/*
	 * This buffer is local to the function, the actual output is prepared
	 * into vhd->buf.  Only the plaintext protected header
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

	if (!jose->alg || !jose->alg->alg)
		goto bail;

	p += lws_snprintf(p, end - p, "{\"alg\":\"%s\",\"jwk\":",
			  jose->alg->alg);
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
	jws.map_b64.buf[LJWS_JOSE] = p1;
	n = lws_jws_base64_enc(start, p - start, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode protected\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_JOSE] = n;
	p1 += n;

	p1 += lws_snprintf(p1, end1 - p1, "\",\"payload\":\"");
	jws.map_b64.buf[LJWS_PYLD] = p1;
	n = lws_jws_base64_enc(payload, len, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode payload\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_PYLD] = n;
	p1 += n;

	p1 += lws_snprintf(p1, end1 - p1, "\",\"header\":\"");
	jws.map_b64.buf[LJWS_UHDR] = p1;
	n = lws_jws_base64_enc(payload, len, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode payload\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_UHDR] = n;

	p1 += n;
	p1 += lws_snprintf(p1, end1 - p1, "\",\"signature\":\"");

	/*
	 * taking the b64 protected header and the b64 payload, sign them
	 * and place the signature into the packet
	 */
	n = lws_jws_sign_from_b64(jose, &jws, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("sig gen failed\n");

		goto bail;
	}
	jws.map_b64.buf[LJWS_SIG] = p1;
	jws.map_b64.len[LJWS_SIG] = n;

	p1 += n;
	p1 += lws_snprintf(p1, end1 - p1, "\"}");

	free(buf);

	return p1 - out;

bail:
	lws_jws_destroy(&jws);
	free(buf);

	return -1;
}
