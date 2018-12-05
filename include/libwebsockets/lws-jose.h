/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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
 * included from libwebsockets.h
 */

enum lws_jws_jose_hdr_indexes {
	LJJHI_ALG,	/* REQUIRED */
	LJJHI_JKU,	/* Optional: string */
	LJJHI_JWK,	/* Optional: jwk JSON object: public key: */
	LJJHI_KID,	/* Optional: string */
	LJJHI_X5U,	/* Optional: string: url of public key cert / chain */
	LJJHI_X5C,	/* Optional: base64 (NOT -url): actual cert */
	LJJHI_X5T,	/* Optional: base64url: SHA-1 of actual cert */
	LJJHI_X5T_S256, /* Optional: base64url: SHA-256 of actual cert */
	LJJHI_TYP,	/* Optional: string: media type */
	LJJHI_CTY,	/* Optional: string: content media type */
	LJJHI_CRIT,	/* Optional for send, REQUIRED: array of strings:
			 * mustn't contain standardized strings or null set */

	LJJHI_ENC,	/* JWE only: Optional: string */
	LJJHI_ZIP,	/* JWE only: Optional: string ("DEF" = deflate) */

	LJJHI_EPK,	/* Additional arg for JWE ECDH:  ephemeral public key */
	LJJHI_APU,	/* Additional arg for JWE ECDH:  base64url */
	LJJHI_APV,	/* Additional arg for JWE ECDH:  base64url */
	LJJHI_IV,	/* Additional arg for JWE AES:   base64url */
	LJJHI_TAG,	/* Additional arg for JWE AES:   base64url */
	LJJHI_P2S,	/* Additional arg for JWE PBES2: base64url: salt */
	LJJHI_P2C,	/* Additional arg for JWE PBES2: integer: count */

	LWS_COUNT_JOSE_HDR_ELEMENTS
};

struct lws_jose {
	/* jose header elements */
	struct lws_gencrypto_keyelem e[LWS_COUNT_JOSE_HDR_ELEMENTS];
};

enum lws_jose_algtype {
	LWS_JOSE_ENCTYPE_NONE,

	LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5,
	LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP,
	LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS,

	LWS_JOSE_ENCTYPE_ECDSA,

	LWS_JOSE_ENCTYPE_AES_CBC,
	LWS_JOSE_ENCTYPE_AES_CFB128,
	LWS_JOSE_ENCTYPE_AES_CFB8,
	LWS_JOSE_ENCTYPE_AES_CTR,
	LWS_JOSE_ENCTYPE_AES_ECB,
	LWS_JOSE_ENCTYPE_AES_OFB,
	LWS_JOSE_ENCTYPE_AES_XTS,	/* care... requires double-length key */
	LWS_JOSE_ENCTYPE_AES_GCM,
};

struct lws_jose_jwe_alg {
	enum lws_genhash_types hash_type;
	enum lws_genhmac_types hmac_type;
	enum lws_jose_algtype algtype_signing; /* the signing cipher */
	enum lws_jose_algtype algtype_crypto; /* the encryption cipher */
	const char *alg; /* the JWA enc alg name, eg "ES512" */
	const char *curve_name; /* NULL, or, eg, "P-256" */
};

LWS_VISIBLE LWS_EXTERN int
lws_gencrypto_jws_alg_to_definition(const char *alg,
				    const struct lws_jose_jwe_alg **jose);

LWS_VISIBLE LWS_EXTERN int
lws_gencrypto_jwe_alg_to_definition(const char *alg,
				    const struct lws_jose_jwe_alg **jose);

LWS_VISIBLE LWS_EXTERN int
lws_gencrypto_jwe_enc_to_definition(const char *enc,
				    const struct lws_jose_jwe_alg **jose);
