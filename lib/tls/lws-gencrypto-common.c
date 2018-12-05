/*
 * libwebsockets - generic crypto hiding the backend - common parts
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

/*
 * Signing algorithms
 *
 * These came from RFC7518 (JSON Web Algorithms) Section 3
 */

static const struct lws_jose_jwe_alg lws_gencrypto_jws_alg_map[] = {
	{	/* optional */
		LWS_GENHASH_TYPE_UNKNOWN,
		LWS_GENHMAC_TYPE_SHA256,
		LWS_JOSE_ENCTYPE_NONE,
		LWS_JOSE_ENCTYPE_NONE,
		"none", NULL
	},
	{	/* required */
		LWS_GENHASH_TYPE_UNKNOWN,
		LWS_GENHMAC_TYPE_SHA256,
		LWS_JOSE_ENCTYPE_NONE,
		LWS_JOSE_ENCTYPE_NONE,
		"HS256", NULL
	},
	{	/* optional */
		LWS_GENHASH_TYPE_UNKNOWN,
		LWS_GENHMAC_TYPE_SHA384,
		LWS_JOSE_ENCTYPE_NONE,
		LWS_JOSE_ENCTYPE_NONE,
		"HS384", NULL
	},
	{	/* optional */
		LWS_GENHASH_TYPE_UNKNOWN,
		LWS_GENHMAC_TYPE_SHA512,
		LWS_JOSE_ENCTYPE_NONE,
		LWS_JOSE_ENCTYPE_NONE,
		"HS512", NULL
	},

	{	/* recommended */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5,
		LWS_JOSE_ENCTYPE_NONE,
		"RS256", NULL
	},
	{	/* optional */
		LWS_GENHASH_TYPE_SHA384,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5,
		LWS_JOSE_ENCTYPE_NONE,
		"RS384", NULL
	},
	{	/* optional */
		LWS_GENHASH_TYPE_SHA512,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5,
		LWS_JOSE_ENCTYPE_NONE,
		"RS512", NULL
	},

	{	/* Recommended+ */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_ECDSA,
		LWS_JOSE_ENCTYPE_NONE,
		"ES256", "P-256"
	},
	{	/* optional */
		LWS_GENHASH_TYPE_SHA384,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_ECDSA,
		LWS_JOSE_ENCTYPE_NONE,
		"ES384", "P-384"
	},
	{	/* optional */
		LWS_GENHASH_TYPE_SHA512,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_ECDSA,
		LWS_JOSE_ENCTYPE_NONE,
		"ES512", "P-521"
	},

	{	/* optional */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS,
		LWS_JOSE_ENCTYPE_NONE,
		"PS256", NULL
	},
	{	/* optional */
		LWS_GENHASH_TYPE_SHA384,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS,
		LWS_JOSE_ENCTYPE_NONE,
		"PS384", NULL
	},
	{	/* optional */
		LWS_GENHASH_TYPE_SHA512,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS,
		LWS_JOSE_ENCTYPE_NONE,
		"PS512", NULL
	},
};

static const struct lws_jose_jwe_alg lws_gencrypto_jwe_alg_map[] = {
	{	/* recommended- */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5,
		LWS_JOSE_ENCTYPE_NONE,
		"RSA1_5", NULL
	},
	{	/* recommended+ */
		LWS_GENHASH_TYPE_SHA1,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP,
		LWS_JOSE_ENCTYPE_NONE,
		"RSA-OAEP", NULL
	},

	{	/* recommended */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP,
		LWS_JOSE_ENCTYPE_NONE,
		"A128KW", NULL
	},
	{	/* recommended */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP,
		LWS_JOSE_ENCTYPE_NONE,
		"A256KW", NULL
	},

	{	/* recommended */
		LWS_GENHASH_TYPE_UNKNOWN,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_NONE,
		LWS_JOSE_ENCTYPE_AES_GCM,
		"dir", NULL
	},

	{	/* recommended+ */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP,
		LWS_JOSE_ENCTYPE_NONE,
		"ECDH-ES", NULL
	},
	{	/* recommended */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP,
		LWS_JOSE_ENCTYPE_NONE,
		"ECDH-ES+A128KW", NULL
	},
	{	/* recommended */
		LWS_GENHASH_TYPE_SHA256,
		LWS_GENHMAC_TYPE_UNKNOWN,
		LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP,
		LWS_JOSE_ENCTYPE_NONE,
		"ECDH-ES+A256KW", NULL
	},

	/* list terminator */
	{ 0, 0, 0, 0, NULL, NULL }
};


static const struct lws_jose_jwe_alg lws_gencrypto_jwe_enc_map[] = {
	/*
	 * It uses the HMAC message authentication code [RFC2104] with the
	 * SHA-256 hash function [SHS] to provide message authentication, with
	 * the HMAC output truncated to 128 bits, corresponding to the
	 * HMAC-SHA-256-128 algorithm defined in [RFC4868].  For encryption, it
	 * uses AES in the CBC mode of operation as defined in Section 6.2 of
	 * [NIST.800-38A], with PKCS #7 padding and a 128-bit IV value.
	 *
	 * The AES_CBC_HMAC_SHA2 parameters specific to AES_128_CBC_HMAC_SHA_256
	 * are:
	 *
	 * The input key K is 32 octets long.
	 *       ENC_KEY_LEN is 16 octets.
	 *       MAC_KEY_LEN is 16 octets.
	 *       The SHA-256 hash algorithm is used for the HMAC.
	 *       The HMAC-SHA-256 output is truncated to T_LEN=16 octets, by
	 *       stripping off the final 16 octets.
	 */
	{	/* required */
		LWS_GENHASH_TYPE_UNKNOWN,
		LWS_GENHMAC_TYPE_SHA256,
		LWS_JOSE_ENCTYPE_NONE,
		LWS_JOSE_ENCTYPE_AES_CBC,
		"A128CBC-HS256", NULL
	},
};

LWS_VISIBLE int
lws_gencrypto_jws_alg_to_definition(const char *alg,
				    const struct lws_jose_jwe_alg **jose)
{
	const struct lws_jose_jwe_alg *a = lws_gencrypto_jws_alg_map;

	while (a->alg) {
		if (!strcmp(alg, a->alg)) {
			*jose = a;

			return 0;
		}
		a++;
	}

	return 1;
}

LWS_VISIBLE int
lws_gencrypto_jwe_alg_to_definition(const char *alg,
				    const struct lws_jose_jwe_alg **jose)
{
	const struct lws_jose_jwe_alg *a = lws_gencrypto_jwe_alg_map;

	while (a->alg) {
		if (!strcmp(alg, a->alg)) {
			*jose = a;

			return 0;
		}
		a++;
	}

	return 1;
}

LWS_VISIBLE int
lws_gencrypto_jwe_enc_to_definition(const char *enc,
				    const struct lws_jose_jwe_alg **jose)
{
	const struct lws_jose_jwe_alg *e = lws_gencrypto_jwe_enc_map;

	while (e->alg) {
		if (!strcmp(enc, e->alg)) {
			*jose = e;

			return 0;
		}
		e++;
	}

	return 1;
}

size_t
lws_genhash_size(enum lws_genhash_types type)
{
	switch(type) {
	case LWS_GENHASH_TYPE_UNKNOWN:
		return 0;
	case LWS_GENHASH_TYPE_SHA1:
		return 20;
	case LWS_GENHASH_TYPE_SHA256:
		return 32;
	case LWS_GENHASH_TYPE_SHA384:
		return 48;
	case LWS_GENHASH_TYPE_SHA512:
		return 64;
	}

	return 0;
}

size_t
lws_genhmac_size(enum lws_genhmac_types type)
{
	switch(type) {
	case LWS_GENHMAC_TYPE_UNKNOWN:
		return 0;
	case LWS_GENHMAC_TYPE_SHA256:
		return 32;
	case LWS_GENHMAC_TYPE_SHA384:
		return 48;
	case LWS_GENHMAC_TYPE_SHA512:
		return 64;
	}

	return 0;
}
