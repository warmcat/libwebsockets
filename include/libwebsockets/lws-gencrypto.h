/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
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

/*
 * These are gencrypto-level constants... they are used by both JOSE and direct
 * gencrypto code.  However while JWK relies on these, using gencrypto apis has
 * no dependency at all on any JOSE type.
 */

enum lws_gencrypto_kty {
	LWS_GENCRYPTO_KTY_UNKNOWN,

	LWS_GENCRYPTO_KTY_OCT,
	LWS_GENCRYPTO_KTY_RSA,
	LWS_GENCRYPTO_KTY_EC
};

/*
 * Keytypes where the same element name is reused must all agree to put the
 * same-named element at the same e[] index.  It's because when used with jwk,
 * we parse and store in incoming key data, but we may not be informed of the
 * definitive keytype until the end.
 */

enum lws_gencrypto_oct_tok {
	LWS_GENCRYPTO_OCT_KEYEL_K, /* note... same offset as AES K */

	LWS_GENCRYPTO_OCT_KEYEL_COUNT
};

enum lws_gencrypto_rsa_tok {
	LWS_GENCRYPTO_RSA_KEYEL_E,
	LWS_GENCRYPTO_RSA_KEYEL_N,
	LWS_GENCRYPTO_RSA_KEYEL_D, /* note... same offset as EC D */
	LWS_GENCRYPTO_RSA_KEYEL_P,
	LWS_GENCRYPTO_RSA_KEYEL_Q,
	LWS_GENCRYPTO_RSA_KEYEL_DP,
	LWS_GENCRYPTO_RSA_KEYEL_DQ,
	LWS_GENCRYPTO_RSA_KEYEL_QI,

	LWS_GENCRYPTO_RSA_KEYEL_COUNT
};

enum lws_gencrypto_ec_tok {
	LWS_GENCRYPTO_EC_KEYEL_CRV,
	LWS_GENCRYPTO_EC_KEYEL_X,
	/* note... same offset as RSA D */
	LWS_GENCRYPTO_EC_KEYEL_D = LWS_GENCRYPTO_RSA_KEYEL_D,
	LWS_GENCRYPTO_EC_KEYEL_Y,

	LWS_GENCRYPTO_EC_KEYEL_COUNT
};

enum lws_gencrypto_aes_tok {
	/* note... same offset as OCT K */
	LWS_GENCRYPTO_AES_KEYEL_K = LWS_GENCRYPTO_OCT_KEYEL_K,

	LWS_GENCRYPTO_AES_KEYEL_COUNT
};

/* largest number of key elements for any algorithm */
#define LWS_GENCRYPTO_MAX_KEYEL_COUNT LWS_GENCRYPTO_RSA_KEYEL_COUNT

/* this "stretchy" type holds individual key element data in binary form.
 * It's typcially used in an array with the layout mapping the element index to
 * the key element meaning defined by the enums above.  An array of these of
 * length LWS_GENCRYPTO_MAX_KEYEL_COUNT can define key elements for any key
 * type.
 */

struct lws_gencrypto_keyelem {
	uint8_t *buf;
	uint32_t len;
};


/**
 * lws_gencrypto_bits_to_bytes() - returns rounded up bytes needed for bits
 *
 * \param bits
 *
 * Returns the number of bytes needed to store the given number of bits.  If
 * a byte is partially used, the byte count is rounded up.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gencrypto_bits_to_bytes(int bits);

/**
 * lws_base64_size() - returns estimated size of base64 encoding
 *
 * \param bytes
 *
 * Returns a slightly oversize estimate of the size of a base64 encoded version
 * of the given amount of unencoded data.
 */
LWS_VISIBLE LWS_EXTERN int
lws_base64_size(int bytes);
