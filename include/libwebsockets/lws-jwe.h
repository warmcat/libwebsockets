/*
 * libwebsockets - JSON Web Encryption
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

/**
 * lws_jwe_create_packet() - add b64 sig to b64 hdr + payload
 *
 * \param jwk: the struct lws_jwk containing the signing key
 * \param algtype: the signing algorithm
 * \param hash_type: the hashing algorithm
 * \param payload: unencoded payload JSON
 * \param len: length of unencoded payload JSON
 * \param nonce: Nonse string to include in protected header
 * \param out: buffer to take signed packet
 * \param out_len: size of \p out buffer
 * \param conext: lws_context to get random from
 *
 * This creates a "flattened" JWS packet from the jwk and the plaintext
 * payload, and signs it.  The packet is written into \p out.
 *
 * This does the whole packet assembly and signing, calling through to
 * lws_jws_sign_from_b64() as part of the process.
 *
 * Returns the length written to \p out, or -1.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwe_create_packet(struct lws_jwk *jwk,
		      const struct lws_jose_jwe_alg *jose_alg,
		      const char *payload, size_t len, const char *nonce,
		      char *out, size_t out_len, struct lws_context *context);
