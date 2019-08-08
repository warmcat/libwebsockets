/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 *  gencrypto openssl-specific helper declarations
 */

/*
 * one of these per different client context
 * cc_owner is in lws_context.lws_context_tls
 */

struct lws_tls_client_reuse {
	lws_tls_ctx *ssl_client_ctx;
	uint8_t hash[32];
	struct lws_dll2 cc_list;
	int refcount;
	int index;
};

typedef int (*next_proto_cb)(SSL *, const unsigned char **out,
                             unsigned char *outlen, const unsigned char *in,
                             unsigned int inlen, void *arg);

struct lws_x509_cert {
	X509 *cert; /* X509 is opaque, this has to be a pointer */
};

int
lws_gencrypto_openssl_hash_to_NID(enum lws_genhash_types hash_type);

const EVP_MD *
lws_gencrypto_openssl_hash_to_EVP_MD(enum lws_genhash_types hash_type);

#if !defined(LWS_HAVE_BN_bn2binpad)
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
#endif
