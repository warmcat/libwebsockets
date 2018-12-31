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
