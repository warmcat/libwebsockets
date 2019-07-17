/*
 * libwebsockets - generic crypto api hiding the backend
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
 *
 *  lws-gencrypto openssl-specific common code
 */

#include "core/private.h"
#include "tls/openssl/private.h"

/*
 * Care: many openssl apis return 1 for success.  These are translated to the
 * lws convention of 0 for success.
 */

int
lws_gencrypto_openssl_hash_to_NID(enum lws_genhash_types hash_type)
{
	int h = -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_UNKNOWN:
		break;
	case LWS_GENHASH_TYPE_MD5:
		h = NID_md5;
		break;
	case LWS_GENHASH_TYPE_SHA1:
		h = NID_sha1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		h = NID_sha256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		h = NID_sha384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		h = NID_sha512;
		break;
	}

	return h;
}

const EVP_MD *
lws_gencrypto_openssl_hash_to_EVP_MD(enum lws_genhash_types hash_type)
{
	const EVP_MD *h = NULL;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_UNKNOWN:
		break;
	case LWS_GENHASH_TYPE_MD5:
		h = EVP_md5();
		break;
	case LWS_GENHASH_TYPE_SHA1:
		h = EVP_sha1();
		break;
	case LWS_GENHASH_TYPE_SHA256:
		h = EVP_sha256();
		break;
	case LWS_GENHASH_TYPE_SHA384:
		h = EVP_sha384();
		break;
	case LWS_GENHASH_TYPE_SHA512:
		h = EVP_sha512();
		break;
	}

	return h;
}
