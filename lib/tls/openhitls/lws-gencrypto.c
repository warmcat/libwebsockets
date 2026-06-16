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
 *
 *  lws-gencrypto common code
 */

#include "private-lib-core.h"
#include "private.h"

CRYPT_MD_AlgId
lws_genhash_type_to_hitls_md_id(enum lws_genhash_types hash_type)
{
	switch (hash_type) {
	case LWS_GENHASH_TYPE_MD5:
		return CRYPT_MD_MD5;
	case LWS_GENHASH_TYPE_SHA1:
		return CRYPT_MD_SHA1;
	case LWS_GENHASH_TYPE_SHA256:
		return CRYPT_MD_SHA256;
	case LWS_GENHASH_TYPE_SHA384:
		return CRYPT_MD_SHA384;
	case LWS_GENHASH_TYPE_SHA512:
		return CRYPT_MD_SHA512;
	case LWS_GENHASH_TYPE_UNKNOWN:
		return CRYPT_MD_SHA1;
	default:
		return CRYPT_MD_MAX;
	}
}

CRYPT_CIPHER_AlgId
lws_genaes_mode_to_hitls_cipher_id(enum enum_aes_modes mode, size_t keylen)
{
	size_t keybits = keylen * 8;

	/* LWS_GAESM_KW is JOSE RFC3394 key wrap (no padding). */
	switch (keybits) {
	case 128:
		switch (mode) {
		case LWS_GAESM_CBC:
			return CRYPT_CIPHER_AES128_CBC;
		case LWS_GAESM_CFB128:
		case LWS_GAESM_CFB8:
			return CRYPT_CIPHER_AES128_CFB;
		case LWS_GAESM_CTR:
			return CRYPT_CIPHER_AES128_CTR;
		case LWS_GAESM_ECB:
			return CRYPT_CIPHER_AES128_ECB;
		case LWS_GAESM_OFB:
			return CRYPT_CIPHER_AES128_OFB;
		case LWS_GAESM_GCM:
			return CRYPT_CIPHER_AES128_GCM;
		case LWS_GAESM_KW:
			return CRYPT_CIPHER_AES128_WRAP_NOPAD;
		default:
			return CRYPT_CIPHER_MAX;
		}
	case 192:
		switch (mode) {
		case LWS_GAESM_CBC:
			return CRYPT_CIPHER_AES192_CBC;
		case LWS_GAESM_CFB128:
		case LWS_GAESM_CFB8:
			return CRYPT_CIPHER_AES192_CFB;
		case LWS_GAESM_CTR:
			return CRYPT_CIPHER_AES192_CTR;
		case LWS_GAESM_ECB:
			return CRYPT_CIPHER_AES192_ECB;
		case LWS_GAESM_OFB:
			return CRYPT_CIPHER_AES192_OFB;
		case LWS_GAESM_GCM:
			return CRYPT_CIPHER_AES192_GCM;
		case LWS_GAESM_KW:
			return CRYPT_CIPHER_AES192_WRAP_NOPAD;
		default:
			return CRYPT_CIPHER_MAX;
		}
	case 256:
		switch (mode) {
		case LWS_GAESM_CBC:
			return CRYPT_CIPHER_AES256_CBC;
		case LWS_GAESM_CFB128:
		case LWS_GAESM_CFB8:
			return CRYPT_CIPHER_AES256_CFB;
		case LWS_GAESM_CTR:
			return CRYPT_CIPHER_AES256_CTR;
		case LWS_GAESM_ECB:
			return CRYPT_CIPHER_AES256_ECB;
		case LWS_GAESM_OFB:
			return CRYPT_CIPHER_AES256_OFB;
		case LWS_GAESM_XTS:
			return CRYPT_CIPHER_AES128_XTS;
		case LWS_GAESM_GCM:
			return CRYPT_CIPHER_AES256_GCM;
		case LWS_GAESM_KW:
			return CRYPT_CIPHER_AES256_WRAP_NOPAD;
		default:
			return CRYPT_CIPHER_MAX;
		}
	case 512:
		if (mode == LWS_GAESM_XTS)
			return CRYPT_CIPHER_AES256_XTS;
		return CRYPT_CIPHER_MAX;
	default:
		return CRYPT_CIPHER_MAX;
	}
}
