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
 *  gencrypto openssl-specific helper declarations
 */

#if !defined(__LWS_PRIVATE_LIB_TLS_OPENSSL_H__)
#define __LWS_PRIVATE_LIB_TLS_OPENSSL_H__


/*
* SSL library compatibility layer:
*
* Different SSL implementations (OpenSSL, BoringSSL, wolfSSL, etc.) require
* different type signatures for their APIs. These macros provide the appropriate
* type definitions and cast operations to ensure correct function signatures
* across all supported SSL backends.
*
* SSL_OPT_TYPE    - Defines the correct type for SSL options based on library
* SSL_SIZE_CAST   - Performs appropriate cast for buffer size parameters
* SSL_DATA_CAST   - Handles buffer pointer type differences between implementations
*/
#if defined(USE_WOLFSSL)
    #define SSL_OPT_TYPE long
#elif defined(LWS_WITH_BORINGSSL) || defined(LWS_WITH_AWSLC)
    #define SSL_OPT_TYPE uint32_t
#elif (OPENSSL_VERSION_NUMBER >= 0x10003000l) && !defined(LIBRESSL_VERSION_NUMBER)
    #define SSL_OPT_TYPE unsigned long
#else
    #define SSL_OPT_TYPE long
#endif

/* Define macro for appropriate size cast by SSL implementation */
#if defined(LWS_WITH_BORINGSSL) || defined(LWS_WITH_AWSLC)
    #define SSL_SIZE_CAST(x) ((size_t)(x))
#else
    #define SSL_SIZE_CAST(x) ((int)(x))
#endif

#if defined(USE_WOLFSSL)
	#define SSL_DATA_CAST(x) ((unsigned char *)(x))
#else
	#define SSL_DATA_CAST(x) (x)
#endif


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

#endif

