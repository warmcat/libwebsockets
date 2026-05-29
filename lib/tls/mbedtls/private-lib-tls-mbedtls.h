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
 *  gencrypto mbedtls-specific helper declarations
 */

#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <errno.h>

#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
#include <psa/crypto.h>
#endif

struct lws_x509_cert {
	mbedtls_x509_crt cert; /* has a .next for linked-list / chain */
};

typedef struct lws_mbedtls_x509_authority
{
	mbedtls_x509_buf	keyIdentifier;
	mbedtls_x509_sequence 	authorityCertIssuer;
	mbedtls_x509_buf	authorityCertSerialNumber;
	mbedtls_x509_buf	raw;
}
lws_mbedtls_x509_authority;


mbedtls_md_type_t
lws_gencrypto_mbedtls_hash_to_MD_TYPE(enum lws_genhash_types hash_type);

int
lws_gencrypto_mbedtls_rngf(void *context, unsigned char *buf, size_t len);

int
lws_tls_session_new_mbedtls(struct lws *wsi);

int
lws_tls_mbedtls_cert_info(mbedtls_x509_crt *x509, enum lws_tls_cert_info type,
			  union lws_tls_cert_info_results *buf, size_t len);

int
lws_x509_get_crt_ext(mbedtls_x509_crt *crt, mbedtls_x509_buf *skid,
		     lws_mbedtls_x509_authority *akid);

#if (MBEDTLS_VERSION_MAJOR == 3) && (MBEDTLS_VERSION_MINOR >= 5)
	int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
						  mbedtls_x509_name *cur);
#endif

static inline int
lws_mbedtls_global_crypto_init(void)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	psa_status_t ps;

	ps = psa_crypto_init();

	return ps == PSA_SUCCESS ? 0 : (int)ps;
#else
	return 0;
#endif
}

static inline int
lws_mbedtls_random(void *rng_ctx, unsigned char *buf, size_t len)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	(void)rng_ctx;

	return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
#else
	return mbedtls_ctr_drbg_random(rng_ctx, buf, len);
#endif
}

static inline int
lws_mbedtls_pk_parse_key(mbedtls_pk_context *pk, const unsigned char *key,
			 const size_t key_len, const unsigned char *pwd,
			 const size_t pwd_len, void *rng_ctx)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	(void)rng_ctx;

	return mbedtls_pk_parse_key(pk, key, key_len, pwd, pwd_len);
#elif defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
	return mbedtls_pk_parse_key(pk, key, key_len, pwd, pwd_len,
				    mbedtls_ctr_drbg_random, rng_ctx);
#else
	(void)rng_ctx;

	return mbedtls_pk_parse_key(pk, key, key_len, pwd, pwd_len);
#endif
}

static inline int
lws_mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *cookie_ctx, void *rng_ctx)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	(void)rng_ctx;

	return mbedtls_ssl_cookie_setup(cookie_ctx);
#else
	return mbedtls_ssl_cookie_setup(cookie_ctx, mbedtls_ctr_drbg_random,
				       rng_ctx);
#endif
}

static inline void
lws_mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf, void *rng_ctx)
{
#if !defined(MBEDTLS_VERSION_MAJOR) || MBEDTLS_VERSION_MAJOR < 4
	mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, rng_ctx);
#else
	(void)conf;
	(void)rng_ctx;
#endif
}

static inline int
lws_mbedtls_x509write_crt_der(mbedtls_x509write_cert *crt, unsigned char *buf,
			      const size_t len, void *rng_ctx)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	(void)rng_ctx;

	return mbedtls_x509write_crt_der(crt, buf, len);
#else
	return mbedtls_x509write_crt_der(crt, buf, len,
					 mbedtls_ctr_drbg_random, rng_ctx);
#endif
}

static inline int
lws_mbedtls_x509write_csr_der(mbedtls_x509write_csr *csr, unsigned char *buf,
			      const size_t len, void *rng_ctx)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	(void)rng_ctx;

	return mbedtls_x509write_csr_der(csr, buf, len);
#else
	return mbedtls_x509write_csr_der(csr, buf, len,
					 mbedtls_ctr_drbg_random, rng_ctx);
#endif
}

