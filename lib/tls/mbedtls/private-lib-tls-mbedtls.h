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

#if defined(LWS_HAVE_MBEDTLS_V4) && !defined(MBEDTLS_ALLOW_PRIVATE_ACCESS)
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif

#include <mbedtls/pk.h>
#if defined(MBEDTLS_PK_HAVE_PRIVATE_HEADER)
#include <mbedtls/private/pk_private.h>
#endif
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#if defined(LWS_HAVE_MBEDTLS_PRIVATE_ECP_H)
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecp.h>
#include <mbedtls/private/ecdsa.h>
#include <mbedtls/private/rsa.h>
#else
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>
#endif
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <errno.h>

#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
#include <psa/crypto.h>
#if !defined(LWS_HAVE_mbedtls_rsa_complete)
#define LWS_HAVE_mbedtls_rsa_complete

static inline int
mbedtls_rsa_complete(mbedtls_rsa_context *ctx)
{
	int ret;
	mbedtls_mpi p1, q1;

	if (!mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(P)) ||
	    !mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(Q)) ||
	    !mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(D)))
		return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

	if (!mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(N))) {
		ret = mbedtls_mpi_mul_mpi(&ctx->MBEDTLS_PRIVATE(N),
					 &ctx->MBEDTLS_PRIVATE(P),
					 &ctx->MBEDTLS_PRIVATE(Q));
		if (ret)
			return ret;
	}

	ctx->MBEDTLS_PRIVATE(len) =
		mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(N));

	mbedtls_mpi_init(&p1);
	mbedtls_mpi_init(&q1);

	ret = mbedtls_mpi_sub_int(&p1, &ctx->MBEDTLS_PRIVATE(P), 1);
	if (ret)
		goto bail;

	ret = mbedtls_mpi_sub_int(&q1, &ctx->MBEDTLS_PRIVATE(Q), 1);
	if (ret)
		goto bail;

	if (!mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(DP))) {
		ret = mbedtls_mpi_mod_mpi(&ctx->MBEDTLS_PRIVATE(DP),
					 &ctx->MBEDTLS_PRIVATE(D), &p1);
		if (ret)
			goto bail;
	}

	if (!mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(DQ))) {
		ret = mbedtls_mpi_mod_mpi(&ctx->MBEDTLS_PRIVATE(DQ),
					 &ctx->MBEDTLS_PRIVATE(D), &q1);
		if (ret)
			goto bail;
	}

	if (!mbedtls_mpi_size(&ctx->MBEDTLS_PRIVATE(QP))) {
		ret = mbedtls_mpi_inv_mod(&ctx->MBEDTLS_PRIVATE(QP),
					 &ctx->MBEDTLS_PRIVATE(Q),
					 &ctx->MBEDTLS_PRIVATE(P));
		if (ret)
			goto bail;
	}

	ret = mbedtls_rsa_check_privkey(ctx);

bail:
	mbedtls_mpi_free(&p1);
	mbedtls_mpi_free(&q1);

	return ret;
}
#endif
#endif

#if defined(LWS_HAVE_MBEDTLS_PRIVATE_ECP_H) && \
	defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4

#if !defined(MBEDTLS_ECDH_OURS)
#define MBEDTLS_ECDH_OURS 0
#endif
#if !defined(MBEDTLS_ECDH_THEIRS)
#define MBEDTLS_ECDH_THEIRS 1
#endif

typedef int mbedtls_ecdh_side;

struct mbedtls_ecdh_context {
	mbedtls_ecp_group MBEDTLS_PRIVATE(grp);
	mbedtls_mpi MBEDTLS_PRIVATE(d);
	mbedtls_ecp_point MBEDTLS_PRIVATE(Q);
	mbedtls_ecp_point MBEDTLS_PRIVATE(Qp);
};

typedef struct mbedtls_ecdh_context mbedtls_ecdh_context;

static inline void
mbedtls_ecdh_init(mbedtls_ecdh_context *ctx)
{
	mbedtls_ecp_group_init(&ctx->MBEDTLS_PRIVATE(grp));
	mbedtls_mpi_init(&ctx->MBEDTLS_PRIVATE(d));
	mbedtls_ecp_point_init(&ctx->MBEDTLS_PRIVATE(Q));
	mbedtls_ecp_point_init(&ctx->MBEDTLS_PRIVATE(Qp));
}

static inline void
mbedtls_ecdh_free(mbedtls_ecdh_context *ctx)
{
	mbedtls_ecp_group_free(&ctx->MBEDTLS_PRIVATE(grp));
	mbedtls_mpi_free(&ctx->MBEDTLS_PRIVATE(d));
	mbedtls_ecp_point_free(&ctx->MBEDTLS_PRIVATE(Q));
	mbedtls_ecp_point_free(&ctx->MBEDTLS_PRIVATE(Qp));
}

static inline int
mbedtls_ecdh_get_params(mbedtls_ecdh_context *ctx,
			const mbedtls_ecp_keypair *key,
			mbedtls_ecdh_side side)
{
	int ret;

	ret = mbedtls_ecp_group_copy(&ctx->MBEDTLS_PRIVATE(grp),
				     &key->MBEDTLS_PRIVATE(grp));
	if (ret)
		return ret;

	if (side == MBEDTLS_ECDH_OURS) {
		ret = mbedtls_mpi_copy(&ctx->MBEDTLS_PRIVATE(d),
				      &key->MBEDTLS_PRIVATE(d));
		if (ret)
			return ret;

		return mbedtls_ecp_copy(&ctx->MBEDTLS_PRIVATE(Q),
					&key->MBEDTLS_PRIVATE(Q));
	}

	return mbedtls_ecp_copy(&ctx->MBEDTLS_PRIVATE(Qp),
				&key->MBEDTLS_PRIVATE(Q));
}

static inline int
mbedtls_ecdh_calc_secret(mbedtls_ecdh_context *ctx, size_t *olen,
			 unsigned char *buf, size_t buflen,
			 int (*f_rng)(void *, unsigned char *, size_t),
			 void *p_rng)
{
	mbedtls_ecp_point shared;
	size_t need;
	int ret;

	mbedtls_ecp_point_init(&shared);

	ret = mbedtls_ecp_mul_restartable(&ctx->MBEDTLS_PRIVATE(grp), &shared,
					  &ctx->MBEDTLS_PRIVATE(d),
					  &ctx->MBEDTLS_PRIVATE(Qp),
					  f_rng, p_rng, NULL);
	if (ret)
		goto bail;

	need = mbedtls_mpi_size(&shared.MBEDTLS_PRIVATE(X));
	if (need > buflen) {
		ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
		goto bail;
	}

	ret = mbedtls_mpi_write_binary(&shared.MBEDTLS_PRIVATE(X), buf, need);
	if (!ret && olen)
		*olen = need;

bail:
	mbedtls_ecp_point_free(&shared);

	return ret;
}
#endif

#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
static inline int
mbedtls_rsa_rsassa_pss_sign(mbedtls_rsa_context *ctx,
			    int (*f_rng)(void *, unsigned char *, size_t),
			    void *p_rng, mbedtls_md_type_t md_alg,
			    unsigned int hashlen, const unsigned char *hash,
			    unsigned char *sig)
{
	return mbedtls_rsa_rsassa_pss_sign_ext(ctx, f_rng, p_rng, md_alg,
					      hashlen, hash,
					      MBEDTLS_RSA_SALT_LEN_ANY,
					      sig);
}

static inline int
mbedtls_rsa_rsassa_pss_verify(mbedtls_rsa_context *ctx,
			      mbedtls_md_type_t md_alg,
			      unsigned int hashlen,
			      const unsigned char *hash,
			      const unsigned char *sig)
{
	mbedtls_md_type_t mgf1_hash_id =
		ctx->MBEDTLS_PRIVATE(hash_id) != MBEDTLS_MD_NONE ?
			(mbedtls_md_type_t)ctx->MBEDTLS_PRIVATE(hash_id) :
			md_alg;

	return mbedtls_rsa_rsassa_pss_verify_ext(ctx, md_alg, hashlen, hash,
						mgf1_hash_id,
						MBEDTLS_RSA_SALT_LEN_ANY,
						sig);
}
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


#if ((MBEDTLS_VERSION_MAJOR == 3) && (MBEDTLS_VERSION_MINOR >= 5)) || \
	((defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4))
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

static inline int
lws_mbedtls_pk_generate_rsa(mbedtls_pk_context *pk, unsigned int bits)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_status_t ps;
	int ret;

	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_EXPORT |
				PSA_KEY_USAGE_SIGN_HASH |
				PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attributes,
			      PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&attributes, bits);

	ps = psa_generate_key(&attributes, &key_id);
	psa_reset_key_attributes(&attributes);
	if (ps != PSA_SUCCESS)
		return (int)ps;

	ret = mbedtls_pk_copy_from_psa(key_id, pk);
	(void)psa_destroy_key(key_id);

	return ret;
#else
	int ret;

	ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (ret)
		return ret;

	return mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), mbedtls_ctr_drbg_random,
				   NULL, bits, 65537);
#endif
}

static inline int
lws_mbedtls_pk_generate_ec(mbedtls_pk_context *pk, mbedtls_ecp_group_id grp_id)
{
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 4
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_ecc_family_t family;
	psa_status_t ps;
	size_t bits;
	int ret;

	switch (grp_id) {
	case MBEDTLS_ECP_DP_SECP256R1:
		family = PSA_ECC_FAMILY_SECP_R1;
		bits = 256;
		break;
	case MBEDTLS_ECP_DP_SECP384R1:
		family = PSA_ECC_FAMILY_SECP_R1;
		bits = 384;
		break;
	case MBEDTLS_ECP_DP_SECP521R1:
		family = PSA_ECC_FAMILY_SECP_R1;
		bits = 521;
		break;
	default:
		return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
	}

	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_EXPORT |
				PSA_KEY_USAGE_SIGN_HASH |
				PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attributes,
			      MBEDTLS_PK_ALG_ECDSA(PSA_ALG_ANY_HASH));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
	psa_set_key_bits(&attributes, bits);

	ps = psa_generate_key(&attributes, &key_id);
	psa_reset_key_attributes(&attributes);
	if (ps != PSA_SUCCESS)
		return (int)ps;

	ret = mbedtls_pk_copy_from_psa(key_id, pk);
	(void)psa_destroy_key(key_id);

	return ret;
#else
	int ret;

	ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (ret)
		return ret;

	return mbedtls_ecp_gen_key(grp_id, mbedtls_pk_ec(*pk),
				   mbedtls_ctr_drbg_random, NULL);
#endif
}

