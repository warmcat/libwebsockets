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
 *  lws_genrsa provides an RSA abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls crypto functions underneath.
 */
#include "private-lib-core.h"
#if !defined(LWS_HAVE_MBEDTLS_V4)
#include "private-lib-tls-mbedtls.h"
#include <mbedtls/rsa.h>

static int mode_map[] = { MBEDTLS_RSA_PKCS_V15, MBEDTLS_RSA_PKCS_V21 };

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	int hash_id;

	if (mode >= LGRSAM_COUNT)
		return -1;

	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENRSA_CTX_CREATED_MARK)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ctx = lws_zalloc(sizeof(*ctx->ctx), "genrsa");
	if (!ctx->ctx)
		return 1;

	ctx->context = context;
	ctx->mode = mode;

	/*
	 * OAEP needs a real md for the MGF1 hash... if the caller has no
	 * preference, use the RFC8017 default of SHA-1.  The mapped md type
	 * is otherwise unusable (-1) for OAEP operations.
	 */

	if (mode == LGRSAM_PKCS1_OAEP_PSS &&
	    oaep_hashid == LWS_GENHASH_TYPE_UNKNOWN)
		oaep_hashid = LWS_GENHASH_TYPE_SHA1;

	hash_id = (int)lws_gencrypto_mbedtls_hash_to_MD_TYPE(oaep_hashid);

#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
	mbedtls_rsa_init(ctx->ctx, mode_map[mode], hash_id);
#else
	mbedtls_rsa_init(ctx->ctx);
	if (mbedtls_rsa_set_padding(ctx->ctx, mode_map[mode],
				    mode == LGRSAM_PKCS1_OAEP_PSS ?
					      (mbedtls_md_type_t)hash_id :
					      MBEDTLS_MD_NONE)) {
		lwsl_notice("%s: mbedtls_rsa_set_padding failed\n", __func__);
		mbedtls_rsa_free(ctx->ctx);
		lws_free_set_NULL(ctx->ctx);

		return -1;
	}
#endif

	{
		int n;

		mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT] = {
			&ctx->ctx->MBEDTLS_PRIVATE(E),
			&ctx->ctx->MBEDTLS_PRIVATE(N),
			&ctx->ctx->MBEDTLS_PRIVATE(D),
			&ctx->ctx->MBEDTLS_PRIVATE(P),
			&ctx->ctx->MBEDTLS_PRIVATE(Q),
			&ctx->ctx->MBEDTLS_PRIVATE(DP),
			&ctx->ctx->MBEDTLS_PRIVATE(DQ),
			&ctx->ctx->MBEDTLS_PRIVATE(QP),
		};

		for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++)
			if (el[n].buf &&
			    mbedtls_mpi_read_binary(mpi[n], el[n].buf,
					    	    el[n].len)) {
				lwsl_notice("mpi load failed\n");
				/*
				 * the mpis read in so far own heap limb
				 * allocations holding key material... they have
				 * to be freed and wiped by mbedtls before the
				 * containing struct goes
				 */
				mbedtls_rsa_free(ctx->ctx);
				lws_free_set_NULL(ctx->ctx);

				return -1;
			}

		/* mbedtls... compute missing P & Q */

		if ( el[LWS_GENCRYPTO_RSA_KEYEL_D].len &&
		    !el[LWS_GENCRYPTO_RSA_KEYEL_P].len &&
		    !el[LWS_GENCRYPTO_RSA_KEYEL_Q].len) {
#if defined(LWS_HAVE_mbedtls_rsa_complete)
			if (mbedtls_rsa_complete(ctx->ctx)) {
				lwsl_notice("mbedtls_rsa_complete failed\n");
#else
			{
				lwsl_notice("%s: you have to provide P and Q\n", __func__);
#endif
				mbedtls_rsa_free(ctx->ctx);
				lws_free_set_NULL(ctx->ctx);

				return -1;
			}

		}
	}

	ctx->ctx->MBEDTLS_PRIVATE(len) = el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	ctx->created_mark = LWS_GENRSA_CTX_CREATED_MARK;

	return 0;
}

static int
_rngf(void *context, unsigned char *buf, size_t len)
{
	if ((size_t)lws_get_random(context, buf, len) == len)
		return 0;

	return -1;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	int n;

	if (mode >= LGRSAM_COUNT)
		return -1;

	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENRSA_CTX_CREATED_MARK)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ctx = lws_zalloc(sizeof(*ctx->ctx), "genrsa");
	if (!ctx->ctx)
		return -1;

	ctx->context = context;
	ctx->mode = mode;

#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
	mbedtls_rsa_init(ctx->ctx, mode_map[mode], 0);
#else
	mbedtls_rsa_init(ctx->ctx);
	mbedtls_rsa_set_padding(ctx->ctx, mode_map[mode], 0);
#endif

	n = mbedtls_rsa_gen_key(ctx->ctx, _rngf, context, (unsigned int)bits, 65537);
	if (n) {
		lwsl_err("mbedtls_rsa_gen_key failed 0x%x\n", -n);
		goto cleanup_1;
	}

	{
		mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT] = {
			&ctx->ctx->MBEDTLS_PRIVATE(E),
			&ctx->ctx->MBEDTLS_PRIVATE(N),
			&ctx->ctx->MBEDTLS_PRIVATE(D),
			&ctx->ctx->MBEDTLS_PRIVATE(P),
			&ctx->ctx->MBEDTLS_PRIVATE(Q),
			&ctx->ctx->MBEDTLS_PRIVATE(DP),
			&ctx->ctx->MBEDTLS_PRIVATE(DQ),
			&ctx->ctx->MBEDTLS_PRIVATE(QP),
		};

		for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++)
			if (mpi[n] && mbedtls_mpi_size(mpi[n])) {
				el[n].buf = lws_malloc(
					mbedtls_mpi_size(mpi[n]), "genrsakey");
				if (!el[n].buf)
					goto cleanup;
				el[n].len = (uint32_t)mbedtls_mpi_size(mpi[n]);
				if (mbedtls_mpi_write_binary(mpi[n], el[n].buf,
							 el[n].len))
					goto cleanup;
			}
	}

	ctx->created_mark = LWS_GENRSA_CTX_CREATED_MARK;

	return 0;

cleanup:
	for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
cleanup_1:
	/*
	 * mbedtls_rsa_gen_key() may already have filled in (and heap-allocated
	 * the limbs for) the private key... release and wipe it through
	 * mbedtls, and leave ctx->ctx NULL so the caller's unconditional
	 * lws_genrsa_destroy() cannot walk or free the block a second time
	 */
	mbedtls_rsa_free(ctx->ctx);
	lws_free_set_NULL(ctx->ctx);

	return -1;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	size_t olen = 0;
	int n;

#if defined(LWS_HAVE_mbedtls_rsa_complete)
	mbedtls_rsa_complete(ctx->ctx);
#endif

	/*
	 * The mbedtls decrypt entrypoints take no input length, they read
	 * exactly ctx->len (ie, modulus-sized) bytes from "in"... a ciphertext
	 * that is not modulus-sized is invalid anyway, so refuse it here
	 * rather than over-read the caller's buffer by the difference
	 */

	if (in_len != ctx->ctx->MBEDTLS_PRIVATE(len)) {
		lwsl_notice("%s: ciphertext len %d, modulus %d\n", __func__,
			    (int)in_len, (int)ctx->ctx->MBEDTLS_PRIVATE(len));

		return -1;
	}

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		n = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(ctx->ctx, _rngf,
							ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
							MBEDTLS_RSA_PUBLIC,
#endif
							&olen, in, out,
							out_max);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		n = mbedtls_rsa_rsaes_oaep_decrypt(ctx->ctx, _rngf,
						   ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
							MBEDTLS_RSA_PUBLIC,
#endif
						   NULL, 0,
						   &olen, in, out, out_max);
		break;
	default:
		return -1;
	}
	if (n) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return (int)olen;
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	size_t olen = 0;
	int n;

#if defined(LWS_HAVE_mbedtls_rsa_complete)
	mbedtls_rsa_complete(ctx->ctx);
#endif

	/*
	 * The mbedtls decrypt entrypoints take no input length, they read
	 * exactly ctx->len (ie, modulus-sized) bytes from "in"... eg, the JWE
	 * Encrypted Key is a peer-sized field, so refuse anything that is not
	 * modulus-sized rather than over-read the caller's buffer
	 */

	if (in_len != ctx->ctx->MBEDTLS_PRIVATE(len)) {
		lwsl_notice("%s: ciphertext len %d, modulus %d\n", __func__,
			    (int)in_len, (int)ctx->ctx->MBEDTLS_PRIVATE(len));

		return -1;
	}

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		n = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(ctx->ctx, _rngf,
							ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
							MBEDTLS_RSA_PRIVATE,
#endif
							&olen, in, out,
							out_max);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		n = mbedtls_rsa_rsaes_oaep_decrypt(ctx->ctx, _rngf,
						   ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
						   MBEDTLS_RSA_PRIVATE,
#endif
						   NULL, 0,
						   &olen, in, out, out_max);
		break;
	default:
		return -1;
	}
	if (n) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return (int)olen;
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	int n;

#if defined(LWS_HAVE_mbedtls_rsa_complete)
	mbedtls_rsa_complete(ctx->ctx);
#endif

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		n = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(ctx->ctx, _rngf,
							ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
							MBEDTLS_RSA_PUBLIC,
#endif
							in_len, in, out);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		n = mbedtls_rsa_rsaes_oaep_encrypt(ctx->ctx, _rngf,
						   ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
						   MBEDTLS_RSA_PUBLIC,
#endif
						   NULL, 0,
						   in_len, in, out);
		break;
	default:
		return -1;
	}
	if (n < 0) {
		lwsl_notice("%s: -0x%x: in_len: %d\n", __func__, -n,
				(int)in_len);

		return -1;
	}

	return (int)mbedtls_mpi_size(&ctx->ctx->MBEDTLS_PRIVATE(N));
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	int n;

#if defined(LWS_HAVE_mbedtls_rsa_complete)
	mbedtls_rsa_complete(ctx->ctx);
#endif

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		n = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(ctx->ctx, _rngf,
							ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
							MBEDTLS_RSA_PRIVATE,
#endif
							in_len, in, out);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		n = mbedtls_rsa_rsaes_oaep_encrypt(ctx->ctx, _rngf,
						   ctx->context,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
						   MBEDTLS_RSA_PRIVATE,
#endif
						   NULL, 0,
						   in_len, in, out);
		break;
	default:
		return -1;
	}
	if (n) {
		lwsl_notice("%s: -0x%x: in_len: %d\n", __func__, -n,
				(int)in_len);

		return -1;
	}

	return (int)mbedtls_mpi_size(&ctx->ctx->MBEDTLS_PRIVATE(N));
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	int n, h = (int)lws_gencrypto_mbedtls_hash_to_MD_TYPE(hash_type);

	if (h < 0)
		return -1;

#if defined(LWS_HAVE_mbedtls_rsa_complete)
	mbedtls_rsa_complete(ctx->ctx);
#endif

	/*
	 * mbedtls reads exactly ctx->len bytes from "sig" and has no idea how
	 * many we actually have... a signature that is not modulus-sized is
	 * invalid anyway, so refuse it here rather than over-read the caller's
	 * buffer with whatever the peer sent
	 */

	if (sig_len != ctx->ctx->MBEDTLS_PRIVATE(len)) {
		lwsl_notice("%s: sig len %d, modulus %d\n", __func__,
			    (int)sig_len, (int)ctx->ctx->MBEDTLS_PRIVATE(len));

		return -1;
	}

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		n = mbedtls_rsa_rsassa_pkcs1_v15_verify(ctx->ctx,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
							NULL, NULL,
							MBEDTLS_RSA_PUBLIC,
#endif
							(mbedtls_md_type_t)h,
							(unsigned int)lws_genhash_size(hash_type),
							in, sig);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		/*
		 * RFC7518 3.5: PS256/384/512 mean "RSASSA-PSS using SHA-nnn and
		 * MGF1 with SHA-nnn", with the salt the same length as the
		 * hash.  mbedtls_rsa_rsassa_pss_verify() would take MGF1 from
		 * ctx->hash_id (which is the OAEP MGF1 hash, SHA-1 by default)
		 * and accept any salt length, ie, check something weaker than
		 * the alg the JOSE header declared.  The _ext form ignores
		 * ctx->hash_id and lets us pin both.
		 */
		n = mbedtls_rsa_rsassa_pss_verify_ext(ctx->ctx,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
						  NULL, NULL,
						  MBEDTLS_RSA_PUBLIC,
#endif
						  (mbedtls_md_type_t)h,
						  (unsigned int)lws_genhash_size(hash_type),
						  in, (mbedtls_md_type_t)h,
						  (int)lws_genhash_size(hash_type),
						  sig);
		break;
	default:
		return -1;
	}
	if (n < 0) {
		lwsl_notice("%s: (mode %d) -0x%x\n", __func__, ctx->mode, -n);

		return -1;
	}

	return n;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	int n, h = (int)lws_gencrypto_mbedtls_hash_to_MD_TYPE(hash_type);

	if (h < 0)
		return -1;

#if defined(LWS_HAVE_mbedtls_rsa_complete)
	mbedtls_rsa_complete(ctx->ctx);
#endif

	/*
	 * The "sig" buffer must be as large as the size of ctx->N
	 * (eg. 128 bytes if RSA-1024 is used).
	 */
	if (sig_len < ctx->ctx->MBEDTLS_PRIVATE(len))
		return -1;

	switch(ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		n = mbedtls_rsa_rsassa_pkcs1_v15_sign(ctx->ctx,
						      mbedtls_ctr_drbg_random,
						      &ctx->context->mcdc,
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
						      MBEDTLS_RSA_PRIVATE,
#endif
						      (mbedtls_md_type_t)h,
						      (unsigned int)lws_genhash_size(hash_type),
						      in, sig);
		break;
	case LGRSAM_PKCS1_OAEP_PSS:
		/*
		 * As for verify: RFC7518 3.5 wants MGF1 with the signature
		 * hash and a salt the same length as the hash.  mbedtls takes
		 * the MGF1 hash for signing from ctx->hash_id, which was set
		 * for OAEP (SHA-1 if the caller had no preference), so it has
		 * to be pointed at the signature hash here.
		 */
#if !defined(MBEDTLS_VERSION_NUMBER) || MBEDTLS_VERSION_NUMBER < 0x03000000
		mbedtls_rsa_set_padding(ctx->ctx, MBEDTLS_RSA_PKCS_V21, h);
		n = mbedtls_rsa_rsassa_pss_sign(ctx->ctx,
						mbedtls_ctr_drbg_random,
						&ctx->context->mcdc,
						MBEDTLS_RSA_PRIVATE,
						(mbedtls_md_type_t)h,
						(unsigned int)lws_genhash_size(hash_type),
						in, sig);
#else
		if (mbedtls_rsa_set_padding(ctx->ctx, MBEDTLS_RSA_PKCS_V21,
					    (mbedtls_md_type_t)h))
			return -1;

		n = mbedtls_rsa_rsassa_pss_sign_ext(ctx->ctx,
						mbedtls_ctr_drbg_random,
						&ctx->context->mcdc,
						(mbedtls_md_type_t)h,
						(unsigned int)lws_genhash_size(hash_type),
						in,
						(int)lws_genhash_size(hash_type),
						sig);
#endif
		break;
	default:
		return -1;
	}

	if (n < 0) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return (int)ctx->ctx->MBEDTLS_PRIVATE(len);
}

int
lws_genrsa_render_pkey_asn1(struct lws_genrsa_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	uint8_t *p = pkey_asn1, *totlen, *end = pkey_asn1 + pkey_asn1_len;
	mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT] = {
		&ctx->ctx->MBEDTLS_PRIVATE(N),
		&ctx->ctx->MBEDTLS_PRIVATE(E),
		&ctx->ctx->MBEDTLS_PRIVATE(D),
		&ctx->ctx->MBEDTLS_PRIVATE(P),
		&ctx->ctx->MBEDTLS_PRIVATE(Q),
		&ctx->ctx->MBEDTLS_PRIVATE(DP),
		&ctx->ctx->MBEDTLS_PRIVATE(DQ),
		&ctx->ctx->MBEDTLS_PRIVATE(QP),
	};
	int n;

	/* 30 82  - sequence
	 *   09 29  <-- length(0x0929) less 4 bytes
	 * 02 01 <- length (1)
	 *  00
	 * 02 82
	 *  02 01 <- length (513)  N
	 *  ...
	 *
	 *  02 03 <- length (3) E
	 *    01 00 01
	 *
	 * 02 82
	 *   02 00 <- length (512) D P Q EXP1 EXP2 COEFF
	 *
	 *  */

	if (pkey_asn1_len < 7)
		return -1;

	*p++ = 0x30;
	*p++ = 0x82;
	totlen = p;
	p += 2;

	*p++ = 0x02;
	*p++ = 0x01;
	*p++ = 0x00;

	for (n = 0; n < LWS_GENCRYPTO_RSA_KEYEL_COUNT; n++) {
		size_t m = mbedtls_mpi_size(mpi[n]), hdr;
		int lead = 0;

		/*
		 * A DER INTEGER is signed, so an mpi whose top bit is set needs
		 * a leading 0x00.  Settle that from the mpi itself, before
		 * anything is emitted: the length has to be written once, in
		 * its final form, and only after the space for the whole
		 * tag + length + content was confirmed available.
		 */

		if (m && mbedtls_mpi_get_bit(mpi[n], (m * 8) - 1))
			lead = 1;

		hdr = 1 + ((m + (size_t)lead) < 0x80 ? 1u : 3u);

		if (lws_ptr_diff_size_t(end, p) < hdr + m + (size_t)lead)
			return -1;

		*p++ = 0x02;
		if ((m + (size_t)lead) < 0x80)
			*p++ = (uint8_t)(m + (size_t)lead);
		else {
			*p++ = 0x82;
			*p++ = (uint8_t)((m + (size_t)lead) >> 8);
			*p++ = (uint8_t)((m + (size_t)lead) & 0xff);
		}

		if (lead)
			*p++ = 0x00;

		if (m && mbedtls_mpi_write_binary(mpi[n], p, m))
			return -1;

		p += m;
	}

	n = lws_ptr_diff(p, pkey_asn1);

	*totlen++ = (uint8_t)((n - 4) >> 8);
	*totlen = (uint8_t)((n - 4) & 0xff);

	return n;
}

void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (ctx->ctx) {
		mbedtls_rsa_free(ctx->ctx);
		lws_free(ctx->ctx);
		ctx->ctx = NULL;
	}

	ctx->created_mark = 0;
}
#else /* LWS_HAVE_MBEDTLS_V4 */

#include "private-lib-tls-mbedtls.h"
#include <psa/crypto.h>

/*
 * PSA imports RSA keys as DER: RFC8017 A.1.2 RSAPrivateKey
 *
 *   SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }
 *
 * or A.1.1 RSAPublicKey, SEQUENCE { n, e }.  Our key elements are in
 * enum lws_gencrypto_rsa_tok order, which is not DER order, and also has
 * JWK-only members (oth, r, d, t) that have no place in either.
 */

static const uint8_t rsa_der_order[] = {
	LWS_GENCRYPTO_RSA_KEYEL_N,  LWS_GENCRYPTO_RSA_KEYEL_E,
	LWS_GENCRYPTO_RSA_KEYEL_D,  LWS_GENCRYPTO_RSA_KEYEL_P,
	LWS_GENCRYPTO_RSA_KEYEL_Q,  LWS_GENCRYPTO_RSA_KEYEL_DP,
	LWS_GENCRYPTO_RSA_KEYEL_DQ, LWS_GENCRYPTO_RSA_KEYEL_QI,
};

static size_t
asn1_len_size(size_t len)
{
	return len < 128 ? 1 : (len < 256 ? 2 : 3);
}

static size_t
asn1_integer_size(const struct lws_gencrypto_keyelem *el)
{
	size_t len;

	if (!el->len || !el->buf)
		return 3; /* INTEGER 0 */

	len = el->len + !!(el->buf[0] & 0x80);

	return 1 + asn1_len_size(len) + len;
}

static int
write_asn1_len(uint8_t **p, uint8_t *end, size_t len)
{
	size_t n = asn1_len_size(len);

	if (len > 0xffff || (size_t)(end - *p) < n)
		return -1;

	if (n > 1)
		*(*p)++ = (uint8_t)(0x80 | (n - 1));
	if (n > 2)
		*(*p)++ = (uint8_t)(len >> 8);
	*(*p)++ = (uint8_t)len;

	return 0;
}

static int
write_asn1_integer(uint8_t **p, uint8_t *end,
		   const struct lws_gencrypto_keyelem *el)
{
	size_t len;
	int lz;

	if (!el->len || !el->buf) {
		if (end - *p < 3)
			return -1;
		*(*p)++ = 0x02;
		*(*p)++ = 0x01;
		*(*p)++ = 0x00;

		return 0;
	}

	/* a leading zero keeps a top-bit-set magnitude positive */
	lz = !!(el->buf[0] & 0x80);
	len = el->len + (size_t)lz;

	if (*p >= end)
		return -1;
	*(*p)++ = 0x02;
	if (write_asn1_len(p, end, len) || (size_t)(end - *p) < len)
		return -1;
	if (lz)
		*(*p)++ = 0x00;
	memcpy(*p, el->buf, el->len);
	*p += el->len;

	return 0;
}

/*
 * RSAPrivateKey if we were given the private exponent, else RSAPublicKey
 */

static int
lws_genrsa_psa_der(const struct lws_gencrypto_keyelem *el, uint8_t *der,
		   size_t der_max, size_t *der_len, int *priv)
{
	static const struct lws_gencrypto_keyelem zero = { NULL, 0 };
	uint8_t *p = der, *end = der + der_max;
	size_t payload = 0, count, i;

	if (!el[LWS_GENCRYPTO_RSA_KEYEL_N].len ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_N].buf ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_E].len ||
	    !el[LWS_GENCRYPTO_RSA_KEYEL_E].buf)
		return -1;

	*priv = el[LWS_GENCRYPTO_RSA_KEYEL_D].len &&
		el[LWS_GENCRYPTO_RSA_KEYEL_D].buf;
	count = *priv ? LWS_ARRAY_SIZE(rsa_der_order) : 2;

	if (*priv)
		payload += asn1_integer_size(&zero); /* version 0 */
	for (i = 0; i < count; i++)
		payload += asn1_integer_size(&el[rsa_der_order[i]]);

	if (p >= end)
		return -1;
	*p++ = 0x30; /* SEQUENCE */
	if (write_asn1_len(&p, end, payload))
		return -1;

	if (*priv && write_asn1_integer(&p, end, &zero))
		return -1;
	for (i = 0; i < count; i++)
		if (write_asn1_integer(&p, end, &el[rsa_der_order[i]]))
			return -1;

	*der_len = (size_t)(p - der);

	return 0;
}

/*
 * A PSA key has a single algorithm policy, so a ctx holds its key twice:
 * key_id with the signing policy for the mode, and key_id_crypt whose
 * policy is exactly the encryption scheme the mode (and, for OAEP, the
 * hash) selects.  Every encrypt / decrypt asks for that same scheme, and
 * PSA refuses any other on that key, so eg, a ctx created for RSA-OAEP can
 * never be driven as RSAES-PKCS1-v1_5.
 */

static psa_algorithm_t
lws_genrsa_psa_crypt_alg(const struct lws_genrsa_ctx *ctx)
{
	psa_algorithm_t h;

	switch (ctx->mode) {
	case LGRSAM_PKCS1_1_5:
		return PSA_ALG_RSA_PKCS1V15_CRYPT;
	case LGRSAM_PKCS1_OAEP_PSS:
		h = lws_genhash_to_psa_alg(ctx->oaep_hashid);

		return h ? PSA_ALG_RSA_OAEP(h) : 0;
	default:
		return 0;
	}
}

static int
lws_genrsa_psa_import_crypt(struct lws_genrsa_ctx *ctx, const uint8_t *der,
			    size_t der_len, int priv)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg = lws_genrsa_psa_crypt_alg(ctx);

	if (!alg)
		return -1;

	psa_set_key_type(&attr, priv ? PSA_KEY_TYPE_RSA_KEY_PAIR :
				       PSA_KEY_TYPE_RSA_PUBLIC_KEY);
	psa_set_key_usage_flags(&attr, priv ? PSA_KEY_USAGE_ENCRYPT |
					      PSA_KEY_USAGE_DECRYPT :
					      PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, alg);

	if (psa_import_key(&attr, der, der_len, &ctx->key_id_crypt) !=
								PSA_SUCCESS) {
		lwsl_notice("%s: psa_import_key failed\n", __func__);
		return -1;
	}

	return 0;
}

int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
		  const struct lws_gencrypto_keyelem *el,
		  struct lws_context *context, enum enum_genrsa_mode mode,
		  enum lws_genhash_types oaep_hashid)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t der[4096];
	size_t der_len;
	int priv, ret = -1;

	if (mode >= LGRSAM_COUNT)
		return -1;

	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENRSA_CTX_CREATED_MARK)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;

	/* as the other backends, OAEP with no preference is RFC8017's SHA-1 */
	ctx->oaep_hashid = oaep_hashid == LWS_GENHASH_TYPE_UNKNOWN ?
					LWS_GENHASH_TYPE_SHA1 : oaep_hashid;

	if (lws_genrsa_psa_der(el, der, sizeof(der), &der_len, &priv)) {
		lwsl_notice("%s: unable to render key\n", __func__);
		goto bail;
	}

	if (priv) {
		psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
					       PSA_KEY_USAGE_VERIFY_HASH);
	} else {
		psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	}

	/* Determine algorithm based on mode */
	if (mode == LGRSAM_PKCS1_1_5)
		psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
	else
		psa_set_key_algorithm(&attr,
				PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_ANY_HASH));

	if (psa_import_key(&attr, der, der_len, &ctx->key_id) != PSA_SUCCESS) {
		lwsl_notice("%s: psa_import_key failed\n", __func__);
		goto bail;
	}

	if (lws_genrsa_psa_import_crypt(ctx, der, der_len, priv)) {
		psa_destroy_key(ctx->key_id);
		ctx->key_id = 0;
		goto bail;
	}

	ctx->created_mark = LWS_GENRSA_CTX_CREATED_MARK;
	ret = 0;

bail:
	lws_explicit_bzero(der, sizeof(der));

	return ret;
}

int
lws_genrsa_new_keypair(struct lws_context *context, struct lws_genrsa_ctx *ctx,
		       enum enum_genrsa_mode mode, struct lws_gencrypto_keyelem *el,
		       int bits)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t der[4096], *p, *end;
	size_t der_len, len;
	unsigned int i;

	if (mode >= LGRSAM_COUNT || bits <= 0)
		return -1;

	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENRSA_CTX_CREATED_MARK)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->mode = mode;
	ctx->oaep_hashid = LWS_GENHASH_TYPE_SHA1;

	psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&attr, (size_t)bits);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
				       PSA_KEY_USAGE_VERIFY_HASH |
				       PSA_KEY_USAGE_EXPORT);

	if (mode == LGRSAM_PKCS1_1_5) {
		psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
	} else if (mode == LGRSAM_PKCS1_OAEP_PSS) {
		psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_ANY_HASH));
	}

	if (psa_generate_key(&attr, &ctx->key_id) != PSA_SUCCESS)
		return -1;

	if (psa_export_key(ctx->key_id, der, sizeof(der), &der_len) != PSA_SUCCESS ||
	    lws_genrsa_psa_import_crypt(ctx, der, der_len, 1))
		goto cleanup_der;

	/*
	 * PSA exports the key pair as RSAPrivateKey (see above)... hand the
	 * elements back to the caller in lws order.  mbedtls_asn1_get_tag()
	 * confirms each length fits in what is left.
	 */

	p = der;
	end = der + der_len;

	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED |
						 MBEDTLS_ASN1_SEQUENCE))
		goto cleanup_der;
	end = p + len;

	/* version */
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER))
		goto cleanup_der;
	p += len;

	for (i = 0; i < LWS_ARRAY_SIZE(rsa_der_order); i++) {
		struct lws_gencrypto_keyelem *e = &el[rsa_der_order[i]];

		if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER) ||
		    !len)
			goto cleanup_der;

		/* drop the leading zero that only keeps it positive */
		if (len > 1 && !p[0]) {
			p++;
			len--;
		}

		e->buf = lws_malloc(len, "genrsakey");
		if (!e->buf)
			goto cleanup_der;
		memcpy(e->buf, p, len);
		e->len = (uint32_t)len;
		p += len;
	}

	lws_explicit_bzero(der, sizeof(der));
	ctx->created_mark = LWS_GENRSA_CTX_CREATED_MARK;

	return 0;

cleanup_der:
	lws_explicit_bzero(der, sizeof(der));
	lws_genrsa_destroy_elements(el);
	psa_destroy_key(ctx->key_id);
	psa_destroy_key(ctx->key_id_crypt);
	ctx->key_id = 0;
	ctx->key_id_crypt = 0;

	return -1;
}

/*
 * PSA only has the private-key decrypt and public-key encrypt primitives,
 * which is also what the mbedtls 3 backend does for the public_decrypt /
 * private_encrypt variants
 */

static int
lws_genrsa_psa_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       size_t in_len, uint8_t *out, size_t out_max)
{
	psa_algorithm_t alg = lws_genrsa_psa_crypt_alg(ctx);
	size_t olen;

	if (!alg || psa_asymmetric_decrypt(ctx->key_id_crypt, alg, in, in_len,
					   NULL, 0, out, out_max, &olen) !=
								PSA_SUCCESS)
		return -1;

	return (int)olen;
}

static int
lws_genrsa_psa_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       size_t in_len, uint8_t *out)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg = lws_genrsa_psa_crypt_alg(ctx);
	size_t olen, osize;

	/*
	 * The api contract is only that "out" has room for a modulus-sized
	 * result, so that is the size we must tell PSA... it may use (and with
	 * MBEDTLS_PSA_COPY_CALLER_BUFFERS, copies back) all of what it is told,
	 * even when the operation fails.
	 */

	if (!alg || psa_get_key_attributes(ctx->key_id_crypt, &attr) !=
								PSA_SUCCESS)
		return -1;
	osize = PSA_BITS_TO_BYTES(psa_get_key_bits(&attr));
	psa_reset_key_attributes(&attr);

	if (psa_asymmetric_encrypt(ctx->key_id_crypt, alg, in, in_len,
				   NULL, 0, out, osize, &olen) != PSA_SUCCESS)
		return -1;

	return (int)olen;
}

int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	return lws_genrsa_psa_decrypt(ctx, in, in_len, out, out_max);
}

int
lws_genrsa_private_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	return lws_genrsa_psa_decrypt(ctx, in, in_len, out, out_max);
}

int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	return lws_genrsa_psa_encrypt(ctx, in, in_len, out);
}

int
lws_genrsa_private_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	return lws_genrsa_psa_encrypt(ctx, in, in_len, out);
}

int
lws_genrsa_hash_sig_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	psa_algorithm_t alg;
	if (ctx->mode == LGRSAM_PKCS1_1_5) {
		alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH); /* We'll use specific if needed */
	} else {
		alg = PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_ANY_HASH);
	}
	if (psa_verify_hash(ctx->key_id, alg, in, lws_genhash_size(hash_type), sig, sig_len) != PSA_SUCCESS)
		return -1;
	return 0;
}

int
lws_genrsa_hash_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	size_t olen;
	psa_algorithm_t alg;
	if (ctx->mode == LGRSAM_PKCS1_1_5) {
		alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH);
	} else {
		alg = PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_ANY_HASH);
	}
	if (psa_sign_hash(ctx->key_id, alg, in, lws_genhash_size(hash_type), sig, sig_len, &olen) != PSA_SUCCESS)
		return -1;
	return (int)olen;
}

int
lws_genrsa_render_pkey_asn1(struct lws_genrsa_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	size_t olen;
	if (psa_export_key(ctx->key_id, pkey_asn1, pkey_asn1_len, &olen) != PSA_SUCCESS)
		return -1;
	return (int)olen;
}

void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	psa_destroy_key(ctx->key_id);
	psa_destroy_key(ctx->key_id_crypt);
	ctx->key_id = 0;
	ctx->key_id_crypt = 0;
	ctx->created_mark = 0;
}

#endif
