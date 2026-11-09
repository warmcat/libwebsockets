/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * Private apis for lws_genkem: the lws ML-KEM implementation, the FIPS 202
 * Keccak it needs, and the optional TLS backend binding.
 */

#if !defined(__LWS_PRIVATE_GENKEM_H__)
#define __LWS_PRIVATE_GENKEM_H__

/*
 * FIPS 202 Keccak sponge, for SHA3-256 / SHA3-512 / SHAKE128 / SHAKE256
 */

#define LWS_KECCAK_RATE_SHAKE128	168
#define LWS_KECCAK_RATE_SHAKE256	136
#define LWS_KECCAK_RATE_SHA3_256	136
#define LWS_KECCAK_RATE_SHA3_512	72

#define LWS_KECCAK_DSEP_SHA3		0x06
#define LWS_KECCAK_DSEP_SHAKE		0x1f

struct lws_keccak {
	uint64_t	s[25];
	unsigned int	pos;	/* byte offset into the current rate block */
	unsigned int	rate;	/* bytes */
	uint8_t		dsep;	/* domain separation / padding byte */
};

void
lws_keccak_init(struct lws_keccak *k, unsigned int rate, uint8_t dsep);

void
lws_keccak_absorb(struct lws_keccak *k, const uint8_t *in, size_t len);

/* pads and moves to squeezing; call once, after the last absorb */
void
lws_keccak_finalize(struct lws_keccak *k);

void
lws_keccak_squeeze(struct lws_keccak *k, uint8_t *out, size_t len);

void
lws_sha3_256(uint8_t out[32], const uint8_t *in, size_t len);

void
lws_sha3_512(uint8_t out[64], const uint8_t *in, size_t len);

void
lws_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t len);

/*
 * The lws ML-KEM (FIPS 203) implementation
 *
 * These take buffers of exactly the sizes in lws_genkem_info(alg).  The
 * encaps and decaps apis assume the EK / DK passed the FIPS 203 input checks
 * (lws_mlkem_check_ek() / lws_mlkem_check_dk()) already.
 */

int
lws_mlkem_keypair_derand(enum lws_genkem_alg alg,
			 const uint8_t seed[LWS_GENKEM_SEED_LEN],
			 uint8_t *ek, uint8_t *dk);

int
lws_mlkem_encaps_derand(enum lws_genkem_alg alg, const uint8_t *ek,
			const uint8_t m[32], uint8_t *ct,
			uint8_t ss[LWS_GENKEM_SS_LEN]);

int
lws_mlkem_decaps(enum lws_genkem_alg alg, const uint8_t *dk,
		 const uint8_t *ct, uint8_t ss[LWS_GENKEM_SS_LEN]);

/* FIPS 203 7.2 modulus check: 0 if every EK coefficient is < q */
int
lws_mlkem_check_ek(enum lws_genkem_alg alg, const uint8_t *ek);

/* FIPS 203 7.3 hash check: 0 if the DK's embedded H(ek) matches its ek */
int
lws_mlkem_check_dk(enum lws_genkem_alg alg, const uint8_t *dk);

/*
 * Optional binding to the TLS backend's own ML-KEM.  The common code checks
 * everything coming in before it reaches these.
 *
 * Each returns 0 if OK, -1 for an error, or 1 if the backend can't do it
 * after all (eg, an OpenSSL whose providers lack ML-KEM at runtime), when the
 * caller uses the lws implementation instead.
 */

#if defined(LWS_HAVE_OPENSSL_ML_KEM)
#define LWS_GENKEM_HAVE_BACKEND
#endif

#if defined(LWS_GENKEM_HAVE_BACKEND)

/* exactly one of seed, dk or ek is non-NULL; ek / dk out are optional */
int
lws_genkem_backend_set_key(struct lws_genkem_ctx *ctx, const uint8_t *seed,
			   const uint8_t *dk, const uint8_t *ek,
			   uint8_t *ek_out, uint8_t *dk_out);

int
lws_genkem_backend_encapsulate(struct lws_genkem_ctx *ctx, uint8_t *ct,
			       uint8_t *ss);

int
lws_genkem_backend_decapsulate(struct lws_genkem_ctx *ctx, const uint8_t *ct,
			       uint8_t *ss);

void
lws_genkem_backend_destroy(struct lws_genkem_ctx *ctx);

#endif

#endif
