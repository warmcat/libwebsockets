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
 * ML-KEM, as specified by FIPS 203 (August 2024)
 *
 * Polynomial arithmetic follows the usual approach for ML-KEM: int16_t
 * coefficients, Montgomery multiplication (R = 2^16) and Barrett reduction,
 * with the NTT twiddle factors kept in the Montgomery domain.
 *
 * Constant time: nothing branches on, or indexes memory by, secret data.
 * Compression uses a multiply and shift in place of dividing by q, the
 * re-encryption check in decapsulation is compared and selected without
 * branching, and only the public matrix sampling is variable time.
 *
 * Memory: the polynomials live in one heap workspace of about 4KB for every
 * operation, so the stack use stays small (a few hundred bytes) for the sake
 * of embedded targets.  The workspace is wiped before it is freed.
 */

#include "private-lib-core.h"
#include "private-genkem.h"

#define MLKEM_N			256
#define MLKEM_Q			3329
#define MLKEM_K_MAX		4
#define MLKEM_POLY_BYTES	384	/* 256 x 12 bits */
#define MLKEM_SYM_BYTES		32

struct mlkem_params {
	uint8_t		k;
	uint8_t		eta1;
	uint8_t		du;
	uint8_t		dv;
};

/* indexed by enum lws_genkem_alg; eta2 is always 2 */
static const struct mlkem_params mlkem_params[] = {
	{ 2, 3, 10, 4 },	/* ML-KEM-512 */
	{ 3, 2, 10, 4 },	/* ML-KEM-768 */
	{ 4, 2, 11, 5 },	/* ML-KEM-1024 */
};

typedef struct {
	int16_t		c[MLKEM_N];
} mlkem_poly;

struct mlkem_ws {
	mlkem_poly	vec[MLKEM_K_MAX]; /* s^ (keygen / decrypt), y^ (encrypt) */
	mlkem_poly	acc;
	mlkem_poly	a;
	mlkem_poly	e;
	uint16_t	tmp[MLKEM_N];
};

/*
 * The NTT twiddle factors: zeta^bitrev7(i) * 2^16 mod q, with zeta = 17,
 * centered on 0.  Computed by
 *
 * [((1 << 16) * pow(17, int('{:07b}'.format(i)[::-1], 2), 3329)) % 3329
 *	for i in range(128)], then subtracting 3329 from any above 1664
 */
static const int16_t zetas[128] = {
	-1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
	 -171,   622,  1577,   182,   962, -1202, -1474,  1468,
	  573, -1325,   264,   383,  -829,  1458, -1602,  -130,
	 -681,  1017,   732,   608, -1542,   411,  -205, -1571,
	 1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
	  516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
	 -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
	 -398,   961, -1508,  -725,   448, -1065,   677, -1275,
	-1103,   430,   555,   843, -1251,   871,  1550,   105,
	  422,   587,   177,  -235,  -291,  -460,  1574,  1653,
	 -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
	-1590,   644,  -872,   349,   418,   329,  -156,   -75,
	  817,  1097,   603,   610,  1322, -1285, -1465,   384,
	-1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
	-1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
	 -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/*
 * Arithmetic mod q
 *
 * These avoid implementation-defined behaviour (narrowing an out of range
 * value to a signed type, or right-shifting a negative one) by working in
 * unsigned arithmetic, or on values made non-negative first.
 */

/* q^-1 mod 2^16 */
#define MLKEM_QINV	62209u

/* for |a| < q * 2^15, returns a * 2^-16 mod q, in (-q, q) */
static int16_t
mont_reduce(int32_t a)
{
	uint32_t u = ((uint32_t)a * MLKEM_QINV) & 0xffffu;
	/* sign-extend the 16-bit u */
	int32_t t = (int32_t)u - (int32_t)((u & 0x8000u) << 1);

	/* a - t * q is an exact multiple of 2^16 */
	return (int16_t)((a - t * MLKEM_Q) / 65536);
}

static int16_t
fqmul(int16_t a, int16_t b)
{
	return mont_reduce((int32_t)a * b);
}

/* returns a mod q, centered in [-(q - 1) / 2, (q - 1) / 2] */
static int16_t
barrett_reduce(int16_t a)
{
	/*
	 * round(a * 20159 / 2^26), where 20159 = round(2^26 / q).  The
	 * 10 << 26 offset keeps the sum non-negative for any int16_t a,
	 * and is taken off again after the shift.
	 */
	int32_t t = (((int32_t)20159 * a + (1 << 25) + (10 << 26)) >> 26) - 10;

	return (int16_t)(a - t * MLKEM_Q);
}

/* maps a in (-q, q) to [0, q) without branching */
static uint16_t
caddq(int16_t a)
{
	uint32_t neg = (uint32_t)(uint16_t)a >> 15;

	return (uint16_t)(a + (int16_t)(neg * MLKEM_Q));
}

/* FIPS 203 Compress_d, for x in [0, q): round(x * 2^d / q) mod 2^d */
static uint16_t
mlkem_compress(uint16_t x, unsigned int d)
{
	/*
	 * 161271 / 2^29 approximates 1 / q closely enough to be exact here,
	 * for every x < q and every d we use (1, 4, 5, 10 and 11).  It was
	 * checked exhaustively against the exact division with
	 *
	 * all((((x << d) + 1664) * 161271 >> 29) % (1 << d) ==
	 *     ((x << d) + 1664) // 3329 % (1 << d) for x in range(3329))
	 */
	uint64_t v = (((uint64_t)x << d) + MLKEM_Q / 2) * 161271u;

	return (uint16_t)((v >> 29) & ((1u << d) - 1));
}

/* FIPS 203 Decompress_d: round(y * q / 2^d) */
static int16_t
mlkem_decompress(uint16_t y, unsigned int d)
{
	return (int16_t)(((uint32_t)y * MLKEM_Q + (1u << (d - 1))) >> d);
}

/*
 * Polynomials
 */

static void
poly_zero(mlkem_poly *r)
{
	memset(r, 0, sizeof(*r));
}

static void
poly_reduce(mlkem_poly *r)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		r->c[i] = barrett_reduce(r->c[i]);
}

static void
poly_add(mlkem_poly *r, const mlkem_poly *a)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		r->c[i] = (int16_t)(r->c[i] + a->c[i]);
}

/* r = a - r */
static void
poly_sub_from(mlkem_poly *r, const mlkem_poly *a)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		r->c[i] = (int16_t)(a->c[i] - r->c[i]);
}

/* multiply by 2^16 mod q, ie, into the Montgomery domain */
static void
poly_tomont(mlkem_poly *r)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		r->c[i] = mont_reduce((int32_t)r->c[i] * 1353); /* 2^32 mod q */
}

/*
 * Forward NTT, FIPS 203 Algorithm 9.  Input coefficients |c| < q, output
 * reduced
 */
static void
poly_ntt(mlkem_poly *r)
{
	unsigned int len, start, j, k = 1;
	int16_t t, zeta;

	for (len = 128; len >= 2; len >>= 1)
		for (start = 0; start < MLKEM_N; start = j + len) {
			zeta = zetas[k++];
			for (j = start; j < start + len; j++) {
				t = fqmul(zeta, r->c[j + len]);
				r->c[j + len] = (int16_t)(r->c[j] - t);
				r->c[j] = (int16_t)(r->c[j] + t);
			}
		}

	poly_reduce(r);
}

/*
 * Inverse NTT, FIPS 203 Algorithm 10, also taking off the 2^-16 factor left
 * by poly_basemul_acc().  Output |c| < q
 */
static void
poly_invntt(mlkem_poly *r)
{
	unsigned int len, start, j, k = 127;
	int16_t t, zeta;

	for (len = 2; len <= 128; len <<= 1)
		for (start = 0; start < MLKEM_N; start = j + len) {
			zeta = zetas[k--];
			for (j = start; j < start + len; j++) {
				t = r->c[j];
				r->c[j] = barrett_reduce((int16_t)(t +
							 r->c[j + len]));
				r->c[j + len] = (int16_t)(r->c[j + len] - t);
				r->c[j + len] = fqmul(zeta, r->c[j + len]);
			}
		}

	/* 1441 = 2^32 / 128 mod q */
	for (j = 0; j < MLKEM_N; j++)
		r->c[j] = fqmul(r->c[j], 1441);
}

/*
 * r += a * b in the NTT domain (FIPS 203 Algorithms 11 and 12), with an
 * extra factor of 2^-16.  Up to MLKEM_K_MAX products can be summed into
 * a zeroed r before it must be reduced
 */
static void
poly_basemul_acc(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
	unsigned int i, n;
	int16_t zeta;

	for (i = 0; i < MLKEM_N / 4; i++) {
		zeta = zetas[64 + i];

		for (n = 4 * i; n < 4 * i + 4; n += 2) {
			r->c[n] = (int16_t)(r->c[n] +
				fqmul(fqmul(a->c[n + 1], b->c[n + 1]), zeta) +
				fqmul(a->c[n], b->c[n]));
			r->c[n + 1] = (int16_t)(r->c[n + 1] +
				fqmul(a->c[n], b->c[n + 1]) +
				fqmul(a->c[n + 1], b->c[n]));
			zeta = (int16_t)-zeta;
		}
	}
}

/*
 * Byte encoding, FIPS 203 Algorithms 5 and 6, for d bits per value
 */

static void
pack_bits(uint8_t *out, const uint16_t *v, unsigned int d)
{
	unsigned int i, bits = 0;
	uint32_t acc = 0;

	for (i = 0; i < MLKEM_N; i++) {
		acc |= (uint32_t)v[i] << bits;
		bits += d;
		while (bits >= 8) {
			*out++ = (uint8_t)acc;
			acc >>= 8;
			bits -= 8;
		}
	}
}

static void
unpack_bits(uint16_t *v, const uint8_t *in, unsigned int d)
{
	unsigned int i, bits = 0;
	uint32_t acc = 0;

	for (i = 0; i < MLKEM_N; i++) {
		while (bits < d) {
			acc |= (uint32_t)*in++ << bits;
			bits += 8;
		}
		v[i] = (uint16_t)(acc & ((1u << d) - 1));
		acc >>= d;
		bits -= d;
	}
}

/* a must be reduced */
static void
poly_tobytes(uint8_t *out, const mlkem_poly *a, uint16_t *tmp)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		tmp[i] = caddq(a->c[i]);

	pack_bits(out, tmp, 12);
}

/* coefficients come out < 4096, not reduced mod q */
static void
poly_frombytes(mlkem_poly *r, const uint8_t *in, uint16_t *tmp)
{
	unsigned int i;

	unpack_bits(tmp, in, 12);
	for (i = 0; i < MLKEM_N; i++)
		r->c[i] = (int16_t)tmp[i];
}

/* a must be reduced */
static void
poly_compress(uint8_t *out, const mlkem_poly *a, unsigned int d,
	      uint16_t *tmp)
{
	unsigned int i;

	for (i = 0; i < MLKEM_N; i++)
		tmp[i] = mlkem_compress(caddq(a->c[i]), d);

	pack_bits(out, tmp, d);
}

static void
poly_decompress(mlkem_poly *r, const uint8_t *in, unsigned int d,
		uint16_t *tmp)
{
	unsigned int i;

	unpack_bits(tmp, in, d);
	for (i = 0; i < MLKEM_N; i++)
		r->c[i] = mlkem_decompress(tmp[i], d);
}

/* each bit of the 32-byte m becomes 0 or (q + 1) / 2 */
static void
poly_frommsg(mlkem_poly *r, const uint8_t m[MLKEM_SYM_BYTES])
{
	unsigned int i;
	uint16_t mask;

	for (i = 0; i < MLKEM_N; i++) {
		mask = (uint16_t)(0u - (((uint32_t)m[i >> 3] >> (i & 7)) & 1u));
		r->c[i] = (int16_t)(mask & ((MLKEM_Q + 1) / 2));
	}
}

/*
 * Sampling
 */

/*
 * FIPS 203 Algorithm 7, SampleNTT(rho || x || y).  The matrix is public, so
 * this rejection sampling is allowed to be variable time
 */
static void
poly_sample_ntt(mlkem_poly *r, const uint8_t rho[MLKEM_SYM_BYTES],
		uint8_t x, uint8_t y)
{
	uint8_t buf[LWS_KECCAK_RATE_SHAKE128], xy[2] = { x, y };
	unsigned int ctr = 0, pos;
	struct lws_keccak k;
	uint16_t d1, d2;

	lws_keccak_init(&k, LWS_KECCAK_RATE_SHAKE128, LWS_KECCAK_DSEP_SHAKE);
	lws_keccak_absorb(&k, rho, MLKEM_SYM_BYTES);
	lws_keccak_absorb(&k, xy, sizeof(xy));
	lws_keccak_finalize(&k);

	while (ctr < MLKEM_N) {
		lws_keccak_squeeze(&k, buf, sizeof(buf));

		for (pos = 0; pos + 3 <= sizeof(buf) && ctr < MLKEM_N;
		     pos += 3) {
			d1 = (uint16_t)(buf[pos] |
					((uint16_t)(buf[pos + 1] & 0xf) << 8));
			d2 = (uint16_t)((buf[pos + 1] >> 4) |
					((uint16_t)buf[pos + 2] << 4));

			if (d1 < MLKEM_Q)
				r->c[ctr++] = (int16_t)d1;
			if (d2 < MLKEM_Q && ctr < MLKEM_N)
				r->c[ctr++] = (int16_t)d2;
		}
	}
}

/*
 * FIPS 203 Algorithm 8, SamplePolyCBD_eta(PRF_eta(seed, nonce)), for eta
 * 2 or 3
 */
static void
poly_sample_cbd(mlkem_poly *r, const uint8_t seed[MLKEM_SYM_BYTES],
		uint8_t nonce, unsigned int eta)
{
	uint8_t in[MLKEM_SYM_BYTES + 1], buf[64 * 3];
	unsigned int i, j;
	uint32_t t, d;

	memcpy(in, seed, MLKEM_SYM_BYTES);
	in[MLKEM_SYM_BYTES] = nonce;
	lws_shake256(buf, 64 * eta, in, sizeof(in));

	if (eta == 2)
		for (i = 0; i < MLKEM_N / 8; i++) {
			t = (uint32_t)buf[4 * i] |
			    ((uint32_t)buf[4 * i + 1] << 8) |
			    ((uint32_t)buf[4 * i + 2] << 16) |
			    ((uint32_t)buf[4 * i + 3] << 24);
			d = (t & 0x55555555u) + ((t >> 1) & 0x55555555u);
			for (j = 0; j < 8; j++)
				r->c[8 * i + j] = (int16_t)(
					(int)((d >> (4 * j)) & 3) -
					(int)((d >> (4 * j + 2)) & 3));
		}
	else
		for (i = 0; i < MLKEM_N / 4; i++) {
			t = (uint32_t)buf[3 * i] |
			    ((uint32_t)buf[3 * i + 1] << 8) |
			    ((uint32_t)buf[3 * i + 2] << 16);
			d = (t & 0x249249u) + ((t >> 1) & 0x249249u) +
			    ((t >> 2) & 0x249249u);
			for (j = 0; j < 4; j++)
				r->c[4 * i + j] = (int16_t)(
					(int)((d >> (6 * j)) & 7) -
					(int)((d >> (6 * j + 3)) & 7));
		}

	lws_explicit_bzero(in, sizeof(in));
	lws_explicit_bzero(buf, sizeof(buf));
}

/*
 * Constant time helpers
 */

/* stops the compiler reasoning about b, so it can't add a branch on it */
static uint8_t
ct_barrier(uint8_t b)
{
#if defined(__GNUC__) || defined(__clang__)
	__asm__ __volatile__("" : "+r"(b));
	return b;
#else
	volatile uint8_t v = b;

	return v;
#endif
}

/* returns 0 if equal, or 1 */
static uint8_t
ct_differ(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t r = 0;

	while (len--)
		r |= *a++ ^ *b++;

	return (uint8_t)((0u - (uint32_t)r) >> 31);
}

/* r = b if sel is 1, leaves r alone if sel is 0 */
static void
ct_cmov(uint8_t *r, const uint8_t *b, size_t len, uint8_t sel)
{
	uint8_t mask = (uint8_t)(0u - ct_barrier(sel));

	while (len--) {
		*r = (uint8_t)(*r ^ (mask & (*r ^ *b++)));
		r++;
	}
}

/*
 * K-PKE, FIPS 203 Algorithms 13 - 15
 */

static size_t
ek_len(const struct mlkem_params *p)
{
	return (size_t)MLKEM_POLY_BYTES * p->k + MLKEM_SYM_BYTES;
}

static size_t
ct_len(const struct mlkem_params *p)
{
	return (size_t)32 * ((size_t)p->du * p->k + p->dv);
}

static void
pke_keygen(struct mlkem_ws *ws, const struct mlkem_params *p,
	   const uint8_t d[MLKEM_SYM_BYTES], uint8_t *ek, uint8_t *dk_pke)
{
	uint8_t g_in[MLKEM_SYM_BYTES + 1], rho_sigma[64];
	const uint8_t *rho = rho_sigma, *sigma = rho_sigma + 32;
	uint8_t i, j;

	/* (rho, sigma) = G(d || k) */

	memcpy(g_in, d, MLKEM_SYM_BYTES);
	g_in[MLKEM_SYM_BYTES] = p->k;
	lws_sha3_512(rho_sigma, g_in, sizeof(g_in));

	/* s^ = NTT(s), with PRF nonces 0 .. k - 1 */

	for (i = 0; i < p->k; i++) {
		poly_sample_cbd(&ws->vec[i], sigma, i, p->eta1);
		poly_ntt(&ws->vec[i]);
		poly_tobytes(dk_pke + MLKEM_POLY_BYTES * i, &ws->vec[i],
			     ws->tmp);
	}

	/*
	 * t^[i] = sum_j A^[i][j] * s^[j] + NTT(e[i]), with
	 * A^[i][j] = SampleNTT(rho || j || i) and e[i] from nonce k + i
	 */

	for (i = 0; i < p->k; i++) {
		poly_zero(&ws->acc);
		for (j = 0; j < p->k; j++) {
			poly_sample_ntt(&ws->a, rho, j, i);
			poly_basemul_acc(&ws->acc, &ws->a, &ws->vec[j]);
		}
		poly_reduce(&ws->acc);
		poly_tomont(&ws->acc);

		poly_sample_cbd(&ws->e, sigma, (uint8_t)(p->k + i), p->eta1);
		poly_ntt(&ws->e);
		poly_add(&ws->acc, &ws->e);
		poly_reduce(&ws->acc);

		poly_tobytes(ek + MLKEM_POLY_BYTES * i, &ws->acc, ws->tmp);
	}

	memcpy(ek + MLKEM_POLY_BYTES * p->k, rho, MLKEM_SYM_BYTES);

	lws_explicit_bzero(g_in, sizeof(g_in));
	lws_explicit_bzero(rho_sigma, sizeof(rho_sigma));
}

static void
pke_encrypt(struct mlkem_ws *ws, const struct mlkem_params *p,
	    const uint8_t *ek, const uint8_t m[MLKEM_SYM_BYTES],
	    const uint8_t r[MLKEM_SYM_BYTES], uint8_t *ct)
{
	const uint8_t *rho = ek + MLKEM_POLY_BYTES * p->k;
	uint8_t i, j;

	/* y^ = NTT(y), with PRF nonces 0 .. k - 1 */

	for (i = 0; i < p->k; i++) {
		poly_sample_cbd(&ws->vec[i], r, i, p->eta1);
		poly_ntt(&ws->vec[i]);
	}

	/*
	 * u[i] = NTT^-1(sum_j A^T[i][j] * y^[j]) + e1[i], where
	 * A^T[i][j] = A^[j][i] = SampleNTT(rho || i || j), and e1[i] is from
	 * nonce k + i
	 */

	for (i = 0; i < p->k; i++) {
		poly_zero(&ws->acc);
		for (j = 0; j < p->k; j++) {
			poly_sample_ntt(&ws->a, rho, i, j);
			poly_basemul_acc(&ws->acc, &ws->a, &ws->vec[j]);
		}
		poly_reduce(&ws->acc);
		poly_invntt(&ws->acc);

		poly_sample_cbd(&ws->e, r, (uint8_t)(p->k + i), 2);
		poly_add(&ws->acc, &ws->e);
		poly_reduce(&ws->acc);

		poly_compress(ct + 32 * p->du * i, &ws->acc, p->du, ws->tmp);
	}

	/* v = NTT^-1(t^ . y^) + e2 + Decompress_1(m), e2 from nonce 2k */

	poly_zero(&ws->acc);
	for (j = 0; j < p->k; j++) {
		/* the EK passed the modulus check, so t^ is reduced */
		poly_frombytes(&ws->a, ek + MLKEM_POLY_BYTES * j, ws->tmp);
		poly_basemul_acc(&ws->acc, &ws->a, &ws->vec[j]);
	}
	poly_reduce(&ws->acc);
	poly_invntt(&ws->acc);

	poly_sample_cbd(&ws->e, r, (uint8_t)(2 * p->k), 2);
	poly_add(&ws->acc, &ws->e);
	poly_frommsg(&ws->e, m);
	poly_add(&ws->acc, &ws->e);
	poly_reduce(&ws->acc);

	poly_compress(ct + 32 * p->du * p->k, &ws->acc, p->dv, ws->tmp);
}

static void
pke_decrypt(struct mlkem_ws *ws, const struct mlkem_params *p,
	    const uint8_t *dk_pke, const uint8_t *ct,
	    uint8_t m[MLKEM_SYM_BYTES])
{
	unsigned int i;

	/* w = v - NTT^-1(s^ . NTT(u)) */

	poly_zero(&ws->acc);
	for (i = 0; i < p->k; i++) {
		poly_decompress(&ws->a, ct + 32 * p->du * i, p->du, ws->tmp);
		poly_ntt(&ws->a);
		poly_frombytes(&ws->vec[0], dk_pke + MLKEM_POLY_BYTES * i,
			       ws->tmp);
		poly_basemul_acc(&ws->acc, &ws->vec[0], &ws->a);
	}
	poly_reduce(&ws->acc);
	poly_invntt(&ws->acc);

	poly_decompress(&ws->a, ct + 32 * p->du * p->k, p->dv, ws->tmp);
	poly_sub_from(&ws->acc, &ws->a);
	poly_reduce(&ws->acc);

	/* m = ByteEncode_1(Compress_1(w)) */

	for (i = 0; i < MLKEM_N; i++)
		ws->tmp[i] = mlkem_compress(caddq(ws->acc.c[i]), 1);
	pack_bits(m, ws->tmp, 1);
}

static struct mlkem_ws *
ws_create(size_t extra)
{
	return (struct mlkem_ws *)lws_malloc(sizeof(struct mlkem_ws) + extra,
					     "mlkem");
}

static void
ws_destroy(struct mlkem_ws *ws, size_t extra)
{
	lws_explicit_bzero(ws, sizeof(*ws) + extra);
	lws_free(ws);
}

/*
 * ML-KEM, FIPS 203 Algorithms 16 - 18
 */

int
lws_mlkem_keypair_derand(enum lws_genkem_alg alg,
			 const uint8_t seed[LWS_GENKEM_SEED_LEN],
			 uint8_t *ek, uint8_t *dk)
{
	const struct mlkem_params *p;
	struct mlkem_ws *ws;
	uint8_t *q;

	if ((unsigned int)alg >= LWS_ARRAY_SIZE(mlkem_params))
		return -1;
	p = &mlkem_params[alg];

	ws = ws_create(0);
	if (!ws)
		return -1;

	/* dk = dk_pke || ek || H(ek) || z, with seed = d || z */

	pke_keygen(ws, p, seed, ek, dk);
	ws_destroy(ws, 0);

	q = dk + MLKEM_POLY_BYTES * p->k;
	memcpy(q, ek, ek_len(p));
	q += ek_len(p);
	lws_sha3_256(q, ek, ek_len(p));
	memcpy(q + MLKEM_SYM_BYTES, seed + MLKEM_SYM_BYTES, MLKEM_SYM_BYTES);

	return 0;
}

int
lws_mlkem_encaps_derand(enum lws_genkem_alg alg, const uint8_t *ek,
			const uint8_t m[32], uint8_t *ct,
			uint8_t ss[LWS_GENKEM_SS_LEN])
{
	uint8_t g_in[2 * MLKEM_SYM_BYTES], k_r[64];
	const struct mlkem_params *p;
	struct mlkem_ws *ws;

	if ((unsigned int)alg >= LWS_ARRAY_SIZE(mlkem_params))
		return -1;
	p = &mlkem_params[alg];

	ws = ws_create(0);
	if (!ws)
		return -1;

	/* (K, r) = G(m || H(ek)) */

	memcpy(g_in, m, MLKEM_SYM_BYTES);
	lws_sha3_256(g_in + MLKEM_SYM_BYTES, ek, ek_len(p));
	lws_sha3_512(k_r, g_in, sizeof(g_in));

	pke_encrypt(ws, p, ek, m, k_r + MLKEM_SYM_BYTES, ct);
	ws_destroy(ws, 0);

	memcpy(ss, k_r, LWS_GENKEM_SS_LEN);

	lws_explicit_bzero(g_in, sizeof(g_in));
	lws_explicit_bzero(k_r, sizeof(k_r));

	return 0;
}

int
lws_mlkem_decaps(enum lws_genkem_alg alg, const uint8_t *dk,
		 const uint8_t *ct, uint8_t ss[LWS_GENKEM_SS_LEN])
{
	uint8_t g_in[2 * MLKEM_SYM_BYTES], k_r[64], k_bar[MLKEM_SYM_BYTES];
	const uint8_t *ek, *h, *z;
	const struct mlkem_params *p;
	struct mlkem_ws *ws;
	struct lws_keccak k;
	uint8_t *ct2, fail;
	size_t clen;

	if ((unsigned int)alg >= LWS_ARRAY_SIZE(mlkem_params))
		return -1;
	p = &mlkem_params[alg];
	clen = ct_len(p);

	ek = dk + MLKEM_POLY_BYTES * p->k;
	h = ek + ek_len(p);
	z = h + MLKEM_SYM_BYTES;

	/* the re-encryption goes in the workspace allocation, after ws */
	ws = ws_create(clen);
	if (!ws)
		return -1;
	ct2 = (uint8_t *)&ws[1];

	/* m' = Decrypt(dk_pke, c), (K', r') = G(m' || h) */

	pke_decrypt(ws, p, dk, ct, g_in);
	memcpy(g_in + MLKEM_SYM_BYTES, h, MLKEM_SYM_BYTES);
	lws_sha3_512(k_r, g_in, sizeof(g_in));

	/* K_bar = J(z || c) */

	lws_keccak_init(&k, LWS_KECCAK_RATE_SHAKE256, LWS_KECCAK_DSEP_SHAKE);
	lws_keccak_absorb(&k, z, MLKEM_SYM_BYTES);
	lws_keccak_absorb(&k, ct, clen);
	lws_keccak_finalize(&k);
	lws_keccak_squeeze(&k, k_bar, sizeof(k_bar));

	/* if c != Encrypt(ek, m', r'), K' = K_bar */

	pke_encrypt(ws, p, ek, g_in, k_r + MLKEM_SYM_BYTES, ct2);
	fail = ct_differ(ct, ct2, clen);
	ct_cmov(k_r, k_bar, MLKEM_SYM_BYTES, fail);

	memcpy(ss, k_r, LWS_GENKEM_SS_LEN);

	ws_destroy(ws, clen);
	lws_explicit_bzero(&k, sizeof(k));
	lws_explicit_bzero(g_in, sizeof(g_in));
	lws_explicit_bzero(k_r, sizeof(k_r));
	lws_explicit_bzero(k_bar, sizeof(k_bar));

	return 0;
}

int
lws_mlkem_check_ek(enum lws_genkem_alg alg, const uint8_t *ek)
{
	const struct mlkem_params *p;
	uint16_t v[MLKEM_N];
	unsigned int i, n;

	if ((unsigned int)alg >= LWS_ARRAY_SIZE(mlkem_params))
		return -1;
	p = &mlkem_params[alg];

	/* ByteEncode_12(ByteDecode_12(t^)) == t^, ie, all coeffs < q */

	for (i = 0; i < p->k; i++) {
		unpack_bits(v, ek + MLKEM_POLY_BYTES * i, 12);
		for (n = 0; n < MLKEM_N; n++)
			if (v[n] >= MLKEM_Q)
				return 1;
	}

	return 0;
}

int
lws_mlkem_check_dk(enum lws_genkem_alg alg, const uint8_t *dk)
{
	const struct mlkem_params *p;
	uint8_t h[MLKEM_SYM_BYTES];
	const uint8_t *ek;

	if ((unsigned int)alg >= LWS_ARRAY_SIZE(mlkem_params))
		return -1;
	p = &mlkem_params[alg];

	/* H(dk[384k : 768k + 32]) == dk[768k + 32 : 768k + 64] */

	ek = dk + MLKEM_POLY_BYTES * p->k;
	lws_sha3_256(h, ek, ek_len(p));

	return ct_differ(h, ek + ek_len(p), sizeof(h));
}
