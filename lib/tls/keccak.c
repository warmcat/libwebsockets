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
 * FIPS 202 Keccak-f[1600] sponge, as needed by ML-KEM: SHA3-256, SHA3-512,
 * SHAKE128 and SHAKE256.
 *
 * Bytes go in and out of the lanes one at a time, little-endian, so this
 * doesn't care about the host byte order or alignment.
 */

#include "private-lib-core.h"
#include "private-genkem.h"

static const uint64_t keccak_rc[24] = {
	0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull,
	0x8000000080008000ull, 0x000000000000808bull, 0x0000000080000001ull,
	0x8000000080008081ull, 0x8000000000008009ull, 0x000000000000008aull,
	0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
	0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull,
	0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull,
	0x000000000000800aull, 0x800000008000000aull, 0x8000000080008081ull,
	0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull
};

/* rho rotation for lane x + 5y */
static const uint8_t keccak_rho[25] = {
	 0,  1, 62, 28, 27,
	36, 44,  6, 55, 20,
	 3, 10, 43, 25, 39,
	41, 45, 15, 21,  8,
	18,  2, 61, 56, 14
};

static uint64_t
rol64(uint64_t v, unsigned int n)
{
	return n ? (v << n) | (v >> (64 - n)) : v;
}

static void
keccak_f1600(uint64_t s[25])
{
	uint64_t c[5], d, b[25];
	int r, x, y;

	for (r = 0; r < 24; r++) {

		/* theta */

		for (x = 0; x < 5; x++)
			c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^
			       s[x + 20];
		for (x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1);
			for (y = 0; y < 25; y += 5)
				s[x + y] ^= d;
		}

		/* rho and pi: lane (x, y) moves to (y, 2x + 3y) */

		for (y = 0; y < 5; y++)
			for (x = 0; x < 5; x++)
				b[y + 5 * ((2 * x + 3 * y) % 5)] =
					rol64(s[x + 5 * y],
					      keccak_rho[x + 5 * y]);

		/* chi */

		for (y = 0; y < 25; y += 5)
			for (x = 0; x < 5; x++)
				s[x + y] = b[x + y] ^ ((~b[(x + 1) % 5 + y]) &
						       b[(x + 2) % 5 + y]);

		/* iota */

		s[0] ^= keccak_rc[r];
	}

	lws_explicit_bzero(b, sizeof(b));
	lws_explicit_bzero(c, sizeof(c));
}

static void
keccak_xor_byte(struct lws_keccak *k, unsigned int i, uint8_t v)
{
	k->s[i >> 3] ^= (uint64_t)v << (8 * (i & 7));
}

void
lws_keccak_init(struct lws_keccak *k, unsigned int rate, uint8_t dsep)
{
	memset(k, 0, sizeof(*k));
	k->rate = rate;
	k->dsep = dsep;
}

void
lws_keccak_absorb(struct lws_keccak *k, const uint8_t *in, size_t len)
{
	while (len--) {
		keccak_xor_byte(k, k->pos++, *in++);
		if (k->pos == k->rate) {
			keccak_f1600(k->s);
			k->pos = 0;
		}
	}
}

void
lws_keccak_finalize(struct lws_keccak *k)
{
	keccak_xor_byte(k, k->pos, k->dsep);
	keccak_xor_byte(k, k->rate - 1, 0x80);
	keccak_f1600(k->s);
	k->pos = 0;
}

void
lws_keccak_squeeze(struct lws_keccak *k, uint8_t *out, size_t len)
{
	while (len--) {
		if (k->pos == k->rate) {
			keccak_f1600(k->s);
			k->pos = 0;
		}
		*out++ = (uint8_t)(k->s[k->pos >> 3] >> (8 * (k->pos & 7)));
		k->pos++;
	}
}

static void
keccak_oneshot(unsigned int rate, uint8_t dsep, uint8_t *out, size_t out_len,
	       const uint8_t *in, size_t len)
{
	struct lws_keccak k;

	lws_keccak_init(&k, rate, dsep);
	lws_keccak_absorb(&k, in, len);
	lws_keccak_finalize(&k);
	lws_keccak_squeeze(&k, out, out_len);
	lws_explicit_bzero(&k, sizeof(k));
}

void
lws_sha3_256(uint8_t out[32], const uint8_t *in, size_t len)
{
	keccak_oneshot(LWS_KECCAK_RATE_SHA3_256, LWS_KECCAK_DSEP_SHA3,
		       out, 32, in, len);
}

void
lws_sha3_512(uint8_t out[64], const uint8_t *in, size_t len)
{
	keccak_oneshot(LWS_KECCAK_RATE_SHA3_512, LWS_KECCAK_DSEP_SHA3,
		       out, 64, in, len);
}

void
lws_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t len)
{
	keccak_oneshot(LWS_KECCAK_RATE_SHAKE256, LWS_KECCAK_DSEP_SHAKE,
		       out, out_len, in, len);
}
