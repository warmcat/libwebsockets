/*
 * Modified from Polarssl here
 * http://polarssl.org/show_source?file=md5
 * under GPL2 or later
 */

#include <string.h>
#include <stdio.h>


#define GET_ULONG_LE(n, b, i)                        \
{                                                    \
	(n) = ((unsigned long)(b)[i])		     \
	| ((unsigned long)(b)[(i) + 1] <<  8)        \
	| ((unsigned long)(b)[(i) + 2] << 16)        \
	| ((unsigned long)(b)[(i) + 3] << 24);       \
}

#define PUT_ULONG_LE(n, b, i)			     \
{						     \
	(b)[i] = (unsigned char)(n);		     \
	(b)[(i) + 1] = (unsigned char)((n) >>  8);   \
	(b)[(i) + 2] = (unsigned char)((n) >> 16);   \
	(b)[(i) + 3] = (unsigned char)((n) >> 24);   \
}

static const unsigned char md5_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

static const unsigned long state_init[] = {
	0, 0, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
};

static void
md5_process(unsigned long *state, const unsigned char *data)
{
	unsigned long X[16], A, B, C, D;
	int v;

	for (v = 0; v < 16; v++)
		GET_ULONG_LE(X[v], data, v << 2);

#define S(x, n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define P(a, b, c, d, k, s, t) { a += F(b, c, d) + X[k] + t; a = S(a, s) + b; }

	A = state[0];
	B = state[1];
	C = state[2];
	D = state[3];

#define F(x, y, z) (z ^ (x & (y ^ z)))

	P(A, B, C, D,  0,  7, 0xD76AA478);
	P(D, A, B, C,  1, 12, 0xE8C7B756);
	P(C, D, A, B,  2, 17, 0x242070DB);
	P(B, C, D, A,  3, 22, 0xC1BDCEEE);
	P(A, B, C, D,  4,  7, 0xF57C0FAF);
	P(D, A, B, C,  5, 12, 0x4787C62A);
	P(C, D, A, B,  6, 17, 0xA8304613);
	P(B, C, D, A,  7, 22, 0xFD469501);
	P(A, B, C, D,  8,  7, 0x698098D8);
	P(D, A, B, C,  9, 12, 0x8B44F7AF);
	P(C, D, A, B, 10, 17, 0xFFFF5BB1);
	P(B, C, D, A, 11, 22, 0x895CD7BE);
	P(A, B, C, D, 12,  7, 0x6B901122);
	P(D, A, B, C, 13, 12, 0xFD987193);
	P(C, D, A, B, 14, 17, 0xA679438E);
	P(B, C, D, A, 15, 22, 0x49B40821);

#undef F

#define F(x, y, z) (y ^ (z & (x ^ y)))

	P(A, B, C, D,  1,  5, 0xF61E2562);
	P(D, A, B, C,  6,  9, 0xC040B340);
	P(C, D, A, B, 11, 14, 0x265E5A51);
	P(B, C, D, A,  0, 20, 0xE9B6C7AA);
	P(A, B, C, D,  5,  5, 0xD62F105D);
	P(D, A, B, C, 10,  9, 0x02441453);
	P(C, D, A, B, 15, 14, 0xD8A1E681);
	P(B, C, D, A,  4, 20, 0xE7D3FBC8);
	P(A, B, C, D,  9,  5, 0x21E1CDE6);
	P(D, A, B, C, 14,  9, 0xC33707D6);
	P(C, D, A, B,  3, 14, 0xF4D50D87);
	P(B, C, D, A,  8, 20, 0x455A14ED);
	P(A, B, C, D, 13,  5, 0xA9E3E905);
	P(D, A, B, C,  2,  9, 0xFCEFA3F8);
	P(C, D, A, B,  7, 14, 0x676F02D9);
	P(B, C, D, A, 12, 20, 0x8D2A4C8A);

#undef F

#define F(x, y, z) (x ^ y ^ z)

	P(A, B, C, D,  5,  4, 0xFFFA3942);
	P(D, A, B, C,  8, 11, 0x8771F681);
	P(C, D, A, B, 11, 16, 0x6D9D6122);
	P(B, C, D, A, 14, 23, 0xFDE5380C);
	P(A, B, C, D,  1,  4, 0xA4BEEA44);
	P(D, A, B, C,  4, 11, 0x4BDECFA9);
	P(C, D, A, B,  7, 16, 0xF6BB4B60);
	P(B, C, D, A, 10, 23, 0xBEBFBC70);
	P(A, B, C, D, 13,  4, 0x289B7EC6);
	P(D, A, B, C,  0, 11, 0xEAA127FA);
	P(C, D, A, B,  3, 16, 0xD4EF3085);
	P(B, C, D, A,  6, 23, 0x04881D05);
	P(A, B, C, D,  9,  4, 0xD9D4D039);
	P(D, A, B, C, 12, 11, 0xE6DB99E5);
	P(C, D, A, B, 15, 16, 0x1FA27CF8);
	P(B, C, D, A,  2, 23, 0xC4AC5665);

#undef F

#define F(x, y, z) (y ^ (x | ~z))

	P(A, B, C, D,  0,  6, 0xF4292244);
	P(D, A, B, C,  7, 10, 0x432AFF97);
	P(C, D, A, B, 14, 15, 0xAB9423A7);
	P(B, C, D, A,  5, 21, 0xFC93A039);
	P(A, B, C, D, 12,  6, 0x655B59C3);
	P(D, A, B, C,  3, 10, 0x8F0CCC92);
	P(C, D, A, B, 10, 15, 0xFFEFF47D);
	P(B, C, D, A,  1, 21, 0x85845DD1);
	P(A, B, C, D,  8,  6, 0x6FA87E4F);
	P(D, A, B, C, 15, 10, 0xFE2CE6E0);
	P(C, D, A, B,  6, 15, 0xA3014314);
	P(B, C, D, A, 13, 21, 0x4E0811A1);
	P(A, B, C, D,  4,  6, 0xF7537E82);
	P(D, A, B, C, 11, 10, 0xBD3AF235);
	P(C, D, A, B,  2, 15, 0x2AD7D2BB);
	P(B, C, D, A,  9, 21, 0xEB86D391);

#undef F

	state[0] += A;
	state[1] += B;
	state[2] += C;
	state[3] += D;
}

static
void md5_update(unsigned long *state, unsigned char *buffer,
					   const unsigned char *input, int ilen)
{
	int fill;
	unsigned long left;

	if (ilen <= 0)
		return;

	left = state[0] & 0x3F;
	fill = 64 - left;

	state[0] += ilen;
	state[0] &= 0xFFFFFFFF;

	if (state[0] < (unsigned long)ilen)
		state[1]++;

	if (left && ilen >= fill) {
		memcpy(buffer + left, input, fill);
		md5_process(&state[2], buffer);
		input += fill;
		ilen -= fill;
		left = 0;
	}

	while (ilen >= 64) {
		md5_process(&state[2], input);
		input += 64;
		ilen -= 64;
	}

	if (ilen > 0)
		memcpy(buffer + left, input, ilen);
}

void
MD5(const unsigned char *input, int ilen, unsigned char *output)
{
	unsigned long last, padn;
	unsigned long high, low;
	unsigned char msglen[8];
	unsigned long state[6];
	unsigned char buffer[64];

	memcpy(&state[0], &state_init[0], sizeof(state_init));

	md5_update(state, buffer, input, ilen);

	high = (state[0] >> 29) | (state[1] <<  3);
	low  = state[0] <<  3;

	PUT_ULONG_LE(low, msglen, 0);
	PUT_ULONG_LE(high, msglen, 4);

	last = state[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	md5_update(state, buffer, md5_padding, padn);
	md5_update(state, buffer, msglen, 8);

	PUT_ULONG_LE(state[2], output, 0);
	PUT_ULONG_LE(state[3], output, 4);
	PUT_ULONG_LE(state[4], output, 8);
	PUT_ULONG_LE(state[5], output, 12);
}

