/*
 * This code originally came from here
 *
 * http://base64.sourceforge.net/b64.c
 *
 * already with MIT license, which is retained.
 *
 * LICENCE:        Copyright (c) 2001 Bob Trower, Trantor Standard Systems Inc.
 *
 *                Permission is hereby granted, free of charge, to any person
 *                obtaining a copy of this software and associated
 *                documentation files (the "Software"), to deal in the
 *                Software without restriction, including without limitation
 *                the rights to use, copy, modify, merge, publish, distribute,
 *                sublicense, and/or sell copies of the Software, and to
 *                permit persons to whom the Software is furnished to do so,
 *                subject to the following conditions:
 *
 *                The above copyright notice and this permission notice shall
 *                be included in all copies or substantial portions of the
 *                Software.
 *
 *                THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 *                KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *                WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 *                PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 *                OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 *                OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 *                OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *                SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * VERSION HISTORY:
 *               Bob Trower 08/04/01 -- Create Version 0.00.00B
 *
 * I cleaned it up quite a bit to match the (linux kernel) style of the rest
 * of libwebsockets
 */

#include "private-lib-core.h"

#include <stdio.h>
#include <string.h>

static const char encode_orig[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			     "abcdefghijklmnopqrstuvwxyz0123456789+/";
static const char encode_url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			     "abcdefghijklmnopqrstuvwxyz0123456789-_";
static const char decode[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW"
			     "$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

static int
_lws_b64_encode_string(const char *encode, const char *in, int in_len,
		       char *out, int out_size)
{
	unsigned char triple[3];
	int i, done = 0;

	while (in_len) {
		int len = 0;
		for (i = 0; i < 3; i++) {
			if (in_len) {
				triple[i] = (unsigned char)*in++;
				len++;
				in_len--;
			} else
				triple[i] = 0;
		}

		if (done + 4 >= out_size)
			return -1;

		*out++ = encode[triple[0] >> 2];
		*out++ = encode[(((triple[0] & 0x03) << 4) & 0x30) |
					     (((triple[1] & 0xf0) >> 4) & 0x0f)];
		*out++ = (char)(len > 1 ? encode[(((triple[1] & 0x0f) << 2) & 0x3c) |
					(((triple[2] & 0xc0) >> 6) & 3)] : '=');
		*out++ = (char)(len > 2 ? encode[triple[2] & 0x3f] : '=');

		done += 4;
	}

	if (done + 1 >= out_size)
		return -1;

	*out++ = '\0';

	return done;
}

int
lws_b64_encode_string(const char *in, int in_len, char *out, int out_size)
{
	return _lws_b64_encode_string(encode_orig, in, in_len, out, out_size);
}

int
lws_b64_encode_string_url(const char *in, int in_len, char *out, int out_size)
{
	return _lws_b64_encode_string(encode_url, in, in_len, out, out_size);
}


void
lws_b64_decode_state_init(struct lws_b64state *state)
{
	memset(state, 0, sizeof(*state));
}

int
lws_b64_decode_stateful(struct lws_b64state *s, const char *in, size_t *in_len,
			uint8_t *out, size_t *out_size, int final)
{
	const char *orig_in = in, *end_in = in + *in_len;
	uint8_t *orig_out = out, *end_out = out + *out_size;
	int equals = 0;

	while ((in < end_in && *in && out + 3 <= end_out) || (final && s->i && out + 3 <= end_out)) {

		for (; s->i < 4 && in < end_in && *in; s->i++) {
			uint8_t v;

			v = 0;
			s->c = 0;
			while (in < end_in && *in && !v) {
				v = (unsigned char)*in++;

				if (v == '\x0a' || v == '\x0d') {
					v = 0;
					continue;
				}

				if (v == '=') {
					equals++;
					v = 0;
					continue;
				}

				s->c = v;

				/* Sanity check this is part of the charset */

				if ((v < '0' || v > '9') &&
				    (v < 'A' || v > 'Z') &&
				    (v < 'a' || v > 'z') &&
				    v != '-' && v != '+' && v != '_' && v != '/') {
					lwsl_err("%s: bad base64 0x%02X '%c' @+%d\n", __func__, v, v, lws_ptr_diff(in, orig_in));
					return -1;
				}

				if (equals) {
					lwsl_err("%s: non = after =\n", __func__);
					return -1;
				}

				/* support the url base64 variant too */
				if (v == '-')
					s->c = v = '+';
				if (v == '_')
					s->c = v = '/';
				v = (uint8_t)decode[v - 43];
				if (v)
					v = (uint8_t)((v == '$') ? 0 : v - 61);
			}
			if (s->c) {
				s->len++;
				if (v)
					s->quad[s->i] = (uint8_t)(v - 1);
			} else
				s->quad[s->i] = 0;
		}

		if (s->i != 4 && !final)
			continue;

		s->i = 0;

		/*
		 * Normally we convert a group of 4 incoming symbols into 3 bytes.
		 *
		 * "The 'XX==' sequence indicates that the last group contained
		 * only one byte, and 'XXX=' indicates that it contained two
		 * bytes." (wikipedia)
		 *
		 */

		if (s->len >= 2)
			*out++ = (uint8_t)(s->quad[0] << 2 | s->quad[1] >> 4);

		if (s->len >= 3 && equals != 2)
			*out++ = (uint8_t)(s->quad[1] << 4 | s->quad[2] >> 2);

		if (s->len >= 4 && equals != 1)
			*out++ = (uint8_t)(((s->quad[2] << 6) & 0xc0) | s->quad[3]);

		s->done += s->len - 1;
		s->len = 0;
	}

	if (out < end_out)
		*out = '\0';

	*in_len = (unsigned int)(in - orig_in);
	*out_size = (unsigned int)(out - orig_out);

	return 0;
}


/*
 * returns length of decoded string in out, or -1 if out was too small
 * according to out_size
 *
 * Only reads up to in_len chars, otherwise if in_len is -1 on entry reads until
 * the first NUL in the input.
 */

static size_t
_lws_b64_decode_string(const char *in, int in_len, char *out, size_t out_size)
{
	struct lws_b64state state;
	size_t il = (size_t)in_len, ol = out_size;

	if (in_len == -1) {
		il = strlen(in);
		in_len = (int)il;
	}

	lws_b64_decode_state_init(&state);
	if (lws_b64_decode_stateful(&state, in, &il, (uint8_t *)out, &ol, 1) < 0)
		/* pass on the failure */
		return 0;

	if ((int)il != in_len) {
		lwsl_err("%s: base64 must end at end of input\n", __func__);
		return 0;
	}

	return ol;
}

int
lws_b64_decode_string(const char *in, char *out, int out_size)
{
	return (int)_lws_b64_decode_string(in, -1, out, (unsigned int)out_size);
}

int
lws_b64_decode_string_len(const char *in, int in_len, char *out, int out_size)
{
	size_t s = _lws_b64_decode_string(in, in_len, out, (unsigned int)out_size);

	return !s ? -1 : (int)s;
}

static const char encode_b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int
lws_b32_encode_string(const char *in, int in_len, char *out, int out_size)
{
	unsigned char buf[5];
	int i, done = 0;

	while (in_len) {
		int len = 0;
		for (i = 0; i < 5; i++) {
			if (in_len) {
				buf[i] = (unsigned char)*in++;
				len++;
				in_len--;
			} else
				buf[i] = 0;
		}

		if (done + 8 >= out_size)
			return -1;

		out[0] = encode_b32[buf[0] >> 3];
		out[1] = encode_b32[((buf[0] & 0x07) << 2) | (buf[1] >> 6)];
		out[2] = len > 1 ? encode_b32[((buf[1] & 0x3e) >> 1)] : '=';
		out[3] = len > 1 ? encode_b32[((buf[1] & 0x01) << 4) | (buf[2] >> 4)] : '=';
		out[4] = len > 2 ? encode_b32[((buf[2] & 0x0f) << 1) | (buf[3] >> 7)] : '=';
		out[5] = len > 3 ? encode_b32[((buf[3] & 0x7c) >> 2)] : '=';
		out[6] = len > 3 ? encode_b32[((buf[3] & 0x03) << 3) | (buf[4] >> 5)] : '=';
		out[7] = len > 4 ? encode_b32[(buf[4] & 0x1f)] : '=';

		out += 8;
		done += 8;
	}

	if (done + 1 >= out_size)
		return -1;

	*out++ = '\0';

	return done;
}

static const int8_t decode_b32[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,26,27,28,29,30,31,-1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int
lws_b32_decode_string_len(const char *in, int in_len, char *out, int out_size)
{
	int done = 0;
	int buf[8] = {0};
	int i;

	if (in_len == -1)
		in_len = (int)strlen(in);

	while (in_len > 0) {
		int len = 0;
		for (i = 0; i < 8; i++) {
			while (in_len > 0 && (*in == ' ' || *in == '\t' || *in == '\n' || *in == '\r')) {
				in++;
				in_len--;
			}
			if (in_len > 0) {
				char c = *in++;
				in_len--;
				if (c == '=') {
					buf[i] = 0;
				} else {
					int8_t v = decode_b32[(unsigned char)c];
					if (v < 0) return -1;
					buf[i] = v;
					len++;
				}
			} else {
				buf[i] = 0;
			}
		}

		if (len == 0) break;

		if (done + 5 > out_size) return -1;

		out[0] = (char)((buf[0] << 3) | (buf[1] >> 2));
		out[1] = (char)(((buf[1] & 0x03) << 6) | (buf[2] << 1) | (buf[3] >> 4));
		out[2] = (char)(((buf[3] & 0x0f) << 4) | (buf[4] >> 1));
		out[3] = (char)(((buf[4] & 0x01) << 7) | (buf[5] << 2) | (buf[6] >> 3));
		out[4] = (char)(((buf[6] & 0x07) << 5) | buf[7]);

		if (len == 2) done += 1;
		else if (len == 4) done += 2;
		else if (len == 5) done += 3;
		else if (len == 7) done += 4;
		else if (len == 8) done += 5;
		else return -1; /* invalid base32 chunk */

		out += 5;
	}

	if (done < out_size)
		*out = '\0';

	return done;
}

int
lws_b32_decode_string(const char *in, char *out, int out_size)
{
	return lws_b32_decode_string_len(in, -1, out, out_size);
}

#if 0
static const char * const plaintext[] = {
	"any carnal pleasure.",
	"any carnal pleasure",
	"any carnal pleasur",
	"any carnal pleasu",
	"any carnal pleas",
	"Admin:kloikloi"
};
static const char * const coded[] = {
	"YW55IGNhcm5hbCBwbGVhc3VyZS4=",
	"YW55IGNhcm5hbCBwbGVhc3VyZQ==",
	"YW55IGNhcm5hbCBwbGVhc3Vy",
	"YW55IGNhcm5hbCBwbGVhc3U=",
	"YW55IGNhcm5hbCBwbGVhcw==",
	"QWRtaW46a2xvaWtsb2k="
};

int
lws_b64_selftest(void)
{
	char buf[64];
	unsigned int n,  r = 0;
	unsigned int test;

	lwsl_notice("%s\n", __func__);

	/* examples from https://en.wikipedia.org/wiki/Base64 */

	for (test = 0; test < (int)LWS_ARRAY_SIZE(plaintext); test++) {

		buf[sizeof(buf) - 1] = '\0';
		n = lws_b64_encode_string(plaintext[test],
				      strlen(plaintext[test]), buf, sizeof buf);
		if (n != strlen(coded[test]) || strcmp(buf, coded[test])) {
			lwsl_err("Failed lws_b64 encode selftest "
					   "%d result '%s' %d\n", test, buf, n);
			r = -1;
		}

		buf[sizeof(buf) - 1] = '\0';
		n = lws_b64_decode_string(coded[test], buf, sizeof buf);
		if (n != strlen(plaintext[test]) ||
		    strcmp(buf, plaintext[test])) {
			lwsl_err("Failed lws_b64 decode selftest "
				 "%d result '%s' / '%s', %d / %zu\n",
				 test, buf, plaintext[test], n,
				 strlen(plaintext[test]));
			lwsl_hexdump_err(buf, n);
			r = -1;
		}
	}

	if (!r)
		lwsl_notice("Base 64 selftests passed\n");
	else
		lwsl_notice("Base64 selftests failed\n");

	return r;
}
#endif
