/*
 * libwebsockets - libFuzzer target for lws_tokenize and the core string helpers
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
 * lws_tokenize is the shared lexer under ~20 lws parsers (headers, alt-svc,
 * policy, conf files, dns, ...), so one harness here covers all of their
 * lexing exposure.  The other helpers in lib/core/libwebsockets.c and
 * base64-decode.c are the small hand-rolled decoders that turn up in the
 * same places (b64 / b32 / hex / urldecode / dumb-json / strexp / iso8601 /
 * uri / humanize / purify).
 *
 * Input layout:
 *
 *   [0]     selects which helper to run (mod 16)
 *   [1..2]  16-bit LE flags: lws_tokenize flags, or a small length / mode
 *           for the other helpers
 *   [3..]   payload; it is copied to a heap buffer with a trailing NUL so
 *           both the (buf, len) and NUL-terminated variants are valid, and
 *           any read past the end is caught by ASan
 *
 * Output buffers are deliberately small so length-bounding bugs show up as
 * overflows rather than being absorbed by slack.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	return 0;
}

static int
exp_cb(void *priv, const char *name, char *out, size_t *pos, size_t olen,
       size_t *exp_ofs)
{
	const char *replace = "0123456789abcdef";
	size_t total = strlen(replace), budget;

	(void)priv;

	/* one unknown name, so both callback outcomes are reachable */
	if (name[0] == 'x')
		return LSTRX_FATAL_NAME_UNKNOWN;

	if (*exp_ofs > total)
		return LSTRX_FATAL_NAME_UNKNOWN;

	budget = olen - *pos;
	total -= *exp_ofs;
	if (total < budget)
		budget = total;

	if (out)
		memcpy(out + *pos, replace + (*exp_ofs), budget);
	*exp_ofs += budget;
	*pos += budget;

	if (budget == total)
		return LSTRX_DONE;

	return LSTRX_FILLED_OUT;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned int sel, flags;
	size_t len, n, alen;
	uint8_t bin[8];
	char *buf, out[32];
	int e;

	if (size < 3)
		return 0;

	sel = data[0] % 16;
	flags = (unsigned int)data[1] | ((unsigned int)data[2] << 8);
	len = size - 3;

	buf = malloc(len + 1);
	if (!buf)
		return 0;
	memcpy(buf, data + 3, len);
	buf[len] = '\0';

	switch (sel) {
	case 0: { /* lws_tokenize with the flags from the input */
		struct lws_tokenize ts;
		char tok[8];

		lws_tokenize_init(&ts, buf, (int)flags);
		ts.len = len;
		n = 0;

		do {
			e = lws_tokenize(&ts);
			if (e < 0)
				break;

			/* C-176: token_len must be sane for every elem */
			lws_tokenize_cstr(&ts, tok, sizeof(tok));

			/*
			 * every call must consume input or end; if we are
			 * still going after more calls than input bytes,
			 * the tokenizer is stuck: make that a finding rather
			 * than a libFuzzer timeout
			 */
			if (++n > len + 64)
				__builtin_trap();
		} while (e != LWS_TOKZE_ENDED);
		break;
	}

	case 1: { /* base64 */
		struct lws_b64state s;
		size_t il, ol, half = len / 2;

		lws_b64_decode_string_len(buf, (int)len, out, sizeof(out));
		lws_b64_decode_string(buf, out, sizeof(out));

		lws_b64_decode_state_init(&s);
		il = half;
		ol = sizeof(out);
		lws_b64_decode_stateful(&s, buf, &il, (uint8_t *)out, &ol, 0);
		il = len - half;
		ol = sizeof(out);
		lws_b64_decode_stateful(&s, buf + half, &il, (uint8_t *)out,
					&ol, 1);

		lws_b64_encode_string(buf, (int)len, out, sizeof(out));
		break;
	}

	case 2: /* base32 (C-111) */
		lws_b32_decode_string_len(buf, (int)len, out, sizeof(out));
		lws_b32_decode_string(buf, out, sizeof(out));
		lws_b32_encode_string(buf, (int)len, out, sizeof(out));
		break;

	case 3: /* hex (C-182, C-306) */
		lws_hex_len_to_byte_array(buf, len, bin, sizeof(bin));
		lws_hex_to_byte_array(buf, bin, sizeof(bin));
		/* dest size 0..32 == sizeof(out): a write at [len] overflows */
		lws_hex_from_byte_array((const uint8_t *)buf, len, out,
					(flags & 31) + 1);
		break;

	case 4: /* url decode / encode: len is the output size 1..32 (C-180) */
		lws_urldecode(out, buf, (int)(flags & 31) + 1);
		lws_urlencode(out, buf, (int)(flags & 31) + 1);
		break;

	case 5: /* dumb JSON string find (C-179) */
		lws_json_simple_find(buf, len, "\"a\":", &alen);
		lws_json_simple_strcmp(buf, len, "\"a\":", "b");
		lws_nstrstr(buf, len, "ab", 2);
		break;

	case 6: { /* strexp, resumed after FILLED_OUT (C-183) */
		size_t used_in, used_out, pos = 0;
		lws_strexp_t exp;
		char obuf[8];

		lws_strexp_init(&exp, NULL, exp_cb, obuf, sizeof(obuf));
		n = 0;
		do {
			e = lws_strexp_expand(&exp, buf + pos, len - pos,
					      &used_in, &used_out);
			if (used_in > len - pos)
				__builtin_trap();
			pos += used_in;
			if (e != LSTRX_FILLED_OUT)
				break;
			lws_strexp_reset_out(&exp, obuf, sizeof(obuf));
			if (++n > len + 64)
				__builtin_trap();
		} while (1);
		break;
	}

	case 7: /* wildcard compare, both halves of the input (C-184) */
		lws_strcmp_wildcard(buf, len / 2, buf + len / 2, len - len / 2);
		lws_strcmp_wildcard(buf, len, buf, len);
		break;

	case 8: /* iso8601 date */
		lws_parse_iso8601(buf);
		break;

	case 9: { /* URI parse */
		lws_parse_uri_t *u = lws_parse_uri_create(buf);

		if (u)
			lws_parse_uri_destroy(&u);
		break;
	}

	case 10: { /* humanize into a buffer of the given size (C-177, C-178) */
		const lws_humanize_unit_t *schema[] = { humanize_schema_si,
					humanize_schema_si_bytes, humanize_schema_us };
		char hb[32];
		uint64_t v = 0;

		memset(hb, 0, sizeof(hb));
		for (n = 0; n < 8 && n < len; n++)
			v = (v << 8) | (uint8_t)buf[n];

		/* len 0..31 into hb[32], so writes at len + 1 are inside hb:
		 * C-177 / C-178 were writes *before* and the numeric part
		 * exceeding len, which still show as overflows at len 0 */
		lws_humanize(hb, flags & 31, v, schema[(flags >> 8) % 3]);
		lws_humanize_pad(hb, flags & 31, v, schema[(flags >> 8) % 3]);
		break;
	}

	case 11: { /* purify helpers: len is the output buffer size */
		int in_used;

		lws_sql_purify(out, buf, sizeof(out));
		lws_json_purify(out, buf, sizeof(out), &in_used);
		lws_json_purify_len(buf);
		break;
	}

	default:
		break;
	}

	free(buf);

	return 0;
}
