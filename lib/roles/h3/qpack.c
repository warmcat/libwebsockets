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
 */

#include "private-lib-core.h"
#include "private-lib-roles-h3.h"
#include "../h2/huftable.h"

/*
 * QPACK Static Table (RFC 9204 Appendix A)
 * 99 entries.
 */
static const unsigned char qpack_static_token[99] = {
	WSI_TOKEN_HTTP_COLON_AUTHORITY,
	WSI_TOKEN_HTTP_COLON_PATH,
	WSI_TOKEN_HTTP_AGE,
	WSI_TOKEN_HTTP_CONTENT_DISPOSITION,
	WSI_TOKEN_HTTP_CONTENT_LENGTH,
	WSI_TOKEN_HTTP_COOKIE,
	WSI_TOKEN_HTTP_DATE,
	WSI_TOKEN_HTTP_ETAG,
	WSI_TOKEN_HTTP_IF_MODIFIED_SINCE,
	WSI_TOKEN_HTTP_IF_NONE_MATCH, /* 9 */
	WSI_TOKEN_HTTP_LAST_MODIFIED,
	WSI_TOKEN_HTTP_LINK,
	WSI_TOKEN_HTTP_LOCATION,
	WSI_TOKEN_HTTP_REFERER,
	WSI_TOKEN_HTTP_SET_COOKIE,
	WSI_TOKEN_HTTP_COLON_METHOD, /* CONNECT */
	WSI_TOKEN_HTTP_COLON_METHOD, /* DELETE */
	WSI_TOKEN_HTTP_COLON_METHOD, /* GET */
	WSI_TOKEN_HTTP_COLON_METHOD, /* HEAD */
	WSI_TOKEN_HTTP_COLON_METHOD, /* OPTIONS */
	WSI_TOKEN_HTTP_COLON_METHOD, /* POST */
	WSI_TOKEN_HTTP_COLON_METHOD, /* PUT */
	WSI_TOKEN_HTTP_COLON_SCHEME, /* http */
	WSI_TOKEN_HTTP_COLON_SCHEME, /* https */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 103 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 200 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 304 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 404 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 503 */
	WSI_TOKEN_HTTP_ACCEPT, /* star/star */
	WSI_TOKEN_HTTP_ACCEPT, /* application/dns-message */
	WSI_TOKEN_HTTP_ACCEPT_ENCODING, /* gzip, deflate, br */
	WSI_TOKEN_HTTP_ACCEPT_RANGES, /* bytes */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-headers: cache-control */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-headers: content-type */
	WSI_TOKEN_HTTP_ACCESS_CONTROL_ALLOW_ORIGIN, /* * */
	WSI_TOKEN_HTTP_CACHE_CONTROL, /* max-age=0 */
	WSI_TOKEN_HTTP_CACHE_CONTROL, /* max-age=2592000 */
	WSI_TOKEN_HTTP_CACHE_CONTROL, /* max-age=604800 */
	WSI_TOKEN_HTTP_CACHE_CONTROL, /* no-cache */
	WSI_TOKEN_HTTP_CACHE_CONTROL, /* no-store */
	WSI_TOKEN_HTTP_CACHE_CONTROL, /* public, max-age=31536000 */
	WSI_TOKEN_HTTP_CONTENT_ENCODING, /* br */
	WSI_TOKEN_HTTP_CONTENT_ENCODING, /* gzip */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* application/dns-message */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* application/javascript */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* application/json */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* application/x-www-form-urlencoded */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* image/gif */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* image/jpeg */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* image/png */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* text/css */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* text/html; charset=utf-8 */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* text/plain */
	WSI_TOKEN_HTTP_CONTENT_TYPE, /* text/plain;charset=utf-8 */
	WSI_TOKEN_HTTP_RANGE, /* bytes=0- */
	WSI_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY, /* max-age=31536000 */
	WSI_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY, /* max-age=31536000; includesubdomains */
	WSI_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY, /* max-age=31536000; includesubdomains; preload */
	WSI_TOKEN_HTTP_VARY, /* accept-encoding */
	WSI_TOKEN_HTTP_VARY, /* origin */
	LWS_QPACK_IGNORE_ENTRY, /* x-content-type-options */
	LWS_QPACK_IGNORE_ENTRY, /* x-xss-protection */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 100 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 204 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 206 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 302 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 400 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 403 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 421 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 425 */
	WSI_TOKEN_HTTP_COLON_STATUS, /* 500 */
	WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-credentials */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-credentials */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-headers */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-methods */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-methods */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-allow-methods */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-expose-headers */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-request-headers */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-request-method */
	LWS_QPACK_IGNORE_ENTRY, /* access-control-request-method */
	LWS_QPACK_IGNORE_ENTRY, /* alt-svc */
	WSI_TOKEN_HTTP_AUTHORIZATION,
	LWS_QPACK_IGNORE_ENTRY, /* content-security-policy */
	LWS_QPACK_IGNORE_ENTRY, /* early-data */
	WSI_TOKEN_HTTP_EXPECT,
	LWS_QPACK_IGNORE_ENTRY, /* forwarded */
	WSI_TOKEN_HTTP_IF_RANGE,
	WSI_TOKEN_ORIGIN,
	LWS_QPACK_IGNORE_ENTRY, /* purpose */
	WSI_TOKEN_HTTP_SERVER,
	LWS_QPACK_IGNORE_ENTRY, /* timing-allow-origin */
	LWS_QPACK_IGNORE_ENTRY, /* upgrade-insecure-requests */
	WSI_TOKEN_HTTP_USER_AGENT,
	WSI_TOKEN_X_FORWARDED_FOR,
	LWS_QPACK_IGNORE_ENTRY, /* x-frame-options */
	LWS_QPACK_IGNORE_ENTRY  /* x-frame-options */
};

static const char * const qpack_canned[] = {
	"", "/", "0", "", "0", "", "", "", "", "",
	"", "", "", "", "", "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS",
	"POST", "PUT", "http", "https", "103", "200", "304", "404", "503", "*/*",
	"application/dns-message", "gzip, deflate, br", "bytes", "cache-control", "content-type", "*", "max-age=0", "max-age=2592000", "max-age=604800", "no-cache", "no-store", "public, max-age=31536000",
	"br", "gzip", "application/dns-message", "application/javascript", "application/json", "application/x-www-form-urlencoded", "image/gif", "image/jpeg", "image/png", "text/css",
	"text/html; charset=utf-8", "text/plain", "text/plain;charset=utf-8", "bytes=0-", "max-age=31536000", "max-age=31536000; includesubdomains", "max-age=31536000; includesubdomains; preload", "accept-encoding", "origin", "nosniff",
	"1; mode=block", "100", "204", "206", "302", "400", "403", "421", "425", "500",
	"", "FALSE", "TRUE", "*", "get", "get, post, options", "options", "content-length", "content-type", "get",
	"post", "clear", "", "script-src 'none'; object-src 'none'; base-uri 'none'", "1", "100-continue", "", "", "", "prefetch",
	"", "*", "1", "", "", "deny", "sameorigin"
};

LWS_VISIBLE int
lws_qpack_find_static_index(int lws_hdr_idx, const char *value, int value_len)
{
	int i;
	
	/* Fast path for matches with value */
	if (value && value_len > 0) {
		for (i = 0; i < 99; i++) {
			if (qpack_static_token[i] == lws_hdr_idx) {
				if (!strncmp(qpack_canned[i], value, (size_t)value_len) && 
				    qpack_canned[i][value_len] == '\0') {
					return i;
				}
			}
		}
	}
	
	/* Fallback to matching just the name, taking the first match */
	for (i = 0; i < 99; i++) {
		if (qpack_static_token[i] == lws_hdr_idx) {
			return i;
		}
	}
	
	return -1;
}

LWS_VISIBLE int
lws_qpack_get_static_token(int index, int *lws_hdr_idx, const char **value)
{
	if (index < 0 || index >= 99)
		return 1;
		
	if (lws_hdr_idx)
		*lws_hdr_idx = qpack_static_token[index];
	if (value)
		*value = qpack_canned[index];
		
	return 0;
}

int
lws_qpack_encode_int(unsigned char *buf, size_t buf_len, uint64_t val, 
		     uint8_t prefix_bits, uint8_t prefix_mask)
{
	size_t pos = 0;
	uint64_t max_val = (1ULL << prefix_bits) - 1;

	if (buf_len < 1) return -1;

	if (val < max_val) {
		buf[pos++] = (unsigned char)(prefix_mask | val);
		return (int)pos;
	}

	buf[pos++] = (unsigned char)(prefix_mask | max_val);
	val -= max_val;

	while (val >= 128) {
		if (pos >= buf_len) return -1;
		buf[pos++] = (unsigned char)((val % 128) + 128);
		val /= 128;
	}

	if (pos >= buf_len) return -1;
	buf[pos++] = (unsigned char)val;

	return (int)pos;
}

LWS_VISIBLE int
lws_qpack_encode_static(unsigned char *buf, size_t buf_len, int index)
{
	/* Indexed Field Line: 11xxxxxx (T=1), prefix_bits=6, mask=0xc0 */
	int ret = lws_qpack_encode_int(buf, buf_len, (uint64_t)index, 6, 0xc0);
	if (ret >= 0)
		lwsl_debug("%s: encoded %d into %d bytes\n", __func__, index, ret);
	return ret;
}

LWS_VISIBLE int
lws_qpack_encode_string(unsigned char *buf, size_t buf_len, const char *str, size_t len)
{
	int n;
	size_t pos = 0;
	
	/* 
	 * String length, N=7. H=0 (Plaintext).
	 * prefix_bits=7, mask=0x00
	 */
	n = lws_qpack_encode_int(buf, buf_len, (uint64_t)len, 7, 0x00);
	if (n < 0) return -1;
	
	pos += (size_t)n;
	
	if (buf_len - pos < len)
		return -1;
		
	if (len)
		memcpy(buf + pos, str, len);
		
	return (int)(pos + len);
}

static struct lws_qpack_tx_table_entry *
lws_qpack_tx_find(struct lws_qpack_tx_encoder *enc, const char *name, size_t name_len, const char *val, size_t val_len);

static int
lws_qpack_tx_insert(struct lws_qpack_tx_encoder *enc, const char *name, size_t name_len, const char *val, size_t val_len, int static_name_idx);

LWS_VISIBLE int
lws_qpack_encode_prefix(unsigned char *buf, size_t buf_len, uint64_t ric, uint64_t base, uint64_t max_entries)
{
	int n;
	size_t pos = 0;
	uint64_t encoded_ric = 0;
	uint64_t delta_base = 0;
	uint8_t s_bit = 0;
	
	if (ric == 0) {
		buf[0] = 0;
		buf[1] = 0;
		return 2;
	}
	
	if (max_entries == 0) max_entries = 1;
	encoded_ric = (ric % (2 * max_entries)) + 1;
	
	if (base >= ric) {
		delta_base = base - ric;
		s_bit = 0;
	} else {
		delta_base = ric - base - 1;
		s_bit = 0x80;
	}
	
	/* Required Insert Count: prefix_bits=8, mask=0x00 */
	n = lws_qpack_encode_int(buf, buf_len, encoded_ric, 8, 0x00);
	if (n < 0) return -1;
	pos += (size_t)n;
	
	/* Base: prefix_bits=7, mask=S bit */
	n = lws_qpack_encode_int(buf + pos, buf_len - pos, delta_base, 7, s_bit);
	if (n < 0) return -1;
	pos += (size_t)n;
	
	return (int)pos;
}

LWS_VISIBLE int
lws_qpack_encode_literal_with_name_ref(unsigned char *buf, size_t buf_len, int index, const char *val, size_t val_len)
{
	int n;
	size_t pos = 0;
	
	/* 0 1 N T Index, T=1 (Static), N=0 -> mask=0x50, prefix=4 */
	n = lws_qpack_encode_int(buf, buf_len, (uint64_t)index, 4, 0x50);
	lwsl_debug("%s: index=%d, output byte: 0x%02X\n", __func__, index, buf[0]);
	if (n < 0) return -1;
	pos += (size_t)n;
	
	n = lws_qpack_encode_string(buf + pos, buf_len - pos, val, val_len);
	if (n < 0) return -1;
	pos += (size_t)n;
	
	return (int)pos;
}

LWS_VISIBLE int
lws_qpack_encode_literal_with_literal_name(unsigned char *buf, size_t buf_len, const char *name, size_t name_len, const char *val, size_t val_len)
{
	int n;
	size_t pos = 0;
	
	/* 0 0 1 N H Name Length, N=0, H=0 (Plaintext) -> mask=0x20, prefix=3 */
	n = lws_qpack_encode_int(buf, buf_len, (uint64_t)name_len, 3, 0x20);
	lwsl_debug("%s: name_len=%d, output byte: 0x%02X\n", __func__, (int)name_len, buf[0]);
	if (n < 0) return -1;
	pos += (size_t)n;
	
	if (name_len)
		memcpy(buf + pos, name, name_len);
	pos += name_len;
	
	n = lws_qpack_encode_string(buf + pos, buf_len - pos, val, val_len);
	if (n < 0) return -1;
	pos += (size_t)n;
	
	return (int)pos;
}

LWS_VISIBLE int
lws_add_http3_header_by_name(struct lws *wsi, const unsigned char *name,
			     const unsigned char *value, int length,
			     unsigned char **p, unsigned char *end)
{
	int name_len = (int)strlen((const char *)name);
	int n;
	char lower_name[256];
	struct lws_qpack_tx_encoder *enc = NULL; /* wsi ? wsi->h3.qpack_tx_encoder : NULL; */

	if (name_len && name[name_len - 1] == ':')
		name_len--;

	if (name_len > 255) return 1;
	for (n = 0; n < name_len; n++)
		lower_name[n] = (char)tolower((int)name[n]);
	lower_name[name_len] = '\0';

	if (enc) {
		struct lws_qpack_tx_table_entry *dte = lws_qpack_tx_find(enc, lower_name, (size_t)name_len, (const char *)value, (size_t)length);
		if (dte) {
				if (dte->insert_index + 1 > wsi->http.h3_req_ric)
					wsi->http.h3_req_ric = dte->insert_index + 1;
				n = lws_qpack_tx_encode_dynamic_index(*p, lws_ptr_diff_size_t(end, *p), dte->insert_index, wsi->http.h3_base);
			if (n >= 0) {
				*p += n;
				return 0;
			}
		}
		
		int new_idx = lws_qpack_tx_insert(enc, lower_name, (size_t)name_len, (const char *)value, (size_t)length, -1);
		if (new_idx >= 0) {
			if ((uint32_t)new_idx + 1 > wsi->http.h3_req_ric)
				wsi->http.h3_req_ric = (uint32_t)new_idx + 1;
			n = lws_qpack_tx_encode_dynamic_name_ref(*p, lws_ptr_diff_size_t(end, *p), (uint32_t)new_idx, wsi->http.h3_base, (const char *)value, (size_t)length);
			if (n >= 0) {
				*p += n;
				return 0;
			}
		}
	}

	n = lws_qpack_encode_literal_with_literal_name(*p, lws_ptr_diff_size_t(end, *p), lower_name, (size_t)name_len, (const char *)value, (size_t)length);
	if (n < 0) return 1;
	*p += n;

	return 0;
}

LWS_VISIBLE int
lws_add_http3_header_by_token(struct lws *wsi, enum lws_token_indexes token,
			      const unsigned char *value, int length,
			      unsigned char **p, unsigned char *end)
{
	int static_idx = lws_qpack_find_static_index((int)token, (const char *)value, length);
	struct lws_qpack_tx_encoder *enc = NULL; /* wsi ? wsi->h3.qpack_tx_encoder : NULL; */
	int n;

	if (static_idx != -1) {
		const char *static_val;
		lws_qpack_get_static_token(static_idx, NULL, &static_val);
		if (static_val && length == (int)strlen(static_val) && !strncmp(static_val, (const char *)value, (size_t)length)) {
			n = lws_qpack_encode_static(*p, lws_ptr_diff_size_t(end, *p), static_idx);
		} else {
			if (enc) {
				const unsigned char *name = lws_token_to_string(token);
				if (name) {
					int name_len = (int)strlen((const char *)name);
					if (name_len && name[name_len - 1] == ':') name_len--;
					struct lws_qpack_tx_table_entry *dte = lws_qpack_tx_find(enc, (const char *)name, (size_t)name_len, (const char *)value, (size_t)length);
					if (dte) {
						if (dte->insert_index + 1 > wsi->http.h3_req_ric) wsi->http.h3_req_ric = dte->insert_index + 1;
						n = lws_qpack_tx_encode_dynamic_index(*p, lws_ptr_diff_size_t(end, *p), dte->insert_index, wsi->http.h3_base);
						if (n >= 0) { *p += n; return 0; }
					}
					int new_idx = lws_qpack_tx_insert(enc, (const char *)name, (size_t)name_len, (const char *)value, (size_t)length, static_idx);
					if (new_idx >= 0) {
						if ((uint32_t)new_idx + 1 > wsi->http.h3_req_ric) wsi->http.h3_req_ric = (uint32_t)new_idx + 1;
						n = lws_qpack_tx_encode_dynamic_name_ref(*p, lws_ptr_diff_size_t(end, *p), (uint32_t)new_idx, wsi->http.h3_base, (const char *)value, (size_t)length);
						if (n >= 0) { *p += n; return 0; }
					}
				}
			}
			n = lws_qpack_encode_literal_with_name_ref(*p, lws_ptr_diff_size_t(end, *p), static_idx, (const char *)value, (size_t)length);
		}
	} else {
		const unsigned char *name = lws_token_to_string(token);
		if (!name) return 1;
		return lws_add_http3_header_by_name(wsi, name, value, length, p, end);
	}

	if (n < 0) return 1;
	*p += n;

	return 0;
}

LWS_VISIBLE int
lws_add_http3_header_status(struct lws *wsi, unsigned int code,
			    unsigned char **p, unsigned char *end)
{
	unsigned char status[12];
	int m;
	int n = lws_snprintf((char *)status, sizeof(status), "%u", code);
	
	/* Prefix is required at the start of the header block! */
	if (wsi) {
		struct lws_qpack_tx_encoder *enc = wsi->h3.qpack_tx_encoder;
		wsi->http.h3_prefix_ptr = *p;
		*p += 2; /* Reserve space for exactly 2-byte prefix */
		wsi->http.h3_req_ric = 0; /* Reset RIC for this block */
		wsi->http.h3_base = enc ? enc->insert_count : 0; /* Set Base to Start RIC */
	} else {
		/* Test encode mode - pure stateless */
		m = lws_qpack_encode_prefix(*p, lws_ptr_diff_size_t(end, *p), 0, 0, 0);
		if (m < 0) return 1;
		*p += m;
	}

	return lws_add_http3_header_by_token(wsi, WSI_TOKEN_HTTP_COLON_STATUS, status, n, p, end);
}

/* 
 * Returns next state or < 0 for error.
 * If decoded a char, it will be OR'd with 0x8000.
 */
LWS_VISIBLE int
lws_qpack_huftable_decode(int pos, char c)
{
	int q = pos + !!c;

	if (lextable_terms[q >> 3] & (1 << (q & 7))) /* terminal */
		return lextable[q] | 0x8000;

	return pos + (lextable[q] << 1);
}

static struct lws_qpack_dynamic_table_entry *
lws_qpack_get_dynamic_entry(struct lws_qpack_context *ctx, int relative_idx);

LWS_VISIBLE int
lws_qpack_decode_header_block(struct lws_qpack_stream_state *state, 
			      struct lws_qpack_context *ctx,
			      const unsigned char *in, size_t in_len,
			      lws_qpack_header_cb cb, void *user)
{
	size_t i;
	unsigned char c;

	for (i = 0; i < in_len; i++) {
		c = in[i];

		switch (state->state) {
		case LQP_DEC_PREFIX_RIC:
			state->int_val = c & 0xff;
			if (state->int_val == 0xff) {
				state->int_shift = 0;
				state->next_state = LQP_DEC_PREFIX_BASE;
				state->state = LQP_DEC_INT;
			} else {
				uint32_t max_entries = ctx ? ctx->dyn_table.num_entries : 0;
				uint32_t full_range = 2 * max_entries;
				uint32_t wire_ric = (uint32_t)state->int_val;
				if (wire_ric == 0 || !max_entries) {
					state->ric = 0;
				} else {
					uint32_t max_val = ctx->dyn_table.insert_count + max_entries;
					uint32_t max_wrapped = (max_val / full_range) * full_range;
					uint32_t req_ric = max_wrapped + wire_ric - 1;
					if (req_ric > max_val) {
						if (req_ric >= full_range)
							req_ric -= full_range;
					}
					state->ric = req_ric;
				}
				state->state = LQP_DEC_PREFIX_BASE;
			}
			break;

		case LQP_DEC_PREFIX_BASE:
			{
				uint8_t s = !!(c & 0x80);
				uint64_t delta = c & 0x7f;
				if (delta == 0x7f) {
					state->int_shift = 0;
					state->int_val = 0x7f;
					state->next_state = LQP_DEC_INSTRUCTION;
					state->state = LQP_DEC_INT;
					state->is_name = s;
				} else {
					if (s) {
						state->base = state->ric - delta - 1;
					} else {
						state->base = state->ric + delta;
					}
					state->state = LQP_DEC_INSTRUCTION;
				}
			}
			break;

		case LQP_DEC_INSTRUCTION:
			state->opcode = c;
			if ((c & 0xc0) == 0xc0 || (c & 0xc0) == 0x80) {
				/* Indexed Field Line */
				state->is_name = 0;
				state->int_val = c & 0x3f;
				if (state->int_val == 0x3f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_EMIT;
					state->state = LQP_DEC_INT;
				} else {
					goto do_emit;
				}
			} else if ((c & 0xf0) == 0x70 || (c & 0xf0) == 0x60 ||
			           (c & 0xf0) == 0x50 || (c & 0xf0) == 0x40) {
				/* Literal Field Line With Name Reference */
				state->is_name = 0;
				state->int_val = c & 0x0f;
				if (state->int_val == 0x0f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_STR_LEN;
					state->state = LQP_DEC_INT;
				} else {
					state->hdr_idx = (int)state->int_val;
					state->state = LQP_DEC_STR_LEN;
				}
			} else if ((c & 0xf0) == 0x20 || (c & 0xf0) == 0x30) {
				/* Literal Field Line With Literal Name */
				state->is_name = 1;
				state->name_pos = 0;
				state->huff = !!(c & 0x08);
				state->int_val = c & 0x07;
				if (state->int_val == 0x07) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_STR_DATA;
					state->state = LQP_DEC_INT;
				} else {
					state->str_len = state->int_val;
					state->str_pos = 0;
					state->huff_pos = 0;
					state->state = state->str_len ? LQP_DEC_STR_DATA : LQP_DEC_STR_LEN;
				}
			} else if ((c & 0xf0) == 0x10) {
				/* Indexed Field Line With Post-Base Index */
				state->is_name = 0;
				state->int_val = c & 0x0f;
				if (state->int_val == 0x0f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_EMIT;
					state->state = LQP_DEC_INT;
				} else {
					goto do_emit;
				}
			} else if ((c & 0xf0) == 0x00) {
				/* Literal Field Line With Post-Base Name Reference */
				state->is_name = 0;
				state->int_val = c & 0x07;
				if (state->int_val == 0x07) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_STR_LEN;
					state->state = LQP_DEC_INT;
				} else {
					state->hdr_idx = (int)state->int_val;
					state->state = LQP_DEC_STR_LEN;
				}
			}
			break;

		case LQP_DEC_INT:
			if (state->int_shift >= 64)
				return 1;
			state->int_val += (uint64_t)(c & 0x7f) << state->int_shift;
			state->int_shift += 7;
			if (!(c & 0x80)) {
				state->state = state->next_state;
				if (state->state == LQP_DEC_STR_DATA) {
					state->str_len = state->int_val;
					state->str_pos = 0;
					state->huff_pos = 0;
					if (state->str_len == 0) {
						if (state->is_name) {
							state->state = LQP_DEC_STR_LEN;
						} else {
							goto do_emit;
						}
					}
				} else if (state->state == LQP_DEC_STR_LEN) {
					state->hdr_idx = (int)state->int_val;
				} else if (state->state == LQP_DEC_EMIT) {
					goto do_emit;
				} else if (state->state == LQP_DEC_PREFIX_BASE) {
					uint32_t max_entries = ctx ? ctx->dyn_table.num_entries : 0;
					uint32_t full_range = 2 * max_entries;
					uint32_t wire_ric = (uint32_t)state->int_val;
					if (wire_ric == 0 || !max_entries) {
						state->ric = 0;
					} else {
						uint32_t max_val = ctx->dyn_table.insert_count + max_entries;
						uint32_t max_wrapped = (max_val / full_range) * full_range;
						uint32_t req_ric = max_wrapped + wire_ric - 1;
						if (req_ric > max_val) {
							if (req_ric >= full_range)
								req_ric -= full_range;
						}
						state->ric = req_ric;
					}
				} else if (state->state == LQP_DEC_INSTRUCTION) {
					if (state->is_name) {
						state->base = state->ric - state->int_val - 1;
					} else {
						state->base = state->ric + state->int_val;
					}
				}
			}
			break;

		case LQP_DEC_STR_LEN:
			state->is_name = 0;
			state->val_pos = 0;
			state->huff = !!(c & 0x80);
			state->int_val = c & 0x7f;
			if (state->int_val == 0x7f) {
				state->int_shift = 0;
				state->next_state = LQP_DEC_STR_DATA;
				state->state = LQP_DEC_INT;
			} else {
				state->str_len = state->int_val;
				state->str_pos = 0;
				state->huff_pos = 0;
				if (state->str_len == 0) {
					goto do_emit;
				} else {
					state->state = LQP_DEC_STR_DATA;
				}
			}
			break;

		case LQP_DEC_STR_DATA:
			if (state->huff) {
				char b;
				int n;
				for (n = 0; n < 8; n++) {
					b = (c >> (7 - n)) & 1;
					state->huff_pos = (uint16_t)lws_qpack_huftable_decode((int)state->huff_pos, b);
					if (state->huff_pos == 0xffff) {
						lwsl_notice("Huffman decode error\n");
						return 1;
					}
					if (state->huff_pos & 0x8000) {
						char dec = (char)(state->huff_pos & 0x7fff);
						if (state->is_name && state->name_pos < sizeof(state->name_buf) - 1)
							state->name_buf[state->name_pos++] = dec;
						else if (!state->is_name && state->val_pos < sizeof(state->val_buf) - 1)
							state->val_buf[state->val_pos++] = dec;
						state->huff_pos = 0;
					}
				}
			} else {
				if (state->is_name && state->name_pos < sizeof(state->name_buf) - 1)
					state->name_buf[state->name_pos++] = (char)c;
				else if (!state->is_name && state->val_pos < sizeof(state->val_buf) - 1)
					state->val_buf[state->val_pos++] = (char)c;
			}
			
			if (++state->str_pos >= state->str_len) {
				if (state->is_name) {
					state->state = LQP_DEC_STR_LEN;
				} else {
					goto do_emit;
				}
			}
			break;
			
		do_emit:
		case LQP_DEC_EMIT:
			{
				int idx = -1;
				const char *name = NULL;
				const char *val = NULL;
				
				if ((state->opcode & 0xc0) == 0xc0) {
					if (lws_qpack_get_static_token((int)state->int_val, &idx, &val)) return 1;
				} else if ((state->opcode & 0xc0) == 0x80) {
					int absolute_idx = (int)(state->base - (uint64_t)state->int_val - 1);
					int relative_idx = ctx ? (int)(ctx->dyn_table.insert_count - 1 - (uint32_t)absolute_idx) : -1;
					
					if (ctx && (uint32_t)absolute_idx >= ctx->dyn_table.insert_count) {
						/* absolute_idx is larger than current insert_count, wait for more encoder stream */
					}
					
					struct lws_qpack_dynamic_table_entry *dte = 
						lws_qpack_get_dynamic_entry(ctx, relative_idx);
					if (dte && dte->value) {
						size_t name_len = (size_t)(dte->hdr_len - dte->value_len - 32);
						idx = dte->lws_hdr_idx;
						name = dte->value;
						val = dte->value + name_len + 1;
					}
				} else if ((state->opcode & 0xf0) == 0x50 || (state->opcode & 0xf0) == 0x70) {
					if (lws_qpack_get_static_token((int)state->hdr_idx, &idx, NULL)) return 1;
					state->val_buf[state->val_pos] = '\0';
					val = state->val_buf;
				} else if ((state->opcode & 0xf0) == 0x40 || (state->opcode & 0xf0) == 0x60) {
					int absolute_idx = (int)(state->base - (uint64_t)(unsigned int)state->hdr_idx - 1);
					int relative_idx = ctx ? (int)(ctx->dyn_table.insert_count - 1 - (uint32_t)absolute_idx) : -1;
					struct lws_qpack_dynamic_table_entry *dte = 
						lws_qpack_get_dynamic_entry(ctx, relative_idx);
					if (dte && dte->value) {
						idx = dte->lws_hdr_idx;
						name = dte->value;
					}
					state->val_buf[state->val_pos] = '\0';
					val = state->val_buf;
				} else if ((state->opcode & 0xf0) == 0x20 || (state->opcode & 0xf0) == 0x30) {
					state->name_buf[state->name_pos] = '\0';
					state->val_buf[state->val_pos] = '\0';
					name = state->name_buf;
					val = state->val_buf;
				} else if ((state->opcode & 0xf0) == 0x10) {
					int absolute_idx = (int)(state->base + state->int_val);
					int relative_idx = ctx ? (int)(ctx->dyn_table.insert_count - 1 - (uint32_t)absolute_idx) : -1;
					struct lws_qpack_dynamic_table_entry *dte = 
						lws_qpack_get_dynamic_entry(ctx, relative_idx);
					if (dte && dte->value) {
						size_t name_len = (size_t)(dte->hdr_len - dte->value_len - 32);
						idx = dte->lws_hdr_idx;
						name = dte->value;
						val = dte->value + name_len + 1;
					}
				} else if ((state->opcode & 0xf0) == 0x00) {
					int absolute_idx = (int)(state->base + (uint64_t)(unsigned int)state->hdr_idx);
					int relative_idx = ctx ? (int)(ctx->dyn_table.insert_count - 1 - (uint32_t)absolute_idx) : -1;
					struct lws_qpack_dynamic_table_entry *dte = 
						lws_qpack_get_dynamic_entry(ctx, relative_idx);
					// DEBUG
					/* lwsl_user("Post-Base Name Ref: base=%d hdr_idx=%d abs=%d rel=%d used=%d name=%s\n", 
						(int)state->base, state->hdr_idx, absolute_idx, relative_idx, 
						ctx ? ctx->dyn_table.used_entries : -1, dte ? (dte->value ? dte->value : "null") : "null"); */
					if (dte && dte->value) {
						idx = dte->lws_hdr_idx;
						name = dte->value;
					}
					state->val_buf[state->val_pos] = '\0';
					val = state->val_buf;
				}
				
				/* lwsl_user("EMIT: opcode=%02x idx=%d name=%s val=%s val_len=%d\n", state->opcode, idx, name ? name : "null", val ? val : "null", val ? (int)strlen(val) : 0); */
				
				if (cb) cb(user, idx, name, name ? strlen(name) : 0, val, val ? strlen(val) : 0);
				
				state->state = LQP_DEC_INSTRUCTION;
			}
			break;

		default:
			break;
		}
	}

	return 0;
}

static struct lws_qpack_dynamic_table_entry *
lws_qpack_get_dynamic_entry(struct lws_qpack_context *ctx, int relative_idx)
{
	int ring_idx;
	
	if (!ctx || !ctx->dyn_table.entries)
		return NULL;
		
	if (relative_idx < 0 || relative_idx >= ctx->dyn_table.used_entries)
		return NULL;
		
	ring_idx = (ctx->dyn_table.pos - 1 - relative_idx + ctx->dyn_table.num_entries) % ctx->dyn_table.num_entries;
	return &ctx->dyn_table.entries[ring_idx];
}

static int
lws_qpack_dynamic_insert(struct lws_qpack_context *ctx, int lws_hdr_idx, const char *name, size_t name_len, const char *val, size_t val_len)
{
	struct lws_qpack_dynamic_table_entry *dte;
	size_t entry_size;
	char *alloc;
	
	if (!ctx || !ctx->dyn_table.entries || !ctx->dyn_table.num_entries)
		return 1;

	entry_size = name_len + val_len + 32;

	alloc = lws_malloc(name_len + val_len + 2, "qpack dyn entry");
	if (!alloc) return 1;

	if (name_len) memcpy(alloc, name, name_len);
	alloc[name_len] = '\0';
	if (val_len) memcpy(alloc + name_len + 1, val, val_len);
	alloc[name_len + 1 + val_len] = '\0';

	while (ctx->dyn_table.used_entries && 
	       ctx->dyn_table.virtual_payload_usage + entry_size > ctx->dyn_table.virtual_payload_max) {
		int old_idx = (ctx->dyn_table.pos - ctx->dyn_table.used_entries + ctx->dyn_table.num_entries) % ctx->dyn_table.num_entries;
		dte = &ctx->dyn_table.entries[old_idx];
		if (dte->value)
			lws_free(dte->value);
		dte->value = NULL;
		ctx->dyn_table.virtual_payload_usage -= dte->hdr_len;
		ctx->dyn_table.used_entries--;
	}

	if (entry_size > ctx->dyn_table.virtual_payload_max) {
		lws_free(alloc);
		while (ctx->dyn_table.used_entries) {
			int old_idx = (ctx->dyn_table.pos - ctx->dyn_table.used_entries + ctx->dyn_table.num_entries) % ctx->dyn_table.num_entries;
			dte = &ctx->dyn_table.entries[old_idx];
			if (dte->value) lws_free(dte->value);
			dte->value = NULL;
			ctx->dyn_table.used_entries--;
		}
		ctx->dyn_table.virtual_payload_usage = 0;
		return 0; 
	}
	
	if (ctx->dyn_table.used_entries == ctx->dyn_table.num_entries) {
		int old_idx = (ctx->dyn_table.pos - ctx->dyn_table.used_entries + ctx->dyn_table.num_entries) % ctx->dyn_table.num_entries;
		dte = &ctx->dyn_table.entries[old_idx];
		if (dte->value) lws_free(dte->value);
		dte->value = NULL;
		ctx->dyn_table.virtual_payload_usage -= dte->hdr_len;
		ctx->dyn_table.used_entries--;
	}

	dte = &ctx->dyn_table.entries[ctx->dyn_table.pos];
	dte->value = alloc;
	dte->value_len = (uint16_t)val_len;
	dte->hdr_len = (uint16_t)entry_size;
	dte->lws_hdr_idx = (uint16_t)(lws_hdr_idx == -1 ? LWS_QPACK_IGNORE_ENTRY : lws_hdr_idx);

	ctx->dyn_table.virtual_payload_usage += (uint32_t)entry_size;
	ctx->dyn_table.pos = (uint16_t)((ctx->dyn_table.pos + 1) % ctx->dyn_table.num_entries);
	ctx->dyn_table.used_entries++;
	ctx->dyn_table.insert_count++;

	return 0;
}

LWS_VISIBLE int
lws_qpack_decode_encoder_stream(struct lws_qpack_stream_state *state, 
			      struct lws_qpack_context *ctx,
			      const unsigned char *in, size_t in_len)
{
	size_t i;
	unsigned char c;

	for (i = 0; i < in_len; i++) {
		c = in[i];

		switch (state->state) {
		case LQP_DEC_INSTRUCTION:
			state->opcode = c;
			if ((c & 0xc0) == 0xc0) {
				state->is_name = 0;
				state->int_val = c & 0x3f;
				if (state->int_val == 0x3f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_STR_LEN;
					state->state = LQP_DEC_INT;
				} else {
					state->hdr_idx = (int)state->int_val;
					state->state = LQP_DEC_STR_LEN;
				}
			} else if ((c & 0xc0) == 0x80) {
				state->is_name = 0;
				state->int_val = c & 0x3f;
				if (state->int_val == 0x3f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_STR_LEN;
					state->state = LQP_DEC_INT;
				} else {
					state->hdr_idx = (int)state->int_val;
					state->state = LQP_DEC_STR_LEN;
				}
			} else if ((c & 0xc0) == 0x40) {
				state->is_name = 1;
				state->name_pos = 0;
				state->huff = !!(c & 0x20);
				state->int_val = c & 0x1f;
				if (state->int_val == 0x1f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_STR_DATA;
					state->state = LQP_DEC_INT;
				} else {
					state->str_len = state->int_val;
					state->str_pos = 0;
					state->huff_pos = 0;
					state->state = state->str_len ? LQP_DEC_STR_DATA : LQP_DEC_STR_LEN;
				}
			} else if ((c & 0xe0) == 0x20) {
				state->int_val = c & 0x1f;
				if (state->int_val == 0x1f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_EMIT;
					state->state = LQP_DEC_INT;
				} else {
					goto do_emit_enc;
				}
			} else if ((c & 0xe0) == 0x00) {
				state->int_val = c & 0x1f;
				if (state->int_val == 0x1f) {
					state->int_shift = 0;
					state->next_state = LQP_DEC_EMIT;
					state->state = LQP_DEC_INT;
				} else {
					goto do_emit_enc;
				}
			}
			break;

		case LQP_DEC_INT:
			state->int_val += (uint64_t)(c & 0x7f) << state->int_shift;
			state->int_shift += 7;
			if (!(c & 0x80)) {
				state->state = state->next_state;
				if (state->state == LQP_DEC_STR_DATA) {
					state->str_len = state->int_val;
					state->str_pos = 0;
					state->huff_pos = 0;
					if (state->str_len == 0) {
						if (state->is_name) {
							state->state = LQP_DEC_STR_LEN;
						} else {
							goto do_emit_enc;
						}
					}
				} else if (state->state == LQP_DEC_STR_LEN) {
					state->hdr_idx = (int)state->int_val;
				} else if (state->state == LQP_DEC_EMIT) {
					goto do_emit_enc;
				}
			}
			break;

		case LQP_DEC_STR_LEN:
			state->is_name = 0;
			state->val_pos = 0;
			state->huff = !!(c & 0x80);
			state->int_val = c & 0x7f;
			if (state->int_val == 0x7f) {
				state->int_shift = 0;
				state->next_state = LQP_DEC_STR_DATA;
				state->state = LQP_DEC_INT;
			} else {
				state->str_len = state->int_val;
				state->str_pos = 0;
				state->huff_pos = 0;
				if (state->str_len == 0) {
					goto do_emit_enc;
				} else {
					state->state = LQP_DEC_STR_DATA;
				}
			}
			break;

		case LQP_DEC_STR_DATA:
			if (state->huff) {
				char b;
				int n;
				for (n = 0; n < 8; n++) {
					b = (c >> (7 - n)) & 1;
					state->huff_pos = (uint16_t)lws_qpack_huftable_decode((int)state->huff_pos, b);
					if (state->huff_pos == 0xffff) {
						lwsl_notice("Huffman decode error\n");
						return 1;
					}
					if (state->huff_pos & 0x8000) {
						char dec = (char)(state->huff_pos & 0x7fff);
						if (state->is_name && state->name_pos < sizeof(state->name_buf) - 1)
							state->name_buf[state->name_pos++] = dec;
						else if (!state->is_name && state->val_pos < sizeof(state->val_buf) - 1)
							state->val_buf[state->val_pos++] = dec;
						state->huff_pos = 0;
					}
				}
			} else {
				if (state->is_name && state->name_pos < sizeof(state->name_buf) - 1)
					state->name_buf[state->name_pos++] = (char)c;
				else if (!state->is_name && state->val_pos < sizeof(state->val_buf) - 1)
					state->val_buf[state->val_pos++] = (char)c;
			}
			
			if (++state->str_pos >= state->str_len) {
				if (state->is_name) {
					state->state = LQP_DEC_STR_LEN;
				} else {
					goto do_emit_enc;
				}
			}
			break;

		case LQP_DEC_EMIT:
do_emit_enc:
			{
				int tok = -1;
				const char *name = NULL;
				
				if ((state->opcode & 0xc0) == 0x80) {
					struct lws_qpack_dynamic_table_entry *dte = 
						lws_qpack_get_dynamic_entry(ctx, (int)state->hdr_idx);
					if (dte && dte->value) {
						size_t name_len = (size_t)(dte->hdr_len - dte->value_len - 32);
						state->val_buf[state->val_pos] = '\0';
						lws_qpack_dynamic_insert(ctx, dte->lws_hdr_idx, dte->value, name_len, state->val_buf, state->val_pos);
					} else {
						lwsl_err("Insert Name Ref (dyn) failed: int_val=%d dte=%p\n", (int)state->hdr_idx, (void*)dte);
					}
				} else if ((state->opcode & 0xc0) == 0xc0) {
					lws_qpack_get_static_token((int)state->hdr_idx, &tok, &name);
					state->val_buf[state->val_pos] = '\0';
					lws_qpack_dynamic_insert(ctx, tok, name, name ? strlen(name) : 0, state->val_buf, state->val_pos);
				} else if ((state->opcode & 0xc0) == 0x40) {
					state->name_buf[state->name_pos] = '\0';
					state->val_buf[state->val_pos] = '\0';
					lws_qpack_dynamic_insert(ctx, -1, state->name_buf, state->name_pos, state->val_buf, state->val_pos);
				} else if ((state->opcode & 0xe0) == 0x20) {
					if (lws_qpack_dynamic_size(ctx, (int)state->int_val))
						return 1;
				} else if ((state->opcode & 0xe0) == 0x00) {
					struct lws_qpack_dynamic_table_entry *dte = 
						lws_qpack_get_dynamic_entry(ctx, (int)state->int_val);
					if (dte && dte->value) {
						size_t name_len = (size_t)(dte->hdr_len - dte->value_len - 32);
						const char *v = dte->value + name_len + 1;
						lws_qpack_dynamic_insert(ctx, dte->lws_hdr_idx, dte->value, name_len, v, dte->value_len);
					} else {
						lwsl_err("Duplicate failed: int_val=%d dte=%p\n", (int)state->int_val, (void*)dte);
					}
				}
				
				state->state = LQP_DEC_INSTRUCTION;
			}
			break;
			
		default:
			break;
		}
	}

	return 0;
}

LWS_VISIBLE int
lws_qpack_dynamic_size(struct lws_qpack_context *ctx, int size)
{
	struct lws_qpack_dynamic_table_entry *dte;
	int n, min, m;

	if ((uint32_t)size > ctx->dyn_table.virtual_payload_limit) {
		lwsl_err("LWS_QPACK_ENCODER_STREAM_ERROR: table capacity limit exceeded!\n");
		return 1;
	}

	if (!size) {
		lws_qpack_destroy_dynamic_header(ctx);
		return 0;
	}

	n = size / 32;
	if (!n) n = 1;
	
	if (n == ctx->dyn_table.num_entries) {
		ctx->dyn_table.virtual_payload_max = (uint32_t)size;
		return 0;
	}

	dte = lws_zalloc(sizeof(*dte) * (size_t)n, "qpack dyn");
	if (!dte)
		return 1;

	min = ctx->dyn_table.used_entries;
	if (min > n)
		min = n;

	if (ctx->dyn_table.entries) {
		for (m = 0; m < min; m++) {
			int old_idx = (ctx->dyn_table.pos - min + m + ctx->dyn_table.num_entries) % ctx->dyn_table.num_entries;
			dte[m] = ctx->dyn_table.entries[old_idx];
		}
		
		for (m = 0; m < ctx->dyn_table.used_entries - min; m++) {
			int old_idx = (ctx->dyn_table.pos - ctx->dyn_table.used_entries + m + ctx->dyn_table.num_entries) % ctx->dyn_table.num_entries;
			if (ctx->dyn_table.entries[old_idx].value)
				lws_free(ctx->dyn_table.entries[old_idx].value);
		}
		lws_free(ctx->dyn_table.entries);
	}
	
	ctx->dyn_table.entries = dte;
	ctx->dyn_table.num_entries = (uint16_t)n;
	ctx->dyn_table.used_entries = (uint16_t)min;
	ctx->dyn_table.pos = (uint16_t)min;
	ctx->dyn_table.virtual_payload_max = (uint32_t)size;

	return 0;
}

LWS_VISIBLE void
lws_qpack_destroy_dynamic_header(struct lws_qpack_context *ctx)
{
	int i;

	if (!ctx->dyn_table.entries)
		return;

	for (i = 0; i < ctx->dyn_table.num_entries; i++)
		if (ctx->dyn_table.entries[i].value)
			lws_free(ctx->dyn_table.entries[i].value);

	lws_free(ctx->dyn_table.entries);
	ctx->dyn_table.entries = NULL;
	ctx->dyn_table.num_entries = 0;
	ctx->dyn_table.used_entries = 0;
	ctx->dyn_table.pos = 0;
	ctx->dyn_table.virtual_payload_max = 0;
	ctx->dyn_table.virtual_payload_usage = 0;
}

#if defined(LWS_ROLE_H3)


LWS_VISIBLE struct lws *
lws_create_h3_dummy_wsi(struct lws_context *context, struct lws_qpack_tx_encoder *tx_enc)
{
	struct lws *wsi;

	wsi = lws_zalloc(sizeof(*wsi), "dummy h3 wsi");
	if (!wsi)
		return NULL;

	wsi->a.context = context;
	wsi->role_ops = &role_ops_h3;
	wsi->h3.qpack_tx_encoder = tx_enc;
	wsi->http.h3_base = 0;
	wsi->http.h3_req_ric = 0;

	return wsi;
}

LWS_VISIBLE void
lws_qpack_set_wsi_base_and_ric(struct lws *wsi, uint32_t base, uint32_t ric)
{
	if (!wsi) return;
	wsi->http.h3_base = base;
	wsi->http.h3_req_ric = ric;
}

#endif

/*
 * QPACK TX Encoder Stream Instructions
 */

LWS_VISIBLE int
lws_qpack_tx_encode_insert_name_ref(unsigned char *buf, size_t buf_len, int is_static, int index, const char *val, size_t val_len)
{
	int n, ret = 0;
	
	/* 1 T Index (6+) */
	n = lws_qpack_encode_int(buf, buf_len, (uint64_t)index, 6, is_static ? 0xc0 : 0x80);
	if (n < 0) return -1;
	buf += n; buf_len -= (size_t)n; ret += n;
	
	/* H Value Length (7+) + Value String */
	n = lws_qpack_encode_string(buf, buf_len, val, val_len);
	if (n < 0) return -1;
	return ret + n;
}

LWS_VISIBLE int
lws_qpack_tx_encode_insert_literal(unsigned char *buf, size_t buf_len, const char *name, size_t name_len, const char *val, size_t val_len)
{
	int n, ret = 0;
	
	/* 0 1 H Name Length (5+) + Name String */
	/* We don't huffman encode names yet, just use H=0 */
	n = lws_qpack_encode_int(buf, buf_len, (uint64_t)name_len, 5, 0x40);
	if (n < 0) return -1;
	buf += n; buf_len -= (size_t)n; ret += n;
	
	if (buf_len < name_len) return -1;
	memcpy(buf, name, name_len);
	buf += name_len; buf_len -= name_len; ret += (int)name_len;
	
	/* H Value Length (7+) + Value String */
	n = lws_qpack_encode_string(buf, buf_len, val, val_len);
	if (n < 0) return -1;
	return ret + n;
}

LWS_VISIBLE int
lws_qpack_tx_encode_set_capacity(unsigned char *buf, size_t buf_len, uint32_t capacity)
{
	/* 0 0 1 Capacity (5+) */
	return lws_qpack_encode_int(buf, buf_len, capacity, 5, 0x20);
}

LWS_VISIBLE int
lws_qpack_tx_encode_dynamic_index(unsigned char *buf, size_t buf_len, uint32_t insert_index, uint32_t base)
{
	if (insert_index < base) {
		/* 1 0 Index (6+) */
		return lws_qpack_encode_int(buf, buf_len, base - insert_index - 1, 6, 0x80);
	} else {
		/* 0 0 0 1 Index (4+) */
		return lws_qpack_encode_int(buf, buf_len, insert_index - base, 4, 0x10);
	}
}

LWS_VISIBLE int
lws_qpack_tx_encode_dynamic_name_ref(unsigned char *buf, size_t buf_len, uint32_t insert_index, uint32_t base, const char *val, size_t val_len)
{
	int n, ret = 0;
	
	if (insert_index < base) {
		/* 0 1 0 0 Index (4+) */
		n = lws_qpack_encode_int(buf, buf_len, base - insert_index - 1, 4, 0x40);
	} else {
		/* 0 0 0 0 Index (3+) */
		n = lws_qpack_encode_int(buf, buf_len, insert_index - base, 3, 0x00);
	}
	if (n < 0) return -1;
	buf += n; buf_len -= (size_t)n; ret += n;
	
	n = lws_qpack_encode_string(buf, buf_len, val, val_len);
	if (n < 0) return -1;
	return ret + n;
}

static struct lws_qpack_tx_table_entry *
lws_qpack_tx_find(struct lws_qpack_tx_encoder *enc, const char *name, size_t name_len, const char *val, size_t val_len)
{
	int i;
	if (!enc || !enc->entries) return NULL;
	for (i = 0; i < enc->used_entries; i++) {
		int idx = (enc->pos - enc->used_entries + i + enc->num_entries) % enc->num_entries;
		struct lws_qpack_tx_table_entry *dte = &enc->entries[idx];
		
		if (dte->insert_index >= enc->known_received_count)
			continue;
			
		if (dte->name_len == name_len && dte->value_len == val_len) {
			if ((!name_len || !memcmp(dte->name, name, name_len)) &&
			    (!val_len || !memcmp(dte->value, val, val_len))) {
				/* Don't return if it's in danger of eviction in this block!
				 * A safe heuristic for single-pass encoders is that the entry
				 * should be within the top half of the table's max capacity. */
				uint32_t bytes_since = 0;
				int j;
				for (j = i + 1; j < enc->used_entries; j++) {
					int jdx = (enc->pos - enc->used_entries + j + enc->num_entries) % enc->num_entries;
					bytes_since += enc->entries[jdx].hdr_len;
				}
				if (bytes_since + 3072 < enc->virtual_payload_max)
					return dte;
			}
		}
	}
	return NULL;
}

static int
lws_qpack_tx_insert(struct lws_qpack_tx_encoder *enc, const char *name, size_t name_len, const char *val, size_t val_len, int static_name_idx)
{
	struct lws_qpack_tx_table_entry *dte;
	int hdr_len = 32 + (int)name_len + (int)val_len;
	int n;
	
	if (!enc || !enc->entries || hdr_len > (int)enc->virtual_payload_max)
		return -1;
		
	/* Evict until we have space */
	while (enc->used_entries > 0 && enc->virtual_payload_usage + (uint32_t)hdr_len > enc->virtual_payload_max) {
		int old_idx = (enc->pos - enc->used_entries + enc->num_entries) % enc->num_entries;
		struct lws_qpack_tx_table_entry *old = &enc->entries[old_idx];
		enc->virtual_payload_usage -= old->hdr_len;
		if (old->name) lws_free(old->name);
		if (old->value) lws_free(old->value);
		old->name = NULL; old->value = NULL;
		old->name_len = 0; old->value_len = 0;
		enc->used_entries--;
	}
	
	if (enc->used_entries == enc->num_entries) {
		/* Table is full of entries despite size being okay */
		int old_idx = (enc->pos - enc->used_entries + enc->num_entries) % enc->num_entries;
		struct lws_qpack_tx_table_entry *old = &enc->entries[old_idx];
		enc->virtual_payload_usage -= old->hdr_len;
		if (old->name) lws_free(old->name);
		if (old->value) lws_free(old->value);
		old->name = NULL; old->value = NULL;
		old->name_len = 0; old->value_len = 0;
		enc->used_entries--;
	}
	
	dte = &enc->entries[enc->pos];
	dte->name = lws_malloc(name_len + 1, "qpack tx name");
	dte->value = lws_malloc(val_len + 1, "qpack tx val");
	if (!dte->name || !dte->value) {
		if (dte->name) lws_free(dte->name);
		if (dte->value) lws_free(dte->value);
		return -1;
	}
	if (name_len) memcpy(dte->name, name, name_len);
	dte->name[name_len] = '\0';
	if (val_len) memcpy(dte->value, val, val_len);
	dte->value[val_len] = '\0';
	dte->name_len = (uint16_t)name_len;
	dte->value_len = (uint16_t)val_len;
	dte->hdr_len = (uint16_t)hdr_len;
	dte->insert_index = enc->insert_count++;
	
	enc->virtual_payload_usage += (uint32_t)hdr_len;
	enc->used_entries++;
	enc->pos = (uint16_t)((enc->pos + 1) % enc->num_entries);
	
	/* Generate the Encoder Stream Instruction */
	{
		uint8_t scratch[512];
		if (static_name_idx >= 0) {
			n = lws_qpack_tx_encode_insert_name_ref(scratch,
				sizeof(scratch), 1, static_name_idx, val, val_len);
		} else {
			n = lws_qpack_tx_encode_insert_literal(scratch,
				sizeof(scratch), name, name_len, val, val_len);
		}

		if (n > 0) {
			if (lws_buflist_append_segment(&enc->tx_bl, scratch, (size_t)n) < 0)
				return -1;
			if (enc->wsi_qpack_enc)
				lws_callback_on_writable(enc->wsi_qpack_enc);
		} else {
			lwsl_err("ENCODER STREAM GENERATION FAILED! n=%d\n", n);
		}
	}
	
	return (int)dte->insert_index;
}

LWS_VISIBLE void
lws_qpack_tx_encoder_destroy(struct lws_qpack_tx_encoder *enc)
{
	int i;
	if (!enc || !enc->entries) return;
	
	for (i = 0; i < enc->used_entries; i++) {
		int idx = (enc->pos - enc->used_entries + i + enc->num_entries) % enc->num_entries;
		if (enc->entries[idx].name) lws_free(enc->entries[idx].name);
		if (enc->entries[idx].value) lws_free(enc->entries[idx].value);
	}
	
	lws_buflist_destroy_all_segments(&enc->tx_bl);
}

LWS_VISIBLE void
lws_destroy_h3_dummy_wsi(struct lws *wsi)
{
	if (wsi) lws_free(wsi);
}
