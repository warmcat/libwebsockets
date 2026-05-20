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

#ifndef _LWS_QPACK_H
#define _LWS_QPACK_H

#ifdef __cplusplus
extern "C" {
#endif

#define LWS_QPACK_IGNORE_ENTRY 0xff

struct lws_qpack_dynamic_table_entry {
	char *value;
	uint16_t value_len;
	uint16_t hdr_len;
	uint16_t lws_hdr_idx;
};

struct lws_qpack_dynamic_table {
	struct lws_qpack_dynamic_table_entry *entries;
	uint32_t virtual_payload_usage;
	uint32_t virtual_payload_max;
	uint32_t insert_count;
	uint32_t known_received_count;
	uint16_t num_entries;
	uint16_t used_entries;
	uint16_t pos;
};

/* TX Encoder structures */
struct lws_qpack_tx_table_entry {
	char *name;
	char *value;
	uint16_t name_len;
	uint16_t value_len;
	uint16_t hdr_len;      /* 32 + name_len + value_len */
	uint32_t insert_index; /* Absolute insert index */
};

struct lws_qpack_tx_encoder {
	struct lws_qpack_tx_table_entry *entries;
	uint32_t virtual_payload_usage;
	uint32_t virtual_payload_max;
	uint32_t insert_count;
	uint32_t known_received_count;
	uint16_t num_entries;
	uint16_t used_entries;
	uint16_t pos; /* Ring buffer head */
	
	/* Temporary buffer for encoder stream output during header generation */
	unsigned char enc_buf[65536];
	size_t enc_ptr;
};

struct lws_qpack_context {
	struct lws_qpack_dynamic_table dyn_table;
	uint8_t blocked;
};

enum lws_qpack_dec_state {
	LQP_DEC_PREFIX_RIC = 0,
	LQP_DEC_PREFIX_BASE,
	LQP_DEC_INSTRUCTION,
	LQP_DEC_INT,
	LQP_DEC_STR_LEN,
	LQP_DEC_STR_DATA,
	LQP_DEC_STR_DATA_HUFF,
	LQP_DEC_WAIT_STR_LEN,
	LQP_DEC_EMIT
};

struct lws_qpack_stream_state {
	enum lws_qpack_dec_state state;
	enum lws_qpack_dec_state next_state;
	
	uint64_t ric;
	uint64_t base;
	uint64_t int_val;
	uint8_t int_shift;
	
	uint8_t opcode;
	uint8_t is_name; /* 1 if currently parsing name, 0 for value */
	uint8_t huff;
	uint16_t huff_pos;
	
	uint64_t str_len;
	uint64_t str_pos;
	
	int hdr_idx;
	char name_buf[128];
	size_t name_pos;
	char val_buf[4096];
	size_t val_pos;
};

typedef int (*lws_qpack_header_cb)(void *user, int name_idx, const char *name, size_t name_len, const char *value, size_t value_len);

LWS_VISIBLE LWS_EXTERN void
lws_qpack_destroy_dynamic_header(struct lws_qpack_context *ctx);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_decode_encoder_stream(struct lws_qpack_stream_state *state, 
			      struct lws_qpack_context *ctx,
			      const unsigned char *in, size_t in_len);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_decode_header_block(struct lws_qpack_stream_state *state, 
			      struct lws_qpack_context *ctx,
			      const unsigned char *in, size_t in_len,
			      lws_qpack_header_cb cb, void *user);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_find_static_index(int lws_hdr_idx, const char *value, int value_len);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_get_static_token(int index, int *lws_hdr_idx, const char **value);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_encode_static(unsigned char *buf, size_t buf_len, int index);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_encode_int(unsigned char *buf, size_t buf_len, uint64_t val, 
		     uint8_t prefix_bits, uint8_t prefix_mask);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_encode_string(unsigned char *buf, size_t buf_len, const char *str, size_t len);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_encode_prefix(unsigned char *buf, size_t buf_len, uint64_t ric, uint64_t base, uint64_t max_entries);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_encode_literal_with_name_ref(unsigned char *buf, size_t buf_len, int index, const char *val, size_t val_len);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_encode_literal_with_literal_name(unsigned char *buf, size_t buf_len, const char *name, size_t name_len, const char *val, size_t val_len);

/* TX Encoder Stream Instructions */
LWS_VISIBLE LWS_EXTERN int
lws_qpack_tx_encode_insert_name_ref(unsigned char *buf, size_t buf_len, int is_static, int index, const char *val, size_t val_len);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_tx_encode_insert_literal(unsigned char *buf, size_t buf_len, const char *name, size_t name_len, const char *val, size_t val_len);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_tx_encode_set_capacity(unsigned char *buf, size_t buf_len, uint32_t capacity);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_dynamic_size(struct lws_qpack_context *ctx, int size);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_tx_encode_dynamic_index(unsigned char *buf, size_t buf_len, uint32_t insert_index, uint32_t base);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_tx_encode_dynamic_name_ref(unsigned char *buf, size_t buf_len, uint32_t insert_index, uint32_t base, const char *val, size_t val_len);

LWS_VISIBLE LWS_EXTERN struct lws *
lws_create_h3_dummy_wsi(struct lws_context *ctx, struct lws_qpack_tx_encoder *tx_enc);

LWS_VISIBLE LWS_EXTERN void
lws_qpack_set_wsi_base_and_ric(struct lws *wsi, uint32_t base, uint32_t ric);

LWS_VISIBLE LWS_EXTERN void
lws_destroy_h3_dummy_wsi(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN void
lws_qpack_tx_encoder_destroy(struct lws_qpack_tx_encoder *enc);

LWS_VISIBLE LWS_EXTERN int
lws_qpack_huftable_decode(int pos, char c);

LWS_VISIBLE LWS_EXTERN int
lws_add_http3_header_by_name(struct lws *wsi, const unsigned char *name,
			     const unsigned char *value, int length,
			     unsigned char **p, unsigned char *end);

LWS_VISIBLE LWS_EXTERN int
lws_add_http3_header_by_token(struct lws *wsi, enum lws_token_indexes token,
			      const unsigned char *value, int length,
			      unsigned char **p, unsigned char *end);

LWS_VISIBLE LWS_EXTERN int
lws_add_http3_header_status(struct lws *wsi, unsigned int code,
			    unsigned char **p, unsigned char *end);

#ifdef __cplusplus
}
#endif

#endif
