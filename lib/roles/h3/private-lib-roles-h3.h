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

#ifndef _PRIVATE_LIB_ROLES_H3_H_
#define _PRIVATE_LIB_ROLES_H3_H_

/* HTTP/3 Error Codes (RFC 9114, Section 8.1) */
#define LWS_H3_NO_ERROR					0x0100
#define LWS_H3_GENERAL_PROTOCOL_ERROR	0x0101
#define LWS_H3_INTERNAL_ERROR			0x0102
#define LWS_H3_STREAM_CREATION_ERROR	0x0103
#define LWS_H3_CLOSED_CRITICAL_STREAM	0x0104
#define LWS_H3_FRAME_UNEXPECTED			0x0105
#define LWS_H3_FRAME_ERROR				0x0106
#define LWS_H3_EXCESSIVE_LOAD			0x0107
#define LWS_H3_ID_ERROR					0x0108
#define LWS_H3_SETTINGS_ERROR			0x0109
#define LWS_H3_MISSING_SETTINGS			0x010a
#define LWS_H3_REQUEST_REJECTED			0x010b
#define LWS_H3_REQUEST_CANCELLED		0x010c
#define LWS_H3_REQUEST_INCOMPLETE		0x010d
#define LWS_H3_MESSAGE_ERROR			0x010e
#define LWS_H3_VERSION_FALLBACK			0x010f

#define LWS_H3_SETTINGS_ENABLE_WEBTRANSPORT 0x2b603742
#define LWS_H3_SETTINGS_H3_DATAGRAM         0x33

/* QPACK Error Codes (RFC 9204, Section 8.2) */
#define LWS_QPACK_DECOMPRESSION_FAILED	0x0200
#define LWS_QPACK_ENCODER_STREAM_ERROR	0x0201
#define LWS_QPACK_DECODER_STREAM_ERROR	0x0202

int
lws_h3_rx_stream_data(struct lws *wsi, const uint8_t *buf, size_t len);

extern const struct lws_role_ops role_ops_h3;
#define lwsi_role_h3(wsi) (wsi->role_ops == &role_ops_h3)

struct lws *
lws_wsi_h3_adopt(struct lws *parent_wsi, struct lws *wsi);



struct lws_h3_netconn {
	struct lws *nwsi;

	/* Local control streams we send to the peer */
	struct lws *cwsi_control;
	struct lws *cwsi_qpack_enc;
	struct lws *cwsi_qpack_dec;

	/* Peer control streams we receive from the peer */
	struct lws *peer_control;
	struct lws *peer_qpack_enc;
	struct lws *peer_qpack_dec;

	struct lws_qpack_tx_encoder qpack_tx_encoder;
	struct lws_qpack_tx_table_entry tx_entries[32];
	
	struct lws_qpack_context qpack_dec_ctx;

	uint8_t peer_supports_ws:1;
	uint8_t peer_supports_webtransport:1;
	uint8_t peer_supports_h3_datagram:1;
};

struct _lws_h3_related {
	struct lws_h3_netconn *h3n; /* malloc'd for root net conn */
	struct lws_qpack_tx_encoder *qpack_tx_encoder;
	struct lws_qpack_stream_state qpack_dec_state;
	uint8_t h3_state;
	uint8_t stream_type;
	uint8_t type_set:1;
	uint8_t seen_settings:1;

	/* Pseudo-header tracking for HTTP/3 4.1.3 validations */
	uint8_t seen_regular_header:1;
	uint8_t seen_pseudo_method:1;
	uint8_t seen_pseudo_scheme:1;
	uint8_t seen_pseudo_authority:1;
	uint8_t seen_pseudo_path:1;
	uint8_t seen_pseudo_status:1;
	uint8_t seen_pseudo_protocol:1;

	/* H3 Frame parsing state */
	uint8_t rx_frame_state; /* 0: type, 1: length, 2: payload */
	uint64_t rx_frame_type;
	uint64_t rx_frame_len;
	uint64_t rx_frame_payload_read;
	
	uint8_t rx_varint_buf[8];
	uint8_t rx_varint_len;
};

/* Internal QPACK API */
int
lws_qpack_dynamic_size(struct lws_qpack_context *ctx, int size);

LWS_VISIBLE int
lws_add_http3_header_by_name(struct lws *wsi, const unsigned char *name,
			     const unsigned char *value, int length,
			     unsigned char **p, unsigned char *end);

LWS_VISIBLE int
lws_add_http3_header_by_token(struct lws *wsi, enum lws_token_indexes token,
			      const unsigned char *value, int length,
			      unsigned char **p, unsigned char *end);

LWS_VISIBLE int
lws_add_http3_header_status(struct lws *wsi, unsigned int code,
			    unsigned char **p, unsigned char *end);



#endif /* _PRIVATE_LIB_ROLES_H3_H_ */
