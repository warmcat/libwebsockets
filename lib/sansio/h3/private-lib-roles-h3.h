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

#define LWS_H3_SETTINGS_MAX_FIELD_SECTION_SIZE 0x06
#define LWS_H3_SETTINGS_ENABLE_WEBTRANSPORT 0x2b603742
#define LWS_H3_SETTINGS_H3_DATAGRAM         0x33

/* QPACK Error Codes (RFC 9204, Section 8.2) */
#define LWS_QPACK_DECOMPRESSION_FAILED	0x0200
#define LWS_QPACK_ENCODER_STREAM_ERROR	0x0201
#define LWS_QPACK_DECODER_STREAM_ERROR	0x0202

/*
 * The most field lines one HEADERS frame's section may have: far above any
 * real request or response, even one with each cookie crumb sent as its own
 * field, but it stops a 64KiB section of one-byte field lines
 */
#define LWS_H3_MAX_FIELD_LINES		1024

/*
 * SETTINGS_MAX_FIELD_SECTION_SIZE when the vhost has no h2 settings to take
 * it from, see lws_h3_max_field_section(): h2's stock header list size
 */
#define LWS_H3_DEF_MAX_FIELD_SECTION	65536

/*
 * the value length of the h3_qpack_enc_big_entry faults' dynamic table
 * entry, a cookie: with the name and the 32 of overhead it fills 4096
 */
#define LWS_H3_FI_BIG_ENTRY_LEN		4058

/* the peer's unidi streams there may be only one of (RFC 9114 6.2.1, 9204 4.2) */
#define LWS_H3_PEER_UNI_CONTROL		(1 << 0)
#define LWS_H3_PEER_UNI_QPACK_ENC	(1 << 1)
#define LWS_H3_PEER_UNI_QPACK_DEC	(1 << 2)

int
lws_h3_rx_stream_data(struct lws *wsi, const uint8_t *buf, size_t len);

/*
 * Nonzero if the h3 connection nwsi may take a bidirectional stream its peer
 * opens.  A server does, they are requests.  A client only does once it has
 * a WebTransport session, whose streams they may be: otherwise one is a
 * connection error (RFC 9114 6.1), not something to hand the app.
 */
int
lws_h3_peer_bidi_allowed(struct lws *nwsi);

/*
 * The peer's FIN has been delivered on a server request stream, after all of
 * the stream's bytes went through lws_h3_rx_stream_data(): a request body
 * with no content-length ends there.  Nonzero means the stream must close.
 */
int
lws_h3_rx_fin_server(struct lws *wsi);

/*
 * The peer's FIN has been delivered on a request stream that is blocked
 * waiting for qpack inserts: what it sent before the FIN is still held, so
 * nothing may act on the FIN yet.  Nonzero says so, and that it will be acted
 * on once the held data has been processed.
 */
int
lws_h3_rx_fin_deferred(struct lws *wsi);

/*
 * RFC 9204 2.1.2: a field section of ours whose Required Insert Count is ric
 * is about to go on wsi.  The peer acknowledges it, and until then counts the
 * stream against the SETTINGS_QPACK_BLOCKED_STREAMS it advertised, if ric is
 * beyond the inserts it told us it has.  0 means it may go, and is counted
 * now; LWS_H3_QPACK_ENC_HOLD that it would make one stream more that might
 * block than the peer allows, so must wait for the peer to acknowledge more
 * inserts; 1 that it can't go at all.
 */
#define LWS_H3_QPACK_ENC_HOLD 2

int
lws_h3_qpack_enc_section(struct lws *wsi, uint32_t ric);

#if defined(LWS_WITH_SERVER)
/*
 * A server closing an h3 connection of its own accord tells the client which
 * of its requests it did not process with a GOAWAY on our control stream
 * (RFC 9114 5.2), ahead of the CONNECTION_CLOSE
 */
void
lws_h3_server_goaway(struct lws *nwsi);
#endif

#if defined(LWS_WITH_CLIENT)
/*
 * A client h3 connection is going: its requests the server is known not to
 * have processed, or that it left unanswered when it ended the connection
 * without error, start over on a new connection if they may (see the policy
 * in ops-h3.c), before the connection's streams are closed
 */
void
lws_h3_client_retry_unanswered(struct lws *nwsi);
#endif

extern const struct lws_role_ops role_ops_h3;
#define lwsi_role_h3(wsi) (wsi->role_ops == &role_ops_h3)

struct lws *
lws_wsi_h3_adopt(struct lws *parent_wsi, struct lws *wsi);

int
lws_wsi_h3_can_adopt(struct lws *parent_wsi);



/*
 * The QPACK dynamic table capacity we advertise with
 * SETTINGS_QPACK_MAX_TABLE_CAPACITY and enforce on the peer's Set Dynamic
 * Table Capacity instruction.  LWS_QPACK_CAP_VARINT is the first byte of
 * the 2-byte RFC 9114 s16 varint encoding of LWS_QPACK_CAP_VAL (0x50 ->
 * 4096, 0x60 -> 8192); the second byte (0x00) is emitted with it.
 */
#if defined(LWS_PLAT_FREERTOS)
#define LWS_QPACK_CAP_VARINT 0x50 /* 4096 */
#define LWS_QPACK_CAP_VAL 4096
#else
#define LWS_QPACK_CAP_VARINT 0x60 /* 8192 */
#define LWS_QPACK_CAP_VAL 8192
#endif

/*
 * The streams we let wait for the peer's inserts at once, advertised with
 * SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 2.1.2).  What a blocked stream
 * brings while it waits is held, and not credited back to the peer until it
 * is processed, so the connection's flow control window bounds it all.
 */
#if defined(LWS_PLAT_FREERTOS)
#define LWS_QPACK_BLOCKED_STREAMS 2
#else
#define LWS_QPACK_BLOCKED_STREAMS 8
#endif

struct lws_h3_netconn {
	struct lws *nwsi;

	/* Local control streams we send to the peer */
	struct lws *cwsi_control;
	struct lws *cwsi_qpack_enc;
	struct lws *cwsi_qpack_dec;

	/* Peer control streams we receive from the peer */
	struct lws *peer_control;
	/*
	 * which of the peer's one-of-a-kind unidi streams came, by
	 * LWS_H3_PEER_UNI_*: a second one is a connection error
	 */
	uint8_t peer_uni_seen;

	struct lws_qpack_tx_encoder qpack_tx_encoder;
	struct lws_qpack_tx_table_entry tx_entries[32];

	/*
	 * The peer's QPACK dynamic table, mirrored from its encoder stream.
	 * Without this storage, every dynamic insert was silently refused and
	 * every dynamic reference in a field block was silently dropped --
	 * RFC-conformant encoders (browsers) lost headers like origin/referer
	 * while literal-only encoders kept working.  Sized so every capacity
	 * up to the advertised LWS_QPACK_CAP_VAL has a slot (cap / 32).
	 */
	struct lws_qpack_context qpack_dec_ctx;
	struct lws_qpack_dynamic_table_entry rx_entries[LWS_QPACK_CAP_VAL / 32];
	/* our decoder stream's instructions, waiting to go (RFC 9204 4.4) */
	struct lws_buflist *qpack_dec_tx_bl;
	/* the streams waiting for inserts, by _lws_h3_related.qpack_blocked */
	lws_dll2_owner_t qpack_blocked_owner;
	/* the peer's SETTINGS_QPACK_BLOCKED_STREAMS, 0 until it says */
	uint64_t peer_qpack_blocked_streams;
	/* the SETTINGS_QPACK_BLOCKED_STREAMS we advertised, and keep to */
	uint8_t qpack_blocked_max;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	/* h3_qpack_enc_big_entry_late's insert, until a request went */
	struct lws_buflist *fi_late_insert;
#endif

	uint8_t peer_supports_ws:1;
	uint8_t peer_supports_webtransport:1;
	uint8_t peer_supports_h3_datagram:1;
	uint8_t peer_settings_done:1; /* the peer's whole SETTINGS is in */
	/*
	 * client: the server's GOAWAY came, and our requests on the streams
	 * from goaway_id up were not processed (RFC 9114 5.2)
	 */
	uint8_t goaway_rx:1;

	uint64_t goaway_id;
};

struct _lws_h3_related {
	struct lws_h3_netconn *h3n; /* malloc'd for root net conn */
	struct lws_qpack_tx_encoder *qpack_tx_encoder;
	struct lws_qpack_stream_state *qpack_dec_state;
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
	/* the request's headers did not fit: answer 431 (see h2's) */
	uint8_t hdrs_oversized:1;
	/* server: no ah for the request, it is refused (G-028) */
	uint8_t ah_refused:1;
	/* a WT bidi stream's type came, its session ID has not yet */
	uint8_t wt_sid_pending:1;
	/* server: the request's trailers came, the message is over */
	uint8_t rx_trailers_seen:1;

	/* H3 Frame parsing state */
	uint8_t rx_frame_state; /* 0: type, 1: length, 2: payload */
	uint64_t rx_frame_type;
	uint64_t rx_frame_len;
	uint64_t rx_frame_payload_read;
	
	uint8_t rx_varint_buf[16];
	uint8_t rx_varint_len;
	
		uint8_t rx_setting_state; /* 0: id, 1: val */
		uint64_t rx_setting_id;
		/*
		 * Q-2: per-SETTINGS-frame entry counter, so a peer can't burn
		 * CPU by stuffing tens of thousands of tiny/junk entries (each
		 * doing two varint parses + an if/else chain) within the
		 * frame-body budget.
		 */
		uint16_t rx_setting_count;
	/*
	 * field lines in this HEADERS frame's section: the frame is bounded,
	 * but a field line can be a single byte
	 */
	uint16_t rx_field_count;
	/*
	 * this HEADERS frame's field section size as RFC 9114 4.2.2 counts it,
	 * the decoded names and values plus 32 for each field line, against
	 * the SETTINGS_MAX_FIELD_SECTION_SIZE we advertise
	 */
	uint32_t rx_section_size;

	uint8_t rx_dec_instr_buf[16];
	uint8_t rx_dec_instr_len;

	/*
	 * encoder: the Required Insert Counts of the field sections we sent
	 * on this stream that refer to the peer's dynamic table and it has
	 * not acknowledged yet, oldest first.  A request has its head and
	 * its trailers.
	 */
	uint32_t qpack_enc_ric[2];
	uint8_t qpack_enc_unacked;
#if defined(LWS_WITH_CLIENT)
	/*
	 * encoder: the request's field section, ready to go but for the peer
	 * acknowledging more inserts first, and its Required Insert Count
	 */
	struct lws_buflist *qpack_held_hdrs;
	uint32_t qpack_held_ric;
#endif

	/*
	 * decoder: the stream's field section waits for inserts, in h3n's
	 * qpack_blocked_owner, and what came after its prefix is held until
	 * they come, with whether the peer's FIN came after it
	 */
	lws_dll2_t qpack_blocked;
	struct lws_buflist *qpack_blocked_bl;
	uint8_t qpack_blocked_fin:1;
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
