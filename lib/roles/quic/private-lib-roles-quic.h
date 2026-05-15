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

#ifndef _LWS_PRIVATE_LIB_ROLES_QUIC
#define _LWS_PRIVATE_LIB_ROLES_QUIC

extern const struct lws_role_ops role_ops_quic;

#define LWS_QUIC_MAX_CID_LEN 20

struct lws_quic_cid {
	uint8_t		id[LWS_QUIC_MAX_CID_LEN];
	uint8_t		len;
};

/* QUIC encryption levels / Packet Number Spaces */
enum lws_quic_level {
	LWS_QUIC_LEVEL_INITIAL = 0,
	LWS_QUIC_LEVEL_EARLY,
	LWS_QUIC_LEVEL_HANDSHAKE,
	LWS_QUIC_LEVEL_APP,

	LWS_QUIC_LEVEL_COUNT
};

/*
 * Crypto state for a specific QUIC encryption level.
 * Allocated on demand to save memory, and freed immediately when the
 * connection drops the protection level (e.g., Initial keys dropped during Handshake).
 */
struct lws_quic_keys {
	/*
	 * Opaque pointers to lws_genaes_ctx or lws_genchacha_ctx.
	 * We use void* to avoid pulling in full crypto headers here, and to
	 * allow polymorphic AES-GCM / ChaChaPoly without union bloat.
	 */
	void		*aead_rx;
	void		*aead_tx;
	void		*hp_rx; /* Header Protection */
	void		*hp_tx;

	struct lws_gencrypto_keyelem el_aead_rx;
	struct lws_gencrypto_keyelem el_aead_tx;
	struct lws_gencrypto_keyelem el_hp_rx;
	struct lws_gencrypto_keyelem el_hp_tx;

	uint8_t		key_aead_rx[32];
	uint8_t		key_aead_tx[32];
	uint8_t		key_hp_rx[32];
	uint8_t		key_hp_tx[32];

	uint8_t		secret_rx[48];
	uint8_t		secret_tx[48];
	size_t		secret_len;

	uint8_t		iv_rx[12];
	uint8_t		iv_tx[12];

	uint64_t	pn_rx_largest;
	uint64_t	pn_tx;

	/* 0 = AES-GCM (HP is AES-ECB), 1 = ChaCha20-Poly1305 (HP is ChaCha20) */
	uint8_t		cipher_type;
	uint8_t		valid:1;
};

/* QUIC Frame Types (RFC 9000) */
enum lws_quic_frame_type {
	LWS_QUIC_FT_PADDING			= 0x00,
	LWS_QUIC_FT_PING			= 0x01,
	LWS_QUIC_FT_ACK				= 0x02,
	LWS_QUIC_FT_ACK_ECN			= 0x03,
	LWS_QUIC_FT_RESET_STREAM		= 0x04,
	LWS_QUIC_FT_STOP_SENDING		= 0x05,
	LWS_QUIC_FT_CRYPTO			= 0x06,
	LWS_QUIC_FT_STREAM			= 0x08, /* 0x08 - 0x0f are STREAM frames */
	LWS_QUIC_FT_MAX_DATA			= 0x10,
	LWS_QUIC_FT_MAX_STREAM_DATA		= 0x11,
	LWS_QUIC_FT_MAX_STREAMS_BIDI		= 0x12,
	LWS_QUIC_FT_MAX_STREAMS_UNIDI		= 0x13,
	LWS_QUIC_FT_DATA_BLOCKED		= 0x14,
	LWS_QUIC_FT_STREAM_DATA_BLOCKED		= 0x15,
	LWS_QUIC_FT_STREAMS_BLOCKED_BIDI	= 0x16,
	LWS_QUIC_FT_STREAMS_BLOCKED_UNIDI	= 0x17,
	LWS_QUIC_FT_NEW_CONNECTION_ID		= 0x18,
	LWS_QUIC_FT_RETIRE_CONNECTION_ID	= 0x19,
	LWS_QUIC_FT_PATH_CHALLENGE		= 0x1a,
	LWS_QUIC_FT_PATH_RESPONSE		= 0x1b,
	LWS_QUIC_FT_CONNECTION_CLOSE		= 0x1c,
};

/*
 * A logical frame queued for transmission or in-flight waiting for ACK.
 */
struct lws_quic_tx_frame {
	lws_dll2_t		list; /* membership in pending_tx or in_flight */

	uint8_t			type; /* enum lws_quic_frame_type */

	/* For STREAM and CRYPTO frames */
	uint64_t		stream_id;
	uint64_t		offset;

	/* Flow Control Fields */
	uint64_t		limit;


	/* The raw payload data for this frame (allocated alongside this struct) */
	uint8_t			*data;
	size_t			len;

	/* If in-flight, which packet number it was sent in (to match against ACKs) */
	uint64_t		sent_in_pn;
	lws_usec_t		sent_time_us;
	size_t			wire_len;
};

struct lws_quic_rx_chunk {
	lws_dll2_t		list;

	uint64_t		offset;

	size_t			len;
	uint8_t			*data; /* allocated directly after the struct */
};

struct lws_cc_ops {
	void (*init)(struct lws *nwsi);
	void (*on_sent)(struct lws *nwsi, size_t bytes);
	void (*on_ack)(struct lws *nwsi, size_t bytes_acked, lws_usec_t rtt);
	void (*on_loss)(struct lws *nwsi, size_t bytes_lost);
	int  (*can_send)(struct lws *nwsi, size_t bytes);
	lws_usec_t (*get_pacing_delay)(struct lws *nwsi, size_t bytes_to_send);
};

struct lws_quic_netconn {
	struct lws		*nwsi; /* the parent UDP network wsi */

	struct lws_quic_cid	loc_cid; /* Our local Connection ID */
	struct lws_quic_cid	rem_cid; /* Remote peer's Connection ID */
	struct lws_quic_cid	orig_dcid; /* Original Destination Connection ID from client */

	/* Array of pointers to lazily allocated key material */
	struct lws_quic_keys	*keys[LWS_QUIC_LEVEL_COUNT];

	uint64_t		crypto_tx_offset[LWS_QUIC_LEVEL_COUNT];
	uint64_t		tx_conn_offset;

	uint64_t		max_streams_bidi_local;
	uint64_t		max_streams_bidi_remote;
	uint64_t		max_streams_unidi_local;
	uint64_t		max_streams_unidi_remote;

	uint64_t		next_stream_id_bidi_local;
	uint64_t		next_stream_id_unidi_local;

	/* Frames waiting to be bundled into outgoing packets */
	lws_dll2_owner_t	pending_tx[LWS_QUIC_LEVEL_COUNT];

	/* Frames that have been sent but are unacknowledged */
	lws_dll2_owner_t	in_flight[LWS_QUIC_LEVEL_COUNT];

	/* Received frames tracking state */
	uint64_t		highest_rx_pn[LWS_QUIC_LEVEL_COUNT];
	uint64_t		rx_pn_bitmask[LWS_QUIC_LEVEL_COUNT];
	uint8_t			needs_ack[LWS_QUIC_LEVEL_COUNT];

	/* RX Reassembly Buffers */
	uint64_t		rx_crypto_offset[LWS_QUIC_LEVEL_COUNT];
	lws_dll2_owner_t	rx_crypto_chunks[LWS_QUIC_LEVEL_COUNT];

	uint64_t		rx_stream_offset;
	lws_dll2_owner_t	rx_stream_chunks;

	/* Probe Timeout timer for packet loss detection */
	lws_sorted_usec_list_t	pto_sul;

	/* Congestion Control Ops */
	const struct lws_cc_ops	*cc_ops;
	void			*cc_state;         /* Algorithm-specific state (e.g., NewReno state) */

	/* Pacing Timer */
	lws_sorted_usec_list_t	pacer_sul;

	/* RTT Tracking */
	lws_usec_t		smoothed_rtt;
	lws_usec_t		rttvar;
	lws_usec_t		min_rtt;
	lws_usec_t		latest_rtt;

	uint64_t		bytes_received;
	uint64_t		bytes_sent;

	uint32_t		version;

	uint8_t			is_server:1;
	uint8_t			handshake_done:1;
	uint8_t			pto_probe_needed:1;
	uint8_t			address_validated:1;
};

extern const struct lws_cc_ops lws_cc_ops_newreno;

int
lws_quic_derive_initial_keys(struct lws *wsi, const struct lws_quic_cid *dcid);

int
lws_quic_set_keys(struct lws *wsi, enum lws_tls_quic_secret_type type, const uint8_t *secret, size_t secret_len);

int
lws_quic_update_keys(struct lws *wsi, int is_rx);

int
lws_quic_unmask_header(struct lws_quic_keys *keys, uint8_t *packet, size_t packet_len, size_t pn_offset);

int
lws_quic_decrypt_payload(struct lws_quic_keys *keys, uint8_t *packet, size_t packet_len,
			 size_t pn_offset, uint8_t pn_len, uint64_t full_pn);

int
lws_quic_encrypt_payload(struct lws_quic_keys *keys, uint8_t *packet, size_t packet_len,
			 size_t pn_offset, uint8_t pn_len, uint64_t full_pn);

size_t
lws_quic_parse_varint(const uint8_t *buf, size_t len, uint64_t *val);

size_t
lws_quic_get_pn_offset(const uint8_t *buf, size_t len, size_t *payload_len);

size_t
lws_quic_write_varint(uint8_t *buf, size_t len, uint64_t val);

int
lws_quic_parse_frames(struct lws *nwsi, int level, uint8_t *payload, size_t payload_len);

void
lws_quic_handle_ack(struct lws *nwsi, int level, uint64_t acked_pn);

void
lws_quic_rx_reassemble(struct lws *nwsi, lws_dll2_owner_t *owner, uint64_t *expected_offset, uint64_t offset, uint8_t *buf, size_t len, int is_crypto, int level);

#define LWS_QUIC_DEFAULT_PTO_US 500000 /* 500ms baseline PTO for early dev */

struct _lws_quic_related {
	struct lws_quic_netconn *qn; /* malloc'd for root net conn */
	uint64_t tx_stream_offset;

	uint8_t initialized:1;
	uint8_t tx_blocked_sent:1;
};

#endif
