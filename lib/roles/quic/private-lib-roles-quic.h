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

#define LWS_QUIC_VERSION_1 0x00000001
#define LWS_QUIC_VERSION_2 0x709a50c4

#define LWS_QUIC_DEFAULT_WINDOW (1024 * 1024)
#define LWS_QUIC_MAX_WINDOW     (16 * 1024 * 1024)

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
	LWS_QUIC_FT_CONNECTION_CLOSE_APP	= 0x1d,
	LWS_QUIC_FT_HANDSHAKE_DONE		= 0x1e,
	LWS_QUIC_FT_DATAGRAM			= 0x30, /* 0x30 and 0x31 (with LEN) */
};

/* QUIC Transport Error Codes (RFC 9000, Section 20.1) */
#define LWS_QUIC_ERR_NO_ERROR                 0x00
#define LWS_QUIC_ERR_INTERNAL_ERROR           0x01
#define LWS_QUIC_ERR_CONNECTION_REFUSED       0x02
#define LWS_QUIC_ERR_FLOW_CONTROL_ERROR       0x03
#define LWS_QUIC_ERR_STREAM_LIMIT_ERROR       0x04
#define LWS_QUIC_ERR_STREAM_STATE_ERROR       0x05
#define LWS_QUIC_ERR_FINAL_SIZE_ERROR         0x06
#define LWS_QUIC_ERR_FRAME_ENCODING_ERROR     0x07
#define LWS_QUIC_ERR_TRANSPORT_PARAMETER_ERROR 0x08
#define LWS_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR 0x09
#define LWS_QUIC_ERR_PROTOCOL_VIOLATION       0x0a
#define LWS_QUIC_ERR_INVALID_TOKEN            0x0b
#define LWS_QUIC_ERR_APPLICATION_ERROR        0x0c
#define LWS_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED   0x0d
#define LWS_QUIC_ERR_KEY_UPDATE_ERROR         0x0e
#define LWS_QUIC_ERR_AEAD_LIMIT_REACHED       0x0f
#define LWS_QUIC_ERR_NO_VIABLE_PATH           0x10

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
	uint16_t		packet_size;
};

struct lws_quic_rx_chunk {
	lws_dll2_t		list;

	uint64_t		offset;

	size_t			len;
	uint8_t			*data; /* allocated directly after the struct */
};

/*
 * Represents a single QUIC stream (unidirectional or bidirectional).
 * Maps 1:1 with a child WSI.
 */
struct lws_quic_stream {
	struct lws		*wsi; /* The child WSI representing this stream */
	uint64_t		stream_id;

	uint64_t		rx_offset;
	lws_dll2_owner_t	rx_chunks; /* struct lws_quic_rx_chunk */

	uint64_t		tx_offset;
	/* Frames wait in the nwsi's pending_tx list, not here.
	 * But we might need to track flow control per stream here. */
	
	uint64_t		tx_max_data;
	uint64_t		rx_max_data;
	uint64_t		rx_window_size;
	uint64_t		highest_rx_offset;
	lws_usec_t		last_rx_update_us;
	
	uint64_t		rx_final_size;
	uint8_t			fin_received:1;
	uint8_t			fin_delivered:1;
	
	uint8_t			is_unidirectional:1;
	uint8_t			is_server_initiated:1;
	uint8_t			opted_into_early_data:1;
};



struct lws_quic_netconn {
	struct lws		*nwsi; /* the parent UDP network wsi */

	struct lws_quic_cid	loc_cid; /* Our local Connection ID */
	struct lws_quic_cid	rem_cid; /* Remote peer's Connection ID */
	struct lws_quic_cid	orig_dcid; /* Original Destination Connection ID from client */

	uint8_t			local_tp_buf[128]; /* buffer for transport parameters */

	/* Array of pointers to lazily allocated key material */
	struct lws_quic_keys	*keys[LWS_QUIC_LEVEL_COUNT];

	uint64_t		crypto_tx_offset[LWS_QUIC_LEVEL_COUNT];
	uint64_t		tx_conn_offset;

	uint64_t		max_streams_bidi_local;
	uint64_t		max_streams_bidi_remote;
	uint64_t		max_streams_unidi_local;
	uint64_t		max_streams_unidi_remote;

	uint64_t		peer_initial_max_data;
	uint64_t		peer_initial_max_stream_data_bidi_local;
	uint64_t		peer_initial_max_stream_data_bidi_remote;
	uint64_t		peer_initial_max_stream_data_uni;
	uint64_t		peer_max_datagram_frame_size;

	uint64_t		rx_max_data;
	uint64_t		rx_window_size;
	uint64_t		highest_rx_offset;
	lws_usec_t		last_rx_update_us;

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

	/* RX Crypto Reassembly Buffers (Streams are handled by child WSIs) */
	uint64_t		rx_crypto_offset[LWS_QUIC_LEVEL_COUNT];
	lws_dll2_owner_t	rx_crypto_chunks[LWS_QUIC_LEVEL_COUNT];

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

	uint64_t		conn_close_err;
	size_t			crypto_rx_expected_msg_len[4];
	uint8_t			highest_rx_level;
	uint8_t			pto_count;

	/* Key Update Tracking */
	uint64_t		tx_packets_since_update;
	uint64_t		rx_packets_since_update;

	/* DPLPMTUD (RFC 9000 Section 14, RFC 8899) */
	uint32_t		current_mtu;
	uint32_t		probed_mtu;
	uint64_t		pmtud_probe_pn;
	uint16_t		consecutive_mtu_losses;
	uint8_t			pmtud_state; /* 0=BASE, 1=SEARCHING, 2=SEARCH_COMPLETE */

	/* Path Validation (RFC 9000 Section 8.2) */
	uint8_t			path_challenge[8];
	uint8_t			path_challenge_pending:1;

	uint8_t			is_server:1;
	uint8_t			handshake_done:1;
	uint8_t			tp_parsed:1;
	uint8_t			alpn_migrated:1;
	uint8_t			pto_probe_needed:1;
	uint8_t			address_validated:1;
	uint8_t			is_closing:1;

	uint8_t			early_data_status; /* enum lws_0rtt_status */
	
	uint8_t			rx_key_phase:1;
	uint8_t			tx_key_phase:1;
	uint8_t			key_update_pending:1;
};

extern const struct lws_cc_ops lws_cc_ops_newreno;

int
lws_quic_derive_initial_keys(struct lws *wsi, const struct lws_quic_cid *dcid);

int
lws_quic_set_keys(struct lws *wsi, enum lws_tls_quic_secret_type type, const uint8_t *secret, size_t secret_len);

void
lws_quic_keys_destroy(struct lws_quic_keys *keys);

int
lws_quic_update_keys(struct lws_quic_keys *k, int is_rx);

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
lws_quic_discard_keys(struct lws *nwsi, int level);

void
lws_quic_rx_reassemble(struct lws *nwsi, struct lws *wsi_child, struct lws_quic_stream *qs,
		       uint64_t offset, uint8_t *buf, size_t len, int is_crypto, int level);

void
lws_quic_stream_cleanup(struct lws *wsi);

struct lws *
lws_quic_stream_find(struct lws *nwsi, uint64_t stream_id);

struct lws *
lws_get_quic_network_wsi(struct lws *wsi);

void
lws_quic_enter_closing_state(struct lws *wsi, uint64_t err_code, uint64_t frame_type, int is_app_error);

int
lws_quic_parse_transport_parameters(struct lws *wsi, const uint8_t *buf, size_t len);

#define LWS_QUIC_DEFAULT_PTO_US 500000 /* 500ms baseline PTO for early dev */

struct _lws_quic_related {
        struct lws_quic_netconn *qn; /* malloc'd for root net conn */
        struct lws_quic_stream *qs; /* malloc'd for stream child wsi */

        lws_usec_t quic_race_start_us;

        uint8_t initialized:1;
        uint8_t tx_blocked_sent:1;
};

#endif
