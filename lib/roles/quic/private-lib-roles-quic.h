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

#define LWS_QUIC_VERSION_1 0x1
#define LWS_QUIC_VERSION_2 0x6b3343cf

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
	uint8_t		app_rx_installed:1; /**< APP-level rx secret has been
					   *  derived once; ignore later re-fires
					   *  of the application secret callback */
	uint8_t		app_tx_installed:1; /**< APP-level tx secret has been
					   *  derived once; ignore later re-fires
					   *  of the application secret callback */
};

/* QUIC Long Header Packet Types (RFC 9000, Section 17.2) */
#define LWS_QUIC_PT_INITIAL		0
#define LWS_QUIC_PT_0RTT		1
#define LWS_QUIC_PT_HANDSHAKE		2
#define LWS_QUIC_PT_RETRY		3

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
 * Corruption-defense thresholds.
 *
 * LWS_QUIC_DECRYPT_FAIL_LIMIT: how many consecutive undecryptable packets in
 *	a pn_space (with no successful decrypt in between) we tolerate before
 *	declaring the path corrupted and closing with NO_VIABLE_PATH.  This is
 *	deliberately generous: a burst of losses or coalesced junk from a
 *	pmtud probe can produce several, and the PTO/loss machinery already
 *	recovers genuine loss.  We only act on a sustained run that real loss
 *	could not produce at this rate.
 *
 * LWS_QUIC_KP_PROBE_LIMIT: how many times we let a demasked key-phase
 *	mismatch drive a provisional key update that then fails AEAD, before
 *	we stop trusting the key-phase bit as a rotation signal.  Past this,
 *	a KP mismatch is treated as corruption, not a peer-initiated update.
 *
 * LWS_QUIC_PN_FORWARD_JUMP_LIMIT: largest acceptable jump of a freshly
 *	decoded packet number ahead of highest_rx_pn.  QUIC senders do not gap
 *	PNs by hundreds for no reason; a decode that lands far ahead is almost
 *	always a corrupted truncated PN, and committing it would wreck the
 *	receive bitmask and ACK accounting.  We drop the packet instead.
 */
#define LWS_QUIC_DECRYPT_FAIL_LIMIT	256u
#define LWS_QUIC_KP_PROBE_LIMIT		8u
#define LWS_QUIC_PN_FORWARD_JUMP_LIMIT	1024u

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
	lws_sockaddr46		dest_sa46;
	uint8_t			has_dest;
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
	uint64_t		advertised_rx_max_data;
	uint64_t		rx_window_size;
	uint64_t		highest_rx_offset;
	lws_usec_t		last_rx_update_us;
	
	uint64_t		rx_final_size;
	uint8_t			fin_received:1;
	uint8_t			fin_delivered:1;
	
	uint8_t			is_unidirectional:1;
	uint8_t			is_server_initiated:1;
	uint8_t			opted_into_early_data:1;
	uint8_t			close_after_rx:1;
	uint8_t			sent_fin:1;
};



struct lws_quic_netconn {
	struct lws		*nwsi; /* the parent UDP network wsi */

	struct lws_quic_cid	loc_cid; /* Our local Connection ID */
	struct lws_quic_cid	rem_cid; /* Remote peer's Connection ID */
	uint64_t                highest_rx_cid_seq; /* F-55: Track NEW_CONNECTION_ID seq */
	uint8_t                 rem_stateless_reset_token[16];
	struct lws_quic_cid	orig_dcid; /* Original Destination Connection ID from client */

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
	uint64_t		peer_ack_delay_exponent;

	uint64_t		rx_max_data;
	uint64_t		advertised_rx_max_data;
	uint64_t		rx_window_size;
	uint64_t		highest_rx_offset;
	lws_usec_t		last_rx_update_us;

	uint64_t		next_stream_id_bidi_local;
	uint64_t		next_stream_id_unidi_local;
	uint64_t		next_stream_id_bidi_remote;
	uint64_t		next_stream_id_unidi_remote;

	/* Frames waiting to be bundled into outgoing packets */
	lws_dll2_owner_t	pending_tx[LWS_QUIC_LEVEL_COUNT];

	/* Frames that have been sent but are unacknowledged */
	lws_dll2_owner_t	in_flight[LWS_QUIC_LEVEL_COUNT];

	/* Received frames tracking state */
	uint64_t		highest_rx_pn[LWS_QUIC_LEVEL_COUNT];
	uint64_t		rx_pn_bitmask[LWS_QUIC_LEVEL_COUNT];
	uint8_t			needs_ack[LWS_QUIC_LEVEL_COUNT];

	/*
	 * Corruption defense (inbound sanity self-checks).
	 *
	 * If a packet passes header protection but fails AEAD, it is either a
	 * legitimate loss (the packet belongs to a key phase we no longer have,
	 * or it is genuinely lost in flight) or it is wire/path corruption that
	 * happened to look plausible enough to reach decryption.  We cannot tell
	 * the two apart from a single failure, but a sustained run of failures
	 * with no progress is corruption until proven otherwise.
	 *
	 * consec_decrypt_fail[] counts undecryptable packets per pn_space since
	 * the last packet that decrypted cleanly; it is reset on every success.
	 *
	 * kp_probe_fail counts provisional key-update attempts (a short-header
	 * packet whose demasked key-phase bit differs from rx_key_phase) that
	 * subsequently failed AEAD.  A single bit flip in junk flips this, so we
	 * refuse to keep re-deriving keys once it's clear the bit is just noise.
	 */
	uint32_t		consec_decrypt_fail[LWS_QUIC_LEVEL_COUNT];
	uint32_t		kp_probe_fail;

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

	/*
	 * Delayed ACK coalescing (RFC 9000 §13.2.1)
	 *
	 * Endpoints SHOULD delay 1-RTT ACKs by ~RTT/8 (capped at the advertised
	 * max_ack_delay) and SHOULD send an ACK immediately on every 2nd
	 * ack-eliciting packet, so that a burst of N packets generates ~N/2 ACKs
	 * instead of N.  Initial/Handshake ACKs and packets carrying
	 * CONNECTION_CLOSE are always sent immediately (§13.2.1 rule 3).
	 */
	lws_sorted_usec_list_t	ack_delay_sul;	/* fires to send a deferred App-space ACK */
	lws_usec_t		ack_delay_us;		/* configured max ACK delay (def 25ms) */
	lws_usec_t		peer_max_ack_delay_us;	/* peer's advertised max_ack_delay (TP 0x0b) */
	lws_usec_t		rx_ack_eliciting_since_us; /* time of 1st un-ACK'd eliciting App pkt */
	uint8_t			rx_ack_eliciting_count;    /* eliciting pkts since last App ACK sent */
	uint8_t			ack_delay_armed;	    /* ack_delay_sul is currently scheduled */

	/* RTT Tracking */
	lws_usec_t		smoothed_rtt;
	lws_usec_t		rttvar;
	lws_usec_t		min_rtt;
	lws_usec_t		latest_rtt;

	uint64_t		bytes_received;
	uint64_t		bytes_sent;

	uint32_t		version;
	uint32_t		original_version;

	uint64_t                conn_close_err;
		/*
		 * Q-19: was sized with a bare [4] while every sibling array in
		 * this struct uses [LWS_QUIC_LEVEL_COUNT].  If the level enum
		 * ever grows these would silently go undersized while every
		 * consumer indexes them with the enum constant.
		 */
		size_t                  crypto_rx_expected_msg_len[LWS_QUIC_LEVEL_COUNT];
		uint8_t                 *crypto_rx_buf[LWS_QUIC_LEVEL_COUNT];
		size_t                  crypto_rx_buf_len[LWS_QUIC_LEVEL_COUNT];
	uint8_t                 highest_rx_level;
	uint8_t			pto_count;

	/* Key Update Tracking */
	uint64_t		tx_packets_since_update;
	uint64_t		rx_packets_since_update;

	/* DPLPMTUD (RFC 9000 Section 14, RFC 8899) */
	uint32_t		current_mtu;
	uint32_t		probed_mtu;
	/*
	 * PN of the packet currently in flight as a PMTUD probe.  PN 0 is a
	 * perfectly valid probe PN (it's the usual case, since the first
	 * app-data packet of a connection doubles as the probe), so "no probe
	 * in flight" needs its own out-of-band sentinel rather than 0.
	 */
#define LWS_QUIC_PMTUD_PROBE_NONE	((uint64_t)~0ull)
	uint64_t		pmtud_probe_pn;
	uint16_t		consecutive_mtu_losses;
	uint8_t			pmtud_state; /* 0=BASE, 1=SEARCHING, 2=SEARCH_COMPLETE */

	/* Path Validation (RFC 9000 Section 8.2) */
	uint8_t			path_challenge[8];
	uint8_t			path_challenge_pending:1;
	lws_sockaddr46		probing_sa46;
	uint8_t			probing_sa46_valid:1;
	uint8_t			rx_has_non_probing:1;

	/*
	 * Client preferred_address active migration (RFC 9000 Section 9.5/9.6).
	 *
	 * The client migrates onto the server's preferred address using a NEW
	 * source socket (so the server observes a second client 4-tuple) and
	 * the new DCID the server advertised in the preferred_address TP.  We
	 * save the original peer address + DCID so a failed path validation can
	 * revert cleanly.
	 */
	lws_sockaddr46		prefaddr_original_sa46;
	struct lws_quic_cid	prefaddr_original_rem_cid;
	struct lws_quic_cid	prefaddr_rem_cid;	/* new DCID from TP */
	uint8_t			prefaddr_rem_token[16];/* stateless reset token */
	lws_sockfd_type		prefaddr_sockfd;	/* new probe socket */
	uint8_t			prefaddr_active:1;
	uint8_t			prefaddr_committed:1;	/* PATH_RESPONSE done */
	uint8_t			prefaddr_pending:1;	/* deferred until handshake done */
	lws_sorted_usec_list_t	prefaddr_sul;

	/* ECN (Explicit Congestion Notification) */
	uint64_t		ecn_rx_ect0;
	uint64_t		ecn_rx_ect1;
	uint64_t		ecn_rx_ce;
	uint64_t		ecn_tx_ce; /* Track peer's reported ECN-CE to detect increases */

	uint8_t			is_server:1;
	uint8_t			handshake_done:1;
	uint8_t			tp_parsed:1;
	uint8_t			alpn_migrated:1;
	uint8_t			pto_probe_needed:2;
	uint8_t			address_validated:1;
	uint8_t			is_closing:1;

	uint8_t			early_data_status; /* enum lws_0rtt_status */
	
	uint8_t			rx_key_phase:1;
	uint8_t			tx_key_phase:1;
	uint8_t			key_update_pending:1;

	/* QUIC Stateless Retry */
	uint8_t			retry_token[128];
	size_t			retry_token_len;
	struct lws_quic_cid	retry_scid;

	/*
	 * 0-RTT accounting (debug-only): on a client that attempted 0-RTT,
	 * track every frame queued for Application-level (1-RTT) TX so the
	 * QUIC-Interop-Runner "zerortt" check (which fails the test if the
	 * client emits more than ~half the request byte budget in 1-RTT
	 * packets) can be diagnosed.  Frames counted here end up in short-
	 * header packets protected by CLIENT_TRAFFIC_SECRET_0 and so are
	 * counted against the 1-RTT budget by the runner's pcap scorer.
	 */
	uint64_t		dbg_1rtt_frames;
	uint64_t		dbg_1rtt_bytes;
	uint64_t		dbg_1rtt_pre_hs_frames; /* queued before handshake_done */
	uint64_t		dbg_1rtt_pre_hs_bytes;
};

struct lws_quic_cc_newreno {
	size_t			cwnd;
	size_t			ssthresh;
	size_t			bytes_in_flight;
	lws_usec_t		congestion_recovery_start_time;

	lws_usec_t		last_pacing_time;
	size_t			pacing_credit;
};

extern const struct lws_cc_ops lws_cc_ops_newreno;

int
lws_quic_derive_initial_keys(struct lws *wsi, const struct lws_quic_cid *dcid);

int
lws_quic_set_keys(struct lws *wsi, enum lws_tls_quic_secret_type type, const uint8_t *secret, size_t secret_len);

void
lws_quic_keys_destroy(struct lws_quic_keys *keys);

void
lws_quic_queue_path_challenge(struct lws *nwsi);

/*
 * Client preferred_address active migration (RFC 9000 Section 9.5/9.6):
 * open a new source socket toward the server's preferred address, swap to the
 * new DCID the server advertised, and validate the new path with
 * PATH_CHALLENGE / PATH_RESPONSE.  On success the connection moves onto the
 * new socket; on timeout it reverts.  pref_cid/pref_token may be NULL.
 * Returns 0 on success.
 */
int
lws_quic_client_probe_preferred_address(struct lws *nwsi,
					const lws_sockaddr46 *pref_sa46,
					const struct lws_quic_cid *pref_cid,
					const uint8_t *pref_token);

void lws_quic_keys_free(struct lws_quic_keys *keys);

void lws_quic_keys_release_aead_rx(struct lws_quic_keys *keys);
void lws_quic_keys_release_aead_tx(struct lws_quic_keys *keys);

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
lws_quic_get_pn_offset(const uint8_t *buf, size_t len, size_t *payload_len, size_t dcid_len);

size_t
lws_quic_write_varint(uint8_t *buf, size_t len, uint64_t val);

int
lws_quic_parse_frames(struct lws *nwsi, int level, uint8_t *payload, size_t payload_len, const lws_sockaddr46 *sa46);

void
lws_quic_handle_ack(struct lws *nwsi, int level, uint64_t acked_pn, int is_largest_ack, uint64_t ack_delay);

void
lws_quic_detect_loss(struct lws *nwsi, int level, uint64_t largest_acked);


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


int
lws_quic_validate_retry_tag(struct lws_quic_netconn *qn,
			    const uint8_t *orig_dcid, size_t orig_dcid_len,
			    const uint8_t *pkt, size_t len, const uint8_t *tag);

int
lws_quic_create_retry_token(struct lws *wsi,
                            const uint8_t *client_dcid, size_t dcid_len,
                            const uint8_t *retry_scid, size_t rscid_len,
                            const uint8_t *client_ip, size_t ip_len,
                            uint8_t *out_token, size_t *out_token_len);

int
lws_quic_validate_retry_token(struct lws *wsi, const uint8_t *token, size_t token_len,
                              const uint8_t *client_ip, size_t ip_len,
                              struct lws_quic_cid *orig_dcid,
                              struct lws_quic_cid *retry_scid);
int
lws_quic_create_retry_tag(const uint8_t *client_dcid, size_t dcid_len,
                          const uint8_t *pkt, size_t len, uint8_t *tag_out);

#endif
