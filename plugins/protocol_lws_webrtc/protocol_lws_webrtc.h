#ifndef __PROTOCOL_LWS_WEBRTC_H__
#define __PROTOCOL_LWS_WEBRTC_H__

#include <libwebsockets/lws-rtp.h>
#include <libwebsockets/lws-srtp.h>
#include <libwebsockets/lws-stun.h>

/*
 * Most ICE agents offer a handful of candidates; anything past this is either
 * broken or an attempt to use us as a UDP reflector, so we stop punching.
 */
#define LWS_WEBRTC_MAX_PUNCHES 16

/*
 * How often we poll the DTLS state machine while its handshake is in
 * progress.  Flight retransmission and the overall handshake deadline are
 * both driven from lws_gendtls_get_rx() / lws_gendtls_get_tx(), so without
 * an independent poll nothing happens at all once the peer goes quiet: a
 * lost flight is never retransmitted, and an abandoned handshake sits there
 * holding its ctx and media object until the ws session happens to close.
 */
#define LWS_WEBRTC_DTLS_POLL_US (100 * LWS_US_PER_MS)

/*
 * Each server session holds a media object, a DTLS ctx once it offers, and
 * a tx pacer thread once media flows, for whoever opened a ws to us, so
 * how many there may be at once is capped, overall and per peer host
 * (lws_get_peer_host_key(): an IPv4 address or an IPv6 /64).  The
 * "max-sessions" and "max-sessions-per-host" pvos override these.
 */
#define LWS_WEBRTC_DEF_MAX_SESSIONS		64
#define LWS_WEBRTC_DEF_MAX_SESSIONS_PER_HOST	16

/*
 * The most of the connection log we keep per session until its handshake
 * completes, for the mixer's request_debug_log
 */
#define LWS_WEBRTC_CONN_LOG_MAX			(8 * 1024)

struct vhd_webrtc {
	struct lws_context      *context;
	struct lws_vhost        *vhost;
	struct lws_dll2_owner   sessions;
	struct lws              *wsi_udp;

	uint8_t                 *cert_mem;
	size_t                  cert_len;
	uint8_t                 *key_mem;
	size_t                  key_len;
	char                    fingerprint[128];
	char                    external_ip[64];
	uint16_t                udp_port;

	/* immutable after PROTOCOL_INIT, see LWS_WEBRTC_DEF_MAX_SESSIONS */
	uint16_t                max_sessions;
	uint16_t                max_sessions_per_host;

	/* Application callbacks */
	lws_webrtc_on_media_cb  on_media;
};

struct vhd_webrtc_udp {
	struct vhd_webrtc       *vhd;
};

struct lws_webrtc_telemetry {
	uint32_t rtp_drops_video;
	uint32_t rtp_late_video;
	uint32_t rtp_drops_audio;
	uint32_t rtp_late_audio;
	uint32_t dtls_errors;
	uint32_t txpacer_drops;
};

struct lws_webrtc_peer_media {
	volatile int            refcount;
	pthread_mutex_t         lock_tx;

	struct lws              *wsi_udp;
	lws_sockaddr46          peer_sa46;
	int                     has_peer_sa46;
	uint8_t                 peer_stun_received;

	struct lws_rtp_ctx      rtp_ctx_video;
	struct lws_rtp_ctx      rtp_ctx_audio;
	struct lws_srtp_ctx     srtp_ctx_tx;
	struct lws_srtp_ctx     srtp_ctx_rx;

	uint8_t                 handshake_done;
	uint8_t                 sent_first_rtp;
	uint16_t                sent_first_video;
	uint8_t                 sent_first_audio;

	uint8_t                 pt_video;
	uint8_t                 pt_audio;
	uint8_t                 pt_video_h264;
	uint8_t                 pt_video_av1;

	uint32_t                ssrc_video;
	uint32_t                ssrc_audio;
	uint32_t                ssrc_peer_video;

	uint32_t                rtp_ts_offset;
	uint8_t                 rtp_ts_offset_set;
	uint32_t                rtp_ts_audio_offset;
	uint8_t                 rtp_ts_audio_offset_set;
    
	uint8_t                 rx_video_corrupted;

	uint16_t                last_seq_video;
	uint8_t                 seq_valid_video;
	uint16_t                last_seq_audio;
	uint8_t                 seq_valid_audio;

	char                    fmtp_audio[128];
	char                    fmtp_video_h264[256];
	char                    fmtp_video_av1[256];

	uint8_t                 sps[128];
	uint8_t                 pps[64];
	size_t                  sps_len;
	size_t                  pps_len;
	lws_usec_t              last_sps_pps_ts;

	struct lws_txp          *txpacer; /* created when media first flows */
	uint8_t                 txpacer_failed; /* don't retry: send direct */

	struct lws_webrtc_telemetry telemetry;
};

struct pss_webrtc {
	struct lws_dll2         list;
	struct lws              *wsi_ws;
	struct lws_gendtls_ctx  dtls_ctx;

	struct lws_webrtc_peer_media *media;

	uint8_t                 is_client;
	uint8_t                 handshake_started;
	/*
	 * Q-21: RFC 8445 §5.3 says the ICE ufrag SHOULD have at least 128 bits
	 * of randomness to resist off-path spoofing of STUN connectivity checks.
	 * Hex-encoding 16 random bytes needs 32 chars + NUL; [40] gives room.
	 * (ice_pwd already carried 128 bits.)
	 */
	char                    ice_ufrag[40];
	char                    ice_pwd[64];
	char                    ice_ufrag_remote[40];
	char                    ice_pwd_remote[64];
	char                    fingerprint_remote[128];

	int                     last_tu_id;
	lws_usec_t              last_pli_req_time;

	/*
	 * How many ICE candidates from the peer we have already hole-punched
	 * for this session.  Capped, since each one is an HMAC + a STUN
	 * datagram to an address the peer chose, ie, a reflector.
	 */
	uint16_t                stun_punches;

	struct lws_buflist      *buflist;

	void                    *user_data;

	/*
	 * Allocated on the first line logged, at most LWS_WEBRTC_CONN_LOG_MAX,
	 * and dropped for good once the DTLS handshake completes
	 */
	char                    *connection_log;
	size_t                  connection_log_len;
	uint8_t                 connection_log_done;

	/*
	 * lws_get_peer_host_key() of a server session's peer, counted against
	 * the session caps while the session is in vhd->sessions; empty for
	 * client sessions, which are not counted
	 */
	char                    peer[LWS_HOST_KEY_LEN];
};

void lws_webrtc_media_ref(struct lws_webrtc_peer_media *media);
void lws_webrtc_media_unref(struct lws_webrtc_peer_media **pmedia);

struct rtp_tx_tracker {
	struct pss_webrtc *pss;
	int count;
};

#endif /* __PROTOCOL_LWS_WEBRTC_H__ */
