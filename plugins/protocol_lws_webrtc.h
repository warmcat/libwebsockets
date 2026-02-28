#ifndef __PROTOCOL_LWS_WEBRTC_H__
#define __PROTOCOL_LWS_WEBRTC_H__

#include <libwebsockets/lws-rtp.h>
#include <libwebsockets/lws-srtp.h>
#include <libwebsockets/lws-stun.h>

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

	/* Application callbacks */
	lws_webrtc_on_media_cb  on_media;
};

struct vhd_webrtc_udp {
	struct vhd_webrtc       *vhd;
};

struct lws_webrtc_peer_media {
	volatile int            refcount;
	pthread_mutex_t         lock_tx;

	struct lws              *wsi_udp;
	struct sockaddr_in      peer_sin;
	int                     has_peer_sin;

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

	uint16_t                last_seq_video;
	uint8_t                 seq_valid_video;
	uint16_t                last_seq_audio;
	uint8_t                 seq_valid_audio;

	char                    fmtp_audio[128];
	char                    fmtp_video[256];

	uint8_t                 sps[128];
	uint8_t                 pps[64];
	size_t                  sps_len;
	size_t                  pps_len;
	lws_usec_t              last_sps_pps_ts;
};

struct pss_webrtc {
	struct lws_dll2         list;
	struct lws              *wsi_ws;
	struct lws_gendtls_ctx  dtls_ctx;

	struct lws_webrtc_peer_media *media;

	uint8_t                 is_client;
	uint8_t                 handshake_started;
	char                    ice_ufrag[32];
	char                    ice_pwd[64];
	char                    ice_ufrag_remote[32];
	char                    ice_pwd_remote[64];
	char                    fingerprint_remote[128];

	int                     last_tu_id;
	lws_usec_t              last_pli_req_time;

	struct lws_buflist      *buflist;

	void                    *user_data;
};

void lws_webrtc_media_ref(struct lws_webrtc_peer_media *media);
void lws_webrtc_media_unref(struct lws_webrtc_peer_media **pmedia);

struct rtp_tx_tracker {
	struct pss_webrtc *pss;
	int count;
};

#endif /* __PROTOCOL_LWS_WEBRTC_H__ */
