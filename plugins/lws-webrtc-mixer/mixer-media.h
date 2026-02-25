#ifndef __MIXER_MEDIA_H__
#define __MIXER_MEDIA_H__

#include <libwebsockets.h>

#include <opus/opus.h>
#include <pthread.h>

int16_t soft_clip(int32_t sample);

#define AUDIO_RATE 48000
#define AUDIO_CHANNELS 1
#define AUDIO_FRAME_MS 20
#define AUDIO_SAMPLES_PER_FRAME ((AUDIO_RATE * AUDIO_FRAME_MS) / 1000)

/* enum lws_webrtc_codec is in lws-protocols-plugins.h */
#define lws_video_codec lws_webrtc_codec
#define LWS_CODEC_H264 LWS_WEBRTC_CODEC_H264
#define LWS_CODEC_AV1 LWS_WEBRTC_CODEC_AV1

struct video_queue_item {
	lws_dll2_t              list;
	uint8_t                 *buf;
	size_t                  len;
	int                     marker;
	lws_usec_t              arrival_us;

	uint32_t                rtp_ts;
	uint16_t                seq;
};

struct rtp_queue_item {
	lws_dll2_t              list;
	uint8_t                 *buf;
	size_t                  len;

	uint16_t                seq;
	uint8_t                 marker;
	lws_usec_t              arrival_us;
};

/* Threading / Messaging */
enum mixer_msg_type {
	MSG_ADD_SESSION,
	MSG_REMOVE_SESSION,
	MSG_AUDIO_FRAME,
	MSG_VIDEO_FRAME,
	MSG_VSYNC_TICK, /* Optional internal tick */
	MSG_UNREF_SESSION,
};

struct lws_webrtc_peer_media;
struct mixer_media_session;

struct mixer_msg {
	int                     type;
	void                    *payload;
	size_t                  len;
	struct mixer_media_session *session;

	/* Metadata for media frames */
	uint32_t                timestamp;
	int                     codec; /* enum lws_video_codec */
	int                     marker;
	uint16_t                seq;
};

/*
 * Long-lived Media Session Object
 * Ref-counted: 1 ref for LWS (participant), 1 ref for Worker
 */
struct mixer_media_session {
	lws_mutex_t             mutex;
	int                     ref_count;

	struct lws_webrtc_peer_media *media;
	void                    *parent_p; /* Back-pointer to participant (Access only with Mutex) */
	char                    room_name[64];
	int                     joined;
	int                     out_only;

	/* Audio Resources */
	OpusDecoder             *decoder;
	OpusEncoder             *encoder;

	/* Audio Jitter Buffer */
	int16_t                 pcm_in[AUDIO_SAMPLES_PER_FRAME];
	struct lws_ring         *ring_pcm;
	int16_t                 *ring_buffer;
	uint32_t                ring_tail;
	uint32_t                ring_pcm_tail;
	int                     last_codec;
	int                     can_rx_h264;
	int                     can_rx_av1;
	int                     has_pcm;
	int                     audio_seen;
	int                     audio_energy;

	/* Sequence Number Handling */
	lws_dll2_owner_t        rtp_queue;     /* Raw RTP packets (sorted) */
	uint16_t                expect_seq;    /* Next expected Seq Num */
	int                     expect_valid;

	/* Video Jitter Buffer */
	struct lws_dll2_owner   video_queue;

	/* Video decoding */
	struct lws_transcode_ctx *tcc_dec;
	void                    *avframe_dec;    /* Managed by lws_transcode */
	void                    *avframe_delayed; /* Back-buffer for 80ms delay */
	lws_usec_t              delayed_frame_ready_time;
	void                    *avframe_tmp;    /* Managed by lws_transcode */
	void                    *sws_ctx_dec;    /* struct SwsContext * */
	void                    *avframe_scaled; /* Managed by lws_transcode */

	uint8_t                 *video_buf;
	size_t                  video_len;
	size_t                  video_alloc;

	uint8_t                 *obu_buf;
	size_t                  obu_len;
	size_t                  obu_alloc;

	int                     frame_complete;
	uint64_t                decoded_frames;
	lws_usec_t              last_pli_req;
	lws_usec_t              last_frame_usec;

	int                     last_dec_w, last_dec_h, last_dec_fmt;
	int                     last_dst_w, last_dst_h;
	enum lws_video_codec    last_dec_codec;

	/* Recovery */
	int                     waiting_for_keyframe;

	/* FPS Tracking */
	uint32_t                processed_frames_count;
	uint32_t                last_processed_frames_count;
	lws_usec_t              last_fps_check;
	int                     current_fps;

	lws_dll2_t              list; /* List in vhd->sessions (Worker Side) */

	/* Input Queue (LWS -> Worker) */
	/* We use a lock-protected ring for input to this session */
	struct lws_ring         *ring_input;
	struct mixer_msg        *ring_input_buffer;
};

struct participant {
	struct mixer_media_session *session; /* Ref-counted handle */

	char                    name[64];
	char                    stats[128];
	char                    client_stats[128];
	char                    *capabilities; /* JSON blob of device controls */
    int                     last_codec; /* enum lws_video_codec */
	int                     joined;

	int                     out_only;

	/* Presence tracking */
	int                     presence_missed;

	/* Audio Energy Tracking */
	lws_usec_t              last_report_time;
	int                     audio_energy; /* Calculated by Worker, read by LWS? Or passed via msg? */

	struct mixer_room       *room;
	struct pss_webrtc       *pss;
	struct lws              *wsi;
	lws_dll2_t              list;
};

struct sound_clip {
	int16_t                 *samples;
	size_t                  length_samples;
	int                     channels;
};

struct active_sound {
	lws_dll2_t              list;
	struct sound_clip       *clip;
	size_t                  offset;
	struct participant      *exclude_p;
	int                     last_mix_len;
};


struct chat_message {
	lws_dll2_t              list;
	char                    *sender;
	char                    *text;
	uint64_t                timestamp; /* microseconds */
};

struct mixer_room; /* forward declaration */

struct encoder_thread {
	pthread_t               thread;
	int                     running;
	pthread_mutex_t         mutex;
	pthread_cond_t          cond;

	/* Input */
	void                    *enc_frame;
	int                     frame_ready;
	uint32_t                rtp_pts;

	/* Output */
	uint8_t                 *encoded_buf;
	size_t                  encoded_len;
	size_t                  encoded_alloc;
	int                     encode_done;
	uint32_t                encoded_rtp_pts;
	enum lws_video_codec    codec;
	struct mixer_room       *room;
};

struct mixer_room {
	lws_dll2_t              list; /* stored in vhd->rooms */
	struct vhd_mixer        *vhd;  /* parent */
	char                    name[64];
	lws_dll2_owner_t        sessions; /* Worker Side: List of active mixer_media_session */

	lws_dll2_owner_t        participants; /* list of struct participant (LWS Side) */
	lws_dll2_owner_t        playing_sounds; /* list of struct active_sound */

	/* Chat History */
	lws_dll2_owner_t        chat_history; /* list of struct chat_message */

	/* Room-specific timers */
	lws_sorted_usec_list_t  sul_presence;

	/* Audio Mixing */
	int32_t                 mixed_pcm[AUDIO_SAMPLES_PER_FRAME];

	struct participant      *active_video; /* Insecure in threaded model? Used for UI hints */
	/* We need a threaded way to signal active speaker.
	   Worker calculates energy -> Sends MSG_AUDIO_LEVEL -> LWS updates this.
	   */

	/* Master video compositing */
	struct lws_transcode_ctx *tcc_enc_h264;
	struct lws_transcode_ctx *tcc_enc_av1;
	void                    *master_frame;   /* Managed by lws_transcode */
	struct encoder_thread   enc_thread_h264;
	struct encoder_thread   enc_thread_av1;

	uint32_t                master_w, master_h;
	int64_t                 master_pts;

	const struct layout_manager_ops *lm_ops;
	void                    *lm_ctx;

	lws_audio_vu_info_t     audio_info;
	lws_usec_t              avg_tick_us;
};

struct lws_mixer_layout_region {
	struct mixer_media_session *s;
	int x;
	int y;
	int w;
	int h;
};

struct layout_manager_ops {
	void * (*create)(struct mixer_room *r);
	void (*destroy)(void *ctx);
	void (*update)(struct mixer_room *r, void *ctx);

	/* Returns array of regions and sets count */
	const struct lws_mixer_layout_region * (*get_regions)(void *ctx, int *count);

	/* Returns a JSON string containing the layout map / overlay text. Caller frees. */
	char * (*get_json)(void *ctx);
};

LWS_VISIBLE extern const struct layout_manager_ops lm_quad_ops;
LWS_VISIBLE extern const struct layout_manager_ops lm_speaker_ops;

struct vhd_mixer {
	struct vhd_webrtc       *vhd;

	lws_dll2_owner_t        rooms; /* list of struct mixer_room */
	lws_sorted_usec_list_t  sul_stats; /* Global system stats */

	/* Worker Threading */
	pthread_t               worker_thread;
	int                     worker_running;

	lws_mutex_t             mutex_tx;  /* Protects ring_tx */
	struct lws_ring         *ring_tx;  /* Worker -> LWS */
	uint32_t                ring_tx_tail; /* LWS Side Tail */
	struct mixer_msg        *ring_tx_buffer;

	lws_mutex_t             mutex_rx; /* Protects ring_rx (Control) */
	struct lws_ring         *ring_rx; /* LWS -> Worker (Control: Add/Remove Session) */
	uint32_t                ring_rx_tail; /* Worker Side Tail */
	struct mixer_msg        *ring_rx_buffer;

	lws_dll2_owner_t        sessions; /* Worker Side: List of active mixer_media_session */

	/* Global Sound Assets */
	struct sound_clip       sfx_join;
	struct sound_clip       sfx_leave;
};

extern const struct lws_webrtc_ops *we_ops;

int
load_sound_clip(struct sound_clip *sc, const char *path);

void
play_sound(struct mixer_room *r, struct sound_clip *sc, struct participant *exclude);

void
mix_sounds(struct mixer_room *r, int32_t *mix_buf, int samples);

void
prune_sounds(struct mixer_room *r);

int
mixer_room_init(struct mixer_room *r);

void
mixer_room_deinit(struct mixer_room *r);

int
init_participant_media(struct participant *p, enum lws_video_codec codec);

void
deinit_participant_media(struct participant *p);

int
media_handle_video_packet(struct participant *p, const uint8_t *buf, size_t len, int marker, uint16_t seq);

int
media_compose_and_broadcast(struct mixer_room *r);

void *
media_worker_thread(void *d);

struct mixer_media_session *
mixer_media_session_create(struct vhd_mixer *vhd, void *parent);

void
mixer_media_session_ref(struct mixer_media_session *s);

void
mixer_media_session_unref(struct mixer_media_session *s);

#endif /* __MIXER_MEDIA_H__ */
