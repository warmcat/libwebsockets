#ifndef __MIXER_MEDIA_H__
#define __MIXER_MEDIA_H__

#include <libwebsockets.h>
#include "../protocol_lws_webrtc/protocol_lws_webrtc.h"

#include <opus/opus.h>
#include <pthread.h>
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>

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
	MSG_REQ_PLI,
};

struct lws_webrtc_peer_media;
struct mixer_media_session;

struct mixer_msg {
	int                     type;
	void                    *payload;
	size_t                  len;
	struct mixer_media_session *session;
	struct mixer_room       *room; /* MSG_ADD_SESSION: room to join */

	/* Metadata for media frames */
	uint32_t                timestamp;
	int                     codec; /* enum lws_video_codec */
	int                     marker;
	uint16_t                seq;
};

/*
 * Long-lived Media Session Object
 *
 * ==========================================================================
 * OWNERSHIP RULE (the plugin runs two threads over these objects)
 * ==========================================================================
 *
 * Thread A is the lws event loop thread: callback_mixer(), sul_stats_cb(),
 * broadcast_*(), mixer_on_media(), deinit_participant_media().
 * Thread B is the detached media worker (media_worker_thread()):
 * process_control_message(), process_session_media(), process_room_mix()
 * and the layout manager ops.
 *
 * 1) `struct mixer_media_session` is the ONLY object shared between the two
 *    threads.  It is refcounted: one reference is held by the lws thread (the
 *    participant's handle) and one by the worker (its `vhd->sessions` entry).
 *    Both are dropped explicitly, and whichever thread drops the last one
 *    destroys it.
 *
 * 2) `struct participant`, `mixer_room::participants`, `mixer_room::
 *    chat_history`, `mixer_room::playing_sounds` and `vhd->rooms` are owned
 *    by the lws thread ALONE.  The worker must never reach a participant;
 *    that is why the session has no back-pointer to one.  Anything the
 *    worker needs from the participant (its display name and stats line) is
 *    snapshotted into the session below under `mutex`.
 *
 * 3) `struct mixer_room` objects themselves, and their GStreamer pipelines,
 *    are created by the lws thread before the session is handed over and are
 *    never destroyed until LWS_CALLBACK_PROTOCOL_DESTROY (which happens only
 *    after the worker has been joined).  The room pointer in a session is
 *    therefore stable, and the worker reaches rooms through it and through
 *    its own `vhd->w_rooms` list, never through `vhd->rooms`.  Because rooms
 *    are immortal for the life of the vhost, their number is capped, see
 *    `vhd->max_rooms`.
 *
 * 4) Fields below marked [mutex] may be touched by both threads and only
 *    under `mutex`.  Fields marked [worker] or [lws] belong to that thread.
 *    The `int` flags marked [lws->worker] have a single writer (the lws
 *    thread) and are only ever read as a whole word by the worker.
 */
struct mixer_media_session {
	lws_mutex_t             mutex;
	int                     ref_count; /* [mutex] */

	struct lws_webrtc_peer_media *media;
	struct mixer_room       *room; /* [worker] set at MSG_ADD_SESSION */
	uint32_t                id; /* immutable, unique per vhost */
	char                    name[64]; /* [mutex] snapshot of participant */
	char                    stats[128]; /* [mutex] snapshot of participant */
	int                     joined; /* [lws->worker] */
	int                     out_only; /* [lws->worker] */

	/*
	 * Set by the lws thread (under mutex) when it dropped its reference
	 * but could not post MSG_REMOVE_SESSION because the control ring was
	 * full.  The worker reaps these itself: the lws thread must never
	 * unlink a session from the worker's list.
	 */
	int                     orphaned; /* [mutex] */


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
	int                     can_rx_h264; /* [mutex] */
	int                     can_rx_av1; /* [mutex] */
	int                     has_pcm;
	int                     audio_seen;
	int                     audio_energy;
	int                     video_muted; /* [lws->worker] */

	/* Sequence Number Handling */
	lws_dll2_owner_t        rtp_queue;     /* Raw RTP packets (sorted) */
	uint16_t                expect_seq;    /* Next expected Seq Num */
	int                     expect_valid;

	/* Video Jitter Buffer */
	struct lws_dll2_owner   video_queue;

	/* Video decoding */
	GstElement              *appsrc;
	GstElement              *decodebin;
	GstPad                  *compositor_pad;

	uint8_t                 *video_buf;
	size_t                  video_len;
	size_t                  video_alloc;
	int                     fu_a_active;

	uint8_t                 *obu_buf;
	size_t                  obu_len;
	size_t                  obu_alloc;

	uint32_t                video_timestamp;

	int                     frame_complete;
	uint64_t                decoded_frames;
	lws_usec_t              last_pli_req;
	lws_usec_t              last_frame_usec;

	uint32_t                first_timestamp;
	int                     timestamp_initialized;
	uint64_t                gst_time_offset;
	uint64_t                last_pts;

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
	uint32_t                gst_qos_drops;

	lws_dll2_t              list; /* List in vhd->sessions (Worker Side) */

	/* Input Queue (LWS -> Worker), and its tail: both [mutex] */
	struct lws_ring         *ring_input;
};

/*
 * struct participant is owned by the lws event loop thread alone, see the
 * ownership rule at struct mixer_media_session.  The worker never sees one.
 */
struct participant {
	struct mixer_media_session *session; /* Ref-counted handle */

	char                    name[64];
	char                    stats[128];
	char                    client_stats[128];
	char                    *capabilities_video; /* JSON blob of video device controls */
	char                    *capabilities_audio; /* JSON blob of audio device controls */
    int                     last_codec; /* enum lws_video_codec */
	int                     joined;

	int                     out_only;

	/* Presence tracking */
	int                     presence_missed;

	/* Audio Energy Tracking */
	lws_usec_t              last_report_time;
	int                     audio_energy; /* Calculated by Worker, read by LWS? Or passed via msg? */

	/* Video Sequence & PLI Tracking (Main Thread) */
	uint16_t                expect_seq;
	int                     expect_valid;
	lws_usec_t              last_pli_req;

	/* Telemetry Rate Calculation */
	struct lws_webrtc_telemetry last_telemetry;
	uint32_t                last_gst_qos_drops;

	/*
	 * Authorization state, see README.md.  `id` is the opaque,
	 * server-assigned handle other peers must use to address this
	 * participant; `controller` is set on the first participant to join
	 * the room, and only the controller may drive somebody else's camera
	 * controls or read their device capabilities.
	 */
	char                    id[24];
	int                     controller;
	lws_usec_t              last_caps_req;

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

	/* Dynamic restart flags */
	int                     pending_restart;
	int                     target_level;
};

struct mixer_encoded_frame {
	lws_dll2_t              list;
	uint8_t                 *buf;
	size_t                  len;
	uint32_t                rtp_ts;
	int                     is_keyframe;
};

struct mixer_room {
	lws_dll2_t              list; /* [lws] stored in vhd->rooms */
	lws_dll2_t              w_list; /* [worker] stored in vhd->w_rooms */
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
	GstElement              *pipeline;
	GstElement              *compositor;
	GstElement              *appsink_h264;
	GstElement              *appsink_av1;

	pthread_mutex_t         encode_mutex;
	lws_dll2_owner_t        h264_queue;
	lws_dll2_owner_t        av1_queue;

	struct lws_adapt        *adapt_h264;
	int                     active_h264_level;

	uint32_t                master_w, master_h;
	int64_t                 master_pts;

	/*
	 * The layout context is worker-owned.  The worker renders it to JSON
	 * and publishes the string here; the lws thread only ever copies the
	 * finished string out under mutex_layout to broadcast it, so it never
	 * walks the region array or a session pointer.
	 */
	const struct layout_manager_ops *lm_ops; /* [worker] */
	void                    *lm_ctx; /* [worker] */
	lws_mutex_t             mutex_layout;
	char                    *layout_json; /* [mutex_layout] */

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

LWS_VISIBLE LWS_EXTERN_FOR_DATA const struct layout_manager_ops lm_quad_ops;
LWS_VISIBLE LWS_EXTERN_FOR_DATA const struct layout_manager_ops lm_speaker_ops;

/*
 * Rooms are never destroyed while the vhost lives (see the ownership rule at
 * struct mixer_media_session), and each one owns a full GStreamer encode
 * pipeline, so the count has to be capped: an unauthenticated peer picks the
 * room name.  Overridable with the "max-rooms" pvo.
 */
#define MIXER_DEFAULT_MAX_ROOMS 8

/* the largest device-capability blob we will store and relay per participant */
#define MIXER_MAX_CAPS_LEN 2048

/* minimum interval between request_caps from one participant */
#define MIXER_CAPS_REQ_MIN_INTERVAL_US (1 * LWS_US_PER_SEC)

/* don't add to a peer's tx backlog past this */
#define MIXER_MAX_TX_BACKLOG 262144

struct vhd_mixer {
	struct vhd_webrtc       *vhd;

	lws_dll2_owner_t        rooms; /* [lws] list of struct mixer_room */
	lws_dll2_owner_t        w_rooms; /* [worker] the same rooms */
	int                     num_rooms; /* [lws] */
	int                     max_rooms; /* immutable after PROTOCOL_INIT */
	uint32_t                next_session_id; /* [lws] */
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

	char                    pipeline_template[512]; /* PVO pipeline string */

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
init_session_media(struct mixer_media_session *s, enum lws_video_codec codec);

void
deinit_participant_media(struct participant *p);

int
media_handle_video_packet(struct participant *p, const uint8_t *buf, size_t len, int marker, uint16_t seq);

void *
media_worker_thread(void *d);

/*
 * Retire everything the worker still owns.  Only legal on the lws thread
 * after the worker has been joined, and it must be done before the rooms are
 * destroyed, since the sessions it releases reach into their pipelines.
 */
void
mixer_worker_drain(struct vhd_mixer *vhd);

struct mixer_media_session *
mixer_media_session_create(struct vhd_mixer *vhd);

/*
 * Hand a newly created session to the worker thread for room \p r.
 *
 * On success (0) the worker owns a second reference, which it releases when
 * it processes the matching MSG_REMOVE_SESSION.  On failure (-1) no
 * reference was handed over and the caller must simply unref its own.
 */
int
mixer_media_session_publish(struct mixer_media_session *s, struct mixer_room *r);

/*
 * Update the worker-visible snapshot of the participant's display name and
 * stats line.  Called on the lws thread only; takes s->mutex.
 */
void
mixer_media_session_set_ident(struct mixer_media_session *s, const char *name,
			      const char *stats);

void
mixer_media_session_ref(struct mixer_media_session *s);

void
mixer_media_session_unref(struct mixer_media_session *s);

void
mixer_force_keyframe(struct mixer_room *r);

#endif /* __MIXER_MEDIA_H__ */
