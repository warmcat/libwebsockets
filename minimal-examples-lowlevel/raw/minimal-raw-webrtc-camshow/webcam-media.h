#ifndef __WEBCAM_MEDIA_H__
#define __WEBCAM_MEDIA_H__

#include <libwebsockets.h>
#include <opus/opus.h>

#define AUDIO_RATE 48000
#define AUDIO_CHANNELS 1
#define AUDIO_FRAME_MS 20
#define AUDIO_SAMPLES_PER_FRAME ((AUDIO_RATE * AUDIO_FRAME_MS) / 1000)

struct vhd_webrtc;
struct pss_webrtc;

struct relay_data {
	void *buf;
	size_t len;
	int is_video;
};

struct pss_camshow {
	struct lws_context      *context;
	struct lws_vhost        *vhost;
	const struct lws_protocols *protocol;

	struct vhd_webrtc       *vhd;   /* The lws-webrtc plugin's VHD */

	struct lws              *wsi_v4l2;
	struct lws              *wsi_alsa;
	void                    *v4l2_ctx; /* lws_v4l2_state * */
	struct lws_alsa_state   *alsa_ctx;

	OpusEncoder             *opus_enc;
	uint8_t                 opus_out[512];
	int16_t                 audio_samples[AUDIO_SAMPLES_PER_FRAME];

	const char              *video_device;
	uint32_t                width, height;
	uint32_t                target_width, target_height;
	uint32_t                pixelformat;

	uint8_t                 *yuv_frame;
	size_t                  yuv_size;

	struct lws_transcode_ctx *tcc_enc;
	void                    *avframe;      /* Managed by lws_transcode */
	void                    *avframe_scaled; /* Managed by lws_transcode */
	void                    *sws_ctx;      /* struct SwsContext * */

	lws_jpeg_t              *jpeg_dec;     /* If MJPEG source */

	uint64_t                frame_count;
	int                     force_av1; /* Use AV1 if true */

	int                     join_sent;
	int                     stats_sent;
	int                     caps_sent;
	int                     send_presence_report;
	uint64_t                packets_sent;
	uint64_t                packets_sent_last;

	/* Parent pointer to App's PSS */
	struct pss_webrtc       *pss;
};

int
media_init(struct pss_camshow *pss);

void
media_deinit(struct pss_camshow *pss);

int
media_update_scaler(struct pss_camshow *pss);

int
media_process_video_frame(struct pss_camshow *pss, int index, size_t len);

extern const struct lws_webrtc_ops *we_ops;

int
relay_to_session(struct pss_webrtc *pss, void *user);

#endif
