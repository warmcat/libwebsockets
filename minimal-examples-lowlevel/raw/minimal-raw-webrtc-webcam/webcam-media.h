#ifndef __WEBCAM_MEDIA_H__
#define __WEBCAM_MEDIA_H__

#include <libwebsockets.h>
#include <opus/opus.h>

#define AUDIO_RATE		48000
#define AUDIO_CHANNELS		1
#define AUDIO_FRAME_MS		20
#define AUDIO_SAMPLES_PER_FRAME	((AUDIO_RATE * AUDIO_FRAME_MS) / 1000)

#if !defined(WIN32) && !defined(_WIN32)
#include <linux/videodev2.h>

struct per_vhost_data {
	struct vhd_webrtc       *vhd;
	const char              *video_device;

	struct lws_v4l2_ctx     *v4l2_ctx;
	uint32_t                width, height;
	uint32_t                pixelformat;
	struct lws              *wsi_v4l2;

	void                    *jpeg_dec; /* lws_jpeg_t * */
	uint8_t                 *yuv_frame;
	size_t                  yuv_size;

	struct lws_transcode_ctx *tcc_enc;
	void                    *avframe;  /* Managed by lws_transcode */
	void                    *avframe_scaled; /* Managed by lws_transcode */
	void                    *sws_ctx;  /* Managed by lws_transcode */

	uint32_t                target_width, target_height;

	struct lws_alsa_ctx     *alsa_ctx;
	OpusEncoder             *opus_enc;
	struct lws              *wsi_alsa;

	int16_t                 audio_samples[AUDIO_SAMPLES_PER_FRAME];
	uint8_t                 opus_out[512];

	int                     raw_rx_count;
	int                     frame_count;
};

int
media_init(struct per_vhost_data *vhd);

void
media_deinit(struct per_vhost_data *vhd);

int
media_update_scaler(struct per_vhost_data *vhd);

int
media_process_video_frame(struct per_vhost_data *vhd, int index, size_t len);

#endif

struct relay_data {
	const uint8_t           *buf;
	size_t                  len;
	int                     is_video;
};

extern const struct lws_webrtc_ops *we_ops;

int
relay_to_session(struct pss_webrtc *pss, void *user);

#endif /* __WEBCAM_MEDIA_H__ */
