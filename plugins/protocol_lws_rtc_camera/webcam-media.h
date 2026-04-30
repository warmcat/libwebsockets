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
	struct lws_alsa_opus_capture *alsa_cap;

	const char              *video_device;
	const char              *audio_device;
	uint32_t                width, height;
	uint32_t                target_width, target_height;
	uint32_t                pixelformat;

	uint8_t                 *yuv_frame;
	size_t                  yuv_size;

#if defined(LWS_WITH_TRANSCODE)
	struct lws_transcode_ctx *tcc_enc;
	void                    *avframe;      /* Managed by lws_transcode */
	void                    *avframe_scaled; /* Managed by lws_transcode */
	void                    *sws_ctx;      /* struct SwsContext * */
#endif

	lws_jpeg_t              *jpeg_dec;     /* If MJPEG source */

	uint64_t                frame_count;
	int                     force_av1; /* Use AV1 if true */

	int                     join_sent;
	int                     stats_sent;
	int                     caps_sent;
	int                     send_presence_report;
	uint64_t                packets_sent;
	uint64_t                packets_sent_last;

	/* Architecture HAL pointer */
	const struct lws_cam_pipeline_ops *ops;

	/* Parent pointer to App's PSS */
	struct pss_webrtc       *pss;
};

struct lws_cam_pipeline_ops {
	const char *name;
	int (*init)(struct pss_camshow *pss);
	int (*get_event_fd)(struct pss_camshow *pss);
	int (*process_rx)(struct pss_camshow *pss);
	int (*send_capabilities)(struct pss_camshow *pss);
	int (*set_control)(struct pss_camshow *pss, uint32_t id, int32_t val);
	void (*deinit)(struct pss_camshow *pss);
};

/* Backends */
extern const struct lws_cam_pipeline_ops pipeline_v4l2;
#if defined(LWS_WITH_MEDIA_RK_MPI)
extern const struct lws_cam_pipeline_ops pipeline_rk_mpi;
#endif

extern const struct lws_webrtc_ops *we_ops;

int
relay_to_session(struct pss_webrtc *pss, void *user);

#endif
