/*
 * lws-minimal-raw-webrtc-webcam
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This example demonstrates selecting an H.264 stream from a V4L2 webcam
 * and preparing it for WebRTC streaming.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <arpa/inet.h>

#include <libwebsockets/lws-rtp.h>
#include <libwebsockets/lws-srtp.h>
#include <libwebsockets/lws-stun.h>
#include <alsa/asoundlib.h>
#include <opus/opus.h>

#define AUDIO_RATE 48000
#define AUDIO_CHANNELS 1
#define AUDIO_FRAME_MS 20
#define AUDIO_SAMPLES_PER_FRAME ((AUDIO_RATE * AUDIO_FRAME_MS) / 1000)

static int interrupted;


struct v4l2_buf {
	void                    *start;
	size_t                  length;
};

struct per_vhost_data {
	struct lws_context      *context;
	struct lws_vhost        *vhost;
	const char              *video_device;
	int                     video_fd;
	struct v4l2_buf         *buffers;
	int                     n_buffers;
	uint32_t                width, height;
	struct lws              *wsi_v4l2;
	struct lws              *wsi_udp;
	struct lws_dll2_owner   sessions;

	uint8_t                 *cert_mem;
	size_t                  cert_len;
	uint8_t                 *key_mem;
	size_t                  key_len;
	char                    fingerprint[128];

	snd_pcm_t               *pcm_capture;
	OpusEncoder             *opus_enc;
	struct lws              *wsi_alsa;

	int16_t                 audio_samples[AUDIO_SAMPLES_PER_FRAME];
	uint8_t                 opus_out[512];
};

struct per_session_data {
	struct lws_dll2         list;
	struct lws              *wsi_ws;
	struct lws_gendtls_ctx  dtls_ctx;
	struct lws_rtp_ctx      rtp_ctx;
	struct lws_rtp_ctx      rtp_ctx_audio;
	struct lws_srtp_ctx     srtp_ctx;
	struct lws_srtp_ctx     srtp_ctx_rx;
	struct lws              *wsi_udp;
	struct sockaddr_in      peer_sin;

	uint8_t                 sps[128];
	uint8_t                 pps[64];
	size_t                  sps_len;
	size_t                  pps_len;
	lws_usec_t              last_sps_pps_ts;

	int                     has_peer_sin;
	int                     handshake_started;
	int                     handshake_done;
	char                    fingerprint[128];
	uint32_t                rtp_ssrc;
	uint32_t                rtp_ssrc_audio;
	uint8_t                 rtp_pt;
	uint8_t                 rtp_pt_audio;
	uint16_t                rtp_seq;
	uint32_t                rtp_ts;
	uint32_t                rtp_ts_audio;

	lws_sorted_usec_list_t  sul_stats;
	uint32_t                tx_count;
	char                    ice_ufrag[16];
	char                    ice_pwd[32];
};

static char external_ip[64] = "127.0.0.1";
static struct per_vhost_data *vhd_global;

static void
sul_stats_cb(lws_sorted_usec_list_t *sul)
{
	struct per_session_data *pss = lws_container_of(sul, struct per_session_data, sul_stats);

	lwsl_info("Stats: TX packets: %u, Handshake: S=%d D=%d\n",
		    pss->tx_count, pss->handshake_started, pss->handshake_done);

	lws_sul_schedule(lws_get_context(pss->wsi_ws), 0, &pss->sul_stats, sul_stats_cb, 1 * LWS_US_PER_SEC);
}

static int
alsa_init(struct per_vhost_data *vhd)
{
	snd_pcm_hw_params_t *params;
	struct pollfd pfd;
	lws_sock_file_fd_type u;
	unsigned int rate = AUDIO_RATE;
	int n;

	n = snd_pcm_open(&vhd->pcm_capture, "default", SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK);
	if (n < 0) {
		lwsl_err("ALSA: Can't open capture: %s\n", snd_strerror(n));
		return -1;
	}

	if (snd_pcm_poll_descriptors(vhd->pcm_capture, &pfd, 1) != 1) {
		lwsl_err("ALSA: Failed to get capture desc\n");
		goto bail;
	}

	u.filefd = (lws_filefd_type)(long long)pfd.fd;
	vhd->wsi_alsa = lws_adopt_descriptor_vhost(vhd->vhost, LWS_ADOPT_RAW_FILE_DESC, u, "lws-webrtc", NULL);
	if (!vhd->wsi_alsa) {
		lwsl_err("ALSA: Failed to adopt capture desc\n");
		goto bail;
	}

	snd_pcm_hw_params_malloc(&params);
	snd_pcm_hw_params_any(vhd->pcm_capture, params);
	snd_pcm_hw_params_set_access(vhd->pcm_capture, params, SND_PCM_ACCESS_RW_INTERLEAVED);
	snd_pcm_hw_params_set_format(vhd->pcm_capture, params, SND_PCM_FORMAT_S16_LE);
	snd_pcm_hw_params_set_channels(vhd->pcm_capture, params, AUDIO_CHANNELS);
	snd_pcm_hw_params_set_rate_near(vhd->pcm_capture, params, &rate, 0);
	n = snd_pcm_hw_params(vhd->pcm_capture, params);
	snd_pcm_hw_params_free(params);
	if (n < 0) {
		lwsl_err("ALSA: Set hw params failed: %s\n", snd_strerror(n));
		goto bail;
	}

	lwsl_user("ALSA: Captured opened at %uHz\n", rate);
	return 0;

bail:
	snd_pcm_close(vhd->pcm_capture);
	return -1;
}

static int
opus_init(struct per_vhost_data *vhd)
{
	int err;
	vhd->opus_enc = opus_encoder_create(AUDIO_RATE, AUDIO_CHANNELS, OPUS_APPLICATION_VOIP, &err);
	if (!vhd->opus_enc) {
		lwsl_err("OPUS: Failed to create encoder: %d\n", err);
		return -1;
	}
	lwsl_user("OPUS: Encoder initialized\n");
	return 0;
}

static int
v4l2_init(struct per_vhost_data *vhd)
{
	struct v4l2_capability          cap;
        struct v4l2_requestbuffers      req;
        struct v4l2_fmtdesc             fmtdesc;
	struct v4l2_format              fmt;
	int                             found = 0;

	vhd->video_fd = open(vhd->video_device, O_RDWR | O_NONBLOCK, 0);
	if (vhd->video_fd < 0) {
		lwsl_err("Unable to open %s\n", vhd->video_device);
		return -1;
	}

	if (ioctl(vhd->video_fd, VIDIOC_QUERYCAP, &cap) < 0) {
		lwsl_err("VIDIOC_QUERYCAP failed\n");
		goto bail;
	}

	if (!(cap.device_caps & V4L2_CAP_VIDEO_CAPTURE)) {
		lwsl_err("Device does not support video capture\n");
		goto bail;
	}

	/* Enumerate formats to find H.264 */
	memset(&fmtdesc, 0, sizeof(fmtdesc));
	fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	while (ioctl(vhd->video_fd, VIDIOC_ENUM_FMT, &fmtdesc) == 0) {
		lwsl_info("  Found format: %s (0x%08x)\n", fmtdesc.description, fmtdesc.pixelformat);
		if (fmtdesc.pixelformat == V4L2_PIX_FMT_H264) {
			found = 1;
			break;
		}
		fmtdesc.index++;
	}

	if (!found) {
		lwsl_err("H.264 format not found on device %s\n", vhd->video_device);
		goto bail;
	}

	/* Find closest resolution to 1280x720 */
	{
		struct v4l2_frmsizeenum frmsize;
		uint32_t best_w = 0, best_h = 0;
		int best_diff = 0x7fffffff;

		memset(&frmsize, 0, sizeof(frmsize));
		frmsize.pixel_format = V4L2_PIX_FMT_H264;
		frmsize.index = 0;

		while (ioctl(vhd->video_fd, VIDIOC_ENUM_FRAMESIZES, &frmsize) == 0) {
			if (frmsize.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
				int diff = abs((int)frmsize.discrete.width - 1280) +
					   abs((int)frmsize.discrete.height - 720);

				lwsl_info("  Available resolution: %dx%d (diff %d)\n",
					  frmsize.discrete.width, frmsize.discrete.height, diff);

				if (diff < best_diff) {
					best_diff = diff;
					best_w = frmsize.discrete.width;
					best_h = frmsize.discrete.height;
				}
			}
			frmsize.index++;
		}

		if (best_w > 0) {
			vhd->width = best_w;
			vhd->height = best_h;
			lwsl_notice("Selected resolution: %dx%d (diff %d)\n", vhd->width, vhd->height, best_diff);
		} else {
			lwsl_warn("Could not enumerate framesizes, falling back to %dx%d\n", vhd->width, vhd->height);
		}
	}

	memset(&fmt, 0, sizeof(fmt));
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.width = vhd->width;
	fmt.fmt.pix.height = vhd->height;
	fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_H264;
	fmt.fmt.pix.field = V4L2_FIELD_ANY;

	if (ioctl(vhd->video_fd, VIDIOC_S_FMT, &fmt) < 0) {
		lwsl_err("VIDIOC_S_FMT failed\n");
		goto bail;
	}

	lwsl_user("Selected H.264 %dx%d\n", (int)fmt.fmt.pix.width, (int)fmt.fmt.pix.height);

	memset(&req, 0, sizeof(req));
	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;

	if (ioctl(vhd->video_fd, VIDIOC_REQBUFS, &req) < 0) {
		lwsl_err("VIDIOC_REQBUFS failed\n");
		goto bail;
	}

	vhd->buffers = malloc(sizeof(*vhd->buffers) * req.count);
	if (!vhd->buffers)
		goto bail;
	memset(vhd->buffers, 0, sizeof(*vhd->buffers) * req.count);

	for (vhd->n_buffers = 0; (uint32_t)vhd->n_buffers < req.count; vhd->n_buffers++) {
		struct v4l2_buffer buf;
		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = (uint32_t)vhd->n_buffers;

		if (ioctl(vhd->video_fd, VIDIOC_QUERYBUF, &buf) < 0) {
			lwsl_err("VIDIOC_QUERYBUF failed\n");
			goto bail;
		}

		vhd->buffers[vhd->n_buffers].length = buf.length;
		vhd->buffers[vhd->n_buffers].start = mmap(NULL, buf.length,
				PROT_READ | PROT_WRITE, MAP_SHARED, vhd->video_fd, buf.m.offset);

		if (vhd->buffers[vhd->n_buffers].start == MAP_FAILED) {
			lwsl_err("mmap failed\n");
			goto bail;
		}

		if (ioctl(vhd->video_fd, VIDIOC_QBUF, &buf) < 0) {
			lwsl_err("VIDIOC_QBUF failed\n");
			goto bail;
		}
	}

	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(vhd->video_fd, VIDIOC_STREAMON, &type) < 0) {
		lwsl_err("VIDIOC_STREAMON failed\n");
		goto bail;
	}

	return 0;

bail:
	if (vhd->video_fd >= 0)
		close(vhd->video_fd);
	if (vhd->buffers)
		free(vhd->buffers);
	return -1;
}

static void
rtp_packet_cb(void *priv, const uint8_t *pkt, size_t len, int marker)
{
	struct per_session_data *pss = (struct per_session_data *)priv;
	uint8_t protected_pkt[2048 + LWS_PRE];
	uint8_t *p = protected_pkt + LWS_PRE;
	size_t protected_len = len;

	(void)marker;

	if (!pss->has_peer_sin)
		return;

	memcpy(p, pkt, len);
	if (lws_srtp_protect(&pss->srtp_ctx, p, &protected_len, 2048)) {
		lwsl_err("SRTP protect failed\n");
		return;
	}

	if (sendto(lws_get_socket_fd(pss->wsi_udp), (const char *)p, protected_len, 0,
		   (const struct sockaddr *)&pss->peer_sin, sizeof(pss->peer_sin)) < (int)protected_len)
		lwsl_err("UDP sendto failed\n");

	pss->tx_count++;
}

static void
rtp_send_h264_frame(struct per_session_data *pss, const uint8_t *buf, size_t len)
{
	const uint8_t *p = buf, *end = buf + len;
	const uint8_t *nal_start = NULL;
	int next_start_len = 0;

	pss->rtp_ctx.ts += 3000; /* Assume 30fps, 90kHz clock */

	/* Find first NALU */
	while (p + 3 < end) {
		if (p[0] == 0 && p[1] == 0 && p[2] == 1) {
			nal_start = p + 3;
			p += 3;
			break;
		}
		if (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1) {
			nal_start = p + 4;
			p += 4;
			break;
		}
		p++;
	}

	if (!nal_start)
		return;

	while (p < end) {
		const uint8_t *q = p;
		const uint8_t *next_nal = NULL;

		while (q + 3 < end) {
			if (q[0] == 0 && q[1] == 0 && q[2] == 0 && q[3] == 1) {
				next_nal = q;
				next_start_len = 4;
				break;
			}
			if (q[0] == 0 && q[1] == 0 && q[2] == 1) {
				next_nal = q;
				next_start_len = 3;
				break;
			}
			q++;
		}

		size_t nal_len = next_nal ? (size_t)(next_nal - nal_start) : (size_t)(end - nal_start);
		uint8_t type = nal_start[0] & 0x1f;
		int last = !next_nal;

		if (type == 7) { /* SPS */
			if (nal_len <= sizeof(pss->sps)) {
				memcpy(pss->sps, nal_start, nal_len);
				pss->sps_len = nal_len;

				if (nal_len >= 4) {
					lwsl_info("SPS: Actual profile_idc %02X, constraints %02X, level %02X\n",
						    nal_start[1], nal_start[2], nal_start[3]);
					/*
					 * SPS Shimming: Force whatever profile the camera sends
					 * to match our signaled SDP Baseline Profile (42E01F).
					 */
					pss->sps[1] = 0x42;
					pss->sps[2] = 0xE0;
					pss->sps[3] = 0x1F;
					lwsl_info("SPS: Shimmed to 42E01F to match SDP signaling\n");
				}
			}
		} else if (type == 8) { /* PPS */
			if (nal_len <= sizeof(pss->pps)) {
				memcpy(pss->pps, nal_start, nal_len);
				pss->pps_len = nal_len;
			}
		} else if (type == 5) { /* IDR */
			lws_usec_t now = lws_now_usecs();
			if (now - pss->last_sps_pps_ts > 1 * LWS_US_PER_SEC) {
				if (pss->sps_len) {
					lwsl_info("Injecting SPS (%d bytes)\n", (int)pss->sps_len);
					lws_rtp_h264_packetize(&pss->rtp_ctx, pss->sps, pss->sps_len, 0, 1200, rtp_packet_cb, pss);
				}
				if (pss->pps_len) {
					lwsl_info("Injecting PPS (%d bytes)\n", (int)pss->pps_len);
					lws_rtp_h264_packetize(&pss->rtp_ctx, pss->pps, pss->pps_len, 0, 1200, rtp_packet_cb, pss);
				}
				pss->last_sps_pps_ts = now;
			}
		}

		lwsl_debug("NAL Type %d (%d bytes)%s\n", type, (int)nal_len, last ? " [LAST]" : "");
		lws_rtp_h264_packetize(&pss->rtp_ctx, nal_start, nal_len, last, 1200, rtp_packet_cb, pss);

		if (!next_nal)
			break;

		nal_start = next_nal + next_start_len;
		p = nal_start;
	}
}

static int
callback_webrtc(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct per_session_data *pss = (struct per_session_data *)user;
	struct per_vhost_data *vhd = (struct per_vhost_data *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	char json_buf[LWS_PRE + 3072], *p = &json_buf[LWS_PRE];
	size_t alen, n_sdp;
	const char *val;
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi),
						  sizeof(struct per_vhost_data));
		vhd->context            = lws_get_context(wsi);
		vhd->vhost              = lws_get_vhost(wsi);
		vhd_global              = vhd;
		vhd->video_device       = "/dev/video0";
		vhd->width              = 1280;
		vhd->height             = 720;

		if (v4l2_init(vhd))
			return -1;

		if (alsa_init(vhd))
			lwsl_warn("ALSA: initialization failed, audio will be disabled\n");

		if (opus_init(vhd))
			return -1;

		/* Generate Ephemeral Identity for DTLS */
		lwsl_user("Generating ephemeral self-signed certificate for WebRTC DTLS...\n");
		if (lws_x509_create_self_signed(vhd->context, &vhd->cert_mem, &vhd->cert_len,
					       &vhd->key_mem, &vhd->key_len,
					       external_ip, 2048)) {
			lwsl_err("Failed to generate self-signed key/cert for DTLS\n");
			return -1;
		}

		{
			uint8_t hash[32];
			struct lws_genhash_ctx hash_ctx;
			int i;

			if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256) ||
			    lws_genhash_update(&hash_ctx, vhd->cert_mem, vhd->cert_len) ||
			    lws_genhash_destroy(&hash_ctx, hash)) {
				lwsl_err("Failed to compute cert hash\n");
				return -1;
			}

			for (i = 0; i < 32; i++)
				lws_snprintf(vhd->fingerprint + (i * 3), 4, "%02X%c", hash[i],
					     i == 31 ? '\0' : ':');

			lwsl_user("Certificate Fingerprint: %s\n", vhd->fingerprint);
		}

		{
			struct lws_adopt_desc ad;

			memset(&ad, 0, sizeof(ad));
			ad.vh = vhd->vhost;
			ad.type = LWS_ADOPT_RAW_FILE_DESC;
			ad.fd.filefd = (lws_filefd_type)(long)vhd->video_fd;
			ad.vh_prot_name = "lws-webrtc";

			vhd->wsi_v4l2 = lws_adopt_descriptor_vhost_via_info(&ad);
			if (!vhd->wsi_v4l2) {
				lwsl_err("Failed to adopt V4L2 fd\n");
				return -1;
			}
		}

		vhd->wsi_udp = lws_create_adopt_udp(vhd->vhost, NULL, 7682, LWS_CAUDP_BIND,
						"lws-webrtc-udp", NULL, NULL, NULL, NULL, NULL);
		if (!vhd->wsi_udp) {
			lwsl_err("Failed to bind UDP port 7682\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED: {
		if (!vhd->wsi_v4l2) {
			lws_sock_file_fd_type fd;
			fd.filefd = vhd->video_fd;
			vhd->wsi_v4l2 = lws_adopt_descriptor_vhost(vhd->vhost, LWS_ADOPT_RAW_FILE_DESC, fd, "lws-webrtc", NULL);
		}
		break;
	}

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_user("WebRTC signaling established\n");
		pss->wsi_ws = wsi;
		lws_dll2_add_tail(&pss->list, &vhd->sessions);
		pss->rtp_ssrc = 0x12345678;
		pss->rtp_ssrc_audio = 0x87654321;
		pss->rtp_seq = (uint16_t)lws_now_usecs();
		pss->rtp_pt_audio = 111;

		{
			uint8_t rand[16];
			lws_get_random(lws_get_context(wsi), rand, 4);
			lws_snprintf(pss->ice_ufrag, sizeof(pss->ice_ufrag), "%02X%02X%02X%02X",
				     rand[0], rand[1], rand[2], rand[3]);

			lws_get_random(lws_get_context(wsi), rand, 16);
			for (int i = 0; i < 16; i++)
				lws_snprintf(pss->ice_pwd + (i * 2), 3, "%02X", rand[i]);

			lwsl_info("Generated credentials: ufrag=%s, pwd=%s\n", pss->ice_ufrag, pss->ice_pwd);
		}

		lws_sul_schedule(lws_get_context(wsi), 0, &pss->sul_stats, sul_stats_cb, 1 * LWS_US_PER_SEC);
		break;

	case LWS_CALLBACK_RECEIVE:
		lwsl_info("LWS_CALLBACK_RECEIVE: %d bytes\n", (int)len);
		/* Provide the raw SDP for diagnostics */
		lwsl_hexdump_info(in, len);
		val = lws_json_simple_find((const char *)in, len, "\"type\":", &alen);
		if (val && !strncmp(val, "offer", alen)) {
			const char *sdp = (const char *)in;
			lwsl_user("Received Offer. Generating Answer...\n");

			/*
			 * Dynamic Payload Type (PT) Extraction for Chrome Compatibility.
			 * Chrome rejects the Answer if we pick a PT (like 126) NOT in its Offer.
			 * We search for H264 with profile 42e01f (Baseline) or 4d001f (Main).
			 */
			pss->rtp_pt = 126; /* Fallback */

			const char *p_h264 = strstr(sdp, "H264/90000");
			if (p_h264) {
				/* Backtrack to find a=rtpmap:<pt> */
				const char *p_rtp = p_h264;
				while (p_rtp > sdp && *p_rtp != ':') p_rtp--;
				if (*p_rtp == ':') pss->rtp_pt = (uint8_t)atoi(p_rtp + 1);

				/* Better: look for specific profile 42e01f or 4d001f */
				const char *p_profile = strstr(sdp, "profile-level-id=42e01f");
				if (!p_profile) p_profile = strstr(sdp, "profile-level-id=4d001f");
				if (p_profile) {
					/* Find a=fmtp:<pt> on this line or previous */
					const char *p_fmtp = p_profile;
					while (p_fmtp > sdp && strncmp(p_fmtp, "a=fmtp:", 7)) p_fmtp--;
					if (!strncmp(p_fmtp, "a=fmtp:", 7))
						pss->rtp_pt = (uint8_t)atoi(p_fmtp + 7);
				}
			}
			lwsl_user("Negotiated Payload Type: %d\n", pss->rtp_pt);

			if (!pss->handshake_started) {
				struct lws_gendtls_creation_info ci;

				memset(&ci, 0, sizeof(ci));
				ci.context = vhd->context;
				ci.mode = LWS_GENDTLS_MODE_SERVER;
				ci.mtu = 1200;
				ci.use_srtp = "SRTP_AES128_CM_SHA1_80";

				if (lws_gendtls_create(&pss->dtls_ctx, &ci))
					return -1;

				if (lws_gendtls_set_cert_mem(&pss->dtls_ctx, vhd->cert_mem, vhd->cert_len) ||
				    lws_gendtls_set_key_mem(&pss->dtls_ctx, vhd->key_mem, vhd->key_len)) {
					lwsl_err("Failed to set DTLS cert/key\n");
					return -1;
				}

				pss->handshake_started = 1;
				pss->wsi_udp = vhd->wsi_udp;
			}

			/*
			 * We align the Payload Type with the browser's offer.
			 * Video at m-line 0 (mid:0), Audio at m-line 1 (mid:1).
			 * Candidates are provided per media section for better compatibility.
			 */
			n_sdp = (size_t)lws_snprintf(p, 3072,
				"{\"type\":\"answer\",\"sdp\":\"v=0\\r\\no=- 123456 2 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0\\r\\na=msid-semantic:WMS *\\r\\na=ice-lite\\r\\na=group:BUNDLE 0 1\\r\\n"
				"m=video 7682 UDP/TLS/RTP/SAVPF %u\\r\\n"
				"c=IN IP4 %s\\r\\n"
				"a=rtcp-mux\\r\\n"
				"a=ice-ufrag:%s\\r\\n"
				"a=ice-pwd:%s\\r\\n"
				"a=fingerprint:sha-256 %s\\r\\n"
				"a=setup:passive\\r\\n"
				"a=mid:0\\r\\n"
				"a=sendonly\\r\\n"
				"a=msid:lws-stream lws-track-video\\r\\n"
				"a=rtpmap:%u H264/90000\\r\\n"
				"a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\\r\\n"
				"a=rtcp-fb:%u nack\\r\\n"
				"a=rtcp-fb:%u nack pli\\r\\n"
				"a=rtcp-fb:%u ccm fir\\r\\n"
				"a=ssrc:%u cname:lws-webcam-video\\r\\n"
				"a=ssrc:%u msid:lws-stream lws-track-video\\r\\n"
				"a=candidate:1 1 UDP 2130706431 %s 7682 typ host\\r\\n"
				"a=end-of-candidates\\r\\n"
				"m=audio 7682 UDP/TLS/RTP/SAVPF 111\\r\\n"
				"c=IN IP4 %s\\r\\n"
				"a=rtcp-mux\\r\\n"
				"a=ice-ufrag:%s\\r\\n"
				"a=ice-pwd:%s\\r\\n"
				"a=fingerprint:sha-256 %s\\r\\n"
				"a=setup:passive\\r\\n"
				"a=mid:1\\r\\n"
				"a=sendonly\\r\\n"
				"a=msid:lws-stream lws-track-audio\\r\\n"
				"a=rtpmap:111 opus/48000/2\\r\\n"
				"a=fmtp:111 minptime=10;useinbandfec=1\\r\\n"
				"a=ssrc:%u cname:lws-webcam-audio\\r\\n"
				"a=ssrc:%u msid:lws-stream lws-track-audio\\r\\n"
				"a=candidate:1 1 UDP 2130706431 %s 7682 typ host\\r\\n"
				"a=end-of-candidates\\r\\n\"}",
				pss->rtp_pt, external_ip, pss->ice_ufrag, pss->ice_pwd, vhd->fingerprint,
				pss->rtp_pt, pss->rtp_pt, pss->rtp_pt, pss->rtp_pt, pss->rtp_pt,
				pss->rtp_ssrc, pss->rtp_ssrc, external_ip,
				external_ip, pss->ice_ufrag, pss->ice_pwd, vhd->fingerprint,
				pss->rtp_ssrc_audio, pss->rtp_ssrc_audio,
				external_ip);

			if (lws_write(wsi, (unsigned char *)p, n_sdp, LWS_WRITE_TEXT) < (int)n_sdp)
				return -1;
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT_FILE:
		lwsl_user("V4L2 adopted\n");
		break;

	case LWS_CALLBACK_RAW_RX_FILE: {
		if (wsi == vhd->wsi_alsa) {
			/* Read exactly one frame of audio (960 samples @ 48kHz / 20ms) */
			n = (int)snd_pcm_readi(vhd->pcm_capture, vhd->audio_samples, AUDIO_SAMPLES_PER_FRAME);
			if (n < 0) {
				if (n == -EPIPE) snd_pcm_prepare(vhd->pcm_capture);
				return 0;
			}
			if (n != AUDIO_SAMPLES_PER_FRAME) return 0;

			/* Encode with Opus */
			int opus_len = opus_encode(vhd->opus_enc, vhd->audio_samples, AUDIO_SAMPLES_PER_FRAME,
						   vhd->opus_out, sizeof(vhd->opus_out));
			if (opus_len <= 0) return 0;

			lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
				struct per_session_data *s = lws_container_of(d, struct per_session_data, list);
				if (s->handshake_done) {
					uint8_t pkt[1514 + LWS_PRE];
					uint8_t *p = pkt + LWS_PRE;
					size_t pkt_len = LWS_RTP_HEADER_LEN + (size_t)opus_len;

					lws_rtp_write_header(&s->rtp_ctx_audio, p, 1);
					memcpy(p + LWS_RTP_HEADER_LEN, vhd->opus_out, (size_t)opus_len);
					s->rtp_ctx_audio.ts += 960; /* 20ms at 48kHz */

					if (lws_srtp_protect(&s->srtp_ctx, p, &pkt_len, 1514) == 0) {
						sendto(lws_get_socket_fd(s->wsi_udp), (const char *)p, pkt_len, 0,
						       (const struct sockaddr *)&s->peer_sin, sizeof(s->peer_sin));
					}
				}
			} lws_end_foreach_dll(d);
			return 0;
		}

		/* Generic RAW RX (V4L2) */
		struct v4l2_buffer buf_v;

		memset(&buf_v, 0, sizeof(buf_v));
		buf_v.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf_v.memory = V4L2_MEMORY_MMAP;

		if (ioctl(vhd->video_fd, VIDIOC_DQBUF, &buf_v) < 0)
			return 0;

		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
			struct per_session_data *s = lws_container_of(d, struct per_session_data, list);
			if (s->handshake_done)
				rtp_send_h264_frame(s, vhd->buffers[buf_v.index].start, buf_v.bytesused);
		} lws_end_foreach_dll(d);

		if (ioctl(vhd->video_fd, VIDIOC_QBUF, &buf_v) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_CLOSED:
		lws_dll2_remove(&pss->list);
		lws_sul_cancel(&pss->sul_stats);
		if (pss->handshake_started)
			lws_gendtls_destroy(&pss->dtls_ctx);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->pcm_capture) {
			snd_pcm_close(vhd->pcm_capture);
			vhd->pcm_capture = NULL;
		}
		if (vhd && vhd->opus_enc) {
			opus_encoder_destroy(vhd->opus_enc);
			vhd->opus_enc = NULL;
		}
		break;

	default:
		break;
	}

	return 0;
}

/* STUN support */


static int
callback_webrtc_udp(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	(void)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_info("UDP wsi adopted\n");
		break;

	case LWS_CALLBACK_RAW_RX: {
		struct per_vhost_data *vhd = (struct per_vhost_data *)
				lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
		struct per_session_data *pss = NULL;
		const struct lws_udp *udp_desc = lws_get_udp(wsi);
		uint8_t out[2048];
		int _tx_len;

		if (!vhd)
			vhd = vhd_global;

		if (vhd && udp_desc) {
			const struct sockaddr_in *sin = &udp_desc->sa46.sa4;
			lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
				struct per_session_data *s = lws_container_of(d, struct per_session_data, list);
				if (s->has_peer_sin &&
				    s->peer_sin.sin_addr.s_addr == sin->sin_addr.s_addr &&
				    s->peer_sin.sin_port == sin->sin_port) {
					pss = s;
					break;
				}
			} lws_end_foreach_dll(d);

			/* If no match, take the first one without an address for STUN processing */
			if (!pss) {
				lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
					struct per_session_data *s = lws_container_of(d, struct per_session_data, list);
					if (!s->has_peer_sin) {
						pss = s;
						break;
					}
				} lws_end_foreach_dll(d);
			}
		}

		if (len > 0 && ((uint8_t *)in)[0] == 0 && ((uint8_t *)in)[1] == 1) {
			const struct sockaddr_in *sin = &udp_desc->sa46.sa4;
			uint8_t pkt[256];
			int n;

			/* Verify and reply using library API */
			n = lws_stun_validate_and_reply(wsi, (uint8_t *)in, len, pkt, sizeof(pkt),
							pss ? pss->ice_pwd : NULL, sin);
			if (n > 0) {
				sendto(lws_get_socket_fd(wsi), (const char *)pkt, (size_t)n, 0,
				       (const struct sockaddr *)sin, sizeof(*sin));

				/* Auto-map first session */
				lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
					struct per_session_data *s = lws_container_of(d, struct per_session_data, list);
					if (!s->has_peer_sin) {
						s->peer_sin = *sin;
						s->has_peer_sin = 1;
						lwsl_user("Mapped peer address to session: %s:%d\n",
							inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
					}
				} lws_end_foreach_dll(d);

				return 0;
			}
		}

		if (pss && pss->handshake_started && len > 0) {
			uint8_t *p = (uint8_t *)in;
			uint8_t first_byte = p[0];

			if (first_byte >= 20 && first_byte <= 63) {
				/* DTLS */
				lwsl_info("Feeding DTLS %d bytes\n", (int)len);
				if (lws_gendtls_put_rx(&pss->dtls_ctx, in, len)) {
					lwsl_err("lws_gendtls_put_rx failed!\n");
				}

				/* Pump the handshake and discard any decrypted app data */
				while (lws_gendtls_get_rx(&pss->dtls_ctx, out, sizeof(out)) > 0)
					;

				if (!pss->handshake_done) {
					int n = lws_gendtls_handshake_done(&pss->dtls_ctx);
					if (n == 1) {
						lwsl_user("DTLS Handshake DONE!\n");
						pss->handshake_done = 1;
						pss->rtp_ssrc = 0x12345678; /* Set SSRC here */

						uint8_t srtp_keying[60];
						if (lws_gendtls_export_keying_material(&pss->dtls_ctx,
								"EXTRACTOR-dtls_srtp", 19, NULL, 0,
								srtp_keying, sizeof(srtp_keying)) == 0) {
							lwsl_user("SRTP keying material exported\n");
							/*
							 * RFC 5764 4.2:
							 * K_C(16), K_S(16), S_C(14), S_S(14).
							 * Server TX: K_S (+16) and S_S (+46).
							 * Server RX: K_C (+0) and S_C (+32).
							 */
							lws_srtp_init(&pss->srtp_ctx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
									     srtp_keying + 16, srtp_keying + 46);
							lws_srtp_init(&pss->srtp_ctx_rx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
									     srtp_keying + 0, srtp_keying + 32);
							lws_rtp_init(&pss->rtp_ctx, pss->rtp_ssrc, pss->rtp_pt);
							lws_rtp_init(&pss->rtp_ctx_audio, pss->rtp_ssrc_audio, pss->rtp_pt_audio);
						}
					}
				}

				/* Drain all pending TX data (handshake packets, ACKs, etc) */
				while ((_tx_len = lws_gendtls_get_tx(&pss->dtls_ctx, out, sizeof(out))) > 0) {
					if (!pss->has_peer_sin) break;
					lwsl_info("Sending DTLS response (%d bytes) to %s:%d\n", _tx_len,
						inet_ntoa(pss->peer_sin.sin_addr), ntohs(pss->peer_sin.sin_port));
					sendto(lws_get_socket_fd(wsi), (const char *)out, (size_t)_tx_len, 0,
					       (const struct sockaddr *)&pss->peer_sin, sizeof(pss->peer_sin));
				}
			} else if (first_byte >= 128 && first_byte <= 200) {
				/* RTP / RTCP */
				uint8_t *p = (uint8_t *)in;
				uint8_t pt = p[1];

				if (pt >= 200 && pt <= 205) {
					/* Encrypted RTCP */
					size_t rtcp_len = len;
					if (lws_srtp_unprotect_rtcp(&pss->srtp_ctx_rx, (uint8_t *)in, &rtcp_len) == 0) {
						/* Decrypted! */
						uint8_t pt_dec = ((uint8_t *)in)[1];
						uint32_t ssrc_src = (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]);
						lwsl_info("Decrypted RTCP PT=%d, SSRC_SRC=0x%08x, len=%d\n", pt_dec, ssrc_src, (int)rtcp_len);

						if (pt_dec == 201 && rtcp_len >= 12) { /* RR */
							uint32_t ssrc_target = (uint32_t)((p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11]);
							lwsl_info("  RTCP RR target SSRC=0x%08x\n", ssrc_target);
						}

						if (pt_dec == 205) { /* Feedback */
							uint8_t fmt = p[0] & 0x1f;
							lwsl_info("  RTCP Feedback: FMT=%d\n", fmt);
							if (fmt == 1) lwsl_info("    -> PLI (Picture Loss Indication) requested!\n");
						}
					} else {
						/* Fallback to basic logging if decryption fails */
						uint32_t ssrc_src = (len >= 8) ? (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]) : 0;
						lwsl_info("Received ENCRYPTED PT=%d (0x%02x), SSRC_SRC=0x%08x, len=%d\n", pt, pt, ssrc_src, (int)len);
						if (len > 8 && pt == 201) {
							uint32_t ssrc_target = (uint32_t)((p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11]);
							lwsl_info("  RTCP RR target SSRC=0x%08x (likely SRTCP Index)\n", ssrc_target);
						}
					}
				} else {
					lwsl_info("Received RTP packet (unexpected PT=%d), len=%d\n", pt, (int)len);
				}
			} else {
				lwsl_warn("Received unknown packet type: 0x%02X, len=%d\n", first_byte, (int)len);
				lwsl_hexdump_notice(in, len > 32 ? 32 : len);
			}
		}
		break;
	}

	default:
		break;
	}

	return 0;
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	(void)user;
	(void)in;
	(void)len;

	switch (reason) {
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		lwsl_user("LWS_CALLBACK_FILTER_NETWORK_CONNECTION\n");
		return 0;
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	{ "lws-webrtc", callback_webrtc, sizeof(struct per_session_data), 4096, 0, NULL, 0 },
	{ "lws-webrtc-udp", callback_webrtc_udp, 0, 2048, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void
sigint_handler(int sig)
{
	(void)sig;
	interrupted = 1;
}

static struct lws_http_mount mount = {
	.mountpoint		= "/",
	.origin			= "./mount-origin",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *opt;

	signal(SIGINT, sigint_handler);

	if ((opt = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(opt);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS Minimal WebRTC Webcam example\n");

	if ((opt = lws_cmdline_option(argc, argv, "--mount-origin")))
		mount.origin = opt;

	if ((opt = lws_cmdline_option(argc, argv, "--ip")))
		lws_strncpy(external_ip, opt, sizeof(external_ip));

	memset(&info, 0, sizeof(info));
	info.port = 7681;
	info.protocols = protocols;
	info.mounts = &mount;
	info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	lws_cmdline_option_handle_builtin(argc, argv, &info);

	context = lws_create_context(&info);
	if (!context) {
		return 1;
	}

	while (!interrupted) {
		if (lws_service(context, 0) < 0)
			break;
	}

	lws_context_destroy(context);

	return 0;
}
